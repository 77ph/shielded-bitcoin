//! The indexer API for verified-sync clients of variant A (`--chain
//! light:<url>`, `README.md` "Verified sync from an indexer"): per block,
//! the header, every transaction the family's carrier rule looks at, a
//! BIP 37 partial merkle tree for them and the indexer's own `R[h]`. The
//! port of `crates/sb-cli/src/serve.rs` without the proven-block route
//! (the family has no batch proofs yet).

use std::net::TcpListener;
use std::time::Duration;

use anyhow::Result;
use bitcoin::BlockHash;
use serde_json::{Value, json};

use sb_common::chain::ChainSource;
use sb_common::chain::light::BlockView;
use sb_common::http::{read_request, respond};
use sba_core::envelope::CANDIDATE_PREFIX;
use sba_indexer::{Indexer, StateStore};
use sba_primitives::encoding::fp_to_bytes;

pub struct Server {
    pub indexer: Indexer,
    pub store: Box<dyn StateStore>,
    pub chain: Box<dyn ChainSource>,
}

impl Server {
    pub fn serve(&mut self, listener: TcpListener, max_requests: Option<u32>) -> Result<()> {
        let mut served = 0u32;
        while max_requests.is_none_or(|m| served < m) {
            let (conn, peer) = listener.accept()?;
            let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
            let (status, body) = match read_request(&conn) {
                Ok((method, path, _)) => self.handle(&method, &path),
                Err(e) => (400, json!({"error": e.to_string()})),
            };
            log::info!("{peer}: {status}");
            respond(conn, status, &body);
            served += 1;
        }
        Ok(())
    }

    fn handle(&mut self, method: &str, path: &str) -> (u16, Value) {
        if method != "GET" {
            return (404, json!({"error": "not found"}));
        }
        match path.strip_prefix("/block/") {
            Some(rest) => self.block(rest),
            None if path == "/tip" => self.tip(),
            None => (404, json!({"error": "not found"})),
        }
    }

    fn tip(&mut self) -> (u16, Value) {
        if let Err(e) = self
            .indexer
            .sync_with(self.chain.as_ref(), Some(self.store.as_mut()))
        {
            return (500, json!({"error": format!("sync: {e}")}));
        }
        match self.indexer.state.blocks.last() {
            Some(cp) => (
                200,
                json!({"height": cp.height, "hash": cp.hash.to_string()}),
            ),
            None => (404, json!({"error": "nothing replayed yet"})),
        }
    }

    fn block(&mut self, which: &str) -> (u16, Value) {
        let cp = if let Ok(h) = which.parse::<u32>() {
            self.indexer.state.blocks.iter().find(|cp| cp.height == h)
        } else if let Ok(hash) = which.parse::<BlockHash>() {
            self.indexer.state.blocks.iter().find(|cp| cp.hash == hash)
        } else {
            return (400, json!({"error": "height or block hash expected"}));
        };
        let Some(cp) = cp.cloned() else {
            return (404, json!({"error": "not replayed"}));
        };
        let block = match self.chain.block(&cp.hash) {
            Ok(b) => b,
            Err(e) => return (500, json!({"error": format!("chain: {e}")})),
        };
        if block.block_hash() != cp.hash {
            return (500, json!({"error": "chain source returned another block"}));
        }
        let root = self
            .indexer
            .root_at(cp.height)
            .map(|r| hex::encode(fp_to_bytes(&r)));
        let view = BlockView::from_block(
            self.indexer.deployment.carrier,
            &CANDIDATE_PREFIX,
            cp.height,
            &block,
            root,
        );
        (200, serde_json::to_value(view).unwrap_or(Value::Null))
    }
}
