//! The indexer API behind `sb serve`: what a verified-sync client
//! (`--chain light:<url>`) reads. `GET /tip` replays to the chain tip and
//! answers with it; `GET /block/<height>` and `GET /block/<hash>` answer
//! with the block's carrier candidates, their partial merkle tree and the
//! replayed root after the block (`sb_indexer::chain::light::BlockView`).
//! The server fetches the full block from its own chain source on demand.

use std::net::TcpListener;
use std::time::Duration;

use anyhow::Result;
use bitcoin::BlockHash;
use serde_json::{Value, json};

use sb_indexer::chain::light::BlockView;
use sb_indexer::{ChainSource, Indexer, StateStore};

use crate::http::{read_request, respond};

pub struct Server {
    pub indexer: Indexer,
    pub store: Box<dyn StateStore>,
    pub chain: Box<dyn ChainSource>,
}

impl Server {
    /// Serve until `max_requests` requests were answered (`None`: forever).
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
            .map(|r| hex::encode(sb_primitives::encoding::fr_to_bytes(&r)));
        let view = BlockView::from_block(self.indexer.deployment.carrier, cp.height, &block, root);
        (200, serde_json::to_value(view).unwrap_or(Value::Null))
    }
}
