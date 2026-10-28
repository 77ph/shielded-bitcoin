//! Electrum protocol chain source (ElectrumX, Fulcrum, electrs).
//!
//! Electrum servers do not serve whole blocks, so a block is rebuilt from
//! `blockchain.block.header`, `blockchain.transaction.id_from_pos` (enumerated
//! until the server reports the end of the block) and
//! `blockchain.transaction.get`; the result is checked against the header's
//! merkle root, so a lying or truncating server cannot alter replay input.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Block, BlockHash, ScriptBuf, Transaction, Txid};
use serde_json::{Value, json};

use super::{BlockId, ChainError, ChainSource};

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

pub struct Electrum {
    host: String,
    port: u16,
    tls: bool,
    stream: RefCell<Option<BufReader<Box<dyn ReadWrite>>>>,
    next_id: Cell<u64>,
    /// `block_hash` results, so `block(hash)` knows the height.
    headers: RefCell<HashMap<BlockHash, (u32, Header)>>,
}

impl Electrum {
    /// `url` like `ssl://mempool.space:60602` or `tcp://host:50001`.
    pub fn new(url: &str) -> Result<Self, ChainError> {
        let (tls, rest) = if let Some(r) = url.strip_prefix("ssl://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("tcp://") {
            (false, r)
        } else {
            (true, url)
        };
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| ChainError::Rpc(format!("electrum url {url:?}: expected host:port")))?;
        let port: u16 = port
            .parse()
            .map_err(|_| ChainError::Rpc(format!("bad port in {url:?}")))?;
        Ok(Electrum {
            host: host.to_string(),
            port,
            tls,
            stream: RefCell::new(None),
            next_id: Cell::new(1),
            headers: RefCell::new(HashMap::new()),
        })
    }

    fn connect(&self) -> Result<BufReader<Box<dyn ReadWrite>>, ChainError> {
        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| ChainError::Rpc(format!("cannot resolve {}", self.host)))?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(15))?;
        tcp.set_read_timeout(Some(Duration::from_secs(60)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
        let stream: Box<dyn ReadWrite> = if self.tls {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
            };
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| ChainError::Rpc(format!("tls: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|e| ChainError::Rpc(format!("tls name: {e}")))?;
            let conn = rustls::ClientConnection::new(Arc::new(config), name)
                .map_err(|e| ChainError::Rpc(format!("tls: {e}")))?;
            Box::new(rustls::StreamOwned::new(conn, tcp))
        } else {
            Box::new(tcp)
        };
        let mut reader = BufReader::new(stream);
        // Protocol negotiation; also validates that this is an Electrum server.
        let id = self.bump();
        let req = json!({"jsonrpc": "2.0", "id": id, "method": "server.version", "params": ["shielded-bitcoin", "1.4"]});
        Self::send_on(&mut reader, &req)?;
        Self::recv_on(&mut reader, id)?;
        Ok(reader)
    }

    fn bump(&self) -> u64 {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        id
    }

    fn send_on(reader: &mut BufReader<Box<dyn ReadWrite>>, req: &Value) -> Result<(), ChainError> {
        let mut line = serde_json::to_string(req).expect("json");
        line.push('\n');
        reader.get_mut().write_all(line.as_bytes())?;
        reader.get_mut().flush()?;
        Ok(())
    }

    /// Read lines until the response with `id` arrives (notifications are skipped).
    fn recv_on(reader: &mut BufReader<Box<dyn ReadWrite>>, id: u64) -> Result<Value, ChainError> {
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Err(ChainError::Rpc("electrum connection closed".into()));
            }
            let v: Value =
                serde_json::from_str(line.trim()).map_err(|e| ChainError::Decode(e.to_string()))?;
            if v.get("id").and_then(|i| i.as_u64()) != Some(id) {
                continue;
            }
            if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                let msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| err.to_string());
                return Err(ChainError::Rpc(msg));
            }
            return v
                .get("result")
                .cloned()
                .ok_or_else(|| ChainError::Rpc("no result".into()));
        }
    }

    /// One JSON-RPC call, reconnecting once if the connection dropped.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        for attempt in 0..2 {
            if self.stream.borrow().is_none() {
                *self.stream.borrow_mut() = Some(self.connect()?);
            }
            let id = self.bump();
            let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
            let result = {
                let mut guard = self.stream.borrow_mut();
                let reader = guard.as_mut().unwrap();
                Self::send_on(reader, &req).and_then(|_| Self::recv_on(reader, id))
            };
            match result {
                Ok(v) => return Ok(v),
                // Application errors come back as Rpc with a message; transport
                // failures are Http (io) — reconnect once for those.
                Err(ChainError::Http(_)) if attempt == 0 => {
                    *self.stream.borrow_mut() = None;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    /// One JSON-RPC batch (array request); results are returned in request
    /// order, each as the server's result or application error.
    pub fn call_batch(
        &self,
        method: &str,
        params: &[Value],
    ) -> Result<Vec<Result<Value, ChainError>>, ChainError> {
        if params.is_empty() {
            return Ok(Vec::new());
        }
        for attempt in 0..2 {
            if self.stream.borrow().is_none() {
                *self.stream.borrow_mut() = Some(self.connect()?);
            }
            let first = self.next_id.get();
            self.next_id.set(first + params.len() as u64);
            let reqs: Vec<Value> = params
                .iter()
                .enumerate()
                .map(|(i, p)| json!({"jsonrpc": "2.0", "id": first + i as u64, "method": method, "params": p}))
                .collect();
            let result: Result<Vec<Result<Value, ChainError>>, ChainError> = (|| {
                let mut guard = self.stream.borrow_mut();
                let reader = guard.as_mut().unwrap();
                Self::send_on(reader, &Value::Array(reqs))?;
                // The whole batch comes back as one JSON array line.
                let mut line = String::new();
                loop {
                    line.clear();
                    if reader.read_line(&mut line)? == 0 {
                        return Err(ChainError::Http("electrum connection closed".into()));
                    }
                    let v: Value = serde_json::from_str(line.trim())
                        .map_err(|e| ChainError::Decode(e.to_string()))?;
                    let Some(arr) = v.as_array() else { continue }; // notification
                    let mut out: Vec<Option<Result<Value, ChainError>>> =
                        (0..params.len()).map(|_| None).collect();
                    for item in arr {
                        let Some(id) = item.get("id").and_then(|i| i.as_u64()) else {
                            continue;
                        };
                        if id < first || id >= first + params.len() as u64 {
                            continue;
                        }
                        let r = match item.get("error").filter(|e| !e.is_null()) {
                            Some(err) => Err(ChainError::Rpc(
                                err.get("message")
                                    .and_then(|m| m.as_str())
                                    .map(str::to_string)
                                    .unwrap_or_else(|| err.to_string()),
                            )),
                            None => item
                                .get("result")
                                .cloned()
                                .ok_or_else(|| ChainError::Rpc("no result".into())),
                        };
                        out[(id - first) as usize] = Some(r);
                    }
                    return out
                        .into_iter()
                        .map(|r| r.ok_or_else(|| ChainError::Rpc("batch item missing".into())))
                        .collect();
                }
            })();
            match result {
                Ok(v) => return Ok(v),
                Err(ChainError::Http(_)) if attempt == 0 => *self.stream.borrow_mut() = None,
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    fn header_at(&self, height: u32) -> Result<Option<(BlockHash, Header)>, ChainError> {
        match self.call("blockchain.block.header", json!([height])) {
            Ok(v) => {
                let hex = v
                    .as_str()
                    .ok_or_else(|| ChainError::Rpc("bad header".into()))?;
                let bytes = hex::decode(hex).map_err(|e| ChainError::Decode(e.to_string()))?;
                let header: Header =
                    deserialize(&bytes).map_err(|e| ChainError::Decode(e.to_string()))?;
                let hash = header.block_hash();
                self.headers.borrow_mut().insert(hash, (height, header));
                Ok(Some((hash, header)))
            }
            // Servers word "no such height" differently ("out of range",
            // "missing header", …); any application error here means none.
            Err(ChainError::Rpc(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `sha256(scriptPubKey)` reversed, as Electrum identifies scripts.
    pub fn scripthash(script: &ScriptBuf) -> String {
        let mut h = sha256::Hash::hash(script.as_bytes()).to_byte_array();
        h.reverse();
        hex::encode(h)
    }
}

impl ChainSource for Electrum {
    fn tip(&self) -> Result<BlockId, ChainError> {
        let v = self.call("blockchain.headers.subscribe", json!([]))?;
        let height = v["height"]
            .as_u64()
            .ok_or_else(|| ChainError::Rpc("bad tip".into()))? as u32;
        let hex = v["hex"]
            .as_str()
            .ok_or_else(|| ChainError::Rpc("bad tip header".into()))?;
        let bytes = hex::decode(hex).map_err(|e| ChainError::Decode(e.to_string()))?;
        let header: Header = deserialize(&bytes).map_err(|e| ChainError::Decode(e.to_string()))?;
        let hash = header.block_hash();
        self.headers.borrow_mut().insert(hash, (height, header));
        Ok(BlockId { height, hash })
    }

    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError> {
        Ok(self.header_at(height)?.map(|(h, _)| h))
    }

    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        let (height, header) = self.headers.borrow().get(hash).copied().ok_or_else(|| {
            ChainError::NotFound(format!("{hash} (height unknown; call block_hash first)"))
        })?;
        // Enumerate txids in chunks; the first application error marks the end.
        const CHUNK: usize = 64;
        let mut txids: Vec<Txid> = Vec::new();
        'outer: loop {
            let base = txids.len();
            let params: Vec<Value> = (0..CHUNK).map(|i| json!([height, base + i])).collect();
            for r in self.call_batch("blockchain.transaction.id_from_pos", &params)? {
                match r {
                    Ok(v) => txids.push(
                        v.as_str()
                            .ok_or_else(|| ChainError::Rpc("bad txid".into()))?
                            .parse::<Txid>()
                            .map_err(|e| ChainError::Decode(e.to_string()))?,
                    ),
                    Err(_) => break 'outer,
                }
            }
        }
        let mut txdata = Vec::with_capacity(txids.len());
        for chunk in txids.chunks(CHUNK) {
            let params: Vec<Value> = chunk.iter().map(|t| json!([t.to_string()])).collect();
            for r in self.call_batch("blockchain.transaction.get", &params)? {
                let hex = r?;
                let hex = hex
                    .as_str()
                    .ok_or_else(|| ChainError::Rpc("bad tx".into()))?;
                let tx: Transaction =
                    deserialize(&hex::decode(hex).map_err(|e| ChainError::Decode(e.to_string()))?)
                        .map_err(|e| ChainError::Decode(e.to_string()))?;
                txdata.push(tx);
            }
        }
        let block = Block { header, txdata };
        if block.compute_merkle_root() != Some(header.merkle_root) {
            return Err(ChainError::Decode(format!(
                "electrum block {hash}: merkle root mismatch ({} txs)",
                block.txdata.len()
            )));
        }
        let _ = serialize(&header);
        Ok(block)
    }
}

/// Electrum-side UTXO lookup and broadcast (used by the CLI publisher).
impl Electrum {
    /// `[(txid, vout, value, confirmed)]` for a script.
    pub fn listunspent(
        &self,
        script: &ScriptBuf,
    ) -> Result<Vec<(Txid, u32, u64, bool)>, ChainError> {
        let v = self.call(
            "blockchain.scripthash.listunspent",
            json!([Self::scripthash(script)]),
        )?;
        let mut out = Vec::new();
        for u in v.as_array().cloned().unwrap_or_default() {
            let txid = u["tx_hash"]
                .as_str()
                .ok_or_else(|| ChainError::Rpc("tx_hash".into()))?
                .parse::<Txid>()
                .map_err(|e| ChainError::Decode(e.to_string()))?;
            let vout = u["tx_pos"]
                .as_u64()
                .ok_or_else(|| ChainError::Rpc("tx_pos".into()))? as u32;
            let value = u["value"]
                .as_u64()
                .ok_or_else(|| ChainError::Rpc("value".into()))?;
            let confirmed = u["height"].as_u64().unwrap_or(0) > 0;
            out.push((txid, vout, value, confirmed));
        }
        Ok(out)
    }

    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, ChainError> {
        let hex = bitcoin::consensus::encode::serialize_hex(tx);
        let v = self.call("blockchain.transaction.broadcast", json!([hex]))?;
        v.as_str()
            .ok_or_else(|| ChainError::Rpc("bad txid".into()))?
            .parse()
            .map_err(|e: bitcoin::hex::HexToArrayError| ChainError::Decode(e.to_string()))
    }
}
