//! In-process fake servers over a [`MockChain`] for tests: an HTTP server
//! that speaks the Esplora routes and Bitcoin Core JSON-RPC used by this
//! project, and a TCP Electrum server. Nothing is validated: any
//! transaction posted lands in the mempool and the next mined block.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use serde_json::{Value, json};

use super::mock::MockChain;
use super::{BlockId, ChainSource};

#[derive(Clone)]
pub struct Shared {
    pub chain: Arc<Mutex<MockChain>>,
    pub mempool: Arc<Mutex<Vec<Transaction>>>,
    /// Electrum: report one transaction fewer per block (merkle mismatch).
    pub truncate: Arc<AtomicBool>,
    /// Electrum: close the connection after the next request (reconnect test).
    pub drop_next: Arc<AtomicBool>,
}

impl Shared {
    pub fn new(chain: MockChain) -> Self {
        Shared {
            chain: Arc::new(Mutex::new(chain)),
            mempool: Arc::new(Mutex::new(Vec::new())),
            truncate: Arc::new(AtomicBool::new(false)),
            drop_next: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mine a block with everything in the mempool.
    pub fn mine(&self, salt: u32) -> BlockId {
        let txs: Vec<Transaction> = std::mem::take(&mut *self.mempool.lock().unwrap());
        self.chain.lock().unwrap().push_block_salted(txs, salt)
    }

    /// Put a synthetic funding transaction (no inputs) into the mempool.
    pub fn fund(&self, script: &ScriptBuf, value: u64) -> Txid {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(value),
                script_pubkey: script.clone(),
            }],
        };
        let txid = tx.compute_txid();
        self.mempool.lock().unwrap().push(tx);
        txid
    }

    /// `(outpoint, value, confirmed height or None)` for a script, over the
    /// chain and the mempool.
    pub fn utxos(&self, script: &ScriptBuf) -> Vec<(OutPoint, u64, Option<u32>)> {
        let chain = self.chain.lock().unwrap();
        let mempool = self.mempool.lock().unwrap();
        let start = chain.start_height();
        let mut all: Vec<(Option<u32>, Transaction)> = Vec::new();
        for (i, b) in chain.blocks().iter().enumerate() {
            for t in &b.txdata {
                all.push((Some(start + i as u32), t.clone()));
            }
        }
        for t in mempool.iter() {
            all.push((None, t.clone()));
        }
        let mut spent: HashSet<OutPoint> = HashSet::new();
        let mut out = Vec::new();
        for (height, tx) in &all {
            for i in &tx.input {
                spent.insert(i.previous_output);
            }
            let txid = tx.compute_txid();
            for (vout, o) in tx.output.iter().enumerate() {
                if o.script_pubkey == *script {
                    out.push((
                        OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        o.value.to_sat(),
                        *height,
                    ));
                }
            }
        }
        out.into_iter()
            .filter(|(op, _, _)| !spent.contains(op))
            .collect()
    }

    fn tx_status(&self, txid: &Txid) -> Value {
        let chain = self.chain.lock().unwrap();
        for (i, b) in chain.blocks().iter().enumerate() {
            if b.txdata.iter().any(|t| t.compute_txid() == *txid) {
                return json!({"confirmed": true, "block_height": chain.start_height() + i as u32, "block_hash": b.block_hash().to_string()});
            }
        }
        json!({"confirmed": false})
    }

    fn find_tx(&self, txid: &Txid) -> Option<Transaction> {
        let chain = self.chain.lock().unwrap();
        chain
            .blocks()
            .iter()
            .flat_map(|b| b.txdata.iter())
            .chain(self.mempool.lock().unwrap().iter())
            .find(|t| t.compute_txid() == *txid)
            .cloned()
    }
}

fn scripthash(script: &ScriptBuf) -> String {
    let mut h = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    h.reverse();
    hex::encode(h)
}

// ---------------------------------------------------------------- HTTP ----

/// HTTP server: Esplora routes at `/` and Bitcoin Core JSON-RPC at `/rpc`.
pub struct FakeHttp {
    pub addr: SocketAddr,
    pub shared: Shared,
}

impl FakeHttp {
    pub fn start(shared: Shared) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s = shared.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let s = s.clone();
                std::thread::spawn(move || handle_http(conn, &s));
            }
        });
        FakeHttp { addr, shared }
    }

    pub fn esplora_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn rpc_url(&self) -> String {
        format!("http://{}/rpc", self.addr)
    }
}

fn handle_http(mut conn: TcpStream, s: &Shared) {
    // One request per connection; the response says `Connection: close`.
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
            return;
        };
        let (method, path) = (method.to_string(), path.to_string());
        let mut content_length = 0usize;
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            if h.trim().is_empty() {
                break;
            }
            if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).unwrap();
        }
        let (status, ctype, out): (u16, &str, Vec<u8>) = match (method.as_str(), path.as_str()) {
            ("POST", "/rpc") => {
                let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let (status, v) = rpc(s, &req);
                (status, "application/json", serde_json::to_vec(&v).unwrap())
            }
            ("POST", "/tx") => {
                let hex = String::from_utf8_lossy(&body).trim().to_string();
                match hex::decode(&hex)
                    .ok()
                    .and_then(|b| deserialize::<Transaction>(&b).ok())
                {
                    Some(tx)
                        if tx
                            .output
                            .iter()
                            .all(|o| o.value.to_sat() == 0 || o.value.to_sat() >= 294) =>
                    {
                        let txid = tx.compute_txid();
                        s.mempool.lock().unwrap().push(tx);
                        (200, "text/plain", txid.to_string().into_bytes())
                    }
                    Some(_) => (
                        400,
                        "text/plain",
                        b"sendrawtransaction RPC error: {\"code\":-26,\"message\":\"dust\"}"
                            .to_vec(),
                    ),
                    None => (400, "text/plain", b"bad tx".to_vec()),
                }
            }
            ("GET", p) => esplora(s, p),
            _ => (404, "text/plain", b"not found".to_vec()),
        };
        let header = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            if status == 200 { "OK" } else { "Error" },
            ctype,
            out.len()
        );
        let _ = conn.write_all(header.as_bytes());
        let _ = conn.write_all(&out);
        let _ = conn.flush();
    }
}

fn esplora(s: &Shared, path: &str) -> (u16, &'static str, Vec<u8>) {
    let chain = s.chain.lock().unwrap();
    let text = |t: String| (200u16, "text/plain", t.into_bytes());
    match path
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["blocks", "tip", "height"] => match chain.height() {
            Some(h) => text(h.to_string()),
            None => (404, "text/plain", b"no blocks".to_vec()),
        },
        ["blocks", "tip", "hash"] => match chain.tip() {
            Ok(t) => text(t.hash.to_string()),
            Err(_) => (404, "text/plain", b"no blocks".to_vec()),
        },
        ["block-height", h] => match h
            .parse::<u32>()
            .ok()
            .and_then(|h| chain.block_hash(h).ok().flatten())
        {
            Some(hash) => text(hash.to_string()),
            None => (404, "text/plain", b"Block not found".to_vec()),
        },
        ["block", hash, "raw"] => match hash.parse().ok().and_then(|h| chain.block(&h).ok()) {
            Some(b) => (200, "application/octet-stream", serialize(&b)),
            None => (404, "text/plain", b"Block not found".to_vec()),
        },
        ["address", addr, "utxo"] => {
            drop(chain);
            let script = addr
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .map(|a| a.assume_checked().script_pubkey())
                .unwrap_or_default();
            let list: Vec<Value> = s
                .utxos(&script)
                .into_iter()
                .map(|(op, value, height)| {
                    json!({"txid": op.txid.to_string(), "vout": op.vout, "value": value,
                           "status": {"confirmed": height.is_some(), "block_height": height}})
                })
                .collect();
            (200, "application/json", serde_json::to_vec(&list).unwrap())
        }
        ["tx", txid, "status"] => {
            drop(chain);
            let v = txid
                .parse::<Txid>()
                .map(|t| s.tx_status(&t))
                .unwrap_or(json!({"confirmed": false}));
            (200, "application/json", serde_json::to_vec(&v).unwrap())
        }
        _ => (404, "text/plain", b"not found".to_vec()),
    }
}

fn rpc(s: &Shared, req: &Value) -> (u16, Value) {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req
        .get("params")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let err = |code: i64, msg: &str| {
        (
            500u16,
            json!({"result": null, "error": {"code": code, "message": msg}, "id": id}),
        )
    };
    let ok = |v: Value| (200u16, json!({"result": v, "error": null, "id": id}));
    let chain = s.chain.lock().unwrap();
    match req.get("method").and_then(|m| m.as_str()) {
        Some("getblockcount") => match chain.height() {
            Some(h) => ok(json!(h)),
            None => err(-1, "no blocks"),
        },
        Some("getblockhash") => {
            let h = params.first().and_then(|v| v.as_u64()).unwrap_or(u64::MAX) as u32;
            if h == 4_000_000_000 {
                return err(-1, "simulated failure");
            }
            if h == 4_000_000_001 {
                return ok(json!("not-a-hash"));
            }
            match chain.block_hash(h).ok().flatten() {
                Some(hash) => ok(json!(hash.to_string())),
                None => err(-8, "Block height out of range"),
            }
        }
        Some("getblock") => {
            let hash = params
                .first()
                .and_then(|v| v.as_str())
                .and_then(|h| h.parse().ok());
            match hash.and_then(|h| chain.block(&h).ok()) {
                Some(b) => ok(json!(hex::encode(serialize(&b)))),
                None => err(-5, "Block not found"),
            }
        }
        Some("scantxoutset") => {
            drop(chain);
            let desc = params
                .get(1)
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let addr = desc.trim_start_matches("addr(").trim_end_matches(')');
            let script = addr
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                .map(|a| a.assume_checked().script_pubkey())
                .unwrap_or_default();
            let unspents: Vec<Value> = s
                .utxos(&script)
                .into_iter()
                .filter(|(_, _, h)| h.is_some())
                .map(|(op, value, h)| json!({"txid": op.txid.to_string(), "vout": op.vout, "amount": value as f64 / 1e8, "height": h}))
                .collect();
            ok(json!({"success": true, "unspents": unspents}))
        }
        Some("sendrawtransaction") => {
            drop(chain);
            let hex = params.first().and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(hex)
                .ok()
                .and_then(|b| deserialize::<Transaction>(&b).ok())
            {
                Some(tx) => {
                    let txid = tx.compute_txid();
                    s.mempool.lock().unwrap().push(tx);
                    ok(json!(txid.to_string()))
                }
                None => err(-22, "TX decode failed"),
            }
        }
        Some("noresult") => (200, json!({"error": null, "id": id})),
        _ => err(-32601, "Method not found"),
    }
}

// ------------------------------------------------------------- Electrum ----

pub struct FakeElectrum {
    pub addr: SocketAddr,
    pub shared: Shared,
}

impl FakeElectrum {
    pub fn start(shared: Shared) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s = shared.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let s = s.clone();
                std::thread::spawn(move || handle_electrum(conn, &s));
            }
        });
        FakeElectrum { addr, shared }
    }

    pub fn url(&self) -> String {
        format!("tcp://{}", self.addr)
    }

    /// TLS variant with a fresh self-signed certificate; returns the server
    /// and the certificate's SHA-256 fingerprint (what a client would pin).
    pub fn start_tls(shared: Shared) -> (Self, [u8; 32]) {
        let certified = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let fingerprint = sha256::Hash::hash(cert_der.as_ref()).to_byte_array();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(StdArc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .unwrap();
        let config = StdArc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s = shared.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let s = s.clone();
                let config = config.clone();
                std::thread::spawn(move || {
                    let tls = rustls::ServerConnection::new(config).unwrap();
                    handle_electrum(rustls::StreamOwned::new(tls, conn), &s);
                });
            }
        });
        (FakeElectrum { addr, shared }, fingerprint)
    }
}

fn handle_electrum<S: Read + Write>(conn: S, s: &Shared) {
    let mut reader = BufReader::new(conn);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if s.drop_next.swap(false, Ordering::SeqCst) {
            return; // connection dropped without an answer
        }
        let req: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => return,
        };
        let resp = match req {
            Value::Array(items) => Value::Array(items.iter().map(|r| electrum_one(s, r)).collect()),
            other => electrum_one(s, &other),
        };
        let mut out = serde_json::to_string(&resp).unwrap();
        out.push('\n');
        if reader.get_mut().write_all(out.as_bytes()).is_err() {
            return;
        }
    }
}

fn electrum_one(s: &Shared, req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req
        .get("params")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let err = |msg: &str| json!({"jsonrpc": "2.0", "id": id, "error": {"code": 1, "message": msg}});
    let ok = |v: Value| json!({"jsonrpc": "2.0", "id": id, "result": v});
    let chain = s.chain.lock().unwrap();
    match req.get("method").and_then(|m| m.as_str()) {
        Some("server.version") => ok(json!(["fake-electrum", "1.4"])),
        Some("blockchain.headers.subscribe") => match chain.tip() {
            Ok(t) => {
                let b = chain.block(&t.hash).unwrap();
                ok(json!({"height": t.height, "hex": hex::encode(serialize(&b.header))}))
            }
            Err(_) => err("no blocks"),
        },
        Some("blockchain.block.header") => {
            let h = params.first().and_then(|v| v.as_u64()).unwrap_or(u64::MAX) as u32;
            match chain
                .block_hash(h)
                .ok()
                .flatten()
                .and_then(|hash| chain.block(&hash).ok())
            {
                Some(b) => ok(json!(hex::encode(serialize(&b.header)))),
                None => err("height out of range"),
            }
        }
        Some("blockchain.transaction.id_from_pos") => {
            let h = params.first().and_then(|v| v.as_u64()).unwrap_or(u64::MAX) as u32;
            let pos = params.get(1).and_then(|v| v.as_u64()).unwrap_or(u64::MAX) as usize;
            let block = chain
                .block_hash(h)
                .ok()
                .flatten()
                .and_then(|hash| chain.block(&hash).ok());
            match block {
                Some(b) => {
                    let n = if s.truncate.load(Ordering::SeqCst) {
                        b.txdata.len().saturating_sub(1)
                    } else {
                        b.txdata.len()
                    };
                    if pos < n {
                        ok(json!(b.txdata[pos].compute_txid().to_string()))
                    } else {
                        err("no tx at position")
                    }
                }
                None => err("height out of range"),
            }
        }
        Some("blockchain.transaction.get") => {
            drop(chain);
            let txid = params
                .first()
                .and_then(|v| v.as_str())
                .and_then(|t| t.parse::<Txid>().ok());
            match txid.and_then(|t| s.find_tx(&t)) {
                Some(tx) => ok(json!(hex::encode(serialize(&tx)))),
                None => err("No such mempool or blockchain transaction"),
            }
        }
        Some("blockchain.scripthash.listunspent") => {
            drop(chain);
            let want = params
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            // find the script with that hash among every output we know
            let scripts: Vec<ScriptBuf> = {
                let chain = s.chain.lock().unwrap();
                chain
                    .blocks()
                    .iter()
                    .flat_map(|b| b.txdata.iter())
                    .chain(s.mempool.lock().unwrap().iter())
                    .flat_map(|t| t.output.iter().map(|o| o.script_pubkey.clone()))
                    .collect()
            };
            let list: Vec<Value> = scripts
                .iter()
                .find(|sc| scripthash(sc) == want)
                .map(|sc| {
                    s.utxos(sc)
                        .into_iter()
                        .map(|(op, value, h)| json!({"tx_hash": op.txid.to_string(), "tx_pos": op.vout, "height": h.unwrap_or(0), "value": value}))
                        .collect()
                })
                .unwrap_or_default();
            ok(Value::Array(list))
        }
        Some("blockchain.transaction.broadcast") => {
            drop(chain);
            let hex = params.first().and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(hex)
                .ok()
                .and_then(|b| deserialize::<Transaction>(&b).ok())
            {
                Some(tx) => {
                    let txid = tx.compute_txid();
                    s.mempool.lock().unwrap().push(tx);
                    ok(json!(txid.to_string()))
                }
                None => err("TX decode failed"),
            }
        }
        _ => err("unknown method"),
    }
}
