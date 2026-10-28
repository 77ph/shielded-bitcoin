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

/// SHA-256 of a DER certificate, the fingerprint Electrum clients pin.
fn fingerprint(cert: &rustls::pki_types::CertificateDer<'_>) -> [u8; 32] {
    sha256::Hash::hash(cert.as_ref()).to_byte_array()
}

/// Accepts exactly one server certificate, identified by its SHA-256
/// fingerprint (`ssl-pin://`): the usual Electrum trust-on-first-use pin.
/// TLS signatures are still verified with the provider's algorithms.
#[derive(Debug)]
struct PinnedCert {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if fingerprint(end_entity) == self.pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Records the fingerprint of the certificate a server presents and then
/// rejects the handshake, so [`Electrum::fingerprint`] never exchanges
/// application data with an unverified peer.
#[derive(Debug)]
struct CaptureFingerprint {
    seen: std::sync::Mutex<Option<[u8; 32]>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for CaptureFingerprint {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.seen.lock().unwrap() = Some(fingerprint(end_entity));
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct Electrum {
    host: String,
    port: u16,
    tls: bool,
    /// `ssl-pin://`: accept only the certificate with this SHA-256 fingerprint.
    pin: Option<[u8; 32]>,
    stream: RefCell<Option<BufReader<Box<dyn ReadWrite>>>>,
    next_id: Cell<u64>,
    /// `block_hash` results, so `block(hash)` knows the height.
    headers: RefCell<HashMap<BlockHash, (u32, Header)>>,
}

impl Electrum {
    /// `url` like `ssl://mempool.space:60602` (certificate checked against the
    /// public roots), `ssl-pin://host:port/<sha256-hex>` (self-signed server
    /// pinned by fingerprint, see [`Electrum::fingerprint`]) or `tcp://host:50001`.
    pub fn new(url: &str) -> Result<Self, ChainError> {
        let (tls, rest, pin) = if let Some(r) = url.strip_prefix("ssl-pin://") {
            let (hp, fp) = r.split_once('/').ok_or_else(|| {
                ChainError::Rpc(format!(
                    "electrum url {url:?}: expected ssl-pin://host:port/<sha256-hex>"
                ))
            })?;
            let fp: [u8; 32] = hex::decode(fp)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| {
                    ChainError::Rpc("ssl-pin fingerprint must be 32 bytes of hex".into())
                })?;
            (true, hp, Some(fp))
        } else if let Some(r) = url.strip_prefix("ssl://") {
            (true, r, None)
        } else if let Some(r) = url.strip_prefix("tcp://") {
            (false, r, None)
        } else {
            (true, url, None)
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
            pin,
            stream: RefCell::new(None),
            next_id: Cell::new(1),
            headers: RefCell::new(HashMap::new()),
        })
    }

    /// Connect to the first reachable address (hosts often publish an IPv6
    /// address that the client cannot route).
    fn tcp(&self) -> Result<TcpStream, ChainError> {
        let addrs: Vec<_> = (self.host.as_str(), self.port).to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(ChainError::Rpc(format!("cannot resolve {}", self.host)));
        }
        let mut last = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
                Ok(tcp) => {
                    tcp.set_read_timeout(Some(Duration::from_secs(60)))?;
                    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
                    return Ok(tcp);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap().into())
    }

    fn tls_builder() -> Result<
        (
            rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
            Arc<rustls::crypto::CryptoProvider>,
        ),
        ChainError,
    > {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| ChainError::Rpc(format!("tls: {e}")))?;
        Ok((builder, provider))
    }

    /// The SHA-256 fingerprint of the certificate `host:port` presents, for
    /// trust-on-first-use pinning. The handshake is aborted after the
    /// certificate is seen; nothing is sent or received.
    pub fn fingerprint(host: &str, port: u16) -> Result<[u8; 32], ChainError> {
        let (builder, provider) = Self::tls_builder()?;
        let capture = Arc::new(CaptureFingerprint {
            seen: std::sync::Mutex::new(None),
            provider,
        });
        let config = builder
            .dangerous()
            .with_custom_certificate_verifier(capture.clone())
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| ChainError::Rpc(format!("tls name: {e}")))?;
        let probe = Electrum::new(&format!("tcp://{host}:{port}"))?;
        let mut tcp = probe.tcp()?;
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name)
            .map_err(|e| ChainError::Rpc(format!("tls: {e}")))?;
        // Drive the handshake until the verifier has run (it always fails).
        let _ = conn.complete_io(&mut tcp);
        let seen = *capture.seen.lock().unwrap();
        seen.ok_or_else(|| ChainError::Rpc("server presented no certificate".into()))
    }

    fn connect(&self) -> Result<BufReader<Box<dyn ReadWrite>>, ChainError> {
        let tcp = self.tcp()?;
        let stream: Box<dyn ReadWrite> = if self.tls {
            let (builder, provider) = Self::tls_builder()?;
            let config = match self.pin {
                Some(pin) => builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinnedCert { pin, provider }))
                    .with_no_client_auth(),
                None => {
                    let roots = rustls::RootCertStore {
                        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
                    };
                    builder.with_root_certificates(roots).with_no_client_auth()
                }
            };
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
