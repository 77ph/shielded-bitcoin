//! Sponsored relayer (deployment layer, docs/BOUNDARY.md "Fee funding"):
//! an HTTP endpoint that publishes other people's transfer envelopes from
//! its own fee wallet, after checking each one against its own replayed
//! state exactly as the indexer would at the next block.
//!
//! * Who pays: the relayer's operator, from the relayer wallet's fee coins.
//! * What it sees: the envelope and memo (public on chain anyway), the
//!   client's network address and the submission time. Nothing private to
//!   the transfer: the relayer cannot decrypt notes or alter the body.
//! * When unavailable: the client keeps the envelope in its outbox and
//!   self-funds it, funds it from another wallet, or tries another relayer.
//!
//! The wire format is one JSON object per request:
//! `POST /relay {"envelope": "<hex>", "memo": "<hex>"?}` →
//! `{"txid": "..."}` or `{"error": "..."}` (HTTP 400); `GET /info` →
//! deployment name, network, replayed tip and fee rate.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use sb_indexer::{ChainSource, Indexer, StateStore};
use sb_primitives::Fr;
use sb_wallet::Wallet;

use crate::funding::{FundingState, FundingWallet, Publisher};

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayRequest {
    pub envelope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// Largest request body accepted (an envelope is 700 bytes = 1400 hex).
const MAX_BODY: usize = 16 * 1024;

/// A running relayer: indexer, chain, fee wallet and the policy knobs.
pub struct Relayer {
    pub indexer: Indexer,
    pub store: Box<dyn StateStore>,
    pub chain: Box<dyn ChainSource>,
    pub publisher: Box<dyn Publisher>,
    pub funding: FundingWallet,
    pub wallet: Wallet,
    pub wallet_path: PathBuf,
    pub fee_rate: u64,
    pub max_per_hour: u32,
    /// Nullifiers of transfers already paid for but not yet replayed, so the
    /// same envelope is not paid twice while it sits in the mempool.
    pending: HashSet<Fr>,
    paid_at: Vec<Instant>,
}

impl Relayer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        indexer: Indexer,
        store: Box<dyn StateStore>,
        chain: Box<dyn ChainSource>,
        publisher: Box<dyn Publisher>,
        funding: FundingWallet,
        wallet: Wallet,
        wallet_path: PathBuf,
        fee_rate: u64,
        max_per_hour: u32,
    ) -> Self {
        Relayer {
            indexer,
            store,
            chain,
            publisher,
            funding,
            wallet,
            wallet_path,
            fee_rate,
            max_per_hour,
            pending: HashSet::new(),
            paid_at: Vec::new(),
        }
    }

    fn funding_state(&self) -> FundingState {
        FundingState {
            receive: self.wallet.funding_receive,
            change: self.wallet.funding_change,
        }
    }

    /// Replay to the tip; the check below is against the next block.
    fn refresh(&mut self) -> Result<u32> {
        self.indexer
            .sync_with(self.chain.as_ref(), Some(self.store.as_mut()))?;
        // paid-for transfers that have been replayed no longer need tracking
        let replayed = &self.indexer.state.nullifiers;
        self.pending.retain(|nf| !replayed.contains(nf));
        self.indexer
            .state
            .last_height()
            .ok_or_else(|| anyhow!("indexer has not replayed any block"))
    }

    /// Check, pay and broadcast one envelope.
    pub fn relay(&mut self, envelope: &[u8], memo: Option<&[u8]>) -> Result<Txid> {
        let tip = self.refresh()?;
        let check = self
            .indexer
            .check_transfer(envelope, tip + 1)
            .map_err(|e| anyhow!("rejected: {e}"))?
            .ok_or_else(|| anyhow!("rejected: a mint pays the vault; publish it yourself"))?;
        if check.nullifiers.iter().any(|nf| self.pending.contains(nf)) {
            bail!("rejected: already relayed, waiting for a block");
        }
        if let Some(m) = memo {
            if !m.starts_with(&sb_indexer::carrier::MEMO_MAGIC) || m.len() > 80 {
                bail!("rejected: memo must start with \"sbx\" and fit a standard OP_RETURN");
            }
        }
        let hour_ago = Instant::now() - Duration::from_secs(3600);
        self.paid_at.retain(|t| *t > hour_ago);
        if self.paid_at.len() as u32 >= self.max_per_hour {
            bail!("busy: hourly budget spent, try later");
        }
        let mut outputs = vec![sb_indexer::carrier::carrier_output(envelope)];
        if let Some(m) = memo {
            outputs.push(sb_indexer::carrier::memo_output(m));
        }
        let (tx, next) = self.funding.pay(
            self.publisher.as_ref(),
            self.funding_state(),
            outputs,
            self.fee_rate,
        )?;
        let txid = self.publisher.broadcast(&tx)?;
        self.wallet.funding_receive = next.receive;
        self.wallet.funding_change = next.change;
        self.wallet.save(&self.wallet_path)?;
        self.pending.extend(check.nullifiers);
        self.paid_at.push(Instant::now());
        log::info!(
            "relayed transfer {} (anchor {}) in {txid}",
            hex::encode(&sb_primitives::encoding::fr_to_bytes(&check.h_body)[..8]),
            check.h_anchor
        );
        Ok(txid)
    }

    pub fn info(&mut self) -> Value {
        let tip = self.refresh().ok();
        json!({
            "deployment": self.indexer.deployment.name,
            "network": format!("{:?}", self.indexer.deployment.network).to_lowercase(),
            "tip": tip,
            "fee_rate": self.fee_rate,
        })
    }

    /// Serve until `max_requests` requests were answered (`None`: forever).
    pub fn serve(&mut self, listener: TcpListener, max_requests: Option<u32>) -> Result<()> {
        let mut served = 0u32;
        while max_requests.is_none_or(|m| served < m) {
            let (conn, peer) = listener.accept()?;
            let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
            let (status, body) = match read_request(&conn) {
                Ok((method, path, body)) => self.handle(&method, &path, &body),
                Err(e) => (400, json!({"error": e.to_string()})),
            };
            log::info!("{peer}: {status}");
            respond(conn, status, &body);
            served += 1;
        }
        Ok(())
    }

    fn handle(&mut self, method: &str, path: &str, body: &[u8]) -> (u16, Value) {
        match (method, path) {
            ("GET", "/info") => (200, self.info()),
            ("POST", "/relay") => {
                let req: RelayRequest = match serde_json::from_slice(body) {
                    Ok(r) => r,
                    Err(e) => return (400, json!({"error": format!("bad request: {e}")})),
                };
                let envelope = match hex::decode(&req.envelope) {
                    Ok(e) => e,
                    Err(e) => return (400, json!({"error": format!("bad envelope hex: {e}")})),
                };
                let memo = match req.memo.as_deref().map(hex::decode).transpose() {
                    Ok(m) => m,
                    Err(e) => return (400, json!({"error": format!("bad memo hex: {e}")})),
                };
                match self.relay(&envelope, memo.as_deref()) {
                    Ok(txid) => (200, json!({"txid": txid.to_string()})),
                    Err(e) => (400, json!({"error": format!("{e:#}")})),
                }
            }
            _ => (404, json!({"error": "not found"})),
        }
    }
}

/// Request line, path and body of one HTTP/1.1 request.
fn read_request(conn: &TcpStream) -> Result<(String, String, Vec<u8>)> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        bail!("empty request");
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        bail!("malformed request line");
    };
    let (method, path) = (method.to_string(), path.to_string());
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            bail!("truncated headers");
        }
        if h.trim().is_empty() {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().context("content-length")?;
        }
    }
    if content_length > MAX_BODY {
        bail!("body too large");
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).context("body")?;
    Ok((method, path, body))
}

fn respond(mut conn: TcpStream, status: u16, body: &Value) {
    let out = serde_json::to_vec(body).unwrap_or_default();
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        match status {
            200 => "OK",
            404 => "Not Found",
            _ => "Bad Request",
        },
        out.len()
    );
    let _ = conn.write_all(header.as_bytes());
    let _ = conn.write_all(&out);
    let _ = conn.flush();
}

/// Client side: hand an envelope to a relayer and return the carrier txid.
pub fn submit(url: &str, envelope: &[u8], memo: Option<&[u8]>) -> Result<Txid> {
    let req = RelayRequest {
        envelope: hex::encode(envelope),
        memo: memo.map(hex::encode),
    };
    let url = format!("{}/relay", url.trim_end_matches('/'));
    let resp = ureq::post(&url)
        .timeout(Duration::from_secs(120))
        .send_json(&req)
        .map_err(|e| match e {
            ureq::Error::Status(code, r) => {
                let text = r.into_string().unwrap_or_default();
                let msg = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v["error"].as_str().map(str::to_string))
                    .unwrap_or(text);
                anyhow!("relayer refused ({code}): {}", msg.trim())
            }
            other => anyhow!("relayer unreachable: {other}"),
        })?;
    let v: Value = resp.into_json().context("relayer response")?;
    v["txid"]
        .as_str()
        .ok_or_else(|| anyhow!("relayer response has no txid: {v}"))?
        .parse()
        .context("txid")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request that never completes its headers is answered 400 and does
    /// not stall the server; so is an oversized body.
    #[test]
    fn malformed_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut replies = Vec::new();
            for _ in 0..4 {
                let (conn, _) = listener.accept().unwrap();
                let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
                let (status, body) = match read_request(&conn) {
                    Ok((m, p, b)) => (200, json!({"m": m, "p": p, "n": b.len()})),
                    Err(e) => (400, json!({"error": e.to_string()})),
                };
                replies.push(status);
                respond(conn, status, &body);
            }
            replies
        });
        let send = |raw: &str| -> String {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(raw.as_bytes()).unwrap();
            let _ = c.shutdown(std::net::Shutdown::Write);
            let mut s = String::new();
            c.read_to_string(&mut s).unwrap();
            s
        };
        assert!(send("").contains("400"));
        assert!(send("GARBAGE\r\n").contains("400"));
        assert!(
            send("POST /relay HTTP/1.1\r\nContent-Length: 999999\r\n\r\n").contains("too large")
        );
        let ok = send("POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc");
        assert!(ok.contains("200") && ok.contains("\"n\":3"), "{ok}");
        assert_eq!(t.join().unwrap(), vec![400, 400, 400, 200]);
    }

    #[test]
    fn submit_reports_refusals_and_outages() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for reply in [
                (400, json!({"error": "rejected: proof does not verify"})),
                (200, json!({"nope": 1})),
            ] {
                let (conn, _) = listener.accept().unwrap();
                let _ = read_request(&conn);
                respond(conn, reply.0, &reply.1);
            }
        });
        let url = format!("http://{addr}");
        let e = submit(&url, b"xx", None).unwrap_err().to_string();
        assert!(e.contains("refused (400)") && e.contains("proof"), "{e}");
        let e = submit(&url, b"xx", Some(b"sbx")).unwrap_err().to_string();
        assert!(e.contains("no txid"), "{e}");
        let e = submit("http://127.0.0.1:1", b"xx", None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("unreachable"), "{e}");
    }
}
