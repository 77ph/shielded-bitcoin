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

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, TcpListener};
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
use crate::http::{read_request, respond};

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayRequest {
    pub envelope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// A running relayer: indexer, chain, fee wallet and the policy knobs.
pub struct Relayer {
    pub indexer: Indexer,
    pub store: Box<dyn StateStore>,
    pub chain: Box<dyn ChainSource>,
    pub publisher: Box<dyn Publisher>,
    pub funding: FundingWallet,
    pub wallet: Wallet,
    pub wallet_path: PathBuf,
    pub network: bitcoin::Network,
    pub fee_rate: u64,
    pub max_per_hour: u32,
    /// Nullifiers of transfers already paid for but not yet replayed, so the
    /// same envelope is not paid twice while it sits in the mempool.
    pending: HashSet<Fr>,
    paid_at: Vec<Instant>,
    /// The check path (replay to tip, proof verification) is the expensive
    /// one: at most this many submissions per client address per minute.
    pub max_checks_per_minute: u32,
    checks: HashMap<IpAddr, Vec<Instant>>,
    /// Replay to the tip at most this often; between syncs the last tip serves.
    pub sync_interval: Duration,
    last_sync: Option<Instant>,
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
        network: bitcoin::Network,
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
            network,
            fee_rate,
            max_per_hour,
            pending: HashSet::new(),
            paid_at: Vec::new(),
            max_checks_per_minute: 6,
            checks: HashMap::new(),
            sync_interval: Duration::from_secs(5),
            last_sync: None,
        }
    }

    fn funding_state(&self) -> FundingState {
        FundingState {
            receive: self.wallet.funding_receive,
            change: self.wallet.funding_change,
        }
    }

    /// Replay to the tip (at most once per `sync_interval`); the check below
    /// is against the next block.
    fn refresh(&mut self) -> Result<u32> {
        if self
            .last_sync
            .is_none_or(|t| t.elapsed() >= self.sync_interval)
        {
            self.indexer
                .sync_with(self.chain.as_ref(), Some(self.store.as_mut()))?;
            self.last_sync = Some(Instant::now());
            // paid-for transfers that have been replayed no longer need tracking
            let replayed = &self.indexer.state.nullifiers;
            self.pending.retain(|nf| !replayed.contains(nf));
        }
        self.indexer
            .state
            .last_height()
            .ok_or_else(|| anyhow!("indexer has not replayed any block"))
    }

    /// One more submission from `ip` allowed within the last minute?
    fn admit(&mut self, ip: IpAddr) -> bool {
        let minute_ago = Instant::now() - Duration::from_secs(60);
        let times = self.checks.entry(ip).or_default();
        times.retain(|t| *t > minute_ago);
        if times.len() as u32 >= self.max_checks_per_minute {
            return false;
        }
        times.push(Instant::now());
        self.checks.retain(|_, t| !t.is_empty());
        true
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
        let txid = if self.indexer.deployment.carrier == sb_indexer::carrier::CarrierMode::Witness {
            let key = self.funding.key(crate::funding::Chain::Receive, 0)?;
            let (coins, st) = self
                .funding
                .coins(self.publisher.as_ref(), self.funding_state())?;
            let p = crate::witness::build_pair(
                &self.funding,
                &key,
                &coins,
                st,
                envelope,
                vec![],
                memo,
                self.fee_rate,
                self.network,
            )?;
            self.wallet.funding_receive = p.next.receive;
            self.wallet.funding_change = p.next.change;
            self.wallet.save(&self.wallet_path)?;
            let (_, r) = crate::witness::broadcast(self.publisher.as_ref(), &p)?;
            r
        } else {
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
            // counters first: a crash after the broadcast must not reuse the
            // change address (an unused index is the harmless outcome)
            self.wallet.funding_receive = next.receive;
            self.wallet.funding_change = next.change;
            self.wallet.save(&self.wallet_path)?;
            self.publisher.broadcast(&tx)?
        };
        self.pending.extend(check.nullifiers);
        self.paid_at.push(Instant::now());
        log::info!(
            "relayed transfer {} (anchor {}) in {txid}",
            hex::encode(&sb_primitives::encoding::fr_to_bytes(&check.h_body)[..8]),
            check.h_anchor
        );
        Ok(txid)
    }

    /// Cheap: the last replayed tip, no sync.
    pub fn info(&self) -> Value {
        let tip = self.indexer.state.last_height();
        json!({
            "deployment": self.indexer.deployment.name,
            "network": format!("{:?}", self.indexer.deployment.network).to_lowercase(),
            "tip": tip,
            "fee_rate": self.fee_rate,
        })
    }

    /// Serve until `max_requests` requests were answered (`None`: forever).
    /// The first replay happens here, before the first request.
    pub fn serve(&mut self, listener: TcpListener, max_requests: Option<u32>) -> Result<()> {
        self.refresh()?;
        let mut served = 0u32;
        while max_requests.is_none_or(|m| served < m) {
            let (conn, peer) = listener.accept()?;
            let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
            let (status, body) = match read_request(&conn) {
                Ok((method, path, body)) => self.handle(&method, &path, &body, peer.ip()),
                Err(e) => (400, json!({"error": e.to_string()})),
            };
            log::info!("{peer}: {status}");
            respond(conn, status, &body);
            served += 1;
        }
        Ok(())
    }

    fn handle(&mut self, method: &str, path: &str, body: &[u8], ip: IpAddr) -> (u16, Value) {
        match (method, path) {
            ("GET", "/info") => (200, self.info()),
            ("POST", "/relay") => {
                if !self.admit(ip) {
                    return (
                        429,
                        json!({"error": "busy: too many submissions from this address, try later"}),
                    );
                }
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
    use std::net::TcpListener;

    #[test]
    fn admission_is_per_address_per_minute() {
        let mut checks: HashMap<IpAddr, Vec<Instant>> = HashMap::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let max = 3u32;
        let mut admit = |ip: IpAddr| {
            let minute_ago = Instant::now() - Duration::from_secs(60);
            let times = checks.entry(ip).or_default();
            times.retain(|t| *t > minute_ago);
            if times.len() as u32 >= max {
                return false;
            }
            times.push(Instant::now());
            true
        };
        assert!((0..3).all(|_| admit(a)));
        assert!(!admit(a));
        assert!(admit(b));
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
