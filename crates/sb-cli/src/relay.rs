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
use bitcoin::{OutPoint, Transaction, Txid};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use sb_indexer::carrier::{CarrierMode, MEMO_MAGIC, carrier_output, memo_output};
use sb_indexer::{ChainSource, Indexer, StateStore, TransferCheck};
use sb_primitives::Fr;
use sb_wallet::Wallet;

use crate::funding::{Chain, Coin, FundingState, FundingWallet, Publisher};
use crate::http::{post_json, read_request, respond};

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayRequest {
    pub envelope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// A carrier built from the fee wallet but not yet broadcast: one
/// transaction (OP_RETURN mode) or a commit-and-reveal pair, the counters
/// it advanced, and the miner fee it pays in total.
pub struct Carrier {
    pub txs: Vec<Transaction>,
    pub next: FundingState,
    pub fee: u64,
}

impl Carrier {
    /// The carrier's txid: the reveal's in witness mode.
    pub fn txid(&self) -> Txid {
        self.txs
            .last()
            .expect("a carrier has a transaction")
            .compute_txid()
    }
}

/// Miner fee of `tx`: its inputs' values (looked up) minus its outputs'.
pub(crate) fn tx_fee(tx: &Transaction, value_of: impl Fn(&OutPoint) -> Option<u64>) -> Result<u64> {
    let mut ins = 0u64;
    for i in &tx.input {
        ins += value_of(&i.previous_output)
            .ok_or_else(|| anyhow!("fee: unknown input {}", i.previous_output))?;
    }
    let outs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    ins.checked_sub(outs)
        .ok_or_else(|| anyhow!("fee: outputs exceed inputs"))
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

    pub(crate) fn funding_state(&self) -> FundingState {
        FundingState {
            receive: self.wallet.funding_receive,
            change: self.wallet.funding_change,
        }
    }

    /// Replay to the tip (at most once per `sync_interval`); the check below
    /// is against the next block.
    pub(crate) fn refresh(&mut self) -> Result<u32> {
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

    /// Are any of these nullifiers in a carrier paid for but not yet replayed?
    pub(crate) fn is_pending(&self, nullifiers: &[Fr]) -> bool {
        nullifiers.iter().any(|nf| self.pending.contains(nf))
    }

    pub(crate) fn mark_pending(&mut self, nullifiers: impl IntoIterator<Item = Fr>) {
        self.pending.extend(nullifiers);
    }

    /// One more submission from `ip` allowed within the last minute?
    pub(crate) fn admit(&mut self, ip: IpAddr) -> bool {
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

    /// The envelope as the indexer would see it at `tip + 1` (profile §11),
    /// plus the publication rules every paying service shares: transfers
    /// only (a mint pays the vault), and a memo must be a payout memo that
    /// fits a standard OP_RETURN.
    pub(crate) fn check(&mut self, envelope: &[u8], memo: Option<&[u8]>) -> Result<TransferCheck> {
        let tip = self.refresh()?;
        let check = self
            .indexer
            .check_transfer(envelope, tip + 1)
            .map_err(|e| anyhow!("rejected: {e}"))?
            .ok_or_else(|| anyhow!("rejected: a mint pays the vault; publish it yourself"))?;
        if let Some(m) = memo {
            if !m.starts_with(&MEMO_MAGIC) || m.len() > 80 {
                bail!("rejected: memo must start with \"sbx\" and fit a standard OP_RETURN");
            }
        }
        Ok(check)
    }

    /// Build the carrier from the fee wallet's coins at this service's fee
    /// rate, without broadcasting it.
    pub(crate) fn build_carrier(&self, envelope: &[u8], memo: Option<&[u8]>) -> Result<Carrier> {
        let (coins, st) = self
            .funding
            .coins(self.publisher.as_ref(), self.funding_state())?;
        self.build_carrier_from(&coins, st, envelope, memo)
    }

    /// [`Self::build_carrier`] from given coins (the fee vault prices a
    /// carrier before the envelope exists, from the same coins).
    pub(crate) fn build_carrier_from(
        &self,
        coins: &[Coin],
        st: FundingState,
        envelope: &[u8],
        memo: Option<&[u8]>,
    ) -> Result<Carrier> {
        let value_of = |o: &OutPoint| {
            coins
                .iter()
                .find(|c| c.utxo.outpoint == *o)
                .map(|c| c.utxo.value)
        };
        if self.indexer.deployment.carrier == CarrierMode::Witness {
            let key = self.funding.key(Chain::Receive, 0)?;
            let p = crate::witness::build_pair(
                &self.funding,
                &key,
                coins,
                st,
                envelope,
                vec![],
                memo,
                self.fee_rate,
                self.network,
            )?;
            let commit_fee = tx_fee(&p.commit, value_of)?;
            let commit_txid = p.commit.compute_txid();
            let reveal_fee = tx_fee(&p.reveal, |o| {
                (o.txid == commit_txid)
                    .then(|| {
                        p.commit
                            .output
                            .get(o.vout as usize)
                            .map(|x| x.value.to_sat())
                    })
                    .flatten()
            })?;
            Ok(Carrier {
                txs: vec![p.commit, p.reveal],
                next: p.next,
                fee: commit_fee + reveal_fee,
            })
        } else {
            let mut outputs = vec![carrier_output(envelope)];
            if let Some(m) = memo {
                outputs.push(memo_output(m));
            }
            let (tx, next) = self.funding.build_tx(coins, st, outputs, self.fee_rate)?;
            let fee = tx_fee(&tx, value_of)?;
            Ok(Carrier {
                txs: vec![tx],
                next,
                fee,
            })
        }
    }

    /// Persist the counters the carrier advanced, then broadcast it.
    pub(crate) fn broadcast_carrier(&mut self, c: &Carrier) -> Result<Txid> {
        // counters first: a crash after the broadcast must not reuse the
        // change address (an unused index is the harmless outcome)
        self.wallet.funding_receive = c.next.receive;
        self.wallet.funding_change = c.next.change;
        self.wallet.save(&self.wallet_path)?;
        let mut txid = None;
        for tx in &c.txs {
            txid = Some(self.publisher.broadcast(tx)?);
        }
        txid.ok_or_else(|| anyhow!("empty carrier"))
    }

    /// Check, pay and broadcast one envelope.
    pub fn relay(&mut self, envelope: &[u8], memo: Option<&[u8]>) -> Result<Txid> {
        let check = self.check(envelope, memo)?;
        if self.is_pending(&check.nullifiers) {
            bail!("rejected: already relayed, waiting for a block");
        }
        let hour_ago = Instant::now() - Duration::from_secs(3600);
        self.paid_at.retain(|t| *t > hour_ago);
        if self.paid_at.len() as u32 >= self.max_per_hour {
            bail!("busy: hourly budget spent, try later");
        }
        let carrier = self.build_carrier(envelope, memo)?;
        let txid = self.broadcast_carrier(&carrier)?;
        self.mark_pending(check.nullifiers);
        self.paid_at.push(Instant::now());
        log::info!(
            "relayed transfer {} (anchor {}) in {txid}, fee {} sat",
            hex::encode(&sb_primitives::encoding::fr_to_bytes(&check.h_body)[..8]),
            check.h_anchor,
            carrier.fee
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
    let v = post_json(&url, &req, "relayer")?;
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
