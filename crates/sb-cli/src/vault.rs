//! Fee vault (deployment layer, `docs/FEE-VAULT.md`): publication paid in
//! shielded credit, the paper's fee-unlock vault (§20.5) with the
//! operator's code in place of the PIPE covenant.
//!
//! * Who pays: the client, from credit it deposited as a shielded note to
//!   the vault; the vault's transparent fee wallet (the pool) fronts the
//!   miner fee and is paid back in shielded value.
//! * What it sees: its own deposit notes, and per draw the envelope, memo,
//!   `h_body`, kind, time and client address; never the transfer.
//! * When unavailable: the carrier stays in the client's outbox and any
//!   other fee model publishes it; credit waits.
//!
//! Wire (FEE-VAULT.md §7): `GET /info`, `GET /credit/<P>`, `POST /draw`,
//! `POST /reclaim`, one JSON object each.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{OutPoint, Transaction, Txid};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use sb_core::address::PaymentAddress;
use sb_core::envelope::{ENVELOPE_LEN, Envelope, parse_envelope};
use sb_core::feeauth::key_commitment;
use sb_indexer::Deployment;
use sb_indexer::carrier::MEMO_MAGIC;
use sb_primitives::Fr;
use sb_primitives::encoding::{fr_from_bytes, fr_to_bytes};
use sb_wallet::wallet::FeeAccountRecord;
use sb_wallet::{Wallet, anchor_for};

use crate::feeauth::{AuthKey, draw_message, reclaim_message, verify};
use crate::funding::{Chain, Coin, FundingState, Utxo};
use crate::http::{get_json, post_json, read_request, respond};
use crate::relay::Relayer;
use crate::{Ctx, OutboxEntry, PublishMode};

const SERVICE: &str = "fee vault";
/// Payout memo size used for the withdraw fee estimate (`sbx` ‖ version ‖
/// amount ‖ a P2TR script).
const WITHDRAW_MEMO_LEN: usize = 46;

// ---------------------------------------------------------------- ledger

/// A draw (§6): what was charged for which publication, and what is
/// needed to re-broadcast it until replay accepts it (I3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Draw {
    pub txid: String,
    pub h_body: String,
    pub fee: u64,
    pub at: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nullifiers: Vec<String>,
    #[serde(default)]
    pub settled: bool,
}

/// A reclaim (§5 R-R): the whole credit consumed, what was paid back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reclaim {
    pub txid: String,
    pub h_body: String,
    pub credit: u64,
    pub paid: u64,
    pub fee: u64,
    pub at: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nullifiers: Vec<String>,
    #[serde(default)]
    pub settled: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    pub released: u64,
    pub reclaimed: u64,
    #[serde(default)]
    pub draws: Vec<Draw>,
    #[serde(default)]
    pub reclaims: Vec<Reclaim>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default)]
    pub accounts: BTreeMap<String, Account>,
}

impl Ledger {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).with_context(|| format!("ledger {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
            Err(e) => Err(e).with_context(|| format!("ledger {}", path.display())),
        }
    }

    /// Write atomically (temporary file, then rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn released_total(&self) -> u64 {
        self.accounts.values().map(|a| a.released).sum()
    }

    pub fn reclaimed_total(&self) -> u64 {
        self.accounts.values().map(|a| a.reclaimed).sum()
    }

    /// Fees earned: draws plus the fee part of reclaims.
    pub fn earned(&self) -> u64 {
        self.accounts
            .values()
            .map(|a| a.released + a.reclaims.iter().map(|r| r.fee).sum::<u64>())
            .sum()
    }
}

/// The backing bound of §6 I2 over a vault's wallet: every note received
/// from someone else may be credit, so `outstanding = received − released
/// − reclaimed`.
pub struct Backing {
    pub received: u64,
    pub released: u64,
    pub reclaimed: u64,
    pub outstanding: u64,
}

pub fn backing(wallet: &Wallet, ledger: &Ledger) -> Backing {
    let received: u64 = wallet
        .notes
        .iter()
        .filter(|n| !wallet.sent.iter().any(|s| s.is_change && s.pos == n.pos))
        .map(|n| n.value)
        .sum();
    let released = ledger.released_total();
    let reclaimed = ledger.reclaimed_total();
    Backing {
        received,
        released,
        reclaimed,
        outstanding: received.saturating_sub(released + reclaimed),
    }
}

// ------------------------------------------------------------------ wire

#[derive(Debug, Serialize, Deserialize)]
pub struct DrawRequest {
    pub envelope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// `P`, hex.
    pub key: String,
    pub max_fee: u64,
    /// BIP 340 signature, hex.
    pub sig: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReclaimRequest {
    pub key: String,
    /// Encoded shielded address to pay.
    pub address: String,
    /// What the client believes it deposited under the key.
    pub deposited: u64,
    pub sig: String,
}

/// Credit of a key as the vault computes it (§4).
#[derive(Debug, Clone, Copy, Default)]
pub struct Credit {
    pub deposited: u64,
    pub unsettled: u64,
    pub released: u64,
    pub reclaimed: u64,
    pub credit: u64,
}

fn h_body_of(envelope: &[u8], const_salt: &[u8; 32]) -> Result<Fr> {
    match parse_envelope(envelope).map_err(|e| anyhow!("rejected: malformed envelope: {e}"))? {
        Envelope::Transfer(e) => Ok(e.body.h_body(const_salt)),
        Envelope::Swap(e) => Ok(e.body.h_body(const_salt)),
        Envelope::Mint(_) => {
            bail!("rejected: a mint pays the vault; the fee vault publishes transfers")
        }
    }
}

fn key_from_hex(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("bad key: 32 hex bytes expected"))
}

fn hex_fr(f: &Fr) -> String {
    hex::encode(fr_to_bytes(f))
}

// ----------------------------------------------------------------- vault

/// A running fee vault: the relayer's machinery (indexer, chain, pool),
/// the vault's shielded wallet (inside the relayer, it receives the
/// deposits), the ledger and the rule.
pub struct Vault {
    pub r: Relayer,
    pub ledger: Ledger,
    pub ledger_path: PathBuf,
    pub margin: u64,
    pub k_min: u32,
    const_salt: [u8; 32],
    params: sb_circuit::TransferParams,
}

impl Vault {
    pub fn new(
        r: Relayer,
        ledger_path: PathBuf,
        margin: u64,
        deployment: &Deployment,
        params: sb_circuit::TransferParams,
    ) -> Result<Self> {
        let ledger = Ledger::load(&ledger_path)?;
        Ok(Vault {
            r,
            ledger,
            ledger_path,
            margin,
            k_min: deployment.k_min,
            const_salt: deployment.const_salt,
            params,
        })
    }

    fn name(&self) -> &str {
        &self.r.indexer.deployment.name
    }

    /// Replay to the tip, scan the vault's wallet for deposits, settle
    /// ledger entries that replay has accepted.
    fn refresh(&mut self) -> Result<u32> {
        let tip = self.r.refresh()?;
        self.r.wallet.scan(
            &self.r.indexer.deployment.const_salt_fr(),
            &self.r.indexer.state.events,
            &self.r.indexer.state.nullifiers,
        )?;
        self.settle()?;
        Ok(tip)
    }

    /// Mark draws and reclaims whose transfer replay has accepted (I3):
    /// their raw transactions and nullifiers are no longer needed.
    fn settle(&mut self) -> Result<()> {
        let open: HashSet<String> = self
            .ledger
            .accounts
            .values()
            .flat_map(|a| {
                a.draws
                    .iter()
                    .filter(|d| !d.settled)
                    .map(|d| d.h_body.clone())
                    .chain(
                        a.reclaims
                            .iter()
                            .filter(|r| !r.settled)
                            .map(|r| r.h_body.clone()),
                    )
            })
            .collect();
        if open.is_empty() {
            return Ok(());
        }
        let accepted: HashSet<String> = self
            .r
            .indexer
            .state
            .events
            .iter()
            .map(|e| hex_fr(&e.h_body))
            .filter(|h| open.contains(h))
            .collect();
        if accepted.is_empty() {
            return Ok(());
        }
        for a in self.ledger.accounts.values_mut() {
            for d in a.draws.iter_mut().filter(|d| accepted.contains(&d.h_body)) {
                d.settled = true;
                d.raw.clear();
                d.nullifiers.clear();
            }
            for r in a
                .reclaims
                .iter_mut()
                .filter(|r| accepted.contains(&r.h_body))
            {
                r.settled = true;
                r.raw.clear();
                r.nullifiers.clear();
            }
        }
        self.ledger.save(&self.ledger_path)
    }

    /// Deposits under `key`: settled (at least `k_min` below `tip`) and
    /// not yet.
    fn deposited(&self, key: &[u8; 32], tip: u32) -> (u64, u64) {
        let c = hex_fr(&key_commitment(key));
        let (mut settled, mut unsettled) = (0u64, 0u64);
        for n in self.r.wallet.notes.iter().filter(|n| n.rseed == c) {
            if n.height.saturating_add(self.k_min) <= tip {
                settled += n.value;
            } else {
                unsettled += n.value;
            }
        }
        (settled, unsettled)
    }

    pub fn credit_of(&self, key: &[u8; 32], tip: u32) -> Credit {
        let (deposited, unsettled) = self.deposited(key, tip);
        let a = self
            .ledger
            .accounts
            .get(&hex::encode(key))
            .cloned()
            .unwrap_or_default();
        Credit {
            deposited,
            unsettled,
            released: a.released,
            reclaimed: a.reclaimed,
            credit: deposited.saturating_sub(a.released + a.reclaimed),
        }
    }

    fn require_deposit(&self, key: &[u8; 32], tip: u32) -> Result<Credit> {
        let cr = self.credit_of(key, tip);
        if cr.deposited == 0 {
            if cr.unsettled > 0 {
                bail!(
                    "deposit not settled yet: {} sat waits for depth {}",
                    cr.unsettled,
                    self.k_min
                );
            }
            bail!("no deposit for this key");
        }
        Ok(cr)
    }

    /// I1 over the whole ledger against the chain as the wallet sees it.
    fn check_i1(&self) -> Result<()> {
        for (key, a) in &self.ledger.accounts {
            let k = key_from_hex(key)?;
            let (s, u) = self.deposited(&k, u32::MAX);
            if a.released + a.reclaimed > s + u {
                bail!(
                    "ledger violates I1 for key {}: released {} + reclaimed {} > deposited {}; the chain no longer backs this ledger (a reorganisation?), resolve it by hand before serving",
                    &key[..16],
                    a.released,
                    a.reclaimed,
                    s + u
                );
            }
        }
        Ok(())
    }

    /// Restart (I3): settle what replay accepted, re-broadcast the rest,
    /// revert what the network refuses, rebuild the pending set. Runs
    /// before the first request is served.
    fn resolve_pending(&mut self) -> Result<()> {
        self.settle()?;
        let mut revert: Vec<(String, bool, usize)> = Vec::new();
        for (key, a) in &self.ledger.accounts {
            for (i, d) in a.draws.iter().enumerate().filter(|(_, d)| !d.settled) {
                if !self.rebroadcast(&d.raw)? {
                    log::warn!(
                        "draw {} of {} refused by the network; reverting",
                        d.txid,
                        &key[..16]
                    );
                    revert.push((key.clone(), true, i));
                }
            }
            for (i, r) in a.reclaims.iter().enumerate().filter(|(_, r)| !r.settled) {
                if !self.rebroadcast(&r.raw)? {
                    log::warn!(
                        "reclaim {} of {} refused by the network; reverting",
                        r.txid,
                        &key[..16]
                    );
                    revert.push((key.clone(), false, i));
                }
            }
        }
        // highest index first so earlier removals do not shift later ones
        revert.sort_by_key(|r| std::cmp::Reverse(r.2));
        for (key, is_draw, i) in revert {
            let a = self.ledger.accounts.get_mut(&key).expect("listed above");
            if is_draw {
                let d = a.draws.remove(i);
                a.released -= d.fee;
            } else {
                let r = a.reclaims.remove(i);
                a.reclaimed -= r.credit;
                self.unlock(&r.h_body);
            }
        }
        let pending: Vec<Fr> = self
            .ledger
            .accounts
            .values()
            .flat_map(|a| {
                a.draws
                    .iter()
                    .filter(|d| !d.settled)
                    .flat_map(|d| d.nullifiers.iter())
                    .chain(
                        a.reclaims
                            .iter()
                            .filter(|r| !r.settled)
                            .flat_map(|r| r.nullifiers.iter()),
                    )
            })
            .filter_map(|h| hex::decode(h).ok())
            .filter_map(|b| fr_from_bytes(&b).ok())
            .collect();
        self.r.mark_pending(pending);
        self.r.wallet.save(&self.r.wallet_path)?;
        self.ledger.save(&self.ledger_path)
    }

    /// Re-broadcast raw transactions; `false` if the network refused one
    /// for a reason other than already knowing it.
    fn rebroadcast(&self, raw: &[String]) -> Result<bool> {
        for r in raw {
            let tx: Transaction = deserialize_hex(r).context("ledger: raw transaction")?;
            match self.r.publisher.broadcast(&tx) {
                Ok(_) => {}
                Err(e) if e.to_string().to_lowercase().contains("already") => {}
                Err(e) => {
                    log::warn!("rebroadcast of {}: {e:#}", tx.compute_txid());
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Release the vault wallet's notes locked by a transfer that was not
    /// published.
    fn unlock(&mut self, h_body_hex: &str) {
        for n in self.r.wallet.notes.iter_mut() {
            if n.locked_by.as_deref() == Some(h_body_hex) {
                n.locked_by = None;
            }
        }
    }

    /// The fee of a one-input carrier for an envelope of the base length,
    /// at the vault's rate, plus the margin (§7 `fee_estimate`).
    fn estimate(&self, memo_len: Option<usize>) -> Option<u64> {
        let coin = Coin {
            utxo: Utxo {
                outpoint: OutPoint::null(),
                value: 1 << 40,
                confirmed: true,
            },
            chain: Chain::Receive,
            index: 0,
        };
        let memo = memo_len.map(|n| {
            let mut m = vec![0u8; n];
            m[..MEMO_MAGIC.len()].copy_from_slice(&MEMO_MAGIC);
            m
        });
        self.r
            .build_carrier_from(
                &[coin],
                FundingState::default(),
                &vec![0u8; ENVELOPE_LEN],
                memo.as_deref(),
            )
            .ok()
            .map(|c| c.fee + self.margin)
    }

    pub fn info(&self) -> Value {
        let mut v = self.r.info();
        let o = v.as_object_mut().expect("object");
        o.insert("margin".into(), json!(self.margin));
        o.insert(
            "carrier".into(),
            json!(format!("{:?}", self.r.indexer.deployment.carrier).to_lowercase()),
        );
        o.insert(
            "deposit_address".into(),
            json!(
                self.r
                    .wallet
                    .default_address()
                    .encode(self.r.indexer.deployment.network)
            ),
        );
        o.insert("min_depth".into(), json!(self.k_min));
        o.insert(
            "fee_estimate".into(),
            json!({
                "transfer": self.estimate(None),
                "withdraw": self.estimate(Some(WITHDRAW_MEMO_LEN)),
            }),
        );
        v
    }

    /// The release rule, R1–R5 of §5. Returns the carrier txid, the fee
    /// charged and the credit left.
    pub fn draw(&mut self, req: &DrawRequest) -> Result<(Txid, u64, u64)> {
        let envelope = hex::decode(&req.envelope).context("bad envelope hex")?;
        let memo = req
            .memo
            .as_deref()
            .map(hex::decode)
            .transpose()
            .context("bad memo hex")?;
        let key = key_from_hex(&req.key)?;
        let sig = hex::decode(&req.sig).context("bad signature hex")?;
        let tip = self.refresh()?;
        // R1: the authorization, before anything expensive
        let h_body = h_body_of(&envelope, &self.const_salt)?;
        let name = self.name().to_string();
        verify(
            &key,
            &draw_message(&name, &h_body, req.max_fee, memo.as_deref()),
            &sig,
        )?;
        // R2
        let cr = self.require_deposit(&key, tip)?;
        // R3
        let check = self.r.check(&envelope, memo.as_deref())?;
        let key_hex = hex::encode(key);
        let h_body_hex = hex_fr(&h_body);
        let already = self
            .ledger
            .accounts
            .values()
            .any(|a| a.draws.iter().any(|d| !d.settled && d.h_body == h_body_hex));
        if already || self.r.is_pending(&check.nullifiers) {
            bail!("rejected: already published, waiting for a block");
        }
        // R4
        let carrier = self.r.build_carrier(&envelope, memo.as_deref())?;
        let fee = carrier.fee + self.margin;
        if fee > req.max_fee {
            bail!("fee {fee} exceeds max_fee {}", req.max_fee);
        }
        if fee > cr.credit {
            bail!("insufficient credit: {}, need {fee}", cr.credit);
        }
        // R5: the ledger first
        let entry = Draw {
            txid: carrier.txid().to_string(),
            h_body: h_body_hex.clone(),
            fee,
            at: tip,
            raw: carrier.txs.iter().map(serialize_hex).collect(),
            nullifiers: check.nullifiers.iter().map(hex_fr).collect(),
            settled: false,
        };
        {
            let a = self.ledger.accounts.entry(key_hex.clone()).or_default();
            a.released += fee;
            a.draws.push(entry);
        }
        self.ledger.save(&self.ledger_path)?;
        match self.r.broadcast_carrier(&carrier) {
            Ok(txid) => {
                self.r.mark_pending(check.nullifiers);
                log::info!(
                    "draw by {}: transfer {} in {txid}, fee {fee} sat, credit left {}",
                    &key_hex[..16],
                    &h_body_hex[..16],
                    cr.credit - fee
                );
                Ok((txid, fee, cr.credit - fee))
            }
            Err(e) => {
                let a = self
                    .ledger
                    .accounts
                    .get_mut(&key_hex)
                    .expect("just written");
                a.released -= fee;
                a.draws.pop();
                self.ledger.save(&self.ledger_path)?;
                Err(anyhow!("broadcast failed, nothing charged: {e:#}"))
            }
        }
    }

    /// R-R of §5: return the whole credit of a key, less the fee of the
    /// transfer that returns it.
    pub fn reclaim(&mut self, req: &ReclaimRequest) -> Result<(Txid, u64, u64)> {
        let key = key_from_hex(&req.key)?;
        let sig = hex::decode(&req.sig).context("bad signature hex")?;
        let (net, to) =
            PaymentAddress::decode(&req.address).map_err(|e| anyhow!("bad address: {e}"))?;
        if net != self.r.indexer.deployment.network {
            bail!("address is for another network");
        }
        let tip = self.refresh()?;
        let name = self.name().to_string();
        verify(
            &key,
            &reclaim_message(&name, &req.address, req.deposited),
            &sig,
        )?;
        let cr = self.require_deposit(&key, tip)?;
        if req.deposited != cr.deposited {
            bail!(
                "deposited total mismatch: the vault sees {}, the request says {}",
                cr.deposited,
                req.deposited
            );
        }
        if cr.credit == 0 {
            bail!("nothing to reclaim");
        }
        // the fee, from the coins the carrier will use
        let (coins, st) = self
            .r
            .funding
            .coins(self.r.publisher.as_ref(), self.r.funding_state())?;
        let probe = self
            .r
            .build_carrier_from(&coins, st, &vec![0u8; ENVELOPE_LEN], None)?;
        let fee = probe.fee + self.margin;
        if cr.credit <= fee {
            bail!("credit {} does not cover the reclaim fee {fee}", cr.credit);
        }
        let amount = cr.credit - fee;
        // the transfer that pays it
        let h_anchor = anchor_for(tip, self.r.indexer.deployment.anchor_depth);
        let size = self
            .r
            .indexer
            .state
            .size_at(h_anchor)
            .ok_or_else(|| anyhow!("anchor {h_anchor} not replayed"))?;
        let built = self
            .r
            .wallet
            .build_send(
                &self.params,
                &self.const_salt,
                &self.r.indexer.state.tree,
                h_anchor,
                size,
                to,
                amount,
                &mut rand::thread_rng(),
            )
            .map_err(|e| {
                anyhow!("the vault cannot back this reclaim ({e}); the operator must restore the shielded balance")
            })?;
        let h_body_hex = hex_fr(&built.statement.h_body);
        let envelope = built.envelope.to_bytes();
        let carrier = match self.r.build_carrier_from(&coins, st, &envelope, None) {
            Ok(c) if c.fee + self.margin == fee => c,
            Ok(c) => {
                self.unlock(&h_body_hex);
                bail!(
                    "carrier fee changed while building ({} vs {fee}); try again",
                    c.fee + self.margin
                );
            }
            Err(e) => {
                self.unlock(&h_body_hex);
                return Err(e);
            }
        };
        let key_hex = hex::encode(key);
        let entry = Reclaim {
            txid: carrier.txid().to_string(),
            h_body: h_body_hex.clone(),
            credit: cr.credit,
            paid: amount,
            fee,
            at: tip,
            raw: carrier.txs.iter().map(serialize_hex).collect(),
            nullifiers: built.statement.nullifiers.iter().map(hex_fr).collect(),
            settled: false,
        };
        {
            let a = self.ledger.accounts.entry(key_hex.clone()).or_default();
            a.reclaimed += cr.credit;
            a.reclaims.push(entry);
        }
        self.ledger.save(&self.ledger_path)?;
        self.r.wallet.save(&self.r.wallet_path)?;
        match self.r.broadcast_carrier(&carrier) {
            Ok(txid) => {
                self.r.mark_pending(built.statement.nullifiers);
                log::info!(
                    "reclaim by {}: {amount} sat in {txid}, fee {fee} sat",
                    &key_hex[..16]
                );
                Ok((txid, amount, fee))
            }
            Err(e) => {
                let a = self
                    .ledger
                    .accounts
                    .get_mut(&key_hex)
                    .expect("just written");
                a.reclaimed -= cr.credit;
                a.reclaims.pop();
                self.ledger.save(&self.ledger_path)?;
                self.unlock(&h_body_hex);
                self.r.wallet.save(&self.r.wallet_path)?;
                Err(anyhow!("broadcast failed, nothing charged: {e:#}"))
            }
        }
    }

    /// Serve until `max_requests` requests were answered (`None`: forever)
    /// or, after any request, `stop_file` exists: a graceful stop for an
    /// operator (and for tests, which must not kill a process whose ledger
    /// and wallet are mid-write). Pending ledger entries are resolved
    /// before the first request (I3).
    pub fn serve(
        &mut self,
        listener: TcpListener,
        max_requests: Option<u32>,
        stop_file: Option<&Path>,
    ) -> Result<()> {
        self.refresh()?;
        self.check_i1()?;
        self.resolve_pending()?;
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
            if stop_file.is_some_and(|f| f.exists()) {
                log::info!("stop file present; stopping after {served} requests");
                break;
            }
        }
        Ok(())
    }

    fn handle(&mut self, method: &str, path: &str, body: &[u8], ip: IpAddr) -> (u16, Value) {
        match (method, path) {
            ("GET", "/info") => (200, self.info()),
            ("GET", p) if p.starts_with("/credit/") => {
                let key = match key_from_hex(&p["/credit/".len()..]) {
                    Ok(k) => k,
                    Err(e) => return (400, json!({"error": e.to_string()})),
                };
                // credit is a function of the chain: replay to the tip
                // (at most once per sync interval) before answering
                let tip = match self.refresh() {
                    Ok(t) => t,
                    Err(e) => return (500, json!({"error": format!("{e:#}")})),
                };
                let c = self.credit_of(&key, tip);
                (
                    200,
                    json!({
                        "deposited": c.deposited,
                        "unsettled": c.unsettled,
                        "released": c.released,
                        "reclaimed": c.reclaimed,
                        "credit": c.credit,
                        "settled": c.deposited > 0,
                    }),
                )
            }
            ("POST", "/draw") | ("POST", "/reclaim") => {
                if !self.r.admit(ip) {
                    return (
                        429,
                        json!({"error": "busy: too many submissions from this address, try later"}),
                    );
                }
                if path == "/draw" {
                    let req: DrawRequest = match serde_json::from_slice(body) {
                        Ok(r) => r,
                        Err(e) => return (400, json!({"error": format!("bad request: {e}")})),
                    };
                    match self.draw(&req) {
                        Ok((txid, fee, credit)) => (
                            200,
                            json!({"txid": txid.to_string(), "fee": fee, "credit": credit}),
                        ),
                        Err(e) => (400, json!({"error": format!("{e:#}")})),
                    }
                } else {
                    let req: ReclaimRequest = match serde_json::from_slice(body) {
                        Ok(r) => r,
                        Err(e) => return (400, json!({"error": format!("bad request: {e}")})),
                    };
                    match self.reclaim(&req) {
                        Ok((txid, amount, fee)) => (
                            200,
                            json!({"txid": txid.to_string(), "amount": amount, "fee": fee}),
                        ),
                        Err(e) => (400, json!({"error": format!("{e:#}")})),
                    }
                }
            }
            _ => (404, json!({"error": "not found"})),
        }
    }
}

// ---------------------------------------------------------------- client

fn base(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

pub fn vault_info(url: &str) -> Result<Value> {
    get_json(&format!("{}/info", base(url)), SERVICE)
}

pub fn vault_credit(url: &str, key_hex: &str) -> Result<Value> {
    get_json(&format!("{}/credit/{key_hex}", base(url)), SERVICE)
}

fn u64_field(v: &Value, name: &str) -> Result<u64> {
    v[name]
        .as_u64()
        .ok_or_else(|| anyhow!("{SERVICE} response has no {name}: {v}"))
}

fn txid_field(v: &Value) -> Result<Txid> {
    v["txid"]
        .as_str()
        .ok_or_else(|| anyhow!("{SERVICE} response has no txid: {v}"))?
        .parse()
        .context("txid")
}

pub fn submit_draw(url: &str, req: &DrawRequest) -> Result<(Txid, u64, u64)> {
    let v = post_json(&format!("{}/draw", base(url)), req, SERVICE)?;
    Ok((
        txid_field(&v)?,
        u64_field(&v, "fee")?,
        u64_field(&v, "credit")?,
    ))
}

pub fn submit_reclaim(url: &str, req: &ReclaimRequest) -> Result<(Txid, u64, u64)> {
    let v = post_json(&format!("{}/reclaim", base(url)), req, SERVICE)?;
    Ok((
        txid_field(&v)?,
        u64_field(&v, "amount")?,
        u64_field(&v, "fee")?,
    ))
}

/// The accounts of `wallet` at the vault serving `url`, each with the
/// credit it reports (`None` when it cannot be asked). A vault is
/// identified by its deposit address (from `/info`), not by its URL; a
/// record written before the address was kept matches by URL.
fn accounts_at<'a>(
    wallet: &'a Wallet,
    url: &str,
    deposit_address: &str,
) -> Vec<(&'a FeeAccountRecord, Option<u64>)> {
    wallet
        .fee_accounts
        .iter()
        .filter(|a| {
            if a.address.is_empty() {
                base(&a.vault) == base(url)
            } else {
                a.address == deposit_address
            }
        })
        .map(|a| {
            let credit = vault_credit(url, &a.key)
                .ok()
                .and_then(|v| v["credit"].as_u64());
            (a, credit)
        })
        .collect()
}

fn deposit_address_of(info: &Value) -> Result<String> {
    info["deposit_address"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("{SERVICE} publishes no deposit address: {info}"))
}

/// Client side of a draw (§8): the account at `url` with the most credit,
/// `max_fee` from the vault's estimate unless given, sign, submit.
pub(crate) fn draw_from_wallet(
    deployment: &Deployment,
    wallet: &Wallet,
    url: &str,
    envelope: &[u8],
    memo: Option<&[u8]>,
    max_fee: Option<u64>,
) -> Result<Txid> {
    let info = vault_info(url)?;
    if info["deployment"] != json!(deployment.name) {
        bail!(
            "{SERVICE} at {url} serves deployment {}, not {}",
            info["deployment"],
            deployment.name
        );
    }
    let kind = if memo.is_some() {
        "withdraw"
    } else {
        "transfer"
    };
    let estimate = info["fee_estimate"][kind]
        .as_u64()
        .ok_or_else(|| anyhow!("{SERVICE} gives no fee estimate for a {kind}: {info}"))?;
    let accounts = accounts_at(wallet, url, &deposit_address_of(&info)?);
    if accounts.is_empty() {
        bail!("no deposit at {url} in this wallet; `sb fee-vault deposit` first");
    }
    let (acct, credit) = accounts
        .iter()
        .map(|(a, c)| (*a, c.unwrap_or(0)))
        .max_by_key(|(_, c)| *c)
        .expect("non-empty");
    // an explicit ceiling is the user's call; otherwise the ceiling is
    // twice the estimate (headroom for extra pool inputs) capped by the
    // credit, and a draw the credit cannot cover is not posted
    let max_fee = match max_fee {
        Some(m) => m,
        None => {
            if credit < estimate {
                bail!(
                    "credit {credit} sat at {url} is below the estimated fee {estimate}; deposit more, wait for the deposit to settle, or set --max-fee"
                );
            }
            estimate.saturating_mul(2).min(credit)
        }
    };
    let h_body = h_body_of(envelope, &deployment.const_salt)?;
    let key = AuthKey::derive(&wallet.keys, acct.index)?;
    if hex::encode(key.public()) != acct.key {
        bail!(
            "account {} does not match this wallet's key {}",
            acct.key,
            acct.index
        );
    }
    let sig = key.sign(&draw_message(&deployment.name, &h_body, max_fee, memo));
    let req = DrawRequest {
        envelope: hex::encode(envelope),
        memo: memo.map(hex::encode),
        key: acct.key.clone(),
        max_fee,
        sig: hex::encode(sig),
    };
    let (txid, fee, left) = submit_draw(url, &req)?;
    println!(
        "published by the fee vault {url}: {txid} (charged {fee} sat, credit left {left} sat)"
    );
    Ok(txid)
}

/// §6 I2 on the operator's side: a vault wallet (one with a ledger) must
/// not spend below the credit it may still owe. `--force` overrides after
/// an explicit confirmation typed on stdin.
pub(crate) fn backing_guard(
    ctx: &Ctx,
    wallet: &Wallet,
    name: &str,
    amount: u64,
    force: bool,
) -> Result<()> {
    let path = ctx.ledger_path(name);
    if !path.exists() {
        return Ok(());
    }
    let b = backing(wallet, &Ledger::load(&path)?);
    let after = wallet.balance().saturating_sub(amount);
    if after >= b.outstanding {
        return Ok(());
    }
    let short = b.outstanding - after;
    eprintln!(
        "this wallet is a fee vault: spending {amount} sat leaves {after} sat against {} sat of outstanding client credit (under-backed by {short} sat)",
        b.outstanding
    );
    if !force {
        bail!(
            "refused: it would under-back the fee vault's credit (docs/FEE-VAULT.md I2); --force overrides, with confirmation"
        );
    }
    eprintln!("type `under-back {short}` to confirm:");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    if line.trim() != format!("under-back {short}") {
        bail!("not confirmed");
    }
    log::warn!("fee vault {name} under-backed by {short} sat on the operator's confirmation");
    Ok(())
}

// --------------------------------------------------------------- commands

#[derive(Subcommand)]
pub enum FeeVaultCmd {
    /// Run the vault: serve draws and reclaims from this wallet's fee coins.
    Serve {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long, default_value = "127.0.0.1:8742")]
        listen: String,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        /// The operator's price per publication, on top of the miner fee.
        #[arg(long, default_value = "0")]
        margin: u64,
        #[arg(long, default_value = "6")]
        max_checks_per_minute: u32,
        /// Replay to the tip at most once per this many seconds.
        #[arg(long, default_value = "5")]
        sync_interval: u64,
        /// Stop after this many requests (tests).
        #[arg(long)]
        max_requests: Option<u32>,
        /// Stop gracefully once this file exists (checked after each request).
        #[arg(long)]
        stop_file: Option<PathBuf>,
    },
    /// Deposit: a transfer to the vault's address whose `rseed` commits to a fresh authorization key.
    Deposit {
        #[arg(long, default_value = "default")]
        name: String,
        /// The vault's URL (`http://host:port`).
        #[arg(long)]
        vault: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "2")]
        fee_rate: u64,
        /// Only write the carrier to the outbox.
        #[arg(long)]
        no_broadcast: bool,
        /// Publish the deposit through a sponsored relayer.
        #[arg(long, conflicts_with = "no_broadcast")]
        relay: Option<String>,
        /// Top up an existing deposit key instead of using a fresh one.
        #[arg(long)]
        index: Option<u64>,
    },
    /// List this wallet's deposits with the credit each vault reports.
    Accounts {
        #[arg(long, default_value = "default")]
        name: String,
        /// Ask this URL (the vault may have moved) instead of the one recorded.
        #[arg(long)]
        vault: Option<String>,
    },
    /// Return the unspent credit of a deposit to this wallet.
    Reclaim {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        vault: String,
        /// Which deposit (key index); default: the one with credit.
        #[arg(long)]
        index: Option<u64>,
        /// Shielded address to pay; default: a fresh one of this wallet.
        #[arg(long)]
        to: Option<String>,
    },
    /// Operator: outstanding credit against the shielded balance (I2), earned fees.
    Status {
        #[arg(long, default_value = "default")]
        name: String,
    },
}

pub fn run(ctx: &Ctx, cmd: FeeVaultCmd) -> Result<()> {
    match cmd {
        FeeVaultCmd::Serve {
            name,
            listen,
            fee_rate,
            margin,
            max_checks_per_minute,
            sync_interval,
            max_requests,
            stop_file,
        } => {
            let (idx, store) = ctx.indexer()?;
            let chain = ctx.chain_source()?;
            let publisher = ctx.publisher()?;
            let w = ctx.wallet(&name)?;
            let fw = ctx.funding(&w)?;
            eprintln!("loading proving parameters…");
            let params = ctx.params()?;
            let listener =
                TcpListener::bind(&listen).with_context(|| format!("listen on {listen}"))?;
            let mut r = Relayer::new(
                idx,
                store,
                chain,
                publisher,
                fw,
                w,
                ctx.wallet_path(&name),
                ctx.btc_network(),
                fee_rate,
                u32::MAX,
            );
            r.max_checks_per_minute = max_checks_per_minute;
            r.sync_interval = Duration::from_secs(sync_interval);
            let mut v = Vault::new(r, ctx.ledger_path(&name), margin, &ctx.deployment, params)?;
            println!(
                "fee vault listening on http://{} (deployment {}, wallet {name}, {fee_rate} sat/vB + {margin} sat margin, deposits to {})",
                listener.local_addr()?,
                ctx.deployment.name,
                v.r.wallet.default_address().encode(ctx.deployment.network)
            );
            std::io::Write::flush(&mut std::io::stdout())?;
            v.serve(listener, max_requests, stop_file.as_deref())?;
        }
        FeeVaultCmd::Deposit {
            name,
            vault,
            amount,
            fee_rate,
            no_broadcast,
            relay,
            index,
        } => {
            let info = vault_info(&vault)?;
            if info["deployment"] != json!(ctx.deployment.name) {
                bail!(
                    "{SERVICE} at {vault} serves deployment {}, not {}",
                    info["deployment"],
                    ctx.deployment.name
                );
            }
            let addr = deposit_address_of(&info)?;
            let (net, to) =
                PaymentAddress::decode(&addr).map_err(|e| anyhow!("deposit address: {e}"))?;
            if net != ctx.deployment.network {
                bail!("the vault's deposit address is for another network");
            }
            let (idx, _store) = ctx.indexer()?;
            let tip = idx
                .state
                .last_height()
                .ok_or_else(|| anyhow!("run `sb sync` first"))?;
            let h_anchor = anchor_for(tip, ctx.deployment.anchor_depth);
            let size = idx
                .state
                .size_at(h_anchor)
                .ok_or_else(|| anyhow!("anchor {h_anchor} not replayed"))?;
            let mut w = ctx.wallet(&name)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            let top_up = index.is_some();
            let mut index = index.unwrap_or(w.fee_deposit_next);
            if top_up && !w.fee_accounts.iter().any(|a| a.index == index) {
                bail!("no deposit with key index {index} to top up");
            }
            let key = loop {
                match AuthKey::derive(&w.keys, index) {
                    Ok(k) => break k,
                    Err(_) => index += 1,
                }
            };
            let public = key.public();
            eprintln!("loading proving parameters…");
            let params = ctx.params()?;
            eprintln!("proving (anchor {h_anchor}, tree size {size})…");
            let built = w.build_send_seeded(
                &params,
                &ctx.deployment.const_salt,
                &idx.state.tree,
                h_anchor,
                size,
                to,
                amount,
                Some(key_commitment(&public)),
                &mut rand::thread_rng(),
            )?;
            let h_body_hex = hex_fr(&built.statement.h_body);
            w.fee_deposit_next = w.fee_deposit_next.max(index + 1);
            w.fee_accounts.push(FeeAccountRecord {
                vault: base(&vault),
                address: addr.clone(),
                index,
                key: hex::encode(public),
                h_body: h_body_hex.clone(),
                value: amount,
                txid: None,
            });
            w.save(&ctx.wallet_path(&name))?;
            let label = format!("deposit-{}", &h_body_hex[..16]);
            let entry = OutboxEntry::new(&built.envelope.to_bytes(), None, vec![]);
            let txid = ctx.publish(
                Some((&mut w, &name)),
                &label,
                &entry,
                fee_rate,
                PublishMode::pick(no_broadcast, relay, None, None),
            )?;
            if let Some(t) = txid {
                if let Some(a) = w.fee_accounts.last_mut() {
                    a.txid = Some(t.to_string());
                }
                w.save(&ctx.wallet_path(&name))?;
            }
            println!(
                "deposit of {amount} sat to {vault}: key {index} ({}…), credit once the transfer is {} blocks deep",
                &hex::encode(public)[..16],
                info["min_depth"]
            );
            println!("inputs locked until the transfer is accepted (`sb unlock` to release)");
        }
        FeeVaultCmd::Accounts { name, vault } => {
            let w = ctx.wallet(&name)?;
            if w.fee_accounts.is_empty() {
                println!("no fee-vault deposits");
            }
            // with --vault, the records of that vault (by its address) are
            // asked there; the others at their recorded URL
            let at = match &vault {
                Some(u) => Some((base(u), deposit_address_of(&vault_info(u)?)?)),
                None => None,
            };
            for a in &w.fee_accounts {
                let url = match &at {
                    Some((u, addr)) if *addr == a.address => u.clone(),
                    _ => a.vault.clone(),
                };
                let state = match vault_credit(&url, &a.key) {
                    Ok(v) => format!(
                        "deposited {} (unsettled {}), released {}, reclaimed {}, credit {}",
                        v["deposited"], v["unsettled"], v["released"], v["reclaimed"], v["credit"]
                    ),
                    Err(e) => format!("{e:#}"),
                };
                println!(
                    "key {} ({}…) at {}: {} sat in {}; {state}",
                    a.index,
                    &a.key[..16],
                    a.vault,
                    a.value,
                    a.txid.as_deref().unwrap_or("(not published)")
                );
            }
        }
        FeeVaultCmd::Reclaim {
            name,
            vault,
            index,
            to,
        } => {
            let mut w = ctx.wallet(&name)?;
            let info = vault_info(&vault)?;
            let accounts = accounts_at(&w, &vault, &deposit_address_of(&info)?);
            let acct = match index {
                Some(i) => accounts
                    .iter()
                    .find(|(a, _)| a.index == i)
                    .map(|(a, _)| (*a).clone())
                    .ok_or_else(|| anyhow!("no deposit with key index {i} at {vault}"))?,
                None => accounts
                    .iter()
                    .filter(|(_, c)| c.unwrap_or(0) > 0)
                    .max_by_key(|(_, c)| c.unwrap_or(0))
                    .map(|(a, _)| (*a).clone())
                    .ok_or_else(|| anyhow!("no deposit with credit at {vault}"))?,
            };
            let credit = vault_credit(&vault, &acct.key)?;
            let deposited = u64_field(&credit, "deposited")?;
            let address = match to {
                Some(s) => s,
                None => {
                    let (_, a) = w.new_address();
                    w.save(&ctx.wallet_path(&name))?;
                    a.encode(ctx.deployment.network)
                }
            };
            let key = AuthKey::derive(&w.keys, acct.index)?;
            let sig = key.sign(&reclaim_message(&ctx.deployment.name, &address, deposited));
            let req = ReclaimRequest {
                key: acct.key.clone(),
                address: address.clone(),
                deposited,
                sig: hex::encode(sig),
            };
            let (txid, amount, fee) = submit_reclaim(&vault, &req)?;
            println!(
                "reclaimed {amount} sat to {address} in {txid} (fee {fee} sat); it appears after `sb scan` once accepted"
            );
        }
        FeeVaultCmd::Status { name } => {
            let (idx, _store) = ctx.indexer()?;
            let mut w = ctx.wallet(&name)?;
            w.scan(
                &ctx.deployment.const_salt_fr(),
                &idx.state.events,
                &idx.state.nullifiers,
            )?;
            let ledger = Ledger::load(&ctx.ledger_path(&name))?;
            let b = backing(&w, &ledger);
            let balance = w.balance();
            println!("received (not own change): {} sat", b.received);
            println!(
                "released: {} sat, reclaimed: {} sat, earned: {} sat",
                b.released,
                b.reclaimed,
                ledger.earned()
            );
            println!("outstanding credit (upper bound): {} sat", b.outstanding);
            println!("shielded balance: {balance} sat");
            if balance >= b.outstanding {
                println!(
                    "backing: ok ({} sat above outstanding)",
                    balance - b.outstanding
                );
            } else {
                println!("backing: UNDER-BACKED by {} sat", b.outstanding - balance);
            }
            println!("accounts seen: {}", ledger.accounts.len());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_round_trip_and_totals() {
        let dir = std::env::temp_dir().join(format!("sb-vault-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        let mut l = Ledger::load(&path).unwrap();
        assert!(l.accounts.is_empty());
        let a = l.accounts.entry("ab".into()).or_default();
        a.released = 10;
        a.reclaimed = 5;
        a.reclaims.push(Reclaim {
            txid: "t".into(),
            h_body: "h".into(),
            credit: 5,
            paid: 3,
            fee: 2,
            at: 1,
            raw: vec![],
            nullifiers: vec![],
            settled: false,
        });
        l.save(&path).unwrap();
        let l2 = Ledger::load(&path).unwrap();
        assert_eq!(l2.released_total(), 10);
        assert_eq!(l2.reclaimed_total(), 5);
        assert_eq!(l2.earned(), 12);
        std::fs::write(&path, b"{not json").unwrap();
        assert!(Ledger::load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
