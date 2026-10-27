//! Stateful wallet: owned notes, spent/locked status, sent history,
//! incremental scanning with reorg-safe rescans, input selection and
//! transfer construction (paper §10, §16.4, Appendix C).
//!
//! **The wallet file stores the seed in plaintext.** Encrypting it is a
//! deployment concern not addressed in this version.

use std::collections::HashSet;
use std::path::Path;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use sb_circuit::TransferParams;
use sb_core::address::{Network, PaymentAddress};
use sb_core::event::{AcceptedEvent, txid_hex};
use sb_core::keys::{Seed, WalletKeys};
use sb_core::note::{NotePlaintext, nullifier};
use sb_core::tree::NoteTree;
use sb_primitives::Fr;
use sb_primitives::encoding::{fr_from_bytes, fr_to_bytes};

use crate::builder::{BuildError, BuiltTransfer, Recipient, SpendableNote, build_transfer};
use crate::scan::{scan_incoming, scan_outgoing};

/// Default wallet anchor depth `K_wallet` (profile §9).
pub const K_WALLET: u32 = 3;

fn hex_fr(f: &Fr) -> String {
    hex::encode(fr_to_bytes(f))
}

fn fr_hex(s: &str) -> Result<Fr, WalletError> {
    let b = hex::decode(s).map_err(|e| WalletError::Corrupt(e.to_string()))?;
    fr_from_bytes(&b).map_err(|e| WalletError::Corrupt(e.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteRecord {
    pub value: u64,
    pub d: String,
    pub rseed: String,
    pub h_body_create: String,
    pub output_index: u64,
    pub pos: u64,
    pub nullifier: String,
    pub height: u32,
    pub txid: String,
    /// Height of the accepted transfer that spent it.
    pub spent_at: Option<u32>,
    /// `h_body` of a built-but-not-yet-accepted transfer that consumes it.
    pub locked_by: Option<String>,
}

impl NoteRecord {
    pub fn plaintext(&self) -> Result<NotePlaintext, WalletError> {
        let d = hex::decode(&self.d).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        Ok(NotePlaintext {
            value: self.value,
            d: d.try_into()
                .map_err(|_| WalletError::Corrupt("diversifier".into()))?,
            rseed: fr_hex(&self.rseed)?,
        })
    }

    pub fn spendable(&self) -> Result<SpendableNote, WalletError> {
        Ok(SpendableNote {
            note: self.plaintext()?,
            h_body_create: fr_hex(&self.h_body_create)?,
            output_index: self.output_index,
            pos: self.pos,
        })
    }

    pub fn is_unspent(&self) -> bool {
        self.spent_at.is_none() && self.locked_by.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentRecord {
    pub value: u64,
    pub to_d: String,
    pub pos: u64,
    pub height: u32,
    pub txid: String,
    /// `true` when the output went to one of this wallet's own addresses.
    pub is_change: bool,
}

/// An operator payout made (or refused) for a withdraw request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutRecord {
    /// Carrier txid of the transfer that requested the payout.
    pub txid: String,
    pub amount: u64,
    pub script_hex: String,
    pub paid_txid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    seed: String,
    network: Network,
    deployment: String,
    notes: Vec<NoteRecord>,
    sent: Vec<SentRecord>,
    #[serde(default)]
    payouts: Vec<PayoutRecord>,
    scanned_events: usize,
    last_scanned_txid: Option<String>,
    next_address_index: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("corrupt wallet: {0}")]
    Corrupt(String),
    #[error("insufficient spendable balance: have {have}, need {need}")]
    Insufficient { have: u64, need: u64 },
    #[error("amount needs more than two inputs; consolidate first (send to yourself)")]
    NeedsConsolidation,
    #[error("no input is confirmed under the selected anchor")]
    NothingUnderAnchor,
    #[error("build: {0}")]
    Build(#[from] BuildError),
}

pub struct Wallet {
    seed: Seed,
    pub keys: WalletKeys,
    pub network: Network,
    pub deployment: String,
    pub notes: Vec<NoteRecord>,
    pub sent: Vec<SentRecord>,
    pub payouts: Vec<PayoutRecord>,
    pub scanned_events: usize,
    pub last_scanned_txid: Option<[u8; 32]>,
    pub next_address_index: u64,
}

impl Wallet {
    pub fn from_seed(seed: Seed, network: Network, deployment: &str) -> Self {
        let keys = WalletKeys::from_seed(&seed);
        Wallet {
            seed,
            keys,
            network,
            deployment: deployment.to_string(),
            notes: Vec::new(),
            sent: Vec::new(),
            payouts: Vec::new(),
            scanned_events: 0,
            last_scanned_txid: None,
            next_address_index: 0,
        }
    }

    pub fn create<R: RngCore + CryptoRng>(rng: &mut R, network: Network, deployment: &str) -> Self {
        Self::from_seed(Seed::random(rng), network, deployment)
    }

    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed.0)
    }

    pub fn load(path: &Path) -> Result<Self, WalletError> {
        let f: WalletFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        if f.version != 1 {
            return Err(WalletError::Corrupt(format!(
                "unknown version {}",
                f.version
            )));
        }
        let seed = hex::decode(&f.seed).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        let seed = Seed(
            seed.try_into()
                .map_err(|_| WalletError::Corrupt("seed length".into()))?,
        );
        let mut w = Self::from_seed(seed, f.network, &f.deployment);
        w.notes = f.notes;
        w.sent = f.sent;
        w.payouts = f.payouts;
        w.scanned_events = f.scanned_events;
        w.last_scanned_txid = match f.last_scanned_txid {
            Some(s) => {
                let b = hex::decode(&s).map_err(|e| WalletError::Corrupt(e.to_string()))?;
                Some(
                    b.try_into()
                        .map_err(|_| WalletError::Corrupt("txid".into()))?,
                )
            }
            None => None,
        };
        w.next_address_index = f.next_address_index;
        Ok(w)
    }

    pub fn save(&self, path: &Path) -> Result<(), WalletError> {
        let f = WalletFile {
            version: 1,
            seed: self.seed_hex(),
            network: self.network,
            deployment: self.deployment.clone(),
            notes: self.notes.clone(),
            sent: self.sent.clone(),
            payouts: self.payouts.clone(),
            scanned_events: self.scanned_events,
            last_scanned_txid: self.last_scanned_txid.map(hex::encode),
            next_address_index: self.next_address_index,
        };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&f)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    /// The wallet's primary address (receive path 0 or the first valid one).
    pub fn default_address(&self) -> PaymentAddress {
        self.keys.ivk.find_address(0).1
    }

    /// A fresh address, advancing the receive-path counter.
    pub fn new_address(&mut self) -> (u64, PaymentAddress) {
        let (i, a) = self.keys.ivk.find_address(self.next_address_index.max(1));
        self.next_address_index = i + 1;
        (i, a)
    }

    /// Spendable balance: unspent, unlocked notes.
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| n.is_unspent())
            .map(|n| n.value)
            .sum()
    }

    /// Scan accepted history incrementally. If the history no longer matches
    /// what was scanned (reorganisation), everything is rescanned from the
    /// start: wallet view is a pure function of seed and history (§16.4).
    pub fn scan(
        &mut self,
        const_salt: &Fr,
        events: &[AcceptedEvent],
        replayed_nullifiers: &HashSet<Fr>,
    ) -> Result<usize, WalletError> {
        let consistent = self.scanned_events <= events.len()
            && match (self.scanned_events, self.last_scanned_txid) {
                (0, _) => true,
                (n, Some(txid)) => events[n - 1].txid == txid,
                (_, None) => false,
            };
        if !consistent {
            log::warn!("accepted history changed under the wallet; rescanning from the start");
            self.notes.clear();
            self.sent.clear();
            self.scanned_events = 0;
            self.last_scanned_txid = None;
        }
        let mut new_notes = 0;
        for ev in &events[self.scanned_events..] {
            // incoming
            for r in scan_incoming(&self.keys.ivk, const_salt, ev) {
                let nf = nullifier(&self.keys.sk_nf, &r.note.rho(), r.pos);
                if self.notes.iter().any(|n| n.pos == r.pos) {
                    continue;
                }
                self.notes.push(NoteRecord {
                    value: r.note.value,
                    d: hex::encode(r.note.d),
                    rseed: hex_fr(&r.note.rseed),
                    h_body_create: hex_fr(&r.h_body_create),
                    output_index: r.output_index,
                    pos: r.pos,
                    nullifier: hex_fr(&nf),
                    height: r.height,
                    txid: txid_hex(&r.txid),
                    spent_at: None,
                    locked_by: None,
                });
                new_notes += 1;
            }
            // spends of our notes by this envelope
            let ours: Vec<usize> = self
                .notes
                .iter()
                .enumerate()
                .filter(|(_, n)| ev.nullifiers.iter().any(|nf| hex_fr(nf) == n.nullifier))
                .map(|(i, _)| i)
                .collect();
            for i in &ours {
                self.notes[*i].spent_at = Some(ev.height);
                self.notes[*i].locked_by = None;
            }
            // outgoing records only for transfers that spent one of our notes
            if !ours.is_empty() {
                if let Some(sent) = scan_outgoing(&self.keys.ovk, const_salt, ev) {
                    for s in sent {
                        let is_change = self
                            .keys
                            .ivk
                            .address_for(s.note.d)
                            .map(|a| a.pk_d == s.pk_d)
                            .unwrap_or(false);
                        self.sent.push(SentRecord {
                            value: s.note.value,
                            to_d: hex::encode(s.note.d),
                            pos: s.pos,
                            height: s.height,
                            txid: txid_hex(&s.txid),
                            is_change,
                        });
                    }
                }
            }
            self.scanned_events += 1;
            self.last_scanned_txid = Some(ev.txid);
        }
        // Spends we did not see as envelopes (same seed elsewhere).
        for n in self.notes.iter_mut() {
            if n.spent_at.is_none() && replayed_nullifiers.contains(&fr_hex(&n.nullifier)?) {
                n.spent_at = Some(0);
                n.locked_by = None;
            }
        }
        Ok(new_notes)
    }

    /// Release locks left by transfers that were never accepted.
    pub fn unlock_all(&mut self) {
        for n in self.notes.iter_mut() {
            n.locked_by = None;
        }
    }

    /// Choose up to two unspent notes under `anchor_size` covering `amount`,
    /// largest first.
    pub fn select_inputs(
        &self,
        amount: u64,
        anchor_size: u64,
    ) -> Result<Vec<&NoteRecord>, WalletError> {
        let mut candidates: Vec<&NoteRecord> = self
            .notes
            .iter()
            .filter(|n| n.is_unspent() && n.pos < anchor_size)
            .collect();
        if candidates.is_empty() {
            return Err(if self.balance() == 0 {
                WalletError::Insufficient {
                    have: 0,
                    need: amount,
                }
            } else {
                WalletError::NothingUnderAnchor
            });
        }
        candidates.sort_by_key(|n| std::cmp::Reverse(n.value));
        if let Some(exact) = candidates.iter().find(|n| n.value == amount) {
            return Ok(vec![exact]);
        }
        if candidates[0].value >= amount {
            return Ok(vec![candidates[0]]);
        }
        if candidates.len() >= 2 && candidates[0].value + candidates[1].value >= amount {
            return Ok(vec![candidates[0], candidates[1]]);
        }
        let have: u64 = candidates.iter().map(|n| n.value).sum();
        if have >= amount {
            Err(WalletError::NeedsConsolidation)
        } else {
            Err(WalletError::Insufficient { have, need: amount })
        }
    }

    /// Build a payment of `amount` to `to` with change back to this wallet,
    /// anchored at `h_anchor` (tree size `anchor_size`), and lock its inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn build_send<R: RngCore + CryptoRng>(
        &mut self,
        params: &TransferParams,
        const_salt: &[u8; 32],
        tree: &NoteTree,
        h_anchor: u32,
        anchor_size: u64,
        to: PaymentAddress,
        amount: u64,
        rng: &mut R,
    ) -> Result<BuiltTransfer, WalletError> {
        let selected: Vec<NoteRecord> = self
            .select_inputs(amount, anchor_size)?
            .into_iter()
            .cloned()
            .collect();
        let inputs: Vec<SpendableNote> = selected
            .iter()
            .map(|n| n.spendable())
            .collect::<Result<_, _>>()?;
        let total: u64 = selected.iter().map(|n| n.value).sum();
        let mut outputs = vec![Recipient {
            address: to,
            value: amount,
        }];
        if total > amount {
            outputs.push(Recipient {
                address: self.default_address(),
                value: total - amount,
            });
        }
        let built = build_transfer(
            params,
            &self.keys,
            const_salt,
            tree,
            h_anchor,
            anchor_size,
            &inputs,
            &outputs,
            rng,
        )?;
        let lock = hex_fr(&built.statement.h_body);
        for n in self.notes.iter_mut() {
            if selected.iter().any(|s| s.pos == n.pos) {
                n.locked_by = Some(lock.clone());
            }
        }
        Ok(built)
    }
}

/// Wallet anchor policy: the newest anchor a transfer included at
/// `replayed_tip + 1` may use under `K_wallet`.
pub fn anchor_for(replayed_tip: u32, k_wallet: u32) -> u32 {
    (replayed_tip + 1).saturating_sub(k_wallet)
}
