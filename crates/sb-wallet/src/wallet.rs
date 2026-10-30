//! Stateful wallet: owned notes, spent/locked status, sent history,
//! incremental scanning with reorg-safe rescans, input selection and
//! transfer construction (paper §10, §16.4, Appendix C).
//!
//! Wallet files are encrypted with a passphrase (Argon2id → ChaCha20-Poly1305,
//! file version 2). Version-1 files (plaintext seed) still load so they can
//! be migrated with [`Wallet::set_passphrase`] + [`Wallet::save`].

use std::collections::HashSet;
use std::path::Path;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use sb_circuit::{SwapParams, TransferParams};
use sb_core::address::{Network, PaymentAddress};
use sb_core::event::{AcceptedEvent, txid_hex};
use sb_core::keys::{Seed, WalletKeys};
use sb_core::lock::{LockOpening, Secret};
use sb_core::note::{NotePlaintext, nullifier, nullifier_locked};
use sb_core::tree::NoteTree;
use sb_primitives::encoding::{fr_from_bytes, fr_to_bytes, point_from_bytes, point_to_bytes};
use sb_primitives::{Fr, JubjubAffine};

use crate::builder::{
    BuildError, BuiltSwap, BuiltTransfer, Recipient, SpendableNote, SwapInput, SwapOutput,
    build_swap_transfer, build_transfer_seeded,
};
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
    /// The leaf's `h_aux` slot, hex; empty or zero for a plain note. A
    /// locked note (`docs/SWAP.md`) is spent only through the swap
    /// extension and does not count towards the plain balance.
    #[serde(default)]
    pub h_aux: String,
}

impl NoteRecord {
    /// Is this a plain note (no lock in its slot)?
    pub fn is_plain(&self) -> bool {
        self.h_aux.is_empty() || self.h_aux.bytes().all(|b| b == b'0')
    }

    pub fn h_aux_fr(&self) -> Result<Fr, WalletError> {
        if self.is_plain() {
            Ok(Fr::from(0u64))
        } else {
            fr_hex(&self.h_aux)
        }
    }

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

/// A swap agreement this wallet is a party to (`docs/SWAP.md` §9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapRecord {
    /// `SHA-256(s)`, hex: the agreement's identifier.
    pub hash: String,
    /// `"x"` (holds the secret, locks the note, claims the HTLC) or `"y"`.
    pub role: String,
    /// The secret, hex, when we are X.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    pub v_sh: u64,
    pub v_btc: u64,
    /// X's refund address (shielded, encoded).
    pub refund_address: String,
    /// Y's shielded address, the locked note's owner.
    #[serde(default)]
    pub owner_address: String,
    pub t_refund: u32,
    pub t_htlc: u32,
    /// Compressed secp256k1 keys, hex: X claims the HTLC, Y refunds it.
    pub btc_pk_x: String,
    #[serde(default)]
    pub btc_pk_y: String,
    /// `h_aux` of the locked note, hex, once agreed.
    #[serde(default)]
    pub h_aux: String,
    /// `offered`, `accepted`, `locked`, `funded`, `claimed`, `refunded`, `done`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub htlc_outpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_txid: Option<String>,
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
    /// Enough to rebuild the note we created: for refunding a locked note
    /// (`docs/SWAP.md` §9). Empty on records written before the extension.
    #[serde(default)]
    pub rseed: String,
    #[serde(default)]
    pub h_body_create: String,
    #[serde(default)]
    pub output_index: u64,
    #[serde(default)]
    pub h_aux: String,
    /// The recipient's `pk_d`, compressed hex.
    #[serde(default)]
    pub pk_d: String,
}

/// A fee-vault deposit this wallet made (`docs/FEE-VAULT.md` §8): the
/// account it draws against at that vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAccountRecord {
    /// The vault's URL when the deposit was made (its address below is
    /// what identifies the vault; the URL may change).
    pub vault: String,
    /// The vault's deposit address: the account belongs to this vault.
    #[serde(default)]
    pub address: String,
    /// Index of the authorization key in the wallet's derivation.
    pub index: u64,
    /// The x-only public key `P`, hex.
    pub key: String,
    /// `h_body` of the deposit transfer, hex.
    pub h_body: String,
    pub value: u64,
    /// Carrier txid once published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
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

/// The encrypted file format is `sb_common::filecrypto` (version 2,
/// Argon2id + ChaCha20-Poly1305); this profile's associated data:
const WALLET_AAD: &[u8] = b"sb/v1/wallet";

pub use sb_common::filecrypto::FileCrypto as WalletCrypto;
use sb_common::filecrypto::{CryptoError, EncryptedFile};

/// Plaintext wallet body (also the version-1 file format).
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
    #[serde(default)]
    swaps: Vec<SwapRecord>,
    #[serde(default)]
    fee_accounts: Vec<FeeAccountRecord>,
    /// Next fee-vault authorization key index.
    #[serde(default)]
    fee_deposit_next: u64,
    scanned_events: usize,
    last_scanned_txid: Option<String>,
    next_address_index: u64,
    /// Next transparent funding receive index (deployment layer, docs/BOUNDARY.md).
    #[serde(default)]
    funding_receive: u32,
    /// Next transparent funding change index.
    #[serde(default)]
    funding_change: u32,
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
    #[error("wallet file is encrypted; a passphrase is required")]
    PassphraseRequired,
    #[error("wrong passphrase (or corrupt wallet file)")]
    WrongPassphrase,
    #[error("no unspent locked note (or sent locked note) with that lock")]
    NoSuchLockedNote,
}

impl From<CryptoError> for WalletError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Corrupt(m) => WalletError::Corrupt(m),
            CryptoError::WrongPassphrase => WalletError::WrongPassphrase,
        }
    }
}

pub struct Wallet {
    seed: Seed,
    crypto: Option<WalletCrypto>,
    pub keys: WalletKeys,
    pub network: Network,
    pub deployment: String,
    pub notes: Vec<NoteRecord>,
    pub sent: Vec<SentRecord>,
    pub payouts: Vec<PayoutRecord>,
    pub swaps: Vec<SwapRecord>,
    pub fee_accounts: Vec<FeeAccountRecord>,
    pub fee_deposit_next: u64,
    pub scanned_events: usize,
    pub last_scanned_txid: Option<[u8; 32]>,
    pub next_address_index: u64,
    /// Next transparent funding receive index (docs/BOUNDARY.md, "Fee funding").
    pub funding_receive: u32,
    /// Next transparent funding change index.
    pub funding_change: u32,
}

impl Wallet {
    pub fn from_seed(seed: Seed, network: Network, deployment: &str) -> Self {
        let keys = WalletKeys::from_seed(&seed);
        Wallet {
            seed,
            crypto: None,
            keys,
            network,
            deployment: deployment.to_string(),
            notes: Vec::new(),
            sent: Vec::new(),
            payouts: Vec::new(),
            swaps: Vec::new(),
            fee_accounts: Vec::new(),
            fee_deposit_next: 0,
            scanned_events: 0,
            last_scanned_txid: None,
            next_address_index: 0,
            funding_receive: 0,
            funding_change: 0,
        }
    }

    pub fn create<R: RngCore + CryptoRng>(rng: &mut R, network: Network, deployment: &str) -> Self {
        Self::from_seed(Seed::random(rng), network, deployment)
    }

    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed.0)
    }

    /// Load a wallet file. Version-2 files need `passphrase`; version-1
    /// (plaintext) files load without one.
    pub fn load(path: &Path, passphrase: Option<&str>) -> Result<Self, WalletError> {
        let text = std::fs::read_to_string(path)?;
        let probe: serde_json::Value = serde_json::from_str(&text)?;
        match probe.get("version").and_then(|v| v.as_u64()) {
            Some(1) => Self::from_body(serde_json::from_str(&text)?, None),
            Some(2) => {
                let f: EncryptedFile = serde_json::from_str(&text)?;
                let passphrase = passphrase.ok_or(WalletError::PassphraseRequired)?;
                let (body, crypto) = WalletCrypto::open(&f, passphrase, WALLET_AAD)?;
                Self::from_body(serde_json::from_slice(&body)?, Some(crypto))
            }
            other => Err(WalletError::Corrupt(format!("unknown version {other:?}"))),
        }
    }

    fn from_body(f: WalletFile, crypto: Option<WalletCrypto>) -> Result<Self, WalletError> {
        if f.version != 1 {
            return Err(WalletError::Corrupt(format!(
                "unknown body version {}",
                f.version
            )));
        }
        let seed = hex::decode(&f.seed).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        let seed = Seed(
            seed.try_into()
                .map_err(|_| WalletError::Corrupt("seed length".into()))?,
        );
        let mut w = Self::from_seed(seed, f.network, &f.deployment);
        w.crypto = crypto;
        w.notes = f.notes;
        w.sent = f.sent;
        w.payouts = f.payouts;
        w.swaps = f.swaps;
        w.fee_accounts = f.fee_accounts;
        w.fee_deposit_next = f.fee_deposit_next;
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
        w.funding_receive = f.funding_receive;
        w.funding_change = f.funding_change;
        Ok(w)
    }

    /// Is this wallet saved encrypted?
    pub fn is_encrypted(&self) -> bool {
        self.crypto.is_some()
    }

    /// Encrypt the file under `passphrase` from the next `save` on.
    pub fn set_passphrase<R: RngCore + CryptoRng>(
        &mut self,
        passphrase: &str,
        rng: &mut R,
    ) -> Result<(), WalletError> {
        self.crypto = Some(WalletCrypto::fresh(passphrase, rng)?);
        Ok(())
    }

    fn body(&self) -> WalletFile {
        WalletFile {
            version: 1,
            seed: self.seed_hex(),
            network: self.network,
            deployment: self.deployment.clone(),
            notes: self.notes.clone(),
            sent: self.sent.clone(),
            payouts: self.payouts.clone(),
            swaps: self.swaps.clone(),
            fee_accounts: self.fee_accounts.clone(),
            fee_deposit_next: self.fee_deposit_next,
            scanned_events: self.scanned_events,
            last_scanned_txid: self.last_scanned_txid.map(hex::encode),
            next_address_index: self.next_address_index,
            funding_receive: self.funding_receive,
            funding_change: self.funding_change,
        }
    }

    /// Write the wallet file (encrypted when a passphrase is set).
    pub fn save(&self, path: &Path) -> Result<(), WalletError> {
        let text = match &self.crypto {
            None => serde_json::to_string_pretty(&self.body())?,
            Some(c) => {
                let plain = serde_json::to_vec(&self.body())?;
                serde_json::to_string_pretty(&c.seal(&plain, WALLET_AAD))?
            }
        };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
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

    /// Spendable balance: unspent, unlocked, plain notes.
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| n.is_unspent() && n.is_plain())
            .map(|n| n.value)
            .sum()
    }

    /// Value held in unspent locked notes we own (claimable with their
    /// preimages, not part of [`Self::balance`]).
    pub fn locked_balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| n.is_unspent() && !n.is_plain())
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
                let plain = r.h_aux == Fr::from(0u64);
                let nf = if plain {
                    nullifier(&self.keys.sk_nf, &r.note.rho(), r.pos)
                } else {
                    nullifier_locked(&r.note.rho(), r.pos)
                };
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
                    h_aux: if plain {
                        String::new()
                    } else {
                        hex_fr(&r.h_aux)
                    },
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
                            rseed: hex_fr(&s.note.rseed),
                            h_body_create: hex_fr(&ev.h_body),
                            output_index: s.output_index,
                            h_aux: if s.h_aux == Fr::from(0u64) {
                                String::new()
                            } else {
                                hex_fr(&s.h_aux)
                            },
                            pk_d: hex::encode(point_to_bytes(&s.pk_d)),
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
            .filter(|n| n.is_unspent() && n.is_plain() && n.pos < anchor_size)
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
        self.build_send_seeded(
            params,
            const_salt,
            tree,
            h_anchor,
            anchor_size,
            to,
            amount,
            None,
            rng,
        )
    }

    /// [`Self::build_send`] with a chosen `rseed` for the payment output
    /// (a fee-vault deposit, `docs/FEE-VAULT.md` §2).
    #[allow(clippy::too_many_arguments)]
    pub fn build_send_seeded<R: RngCore + CryptoRng>(
        &mut self,
        params: &TransferParams,
        const_salt: &[u8; 32],
        tree: &NoteTree,
        h_anchor: u32,
        anchor_size: u64,
        to: PaymentAddress,
        amount: u64,
        rseed: Option<Fr>,
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
        let built = build_transfer_seeded(
            params,
            &self.keys,
            const_salt,
            tree,
            h_anchor,
            anchor_size,
            &inputs,
            &outputs,
            &[rseed],
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

impl Wallet {
    fn lock_inputs(&mut self, positions: &[u64], h_body: &Fr) {
        let lock = hex_fr(h_body);
        for n in self.notes.iter_mut() {
            if positions.contains(&n.pos) {
                n.locked_by = Some(lock.clone());
            }
        }
    }

    /// Lock `amount` to `owner` under `opening` (we are X): plain inputs of
    /// ours, one locked output, change back to us (`docs/SWAP.md` §9 step 2).
    #[allow(clippy::too_many_arguments)]
    pub fn build_lock<R: RngCore + CryptoRng>(
        &mut self,
        params: &SwapParams,
        const_salt: &[u8; 32],
        tree: &NoteTree,
        h_anchor: u32,
        anchor_size: u64,
        owner: PaymentAddress,
        amount: u64,
        opening: LockOpening,
        rng: &mut R,
    ) -> Result<BuiltSwap, WalletError> {
        let selected = self.select_inputs(amount, anchor_size)?;
        let inputs: Vec<SwapInput> = selected
            .iter()
            .map(|n| n.spendable().map(SwapInput::Plain))
            .collect::<Result<_, _>>()?;
        let positions: Vec<u64> = selected.iter().map(|n| n.pos).collect();
        let total: u64 = selected.iter().map(|n| n.value).sum();
        let mut outputs = vec![SwapOutput {
            recipient: Recipient {
                address: owner,
                value: amount,
            },
            lock: Some(opening),
        }];
        if total > amount {
            outputs.push(SwapOutput {
                recipient: Recipient {
                    address: self.default_address(),
                    value: total - amount,
                },
                lock: None,
            });
        }
        let built = build_swap_transfer(
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
        self.lock_inputs(&positions, &built.statement.base.h_body);
        Ok(built)
    }

    /// Claim the locked note whose slot is `opening.commitment()` with
    /// `secret` (we are Y), paying its value to ourselves.
    #[allow(clippy::too_many_arguments)]
    pub fn build_claim<R: RngCore + CryptoRng>(
        &mut self,
        params: &SwapParams,
        const_salt: &[u8; 32],
        tree: &NoteTree,
        h_anchor: u32,
        anchor_size: u64,
        opening: LockOpening,
        secret: Secret,
        rng: &mut R,
    ) -> Result<BuiltSwap, WalletError> {
        let h_aux = hex_fr(&opening.commitment());
        let note = self
            .notes
            .iter()
            .find(|n| n.h_aux == h_aux && n.is_unspent())
            .ok_or(WalletError::NoSuchLockedNote)?;
        if note.pos >= anchor_size {
            return Err(WalletError::NothingUnderAnchor);
        }
        let pos = note.pos;
        let value = note.value;
        let input = SwapInput::Claim {
            note: note.spendable()?,
            opening,
            secret,
        };
        let built = build_swap_transfer(
            params,
            &self.keys,
            const_salt,
            tree,
            h_anchor,
            anchor_size,
            &[input],
            &[SwapOutput {
                recipient: Recipient {
                    address: self.default_address(),
                    value,
                },
                lock: None,
            }],
            rng,
        )?;
        self.lock_inputs(&[pos], &built.statement.base.h_body);
        Ok(built)
    }

    /// Refund a locked note we created (we are X): rebuilt from the sent
    /// record whose slot is `opening.commitment()`, paid back to us.
    #[allow(clippy::too_many_arguments)]
    pub fn build_refund<R: RngCore + CryptoRng>(
        &mut self,
        params: &SwapParams,
        const_salt: &[u8; 32],
        tree: &NoteTree,
        h_anchor: u32,
        anchor_size: u64,
        opening: LockOpening,
        rng: &mut R,
    ) -> Result<BuiltSwap, WalletError> {
        let h_aux = hex_fr(&opening.commitment());
        let sent = self
            .sent
            .iter()
            .find(|s| s.h_aux == h_aux)
            .ok_or(WalletError::NoSuchLockedNote)?;
        if sent.pos >= anchor_size {
            return Err(WalletError::NothingUnderAnchor);
        }
        let d = hex::decode(&sent.to_d).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        let note = SpendableNote {
            note: NotePlaintext {
                value: sent.value,
                d: d.try_into()
                    .map_err(|_| WalletError::Corrupt("diversifier".into()))?,
                rseed: fr_hex(&sent.rseed)?,
            },
            h_body_create: fr_hex(&sent.h_body_create)?,
            output_index: sent.output_index,
            pos: sent.pos,
        };
        let owner_bytes =
            hex::decode(&sent.pk_d).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        let owner: JubjubAffine =
            point_from_bytes(&owner_bytes).map_err(|e| WalletError::Corrupt(e.to_string()))?;
        let value = sent.value;
        let d_refund = self
            .diversifier_for(&opening.pk_refund)
            .ok_or(WalletError::NoSuchLockedNote)?;
        let built = build_swap_transfer(
            params,
            &self.keys,
            const_salt,
            tree,
            h_anchor,
            anchor_size,
            &[SwapInput::Refund {
                note,
                opening,
                owner,
                d_refund,
            }],
            &[SwapOutput {
                recipient: Recipient {
                    address: self.default_address(),
                    value,
                },
                lock: None,
            }],
            rng,
        )?;
        Ok(built)
    }

    /// The diversifier of this wallet's address with transmission key
    /// `pk_d`, searched over the receive paths handed out so far plus a
    /// margin (the address book, not a fixed range).
    pub fn diversifier_for(&self, pk_d: &JubjubAffine) -> Option<[u8; 11]> {
        let upto = self.next_address_index + 32;
        (0..=upto)
            .filter_map(|k| self.keys.ivk.address_at(k))
            .find(|a| a.pk_d == *pk_d)
            .map(|a| a.d)
    }

    /// The nullifier a locked note we created will carry (either path), from
    /// its sent record: to tell a counterparty's claim from a note still
    /// waiting for our refund.
    pub fn sent_lock_nullifier(&self, h_aux: &str) -> Result<Fr, WalletError> {
        let sent = self
            .sent
            .iter()
            .find(|s| s.h_aux == h_aux)
            .ok_or(WalletError::NoSuchLockedNote)?;
        let rseed = fr_hex(&sent.rseed)?;
        let rho = sb_primitives::poseidon::native::hash(
            sb_primitives::tags::t_rho(),
            std::slice::from_ref(&rseed),
        );
        Ok(nullifier_locked(&rho, sent.pos))
    }

    /// The swap record with this hash, if any.
    pub fn swap_mut(&mut self, hash: &str) -> Option<&mut SwapRecord> {
        self.swaps.iter_mut().find(|s| s.hash == hash)
    }

    pub fn swap(&self, hash: &str) -> Option<&SwapRecord> {
        self.swaps.iter().find(|s| s.hash == hash)
    }
}

/// Wallet anchor policy: the newest anchor a transfer included at
/// `replayed_tip + 1` may use under `K_wallet`.
pub fn anchor_for(replayed_tip: u32, k_wallet: u32) -> u32 {
    (replayed_tip + 1).saturating_sub(k_wallet)
}

#[cfg(test)]
mod private_branches {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn body_version_and_build_send_errors() {
        let body = WalletFile {
            version: 9,
            seed: "00".repeat(32),
            network: Network::Regtest,
            deployment: "x".into(),
            notes: vec![],
            sent: vec![],
            payouts: vec![],
            swaps: vec![],
            fee_accounts: vec![],
            fee_deposit_next: 0,
            scanned_events: 0,
            last_scanned_txid: None,
            next_address_index: 0,
            funding_receive: 0,
            funding_change: 0,
        };
        assert!(matches!(
            Wallet::from_body(body, None),
            Err(WalletError::Corrupt(_))
        ));
        // a note record that is not in the tree makes build_send fail inside the builder
        let mut w = Wallet::from_seed(Seed([4u8; 32]), Network::Regtest, "x");
        let addr = w.default_address();
        w.notes.push(NoteRecord {
            value: 10,
            d: hex::encode(addr.d),
            rseed: hex_fr(&Fr::from(1u64)),
            h_body_create: hex_fr(&Fr::from(2u64)),
            output_index: 0,
            pos: 0,
            nullifier: hex_fr(&Fr::from(3u64)),
            height: 1,
            txid: "aa".repeat(32),
            spent_at: None,
            locked_by: None,
            h_aux: String::new(),
        });
        let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let mut tree = NoteTree::new();
        tree.append(Fr::from(99u64)); // some other leaf sits at the record's position
        let r = w.build_send(&params, &[0u8; 32], &tree, 5, 1, addr, 10, &mut rng);
        assert!(matches!(
            r,
            Err(WalletError::Build(BuildError::LeafMismatch(0)))
        ));
        assert!(
            w.notes[0].locked_by.is_none(),
            "a failed build leaves no lock"
        );
    }
}
