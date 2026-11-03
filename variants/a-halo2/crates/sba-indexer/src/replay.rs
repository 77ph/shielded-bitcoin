//! Deterministic replay of family-A envelopes (paper §8, §15; PROFILE-A.md
//! §11), plus the development mint of docs/BOUNDARY.md.

use bitcoin::hashes::Hash;
use bitcoin::{Block, ScriptBuf, Transaction};
use log::{debug, info, warn};

use sba_circuit::{TransferStatement, TransferVerifier};
use sba_core::envelope::{
    CANDIDATE_PREFIX, Envelope, MintEnvelope, ParseError, TransferBody, TransferEnvelope,
    parse_envelope,
};
use sba_core::event::AcceptedEvent;
use sba_core::note::note_leaf;
use sba_core::recovery::N_OUT;
use sba_primitives::Fp;

use sb_common::carrier::CarrierError;
use sb_common::chain::{BlockId, ChainError, ChainSource};

use crate::deployment::Deployment;
use crate::state::{BlockCheckpoint, Rejection, ReplayState};
use crate::store::{StateStore, StoreError};

/// Why an envelope did not mutate state (PROFILE-A.md §11, steps 1–6).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RejectReason {
    #[error("carrier: {0}")]
    Carrier(#[from] CarrierError),
    #[error("parse: {0}")]
    Parse(#[from] ParseError),
    #[error("anchor {h_anchor} outside the window for block {height}")]
    AnchorOutOfWindow { h_anchor: u32, height: u32 },
    #[error("anchor {0} has no replayed root")]
    AnchorUnknown(u32),
    #[error("duplicate nullifier inside the envelope")]
    DuplicateNullifier,
    #[error("nullifier is zero")]
    ZeroNullifier,
    #[error("nullifier already spent")]
    SpentNullifier,
    #[error("proof does not verify")]
    ProofInvalid,
    #[error("mint: this deployment has no boundary")]
    MintDisabled,
    #[error("mint: vault output missing or amount differs")]
    MintVault,
    #[error("mint: invalid diversifier")]
    MintDiversifier,
}

/// What [`Indexer::check_transfer`] learned about a valid transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCheck {
    pub h_body: Fp,
    pub h_anchor: u32,
    pub nullifiers: [Fp; 2],
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlockReport {
    pub accepted: usize,
    pub rejected: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub rolled_back_to: Option<u32>,
    pub blocks: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub tip: Option<u32>,
}

pub struct Indexer {
    pub deployment: Deployment,
    verifier: TransferVerifier,
    pub state: ReplayState,
    vault_script: Option<ScriptBuf>,
}

impl Indexer {
    pub fn new(deployment: Deployment, verifier: TransferVerifier, state: ReplayState) -> Self {
        let vault_script = deployment.boundary.as_ref().map(|b| {
            ScriptBuf::from_bytes(hex::decode(&b.vault_script_hex).expect("vault script hex"))
        });
        Indexer {
            deployment,
            verifier,
            state,
            vault_script,
        }
    }

    /// Height the next replayed block must have.
    pub fn next_height(&self) -> u32 {
        self.state
            .last_height()
            .map(|h| h + 1)
            .unwrap_or(self.deployment.activation_height)
    }

    /// `R[h]` as replay defines it.
    pub fn root_at(&self, height: u32) -> Option<Fp> {
        self.state
            .root_at(height, self.deployment.activation_height)
    }

    /// Replay one block at the expected height. Panics if `id.height` is not
    /// [`Self::next_height`]; `sync` guarantees the order.
    pub fn replay_block(&mut self, id: BlockId, block: &Block) -> BlockReport {
        assert_eq!(
            id.height,
            self.next_height(),
            "blocks must be replayed in order"
        );
        // Optimistic pass first (`REPLAY-PROOF-A.md` §2): every envelope goes
        // through steps 1–5 and 7 in order with its proof left for a batch
        // verification at the end of the block. When the batch holds, every
        // proof was valid and the outcome equals the normative one. When it
        // does not, the block is undone and replayed sequentially with each
        // proof verified alone (§11 as written), which also names the culprit.
        let mut cp = self.checkpoint(id);
        let mut report = BlockReport::default();
        let mut batch = Vec::new();
        self.replay_txs(id, block, &mut cp, &mut report, Some(&mut batch));
        if !batch.is_empty() && !self.verifier.verify_batch(&batch) {
            debug!(
                "height {}: batch of {} proofs failed, replaying sequentially",
                id.height,
                batch.len()
            );
            self.undo(&cp);
            cp = self.checkpoint(id);
            report = BlockReport::default();
            self.replay_txs(id, block, &mut cp, &mut report, None);
        }
        let root = self.state.tree.root();
        self.state.roots.insert(id.height, root);
        self.state.blocks.push(cp);
        report
    }

    fn checkpoint(&self, id: BlockId) -> BlockCheckpoint {
        BlockCheckpoint {
            height: id.height,
            hash: id.hash,
            leaf_count_before: self.state.tree.size(),
            events_before: self.state.events.len(),
            rejections_before: self.state.rejections.len(),
            nullifiers_added: Vec::new(),
        }
    }

    /// Undo a block in progress: back to the checkpoint's before-state.
    fn undo(&mut self, cp: &BlockCheckpoint) {
        self.state.tree.truncate(cp.leaf_count_before);
        for nf in &cp.nullifiers_added {
            self.state.unmark_spent(nf);
        }
        self.state.events.truncate(cp.events_before);
        self.state.rejections.truncate(cp.rejections_before);
    }

    /// The block's carriers in order; with `batch`, transfer proofs are
    /// collected instead of verified.
    fn replay_txs(
        &mut self,
        id: BlockId,
        block: &Block,
        cp: &mut BlockCheckpoint,
        report: &mut BlockReport,
        mut batch: Option<&mut Vec<(TransferStatement, Vec<u8>)>>,
    ) {
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let Some(candidate) = self.deployment.carrier.extract(tx, &CANDIDATE_PREFIX) else {
                continue;
            };
            let txid = tx.compute_txid().to_byte_array();
            let result = candidate.map_err(RejectReason::from).and_then(|c| {
                self.accept(
                    id.height,
                    tx_index as u32,
                    txid,
                    tx,
                    &c.envelope,
                    batch.as_deref_mut(),
                )
                .map(|mut ev| {
                    ev.memo = c.memo;
                    ev
                })
            });
            match result {
                Ok(event) => {
                    cp.nullifiers_added.extend_from_slice(&event.nullifiers);
                    info!(
                        "height {} tx {}: accepted {:?}, leaves at {}",
                        id.height, tx_index, event.kind, event.first_position
                    );
                    self.state.events.push(event);
                    report.accepted += 1;
                }
                Err(reason) => {
                    debug!("height {} tx {}: rejected: {}", id.height, tx_index, reason);
                    self.state.rejections.push(Rejection {
                        height: id.height,
                        tx_index: tx_index as u32,
                        txid,
                        reason: reason.to_string(),
                    });
                    report.rejected += 1;
                }
            }
        }
    }

    fn accept(
        &mut self,
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        tx: &Transaction,
        bytes: &[u8],
        batch: Option<&mut Vec<(TransferStatement, Vec<u8>)>>,
    ) -> Result<AcceptedEvent, RejectReason> {
        match parse_envelope(bytes)? {
            Envelope::Transfer(env) => {
                let (h_body, statement) =
                    self.validate_transfer_with(height, &env, batch.is_none())?;
                if let Some(batch) = batch {
                    batch.push((statement, env.proof.clone()));
                }
                self.apply_transfer(height, tx_index, txid, env, h_body)
            }
            Envelope::Mint(env) => self.accept_mint(height, tx_index, txid, tx, env),
        }
    }

    /// Would this envelope be accepted if its carrier were included at
    /// `height`? Read-only: PROFILE-A.md §11 steps 1–6 against the current
    /// state. Mints are not checkable here (`None`).
    pub fn check_transfer(
        &self,
        bytes: &[u8],
        height: u32,
    ) -> Result<Option<TransferCheck>, RejectReason> {
        match parse_envelope(bytes)? {
            Envelope::Mint(_) => Ok(None),
            Envelope::Transfer(env) => {
                let h_body = self.validate_transfer(height, &env)?;
                Ok(Some(TransferCheck {
                    h_body,
                    h_anchor: env.body.h_anchor,
                    nullifiers: env.body.nullifiers,
                }))
            }
        }
    }

    /// PROFILE-A.md §11 steps 2–6; returns `h_body`.
    fn validate_transfer(
        &self,
        height: u32,
        envelope: &TransferEnvelope,
    ) -> Result<Fp, RejectReason> {
        self.validate_transfer_with(height, envelope, true)
            .map(|(h_body, _)| h_body)
    }

    /// Steps 2–5, and step 6 when `check_proof`; returns `h_body` and the
    /// statement the proof is (to be) verified against.
    fn validate_transfer_with(
        &self,
        height: u32,
        envelope: &TransferEnvelope,
        check_proof: bool,
    ) -> Result<(Fp, TransferStatement), RejectReason> {
        let body = &envelope.body;
        let h_body = body.h_body(&self.deployment.const_salt);
        let r_anchor = self.check_anchor_and_nullifiers(height, body)?;
        let statement = TransferStatement {
            const_salt: self.deployment.const_salt_fp(),
            r_anchor,
            nullifiers: body.nullifiers,
            pk_eph: body.pk_eph,
            ct_note: body.ct_note,
            h_body,
        };
        if check_proof && !self.verifier.verify(&statement, &envelope.proof) {
            return Err(RejectReason::ProofInvalid);
        }
        Ok((h_body, statement))
    }

    /// Steps 3–5; returns `r_anchor`.
    fn check_anchor_and_nullifiers(
        &self,
        height: u32,
        body: &TransferBody,
    ) -> Result<Fp, RejectReason> {
        let d = &self.deployment;
        let in_window = body.h_anchor as u64 + d.window_w as u64 >= height as u64
            && body.h_anchor as u64 + d.k_min as u64 <= height as u64;
        if !in_window {
            return Err(RejectReason::AnchorOutOfWindow {
                h_anchor: body.h_anchor,
                height,
            });
        }
        let r_anchor = self
            .root_at(body.h_anchor)
            .ok_or(RejectReason::AnchorUnknown(body.h_anchor))?;
        if body.nullifiers[0] == body.nullifiers[1] {
            return Err(RejectReason::DuplicateNullifier);
        }
        if body.nullifiers.iter().any(|nf| *nf == Fp::zero()) {
            return Err(RejectReason::ZeroNullifier);
        }
        if body.nullifiers.iter().any(|nf| self.state.is_spent(nf)) {
            return Err(RejectReason::SpentNullifier);
        }
        Ok(r_anchor)
    }

    /// Step 7.
    fn apply_transfer(
        &mut self,
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        envelope: TransferEnvelope,
        h_body: Fp,
    ) -> Result<AcceptedEvent, RejectReason> {
        let body = &envelope.body;
        let salt_fe = self.deployment.const_salt_fp();
        let first_position = self.state.tree.size();
        let mut leaves = Vec::with_capacity(N_OUT);
        for j in 0..N_OUT {
            let leaf = note_leaf(
                &salt_fe,
                &h_body,
                j as u64,
                &body.pk_eph[j],
                &body.ct_note[j],
            );
            self.state.tree.append(leaf);
            leaves.push(leaf);
        }
        for nf in &body.nullifiers {
            self.state.mark_spent(nf);
        }
        Ok(AcceptedEvent::from_transfer(
            height,
            tx_index,
            txid,
            &envelope,
            h_body,
            first_position,
            leaves,
        ))
    }

    /// Development mint (docs/BOUNDARY.md).
    fn accept_mint(
        &mut self,
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        tx: &Transaction,
        envelope: MintEnvelope,
    ) -> Result<AcceptedEvent, RejectReason> {
        let vault = self
            .vault_script
            .as_ref()
            .ok_or(RejectReason::MintDisabled)?;
        let paid: Vec<u64> = tx
            .output
            .iter()
            .filter(|o| o.script_pubkey == *vault)
            .map(|o| o.value.to_sat())
            .collect();
        if paid.len() != 1 || paid[0] != envelope.note.value {
            return Err(RejectReason::MintVault);
        }
        let h_body = envelope.h_body(&self.deployment.const_salt);
        let derived = envelope.derive().ok_or(RejectReason::MintDiversifier)?;
        let salt_fe = self.deployment.const_salt_fp();
        let leaf = note_leaf(&salt_fe, &h_body, 0, &derived.0, &derived.1);
        let first_position = self.state.tree.append(leaf);
        Ok(AcceptedEvent::from_mint(
            height,
            tx_index,
            txid,
            &envelope,
            h_body,
            derived,
            first_position,
            leaf,
        ))
    }

    /// Roll back to the last block still on the active chain, then replay
    /// every block up to the tip (in memory only).
    pub fn sync(&mut self, chain: &dyn ChainSource) -> Result<SyncReport, SyncError> {
        self.sync_with(chain, None)
    }

    /// [`Self::sync`] that also persists through `store`.
    pub fn sync_with(
        &mut self,
        chain: &dyn ChainSource,
        mut store: Option<&mut dyn StateStore>,
    ) -> Result<SyncReport, SyncError> {
        let mut report = SyncReport::default();
        let tip = chain.tip()?;
        report.tip = Some(tip.height);

        let mut fork: Option<u32> = None;
        for cp in self.state.blocks.iter().rev() {
            if chain.block_hash(cp.height)? == Some(cp.hash) {
                fork = Some(cp.height);
                break;
            }
        }
        if let Some(last) = self.state.last_height() {
            if fork != Some(last) {
                let rollback_to =
                    fork.unwrap_or(self.deployment.activation_height.saturating_sub(1));
                warn!(
                    "reorganisation: rolling back from {} to {}",
                    last, rollback_to
                );
                if fork.is_none() {
                    self.state = ReplayState::new();
                } else {
                    self.state.rollback_to(rollback_to);
                }
                if let Some(s) = store.as_mut() {
                    s.rollback_to(&self.state, rollback_to)?;
                }
                report.rolled_back_to = Some(rollback_to);
            }
        }

        let mut h = self.next_height();
        while h <= tip.height {
            let mut hash = chain.block_hash(h)?;
            let mut tries = 0;
            while hash.is_none() && tries < 10 {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_secs(3));
                hash = chain.block_hash(h)?;
            }
            let Some(hash) = hash else {
                break;
            };
            let block = chain.block(&hash)?;
            if block.block_hash() != hash {
                return Err(
                    ChainError::Decode(format!("block at {h} does not hash to {hash}")).into(),
                );
            }
            if let Some(prev) = self.state.blocks.last() {
                if block.header.prev_blockhash != prev.hash {
                    return Err(ChainError::Decode(format!(
                        "block {h} ({hash}) does not extend replayed block {} ({})",
                        prev.height, prev.hash
                    ))
                    .into());
                }
            }
            let r = self.replay_block(BlockId { height: h, hash }, &block);
            if let Some(s) = store.as_mut() {
                s.commit_block(&self.state, self.state.blocks.len() - 1)?;
            }
            report.blocks += 1;
            report.accepted += r.accepted;
            report.rejected += r.rejected;
            h += 1;
        }
        if let Some(s) = store {
            s.flush(&self.state)?;
        }
        Ok(report)
    }

    /// Accepted history after `index` (for wallet scanning).
    pub fn events_from(&self, index: usize) -> &[AcceptedEvent] {
        &self.state.events[index.min(self.state.events.len())..]
    }

    /// Is this transaction a carrier candidate under this deployment's rule?
    pub fn is_carrier(&self, tx: &Transaction) -> bool {
        self.deployment.carrier.is_carrier(tx, &CANDIDATE_PREFIX)
    }
}
