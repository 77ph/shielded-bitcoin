//! Deterministic replay (paper §8, §15; profile §11), plus the development
//! mint of docs/BOUNDARY.md.

use bitcoin::hashes::Hash;
use bitcoin::{Block, ScriptBuf, Transaction};
use log::{debug, info, warn};

use sb_circuit::{SwapStatement, SwapVerifier, TransferStatement, TransferVerifier};
use sb_core::envelope::{
    Envelope, MintEnvelope, ParseError, SwapEnvelope, TransferBody, TransferEnvelope,
    parse_envelope,
};
use sb_core::event::AcceptedEvent;
use sb_core::note::{note_leaf, note_leaf_aux};
use sb_core::recovery::N_OUT;
use sb_primitives::Fr;

use crate::carrier::CarrierError;
use crate::chain::{BlockId, ChainError, ChainSource};
use crate::deployment::Deployment;
use crate::state::{BlockCheckpoint, Rejection, ReplayState};
use crate::store::{StateStore, StoreError};

/// Why an envelope did not mutate state (profile §11, steps 1–6).
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
    #[error("swap: this deployment has no swap extension")]
    SwapDisabled,
}

/// What [`Indexer::check_transfer`] learned about a valid transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCheck {
    pub h_body: Fr,
    pub h_anchor: u32,
    pub nullifiers: [Fr; 2],
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
    /// The swap extension's verifier when the deployment enables it.
    swap_verifier: Option<SwapVerifier>,
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
            swap_verifier: None,
            state,
            vault_script,
        }
    }

    /// Enable the swap extension (`docs/SWAP.md` §8) with its verifier.
    pub fn with_swap_verifier(mut self, verifier: SwapVerifier) -> Self {
        self.swap_verifier = Some(verifier);
        self
    }

    /// Height the next replayed block must have.
    pub fn next_height(&self) -> u32 {
        self.state
            .last_height()
            .map(|h| h + 1)
            .unwrap_or(self.deployment.activation_height)
    }

    /// `R[h]` as replay defines it.
    pub fn root_at(&self, height: u32) -> Option<Fr> {
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
        let mut cp = BlockCheckpoint {
            height: id.height,
            hash: id.hash,
            leaf_count_before: self.state.tree.size(),
            events_before: self.state.events.len(),
            rejections_before: self.state.rejections.len(),
            nullifiers_added: Vec::new(),
        };
        let mut report = BlockReport::default();
        for (tx_index, tx) in block.txdata.iter().enumerate() {
            let Some(candidate) = self.deployment.carrier.extract(tx) else {
                continue;
            };
            let txid = tx.compute_txid().to_byte_array();
            let result = candidate.map_err(RejectReason::from).and_then(|c| {
                self.accept(id.height, tx_index as u32, txid, tx, &c.envelope)
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
        let root = self.state.tree.root();
        self.state.roots.insert(id.height, root);
        self.state.blocks.push(cp);
        report
    }

    fn accept(
        &mut self,
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        tx: &Transaction,
        bytes: &[u8],
    ) -> Result<AcceptedEvent, RejectReason> {
        match parse_envelope(bytes)? {
            Envelope::Transfer(env) => self.accept_transfer(height, tx_index, txid, env),
            Envelope::Mint(env) => self.accept_mint(height, tx_index, txid, tx, env),
            Envelope::Swap(env) => self.accept_swap(height, tx_index, txid, env),
        }
    }

    /// Would this envelope be accepted if its carrier were included at
    /// `height`? Read-only: profile §11 steps 1–6 against the current state.
    /// A publisher that pays the carrier fee for someone else runs this
    /// before spending (docs/BOUNDARY.md, "Fee funding"). Mints are not
    /// checkable here (`None`): their validity depends on the carrier's
    /// vault output.
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
            Envelope::Swap(env) => {
                let h_body = self.validate_swap(height, &env)?;
                Ok(Some(TransferCheck {
                    h_body,
                    h_anchor: env.body.base.h_anchor,
                    nullifiers: env.body.base.nullifiers,
                }))
            }
        }
    }

    /// Validate and, if accepted, apply one transfer (profile §11).
    fn accept_transfer(
        &mut self,
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        envelope: TransferEnvelope,
    ) -> Result<AcceptedEvent, RejectReason> {
        let h_body = self.validate_transfer(height, &envelope)?;
        self.apply_transfer(height, tx_index, txid, envelope, h_body)
    }

    /// Profile §11 steps 2–6; returns `h_body`.
    fn validate_transfer(
        &self,
        height: u32,
        envelope: &TransferEnvelope,
    ) -> Result<Fr, RejectReason> {
        let body = &envelope.body;
        // 2. h_body
        let h_body = body.h_body(&self.deployment.const_salt);
        let r_anchor = self.check_anchor_and_nullifiers(height, body)?;
        let statement = self.statement(body, r_anchor, h_body);
        // 6. proof
        if !self.verifier.verify(&statement, &envelope.proof) {
            return Err(RejectReason::ProofInvalid);
        }
        Ok(h_body)
    }

    /// `docs/SWAP.md` §8: the base steps with the extension's verifier and
    /// statement; returns `h_body` over the swap body.
    fn validate_swap(&self, height: u32, envelope: &SwapEnvelope) -> Result<Fr, RejectReason> {
        let verifier = self
            .swap_verifier
            .as_ref()
            .ok_or(RejectReason::SwapDisabled)?;
        let body = &envelope.body.base;
        let h_body = envelope.body.h_body(&self.deployment.const_salt);
        let r_anchor = self.check_anchor_and_nullifiers(height, body)?;
        let statement = SwapStatement {
            base: self.statement(body, r_anchor, h_body),
            h_anchor: body.h_anchor,
        };
        if !verifier.verify(&statement, &envelope.proof) {
            return Err(RejectReason::ProofInvalid);
        }
        Ok(h_body)
    }

    fn statement(&self, body: &TransferBody, r_anchor: Fr, h_body: Fr) -> TransferStatement {
        TransferStatement {
            const_salt: self.deployment.const_salt_fr(),
            r_anchor,
            nullifiers: body.nullifiers,
            pk_eph: body.pk_eph,
            ct_note: body.ct_note,
            h_body,
        }
    }

    /// Profile §11 steps 3–5; returns `r_anchor`.
    fn check_anchor_and_nullifiers(
        &self,
        height: u32,
        body: &TransferBody,
    ) -> Result<Fr, RejectReason> {
        // 3. anchor window: H - W <= h_anchor <= H - K_min
        let d = &self.deployment;
        let in_window = body.h_anchor as u64 + d.window_w as u64 >= height as u64
            && body.h_anchor as u64 + d.k_min as u64 <= height as u64;
        if !in_window {
            return Err(RejectReason::AnchorOutOfWindow {
                h_anchor: body.h_anchor,
                height,
            });
        }
        // 4. r_anchor
        let r_anchor = self
            .root_at(body.h_anchor)
            .ok_or(RejectReason::AnchorUnknown(body.h_anchor))?;
        // 5. nullifiers
        if body.nullifiers[0] == body.nullifiers[1] {
            return Err(RejectReason::DuplicateNullifier);
        }
        if body
            .nullifiers
            .iter()
            .any(|nf| self.state.nullifiers.contains(nf))
        {
            return Err(RejectReason::SpentNullifier);
        }
        Ok(r_anchor)
    }

    /// Validate and apply one swap envelope (`docs/SWAP.md` §8).
    fn accept_swap(
        &mut self,
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        envelope: SwapEnvelope,
    ) -> Result<AcceptedEvent, RejectReason> {
        let h_body = self.validate_swap(height, &envelope)?;
        let body = &envelope.body.base;
        let salt_fe = self.deployment.const_salt_fr();
        let first_position = self.state.tree.size();
        let mut leaves = Vec::with_capacity(N_OUT);
        for j in 0..N_OUT {
            let leaf = note_leaf_aux(
                &salt_fe,
                &h_body,
                j as u64,
                &body.pk_eph[j],
                &body.ct_note[j],
                &envelope.body.h_aux[j],
            );
            self.state.tree.append(leaf);
            leaves.push(leaf);
        }
        for nf in &body.nullifiers {
            self.state.nullifiers.insert(*nf);
        }
        Ok(AcceptedEvent::from_swap(
            height,
            tx_index,
            txid,
            &envelope,
            h_body,
            first_position,
            leaves,
        ))
    }

    /// Profile §11 step 7.
    fn apply_transfer(
        &mut self,
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        envelope: TransferEnvelope,
        h_body: Fr,
    ) -> Result<AcceptedEvent, RejectReason> {
        let body = &envelope.body;
        let salt_fe = self.deployment.const_salt_fr();
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
            self.state.nullifiers.insert(*nf);
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
        let salt_fe = self.deployment.const_salt_fr();
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

    /// Roll back to the last block that is still on the active chain, then
    /// replay every block up to the tip (state kept in memory only).
    pub fn sync(&mut self, chain: &dyn ChainSource) -> Result<SyncReport, SyncError> {
        self.sync_with(chain, None)
    }

    /// [`Self::sync`] that also persists through `store`: a rollback is
    /// recorded before replay resumes and every replayed block is committed
    /// as soon as it is applied, so a crash loses at most the block in flight.
    pub fn sync_with(
        &mut self,
        chain: &dyn ChainSource,
        mut store: Option<&mut dyn StateStore>,
    ) -> Result<SyncReport, SyncError> {
        let mut report = SyncReport::default();
        let tip = chain.tip()?;
        report.tip = Some(tip.height);

        // Reorganisation detection: walk back until a stored hash matches.
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
            // An Esplora tip height can run ahead of its block-hash lookup for a
            // few seconds; retry briefly before giving up on this round.
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
            // The source is trusted for chain selection, not for block
            // contents: the block must be the one named by the hash and must
            // extend the block replayed before it.
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
        self.deployment.carrier.is_carrier(tx)
    }
}
