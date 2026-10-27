//! Deterministic replay (paper §8, §15; profile §11).

use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction};
use log::{debug, info, warn};

use sb_circuit::{TransferStatement, TransferVerifier};
use sb_core::envelope::{ParseError, TransferEnvelope};
use sb_core::event::AcceptedTransfer;
use sb_core::note::note_leaf;
use sb_core::recovery::N_OUT;
use sb_primitives::Fr;

use crate::carrier::{CarrierError, extract_envelope};
use crate::chain::{BlockId, ChainError, ChainSource};
use crate::deployment::Deployment;
use crate::state::{BlockCheckpoint, Rejection, ReplayState};

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
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlockReport {
    pub accepted: usize,
    pub rejected: usize,
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
}

impl Indexer {
    pub fn new(deployment: Deployment, verifier: TransferVerifier, state: ReplayState) -> Self {
        Indexer {
            deployment,
            verifier,
            state,
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
            let Some(candidate) = extract_envelope(tx) else {
                continue;
            };
            let txid = tx.compute_txid().to_byte_array();
            let result = candidate
                .map_err(RejectReason::from)
                .and_then(|bytes| self.accept(id.height, tx_index as u32, txid, &bytes));
            match result {
                Ok(event) => {
                    cp.nullifiers_added
                        .extend_from_slice(&event.envelope.body.nullifiers);
                    info!(
                        "height {} tx {}: accepted transfer, leaves at {}",
                        id.height, tx_index, event.first_position
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

    /// Validate and, if accepted, apply one envelope (profile §11).
    fn accept(
        &mut self,
        height: u32,
        tx_index: u32,
        txid: [u8; 32],
        bytes: &[u8],
    ) -> Result<AcceptedTransfer, RejectReason> {
        // 1. canonical parse
        let envelope = TransferEnvelope::parse(bytes)?;
        let body = &envelope.body;
        // 2. h_body
        let h_body = body.h_body(&self.deployment.const_salt);
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
        // 6. proof
        let statement = TransferStatement {
            const_salt: d.const_salt_fr(),
            r_anchor,
            nullifiers: body.nullifiers,
            pk_eph: body.pk_eph,
            ct_note: body.ct_note,
            h_body,
        };
        if !self.verifier.verify(&statement, &envelope.proof) {
            return Err(RejectReason::ProofInvalid);
        }
        // 7. apply
        let salt_fe = d.const_salt_fr();
        let first_position = self.state.tree.size();
        let mut leaves = [Fr::from(0u64); N_OUT];
        for j in 0..N_OUT {
            leaves[j] = note_leaf(
                &salt_fe,
                &h_body,
                j as u64,
                &body.pk_eph[j],
                &body.ct_note[j],
            );
            self.state.tree.append(leaves[j]);
        }
        for nf in &body.nullifiers {
            self.state.nullifiers.insert(*nf);
        }
        Ok(AcceptedTransfer {
            height,
            tx_index,
            txid,
            envelope,
            h_body,
            first_position,
            leaves,
        })
    }

    /// Roll back to the last block that is still on the active chain, then
    /// replay every block up to the tip.
    pub fn sync(&mut self, chain: &dyn ChainSource) -> Result<SyncReport, ChainError> {
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
            let rollback_to = fork.unwrap_or(self.deployment.activation_height.saturating_sub(1));
            if fork != Some(last) {
                warn!(
                    "reorganisation: rolling back from {} to {}",
                    last, rollback_to
                );
                if fork.is_none() {
                    self.state = ReplayState::new();
                } else {
                    self.state.rollback_to(rollback_to);
                }
                report.rolled_back_to = Some(rollback_to);
            }
        }

        let mut h = self.next_height();
        while h <= tip.height {
            let Some(hash) = chain.block_hash(h)? else {
                break;
            };
            let block = chain.block(&hash)?;
            let r = self.replay_block(BlockId { height: h, hash }, &block);
            report.blocks += 1;
            report.accepted += r.accepted;
            report.rejected += r.rejected;
            h += 1;
        }
        Ok(report)
    }

    /// Accepted history after `index` (for wallet scanning).
    pub fn events_from(&self, index: usize) -> &[AcceptedTransfer] {
        &self.state.events[index.min(self.state.events.len())..]
    }

    /// Is this transaction a carrier candidate? (Convenience for wallets
    /// tracking their own publications.)
    pub fn is_carrier(tx: &Transaction) -> bool {
        extract_envelope(tx).is_some()
    }
}
