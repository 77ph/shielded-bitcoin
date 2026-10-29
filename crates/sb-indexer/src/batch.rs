//! Batch construction on the indexer's side (`docs/REPLAY-PROOF.md` §4.5):
//! the state of one block rebuilt from the replayed history, its accepted
//! envelopes turned into slot statements, and the witnesses of the three
//! trees' changes, in fragments of `n` slots, the last one closing the
//! block. The light client's side is `crate::proof`.

use std::collections::BTreeMap;

use sb_core::batch::{
    BatchStatement, BatchWitness, N_OUT, NullifierInsert, SlotStatement, SlotWitness, StateOpening,
    batch_digest,
};
use sb_core::envelope::{Envelope, parse_envelope};
use sb_core::event::AcceptedEvent;
use sb_core::imt::IndexedMerkleTree;
use sb_core::note::{NoteCiphertext, note_leaf_aux};
use sb_core::tree::{DEPTH, EMPTY_ROOTS, MerklePath, NoteTree};
use sb_primitives::{Fr, JubjubAffine};

use crate::state::ReplayState;

#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    #[error("block {0} is not replayed")]
    NotReplayed(u32),
    #[error("event at height {0} tx {1} has no parsable envelope")]
    Envelope(u32, u32),
    #[error("anchor {0} has no root in the history")]
    Anchor(u32),
    #[error("nullifier tree: {0}")]
    Imt(#[from] sb_core::imt::ImtError),
}

/// One fragment of a block's proof: its public inputs, its witness and the
/// statements the client will receive (with the carrier txid for its
/// bookkeeping).
#[derive(Clone, Debug)]
pub struct Fragment {
    pub statement: BatchStatement,
    pub witness: BatchWitness,
    pub slots: Vec<Option<(SlotStatement, [u8; 32])>>,
    pub next: StateOpening,
}

/// The slot statement of an accepted event; `roots` is the history it
/// anchors into.
pub fn slot_statement(
    event: &AcceptedEvent,
    roots: &BTreeMap<u32, Fr>,
    activation: u32,
) -> Result<SlotStatement, BatchError> {
    let env = parse_envelope(&event.raw)
        .map_err(|_| BatchError::Envelope(event.height, event.tx_index))?;
    let (h_anchor, h_aux, mint) = match &env {
        Envelope::Transfer(e) => (e.body.h_anchor, [Fr::from(0u64); N_OUT], false),
        Envelope::Swap(e) => (e.body.base.h_anchor, e.body.h_aux, false),
        Envelope::Mint(_) => (0, [Fr::from(0u64); N_OUT], true),
    };
    let zero_ct = NoteCiphertext {
        c0: Fr::from(0u64),
        c1: Fr::from(0u64),
        tag: Fr::from(0u64),
    };
    let mut pk_eph = [JubjubAffine::default(); N_OUT];
    let mut ct = [zero_ct; N_OUT];
    for (j, (p, c)) in event.outputs.iter().enumerate().take(N_OUT) {
        pk_eph[j] = *p;
        ct[j] = *c;
    }
    let mut nullifiers = [Fr::from(0u64); 2];
    for (i, nf) in event.nullifiers.iter().enumerate().take(2) {
        nullifiers[i] = *nf;
    }
    let r_anchor = if mint {
        Fr::from(0u64)
    } else if h_anchor < activation {
        EMPTY_ROOTS[DEPTH]
    } else {
        *roots.get(&h_anchor).ok_or(BatchError::Anchor(h_anchor))?
    };
    Ok(SlotStatement {
        h_anchor,
        r_anchor,
        nullifiers,
        pk_eph,
        ct,
        h_body: event.h_body,
        h_aux,
        mint,
    })
}

/// The trees as they were before block `height`, rebuilt from the replayed
/// history (an indexer that proves every block would record its witnesses
/// while replaying instead; this is the simple way).
pub struct Trees {
    pub tree: NoteTree,
    pub nf: IndexedMerkleTree,
    pub roots: NoteTree,
    pub history: BTreeMap<u32, Fr>,
    pub height: u32,
    pub applied: u32,
    salt: Fr,
}

impl Trees {
    pub fn before(state: &ReplayState, height: u32, const_salt: &Fr) -> Result<Self, BatchError> {
        let cp = state
            .blocks
            .iter()
            .find(|b| b.height == height)
            .ok_or(BatchError::NotReplayed(height))?;
        let leaves = &state.tree.leaves()[..cp.leaf_count_before as usize];
        let nfs: Vec<Fr> = state.events[..cp.events_before]
            .iter()
            .flat_map(|e| e.nullifiers.iter().copied())
            .collect();
        let history: BTreeMap<u32, Fr> = state
            .roots
            .iter()
            .filter(|(h, _)| **h < height)
            .map(|(h, r)| (*h, *r))
            .collect();
        let mut root_leaves = vec![EMPTY_ROOTS[DEPTH]];
        root_leaves.extend(history.values().copied());
        Ok(Trees {
            tree: NoteTree::from_leaves(leaves),
            nf: IndexedMerkleTree::from_values(&nfs)?,
            roots: NoteTree::from_leaves(&root_leaves),
            history,
            height,
            applied: 0,
            salt: *const_salt,
        })
    }

    pub fn opening(&self) -> StateOpening {
        StateOpening {
            root: self.tree.root(),
            size: self.tree.size(),
            nf_root: self.nf.root(),
            nf_size: self.nf.size(),
            h_root: self.roots.root(),
            height: self.height,
            applied: self.applied,
        }
    }

    /// Apply one event, returning its slot witness.
    fn apply(&mut self, event: &AcceptedEvent, activation: u32) -> Result<SlotWitness, BatchError> {
        let statement = slot_statement(event, &self.history, activation)?;
        let zero_path = MerklePath {
            position: 0,
            siblings: [Fr::from(0u64); DEPTH],
        };
        let unused = NullifierInsert {
            low: sb_core::imt::Leaf {
                value: Fr::from(0u64),
                next: Fr::from(0u64),
            },
            low_path: zero_path.clone(),
            new_path: zero_path.clone(),
        };
        let (anchor_siblings, nullifiers) = if statement.mint {
            ([Fr::from(0u64); DEPTH], [unused.clone(), unused])
        } else {
            let sibs = if statement.h_anchor < activation {
                [Fr::from(0u64); DEPTH]
            } else {
                let pos = (statement.h_anchor - activation + 1) as u64;
                self.roots
                    .path_at(pos, self.roots.size())
                    .ok_or(BatchError::Anchor(statement.h_anchor))?
                    .siblings
            };
            let a = NullifierInsert::from(&self.nf.insert(statement.nullifiers[0])?);
            let b = NullifierInsert::from(&self.nf.insert(statement.nullifiers[1])?);
            (sibs, [a, b])
        };
        let salt = self.salt;
        let mut leaves = [zero_path.clone(), zero_path];
        let n_leaves = if statement.mint { 1 } else { N_OUT };
        for (j, leaf_path) in leaves.iter_mut().enumerate().take(n_leaves) {
            let leaf = note_leaf_aux(
                &salt,
                &statement.h_body,
                j as u64,
                &statement.pk_eph[j],
                &statement.ct[j],
                &statement.h_aux[j],
            );
            debug_assert_eq!(leaf, event.leaves[j], "the statement reproduces the leaf");
            *leaf_path = self.tree.append_path();
            self.tree.append(leaf);
        }
        self.applied += 1;
        Ok(SlotWitness {
            statement,
            anchor_siblings,
            nullifiers,
            leaves,
        })
    }

    fn finish_block(&mut self) -> MerklePath {
        let path = self.roots.append_path();
        let root = self.tree.root();
        self.roots.append(root);
        self.history.insert(self.height, root);
        self.height += 1;
        self.applied = 0;
        path
    }
}

/// Build the fragments of block `height`: the state before it rebuilt from
/// `state`, its accepted events in order, `n` slots per fragment, the last
/// fragment closing the block (an empty block is one fragment with no
/// slots).
pub fn build_block(
    state: &ReplayState,
    height: u32,
    n: usize,
    activation: u32,
    const_salt: &Fr,
) -> Result<Vec<Fragment>, BatchError> {
    let mut trees = Trees::before(state, height, const_salt)?;
    let events: Vec<&AcceptedEvent> = state.events.iter().filter(|e| e.height == height).collect();
    let mut fragments = Vec::new();
    let chunks: Vec<&[&AcceptedEvent]> = if events.is_empty() {
        vec![&[]]
    } else {
        events.chunks(n).collect()
    };
    let last = chunks.len() - 1;
    for (ci, chunk) in chunks.iter().enumerate() {
        let prev = trees.opening();
        let mut slots = Vec::with_capacity(n);
        let mut witnesses = Vec::with_capacity(n);
        for ev in chunk.iter() {
            let w = trees.apply(ev, activation)?;
            slots.push(Some((w.statement, ev.txid)));
            witnesses.push(Some(w));
        }
        while witnesses.len() < n {
            witnesses.push(None);
            slots.push(None);
        }
        let final_block = ci == last;
        let root_append = final_block.then(|| trees.finish_block());
        let next = trees.opening();
        let statements: Vec<Option<SlotStatement>> =
            slots.iter().map(|s| s.map(|(st, _)| st)).collect();
        let statement = BatchStatement {
            s_prev: prev.digest(),
            s_next: next.digest(),
            d: batch_digest(&statements),
        };
        fragments.push(Fragment {
            statement,
            witness: BatchWitness {
                prev,
                slots: witnesses,
                final_block,
                root_append,
            },
            slots,
            next,
        });
    }
    Ok(fragments)
}
