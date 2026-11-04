//! Replayed shielded state `S = (T, N, R, H)` (paper Definition 1) with
//! per-block checkpoints for reorganisation rollback, and its file format.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

use sba_core::batch::{BatchWitness, StateOpening};
use sba_core::envelope::{Envelope, parse_envelope};
use sba_core::event::AcceptedEvent;
use sba_core::imt::{IndexedMerkleTree, Insertion};
use sba_core::tree::{DEPTH, EMPTY_ROOTS, NoteTree};
use sba_primitives::Fp;
use sba_primitives::encoding::fp_to_bytes;

use crate::hexbytes;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejection {
    pub height: u32,
    pub tx_index: u32,
    #[serde(with = "hexbytes")]
    pub txid: [u8; 32],
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockCheckpoint {
    pub height: u32,
    pub hash: BlockHash,
    pub leaf_count_before: u64,
    pub events_before: usize,
    pub rejections_before: usize,
    #[serde(with = "hexbytes::fp_vec")]
    pub nullifiers_added: Vec<Fp>,
}

#[derive(Clone, Debug)]
pub struct ReplayState {
    pub tree: NoteTree,
    /// The spent set, keyed by the nullifier's canonical bytes (`Fp` has
    /// no `Hash`); [`ReplayState::is_spent`] looks one up.
    pub nullifiers: HashSet<[u8; 32]>,
    /// The spent set again, as the indexed tree the accumulated replay
    /// proof opens (`docs/REPLAY-PROOF-A.md` §3.7): the same nullifiers in
    /// insertion order.
    pub nf_tree: IndexedMerkleTree,
    /// `R[h]` for every replayed height.
    pub roots: BTreeMap<u32, Fp>,
    /// The root tree: leaf 0 the initial (empty) note root, leaf `i` the
    /// root after the `i`-th replayed block.
    pub h_tree: NoteTree,
    pub blocks: Vec<BlockCheckpoint>,
    pub events: Vec<AcceptedEvent>,
    pub rejections: Vec<Rejection>,
    /// One batch witness per replayed block, in memory only (the prover of
    /// the accumulated replay proof consumes them as blocks are replayed).
    pub batches: Vec<BatchWitness>,
}

impl Default for ReplayState {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialisable event record; outputs are re-derived from `raw` on load.
#[derive(Serialize, Deserialize)]
struct EventRecord {
    height: u32,
    tx_index: u32,
    #[serde(with = "hexbytes")]
    txid: [u8; 32],
    #[serde(with = "hexbytes::bytes")]
    raw: Vec<u8>,
    #[serde(with = "hexbytes::fp")]
    h_body: Fp,
    first_position: u64,
    #[serde(with = "hexbytes::fp_vec")]
    leaves: Vec<Fp>,
    #[serde(default, with = "hexbytes::opt_bytes")]
    memo: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    version: u32,
    family: String,
    #[serde(with = "hexbytes::fp_vec")]
    leaves: Vec<Fp>,
    #[serde(with = "hexbytes::fp_vec")]
    nullifiers: Vec<Fp>,
    roots: Vec<(u32, String)>,
    blocks: Vec<BlockCheckpoint>,
    events: Vec<EventRecord>,
    rejections: Vec<Rejection>,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("corrupt state: {0}")]
    Corrupt(String),
}

impl ReplayState {
    pub fn new() -> Self {
        let mut h_tree = NoteTree::new();
        h_tree.append(EMPTY_ROOTS[DEPTH]);
        ReplayState {
            tree: NoteTree::new(),
            nullifiers: HashSet::new(),
            nf_tree: IndexedMerkleTree::new(),
            roots: BTreeMap::new(),
            h_tree,
            blocks: Vec::new(),
            events: Vec::new(),
            rejections: Vec::new(),
            batches: Vec::new(),
        }
    }

    pub fn is_spent(&self, nf: &Fp) -> bool {
        self.nullifiers.contains(&fp_to_bytes(nf))
    }

    /// Spend: into the set and the tree, whose insertion witness is returned.
    pub fn mark_spent(&mut self, nf: &Fp) -> Insertion {
        self.nullifiers.insert(fp_to_bytes(nf));
        self.nf_tree
            .insert(*nf)
            .expect("checked absent, non-zero, and the tree is not full")
    }

    /// The inverse of [`mark_spent`](Self::mark_spent) for the set; the
    /// tree is rolled back by count ([`unspend_last`](Self::unspend_last)).
    pub fn unmark_spent(&mut self, nf: &Fp) {
        self.nullifiers.remove(&fp_to_bytes(nf));
    }

    /// Roll the nullifier tree back over its last `n` insertions.
    pub fn unspend_last(&mut self, n: usize) {
        let len = self.nf_tree.len();
        self.nf_tree.truncate(len.saturating_sub(n));
    }

    /// The state opening at the start of block `height` (nothing applied).
    pub fn opening(&self, height: u32) -> StateOpening {
        StateOpening {
            root: self.tree.root(),
            size: self.tree.size(),
            nf_root: self.nf_tree.root(),
            nf_size: self.nf_tree.size(),
            h_root: self.h_tree.root(),
            height,
            applied: 0,
        }
    }

    /// Height of the last replayed block.
    pub fn last_height(&self) -> Option<u32> {
        self.blocks.last().map(|b| b.height)
    }

    /// `R[h]`: the empty root before the first replayed block, else the
    /// stored root. `None` for a height not yet replayed.
    pub fn root_at(&self, height: u32, first_height: u32) -> Option<Fp> {
        if height < first_height {
            return Some(EMPTY_ROOTS[DEPTH]);
        }
        self.roots.get(&height).copied()
    }

    /// Leaf count after block `height` (for anchor-relative Merkle paths).
    pub fn size_at(&self, height: u32) -> Option<u64> {
        if let Some(pos) = self.blocks.iter().position(|b| b.height == height) {
            return Some(
                self.blocks
                    .get(pos + 1)
                    .map(|n| n.leaf_count_before)
                    .unwrap_or(self.tree.size()),
            );
        }
        if self
            .blocks
            .first()
            .map(|b| height < b.height)
            .unwrap_or(true)
        {
            return Some(0);
        }
        None
    }

    /// Undo every block above `height`.
    pub fn rollback_to(&mut self, height: u32) {
        while let Some(last) = self.blocks.last() {
            if last.height <= height {
                break;
            }
            let cp = self.blocks.pop().unwrap();
            for nf in &cp.nullifiers_added {
                self.nullifiers.remove(&fp_to_bytes(nf));
            }
            self.unspend_last(cp.nullifiers_added.len());
            self.tree.truncate(cp.leaf_count_before);
            self.events.truncate(cp.events_before);
            self.rejections.truncate(cp.rejections_before);
            self.roots.remove(&cp.height);
            self.h_tree.truncate(self.blocks.len() as u64 + 1);
            self.batches.truncate(self.blocks.len());
        }
    }

    pub fn to_json(&self) -> String {
        let f = StateFile {
            // 2: nullifiers in insertion order (the tree's); 1 stored them sorted
            version: 2,
            family: sba_core::FAMILY.into(),
            leaves: self.tree.leaves().to_vec(),
            nullifiers: self.nf_tree.leaves()[1..].iter().map(|l| l.value).collect(),
            roots: self
                .roots
                .iter()
                .map(|(h, r)| (*h, hex::encode(sba_primitives::encoding::fp_to_bytes(r))))
                .collect(),
            blocks: self.blocks.clone(),
            events: self
                .events
                .iter()
                .map(|e| EventRecord {
                    height: e.height,
                    tx_index: e.tx_index,
                    txid: e.txid,
                    raw: e.raw.clone(),
                    h_body: e.h_body,
                    first_position: e.first_position,
                    leaves: e.leaves.clone(),
                    memo: e.memo.clone(),
                })
                .collect(),
            rejections: self.rejections.clone(),
        };
        serde_json::to_string(&f).expect("serializable")
    }

    pub fn from_json(json: &str) -> Result<Self, StateError> {
        let f: StateFile = serde_json::from_str(json)?;
        if !(f.version == 1 || f.version == 2) || f.family != sba_core::FAMILY {
            return Err(StateError::Corrupt(format!(
                "unknown version {} / family {}",
                f.version, f.family
            )));
        }
        let mut roots = BTreeMap::new();
        for (h, r) in f.roots {
            let bytes = hex::decode(&r).map_err(|e| StateError::Corrupt(e.to_string()))?;
            roots.insert(
                h,
                sba_primitives::encoding::fp_from_bytes(&bytes)
                    .map_err(|e| StateError::Corrupt(e.to_string()))?,
            );
        }
        let mut events = Vec::with_capacity(f.events.len());
        for e in f.events {
            let env = parse_envelope(&e.raw).map_err(|e| StateError::Corrupt(e.to_string()))?;
            let mut ev = match env {
                Envelope::Transfer(t) => AcceptedEvent::from_transfer(
                    e.height,
                    e.tx_index,
                    e.txid,
                    &t,
                    e.h_body,
                    e.first_position,
                    e.leaves,
                ),
                Envelope::Mint(m) => {
                    let derived = m
                        .derive()
                        .ok_or_else(|| StateError::Corrupt("mint diversifier".into()))?;
                    let leaf = *e
                        .leaves
                        .first()
                        .ok_or_else(|| StateError::Corrupt("mint leaf".into()))?;
                    AcceptedEvent::from_mint(
                        e.height,
                        e.tx_index,
                        e.txid,
                        &m,
                        e.h_body,
                        derived,
                        e.first_position,
                        leaf,
                    )
                }
            };
            ev.memo = e.memo;
            events.push(ev);
        }
        // a version-1 file lost the insertion order (it stored the set
        // sorted): its tree is rebuilt in file order and differs from the
        // history's; a resync restores it
        let nf_tree = IndexedMerkleTree::from_values(&f.nullifiers)
            .map_err(|e| StateError::Corrupt(e.to_string()))?;
        let mut h_tree = NoteTree::new();
        h_tree.append(EMPTY_ROOTS[DEPTH]);
        for r in roots.values() {
            h_tree.append(*r);
        }
        Ok(ReplayState {
            tree: NoteTree::from_leaves(&f.leaves),
            nullifiers: f.nullifiers.iter().map(fp_to_bytes).collect(),
            nf_tree,
            roots,
            h_tree,
            blocks: f.blocks,
            events,
            rejections: f.rejections,
            batches: Vec::new(),
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), StateError> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_json())?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, StateError> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }
}

impl PartialEq for ReplayState {
    /// Two states are equal when replay produced the same `(T, N, R, H)`.
    fn eq(&self, other: &Self) -> bool {
        self.tree.leaves() == other.tree.leaves()
            && self.nullifiers == other.nullifiers
            && self.nf_tree.root() == other.nf_tree.root()
            && self.roots == other.roots
            && self.h_tree.root() == other.h_tree.root()
            && self.blocks == other.blocks
            && self.events == other.events
            && self.rejections == other.rejections
    }
}
