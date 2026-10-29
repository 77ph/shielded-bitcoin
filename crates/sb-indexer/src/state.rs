//! Replayed shielded state `S = (T, N, R, H)` (paper Definition 1) with
//! per-block checkpoints for reorganisation rollback, and its file format.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};

use sb_core::batch::StateOpening;
use sb_core::envelope::{Envelope, parse_envelope};
use sb_core::event::{AcceptedEvent, EventKind};
use sb_core::imt::IndexedMerkleTree;
use sb_core::tree::{DEPTH, EMPTY_ROOTS, NoteTree};
use sb_primitives::Fr;

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
    #[serde(with = "hexbytes::fr_vec")]
    pub nullifiers_added: Vec<Fr>,
}

#[derive(Clone, Debug, Default)]
pub struct ReplayState {
    pub tree: NoteTree,
    pub nullifiers: HashSet<Fr>,
    /// `R[h]` for every replayed height.
    pub roots: BTreeMap<u32, Fr>,
    pub blocks: Vec<BlockCheckpoint>,
    pub events: Vec<AcceptedEvent>,
    pub rejections: Vec<Rejection>,
    /// The nullifier set as a commitment (`docs/REPLAY-PROOF.md` §4.1):
    /// the same set as `nullifiers`, in acceptance order. Derived from
    /// `events`; rebuilt on load and after a rollback.
    pub nullifier_tree: IndexedMerkleTree,
    /// The root history as a commitment: leaf `i` is the root of the
    /// `i`-th replayed block. Derived from `roots`.
    pub root_tree: NoteTree,
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
    #[serde(with = "hexbytes::fr")]
    h_body: Fr,
    first_position: u64,
    #[serde(with = "hexbytes::fr_vec")]
    leaves: Vec<Fr>,
    #[serde(default, with = "hexbytes::opt_bytes")]
    memo: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    version: u32,
    #[serde(with = "hexbytes::fr_vec")]
    leaves: Vec<Fr>,
    #[serde(with = "hexbytes::fr_vec")]
    nullifiers: Vec<Fr>,
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
    /// Rebuild the two commitments from the replayed history (after a
    /// load or a rollback; both are pure functions of it).
    pub fn rebuild_commitments(&mut self) {
        let nfs: Vec<Fr> = self
            .events
            .iter()
            .flat_map(|e| e.nullifiers.iter().copied())
            .collect();
        self.nullifier_tree =
            IndexedMerkleTree::from_values(&nfs).expect("replay accepts no duplicate nullifier");
        let roots: Vec<Fr> = self.roots.values().copied().collect();
        self.root_tree = NoteTree::from_leaves(&roots);
    }

    /// Do the commitments describe exactly the sets and history replay
    /// keeps? (A test oracle; production code keeps them in step.)
    pub fn check_commitments(&self) -> bool {
        self.nullifier_tree.len() == self.nullifiers.len()
            && self
                .nullifiers
                .iter()
                .all(|nf| self.nullifier_tree.contains(nf))
            && self.root_tree.size() == self.roots.len() as u64
            && self
                .roots
                .values()
                .zip(self.root_tree.leaves())
                .all(|(a, b)| a == b)
    }

    /// The state as a batch proof opens it (`docs/REPLAY-PROOF.md` §4.1),
    /// between blocks: `height` is the next block to replay, `applied` 0.
    /// `activation` is the first replayed height.
    pub fn opening(&self, activation: u32) -> StateOpening {
        StateOpening {
            root: self.tree.root(),
            size: self.tree.size(),
            nf_root: self.nullifier_tree.root(),
            nf_size: self.nullifier_tree.size(),
            h_root: self.root_tree.root(),
            height: self.last_height().map_or(activation, |h| h + 1),
            applied: 0,
        }
    }

    /// The state digest a replay proof transitions between.
    pub fn digest(&self, activation: u32) -> Fr {
        self.opening(activation).digest()
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// Height of the last replayed block.
    pub fn last_height(&self) -> Option<u32> {
        self.blocks.last().map(|b| b.height)
    }

    /// `R[h]`: the empty root before the first replayed block, else the
    /// stored root. `None` for a height not yet replayed.
    pub fn root_at(&self, height: u32, first_height: u32) -> Option<Fr> {
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
                self.nullifiers.remove(nf);
            }
            self.tree.truncate(cp.leaf_count_before);
            self.events.truncate(cp.events_before);
            self.rejections.truncate(cp.rejections_before);
            self.roots.remove(&cp.height);
        }
        self.rebuild_commitments();
    }

    pub fn to_json(&self) -> String {
        let f = StateFile {
            version: 1,
            leaves: self.tree.leaves().to_vec(),
            nullifiers: {
                let mut v: Vec<Fr> = self.nullifiers.iter().copied().collect();
                v.sort();
                v
            },
            roots: self
                .roots
                .iter()
                .map(|(h, r)| (*h, hex::encode(sb_primitives::encoding::fr_to_bytes(r))))
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
        if f.version != 1 {
            return Err(StateError::Corrupt(format!(
                "unknown version {}",
                f.version
            )));
        }
        let mut roots = BTreeMap::new();
        for (h, r) in f.roots {
            let bytes = hex::decode(&r).map_err(|e| StateError::Corrupt(e.to_string()))?;
            roots.insert(
                h,
                sb_primitives::encoding::fr_from_bytes(&bytes)
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
                Envelope::Swap(sw) => AcceptedEvent::from_swap(
                    e.height,
                    e.tx_index,
                    e.txid,
                    &sw,
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
            debug_assert!(matches!(
                ev.kind,
                EventKind::Transfer | EventKind::Mint | EventKind::Swap
            ));
            events.push(ev);
        }
        let mut state = ReplayState {
            tree: NoteTree::from_leaves(&f.leaves),
            nullifiers: f.nullifiers.into_iter().collect(),
            roots,
            blocks: f.blocks,
            events,
            rejections: f.rejections,
            nullifier_tree: IndexedMerkleTree::new(),
            root_tree: NoteTree::new(),
        };
        state.rebuild_commitments();
        Ok(state)
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
            && self.roots == other.roots
            && self.blocks == other.blocks
            && self.events == other.events
            && self.rejections == other.rejections
    }
}
