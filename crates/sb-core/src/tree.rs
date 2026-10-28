//! The append-only note tree (paper §8; profile §6).
//!
//! Depth 32, Poseidon nodes, empty leaf `0`. Every level is stored so that
//! authentication paths can be produced for any leaf under the root at any
//! earlier tree size (`size`), which is what anchoring to `R[h_anchor]`
//! requires after the tree has grown.

use std::sync::LazyLock;

use sb_primitives::Fr;
use sb_primitives::poseidon::hash;
use sb_primitives::tags::t_node;

pub const DEPTH: usize = 32;

/// `PH(T_NODE, left, right)`.
pub fn node_hash(left: &Fr, right: &Fr) -> Fr {
    hash(t_node(), &[*left, *right])
}

/// `E_0 = 0`, `E_{k+1} = PH(T_NODE, E_k, E_k)`.
pub static EMPTY_ROOTS: LazyLock<[Fr; DEPTH + 1]> = LazyLock::new(|| {
    let mut e = [Fr::from(0u64); DEPTH + 1];
    for k in 0..DEPTH {
        e[k + 1] = node_hash(&e[k], &e[k]);
    }
    e
});

/// Authentication path of a leaf: sibling at each level, leaf level first.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerklePath {
    pub position: u64,
    pub siblings: [Fr; DEPTH],
}

impl MerklePath {
    /// Recompute the root for `leaf` at `self.position`.
    pub fn root(&self, leaf: &Fr) -> Fr {
        let mut cur = *leaf;
        let mut idx = self.position;
        for s in &self.siblings {
            cur = if idx & 1 == 0 {
                node_hash(&cur, s)
            } else {
                node_hash(s, &cur)
            };
            idx >>= 1;
        }
        cur
    }
}

/// The note tree with all levels materialised.
#[derive(Clone, Debug)]
pub struct NoteTree {
    /// `levels[0]` = leaves, `levels[k][i]` = node `i` at height `k`.
    levels: Vec<Vec<Fr>>,
}

impl Default for NoteTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteTree {
    pub fn new() -> Self {
        NoteTree {
            levels: vec![Vec::new(); DEPTH + 1],
        }
    }

    /// Rebuild from a leaf sequence.
    pub fn from_leaves(leaves: &[Fr]) -> Self {
        let mut t = Self::new();
        for l in leaves {
            t.append(*l);
        }
        t
    }

    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.levels[0]
    }

    /// Append a leaf, returning its position.
    pub fn append(&mut self, leaf: Fr) -> u64 {
        let pos = self.levels[0].len();
        assert!(pos < (1usize << DEPTH), "note tree is full");
        self.levels[0].push(leaf);
        let mut idx = pos;
        for k in 0..DEPTH {
            let parent = idx >> 1;
            let left = self.levels[k][parent * 2];
            let right = self.levels[k]
                .get(parent * 2 + 1)
                .copied()
                .unwrap_or(EMPTY_ROOTS[k]);
            let h = node_hash(&left, &right);
            if parent < self.levels[k + 1].len() {
                self.levels[k + 1][parent] = h;
            } else {
                self.levels[k + 1].push(h);
            }
            idx = parent;
        }
        pos as u64
    }

    /// Truncate to the first `size` leaves (reorganisation rollback).
    pub fn truncate(&mut self, size: u64) {
        let size = size as usize;
        if size >= self.levels[0].len() {
            return;
        }
        let leaves: Vec<Fr> = self.levels[0][..size].to_vec();
        *self = Self::from_leaves(&leaves);
    }

    /// Node `index` at height `level`, as it was when the tree had `size` leaves.
    fn node_at(&self, level: usize, index: u64, size: u64) -> Fr {
        let start = index << level;
        let end = start + (1u64 << level);
        if start >= size {
            return EMPTY_ROOTS[level];
        }
        if end <= size {
            // Fully populated at `size`: final, equal to the stored node.
            return self.levels[level][index as usize];
        }
        // level > 0 here: a leaf is either fully inside or fully outside `size`.
        let l = self.node_at(level - 1, index * 2, size);
        let r = self.node_at(level - 1, index * 2 + 1, size);
        node_hash(&l, &r)
    }

    /// Root of the current tree.
    pub fn root(&self) -> Fr {
        self.root_at(self.size())
    }

    /// Root as it was at `size` leaves.
    pub fn root_at(&self, size: u64) -> Fr {
        assert!(size <= self.size());
        self.node_at(DEPTH, 0, size)
    }

    /// Authentication path for `position` under the root at `size` leaves.
    pub fn path_at(&self, position: u64, size: u64) -> Option<MerklePath> {
        if position >= size || size > self.size() {
            return None;
        }
        let mut siblings = [Fr::from(0u64); DEPTH];
        let mut idx = position;
        for (k, s) in siblings.iter_mut().enumerate() {
            *s = self.node_at(k, idx ^ 1, size);
            idx >>= 1;
        }
        Some(MerklePath { position, siblings })
    }

    /// Authentication path under the current root.
    pub fn path(&self, position: u64) -> Option<MerklePath> {
        self.path_at(position, self.size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    fn naive_root(leaves: &[Fr]) -> Fr {
        let mut layer: Vec<Fr> = leaves.to_vec();
        for k in 0..DEPTH {
            if layer.is_empty() {
                return EMPTY_ROOTS[DEPTH];
            }
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            for pair in layer.chunks(2) {
                let r = pair.get(1).copied().unwrap_or(EMPTY_ROOTS[k]);
                next.push(node_hash(&pair[0], &r));
            }
            layer = next;
        }
        layer[0]
    }

    #[test]
    fn empty_tree_root() {
        assert_eq!(NoteTree::new().root(), EMPTY_ROOTS[DEPTH]);
    }

    #[test]
    fn roots_paths_and_history_agree_with_naive() {
        let mut rng = StdRng::seed_from_u64(4);
        let leaves: Vec<Fr> = (0..13).map(|_| Fr::rand(&mut rng)).collect();
        let mut t = NoteTree::new();
        let mut roots = vec![t.root()];
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(t.append(*l), i as u64);
            roots.push(t.root());
            assert_eq!(t.root(), naive_root(&leaves[..=i]));
        }
        // past roots and paths under them
        for size in 0..=leaves.len() as u64 {
            assert_eq!(t.root_at(size), roots[size as usize]);
            for pos in 0..size {
                let p = t.path_at(pos, size).unwrap();
                assert_eq!(p.root(&leaves[pos as usize]), roots[size as usize]);
            }
            assert!(t.path_at(size, size).is_none());
        }
        // truncate and compare with a fresh tree
        t.truncate(7);
        assert_eq!(t.size(), 7);
        assert_eq!(t.root(), roots[7]);
        assert_eq!(t.root(), NoteTree::from_leaves(&leaves[..7]).root());
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn empty_tree_paths_and_truncate_noop() {
        let mut t = NoteTree::new();
        assert!(t.path(0).is_none());
        assert!(t.path_at(0, 0).is_none());
        t.truncate(5);
        assert_eq!(t.size(), 0);
        assert_eq!(t.root_at(0), EMPTY_ROOTS[DEPTH]);
        let d = NoteTree::default();
        assert_eq!(d.root(), EMPTY_ROOTS[DEPTH]);
    }
}
