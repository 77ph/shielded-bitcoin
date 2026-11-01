//! The append-only note tree (paper §8; PROFILE-A.md §6): depth 32,
//! Poseidon nodes, empty leaf `0`, every level stored so that
//! authentication paths exist under any earlier root.

use std::sync::LazyLock;

use ff::Field;
use sba_primitives::Fp;
use sba_primitives::poseidon::hash;
use sba_primitives::tags::t_node;

pub const DEPTH: usize = 32;

/// `PH_A(T_NODE, left, right)`.
pub fn node_hash(left: &Fp, right: &Fp) -> Fp {
    hash(t_node(), &[*left, *right])
}

/// `E_0 = 0`, `E_{k+1} = PH_A(T_NODE, E_k, E_k)`.
pub static EMPTY_ROOTS: LazyLock<[Fp; DEPTH + 1]> = LazyLock::new(|| {
    let mut e = [Fp::ZERO; DEPTH + 1];
    for k in 0..DEPTH {
        e[k + 1] = node_hash(&e[k], &e[k]);
    }
    e
});

/// Authentication path of a leaf: sibling at each level, leaf level first.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerklePath {
    pub position: u64,
    pub siblings: [Fp; DEPTH],
}

impl MerklePath {
    /// Recompute the root for `leaf` at `self.position`.
    pub fn root(&self, leaf: &Fp) -> Fp {
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
    levels: Vec<Vec<Fp>>,
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

    pub fn from_leaves(leaves: &[Fp]) -> Self {
        let mut t = Self::new();
        for l in leaves {
            t.append(*l);
        }
        t
    }

    pub fn size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn leaves(&self) -> &[Fp] {
        &self.levels[0]
    }

    /// Append a leaf, returning its position.
    pub fn append(&mut self, leaf: Fp) -> u64 {
        let pos = self.levels[0].len();
        assert!(pos < (1usize << DEPTH), "note tree is full");
        self.levels[0].push(leaf);
        self.recompute(pos);
        pos as u64
    }

    fn recompute(&mut self, pos: usize) {
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
    }

    /// Truncate to the first `size` leaves (reorganisation rollback).
    pub fn truncate(&mut self, size: u64) {
        let size = size as usize;
        if size >= self.levels[0].len() {
            return;
        }
        let leaves: Vec<Fp> = self.levels[0][..size].to_vec();
        *self = Self::from_leaves(&leaves);
    }

    fn node_at(&self, level: usize, index: u64, size: u64) -> Fp {
        let start = index << level;
        let end = start + (1u64 << level);
        if start >= size {
            return EMPTY_ROOTS[level];
        }
        if end <= size {
            return self.levels[level][index as usize];
        }
        let l = self.node_at(level - 1, index * 2, size);
        let r = self.node_at(level - 1, index * 2 + 1, size);
        node_hash(&l, &r)
    }

    pub fn root(&self) -> Fp {
        self.root_at(self.size())
    }

    /// Root as it was at `size` leaves.
    pub fn root_at(&self, size: u64) -> Fp {
        assert!(size <= self.size());
        self.node_at(DEPTH, 0, size)
    }

    /// Authentication path for `position` under the root at `size` leaves.
    pub fn path_at(&self, position: u64, size: u64) -> Option<MerklePath> {
        if position >= size || size > self.size() {
            return None;
        }
        let mut siblings = [Fp::ZERO; DEPTH];
        let mut idx = position;
        for (k, s) in siblings.iter_mut().enumerate() {
            *s = self.node_at(k, idx ^ 1, size);
            idx >>= 1;
        }
        Some(MerklePath { position, siblings })
    }

    pub fn path(&self, position: u64) -> Option<MerklePath> {
        self.path_at(position, self.size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn naive_root(leaves: &[Fp]) -> Fp {
        let mut layer: Vec<Fp> = leaves.to_vec();
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
    fn roots_paths_and_history_agree_with_naive() {
        let mut rng = StdRng::seed_from_u64(4);
        assert_eq!(NoteTree::new().root(), EMPTY_ROOTS[DEPTH]);
        let leaves: Vec<Fp> = (0..13).map(|_| Fp::random(&mut rng)).collect();
        let mut t = NoteTree::new();
        let mut roots = vec![t.root()];
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(t.append(*l), i as u64);
            roots.push(t.root());
            assert_eq!(t.root(), naive_root(&leaves[..=i]));
        }
        for size in 0..=leaves.len() as u64 {
            assert_eq!(t.root_at(size), roots[size as usize]);
            for pos in 0..size {
                let p = t.path_at(pos, size).unwrap();
                assert_eq!(p.root(&leaves[pos as usize]), roots[size as usize]);
            }
            assert!(t.path_at(size, size).is_none());
        }
        t.truncate(7);
        assert_eq!(t.size(), 7);
        assert_eq!(t.root(), roots[7]);
        assert_eq!(t.root(), NoteTree::from_leaves(&leaves[..7]).root());
        assert!(NoteTree::default().path(0).is_none());
    }
}
