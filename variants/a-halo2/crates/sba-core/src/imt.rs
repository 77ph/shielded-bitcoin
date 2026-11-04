//! The indexed nullifier tree (`docs/REPLAY-PROOF.md` §4.1, the paper's
//! `sb-core/src/imt.rs` with the family's field and hash): the spent set as
//! a Merkle tree of sorted linked leaves `(value, next)` so that
//! non-membership is a path to the leaf whose gap holds the value, and an
//! insertion is two path updates. Leaf 0 is the sentinel `(0, 0)`; `next =
//! 0` means "no greater value". Leaves are hashed as `PH_A(T_IMT, value,
//! next)`; the tree is a `NoteTree` (depth 32, `PH_A(T_NODE, …)` nodes).

use std::collections::BTreeMap;

use ff::{Field, PrimeField};
use sba_primitives::Fp;
use sba_primitives::poseidon::hash;
use sba_primitives::tags::t_imt;

use crate::tree::{DEPTH, MerklePath, NoteTree};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leaf {
    pub value: Fp,
    pub next: Fp,
}

impl Leaf {
    pub fn hash(&self) -> Fp {
        hash(t_imt(), &[self.value, self.next])
    }
}

/// The canonical bytes, big-endian, so that byte order is integer order.
fn key(v: &Fp) -> [u8; 32] {
    let mut k = v.to_repr();
    k.reverse();
    k
}

fn lt(a: &Fp, b: &Fp) -> bool {
    key(a) < key(b)
}

/// A value's absence: the leaf below it and that leaf's path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NonMembership {
    pub low: Leaf,
    pub low_path: MerklePath,
}

impl NonMembership {
    /// `low.value < value < low.next` (or `low.next = 0`), and the low leaf
    /// is in the tree of `root`.
    pub fn verify(&self, root: &Fp, value: &Fp) -> bool {
        let ordered =
            lt(&self.low.value, value) && (self.low.next == Fp::ZERO || lt(value, &self.low.next));
        ordered && self.low_path.root(&self.low.hash()) == *root
    }
}

/// The witness of one insertion: the low leaf before, its path, and the
/// path of the new leaf's (then empty) position.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Insertion {
    pub value: Fp,
    pub low_before: Leaf,
    pub low_path: MerklePath,
    pub new_position: u64,
    pub new_path: MerklePath,
}

impl Insertion {
    /// The roots before and after, if the witness is consistent: the low
    /// leaf proves non-membership under the root before; rewriting it and
    /// appending the new leaf over an empty slot gives the root after.
    pub fn roots(&self) -> Option<(Fp, Fp)> {
        let low_after = Leaf {
            value: self.low_before.value,
            next: self.value,
        };
        let new_leaf = Leaf {
            value: self.value,
            next: self.low_before.next,
        };
        let nm = NonMembership {
            low: self.low_before,
            low_path: self.low_path.clone(),
        };
        let before = self.low_path.root(&self.low_before.hash());
        if !nm.verify(&before, &self.value) {
            return None;
        }
        let mid = self.low_path.root(&low_after.hash());
        if self.new_path.position != self.new_position || self.new_path.root(&Fp::ZERO) != mid {
            return None;
        }
        Some((before, self.new_path.root(&new_leaf.hash())))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImtError {
    #[error("value already in the tree")]
    Duplicate,
    #[error("zero is the sentinel and cannot be inserted")]
    Zero,
    #[error("tree is full")]
    Full,
}

#[derive(Clone, Debug)]
pub struct IndexedMerkleTree {
    tree: NoteTree,
    leaves: Vec<Leaf>,
    index: BTreeMap<[u8; 32], usize>,
}

impl Default for IndexedMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexedMerkleTree {
    pub fn new() -> Self {
        let zero = Leaf {
            value: Fp::ZERO,
            next: Fp::ZERO,
        };
        let mut tree = NoteTree::new();
        tree.append(zero.hash());
        let mut index = BTreeMap::new();
        index.insert(key(&zero.value), 0);
        IndexedMerkleTree {
            tree,
            leaves: vec![zero],
            index,
        }
    }

    pub fn from_values(values: &[Fp]) -> Result<Self, ImtError> {
        let mut t = Self::new();
        for v in values {
            t.insert(*v)?;
        }
        Ok(t)
    }

    pub fn root(&self) -> Fp {
        self.tree.root_at(self.tree.size())
    }

    /// Values inserted (the sentinel not counted).
    pub fn len(&self) -> usize {
        self.leaves.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, value: &Fp) -> bool {
        self.index.contains_key(&key(value))
    }

    fn low_position(&self, value: &Fp) -> usize {
        let k = key(value);
        *self
            .index
            .range(..k)
            .next_back()
            .map(|(_, p)| p)
            .expect("the zero sentinel is below every value")
    }

    fn path(&self, pos: usize) -> MerklePath {
        self.tree
            .path_at(pos as u64, self.tree.size())
            .expect("leaf exists")
    }

    /// The witness that `value` is absent (`None` if present, or zero).
    pub fn non_membership(&self, value: &Fp) -> Option<NonMembership> {
        if self.contains(value) || *value == Fp::ZERO {
            return None;
        }
        let p = self.low_position(value);
        Some(NonMembership {
            low: self.leaves[p],
            low_path: self.path(p),
        })
    }

    pub fn insert(&mut self, value: Fp) -> Result<Insertion, ImtError> {
        if value == Fp::ZERO {
            return Err(ImtError::Zero);
        }
        if self.contains(&value) {
            return Err(ImtError::Duplicate);
        }
        if self.leaves.len() >= 1usize << DEPTH {
            return Err(ImtError::Full);
        }
        let p = self.low_position(&value);
        let low_before = self.leaves[p];
        let low_path = self.path(p);
        let low_after = Leaf {
            value: low_before.value,
            next: value,
        };
        self.leaves[p] = low_after;
        self.tree.set(p as u64, low_after.hash());
        let new_leaf = Leaf {
            value,
            next: low_before.next,
        };
        let new_position = self.leaves.len();
        // the path of the still-empty slot, in the tree after the rewrite
        let new_path = self.tree.append_path();
        debug_assert_eq!(new_path.position, new_position as u64);
        self.leaves.push(new_leaf);
        self.tree.append(new_leaf.hash());
        self.index.insert(key(&value), new_position);
        Ok(Insertion {
            value,
            low_before,
            low_path,
            new_position: new_position as u64,
            new_path,
        })
    }

    /// Leaves including the sentinel: `nf_size` of the state opening.
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn leaves(&self) -> &[Leaf] {
        &self.leaves
    }

    /// Rebuild with the first `len` inserted values only (a reorganisation
    /// rolls insertions back in order).
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }
        // insertion order is leaf order
        let values: Vec<Fp> = self.leaves[1..=len].iter().map(|l| l.value).collect();
        *self = Self::from_values(&values).expect("were inserted once");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertions_prove_before_and_after_and_non_membership_holds() {
        let mut t = IndexedMerkleTree::new();
        let empty_root = t.root();
        let values = [
            Fp::from(500u64),
            Fp::from(20u64),
            Fp::from(9000u64),
            Fp::from(300u64),
        ];
        let mut prev = empty_root;
        for v in values {
            let nm = t.non_membership(&v).unwrap();
            assert!(nm.verify(&prev, &v));
            let ins = t.insert(v).unwrap();
            let (before, after) = ins.roots().unwrap();
            assert_eq!(before, prev);
            assert_eq!(after, t.root());
            prev = after;
            assert!(t.contains(&v));
            assert!(t.non_membership(&v).is_none());
        }
        assert_eq!(t.len(), 4);
        assert_eq!(t.size(), 5);
        // the sorted chain: 0 → 20 → 300 → 500 → 9000 → none
        let mut chain = Vec::new();
        let mut cur = Fp::ZERO;
        loop {
            let leaf = t.leaves().iter().find(|l| l.value == cur).unwrap();
            if leaf.next == Fp::ZERO {
                break;
            }
            chain.push(leaf.next);
            cur = leaf.next;
        }
        assert_eq!(
            chain,
            vec![
                Fp::from(20u64),
                Fp::from(300u64),
                Fp::from(500u64),
                Fp::from(9000u64)
            ]
        );
        for (v, ok) in [
            (Fp::from(21u64), true),
            (Fp::from(10_000u64), true),
            (Fp::from(300u64), false),
        ] {
            assert_eq!(t.non_membership(&v).is_some(), ok);
        }
        let nm = t.non_membership(&Fp::from(21u64)).unwrap();
        assert!(nm.verify(&t.root(), &Fp::from(21u64)));
        assert!(!nm.verify(&t.root(), &Fp::from(301u64)));
        assert!(!nm.verify(&empty_root, &Fp::from(21u64)));
        assert!(nm.verify(&t.root(), &Fp::from(299u64)));
        assert_eq!(nm.low.value, Fp::from(20u64));
        assert_eq!(nm.low.next, Fp::from(300u64));
        assert!(!nm.verify(&t.root(), &Fp::from(20u64)));
        assert!(!nm.verify(&t.root(), &Fp::from(300u64)));
        // the sentinel: the empty tree answers "not a member" for every
        // value through the (0, 0) leaf, and zero itself is never absent
        let empty = IndexedMerkleTree::new();
        let nm0 = empty.non_membership(&Fp::from(1u64)).unwrap();
        assert!(nm0.verify(&empty_root, &Fp::from(1u64)));
        assert!(nm0.verify(&empty_root, &(-Fp::from(1u64))));
        assert!(empty.non_membership(&Fp::ZERO).is_none());
        assert!(!nm0.verify(&empty_root, &Fp::ZERO));
        assert!(empty.contains(&Fp::ZERO));
        // errors, rebuild, order, rollback
        assert_eq!(t.insert(Fp::from(300u64)), Err(ImtError::Duplicate));
        assert_eq!(t.insert(Fp::ZERO), Err(ImtError::Zero));
        let again = IndexedMerkleTree::from_values(&values).unwrap();
        assert_eq!(again.root(), t.root());
        let other =
            IndexedMerkleTree::from_values(&[values[1], values[0], values[2], values[3]]).unwrap();
        assert_ne!(other.root(), t.root(), "the root commits to the order");
        let two = IndexedMerkleTree::from_values(&values[..2]).unwrap();
        t.truncate(2);
        assert_eq!(t.root(), two.root());
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn a_tampered_insertion_witness_does_not_verify() {
        let mut t = IndexedMerkleTree::new();
        t.insert(Fp::from(7u64)).unwrap();
        let mut ins = t.insert(Fp::from(9u64)).unwrap();
        assert!(ins.roots().is_some());
        ins.value = Fp::from(5u64);
        assert!(ins.roots().is_none());
        let mut ins = t.insert(Fp::from(11u64)).unwrap();
        ins.new_position += 1;
        assert!(ins.roots().is_none());
    }
}
