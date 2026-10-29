//! Indexed Merkle tree over field elements (`docs/REPLAY-PROOF.md` §4.1):
//! the nullifier set as a commitment with short non-membership proofs.
//!
//! Leaves are `(value, next)` pairs sorted by `value` through the `next`
//! links, hashed as `PH(T_IMT, value, next)`; leaf 0 is `(0, 0)` where
//! `next = 0` means "no greater value". Non-membership of `x` is the leaf
//! `(low, next)` with `low < x` and (`x < next` or `next = 0`) and its
//! path; inserting `x` rewrites that leaf to `(low, x)` and appends
//! `(x, next)`. Every path has `DEPTH` (32) siblings, against the 255 a
//! sparse tree over the field would need, at the price of a capacity of
//! 2³² values.

use std::collections::BTreeMap;

use ark_ff::{BigInteger, PrimeField};

use sb_primitives::Fr;
use sb_primitives::poseidon::hash;
use sb_primitives::tags::t_imt;

use crate::tree::{DEPTH, MerklePath, NoteTree};

/// A leaf: the value and the next greater value (`0` for none).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Leaf {
    pub value: Fr,
    pub next: Fr,
}

impl Leaf {
    pub fn hash(&self) -> Fr {
        hash(t_imt(), &[self.value, self.next])
    }
}

/// Field elements compared as integers.
fn lt(a: &Fr, b: &Fr) -> bool {
    a.into_bigint() < b.into_bigint()
}

/// Proof that `value` is not in the tree: the low leaf and its path under
/// the current root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NonMembership {
    pub low: Leaf,
    pub low_path: MerklePath,
}

impl NonMembership {
    /// Does this prove `value ∉` the tree with root `root`?
    pub fn verify(&self, root: &Fr, value: &Fr) -> bool {
        let ordered = lt(&self.low.value, value)
            && (self.low.next == Fr::from(0u64) || lt(value, &self.low.next));
        ordered && self.low_path.root(&self.low.hash()) == *root
    }
}

/// What an insertion of `value` changed: the low leaf before, its path,
/// the position of the new leaf and the new leaf's path in the tree
/// after the low leaf was rewritten (so that a verifier can recompute
/// the three roots: before, after the rewrite, after the append).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Insertion {
    pub value: Fr,
    pub low_before: Leaf,
    pub low_path: MerklePath,
    pub new_position: u64,
    pub new_path: MerklePath,
}

impl Insertion {
    /// The roots this insertion goes through: `(before, after)`, or `None`
    /// if the witness is inconsistent.
    pub fn roots(&self) -> Option<(Fr, Fr)> {
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
        // the new leaf's path must be a path in the tree with root `mid`
        // where its slot is still empty
        if self.new_path.position != self.new_position || self.new_path.root(&Fr::from(0u64)) != mid
        {
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

/// The tree with its leaves and a value index.
#[derive(Clone, Debug)]
pub struct IndexedMerkleTree {
    tree: NoteTree,
    leaves: Vec<Leaf>,
    /// value → leaf position
    index: BTreeMap<[u8; 32], usize>,
}

impl Default for IndexedMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

fn key(v: &Fr) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&v.into_bigint().to_bytes_be());
    k
}

impl IndexedMerkleTree {
    pub fn new() -> Self {
        let zero = Leaf {
            value: Fr::from(0u64),
            next: Fr::from(0u64),
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

    /// Rebuild from an insertion sequence.
    pub fn from_values(values: &[Fr]) -> Result<Self, ImtError> {
        let mut t = Self::new();
        for v in values {
            t.insert(*v)?;
        }
        Ok(t)
    }

    pub fn root(&self) -> Fr {
        self.tree.root_at(self.tree.size())
    }

    /// Number of values (the sentinel excluded).
    pub fn len(&self) -> usize {
        self.leaves.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, value: &Fr) -> bool {
        self.index.contains_key(&key(value))
    }

    /// Position of the leaf whose value is the greatest below `value`.
    fn low_position(&self, value: &Fr) -> usize {
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

    /// A non-membership proof for `value` under the current root, `None`
    /// if the value is in the tree.
    pub fn non_membership(&self, value: &Fr) -> Option<NonMembership> {
        if self.contains(value) || *value == Fr::from(0u64) {
            return None;
        }
        let p = self.low_position(value);
        Some(NonMembership {
            low: self.leaves[p],
            low_path: self.path(p),
        })
    }

    /// Insert `value`, returning the witness of the change.
    pub fn insert(&mut self, value: Fr) -> Result<Insertion, ImtError> {
        if value == Fr::from(0u64) {
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
        let new_path = MerklePath {
            position: new_position as u64,
            siblings: self.empty_slot_siblings(new_position),
        };
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

    /// Siblings of the (empty) slot `pos == size` in the current tree.
    fn empty_slot_siblings(&self, pos: usize) -> [Fr; DEPTH] {
        let mut probe = self.tree.clone();
        probe.append(Fr::from(0u64));
        probe
            .path_at(pos as u64, probe.size())
            .expect("just appended")
            .siblings
    }

    pub fn leaves(&self) -> &[Leaf] {
        &self.leaves
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
            Fr::from(500u64),
            Fr::from(20u64),
            Fr::from(9000u64),
            Fr::from(300u64),
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
        // the sorted chain: 0 → 20 → 300 → 500 → 9000 → none
        let mut chain = Vec::new();
        let mut cur = Fr::from(0u64);
        loop {
            let leaf = t.leaves().iter().find(|l| l.value == cur).unwrap();
            if leaf.next == Fr::from(0u64) {
                break;
            }
            chain.push(leaf.next);
            cur = leaf.next;
        }
        assert_eq!(
            chain,
            vec![
                Fr::from(20u64),
                Fr::from(300u64),
                Fr::from(500u64),
                Fr::from(9000u64)
            ]
        );
        // non-membership between and beyond existing values
        for (v, ok) in [
            (Fr::from(21u64), true),
            (Fr::from(10_000u64), true),
            (Fr::from(300u64), false),
        ] {
            assert_eq!(t.non_membership(&v).is_some(), ok);
        }
        let nm = t.non_membership(&Fr::from(21u64)).unwrap();
        assert!(nm.verify(&t.root(), &Fr::from(21u64)));
        assert!(
            !nm.verify(&t.root(), &Fr::from(301u64)),
            "another value under the same low leaf"
        );
        assert!(!nm.verify(&empty_root, &Fr::from(21u64)), "wrong root");
        assert!(
            nm.verify(&t.root(), &Fr::from(299u64)),
            "any value strictly inside the gap"
        );
        // the bounds are strict: a value equal to the low leaf or to its
        // successor is a member, and the same witness must not prove it out
        assert_eq!(nm.low.value, Fr::from(20u64));
        assert_eq!(nm.low.next, Fr::from(300u64));
        assert!(
            !nm.verify(&t.root(), &Fr::from(20u64)),
            "x == low is a member"
        );
        assert!(
            !nm.verify(&t.root(), &Fr::from(300u64)),
            "x == next is a member"
        );
        // the sentinel: the empty tree answers "not a member" for every value
        // through the (0, 0) leaf, and zero itself is never provable absent
        let empty = IndexedMerkleTree::new();
        let nm0 = empty.non_membership(&Fr::from(1u64)).unwrap();
        assert!(nm0.verify(&empty_root, &Fr::from(1u64)));
        assert!(
            nm0.verify(&empty_root, &(-Fr::from(1u64))),
            "the largest element too"
        );
        assert!(empty.non_membership(&Fr::from(0u64)).is_none());
        assert!(!nm0.verify(&empty_root, &Fr::from(0u64)));
        assert!(
            empty.contains(&Fr::from(0u64)),
            "the sentinel counts as present"
        );
        // errors and rebuild
        assert_eq!(t.insert(Fr::from(300u64)), Err(ImtError::Duplicate));
        assert_eq!(t.insert(Fr::from(0u64)), Err(ImtError::Zero));
        let again = IndexedMerkleTree::from_values(&values).unwrap();
        assert_eq!(again.root(), t.root());
        let other =
            IndexedMerkleTree::from_values(&[values[1], values[0], values[2], values[3]]).unwrap();
        assert_ne!(
            other.root(),
            t.root(),
            "the root commits to the insertion order"
        );
    }

    #[test]
    fn a_tampered_insertion_witness_does_not_verify() {
        let mut t = IndexedMerkleTree::new();
        t.insert(Fr::from(7u64)).unwrap();
        let mut ins = t.insert(Fr::from(9u64)).unwrap();
        assert!(ins.roots().is_some());
        ins.value = Fr::from(5u64); // not above the low leaf (7)
        assert!(ins.roots().is_none());
        let mut ins = t.insert(Fr::from(11u64)).unwrap();
        ins.new_position += 1;
        assert!(ins.roots().is_none());
    }
}
