//! Replay batches for the accumulated replay proof (`docs/REPLAY-PROOF-A.md`
//! §3.7, after `docs/REPLAY-PROOF.md` §4 and the paper's
//! `sb-core/src/batch.rs`): the state opening behind a state digest, the
//! statement of one accepted transfer as the batch relation sees it, and
//! the witnesses of the three trees' changes. Native only; the circuit is
//! the recursion's `T_p`.

use ff::{Field, PrimeField};
use sba_primitives::poseidon::hash;
use sba_primitives::tags::{t_batch, t_state};
use sba_primitives::{Affine, Fp};

use crate::imt::{Insertion, Leaf};
use crate::note::{NoteCiphertext, note_leaf};
use crate::tree::{DEPTH, EMPTY_ROOTS, MerklePath};

pub use crate::envelope::N_IN;
pub use crate::recovery::N_OUT;

/// The replay state as the relation transitions it: the note tree
/// (`root`, `size`), the nullifier tree (`nf_root`, `nf_size`, sentinel
/// included), the root tree (`h_root`), the block in progress (`height`,
/// the first block whose root is **not** in the root tree) and how many
/// statements of it were applied so far (`applied`; `0` between blocks).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateOpening {
    pub root: Fp,
    pub size: u64,
    pub nf_root: Fp,
    pub nf_size: u64,
    pub h_root: Fp,
    pub height: u32,
    pub applied: u32,
}

impl StateOpening {
    /// `PH_A(T_STATE, R, size, N, nf_size, H, height, applied)`.
    pub fn digest(&self) -> Fp {
        hash(
            t_state(),
            &[
                self.root,
                Fp::from(self.size),
                self.nf_root,
                Fp::from(self.nf_size),
                self.h_root,
                Fp::from(self.height as u64),
                Fp::from(self.applied as u64),
            ],
        )
    }
}

/// One accepted envelope as the batch sees it: the public inputs of its
/// proof without the constants (`const_salt`, arities), plus the anchor
/// height and its kind. A **mint** (the development boundary) has no
/// anchor, no nullifiers and one output: its validity is the carrier's
/// vault payment, and the relation only appends its leaf.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotStatement {
    pub h_anchor: u32,
    pub r_anchor: Fp,
    pub nullifiers: [Fp; N_IN],
    /// The ephemeral keys as coordinates; `(0, 0)` for a mint's absent
    /// second output.
    pub pk_eph: [(Fp, Fp); N_OUT],
    pub ct: [NoteCiphertext; N_OUT],
    pub h_body: Fp,
    pub mint: bool,
}

/// An absent output's ciphertext.
pub const NO_CT: NoteCiphertext = NoteCiphertext {
    c0: Fp::ZERO,
    c1: Fp::ZERO,
    tag: Fp::ZERO,
};

/// `h_anchor, r_anchor, nullifiers, (x, y, c0, c1, tag) per output, h_body, kind`.
pub const SLOT_ELEMENTS: usize = 1 + 1 + N_IN + N_OUT * 5 + 1 + 1;

/// Index of `h_body` among a slot's elements.
pub const SLOT_H_BODY: usize = 2 + N_IN + N_OUT * 5;

fn u32_of(f: &Fp) -> Option<u32> {
    let b = f.to_repr();
    if b[4..].iter().any(|x| *x != 0) {
        return None;
    }
    Some(u32::from_le_bytes(b[..4].try_into().ok()?))
}

impl SlotStatement {
    /// Outputs a slot of this kind appends: one for a mint.
    pub fn outputs(&self) -> usize {
        if self.mint { 1 } else { N_OUT }
    }

    pub fn to_elements(&self) -> [Fp; SLOT_ELEMENTS] {
        let mut v = Vec::with_capacity(SLOT_ELEMENTS);
        v.push(Fp::from(self.h_anchor as u64));
        v.push(self.r_anchor);
        v.extend_from_slice(&self.nullifiers);
        for j in 0..N_OUT {
            let (x, y) = self.pk_eph[j];
            v.push(x);
            v.push(y);
            v.extend_from_slice(&self.ct[j].elements());
        }
        v.push(self.h_body);
        v.push(Fp::from(self.mint as u64));
        v.try_into().expect("SLOT_ELEMENTS")
    }

    /// The inverse of [`Self::to_elements`], `None` if the elements are
    /// not a statement: a height above `u32`, a used output's key off the
    /// curve, a kind other than 0 or 1.
    pub fn from_elements(e: &[Fp]) -> Option<Self> {
        use pasta_curves::arithmetic::CurveAffine;
        if e.len() != SLOT_ELEMENTS {
            return None;
        }
        let h_anchor = u32_of(&e[0])?;
        let mint = match u32_of(&e[SLOT_ELEMENTS - 1])? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let outputs = if mint { 1 } else { N_OUT };
        let mut pk_eph = [(Fp::ZERO, Fp::ZERO); N_OUT];
        let mut ct = [NO_CT; N_OUT];
        for j in 0..N_OUT {
            let base = 2 + N_IN + j * 5;
            if j < outputs {
                Option::<Affine>::from(Affine::from_xy(e[base], e[base + 1]))?;
            }
            pk_eph[j] = (e[base], e[base + 1]);
            ct[j] = NoteCiphertext {
                c0: e[base + 2],
                c1: e[base + 3],
                tag: e[base + 4],
            };
        }
        let mut nullifiers = [Fp::ZERO; N_IN];
        nullifiers.copy_from_slice(&e[2..2 + N_IN]);
        Some(SlotStatement {
            h_anchor,
            r_anchor: e[1],
            nullifiers,
            pk_eph,
            ct,
            h_body: e[SLOT_H_BODY],
            mint,
        })
    }
}

/// Elements per chunk of the batch digest's chain.
pub const DIGEST_CHUNK: usize = 8;

/// `D` over the `16 n` elements of `n` slots (an empty slot all zeros), in
/// the order replay applied them: `PH_A` is defined up to 10 inputs, so
/// `D` is the chain `acc ← PH_A(T_BATCH, acc, e_1 … e_8)` over the elements
/// in chunks of 8 (zero-padded), from `acc = n` — the slot count first,
/// so that padding and empty slots are told apart.
pub fn batch_digest(slots: &[Option<SlotStatement>]) -> Fp {
    let mut v = Vec::with_capacity(slots.len() * SLOT_ELEMENTS);
    for s in slots {
        match s {
            Some(st) => v.extend_from_slice(&st.to_elements()),
            None => v.extend(std::iter::repeat_n(Fp::ZERO, SLOT_ELEMENTS)),
        }
    }
    digest_chain(slots.len(), &v)
}

/// The chain itself, over any elements (what the circuit computes).
pub fn digest_chain(n_slots: usize, elements: &[Fp]) -> Fp {
    let mut acc = Fp::from(n_slots as u64);
    let mut input = [Fp::ZERO; DIGEST_CHUNK + 1];
    for chunk in elements.chunks(DIGEST_CHUNK) {
        input[0] = acc;
        input[1..].fill(Fp::ZERO);
        input[1..1 + chunk.len()].copy_from_slice(chunk);
        acc = hash(t_batch(), &input);
    }
    acc
}

/// The witness of one nullifier's insertion, as `imt::Insertion` gives it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NullifierInsert {
    pub low: Leaf,
    pub low_path: MerklePath,
    pub new_path: MerklePath,
}

impl From<&Insertion> for NullifierInsert {
    fn from(i: &Insertion) -> Self {
        NullifierInsert {
            low: i.low_before,
            low_path: i.low_path.clone(),
            new_path: i.new_path.clone(),
        }
    }
}

/// Everything the relation needs for one accepted transfer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlotWitness {
    pub statement: SlotStatement,
    /// Siblings of `r_anchor` in the root tree at position
    /// `h_anchor − activation + 1` (leaf 0 is the initial root).
    pub anchor_siblings: [Fp; DEPTH],
    pub nullifiers: [NullifierInsert; N_IN],
    /// The append paths of the output leaves, in order.
    pub leaves: [MerklePath; N_OUT],
}

/// A batch: the state before, up to `n` slots, and whether the block in
/// progress is complete after them (then its root is appended to the root
/// tree over `root_append`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BatchWitness {
    pub prev: StateOpening,
    pub slots: Vec<Option<SlotWitness>>,
    pub final_block: bool,
    pub root_append: Option<MerklePath>,
}

/// The public inputs of the relation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BatchStatement {
    pub s_prev: Fp,
    pub s_next: Fp,
    pub d: Fp,
}

impl BatchStatement {
    pub fn to_field_elements(&self) -> Vec<Fp> {
        vec![self.s_prev, self.s_next, self.d]
    }
}

/// The deployment constants the relation is fixed by.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BatchParams {
    pub activation: u32,
    pub window_w: u32,
    pub k_min: u32,
    pub const_salt: Fp,
}

/// An absent path.
pub fn no_path() -> MerklePath {
    MerklePath {
        position: 0,
        siblings: [Fp::ZERO; DEPTH],
    }
}

impl NullifierInsert {
    /// An absent insertion (a mint's, an empty slot's).
    pub fn none() -> Self {
        NullifierInsert {
            low: Leaf {
                value: Fp::ZERO,
                next: Fp::ZERO,
            },
            low_path: no_path(),
            new_path: no_path(),
        }
    }
}

impl BatchWitness {
    /// The relation, natively — the specification the circuit follows rule
    /// by rule: the statement it proves, or `None` where a rule fails.
    pub fn check(&self, p: &BatchParams) -> Option<BatchStatement> {
        let prev = &self.prev;
        let mut root = prev.root;
        let mut size = prev.size;
        let mut nf_root = prev.nf_root;
        let mut nf_size = prev.nf_size;
        let mut applied = prev.applied;
        let mut statements = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let Some(sw) = slot else {
                statements.push(None);
                continue;
            };
            let st = &sw.statement;
            statements.push(Some(*st));
            if !st.mint {
                // the anchor: in the window, its root in the root tree (an
                // anchor below activation opens to the initial root)
                let h = st.h_anchor as u64;
                let height = prev.height as u64;
                if h + (p.window_w as u64) < height || height < h + (p.k_min as u64) {
                    return None;
                }
                if st.h_anchor < p.activation {
                    if st.r_anchor != EMPTY_ROOTS[DEPTH] {
                        return None;
                    }
                } else {
                    let path = MerklePath {
                        position: (st.h_anchor - p.activation) as u64 + 1,
                        siblings: sw.anchor_siblings,
                    };
                    if path.root(&st.r_anchor) != prev.h_root {
                        return None;
                    }
                }
                // the nullifiers: absent, then inserted, in order
                for (k, nf) in st.nullifiers.iter().enumerate() {
                    let ins = Insertion {
                        value: *nf,
                        low_before: sw.nullifiers[k].low,
                        low_path: sw.nullifiers[k].low_path.clone(),
                        new_position: nf_size,
                        new_path: sw.nullifiers[k].new_path.clone(),
                    };
                    let (before, after) = ins.roots()?;
                    if before != nf_root {
                        return None;
                    }
                    nf_root = after;
                    nf_size += 1;
                }
            }
            // the output leaves, appended in order
            for j in 0..st.outputs() {
                use pasta_curves::arithmetic::CurveAffine;
                let pk: Affine = Option::from(Affine::from_xy(st.pk_eph[j].0, st.pk_eph[j].1))?;
                let leaf = note_leaf(&p.const_salt, &st.h_body, j as u64, &pk, &st.ct[j]);
                let path = &sw.leaves[j];
                if path.position != size || path.root(&Fp::ZERO) != root {
                    return None;
                }
                root = path.root(&leaf);
                size += 1;
            }
            applied += 1;
        }
        // the end of a block: the note root appended to the root tree
        let (h_root, height, applied) = if self.final_block {
            let ra = self.root_append.as_ref()?;
            if ra.position != (prev.height - p.activation) as u64 + 1
                || ra.root(&Fp::ZERO) != prev.h_root
            {
                return None;
            }
            (ra.root(&root), prev.height + 1, 0)
        } else {
            (prev.h_root, prev.height, applied)
        };
        let next = StateOpening {
            root,
            size,
            nf_root,
            nf_size,
            h_root,
            height,
            applied,
        };
        Some(BatchStatement {
            s_prev: prev.digest(),
            s_next: next.digest(),
            d: batch_digest(&statements),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::prime::PrimeCurveAffine;

    #[test]
    fn digests_bind_every_component_and_the_order() {
        let s = StateOpening {
            root: Fp::from(1u64),
            size: 2,
            nf_root: Fp::from(3u64),
            nf_size: 4,
            h_root: Fp::from(5u64),
            height: 6,
            applied: 0,
        };
        let d = s.digest();
        for f in [
            |x: &mut StateOpening| x.root += Fp::ONE,
            |x: &mut StateOpening| x.size += 1,
            |x: &mut StateOpening| x.nf_root += Fp::ONE,
            |x: &mut StateOpening| x.nf_size += 1,
            |x: &mut StateOpening| x.h_root += Fp::ONE,
            |x: &mut StateOpening| x.height += 1,
            |x: &mut StateOpening| x.applied += 1,
        ] {
            let mut t = s;
            f(&mut t);
            assert_ne!(t.digest(), d);
        }
        let st = SlotStatement {
            h_anchor: 7,
            r_anchor: Fp::from(8u64),
            nullifiers: [Fp::from(9u64), Fp::from(10u64)],
            pk_eph: [crate::xy(&Affine::generator()); N_OUT],
            ct: [NoteCiphertext {
                c0: Fp::from(11u64),
                c1: Fp::from(12u64),
                tag: Fp::from(13u64),
            }; N_OUT],
            h_body: Fp::from(14u64),
            mint: false,
        };
        assert_eq!(st.to_elements().len(), SLOT_ELEMENTS);
        assert_eq!(SLOT_ELEMENTS, 16);
        assert_eq!(st.to_elements()[SLOT_H_BODY], st.h_body);
        let mut m = st;
        m.mint = true;
        assert_ne!(batch_digest(&[Some(m)]), batch_digest(&[Some(st)]));
        assert_eq!(SlotStatement::from_elements(&st.to_elements()), Some(st));
        let mut bad = st.to_elements();
        bad[SLOT_ELEMENTS - 1] = Fp::from(2u64);
        assert_eq!(SlotStatement::from_elements(&bad), None, "kind");
        let mut bad = st.to_elements();
        bad[4] += Fp::ONE;
        assert_eq!(SlotStatement::from_elements(&bad), None, "point");
        let mut bad = st.to_elements();
        bad[0] = -Fp::ONE;
        assert_eq!(SlotStatement::from_elements(&bad), None, "height");
        let a = batch_digest(&[Some(st), None]);
        let b = batch_digest(&[None, Some(st)]);
        assert_ne!(a, b, "the order is committed");
        assert_ne!(a, batch_digest(&[Some(st)]), "the batch size is committed");
        assert_ne!(
            batch_digest(&[None]),
            batch_digest(&[None, None]),
            "empty slots are not padding"
        );
        assert_eq!(SLOT_ELEMENTS * 2 % DIGEST_CHUNK, 0);
    }
}
