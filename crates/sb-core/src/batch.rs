//! Replay batches (`docs/REPLAY-PROOF.md` §4): the state opening behind
//! a state digest, the statement of one accepted transfer as the batch
//! circuit sees it, and the witnesses of the three trees' changes. Native
//! only; the circuit is `sb_circuit::batch`.

use sb_primitives::Fr;
use sb_primitives::JubjubAffine;
use sb_primitives::poseidon::hash;
use sb_primitives::tags::{t_batch, t_state};

use crate::imt::{Insertion, Leaf};
use crate::note::NoteCiphertext;
use crate::tree::{DEPTH, MerklePath};

/// Number of inputs and outputs of a transfer (profile §7).
pub use crate::envelope::N_IN;
pub use crate::recovery::N_OUT;

/// The replay state as the batch circuit transitions it: the note tree
/// (`root`, `size`), the nullifier tree (`nf_root`, `nf_size`, sentinel
/// included), the root tree (`h_root`), the block in progress (`height`,
/// the first block whose root is **not** in the root tree) and how many
/// statements of it were applied so far (`applied`; `0` between blocks).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateOpening {
    pub root: Fr,
    pub size: u64,
    pub nf_root: Fr,
    pub nf_size: u64,
    pub h_root: Fr,
    pub height: u32,
    pub applied: u32,
}

impl StateOpening {
    /// `PH(T_STATE, R, size, N, nf_size, H, height, applied)`.
    pub fn digest(&self) -> Fr {
        hash(
            t_state(),
            &[
                self.root,
                Fr::from(self.size),
                self.nf_root,
                Fr::from(self.nf_size),
                self.h_root,
                Fr::from(self.height),
                Fr::from(self.applied),
            ],
        )
    }
}

/// One accepted envelope as the batch sees it: the public inputs of its
/// proof without the constants (`const_salt`, arity), plus the anchor
/// height, the `h_aux` slots and its kind. 18 field elements. A **mint**
/// (the development boundary, `BOUNDARY.md`) has no anchor, no
/// nullifiers and one output: its validity is the carrier's vault
/// payment, which is enumeration-class trust (`REPLAY-PROOF.md` §3), and
/// the circuit only appends its leaf.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotStatement {
    pub h_anchor: u32,
    pub r_anchor: Fr,
    pub nullifiers: [Fr; N_IN],
    pub pk_eph: [JubjubAffine; N_OUT],
    pub ct: [NoteCiphertext; N_OUT],
    pub h_body: Fr,
    pub h_aux: [Fr; N_OUT],
    pub mint: bool,
}

pub const SLOT_ELEMENTS: usize = 1 + 1 + N_IN + N_OUT * 5 + 1 + N_OUT + 1;

impl SlotStatement {
    pub fn to_elements(&self) -> [Fr; SLOT_ELEMENTS] {
        let mut v = Vec::with_capacity(SLOT_ELEMENTS);
        v.push(Fr::from(self.h_anchor));
        v.push(self.r_anchor);
        v.extend_from_slice(&self.nullifiers);
        for j in 0..N_OUT {
            v.push(self.pk_eph[j].x);
            v.push(self.pk_eph[j].y);
            v.extend_from_slice(&self.ct[j].elements());
        }
        v.push(self.h_body);
        v.extend_from_slice(&self.h_aux);
        v.push(Fr::from(self.mint as u64));
        v.try_into().expect("SLOT_ELEMENTS")
    }

    /// The inverse of [`Self::to_elements`], `None` if the elements are
    /// not a statement: a height above `u32`, a point off the curve or
    /// outside the prime-order subgroup, a kind other than 0 or 1.
    pub fn from_elements(e: &[Fr]) -> Option<Self> {
        use ark_ff::{BigInteger, PrimeField};
        if e.len() != SLOT_ELEMENTS {
            return None;
        }
        let u32_of = |f: &Fr| -> Option<u32> {
            let b = f.into_bigint().to_bytes_le();
            if b[4..].iter().any(|x| *x != 0) {
                return None;
            }
            Some(u32::from_le_bytes(b[..4].try_into().ok()?))
        };
        let h_anchor = u32_of(&e[0])?;
        let mut pk_eph = [JubjubAffine::default(); N_OUT];
        let mut ct = [NoteCiphertext {
            c0: Fr::from(0u64),
            c1: Fr::from(0u64),
            tag: Fr::from(0u64),
        }; N_OUT];
        for j in 0..N_OUT {
            let base = 4 + j * 5;
            let p = JubjubAffine::new_unchecked(e[base], e[base + 1]);
            if !(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()) {
                return None;
            }
            pk_eph[j] = p;
            ct[j] = NoteCiphertext {
                c0: e[base + 2],
                c1: e[base + 3],
                tag: e[base + 4],
            };
        }
        let mint = match u32_of(&e[17])? {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some(SlotStatement {
            h_anchor,
            r_anchor: e[1],
            nullifiers: [e[2], e[3]],
            pk_eph,
            ct,
            h_body: e[14],
            h_aux: [e[15], e[16]],
            mint,
        })
    }
}

/// `D = PH(T_BATCH, st_1 … st_n)` over `n` slots, an empty slot being all
/// zeros; the order is what replay applied.
pub fn batch_digest(slots: &[Option<SlotStatement>]) -> Fr {
    let mut v = Vec::with_capacity(slots.len() * SLOT_ELEMENTS);
    for s in slots {
        match s {
            Some(st) => v.extend_from_slice(&st.to_elements()),
            None => v.extend(std::iter::repeat_n(Fr::from(0u64), SLOT_ELEMENTS)),
        }
    }
    hash(t_batch(), &v)
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

/// Everything the circuit needs for one accepted transfer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlotWitness {
    pub statement: SlotStatement,
    /// Siblings of `r_anchor` in the root tree at position
    /// `h_anchor − activation`.
    pub anchor_siblings: [Fr; DEPTH],
    pub nullifiers: [NullifierInsert; N_IN],
    /// The append paths of the two output leaves, in order.
    pub leaves: [MerklePath; N_OUT],
}

/// A batch: the state before, up to `n` slots, and whether the block in
/// progress is complete after them (then its root is appended to the root
/// tree at `height − activation` over `root_append`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BatchWitness {
    pub prev: StateOpening,
    pub slots: Vec<Option<SlotWitness>>,
    pub final_block: bool,
    pub root_append: Option<MerklePath>,
}

/// The public inputs of a batch proof.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BatchStatement {
    pub s_prev: Fr,
    pub s_next: Fr,
    pub d: Fr,
}

impl BatchStatement {
    pub fn to_field_elements(&self) -> Vec<Fr> {
        vec![self.s_prev, self.s_next, self.d]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_bind_every_component_and_the_order() {
        let s = StateOpening {
            root: Fr::from(1u64),
            size: 2,
            nf_root: Fr::from(3u64),
            nf_size: 4,
            h_root: Fr::from(5u64),
            height: 6,
            applied: 0,
        };
        let d = s.digest();
        for f in [
            |x: &mut StateOpening| x.root += Fr::from(1u64),
            |x: &mut StateOpening| x.size += 1,
            |x: &mut StateOpening| x.nf_root += Fr::from(1u64),
            |x: &mut StateOpening| x.nf_size += 1,
            |x: &mut StateOpening| x.h_root += Fr::from(1u64),
            |x: &mut StateOpening| x.height += 1,
            |x: &mut StateOpening| x.applied += 1,
        ] {
            let mut t = s;
            f(&mut t);
            assert_ne!(t.digest(), d);
        }
        let st = SlotStatement {
            h_anchor: 7,
            r_anchor: Fr::from(8u64),
            nullifiers: [Fr::from(9u64), Fr::from(10u64)],
            pk_eph: [JubjubAffine::default(); N_OUT],
            ct: [NoteCiphertext {
                c0: Fr::from(11u64),
                c1: Fr::from(12u64),
                tag: Fr::from(13u64),
            }; N_OUT],
            h_body: Fr::from(14u64),
            h_aux: [Fr::from(0u64); N_OUT],
            mint: false,
        };
        assert_eq!(st.to_elements().len(), SLOT_ELEMENTS);
        assert_eq!(SLOT_ELEMENTS, 18);
        let mut m = st;
        m.mint = true;
        assert_ne!(
            batch_digest(&[Some(m)]),
            batch_digest(&[Some(st)]),
            "the kind is committed"
        );
        assert_eq!(SlotStatement::from_elements(&st.to_elements()), Some(st));
        let mut bad = st.to_elements();
        bad[17] = Fr::from(2u64);
        assert_eq!(SlotStatement::from_elements(&bad), None, "kind");
        let mut bad = st.to_elements();
        bad[4] += Fr::from(1u64);
        assert_eq!(SlotStatement::from_elements(&bad), None, "point");
        let a = batch_digest(&[Some(st), None]);
        let b = batch_digest(&[None, Some(st)]);
        assert_ne!(a, b, "the order is committed");
        assert_ne!(a, batch_digest(&[Some(st)]), "the batch size is committed");
    }
}
