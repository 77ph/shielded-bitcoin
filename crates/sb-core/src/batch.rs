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

/// One accepted transfer as the batch sees it: the public inputs of its
/// proof without the constants (`const_salt`, arity), plus the anchor
/// height and the `h_aux` slots. 17 field elements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotStatement {
    pub h_anchor: u32,
    pub r_anchor: Fr,
    pub nullifiers: [Fr; N_IN],
    pub pk_eph: [JubjubAffine; N_OUT],
    pub ct: [NoteCiphertext; N_OUT],
    pub h_body: Fr,
    pub h_aux: [Fr; N_OUT],
}

pub const SLOT_ELEMENTS: usize = 1 + 1 + N_IN + N_OUT * 5 + 1 + N_OUT;

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
        v.try_into().expect("SLOT_ELEMENTS")
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
        };
        assert_eq!(st.to_elements().len(), SLOT_ELEMENTS);
        assert_eq!(SLOT_ELEMENTS, 17);
        let a = batch_digest(&[Some(st), None]);
        let b = batch_digest(&[None, Some(st)]);
        assert_ne!(a, b, "the order is committed");
        assert_ne!(a, batch_digest(&[Some(st)]), "the batch size is committed");
    }
}
