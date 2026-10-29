//! The batch circuit `T` (`docs/REPLAY-PROOF.md` §4.2): the replay state
//! transition for up to `n` accepted statements of one block, applied in
//! order over the note tree, the indexed nullifier tree and the root tree.
//! Public inputs: `digest(S_prev)`, `digest(S_next)`, `D`.
//!
//! What it proves: for the given statements (valid or not: their proofs
//! are the client's business, §4.3), the trees change as replay's `Step`
//! prescribes. An empty slot is all zeros and leaves the state alone.

use ark_ff::Zero;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use sb_core::batch::{BatchStatement, BatchWitness, SLOT_ELEMENTS, StateOpening};
use sb_core::tree::DEPTH;
use sb_primitives::Fr;
use sb_primitives::poseidon::gadget::hash_var;
use sb_primitives::tags::{t_batch, t_imt, t_state};

use crate::gadgets::{
    Bit, PointVar, Var, alloc_bounded, enforce_geq_u32_if, leaf_var_aux, merkle_root_var,
};

/// Number of public inputs of a batch proof.
pub const NUM_BATCH_PUBLIC_INPUTS: usize = 3;

/// The circuit; `statement` and `witness` are `None` for setup. The shape
/// is fixed by `n` and the deployment constants.
#[derive(Clone)]
pub struct BatchCircuit {
    pub n: usize,
    pub activation: u32,
    pub window_w: u32,
    pub k_min: u32,
    pub const_salt: Fr,
    pub statement: Option<BatchStatement>,
    pub witness: Option<BatchWitness>,
}

fn missing<T>(v: Option<T>) -> Result<T, SynthesisError> {
    v.ok_or(SynthesisError::AssignmentMissing)
}

/// `a < b` as integers, for any two field elements (both are decomposed
/// into their canonical bits).
fn lt_var(a: &Var, b: &Var) -> Result<Bit, SynthesisError> {
    let ba = a.to_bits_le()?;
    let bb = b.to_bits_le()?;
    let mut lt = Bit::FALSE;
    let mut eq = Bit::TRUE;
    for (x, y) in ba.iter().rev().zip(bb.iter().rev()) {
        let here = (!x) & y;
        lt |= &eq & &here;
        eq &= !(x ^ y);
    }
    Ok(lt)
}

struct OpeningVars {
    root: Var,
    size: Var,
    nf_root: Var,
    nf_size: Var,
    h_root: Var,
    height: Var,
    applied: Var,
}

impl OpeningVars {
    fn alloc(
        cs: ConstraintSystemRef<Fr>,
        o: Option<&StateOpening>,
    ) -> Result<Self, SynthesisError> {
        let w =
            |f: &dyn Fn(&StateOpening) -> Fr| Var::new_witness(cs.clone(), || missing(o.map(f)));
        let (height, _) = alloc_bounded(cs.clone(), o.map(|o| Fr::from(o.height)), 32)?;
        Ok(OpeningVars {
            root: w(&|o| o.root)?,
            size: w(&|o| Fr::from(o.size))?,
            nf_root: w(&|o| o.nf_root)?,
            nf_size: w(&|o| Fr::from(o.nf_size))?,
            h_root: w(&|o| o.h_root)?,
            height,
            applied: w(&|o| Fr::from(o.applied))?,
        })
    }

    fn digest(&self) -> Result<Var, SynthesisError> {
        hash_var(
            t_state(),
            &[
                self.root.clone(),
                self.size.clone(),
                self.nf_root.clone(),
                self.nf_size.clone(),
                self.h_root.clone(),
                self.height.clone(),
                self.applied.clone(),
            ],
        )
    }
}

fn alloc_siblings(
    cs: ConstraintSystemRef<Fr>,
    s: Option<&[Fr; DEPTH]>,
) -> Result<Vec<Var>, SynthesisError> {
    (0..DEPTH)
        .map(|k| Var::new_witness(cs.clone(), || Ok(s.map_or(Fr::zero(), |s| s[k]))))
        .collect()
}

impl ConstraintSynthesizer<Fr> for BatchCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let st = self.statement.as_ref();
        let s_prev = Var::new_input(cs.clone(), || missing(st.map(|s| s.s_prev)))?;
        let s_next = Var::new_input(cs.clone(), || missing(st.map(|s| s.s_next)))?;
        let d = Var::new_input(cs.clone(), || missing(st.map(|s| s.d)))?;

        let w = self.witness.as_ref();
        let prev = OpeningVars::alloc(cs.clone(), w.map(|w| &w.prev))?;
        prev.digest()?.enforce_equal(&s_prev)?;

        let activation = Var::Constant(Fr::from(self.activation));
        let const_salt = Var::Constant(self.const_salt);
        let mut cur_root = prev.root.clone();
        let mut cur_size = prev.size.clone();
        let mut cur_nf_root = prev.nf_root.clone();
        let mut cur_nf_size = prev.nf_size.clone();
        let mut cur_applied = prev.applied.clone();
        let mut all_elems: Vec<Var> = Vec::with_capacity(self.n * SLOT_ELEMENTS);

        for i in 0..self.n {
            let sw = w.and_then(|w| w.slots.get(i)).and_then(|s| s.as_ref());
            let active = Bit::new_witness(cs.clone(), || Ok(sw.is_some()))?;
            let active_fr: Var = Var::from(active.clone());
            let elems_native = sw
                .map(|s| s.statement.to_elements())
                .unwrap_or([Fr::zero(); SLOT_ELEMENTS]);
            let mut elems = Vec::with_capacity(SLOT_ELEMENTS);
            for native in &elems_native {
                let v = Var::new_witness(cs.clone(), || Ok(*native))?;
                // an empty slot is all zeros, so that `D` is canonical
                v.conditional_enforce_equal(&Var::zero(), &!active.clone())?;
                elems.push(v);
            }
            all_elems.extend(elems.iter().cloned());
            let r_anchor = &elems[1];
            let nfs = [&elems[2], &elems[3]];
            let h_body = &elems[14];
            let h_aux = [&elems[15], &elems[16]];
            // the kind: 0 a transfer or swap, 1 a mint (one leaf, no anchor,
            // no nullifiers); anything else is refused
            let kind = &elems[17];
            (kind * (kind - Var::one())).enforce_equal(&Var::zero())?;
            let is_mint = kind.is_eq(&Var::one())?;
            let active_tx = &active & &!is_mint;
            let active_tx_fr: Var = Var::from(active_tx.clone());

            // ---- anchor: in the window, and its root in the root tree ----
            // absent witnesses (an empty slot, no root append) allocate zeros:
            // the constraints on them are conditional on `active` / `final`
            let (h_anchor, _) = alloc_bounded(
                cs.clone(),
                Some(sw.map_or(Fr::zero(), |s| Fr::from(s.statement.h_anchor))),
                32,
            )?;
            h_anchor.enforce_equal(&elems[0])?;
            let (anchor_pos, anchor_bits) = alloc_bounded(
                cs.clone(),
                Some(sw.map_or(Fr::zero(), |s| {
                    if s.statement.mint {
                        Fr::zero()
                    } else {
                        Fr::from(s.statement.h_anchor.wrapping_sub(self.activation))
                    }
                })),
                DEPTH,
            )?;
            anchor_pos.conditional_enforce_equal(&(&h_anchor - &activation), &active_tx)?;
            let anchor_sibs = alloc_siblings(cs.clone(), sw.map(|s| &s.anchor_siblings))?;
            merkle_root_var(r_anchor, &anchor_bits, &anchor_sibs)?
                .conditional_enforce_equal(&prev.h_root, &active_tx)?;
            let w_fr = Var::Constant(Fr::from(self.window_w));
            let k_fr = Var::Constant(Fr::from(self.k_min));
            enforce_geq_u32_if(&(&h_anchor + &w_fr), &prev.height, &active_tx)?;
            enforce_geq_u32_if(&prev.height, &(&h_anchor + &k_fr), &active_tx)?;

            // ---- nullifiers: not present, then inserted, in order ----
            for (k, nf) in nfs.iter().enumerate() {
                let ins = sw.map(|s| &s.nullifiers[k]);
                let lv =
                    Var::new_witness(cs.clone(), || Ok(ins.map_or(Fr::zero(), |i| i.low.value)))?;
                let ln =
                    Var::new_witness(cs.clone(), || Ok(ins.map_or(Fr::zero(), |i| i.low.next)))?;
                let (_, low_bits) = alloc_bounded(
                    cs.clone(),
                    Some(ins.map_or(Fr::zero(), |i| Fr::from(i.low_path.position))),
                    DEPTH,
                )?;
                let low_sibs = alloc_siblings(cs.clone(), ins.map(|i| &i.low_path.siblings))?;
                let (new_pos, new_bits) = alloc_bounded(
                    cs.clone(),
                    Some(ins.map_or(Fr::zero(), |i| Fr::from(i.new_path.position))),
                    DEPTH,
                )?;
                let new_sibs = alloc_siblings(cs.clone(), ins.map(|i| &i.new_path.siblings))?;
                // low < nf < next (or next = 0: no greater value)
                let ordered = &lt_var(&lv, nf)? & &(&ln.is_zero()? | &lt_var(nf, &ln)?);
                ordered.conditional_enforce_equal(&Bit::TRUE, &active_tx)?;
                let low_leaf = hash_var(t_imt(), &[lv.clone(), ln.clone()])?;
                merkle_root_var(&low_leaf, &low_bits, &low_sibs)?
                    .conditional_enforce_equal(&cur_nf_root, &active_tx)?;
                let low_after = hash_var(t_imt(), &[lv.clone(), (*nf).clone()])?;
                let mid = merkle_root_var(&low_after, &low_bits, &low_sibs)?;
                new_pos.conditional_enforce_equal(&cur_nf_size, &active_tx)?;
                merkle_root_var(&Var::zero(), &new_bits, &new_sibs)?
                    .conditional_enforce_equal(&mid, &active_tx)?;
                let new_leaf = hash_var(t_imt(), &[(*nf).clone(), ln.clone()])?;
                let next = merkle_root_var(&new_leaf, &new_bits, &new_sibs)?;
                cur_nf_root = Var::conditionally_select(&active_tx, &next, &cur_nf_root)?;
                cur_nf_size = &cur_nf_size + &active_tx_fr;
            }

            // ---- output leaves, appended in order ----
            for (j, h_aux_j) in h_aux.iter().enumerate() {
                let base = 4 + j * 5;
                let pk = PointVar::new(elems[base].clone(), elems[base + 1].clone());
                let ct = [
                    elems[base + 2].clone(),
                    elems[base + 3].clone(),
                    elems[base + 4].clone(),
                ];
                let leaf = leaf_var_aux(
                    &const_salt,
                    h_body,
                    &Var::Constant(Fr::from(j as u64)),
                    &pk,
                    &ct,
                    h_aux_j,
                )?;
                let lp = sw.map(|s| &s.leaves[j]);
                let (pos, bits) = alloc_bounded(
                    cs.clone(),
                    Some(lp.map_or(Fr::zero(), |p| Fr::from(p.position))),
                    DEPTH,
                )?;
                let sibs = alloc_siblings(cs.clone(), lp.map(|p| &p.siblings))?;
                // a mint appends its one leaf (index 0) only
                let (on, on_fr) = if j == 0 {
                    (&active, &active_fr)
                } else {
                    (&active_tx, &active_tx_fr)
                };
                pos.conditional_enforce_equal(&cur_size, on)?;
                merkle_root_var(&Var::zero(), &bits, &sibs)?
                    .conditional_enforce_equal(&cur_root, on)?;
                let next = merkle_root_var(&leaf, &bits, &sibs)?;
                cur_root = Var::conditionally_select(on, &next, &cur_root)?;
                cur_size = &cur_size + on_fr;
            }
            cur_applied = &cur_applied + &active_fr;
        }

        // ---- end of block: append the note root to the root tree ----
        let final_block = Bit::new_witness(cs.clone(), || Ok(w.is_some_and(|w| w.final_block)))?;
        let ra = w.and_then(|w| w.root_append.as_ref());
        let (ra_pos, ra_bits) = alloc_bounded(
            cs.clone(),
            Some(ra.map_or(Fr::zero(), |p| Fr::from(p.position))),
            DEPTH,
        )?;
        let ra_sibs = alloc_siblings(cs.clone(), ra.map(|p| &p.siblings))?;
        ra_pos.conditional_enforce_equal(&(&prev.height - &activation), &final_block)?;
        merkle_root_var(&Var::zero(), &ra_bits, &ra_sibs)?
            .conditional_enforce_equal(&prev.h_root, &final_block)?;
        let appended = merkle_root_var(&cur_root, &ra_bits, &ra_sibs)?;
        let next_h_root = Var::conditionally_select(&final_block, &appended, &prev.h_root)?;
        let final_fr: Var = Var::from(final_block.clone());
        let next_height = &prev.height + &final_fr;
        let next_applied = Var::conditionally_select(&final_block, &Var::zero(), &cur_applied)?;

        let next = OpeningVars {
            root: cur_root,
            size: cur_size,
            nf_root: cur_nf_root,
            nf_size: cur_nf_size,
            h_root: next_h_root,
            height: next_height,
            applied: next_applied,
        };
        next.digest()?.enforce_equal(&s_next)?;
        hash_var(t_batch(), &all_elems)?.enforce_equal(&d)?;
        Ok(())
    }
}
