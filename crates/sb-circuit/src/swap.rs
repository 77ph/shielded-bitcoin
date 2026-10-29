//! The swap extension relation (`docs/SWAP.md` §5–§7): the base transfer
//! relation with the input blocks E1–E7, which open the `h_aux` slot of a
//! locked note and authorise its spend either by the owner with the
//! SHA-256 preimage or by the refund key once the anchor height has
//! reached the refund height.

use ark_ec::AffineRepr;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use sb_core::envelope::N_IN;
use sb_core::lock::{LockOpening, Secret, hash_halves};
use sb_core::note::NotePlaintext;
use sb_core::recovery::N_OUT;
use sb_core::tree::DEPTH;
use sb_primitives::diversify::diversifier_to_fr;
use sb_primitives::poseidon::gadget::hash_var;
use sb_primitives::scalar::scalar_to_fr;
use sb_primitives::tags::{t_sknf, t_view, t_vkin};
use sb_primitives::{Fr, JubjubAffine};

use crate::gadgets::{
    NoteVars, PointVar, SCALAR_BITS, Var, alloc_bounded, diversify_hash_var, enforce_geq_u32_if,
    leaf_var_aux, lock_commitment_var, low_bits, merkle_root_var, nullifier_locked_var,
    nullifier_var, output_channel, sha256_halves_var,
};
use crate::transfer::{
    InputWitness, NUM_PUBLIC_INPUTS, OutputWitness, TransferStatement, pk_d_root,
};

/// Public inputs of the swap statement: the base ones plus `h_anchor`.
pub const NUM_SWAP_PUBLIC_INPUTS: usize = NUM_PUBLIC_INPUTS + 1;

/// Private data for one input of a swap transfer (`docs/SWAP.md` §6).
#[derive(Clone, Debug)]
pub struct SwapInputWitness {
    pub base: InputWitness,
    /// The slot of the note's leaf; `0` for a plain note.
    pub h_aux: Fr,
    /// The lock's opening (any values for a plain note).
    pub opening: LockOpening,
    /// The preimage, for a claim (any bytes otherwise).
    pub secret: Secret,
    /// The refund party's diversifier, for a refund (any valid diversifier
    /// otherwise; the wallet uses its own).
    pub d_refund: [u8; 11],
    /// The note owner's transmission key.
    pub pk_owner: JubjubAffine,
    /// Take the refund branch.
    pub refund: bool,
}

impl SwapInputWitness {
    /// A plain input (a base note spent by its owner, or a dummy).
    pub fn plain(base: InputWitness, pk_owner: JubjubAffine, d_own: [u8; 11]) -> Self {
        SwapInputWitness {
            base,
            h_aux: Fr::from(0u64),
            opening: LockOpening {
                hash: [0u8; 32],
                pk_refund: JubjubAffine::zero(),
                t_refund: 0,
            },
            secret: Secret([0u8; 32]),
            d_refund: d_own,
            pk_owner,
            refund: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SwapWitness {
    pub sk_spend: sb_primitives::JubjubScalar,
    pub inputs: [SwapInputWitness; N_IN],
    pub outputs: [OutputWitness; N_OUT],
}

/// The swap statement: the base statement and the anchor height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapStatement {
    pub base: TransferStatement,
    pub h_anchor: u32,
}

impl SwapStatement {
    pub fn to_field_elements(&self) -> Vec<Fr> {
        let mut v = self.base.to_field_elements();
        v.push(Fr::from(self.h_anchor as u64));
        debug_assert_eq!(v.len(), NUM_SWAP_PUBLIC_INPUTS);
        v
    }
}

/// The circuit. Both fields are `None` for setup.
#[derive(Clone, Default)]
pub struct SwapCircuit {
    pub statement: Option<SwapStatement>,
    pub witness: Option<SwapWitness>,
}

fn missing<T>(v: Option<T>) -> Result<T, SynthesisError> {
    v.ok_or(SynthesisError::AssignmentMissing)
}

impl ConstraintSynthesizer<Fr> for SwapCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let st = self.statement.as_ref();
        let input =
            |f: &dyn Fn(&SwapStatement) -> Fr| Var::new_input(cs.clone(), || missing(st.map(f)));

        // ---- public inputs: the base ones in profile order, then h_anchor ----
        let const_salt = input(&|s| s.base.const_salt)?;
        let r_anchor = input(&|s| s.base.r_anchor)?;
        let n = input(&|_| Fr::from(N_IN as u64))?;
        let m = input(&|_| Fr::from(N_OUT as u64))?;
        let mut nf_pub = Vec::with_capacity(N_IN);
        for i in 0..N_IN {
            nf_pub.push(input(&|s| s.base.nullifiers[i])?);
        }
        let mut pk_eph_pub = Vec::with_capacity(N_OUT);
        for j in 0..N_OUT {
            let x = input(&|s| s.base.pk_eph[j].x)?;
            let y = input(&|s| s.base.pk_eph[j].y)?;
            pk_eph_pub.push(AffineVar::new(x, y));
        }
        let mut ct_pub = Vec::with_capacity(N_OUT);
        for j in 0..N_OUT {
            let c0 = input(&|s| s.base.ct_note[j].c0)?;
            let c1 = input(&|s| s.base.ct_note[j].c1)?;
            let tag = input(&|s| s.base.ct_note[j].tag)?;
            ct_pub.push([c0, c1, tag]);
        }
        let h_body = input(&|s| s.base.h_body)?;
        let h_anchor = input(&|s| Fr::from(s.h_anchor as u64))?;

        n.enforce_equal(&Var::Constant(Fr::from(N_IN as u64)))?;
        m.enforce_equal(&Var::Constant(Fr::from(N_OUT as u64)))?;
        let _ = h_body.square()?;
        let _ = r_anchor.square()?;
        // h_anchor is a block height
        let _ = h_anchor.to_bits_le_with_top_bits_zero(32)?;

        // ---- spend authority of the spender (owner or refund party) ----
        let w = self.witness.as_ref();
        let sk_spend =
            Var::new_witness(cs.clone(), || missing(w.map(|w| scalar_to_fr(&w.sk_spend))))?;
        let sk_nf = hash_var(t_sknf(), std::slice::from_ref(&sk_spend))?;
        let vk_in = hash_var(t_vkin(), std::slice::from_ref(&sk_spend))?;
        let sk_view_bits = low_bits(&hash_var(t_view(), &[vk_in])?, SCALAR_BITS)?;

        // ---- inputs (E1–E7) ----
        let mut v_in = Var::zero();
        for (i, nf_pub_i) in nf_pub.iter().enumerate() {
            let iw = w.map(|w| &w.inputs[i]);
            let note = NoteVars::alloc(cs.clone(), iw.map(|w| &w.base.note))?;
            let h_body_create =
                Var::new_witness(cs.clone(), || missing(iw.map(|w| w.base.h_body_create)))?;
            let j = Var::new_witness(cs.clone(), || {
                missing(iw.map(|w| Fr::from(w.base.output_index)))
            })?;
            let (pos, pos_bits) =
                alloc_bounded(cs.clone(), iw.map(|w| Fr::from(w.base.pos)), DEPTH)?;
            let mut siblings = Vec::with_capacity(DEPTH);
            for k in 0..DEPTH {
                siblings.push(Var::new_witness(cs.clone(), || {
                    missing(iw.map(|w| w.base.siblings[k]))
                })?);
            }
            let h_aux = Var::new_witness(cs.clone(), || missing(iw.map(|w| w.h_aux)))?;
            let (h_lo, h_hi) = {
                let halves = iw.map(|w| hash_halves(&w.opening.hash));
                (
                    Var::new_witness(cs.clone(), || missing(halves.map(|h| h.0)))?,
                    Var::new_witness(cs.clone(), || missing(halves.map(|h| h.1)))?,
                )
            };
            let pk_refund = PointVar::new_variable_omit_prime_order_check(
                cs.clone(),
                || missing(iw.map(|w| w.opening.pk_refund.into_group())),
                ark_r1cs_std::alloc::AllocationMode::Witness,
            )?;
            let (t_refund, _) = alloc_bounded(
                cs.clone(),
                iw.map(|w| Fr::from(w.opening.t_refund as u64)),
                32,
            )?;
            let mut secret = Vec::with_capacity(32);
            for k in 0..32 {
                secret.push(UInt8::new_witness(cs.clone(), || {
                    missing(iw.map(|w| w.secret.0[k]))
                })?);
            }
            let (d_refund, _) =
                alloc_bounded(cs.clone(), iw.map(|w| diversifier_to_fr(&w.d_refund)), 88)?;
            let owner_root = PointVar::new_variable_omit_prime_order_check(
                cs.clone(),
                || missing(iw.map(|w| pk_d_root(&w.pk_owner).into_group())),
                ark_r1cs_std::alloc::AllocationMode::Witness,
            )?;
            let mut pk_owner = owner_root;
            pk_owner.double_in_place()?;
            pk_owner.double_in_place()?;
            pk_owner.double_in_place()?;
            let refund = Boolean::new_witness(cs.clone(), || missing(iw.map(|w| w.refund)))?;

            // E1: channel under the owner's key, leaf with the slot, membership
            let g_d = diversify_hash_var(&note.d)?;
            let chan = output_channel(&note, &g_d, &pk_owner)?;
            let leaf = leaf_var_aux(
                &const_salt,
                &h_body_create,
                &j,
                &chan.pk_eph,
                &chan.ct,
                &h_aux,
            )?;
            let root = merkle_root_var(&leaf, &pos_bits, &siblings)?;
            let is_real = !(note.v.is_zero()?);
            root.conditional_enforce_equal(&r_anchor, &is_real)?;

            // E2: flags
            let locked = !(h_aux.is_zero()?);
            (&refund & !locked.clone()).enforce_equal(&Boolean::FALSE)?;

            // E3 / E5: unless refunding, the spender is the owner
            let pk_d_derived = g_d.scalar_mul_le(sk_view_bits.iter())?;
            pk_owner.conditional_enforce_equal(&pk_d_derived, &!refund.clone())?;

            // E4: the slot opens to the lock
            let lock = lock_commitment_var(&h_lo, &h_hi, &pk_refund, &t_refund)?;
            h_aux.conditional_enforce_equal(&lock, &locked)?;

            // E5: a claim knows the preimage
            let claim = &locked & !refund.clone();
            let (s_lo, s_hi) = sha256_halves_var(&secret)?;
            s_lo.conditional_enforce_equal(&h_lo, &claim)?;
            s_hi.conditional_enforce_equal(&h_hi, &claim)?;

            // E6: a refund holds the refund key and the anchor has reached t_refund
            let g_refund = diversify_hash_var(&d_refund)?;
            let pk_refund_derived = g_refund.scalar_mul_le(sk_view_bits.iter())?;
            pk_refund.conditional_enforce_equal(&pk_refund_derived, &refund)?;
            enforce_geq_u32_if(&h_anchor, &t_refund, &refund)?;

            // E7: the nullifier of the path
            let rho = note.rho()?;
            let nf_base = nullifier_var(&sk_nf, &rho, &pos)?;
            let nf_lock = nullifier_locked_var(&rho, &pos)?;
            let nf = Var::conditionally_select(&locked, &nf_lock, &nf_base)?;
            nf.enforce_equal(nf_pub_i)?;
            v_in += &note.v;
        }

        // ---- outputs (base block 5) ----
        let mut v_out = Var::zero();
        for j in 0..N_OUT {
            let ow = w.map(|w| &w.outputs[j]);
            let note = NoteVars::alloc(cs.clone(), ow.map(|w| &w.note))?;
            let root = PointVar::new_variable_omit_prime_order_check(
                cs.clone(),
                || missing(ow.map(|w| pk_d_root(&w.pk_d).into_group())),
                ark_r1cs_std::alloc::AllocationMode::Witness,
            )?;
            let mut pk_d = root;
            pk_d.double_in_place()?;
            pk_d.double_in_place()?;
            pk_d.double_in_place()?;
            let g_d = diversify_hash_var(&note.d)?;
            let chan = output_channel(&note, &g_d, &pk_d)?;
            chan.pk_eph.enforce_equal(&pk_eph_pub[j])?;
            for (c, c_pub) in chan.ct.iter().zip(&ct_pub[j]) {
                c.enforce_equal(c_pub)?;
            }
            v_out += &note.v;
        }

        // ---- value conservation (base blocks 6, 7) ----
        v_in.enforce_equal(&v_out)?;
        Ok(())
    }
}

/// Keep `NotePlaintext` in the public API of this module for callers that
/// build witnesses.
pub type SwapNote = NotePlaintext;
