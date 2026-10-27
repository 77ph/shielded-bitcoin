//! The transfer relation (paper §14, Appendix B; profile §8).

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use sb_core::envelope::N_IN;
use sb_core::note::{NoteCiphertext, NotePlaintext};
use sb_core::recovery::N_OUT;
use sb_core::tree::DEPTH;
use sb_primitives::poseidon::gadget::hash_var;
use sb_primitives::scalar::scalar_to_fr;
use sb_primitives::tags::{t_sknf, t_view, t_vkin};
use sb_primitives::{Fr, JubjubAffine, JubjubScalar};

use crate::gadgets::{
    NoteVars, PointVar, SCALAR_BITS, Var, alloc_bounded, diversify_hash_var, leaf_var, low_bits,
    merkle_root_var, nullifier_var, output_channel,
};

/// Number of public inputs (profile §8.1).
pub const NUM_PUBLIC_INPUTS: usize = 1 + 1 + 2 + N_IN + 2 * N_OUT + 3 * N_OUT + 1;

/// Private data for one spent note (profile §8.2).
#[derive(Clone, Debug)]
pub struct InputWitness {
    pub note: NotePlaintext,
    /// `h_body` of the envelope that created the note.
    pub h_body_create: Fr,
    /// Output index `j` in that envelope.
    pub output_index: u64,
    /// Replay-assigned tree position.
    pub pos: u64,
    /// Authentication path under `r_anchor`, leaf level first.
    pub siblings: [Fr; DEPTH],
}

impl InputWitness {
    /// A zero-value dummy input (profile §8.2). `d` must be a valid
    /// diversifier; the wallet uses one of its own.
    pub fn dummy(d: [u8; 11], rseed: Fr) -> Self {
        InputWitness {
            note: NotePlaintext { value: 0, d, rseed },
            h_body_create: Fr::from(0u64),
            output_index: 0,
            pos: 0,
            siblings: [Fr::from(0u64); DEPTH],
        }
    }
}

/// Private data for one created note.
#[derive(Clone, Debug)]
pub struct OutputWitness {
    pub note: NotePlaintext,
    /// Recipient transmission key from the destination address.
    pub pk_d: JubjubAffine,
}

#[derive(Clone, Debug)]
pub struct TransferWitness {
    pub sk_spend: JubjubScalar,
    pub inputs: [InputWitness; N_IN],
    pub outputs: [OutputWitness; N_OUT],
}

/// The public statement (profile §8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferStatement {
    pub const_salt: Fr,
    pub r_anchor: Fr,
    pub nullifiers: [Fr; N_IN],
    pub pk_eph: [JubjubAffine; N_OUT],
    pub ct_note: [NoteCiphertext; N_OUT],
    pub h_body: Fr,
}

impl TransferStatement {
    /// The verifier input vector, in profile order.
    pub fn to_field_elements(&self) -> Vec<Fr> {
        let mut v = Vec::with_capacity(NUM_PUBLIC_INPUTS);
        v.push(self.const_salt);
        v.push(self.r_anchor);
        v.push(Fr::from(N_IN as u64));
        v.push(Fr::from(N_OUT as u64));
        v.extend_from_slice(&self.nullifiers);
        for p in &self.pk_eph {
            v.push(p.x);
            v.push(p.y);
        }
        for c in &self.ct_note {
            v.extend_from_slice(&c.elements());
        }
        v.push(self.h_body);
        debug_assert_eq!(v.len(), NUM_PUBLIC_INPUTS);
        v
    }
}

/// `pk_d_root` with `[8] pk_d_root = pk_d` (profile §4.1).
pub fn pk_d_root(pk_d: &JubjubAffine) -> JubjubAffine {
    let inv8 = JubjubScalar::from(8u64).inverse().expect("8 is invertible");
    (pk_d.into_group() * inv8).into_affine()
}

/// The circuit. Both fields are `None` for setup.
#[derive(Clone, Default)]
pub struct TransferCircuit {
    pub statement: Option<TransferStatement>,
    pub witness: Option<TransferWitness>,
}

fn missing<T>(v: Option<T>) -> Result<T, SynthesisError> {
    v.ok_or(SynthesisError::AssignmentMissing)
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let st = self.statement.as_ref();
        let input = |f: &dyn Fn(&TransferStatement) -> Fr| {
            Var::new_input(cs.clone(), || missing(st.map(f)))
        };

        // ---- public inputs, in profile order ----
        let const_salt = input(&|s| s.const_salt)?;
        let r_anchor = input(&|s| s.r_anchor)?;
        let n = input(&|_| Fr::from(N_IN as u64))?;
        let m = input(&|_| Fr::from(N_OUT as u64))?;
        let mut nf_pub = Vec::with_capacity(N_IN);
        for i in 0..N_IN {
            nf_pub.push(input(&|s| s.nullifiers[i])?);
        }
        let mut pk_eph_pub = Vec::with_capacity(N_OUT);
        for j in 0..N_OUT {
            let x = input(&|s| s.pk_eph[j].x)?;
            let y = input(&|s| s.pk_eph[j].y)?;
            pk_eph_pub.push(AffineVar::new(x, y));
        }
        let mut ct_pub = Vec::with_capacity(N_OUT);
        for j in 0..N_OUT {
            let c0 = input(&|s| s.ct_note[j].c0)?;
            let c1 = input(&|s| s.ct_note[j].c1)?;
            let tag = input(&|s| s.ct_note[j].tag)?;
            ct_pub.push([c0, c1, tag]);
        }
        let h_body = input(&|s| s.h_body)?;

        // Arity is fixed; h_body and r_anchor get one constraint each so that
        // no public input is ever left unconstrained in the R1CS (block 8).
        n.enforce_equal(&Var::Constant(Fr::from(N_IN as u64)))?;
        m.enforce_equal(&Var::Constant(Fr::from(N_OUT as u64)))?;
        let _ = h_body.square()?;
        let _ = r_anchor.square()?;

        // ---- spend authority (blocks 3, 4) ----
        let w = self.witness.as_ref();
        let sk_spend =
            Var::new_witness(cs.clone(), || missing(w.map(|w| scalar_to_fr(&w.sk_spend))))?;
        let sk_nf = hash_var(t_sknf(), std::slice::from_ref(&sk_spend))?;
        let vk_in = hash_var(t_vkin(), std::slice::from_ref(&sk_spend))?;
        let sk_view_bits = low_bits(&hash_var(t_view(), &[vk_in])?, SCALAR_BITS)?;

        // ---- inputs (blocks 1, 2, 3, 4) ----
        let mut v_in = Var::zero();
        for (i, nf_pub_i) in nf_pub.iter().enumerate() {
            let iw = w.map(|w| &w.inputs[i]);
            let note = NoteVars::alloc(cs.clone(), iw.map(|w| &w.note))?;
            let h_body_create =
                Var::new_witness(cs.clone(), || missing(iw.map(|w| w.h_body_create)))?;
            let j = Var::new_witness(cs.clone(), || missing(iw.map(|w| Fr::from(w.output_index))))?;
            let (pos, pos_bits) = alloc_bounded(cs.clone(), iw.map(|w| Fr::from(w.pos)), DEPTH)?;
            let mut siblings = Vec::with_capacity(DEPTH);
            for k in 0..DEPTH {
                siblings.push(Var::new_witness(cs.clone(), || {
                    missing(iw.map(|w| w.siblings[k]))
                })?);
            }

            let g_d = diversify_hash_var(&note.d)?;
            let pk_d = g_d.scalar_mul_le(sk_view_bits.iter())?;
            let chan = output_channel(&note, &g_d, &pk_d)?;
            let leaf = leaf_var(&const_salt, &h_body_create, &j, &chan.pk_eph, &chan.ct)?;
            let root = merkle_root_var(&leaf, &pos_bits, &siblings)?;
            let is_real = !(note.v.is_zero()?);
            root.conditional_enforce_equal(&r_anchor, &is_real)?;

            let nf = nullifier_var(&sk_nf, &note.rho()?, &pos)?;
            nf.enforce_equal(nf_pub_i)?;
            v_in += &note.v;
        }

        // ---- outputs (block 5) ----
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

        // ---- value conservation (blocks 6, 7) ----
        v_in.enforce_equal(&v_out)?;
        Ok(())
    }
}
