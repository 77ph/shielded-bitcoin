//! R1CS gadgets mirroring the native derivations of `sb-core` (profile §8.3).
//!
//! Every gadget here has a native twin; the tests in `transfer.rs` check that
//! the circuit accepts exactly the values the native code produces.

use ark_ec::twisted_edwards::TECurveConfig;
use ark_ed_on_bls12_381::EdwardsConfig;
use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_ff::One;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use sb_core::note::NotePlaintext;
use sb_core::tree::DEPTH;
use sb_primitives::Fr;
use sb_primitives::diversify::{diversifier_to_fr, even_x_for_y};
use sb_primitives::poseidon::gadget::hash_var;
use sb_primitives::tags::{t_div, t_eph, t_kdf, t_leaf, t_mac, t_nf, t_node, t_rho, t_stream};

pub type Var = FpVar<Fr>;
pub type PointVar = EdwardsVar;
pub type Bit = Boolean<Fr>;

/// Bits of a Jubjub scalar produced by `Scalar250`.
pub const SCALAR_BITS: usize = 250;

fn missing<T>(v: Option<T>) -> Result<T, SynthesisError> {
    v.ok_or(SynthesisError::AssignmentMissing)
}

/// Witness `value` and enforce `value < 2^size`; returns the element and its bits.
pub fn alloc_bounded(
    cs: ConstraintSystemRef<Fr>,
    value: Option<Fr>,
    size: usize,
) -> Result<(Var, Vec<Bit>), SynthesisError> {
    let fp = Var::new_witness(cs, || missing(value))?;
    let (bits, _) = fp.to_bits_le_with_top_bits_zero(size)?;
    Ok((fp, bits))
}

/// Low `n` bits of the canonical representation of `x`.
pub fn low_bits(x: &Var, n: usize) -> Result<Vec<Bit>, SynthesisError> {
    let bits = x.to_bits_le()?;
    Ok(bits[..n].to_vec())
}

/// `DiversifyHash(d)` (profile §4.2): `y = PH(T_DIV, d)`, witnessed even `x`
/// on the curve, cofactor cleared, not the identity. Fails at witness
/// generation if `d` is invalid, exactly like the native function.
pub fn diversify_hash_var(d: &Var) -> Result<PointVar, SynthesisError> {
    let y = hash_var(t_div(), &[d.clone()])?;
    let cs = d.cs();
    let x = Var::new_witness(cs, || {
        let y = y.value()?;
        even_x_for_y(&y).ok_or(SynthesisError::Unsatisfiable)
    })?;
    // (y² − 1) = x² · (d_J y² + 1)
    let x2 = x.square()?;
    let y2 = y.square()?;
    let lhs = &y2 - Fr::one();
    let factor = &y2 * <EdwardsConfig as TECurveConfig>::COEFF_D + Fr::one();
    x2.mul_equals(&factor, &lhs)?;
    // canonical sign: x even
    let x_bits = x.to_bits_le()?;
    x_bits[0].enforce_equal(&Bit::FALSE)?;
    let mut p = PointVar::new(x, y);
    p.double_in_place()?;
    p.double_in_place()?;
    p.double_in_place()?;
    // not the identity (x ≠ 0 within the prime-order subgroup)
    let _ = p.x.inverse()?;
    Ok(p)
}

/// Allocated note plaintext with range-checked `v` (64 bits) and `d` (88 bits).
pub struct NoteVars {
    pub v: Var,
    pub d: Var,
    pub rseed: Var,
}

impl NoteVars {
    pub fn alloc(
        cs: ConstraintSystemRef<Fr>,
        note: Option<&NotePlaintext>,
    ) -> Result<Self, SynthesisError> {
        let (v, _) = alloc_bounded(cs.clone(), note.map(|n| Fr::from(n.value)), 64)?;
        let (d, _) = alloc_bounded(cs.clone(), note.map(|n| diversifier_to_fr(&n.d)), 88)?;
        let rseed = Var::new_witness(cs, || missing(note.map(|n| n.rseed)))?;
        Ok(NoteVars { v, d, rseed })
    }

    /// `m_0 = v + 2^64 · d`.
    pub fn m0(&self) -> Var {
        &self.v + &self.d * Fr::from(1u128 << 64)
    }

    /// `rho = PH(T_RHO, rseed)`.
    pub fn rho(&self) -> Result<Var, SynthesisError> {
        hash_var(t_rho(), &[self.rseed.clone()])
    }

    /// `sk_eph` bits.
    pub fn sk_eph_bits(&self) -> Result<Vec<Bit>, SynthesisError> {
        low_bits(&hash_var(t_eph(), &[self.rseed.clone()])?, SCALAR_BITS)
    }
}

/// `k = PH(T_KDF, ss.x, ss.y, pk_eph.x, pk_eph.y)`.
pub fn note_key_var(ss: &PointVar, pk_eph: &PointVar) -> Result<Var, SynthesisError> {
    hash_var(
        t_kdf(),
        &[
            ss.x.clone(),
            ss.y.clone(),
            pk_eph.x.clone(),
            pk_eph.y.clone(),
        ],
    )
}

/// `(c_0, c_1, tag)` under `k`.
pub fn encrypt_var(k: &Var, m0: &Var, m1: &Var) -> Result<[Var; 3], SynthesisError> {
    let c0 = m0 + hash_var(t_stream(), &[k.clone(), Var::zero()])?;
    let c1 = m1 + hash_var(t_stream(), &[k.clone(), Var::one()])?;
    let tag = hash_var(t_mac(), &[k.clone(), c0.clone(), c1.clone()])?;
    Ok([c0, c1, tag])
}

/// Output-channel values for a note sent to `pk_d`: `(pk_eph, ss, ct)`.
pub struct OutputChannel {
    pub pk_eph: PointVar,
    pub ct: [Var; 3],
}

/// Derive `pk_eph = [sk_eph] G_d`, `ss = [sk_eph] pk_d`, `ct`.
pub fn output_channel(
    note: &NoteVars,
    g_d: &PointVar,
    pk_d: &PointVar,
) -> Result<OutputChannel, SynthesisError> {
    let eph_bits = note.sk_eph_bits()?;
    let pk_eph = g_d.scalar_mul_le(eph_bits.iter())?;
    let ss = pk_d.scalar_mul_le(eph_bits.iter())?;
    let k = note_key_var(&ss, &pk_eph)?;
    let ct = encrypt_var(&k, &note.m0(), &note.rseed)?;
    Ok(OutputChannel { pk_eph, ct })
}

/// `leaf = PH(T_LEAF, const_salt, h_body, j, pk_eph.x, pk_eph.y, c_0, c_1, tag, 0)`.
pub fn leaf_var(
    const_salt: &Var,
    h_body: &Var,
    j: &Var,
    pk_eph: &PointVar,
    ct: &[Var; 3],
) -> Result<Var, SynthesisError> {
    hash_var(
        t_leaf(),
        &[
            const_salt.clone(),
            h_body.clone(),
            j.clone(),
            pk_eph.x.clone(),
            pk_eph.y.clone(),
            ct[0].clone(),
            ct[1].clone(),
            ct[2].clone(),
            Var::zero(),
        ],
    )
}

/// `nf = PH(T_NF, sk_nf, rho, pos)`.
pub fn nullifier_var(sk_nf: &Var, rho: &Var, pos: &Var) -> Result<Var, SynthesisError> {
    hash_var(t_nf(), &[sk_nf.clone(), rho.clone(), pos.clone()])
}

/// Merkle root of `leaf` at the position given by `pos_bits` (LSB first).
pub fn merkle_root_var(
    leaf: &Var,
    pos_bits: &[Bit],
    siblings: &[Var],
) -> Result<Var, SynthesisError> {
    debug_assert_eq!(pos_bits.len(), DEPTH);
    debug_assert_eq!(siblings.len(), DEPTH);
    let mut cur = leaf.clone();
    for (bit, sib) in pos_bits.iter().zip(siblings) {
        // bit = 1 → current node is the right child
        let left = Var::conditionally_select(bit, sib, &cur)?;
        let right = Var::conditionally_select(bit, &cur, sib)?;
        cur = hash_var(t_node(), &[left, right])?;
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{SeedableRng, rngs::StdRng};
    use sb_core::keys::{Seed, WalletKeys};
    use sb_core::note::{encrypt_note, note_leaf, nullifier};
    use sb_core::tree::NoteTree;
    use sb_primitives::diversify::diversify_hash;
    use sb_primitives::scalar::scalar250_bits;

    #[test]
    fn diversify_hash_gadget_matches_native() {
        let k = WalletKeys::from_seed(&Seed([1u8; 32]));
        let (_, addr) = k.ivk.find_address(0);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let d = Var::new_witness(cs.clone(), || Ok(diversifier_to_fr(&addr.d))).unwrap();
        let before = cs.num_constraints();
        let g = diversify_hash_var(&d).unwrap();
        println!(
            "DiversifyHash constraints: {}",
            cs.num_constraints() - before
        );
        let expected = diversify_hash(&addr.d).unwrap();
        assert_eq!(g.x.value().unwrap(), expected.x);
        assert_eq!(g.y.value().unwrap(), expected.y);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn output_channel_and_leaf_match_native() {
        let mut rng = StdRng::seed_from_u64(3);
        let k = WalletKeys::from_seed(&Seed([2u8; 32]));
        let (_, addr) = k.ivk.find_address(0);
        let pt = NotePlaintext {
            value: 777,
            d: addr.d,
            rseed: Fr::rand(&mut rng),
        };
        let (pk_eph, ct) = encrypt_note(&pt, &addr.pk_d).unwrap();

        let cs = ConstraintSystem::<Fr>::new_ref();
        let note = NoteVars::alloc(cs.clone(), Some(&pt)).unwrap();
        let g_d = diversify_hash_var(&note.d).unwrap();
        let pk_d = PointVar::new_witness(cs.clone(), || Ok(addr.pk_d.into_group())).unwrap();
        let before = cs.num_constraints();
        let out = output_channel(&note, &g_d, &pk_d).unwrap();
        println!(
            "output channel constraints: {}",
            cs.num_constraints() - before
        );
        assert_eq!(out.pk_eph.x.value().unwrap(), pk_eph.x);
        assert_eq!(out.pk_eph.y.value().unwrap(), pk_eph.y);
        assert_eq!(out.ct[0].value().unwrap(), ct.c0);
        assert_eq!(out.ct[1].value().unwrap(), ct.c1);
        assert_eq!(out.ct[2].value().unwrap(), ct.tag);

        let salt = Fr::from(5u64);
        let hb = Fr::from(6u64);
        let leaf = leaf_var(
            &Var::Constant(salt),
            &Var::Constant(hb),
            &Var::Constant(Fr::from(1u64)),
            &out.pk_eph,
            &out.ct,
        )
        .unwrap();
        assert_eq!(
            leaf.value().unwrap(),
            note_leaf(&salt, &hb, 1, &pk_eph, &ct)
        );

        // pk_d via sk_view
        let bits: Vec<Bit> = scalar250_bits(&sb_primitives::poseidon::hash(
            sb_primitives::tags::t_view(),
            &[k.ivk.vk_in],
        ))
        .iter()
        .map(|b| Bit::new_witness(cs.clone(), || Ok(*b)).unwrap())
        .collect();
        let pk_d2 = g_d.scalar_mul_le(bits.iter()).unwrap();
        assert_eq!(pk_d2.x.value().unwrap(), addr.pk_d.x);
        assert_eq!(pk_d2.y.value().unwrap(), addr.pk_d.y);

        let nf = nullifier_var(
            &Var::Constant(k.sk_nf),
            &note.rho().unwrap(),
            &Var::Constant(Fr::from(9u64)),
        )
        .unwrap();
        assert_eq!(nf.value().unwrap(), nullifier(&k.sk_nf, &pt.rho(), 9));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn merkle_gadget_matches_tree() {
        let mut rng = StdRng::seed_from_u64(4);
        let leaves: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let tree = NoteTree::from_leaves(&leaves);
        for pos in 0..5u64 {
            let path = tree.path(pos).unwrap();
            let cs = ConstraintSystem::<Fr>::new_ref();
            let leaf = Var::new_witness(cs.clone(), || Ok(leaves[pos as usize])).unwrap();
            let (_, bits) = alloc_bounded(cs.clone(), Some(Fr::from(pos)), DEPTH).unwrap();
            let sibs: Vec<Var> = path
                .siblings
                .iter()
                .map(|s| Var::new_witness(cs.clone(), || Ok(*s)).unwrap())
                .collect();
            let root = merkle_root_var(&leaf, &bits, &sibs).unwrap();
            assert_eq!(root.value().unwrap(), tree.root());
            assert!(cs.is_satisfied().unwrap());
        }
    }
}
