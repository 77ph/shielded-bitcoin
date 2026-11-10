//! The verifier's field arithmetic, natively, for either curve
//! (`shadow_body.rs`, included once per side): `fp` for Vesta-committed
//! proofs, `fq` for Pallas-committed ones.

/// Vesta-committed proofs: scalars in `Fp`.
pub mod fp {
    use pasta_curves::vesta as curve;
    type F = curve::Scalar;
    include!("shadow_body.rs");
}

/// Pallas-committed proofs: scalars in `Fq`.
pub mod fq {
    use pasta_curves::pallas as curve;
    type F = curve::Scalar;
    include!("shadow_body.rs");
}

#[cfg(test)]
mod tests {
    use super::fp::*;
    use crate::verifier::tests_support::real;
    use ff::{Field, PrimeField};
    use pasta_curves::vesta;
    use sba_primitives::Fp;
    use std::collections::BTreeMap;

    #[test]
    fn the_shadow_reproduces_the_verifiers_scalars() {
        let (params, vk, cap) = real();
        let sh = Shadow::compute(&params, &vk, &cap);
        println!(
            "commitments {}, queries {}, point sets {} (sizes {:?}), terms {} (merged {})",
            sh.commitments.len(),
            sh.queries.len(),
            sh.point_sets.len(),
            sh.point_sets.iter().map(|s| s.len()).collect::<Vec<_>>(),
            sh.terms.len(),
            sh.merged().len()
        );
        let ours = sh.merged();
        let mut theirs: BTreeMap<[u8; 64], Fp> = BTreeMap::new();
        for (s, p) in &cap.terms {
            use pasta_curves::arithmetic::CurveAffine;
            let c = p.coordinates().unwrap();
            let mut key = [0u8; 64];
            key[..32].copy_from_slice(&c.x().to_repr());
            key[32..].copy_from_slice(&c.y().to_repr());
            *theirs.entry(key).or_insert(Fp::ZERO) += s;
        }
        assert_eq!(ours.len(), theirs.len(), "same set of points");
        let mut mismatches = 0;
        let label = |key: &[u8; 64]| -> String {
            let t = &sh.typed;
            let same = |p: &vesta::Affine| {
                use pasta_curves::arithmetic::CurveAffine;
                let c = p.coordinates().unwrap();
                key[..32] == c.x().to_repr()[..] && key[32..] == c.y().to_repr()[..]
            };
            if same(&t.q_prime) {
                return "q_prime".into();
            }
            if same(&t.s_poly) {
                return "s_poly".into();
            }
            if same(&t.random_commitment) {
                return "random".into();
            }
            if same(&t.instance_commitment) {
                return "instance".into();
            }
            if same(&cap.g) {
                return "G".into();
            }
            if same(&params.get_g()[0]) {
                return "G_0".into();
            }
            for (i, p) in t.advice_commitments.iter().enumerate() {
                if same(p) {
                    return format!("advice[{i}]");
                }
            }
            for (i, p) in t.h_commitments.iter().enumerate() {
                if same(p) {
                    return format!("h[{i}]");
                }
            }
            for (i, p) in t.permutation_products.iter().enumerate() {
                if same(p) {
                    return format!("perm_product[{i}]");
                }
            }
            for (i, p) in t.lookup_products.iter().enumerate() {
                if same(p) {
                    return format!("lookup_product[{i}]");
                }
            }
            for (i, (a, b)) in t.lookups_permuted.iter().enumerate() {
                if same(a) {
                    return format!("lookup_permuted_input[{i}]");
                }
                if same(b) {
                    return format!("lookup_permuted_table[{i}]");
                }
            }
            for (i, (l, r, _)) in t.rounds.iter().enumerate() {
                if same(l) {
                    return format!("L[{i}]");
                }
                if same(r) {
                    return format!("R[{i}]");
                }
            }
            for (i, p) in vk.fixed_commitments().iter().enumerate() {
                if same(p) {
                    return format!("fixed[{i}]");
                }
            }
            for (i, p) in vk.permutation_commitments().iter().enumerate() {
                if same(p) {
                    return format!("perm_common[{i}]");
                }
            }
            "?".into()
        };
        for (k, s) in &ours {
            if theirs.get(k) != Some(s) {
                mismatches += 1;
                let th = theirs[k];
                let ratio = th * s.invert().unwrap_or(Fp::ZERO);
                let mut note = String::new();
                for e in 0..8u64 {
                    if ratio == sh.typed.x_1.pow_vartime([e]) {
                        note = format!("theirs = ours * x_1^{e}");
                    }
                    if ratio == sh.typed.x_4.pow_vartime([e]) {
                        note = format!("theirs = ours * x_4^{e}");
                    }
                    if ratio == sh.typed.x_1.pow_vartime([e]).invert().unwrap() {
                        note = format!("theirs = ours / x_1^{e}");
                    }
                    if ratio == sh.typed.x_4.pow_vartime([e]).invert().unwrap() {
                        note = format!("theirs = ours / x_4^{e}");
                    }
                }
                println!("mismatch {}: {note}", label(k));
            }
        }
        assert_eq!(mismatches, 0, "every scalar as the verifier computes it");
        assert_eq!(sh.w_scalar, cap.w_scalar);
        assert_eq!(sh.u_scalar, cap.u_scalar);
    }
}
