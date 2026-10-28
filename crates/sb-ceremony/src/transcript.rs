//! Hashing, hashing to `G2`, and the pairing checks both phases use.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

/// Every point on the curve and in the prime-order subgroup, checked in
/// parallel (files are read unchecked and validated here).
pub fn valid_g1(points: &[G1Affine]) -> bool {
    use rayon::prelude::*;
    points
        .par_iter()
        .all(|p| p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
}

pub fn valid_g2(points: &[G2Affine]) -> bool {
    use rayon::prelude::*;
    points
        .par_iter()
        .all(|p| p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve())
}

/// SHA-256.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Compressed bytes of a curve point.
pub fn point_bytes<P: CanonicalSerialize>(p: &P) -> Vec<u8> {
    let mut out = Vec::new();
    p.serialize_compressed(&mut out).expect("in-memory write");
    out
}

/// A `G2` point nobody knows the discrete logarithm of, derived from
/// `domain` and `inputs`: SHA-256 seeds a ChaCha20 stream that samples the
/// point (random-oracle idiom, as in the Sapling tools).
pub fn hash_to_g2(domain: &[u8], inputs: &[&[u8]]) -> G2Projective {
    let mut h = Sha256::new();
    h.update(b"sb-ceremony/hash-to-g2/");
    h.update(domain);
    for i in inputs {
        h.update((i.len() as u64).to_le_bytes());
        h.update(i);
    }
    let mut rng = ChaCha20Rng::from_seed(h.finalize().into());
    G2Projective::rand(&mut rng)
}

/// `e(a₁, b₂) == e(a₂, b₁)`: the pairs `(a₁, a₂)` and `(b₁, b₂)` have the
/// same discrete-log ratio.
pub fn same_ratio(g1: (G1Affine, G1Affine), g2: (G2Affine, G2Affine)) -> bool {
    Bls12_381::pairing(g1.0, g2.1) == Bls12_381::pairing(g1.1, g2.0)
}

/// Random scalars for batching checks over `n` elements.
pub fn random_scalars<R: RngCore>(n: usize, rng: &mut R) -> Vec<Fr> {
    (0..n).map(|_| Fr::rand(rng)).collect()
}

/// One pair standing for all consecutive pairs of `v`: `(Σ rᵢ vᵢ, Σ rᵢ vᵢ₊₁)`
/// has ratio `x` exactly when every `vᵢ₊₁ / vᵢ` does (with overwhelming
/// probability over the `rᵢ`).
pub fn power_pairs_g1<R: RngCore>(v: &[G1Affine], rng: &mut R) -> (G1Affine, G1Affine) {
    let r = random_scalars(v.len() - 1, rng);
    let l = G1Projective::msm(&v[..v.len() - 1], &r).expect("lengths match");
    let h = G1Projective::msm(&v[1..], &r).expect("lengths match");
    (l.into_affine(), h.into_affine())
}

pub fn power_pairs_g2<R: RngCore>(v: &[G2Affine], rng: &mut R) -> (G2Affine, G2Affine) {
    let r = random_scalars(v.len() - 1, rng);
    let l = G2Projective::msm(&v[..v.len() - 1], &r).expect("lengths match");
    let h = G2Projective::msm(&v[1..], &r).expect("lengths match");
    (l.into_affine(), h.into_affine())
}

/// One pair standing for the element-wise pairs `(aᵢ, bᵢ)`: same ratio for
/// the combination exactly when every pair has it.
pub fn merge_pairs_g1<R: RngCore>(
    a: &[G1Affine],
    b: &[G1Affine],
    rng: &mut R,
) -> (G1Affine, G1Affine) {
    assert_eq!(a.len(), b.len());
    let r = random_scalars(a.len(), rng);
    let l = G1Projective::msm(a, &r).expect("lengths match");
    let h = G1Projective::msm(b, &r).expect("lengths match");
    (l.into_affine(), h.into_affine())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_ff::Field;
    use rand::SeedableRng;

    #[test]
    fn ratio_checks() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let x = Fr::rand(&mut rng);
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        assert!(same_ratio(
            (g1.into_affine(), (g1 * x).into_affine()),
            (g2.into_affine(), (g2 * x).into_affine())
        ));
        assert!(!same_ratio(
            (g1.into_affine(), (g1 * x).into_affine()),
            (g2.into_affine(), (g2 * x.square()).into_affine())
        ));
        // powers of x in G1 against (1, x) in G2
        let mut p = Fr::ONE;
        let powers: Vec<G1Affine> = (0..9)
            .map(|_| {
                let q = (g1 * p).into_affine();
                p *= x;
                q
            })
            .collect();
        let g2x = (g2 * x).into_affine();
        assert!(same_ratio(
            power_pairs_g1(&powers, &mut rng),
            (g2.into_affine(), g2x)
        ));
        let mut broken = powers.clone();
        broken[5] = (g1 * Fr::from(3u64)).into_affine();
        assert!(!same_ratio(
            power_pairs_g1(&broken, &mut rng),
            (g2.into_affine(), g2x)
        ));
        // the G2 side
        let mut p = Fr::ONE;
        let powers2: Vec<G2Affine> = (0..5)
            .map(|_| {
                let q = (g2 * p).into_affine();
                p *= x;
                q
            })
            .collect();
        assert!(same_ratio(
            (powers[0], powers[1]),
            power_pairs_g2(&powers2, &mut rng)
        ));
        // element-wise pairs with one common ratio
        let scaled: Vec<G1Affine> = powers.iter().map(|q| (*q * x).into_affine()).collect();
        assert!(same_ratio(
            merge_pairs_g1(&powers, &scaled, &mut rng),
            (g2.into_affine(), g2x)
        ));
        assert!(!same_ratio(
            merge_pairs_g1(&powers, &broken, &mut rng),
            (g2.into_affine(), g2x)
        ));
    }

    #[test]
    fn hash_to_g2_is_deterministic_and_domain_separated() {
        let a = hash_to_g2(b"x", &[b"1", b"2"]);
        assert_eq!(a, hash_to_g2(b"x", &[b"1", b"2"]));
        assert_ne!(a, hash_to_g2(b"y", &[b"1", b"2"]));
        assert_ne!(a, hash_to_g2(b"x", &[b"12"]));
        assert_ne!(a, hash_to_g2(b"x", &[b"1", b"3"]));
    }
}
