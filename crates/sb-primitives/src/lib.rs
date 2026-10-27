//! Primitives shared by every Shielded Bitcoin crate.
//!
//! * `Fr`: the BLS12-381 scalar field, in which all in-circuit values live.
//! * Jubjub: the embedded twisted Edwards curve used for keys and ECDH.
//! * Poseidon: the single in-circuit hash (profile §2.1).
//! * Domain tags (profile §2.1) and wire encodings (profile §1).
//!
//! Everything here must be byte-for-byte reproducible by any other
//! implementation of the same profile; see `docs/PROFILE.md`.

pub use ark_bls12_381::Fr;
pub use ark_ed_on_bls12_381::{
    EdwardsAffine as JubjubAffine, EdwardsProjective as Jubjub, Fr as JubjubScalar,
};

pub mod diversify;
pub mod encoding;
pub mod poseidon;
pub mod scalar;
pub mod tags;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::{BigInteger, PrimeField};

    #[test]
    fn field_and_curve_parameters_are_the_profile_ones() {
        // BLS12-381 scalar field modulus, profile §1.
        let q = Fr::MODULUS.to_bytes_be();
        assert_eq!(
            hex::encode(q),
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
        );
        // Jubjub subgroup order, profile §1.
        let r = JubjubScalar::MODULUS.to_bytes_be();
        assert_eq!(
            hex::encode(r),
            "0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7"
        );
        // 2^250 < r_J, so `Scalar250` never needs a reduction (profile §2.1).
        assert_eq!(JubjubScalar::MODULUS_BIT_SIZE, 252);
        let g = Jubjub::generator().into_affine();
        assert!(g.is_on_curve());
    }
}
