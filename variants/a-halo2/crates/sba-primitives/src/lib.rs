//! Primitives of variant A (`docs/PROFILE-A.md` §1–§4): the circuit field
//! `Fp` (Pallas's base field), the embedded curve Pallas, Poseidon in the
//! halo2 constant-length mode, domain tags and wire encodings. Everything
//! here must be byte-for-byte reproducible by another implementation of
//! the profile, exactly as `sb-primitives` is for the paper profile.

pub use pasta_curves::pallas;

/// The circuit field: Pallas's base field (= Vesta's scalar field).
pub type Fp = pallas::Base;
/// Scalars of Pallas.
pub type Scalar = pallas::Scalar;
/// Pallas points, projective.
pub type Point = pallas::Point;
/// Pallas points, affine.
pub type Affine = pallas::Affine;

pub mod diversify;
pub mod encoding;
pub mod poseidon;
pub mod poseidon_params;
pub mod scalar;
pub mod tags;

#[cfg(test)]
mod tests {
    use super::*;
    use ff::{Field, PrimeField};

    #[test]
    fn field_and_curve_parameters_are_the_profile_ones() {
        // PROFILE-A.md §1: p (base field) and q (scalar field) of Pallas
        assert_eq!(
            Fp::MODULUS,
            "0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001"
        );
        assert_eq!(
            Scalar::MODULUS,
            "0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001"
        );
        // p < q: every Fp element is a valid scalar (PROFILE-A.md §3)
        let p_max = -Fp::ONE;
        assert!(Scalar::from_repr(p_max.to_repr()).is_some().unwrap_u8() == 1);
        // 2^254 < p: a 254-bit value is a canonical element (PROFILE-A.md §2.2)
        let mut b = [0u8; 32];
        b[31] = 0x3f;
        b[30] = 0xff;
        assert!(Fp::from_repr(b).is_some().unwrap_u8() == 1);
    }
}
