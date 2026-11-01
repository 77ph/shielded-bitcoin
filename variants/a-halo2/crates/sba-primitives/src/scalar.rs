//! Scalars of Pallas (`PROFILE-A.md` §3): hash outputs in `Fp` are used as
//! scalars by their canonical integer value, which is always below `q`.

use ff::{FromUniformBytes, PrimeField};

use crate::encoding::DecodeError;
use crate::{Fp, Scalar};

/// `LE_int(s) ∈ Fq` for `s ∈ Fp`; injective since `p < q`.
pub fn scalar_from_fp(f: &Fp) -> Scalar {
    Scalar::from_repr(f.to_repr()).expect("p < q")
}

pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_repr()
}

pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, DecodeError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| DecodeError::Length {
        expected: 32,
        got: bytes.len(),
    })?;
    Option::from(Scalar::from_repr(arr)).ok_or(DecodeError::NonCanonical)
}

/// A scalar from 64 uniform bytes (key derivation).
pub fn scalar_from_wide_bytes(bytes: &[u8; 64]) -> Scalar {
    Scalar::from_uniform_bytes(bytes)
}

/// An `Fp` element from 64 uniform bytes (key derivation).
pub fn fp_from_wide_bytes(bytes: &[u8; 64]) -> Fp {
    Fp::from_uniform_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn scalars_round_trip() {
        let s = scalar_from_fp(&(-Fp::ONE));
        assert_eq!(scalar_from_bytes(&scalar_to_bytes(&s)).unwrap(), s);
        assert_eq!(scalar_to_bytes(&s), (-Fp::ONE).to_repr());
        assert!(scalar_from_bytes(&[0xffu8; 32]).is_err());
        let w = scalar_from_wide_bytes(&[7u8; 64]);
        assert_ne!(w, Scalar::ZERO);
    }
}
