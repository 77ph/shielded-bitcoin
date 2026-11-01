//! Wire encodings (`PROFILE-A.md` §1): field elements as 32-byte
//! little-endian canonical values, Pallas points compressed as `x` with the
//! parity of `y` in bit 255 (the `pasta_curves` convention).

use ff::PrimeField;
use group::GroupEncoding;
use group::prime::PrimeCurveAffine;

use crate::{Affine, Fp};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("wrong length: expected {expected}, got {got}")]
    Length { expected: usize, got: usize },
    #[error("non-canonical field element")]
    NonCanonical,
    #[error("not a point on the curve")]
    NotOnCurve,
    #[error("the identity is not a valid point")]
    Identity,
}

/// 32-byte LE canonical encoding.
pub fn fp_to_bytes(f: &Fp) -> [u8; 32] {
    f.to_repr()
}

/// Decode a canonical field element; rejects wrong lengths and values ≥ p.
pub fn fp_from_bytes(bytes: &[u8]) -> Result<Fp, DecodeError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| DecodeError::Length {
        expected: 32,
        got: bytes.len(),
    })?;
    Option::from(Fp::from_repr(arr)).ok_or(DecodeError::NonCanonical)
}

/// Compressed Pallas point: `x` LE with the parity of `y` in the top bit.
pub fn point_to_bytes(p: &Affine) -> [u8; 32] {
    p.to_bytes()
}

/// Decode a compressed point; rejects wrong lengths, `x ≥ p`, non-curve `x`
/// and the identity. (Pallas has prime order: no subgroup check exists.)
pub fn point_from_bytes(bytes: &[u8]) -> Result<Affine, DecodeError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| DecodeError::Length {
        expected: 32,
        got: bytes.len(),
    })?;
    let p: Affine = Option::from(Affine::from_bytes(&arr)).ok_or(DecodeError::NotOnCurve)?;
    if bool::from(p.is_identity()) {
        return Err(DecodeError::Identity);
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{Curve, Group};

    #[test]
    fn round_trips_and_rejections() {
        let f = Fp::from(123456789u64);
        assert_eq!(fp_from_bytes(&fp_to_bytes(&f)).unwrap(), f);
        assert_eq!(
            fp_from_bytes(&[0u8; 31]).unwrap_err(),
            DecodeError::Length {
                expected: 32,
                got: 31
            }
        );
        assert_eq!(
            fp_from_bytes(&[0xffu8; 32]).unwrap_err(),
            DecodeError::NonCanonical
        );
        let g = crate::Point::generator().to_affine();
        assert_eq!(point_from_bytes(&point_to_bytes(&g)).unwrap(), g);
        assert_eq!(
            point_from_bytes(&[0u8; 32]).unwrap_err(),
            DecodeError::Identity
        );
        let mut bad = point_to_bytes(&g);
        bad[0] ^= 1;
        assert!(matches!(
            point_from_bytes(&bad),
            Err(DecodeError::NotOnCurve)
        ));
    }
}
