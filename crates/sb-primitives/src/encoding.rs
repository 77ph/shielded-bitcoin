//! Wire encodings (profile §1): canonical 32-byte LE field elements and
//! compressed Jubjub points with the Zcash sign convention
//! (`y` little-endian, bit 255 = least significant bit of `x`).

use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

use crate::{Fr, JubjubAffine};

/// Errors raised by canonical decoders.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    #[error("field element is not canonical (>= modulus)")]
    NonCanonicalField,
    #[error("point encoding is not canonical")]
    NonCanonicalPoint,
    #[error("point is not on the curve")]
    NotOnCurve,
    #[error("point is not in the prime-order subgroup")]
    NotInSubgroup,
    #[error("point is the identity")]
    Identity,
    #[error("wrong length: expected {expected}, got {got}")]
    Length { expected: usize, got: usize },
}

/// Canonical 32-byte little-endian encoding of an `Fr` element.
pub fn fr_to_bytes(f: &Fr) -> [u8; 32] {
    let v = f.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Decode a 32-byte little-endian `Fr` element, rejecting values `>= q`.
pub fn fr_from_bytes(bytes: &[u8]) -> Result<Fr, DecodeError> {
    if bytes.len() != 32 {
        return Err(DecodeError::Length {
            expected: 32,
            got: bytes.len(),
        });
    }
    let f = Fr::from_le_bytes_mod_order(bytes);
    if fr_to_bytes(&f)[..] != bytes[..] {
        return Err(DecodeError::NonCanonicalField);
    }
    Ok(f)
}

/// Jubjub `d` coefficient (`-(10240/10241)`).
pub fn jubjub_d() -> Fr {
    <ark_ed_on_bls12_381::EdwardsConfig as TECurveConfig>::COEFF_D
}

/// Compressed Jubjub point: `y` LE with bit 255 = LSB of `x`.
pub fn point_to_bytes(p: &JubjubAffine) -> [u8; 32] {
    let mut out = fr_to_bytes(&p.y);
    if p.x.into_bigint().is_odd() {
        out[31] |= 0x80;
    }
    out
}

/// Decode a compressed Jubjub point. Rejects non-canonical `y`, off-curve
/// values, the identity, points outside the prime-order subgroup, and the
/// non-canonical encoding of `x = 0` with the sign bit set.
pub fn point_from_bytes(bytes: &[u8]) -> Result<JubjubAffine, DecodeError> {
    if bytes.len() != 32 {
        return Err(DecodeError::Length {
            expected: 32,
            got: bytes.len(),
        });
    }
    let sign = bytes[31] & 0x80 != 0;
    let mut yb = [0u8; 32];
    yb.copy_from_slice(bytes);
    yb[31] &= 0x7f;
    let y = fr_from_bytes(&yb)?;

    // -x^2 + y^2 = 1 + d x^2 y^2  =>  x^2 = (y^2 - 1) / (d y^2 + 1)
    let y2 = y.square();
    let num = y2 - Fr::one();
    let den = jubjub_d() * y2 + Fr::one();
    let x2 = num * den.inverse().ok_or(DecodeError::NotOnCurve)?;
    let mut x = x2.sqrt().ok_or(DecodeError::NotOnCurve)?;
    if x.is_zero() {
        if sign {
            return Err(DecodeError::NonCanonicalPoint);
        }
    } else if x.into_bigint().is_odd() != sign {
        x = -x;
    }
    let p = JubjubAffine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(DecodeError::NotOnCurve);
    }
    if p.is_zero() {
        return Err(DecodeError::Identity);
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(DecodeError::NotInSubgroup);
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Jubjub, JubjubScalar};
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::UniformRand;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn fr_round_trip_and_canonicality() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..100 {
            let f = Fr::rand(&mut rng);
            assert_eq!(fr_from_bytes(&fr_to_bytes(&f)).unwrap(), f);
        }
        // q itself is not canonical.
        let q = Fr::MODULUS.to_bytes_le();
        assert_eq!(fr_from_bytes(&q), Err(DecodeError::NonCanonicalField));
        // all-ones is not canonical.
        assert_eq!(
            fr_from_bytes(&[0xffu8; 32]),
            Err(DecodeError::NonCanonicalField)
        );
        assert_eq!(
            fr_from_bytes(&[0u8; 31]),
            Err(DecodeError::Length {
                expected: 32,
                got: 31
            })
        );
    }

    #[test]
    fn point_round_trip_both_signs() {
        let mut rng = StdRng::seed_from_u64(2);
        for _ in 0..50 {
            let s = JubjubScalar::rand(&mut rng);
            let p = (Jubjub::generator() * s).into_affine();
            let enc = point_to_bytes(&p);
            assert_eq!(point_from_bytes(&enc).unwrap(), p);
            let neg = -p;
            let enc_neg = point_to_bytes(&neg);
            assert_eq!(point_from_bytes(&enc_neg).unwrap(), neg);
            assert_ne!(enc, enc_neg);
            assert_eq!(enc[..31], enc_neg[..31]);
        }
    }

    #[test]
    fn point_rejections() {
        // identity (0, 1)
        let mut id = fr_to_bytes(&Fr::one());
        assert_eq!(point_from_bytes(&id), Err(DecodeError::Identity));
        id[31] |= 0x80;
        assert_eq!(point_from_bytes(&id), Err(DecodeError::NonCanonicalPoint));
        // y >= q
        let q = Fr::MODULUS.to_bytes_le();
        assert_eq!(point_from_bytes(&q), Err(DecodeError::NonCanonicalField));
        // small-order point of order 2: (0, -1)
        let t2 = fr_to_bytes(&(-Fr::one()));
        assert_eq!(point_from_bytes(&t2), Err(DecodeError::NotInSubgroup));
        // a y with no x on the curve
        let mut rng = StdRng::seed_from_u64(3);
        let mut rejected = 0;
        for _ in 0..64 {
            let y = Fr::rand(&mut rng);
            if point_from_bytes(&fr_to_bytes(&y)).is_err() {
                rejected += 1;
            }
        }
        assert!(rejected > 0);
    }
}
