//! `DiversifyHash` (profile §4.2): diversifier → prime-order Jubjub point.
//!
//! ```text
//! y  = PH(T_DIV, LE_int(d))
//! x² = (y² − 1) / (d_J y² + 1)        must be a square, else INVALID
//! x  = the even square root
//! P  = [8](x, y)                       must not be the identity, else INVALID
//! ```

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, One, PrimeField};

use crate::encoding::jubjub_d;
use crate::poseidon::hash;
use crate::tags::t_div;
use crate::{Fr, JubjubAffine};

/// Diversifier length in bytes (profile §A.2).
pub const DIVERSIFIER_LEN: usize = 11;

/// A diversifier as a field element (`LE_int(d)`, at most 88 bits).
pub fn diversifier_to_fr(d: &[u8; DIVERSIFIER_LEN]) -> Fr {
    Fr::from_le_bytes_mod_order(d)
}

/// Recover the 11 diversifier bytes from a field element, if it fits in 88 bits.
pub fn diversifier_from_fr(f: &Fr) -> Option<[u8; DIVERSIFIER_LEN]> {
    let bytes = f.into_bigint().to_bytes_le();
    if bytes[DIVERSIFIER_LEN..].iter().any(|b| *b != 0) {
        return None;
    }
    let mut d = [0u8; DIVERSIFIER_LEN];
    d.copy_from_slice(&bytes[..DIVERSIFIER_LEN]);
    Some(d)
}

/// The `y` coordinate candidate for a diversifier.
pub fn diversify_y(d: &[u8; DIVERSIFIER_LEN]) -> Fr {
    hash(t_div(), &[diversifier_to_fr(d)])
}

/// Given `y`, the even `x` with `(x, y)` on Jubjub, if any.
pub fn even_x_for_y(y: &Fr) -> Option<Fr> {
    let y2 = y.square();
    let num = y2 - Fr::one();
    let den = jubjub_d() * y2 + Fr::one();
    let x2 = num * den.inverse()?;
    let x = x2.sqrt()?;
    Some(if x.into_bigint().is_odd() { -x } else { x })
}

/// `DiversifyHash(d)`, or `None` if `d` is invalid (≈ 50 % of diversifiers).
pub fn diversify_hash(d: &[u8; DIVERSIFIER_LEN]) -> Option<JubjubAffine> {
    let y = diversify_y(d);
    let x = even_x_for_y(&y)?;
    let p = JubjubAffine::new_unchecked(x, y);
    debug_assert!(p.is_on_curve());
    let p8 = p.into_group().double().double().double().into_affine();
    if p8.is_zero() { None } else { Some(p8) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_in_subgroup_and_roughly_half_valid() {
        let mut valid = 0;
        for i in 0u64..200 {
            let mut d = [0u8; DIVERSIFIER_LEN];
            d[..8].copy_from_slice(&i.to_le_bytes());
            if let Some(p) = diversify_hash(&d) {
                valid += 1;
                assert!(p.is_on_curve());
                assert!(p.is_in_correct_subgroup_assuming_on_curve());
                assert!(!p.is_zero());
            }
        }
        assert!((60..140).contains(&valid), "valid = {valid}");
    }

    #[test]
    fn diversifier_field_round_trip() {
        let d = [0xabu8; DIVERSIFIER_LEN];
        assert_eq!(diversifier_from_fr(&diversifier_to_fr(&d)), Some(d));
        assert_eq!(diversifier_from_fr(&Fr::from(1u128 << 90)), None);
    }
}
