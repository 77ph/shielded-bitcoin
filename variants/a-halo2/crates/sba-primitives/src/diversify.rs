//! `DiversifyHash` on Pallas (`PROFILE-A.md` §4.2): diversifier → point.
//!
//! ```text
//! x  = PH_A(T_DIV, LE_int(d))
//! y² = x³ + 5                          must be a square, else INVALID
//! y  = the even square root
//! P  = (x, y)                          prime order: no cofactor step
//! ```

use ff::{Field, PrimeField};
use pasta_curves::arithmetic::CurveAffine;

use crate::poseidon::hash;
use crate::tags::t_div;
use crate::{Affine, Fp};

/// Diversifier length in bytes (profile §A.2).
pub const DIVERSIFIER_LEN: usize = 11;

/// A diversifier as a field element (`LE_int(d)`, at most 88 bits).
pub fn diversifier_to_fp(d: &[u8; DIVERSIFIER_LEN]) -> Fp {
    let mut bytes = [0u8; 32];
    bytes[..DIVERSIFIER_LEN].copy_from_slice(d);
    Fp::from_repr(bytes).expect("88 bits are below the modulus")
}

/// Recover the 11 diversifier bytes from a field element, if it fits in 88 bits.
pub fn diversifier_from_fp(f: &Fp) -> Option<[u8; DIVERSIFIER_LEN]> {
    let bytes = f.to_repr();
    if bytes[DIVERSIFIER_LEN..].iter().any(|b| *b != 0) {
        return None;
    }
    let mut d = [0u8; DIVERSIFIER_LEN];
    d.copy_from_slice(&bytes[..DIVERSIFIER_LEN]);
    Some(d)
}

/// The `x` coordinate candidate for a diversifier.
pub fn diversify_x(d: &[u8; DIVERSIFIER_LEN]) -> Fp {
    hash(t_div(), &[diversifier_to_fp(d)])
}

/// Given `x`, the even `y` with `(x, y)` on Pallas, if any.
pub fn even_y_for_x(x: &Fp) -> Option<Fp> {
    let y2 = x.square() * x + Fp::from(5);
    let y: Fp = Option::from(y2.sqrt())?;
    Some(if bool::from(y.is_odd()) { -y } else { y })
}

/// `DiversifyHash(d)`, or `None` if `d` is invalid (≈ 50 % of diversifiers).
pub fn diversify_hash(d: &[u8; DIVERSIFIER_LEN]) -> Option<Affine> {
    let x = diversify_x(d);
    let y = even_y_for_x(&x)?;
    Option::from(Affine::from_xy(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::prime::PrimeCurveAffine;
    use pasta_curves::arithmetic::CurveAffine;

    #[test]
    fn output_is_on_the_curve_even_and_roughly_half_valid() {
        let mut valid = 0;
        for i in 0u64..200 {
            let mut d = [0u8; DIVERSIFIER_LEN];
            d[..8].copy_from_slice(&i.to_le_bytes());
            if let Some(p) = diversify_hash(&d) {
                valid += 1;
                assert!(bool::from(p.is_on_curve()));
                assert!(!bool::from(p.is_identity()));
                let y = *p.coordinates().unwrap().y();
                assert!(!bool::from(y.is_odd()));
            }
        }
        assert!((60..140).contains(&valid), "valid = {valid}");
    }

    #[test]
    fn diversifier_field_round_trip() {
        let d = [0xabu8; DIVERSIFIER_LEN];
        assert_eq!(diversifier_from_fp(&diversifier_to_fp(&d)), Some(d));
        assert_eq!(diversifier_from_fp(&Fp::from_u128(1u128 << 90)), None);
    }
}
