//! Jubjub scalar helpers: `Scalar250`, canonical scalar bytes, and the
//! embedding of a scalar into `Fr` (profile §2.1, §3).

use ark_ff::{BigInteger, PrimeField};

use crate::encoding::DecodeError;
use crate::{Fr, JubjubScalar};

/// `Scalar250(f)`: the integer formed by the low 250 bits of the canonical LE
/// encoding of `f`, as a Jubjub scalar. `2^250 < r_J`, so no reduction occurs.
pub fn scalar250(f: &Fr) -> JubjubScalar {
    let mut b = f.into_bigint().to_bytes_le();
    b[31] &= 0x03;
    JubjubScalar::from_le_bytes_mod_order(&b)
}

/// The 250 bits used by [`scalar250`], least significant first (for the
/// in-circuit scalar multiplication, which consumes the same bits).
pub fn scalar250_bits(f: &Fr) -> Vec<bool> {
    f.into_bigint().to_bits_le().into_iter().take(250).collect()
}

/// Canonical 32-byte LE encoding of a Jubjub scalar (`BytesFromScalar`).
pub fn scalar_to_bytes(s: &JubjubScalar) -> [u8; 32] {
    let v = s.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Decode a canonical Jubjub scalar (`< r_J`).
pub fn scalar_from_bytes(bytes: &[u8]) -> Result<JubjubScalar, DecodeError> {
    if bytes.len() != 32 {
        return Err(DecodeError::Length {
            expected: 32,
            got: bytes.len(),
        });
    }
    let s = JubjubScalar::from_le_bytes_mod_order(bytes);
    if scalar_to_bytes(&s)[..] != bytes[..] {
        return Err(DecodeError::NonCanonicalField);
    }
    Ok(s)
}

/// `LE_int(bytes) mod r_J` for a 64-byte wide input (uniform scalar).
pub fn scalar_from_wide_bytes(bytes: &[u8; 64]) -> JubjubScalar {
    JubjubScalar::from_le_bytes_mod_order(bytes)
}

/// Embed a Jubjub scalar into `Fr` (`r_J < q`, so this is injective).
pub fn scalar_to_fr(s: &JubjubScalar) -> Fr {
    Fr::from_le_bytes_mod_order(&scalar_to_bytes(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, UniformRand};
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn scalar250_is_below_2_250_and_matches_bits() {
        let mut rng = StdRng::seed_from_u64(5);
        for _ in 0..50 {
            let f = Fr::rand(&mut rng);
            let s = scalar250(&f);
            let bits = scalar250_bits(&f);
            let mut acc = JubjubScalar::from(0u64);
            let mut pow = JubjubScalar::from(1u64);
            for b in &bits {
                if *b {
                    acc += pow;
                }
                pow.double_in_place();
            }
            assert_eq!(acc, s);
            assert!(scalar_to_bytes(&s)[31] <= 0x03);
        }
    }

    #[test]
    fn scalar_round_trip() {
        let mut rng = StdRng::seed_from_u64(6);
        for _ in 0..50 {
            let s = JubjubScalar::rand(&mut rng);
            assert_eq!(scalar_from_bytes(&scalar_to_bytes(&s)).unwrap(), s);
            let f = scalar_to_fr(&s);
            assert_eq!(crate::encoding::fr_to_bytes(&f), scalar_to_bytes(&s));
        }
        let r = JubjubScalar::MODULUS.to_bytes_le();
        assert_eq!(scalar_from_bytes(&r), Err(DecodeError::NonCanonicalField));
    }
}
