//! Hash-locks of the swap extension (`docs/SWAP.md` §1–§2): the secret,
//! its SHA-256 hash as two field elements, and the lock commitment that
//! goes into a note's `h_aux` slot.

use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

use sb_primitives::poseidon::native::hash;
use sb_primitives::tags::t_aux;
use sb_primitives::{Fr, JubjubAffine};

/// The 32-byte preimage shared by the shielded lock and the Bitcoin HTLC.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secret(pub [u8; 32]);

impl Secret {
    pub fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        Secret(s)
    }

    /// `H = SHA-256(s)`.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

/// `H` as `(H_lo, H_hi) = (LE_int(H[0..16]), LE_int(H[16..32]))`.
pub fn hash_halves(h: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from_le_bytes_mod_order(&h[..16]),
        Fr::from_le_bytes_mod_order(&h[16..]),
    )
}

/// The opening of a lock commitment: what the two parties agree on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LockOpening {
    /// `SHA-256(s)`.
    pub hash: [u8; 32],
    /// The refund party's transmission key.
    pub pk_refund: JubjubAffine,
    /// Bitcoin height from which the refund branch opens.
    pub t_refund: u32,
}

impl LockOpening {
    /// `h_aux = PH(T_AUX, H_lo, H_hi, pk_refund.x, pk_refund.y, t_refund)`.
    pub fn commitment(&self) -> Fr {
        let (lo, hi) = hash_halves(&self.hash);
        hash(
            t_aux(),
            &[
                lo,
                hi,
                self.pk_refund.x,
                self.pk_refund.y,
                Fr::from(self.t_refund as u64),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::BigInteger;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn halves_and_commitment() {
        let mut rng = StdRng::seed_from_u64(1);
        let s = Secret::random(&mut rng);
        let h = s.hash();
        assert_eq!(h, <[u8; 32]>::from(Sha256::digest(s.0)));
        let (lo, hi) = hash_halves(&h);
        let mut back = [0u8; 32];
        back[..16].copy_from_slice(&lo.into_bigint().to_bytes_le()[..16]);
        back[16..].copy_from_slice(&hi.into_bigint().to_bytes_le()[..16]);
        assert_eq!(back, h);
        let o = LockOpening {
            hash: h,
            pk_refund: JubjubAffine::generator(),
            t_refund: 100,
        };
        let c = o.commitment();
        assert_ne!(c, Fr::from(0u64));
        for other in [
            LockOpening { t_refund: 101, ..o },
            LockOpening {
                hash: Secret::random(&mut rng).hash(),
                ..o
            },
            LockOpening {
                pk_refund: (JubjubAffine::generator() + JubjubAffine::generator()).into(),
                ..o
            },
        ] {
            assert_ne!(other.commitment(), c);
        }
        assert_eq!(o.commitment(), c);
    }
}
