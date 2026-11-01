//! Notes: plaintext, per-note derivations, recipient-channel encryption,
//! leaves and nullifiers (paper §5, §9, §12.1; PROFILE-A.md §5).

use ff::PrimeField;
use group::Curve;
use group::prime::PrimeCurveAffine;

pub use sba_primitives::diversify::DIVERSIFIER_LEN;
use sba_primitives::diversify::{diversifier_to_fp, diversify_hash};
use sba_primitives::encoding::{DecodeError, fp_from_bytes, fp_to_bytes};
use sba_primitives::poseidon::hash;
use sba_primitives::scalar::scalar_from_fp;
use sba_primitives::tags::{t_eph, t_kdf, t_leaf, t_mac, t_nf, t_rho, t_stream};
use sba_primitives::{Affine, Fp, Scalar};

use crate::xy;

/// `pt_note = (v, d, rseed)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotePlaintext {
    pub value: u64,
    pub d: [u8; DIVERSIFIER_LEN],
    pub rseed: Fp,
}

impl NotePlaintext {
    /// `rho = PH_A(T_RHO, rseed)`.
    pub fn rho(&self) -> Fp {
        hash(t_rho(), &[self.rseed])
    }

    /// `sk_eph = PH_A(T_EPH, rseed)` as a Pallas scalar.
    pub fn sk_eph(&self) -> Scalar {
        scalar_from_fp(&hash(t_eph(), &[self.rseed]))
    }

    /// `G_d = DiversifyHash(d)`.
    pub fn g_d(&self) -> Option<Affine> {
        diversify_hash(&self.d)
    }

    /// `pk_eph = [sk_eph] G_d`.
    pub fn pk_eph(&self) -> Option<Affine> {
        Some((self.g_d()?.to_curve() * self.sk_eph()).to_affine())
    }

    /// `m_0 = v + 2^64 · LE_int(d)`.
    pub fn m0(&self) -> Fp {
        Fp::from(self.value) + Fp::from_u128(1u128 << 64) * diversifier_to_fp(&self.d)
    }

    /// Inverse of [`Self::m0`]; `None` if the element does not fit 152 bits.
    pub fn unpack_m0(m0: &Fp) -> Option<(u64, [u8; DIVERSIFIER_LEN])> {
        let bytes = m0.to_repr();
        if bytes[8 + DIVERSIFIER_LEN..].iter().any(|b| *b != 0) {
            return None;
        }
        let value = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let mut d = [0u8; DIVERSIFIER_LEN];
        d.copy_from_slice(&bytes[8..8 + DIVERSIFIER_LEN]);
        Some((value, d))
    }

    /// `(m_0, m_1)`.
    pub fn to_elements(&self) -> [Fp; 2] {
        [self.m0(), self.rseed]
    }

    pub fn from_elements(m0: &Fp, m1: &Fp) -> Option<Self> {
        let (value, d) = Self::unpack_m0(m0)?;
        Some(NotePlaintext {
            value,
            d,
            rseed: *m1,
        })
    }
}

/// `ct_note = c_0 ‖ c_1 ‖ tag`, 96 bytes on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NoteCiphertext {
    pub c0: Fp,
    pub c1: Fp,
    pub tag: Fp,
}

pub const CT_NOTE_LEN: usize = 96;

impl NoteCiphertext {
    pub fn to_bytes(&self) -> [u8; CT_NOTE_LEN] {
        let mut out = [0u8; CT_NOTE_LEN];
        out[..32].copy_from_slice(&fp_to_bytes(&self.c0));
        out[32..64].copy_from_slice(&fp_to_bytes(&self.c1));
        out[64..].copy_from_slice(&fp_to_bytes(&self.tag));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != CT_NOTE_LEN {
            return Err(DecodeError::Length {
                expected: CT_NOTE_LEN,
                got: bytes.len(),
            });
        }
        Ok(NoteCiphertext {
            c0: fp_from_bytes(&bytes[..32])?,
            c1: fp_from_bytes(&bytes[32..64])?,
            tag: fp_from_bytes(&bytes[64..])?,
        })
    }

    pub fn elements(&self) -> [Fp; 3] {
        [self.c0, self.c1, self.tag]
    }
}

/// `k = PH_A(T_KDF, ss.x, ss.y, pk_eph.x, pk_eph.y)`.
pub fn note_key(ss: &Affine, pk_eph: &Affine) -> Fp {
    let (sx, sy) = xy(ss);
    let (ex, ey) = xy(pk_eph);
    hash(t_kdf(), &[sx, sy, ex, ey])
}

/// Encrypt `(m_0, m_1)` under `k`.
pub fn encrypt_with_key(k: &Fp, m: &[Fp; 2]) -> NoteCiphertext {
    let c0 = m[0] + hash(t_stream(), &[*k, Fp::zero()]);
    let c1 = m[1] + hash(t_stream(), &[*k, Fp::one()]);
    let tag = hash(t_mac(), &[*k, c0, c1]);
    NoteCiphertext { c0, c1, tag }
}

/// Decrypt under `k`; `None` if the tag does not verify.
pub fn decrypt_with_key(k: &Fp, ct: &NoteCiphertext) -> Option<[Fp; 2]> {
    if hash(t_mac(), &[*k, ct.c0, ct.c1]) != ct.tag {
        return None;
    }
    let m0 = ct.c0 - hash(t_stream(), &[*k, Fp::zero()]);
    let m1 = ct.c1 - hash(t_stream(), &[*k, Fp::one()]);
    Some([m0, m1])
}

/// Sender side: `pk_eph = [sk_eph] G_d`, `ss = [sk_eph] pk_d`, encrypt.
/// `None` if `d` is invalid.
pub fn encrypt_note(pt: &NotePlaintext, pk_d: &Affine) -> Option<(Affine, NoteCiphertext)> {
    let sk_eph = pt.sk_eph();
    let pk_eph = (pt.g_d()?.to_curve() * sk_eph).to_affine();
    let ss = (pk_d.to_curve() * sk_eph).to_affine();
    let k = note_key(&ss, &pk_eph);
    Some((pk_eph, encrypt_with_key(&k, &pt.to_elements())))
}

/// Recipient side: `ss = [sk_view] pk_eph`.
pub fn decrypt_as_recipient(
    sk_view: &Scalar,
    pk_eph: &Affine,
    ct: &NoteCiphertext,
) -> Option<NotePlaintext> {
    let ss = (pk_eph.to_curve() * sk_view).to_affine();
    let m = decrypt_with_key(&note_key(&ss, pk_eph), ct)?;
    NotePlaintext::from_elements(&m[0], &m[1])
}

/// Sender recovery: `ss = [sk_eph] pk_d` with `(pk_d, sk_eph)` from `ct_out`.
pub fn decrypt_as_sender(
    sk_eph: &Scalar,
    pk_d: &Affine,
    pk_eph: &Affine,
    ct: &NoteCiphertext,
) -> Option<NotePlaintext> {
    let ss = (pk_d.to_curve() * sk_eph).to_affine();
    let m = decrypt_with_key(&note_key(&ss, pk_eph), ct)?;
    NotePlaintext::from_elements(&m[0], &m[1])
}

/// Paper §16.1: `pk_eph == [sk_eph(rseed)] DiversifyHash(d)`.
pub fn check_note_consistency(pt: &NotePlaintext, pk_eph: &Affine) -> bool {
    pt.pk_eph().as_ref() == Some(pk_eph)
}

/// `leaf = PH_A(T_LEAF, const_salt, h_body, j, pk_eph.x, pk_eph.y, c_0, c_1, tag, h_aux)` with `h_aux = 0`.
pub fn note_leaf(const_salt: &Fp, h_body: &Fp, j: u64, pk_eph: &Affine, ct: &NoteCiphertext) -> Fp {
    let (ex, ey) = xy(pk_eph);
    hash(
        t_leaf(),
        &[
            *const_salt,
            *h_body,
            Fp::from(j),
            ex,
            ey,
            ct.c0,
            ct.c1,
            ct.tag,
            Fp::zero(),
        ],
    )
}

/// `nf = PH_A(T_NF, sk_nf, rho, pos)`.
pub fn nullifier(sk_nf: &Fp, rho: &Fp, pos: u64) -> Fp {
    hash(t_nf(), &[*sk_nf, *rho, Fp::from(pos)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Seed, WalletKeys};
    use ff::Field;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn sample() -> (WalletKeys, NotePlaintext) {
        let mut rng = StdRng::seed_from_u64(9);
        let k = WalletKeys::from_seed(&Seed([5u8; 32]));
        let (_, addr) = k.ivk.find_address(0);
        let pt = NotePlaintext {
            value: 123_456,
            d: addr.d,
            rseed: Fp::random(&mut rng),
        };
        (k, pt)
    }

    #[test]
    fn m0_packing_round_trip() {
        let (_, pt) = sample();
        assert_eq!(NotePlaintext::unpack_m0(&pt.m0()), Some((pt.value, pt.d)));
        assert_eq!(
            NotePlaintext::unpack_m0(&(Fp::from_u128(1u128 << 100) * Fp::from_u128(1u128 << 100))),
            None
        );
    }

    #[test]
    fn recipient_and_sender_decrypt_what_was_encrypted() {
        let (k, pt) = sample();
        let addr = k.ivk.address_for(pt.d).unwrap();
        let (pk_eph, ct) = encrypt_note(&pt, &addr.pk_d).unwrap();
        assert_eq!(decrypt_as_recipient(&k.ivk.sk_view, &pk_eph, &ct), Some(pt));
        assert_eq!(
            decrypt_as_sender(&pt.sk_eph(), &addr.pk_d, &pk_eph, &ct),
            Some(pt)
        );
        assert!(check_note_consistency(&pt, &pk_eph));
        let other = WalletKeys::from_seed(&Seed([6u8; 32]));
        assert_eq!(decrypt_as_recipient(&other.ivk.sk_view, &pk_eph, &ct), None);
        let mut bad = ct;
        bad.c0 += Fp::one();
        assert_eq!(decrypt_as_recipient(&k.ivk.sk_view, &pk_eph, &bad), None);
        assert_eq!(NoteCiphertext::from_bytes(&ct.to_bytes()).unwrap(), ct);
        assert!(NoteCiphertext::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn leaf_and_nullifier_depend_on_every_input() {
        let (k, pt) = sample();
        let addr = k.ivk.address_for(pt.d).unwrap();
        let (pk_eph, ct) = encrypt_note(&pt, &addr.pk_d).unwrap();
        let salt = Fp::from(42u64);
        let hb = Fp::from(43u64);
        let l = note_leaf(&salt, &hb, 0, &pk_eph, &ct);
        assert_ne!(l, note_leaf(&salt, &hb, 1, &pk_eph, &ct));
        assert_ne!(l, note_leaf(&salt, &Fp::from(44u64), 0, &pk_eph, &ct));
        assert_ne!(l, note_leaf(&Fp::one(), &hb, 0, &pk_eph, &ct));
        let nf = nullifier(&k.sk_nf, &pt.rho(), 5);
        assert_ne!(nf, nullifier(&k.sk_nf, &pt.rho(), 6));
        assert_ne!(nf, nullifier(&Fp::one(), &pt.rho(), 5));
    }
}
