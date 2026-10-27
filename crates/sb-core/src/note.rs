//! Notes: plaintext, per-note derivations, recipient-channel encryption,
//! leaves and nullifiers (paper §5, §9, §12.1; profile §5).

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};

pub use sb_primitives::diversify::DIVERSIFIER_LEN;
use sb_primitives::diversify::{diversifier_to_fr, diversify_hash};
use sb_primitives::encoding::{DecodeError, fr_from_bytes, fr_to_bytes};
use sb_primitives::poseidon::hash;
use sb_primitives::scalar::scalar250;
use sb_primitives::tags::{t_eph, t_kdf, t_leaf, t_mac, t_nf, t_rho, t_stream};
use sb_primitives::{Fr, JubjubAffine, JubjubScalar};

/// `pt_note = (v, d, rseed)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotePlaintext {
    pub value: u64,
    pub d: [u8; DIVERSIFIER_LEN],
    pub rseed: Fr,
}

impl NotePlaintext {
    /// `rho = PH(T_RHO, rseed)`.
    pub fn rho(&self) -> Fr {
        hash(t_rho(), &[self.rseed])
    }

    /// `sk_eph = Scalar250(PH(T_EPH, rseed))`.
    pub fn sk_eph(&self) -> JubjubScalar {
        scalar250(&hash(t_eph(), &[self.rseed]))
    }

    /// `G_d = DiversifyHash(d)`.
    pub fn g_d(&self) -> Option<JubjubAffine> {
        diversify_hash(&self.d)
    }

    /// `pk_eph = [sk_eph] G_d`.
    pub fn pk_eph(&self) -> Option<JubjubAffine> {
        Some((self.g_d()?.into_group() * self.sk_eph()).into_affine())
    }

    /// `m_0 = v + 2^64 · LE_int(d)`.
    pub fn m0(&self) -> Fr {
        Fr::from(self.value) + Fr::from(1u128 << 64) * diversifier_to_fr(&self.d)
    }

    /// Inverse of [`Self::m0`]; `None` if the element does not fit 152 bits.
    pub fn unpack_m0(m0: &Fr) -> Option<(u64, [u8; DIVERSIFIER_LEN])> {
        let bytes = m0.into_bigint().to_bytes_le();
        if bytes[8 + DIVERSIFIER_LEN..].iter().any(|b| *b != 0) {
            return None;
        }
        let value = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let mut d = [0u8; DIVERSIFIER_LEN];
        d.copy_from_slice(&bytes[8..8 + DIVERSIFIER_LEN]);
        Some((value, d))
    }

    /// `(m_0, m_1)`.
    pub fn to_elements(&self) -> [Fr; 2] {
        [self.m0(), self.rseed]
    }

    pub fn from_elements(m0: &Fr, m1: &Fr) -> Option<Self> {
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
    pub c0: Fr,
    pub c1: Fr,
    pub tag: Fr,
}

pub const CT_NOTE_LEN: usize = 96;

impl NoteCiphertext {
    pub fn to_bytes(&self) -> [u8; CT_NOTE_LEN] {
        let mut out = [0u8; CT_NOTE_LEN];
        out[..32].copy_from_slice(&fr_to_bytes(&self.c0));
        out[32..64].copy_from_slice(&fr_to_bytes(&self.c1));
        out[64..].copy_from_slice(&fr_to_bytes(&self.tag));
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
            c0: fr_from_bytes(&bytes[..32])?,
            c1: fr_from_bytes(&bytes[32..64])?,
            tag: fr_from_bytes(&bytes[64..])?,
        })
    }

    pub fn elements(&self) -> [Fr; 3] {
        [self.c0, self.c1, self.tag]
    }
}

/// `k = PH(T_KDF, ss.x, ss.y, pk_eph.x, pk_eph.y)`.
pub fn note_key(ss: &JubjubAffine, pk_eph: &JubjubAffine) -> Fr {
    hash(t_kdf(), &[ss.x, ss.y, pk_eph.x, pk_eph.y])
}

/// Encrypt `(m_0, m_1)` under `k`.
pub fn encrypt_with_key(k: &Fr, m: &[Fr; 2]) -> NoteCiphertext {
    let c0 = m[0] + hash(t_stream(), &[*k, Fr::from(0u64)]);
    let c1 = m[1] + hash(t_stream(), &[*k, Fr::from(1u64)]);
    let tag = hash(t_mac(), &[*k, c0, c1]);
    NoteCiphertext { c0, c1, tag }
}

/// Decrypt under `k`; `None` if the tag does not verify.
pub fn decrypt_with_key(k: &Fr, ct: &NoteCiphertext) -> Option<[Fr; 2]> {
    if hash(t_mac(), &[*k, ct.c0, ct.c1]) != ct.tag {
        return None;
    }
    let m0 = ct.c0 - hash(t_stream(), &[*k, Fr::from(0u64)]);
    let m1 = ct.c1 - hash(t_stream(), &[*k, Fr::from(1u64)]);
    Some([m0, m1])
}

/// Sender side: `pk_eph = [sk_eph] G_d`, `ss = [sk_eph] pk_d`, encrypt.
/// `None` if `d` is invalid.
pub fn encrypt_note(
    pt: &NotePlaintext,
    pk_d: &JubjubAffine,
) -> Option<(JubjubAffine, NoteCiphertext)> {
    let sk_eph = pt.sk_eph();
    let pk_eph = (pt.g_d()?.into_group() * sk_eph).into_affine();
    let ss = (pk_d.into_group() * sk_eph).into_affine();
    let k = note_key(&ss, &pk_eph);
    Some((pk_eph, encrypt_with_key(&k, &pt.to_elements())))
}

/// Recipient side: `ss = [sk_view] pk_eph`. Returns the plaintext if the tag
/// verifies and the plaintext unpacks. The §16.1 checks are
/// [`check_note_consistency`] plus the wallet's leaf and address checks.
pub fn decrypt_as_recipient(
    sk_view: &JubjubScalar,
    pk_eph: &JubjubAffine,
    ct: &NoteCiphertext,
) -> Option<NotePlaintext> {
    let ss = (pk_eph.into_group() * sk_view).into_affine();
    let m = decrypt_with_key(&note_key(&ss, pk_eph), ct)?;
    NotePlaintext::from_elements(&m[0], &m[1])
}

/// Sender recovery: `ss = [sk_eph] pk_d` with `(pk_d, sk_eph)` from `ct_out`.
pub fn decrypt_as_sender(
    sk_eph: &JubjubScalar,
    pk_d: &JubjubAffine,
    pk_eph: &JubjubAffine,
    ct: &NoteCiphertext,
) -> Option<NotePlaintext> {
    let ss = (pk_d.into_group() * sk_eph).into_affine();
    let m = decrypt_with_key(&note_key(&ss, pk_eph), ct)?;
    NotePlaintext::from_elements(&m[0], &m[1])
}

/// Paper §16.1: `pk_eph == [sk_eph(rseed)] DiversifyHash(d)`.
pub fn check_note_consistency(pt: &NotePlaintext, pk_eph: &JubjubAffine) -> bool {
    pt.pk_eph().as_ref() == Some(pk_eph)
}

/// `leaf = PH(T_LEAF, const_salt, h_body, j, pk_eph.x, pk_eph.y, c_0, c_1, tag, h_aux)` with `h_aux = 0`.
pub fn note_leaf(
    const_salt: &Fr,
    h_body: &Fr,
    j: u64,
    pk_eph: &JubjubAffine,
    ct: &NoteCiphertext,
) -> Fr {
    hash(
        t_leaf(),
        &[
            *const_salt,
            *h_body,
            Fr::from(j),
            pk_eph.x,
            pk_eph.y,
            ct.c0,
            ct.c1,
            ct.tag,
            Fr::from(0u64),
        ],
    )
}

/// `nf = PH(T_NF, sk_nf, rho, pos)`.
pub fn nullifier(sk_nf: &Fr, rho: &Fr, pos: u64) -> Fr {
    hash(t_nf(), &[*sk_nf, *rho, Fr::from(pos)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Seed, WalletKeys};
    use ark_ff::UniformRand;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    fn sample() -> (WalletKeys, NotePlaintext) {
        let mut rng = StdRng::seed_from_u64(9);
        let k = WalletKeys::from_seed(&Seed([5u8; 32]));
        let (_, addr) = k.ivk.find_address(0);
        let pt = NotePlaintext {
            value: 123_456,
            d: addr.d,
            rseed: Fr::rand(&mut rng),
        };
        (k, pt)
    }

    #[test]
    fn m0_packing_round_trip() {
        let (_, pt) = sample();
        assert_eq!(NotePlaintext::unpack_m0(&pt.m0()), Some((pt.value, pt.d)));
        assert_eq!(
            NotePlaintext::unpack_m0(&(Fr::from(1u128 << 100) * Fr::from(1u128 << 100))),
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
        // wrong recipient
        let other = WalletKeys::from_seed(&Seed([6u8; 32]));
        assert_eq!(decrypt_as_recipient(&other.ivk.sk_view, &pk_eph, &ct), None);
        // tampered ciphertext
        let mut bad = ct;
        bad.c0 += Fr::from(1u64);
        assert_eq!(decrypt_as_recipient(&k.ivk.sk_view, &pk_eph, &bad), None);
        // wire round trip
        assert_eq!(NoteCiphertext::from_bytes(&ct.to_bytes()).unwrap(), ct);
    }

    #[test]
    fn leaf_and_nullifier_depend_on_every_input() {
        let (k, pt) = sample();
        let addr = k.ivk.address_for(pt.d).unwrap();
        let (pk_eph, ct) = encrypt_note(&pt, &addr.pk_d).unwrap();
        let salt = Fr::from(42u64);
        let hb = Fr::from(43u64);
        let l = note_leaf(&salt, &hb, 0, &pk_eph, &ct);
        assert_ne!(l, note_leaf(&salt, &hb, 1, &pk_eph, &ct));
        assert_ne!(l, note_leaf(&salt, &Fr::from(44u64), 0, &pk_eph, &ct));
        assert_ne!(l, note_leaf(&Fr::from(1u64), &hb, 0, &pk_eph, &ct));
        let nf = nullifier(&k.sk_nf, &pt.rho(), 5);
        assert_ne!(nf, nullifier(&k.sk_nf, &pt.rho(), 6));
        assert_ne!(nf, nullifier(&Fr::from(1u64), &pt.rho(), 5));
    }
}
