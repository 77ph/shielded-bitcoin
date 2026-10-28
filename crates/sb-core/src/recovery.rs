//! Sender-recovery channel `ct_out` (paper §12.2, §16.2; profile §7.3).
//!
//! ChaCha20-Poly1305 is not key-committing on its own; the profile makes it
//! so with the padding fix: the plaintext starts with 32 zero bytes that the
//! decryptor verifies, so one ciphertext cannot open under two keys (§A.1).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use sb_primitives::encoding::{point_from_bytes, point_to_bytes};
use sb_primitives::scalar::{scalar_from_bytes, scalar_to_bytes};
use sb_primitives::{JubjubAffine, JubjubScalar};

use crate::keys::OutgoingViewingKey;
use crate::note::NoteCiphertext;

/// Number of outputs per transfer (profile §7).
pub const N_OUT: usize = 2;
/// `(pk_d, sk_eph)` per output.
pub const ENTRY_LEN: usize = 64;
/// Zero prefix that makes the AEAD key-committing (padding fix).
pub const COMMIT_PAD_LEN: usize = 32;
/// `COMMIT_PAD_LEN + N_OUT * ENTRY_LEN + 16` (Poly1305 tag).
pub const CT_OUT_LEN: usize = COMMIT_PAD_LEN + N_OUT * ENTRY_LEN + 16;

/// One recovery record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecoveryEntry {
    pub pk_d: JubjubAffine,
    pub sk_eph: JubjubScalar,
}

/// `digest = SHA-256(M ‖ pk_eph_0 ‖ … ‖ ct_note_0 ‖ …)`.
pub fn binding_digest(pk_eph: &[JubjubAffine; N_OUT], ct: &[NoteCiphertext; N_OUT]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([N_OUT as u8]);
    for p in pk_eph {
        h.update(point_to_bytes(p));
    }
    for c in ct {
        h.update(c.to_bytes());
    }
    h.finalize().into()
}

fn key_nonce(ovk: &OutgoingViewingKey, digest: &[u8; 32]) -> (Key, Nonce) {
    let hk = Hkdf::<Sha256>::new(Some(digest), &ovk.0);
    let mut key = [0u8; 32];
    hk.expand(b"sb/v1/ctout/key", &mut key).unwrap();
    let mut nonce = [0u8; 12];
    hk.expand(b"sb/v1/ctout/nonce", &mut nonce).unwrap();
    (key.into(), nonce.into())
}

/// Encrypt the ordered recovery entries; `digest` is the AEAD associated data.
pub fn encrypt_recovery(
    ovk: &OutgoingViewingKey,
    digest: &[u8; 32],
    entries: &[RecoveryEntry; N_OUT],
) -> [u8; CT_OUT_LEN] {
    let mut pt = vec![0u8; COMMIT_PAD_LEN];
    for e in entries {
        pt.extend_from_slice(&point_to_bytes(&e.pk_d));
        pt.extend_from_slice(&scalar_to_bytes(&e.sk_eph));
    }
    let (key, nonce) = key_nonce(ovk, digest);
    let ct = ChaCha20Poly1305::new(&key)
        .encrypt(
            &nonce,
            Payload {
                msg: &pt,
                aad: digest,
            },
        )
        .expect("encryption cannot fail");
    let mut out = [0u8; CT_OUT_LEN];
    out.copy_from_slice(&ct);
    out
}

/// Decrypt `ct_out`; `None` if the tag fails, the key-commitment prefix is
/// not all zero, or an entry does not decode.
pub fn decrypt_recovery(
    ovk: &OutgoingViewingKey,
    digest: &[u8; 32],
    ct_out: &[u8; CT_OUT_LEN],
) -> Option<[RecoveryEntry; N_OUT]> {
    let (key, nonce) = key_nonce(ovk, digest);
    let pt = ChaCha20Poly1305::new(&key)
        .decrypt(
            &nonce,
            Payload {
                msg: ct_out,
                aad: digest,
            },
        )
        .ok()?;
    let mut out = [RecoveryEntry {
        pk_d: JubjubAffine::default(),
        sk_eph: JubjubScalar::default(),
    }; N_OUT];
    if pt.len() != COMMIT_PAD_LEN + N_OUT * ENTRY_LEN
        || pt[..COMMIT_PAD_LEN].iter().any(|b| *b != 0)
    {
        return None;
    }
    for (i, chunk) in pt[COMMIT_PAD_LEN..].chunks(ENTRY_LEN).enumerate() {
        out[i] = RecoveryEntry {
            pk_d: point_from_bytes(&chunk[..32]).ok()?,
            sk_eph: scalar_from_bytes(&chunk[32..]).ok()?,
        };
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Seed, WalletKeys};
    use crate::note::{NotePlaintext, encrypt_note};
    use ark_ff::UniformRand;
    use ark_std::rand::{SeedableRng, rngs::StdRng};
    use sb_primitives::Fr;

    #[test]
    fn recovery_round_trip_and_binding() {
        let mut rng = StdRng::seed_from_u64(21);
        let alice = WalletKeys::from_seed(&Seed([10u8; 32]));
        let bob = WalletKeys::from_seed(&Seed([11u8; 32]));
        let (_, to_bob) = bob.ivk.find_address(0);
        let (_, change) = alice.ivk.find_address(0);
        let pts = [
            NotePlaintext {
                value: 10,
                d: to_bob.d,
                rseed: Fr::rand(&mut rng),
            },
            NotePlaintext {
                value: 5,
                d: change.d,
                rseed: Fr::rand(&mut rng),
            },
        ];
        let pk_ds = [to_bob.pk_d, change.pk_d];
        let mut pk_eph = [JubjubAffine::default(); 2];
        let mut cts = [NoteCiphertext {
            c0: Fr::from(0u64),
            c1: Fr::from(0u64),
            tag: Fr::from(0u64),
        }; 2];
        for j in 0..2 {
            (pk_eph[j], cts[j]) = encrypt_note(&pts[j], &pk_ds[j]).unwrap();
        }
        let entries = [
            RecoveryEntry {
                pk_d: pk_ds[0],
                sk_eph: pts[0].sk_eph(),
            },
            RecoveryEntry {
                pk_d: pk_ds[1],
                sk_eph: pts[1].sk_eph(),
            },
        ];
        let digest = binding_digest(&pk_eph, &cts);
        let ct_out = encrypt_recovery(&alice.ovk, &digest, &entries);
        assert_eq!(
            decrypt_recovery(&alice.ovk, &digest, &ct_out),
            Some(entries)
        );
        assert_eq!(decrypt_recovery(&bob.ovk, &digest, &ct_out), None);
        let mut other = digest;
        other[0] ^= 1;
        assert_eq!(decrypt_recovery(&alice.ovk, &other, &ct_out), None);
        // sender recovery decrypts the recipient ciphertexts
        for j in 0..2 {
            let pt = crate::note::decrypt_as_sender(
                &entries[j].sk_eph,
                &entries[j].pk_d,
                &pk_eph[j],
                &cts[j],
            )
            .unwrap();
            assert_eq!(pt, pts[j]);
        }
    }
}
