//! Fee-vault authorizations (`docs/FEE-VAULT.md` §2–§3): the client's
//! BIP 340 key, the draw and reclaim messages and their signatures. The
//! commitment that ties a key to a deposit note is `sb_core::feeauth`.

use anyhow::{Context, Result, anyhow};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use sb_core::keys::WalletKeys;
use sb_primitives::Fr;
use sb_primitives::encoding::fr_to_bytes;

pub const DRAW_TAG: &str = "sb/v1/feeauth/draw";
pub const RECLAIM_TAG: &str = "sb/v1/feeauth/reclaim";

/// BIP 340 tagged hash: `SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ msg)`.
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(msg);
    h.finalize().into()
}

fn push_len16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The draw message (§3): deployment, `h_body`, `max_fee`, memo.
pub fn draw_message(deployment: &str, h_body: &Fr, max_fee: u64, memo: Option<&[u8]>) -> [u8; 32] {
    let mut m = Vec::new();
    push_len16(&mut m, deployment.as_bytes());
    m.extend_from_slice(&fr_to_bytes(h_body));
    m.extend_from_slice(&max_fee.to_le_bytes());
    push_len16(&mut m, memo.unwrap_or(&[]));
    tagged_hash(DRAW_TAG, &m)
}

/// The reclaim message (§3): deployment, the address to pay, the total
/// the client believes it deposited under the key.
pub fn reclaim_message(deployment: &str, address: &str, deposited: u64) -> [u8; 32] {
    let mut m = Vec::new();
    push_len16(&mut m, deployment.as_bytes());
    push_len16(&mut m, address.as_bytes());
    m.extend_from_slice(&deposited.to_le_bytes());
    tagged_hash(RECLAIM_TAG, &m)
}

/// The client's authorization key at a derivation index (§2).
pub struct AuthKey {
    keypair: Keypair,
}

impl AuthKey {
    pub fn derive(keys: &WalletKeys, index: u64) -> Result<Self> {
        let sk = SecretKey::from_slice(&keys.fee_auth_secret(index))
            .map_err(|_| anyhow!("fee-auth key {index} is out of range; use the next index"))?;
        Ok(AuthKey {
            keypair: Keypair::from_secret_key(&Secp256k1::new(), &sk),
        })
    }

    /// `P`, the x-only public key.
    pub fn public(&self) -> [u8; 32] {
        self.keypair.x_only_public_key().0.serialize()
    }

    pub fn sign(&self, msg: &[u8; 32]) -> [u8; 64] {
        Secp256k1::new()
            .sign_schnorr(&Message::from_digest(*msg), &self.keypair)
            .serialize()
    }
}

/// Verify a BIP 340 signature under the x-only key `key`.
pub fn verify(key: &[u8; 32], msg: &[u8; 32], sig: &[u8]) -> Result<()> {
    let pk = XOnlyPublicKey::from_slice(key).context("bad key")?;
    let sig = Signature::from_slice(sig).context("bad signature encoding")?;
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(*msg), &pk)
        .map_err(|_| anyhow!("bad signature"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_core::keys::Seed;

    #[test]
    fn messages_bind_every_field_and_signatures_verify_under_the_key_only() {
        let keys = WalletKeys::from_seed(&Seed([9u8; 32]));
        let k0 = AuthKey::derive(&keys, 0).unwrap();
        let k1 = AuthKey::derive(&keys, 1).unwrap();
        assert_ne!(k0.public(), k1.public());
        assert_eq!(k0.public(), AuthKey::derive(&keys, 0).unwrap().public());
        let hb = Fr::from(77u64);
        let m = draw_message("e2e", &hb, 1000, None);
        assert_ne!(m, draw_message("e2f", &hb, 1000, None));
        assert_ne!(m, draw_message("e2e", &Fr::from(78u64), 1000, None));
        assert_ne!(m, draw_message("e2e", &hb, 1001, None));
        assert_ne!(m, draw_message("e2e", &hb, 1000, Some(b"sbx")));
        assert_ne!(m, reclaim_message("e2e", "addr", 1000));
        let r = reclaim_message("e2e", "addr", 1000);
        assert_ne!(r, reclaim_message("e2e", "addr", 1001));
        assert_ne!(r, reclaim_message("e2e", "addq", 1000));
        let sig = k0.sign(&m);
        verify(&k0.public(), &m, &sig).unwrap();
        assert!(verify(&k1.public(), &m, &sig).is_err());
        assert!(verify(&k0.public(), &r, &sig).is_err());
        assert!(verify(&k0.public(), &m, &sig[..63]).is_err());
        assert!(verify(&[0u8; 32], &m, &sig).is_err());
        // BIP 340 tagged hash, checked against the definition
        let t: [u8; 32] = Sha256::digest(b"x").into();
        let mut h = Sha256::new();
        h.update(t);
        h.update(t);
        h.update(b"y");
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(tagged_hash("x", b"y"), want);
    }
}
