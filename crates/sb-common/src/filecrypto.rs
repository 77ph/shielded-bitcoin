//! The encrypted-file format of wallets (version 2): Argon2id (`m`, `t`,
//! `p` parameters stored with the file) derives a 32-byte key from the
//! passphrase and a random salt; the body is ChaCha20-Poly1305 under a
//! random nonce with a caller-supplied associated-data string (the
//! family's file domain). The plaintext body and its JSON layout belong
//! to the caller.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encrypted file (version 2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedFile {
    pub version: u32,
    pub kdf: String,
    pub salt: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub nonce: String,
    pub ciphertext: String,
}

pub const KDF_M_COST_KIB: u32 = 65536;
pub const KDF_T_COST: u32 = 3;
pub const KDF_P_COST: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("corrupt wallet file: {0}")]
    Corrupt(String),
    #[error("wrong passphrase")]
    WrongPassphrase,
}

/// Derived file key and the KDF parameters it came from.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileCrypto {
    key: [u8; 32],
    salt: [u8; 16],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl FileCrypto {
    pub fn derive(
        passphrase: &str,
        salt: [u8; 16],
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Self, CryptoError> {
        let params = argon2::Params::new(m_cost_kib, t_cost, p_cost, Some(32))
            .map_err(|e| CryptoError::Corrupt(format!("kdf params: {e}")))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| CryptoError::Corrupt(format!("kdf: {e}")))?;
        Ok(FileCrypto {
            key,
            salt,
            m_cost_kib,
            t_cost,
            p_cost,
        })
    }

    /// A fresh salt with the default parameters.
    pub fn fresh<R: RngCore + CryptoRng>(
        passphrase: &str,
        rng: &mut R,
    ) -> Result<Self, CryptoError> {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        Self::derive(passphrase, salt, KDF_M_COST_KIB, KDF_T_COST, KDF_P_COST)
    }

    /// Open an encrypted file: the plaintext body and the key it was under.
    pub fn open(
        f: &EncryptedFile,
        passphrase: &str,
        aad: &[u8],
    ) -> Result<(Vec<u8>, Self), CryptoError> {
        if f.kdf != "argon2id" {
            return Err(CryptoError::Corrupt(format!("unknown kdf {}", f.kdf)));
        }
        let salt: [u8; 16] = hex::decode(&f.salt)
            .map_err(|e| CryptoError::Corrupt(e.to_string()))?
            .try_into()
            .map_err(|_| CryptoError::Corrupt("salt".into()))?;
        let crypto = FileCrypto::derive(passphrase, salt, f.m_cost_kib, f.t_cost, f.p_cost)?;
        let nonce = hex::decode(&f.nonce).map_err(|e| CryptoError::Corrupt(e.to_string()))?;
        let ct = hex::decode(&f.ciphertext).map_err(|e| CryptoError::Corrupt(e.to_string()))?;
        let body = ChaCha20Poly1305::new(Key::from_slice(&crypto.key))
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad })
            .map_err(|_| CryptoError::WrongPassphrase)?;
        Ok((body, crypto))
    }

    /// Encrypt a body under this key with a fresh nonce.
    pub fn seal(&self, plain: &[u8], aad: &[u8]) -> EncryptedFile {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = ChaCha20Poly1305::new(Key::from_slice(&self.key))
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad })
            .expect("encryption cannot fail");
        EncryptedFile {
            version: 2,
            kdf: "argon2id".into(),
            salt: hex::encode(self.salt),
            m_cost_kib: self.m_cost_kib,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ct),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_wrong_passphrase_and_aad() {
        let c = FileCrypto::derive("pw", [1u8; 16], 8, 1, 1).unwrap();
        let f = c.seal(b"hello", b"aad");
        assert_eq!(f.version, 2);
        let (body, c2) = FileCrypto::open(&f, "pw", b"aad").unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(c2.salt, c.salt);
        assert!(matches!(
            FileCrypto::open(&f, "no", b"aad"),
            Err(CryptoError::WrongPassphrase)
        ));
        assert!(matches!(
            FileCrypto::open(&f, "pw", b"other"),
            Err(CryptoError::WrongPassphrase)
        ));
        let mut bad = f.clone();
        bad.kdf = "scrypt".into();
        assert!(matches!(
            FileCrypto::open(&bad, "pw", b"aad"),
            Err(CryptoError::Corrupt(_))
        ));
    }
}
