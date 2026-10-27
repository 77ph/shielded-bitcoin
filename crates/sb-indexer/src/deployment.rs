//! Deployment profile (profile §9): everything replay needs to agree on.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sb_circuit::{TransferParams, TransferVerifier, vk_sha256};
use sb_core::address::Network;
use sb_core::envelope::bytes_to_fr_253;
use sb_primitives::Fr;

use crate::hexbytes;

/// Where the Groth16 keys come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Setup {
    /// Deterministic **insecure** setup from a public seed (dev/test only).
    InsecureSeed {
        #[serde(with = "hexbytes")]
        seed: [u8; 32],
    },
    /// Keys produced by a ceremony; `vk_path` is relative to the profile.
    Ceremony {
        vk_path: String,
        pk_path: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    pub name: String,
    pub network: Network,
    /// First block height replay looks at.
    pub activation_height: u32,
    #[serde(with = "hexbytes")]
    pub const_salt: [u8; 32],
    #[serde(with = "hexbytes")]
    pub transfer_vk_sha256: [u8; 32],
    pub setup: Setup,
    /// `W` (profile §A.6).
    pub window_w: u32,
    /// `K_min` (profile §A.6).
    pub k_min: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("proof system: {0}")]
    Proof(#[from] sb_circuit::ProofError),
    #[error("verifying key hash mismatch: profile pins {expected}, keys give {got}")]
    VkMismatch { expected: String, got: String },
}

impl Deployment {
    /// `const_salt = SHA-256("sb/v1/const_salt/" ‖ name)` (profile §9).
    pub fn derive_const_salt(name: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"sb/v1/const_salt/");
        h.update(name.as_bytes());
        h.finalize().into()
    }

    /// The `Fr` embedding used in leaves and as a public input.
    pub fn const_salt_fr(&self) -> Fr {
        bytes_to_fr_253(&self.const_salt)
    }

    pub fn from_json(json: &str) -> Result<Self, DeploymentError> {
        Ok(serde_json::from_str(json)?)
    }

    pub fn load(path: &Path) -> Result<Self, DeploymentError> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serializable")
    }

    /// Build the full proving parameters (wallets and dev indexers) and
    /// check the pinned verifying-key hash.
    pub fn params(&self, base_dir: &Path) -> Result<TransferParams, DeploymentError> {
        let params = match &self.setup {
            Setup::InsecureSeed { seed } => TransferParams::insecure_setup(seed)?,
            Setup::Ceremony { pk_path, .. } => {
                let pk_path = pk_path.as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "profile has no proving key path",
                    )
                })?;
                TransferParams::from_pk_bytes(&std::fs::read(base_dir.join(pk_path))?)?
            }
        };
        self.check_vk(&vk_sha256(params.vk()))?;
        Ok(params)
    }

    /// Build only the verifier (indexers), checking the pinned hash.
    pub fn verifier(&self, base_dir: &Path) -> Result<TransferVerifier, DeploymentError> {
        let verifier = match &self.setup {
            Setup::InsecureSeed { seed } => {
                let params = TransferParams::insecure_setup(seed)?;
                TransferVerifier::new(params.vk().clone())
            }
            Setup::Ceremony { vk_path, .. } => {
                TransferVerifier::from_vk_bytes(&std::fs::read(base_dir.join(vk_path))?)?
            }
        };
        self.check_vk(&vk_sha256(&verifier.vk))?;
        Ok(verifier)
    }

    fn check_vk(&self, got: &[u8; 32]) -> Result<(), DeploymentError> {
        if *got != self.transfer_vk_sha256 {
            return Err(DeploymentError::VkMismatch {
                expected: hex::encode(self.transfer_vk_sha256),
                got: hex::encode(got),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        let d = Deployment {
            name: "regtest-dev".into(),
            network: Network::Regtest,
            activation_height: 100,
            const_salt: Deployment::derive_const_salt("regtest-dev"),
            transfer_vk_sha256: [0u8; 32],
            setup: Setup::InsecureSeed { seed: [1u8; 32] },
            window_w: 100,
            k_min: 1,
        };
        let json = d.to_json();
        assert!(json.contains("\"insecure-seed\""));
        assert_eq!(Deployment::from_json(&json).unwrap(), d);
    }
}
