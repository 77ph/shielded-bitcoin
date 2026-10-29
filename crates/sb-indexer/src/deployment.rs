//! Deployment profile (profile §9): everything replay needs to agree on.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sb_circuit::{SwapParams, SwapVerifier, TransferParams, TransferVerifier, vk_sha256};
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

/// Custodial development boundary (docs/BOUNDARY.md). Absent → mints rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevBoundary {
    /// Hex `scriptPubKey` of the vault that mints must pay.
    pub vault_script_hex: String,
    /// The operator's shielded address; withdrawals are transfers to it.
    #[serde(default)]
    pub operator_address: Option<String>,
}

/// The swap extension of a deployment (`docs/SWAP.md` §12): its own
/// verifying-key hash and setup. Absent → kind `0x03` envelopes are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapDeployment {
    #[serde(with = "hexbytes")]
    pub vk_sha256: [u8; 32],
    pub setup: Setup,
}

fn default_anchor_depth() -> u32 {
    DEFAULT_ANCHOR_DEPTH
}

/// The anchor depth wallets used before the field existed.
pub const DEFAULT_ANCHOR_DEPTH: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    /// `docs/PROFILE.md` version this deployment follows (must equal
    /// `sb_core::PROFILE_VERSION`).
    pub profile: String,
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
    /// How many blocks before the next block every wallet of this
    /// deployment anchors its transfers (`tip + 1 − anchor_depth`,
    /// `docs/PUBLICATION.md` §3.3): shared, so that the anchor age does not
    /// fingerprint a wallet.
    #[serde(default = "default_anchor_depth")]
    pub anchor_depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<DevBoundary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap: Option<SwapDeployment>,
    /// Where envelopes are published: the base profile's OP_RETURN output
    /// (default) or the witness carrier of `docs/WITNESS-CARRIER.md`. A
    /// different carrier is a different, non-interoperable deployment.
    #[serde(default)]
    pub carrier: crate::carrier::CarrierMode,
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
    #[error("deployment follows profile {found} but this build implements {expected}")]
    ProfileMismatch { found: String, expected: String },
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
        let d: Deployment = serde_json::from_str(json)?;
        if d.profile != sb_core::PROFILE_VERSION {
            return Err(DeploymentError::ProfileMismatch {
                found: d.profile,
                expected: sb_core::PROFILE_VERSION.to_string(),
            });
        }
        Ok(d)
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
        Self::check_pin(&self.transfer_vk_sha256, got)
    }

    fn check_pin(expected: &[u8; 32], got: &[u8; 32]) -> Result<(), DeploymentError> {
        if got != expected {
            return Err(DeploymentError::VkMismatch {
                expected: hex::encode(expected),
                got: hex::encode(got),
            });
        }
        Ok(())
    }

    /// The swap extension's proving parameters, if the deployment has it.
    pub fn swap_params(&self, base_dir: &Path) -> Result<Option<SwapParams>, DeploymentError> {
        let Some(sw) = &self.swap else {
            return Ok(None);
        };
        let params = match &sw.setup {
            Setup::InsecureSeed { seed } => SwapParams::insecure_setup(seed)?,
            Setup::Ceremony { pk_path, .. } => {
                let pk_path = pk_path.as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "swap section has no proving key path",
                    )
                })?;
                SwapParams::from_pk_bytes(&std::fs::read(base_dir.join(pk_path))?)?
            }
        };
        Self::check_pin(&sw.vk_sha256, &vk_sha256(params.vk()))?;
        Ok(Some(params))
    }

    /// The swap extension's verifier, if the deployment has it.
    pub fn swap_verifier(&self, base_dir: &Path) -> Result<Option<SwapVerifier>, DeploymentError> {
        let Some(sw) = &self.swap else {
            return Ok(None);
        };
        let verifier = match &sw.setup {
            Setup::InsecureSeed { seed } => {
                let params = SwapParams::insecure_setup(seed)?;
                SwapVerifier::new(params.vk().clone())
            }
            Setup::Ceremony { vk_path, .. } => {
                SwapVerifier::from_vk_bytes(&std::fs::read(base_dir.join(vk_path))?)?
            }
        };
        Self::check_pin(&sw.vk_sha256, &vk_sha256(&verifier.vk))?;
        Ok(Some(verifier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        let d = Deployment {
            profile: sb_core::PROFILE_VERSION.into(),
            name: "regtest-dev".into(),
            network: Network::Regtest,
            activation_height: 100,
            const_salt: Deployment::derive_const_salt("regtest-dev"),
            transfer_vk_sha256: [0u8; 32],
            setup: Setup::InsecureSeed { seed: [1u8; 32] },
            window_w: 100,
            anchor_depth: 3,
            k_min: 1,
            boundary: None,
            swap: None,
            carrier: Default::default(),
        };
        let json = d.to_json();
        assert!(json.contains("\"insecure-seed\""));
        assert_eq!(Deployment::from_json(&json).unwrap(), d);
        let other = json.replace(
            &format!("\"profile\": \"{}\"", sb_core::PROFILE_VERSION),
            "\"profile\": \"0.0\"",
        );
        assert!(matches!(
            Deployment::from_json(&other),
            Err(DeploymentError::ProfileMismatch { .. })
        ));
    }
}
