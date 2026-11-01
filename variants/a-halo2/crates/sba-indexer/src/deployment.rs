//! Deployment profile of family A (PROFILE-A.md §9): everything replay
//! needs to agree on. No key material: the verifying key is derived from
//! the circuit and checked against the pinned identifier.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use sba_circuit::{K, TransferParams, TransferVerifier};
use sba_core::address::Network;
use sba_core::envelope::bytes_to_fp_254;
use sba_primitives::Fp;

use crate::hexbytes;

/// Custodial development boundary (docs/BOUNDARY.md). Absent → mints rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevBoundary {
    /// Hex `scriptPubKey` of the vault that mints must pay.
    pub vault_script_hex: String,
    /// The operator's shielded address; withdrawals are transfers to it.
    #[serde(default)]
    pub operator_address: Option<String>,
}

fn default_anchor_depth() -> u32 {
    DEFAULT_ANCHOR_DEPTH
}

/// The anchor depth of the paper profile's deployments (`PUBLICATION.md` §3.3).
pub const DEFAULT_ANCHOR_DEPTH: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deployment {
    /// `docs/PROFILE-A.md` version (must equal `sba_core::PROFILE_VERSION`).
    pub profile: String,
    /// The family (must equal `sba_core::FAMILY`).
    pub family: String,
    pub name: String,
    pub network: Network,
    /// First block height replay looks at.
    pub activation_height: u32,
    #[serde(with = "hexbytes")]
    pub const_salt: [u8; 32],
    /// Rows of the transfer circuit, `2^k` (must equal `sba_circuit::K`).
    pub transfer_k: u32,
    /// The verifying-key identifier (PROFILE-A.md §8.4).
    #[serde(with = "hexbytes")]
    pub transfer_vk_id: [u8; 32],
    /// `W` (profile §A.6).
    pub window_w: u32,
    /// `K_min` (profile §A.6).
    pub k_min: u32,
    #[serde(default = "default_anchor_depth")]
    pub anchor_depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<DevBoundary>,
    /// Where envelopes are published (`PROFILE-A.md` §10): the witness
    /// carrier by default.
    #[serde(default = "default_carrier")]
    pub carrier: sb_common::carrier::CarrierMode,
}

fn default_carrier() -> sb_common::carrier::CarrierMode {
    sb_common::carrier::CarrierMode::Witness
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("proof system: {0}")]
    Proof(#[from] sba_circuit::ProofError),
    #[error("verifying key mismatch: profile pins {expected}, the circuit gives {got}")]
    VkMismatch { expected: String, got: String },
    #[error("deployment follows profile {found} but this build implements {expected}")]
    ProfileMismatch { found: String, expected: String },
    #[error("deployment is of family {found}, this code is family {expected}")]
    FamilyMismatch { found: String, expected: String },
    #[error("deployment names k = {found}, this circuit has k = {expected}")]
    KMismatch { found: u32, expected: u32 },
}

impl Deployment {
    /// `const_salt = SHA-256("sb-a/v1/const_salt/" ‖ name)` (PROFILE-A.md §9).
    pub fn derive_const_salt(name: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"sb-a/v1/const_salt/");
        h.update(name.as_bytes());
        h.finalize().into()
    }

    /// The `Fp` embedding used in leaves and as a public input.
    pub fn const_salt_fp(&self) -> Fp {
        bytes_to_fp_254(&self.const_salt)
    }

    pub fn from_json(json: &str) -> Result<Self, DeploymentError> {
        let d: Deployment = serde_json::from_str(json)?;
        if d.family != sba_core::FAMILY {
            return Err(DeploymentError::FamilyMismatch {
                found: d.family,
                expected: sba_core::FAMILY.to_string(),
            });
        }
        if d.profile != sba_core::PROFILE_VERSION {
            return Err(DeploymentError::ProfileMismatch {
                found: d.profile,
                expected: sba_core::PROFILE_VERSION.to_string(),
            });
        }
        if d.transfer_k != K {
            return Err(DeploymentError::KMismatch {
                found: d.transfer_k,
                expected: K,
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

    /// Derive the proving parameters (wallets) and check the pinned identifier.
    pub fn params(&self) -> Result<TransferParams, DeploymentError> {
        let params = TransferParams::build()?;
        self.check_vk(&params.vk_id())?;
        Ok(params)
    }

    /// Derive the verifier (indexers) and check the pinned identifier.
    pub fn verifier(&self) -> Result<TransferVerifier, DeploymentError> {
        let v = TransferVerifier::build()?;
        self.check_vk(&v.vk_id())?;
        Ok(v)
    }

    fn check_vk(&self, got: &[u8; 32]) -> Result<(), DeploymentError> {
        if *got != self.transfer_vk_id {
            return Err(DeploymentError::VkMismatch {
                expected: hex::encode(self.transfer_vk_id),
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
    fn json_round_trip_and_refusals() {
        let d = Deployment {
            profile: sba_core::PROFILE_VERSION.into(),
            family: sba_core::FAMILY.into(),
            name: "regtest-a".into(),
            network: Network::Regtest,
            activation_height: 100,
            const_salt: Deployment::derive_const_salt("regtest-a"),
            transfer_k: K,
            transfer_vk_id: [0u8; 32],
            window_w: 100,
            k_min: 1,
            anchor_depth: 3,
            boundary: None,
            carrier: Default::default(),
        };
        let json = d.to_json();
        assert!(json.contains("\"family\": \"a-halo2\""));
        assert_eq!(Deployment::from_json(&json).unwrap(), d);
        let other = json.replace("\"family\": \"a-halo2\"", "\"family\": \"b-stark\"");
        assert!(matches!(
            Deployment::from_json(&other),
            Err(DeploymentError::FamilyMismatch { .. })
        ));
        let other = json.replace(
            &format!("\"profile\": \"{}\"", sba_core::PROFILE_VERSION),
            "\"profile\": \"a-9.9\"",
        );
        assert!(matches!(
            Deployment::from_json(&other),
            Err(DeploymentError::ProfileMismatch { .. })
        ));
        let other = json.replace("\"transfer_k\": 14", "\"transfer_k\": 13");
        assert!(matches!(
            Deployment::from_json(&other),
            Err(DeploymentError::KMismatch { .. })
        ));
        // a paper-profile deployment has no family field: refused by serde
        assert!(Deployment::from_json(r#"{"profile":"0.2","name":"x"}"#).is_err());
    }
}
