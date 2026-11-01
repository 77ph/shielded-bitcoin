//! The transfer relation of variant A in Halo 2 (`docs/PROFILE-A.md` §8):
//! the circuit, the statement and witness types, proving and verification
//! over the deterministic parameters of `halo2_proofs` (no setup). The
//! circuit is the one measured in `experiments/halo2-transfer`
//! (`VARIANT-A.md` §4.2), with the witnesses now derived by `sba-core`.

pub mod circuit;
pub mod fixed;
pub mod proof;

pub use circuit::{
    InputWitness, K, NUM_PUBLIC_INPUTS, OutputWitness, TransferCircuit, TransferStatement,
    TransferWitness,
};
pub use proof::{ProofError, TransferParams, TransferVerifier, vk_id};
