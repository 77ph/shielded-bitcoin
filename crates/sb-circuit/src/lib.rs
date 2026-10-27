//! The transfer relation as R1CS and its Groth16 setup/prove/verify
//! (paper §14, §B; profile §8).

pub mod gadgets;
pub mod groth16;
pub mod transfer;

pub use groth16::{
    ProofError, TransferParams, TransferVerifier, proof_from_bytes, proof_to_bytes, vk_sha256,
    vk_to_bytes,
};
pub use transfer::{
    InputWitness, NUM_PUBLIC_INPUTS, OutputWitness, TransferCircuit, TransferStatement,
    TransferWitness,
};
