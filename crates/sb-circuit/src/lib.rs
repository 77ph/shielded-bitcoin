//! The transfer relation as R1CS and its Groth16 setup/prove/verify
//! (paper §14, §B; profile §8).

pub mod batch;
pub mod gadgets;
pub mod groth16;
pub mod swap;
pub mod transfer;

pub use batch::{BatchCircuit, NUM_BATCH_PUBLIC_INPUTS};
pub use groth16::{
    BatchParams, BatchVerifier, ProofError, SwapParams, SwapVerifier, TransferParams,
    TransferVerifier, proof_from_bytes, proof_to_bytes, vk_sha256, vk_to_bytes,
};
pub use swap::{NUM_SWAP_PUBLIC_INPUTS, SwapCircuit, SwapInputWitness, SwapStatement, SwapWitness};
pub use transfer::{
    InputWitness, NUM_PUBLIC_INPUTS, OutputWitness, TransferCircuit, TransferStatement,
    TransferWitness,
};
