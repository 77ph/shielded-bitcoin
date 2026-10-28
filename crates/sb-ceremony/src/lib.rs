//! Multi-party generation of the transfer circuit's Groth16 parameters,
//! after Bowe, Gabizon and Miers, "Scalable Multi-party Computation for
//! zk-SNARK Parameters in the Random Beacon Model" (BGM17), the protocol
//! behind the Zcash Sapling ceremony.
//!
//! * **Phase 1** ([`phase1`]): the circuit-independent "powers of tau"
//!   accumulator `[τ^i]₁`, `[τ^i]₂`, `[ατ^i]₁`, `[βτ^i]₁`, `[β]₂`. Each
//!   participant multiplies it by fresh secrets `(τ', α', β')` and proves
//!   knowledge of them; anyone can verify every transition.
//! * **Key derivation** ([`keygen`]): the circuit's R1CS turns the final
//!   accumulator into a Groth16 proving key with `γ = δ = 1`, computing in
//!   the exponent exactly what arkworks' generator computes in the field.
//! * **Phase 2** ([`phase2`]): participants randomise `δ` in turn, again
//!   with proofs of knowledge; a public random beacon finishes it.
//!
//! The parameters are secure if **at least one** participant of each phase
//! destroyed their secret. Files chain by SHA-256 digests, and every proof
//! of knowledge is bound to the digest of the state it was made from.
//! Transcript hashing and hashing to `G2` use SHA-256 and a ChaCha20
//! sampler rather than the BLAKE2b of the Sapling tools, so the files are
//! not interchangeable with those. A public powers-of-tau transcript in the
//! Sapling `powersoftau` response format can be imported as a phase 1
//! accumulator instead ([`powersoftau`]).

pub mod keygen;
pub mod phase1;
pub mod phase2;
pub mod powersoftau;
pub mod transcript;

pub use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};

#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("serialization: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("synthesis: {0}")]
    Synthesis(#[from] ark_relations::r1cs::SynthesisError),
    #[error("invalid: {0}")]
    Invalid(String),
}

pub type CeremonyResult<T> = std::result::Result<T, CeremonyError>;
