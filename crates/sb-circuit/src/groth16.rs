//! Groth16 over BLS12-381 for the transfer circuit (profile §1, §8.4).

use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use sb_core::envelope::PROOF_LEN;

use crate::transfer::{TransferCircuit, TransferStatement, TransferWitness};

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("synthesis: {0}")]
    Synthesis(#[from] ark_relations::r1cs::SynthesisError),
    #[error("serialization: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
}

/// Proving and verifying keys for one circuit.
pub struct TransferParams {
    pub pk: ProvingKey<Bls12_381>,
    pub pvk: PreparedVerifyingKey<Bls12_381>,
}

impl TransferParams {
    /// **Insecure** deterministic setup from a public seed: anyone who knows
    /// the seed can forge proofs. For development and test networks only.
    pub fn insecure_setup(seed: &[u8; 32]) -> Result<Self, ProofError> {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let (pk, _vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(TransferCircuit::default(), &mut rng)?;
        Ok(Self::from_pk(pk))
    }

    pub fn from_pk(pk: ProvingKey<Bls12_381>) -> Self {
        let pvk = Groth16::<Bls12_381>::process_vk(&pk.vk).expect("vk is well formed");
        TransferParams { pk, pvk }
    }

    pub fn vk(&self) -> &VerifyingKey<Bls12_381> {
        &self.pk.vk
    }

    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        statement: &TransferStatement,
        witness: &TransferWitness,
        rng: &mut R,
    ) -> Result<[u8; PROOF_LEN], ProofError> {
        let circuit = TransferCircuit {
            statement: Some(statement.clone()),
            witness: Some(witness.clone()),
        };
        let proof = Groth16::<Bls12_381>::prove(&self.pk, circuit, rng)?;
        Ok(proof_to_bytes(&proof)?)
    }

    /// Serialize the proving key (uncompressed, for fast local reloads).
    pub fn pk_to_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let mut out = Vec::new();
        self.pk.serialize_uncompressed(&mut out)?;
        Ok(out)
    }

    /// Reload a proving key written by [`Self::pk_to_bytes`]. The file is
    /// trusted local state, so no subgroup checks are performed.
    pub fn from_pk_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let pk = ProvingKey::<Bls12_381>::deserialize_uncompressed_unchecked(bytes)?;
        Ok(Self::from_pk(pk))
    }
}

/// A verifier that only holds the verifying key (indexers).
pub struct TransferVerifier {
    pub vk: VerifyingKey<Bls12_381>,
    pub pvk: PreparedVerifyingKey<Bls12_381>,
}

impl TransferVerifier {
    pub fn new(vk: VerifyingKey<Bls12_381>) -> Self {
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).expect("vk is well formed");
        TransferVerifier { vk, pvk }
    }

    pub fn from_vk_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        Ok(Self::new(
            VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)?,
        ))
    }

    /// `false` for an undecodable proof or a failed verification.
    pub fn verify(&self, statement: &TransferStatement, proof: &[u8; PROOF_LEN]) -> bool {
        let Ok(proof) = proof_from_bytes(proof) else {
            return false;
        };
        Groth16::<Bls12_381>::verify_with_processed_vk(
            &self.pvk,
            &statement.to_field_elements(),
            &proof,
        )
        .unwrap_or(false)
    }
}

pub fn vk_to_bytes(vk: &VerifyingKey<Bls12_381>) -> Vec<u8> {
    let mut out = Vec::new();
    vk.serialize_compressed(&mut out).expect("in-memory write");
    out
}

/// `SHA-256(vk_bytes)`, pinned in the deployment profile (profile §9).
pub fn vk_sha256(vk: &VerifyingKey<Bls12_381>) -> [u8; 32] {
    Sha256::digest(vk_to_bytes(vk)).into()
}

/// 192-byte compressed `A ‖ B ‖ C`.
pub fn proof_to_bytes(
    proof: &Proof<Bls12_381>,
) -> Result<[u8; PROOF_LEN], ark_serialize::SerializationError> {
    let mut out = Vec::with_capacity(PROOF_LEN);
    proof.serialize_compressed(&mut out)?;
    let mut arr = [0u8; PROOF_LEN];
    arr.copy_from_slice(&out);
    Ok(arr)
}

/// Decode with subgroup checks (the proof comes from the chain).
pub fn proof_from_bytes(
    bytes: &[u8; PROOF_LEN],
) -> Result<Proof<Bls12_381>, ark_serialize::SerializationError> {
    Proof::<Bls12_381>::deserialize_compressed(&bytes[..])
}
