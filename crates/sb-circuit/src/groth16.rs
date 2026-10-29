//! Groth16 over BLS12-381 for the transfer circuit (profile §1, §8.4).

use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

use sb_core::envelope::PROOF_LEN;
use sb_primitives::Fr;

use crate::batch::BatchCircuit;
use crate::swap::{SwapCircuit, SwapStatement, SwapWitness};
use crate::transfer::{TransferCircuit, TransferStatement, TransferWitness};
use sb_core::batch::{BatchStatement, BatchWitness};

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

/// Proving and verifying keys of the swap extension circuit (`docs/SWAP.md`).
pub struct SwapParams {
    pub pk: ProvingKey<Bls12_381>,
    pub pvk: PreparedVerifyingKey<Bls12_381>,
}

impl SwapParams {
    /// **Insecure** deterministic setup from a public seed (development only).
    pub fn insecure_setup(seed: &[u8; 32]) -> Result<Self, ProofError> {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let (pk, _vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(SwapCircuit::default(), &mut rng)?;
        Ok(Self::from_pk(pk))
    }

    pub fn from_pk(pk: ProvingKey<Bls12_381>) -> Self {
        let pvk = Groth16::<Bls12_381>::process_vk(&pk.vk).expect("vk is well formed");
        SwapParams { pk, pvk }
    }

    pub fn vk(&self) -> &VerifyingKey<Bls12_381> {
        &self.pk.vk
    }

    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        statement: &SwapStatement,
        witness: &SwapWitness,
        rng: &mut R,
    ) -> Result<[u8; PROOF_LEN], ProofError> {
        let circuit = SwapCircuit {
            statement: Some(statement.clone()),
            witness: Some(witness.clone()),
        };
        let proof = Groth16::<Bls12_381>::prove(&self.pk, circuit, rng)?;
        Ok(proof_to_bytes(&proof)?)
    }

    pub fn pk_to_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let mut out = Vec::new();
        self.pk.serialize_uncompressed(&mut out)?;
        Ok(out)
    }

    /// Trusted local state, no subgroup checks (as [`TransferParams::from_pk_bytes`]).
    pub fn from_pk_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let pk = ProvingKey::<Bls12_381>::deserialize_uncompressed_unchecked(bytes)?;
        Ok(Self::from_pk(pk))
    }
}

/// A verifier of swap envelopes (indexers).
pub struct SwapVerifier {
    pub vk: VerifyingKey<Bls12_381>,
    pub pvk: PreparedVerifyingKey<Bls12_381>,
}

impl SwapVerifier {
    pub fn new(vk: VerifyingKey<Bls12_381>) -> Self {
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).expect("vk is well formed");
        SwapVerifier { vk, pvk }
    }

    pub fn from_vk_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        Ok(Self::new(
            VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)?,
        ))
    }

    /// `false` for an undecodable proof or a failed verification.
    pub fn verify(&self, statement: &SwapStatement, proof: &[u8; PROOF_LEN]) -> bool {
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

/// The shape of a batch circuit: what a setup is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchShape {
    pub n: usize,
    pub activation: u32,
    pub window_w: u32,
    pub k_min: u32,
    pub const_salt: Fr,
}

impl BatchShape {
    fn circuit(
        &self,
        statement: Option<BatchStatement>,
        witness: Option<BatchWitness>,
    ) -> BatchCircuit {
        BatchCircuit {
            n: self.n,
            activation: self.activation,
            window_w: self.window_w,
            k_min: self.k_min,
            const_salt: self.const_salt,
            statement,
            witness,
        }
    }
}

/// Proving and verifying keys of a batch circuit (`docs/REPLAY-PROOF.md`
/// §4.2), one per shape.
pub struct BatchParams {
    pub shape: BatchShape,
    pub pk: ProvingKey<Bls12_381>,
    pub pvk: PreparedVerifyingKey<Bls12_381>,
}

impl BatchParams {
    /// **Insecure** deterministic setup from a public seed (development only).
    pub fn insecure_setup(shape: BatchShape, seed: &[u8; 32]) -> Result<Self, ProofError> {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let (pk, _vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(shape.circuit(None, None), &mut rng)?;
        Ok(Self::from_pk(shape, pk))
    }

    pub fn from_pk(shape: BatchShape, pk: ProvingKey<Bls12_381>) -> Self {
        let pvk = Groth16::<Bls12_381>::process_vk(&pk.vk).expect("vk is well formed");
        BatchParams { shape, pk, pvk }
    }

    pub fn vk(&self) -> &VerifyingKey<Bls12_381> {
        &self.pk.vk
    }

    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        statement: &BatchStatement,
        witness: &BatchWitness,
        rng: &mut R,
    ) -> Result<[u8; PROOF_LEN], ProofError> {
        let circuit = self.shape.circuit(Some(*statement), Some(witness.clone()));
        let proof = Groth16::<Bls12_381>::prove(&self.pk, circuit, rng)?;
        Ok(proof_to_bytes(&proof)?)
    }

    pub fn verify(&self, statement: &BatchStatement, proof: &[u8; PROOF_LEN]) -> bool {
        BatchVerifier::verify_with(&self.pvk, statement, proof)
    }

    pub fn pk_to_bytes(&self) -> Result<Vec<u8>, ProofError> {
        let mut out = Vec::new();
        self.pk.serialize_uncompressed(&mut out)?;
        Ok(out)
    }

    pub fn from_pk_bytes(shape: BatchShape, bytes: &[u8]) -> Result<Self, ProofError> {
        let pk = ProvingKey::<Bls12_381>::deserialize_uncompressed_unchecked(bytes)?;
        Ok(Self::from_pk(shape, pk))
    }
}

/// A verifier of batch proofs (light clients).
pub struct BatchVerifier {
    pub vk: VerifyingKey<Bls12_381>,
    pub pvk: PreparedVerifyingKey<Bls12_381>,
}

impl BatchVerifier {
    pub fn new(vk: VerifyingKey<Bls12_381>) -> Self {
        let pvk = Groth16::<Bls12_381>::process_vk(&vk).expect("vk is well formed");
        BatchVerifier { vk, pvk }
    }

    pub fn from_vk_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        Ok(Self::new(
            VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)?,
        ))
    }

    pub fn verify(&self, statement: &BatchStatement, proof: &[u8; PROOF_LEN]) -> bool {
        Self::verify_with(&self.pvk, statement, proof)
    }

    fn verify_with(
        pvk: &PreparedVerifyingKey<Bls12_381>,
        statement: &BatchStatement,
        proof: &[u8; PROOF_LEN],
    ) -> bool {
        let Ok(proof) = proof_from_bytes(proof) else {
            return false;
        };
        Groth16::<Bls12_381>::verify_with_processed_vk(pvk, &statement.to_field_elements(), &proof)
            .unwrap_or(false)
    }
}

/// Batched verification of Groth16 proofs under one verifying key
/// (`docs/REPLAY-PROOF.md` §4.3, option 2): one multi-pairing instead of
/// one pairing check per proof, with random scalars so that no proof can
/// compensate for another. `None` scalars (a deterministic check) would
/// let a pair of invalid proofs cancel; the scalars come from `rng`.
pub fn verify_batch<R: RngCore + CryptoRng>(
    vk: &VerifyingKey<Bls12_381>,
    items: &[(Vec<Fr>, [u8; PROOF_LEN])],
    rng: &mut R,
) -> bool {
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
    use ark_ff::UniformRand;
    if items.is_empty() {
        return true;
    }
    let mut g1 = Vec::with_capacity(items.len() * 3 + 1);
    let mut g2 = Vec::with_capacity(items.len() * 3 + 1);
    let mut r_sum = Fr::from(0u64);
    for (inputs, bytes) in items {
        let Ok(proof) = proof_from_bytes(bytes) else {
            return false;
        };
        if inputs.len() + 1 != vk.gamma_abc_g1.len() {
            return false;
        }
        // the public-input combination L = gamma_abc[0] + Σ x_i gamma_abc[i]
        let l = vk.gamma_abc_g1[0].into_group()
            + <ark_bls12_381::G1Projective as VariableBaseMSM>::msm_unchecked(
                &vk.gamma_abc_g1[1..],
                inputs,
            );
        let r = Fr::rand(rng);
        r_sum += r;
        // e(rA, B) · e(−rL, γ) · e(−rC, δ) per proof, · e(−Σr α, β) once == 1
        g1.push((proof.a.into_group() * r).into_affine());
        g2.push(proof.b);
        g1.push((-(l * r)).into_affine());
        g2.push(vk.gamma_g2);
        g1.push((-(proof.c.into_group() * r)).into_affine());
        g2.push(vk.delta_g2);
    }
    g1.push((-(vk.alpha_g1.into_group() * r_sum)).into_affine());
    g2.push(vk.beta_g2);
    let out = Bls12_381::multi_pairing(g1, g2);
    out.0 == <Bls12_381 as Pairing>::TargetField::from(1u64)
}
