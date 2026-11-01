//! Proving and verification (PROFILE-A.md §8.4): deterministic parameters
//! (`Params::new(K)`), keys derived from the circuit, Blake2b transcripts,
//! fixed-length proofs, and the verifying-key identifier a deployment pins.

use halo2_proofs::{
    plonk::{self, ProvingKey, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, Transcript},
};
use pasta_curves::vesta;
use rand::{CryptoRng, RngCore};

use sba_core::envelope::PROOF_LEN;
use sba_primitives::Fp;
use sba_primitives::encoding::fp_to_bytes;

use crate::circuit::{K, TransferCircuit, TransferStatement, TransferWitness};

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("halo2: {0:?}")]
    Halo2(plonk::Error),
    #[error("the proof is not {PROOF_LEN} bytes: {0}")]
    Length(usize),
}

impl From<plonk::Error> for ProofError {
    fn from(e: plonk::Error) -> Self {
        ProofError::Halo2(e)
    }
}

/// The verifying-key identifier (PROFILE-A.md §8.4): the key hashed into a
/// Blake2b transcript, one challenge squeezed, LE-encoded.
pub fn vk_id(vk: &VerifyingKey<vesta::Affine>) -> [u8; 32] {
    let mut t = Blake2bWrite::<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>::init(vec![]);
    vk.hash_into(&mut t).expect("hashing a key cannot fail");
    let c = t.squeeze_challenge();
    fp_to_bytes(&c.get_scalar())
}

/// Parameters and keys of the transfer circuit, derived (no setup).
pub struct TransferParams {
    params: Params<vesta::Affine>,
    pk: ProvingKey<vesta::Affine>,
}

impl TransferParams {
    /// `Params::new(K)` and `keygen_vk`/`keygen_pk` over the empty circuit.
    pub fn build() -> Result<Self, ProofError> {
        let params: Params<vesta::Affine> = Params::new(K);
        let empty = TransferCircuit::default();
        let vk = plonk::keygen_vk(&params, &empty)?;
        let pk = plonk::keygen_pk(&params, vk, &empty)?;
        Ok(TransferParams { params, pk })
    }

    pub fn vk(&self) -> &VerifyingKey<vesta::Affine> {
        self.pk.get_vk()
    }

    pub fn vk_id(&self) -> [u8; 32] {
        vk_id(self.vk())
    }

    pub fn verifier(&self) -> TransferVerifier {
        TransferVerifier {
            params: self.params.clone(),
            vk: self.vk().clone(),
        }
    }

    /// Prove one transfer; exactly `PROOF_LEN` bytes.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        statement: &TransferStatement,
        witness: &TransferWitness,
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        let circuit = TransferCircuit {
            statement: Some(statement.clone()),
            witness: Some(witness.clone()),
        };
        let instance = statement.to_field_elements();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(
            &self.params,
            &self.pk,
            &[circuit],
            &[&[&instance[..]]],
            rng,
            &mut transcript,
        )?;
        let proof = transcript.finalize();
        if proof.len() != PROOF_LEN {
            return Err(ProofError::Length(proof.len()));
        }
        Ok(proof)
    }
}

/// The verifier: parameters and the verifying key.
pub struct TransferVerifier {
    params: Params<vesta::Affine>,
    vk: VerifyingKey<vesta::Affine>,
}

impl TransferVerifier {
    /// Derive the key (every indexer does this once at start).
    pub fn build() -> Result<Self, ProofError> {
        let params: Params<vesta::Affine> = Params::new(K);
        let vk = plonk::keygen_vk(&params, &TransferCircuit::default())?;
        Ok(TransferVerifier { params, vk })
    }

    pub fn vk_id(&self) -> [u8; 32] {
        vk_id(&self.vk)
    }

    /// Verify a proof of `statement`; a proof of the wrong length is invalid.
    pub fn verify(&self, statement: &TransferStatement, proof: &[u8]) -> bool {
        if proof.len() != PROOF_LEN {
            return false;
        }
        let instance = statement.to_field_elements();
        let strategy = SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::init(proof);
        plonk::verify_proof(
            &self.params,
            &self.vk,
            strategy,
            &[&[&instance[..]]],
            &mut transcript,
        )
        .is_ok()
    }
}

#[allow(dead_code)]
fn _assert_fp_is_vesta_scalar(x: Fp) -> vesta::Scalar {
    x
}
