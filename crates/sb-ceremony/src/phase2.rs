//! Phase 2: circuit-specific contributions to `δ`.
//!
//! A participant multiplies `[δ]₁`, `[δ]₂` by a fresh `δ'` and the `H` and
//! `L` queries by `δ'⁻¹`, and proves knowledge of `δ'` bound to the
//! transcript so far. A verifier recomputes the initial key from phase 1
//! and the circuit, checks that everything except `δ`, `H` and `L` is
//! unchanged, walks the contributions, and checks `H` and `L` against the
//! final `δ` in one batched pairing each.
//!
//! File layout (`sbp2`): magic, version, digest of the initial key, the
//! contributions, the proving key (compressed).

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, UniformRand};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::transcript::{
    digest, hash_to_g2, merge_pairs_g1, point_bytes, same_ratio, valid_g1, valid_g2,
};
use crate::{CeremonyError, CeremonyResult};

const MAGIC: &[u8; 4] = b"sbp2";
const VERSION: u32 = 1;

/// A participant's contribution: the new `[δ]₁` and a proof of knowledge
/// of the factor applied, bound to the transcript before it.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2Key {
    pub delta_after: G1Affine,
    pub s: G1Affine,
    pub s_delta: G1Affine,
    pub r_delta: G2Affine,
    pub transcript: [u8; 32],
}

impl Phase2Key {
    /// SHA-256 of the key, the identifier a participant publishes.
    pub fn hash(&self) -> [u8; 32] {
        digest(&point_bytes(self))
    }

    fn r(&self) -> G2Projective {
        hash_to_g2(
            b"phase2",
            &[
                &self.transcript,
                &point_bytes(&self.s),
                &point_bytes(&self.s_delta),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Phase2 {
    /// Digest of the initial proving key (what phase 1 and the circuit give).
    pub cs_hash: [u8; 32],
    pub contributions: Vec<Phase2Key>,
    pub pk: ProvingKey<Bls12_381>,
}

impl Phase2 {
    /// Phase 2 at its start: the key from [`crate::keygen::initial_proving_key`].
    pub fn new(pk: ProvingKey<Bls12_381>) -> CeremonyResult<Self> {
        let mut bytes = Vec::new();
        pk.serialize_compressed(&mut bytes)?;
        Ok(Phase2 {
            cs_hash: digest(&bytes),
            contributions: Vec::new(),
            pk,
        })
    }

    /// Transcript hash a new contribution binds to: the initial key's
    /// digest and every contribution so far.
    fn transcript(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"sb-ceremony/phase2/transcript");
        h.update(self.cs_hash);
        for c in &self.contributions {
            h.update(point_bytes(c));
        }
        h.finalize().into()
    }

    fn apply(&self, delta: Fr, s: G1Affine) -> CeremonyResult<Self> {
        let delta_inv = delta
            .inverse()
            .ok_or_else(|| CeremonyError::Invalid("zero delta".into()))?;
        let mut pk = self.pk.clone();
        pk.delta_g1 = (pk.delta_g1 * delta).into_affine();
        pk.vk.delta_g2 = (pk.vk.delta_g2 * delta).into_affine();
        let scale = |v: &[G1Affine]| -> Vec<G1Affine> {
            let p: Vec<G1Projective> = v.par_iter().map(|a| *a * delta_inv).collect();
            G1Projective::normalize_batch(&p)
        };
        pk.h_query = scale(&pk.h_query);
        pk.l_query = scale(&pk.l_query);
        let transcript = self.transcript();
        let s_delta = (s * delta).into_affine();
        let key = Phase2Key {
            delta_after: pk.delta_g1,
            s,
            s_delta,
            r_delta: G2Affine::identity(),
            transcript,
        };
        let r_delta = (key.r() * delta).into_affine();
        let key = Phase2Key { r_delta, ..key };
        let mut contributions = self.contributions.clone();
        contributions.push(key);
        Ok(Phase2 {
            cs_hash: self.cs_hash,
            contributions,
            pk,
        })
    }

    /// Contribute a fresh random `δ'`; it exists only inside this call.
    pub fn contribute<R: RngCore + CryptoRng>(&self, rng: &mut R) -> CeremonyResult<Self> {
        let delta = Fr::rand(rng);
        let s = G1Projective::rand(rng).into_affine();
        self.apply(delta, s)
    }

    /// The final contribution from a public random beacon (a value nobody
    /// could predict before the last participant finished, for example a
    /// Bitcoin block hash chosen in advance by height): `δ'` and `s` are
    /// derived from it, so anyone can recompute this step.
    pub fn beacon(&self, beacon: &[u8]) -> CeremonyResult<Self> {
        let mut h = Sha256::new();
        h.update(b"sb-ceremony/phase2/beacon");
        h.update(self.transcript());
        h.update(beacon);
        let mut rng = ChaCha20Rng::from_seed(h.finalize().into());
        let delta = Fr::rand(&mut rng);
        let s = G1Projective::rand(&mut rng).into_affine();
        self.apply(delta, s)
    }

    /// Verify `self` against the recomputed initial key: the circuit part
    /// is untouched, every contribution's proof holds and chains, and `H`
    /// and `L` were divided by exactly the final `δ`. Returns the
    /// contribution hashes in order.
    pub fn verify<R: RngCore>(
        &self,
        initial: &ProvingKey<Bls12_381>,
        rng: &mut R,
    ) -> CeremonyResult<Vec<[u8; 32]>> {
        let bad = |what: &str| CeremonyError::Invalid(what.to_string());
        let mut bytes = Vec::new();
        initial.serialize_compressed(&mut bytes)?;
        if digest(&bytes) != self.cs_hash {
            return Err(bad("initial key digest differs"));
        }
        let pk = &self.pk;
        if pk.vk.alpha_g1 != initial.vk.alpha_g1
            || pk.vk.beta_g2 != initial.vk.beta_g2
            || pk.vk.gamma_g2 != initial.vk.gamma_g2
            || pk.vk.gamma_abc_g1 != initial.vk.gamma_abc_g1
            || pk.beta_g1 != initial.beta_g1
            || pk.a_query != initial.a_query
            || pk.b_g1_query != initial.b_g1_query
            || pk.b_g2_query != initial.b_g2_query
        {
            return Err(bad("the circuit part of the key was changed"));
        }
        if pk.h_query.len() != initial.h_query.len() || pk.l_query.len() != initial.l_query.len() {
            return Err(bad("H or L query length changed"));
        }
        // walk the contributions
        let mut delta_g1 = initial.delta_g1;
        let mut transcript_state = Phase2 {
            cs_hash: self.cs_hash,
            contributions: Vec::new(),
            pk: initial.clone(),
        };
        let mut hashes = Vec::new();
        for (i, c) in self.contributions.iter().enumerate() {
            if c.transcript != transcript_state.transcript() {
                return Err(bad(&format!(
                    "contribution {i} is not bound to the transcript"
                )));
            }
            let r = c.r().into_affine();
            if !same_ratio((c.s, c.s_delta), (r, c.r_delta)) {
                return Err(bad(&format!("contribution {i}: proof of knowledge fails")));
            }
            if !same_ratio((delta_g1, c.delta_after), (r, c.r_delta)) {
                return Err(bad(&format!("contribution {i}: delta was not applied")));
            }
            delta_g1 = c.delta_after;
            hashes.push(c.hash());
            transcript_state.contributions.push(c.clone());
        }
        if pk.delta_g1 != delta_g1 {
            return Err(bad("final delta differs from the last contribution"));
        }
        let g1 = G1Projective::generator().into_affine();
        let g2 = G2Projective::generator().into_affine();
        if !same_ratio((g1, pk.delta_g1), (g2, pk.vk.delta_g2)) {
            return Err(bad("delta differs between G1 and G2"));
        }
        // H and L: initial / final = δ_final / δ_initial
        let delta_pair = (pk.vk.delta_g2, initial.vk.delta_g2);
        if !same_ratio(
            merge_pairs_g1(&initial.h_query, &pk.h_query, rng),
            delta_pair,
        ) {
            return Err(bad("H query is not divided by delta"));
        }
        if !same_ratio(
            merge_pairs_g1(&initial.l_query, &pk.l_query, rng),
            delta_pair,
        ) {
            return Err(bad("L query is not divided by delta"));
        }
        Ok(hashes)
    }

    pub fn write<W: Write>(&self, mut w: W) -> CeremonyResult<()> {
        w.write_all(MAGIC)?;
        VERSION.serialize_compressed(&mut w)?;
        w.write_all(&self.cs_hash)?;
        self.contributions.serialize_compressed(&mut w)?;
        self.pk.serialize_compressed(&mut w)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> CeremonyResult<Vec<u8>> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    /// Read with full point validation: the file comes from another participant.
    pub fn read<R: Read>(mut r: R) -> CeremonyResult<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(CeremonyError::Invalid("not a phase 2 file".into()));
        }
        let version = u32::deserialize_compressed(&mut r)?;
        if version != VERSION {
            return Err(CeremonyError::Invalid(format!(
                "phase 2 file version {version}"
            )));
        }
        let mut cs_hash = [0u8; 32];
        r.read_exact(&mut cs_hash)?;
        let contributions = Vec::<Phase2Key>::deserialize_compressed(&mut r)?;
        // the key's vectors are validated in parallel below
        let pk = ProvingKey::<Bls12_381>::deserialize_compressed_unchecked(&mut r)?;
        if !valid_g1(&[pk.vk.alpha_g1, pk.beta_g1, pk.delta_g1])
            || !valid_g2(&[pk.vk.beta_g2, pk.vk.gamma_g2, pk.vk.delta_g2])
            || !valid_g1(&pk.vk.gamma_abc_g1)
            || !valid_g1(&pk.a_query)
            || !valid_g1(&pk.b_g1_query)
            || !valid_g2(&pk.b_g2_query)
            || !valid_g1(&pk.h_query)
            || !valid_g1(&pk.l_query)
        {
            return Err(CeremonyError::Invalid(
                "a point is not in the prime-order subgroup".into(),
            ));
        }
        Ok(Phase2 {
            cs_hash,
            contributions,
            pk,
        })
    }
}
