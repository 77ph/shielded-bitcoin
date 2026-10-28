//! Phase 1: the powers-of-tau accumulator and its contributions.
//!
//! For a domain of size `n` (a power of two) the accumulator holds
//! `[τ^i]₁` for `i < 2n − 1`, `[τ^i]₂`, `[ατ^i]₁` and `[βτ^i]₁` for `i < n`,
//! and `[β]₂`. It starts at `τ = α = β = 1`. A contribution multiplies
//! every element by the participant's fresh secrets and comes with three
//! proofs of knowledge, each bound to the digest of the accumulator file it
//! was made from.
//!
//! File layout (`sbp1`): magic, version, `n`, digest of the previous file
//! (zero for the initial accumulator), the contribution key (absent for
//! the initial accumulator) and the accumulator, all points compressed.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;

use crate::transcript::{
    hash_to_g2, point_bytes, power_pairs_g1, power_pairs_g2, same_ratio, valid_g1, valid_g2,
};
use crate::{CeremonyError, CeremonyResult};

const MAGIC: &[u8; 4] = b"sbp1";
const VERSION: u32 = 1;

/// Proof of knowledge of a secret `s` (BGM17 §4): a random `[r]₁`, `[sr]₁`
/// and `[s·H(…)]₂` where `H(…)` is a hash to `G2` of the transcript and
/// the two `G1` points.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Pok {
    pub g1_s: G1Affine,
    pub g1_s_x: G1Affine,
    pub g2_s_x: G2Affine,
}

impl Pok {
    fn make<R: RngCore + CryptoRng>(
        secret: Fr,
        label: &[u8],
        digest: &[u8; 32],
        rng: &mut R,
    ) -> Self {
        let g1_s = G1Projective::rand(rng).into_affine();
        let g1_s_x = (g1_s * secret).into_affine();
        let g2_s = Self::g2_s(label, digest, &g1_s, &g1_s_x);
        Pok {
            g1_s,
            g1_s_x,
            g2_s_x: (g2_s * secret).into_affine(),
        }
    }

    fn g2_s(label: &[u8], digest: &[u8; 32], g1_s: &G1Affine, g1_s_x: &G1Affine) -> G2Projective {
        hash_to_g2(
            b"phase1",
            &[label, digest, &point_bytes(g1_s), &point_bytes(g1_s_x)],
        )
    }

    /// `(g2_s, g2_s_x)`: the `G2` pair with the secret's ratio, if the proof holds.
    fn verify(&self, label: &[u8], digest: &[u8; 32]) -> CeremonyResult<(G2Affine, G2Affine)> {
        let g2_s = Self::g2_s(label, digest, &self.g1_s, &self.g1_s_x).into_affine();
        if !same_ratio((self.g1_s, self.g1_s_x), (g2_s, self.g2_s_x)) {
            return Err(CeremonyError::Invalid(format!(
                "proof of knowledge of {} does not verify",
                String::from_utf8_lossy(label)
            )));
        }
        Ok((g2_s, self.g2_s_x))
    }
}

/// A participant's public key: proofs of knowledge of `τ'`, `α'`, `β'`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Key {
    pub tau: Pok,
    pub alpha: Pok,
    pub beta: Pok,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase1 {
    /// Domain size; the accumulator serves any circuit whose domain is at
    /// most this.
    pub n: usize,
    /// Digest of the file this accumulator was computed from (zero initially).
    pub prev_digest: [u8; 32],
    /// The contribution that produced this accumulator (none initially).
    pub key: Option<Phase1Key>,
    pub tau_g1: Vec<G1Affine>,
    pub tau_g2: Vec<G2Affine>,
    pub alpha_tau_g1: Vec<G1Affine>,
    pub beta_tau_g1: Vec<G1Affine>,
    pub beta_g2: G2Affine,
}

fn powers(x: Fr, len: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(len);
    let mut p = Fr::ONE;
    for _ in 0..len {
        out.push(p);
        p *= x;
    }
    out
}

fn scale_g1(points: &[G1Affine], scalars: &[Fr]) -> Vec<G1Affine> {
    let v: Vec<G1Projective> = points
        .par_iter()
        .zip(scalars.par_iter())
        .map(|(p, s)| *p * s)
        .collect();
    G1Projective::normalize_batch(&v)
}

fn scale_g2(points: &[G2Affine], scalars: &[Fr]) -> Vec<G2Affine> {
    let v: Vec<G2Projective> = points
        .par_iter()
        .zip(scalars.par_iter())
        .map(|(p, s)| *p * s)
        .collect();
    G2Projective::normalize_batch(&v)
}

impl Phase1 {
    /// The initial accumulator (`τ = α = β = 1`) for a domain of `n`
    /// elements, `n` a power of two.
    pub fn new(n: usize) -> CeremonyResult<Self> {
        if n < 2 || !n.is_power_of_two() {
            return Err(CeremonyError::Invalid(format!(
                "domain size {n} is not a power of two ≥ 2"
            )));
        }
        let g1 = G1Projective::generator().into_affine();
        let g2 = G2Projective::generator().into_affine();
        Ok(Phase1 {
            n,
            prev_digest: [0u8; 32],
            key: None,
            tau_g1: vec![g1; 2 * n - 1],
            tau_g2: vec![g2; n],
            alpha_tau_g1: vec![g1; n],
            beta_tau_g1: vec![g1; n],
            beta_g2: g2,
        })
    }

    /// Multiply the accumulator by fresh secrets drawn from `rng`;
    /// `digest` is the digest of the file this accumulator was read from.
    /// The secrets exist only inside this call.
    pub fn contribute<R: RngCore + CryptoRng>(&self, digest: [u8; 32], rng: &mut R) -> Self {
        let tau = Fr::rand(rng);
        let alpha = Fr::rand(rng);
        let beta = Fr::rand(rng);
        self.contribute_with(tau, alpha, beta, digest, rng)
    }

    /// [`Self::contribute`] with the secrets chosen by the caller: for
    /// tests that compare the derived key with a plain trusted setup.
    pub fn contribute_with<R: RngCore + CryptoRng>(
        &self,
        tau: Fr,
        alpha: Fr,
        beta: Fr,
        digest: [u8; 32],
        rng: &mut R,
    ) -> Self {
        let key = Phase1Key {
            tau: Pok::make(tau, b"tau", &digest, rng),
            alpha: Pok::make(alpha, b"alpha", &digest, rng),
            beta: Pok::make(beta, b"beta", &digest, rng),
        };
        let tau_powers = powers(tau, 2 * self.n - 1);
        let alpha_tau: Vec<Fr> = tau_powers[..self.n].iter().map(|t| *t * alpha).collect();
        let beta_tau: Vec<Fr> = tau_powers[..self.n].iter().map(|t| *t * beta).collect();
        Phase1 {
            n: self.n,
            prev_digest: digest,
            key: Some(key),
            tau_g1: scale_g1(&self.tau_g1, &tau_powers),
            tau_g2: scale_g2(&self.tau_g2, &tau_powers[..self.n]),
            alpha_tau_g1: scale_g1(&self.alpha_tau_g1, &alpha_tau),
            beta_tau_g1: scale_g1(&self.beta_tau_g1, &beta_tau),
            beta_g2: (self.beta_g2 * beta).into_affine(),
        }
    }

    /// Is `after` a valid contribution on top of `before`, whose file has
    /// `before_digest`? Checks the proofs of knowledge, that the same
    /// secrets were applied to every component, and that `after` is a
    /// well-formed accumulator on its own.
    pub fn verify_transition<R: RngCore>(
        before: &Self,
        before_digest: [u8; 32],
        after: &Self,
        rng: &mut R,
    ) -> CeremonyResult<()> {
        let bad = |what: &str| CeremonyError::Invalid(what.to_string());
        if before.n != after.n {
            return Err(bad("domain sizes differ"));
        }
        if after.prev_digest != before_digest {
            return Err(bad("the contribution is not built on this accumulator"));
        }
        let key = after
            .key
            .as_ref()
            .ok_or_else(|| bad("the accumulator carries no contribution key"))?;
        let tau = key.tau.verify(b"tau", &before_digest)?;
        let alpha = key.alpha.verify(b"alpha", &before_digest)?;
        let beta = key.beta.verify(b"beta", &before_digest)?;
        // the new secrets were applied to the old accumulator
        if !same_ratio((before.tau_g1[1], after.tau_g1[1]), tau) {
            return Err(bad("tau was not applied to the accumulator"));
        }
        if !same_ratio((before.alpha_tau_g1[0], after.alpha_tau_g1[0]), alpha) {
            return Err(bad("alpha was not applied to the accumulator"));
        }
        if !same_ratio((before.beta_tau_g1[0], after.beta_tau_g1[0]), beta) {
            return Err(bad("beta was not applied to the accumulator"));
        }
        if !same_ratio(
            (before.beta_tau_g1[0], after.beta_tau_g1[0]),
            (before.beta_g2, after.beta_g2),
        ) {
            return Err(bad("beta differs between G1 and G2"));
        }
        after.verify_shape(rng)
    }

    /// Is this a well-formed accumulator: generators at index 0, every
    /// vector a consistent sequence of powers of one `τ`, scaled by one
    /// `α` and one `β`?
    pub fn verify_shape<R: RngCore>(&self, rng: &mut R) -> CeremonyResult<()> {
        let bad = |what: &str| CeremonyError::Invalid(what.to_string());
        let n = self.n;
        if !n.is_power_of_two()
            || self.tau_g1.len() != 2 * n - 1
            || self.tau_g2.len() != n
            || self.alpha_tau_g1.len() != n
            || self.beta_tau_g1.len() != n
        {
            return Err(bad("vector lengths do not match the domain size"));
        }
        if self.tau_g1[0] != G1Projective::generator().into_affine()
            || self.tau_g2[0] != G2Projective::generator().into_affine()
        {
            return Err(bad("index 0 is not the generator"));
        }
        let tau_g2 = (self.tau_g2[0], self.tau_g2[1]);
        if !same_ratio(power_pairs_g1(&self.tau_g1, rng), tau_g2) {
            return Err(bad("G1 powers of tau are inconsistent"));
        }
        if !same_ratio(
            (self.tau_g1[0], self.tau_g1[1]),
            power_pairs_g2(&self.tau_g2, rng),
        ) {
            return Err(bad("G2 powers of tau are inconsistent"));
        }
        if !same_ratio(power_pairs_g1(&self.alpha_tau_g1, rng), tau_g2) {
            return Err(bad("alpha powers are inconsistent"));
        }
        if !same_ratio(power_pairs_g1(&self.beta_tau_g1, rng), tau_g2) {
            return Err(bad("beta powers are inconsistent"));
        }
        Ok(())
    }

    pub fn write<W: Write>(&self, mut w: W) -> CeremonyResult<()> {
        w.write_all(MAGIC)?;
        VERSION.serialize_compressed(&mut w)?;
        (self.n as u64).serialize_compressed(&mut w)?;
        w.write_all(&self.prev_digest)?;
        self.key.serialize_compressed(&mut w)?;
        self.tau_g1.serialize_compressed(&mut w)?;
        self.tau_g2.serialize_compressed(&mut w)?;
        self.alpha_tau_g1.serialize_compressed(&mut w)?;
        self.beta_tau_g1.serialize_compressed(&mut w)?;
        self.beta_g2.serialize_compressed(&mut w)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> CeremonyResult<Vec<u8>> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    /// Read with full point validation (subgroup checks): the file comes
    /// from another participant.
    pub fn read<R: Read>(mut r: R) -> CeremonyResult<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(CeremonyError::Invalid("not a phase 1 file".into()));
        }
        let version = u32::deserialize_compressed(&mut r)?;
        if version != VERSION {
            return Err(CeremonyError::Invalid(format!(
                "phase 1 file version {version}"
            )));
        }
        let n = u64::deserialize_compressed(&mut r)? as usize;
        if n < 2 || !n.is_power_of_two() || n > (1 << 28) {
            return Err(CeremonyError::Invalid(format!("domain size {n}")));
        }
        let mut prev_digest = [0u8; 32];
        r.read_exact(&mut prev_digest)?;
        let key = Option::<Phase1Key>::deserialize_compressed(&mut r)?;
        // the vectors are validated in parallel below
        let tau_g1 = Vec::<G1Affine>::deserialize_compressed_unchecked(&mut r)?;
        let tau_g2 = Vec::<G2Affine>::deserialize_compressed_unchecked(&mut r)?;
        let alpha_tau_g1 = Vec::<G1Affine>::deserialize_compressed_unchecked(&mut r)?;
        let beta_tau_g1 = Vec::<G1Affine>::deserialize_compressed_unchecked(&mut r)?;
        let beta_g2 = G2Affine::deserialize_compressed(&mut r)?;
        if !valid_g1(&tau_g1)
            || !valid_g2(&tau_g2)
            || !valid_g1(&alpha_tau_g1)
            || !valid_g1(&beta_tau_g1)
        {
            return Err(CeremonyError::Invalid(
                "a point is not in the prime-order subgroup".into(),
            ));
        }
        let p = Phase1 {
            n,
            prev_digest,
            key,
            tau_g1,
            tau_g2,
            alpha_tau_g1,
            beta_tau_g1,
            beta_g2,
        };
        if p.tau_g1.len() != 2 * n - 1
            || p.tau_g2.len() != n
            || p.alpha_tau_g1.len() != n
            || p.beta_tau_g1.len() != n
        {
            return Err(CeremonyError::Invalid("vector lengths".into()));
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::digest;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn two_contributions_verify_and_tampering_is_caught() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let p0 = Phase1::new(8).unwrap();
        assert!(Phase1::new(6).is_err());
        let b0 = p0.to_bytes().unwrap();
        let d0 = digest(&b0);
        p0.verify_shape(&mut rng).unwrap();
        let p1 = p0.contribute(d0, &mut rng);
        Phase1::verify_transition(&p0, d0, &p1, &mut rng).unwrap();
        let b1 = p1.to_bytes().unwrap();
        let d1 = digest(&b1);
        let p1_back = Phase1::read(&b1[..]).unwrap();
        assert_eq!(p1_back, p1);
        let p2 = p1_back.contribute(d1, &mut rng);
        Phase1::verify_transition(&p1, d1, &p2, &mut rng).unwrap();
        // not built on this accumulator
        let e = Phase1::verify_transition(&p0, d0, &p2, &mut rng).unwrap_err();
        assert!(e.to_string().contains("not built on"), "{e}");
        // a contribution without its key
        let mut nokey = p1.clone();
        nokey.key = None;
        let e = Phase1::verify_transition(&p0, d0, &nokey, &mut rng).unwrap_err();
        assert!(e.to_string().contains("no contribution key"), "{e}");
        // a tampered power
        let mut t = p2.clone();
        t.tau_g1[3] = t.tau_g1[4];
        let e = Phase1::verify_transition(&p1, d1, &t, &mut rng).unwrap_err();
        assert!(e.to_string().contains("G1 powers"), "{e}");
        let mut t = p2.clone();
        t.tau_g2[2] = t.tau_g2[3];
        assert!(Phase1::verify_transition(&p1, d1, &t, &mut rng).is_err());
        let mut t = p2.clone();
        t.alpha_tau_g1[2] = t.alpha_tau_g1[3];
        let e = Phase1::verify_transition(&p1, d1, &t, &mut rng).unwrap_err();
        assert!(e.to_string().contains("alpha powers"), "{e}");
        let mut t = p2.clone();
        t.beta_tau_g1[2] = t.beta_tau_g1[3];
        let e = Phase1::verify_transition(&p1, d1, &t, &mut rng).unwrap_err();
        assert!(e.to_string().contains("beta powers"), "{e}");
        // a key that does not match the accumulator (alpha of another contribution)
        let mut t = p2.clone();
        t.key.as_mut().unwrap().alpha = p1.key.clone().unwrap().alpha;
        let e = Phase1::verify_transition(&p1, d1, &t, &mut rng).unwrap_err();
        assert!(e.to_string().contains("alpha"), "{e}");
        // beta applied to G1 but not G2
        let mut t = p2.clone();
        t.beta_g2 = p1.beta_g2;
        let e = Phase1::verify_transition(&p1, d1, &t, &mut rng).unwrap_err();
        assert!(e.to_string().contains("beta differs"), "{e}");
        // index 0 replaced
        let mut t = p2.clone();
        t.tau_g1[0] = t.tau_g1[1];
        assert!(
            t.verify_shape(&mut rng)
                .unwrap_err()
                .to_string()
                .contains("generator")
        );
        // another domain size
        let other = Phase1::new(4).unwrap();
        assert!(Phase1::verify_transition(&other, d1, &p2, &mut rng).is_err());
        // a point on the curve but outside the prime-order subgroup
        let mut t = p2.clone();
        let mut x = ark_bls12_381::Fq::from(5u64);
        let rogue = loop {
            if let Some(q) = G1Affine::get_point_from_x_unchecked(x, true) {
                if !q.is_in_correct_subgroup_assuming_on_curve() {
                    break q;
                }
            }
            x += ark_bls12_381::Fq::from(1u64);
        };
        t.tau_g1[2] = rogue;
        let e = Phase1::read(&t.to_bytes().unwrap()[..]).unwrap_err();
        assert!(e.to_string().contains("subgroup"), "{e}");
        // file checks
        assert!(Phase1::read(&b"sbp2"[..]).is_err());
        let mut junk = b1.clone();
        junk[4] ^= 1;
        assert!(Phase1::read(&junk[..]).is_err());
        assert!(Phase1::read(&b1[..b1.len() - 10]).is_err());
    }
}
