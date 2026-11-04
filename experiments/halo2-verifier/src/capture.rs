//! What the native verifier does with one proof, captured for the circuit
//! that verifies its group side: the transcript's events in order (points
//! and scalars absorbed, challenges squeezed), the accumulated final
//! multi-scalar multiplication (every commitment with its combined scalar,
//! the `W` and `U` terms, `[-c] G` for the prover-supplied `G`), and the
//! claim `(G, u_1 … u_k)` a later proof on the same curve opens. Built on
//! `halo2_proofs`' own verifier through a `VerificationStrategy` that keeps
//! the guard's deferred form (`Guard::use_g`), `REPLAY-PROOF-A.md` §2's
//! accumulated mode. Generic over the curve: Vesta for the family's
//! transfer proofs, Pallas for the recursion's own.

use std::io::{self, Read};

use ff::Field;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::{self, Error, VerificationStrategy, VerifyingKey};
use halo2_proofs::poly::commitment::{Claim, Guard, Params, MSM};
use halo2_proofs::transcript::{EncodedChallenge, Transcript, TranscriptRead};

use crate::native::{Challenge, Limbs, PoseidonField, PoseidonRead};

#[derive(Clone, Debug)]
pub enum Event<C: CurveAffine> {
    /// A point absorbed without being read: the instance commitment, then
    /// the `G` of every claim the proof opens.
    CommonPoint(C),
    /// A scalar absorbed without being read (the key's representative).
    CommonScalar(C::Scalar),
    ReadPoint(C),
    ReadScalar(C::Scalar),
    /// A squeezed 128-bit challenge, as the scalar-field integer.
    Squeeze(C::Scalar),
}

/// The Poseidon transcript, recording.
pub struct Recorder<R: Read, C: Limbs>
where
    C::Base: PoseidonField,
{
    inner: PoseidonRead<R, C>,
    pub events: Vec<Event<C>>,
}

impl<R: Read, C: Limbs> Recorder<R, C>
where
    C::Base: PoseidonField,
{
    pub fn init(reader: R) -> Self {
        Recorder {
            inner: PoseidonRead::init(reader),
            events: Vec::new(),
        }
    }
}

impl<R: Read, C: Limbs> Transcript<C, Challenge<C>> for Recorder<R, C>
where
    C::Base: PoseidonField,
{
    fn squeeze_challenge(&mut self) -> Challenge<C> {
        let c = self.inner.squeeze_challenge();
        self.events.push(Event::Squeeze(c.get_scalar()));
        c
    }
    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.events.push(Event::CommonPoint(point));
        self.inner.common_point(point)
    }
    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.events.push(Event::CommonScalar(scalar));
        self.inner.common_scalar(scalar)
    }
}

impl<R: Read, C: Limbs> TranscriptRead<C, Challenge<C>> for Recorder<R, C>
where
    C::Base: PoseidonField,
{
    fn read_point(&mut self) -> io::Result<C> {
        let p = self.inner.read_point()?;
        self.events.push(Event::ReadPoint(p));
        Ok(p)
    }
    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        let s = self.inner.read_scalar()?;
        self.events.push(Event::ReadScalar(s));
        Ok(s)
    }
}

/// The accumulated final MSM and the claim.
#[derive(Clone, Debug)]
pub struct Capture<C: CurveAffine> {
    /// The instance column's values.
    pub instance: Vec<C::Scalar>,
    pub events: Vec<Event<C>>,
    /// `(scalar, point)` over the commitments, `[-c] G` included.
    pub terms: Vec<(C::Scalar, C)>,
    /// Scalars of the parameters' `W` and `U`.
    pub w_scalar: C::Scalar,
    pub u_scalar: C::Scalar,
    /// The prover's `G` and the inner-product challenges.
    pub g: C,
    pub u: Vec<C::Scalar>,
}

impl<C: CurveAffine> Capture<C> {
    /// The sum the circuit must find to be the identity.
    pub fn sum(&self, params: &Params<C>) -> C::Curve {
        let mut acc = C::Curve::default();
        for (s, p) in &self.terms {
            acc += *p * s;
        }
        acc += params.get_w() * self.w_scalar;
        acc += params.get_u() * self.u_scalar;
        acc
    }

    /// The claim this proof leaves for a later proof on its curve.
    pub fn claim(&self) -> Claim<C> {
        Claim {
            g: self.g,
            u: self.u.clone(),
        }
    }

    pub fn points_read(&self) -> Vec<C> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::ReadPoint(p) => Some(*p),
                _ => None,
            })
            .collect()
    }

    /// The common points in order: the instance commitment, then the
    /// opened claims' `G`.
    pub fn common_points(&self) -> Vec<C> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::CommonPoint(p) => Some(*p),
                _ => None,
            })
            .collect()
    }
}

struct Deferred<'p, C: CurveAffine>(&'p Params<C>);

struct Out<'p, C: CurveAffine> {
    msm: MSM<'p, C>,
    g: C,
    u: Vec<C::Scalar>,
}

impl<'p, C: CurveAffine> VerificationStrategy<'p, C> for Deferred<'p, C> {
    type Output = Out<'p, C>;
    fn process<E: EncodedChallenge<C>>(
        self,
        f: impl FnOnce(MSM<'p, C>) -> Result<Guard<'p, C, E>, Error>,
    ) -> Result<Self::Output, Error> {
        let guard = f(MSM::new(self.0))?;
        let g = guard.compute_g();
        let (msm, acc) = guard.use_g(g);
        let u = acc.u_packed.iter().map(|c| c.get_scalar()).collect();
        Ok(Out { msm, g: acc.g, u })
    }
}

/// Run the verifier on `proof` (made over `claims`, possibly none) and
/// capture everything the circuit needs.
pub fn capture<C: Limbs>(
    params: &Params<C>,
    vk: &VerifyingKey<C>,
    instance: &[C::Scalar],
    proof: &[u8],
    claims: &[Claim<C>],
) -> Result<Capture<C>, Error>
where
    C::Base: PoseidonField,
{
    let mut transcript = Recorder::<_, C>::init(proof);
    let out = plonk::verify_proof_with_openings(
        params,
        vk,
        Deferred(params),
        &[&[instance]],
        &mut transcript,
        claims,
    )?;
    let (g_scalars, w_scalar, u_scalar, other) = out.msm.fingerprint_terms();
    let mut terms: Vec<(C::Scalar, C)> = other
        .into_iter()
        .map(|(s, x, y)| (s, C::from_xy(x, y).unwrap()))
        .collect();
    // the deferred form keeps no generator vector except the constant term
    // `[-v] G_0` the verifier adds before the inner product
    if let Some(gs) = g_scalars {
        let g = params.get_g();
        for (i, s) in gs.iter().enumerate() {
            if !bool::from(s.is_zero()) {
                terms.push((*s, g[i]));
            }
        }
    }
    Ok(Capture {
        instance: instance.to_vec(),
        events: transcript.events,
        terms,
        w_scalar: w_scalar.unwrap_or(C::Scalar::ZERO),
        u_scalar: u_scalar.unwrap_or(C::Scalar::ZERO),
        g: out.g,
        u: out.u,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::prime::PrimeCurveAffine;
    use group::Curve;
    use halo2_proofs::poly::commitment::Params;
    use pasta_curves::vesta;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sba_circuit::{TransferCircuit, TransferParams, K};

    #[test]
    fn a_real_proof_captures_to_an_identity_msm() {
        let params = TransferParams::build().unwrap();
        let (st, w) = crate::sample::sample();
        let mut rng = StdRng::seed_from_u64(3);
        let proof = params.prove(&st, &w, &mut rng).unwrap();
        let halo_params: Params<vesta::Affine> = Params::new(K);
        let vk = plonk::keygen_vk(&halo_params, &TransferCircuit::default()).unwrap();
        let cap = capture(&halo_params, &vk, &st.to_field_elements(), &proof, &[]).unwrap();
        let n =
            |f: &dyn Fn(&Event<vesta::Affine>) -> bool| cap.events.iter().filter(|e| f(e)).count();
        println!(
            "events: {} common points, {} common scalars, {} points read, {} scalars read, {} challenges; msm terms {} (+ W, U); claim u's {}",
            n(&|e| matches!(e, Event::CommonPoint(_))),
            n(&|e| matches!(e, Event::CommonScalar(_))),
            n(&|e| matches!(e, Event::ReadPoint(_))),
            n(&|e| matches!(e, Event::ReadScalar(_))),
            n(&|e| matches!(e, Event::Squeeze(_))),
            cap.terms.len(),
            cap.u.len()
        );
        assert!(bool::from(cap.sum(&halo_params).to_affine().is_identity()));
        assert_eq!(cap.u.len(), K as usize);
        // a tampered proof captures to a non-identity sum (or fails to parse)
        let mut bad = proof.clone();
        bad[100] ^= 1;
        if let Ok(c) = capture(&halo_params, &vk, &st.to_field_elements(), &bad, &[]) {
            assert!(!bool::from(c.sum(&halo_params).to_affine().is_identity()));
        }
    }
}
