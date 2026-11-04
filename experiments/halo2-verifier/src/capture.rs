//! What the native verifier does with one proof, captured for the circuit:
//! the transcript's events in order (points and scalars absorbed, challenges
//! squeezed), the accumulated final multi-scalar multiplication (the ≈ 55
//! commitments with their combined scalars, the `W` and `U` terms, and
//! `[-c] G` for the prover-supplied `G`), and the claim `(G, u_1 … u_k)`
//! that the next circuit accumulates. Built on `halo2_proofs`' own verifier
//! through a `VerificationStrategy` that keeps the guard's deferred form
//! (`Guard::use_g`), exactly `REPLAY-PROOF-A.md` §2's accumulated mode.

use std::io::{self, Read};

use ff::Field;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::{self, Error, VerificationStrategy, VerifyingKey};
use halo2_proofs::poly::commitment::{Guard, Params, MSM};
use halo2_proofs::transcript::{EncodedChallenge, Transcript, TranscriptRead};
use pasta_curves::vesta;

use sba_circuit::transcript::{Challenge128, PoseidonRead};
use sba_primitives::Fp;

#[derive(Clone, Debug)]
pub enum Event {
    /// A point absorbed without being read (the instance commitment).
    CommonPoint(vesta::Affine),
    /// A scalar absorbed without being read (the key's representative).
    CommonScalar(Fp),
    ReadPoint(vesta::Affine),
    ReadScalar(Fp),
    /// A squeezed 128-bit challenge, as the `Fp` integer.
    Squeeze(Fp),
}

/// The Poseidon transcript, recording.
pub struct Recorder<R: Read> {
    inner: PoseidonRead<R>,
    pub events: Vec<Event>,
}

impl<R: Read> Recorder<R> {
    pub fn init(reader: R) -> Self {
        Recorder {
            inner: PoseidonRead::init(reader),
            events: Vec::new(),
        }
    }
}

impl<R: Read> Transcript<vesta::Affine, Challenge128> for Recorder<R> {
    fn squeeze_challenge(&mut self) -> Challenge128 {
        let c = self.inner.squeeze_challenge();
        self.events.push(Event::Squeeze(c.get_scalar()));
        c
    }

    fn common_point(&mut self, point: vesta::Affine) -> io::Result<()> {
        self.events.push(Event::CommonPoint(point));
        self.inner.common_point(point)
    }

    fn common_scalar(&mut self, scalar: Fp) -> io::Result<()> {
        self.events.push(Event::CommonScalar(scalar));
        self.inner.common_scalar(scalar)
    }
}

impl<R: Read> TranscriptRead<vesta::Affine, Challenge128> for Recorder<R> {
    fn read_point(&mut self) -> io::Result<vesta::Affine> {
        let p = self.inner.read_point()?;
        self.events.push(Event::ReadPoint(p));
        Ok(p)
    }

    fn read_scalar(&mut self) -> io::Result<Fp> {
        let s = self.inner.read_scalar()?;
        self.events.push(Event::ReadScalar(s));
        Ok(s)
    }
}

/// The accumulated final MSM and the claim.
#[derive(Clone, Debug)]
pub struct Capture {
    /// The transfer statement (the instance column's values).
    pub instance: Vec<Fp>,
    pub events: Vec<Event>,
    /// `(scalar, point)` over the commitments, `[-c] G` included.
    pub terms: Vec<(Fp, vesta::Affine)>,
    /// Scalars of the parameters' `W` and `U`.
    pub w_scalar: Fp,
    pub u_scalar: Fp,
    /// The prover's `G` and the inner-product challenges.
    pub g: vesta::Affine,
    pub u: Vec<Fp>,
}

impl Capture {
    /// The sum the circuit must find to be the identity.
    pub fn sum(&self, params: &Params<vesta::Affine>) -> vesta::Point {
        let mut acc = vesta::Point::default();
        for (s, p) in &self.terms {
            acc += *p * s;
        }
        acc += params.get_w() * self.w_scalar;
        acc += params.get_u() * self.u_scalar;
        acc
    }
}

struct Deferred<'p>(&'p Params<vesta::Affine>);

struct Out<'p> {
    msm: MSM<'p, vesta::Affine>,
    g: vesta::Affine,
    u: Vec<Fp>,
}

impl<'p> VerificationStrategy<'p, vesta::Affine> for Deferred<'p> {
    type Output = Out<'p>;
    fn process<E: EncodedChallenge<vesta::Affine>>(
        self,
        f: impl FnOnce(MSM<'p, vesta::Affine>) -> Result<Guard<'p, vesta::Affine, E>, Error>,
    ) -> Result<Self::Output, Error> {
        let guard = f(MSM::new(self.0))?;
        let g = guard.compute_g();
        let (msm, acc) = guard.use_g(g);
        let u = acc.u_packed.iter().map(|c| c.get_scalar()).collect();
        Ok(Out { msm, g: acc.g, u })
    }
}

/// Run the verifier on `proof` and capture everything the circuit needs.
pub fn capture(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    instance: &[Fp],
    proof: &[u8],
) -> Result<Capture, Error> {
    let mut transcript = Recorder::init(proof);
    let out = plonk::verify_proof(
        params,
        vk,
        Deferred(params),
        &[&[instance]],
        &mut transcript,
    )?;
    let (g_scalars, w_scalar, u_scalar, other) = out.msm.fingerprint_terms();
    let mut terms: Vec<(Fp, vesta::Affine)> = other
        .into_iter()
        .map(|(s, x, y)| (s, vesta::Affine::from_xy(x, y).unwrap()))
        .collect();
    // the deferred form keeps no generator vector except the constant term
    // `[-v] G_0` the verifier adds before the inner product (and whatever
    // else is non-zero: none for this circuit, asserted by the test)
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
        w_scalar: w_scalar.unwrap_or(Fp::zero()),
        u_scalar: u_scalar.unwrap_or(Fp::zero()),
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
        let cap = capture(&halo_params, &vk, &st.to_field_elements(), &proof).unwrap();
        let n = |f: &dyn Fn(&Event) -> bool| cap.events.iter().filter(|e| f(e)).count();
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
        if let Ok(c) = capture(&halo_params, &vk, &st.to_field_elements(), &bad) {
            assert!(!bool::from(c.sum(&halo_params).to_affine().is_identity()));
        }
    }
}
