//! The split transcript of `docs/REPLAY-PROOF-A.md` §3.6 (the candidate
//! a-0.4 rule), natively, for Vesta-committed proofs: two duplex Poseidon
//! sponges — one over `Fq` that absorbs the points, one over `Fp` that
//! absorbs the scalars, each natively — a challenge squeezed from the
//! sponge that absorbed last and then absorbed into the other, so that
//! each sponge's state depends on the whole history through the
//! challenges. A *common* scalar (the key's representative, absorbed by
//! the verifier and not read from the proof) goes into both sponges, so
//! that every challenge depends on the key. Challenges are 128 bits, as
//! a-0.3's.
//!
//! What it buys: the circuit over `Fq` that verifies the group side
//! absorbs no evaluation (it takes `x_1, x_2, x_4` as witnesses), and the
//! circuit over `Fp` that verifies the field side absorbs the evaluations
//! natively and squeezes those three itself.

use std::io::{self, Read, Write};

use ff::{Field, PrimeField};
use group::GroupEncoding;
use halo2_proofs::arithmetic::{Coordinates, CurveAffine};
use halo2_proofs::transcript::{EncodedChallenge, Transcript, TranscriptRead, TranscriptWrite};
use pasta_curves::vesta;

use crate::native::{Challenge, Sponge};
use sba_primitives::Fp;

type Fq = vesta::Base;
type C = vesta::Affine;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Last {
    Points,
    Scalars,
}

/// The two sponges and the rule.
#[derive(Clone, Debug)]
pub struct SplitSponge {
    /// Over `Fq`, the points.
    pub points: Sponge<vesta::Affine>,
    /// Over `Fp`, the scalars (a Pallas-typed sponge: its base field is `Fp`).
    pub scalars: Sponge<pasta_curves::pallas::Affine>,
    last: Last,
    /// Whether the key's representative has been absorbed: the rule opens
    /// the transcript with it (into both sponges), and every other
    /// operation before it is a mistake in the caller's order.
    opened: bool,
}

/// Which sponge a challenge came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum From {
    Points,
    Scalars,
}

impl Default for SplitSponge {
    fn default() -> Self {
        SplitSponge {
            points: Sponge::default(),
            scalars: Sponge::default(),
            // the first absorption is the key's representative, a scalar
            last: Last::Scalars,
            opened: false,
        }
    }
}

fn low128(repr: &[u8]) -> u128 {
    u128::from_le_bytes(repr[..16].try_into().unwrap())
}

impl SplitSponge {
    fn opened(&self) {
        assert!(
            self.opened,
            "the split transcript opens with the key's representative (absorb_common_scalar)"
        );
    }

    pub fn absorb_point(&mut self, p: C) -> io::Result<()> {
        self.opened();
        let coords: Coordinates<C> = Option::from(p.coordinates())
            .ok_or_else(|| io::Error::other("cannot write points at infinity to the transcript"))?;
        self.points.absorb(*coords.x());
        self.points.absorb(*coords.y());
        self.last = Last::Points;
        Ok(())
    }

    /// A scalar read from the proof: into the `Fp` sponge.
    pub fn absorb_scalar(&mut self, s: Fp) {
        self.opened();
        self.scalars.absorb(s);
        self.last = Last::Scalars;
    }

    /// A scalar the verifier supplies (the key's representative): into both.
    pub fn absorb_common_scalar(&mut self, s: Fp) {
        self.opened = true;
        self.scalars.absorb(s);
        self.points
            .absorb(Fq::from_repr(s.to_repr()).expect("p < q"));
        self.last = Last::Scalars;
    }

    /// The challenge (128 bits) and which sponge produced it; the other
    /// sponge absorbs it.
    pub fn squeeze(&mut self) -> (u128, From) {
        self.opened();
        match self.last {
            Last::Points => {
                let c = low128(&self.points.squeeze().to_repr());
                self.scalars.absorb(Fp::from_u128(c));
                (c, From::Points)
            }
            Last::Scalars => {
                let c = low128(&self.scalars.squeeze().to_repr());
                self.points.absorb(Fq::from_u128(c));
                (c, From::Scalars)
            }
        }
    }
}

fn challenge(c: u128) -> Challenge<C> {
    Challenge::new(&Fq::from_u128(c))
}

/// The prover's side.
pub struct SplitWrite<W: Write> {
    pub sponge: SplitSponge,
    writer: W,
}

impl<W: Write> SplitWrite<W> {
    pub fn init(writer: W) -> Self {
        SplitWrite {
            sponge: SplitSponge::default(),
            writer,
        }
    }
    pub fn finalize(self) -> W {
        self.writer
    }
}

impl<W: Write> Transcript<C, Challenge<C>> for SplitWrite<W> {
    fn squeeze_challenge(&mut self) -> Challenge<C> {
        challenge(self.sponge.squeeze().0)
    }
    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.sponge.absorb_point(point)
    }
    fn common_scalar(&mut self, scalar: Fp) -> io::Result<()> {
        self.sponge.absorb_common_scalar(scalar);
        Ok(())
    }
}

impl<W: Write> TranscriptWrite<C, Challenge<C>> for SplitWrite<W> {
    fn write_point(&mut self, point: C) -> io::Result<()> {
        self.sponge.absorb_point(point)?;
        self.writer.write_all(point.to_bytes().as_ref())
    }
    fn write_scalar(&mut self, scalar: Fp) -> io::Result<()> {
        self.sponge.absorb_scalar(scalar);
        self.writer.write_all(scalar.to_repr().as_ref())
    }
}

/// What the verifier does, as events for the circuits.
#[derive(Clone, Debug)]
pub enum Event {
    CommonScalar(Fp),
    CommonPoint(C),
    ReadPoint(C),
    ReadScalar(Fp),
    /// A challenge and the sponge that produced it.
    Squeeze(Fp, From),
}

/// The verifier's side, recording.
pub struct SplitRead<R: Read> {
    pub sponge: SplitSponge,
    reader: R,
    pub events: Vec<Event>,
}

impl<R: Read> SplitRead<R> {
    pub fn init(reader: R) -> Self {
        SplitRead {
            sponge: SplitSponge::default(),
            reader,
            events: Vec::new(),
        }
    }
}

impl<R: Read> Transcript<C, Challenge<C>> for SplitRead<R> {
    fn squeeze_challenge(&mut self) -> Challenge<C> {
        let (c, from) = self.sponge.squeeze();
        self.events.push(Event::Squeeze(Fp::from_u128(c), from));
        challenge(c)
    }
    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.events.push(Event::CommonPoint(point));
        self.sponge.absorb_point(point)
    }
    fn common_scalar(&mut self, scalar: Fp) -> io::Result<()> {
        self.events.push(Event::CommonScalar(scalar));
        self.sponge.absorb_common_scalar(scalar);
        Ok(())
    }
}

impl<R: Read> TranscriptRead<C, Challenge<C>> for SplitRead<R> {
    fn read_point(&mut self) -> io::Result<C> {
        let mut compressed = <C as GroupEncoding>::Repr::default();
        self.reader.read_exact(compressed.as_mut())?;
        let point: C = Option::from(C::from_bytes(&compressed))
            .ok_or_else(|| io::Error::other("invalid point encoding in proof"))?;
        self.events.push(Event::ReadPoint(point));
        self.sponge.absorb_point(point)?;
        Ok(point)
    }
    fn read_scalar(&mut self) -> io::Result<Fp> {
        let mut data = <Fp as PrimeField>::Repr::default();
        self.reader.read_exact(data.as_mut())?;
        let scalar: Fp = Option::from(Fp::from_repr(data))
            .ok_or_else(|| io::Error::other("invalid field element encoding in proof"))?;
        self.events.push(Event::ReadScalar(scalar));
        self.sponge.absorb_scalar(scalar);
        Ok(scalar)
    }
}

/// The capture of a proof under the split transcript: the a-0.3 shaped
/// capture (so that `shadow` reads it) and, per challenge, which sponge
/// produced it.
pub fn capture_split(
    params: &halo2_proofs::poly::commitment::Params<C>,
    vk: &halo2_proofs::plonk::VerifyingKey<C>,
    instance: &[Fp],
    proof: &[u8],
) -> Result<(crate::capture::Capture<C>, Vec<From>), halo2_proofs::plonk::Error> {
    use crate::capture::{Capture, Deferred, Event as E};
    let mut transcript = SplitRead::init(proof);
    let out = halo2_proofs::plonk::verify_proof(
        params,
        vk,
        Deferred(params),
        &[&[instance]],
        &mut transcript,
    )?;
    let (g_scalars, w_scalar, u_scalar, other) = out.msm.fingerprint_terms();
    let mut terms: Vec<(Fp, C)> = other
        .into_iter()
        .map(|(s, x, y)| (s, C::from_xy(x, y).unwrap()))
        .collect();
    if let Some(gs) = g_scalars {
        let g = params.get_g();
        for (i, s) in gs.iter().enumerate() {
            if !bool::from(s.is_zero()) {
                terms.push((*s, g[i]));
            }
        }
    }
    let mut froms = Vec::new();
    let events = transcript
        .events
        .iter()
        .map(|e| match e {
            Event::CommonScalar(s) => E::CommonScalar(*s),
            Event::CommonPoint(p) => E::CommonPoint(*p),
            Event::ReadPoint(p) => E::ReadPoint(*p),
            Event::ReadScalar(s) => E::ReadScalar(*s),
            Event::Squeeze(s, f) => {
                froms.push(*f);
                E::Squeeze(*s)
            }
        })
        .collect();
    Ok((
        Capture {
            instance: instance.to_vec(),
            events,
            terms,
            w_scalar: w_scalar.unwrap_or(Fp::ZERO),
            u_scalar: u_scalar.unwrap_or(Fp::ZERO),
            g: out.g,
            u: out.u,
            opened: vec![],
        },
        froms,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::Params;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sba_circuit::{K, TransferCircuit};

    /// A transfer proof under the split transcript: proven, verified, its
    /// challenges by sponge as §3.6 lists them.
    #[test]
    fn a_transfer_proof_under_the_split_transcript() {
        let (st, w) = crate::sample::sample();
        let params: Params<vesta::Affine> = Params::new(K);
        let vk = plonk::keygen_vk(&params, &TransferCircuit::default()).unwrap();
        let pk = plonk::keygen_pk(&params, vk.clone(), &TransferCircuit::default()).unwrap();
        let circuit = TransferCircuit {
            statement: Some(st.clone()),
            witness: Some(w),
            negate_g_d: false,
        };
        let instance = st.to_field_elements();
        let mut tr = SplitWrite::init(vec![]);
        plonk::create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&instance[..]]],
            &mut StdRng::seed_from_u64(61),
            &mut tr,
        )
        .unwrap();
        let proof = tr.finalize();
        assert_eq!(proof.len(), 4416, "the bytes are a-0.3's");
        let mut tr = SplitRead::init(&proof[..]);
        plonk::verify_proof(
            &params,
            &vk,
            plonk::SingleVerifier::new(&params),
            &[&[&instance[..]]],
            &mut tr,
        )
        .unwrap();
        let froms: Vec<From> = tr
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Squeeze(_, f) => Some(*f),
                _ => None,
            })
            .collect();
        // θ β γ y x from the points; x_1 x_2 from the scalars; x_3 from the
        // points; x_4 from the scalars; ξ z and the 14 u_j from the points
        let mut expected = vec![From::Points; 5];
        expected.extend([From::Scalars, From::Scalars, From::Points, From::Scalars]);
        expected.extend(vec![From::Points; 2 + K as usize]);
        assert_eq!(froms, expected);
        // the a-0.3 verifier refuses it, and a tampered proof fails here
        let mut tr = crate::native::PoseidonRead::<_, vesta::Affine>::init(&proof[..]);
        assert!(
            plonk::verify_proof(
                &params,
                &vk,
                plonk::SingleVerifier::new(&params),
                &[&[&instance[..]]],
                &mut tr,
            )
            .is_err()
        );
        let mut bad = proof.clone();
        bad[300] ^= 1;
        let mut tr = SplitRead::init(&bad[..]);
        assert!(
            plonk::verify_proof(
                &params,
                &vk,
                plonk::SingleVerifier::new(&params),
                &[&[&instance[..]]],
                &mut tr,
            )
            .is_err()
        );
    }
}
