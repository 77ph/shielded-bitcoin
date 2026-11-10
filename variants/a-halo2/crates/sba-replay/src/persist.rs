//! What the chain keeps between runs, as bytes: a verified proof's capture
//! (the previous step's two), the chain prover's state and the client's.
//! Each format starts with a version byte; points are 32-byte compressed
//! encodings, scalars 32-byte canonical ones, lengths little-endian `u32`.

use ff::PrimeField;
use halo2_proofs::arithmetic::CurveAffine;
use pasta_curves::{pallas, vesta};
use sba_primitives::Fp;

use crate::capture::{Capture, Event};
use crate::wire::{Rd, put_bytes, put_u32};

fn put_scalar<F: PrimeField>(out: &mut Vec<u8>, v: &F) {
    out.extend_from_slice(v.to_repr().as_ref());
}
fn put_point<C: CurveAffine>(out: &mut Vec<u8>, p: &C) {
    out.extend_from_slice(p.to_bytes().as_ref());
}
fn put_scalars<F: PrimeField>(out: &mut Vec<u8>, v: &[F]) {
    put_u32(out, v.len() as u32);
    for s in v {
        put_scalar(out, s);
    }
}

impl Rd<'_> {
    pub(crate) fn scalar<F: PrimeField>(&mut self) -> Result<F, String> {
        let mut r = F::Repr::default();
        let n = r.as_ref().len();
        r.as_mut().copy_from_slice(self.take(n)?);
        Option::from(F::from_repr(r)).ok_or_else(|| "a non-canonical scalar".to_string())
    }
    pub(crate) fn point<C: CurveAffine>(&mut self) -> Result<C, String> {
        let mut r = C::Repr::default();
        let n = r.as_ref().len();
        r.as_mut().copy_from_slice(self.take(n)?);
        Option::from(C::from_bytes(&r)).ok_or_else(|| "not a point".to_string())
    }
    fn scalars<F: PrimeField>(&mut self) -> Result<Vec<F>, String> {
        let n = self.u32()? as usize;
        (0..n).map(|_| self.scalar()).collect()
    }
}

impl<C: CurveAffine> Capture<C> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_scalars(&mut out, &self.instance);
        put_u32(&mut out, self.events.len() as u32);
        for e in &self.events {
            match e {
                Event::CommonPoint(p) => {
                    out.push(0);
                    put_point(&mut out, p);
                }
                Event::CommonScalar(s) => {
                    out.push(1);
                    put_scalar(&mut out, s);
                }
                Event::ReadPoint(p) => {
                    out.push(2);
                    put_point(&mut out, p);
                }
                Event::ReadScalar(s) => {
                    out.push(3);
                    put_scalar(&mut out, s);
                }
                Event::Squeeze(s) => {
                    out.push(4);
                    put_scalar(&mut out, s);
                }
            }
        }
        put_u32(&mut out, self.terms.len() as u32);
        for (s, p) in &self.terms {
            put_scalar(&mut out, s);
            put_point(&mut out, p);
        }
        put_scalar(&mut out, &self.w_scalar);
        put_scalar(&mut out, &self.u_scalar);
        put_point(&mut out, &self.g);
        put_scalars(&mut out, &self.u);
        put_u32(&mut out, self.opened.len() as u32);
        for u in &self.opened {
            put_scalars(&mut out, u);
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let mut rd = Rd(b);
        let c = Self::read(&mut rd)?;
        if !rd.0.is_empty() {
            return Err("trailing bytes".into());
        }
        Ok(c)
    }

    pub(crate) fn read(rd: &mut Rd<'_>) -> Result<Self, String> {
        let instance = rd.scalars()?;
        let n = rd.u32()? as usize;
        let mut events = Vec::with_capacity(n);
        for _ in 0..n {
            events.push(match rd.take(1)?[0] {
                0 => Event::CommonPoint(rd.point()?),
                1 => Event::CommonScalar(rd.scalar()?),
                2 => Event::ReadPoint(rd.point()?),
                3 => Event::ReadScalar(rd.scalar()?),
                4 => Event::Squeeze(rd.scalar()?),
                t => return Err(format!("event tag {t}")),
            });
        }
        let n = rd.u32()? as usize;
        let mut terms = Vec::with_capacity(n);
        for _ in 0..n {
            terms.push((rd.scalar()?, rd.point()?));
        }
        let w_scalar = rd.scalar()?;
        let u_scalar = rd.scalar()?;
        let g = rd.point()?;
        let u = rd.scalars()?;
        let n = rd.u32()? as usize;
        let mut opened = Vec::with_capacity(n);
        for _ in 0..n {
            opened.push(rd.scalars()?);
        }
        Ok(Capture {
            instance,
            events,
            terms,
            w_scalar,
            u_scalar,
            g,
            u,
            opened,
        })
    }
}

/// The chain prover's state between runs: which key set, how many steps,
/// the digest after the last one, the block the next step takes, and the
/// previous step's two captures (the dummy step 0's before the first).
#[derive(Clone, Debug)]
pub struct ChainState {
    pub keys_id: [u8; 32],
    pub index: u32,
    pub next_height: u32,
    pub s: Fp,
    pub cap_q: Capture<pallas::Affine>,
    pub cap_p: Capture<vesta::Affine>,
}

const CHAIN_STATE_VERSION: u8 = 1;

impl ChainState {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![CHAIN_STATE_VERSION];
        out.extend_from_slice(&self.keys_id);
        put_u32(&mut out, self.index);
        put_u32(&mut out, self.next_height);
        put_scalar(&mut out, &self.s);
        put_bytes(&mut out, &self.cap_q.to_bytes());
        put_bytes(&mut out, &self.cap_p.to_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let mut rd = Rd(b);
        if rd.take(1)?[0] != CHAIN_STATE_VERSION {
            return Err("chain state version".into());
        }
        let keys_id: [u8; 32] = rd.take(32)?.try_into().unwrap();
        let index = rd.u32()?;
        let next_height = rd.u32()?;
        let s = rd.scalar()?;
        let cap_q = Capture::from_bytes(&rd.bytes()?)?;
        let cap_p = Capture::from_bytes(&rd.bytes()?)?;
        if !rd.0.is_empty() {
            return Err("trailing bytes".into());
        }
        Ok(ChainState {
            keys_id,
            index,
            next_height,
            s,
            cap_q,
            cap_p,
        })
    }
}

/// The client's state: which key set, how many steps decided, the digest
/// after the last one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientState {
    pub keys_id: [u8; 32],
    pub index: u32,
    pub s: Fp,
}

const CLIENT_STATE_VERSION: u8 = 1;

impl ClientState {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![CLIENT_STATE_VERSION];
        out.extend_from_slice(&self.keys_id);
        put_u32(&mut out, self.index);
        put_scalar(&mut out, &self.s);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let mut rd = Rd(b);
        if rd.take(1)?[0] != CLIENT_STATE_VERSION {
            return Err("client state version".into());
        }
        let keys_id: [u8; 32] = rd.take(32)?.try_into().unwrap();
        let index = rd.u32()?;
        let s = rd.scalar()?;
        if !rd.0.is_empty() {
            return Err("trailing bytes".into());
        }
        Ok(ClientState { keys_id, index, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use group::{Curve, Group};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn capture<C: CurveAffine>(rng: &mut StdRng, n: usize) -> Capture<C>
    where
        C::Curve: Group<Scalar = C::Scalar>,
    {
        let p = |rng: &mut StdRng| C::Curve::random(&mut *rng).to_affine();
        let s = |rng: &mut StdRng| C::Scalar::random(&mut *rng);
        let mut events = vec![Event::CommonScalar(s(rng)), Event::CommonPoint(p(rng))];
        for _ in 0..n {
            events.push(Event::ReadPoint(p(rng)));
            events.push(Event::ReadScalar(s(rng)));
            events.push(Event::Squeeze(s(rng)));
        }
        Capture {
            instance: (0..n).map(|_| s(rng)).collect(),
            events,
            terms: (0..n).map(|_| (s(rng), p(rng))).collect(),
            w_scalar: s(rng),
            u_scalar: s(rng),
            g: p(rng),
            u: (0..n).map(|_| s(rng)).collect(),
            opened: vec![(0..n).map(|_| s(rng)).collect(), vec![]],
        }
    }

    #[test]
    fn captures_and_states_round_trip() {
        let mut rng = StdRng::seed_from_u64(7);
        let cq: Capture<pallas::Affine> = capture(&mut rng, 5);
        let cp: Capture<vesta::Affine> = capture(&mut rng, 3);
        let bq = cq.to_bytes();
        assert_eq!(
            Capture::<pallas::Affine>::from_bytes(&bq)
                .unwrap()
                .to_bytes(),
            bq
        );
        assert!(Capture::<pallas::Affine>::from_bytes(&bq[..bq.len() - 1]).is_err());
        let mut bad = bq.clone();
        bad.push(0);
        assert!(Capture::<pallas::Affine>::from_bytes(&bad).is_err());
        let state = ChainState {
            keys_id: [9; 32],
            index: 3,
            next_height: 1003,
            s: Fp::from(77u64),
            cap_q: cq,
            cap_p: cp,
        };
        let b = state.to_bytes();
        let back = ChainState::from_bytes(&b).unwrap();
        assert_eq!(back.to_bytes(), b);
        assert_eq!(
            (back.index, back.next_height, back.s),
            (3, 1003, Fp::from(77u64))
        );
        let mut other = b.clone();
        other[0] = 2;
        assert!(ChainState::from_bytes(&other).is_err());
        let client = ClientState {
            keys_id: [9; 32],
            index: 3,
            s: Fp::from(77u64),
        };
        assert_eq!(ClientState::from_bytes(&client.to_bytes()).unwrap(), client);
    }
}
