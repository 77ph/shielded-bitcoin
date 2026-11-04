//! The proof transcript of `PROFILE-A.md` §1.1: a duplex Poseidon sponge
//! over `Fq` (the field of the Vesta commitments' coordinates) with
//! 128-bit challenges, in place of `halo2_proofs`' Blake2b transcript, so
//! that a verifier written as a circuit over `Fq` can recompute every
//! challenge natively (`REPLAY-PROOF-A.md` §3.2). Proof bytes are the same
//! point and scalar encodings as before; only the challenge derivation
//! differs.
//!
//! The sponge: state `[s0, s1, s2]`, `s2` initialised to the tag
//! `T_TRANSCRIPT`; absorbing adds the element into the next free rate slot
//! (`s0`, then `s1`), permuting first when both are taken; squeezing adds
//! the pending slots, permutes, clears them and returns `s0`, whose low 128
//! bits are the challenge (used as the same integer in `Fp`). A point is
//! absorbed as `x` then `y`; a scalar (an `Fp` element) as the same integer
//! in `Fq` (`p < q`). The verifying key enters as `halo2_proofs` makes it
//! enter every transcript: one absorbed scalar.

use std::io::{self, Read, Write};
use std::marker::PhantomData;

use ff::PrimeField;
use group::GroupEncoding;
use halo2_proofs::arithmetic::{Coordinates, CurveAffine};
use halo2_proofs::transcript::{EncodedChallenge, Transcript, TranscriptRead, TranscriptWrite};
use pasta_curves::vesta;

use sba_primitives::Fp;
use sba_primitives::poseidon_fq::{Fq, permute};

/// `LE_int("sb-a/v1/transcript")` as `Fq`.
pub fn t_transcript() -> Fq {
    let mut b = [0u8; 32];
    let label = b"sb-a/v1/transcript";
    b[..label.len()].copy_from_slice(label);
    Fq::from_repr(b).expect("18 bytes are canonical")
}

/// A 128-bit challenge: the low 16 bytes of a squeezed `Fq` element, as the
/// same integer in `Fp`.
#[derive(Clone, Copy, Debug)]
pub struct Challenge128([u8; 16], PhantomData<vesta::Affine>);

impl EncodedChallenge<vesta::Affine> for Challenge128 {
    type Input = Fq;

    fn new(squeezed: &Fq) -> Self {
        let repr = squeezed.to_repr();
        let mut c = [0u8; 16];
        c.copy_from_slice(&repr[..16]);
        Challenge128(c, PhantomData)
    }

    fn get_scalar(&self) -> Fp {
        Fp::from_u128(u128::from_le_bytes(self.0))
    }
}

/// The duplex sponge shared by the reader and the writer.
#[derive(Clone, Debug)]
pub struct Sponge {
    state: [Fq; 3],
    pending: [Option<Fq>; 2],
}

impl Default for Sponge {
    fn default() -> Self {
        Sponge {
            state: [Fq::ZERO, Fq::ZERO, t_transcript()],
            pending: [None, None],
        }
    }
}

impl Sponge {
    fn flush(&mut self) {
        for (slot, v) in self.state.iter_mut().zip(self.pending.iter_mut()) {
            if let Some(v) = v.take() {
                *slot += v;
            }
        }
        permute(&mut self.state);
    }

    pub fn absorb(&mut self, v: Fq) {
        if self.pending.iter().all(Option::is_some) {
            self.flush();
        }
        let free = self.pending.iter_mut().find(|p| p.is_none()).unwrap();
        *free = Some(v);
    }

    pub fn squeeze(&mut self) -> Fq {
        self.flush();
        self.state[0]
    }

    pub fn absorb_point(&mut self, point: vesta::Affine) -> io::Result<()> {
        let coords: Coordinates<vesta::Affine> = Option::from(point.coordinates())
            .ok_or_else(|| io::Error::other("cannot write points at infinity to the transcript"))?;
        self.absorb(*coords.x());
        self.absorb(*coords.y());
        Ok(())
    }

    pub fn absorb_scalar(&mut self, scalar: Fp) {
        // p < q: the integer is the same element of both fields
        self.absorb(Fq::from_repr(scalar.to_repr()).expect("p < q"));
    }
}

use ff::Field;

/// The verifier's side: reads a proof while driving the sponge.
pub struct PoseidonRead<R: Read> {
    sponge: Sponge,
    reader: R,
}

impl<R: Read> PoseidonRead<R> {
    pub fn init(reader: R) -> Self {
        PoseidonRead {
            sponge: Sponge::default(),
            reader,
        }
    }
}

impl<R: Read> Transcript<vesta::Affine, Challenge128> for PoseidonRead<R> {
    fn squeeze_challenge(&mut self) -> Challenge128 {
        Challenge128::new(&self.sponge.squeeze())
    }

    fn common_point(&mut self, point: vesta::Affine) -> io::Result<()> {
        self.sponge.absorb_point(point)
    }

    fn common_scalar(&mut self, scalar: Fp) -> io::Result<()> {
        self.sponge.absorb_scalar(scalar);
        Ok(())
    }
}

impl<R: Read> TranscriptRead<vesta::Affine, Challenge128> for PoseidonRead<R> {
    fn read_point(&mut self) -> io::Result<vesta::Affine> {
        let mut compressed = <vesta::Affine as GroupEncoding>::Repr::default();
        self.reader.read_exact(compressed.as_mut())?;
        let point: vesta::Affine = Option::from(vesta::Affine::from_bytes(&compressed))
            .ok_or_else(|| io::Error::other("invalid point encoding in proof"))?;
        self.common_point(point)?;
        Ok(point)
    }

    fn read_scalar(&mut self) -> io::Result<Fp> {
        let mut data = <Fp as PrimeField>::Repr::default();
        self.reader.read_exact(data.as_mut())?;
        let scalar: Fp = Option::from(Fp::from_repr(data))
            .ok_or_else(|| io::Error::other("invalid field element encoding in proof"))?;
        self.common_scalar(scalar)?;
        Ok(scalar)
    }
}

/// The prover's side: writes a proof while driving the sponge.
pub struct PoseidonWrite<W: Write> {
    sponge: Sponge,
    writer: W,
}

impl<W: Write> PoseidonWrite<W> {
    pub fn init(writer: W) -> Self {
        PoseidonWrite {
            sponge: Sponge::default(),
            writer,
        }
    }

    pub fn finalize(self) -> W {
        self.writer
    }
}

impl<W: Write> Transcript<vesta::Affine, Challenge128> for PoseidonWrite<W> {
    fn squeeze_challenge(&mut self) -> Challenge128 {
        Challenge128::new(&self.sponge.squeeze())
    }

    fn common_point(&mut self, point: vesta::Affine) -> io::Result<()> {
        self.sponge.absorb_point(point)
    }

    fn common_scalar(&mut self, scalar: Fp) -> io::Result<()> {
        self.sponge.absorb_scalar(scalar);
        Ok(())
    }
}

impl<W: Write> TranscriptWrite<vesta::Affine, Challenge128> for PoseidonWrite<W> {
    fn write_point(&mut self, point: vesta::Affine) -> io::Result<()> {
        self.common_point(point)?;
        let compressed = point.to_bytes();
        self.writer.write_all(compressed.as_ref())
    }

    fn write_scalar(&mut self, scalar: Fp) -> io::Result<()> {
        self.common_scalar(scalar)?;
        let data = scalar.to_repr();
        self.writer.write_all(data.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_depend_on_everything_absorbed_and_are_128_bits() {
        let mut a = Sponge::default();
        let mut b = Sponge::default();
        a.absorb_scalar(Fp::from(1u64));
        b.absorb_scalar(Fp::from(2u64));
        let ca = Challenge128::new(&a.squeeze());
        let cb = Challenge128::new(&b.squeeze());
        assert_ne!(ca.0, cb.0);
        assert!(ca.get_scalar().to_repr()[16..].iter().all(|&x| x == 0));
        // the same sequence gives the same challenge; a second squeeze differs
        let mut c = Sponge::default();
        c.absorb_scalar(Fp::from(1u64));
        assert_eq!(Challenge128::new(&c.squeeze()).0, ca.0);
        assert_ne!(Challenge128::new(&c.squeeze()).0, ca.0);
        // three absorbs cross a rate boundary without losing the first
        let mut d = Sponge::default();
        let mut e = Sponge::default();
        for v in [3u64, 4, 5] {
            d.absorb_scalar(Fp::from(v));
        }
        for v in [9u64, 4, 5] {
            e.absorb_scalar(Fp::from(v));
        }
        assert_ne!(d.squeeze(), e.squeeze());
    }
}
