//! The proof transcript of `PROFILE-A.md` §1.1 for either curve of the
//! cycle: a duplex Poseidon sponge over the commitment curve's base field
//! with 128-bit challenges. For Vesta-committed proofs (the family's
//! transfer proofs, circuits over `Fp`) this is `sba_circuit::transcript`
//! exactly (the test checks it); for Pallas-committed proofs (the
//! recursion's `T_q`, circuits over `Fq`) it is the same construction over
//! `Fp`, with one difference forced by `q > p`: a scalar of such a proof
//! (an `Fq` element) does not fit the sponge's field and is absorbed as two
//! 128-bit limbs, low then high — the representation the circuit over `Fp`
//! that verifies the proof uses for it too (`REPLAY-PROOF-A.md` §3.4).

use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::sync::LazyLock;

use ff::{Field, FromUniformBytes, PrimeField};
use halo2_gadgets::poseidon::primitives::{P128Pow5T3, Spec};
use halo2_proofs::arithmetic::{Coordinates, CurveAffine};
use halo2_proofs::transcript::{EncodedChallenge, Transcript, TranscriptRead, TranscriptWrite};
use pasta_curves::{pallas, vesta};

/// How a scalar of a proof over this curve is carried in the base field:
/// one element (the same integer, when the scalar field is the smaller) or
/// two 128-bit limbs (when it is the larger).
pub trait Limbs: CurveAffine {
    const N: usize;
    /// The limbs, low first; entries past `N` are zero.
    fn limbs(s: &Self::Scalar) -> [Self::Base; 2];
    fn from_limbs(l: &[Self::Base]) -> Self::Scalar;
    /// The whole scalar as one base-field element: the same integer, for a
    /// scalar known to be below the base field's order.
    fn embed(s: &Self::Scalar) -> Self::Base {
        let mut repr = <Self::Base as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(s.to_repr().as_ref());
        Self::Base::from_repr(repr).expect("the scalar fits the base field")
    }
    /// `n` cells for a scalar: the whole of it for `n = 1`, its limbs otherwise.
    fn cells(s: &Self::Scalar, n: usize) -> Vec<Self::Base> {
        if n == 1 {
            vec![Self::embed(s)]
        } else {
            Self::limbs(s)[..n].to_vec()
        }
    }
}

impl Limbs for vesta::Affine {
    const N: usize = 1;
    fn limbs(s: &vesta::Scalar) -> [vesta::Base; 2] {
        // p < q: the same integer
        [
            vesta::Base::from_repr(s.to_repr()).expect("p < q"),
            vesta::Base::ZERO,
        ]
    }
    fn from_limbs(l: &[vesta::Base]) -> vesta::Scalar {
        vesta::Scalar::from_repr(l[0].to_repr()).expect("an Fp element embedded in Fq")
    }
}

impl Limbs for pallas::Affine {
    const N: usize = 2;
    fn limbs(s: &pallas::Scalar) -> [pallas::Base; 2] {
        let repr = s.to_repr();
        let mut lo = [0u8; 32];
        lo[..16].copy_from_slice(&repr[..16]);
        let mut hi = [0u8; 32];
        hi[..16].copy_from_slice(&repr[16..]);
        [
            pallas::Base::from_repr(lo).unwrap(),
            pallas::Base::from_repr(hi).unwrap(),
        ]
    }
    fn from_limbs(l: &[pallas::Base]) -> pallas::Scalar {
        let mut repr = [0u8; 32];
        repr[..16].copy_from_slice(&l[0].to_repr()[..16]);
        repr[16..].copy_from_slice(&l[1].to_repr()[..16]);
        pallas::Scalar::from_repr(repr).expect("canonical limbs")
    }
}

/// `LE_int("sb-a/v1/transcript")` in the field.
pub fn tag<F: PrimeField>() -> F {
    let mut b = [0u8; 32];
    let label = b"sb-a/v1/transcript";
    b[..label.len()].copy_from_slice(label);
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(&b);
    F::from_repr(repr).expect("18 bytes are canonical")
}

pub struct Constants<F> {
    pub round_constants: Vec<[F; 3]>,
    pub mds: [[F; 3]; 3],
}

static CONSTANTS_FP: LazyLock<Constants<pallas::Base>> = LazyLock::new(constants);
static CONSTANTS_FQ: LazyLock<Constants<vesta::Base>> = LazyLock::new(constants);

fn constants<F: FromUniformBytes<64> + Ord>() -> Constants<F>
where
    P128Pow5T3: Spec<F, 3, 2>,
{
    let (round_constants, mds, _) = <P128Pow5T3 as Spec<F, 3, 2>>::constants();
    Constants {
        round_constants,
        mds,
    }
}

/// The field's pinned constants (`sba-primitives/src/poseidon_params.rs`).
pub trait PoseidonField: PrimeField {
    fn constants() -> &'static Constants<Self>;
}
impl PoseidonField for pallas::Base {
    fn constants() -> &'static Constants<Self> {
        &CONSTANTS_FP
    }
}
impl PoseidonField for vesta::Base {
    fn constants() -> &'static Constants<Self> {
        &CONSTANTS_FQ
    }
}

/// The `P128Pow5T3` permutation (8 full and 56 partial rounds), as the
/// gadget crate computes it.
pub fn permute<F: PoseidonField>(state: &mut [F; 3]) {
    let c = F::constants();
    let sbox = |x: F| x.square().square() * x;
    for (round, rc) in c.round_constants.iter().enumerate() {
        let full = !(4..4 + 56).contains(&round);
        for (w, r) in state.iter_mut().zip(rc) {
            *w += r;
        }
        if full {
            for w in state.iter_mut() {
                *w = sbox(*w);
            }
        } else {
            state[0] = sbox(state[0]);
        }
        let mut out = [F::ZERO; 3];
        for (i, o) in out.iter_mut().enumerate() {
            for (m, s) in c.mds[i].iter().zip(state.iter()) {
                *o += *m * *s;
            }
        }
        *state = out;
    }
}

/// A 128-bit challenge: the low 16 bytes of a squeezed base-field element,
/// as the same integer in the scalar field.
#[derive(Clone, Copy, Debug)]
pub struct Challenge<C>([u8; 16], PhantomData<C>);

impl<C: CurveAffine> EncodedChallenge<C> for Challenge<C> {
    type Input = C::Base;

    fn new(squeezed: &C::Base) -> Self {
        let repr = squeezed.to_repr();
        let mut c = [0u8; 16];
        c.copy_from_slice(&repr.as_ref()[..16]);
        Challenge(c, PhantomData)
    }

    fn get_scalar(&self) -> C::Scalar {
        C::Scalar::from_u128(u128::from_le_bytes(self.0))
    }
}

/// The duplex sponge shared by the reader and the writer.
#[derive(Clone, Debug)]
pub struct Sponge<C: CurveAffine> {
    state: [C::Base; 3],
    pending: [Option<C::Base>; 2],
}

impl<C: Limbs> Default for Sponge<C>
where
    C::Base: PoseidonField,
{
    fn default() -> Self {
        Sponge {
            state: [C::Base::ZERO, C::Base::ZERO, tag()],
            pending: [None, None],
        }
    }
}

impl<C: Limbs> Sponge<C>
where
    C::Base: PoseidonField,
{
    fn flush(&mut self) {
        for (slot, v) in self.state.iter_mut().zip(self.pending.iter_mut()) {
            if let Some(v) = v.take() {
                *slot += v;
            }
        }
        permute(&mut self.state);
    }

    pub fn absorb(&mut self, v: C::Base) {
        if self.pending.iter().all(Option::is_some) {
            self.flush();
        }
        let free = self.pending.iter_mut().find(|p| p.is_none()).unwrap();
        *free = Some(v);
    }

    pub fn squeeze(&mut self) -> C::Base {
        self.flush();
        self.state[0]
    }

    pub fn absorb_point(&mut self, point: C) -> io::Result<()> {
        let coords: Coordinates<C> = Option::from(point.coordinates())
            .ok_or_else(|| io::Error::other("cannot write points at infinity to the transcript"))?;
        self.absorb(*coords.x());
        self.absorb(*coords.y());
        Ok(())
    }

    pub fn absorb_scalar(&mut self, scalar: C::Scalar) {
        for limb in &C::limbs(&scalar)[..C::N] {
            self.absorb(*limb);
        }
    }
}

/// The verifier's side: reads a proof while driving the sponge.
pub struct PoseidonRead<R: Read, C: Limbs>
where
    C::Base: PoseidonField,
{
    sponge: Sponge<C>,
    reader: R,
}

impl<R: Read, C: Limbs> PoseidonRead<R, C>
where
    C::Base: PoseidonField,
{
    pub fn init(reader: R) -> Self {
        PoseidonRead {
            sponge: Sponge::default(),
            reader,
        }
    }
}

impl<R: Read, C: Limbs> Transcript<C, Challenge<C>> for PoseidonRead<R, C>
where
    C::Base: PoseidonField,
{
    fn squeeze_challenge(&mut self) -> Challenge<C> {
        Challenge::new(&self.sponge.squeeze())
    }
    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.sponge.absorb_point(point)
    }
    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.sponge.absorb_scalar(scalar);
        Ok(())
    }
}

impl<R: Read, C: Limbs> TranscriptRead<C, Challenge<C>> for PoseidonRead<R, C>
where
    C::Base: PoseidonField,
{
    fn read_point(&mut self) -> io::Result<C> {
        let mut compressed = C::Repr::default();
        self.reader.read_exact(compressed.as_mut())?;
        let point: C = Option::from(C::from_bytes(&compressed))
            .ok_or_else(|| io::Error::other("invalid point encoding in proof"))?;
        self.common_point(point)?;
        Ok(point)
    }
    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        let mut data = <C::Scalar as PrimeField>::Repr::default();
        self.reader.read_exact(data.as_mut())?;
        let scalar: C::Scalar = Option::from(C::Scalar::from_repr(data))
            .ok_or_else(|| io::Error::other("invalid field element encoding in proof"))?;
        self.common_scalar(scalar)?;
        Ok(scalar)
    }
}

/// The prover's side: writes a proof while driving the sponge.
pub struct PoseidonWrite<W: Write, C: Limbs>
where
    C::Base: PoseidonField,
{
    sponge: Sponge<C>,
    writer: W,
}

impl<W: Write, C: Limbs> PoseidonWrite<W, C>
where
    C::Base: PoseidonField,
{
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

impl<W: Write, C: Limbs> Transcript<C, Challenge<C>> for PoseidonWrite<W, C>
where
    C::Base: PoseidonField,
{
    fn squeeze_challenge(&mut self) -> Challenge<C> {
        Challenge::new(&self.sponge.squeeze())
    }
    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.sponge.absorb_point(point)
    }
    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.sponge.absorb_scalar(scalar);
        Ok(())
    }
}

impl<W: Write, C: Limbs> TranscriptWrite<C, Challenge<C>> for PoseidonWrite<W, C>
where
    C::Base: PoseidonField,
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        self.common_point(point)?;
        self.writer.write_all(point.to_bytes().as_ref())
    }
    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.common_scalar(scalar)?;
        self.writer.write_all(scalar.to_repr().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{Curve, Group};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sba_primitives::Fp;

    #[test]
    fn over_vesta_it_is_the_family_transcript() {
        use halo2_proofs::transcript::Transcript as _;
        let mut rng = StdRng::seed_from_u64(11);
        let mut ours = PoseidonWrite::<_, vesta::Affine>::init(vec![]);
        let mut theirs = sba_circuit::transcript::PoseidonWrite::init(vec![]);
        for i in 0..40 {
            let p = (vesta::Point::generator() * vesta::Scalar::random(&mut rng)).to_affine();
            let s = Fp::random(&mut rng);
            if i % 3 == 0 {
                ours.write_point(p).unwrap();
                theirs.write_point(p).unwrap();
            } else {
                ours.write_scalar(s).unwrap();
                theirs.write_scalar(s).unwrap();
            }
            if i % 4 == 1 {
                assert_eq!(
                    ours.squeeze_challenge().get_scalar(),
                    theirs.squeeze_challenge().get_scalar()
                );
            }
        }
        assert_eq!(ours.finalize(), theirs.finalize());
        // the permutation over Fq is the family's
        let mut a = [vesta::Base::from(1u64), vesta::Base::from(2u64), tag()];
        let mut b = a;
        permute(&mut a);
        sba_primitives::poseidon_fq::permute(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn pallas_scalars_go_through_two_limbs_and_back() {
        let mut rng = StdRng::seed_from_u64(12);
        for _ in 0..100 {
            let s = pallas::Scalar::random(&mut rng);
            let l = <pallas::Affine as Limbs>::limbs(&s);
            assert!(l.iter().all(|x| x.to_repr()[16..].iter().all(|&b| b == 0)));
            assert_eq!(<pallas::Affine as Limbs>::from_limbs(&l), s);
        }
        // and are absorbed as two elements: a proof's bytes still read back
        let mut w = PoseidonWrite::<_, pallas::Affine>::init(vec![]);
        let s = pallas::Scalar::random(&mut rng);
        let p = (pallas::Point::generator() * pallas::Scalar::random(&mut rng)).to_affine();
        w.write_scalar(s).unwrap();
        w.write_point(p).unwrap();
        let c1 = w.squeeze_challenge().get_scalar();
        let bytes = w.finalize();
        let mut r = PoseidonRead::<_, pallas::Affine>::init(&bytes[..]);
        assert_eq!(r.read_scalar().unwrap(), s);
        assert_eq!(r.read_point().unwrap(), p);
        assert_eq!(r.squeeze_challenge().get_scalar(), c1);
        assert!(c1.to_repr()[16..].iter().all(|&b| b == 0));
    }
}

#[cfg(test)]
mod timing {
    #[test]
    #[ignore]
    fn zs_and_us_of_one_point() {
        use halo2_proofs::poly::commitment::Params;
        let params: Params<pasta_curves::pallas::Affine> = Params::new(15);
        let g = params.get_g_lagrange();
        let t = std::time::Instant::now();
        for p in &g[..4] {
            let v =
                halo2_gadgets::ecc::chip::find_zs_and_us(*p, halo2_gadgets::ecc::chip::NUM_WINDOWS)
                    .unwrap();
            assert_eq!(v.len(), halo2_gadgets::ecc::chip::NUM_WINDOWS);
        }
        println!(
            "find_zs_and_us: {:.2} s per point",
            t.elapsed().as_secs_f64() / 4.0
        );
    }
}
