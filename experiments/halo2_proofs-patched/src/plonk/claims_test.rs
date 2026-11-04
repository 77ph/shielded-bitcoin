//! Claims of earlier proofs opened inside later ones (Halo's amortisation),
//! end to end: three proofs over two parameter sizes, a decider at the end,
//! and the ways it must fail.

use crate::circuit::{Layouter, SimpleFloorPlanner, Value};
use crate::plonk::*;
use crate::poly::commitment::{Claim, Guard, Params, MSM};
use crate::poly::Rotation;
use crate::transcript::{Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge};
use group::prime::PrimeCurveAffine;

use pasta_curves::{EqAffine, Fp};
use rand_core::OsRng;

#[derive(Clone, Debug)]
struct Config {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    s: Selector,
    p: Column<Instance>,
}

/// `a · b = c` with `c` public.
#[derive(Clone, Default)]
struct Mul {
    a: Value<Fp>,
    b: Value<Fp>,
}

impl Mul {
    fn new(a: u64, b: u64) -> (Self, Fp) {
        (
            Mul {
                a: Value::known(Fp::from(a)),
                b: Value::known(Fp::from(b)),
            },
            Fp::from(a * b),
        )
    }
}

impl Circuit<Fp> for Mul {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let p = meta.instance_column();
        let s = meta.selector();
        meta.enable_equality(c);
        meta.enable_equality(p);
        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(s);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            vec![s * (a * b - c)]
        });
        Config { a, b, c, s, p }
    }

    fn synthesize(&self, cfg: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let c = layouter.assign_region(
            || "mul",
            |mut region| {
                cfg.s.enable(&mut region, 0)?;
                region.assign_advice(|| "a", cfg.a, 0, || self.a)?;
                region.assign_advice(|| "b", cfg.b, 0, || self.b)?;
                region.assign_advice(|| "c", cfg.c, 0, || self.a * self.b)
            },
        )?;
        layouter.constrain_instance(c.cell(), cfg.p, 0)
    }
}

/// A strategy that settles the proof's own claim by the full multi-scalar
/// multiplication (the decider) and hands the claim back.
struct Decide<'p>(&'p Params<EqAffine>);

impl<'p> VerificationStrategy<'p, EqAffine> for Decide<'p> {
    type Output = Claim<EqAffine>;
    fn process<E: EncodedChallenge<EqAffine>>(
        self,
        f: impl FnOnce(MSM<'p, EqAffine>) -> Result<Guard<'p, EqAffine, E>, Error>,
    ) -> Result<Claim<EqAffine>, Error> {
        let guard = f(MSM::new(self.0))?;
        let claim = guard.claim();
        let (msm, _) = guard.use_g(claim.g);
        if msm.eval() {
            Ok(claim)
        } else {
            Err(Error::ConstraintSystemFailure)
        }
    }
}

fn prove(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: &Mul,
    public: Fp,
    claims: &[Claim<EqAffine>],
) -> Result<Vec<u8>, Error> {
    let mut t = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof_with_openings(
        params,
        pk,
        std::slice::from_ref(circuit),
        &[&[&[public]]],
        claims,
        OsRng,
        &mut t,
    )?;
    Ok(t.finalize())
}

fn verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    public: Fp,
    claims: &[Claim<EqAffine>],
    proof: &[u8],
) -> Result<Claim<EqAffine>, Error> {
    let mut t = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
    verify_proof_with_openings(params, vk, Decide(params), &[&[&[public]]], &mut t, claims)
}

#[test]
fn claims_chain_through_proofs_of_two_sizes() {
    let p5: Params<EqAffine> = Params::new(5);
    let p6: Params<EqAffine> = Params::new(6);
    let vk5 = keygen_vk(&p5, &Mul::default()).unwrap();
    let pk5 = keygen_pk(&p5, vk5.clone(), &Mul::default()).unwrap();
    let vk6 = keygen_vk(&p6, &Mul::default()).unwrap();
    let pk6 = keygen_pk(&p6, vk6.clone(), &Mul::default()).unwrap();

    // 1. A plain proof at k = 5 leaves a claim of five challenges.
    let (c1, v1) = Mul::new(3, 5);
    let proof1 = prove(&p5, &pk5, &c1, v1, &[]).unwrap();
    let claim1 = verify(&p5, &vk5, v1, &[], &proof1).unwrap();
    assert_eq!(claim1.u.len(), 5);
    let plain6 = prove(&p6, &pk6, &c1, v1, &[]).unwrap();
    let claim6 = verify(&p6, &vk6, v1, &[], &plain6).unwrap();
    assert_eq!(
        p5.get_g()[..32],
        p6.get_g()[..32],
        "generators are not a prefix"
    );
    // same size first
    let same = prove(&p6, &pk6, &c1, v1, &[claim6.clone()]).unwrap();
    verify(&p6, &vk6, v1, &[claim6.clone()], &same).expect("same-size opening");
    let same5 = prove(&p5, &pk5, &c1, v1, &[claim1.clone()]).unwrap();
    verify(&p5, &vk5, v1, &[claim1.clone()], &same5).expect("same-size opening at k=5");

    // 2. That claim is opened inside a k = 6 proof (the generators are a
    //    prefix of the larger parameters'), which costs the proof one more
    //    query and leaves a single claim of six challenges.
    let (c2, v2) = Mul::new(7, 11);
    let proof2 = prove(&p6, &pk6, &c2, v2, &[claim1.clone()]).unwrap();
    let claim2 = verify(&p6, &vk6, v2, &[claim1.clone()], &proof2).unwrap();
    assert_eq!(claim2.u.len(), 6);
    // The opened claim adds nothing to the proof: its value at x is the
    // verifier's to compute, and x is a point set the proof already has.
    assert_eq!(proof2.len(), plain6.len());
    println!("proof sizes: k=5 {}, k=6 {}", proof1.len(), proof2.len());

    // 3. Two claims at once; the decider settles the one claim that is left.
    let (c3, v3) = Mul::new(2, 9);
    let both = [claim1.clone(), claim2.clone()];
    let proof3 = prove(&p6, &pk6, &c3, v3, &both).unwrap();
    let claim3 = verify(&p6, &vk6, v3, &both, &proof3).unwrap();
    assert_eq!(claim3.u.len(), 6);

    // The verifier must be given the claims the prover opened ...
    assert!(verify(&p6, &vk6, v2, &[], &proof2).is_err());
    assert!(verify(&p6, &vk6, v3, &[claim1.clone()], &proof3).is_err());
    // ... exactly: a claim with a wrong point or a wrong challenge fails.
    let mut wrong_g = claim1.clone();
    wrong_g.g = EqAffine::generator();
    assert!(verify(&p6, &vk6, v2, &[wrong_g.clone()], &proof2).is_err());
    let mut wrong_u = claim1.clone();
    wrong_u.u[2] = wrong_u.u[2].double();
    assert!(verify(&p6, &vk6, v2, &[wrong_u.clone()], &proof2).is_err());

    // A prover cannot launder a false claim: a proof made over a claim whose
    // point is not ⟨s(u), g⟩ is rejected by a verifier given that same claim.
    let laundered = prove(&p6, &pk6, &c2, v2, &[wrong_g.clone()]).unwrap();
    assert!(verify(&p6, &vk6, v2, &[wrong_g], &laundered).is_err());
    let laundered = prove(&p6, &pk6, &c2, v2, &[wrong_u.clone()]).unwrap();
    assert!(verify(&p6, &vk6, v2, &[wrong_u], &laundered).is_err());

    // A claim larger than the parameters cannot be opened.
    assert!(matches!(
        prove(&p5, &pk5, &c1, v1, &[claim2.clone()]),
        Err(Error::Opening)
    ));
    assert!(matches!(
        verify(&p5, &vk5, v1, &[claim2], &proof1),
        Err(Error::Opening)
    ));
}
