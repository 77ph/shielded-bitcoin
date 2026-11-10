//! The group side of a Vesta-committed proof under the split transcript
//! (`docs/REPLAY-PROOF-A.md` §3.6), a circuit over `Fq`: the `Fq` sponge
//! absorbs the points and the key's representative and squeezes every
//! challenge the points produce; the three the scalars produce (`x_1, x_2,
//! x_4`) are witnessed, exposed and absorbed; no evaluation is read. The
//! final multi-scalar multiplication is combined by Horner's rule — in
//! `x_1` within a point set, in `x_4` across sets, in `x^n` over the
//! quotient chunks — so the only full-width scalars are prover-claimed
//! values the field side checks: `x^n`, `−v`, `−c`, `−f`, `−c·b·z` and the
//! `u_j^{−1}`. Public inputs: the key's representative, the statement, the
//! challenges in order, the claimed scalars, `G`.

use ff::Field;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use vesta_ecc::ecc::chip::{CircuitVersion, EccChip};
use vesta_ecc::ecc::{NonIdentityPoint, Point, ScalarVar};
use vesta_ecc::utilities::lookup_range_check::VestaLookupRangeCheckConfig;

use crate::capture::{Capture, Event};
use crate::fixed::q::Bases;
use crate::native::Limbs;
use crate::shadow::fp::{Commitment, Shadow};
use crate::split::From;
use crate::transcript::Transcript;
use crate::verifier::q::VerifierConfig;
use sba_primitives::Fp;

type C = vesta::Affine;
type F = vesta::Base;
type Ecc = EccChip<Bases, VestaLookupRangeCheckConfig>;
type Cell = AssignedCell<F, F>;
type Pt = NonIdentityPoint<C, Ecc>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SKind {
    CommonScalar,
    CommonPoint,
    ReadPoint,
    ReadScalar,
    SqueezeNative,
    SqueezeWitnessed,
}

/// Where a commitment's point comes from.
#[derive(Clone, Copy, Debug)]
pub enum Src {
    Read(usize),
    Common,
    Constant(C),
}

#[derive(Clone, Debug)]
pub enum Cmt {
    Point(Src),
    /// The quotient chunks, combined in `x^n`.
    HChunks(Vec<Src>),
}

/// The structure of the verification, from the key and one capture.
#[derive(Clone, Debug)]
pub struct SplitPlan {
    pub kinds: Vec<SKind>,
    /// Per point set, the commitments in Horner order (highest `x_1`
    /// power first).
    pub sets: Vec<Vec<Cmt>>,
    pub q_prime: Src,
    pub s_poly: Src,
    pub rounds: Vec<(Src, Src)>,
    /// Indices among the squeezes of `x_1`, `x_4`, `ξ`, and the `u_j`.
    pub i_x1: usize,
    pub i_x4: usize,
    pub i_xi: usize,
    pub i_u: Vec<usize>,
    pub g0: C,
    pub w: C,
    pub u: C,
}

/// The circuit: the plan, the statement's generators, and when proving
/// the capture and the shadow (the values).
#[derive(Clone, Debug)]
pub struct SplitCircuit {
    pub plan: SplitPlan,
    pub lagrange: Vec<C>,
    pub values: Option<(Capture<C>, Shadow)>,
}

fn src_of(p: C, read: &[C], common: C) -> Src {
    if let Some(i) = read.iter().position(|q| *q == p) {
        Src::Read(i)
    } else if p == common {
        Src::Common
    } else {
        Src::Constant(p)
    }
}

impl SplitPlan {
    pub fn build(
        params: &Params<C>,
        _vk: &VerifyingKey<C>,
        cap: &Capture<C>,
        froms: &[From],
        sh: &Shadow,
    ) -> Self {
        let mut fi = 0;
        let kinds = cap
            .events
            .iter()
            .map(|e| match e {
                Event::CommonScalar(_) => SKind::CommonScalar,
                Event::CommonPoint(_) => SKind::CommonPoint,
                Event::ReadPoint(_) => SKind::ReadPoint,
                Event::ReadScalar(_) => SKind::ReadScalar,
                Event::Squeeze(_) => {
                    let k = match froms[fi] {
                        From::Points => SKind::SqueezeNative,
                        From::Scalars => SKind::SqueezeWitnessed,
                    };
                    fi += 1;
                    k
                }
            })
            .collect();
        let read = cap.points_read();
        let common = cap.common_points()[0];
        let t = &sh.typed;
        let n_sets = sh.point_sets.len();
        let mut sets: Vec<Vec<Cmt>> = vec![Vec::new(); n_sets];
        for (ci, (_, c)) in sh.commitments.iter().enumerate() {
            let (si, _) = sh.plan[ci];
            let cmt = match c {
                Commitment::Point(p) => Cmt::Point(src_of(*p, &read, common)),
                Commitment::HChunks(hs) => {
                    Cmt::HChunks(hs.iter().map(|h| src_of(*h, &read, common)).collect())
                }
            };
            sets[si].push(cmt);
        }
        // squeezes: θ β γ y x x_1 x_2 x_3 x_4 ξ z u_1 … u_k
        let k = t.rounds.len();
        SplitPlan {
            kinds,
            sets,
            q_prime: src_of(t.q_prime, &read, common),
            s_poly: src_of(t.s_poly, &read, common),
            rounds: t
                .rounds
                .iter()
                .map(|(l, r, _)| (src_of(*l, &read, common), src_of(*r, &read, common)))
                .collect(),
            i_x1: 5,
            i_x4: 8,
            i_xi: 9,
            i_u: (0..k).map(|j| 11 + j).collect(),
            g0: params.get_g()[0],
            w: params.get_w(),
            u: params.get_u(),
        }
    }
}

fn embed(s: &Fp) -> F {
    <C as Limbs>::embed(s)
}

impl SplitCircuit {
    /// The claimed scalars, natively: `x^n, −v, −c, −f, −c·b·z, u_j^{−1}`.
    pub fn claimed(sh: &Shadow) -> Vec<Fp> {
        let t = &sh.typed;
        let mut v = vec![sh.xn, -sh.v, -t.c, -t.f, sh.u_scalar];
        v.extend(t.rounds.iter().map(|(_, _, u)| u.invert().unwrap()));
        v
    }

    /// The public inputs.
    pub fn instance(&self) -> Vec<F> {
        let (cap, sh) = self.values.as_ref().expect("values");
        let mut v = Vec::new();
        for e in &cap.events {
            match e {
                Event::CommonScalar(s) | Event::Squeeze(s) => v.push(embed(s)),
                Event::CommonPoint(_) => v.extend(cap.instance.iter().map(embed)),
                Event::ReadPoint(_) | Event::ReadScalar(_) => {}
            }
        }
        v.extend(Self::claimed(sh).iter().map(embed));
        let c = {
            use pasta_curves::arithmetic::CurveAffine;
            let c = cap.g.coordinates().unwrap();
            (*c.x(), *c.y())
        };
        v.push(c.0);
        v.push(c.1);
        v
    }
}

struct Gadgets<'c> {
    cfg: &'c VerifierConfig,
    ecc: Ecc,
    exposed: usize,
    muls: usize,
}

impl Gadgets<'_> {
    fn witness(&self, l: &mut impl Layouter<F>, v: Value<F>) -> Result<Cell, Error> {
        l.assign_region(
            || "w",
            |mut r| r.assign_advice(|| "w", self.cfg.advices[3], 0, || v),
        )
    }

    fn expose(&mut self, l: &mut impl Layouter<F>, c: &Cell) -> Result<(), Error> {
        l.constrain_instance(c.cell(), self.cfg.instance, self.exposed)?;
        self.exposed += 1;
        Ok(())
    }

    /// A canonical scalar (below `2^254`), witnessed and exposed.
    fn scalar(&mut self, l: &mut impl Layouter<F>, v: Option<Fp>) -> Result<Cell, Error> {
        let cell = self.witness(
            l,
            v.map(|s| Value::known(embed(&s)))
                .unwrap_or(Value::unknown()),
        )?;
        self.expose(l, &cell)?;
        self.cfg.transcript.check(l, &cell, 25, 4)?;
        Ok(cell)
    }

    fn pinned(&self, l: &mut impl Layouter<F>, c: C) -> Result<Pt, Error> {
        let w = NonIdentityPoint::new(
            self.ecc.clone(),
            l.namespace(|| "constant"),
            Value::known(c),
        )?;
        let k = Point::new_from_constant(self.ecc.clone(), l.namespace(|| "constant"), c)?;
        w.constrain_equal(l.namespace(|| "pin"), &k)?;
        Ok(w)
    }

    /// A (possibly identity-typed) point as a non-identity one.
    fn nip(&self, l: &mut impl Layouter<F>, p: &Point<C, Ecc>) -> Result<Pt, Error> {
        let w = NonIdentityPoint::new(self.ecc.clone(), l.namespace(|| "nip"), p.inner().point())?;
        w.constrain_equal(l.namespace(|| "pin nip"), p)?;
        Ok(w)
    }

    fn mul(
        &mut self,
        l: &mut impl Layouter<F>,
        base: &Pt,
        scalar: &Cell,
    ) -> Result<Point<C, Ecc>, Error> {
        self.muls += 1;
        let s = ScalarVar::from_base(self.ecc.clone(), l.namespace(|| "scalar var"), scalar)?;
        let (p, _) = base.mul(l.namespace(|| "mul"), s)?;
        Ok(p)
    }

    /// `sum + [scalar] base`
    fn term(
        &mut self,
        l: &mut impl Layouter<F>,
        base: &Pt,
        scalar: &Cell,
        sum: Point<C, Ecc>,
    ) -> Result<Point<C, Ecc>, Error> {
        let m = self.mul(l, base, scalar)?;
        sum.add(l.namespace(|| "add"), &m)
    }

    /// `[scalar] acc + add`
    fn horner(
        &mut self,
        l: &mut impl Layouter<F>,
        acc: &Point<C, Ecc>,
        scalar: &Cell,
        add: &Pt,
    ) -> Result<Point<C, Ecc>, Error> {
        let a = self.nip(l, acc)?;
        let m = self.mul(l, &a, scalar)?;
        m.add(l.namespace(|| "add"), add)
    }
}

impl Circuit<F> for SplitCircuit {
    type Config = VerifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        SplitCircuit {
            plan: self.plan.clone(),
            lagrange: self.lagrange.clone(),
            values: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> VerifierConfig {
        crate::verifier::q::VerifierCircuit::configure(meta)
    }

    fn synthesize(&self, cfg: VerifierConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        cfg.assign_table(&mut layouter)?;
        let l = &mut layouter;
        let mut g = Gadgets {
            cfg: &cfg,
            ecc: EccChip::construct(cfg.ecc.clone(), CircuitVersion::AnchoredBase),
            exposed: 0,
            muls: 0,
        };
        let mut t = Transcript::new(&cfg.transcript, l)?;
        let vals = self.values.as_ref();
        let cap = vals.map(|v| &v.0);
        let sh = vals.map(|v| &v.1);

        // the walk
        let mut read: Vec<Pt> = Vec::new();
        let mut common: Option<Pt> = None;
        let mut challenges: Vec<Cell> = Vec::new();
        for (i, kind) in self.plan.kinds.iter().enumerate() {
            match kind {
                SKind::CommonScalar => {
                    let v = cap.map(|c| match &c.events[i] {
                        Event::CommonScalar(s) => *s,
                        _ => unreachable!(),
                    });
                    let cell = g.scalar(l, v)?;
                    t.absorb(l, cell)?;
                }
                SKind::ReadScalar => {}
                SKind::CommonPoint => {
                    let mut acc: Option<Point<C, Ecc>> = None;
                    for (j, gen) in self.lagrange.iter().enumerate() {
                        let cell = g.scalar(l, cap.map(|c| c.instance[j]))?;
                        let base = g.pinned(l, *gen)?;
                        let prod = g.mul(l, &base, &cell)?;
                        acc = Some(match acc {
                            None => prod,
                            Some(a) => a.add(l.namespace(|| "add"), &prod)?,
                        });
                    }
                    let w =
                        Point::new_from_constant(g.ecc.clone(), l.namespace(|| "W"), self.plan.w)?;
                    let commitment = acc.expect("values").add(l.namespace(|| "blind"), &w)?;
                    let p = g.nip(l, &commitment)?;
                    t.absorb(l, p.inner().x())?;
                    t.absorb(l, p.inner().y())?;
                    common = Some(p);
                }
                SKind::ReadPoint => {
                    let v = cap
                        .map(|c| match &c.events[i] {
                            Event::ReadPoint(p) => Value::known(*p),
                            _ => unreachable!(),
                        })
                        .unwrap_or(Value::unknown());
                    let p = NonIdentityPoint::new(g.ecc.clone(), l.namespace(|| "point"), v)?;
                    t.absorb(l, p.inner().x())?;
                    t.absorb(l, p.inner().y())?;
                    read.push(p);
                }
                SKind::SqueezeNative => {
                    let (_, c) = t.squeeze(l)?;
                    g.expose(l, &c)?;
                    challenges.push(c);
                }
                SKind::SqueezeWitnessed => {
                    // a challenge the scalars' sponge produced: witnessed,
                    // exposed, absorbed (128 bits, checked)
                    let v = cap.map(|c| match &c.events[i] {
                        Event::Squeeze(s) => Value::known(embed(s)),
                        _ => unreachable!(),
                    });
                    let cell = g.witness(l, v.unwrap_or(Value::unknown()))?;
                    g.expose(l, &cell)?;
                    cfg.transcript.check_128(l, &cell)?;
                    t.absorb(l, cell.clone())?;
                    challenges.push(cell);
                }
            }
        }
        // the claimed scalars
        let claimed_v: Option<Vec<Fp>> = sh.map(SplitCircuit::claimed);
        let n_claimed = 5 + self.plan.rounds.len();
        let mut claimed: Vec<Cell> = Vec::with_capacity(n_claimed);
        for j in 0..n_claimed {
            claimed.push(g.scalar(l, claimed_v.as_ref().map(|v| v[j]))?);
        }
        let (xn, neg_v, neg_c, neg_f, ucz) = (
            &claimed[0],
            &claimed[1],
            &claimed[2],
            &claimed[3],
            &claimed[4],
        );
        let u_inv = &claimed[5..];
        let point_of = |g: &Gadgets, l: &mut _, s: &Src| -> Result<Pt, Error> {
            Ok(match s {
                Src::Read(i) => read[*i].clone(),
                Src::Common => common.clone().expect("absorbed"),
                Src::Constant(c) => g.pinned(l, *c)?,
            })
        };
        let x1 = challenges[self.plan.i_x1].clone();
        let x4 = challenges[self.plan.i_x4].clone();
        let xi = challenges[self.plan.i_xi].clone();

        // P = Horner over the sets in x_4, within a set in x_1, chunks in x^n
        let mut acc: Point<C, Ecc> = point_of(&g, l, &self.plan.q_prime)?.into();
        for set in &self.plan.sets {
            let mut q: Option<Point<C, Ecc>> = None;
            for cmt in set {
                let point: Pt = match cmt {
                    Cmt::Point(s) => point_of(&g, l, s)?,
                    Cmt::HChunks(hs) => {
                        let mut h: Point<C, Ecc> = point_of(&g, l, hs.last().unwrap())?.into();
                        for s in hs.iter().rev().skip(1) {
                            let p = point_of(&g, l, s)?;
                            h = g.horner(l, &h, xn, &p)?;
                        }
                        g.nip(l, &h)?
                    }
                };
                q = Some(match q {
                    None => point.into(),
                    Some(a) => g.horner(l, &a, &x1, &point)?,
                });
            }
            let qp = g.nip(l, &q.expect("a set has commitments"))?;
            acc = g.horner(l, &acc, &x4, &qp)?;
        }
        // the inner-product argument's terms
        let mut sum = acc;
        let g0 = g.pinned(l, self.plan.g0)?;
        sum = g.term(l, &g0, neg_v, sum)?;
        let s_poly = point_of(&g, l, &self.plan.s_poly)?;
        sum = g.term(l, &s_poly, &xi, sum)?;
        for (j, (ls, rs)) in self.plan.rounds.iter().enumerate() {
            let lp = point_of(&g, l, ls)?;
            let rp = point_of(&g, l, rs)?;
            sum = g.term(l, &lp, &u_inv[j], sum)?;
            sum = g.term(l, &rp, &challenges[self.plan.i_u[j]], sum)?;
        }
        let gv = cap.map(|c| Value::known(c.g)).unwrap_or(Value::unknown());
        let gp = NonIdentityPoint::new(g.ecc.clone(), l.namespace(|| "G"), gv)?;
        sum = g.term(l, &gp, neg_c, sum)?;
        let w = g.pinned(l, self.plan.w)?;
        sum = g.term(l, &w, neg_f, sum)?;
        let u = g.pinned(l, self.plan.u)?;
        sum = g.term(l, &u, ucz, sum)?;
        g.expose(l, &gp.inner().x())?;
        g.expose(l, &gp.inner().y())?;
        l.assign_region(
            || "identity",
            |mut r| {
                r.constrain_constant(sum.inner().x().cell(), F::ZERO)?;
                r.constrain_constant(sum.inner().y().cell(), F::ZERO)?;
                Ok(())
            },
        )?;
        eprintln!(
            "split group side: {} permutations, {} multiplications, {} public inputs",
            t.permutations, g.muls, g.exposed
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::{capture_split, SplitWrite};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sba_circuit::{TransferCircuit, K};

    #[test]
    fn the_group_side_under_the_split_transcript() {
        let (st, w) = crate::sample::sample();
        let params: Params<C> = Params::new(K);
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
            &mut StdRng::seed_from_u64(71),
            &mut tr,
        )
        .unwrap();
        let proof = tr.finalize();
        let (cap, froms) = capture_split(&params, &vk, &instance, &proof).unwrap();
        let sh = Shadow::compute(&params, &vk, &cap);
        let plan = SplitPlan::build(&params, &vk, &cap, &froms, &sh);
        let circuit = SplitCircuit {
            plan,
            lagrange: params.get_g_lagrange()[..instance.len()].to_vec(),
            values: Some((cap.clone(), sh)),
        };
        let pi = circuit.instance();
        println!("split group side public inputs: {}", pi.len());
        let mut k = 14;
        let t = std::time::Instant::now();
        let prover = loop {
            match MockProver::run(k, &circuit, vec![pi.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k += 1;
                    assert!(k <= 18);
                }
            }
        };
        prover.assert_satisfied();
        println!(
            "split group side fits k = {k} (mock {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<pasta_curves::pallas::Point, _>::measure(k, &circuit)
        );
        // a wrong witnessed challenge (x_1) and a wrong claimed scalar are refused
        let n_walk = 1 + instance.len() + 25;
        let mut bad = pi.clone();
        bad[1 + instance.len() + 5] += F::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        let mut bad = pi.clone();
        bad[n_walk] += F::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
    }
}
