// Included twice by `verifier.rs`, with `curve`, `ecc`, `RangeConfig`,
// `LookupRangeCheck` and `Bases` bound per side.

use ecc::ecc::chip::{CircuitVersion, EccChip, EccConfig};
use ecc::ecc::{NonIdentityPoint, Point, ScalarVar};
use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_gadgets::poseidon::Pow5Chip;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, TableColumn,
};
use halo2_proofs::poly::commitment::Params;

use crate::capture::{Capture, Event};
use crate::native::Limbs;
use crate::transcript::{Transcript, TranscriptConfig};

/// The verified proof's commitment curve.
pub type C = curve::Affine;
/// The circuit's field, the curve's base field.
pub type F = curve::Base;
/// The verified proof's scalar field.
pub type S = curve::Scalar;
/// Cells per scalar of the verified proof.
pub const N: usize = <C as Limbs>::N;

type Ecc = EccChip<Bases, RangeConfig>;
type Cell = AssignedCell<F, F>;
type Pt = NonIdentityPoint<C, Ecc>;

/// The kind of each transcript event: the circuit's structure, fixed by the
/// verifying key; the values come with a capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The instance commitment, recomputed from the instance values.
    CommonPoint,
    /// The `G` of a claim the proof opens: witnessed and exposed.
    OpenedPoint,
    CommonScalar,
    ReadPoint,
    ReadScalar,
    Squeeze,
}

/// Where a term of the final MSM takes its point from.
#[derive(Clone, Copy, Debug)]
pub enum Source {
    /// The i-th point read from the proof.
    Read(usize),
    /// The instance commitment (the first common point).
    Common,
    /// The i-th opened claim's `G` (the following common points).
    Opened(usize),
    /// A constant point: a commitment of the key, `G_0`, `W`, `U`.
    Constant(C),
    /// The prover's accumulator point `G`.
    Claim,
}

/// The structure (from the key) and, when proving, the values.
#[derive(Clone, Debug)]
pub struct VerifierCircuit {
    pub kinds: Vec<Kind>,
    /// One per term of the final MSM, in a canonical order.
    pub sources: Vec<Source>,
    /// The parameters' `W` and `U` (constants of the circuit).
    pub params_w: C,
    pub params_u: C,
    /// The Lagrange generators of the instance values (constants).
    pub lagrange: Vec<C>,
    /// Cells per instance value of the verified proof: 1 for a value known
    /// to be below `2^254` (a scalar-field element of the proof *it*
    /// verified, embedded), `N` otherwise.
    pub instance_limbs: Vec<usize>,
    /// Whether the verified proof's instance values are public inputs of
    /// this circuit (a circuit embedding this one binds them in-circuit
    /// instead when nothing later needs them; they are witnessed and
    /// bound by the instance commitment either way).
    pub expose_instance: bool,
    pub capture: Option<Capture<C>>,
}

#[derive(Clone, Debug)]
pub struct VerifierConfig {
    pub ecc: EccConfig<Bases, RangeConfig>,
    pub transcript: TranscriptConfig<F>,
    pub advices: [Column<Advice>; 11],
    pub instance: Column<Instance>,
    pub table_idx: TableColumn,
}

/// The cells exposed as public inputs, in the instance's order, and the
/// verified proof's instance values among them (the limbs of each).
pub struct Exposed {
    pub cells: Vec<Cell>,
    pub instance_values: Vec<Vec<Cell>>,
}

impl VerifierCircuit {
    /// The structure of a capture: the event kinds and, for every term of
    /// its MSM, where the point comes from; `terms` of a later capture of
    /// the same circuit are matched to these sources by coordinates.
    pub fn shape(
        cap: &Capture<C>,
        params: &Params<C>,
        fixed_commitments: &[C],
        permutation_commitments: &[C],
    ) -> (Vec<Kind>, Vec<Source>) {
        let mut commons = 0usize;
        let kinds = cap
            .events
            .iter()
            .map(|e| match e {
                Event::CommonPoint(_) => {
                    commons += 1;
                    if commons == 1 {
                        Kind::CommonPoint
                    } else {
                        Kind::OpenedPoint
                    }
                }
                Event::CommonScalar(_) => Kind::CommonScalar,
                Event::ReadPoint(_) => Kind::ReadPoint,
                Event::ReadScalar(_) => Kind::ReadScalar,
                Event::Squeeze(_) => Kind::Squeeze,
            })
            .collect();
        // one source per distinct point: `halo2_proofs`' MSM merges equal
        // points (two identical fixed columns commit to the same point), so
        // a repeated point keeps its first source only
        let mut candidates: Vec<(Source, C)> = Vec::new();
        for (i, p) in cap.points_read().iter().enumerate() {
            candidates.push((Source::Read(i), *p));
        }
        let commons = cap.common_points();
        candidates.push((Source::Common, commons[0]));
        for (i, p) in commons[1..].iter().enumerate() {
            candidates.push((Source::Opened(i), *p));
        }
        for c in fixed_commitments.iter().chain(permutation_commitments) {
            candidates.push((Source::Constant(*c), *c));
        }
        candidates.push((Source::Constant(params.get_g()[0]), params.get_g()[0]));
        candidates.push((Source::Claim, cap.g));
        let mut seen: Vec<C> = Vec::new();
        let mut sources = Vec::new();
        for (src, p) in candidates {
            if seen.contains(&p) {
                continue;
            }
            seen.push(p);
            sources.push(src);
        }
        (kinds, sources)
    }

    /// The scalar of each source in a capture (zero for a source the MSM
    /// has no term for).
    pub fn scalars(&self, cap: &Capture<C>) -> Vec<S> {
        let read = cap.points_read();
        let commons = cap.common_points();
        let scalar_of = |p: &C| -> S {
            cap.terms
                .iter()
                .find(|(_, q)| q == p)
                .map(|(s, _)| *s)
                .unwrap_or(S::ZERO)
        };
        self.sources
            .iter()
            .map(|s| match s {
                Source::Read(i) => scalar_of(&read[*i]),
                Source::Common => scalar_of(&commons[0]),
                Source::Opened(i) => scalar_of(&commons[1 + *i]),
                Source::Constant(c) => scalar_of(c),
                Source::Claim => scalar_of(&cap.g),
            })
            .collect()
    }

    /// The public inputs of a capture, in the circuit's order: the
    /// transcript walk (each scalar as its `N` limbs, the instance values
    /// likewise, each opened `G` as two coordinates, each challenge as one
    /// cell), the MSM scalars (`N` limbs each), `W`'s and `U`'s, `G`.
    pub fn instance(&self, cap: &Capture<C>) -> Vec<F> {
        let mut v = Vec::new();
        let mut commons = 0usize;
        for e in &cap.events {
            match e {
                Event::CommonScalar(s) | Event::ReadScalar(s) => {
                    v.extend(C::cells(s, N));
                }
                Event::Squeeze(s) => v.push(C::limbs(s)[0]),
                Event::CommonPoint(p) => {
                    commons += 1;
                    if commons == 1 {
                        if self.expose_instance {
                            for (s, limbs) in cap.instance.iter().zip(&self.instance_limbs) {
                                v.extend(C::cells(s, *limbs));
                            }
                        }
                    } else {
                        let (x, y) = coords(p);
                        v.push(x);
                        v.push(y);
                    }
                }
                Event::ReadPoint(_) => {}
            }
        }
        for s in self.scalars(cap) {
            v.extend(C::cells(&s, N));
        }
        v.extend(C::cells(&cap.w_scalar, N));
        v.extend(C::cells(&cap.u_scalar, N));
        let (gx, gy) = coords(&cap.g);
        v.push(gx);
        v.push(gy);
        v
    }
}

impl VerifierCircuit {
    /// How a proof of *this* circuit's instance values are carried by the
    /// circuit verifying it: every one is a scalar-field element of the
    /// proof verified here (embedded, below `2^254`) and fits one cell,
    /// except the claim's `G` at the end, two full base-field coordinates.
    pub fn instance_limbs_when_verified(&self, cap: &Capture<C>) -> Vec<usize> {
        let n = self.instance(cap).len();
        let mut v = vec![1; n];
        v[n - 2] = 2;
        v[n - 1] = 2;
        v
    }
}

fn coords(p: &C) -> (F, F) {
    use pasta_curves::arithmetic::CurveAffine;
    let c = p.coordinates().unwrap();
    (*c.x(), *c.y())
}

/// Expose a cell as the next public input.
fn expose<L: Layouter<F>>(
    cfg: &VerifierConfig,
    layouter: &mut L,
    c: &Cell,
    exposed: &mut Vec<Cell>,
) -> Result<(), Error> {
    layouter.constrain_instance(c.cell(), cfg.instance, exposed.len())?;
    exposed.push(c.clone());
    Ok(())
}

/// A constant point as a non-identity point of the chip: witnessed, then
/// pinned to the constant.
fn pinned<L: Layouter<F>>(ecc: &Ecc, layouter: &mut L, c: C) -> Result<Pt, Error> {
    let w = NonIdentityPoint::new(
        ecc.clone(),
        layouter.namespace(|| "constant"),
        Value::known(c),
    )?;
    let k = Point::new_from_constant(ecc.clone(), layouter.namespace(|| "constant"), c)?;
    w.constrain_equal(layouter.namespace(|| "pin"), &k)?;
    Ok(w)
}

/// Witness one value.
fn witness<L: Layouter<F>>(
    cfg: &VerifierConfig,
    layouter: &mut L,
    v: Value<F>,
) -> Result<Cell, Error> {
    layouter.assign_region(
        || "scalar",
        |mut r| r.assign_advice(|| "s", cfg.advices[3], 0, || v),
    )
}

/// A scalar of the verified proof as `n` range-checked limbs, exposed or not.
fn witness_scalar<L: Layouter<F>>(
    cfg: &VerifierConfig,
    layouter: &mut L,
    s: Option<S>,
    n: usize,
    exposed: Option<&mut Vec<Cell>>,
) -> Result<Vec<Cell>, Error> {
    let limbs = s.map(|s| C::cells(&s, n));
    let mut cells = Vec::with_capacity(n);
    let mut exposed = exposed;
    for l in 0..n {
        let v = limbs
            .as_ref()
            .map(|limbs| Value::known(limbs[l]))
            .unwrap_or(Value::unknown());
        let cell = witness(cfg, layouter, v)?;
        if let Some(exposed) = exposed.as_deref_mut() {
            expose(cfg, layouter, &cell, exposed)?;
        }
        match (n, l) {
            // one cell: below 2^254 (25 words and 4 bits), hence canonical
            (1, _) => cfg.transcript.check(layouter, &cell, 25, 4)?,
            // low limb below 2^128
            (_, 0) => cfg.transcript.check_128(layouter, &cell)?,
            // high limb below 2^126 (12 words and 6 bits): the scalar below 2^254
            _ => cfg.transcript.check(layouter, &cell, 12, 6)?,
        }
        cells.push(cell);
    }
    Ok(cells)
}

/// Per-limb accumulators of a multi-scalar multiplication.
struct Acc(Vec<Option<Point<C, Ecc>>>);

impl Acc {
    fn new() -> Self {
        Acc((0..N).map(|_| None).collect())
    }

    /// `acc_l += [limb_l] base` for each limb.
    fn add_term<L: Layouter<F>>(
        &mut self,
        ecc: &Ecc,
        layouter: &mut L,
        base: &Pt,
        limbs: &[Cell],
    ) -> Result<(), Error> {
        for (l, limb) in limbs.iter().enumerate() {
            let scalar = ScalarVar::from_base(ecc.clone(), layouter.namespace(|| "scalar var"), limb)?;
            let (prod, _) = base.mul(layouter.namespace(|| "mul"), scalar)?;
            self.0[l] = Some(match self.0[l].take() {
                None => prod,
                Some(a) => a.add(layouter.namespace(|| "add"), &prod)?,
            });
        }
        Ok(())
    }

    /// `acc_0 + [2^128] acc_1`.
    fn fold<L: Layouter<F>>(self, cfg: &VerifierConfig, ecc: &Ecc, layouter: &mut L) -> Result<Point<C, Ecc>, Error> {
        let mut it = self.0.into_iter();
        let lo = it.next().flatten().expect("terms");
        match it.next().flatten() {
            None => Ok(lo),
            Some(hi) => {
                let hi_pt = NonIdentityPoint::new(
                    ecc.clone(),
                    layouter.namespace(|| "high sum"),
                    hi.inner().point(),
                )?;
                hi_pt.constrain_equal(layouter.namespace(|| "pin high sum"), &hi)?;
                let two_128 = F::from_u128(1u128 << 64).square();
                let cell = layouter.assign_region(
                    || "2^128",
                    |mut r| {
                        let c = r.assign_advice(|| "2^128", cfg.advices[3], 0, || Value::known(two_128))?;
                        r.constrain_constant(c.cell(), two_128)?;
                        Ok(c)
                    },
                )?;
                let scalar = ScalarVar::from_base(ecc.clone(), layouter.namespace(|| "2^128 var"), &cell)?;
                let (shifted, _) = hi_pt.mul(layouter.namespace(|| "shift"), scalar)?;
                lo.add(layouter.namespace(|| "fold"), &shifted)
            }
        }
    }
}

impl Circuit<F> for VerifierCircuit {
    type Config = VerifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        VerifierCircuit {
            kinds: self.kinds.clone(),
            sources: self.sources.clone(),
            params_w: self.params_w,
            params_u: self.params_u,
            lagrange: self.lagrange.clone(),
            instance_limbs: self.instance_limbs.clone(),
            expose_instance: self.expose_instance,
            capture: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> VerifierConfig {
        let advices: [Column<Advice>; 11] = core::array::from_fn(|_| meta.advice_column());
        for a in &advices {
            meta.enable_equality(*a);
        }
        let lagrange_coeffs: [Column<Fixed>; 8] = core::array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(lagrange_coeffs[0]);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let table_idx = meta.lookup_table_column();
        let range = RangeConfig::configure(meta, advices[9], table_idx);
        let ecc = EccChip::<Bases>::configure(
            meta,
            advices[..10].try_into().unwrap(),
            lagrange_coeffs,
            range,
        );
        let poseidon = Pow5Chip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            lagrange_coeffs[2..5].try_into().unwrap(),
            lagrange_coeffs[5..8].try_into().unwrap(),
        );
        let transcript = TranscriptConfig::configure(
            meta,
            poseidon,
            advices[10],
            table_idx,
            [advices[0], advices[1], advices[2]],
        );
        VerifierConfig {
            ecc,
            transcript,
            advices,
            instance,
            table_idx,
        }
    }

    fn synthesize(&self, cfg: VerifierConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        self.synthesize_core(&cfg, &mut layouter).map(|_| ())
    }
}

impl VerifierCircuit {
    /// The whole circuit, returning its exposed cells (for a circuit that
    /// embeds this one and binds other cells to them).
    pub fn synthesize_core(
        &self,
        cfg: &VerifierConfig,
        layouter: &mut impl Layouter<F>,
    ) -> Result<Exposed, Error> {
        let cfg = cfg.clone();
        let mut layouter = layouter.namespace(|| "group side");
        let layouter = &mut layouter;
        layouter.assign_table(
            || "10-bit table",
            |mut table| {
                for i in 0..(1 << 10) {
                    table.assign_cell(|| "idx", cfg.table_idx, i, || Value::known(F::from(i as u64)))?;
                }
                Ok(())
            },
        )?;
        let ecc = EccChip::construct(cfg.ecc.clone(), CircuitVersion::AnchoredBase);
        let mut t = Transcript::new(&cfg.transcript, layouter)?;
        let cap = self.capture.as_ref();
        let commons: Vec<C> = cap.map(|c| c.common_points()).unwrap_or_default();
        let mut exposed: Vec<Cell> = Vec::new();
        let mut instance_values: Vec<Vec<Cell>> = Vec::new();

        // the transcript walk
        let mut read_points: Vec<Pt> = Vec::new();
        let mut common_point: Option<Pt> = None;
        let mut opened_points: Vec<Pt> = Vec::new();
        for (i, kind) in self.kinds.iter().enumerate() {
            match kind {
                Kind::CommonScalar | Kind::ReadScalar => {
                    let s = cap.map(|c| match &c.events[i] {
                        Event::CommonScalar(s) | Event::ReadScalar(s) => *s,
                        _ => unreachable!(),
                    });
                    for limb in witness_scalar(&cfg, layouter, s, N, Some(&mut exposed))? {
                        t.absorb(layouter, limb)?;
                    }
                }
                Kind::CommonPoint => {
                    // the instance commitment from the instance values:
                    // Σ instance_j · G_lagrange[j] + [1] W
                    let mut acc = Acc::new();
                    for (j, g) in self.lagrange.iter().enumerate() {
                        let s = cap.map(|c| c.instance[j]);
                        let limbs = witness_scalar(
                            &cfg,
                            layouter,
                            s,
                            self.instance_limbs[j],
                            self.expose_instance.then_some(&mut exposed),
                        )?;
                        let base = pinned(&ecc, layouter, *g)?;
                        acc.add_term(&ecc, layouter, &base, &limbs)?;
                        instance_values.push(limbs);
                    }
                    let sum = acc.fold(&cfg, &ecc, layouter)?;
                    let w = Point::new_from_constant(ecc.clone(), layouter.namespace(|| "W"), self.params_w)?;
                    let commitment = sum.add(layouter.namespace(|| "blind"), &w)?;
                    // as a non-identity point: witnessed and pinned to the sum
                    let p = NonIdentityPoint::new(
                        ecc.clone(),
                        layouter.namespace(|| "instance commitment"),
                        commitment.inner().point(),
                    )?;
                    p.constrain_equal(layouter.namespace(|| "pin commitment"), &commitment)?;
                    t.absorb(layouter, p.inner().x())?;
                    t.absorb(layouter, p.inner().y())?;
                    common_point = Some(p);
                }
                Kind::OpenedPoint => {
                    let v = commons
                        .get(1 + opened_points.len())
                        .map(|p| Value::known(*p))
                        .unwrap_or(Value::unknown());
                    let p = NonIdentityPoint::new(ecc.clone(), layouter.namespace(|| "opened G"), v)?;
                    expose(&cfg, layouter, &p.inner().x(), &mut exposed)?;
                    expose(&cfg, layouter, &p.inner().y(), &mut exposed)?;
                    t.absorb(layouter, p.inner().x())?;
                    t.absorb(layouter, p.inner().y())?;
                    opened_points.push(p);
                }
                Kind::ReadPoint => {
                    let v = cap
                        .map(|c| match &c.events[i] {
                            Event::ReadPoint(p) => Value::known(*p),
                            _ => unreachable!(),
                        })
                        .unwrap_or(Value::unknown());
                    let p = NonIdentityPoint::new(ecc.clone(), layouter.namespace(|| "point"), v)?;
                    t.absorb(layouter, p.inner().x())?;
                    t.absorb(layouter, p.inner().y())?;
                    read_points.push(p);
                }
                Kind::Squeeze => {
                    let (_, c) = t.squeeze(layouter)?;
                    expose(&cfg, layouter, &c, &mut exposed)?;
                }
            }
        }

        // the multi-scalar multiplication
        let scalars: Option<Vec<S>> = cap.map(|c| self.scalars(c));
        let mut acc = Acc::new();
        let mut claim_point: Option<Pt> = None;
        for (j, source) in self.sources.iter().enumerate() {
            let limbs = witness_scalar(
                &cfg,
                layouter,
                scalars.as_ref().map(|v| v[j]),
                N,
                Some(&mut exposed),
            )?;
            let base: Pt = match source {
                Source::Read(i) => read_points[*i].clone(),
                Source::Common => common_point.clone().expect("absorbed before the MSM"),
                Source::Opened(i) => opened_points[*i].clone(),
                Source::Constant(c) => pinned(&ecc, layouter, *c)?,
                Source::Claim => {
                    let v = cap.map(|c| Value::known(c.g)).unwrap_or(Value::unknown());
                    let g = NonIdentityPoint::new(ecc.clone(), layouter.namespace(|| "G"), v)?;
                    claim_point = Some(g.clone());
                    g
                }
            };
            acc.add_term(&ecc, layouter, &base, &limbs)?;
        }
        // W and U
        for (point, value) in [
            (self.params_w, cap.map(|c| c.w_scalar)),
            (self.params_u, cap.map(|c| c.u_scalar)),
        ] {
            let limbs = witness_scalar(&cfg, layouter, value, N, Some(&mut exposed))?;
            let w = pinned(&ecc, layouter, point)?;
            acc.add_term(&ecc, layouter, &w, &limbs)?;
        }
        // the claim's G exposed, and the sum must be the identity (0, 0)
        let g = claim_point.expect("a claim term");
        expose(&cfg, layouter, &g.inner().x(), &mut exposed)?;
        expose(&cfg, layouter, &g.inner().y(), &mut exposed)?;
        let sum = acc.fold(&cfg, &ecc, layouter)?;
        layouter.assign_region(
            || "identity",
            |mut r| {
                r.constrain_constant(sum.inner().x().cell(), F::ZERO)?;
                r.constrain_constant(sum.inner().y().cell(), F::ZERO)?;
                Ok(())
            },
        )?;
        eprintln!(
            "transcript permutations: {}, msm terms: {} ({} limbs each), public inputs {}",
            t.permutations,
            self.sources.len() + 2,
            N,
            exposed.len()
        );
        Ok(Exposed {
            cells: exposed,
            instance_values,
        })
    }
}
