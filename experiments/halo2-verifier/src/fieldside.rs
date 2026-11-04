//! The field side of the verifier as a circuit over `Fp`
//! (`docs/REPLAY-PROOF-A.md` §3.3, piece 3): from the challenges and the
//! proof's evaluations (public inputs, in transcript order), recompute every
//! scalar of the final multi-scalar multiplication exactly as `shadow.rs`
//! does natively, and expose them (public inputs, in the group circuit's
//! source order) together with the `W` and `U` scalars. Together with the
//! group circuit this is the whole verifier: the group circuit shows that
//! the proof bytes bind the challenges and that the equation holds for the
//! scalars it was given; this one shows those scalars are the verifier's.
//!
//! Everything that depends on the key alone (gate polynomials, query
//! layout, point sets, `x_1` exponents, which references share a point) is
//! a `Structure`, built once from the key and a capture; the circuit's
//! shape does not depend on the proof.

use ff::{Field, PrimeField};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{
    Advice, Any, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance,
    VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use pasta_curves::vesta;

use crate::capture::{Capture, Event};
use crate::field::{Cell, FieldChip, FieldConfig, Fp};
use crate::shadow::{CRef, Commitment, Shadow};
use crate::verifier::Source;

/// Where an evaluation of the multiopen argument comes from.
#[derive(Clone, Copy, Debug)]
pub enum EvalSrc {
    Instance(usize),
    Advice(usize),
    Fixed(usize),
    Random,
    PermCommon(usize),
    /// (chunk, 0 = at x, 1 = at x·ω, 2 = at x·ω^-last)
    PermSet(usize, usize),
    /// (lookup, 0 product, 1 product_next, 2 permuted_input, 3 permuted_input_inv, 4 permuted_table)
    Lookup(usize, usize),
    ExpectedH,
}

/// A term of the final MSM, by what it multiplies.
#[derive(Clone, Copy, Debug)]
pub enum Term {
    QPrime,
    /// A commitment reference (index into `Structure::refs`).
    Ref(usize),
    /// The j-th quotient chunk of the reference.
    HChunk(usize, usize),
    G0,
    SPoly,
    L(usize),
    R(usize),
    G,
}

/// A column of the permutation argument: which evaluation list and index.
#[derive(Clone, Copy, Debug)]
pub enum ColEval {
    Advice(usize),
    Fixed(usize),
    Instance(usize),
}

#[derive(Clone, Debug)]
pub struct Structure {
    pub k_inner: u32,
    pub blinding: usize,
    pub n_instance_q: usize,
    pub n_advice_q: usize,
    pub n_fixed_q: usize,
    pub n_perm_common: usize,
    pub n_chunks: usize,
    pub chunk_len: usize,
    pub n_lookups: usize,
    pub quotient_degree: usize,
    pub gate_polys: Vec<Expression<Fp>>,
    pub perm_columns: Vec<ColEval>,
    pub lookups: Vec<(Vec<Expression<Fp>>, Vec<Expression<Fp>>)>,
    /// The rotation of each distinct evaluation point.
    pub point_rotations: Vec<i32>,
    /// Each point set as point indices.
    pub sets: Vec<Vec<usize>>,
    /// Per commitment reference: (set index, x_1 exponent, evals per set slot).
    pub refs: Vec<(CRef, usize, usize, Vec<EvalSrc>)>,
    /// Per output scalar (the group circuit's source order): the terms summed.
    pub outputs: Vec<Vec<Term>>,
    pub omega: Fp,
}

fn rot_of(
    point: Fp,
    x: Fp,
    domain: &halo2_proofs::poly::EvaluationDomain<Fp>,
    blinding: usize,
) -> i32 {
    for r in [0i32, 1, -1, -((blinding + 1) as i32)] {
        if domain.rotate_omega(x, Rotation(r)) == point {
            return r;
        }
    }
    panic!("an evaluation point that is not a known rotation of x");
}

impl Structure {
    pub fn build(
        params: &Params<vesta::Affine>,
        vk: &VerifyingKey<vesta::Affine>,
        cap: &Capture,
        sources: &[Source],
    ) -> (Structure, Shadow) {
        let sh = Shadow::compute(params, vk, cap);
        let cs = vk.cs();
        let domain = vk.get_domain();
        let t = &sh.typed;
        let blinding = cs.blinding_factors();
        let chunk_len = cs.degree() - 2;
        let gate_polys = cs
            .gates()
            .iter()
            .flat_map(|g| g.polynomials().iter().cloned())
            .collect();
        let perm_columns = cs
            .permutation()
            .get_columns()
            .iter()
            .map(|c| {
                let i = cs.get_any_query_index(*c);
                match c.column_type() {
                    Any::Advice => ColEval::Advice(i),
                    Any::Fixed => ColEval::Fixed(i),
                    Any::Instance => ColEval::Instance(i),
                }
            })
            .collect();
        let lookups = cs
            .lookups()
            .iter()
            .map(|a| (a.input_expressions.clone(), a.table_expressions.clone()))
            .collect();
        // points by index, as rotations
        let mut points_by_index: Vec<Fp> = Vec::new();
        for q in &sh.queries {
            if !points_by_index.contains(&q.point) {
                points_by_index.push(q.point);
            }
        }
        let point_rotations: Vec<i32> = points_by_index
            .iter()
            .map(|p| rot_of(*p, t.x, domain, blinding))
            .collect();
        let sets: Vec<Vec<usize>> = sh
            .point_sets
            .iter()
            .map(|s| {
                s.iter()
                    .map(|p| points_by_index.iter().position(|q| q == p).unwrap())
                    .collect()
            })
            .collect();
        // eval source of each query
        let eval_src = |q: &crate::shadow::Query, cref: CRef| -> EvalSrc {
            // identify by value against the typed evaluations
            let e = q.eval;
            let pos = |v: &[Fp]| v.iter().position(|x| *x == e);
            match cref {
                CRef::Instance(_) => EvalSrc::Instance(pos(&t.instance_evals).unwrap()),
                CRef::Advice(_) => EvalSrc::Advice(pos(&t.advice_evals).unwrap()),
                CRef::Fixed(_) => EvalSrc::Fixed(pos(&t.fixed_evals).unwrap()),
                CRef::Random => EvalSrc::Random,
                CRef::PermCommon(_) => {
                    EvalSrc::PermCommon(pos(&t.permutation_common_evals).unwrap())
                }
                CRef::PermProduct(i) => {
                    let s = &t.permutation_sets[i];
                    if s.0 == e {
                        EvalSrc::PermSet(i, 0)
                    } else if s.1 == e {
                        EvalSrc::PermSet(i, 1)
                    } else {
                        EvalSrc::PermSet(i, 2)
                    }
                }
                CRef::LookupProduct(i)
                | CRef::LookupPermutedInput(i)
                | CRef::LookupPermutedTable(i) => {
                    let l = &t.lookup_evals[i];
                    let which = [l.0, l.1, l.2, l.3, l.4]
                        .iter()
                        .position(|x| *x == e)
                        .unwrap();
                    EvalSrc::Lookup(i, which)
                }
                CRef::H => EvalSrc::ExpectedH,
            }
        };
        let x1_exp = |p: Fp| -> usize {
            let mut e = 0;
            let mut acc = Fp::ONE;
            while acc != p {
                acc *= t.x_1;
                e += 1;
                assert!(e < 1000);
            }
            e
        };
        let refs: Vec<(CRef, usize, usize, Vec<EvalSrc>)> = sh
            .commitments
            .iter()
            .enumerate()
            .map(|(ci, (cref, _))| {
                let (si, x1p) = sh.plan[ci];
                let set = &sh.point_sets[si];
                let mut slots = vec![EvalSrc::Random; set.len()];
                for q in sh.queries.iter().filter(|q| q.commitment == ci) {
                    let pos = set.iter().position(|p| *p == q.point).unwrap();
                    slots[pos] = eval_src(q, *cref);
                }
                (*cref, si, x1_exp(x1p), slots)
            })
            .collect();
        // every term with its point
        let mut terms: Vec<(Term, vesta::Affine)> = vec![(Term::QPrime, t.q_prime)];
        for (ci, (_, c)) in sh.commitments.iter().enumerate() {
            match c {
                Commitment::Point(p) => terms.push((Term::Ref(ci), *p)),
                Commitment::HChunks(hs) => {
                    for (j, h) in hs.iter().enumerate() {
                        terms.push((Term::HChunk(ci, j), *h));
                    }
                }
            }
        }
        terms.push((Term::G0, params.get_g()[0]));
        terms.push((Term::SPoly, t.s_poly));
        for (j, (l, r, _)) in t.rounds.iter().enumerate() {
            terms.push((Term::L(j), *l));
            terms.push((Term::R(j), *r));
        }
        terms.push((Term::G, cap.g));
        // the group circuit's sources, each with the terms whose point it is
        let read: Vec<vesta::Affine> = cap
            .events
            .iter()
            .filter_map(|e| match e {
                Event::ReadPoint(p) => Some(*p),
                _ => None,
            })
            .collect();
        let point_of = |s: &Source| -> vesta::Affine {
            match s {
                Source::Read(i) => read[*i],
                Source::Common => t.instance_commitment,
                Source::Constant(c) => *c,
                Source::Claim => cap.g,
            }
        };
        let outputs: Vec<Vec<Term>> = sources
            .iter()
            .map(|s| {
                let p = point_of(s);
                terms
                    .iter()
                    .filter(|(_, q)| *q == p)
                    .map(|(term, _)| *term)
                    .collect()
            })
            .collect();
        assert_eq!(
            outputs.iter().map(|o| o.len()).sum::<usize>(),
            terms.len(),
            "every term in one output"
        );
        let st = Structure {
            k_inner: params.k(),
            blinding,
            n_instance_q: cs.instance_queries().len(),
            n_advice_q: cs.advice_queries().len(),
            n_fixed_q: cs.fixed_queries().len(),
            n_perm_common: vk.permutation_commitments().len(),
            n_chunks: t.permutation_sets.len(),
            chunk_len,
            n_lookups: cs.lookups().len(),
            quotient_degree: domain.get_quotient_poly_degree(),
            gate_polys,
            perm_columns,
            lookups,
            point_rotations,
            sets,
            refs,
            outputs,
            omega: domain.get_omega(),
        };
        (st, sh)
    }
}

#[derive(Clone)]
pub struct FieldSideCircuit {
    pub structure: Structure,
    pub shadow: Option<Shadow>,
}

#[derive(Clone, Debug)]
pub struct FieldSideConfig {
    field: FieldConfig,
    instance: Column<Instance>,
}

/// The public inputs: challenges and evaluations in transcript order, then
/// the output scalars, then the `W` and `U` scalars.
impl FieldSideCircuit {
    pub fn instance(&self) -> Vec<Fp> {
        let sh = self.shadow.as_ref().expect("values");
        let t = &sh.typed;
        let mut v = transcript_order(t);
        let merged = sh.merged();
        let n_out = self.structure.outputs.len();
        // the outputs, in source order: sum of the terms' scalars
        let out = output_scalars(&self.structure, sh);
        assert_eq!(out.len(), n_out);
        let _ = merged;
        v.extend(out);
        v.push(sh.w_scalar);
        v.push(sh.u_scalar);
        v
    }
}

/// Challenges and evaluations as the transcript produced them.
fn transcript_order(t: &crate::shadow::Typed) -> Vec<Fp> {
    let mut v = vec![t.vk_repr, t.theta, t.beta, t.gamma, t.y, t.x];
    v.extend(&t.instance_evals);
    v.extend(&t.advice_evals);
    v.extend(&t.fixed_evals);
    v.push(t.random_eval);
    v.extend(&t.permutation_common_evals);
    for s in &t.permutation_sets {
        v.push(s.0);
        v.push(s.1);
        if let Some(l) = s.2 {
            v.push(l);
        }
    }
    for l in &t.lookup_evals {
        v.extend([l.0, l.1, l.2, l.3, l.4]);
    }
    v.push(t.x_1);
    v.push(t.x_2);
    v.push(t.x_3);
    v.extend(&t.multiopen_u);
    v.push(t.x_4);
    v.push(t.xi);
    v.push(t.z);
    for (_, _, u) in &t.rounds {
        v.push(*u);
    }
    v.push(t.c);
    v.push(t.f);
    v
}

/// The scalars of the outputs, natively (for the instance).
fn output_scalars(st: &Structure, sh: &Shadow) -> Vec<Fp> {
    let t = &sh.typed;
    let n_sets = st.sets.len();
    let x4 = |e: usize| t.x_4.pow_vartime([e as u64]);
    let term_scalar = |term: &Term| -> Fp {
        match term {
            Term::QPrime => x4(n_sets),
            Term::Ref(ci) => {
                let (_, si, e, _) = &st.refs[*ci];
                x4(n_sets - 1 - si) * t.x_1.pow_vartime([*e as u64])
            }
            Term::HChunk(ci, j) => {
                let (_, si, e, _) = &st.refs[*ci];
                x4(n_sets - 1 - si)
                    * t.x_1.pow_vartime([*e as u64])
                    * sh.xn.pow_vartime([*j as u64])
            }
            Term::G0 => -sh.v,
            Term::SPoly => t.xi,
            Term::L(j) => t.rounds[*j].2.invert().unwrap(),
            Term::R(j) => t.rounds[*j].2,
            Term::G => -t.c,
        }
    };
    st.outputs
        .iter()
        .map(|terms| terms.iter().map(term_scalar).sum())
        .collect()
}

impl Circuit<Fp> for FieldSideCircuit {
    type Config = FieldSideConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        FieldSideCircuit {
            structure: self.structure.clone(),
            shadow: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> FieldSideConfig {
        let advices: [Column<Advice>; 4] = core::array::from_fn(|_| meta.advice_column());
        for a in &advices {
            meta.enable_equality(*a);
        }
        let fixed: [Column<Fixed>; 5] = core::array::from_fn(|_| meta.fixed_column());
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let field = FieldConfig::configure(meta, advices, fixed);
        FieldSideConfig { field, instance }
    }

    fn synthesize(
        &self,
        cfg: FieldSideConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let st = &self.structure;
        let mut ch = FieldChip::new(&cfg.field);
        let l = &mut layouter;
        let sh = self.shadow.as_ref();
        let t = sh.map(|s| &s.typed);
        let mut row = 0usize;
        // public inputs in transcript order, witnessed and exposed
        let values: Option<Vec<Fp>> = t.map(transcript_order);
        let n_in = st_transcript_len(st);
        let mut cells: Vec<Cell> = Vec::with_capacity(n_in);
        for i in 0..n_in {
            let v = values
                .as_ref()
                .map(|v| Value::known(v[i]))
                .unwrap_or(Value::unknown());
            let c = ch.witness(l, v)?;
            l.constrain_instance(c.cell(), cfg.instance, row)?;
            row += 1;
            cells.push(c);
        }
        // name them
        let mut it = cells.iter();
        let mut take =
            |n: usize| -> Vec<Cell> { (0..n).map(|_| it.next().unwrap().clone()).collect() };
        let _vk_repr = take(1);
        let theta = take(1).remove(0);
        let beta = take(1).remove(0);
        let gamma = take(1).remove(0);
        let y = take(1).remove(0);
        let x = take(1).remove(0);
        let instance_evals = take(st.n_instance_q);
        let advice_evals = take(st.n_advice_q);
        let fixed_evals = take(st.n_fixed_q);
        let random_eval = take(1).remove(0);
        let perm_common = take(st.n_perm_common);
        let mut perm_sets: Vec<(Cell, Cell, Option<Cell>)> = Vec::new();
        for i in 0..st.n_chunks {
            let e = take(1).remove(0);
            let n = take(1).remove(0);
            let last = if i + 1 < st.n_chunks {
                Some(take(1).remove(0))
            } else {
                None
            };
            perm_sets.push((e, n, last));
        }
        let mut lookup_evals: Vec<[Cell; 5]> = Vec::new();
        for _ in 0..st.n_lookups {
            let v = take(5);
            lookup_evals.push([
                v[0].clone(),
                v[1].clone(),
                v[2].clone(),
                v[3].clone(),
                v[4].clone(),
            ]);
        }
        let x_1 = take(1).remove(0);
        let x_2 = take(1).remove(0);
        let x_3 = take(1).remove(0);
        let multiopen_u = take(st.sets.len());
        let x_4 = take(1).remove(0);
        let xi = take(1).remove(0);
        let z = take(1).remove(0);
        let u = take(st.k_inner as usize);
        let c = take(1).remove(0);
        let f = take(1).remove(0);
        assert!(it.next().is_none());

        // x^n and (x^n - 1)
        let mut xn = x.clone();
        for _ in 0..st.k_inner {
            xn = ch.mul(l, &xn, &xn)?;
        }
        let xn_minus_1 = ch.affine(l, &xn, Fp::ONE, -Fp::ONE)?;
        // l_r(x) = (x^n - 1) · ω^r / n · 1/(x - ω^r)
        let n_inv = Fp::from(1u64 << st.k_inner).invert().unwrap();
        let lagrange = |ch: &mut FieldChip, l: &mut _, r: i32| -> Result<Cell, Error> {
            let omega_r = st
                .omega
                .pow_vartime([r.rem_euclid(1i32 << st.k_inner) as u64]);
            let den = ch.affine(l, &x, Fp::ONE, -omega_r)?;
            let inv = ch.invert(l, &den)?;
            let num = ch.affine(l, &xn_minus_1, omega_r * n_inv, Fp::ZERO)?;
            ch.mul(l, &num, &inv)
        };
        let l_last = lagrange(&mut ch, l, -((st.blinding + 1) as i32))?;
        let mut l_blind: Option<Cell> = None;
        for r in -(st.blinding as i32)..0 {
            let li = lagrange(&mut ch, l, r)?;
            l_blind = Some(match l_blind {
                None => li,
                Some(acc) => ch.add(l, &acc, &li)?,
            });
        }
        let l_blind = l_blind.expect("blinding factors");
        let l_0 = lagrange(&mut ch, l, 0)?;
        let one = ch.constant(l, Fp::ONE)?;
        let active_rows = {
            let s = ch.add(l, &l_last, &l_blind)?;
            ch.sub(l, &one, &s)?
        };

        // the vanishing argument's expressions, folded with y
        let mut acc: Option<Cell> = None;
        let push =
            |ch: &mut FieldChip, l: &mut _, e: Cell, acc: &mut Option<Cell>| -> Result<(), Error> {
                *acc = Some(match acc.take() {
                    None => e,
                    Some(a) => ch.mul_add(l, &a, &y, &e)?,
                });
                Ok(())
            };
        for poly in &st.gate_polys {
            let e = ch.evaluate(
                l,
                poly,
                &|i| fixed_evals[i].clone(),
                &|i| advice_evals[i].clone(),
                &|i| instance_evals[i].clone(),
            )?;
            push(&mut ch, l, e, &mut acc)?;
        }
        // permutation
        let col_eval = |c: &ColEval| -> Cell {
            match c {
                ColEval::Advice(i) => advice_evals[*i].clone(),
                ColEval::Fixed(i) => fixed_evals[*i].clone(),
                ColEval::Instance(i) => instance_evals[*i].clone(),
            }
        };
        if let Some(first) = perm_sets.first() {
            let d = ch.sub(l, &one, &first.0)?;
            let e = ch.mul(l, &l_0, &d)?;
            push(&mut ch, l, e, &mut acc)?;
        }
        if let Some(last) = perm_sets.last() {
            let sq = ch.mul(l, &last.0, &last.0)?;
            let d = ch.sub(l, &sq, &last.0)?;
            let e = ch.mul(l, &d, &l_last)?;
            push(&mut ch, l, e, &mut acc)?;
        }
        for i in 1..perm_sets.len() {
            let prev_last = perm_sets[i - 1]
                .2
                .clone()
                .expect("last eval of a non-final chunk");
            let d = ch.sub(l, &perm_sets[i].0, &prev_last)?;
            let e = ch.mul(l, &d, &l_0)?;
            push(&mut ch, l, e, &mut acc)?;
        }
        let beta_x = ch.mul(l, &beta, &x)?;
        for (chunk_index, (set, cols)) in perm_sets
            .iter()
            .zip(st.perm_columns.chunks(st.chunk_len))
            .enumerate()
        {
            let perm_evals =
                &perm_common[chunk_index * st.chunk_len..(chunk_index * st.chunk_len + cols.len())];
            let mut left = set.1.clone();
            for (col, pe) in cols.iter().zip(perm_evals) {
                // eval + beta·pe + gamma
                let bp = ch.mul_add(l, &beta, pe, &gamma)?;
                let term = ch.add(l, &col_eval(col), &bp)?;
                left = ch.mul(l, &left, &term)?;
            }
            let mut right = set.0.clone();
            let delta0 = Fp::DELTA.pow_vartime([(chunk_index * st.chunk_len) as u64]);
            let mut current_delta = ch.affine(l, &beta_x, delta0, Fp::ZERO)?;
            for (j, col) in cols.iter().enumerate() {
                let term = {
                    let s = ch.add(l, &col_eval(col), &current_delta)?;
                    ch.add(l, &s, &gamma)?
                };
                right = ch.mul(l, &right, &term)?;
                if j + 1 < cols.len() {
                    current_delta = ch.affine(l, &current_delta, Fp::DELTA, Fp::ZERO)?;
                }
            }
            let d = ch.sub(l, &left, &right)?;
            let e = ch.mul(l, &d, &active_rows)?;
            push(&mut ch, l, e, &mut acc)?;
        }
        // lookups
        for ((input_exprs, table_exprs), ev) in st.lookups.iter().zip(&lookup_evals) {
            let [product, product_next, pin, pin_inv, ptable] = ev.clone();
            let compress =
                |ch: &mut FieldChip, l: &mut _, exprs: &[Expression<Fp>]| -> Result<Cell, Error> {
                    let mut acc: Option<Cell> = None;
                    for e in exprs {
                        let v = ch.evaluate(
                            l,
                            e,
                            &|i| fixed_evals[i].clone(),
                            &|i| advice_evals[i].clone(),
                            &|i| instance_evals[i].clone(),
                        )?;
                        acc = Some(match acc {
                            None => v,
                            Some(a) => ch.mul_add(l, &a, &theta, &v)?,
                        });
                    }
                    Ok(acc.expect("expressions"))
                };
            let left = {
                let a = ch.add(l, &pin, &beta)?;
                let b = ch.add(l, &ptable, &gamma)?;
                let ab = ch.mul(l, &a, &b)?;
                ch.mul(l, &product_next, &ab)?
            };
            let right = {
                let ci = compress(&mut ch, l, input_exprs)?;
                let ct = compress(&mut ch, l, table_exprs)?;
                let a = ch.add(l, &ci, &beta)?;
                let b = ch.add(l, &ct, &gamma)?;
                let ab = ch.mul(l, &a, &b)?;
                ch.mul(l, &product, &ab)?
            };
            let e1 = {
                let d = ch.sub(l, &one, &product)?;
                ch.mul(l, &l_0, &d)?
            };
            let e2 = {
                let sq = ch.mul(l, &product, &product)?;
                let d = ch.sub(l, &sq, &product)?;
                ch.mul(l, &l_last, &d)?
            };
            let e3 = {
                let d = ch.sub(l, &left, &right)?;
                ch.mul(l, &d, &active_rows)?
            };
            let e4 = {
                let d = ch.sub(l, &pin, &ptable)?;
                ch.mul(l, &l_0, &d)?
            };
            let e5 = {
                let d1 = ch.sub(l, &pin, &ptable)?;
                let d2 = ch.sub(l, &pin, &pin_inv)?;
                let p = ch.mul(l, &d1, &d2)?;
                ch.mul(l, &p, &active_rows)?
            };
            for e in [e1, e2, e3, e4, e5] {
                push(&mut ch, l, e, &mut acc)?;
            }
        }
        let expected_h_eval = {
            let inv = ch.invert(l, &xn_minus_1)?;
            ch.mul(l, &acc.expect("expressions"), &inv)?
        };

        // the multiopen argument: evals per set slot, interpolation, v
        let max_exp = st.refs.iter().map(|r| r.2).max().unwrap_or(0);
        let mut x1_pows = vec![one.clone()];
        for _ in 0..max_exp {
            let next = ch.mul(l, x1_pows.last().unwrap(), &x_1)?;
            x1_pows.push(next);
        }
        let eval_cell = |src: &EvalSrc| -> Cell {
            match src {
                EvalSrc::Instance(i) => instance_evals[*i].clone(),
                EvalSrc::Advice(i) => advice_evals[*i].clone(),
                EvalSrc::Fixed(i) => fixed_evals[*i].clone(),
                EvalSrc::Random => random_eval.clone(),
                EvalSrc::PermCommon(i) => perm_common[*i].clone(),
                EvalSrc::PermSet(i, w) => match w {
                    0 => perm_sets[*i].0.clone(),
                    1 => perm_sets[*i].1.clone(),
                    _ => perm_sets[*i].2.clone().unwrap(),
                },
                EvalSrc::Lookup(i, w) => lookup_evals[*i][*w].clone(),
                EvalSrc::ExpectedH => expected_h_eval.clone(),
            }
        };
        let mut q_eval_sets: Vec<Vec<Option<Cell>>> =
            st.sets.iter().map(|s| vec![None; s.len()]).collect();
        for (_, si, e, slots) in st.refs.iter().rev() {
            for (slot, src) in slots.iter().enumerate() {
                let ev = eval_cell(src);
                let scaled = ch.mul(l, &ev, &x1_pows[*e])?;
                q_eval_sets[*si][slot] = Some(match q_eval_sets[*si][slot].take() {
                    None => scaled,
                    Some(a) => ch.add(l, &a, &scaled)?,
                });
            }
        }
        // points: x · ω^r
        let omega_pow = |r: i32| {
            st.omega
                .pow_vartime([r.rem_euclid(1i32 << st.k_inner) as u64])
        };
        let x_inv = ch.invert(l, &x)?;
        let mut msm_eval: Option<Cell> = None;
        for (si, set) in st.sets.iter().enumerate() {
            let points: Vec<Cell> = set
                .iter()
                .map(|pi| ch.affine(l, &x, omega_pow(st.point_rotations[*pi]), Fp::ZERO))
                .collect::<Result<_, _>>()?;
            let evals: Vec<Cell> = q_eval_sets[si]
                .iter()
                .map(|c| c.clone().expect("every slot filled"))
                .collect();
            // r_eval = Σ_i y_i Π_{j≠i} (x_3 - p_j) / (p_i - p_j); p_i - p_j = x (ω^ri - ω^rj)
            let mut r_eval: Option<Cell> = None;
            for i in 0..set.len() {
                let mut term = evals[i].clone();
                for j in 0..set.len() {
                    if i == j {
                        continue;
                    }
                    let num = ch.sub(l, &x_3, &points[j])?;
                    let dw = omega_pow(st.point_rotations[set[i]])
                        - omega_pow(st.point_rotations[set[j]]);
                    let inv = ch.affine(l, &x_inv, dw.invert().unwrap(), Fp::ZERO)?;
                    let q = ch.mul(l, &num, &inv)?;
                    term = ch.mul(l, &term, &q)?;
                }
                r_eval = Some(match r_eval {
                    None => term,
                    Some(a) => ch.add(l, &a, &term)?,
                });
            }
            let r_eval = r_eval.expect("points");
            let mut eval = ch.sub(l, &multiopen_u[si], &r_eval)?;
            for p in &points {
                let d = ch.sub(l, &x_3, p)?;
                let inv = ch.invert(l, &d)?;
                eval = ch.mul(l, &eval, &inv)?;
            }
            msm_eval = Some(match msm_eval {
                None => eval,
                Some(a) => ch.mul_add(l, &a, &x_2, &eval)?,
            });
        }
        let mut v = msm_eval.expect("sets");
        for u_s in &multiopen_u {
            v = ch.mul_add(l, &v, &x_4, u_s)?;
        }
        // b = Π (1 + u_j x_3^{2^j}) over the rounds in reverse
        let mut b = one.clone();
        let mut cur = x_3.clone();
        for uj in u.iter().rev() {
            let f_ = ch.mul_add(l, uj, &cur, &one)?;
            b = ch.mul(l, &b, &f_)?;
            cur = ch.mul(l, &cur, &cur)?;
        }
        // the output scalars
        let n_sets = st.sets.len();
        let mut x4_pows = vec![one.clone()];
        for _ in 0..n_sets {
            let next = ch.mul(l, x4_pows.last().unwrap(), &x_4)?;
            x4_pows.push(next);
        }
        let mut xn_pows = vec![one.clone()];
        for _ in 1..st.quotient_degree {
            let next = ch.mul(l, xn_pows.last().unwrap(), &xn)?;
            xn_pows.push(next);
        }
        let neg_v = ch.neg(l, &v)?;
        let neg_c = ch.neg(l, &c)?;
        let u_inv: Vec<Cell> = u
            .iter()
            .map(|uj| ch.invert(l, uj))
            .collect::<Result<_, _>>()?;
        for terms in &st.outputs {
            let mut sum: Option<Cell> = None;
            for term in terms {
                let s = match term {
                    Term::QPrime => x4_pows[n_sets].clone(),
                    Term::Ref(ci) => {
                        let (_, si, e, _) = &st.refs[*ci];
                        ch.mul(l, &x4_pows[n_sets - 1 - si], &x1_pows[*e])?
                    }
                    Term::HChunk(ci, j) => {
                        let (_, si, e, _) = &st.refs[*ci];
                        let a = ch.mul(l, &x4_pows[n_sets - 1 - si], &x1_pows[*e])?;
                        ch.mul(l, &a, &xn_pows[*j])?
                    }
                    Term::G0 => neg_v.clone(),
                    Term::SPoly => xi.clone(),
                    Term::L(j) => u_inv[*j].clone(),
                    Term::R(j) => u[*j].clone(),
                    Term::G => neg_c.clone(),
                };
                sum = Some(match sum {
                    None => s,
                    Some(a) => ch.add(l, &a, &s)?,
                });
            }
            let out = sum.expect("terms");
            l.constrain_instance(out.cell(), cfg.instance, row)?;
            row += 1;
        }
        // W: -f; U: -c·b·z
        let w_s = ch.neg(l, &f)?;
        l.constrain_instance(w_s.cell(), cfg.instance, row)?;
        row += 1;
        let cb = ch.mul(l, &neg_c, &b)?;
        let u_s = ch.mul(l, &cb, &z)?;
        l.constrain_instance(u_s.cell(), cfg.instance, row)?;
        eprintln!("field side rows: {}", ch.rows);
        Ok(())
    }
}

fn st_transcript_len(st: &Structure) -> usize {
    6 + st.n_instance_q
        + st.n_advice_q
        + st.n_fixed_q
        + 1
        + st.n_perm_common
        + (3 * st.n_chunks - 1)
        + 5 * st.n_lookups
        + 3
        + st.sets.len()
        + 3
        + st.k_inner as usize
        + 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::tests_support::real;
    use crate::verifier::VerifierCircuit;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn the_field_side_reproduces_the_verifiers_scalars_in_circuit() {
        let (params, vk, cap) = real();
        let (_, sources) = VerifierCircuit::shape(
            &cap,
            &params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        let (structure, shadow) = Structure::build(&params, &vk, &cap, &sources);
        let circuit = FieldSideCircuit {
            structure,
            shadow: Some(shadow.clone()),
        };
        let instance = circuit.instance();
        println!("field side public inputs: {}", instance.len());
        // the outputs agree with the capture's merged terms, natively
        let merged = shadow.merged();
        let n_in = st_transcript_len(&circuit.structure);
        let outs = &instance[n_in..n_in + circuit.structure.outputs.len()];
        assert_eq!(
            outs.iter()
                .filter(|s| merged.values().any(|m| m == *s))
                .count(),
            outs.len(),
            "every output scalar is a merged term"
        );
        let mut k = 11;
        let prover = loop {
            match MockProver::run(k, &circuit, vec![instance.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k += 1;
                    assert!(k <= 20);
                }
            }
        };
        prover.assert_satisfied();
        println!("field side fits k = {k}");
        // a wrong challenge changes every scalar: refused
        let mut bad = instance.clone();
        bad[1] += Fp::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        // a wrong output scalar: refused
        let mut bad = instance.clone();
        bad[n_in] += Fp::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
    }
}

#[cfg(test)]
mod prove_tests {
    use super::*;
    use crate::verifier::tests_support::real;
    use crate::verifier::VerifierCircuit;
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// The field circuit as a Vesta-committed proof of its own (an `Fp`
    /// circuit), at k = 13:
    /// `cargo test --release prove_the_field_side -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn prove_the_field_side() {
        let (params, vk, cap) = real();
        let (_, sources) = VerifierCircuit::shape(
            &cap,
            &params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        let (structure, shadow) = Structure::build(&params, &vk, &cap, &sources);
        let circuit = FieldSideCircuit {
            structure,
            shadow: Some(shadow),
        };
        let instance = circuit.instance();
        let k = 13;
        let t = std::time::Instant::now();
        let outer: Params<vesta::Affine> = Params::new(k);
        let ovk = plonk::keygen_vk(&outer, &circuit.without_witnesses()).unwrap();
        let opk = plonk::keygen_pk(&outer, ovk.clone(), &circuit.without_witnesses()).unwrap();
        println!("keygen (k = {k}): {:.1} s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let mut tr = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
        plonk::create_proof(
            &outer,
            &opk,
            &[circuit.clone()],
            &[&[&instance[..]]],
            &mut StdRng::seed_from_u64(11),
            &mut tr,
        )
        .unwrap();
        let proof = tr.finalize();
        println!(
            "prove: {:.1} s, proof {} bytes",
            t.elapsed().as_secs_f64(),
            proof.len()
        );
        let t = std::time::Instant::now();
        let strategy = plonk::SingleVerifier::new(&outer);
        let mut tr = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        plonk::verify_proof(&outer, &ovk, strategy, &[&[&instance[..]]], &mut tr).unwrap();
        println!("verify: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    }
}
