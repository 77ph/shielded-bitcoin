//! The field side of the verifier, natively: from the transcript's events
//! of one proof (`capture`) and the verifying key, recompute every scalar
//! of the accumulated final multi-scalar multiplication exactly as
//! `halo2_proofs`' verifier does — the gate, permutation and lookup
//! expressions at `x`, the vanishing identity, the multiopen combination
//! (`x_1`, `x_2`, `x_4`), the inner product's `b`, `c`, `f` — and check them
//! against the captured terms. This is the specification the `Fp` circuit
//! (`fieldside`) mirrors step by step; a step the shadow gets wrong shows up
//! here as a mismatch with the real verifier before it is put in a circuit.

use std::collections::BTreeMap;

use ff::{Field, PrimeField};
use halo2_proofs::plonk::{Any, Expression, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use pasta_curves::vesta;

use crate::capture::{Capture, Event};
use sba_primitives::Fp;

/// Everything the verifier reads and squeezes, typed and in order.
#[derive(Clone, Debug)]
pub struct Typed {
    pub vk_repr: Fp,
    pub instance_commitment: vesta::Affine,
    pub advice_commitments: Vec<vesta::Affine>,
    pub theta: Fp,
    pub lookups_permuted: Vec<(vesta::Affine, vesta::Affine)>,
    pub beta: Fp,
    pub gamma: Fp,
    pub permutation_products: Vec<vesta::Affine>,
    pub lookup_products: Vec<vesta::Affine>,
    pub random_commitment: vesta::Affine,
    pub y: Fp,
    pub h_commitments: Vec<vesta::Affine>,
    pub x: Fp,
    pub instance_evals: Vec<Fp>,
    pub advice_evals: Vec<Fp>,
    pub fixed_evals: Vec<Fp>,
    pub random_eval: Fp,
    pub permutation_common_evals: Vec<Fp>,
    /// Per product chunk: (eval, next_eval, last_eval except for the last chunk).
    pub permutation_sets: Vec<(Fp, Fp, Option<Fp>)>,
    /// Per lookup: (product, product_next, permuted_input, permuted_input_inv, permuted_table).
    pub lookup_evals: Vec<(Fp, Fp, Fp, Fp, Fp)>,
    pub x_1: Fp,
    pub x_2: Fp,
    pub q_prime: vesta::Affine,
    pub x_3: Fp,
    pub multiopen_u: Vec<Fp>,
    pub x_4: Fp,
    pub s_poly: vesta::Affine,
    pub xi: Fp,
    pub z: Fp,
    /// Per round: (L, R, u_j).
    pub rounds: Vec<(vesta::Affine, vesta::Affine, Fp)>,
    pub c: Fp,
    pub f: Fp,
}

struct Reader<'a> {
    events: &'a [Event],
    i: usize,
}

impl<'a> Reader<'a> {
    fn next(&mut self) -> &'a Event {
        let e = &self.events[self.i];
        self.i += 1;
        e
    }
    fn common_scalar(&mut self) -> Fp {
        match self.next() {
            Event::CommonScalar(s) => *s,
            e => panic!("expected a common scalar at {}, got {e:?}", self.i - 1),
        }
    }
    fn common_point(&mut self) -> vesta::Affine {
        match self.next() {
            Event::CommonPoint(p) => *p,
            e => panic!("expected a common point at {}, got {e:?}", self.i - 1),
        }
    }
    fn point(&mut self) -> vesta::Affine {
        match self.next() {
            Event::ReadPoint(p) => *p,
            e => panic!("expected a point at {}, got {e:?}", self.i - 1),
        }
    }
    fn scalar(&mut self) -> Fp {
        match self.next() {
            Event::ReadScalar(s) => *s,
            e => panic!("expected a scalar at {}, got {e:?}", self.i - 1),
        }
    }
    fn challenge(&mut self) -> Fp {
        match self.next() {
            Event::Squeeze(s) => *s,
            e => panic!("expected a challenge at {}, got {e:?}", self.i - 1),
        }
    }
    fn points(&mut self, n: usize) -> Vec<vesta::Affine> {
        (0..n).map(|_| self.point()).collect()
    }
    fn scalars(&mut self, n: usize) -> Vec<Fp> {
        (0..n).map(|_| self.scalar()).collect()
    }
}

impl Typed {
    /// Parse the events in the verifier's order (`plonk::verify_proof`).
    pub fn parse(vk: &VerifyingKey<vesta::Affine>, cap: &Capture, k: u32) -> Typed {
        let cs = vk.cs();
        let mut r = Reader { events: &cap.events, i: 0 };
        let vk_repr = r.common_scalar();
        let instance_commitment = r.common_point();
        let advice_commitments = r.points(cs.num_advice_columns());
        let theta = r.challenge();
        let lookups_permuted = cs.lookups().iter().map(|_| (r.point(), r.point())).collect();
        let beta = r.challenge();
        let gamma = r.challenge();
        let chunk_len = cs.degree() - 2;
        let n_chunks = cs.permutation().get_columns().chunks(chunk_len).count();
        let permutation_products = r.points(n_chunks);
        let lookup_products = r.points(cs.lookups().len());
        let random_commitment = r.point();
        let y = r.challenge();
        let h_commitments = r.points(vk.get_domain().get_quotient_poly_degree());
        let x = r.challenge();
        let instance_evals = r.scalars(cs.instance_queries().len());
        let advice_evals = r.scalars(cs.advice_queries().len());
        let fixed_evals = r.scalars(cs.fixed_queries().len());
        let random_eval = r.scalar();
        let permutation_common_evals = r.scalars(vk.permutation_commitments().len());
        let permutation_sets = (0..n_chunks)
            .map(|i| {
                let e = r.scalar();
                let n = r.scalar();
                let l = if i + 1 < n_chunks { Some(r.scalar()) } else { None };
                (e, n, l)
            })
            .collect();
        let lookup_evals = cs
            .lookups()
            .iter()
            .map(|_| (r.scalar(), r.scalar(), r.scalar(), r.scalar(), r.scalar()))
            .collect();
        let x_1 = r.challenge();
        let x_2 = r.challenge();
        let q_prime = r.point();
        let x_3 = r.challenge();
        // the number of point sets is only known from the query structure; read
        // scalars until the next event is a challenge
        let mut multiopen_u = Vec::new();
        while matches!(r.events[r.i], Event::ReadScalar(_)) {
            multiopen_u.push(r.scalar());
        }
        let x_4 = r.challenge();
        let s_poly = r.point();
        let xi = r.challenge();
        let z = r.challenge();
        let rounds = (0..k as usize).map(|_| (r.point(), r.point(), r.challenge())).collect();
        let c = r.scalar();
        let f = r.scalar();
        assert_eq!(r.i, cap.events.len(), "every event consumed");
        Typed {
            vk_repr,
            instance_commitment,
            advice_commitments,
            theta,
            lookups_permuted,
            beta,
            gamma,
            permutation_products,
            lookup_products,
            random_commitment,
            y,
            h_commitments,
            x,
            instance_evals,
            advice_evals,
            fixed_evals,
            random_eval,
            permutation_common_evals,
            permutation_sets,
            lookup_evals,
            x_1,
            x_2,
            q_prime,
            x_3,
            multiopen_u,
            x_4,
            s_poly,
            xi,
            z,
            rounds,
            c,
            f,
        }
    }
}

/// A query of the multiopen argument: a commitment (by index into
/// `Shadow::commitments`), an evaluation point and the claimed value.
#[derive(Clone, Debug)]
pub struct Query {
    pub commitment: usize,
    pub point: Fp,
    pub eval: Fp,
}

/// A commitment of the multiopen argument: a point, or the vanishing
/// argument's combination of the quotient chunks (`Σ xn^j h_j`).
#[derive(Clone, Debug)]
pub enum Commitment {
    Point(vesta::Affine),
    HChunks(Vec<vesta::Affine>),
}

/// Which commitment a query refers to. `halo2_proofs` keys its commitment
/// map by reference, not by value: two fixed columns with equal
/// commitments are two entries, each with its own `x_1` power.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CRef {
    Instance(usize),
    Advice(usize),
    PermProduct(usize),
    LookupProduct(usize),
    LookupPermutedInput(usize),
    LookupPermutedTable(usize),
    Fixed(usize),
    PermCommon(usize),
    H,
    Random,
}

/// The scalars, as the verifier computes them.
#[derive(Clone, Debug)]
pub struct Shadow {
    pub typed: Typed,
    pub xn: Fp,
    pub l_0: Fp,
    pub l_last: Fp,
    pub l_blind: Fp,
    pub expected_h_eval: Fp,
    pub commitments: Vec<(CRef, Commitment)>,
    pub queries: Vec<Query>,
    /// Per commitment: its set index and its `x_1` power.
    pub plan: Vec<(usize, Fp)>,
    pub point_sets: Vec<Vec<Fp>>,
    pub q_eval_sets: Vec<Vec<Fp>>,
    pub msm_eval: Fp,
    pub v: Fp,
    pub b: Fp,
    /// `(scalar, point)` of the final MSM, before merging equal points.
    pub terms: Vec<(Fp, vesta::Affine)>,
    pub w_scalar: Fp,
    pub u_scalar: Fp,
}

fn eval_at(e: &Expression<Fp>, fixed: &[Fp], advice: &[Fp], instance: &[Fp]) -> Fp {
    e.evaluate(
        &|s| s,
        &|_| panic!("virtual selectors are removed during optimization"),
        &|q| fixed[q.index()],
        &|q| advice[q.index()],
        &|q| instance[q.index()],
        &|a| -a,
        &|a, b| a + b,
        &|a, b| a * b,
        &|a, s| a * s,
    )
}

/// Lagrange interpolation through `(points[i], evals[i])`, evaluated at `at`.
pub fn interpolate_at(points: &[Fp], evals: &[Fp], at: Fp) -> Fp {
    let mut acc = Fp::ZERO;
    for (i, (xi, yi)) in points.iter().zip(evals).enumerate() {
        let mut term = *yi;
        for (j, xj) in points.iter().enumerate() {
            if i != j {
                term *= (at - xj) * (*xi - xj).invert().unwrap();
            }
        }
        acc += term;
    }
    acc
}

impl Shadow {
    pub fn compute(params: &Params<vesta::Affine>, vk: &VerifyingKey<vesta::Affine>, cap: &Capture) -> Shadow {
        let t = Typed::parse(vk, cap, params.k());
        let cs = vk.cs();
        let domain = vk.get_domain();
        let n = 1u64 << params.k();
        let xn = t.x.pow([n, 0, 0, 0]);
        let blinding = cs.blinding_factors();
        let l_evals = domain.l_i_range(t.x, xn, (-((blinding + 1) as i32))..=0);
        let l_last = l_evals[0];
        let l_blind: Fp = l_evals[1..(1 + blinding)].iter().sum();
        let l_0 = l_evals[1 + blinding];

        // the expressions of the vanishing argument, in the verifier's order
        let mut expressions: Vec<Fp> = Vec::new();
        for gate in cs.gates() {
            for poly in gate.polynomials() {
                expressions.push(eval_at(poly, &t.fixed_evals, &t.advice_evals, &t.instance_evals));
            }
        }
        // permutation
        let chunk_len = cs.degree() - 2;
        let columns = cs.permutation().get_columns();
        let eval_of = |column: halo2_proofs::plonk::Column<Any>| -> Fp {
            let i = cs.get_any_query_index(column);
            match column.column_type() {
                Any::Advice => t.advice_evals[i],
                Any::Fixed => t.fixed_evals[i],
                Any::Instance => t.instance_evals[i],
            }
        };
        if let Some(first) = t.permutation_sets.first() {
            expressions.push(l_0 * (Fp::ONE - first.0));
        }
        if let Some(last) = t.permutation_sets.last() {
            expressions.push((last.0.square() - last.0) * l_last);
        }
        for (set, prev) in t.permutation_sets.iter().skip(1).zip(t.permutation_sets.iter()) {
            expressions.push((set.0 - prev.2.unwrap()) * l_0);
        }
        for (chunk_index, ((set, cols), perm_evals)) in t
            .permutation_sets
            .iter()
            .zip(columns.chunks(chunk_len))
            .zip(t.permutation_common_evals.chunks(chunk_len))
            .enumerate()
        {
            let mut left = set.1;
            for (col, pe) in cols.iter().zip(perm_evals) {
                left *= eval_of(*col) + t.beta * pe + t.gamma;
            }
            let mut right = set.0;
            let mut current_delta = (t.beta * t.x) * Fp::DELTA.pow_vartime([(chunk_index * chunk_len) as u64]);
            for col in cols {
                right *= eval_of(*col) + current_delta + t.gamma;
                current_delta *= Fp::DELTA;
            }
            expressions.push((left - right) * (Fp::ONE - (l_last + l_blind)));
        }
        // lookups
        let active_rows = Fp::ONE - (l_last + l_blind);
        for (arg, ev) in cs.lookups().iter().zip(&t.lookup_evals) {
            let (product, product_next, pin, pin_inv, ptable) = *ev;
            let compress = |exprs: &[Expression<Fp>]| {
                exprs
                    .iter()
                    .map(|e| eval_at(e, &t.fixed_evals, &t.advice_evals, &t.instance_evals))
                    .fold(Fp::ZERO, |acc, e| acc * t.theta + e)
            };
            let left = product_next * (pin + t.beta) * (ptable + t.gamma);
            let right = product * (compress(&arg.input_expressions) + t.beta) * (compress(&arg.table_expressions) + t.gamma);
            expressions.push(l_0 * (Fp::ONE - product));
            expressions.push(l_last * (product.square() - product));
            expressions.push((left - right) * active_rows);
            expressions.push(l_0 * (pin - ptable));
            expressions.push((pin - ptable) * (pin - pin_inv) * active_rows);
        }
        let expected_h_eval =
            expressions.iter().fold(Fp::ZERO, |h, v| h * t.y + v) * (xn - Fp::ONE).invert().unwrap();

        // the queries, in the verifier's order
        let mut commitments: Vec<(CRef, Commitment)> = Vec::new();
        let mut queries: Vec<Query> = Vec::new();
        let index_of = |r: CRef, c: Commitment, commitments: &mut Vec<(CRef, Commitment)>| -> usize {
            if let Some(i) = commitments.iter().position(|(x, _)| *x == r) {
                return i;
            }
            commitments.push((r, c));
            commitments.len() - 1
        };
        let rot = |r: Rotation| domain.rotate_omega(t.x, r);
        for (qi, (col, at)) in cs.instance_queries().iter().enumerate() {
            let ci = index_of(CRef::Instance(col.index()), Commitment::Point(t.instance_commitment), &mut commitments);
            queries.push(Query { commitment: ci, point: rot(*at), eval: t.instance_evals[qi] });
        }
        for (qi, (col, at)) in cs.advice_queries().iter().enumerate() {
            let ci = index_of(CRef::Advice(col.index()), Commitment::Point(t.advice_commitments[col.index()]), &mut commitments);
            queries.push(Query { commitment: ci, point: rot(*at), eval: t.advice_evals[qi] });
        }
        // permutation queries
        let x_next = rot(Rotation::next());
        let x_last = rot(Rotation(-((blinding + 1) as i32)));
        for (i, (set, pc)) in t.permutation_sets.iter().zip(&t.permutation_products).enumerate() {
            let ci = index_of(CRef::PermProduct(i), Commitment::Point(*pc), &mut commitments);
            queries.push(Query { commitment: ci, point: t.x, eval: set.0 });
            queries.push(Query { commitment: ci, point: x_next, eval: set.1 });
        }
        for (i, (set, pc)) in t.permutation_sets.iter().zip(&t.permutation_products).enumerate().rev().skip(1) {
            let ci = index_of(CRef::PermProduct(i), Commitment::Point(*pc), &mut commitments);
            queries.push(Query { commitment: ci, point: x_last, eval: set.2.unwrap() });
        }
        // lookup queries
        let x_inv = rot(Rotation::prev());
        for (i, (((pin_c, ptable_c), prod_c), ev)) in t.lookups_permuted.iter().zip(&t.lookup_products).zip(&t.lookup_evals).enumerate() {
            let (product, product_next, pin, pin_inv, ptable) = *ev;
            let cp = index_of(CRef::LookupProduct(i), Commitment::Point(*prod_c), &mut commitments);
            let cpi = index_of(CRef::LookupPermutedInput(i), Commitment::Point(*pin_c), &mut commitments);
            let cpt = index_of(CRef::LookupPermutedTable(i), Commitment::Point(*ptable_c), &mut commitments);
            queries.push(Query { commitment: cp, point: t.x, eval: product });
            queries.push(Query { commitment: cpi, point: t.x, eval: pin });
            queries.push(Query { commitment: cpt, point: t.x, eval: ptable });
            queries.push(Query { commitment: cpi, point: x_inv, eval: pin_inv });
            queries.push(Query { commitment: cp, point: x_next, eval: product_next });
        }
        // fixed queries
        for (qi, (col, at)) in cs.fixed_queries().iter().enumerate() {
            let ci = index_of(CRef::Fixed(col.index()), Commitment::Point(vk.fixed_commitments()[col.index()]), &mut commitments);
            queries.push(Query { commitment: ci, point: rot(*at), eval: t.fixed_evals[qi] });
        }
        // permutation common queries
        for (i, (pc, pe)) in vk.permutation_commitments().iter().zip(&t.permutation_common_evals).enumerate() {
            let ci = index_of(CRef::PermCommon(i), Commitment::Point(*pc), &mut commitments);
            queries.push(Query { commitment: ci, point: t.x, eval: *pe });
        }
        // vanishing: h chunks (as one MSM) and the random polynomial
        let ch = index_of(CRef::H, Commitment::HChunks(t.h_commitments.clone()), &mut commitments);
        queries.push(Query { commitment: ch, point: t.x, eval: expected_h_eval });
        let cr = index_of(CRef::Random, Commitment::Point(t.random_commitment), &mut commitments);
        queries.push(Query { commitment: cr, point: t.x, eval: t.random_eval });

        // intermediate sets, as `construct_intermediate_sets`
        let mut point_index: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        let mut points_by_index: Vec<Fp> = Vec::new();
        for q in &queries {
            let key = q.point.to_repr();
            if !point_index.contains_key(&key) {
                point_index.insert(key, points_by_index.len());
                points_by_index.push(q.point);
            }
        }
        // per commitment (in first-appearance order): its point-index set
        let n_comm = commitments.len();
        let mut comm_point_sets: Vec<Vec<usize>> = vec![Vec::new(); n_comm];
        for q in &queries {
            let pi = point_index[&q.point.to_repr()];
            if !comm_point_sets[q.commitment].contains(&pi) {
                comm_point_sets[q.commitment].push(pi);
            }
        }
        for s in comm_point_sets.iter_mut() {
            s.sort();
        }
        let mut sets: Vec<Vec<usize>> = Vec::new();
        let mut set_of: Vec<usize> = vec![0; n_comm];
        for (ci, s) in comm_point_sets.iter().enumerate() {
            let si = match sets.iter().position(|x| x == s) {
                Some(i) => i,
                None => {
                    sets.push(s.clone());
                    sets.len() - 1
                }
            };
            set_of[ci] = si;
        }
        let point_sets: Vec<Vec<Fp>> = sets.iter().map(|s| s.iter().map(|&i| points_by_index[i]).collect()).collect();
        // evals of each commitment at its set's points, in the set's order
        let mut comm_evals: Vec<Vec<Fp>> = (0..n_comm).map(|ci| vec![Fp::ZERO; sets[set_of[ci]].len()]).collect();
        for q in &queries {
            let pi = point_index[&q.point.to_repr()];
            let pos = sets[set_of[q.commitment]].iter().position(|&i| i == pi).unwrap();
            comm_evals[q.commitment][pos] = q.eval;
        }
        // accumulation in reverse commitment order with per-set x_1 powers
        let mut x_1_power: Vec<Fp> = vec![Fp::ONE; sets.len()];
        let mut plan: Vec<(usize, Fp)> = vec![(0, Fp::ZERO); n_comm];
        let mut q_eval_sets: Vec<Vec<Fp>> = sets.iter().map(|s| vec![Fp::ZERO; s.len()]).collect();
        for ci in (0..n_comm).rev() {
            let si = set_of[ci];
            plan[ci] = (si, x_1_power[si]);
            for (e, acc) in comm_evals[ci].iter().zip(q_eval_sets[si].iter_mut()) {
                *acc += *e * x_1_power[si];
            }
            x_1_power[si] *= t.x_1;
        }
        assert_eq!(t.multiopen_u.len(), sets.len(), "one u per point set");
        let mut msm_eval = Fp::ZERO;
        for ((points, evals), proof_eval) in point_sets.iter().zip(&q_eval_sets).zip(&t.multiopen_u) {
            let r_eval = interpolate_at(points, evals, t.x_3);
            let mut eval = *proof_eval - r_eval;
            for p in points {
                eval *= (t.x_3 - p).invert().unwrap();
            }
            msm_eval = msm_eval * t.x_2 + eval;
        }
        let n_sets = sets.len();
        let mut v = msm_eval;
        for u in &t.multiopen_u {
            v = v * t.x_4 + u;
        }
        // scalars of the final MSM
        let x4_pow = |e: usize| t.x_4.pow_vartime([e as u64]);
        let mut terms: Vec<(Fp, vesta::Affine)> = Vec::new();
        terms.push((x4_pow(n_sets), t.q_prime));
        for (ci, (_, c)) in commitments.iter().enumerate() {
            let (si, x1p) = plan[ci];
            let s = x4_pow(n_sets - 1 - si) * x1p;
            match c {
                Commitment::Point(p) => terms.push((s, *p)),
                Commitment::HChunks(hs) => {
                    let mut xn_pow = Fp::ONE;
                    for h in hs {
                        terms.push((s * xn_pow, *h));
                        xn_pow *= xn;
                    }
                }
            }
        }
        terms.push((-v, params.get_g()[0]));
        terms.push((t.xi, t.s_poly));
        let u: Vec<Fp> = t.rounds.iter().map(|r| r.2).collect();
        for (l, r, uj) in &t.rounds {
            terms.push((uj.invert().unwrap(), *l));
            terms.push((*uj, *r));
        }
        // b = Π (1 + u_j x_3^{2^j}) over the rounds in reverse
        let mut b = Fp::ONE;
        let mut cur = t.x_3;
        for uj in u.iter().rev() {
            b *= Fp::ONE + *uj * cur;
            cur = cur.square();
        }
        let u_scalar = -t.c * b * t.z;
        let w_scalar = -t.f;
        terms.push((-t.c, cap.g));
        Shadow {
            typed: t,
            xn,
            l_0,
            l_last,
            l_blind,
            expected_h_eval,
            commitments,
            queries,
            plan,
            point_sets,
            q_eval_sets,
            msm_eval,
            v,
            b,
            terms,
            w_scalar,
            u_scalar,
        }
    }

    /// The terms merged by point, as `halo2_proofs`' MSM keeps them.
    pub fn merged(&self) -> BTreeMap<[u8; 64], Fp> {
        use pasta_curves::arithmetic::CurveAffine;
        let mut m: BTreeMap<[u8; 64], Fp> = BTreeMap::new();
        for (s, p) in &self.terms {
            let c = p.coordinates().unwrap();
            let mut key = [0u8; 64];
            key[..32].copy_from_slice(&c.x().to_repr());
            key[32..].copy_from_slice(&c.y().to_repr());
            *m.entry(key).or_insert(Fp::ZERO) += s;
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::tests_support::real;

    #[test]
    fn the_shadow_reproduces_the_verifiers_scalars() {
        let (params, vk, cap) = real();
        let sh = Shadow::compute(&params, &vk, &cap);
        println!(
            "commitments {}, queries {}, point sets {} (sizes {:?}), terms {} (merged {})",
            sh.commitments.len(),
            sh.queries.len(),
            sh.point_sets.len(),
            sh.point_sets.iter().map(|s| s.len()).collect::<Vec<_>>(),
            sh.terms.len(),
            sh.merged().len()
        );
        let ours = sh.merged();
        let mut theirs: BTreeMap<[u8; 64], Fp> = BTreeMap::new();
        for (s, p) in &cap.terms {
            use pasta_curves::arithmetic::CurveAffine;
            let c = p.coordinates().unwrap();
            let mut key = [0u8; 64];
            key[..32].copy_from_slice(&c.x().to_repr());
            key[32..].copy_from_slice(&c.y().to_repr());
            *theirs.entry(key).or_insert(Fp::ZERO) += s;
        }
        assert_eq!(ours.len(), theirs.len(), "same set of points");
        let mut mismatches = 0;
        let label = |key: &[u8; 64]| -> String {
            let t = &sh.typed;
            let same = |p: &vesta::Affine| {
                use pasta_curves::arithmetic::CurveAffine;
                let c = p.coordinates().unwrap();
                key[..32] == c.x().to_repr()[..] && key[32..] == c.y().to_repr()[..]
            };
            if same(&t.q_prime) { return "q_prime".into(); }
            if same(&t.s_poly) { return "s_poly".into(); }
            if same(&t.random_commitment) { return "random".into(); }
            if same(&t.instance_commitment) { return "instance".into(); }
            if same(&cap.g) { return "G".into(); }
            if same(&params.get_g()[0]) { return "G_0".into(); }
            for (i, p) in t.advice_commitments.iter().enumerate() { if same(p) { return format!("advice[{i}]"); } }
            for (i, p) in t.h_commitments.iter().enumerate() { if same(p) { return format!("h[{i}]"); } }
            for (i, p) in t.permutation_products.iter().enumerate() { if same(p) { return format!("perm_product[{i}]"); } }
            for (i, p) in t.lookup_products.iter().enumerate() { if same(p) { return format!("lookup_product[{i}]"); } }
            for (i, (a, b)) in t.lookups_permuted.iter().enumerate() { if same(a) { return format!("lookup_permuted_input[{i}]"); } if same(b) { return format!("lookup_permuted_table[{i}]"); } }
            for (i, (l, r, _)) in t.rounds.iter().enumerate() { if same(l) { return format!("L[{i}]"); } if same(r) { return format!("R[{i}]"); } }
            for (i, p) in vk.fixed_commitments().iter().enumerate() { if same(p) { return format!("fixed[{i}]"); } }
            for (i, p) in vk.permutation_commitments().iter().enumerate() { if same(p) { return format!("perm_common[{i}]"); } }
            "?".into()
        };
        for (k, s) in &ours {
            if theirs.get(k) != Some(s) {
                mismatches += 1;
                let th = theirs[k];
                let ratio = th * s.invert().unwrap_or(Fp::ZERO);
                let mut note = String::new();
                for e in 0..8u64 {
                    if ratio == sh.typed.x_1.pow_vartime([e]) { note = format!("theirs = ours * x_1^{e}"); }
                    if ratio == sh.typed.x_4.pow_vartime([e]) { note = format!("theirs = ours * x_4^{e}"); }
                    if ratio == sh.typed.x_1.pow_vartime([e]).invert().unwrap() { note = format!("theirs = ours / x_1^{e}"); }
                    if ratio == sh.typed.x_4.pow_vartime([e]).invert().unwrap() { note = format!("theirs = ours / x_4^{e}"); }
                }
                println!("mismatch {}: {note}", label(k));
            }
        }
        assert_eq!(mismatches, 0, "every scalar as the verifier computes it");
        assert_eq!(sh.w_scalar, cap.w_scalar);
        assert_eq!(sh.u_scalar, cap.u_scalar);
    }
}
