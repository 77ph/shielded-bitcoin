//! From a phase 1 accumulator and a circuit to the initial phase 2 proving
//! key: arkworks' Groth16 generator computed in the exponent, with
//! `γ = δ = 1`.
//!
//! The generator evaluates the QAP polynomials at a secret `t` through the
//! Lagrange basis of the evaluation domain: `aᵢ(t) = Σₖ Aₖᵢ · Lₖ(t)` (plus one
//! extra Lagrange term per public input), likewise `bᵢ`, `cᵢ`, and
//! `hᵢ = tⁱ · Z(t)` with `Z(t) = tⁿ − 1`. Every one of these is linear in
//! the powers of `t`, so with `[τ^i]` in the exponent the same values come
//! out as curve points: `[Lₖ(τ)]` is the inverse FFT of `[τ^j]` over the
//! domain, and `[τⁱ Z(τ)] = [τ^{i+n}] − [τⁱ]`.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::One;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use rayon::prelude::*;

use crate::phase1::Phase1;
use crate::{CeremonyError, CeremonyResult};

/// Size of the evaluation domain the circuit needs (what phase 1 must
/// provide at least).
pub fn domain_size<C: ConstraintSynthesizer<Fr>>(circuit: C) -> CeremonyResult<usize> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    let n = cs.num_constraints() + cs.num_instance_variables();
    Radix2EvaluationDomain::<Fr>::new(n)
        .map(|d| d.size())
        .ok_or_else(|| CeremonyError::Invalid("domain too large".into()))
}

/// Σ coeff · basis[k] over the entries of one variable, in projective form.
fn combine<G: CurveGroup<ScalarField = Fr>>(entries: &[(Fr, usize)], basis: &[G]) -> G {
    let mut acc = G::ZERO;
    for (coeff, k) in entries {
        let p = basis[*k];
        if coeff.is_one() {
            acc += p;
        } else if *coeff == -Fr::one() {
            acc -= p;
        } else {
            acc += p * coeff;
        }
    }
    acc
}

/// Transpose constraint rows `(coeff, variable)` into per-variable lists
/// `(coeff, constraint)`.
fn by_variable(rows: &[Vec<(Fr, usize)>], num_vars: usize) -> Vec<Vec<(Fr, usize)>> {
    let mut out = vec![Vec::new(); num_vars];
    for (k, row) in rows.iter().enumerate() {
        for (coeff, var) in row {
            out[*var].push((*coeff, k));
        }
    }
    out
}

/// The initial phase 2 proving key for `circuit` from the phase 1
/// accumulator `p1` (whose domain must be at least the circuit's).
pub fn initial_proving_key<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
    p1: &Phase1,
) -> CeremonyResult<ProvingKey<Bls12_381>> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    let matrices = cs
        .to_matrices()
        .ok_or_else(|| CeremonyError::Invalid("no constraint matrices".into()))?;
    let num_constraints = cs.num_constraints();
    let num_instance = cs.num_instance_variables();
    let num_vars = num_instance + cs.num_witness_variables();
    let domain = Radix2EvaluationDomain::<Fr>::new(num_constraints + num_instance)
        .ok_or_else(|| CeremonyError::Invalid("domain too large".into()))?;
    let n = domain.size();
    if p1.n < n {
        return Err(CeremonyError::Invalid(format!(
            "phase 1 covers a domain of {} but the circuit needs {n}",
            p1.n
        )));
    }
    // Lagrange basis in the exponent: [L_k(τ)] = ifft([τ^j])_k
    let lagrange = |v: &[G1Affine]| -> Vec<G1Projective> {
        let mut p: Vec<G1Projective> = v[..n].iter().map(|a| a.into_group()).collect();
        domain.ifft_in_place(&mut p);
        p
    };
    let lag_tau = lagrange(&p1.tau_g1);
    let lag_alpha = lagrange(&p1.alpha_tau_g1);
    let lag_beta = lagrange(&p1.beta_tau_g1);
    let lag_tau_g2: Vec<G2Projective> = {
        let mut p: Vec<G2Projective> = p1.tau_g2[..n].iter().map(|a| a.into_group()).collect();
        domain.ifft_in_place(&mut p);
        p
    };
    // per-variable sparse columns; the extra Lagrange term of each public
    // input is the libsnark reduction's full-rank fix
    let mut a_cols = by_variable(&matrices.a, num_vars);
    for (i, col) in a_cols.iter_mut().enumerate().take(num_instance) {
        col.push((Fr::one(), num_constraints + i));
    }
    let b_cols = by_variable(&matrices.b, num_vars);
    let c_cols = by_variable(&matrices.c, num_vars);

    let a_query: Vec<G1Projective> = a_cols.par_iter().map(|e| combine(e, &lag_tau)).collect();
    let b_g1_query: Vec<G1Projective> = b_cols.par_iter().map(|e| combine(e, &lag_tau)).collect();
    let b_g2_query: Vec<G2Projective> =
        b_cols.par_iter().map(|e| combine(e, &lag_tau_g2)).collect();
    // β·aᵢ + α·bᵢ + cᵢ, split into the public (γ = 1) and private (δ = 1) parts
    let abc: Vec<G1Projective> = (0..num_vars)
        .into_par_iter()
        .map(|i| {
            combine(&a_cols[i], &lag_beta)
                + combine(&b_cols[i], &lag_alpha)
                + combine(&c_cols[i], &lag_tau)
        })
        .collect();
    let gamma_abc_g1 = G1Projective::normalize_batch(&abc[..num_instance]);
    let l_query = G1Projective::normalize_batch(&abc[num_instance..]);
    // hᵢ = τⁱ Z(τ) = τ^{i+n} − τⁱ for i < n − 1
    let h: Vec<G1Projective> = (0..n - 1)
        .into_par_iter()
        .map(|i| p1.tau_g1[i + n].into_group() - p1.tau_g1[i].into_group())
        .collect();
    let g1 = G1Projective::generator().into_affine();
    let g2 = G2Projective::generator().into_affine();
    let vk = VerifyingKey {
        alpha_g1: p1.alpha_tau_g1[0],
        beta_g2: p1.beta_g2,
        gamma_g2: g2,
        delta_g2: g2,
        gamma_abc_g1,
    };
    Ok(ProvingKey {
        vk,
        beta_g1: p1.beta_tau_g1[0],
        delta_g1: g1,
        a_query: G1Projective::normalize_batch(&a_query),
        b_g1_query: G1Projective::normalize_batch(&b_g1_query),
        b_g2_query: G2Projective::normalize_batch(&b_g2_query),
        h_query: G1Projective::normalize_batch(&h),
        l_query,
    })
}
