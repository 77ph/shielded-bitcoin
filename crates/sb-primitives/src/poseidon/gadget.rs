//! R1CS gadget for the Poseidon permutation and `PH`, mirroring `native.rs`.
//!
//! Round constants and MDS entries are circuit constants, so every linear
//! step is free; each S-box costs 3 constraints (`x^2`, `x^4`, `x^5`).
//! One permutation therefore costs `3 * (8 * 3 + 57) = 243` constraints.

use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

use super::{FULL_ROUNDS, PARTIAL_ROUNDS, RATE, T, params};
use crate::Fr;

type Var = FpVar<Fr>;

fn pow5_var(x: &Var) -> Result<Var, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(&x4 * x)
}

fn add_round_constants_var(state: &mut [Var; T], rc: &[Fr; T]) {
    for i in 0..T {
        state[i] = &state[i] + rc[i];
    }
}

fn mix_var(state: &mut [Var; T], mds: &[[Fr; T]; T]) {
    let mut out: [Var; T] = [Var::zero(), Var::zero(), Var::zero()];
    for (i, row) in mds.iter().enumerate() {
        let mut acc = Var::zero();
        for j in 0..T {
            acc += &state[j] * row[j];
        }
        out[i] = acc;
    }
    *state = out;
}

/// In-circuit Poseidon permutation.
pub fn permute_var(state: &mut [Var; T]) -> Result<(), SynthesisError> {
    let p = params();
    let half = FULL_ROUNDS / 2;
    let mut r = 0;
    for _ in 0..half {
        add_round_constants_var(state, &p.round_constants[r]);
        for s in state.iter_mut() {
            *s = pow5_var(s)?;
        }
        mix_var(state, &p.mds);
        r += 1;
    }
    for _ in 0..PARTIAL_ROUNDS {
        add_round_constants_var(state, &p.round_constants[r]);
        state[0] = pow5_var(&state[0])?;
        mix_var(state, &p.mds);
        r += 1;
    }
    for _ in 0..half {
        add_round_constants_var(state, &p.round_constants[r]);
        for s in state.iter_mut() {
            *s = pow5_var(s)?;
        }
        mix_var(state, &p.mds);
        r += 1;
    }
    Ok(())
}

/// In-circuit `PH(tag, inputs…)`; `tag` is a circuit constant.
pub fn hash_var(tag: Fr, inputs: &[Var]) -> Result<Var, SynthesisError> {
    let len = inputs.len() + 1;
    let mut state: [Var; T] = [
        Var::Constant(Fr::from(len as u64)),
        Var::zero(),
        Var::zero(),
    ];
    let mut elems: Vec<Var> = Vec::with_capacity(len + 1);
    elems.push(Var::Constant(tag));
    elems.extend_from_slice(inputs);
    if elems.len() % RATE != 0 {
        elems.push(Var::zero());
    }
    for chunk in elems.chunks(RATE) {
        state[1] = &state[1] + &chunk[0];
        state[2] = &state[2] + &chunk[1];
        permute_var(&mut state)?;
    }
    Ok(state[1].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::native;
    use ark_ff::UniformRand;
    use ark_r1cs_std::R1CSVar;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn gadget_matches_native_and_constraint_count() {
        let mut rng = StdRng::seed_from_u64(11);
        for n in 0..6 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let tag = Fr::rand(&mut rng);
            let inputs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let vars: Vec<Var> = inputs
                .iter()
                .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
                .collect();
            let before = cs.num_constraints();
            let out = hash_var(tag, &vars).unwrap();
            // With no witness inputs everything is constant-folded (0 constraints).
            // Otherwise the first permutation starts with constant capacity and
            // tag elements, so two S-boxes of its first round are free:
            // 237 + 243 * (perms - 1).
            let perms = (n + 2) / 2;
            let expected = if n == 0 { 0 } else { 237 + 243 * (perms - 1) };
            assert_eq!(cs.num_constraints() - before, expected, "n={n}");
            assert_eq!(out.value().unwrap(), native::hash(tag, &inputs));
            assert!(cs.is_satisfied().unwrap());
        }
    }
}
