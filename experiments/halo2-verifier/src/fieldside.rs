//! The field side of verifying one proof, as a circuit over the proof's
//! scalar field (`fieldside_body.rs`, included once per side): `fp` for
//! Vesta-committed proofs (the family's transfer proofs, `T_p`), `fq` for
//! Pallas-committed ones (`T_q`). Each is built over the matching group
//! side's sources (`verifier::q` for `fp`, `verifier::p` for `fq`).

/// Vesta-committed proofs: a circuit over `Fp`.
pub mod fp {
    use crate::field::fp as field;
    use crate::shadow::fp as shadow;
    use crate::verifier::q as group;
    use pasta_curves::vesta as curve;
    type F = curve::Scalar;
    include!("fieldside_body.rs");
}

/// Pallas-committed proofs: a circuit over `Fq`.
pub mod fq {
    use crate::field::fq as field;
    use crate::shadow::fq as shadow;
    use crate::verifier::p as group;
    use pasta_curves::pallas as curve;
    type F = curve::Scalar;
    include!("fieldside_body.rs");
}

#[cfg(test)]
mod tests {
    use super::fp::*;
    use crate::verifier::q::VerifierCircuit;
    use crate::verifier::tests_support::real;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use sba_primitives::Fp;

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
    use super::fp::*;
    use crate::verifier::q::VerifierCircuit;
    use crate::verifier::tests_support::real;
    use halo2_proofs::plonk;
    use halo2_proofs::plonk::Circuit;
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use pasta_curves::vesta;
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

#[cfg(test)]
mod fq_tests {
    use super::fq::*;
    use crate::step::tests_support::tq;
    use crate::verifier::p::VerifierCircuit;
    use crate::verifier::tests_support::real;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use pasta_curves::pallas;

    /// The field side of a real `T_q` proof, a circuit over `Fq`:
    /// `cargo test --release the_field_side_of_a_tq_proof -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn the_field_side_of_a_tq_proof_verifies_in_circuit() {
        let (params, vk, cap) = real();
        let (outer, ovk, _instance_q, _proof_q, cap_q) = tq(&params, &vk, &cap);
        let (_, sources) = VerifierCircuit::shape(
            &cap_q,
            &outer,
            ovk.fixed_commitments(),
            ovk.permutation_commitments(),
        );
        let (structure, shadow) = Structure::build(&outer, &ovk, &cap_q, &sources);
        let circuit = FieldSideCircuit {
            structure,
            shadow: Some(shadow.clone()),
        };
        let instance = circuit.instance();
        println!("T_q field side public inputs: {}", instance.len());
        let mut k = 13;
        let t = std::time::Instant::now();
        let prover = loop {
            match MockProver::run(k, &circuit, vec![instance.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k += 1;
                    assert!(k <= 20, "does not fit k = 20");
                }
            }
        };
        println!(
            "T_q field side fits k = {k} (mock prover {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        prover.assert_satisfied();
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<pallas::Point, _>::measure(k, &circuit)
        );
        // a wrong challenge, and a wrong output scalar, are refused
        let mut bad = instance.clone();
        bad[1] += pallas::Scalar::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        let mut bad = instance.clone();
        let n_in = st_transcript_len(&circuit.structure);
        bad[n_in] += pallas::Scalar::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
    }
}

#[cfg(test)]
mod opened_tests {
    use super::fp::*;
    use crate::step::tests_support::{tp, tq};
    use crate::verifier::q::VerifierCircuit;
    use crate::verifier::tests_support::real;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use sba_primitives::Fp;

    /// The field side of a real `T_p` proof — one that opened a claim: the
    /// claim's `G` is a commitment of its multi-point argument whose value
    /// at `x`, `b(x, u)`, the circuit computes from the claim's challenges
    /// (its last inputs):
    /// `cargo test --release the_field_side_of_a_tp_proof -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn the_field_side_of_a_tp_proof_with_an_opened_claim() {
        let (params, vk, cap) = real();
        let (outer, ovk, instance_q, _proof_q, cap_q) = tq(&params, &vk, &cap);
        let (_step, pparams, pvk, _instance_p, _proof_p, cap_p, claim) =
            tp(&params, &vk, &cap, &outer, &ovk, &instance_q, &cap_q);
        assert_eq!(cap_p.opened, vec![claim.u.clone()]);
        let (_, sources) = VerifierCircuit::shape(
            &cap_p,
            &pparams,
            pvk.fixed_commitments(),
            pvk.permutation_commitments(),
        );
        let (structure, shadow) = Structure::build(&pparams, &pvk, &cap_p, &sources);
        assert_eq!(structure.opened_k, vec![claim.u.len()]);
        let circuit = FieldSideCircuit {
            structure,
            shadow: Some(shadow),
        };
        let instance = circuit.instance();
        println!("T_p field side public inputs: {}", instance.len());
        let mut k = 13;
        let prover = loop {
            match MockProver::run(k, &circuit, vec![instance.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k += 1;
                    assert!(k <= 20);
                }
            }
        };
        println!("T_p field side fits k = {k}");
        prover.assert_satisfied();
        // a wrong challenge of the opened claim is refused
        let n_in = st_transcript_len(&circuit.structure);
        let mut bad = instance.clone();
        bad[n_in - 1] += Fp::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
    }
}

#[cfg(test)]
mod split_tests {
    use super::fp::*;
    use crate::split::{capture_split, SplitWrite};
    use crate::verifier::q::VerifierCircuit;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::Params;
    use pasta_curves::vesta;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sba_circuit::{TransferCircuit, K};
    use sba_primitives::Fp;

    /// The field side under the split transcript (§3.6): the evaluations
    /// absorbed into this side's sponge, `x_1 x_2 x_4` squeezed and matched,
    /// the 19 claimed scalars as outputs.
    #[test]
    fn the_field_side_under_the_split_transcript() {
        let (st, w) = crate::sample::sample();
        let params: Params<vesta::Affine> = Params::new(K);
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
            &mut StdRng::seed_from_u64(81),
            &mut tr,
        )
        .unwrap();
        let proof = tr.finalize();
        let (cap, _froms) = capture_split(&params, &vk, &instance, &proof).unwrap();
        let (_, sources) = VerifierCircuit::shape(
            &cap,
            &params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        let (mut structure, shadow) = Structure::build(&params, &vk, &cap, &sources);
        structure.split = true;
        let circuit = FieldSideCircuit {
            structure,
            shadow: Some(shadow),
        };
        let pi = circuit.instance();
        let n_in = st_transcript_len(&circuit.structure);
        println!(
            "split field side: {} public inputs ({n_in} inputs, {} claimed)",
            pi.len(),
            pi.len() - n_in
        );
        assert_eq!(pi.len() - n_in, 19);
        let mut k = 13;
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
        println!("split field side fits k = {k}");
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k, &circuit)
        );
        // an evaluation changed: the sponge's x_1 no longer matches
        let mut bad = pi.clone();
        bad[7] += Fp::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        // a claimed scalar changed
        let mut bad = pi.clone();
        bad[n_in + 1] += Fp::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
    }
}
