//! One recursive step, piece by piece (`docs/REPLAY-PROOF-A.md` §3.4):
//! `T_q` is the `q` group side of a transfer proof, proven for real as a
//! Pallas-committed proof under the Poseidon transcript over `Fp`; then
//! the `p` group side verifies *that* proof in a circuit over `Fp` — the
//! first circuit of `T_p`, measured here on its own.

#[cfg(test)]
mod tests {
    use crate::capture::{capture, Capture, Event};
    use crate::native::{PoseidonRead, PoseidonWrite};
    use crate::verifier::tests_support::{q_circuit, real};
    use crate::verifier::{p, q};
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{self, Circuit, VerifyingKey};
    use halo2_proofs::poly::commitment::Params;
    use pasta_curves::pallas;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// `T_q` over a real transfer proof: keys, a Pallas-committed proof
    /// under the Poseidon transcript, its capture.
    fn tq() -> (
        Params<pallas::Affine>,
        VerifyingKey<pallas::Affine>,
        Vec<pallas::Scalar>,
        Vec<u8>,
        Capture<pallas::Affine>,
    ) {
        let (params, vk, cap) = real();
        let circuit = q_circuit(&params, &vk, &cap);
        let instance = circuit.instance(&cap);
        let k = 15;
        let t = std::time::Instant::now();
        let outer: Params<pallas::Affine> = Params::new(k);
        let ovk = plonk::keygen_vk(&outer, &circuit.without_witnesses()).unwrap();
        let opk = plonk::keygen_pk(&outer, ovk.clone(), &circuit.without_witnesses()).unwrap();
        println!("T_q keygen (k = {k}): {:.1} s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let mut tr = PoseidonWrite::<_, pallas::Affine>::init(vec![]);
        plonk::create_proof(
            &outer,
            &opk,
            &[circuit.clone()],
            &[&[&instance[..]]],
            &mut StdRng::seed_from_u64(9),
            &mut tr,
        )
        .unwrap();
        let proof = tr.finalize();
        println!(
            "T_q prove: {:.1} s, proof {} bytes, {} public inputs",
            t.elapsed().as_secs_f64(),
            proof.len(),
            instance.len()
        );
        let t = std::time::Instant::now();
        let mut tr = PoseidonRead::<_, pallas::Affine>::init(&proof[..]);
        plonk::verify_proof(
            &outer,
            &ovk,
            plonk::SingleVerifier::new(&outer),
            &[&[&instance[..]]],
            &mut tr,
        )
        .unwrap();
        println!("T_q verify: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
        let cap_q = capture(&outer, &ovk, &instance, &proof, &[]).unwrap();
        let n = |f: &dyn Fn(&Event<pallas::Affine>) -> bool| {
            cap_q.events.iter().filter(|e| f(e)).count()
        };
        println!(
            "T_q capture: {} common points, {} common scalars, {} points read, {} scalars read, {} challenges; msm terms {} (+ W, U); claim u's {}",
            n(&|e| matches!(e, Event::CommonPoint(_))),
            n(&|e| matches!(e, Event::CommonScalar(_))),
            n(&|e| matches!(e, Event::ReadPoint(_))),
            n(&|e| matches!(e, Event::ReadScalar(_))),
            n(&|e| matches!(e, Event::Squeeze(_))),
            cap_q.terms.len(),
            cap_q.u.len()
        );
        (outer, ovk, instance, proof, cap_q)
    }

    /// `cargo test --release the_p_group_side_of_a_tq_proof -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn the_p_group_side_of_a_tq_proof_verifies_in_circuit() {
        let (outer, ovk, instance_q, _proof, cap_q) = tq();
        let (kinds, sources) = p::VerifierCircuit::shape(
            &cap_q,
            &outer,
            ovk.fixed_commitments(),
            ovk.permutation_commitments(),
        );
        let circuit = p::VerifierCircuit {
            kinds,
            sources,
            params_w: outer.get_w(),
            params_u: outer.get_u(),
            lagrange: outer.get_g_lagrange()[..instance_q.len()].to_vec(),
            capture: Some(cap_q.clone()),
        };
        let nonzero = circuit
            .scalars(&cap_q)
            .iter()
            .filter(|s| !bool::from(s.is_zero()))
            .count();
        println!(
            "T_p group side: msm terms {}, sources {} ({nonzero} non-zero), instance values of T_q {}",
            cap_q.terms.len(),
            circuit.sources.len(),
            instance_q.len()
        );
        assert_eq!(nonzero, cap_q.terms.len());
        let instance = circuit.instance(&cap_q);
        println!("T_p group side public inputs: {}", instance.len());
        let mut k = 16;
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
            "T_p group side fits k = {k} (mock prover {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        prover.assert_satisfied();
        // a wrong G of T_q is refused
        let mut bad = instance.clone();
        let n = bad.len();
        bad[n - 1] += p::F::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        // and a wrong limb of one of T_q's instance values
        let mut bad = instance.clone();
        bad[2] += p::F::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        let _ = q::N;
    }
}
