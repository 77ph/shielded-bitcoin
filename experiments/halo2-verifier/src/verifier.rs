//! The group part of verifying one proof, as a circuit over the base field
//! of the proof's commitment curve (`docs/REPLAY-PROOF-A.md` §3.3–3.4):
//! the proof's points are witnessed on the curve's chip and absorbed into
//! the transcript gadget together with its scalars, the challenges are
//! squeezed, and the verifier's accumulated final multi-scalar
//! multiplication — every commitment of the proof and of the key
//! multiplied by its scalar, plus `W`, `U` and the prover's `G` — is
//! checked to be the identity. The scalars of that multiplication, the
//! challenges, the proof's scalars and the claim `(G, u_j)` are public
//! inputs: the field side (a circuit over the other field) checks that the
//! scalars are the right functions of the challenges and evaluations. What
//! this circuit therefore proves: *these* proof bytes bind *these*
//! challenges, and with *these* scalars the group equation holds.
//!
//! The instance commitment is recomputed in-circuit from the instance
//! values as `halo2_proofs`' verifier does: `Σ instance_i · G_lagrange[i] +
//! [1] W` (the default blind is one), so the statement itself is the public
//! input, not an opaque point. The `G` of every claim the proof opens
//! (`create_proof_with_openings`) is a witnessed point exposed as public
//! input, absorbed and multiplied like a commitment.
//!
//! Scalars of the verified proof are carried as `native::Limbs` says: one
//! cell on the `q` side (an `Fp` element in `Fq`, range-checked below
//! `2^254` so that it is canonical), two 128-bit limbs on the `p` side (an
//! `Fq` element in `Fp`: low limb below `2^128`, high below `2^126`, the
//! same bound); a multiplication by a two-limb scalar is two
//! multiplications, folded as `Σ [lo_i] P_i + [2^128] Σ [hi_i] P_i`.
//!
//! One body (`verifier_body.rs`), included once per side.

/// Verifies Vesta-committed proofs (the family's transfer proofs, the
/// recursion's `T_p`): a circuit over `Fq` with the ported Vesta chip.
pub mod q {
    pub use crate::fixed::q::Bases;
    use pasta_curves::vesta as curve;
    use vesta_ecc as ecc;
    use vesta_ecc::utilities::lookup_range_check::{
        LookupRangeCheck, VestaLookupRangeCheckConfig as RangeConfig,
    };
    include!("verifier_body.rs");
}

/// Verifies Pallas-committed proofs (the recursion's `T_q`): a circuit
/// over `Fp` with `halo2_gadgets`' Pallas chip.
pub mod p {
    pub use crate::fixed::p::Bases;
    use halo2_gadgets as ecc;
    use halo2_gadgets::utilities::lookup_range_check::{
        LookupRangeCheck, PallasLookupRangeCheckConfig as RangeConfig,
    };
    use pasta_curves::pallas as curve;
    include!("verifier_body.rs");
}

#[cfg(test)]
pub(crate) mod tests_support {
    use crate::capture::{capture, Capture};
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::Params;
    use pasta_curves::vesta;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use sba_circuit::{TransferCircuit, TransferParams, K};

    /// A real transfer proof, captured.
    pub(crate) fn real() -> (
        Params<vesta::Affine>,
        plonk::VerifyingKey<vesta::Affine>,
        Capture<vesta::Affine>,
    ) {
        let params = TransferParams::build().unwrap();
        let (st, w) = crate::sample::sample();
        let mut rng = StdRng::seed_from_u64(5);
        let proof = params.prove(&st, &w, &mut rng).unwrap();
        let halo_params: Params<vesta::Affine> = Params::new(K);
        let vk = plonk::keygen_vk(&halo_params, &TransferCircuit::default()).unwrap();
        let cap = capture(&halo_params, &vk, &st.to_field_elements(), &proof, &[]).unwrap();
        (halo_params, vk, cap)
    }

    /// The `q` circuit over a capture.
    pub(crate) fn q_circuit(
        params: &Params<vesta::Affine>,
        vk: &plonk::VerifyingKey<vesta::Affine>,
        cap: &Capture<vesta::Affine>,
    ) -> super::q::VerifierCircuit {
        let (kinds, sources) = super::q::VerifierCircuit::shape(
            cap,
            params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        super::q::VerifierCircuit {
            kinds,
            sources,
            params_w: params.get_w(),
            params_u: params.get_u(),
            lagrange: params.get_g_lagrange()[..cap.instance.len()].to_vec(),
            instance_limbs: vec![1; cap.instance.len()],
            expose_instance: true,
            capture: Some(cap.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::q::*;
    use super::tests_support::{q_circuit, real};
    use crate::capture::Event;
    use ff::Field;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn the_group_part_of_a_real_proof_verifies_in_circuit() {
        let (params, vk, cap) = real();
        let circuit = q_circuit(&params, &vk, &cap);
        // every MSM term found a source
        let n_terms = cap.terms.len();
        let nonzero = circuit
            .scalars(&cap)
            .iter()
            .filter(|s| !bool::from(s.is_zero()))
            .count();
        println!(
            "msm terms {n_terms}, sources {} ({nonzero} with a non-zero scalar)",
            circuit.sources.len()
        );
        assert_eq!(nonzero, n_terms);
        let instance = circuit.instance(&cap);
        println!("public inputs: {}", instance.len());
        let mut k = 15;
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
            "fits k = {k} (mock prover {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        prover.assert_satisfied();
        // a wrong scalar for one term is refused
        let mut bad = instance.clone();
        let n_transcript = cap
            .events
            .iter()
            .filter(|e| !matches!(e, Event::ReadPoint(_)))
            .map(|e| {
                if matches!(e, Event::CommonPoint(_)) {
                    cap.instance.len()
                } else {
                    1
                }
            })
            .sum::<usize>();
        bad[n_transcript] += F::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        // a wrong statement value is refused too (the commitment moves)
        let mut bad = instance.clone();
        bad[1] += F::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
        // and so is a wrong G
        let mut bad = instance.clone();
        let n = bad.len();
        bad[n - 1] += F::ONE;
        assert!(MockProver::run(k, &circuit, vec![bad])
            .unwrap()
            .verify()
            .is_err());
    }
}
