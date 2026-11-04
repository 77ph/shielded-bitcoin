//! One recursive step, piece by piece (`docs/REPLAY-PROOF-A.md` §3.4):
//! `T_q` is the `q` group side of a transfer proof, proven for real as a
//! Pallas-committed proof under the Poseidon transcript over `Fp`; `T_p`
//! is one circuit over `Fp` made of the `p` group side of that `T_q` proof
//! and the field side of the transfer proof, the two bound together
//! in-circuit (every value the field side works on is a `T_q` instance
//! value, reconstructed from the limbs the group side exposes), proven for
//! real as a Vesta-committed proof that opens the transfer proof's claim.
//! The decider — the native verifier of `T_q` and of `T_p` with that claim
//! — never touches the transfer proof.

use ff::PrimeField;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use pasta_curves::vesta;

use crate::capture::{Capture, Event};
use crate::field::{FieldChip, FieldConfig};
use crate::fieldside::FieldSideCircuit;
use crate::verifier::p;
use sba_primitives::Fp;

/// `T_p` without the batch relation: the `p` group side of a `T_q` proof
/// and the field side of the transfer proof `T_q` verified.
#[derive(Clone)]
pub struct StepP {
    pub group: p::VerifierCircuit,
    pub field: FieldSideCircuit,
    /// For each of the field side's inputs and outputs, the index of the
    /// `T_q` instance value it must equal.
    pub link: Vec<usize>,
}

impl std::fmt::Debug for StepP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StepP({} links)", self.link.len())
    }
}

#[derive(Clone, Debug)]
pub struct StepPConfig {
    pub group: p::VerifierConfig,
    pub field: FieldConfig,
}

impl StepP {
    /// The link from the field side's cells to `T_q`'s instance values
    /// (`q::VerifierCircuit::instance`'s order): the scalar events in
    /// transcript order, skipping the transfer statement's values, then
    /// the MSM scalars, `W`'s and `U`'s.
    pub fn link(cap_pi: &Capture<vesta::Affine>, n_outputs: usize) -> Vec<usize> {
        let mut map = Vec::new();
        let mut q = 0usize;
        for e in &cap_pi.events {
            match e {
                Event::CommonScalar(_) | Event::ReadScalar(_) | Event::Squeeze(_) => {
                    map.push(q);
                    q += 1;
                }
                Event::CommonPoint(_) => q += cap_pi.instance.len(),
                Event::ReadPoint(_) => {}
            }
        }
        for i in 0..n_outputs + 2 {
            map.push(q + i);
        }
        map
    }
}

impl Circuit<Fp> for StepP {
    type Config = StepPConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        StepP {
            group: self.group.without_witnesses(),
            field: self.field.without_witnesses(),
            link: self.link.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> StepPConfig {
        StepPConfig {
            group: p::VerifierCircuit::configure(meta),
            field: FieldSideCircuit::configure_field(meta),
        }
    }

    fn synthesize(&self, cfg: StepPConfig, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let exposed = self.group.synthesize_core(&cfg.group, &mut layouter)?;
        let (inputs, outputs) = self
            .field
            .synthesize_core(&cfg.field, None, &mut layouter)?;
        // bind: each field-side value is the T_q instance value its limbs say
        let mut ch = FieldChip::new(&cfg.field);
        let l = &mut layouter;
        let two_128 = ch.constant(l, Fp::from_u128(1u128 << 64).square())?;
        for (cell, m) in inputs.iter().chain(outputs.iter()).zip(&self.link) {
            let limbs = &exposed.instance_values[*m];
            let value = if limbs.len() == 1 {
                limbs[0].clone()
            } else {
                ch.mul_add(l, &limbs[1], &two_128, &limbs[0])?
            };
            ch.assert_equal(l, cell, &value)?;
        }
        eprintln!("step: {} links", self.link.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{capture, Capture, Event};
    use crate::fieldside::Structure;
    use crate::native::{PoseidonRead, PoseidonWrite};
    use crate::verifier::tests_support::{q_circuit, real};
    use crate::verifier::{p, q};
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{self, Circuit, VerifyingKey};
    use halo2_proofs::poly::commitment::{Claim, Params};
    use pasta_curves::pallas;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// `T_q` over a real transfer proof: keys, a Pallas-committed proof
    /// under the Poseidon transcript, its capture.
    fn tq(
        params: &Params<vesta::Affine>,
        vk: &VerifyingKey<vesta::Affine>,
        cap: &Capture<vesta::Affine>,
    ) -> (
        Params<pallas::Affine>,
        VerifyingKey<pallas::Affine>,
        Vec<pallas::Scalar>,
        Vec<u8>,
        Capture<pallas::Affine>,
    ) {
        let circuit = q_circuit(params, vk, cap);
        let instance = circuit.instance(cap);
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
        let (params, vk, cap) = real();
        let (outer, ovk, instance_q, _proof, cap_q) = tq(&params, &vk, &cap);
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
            instance_limbs: q_circuit(&params, &vk, &cap).instance_limbs_when_verified(&cap),
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
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k, &circuit)
        );
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

    /// `cargo test --release one_transfer_proof_verified_recursively -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn one_transfer_proof_verified_recursively() {
        let (params, vk, cap) = real();
        let (outer, ovk, instance_q, _proof_q, cap_q) = tq(&params, &vk, &cap);
        // the p group side of T_q
        let (kinds, sources_q) = p::VerifierCircuit::shape(
            &cap_q,
            &outer,
            ovk.fixed_commitments(),
            ovk.permutation_commitments(),
        );
        let group = p::VerifierCircuit {
            kinds,
            sources: sources_q,
            params_w: outer.get_w(),
            params_u: outer.get_u(),
            lagrange: outer.get_g_lagrange()[..instance_q.len()].to_vec(),
            instance_limbs: q_circuit(&params, &vk, &cap).instance_limbs_when_verified(&cap),
            capture: Some(cap_q.clone()),
        };
        // the field side of the transfer proof, over the q circuit's sources
        let (_, sources) = q::VerifierCircuit::shape(
            &cap,
            &params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        let (structure, shadow) = Structure::build(&params, &vk, &cap, &sources);
        let link = StepP::link(&cap, structure.outputs.len());
        let field = FieldSideCircuit {
            structure,
            shadow: Some(shadow),
        };
        // the field side's values are T_q's instance values, as linked
        let field_values = field.instance();
        assert_eq!(field_values.len(), link.len());
        for (v, m) in field_values.iter().zip(&link) {
            // the same integer in both fields
            assert_eq!(v.to_repr(), instance_q[*m].to_repr(), "link {m}");
        }
        let step = StepP { group, field, link };
        let instance = step.group.instance(&cap_q);
        println!("T_p public inputs: {}", instance.len());
        let mut k = 17;
        let t = std::time::Instant::now();
        let prover = loop {
            match MockProver::run(k, &step, vec![instance.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k += 1;
                    assert!(k <= 20, "does not fit k = 20");
                }
            }
        };
        println!(
            "T_p fits k = {k} (mock prover {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        prover.assert_satisfied();
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k, &step)
        );
        drop(prover);
        // for real: a Vesta-committed proof opening the transfer proof's claim
        let claim: Claim<vesta::Affine> = cap.claim();
        let t = std::time::Instant::now();
        let pparams: Params<vesta::Affine> = Params::new(k);
        let pvk = plonk::keygen_vk(&pparams, &step.without_witnesses()).unwrap();
        let ppk = plonk::keygen_pk(&pparams, pvk.clone(), &step.without_witnesses()).unwrap();
        println!("T_p keygen (k = {k}): {:.1} s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let mut tr = PoseidonWrite::<_, vesta::Affine>::init(vec![]);
        plonk::create_proof_with_openings(
            &pparams,
            &ppk,
            &[step.clone()],
            &[&[&instance[..]]],
            &[claim.clone()],
            &mut StdRng::seed_from_u64(21),
            &mut tr,
        )
        .unwrap();
        let proof_p = tr.finalize();
        println!(
            "T_p prove: {:.1} s, proof {} bytes",
            t.elapsed().as_secs_f64(),
            proof_p.len()
        );
        // the decider: T_p with the claim the transfer proof left (its G and
        // u's are T_q's public inputs), natively
        let t = std::time::Instant::now();
        let mut tr = PoseidonRead::<_, vesta::Affine>::init(&proof_p[..]);
        plonk::verify_proof_with_openings(
            &pparams,
            &pvk,
            plonk::SingleVerifier::new(&pparams),
            &[&[&instance[..]]],
            &mut tr,
            &[claim.clone()],
        )
        .unwrap();
        println!("T_p verify: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
        let n = instance_q.len();
        let (gx, gy) = {
            use pasta_curves::arithmetic::CurveAffine;
            let c = claim.g.coordinates().unwrap();
            (*c.x(), *c.y())
        };
        assert_eq!(instance_q[n - 2], gx);
        assert_eq!(instance_q[n - 1], gy);
        // without the claim, or with a wrong one, T_p is refused
        let mut tr = PoseidonRead::<_, vesta::Affine>::init(&proof_p[..]);
        assert!(plonk::verify_proof_with_openings(
            &pparams,
            &pvk,
            plonk::SingleVerifier::new(&pparams),
            &[&[&instance[..]]],
            &mut tr,
            &[],
        )
        .is_err());
        let mut wrong = claim.clone();
        wrong.u[3] = wrong.u[3].double();
        let mut tr = PoseidonRead::<_, vesta::Affine>::init(&proof_p[..]);
        assert!(plonk::verify_proof_with_openings(
            &pparams,
            &pvk,
            plonk::SingleVerifier::new(&pparams),
            &[&[&instance[..]]],
            &mut tr,
            &[wrong],
        )
        .is_err());
    }
}
