//! The chain's two circuits with one key set (`docs/REPLAY-PROOF-A.md`
//! §3.8): `T_q(i)` = the `q` group sides of the fragment's transfer proofs,
//! the `q` group side of `T_p(i−1)` with that key's commitments as public
//! inputs and the base bit, and the field side of `T_q(i−1)`; `T_p(i)` =
//! the `p` group side of `T_q(i)` (its key's commitments as inputs), the
//! transfer proofs' field sides, the field side of `T_p(i−1)`, and the
//! relation, with `s_prev` chained to `T_p(i−1)`'s `s_next`. Neither
//! circuit's constants depend on the other's key, so the same keys serve
//! every step; the first step verifies a dummy previous step under
//! `base = 1`.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use pasta_curves::{pallas, vesta};

use crate::batch::{BatchCircuit, BatchConfig};
use crate::field;
use crate::fieldside;
use crate::step2::bind;
use crate::step4::bind_slots;
use crate::verifier::{p, q};
use sba_primitives::Fp;

/// `T_q(i)`.
#[derive(Clone)]
pub struct StepQChain {
    pub groups_pi: Vec<q::VerifierCircuit>,
    /// Over `T_p(i−1)`: `keys_as_inputs`, `allow_base`, instance values
    /// witnessed and re-exposed as the next circuits need them.
    pub group_tp: q::VerifierCircuit,
    /// The field side of `T_q(i−1)`, its values among `T_p(i−1)`'s instance.
    pub field_tq: fieldside::fq::FieldSideCircuit,
    pub links_tq: Vec<Vec<usize>>,
}

#[derive(Clone, Debug)]
pub struct StepQChainConfig {
    pub group: q::VerifierConfig,
    pub field: field::fq::FieldConfig,
}

impl std::fmt::Debug for StepQChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StepQChain({} proofs)", self.groups_pi.len())
    }
}

impl StepQChain {
    pub fn instance(&self) -> Vec<pallas::Scalar> {
        let mut v: Vec<_> = self
            .groups_pi
            .iter()
            .flat_map(|g| g.instance(g.capture.as_ref().expect("values")))
            .collect();
        v.extend(
            self.group_tp
                .instance(self.group_tp.capture.as_ref().expect("values")),
        );
        v
    }
    /// Where each transfer proof's part starts, then `T_p(i−1)`'s.
    pub fn offsets(&self) -> Vec<usize> {
        let mut v = Vec::new();
        let mut at = 0;
        for g in &self.groups_pi {
            v.push(at);
            at += g.layout().len();
        }
        v.push(at);
        v
    }
    pub fn instance_limbs_when_verified(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self
            .groups_pi
            .iter()
            .flat_map(|g| g.instance_limbs_when_verified())
            .collect();
        v.extend(self.group_tp.instance_limbs_when_verified());
        v
    }
}

impl Circuit<pallas::Scalar> for StepQChain {
    type Config = StepQChainConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        StepQChain {
            groups_pi: self
                .groups_pi
                .iter()
                .map(|g| g.without_witnesses())
                .collect(),
            group_tp: self.group_tp.without_witnesses(),
            field_tq: self.field_tq.without_witnesses(),
            links_tq: self.links_tq.clone(),
        }
    }
    fn configure(meta: &mut ConstraintSystem<pallas::Scalar>) -> StepQChainConfig {
        StepQChainConfig {
            group: q::VerifierCircuit::configure(meta),
            field: fieldside::fq::FieldSideCircuit::configure_field(meta),
        }
    }
    fn synthesize(
        &self,
        cfg: StepQChainConfig,
        mut l: impl Layouter<pallas::Scalar>,
    ) -> Result<(), Error> {
        cfg.group.assign_table(&mut l)?;
        let mut at = 0;
        for g in &self.groups_pi {
            let ex = g.synthesize_core(&cfg.group, &mut l, at)?;
            at += ex.cells.len();
        }
        let ex_tp = self.group_tp.synthesize_core(&cfg.group, &mut l, at)?;
        let (inputs, outputs) = self
            .field_tq
            .synthesize_core(&cfg.field, None, None, &mut l)?;
        let cells: Vec<_> = inputs.into_iter().chain(outputs).collect();
        let mut ch = field::fq::FieldChip::new(&cfg.field);
        bind(
            &mut ch,
            &mut l,
            &cells,
            &self.links_tq,
            &ex_tp.instance_values,
            0,
        )?;
        Ok(())
    }
}

/// `T_p(i)`.
#[derive(Clone)]
pub struct StepPChain {
    /// Over `T_q(i)`: `keys_as_inputs`; its instance values witnessed, the
    /// opened claim's challenges re-exposed for `T_q(i+1)`'s field side.
    pub group_tq: p::VerifierCircuit,
    pub fields_pi: Vec<(fieldside::fp::FieldSideCircuit, Vec<Vec<usize>>, usize)>,
    /// The field side of `T_p(i−1)`, its values in `T_q(i)`'s `T_p(i−1)` part.
    pub field_tp: (fieldside::fp::FieldSideCircuit, Vec<Vec<usize>>, usize),
    pub batch: BatchCircuit,
    pub statement_positions: Vec<Vec<usize>>,
    pub slot_proof: Vec<Option<usize>>,
    pub used: Vec<bool>,
    /// Among `T_q(i)`'s instance values, `T_p(i−1)`'s `s_next` (re-exposed),
    /// which this step's `s_prev` must equal.
    pub prev_s_next: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct StepPChainConfig {
    pub group: p::VerifierConfig,
    pub field: field::fp::FieldConfig,
    pub batch: BatchConfig,
}

impl std::fmt::Debug for StepPChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StepPChain({} proofs, {} slots)",
            self.fields_pi.len(),
            self.batch.n
        )
    }
}

impl StepPChain {
    pub fn instance(&self) -> Vec<Fp> {
        let mut v = self
            .group_tq
            .instance(self.group_tq.capture.as_ref().expect("values"));
        v.extend(self.batch.instance());
        v
    }
}

impl Circuit<vesta::Scalar> for StepPChain {
    type Config = StepPChainConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        StepPChain {
            group_tq: self.group_tq.without_witnesses(),
            fields_pi: self
                .fields_pi
                .iter()
                .map(|(f, l, o)| (f.without_witnesses(), l.clone(), *o))
                .collect(),
            field_tp: (
                self.field_tp.0.without_witnesses(),
                self.field_tp.1.clone(),
                self.field_tp.2,
            ),
            batch: self.batch.without_witnesses(),
            statement_positions: self.statement_positions.clone(),
            slot_proof: vec![None; self.slot_proof.len()],
            used: vec![false; self.used.len()],
            prev_s_next: self.prev_s_next,
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> StepPChainConfig {
        StepPChainConfig {
            group: p::VerifierCircuit::configure(meta),
            field: fieldside::fp::FieldSideCircuit::configure_field(meta),
            batch: BatchConfig::configure(meta),
        }
    }
    fn synthesize(&self, cfg: StepPChainConfig, mut l: impl Layouter<Fp>) -> Result<(), Error> {
        cfg.group.assign_table(&mut l)?;
        cfg.batch.assign_table(&mut l)?;
        let ex = self.group_tq.synthesize_core(&cfg.group, &mut l, 0)?;
        let mut ch = field::fp::FieldChip::new(&cfg.field);
        for (f, links, offset) in self.fields_pi.iter().chain(std::iter::once(&self.field_tp)) {
            let (inputs, outputs) = f.synthesize_core(&cfg.field, None, None, &mut l)?;
            let cells: Vec<_> = inputs.into_iter().chain(outputs).collect();
            bind(&mut ch, &mut l, &cells, links, &ex.instance_values, *offset)?;
        }
        let (slots, [s_prev, _, _]) = self.batch.synthesize_core(
            &cfg.batch,
            &mut l,
            Some((cfg.group.instance, ex.cells.len())),
        )?;
        bind_slots(
            &mut ch,
            &mut l,
            &slots,
            &ex.instance_values,
            &self.statement_positions,
            &self.slot_proof,
            &self.used,
            self.batch.witness.as_ref(),
        )?;
        if let Some(pos) = self.prev_s_next {
            let prev = &ex.instance_values[pos];
            assert_eq!(prev.len(), 1);
            ch.assert_equal(&mut l, &s_prev, &prev[0])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::fake_capture;
    use crate::fieldside::fq::Structure as StructureQ;
    use crate::step::tests_support::{tp, tq};
    use crate::verifier::p::Slot;
    use crate::verifier::tests_support::{q_circuit, real, real_with_seed};
    use halo2_proofs::dev::MockProver;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sba_circuit::K;

    /// `T_q(2)` of the chain over a real `T_p(1)` (base 0) and over a dummy
    /// `T_p(1)` of the same shape with the real instance (base 1, and
    /// refused with base 0): `cargo test -p sba-replay --release the_chain_t_q -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn the_chain_t_q_over_a_real_and_a_dummy_previous_step() {
        let (params, vk, cap1) = real();
        let (_, _, cap2) = real_with_seed(6);
        let (outer, ovk, instance_q1, _proof_q1, cap_q1) = tq(&params, &vk, &cap1);
        let (step1, pparams, pvk, instance_p1, _proof_p1, cap_p1, claim1) =
            tp(&params, &vk, &cap1, &outer, &ovk, &instance_q1, &cap_q1);
        // what T_q(2) re-exposes of T_p(1): the challenges of the claim
        // T_p(1) opened (the transfer's), the claim of T_q(1) (G, u)
        let qc1 = q_circuit(&params, &vk, &cap1);
        let u_pi_in_tp1: Vec<usize> = qc1
            .ipa_challenge_slots(cap1.u.len())
            .iter()
            .map(|j| step1.group.instance_value_slots(*j)[0])
            .collect();
        let layout_p1 = step1.group.layout();
        let g_q1_in_tp1: Vec<usize> = [Slot::G(0), Slot::G(1)]
            .iter()
            .map(|s| layout_p1.iter().position(|x| x == s).unwrap())
            .collect();
        let u_q1_in_tp1 = step1.group.ipa_challenge_slots(cap_q1.u.len());
        let mut re_expose = g_q1_in_tp1.clone();
        re_expose.extend(u_q1_in_tp1.iter().copied());
        let build = |cap_p: &crate::capture::Capture<vesta::Affine>, base: bool| -> StepQChain {
            let mut group_tp = q::VerifierCircuit::over(&pparams, &pvk, cap_p);
            group_tp.expose_instance = false;
            group_tp.keys_as_inputs = true;
            group_tp.allow_base = true;
            group_tp.base = base;
            group_tp.opened_u_slots = vec![u_pi_in_tp1.clone()];
            group_tp.re_expose = re_expose.clone();
            let (_, sources_q1) = p::VerifierCircuit::shape(
                &cap_q1,
                &outer,
                ovk.fixed_commitments(),
                ovk.permutation_commitments(),
            );
            let (structure, shadow) = StructureQ::build(&outer, &ovk, &cap_q1, &sources_q1);
            StepQChain {
                groups_pi: vec![q_circuit(&params, &vk, &cap2)],
                group_tp,
                field_tq: fieldside::fq::FieldSideCircuit {
                    structure,
                    shadow: Some(shadow),
                },
                links_tq: step1.group.links_for_field_side(),
            }
        };
        let step = build(&cap_p1, false);
        let instance = step.instance();
        println!("chain T_q public inputs: {}", instance.len());
        let t = std::time::Instant::now();
        let mut k = 17;
        let prover = loop {
            match MockProver::run(k, &step, vec![instance.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k += 1;
                    assert!(k <= 20);
                }
            }
        };
        prover.assert_satisfied();
        println!(
            "chain T_q fits k = {k} (mock {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<pallas::Point, _>::measure(k, &step)
        );
        // the dummy previous T_p: fake bytes of the same shape, the real
        // instance and opened claim; base 0 refused, base 1 accepted
        let (fake_p1, _bytes) = fake_capture(
            &pparams,
            &pvk,
            &instance_p1,
            std::slice::from_ref(&claim1),
            StdRng::seed_from_u64(3),
        )
        .unwrap();
        assert_eq!(fake_p1.events.len(), cap_p1.events.len());
        let dummy0 = build(&fake_p1, false);
        let pi = dummy0.instance();
        assert!(
            MockProver::run(k, &dummy0, vec![pi])
                .unwrap()
                .verify()
                .is_err()
        );
        let dummy1 = build(&fake_p1, true);
        let pi = dummy1.instance();
        MockProver::run(k, &dummy1, vec![pi])
            .unwrap()
            .assert_satisfied();
        let _ = K;
    }
}
