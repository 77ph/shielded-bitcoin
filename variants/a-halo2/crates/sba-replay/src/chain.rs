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
    /// Among `T_q(i)`'s instance values, `T_p(i−1)`'s `g` (re-exposed): the
    /// chain's genesis digest, this step's fourth public value — equal to
    /// the previous step's, or to this step's `s_prev` in the base step.
    pub prev_g: Option<usize>,
    /// Among `T_q(i)`'s instance values, its `base` bit.
    pub base_pos: Option<usize>,
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
    /// The public inputs: `T_q(i)`'s group side's exposure, the relation's
    /// `[s_prev, s_next, D]`, then `g` — the chain's genesis digest.
    pub fn instance(&self) -> Vec<Fp> {
        let cap = self.group_tq.capture.as_ref().expect("values");
        let mut v = self.group_tq.instance(cap);
        let batch = self.batch.instance();
        let g = match (self.base_pos, self.prev_g) {
            (Some(b), Some(pg)) => {
                // T_q(i)'s instance values are Fq cells holding Fp integers
                let as_fp = |x: &vesta::Base| {
                    Option::from(Fp::from_repr(x.to_repr())).expect("an Fp value in an Fq cell")
                };
                if as_fp(&cap.instance[b]) == Fp::from(1u64) {
                    batch[0]
                } else {
                    as_fp(&cap.instance[pg])
                }
            }
            _ => batch[0],
        };
        v.extend(batch);
        v.push(g);
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
            prev_g: self.prev_g,
            base_pos: self.base_pos,
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> StepPChainConfig {
        let group = p::VerifierCircuit::configure(meta);
        StepPChainConfig {
            batch: BatchConfig::configure_in(meta, group.instance),
            group,
            field: fieldside::fp::FieldSideCircuit::configure_field(meta),
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
        // g = prev_g + base · (s_prev − prev_g): the previous step's genesis
        // digest, or this step's s_prev when this is the base step
        let mut ctx = crate::batch::Ctx::new(&cfg.batch);
        let g = match (self.base_pos, self.prev_g) {
            (Some(b), Some(pg)) => {
                let base = &ex.instance_values[b];
                let prev_g = &ex.instance_values[pg];
                assert_eq!((base.len(), prev_g.len()), (1, 1));
                let d = ctx.sub(&mut l, &s_prev, &prev_g[0])?;
                let t = ctx.mul(&mut l, &base[0], &d)?;
                ctx.add(&mut l, &prev_g[0], &t)?
            }
            _ => s_prev.clone(),
        };
        l.constrain_instance(g.cell(), cfg.group.instance, ex.cells.len() + 3)?;
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

// ---------------------------------------------------------------- keys, prover, decider

use crate::capture::{Capture, capture, fake_capture};
use crate::persist::ChainState;
use crate::wire::ProvenStep;
use bitcoin::{Block, BlockHash};
use blake2::{Blake2s256, Digest};
use ff::PrimeField;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::{self, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::{Claim, Params};
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, EncodedChallenge, Transcript};
use rand::rngs::OsRng;
use sba_circuit::{K, TransferCircuit, TransferParams, TransferStatement};
use sba_core::batch::{BatchParams, BatchWitness, StateOpening};
use sba_indexer::{BlockId, ChainError, ChainSource, Indexer, StateStore};

/// Positions in a group side's layout: its claim's `G` and `u`.
fn claim_positions(g: &q::VerifierCircuit, k: usize) -> Vec<usize> {
    let layout = g.layout();
    let mut v: Vec<usize> = [q::Slot::G(0), q::Slot::G(1)]
        .iter()
        .map(|s| layout.iter().position(|x| x == s).expect("G exposed"))
        .collect();
    v.extend(g.ipa_challenge_slots(k));
    v
}
fn claim_positions_p(g: &p::VerifierCircuit, k: usize) -> Vec<usize> {
    let layout = g.layout();
    let mut v: Vec<usize> = [p::Slot::G(0), p::Slot::G(1)]
        .iter()
        .map(|s| layout.iter().position(|x| x == s).expect("G exposed"))
        .collect();
    v.extend(g.ipa_challenge_slots(k));
    v
}

/// A claim read out of public inputs at `positions` (`G` coordinates, then
/// `u`, 128-bit values carried as one cell each).
fn claim_at<C: crate::native::Limbs>(
    values: &[C::Base],
    positions: &[usize],
) -> Result<Claim<C>, String> {
    use ff::Field;
    let at = |i: usize| -> Result<C::Base, String> {
        values
            .get(positions[i])
            .copied()
            .ok_or_else(|| "short instance".to_string())
    };
    let g: C = Option::from(C::from_xy(at(0)?, at(1)?)).ok_or("G off the curve")?;
    let mut u = Vec::with_capacity(positions.len() - 2);
    for i in 2..positions.len() {
        u.push(C::from_limbs(&[at(i)?, C::Base::ZERO]));
    }
    Ok(Claim { g, u })
}

/// The key commitments a group side exposes (`Source::Key` order).
fn key_commitments_q(g: &q::VerifierCircuit) -> Vec<vesta::Affine> {
    g.sources
        .iter()
        .filter_map(|s| {
            if let q::Source::Key(c) = s {
                Some(*c)
            } else {
                None
            }
        })
        .collect()
}
fn key_commitments_p(g: &p::VerifierCircuit) -> Vec<pallas::Affine> {
    g.sources
        .iter()
        .filter_map(|s| {
            if let p::Source::Key(c) = s {
                Some(*c)
            } else {
                None
            }
        })
        .collect()
}
/// Where a group side's layout puts the j-th instance value of the proof
/// it verifies (one cell).
fn pos_q(g: &q::VerifierCircuit, j: usize) -> usize {
    g.layout()
        .iter()
        .position(|s| matches!(s, q::Slot::InstanceValue(i, _) if *i == j))
        .expect("exposed")
}
fn pos_p(g: &p::VerifierCircuit, j: usize) -> usize {
    g.layout()
        .iter()
        .position(|s| matches!(s, p::Slot::InstanceValue(i, _) if *i == j))
        .expect("exposed")
}
/// Where a `q` group side exposes its `base` bit.
fn base_slot_q(g: &q::VerifierCircuit) -> usize {
    g.layout()
        .iter()
        .position(|s| matches!(s, q::Slot::Base))
        .expect("base")
}
fn key_slots_q(g: &q::VerifierCircuit) -> Vec<usize> {
    g.layout()
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s, q::Slot::Key(..)))
        .map(|(i, _)| i)
        .collect()
}
fn key_slots_p(g: &p::VerifierCircuit) -> Vec<usize> {
    g.layout()
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s, p::Slot::Key(..)))
        .map(|(i, _)| i)
        .collect()
}

/// The chain's circuits from the previous step's captures (real or fake):
/// the shapes, and the values when the captures carry them.
pub struct Shaper<'k> {
    pub tparams: &'k Params<vesta::Affine>,
    pub tvk: &'k VerifyingKey<vesta::Affine>,
    pub outer: &'k Params<pallas::Affine>,
    pub pparams: &'k Params<vesta::Affine>,
    pub pvk: &'k VerifyingKey<vesta::Affine>,
    pub ovk: &'k VerifyingKey<pallas::Affine>,
    pub n_slots: usize,
    pub batch_params: BatchParams,
}

impl Shaper<'_> {
    /// `T_q(i)`: the fragment's transfer captures; `T_p(i−1)`'s capture and
    /// the `T_p` circuit it is a proof of (for where its instance puts
    /// things); `T_q(i−1)`'s capture; the base bit.
    pub fn step_q(
        &self,
        caps: &[Capture<vesta::Affine>],
        prev_p: &Capture<vesta::Affine>,
        prev_sp: &StepPChain,
        prev_q: &Capture<pallas::Affine>,
        base: bool,
    ) -> StepQChain {
        let groups_pi: Vec<q::VerifierCircuit> = caps
            .iter()
            .map(|c| q::VerifierCircuit::over(self.tparams, self.tvk, c))
            .collect();
        let g_prev = &prev_sp.group_tq;
        let k_q = prev_q.u.len();
        // T_p(i−1)'s instance: the re-exposed T_q(i−1) values (the u's of
        // the n+1 claims T_p(i−1) opened) sit at pos_p(j) for j in g_prev.re_expose
        let n = caps.len();
        let k_t = K as usize;
        let mut opened_u_slots = Vec::new();
        let mut it = g_prev.re_expose.iter();
        for _ in 0..n {
            opened_u_slots.push(
                (0..k_t)
                    .map(|_| pos_p(g_prev, *it.next().expect("re-exposed")))
                    .collect::<Vec<_>>(),
            );
        }
        let k_p = prev_p.u.len();
        opened_u_slots.push(
            (0..k_p)
                .map(|_| pos_p(g_prev, *it.next().expect("re-exposed")))
                .collect::<Vec<_>>(),
        );
        // T_q(i−1)'s claim (G, u), then T_p(i−1)'s s_next and g, as T_p(i−1)
        // instance indices (its instance ends [s_prev, s_next, D, g])
        let mut re_expose = claim_positions_p(g_prev, k_q);
        let n_p = prev_p.instance.len();
        re_expose.push(n_p - 3);
        re_expose.push(n_p - 1);
        let mut group_tp = q::VerifierCircuit::over(self.pparams, self.pvk, prev_p);
        group_tp.expose_instance = false;
        group_tp.keys_as_inputs = true;
        group_tp.allow_base = true;
        group_tp.base = base;
        group_tp.opened_u_slots = opened_u_slots;
        group_tp.re_expose = re_expose;
        // the field side of T_q(i−1): its values in T_p(i−1)'s instance as
        // T_p(i−1)'s group side laid them out
        let (_, sources) = p::VerifierCircuit::shape(
            prev_q,
            self.outer,
            self.ovk.fixed_commitments(),
            self.ovk.permutation_commitments(),
        );
        let (structure, shadow) =
            fieldside::fq::Structure::build(self.outer, self.ovk, prev_q, &sources);
        StepQChain {
            groups_pi,
            group_tp,
            field_tq: fieldside::fq::FieldSideCircuit {
                structure,
                shadow: Some(shadow),
            },
            links_tq: g_prev.links_for_field_side(),
        }
    }

    /// `T_p(i)`: over `T_q(i)`'s capture and circuit, the transfer
    /// captures, `T_p(i−1)`'s capture (its field side) and the previous
    /// `T_p` circuit, the batch witness and the slot data.
    #[allow(clippy::too_many_arguments)]
    pub fn step_p(
        &self,
        cap_q: &Capture<pallas::Affine>,
        sq: &StepQChain,
        caps: &[Capture<vesta::Affine>],
        prev_p: &Capture<vesta::Affine>,
        prev_sp: &StepPChain,
        witness: Option<BatchWitness>,
        slot_proof: Vec<Option<usize>>,
        used: Vec<bool>,
    ) -> StepPChain {
        let offsets = sq.offsets();
        let off_tp = offsets[caps.len()];
        let k_t = K as usize;
        let k_p = prev_p.u.len();
        // T_q(i) opened T_q(i−1)'s claim: its u's are the re-exposed values
        // of T_p(i−1)'s instance at the claim's positions (after G's two);
        // the last two re-exposed are T_p(i−1)'s s_next and g
        let re = &sq.group_tp.re_expose;
        let claim_q_prev_in_tp = &re[..re.len() - 2];
        let u_q_prev_in_tq: Vec<usize> = claim_q_prev_in_tp[2..]
            .iter()
            .map(|j| off_tp + pos_q(&sq.group_tp, *j))
            .collect();
        // what T_p(i) re-exposes for T_q(i+1): the u's of the n+1 claims it
        // opens — the transfers' (their parts' squeezes) and T_p(i−1)'s
        // (the T_p part's squeezes)
        let mut re_expose = Vec::new();
        for (i, g) in sq.groups_pi.iter().enumerate() {
            re_expose.extend(g.ipa_challenge_slots(k_t).iter().map(|p| offsets[i] + p));
        }
        re_expose.extend(
            sq.group_tp
                .ipa_challenge_slots(k_p)
                .iter()
                .map(|p| off_tp + p),
        );
        let (kinds, sources) = p::VerifierCircuit::shape(
            cap_q,
            self.outer,
            self.ovk.fixed_commitments(),
            self.ovk.permutation_commitments(),
        );
        let instance_q_len = sq.instance_limbs_when_verified().len();
        let group_tq = p::VerifierCircuit {
            kinds,
            sources,
            params_w: self.outer.get_w(),
            params_u: self.outer.get_u(),
            lagrange: self.outer.get_g_lagrange()[..instance_q_len].to_vec(),
            instance_limbs: sq.instance_limbs_when_verified(),
            expose_instance: false,
            opened_u_slots: vec![u_q_prev_in_tq],
            re_expose,
            keys_as_inputs: true,
            allow_base: false,
            base: false,
            capture: Some(cap_q.clone()),
        };
        let mut fields_pi = Vec::new();
        let mut statement_positions = Vec::new();
        for (i, (cap, g)) in caps.iter().zip(&sq.groups_pi).enumerate() {
            let (_, src) = q::VerifierCircuit::shape(
                cap,
                self.tparams,
                self.tvk.fixed_commitments(),
                self.tvk.permutation_commitments(),
            );
            let (structure, shadow) =
                fieldside::fp::Structure::build(self.tparams, self.tvk, cap, &src);
            fields_pi.push((
                fieldside::fp::FieldSideCircuit {
                    structure,
                    shadow: Some(shadow),
                },
                g.links_for_field_side(),
                offsets[i],
            ));
            statement_positions.push(
                (0..cap.instance.len())
                    .map(|j| offsets[i] + g.instance_value_slots(j)[0])
                    .collect(),
            );
        }
        let (_, src_p) = q::VerifierCircuit::shape(
            prev_p,
            self.pparams,
            self.pvk.fixed_commitments(),
            self.pvk.permutation_commitments(),
        );
        let (structure, shadow) =
            fieldside::fp::Structure::build(self.pparams, self.pvk, prev_p, &src_p);
        let field_tp = (
            fieldside::fp::FieldSideCircuit {
                structure,
                shadow: Some(shadow),
            },
            sq.group_tp.links_for_field_side(),
            off_tp,
        );
        let s_next_prev = re[re.len() - 2];
        let g_prev = re[re.len() - 1];
        let _ = prev_sp;
        StepPChain {
            group_tq,
            fields_pi,
            field_tp,
            batch: BatchCircuit {
                n: self.n_slots,
                params: self.batch_params,
                witness,
            },
            statement_positions,
            slot_proof,
            used,
            prev_s_next: Some(off_tp + pos_q(&sq.group_tp, s_next_prev)),
            prev_g: Some(off_tp + pos_q(&sq.group_tp, g_prev)),
            base_pos: Some(off_tp + base_slot_q(&sq.group_tp)),
        }
    }
}

/// The shapes and keys of the chain's two circuits, made once, and the
/// dummy step 0 the first real step builds on.
pub struct ChainKeys {
    pub n_proofs: usize,
    pub n_slots: usize,
    pub tparams: Params<vesta::Affine>,
    pub tvk: VerifyingKey<vesta::Affine>,
    pub outer: Params<pallas::Affine>,
    pub ovk: VerifyingKey<pallas::Affine>,
    pub opk: ProvingKey<pallas::Affine>,
    pub pparams: Params<vesta::Affine>,
    pub pvk: VerifyingKey<vesta::Affine>,
    pub ppk: ProvingKey<vesta::Affine>,
    pub step_q: StepQChain,
    pub step_p: StepPChain,
    pub batch_params: BatchParams,
    /// One valid transfer proof of the sample statement per fragment slot,
    /// all distinct: the verifier's MSM merges equal points, so identical
    /// proofs in two slots would open identical claims and `T_p`'s proof
    /// would have one term fewer than the keys' shape.
    pub padding: Vec<(TransferStatement, Vec<u8>)>,
    pub step0: Artifacts,
}

/// What a step leaves for the next.
#[derive(Clone)]
pub struct Artifacts {
    pub cap_q: Capture<pallas::Affine>,
    pub cap_p: Capture<vesta::Affine>,
    pub sq: StepQChain,
    pub sp: StepPChain,
}

fn err<E: std::fmt::Debug>(e: E) -> String {
    format!("{e:?}")
}

/// A key's representative (its `transcript_repr`, through the Blake2b
/// transcript), as bytes.
fn key_repr<C: CurveAffine>(vk: &VerifyingKey<C>) -> Vec<u8>
where
    C::Scalar: ff::FromUniformBytes<64>,
{
    let mut t = Blake2bWrite::<Vec<u8>, C, Challenge255<C>>::init(vec![]);
    vk.hash_into(&mut t).expect("hashing a key cannot fail");
    t.squeeze_challenge()
        .get_scalar()
        .to_repr()
        .as_ref()
        .to_vec()
}

impl ChainKeys {
    /// The key set's identifier: the fragment's sizes, both `k`, and both
    /// verifying keys' representatives, hashed. Keys are a function of the
    /// circuits' structure alone, so two bootstraps of one configuration
    /// agree on it; a chain state names the key set it was made under.
    pub fn id(&self) -> [u8; 32] {
        let mut h = Blake2s256::new();
        h.update(b"sba-replay chain keys v1");
        for v in [
            self.n_proofs as u32,
            self.n_slots as u32,
            self.outer.k(),
            self.pparams.k(),
        ] {
            h.update(v.to_le_bytes());
        }
        h.update(key_repr(&self.ovk));
        h.update(key_repr(&self.pvk));
        h.finalize().into()
    }

    /// The digest of the genesis opening, as the dummy step 0 exposes it:
    /// its `g`, the last of its public values `[s_prev, s_next, D, g]`.
    pub fn genesis_digest(&self) -> Fp {
        let i = &self.step0.cap_p.instance;
        i[i.len() - 1]
    }

    /// Keys for fragments of `n_proofs` over `n_slots` at `k_q`, `k_p`,
    /// starting the chain from `genesis` (the state opening before the
    /// first block). Minutes: the two circuits are shaped from fake
    /// captures of each other until stable (three key generations a side).
    pub fn generate(
        n_proofs: usize,
        n_slots: usize,
        k_q: u32,
        k_p: u32,
        batch_params: BatchParams,
        genesis: &StateOpening,
    ) -> Result<Self, String> {
        use crate::step4::{StepPN, StepQN};
        let tp = TransferParams::build().map_err(err)?;
        let (st, w) = crate::sample::sample();
        let tparams: Params<vesta::Affine> = Params::new(K);
        let tvk = plonk::keygen_vk(&tparams, &TransferCircuit::default()).map_err(err)?;
        // n proofs of the sample, distinct (see `padding`)
        let mut padding = Vec::with_capacity(n_proofs);
        let mut caps: Vec<Capture<vesta::Affine>> = Vec::with_capacity(n_proofs);
        for _ in 0..n_proofs {
            let proof = tp.prove(&st, &w, &mut OsRng).map_err(err)?;
            caps.push(capture(&tparams, &tvk, &st.to_field_elements(), &proof, &[]).map_err(err)?);
            padding.push((st.clone(), proof));
        }
        let outer: Params<pallas::Affine> = Params::new(k_q);
        let pparams: Params<vesta::Affine> = Params::new(k_p);
        // placeholders of the right columns: a T_q of the transfer group
        // sides alone, a T_p over its fake with the relation
        let q0 = StepQN {
            groups: caps
                .iter()
                .map(|c| q::VerifierCircuit::over(&tparams, &tvk, c))
                .collect(),
        };
        let vk_q0 = plonk::keygen_vk(&outer, &q0.without_witnesses())
            .map_err(|e| format!("T_q keys: {e:?}"))?;
        let (cap_q0, _) = fake_capture(&outer, &vk_q0, &q0.instance(), &[], OsRng).map_err(err)?;
        let p0 = crate::prover::Keys::step_p(
            &q0,
            &cap_q0,
            &outer,
            &vk_q0,
            &tparams,
            &tvk,
            &caps,
            n_slots,
            batch_params,
            None,
            &[],
            &vec![false; n_proofs],
        )?;
        let vk_p0 = plonk::keygen_vk(&pparams, &p0.without_witnesses())
            .map_err(|e| format!("T_p keys: {e:?}"))?;
        let claims_t: Vec<Claim<vesta::Affine>> = caps.iter().map(|c| c.claim()).collect();
        // the placeholder opens what a chain T_p opens: the transfers' claims
        // and a previous T_p's — one of k_p challenges (any values: a claim's
        // shape is its challenge count)
        let k_p = k_p as usize;
        let mut claims_p0 = claims_t.clone();
        claims_p0.push(Claim {
            g: group::Curve::to_affine(&<vesta::Point as group::Group>::random(OsRng)),
            u: (1..=k_p as u64).map(Fp::from).collect(),
        });
        let (cap_p0, _) =
            fake_capture(&pparams, &vk_p0, &p0.instance(), &claims_p0, OsRng).map_err(err)?;
        // the placeholder T_p as a StepPChain shape is not available; the
        // first chain round shapes group_tp over the StepPN fake through a
        // minimal StepPChain-like view of it
        let _ = StepPN::instance;
        let shaper0 = Shaper {
            tparams: &tparams,
            tvk: &tvk,
            outer: &outer,
            pparams: &pparams,
            pvk: &vk_p0,
            ovk: &vk_q0,
            n_slots,
            batch_params,
        };
        // round 1: T_q over (p0 fake, q0 fake); p0's group side is a StepPN's
        // — it exposed every T_q(−1) instance value, so re_expose/opened
        // positions are read off it as if it had re-exposed them
        let p0_as_chain = StepPChain {
            group_tq: {
                let mut g = p0.group.clone();
                // every value is exposed; mark the ones the chain re-exposes
                g.re_expose = {
                    let mut v = Vec::new();
                    for (i, gq) in q0.groups.iter().enumerate() {
                        v.extend(
                            gq.ipa_challenge_slots(K as usize)
                                .iter()
                                .map(|p| q0.offsets()[i] + p),
                        );
                    }
                    v.extend(gq_dummy_u(k_p, q0.instance().len()));
                    v
                };
                g
            },
            fields_pi: Vec::new(),
            field_tp: (p0.fields[0].0.clone(), Vec::new(), 0),
            batch: p0.batch.clone(),
            statement_positions: Vec::new(),
            slot_proof: Vec::new(),
            used: Vec::new(),
            prev_s_next: None,
            prev_g: None,
            base_pos: None,
        };
        let sq1 = shaper0.step_q(&caps, &cap_p0, &p0_as_chain, &cap_q0, true);
        let vk_q1 = plonk::keygen_vk(&outer, &sq1.without_witnesses())
            .map_err(|e| format!("T_q keys: {e:?}"))?;
        let (cap_q1, _) = fake_capture(
            &outer,
            &vk_q1,
            &sq1.instance(),
            std::slice::from_ref(&cap_q0.claim()),
            OsRng,
        )
        .map_err(err)?;
        let shaper1 = Shaper {
            tparams: &tparams,
            tvk: &tvk,
            outer: &outer,
            pparams: &pparams,
            pvk: &vk_p0,
            ovk: &vk_q1,
            n_slots,
            batch_params,
        };
        let sp1 = shaper1.step_p(
            &cap_q1,
            &sq1,
            &caps,
            &cap_p0,
            &p0_as_chain,
            None,
            vec![None; n_slots],
            vec![false; n_proofs],
        );
        let vk_p1 = plonk::keygen_vk(&pparams, &sp1.without_witnesses())
            .map_err(|e| format!("T_p keys: {e:?}"))?;
        let mut claims_p1 = claims_t.clone();
        claims_p1.push(cap_p0.claim());
        let (cap_p1, _) =
            fake_capture(&pparams, &vk_p1, &sp1.instance(), &claims_p1, OsRng).map_err(err)?;
        // round 2: over the chain-shaped fakes; the shapes must now be stable
        let shaper2 = Shaper {
            tparams: &tparams,
            tvk: &tvk,
            outer: &outer,
            pparams: &pparams,
            pvk: &vk_p1,
            ovk: &vk_q1,
            n_slots,
            batch_params,
        };
        let sq2 = shaper2.step_q(&caps, &cap_p1, &sp1, &cap_q1, true);
        let vk_q2 = plonk::keygen_vk(&outer, &sq2.without_witnesses())
            .map_err(|e| format!("T_q keys: {e:?}"))?;
        let (cap_q2, _) = fake_capture(
            &outer,
            &vk_q2,
            &sq2.instance(),
            std::slice::from_ref(&cap_q1.claim()),
            OsRng,
        )
        .map_err(err)?;
        let shaper3 = Shaper {
            tparams: &tparams,
            tvk: &tvk,
            outer: &outer,
            pparams: &pparams,
            pvk: &vk_p1,
            ovk: &vk_q2,
            n_slots,
            batch_params,
        };
        let sp2 = shaper3.step_p(
            &cap_q2,
            &sq2,
            &caps,
            &cap_p1,
            &sp1,
            None,
            vec![None; n_slots],
            vec![false; n_proofs],
        );
        let vk_p2 = plonk::keygen_vk(&pparams, &sp2.without_witnesses())
            .map_err(|e| format!("T_p keys: {e:?}"))?;
        if sq2.instance().len() != sq1.instance().len()
            || sp2.instance().len() != sp1.instance().len()
        {
            return Err(format!(
                "shapes not stable: T_q {} → {}, T_p {} → {}",
                sq1.instance().len(),
                sq2.instance().len(),
                sp1.instance().len(),
                sp2.instance().len()
            ));
        }
        if vk_q2.fixed_commitments().len() != vk_q1.fixed_commitments().len()
            || vk_p2.fixed_commitments().len() != vk_p1.fixed_commitments().len()
        {
            return Err("key shapes not stable".into());
        }
        // round 3: the final keys over round-2 fakes, and the dummy step 0
        let shaper4 = Shaper {
            tparams: &tparams,
            tvk: &tvk,
            outer: &outer,
            pparams: &pparams,
            pvk: &vk_p2,
            ovk: &vk_q2,
            n_slots,
            batch_params,
        };
        let mut claims_p2 = claims_t.clone();
        claims_p2.push(cap_p1.claim());
        let (cap_p2, _) =
            fake_capture(&pparams, &vk_p2, &sp2.instance(), &claims_p2, OsRng).map_err(err)?;
        let sq3 = shaper4.step_q(&caps, &cap_p2, &sp2, &cap_q2, true);
        let ovk = plonk::keygen_vk(&outer, &sq3.without_witnesses())
            .map_err(|e| format!("T_q keys: {e:?}"))?;
        let opk = plonk::keygen_pk(&outer, ovk.clone(), &sq3.without_witnesses())
            .map_err(|e| format!("T_q keys: {e:?}"))?;
        let (cap_q3, _) = fake_capture(
            &outer,
            &ovk,
            &sq3.instance(),
            std::slice::from_ref(&cap_q2.claim()),
            OsRng,
        )
        .map_err(err)?;
        let shaper5 = Shaper {
            tparams: &tparams,
            tvk: &tvk,
            outer: &outer,
            pparams: &pparams,
            pvk: &vk_p2,
            ovk: &ovk,
            n_slots,
            batch_params,
        };
        let sp3 = shaper5.step_p(
            &cap_q3,
            &sq3,
            &caps,
            &cap_p2,
            &sp2,
            None,
            vec![None; n_slots],
            vec![false; n_proofs],
        );
        let pvk = plonk::keygen_vk(&pparams, &sp3.without_witnesses())
            .map_err(|e| format!("T_p keys: {e:?}"))?;
        let ppk = plonk::keygen_pk(&pparams, pvk.clone(), &sp3.without_witnesses())
            .map_err(|e| format!("T_p keys: {e:?}"))?;
        if ovk.fixed_commitments().len() != vk_q2.fixed_commitments().len()
            || pvk.fixed_commitments().len() != vk_p2.fixed_commitments().len()
        {
            return Err("final key shapes differ".into());
        }
        // the dummy step 0 under the final keys: T_q(0) a fake over the
        // final T_q key; T_p(0)'s instance what its group side exposes of
        // it, then [s0, s0, 0] with s0 the genesis digest; its proof a fake
        let shaper = Shaper {
            tparams: &tparams,
            tvk: &tvk,
            outer: &outer,
            pparams: &pparams,
            pvk: &pvk,
            ovk: &ovk,
            n_slots,
            batch_params,
        };
        let (cap_q0f, _) = fake_capture(
            &outer,
            &ovk,
            &sq3.instance(),
            std::slice::from_ref(&cap_q2.claim()),
            OsRng,
        )
        .map_err(err)?;
        let sq0 = shaper.step_q(&caps, &cap_p2, &sp2, &cap_q2, true);
        let mut sp0 = shaper.step_p(
            &cap_q0f,
            &sq0,
            &caps,
            &cap_p2,
            &sp2,
            None,
            vec![None; n_slots],
            vec![false; n_proofs],
        );
        let s0 = genesis.digest();
        let mut instance_p0 = sp0.group_tq.instance(&cap_q0f);
        instance_p0.extend([s0, s0, Fp::from(0u64), s0]);
        let mut claims_p0f = claims_t.clone();
        claims_p0f.push(claim_at::<vesta::Affine>(
            &sq0.instance(),
            &claim_positions(&sq0.group_tp, cap_p2.u.len())
                .iter()
                .map(|p| sq0.offsets()[n_proofs] + p)
                .collect::<Vec<_>>(),
        )?);
        let (cap_p0f, _) =
            fake_capture(&pparams, &pvk, &instance_p0, &claims_p0f, OsRng).map_err(err)?;
        sp0.batch.witness = None;
        Ok(ChainKeys {
            n_proofs,
            n_slots,
            tparams,
            tvk,
            outer,
            ovk,
            opk,
            pparams,
            pvk,
            ppk,
            step_q: sq3.without_witnesses(),
            step_p: sp3.without_witnesses(),
            batch_params,
            padding,
            step0: Artifacts {
                cap_q: cap_q0f,
                cap_p: cap_p0f,
                sq: sq0,
                sp: sp0,
            },
        })
    }

    pub fn shaper(&self) -> Shaper<'_> {
        Shaper {
            tparams: &self.tparams,
            tvk: &self.tvk,
            outer: &self.outer,
            pparams: &self.pparams,
            pvk: &self.pvk,
            ovk: &self.ovk,
            n_slots: self.n_slots,
            batch_params: self.batch_params,
        }
    }
}

/// Placeholder positions for the round-0 placeholder (no T_p part exists).
fn gq_dummy_u(k: usize, n: usize) -> Vec<usize> {
    (0..k).map(|i| (n.saturating_sub(k)) + i).collect()
}

/// The chain prover: each call proves the next block from the previous
/// step's artifacts (the dummy step 0 first).
pub struct ChainProver<'k> {
    pub keys: &'k ChainKeys,
    pub prev: Artifacts,
    pub steps: usize,
    /// The state digest after the last step (the genesis digest before
    /// the first): the next block's witness must open from it.
    pub s: Fp,
}

impl<'k> ChainProver<'k> {
    pub fn new(keys: &'k ChainKeys) -> Self {
        ChainProver {
            keys,
            prev: keys.step0.clone(),
            steps: 0,
            s: keys.genesis_digest(),
        }
    }

    /// The prover as a saved state left it: the previous step's captures
    /// with the keys' shapes (a step's shape is the keys', values apart).
    pub fn resume(keys: &'k ChainKeys, state: &ChainState) -> Result<Self, String> {
        if state.keys_id != keys.id() {
            return Err("the chain state is of another key set".into());
        }
        Ok(ChainProver {
            keys,
            prev: Artifacts {
                cap_q: state.cap_q.clone(),
                cap_p: state.cap_p.clone(),
                sq: keys.step_q.clone(),
                sp: keys.step_p.clone(),
            },
            steps: state.index as usize,
            s: state.s,
        })
    }

    /// What to save: `next_height` is the block the next step takes.
    pub fn state(&self, next_height: u32) -> ChainState {
        ChainState {
            keys_id: self.keys.id(),
            index: self.steps as u32,
            next_height,
            s: self.s,
            cap_q: self.prev.cap_q.clone(),
            cap_p: self.prev.cap_p.clone(),
        }
    }

    pub fn prove(
        &mut self,
        height: u32,
        witness: &BatchWitness,
        opening_after: &StateOpening,
        transfers: &[(TransferStatement, Vec<u8>)],
    ) -> Result<ProvenStep, String> {
        let k = self.keys;
        if transfers.len() > k.n_proofs || witness.slots.len() > k.n_slots {
            return Err("fragment size".into());
        }
        // a block with fewer statements than the fragment: empty slots
        let mut witness = witness.clone();
        while witness.slots.len() < k.n_slots {
            witness.slots.push(None);
        }
        let witness = &witness;
        let statement = witness
            .check(&k.batch_params)
            .ok_or("the relation refuses the witness")?;
        if statement.s_prev != self.s {
            return Err("the witness does not open from the chain's state".into());
        }
        if statement.s_next != opening_after.digest() {
            return Err("the opening after is not the witness's".into());
        }
        let used: Vec<bool> = (0..k.n_proofs).map(|i| i < transfers.len()).collect();
        let mut transfers = transfers.to_vec();
        while transfers.len() < k.n_proofs {
            transfers.push(k.padding[transfers.len()].clone());
        }
        let mut next = 0;
        let slot_proof: Vec<Option<usize>> = witness
            .slots
            .iter()
            .map(|s| match s {
                Some(s) if !s.statement.mint => {
                    next += 1;
                    Some(next - 1)
                }
                _ => None,
            })
            .collect();
        if next != used.iter().filter(|u| **u).count() {
            return Err("transfer slots and proofs differ".into());
        }
        let caps: Vec<Capture<vesta::Affine>> = transfers
            .iter()
            .map(|(st, proof)| {
                capture(&k.tparams, &k.tvk, &st.to_field_elements(), proof, &[]).map_err(err)
            })
            .collect::<Result<_, _>>()?;
        let shaper = k.shaper();
        let base = self.steps == 0;
        let sq = shaper.step_q(
            &caps,
            &self.prev.cap_p,
            &self.prev.sp,
            &self.prev.cap_q,
            base,
        );
        let instance_q = sq.instance();
        let mut tr = crate::native::PoseidonWrite::<_, pallas::Affine>::init(vec![]);
        plonk::create_proof_with_openings(
            &k.outer,
            &k.opk,
            std::slice::from_ref(&sq),
            &[&[&instance_q[..]]],
            std::slice::from_ref(&self.prev.cap_q.claim()),
            OsRng,
            &mut tr,
        )
        .map_err(|e| format!("T_q: {e:?}"))?;
        let proof_q = tr.finalize();
        let cap_q = capture(
            &k.outer,
            &k.ovk,
            &instance_q,
            &proof_q,
            std::slice::from_ref(&self.prev.cap_q.claim()),
        )
        .map_err(err)?;
        let sp = shaper.step_p(
            &cap_q,
            &sq,
            &caps,
            &self.prev.cap_p,
            &self.prev.sp,
            Some(witness.clone()),
            slot_proof,
            used,
        );
        let instance_p = sp.instance();
        let mut claims: Vec<Claim<vesta::Affine>> = caps.iter().map(|c| c.claim()).collect();
        claims.push(self.prev.cap_p.claim());
        let mut tr = crate::native::PoseidonWrite::<_, vesta::Affine>::init(vec![]);
        plonk::create_proof_with_openings(
            &k.pparams,
            &k.ppk,
            std::slice::from_ref(&sp),
            &[&[&instance_p[..]]],
            &claims,
            OsRng,
            &mut tr,
        )
        .map_err(|e| format!("T_p: {e:?}"))?;
        let proof_p = tr.finalize();
        let cap_p = capture(&k.pparams, &k.pvk, &instance_p, &proof_p, &claims).map_err(err)?;
        self.prev = Artifacts {
            cap_q,
            cap_p,
            sq: sq.without_witnesses(),
            sp: sp.without_witnesses(),
        };
        self.steps += 1;
        self.s = statement.s_next;
        Ok(ProvenStep {
            height,
            slots: witness
                .slots
                .iter()
                .map(|s| s.as_ref().map(|s| s.statement))
                .collect(),
            opening_after: *opening_after,
            instance_q,
            proof_q,
            instance_p,
            proof_p,
        })
    }
}

/// The transfer statements and proofs of block `height` as the indexer
/// accepted them, the statement rebuilt as its verifier saw it.
pub fn transfers_of(
    idx: &Indexer,
    height: u32,
) -> Result<Vec<(TransferStatement, Vec<u8>)>, String> {
    use sba_core::envelope::{Envelope, parse_envelope};
    use sba_core::event::EventKind;
    let d = &idx.deployment;
    idx.state
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Transfer && e.height == height)
        .map(|ev| {
            let Envelope::Transfer(t) = parse_envelope(&ev.raw).map_err(err)? else {
                return Err("a transfer event carrying another envelope".into());
            };
            let r_anchor = idx
                .root_at(t.body.h_anchor)
                .ok_or("the anchor's root is not replayed")?;
            Ok((
                TransferStatement {
                    const_salt: d.const_salt_fp(),
                    r_anchor,
                    nullifiers: t.body.nullifiers,
                    pk_eph: t.body.pk_eph,
                    ct_note: t.body.ct_note,
                    h_body: t.body.h_body(&d.const_salt),
                },
                t.proof.clone(),
            ))
        })
        .collect()
}

/// A chain source whose tip is held at `tip`: the indexer replays up to
/// that block and no further, one step's block at a time.
pub struct Capped<'c> {
    pub inner: &'c dyn ChainSource,
    pub tip: u32,
}

impl ChainSource for Capped<'_> {
    fn tip(&self) -> Result<BlockId, ChainError> {
        let t = self.inner.tip()?;
        if t.height <= self.tip {
            return Ok(t);
        }
        match self.inner.block_hash(self.tip)? {
            Some(hash) => Ok(BlockId {
                height: self.tip,
                hash,
            }),
            None => Ok(t),
        }
    }
    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError> {
        if height > self.tip {
            return Ok(None);
        }
        self.inner.block_hash(height)
    }
    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        self.inner.block(hash)
    }
}

/// Replay the indexer's next block from `chain` (persisting through
/// `store`, if any) and prove it as the chain's next step; `None` when the
/// chain has no such block yet. The indexer must stand exactly where the
/// prover does (`reconcile`); a reorganisation below the proven chain is
/// an error — the proven chain cannot continue on another branch.
pub fn prove_next_block(
    prover: &mut ChainProver,
    idx: &mut Indexer,
    store: Option<&mut dyn StateStore>,
    chain: &dyn ChainSource,
) -> Result<Option<ProvenStep>, String> {
    let height = idx.next_height();
    if chain.tip().map_err(err)?.height < height {
        return Ok(None);
    }
    let blocks_before = idx.state.blocks.len();
    let report = idx
        .sync_with(
            &Capped {
                inner: chain,
                tip: height,
            },
            store,
        )
        .map_err(err)?;
    if report.rolled_back_to.is_some() {
        return Err(format!(
            "the chain reorganised below block {height}: the proven chain cannot continue"
        ));
    }
    if idx.state.blocks.len() != blocks_before + 1 || idx.state.last_height() != Some(height) {
        return Err("the sync did not replay exactly the next block".into());
    }
    let witness = idx
        .state
        .batches
        .pop()
        .ok_or("the replayed block left no batch witness")?;
    let opening_after = idx.state.opening(idx.next_height());
    let transfers = transfers_of(idx, height)?;
    let step = prover.prove(height, &witness, &opening_after, &transfers)?;
    Ok(Some(step))
}

/// Put the indexer where the prover is: blocks it replayed beyond
/// `next_height − 1` (a run that synced and did not prove) are rolled back,
/// in memory and in `store`; batch witnesses in memory are dropped (the
/// next sync makes the one needed).
pub fn reconcile(
    idx: &mut Indexer,
    store: Option<&mut dyn StateStore>,
    next_height: u32,
) -> Result<(), String> {
    if idx.next_height() > next_height {
        let keep = next_height.saturating_sub(1);
        idx.state.rollback_to(keep);
        if let Some(store) = store {
            store.rollback_to(&idx.state, keep).map_err(err)?;
        }
    }
    if idx.next_height() != next_height {
        return Err(format!(
            "the indexer stands at block {}, the chain at {next_height}",
            idx.next_height()
        ));
    }
    idx.state.batches.clear();
    Ok(())
}

/// The client's decider for the chain: from the keys alone.
pub struct ChainDecider<'k> {
    pub keys: &'k ChainKeys,
}

impl ChainDecider<'_> {
    /// Decide step `index` (1 for the first real block) against the
    /// client's state digest; the digest after on success.
    pub fn decide(&self, step: &ProvenStep, index: usize, s_prev: Fp) -> Result<Fp, String> {
        self.verify(step)?;
        let sq = &self.keys.step_q;
        let off_tp = sq.offsets()[self.keys.n_proofs];
        let want_base = if index == 1 {
            pallas::Scalar::from(1u64)
        } else {
            pallas::Scalar::from(0u64)
        };
        if step.instance_q[off_tp + base_slot_q(&sq.group_tp)] != want_base {
            return Err("the base bit is not the step's".into());
        }
        let ip = &step.instance_p;
        if ip[ip.len() - 4] != s_prev {
            return Err("s_prev is not the client's state".into());
        }
        Ok(self.public_values(step)?.1)
    }

    /// Both proofs verified natively with the claims and the keys read out
    /// of the public inputs: `T_q(i)` with `T_q(i−1)`'s claim (re-exposed
    /// from `T_p(i−1)`'s instance), `T_p(i)` with the transfers' claims and
    /// `T_p(i−1)`'s (from `T_q(i)`'s instance); both keys' commitments
    /// against the deployment's.
    fn verify(&self, step: &ProvenStep) -> Result<(), String> {
        let k = self.keys;
        let sq = &k.step_q;
        let sp = &k.step_p;
        let offsets = sq.offsets();
        let off_tp = offsets[k.n_proofs];
        let iq = &step.instance_q;
        let ip = &step.instance_p;
        if ip.len() < 4 {
            return Err("short T_p instance".into());
        }
        // the claims T_q opened: T_q(i−1)'s, re-exposed from T_p(i−1)'s instance
        // (the last two re-exposed values are its s_next and g)
        let re = &sq.group_tp.re_expose;
        let claim_q_prev_pos: Vec<usize> = re[..re.len() - 2]
            .iter()
            .map(|j| off_tp + pos_q(&sq.group_tp, *j))
            .collect();
        // a Pallas claim carried in Fq cells: its coordinates are Fp values
        // (the same integers), its challenges 128-bit
        let as_fp: Vec<Fp> = iq
            .iter()
            .map(|v| Option::from(Fp::from_repr(v.to_repr())).ok_or("a value above p"))
            .collect::<Result<_, _>>()?;
        let claim_q_prev = claim_at::<pallas::Affine>(&as_fp, &claim_q_prev_pos)?;
        // T_p(i−1)'s key
        let keys_p = key_commitments_q(&sq.group_tp);
        for (i, pos) in key_slots_q(&sq.group_tp).chunks(2).enumerate() {
            use pasta_curves::arithmetic::CurveAffine;
            let c = keys_p[i].coordinates().unwrap();
            if iq[off_tp + pos[0]] != *c.x() || iq[off_tp + pos[1]] != *c.y() {
                return Err("T_p's key is not the deployment's".into());
            }
        }
        let mut tr = crate::native::PoseidonRead::<_, pallas::Affine>::init(&step.proof_q[..]);
        plonk::verify_proof_with_openings(
            &k.outer,
            &k.ovk,
            plonk::SingleVerifier::new(&k.outer),
            &[&[&iq[..]]],
            &mut tr,
            std::slice::from_ref(&claim_q_prev),
        )
        .map_err(|e| format!("T_q: {e:?}"))?;
        // the claims T_p opened: the transfers' and T_p(i−1)'s, from T_q's instance
        let mut claims: Vec<Claim<vesta::Affine>> = Vec::new();
        for (i, g) in sq.groups_pi.iter().enumerate() {
            let pos: Vec<usize> = claim_positions(g, K as usize)
                .iter()
                .map(|p| offsets[i] + p)
                .collect();
            claims.push(claim_at::<vesta::Affine>(iq, &pos)?);
        }
        let k_p = k.step0.cap_p.u.len();
        let pos: Vec<usize> = claim_positions(&sq.group_tp, k_p)
            .iter()
            .map(|p| off_tp + p)
            .collect();
        claims.push(claim_at::<vesta::Affine>(iq, &pos)?);
        // T_q(i)'s key as T_p exposed it
        let keys_q = key_commitments_p(&sp.group_tq);
        for (i, pos) in key_slots_p(&sp.group_tq).chunks(2).enumerate() {
            use pasta_curves::arithmetic::CurveAffine;
            let c = keys_q[i].coordinates().unwrap();
            if ip[pos[0]] != *c.x() || ip[pos[1]] != *c.y() {
                return Err("T_q's key is not the deployment's".into());
            }
        }
        let mut tr = crate::native::PoseidonRead::<_, vesta::Affine>::init(&step.proof_p[..]);
        plonk::verify_proof_with_openings(
            &k.pparams,
            &k.pvk,
            plonk::SingleVerifier::new(&k.pparams),
            &[&[&ip[..]]],
            &mut tr,
            &claims,
        )
        .map_err(|e| format!("T_p: {e:?}"))?;
        Ok(())
    }

    /// Decide the latest step alone, from the keys and the deployment's
    /// genesis digest: the step's `g` must be the genesis — the base step
    /// set it to its `s_prev` and every step since carried it — so one
    /// step attests the whole history from the genesis. Returns the
    /// block height and the state digest after it.
    pub fn decide_latest(&self, step: &ProvenStep) -> Result<(u32, Fp), String> {
        self.verify(step)?;
        let (_, s_next) = self.public_values(step)?;
        Ok((step.height, s_next))
    }

    /// Both proofs verified with the claims and keys read out of the
    /// public inputs; `D` and `s_next` against the step's data; `g`
    /// against the genesis. What `decide` adds is the base bit for the
    /// index and `s_prev` for the running digest.
    fn public_values(&self, step: &ProvenStep) -> Result<(Fp, Fp), String> {
        let ip = &step.instance_p;
        let n = ip.len();
        if ip[n - 2] != sba_core::batch::batch_digest(&step.slots) {
            return Err("D is not the digest of the statements".into());
        }
        if ip[n - 3] != step.opening_after.digest() {
            return Err("s_next is not the opening's digest".into());
        }
        if ip[n - 1] != self.keys.genesis_digest() {
            return Err("the chain's genesis is not the deployment's".into());
        }
        Ok((ip[n - 4], ip[n - 3]))
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    /// The verifier mirror takes one instance column: the relation shares
    /// the step's.
    #[test]
    fn the_chain_circuits_have_one_instance_column() {
        let mut cs = ConstraintSystem::<pallas::Base>::default();
        StepPChain::configure(&mut cs);
        assert_eq!(cs.num_instance_columns(), 1);
        let mut cs = ConstraintSystem::<vesta::Base>::default();
        StepQChain::configure(&mut cs);
        assert_eq!(cs.num_instance_columns(), 1);
    }
    use sb_common::carrier::carrier_output;
    use sba_core::note::decrypt_as_recipient;
    use sba_indexer::testing::{ACTIVATION, MockChain, World, tx_with};

    /// One key set, two blocks: `cargo test -p sba-replay --release two_blocks_through_the_chain -- --ignored --nocapture`
    /// (the server: keys at k = 18/18 — the chain's `T_p` over a two-proof
    /// `T_q` of ≈ 1 000 public inputs outgrows k = 17 — and six proofs,
    /// about an hour).
    #[test]
    #[ignore]
    fn two_blocks_through_the_chain() {
        let mut w = World::new();
        let (_, alice0) = w.alice.ivk.find_address(0);
        let (_, bob0) = w.bob.ivk.find_address(0);
        let mut chain = MockChain::new(ACTIVATION);
        let mut idx = w.indexer();
        let genesis = idx.state.opening(idx.next_height());
        let (m1, _) = w.mint_tx(&alice0, 1000);
        let (m2, _) = w.mint_tx(&alice0, 400);
        chain.push_block(vec![m1, m2]);
        idx.sync(&chain).unwrap();
        let bparams = idx.batch_params();
        let t = std::time::Instant::now();
        let keys = ChainKeys::generate(2, 3, 18, 18, bparams, &genesis).unwrap();
        println!("chain keys: {:.1} s", t.elapsed().as_secs_f64());
        let mut prover = ChainProver::new(&keys);
        let decider = ChainDecider { keys: &keys };
        // block 1000 (the two mints) as the first step: no transfers
        let mut s = genesis.digest();
        let w0 = idx.state.batches[0].clone();
        let o0 = idx.state.opening(idx.next_height());
        let t = std::time::Instant::now();
        let step1 = prover.prove(1000, &w0, &o0, &[]).unwrap();
        println!(
            "step 1 (two mints, base): {:.1} s, {} bytes",
            t.elapsed().as_secs_f64(),
            step1.to_bytes().len()
        );
        s = decider.decide(&step1, 1, s).unwrap();
        assert_eq!(s, o0.digest());
        // the prover put away and taken up again from its saved state
        let saved = prover.state(idx.next_height()).to_bytes();
        println!("chain state: {} bytes", saved.len());
        let restored = ChainState::from_bytes(&saved).unwrap();
        assert_eq!(
            (restored.index, restored.next_height, restored.s),
            (1, 1001, s)
        );
        let mut prover = ChainProver::resume(&keys, &restored).unwrap();
        // block 1001: two transfers and a mint
        let notes: Vec<_> = idx.state.events[..2]
            .iter()
            .map(|ev| {
                let (pk_eph, ct) = &ev.outputs[0];
                let pt = decrypt_as_recipient(&w.alice.ivk.sk_view, pk_eph, ct).unwrap();
                (pt, ev.h_body, ev.first_position)
            })
            .collect();
        let e1 = w.transfer(
            &idx,
            1000,
            Some((notes[0].0, notes[0].1, 0, notes[0].2)),
            [(bob0, 700), (alice0, 300)],
        );
        let e2 = w.transfer(
            &idx,
            1000,
            Some((notes[1].0, notes[1].1, 0, notes[1].2)),
            [(bob0, 400), (alice0, 0)],
        );
        let (m3, _) = w.mint_tx(&alice0, 5);
        chain.push_block(vec![
            tx_with(vec![carrier_output(&e1.to_bytes())]),
            tx_with(vec![carrier_output(&e2.to_bytes())]),
            m3,
        ]);
        idx.sync(&chain).unwrap();
        let w1 = idx.state.batches[1].clone();
        let o1 = idx.state.opening(idx.next_height());
        let tr1 = transfers_of(&idx, 1001).unwrap();
        assert_eq!(tr1.len(), 2);
        let t = std::time::Instant::now();
        let step2 = prover.prove(1001, &w1, &o1, &tr1).unwrap();
        println!(
            "step 2 (two transfers, a mint): {:.1} s, {} bytes",
            t.elapsed().as_secs_f64(),
            step2.to_bytes().len()
        );
        s = decider.decide(&step2, 2, s).unwrap();
        assert_eq!(s, o1.digest());
        // the client of constant size: step 2 alone, from the genesis
        assert_eq!(decider.decide_latest(&step2).unwrap(), (1001, o1.digest()));
        assert_eq!(decider.decide_latest(&step1).unwrap(), (1000, o0.digest()));
        // a rogue prover restarting the chain at block 1001 (a base step over
        // the real T_p(1)): its g is block 1001's s_prev, not the genesis
        let mut rogue = ChainProver::resume(&keys, &restored).unwrap();
        rogue.steps = 0;
        let t = std::time::Instant::now();
        let rogue2 = rogue.prove(1001, &w1, &o1, &tr1).unwrap();
        println!(
            "rogue base step at block 1001: {:.1} s",
            t.elapsed().as_secs_f64()
        );
        assert_eq!(
            rogue2.instance_p.last(),
            Some(&o0.digest()),
            "its g is its s_prev"
        );
        assert!(decider.decide_latest(&rogue2).is_err(), "not the genesis");
        assert!(
            decider.decide(&rogue2, 2, o0.digest()).is_err(),
            "base at index 2"
        );
        // block 1002: one transfer (alice's change), padded to the fragment
        let ev = &idx.state.events[2];
        let (pk_eph, ct) = &ev.outputs[1];
        let change = decrypt_as_recipient(&w.alice.ivk.sk_view, pk_eph, ct).unwrap();
        let e3 = w.transfer(
            &idx,
            1001,
            Some((change, ev.h_body, 1, ev.first_position + 1)),
            [(bob0, 300), (alice0, 0)],
        );
        chain.push_block(vec![tx_with(vec![carrier_output(&e3.to_bytes())])]);
        // through the runner: the indexer stands at 1002, the chain has it
        reconcile(&mut idx, None, 1002).unwrap();
        let t = std::time::Instant::now();
        let step3 = prove_next_block(&mut prover, &mut idx, None, &chain)
            .unwrap()
            .expect("the block is on the chain");
        assert_eq!(step3.height, 1002);
        assert_eq!(idx.next_height(), 1003);
        assert!(
            idx.state.batches.is_empty(),
            "the runner consumed the witness"
        );
        let o2 = idx.state.opening(1003);
        assert!(
            prove_next_block(&mut prover, &mut idx, None, &chain)
                .unwrap()
                .is_none(),
            "no block 1003 yet"
        );
        println!(
            "step 3 (one transfer, padded): {:.1} s, {} bytes",
            t.elapsed().as_secs_f64(),
            step3.to_bytes().len()
        );
        let t = std::time::Instant::now();
        s = decider.decide(&step3, 3, s).unwrap();
        println!("decide: {:.2} s", t.elapsed().as_secs_f64());
        assert_eq!(s, o2.digest());
        // the wrong index (base bit) and a wrong state are refused
        assert!(decider.decide(&step3, 1, o1.digest()).is_err());
        assert!(decider.decide(&step3, 3, genesis.digest()).is_err());
        let t = std::time::Instant::now();
        assert_eq!(decider.decide_latest(&step3).unwrap(), (1002, o2.digest()));
        println!("decide_latest: {:.2} s", t.elapsed().as_secs_f64());
        let mut other = step3.clone();
        *other.instance_p.last_mut().unwrap() = o0.digest();
        assert!(
            decider.decide_latest(&other).is_err(),
            "g is a public input of the proof"
        );
    }
}
