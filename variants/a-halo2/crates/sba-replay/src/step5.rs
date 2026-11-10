//! The step with both sides under the split transcript (`docs/REPLAY-PROOF-A.md`
//! §3.6): `T_q` of `SplitCircuit`s — 64 public inputs per transfer proof —
//! and `T_p` with the `p` group side of that `T_q`, each transfer proof's
//! split field side bound to its part (the evaluations bound by the
//! sponge instead), and the relation with the slots bound to the
//! statements. The block is the indexer's; its transfer proofs are made
//! again under the split transcript from the same statements and
//! witnesses (the family's prover is a-0.3 until the profile changes).

use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use pasta_curves::{pallas, vesta};

use crate::batch::{BatchCircuit, BatchConfig};
use crate::field::fp::{FieldChip, FieldConfig};
use crate::fieldside::fp::FieldSideCircuit;
use crate::step2::bind;
use crate::step3::SLOT_FROM_STATEMENT;
use crate::transcript::TranscriptConfig;
use crate::verifier::p;
use crate::verifier::q::VerifierConfig;
use crate::verifier_split::SplitCircuit;
use sba_core::batch::SLOT_ELEMENTS;
use sba_primitives::Fp;

/// `T_q` over `n` transfer proofs under the split transcript.
#[derive(Clone)]
pub struct StepQSplit {
    pub groups: Vec<SplitCircuit>,
}

impl std::fmt::Debug for StepQSplit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StepQSplit({} proofs)", self.groups.len())
    }
}

impl StepQSplit {
    pub fn instance(&self) -> Vec<pallas::Scalar> {
        self.groups.iter().flat_map(|g| g.instance()).collect()
    }
    pub fn offsets(&self) -> Vec<usize> {
        let mut v = Vec::new();
        let mut at = 0;
        for g in &self.groups {
            v.push(at);
            at += g.instance_len();
        }
        v
    }
    pub fn instance_limbs_when_verified(&self) -> Vec<usize> {
        self.groups
            .iter()
            .flat_map(|g| g.instance_limbs_when_verified())
            .collect()
    }
}

impl Circuit<pallas::Scalar> for StepQSplit {
    type Config = VerifierConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        StepQSplit {
            groups: self.groups.iter().map(|g| g.without_witnesses()).collect(),
        }
    }
    fn configure(meta: &mut ConstraintSystem<pallas::Scalar>) -> VerifierConfig {
        crate::verifier::q::VerifierCircuit::configure(meta)
    }
    fn synthesize(
        &self,
        cfg: VerifierConfig,
        mut l: impl Layouter<pallas::Scalar>,
    ) -> Result<(), Error> {
        cfg.assign_table(&mut l)?;
        let mut at = 0;
        for g in &self.groups {
            at = g.synthesize_from(&cfg, &mut l, at)?;
        }
        Ok(())
    }
}

/// `T_p` over the block, both sides split.
#[derive(Clone)]
pub struct StepPSplit {
    pub group: p::VerifierCircuit,
    /// Per transfer proof: its split field side, its links (empty = bound
    /// by the sponge), and where its proof's part of `T_q`'s instance starts.
    pub fields: Vec<(FieldSideCircuit, Vec<Vec<usize>>, usize)>,
    pub batch: BatchCircuit,
    pub slot_links: Vec<Option<Vec<usize>>>,
}

#[derive(Clone, Debug)]
pub struct StepPSplitConfig {
    pub group: p::VerifierConfig,
    pub field: FieldConfig,
    pub sponge: TranscriptConfig<Fp>,
    pub batch: BatchConfig,
}

impl std::fmt::Debug for StepPSplit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StepPSplit({} proofs, {} slots)",
            self.fields.len(),
            self.batch.n
        )
    }
}

impl StepPSplit {
    pub fn instance(&self) -> Vec<Fp> {
        let mut v = self
            .group
            .instance(self.group.capture.as_ref().expect("values"));
        v.extend(self.batch.instance());
        v
    }
}

impl Circuit<vesta::Scalar> for StepPSplit {
    type Config = StepPSplitConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        StepPSplit {
            group: self.group.without_witnesses(),
            fields: self
                .fields
                .iter()
                .map(|(f, l, o)| (f.without_witnesses(), l.clone(), *o))
                .collect(),
            batch: self.batch.without_witnesses(),
            slot_links: self.slot_links.clone(),
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> StepPSplitConfig {
        let field = FieldSideCircuit::configure_field(meta);
        let sponge = FieldSideCircuit::configure_sponge(meta, &field);
        let group = p::VerifierCircuit::configure(meta);
        StepPSplitConfig {
            batch: BatchConfig::configure_in(meta, group.instance),
            group,
            field,
            sponge,
        }
    }
    fn synthesize(&self, cfg: StepPSplitConfig, mut l: impl Layouter<Fp>) -> Result<(), Error> {
        cfg.group.assign_table(&mut l)?;
        cfg.sponge.assign_table(&mut l)?;
        cfg.batch.assign_table(&mut l)?;
        let ex = self.group.synthesize_core(&cfg.group, &mut l, 0)?;
        let mut ch = FieldChip::new(&cfg.field);
        for (field, links, offset) in &self.fields {
            let (inputs, outputs) =
                field.synthesize_core(&cfg.field, Some(&cfg.sponge), None, &mut l)?;
            let cells: Vec<_> = inputs.into_iter().chain(outputs).collect();
            bind(&mut ch, &mut l, &cells, links, &ex.instance_values, *offset)?;
        }
        let (slots, _) = self.batch.synthesize_core(
            &cfg.batch,
            &mut l,
            Some((cfg.group.instance, ex.cells.len())),
        )?;
        let zero = ch.constant(&mut l, Fp::ZERO)?;
        for (slot, link) in slots.iter().zip(&self.slot_links) {
            let Some(positions) = link else { continue };
            assert_eq!(slot.len(), SLOT_ELEMENTS);
            for (si, sti) in SLOT_FROM_STATEMENT {
                let cell = &ex.instance_values[positions[sti]];
                assert_eq!(cell.len(), 1);
                ch.assert_equal(&mut l, &slot[si], &cell[0])?;
            }
            ch.assert_equal(&mut l, &slot[SLOT_ELEMENTS - 1], &zero)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::capture;
    use crate::fieldside::fp::Structure;
    use crate::native::{PoseidonRead, PoseidonWrite};
    use crate::shadow::fp::Shadow;
    use crate::split::{SplitWrite, capture_split};
    use crate::verifier::q;
    use crate::verifier_split::SplitPlan;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::{Claim, Params};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sb_common::carrier::carrier_output;
    use sba_circuit::{K, TransferCircuit};
    use sba_core::note::decrypt_as_recipient;
    use sba_indexer::testing::{ACTIVATION, MockChain, World, tx_with};

    /// `cargo test --release two_transfers_both_sides_split -- --ignored --nocapture`
    /// (`SB_PROVE_STEP5=1`: the real proofs and the decider).
    #[test]
    #[ignore]
    fn two_transfers_both_sides_split() {
        // the block, as the indexer replays it, and the two transfers' circuit inputs
        let mut w = World::new();
        let (_, alice0) = w.alice.ivk.find_address(0);
        let (_, bob0) = w.bob.ivk.find_address(0);
        let mut chain = MockChain::new(ACTIVATION);
        let mut idx = w.indexer();
        let (m1, _) = w.mint_tx(&alice0, 1000);
        let (m2, _) = w.mint_tx(&alice0, 400);
        chain.push_block(vec![m1, m2]);
        idx.sync(&chain).unwrap();
        let notes: Vec<_> = idx.state.events[..2]
            .iter()
            .map(|ev| {
                let (pk_eph, ct) = &ev.outputs[0];
                let pt = decrypt_as_recipient(&w.alice.ivk.sk_view, pk_eph, ct).unwrap();
                (pt, ev.h_body, ev.first_position)
            })
            .collect();
        let (e1, st1, w1) = w.transfer_full(
            &idx,
            1000,
            Some((notes[0].0, notes[0].1, 0, notes[0].2)),
            [(bob0, 700), (alice0, 300)],
        );
        let (e2, st2, w2) = w.transfer_full(
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
        let r = idx.sync(&chain).unwrap();
        assert_eq!((r.accepted, r.rejected), (3, 0));
        let witness = idx.state.batches[1].clone();
        let bparams = idx.batch_params();
        let opening_after = idx.state.opening(idx.next_height());
        let s_next = opening_after.digest();
        assert_eq!(witness.check(&bparams).unwrap().s_next, s_next);
        // the same two transfers proven under the split transcript
        let params: Params<vesta::Affine> = Params::new(K);
        let vk = plonk::keygen_vk(&params, &TransferCircuit::default()).unwrap();
        let pk = plonk::keygen_pk(&params, vk.clone(), &TransferCircuit::default()).unwrap();
        let mut groups = Vec::new();
        let mut fields_data = Vec::new();
        for (i, (st, wit)) in [(st1, w1), (st2, w2)].into_iter().enumerate() {
            let instance = st.to_field_elements();
            let mut tr = SplitWrite::init(vec![]);
            plonk::create_proof(
                &params,
                &pk,
                &[TransferCircuit {
                    statement: Some(st.clone()),
                    witness: Some(wit),
                    negate_g_d: false,
                }],
                &[&[&instance[..]]],
                &mut StdRng::seed_from_u64(90 + i as u64),
                &mut tr,
            )
            .unwrap();
            let proof = tr.finalize();
            let (cap, froms) = capture_split(&params, &vk, &instance, &proof).unwrap();
            let sh = Shadow::compute(&params, &vk, &cap);
            let plan = SplitPlan::build(&params, &vk, &cap, &froms, &sh);
            groups.push(SplitCircuit {
                plan,
                lagrange: params.get_g_lagrange()[..instance.len()].to_vec(),
                values: Some((cap.clone(), sh.clone())),
            });
            let (_, sources) = q::VerifierCircuit::shape(
                &cap,
                &params,
                vk.fixed_commitments(),
                vk.permutation_commitments(),
            );
            let (mut structure, shadow) = Structure::build(&params, &vk, &cap, &sources);
            structure.split = true;
            fields_data.push((
                FieldSideCircuit {
                    structure,
                    shadow: Some(shadow),
                },
                cap,
            ));
        }
        let step_q = StepQSplit {
            groups: groups.clone(),
        };
        let instance_q = step_q.instance();
        let offsets = step_q.offsets();
        println!(
            "T_q (split) over 2 proofs: public inputs {}",
            instance_q.len()
        );
        let t = std::time::Instant::now();
        let mut k_q = 15;
        let prover = loop {
            match MockProver::run(k_q, &step_q, vec![instance_q.clone()]) {
                Ok(p) => break p,
                Err(_) => {
                    k_q += 1;
                    assert!(k_q <= 20);
                }
            }
        };
        prover.assert_satisfied();
        println!(
            "T_q (split) fits k = {k_q} (mock {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<pallas::Point, _>::measure(k_q, &step_q)
        );
        let t = std::time::Instant::now();
        let outer: Params<pallas::Affine> = Params::new(k_q);
        let ovk = plonk::keygen_vk(&outer, &step_q.without_witnesses()).unwrap();
        let opk = plonk::keygen_pk(&outer, ovk.clone(), &step_q.without_witnesses()).unwrap();
        println!("T_q keygen: {:.1} s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let mut tr = PoseidonWrite::<_, pallas::Affine>::init(vec![]);
        plonk::create_proof(
            &outer,
            &opk,
            &[step_q.clone()],
            &[&[&instance_q[..]]],
            &mut StdRng::seed_from_u64(95),
            &mut tr,
        )
        .unwrap();
        let proof_q = tr.finalize();
        println!(
            "T_q prove: {:.1} s, {} bytes",
            t.elapsed().as_secs_f64(),
            proof_q.len()
        );
        let cap_q = capture(&outer, &ovk, &instance_q, &proof_q, &[]).unwrap();
        // T_p
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
            instance_limbs: step_q.instance_limbs_when_verified(),
            expose_instance: true,
            opened_u_slots: vec![],
            re_expose: vec![],
            keys_as_inputs: false,
            allow_base: false,
            base: false,
            capture: Some(cap_q.clone()),
        };
        let mut fields = Vec::new();
        let mut statement_positions = Vec::new();
        for (i, ((field, cap), g)) in fields_data.into_iter().zip(&groups).enumerate() {
            let n_evals = field.structure.n_instance_q
                + field.structure.n_advice_q
                + field.structure.n_fixed_q
                + 1
                + field.structure.n_perm_common
                + (3 * field.structure.n_chunks - 1)
                + 5 * field.structure.n_lookups;
            let links = g.links_for_field_side(n_evals, field.structure.sets.len());
            let _ = cap;
            fields.push((field, links, offsets[i]));
            statement_positions.push(
                g.statement_positions()
                    .iter()
                    .map(|p| offsets[i] + p)
                    .collect::<Vec<_>>(),
            );
        }
        let mut next_transfer = 0;
        let slot_links: Vec<Option<Vec<usize>>> = witness
            .slots
            .iter()
            .map(|s| match s {
                Some(s) if !s.statement.mint => {
                    let l = statement_positions[next_transfer].clone();
                    next_transfer += 1;
                    Some(l)
                }
                _ => None,
            })
            .collect();
        assert_eq!(next_transfer, 2);
        let n = witness.slots.len();
        let step_p = StepPSplit {
            group,
            fields,
            batch: BatchCircuit {
                n,
                params: bparams,
                witness: Some(witness.clone()),
            },
            slot_links,
        };
        let instance_p = step_p.instance();
        println!(
            "T_p (split) over the block: public inputs {}",
            instance_p.len()
        );
        let t = std::time::Instant::now();
        let mut k_p = 17;
        let prover = loop {
            match MockProver::run(k_p, &step_p, vec![instance_p.clone()]) {
                Ok(p) => break p,
                Err(e) => {
                    eprintln!("k = {k_p}: {e:?}");
                    k_p += 1;
                    assert!(k_p <= 20);
                }
            }
        };
        prover.assert_satisfied();
        println!(
            "T_p (split) fits k = {k_p} (mock {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k_p, &step_p)
        );
        if std::env::var("SB_PROVE_STEP5").is_err() {
            println!("SB_PROVE_STEP5 unset: stopping before the real T_p proof");
            return;
        }
        let claims: Vec<Claim<vesta::Affine>> = groups
            .iter()
            .map(|g| g.values.as_ref().unwrap().0.claim())
            .collect();
        let t = std::time::Instant::now();
        let pparams: Params<vesta::Affine> = Params::new(k_p);
        let pvk = plonk::keygen_vk(&pparams, &step_p.without_witnesses()).unwrap();
        let ppk = plonk::keygen_pk(&pparams, pvk.clone(), &step_p.without_witnesses()).unwrap();
        println!("T_p keygen (k = {k_p}): {:.1} s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let mut tr = PoseidonWrite::<_, vesta::Affine>::init(vec![]);
        plonk::create_proof_with_openings(
            &pparams,
            &ppk,
            &[step_p.clone()],
            &[&[&instance_p[..]]],
            &claims,
            &mut StdRng::seed_from_u64(96),
            &mut tr,
        )
        .unwrap();
        let proof_p = tr.finalize();
        println!(
            "T_p prove: {:.1} s, {} bytes",
            t.elapsed().as_secs_f64(),
            proof_p.len()
        );
        let t = std::time::Instant::now();
        let mut tr = PoseidonRead::<_, pallas::Affine>::init(&proof_q[..]);
        plonk::verify_proof(
            &outer,
            &ovk,
            plonk::SingleVerifier::new(&outer),
            &[&[&instance_q[..]]],
            &mut tr,
        )
        .unwrap();
        let mut tr = PoseidonRead::<_, vesta::Affine>::init(&proof_p[..]);
        plonk::verify_proof_with_openings(
            &pparams,
            &pvk,
            plonk::SingleVerifier::new(&pparams),
            &[&[&instance_p[..]]],
            &mut tr,
            &claims,
        )
        .unwrap();
        println!(
            "decider (both): {:.1} ms",
            t.elapsed().as_secs_f64() * 1000.0
        );
        println!(
            "on the wire: {} bytes",
            4 + 4
                + 4
                + n * SLOT_ELEMENTS * 32
                + 3 * 32
                + 24
                + 4
                + instance_q.len() * 32
                + 4
                + proof_q.len()
                + 4
                + instance_p.len() * 32
                + 4
                + proof_p.len()
        );
        let _ = s_next;
    }
}
