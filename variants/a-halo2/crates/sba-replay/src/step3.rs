//! `T_p` with the batch relation inside (`docs/REPLAY-PROOF-A.md` §3.7):
//! the `p` group side of `T_q`, the field side of the block's transfer
//! proof, and the relation over the block's batch witness, with every
//! transfer slot's elements bound to the statement `T_q` exposed for that
//! proof — `r_anchor`, the nullifiers, the keys, the ciphertexts, `h_body`;
//! `h_anchor` and the kind are the slot's own, and a linked slot's kind is
//! a transfer. The block comes from the indexer's own replay (its test
//! world), so the witness is what a deployment's indexer produces.

use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use pasta_curves::vesta;

use crate::batch::{BatchCircuit, BatchConfig};
use crate::field::fp::{FieldChip, FieldConfig};
use crate::fieldside::fp::FieldSideCircuit;
use crate::step2::bind;
use crate::verifier::p;
use sba_core::batch::{SLOT_ELEMENTS, SLOT_H_BODY};
use sba_primitives::Fp;

/// The slot elements a transfer statement fixes, as (slot index, index in
/// `TransferStatement::to_field_elements`): `r_anchor`, the nullifiers,
/// the keys and ciphertexts in the slot's per-output order, `h_body`.
pub const SLOT_FROM_STATEMENT: [(usize, usize); 14] = [
    (1, 1),
    (2, 4),
    (3, 5),
    (4, 6),
    (5, 7),
    (6, 10),
    (7, 11),
    (8, 12),
    (9, 8),
    (10, 9),
    (11, 13),
    (12, 14),
    (13, 15),
    (SLOT_H_BODY, 16),
];

#[derive(Clone)]
pub struct StepPBatch {
    /// The `p` group side of `T_q` (instance values exposed).
    pub group: p::VerifierCircuit,
    /// The field side of the block's transfer proof, linked to `T_q`'s
    /// instance values.
    pub field: FieldSideCircuit,
    pub links: Vec<Vec<usize>>,
    /// The relation over the block's witness.
    pub batch: BatchCircuit,
    /// Per slot: the positions among `T_q`'s instance values of the
    /// transfer statement it is bound to (`None` for a mint or an empty
    /// slot).
    pub slot_links: Vec<Option<Vec<usize>>>,
}

#[derive(Clone, Debug)]
pub struct StepPBatchConfig {
    pub group: p::VerifierConfig,
    pub field: FieldConfig,
    pub batch: BatchConfig,
}

impl std::fmt::Debug for StepPBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StepPBatch({} slots)", self.batch.n)
    }
}

impl StepPBatch {
    /// The public inputs (the first instance column; the relation's own
    /// column stays empty, its values go after the group side's here):
    /// the group side's, then `s_prev`, `s_next`, `D`.
    pub fn instance(&self) -> Vec<Fp> {
        let mut v = self
            .group
            .instance(self.group.capture.as_ref().expect("values"));
        v.extend(self.batch.instance());
        v
    }
}

impl Circuit<vesta::Scalar> for StepPBatch {
    type Config = StepPBatchConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        StepPBatch {
            group: self.group.without_witnesses(),
            field: self.field.without_witnesses(),
            links: self.links.clone(),
            batch: self.batch.without_witnesses(),
            slot_links: self.slot_links.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> StepPBatchConfig {
        let group = p::VerifierCircuit::configure(meta);
        StepPBatchConfig {
            batch: BatchConfig::configure_in(meta, group.instance),
            group,
            field: FieldSideCircuit::configure_field(meta),
        }
    }

    fn synthesize(
        &self,
        cfg: StepPBatchConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        cfg.group.assign_table(&mut layouter)?;
        cfg.batch.assign_table(&mut layouter)?;
        let ex = self.group.synthesize_core(&cfg.group, &mut layouter, 0)?;
        let (inputs, outputs) =
            self.field
                .synthesize_core(&cfg.field, None, None, &mut layouter)?;
        let cells: Vec<_> = inputs.into_iter().chain(outputs).collect();
        let mut ch = FieldChip::new(&cfg.field);
        bind(
            &mut ch,
            &mut layouter,
            &cells,
            &self.links,
            &ex.instance_values,
            0,
        )?;
        // the relation, its public values after the group side's
        let (slots, _) = self.batch.synthesize_core(
            &cfg.batch,
            &mut layouter,
            Some((cfg.group.instance, ex.cells.len())),
        )?;
        // each transfer slot's elements are the statement T_q exposed
        for (slot, link) in slots.iter().zip(&self.slot_links) {
            let Some(positions) = link else { continue };
            assert_eq!(slot.len(), SLOT_ELEMENTS);
            for (si, sti) in SLOT_FROM_STATEMENT {
                let cell = &ex.instance_values[positions[sti]];
                assert_eq!(cell.len(), 1, "a statement element is one cell");
                ch.assert_equal(&mut layouter, &slot[si], &cell[0])?;
            }
            // a linked slot is a transfer: its kind is zero
            let zero = ch.constant(&mut layouter, Fp::ZERO)?;
            ch.assert_equal(&mut layouter, &slot[SLOT_ELEMENTS - 1], &zero)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Capture, capture};
    use crate::fieldside::fp::Structure;
    use crate::native::{PoseidonRead, PoseidonWrite};
    use crate::step::tests_support::tq;
    use crate::verifier::q;
    use crate::verifier::tests_support::q_circuit;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::Params;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sb_common::carrier::carrier_output;
    use sba_circuit::{K, TransferCircuit, TransferStatement};
    use sba_core::envelope::{Envelope, parse_envelope};
    use sba_core::event::EventKind;
    use sba_core::note::decrypt_as_recipient;
    use sba_indexer::testing::{ACTIVATION, MockChain, World, tx_with};

    /// The indexer replays a mint, then a block with a transfer and a
    /// mint; the second block's batch witness and its transfer proof's
    /// capture, with the statement as the circuit saw it.
    fn replayed_block() -> (
        sba_core::batch::BatchWitness,
        sba_core::batch::BatchParams,
        Params<vesta::Affine>,
        plonk::VerifyingKey<vesta::Affine>,
        Capture<vesta::Affine>,
        Fp,
        Fp,
    ) {
        let mut w = World::new();
        let (_, alice0) = w.alice.ivk.find_address(0);
        let (_, bob0) = w.bob.ivk.find_address(0);
        let mut chain = MockChain::new(ACTIVATION);
        let mut idx = w.indexer();
        let (mint_tx, _) = w.mint_tx(&alice0, 1000);
        chain.push_block(vec![mint_tx]);
        idx.sync(&chain).unwrap();
        let ev = &idx.state.events[0];
        let (pk_eph, ct) = &ev.outputs[0];
        let pt = decrypt_as_recipient(&w.alice.ivk.sk_view, pk_eph, ct).unwrap();
        let mint_hb = ev.h_body;
        let env = w.transfer(
            &idx,
            1000,
            Some((pt, mint_hb, 0, 0)),
            [(bob0, 700), (alice0, 300)],
        );
        let (mint2, _) = w.mint_tx(&alice0, 5);
        chain.push_block(vec![tx_with(vec![carrier_output(&env.to_bytes())]), mint2]);
        let r = idx.sync(&chain).unwrap();
        assert_eq!((r.accepted, r.rejected), (2, 0));
        let witness = idx.state.batches[1].clone();
        let params = idx.batch_params();
        let s_next = idx.state.opening(idx.next_height()).digest();
        // the transfer proof and its statement from the accepted event
        let ev = idx
            .state
            .events
            .iter()
            .find(|e| e.kind == EventKind::Transfer)
            .unwrap();
        let Envelope::Transfer(t) = parse_envelope(&ev.raw).unwrap() else {
            panic!("a transfer")
        };
        let st = TransferStatement {
            const_salt: w.deployment.const_salt_fp(),
            r_anchor: idx.root_at(t.body.h_anchor).unwrap(),
            nullifiers: t.body.nullifiers,
            pk_eph: t.body.pk_eph,
            ct_note: t.body.ct_note,
            h_body: t.body.h_body(&w.deployment.const_salt),
        };
        assert_eq!(st.h_body, ev.h_body);
        let halo_params: Params<vesta::Affine> = Params::new(K);
        let vk = plonk::keygen_vk(&halo_params, &TransferCircuit::default()).unwrap();
        let cap = capture(&halo_params, &vk, &st.to_field_elements(), &t.proof, &[]).unwrap();
        let s_prev = witness.prev.digest();
        (witness, params, halo_params, vk, cap, s_prev, s_next)
    }

    /// `cargo test --release a_replayed_block -- --ignored --nocapture`
    /// (with `SB_PROVE_STEP3=1`, the proof is made for real and decided).
    #[test]
    #[ignore]
    fn a_replayed_blocks_relation_inside_the_step() {
        let (witness, bparams, params, vk, cap, s_prev, s_next) = replayed_block();
        let st = witness
            .check(&bparams)
            .expect("the native relation accepts");
        assert_eq!(st.s_prev, s_prev);
        assert_eq!(st.s_next, s_next);
        // T_q over the transfer proof
        let (outer, ovk, instance_q, _proof_q, cap_q) = tq(&params, &vk, &cap);
        let (kinds, sources_q) = p::VerifierCircuit::shape(
            &cap_q,
            &outer,
            ovk.fixed_commitments(),
            ovk.permutation_commitments(),
        );
        let qc = q_circuit(&params, &vk, &cap);
        let group = p::VerifierCircuit {
            kinds,
            sources: sources_q,
            params_w: outer.get_w(),
            params_u: outer.get_u(),
            lagrange: outer.get_g_lagrange()[..instance_q.len()].to_vec(),
            instance_limbs: qc.instance_limbs_when_verified(),
            expose_instance: true,
            opened_u_slots: vec![],
            re_expose: vec![],
            keys_as_inputs: false,
            allow_base: false,
            base: false,
            capture: Some(cap_q.clone()),
        };
        let (_, sources) = q::VerifierCircuit::shape(
            &cap,
            &params,
            vk.fixed_commitments(),
            vk.permutation_commitments(),
        );
        let (structure, shadow) = Structure::build(&params, &vk, &cap, &sources);
        let field = FieldSideCircuit {
            structure,
            shadow: Some(shadow),
        };
        let links = qc.links_for_field_side();
        // the statement's 17 values are T_q's instance values 0..17
        let statement_positions: Vec<usize> = (0..cap.instance.len())
            .map(|j| {
                let s = qc.instance_value_slots(j);
                assert_eq!(s.len(), 1);
                s[0]
            })
            .collect();
        let slot_links: Vec<Option<Vec<usize>>> = witness
            .slots
            .iter()
            .map(|s| match s {
                Some(s) if !s.statement.mint => Some(statement_positions.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(slot_links.iter().filter(|l| l.is_some()).count(), 1);
        let n = witness.slots.len();
        let step = StepPBatch {
            group,
            field,
            links,
            batch: BatchCircuit {
                n,
                n_empty: 0,
                params: bparams,
                witness: Some(witness.clone()),
            },
            slot_links,
        };
        let instance = step.instance();
        println!(
            "T_p with the relation ({n} slots): public inputs {}",
            instance.len()
        );
        let mut k = 17;
        let t = std::time::Instant::now();
        let prover = loop {
            match MockProver::run(k, &step, vec![instance.clone()]) {
                Ok(p) => break p,
                Err(e) => {
                    eprintln!("k = {k}: {e:?}");
                    k += 1;
                    assert!(k <= 20);
                }
            }
        };
        println!("fits k = {k} (mock {:.1} s)", t.elapsed().as_secs_f64());
        prover.assert_satisfied();
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k, &step)
        );
        // a slot whose r_anchor is not the proof's is refused
        let mut tampered = witness.clone();
        tampered.slots[0].as_mut().unwrap().statement.r_anchor += Fp::ONE;
        let mut bad = step.clone();
        bad.batch.witness = Some(tampered);
        assert!(
            MockProver::run(k, &bad, vec![instance.clone()])
                .unwrap()
                .verify()
                .is_err()
        );
        if std::env::var("SB_PROVE_STEP3").is_err() {
            println!("SB_PROVE_STEP3 unset: stopping before the real proof");
            return;
        }
        let claim = cap.claim();
        let t = std::time::Instant::now();
        let pparams: Params<vesta::Affine> = Params::new(k);
        let pvk = plonk::keygen_vk(&pparams, &step.without_witnesses()).unwrap();
        let ppk = plonk::keygen_pk(&pparams, pvk.clone(), &step.without_witnesses()).unwrap();
        println!("keygen (k = {k}): {:.1} s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        let mut tr = PoseidonWrite::<_, vesta::Affine>::init(vec![]);
        plonk::create_proof_with_openings(
            &pparams,
            &ppk,
            &[step.clone()],
            &[&[&instance[..]]],
            &[claim.clone()],
            &mut StdRng::seed_from_u64(41),
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
        let mut tr = PoseidonRead::<_, vesta::Affine>::init(&proof[..]);
        plonk::verify_proof_with_openings(
            &pparams,
            &pvk,
            plonk::SingleVerifier::new(&pparams),
            &[&[&instance[..]]],
            &mut tr,
            &[claim],
        )
        .unwrap();
        println!("decider: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
        let n_i = instance.len();
        assert_eq!(instance[n_i - 3], s_prev);
        assert_eq!(instance[n_i - 2], s_next);
    }
}
