//! Steps over several transfer proofs — the fragment size `n` of
//! `docs/REPLAY-PROOF-A.md` §3.4 and §3.7: `T_q` carries the `q` group
//! side of every transfer proof of the block, side by side in the same
//! columns, their public inputs one after another; `T_p` carries the `p`
//! group side of that `T_q`, every transfer proof's field side bound to
//! its part of `T_q`'s instance values, and the relation with each
//! transfer slot bound to its proof's statement. The block and its proofs
//! come from the indexer's replay.

use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use pasta_curves::{pallas, vesta};

use crate::batch::{BatchCircuit, BatchConfig};
use crate::field::fp::{FieldChip, FieldConfig};
use crate::fieldside::fp::FieldSideCircuit;
use crate::step2::bind;
use crate::step3::SLOT_FROM_STATEMENT;
use crate::verifier::{p, q};
use sba_core::batch::SLOT_ELEMENTS;
use sba_primitives::Fp;

/// `T_q` over `n` transfer proofs (no previous step).
#[derive(Clone)]
pub struct StepQN {
    pub groups: Vec<q::VerifierCircuit>,
}

impl std::fmt::Debug for StepQN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StepQN({} proofs)", self.groups.len())
    }
}

impl StepQN {
    /// The public inputs: each group side's, in order.
    pub fn instance(&self) -> Vec<pallas::Scalar> {
        self.groups
            .iter()
            .flat_map(|g| g.instance(g.capture.as_ref().expect("values")))
            .collect()
    }

    /// Where the i-th proof's public inputs start.
    pub fn offsets(&self) -> Vec<usize> {
        let mut v = Vec::with_capacity(self.groups.len());
        let mut at = 0;
        for g in &self.groups {
            v.push(at);
            at += g.layout().len();
        }
        v
    }

    /// How a `p` circuit carries this circuit's instance values.
    pub fn instance_limbs_when_verified(&self) -> Vec<usize> {
        self.groups
            .iter()
            .flat_map(|g| g.instance_limbs_when_verified())
            .collect()
    }
}

impl Circuit<pallas::Scalar> for StepQN {
    type Config = q::VerifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        StepQN {
            groups: self.groups.iter().map(|g| g.without_witnesses()).collect(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Scalar>) -> q::VerifierConfig {
        q::VerifierCircuit::configure(meta)
    }

    fn synthesize(
        &self,
        cfg: q::VerifierConfig,
        mut l: impl Layouter<pallas::Scalar>,
    ) -> Result<(), Error> {
        cfg.assign_table(&mut l)?;
        let mut at = 0;
        for g in &self.groups {
            let ex = g.synthesize_core(&cfg, &mut l, at)?;
            at += ex.cells.len();
        }
        Ok(())
    }
}

/// `T_p` over the block: the `p` group side of `T_q`, the field side of
/// each transfer proof bound to its part of `T_q`'s instance values, the
/// relation with each transfer slot bound to its proof's statement.
#[derive(Clone)]
pub struct StepPN {
    pub group: p::VerifierCircuit,
    /// Per transfer proof: its field side, the links into its part of
    /// `T_q`'s instance values, and where that part starts.
    pub fields: Vec<(FieldSideCircuit, Vec<Vec<usize>>, usize)>,
    pub batch: BatchCircuit,
    /// Per transfer proof, the positions among `T_q`'s instance values of
    /// its statement (the circuit's structure).
    pub statement_positions: Vec<Vec<usize>>,
    /// Per slot, the index of the proof it is bound to (`None` for a mint
    /// or an empty slot): witness data; the circuit's shape does not
    /// depend on it — a slot links to a proof through witnessed bits with
    /// one proof per active transfer slot and one slot per *used* proof.
    pub slot_proof: Vec<Option<usize>>,
    /// Per proof, whether a slot uses it: a fragment holds *up to*
    /// `n_proofs` transfers, the rest being a canned valid proof no slot
    /// binds to (witness data).
    pub used: Vec<bool>,
}

#[derive(Clone, Debug)]
pub struct StepPNConfig {
    pub group: p::VerifierConfig,
    pub field: FieldConfig,
    pub batch: BatchConfig,
}

impl std::fmt::Debug for StepPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StepPN({} proofs, {} slots)",
            self.fields.len(),
            self.batch.n
        )
    }
}

impl StepPN {
    /// The first instance column: the group side's public inputs, then
    /// `s_prev`, `s_next`, `D`; the relation's own column stays empty.
    pub fn instance(&self) -> Vec<Fp> {
        let mut v = self
            .group
            .instance(self.group.capture.as_ref().expect("values"));
        v.extend(self.batch.instance());
        v
    }
}

/// The slots' binding to the proofs' statements, by witnessed bits
/// (`StepPN`'s rule; the chain's circuit uses it too).
#[allow(clippy::too_many_arguments)]
pub fn bind_slots(
    ch: &mut FieldChip,
    l: &mut impl Layouter<Fp>,
    slots: &[Vec<crate::field::fp::Cell>],
    instance_values: &[Vec<crate::field::fp::Cell>],
    statement_positions: &[Vec<usize>],
    slot_proof: &[Option<usize>],
    used: &[bool],
    witness: Option<&sba_core::batch::BatchWitness>,
) -> Result<(), Error> {
    let known = witness.is_some();
    // the slots' binding to the proofs' statements, by witnessed bits:
    // link[s][p] ∈ {0, 1}; Σ_p link[s][p] = active_s · (1 − kind_s) (an
    // active transfer slot binds to exactly one proof, a mint or an
    // empty slot to none); Σ_s link[s][p] = used_p ∈ {0, 1} (a used
    // proof is exactly one slot's, an unused one none's — it is still
    // verified); link[s][p] · (slot_s[i] − statement_p[i]) = 0
    let one = ch.constant(l, Fp::ONE)?;
    let n_p = statement_positions.len();
    let mut per_proof: Vec<Option<_>> = vec![None; n_p];
    for (s, slot) in slots.iter().enumerate() {
        assert_eq!(slot.len(), SLOT_ELEMENTS);
        let kind = &slot[SLOT_ELEMENTS - 1];
        // active: the slot is not all zeros — its h_body is non-zero for
        // a real statement; use the witness to say so, bound below
        let active_v = witness.map(|w| w.slots[s].is_some());
        let active = ch.witness(
            l,
            active_v
                .map(|a| halo2_proofs::circuit::Value::known(Fp::from(a as u64)))
                .unwrap_or(halo2_proofs::circuit::Value::unknown()),
        )?;
        let aa = ch.mul(l, &active, &active)?;
        ch.assert_equal(l, &aa, &active)?;
        // an inactive slot is all zeros (h_body = 0); an active one has
        // h_body ≠ 0 — bind `active` to that through an inverse witness
        let h_body = &slot[sba_core::batch::SLOT_H_BODY];
        let inv = ch.witness(l, h_body.value().map(|v| v.invert().unwrap_or(Fp::ZERO)))?;
        let hi = ch.mul(l, h_body, &inv)?;
        ch.assert_equal(l, &hi, &active)?;
        let not_kind = ch.sub(l, &one, kind)?;
        let want = ch.mul(l, &active, &not_kind)?;
        let mut row_sum: Option<_> = None;
        for (p, proof_sum) in per_proof.iter_mut().enumerate() {
            let bit_v = match (known, slot_proof[s]) {
                (true, Some(q)) => halo2_proofs::circuit::Value::known(Fp::from((q == p) as u64)),
                (true, None) => halo2_proofs::circuit::Value::known(Fp::ZERO),
                (false, _) => halo2_proofs::circuit::Value::unknown(),
            };
            let bit = ch.witness(l, bit_v)?;
            let bb = ch.mul(l, &bit, &bit)?;
            ch.assert_equal(l, &bb, &bit)?;
            for (si, sti) in SLOT_FROM_STATEMENT {
                let cell = &instance_values[statement_positions[p][sti]];
                assert_eq!(cell.len(), 1);
                let d = ch.sub(l, &slot[si], &cell[0])?;
                let t = ch.mul(l, &bit, &d)?;
                ch.assert_constant(l, &t, Fp::ZERO)?;
            }
            row_sum = Some(match row_sum {
                None => bit.clone(),
                Some(acc) => ch.add(l, &acc, &bit)?,
            });
            *proof_sum = Some(match proof_sum.take() {
                None => bit,
                Some(acc) => ch.add(l, &acc, &bit)?,
            });
        }
        if let Some(rs) = row_sum {
            ch.assert_equal(l, &rs, &want)?;
        }
    }
    for (p, col) in per_proof.into_iter().enumerate() {
        let used_v = if known {
            halo2_proofs::circuit::Value::known(Fp::from(used[p] as u64))
        } else {
            halo2_proofs::circuit::Value::unknown()
        };
        let used = ch.witness(l, used_v)?;
        let uu = ch.mul(l, &used, &used)?;
        ch.assert_equal(l, &uu, &used)?;
        if let Some(col) = col {
            ch.assert_equal(l, &col, &used)?;
        }
    }
    Ok(())
}

impl Circuit<vesta::Scalar> for StepPN {
    type Config = StepPNConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        StepPN {
            group: self.group.without_witnesses(),
            fields: self
                .fields
                .iter()
                .map(|(f, l, o)| (f.without_witnesses(), l.clone(), *o))
                .collect(),
            batch: self.batch.without_witnesses(),
            statement_positions: self.statement_positions.clone(),
            slot_proof: vec![None; self.slot_proof.len()],
            used: vec![false; self.used.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> StepPNConfig {
        let group = p::VerifierCircuit::configure(meta);
        StepPNConfig {
            batch: BatchConfig::configure_in(meta, group.instance),
            group,
            field: FieldSideCircuit::configure_field(meta),
        }
    }

    fn synthesize(&self, cfg: StepPNConfig, mut l: impl Layouter<Fp>) -> Result<(), Error> {
        cfg.group.assign_table(&mut l)?;
        cfg.batch.assign_table(&mut l)?;
        let ex = self.group.synthesize_core(&cfg.group, &mut l, 0)?;
        let mut ch = FieldChip::new(&cfg.field);
        for (field, links, offset) in &self.fields {
            let (inputs, outputs) = field.synthesize_core(&cfg.field, None, None, &mut l)?;
            let cells: Vec<_> = inputs.into_iter().chain(outputs).collect();
            bind(&mut ch, &mut l, &cells, links, &ex.instance_values, *offset)?;
        }
        let (slots, _) = self.batch.synthesize_core(
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
        eprintln!("step: {} proofs, {} slots", self.fields.len(), self.batch.n);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use crate::capture::{Capture, capture};
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::Params;
    use pasta_curves::vesta;
    use sb_common::carrier::carrier_output;
    use sba_circuit::{K, TransferCircuit, TransferStatement};
    use sba_core::envelope::{Envelope, parse_envelope};
    use sba_core::event::EventKind;
    use sba_core::note::decrypt_as_recipient;
    use sba_indexer::testing::{ACTIVATION, MockChain, World, tx_with};
    use sba_primitives::Fp;

    /// Two mints to alice; then a block with two transfers (each spending
    /// one mint, to bob) and a mint. The second block's witness and
    /// parameters, the transfer circuit's keys, the captures of its two
    /// transfer proofs in slot order, `s_next`, the opening after, and the
    /// transfers as (statement, proof).
    #[allow(clippy::type_complexity)]
    pub(crate) fn replayed_block_with_two_transfers() -> (
        sba_core::batch::BatchWitness,
        sba_core::batch::BatchParams,
        Params<vesta::Affine>,
        plonk::VerifyingKey<vesta::Affine>,
        Vec<Capture<vesta::Affine>>,
        Fp,
        sba_core::batch::StateOpening,
        Vec<(TransferStatement, Vec<u8>)>,
    ) {
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
        let r = idx.sync(&chain).unwrap();
        assert_eq!((r.accepted, r.rejected), (3, 0));
        let witness = idx.state.batches[1].clone();
        let params = idx.batch_params();
        let opening_after = idx.state.opening(idx.next_height());
        let s_next = opening_after.digest();
        let halo_params: Params<vesta::Affine> = Params::new(K);
        let vk = plonk::keygen_vk(&halo_params, &TransferCircuit::default()).unwrap();
        let mut caps = Vec::new();
        let mut transfers = Vec::new();
        for ev in idx
            .state
            .events
            .iter()
            .filter(|e| e.kind == EventKind::Transfer)
        {
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
            caps.push(capture(&halo_params, &vk, &st.to_field_elements(), &t.proof, &[]).unwrap());
            transfers.push((st, t.proof.clone()));
        }
        assert_eq!(caps.len(), 2);
        (
            witness,
            params,
            halo_params,
            vk,
            caps,
            s_next,
            opening_after,
            transfers,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::replayed_block_with_two_transfers;
    use super::*;
    use crate::capture::capture;
    use crate::fieldside::fp::Structure;
    use crate::native::{PoseidonRead, PoseidonWrite};
    use crate::verifier::tests_support::q_circuit;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk;
    use halo2_proofs::poly::commitment::{Claim, Params};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sba_circuit::K;

    /// `cargo test --release a_block_with_two_transfers -- --ignored --nocapture`
    /// (`SB_PROVE_STEP4=1`: both proofs for real and the decider).
    #[test]
    #[ignore]
    fn a_block_with_two_transfers_in_one_step() {
        let (witness, bparams, params, vk, caps, s_next, opening_after, _transfers) =
            replayed_block_with_two_transfers();
        let st = witness
            .check(&bparams)
            .expect("the native relation accepts");
        assert_eq!(st.s_next, s_next);
        // T_q over both transfer proofs
        let qcs: Vec<q::VerifierCircuit> =
            caps.iter().map(|c| q_circuit(&params, &vk, c)).collect();
        let step_q = StepQN {
            groups: qcs.clone(),
        };
        let instance_q = step_q.instance();
        let offsets = step_q.offsets();
        println!("T_q over 2 proofs: public inputs {}", instance_q.len());
        let t = std::time::Instant::now();
        let mut k_q = 16;
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
            "T_q fits k = {k_q} (mock {:.1} s)",
            t.elapsed().as_secs_f64()
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
            &mut StdRng::seed_from_u64(51),
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
        let mut statement_positions: Vec<Vec<usize>> = Vec::new();
        for (i, (cap, qc)) in caps.iter().zip(&qcs).enumerate() {
            let (_, sources) = q::VerifierCircuit::shape(
                cap,
                &params,
                vk.fixed_commitments(),
                vk.permutation_commitments(),
            );
            let (structure, shadow) = Structure::build(&params, &vk, cap, &sources);
            fields.push((
                FieldSideCircuit {
                    structure,
                    shadow: Some(shadow),
                },
                qc.links_for_field_side(),
                offsets[i],
            ));
            statement_positions.push(
                (0..cap.instance.len())
                    .map(|j| offsets[i] + qc.instance_value_slots(j)[0])
                    .collect(),
            );
        }
        // transfer slots in order are the transfer proofs in order
        let mut next_transfer = 0;
        let slot_proof: Vec<Option<usize>> = witness
            .slots
            .iter()
            .map(|s| match s {
                Some(s) if !s.statement.mint => {
                    next_transfer += 1;
                    Some(next_transfer - 1)
                }
                _ => None,
            })
            .collect();
        assert_eq!(next_transfer, 2);
        let n = witness.slots.len();
        let step_p = StepPN {
            group,
            fields,
            batch: BatchCircuit {
                n,
                n_empty: 0,
                params: bparams,
                witness: Some(witness.clone()),
            },
            statement_positions,
            slot_proof,
            used: vec![true; 2],
        };
        let instance_p = step_p.instance();
        println!(
            "T_p over the block ({n} slots, 2 proofs): public inputs {}",
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
            "T_p fits k = {k_p} (mock {:.1} s)",
            t.elapsed().as_secs_f64()
        );
        println!(
            "{:?}",
            halo2_proofs::dev::CircuitCost::<vesta::Point, _>::measure(k_p, &step_p)
        );
        // the second transfer's slot bound to the first proof's statement is refused
        let mut swapped = step_p.clone();
        swapped.slot_proof.swap(0, 1);
        assert!(
            MockProver::run(k_p, &swapped, vec![instance_p.clone()])
                .unwrap()
                .verify()
                .is_err()
        );
        // the wire: the claims read back from T_q's public inputs are the
        // transfer proofs' own
        let read_claims = crate::wire::claims_of(&step_q, K as usize, &instance_q).unwrap();
        for (c, cap) in read_claims.iter().zip(&caps) {
            assert_eq!(c.g, cap.g);
            assert_eq!(c.u, cap.u);
        }
        if std::env::var("SB_PROVE_STEP4").is_err() {
            println!("SB_PROVE_STEP4 unset: stopping before the real T_p proof");
            return;
        }
        let claims: Vec<Claim<vesta::Affine>> = caps.iter().map(|c| c.claim()).collect();
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
            &mut StdRng::seed_from_u64(52),
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
        // the proven step on the wire, decided by a client from its state digest
        let step = crate::wire::ProvenStep {
            first_height: 1001,
            height: 1001,
            slots: witness
                .slots
                .iter()
                .map(|s| s.as_ref().map(|s| s.statement))
                .collect(),
            opening_after,
            instance_q: instance_q.clone(),
            proof_q: proof_q.clone(),
            instance_p: instance_p.clone(),
            proof_p: proof_p.clone(),
        };
        let bytes = step.to_bytes();
        println!("proven step on the wire: {} bytes", bytes.len());
        let back = crate::wire::ProvenStep::from_bytes(&bytes).unwrap();
        let decider = crate::wire::Decider {
            outer: &outer,
            ovk: &ovk,
            pparams: &pparams,
            pvk: &pvk,
            step_q: &step_q,
            transfer_k: K as usize,
        };
        let t = std::time::Instant::now();
        let s_next_got = decider.decide(&back, witness.prev.digest()).unwrap();
        println!("decide: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(s_next_got, s_next);
        assert!(
            decider
                .decide(&back, witness.prev.digest() + Fp::ONE)
                .is_err()
        );
        let mut tampered = back.clone();
        tampered.slots.swap(0, 1);
        assert!(decider.decide(&tampered, witness.prev.digest()).is_err());
    }
}
