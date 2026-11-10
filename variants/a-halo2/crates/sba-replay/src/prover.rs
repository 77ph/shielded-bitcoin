//! The step prover and its keys (`docs/REPLAY-PROOF-A.md` §3.4, §3.7):
//! `Keys` fixes the two circuits of a step for a fragment of `n_proofs`
//! transfer proofs and `n_slots` slots — their shapes come from one sample
//! transfer proof, since every transfer proof has the same structure —
//! and makes their proving and verifying keys once; `Prover` turns a
//! block's batch witness and its accepted transfer proofs into a
//! `ProvenStep`; the client's `Decider` comes from the same keys.

use halo2_proofs::plonk::{self, Circuit, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::{Claim, Params};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;

use crate::batch::BatchCircuit;
use crate::capture::capture;
use crate::fieldside::fp::{FieldSideCircuit, Structure};
use crate::native::PoseidonWrite;
use crate::step4::{StepPN, StepQN};
use crate::verifier::{p, q};
use crate::wire::{Decider, ProvenStep};
use sba_circuit::{K, TransferCircuit, TransferParams, TransferStatement};
use sba_core::batch::{BatchParams, BatchWitness, StateOpening};

/// A fragment's circuits and keys.
pub struct Keys {
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
    /// The circuits' shapes (no values).
    pub step_q: StepQN,
    pub step_p: StepPN,
    pub batch_params: BatchParams,
    /// A valid transfer proof of a sample statement: the padding of a
    /// fragment with fewer transfers than `n_proofs`.
    pub padding: (TransferStatement, Vec<u8>),
}

impl Keys {
    /// Keys for fragments of `n_proofs` transfer proofs over `n_slots`
    /// slots at `k_q`, `k_p` (the study's table: 1 → 15/17, 2 → 16/17,
    /// 4 → 17/18). Minutes.
    pub fn generate(
        n_proofs: usize,
        n_slots: usize,
        k_q: u32,
        k_p: u32,
        batch_params: BatchParams,
    ) -> Result<Self, String> {
        assert!(n_proofs >= 1 && n_slots >= n_proofs);
        // one sample transfer proof fixes every shape
        let tp = TransferParams::build().map_err(|e| format!("{e:?}"))?;
        let (st, w) = crate::sample::sample();
        let proof = tp
            .prove(&st, &w, &mut OsRng)
            .map_err(|e| format!("{e:?}"))?;
        let tparams: Params<vesta::Affine> = Params::new(K);
        let tvk = plonk::keygen_vk(&tparams, &TransferCircuit::default())
            .map_err(|e| format!("{e:?}"))?;
        let cap = capture(&tparams, &tvk, &st.to_field_elements(), &proof, &[])
            .map_err(|e| format!("{e:?}"))?;
        let step_q = StepQN {
            groups: vec![q::VerifierCircuit::over(&tparams, &tvk, &cap); n_proofs],
        };
        let outer: Params<pallas::Affine> = Params::new(k_q);
        let ovk = plonk::keygen_vk(&outer, &step_q.without_witnesses())
            .map_err(|e| format!("T_q keygen: {e:?}"))?;
        let opk = plonk::keygen_pk(&outer, ovk.clone(), &step_q.without_witnesses())
            .map_err(|e| format!("{e:?}"))?;
        // a sample T_q proof fixes T_p's group side
        let instance_q = step_q.instance();
        let mut tr = PoseidonWrite::<_, pallas::Affine>::init(vec![]);
        plonk::create_proof(
            &outer,
            &opk,
            std::slice::from_ref(&step_q),
            &[&[&instance_q[..]]],
            OsRng,
            &mut tr,
        )
        .map_err(|e| format!("sample T_q: {e:?}"))?;
        let cap_q = capture(&outer, &ovk, &instance_q, &tr.finalize(), &[])
            .map_err(|e| format!("{e:?}"))?;
        let step_p = Self::step_p(
            &step_q,
            &cap_q,
            &outer,
            &ovk,
            &tparams,
            &tvk,
            &[cap],
            n_slots,
            batch_params,
            None,
            &[],
            &vec![false; n_proofs],
        )?;
        let pparams: Params<vesta::Affine> = Params::new(k_p);
        let pvk = plonk::keygen_vk(&pparams, &step_p.without_witnesses())
            .map_err(|e| format!("T_p keygen: {e:?}"))?;
        let ppk = plonk::keygen_pk(&pparams, pvk.clone(), &step_p.without_witnesses())
            .map_err(|e| format!("{e:?}"))?;
        Ok(Keys {
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
            step_q: step_q.without_witnesses(),
            step_p: step_p.without_witnesses(),
            batch_params,
            padding: (st, proof),
        })
    }

    /// `T_p` over a `T_q` capture: the field sides take the transfer
    /// captures in proof order (`caps[0]` repeated when fewer are given —
    /// the shape is the same); the relation over `witness`.
    #[allow(clippy::too_many_arguments)]
    fn step_p(
        step_q: &StepQN,
        cap_q: &crate::capture::Capture<pallas::Affine>,
        outer: &Params<pallas::Affine>,
        ovk: &VerifyingKey<pallas::Affine>,
        tparams: &Params<vesta::Affine>,
        tvk: &VerifyingKey<vesta::Affine>,
        caps: &[crate::capture::Capture<vesta::Affine>],
        n_slots: usize,
        batch_params: BatchParams,
        witness: Option<BatchWitness>,
        slot_proof: &[Option<usize>],
        used: &[bool],
    ) -> Result<StepPN, String> {
        let (kinds, sources) = p::VerifierCircuit::shape(
            cap_q,
            outer,
            ovk.fixed_commitments(),
            ovk.permutation_commitments(),
        );
        let instance_q_len = step_q
            .groups
            .iter()
            .map(|g| g.layout().len())
            .sum::<usize>();
        let group = p::VerifierCircuit {
            kinds,
            sources,
            params_w: outer.get_w(),
            params_u: outer.get_u(),
            lagrange: outer.get_g_lagrange()[..instance_q_len].to_vec(),
            instance_limbs: step_q.instance_limbs_when_verified(),
            expose_instance: true,
            opened_u_slots: vec![],
            re_expose: vec![],
            capture: Some(cap_q.clone()),
        };
        let offsets = step_q.offsets();
        let mut fields = Vec::new();
        let mut statement_positions = Vec::new();
        for (i, g) in step_q.groups.iter().enumerate() {
            let cap = caps.get(i).unwrap_or(&caps[0]);
            let (_, src) = q::VerifierCircuit::shape(
                cap,
                tparams,
                tvk.fixed_commitments(),
                tvk.permutation_commitments(),
            );
            let (structure, shadow) = Structure::build(tparams, tvk, cap, &src);
            fields.push((
                FieldSideCircuit {
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
        Ok(StepPN {
            group,
            fields,
            batch: BatchCircuit {
                n: n_slots,
                params: batch_params,
                witness,
            },
            statement_positions,
            slot_proof: if slot_proof.is_empty() {
                vec![None; n_slots]
            } else {
                slot_proof.to_vec()
            },
            used: used.to_vec(),
        })
    }

    pub fn decider(&self) -> Decider<'_> {
        Decider {
            outer: &self.outer,
            ovk: &self.ovk,
            pparams: &self.pparams,
            pvk: &self.pvk,
            step_q: &self.step_q,
            transfer_k: K as usize,
        }
    }
}

/// The step prover over the keys.
pub struct Prover<'k> {
    pub keys: &'k Keys,
}

impl Prover<'_> {
    /// Prove one block's fragment: its batch witness (from the indexer),
    /// the opening after it, and the accepted transfers' statements and
    /// proofs in the order the slots have them.
    pub fn prove_block(
        &self,
        height: u32,
        witness: &BatchWitness,
        opening_after: &StateOpening,
        transfers: &[(TransferStatement, Vec<u8>)],
    ) -> Result<ProvenStep, String> {
        let k = self.keys;
        if transfers.len() > k.n_proofs {
            return Err(format!(
                "{} transfer proofs for a fragment of {}",
                transfers.len(),
                k.n_proofs
            ));
        }
        let used: Vec<bool> = (0..k.n_proofs).map(|i| i < transfers.len()).collect();
        let mut transfers: Vec<(TransferStatement, Vec<u8>)> = transfers.to_vec();
        while transfers.len() < k.n_proofs {
            transfers.push(k.padding.clone());
        }
        if witness.slots.len() != k.n_slots {
            return Err(format!(
                "{} slots for a fragment of {}",
                witness.slots.len(),
                k.n_slots
            ));
        }
        let statement = witness
            .check(&k.batch_params)
            .ok_or("the relation refuses the witness")?;
        if statement.s_next != opening_after.digest() {
            return Err("the opening after is not the witness's".into());
        }
        // the transfer slots in order are the transfers in order
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
            return Err(format!(
                "{next} transfer slots, {} proofs",
                used.iter().filter(|u| **u).count()
            ));
        }
        let caps: Vec<_> = transfers
            .iter()
            .map(|(st, proof)| {
                capture(&k.tparams, &k.tvk, &st.to_field_elements(), proof, &[])
                    .map_err(|e| format!("a transfer proof: {e:?}"))
            })
            .collect::<Result<_, _>>()?;
        // T_q
        let step_q = StepQN {
            groups: caps
                .iter()
                .map(|c| q::VerifierCircuit::over(&k.tparams, &k.tvk, c))
                .collect(),
        };
        let instance_q = step_q.instance();
        let mut tr = PoseidonWrite::<_, pallas::Affine>::init(vec![]);
        plonk::create_proof(
            &k.outer,
            &k.opk,
            std::slice::from_ref(&step_q),
            &[&[&instance_q[..]]],
            OsRng,
            &mut tr,
        )
        .map_err(|e| format!("T_q: {e:?}"))?;
        let proof_q = tr.finalize();
        let cap_q =
            capture(&k.outer, &k.ovk, &instance_q, &proof_q, &[]).map_err(|e| format!("{e:?}"))?;
        // T_p
        let step_p = Keys::step_p(
            &step_q,
            &cap_q,
            &k.outer,
            &k.ovk,
            &k.tparams,
            &k.tvk,
            &caps,
            k.n_slots,
            k.batch_params,
            Some(witness.clone()),
            &slot_proof,
            &used,
        )?;
        let instance_p = step_p.instance();
        let claims: Vec<Claim<vesta::Affine>> = caps.iter().map(|c| c.claim()).collect();
        let mut tr = PoseidonWrite::<_, vesta::Affine>::init(vec![]);
        plonk::create_proof_with_openings(
            &k.pparams,
            &k.ppk,
            &[step_p],
            &[&[&instance_p[..], &[]]],
            &claims,
            OsRng,
            &mut tr,
        )
        .map_err(|e| format!("T_p: {e:?}"))?;
        let proof_p = tr.finalize();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step4::tests_support::replayed_block_with_two_transfers;

    /// Keys once, then a replayed block proven and decided through the
    /// API: `cargo test -p sba-replay --release keys_once -- --ignored --nocapture`
    /// (the server: k = 17 keys and proof, ≈ 10 GB).
    #[test]
    #[ignore]
    fn keys_once_then_a_block_proven_and_decided() {
        let (witness, bparams, _params, _vk, _caps, _s_next, opening_after, transfers) =
            replayed_block_with_two_transfers();
        let t = std::time::Instant::now();
        let keys = Keys::generate(2, witness.slots.len(), 16, 17, bparams).unwrap();
        println!("keys: {:.1} s", t.elapsed().as_secs_f64());
        let prover = Prover { keys: &keys };
        let t = std::time::Instant::now();
        let step = prover
            .prove_block(1001, &witness, &opening_after, &transfers)
            .unwrap();
        println!(
            "prove_block: {:.1} s, {} bytes on the wire",
            t.elapsed().as_secs_f64(),
            step.to_bytes().len()
        );
        let decider = keys.decider();
        let t = std::time::Instant::now();
        let s_next = decider.decide(&step, witness.prev.digest()).unwrap();
        println!("decide: {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(s_next, opening_after.digest());
    }
}
