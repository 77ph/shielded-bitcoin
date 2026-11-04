//! Replay of family-A envelopes against a mock chain: a mint, an accepted
//! transfer proven with the Halo 2 circuit, every rejection class, a
//! reorganisation rollback, and state persistence.

use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use ff::Field;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_common::carrier::{CarrierMode, carrier_output};
use sb_common::chain::mock::MockChain;
use sba_circuit::{
    InputWitness, OutputWitness, TransferParams, TransferStatement, TransferWitness,
};
use sba_core::address::Network;
use sba_core::envelope::{MintEnvelope, PROOF_LEN, TransferBody, TransferEnvelope};
use sba_core::keys::{Seed, WalletKeys};
use sba_core::note::{NotePlaintext, decrypt_as_recipient, encrypt_note, nullifier};
use sba_core::recovery::{RecoveryEntry, binding_digest, encrypt_recovery};
use sba_core::tree::{DEPTH, EMPTY_ROOTS};
use sba_indexer::{Deployment, DevBoundary, Indexer, RejectReason, ReplayState};
use sba_primitives::Fp;

const ACTIVATION: u32 = 1000;

fn vault_script() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![
        0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
    ])
}

fn tx_with(outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: outputs,
    }
}

struct World {
    deployment: Deployment,
    params: TransferParams,
    alice: WalletKeys,
    bob: WalletKeys,
    rng: ChaCha20Rng,
}

impl World {
    fn new() -> Self {
        let params = TransferParams::build().unwrap();
        let deployment = Deployment {
            profile: sba_core::PROFILE_VERSION.into(),
            family: sba_core::FAMILY.into(),
            name: "mock-a".into(),
            network: Network::Regtest,
            activation_height: ACTIVATION,
            const_salt: Deployment::derive_const_salt("mock-a"),
            transfer_k: sba_circuit::K,
            transfer_vk_id: params.vk_id(),
            window_w: 5,
            k_min: 1,
            anchor_depth: 3,
            boundary: Some(DevBoundary {
                vault_script_hex: hex::encode(vault_script().as_bytes()),
                operator_address: None,
            }),
            carrier: CarrierMode::OpReturn,
        };
        World {
            deployment,
            params,
            alice: WalletKeys::from_seed(&Seed([1u8; 32])),
            bob: WalletKeys::from_seed(&Seed([2u8; 32])),
            rng: ChaCha20Rng::from_seed([7u8; 32]),
        }
    }

    fn indexer(&self) -> Indexer {
        Indexer::new(
            self.deployment.clone(),
            self.deployment.verifier().unwrap(),
            ReplayState::new(),
        )
    }

    fn mint_tx(
        &mut self,
        to: &sba_core::address::PaymentAddress,
        value: u64,
    ) -> (Transaction, MintEnvelope) {
        let env = MintEnvelope {
            note: NotePlaintext {
                value,
                d: to.d,
                rseed: Fp::random(&mut self.rng),
            },
            pk_d: to.pk_d,
        };
        let tx = tx_with(vec![
            carrier_output(&env.to_bytes()),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: vault_script(),
            },
        ]);
        (tx, env)
    }

    /// Alice spends `input` (or a dummy) to `outputs`, anchored at `h_anchor`.
    fn transfer(
        &mut self,
        idx: &Indexer,
        h_anchor: u32,
        input: Option<(NotePlaintext, Fp, u64, u64)>, // note, h_body_create, j, pos
        outputs: [(sba_core::address::PaymentAddress, u64); 2],
    ) -> TransferEnvelope {
        let size = idx.state.size_at(h_anchor).expect("anchor replayed");
        let r_anchor = idx.root_at(h_anchor).unwrap();
        let (_, a_dummy) = self.alice.ivk.find_address(5);
        let in0 = match input {
            Some((note, hb, j, pos)) => {
                let path = idx.state.tree.path_at(pos, size).unwrap();
                InputWitness {
                    note,
                    h_body_create: hb,
                    output_index: j,
                    pos,
                    siblings: path.siblings,
                }
            }
            None => InputWitness::dummy(a_dummy.d, Fp::random(&mut self.rng)),
        };
        let in1 = InputWitness::dummy(a_dummy.d, Fp::random(&mut self.rng));
        let outs = outputs.map(|(addr, v)| OutputWitness {
            note: NotePlaintext {
                value: v,
                d: addr.d,
                rseed: Fp::random(&mut self.rng),
            },
            pk_d: addr.pk_d,
        });
        let (e0, c0) = encrypt_note(&outs[0].note, &outs[0].pk_d).unwrap();
        let (e1, c1) = encrypt_note(&outs[1].note, &outs[1].pk_d).unwrap();
        let digest = binding_digest(&[e0, e1], &[c0, c1]);
        let ct_out = encrypt_recovery(
            &self.alice.ovk,
            &digest,
            &[
                RecoveryEntry {
                    pk_d: outs[0].pk_d,
                    sk_eph: outs[0].note.sk_eph(),
                },
                RecoveryEntry {
                    pk_d: outs[1].pk_d,
                    sk_eph: outs[1].note.sk_eph(),
                },
            ],
        );
        let nullifiers = [
            nullifier(&self.alice.sk_nf, &in0.note.rho(), in0.pos),
            nullifier(&self.alice.sk_nf, &in1.note.rho(), in1.pos),
        ];
        let body = TransferBody {
            h_anchor,
            nullifiers,
            pk_eph: [e0, e1],
            ct_note: [c0, c1],
            ct_out,
        };
        let st = TransferStatement {
            const_salt: self.deployment.const_salt_fp(),
            r_anchor,
            nullifiers,
            pk_eph: [e0, e1],
            ct_note: [c0, c1],
            h_body: body.h_body(&self.deployment.const_salt),
        };
        let w = TransferWitness {
            sk_spend: self.alice.sk_spend,
            inputs: [in0, in1],
            outputs: outs,
        };
        let proof = self.params.prove(&st, &w, &mut self.rng).unwrap();
        TransferEnvelope { body, proof }
    }
}

#[test]
fn mint_spend_reject_reorg_and_persist() {
    let mut w = World::new();
    let (_, alice0) = w.alice.ivk.find_address(0);
    let (_, bob0) = w.bob.ivk.find_address(0);
    let mut chain = MockChain::new(ACTIVATION);
    let mut idx = w.indexer();

    // block 1000: a mint of 1000 to alice
    let (mint_tx, mint_env) = w.mint_tx(&alice0, 1000);
    chain.push_block(vec![mint_tx]);
    // block 1001: a mint whose vault output is wrong (rejected)
    let (mut bad_mint, _) = w.mint_tx(&alice0, 500);
    bad_mint.output[1].value = Amount::from_sat(499);
    chain.push_block(vec![bad_mint]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.blocks, r.accepted, r.rejected), (2, 1, 1));
    assert_eq!(idx.state.tree.size(), 1);
    assert!(idx.state.rejections[0].reason.contains("vault"));
    assert_eq!(idx.root_at(ACTIVATION - 1), Some(EMPTY_ROOTS[DEPTH]));
    // alice finds her note
    let ev = &idx.state.events[0];
    let (pk_eph, ct) = &ev.outputs[0];
    let pt = decrypt_as_recipient(&w.alice.ivk.sk_view, pk_eph, ct).unwrap();
    assert_eq!(pt, mint_env.note);
    let mint_hb = ev.h_body;

    // block 1002: alice pays bob 700 with change 300, anchored at 1001
    let env = w.transfer(
        &idx,
        1001,
        Some((pt, mint_hb, 0, 0)),
        [(bob0, 700), (alice0, 300)],
    );
    assert_eq!(env.proof.len(), PROOF_LEN);
    let bytes = env.to_bytes();
    assert!(idx.check_transfer(&bytes, 1002).unwrap().is_some());
    // a tampered proof is refused at step 6 (before the block, so that
    // step 5 does not fire first)
    let mut tampered = env.clone();
    tampered.proof[200] ^= 1;
    assert_eq!(
        idx.check_transfer(&tampered.to_bytes(), 1002),
        Err(RejectReason::ProofInvalid)
    );
    // the same envelope again in the block: spent nullifier
    chain.push_block(vec![
        tx_with(vec![carrier_output(&bytes)]),
        tx_with(vec![carrier_output(&bytes)]),
    ]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (1, 1));
    assert_eq!(idx.state.tree.size(), 3);
    assert!(idx.state.rejections[1].reason.contains("spent"));
    let ev = &idx.state.events[1];
    let got = decrypt_as_recipient(&w.bob.ivk.sk_view, &ev.outputs[0].0, &ev.outputs[0].1).unwrap();
    assert_eq!(got.value, 700);

    // rejections: spent, anchor out of window, unknown anchor, bad parse
    assert_eq!(
        idx.check_transfer(&bytes, 1003),
        Err(RejectReason::SpentNullifier)
    );
    let stale = w.transfer(&idx, 1000, None, [(bob0, 0), (bob0, 0)]);
    assert!(matches!(
        idx.check_transfer(&stale.to_bytes(), 1010),
        Err(RejectReason::AnchorOutOfWindow { .. })
    ));
    let mut future = env.clone();
    future.body.h_anchor = 5000;
    assert!(matches!(
        idx.check_transfer(&future.to_bytes(), 5001),
        Err(RejectReason::AnchorUnknown(5000))
    ));
    let mut garbage = bytes.clone();
    garbage[3] = 1;
    assert!(matches!(
        idx.check_transfer(&garbage, 1003),
        Err(RejectReason::Parse(_))
    ));

    // determinism: a fresh indexer replays to the same state
    let mut again = w.indexer();
    again.sync(&chain).unwrap();
    assert_eq!(again.state, idx.state);

    // persistence
    let json = idx.state.to_json();
    assert_eq!(ReplayState::from_json(&json).unwrap(), idx.state);

    // reorganisation: block 1002 is replaced by an empty one
    chain.reorg_to(1001);
    chain.push_block(vec![]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(r.rolled_back_to, Some(1001));
    assert_eq!(idx.state.tree.size(), 1);
    assert!(idx.state.nullifiers.is_empty());
    assert_eq!(idx.state.events.len(), 1);
    // the orphaned transfer is valid again on the new branch
    assert!(idx.check_transfer(&bytes, 1003).unwrap().is_some());
}

/// A block's transfer proofs are verified as one batch (`REPLAY-PROOF-A.md`
/// §2); when the batch fails the block is replayed sequentially, so the
/// outcome is the normative one: the bad proof alone is rejected, with its
/// reason, and the good transfers around it stand in order.
#[test]
fn a_block_with_a_bad_proof_is_replayed_sequentially() {
    let mut w = World::new();
    let (_, alice0) = w.alice.ivk.find_address(0);
    let (_, bob0) = w.bob.ivk.find_address(0);
    let mut chain = MockChain::new(ACTIVATION);
    let mut idx = w.indexer();

    // block 1000: two mints to alice (positions 0 and 1); 1001: empty
    let (m0, _) = w.mint_tx(&alice0, 1000);
    let (m1, _) = w.mint_tx(&alice0, 500);
    chain.push_block(vec![m0, m1]);
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    let notes: Vec<(NotePlaintext, Fp)> = idx.state.events[..2]
        .iter()
        .map(|ev| {
            let (pk_eph, ct) = &ev.outputs[0];
            (
                decrypt_as_recipient(&w.alice.ivk.sk_view, pk_eph, ct).unwrap(),
                ev.h_body,
            )
        })
        .collect();

    // block 1002: a valid spend of note 0, a spend of note 1 with a tampered
    // proof, and a valid dummy-only transfer, all anchored at 1001
    let a = w.transfer(
        &idx,
        1001,
        Some((notes[0].0, notes[0].1, 0, 0)),
        [(bob0, 700), (alice0, 300)],
    );
    let mut b = w.transfer(
        &idx,
        1001,
        Some((notes[1].0, notes[1].1, 0, 1)),
        [(bob0, 500), (alice0, 0)],
    );
    b.proof[1234] ^= 0x80;
    let c = w.transfer(&idx, 1001, None, [(bob0, 0), (bob0, 0)]);
    chain.push_block(vec![
        tx_with(vec![carrier_output(&a.to_bytes())]),
        tx_with(vec![carrier_output(&b.to_bytes())]),
        tx_with(vec![carrier_output(&c.to_bytes())]),
    ]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (2, 1));
    assert_eq!(idx.state.tree.size(), 2 + 4);
    // the mock chain's coinbase is tx 0: the carriers are 1, 2, 3
    assert_eq!(idx.state.rejections.len(), 1);
    assert_eq!(idx.state.rejections[0].tx_index, 2);
    assert!(
        idx.state.rejections[0].reason.contains("proof"),
        "{}",
        idx.state.rejections[0].reason
    );
    assert_eq!(idx.state.events[2].tx_index, 1);
    assert_eq!(idx.state.events[3].tx_index, 3);
    // note 1 is still unspent after the undo: the same spend with a good
    // proof is accepted in the next block, together with another valid one
    let b_good = w.transfer(
        &idx,
        1002,
        Some((notes[1].0, notes[1].1, 0, 1)),
        [(bob0, 500), (alice0, 0)],
    );
    let d = w.transfer(&idx, 1002, None, [(bob0, 0), (bob0, 0)]);
    chain.push_block(vec![
        tx_with(vec![carrier_output(&b_good.to_bytes())]),
        tx_with(vec![carrier_output(&d.to_bytes())]),
    ]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (2, 0));
    assert_eq!(idx.state.tree.size(), 6 + 4);
    // a fresh replay of the same chain lands in the same state
    let mut fresh = w.indexer();
    fresh.sync(&chain).unwrap();
    assert_eq!(fresh.state.to_json(), idx.state.to_json());
}

/// A transfer the optimistic pass accepted but did not put in the batch
/// must not stand on the batch's verdict: the completeness guard sends the
/// block to the sequential path, where its (bad) proof is checked.
#[test]
fn a_transfer_missing_from_the_batch_is_not_accepted_unchecked() {
    let mut w = World::new();
    let (_, alice0) = w.alice.ivk.find_address(0);
    let (_, bob0) = w.bob.ivk.find_address(0);
    let mut chain = MockChain::new(ACTIVATION);
    let mut idx = w.indexer();
    let (m0, _) = w.mint_tx(&alice0, 1000);
    chain.push_block(vec![m0]);
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    // a tampered dummy-only transfer first, a valid one second
    let mut bad = w.transfer(&idx, 1001, None, [(bob0, 0), (bob0, 0)]);
    bad.proof[2000] ^= 1;
    let good = w.transfer(&idx, 1001, None, [(bob0, 0), (bob0, 0)]);
    chain.push_block(vec![
        tx_with(vec![carrier_output(&bad.to_bytes())]),
        tx_with(vec![carrier_output(&good.to_bytes())]),
    ]);
    idx.drop_first_from_batch = true;
    let r = idx.sync(&chain).unwrap();
    assert!(!idx.drop_first_from_batch, "the hook fired");
    assert_eq!((r.accepted, r.rejected), (1, 1));
    assert_eq!(idx.state.rejections.len(), 1);
    assert_eq!(idx.state.rejections[0].tx_index, 1);
    assert!(idx.state.rejections[0].reason.contains("proof"));
    assert_eq!(idx.state.events[1].tx_index, 2);
    // and with the batch complete, the same block gives the same outcome
    let mut fresh = w.indexer();
    fresh.sync(&chain).unwrap();
    assert_eq!(fresh.state.to_json(), idx.state.to_json());
}

/// The sequential fallback rejects every bad proof of a block, not only the
/// first one it meets.
#[test]
fn two_bad_proofs_in_one_block_are_both_rejected() {
    let mut w = World::new();
    let (_, alice0) = w.alice.ivk.find_address(0);
    let (_, bob0) = w.bob.ivk.find_address(0);
    let mut chain = MockChain::new(ACTIVATION);
    let mut idx = w.indexer();
    let (m0, _) = w.mint_tx(&alice0, 1000);
    chain.push_block(vec![m0]);
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    let mut bad1 = w.transfer(&idx, 1001, None, [(bob0, 0), (bob0, 0)]);
    bad1.proof[100] ^= 1;
    let good = w.transfer(&idx, 1001, None, [(bob0, 0), (bob0, 0)]);
    let mut bad2 = w.transfer(&idx, 1001, None, [(bob0, 0), (bob0, 0)]);
    bad2.proof[4000] ^= 1;
    chain.push_block(vec![
        tx_with(vec![carrier_output(&bad1.to_bytes())]),
        tx_with(vec![carrier_output(&good.to_bytes())]),
        tx_with(vec![carrier_output(&bad2.to_bytes())]),
    ]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (1, 2));
    let rejected: Vec<u32> = idx.state.rejections.iter().map(|r| r.tx_index).collect();
    assert_eq!(rejected, vec![1, 3]);
    assert!(
        idx.state
            .rejections
            .iter()
            .all(|r| r.reason.contains("proof"))
    );
    assert_eq!(idx.state.events[1].tx_index, 2);
    assert_eq!(idx.state.tree.size(), 1 + 2);
}

/// Every replayed block leaves a batch witness (`REPLAY-PROOF-A.md` §3.7)
/// that the relation accepts natively, and the witnesses chain through
/// the state openings: a block's `s_next` is the next block's `s_prev`,
/// the last one opens to the state as it stands; a reorganisation drops
/// them with their blocks.
#[test]
fn batch_witnesses_chain_through_the_openings() {
    use sba_core::batch::batch_digest;
    let mut w = World::new();
    let (_, alice0) = w.alice.ivk.find_address(0);
    let (_, bob0) = w.bob.ivk.find_address(0);
    let mut chain = MockChain::new(ACTIVATION);
    let mut idx = w.indexer();
    let (mint_tx, _) = w.mint_tx(&alice0, 1000);
    chain.push_block(vec![mint_tx]);
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    let ev = &idx.state.events[0];
    let (pk_eph, ct) = &ev.outputs[0];
    let pt = decrypt_as_recipient(&w.alice.ivk.sk_view, pk_eph, ct).unwrap();
    let mint_hb = ev.h_body;
    let env = w.transfer(
        &idx,
        1001,
        Some((pt, mint_hb, 0, 0)),
        [(bob0, 700), (alice0, 300)],
    );
    let bytes = env.to_bytes();
    let (mint2, _) = w.mint_tx(&alice0, 5);
    chain.push_block(vec![
        tx_with(vec![carrier_output(&bytes)]),
        tx_with(vec![carrier_output(&bytes)]),
        mint2,
    ]);
    idx.sync(&chain).unwrap();
    assert_eq!(idx.state.batches.len(), 3);
    let params = idx.batch_params();
    let mut prev_next = idx.state.batches[0].prev.digest();
    let mut last = None;
    for (i, wit) in idx.state.batches.iter().enumerate() {
        let st = wit
            .check(&params)
            .unwrap_or_else(|| panic!("block {i} witness refused"));
        assert_eq!(st.s_prev, prev_next, "block {i} chains");
        let slots: Vec<_> = wit
            .slots
            .iter()
            .map(|s| s.as_ref().map(|s| s.statement))
            .collect();
        assert_eq!(st.d, batch_digest(&slots));
        prev_next = st.s_next;
        last = Some(st);
    }
    // block 1002: the transfer and the mint, the duplicate rejected
    let b = &idx.state.batches[2];
    assert_eq!(b.slots.len(), 2);
    assert!(!b.slots[0].as_ref().unwrap().statement.mint);
    assert!(b.slots[1].as_ref().unwrap().statement.mint);
    assert_eq!(
        last.unwrap().s_next,
        idx.state.opening(idx.next_height()).digest()
    );
    assert_eq!(idx.state.nf_tree.len(), 2);
    assert_eq!(idx.state.h_tree.size(), 4);
    // a tampered witness is refused
    let mut bad = b.clone();
    bad.slots[0].as_mut().unwrap().statement.nullifiers[0] += Fp::one();
    assert!(bad.check(&params).is_none());
    let mut bad = b.clone();
    bad.slots[0].as_mut().unwrap().statement.h_anchor = 0;
    assert!(bad.check(&params).is_none(), "window");
    // persistence keeps the trees; a reorganisation drops the witnesses
    let again = ReplayState::from_json(&idx.state.to_json()).unwrap();
    assert_eq!(again.nf_tree.root(), idx.state.nf_tree.root());
    assert_eq!(again.h_tree.root(), idx.state.h_tree.root());
    chain.reorg_to(1001);
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    assert_eq!(idx.state.batches.len(), 3);
    assert_eq!(idx.state.nf_tree.len(), 0);
    assert_eq!(idx.state.h_tree.size(), 4);
    assert_eq!(
        idx.state.batches[2].check(&params).unwrap().s_next,
        idx.state.opening(idx.next_height()).digest()
    );
}
