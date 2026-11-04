//! A real transfer of variant A: wallet keys, notes and a tree from
//! `sba-core`, proven and verified with `sba-circuit`; tampered statements
//! are refused; the proof has the profile's length.

use ff::Field;
use halo2_proofs::dev::MockProver;
use rand::SeedableRng;
use rand::rngs::StdRng;

use sba_circuit::{
    InputWitness, K, OutputWitness, TransferCircuit, TransferParams, TransferStatement,
    TransferWitness,
};
use sba_core::envelope::{PROOF_LEN, TransferBody, TransferEnvelope};
use sba_core::keys::{Seed, WalletKeys};
use sba_core::note::{NotePlaintext, encrypt_note, note_leaf, nullifier};
use sba_core::recovery::{RecoveryEntry, binding_digest, encrypt_recovery};
use sba_core::tree::NoteTree;
use sba_primitives::Fp;

fn sample() -> (TransferStatement, TransferWitness) {
    let mut rng = StdRng::seed_from_u64(42);
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let bob = WalletKeys::from_seed(&Seed([2u8; 32]));
    let (_, a0) = alice.ivk.find_address(0);
    let (_, a1) = alice.ivk.find_address(1);
    let (_, b0) = bob.ivk.find_address(0);
    let const_salt = Fp::random(&mut rng);

    // alice's note was created as output 1 of an earlier envelope with
    // h_body = hb0, and sits at position 5 of the tree
    let hb0 = Fp::random(&mut rng);
    let note_in = NotePlaintext {
        value: 1000,
        d: a0.d,
        rseed: Fp::random(&mut rng),
    };
    let (pe, ct) = encrypt_note(&note_in, &a0.pk_d).unwrap();
    let leaf = note_leaf(&const_salt, &hb0, 1, &pe, &ct);
    let mut tree = NoteTree::new();
    for _ in 0..5 {
        tree.append(Fp::random(&mut rng));
    }
    let pos = tree.append(leaf);
    tree.append(Fp::random(&mut rng));
    let path = tree.path(pos).unwrap();
    let r_anchor = tree.root();

    let dummy = InputWitness::dummy(a1.d, Fp::random(&mut rng));
    let inputs = [
        InputWitness {
            note: note_in,
            h_body_create: hb0,
            output_index: 1,
            pos,
            siblings: path.siblings,
        },
        dummy,
    ];
    let outs = [
        OutputWitness {
            note: NotePlaintext {
                value: 700,
                d: b0.d,
                rseed: Fp::random(&mut rng),
            },
            pk_d: b0.pk_d,
        },
        OutputWitness {
            note: NotePlaintext {
                value: 300,
                d: a1.d,
                rseed: Fp::random(&mut rng),
            },
            pk_d: a1.pk_d,
        },
    ];
    let (e0, c0) = encrypt_note(&outs[0].note, &outs[0].pk_d).unwrap();
    let (e1, c1) = encrypt_note(&outs[1].note, &outs[1].pk_d).unwrap();
    let digest = binding_digest(&[e0, e1], &[c0, c1]);
    let ct_out = encrypt_recovery(
        &alice.ovk,
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
        nullifier(&alice.sk_nf, &inputs[0].note.rho(), inputs[0].pos),
        nullifier(&alice.sk_nf, &inputs[1].note.rho(), 0),
    ];
    let body = TransferBody {
        h_anchor: 100,
        nullifiers,
        pk_eph: [e0, e1],
        ct_note: [c0, c1],
        ct_out,
    };
    let salt_bytes = sba_primitives::encoding::fp_to_bytes(&const_salt);
    let st = TransferStatement {
        const_salt,
        r_anchor,
        nullifiers,
        pk_eph: [e0, e1],
        ct_note: [c0, c1],
        h_body: body.h_body(&salt_bytes),
    };
    let w = TransferWitness {
        sk_spend: alice.sk_spend,
        inputs,
        outputs: outs,
    };
    (st, w)
}

#[test]
fn real_transfer_proves_and_verifies() {
    let (st, w) = sample();
    let circuit = TransferCircuit {
        statement: Some(st.clone()),
        witness: Some(w.clone()),
        negate_g_d: false,
    };
    MockProver::run(K, &circuit, vec![st.to_field_elements()])
        .unwrap()
        .verify()
        .unwrap();

    let params = TransferParams::build().unwrap();
    let verifier = params.verifier();
    assert_eq!(params.vk_id(), verifier.vk_id());
    let mut rng = StdRng::seed_from_u64(7);
    let proof = params.prove(&st, &w, &mut rng).unwrap();
    assert_eq!(proof.len(), PROOF_LEN);
    assert!(verifier.verify(&st, &proof));
    // the envelope carries the proof at the profile's length
    let env = TransferEnvelope {
        body: TransferBody {
            h_anchor: 100,
            nullifiers: st.nullifiers,
            pk_eph: st.pk_eph,
            ct_note: st.ct_note,
            ct_out: [0u8; sba_core::recovery::CT_OUT_LEN],
        },
        proof: proof.clone(),
    };
    assert_eq!(TransferEnvelope::parse(&env.to_bytes()).unwrap(), env);

    // tampering
    let mut bad = st.clone();
    bad.nullifiers[0] += Fp::one();
    assert!(!verifier.verify(&bad, &proof));
    let mut bad = st.clone();
    bad.r_anchor += Fp::one();
    assert!(!verifier.verify(&bad, &proof));
    let mut bad = st.clone();
    bad.h_body += Fp::one();
    assert!(!verifier.verify(&bad, &proof));
    let mut bad_proof = proof.clone();
    bad_proof[100] ^= 1;
    assert!(!verifier.verify(&st, &bad_proof));
    assert!(!verifier.verify(&st, &proof[..PROOF_LEN - 1]));
    // the second verifier instance derives the same key
    let v2 = sba_circuit::TransferVerifier::build().unwrap();
    assert_eq!(v2.vk_id(), verifier.vk_id());
    assert!(v2.verify(&st, &proof));
}

#[test]
fn unsatisfiable_witnesses_are_refused_by_the_mock_prover() {
    let (st, mut w) = sample();
    // a wrong position: the Merkle root check fails (the input is real)
    w.inputs[0].pos += 1;
    let circuit = TransferCircuit {
        statement: Some(st.clone()),
        witness: Some(w),
        negate_g_d: false,
    };
    assert!(
        MockProver::run(K, &circuit, vec![st.to_field_elements()])
            .unwrap()
            .verify()
            .is_err()
    );
}

#[test]
fn batch_verification_agrees_with_one_by_one() {
    let (st, w) = sample();
    let params = TransferParams::build().unwrap();
    let verifier = params.verifier();
    let mut rng = StdRng::seed_from_u64(9);
    let p1 = params.prove(&st, &w, &mut rng).unwrap();
    let p2 = params.prove(&st, &w, &mut rng).unwrap();
    assert_ne!(p1, p2, "proofs are randomised");
    assert!(verifier.verify_batch(&[]));
    assert!(verifier.verify_batch(&[(st.clone(), p1.clone())]));
    assert!(verifier.verify_batch(&[(st.clone(), p1.clone()), (st.clone(), p2.clone())]));
    let mut bad = p2.clone();
    bad[300] ^= 1;
    assert!(!verifier.verify_batch(&[(st.clone(), p1.clone()), (st.clone(), bad)]));
    let mut wrong_st = st.clone();
    wrong_st.h_body += Fp::ONE;
    assert!(!verifier.verify_batch(&[(st.clone(), p1.clone()), (wrong_st, p2.clone())]));
    assert!(!verifier.verify_batch(&[(st.clone(), p1), (st, p2[..PROOF_LEN - 1].to_vec())]));
}

/// The odd root of `x³ + 5` as `G_d` satisfies every other constraint (the
/// discrete logarithms are the same up to sign) and must be refused by the
/// parity rule alone; with the former bound `h < 2^254` it was accepted
/// (review finding, 3 November 2026).
#[test]
fn the_odd_root_of_g_d_is_refused_by_the_mock_prover() {
    let (st, w) = sample();
    let circuit = TransferCircuit {
        statement: Some(st.clone()),
        witness: Some(w),
        negate_g_d: true,
    };
    let err = MockProver::run(K, &circuit, vec![st.to_field_elements()])
        .unwrap()
        .verify()
        .unwrap_err();
    let text = format!("{err:?}");
    assert!(
        text.contains("2h") || text.contains("rc") || text.contains("Lookup"),
        "{text}"
    );
}

/// What a verifier of this circuit reads and squeezes (`REPLAY-PROOF-A.md`
/// §3.4): `cargo test -p sba-circuit --release --test transfer print_verifier_shape -- --ignored --nocapture`.
#[test]
#[ignore]
fn print_verifier_shape() {
    let params = TransferParams::build().unwrap();
    println!("k = {K}, rows = {}", 1u64 << K);
    println!("{:#?}", params.vk().pinned());
    println!(
        "proof bytes: {} = {} elements of 32 bytes",
        PROOF_LEN,
        PROOF_LEN / 32
    );
}
