//! End-to-end: build notes natively, prove a 2-in/2-out transfer, verify,
//! and check that every public input and every relation block is enforced.

use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha20Rng;

use sb_circuit::*;
use sb_core::envelope::{TransferBody, bytes_to_fr_253};
use sb_core::keys::{Seed, WalletKeys};
use sb_core::note::{NotePlaintext, encrypt_note, note_leaf, nullifier};
use sb_core::recovery::{RecoveryEntry, binding_digest, encrypt_recovery};
use sb_core::tree::NoteTree;
use sb_primitives::Fr;

struct Fixture {
    alice: WalletKeys,
    tree: NoteTree,
    const_salt: [u8; 32],
    statement: TransferStatement,
    witness: TransferWitness,
    body: TransferBody,
}

/// Alice owns two notes (600 and 400); she pays Bob 700 and keeps 300.
fn fixture() -> Fixture {
    let mut rng = StdRng::seed_from_u64(42);
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let bob = WalletKeys::from_seed(&Seed([2u8; 32]));
    let (_, alice_addr) = alice.ivk.find_address(0);
    let (_, bob_addr) = bob.ivk.find_address(0);
    let const_salt = [9u8; 32];
    let salt_fe = bytes_to_fr_253(&const_salt);

    // Two earlier envelopes created Alice's notes (we only need their h_body).
    let mut tree = NoteTree::new();
    let mut inputs = Vec::new();
    for (value, h_body_create, j) in [
        (600u64, Fr::from(1001u64), 0u64),
        (400, Fr::from(1002u64), 1),
    ] {
        let note = NotePlaintext {
            value,
            d: alice_addr.d,
            rseed: Fr::rand(&mut rng),
        };
        let (pk_eph, ct) = encrypt_note(&note, &alice_addr.pk_d).unwrap();
        let leaf = note_leaf(&salt_fe, &h_body_create, j, &pk_eph, &ct);
        // a few unrelated leaves in between
        tree.append(Fr::rand(&mut rng));
        let pos = tree.append(leaf);
        inputs.push((note, h_body_create, j, pos));
    }
    tree.append(Fr::rand(&mut rng));
    let r_anchor = tree.root();

    let input_witnesses: Vec<InputWitness> = inputs
        .iter()
        .map(|(note, h_body_create, j, pos)| InputWitness {
            note: *note,
            h_body_create: *h_body_create,
            output_index: *j,
            pos: *pos,
            siblings: tree.path(*pos).unwrap().siblings,
        })
        .collect();

    let outputs = [
        OutputWitness {
            note: NotePlaintext {
                value: 700,
                d: bob_addr.d,
                rseed: Fr::rand(&mut rng),
            },
            pk_d: bob_addr.pk_d,
        },
        OutputWitness {
            note: NotePlaintext {
                value: 300,
                d: alice_addr.d,
                rseed: Fr::rand(&mut rng),
            },
            pk_d: alice_addr.pk_d,
        },
    ];
    let mut pk_eph = Vec::new();
    let mut ct_note = Vec::new();
    for o in &outputs {
        let (p, c) = encrypt_note(&o.note, &o.pk_d).unwrap();
        pk_eph.push(p);
        ct_note.push(c);
    }
    let pk_eph: [_; 2] = pk_eph.try_into().unwrap();
    let ct_note: [_; 2] = ct_note.try_into().unwrap();
    let nullifiers = [
        nullifier(&alice.sk_nf, &inputs[0].0.rho(), inputs[0].3),
        nullifier(&alice.sk_nf, &inputs[1].0.rho(), inputs[1].3),
    ];
    let digest = binding_digest(&pk_eph, &ct_note);
    let entries = [
        RecoveryEntry {
            pk_d: outputs[0].pk_d,
            sk_eph: outputs[0].note.sk_eph(),
        },
        RecoveryEntry {
            pk_d: outputs[1].pk_d,
            sk_eph: outputs[1].note.sk_eph(),
        },
    ];
    let ct_out = encrypt_recovery(&alice.ovk, &digest, &entries);
    let body = TransferBody {
        h_anchor: 123,
        nullifiers,
        pk_eph,
        ct_note,
        ct_out,
    };
    let h_body = body.h_body(&const_salt);

    let statement = TransferStatement {
        const_salt: salt_fe,
        r_anchor,
        nullifiers,
        pk_eph,
        ct_note,
        h_body,
    };
    let witness = TransferWitness {
        sk_spend: alice.sk_spend,
        inputs: [input_witnesses[0].clone(), input_witnesses[1].clone()],
        outputs,
    };
    Fixture {
        alice,
        tree,
        const_salt,
        statement,
        witness,
        body,
    }
}

fn satisfied(statement: &TransferStatement, witness: &TransferWitness) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = TransferCircuit {
        statement: Some(statement.clone()),
        witness: Some(witness.clone()),
    };
    match circuit.generate_constraints(cs.clone()) {
        Ok(()) => cs.is_satisfied().unwrap(),
        Err(_) => false,
    }
}

#[test]
fn honest_transfer_satisfies_the_relation() {
    let f = fixture();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = TransferCircuit {
        statement: Some(f.statement.clone()),
        witness: Some(f.witness.clone()),
    };
    circuit.generate_constraints(cs.clone()).unwrap();
    println!("constraints: {}", cs.num_constraints());
    println!("instance variables: {}", cs.num_instance_variables());
    println!("witness variables: {}", cs.num_witness_variables());
    assert_eq!(cs.num_instance_variables(), NUM_PUBLIC_INPUTS + 1);
    assert!(
        cs.is_satisfied().unwrap(),
        "unsatisfied at {:?}",
        cs.which_is_unsatisfied().unwrap()
    );
}

#[test]
fn every_block_is_enforced() {
    let f = fixture();
    assert!(satisfied(&f.statement, &f.witness));

    // wrong spend authority
    let other = WalletKeys::from_seed(&Seed([3u8; 32]));
    let mut w = f.witness.clone();
    w.sk_spend = other.sk_spend;
    assert!(
        !satisfied(&f.statement, &w),
        "block 3: foreign sk_spend accepted"
    );

    // value imbalance
    let mut w = f.witness.clone();
    w.outputs[0].note.value += 1;
    let mut s = f.statement.clone();
    let (p, c) = encrypt_note(&w.outputs[0].note, &w.outputs[0].pk_d).unwrap();
    s.pk_eph[0] = p;
    s.ct_note[0] = c;
    assert!(!satisfied(&s, &w), "block 7: imbalance accepted");

    // wrong nullifier
    let mut s = f.statement.clone();
    s.nullifiers[0] += Fr::from(1u64);
    assert!(
        !satisfied(&s, &f.witness),
        "block 4: wrong nullifier accepted"
    );

    // wrong position (nullifier bound to pos; path then fails too)
    let mut w = f.witness.clone();
    w.inputs[0].pos += 1;
    assert!(
        !satisfied(&f.statement, &w),
        "block 2/4: wrong pos accepted"
    );

    // wrong anchor
    let mut s = f.statement.clone();
    s.r_anchor += Fr::from(1u64);
    assert!(!satisfied(&s, &f.witness), "block 2: wrong anchor accepted");

    // output ciphertext not matching the note
    let mut s = f.statement.clone();
    s.ct_note[1].c0 += Fr::from(1u64);
    assert!(
        !satisfied(&s, &f.witness),
        "block 5: inconsistent ciphertext accepted"
    );

    // input value claimed larger than created
    let mut w = f.witness.clone();
    w.inputs[0].note.value += 100;
    w.outputs[1].note.value += 100;
    let mut s = f.statement.clone();
    let (p, c) = encrypt_note(&w.outputs[1].note, &w.outputs[1].pk_d).unwrap();
    s.pk_eph[1] = p;
    s.ct_note[1] = c;
    assert!(!satisfied(&s, &w), "block 1/2: forged input value accepted");

    // dummy input: zero value skips the membership check but still needs a nullifier
    let mut w = f.witness.clone();
    w.inputs[1] = InputWitness::dummy(f.witness.inputs[1].note.d, Fr::from(77u64));
    w.outputs[0].note.value = 300; // 600 = 300 + 300
    let mut s = f.statement.clone();
    let (p, c) = encrypt_note(&w.outputs[0].note, &w.outputs[0].pk_d).unwrap();
    s.pk_eph[0] = p;
    s.ct_note[0] = c;
    s.nullifiers[1] = nullifier(&f.alice.sk_nf, &w.inputs[1].note.rho(), 0);
    assert!(satisfied(&s, &w), "dummy input rejected");
    // ... but a non-zero value with a bogus path is rejected
    w.inputs[1].note.value = 1;
    w.outputs[0].note.value = 301;
    let (p, c) = encrypt_note(&w.outputs[0].note, &w.outputs[0].pk_d).unwrap();
    s.pk_eph[0] = p;
    s.ct_note[0] = c;
    assert!(!satisfied(&s, &w), "non-member input accepted");
}

#[test]
fn groth16_prove_verify_and_public_input_binding() {
    let f = fixture();
    let t = std::time::Instant::now();
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    println!("setup: {:?}", t.elapsed());
    let verifier = TransferVerifier::from_vk_bytes(&vk_to_bytes(params.vk())).unwrap();
    println!("vk sha256: {}", hex::encode(vk_sha256(params.vk())));

    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let t = std::time::Instant::now();
    let proof = params.prove(&f.statement, &f.witness, &mut rng).unwrap();
    println!("prove: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    assert!(verifier.verify(&f.statement, &proof));
    println!("verify: {:?}", t.elapsed());

    // Every public input must be bound by the proof.
    let base = f.statement.to_field_elements();
    for i in 0..base.len() {
        let mut s = f.statement.clone();
        let bump = Fr::from(1u64);
        match i {
            0 => s.const_salt += bump,
            1 => s.r_anchor += bump,
            2 | 3 => continue, // N, M are constants of the statement encoding
            4 => s.nullifiers[0] += bump,
            5 => s.nullifiers[1] += bump,
            6 => s.pk_eph[0].x += bump,
            7 => s.pk_eph[0].y += bump,
            8 => s.pk_eph[1].x += bump,
            9 => s.pk_eph[1].y += bump,
            10 => s.ct_note[0].c0 += bump,
            11 => s.ct_note[0].c1 += bump,
            12 => s.ct_note[0].tag += bump,
            13 => s.ct_note[1].c0 += bump,
            14 => s.ct_note[1].c1 += bump,
            15 => s.ct_note[1].tag += bump,
            16 => s.h_body += bump,
            _ => unreachable!(),
        }
        assert!(
            !verifier.verify(&s, &proof),
            "public input {i} is not bound"
        );
    }
    // A garbage proof fails to decode or verify.
    assert!(!verifier.verify(&f.statement, &[0xffu8; 192]));
    // The published body recomputes the bound h_body.
    assert_eq!(f.body.h_body(&f.const_salt), f.statement.h_body);
    assert_eq!(f.tree.root(), f.statement.r_anchor);
}

#[test]
fn proving_key_round_trips_through_bytes() {
    let f = fixture();
    let params = TransferParams::insecure_setup(&[1u8; 32]).unwrap();
    let bytes = params.pk_to_bytes().unwrap();
    let reloaded = TransferParams::from_pk_bytes(&bytes).unwrap();
    assert_eq!(vk_sha256(reloaded.vk()), vk_sha256(params.vk()));
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let proof = reloaded.prove(&f.statement, &f.witness, &mut rng).unwrap();
    let verifier = TransferVerifier::new(params.vk().clone());
    assert!(verifier.verify(&f.statement, &proof));
    assert!(TransferParams::from_pk_bytes(&bytes[..100]).is_err());
    assert!(TransferVerifier::from_vk_bytes(&[0u8; 10]).is_err());
}
