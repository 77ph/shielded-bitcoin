//! The swap extension end to end at the circuit level (`docs/SWAP.md` §7):
//! a locked note claimed by its owner with the preimage, refunded by its
//! creator after the refund height, every block E1–E7 rejecting its
//! violation, and the plain path equal to the base relation.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha20Rng;

use sb_circuit::*;
use sb_core::keys::{Seed, WalletKeys};
use sb_core::lock::{LockOpening, Secret};
use sb_core::note::{NotePlaintext, encrypt_note, note_leaf_aux, nullifier, nullifier_locked};
use sb_core::tree::NoteTree;
use sb_primitives::Fr;
use sb_primitives::encoding::fr_from_bytes;

const T_REFUND: u32 = 100;

/// X (creator, refund party) locked 500 to Y (owner); Y also owns a plain
/// note of 300. The tree holds both.
struct Fixture {
    x: WalletKeys,
    y: WalletKeys,
    tree: NoteTree,
    salt: Fr,
    secret: Secret,
    opening: LockOpening,
    h_aux: Fr,
    locked: (NotePlaintext, Fr, u64, u64), // note, h_body_create, j, pos
    plain: (NotePlaintext, Fr, u64, u64),
}

fn fixture() -> Fixture {
    let mut rng = StdRng::seed_from_u64(7);
    let x = WalletKeys::from_seed(&Seed([3u8; 32]));
    let y = WalletKeys::from_seed(&Seed([4u8; 32]));
    let (_, x_addr) = x.ivk.find_address(0);
    let (_, y_addr) = y.ivk.find_address(0);
    let salt = Fr::from(77u64);
    let secret = Secret::random(&mut rng);
    let opening = LockOpening {
        hash: secret.hash(),
        pk_refund: x_addr.pk_d,
        t_refund: T_REFUND,
    };
    let h_aux = opening.commitment();
    let mut tree = NoteTree::new();
    let locked_note = NotePlaintext {
        value: 500,
        d: y_addr.d,
        rseed: Fr::from(11u64),
    };
    let (pk_eph, ct) = encrypt_note(&locked_note, &y_addr.pk_d).unwrap();
    let h1 = Fr::from(2001u64);
    tree.append(Fr::from(5u64));
    let pos_locked = tree.append(note_leaf_aux(&salt, &h1, 0, &pk_eph, &ct, &h_aux));
    let plain_note = NotePlaintext {
        value: 300,
        d: y_addr.d,
        rseed: Fr::from(12u64),
    };
    let (pk_eph2, ct2) = encrypt_note(&plain_note, &y_addr.pk_d).unwrap();
    let h2 = Fr::from(2002u64);
    let pos_plain = tree.append(note_leaf_aux(
        &salt,
        &h2,
        1,
        &pk_eph2,
        &ct2,
        &Fr::from(0u64),
    ));
    tree.append(Fr::from(6u64));
    Fixture {
        x,
        y,
        tree,
        salt,
        secret,
        opening,
        h_aux,
        locked: (locked_note, h1, 0, pos_locked),
        plain: (plain_note, h2, 1, pos_plain),
    }
}

fn base_input(f: &Fixture, which: &(NotePlaintext, Fr, u64, u64)) -> InputWitness {
    InputWitness {
        note: which.0,
        h_body_create: which.1,
        output_index: which.2,
        pos: which.3,
        siblings: f.tree.path(which.3).unwrap().siblings,
    }
}

/// Outputs paying `total` to X's address (one note, one zero dummy).
fn outputs(
    f: &Fixture,
    total: u64,
) -> (
    [OutputWitness; 2],
    Vec<(sb_primitives::JubjubAffine, sb_core::note::NoteCiphertext)>,
) {
    let (_, x_addr) = f.x.ivk.find_address(0);
    let o0 = NotePlaintext {
        value: total,
        d: x_addr.d,
        rseed: Fr::from(21u64),
    };
    let o1 = NotePlaintext {
        value: 0,
        d: x_addr.d,
        rseed: Fr::from(22u64),
    };
    let c0 = encrypt_note(&o0, &x_addr.pk_d).unwrap();
    let c1 = encrypt_note(&o1, &x_addr.pk_d).unwrap();
    (
        [
            OutputWitness {
                note: o0,
                pk_d: x_addr.pk_d,
            },
            OutputWitness {
                note: o1,
                pk_d: x_addr.pk_d,
            },
        ],
        vec![c0, c1],
    )
}

fn statement(
    f: &Fixture,
    nullifiers: [Fr; 2],
    chans: &[(sb_primitives::JubjubAffine, sb_core::note::NoteCiphertext)],
    h_anchor: u32,
) -> SwapStatement {
    SwapStatement {
        base: TransferStatement {
            const_salt: f.salt,
            r_anchor: f.tree.root(),
            nullifiers,
            pk_eph: [chans[0].0, chans[1].0],
            ct_note: [chans[0].1, chans[1].1],
            h_body: Fr::from(4242u64),
        },
        h_anchor,
    }
}

/// Y claims the locked note with the preimage, together with its plain note.
fn claim_case(f: &Fixture, h_anchor: u32) -> (SwapStatement, SwapWitness) {
    let (_, y_addr) = f.y.ivk.find_address(0);
    let locked = SwapInputWitness {
        base: base_input(f, &f.locked),
        h_aux: f.h_aux,
        opening: f.opening,
        secret: f.secret,
        d_refund: y_addr.d,
        pk_owner: y_addr.pk_d,
        refund: false,
    };
    let plain = SwapInputWitness::plain(base_input(f, &f.plain), y_addr.pk_d, y_addr.d);
    let (outs, chans) = outputs(f, 800);
    let nfs = [
        nullifier_locked(&f.locked.0.rho(), f.locked.3),
        nullifier(&f.y.sk_nf, &f.plain.0.rho(), f.plain.3),
    ];
    (
        statement(f, nfs, &chans, h_anchor),
        SwapWitness {
            sk_spend: f.y.sk_spend,
            inputs: [locked, plain],
            outputs: outs,
        },
    )
}

/// X refunds the locked note after the refund height (second input dummy).
fn refund_case(f: &Fixture, h_anchor: u32) -> (SwapStatement, SwapWitness) {
    let (_, x_addr) = f.x.ivk.find_address(0);
    let (_, y_addr) = f.y.ivk.find_address(0);
    let locked = SwapInputWitness {
        base: base_input(f, &f.locked),
        h_aux: f.h_aux,
        opening: f.opening,
        secret: Secret([0u8; 32]),
        d_refund: x_addr.d,
        pk_owner: y_addr.pk_d,
        refund: true,
    };
    let dummy = SwapInputWitness::plain(
        InputWitness::dummy(x_addr.d, Fr::from(99u64)),
        x_addr.pk_d,
        x_addr.d,
    );
    let (outs, chans) = outputs(f, 500);
    let nfs = [
        nullifier_locked(&f.locked.0.rho(), f.locked.3),
        nullifier(&f.x.sk_nf, &dummy.base.note.rho(), 0),
    ];
    (
        statement(f, nfs, &chans, h_anchor),
        SwapWitness {
            sk_spend: f.x.sk_spend,
            inputs: [locked, dummy],
            outputs: outs,
        },
    )
}

fn satisfied(st: &SwapStatement, w: &SwapWitness) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    SwapCircuit {
        statement: Some(st.clone()),
        witness: Some(w.clone()),
    }
    .generate_constraints(cs.clone())
    .unwrap();
    cs.is_satisfied().unwrap()
}

#[test]
fn claim_and_refund_satisfy_the_relation() {
    let f = fixture();
    let (st, w) = claim_case(&f, 50);
    let cs = ConstraintSystem::<Fr>::new_ref();
    SwapCircuit {
        statement: Some(st.clone()),
        witness: Some(w.clone()),
    }
    .generate_constraints(cs.clone())
    .unwrap();
    println!("swap constraints: {}", cs.num_constraints());
    assert_eq!(cs.num_instance_variables(), NUM_SWAP_PUBLIC_INPUTS + 1);
    assert!(
        cs.is_satisfied().unwrap(),
        "{:?}",
        cs.which_is_unsatisfied()
    );
    assert!(
        satisfied(&claim_case(&f, 500).0, &claim_case(&f, 500).1),
        "a claim has no height condition"
    );
    let (st, w) = refund_case(&f, T_REFUND);
    assert!(satisfied(&st, &w), "refund at exactly t_refund");
    assert!(satisfied(
        &refund_case(&f, T_REFUND + 7).0,
        &refund_case(&f, T_REFUND + 7).1
    ));
    // both paths publish the same nullifier for the locked note
    assert_eq!(
        claim_case(&f, 50).0.base.nullifiers[0],
        st.base.nullifiers[0]
    );
}

#[test]
fn every_block_rejects_its_violation() {
    let f = fixture();
    let (_, x_addr) = f.x.ivk.find_address(0);
    // E6: refund below t_refund
    let (st, w) = refund_case(&f, T_REFUND - 1);
    assert!(!satisfied(&st, &w));
    // E5: a claim with a wrong preimage
    let (st, mut w) = claim_case(&f, 50);
    w.inputs[0].secret.0[0] ^= 1;
    assert!(!satisfied(&st, &w));
    // E6: a refund with the owner's key instead of the refund key
    let (st, mut w) = refund_case(&f, T_REFUND);
    w.sk_spend = f.y.sk_spend;
    let (_, y_addr) = f.y.ivk.find_address(0);
    w.inputs[0].d_refund = y_addr.d;
    assert!(!satisfied(&st, &w));
    // E6: the right key but another diversifier
    let (st, mut w) = refund_case(&f, T_REFUND);
    w.inputs[0].d_refund = f.x.ivk.find_address(1).1.d;
    assert!(!satisfied(&st, &w));
    // E4: a claim whose opening does not match the slot
    let (st, mut w) = claim_case(&f, 50);
    w.inputs[0].opening.t_refund += 1;
    assert!(!satisfied(&st, &w));
    // E4: a plain input pretending to be locked (h_aux = 0 opens to nothing)
    let (st, mut w) = claim_case(&f, 50);
    w.inputs[1].h_aux = Fr::from(1u64);
    assert!(!satisfied(&st, &w));
    // E2: refund on a plain input
    let (st, mut w) = claim_case(&f, 50);
    w.inputs[1].refund = true;
    assert!(!satisfied(&st, &w));
    // E7: the locked input with a base nullifier
    let (mut st, w) = claim_case(&f, 50);
    st.base.nullifiers[0] = nullifier(&f.y.sk_nf, &f.locked.0.rho(), f.locked.3);
    assert!(!satisfied(&st, &w));
    // E7: the plain input with a locked nullifier
    let (mut st, w) = claim_case(&f, 50);
    st.base.nullifiers[1] = nullifier_locked(&f.plain.0.rho(), f.plain.3);
    assert!(!satisfied(&st, &w));
    // E1: a locked note claimed with the wrong slot value (leaf mismatch)
    let (st, mut w) = claim_case(&f, 50);
    w.inputs[0].h_aux = Fr::from(0u64);
    assert!(!satisfied(&st, &w));
    // E3: a plain note spent by someone else
    let (st, mut w) = claim_case(&f, 50);
    w.sk_spend = f.x.sk_spend;
    w.inputs[0].refund = false;
    assert!(!satisfied(&st, &w));
    // base block 6: value inflation
    let (mut st, mut w) = claim_case(&f, 50);
    let (outs, chans) = outputs(&f, 801);
    w.outputs = outs;
    st.base.pk_eph = [chans[0].0, chans[1].0];
    st.base.ct_note = [chans[0].1, chans[1].1];
    assert!(!satisfied(&st, &w));
    // public h_anchor must be a 32-bit height
    let (mut st, w) = claim_case(&f, 50);
    st.h_anchor = u32::MAX;
    assert!(satisfied(&st, &w));
    let _ = x_addr;
}

#[test]
fn proofs_verify_and_bind_h_anchor() {
    let f = fixture();
    let params = SwapParams::insecure_setup(&[5u8; 32]).unwrap();
    let verifier = SwapVerifier::from_vk_bytes(&vk_to_bytes(params.vk())).unwrap();
    assert_eq!(vk_sha256(&verifier.vk), vk_sha256(params.vk()));
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let (st, w) = refund_case(&f, T_REFUND + 2);
    let proof = params.prove(&st, &w, &mut rng).unwrap();
    assert!(verifier.verify(&st, &proof));
    // the anchor height is a public input: another height, another statement
    let mut other = st.clone();
    other.h_anchor = T_REFUND + 3;
    assert!(!verifier.verify(&other, &proof));
    // the base verifying key does not accept a swap proof
    let base = TransferParams::insecure_setup(&[5u8; 32]).unwrap();
    assert_ne!(vk_sha256(base.vk()), vk_sha256(params.vk()));
    assert!(!TransferVerifier::new(base.vk().clone()).verify(&st.base, &proof));
    // a claim proof too, and a flipped proof byte fails
    let (st, w) = claim_case(&f, 40);
    let mut proof = params.prove(&st, &w, &mut rng).unwrap();
    assert!(verifier.verify(&st, &proof));
    proof[10] ^= 1;
    assert!(!verifier.verify(&st, &proof));
    // round trip of the proving key
    let again = SwapParams::from_pk_bytes(&params.pk_to_bytes().unwrap()).unwrap();
    assert_eq!(vk_sha256(again.vk()), vk_sha256(params.vk()));
    let _ = fr_from_bytes(&[0u8; 32]);
}
