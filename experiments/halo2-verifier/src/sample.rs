//! The sample transfer of `sba-circuit/tests/transfer.rs`, for the tests.

use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sba_circuit::{InputWitness, OutputWitness, TransferStatement, TransferWitness};
use sba_core::envelope::TransferBody;
use sba_core::keys::{Seed, WalletKeys};
use sba_core::note::{encrypt_note, note_leaf, nullifier, NotePlaintext};
use sba_core::recovery::{binding_digest, encrypt_recovery, RecoveryEntry};
use sba_core::tree::NoteTree;
use sba_primitives::Fp;

pub fn sample() -> (TransferStatement, TransferWitness) {
    let mut rng = StdRng::seed_from_u64(42);
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let bob = WalletKeys::from_seed(&Seed([2u8; 32]));
    let (_, a0) = alice.ivk.find_address(0);
    let (_, a1) = alice.ivk.find_address(1);
    let (_, b0) = bob.ivk.find_address(0);
    let const_salt = Fp::random(&mut rng);
    let hb0 = Fp::random(&mut rng);
    let note_in = NotePlaintext { value: 1000, d: a0.d, rseed: Fp::random(&mut rng) };
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
        InputWitness { note: note_in, h_body_create: hb0, output_index: 1, pos, siblings: path.siblings },
        dummy,
    ];
    let outs = [
        OutputWitness { note: NotePlaintext { value: 700, d: b0.d, rseed: Fp::random(&mut rng) }, pk_d: b0.pk_d },
        OutputWitness { note: NotePlaintext { value: 300, d: a1.d, rseed: Fp::random(&mut rng) }, pk_d: a1.pk_d },
    ];
    let (e0, c0) = encrypt_note(&outs[0].note, &outs[0].pk_d).unwrap();
    let (e1, c1) = encrypt_note(&outs[1].note, &outs[1].pk_d).unwrap();
    let digest = binding_digest(&[e0, e1], &[c0, c1]);
    let ct_out = encrypt_recovery(
        &alice.ovk,
        &digest,
        &[
            RecoveryEntry { pk_d: outs[0].pk_d, sk_eph: outs[0].note.sk_eph() },
            RecoveryEntry { pk_d: outs[1].pk_d, sk_eph: outs[1].note.sk_eph() },
        ],
    );
    let nullifiers = [
        nullifier(&alice.sk_nf, &inputs[0].note.rho(), inputs[0].pos),
        nullifier(&alice.sk_nf, &inputs[1].note.rho(), 0),
    ];
    let body = TransferBody { h_anchor: 100, nullifiers, pk_eph: [e0, e1], ct_note: [c0, c1], ct_out };
    let salt_bytes = sba_primitives::encoding::fp_to_bytes(&const_salt);
    let st = TransferStatement { const_salt, r_anchor, nullifiers, pk_eph: [e0, e1], ct_note: [c0, c1], h_body: body.h_body(&salt_bytes) };
    let w = TransferWitness { sk_spend: alice.sk_spend, inputs, outputs: outs };
    (st, w)
}
