//! Wallet, scan and payout branches that the chain flows do not reach:
//! file corruption, rescans, external spends, input selection, memo cases.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ark_ff::UniformRand;
use sb_core::address::{Network, PaymentAddress};
use sb_core::envelope::{TransferBody, TransferEnvelope, bytes_to_fr_253};
use sb_core::event::{AcceptedEvent, txid_hex};
use sb_core::keys::{Seed, WalletKeys};
use sb_core::note::{NotePlaintext, encrypt_note, note_leaf, nullifier};
use sb_core::recovery::{RecoveryEntry, binding_digest, encrypt_recovery};
use sb_primitives::Fr;
use sb_wallet::{NoteRecord, Wallet, WalletError, build_payout_memo, scan_incoming, scan_outgoing};

const SALT: [u8; 32] = [9u8; 32];

/// An accepted transfer event from `sender` paying `outs`, without a proof.
fn transfer_event(
    sender: &WalletKeys,
    outs: [(PaymentAddress, u64); 2],
    nfs: [Fr; 2],
    height: u32,
    first_position: u64,
    memo: Option<Vec<u8>>,
    rng: &mut ChaCha20Rng,
) -> AcceptedEvent {
    let salt_fe = bytes_to_fr_253(&SALT);
    let pts = [
        NotePlaintext {
            value: outs[0].1,
            d: outs[0].0.d,
            rseed: Fr::rand(rng),
        },
        NotePlaintext {
            value: outs[1].1,
            d: outs[1].0.d,
            rseed: Fr::rand(rng),
        },
    ];
    let (p0, c0) = encrypt_note(&pts[0], &outs[0].0.pk_d).unwrap();
    let (p1, c1) = encrypt_note(&pts[1], &outs[1].0.pk_d).unwrap();
    let pk_eph = [p0, p1];
    let ct_note = [c0, c1];
    let entries = [
        RecoveryEntry {
            pk_d: outs[0].0.pk_d,
            sk_eph: pts[0].sk_eph(),
        },
        RecoveryEntry {
            pk_d: outs[1].0.pk_d,
            sk_eph: pts[1].sk_eph(),
        },
    ];
    let digest = binding_digest(&pk_eph, &ct_note);
    let ct_out = encrypt_recovery(&sender.ovk, &digest, &entries);
    let body = TransferBody {
        h_anchor: 1,
        nullifiers: nfs,
        pk_eph,
        ct_note,
        ct_out,
    };
    let h_body = body.h_body(&SALT);
    let leaves = vec![
        note_leaf(&salt_fe, &h_body, 0, &pk_eph[0], &ct_note[0]),
        note_leaf(&salt_fe, &h_body, 1, &pk_eph[1], &ct_note[1]),
    ];
    let env = TransferEnvelope {
        body,
        proof: [0u8; 192],
    };
    let mut txid = [0u8; 32];
    txid[0] = height as u8;
    txid[1] = first_position as u8;
    let mut ev =
        AcceptedEvent::from_transfer(height, 0, txid, &env, h_body, first_position, leaves);
    ev.memo = memo;
    ev
}

#[test]
fn scans_reject_inconsistent_events() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let bob = WalletKeys::from_seed(&Seed([2u8; 32]));
    let (_, a) = alice.ivk.find_address(0);
    let (_, b) = bob.ivk.find_address(0);
    let salt_fe = bytes_to_fr_253(&SALT);
    let mut ev = transfer_event(
        &alice,
        [(b, 10), (a, 5)],
        [Fr::from(1u64), Fr::from(2u64)],
        7,
        0,
        None,
        &mut rng,
    );
    assert_eq!(scan_incoming(&bob.ivk, &salt_fe, &ev).len(), 1);
    assert_eq!(scan_outgoing(&alice.ovk, &salt_fe, &ev).unwrap().len(), 2);
    // a leaf that replay did not derive → both sides reject the output
    ev.leaves[0] += Fr::from(1u64);
    assert!(scan_incoming(&bob.ivk, &salt_fe, &ev).is_empty());
    assert!(scan_outgoing(&alice.ovk, &salt_fe, &ev).is_none());
    // sender recovery needs exactly two outputs next to a ct_out
    let mut odd = ev.clone();
    odd.outputs.truncate(1);
    assert!(scan_outgoing(&alice.ovk, &salt_fe, &odd).is_none());
    let mut no_ct = ev.clone();
    no_ct.ct_out = None;
    assert!(scan_outgoing(&alice.ovk, &salt_fe, &no_ct).is_none());
}

#[test]
fn wallet_files_and_rescans() {
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let dir = std::env::temp_dir().join(format!("sb-wallet-cov-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut w = Wallet::create(&mut rng, Network::Regtest, "cov");
    assert_eq!(w.seed_hex().len(), 64);
    assert!(!w.is_encrypted());
    let (i, fresh) = w.new_address();
    assert!(i >= 1);
    assert_ne!(fresh, w.default_address());

    // corrupt files
    let p = dir.join("bad.json");
    std::fs::write(&p, r#"{"version": 3}"#).unwrap();
    assert!(matches!(
        Wallet::load(&p, None),
        Err(WalletError::Corrupt(_))
    ));
    std::fs::write(&p, r#"{"version": 2, "kdf": "scrypt", "salt": "00", "m_cost_kib": 1, "t_cost": 1, "p_cost": 1, "nonce": "00", "ciphertext": "00"}"#).unwrap();
    assert!(matches!(
        Wallet::load(&p, Some("x")),
        Err(WalletError::Corrupt(_))
    ));
    std::fs::write(&p, "not json").unwrap();
    assert!(matches!(Wallet::load(&p, None), Err(WalletError::Json(_))));
    assert!(matches!(
        Wallet::load(&dir.join("missing.json"), None),
        Err(WalletError::Io(_))
    ));

    // events: alice receives, then history "changes" under the wallet
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let (_, a) = alice.ivk.find_address(0);
    let salt_fe = bytes_to_fr_253(&SALT);
    let mut aw = Wallet::from_seed(Seed([1u8; 32]), Network::Regtest, "cov");
    let ev1 = transfer_event(
        &alice,
        [(a, 10), (a, 5)],
        [Fr::from(1u64), Fr::from(2u64)],
        7,
        0,
        None,
        &mut rng,
    );
    assert_eq!(
        aw.scan(&salt_fe, std::slice::from_ref(&ev1), &Default::default())
            .unwrap(),
        2
    );
    assert_eq!(aw.balance(), 15);
    // scanned_events > 0 with no last txid → inconsistent → full rescan, same result
    aw.last_scanned_txid = None;
    assert_eq!(
        aw.scan(&salt_fe, std::slice::from_ref(&ev1), &Default::default())
            .unwrap(),
        2
    );
    assert_eq!(aw.balance(), 15);
    // scanning the same events again from the start without clearing notes skips duplicates
    aw.scanned_events = 0;
    aw.last_scanned_txid = None;
    assert_eq!(
        aw.scan(&salt_fe, std::slice::from_ref(&ev1), &Default::default())
            .unwrap(),
        0
    );
    // a spend seen only through the replayed nullifier set (same seed elsewhere)
    let nf0 = nullifier(&alice.sk_nf, &aw.notes[0].plaintext().unwrap().rho(), 0);
    let set: std::collections::HashSet<Fr> = [nf0].into_iter().collect();
    aw.scan(&salt_fe, std::slice::from_ref(&ev1), &set).unwrap();
    assert_eq!(aw.balance(), 5);
    assert_eq!(aw.notes[0].spent_at, Some(0));
    // locks
    aw.notes[1].locked_by = Some("x".into());
    assert_eq!(aw.balance(), 0);
    aw.unlock_all();
    assert_eq!(aw.balance(), 5);
    // persistence of every record kind
    let p = dir.join("alice.json");
    aw.save(&p).unwrap();
    let back = Wallet::load(&p, None).unwrap();
    assert_eq!(back.notes, aw.notes);
    assert_eq!(back.last_scanned_txid, aw.last_scanned_txid);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn record(pos: u64, value: u64, txid: &str) -> NoteRecord {
    NoteRecord {
        value,
        d: "00".repeat(11),
        rseed: "00".repeat(32),
        h_body_create: "00".repeat(32),
        output_index: 0,
        pos,
        nullifier: format!("{:064x}", pos + 1).chars().rev().collect(),
        height: 1,
        txid: txid.to_string(),
        spent_at: None,
        locked_by: None,
    }
}

#[test]
fn input_selection_branches() {
    let mut w = Wallet::from_seed(Seed([5u8; 32]), Network::Regtest, "cov");
    assert!(matches!(
        w.select_inputs(1, 10),
        Err(WalletError::Insufficient { have: 0, need: 1 })
    ));
    w.notes.push(record(0, 100, "a"));
    assert!(matches!(
        w.select_inputs(1, 0),
        Err(WalletError::NothingUnderAnchor)
    ));
    assert_eq!(w.select_inputs(100, 10).unwrap()[0].pos, 0);
    assert_eq!(w.select_inputs(40, 10).unwrap().len(), 1);
    w.notes.push(record(1, 50, "b"));
    assert_eq!(w.select_inputs(120, 10).unwrap().len(), 2);
    w.notes.push(record(2, 30, "c"));
    assert!(matches!(
        w.select_inputs(170, 10),
        Err(WalletError::NeedsConsolidation)
    ));
    assert!(matches!(
        w.select_inputs(500, 10),
        Err(WalletError::Insufficient {
            have: 180,
            need: 500
        })
    ));
    assert!(format!("{}", WalletError::NeedsConsolidation).contains("consolidate"));
}

#[test]
fn pending_payout_branches() {
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let op = WalletKeys::from_seed(&Seed([8u8; 32]));
    let (_, o) = op.ivk.find_address(0);
    let payer = WalletKeys::from_seed(&Seed([9u8; 32]));
    let (_, p) = payer.ivk.find_address(0);
    let salt_fe = bytes_to_fr_253(&SALT);
    let mut w = Wallet::from_seed(Seed([8u8; 32]), Network::Regtest, "cov");
    let good = build_payout_memo(5, &[0x51]);
    let events = vec![
        transfer_event(
            &payer,
            [(o, 10), (p, 1)],
            [Fr::from(1u64), Fr::from(2u64)],
            1,
            0,
            Some(good.clone()),
            &mut rng,
        ),
        transfer_event(
            &payer,
            [(o, 10), (p, 1)],
            [Fr::from(3u64), Fr::from(4u64)],
            2,
            2,
            None,
            &mut rng,
        ),
        transfer_event(
            &payer,
            [(o, 10), (p, 1)],
            [Fr::from(5u64), Fr::from(6u64)],
            3,
            4,
            Some(b"garbage".to_vec()),
            &mut rng,
        ),
        transfer_event(
            &payer,
            [(o, 10), (p, 1)],
            [Fr::from(7u64), Fr::from(8u64)],
            4,
            6,
            Some(build_payout_memo(11, &[0x51])),
            &mut rng,
        ),
        transfer_event(
            &payer,
            [(o, 10), (p, 1)],
            [Fr::from(9u64), Fr::from(10u64)],
            5,
            8,
            Some(build_payout_memo(0, &[0x51])),
            &mut rng,
        ),
    ];
    w.scan(&salt_fe, &events, &Default::default()).unwrap();
    assert_eq!(w.notes.len(), 5);
    // only the first request is payable: no memo, bad memo, too large, zero are skipped
    let pending = w.pending_payouts(&events);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request.amount, 5);
    // a note whose creating event is unknown is skipped too
    w.notes.push(record(99, 7, &txid_hex(&[0xaa; 32])));
    assert_eq!(w.pending_payouts(&events).len(), 1);
    w.record_payout(&pending[0].note.txid, &pending[0].request, None);
    assert!(w.pending_payouts(&events).is_empty());
}
