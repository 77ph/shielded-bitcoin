#![no_main]
//! The paper family's wallet scanning accepted events an adversary shaped:
//! what it finds is ours, consistent and leaf-bound; what is honestly ours
//! it finds; the wallet scanned in two steps equals one scanned in one.

use std::collections::HashSet;
use std::sync::LazyLock;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use libfuzzer_sys::fuzz_target;
use sb_core::address::{Network, PaymentAddress};
use sb_core::event::{AcceptedEvent, EventKind};
use sb_core::keys::{Seed, WalletKeys};
use sb_core::note::{
    NoteCiphertext, NotePlaintext, check_note_consistency, encrypt_note, note_leaf_aux,
};
use sb_core::recovery::{CT_OUT_LEN, RecoveryEntry, binding_digest, encrypt_recovery};
use sb_fuzz::{EventSpec, MAX_EVENTS, MAX_OUTPUTS, MAX_VALUE, NoteSrc, Recovery, WalletScript};
use sb_primitives::encoding::point_from_bytes;
use sb_primitives::{Fr, JubjubAffine, JubjubScalar};
use sb_wallet::{Wallet, scan_incoming, scan_outgoing};

struct Keys {
    ours: WalletKeys,
    stranger: WalletKeys,
    addrs: Vec<PaymentAddress>,
    stranger_addr: PaymentAddress,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let ours = WalletKeys::from_seed(&Seed([7u8; 32]));
    let stranger = WalletKeys::from_seed(&Seed([9u8; 32]));
    let addrs = (0..16u64)
        .filter_map(|i| ours.ivk.address_at(i))
        .take(4)
        .collect::<Vec<_>>();
    assert_eq!(addrs.len(), 4);
    let stranger_addr = stranger.ivk.find_address(0).1;
    Keys {
        ours,
        stranger,
        addrs,
        stranger_addr,
    }
});

const SALT: u64 = 0x5a17;

fn fr(b: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(b)
}

/// A point as the indexer could have parsed one: `point_from_bytes` refuses
/// the identity, so the fallback never yields it either.
fn point(b: &[u8; 32]) -> JubjubAffine {
    point_from_bytes(b).unwrap_or_else(|_| {
        let p =
            (JubjubAffine::generator() * JubjubScalar::from_le_bytes_mod_order(b)).into_affine();
        if p.is_zero() {
            JubjubAffine::generator()
        } else {
            p
        }
    })
}

/// One output as made: the pair on the wire, what the sender knew (for the
/// recovery), whether the ciphertext is intact, and what our scan should find.
struct Made {
    pk_eph: JubjubAffine,
    ct: NoteCiphertext,
    sender: Option<(JubjubAffine, JubjubScalar)>,
    intact: bool,
    expect: Option<NotePlaintext>,
}

fn make(k: &Keys, src: &NoteSrc) -> Made {
    let encrypt = |pt: &NotePlaintext, pk_d: &JubjubAffine| {
        let (pk_eph, ct) = encrypt_note(pt, pk_d).expect("a valid diversifier");
        (pk_eph, ct, Some((*pk_d, pt.sk_eph())))
    };
    match src {
        NoteSrc::Random {
            pk_eph,
            c0,
            c1,
            tag,
        } => Made {
            pk_eph: point(pk_eph),
            ct: NoteCiphertext {
                c0: fr(c0),
                c1: fr(c1),
                tag: fr(tag),
            },
            sender: None,
            intact: false,
            expect: None,
        },
        NoteSrc::ToUs { to, value, rseed } => {
            let a = k.addrs[*to as usize % 4];
            let pt = NotePlaintext {
                value: value % MAX_VALUE,
                d: a.d,
                rseed: fr(rseed),
            };
            let (pk_eph, ct, sender) = encrypt(&pt, &a.pk_d);
            Made {
                pk_eph,
                ct,
                sender,
                intact: true,
                expect: Some(pt),
            }
        }
        NoteSrc::ToUsFlipped {
            to,
            value,
            rseed,
            at,
            xor,
        } => {
            let a = k.addrs[*to as usize % 4];
            let pt = NotePlaintext {
                value: value % MAX_VALUE,
                d: a.d,
                rseed: fr(rseed),
            };
            let (pk_eph, ct, sender) = encrypt(&pt, &a.pk_d);
            let mut bytes = ct.to_bytes();
            let at = *at as usize % bytes.len();
            bytes[at] ^= xor | 1;
            let ct = NoteCiphertext::from_bytes(&bytes).unwrap_or(NoteCiphertext {
                c0: ct.c0,
                c1: ct.c1,
                tag: ct.tag + Fr::from(1u64),
            });
            Made {
                pk_eph,
                ct,
                sender,
                intact: false,
                expect: None,
            }
        }
        NoteSrc::OurDiversifierForeignKey { to, value, rseed } => {
            let a = k.addrs[*to as usize % 4];
            let pt = NotePlaintext {
                value: value % MAX_VALUE,
                d: a.d,
                rseed: fr(rseed),
            };
            let foreign = k
                .stranger
                .ivk
                .address_for(a.d)
                .expect("our d is valid")
                .pk_d;
            let (pk_eph, ct, sender) = encrypt(&pt, &foreign);
            Made {
                pk_eph,
                ct,
                sender,
                intact: true,
                expect: None,
            }
        }
        NoteSrc::Stranger { value, rseed } => {
            let a = k.stranger_addr;
            let pt = NotePlaintext {
                value: value % MAX_VALUE,
                d: a.d,
                rseed: fr(rseed),
            };
            let (pk_eph, ct, sender) = encrypt(&pt, &a.pk_d);
            Made {
                pk_eph,
                ct,
                sender,
                intact: true,
                expect: None,
            }
        }
    }
}

/// The event, what our incoming scan should find per output, and whether
/// the outgoing scan should find both outputs.
fn event(
    k: &Keys,
    spec: &EventSpec,
    salt: &Fr,
) -> (AcceptedEvent, Vec<Option<NotePlaintext>>, bool) {
    let n = spec.outputs.len().min(MAX_OUTPUTS);
    let made: Vec<Made> = spec.outputs[..n].iter().map(|s| make(k, s)).collect();
    let outputs: Vec<(JubjubAffine, NoteCiphertext)> =
        made.iter().map(|m| (m.pk_eph, m.ct)).collect();
    let h_body = fr(&spec.h_body);
    let h_aux: Vec<Fr> = spec.aux.iter().take(n).map(fr).collect();
    let zero = Fr::from(0u64);
    let honest = |j: usize| (spec.honest_leaves >> j) & 1 == 1;
    let leaves: Vec<Fr> = (0..n)
        .map(|j| {
            if honest(j) {
                note_leaf_aux(
                    salt,
                    &h_body,
                    j as u64,
                    &outputs[j].0,
                    &outputs[j].1,
                    h_aux.get(j).unwrap_or(&zero),
                )
            } else {
                fr(&spec.leaf_salt) + Fr::from(j as u64 + 1)
            }
        })
        .collect();
    // a position that would overflow is no position: the wallet skips the
    // output (fail closed), so nothing of ours is expected there
    let fits = |j: usize| spec.first_position.checked_add(j as u64).is_some();
    let expect: Vec<Option<NotePlaintext>> = made
        .iter()
        .enumerate()
        .map(|(j, m)| if honest(j) && fits(j) { m.expect } else { None })
        .collect();
    let (ct_out, expect_sent) = match &spec.recovery {
        Recovery::None => (None, false),
        Recovery::Random(b) => {
            let mut a = [0u8; CT_OUT_LEN];
            for (i, x) in a.iter_mut().enumerate() {
                *x = *b.get(i).unwrap_or(&0x5a);
            }
            (Some(a), false)
        }
        r @ (Recovery::Honest | Recovery::HonestFlipped { .. }) => {
            if n == 2 && made[0].sender.is_some() && made[1].sender.is_some() {
                let pk = [outputs[0].0, outputs[1].0];
                let ct = [outputs[0].1, outputs[1].1];
                let digest = binding_digest(&pk, &ct);
                let entry = |m: &Made| {
                    let (pk_d, sk_eph) = m.sender.unwrap();
                    RecoveryEntry { pk_d, sk_eph }
                };
                let mut out =
                    encrypt_recovery(&k.ours.ovk, &digest, &[entry(&made[0]), entry(&made[1])]);
                let flipped = if let Recovery::HonestFlipped { at, xor } = r {
                    out[*at as usize % CT_OUT_LEN] ^= xor | 1;
                    true
                } else {
                    false
                };
                let complete =
                    !flipped && made.iter().all(|m| m.intact) && honest(0) && honest(1) && fits(1);
                (Some(out), complete)
            } else {
                (None, false)
            }
        }
    };
    let ev = AcceptedEvent {
        kind: if spec.mint {
            EventKind::Mint
        } else {
            EventKind::Transfer
        },
        height: spec.height,
        tx_index: 0,
        txid: spec.txid,
        raw: spec.txid.to_vec(),
        h_body,
        nullifiers: spec.nullifiers.iter().take(4).map(fr).collect(),
        outputs,
        ct_out,
        first_position: spec.first_position,
        leaves,
        h_aux,
        memo: None,
    };
    (ev, expect, expect_sent)
}

fuzz_target!(|script: WalletScript| {
    let k = &*KEYS;
    let salt = Fr::from(SALT);
    let n_ev = script.events.len().min(MAX_EVENTS);
    let mut events = Vec::with_capacity(n_ev);
    let mut found_total = 0usize;
    for spec in &script.events[..n_ev] {
        let (ev, expect, expect_sent) = event(k, spec, &salt);
        let found = scan_incoming(&k.ours.ivk, &salt, &ev);
        for r in &found {
            let j = r.output_index as usize;
            assert!(
                k.ours.ivk.owns(&r.address),
                "a found note is at our address"
            );
            assert_eq!(k.ours.ivk.address_for(r.note.d), Some(r.address));
            assert!(check_note_consistency(&r.note, &ev.outputs[j].0));
            assert_eq!(r.leaf, ev.leaves[j], "a found note's leaf is the event's");
            assert_eq!(r.pos, ev.first_position + r.output_index);
            assert_eq!(
                (r.height, r.txid, r.h_body_create),
                (ev.height, ev.txid, ev.h_body)
            );
        }
        for (j, e) in expect.iter().enumerate() {
            let at_j: Vec<_> = found
                .iter()
                .filter(|r| r.output_index == j as u64)
                .collect();
            match e {
                Some(pt) => {
                    assert_eq!(at_j.len(), 1, "an honest note to us at {j} is found once");
                    assert_eq!(at_j[0].note, *pt);
                }
                None => assert!(at_j.is_empty(), "nothing of ours at {j}"),
            }
        }
        found_total += found.len();
        assert_eq!(
            scan_incoming(&k.ours.ivk, &salt, &ev),
            found,
            "deterministic"
        );
        for r in scan_incoming(&k.stranger.ivk, &salt, &ev) {
            assert!(
                !k.ours.ivk.owns(&r.address),
                "the stranger finds nothing of ours"
            );
        }
        let sent = scan_outgoing(&k.ours.ovk, &salt, &ev);
        if let Some(s) = &sent {
            assert_eq!(s.len(), 2, "the outgoing scan finds both or nothing");
            for (j, sn) in s.iter().enumerate() {
                assert_eq!(sn.output_index, j as u64);
                assert!(check_note_consistency(&sn.note, &ev.outputs[j].0));
                assert_eq!(sn.pos, ev.first_position + j as u64);
            }
        }
        if expect_sent {
            assert!(
                sent.is_some(),
                "an honest recovery over intact outputs is read"
            );
        }
        assert_eq!(
            scan_outgoing(&k.ours.ovk, &salt, &ev),
            sent,
            "deterministic"
        );
        events.push(ev);
    }
    // the wallet over the history: in two steps, and in one
    let spent: HashSet<Fr> = HashSet::new();
    let split = script.split as usize % (n_ev + 1);
    let mut two = Wallet::from_seed(Seed([7u8; 32]), Network::Regtest, "fuzz");
    let a = two.scan(&salt, &events[..split], &spent);
    let b = two.scan(&salt, &events, &spent);
    let mut one = Wallet::from_seed(Seed([7u8; 32]), Network::Regtest, "fuzz");
    let c = one.scan(&salt, &events, &spent);
    assert_eq!(
        a.is_ok() && b.is_ok(),
        c.is_ok(),
        "the two scans agree on success"
    );
    assert_eq!(two.notes, one.notes, "incremental equals from scratch");
    assert_eq!(two.sent, one.sent);
    assert_eq!(two.balance(), one.balance());
    if c.is_ok() {
        assert_eq!(
            one.notes.len(),
            found_total,
            "the wallet keeps what the scan found"
        );
    }
});
