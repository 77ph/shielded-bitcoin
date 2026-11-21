//! Variant A's property tests: the same statements as the paper family's
//! (`crates/sb-core/tests/props.rs`) over the Pallas base field, plus the
//! nullifier tree's truncation, which the variant's indexer rolls back with.
use std::collections::BTreeSet;

use ff::Field;
use group::{Curve, Group};
use proptest::prelude::*;
use sba_core::address::{Network, PaymentAddress};
use sba_core::envelope::{
    ENVELOPE_LEN, Envelope, HEADER_LEN, MINT_LEN, MintEnvelope, PROOF_LEN, TransferBody,
    TransferEnvelope, parse_envelope,
};
use sba_core::imt::{ImtError, IndexedMerkleTree};
use sba_core::keys::{Seed, WalletKeys};
use sba_core::note::{NoteCiphertext, NotePlaintext};
use sba_core::recovery::CT_OUT_LEN;
use sba_core::tree::{DEPTH, EMPTY_ROOTS, NoteTree, node_hash};
use sba_primitives::{Affine, Fp, Point, Scalar};

fn fp() -> impl Strategy<Value = Fp> {
    any::<[u64; 4]>().prop_map(Fp::from_raw)
}

/// A small domain, so that duplicates and the zero happen.
fn small_fp() -> impl Strategy<Value = Fp> {
    (0u64..40).prop_map(Fp::from)
}

fn point() -> impl Strategy<Value = Affine> {
    (1u64..u64::MAX).prop_map(|k| (Point::generator() * Scalar::from(k)).to_affine())
}

fn ct() -> impl Strategy<Value = NoteCiphertext> {
    (fp(), fp(), fp()).prop_map(|(c0, c1, tag)| NoteCiphertext { c0, c1, tag })
}

fn body() -> impl Strategy<Value = TransferBody> {
    (
        any::<u32>(),
        (fp(), fp()),
        (point(), point()),
        (ct(), ct()),
        prop::collection::vec(any::<u8>(), CT_OUT_LEN),
    )
        .prop_map(|(h_anchor, nf, pk, ct, out)| TransferBody {
            h_anchor,
            nullifiers: [nf.0, nf.1],
            pk_eph: [pk.0, pk.1],
            ct_note: [ct.0, ct.1],
            ct_out: out.try_into().unwrap(),
        })
}

fn naive_root(leaves: &[Fp]) -> Fp {
    if leaves.is_empty() {
        return EMPTY_ROOTS[DEPTH];
    }
    let mut layer: Vec<Fp> = leaves.to_vec();
    for k in 0..DEPTH {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let r = pair.get(1).copied().unwrap_or(EMPTY_ROOTS[k]);
            next.push(node_hash(&pair[0], &r));
        }
        layer = next;
    }
    layer[0]
}

#[derive(Debug, Clone)]
enum Op {
    Append(Fp),
    Set(u8, Fp),
    Truncate(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => fp().prop_map(Op::Append),
        1 => (any::<u8>(), fp()).prop_map(|(i, f)| Op::Set(i, f)),
        1 => any::<u8>().prop_map(Op::Truncate),
    ]
}

fn key(v: &Fp) -> [u8; 32] {
    sba_primitives::encoding::fp_to_bytes(v)
}

fn bytes_of(e: &Envelope) -> Vec<u8> {
    match e {
        Envelope::Transfer(t) => t.to_bytes(),
        Envelope::Mint(m) => m.to_bytes(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn the_note_tree_matches_a_naive_recomputation(
        ops in prop::collection::vec(op(), 1..16),
        probe in any::<u8>(),
    ) {
        let mut tree = NoteTree::new();
        let mut model: Vec<Fp> = Vec::new();
        for op in ops {
            match op {
                Op::Append(f) => {
                    prop_assert_eq!(tree.append(f), model.len() as u64);
                    model.push(f);
                }
                Op::Set(i, f) => {
                    if !model.is_empty() {
                        let p = i as usize % model.len();
                        tree.set(p as u64, f);
                        model[p] = f;
                    }
                }
                Op::Truncate(n) => {
                    let s = n as usize % (model.len() + 1);
                    tree.truncate(s as u64);
                    model.truncate(s);
                }
            }
            prop_assert_eq!(tree.size(), model.len() as u64);
            prop_assert_eq!(tree.leaves(), &model[..]);
            prop_assert_eq!(tree.root(), naive_root(&model));
            // an earlier size's root, and a path under it
            let size = probe as u64 % (model.len() as u64 + 1);
            prop_assert_eq!(tree.root_at(size), naive_root(&model[..size as usize]));
            if size > 0 {
                let pos = (probe as u64 * 7) % size;
                let path = tree.path_at(pos, size).unwrap();
                prop_assert_eq!(path.position, pos);
                prop_assert_eq!(path.root(&model[pos as usize]), tree.root_at(size));
            }
            prop_assert!(tree.path_at(size, size).is_none());
            // the next slot's path: the empty leaf over it is the root now
            let ap = tree.append_path();
            prop_assert_eq!(ap.position, tree.size());
            prop_assert_eq!(ap.root(&Fp::ZERO), tree.root());
        }
    }

    #[test]
    fn the_nullifier_tree_matches_a_set(
        values in prop::collection::vec(small_fp(), 1..24),
        probe in small_fp(),
        cut in any::<u8>(),
    ) {
        let mut imt = IndexedMerkleTree::new();
        let mut set: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut roots = vec![imt.root()];
        for v in values {
            let before = imt.root();
            let r = imt.insert(v);
            if v == Fp::ZERO {
                prop_assert_eq!(r, Err(ImtError::Zero));
            } else if set.contains(&key(&v)) {
                prop_assert_eq!(r, Err(ImtError::Duplicate));
                prop_assert_eq!(imt.root(), before);
            } else {
                let ins = r.unwrap();
                prop_assert_eq!(ins.value, v);
                prop_assert_eq!(ins.roots(), Some((before, imt.root())));
                set.insert(key(&v));
                roots.push(imt.root());
            }
            prop_assert_eq!(imt.len(), set.len());
            // the sentinel counts as present: never inserted, never provably absent
            prop_assert!(imt.contains(&v) == (v == Fp::ZERO || set.contains(&key(&v))));
            match imt.non_membership(&probe) {
                None => prop_assert!(probe == Fp::ZERO || set.contains(&key(&probe))),
                Some(nm) => {
                    prop_assert!(!set.contains(&key(&probe)));
                    prop_assert!(nm.verify(&imt.root(), &probe));
                    // the witness is for this value only
                    prop_assert!(!nm.verify(&imt.root(), &nm.low.value));
                }
            }
        }
        let values: Vec<Fp> = imt.leaves()[1..].iter().map(|l| l.value).collect();
        prop_assert_eq!(IndexedMerkleTree::from_values(&values).unwrap().root(), imt.root());
        // truncating to an earlier length gives that length's root (the
        // rollback path of the variant's indexer)
        let keep = cut as usize % (values.len() + 1);
        imt.truncate(keep);
        prop_assert_eq!(imt.len(), keep);
        prop_assert_eq!(imt.root(), roots[keep]);
        prop_assert_eq!(IndexedMerkleTree::from_values(&values[..keep]).unwrap().root(), imt.root());
    }

    #[test]
    fn envelopes_round_trip_and_stay_canonical_under_a_flipped_byte(
        body in body(),
        proof in prop::collection::vec(any::<u8>(), PROOF_LEN),
        value in any::<u64>(),
        d in any::<[u8; 11]>(),
        at in any::<usize>(),
        x in 1u8..,
    ) {
        let t = TransferEnvelope { body: body.clone(), proof };
        let m = MintEnvelope {
            note: NotePlaintext { value, d, rseed: body.nullifiers[0] },
            pk_d: body.pk_eph[0],
        };
        let tb = t.to_bytes();
        let mb = m.to_bytes();
        prop_assert_eq!((tb.len(), mb.len()), (ENVELOPE_LEN, MINT_LEN));
        prop_assert_eq!(parse_envelope(&tb), Ok(Envelope::Transfer(t)));
        prop_assert_eq!(parse_envelope(&mb), Ok(Envelope::Mint(m)));
        for b in [tb, mb] {
            // one byte flipped: refused, or accepted as the canonical bytes
            // of another envelope; in the header always refused
            let i = at % b.len();
            let mut f = b.clone();
            f[i] ^= x;
            if let Ok(e) = parse_envelope(&f) {
                prop_assert!(i >= HEADER_LEN, "a header flip at {i} was accepted");
                prop_assert_eq!(bytes_of(&e), f);
            }
            // one byte more or less: refused
            prop_assert!(parse_envelope(&b[..b.len() - 1]).is_err());
            let mut longer = b.clone();
            longer.push(0);
            prop_assert!(parse_envelope(&longer).is_err());
        }
    }

    #[test]
    fn addresses_round_trip_as_bytes_and_text(seed in any::<[u8; 32]>(), start in 0u64..1000, mainnet: bool) {
        let keys = WalletKeys::from_seed(&Seed(seed));
        let (_, a) = keys.ivk.find_address(start);
        prop_assert_eq!(PaymentAddress::from_bytes(&a.to_bytes()).unwrap(), a);
        let net = if mainnet { Network::Mainnet } else { Network::Signet };
        let text = a.encode(net);
        prop_assert_eq!(PaymentAddress::decode(&text).unwrap(), (net, a));
        prop_assert_eq!(PaymentAddress::decode(&text.to_uppercase()).unwrap(), (net, a));
    }
}
