//! Property tests of the paper family's structures and codecs: the note
//! tree against a naive recomputation under appends, overwrites and
//! truncations, with its paths under earlier roots; the nullifier tree
//! against a set, with its witnesses; the envelopes' round trips, and the
//! strict parsers' canonicality under a flipped byte.
use std::collections::BTreeSet;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use proptest::prelude::*;
use sb_core::address::{Network, PaymentAddress};
use sb_core::envelope::{
    ENVELOPE_LEN, Envelope, HEADER_LEN, MINT_LEN, MintEnvelope, PROOF_LEN, SWAP_ENVELOPE_LEN,
    SwapBody, SwapEnvelope, TransferBody, TransferEnvelope, parse_envelope,
};
use sb_core::imt::{ImtError, IndexedMerkleTree};
use sb_core::keys::{Seed, WalletKeys};
use sb_core::note::{NoteCiphertext, NotePlaintext};
use sb_core::recovery::CT_OUT_LEN;
use sb_core::tree::{DEPTH, EMPTY_ROOTS, NoteTree, node_hash};
use sb_primitives::{Fr, Jubjub, JubjubAffine, JubjubScalar};

fn fr() -> impl Strategy<Value = Fr> {
    any::<[u8; 32]>().prop_map(|b| Fr::from_le_bytes_mod_order(&b))
}

/// A small domain, so that duplicates and the zero happen.
fn small_fr() -> impl Strategy<Value = Fr> {
    (0u64..40).prop_map(Fr::from)
}

fn point() -> impl Strategy<Value = JubjubAffine> {
    (1u64..u64::MAX).prop_map(|k| (Jubjub::generator() * JubjubScalar::from(k)).into_affine())
}

fn ct() -> impl Strategy<Value = NoteCiphertext> {
    (fr(), fr(), fr()).prop_map(|(c0, c1, tag)| NoteCiphertext { c0, c1, tag })
}

fn body() -> impl Strategy<Value = TransferBody> {
    (
        any::<u32>(),
        (fr(), fr()),
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

fn naive_root(leaves: &[Fr]) -> Fr {
    if leaves.is_empty() {
        return EMPTY_ROOTS[DEPTH];
    }
    let mut layer: Vec<Fr> = leaves.to_vec();
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
    Append(Fr),
    Set(u8, Fr),
    Truncate(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => fr().prop_map(Op::Append),
        1 => (any::<u8>(), fr()).prop_map(|(i, f)| Op::Set(i, f)),
        1 => any::<u8>().prop_map(Op::Truncate),
    ]
}

fn key(v: &Fr) -> [u8; 32] {
    sb_primitives::encoding::fr_to_bytes(v)
}

fn bytes_of(e: &Envelope) -> Vec<u8> {
    match e {
        Envelope::Transfer(t) => t.to_bytes(),
        Envelope::Mint(m) => m.to_bytes(),
        Envelope::Swap(s) => s.to_bytes(),
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
        let mut model: Vec<Fr> = Vec::new();
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
            prop_assert_eq!(ap.root(&Fr::from(0u64)), tree.root());
        }
    }

    #[test]
    fn the_nullifier_tree_matches_a_set(
        values in prop::collection::vec(small_fr(), 1..24),
        probe in small_fr(),
    ) {
        let mut imt = IndexedMerkleTree::new();
        let mut set: BTreeSet<[u8; 32]> = BTreeSet::new();
        for v in values {
            let before = imt.root();
            let r = imt.insert(v);
            if v == Fr::from(0u64) {
                prop_assert_eq!(r, Err(ImtError::Zero));
            } else if set.contains(&key(&v)) {
                prop_assert_eq!(r, Err(ImtError::Duplicate));
                prop_assert_eq!(imt.root(), before);
            } else {
                let ins = r.unwrap();
                prop_assert_eq!(ins.value, v);
                prop_assert_eq!(ins.roots(), Some((before, imt.root())));
                set.insert(key(&v));
            }
            prop_assert_eq!(imt.len(), set.len());
            // the sentinel counts as present: never inserted, never provably absent
            prop_assert!(imt.contains(&v) == (v == Fr::from(0u64) || set.contains(&key(&v))));
            match imt.non_membership(&probe) {
                None => prop_assert!(probe == Fr::from(0u64) || set.contains(&key(&probe))),
                Some(nm) => {
                    prop_assert!(!set.contains(&key(&probe)));
                    prop_assert!(nm.verify(&imt.root(), &probe));
                    // the witness is for this value and this root only
                    prop_assert!(!nm.verify(&imt.root(), &nm.low.value));
                    prop_assert!(!nm.verify(&before, &probe) || before == imt.root());
                }
            }
        }
        // the same values in one go give the same tree
        let values: Vec<Fr> = imt.leaves()[1..].iter().map(|l| l.value).collect();
        prop_assert_eq!(IndexedMerkleTree::from_values(&values).unwrap().root(), imt.root());
    }

    #[test]
    fn envelopes_round_trip_and_stay_canonical_under_a_flipped_byte(
        body in body(),
        proof in prop::collection::vec(any::<u8>(), PROOF_LEN),
        h_aux in (fr(), fr()),
        value in any::<u64>(),
        d in any::<[u8; 11]>(),
        at in any::<usize>(),
        x in 1u8..,
    ) {
        let proof: [u8; PROOF_LEN] = proof.try_into().unwrap();
        let t = TransferEnvelope { body: body.clone(), proof };
        let s = SwapEnvelope {
            body: SwapBody { base: body.clone(), h_aux: [h_aux.0, h_aux.1] },
            proof,
        };
        let m = MintEnvelope {
            note: NotePlaintext { value, d, rseed: body.nullifiers[0] },
            pk_d: body.pk_eph[0],
        };
        let tb = t.to_bytes();
        let sb = s.to_bytes();
        let mb = m.to_bytes();
        prop_assert_eq!((tb.len(), sb.len(), mb.len()), (ENVELOPE_LEN, SWAP_ENVELOPE_LEN, MINT_LEN));
        prop_assert_eq!(parse_envelope(&tb), Ok(Envelope::Transfer(t)));
        prop_assert_eq!(parse_envelope(&sb), Ok(Envelope::Swap(s)));
        prop_assert_eq!(parse_envelope(&mb), Ok(Envelope::Mint(m)));
        for b in [tb, sb, mb] {
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
