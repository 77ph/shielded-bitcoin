//! The replay proof's wire and persisted formats as properties: a proven
//! step, a transcript capture, the prover's and the client's state read
//! back equal from their bytes and refuse a byte more or less; a slot
//! statement reads back from its elements; the heights check holds exactly
//! when the wire agrees with the opening.
use ff::Field;
use group::{Curve, Group};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::{pallas, vesta};
use proptest::prelude::*;
use sba_core::batch::{NO_CT, SLOT_ELEMENTS, SlotStatement, StateOpening};
use sba_core::note::NoteCiphertext;
use sba_primitives::Fp;
use sba_replay::capture::{Capture, Event};
use sba_replay::chain::check_heights;
use sba_replay::persist::{ChainState, ClientState};
use sba_replay::wire::ProvenStep;

type Fq = vesta::Base;

fn fp() -> BoxedStrategy<Fp> {
    any::<[u64; 4]>().prop_map(Fp::from_raw).boxed()
}
fn fq() -> BoxedStrategy<Fq> {
    any::<[u64; 4]>().prop_map(Fq::from_raw).boxed()
}
fn pallas_point() -> BoxedStrategy<pallas::Affine> {
    (1u64..u64::MAX)
        .prop_map(|k| (pallas::Point::generator() * pallas::Scalar::from(k)).to_affine())
        .boxed()
}
fn vesta_point() -> BoxedStrategy<vesta::Affine> {
    (1u64..u64::MAX)
        .prop_map(|k| (vesta::Point::generator() * vesta::Scalar::from(k)).to_affine())
        .boxed()
}
fn xy(p: pallas::Affine) -> (Fp, Fp) {
    let c = p.coordinates().unwrap();
    (*c.x(), *c.y())
}
fn ct() -> impl Strategy<Value = NoteCiphertext> {
    (fp(), fp(), fp()).prop_map(|(c0, c1, tag)| NoteCiphertext { c0, c1, tag })
}

fn slot() -> impl Strategy<Value = SlotStatement> {
    (
        any::<u32>(),
        fp(),
        (fp(), fp()),
        (pallas_point(), pallas_point()),
        (ct(), ct()),
        fp(),
        any::<bool>(),
    )
        .prop_map(|(h_anchor, r_anchor, nf, pk, ct, h_body, mint)| {
            // a mint has one output; the indexer leaves the other empty
            let second = if mint { (Fp::ZERO, Fp::ZERO) } else { xy(pk.1) };
            let ct1 = if mint { NO_CT } else { ct.1 };
            SlotStatement {
                h_anchor,
                r_anchor,
                nullifiers: [nf.0, nf.1],
                pk_eph: [xy(pk.0), second],
                ct: [ct.0, ct1],
                h_body,
                mint,
            }
        })
}

fn opening() -> impl Strategy<Value = StateOpening> {
    (
        fp(),
        any::<u64>(),
        fp(),
        any::<u64>(),
        fp(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(root, size, nf_root, nf_size, h_root, height, applied)| StateOpening {
                root,
                size,
                nf_root,
                nf_size,
                h_root,
                height,
                applied,
            },
        )
}

fn step() -> impl Strategy<Value = ProvenStep> {
    (
        any::<u32>(),
        any::<u32>(),
        prop::collection::vec(prop::option::of(slot()), 0..5),
        opening(),
        prop::collection::vec(fq(), 0..12),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(fp(), 0..12),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(
            |(a, b, slots, opening_after, instance_q, proof_q, instance_p, proof_p)| ProvenStep {
                first_height: a.min(b),
                height: a.max(b),
                slots,
                opening_after,
                instance_q,
                proof_q,
                instance_p,
                proof_p,
            },
        )
}

fn capture<C: CurveAffine>(
    scalar: BoxedStrategy<C::Scalar>,
    point: BoxedStrategy<C>,
) -> impl Strategy<Value = Capture<C>> {
    let event = prop_oneof![
        point.clone().prop_map(Event::CommonPoint),
        scalar.clone().prop_map(Event::CommonScalar),
        point.clone().prop_map(Event::ReadPoint),
        scalar.clone().prop_map(Event::ReadScalar),
        scalar.clone().prop_map(Event::Squeeze),
    ];
    (
        prop::collection::vec(scalar.clone(), 0..6),
        prop::collection::vec(event, 0..8),
        prop::collection::vec((scalar.clone(), point.clone()), 0..6),
        scalar.clone(),
        scalar.clone(),
        point,
        prop::collection::vec(scalar.clone(), 0..5),
        prop::collection::vec(prop::collection::vec(scalar, 0..4), 0..3),
    )
        .prop_map(
            |(instance, events, terms, w_scalar, u_scalar, g, u, opened)| Capture {
                instance,
                events,
                terms,
                w_scalar,
                u_scalar,
                g,
                u,
                opened,
            },
        )
}

fn refuses_a_byte_more_or_less<T>(
    bytes: &[u8],
    read: impl Fn(&[u8]) -> Result<T, String>,
) -> Result<(), TestCaseError> {
    prop_assert!(read(&bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.to_vec();
    longer.push(0);
    prop_assert!(read(&longer).is_err());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn a_proven_step_reads_back_from_its_bytes(step in step()) {
        let bytes = step.to_bytes();
        let read = ProvenStep::from_bytes(&bytes);
        prop_assert_eq!(read.as_ref(), Ok(&step));
        refuses_a_byte_more_or_less(&bytes, ProvenStep::from_bytes)?;
        // the version-1 form of a one-block step reads as the same step
        if step.first_height == step.height {
            let mut v1 = bytes.clone();
            v1[0] = 1;
            v1.drain(4..8);
            let read = ProvenStep::from_bytes(&v1);
            prop_assert_eq!(read.as_ref(), Ok(&step));
        }
    }

    #[test]
    fn a_slot_statement_reads_back_from_its_elements(st in slot()) {
        prop_assert_eq!(SlotStatement::from_elements(&st.to_elements()), Some(st));
        // all zeros read as a statement whose elements are all zeros (the
        // identity passes for a point): the wire tells an empty slot apart
        // by that rule, and the digest is the same either way
        let zeros = SlotStatement::from_elements(&[Fp::ZERO; SLOT_ELEMENTS]);
        prop_assert_eq!(zeros.map(|z| z.to_elements()), Some([Fp::ZERO; SLOT_ELEMENTS]));
    }

    #[test]
    fn the_heights_check_holds_exactly_when_the_wire_agrees_with_the_opening(
        first in any::<u32>(),
        height in any::<u32>(),
        open in any::<u32>(),
        mut step in step(),
    ) {
        step.first_height = first;
        step.height = height;
        step.opening_after.height = open;
        let expected = first <= height && height.checked_add(1) == Some(open);
        prop_assert_eq!(check_heights(&step).is_ok(), expected);
    }

    #[test]
    fn captures_and_states_read_back_from_their_bytes(
        cap_q in capture::<pallas::Affine>(fq(), pallas_point()),
        cap_p in capture::<vesta::Affine>(fp(), vesta_point()),
        keys_id in any::<[u8; 32]>(),
        index in any::<u32>(),
        next_height in any::<u32>(),
        s in fp(),
    ) {
        let q = cap_q.to_bytes();
        prop_assert_eq!(Capture::<pallas::Affine>::from_bytes(&q).unwrap().to_bytes(), q.clone());
        refuses_a_byte_more_or_less(&q, Capture::<pallas::Affine>::from_bytes)?;
        let p = cap_p.to_bytes();
        prop_assert_eq!(Capture::<vesta::Affine>::from_bytes(&p).unwrap().to_bytes(), p.clone());
        refuses_a_byte_more_or_less(&p, Capture::<vesta::Affine>::from_bytes)?;
        let chain = ChainState { keys_id, index, next_height, s, cap_q, cap_p };
        let b = chain.to_bytes();
        prop_assert_eq!(ChainState::from_bytes(&b).unwrap().to_bytes(), b.clone());
        refuses_a_byte_more_or_less(&b, ChainState::from_bytes)?;
        let client = ClientState { keys_id, index, s };
        let b = client.to_bytes();
        prop_assert_eq!(ClientState::from_bytes(&b).unwrap(), client);
        refuses_a_byte_more_or_less(&b, ClientState::from_bytes)?;
    }
}
