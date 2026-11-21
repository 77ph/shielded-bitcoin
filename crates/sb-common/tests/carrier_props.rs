//! The carrier rules as properties: what `carrier_output` and
//! `envelope_tapscript` publish for any payload under either family's
//! prefix is located again, with its memo, and only under that prefix; a
//! second carrier output or witness is refused; the witness rule's
//! chunking round-trips across the push limit.
use bitcoin::TxOut;
use proptest::prelude::*;
use sb_common::carrier::{
    Candidate, CarrierError, CarrierMode, MEMO_MAGIC, carrier_output, memo_output,
};
use sb_common::chain::mock::{carrier_tx, carrier_tx_with_memo, carrier_tx_witness};

const PREFIX_S: &[u8] = b"btc\x01";
const PREFIX_A: &[u8] = b"btc\x02";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn both_rules_locate_what_they_publish(
        family_a: bool,
        rest in prop::collection::vec(any::<u8>(), 0..1200),
        memo_rest in prop::collection::vec(any::<u8>(), 0..80),
        with_memo: bool,
        nonce: u32,
    ) {
        let (prefix, other) = if family_a { (PREFIX_A, PREFIX_S) } else { (PREFIX_S, PREFIX_A) };
        let envelope = [prefix, &rest[..]].concat();
        let memo = [&MEMO_MAGIC[..], &memo_rest[..]].concat();
        let located = Candidate {
            envelope: envelope.clone(),
            memo: with_memo.then(|| memo.clone()),
        };

        // the OP_RETURN rule
        let tx = if with_memo {
            carrier_tx_with_memo(&envelope, &memo, nonce)
        } else {
            carrier_tx(&envelope, nonce)
        };
        prop_assert_eq!(CarrierMode::OpReturn.extract(&tx, prefix), Some(Ok(located.clone())));
        prop_assert_eq!(CarrierMode::OpReturn.extract(&tx, other), None);
        prop_assert_eq!(CarrierMode::Witness.extract(&tx, prefix), None);
        let mut twice = tx.clone();
        twice.output.push(carrier_output(&envelope));
        prop_assert_eq!(
            CarrierMode::OpReturn.extract(&twice, prefix),
            Some(Err(CarrierError::MultipleEnvelopes))
        );

        // the witness rule, the memo staying in an OP_RETURN
        let outputs: Vec<TxOut> = if with_memo { vec![memo_output(&memo)] } else { vec![] };
        let wtx = carrier_tx_witness(&envelope, nonce, outputs);
        prop_assert_eq!(CarrierMode::Witness.extract(&wtx, prefix), Some(Ok(located)));
        prop_assert_eq!(CarrierMode::Witness.extract(&wtx, other), None);
        prop_assert_eq!(CarrierMode::OpReturn.extract(&wtx, prefix), None);
        let mut twice = wtx.clone();
        twice.input.push(wtx.input[0].clone());
        prop_assert_eq!(
            CarrierMode::Witness.extract(&twice, prefix),
            Some(Err(CarrierError::MultipleWitnessEnvelopes))
        );
    }
}
