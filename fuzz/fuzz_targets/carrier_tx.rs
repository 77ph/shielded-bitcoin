//! The carrier rules over any transaction the consensus decoder accepts,
//! under both rules and both families' prefixes: never panics, and what is
//! located starts with the prefix.
#![no_main]
use bitcoin::Transaction;
use libfuzzer_sys::fuzz_target;
use sb_common::carrier::{CarrierMode, MEMO_MAGIC};

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = bitcoin::consensus::deserialize::<Transaction>(data) else {
        return;
    };
    let _ = tx.compute_txid();
    for prefix in [
        &sb_core::envelope::CANDIDATE_PREFIX[..],
        &sba_core::envelope::CANDIDATE_PREFIX[..],
    ] {
        for mode in [CarrierMode::OpReturn, CarrierMode::Witness] {
            let r = mode.extract(&tx, prefix);
            assert_eq!(r.is_some(), mode.is_carrier(&tx, prefix));
            if let Some(Ok(c)) = r {
                assert!(c.envelope.starts_with(prefix));
                if let Some(m) = c.memo {
                    assert!(m.starts_with(&MEMO_MAGIC));
                }
            }
        }
    }
});
