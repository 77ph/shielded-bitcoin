//! The small variable-length parsers: the payout memo of both wallets, the
//! proxy URL, an outpoint, and both families' deployment files. Never
//! panic; a memo that parses rebuilds to its bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, b)) = data.split_first() else {
        return;
    };
    match sel % 4 {
        0 => {
            if let Some(r) = sb_wallet::payout::parse_payout_memo(b) {
                assert_eq!(
                    sb_wallet::payout::build_payout_memo(r.amount, &r.script_pubkey),
                    b
                );
            }
            if let Some(r) = sba_wallet::payout::parse_payout_memo(b) {
                assert_eq!(
                    sba_wallet::payout::build_payout_memo(r.amount, &r.script_pubkey),
                    b
                );
            }
        }
        1 => {
            let Ok(s) = std::str::from_utf8(b) else {
                return;
            };
            let _ = sb_common::net::Proxy::parse(s);
            let _ = sb_common::htlc::parse_outpoint(s);
        }
        2 => {
            let Ok(s) = std::str::from_utf8(b) else {
                return;
            };
            if let Ok(d) = sb_indexer::Deployment::from_json(s) {
                let again = serde_json::to_string(&d).unwrap();
                let d2 = sb_indexer::Deployment::from_json(&again).unwrap();
                assert_eq!(serde_json::to_string(&d2).unwrap(), again);
            }
        }
        _ => {
            let Ok(s) = std::str::from_utf8(b) else {
                return;
            };
            if let Ok(d) = sba_indexer::Deployment::from_json(s) {
                let again = d.to_json();
                assert_eq!(
                    sba_indexer::Deployment::from_json(&again)
                        .unwrap()
                        .to_json(),
                    again
                );
            }
        }
    }
});
