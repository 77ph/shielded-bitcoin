//! Variant A's envelope parser (`sba-core::envelope`) on any bytes: the
//! same invariants as `envelope_s`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sba_core::envelope::{
    BODY_LEN, Envelope, MintEnvelope, TransferBody, TransferEnvelope, is_candidate, parse_envelope,
};

fuzz_target!(|data: &[u8]| {
    let salt = [7u8; 32];
    if let Ok(env) = parse_envelope(data) {
        assert!(is_candidate(data));
        let back = match &env {
            Envelope::Transfer(t) => {
                let _ = t.body.h_body(&salt);
                assert_eq!(TransferBody::parse(&data[..BODY_LEN]).as_ref(), Ok(&t.body));
                t.to_bytes()
            }
            Envelope::Mint(m) => {
                let _ = m.h_body(&salt);
                let _ = m.derive();
                m.to_bytes()
            }
        };
        assert_eq!(
            back, data,
            "an accepted envelope re-serialises to its bytes"
        );
    }
    let _ = TransferEnvelope::parse(data);
    let _ = TransferBody::parse(data);
    let _ = MintEnvelope::parse(data);
});
