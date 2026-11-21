//! The paper family's envelope parser (`sb-core::envelope`) on any bytes:
//! never panics; what it accepts is canonical (re-serialises to the input)
//! and a candidate; the per-kind parsers and the body hash hold too.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sb_core::envelope::{
    BODY_LEN, Envelope, MintEnvelope, SWAP_BODY_LEN, SwapBody, SwapEnvelope, TransferBody,
    TransferEnvelope, is_candidate, parse_envelope,
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
            Envelope::Swap(s) => {
                let _ = s.body.h_body(&salt);
                assert_eq!(
                    SwapBody::parse(&data[..SWAP_BODY_LEN]).as_ref(),
                    Ok(&s.body)
                );
                s.to_bytes()
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
    // the kind parsers on bytes of any kind
    let _ = TransferEnvelope::parse(data);
    let _ = TransferBody::parse(data);
    let _ = SwapEnvelope::parse(data);
    let _ = SwapBody::parse(data);
    let _ = MintEnvelope::parse(data);
});
