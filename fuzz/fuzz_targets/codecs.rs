//! The fixed-size codecs of both families: field elements, compressed
//! points, note ciphertexts, payment addresses as bytes and as bech32m
//! text. Never panic; what decodes re-encodes to the input (canonical).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, b)) = data.split_first() else {
        return;
    };
    match sel % 6 {
        0 => {
            if let Ok(f) = sb_primitives::encoding::fr_from_bytes(b) {
                assert_eq!(&sb_primitives::encoding::fr_to_bytes(&f)[..], b);
            }
            if let Ok(f) = sba_primitives::encoding::fp_from_bytes(b) {
                assert_eq!(&sba_primitives::encoding::fp_to_bytes(&f)[..], b);
            }
            if let Ok(s) = sb_primitives::scalar::scalar_from_bytes(b) {
                assert_eq!(&sb_primitives::scalar::scalar_to_bytes(&s)[..], b);
            }
            if let Ok(arr) = <[u8; 32]>::try_from(b) {
                let _ = sb_core::envelope::bytes_to_fr_253(&arr);
                let _ = sba_core::envelope::bytes_to_fp_254(&arr);
            }
        }
        1 => {
            if let Ok(p) = sb_primitives::encoding::point_from_bytes(b) {
                assert_eq!(&sb_primitives::encoding::point_to_bytes(&p)[..], b);
            }
            if let Ok(p) = sba_primitives::encoding::point_from_bytes(b) {
                assert_eq!(&sba_primitives::encoding::point_to_bytes(&p)[..], b);
            }
        }
        2 => {
            if let Ok(c) = sb_core::note::NoteCiphertext::from_bytes(b) {
                assert_eq!(&c.to_bytes()[..], b);
            }
            if let Ok(c) = sba_core::note::NoteCiphertext::from_bytes(b) {
                assert_eq!(&c.to_bytes()[..], b);
            }
        }
        3 => {
            if let Ok(a) = sb_core::address::PaymentAddress::from_bytes(b) {
                assert_eq!(&a.to_bytes()[..], b);
            }
            if let Ok(a) = sba_core::address::PaymentAddress::from_bytes(b) {
                assert_eq!(&a.to_bytes()[..], b);
            }
        }
        4 => {
            let Ok(s) = std::str::from_utf8(b) else {
                return;
            };
            if let Ok((net, a)) = sb_core::address::PaymentAddress::decode(s) {
                assert!(a.encode(net).eq_ignore_ascii_case(s));
            }
        }
        _ => {
            let Ok(s) = std::str::from_utf8(b) else {
                return;
            };
            if let Ok((net, a)) = sba_core::address::PaymentAddress::decode(s) {
                assert!(a.encode(net).eq_ignore_ascii_case(s));
            }
        }
    }
});
