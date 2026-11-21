//! The relayer's and the indexer API's request reader on any bytes: never
//! panics, and a body it returns is within the limit.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::{BufReader, Cursor};

fuzz_target!(|data: &[u8]| {
    if let Ok((method, path, body)) =
        sb_common::http::read_request_from(BufReader::new(Cursor::new(data)))
    {
        assert!(!method.is_empty() && !path.is_empty());
        assert!(body.len() <= 16 * 1024);
    }
});
