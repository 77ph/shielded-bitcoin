//! The chain prover's and the client's persisted state and the transcript
//! captures (`sba-replay::persist`): never panic on any bytes; what reads
//! re-serialises to its bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use pasta_curves::{pallas, vesta};
use sba_replay::capture::Capture;
use sba_replay::persist::{ChainState, ClientState};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = ClientState::from_bytes(data) {
        assert_eq!(s.to_bytes(), data);
    }
    if let Ok(s) = ChainState::from_bytes(data) {
        assert_eq!(s.to_bytes(), data);
    }
    if let Ok(c) = Capture::<pallas::Affine>::from_bytes(data) {
        assert_eq!(c.to_bytes(), data);
    }
    if let Ok(c) = Capture::<vesta::Affine>::from_bytes(data) {
        assert_eq!(c.to_bytes(), data);
    }
});
