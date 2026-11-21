//! A proven step off the wire (`sba-replay::wire`): what a light client
//! reads from whoever serves it steps. Never panics; a version-2 step that
//! reads re-serialises to its bytes, a version-1 one reads back from its
//! own serialisation; the heights check, the two digests and the slot
//! statements' element round trip hold on whatever was read.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sba_core::batch::{SlotStatement, batch_digest};
use sba_replay::chain::check_heights;
use sba_replay::wire::ProvenStep;

fuzz_target!(|data: &[u8]| {
    let Ok(step) = ProvenStep::from_bytes(data) else {
        return;
    };
    let bytes = step.to_bytes();
    if data.first() == Some(&2) {
        assert_eq!(bytes, data, "a version-2 step re-serialises to its bytes");
    } else {
        assert_eq!(ProvenStep::from_bytes(&bytes).as_ref(), Ok(&step));
    }
    let _ = check_heights(&step);
    let _ = batch_digest(&step.slots);
    let _ = step.opening_after.digest();
    for s in step.slots.iter().flatten() {
        assert_eq!(SlotStatement::from_elements(&s.to_elements()), Some(*s));
    }
});
