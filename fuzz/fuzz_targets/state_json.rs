//! Both indexers' state files (`ReplayState::from_json`): the operator's
//! own file, but a loader all the same. Never panics; a state that loads
//! saves and loads back equal, with its commitments in step.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, b)) = data.split_first() else {
        return;
    };
    let Ok(s) = std::str::from_utf8(b) else {
        return;
    };
    if sel & 1 == 0 {
        if let Ok(st) = sb_indexer::ReplayState::from_json(s) {
            assert!(st.check_commitments());
            let again = st.to_json();
            assert_eq!(sb_indexer::ReplayState::from_json(&again).unwrap(), st);
        }
    } else if let Ok(st) = sba_indexer::ReplayState::from_json(s) {
        let _ = st.opening(0);
        let again = st.to_json();
        assert_eq!(sba_indexer::ReplayState::from_json(&again).unwrap(), st);
    }
});
