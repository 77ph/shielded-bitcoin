//! The in-circuit pieces of a verifier of variant A's transfer proofs and
//! of the recursion's own proofs (`docs/REPLAY-PROOF-A.md` §3.3–3.4):
//! the native transcript for either curve (`native`), the transcript gadget
//! (`transcript`), the group side (`verifier`, one body for both sides) and
//! the field side (`fieldside`), each measured.

pub mod batch;
pub mod capture;
pub mod field;
pub mod fieldside;
pub mod fixed;
pub mod native;
pub mod sample;
pub mod shadow;
pub mod step;
pub mod step2;
pub mod step3;
pub mod transcript;
pub mod verifier;
