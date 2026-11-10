//! Variant A's accumulated replay proof (`docs/REPLAY-PROOF-A.md`): the
//! verifier of a Halo 2 proof split by field over the Pasta cycle — the
//! native transcript for either curve (`native`), the transcript gadget
//! (`transcript`), the group side (`verifier`, one body per side) and the
//! field side (`fieldside`) — the batch relation (`batch`), the steps that
//! compose them (`step`…`step5`), the proven step on the wire and its
//! decider (`wire`), and the split transcript of §3.6 (`split`,
//! `verifier_split`), the chain of steps under one key set (`chain`) and
//! what it keeps between runs (`persist`). Development-grade: the
//! measurements are the study's.

// the tests are measurement scaffolding: long tuples and clones are theirs
#![cfg_attr(
    test,
    allow(
        clippy::type_complexity,
        clippy::cloned_ref_to_slice_refs,
        clippy::too_many_arguments,
        clippy::needless_range_loop
    )
)]
pub mod batch;
pub mod capture;
pub mod chain;
pub mod field;
pub mod fieldside;
pub mod fixed;
pub mod native;
pub mod persist;
pub mod prover;
pub mod sample;
pub mod shadow;
pub mod split;
pub mod step;
pub mod step2;
pub mod step3;
pub mod step4;
pub mod step5;
pub mod transcript;
pub mod verifier;
pub mod verifier_split;
pub mod wire;
