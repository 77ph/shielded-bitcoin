//! The in-circuit pieces of a verifier of variant A's transfer proofs, a
//! circuit over `Fq` (`docs/REPLAY-PROOF-A.md` §3.3). Piece by piece, each
//! measured: the transcript gadget (`transcript`), then the group
//! arithmetic of the inner-product argument over `vesta-ecc`.

pub mod transcript;
