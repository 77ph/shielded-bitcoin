# Changes against upstream

This directory is a modified copy of the crate `halo2_proofs` 0.3.5
(crates.io; https://github.com/zcash/halo2), Copyright (c) 2020-2022 The
Electric Coin Company and (c) 2022 The Halo 2 developers, offered by its
authors under either the MIT license (`LICENSE-MIT`) or the Apache
License, Version 2.0 (`LICENSE-APACHE`), and redistributed here under the
Apache License, Version 2.0 (`NOTICE`). The modifications and the new
files are Copyright (c) 2026 PostCryptum Research (https://postcryptum.io/),
under the Apache License, Version 2.0.

Upstream files modified here (Apache License §4(b): this is the notice
that they were changed):

- `src/lib.rs`
- `src/plonk.rs` — the verifying key keeps the selector assignments
  (`selectors`), `from_parts` takes them; accessors made public
- `src/plonk/circuit.rs`, `src/plonk/lookup.rs` — read-only accessors
  made public (the constraint system, the queries' indices)
- `src/plonk/keygen.rs` — the selectors kept in the verifying key
- `src/plonk/permutation.rs` — `permutations()`, `from_permutations`
- `src/plonk/prover.rs` — `create_proof_with_openings`: an earlier
  proof's deferred claim opened inside this proof's multi-point argument
- `src/plonk/verifier.rs` — `verify_proof_with_openings`
- `src/poly/commitment.rs`, `src/poly/commitment/msm.rs`,
  `src/poly/commitment/verifier.rs` — the MSM's terms, `W`, `U` and the
  Lagrange generators readable; the claim's verification
- `src/poly/domain.rs` — `k()`, `n()` readable within the crate

New files, not from upstream:

- `src/poly/commitment/claim.rs` — `Claim`, a deferred inner-product claim
- `src/plonk/keys_io.rs`, `src/plonk/keys_io_test.rs` — reading and
  writing verifying and proving keys
- `src/plonk/claims_test.rs` — tests of the opened claims

`Cargo.toml` was edited for the vendored build (a workspace member; the
root `[patch.crates-io]` points the workspace's `halo2_proofs` here) and
its `license` field states the license the copy is redistributed under.
