# Experiments

Standalone measurements that back a number in the documents, kept out of
the workspace so that they do not add their dependencies (other curves)
to every build. Each has its own `Cargo.toml`; run with
`cargo run --release` inside the directory.

| Directory | Backs | Prints |
|---|---|---|
| `twochain` | `docs/REPLAY-PROOF.md` §4.4 (one native recursion level on the BLS12-377 / BW6-761 two-chain) | the BW6-761 constraint count of verifying one BLS12-377 Groth16 proof with 17 public inputs in-circuit |
