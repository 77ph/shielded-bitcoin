# Experiments

Standalone measurements that back a number in the documents, kept out of
the workspace so that they do not add their dependencies (other curves)
to every build. Each has its own `Cargo.toml`; run with
`cargo run --release` inside the directory.

| Directory | Backs | Prints |
|---|---|---|
| `twochain` | `docs/REPLAY-PROOF.md` §4.4, `docs/REMAINING.md` §2.3(b) (one native recursion level on a 2-chain) | the outer constraint count of verifying one Groth16 proof with 17 public inputs in-circuit, for BLS12-377 inside BW6-761 and for BLS12-381 inside BW6-767; with `--prove`, the outer setup, proving and verification times (the BW6-767 setup fails: its scalar field has 2-adicity 1) |
| `halo2` | `docs/VARIANT-A.md` §4 (the cost of a Halo 2 / IPA shielded proof) | proof size, proving and verification time of Zcash Orchard action bundles of 1–4 actions with the `orchard` crate, the nearest production relation to this project's transfer |
| `halo2-transfer` | `docs/VARIANT-A.md` §4.2 (S1: this profile's transfer relation in Halo 2) | the smallest k, proof size, key generation, proving and verification time of the 2-in-2-out transfer relation of `PROFILE.md` §8 expressed in Halo 2 with `halo2_gadgets` on Pallas, for one transfer and for two in one proof; `--mock-only` stops after the mock prover |
| `halo2-accumulate` | `docs/REPLAY-PROOF-A.md` §2 (verification of n variant-A transfer proofs: one by one, batched into one MSM, accumulated with the deferred claims settled at the end) | per-proof verification time in the three modes for n = 1, 4, 16, 64; the prover-side `G` cost; the accumulator size |
| `vesta-ecc` | `docs/REPLAY-PROOF-A.md` §3.3 (the first piece of a recursive verifier for variant A) | a library, not a measurement: `halo2_gadgets`' ECC chip (v0.5.0) ported from Pallas points in an `Fp` circuit to Vesta points in an `Fq` circuit, with the chip's own tests (`cargo test --release`); scalars are `Fp` elements embedded in `Fq` |
| `halo2-verifier` | `docs/REPLAY-PROOF-A.md` §3.3 (the in-circuit verifier of variant A's proofs, piece by piece) | `cargo test --release -- --nocapture`: the transcript gadget reproduces the native sponge's challenges (a transfer-shaped transcript fits k = 13); the capture of a real proof's transcript events and accumulated MSM; the verifier circuit over `Fq` that walks the events and checks the MSM over the Vesta chip, with the instance commitment recomputed from the statement, fitting k = 15; `cargo test --release prove_the_verifier_circuit -- --ignored --nocapture` proves it (13.1 s keygen, 4.5 s, 50 ms); `shadow.rs` recomputes every scalar of that MSM natively as the verifier does (checked term by term), the specification of the `Fp` circuit; `field.rs` is the `Fp` chip for it |
| `halo2_proofs-patched` | `docs/REPLAY-PROOF-A.md` §3.3 | not a measurement: `halo2_proofs` 0.3.5 vendored with read-only accessors made public (the MSM's terms, `W`, `U`, the Lagrange generators, the key's commitments and constraint system, the queries' indices), used by `halo2-verifier` through `[patch.crates-io]` |
| `cycle` | `docs/REMAINING.md` §2.3(a) (unbounded recursion on the MNT4-753 / MNT6-753 pairing cycle) | the outer constraint count in both directions of the cycle; with `--prove`, the outer setup and proof (killed at 9.4 GB on a 16 GB machine) |
