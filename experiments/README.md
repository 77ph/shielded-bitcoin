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
| `cycle` | `docs/REMAINING.md` §2.3(a) (unbounded recursion on the MNT4-753 / MNT6-753 pairing cycle) | the outer constraint count in both directions of the cycle; with `--prove`, the outer setup and proof (killed at 9.4 GB on a 16 GB machine) |
