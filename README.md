# shielded-bitcoin

An independent implementation of
[**Shielded Bitcoin: Private Transfers on the Bitcoin L1**](https://www.allocinit.xyz/uploads/shielded-bitcoin.pdf)
(Shikhelman, Komarov, Moskvin, [alloc] init, 24 September 2026).

Shielded Bitcoin is a *metaprotocol*: encrypted notes, nullifiers and Groth16
transfer proofs are published in a single `OP_RETURN` output of an ordinary
Bitcoin transaction, and every indexer rebuilds the shielded state (note tree,
nullifier set, per-block roots) by deterministic replay of accepted envelopes
in block order. **No change to Bitcoin consensus is required** — this is not a
soft fork or a hard fork.

> **Status: pre-alpha.** Nothing here has been audited, the trusted setup is
> a published seed, and there is no production peg. Do not hold value with it.

## Prior art

As of 28 October 2026 there is no official or production implementation.
Two proof-of-concepts exist and were studied before starting this project:

* [bitsagarob/shielded-btc-probe](https://github.com/bitsagarob/shielded-btc-probe) —
  Rust + arkworks, 2-in/2-out Groth16, Electrum indexer, ran on mainnet and
  signet. "Insecure by design, not usable today." Its `PROFILE.md` audit of
  the paper was a useful cross-check.
* [harshjv/shielded-bitcoin-poc](https://github.com/harshjv/shielded-bitcoin-poc) —
  TypeScript + circom browser demo, dev-only setup.

This project is written from scratch, with its own implementation profile
(`docs/PROFILE.md`), a workspace layout meant to grow into a real indexer and
wallet, and a test-vector-first approach so that other implementations can
interoperate.

## Layout

| Crate | Paper sections | Content |
|---|---|---|
| `crates/sb-primitives` | §2, §A.1 | Poseidon over BLS12-381 `Fr`, domain tags, Jubjub encodings, `DiversifyHash` |
| `crates/sb-core` | §5, §6, §9, §12, §13, §A.3, §A.5 | keys, addresses, notes, encryption, leaves, nullifiers, envelope serialisation, `h_body`, note tree |
| `crates/sb-circuit` | §14, §B | R1CS gadgets, the transfer circuit, Groth16 setup/prove/verify |
| `crates/sb-indexer` | §8, §11, §15, §A.4, §A.6, §A.7 | chain sources (Bitcoin Core RPC/REST, Esplora, mock), carrier extraction, replay, state persistence, reorg handling |
| `crates/sb-wallet` | §10, §16, §C | scanning, recovery, note selection, anchor policy, transfer construction |
| `crates/sb-cli` | — | `sb` command-line tool |
| `docs/` | — | `PROFILE.md` (normative profile), design notes, test vectors |
| `deployments/` | §9 of the profile | deployment profiles (signet, regtest) |

## Roadmap

1. **Primitives** — Poseidon (native + R1CS), Jubjub encodings, DiversifyHash, pinned test vectors.
2. **Core** — key hierarchy, addresses (bech32m), note encryption, leaf/nullifier, canonical envelope codec with property tests, note tree.
3. **Circuit** — transfer relation, Groth16 (insecure dev setup), constraint-count and timing report, negative tests (every Appendix B block must fail when violated).
4. **Indexer** — replay engine against a mock chain, then Bitcoin Core / Esplora backends, checkpoints and reorg rollback, determinism test (two replays of the same history → identical state).
5. **Wallet + CLI** — `sb init | address | sync | scan | send | status`, end-to-end on regtest.
6. **Dev boundary** — non-normative mint/withdraw for test networks; signet run.
7. Later: Electrum backend, light-client sync, ceremony tooling, upgrade/versioning rules.

## Build

```sh
cargo build --release
cargo test
```

Rust 1.85+ (edition 2024).
