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

> **Status: pre-alpha.** Nothing here has been audited, the deployments
> shipped here use a trusted setup from a published seed (anyone can forge
> proofs), and the only peg is a custodial development vault. Do not hold
> value with it.

## What works

| Layer | State |
|---|---|
| Profile (`docs/PROFILE.md`) | every open parameter of the paper fixed; departures listed in its §12 |
| Primitives | Poseidon (native + R1CS, pinned constants), Jubjub encodings, DiversifyHash |
| Core | key hierarchy, bech32m addresses, note encryption, leaves, nullifiers, 700-byte canonical envelope, note tree with historical paths |
| Circuit | 2-in/2-out transfer relation, 84 362 constraints, Groth16/BLS12-381; prove ≈ 1.5 s, verify ≈ 4 ms (16 threads) |
| Ceremony | `sb ceremony`: BGM17 multi-party setup (powers of tau, key derivation checked against arkworks, delta contributions, beacon), verifiable from files; `profile-new --ceremony-vk` (`docs/CEREMONY.md`) |
| Indexer | Bitcoin Core RPC / Esplora / Electrum / mock sources, carrier rule, normative acceptance order, per-block checkpoints with reorg rollback, JSON or PostgreSQL state |
| Wallet | scanning and sender recovery, note selection, anchor policy, change, input locks, reorg-safe rescan |
| Boundary | development **mint** into a custodial vault and **withdraw** via payout memos (`docs/BOUNDARY.md`) |
| CLI | `sb`: profile, wallets, sync, scan, mint, send, withdraw, payouts; carriers self-funded (fresh addresses), externally funded (`--no-broadcast` + `publish`) or relayed (`relay-serve`, `--relay`); indexer API (`serve`) and verified sync from it (`--chain light:`) |

Measured on this machine (release build): setup 1.5 s, prove 1.5 s,
verify 4 ms, envelope 700 bytes, carrier ≈ 830 vB.

## Layout

| Crate | Paper sections | Content |
|---|---|---|
| `crates/sb-primitives` | §2, §A.1 | Poseidon over BLS12-381 `Fr`, domain tags, Jubjub encodings, `DiversifyHash` |
| `crates/sb-core` | §5, §6, §9, §12, §13, §A.3, §A.5 | keys, addresses, notes, encryption, leaves, nullifiers, envelope codec, `h_body`, note tree |
| `crates/sb-circuit` | §14, §B | R1CS gadgets, the transfer circuit, Groth16 setup/prove/verify |
| `crates/sb-indexer` | §8, §11, §15, §A.4, §A.6, §A.7 | chain sources, carrier extraction, replay, state, reorg handling, dev mint |
| `crates/sb-wallet` | §10, §16, §C | scanning, recovery, note selection, anchor policy, transfer construction |
| `crates/sb-ceremony` | §8.4 | BGM17 multi-party setup: powers of tau, key derivation, delta contributions, beacon |
| `crates/sb-cli` | — | `sb` command-line tool |
| `docs/` | — | `PROFILE.md` (normative profile), `BOUNDARY.md` (dev peg, fee funding), `CEREMONY.md` (parameter ceremony), `TEST_VECTORS.md`, `RUNS.md` |
| `deployments/` | profile §9 | deployment profiles |

## Quick start (signet)

```sh
cargo build --release
SB="./target/release/sb --profile deployments/signet-dev-1.json --data-dir sb-data"

$SB wallet-new --name alice        # prints the shielded and the funding address
# send signet coins to the funding address (any signet faucet), then:
$SB sync                           # replay from the profile's activation height
$SB mint --name alice --amount 20000   # pays the dev vault, publishes the mint envelope
$SB sync && $SB scan --name alice      # after confirmation: balance 20000
$SB send --name alice --to tsb1... --amount 5000   # proves and publishes a private transfer
$SB sync && $SB scan --name alice      # change note appears, inputs marked spent
$SB withdraw --name alice --amount 3000 --to tb1q...   # dev boundary: pays the operator + payout memo
$SB payouts --name operator            # operator: pays pending withdraw requests from the vault
```

`--chain` selects the block source and the publisher: `esplora:<url>`
(default mempool.space signet), `electrum:ssl://host:port` (also `tcp://`;
blocks are rebuilt from `id_from_pos` + `transaction.get` in batches and
checked against the header's merkle root; a self-signed server is pinned by
certificate fingerprint: `sb electrum-fingerprint host:port`, then
`electrum:ssl-pin://host:port/<sha256>`), `rpc:<url>:<user>:<pass>` or
`rpc-cookie:<url>:<path>`
(UTXOs via `scantxoutset`, broadcast via `sendrawtransaction`, no node
wallet needed). Everything under `sb-data*/` is local and git-ignored.

**Trust boundary of chain sources.** Replay verifies every envelope itself,
so no source can forge a shielded transfer. What a source is trusted for is
*chain selection*: which block hash sits at a height and where the tip is.
Esplora and Electrum are remote APIs; the indexer checks that each block
hashes to the hash it asked for, extends the block replayed before it, and
(Electrum) matches its header's merkle root, so a server cannot alter or
truncate a block, but a server that serves a self-consistent fake chain
would lead the indexer onto a fake history. Proof-of-work and difficulty
are not validated. For anything that holds value, run your own node and use
the RPC source; that is also the assumption the paper makes about the
publication layer.

**Fee funding.** A carrier's inputs link carriers at the Bitcoin layer,
outside the paper's privacy claims (§20.5). `sb` offers three models, all
outside the profile: self-funding from a per-wallet fee wallet with fresh
addresses (the change chain still clusters a wallet's carriers), external
funding of an unfunded carrier template by any other wallet (Bitcoin Core's
`fundrawtransaction` or `sb publish --name <other wallet>`), and a sponsored
relayer (`sb relay-serve`, `sb send --relay`) that checks and pays
transfers from its own coins. Who pays, what each party sees and what
happens when a service is down are stated per model in "Fee funding" in
`docs/BOUNDARY.md`.

**Verified sync from an indexer.** `sb serve` exposes an indexer's replay
as an API (`/tip`, `/block/<height|hash>`): per block, the header, every
transaction the carrier rule looks at, a BIP 37 partial merkle tree for
them and the indexer's own `R[h]`. A client with `--chain
light:<url>` checks each tree against the header, replays the carriers
itself and compares its roots with the indexer's claims, so the indexer
cannot forge, alter or reorder a carrier; with `light:<url>|<full source>`
the block hashes are also cross-checked against that source, so it cannot
choose the chain either. What it can do is **omit** carriers, which the
client sees only as a root mismatch (against the indexer's own claim, or
against a second indexer or a full replay). This is the "verification of an
indexer response against Bitcoin data" option of the paper's §22.2; the
succinct proof of replay the paper asks for is open research and not
implemented. A client in this mode publishes through the full source or
a relayer.

Indexer state lives in a JSON file by default; `--db "<libpq string>"`
(e.g. `host=/var/run/postgresql dbname=shielded_bitcoin`) keeps it in
PostgreSQL instead, one transaction per replayed block, rolled back by
height on a reorganisation. Tables are shared across deployments and keyed
by deployment name.

Wallet files are encrypted with a passphrase (Argon2id, 64 MiB / 3 passes,
then ChaCha20-Poly1305). The passphrase comes from `--passphrase-file`, the
`SB_WALLET_PASSPHRASE` environment variable, or a terminal prompt.
`wallet-new --no-encrypt` writes a plaintext file; `wallet-encrypt` migrates
one (or changes the passphrase).

### Private signet

`scripts/localsignet.sh` stands up a signet you can mine yourself
(`signetchallenge=51`), funds a wallet and mines on demand; it needs Bitcoin
Core binaries and a Core source checkout for `contrib/signet/miner`.
`deployments/localsignet-dev.json` is the matching profile (activation 100,
dev vault held by the `operator` wallet).

## Static build

A binary built on one distribution often fails on another over the glibc
version. With `musl-tools` installed (`apt install musl-tools`) the `sb`
binary builds fully static and runs on any x86-64 Linux:

```sh
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --release -p sb-cli --target x86_64-unknown-linux-musl
# target/x86_64-unknown-linux-musl/release/sb, about 12 MB, static-pie
```

## Tests

```sh
cargo test --release
```

Covers: primitives against the arkworks reference, codec canonicality and
rejections, gadget/native equivalence, every circuit block rejecting its
violation, every public input bound by the proof, replay acceptance and all
rejection classes, reorg rollback, fresh-replay determinism, state and wallet
persistence, and a two-wallet mint → pay → change → reorg → repay flow.
`cargo test -p sb-indexer --release --test esplora_live -- --ignored` and
`--test electrum_live` hit public signet; `--test pg_store` needs
`SB_TEST_PG` pointing at a PostgreSQL database.

## Coverage

```sh
cargo llvm-cov --workspace --release --ignore-run-fail \
  --ignore-filename-regex 'chain/fake\.rs' -- --include-ignored
```

Measured in CI on 28 October 2026 (PostgreSQL included, live network tests
best effort): **93 % of lines, 89 % of regions**; CI fails below 90 % of
lines. The ceremony commands on the full-size circuit run only with
`SB_CEREMONY_FULL=1` (minutes) and are not counted. The in-process fake Esplora / RPC / Electrum servers
(`sb-indexer/src/chain/fake.rs`) are test support and are excluded. What
stays uncovered is of four kinds: error arms of `?` on multi-line calls,
interactive passphrase prompts, defensive branches that cannot be reached
through the public API (for example a non-canonical re-serialisation that
the strict parser already rejects), and a few corruption arms of rows inside
the PostgreSQL store.

## Prior art

As of 28 October 2026 there is no official or production implementation.
Two proof-of-concepts exist and were studied before starting this project:

* [bitsagarob/shielded-btc-probe](https://github.com/bitsagarob/shielded-btc-probe) —
  Rust + arkworks, 2-in/2-out Groth16, Electrum indexer, ran on mainnet and
  signet. "Insecure by design, not usable today." Its `PROFILE.md` audit of
  the paper was a useful cross-check.
* [harshjv/shielded-bitcoin-poc](https://github.com/harshjv/shielded-bitcoin-poc) —
  TypeScript + circom browser demo, dev-only setup.

This project is written from scratch with its own profile, a workspace meant
to grow into a real indexer and wallet, and test-vector-first interoperability.

## Roadmap

1. ~~Primitives~~ 2. ~~Core~~ 3. ~~Circuit~~ 4. ~~Indexer~~ 5. ~~Wallet + CLI~~
6. ~~End-to-end runs on real nodes~~ (private and public signet, see
   `docs/RUNS.md`).
7. ~~Encrypted wallet files~~, ~~profile versioning rules~~, ~~Electrum
   source~~, ~~PostgreSQL-backed indexer state~~, ~~fee-funding models
   (fresh addresses, external funding, sponsored relayer)~~, ~~verified
   sync from an indexer (`sb serve`, `--chain light:`)~~, ~~ceremony
   tooling~~, ~~proving-key cache~~.
8. ~~Import of public powers-of-tau transcripts~~; outside review of the
   ceremony tooling and a ceremony with independent participants are
   operational steps for whoever deploys, not code.

Rust 1.85+ (edition 2024).
