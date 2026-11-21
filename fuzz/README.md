# Fuzzing

The code that reads what nobody vouched for, under libFuzzer: an envelope
off the chain, a script or a transaction under the carrier rules, a proven
step a light client is served, the prover's own files, the codecs, the
deployment and state files, an HTTP request line — and, structure-aware,
the two indexers over generated chains with reorganisations. The targets
state what must hold on any input: no panic, and for a parser that accepts,
canonicality (the input re-serialises from what was read); for an indexer,
that the state after reorganisations is a fresh replay's.

This directory is its own Cargo workspace (the root excludes it), in the
`cargo-fuzz` layout. It builds with the nightly toolchain `cargo fuzz`
needs; the crates themselves stay on stable.

## Running

```sh
cargo install cargo-fuzz            # once
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run envelope_s -s none -- -max_total_time=600 seeds/envelope_s
```

`-s none` turns the sanitizer off: the workspace has no `unsafe` of its
own, the failures looked for are panics and aborts, and the build is
several times faster. `seeds/<target>/` holds a committed seed corpus —
one well-formed input of each shape the parser accepts (written by
`cargo run --release --example seeds`), plus the minimised input of every
crash found so far (`regress-*`), so a run starts on the accepting paths
and re-checks the fixed bugs first. The working corpus a run grows goes to
`corpus/<target>/` (ignored by git); crashes land in `artifacts/<target>/`.

To reproduce a crash: `cargo +nightly fuzz run <target> -s none
artifacts/<target>/crash-…`. To run every target for a while, from this
directory:

```sh
for t in $(cargo +nightly fuzz list); do
  cargo +nightly fuzz run $t -s none -- -max_total_time=600 -rss_limit_mb=1024 seeds/$t &
done; wait
```

## Targets

| Target | Reads | Must hold |
|---|---|---|
| `envelope_s` | `sb_core::envelope::parse_envelope` and the kind parsers on any bytes | no panic; an accepted envelope re-serialises to the input and is a candidate; the body parsers agree on the body |
| `envelope_a` | `sba_core::envelope` likewise | the same |
| `carrier_script` | one script of any bytes as an OP_RETURN output (alone, twice, beside a memo) and as the tapscript of a script-path witness (with/without signature and annex), under both prefixes | no panic; a located envelope starts with the prefix asked for, a memo with its magic; a lone OP_RETURN candidate is exactly `carrier_output` of its payload; a located tapscript is exactly `envelope_tapscript` of its payload under the script's key (the rules accept only the canonical form) |
| `carrier_tx` | any transaction the consensus decoder accepts, both rules, both prefixes | no panic; a located envelope starts with the prefix |
| `proven_step` | `ProvenStep::from_bytes` — what a light client reads from whoever serves it steps | no panic; a version-2 step re-serialises to the input, a version-1 one reads back from its serialisation; `check_heights`, the batch digest, the opening digest and the slot statements' element round trip hold |
| `persist` | `ChainState`, `ClientState`, `Capture` (both curves) from bytes | no panic; what reads re-serialises to the input |
| `codecs` | field elements, compressed points, note ciphertexts, addresses as bytes and bech32m text, both families | no panic; what decodes re-encodes to the input |
| `strings` | payout memos (both wallets), the proxy URL, an outpoint, both deployment files | no panic; a memo that parses rebuilds to its bytes; a deployment that loads saves and loads back the same |
| `state_json` | both indexers' state files | no panic; a state that loads has its commitments in step and saves and loads back equal |
| `http_request` | the relayer's and the API's request reader on any bytes | no panic; a body returned is within the limit |
| `indexer_s` | the paper family's indexer over a generated chain: blocks of mints (paid and underpaid), the one valid transfer, flipped copies of it and of a mint, raw and foreign candidates, memos, two carriers in one transaction; reorganisations to any depth down to the activation; syncs | no panic; synced to the tip after every operation; the commitments in step; at the end the state equals a fresh indexer's replay of the final chain; one event per carrier; the nullifier set is the events' nullifiers |
| `indexer_a` | variant A's indexer (the one replaying public signet) over the same grammar, the mint and the transfer from its test world | the same, with the nullifier tree holding the set exactly |

The grammar the two indexer targets share is `src/lib.rs`
(`arbitrary`-derived operations), and each target prepares its family's
valid transfer once (a proof, seconds) in a `LazyLock` fixture; each
input then replays a prologue of two blocks and plays at most twelve
operations of at most four transactions, so one run is milliseconds.

The two indexer targets are slow by nature: each input replays a prologue
(a mint, the one valid transfer) and verifies every carrier it meets, so
they run slowly — `indexer_s` about six inputs a second, `indexer_a` about
one a minute (its Halo 2 verifications, under instrumentation) — and the
fixture is built before the first input — `indexer_s` sets its parameters up in seconds, `indexer_a`
makes the real `K = 14` proving key and one Halo 2 proof under coverage
instrumentation, eight minutes on twenty cores. CI runs `indexer_s` on
every push and `indexer_a` on the weekly schedule only, with a per-input
timeout wide enough for the fixture.

## Campaigns

Runs on the development laptop (20 cores, the targets `nice`d, 1 GB of
RSS each), without a sanitizer. Figures are libFuzzer's: coverage edges
reached (`cov`) and inputs executed.

| Date | Targets | Time each | Result |
|---|---|---|---|
| 2026-11-21, run 1 | the ten parsers, unseeded | 2 min | **`proven_step` and `persist` aborted within seconds**: a count read off the wire sized a `Vec::with_capacity` of terabytes (a 14-byte and an 8-byte input). Fixed — `Rd::count` refuses a count the remaining bytes cannot hold before anything is allocated — with the inputs kept as `regress-huge-count` seeds and as unit tests. The other eight: no finding. |
| 2026-11-21, run 2 | the ten parsers, seeded, after the fix | 5 min | `proven_step` and `persist` clean (2.3 M and 3.7 M inputs). **`carrier_script` failed its canonical-form invariant**: the witness rule accepted a tapscript carrying a 521-byte payload in one chunk — the rule says no chunk over 520, the code never checked a chunk's size, only that the earlier ones summed to full chunks. Fixed in `tapscript_payload` with a unit test; the input kept as `regress-oversize-chunk`. |
| 2026-11-21, run 3 | all twelve, seeded, after the fixes | 10 min | The ten parsers clean: 1.0 M (`envelope_s`) to 47 M (`strings`) inputs each, `carrier_script` 31 M with the oversize-chunk seed in its corpus. `indexer_a` spent eight minutes in its fixture and ran 4 inputs. **`indexer_s` stopped at its 89th input on a `debug_assert` in the mock chain's memo helper** (`memo_output` demands the memo magic; the harness fed it arbitrary bytes) — a precondition of the test helper, not a finding against the indexer; the grammar now makes a proper memo of the bytes and sends arbitrary ones as a plain second `OP_RETURN`. |
| 2026-11-21, run 4 | the two indexers, corrected grammar | 10 and 15 min | Both clean. `indexer_s`: 3 684 inputs at about six a second, coverage 1 849 → 2 161 edges, a 295-input corpus. `indexer_a`: eight minutes in the fixture, then 7 inputs — about a minute each, the `K = 14` verifications under instrumentation — so it is a random walk with a determinism check more than a fuzzer; kept, weekly in CI. |

## What was found, and by what

- **A count on the wire sized an allocation** (`sba-replay::wire`,
  `sba-replay::persist`; the fuzzer, in seconds). A proven step or a saved
  state with a corrupted count aborted the process on the allocation
  instead of being refused. A light client reads steps from whoever serves
  them: anyone could stop it with 14 bytes. Fixed as above.
- **The decider indexed the instance columns** (`sba-replay::chain`,
  `ChainDecider::verify`/`decide`; found by reading while writing the
  targets, not reachable without the keys). A step whose columns were
  shorter than the keys' shape would have panicked at the first position
  read. Fixed: `check_shape` refuses a slot count or a column length off
  the keys' shape before any position is read, in the decider and in the
  prover's rewind path; a unit test, and four misshapen steps in the
  chain test on real proofs.
- **A tapscript chunk over the push limit was accepted** (`sb-common::carrier`,
  the witness rule; the fuzzer against the canonical-form invariant, run 2).
  `WITNESS-CARRIER.md` §2 says no chunk over 520 bytes; the code checked
  that earlier chunks were full and never a chunk's own size, so one
  oversize chunk — legal in an unexecuted branch — carried a payload in a
  second encoding. Fixed: a chunk over 520 bytes is a probe, like an empty
  one.
- **An all-uppercase address was refused** (`PaymentAddress::decode`, both
  families; the property test). bech32m allows an all-uppercase string and
  the decoder accepted the checksum, then looked the uppercase prefix up
  and found no network. Fixed: the prefix is lowercased first.
- **A wrong property, not a finding**: the tree-versus-set statement first
  demanded `contains(0) == false` on an empty tree. The sentinel counts as
  present by design — zero can neither be inserted (`ImtError::Zero`) nor
  be proven absent (`non_membership(0)` is `None`) — and the unit tests of
  both families assert it. The property was corrected to model the
  sentinel; the tree was left alone.

## Property tests

Beside the fuzz targets, `proptest` statements run with `cargo test` in
the crates, on stable, in CI: `crates/sb-core/tests/props.rs` and
`variants/a-halo2/crates/sba-core/tests/props.rs` (the note tree against a
naive recomputation under appends, overwrites and truncations with paths
under earlier roots; the nullifier tree against a set with its witnesses,
and in the variant its truncation; envelopes round-tripping and staying
canonical under a flipped byte, a header flip always refused; addresses as
bytes and text, uppercase included), `crates/sb-common/tests/carrier_props.rs`
(both carrier rules locate what they publish, with the memo, only under
their prefix, and refuse a second carrier; the witness rule's chunking
across the push limit), and
`variants/a-halo2/crates/sba-replay/tests/wire_props.rs` (a proven step, a
capture, both saved states read back from their bytes and refuse a byte
more or less; a slot statement from its elements; the heights check
exactly when the wire agrees with the opening).
