# Variant A: the paper's protocol without a trusted setup (study, draft v0.3)

Status: a study with a first measurement, 30 October 2026; no change to
the paper implementation. It records a decision of the owner and the
reasoning behind it, and it fixes how variants that go beyond the paper
live in this repository next to the implementation of the paper.
Conventions as in `REMAINING.md`: **[cited]**, **[measured]** (this
laptop: 20 threads, 16 GB, release build), **[computed]**,
**[estimate]**.

**Decision record (30 October 2026).** The owner reframed the first
question of `POST-QUANTUM.md`: not "does the post-quantum thread need
Halo 2", but "if the goal is to fix the problems of the original
paper, with no post-quantum requirement, is a change to a transparent
proof system worth doing?" The answer of §2 is yes, with a stated
price; the owner decided: **variant A is built as a separate profile,
study and measurement first, code second**, and the post-paper
variants share this repository with the paper implementation under the
rules of §6.

## 1. The question

The paper fixes Groth16 over BLS12-381 (§A) for its 192-byte proof and
says in §22.1 that "each candidate also carries its own setup and
security assumptions, and a circuit-specific system needs one trusted
setup per supported arity". This stack implements the paper as written
and has met every consequence of that choice: a BGM17 ceremony tool
(`CEREMONY.md`), drills in which one person plays every role, deployment
profiles that say "insecure setup from a published seed", and the
owner's ruling that a ceremony with independent participants is not on
the table. `REMAINING.md` §1 then found that the smaller pairing-based
systems (Polymath, Pari) change nothing about this: they are
circuit-specific too and have no published multi-party setup.

Variant A asks what a **transparent** system changes. Concretely: Halo 2,
the PLONKish proof system with the inner-product-argument polynomial
commitment over the Pasta cycle (Pallas, Vesta), with no setup of any
kind, as deployed in Zcash Orchard since NU5 (2022) and as reused
unchanged by the owner's `kupermind/confidant` (`orchard` 0.15.5, the
"FixedPostNu6_2" circuit) [cited: confidant README]. Its soundness is a
discrete-logarithm assumption on Pasta; it is not post-quantum
(`POST-QUANTUM.md` §1), and that is not the question here.

## 2. The paper's problems, one by one

| Problem of the paper | Where | What A does with it |
|---|---|---|
| Trusted setup; toxic waste; a ceremony before any value deployment | §8.4, §A; `CEREMONY.md`; every deployment profile's caveat | **removed entirely.** No parameters to generate, nothing to trust, nothing to drill. The BGM17 crate and its documents retire for this variant. |
| One trusted setup per supported arity | §22.1 | **removed.** Supporting a second arity is a second circuit shape, not a second ceremony; the paper's coupling between the arity decision and the setup disappears. (The privacy-set argument against mixed arities stays.) |
| Proof re-randomization caveat | §14.3 | **weakened, not closed.** Groth16's known re-randomization map does not exist for a Fiat–Shamir proof whose transcript binds the statement; but Halo 2 is not proven non-malleable either, so the caveat becomes "non-malleability unproven" instead of "re-randomization exists". The protocol's defence (replay rejects a repeated nullifier) is unchanged. |
| Succinct replay proof: per batch only, no unbounded recursion on BLS12-381 | §22.2; `REPLAY-PROOF.md` §4.4; `REMAINING.md` §2.3 | **the wall falls.** The Pasta cycle exists for accumulation: a Halo 2 proof verifies a Halo 2 proof natively at every depth (Halo's design goal; split accumulation's recursion threshold is 52 000 constraints on Pasta [cited: ePrint 2020/1618 §1.1]). One accumulated proof of the whole replay from activation becomes an engineering task. |
| Certified-recipient lineage: "not now, and not by engineering" | §22.4, §D; `REMAINING.md` §2 | **the cryptographic obstacle R1 falls**, for the same reason; the economic one stays: a package per output is a Halo 2 proof of kilobytes (`REMAINING.md` §2.4), so a lineage-carrying envelope is still several times the plain one. |
| Footprint, for which Groth16 was chosen | §22.1, §A.4 | **regresses.** The proof of this relation is 4 416 bytes [measured, §4.2], 23 × Groth16's 192; the witness carrier grows 3.4 ×, the OP_RETURN carrier 6.1 × (§4.3). |
| Everything else: the boundary (PIPE), publication privacy, the completeness of the carrier list, wallet policy | §20.4, §22.3; `BOUNDARY.md`, `PUBLICATION.md`, `REPLAY-PROOF.md` §3 | **unaffected** either way. |

So A is the one proof-system change that answers several of the paper's
own open items at once (setup, setup-per-arity, and the recursion wall
behind §22.2 and §22.4), at the price of a 3.4–6 × heavier carrier, a
6 × slower verifier and a full profile migration (§5). Whether that is "fixing" the paper depends
on which of its problems is held to be the first one. For a project
that has ruled out a real ceremony, the trusted setup is the first one:
every deployment profile this repository ships says, truthfully, that
anyone can forge its proofs. A is the honest answer to that sentence.

There is no half-way version: keeping Groth16 in the envelope and using
Pasta only for the off-chain replay proof does not work, because the
transfer proofs would then be verified non-natively inside a Pasta
circuit, ≈ 3.9 M constraints each (`REMAINING.md` §2.3(c)).

## 3. What A is, precisely

* **Arithmetization**: PLONKish (advice/fixed/instance columns, custom
  gates, lookups), not R1CS. The relation is re-expressed, not ported.
* **Commitment**: inner-product argument over Pasta; proof size grows
  with log of the circuit size and with the number of committed
  columns and openings, not with the constraint count; verification is
  linear in the circuit size (amortised by accumulation).
* **Fields and curves**: the circuit field is Pallas's base field (=
  Vesta's scalar field) in Orchard's arrangement, and the embedded curve
  for keys is Pallas itself, exactly as Jubjub is embedded in
  BLS12-381's scalar field today. Neither Pasta field is BLS12-381's
  scalar field: no value of the current profile carries over.
* **Assumptions**: discrete logarithm on Pasta, random oracle (Fiat–
  Shamir). No pairings, no q-type assumptions, no setup.
* **Reference implementation**: `halo2_proofs` 0.3 and `halo2_gadgets`
  (Poseidon, Sinsemilla, ECC, Merkle path, lookups), the `orchard` crate
  as a complete worked example of a shielded action circuit of this
  class (k = 11, 2¹¹ rows [cited: `orchard::circuit::K`]).

## 4. Measured: the nearest production relation

`experiments/halo2` proves Orchard action bundles with the `orchard`
crate on this laptop. An action is one (dummy) spend and one output; a
bundle of n actions is one proof; Orchard's default bundle type pads to
at least two actions, which is why one and two actions cost the same.
This project's 2-in-2-out transfer corresponds to a two-action bundle.

| Bundle | Proof size | Prove (20 threads) | Verify | Key generation | Peak memory |
|---|---|---|---|---|---|
| 1 action (padded to 2) | 7 264 B | 0.85 s | 7.4 ms | vk 0.9 s, pk 1.5 s | 152 MB (whole run) |
| 2 actions | **7 264 B** | **0.85 s** | **6.6 ms** | | |
| 3 actions | 9 536 B | 1.21 s | 8.7 ms | | |
| 4 actions | 11 808 B | 1.52 s | 9.4 ms | | |

[measured, `orchard` 0.15.5, `FixedPostNu6_2`, release; 2 272 bytes per
further action, matching zebra-chain's `expected_proof_size`.] For
comparison, this profile's Groth16 transfer: 192 bytes, prove 1.5 s,
verify 4 ms, setup 1.5 s, 84 362 R1CS constraints [measured, `README.md`].

### 4.1 From Orchard's relation to this one

What Orchard's action proves that this transfer also proves: a Merkle
path of depth 32, a nullifier bound to the note, a note commitment, the
derivation of the spend authority from the spending key, the recipient
address's consistency, value conservation. What this transfer proves
in addition: the consistency of the published ciphertext with the note
(§12.1 of the paper, Poseidon-based, ≈ 2 k R1CS constraints per note
today), the position-bound nullifier (§9), the dummy flags, and the
binding of the whole body through `h_body` as a public input (no
in-circuit cost). What Orchard proves that this transfer does not:
Pedersen value commitments and their balance, and Sinsemilla
commitments (replaced here by Poseidon throughout). Net, the two
relations are of the same class and size; with Poseidon in place of
Sinsemilla the row count is, if anything, lower. **[estimate]**: the
transfer relation fits k = 11 or 12, and its proof is 7–9 KB for the
two instances; the exact number is the first measurement of §7.

### 4.2 S1: this profile's transfer relation in Halo 2 [measured]

`experiments/halo2-transfer` expresses the transfer relation of
`PROFILE.md` §8 in Halo 2 with `halo2_gadgets` 0.5 (`halo2_proofs`
0.3.5), structurally faithful to the R1CS circuit of `sb-circuit`: two
inputs and two outputs; Poseidon (width 3, x⁵, 8 + 56 rounds, the tag as
first element) for every hash; the spend-authority derivations; the
position-bound nullifier; DiversifyHash with a witnessed even
coordinate and the curve check; the diversified-address check
`pk_d = [sk_view] G_d`; the recipient channel (`pk_eph = [sk_eph] G_d`,
`ss = [sk_eph] pk_d`, KDF, stream, MAC) proven in circuit for every
input and output; the leaf; a depth-32 Poseidon Merkle path skipped for
a zero-value dummy by `(root − anchor) · v = 0`; 64- and 88-bit range
checks by 10-bit lookups; value conservation; the 17 public inputs in
the profile's order. Variable-base scalar multiplications use the
gadget's base-field-element scalars, as Orchard does for `[ivk] g_d`.
Two differences are forced by the curve: Pallas has prime order, so the
cofactor clearings (`[8]·`) of Jubjub disappear, and the even-coordinate
rule applies to `y` (short Weierstrass) instead of `x` (twisted
Edwards). The ten advice columns, the fixed columns and the lookup table
are laid out as in Orchard's circuit; the ECC chip's fixed-base
multiplication is configured but unused.

| | Server container (4 CPUs of a loaded 8-core host) | Laptop (20 threads, idle) |
|---|---|---|
| Rows | **k = 14** (2¹⁴ = 16 384; k = 13 does not fit) | same |
| Key generation | 14.1 s | 4.4 s |
| Prove, one transfer | 7.79 s | **1.97 s** |
| Proof size, one transfer | **4 416 B** | same |
| Verify | 106.5 ms | 24.5 ms |
| Two transfers in one proof | 12.03 s, 6 176 B (+1 760 B per instance) | 3.10 s, 6 176 B |
| Peak memory | 673 MB | 672 MB |
| Mock prover (satisfied) | 2.0 s | 0.9 s |

[measured, 30 October 2026, release builds; the server numbers inside
Docker with `--cpus=4`, CPU use 260 %; the laptop numbers at 713 % CPU.]
The Groth16 row of this profile, for comparison: 192 B, prove 1.5 s,
verify 4 ms, setup 1.5 s (`README.md`).

Reading the numbers. The proof for one transfer is 4 416 bytes, not the
7 264 of the two-action Orchard proxy, because one 2-in-2-out transfer
is one instance of one circuit; a second instance in the same proof adds
1 760 bytes. Proving is in the range of the Groth16 prover on the same
hardware (2.0 s against 1.5 s on the laptop). Verification is 6 × slower
than Groth16 (24.5 ms against 4 ms) and grows with the circuit's rows
(the inner-product argument's verifier is linear in 2ᵏ): an indexer
replaying a full block of transfers verifies at ≈ 40 proofs per second
per core, which is the cost A moves from the prover to every verifier;
Halo 2's accumulation amortises it when proofs are verified in batches,
and a smaller circuit (Sinsemilla for the Merkle path, as Orchard, or
fewer in-circuit hashes) would lower k. Rows are dominated by the
≈ 127 Poseidon permutations of the relation (≈ 66 rows each in the
width-3 chip), not by the ten scalar multiplications.

**Gate of S1** (≤ 9 KB per transfer, ≤ 3 s proving): met, 4 416 B and
1.97 s on the laptop; the 7.8 s of the 4-CPU container is the same
work on fewer and busier cores.

### 4.3 The carrier arithmetic [computed]

Measured carriers of this profile: OP_RETURN 825 vB and witness 447 vB
for a 700-byte envelope (`WITNESS-CARRIER.md` §6); non-envelope parts
125 vB and 272 vB; envelope = 508 bytes of body + proof.

| | Groth16 (today) | A, this relation (4 416 B, measured) | A, Orchard two-action proxy (7 264 B) |
|---|---|---|---|
| Envelope | 700 B | 4 924 B | 7 772 B |
| OP_RETURN carrier | 825 vB | 5 049 vB (× 6.1) | 7 897 vB (× 9.6) |
| Witness carrier | 447 vB | **1 503 vB (× 3.4)** | 2 215 vB (× 5.0) |
| Fee at 1 / 20 sat/vB, witness | 447 / 8 940 sat | 1 503 / 30 060 sat | 2 215 / 44 300 sat |
| Transfers per 1-MvB block, witness | ≈ 2 240 | ≈ 665 | ≈ 450 |

The witness carrier is the only sensible one for A; the OP_RETURN
carrier at 5 kvB is a 4.9-KB OP_RETURN, within current default policy
but pointless against the witness alternative.

## 5. The migration, as an inventory

Nothing field-bound survives; everything field-agnostic does.

| Crate / area | Today | Under A |
|---|---|---|
| `sb-primitives` | Poseidon over BLS12-381 `Fr`, pinned constants; Jubjub encodings; DiversifyHash on Jubjub | Poseidon over Pallas `Fp` (new parameters, pinned and checked by a script as today); Pallas encodings; DiversifyHash on Pallas (Orchard's exists) |
| `sb-core` | keys, addresses (bech32m `sb…`), notes, encryption, leaves, nullifiers, envelope codec, note tree, IMT, batch types | the same design over Pallas; a new address HRP; envelope magic/version distinct from the paper's so that the paper's indexer refuses it as unknown and vice versa; test vectors regenerated |
| `sb-circuit` | R1CS gadgets, transfer, swap, batch circuits, Groth16 glue | rewritten in PLONKish with `halo2_gadgets`: transfer first, swap and batch after; no proving-key files, no `--*-insecure` flags |
| `sb-ceremony` | BGM17 phases, drills | not used by A |
| `sb-indexer` | chain sources, carriers, replay, state, light/proof clients, net, deployment | chain sources, carriers, net, publication and deployment plumbing are reused; replay state and the proof client are over `Fp` |
| `sb-wallet` | scanning, recovery, selection, anchors, builder | the same over `Fp`; the builder emits A's envelopes |
| `sb-cli` | `sb` | the same commands; the family chosen by the deployment profile (§6) |
| `deployments/` | profiles with `vk_sha256` and setup fields | profiles with a `family` field and no key material |
| `docs/` | `PROFILE.md` normative | `PROFILE-A.md` normative for A; departures from the paper listed as `PROFILE.md` §12 does today |
| Reviews | PASS on every circuit and slice | to be repeated for A's circuits and codec |

## 6. Post-paper variants in one repository

The owner's question: how do variants beyond the paper coexist with the
implementation of the paper? Rules this repository adopts:

1. **The paper implementation is the reference and stays frozen as
   such.** `crates/`, `docs/PROFILE.md` and the other normative
   documents, `deployments/*`, `TEST_VECTORS.md` describe the paper as
   implemented; a variant never edits them to fit itself. The paper
   implementation is parked, not abandoned: its CI keeps running.
2. **A variant is a family, named by its letter** from
   `POST-QUANTUM.md`: A (transparent, Halo 2), B (hash-based,
   post-quantum soundness), C (post-quantum privacy). A family is a
   deployment-profile attribute (`family`) and an envelope version:
   envelopes of different families are distinguishable on chain and
   mutually invalid; there is no interoperability and none is claimed.
3. **Layout.** A family lives under `variants/<letter>-<name>/` with its
   own crates, documents, deployments and tests; `experiments/` keeps
   the measurements that back numbers in documents (as now);
   family-agnostic code is extracted from the paper crates into shared
   crates rather than duplicated: the chain sources and carrier
   extraction, the publication layer (`net`, proxies, publish-via,
   delay), fee funding and the relayer, the fee vault's protocol, the
   HTLC scripts, wallet-file encryption, the deployment-profile
   machinery, the HTTP server and client. The extraction is a refactor
   of the paper crates with no behaviour change, reviewed as such, and
   it is the first code step of any variant.
4. **Field-bound code is not made generic.** Two fields in one code
   path would turn every reviewed line of the paper implementation into
   an unreviewed generic one. A variant's primitives, core, circuit,
   state and wallet are their own crates (`sba-*` for A), free to copy
   from the paper crates and to diverge.
5. **One CLI, one deployment model.** `sb` resolves the family from the
   deployment profile and dispatches; commands keep their names;
   family-specific commands are namespaced. A user of the paper
   deployment sees no change.
6. **Documents.** Each variant has its normative profile
   (`PROFILE-<letter>.md`), its own `RUNS` entries, reviews
   (`REVIEW-<letter>-*.md`), and a section in `ROADMAP.md`; the variant's
   security analysis is its own: nothing of the paper's analysis is
   claimed to cover a variant until the affected parts are redone for
   it, and the variant's documents say which parts those are.
7. **CI** builds and tests the paper workspace and every variant;
   heavy variant builds get their own job so the paper's job stays as
   it is.
8. **Machines.** Measurements and tests that need more than a few GB
   or minutes run in Docker on the server, not on the laptop; the
   laptop's memory and disk are watched during every build (owner's
   rule, 30 October 2026). `experiments/halo2` needed 152 MB and 7 s and
   ran locally.

## 7. Plan for A, with gates

* **S0, this document**: the question, the problem table, the proxy
  measurement. Done.
* **S1, the real measurement**: done, §4.2 (`experiments/halo2-transfer`,
  run in Docker on the server and on the laptop): k = 14, 4 416 bytes,
  2.0 s proving on 20 threads, 24.5 ms verification. Gate met.
* **S2, `PROFILE-A.md`**: written (v0.1, 30 October 2026) as a delta to
  `PROFILE.md`: fields, curves, the halo2 hash mode, scalars from field
  elements, DiversifyHash on Pallas, the envelope with a 4 416-byte
  proof and version byte `0x02`, the circuit as built in S1, the
  verifying-key identifier, the deployment profile with `family`, the
  departures and the security-analysis delta. To be reviewed on paper
  by the auditor before code (review batch planned for 3 November 2026).
* **S3, the shared-crate extraction** (§6.3), no behaviour change,
  reviewed.
* **S4, `variants/a-halo2`**: primitives, core, circuit, test vectors,
  state, wallet, the family dispatch in `sb`; the transfer only
  (swap and batch circuits come after, by the same procedure as for
  the paper).
* **S5, a run on signet** on the witness carrier, `RUNS.md`.
* **S6, review** of the circuits and the codec.
* **Later, the items A reopens**: the accumulated replay proof (§22.2)
  and lineage feasibility (§22.4), each as its own study first.

## 8. Sources

* The paper [SB26]: §8.4, §9, §12.1, §14.3, §20.4, §22.1, §22.2, §22.4,
  §A, §D.
* This repository: `PROFILE.md`, `CEREMONY.md`, `WITNESS-CARRIER.md`
  §6, `REPLAY-PROOF.md` §4.4, `REMAINING.md` §1–2, `POST-QUANTUM.md`
  §1–3, `README.md` (measured Groth16 figures).
* `experiments/halo2` (this document's measurement), `orchard` 0.15.5
  (`src/circuit.rs`, `benches/circuit.rs`), zebra-chain
  `orchard::shielded_data::expected_proof_size`.
* `kupermind/confidant` README (Orchard reused unchanged).
* Bowe, Grigg, Hopwood, *Halo: Recursive Proof Composition without a
  Trusted Setup*, ePrint 2019/1021; the halo2 book (Zcash).
* Bünz, Chiesa, Lin, Mishra, Spooner, ePrint 2020/1618 (split
  accumulation on Pasta, recursion threshold).

## 9. Changelog

* **v0.3** (30 October 2026) — S2 done: `PROFILE-A.md` v0.1 written,
  the plan updated.
* **v0.2** (30 October 2026) — S1 done: the transfer relation in Halo 2
  measured on the server and the laptop (§4.2), the carrier arithmetic
  and the problem table updated to the measured 4 416 bytes.
* **v0.1** (30 October 2026) — the reframed question, the problem
  table, the Orchard measurement, the migration inventory, the
  repository rules for post-paper variants, the plan with gates.
