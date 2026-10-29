# Succinct replay proofs (draft v0.6)

The paper's §22.2 asks whether a light client can obtain a **succinct
proof that `R[h]` is the correct deterministic replay** of the accepted
envelopes up to height `h`, verifiable without re-executing replay, "for
example a recursive or proof-carrying construction over the replay
function", and names its proving cost, update frequency and proof size
as open. This document is this implementation's answer: the replay
function written as a relation, the three questions hidden in the one
sentence, which of them a proof can close on this stack and at what
cost, which it cannot and why, and the construction that is built and
measured. Numbers marked *estimate* become measurements in §6.

Nothing in the transfer layer changes. The transfer circuit, the
envelope, the acceptance rules and replay are those of `PROFILE.md`; a
replay proof is a statement *about* replay, produced by an indexer and
checked by a client, and a client that does not want it replays as
before.

Status: draft; slices 1–4 of §5 implemented (the commitments kept by
replay, the batch circuit `T`, the indexer's `prove-batches` and the
`proof:` light client, the two-chain experiment), tested end to end and
run on signet (§6). Reviewed by the project's
security reviewer: v0.1 on paper, slices 1–3 of the code firsthand
(`docs/REVIEW-REPLAY-PROOF-IMPL.md`); v0.2 folded in the rigour notes,
v0.3 replaced estimates by measurements, v0.4 described the protocol as
built, v0.5 names the mint as the client's inflation surface (the
review's F-3-1).

## 1. Replay as a relation

Replay state after block `h` (profile §11, §A.5–A.7):

```
S_h = ( R_h,  the note tree root (Poseidon Merkle tree, depth 32)
        N_h,  the nullifier set
        H_h,  the root history { h' ↦ R_h' } for h' ≤ h
        h )
```

For block `h` with carrier candidates in block order, the acceptance
order yields the list of **accepted** envelopes `e_1 … e_n` and, for
each, its statement `st_i` (the public inputs of its proof: `const_salt`,
`r_anchor`, the nullifiers, `pk_eph` and `ct_note` per output, `h_body`;
plus `h_anchor` from the body, and `h_aux` per output for a swap). The
step is

```
S_h = Step(S_{h−1}, [e_1 … e_n])
```

where, for each `e_i` in order: `r_anchor = H[h_anchor]` with
`h_anchor + W ≥ h ≥ h_anchor + K_min`; the nullifiers are not in `N`
and distinct within the block; the proof verifies against `st_i`; the
output leaves `leaf_j = PH(T_LEAF, const_salt, h_body, j, pk_eph_j,
ct_j, h_aux_j)` are appended to the tree; the nullifiers are added to
`N`. Then `H[h] = R_h`. An envelope that fails any check leaves the
state untouched.

## 2. Three questions in one sentence

* **Q1, correctness.** Given the list of accepted envelopes (their
  statements), is `S_h` the state that `Step` produces from `S_{h−1}`?
* **Q2, completeness.** Is that list exactly what the carrier rule and
  the acceptance order yield on the Bitcoin block `h`: nothing omitted,
  nothing added, every rejection justified?
* **Q3, succinctness over history.** Is there one proof for all heights
  up to `h`, or one per step?

A proof of Q1 is a statement about field elements and Poseidon hashes;
a proof of Q2 is a statement about megabytes of Bitcoin transactions;
Q3 is about recursion. They have different answers.

## 3. Q2: what Bitcoin does not commit to

To prove that a list of envelopes is complete for block `h`, a prover
must show, for **every** transaction of the block, that it is either in
the list or not a carrier. That needs every raw transaction inside the
circuit (its outputs scanned for the OP_RETURN magic, or its witnesses
for the tapscript shape of `WITNESS-CARRIER.md`) and the SHA-256d
Merkle tree from those transactions to the header's root, since the
header is all a light client holds. One SHA-256 block costs about
40 000 R1CS constraints in this stack (the swap circuit measured 39 482
for a one-block input, `SWAP.md` §13). A 1.5 MB block is ≈ 25 000
compression blocks for the txids and ≈ 2 × 3 000 for the Merkle tree:
≈ 1.2 · 10⁹ constraints (*estimate*), four orders of magnitude above
the 2¹⁷ constraints this implementation proves in 1.5 s and far beyond
any single Groth16 prover. Splitting the block across many proofs does
not change the total.

There is no cheaper commitment to prove against. Bitcoin commits to
transactions through the txid Merkle root in the header and, for
witness data, through the witness commitment (the wtxid Merkle root)
in the coinbase transaction: an OP_RETURN carrier is visible in the
txid tree, a witness carrier (`WITNESS-CARRIER.md`) only in the wtxid
tree, so proving completeness for a witness deployment needs the
coinbase and a second tree on top of the above. The txid tree itself
has the leaf-count malleability of CVE-2012-2459 (one root for trees
whose last leaf is duplicated), which is why the verified sync of
`light:` checks the transaction count against the header's claim
before trusting a partial tree, and why a completeness statement has to
fix the count too. Compact block filters (BIP 158) would be the right
object, but they are not committed anywhere; a deployment could run its
own filter commitment, which is an indexer again. So:

> A succinct replay proof removes the **state computation** from what a
> light client trusts an indexer for. It cannot remove the **carrier
> enumeration**: the client either downloads full blocks (and is then a
> replayer that skips the proof verification) or accepts an indexer's
> list, with omissions detectable only as a divergence between indexers
> or against a full replay, exactly as the verified sync of `light:`
> today (`README.md`, "Verified sync").

Enumeration trust has a sharper edge than omission. A transfer the
indexer **adds** is caught by the client, because its proof must verify
and a valid transfer conserves value. A **mint** is not: a mint creates
value, carries no proof, and is valid only by a fact of the Bitcoin
layer (the carrier's payment to the vault, `BOUNDARY.md`) that a client
holding headers cannot check. So the one place where an indexer can
inflate the shielded supply towards a proof client is a mint it
invents; a full replayer sees the carrier and refuses it, a proof client
cannot. This is inherent to a light client of the development boundary,
not to the proof: a PIPE-based peg (§20.4) would make the mint's
backing a statement a proof could cover.

This is the first result of this document, and it holds for every
proof system: it is a property of what Bitcoin commits to.

## 4. Q1: the construction

### 4.1 Authenticated state

Replay keeps `N` as a hash set and `H` as a map; a proof needs both as
commitments with membership and non-membership proofs.

* **Nullifier set: an indexed Merkle tree** (sorted leaves, each
  `(value, next_value)`, depth 32, Poseidon nodes). Non-membership of
  `x` is one leaf `(low, next)` with `low < x < next` and its path;
  insertion updates that leaf's `next` and appends `(x, next)`: three
  paths of 32 hashes. A sparse Merkle tree over the 255-bit key would
  need 255 hashes per path; the indexed tree needs 32 and fixes the set
  at 2³² nullifiers, which is a deployment parameter like the note
  tree's depth. Its root is `N_h`.
* **Root history: an append-only Merkle tree of roots** (depth 32),
  root `H_h`: leaf 0 is the root before activation (the initial, empty
  tree, which replay returns for any earlier anchor height), leaf `i`
  the root of the `i`-th replayed block, so `R[h]` sits at
  `h − activation + 1`. The anchor check is a membership path; an anchor
  below activation is checked against the initial root as a constant,
  with no path.
* **Note tree:** as today (depth 32, `tree.rs`); appends are paths from
  the current frontier.
* **State digest:** `PH(T_STATE, R, |R|, N, |N|, H, height, applied)`,
  where `|R|` and `|N|` are the leaf counts of the note tree and the
  nullifier tree (a Merkle root does not commit to its size, and `T`
  appends against the size), `height` is the block in progress (the
  first whose root is not yet in `H`) and `applied` how many of its
  statements `T` has applied so far (`0` between blocks), which lets a
  block with more statements than `n` be proven in fragments that chain.

### 4.2 The batch circuit `T`

Groth16 over BLS12-381 with the stack's Poseidon, like the transfer
circuit; one trusted setup per batch size `n` (the ceremony tooling of
`CEREMONY.md` applies). Public inputs: `digest(S_prev)`,
`digest(S_next)`, and `D = PH(T_BATCH, st_1 … st_n)` over the `n`
statements (a statement is 17 field elements: `h_anchor`, `r_anchor`,
the two nullifiers, per output `pk_eph` and the ciphertext, `h_body`,
the two `h_aux`; a slot left empty is the all-zero statement, which the
circuit enforces and skips). Witness: the state opening, the statements
and every path. Constraints per slot (`crates/sb-circuit/src/batch.rs`,
**measured**):

| Check | Hashes / work |
|---|---|
| anchor: `r_anchor` at `h_anchor − activation` in the root tree, window and `K_min` range | 32 hashes + two 32-bit ranges |
| two nullifiers: non-membership, strict order, insert | 2 × (3 × 32 hashes + 2 full-field comparisons) |
| two leaves: `leaf_j` from the statement, append at the next position | 2 × (1 + 2 × 32 hashes) |
| the statement into `D` | part of one sponge |
| **≈ 217 000 constraints per slot** (plus ≈ 33 000 for the opening, the root append and the digests) | |

Measured: `n = 1` 250 368, `n = 2` 467 888, `n = 4` 902 685, `n = 16`
3 511 467 constraints. So `n = 16` is a 2²² circuit and `n = 64` would
be ≈ 1.4 · 10⁷ (2²⁴): the batch size an indexer can afford on one
machine is in the tens of statements, which with fragments (one block
over several proofs, chained through `applied`) sets the update
frequency the paper asks about (§6). The comparisons cost more than
expected (a full-field comparison decomposes both operands into 255
bits), the hashes about as estimated.

`T` applies the statements **in order**, threading the nullifier tree
and the note tree through the `n` slots: the non-membership proof of a
later slot is against the tree as the earlier slots left it, so a
double spend inside one batch fails at the second insertion, exactly as
replay rejects it. The digest `D` is a sponge over the statements in
that order, so it commits to the order, which is semantically
significant (positions, roots). An empty slot is the all-zero
statement; a real statement is never all zero (its nullifiers and
`h_body` are Poseidon outputs), so a skipped slot cannot hide a
transfer and a transfer cannot pass as a skipped slot.

What `T` does **not** do: verify the `n` transfer proofs, or parse
envelopes. It proves that the state transition is the one `Step`
prescribes **for the given statements**, valid or not; the validity of
the statements is the next layer. Stated as the theorem a client
relies on, soundness is a conjunction:

> A client that accepts a batch is right about `S_next` if (1) `T` is
> sound, (2) Poseidon is collision-resistant (the digests `D` and
> `digest(S)` bind what they hash), (3) every statement in the batch
> carries a valid transfer proof, checked by the client as §4.3
> describes, and (4) the batch's list of statements is the list replay
> would have produced from the Bitcoin block (§3, trusted or checked
> against full blocks).

None of the four implies another; `T` alone proves the correct
application of possibly invalid statements.

### 4.3 The `n` transfer proofs

Three ways for a client to be sure the `n` statements carry valid
proofs, in increasing strength:

1. **Verify them one by one.** `n` pairings (≈ 4 ms each here). This is
   what replay does; the client saves the envelopes, the hashing and
   the state, not the pairings.
2. **Batch-verify them.** Groth16 proofs under one verifying key
   batch-verify with random scalars into one multi-pairing of size
   ≈ `n + 3`: the proof bytes stay `n × 192`, the time drops several
   times. Standard, no new assumptions, no new setup. A batch that
   mixes transfers and swaps holds proofs under **two** verifying keys
   (the base and the extension circuit, `SWAP.md`), so it batch-verifies
   as two groups, one multi-pairing each.
3. **Aggregate them** (SnarkPack, Gailly–Maller–Nitulescu 2021): `n`
   Groth16 proofs under one key into one proof of `O(log n)` size,
   verified in `O(log n)` pairings, from a structured reference string
   that a powers-of-tau transcript provides (the phase-1 output of
   `CEREMONY.md` has the powers in both groups); again one aggregate per
   verifying key. This is the only option that makes the per-batch
   proof *succinct in n*; it is also a serious piece of cryptography to
   implement (inner pairing products with KZG commitments in both
   groups) that arkworks does not ship.

Plan: 2 now, measured next to 1; 3 as a second slice if the measured
batch sizes make it matter, else documented as the frontier.

### 4.4 Q3: recursion, and why it stops

One proof for the whole history needs the verifier of `T` inside `T`.
On BLS12-381 alone that is non-native arithmetic (pairings over the
base field expressed in the scalar field): tens of millions of
constraints per verification (*estimate*), measurable, not practical.
On a two-chain the first level is native: a BLS12-377 proof verifies
natively inside a BW6-761 circuit, because BW6-761's scalar field is
BLS12-377's base field, the field the pairing of a BLS12-377 proof is
computed in; but the converse fails (BLS12-377's scalar field is not
BW6-761's base field, which is far larger), so a BW6-761 proof does not
verify natively inside BLS12-377 and the chain has exactly one level.
Unbounded recursion needs a pairing cycle (MNT4/MNT6-753: pairings an
order of magnitude slower, keys to match) or an accumulation scheme
over a cycle of non-pairing curves (Pasta-style folding), which would
replace Groth16 for `T` and leave the transfer proofs on a different
curve, verified non-natively again.

**Measured** (`experiments/twochain`, arkworks' pairing gadgets):
verifying one BLS12-377 Groth16 proof with 17 public inputs inside a
BW6-761 circuit costs **154 649 constraints**, 75 003 of them the
verifier itself (pairings and the input combination), the rest the
allocation of the key, the proof and the inputs as witnesses (a key
fixed as a constant would cost less). The number is for the native
level the two-chain exists for; the non-native self-recursion on one
curve stays where the estimate above puts it. It does change what the
one native level buys: an outer BW6-761 proof could verify the `k`
transfer proofs of a batch **and** the `T` proof natively, at
≈ `(k + 1) × 155 000` constraints (`k = 64`: ≈ 10⁷), giving one
constant-size proof per batch without an aggregation scheme (§4.3's
option 3 by other means). The full price: both inner proofs, the
transfer circuit **and** `T`, must live on BLS12-377, so every Poseidon
value of the profile (note commitments, nullifiers, digests, the three
trees) moves to that curve's scalar field with a different embedded
curve for keys; that is a new, non-interoperable profile with two new
trusted setups (the transfer key and `T`'s), not a parameter change;
plus the slower BW6-761 prover and verifier (a 761-bit curve), and the
same one-level limit: batches still chain linearly.

An outer curve for BLS12-381 itself exists (BW6-767) and verifies a
BLS12-381 proof natively in **169 580 constraints** (74 741 for the
gadget) [measured], but no Groth16 key can be generated over it: its
scalar field is BLS12-381's base field, whose multiplicative group has
2-adicity 1, so no evaluation domain beyond 18 points exists and the
setup fails with `PolynomialDegreeTooLarge` [measured]. BLS12-381 is by
definition not the inner curve of a SNARK-friendly 2-chain (El Housni
and Guillevic, ePrint 2021/1359, Definition 2); the one native level
is bought only by moving the profile to BLS12-377. `REMAINING.md`
§2.3 has the measurement and the cycle and non-native numbers.

So, within this profile, succinctness is **per batch**: a client
verifies a chain of batch proofs from the activation state, each of
constant size (`T`) plus the layer of §4.3; the cost is linear in the
number of batches and independent of the transfers inside a batch up
to that layer.

### 4.5 The protocol, as built

A batch is one block, in fragments of `n` slots when the block has more
accepted envelopes than `n` (`applied` chains the fragments). The
indexer (`sb prove-batches`) rebuilds the trees as they were before each
replayed block from its history, builds the fragments, proves them and
writes, per block, a **proven block**: the block hash, the opening of
the state after it, and per fragment the three public inputs, the `T`
proof, the opening it ends in and the slots: each a statement (18
elements), its kind, the carrier txid, the envelope's own proof (none for
a mint) and `ct_out` (for the sender's recovery, not bound by the
batch). A block without carriers is written without a proof. `sb serve`
publishes them at `GET /batches/<height>`.

A client with `--chain proof:<url>` starts from the activation state and
takes blocks in order. For a proven block it checks that the first
fragment starts from its own digest, verifies every `T` proof, checks
each fragment's opening against the proof's `s_next`, recomputes `D`
from the statements, batch-verifies the transfer proofs under the
transfer key and the swap proofs under the swap key (§4.3, option 2),
and only then applies the statements: the leaves into its note tree,
events for its wallet, the nullifiers into a plain set for the wallet's
bookkeeping, and the nullifier commitment's root and size from the
proven opening. It then appends the block's root to its root tree and
requires the resulting opening to be the one the proofs end in. For an
**empty** block it advances the same way by itself and requires the
indexer's claimed opening to agree. A reorganisation shows as the
indexer's final digest for the client's last block differing from the
client's own; the client rolls back block by block until they agree.

So the client keeps the note tree (the wallet needs paths) and the root
tree (it needs `H` to step over empty blocks: an append-only tree, 32
bytes per block) and **never keeps or checks the nullifier tree**, the
one structure whose cost grows with every transfer and whose
non-membership checks are what `T` proves. It downloads `18 × 32`
bytes of statement plus 192 bytes of proof per envelope and one `T`
proof per fragment, instead of blocks, carriers and partial Merkle
trees; what a wallet gets from its data is the same as from a full
replay, with no envelope bytes kept.

### 4.6 What stays open or trusted

* Q2 (§3): the list's completeness, trusted to the indexer or checked
  against full blocks; and, sharper, the **backing of every mint** in
  the list (§3), which only a full replayer verifies: a proof client
  takes the creation of value on the indexer's word.
* Batch boundaries and the batch size are the indexer's; a client that
  wants a proof for an arbitrary height needs the indexer to close a
  batch there.
* The trust base is every trusted setup in play (the transfer and swap
  circuits', `T`'s per batch size, and an aggregation SRS if §4.3's
  option 3 is used; `CEREMONY.md`'s tooling covers the Groth16 ones with
  the same conditions as the transfer circuit's) and the
  collision-resistance of Poseidon, on which the digests and all three
  trees stand.
* Proving cost sits on the indexer and sets the update frequency;
  measured in §6.
* Succinctness over history is per batch (§4.4).

## 5. Slices

1. Indexed Merkle tree for nullifiers and the root tree, native, with
   proofs, in `sb-core`; replay keeps both alongside its sets and
   checks that the roots agree.
2. The batch circuit `T` in `sb-circuit`, with measurements: constraints
   per transfer, proving time and key size for `n = 4, 16, 64`.
3. Batched Groth16 verification; `sb serve` producing batches;
   `--chain proof:<url>`; the end-to-end test; a signet run.
4. Appendix experiment (done, `experiments/twochain`): the constraint
   count of one in-circuit Groth16 verification of a BLS12-377 proof
   with 17 public inputs inside a BW6-761 circuit, with arkworks'
   pairing gadgets, to measure the one native recursion level of §4.4.
5. (If the numbers call for it) SnarkPack aggregation.

## 6. Measured

* **`T`** (`crates/sb-circuit/tests/batch.rs`, release build): 250 368
  constraints for `n = 1`, 467 888 for `n = 2`, 902 685 for `n = 4`,
  3 511 467 for `n = 16`; ≈ 217 000 per slot. A two-slot block proves
  and verifies; the same block as two fragments (one slot open, one
  slot closing the block) ends in the same state digest; an empty block
  proves the root append alone; a double spend inside the batch, an
  anchor root absent from the root tree, an anchor at the block in
  progress, a leaf at the wrong position and a block closed without its
  root append each leave the constraints unsatisfied.
* **Two-chain** (`experiments/twochain`): 154 649 BW6-761 constraints to
  verify one BLS12-377 Groth16 proof with 17 public inputs in-circuit
  (75 003 for the verifier gadget), satisfied; outer setup 8.8 s, proof
  10.7 s, verification 12.6 ms, 2.2 GB peak. The same for BLS12-381
  inside BW6-767: 169 580 constraints (74 741), satisfied, and no
  Groth16 setup possible (`PolynomialDegreeTooLarge`, 2-adicity 1).
* **Not yet exercised end to end:** a reorganisation on the client's
  side (the rollback through the digest history is implemented and
  reviewed as logic only).
* **End to end** (`crates/sb-cli/tests/proof_e2e.rs`): an indexer
  proves a history of a mint and two transfers to the light client's
  wallet (and the empty blocks between), the client syncs from the
  proofs alone and sees the balances, spends from its own tree through a
  separate publication route, and syncs the resulting block; a proven
  block with a slot's kind changed, or declared empty, is refused.
* **Signet** (`RUNS.md`, 29 October 2026, deployment `signet-dev-2`,
  245 blocks, 4 envelopes, batch size 4): proving 31–54 s per fragment
  on a laptop after a 36-second setup, 4.6 GB peak; the 245 proven
  blocks weigh 110 KB; a light client synced them in 24 s with the same
  balances as the full indexer, against 35.2 MB of full blocks for the
  same heights.

## 7. Changelog

* **v0.6** — the BLS12-381 / BW6-767 measurement in §4.4 and §6 (one
  native level exists for this profile's curve, with no FFT-friendly
  prover); `REMAINING.md` linked.
* **v0.5** — after the code review: the mint as the proof client's
  inflation surface (§3, §4.6); the client-side reorganisation noted as
  untested end to end (§6); the review linked.
* **v0.4** — the protocol as built (§4.5): one block per batch in
  fragments, proven blocks with their openings, the client's checks in
  order, what it keeps (note tree, root tree) and does not (nullifier
  tree), empty blocks and reorganisations; the end-to-end test in §6.
* **v0.3** — measurements replace estimates: the per-slot cost of `T`
  and its shape (17-element statements, the all-zero skip slot, the
  size and `applied` fields of the digest, fragments); the two-chain
  verification cost, what it buys and its full price (§4.4); slices 1,
  2 and 4 done.
* **v0.2** — after the paper review: the witness commitment and the
  leaf-count malleability in §3; `T` threads the trees in order, `D`
  binds the order, the all-zero skip slot is unambiguous, and the
  client's soundness stated as a four-part conjunction in §4.2; per-key
  groups in §4.3; the field-embedding reason in §4.4; the trust base in
  §4.6; slice 1 marked implemented.
* **v0.1** — initial draft: replay as a relation, the three questions,
  the completeness result (§3), the batch construction, the recursion
  frontier, the protocol, the slices.
