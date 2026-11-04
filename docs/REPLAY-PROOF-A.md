# Succinct replay proofs for variant A (study, draft v0.6)

Status: a study, no code beyond `experiments/halo2-accumulate`. The
question `VARIANT-A.md` §7 left for after S6: the paper's §22.2 asks
for one succinct proof of the whole replay; `REPLAY-PROOF.md` answered
it for the paper's stack with a per-batch proof and a measured
recursion frontier (no cycle for BLS12-381, one native level on a
two-chain, §4.4). Variant A lives on the Pasta cycle, which exists for
accumulation. This document says what that changes, what it does not,
what exists to build on, what was measured, and what the next
measurement would be. Tags: [measured] by the code here, [computed]
arithmetic from measured or stated quantities, [cited] with the source,
[estimate] my own, to be replaced by a measurement.

## 1. The three questions, under A

`REPLAY-PROOF.md` §2 splits the paper's one sentence into three:

* **Q1, the state transition** (the batch circuit `T`): unchanged in
  form. `T` proves, over an indexed nullifier tree and a root tree,
  that `n` accepted statements take the state from `S_prev` to
  `S_next` (§4.1–4.2 there). Under A it is a Halo 2 circuit over `Fp`
  with `PH_A`, the family's own hash, so the trees of the replay state
  are in the same field as the transfer circuit's values: **no
  non-native arithmetic** anywhere in `T`, and no setup per batch
  size `n` (a second `n` is a second circuit shape, nothing to
  ceremony). This is the same gain `VARIANT-A.md` §2 lists for the
  transfer circuit.
* **Q2, completeness of the envelope list**: untouched. It is a
  statement about what Bitcoin commits to (`REPLAY-PROOF.md` §3), not
  about the proof system; the carrier list stays trusted or full
  blocks are needed, for A exactly as for the paper.
* **Q3, recursion**: the wall of §4.4 falls, and what is left is
  engineering with a known shape. The rest of this document is Q3,
  plus the one part of Q1 that recursion decides: how the `n`
  transfer proofs inside a batch are verified.

## 2. The `n` transfer proofs inside a batch [measured]

`REPLAY-PROOF.md` §4.3 gives a client three ways to be sure the `n`
statements of a batch carry valid proofs: verify them one by one,
batch-verify them, or aggregate them into one proof (recursion). Under
A the first two are measured, and the third has a precise meaning,
because an inner-product-argument verifier splits into a **succinct
part** (reading the transcript, the challenges, a small
multi-scalar multiplication over the proof's few dozen commitments)
and a **deferred part** (the claim that the point `G` the argument
ends in equals `⟨s, params.g⟩` for the `2^k` generators, with `s`
determined by the `k` challenges), which is the `2^k`-sized
multi-scalar multiplication that makes IPA verification linear in the
circuit size. Halo's accumulation [cited: Halo, ePrint 2019/1021;
`halo2_proofs::poly::commitment::Guard::use_g`] lets a verifier
accept the prover's `G`, carry the claim `(G, u_1 … u_k)` forward, and
settle any number of such claims at once with one `2^k`
multi-scalar multiplication of a random linear combination.

`experiments/halo2-accumulate` verifies `n` proofs of the family's
transfer circuit (k = 14, 4 416-byte proofs, the Poseidon transcript of
profile a-0.3) in the three modes, on the laptop (release, 20 threads
for the multi-scalar multiplications):

| n | one by one, per proof | batched into one MSM (`Guard::use_challenges`), per proof | accumulated: succinct part per proof + one final MSM for all claims, per proof |
|---|---|---|---|
| 1 | 31.3 ms | 31.2 ms | 10.2 ms + 24.3 ms = 34.4 ms |
| 4 | 33.0 ms | 13.4 ms | (40.2 ms + 24.9 ms) / 4 = 16.3 ms |
| 16 | 33.0 ms | 8.8 ms | (111.5 ms + 30.3 ms) / 16 = 8.9 ms |
| 64 | 32.6 ms | 7.5 ms | (454.8 ms + 49.0 ms) / 64 = 7.9 ms |

[measured, 4 November 2026; 64 proofs in 146 s]. Under the Blake2b
transcript of a-0.2 the same run gave 30.5 / 5.8 / 5.7 ms at n = 64
[measured, 3 November]: the algebraic transcript costs about 2 ms of
native Poseidon per verification (≈ 135 permutations), the price of
being computable inside a circuit. The prover-side `G` (what a prover
ships with an accumulated proof) costs 32 ms per proof to compute, the
same MSM the verifier saves. The accumulator per proof is `G` (32 bytes) plus the
`k = 14` challenges (32 bytes each), 480 bytes, all of it
recomputable from the proof: nothing new goes on chain.

What the table says:

* **Batch verification is native to the stack and already pays off at
  the block level.** An indexer verifying a block of 64 transfers
  spends 0.37 s instead of 1.95 s; the 6 × verification penalty of A
  against Groth16 (`VARIANT-A.md` §4.2: 24.5 ms against 4 ms) shrinks
  to ≈ 1.4 × at 64 proofs. This is a plain code change in
  `sba-indexer` (verify a block's candidates together, reject the
  block's set and fall back to one-by-one verification to find the
  culprit when the batch fails), with no profile change and no new
  assumption [computed from the table].
* **The succinct part is ≈ 7 ms of native work per proof** (454.8 ms /
  64), against ≈ 25 ms of deferred MSM. That ratio is the point of
  accumulation: a recursive verifier carries the 5 ms part in-circuit
  and the 25 ms part as a 480-byte claim folded into the next
  accumulator, and the whole history settles with one `2^k` MSM at the
  end. The paper's stack has no such split: a Groth16 verification is
  three pairings, indivisible and non-native on its own curve.

## 3. Q3: what recursion looks like for A

### 3.1 The shape

Halo's design [cited: ePrint 2019/1021 §4; the Halo 2 book,
"Recursion"]: two circuits, one per curve of the cycle, each
verifying the succinct part of a proof made with the other and
accumulating its deferred claim. For this stack the two halves fall
out of the fields:

* Transfer proofs and `T` are circuits over `Fp` (Pallas's base field),
  committed on **Vesta**; their commitments are Vesta points with
  coordinates in `Fq`, so the succinct verification of such a proof is
  `Fq` arithmetic, i.e. a circuit over `Fq` committed on **Pallas**.
  Call it `V_q`: it reads the transcript of one or more Vesta-committed
  proofs, derives the challenges, does the small MSM over the
  commitments, and outputs the accumulated claim.
* `V_q`'s own proof is Pallas-committed, so its succinct verification
  is `Fp` arithmetic: a circuit over `Fp`, committed on Vesta, which is
  where `T` already lives. `T_i` verifies the succinct part of
  `V_q`'s proof for batch `i − 1` and of `T_{i−1}`, and carries both
  accumulators. The chain alternates and never leaves native
  arithmetic; depth is unbounded; the final verifier settles two
  accumulators (one per curve) with two `2^k` MSMs.

So a light client of A would hold: the latest `T` proof (one Halo 2
proof, kilobytes), the two accumulators (480 bytes each, for the
respective `k`), and the state opening; it would verify one proof's
succinct part and two MSMs, independent of the history's length. That
is the paper's §22.2 "succinct proof of replay" as far as Q1 and Q3
go, with Q2's trust in the carrier list unchanged (§1).

### 3.2 What has to exist, and what exists

Three pieces, none shipped for this stack:

1. **A succinct-verifier gadget**: in-circuit transcript, challenge
   derivation, the small MSM, the accumulator fold, over the opposite
   curve, in `halo2_gadgets`' ECC chip. Zcash designed Halo 2 for
   this and never shipped it: "the vision of a recursive proving
   system was never completed" [cited: zcash/halo2 issue tracker and
   the DAG page, 2026]; the only in-circuit IPA verifier found is
   experimental, non-native over BN254 in `halo2-lib` (29 M advice
   cells for a batch of 20 openings of length 256, with the note that
   a native curve "should dramatically improve performance") [cited:
   notnotraju, HackMD]. For the Pasta cycle the gadget would be
   native, which is the whole difference; it still has to be written.
   Its size [estimate]: the transcript of a k = 14 proof of this
   circuit absorbs ≈ 50 commitments and ≈ 70 evaluations and squeezes
   ≈ 30 challenges, the small MSM has ≈ 50 terms, the accumulator
   fold adds `k + 1` scalar multiplications; at the ECC chip's cost of
   a variable-base multiplication (≈ 2 rows per scalar bit, Orchard's
   figures) and the width-3 Poseidon's ≈ 66 rows per permutation,
   that is of the order of 2^15–2^16 rows per verified proof, i.e. a
   `V_q` of k = 16–17 for one proof and k ≈ 20 for a batch of 16. To
   be measured by building the gadget, not by this arithmetic.
2. **An algebraic transcript.** The family's proofs use a Blake2b
   transcript (`PROFILE-A.md` §1); a verifier gadget would have to
   compute Blake2b in-circuit, which is the one thing nobody does. The
   recursive profile needs a Poseidon transcript over the commitment
   curve's base field with challenges truncated to 128 bits, as Halo
   does [cited: ePrint 2019/1021 §5; the Halo 2 book, "Transcript"].
   That is a profile change: every proof's challenges move (the bytes
   keep their length and `vk_id` stays), a `a-0.x` bump with no change
   to the relation. **Done as a-0.3 on 4 November 2026** (`PROFILE-A.md`
   §1.1, `sba-circuit/src/transcript.rs`: a duplex sponge over `Fq`,
   128-bit challenges), before any deployment whose history is meant to
   be accumulated later, because proofs made under the Blake2b
   transcript can never be verified in-circuit; the paper implementation
   has the same kind of frozen choice in its Groth16 proofs.
3. **`T` in Halo 2.** A port of `crates/sb-circuit/src/batch.rs` to
   the family: the indexed nullifier tree and the root tree with
   `PH_A`, the statement digest, the slot rules. Rows [estimate from
   `REPLAY-PROOF.md` §6: ≈ 217 000 R1CS constraints per slot, almost
   all Poseidon, and the transfer circuit's ratio of 84 362 constraints
   to 2^14 rows]: ≈ 40 000 rows per slot, k = 19 for 16 slots; proving
   time on the laptop of the order of a minute per fragment, memory of
   the order of 10 GB [estimate: the k = 14 transfer takes 2 s and
   0.5 GB; the IPA prover is near-linear in rows]. The server's
   container is the place to measure it.

Alternatives, and why they do not shortcut the three pieces:

* **Nova-style folding** (`nova-snark` 0.76, Pasta supported, zero
  knowledge by folding in a random instance before compression,
  compressed proofs with Spartan over IPA; [cited: microsoft/Nova
  README; `REMAINING.md` §2.3(d): ≈ 10 000-constraint folding
  verifier, compressed proofs ≈ 8–9 KB]; CycleFold reduces the
  second-curve circuit to ≈ 1 000–1 500 gates [cited: ePrint
  2023/1192]). Folding replaces piece 3's recursion plumbing by a
  cheaper fold, but the step circuit still has to **verify the
  transfer proofs**, which are Halo 2 / IPA proofs: piece 1 again, in
  R1CS (bellpepper) instead of PLONKish, and piece 2 identically. No
  IPA verifier for halo2 proofs exists in bellpepper either. Folding
  helps the `T`-to-`T` link, not the transfer-proof link, and the
  transfer-proof link is the expensive one (§2: 64 succinct
  verifications per block of 64).
* **Protostar / ProtoGalaxy / Sangria** for PLONKish folding: Sirius
  (bn256/grumpkin, archived March 2025) and Sonobe (bn254/grumpkin,
  alpha, "do not use in production") [cited: their repositories];
  neither on Pasta, neither with an IPA verifier gadget. Same remark.
* **Accordion** (ePrint 2026/2160, [cited]): batch proving by
  multi-folding many instances of one relation into one accumulator
  and one decider proof, instantiated with KZG; for 64 SHA-256
  instances 2.5 × faster proving and 4 × smaller proofs than 64
  separate proofs. It needs one prover holding every witness, which
  is a wallet proving many of its own transfers, not an indexer
  replaying other people's; not applicable to replay, worth
  remembering for a batch-sending wallet.
* **Changing the transfer circuit's proof system** to something with a
  cheaper in-circuit verifier (e.g. a pairing-based proof over a
  pairing-friendly cycle): that is `REMAINING.md` §2.3(a) again, MNT
  at 753 bits, and the reason A exists is to have no setup.

### 3.3 The verifier split by field: what each circuit computes

What a verifier of one transfer proof does, read off `halo2_proofs`'
verifier for this circuit (`print_verifier_shape` in
`sba-circuit/tests/transfer.rs`: 1 instance column, 10 advice, 21
fixed, 1 lookup, 15 permutation columns, 25 advice and 21 fixed
queries, k = 14; the proof's 138 elements are about 55 Vesta points and
83 `Fp` scalars):

1. **Transcript** (`Fq` sponge, §3.2 piece 2, done): absorb the key's
   representative, the instance commitment, the 10 advice commitments,
   the lookup's 3 and the permutation's product commitments, the
   quotient chunks, then the 83 evaluations, the multiopen's and the
   inner product's 29 points; squeeze ≈ 30 challenges (theta, beta,
   gamma, y, x, x_1…x_4, xi, z, the 14 round challenges). About 135
   permutations.
2. **Group arithmetic** (Vesta points, coordinates in `Fq`, native in
   the `Fq` circuit): the instance commitment (17 fixed-base
   multiplications over the Lagrange generators), the multiopen's
   combination of ≈ 50 commitments with scalars that are powers and
   products of `x_1`, `x_2`, `x_4` (full-width `Fp` scalars), the inner
   product's 28 `L_j`, `R_j` multiplications by `u_j` and `u_j^{-1}`
   (128-bit challenges, but the inverses are full-width), and the
   accumulator fold. Scalars live in `Fp`: the `Fq` circuit cannot
   compute them, so it takes them as witnesses, embedded in `Fq`
   (`p < q`), and the **`Fp` circuit** of the next step checks that
   they are the right functions of the challenges — the 128-bit
   challenges are the only values both circuits derive themselves (the
   `Fq` one from its sponge, the `Fp` one as public inputs it is handed),
   which is why they are 128-bit.
3. **Field algebra** (`Fp`, native in the `Fp` circuit, i.e. inside `T`
   of the next batch): the gate polynomials evaluated at `x` (every
   constraint of the transfer circuit, a few hundred multiplications),
   the permutation and lookup expressions, `l_0`, `l_last`, `l_blind`,
   the vanishing check, the multiopen scalars, `b = Π(1 + u_j x^{2^j})`,
   the inverses `u_j^{-1}`, and the equation the final MSM must satisfy
   (`c`, `f`, the `[-v] G_0` term). A few thousand rows.

Rows of the `Fq` circuit per verified proof [estimate from the ECC
chip's costs in `halo2_gadgets`: a variable-base multiplication by a
full-width scalar ≈ 2–3 rows per bit, so ≈ 700 rows; the width-3
Poseidon ≈ 66 rows per permutation]: ≈ 50 × 700 + 28 × 700 ≈ 55 000
for the multiplications, ≈ 9 000 for the transcript, ≈ 2 000 for the
17 fixed-base ones and the additions — of the order of **2^16 per
transfer proof**, k = 17 for one, k ≈ 21 for a batch of 16. That is
the same order as the paper's `T` costs per slot in R1CS (≈ 217 000
constraints, `REPLAY-PROOF.md` §6), which is to say: a batch step of A
with its transfer proofs verified in-circuit is not smaller than the
paper's, it is merely possible. The first measurement to make is this
circuit for one proof.

What has to exist for it: `halo2_gadgets`' ECC chip is written for
Pallas points in an `Fp` circuit (5 800 lines naming `pallas`); the
`Fq` circuit needs the same chip for **Vesta** points, which the crate
does not have — the mirror image, with the variable-base
multiplication's constants recomputed for the scalar field `Fp`
(`T_Q` → `T_P`, the 255-bit decomposition unchanged in shape). **Done,
4 November 2026: `experiments/vesta-ecc`**, the crate's `ecc` and
`utilities` modules copied with `pallas` → `vesta`, the two constants
swapped (`T_Q = p − 2^254`, `T_P = q − 2^254`), the Sinsemilla
dependency of the lookup table reduced to its constant, the
stored-circuit regression tests replaced by mock-prover runs; the
chip's own tests pass (add, variable-base and fixed-base multiplication,
range checks, the 4.5-bit variant). One asymmetry the port makes
explicit: the Pallas chip takes a base-field element as a scalar
because `p < q` makes every `Fp` element a valid `Fq` scalar; on Vesta
a base-field element (`Fq`) is a valid scalar only when it is `< p`, so
the Vesta chip's scalars are **`Fp` elements embedded in `Fq`** — which
is exactly what a verifier multiplies by (challenges and evaluation
scalars live in `Fp`) — and the crate's tests that drew scalars as
random base-field elements or `−1` were changed to draw them in `Fp`.
The transcript gadget is the gadget crate's `Pow5Chip` over `Fq` with
the sponge rule of `PROFILE-A.md` §1.1: **done the same day,
`experiments/halo2-verifier/src/transcript.rs`** [measured]: the gadget
reproduces the native sponge's challenges on random scripts (the mock
prover refuses a wrong challenge), the 128-bit challenge is a
constrained cell (`s0 = c + 2^128 h`, `c < 2^128`, `h < 2^127` through
the 10-bit table), and a transcript of the shape of a transfer proof's
(201 absorbed elements, 25 challenges, 104 permutations) fits
**k = 13** on its own, below the ≈ 9 000 rows estimated above.

**The verifier gadget, measured the same day**
(`experiments/halo2-verifier/src/{capture,verifier}.rs`). The native
verifier is run first with a recording Poseidon transcript and a
strategy that keeps the guard's deferred form (`Guard::use_g`, the
accumulated mode of §2), which yields for one real transfer proof: 1
instance commitment and the key's representative absorbed, 55 points
and 83 scalars read, 25 challenges, and a final multi-scalar
multiplication of **91 distinct points** (the proof's 55, the instance
commitment, the key's 21 fixed and 13 permutation commitments — three of
which coincide, as identical fixed columns commit to the same point and
`halo2_proofs` merges equal bases — `G_0`, and the prover's accumulator
`G`) plus `W` and `U`. The circuit over `Fq` walks the events: every
point is witnessed on the Vesta chip (on the curve, not the identity)
and absorbed as `x, y`; every scalar is witnessed as the embedded `Fq`
element and absorbed; every challenge is squeezed as a constrained
128-bit cell; then each of the 93 points is multiplied by its witnessed
scalar (the key's commitments, `G_0`, `W`, `U` pinned as constants) and
the sum is constrained to the identity. The instance commitment is
recomputed from the statement's 17 values as the native verifier does
(`Σ instance_i · G_lagrange[i] + [1] W`, the default blind being one),
17 more multiplications by pinned constants, so the statement itself is
a public input and not an opaque point. Public inputs (221): the
statement, the proof's scalars and the challenges in transcript order,
the 93 multiplication scalars, and `G`. What it proves: these proof
bytes and this statement bind these challenges, and with these scalars
the group equation holds; the field side (that the scalars are the
right functions of the challenges and evaluations) is the `Fp`
circuit's, not yet written.

[measured, 4 November 2026, laptop]: **k = 15** (32 768 rows): 101
transcript permutations, 110 variable-base multiplications; the mock
prover accepts the real proof's capture in 0.9 s and refuses a
tampered multiplication scalar and a tampered statement value; as a
Pallas-committed proof of its own: key generation 13.1 s, proving
**4.5 s**, verification 50 ms, 4 416 bytes, 1.1 GB peak. That is a
quarter of the ≈ 2^17 estimated in §3.3: the chip's variable-base
multiplication costs ≈ 260 rows, not 700. Not yet in: the `Fp` side.

**Towards the `Fp` side** (same day): `experiments/halo2-verifier/src/
shadow.rs` recomputes natively, from the typed transcript events and the
key, every scalar of the final multi-scalar multiplication exactly as
`halo2_proofs`' verifier does — `x^n`, `l_0`, `l_last`, `l_blind`, the
gate polynomials at `x` (walked as expression trees over the
evaluations), the permutation and lookup expressions, the expected
quotient evaluation, the multiopen queries (77, over 55 commitment
references in 5 point sets of sizes 1, 2, 3, 3, 2, keyed by reference
as `halo2_proofs` keys them: two equal fixed commitments are two
entries with their own `x_1` powers), the Lagrange interpolation of
each set at `x_3`, `v`, `b`, and the inner product's scalars — and is
checked term by term against the captured MSM [measured: every scalar
equal]. `src/field.rs` is the `Fp` chip the circuit will use (one row
per operation: `a·b·m + a·sa + b·sb + c·sc + k = d`, with inversion as a
witnessed inverse and an expression-tree evaluator).

**The field side, measured the same day**
(`experiments/halo2-verifier/src/fieldside.rs`): the circuit over `Fp`
that mirrors the shadow step by step with that chip. Its structure
(the gate polynomials, the permutation columns and their query indices,
the lookup expressions, the evaluation points as rotations of `x`, the
point sets, each commitment reference's set and `x_1` exponent, and
which references share a point) is built once from the key and one
capture; its public inputs are the challenges and the proof's
evaluations in transcript order (107), then the 93 scalars in the group
circuit's source order, then the `W` and `U` scalars (202 in all). It
recomputes `x^n`, the Lagrange evaluations `l_0`, `l_last`, `l_blind`
(one inversion each), every gate polynomial at `x`, the permutation and
lookup expressions, the expected quotient evaluation, the multiopen
combination (the interpolation of each point set at `x_3` with the
inversions it needs), `v`, `b`, the inner product's scalars, and the
sums over coinciding points, and constrains the results to the
exposed scalars [measured: the mock prover accepts the real proof's
values and refuses a wrong challenge and a wrong output scalar]:
**3 192 field operations, k = 13**; as a Vesta-committed proof of its
own: key generation 2.5 s, proving **0.6 s**, verification 17 ms,
2 272 bytes.

**So the whole verification of one transfer proof is in two circuits:**
the group side over `Fq` (k = 15, 4.5 s to prove) and the field side
over `Fp` (k = 13, 0.6 s), joined by their shared public inputs (the
challenges, the evaluations, the 93 scalars, `W`, `U`). What a batch
step `T` adds is the accumulation itself: it carries the two
accumulators (one per curve), absorbs each new transfer proof's claim
`(G, u_1 … u_14)` into the Vesta one and the field circuit's proof's
claim into the Pallas one, and is verified in turn the same way; for 16
transfers per step that is ≈ 2^19 rows on the `Fq` side and ≈ 2^17 on
the `Fp` side, a minute of proving on the laptop by the scaling of the
transfer circuit (2 s at k = 14). Vendored for it, in `experiments/halo2_proofs-patched`:
`halo2_proofs` 0.3.5 with five read-only accessors made public (the
MSM's terms, the parameters' `W`, `U` and Lagrange generators, the
key's commitments), used through `[patch.crates-io]` by that experiment
alone.

### 3.4 The step `T`, designed

A step proves one fragment of `n` statements of one block. It is two
proofs, one per curve, made **one after the other** by the indexer —
`T_q` first, then `T_p` verifying `T_q`'s group side — because a value
that crosses between the curves (a challenge derived on one side and
used on the other) can only be bound by the circuit that verifies the
proof it is a public input of; two circuits made side by side would
each leave the other's values unbound, and binding them one step later
would need the same binding again a step after that. Halo and Pickles
arrange their step and wrap proofs in the same alternation.

* **`T_q(i)`, over `Fq`, Pallas-committed.** The group side of each of
  the `n` transfer proofs (§3.3: k = 15 each); the group side of
  `T_p(i−1)` (Vesta points, native); the field side of `T_q(i−1)` (`Fq`
  arithmetic, native); and the opening of `T_q(i−1)`'s claim (a
  Pallas claim, inside a Pallas-committed proof). Its public inputs:
  the transfer proofs' challenges, scalars and `G`s, the deferred
  values of the two previous proofs.
* **`T_p(i)`, over `Fp`, Vesta-committed.** (a) The batch relation of
  `REPLAY-PROOF.md` §4.2 over the family's Poseidon: the state opening,
  the `n` statements applied in order through the indexed nullifier
  tree and the note tree, the anchor checks, the digest `D` [estimate
  as §3.2 item 3: ≈ 40 000 rows per slot, 2^20 for 16 slots, 2^18 for
  4]. (b) The field side of each of the `n` transfer proofs (§3.3:
  3 192 operations each). (c) The group side of `T_q(i)` — the same
  step's, which binds everything `T_q(i)` exposed — and the field side
  of `T_p(i−1)`. (d) The openings of the `n` transfer proofs' claims and
  of `T_p(i−1)`'s (Vesta claims, inside a Vesta-committed proof).

Every proof of step `i−1` is thereby verified by step `i`: `T_q(i−1)`'s
group side was in `T_p(i−1)`, its field side is in `T_q(i)`;
`T_p(i−1)`'s group side is in `T_q(i)`, its field side in `T_p(i)`. The
decider verifies the last step's two proofs natively and in full (the
claims `T_p(i)` opened are read from `T_q(i)`'s public inputs), settling
the two claims those leave by two multi-scalar multiplications.

**Scalars across the cycle** [built]. A proof's scalars live in its
curve's scalar field and the circuit verifying its group side in the
base field. For Vesta-committed proofs that is `Fp` in `Fq`, `p < q`:
one cell, range-checked below `2^254` so that the cell is a canonical
`Fp` element (without the check a prover could absorb `s + p` in place
of `s` and grind a second transcript per scalar). For Pallas-committed
proofs it is `Fq` in `Fp`, `q > p`: an `Fq` element does not fit, so it
is carried as two 128-bit limbs — in the proof's transcript (the
sponge over `Fp` absorbs low then high: `native.rs`), as the circuit's
public inputs (two cells, low below `2^128`, high below `2^126`), and
in the multiplications: `Σ [s_i] P_i = Σ [lo_i] P_i + [2^128] Σ
[hi_i] P_i`, two multiplications per term and one more at the end. The
other side reconstructs `hi · 2^128 + lo` natively. A coordinate of a
Vesta point exposed by `T_q` (a claim's `G`) is an `Fq` value `T_p`
reads as a Pallas scalar: it fits unless it lies in `[p, q)`, a range of
`2^-178` of the field — a completeness loss that small, not a
soundness one, since the commitment is binding.

**One step, measured (4 November 2026)** [measured,
`experiments/halo2-verifier/src/step.rs`]: the `q` group side of a
real transfer proof proven for real as `T_q` at k = 15 (keygen 10.8 s,
prove 4.2 s, 4 960 bytes, 221 public inputs, native verification 55 ms
with the Poseidon transcript over `Fp`); its capture: 61 points and 94
scalars read, 26 challenges, 99 MSM terms, 15 inner-product challenges;
the `p` group side of *that* proof in a circuit over `Fp`: 862 public
inputs, 159 permutations, (101 + 221) · 2 = 644 multiplications, **fits
k = 17** (mock prover 6.3 s, 1.2 GB for the whole run), and refuses a
wrong `G` or a wrong limb of a `T_q` instance value. The instance
commitment of `T_q` is 442 of the 644 multiplications: 221 values, each
two limbs, each multiplied as a variable base. Two reductions looked
plain. The first is done: the 219 of those values that are `Fp`
elements embedded in `Fq` (challenges, scalars, evaluations of the
transfer proof, its statement) are carried as one cell each (the
verified circuit says which of its instance values are such,
`instance_limbs_when_verified`), leaving 643 public inputs and 425
multiplications; the `p` group side then uses 70 826 rows [measured,
`CircuitCost`], still k = 17 (the limit of k = 16 is 65 536 rows), so a
variable-base multiplication costs ≈ 130 rows here, half the estimate.
The second — the Lagrange generators as fixed bases with the chip's
window tables — is therefore worth ≈ 40 rows per value, a tenth of the
circuit, and its tables cost 64 s of search per generator [measured,
`find_zs_and_us`], four CPU-hours for 221 of them per (curve, k): a
build artefact for later, not a lever. The lever is the number of
values that cross between the curves, and that is a transcript
question, §3.6.

**One transfer proof verified recursively, end to end (4 November
2026)** [measured, `step.rs::one_transfer_proof_verified_recursively`,
laptop]. `T_p(1)` as one circuit over `Fp`: the `p` group side of
`T_q(1)` and the field side of the transfer proof, bound in-circuit —
each of the field side's 202 values (challenges, evaluations, the 93
scalars, `W`'s, `U`'s) is constrained equal to the `T_q` instance value
the group side exposes, reconstructed from its limbs — and proven as a
Vesta-committed proof that opens the transfer proof's claim
(`create_proof_with_openings`). It fits **k = 17** with the field side
inside (3 192 field rows and 202 links fit in the group side's slack):
keygen 47.8 s, **prove 17.3 s, 5 664 bytes**, 862 public inputs; the
test's peak memory 5.8 GB (the laptop's limit for this; larger keys go
to the server). The decider verifies `T_q(1)` natively (47 ms) and
`T_p(1)` natively with the claim whose `G` and `u` are `T_q(1)`'s public
inputs (163 ms, the full `2^17` multiplication included), and refuses
`T_p(1)` without the claim or with a wrong `u`. The transfer proof
itself is never read by the decider: what it verifies is `T_q(1)`,
`T_p(1)`, and the claim — 10.6 KB and 480 bytes in place of 4.4 KB,
which is the expected loss for one proof and the gain for a block, since
the step's cost does not grow with the number of proofs it covers
beyond the per-proof circuits.

**The second step's pieces (4 November 2026)** [measured]. The field
side of a `T_q` proof, a circuit over `Fq` (`fieldside::fq`, the same
body as the transfer proof's field side with the field and the group
side's sources swapped): 222 public inputs, 3 037 field rows, **k = 13**
— the Pallas chip's gates evaluate in fewer rows than the transfer
circuit's. The `q` group side of a `T_p` proof — a proof that opened a
claim, so its transcript has a second common point, the claim's `G`,
witnessed and exposed and multiplied like a commitment — with `T_p`'s
643 instance values witnessed for its instance commitment but not
exposed (`expose_instance: false`; nothing after the step needs them,
and they are bound by the commitment): 117 MSM terms, 260 public
inputs, 120 210 rows, **k = 17**. So the two circuits of a steady-state
step, by the pieces: `T_q(i)` = the group side of a transfer proof
(≈ 33 000 rows) + the group side of `T_p(i−1)` (≈ 120 000) + the field
side of `T_q(i−1)` (≈ 4 000) ≈ 2^18; `T_p(i)` = the field side of the
transfer proof (≈ 3 000) + the group side of `T_q(i)` (≈ 500 instance
values and ≈ 120 terms, ≈ 80 000) + the field side of `T_p(i−1)`
(≈ 5 000) ≈ 2^17. The server's container for a k = 18 prover
(≈ 10 GB).

**The second step composed (4 November 2026)** [measured,
`step2.rs`]. `T_q(2)` as one circuit over `Fq`: the `q` group side of a
second transfer proof, the `q` group side of `T_p(1)` (sharing the first
one's chip and columns, its public inputs after the first one's), and
the field side of `T_q(1)` bound by 222 links to the `T_p(1)` instance
values the second group side witnessed — a value `T_p(1)` carried as
two limbs is rebuilt in `Fq` as `lo + 2^128 · hi` before the equality.
481 public inputs, 140 846 rows, **k = 18**, mock-satisfied on the
laptop (15 s). `T_p(2)` as one circuit over `Fp`: the field sides of
the transfer proof and of `T_p(1)`, bound to the two parts of `T_q(2)`'s
instance values the `p` group side of `T_q(2)` witnesses (not exposed).
The chain test proves both for real and decides them with `T_q(1)`'s
claim opened in `T_q(2)` and the transfer proof's and `T_p(1)`'s in
`T_p(2)`; k = 18 is the server's job, its figures below once run.

**Accumulation, the Halo way** [cited: ePrint 2019/1021 §4 and §5].
Every verified proof leaves a claim `(G, u_1 … u_k)` on its curve:
the deferred assertion `G = ⟨s(u), params.g⟩`. The claim is settled
without the `2^k` multiplication by opening `G`, as a polynomial
commitment to `s(X)` whose coefficients the prover knows from `u`, at
the next proof's challenge point inside that next proof's multiopen
argument on the same curve: the verifier recomputes the claimed value
as `b(x_3, u) = Π_j (1 + u_j x_3^{2^j})` in `k` multiplications, so the
old claim becomes part of the new proof's single deferred claim, and
each curve carries exactly one claim at any time. In the step: the
Vesta claims of the `n` transfer proofs and of the previous `T_p` are
opened inside `T_p`'s own proof; the Pallas claim of the previous `T_q`
inside `T_q`'s. The decider (the light client, §3.5) settles the two
claims it is left with by two multi-scalar multiplications of `2^k`.
What this needed that `halo2_proofs` did not have — a prover that
adds external commitments with known polynomials to its multi-point
queries and a verifier that expects them — **is done (4 November 2026)
in the vendored crate** `experiments/halo2_proofs-patched`:
`poly::commitment::Claim` (`G`, `u`), `Guard::claim()`,
`create_proof_with_openings` and `verify_proof_with_openings`. Each
claim's `G` is absorbed as a common point after the instance
commitments; its `s(X)` is queried at the proof's `x` with zero
blinding (the crate's default blind is one, the first bug); the
verifier computes `s(x)` itself in `k` multiplications, so an opened
claim adds no bytes to the proof (`x` is a point set the proof already
has). A claim of a smaller `k` opens inside larger parameters because
the generators are hashed by index and so are a prefix. The test
`claims_chain_through_proofs_of_two_sizes` chains three proofs over
k = 5 and k = 6 with the decider at the end, and checks that a
missing, wrong-point or wrong-challenge claim is rejected, that a false
claim cannot be laundered through a proof made over it, and that a
claim larger than the parameters is refused. The alternative that needs no
prover change — a linear accumulator `G_acc ← α·G_acc + G_new` with
every accumulated `u` vector carried along — keeps 14 field elements
per accumulated proof in the state, ≈ 7 KB per 16-transfer block,
which is no longer constant in the history and is rejected for the
light client (it would do for an offline decider of a whole history).

**What crosses between the two circuits, and what it costs.** The
group side of a transfer proof (in `T_q`) derives the 25 challenges
from the proof bytes and needs the 95 multiplication scalars; the field
side (in `T_p`) needs the challenges and the 83 evaluations and
computes the scalars. So per transfer proof 108 values go `T_q → T_p`
and 95 go `T_p → T_q` (the evaluations are proof bytes both can read).
In Halo-style recursion a value crosses curves as a **public input of
the proof it comes from**, read by the circuit that verifies that proof
when it recomputes the instance commitment (§3.3: one multiplication
per value). The step's `T_q` therefore exposes `108 n` values and `T_p`
`95 n`, and the next step's circuits pay `(108 + 95) · n`
multiplications to bind them: for `n = 16`, 3 248 multiplications,
≈ 2^20 rows with the chip's variable-base multiplication (2^18 with
fixed-base tables for the Lagrange generators, which are the same at
every step) — of the same order as everything else in the step
together. This is the known cost of the two-curve design (Pickles
carries its deferred values the same way), and the lever is `n`: a
fragment of 4 statements makes the binding 2^18 rows and the whole
step ≈ 2^19 per side; a fragment of 16 makes it ≈ 2^21. The
indexer's memory sets `n` (the k = 14 transfer prover takes 0.5 GB;
proving scales linearly in rows: ≈ 16 GB at k = 19, which is the
server's container, not the laptop).

**Public inputs of a step** (both circuits): `digest(S_prev)`,
`digest(S_next)`, `D` (as the paper's `T`), the two claims carried in
(`G` as two coordinates, `k` challenges), the cross values above. The
statements themselves are witnesses of `T_p` (bound by `D`) and the
instance values of the transfer proofs' group sides in `T_q` (bound by
their instance commitments and, through the step, by `D`).

**A proven block** (the wire format the light client reads): the block
hash, the state opening after the block, and per fragment the `n`
statements (18 elements each, for the client's own tree), the two
proofs (≈ 6–8 KB each at k = 18–19 [computed as §3.5]), the two
claims (480 bytes each) and the cross values (`203 n` field elements,
≈ 100 KB for `n = 16`, 26 KB for `n = 4`), the last being the part
that does not shrink with recursion: a client that keeps only the
latest step keeps one fragment's worth. The paper's proven block
(`REPLAY-PROOF.md` §4.5) ships, per slot, the envelope's own 192-byte
proof instead; here the transfer proofs are not shipped at all, the
step having verified them.

**Order of work:** the prover change (extra openings) in the vendored
crate with a test that a claim opened in a following proof settles
(done, above); the `p` group side over a real `T_q` (done, above);
`T_p(1)` whole, proven for real and decided, one transfer proof
verified recursively end to end (done, above); then the two reductions
of the instance cost;
then the field side of a `T_q` and the group side of a `T_p` (the
second step); then the batch relation ported from
`crates/sb-circuit/src/batch.rs`; then the fragment size chosen on the
server's memory and the light client's wire format.

### 3.5 Sizes on the light client's side [computed]

Today, without recursion, A's light client would download a **chain
of `T` proofs** like the paper's (`REPLAY-PROOF.md` §4.5): one per
proven block. A Halo 2 proof of a k = 19 `T` is ≈ 6–7 KB [computed:
the proof grows with `k` as ≈ 2k + the fixed number of commitments and
evaluations; the k = 14 transfer proof is 4 416 bytes], against 192
bytes for Groth16: the paper's 245 proven signet blocks of 110 KB
would be ≈ 1.5 MB [computed: 245 × 6 KB] for the same history, 14 ×
more, which is still 23 × less than the 35.2 MB of full blocks
(`REPLAY-PROOF.md` §6) but no longer "succinct" in any sense that
improves with time. **For A, recursion is not an option on top of a
working per-batch chain; it is the way the light client gets back to
a constant-size download.** With it: one `T` proof (≈ 6–7 KB), two
accumulators (≈ 1 KB), the state opening: independent of the number of
blocks.

### 3.6 Fewer values across the cycle: the split transcript [design]

Of the 221 values `T_q` exposes for one transfer proof, 83 are the
proof's evaluations and 93 the scalars of the final multiplication;
26 are challenges, 2 the claim's `G`, the rest the statement. Pickles
[cited: o1-labs/proof-systems, the Pickles design] crosses an order of
magnitude fewer per proof by splitting the transcript by field: the
group side's sponge (over `Fq`) absorbs the commitments and derives the
challenges needed before the evaluations, then squeezes its state into
one digest; the field side's sponge (over `Fp`) starts from that digest,
absorbs the evaluations natively — they are `Fp` elements — and derives
the remaining challenges (`x_1`, `x_2`, `x_3`, `x_4`, the inner-product
`u_j`). The evaluations then never cross; the scalars need not cross
either if the group side combines the commitments by Horner's rule in
the 128-bit challenges (`x_1`, `x_4`, `u_j`) rather than taking their
products as inputs, the few full-width scalars that remain (`u_j^{-1}`
by the Halo rearrangement, the `x^n` powers of the quotient chunks,
`-v`, `c`) being prover-claimed values the field side checks. What
crosses per transfer proof is then ≈ 26 challenges, one digest, a
handful of claimed scalars and `G`: ≈ 40 values in place of 221, and
the challenges after the evaluations cross the other way, from the
field side to the group side of the *following* step (the group side
of a proof needs `x_1 … x_4`, derived after the evaluations it does not
absorb), so the group side of a transfer proof moves to `T_q(i+1)` —
the same delay by one step that Pickles' wrap has. It is a change of
the family's transcript (a-0.4: two sponges, one per field, with a
digest between them), of `verifier_body.rs` (Horner in the challenges,
a 128-bit variable-base multiplication worth adding to the chip) and
of `fieldside.rs` (the second sponge and the challenge derivation).
Decided for later: the structure of the step comes first, then this.

### 3.7 The batch relation in `T_p` [design]

What `T_p(i)` adds to the verifier circuits is `REPLAY-PROOF.md` §4.2's
relation over the family's own state, with one change of role: there
the batch circuit takes the statements on trust (their proofs being the
client's business, §4.3); here the same circuit holds, in the same
proof, the field sides of those statements' proofs and the group side
of the `T_q` that did the rest, so a slot's statement elements are
not free witnesses but copies, bound in-circuit, of the transfer
statement `T_q(i)` exposed as that proof's instance (the `q` group side
recomputes the instance commitment from them: a statement is bound to
its proof by the commitment, and to the slot by the links). `D` stays,
for the light client's own copy of the statements.

* **State.** The family's indexer keeps a note tree, a spent set and the
  roots by height (`sba-indexer/src/state.rs`); the relation needs what
  the paper's state has (`sb-core/src/batch.rs`): the note tree
  (`root`, `size`), an indexed nullifier tree (`nf_root`, `nf_size`;
  `sb-core/src/imt.rs`, sorted linked leaves `(value, next)`, insertion
  as two path updates), a root tree of the note roots by height
  (`h_root`), `height`, `applied`; the state digest `PH_A(T_STATE, …)`
  over the seven. The port: `imt.rs` and `batch.rs` into `sba-core`
  with `Fp` and `PH_A` and tags in the family's style (`sb-a/v1/state`,
  `sb-a/v1/imt`, `sb-a/v1/batch`), the three trees and the opening
  into `ReplayState` beside the spent set (the set stays as the index
  the CLI reads; the trees are what the proof opens), and the
  checkpoints extended so that a reorganisation rolls the trees back
  as it rolls the set back.
* **Slot.** The paper's 18 elements become the family's 16: `h_anchor`,
  `r_anchor`, 2 nullifiers, 2 × (`pk_eph` as two coordinates, `ct_note`
  as its 3 elements), `h_body`, the kind — with no `h_aux` (the
  family's leaf is `note_leaf(const_salt, h_body, j, pk_eph, ct)`,
  `sba-core/src/note.rs`, which the circuit recomputes with the
  Poseidon chip). The transfer statement's `const_salt` and arities are
  the circuit's constants.
* **Rows** [estimate from the paper's circuit, `sb-circuit/src/batch.rs`]:
  per slot, 13 Merkle paths of depth 32 (the anchor's, four per
  nullifier insertion, two per output leaf) and a few leaf hashes,
  ≈ 430 permutations of the width-3 Poseidon chip at ≈ 66 rows each
  ≈ 28 000 rows, plus the range checks of heights and positions
  (lookups) and the comparisons; the digest `D` over `23 n` elements.
  `n = 4`: ≈ 2^17 for the relation, so `T_p(i)` ≈ 2^18 with its
  verifier parts (§3.4's figures: 4 × 3 000 + 80 000 + 5 000), and
  `T_q(i)` with four transfer proofs' group sides (4 × 33 000) beside
  `T_p(i−1)`'s (120 000) ≈ 2^18, at its limit; `n = 8` puts both at
  2^19 — the server's k = 19 is the fragment size's ceiling until §3.6
  shrinks the group sides.
* **Order of work.** `sba-core`: `imt.rs`, `batch.rs` (the opening,
  the slot, the digest, the witnesses) — native, tested against the
  paper's by shape; `sba-indexer`: the trees in the state and the
  checkpoints, the batch witness produced per block; the circuit in
  `experiments/halo2-verifier/src/batch.rs` over the Poseidon chip (a
  Merkle gadget, the indexed insertion, the slot rules) measured alone
  with the mock prover; then into `StepP2` with the links to the
  transfer statements; then the chain test with real statements from a
  replayed signet history.

## 4. What this study decides

* **Now, no profile change:** batch verification in the indexer (§2),
  a code change in `sba-indexer` with a test that a bad proof in a
  block is found. It cuts A's verification cost per transfer by 5 × at
  block size 64 and is independent of everything else here.
* **Before any accumulable deployment:** the algebraic transcript
  (§3.2 piece 2), as `a-0.x`, with the vectors regenerated; the rest
  of the circuit untouched. Done: a-0.3, 4 November 2026.
* **The measurement that decides the rest: made.** The succinct-verifier
  gadget (§3.3) verifies the group part of one transfer proof at k = 15,
  2^15 rows, a quarter of the estimate; a batch of 16 transfer proofs
  is ≈ 2^19 rows of verification, which the laptop proves (the k = 14
  transfer takes 2 s; k = 19 of the order of a minute). So the
  recursive `T` is a slice of ordinary size, on the paper's scale per
  slot, and the design stays the full one: every transfer proof
  verified in-circuit, no trust in the indexer for them.
* **Next:** the step `T` as §3.4 designs it, in its order of work:
  the prover's extra openings, one recursive step over two transfer
  proofs measured, the batch relation ported, the fragment size and
  the wire format. The cost that recursion does not remove — the
  binding of the values that cross between the two curves, ≈ 203
  multiplications per transfer proof in the following step — is stated
  there with the lever that controls it (the fragment size).
* **Not now:** porting `T` (piece 3) before the gadget is measured;
  Nova or any folding library, for the reason in §3.2.

## 5. Sources

* `REPLAY-PROOF.md` §2–§4, §6; `REMAINING.md` §2.3; `VARIANT-A.md`
  §2, §4.2, §7; `PROFILE-A.md` §1, §8.
* `experiments/halo2-accumulate` (this document's §2), 3 November 2026.
* Bowe, Grigg, Hopwood, *Halo: Recursive Proof Composition without a
  Trusted Setup*, ePrint 2019/1021. The Halo 2 book, chapters
  "Recursion" and "Transcript". `halo2_proofs` 0.3.5,
  `poly::commitment::{Guard, Accumulator, MSM}` and
  `tests/plonk_api.rs` (the accumulation strategy).
* zcash/halo2 DAG page and issue tracker (recursion never completed),
  read 3 November 2026.
* notnotraju, *Verification of batch IPA proofs in halo2-lib*, HackMD.
* Kothapalli, Setty, Tzialla, *Nova*, ePrint 2021/370; microsoft/Nova
  README (`nova-snark` 0.76, Pasta, zero knowledge, compression);
  Kothapalli, Setty, *CycleFold*, ePrint 2023/1192.
* snarkify/sirius (archived 24 March 2025); privacy-ethereum/sonobe
  (alpha); `sonobe` 0.1.0-alpha.1 on crates.io.
* Balbás, Nitulescu, Plançon, *Accordion: Efficient Batch Proving via
  Algebraic Folding*, ePrint 2026/2160.

## 6. Changelog

* **v0.6** (4 November 2026) — §3.4, the step `T` designed: the two
  circuits of a step, Halo-style accumulation by re-opening (and the
  prover change it needs, done the same day in the vendored crate:
  claims opened inside a later proof, tested over two sizes), the
  cross-circuit binding and its cost, the proven block's wire format,
  the order of work. Then, the same day: the sequential order of the
  two circuits (the binding argument), scalars across the cycle (two
  limbs, canonicity), and one step measured — the `p` group side of a
  real `T_q` proof at k = 17, then `T_p(1)` whole at k = 17 proven and
  decided: one transfer proof verified recursively end to end.
* **v0.5** (4 November 2026) — the field side measured on the real
  proof (§3.3: k = 13, 0.6 s); the verification of one transfer proof
  complete in two circuits; the batch step `T` set as the next design.
* **v0.4** (4 November 2026) — the verifier gadget measured on a real
  proof (§3.3: k = 15, 4.5 s with the instance commitment recomputed
  in-circuit), §4's deciding measurement made and the next steps set.
* **v0.3** (4 November 2026) — §2 re-measured under the a-0.3
  transcript; §3.3, the verifier split by field with the message
  inventory of this circuit and the row estimate; §4's third decision
  made concrete; the Vesta chip port and the transcript gadget done and
  measured (§3.3).
* **v0.2** (4 November 2026) — §3.2 piece 2 and §4's second decision
  done (the Poseidon transcript, a-0.3).
* **v0.1** (3 November 2026) — the three questions under A, the
  measured verification modes, the recursion shape and inventory, the
  light-client arithmetic, the decisions.
