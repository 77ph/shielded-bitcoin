# Succinct replay proofs for variant A (study, draft v0.5)

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

### 3.4 Sizes on the light client's side [computed]

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
* **Next:** `T` in Halo 2 carrying both accumulators (§3.3's last
  paragraph): the batch relation of `REPLAY-PROOF.md` §4.2 over the
  family's Poseidon, plus the two circuits above applied to each
  transfer proof of the batch and to the previous step's proofs, with
  the accumulators' claims settled by the light client at the end with
  two multi-scalar multiplications. Design first (what each of the two
  circuits of a step contains, what crosses between them as public
  inputs, the wire format of a proven block), then the port of
  `batch.rs`.
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
