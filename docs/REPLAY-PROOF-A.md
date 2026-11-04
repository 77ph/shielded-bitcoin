# Succinct replay proofs for variant A (study, draft v0.2)

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
transfer circuit (k = 14, 4 416-byte proofs, the Blake2b transcript of
the profile) in the three modes, on the laptop (release, 20 threads
for the multi-scalar multiplications):

| n | one by one, per proof | batched into one MSM (`Guard::use_challenges`), per proof | accumulated: succinct part per proof + one final MSM for all claims, per proof |
|---|---|---|---|
| 1 | 29.7 ms | 29.1 ms | 8.4 ms + 26.3 ms = 34.7 ms |
| 4 | 31.2 ms | 11.6 ms | (23.6 ms + 27.7 ms) / 4 = 12.8 ms |
| 16 | 30.7 ms | 7.2 ms | (83.2 ms + 32.2 ms) / 16 = 7.2 ms |
| 64 | 30.5 ms | 5.8 ms | (309.8 ms + 55.6 ms) / 64 = 5.7 ms |

[measured, 3 November 2026; keygen 1.1 s, 64 proofs in 152 s, peak
531 MB]. The prover-side `G` (what a prover ships with an
accumulated proof) costs 30 ms per proof to compute, the same MSM the
verifier saves. The accumulator per proof is `G` (32 bytes) plus the
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
* **The succinct part is ≈ 5 ms of native work per proof** (309.8 ms /
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

### 3.3 Sizes on the light client's side [computed]

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
* **The measurement that decides the rest:** the succinct-verifier
  gadget prototype (§3.2 piece 1) in `experiments/`, over `Fq` with the
  ECC chip, verifying one transfer proof made under a Poseidon
  transcript: rows, k, proving time. If it lands near the estimate
  (2^15–2^16 rows per proof), the recursive `T` is a slice of ordinary
  size; if it is an order of magnitude worse, a batch of 16 transfer
  proofs does not fit a circuit the laptop can prove, and the design
  moves to verifying transfer proofs natively per block (the batched
  mode of §2) with recursion only over the `T` chain, which keeps the
  light client's constant size but trusts the indexer for the transfer
  proofs it did not verify — a weaker statement that must be said as
  such.
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

* **v0.2** (4 November 2026) — §3.2 piece 2 and §4's second decision
  done (the Poseidon transcript, a-0.3).
* **v0.1** (3 November 2026) — the three questions under A, the
  measured verification modes, the recursion shape and inventory, the
  light-client arithmetic, the decisions.
