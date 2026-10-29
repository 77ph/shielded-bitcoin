# What remains of §22, and why not now (draft v0.3)

Status: a closing document for the paper's §22, the companion of the
roadmap. Every item of §22 now ends in one of two ways: as an
implementation run on a test network, documented in its own file, or
here, as a demonstration with numbers that it cannot be implemented on
this stack now, with the conditions under which it could be. Reviewed:
`REVIEW-REMAINING.md` (paper pass, PASS, arithmetic re-derived). This file
covers the three items that end the second way: smaller proof systems
(§22.1), certified-recipient lineage (§22.4, Appendix D) and the
PIPE-based boundary (§20.4, §22.3). It is written for a reader who will
check the arithmetic.

Conventions. Every number is tagged. **[cited]** is a number taken from a
source, with the section or table it comes from; **[measured]** is a
number produced by this repository's code on the development laptop (16
GB, 16 threads, release builds, commit of this file); **[computed]** is
arithmetic on tagged numbers, shown; **[estimate]** is an extrapolation,
with its assumption stated. Sources are listed in §5 and referred to by
ePrint number. The paper is [SB26].

## 1. Smaller proofs: Polymath and Pari (§22.1)

### 1.1 What the paper asks

§22.1 notes that Groth16 proofs are about 192 bytes, that Polymath
[2024/916] and Pari [2024/1245] report about 176 and 160 bytes, that
the difference "feed[s] directly into the footprint figures", that each
candidate "carries its own setup and security assumptions", that a
circuit-specific system "needs one trusted setup per supported arity",
and that a system without Groth16's proof re-randomization "would remove
the re-randomization caveat in the security analysis (Section 14.3)".

### 1.2 The exact saving on this stack [computed]

The profile (`PROFILE.md` §7.1) publishes a 508-byte body and a 192-byte
Groth16 proof (`A` 48 ‖ `B` 96 ‖ `C` 48 bytes, compressed BLS12-381).
Polymath's proof is 3 G1 + 1 field element = 3 × 48 + 32 = 176 bytes
(1408 bits [cited: 2024/916 Table 1]); Pari's is 2 G1 + 2 field elements
= 2 × 48 + 2 × 32 = 160 bytes (1280 bits [cited: 2024/1245 §1,
"Concurrent work"]). Carrier weights are the measured ones of
`WITNESS-CARRIER.md` §6: an OP_RETURN byte weighs 1 vB, a witness byte
0.25 vB.

| Proof system | Proof | Envelope | OP_RETURN carrier | Witness carrier |
|---|---|---|---|---|
| Groth16 (this profile) | 192 B | 700 B | 825 vB [measured] | 447 vB [measured] |
| Polymath | 176 B | 684 B | 809 vB (−1.9 %) | 443 vB (−0.9 %) |
| Pari | 160 B | 668 B | 793 vB (−3.9 %) | 439 vB (−1.8 %) |

For scale: the carrier choice already implemented moved the same
envelope from 825 to 447 vB, −45.8 % [measured]; the key-committing
`ct_out` pad of the profile's v0.2 cost +32 bytes, the exact size of the
larger of the two savings. At 1 sat/vB the saving is 16–32 sat per
transfer; at 50 sat/vB, 800–1600 sat.

### 1.3 What each system gives and does not give [cited]

| | Groth16 [Gro16] | Polymath [2024/916] | Pari [2024/1245] |
|---|---|---|---|
| Proof | 2 G1 + 1 G2 | 3 G1 + 1 F | 2 G1 + 2 F |
| Arithmetization | R1CS | SAP (m̃ ≈ 2m, ñ ≈ 2n) | SR1CS |
| Setup | circuit-specific | circuit-specific ("non-universal"), SRS (m̃ + 12ñ) G1 | circuit-specific, pk O(η) F + (4k − n) G1 |
| Prover | (m + 3n) m1 + n m2 | (m̃ + 13ñ) m1 | 1 MSM of size k − n and 3 of size m in G1 |
| Verifier | 3 pairings + m0 m1 | 2 pairings + 2 m1 + 1 m2 + O(m0 log m0) f | 3 pairings + O(x) f |
| Zero knowledge | yes | yes | **not as published**: "we believe that PARI can be extended to support zero-knowledge … we leave this for future work" |
| Security model | generic group model | AGMOS (AGM with oblivious sampling) | AGM + ROM, for "(an interactive version of) PARI" |
| Non-malleability or simulation extractability | not claimed; re-randomizable | not claimed in the paper | not claimed in the paper |
| Multi-party setup protocol | BGM17, implemented here (`CEREMONY.md`) | none described | none described |

(Polymath row: Table 1 and §1 of 2024/916; Pari row: §1 "Concurrent
work" and §6.2 of 2024/1245. "Not claimed" means that neither paper
states the property for its construction; the Polymath paper names
"simulation-extractability" once, in §2.1, among the "additional
security properties" that a choice of trapdoor exponents "possibly"
guarantees, without claiming it for Polymath.)

### 1.4 Why the re-randomization caveat is not what moves

The paper's caveat (§14.3, "Proof re-randomization") is that Groth16
admits π′ ≠ π for the same statement, and that since `h_body` excludes
the proof bytes, π′ yields the same body and nullifiers and "replay
rejects it as a repeated nullifier"; the residue is a changed carrier
txid, "a publication-layer concern". Removing the caveat therefore needs
a proof system *proven* non-malleable (simulation-extractable), not one
that merely lacks Groth16's known re-randomization map. Neither Polymath
nor Pari claims that property (§1.3). The replacement would move the
caveat from "re-randomization exists" to "non-malleability is not
proven", which is not a smaller caveat. On this stack the txid residue is
already handled where the paper puts it: the fee vault's draw
authorization signs `h_body`, not a txid (`FEE-VAULT.md` §3), and the
batch statements of the replay proof carry the envelope's statement
elements, not the txid (`REPLAY-PROOF.md` §4.2).

### 1.5 Implementation status [cited: repository metadata, 29 October 2026]

* `CharmsDev/polymath`: "the first (as far as we know) implementation"
  of Polymath, Rust on arkworks 0.4, Apache-2.0, last push February
  2025, 31 stars. This repository is on arkworks 0.5.
* `alireza-shirzad/garuda-pari`: "A Rust implementation of the Garuda
  and Pari SNARKs", no licence field, last push June 2026, 2 stars.

Neither is a reviewed library, neither ships a parameter ceremony, and
neither paper describes a multi-party setup. Adopting either here would
mean: a new proof encoding and verifier interface (`PROFILE.md` §7,
§8.4), a new circuit-specific setup for each of the three circuits of
this stack (transfer, swap, batch) without a published MPC protocol for
it (the ceremony crate implements BGM17, which is Groth16-specific), and
for Pari a transfer proof that is not zero-knowledge until the authors'
future work exists.

### 1.6 The arity and statement-scope items of §22.1

These two are closed by implementation, not by this document: the
profile fixes a single 2-in-2-out arity with dummy padding ("Any other
arity is invalid", `PROFILE.md` §7), so no transfer is classifiable by
its counts, at the cost the paper asks to measure: a dummy input or
output costs exactly what a real one costs, the transfer circuit is
84 362 constraints for every transfer [measured], and the envelope is
700 bytes for every transfer. The statement scope is the 17 public
inputs of `PROFILE.md` §8.1.

### 1.7 Verdict

No cryptographic obstacle, and no reason now. The lever is worth at most
32 bytes per envelope, 3.9 % of the OP_RETURN carrier and 1.8 % of the
witness carrier, an order of magnitude below the carrier lever already
pulled (45.8 %). The price is a change of security model (AGMOS or AGM +
ROM in place of the generic group model), a circuit-specific setup
without a published ceremony protocol, and for Pari the loss of zero
knowledge as published. The item reopens when (a) a multi-party setup
for the chosen system is published, (b) the system is proven
simulation-extractable, so that the caveat of §14.3 actually closes,
and (c) a carrier limit exists under which 16–32 bytes decide
standardness. None of the three holds on 29 October 2026.

## 2. Certified-recipient lineage (§22.4, Appendix D)

### 2.1 What the paper asks [cited: SB26 Appendix D]

A certified-lineage output "carries a recursive proof that its roots are
authenticated peg-ins, that every preserving transfer used only inputs
with valid lineage, and that the output was created for its certified
recipient address". At peg-in, "a PegInExecutionProof, evaluated under a
rule fixed by the deployment, authenticates the accepted Bitcoin anchor,
the inputs and amount actually used, and the shielded output". For a
transfer, "the lineage-step proof verifies the package of every consumed
input" and "binds the new claim to the specific base transfer and to the
specific output within it". "A preserving output carries a fixed-size
encrypted package containing the current recursive proof and a compact
statement commitment"; ordinary outputs carry "a same-length encrypted
dummy payload, so the branches are not distinguishable on chain". "Under
the zero-knowledge and encryption assumptions, the lineage proof need
not reveal earlier addresses, holders, or the transfer graph."

### 2.2 The requirements, separated

* **R1, unbounded recursion.** A package must verify the packages of
  both consumed inputs (the profile's arity is 2-in), at any depth: the
  depth of a lineage is the number of preserving transfers since the
  peg-in, unbounded by the protocol.
* **R2, zero knowledge at every step**, otherwise earlier addresses leak
  through the package.
* **R3, binding to the base transfer.** The step must bind to the
  exact transfer and output: the nullifiers, the note commitments, the
  `h_body` of the base envelope, all of which are field elements of
  BLS12-381's scalar field (`PROFILE.md` §2.1, §5.3–5.4, §7.2).
* **R4, a peg-in execution proof** under a peg rule, which presupposes a
  boundary with a rule a proof can authenticate (§3 of this file).
* **R5, a fixed-size package on chain**, in the note's encrypted data,
  per output, with dummies of the same length on every other output.

R2 and R3 are circuit work of the kind this repository does (the swap
extension binds a SHA-256 hash-lock in-circuit; the batch circuit
rebinds whole statements). R1 is the obstacle; R5 prices it; R4 waits
on §3.

### 2.3 R1 on this curve, with numbers

A recursive proof needs a verifier of the proof system inside the proof
system. For pairing-based proofs the verifier computes pairings over
the curve's *base* field while the circuit is over its *scalar* field.
The four known ways to close that gap are listed, each with its number.

**(a) A pairing-friendly cycle.** Two curves such that each one's base
field is the other's scalar field give native recursion at every depth.
"The only known cycles are formed by alternating MNT curves of
embedding degrees 4 and 6" [cited: 2022/1662 §1]; "there is no 2-cycle
with embedding degree pairs (5, 10), (8, 8) or (12, 12)" and no cycle of
only Freeman or only BN curves [cited: 2022/1662 Proposition 3.4]; for
the known parametric families, "no 2-cycles can arise from the known
families, except for those cycles already known" [cited: 2022/1662
abstract, Theorem 4.5]. Because of the low embedding degrees "the
parameter sizes need to be very large to avoid classical
discrete-logarithm attacks" [cited: 2022/1662 §1]; the MNT4/6 cycle at
753 bits is "quite inefficient at the 128-bit security level" [cited:
2022/1162 §6]. BLS12-381 is on no known cycle, so this route means
moving the whole profile (every Poseidon value, the embedded curve for
keys, the three circuits, the three setups, the address format) to
MNT4-753/MNT6-753.

[measured, `experiments/cycle`, arkworks 0.5 pairing gadgets, inner
proof with 17 public inputs]: verifying one MNT4-753 Groth16 proof
inside an MNT6-753 circuit costs **372 279** constraints; the converse,
an MNT6-753 proof inside MNT4-753, **660 423**. Levels alternate, so a
lineage step at depth d verifies two packages of the other curve: 2 ×
372 279 = 744 558 or 2 × 660 423 = 1 320 846 constraints per step
[computed], before the step relation itself. Proving the 372 279-
constraint outer circuit alone was attempted: the Groth16 setup was
killed by the kernel at **9.4 GB resident** on the 16 GB laptop
[measured, `--prove`]. The lineage prover is the user's wallet; the
transfer circuit it runs today is 84 362 constraints on a 255-bit field,
proven in 1.5 s [measured].

**(b) A 2-chain: one native level.** An outer curve whose scalar field
is the inner curve's base field verifies the inner proof natively, once;
the outer proof has no native verifier in turn, so the chain has one
level. A lineage of depth d needs d levels: a 2-chain does not give R1.
It is still measured here because it bounds what *any* bounded-depth
scheme costs, and because it exposes a property of BLS12-381 that the
reader of §22.4 should know.

[measured, `experiments/twochain`, 17 inner public inputs, outer proof
over the outer curve, `--prove`]:

| Inner → outer | Outer scalar field | Constraints (of which verifier gadget) | Outer setup | Outer prove | Outer verify |
|---|---|---|---|---|---|
| BLS12-377 → BW6-761 | 377 bits, 2-adicity 46 | 154 649 (75 003) | 8.8 s | 10.7 s | 12.6 ms |
| BLS12-381 → BW6-767 | 381 bits, 2-adicity 1 | 169 580 (74 741) | **fails**: `PolynomialDegreeTooLarge` | — | — |

Peak resident memory of the run: 2.2 GB [measured]. The second row is
this profile's curve. Its outer curve exists (BW6-767, shipped by
arkworks as `ark-bw6-767`, scalar field = BLS12-381's base field) and
the verifier circuit synthesises and is satisfied, but no Groth16 key
can be generated for it: the prover needs an evaluation domain of at
least 2^18 points, and BLS12-381's base field q has q − 1 ≡ 2 mod 4
(2-adicity 1), with arkworks' mixed-radix fallback allowing 2 × 3² =
18 points. This is not an arkworks limitation but the definition: a
SNARK-friendly 2-chain requires "r₂ − 1 ≡ r₁ − 1 ≡ 0 mod 2^L" for a
large L [cited: 2021/1359 Definition 2], and for an outer curve over
BLS12-381, r₂ − 1 = q − 1 has L = 1. BLS12-381 is not the inner curve of
any SNARK-friendly 2-chain, by definition; an FFT-free prover over
BW6-767 would be a research object, not an engineering one. The
corollary for `REPLAY-PROOF.md` §4.4 stands: the one native level is
bought only by moving the profile to BLS12-377.

**(c) Non-native verification on the same curve.** The verifier's
pairings over the 381-bit base field are emulated in the 255-bit scalar
field. The reference point is gnark's emulated pairing, R1CS, in a
254-bit scalar field [cited: El Housni, "emulated pairing", ACNS 2023
companion page]: one BLS12-381 pairing costs **2 088 277** constraints
(Miller loop 898 237, final exponentiation 1 190 040); a product of 4
pairings, which is what a Groth16 verification is (e(A, B) against α·β,
L·γ, C·δ), costs **3 895 167**. A lineage step verifying two packages
is then ≥ 7 790 334 constraints [computed] before the step relation,
92 × the transfer circuit [computed: 7 790 334 / 84 362]. The largest
circuit proven on this laptop is the n = 4 batch circuit, 902 685
constraints, at 4.6 GB and 31–54 s [measured, `RUNS.md`]; a step 8.6 ×
larger is beyond 16 GB if memory scales linearly [estimate: Groth16
proving memory is linear in the constraint count; measured 4.6 GB × 8.6
≈ 40 GB]. The emulation itself exists in gnark (Go), not in arkworks.

**(d) Folding or accumulation on a cycle of non-pairing curves.** Nova
[2021/370] folds R1CS instances over a cycle such as Pasta with a
verifier circuit of "≈10,000 R1CS constraints" [cited: §1.3]; "Nova is
not a zero-knowledge IVC scheme" and zero knowledge comes only from the
final compression SNARK, whose "compressed IVC proofs are ≈ 8–9 KB"
[cited: §1.3, §5]. Split accumulation [2020/1618] gives zero-knowledge
PCD with a "recursion threshold … as low as 52,000 constraints" on
Pasta "at the expense of much larger proof sizes" [cited: §1.1 (5)].
Both replace Groth16 for the lineage layer with a transparent system
over non-pairing curves; R3 then binds Poseidon values of BLS12-381's
scalar field inside a Pasta circuit, which is non-native arithmetic
again, and R5 puts a package of kilobytes on every output.

### 2.4 R5: what each route puts on chain [computed]

Package = proof + 32-byte statement commitment + 16-byte AEAD tag, per
output, two outputs per envelope. Proof sizes use arkworks' compressed
encodings: a G1 point is ⌈log₂ q / 8⌉ bytes, a G2 point that times the
twist degree.

| Route | Proof per package | Added per envelope (2 outputs) | OP_RETURN carrier | Witness carrier |
|---|---|---|---|---|
| none (today) | — | 0 | 825 vB | 447 vB |
| Groth16 on MNT4-753 | 95 + 190 + 95 = 380 B | 856 B | ≈ 1 681 vB (×2.0) | ≈ 661 vB (×1.5) |
| Groth16 on MNT6-753 | 95 + 285 + 95 = 475 B | 1 046 B | ≈ 1 871 vB (×2.3) | ≈ 709 vB (×1.6) |
| Groth16 on BW6-761/767 (one level only) | 96 + 96 + 96 = 288 B | 672 B | ≈ 1 497 vB (×1.8) | ≈ 615 vB (×1.4) |
| Nova compressed (not ZK as IVC) | 8–9 KB [cited] | ≈ 16–18 KB | ≈ 17 000–19 000 vB (×21–23) | ≈ 4 500–5 100 vB (×10–11) |

Every ordinary transfer pays the same, because Appendix D requires the
dummy payload on every non-lineage output "so the branches are not
distinguishable on chain". The lineage layer is therefore not opt-in in
its footprint: it is paid by every envelope of the deployment.

### 2.5 R4: the peg dependency

The issuance proof "authenticates the accepted Bitcoin anchor, the
inputs and amount actually used" under "a rule fixed by the
deployment". This stack's boundary is the custodial development mint
(`BOUNDARY.md`): the rule is the operator's signature, and a proof of
it proves nothing about Bitcoin inputs. A lineage root cannot be
specified before the boundary of §3 exists; the Trust Authority and its
policy epochs are organisational components with no code counterpart.

### 2.6 Verdict

Not now, and not by engineering. R1 has no solution on this curve
without changing the curve of the whole profile: (a) costs 0.74–1.32 M
constraints per step on 753-bit fields and already exceeds the laptop at
one verification; (b) is not recursion and, for BLS12-381, has no
prover at all; (c) is ≥ 7.8 M constraints per step, 92 × the transfer
proof, with no arkworks implementation; (d) abandons Groth16 and puts
8–9 KB per output on chain or gives up zero knowledge. R5 multiplies
every envelope's weight by 1.5–22 whichever route is taken. R4 waits
on §3. The item reopens when a pairing-friendly cycle at 128-bit
security with a verifier under ≈ 10⁵ constraints is found (2022/1662
proves there is none in the known families), or when a zero-knowledge
IVC with sub-kilobyte proofs exists natively over BLS12-381's scalar
field, and in either case only after a boundary with a rule.

## 3. The PIPE-based boundary (§20.4, §22.3)

### 3.1 What the paper asks

§20.4: "the expected boundary construction is PIPE-based. The peg-in,
peg-out, and related unlock rules are meant to be expressed as
Bitcoin-anchored metaprotocol transitions"; §22.3: "the intended
architecture is PIPE-based" and the fee-unlock vault is "the intended
PIPE-based direction". Both sections say the boundary's trust, liveness,
censorship-resistance and privacy "belong to the boundary protocol".

### 3.2 What PIPEs v2 is [cited: 2026/186]

A PIPE "binds the release of a private key to the satisfaction of an NP
statement" (§1): the Schnorr key of a locked output is witness-encrypted
under a statement x, and "a valid witness w with (x, w) ∈ R allows sk to
be recovered exactly once. After decryption, the user holds an ordinary
secret key and can generate Schnorr signatures on arbitrary messages
without any further interaction with the PIPE mechanism. Consequently,
WE-based PIPEs do not provide per-signature enforcement … they realize a
one-time, witness-gated key release" (§1.1). The earlier functional-
encryption design (PIPE v1) was abandoned: "expressing elliptic-curve
operations required for Schnorr signatures as low-degree polynomials
exceeded the computational depth supported by QFE, and general-purpose
FE schemes … require iO or graded encodings, which are currently far
from practical" (§1.1). The paper proves the generic construction
(witness signatures from WE + Schnorr + a NIZK, Theorems 1–3) and
leaves the instantiation of WE to §5.

### 3.3 The instantiation and its numbers [cited: 2026/186 §5, 2026/175]

The chosen WE is the AADP construction of [2026/175]: "Our security
claim remains heuristic, as in [BIJ+20], and we support it via
extensive cryptanalysis" (2026/175 §1); "Neither AADPs nor original
ADPs have a reduction to a well-established security assumption"
(2026/175 §3); the theoretical claim is an unfalsifiable extractability
assumption (2026/175 Assumption 1) and the concrete claim is "at least
100 bits of security" on BN254 (Assumption 2). The PIPEs paper says the
same: the AADP schemes "are heuristic and do not currently admit
security proofs under standard falsifiable assumptions" (§5, introduction), and lists
as open "identifying and formalizing minimal algebraic conditions
sufficient to guarantee soundness" (§5.4).

Cost, from 2026/175 §4.10, "a python script (approximately) modeling
the gadgets": the arithmetized verifier of the authors' own tailored
SNARK has v = 14 083 variables and g = 14 371 gates, of which the
pairing equation is 8 212 / 8 307, and the ciphertext size is
v (2g + 1)² |F|. With |F| = 32 bytes:

    14 083 × (2 × 14 371 + 1)² × 32 B = 14 083 × 826 160 049 × 32 B
                                      = 3.72 × 10¹⁴ B = 338 TiB = 372 TB   [computed]

matching the papers' "≈ 338 TB" when their TB is read as the binary
unit (2⁴⁰ bytes); in decimal terabytes the same ciphertext is 372 TB. The authors add: "These numbers should
not be fully trusted - after all, we do not have a full implementation
and only a modeling script which could very well miss some important
subroutine completely" (2026/175 §4.10); the PIPEs paper: "based on a
modeling script rather than a complete end-to-end implementation" (§5.3.1).
The alternatives the PIPEs paper surveys are worse: bit-level ADP
encodings of a SNARK verifier give ciphertexts "on the order of 10²⁷"
field elements (2026/175 §1); iO-based WE is "quite inefficient";
evasive-LWE WE rests on non-standard assumptions with known
counterexamples (2026/186 §5). The linear-verifier WE line "cannot be
used to construct WE for Groth16 SNARK, which has a quadratic verifier"
(2026/186 §1.3).

### 3.4 Mapped onto this stack

* **Per release.** One PIPE releases one key once. A peg-out is one
  release, so one ciphertext of ≥ 338 TiB per withdrawal, generated at
  deposit time for a statement that must already name the exit
  condition. The number is for the authors' tailored SNARK over BN254
  at ~100-bit security. A ciphertext that verified this profile's
  Groth16 proofs directly would be larger: |F| is 48 bytes on BLS12-381
  (× 1.5 in the formula) and a Groth16 verification is four Miller
  loops where the tailored verifier's "pairing equation" is counted
  once; the factor is not estimated here because the ciphertext is
  cubic in the gate count and the gate count of a projectively safe
  BLS12-381 verifier is not in any source. Either way the proof system
  of the lock is not this profile's: a withdrawal would be proven twice,
  once for replay (Groth16) and once for the lock.
* **The fee vault.** The vault releases fees per draw under rule R1–R5
  (`FEE-VAULT.md` §5), one draw per publication. A one-time key release
  cannot enforce a per-draw rule (3.2); the vault as the paper wants it
  needs the per-signature enforcement the authors abandoned with PIPE
  v1. A WE-PIPE vault would be one locked output per draw, each with its
  own ciphertext.
* **What is ready for a PIPE.** The parts of the boundary that are
  protocol, not cryptography, are specified and run: the deposit whose
  `rseed` commits to a BIP 340 key and the signed draw and reclaim
  messages (`FEE-VAULT.md` §2–3), the release rule and the ledger
  invariants I1–I3 (§5–6), the payout memo and withdraw flow
  (`BOUNDARY.md`), the boundary leakage model (`FEE-VAULT.md` §10), and
  a succinct statement a lock could reference: the state digest D and
  the batch proof chain of `REPLAY-PROOF.md`, which is exactly the
  "validity proof" shape a one-time release expects. A PIPE would
  replace the operator's code at the points `FEE-VAULT.md` §9 marks,
  and nothing else.

### 3.5 Verdict

Not now, by orders of magnitude and by an open problem. The only
candidate the PIPEs authors consider implementable needs ≈ 3.7 × 10¹⁴
bytes per key release, has no end-to-end implementation, rests on a
heuristic security claim whose soundness conditions the authors list as
open, and releases a key once, which fits a peg-out and not the fee
vault. The item reopens when a WE for a SNARK verifier exists with a
security reduction and ciphertexts measured in megabytes, or when
Bitcoin gains a covenant opcode, at which point the vault's rule R1–R5
and the withdraw flow are the specification to enforce.

## 4. §22 as a whole: where each item ends

| Item | Ends as | Where |
|---|---|---|
| §22.1 proof system | demonstration with numbers | this file, §1 |
| §22.1 publication carrier | implementation, signet | `WITNESS-CARRIER.md` |
| §22.1 transfer arity, standard format | implementation (fixed 2-in-2-out, dummies) | `PROFILE.md` §7–8; this file §1.6 |
| §22.1 statement scope | implementation (17 public inputs) | `PROFILE.md` §8.1 |
| §22.2 light clients, verified sync | implementation, signet, with the completeness result and the recursion frontier measured | `REPLAY-PROOF.md` |
| §22.3 peg-in and peg-out | demonstration with numbers | this file, §3 |
| §22.3 fee publication and fee privacy | implementation (three fee models and the vault scaffold), signet | `BOUNDARY.md`, `FEE-VAULT.md` |
| §22.3 network observation, mempool, retry | implementation, signet through a proxy | `PUBLICATION.md` |
| §22.3 wallet policy | implementation | `PUBLICATION.md` |
| §22.3 implementation, serialization, upgrades | implementation (versioned profile, deployments) | `PROFILE.md`, `deployments/` |
| §22.4 certified-recipient lineage | demonstration with numbers | this file, §2 |
| §22.5 extensions via `h_aux` (atomic swap) | implementation, signet | `SWAP.md` |

One note stays recorded for whoever un-parks the project:
`REPLAY-PROOF.md` §4.4 should be read with §2.3(b) of this file
(BW6-767 exists; it has no prover). The client-side reorganisation of
the proof light client, open when v0.1 of this file was written, has
since been run end to end (`REPLAY-PROOF.md` §6, v0.7).

## 5. Sources

Read in full for this document; ePrint PDFs were obtained from the
archive's own URLs through a web archive mirror because eprint.iacr.org
refuses non-browser clients.

* [SB26] alloc-init, *Shielded Bitcoin: Private Transfers on the
  Bitcoin L1*, 24 September 2026. §14.3, §20.4, §22, Appendix D.
* [2026/186] Abdalla, Carmer, El Gebali, Kilinc-Alper, Komarov, Rebenko,
  Soukhanov, Tairi, Tatuzova, Towa, *Bitcoin PIPEs v2*. §1, §2, §5,
  §5.3.1, §5.4, §7.
* [2026/175] Soukhanov, Rebenko, El Gebali, Komarov, Kilinc-Alper,
  Abdalla, Towa, *Implementable Witness Encryption from Arithmetic
  Affine Determinant Programs*. §1, §3, §3.5, §4.10.
* [2024/916] Lipmaa, *Polymath: Groth16 Is Not The Limit*, CRYPTO 2024.
  §1, Table 1.
* [2024/1245] Dellepere, Mishra, Shirzad, *Garuda and Pari: Faster and
  Smaller SNARKs via Equifficient Polynomial Commitments*. §1, Table 1,
  §6.2.
* [2022/1162] El Housni, *Pairings in Rank-1 Constraint Systems*. §6,
  Tables 10–11.
* [2021/1359] El Housni, Guillevic, *Families of SNARK-friendly 2-chains
  of elliptic curves*, EUROCRYPT 2022. Definition 2.
* [2022/1662] Bellés-Muñoz, Jiménez Urroz, Silva, *Revisiting cycles of
  pairing-friendly elliptic curves*, CRYPTO 2023. Abstract, §1,
  Proposition 3.4, Theorem 4.5.
* [2021/370] Kothapalli, Setty, Tzialla, *Nova: Recursive
  Zero-Knowledge Arguments from Folding Schemes*. §1.3, §5.
* [2020/1618] Bünz, Chiesa, Lin, Mishra, Spooner, *Proof-Carrying Data
  without Succinct Arguments*. §1.1.
* El Housni, *emulated pairing* (gnark, R1CS, BN254 scalar field;
  companion page of the ACNS 2023 paper), hackmd.io/@yelhousni/emulated-pairing.
* [Gro16] Groth, *On the Size of Pairing-Based Non-interactive
  Arguments*, ePrint 2016/260.
* Repositories: `CharmsDev/polymath`, `alireza-shirzad/garuda-pari`,
  arkworks `ark-bw6-767` 0.5.0 (scalar field re-exported from
  `ark-bls12-381`, `small_subgroup_base = 3`, `small_subgroup_power = 2`).

Measurements: `experiments/twochain` (both 2-chains, `--prove`) and
`experiments/cycle` (MNT4/6-753 both directions, `--prove`), 29 October
2026, this laptop; the transfer, swap and batch numbers are those of
`README.md`, `SWAP.md`, `REPLAY-PROOF.md` §6 and `RUNS.md`.

## 6. Changelog

* **v0.3** (29 October 2026) — the reorganisation obligation of §4
  closed (`REPLAY-PROOF.md` v0.7).
* **v0.2** (29 October 2026) — after the paper review (PASS, no
  findings): the TiB/TB convention stated in §3.3, the Nova row of §2.4
  given as the cited band; review linked.
* **v0.1** (29 October 2026) — first version: the three items, the
  2-chain measurement on BLS12-381/BW6-767, the §22 table.
