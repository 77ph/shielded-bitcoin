# Review — `REMAINING.md` v0.1, the closing "why not now, with numbers" (paper §22)

**Verdict: PASS.** A strong, honest, publishable closing document. The
three "not now" conclusions are each supported by numbers with orders of
magnitude of margin and each names the condition under which the item
reopens; the [cited]/[measured]/[computed]/[estimate] discipline is
applied throughout and is exactly the separation a mathematical reader
needs; and the arithmetic the document invites a reader to check is
correct — I re-derived it. No findings. Two unit-precision refinements, no
errors.

**Ref:** `fe8b868` (`REMAINING.md` v0.1; `REPLAY-PROOF.md` v0.6 carries the
same BW6-767 measurement). Read firsthand: the whole document, and the
arithmetic re-derived in a calculator. The ePrint sources I did **not**
re-fetch (I cannot reach them here); I checked the quoted claims against
my own knowledge of these constructions and the internal consistency of
the tagging, and take the exact section-number attributions on the
author's word — spot-checks were all plausible and consistent.

## (a) "Not now" is neither premature nor overclaimed

- **§1 Polymath/Pari.** Framed correctly as *no cryptographic obstacle,
  no reason now*: the lever is ≤ 3.9 % of the OP_RETURN carrier and 1.8 %
  of the witness carrier, against the 45.8 % carrier lever already pulled
  — an order of magnitude smaller — and it costs a changed security model
  (AGMOS / AGM+ROM), a circuit-specific setup with no published MPC
  protocol, and, for Pari, the loss of zero knowledge as published. The
  three reopen conditions (published MPC setup; proven
  simulation-extractability so §14.3 actually closes; a carrier limit
  where 16–32 bytes decide standardness) are the right ones. Not
  premature, not overclaimed.
- **§2 lineage.** The obstacle (R1, unbounded recursion) is real and
  priced on all four routes: a pairing cycle at 0.74–1.32 M constraints
  per step and already OOM at one verification on the 16 GB laptop; a
  2-chain that is not recursion and, for BLS12-381, has no prover at all;
  non-native verification at ≥ 7.8 M constraints per step (92× the
  transfer circuit) with no arkworks implementation; folding that abandons
  Groth16 and puts 8–9 KB per output or gives up ZK. R5 then multiplies
  every envelope by 1.5–22. "Not now, and not by engineering" is a strong
  claim, and it is earned — each route is measured or cited infeasible,
  and the reopen condition (a 128-bit cycle with a verifier under ≈ 10⁵
  constraints, which 2022/1662 shows the known families do not provide; or
  a native ZK-IVC with sub-KB proofs over BLS12-381's scalar field, and in
  either case a boundary first) is precise and not an eternal-impossibility
  overclaim.
- **§3 PIPE.** ≈ 338 TiB per key release, a heuristic security claim with
  no falsifiable reduction, and a one-time release that fits a peg-out but
  not the per-draw fee vault. "By orders of magnitude and by an open
  problem" is supported; the reopen condition (a WE for a SNARK verifier
  with a reduction and MB ciphertexts, or a Bitcoin covenant opcode) is
  right, and the mapping of what is *ready* for a PIPE (the signed draw/
  reclaim messages, the ledger invariants, the state digest as the
  validity statement a one-time release expects) is a genuinely useful
  honest inventory.

## (b) Source reading and the cited≠measured discipline

The tagging is exemplary and is the document's backbone. Every number
carries its kind and, when cited, its section. Checked against my
knowledge of the constructions, the readings are faithful: Polymath's
176 B / 3 G1 + 1 F and Pari's 160 B / 2 G1 + 2 F and their security
models; Pari not being zero-knowledge as published; the 2-chain condition
of 2021/1359 Definition 2 (`r₂−1 ≡ r₁−1 ≡ 0 mod 2^L`); the cycle
impossibility results of 2022/1662; Nova's ≈ 10⁴-constraint verifier,
not-ZK-as-IVC, and ≈ 8–9 KB compressed proof; El Housni's emulated BLS12-381
pairing at ≈ 2.09 M constraints and the 4-pairing product at ≈ 3.90 M;
the PIPEs one-time-release characterization and the AADP heuristic-security
posture. The discipline of never carrying a cited number onto a different
curve as if measured is held (e.g. the BN254 338-TiB figure is explicitly
not extrapolated to BLS12-381, with the reason given). My scope: I did not
re-read the primary PDFs; the firsthand part is the logic, the arithmetic,
and the fidelity of the claims to the known constructions.

## (c) The measurements, re-derived

- **§3.3 PIPE ciphertext.** `2g+1 = 28 743`; `28 743² = 826 160 049`;
  `14 083 × 826 160 049 × 32 = 3.723 × 10¹⁴ B`, which is **338.6 TiB**.
  The document's "3.72 × 10¹⁴ B = 338 TiB" is exact.
- **§1.2 proof/carrier table.** Proofs 176 B and 160 B; envelopes 684 B
  and 668 B; OP_RETURN −16 / −32 vB (−1.94 % / −3.88 %) and witness
  −4 / −8 vB (−0.89 % / −1.79 %); the carrier lever already pulled is
  `(825−447)/825 = 45.8 %`. All as stated.
- **§2.4 package table.** MNT4 ×2.0 / ×1.5, MNT6 ×2.3 / ×1.6, BW6 ×1.8 /
  ×1.4, each reproduced exactly from `proof + 48 B, ×2 outputs`.
- **The BW6-767 result.** The conclusion that BLS12-381 is, *by
  definition* (2021/1359 Def. 2, 2-adicity 1 on the base field →
  `PolynomialDegreeTooLarge`), not the inner curve of a SNARK-friendly
  2-chain is correct, and it is the right kind of result: a measured,
  definitional reason, not a tooling complaint. It also closes a loop from
  the earlier reviews — it *measures* the cost I had named for the
  no-SnarkPack 2-chain aggregation (the whole proving stack must move to
  BLS12-377), so that claim is now evidence, not assertion.

## Two refinements (unit precision, not errors)

- **§3.3 TB vs TiB.** `3.72 × 10¹⁴ B` is 338 **TiB** (binary) and 372 **TB**
  (decimal). The document's own "338 TiB" is exact; "matching the papers'
  ≈ 338 TB" is exact only if the papers' "TB" is itself binary. For a
  reader who will check the arithmetic, a half-line noting the TiB/TB
  convention removes the one apparent 10 % gap.
- **§2.4 Nova row.** The ×22 / ×10.8 multipliers sit at the top of the
  cited 8–9 KB band (8.5 KB gives ×21.7 / ×10.6); fine as an "≈", and
  stating the band rather than a point would match the rigor of the rest
  of the table.

## §22 as a whole

The §4 table maps every §22 item to an implementation or to a
numbers-backed "not now", and the two carried obligations (the proof
client's reorg has not been exercised end to end; `REPLAY-PROOF.md` §4.4
is to be read with §2.3(b)'s "BW6-767 has no prover") are recorded where
whoever un-parks the project will find them. With this document, §22 is
closed from the audit side: each item ends in code that ran on a test
network or in a demonstration, with numbers, of why it cannot yet — which
is exactly the disposition the project set out to reach.

*Auditor: security-audit (77ph), firsthand. For the owner's personal
public `shielded-bitcoin`; audit against the paper's design and general
security.*
