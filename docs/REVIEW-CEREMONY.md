# Ceremony review

A firsthand code review of the parameter-ceremony tooling (`sb ceremony`,
crate `sb-ceremony`, documented in [`CEREMONY.md`](./CEREMONY.md)), graded
against the protocol it implements — Bowe–Gabizon–Miers, *"Scalable
Multi-party Computation for zk-SNARK Parameters in the Random Beacon
Model"* (BGM17), the one the Zcash Sapling parameters were made with — and
against general trusted-setup soundness.

**Reviewed at:** `bb2f379` (the tooling) and `f5db2ae` (the two fixes
below, the transcript importer, and the drill script). Curve BLS12-381,
`arkworks` 0.5.0.

**Verdict:** the core is a faithful BGM17 implementation and its soundness
holds. The two findings of the first pass are fixed and re-verified. One
design finding (F-3) remains, scoped to importing a *foreign* transcript
for a value-holding deployment; it does not affect a ceremony that runs
its own phase 1, nor the development setup.

This review is **not** a substitute for an independent specialist audit
before a ceremony whose keys will hold value. `CEREMONY.md` already states
that requirement; this document affirms it. What it records is that the
logic and the soundness arguments were checked against the code as it
stands, and where the edges are.

---

## What was verified, firsthand

**The proof of knowledge is the real BGM17 construction.** Each
contribution proves knowledge of its secret exponent with a pair
`(g1_s, g1_s·x)` in `G1` and a challenge point `g2_s` in `G2`, checked by
`e(g1_s, g2_s·x) == e(g1_s·x, g2_s)` (`transcript::same_ratio`). The single
property this rests on is that `g2_s` has an **unknown discrete logarithm**:
it is `hash_to_g2(...)`, which seeds a ChaCha20 stream from a SHA-256
digest and samples a `G2` point from it. Confirmed in `arkworks` 0.5.0
itself (`ark-ec`, short-Weierstrass `Projective` sampling): the point is
drawn by lifting a random `x`-coordinate to the curve and clearing the
cofactor — **not** by multiplying the generator by a scalar — so no one,
including whoever recomputes the hash, learns its discrete log. The
challenge is bound to the transcript so it cannot be replayed: in phase 1
to `(label, prev-file-digest, g1_s, g1_s·x)` with the label separating
`τ`/`α`/`β`; in phase 2 to `(running-transcript, s, s·δ)`. Inputs are
length-prefixed, so distinct input lists cannot collide.

**Phase 1 verification is complete.** `verify_transition` checks the three
proofs of knowledge, that each secret was applied to the right component
(`τ` to `tau_g1[1]`, `α`/`β` to the index-0 entries), and that `β` is the
same in `G1` and `G2`; then `verify_shape` checks that index 0 is the
generator (which pins the absolute scale), that every vector is a
consistent sequence of powers of one `τ` (batched pairing checks against
`tau_g2`), and — after the F-1 fix — that `β` agrees between `G1` and `G2`
on its own. `α` appears only in `G1`, as in BGM17, so there is no `α`-in-`G2`
relation to check.

**The key derivation is arkworks' own generator, in the exponent.** With
`γ = δ = 1`, `keygen` computes the Lagrange basis in the exponent
(`[L_k(τ)]` = inverse FFT of `[τ^j]`), the QAP columns `a_i(τ)`/`b_i(τ)`/`c_i(τ)`,
the input-consistency Lagrange term per public input, `h_i = τ^{i+n} − τ^i`,
and `β·a + α·b + c` split into the public (`gamma_abc`) and private (`l`)
halves. The test `derived_key_equals_a_plain_setup_with_the_same_secrets`
compares the whole proving key, element by element, against
`Groth16::generate_parameters_with_qap` run at the **same** `(τ, α, β,
γ=1, δ=1)` — it drives arkworks' evaluation point to `τ` through a small
RNG shim and asserts full structural equality. The test can only pass if
the derived key is identical to the one arkworks' trusted-setup generator
produces, so arkworks' prover and verifier work on it unchanged.

**Phase 2 verification is complete.** Every field of the proving key is
accounted for: the circuit part (`α`, `β_g2`, `γ_g2`, `gamma_abc`, `β_g1`,
`a_query`, `b_g1_query`, `b_g2_query`) is compared equal to the key
recomputed from phase 1; `δ` in `G1` and `G2` is tied to the contribution
chain (per-step proof of knowledge and ratio) and cross-checked between the
groups; `H` and `L` are length-checked and batch-pairing-checked to be the
initial queries scaled by exactly the final `1/δ`. The transcript chain
binds the order of contributions (each commits to the exact prefix before
it, anchored to the digest of the recomputed initial key), so a
contribution cannot be inserted, removed or reordered.

**The beacon provides unbiasedness, not secrecy** — correctly, and as
`CEREMONY.md` states. Its `δ'` is derived publicly from the transcript and
the beacon value, so anyone can recompute the last step; what it buys is
that no earlier participant could have chosen their `δ'` to force a known
final `δ`, because the beacon is added afterwards and is unpredictable
until revealed. Secrecy still rests on at least one earlier participant
having destroyed their secret.

**Operational hygiene.** Verification draws its batch-check randomness from
fresh OS entropy, so a contributor cannot grind a malformed accumulator or
key past the probabilistic checks. File digests are taken over the actual
bytes read. Every read path validates points on the curve and in the
prime-order subgroup (with a rogue-point test). `export` refuses a key with
no contributions (`δ = 1`, which anyone could forge against). A deployment
profile pins the verifying key's hash, and a proving key — from the file or
from the cache — is accepted only if the verifying key it carries hashes to
that pin; a mainnet profile refuses the insecure development setup
outright.

---

## Findings

### F-1 — `verify_shape` now checks `β` across `G1` and `G2` (FIXED, `f5db2ae`)

Before the fix, the `β`-in-`G1`-vs-`G2` consistency check lived only in
`verify_transition`. `phase2-new`, `phase2-verify` and `phase1-import` call
`verify_shape`, so the path that verifies phase 2 from the published files
alone did not check `beta_g2` against `beta_tau_g1`. An accumulator whose
`beta_g2` used a different `β` (internally consistent otherwise) would have
yielded a key whose `vk.beta_g2` and `pk.beta_g1` disagreed, so no honest
proof would verify — a broken, not a forgeable, key, and only reachable if
`phase1-verify` had been skipped on some transition.

The fix adds the self-contained check to `verify_shape`
(`same_ratio((tau_g1[0], beta_tau_g1[0]), (tau_g2[0], beta_g2))`, over the
generators the same function has already pinned), with a test that
`verify_shape` alone now rejects a mismatched `beta_g2`. Verified: the
check is correct and reachable from all three callers.

### F-2 — contribution secrets are wiped from memory (FIXED, `f5db2ae`)

The secret scalars and the derived power vectors are now overwritten
(`zeroize`) after each contribution. `CEREMONY.md` scopes this honestly: it
is best effort, because the scalars are `Copy` and the arithmetic makes
copies the wipe does not reach, and a machine that swaps or dumps core can
still leak them — so a contribution should run on a trusted machine. The
claim that secrets are "never written to disk" is accurate. Verified.

### F-3 — a foreign transcript's provenance should be enforced, not printed (OPEN, design)

**Scope: only the import of a foreign powers-of-tau transcript for a
value-holding deployment. It does not affect a ceremony that runs its own
phase 1, nor development or drill setups, which generate their own
parameters.**

`phase1-import` reads a public `powersoftau` response (Sapling, Filecoin),
validates its points and runs `verify_shape`. `verify_shape` proves the
accumulator is **well-formed** — a consistent sequence of powers of one
`τ`. It does **not**, and cannot, prove that `τ` is unknown: an accumulator
built by an adversary from a `τ` they chose is perfectly well-formed and
passes every shape check. The only thing separating the real ceremony's
transcript (whose `τ` no one knows, by the honesty of its participants)
from such a forgery is that its bytes hash to the value that ceremony
published.

The importer computes that hash (BLAKE2b-512 of the response, and the
challenge hash it carries) and **prints** it for the operator to compare by
eye against the published record. It does not take the expected hash as an
argument and refuse on a mismatch. That makes a human comparison the single
security link at the root of the whole setup: if the operator does not
compare, or compares the wrong value, a forged transcript with a known `τ`
is accepted, and a known `τ` means forgeable proofs.

The trust model — trust the ceremony's public record, as every reuser of
the Sapling transcript does — is the right one. What should change is the
*enforcement* of it: `phase1-import` should accept
`--expect-challenge-hash` / `--expect-response-hash`, compute the hashes,
and refuse unless they match. That reduces the operator's role to supplying
one authoritative value from the public record (irreducible), and makes the
tool, not an eye, enforce it — the same pin-and-verify pattern the code
already uses for the verifying-key hash in a deployment profile.

**Recommended before importing any real transcript for a value
deployment.** Until then, an import is only as sound as the operator's
manual hash comparison.

---

## Caveats (stable, worth re-reading before a value ceremony)

* **The transcript format is not Sapling's.** This tooling hashes with
  SHA-256 and samples `G2` from a ChaCha20 stream, where the Sapling tools
  use BLAKE2b; its own phase-1 and phase-2 files are therefore not
  interchangeable with Sapling or Filecoin tooling. A *public* phase-1
  transcript can be imported (the point encoding is shared), but our files
  cannot be fed back to those tools.
* **The importer has not been run on a real transcript.** It is tested on
  synthetic files in the `powersoftau` format produced by its own writer,
  and the point encoding is pinned against the real BLS12-381 generator;
  but the actual Sapling (≈600 MB) and Filecoin files have not been
  imported. Their exact layout, point encoding and public-key framing
  should be confirmed against a real download before a value import.
* **The full transfer-circuit ceremony is not exercised in CI.** The test
  that runs phase 1 and phase 2 on the real circuit is gated behind an
  environment variable and takes minutes; CI runs the whole protocol on a
  small circuit, with the tampering cases, and the key-derivation equality
  against arkworks.
* **An independent cryptographic review is still owed** before a
  value-holding ceremony. This document is a code-and-soundness review by
  the project's security reviewer; it is not a formal audit by a
  trusted-setup specialist, and the stakes (a compromised setup mints value
  from nothing) justify a second, independent pair of eyes.

---

*Reviewed 2026-10-28 against `bb2f379` / `f5db2ae`. Findings F-1 and F-2
verified fixed; F-3 open by design, scoped to foreign-transcript import for
value deployments.*
