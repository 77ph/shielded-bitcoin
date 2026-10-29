# Ceremony review

A firsthand code review of the parameter-ceremony tooling (`sb ceremony`,
crate `sb-ceremony`, documented in [`CEREMONY.md`](./CEREMONY.md)), graded
against the protocol it implements — Bowe–Gabizon–Miers, *"Scalable
Multi-party Computation for zk-SNARK Parameters in the Random Beacon
Model"* (BGM17), the one the Zcash Sapling parameters were made with — and
against general trusted-setup soundness.

**Reviewed at:** `0ecd46e` (the tooling), `b1adf30` (the transcript
importer, the drill script, and findings F-1/F-2), and `647a889` (finding
F-3 and the per-contribution phase-2 check). Curve BLS12-381,
`arkworks` 0.5.0.

**Verdict:** the core is a faithful BGM17 implementation and its soundness
holds. All three findings below are fixed and re-verified firsthand. One
small residual, noted under F-3, is a forward-looking belt rather than a
gap: it is left to operator discipline and documentation today, which is
right for a setup whose keys do not yet hold value.

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
contribution cannot be inserted, removed or reordered. The authoritative
verification (`phase2-verify --phase1`) recomputes the initial key from the
accumulator and the circuit and so trusts no phase-2 file; a fast
per-contribution mode (`--initial`) checks the same chain against the
published initial file, which is accepted only if it carries no
contributions and `δ = 1`. The fast mode is a coordinator's early-warning
check, not a trust root — the recompute remains the final word, and an
independent verifier should use it.

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

### F-1 — `verify_shape` now checks `β` across `G1` and `G2` (FIXED, `b1adf30`)

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

### F-2 — contribution secrets are wiped from memory (FIXED, `b1adf30`)

The secret scalars and the derived power vectors are now overwritten
(`zeroize`) after each contribution. `CEREMONY.md` scopes this honestly: it
is best effort, because the scalars are `Copy` and the arithmetic makes
copies the wipe does not reach, and a machine that swaps or dumps core can
still leak them — so a contribution should run on a trusted machine. The
claim that secrets are "never written to disk" is accurate. Verified.

### F-3 — a foreign transcript's provenance is now enforced, not printed (FIXED, `647a889`)

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

As first reviewed, the importer only **printed** that hash (BLAKE2b-512 of
the response, and the challenge hash it carries) for the operator to
compare by eye against the published record — which made a human comparison
the single security link at the root of the setup: if the operator did not
compare, or compared the wrong value, a forged transcript with a known `τ`
would be accepted, and a known `τ` means forgeable proofs.

The fix makes the tool enforce the match. `phase1-import` now takes
`--expect-response-hash` and `--expect-challenge-hash`; `Imported::expect`
recomputes the response's BLAKE2b-512 and the embedded challenge hash and
**refuses** the import unless they equal the expected values ("this is not
the published transcript" / "not the expected"). The operator's role is now
to supply one authoritative value from the public record once; the tool,
not an eye, enforces it — the same pin-and-verify pattern the code uses for
the verifying-key hash in a deployment profile. Both directions are tested
(right hashes pass, wrong response/challenge and malformed hex are
refused). `CEREMONY.md` now states plainly that the shape check is
consistency, not honesty, and that the hash is what ties an import to the
real ceremony.

**Residual (forward-looking, not blocking).** The pins are optional: an
import run without `--expect-response-hash` still succeeds, after printing a
loud warning that the accumulator is tied to no record and its keys must
not hold value. That is the right default for drills and experiments, which
generate their own parameters and have no published hash to pin to. The one
thing a tool cannot catch today is an operator who imports a real transcript
without the pin, ignores the warning, and carries the key to a value
deployment anyway. A future belt would thread the import's pinned/unpinned
provenance through to profile creation, so that a mainnet profile refuses a
verifying key whose phase-1 origin was never pinned. Until then this rests
on the warning and on this document; given that no deployment holds value
yet, that is a reasonable place to leave it.

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

*Reviewed 2026-10-28 against `0ecd46e` / `b1adf30` / `647a889`. Findings
F-1, F-2 and F-3 verified fixed; one forward-looking residual noted under
F-3 (optional provenance pin), left to the warning and this document while
no keys hold value. An independent specialist review is still owed before a
value-holding ceremony.*
