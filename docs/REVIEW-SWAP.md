# Swap extension review

A firsthand code review of the swap extension (`docs/SWAP.md`, crates
`sb-circuit`/`sb-core`/`sb-indexer`/`sb-wallet`/`sb-cli`), graded against the
atomic-swap properties it claims and against the paper's motivating example
(§22.5): a shielded note exchanged for transparent Bitcoin through the
reserved `h_aux` leaf slot and a standard Bitcoin HTLC.

**Reviewed at:** `f854c38` (the circuit), `2cb395b` (envelope/replay/
deployment), `5908a20` (wallet, HTLC, `sb swap`/`sb htlc`, end to end), and
`fad605d` (the localsignet drill and `docs/RUNS.md`). Curve BLS12-381,
Groth16; the extension is a separate circuit with its own verifying key and
does not change base profile v0.2.

**Verdict:** sound end to end. Every soundness-relevant path was checked
firsthand and the atomicity argument holds; the one implementation finding
of the first pass (a wallet refund-key lookup) is fixed and re-verified.
Remaining items are the honest caveats below, which are inherent to HTLC
atomic swaps and are stated in `SWAP.md`, not defects.

This review is a code-and-soundness review by the project's security
reviewer, not a formal audit by an atomic-swap specialist. Nothing here
holds value yet; before a value-holding deployment an independent review is
warranted, the more so because the swap is where value crosses between the
shielded and transparent sides.

---

## What was verified, firsthand

**The cross-chain binding is the one transfer proof, not a second one.**
A locked note's leaf slot `h_aux = PH(T_AUX, H_lo, H_hi, pk_refund.x,
pk_refund.y, t_refund)` commits to `H = SHA-256(s)`. The extended circuit's
claim branch (E5) computes `SHA-256(s)` *in circuit* and asserts it equals
`(H_lo, H_hi)`; the same `H` is the hash-lock of the Bitcoin HTLC. So the
single secret `s` opens both legs, and the binding is enforced by the one
proof that replay already verifies — no off-chain binding proof, no second
trusted setup, no interactive exchange to fail. The design note (`SWAP.md`
§13) measured and chose this deliberately; it is the stronger choice. The
digest's 32 bytes pack bit-by-bit into the two `<2^128` halves, so
`(H_lo, H_hi)` canonically are the halves of the same 32-byte `H` the HTLC
uses and the counterparty recomputes — verified against the native
`hash_halves` and the round-trip test.

**Exactly one spend path, and it is not the prover's to choose.** `locked`
is `h_aux ≠ 0`, bound into the leaf under the anchor root (E1), so a real
note's path follows its creation. `refund ⇒ locked` (E2), so a plain input
always takes the owner check (E3); a claim needs the owner key *and* the
preimage (E5); a refund needs the refund key *and* `h_anchor ≥ t_refund`
(E6), checked by a both-directions `u32` comparison. The nullifier is
selected by the same `locked` flag — `PH(T_NFLOCK, rho, pos)` for a locked
note, the base keyed nullifier otherwise — so one note has one nullifier
whichever branch spends it, and a claim and a refund of the same note
collide in the nullifier set: replay accepts at most one. The keyless
nullifier is safe against third parties because `rho` is derived from the
note's `rseed`, which only the two swap parties know.

**The base profile is not regressed.** A plain output (`h_aux = 0`) has the
same leaf as a base output, so the slot was always reserved and a base
deployment is unaffected; a locked note (`h_aux ≠ 0`) cannot be proven by
the base circuit, which hashes the leaf with `h_aux = 0`. The slot carries
no value: it enters neither `m_0`, the ciphertext, nor the value sum. The
circuit's `every_block_rejects_its_violation` mutation-tests each of
E1–E7 (E6 three ways, E4 and E7 in both directions, value inflation, the
`h_anchor` binding as the 18th public input, and the base verifying key
refusing a swap proof); the host side (`validate_swap`) requires the pinned
swap verifying key, computes `h_body` over the whole swap body so the
published `h_aux` values are proof-bound, shares the base anchor/nullifier
discipline, and passes `h_anchor` as the public input it looked the anchor
root up at — so it cannot be gamed.

**The Bitcoin HTLC is exact, and a real node accepts both branches.** The
witness script is
`OP_IF OP_SHA256 <H> OP_EQUALVERIFY <P_X> OP_CHECKSIG OP_ELSE <T_htlc>
OP_CHECKLOCKTIMEVERIFY OP_DROP <P_Y> OP_CHECKSIG OP_ENDIF`, P2WSH; the claim
witness is `[sig, s, 1, script]` and the refund witness `[sig, <>, script]`
with the transaction's lock time set to the timeout and a non-final
sequence so `OP_CHECKLOCKTIMEVERIFY` is enforced. `find_preimage` reads `s`
from the claim spend of exactly that outpoint and verifies `SHA-256(s) = H`
before returning; a refund-shaped spend is reported as such, never as a
preimage. The localsignet drill (`docs/RUNS.md`, Bitcoin Core validating
the scripts) ran both endings — a completed swap whose claim reveals `s`
and a double refund via `OP_CHECKLOCKTIMEVERIFY` — so the script bytes and
both witness layouts are accepted by a real node, which no static test can
show.

**The off-chain protocol gates each party before it commits.** Both parties
check `T_htlc + Δ ≤ t_refund` (`Δ = K_min + K_wallet + R`) at *offer and
accept*, and the locker re-checks that the accepted terms equal its offer.
Y verifies the lock before funding: `sb swap check` recomputes `h_aux` from
the agreed `(H, pk_refund, t_refund)`, finds the note carrying exactly that
slot, and confirms its value; `sb htlc fund` refuses until that check has
passed. The refund path refuses while the counterparty has already claimed
(the locked nullifier is in the set) and before `t_refund` is reached. The
end-to-end suite exercises both endings and eleven distinct rejections.

## Finding

**F-1 — the wallet's refund-key lookup (FIXED).** The first pass scanned a
fixed range of diversifier indices to recover the refund key's diversifier,
which would have made a refund address outside that range unspendable *by
the wallet* (a liveness limitation, not a soundness hole — the circuit still
required the correct witness, and the locker chooses its own refund
address). The wallet now resolves the diversifier from its own address book
(`diversifier_for`, the issued range plus a margin) and the builder takes
the refund diversifier explicitly, checking it maps to the committed refund
key; `SWAP.md` §6 states the constraint. Re-verified.

An informational note stands: `pk_refund` is witnessed without a
prime-order check, so a refund key that is a small-order or mixed point
would make the note unrefundable (the refund branch requires a prime-order
derived key). This is a locker's self-inflicted foot-gun, not an attack, and
a wallet only ever produces prime-order transmission keys.

## Caveats (stable, worth re-reading before a value-holding swap)

* **Liveness is Y's assumption, and `SWAP.md` §10 names it.** Atomicity
  holds only if Y watches the chain for the spend that reveals `s` and
  reacts within the reaction margin `R`; a Y that is offline past the margin
  can lose the shielded amount while X keeps the Bitcoin. `Δ` is sized for
  this and the liveness requirement is stated; it is the standard HTLC
  assumption, not removable.
* **The free option is bounded by `T_htlc`, not eliminated.** The party
  holding `s` has, until the HTLC timeout, the option to complete or walk
  away — the usual atomic-swap asymmetry. It is disclosed; if the swap ever
  carries value worth optioning, a premium or collateral is the usual
  mitigation and is out of scope here.
* **The timelock safety rests on one clock.** `h_anchor` (the shielded
  anchor) and `T_htlc`/`t_refund` (the HTLC's `OP_CHECKLOCKTIMEVERIFY`) are
  both Bitcoin block heights, because the shielded notes live on Bitcoin L1;
  the margins also assume no reorganisation deeper than `K_min`.
* **Dynamics are shown on a local signet, not mainnet.** The drill runs
  against a local signet with `signetchallenge` set so blocks need no
  signature; Bitcoin Core validates the scripts, which is the point, but
  mainnet relay standardness and fee behaviour are not exercised there.
* **An independent review is still owed** before a value-holding swap, as
  for any from-scratch cryptographic construction that moves value across a
  trust boundary.

---

*Reviewed 2026-10-29 against `f854c38` / `2cb395b` / `5908a20` / `fad605d`.
Circuit, host, HTLC, wallet and the end-to-end and localsignet runs checked
firsthand; F-1 verified fixed; the caveats are inherent to HTLC atomic
swaps and are stated in `SWAP.md`.*
