# Review — fee-vault implementation (paper §20.5, `docs/FEE-VAULT.md`)

**Verdict: PASS, firsthand, no findings.** The implementation matches the
FEE-VAULT.md v0.1 design (paper-passed at `04885eb`) and honours the
zero-loss invariant: on correct function the vault loses zero client and
zero operator funds; the sole fund-at-risk path is the operator's
deliberate, loud `--force` under-back — an emergency brake, not an
operating mode.

**Ref:** `63026f2` (parent `04885eb`). Read firsthand:
`crates/sb-cli/src/vault.rs` (whole), `relay.rs` (whole), `feeauth.rs`,
`crates/sb-core/src/feeauth.rs`, `keys.rs:158` (`fee_auth_secret`),
`sb-wallet/src/wallet.rs` (`build_send_seeded`), `sb-core/src/note.rs`
(nullifier), `main.rs:1271–1398` (Send/Withdraw guard sites). The
localsignet drill (`docs/RUNS.md`, `scripts/fee-vault-drill.sh`)
corroborates every invariant below in both directions; I reasoned from
the code firsthand and did **not** re-run the drill (testnet ≈ $0,
dev-scaffold — right-sized).

## The five focuses

**(1) R5/I3 crash order — write-ahead, correct.** `draw` persists the
ledger entry (with `raw` + `nullifiers`, `released += fee`,
`settled=false`) **before** `broadcast_carrier`; `broadcast_carrier`
itself saves the funding counters before it broadcasts. On a broadcast
`Err` the entry is rolled back (`released -= fee`, `draws.pop()`, save)
and the caller is told "nothing charged". `resolve_pending` (run before
the first request is served) settles what replay accepted, re-broadcasts
the rest ("already" = success), reverts what the network refuses
(`released -= fee` / `reclaimed -= credit` + `unlock`), and rebuilds the
in-memory pending set from the unsettled entries' nullifiers. I traced
the crash windows: a crash between ledger-save and broadcast is recovered
by re-broadcast or reverted if unbroadcastable; a crash after broadcast
but before `mark_pending` is covered because the pending set is rebuilt
from the ledger. Durable intent precedes the irreversible action; the fee
is charged iff the carrier lands. No double-charge, no charge for an
unlanded carrier.

**(2) I2 backing — conservative, reachable both paths, loud brake.**
`backing()` is a conservative upper bound (every non-change received note
counts as possibly-owed: `outstanding = received − released − reclaimed`,
saturating). `backing_guard` is called **before `build_send` on both**
operator shielded-spend paths — `Cmd::Send` (`main.rs:1306`) and
`Cmd::Withdraw` (`main.rs:1384`) — and `amount` is the exact shielded
outflow (a shielded transfer is value-conserving; the Bitcoin carrier's
miner fee is paid from the separate transparent funding pool, not the
backing pot). It permits a spend that leaves `after >= outstanding`,
refuses otherwise, and `== outstanding` is permitted (not over-tight).
`--force` prints the shortfall, requires the operator to type
`under-back <N>` on stdin, and logs a warning — the deliberate, loud
emergency brake the zero-loss rule calls for. `reclaim` is
self-balancing (it pays owed credit and reduces `outstanding` in the same
entry), and `FundSend` moves transparent pool coins, so both correctly
need no guard.

**(3) R4 credit / maturity.** `credit_of` counts only **settled**
deposits — `note.height + k_min <= tip` — minus `released` minus
`reclaimed`; unsettled deposits are tracked separately and are **not**
credit. That `k_min` depth is the maturity guard against a reorg granting
credit that could vanish. `draw` enforces `fee <= max_fee` **and**
`fee <= credit`.

**(4) R1 signature.** `verify` runs before the expensive `build_carrier`.
`draw_message` / `reclaim_message` use `len16`-prefixed variable fields
(deployment, memo, address) and fixed-width `h_body`(32) / `max_fee`(8) /
`deposited`(8), with distinct `DRAW`/`RECLAIM` tags (domain separation,
test-confirmed) over a correct BIP-340 tagged hash — no concatenation
ambiguity, no cross-use. `key_commitment` ties a deposit note's `rseed`
to the auth key injectively; the auth key is
`HKDF(sk_master, "sb/v1/feeauth" ‖ index)`, domain-separated from and not
invertible to the spend authority. `max_fee` is itself signed, so the
vault cannot charge beyond what the client authorised.

**(5) R-R reclaim.** `req.deposited == cr.deposited` binds the signature
to the client's view of the deposited total (a reclaim signature cannot
be replayed across a deposit change); `credit > 0`, `credit > fee`,
`amount = credit − fee`; `reclaimed += credit` zeroes the key's credit
(no double-reclaim). Same write-ahead order and `unlock`-on-failure as
`draw`. An under-backed reclaim fails loudly ("the operator must restore
the shielded balance") — a liveness stop, not a loss of the client's
recorded credit.

## Candidate examined and neutralised

**Replay of a draw after it settles.** The ledger dedup (`already`) only
scans `!settled` draws, and `draw_message` carries no nonce — so I asked
whether a settled draw could be replayed to charge the client again. It
cannot: `check()` calls `indexer.check_transfer(envelope, tip+1)`, which
rejects a transfer whose nullifiers are already spent on chain, so a
post-settle replay fails at R3; the in-flight window is covered by
`already` **and** `is_pending`. The double-spend defence lives at the
indexer nullifier set, the dedup covers only the pre-replay window — the
layering is complete, not a gap.

## Two documented deviations from v0.1 — both safe

- **Client `max_fee` default = `min(2×estimate, credit)`; an explicit
  `--max-fee` bypasses the client pre-check.** Safe: the authoritative
  checks are vault-side (`fee <= credit` and `fee <= signed max_fee`); the
  client default is UX only, and `max_fee` is signed so the vault cannot
  inflate the charge.
- **A vault is identified by its deposit address, not its URL.** Safe:
  the address is bookkeeping identity for the client's local records;
  security rests on the signed auth key and per-vault deposits, never on
  URL/address. A wrong-address server fails to match (liveness) or is the
  real vault.

## Leaned-on primitive checked

**Deposit rseed-seeding does not strand a top-up.** A deposit note's
`rseed` is forced to `key_commitment(P)`, so two top-ups to the same key
share `rseed` and thus `rho`. They do not collide: `nf = PH(T_NF, sk_nf,
rho, pos)` includes the leaf **position**, so same-key same-amount
top-ups get distinct nullifiers at distinct positions — independently
spendable, no stranding. Outside linkability of a deposit needs `P`,
which is secret-derived and unguessable; only the vault (holding `P`) can
attribute its own deposits, which is the intent.

## Side-observations (not fee-vault findings)

- **`swap_replay.rs` early-refund `debug_assert` (dev-flagged, out of
  scope, not read firsthand).** A `debug_assert` that fails means the
  asserted invariant is violated on that path; "CI is `--release` so it's
  green" is the muted-warning pattern (green because the check is compiled
  out). Recommend fixing the early-refund so the assert holds, or
  converting it to a runtime check / documenting why the assert is wrong —
  rather than relying on `--release` to hide it. Low priority (swap,
  debug-only, scaffold); happy to look firsthand on request.
- **Crash-hygiene nits, not fund-loss.** If a rollback's `ledger.save`
  fails, in-memory and disk diverge briefly and self-heal on restart
  (re-broadcast → refuse → revert). A crash between the ledger save and
  the funding-counter save can reuse a change index (address reuse, a
  privacy nit). Both acceptable for a scaffold.

*Auditor: security-audit (77ph), firsthand. For the owner's personal
public `shielded-bitcoin`; audit against the paper's design and general
security, not TRUST-stack relevance.*
