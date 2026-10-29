# Fee vault (draft v0.1)

The fee model the paper intends (§20.5, §22.3): a user proves
authorization to a fee vault whose Bitcoin liquidity is reserved for that
user's publication costs; when the vault's rule verifies, the vault
releases the Bitcoin that funds the carrier transaction; fee-paying
capability is thereby derived from metaprotocol state instead of from
repeated use of the user's transparent wallet cluster. The paper makes the
vault **PIPE-based** (the rule is a Bitcoin-anchored covenant) and asks
for the model's own leakage analysis.

This document specifies a **development scaffold** of that vault, in the
same sense as the development boundary of `BOUNDARY.md`: the release rule
is deterministic and enforced by the vault operator's code where the
paper's design has a PIPE covenant enforce it. The scaffold is not the
paper's security; §9 names what the covenant replaces, what breaks and
what must not get weaker when it does. Everything else, the reservation,
the authorization object, the rule, the ledger invariants, the client flow
and the leakage, is meant to survive that replacement.

Nothing in the transfer layer changes: the profile (`PROFILE.md`), the
circuit, the envelope and replay are untouched. A deposit is an ordinary
transfer; a draw publishes an ordinary carrier. The vault is a fourth fee
model beside the three of `BOUNDARY.md` ("Fee funding"), with the same
three questions answered: who pays, what each party sees, what happens
when the service is unavailable.

Status: draft, implemented (`sb fee-vault serve | deposit | accounts |
reclaim | status`, `--fee-vault` on `send`, `withdraw` and `publish`),
run on the private signet (§11, `RUNS.md`). Reviewed by the project's
security reviewer, on paper (v0.1) and then the code firsthand:
`docs/REVIEW-FEE-VAULT-IMPL.md`.

## 1. Roles and flow

| Role | Holds | Does |
|---|---|---|
| **vault** (operator) | a shielded wallet (receives deposits), a transparent fee wallet (the **pool** that funds carriers), the ledger (§6) | serves `/draw` and `/reclaim` by the rule of §5, nothing else |
| **client** | a shielded wallet with a deposit, the authorization key of that deposit | deposits once, draws many times, reclaims what is left |

```
client                                  vault                          Bitcoin
  │ 1. deposit: transfer, output to the   │                               │
  │    vault's address, rseed = C(P)   ───┼──── carrier (any fee model) ──▶│
  │                                       │◀── accepted at height h ──────│
  │ 2. draw: envelope, memo, max_fee,     │                               │
  │    P, signature            ──────────▶│ rule §5: deposit of P found,  │
  │                                       │ signature valid, envelope     │
  │                                       │ valid, fee ≤ max_fee ≤ credit │
  │                                       │ ledger: released += fee       │
  │                                       ├──── carrier from the pool ───▶│
  │◀── txid, credit left ─────────────────┤                               │
  │ 3. reclaim: address, P, signature ───▶│ rule §5: credit − fee back    │
  │                                       ├──── transfer to the address ─▶│
```

Step 1 is the paper's "liquidity reserved for that user": the client
prepays the vault in shielded value. Step 2 is the "fee-unlock": a signed
authorization against that reservation releases pool Bitcoin into one
carrier. Step 3 is the exit path.

## 2. The reservation (deposit)

A deposit is a base transfer (kind `0x01`, `PROFILE.md`) with one output
to the vault's published payment address `(d_V, pk_V)` and the usual
change. The only thing that distinguishes it from any other transfer is
private to the sender and the vault: the output's `rseed`, which commits
to the client's **authorization key**:

```
P      = a BIP 340 x-only secp256k1 public key, 32 bytes
C(P)   = PH(T_FEEAUTH, LE_int(P[0..16]), LE_int(P[16..32]))
rseed  = C(P)
T_FEEAUTH = tag("sb/v1/feeauth")
```

* `rseed` is a Poseidon output over secret input, so the note is
  distributed like any other note: `rho`, `sk_eph`, `pk_eph` and the
  ciphertext are derived from it as always (§5 of the profile), and a chain
  observer, or the vault before a draw, sees an ordinary transfer. The
  split into two 128-bit limbs makes the commitment injective in `P`.
* The vault learns `rseed` when it decrypts its note (every recipient
  does), not `P`: `C` is one-way. `P` is first shown to the vault in a
  draw. The vault cannot forge a draw before that; afterwards it cannot
  forge one either, because a draw needs a signature under `P` (§3).
* The client derives `P` from its seed, one key per deposit:
  `sk_i = HKDF-SHA256(sk_master, "sb/v1/feeauth" ‖ LE64(i))` reduced into
  the secp256k1 scalar range, `P_i = x(sk_i · G)`; `i` is the wallet's
  next unused deposit index. A seed restore recovers deposits by scanning
  its sent notes (`ct_out`) for `rseed = C(P_i)`, `i` up to a gap past the
  last match; only the vault's URL is not derivable from the chain.
* A deposit **counts** once its creating transfer is accepted at a height
  at least `K_min` below the vault's replayed tip (the deployment's
  minimum anchor depth, `PROFILE.md` §A.6): the same depth the protocol
  already treats as settled for anchors. A deposit in the mempool or in
  the last `K_min` blocks is not credit yet.
* Several deposits may commit to one `P`; the credit is their sum. The
  wallet never reuses a key, so that is a recovery edge case, not a
  feature.

The deposit's own carrier is published through one of the three existing
models (`BOUNDARY.md`); the vault itself can publish it only once the
client has credit, so the first deposit of a wallet is where its
transparent wallet (or a relayer) appears, once.

## 3. The authorization (draw request)

A draw asks the vault to publish one envelope for at most `max_fee`
satoshis of the client's credit:

```
draw = { envelope, memo?, P, max_fee, sig }
m    = tagged_hash("sb/v1/feeauth/draw",
         LE16(len(name)) ‖ name            deployment name
       ‖ h_body                            32 bytes, canonical Fr encoding
       ‖ LE64(max_fee)
       ‖ LE16(len(memo)) ‖ memo)           empty if none
sig  = BIP 340 signature of m under P
```

`tagged_hash` is BIP 340's (`SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ msg)`).
The signature binds:

* **which envelope**: `h_body` commits to the whole transfer body (profile
  §7), so the vault can publish exactly this transfer and no other under
  this authorization; the envelope bytes themselves travel in the request
  and the vault recomputes `h_body` from them;
* **the memo**: a withdraw's payout memo (`BOUNDARY.md`) is not part of
  the proof, so a relayer could redirect it; here it is signed, so the
  vault (or anyone between) cannot;
* **the most it may cost**: `max_fee` is the client's ceiling; the vault
  charges the actual fee (§5), never more than the ceiling;
* **the deployment**: a signature for one deployment is meaningless in
  another.

A draw is idempotent by construction: the same envelope can be accepted
into replay at most once (its nullifiers), so re-sending a draw after a
network failure either repeats a refusal ("already published") or, if the
first attempt never reached the vault, publishes once. No nonce is needed.

A reclaim (§5, R-R) signs
`tagged_hash("sb/v1/feeauth/reclaim", LE16(len(name)) ‖ name ‖ LE16(len(addr)) ‖ addr ‖ LE64(deposited))`
where `addr` is the encoded shielded address to pay and `deposited` the
total the client believes it has deposited under `P`; the vault accepts
only if that total matches, so a reclaim signed before a later deposit
cannot be replayed against it.

## 4. Credit

For a key `P` the vault computes, from its own wallet and ledger:

```
deposited(P) = Σ value of notes received by the vault with rseed = C(P)
               and height ≤ tip − K_min        (§2; spent or not)
released(P)  = Σ fees charged to P                 (ledger, §6)
reclaimed(P) = Σ amounts returned to P             (ledger, §6)
credit(P)    = deposited(P) − released(P) − reclaimed(P)
```

Credit is a pure function of accepted chain state and the ledger. Nothing
in it is the operator's judgement: the operator cannot grant credit that
was not deposited, and the code never releases against credit that does
not exist (R4 below).

## 5. The release rule

The vault publishes a carrier for a draw if and only if all of the
following hold, checked in this order; the first failure is the refusal
and nothing is charged:

| | Rule | Refusal |
|---|---|---|
| R1 | the request parses; `P` is a valid x-only key; the signature verifies over `m` (§3) | `bad signature` |
| R2 | `deposited(P) > 0` | `no deposit for this key` (a deposit still shallower than `K_min` says `deposit not settled yet`) |
| R3 | the envelope is a transfer (kind `0x01`, or `0x03` in a swap-enabled deployment) that the indexer would accept at `tip + 1`: parses, anchor in the window with the right root, nullifiers unspent, proof verifies (the sponsored relayer's check, `BOUNDARY.md` model 3); mints are refused; a memo must be a payout memo of at most 80 bytes; the envelope must not be one the vault already published that still waits for a block | `rejected: …` |
| R4 | the carrier is built from the pool at the vault's fee rate; `fee = miner fee of the carrier (commit + reveal in witness mode) + margin`; `fee ≤ max_fee` and `fee ≤ credit(P)` | `fee N exceeds max_fee M` / `insufficient credit: C, need N` |
| R5 | the ledger entry `(P, h_body, fee, txid)` is written to disk **before** the broadcast | (a write failure refuses) |

Then the carrier is broadcast. If the broadcast fails (the node refuses
it), the entry is removed and the ledger written again: nothing was
published, nothing is charged. If the broadcast succeeds but the transfer
is later **not** accepted by replay (another spend of one of its
nullifiers confirmed first), the fee stays charged: the vault paid the
miner, and the only way to reach that state is for the client to have
published the same note twice. The client's wallet locks spent notes until
acceptance exactly to avoid it.

`margin` is the operator's price per publication, published in `/info`
(default 0). The fee rate is the vault's, also published; the client sets
`max_fee` from them (§8).

**R-R, reclaim.** For a reclaim the vault checks R1 with the reclaim
message, R2, that the signed `deposited` equals `deposited(P)`, and that
`credit(P) > fee_R + margin` where `fee_R` is the vault's fee for the
reclaim carrier (a transfer it builds from its own notes to `addr`, change
to itself). It writes `reclaimed += credit(P)` to the ledger, builds the
transfer paying `credit(P) − fee_R − margin` to `addr`, and publishes it
from the pool like a draw; a failed broadcast reverts the entry. After a
reclaim `credit(P) = 0`. The reclaim is the exit path: it exists so that
unspent credit is never stranded by the rule; what it cannot cover is an
operator that is offline (§9).

## 6. The ledger and its invariants

`fee-vault-ledger.json` in the vault's data directory:

```json
{
  "accounts": {
    "<P hex>": {
      "released": 1234,
      "reclaimed": 0,
      "draws":    [{"txid": "…", "h_body": "…", "fee": 617, "at": 190,
                    "raw": ["<carrier tx hex>"], "nullifiers": ["…", "…"],
                    "settled": false}],
      "reclaims": []
    }
  }
}
```

`raw` and `nullifiers` are kept while the entry is unsettled (I3) and
dropped once replay has accepted the transfer; `at` is the vault's tip
when the entry was written.

Invariants, checked by the code on every write and reported by
`sb fee-vault status`:

* **I1, no over-release.** For every `P`:
  `released(P) + reclaimed(P) ≤ deposited(P)`. R4 and R-R enforce it before
  writing; a ledger that violates it on load is refused (the vault does
  not start).
* **I2, backing.** The vault's shielded balance must cover every credit
  that may still be drawn or reclaimed, including deposits whose `P` the
  vault has not seen yet (an undrawn deposit is indistinguishable from any
  other received note). So the bound the vault maintains is over **all**
  notes it received from others:
  `outstanding = Σ received(not own change) − Σ released − Σ reclaimed`,
  and its shielded wallet refuses to spend below `outstanding`: a `sb
  send` or `sb withdraw` from a wallet that has a ledger checks it and
  stops. The one lever past it is `--force`, and it is the operator's
  **under-backing lever**: it prints the shortfall, requires the operator
  to type `under-back <shortfall>` on the terminal, and is logged. It
  exists for the operator to move earned fees out while the arithmetic is
  conservative (an undrawn note that is not a deposit still counts), not
  as a quiet flag; §9 names it as the one way the operator can leave
  credit unbacked. What the operator may spend without it is
  `earned = Σ released + Σ reclaim fees`: the fees it has actually been
  paid, and only those.
* **I3, write before broadcast.** A crash between the write and the
  broadcast leaves a charged, unpublished draw. On restart, **before the
  first request is served**, the vault settles every entry whose transfer
  replay has accepted, re-broadcasts the raw transactions of the rest
  (a network that already knows them answers so, which counts as
  success), reverts any entry the network refuses (the credit returns,
  a reclaim's locked notes are released), and rebuilds its set of pending
  nullifiers from the entries that remain, so the same envelope cannot be
  charged twice across a restart. A crash after the broadcast (the write
  came first) loses nothing.
* **I4, determinism.** Two vault instances with the same wallet, ledger
  and chain compute the same `credit(P)` and give the same answers.

The ledger holds no secrets: `P` identifies an account, it does not
authorize anything. The vault's private material is its wallet seed and
its fee wallet, as for any `sb` wallet.

## 7. API

`sb fee-vault serve --name <vault wallet> --listen host:port --fee-rate
<sat/vB> [--margin <sat>]`, one JSON object per request as the relayer:

| | Request | Response |
|---|---|---|
| `GET /info` | | `{deployment, network, tip, fee_rate, margin, carrier, deposit_address, min_depth, fee_estimate: {transfer, withdraw}}` |
| `GET /credit/<P hex>` | | `{deposited, unsettled, released, reclaimed, credit, settled: bool}`: `deposited` counts only settled deposits, `unsettled` the rest; public knowledge to whoever knows `P`, which only the client and the vault do |
| `POST /draw` | `{envelope: hex, memo?: hex, key: P hex, max_fee, sig: hex}` | `{txid, fee, credit}` or `{error}` (400) |
| `POST /reclaim` | `{key: P hex, address, deposited, sig: hex}` | `{txid, amount, fee}` or `{error}` (400) |

`fee_estimate` is the fee for a one-input carrier of each kind at the
vault's rate plus the margin; the actual fee may be higher when the pool's
coin selection needs more inputs, which is why a draw carries `max_fee`.
Submissions per client address per minute are limited as for the relayer
(`--max-checks-per-minute`); `/info` is answered from memory, `/credit`
after a replay to the tip (at most once per sync interval, as every
draw); request bodies are capped.

## 8. Wallet side

* `sb fee-vault serve --name <vault wallet> --listen … --fee-rate …
  [--margin …]` runs the vault; `sb fee-vault status --name <vault
  wallet>` shows the operator the I2 bound against the shielded balance.
* `sb fee-vault deposit --name <w> --vault <url> --amount <sat>`: reads
  `/info`, takes the next deposit key, builds the transfer to
  `deposit_address` with `rseed = C(P)`, publishes it through the chosen
  model (self-funding by default, `--relay`, `--no-broadcast` as any
  carrier), and records the account `{vault url, vault deposit address,
  key index, P, h_body, value}` in the wallet file. The vault is
  identified by its deposit address, so a vault that moves to another URL
  still serves the account. `sb fee-vault accounts [--vault <url>]` lists
  accounts with their credit as the vault reports it.
* `sb send … --fee-vault <url>`, `sb withdraw … --fee-vault <url>`,
  `sb publish <label> --fee-vault <url>`: the wallet picks the account at
  that URL with the largest credit, sets `max_fee = min(2 × fee_estimate,
  credit)` for the kind (headroom for extra pool inputs, never above what
  the credit holds) and does not post a draw when the credit is below the
  estimate; `--max-fee` overrides the ceiling and that check, the vault
  being the judge. It signs, posts the draw, and prints the
  txid, the fee charged and the credit left. The sender's notes stay
  locked until the transfer is seen accepted, as with every model. A
  deposit can be topped up under the same key (`--index`), which is how
  a remainder too small to reclaim (below the reclaim fee) is recovered.
* `sb fee-vault reclaim --name <w> --vault <url> [--to <address>]`: signs
  a reclaim to one of the wallet's own addresses (the default: a fresh
  one) and posts it.
* **Unavailable vault**: the draw fails with `vault unreachable`, the
  carrier stays in the outbox, and any of the other three models publishes
  it (`sb publish <label>` with `--name`, `--relay`, or the unfunded
  template). Credit is not consumed by a request that got no answer; if
  the answer was lost after a successful publication, the next sync shows
  the transfer accepted and `sb publish` of the same label is refused as
  already published.

## 9. What is scaffolding, what replaces it, what must not regress

The paper's vault is a PIPE covenant: the reservation is Bitcoin
liquidity committed on L1 under a rule, and the release of a fee is a
Bitcoin-anchored transition that anyone can verify. This scaffold replaces
the covenant by the operator's code. Stated per property:

| Property | This scaffold | The covenant (§20.5) | What changes at the swap |
|---|---|---|---|
| Who holds the reservation | the vault's shielded wallet owns the deposit note; the client holds a claim on the ledger | the reserved Bitcoin stays the user's, under the rule | custody disappears; the deposit becomes a covenant-locked UTXO instead of a note |
| What releases a fee | the rule of §5 run by the operator's code; the operator has no knob in it | the same rule, checked by the PIPE verifier against the carrier | the authorization object (§3) is what the covenant verifies; it is designed to be verifiable without the operator |
| Over-release | I1, checked before every write | the UTXO's value: cannot release more than it holds | I1 becomes a consensus fact |
| Exit | R-R, served by the code while the operator is online | a timeout path the user can take alone | liveness no longer depends on the operator |
| What the operator can do | refuse to serve (censor), go offline (credit waits), keep the pool's own Bitcoin | nothing beyond publishing | censorship and downtime remain the covenant's only residual (anyone can publish) |
| What the operator cannot do, in both | publish for a key without its signature, charge above `max_fee` or above credit, double-charge, redirect a memo, read the transfer | the same, by consensus | the guarantee moves from "the code does this" to "the chain does this" |
| Client's exposure | unspent credit, if the operator goes away for good, or spends below it with `--force` (the one under-backing lever, loud and confirmed, §6 I2); bounded by deposit size (deposit for a few publications at a time) | none beyond the fee | the bound is removed, not the rule |
| Operator's exposure | miner fees of carriers that replay then rejects (a client's double publication); bounded by that client's credit, since the fee was charged | the same, inherent to publishing | none |
| Fee privacy | carriers are funded from the operator's pool: the client's carriers mix with every other client's (§10) | a per-reservation UTXO funds that user's carriers: they link to each other and to the reservation on chain | the covenant version is **worse** here unless the reserved liquidity is pooled; the paper flags "vault access patterns" as metadata for this reason |

Non-regression: a covenant that implements this vault must enforce at
least R1–R5 and R-R as stated, I1 by construction, and an exit the user
can take alone. A covenant that enforced less (for instance release
without `h_body` binding, or no exit) would be weaker than this scaffold
and must not replace it.

The scaffold is the same kind of placeholder as the development boundary
(`BOUNDARY.md`): value held by an operator under a rule the code enforces,
to be replaced by a PIPE-based construction when one exists. Like the
boundary, it is for test networks.

## 10. Leakage (§20.5 asks for it)

**On chain.** A deposit is an ordinary transfer: nothing marks it. The
deposit's carrier is published by one of models 1–3 with their leakage
(`BOUNDARY.md`), once per deposit instead of once per publication. Every
drawn carrier is funded from the vault's pool: its inputs and change
belong to the vault's cluster, so what the chain says about it is "a
client of this vault published", the same statement as for the sponsored
relayer, and all clients' carriers share that cluster. The vault's change
chain links the vault's carriers to each other, not to clients. Carrier
size, anchor age, timing and fee rate are public as in every model (§22.1
of the paper).

**The vault** sees, for a key `P`: the deposit note (value, height; it is
its own note), and every draw: the envelope and memo (public anyway),
`h_body`, the kind, the time and the client's network address. It cannot
read the transfer. So the vault learns a client's **publication pattern**:
how often, when, which kinds, and that these publications were funded by
one deposit. That is the paper's "vault access pattern" leakage, and it is
the cost of this model relative to self-funding: traded for keeping the
client's transparent wallet out of every carrier but the deposit's. A
client bounds it by using one deposit (one key) per batch of related
publications and a network layer (Tor) towards the vault. A reclaim
additionally tells the vault a shielded address of the client's; the
wallet uses a fresh one.

**Nobody else** learns the link between a deposit and a draw: `P` is
shown only to the vault, over the request channel.

Relative to the three existing models, the vault removes the per-carrier
transparent link of model 1, needs no second wallet (model 2), and pays
the operator where model 3 is sponsored; what it adds is the custody of
unspent credit (§9) and the pattern the vault sees.

## 11. Measured

On the private signet (`RUNS.md`, 29 October 2026; OP_RETURN carrier,
1 sat/vB, margin 10 sat):

| Step | Charged | Note |
|---|---|---|
| deposit of 2 500 sat | the client's own carrier, 825 vB | an ordinary transfer |
| transfer draw | **833 sat** | 823 vB + margin; equals `/info`'s estimate for one pool input |
| withdraw draw (34-byte memo) | **878 sat** | 868 vB + margin; the estimate assumes a 46-byte memo (890) |
| reclaim of 2 789 sat | **833 sat** | 1 956 sat returned |
| refusals: `max_fee 1`, credit 789 < 833, reclaim below its fee, bad signature, unknown key, duplicate | nothing | the rule's order of §5 |

A restart with a draw pending in the mempool re-broadcast it and charged
it once; the end state of the ledger (released 1 711, reclaimed 2 789,
earned 2 544) matched the vault wallet's balance against an outstanding
credit of 0.

## 12. Changelog

* **v0.1** — initial draft: reservation by `rseed = C(P)`, BIP 340 draw
  and reclaim authorizations, the release rule R1–R5 and R-R, ledger
  invariants I1–I4, API, wallet flow, the scaffold-versus-covenant table,
  leakage.
