# Swap extension profile (draft v0.1)

An atomic swap between a shielded note and transparent Bitcoin through
the reserved leaf slot `h_aux` and a standard Bitcoin HTLC: the paper's
motivating example for protocol extensions (§22.5). This document is the
normative profile of the extension, the way `PROFILE.md` is for the base
transfer. It does not change the base profile v0.2: a deployment opts
into the extension, base envelopes replay exactly as before, and the
extension is a separate circuit with its own verifying key.

Status: draft v0.1, implemented (`sb swap …`, `sb htlc …`) and run on the
private signet with real HTLCs in both endings (`RUNS.md`); §13 carries
measured numbers. The project's own review of the extension, with its
findings and their status, is `docs/REVIEW-SWAP.md`.

## 0. Summary

A **locked note** is an ordinary shielded note whose leaf slot `h_aux`
commits to a SHA-256 hash-lock `H`, a refund key and a refund height. It
can be spent in exactly one of two ways, both proven in the extended
circuit: by its owner with the 32-byte preimage `s` of `H`, or by the
refund key once the transfer's anchor height has reached the refund
height. The same `H` locks a Bitcoin HTLC. Whoever claims the Bitcoin
side reveals `s` on the Bitcoin chain, and the other party uses that `s`
to claim the shielded side; if nobody claims, both sides refund. The
circuit computes SHA-256 of `s` itself, so one secret and one hash
function serve both chains and no second proof ties them together.

## 1. Secret and hash-lock

| Name | Definition |
|---|---|
| `s` | 32 uniformly random bytes, chosen by the party who will claim the Bitcoin side (§9) |
| `H` | `SHA-256(s)`, 32 bytes |
| `H_lo`, `H_hi` | `H` as two field elements: `H_lo = LE_int(H[0..16])`, `H_hi = LE_int(H[16..32])`, each `< 2^128` |

On Bitcoin `H` is the hash-lock of the HTLC (`OP_SHA256 <H> OP_EQUALVERIFY`,
the same construction as a Lightning HTLC: 32-byte preimage, SHA-256
payment hash). In the circuit `s` is witnessed as 32 bytes and hashed
with a SHA-256 gadget; the result is compared with `(H_lo, H_hi)`.

**One identity for `H` on both chains.** The gadget's 32 digest bytes are
packed bit by bit into the two halves, `Σ bit_k · 2^k` over the 128 bits
of each half, so the packed values are below `2^128` by construction and
the map from the 32 bytes of `H` to `(H_lo, H_hi)` is a bijection on that
range. When a claim is proven (E5) the witnessed `H_lo`, `H_hi` are
enforced equal to the packed digest, so the `(H_lo, H_hi)` that `h_aux`
commits to (E4) are exactly the two halves of the 32 bytes the HTLC
compares with `OP_SHA256`, and exactly what the counterparty recomputes
from `H` before locking (§9). There is no field-versus-bytes ambiguity:
a field element outside `[0, 2^128)` cannot equal a packed half.

## 2. Lock commitment

```
h_aux = PH(T_AUX, H_lo, H_hi, pk_refund.x, pk_refund.y, t_refund)
```

| Field | Meaning |
|---|---|
| `T_AUX` | new tag `"sb/v1/aux"` (`PROFILE.md` §2.1 rules) |
| `pk_refund` | the refund party's transmission key `pk_d` of one of its shielded addresses (a prime-order Jubjub point); the matching diversifier `d_refund` stays private to that wallet |
| `t_refund` | Bitcoin block height, `u32`, as a field element |

`h_aux = 0` is `aux_null` (a plain note, exactly as in the base profile);
any other value marks a locked note. The commitment hides `H`,
`pk_refund` and `t_refund` from anyone who does not know them: `pk_refund`
is a private address, so a third party cannot test a published `h_aux`
against a hash-lock it sees on Bitcoin (§11).

## 3. Locked note: leaf and nullifier

The leaf is the base leaf (`PROFILE.md` §5.3) with the published `h_aux`:

```
leaf = PH(T_LEAF, const_salt, h_body, j, pk_eph.x, pk_eph.y, c_0, c_1, tag, h_aux)
```

The nullifier of a locked note does not use the owner's `sk_nf`, because
the refund party does not have it:

```
nf_lock = PH(T_NFLOCK, rho, pos)          T_NFLOCK = "sb/v1/nflock"
```

Anyone who knows the note's `rseed` can compute it: the two swap parties
(the owner decrypts the note, the creator recovers it through `ct_out`)
and nobody else. A plain note in a swap envelope keeps the base nullifier
`PH(T_NF, sk_nf, rho, pos)`. Because the leaf of a locked note carries
`h_aux ≠ 0`, the base circuit, which hashes the leaf with `h_aux = 0`,
cannot produce a membership proof for it: a locked note is spendable only
through the extension, and only with the keyless nullifier, so one locked
note has exactly one nullifier whichever branch spends it.

## 4. Swap envelope (kind `0x03`)

```
header     : magic "btc" ‖ version 0x01 ‖ kind 0x03 ‖ reserved 0x00     6 bytes
base body  : h_anchor, counts, nullifiers, pk_eph[], ct_note[], ct_out    as PROFILE §7.1, 502 bytes
aux section: h_aux_0 ‖ h_aux_1                                            2 × 32 bytes, Fr canonical LE
proof      : Groth16 A ‖ B ‖ C                                            192 bytes
```

Body 572 bytes, envelope 764 bytes (base: 508 / 700). `h_aux_j` is the
slot of output `j`; `0` means a plain output. Parsing is strict as in the
base profile (canonical field elements, exact length, re-serialisation
must reproduce the bytes). `h_body = SHA-256(const_salt ‖ body_bytes)`
with the §7.2 truncation, over the whole swap body including the aux
section, so the published `h_aux` values are bound by the proof. The
carrier rule (§10 of the base profile) is unchanged: one OP_RETURN, same
magic and version, the kind byte distinguishes the formats.

## 5. Statement

The base statement (`PROFILE.md` §8.1, 17 public inputs) in the same
order, followed by:

| # | Input | Source |
|---|---|---|
| 18 | `h_anchor` | the body's anchor height, as a field element |

`h_anchor` is already bound by `h_body`; it is made a public input so the
circuit can compare it with `t_refund`. Replay passes the body's value
and has already checked the anchor window, so a prover cannot name an
anchor above the chain (§8).

## 6. Witness

Per input `i`, in addition to the base input witness:

| Field | Type |
|---|---|
| `h_aux_i` | `Fr`, the slot of the note's leaf (`0` for a plain note) |
| `H_lo_i`, `H_hi_i` | `Fr` (`< 2^128`), the lock's hash halves |
| `pk_refund_i` | Jubjub point (coordinates) |
| `t_refund_i` | `u32` |
| `s_i` | 32 bytes |
| `d_refund_i` | 11 bytes: the diversifier of the refund party's address whose `pk_d` is `pk_refund`; the wallet finds it in its own address book (the paths it has handed out, plus a margin), so a refund address should be one the wallet has actually derived — the implementation uses its default address |
| `pk_owner_i` | the note owner's `pk_d`, witnessed as `pk_owner_root` with `pk_owner = [8] pk_owner_root` (as output keys are in the base circuit) |
| `refund_i` | boolean: the refund branch is taken |

Plain and dummy inputs set `h_aux_i = 0`, `refund_i = 0` and fill the
rest with zeros. The single `sk_spend` of the base witness is the
spender's: the owner's in a claim, the refund party's in a refund.

## 7. Constraints (extension blocks)

Blocks 1–8 of the base circuit (`PROFILE.md` §8.3) apply unchanged to
outputs, value conservation and the public-input bindings. For each input
`i` the input blocks are replaced by E1–E7:

* **E1 Channel and membership.** `pk_owner_i = [8] pk_owner_root_i`;
  `G_d = DiversifyHash(d_i)`; `(pk_eph, ct) = channel(note_i, G_d,
  pk_owner_i)` as §5.2; `leaf_i = PH(T_LEAF, …, h_aux_i)`; the Merkle path
  from `leaf_i` at `pos_i` reaches `r_anchor` when `v_i ≠ 0`.
* **E2 Flags.** `locked_i := (h_aux_i ≠ 0)`; `refund_i` is boolean;
  `refund_i ⇒ locked_i`.
* **E3 Plain path (`¬locked_i`).** `pk_owner_i = [sk_view] G_d`: the
  spender is the owner. This is the base relation.
* **E4 Lock opening (`locked_i`).** `h_aux_i = PH(T_AUX, H_lo_i, H_hi_i,
  pk_refund_i.x, pk_refund_i.y, t_refund_i)`; `t_refund_i < 2^32`.
* **E5 Claim (`locked_i ∧ ¬refund_i`).** `pk_owner_i = [sk_view] G_d` and
  `SHA-256(s_i) = (H_lo_i, H_hi_i)`.
* **E6 Refund (`locked_i ∧ refund_i`).** `pk_refund_i = [sk_view]
  DiversifyHash(d_refund_i)` and `h_anchor ≥ t_refund_i` (both as 32-bit
  values). `h_anchor` is a Bitcoin block height: the note tree's anchors
  *are* heights of the Bitcoin chain the envelopes are published on (base
  profile §8, replay keeps one root per Bitcoin block), so this comparison
  is between two values on the same scale as the HTLC's `OP_CLTV` height.
* **E7 Nullifier.** `nf_pub_i = locked_i ? PH(T_NFLOCK, rho_i, pos_i) :
  PH(T_NF, sk_nf, rho_i, pos_i)`.

Every block is present for every input (the circuit is fixed-size);
conditions are enforced through the flags. The SHA-256 gadget runs for
every input; plain and dummy inputs hash whatever `s_i` holds and the
result is not constrained.

**Exactly one path.** `locked_i` is not a prover choice: it is a function
of `h_aux_i`, which E1 binds into the leaf under the anchor root, that is,
to the value replay used when the note was created. `refund_i` is a prover
choice, but each value enforces its own predicate: without `s` the claim
branch fails E5; before `t_refund` the refund branch fails E6; with the
wrong keys both fail. A claim and a refund of the same note publish the
same nullifier (E7), so replay accepts at most one.

**The anchor cannot be gamed.** Replay accepts an envelope at height `H`
only with `H − W ≤ h_anchor ≤ H − K_min` and `r_anchor = R[h_anchor]`
(base §11), and `h_anchor` is in `h_body`, which the proof binds. So a
refund accepted at `H` has `H ≥ h_anchor + K_min ≥ t_refund + K_min`: no
refund can be accepted before `t_refund`.

**Non-regression of the base profile.** A plain output of a swap envelope
has `h_aux = 0` and therefore the same leaf as a base output; a plain
input takes E3 and E7's base nullifier, which is the base relation; value
conservation is the same constraint over the same values; the nullifier
set is shared. The slot cannot carry value: `h_aux` is not an input to
`m_0`, the ciphertext or the value sum, and an output's `h_aux` is chosen
by its creator and fixed by replay at creation. Break-tests the
implementation carries: a locked note spent through a base envelope
(leaf mismatch → `ProofInvalid`); a locked input with a base nullifier
(E7); a claim with a wrong `s` (E5); a refund with an anchor below
`t_refund` (E6); a refund with a key other than `pk_refund` (E6); a plain
input claiming to be locked (E4, `h_aux = 0` cannot open); output value
inflation (base block 6); the same locked note claimed and refunded in two
envelopes (second rejected: nullifier spent); a published `h_aux` that
differs from the agreed one (the counterparty's pre-lock check, §9).

## 8. Replay

Kind `0x03` follows the base acceptance order (`PROFILE.md` §11) with:

* the verifying key of the extension, pinned in the deployment as
  `swap.vk_sha256` (§12); a deployment without a `swap` section rejects
  kind `0x03` as an unsupported kind, recorded like any rejection;
* the statement of §5 (`h_anchor` appended);
* output leaves derived with the published `h_aux_j`;
* the same note tree and the same nullifier set as the base kind.

Replay never interprets `h_aux` beyond hashing it into the leaf, as
§22.5 of the paper requires of the base layer.

## 9. The swap protocol (off-chain between the two parties)

Roles: **X** holds the secret `s` and will claim the Bitcoin HTLC,
revealing `s`; **Y** will claim the shielded note with the revealed `s`.
X locks the shielded note (paying Y), Y funds the HTLC (paying X). The two
flows are this one protocol with the roles assigned:

| Flow | X (knows `s`, claims BTC, locks the note) | Y (funds the HTLC, claims the note) |
|---|---|---|
| swap out: shielded → BTC | the user | the liquidity provider |
| swap in: BTC → shielded | the liquidity provider | the user |

Steps, with what each party checks **before locking its own leg**:

1. **Agreement** (two JSON messages, offer and accept): shielded amount
   `v_sh`, Bitcoin amount `v_btc`, `H`, X's refund address (`pk_refund`),
   Y's shielded address (owner of the locked note), the Bitcoin public
   keys `P_X` (HTLC claim) and `P_Y` (HTLC refund), `t_refund` and
   `T_htlc`. Both parties check `T_htlc + Δ ≤ t_refund` (§10).
2. **X locks.** X publishes a swap envelope whose output to Y's address
   carries `h_aux = PH(T_AUX, H_lo, H_hi, pk_refund.x, pk_refund.y,
   t_refund)` and value `v_sh`.
3. **Y verifies, then funds.** Y waits for the envelope to be accepted,
   decrypts the output as its owner, checks `v_sh`, and recomputes
   `h_aux` from the agreed `H`, `pk_refund` and `t_refund`: it must equal
   the published slot of that output. If it does not, Y does not fund;
   nothing of Y's is at risk yet, and X's note refunds to X after
   `t_refund`. Y then funds the HTLC: P2WSH of
   `OP_IF OP_SHA256 <H> OP_EQUALVERIFY <P_X> OP_CHECKSIG OP_ELSE <T_htlc>
   OP_CHECKLOCKTIMEVERIFY OP_DROP <P_Y> OP_CHECKSIG OP_ENDIF` with `v_btc`.
4. **X checks the HTLC, then claims it.** X verifies on chain the script,
   amount and `T_htlc`, then spends it with `s` before `T_htlc`. `s` is
   now public.
5. **Y claims the note.** Y reads `s` from the HTLC spend and publishes a
   swap envelope spending the locked note on the claim branch, with any
   anchor inside the window; it must be accepted before X's refund can
   be, which §10 guarantees.

Endings:

| Case | Shielded leg | Bitcoin leg |
|---|---|---|
| both honest, both claim | Y gets `v_sh` | X gets `v_btc` |
| Y never funds | X refunds after `t_refund` | nothing happened |
| X never claims the HTLC | X refunds after `t_refund` | Y refunds after `T_htlc` |
| X claims the HTLC late, after Y's refund | X refunds after `t_refund` | Y refunded; X's claim fails (no UTXO) |
| X claims the HTLC in time | Y claims the note with `s` (§10) | X got `v_btc` |

There is no ending in which one party receives and the other loses: Y's
shielded claim needs `s`, which exists on chain only because X took
`v_btc`; X's refund of the note needs `h_anchor ≥ t_refund`, which §10
keeps out of reach while Y can still claim.

## 10. Timeouts and the ordering that makes it atomic

Both timelocks are Bitcoin heights, so they are on one clock: the shielded
side has no clock of its own. The anchor `h_anchor` a transfer names is
the height of a Bitcoin block (replay derives `R[h]` per Bitcoin block
and accepts an anchor only inside the window below the inclusion
height), and `t_refund` is compared with it in E6; `T_htlc` is the height
in the HTLC's `OP_CHECKLOCKTIMEVERIFY`. Everything below rests on that.

Constants: `K_min` is the deployment's minimum anchor depth (base profile
§9, `1` in the development deployments); `K_wallet` is the wallet's own
anchor depth (base profile §A.6, `3` in this implementation: a wallet
anchors `K_wallet` blocks below the tip so a shallow reorganisation does
not invalidate its proof); `R` is the reaction margin defined here.

Y's claim
of the note needs: `s` published (by X's HTLC spend at some height `h_s`),
a replayed anchor, proving, inclusion. X's refund becomes acceptable at
height `t_refund + K_min` at the earliest (§7). X can only reveal `s`
while the HTLC is unspent, that is, before Y refunds it, which Y may do
from `T_htlc` on. Therefore the rule

```
T_htlc + Δ ≤ t_refund,    Δ = K_min + K_wallet + R
```

gives Y at least `Δ` blocks after the latest possible `h_s ≈ T_htlc` (Y
refunds the HTLC at `T_htlc` if `s` has not appeared, after which X cannot
reveal it) before X's refund can be accepted, where `R` is a reaction
margin (profile default `R = 6`, so `Δ = 1 + 3 + 6 = 10` blocks). Y must
refuse any agreement that violates the rule; X loses nothing by a larger
`Δ` except a longer worst-case lock of `v_sh`.

**Liveness assumption.** The rule protects Y only if Y is online: from
the moment it funds the HTLC until its claim of the note is accepted, Y
must watch the Bitcoin chain for the HTLC spend that reveals `s` and react
within `R` blocks (sync, prove, publish). A Y that is offline longer than
the margin after `s` appears can lose `v_sh` while X keeps `v_btc`. This
is inherent to HTLC swaps, not to this construction; the implementation's
provider role is a process that polls the chain, and the drill keeps it
running. The margins also assume no reorganisation deeper than `K_min`
once a transfer is accepted, as the base profile does.

The symmetric danger, the "free option" where X waits to see prices move
before claiming, is bounded by `T_htlc`: X's option expires when Y
refunds. Its economic value is a matter for a provider's pricing
(a premium, or collateral), outside this profile.

## 11. Privacy

What the extension adds to the base leakage (`PROFILE.md`, paper §20):

* **A locked output is visible as one.** The envelope kind and a
  non-zero `h_aux` are public, so swap creations form their own anonymity
  set; the spend of a locked note is also a kind `0x03` envelope. Its
  amount, owner and spending branch stay hidden; the keyless nullifier
  reveals nothing a base nullifier does not.
* **No cryptographic link to the HTLC for third parties.** `h_aux` commits
  to `H` together with `pk_refund` and `t_refund`; `pk_refund` is a
  private address, so an observer who sees `H` in the HTLC script cannot
  test it against any published `h_aux`. What remains is **timing
  correlation**: a swap envelope and an HTLC of plausible size appearing
  close together. The HTLC amount and parties' Bitcoin keys are public as
  for any Bitcoin transaction.
* **The counterparty learns what a counterparty learns**: the amounts,
  the shielded address used as owner or refund key, the Bitcoin keys, and
  the timing. A user who swaps repeatedly with one provider gives that
  provider a view of those swaps; reusing addresses across swaps links
  them for the provider.

## 12. Deployment, keys, setup

A deployment enables the extension with a `swap` section:

```json
"swap": { "vk_sha256": "…", "setup": { "kind": "insecure-seed" | "ceremony", … } }
```

The extension circuit needs its own trusted setup; the ceremony tooling
takes a circuit name (`--circuit swap`), and the pinned hash is checked
the same way as the base key's. The base key is unaffected by enabling
the extension.

## 13. Costs (measured)

| Item | Value |
|---|---|
| SHA-256 of a 32-byte `s` in circuit (arkworks gadget) | 39 482 constraints per input |
| Base transfer circuit | 84 362 constraints, domain `2^17` |
| Swap circuit (measured) | 174 803 constraints, 18 public inputs, domain `2^18` |
| Envelope | 764 bytes (+64) |
| Proof | 192 bytes (unchanged) |

The paper mentions an *off-chain binding proof* tying the circuit-native
and Bitcoin hash contexts to one preimage, which would keep the transfer
circuit free of SHA-256 (a Poseidon lock in `h_aux`, a separate proof
exchanged before funding). We measured and chose SHA-256 in the circuit
instead: the binding proof would be a second circuit of about the same
size with its own trusted setup, and the swap's atomicity would then rest
on an interactive exchange of proofs rather than on the transfer proof
replay verifies. The price is a circuit twice as large and a proving time
of a few seconds.

## 14. Tests and the signet run

Tests at every layer: each block E1–E7 rejecting its violation and the
break-tests of §7; codec round trip, canonicality and rejections of the
swap envelope; replay of base and swap envelopes in one deployment,
including a deployment without the extension; wallet flows for lock,
claim and refund; the protocol messages. The signet run (`RUNS.md`) uses
a real P2WSH HTLC validated by Bitcoin Core and shows both flows and both
endings: a completed swap (HTLC claim reveals `s`, the note is claimed)
and a double refund (HTLC refunded after `T_htlc`, note refunded after
`t_refund`), plus the rejections that keep the mixed endings impossible:
a note claim with a wrong `s` and a refund below `t_refund` rejected by
replay, an HTLC claim with a wrong preimage rejected by the node.

## 15. Changelog

* **v0.1** — initial draft: in-circuit SHA-256 lock, keyless locked-note
  nullifier, kind `0x03` with a 64-byte aux section, `h_anchor` as the
  18th public input, the X/Y protocol with `T_htlc + Δ ≤ t_refund`.
