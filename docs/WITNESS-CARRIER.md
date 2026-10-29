# Witness carrier profile (draft v0.1)

The alternative publication carrier the paper names in §22.1 and sizes in
§A.4: the envelope bytes travel in transaction **witness** data, at one
weight unit per byte instead of the four of an OP_RETURN output, through a
two-transaction commit-and-reveal flow. Per the paper (§A), a different
carrier is a **separate, non-interoperable deployment**: a deployment
picks `"carrier": "witness"` in its profile and every replaying
implementation of that deployment applies the rule below; an OP_RETURN
deployment (`PROFILE.md` §10, the default) is untouched.

Nothing but the carrier changes. The envelope bytes, their canonical
parsing, `h_body`, the statement, the proof, the acceptance order and the
replay rules are those of `PROFILE.md` (and `SWAP.md` for kind `0x03`).
This document only says where the bytes are and how they get there.

Status: draft, implemented (`profile-new --carrier witness`, the
publisher, the relayer, the indexer rule); §6 carries measured numbers.
Reviewed firsthand by the project's security reviewer: findings and their
status are in `docs/REVIEW-WITNESS-CARRIER.md`.

## 1. Transactions

| Transaction | Role |
|---|---|
| **commit** | pays one P2TR output whose only script path is the envelope tapscript (§2); any inputs, any other outputs (its change) |
| **reveal** | spends that output through the script path; its witness therefore contains the tapscript and so the envelope; its outputs carry whatever the envelope kind needs beside the bytes (a mint's vault payment, a payout memo in an OP_RETURN output, change) |

The **reveal transaction is the carrier**. The commit transaction carries
nothing an indexer reads: it only commits to the envelope (§4). Replay
processes reveal transactions in block order like any carrier; the commit
may sit in the same block or an earlier one.

## 2. The envelope tapscript

```
<x-only key, 32 bytes> OP_CHECKSIG OP_FALSE OP_IF <chunk 0> … <chunk k> OP_ENDIF
```

* The chunks are the envelope bytes in order, every chunk but the last
  exactly 520 bytes (the largest push Bitcoin script allows), the last the
  remainder, none empty. A 700-byte base envelope is `520 ‖ 180`; a
  764-byte swap envelope `520 ‖ 244`; an 89-byte mint one push.
* `OP_FALSE OP_IF … OP_ENDIF` never executes: the branch is inert data.
  The script's only live instruction is `OP_CHECKSIG` against the key,
  which the reveal satisfies with a 64-byte Schnorr signature
  (`SIGHASH_DEFAULT`, no annex). The key belongs to whoever publishes
  (the wallet's or the relayer's fee wallet, receive key 0); it plays no
  protocol role beyond making the reveal theirs to sign.
* Leaf version `0xc0` (tapscript). Pushes are minimal, as the parser
  requires.

## 3. Commit output

The P2TR output key is the BIP 341 tweak of the **unspendable internal
key** `H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)`
(BIP 341's "nothing up my sleeve" point, the hash of the secp256k1
generator's uncompressed encoding; nobody knows its discrete logarithm) by
the Merkle root of the single leaf above. Consequences:

* **The key path is provably unspendable.** A key-path spend needs a
  signature under `H` tweaked, which nobody can make. The only way to
  spend the commit output is the script path, which reveals the
  tapscript, which contains the envelope. Nobody, publisher included, can
  spend the output without publishing exactly the committed envelope.
* **The envelope is fixed when the commit confirms.** The output key
  commits to the leaf hash, the leaf hash to the script bytes, the script
  to the envelope. The control block of the reveal (33 bytes: leaf
  version, parity, `H`) lets Bitcoin consensus check that the revealed
  script is the committed leaf; a reveal with a different script is
  invalid. So there is no carrier-level malleability: the bytes an indexer
  reads are the bytes committed, and `h_body` over them is what the proof
  was made for, exactly as with OP_RETURN.

The commit output must hold the reveal's fee plus the value of the
reveal's outputs (the mint's vault payment, dust for the change output).
The publisher computes it from the reveal's size at the chosen fee rate.

## 4. The carrier rule (witness mode)

For a transaction `tx`, in block order:

1. For each input, take the script of its script-path witness: the
   second-to-last item (`…signatures…, script, control block`), or the
   third-to-last when the last item is a BIP 341 annex (it starts with
   `0x50`: `…, script, control block, annex`); a witness too short for
   that reveals nothing. If the script has the shape of §2 and its
   concatenated chunks start with the magic `"btc" 0x01`, the input
   **reveals an envelope**. (The publisher never adds an annex; the rule
   reads one so that a valid reveal is never a spent commit the indexer
   ignores, and so that every implementation agrees on the same inputs.)
2. If exactly one input reveals an envelope, `tx` is a candidate with
   those bytes. If more than one does, `tx` is **rejected and logged**
   (never "the first one"). If a script has the magic inside but breaks
   the shape (an empty chunk, a non-full chunk followed by another, extra
   opcodes), `tx` is a probe: rejected and logged.
3. OP_RETURN outputs of `tx` are never envelopes under this rule; an
   OP_RETURN output whose payload starts with `"sbx"` is the payout memo
   of `docs/BOUNDARY.md`, as in OP_RETURN mode.
4. A commit transaction is never a candidate: its outputs are plain P2TR
   and its inputs reveal nothing.

The candidate bytes go to the same strict parser and the same acceptance
order as an OP_RETURN candidate (`PROFILE.md` §7, §11). Two implementations
of a witness deployment that agree on this rule derive the same state; an
OP_RETURN implementation reading the same chain sees none of these
carriers, and a witness implementation sees none of the OP_RETURN ones.

## 5. Publication

`sb` publishes a witness-mode envelope from the fee wallet as a pair: the
commit from the wallet's coins to the commit address, the reveal from the
commit output to the kind's extra outputs, the memo and a fresh change
address; both are broadcast, the reveal spending the unconfirmed commit.
The fee-funding models of `docs/BOUNDARY.md` carry over:

* **self-funding**: as above;
* **external funding**: `--no-broadcast` writes the commit output's
  address and required value (and a `fundrawtransaction` template with
  that one output); any wallet funds it; `sb publish <label> --reveal`
  then signs and broadcasts the reveal from the wallet that wrote the
  entry, since the tapscript's key is its;
* **relayer**: a relayer whose deployment is in witness mode publishes
  the pair from its own coins; the client's request is unchanged.

The wallet's own copy of its notes, locks and swap state is unaffected:
only the carrier differs.

## 6. Footprint and standardness (measured)

Measured on the private signet (`RUNS.md`, Bitcoin Core 30.2, one
P2WPKH input to the commit, P2WPKH change outputs):

| Envelope | OP_RETURN carrier | Witness carrier: commit + reveal | Saving |
|---|---|---|---|
| mint, 89 B | 242 vB | 153 + 171 = **324 vB** | none (the pair's overhead exceeds a small envelope) |
| transfer, 700 B | 825–892 vB | 153 + 294 = **447 vB** | ≈ 46–50 % |
| withdraw, 700 B + 46-byte memo output | 839–870 vB | 153 + 339 = **492 vB** | ≈ 41–43 % |

The commit transaction is a fixed 153 vB (one input, the P2TR output and
change); the reveal is where the envelope's weight is paid at a quarter
of the OP_RETURN rate. The paper's §A.4 template (P2TR key-path inputs
and P2TR outputs) gives 154 + 284 = 438 vB for a 610-byte envelope; this
implementation's 447 vB for 700 bytes is the same construction with
P2WPKH outputs.

Standardness: a reveal of this shape is the same construction as an
inscription (`OP_FALSE OP_IF` data in a tapscript), relayed and mined
under Bitcoin Core's **default** policy on every version since Taproot,
and it does not depend on the `datacarriersize` setting that an OP_RETURN
envelope above 83 bytes does. That is a statement about the default: node
operators and miners can and some do run policies that filter such
witness data, so relay is a property of the network a deployment
publishes to, to be measured there, not a guarantee. The limits that apply are script's 520
bytes per push (hence the chunks), the standard transaction weight
(400 000 WU, far above a reveal), and whatever policy a future node
version may add for witness data; like any standardness property it is a
deployment assumption, not a consensus guarantee.

## 7. What this does not change

* The privacy model: a witness envelope is as visible as an OP_RETURN one
  (the bytes are public), and the two transactions, their keys and the
  fee pattern are the same fee-wallet linkage as `docs/BOUNDARY.md`
  describes. A commit output waiting for its reveal is a visible signal
  that an envelope is about to appear.
* The trust model of chain sources (`README.md`): a verified-sync client
  of a witness deployment gets the reveal transactions as carrier
  candidates in its block views, witness included, and applies this rule
  itself.

## 8. Changelog

* **v0.1** — initial draft: tapscript shape, NUMS internal key, exactly-one
  revealing input rule, two-transaction publication through the three fee
  models, measurements on the private signet.
