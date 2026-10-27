# Development boundary (non-normative)

The paper leaves peg-in and peg-out to a separate PIPE-based treatment
(§20.4, §22.3). Until that exists, test deployments of this implementation
use a **custodial development boundary** so that value can enter the shielded
layer at all. Nothing here is part of the transfer protocol; a deployment
profile without a `boundary` section rejects every mint.

**Never hold real value with this boundary.** The vault is a single key held
by the deployment operator.

## Mint (kind `0x02`)

A mint is a carrier transaction that

1. pays exactly `v` satoshis to the deployment's vault `scriptPubKey`, in
   exactly one output, and
2. carries a mint envelope in its single OP_RETURN:

```
"btc" 0x01 0x02 0x00 ‖ v (u64 LE) ‖ d (11) ‖ rseed (32) ‖ pk_d (32)      = 89 bytes
```

Replay (after the ordinary carrier and parse checks):

* `h_body = H_body(const_salt ‖ mint_bytes)`;
* `v` must equal the vault output amount;
* `(pk_eph, ct_note) = Encrypt((v, d, rseed), pk_d)` is recomputed
  (invalid `d` → reject);
* `leaf = PH(T_LEAF, const_salt, h_body, 0, pk_eph.x, pk_eph.y, c_0, c_1, tag, 0)`
  is appended; no nullifier is published.

The minted note is an ordinary note: its creation fields are the mint's
`h_body` and output index 0, and the standard transfer circuit spends it.
The plaintext is public, which is acceptable for a boundary event (§20.4);
every later transfer of that value is private.

## Withdraw

A withdraw is an ordinary private transfer of `amount` to the operator's
shielded address (`boundary.operator_address`), whose carrier transaction
additionally carries a **payout memo** in a second OP_RETURN output:

```
"sbx" 0x01 ‖ amount (u64 LE) ‖ destination scriptPubKey
```

The carrier rule ignores OP_RETURN outputs without the protocol magic, so the
memo never affects replay; the indexer only records it next to the accepted
event. The operator wallet (`sb payouts`) scans its received notes, matches
each creating transfer's memo, pays `amount` (at most the note value) to the
destination from the vault key, and records the payout so it is never made
twice. Nothing binds the memo to the proof: a relayer that rewrote it could
redirect a payout, which is acceptable only for a development deployment.
