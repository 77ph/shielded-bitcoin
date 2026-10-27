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

Not yet implemented. The planned development mechanism: a transfer whose
output 0 pays the operator's shielded address, plus a second OP_RETURN
(without the protocol magic) naming the payout `scriptPubKey`; the operator
pays from the vault after the transfer is accepted. Until then, value leaves
a test deployment only by the operator's manual action.
