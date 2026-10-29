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

## Fee funding

Every carrier transaction needs Bitcoin inputs to pay its miner fee, and
those inputs are what links carriers at the Bitcoin layer (paper §20.5):
the transfer proof says nothing about them. The paper requires any fee
model to state who pays, what each party sees, and what happens when a
service is unavailable. `sb` implements four, all outside the profile
(`PROFILE.md` §14): the three below, and a development scaffold of the
PIPE-based fee vault the paper intends, specified in `docs/FEE-VAULT.md`.

### 1. Self-funding from the wallet's fee wallet (default)

Each shielded wallet has a transparent **fee wallet** derived from its seed:
secp256k1 keys on two chains, receive (`"sb/v1/funding"` for index 0, the
pre-HD key, then `"sb/v1/funding/<i>"`) and change
(`"sb/v1/funding/change/<i>"`), all P2WPKH. `sb address` shows the first
unused receive address; `--new` hands out the next one. Change always goes
to a fresh change address, and the wallet looks for coins up to five
indices past the last known one on each chain.

* Who pays: the wallet itself, from coins sent to its receive addresses.
* What is visible: the carrier's inputs and change output. No address is
  used twice, so a casual address lookup no longer lists every carrier, but
  the **change chain still links them**: whoever follows the change output of
  one carrier into the next sees the same cluster as before, with its count
  and timing of mints, transfers and withdraws, and the mint ↔ transfer ↔
  withdraw connection (the vault payment and the withdraw carrier are paid
  from the same wallet). Note values, recipients, the spent note and the
  sender ↔ recipient link stay hidden, and a recipient that never publishes
  is invisible. This is still the maximal form of the leak the paper names.
* Unavailable: never; it needs only the chain source.

### 2. External funding (any other wallet pays)

`--no-broadcast` writes the carrier to the outbox as three files:
`<label>.json` (envelope, memo, required extra outputs), `<label>.hex`
(the envelope alone) and `<label>.tx`, the **unfunded transaction**: the
carrier's outputs with no inputs, framed as Bitcoin Core's
`createrawtransaction` frames it. Any wallet can add inputs and a change
output and broadcast it; with Bitcoin Core:

```sh
bitcoin-cli fundrawtransaction $(cat outbox/<label>.tx) | jq -r .hex \
  | xargs bitcoin-cli signrawtransactionwithwallet | jq -r .hex \
  | xargs bitcoin-cli sendrawtransaction
```

`sb publish <label> --name <wallet>` does the same from another `sb` wallet's
fee coins (a friend's, or a wallet kept only for fees). The sender's notes
stay locked until the transfer is seen accepted (`sb unlock` releases them
if it never is).

* Who pays: the owner of the funding wallet.
* What is visible: that wallet's inputs and change. If it is unconnected
  to the shielded wallet's other carriers, the carrier joins that wallet's
  cluster instead; the paper's "dedicated fee wallet" model.
* Unavailable: the carrier waits in the outbox; any of the other models
  publishes it later.

### 3. Sponsored relayer

`sb relay-serve --name <wallet>` runs an HTTP service that publishes other
people's **transfer** envelopes from its own fee wallet: `POST /relay
{"envelope": "<hex>", "memo": "<hex>"?}` answers with the carrier txid,
`GET /info` with deployment, network, replayed tip and fee rate. Before
paying, the relayer replays to the chain tip and checks the envelope
exactly as the indexer will at the next block (parse, anchor window and
root, unspent nullifiers, proof); it refuses mints (they pay the vault),
envelopes it already paid for that still wait for a block, memos that are
not a payout memo, and more than `--max-per-hour` carriers. Clients use
`sb send --relay http://host:port`, `sb withdraw --relay …` or `sb publish
<label> --relay …`.

* Who pays: the relayer's operator. There is no fee channel back to it in
  this design (a fee note would take the transfer's second output), so it
  is **sponsored publication**: a development service, or one that is paid
  out of band.
* What is visible: the relayer sees the envelope and memo (public on chain
  anyway), the client's network address and the submission time; it cannot
  read notes or alter the body, and a transfer it relays is bound to its
  nullifiers, not to the relayer. On chain the carrier joins the relayer's
  cluster, which says nothing about which wallet built it beyond "a client
  of this relayer". Network metadata is the client's problem (Tor or a
  trusted relayer).
* Unavailable: the client gets an error and the carrier stays in the
  outbox; publish it with model 1 or 2 or another relayer. A relayer can
  censor but not forge, replay or redirect a transfer.
* The operator's exposure: anyone can make the relayer run a check
  (replay to the tip, one proof verification), so the service is a
  single-threaded target for availability attacks. It limits submissions
  per client address per minute (`--max-checks-per-minute`), replays at
  most once per `--sync-interval`, answers `/info` from memory, and caps
  request bodies; none of that is authentication, and a public relayer
  needs a front proxy or an allow-list. Funds are never at risk beyond the
  hourly budget: only valid, unspent, never-seen transfers are paid for.

### 4. Fee vault (paid in shielded credit)

`sb fee-vault serve` runs the paper's fee-unlock vault (§20.5) with the
operator's code in place of the PIPE covenant: a client deposits a
shielded note to the vault whose `rseed` commits to an authorization key,
then has carriers published from the vault's pool by signed draws against
that credit, and reclaims what is left by the same key. The rule, the
ledger invariants (no over-release, backing, write-before-broadcast), the
leakage and what the covenant would replace are in `docs/FEE-VAULT.md`.

* Who pays: the client, from its credit; the vault's pool fronts the
  miner fee and is paid in shielded value.
* What is visible: on chain, an ordinary transfer (the deposit) and
  carriers in the vault's cluster, as for a relayer; to the vault, the
  client's publication pattern under one deposit.
* Unavailable: the carrier waits in the outbox for any other model;
  credit waits for the vault (the one exposure of the model: unspent
  credit, bounded by deposit size).

What none of the four does: hide the **fact** of publication, the carrier
size (700-byte envelopes in ~830–890 vB transactions), the anchor age or
the fee rate; those fingerprints are the paper's §22.1.
