# Publication privacy and wallet policy (draft v0.1)

The paper's §22.3 names two surfaces that the transfer proof does not
cover and a deployment must: **network observation** (who sees a carrier
before it is in a block, and where it came from) and **wallet policy**
(the choices a wallet makes that shape an observer's posterior without
breaking any validity rule: arity, change placement, anchor selection,
publication timing, relayer choice, retries, fees). §20.6 adds that the
privacy set is always relative to an observer and an observation model.

This document is the deployment-layer answer of this implementation:
what each surface leaks, what `sb` does about it, what it deliberately
does not do, and what no wallet can hide. Nothing in the profile
(`PROFILE.md`) changes; the envelope, the proof, the acceptance rules and
replay are untouched. Where a choice is a per-deployment policy (the
anchor depth) it lives in the deployment profile so that every wallet of
the deployment behaves the same way; where it is a per-wallet choice (a
proxy, a delay) it is an option with a stated default.

Status: draft, not yet implemented; §6 to be measured.

## 1. What an observer sees, by vantage point

| Vantage point | Sees, for one accepted transfer | Sees across transfers |
|---|---|---|
| **the chain** (anyone, forever) | the carrier: its size (700-byte envelope, 825–892 vB, or the witness pair), its fee rate, its inputs and change (the fee model's cluster, `BOUNDARY.md`), the envelope's anchor height (and so the anchor age at acceptance), the arity (always 2-in-2-out), the kind (transfer, swap, mint) and a withdraw's memo | the fee cluster's history; timing between related carriers; anchor-age and fee-rate habits |
| **the network** (a node that relays the carrier, the mempool, a service it was submitted to) | the IP address that submitted it, the time it was first seen, whether it was re-submitted, replaced or never confirmed | an address's submission pattern; the link between a failed attempt and its rebuilt successor (same nullifiers) |
| **a service** (relayer, fee vault, indexer the wallet syncs from) | the client's address and time, the envelope (public anyway); a vault, the client's draw pattern under one deposit (`FEE-VAULT.md` §10); an indexer, which blocks and transactions the wallet asked for | everything above, per client |

The transfer proof hides the amounts, the spent notes and the
sender–recipient relation under every vantage point. The rest is this
document's subject.

## 2. The network layer

### 2.1 One proxy for everything outbound

`sb --proxy socks5://host:port` (or `SB_PROXY`) routes **every**
outbound connection through a SOCKS5 proxy: chain sync (Esplora,
Electrum, Bitcoin Core RPC, a verified-sync indexer), broadcast,
relayer and fee-vault requests. Host names are passed to the proxy and
resolved there (SOCKS5 with domain-name addresses), so there is no local
DNS lookup to observe. Tor's SOCKS port is such a proxy; so is an SSH
dynamic forward (`ssh -D`), which is what the signet run in §6 used.
With a proxy set, a connection that cannot go through it fails rather
than falling back to a direct one.

What it does: the submitting address a node or a service sees is the
proxy's, not the wallet's; the same for the sync traffic that would
otherwise tell an indexer which wallet is behind which queries.

What it does not do: hide the fact or the time of a submission from the
node or service that receives it, or make two submissions from the same
proxy unlinkable to each other (Tor gives a fresh circuit per connection
only when configured to; an SSH forward is one address).

### 2.2 A separate route for publication

`sb --publish-via <chain spec>` broadcasts carriers through a different
backend from the one the wallet syncs from (for instance: sync from a
local node, broadcast through a public Esplora over Tor). The node a
wallet syncs from sees its sync pattern; the node it broadcasts through
sees its carriers; with two routes nobody sees both. Without the option
the chain source does both, as before.

### 2.3 Delayed publication

`sb --delay <lo>-<hi>` (seconds) holds a built carrier for a uniformly
random time in the range before broadcasting it, in every fee model
(self-funded, external, relayer, fee vault). A wallet that publishes the
instant it finishes proving ties the carrier to whatever triggered it (a
received payment, an interactive session); the delay decorrelates the
two. The anchor policy bounds the delay (§3.3): the carrier must still
be accepted within the window `W`, so the wallet refuses a delay that
could outlive it and re-checks the anchor when the delay ends.

### 2.4 Not done, and why

* **Dandelion / stem relay.** Bitcoin Core does not implement it; a
  metaprotocol wallet cannot add it. The proxy is the substitute at the
  submission hop.
* **Mixnet transport, cover traffic.** A separate network adversary
  model, as the paper says; out of scope. The proxy option accepts any
  SOCKS5 endpoint, so a mixnet client that speaks SOCKS5 can be plugged
  in without a code change.
* **Rebroadcast.** `sb` submits a carrier once; a carrier the network
  drops is republished by the user (`sb publish <label>`), which is the
  same bytes and so visibly a retry. Bitcoin Core rebroadcasts its own
  wallet's transactions; it does not know about carriers it only relayed.
* **Batching.** One envelope per carrier; a batching service would be a
  relayer that pays for several carriers in one transaction, which this
  implementation does not provide.

## 3. Wallet policy

### 3.1 Arity: uniform by construction

Every transfer is 2-in-2-out (profile §8.2): missing inputs and outputs
are dummies of value 0 with fresh randomness, and a dummy is
indistinguishable from a real note on chain. The paper's "standard arity
with padding" is therefore what the profile already does, and padding
costs nothing in bytes (the envelope is fixed-size). The number of
**real** inputs is invisible: a nullifier does not say whether its note
was real.

### 3.2 Change placement: random

Output positions are public (index 0 and 1); contents are not. The
wallet used to put the payment at index 0 and the change at index 1,
which an observer cannot see directly, but which a recipient who learns
(or publishes) their note's index can turn into "the other output is the
sender's change". The builder now places the outputs in a uniformly
random order, including a lone real output against its dummy. The wallet
finds its own notes by decryption, so nothing in scanning or recovery
depends on the position.

A swap envelope (`SWAP.md`) publishes `h_aux` per output, so which
output is the locked one is visible by construction; its placement is
not randomised, since there is nothing to hide.

### 3.3 Anchor selection: a deployment policy

A transfer names its anchor height; the chain shows at what height the
carrier was accepted; the difference is the **anchor age**, and a wallet
that always builds at `tip − 3` while another builds at `tip − 6` is
fingerprinted by it. The paper asks for a shared policy. The anchor depth
is therefore a field of the deployment profile (`anchor_depth`, default
3, the value the wallets used so far) that every wallet of the deployment
reads, instead of a constant in the wallet code: all wallets of a
deployment build at the same depth. What then varies the observed age is
the time between building and acceptance: proving time, a delay (§2.3),
mempool time. The acceptance window `W` (profile §A.6) bounds all of it.

### 3.4 Input selection: invisible

Largest note first, two at most: the selection is not observable (§3.1),
so it is chosen for the fewest proofs, not for privacy. What is
observable is the **consequence** of selection over time, such as a
wallet that has to consolidate (send to itself) before a payment, which
is one more carrier.

### 3.5 Retries: fresh randomness, same nullifiers

A transfer that is rebuilt (a stale anchor, a changed amount, a lost
outbox) draws fresh randomness for everything: `rseed`, and with it the
ephemeral keys, the ciphertexts, the note commitments, and the dummies.
Two builds of the same payment share nothing an observer can match,
**except the nullifiers**: a nullifier is a function of the spent note
and its position, so a rebuilt transfer that spends the same notes
publishes the same nullifiers, and an observer who saw the first attempt
in the mempool links the two. That is inherent to nullifier-based
designs; the wallet documents it and keeps the first attempt in the
outbox so that a retry is the same carrier whenever possible (a stuck
carrier is republished, not rebuilt).

### 3.6 Fees and funding

The fee rate is explicit (`--fee-rate`, default 2 sat/vB) and public on
chain; a wallet that always pays the same unusual rate is
fingerprinted by it, as the paper notes, and so is one whose rate
tracks a particular estimator. This implementation does not pick a rate
for the user; a deployment that wants uniformity should document a
rate policy for its wallets (for instance the node's estimate for the
next block, rounded to whole satoshis per vbyte). The funding model is
the other half of the fingerprint and has its own document
(`BOUNDARY.md`, "Fee funding", `FEE-VAULT.md`).

### 3.7 Publication timing

Besides the delay (§2.3): a wallet that publishes right after receiving
a note links the two in time; a wallet that publishes at the same hour
every day is a clock. These are user behaviours, not code; the delay
option is the one tool the wallet offers, and it is off by default so
that a test run is reproducible.

## 4. What stays visible under every policy

The fact of publication, the carrier's size and kind, its fee rate and
funding cluster, its anchor age within the window, the time it entered a
block, a withdraw's payout, and, to the node or service that received
it, the submitting address (the proxy's, with §2.1) and time. These are
the paper's residual surfaces (§20.5, §22.1, §22.3), restated here so
that no reader takes the options above for more than they are.

## 5. Options, summarised

| Option | Default | Scope |
|---|---|---|
| `--proxy socks5://host:port` / `SB_PROXY` | none | all outbound connections |
| `--publish-via <chain spec>` | the `--chain` source | broadcast only |
| `--delay <lo>-<hi>` | none | every fee model's broadcast |
| `anchor_depth` (profile) | 3 | every wallet of the deployment |
| change placement | random | the builder |

## 6. Measured

To be filled: the end-to-end test with an in-process SOCKS5 proxy (every
connection of a sync and a send arrives at the proxy, none directly; a
proxy that is down fails the command), and a signet run publishing
through an SSH dynamic forward with a delay (the egress address seen by
the network, the delay drawn, the anchor age at acceptance).

## 7. Changelog

* **v0.1** — initial draft: the three vantage points, proxy / separate
  publication route / delay, the five wallet-policy points with what is
  inherent, the residual list.
