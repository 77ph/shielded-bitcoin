# Roadmap

What this implementation has done, what it does next, and in what order.
The next directions are taken from the paper's own "Future Work" (§22):
each one below names the section it comes from.

## Purpose and scope

This is an independent implementation of *Shielded Bitcoin: Private
Transfers on the Bitcoin L1* (alloc-init, September 2026), written to be
read and run: code, tests, and runs on test networks. It is not a product
and no mainnet deployment is planned. Organisational steps that a real
deployment would need (an independent audit, a parameter ceremony with
independent participants) are recorded as conditions in the documents
and rehearsed as scripted drills, not performed. Everything else, from
the transfer relation to the deployment layer the paper leaves open, is
built, tested, and run on signet.

## Done

| Area | Paper | State |
|---|---|---|
| Transfer layer: notes, keys, encryption, leaves, nullifiers, envelope, `h_body`, note tree | §5, §6, §9, §12, §13, §A | profile v0.2 (`PROFILE.md`), test vectors regression-locked |
| Transfer circuit, Groth16 over BLS12-381 | §14, §B | 84 362 constraints, 17 public inputs, prove ≈ 1.5 s |
| Deterministic replay: carrier rule, acceptance order, anchor window, checkpoints, reorgs | §8, §11, §15, §A.4–A.7 | Bitcoin Core RPC, Esplora, Electrum (pinned TLS) sources; JSON or PostgreSQL state |
| Wallet: scanning, recovery, selection, anchor policy, locks | §10, §16, §C | encrypted wallet files, CLI |
| Development boundary: custodial mint and withdraw via payout memos | outside §22.3 | dev-only, documented in `BOUNDARY.md` |
| Fee funding: fresh addresses, external funding of unfunded carriers, sponsored relayer | §20.5, §22.3 | three models, each with who pays, what it sees, what happens when it is down |
| Verified sync from an indexer: carriers with BIP 37 proofs, root claims checked | §22.2 (the "verify an indexer's response" option) | `sb serve`, `--chain light:`; the succinct replay proof remains open |
| Parameter ceremony: BGM17 phase 1, key derivation checked against arkworks, phase 2, beacon, import of public powers-of-tau transcripts | §A.1 | `sb ceremony`, drills with real beacons, `CEREMONY.md`, `REVIEW-CEREMONY.md` |
| Static build, CI with coverage gate | — | runs on the server's older glibc |

Runs: private signet, public signet, verified sync, ceremony drills, all
in `RUNS.md`.

## Done since (29 October 2026)

| Direction | Paper | State |
|---|---|---|
| Atomic swap between a shielded note and transparent Bitcoin through `h_aux` and a P2WSH HTLC | §22.5 | `SWAP.md`, extension circuit (SHA-256 in circuit), kind `0x03`, `sb swap` / `sb htlc`, both endings run on the private signet under Bitcoin Core, reviewed (`REVIEW-SWAP.md`) |
| Witness-carried envelopes, a separate deployment profile | §22.1, §A.4 | `WITNESS-CARRIER.md`, commit-and-reveal publisher through all three fee models, indexer rule, measured on the private signet, reviewed (`REVIEW-WITNESS-CARRIER.md`) |
| Fee-unlock vault as a development scaffold | §20.5, §22.3 | `FEE-VAULT.md`, `sb fee-vault`, deterministic release rule and ledger, backing guard, reclaim, run on the private signet with both endings and every refusal, reviewed (`REVIEW-FEE-VAULT-IMPL.md`) |
| Publication privacy and wallet policy | §22.3, §20.6 | `PUBLICATION.md`: a SOCKS5 proxy for every outbound connection, a separate publication route, delayed broadcast within the window, a shared anchor depth per deployment, random change placement, the residual surfaces named; tested against an in-process proxy, run on signet through an SSH forward, reviewed (`REVIEW-PUBLICATION-IMPL.md`) |
| Succinct replay proofs | §22.2 | `REPLAY-PROOF.md`: the completeness result (enumeration cannot be proven short of every raw transaction), the batch circuit over an indexed nullifier tree and a root tree (≈ 217 000 constraints per slot, measured), batched verification, the recursion frontier measured on a two-chain (155 000 constraints per native level); `sb prove-batches` and the `proof:` light client, run on signet (245 blocks, 110 KB against 35 MB); reviewed (`REVIEW-REPLAY-PROOF-IMPL.md`) |

## Next

The aim now is to exhaust the paper's §22: every item ends either as an
implementation run on a test network, or as a demonstration, with
numbers, that it cannot be implemented at present (or that nobody knows
how). The intended output is an article in academic form, a
continuation of the original devoted to its §22. The owner's
post-quantum thread comes after that.

Nothing: §22 is exhausted as of 29 October 2026. The three items that
could not be implemented end in `REMAINING.md` as demonstrations with
numbers (smaller proof systems, certified-recipient lineage, the
PIPE-based boundary), with the conditions under which each reopens;
`REMAINING.md` §4 maps every item of §22 to where it ends. The project
is parked here.

## Completed directions, as planned

### 5. Succinct replay proofs (§22.2)

`REPLAY-PROOF.md`: replay written as a relation; the three questions
inside the paper's one (correctness of the state transition,
completeness of the envelope list against the Bitcoin block,
succinctness over history); the completeness result (Bitcoin commits to
nothing a proof could be made against short of every raw transaction,
so an indexer's enumeration stays trusted or full blocks are needed);
a batch circuit over an indexed nullifier tree and a root tree with
batched verification of the transfer proofs, measured; the recursion
frontier (one native level on a two-chain, measured; none beyond
without a cycle or folding); the indexer's proven blocks and the light
client that syncs from them, run on signet.

### 4. Publication privacy and wallet policy (§22.3)

The two surfaces the paper leaves to a deployment: what the network sees
of a carrier before it is in a block, and what a wallet's choices
(arity, change placement, anchor selection, timing, retries, fees) say
about it. Built as `PUBLICATION.md`: one proxy for everything outbound,
a separate publication route, a delay bounded by the window, the anchor
depth as a deployment policy, random change placement; and an explicit
list of what no option hides, the proxy as a vantage point among them.

### 3. Fee-unlock vault (§20.5, §22.3)

The paper's intended fee model: the user proves authorization to a fee
vault whose Bitcoin liquidity is reserved for that user's publication
costs, the vault releases the Bitcoin that funds the carrier, and
fee-paying capability is derived from metaprotocol state instead of the
user's transparent wallet cluster. The paper makes the vault PIPE-based
and asks for its own leakage analysis.

What gets built (`FEE-VAULT.md`): a development scaffold of that vault in
the same sense as the development boundary of `BOUNDARY.md`: the release
rule is enforced by the operator's code where a PIPE covenant would
enforce it. A reservation is a shielded note to the vault whose `rseed`
commits to an authorization key; a draw is a signed request naming the
envelope to publish and the most it may cost; the vault's rule is
deterministic (accepted deposit, valid signature, valid envelope, fee
within credit) and the ledger it keeps never releases more than was
deposited; a reclaim path returns unspent credit by the same rule. The
document states what the operator can and cannot do, what the covenant
would replace, and the leakage of the model next to the three existing
ones. Acceptance: the document reviewed, tests at every layer, a signet
run with a funded draw, a refused one and a reclaim in `RUNS.md`.

### 1. Atomic swap between a shielded note and transparent Bitcoin (§22.5)

The paper reserves a commitment slot `h_aux` in every note leaf, fixed to
`aux_null` in the base profile, as the binding point for extensions, and
names one motivating example: an atomic swap between a shielded note and
transparent Bitcoin, mediated by a liquidity provider and a standard
Bitcoin HTLC, where a hash-lock committed in `h_aux` and the HTLC share
one secret. HTLCs are the primitive Lightning is built on, so this is the
natural bridge story towards that audience.

What gets built:

* **An extension profile** (`SWAP.md`, normative for the extension, the
  base profile unchanged): a *locked note* whose `h_aux` commits to a
  hash-lock, a refund key and a refund height; an extension envelope kind
  carrying the per-output `h_aux` values the replay needs to derive the
  leaves (the base rules say the slot is not serialised, so the extension
  publishes it in its own format, as §22.5 prescribes); the extended
  transfer relation, which opens `h_aux` for every locked input and
  authorises the spend either by the owner with the preimage or by the
  refund key once the anchor height has passed the refund height.
* **The binding between the two hash contexts.** The circuit works in
  Poseidon over `Fr`; the HTLC works in SHA-256 (or HASH160) over bytes.
  The paper speaks of an *off-chain binding proof* that ties both to one
  preimage. The plan is a separate proof, exchanged between the parties
  and never published, that `h_aux` and the HTLC's hash-lock open to the
  same secret; the alternative, SHA-256 inside the transfer circuit, is
  measured and rejected or adopted on numbers (constraint count, proving
  time, key size), not by assumption.
* **The protocol run**: a liquidity-provider role (`sb lp`) and the two
  client flows, swap out (shielded → transparent) and swap in
  (transparent → shielded), with an HTLC on signet, timeouts on both
  sides, and the four endings exercised: both claim, both refund, and the
  two mixed cases that must be impossible.
* **Honest limits**: a locked note is visible as such (the extension kind
  and the published `h_aux` are public), so swaps form their own
  anonymity set; the liquidity provider learns what any swap counterparty
  learns; the extension needs its own trusted setup, rehearsed with the
  existing ceremony tooling.

Acceptance: the extension profile, tests at every layer (circuit blocks,
envelope codec, replay of both kinds in one deployment, wallet flows), a
signet run with a real HTLC in `RUNS.md`, and the auditor's pass.

### 2. Witness-carried envelopes (§22.1)

The base profile publishes the 700-byte envelope in one OP_RETURN output,
which costs full weight and depends on relay policy for large data
carriers. The paper names the alternative: envelope bytes in witness data
at about a quarter of the weight, through a two-transaction
prepay-and-reveal flow with its own standardness assumptions. Per the
paper this is a separate, non-interoperable profile, not an option.

What gets built: a second carrier rule in the indexer (the reveal
transaction's witness), the two-transaction publisher in the wallet with
the fee-funding models reused, a deployment on signet alongside the
OP_RETURN one, and measurements of weight, fees and confirmation
behaviour side by side, recorded in `RUNS.md`.

### Closed without implementation, with numbers (`REMAINING.md`, reviewed: `REVIEW-REMAINING.md`)

* Peg-in and peg-out through PIPEs v2 (§20.4, §22.3; ePrint 2026/186):
  the only WE instantiation its authors consider implementable needs
  ≈ 338 TiB per key release, has no implementation, rests on a
  heuristic security claim, and releases a key once (`REMAINING.md` §3).
* Proof systems with smaller proofs (Polymath, Pari; §22.1): 16–32
  bytes per envelope, ≤ 3.9 % of the carrier, against a new
  circuit-specific setup without a published ceremony, a different
  security model and, for Pari, no zero knowledge as published
  (`REMAINING.md` §1). The standard arity with padding is implemented
  (the profile's fixed 2-in-2-out).
* Opt-in certified-recipient lineage (§22.4, §D): needs unbounded
  recursion, which BLS12-381 does not have natively (no cycle; its
  2-chain partner BW6-767 has no FFT-friendly prover, measured), costs
  0.7–7.8 M constraints per step on the alternatives, multiplies every
  envelope's weight by 1.5–22, and presupposes the boundary above
  (`REMAINING.md` §2).

### A thread of the owner's own

A post-quantum variant of the transfer relation: what the profile would
have to change to prove the same statement with a hash-based proof system
(no pairing, no trusted setup), and what it would cost in proof size on
Bitcoin. A study first, code second.

## Not planned

An independent audit, a ceremony with independent participants, a
mainnet deployment. They stay in the documents as the conditions any
value deployment would have to meet.
