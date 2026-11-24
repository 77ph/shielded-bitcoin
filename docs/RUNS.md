# Runs

Every end-to-end run of `sb` against a real `bitcoind`, with the transactions
it produced. Amounts in satoshi. Runs dated before the profile v0.2 change
used 668-byte envelopes (144-byte `ct_out`); those envelopes are not valid
under v0.2 (see PROFILE.md §13).

## Private signet, 28 October 2026 (profile `localsignet-dev`, activation 100)

Chain: `scripts/localsignet.sh` (signet with `signetchallenge=51`, Bitcoin
Core v30.2, blocks mined on demand). Not publicly explorable; reproducible.
Wallets alice, bob, operator; the dev vault is the operator's funding address.

| Step | Height | Carrier | Size |
|---|---|---|---|
| alice funded with 1 BTC from the miner | 131 | `4cb30aee3c49e9573b9718e145d0a5e10840ea1d0c6b762a97229863285bbc98` | — |
| mint 50 000 to alice (89-byte envelope, vault paid) | 132 | `66f1bf90f1d5a44656f8e71c295cd80f66f04245d6336230ca4c2ef904450075` | 242 vB |
| alice pays bob 20 000 shielded, change 30 000 (668-byte envelope, anchor 132) | 135 | `0e9264e8f26c0d9a5878de41ee3736a11f3411aab096b8c049cef462d2301dbb` | 793 vB |
| bob's first withdraw attempt: carrier built with no inputs (bug, fixed in the same commit), node rejected it | — | — | — |
| bob funded with 0.1 BTC for fees | 140 | `0a07e1f02e935d5fdb9826dfb50902a9486f5d250b2e1af74f2a1307d07a7a44` | — |
| bob withdraws 5 000 to `tb1q57j…`: shielded transfer to the operator + payout memo, change 15 000 (anchor 138) | 141 | `18cb6f1403181bf0c712db58044b883247e30e36780e85f9a3265d0da837142c` | 838 vB |
| operator pays 5 000 from the vault (`sb payouts`) | 142 | `951b7047abdcb56dbd062ae7d59ce0e5e67389ec7d76292f0f2678b4ad353ec4` | — |

End state: tree 5 leaves, 4 nullifiers, 3 accepted events, 0 rejections.
Wallet views after scanning: alice 30 000 (one spent, one change note), bob
15 000, operator 5 000 shielded; destination received 5 000 sat on L1; vault
holds 44 859 sat (50 000 deposit − 5 000 payout − 141 fee).

Timings on the laptop (16 threads): `sb send` ≈ 3.5 s including the insecure
setup regeneration (1.5 s) and proving (1.5 s); indexer verification per
envelope ≈ 4 ms.

## Private signet, 28 October 2026, profile v0.2 (700-byte envelopes)

Same chain and wallets as the first private run, replayed from scratch under
v0.2: the mint (89 bytes, unchanged format) is accepted, the two v0.1
transfers are rejected (`parse: bad length 668, expected 700`), so alice's
mint note is unspent again and bob's view is empty. Then:

| Step | Height | Carrier | Size |
|---|---|---|---|
| alice pays bob 20 000 shielded, change 30 000 (700-byte envelope, key-committing `ct_out`) | 143 | `ba3671e2b9dc51b7f64ac66cb86e6de8c2e1d1e50fb1ecf0b9cabae6ecf4a178` | 825 vB |
| bob withdraws 5 000 to `tb1q57j…`, change 15 000 | 146 | `73ea981a9a4f1a1692b95e234564808f16b485410ccca58947a08546dd60855c` | 870 vB |
| operator pays 5 000 from the vault | 147 | `ff4e2933e422bf4445139c10b4b5b8ad6508d12a89dde58aa71a1dc4786c6d93` | — |

End state: 3 accepted events, 2 rejections (the v0.1 envelopes), alice 30 000,
bob 15 000, operator 5 000; the destination received 5 000 sat.

## Public signet, 28 October 2026 (profile `signet-dev-1`, activation 328289, envelope format v0.1)

Block source and publisher: mempool.space Esplora. Funding: faucets
(bitcoinsignetfaucet.com, signet.dcorral.com, faucet.coinbin.org) to alice's
funding address; bob's fee coins sent from alice with `sb fund-send`.
Every transaction is public on [mempool.space/signet](https://mempool.space/signet).

| Step | Height | Carrier | Size |
|---|---|---|---|
| mint 5 000 to alice (89-byte envelope, vault paid) | 328292 | `ae97279ffdc91b8deba63c1f86585fc2a68afc9ec9f4867e2767236b89a9f855` | 241 vB, fee 242 |
| bob funded with 2 000 for fees | 328292 | `2d82a5f63eafa897723a6daed70e8842810816d24a0b68710f5ac8dabe81fb5a` | 141 vB |
| alice pays bob 2 000 shielded, change 3 000 (668-byte envelope, anchor 328292) | 328295 | `b494ea0e62abf716278ba39c3456246e8a8a9380c57c1edb8ddd994795f3542c` | 793 vB |
| bob withdraws 1 000 to `tb1qxtws…`: transfer to the operator + payout memo, change 1 000 (anchor 328295) | 328298 | `cc6132cbc1c00773097051ddab98bb4d5f1ccaba3d34d1ec10f15f29ce889bfc` | 838 vB |
| operator pays 1 000 from the vault (`sb payouts`) | 328300 | `57e792fe3371c6ff48a0e1ee5d5af2e6698f5f45fca79e89abd6fa46996206d2` | — |

End state at 328300: tree 5 leaves, 3 accepted events (tx 144 of 328292,
tx 38 of 328295, tx 126 of 328298), 0 rejections. Wallet views: alice 3 000,
bob 1 000, operator 1 000 shielded; the destination received 1 000 sat on L1.
Both 668-byte and 838-vB carriers were relayed by mempool.space's node with
default policy. One operational lesson: Esplora's tip height can run ahead of
its block-hash lookup for a few seconds, so the scripts replay until the
indexer actually reaches the required height before building a transfer.

## Public signet, 28 October 2026, profile v0.2 (deployment `signet-dev-2`, activation 328300)

Fresh deployment (new `const_salt`), same wallets. First 700-byte envelopes
on the public network.

| Step | Height | Carrier | Size |
|---|---|---|---|
| mint 1 000 to alice | 328301 | `56897dd859abf93f0807cac786c3689e8988a603e1e1480c7e2efecd99907aeb` | 242 vB |
| alice pays bob 400 shielded, change 600 (700-byte envelope, anchor 328301) | 328304 | `73eefe2b82cc744214ab3bdc8abbac237c1d627145c935b6328888e98c742d31` | 892 vB |
| bob withdraws 200 to `tb1qxtws…`, change 200 (anchor 328304) | 328308 | `131f8973769192e2ecd02a3e7d32e6cee9ee8a3c985f68866ae876af415e837a` | 839 vB |
| operator payout of 200 | — | refused: 200 sat is below the P2WPKH dust limit, mempool.space rejected the transaction (HTTP 400) | — |

All three envelopes were relayed and accepted (3 events, 0 rejections);
alice 600, bob 200, operator 200 shielded. The payout failed on a test-design
mistake, not on the protocol: the requested amount was dust. `sb withdraw`
now refuses amounts below 546 sat and `sb payouts` records such requests as
refused instead of retrying them; Esplora rejection texts are surfaced.


## Private signet, 28 October 2026: fee-funding models

Same chain and wallets, continued at height 147 (alice 30 000, bob 15 000,
operator 5 000 shielded). Two carriers that the sending wallet did **not**
pay for:

| Step | Height | Carrier | Size |
|---|---|---|---|
| alice pays bob 7 000 shielded, change 23 000, built with `--no-broadcast`; the unfunded template was funded, signed and sent by the node's own Bitcoin Core wallet (`fundrawtransaction` → `signrawtransactionwithwallet` → `sendrawtransaction`, taproot change) | 148 | `c1ae15857f6e7cfe86a7bc8b4d239da8750dc7bc85fbc4bc3cb66831396b2981` | 837 vB |
| bob pays alice 4 000 shielded, change 18 000, handed to `sb relay-serve` run from the operator wallet (`sb send --relay http://127.0.0.1:8787`); the relayer replayed to 148, checked the envelope against the next block, paid and broadcast it | 149 | `66ec8c2cb395e18a5cd3690bd7da49ac08e40a55087e95fc79dabca893e27735` | 825 vB |

End state at 149: 5 accepted events, alice 27 000, bob 18 000, operator
5 000. Neither carrier spends a coin of the wallet that built the transfer.
One lesson from the first attempt: a transaction with no inputs must be
framed the legacy way (version, empty input list, outputs, lock time); the
segwit framing puts a marker and flag where Core expects the input count
and `fundrawtransaction` answers `TX decode failed`. `sb` now writes the
template as Core's `createrawtransaction` does.

## Private signet, 28 October 2026: verified sync from an indexer

`sb serve` was run over the node (RPC, cookie auth) on the data directory
of the runs above, and an **empty** data directory replayed the deployment
from its API with `--chain light:http://127.0.0.1:8788|rpc-cookie:…`: 50
blocks (activation 100 to 149), 5 accepted events and 2 rejections, the
block hashes cross-checked against the node, each block's carriers checked
against its header through the partial merkle tree, and the indexer's
claimed `R[h]` compared with local replay for all 50 blocks. The resulting
state file is byte-identical to the full replay's. Block 149, for example,
is served as 2 transactions with carrier index 1 and a 71-byte partial
merkle tree instead of the full block. The 23 seconds it took were spent
by the server fetching full blocks from the node through an SSH tunnel,
not by the client.

## Private signet, 28 October 2026: parameters from a ceremony

`sb ceremony` end to end on the transfer circuit (domain `2^17`), two
participants per phase plus a beacon, on one laptop (16 threads), file to
file with full validation on every read:

| Step | Time | File |
|---|---|---|
| `phase1-new` | seconds | 37.7 MB |
| `phase1-contribute` (×2) | ≈ 50 s each, incl. reading and validating the input | 37.7 MB |
| `phase1-verify` (×2) | ≈ 50 s each (two files to validate, checks ≈ 4 s) | — |
| `phase2-new` (key derivation) | ≈ 8 min (four inverse FFTs over curve points) | 26.3 MB |
| `phase2-contribute` (×2), `phase2-beacon` | ≈ 30 s each, mostly validation | 26.3 MB |
| `phase2-verify` | ≈ 9 min (recomputes the initial key) | — |
| `export` | seconds | `transfer.pk` 52.6 MB, `transfer.vk` 1.2 KB |

A deployment `localsignet-ceremony` (activation 150) was then pinned to
the exported verifying key (`profile-new --ceremony-vk --ceremony-pk`):

| Step | Height | Carrier | Size |
|---|---|---|---|
| mint 5 000 to alice | 151 | `71a0d327b73fffd4248769d60d9f5cefeb25d87c8637cd044cc1259c64e57285` | 242 vB |
| alice pays herself 1 000, change 4 000, proven with the ceremony key (2.6 s wall, key loaded from the file) | 154 | `48f64826a8c6eea4eff2aa2a91f79f8b2579657dcd43a3ebcb181fdafa70c626` | 825 vB |

The older `localsignet-dev` deployment, replaying the same blocks with its
insecure-seed verifying key and its own vault, rejects both: `proof does
not verify` at 154 and `mint: vault output missing` at 151, as it must.
The keys of this run are **not** secure parameters: both participants were
the same machine and the beacon was a constant. The point was the
tooling, see `docs/CEREMONY.md`.

## Server, 28 October 2026: the static binary

`sb` built with the musl target on the laptop (12 MB, static-pie) runs on
the server (glibc 2.35, where the glibc build did not) and replayed the
private signet from the node there directly: 55 blocks, 5 accepted events,
4 rejections (the two v0.1 envelopes and the two carriers of the ceremony
deployment, which this deployment's key and vault refuse).

## Drill, 28 October 2026: a two-role ceremony with a real beacon

`scripts/ceremony.sh sb-data-drill mainnet:973580 "<entropy 1>" "<entropy 2>"`,
both roles played on one laptop (the owner's drill format: the commands
are those of a distributed ceremony, only the holder of the secrets is
the same). 26 minutes end to end, every transition verified before the
next role's turn, the full log with every digest in `sb-data-drill/LOG.md`
(local, not committed):

| Step | Result |
|---|---|
| phase 1, initial accumulator | digest `0863cd70…a32dee` |
| phase 1, role 1 | digest `f971d51a…d97b55`, transition valid |
| phase 1, role 2 | digest `0b4e77d7…e2a216`, transition valid |
| key derivation | from digest `0b4e77d7…e2a216` |
| phase 2, role 1 | contribution `35ad19df…50aae55` |
| phase 2, role 2 | contribution `3aa9f44d…5df4fa` |
| beacon | mainnet block 973580, hash `000000000000000000001b1ebd09f8cc443853440687acd474b0196c40681c98`, fetched after the last contribution; contribution `8967f221…b24a53` |
| phase 2 verification against phase 1 | valid, 3 contributions |
| export | `transfer.vk` sha256 `aa1303eb79d654343d8716a5af6c5acf9c0efdec370a91900b92cffd05900b03` |

What the drill checks is the procedure and the tooling: that each file
verifies against the previous one, that the beacon can be a public
value chosen by height before anyone contributed, and that the log is
enough for a third party to re-verify. What it does not give is secure
keys: one person held every secret.

## Drill, 28 October 2026: three roles, run by the owner

`scripts/ceremony.sh sb-data-drill-2 mainnet:973586 …` with three entropy
strings, started by the owner at 19:00 UTC with the beacon height chosen
one block ahead of the tip, finished 19:18 UTC:

| Step | Result |
|---|---|
| phase 1, roles 1–3 | digests `ca6f8a83…3767ea`, `a928ea37…cb0ca7`, `4432a1d9…e8bc35`, every transition valid |
| key derivation | initial key digest `07d8b041…a8543e` |
| phase 2, roles 1–3 | contributions `23c93b3c…67278a`, `b605147d…d8f138`, `89b11e87…0ecf07` |
| beacon | mainnet block 973586, hash `00000000000000000001a86209d92c442d35a81f4d5fd60e27df60801b80a82c`; contribution `f57ec38e…ead172` |
| phase 2 verification against phase 1 | valid, 4 contributions |
| export | `transfer.vk` sha256 `166d80bfd0261ae7a89cb2adc9dcc16bbcef87aaa8abf9dc9989fcca27f8b798` |

Same caveat as the first drill: one person held every secret, so the keys
prove the procedure, not anything else.

## Private signet, 29 October 2026: two atomic swaps with real HTLCs

`scripts/swap-drill.sh` on a fresh deployment `localsignet-swap`
(activation 155, swap extension with the insecure setup), both roles on
one laptop in separate data directories, Bitcoin Core 30.2 validating the
HTLC scripts, 9 minutes end to end. Swap envelopes are 764 bytes in
889 vB carriers.

**Swap one, completed** (7 000 sat shielded for 50 000 sat, `t_htlc` 171,
`t_refund` 183):

| Step | Height | Transaction |
|---|---|---|
| alice (X) locks 7 000 to lp under the hash-lock, change 13 000 | 160 | swap envelope `684f1b1a…` |
| lp (Y) checks the locked note (value and recomputed `h_aux`) and funds the P2WSH HTLC with 50 000 | 161 | `63c092b2…:0`, 153 vB |
| alice claims the HTLC with the preimage (witness `sig, s, 1, script`), 49 840 to her | 162 | `73865834…`, 139 vB |
| lp reads `s` from that spend and claims the note | 163 | swap envelope `45f88caf…` |
| alice's `swap refund` | — | refused: "the counterparty already claimed this note with the preimage" |

**Swap two, nobody claims** (5 000 for 40 000, `t_htlc` 169, `t_refund` 181):

| Step | Height | Transaction |
|---|---|---|
| alice locks 5 000 | 164 | swap envelope `a5b60827…` |
| lp funds the HTLC with 40 000 | 165 | `1b3820e3…:0` |
| alice's `swap refund` before the height | — | refused: "wait for height 183" |
| lp refunds the HTLC after `t_htlc` (`OP_CLTV`, lock time 169, non-final sequence), 39 840 back | 170 | `129ce506…`, 130 vB |
| alice refunds the note at anchor 182 ≥ `t_refund` | 185 | swap envelope `ffea1cfb…` |

End state: 5 accepted events, no rejections; alice 13 000 shielded (change
and the refunded 5 000), lp 7 000 shielded; on Bitcoin, alice received
49 840 sat for the first swap and lp got its 39 840 back from the second.
Every value-moving step of `docs/SWAP.md` §9 happened on chain and the
two mixed endings were refused by the tools and would be rejected by
replay (the refund of a claimed note) or by the node (an HTLC claim
without the preimage).

## Private signet, 29 October 2026: a witness-carrier deployment

Deployment `localsignet-wit` (`--carrier witness`, activation 187) on the
same node, Bitcoin Core 30.2 validating the taproot script-path spends.
Every envelope went out as a commit-and-reveal pair; the indexer read it
from the reveal's witness.

| Step | Heights (commit, reveal) | Pair | Size |
|---|---|---|---|
| mint 20 000 to alice (89-byte envelope, vault paid by the reveal) | 187 | `b0aa7a9b…` + `6e05758b…` | 153 + 171 = 324 vB |
| alice pays bob 7 000 shielded, change 13 000 (700-byte envelope) | 190 | `9743ed4a…` + `451238be…` | 153 + 294 = 447 vB |
| bob withdraws 2 000 to alice's funding address (envelope + payout memo in an OP_RETURN output of the reveal) | 198 | `4f1485ee…` + `7e44f345…` | 153 + 339 = 492 vB |
| operator pays 2 000 (`sb payouts`) | 199 | `8707c353…` | — |

3 accepted events, 0 rejections; alice 13 000, bob 5 000 shielded. The
same envelopes cost 242 / 825–892 / 839–870 vB in the OP_RETURN runs
above. One operational note: the first withdraw attempt failed for want
of fee coins in bob's wallet and left its input locked, as designed;
`sb unlock` released it before the second attempt.

## Private signet, 29 October 2026: the fee vault, both endings and every refusal

`scripts/fee-vault-drill.sh` on the `localsignet-dev` deployment (OP_RETURN
carrier, `K_min` 1), the client and the vault on one laptop in separate
data directories, Bitcoin Core 30.2 validating the carriers, 8 minutes end
to end (`sb-data-fv/LOG.md`, the vault's log and ledger beside it). The
vault ran at 1 sat/vB with a 10-sat margin; `/info` quoted
`fee_estimate: {transfer: 833, withdraw: 890}`.

**Deposit.** Alice minted 20 000 sat, then deposited 2 500 sat
(`032ba25a…`, an 825-vB carrier indistinguishable from any transfer).
In the mempool and one block deep the vault reported
`deposited 0 (unsettled 2500), credit 0`; two blocks later
`deposited 2500, credit 2500`. Before the deposit the client refused a
`--fee-vault` send without asking (`no deposit at …`).

**Draws.** A send with `--max-fee 1` was refused by the vault
(`fee 833 exceeds max_fee 1`), nothing charged. A 1 000-sat transfer to
Bob was published by the vault in `d4f4bc43…` for **833 sat** (823 vB at
1 sat/vB plus the margin), credit left 1 667; Bob's balance 1 000 after
three blocks. A 2 000-sat withdraw to Bob's Bitcoin address, its payout
memo signed into the draw, was published in `d79f7f09…` for **878 sat**
(a 34-byte P2WPKH memo, 12 bytes under the estimate's P2TR assumption),
credit left 789.

**Restart with a pending draw (I3).** The vault was stopped with the
withdraw still in the mempool and started again on another port. It
settled nothing (the draw was not yet accepted), re-broadcast the raw
carrier (Core already had it), rebuilt its pending set, and answered the
client's `accounts --vault <new url>` with the same credit 789: the
account is identified by the vault's deposit address, not its URL. After
three blocks the withdraw was accepted and the ledger entry settled.

**Refusals on the rule.** With 789 sat of credit, a transfer posted with
`--max-fee 5000` was refused `insufficient credit: 789, need 833`; a
reclaim was refused `credit 789 does not cover the reclaim fee 833`.
Nothing was charged for either.

**The operator's backing guard (I2).** With the vault stopped,
`fee-vault status` showed received 2 500, released 1 711, outstanding
789, shielded balance 2 500, `backing: ok`. A 2 400-sat send from the
vault's wallet was refused (`leaves 100 sat against 789 sat of
outstanding client credit (under-backed by 689 sat)`); a 100-sat send was
built without a question.

**Top-up and reclaim.** A 2 000-sat deposit under the same key
(`--index 0`, `0dc6fa29…`) brought the credit to 2 789. The reclaim paid
**1 956 sat** to a fresh address of Alice's in `d2de8d48…` (credit 2 789
less the 833-sat fee of the returning transfer), accepted three blocks
later; Alice's balance rose by exactly that, the account's credit went to
0. The vault's final state: received 4 500, released 1 711, reclaimed
2 789, earned 2 544, outstanding 0, shielded balance 2 544, `backing: ok`.
The ledger holds the two draws and the reclaim, all settled, raw
transactions and nullifiers dropped.

What the run shows: the rule released exactly the fees of the carriers
it published plus the margin, never more than the credit; the one draw a
restart found pending was neither lost nor charged twice; the credit
that remained was returned by the same key; and the operator's wallet
refused to spend below what it still owed.

## Public signet, 29 October 2026: a transfer published through a proxy, with a delay

Deployment `signet-dev-2` (anchor depth 3, the default), mempool.space
Esplora as the chain source, every connection through an SSH dynamic
forward to the project's Hetzner server (`ssh -D 127.0.0.1:1080`), given
to `sb` as `--proxy socks5://127.0.0.1:1080` (`docs/PUBLICATION.md` §2.1).

**The route.** From the laptop, `ifconfig.me` answered the laptop's own
public address directly and the server's address through the forward
(two different addresses on two different networks; neither is recorded
here). The sync (`sb sync`, two blocks of catch-up) and the scans
of both wallets ran through the same forward; nothing left the laptop
directly.

**The transfer.** Alice paid Bob 300 sat (`sb --proxy … --delay 60-180
send`): proving at anchor 328 524 (tip 328 526 at the time, depth 3
before the next block),
then `holding the carrier for 156 s before publishing (--delay 60-180)`,
then the broadcast of `6d062107…` (825 vB, 1 sat/vB) at 15:00:25 UTC.
The anchor was re-checked against the tip when the hold ended (window
`W` 100). The carrier was in block **328 527**, 43 seconds after the
broadcast; replay accepted it as the first transfer of that block seen by
this deployment (`accepted: 1`). Anchor age at acceptance: 3 blocks, the
deployment's depth plus nothing, because no block came in during the
156-second hold.

Bob's balance 200 → 500 sat, Alice's 600 → 300. What mempool.space saw of
the submission was the server's address; what the chain shows is an
825-vB carrier with anchor age 3, like every carrier of this deployment.

## Public signet, 29 October 2026: replay proofs for the whole deployment history, a light client synced from them

Deployment `signet-dev-2` (activation 328 300), its profile extended with
a batch circuit of 4 slots (`--batch-insecure 4`; every other field of
the profile byte-identical). The indexer's state (245 blocks replayed,
4 accepted envelopes: the mint at 328 301, transfers at 328 304,
328 308 and 328 527) was proven on the laptop, served locally, and
synced by a light client in a fresh data directory holding only the two
wallet files (`docs/REPLAY-PROOF.md` §4.5).

**Proving** (`sb prove-batches`, release build): the insecure batch setup
for 4 slots in about 36 s, then one fragment per block with carriers:
43.3 s, 31.2 s, 42.7 s and 53.6 s; the 241 empty blocks written without
a proof in under 2 s each (the builder rebuilds the trees before every
block from the history, so the time grows with it). 4 min 39 s wall
clock for the 245 blocks, 4.6 GB of memory at peak. The proven blocks
weigh **110 KB** together (hex JSON).

**The light client** (`--chain proof:http://127.0.0.1:…`): 245 blocks in
23.8 s, `accepted: 4`, the state digest chain verified end to end, the
four envelope proofs batch-verified under the transfer key; a second
sync found nothing new. Both wallets report the same balances as the
full indexer (Bob 500 sat over 3 notes, Alice 300 sat), and the light
state file keeps no envelope bytes and no nullifier tree. The 3.6 GB
peak is the insecure batch setup run to derive the verifying key: a
deployment with a ceremony ships the key as a file.

**What the client downloaded instead of the chain:** 110 KB of proven
blocks against **35.2 MB** of full blocks for the same 245 heights
(about 320 times less), or against the 2 189 bytes of envelopes plus
their carriers' partial Merkle trees that the `light:` verified sync of
`README.md` fetches, with the difference that here the client also
skipped every nullifier-set check and never held the set. What it still
trusts the indexer for is the enumeration of carriers (§3 of the design):
that these four were all of them.


## Public signet, 1 November 2026: variant A on the witness carrier (deployment `signet-a-1`, activation 328966)

The first run of a family-A deployment (`VARIANT-A.md`, `PROFILE-A.md`):
Halo 2 transfer proofs of 4 416 bytes with no trusted setup, 4 924-byte
envelopes in the witness of a reveal transaction. Profile
`signet-a-1` (profile a-0.1, `transfer_vk_id` as `TEST_VECTORS-A.md`
pinned it then; the file is in git history at f3aa38f, since the profile
moved to a-0.2 after the review's parity finding of 3 November), mempool.space Esplora as the chain
source, 1 sat/vB, anchor depth 3. The development vault is alice's own
funding script, as in the swap drill, so the mint's vault payment
returned to her fee coins; those came from the paper deployment's
operator wallet (4 150 sat in `54bef760…`, block 328 966: the family's
funding keys are its own, so a paper-profile wallet could only fund it
transparently). On the laptop a `send` took 11.4–11.7 s and 535 MB: the
proving key is derived from the deterministic parameters at every call
(about 8 s, no key file), the proof itself about 2 s.

| Step | Heights (commit, reveal) | Pair | Size |
|---|---|---|---|
| mint 1 000 to alice (89-byte envelope, vault paid by the reveal) | 328969 | `671d5399…` + `c3981a2f…` | 153 + 171 = 324 vB |
| alice pays bob 400 shielded, change 600 (4 924-byte envelope, anchor 328970) | 328973 | `6ad5c4f6…` + `2a70ba59…` | 221 + 1 356 = 1 577 vB |
| alice pays the operator 200 shielded, change 400 (anchor 328974) | 328977 | `fda76086…` + `a8a3921f…` | 258 + 1 356 = 1 614 vB |

3 accepted events, 0 rejections; alice 400, bob 400, operator 200
shielded, each wallet scanning its notes from the chain. The reveal of a
transfer carries 5 087 witness bytes (the envelope in ten pushes, the
signature, the script, the control block) for 1 356 vB, against 1 350
computed in `VARIANT-A.md` §4.3. The commits weighed 221 and 258 vB
instead of the 153 vB of a single-input commit because alice's fee
wallet spent two and then three coins (the second commit had no change
output: the remainder was below the dust limit and went to the fee, 335
sat for 258 vB). With a single-input commit the pair is 1 509 vB, 3.4
times the paper profile's 447 vB on the same carrier (825 vB on its
OP_RETURN carrier). The first transfer was in a block 9 minutes after
its broadcast, the second in the next block, 2 minutes after. The anchor policy was exercised as
designed: a `send` attempted right after the mint's block was refused
("no input is confirmed under the selected anchor") with no input left
locked, and succeeded three blocks later.

## Private signet, 10–11 November 2026: the accumulated replay proof's chain over ten blocks, decided from one step

The first run of `REPLAY-PROOF-A.md` §3.8 outside its tests: a family-A
deployment on the private signet of `scripts/localsignet.sh`
(`replay-drill`, profile a-0.3, witness carrier, activation 251), its
history proven as one chain of steps by `sb a replay-prove`, and the
chain accepted by a client holding only the keys and the genesis digest
(`sb a replay-decide --latest`). The drill is `scripts/replay-chain-drill.sh`
in three phases; its log stays with the deployment's data.

**Events** (the host, beside the node, 3 minutes): the operator's
funding script as the development vault; alice funded with 0.01 sBTC in
block 251; a mint of 5 000 in block 252; alice pays bob 2 000 (block
255) and the operator 1 000 (block 258), each a commit-and-reveal pair
of 1 509 vB; three blocks mined after each so the anchor is deep
enough; 3 accepted events, 0 rejections; blocks 251–260 to prove — ten
steps, seven of them for blocks with no event (a step is a step: the
relation appends a root per block).

**Prove.** Started on the host with the static binary, niced on four
cores: keys 996 s, step 1 (block 251, no slot) 1 038 s, step 2 (the
mint) 948 s — then stopped: the prover held 21 GB and the box's swap
was full, which is not a load the server's other projects should carry;
the chain's state (92 546 bytes) and the two steps stayed on disk.
Resumed inside the container `sb-s1` (4 cores, a 24 GB limit; the node
reached across the docker bridge through a host firewall rule for that
one port): keys **877 s, the same key-set id** as the host's — the keys
are a function of the circuits' structure, so two bootstraps on two
machines agree — the state taken up at step 2 ("2 steps, next block
253"), steps 3–10 in 453, 428, 335, 325, 309, 322, 314, 327 s, each
**70 292 bytes** on the wire (four slots), each decided by the prover's
own sequential check in 2–7 s, then "block 261 is not on the chain
yet"; the container's memory peaked at 17.3 GB; the phase 3 738 s wall
with the keys.

**Decide.** `replay-decide --latest`: keys 959 s (the same id), then
**step 10 alone, from the genesis: block 260 accepted in 2.36 s**, the
digest after it the one the prover reported. That is the light client of
`REPLAY-PROOF-A.md` §3.5: one step of 70 292 bytes and two seconds for a
history of any length, given the keys and the deployment's genesis
digest. The sequential `replay-decide` that followed found the client's
state already at step 10 and decided nothing more — the sequential path
was exercised by the prover's self-check of every step, not by this
command; a separate client directory would show it.

What the run says beyond the study's test: the chain runs block by block
from a live node through the CLI, survives a stop and a change of
machine on its saved state, and its keys need no file to agree across
runs; the cost of key generation at every start (15–17 minutes) and the
step per empty block (five minutes of proving for nothing) are the two
figures to bring down next.

**The same blocks again, with steps over block ranges** (`REPLAY-PROOF-A.md`
§3.9, built the same day; the container, 11 November). Keys with room
for eight empty blocks a step: 956 s (a new key-set id — the relation
changed). The ten blocks became **four steps**: 251–252 (one empty
block, then the mint), 253–255 (two, then the first transfer), 256–258
(two, then the second), 259–260 (one, then the last block, empty, at
the tip), proved in 359, 351, 347 and 342 s, **70 296 bytes** each (the
step's first block on the wire); the digest after each range equals the
first run's after the same block, and the final digest is the same to
the bit — the state transition does not depend on where the steps are
cut. The prove phase took 2 391 s wall with the keys, against 3 738 s
for eight of the ten blocks before. `replay-decide --latest`: keys
977 s, then **step 4 alone, from the genesis: block 260 accepted in
2.27 s**. A quiet day of a test network (144 blocks) is now 16 steps,
not 144; with the measured headroom the relation can take twelve empty
blocks a step at four slots.

## Public signet, 11–17 November 2026: the replay chain following the network live (deployment `signet-a-2`, activation 330433)

The chain of `REPLAY-PROOF-A.md` §3.8–3.9 run as a follower of public
signet, in the server container, by `sb a replay-prove --follow`
(blocks from mempool.space's Esplora): a family-A deployment
`signet-a-2` (profile a-0.3, witness carrier, the development vault the
operator's funding script), its wallets made on the laptop, no shielded
event yet — the funding of the first wallet awaited — so what is proven
is the state standing still, block after block: the relation's root
appends and the digests, which is what a light client would check for
a quiet period too.

**The first night** (started 20:05 UTC, keys generated in 1 286 s and
written, 1.1 GB): one step per block at the tip, as the runner cut a
step whenever it reached the tip — 59 steps for blocks 330433–330500 by
09:30 UTC, each 70 296 bytes, proved in 370–540 s on a host still loaded
after its reboot, the prover one or two blocks behind the tip
throughout, no error. **The restart** (10:27 UTC, with `--settle 1800`):
the keys read from disk instead of generated — 660 s, of which the four
key files 122 s and the rest `Params::new` twice, hence the parameters'
files now written next to the keys — and the chain taken up at step 60,
block 330502; from there one step per half hour covering the blocks that
arrived meanwhile.

**The weekend** (12–14 November): 72 steps (61–132) for blocks
330502–330796, a step every half hour or every eight quiet blocks,
whichever came first (that binary's "proved in" still counted the
settle wait, hence its 2 100–2 300 s against the 350–400 s of proving;
step 62, cut at once by an event, 346 s). The event was the
deployment's first: **alice's mint of 3 000 at block 330511**, in step
62, the wallets' funding having arrived from the owner. **The stop**
(14 November, 10:23 UTC): for a moment Esplora answered height 330796
with another hash; the indexer rolled back to 330795 in memory and the
runner refused to go on below the proven chain. The chain kept the
proven block (its hash stands at that height on the 17th), and the
rollback never reached the disk, so nothing was lost; the account is
in `REPLAY-PROOF-A.md` §3.8. **The restart** (17 November, 09:18 UTC,
the binary of 71204ae with `--confirm 3 --settle 1800`): the keys read
in 632 s (the parameters made and written this time, 16 MB each; the
process at 22.0 GB during the read, 12.6 GB proving), the chain taken
up at step 133 — blocks 330797–330805, nine blocks a step now that
nothing waits at the tip, proved in 456 s — and the follower catching
up some 460 blocks at about nine blocks every eight minutes.

**The wallet side.** Replaying the deployment's 800 blocks on the
laptop in one go met the public Esploras' rate limit (`429`) at
mempool.space and at blockstream.info alike, every retry starting over
because the JSON store wrote only at the end of a sync. The HTTP
client now paces its requests to a remote host (250 ms apart,
`SB_HTTP_PACE_MS`; loopback never paced) and waits a `429` out as the
server's `Retry-After` asks, and a replay saves its progress every 32
blocks.

**The transfers, 17 November.** The first attempt paid for a lesson.
An envelope built at 10:44 UTC against anchor 330974 was published at
12:01 UTC, 295 blocks later, and the chain rejected it in block 331269
(tx 183): `anchor 330974 outside the window for block 331269`, `W =
100`. The carrier had been paid — 1 509 vB for an envelope no indexer
accepts — and the note's lock was released with `sb unlock`. Since the same hour
`publish` in both families refuses an outbox entry whose anchor is
outside the window at the tip before any carrier is paid for
(`PUBLICATION.md` §2.3). The fresh send at 13:22 UTC (alice to bob
1 200, anchor 331274) had its commit `d175f842…` reach the mempool and
its reveal refused as `bad-txns-inputs-missingorspent`, most likely
because the Esplora instance asked to broadcast the reveal had not yet
seen the commit (`WITNESS-CARRIER.md` §7). The reveal is now retried five times three
seconds apart, and `publish --reveal`, added to the A family's
`publish` for it, spends a commit the network has seen: at 13:41 UTC it
broadcast the reveal `4fedea5d…` (1 356 vB) over the commit's output;
the commit confirmed in block 331277, the carrier in 331283 (tx 134),
where the deployment's indexer accepted the transfer with its leaves at
position 1 — note tree of three leaves, two nullifiers, two accepted
events and the one rejected envelope. The operator's 800 (anchor
331284) at 14:42 UTC went through the retry on the real network: the
commit `168cf9e8…` (153 vB), the first reveal refused for the same
reason, the second accepted — the reveal `eb427c98…` (1 356 vB), 1 509
vB for the pair; commit and reveal confirmed together in block 331287
(the carrier tx 496), where the indexer accepted the transfer with its
leaves at position 3. After the two transfers (`sb scan` at block
331288): the note tree holds five leaves and four nullifiers, three
accepted events and the one rejected envelope; alice has 1 000 sat in
one note (position 3, the change of the second transfer; her 3 000
mint and 1 800 change spent), bob 1 200 (position 1). The carriers'
fees came from the funding wallet, not from the notes. The follower
stood at step 183 (blocks to 331255) while the transfers confirmed and
reached them an hour later: step 187 is block 331283 alone (a range
closes at a block with events), one slot, 70 296 bytes, proved in
374 s; step 188 is blocks 331284–331287, three without events and the
operator's transfer in the fourth, one slot, the same 70 296 bytes,
proved in 400 s after a 240 s wait for the third confirmation.

**The light client, for real** (17 November, 15:45 UTC). A fresh
directory holding the key set (1.1 GB on disk, linked from the
follower's) and the one file `step-000188-331287.bin` of 70 296 bytes
— no indexer state, no earlier step, no chain source consulted. `sb
replay-decide --latest` under the family-A profile read the keys in
185 s (the parameter and key files 128 s, the transfer key and padding
48 s, the shapes 7 s, the dummy step 2.5 s; host load about 12) and
accepted step 188 alone from the deployment's genesis digest in
**2.46 s**: block 331287, and with it the deployment's whole history —
855 blocks since activation, three shielded events — attested by
one step. 3 min 22 s of wall clock and 11.5 GB resident in all, the key
set's cosets being the memory. The follower was stopped for those four
minutes and restarted from its state on disk (the 24 GB container
holds one key set comfortably, not two while a step is proven).

## Public signet, 17–24 November 2026: the follower's second week, the light client with the decider's own keys (deployment `signet-a-2`)

**The week.** The follower ran on from step 188 (17 November, 15:45
UTC) to step 427 (24 November, 10:31 UTC: blocks 332270–332274, five
blocks without events, 0 slots, 70 296 bytes, proved in 596.9 s after
the 1 800 s settle wait, decided in 7.92 s) — 239 steps, 33 to 37 a day,
one every 40 minutes or so: the settle wait and then ten minutes of
proving, each step four or five signet blocks. At step 427 the chain
stands at block 332274, 1 842 blocks since activation, attested by the
newest step alone. Its log for 19–24 November (steps 257–427) was lost
at the stop of 24 November, by a mistake of the operator's and worth
recording: the runner script of 19 November was still alive, blocked in
its last line (the follower run in the foreground, its output to
`follow.log`), when the 24 November runner was uploaded over the same
file name; a shell reads a script by offset, so when the new runner
killed the follower the old shell resumed reading the new file mid-line
— `follow --poll … > follow.log` — and the redirect truncated the log
before "follow: not found" was written into it. The step files are all
there (427, their dates the cadence above); the last line survives in
the chain test's log; the figures lost are the week's per-step timings,
which the earlier weeks recorded. Runner scripts get new names from now
on.

**The light client with the decider's own keys** (24 November). The 17
November run above read the key set the prover reads — the two proving
keys and their cosets, 1.1 GB on disk, 11.5 GB resident, 185 s — which
a client needs none of. `ChainKeys::read_for_decider`
(`REPLAY-PROOF-A.md` §3.8, v0.13) reads the decider's part: the two
circuits' parameters (16 MB each), their verifying keys (0.95 and
1.28 MB) and the transfer circuit's parameters and verifying key
(1.1 MB), 35 MB in all, and rebuilds the shapes; `sb replay-decide`
uses it and never generates keys. Run on the laptop as the client of 17
November: a fresh directory with the server's five key files (copied,
checksums compared) and the one file `step-000427-332274.bin` of
70 296 bytes — no proving key, no indexer state, no earlier step, no
chain source consulted — the laptop under another project's load (load
average 13). The keys read in **21.5 s** (the parameters and verifying
keys 10.9 s; the transfer key 7.2 s, made and written, as the server's
set predates the `t.params`/`t.vk` files; the shapes 3.3 s) and step 427
accepted from the deployment's genesis digest in **1.04 s** — block
332274 and the 1 842 blocks before it — 30.4 s of wall clock and
**243 MB resident**. A second run, the transfer key now from its files:
the keys in 12.5 s (8.5 + 0.4 + 3.5), the step in 1.16 s, 22.0 s in all,
the same 243 MB. The digest accepted,
`b74f45ad8a0a9e9792a35459951995cb12e773bc8dc873ed035a8ae4a2245c18`, is
the one the follower holds as its state after step 427 (its restart
line of 11:25 UTC: 427 steps, next block 332275, the same digest).

**The same on the server, beside the live follower** (24 November,
11:36 and 11:41 UTC, the follower idle between steps at 10–11 GB, host
load 10–16). A fresh client directory with the follower's key set linked
and the one step file, no stop of the follower. A first attempt copied
the follower's own binary and so measured the prover's read beside the
follower — the comparison figure: the keys in 282 s and 227 s (the
parameter and key files 217 s and 165 s, the transfer key and padding
52 s and 49 s, the shapes 9.7 s and 9.2 s, step 0 3.3 s), step 427
decided from the genesis in 2.91 s and 3.43 s, 5 min 3 s and 4 min 8 s
of wall clock, the same digest. **The decider's own read**, with the
binary of the day (11:56 and 11:57 UTC; the follower had meanwhile
proven step 428 — blocks 332275–332283, eight without events, 572.8 s
after a 900 s wait — and stood idle at 10.3 GB; host load 10–13; the
build of the binary was aborted once by the guard when the follower
began proving, and made in the next idle window): the keys read in
**29.9 s** (the parameters and verifying keys 8.1 s; the transfer key
13.7 s, made and written into the follower's key directory, 1 048 644
and 60 608 bytes; the shapes 8.1 s) and step 428 accepted from the
genesis in **3.18 s**, 44.1 s of wall clock, **242.5 MB resident**; the
second run, the transfer key from its files, 17.9 s (9.7 + 0.6 + 7.6)
and 2.86 s, 34.4 s in all, the same 242.5 MB. The digest accepted is the
follower's for step 428. Against the prover's read in the same place
minutes earlier — 227–282 s, 2.91–3.43 s to decide, and 11.5 GB on 17
November — the decider's read is eight to fifteen times shorter and a
forty-seventh of the memory, while the deciding itself is the same work
on either read path: the laptop's 1.0–1.2 s against the server's
2.9–3.4 s is the machine and its load, not the keys.

**The chain test with nine negatives** (24 November, the server
container, host load 12–15). The real-key chain test of
`REPLAY-PROOF-A.md` §3.8, run with the follower stopped between steps
(the stop above), now carries beside the mislabelled step the four
misshapen steps of 21 November (an instance column too short, too long,
a slot too many, a position past the end) and the five proof-tampered
steps of the same day (a byte flipped in either proof, either proof
zeroed, both emptied) — the inputs the three guards of §3.4 answer for.
It passed: keys generated in 1 087.2 s; step 1 (two mints, the base)
426.4 s and 69 784 bytes; the keys written, 1 111 762 397 bytes, in
2.3 s and read back in 214.8 s (the parameters and key files 149.2 s,
the transfer key and padding 52.1 s, the shapes 9.7 s, step 0 3.8 s);
step 2 (two transfers, a mint) 366.4 s; the rogue base step at block
1001 308.8 s to prove and refused by both deciders; step 3 (one
transfer, padded) 382.8 s; decided in sequence in 2.47 s, alone in
2.42 s; every misshapen and tampered step refused with an error, none
with a panic (the test asserts them without printing; the pass is the
record); step 3 again after a reorganisation (a mint) 324.2 s. 53 min
59 s of wall clock, 22.77 GB resident at the peak. The run was at the
fuzzing commit of 21 November, before the decider's own key read.

The same test ran again that afternoon at the day's last commit, with
that read's assertions beside the nine negatives — both sets read from
one directory: the same id, shapes and genesis digest; the decider's set
deciding step 3 as the full one does and reading its state; refusing to
prove — the follower stopped after step 431 (the test binary built
beside it while it idled: the memory guard of the morning's measurement
aborted the build twice as a step began, the third attempt took 262 s).
It passed: keys generated in 1 225.4 s; step 1 315.9 s; the keys written
in 2.2 s and read back by the prover's read in 164.1 s (the parameters
and key files 121.9 s, the transfer key and padding 30.5 s, the shapes
9.1 s, step 0 2.6 s) and by the decider's read, from the same directory
in the same process, in **18.0 s** (the parameters and verifying keys
10.2 s, the transfer key 0.6 s, the shapes 7.2 s); step 2 368.0 s; the
rogue base step 345.6 s; step 3 312.6 s, decided in 2.91 s and alone in
2.98 s; step 3 after the reorganisation 347.6 s. 53 min 58 s of wall
clock, 22.75 GB resident at the peak — the same hour and the same peak
as the morning's run, the decider's read costing the test nothing it
could measure. The follower was restarted at 15:01 UTC, read its keys in
190 s and went on from step 431 (its log of the afternoon kept as
`follow-run8.log`, 58 lines).

## Public signet, 24 November 2026: the circuits carry the keys — the chain test under them, the chain restarted from the genesis (deployment `signet-a-2`)

**What changed** (`REPLAY-PROOF-A.md` v0.14, the commit of the
evening). Each chain circuit hashes the key points it verifies the
other circuit's proof under and ends its instance with that hash and
the other circuit's, copied from the verified proof's instance; the
hashes are constrained equal from step to step from the dummy step 0
on, and the decider checks them beside the key points of the step it
holds (`key_tail`, §3.8). The batch relation shows a slot's inverse
both ways and hands its active bits to the slot binding, which no
longer witnesses its own. A circuit change is a new key set, so the
chain restarts from the genesis (activation 330433) in a fresh data
directory with the same profile and arguments; the old follower's
directory, log and binary are left as they are.

**The chain test under the new circuits** (the server container, host
load 18–20 at the start). The test binary and the CLI were built beside
the live follower under the memory guard of the morning (a build only
while the follower is between steps, aborted the moment it begins
proving): the guard aborted the build twice, after 755 s and 269 s, as
steps began; the third attempt took 318 s. The follower was stopped at
17:51 UTC after step 435 (blocks 332319–332324, five without events,
no slots, 1 059.5 s to prove beside the build after a 1 800 s wait,
decided in 7.29 s) — 435 steps over blocks 330433–332324 under the key
set of 11 November; its log of the afternoon, steps 432–435, kept as
`follow-run9.log`. The test passed: keys generated in **1 239.0 s**;
**`T_p` 225 836 rows at k = 18**, 2 477 more than before the tail (of
262 144); step 1 (two mints, the base) 367.8 s and **70 040 bytes** on
the wire, 256 more than before — the four tail values of each instance;
the base step over a dummy step 0 carrying another hash of `T_q`'s key
(the test's new negative) 355.3 s to prove and refused by both
deciders; the saved chain state 92 802 bytes (92 546 before); the keys
written, 1 112 871 649 bytes — the same count as before, the files
sized by `k` and the columns, not the rows — in 2.5 s and read back by
the prover's read in 179.5 s (the parameters and key files 133.9 s, the
transfer key and padding 35.6 s, the shapes 7.5 s, step 0 2.5 s) and by
the decider's read in **17.0 s** (9.1 + 0.5 + 7.4), the same id, shapes
and genesis digest; step 2 (two transfers, a mint) 323.1 s; the rogue
base step at block 1001 310.8 s, refused; step 3 (one transfer, padded)
315.4 s, decided in sequence in **2.59 s** and alone in **2.32 s**; the
nine negatives of the morning refused without a panic; step 3 again
after a reorganisation (a mint) 343.0 s. 1 h 0 min 58 s of wall clock,
**22.85 GB** resident at the peak (22.75–22.77 GB in the morning's and
the afternoon's runs).

**The chain restarted from the genesis** (18:52 UTC, the server
container: the binary of the evening's commit in a fresh data
directory, the same profile, chain source and arguments). The new
follower generated its key set in **1 069 s** (id
`476461074b30810a4de3bf3a8603af6bbf2bc1eefb1b5d47f9a1ba812614f6ad`,
written in 2 s: the proving keys 647 and 429 MB, the parameters 16 MB
each, the verifying keys 1.28 and 0.95 MB, the transfer key's files
1.1 MB) and started at block 330433 from the deployment's genesis digest
`87f0f4604b52d600a2c6e37ab21ecb86863aefbf045c046e4d9f69f5f20fb212`; its
step 1, blocks 330433–330441 (eight without events, no slots), proved
in **359.5 s** with no wait, **70 552 bytes** on the wire (70 296 under
the key set of 11 November: the four tail values of each instance),
decided in 3.25 s; at 19:18 UTC it was proving step 2 at 17.9 GB
resident. It has the 1 892 blocks to 332324 to redo, nine a step where
none has events — about 210 steps, a day at six minutes a step — before
it is at the network's head again and follows block by block. The
first chain's step files do not decide under the new keys (another key
set is another id) and stay in the old directory with its log and
binary.
