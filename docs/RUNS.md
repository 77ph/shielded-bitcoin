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

**The route.** From the laptop, `ifconfig.me` answered `84.43.158.231`
directly and `2a01:4f8:c013:eb87::1` (the server's address) through the
forward. The sync (`sb sync`, two blocks of catch-up) and the scans
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
