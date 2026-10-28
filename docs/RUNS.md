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
