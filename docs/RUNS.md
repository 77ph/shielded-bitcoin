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

## Public signet

Profile `signet-dev-1` (activation 328289) is ready; the live run waits for
signet coins on the funding address `tb1qxtws5pnknuvxqhp9w6uvvcq6uyc3frszw83xjz`
(public faucets were unreachable on 28 October 2026).
