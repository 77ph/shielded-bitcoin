//! The paper family's indexer (`sb-indexer`) over generated chains: blocks
//! of mints, the one valid transfer, its flipped copies, foreign and raw
//! candidates, memos, two carriers in one transaction; reorganisations of
//! any depth down to the activation; syncs. Never panics; after every sync
//! the state is the one a fresh indexer reaches by replaying the chain
//! from scratch (rollback equals fresh replay), its commitments are in
//! step, and what it accepted is what the chain carries.
#![no_main]
use std::sync::LazyLock;

use bitcoin::{Amount, ScriptBuf, TxOut};
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sb_circuit::{TransferParams, TransferVerifier, vk_sha256};
use sb_common::carrier::{MEMO_MAGIC, carrier_output};
use sb_common::chain::mock::{MockChain, carrier_tx, carrier_tx_with_memo, mint_tx};
use sb_core::address::{Network, PaymentAddress};
use sb_core::envelope::{CANDIDATE_PREFIX, MintEnvelope};
use sb_core::keys::{Seed, WalletKeys};
use sb_core::note::NotePlaintext;
use sb_fuzz::{Op, Script, Tx, flipped};
use sb_indexer::deployment::DevBoundary;
use sb_indexer::{Deployment, Indexer, ReplayState, Setup};
use sb_primitives::Fr;
use sb_wallet::{Recipient, build_transfer};

const ACT: u32 = 50;

struct Fixture {
    params: TransferParams,
    deployment: Deployment,
    vault: ScriptBuf,
    addresses: Vec<PaymentAddress>,
    /// Blocks ACT and ACT+1 every chain starts with.
    prologue: Vec<Vec<bitcoin::Transaction>>,
    transfer: Vec<u8>,
    mint: Vec<u8>,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let vault = ScriptBuf::from_bytes(vec![0x51]);
    let deployment = Deployment {
        profile: sb_core::PROFILE_VERSION.into(),
        name: "fuzz".into(),
        network: Network::Regtest,
        activation_height: ACT,
        const_salt: Deployment::derive_const_salt("fuzz"),
        transfer_vk_sha256: vk_sha256(params.vk()),
        setup: Setup::InsecureSeed { seed: [0u8; 32] },
        window_w: 6,
        anchor_depth: 3,
        batch: None,
        k_min: 1,
        boundary: Some(DevBoundary {
            vault_script_hex: hex::encode(vault.as_bytes()),
            operator_address: None,
        }),
        swap: None,
        carrier: Default::default(),
    };
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let addresses: Vec<PaymentAddress> = (0..3).map(|i| alice.ivk.find_address(i).1).collect();
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let mint = MintEnvelope {
        note: NotePlaintext {
            value: 5_000,
            d: addresses[0].d,
            rseed: Fr::from(77u64),
        },
        pk_d: addresses[0].pk_d,
    }
    .to_bytes();
    // the prologue: a mint at the activation, an empty block, so the
    // transfer below anchors at ACT with a non-empty tree
    let prologue = vec![vec![mint_tx(&mint, &vault, 5_000, 1)], vec![]];
    let mut idx = Indexer::new(
        deployment.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    let mut chain = MockChain::new(ACT);
    for txs in &prologue {
        chain.push_block(txs.clone());
    }
    idx.sync(&chain).unwrap();
    let outs = [
        Recipient {
            address: addresses[1].clone(),
            value: 0,
        },
        Recipient {
            address: addresses[2].clone(),
            value: 0,
        },
    ];
    let transfer = build_transfer(
        &params,
        &alice,
        &deployment.const_salt,
        &idx.state.tree,
        ACT,
        idx.state.size_at(ACT).unwrap(),
        &[],
        &outs,
        &mut rng,
    )
    .unwrap()
    .envelope
    .to_bytes();
    Fixture {
        params,
        deployment,
        vault,
        addresses,
        prologue,
        transfer,
        mint,
    }
});

impl Fixture {
    fn indexer(&self) -> Indexer {
        Indexer::new(
            self.deployment.clone(),
            TransferVerifier::new(self.params.vk().clone()),
            ReplayState::new(),
        )
    }

    fn mint_bytes(&self, to: u8, value: u64) -> Vec<u8> {
        let a = &self.addresses[to as usize % self.addresses.len()];
        MintEnvelope {
            note: NotePlaintext {
                value,
                d: a.d,
                rseed: Fr::from(value ^ 0x5151),
            },
            pk_d: a.pk_d,
        }
        .to_bytes()
    }

    fn tx(&self, t: &Tx, nonce: u32) -> bitcoin::Transaction {
        match t {
            Tx::Mint { to, value } => {
                mint_tx(&self.mint_bytes(*to, *value), &self.vault, *value, nonce)
            }
            Tx::MintPaid { to, value, paid } => {
                mint_tx(&self.mint_bytes(*to, *value), &self.vault, *paid, nonce)
            }
            Tx::Transfer => carrier_tx(&self.transfer, nonce),
            Tx::TransferFlipped { at, xor } => {
                carrier_tx(&flipped(&self.transfer, *at, *xor), nonce)
            }
            Tx::MintFlipped { at, xor } => {
                mint_tx(&flipped(&self.mint, *at, *xor), &self.vault, 5_000, nonce)
            }
            Tx::Raw(b) => carrier_tx(&[&CANDIDATE_PREFIX[..], b].concat(), nonce),
            Tx::Foreign(b) => {
                let mut tx = carrier_tx(b, nonce);
                tx.output.push(TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: self.vault.clone(),
                });
                tx
            }
            Tx::TwoCarriers => {
                let mut tx = carrier_tx(&self.transfer, nonce);
                tx.output.push(carrier_output(&self.transfer));
                tx
            }
            Tx::WithMemo(m) => {
                carrier_tx_with_memo(&self.transfer, &[&MEMO_MAGIC[..], m].concat(), nonce)
            }
            Tx::SecondOpReturn(b) => {
                let mut tx = carrier_tx(&self.transfer, nonce);
                tx.output.push(carrier_output(b));
                tx
            }
        }
    }
}

fuzz_target!(|script: Script| {
    let f = &*FIXTURE;
    let mut chain = MockChain::new(ACT);
    for txs in &f.prologue {
        chain.push_block(txs.clone());
    }
    let mut idx = f.indexer();
    idx.sync(&chain).unwrap();
    let mut nonce = 100u32;
    for op in script.ops.iter().take(Script::MAX_OPS) {
        let txs = |f: &Fixture, list: &[Tx], nonce: &mut u32| -> Vec<bitcoin::Transaction> {
            list.iter()
                .take(Script::MAX_TXS)
                .map(|t| {
                    *nonce += 1;
                    f.tx(t, *nonce)
                })
                .collect()
        };
        match op {
            Op::Block(list) => {
                let txs = txs(f, list, &mut nonce);
                chain.push_block_salted(txs, nonce);
            }
            Op::Reorg { depth, txs: list } => {
                let tip = chain.height().unwrap();
                let keep = tip.saturating_sub(*depth as u32).max(ACT + 1);
                chain.reorg_to(keep);
                let txs = txs(f, list, &mut nonce);
                chain.push_block_salted(txs, nonce);
            }
            Op::Sync => {}
        }
        idx.sync(&chain).expect("the mock chain always answers");
        assert!(idx.state.check_commitments(), "commitments in step");
        assert_eq!(idx.state.last_height(), chain.height(), "synced to the tip");
    }
    // rollback equals fresh replay
    let mut fresh = f.indexer();
    fresh.sync(&chain).unwrap();
    assert_eq!(
        fresh.state, idx.state,
        "the state after reorganisations is a fresh replay's"
    );
    // what was accepted is on the chain, once each
    let mut seen = std::collections::HashSet::new();
    for e in &idx.state.events {
        assert!(seen.insert(e.txid), "an event per carrier");
        for nf in &e.nullifiers {
            assert!(idx.state.nullifiers.contains(nf));
        }
    }
    assert_eq!(
        idx.state.nullifiers.len(),
        idx.state
            .events
            .iter()
            .map(|e| e.nullifiers.len())
            .sum::<usize>(),
        "the nullifier set is the events' nullifiers"
    );
});
