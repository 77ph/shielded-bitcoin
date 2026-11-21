//! Variant A's indexer (`sba-indexer`, the one replaying public signet)
//! over generated chains: the same grammar and invariants as `indexer_s`,
//! with the variant's test world making the mint and the transfer.
#![no_main]
use std::sync::{LazyLock, Mutex};

use bitcoin::{Amount, TxOut};
use libfuzzer_sys::fuzz_target;
use sb_common::carrier::{MEMO_MAGIC, carrier_output};
use sb_common::chain::mock::{MockChain, carrier_tx, carrier_tx_with_memo, mint_tx};
use sb_fuzz::{Op, Script, Tx, flipped};
use sba_core::address::PaymentAddress;
use sba_core::envelope::{CANDIDATE_PREFIX, MintEnvelope};
use sba_core::note::NotePlaintext;
use sba_indexer::Indexer;
use sba_indexer::testing::{ACTIVATION, World, vault_script};
use sba_primitives::Fp;

struct Fixture {
    world: Mutex<World>,
    addresses: Vec<PaymentAddress>,
    prologue: Vec<Vec<bitcoin::Transaction>>,
    transfer: Vec<u8>,
    mint: Vec<u8>,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let mut w = World::new();
    let addresses: Vec<PaymentAddress> = (0..3).map(|i| w.alice.ivk.find_address(i).1).collect();
    let (mint_tx0, mint_env) = w.mint_tx(&addresses[0], 5_000);
    let prologue = vec![vec![mint_tx0], vec![]];
    let mut idx = w.indexer();
    let mut chain = MockChain::new(ACTIVATION);
    for txs in &prologue {
        chain.push_block(txs.clone());
    }
    idx.sync(&chain).unwrap();
    let transfer = w
        .transfer(
            &idx,
            ACTIVATION,
            None,
            [(addresses[1].clone(), 0), (addresses[2].clone(), 0)],
        )
        .to_bytes();
    Fixture {
        world: Mutex::new(w),
        addresses,
        prologue,
        transfer,
        mint: mint_env.to_bytes(),
    }
});

impl Fixture {
    fn indexer(&self) -> Indexer {
        self.world.lock().unwrap().indexer()
    }

    fn mint_bytes(&self, to: u8, value: u64) -> Vec<u8> {
        let a = &self.addresses[to as usize % self.addresses.len()];
        MintEnvelope {
            note: NotePlaintext {
                value,
                d: a.d,
                rseed: Fp::from(value ^ 0x5151),
            },
            pk_d: a.pk_d,
        }
        .to_bytes()
    }

    fn tx(&self, t: &Tx, nonce: u32) -> bitcoin::Transaction {
        let vault = vault_script();
        match t {
            Tx::Mint { to, value } => mint_tx(&self.mint_bytes(*to, *value), &vault, *value, nonce),
            Tx::MintPaid { to, value, paid } => {
                mint_tx(&self.mint_bytes(*to, *value), &vault, *paid, nonce)
            }
            Tx::Transfer => carrier_tx(&self.transfer, nonce),
            Tx::TransferFlipped { at, xor } => {
                carrier_tx(&flipped(&self.transfer, *at, *xor), nonce)
            }
            Tx::MintFlipped { at, xor } => {
                mint_tx(&flipped(&self.mint, *at, *xor), &vault, 5_000, nonce)
            }
            Tx::Raw(b) => carrier_tx(&[&CANDIDATE_PREFIX[..], b].concat(), nonce),
            Tx::Foreign(b) => {
                let mut tx = carrier_tx(b, nonce);
                tx.output.push(TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: vault,
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
    let mut chain = MockChain::new(ACTIVATION);
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
                let keep = tip.saturating_sub(*depth as u32).max(ACTIVATION + 1);
                chain.reorg_to(keep);
                let txs = txs(f, list, &mut nonce);
                chain.push_block_salted(txs, nonce);
            }
            Op::Sync => {}
        }
        idx.sync(&chain).expect("the mock chain always answers");
        assert_eq!(idx.state.last_height(), chain.height(), "synced to the tip");
        // the nullifier tree holds the set, exactly
        assert_eq!(idx.state.nf_tree.len(), idx.state.nullifiers.len());
        for nf in &idx.state.nullifiers {
            let v = sba_primitives::encoding::fp_from_bytes(nf).unwrap();
            assert!(idx.state.nf_tree.contains(&v));
        }
    }
    let mut fresh = f.indexer();
    fresh.sync(&chain).unwrap();
    assert_eq!(
        fresh.state, idx.state,
        "the state after reorganisations is a fresh replay's"
    );
    let mut seen = std::collections::HashSet::new();
    for e in &idx.state.events {
        assert!(seen.insert(e.txid), "an event per carrier");
    }
});
