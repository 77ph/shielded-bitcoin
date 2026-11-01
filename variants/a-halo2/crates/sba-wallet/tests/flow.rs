//! A wallet flow of variant A against the indexer and a mock chain: a mint
//! is found, spent to another wallet with change, both sides see it, the
//! file round-trips encrypted, and a reorganisation triggers a rescan.

use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use ff::Field;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_common::carrier::{CarrierMode, carrier_output};
use sb_common::chain::mock::MockChain;
use sba_circuit::TransferParams;
use sba_core::address::Network;
use sba_core::envelope::MintEnvelope;
use sba_core::keys::Seed;
use sba_core::note::NotePlaintext;
use sba_indexer::{Deployment, DevBoundary, Indexer, ReplayState};
use sba_primitives::Fp;
use sba_wallet::{Wallet, anchor_for};

const ACTIVATION: u32 = 10;

fn vault() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![
        0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ])
}

fn tx(outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: outputs,
    }
}

#[test]
fn mint_pay_change_persist_reorg() {
    let dir = std::env::temp_dir().join(format!("sba-wallet-flow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let params = TransferParams::build().unwrap();
    let deployment = Deployment {
        profile: sba_core::PROFILE_VERSION.into(),
        family: sba_core::FAMILY.into(),
        name: "flow-a".into(),
        network: Network::Regtest,
        activation_height: ACTIVATION,
        const_salt: Deployment::derive_const_salt("flow-a"),
        transfer_k: sba_circuit::K,
        transfer_vk_id: params.vk_id(),
        window_w: 100,
        k_min: 1,
        anchor_depth: 3,
        boundary: Some(DevBoundary {
            vault_script_hex: hex::encode(vault().as_bytes()),
            operator_address: None,
        }),
        carrier: CarrierMode::OpReturn,
    };
    let salt_fp = deployment.const_salt_fp();
    let mut idx = Indexer::new(
        deployment.clone(),
        deployment.verifier().unwrap(),
        ReplayState::new(),
    );
    let mut alice = Wallet::from_seed(Seed([1u8; 32]), Network::Regtest, "flow-a");
    let mut bob = Wallet::from_seed(Seed([2u8; 32]), Network::Regtest, "flow-a");
    let mut chain = MockChain::new(ACTIVATION);

    // block 10: mint 5000 to alice; blocks 11-12 empty
    let a0 = alice.default_address();
    let mint = MintEnvelope {
        note: NotePlaintext {
            value: 5000,
            d: a0.d,
            rseed: Fp::random(&mut rng),
        },
        pk_d: a0.pk_d,
    };
    chain.push_block(vec![tx(vec![
        carrier_output(&mint.to_bytes()),
        TxOut {
            value: Amount::from_sat(5000),
            script_pubkey: vault(),
        },
    ])]);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    assert_eq!(
        alice
            .scan(&salt_fp, &idx.state.events, &idx.state.nullifiers)
            .unwrap(),
        1
    );
    assert_eq!(alice.balance(), 5000);
    assert_eq!(
        bob.scan(&salt_fp, &idx.state.events, &idx.state.nullifiers)
            .unwrap(),
        0
    );

    // alice pays bob 2000, anchored by the wallet policy
    let tip = idx.state.last_height().unwrap();
    let h_anchor = anchor_for(tip, sba_wallet::K_WALLET);
    let size = idx.state.size_at(h_anchor).unwrap();
    let built = alice
        .build_send(
            &params,
            &deployment.const_salt,
            &idx.state.tree,
            h_anchor,
            size,
            bob.default_address(),
            2000,
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        alice.balance(),
        0,
        "the input is locked while the transfer is pending"
    );
    chain.push_block(vec![tx(vec![carrier_output(&built.envelope.to_bytes())])]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(r.accepted, 1);
    alice
        .scan(&salt_fp, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    bob.scan(&salt_fp, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    assert_eq!(alice.balance(), 3000);
    assert_eq!(bob.balance(), 2000);
    assert_eq!(alice.sent.len(), 2);
    assert!(alice.sent.iter().any(|s| s.is_change && s.value == 3000));
    assert!(alice.sent.iter().any(|s| !s.is_change && s.value == 2000));
    assert_eq!(
        alice.notes.iter().filter(|n| n.spent_at.is_some()).count(),
        1
    );

    // the encrypted file round-trips; wrong passphrase refused
    let path = dir.join("alice.json");
    alice.set_passphrase("pw", &mut rng).unwrap();
    alice.save(&path).unwrap();
    assert!(matches!(
        Wallet::load(&path, None),
        Err(sba_wallet::WalletError::PassphraseRequired)
    ));
    assert!(matches!(
        Wallet::load(&path, Some("no")),
        Err(sba_wallet::WalletError::WrongPassphrase)
    ));
    let back = Wallet::load(&path, Some("pw")).unwrap();
    assert_eq!(back.balance(), 3000);
    assert_eq!(back.notes, alice.notes);
    assert_eq!(back.sent, alice.sent);
    assert!(back.is_encrypted());

    // reorg drops the payment block: alice's note is unspent again, bob has nothing
    chain.reorg_to(ACTIVATION + 2);
    chain.push_block(vec![]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(r.rolled_back_to, Some(ACTIVATION + 2));
    alice
        .scan(&salt_fp, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    bob.scan(&salt_fp, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    assert_eq!(alice.balance(), 5000);
    assert_eq!(bob.balance(), 0);
    assert!(alice.sent.is_empty());

    // selection errors
    assert!(matches!(
        bob.select_inputs(1, idx.state.tree.size()),
        Err(sba_wallet::WalletError::Insufficient { have: 0, need: 1 })
    ));
    assert!(matches!(
        alice.select_inputs(6000, idx.state.tree.size()),
        Err(sba_wallet::WalletError::Insufficient { .. })
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
