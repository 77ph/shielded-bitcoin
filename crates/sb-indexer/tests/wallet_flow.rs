//! Mint → private payment → change, through the stateful wallet, with
//! persistence and a reorganisation-triggered rescan.

use ark_ff::UniformRand;
use bitcoin::ScriptBuf;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_circuit::{TransferParams, TransferVerifier, vk_sha256};
use sb_core::address::Network;
use sb_core::envelope::MintEnvelope;
use sb_core::keys::Seed;
use sb_core::note::NotePlaintext;
use sb_indexer::chain::mock::{MockChain, carrier_tx, carrier_tx_with_memo, mint_tx};
use sb_indexer::deployment::DevBoundary;
use sb_indexer::{Deployment, Indexer, ReplayState, Setup};
use sb_primitives::Fr;
use sb_wallet::{K_WALLET, Wallet, WalletError, anchor_for, build_payout_memo};

const ACTIVATION: u32 = 1000;

#[test]
fn mint_pay_change_persist_reorg() {
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let vault = ScriptBuf::from_bytes(vec![0x51]);
    let deployment = Deployment {
        profile: sb_core::PROFILE_VERSION.into(),
        name: "mock-boundary".into(),
        network: Network::Regtest,
        activation_height: ACTIVATION,
        const_salt: Deployment::derive_const_salt("mock-boundary"),
        transfer_vk_sha256: vk_sha256(params.vk()),
        setup: Setup::InsecureSeed { seed: [0u8; 32] },
        window_w: 100,
        k_min: 1,
        boundary: Some(DevBoundary {
            vault_script_hex: "51".into(),
            operator_address: None,
        }),
        swap: None,
    };
    let salt = deployment.const_salt_fr();
    let mut idx = Indexer::new(
        deployment.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    let mut alice = Wallet::from_seed(Seed([1u8; 32]), Network::Regtest, "mock-boundary");
    let mut bob = Wallet::from_seed(Seed([2u8; 32]), Network::Regtest, "mock-boundary");
    let mut operator = Wallet::from_seed(Seed([9u8; 32]), Network::Regtest, "mock-boundary");
    let operator_addr = operator.default_address();
    let alice_addr = alice.default_address();
    let (_, bob_addr) = bob.new_address();

    // Block 1000: mint 1000 sat to Alice; a mint with the wrong vault amount
    // and one to an unknown deployment-less indexer are rejected.
    let mut chain = MockChain::new(ACTIVATION);
    let mint = MintEnvelope {
        note: NotePlaintext {
            value: 1000,
            d: alice_addr.d,
            rseed: Fr::rand(&mut rng),
        },
        pk_d: alice_addr.pk_d,
    };
    let bad = MintEnvelope {
        note: NotePlaintext {
            value: 500,
            d: alice_addr.d,
            rseed: Fr::rand(&mut rng),
        },
        pk_d: alice_addr.pk_d,
    };
    chain.push_block(vec![
        mint_tx(&mint.to_bytes(), &vault, 1000, 1),
        mint_tx(&bad.to_bytes(), &vault, 499, 2),
    ]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 1),
        "{:?}",
        idx.state.rejections
    );
    assert!(idx.state.rejections[0].reason.contains("vault"));
    assert_eq!(idx.state.tree.size(), 1);

    let mut no_boundary = Indexer::new(
        Deployment {
            boundary: None,
            ..deployment.clone()
        },
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    no_boundary.sync(&chain).unwrap();
    assert_eq!(no_boundary.state.events.len(), 0);
    assert!(
        no_boundary
            .state
            .rejections
            .iter()
            .all(|r| r.reason.contains("no boundary"))
    );

    assert_eq!(
        alice
            .scan(&salt, &idx.state.events, &idx.state.nullifiers)
            .unwrap(),
        1
    );
    assert_eq!(alice.balance(), 1000);
    assert_eq!(
        bob.scan(&salt, &idx.state.events, &idx.state.nullifiers)
            .unwrap(),
        0
    );

    // Two more blocks so K_wallet = 3 allows anchoring at 1000.
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    let tip = idx.state.last_height().unwrap();
    let h_anchor = anchor_for(tip, K_WALLET);
    assert_eq!(h_anchor, ACTIVATION);
    let size = idx.state.size_at(h_anchor).unwrap();
    assert_eq!(size, 1);

    // Alice pays Bob 600 with 400 change.
    assert!(matches!(
        alice.select_inputs(1001, size),
        Err(WalletError::Insufficient { .. })
    ));
    let built = alice
        .build_send(
            &params,
            &deployment.const_salt,
            &idx.state.tree,
            h_anchor,
            size,
            bob_addr,
            600,
            &mut rng,
        )
        .unwrap();
    assert_eq!(alice.balance(), 0, "inputs are locked while pending");
    chain.push_block(vec![carrier_tx(&built.envelope.to_bytes(), 3)]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 0),
        "{:?}",
        idx.state.rejections
    );

    assert_eq!(
        alice
            .scan(&salt, &idx.state.events, &idx.state.nullifiers)
            .unwrap(),
        1
    );
    assert_eq!(alice.balance(), 400);
    assert_eq!(
        alice.notes.iter().filter(|n| n.spent_at.is_some()).count(),
        1
    );
    assert_eq!(alice.sent.len(), 2);
    assert_eq!(alice.sent.iter().filter(|s| s.is_change).count(), 1);
    assert_eq!(alice.sent.iter().find(|s| !s.is_change).unwrap().value, 600);
    assert_eq!(
        bob.scan(&salt, &idx.state.events, &idx.state.nullifiers)
            .unwrap(),
        1
    );
    assert_eq!(bob.balance(), 600);

    // Persistence.
    let dir = std::env::temp_dir().join(format!("sb-wallet-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("alice.json");
    alice.save(&path).unwrap();
    let reloaded = Wallet::load(&path, None).unwrap();
    assert_eq!(reloaded.balance(), 400);
    assert_eq!(reloaded.notes, alice.notes);
    assert_eq!(reloaded.scanned_events, alice.scanned_events);
    // encrypted file: needs the passphrase, rejects a wrong one, round-trips
    let mut enc = Wallet::load(&path, None).unwrap();
    enc.set_passphrase("correct horse", &mut rng).unwrap();
    let epath = dir.join("alice.enc.json");
    enc.save(&epath).unwrap();
    assert!(
        std::fs::read_to_string(&epath)
            .unwrap()
            .contains("\"version\": 2")
    );
    assert!(matches!(
        Wallet::load(&epath, None),
        Err(WalletError::PassphraseRequired)
    ));
    assert!(matches!(
        Wallet::load(&epath, Some("wrong")),
        Err(WalletError::WrongPassphrase)
    ));
    let dec = Wallet::load(&epath, Some("correct horse")).unwrap();
    assert_eq!(dec.balance(), 400);
    assert!(dec.is_encrypted());
    std::fs::remove_dir_all(&dir).unwrap();

    // Reorg drops the payment block: Alice's note is unspent again, Bob has nothing.
    chain.reorg_to(ACTIVATION + 2);
    chain.push_block_salted(vec![], 7);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(r.rolled_back_to, Some(ACTIVATION + 2));
    alice
        .scan(&salt, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    bob.scan(&salt, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    assert_eq!(alice.balance(), 1000);
    assert_eq!(alice.sent.len(), 0);
    assert_eq!(bob.balance(), 0);

    // Bob later spends his note after the payment is re-included.
    chain.push_block(vec![carrier_tx(&built.envelope.to_bytes(), 4)]);
    for _ in 0..2 {
        chain.push_block(vec![]);
    }
    idx.sync(&chain).unwrap();
    alice
        .scan(&salt, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    bob.scan(&salt, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    assert_eq!((alice.balance(), bob.balance()), (400, 600));
    let tip = idx.state.last_height().unwrap();
    let h_anchor = anchor_for(tip, K_WALLET);
    let size = idx.state.size_at(h_anchor).unwrap();
    let back = bob
        .build_send(
            &params,
            &deployment.const_salt,
            &idx.state.tree,
            h_anchor,
            size,
            alice_addr,
            600,
            &mut rng,
        )
        .unwrap();
    chain.push_block(vec![carrier_tx(&back.envelope.to_bytes(), 5)]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 0),
        "{:?}",
        idx.state.rejections
    );
    alice
        .scan(&salt, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    bob.scan(&salt, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    assert_eq!((alice.balance(), bob.balance()), (1000, 0));
    assert_eq!(idx.state.tree.size(), 5);

    // Withdraw: Alice pays 250 to the operator with a payout memo naming a script.
    for _ in 0..2 {
        chain.push_block(vec![]);
    }
    idx.sync(&chain).unwrap();
    let tip = idx.state.last_height().unwrap();
    let h_anchor = anchor_for(tip, K_WALLET);
    let size = idx.state.size_at(h_anchor).unwrap();
    let memo = build_payout_memo(
        250,
        &[
            0x00, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        ],
    );
    let wd = alice
        .build_send(
            &params,
            &deployment.const_salt,
            &idx.state.tree,
            h_anchor,
            size,
            operator_addr,
            250,
            &mut rng,
        )
        .unwrap();
    chain.push_block(vec![carrier_tx_with_memo(
        &wd.envelope.to_bytes(),
        &memo,
        6,
    )]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 0),
        "{:?}",
        idx.state.rejections
    );
    assert_eq!(
        idx.state.events.last().unwrap().memo.as_deref(),
        Some(&memo[..])
    );
    operator
        .scan(&salt, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    assert_eq!(operator.balance(), 250);
    let pending = operator.pending_payouts(&idx.state.events);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request.amount, 250);
    assert_eq!(pending[0].request.script_pubkey[1], 0x14);
    operator.record_payout(
        &pending[0].note.txid,
        &pending[0].request,
        Some("deadbeef".into()),
    );
    assert!(operator.pending_payouts(&idx.state.events).is_empty());
    // the memo survives state persistence
    let reloaded = ReplayState::from_json(&idx.state.to_json()).unwrap();
    assert_eq!(reloaded, idx.state);
    alice
        .scan(&salt, &idx.state.events, &idx.state.nullifiers)
        .unwrap();
    assert_eq!(alice.balance(), 750);
}
