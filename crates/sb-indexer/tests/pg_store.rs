//! PostgreSQL store against a real database: set `SB_TEST_PG` to a libpq
//! connection string (e.g. `host=/path/to/socket-dir dbname=shielded_bitcoin`)
//! and run `cargo test -p sb-indexer --release --test pg_store -- --ignored --nocapture`.
//! Uses a throwaway deployment name and deletes its rows afterwards.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_circuit::{TransferParams, TransferVerifier, vk_sha256};
use sb_core::address::Network;
use sb_core::keys::{Seed, WalletKeys};
use sb_indexer::chain::mock::{MockChain, carrier_tx};
use sb_indexer::{Deployment, Indexer, PgStore, ReplayState, Setup, StateStore};
use sb_wallet::{Recipient, build_transfer};

#[test]
#[ignore]
fn pg_store_round_trip_and_rollback() {
    let conn = std::env::var("SB_TEST_PG").expect("SB_TEST_PG connection string");
    let name = format!("pgtest-{}", std::process::id());
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let deployment = Deployment {
        profile: sb_core::PROFILE_VERSION.into(),
        name: name.clone(),
        network: Network::Regtest,
        activation_height: 10,
        const_salt: Deployment::derive_const_salt(&name),
        transfer_vk_sha256: vk_sha256(params.vk()),
        setup: Setup::InsecureSeed { seed: [0u8; 32] },
        window_w: 100,
        k_min: 1,
        boundary: None,
    };
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let (_, addr) = alice.ivk.find_address(0);
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);

    let mut store = PgStore::connect(&conn, &name).unwrap();
    let mut idx = Indexer::new(
        deployment.clone(),
        TransferVerifier::new(params.vk().clone()),
        store.load().unwrap(),
    );
    assert_eq!(idx.state.tree.size(), 0);

    // Blocks 10..13 with one zero-value transfer in 11 and a parse rejection in 12.
    let mut chain = MockChain::new(10);
    chain.push_block(vec![]);
    idx.sync_with(&chain, Some(&mut store)).unwrap();
    let outs = [
        Recipient {
            address: addr,
            value: 0,
        },
        Recipient {
            address: addr,
            value: 0,
        },
    ];
    let t = build_transfer(
        &params,
        &alice,
        &deployment.const_salt,
        &idx.state.tree,
        10,
        0,
        &[],
        &outs,
        &mut rng,
    )
    .unwrap();
    chain.push_block(vec![carrier_tx(&t.envelope.to_bytes(), 1)]);
    let mut garbage = t.envelope.to_bytes();
    garbage.truncate(50);
    chain.push_block(vec![carrier_tx(&garbage, 2)]);
    chain.push_block(vec![]);
    let r = idx.sync_with(&chain, Some(&mut store)).unwrap();
    assert_eq!((r.accepted, r.rejected), (1, 1));

    // A fresh store connection rebuilds exactly the in-memory state.
    let mut store2 = PgStore::connect(&conn, &name).unwrap();
    let loaded = store2.load().unwrap();
    assert_eq!(loaded, idx.state);
    assert_eq!(loaded.tree.root(), idx.state.tree.root());

    // Reorg: drop blocks above 11, replace with an empty one.
    chain.reorg_to(11);
    chain.push_block_salted(vec![], 5);
    let r = idx.sync_with(&chain, Some(&mut store)).unwrap();
    assert_eq!(r.rolled_back_to, Some(11));
    let loaded = PgStore::connect(&conn, &name).unwrap().load().unwrap();
    assert_eq!(loaded, idx.state);
    assert_eq!(loaded.rejections.len(), 0);
    assert_eq!(loaded.events.len(), 1);

    // Determinism: a fresh indexer over the same chain equals the stored state.
    let mut fresh = Indexer::new(
        deployment.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    fresh.sync(&chain).unwrap();
    assert_eq!(fresh.state, loaded);

    // Clean up this deployment's rows.
    store.rollback_to(&idx.state, 0).unwrap();
    assert_eq!(
        PgStore::connect(&conn, &name)
            .unwrap()
            .load()
            .unwrap()
            .blocks
            .len(),
        0
    );
}
