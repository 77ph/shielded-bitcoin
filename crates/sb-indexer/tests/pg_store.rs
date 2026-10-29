//! PostgreSQL store against a real database: set `SB_TEST_PG` to a libpq
//! connection string (e.g. `host=/path/to/socket-dir dbname=shielded_bitcoin`)
//! and run `cargo test -p sb-indexer --release --test pg_store -- --ignored --nocapture`.
//! Uses a throwaway deployment name and deletes its rows afterwards.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use bitcoin::hashes::Hash;
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
        anchor_depth: 3,
        k_min: 1,
        boundary: None,
        swap: None,
        carrier: Default::default(),
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

/// Rows damaged outside the indexer are reported as corruption, never
/// silently replayed into state.
#[test]
#[ignore]
fn pg_store_rejects_corrupt_rows() {
    use postgres::{Client, NoTls};
    use sb_indexer::StoreError;
    let conn = std::env::var("SB_TEST_PG").expect("SB_TEST_PG connection string");
    let name = format!("pgcorrupt-{}", std::process::id());
    let mut raw = Client::connect(&conn, NoTls).unwrap();
    // make sure the schema exists
    let _ = PgStore::connect(&conn, &name).unwrap();
    let cases: Vec<(&str, &str)> = vec![
        (
            "leaf",
            "INSERT INTO sb_leaves (deployment, pos, leaf, height) VALUES ($1, 0, '\\x00ff', 1)",
        ),
        (
            "nullifier",
            "INSERT INTO sb_nullifiers (deployment, nf, height) VALUES ($1, '\\x00ff', 1)",
        ),
        (
            "block hash",
            "INSERT INTO sb_blocks (deployment, height, hash, leaf_count_before, events_before, rejections_before, nullifiers_added, root) VALUES ($1, 1, '\\x00', 0, 0, 0, '{}', '\\x00')",
        ),
        (
            "block root",
            "INSERT INTO sb_blocks (deployment, height, hash, leaf_count_before, events_before, rejections_before, nullifiers_added, root) VALUES ($1, 1, decode(repeat('00', 32), 'hex'), 0, 0, 0, '{}', '\\x00ff')",
        ),
        (
            "block nullifier",
            "INSERT INTO sb_blocks (deployment, height, hash, leaf_count_before, events_before, rejections_before, nullifiers_added, root) VALUES ($1, 1, decode(repeat('00', 32), 'hex'), 0, 0, 0, ARRAY['\\x00ff'::bytea], decode(repeat('00', 32), 'hex'))",
        ),
        (
            "event raw",
            "INSERT INTO sb_events (deployment, idx, kind, height, tx_index, txid, raw, h_body, first_position, leaves, memo) VALUES ($1, 0, 1, 1, 0, decode(repeat('00', 32), 'hex'), '\\x00', decode(repeat('00', 32), 'hex'), 0, '{}', NULL)",
        ),
        (
            "event txid",
            "INSERT INTO sb_events (deployment, idx, kind, height, tx_index, txid, raw, h_body, first_position, leaves, memo) VALUES ($1, 0, 1, 1, 0, '\\x00', '\\x00', decode(repeat('00', 32), 'hex'), 0, '{}', NULL)",
        ),
        (
            "event h_body",
            "INSERT INTO sb_events (deployment, idx, kind, height, tx_index, txid, raw, h_body, first_position, leaves, memo) VALUES ($1, 0, 1, 1, 0, decode(repeat('00', 32), 'hex'), '\\x00', '\\x00ff', 0, '{}', NULL)",
        ),
        (
            "event leaf",
            "INSERT INTO sb_events (deployment, idx, kind, height, tx_index, txid, raw, h_body, first_position, leaves, memo) VALUES ($1, 0, 1, 1, 0, decode(repeat('00', 32), 'hex'), '\\x00', decode(repeat('00', 32), 'hex'), 0, ARRAY['\\x00ff'::bytea], NULL)",
        ),
        (
            "rejection txid",
            "INSERT INTO sb_rejections (deployment, idx, height, tx_index, txid, reason) VALUES ($1, 0, 1, 0, '\\x00', 'x')",
        ),
    ];
    for (what, sql) in cases {
        raw.execute(sql, &[&name]).unwrap();
        let err = PgStore::connect(&conn, &name).unwrap().load().unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt(_) | StoreError::Pg(_)),
            "{what}: {err}"
        );
        for t in [
            "sb_leaves",
            "sb_nullifiers",
            "sb_blocks",
            "sb_events",
            "sb_rejections",
        ] {
            raw.execute(&format!("DELETE FROM {t} WHERE deployment = $1"), &[&name])
                .unwrap();
        }
    }
    // a mint whose diversifier has no curve point, and one without a leaf
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let mut i = 0u64;
    let bad_d = loop {
        let d = alice.ivk.diversifier(i);
        if sb_primitives::diversify::diversify_hash(&d).is_none() {
            break d;
        }
        i += 1;
    };
    let (_, addr) = alice.ivk.find_address(0);
    let mint = sb_core::envelope::MintEnvelope {
        note: sb_core::note::NotePlaintext {
            value: 1,
            d: bad_d,
            rseed: sb_primitives::Fr::from(1u64),
        },
        pk_d: addr.pk_d,
    };
    raw.execute(
        "INSERT INTO sb_events (deployment, idx, kind, height, tx_index, txid, raw, h_body, first_position, leaves, memo) VALUES ($1, 0, 2, 1, 0, decode(repeat('00', 32), 'hex'), $2, decode(repeat('00', 32), 'hex'), 0, ARRAY[decode(repeat('00', 32), 'hex')], NULL)",
        &[&name, &mint.to_bytes()],
    )
    .unwrap();
    assert!(matches!(
        PgStore::connect(&conn, &name).unwrap().load().unwrap_err(),
        StoreError::Corrupt(_)
    ));
    raw.execute("DELETE FROM sb_events WHERE deployment = $1", &[&name])
        .unwrap();
    let good = sb_core::envelope::MintEnvelope {
        note: sb_core::note::NotePlaintext {
            value: 1,
            d: addr.d,
            rseed: sb_primitives::Fr::from(1u64),
        },
        pk_d: addr.pk_d,
    };
    raw.execute(
        "INSERT INTO sb_events (deployment, idx, kind, height, tx_index, txid, raw, h_body, first_position, leaves, memo) VALUES ($1, 0, 2, 1, 0, decode(repeat('00', 32), 'hex'), $2, decode(repeat('00', 32), 'hex'), 0, '{}', NULL)",
        &[&name, &good.to_bytes()],
    )
    .unwrap();
    assert!(matches!(
        PgStore::connect(&conn, &name).unwrap().load().unwrap_err(),
        StoreError::Corrupt(_)
    ));
    raw.execute("DELETE FROM sb_events WHERE deployment = $1", &[&name])
        .unwrap();
    // committing a block whose root was never recorded
    let mut store = PgStore::connect(&conn, &name).unwrap();
    let mut state = ReplayState::new();
    state.blocks.push(sb_indexer::BlockCheckpoint {
        height: 5,
        hash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
        leaf_count_before: 0,
        events_before: 0,
        rejections_before: 0,
        nullifiers_added: vec![],
    });
    assert!(matches!(
        store.commit_block(&state, 0),
        Err(StoreError::Corrupt(_))
    ));
    assert!(format!("{}", StoreError::Corrupt("x".into())).contains("corrupt"));
}
