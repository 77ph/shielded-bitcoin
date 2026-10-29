//! Verified indexer sync against the fake node: the light replay must equal
//! the full replay, every check must fire, and a censoring indexer must be
//! caught by the root comparison.

use bitcoin::hashes::Hash;
use sb_circuit::{TransferParams, TransferVerifier};
use sb_core::address::Network;
use sb_core::keys::{Seed, WalletKeys};
use sb_indexer::chain::esplora::Esplora;
use sb_indexer::chain::fake::{FakeHttp, Shared};
use sb_indexer::chain::light::LightSource;
use sb_indexer::chain::mock::{MockChain, carrier_tx, mint_tx};
use sb_indexer::{ChainError, ChainSource, Deployment, Indexer, ReplayState, Setup};
use sb_wallet::{Recipient, build_transfer};
use std::sync::atomic::Ordering;

fn deployment(vault: &bitcoin::ScriptBuf) -> (Deployment, TransferParams) {
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let d = Deployment {
        profile: sb_core::PROFILE_VERSION.into(),
        name: "light".into(),
        network: Network::Regtest,
        activation_height: 10,
        const_salt: [7u8; 32],
        transfer_vk_sha256: sb_circuit::vk_sha256(params.vk()),
        setup: Setup::InsecureSeed { seed: [0u8; 32] },
        window_w: 100,
        anchor_depth: 3,
        k_min: 1,
        boundary: Some(sb_indexer::deployment::DevBoundary {
            vault_script_hex: hex::encode(vault.as_bytes()),
            operator_address: None,
        }),
        swap: None,
        carrier: Default::default(),
    };
    (d, params)
}

/// A chain with a mint, a transfer spending it, a malformed probe and
/// empty blocks in between.
fn chain_with_history(
    d: &Deployment,
    params: &TransferParams,
    vault: &bitcoin::ScriptBuf,
) -> MockChain {
    let keys = WalletKeys::from_seed(&Seed([1u8; 32]));
    let addr = keys.ivk.find_address(0).1;
    let note = sb_core::note::NotePlaintext {
        value: 5000,
        d: addr.d,
        rseed: sb_primitives::Fr::from(9u64),
    };
    let mint = sb_core::envelope::MintEnvelope {
        note,
        pk_d: addr.pk_d,
    };
    let mut chain = MockChain::new(10);
    chain.push_block(vec![]); // 10
    chain.push_block(vec![mint_tx(&mint.to_bytes(), vault, 5000, 1)]); // 11
    chain.push_block(vec![]); // 12
    // replay what we have so far to build a spend at anchor 11
    let mut idx = Indexer::new(
        d.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    idx.sync(&chain).unwrap();
    let h_body_create = idx.state.events[0].h_body;
    let spend = sb_wallet::SpendableNote {
        note,
        h_body_create,
        output_index: 0,
        pos: 0,
    };
    let built = build_transfer(
        params,
        &keys,
        &d.const_salt,
        &idx.state.tree,
        11,
        1,
        &[spend],
        &[Recipient {
            address: addr,
            value: 5000,
        }],
        &mut rand::thread_rng(),
    )
    .unwrap();
    let mut probe = vec![0u8; 50];
    probe[..4].copy_from_slice(&sb_core::envelope::CANDIDATE_PREFIX);
    chain.push_block(vec![
        carrier_tx(&probe, 2),
        carrier_tx(&built.envelope.to_bytes(), 3),
    ]); // 13
    chain.push_block(vec![]); // 14
    chain
}

fn state_json(idx: &Indexer) -> String {
    idx.state.to_json()
}

#[test]
fn light_replay_equals_full_replay_and_every_check_fires() {
    let vault = bitcoin::ScriptBuf::new_op_return([5u8; 4]);
    let (d, params) = deployment(&vault);
    let chain = chain_with_history(&d, &params, &vault);
    let shared = Shared::new(chain);
    let http = FakeHttp::start(shared.clone());
    let esplora = || Box::new(Esplora::new(&http.esplora_url())) as Box<dyn ChainSource>;
    let light_url = format!("{}/light", http.esplora_url());

    // full replay
    let mut full = Indexer::new(
        d.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    let r = full.sync(esplora().as_ref()).unwrap();
    assert_eq!((r.accepted, r.rejected), (2, 1));

    // light replay, with and without a header source
    for headers in [Some(esplora()), None] {
        let light = LightSource::new(&light_url, headers);
        let mut idx = Indexer::new(
            d.clone(),
            TransferVerifier::new(params.vk().clone()),
            ReplayState::new(),
        );
        let r = idx.sync(&light).unwrap();
        assert_eq!((r.accepted, r.rejected), (2, 1));
        assert_eq!(state_json(&idx), state_json(&full));
        // the fake claims no roots, so nothing to compare
        assert_eq!(light.verify_claims(&idx).unwrap(), 0);
        // a second sync is a no-op and `block` by hash works from the cache or the route
        let r = idx.sync(&light).unwrap();
        assert_eq!(r.blocks, 0);
        let tip = light.tip().unwrap();
        assert_eq!(tip.height, 14);
        let b = light.block(&tip.hash).unwrap();
        assert_eq!(b.block_hash(), tip.hash);
    }

    // a censoring indexer: the last carrier of every block is missing; the
    // proofs still verify (it is a valid view of fewer carriers) but the
    // replay diverges, and a bogus root claim is caught
    shared.light_omit.store(true, Ordering::SeqCst);
    let light = LightSource::new(&light_url, None);
    let mut idx = Indexer::new(
        d.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    let r = idx.sync(&light).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (0, 1),
        "mint and transfer hidden, probe kept"
    );
    assert_ne!(state_json(&idx), state_json(&full));
    shared.light_omit.store(false, Ordering::SeqCst);
    shared.light_bogus_root.store(true, Ordering::SeqCst);
    let light = LightSource::new(&light_url, None);
    let mut idx = Indexer::new(
        d.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    idx.sync(&light).unwrap();
    let e = light.verify_claims(&idx).unwrap_err().to_string();
    assert!(
        e.contains("claims R[10]") && e.contains("different carrier set"),
        "{e}"
    );
    shared.light_bogus_root.store(false, Ordering::SeqCst);

    // an indexer on another chain than the header source
    shared.light_wrong_hash.store(true, Ordering::SeqCst);
    let light = LightSource::new(&light_url, Some(esplora()));
    let e = light.block_hash(12).unwrap_err().to_string();
    assert!(e.contains("header source has"), "{e}");
    // without a header source the wrong hash is caught by the header check
    let light = LightSource::new(&light_url, None);
    let claimed = light.block_hash(12).unwrap().unwrap();
    let e = light.block(&claimed).unwrap_err().to_string();
    assert!(e.contains("header hashes to"), "{e}");
    shared.light_wrong_hash.store(false, Ordering::SeqCst);

    // tip cross-check, unknown heights, bad answers
    let light = LightSource::new(&light_url, Some(esplora()));
    assert!(light.block_hash(99).unwrap().is_none());
    assert!(matches!(
        light.block(&bitcoin::BlockHash::from_byte_array([9u8; 32])),
        Err(ChainError::NotFound(_))
    ));
    let bad = LightSource::new(&format!("{}/light/bad-json", http.esplora_url()), None);
    assert!(matches!(bad.tip(), Err(ChainError::Decode(_))));
    let bad = LightSource::new(&format!("{}/nothing", http.esplora_url()), None);
    assert!(matches!(bad.tip(), Err(ChainError::NotFound(_))));
    let bad = LightSource::new("http://127.0.0.1:1", None);
    assert!(matches!(bad.tip(), Err(ChainError::Http(_))));
    // a tip the header source does not know
    shared.light_wrong_hash.store(true, Ordering::SeqCst);
    let light = LightSource::new(&light_url, Some(esplora()));
    assert!(
        light.tip().is_ok(),
        "the tip route is unaffected by the flag"
    );
    shared.light_wrong_hash.store(false, Ordering::SeqCst);
    let other = Shared::new(MockChain::new(10));
    {
        let mut c = other.chain.lock().unwrap();
        c.push_block(vec![]);
    }
    let other_http = FakeHttp::start(other);
    let light = LightSource::new(
        &light_url,
        Some(Box::new(Esplora::new(&other_http.esplora_url()))),
    );
    let e = light.tip().unwrap_err().to_string();
    assert!(e.contains("not on the header source"), "{e}");
}
