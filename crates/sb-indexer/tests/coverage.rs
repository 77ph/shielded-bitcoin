//! Indexer branches the main scenarios do not reach: rejection classes,
//! chain-source tampering, full-reset reorganisation, the JSON store,
//! deployment key sources and state-file errors.

use bitcoin::{Block, BlockHash};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_circuit::{TransferParams, TransferVerifier, vk_sha256, vk_to_bytes};
use sb_core::address::Network;
use sb_core::envelope::TransferEnvelope;
use sb_core::keys::{Seed, WalletKeys};
use sb_indexer::chain::mock::{MockChain, carrier_tx};
use sb_indexer::{
    BlockId, ChainError, ChainSource, Deployment, DeploymentError, Indexer, JsonStore, ReplayState,
    Setup, StateError, StateStore, SyncError,
};
use sb_wallet::{Recipient, build_transfer};

const ACT: u32 = 50;

fn deployment(params: &TransferParams, name: &str) -> Deployment {
    Deployment {
        profile: sb_core::PROFILE_VERSION.into(),
        name: name.into(),
        network: Network::Regtest,
        activation_height: ACT,
        const_salt: Deployment::derive_const_salt(name),
        transfer_vk_sha256: vk_sha256(params.vk()),
        setup: Setup::InsecureSeed { seed: [0u8; 32] },
        window_w: 10,
        k_min: 1,
        boundary: None,
    }
}

fn indexer(params: &TransferParams, d: &Deployment) -> Indexer {
    Indexer::new(
        d.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    )
}

fn zero_transfer(
    params: &TransferParams,
    d: &Deployment,
    idx: &Indexer,
    h_anchor: u32,
    rng: &mut ChaCha20Rng,
) -> TransferEnvelope {
    let alice = WalletKeys::from_seed(&Seed([1u8; 32]));
    let (_, a) = alice.ivk.find_address(0);
    let size = idx.state.size_at(h_anchor).unwrap();
    let outs = [
        Recipient {
            address: a,
            value: 0,
        },
        Recipient {
            address: a,
            value: 0,
        },
    ];
    build_transfer(
        params,
        &alice,
        &d.const_salt,
        &idx.state.tree,
        h_anchor,
        size,
        &[],
        &outs,
        rng,
    )
    .unwrap()
    .envelope
}

#[test]
fn rejection_classes_and_json_store() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let d = deployment(&params, "cov-reject");
    let dir = std::env::temp_dir().join(format!("sb-indexer-cov-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut store = JsonStore::new(dir.join("state.json"));
    let mut idx = Indexer::new(
        d.clone(),
        TransferVerifier::new(params.vk().clone()),
        store.load().unwrap(),
    );
    let mut chain = MockChain::new(ACT);
    chain.push_block(vec![]);
    idx.sync_with(&chain, Some(&mut store)).unwrap();

    let t = zero_transfer(&params, &d, &idx, ACT, &mut rng);
    // duplicate nullifier inside the envelope
    let mut dup = t.clone();
    dup.body.nullifiers[1] = dup.body.nullifiers[0];
    // invalid proof
    let mut bad = t.clone();
    bad.proof[5] ^= 1;
    chain.push_block(vec![
        carrier_tx(&dup.to_bytes(), 1),
        carrier_tx(&bad.to_bytes(), 2),
        carrier_tx(&t.to_bytes(), 3),
    ]);
    let r = idx.sync_with(&chain, Some(&mut store)).unwrap();
    assert_eq!((r.accepted, r.rejected), (1, 2));
    assert!(
        idx.state.rejections[0]
            .reason
            .contains("duplicate nullifier"),
        "{}",
        idx.state.rejections[0].reason
    );
    assert!(
        idx.state.rejections[1]
            .reason
            .contains("proof does not verify"),
        "{}",
        idx.state.rejections[1].reason
    );
    assert_eq!(idx.events_from(0).len(), 1);
    assert_eq!(idx.events_from(100).len(), 0);
    assert!(Indexer::is_carrier(&carrier_tx(&t.to_bytes(), 9)));

    // JSON store persisted the state; a reorg goes through the store too
    let loaded = JsonStore::new(dir.join("state.json")).load().unwrap();
    assert_eq!(loaded, idx.state);
    chain.reorg_to(ACT);
    chain.push_block_salted(vec![], 3);
    let r = idx.sync_with(&chain, Some(&mut store)).unwrap();
    assert_eq!(r.rolled_back_to, Some(ACT));
    assert_eq!(
        JsonStore::new(dir.join("state.json")).load().unwrap(),
        idx.state
    );

    // a chain sharing no block with the replayed history resets everything
    let mut other = MockChain::new(ACT);
    other.push_block_salted(vec![], 77);
    other.push_block_salted(vec![], 78);
    let r = idx.sync_with(&other, Some(&mut store)).unwrap();
    assert_eq!(r.rolled_back_to, Some(ACT - 1));
    assert_eq!(idx.state.blocks.len(), 2);
    assert_eq!(idx.state.events.len(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Serves `a` up to `switch`, then `b` above it (hashes link within each
/// chain but not across), and optionally returns the wrong block for a hash.
struct Spliced {
    a: MockChain,
    b: MockChain,
    switch: u32,
    wrong_block: bool,
    lag_once: std::cell::Cell<bool>,
}

impl ChainSource for Spliced {
    fn tip(&self) -> Result<BlockId, ChainError> {
        self.b.tip()
    }
    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError> {
        if self.lag_once.replace(false) {
            return Ok(None);
        }
        if height <= self.switch {
            self.a.block_hash(height)
        } else {
            self.b.block_hash(height)
        }
    }
    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        let block = self.a.block(hash).or_else(|_| self.b.block(hash))?;
        if self.wrong_block {
            // a different (valid) block than the one asked for
            let other = self.a.block_hash(ACT)?.unwrap();
            if other != *hash {
                return self.a.block(&other);
            }
        }
        Ok(block)
    }
}

#[test]
fn tampered_sources_are_refused() {
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let d = deployment(&params, "cov-tamper");
    let mut a = MockChain::new(ACT);
    a.push_block(vec![]);
    a.push_block(vec![]);
    let mut b = MockChain::new(ACT);
    b.push_block_salted(vec![], 9);
    b.push_block_salted(vec![], 9);
    b.push_block_salted(vec![], 9);

    // block at switch+1 comes from b: it does not extend a's block at switch
    let mut idx = indexer(&params, &d);
    let spliced = Spliced {
        a: a.clone(),
        b: b.clone(),
        switch: ACT + 1,
        wrong_block: false,
        lag_once: false.into(),
    };
    match idx.sync(&spliced) {
        Err(SyncError::Chain(ChainError::Decode(msg))) => {
            assert!(msg.contains("does not extend"), "{msg}")
        }
        other => panic!("expected a linkage error, got {other:?}"),
    }
    assert_eq!(idx.state.last_height(), Some(ACT + 1));

    // a block that does not hash to the requested hash
    let mut idx = indexer(&params, &d);
    let spliced = Spliced {
        a: a.clone(),
        b: a.clone(),
        switch: ACT + 5,
        wrong_block: true,
        lag_once: false.into(),
    };
    match idx.sync(&spliced) {
        Err(SyncError::Chain(ChainError::Decode(msg))) => {
            assert!(msg.contains("does not hash"), "{msg}")
        }
        other => panic!("expected a hash error, got {other:?}"),
    }

    // a momentary None below the tip is retried
    let mut idx = indexer(&params, &d);
    let spliced = Spliced {
        a: a.clone(),
        b: a.clone(),
        switch: ACT + 5,
        wrong_block: false,
        lag_once: true.into(),
    };
    let r = idx.sync(&spliced).unwrap();
    assert_eq!(r.blocks, 2);
}

#[test]
fn deployment_key_sources_and_state_files() {
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let dir = std::env::temp_dir().join(format!("sb-deploy-cov-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut d = deployment(&params, "cov-deploy");
    // file round trip
    std::fs::write(dir.join("d.json"), d.to_json()).unwrap();
    assert_eq!(Deployment::load(&dir.join("d.json")).unwrap(), d);
    assert!(matches!(
        Deployment::load(&dir.join("missing.json")),
        Err(DeploymentError::Io(_))
    ));
    // insecure seed params
    assert!(d.params(&dir).is_ok());
    // ceremony files
    std::fs::write(dir.join("transfer.vk"), vk_to_bytes(params.vk())).unwrap();
    std::fs::write(dir.join("transfer.pk"), params.pk_to_bytes().unwrap()).unwrap();
    d.setup = Setup::Ceremony {
        vk_path: "transfer.vk".into(),
        pk_path: None,
    };
    assert!(d.verifier(&dir).is_ok());
    assert!(matches!(d.params(&dir), Err(DeploymentError::Io(_))));
    d.setup = Setup::Ceremony {
        vk_path: "transfer.vk".into(),
        pk_path: Some("transfer.pk".into()),
    };
    assert!(d.params(&dir).is_ok());
    d.transfer_vk_sha256 = [1u8; 32];
    assert!(matches!(
        d.params(&dir),
        Err(DeploymentError::VkMismatch { .. })
    ));
    assert!(
        format!(
            "{}",
            DeploymentError::ProfileMismatch {
                found: "a".into(),
                expected: "b".into()
            }
        )
        .contains("profile a")
    );

    // state files
    assert!(matches!(
        ReplayState::from_json(
            r#"{"version":2,"leaves":[],"nullifiers":[],"roots":[],"blocks":[],"events":[],"rejections":[]}"#
        ),
        Err(StateError::Corrupt(_))
    ));
    assert!(matches!(
        ReplayState::from_json("nope"),
        Err(StateError::Json(_))
    ));
    assert!(matches!(
        ReplayState::load(&dir.join("none.json")),
        Err(StateError::Io(_))
    ));
    let s = ReplayState::new();
    assert_eq!(s.size_at(5), Some(0));
    s.save(&dir.join("s.json")).unwrap();
    assert_eq!(ReplayState::load(&dir.join("s.json")).unwrap(), s);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn mock_chain_edges() {
    let c = MockChain::new(5);
    assert_eq!(c.height(), None);
    assert!(c.tip().is_err());
    assert_eq!(c.block_hash(1).unwrap(), None);
    assert!(c.block(&BlockHash::from_byte_array([0u8; 32])).is_err());
    use bitcoin::hashes::Hash;
    let _ = BlockHash::all_zeros();
}

#[test]
fn json_store_direct() {
    let dir = std::env::temp_dir().join(format!("sb-json-store-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");
    let mut store = JsonStore::new(path.clone());
    assert_eq!(
        store.load().unwrap().blocks.len(),
        0,
        "no file yet means an empty state"
    );
    let state = ReplayState::new();
    store.commit_block(&state, 0).unwrap();
    store.rollback_to(&state, 0).unwrap();
    assert!(!path.exists(), "per-block hooks do not write; flush does");
    store.flush(&state).unwrap();
    assert!(path.exists());
    assert_eq!(JsonStore::new(path).load().unwrap(), state);
    std::fs::remove_dir_all(&dir).unwrap();
}
