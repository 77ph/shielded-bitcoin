//! Replay against a mock chain: acceptance, every rejection class,
//! reorganisation rollback, determinism and state persistence.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_circuit::{TransferParams, TransferVerifier, vk_sha256};
use sb_core::address::{Network, PaymentAddress};
use sb_core::envelope::TransferEnvelope;
use sb_core::keys::{Seed, WalletKeys};
use sb_core::tree::{DEPTH, EMPTY_ROOTS};
use sb_indexer::chain::mock::{MockChain, carrier_tx};
use sb_indexer::{Deployment, Indexer, ReplayState, Setup};
use sb_wallet::{Recipient, SpendableNote, build_transfer, scan_incoming, scan_outgoing};

const ACTIVATION: u32 = 1000;

struct World {
    deployment: Deployment,
    params: TransferParams,
    alice: WalletKeys,
    bob: WalletKeys,
    rng: ChaCha20Rng,
}

impl World {
    fn new() -> Self {
        let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
        let deployment = Deployment {
            profile: sb_core::PROFILE_VERSION.into(),
            name: "mock".into(),
            network: Network::Regtest,
            activation_height: ACTIVATION,
            const_salt: Deployment::derive_const_salt("mock"),
            transfer_vk_sha256: vk_sha256(params.vk()),
            setup: Setup::InsecureSeed { seed: [0u8; 32] },
            window_w: 5,
            k_min: 1,
            boundary: None,
            swap: None,
        };
        World {
            deployment,
            params,
            alice: WalletKeys::from_seed(&Seed([1u8; 32])),
            bob: WalletKeys::from_seed(&Seed([2u8; 32])),
            rng: ChaCha20Rng::from_seed([7u8; 32]),
        }
    }

    fn indexer(&self) -> Indexer {
        let verifier = TransferVerifier::new(self.params.vk().clone());
        Indexer::new(self.deployment.clone(), verifier, ReplayState::new())
    }

    /// A transfer from Alice spending `inputs` (dummies when empty) to `outputs`,
    /// anchored at `h_anchor`.
    fn transfer(
        &mut self,
        idx: &Indexer,
        h_anchor: u32,
        inputs: &[SpendableNote],
        outputs: &[Recipient],
    ) -> TransferEnvelope {
        let size = idx
            .state
            .size_at(h_anchor)
            .expect("anchor height replayed or before activation");
        let alice = self.alice.clone();
        build_transfer(
            &self.params,
            &alice,
            &self.deployment.const_salt,
            &idx.state.tree,
            h_anchor,
            size,
            inputs,
            outputs,
            &mut self.rng,
        )
        .unwrap()
        .envelope
    }

    /// Two dummy inputs, two zero-value outputs to `to`.
    fn zero_transfer(
        &mut self,
        idx: &Indexer,
        h_anchor: u32,
        to: &PaymentAddress,
    ) -> TransferEnvelope {
        let outs = [
            Recipient {
                address: *to,
                value: 0,
            },
            Recipient {
                address: *to,
                value: 0,
            },
        ];
        self.transfer(idx, h_anchor, &[], &outs)
    }
}

#[test]
fn accept_spend_reject_and_reorg() {
    let mut w = World::new();
    let mut idx = w.indexer();
    let salt = w.deployment.const_salt_fr();
    let (_, alice_addr) = w.alice.ivk.find_address(0);
    let (_, bob_addr) = w.bob.ivk.find_address(0);

    // Two blocks before activation are ignored by replay.
    let mut chain = MockChain::new(ACTIVATION - 2);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(r.blocks, 0);
    assert_eq!(idx.next_height(), ACTIVATION);

    // Block 1000: Alice creates two zero-value notes to herself from dummies.
    // (Without a boundary no value can enter; replay logic is identical.)
    let t1 = w.zero_transfer(&idx, ACTIVATION - 1, &alice_addr);
    let b1 = chain.push_block(vec![carrier_tx(&t1.to_bytes(), 1)]);
    assert_eq!(b1.height, ACTIVATION);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 0),
        "{:?}",
        idx.state.rejections
    );
    assert_eq!(idx.state.tree.size(), 2);
    assert_eq!(idx.state.nullifiers.len(), 2);

    // Alice scans and finds her two notes; Bob finds nothing.
    let ev = &idx.state.events[0];
    let received = scan_incoming(&w.alice.ivk, &salt, ev);
    assert_eq!(received.len(), 2);
    assert_eq!(received[0].pos, 0);
    assert_eq!(received[1].pos, 1);
    assert!(scan_incoming(&w.bob.ivk, &salt, ev).is_empty());
    assert_eq!(scan_outgoing(&w.alice.ovk, &salt, ev).unwrap().len(), 2);
    assert!(scan_outgoing(&w.bob.ovk, &salt, ev).is_none());

    // Block 1001: Alice spends both notes (real membership under R[1000]) to Bob,
    // and a truncated probe sits in the same block.
    let inputs: Vec<SpendableNote> = received
        .iter()
        .map(|r| SpendableNote {
            note: r.note,
            h_body_create: r.h_body_create,
            output_index: r.output_index,
            pos: r.pos,
        })
        .collect();
    let t2 = w.transfer(
        &idx,
        ACTIVATION,
        &inputs,
        &[Recipient {
            address: bob_addr,
            value: 0,
        }],
    );
    let mut garbage = t2.to_bytes();
    garbage.truncate(100);
    chain.push_block(vec![carrier_tx(&garbage, 2), carrier_tx(&t2.to_bytes(), 3)]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 1),
        "{:?}",
        idx.state.rejections
    );
    assert!(
        idx.state.rejections[0].reason.starts_with("parse"),
        "{}",
        idx.state.rejections[0].reason
    );
    assert_eq!(idx.state.tree.size(), 4);
    let bob_notes = scan_incoming(&w.bob.ivk, &salt, &idx.state.events[1]);
    assert_eq!(bob_notes.len(), 1);
    assert_eq!(bob_notes[0].pos, 2);

    // Block 1002: t2 republished (double spend) plus a fresh anchor-999 transfer
    // (still inside the window W = 5).
    let t3 = w.zero_transfer(&idx, ACTIVATION - 1, &alice_addr);
    chain.push_block(vec![
        carrier_tx(&t2.to_bytes(), 4),
        carrier_tx(&t3.to_bytes(), 5),
    ]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 1),
        "{:?}",
        idx.state.rejections
    );
    assert!(
        idx.state.rejections[1].reason.contains("already spent"),
        "{}",
        idx.state.rejections[1].reason
    );

    // Blocks 1003..1005 empty; at 1006 an anchor of 999 is older than H - W.
    for _ in 0..3 {
        chain.push_block(vec![]);
    }
    let t4 = w.zero_transfer(&idx, ACTIVATION - 1, &alice_addr);
    chain.push_block(vec![carrier_tx(&t4.to_bytes(), 6)]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (0, 1));
    assert!(
        idx.state.rejections[2]
            .reason
            .contains("outside the window"),
        "{}",
        idx.state.rejections[2].reason
    );
    // A valid anchor at 1005 for a block at 1007 is accepted (tree has 6 leaves).
    let t5 = w.zero_transfer(&idx, ACTIVATION + 5, &alice_addr);
    chain.push_block(vec![carrier_tx(&t5.to_bytes(), 7)]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 0),
        "{:?}",
        idx.state.rejections
    );
    assert_eq!(idx.state.tree.size(), 8);
    let snapshot = idx.state.clone();

    // Reorg: replace everything above 1001 with one empty block; t2 (1001) survives.
    chain.reorg_to(ACTIVATION + 1);
    chain.push_block_salted(vec![], 99);
    let r = idx.sync(&chain).unwrap();
    assert_eq!(r.rolled_back_to, Some(ACTIVATION + 1));
    assert_eq!(idx.state.tree.size(), 4);
    assert_eq!(idx.state.events.len(), 2);
    assert_eq!(idx.state.rejections.len(), 1);
    assert_eq!(idx.state.nullifiers.len(), 4);
    assert_eq!(idx.state.last_height(), Some(ACTIVATION + 2));
    assert_ne!(idx.state, snapshot);

    // Determinism: a fresh indexer over the same chain derives the same state.
    let mut fresh = w.indexer();
    fresh.sync(&chain).unwrap();
    assert_eq!(fresh.state, idx.state);

    // Persistence round trip.
    let json = idx.state.to_json();
    assert_eq!(ReplayState::from_json(&json).unwrap(), idx.state);

    // Roots: every replayed height has one; anchors below activation are empty.
    for h in ACTIVATION..=ACTIVATION + 2 {
        assert!(idx.root_at(h).is_some());
    }
    assert_eq!(idx.root_at(ACTIVATION - 1), Some(EMPTY_ROOTS[DEPTH]));
    assert_eq!(idx.root_at(ACTIVATION + 3), None);
}

#[test]
fn pinned_vk_hash_is_checked() {
    let mut d = World::new().deployment;
    d.transfer_vk_sha256 = [0u8; 32];
    assert!(matches!(
        d.verifier(std::path::Path::new(".")),
        Err(sb_indexer::DeploymentError::VkMismatch { .. })
    ));
}
