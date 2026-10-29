//! The swap extension through replay (`docs/SWAP.md` §8–§9): X locks a
//! note to Y, Y claims it with the preimage (or X refunds it after the
//! refund height), every rejection that keeps the mixed endings impossible,
//! a deployment without the extension, and state persistence.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_circuit::{SwapParams, SwapVerifier, TransferParams, TransferVerifier, vk_sha256};
use sb_core::address::Network;
use sb_core::event::EventKind;
use sb_core::keys::{Seed, WalletKeys};
use sb_core::lock::{LockOpening, Secret};
use sb_core::note::{NotePlaintext, nullifier_locked};
use sb_indexer::chain::mock::{MockChain, carrier_tx, mint_tx};
use sb_indexer::deployment::{DevBoundary, SwapDeployment};
use sb_indexer::{Deployment, Indexer, ReplayState, Setup};
use sb_primitives::Fr;
use sb_wallet::{
    BuildError, Recipient, SpendableNote, SwapInput, SwapOutput, build_swap_transfer,
    build_transfer, scan_incoming, scan_outgoing,
};

const ACT: u32 = 100;
const T_REFUND: u32 = 120;

struct World {
    params: TransferParams,
    swap_params: SwapParams,
    deployment: Deployment,
    x: WalletKeys,
    y: WalletKeys,
}

fn world() -> World {
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let swap_params = SwapParams::insecure_setup(&[0u8; 32]).unwrap();
    let deployment = Deployment {
        profile: sb_core::PROFILE_VERSION.into(),
        name: "swap-test".into(),
        network: Network::Regtest,
        activation_height: ACT,
        const_salt: Deployment::derive_const_salt("swap-test"),
        transfer_vk_sha256: vk_sha256(params.vk()),
        setup: Setup::InsecureSeed { seed: [0u8; 32] },
        window_w: 100,
        k_min: 1,
        boundary: Some(DevBoundary {
            vault_script_hex: "51".into(),
            operator_address: None,
        }),
        swap: Some(SwapDeployment {
            vk_sha256: vk_sha256(swap_params.vk()),
            setup: Setup::InsecureSeed { seed: [0u8; 32] },
        }),
        carrier: Default::default(),
    };
    World {
        params,
        swap_params,
        deployment,
        x: WalletKeys::from_seed(&Seed([21u8; 32])),
        y: WalletKeys::from_seed(&Seed([22u8; 32])),
    }
}

fn indexer(w: &World, with_swap: bool) -> Indexer {
    let idx = Indexer::new(
        w.deployment.clone(),
        TransferVerifier::new(w.params.vk().clone()),
        ReplayState::new(),
    );
    if with_swap {
        idx.with_swap_verifier(SwapVerifier::new(w.swap_params.vk().clone()))
    } else {
        idx
    }
}

/// Blocks ACT..=ACT+2: a mint of 1000 to X at ACT, two empty blocks.
fn chain_with_mint(w: &World) -> (MockChain, NotePlaintext) {
    let (_, x_addr) = w.x.ivk.find_address(0);
    let note = NotePlaintext {
        value: 1000,
        d: x_addr.d,
        rseed: Fr::from(5u64),
    };
    let mint = sb_core::envelope::MintEnvelope {
        note,
        pk_d: x_addr.pk_d,
    };
    let vault = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    let mut chain = MockChain::new(ACT);
    chain.push_block(vec![mint_tx(&mint.to_bytes(), &vault, 1000, 1)]);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    (chain, note)
}

fn spendable(idx: &Indexer, keys: &WalletKeys, salt: &Fr) -> Vec<(SpendableNote, Fr)> {
    let mut out = Vec::new();
    for ev in &idx.state.events {
        for r in scan_incoming(&keys.ivk, salt, ev) {
            out.push((
                SpendableNote {
                    note: r.note,
                    h_body_create: r.h_body_create,
                    output_index: r.output_index,
                    pos: r.pos,
                },
                r.h_aux,
            ));
        }
    }
    out
}

/// X locks 700 to Y (change 300) at anchor ACT+1, carrier in block ACT+3.
fn lock(w: &World, idx: &Indexer, chain: &mut MockChain, secret: &Secret) -> (LockOpening, Fr) {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let salt = w.deployment.const_salt_fr();
    let (_, x_addr) = w.x.ivk.find_address(0);
    let (_, y_addr) = w.y.ivk.find_address(0);
    let opening = LockOpening {
        hash: secret.hash(),
        pk_refund: x_addr.pk_d,
        t_refund: T_REFUND,
    };
    let mine = spendable(idx, &w.x, &salt);
    assert_eq!(mine.len(), 1);
    let anchor = ACT + 1;
    let built = build_swap_transfer(
        &w.swap_params,
        &w.x,
        &w.deployment.const_salt,
        &idx.state.tree,
        anchor,
        idx.state.size_at(anchor).unwrap(),
        &[SwapInput::Plain(mine[0].0.clone())],
        &[
            SwapOutput {
                recipient: Recipient {
                    address: y_addr,
                    value: 700,
                },
                lock: Some(opening),
            },
            SwapOutput {
                recipient: Recipient {
                    address: x_addr,
                    value: 300,
                },
                lock: None,
            },
        ],
        &mut rng,
    )
    .unwrap();
    assert_eq!(built.h_aux[0], opening.commitment());
    assert_eq!(built.h_aux[1], Fr::from(0u64));
    chain.push_block(vec![carrier_tx(&built.envelope.to_bytes(), 7)]);
    (opening, built.statement.base.h_body)
}

#[test]
fn lock_claim_refund_and_rejections() {
    let w = world();
    let salt = w.deployment.const_salt_fr();
    let secret = Secret::random(&mut ChaCha20Rng::from_seed([9u8; 32]));
    let (_, x_addr) = w.x.ivk.find_address(0);
    let (_, y_addr) = w.y.ivk.find_address(0);

    // ---- X locks ----
    let (mut chain, _) = chain_with_mint(&w);
    let mut idx = indexer(&w, true);
    idx.sync(&chain).unwrap();
    let (opening, lock_h_body) = lock(&w, &idx, &mut chain, &secret);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (1, 0));
    let ev = idx.state.events.last().unwrap();
    assert_eq!(ev.kind, EventKind::Swap);
    assert_eq!(ev.h_aux, vec![opening.commitment(), Fr::from(0u64)]);
    assert_eq!(ev.h_body, lock_h_body);
    // Y sees the locked note and its slot; X sees the change and, through
    // ct_out, the locked note it created
    let ys = spendable(&idx, &w.y, &salt);
    assert_eq!(ys.len(), 1);
    assert_eq!(ys[0].0.note.value, 700);
    assert_eq!(ys[0].1, opening.commitment());
    let xs = spendable(&idx, &w.x, &salt);
    assert_eq!(xs.len(), 2, "the mint note and the change");
    let sent = scan_outgoing(&w.x.ovk, &salt, ev).unwrap();
    assert_eq!(sent[0].h_aux, opening.commitment());
    assert_eq!(sent[0].note.value, 700);
    // the state survives JSON persistence with the swap event
    let again = ReplayState::from_json(&idx.state.to_json()).unwrap();
    assert!(again == idx.state);

    // ---- the locked note cannot go through the base relation ----
    let e = build_transfer(
        &w.params,
        &w.y,
        &w.deployment.const_salt,
        &idx.state.tree,
        ACT + 3,
        idx.state.size_at(ACT + 3).unwrap(),
        &[ys[0].0.clone()],
        &[Recipient {
            address: y_addr,
            value: 700,
        }],
        &mut ChaCha20Rng::from_seed([2u8; 32]),
    )
    .unwrap_err();
    assert!(matches!(e, BuildError::LeafMismatch(_)), "{e}");

    // ---- Y claims with the preimage (block ACT+5, anchor ACT+3) ----
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    let claim = |secret: Secret, anchor: u32| {
        build_swap_transfer(
            &w.swap_params,
            &w.y,
            &w.deployment.const_salt,
            &idx.state.tree,
            anchor,
            idx.state.size_at(anchor).unwrap(),
            &[SwapInput::Claim {
                note: ys[0].0.clone(),
                opening,
                secret,
            }],
            &[SwapOutput {
                recipient: Recipient {
                    address: y_addr,
                    value: 700,
                },
                lock: None,
            }],
            &mut ChaCha20Rng::from_seed([3u8; 32]),
        )
        .unwrap()
    };
    let good = claim(secret, ACT + 3);
    assert_eq!(
        good.statement.base.nullifiers[0],
        nullifier_locked(&ys[0].0.note.rho(), ys[0].0.pos)
    );
    // a claim with a wrong preimage proves nothing valid
    let mut wrong = secret;
    wrong.0[0] ^= 1;
    let bad = claim(wrong, ACT + 3);
    let mut chain2 = chain.clone();
    chain2.push_block(vec![carrier_tx(&bad.envelope.to_bytes(), 8)]);
    let mut idx2 = indexer(&w, true);
    idx2.sync(&chain2).unwrap();
    assert!(
        idx2.state
            .rejections
            .iter()
            .any(|r| r.reason.contains("proof")),
        "{:?}",
        idx2.state.rejections
    );
    // the right one is accepted
    chain.push_block(vec![carrier_tx(&good.envelope.to_bytes(), 8)]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (1, 0));
    assert!(
        idx.state
            .nullifiers
            .contains(&good.statement.base.nullifiers[0])
    );

    // ---- X's refund of the same note is now a double spend ----
    chain.push_block(vec![]);
    idx.sync(&chain).unwrap();
    let refund = |idx: &Indexer, anchor: u32| {
        build_swap_transfer(
            &w.swap_params,
            &w.x,
            &w.deployment.const_salt,
            &idx.state.tree,
            anchor,
            idx.state.size_at(anchor).unwrap(),
            &[SwapInput::Refund {
                note: ys[0].0.clone(),
                opening,
                owner: y_addr.pk_d,
                d_refund: x_addr.d,
            }],
            &[SwapOutput {
                recipient: Recipient {
                    address: x_addr,
                    value: 700,
                },
                lock: None,
            }],
            &mut ChaCha20Rng::from_seed([4u8; 32]),
        )
        .unwrap()
    };
    // (a refund needs an anchor ≥ T_REFUND: mine empty blocks up to there)
    while chain.height().unwrap() < T_REFUND + 1 {
        chain.push_block(vec![]);
    }
    idx.sync(&chain).unwrap();
    let late = refund(&idx, T_REFUND);
    chain.push_block(vec![carrier_tx(&late.envelope.to_bytes(), 9)]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (0, 1));
    assert!(
        idx.state
            .rejections
            .last()
            .unwrap()
            .reason
            .contains("already spent")
    );

    // ---- on a fresh history X refunds instead: early is rejected, on time accepted ----
    let (mut chain, _) = chain_with_mint(&w);
    let mut idx = indexer(&w, true);
    idx.sync(&chain).unwrap();
    let (opening, _) = lock(&w, &idx, &mut chain, &secret);
    while chain.height().unwrap() < T_REFUND + 1 {
        chain.push_block(vec![]);
    }
    idx.sync(&chain).unwrap();
    let ys = spendable(&idx, &w.y, &salt);
    let refund_at = |anchor: u32| {
        build_swap_transfer(
            &w.swap_params,
            &w.x,
            &w.deployment.const_salt,
            &idx.state.tree,
            anchor,
            idx.state.size_at(anchor).unwrap(),
            &[SwapInput::Refund {
                note: ys[0].0.clone(),
                opening,
                owner: y_addr.pk_d,
                d_refund: x_addr.d,
            }],
            &[SwapOutput {
                recipient: Recipient {
                    address: x_addr,
                    value: 700,
                },
                lock: None,
            }],
            &mut ChaCha20Rng::from_seed([5u8; 32]),
        )
        .unwrap()
    };
    // the early refund is an unsatisfiable witness: in a debug build the
    // prover's debug_assert panics on it, so this test needs --release
    // (as CI runs it); in release the proof is produced and fails to verify
    let early = refund_at(T_REFUND - 1);
    let on_time = refund_at(T_REFUND);
    chain.push_block(vec![
        carrier_tx(&early.envelope.to_bytes(), 10),
        carrier_tx(&on_time.envelope.to_bytes(), 11),
    ]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (1, 1));
    assert!(
        idx.state
            .rejections
            .last()
            .unwrap()
            .reason
            .contains("proof")
    );
    assert_eq!(idx.state.events.last().unwrap().kind, EventKind::Swap);
    // X got its 700 back
    let xs = spendable(&idx, &w.x, &salt);
    assert!(
        xs.iter()
            .any(|(n, h)| n.note.value == 700 && *h == Fr::from(0u64))
    );

    // ---- a deployment without the extension rejects every swap envelope ----
    let mut plain = indexer(&w, false);
    plain.sync(&chain).unwrap();
    assert_eq!(plain.state.events.len(), 1, "only the mint");
    assert!(
        plain
            .state
            .rejections
            .iter()
            .all(|r| r.reason.contains("no swap extension"))
    );
    // and so does the relayer's check
    assert!(matches!(
        plain.check_transfer(&on_time.envelope.to_bytes(), T_REFUND + 5),
        Err(sb_indexer::RejectReason::SwapDisabled)
    ));
    let fresh = {
        let (mut c, _) = chain_with_mint(&w);
        let mut i = indexer(&w, true);
        i.sync(&c).unwrap();
        let _ = lock(&w, &i, &mut c, &secret);
        while c.height().unwrap() < T_REFUND + 1 {
            c.push_block(vec![]);
        }
        i.sync(&c).unwrap();
        i
    };
    let check = fresh
        .check_transfer(&on_time.envelope.to_bytes(), T_REFUND + 5)
        .unwrap()
        .unwrap();
    assert_eq!(check.nullifiers, on_time.statement.base.nullifiers);

    // ---- the deployment profile round-trips with its swap section ----
    let json = w.deployment.to_json();
    assert!(json.contains("\"swap\""));
    assert_eq!(Deployment::from_json(&json).unwrap(), w.deployment);
    let base_dir = std::path::Path::new(".");
    assert!(w.deployment.swap_verifier(base_dir).unwrap().is_some());
    assert!(w.deployment.swap_params(base_dir).unwrap().is_some());
    let mut no_swap = w.deployment.clone();
    no_swap.swap = None;
    assert!(no_swap.swap_verifier(base_dir).unwrap().is_none());
    let mut wrong_pin = w.deployment.clone();
    wrong_pin.swap.as_mut().unwrap().vk_sha256 = [1u8; 32];
    assert!(wrong_pin.swap_verifier(base_dir).is_err());
    assert!(wrong_pin.swap_params(base_dir).is_err());
}
