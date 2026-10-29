//! Replay under the witness carrier (`docs/WITNESS-CARRIER.md`): envelopes
//! in tapscripts are accepted, OP_RETURN carriers are ignored, and the
//! other way round for an OP_RETURN deployment; the dev mint's vault
//! output lives in the reveal transaction.

use bitcoin::{Amount, ScriptBuf, TxOut};
use sb_circuit::{TransferParams, TransferVerifier, vk_sha256};
use sb_core::address::Network;
use sb_core::envelope::MintEnvelope;
use sb_core::keys::{Seed, WalletKeys};
use sb_core::note::NotePlaintext;
use sb_indexer::carrier::CarrierMode;
use sb_indexer::chain::mock::{MockChain, carrier_tx, carrier_tx_witness, mint_tx};
use sb_indexer::deployment::DevBoundary;
use sb_indexer::{Deployment, Indexer, ReplayState, Setup};
use sb_primitives::Fr;
use sb_wallet::{Recipient, build_transfer, scan_incoming};

#[test]
fn witness_and_op_return_deployments_see_only_their_own_carriers() {
    let params = TransferParams::insecure_setup(&[0u8; 32]).unwrap();
    let vault = ScriptBuf::from_bytes(vec![0x51]);
    let mut deployment = Deployment {
        profile: sb_core::PROFILE_VERSION.into(),
        name: "wit".into(),
        network: Network::Regtest,
        activation_height: 10,
        const_salt: Deployment::derive_const_salt("wit"),
        transfer_vk_sha256: vk_sha256(params.vk()),
        setup: Setup::InsecureSeed { seed: [0u8; 32] },
        window_w: 100,
        anchor_depth: 3,
        k_min: 1,
        boundary: Some(DevBoundary {
            vault_script_hex: "51".into(),
            operator_address: None,
        }),
        swap: None,
        carrier: CarrierMode::Witness,
    };
    let salt = deployment.const_salt_fr();
    let keys = WalletKeys::from_seed(&Seed([5u8; 32]));
    let (_, addr) = keys.ivk.find_address(0);
    let mint = MintEnvelope {
        note: NotePlaintext {
            value: 1000,
            d: addr.d,
            rseed: Fr::from(3u64),
        },
        pk_d: addr.pk_d,
    };
    // block 10: the mint in a reveal transaction (vault output in it), and
    // the same mint in an OP_RETURN carrier, which a witness deployment ignores
    let mut chain = MockChain::new(10);
    chain.push_block(vec![
        carrier_tx_witness(
            &mint.to_bytes(),
            1,
            vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: vault.clone(),
            }],
        ),
        mint_tx(&mint.to_bytes(), &vault, 1000, 2),
    ]);
    chain.push_block(vec![]);
    chain.push_block(vec![]);
    let mut idx = Indexer::new(
        deployment.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    let r = idx.sync(&chain).unwrap();
    assert_eq!(
        (r.accepted, r.rejected),
        (1, 0),
        "one mint, the OP_RETURN one unseen"
    );
    assert!(idx.is_carrier(&chain.blocks()[0].txdata[1]));
    assert!(!idx.is_carrier(&chain.blocks()[0].txdata[2]));
    // a transfer in the witness, spending the minted note
    let mine: Vec<_> = idx
        .state
        .events
        .iter()
        .flat_map(|e| scan_incoming(&keys.ivk, &salt, e))
        .collect();
    assert_eq!(mine.len(), 1);
    let built = build_transfer(
        &params,
        &keys,
        &deployment.const_salt,
        &idx.state.tree,
        11,
        idx.state.size_at(11).unwrap(),
        &[sb_wallet::SpendableNote {
            note: mine[0].note,
            h_body_create: mine[0].h_body_create,
            output_index: mine[0].output_index,
            pos: mine[0].pos,
        }],
        &[Recipient {
            address: addr,
            value: 1000,
        }],
        &mut rand::thread_rng(),
    )
    .unwrap();
    chain.push_block(vec![
        carrier_tx(&built.envelope.to_bytes(), 3),
        carrier_tx_witness(&built.envelope.to_bytes(), 4, vec![]),
    ]);
    let r = idx.sync(&chain).unwrap();
    assert_eq!((r.accepted, r.rejected), (1, 0));
    assert_eq!(
        idx.state.events.last().unwrap().tx_index,
        2,
        "the reveal, not the OP_RETURN one"
    );
    // an OP_RETURN deployment over the same chain sees the other two carriers
    deployment.carrier = CarrierMode::OpReturn;
    deployment.name = "opr".into();
    let mut opr = Indexer::new(
        deployment.clone(),
        TransferVerifier::new(params.vk().clone()),
        ReplayState::new(),
    );
    let r = opr.sync(&chain).unwrap();
    // same const_salt, so the OP_RETURN mint makes the same leaf and the
    // OP_RETURN transfer is valid for it too; the witness carriers are unseen
    assert_eq!((r.accepted, r.rejected), (2, 0));
    assert_eq!(
        opr.state.events[0].tx_index, 2,
        "the OP_RETURN mint, not the reveal"
    );
    assert_eq!(opr.state.events[1].tx_index, 1, "the OP_RETURN transfer");
    // the profile round-trips its carrier and defaults to OP_RETURN
    let json = deployment.to_json();
    assert!(json.contains("\"carrier\": \"op-return\""));
    let mut d2 = Deployment::from_json(&json).unwrap();
    assert_eq!(d2.carrier, CarrierMode::OpReturn);
    d2.carrier = CarrierMode::Witness;
    assert!(d2.to_json().contains("\"witness\""));
    let without: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut without = without.as_object().unwrap().clone();
    without.remove("carrier");
    let d3 = Deployment::from_json(&serde_json::to_string(&without).unwrap()).unwrap();
    assert_eq!(d3.carrier, CarrierMode::OpReturn);
}
