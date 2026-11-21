//! Seed corpora for the fuzz targets: one well-formed input of each shape a
//! parser accepts, so a campaign starts on the accepting paths instead of
//! having to find them. `cargo run --example seeds` from `fuzz/` writes
//! them under `seeds/<target>/`, which a run reads beside its working corpus.
use std::fs;
use std::path::Path;

use bitcoin::ScriptBuf;
use bitcoin::consensus::serialize;
use ff::Field;
use group::prime::PrimeCurveAffine;
use pasta_curves::{pallas, vesta};
use sb_common::carrier::{carrier_output, envelope_tapscript, memo_output};
use sb_common::chain::mock::{carrier_tx, carrier_tx_with_memo, carrier_tx_witness, mint_tx};
use sb_primitives::Fr;
use sba_primitives::Fp;
use sba_replay::capture::{Capture, Event};
use sba_replay::persist::{ChainState, ClientState};
use sba_replay::wire::ProvenStep;

fn put(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new("seeds").join(target);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

fn with_sel(sel: u8, b: &[u8]) -> Vec<u8> {
    let mut v = vec![sel];
    v.extend_from_slice(b);
    v
}

fn capture<C: halo2_proofs_curve::CurveAffine>(g: C, s: impl Fn(u64) -> C::Scalar) -> Capture<C> {
    Capture {
        instance: vec![s(1), s(2)],
        events: vec![
            Event::CommonPoint(g),
            Event::CommonScalar(s(3)),
            Event::ReadPoint(g),
            Event::ReadScalar(s(4)),
            Event::Squeeze(s(5)),
        ],
        terms: vec![(s(6), g), (s(7), g)],
        w_scalar: s(8),
        u_scalar: s(9),
        g,
        u: vec![s(10), s(11), s(12)],
        opened: vec![vec![s(13), s(14), s(15)]],
    }
}

mod halo2_proofs_curve {
    pub use pasta_curves::arithmetic::CurveAffine;
}

fn main() {
    // --- the paper family's envelopes
    let s_keys = sb_core::keys::WalletKeys::from_seed(&sb_core::keys::Seed([1u8; 32]));
    let (_, s_addr) = s_keys.ivk.find_address(0);
    let s_note = sb_core::note::NotePlaintext {
        value: 5_000,
        d: s_addr.d,
        rseed: Fr::from(9u64),
    };
    let (pk_eph, ct) = sb_core::note::encrypt_note(&s_note, &s_addr.pk_d).unwrap();
    let s_body = sb_core::envelope::TransferBody {
        h_anchor: 1234,
        nullifiers: [Fr::from(1u64), Fr::from(2u64)],
        pk_eph: [pk_eph, pk_eph],
        ct_note: [ct.clone(), ct],
        ct_out: [3u8; sb_core::recovery::CT_OUT_LEN],
    };
    let s_transfer = sb_core::envelope::TransferEnvelope {
        body: s_body.clone(),
        proof: [4u8; sb_core::envelope::PROOF_LEN],
    };
    let s_mint = sb_core::envelope::MintEnvelope {
        note: s_note,
        pk_d: s_addr.pk_d,
    };
    let s_swap = sb_core::envelope::SwapEnvelope {
        body: sb_core::envelope::SwapBody {
            base: s_body,
            h_aux: [Fr::from(0u64), Fr::from(7u64)],
        },
        proof: [4u8; sb_core::envelope::PROOF_LEN],
    };
    put("envelope_s", "transfer", &s_transfer.to_bytes());
    put("envelope_s", "mint", &s_mint.to_bytes());
    put("envelope_s", "swap", &s_swap.to_bytes());

    // --- variant A's
    let a_keys = sba_core::keys::WalletKeys::from_seed(&sba_core::keys::Seed([1u8; 32]));
    let (_, a_addr) = a_keys.ivk.find_address(0);
    let a_note = sba_core::note::NotePlaintext {
        value: 5_000,
        d: a_addr.d,
        rseed: Fp::from(9u64),
    };
    let (a_pk_eph, a_ct) = sba_core::note::encrypt_note(&a_note, &a_addr.pk_d).unwrap();
    let a_body = sba_core::envelope::TransferBody {
        h_anchor: 1234,
        nullifiers: [Fp::from(1u64), Fp::from(2u64)],
        pk_eph: [a_pk_eph, a_pk_eph],
        ct_note: [a_ct.clone(), a_ct],
        ct_out: [3u8; sba_core::recovery::CT_OUT_LEN],
    };
    let a_transfer = sba_core::envelope::TransferEnvelope {
        body: a_body,
        proof: vec![4u8; sba_core::envelope::PROOF_LEN],
    };
    let a_mint = sba_core::envelope::MintEnvelope {
        note: a_note,
        pk_d: a_addr.pk_d,
    };
    put("envelope_a", "transfer", &a_transfer.to_bytes());
    put("envelope_a", "mint", &a_mint.to_bytes());

    // --- carrier scripts and transactions
    let key = {
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
        Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[0x42u8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0
    };
    let memo = sb_wallet::payout::build_payout_memo(1_000, &[0x00, 0x14, 0x11, 0x22, 0x33]);
    put(
        "carrier_script",
        "opreturn_s",
        &with_sel(
            0,
            carrier_output(&s_transfer.to_bytes())
                .script_pubkey
                .as_bytes(),
        ),
    );
    put(
        "carrier_script",
        "opreturn_a_memo",
        &with_sel(
            1 | 4,
            carrier_output(&a_transfer.to_bytes())
                .script_pubkey
                .as_bytes(),
        ),
    );
    put(
        "carrier_script",
        "opreturn_twice",
        &with_sel(
            2,
            carrier_output(&s_mint.to_bytes()).script_pubkey.as_bytes(),
        ),
    );
    put(
        "carrier_script",
        "tapscript_s",
        &with_sel(
            8,
            envelope_tapscript(&s_transfer.to_bytes(), &key).as_bytes(),
        ),
    );
    put(
        "carrier_script",
        "tapscript_a_annex",
        &with_sel(
            1 | 8 | 16,
            envelope_tapscript(&a_transfer.to_bytes(), &key).as_bytes(),
        ),
    );
    put(
        "carrier_script",
        "memo",
        &with_sel(0, memo_output(&memo).script_pubkey.as_bytes()),
    );
    let vault = ScriptBuf::from_bytes(vec![0x51]);
    put(
        "carrier_tx",
        "opreturn",
        &serialize(&carrier_tx(&s_transfer.to_bytes(), 1)),
    );
    put(
        "carrier_tx",
        "opreturn_memo",
        &serialize(&carrier_tx_with_memo(&a_transfer.to_bytes(), &memo, 2)),
    );
    put(
        "carrier_tx",
        "mint",
        &serialize(&mint_tx(&s_mint.to_bytes(), &vault, 5_000, 3)),
    );
    put(
        "carrier_tx",
        "witness",
        &serialize(&carrier_tx_witness(
            &a_transfer.to_bytes(),
            4,
            vec![memo_output(&memo)],
        )),
    );

    // --- a proven step, version 2 and version 1
    let st = sba_core::batch::SlotStatement {
        h_anchor: 7,
        r_anchor: Fp::from(8u64),
        nullifiers: [Fp::from(9u64), Fp::from(10u64)],
        pk_eph: [sba_core::xy(&sba_primitives::Affine::generator()); 2],
        ct: [sba_core::note::NoteCiphertext {
            c0: Fp::from(1u64),
            c1: Fp::from(2u64),
            tag: Fp::from(3u64),
        }; 2],
        h_body: Fp::from(14u64),
        mint: false,
    };
    let step = ProvenStep {
        first_height: 1001,
        height: 1003,
        slots: vec![Some(st), None],
        opening_after: sba_core::batch::StateOpening {
            root: Fp::from(1u64),
            size: 2,
            nf_root: Fp::from(3u64),
            nf_size: 4,
            h_root: Fp::from(5u64),
            height: 1004,
            applied: 0,
        },
        instance_q: vec![vesta::Base::from(11u64), -vesta::Base::ONE],
        proof_q: vec![1, 2, 3],
        instance_p: vec![
            Fp::from(12u64),
            Fp::from(13u64),
            Fp::from(14u64),
            Fp::from(15u64),
        ],
        proof_p: vec![4, 5],
    };
    let bytes = step.to_bytes();
    put("proven_step", "v2", &bytes);
    let mut v1 = bytes.clone();
    v1[0] = 1;
    v1.drain(4..8);
    put("proven_step", "v1", &v1);

    // --- the persisted states
    let cap_q = capture(pallas::Affine::generator(), pallas::Scalar::from);
    let cap_p = capture(vesta::Affine::generator(), vesta::Scalar::from);
    put("persist", "capture_q", &cap_q.to_bytes());
    put("persist", "capture_p", &cap_p.to_bytes());
    put(
        "persist",
        "client",
        &ClientState {
            keys_id: [1u8; 32],
            index: 3,
            s: Fp::from(5u64),
        }
        .to_bytes(),
    );
    put(
        "persist",
        "chain",
        &ChainState {
            keys_id: [1u8; 32],
            index: 3,
            next_height: 1004,
            s: Fp::from(5u64),
            cap_q,
            cap_p,
        }
        .to_bytes(),
    );

    // --- codecs
    put(
        "codecs",
        "fr",
        &with_sel(0, &sb_primitives::encoding::fr_to_bytes(&Fr::from(77u64))),
    );
    put(
        "codecs",
        "point_s",
        &with_sel(1, &sb_primitives::encoding::point_to_bytes(&s_addr.pk_d)),
    );
    put(
        "codecs",
        "point_a",
        &with_sel(1, &sba_primitives::encoding::point_to_bytes(&a_addr.pk_d)),
    );
    put(
        "codecs",
        "ct_s",
        &with_sel(2, &s_transfer.body.ct_note[0].to_bytes()),
    );
    put(
        "codecs",
        "ct_a",
        &with_sel(2, &a_transfer.body.ct_note[0].to_bytes()),
    );
    put("codecs", "address_s", &with_sel(3, &s_addr.to_bytes()));
    put("codecs", "address_a", &with_sel(3, &a_addr.to_bytes()));
    put(
        "codecs",
        "bech32_s",
        &with_sel(
            4,
            s_addr.encode(sb_core::address::Network::Signet).as_bytes(),
        ),
    );
    put(
        "codecs",
        "bech32_a",
        &with_sel(
            5,
            a_addr.encode(sba_core::address::Network::Signet).as_bytes(),
        ),
    );

    // --- strings
    put("strings", "memo", &with_sel(0, &memo));
    put("strings", "proxy", &with_sel(1, b"socks5://localhost:9050"));
    put(
        "strings",
        "outpoint",
        &with_sel(1, format!("{}:1", "ab".repeat(32)).as_bytes()),
    );
    for (name, sel) in [
        ("signet-dev-2", 2u8),
        ("signet-a-2", 3u8),
        ("localsignet-dev", 2u8),
    ] {
        let json = fs::read(Path::new("../deployments").join(format!("{name}.json"))).unwrap();
        put("strings", name, &with_sel(sel, &json));
    }

    // --- state files
    put(
        "state_json",
        "empty_s",
        &with_sel(0, sb_indexer::ReplayState::new().to_json().as_bytes()),
    );
    put(
        "state_json",
        "empty_a",
        &with_sel(1, sba_indexer::ReplayState::new().to_json().as_bytes()),
    );

    // --- the indexer grammars take any bytes (`arbitrary`): three
    // deterministic strings of different lengths to start from
    for (name, len, step) in [
        ("short", 24usize, 7u8),
        ("medium", 160, 13),
        ("long", 900, 29),
    ] {
        let bytes: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(step) ^ (i >> 3) as u8)
            .collect();
        put("indexer_s", name, &bytes);
        put("indexer_a", name, &bytes);
        put("wallet_s", name, &bytes);
        put("wallet_a", name, &bytes);
    }

    // --- http
    put(
        "http_request",
        "post",
        b"POST /submit HTTP/1.1\r\nHost: relay\r\nContent-Length: 2\r\n\r\n{}",
    );
    put("http_request", "get", b"GET /state HTTP/1.1\r\n\r\n");
    println!("seeds written under seeds/");
}
