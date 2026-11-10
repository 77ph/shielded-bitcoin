//! A test world for the family's replay: a deployment on a mock chain,
//! two wallets, mints paid to a vault and transfers proven with the Halo 2
//! circuit. The indexer's own tests and the accumulated replay proof's
//! experiments drive it (`features = ["testing"]`).

use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use ff::Field;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use sb_common::carrier::{CarrierMode, carrier_output};
use sba_circuit::{
    InputWitness, OutputWitness, TransferParams, TransferStatement, TransferWitness,
};
use sba_core::address::Network;
use sba_core::envelope::{MintEnvelope, TransferBody, TransferEnvelope};
use sba_core::keys::{Seed, WalletKeys};
use sba_core::note::{NotePlaintext, encrypt_note, nullifier};
use sba_core::recovery::{RecoveryEntry, binding_digest, encrypt_recovery};
use sba_primitives::Fp;

use crate::{Deployment, DevBoundary, Indexer, ReplayState};

pub use sb_common::chain::mock::MockChain;

pub const ACTIVATION: u32 = 1000;

pub fn vault_script() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![
        0x00, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
    ])
}

pub fn tx_with(outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: outputs,
    }
}

pub struct World {
    pub deployment: Deployment,
    pub params: TransferParams,
    pub alice: WalletKeys,
    pub bob: WalletKeys,
    pub rng: ChaCha20Rng,
}

impl World {
    pub fn new() -> Self {
        let params = TransferParams::build().unwrap();
        let deployment = Deployment {
            profile: sba_core::PROFILE_VERSION.into(),
            family: sba_core::FAMILY.into(),
            name: "mock-a".into(),
            network: Network::Regtest,
            activation_height: ACTIVATION,
            const_salt: Deployment::derive_const_salt("mock-a"),
            transfer_k: sba_circuit::K,
            transfer_vk_id: params.vk_id(),
            window_w: 5,
            k_min: 1,
            anchor_depth: 3,
            boundary: Some(DevBoundary {
                vault_script_hex: hex::encode(vault_script().as_bytes()),
                operator_address: None,
            }),
            carrier: CarrierMode::OpReturn,
        };
        World {
            deployment,
            params,
            alice: WalletKeys::from_seed(&Seed([1u8; 32])),
            bob: WalletKeys::from_seed(&Seed([2u8; 32])),
            rng: ChaCha20Rng::from_seed([7u8; 32]),
        }
    }

    pub fn indexer(&self) -> Indexer {
        Indexer::new(
            self.deployment.clone(),
            self.deployment.verifier().unwrap(),
            ReplayState::new(),
        )
    }

    pub fn mint_tx(
        &mut self,
        to: &sba_core::address::PaymentAddress,
        value: u64,
    ) -> (Transaction, MintEnvelope) {
        let env = MintEnvelope {
            note: NotePlaintext {
                value,
                d: to.d,
                rseed: Fp::random(&mut self.rng),
            },
            pk_d: to.pk_d,
        };
        let tx = tx_with(vec![
            carrier_output(&env.to_bytes()),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: vault_script(),
            },
        ]);
        (tx, env)
    }

    /// Alice spends `input` (or a dummy) to `outputs`, anchored at `h_anchor`.
    pub fn transfer(
        &mut self,
        idx: &Indexer,
        h_anchor: u32,
        input: Option<(NotePlaintext, Fp, u64, u64)>, // note, h_body_create, j, pos
        outputs: [(sba_core::address::PaymentAddress, u64); 2],
    ) -> TransferEnvelope {
        self.transfer_full(idx, h_anchor, input, outputs).0
    }

    /// [`transfer`](Self::transfer) with the circuit's statement and witness
    /// too (for proving the same transfer again, under another transcript).
    pub fn transfer_full(
        &mut self,
        idx: &Indexer,
        h_anchor: u32,
        input: Option<(NotePlaintext, Fp, u64, u64)>,
        outputs: [(sba_core::address::PaymentAddress, u64); 2],
    ) -> (TransferEnvelope, TransferStatement, TransferWitness) {
        let size = idx.state.size_at(h_anchor).expect("anchor replayed");
        let r_anchor = idx.root_at(h_anchor).unwrap();
        let (_, a_dummy) = self.alice.ivk.find_address(5);
        let in0 = match input {
            Some((note, hb, j, pos)) => {
                let path = idx.state.tree.path_at(pos, size).unwrap();
                InputWitness {
                    note,
                    h_body_create: hb,
                    output_index: j,
                    pos,
                    siblings: path.siblings,
                }
            }
            None => InputWitness::dummy(a_dummy.d, Fp::random(&mut self.rng)),
        };
        let in1 = InputWitness::dummy(a_dummy.d, Fp::random(&mut self.rng));
        let outs = outputs.map(|(addr, v)| OutputWitness {
            note: NotePlaintext {
                value: v,
                d: addr.d,
                rseed: Fp::random(&mut self.rng),
            },
            pk_d: addr.pk_d,
        });
        let (e0, c0) = encrypt_note(&outs[0].note, &outs[0].pk_d).unwrap();
        let (e1, c1) = encrypt_note(&outs[1].note, &outs[1].pk_d).unwrap();
        let digest = binding_digest(&[e0, e1], &[c0, c1]);
        let ct_out = encrypt_recovery(
            &self.alice.ovk,
            &digest,
            &[
                RecoveryEntry {
                    pk_d: outs[0].pk_d,
                    sk_eph: outs[0].note.sk_eph(),
                },
                RecoveryEntry {
                    pk_d: outs[1].pk_d,
                    sk_eph: outs[1].note.sk_eph(),
                },
            ],
        );
        let nullifiers = [
            nullifier(&self.alice.sk_nf, &in0.note.rho(), in0.pos),
            nullifier(&self.alice.sk_nf, &in1.note.rho(), in1.pos),
        ];
        let body = TransferBody {
            h_anchor,
            nullifiers,
            pk_eph: [e0, e1],
            ct_note: [c0, c1],
            ct_out,
        };
        let st = TransferStatement {
            const_salt: self.deployment.const_salt_fp(),
            r_anchor,
            nullifiers,
            pk_eph: [e0, e1],
            ct_note: [c0, c1],
            h_body: body.h_body(&self.deployment.const_salt),
        };
        let w = TransferWitness {
            sk_spend: self.alice.sk_spend,
            inputs: [in0, in1],
            outputs: outs,
        };
        let proof = self.params.prove(&st, &w, &mut self.rng).unwrap();
        (TransferEnvelope { body, proof }, st, w)
    }
}
