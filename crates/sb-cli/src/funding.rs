//! Transparent funding wallet for carrier transactions: one P2WPKH key
//! derived from the shielded wallet seed, UTXOs and broadcast through
//! Esplora. Fee inputs link carriers at the Bitcoin layer (paper §20.5);
//! this is a development convenience, not a privacy feature.

use anyhow::{Context, Result, anyhow, bail};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;

pub struct FundingKey {
    sk: SecretKey,
    pk: CompressedPublicKey,
    pub address: Address,
}

#[derive(Debug, Deserialize)]
struct EsploraUtxo {
    txid: String,
    vout: u32,
    value: u64,
    status: EsploraStatus,
}

#[derive(Debug, Deserialize)]
struct EsploraStatus {
    confirmed: bool,
}

#[derive(Clone, Debug)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub confirmed: bool,
}

impl FundingKey {
    /// `HKDF-SHA256(seed, "sb/v1/funding")` → secp256k1 secret key.
    pub fn from_seed(seed: &[u8; 32], network: Network) -> Result<Self> {
        let mut raw = [0u8; 32];
        Hkdf::<Sha256>::new(None, seed)
            .expand(b"sb/v1/funding", &mut raw)
            .unwrap();
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&raw).context("funding key")?;
        let pk = CompressedPublicKey(sk.public_key(&secp));
        let address = Address::p2wpkh(&pk, network);
        Ok(FundingKey { sk, pk, address })
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address.script_pubkey()
    }

    /// Confirmed and unconfirmed UTXOs of the funding address via Esplora.
    pub fn utxos(&self, esplora: &str) -> Result<Vec<Utxo>> {
        let url = format!(
            "{}/address/{}/utxo",
            esplora.trim_end_matches('/'),
            self.address
        );
        let list: Vec<EsploraUtxo> = ureq::get(&url)
            .call()
            .context("esplora utxo")?
            .into_json()?;
        list.into_iter()
            .map(|u| {
                Ok(Utxo {
                    outpoint: OutPoint {
                        txid: u.txid.parse::<Txid>()?,
                        vout: u.vout,
                    },
                    value: u.value,
                    confirmed: u.status.confirmed,
                })
            })
            .collect()
    }

    /// Build and sign a carrier transaction: `extra` outputs (e.g. the vault
    /// payment) + the OP_RETURN carrier + change. `fee_rate` in sat/vB.
    pub fn build_carrier(
        &self,
        utxos: &[Utxo],
        mut extra: Vec<TxOut>,
        carrier: TxOut,
        fee_rate: u64,
    ) -> Result<Transaction> {
        let target: u64 = extra.iter().map(|o| o.value.to_sat()).sum();
        // confirmed first, then largest first
        let mut sorted: Vec<&Utxo> = utxos.iter().collect();
        sorted.sort_by(|a, b| b.confirmed.cmp(&a.confirmed).then(b.value.cmp(&a.value)));
        let mut inputs: Vec<&Utxo> = Vec::new();
        let mut total = 0u64;
        let mut fee = 0u64;
        for u in sorted {
            inputs.push(u);
            total += u.value;
            // P2WPKH input ≈ 68 vB, each output ≈ 31 vB (+ data), overhead ≈ 11 vB
            let vbytes = 11
                + 68 * inputs.len() as u64
                + 31 * (extra.len() as u64 + 1)
                + 9
                + carrier.script_pubkey.len() as u64;
            fee = vbytes * fee_rate;
            if total >= target + fee + 546 {
                break;
            }
        }
        if total < target + fee {
            bail!(
                "funding address {} holds {} sat; need {} + fee {}",
                self.address,
                total,
                target,
                fee
            );
        }
        let change = total - target - fee;
        let mut output = std::mem::take(&mut extra);
        output.push(carrier);
        if change >= 546 {
            output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: self.script_pubkey(),
            });
        }
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|u| TxIn {
                    previous_output: u.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output,
        };
        let secp = Secp256k1::new();
        let spk = self.script_pubkey();
        let mut cache = SighashCache::new(tx.clone());
        for (i, u) in inputs.iter().enumerate() {
            let sighash = cache
                .p2wpkh_signature_hash(i, &spk, Amount::from_sat(u.value), EcdsaSighashType::All)
                .context("sighash")?;
            let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &self.sk);
            let sig = bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            };
            tx.input[i].witness = Witness::p2wpkh(&sig, &self.pk.0);
        }
        Ok(tx)
    }
}

/// `POST /tx` with the raw hex; returns the txid.
pub fn broadcast(esplora: &str, tx: &Transaction) -> Result<Txid> {
    let hex = bitcoin::consensus::encode::serialize_hex(tx);
    let url = format!("{}/tx", esplora.trim_end_matches('/'));
    let resp = ureq::post(&url)
        .send_string(&hex)
        .map_err(|e| anyhow!("broadcast: {e}"))?;
    let txid = resp.into_string()?;
    txid.trim().parse().context("txid")
}
