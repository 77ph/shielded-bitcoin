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

    /// Build and sign a transaction paying `outputs` plus change; the fee is
    /// taken from the funding UTXOs. `fee_rate` in sat/vB.
    pub fn build_tx(
        &self,
        utxos: &[Utxo],
        outputs: Vec<TxOut>,
        fee_rate: u64,
    ) -> Result<Transaction> {
        let target: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
        let out_bytes: u64 = outputs
            .iter()
            .map(|o| 9 + o.script_pubkey.len() as u64)
            .sum();
        // confirmed first, then largest first
        let mut sorted: Vec<&Utxo> = utxos.iter().collect();
        sorted.sort_by(|a, b| b.confirmed.cmp(&a.confirmed).then(b.value.cmp(&a.value)));
        let mut inputs: Vec<&Utxo> = Vec::new();
        let mut total = 0u64;
        let mut fee = 0u64;
        for u in sorted {
            inputs.push(u);
            total += u.value;
            // P2WPKH input ≈ 68 vB, change output 31 vB, overhead ≈ 11 vB
            let vbytes = 11 + 68 * inputs.len() as u64 + out_bytes + 31;
            fee = vbytes * fee_rate;
            if total >= target + fee + 546 {
                break;
            }
        }
        if inputs.is_empty() {
            bail!(
                "funding address {} has no confirmed coins; fund it first",
                self.address
            );
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
        let mut output = outputs;
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

/// Smallest output this tool will create or pay (Bitcoin Core's dust limit for
/// P2WPKH is 294 sat; 546 covers every standard script type).
pub const DUST_LIMIT: u64 = 546;

/// Where UTXOs are looked up and transactions are broadcast.
pub trait Publisher {
    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>>;
    fn broadcast(&self, tx: &Transaction) -> Result<Txid>;
}

/// Esplora HTTP (`/address/:addr/utxo`, `POST /tx`).
pub struct EsploraPublisher {
    base: String,
}

impl EsploraPublisher {
    pub fn new(base: &str) -> Self {
        EsploraPublisher {
            base: base.trim_end_matches('/').to_string(),
        }
    }
}

impl Publisher for EsploraPublisher {
    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>> {
        let url = format!("{}/address/{}/utxo", self.base, address);
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

    fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let hex = bitcoin::consensus::encode::serialize_hex(tx);
        let url = format!("{}/tx", self.base);
        let resp = ureq::post(&url).send_string(&hex).map_err(|e| match e {
            // Esplora answers policy rejections (dust, fee, missing inputs…) with 400 and a text body.
            ureq::Error::Status(code, r) => {
                anyhow!(
                    "broadcast rejected ({code}): {}",
                    r.into_string().unwrap_or_default().trim()
                )
            }
            other => anyhow!("broadcast: {other}"),
        })?;
        let txid = resp.into_string()?;
        txid.trim().parse().context("txid")
    }
}

/// Bitcoin Core RPC without a node wallet: `scantxoutset` for UTXOs (confirmed
/// only) and `sendrawtransaction`.
pub struct RpcPublisher {
    pub rpc: sb_indexer::chain::rpc::BitcoinCoreRpc,
}

impl Publisher for RpcPublisher {
    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>> {
        let desc = format!("addr({address})");
        let res = self
            .rpc
            .call("scantxoutset", serde_json::json!(["start", [desc]]))
            .map_err(|e| anyhow!("scantxoutset: {e}"))?;
        let mut out = Vec::new();
        for u in res["unspents"].as_array().cloned().unwrap_or_default() {
            let txid: Txid = u["txid"].as_str().context("txid")?.parse()?;
            let vout = u["vout"].as_u64().context("vout")? as u32;
            let amount = Amount::from_btc(u["amount"].as_f64().context("amount")?)?;
            out.push(Utxo {
                outpoint: OutPoint { txid, vout },
                value: amount.to_sat(),
                confirmed: true,
            });
        }
        Ok(out)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let hex = bitcoin::consensus::encode::serialize_hex(tx);
        let res = self
            .rpc
            .call("sendrawtransaction", serde_json::json!([hex]))
            .map_err(|e| anyhow!("sendrawtransaction: {e}"))?;
        res.as_str().context("txid")?.parse().context("txid")
    }
}
