//! Transparent fee wallet for carrier transactions (deployment layer,
//! docs/BOUNDARY.md "Fee funding"). Keys are derived from the shielded
//! wallet seed on two chains, receive and change, so no address is used
//! twice; coins are looked up and transactions broadcast through the same
//! backend as `--chain`.
//!
//! Fee inputs still link carriers at the Bitcoin layer through the change
//! chain (paper §20.5); fresh addresses remove address reuse, not that
//! link. The two models that do break it, external funding and a relayer,
//! live in `main.rs` and `relay.rs`.

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

/// One transparent key of the fee wallet.
pub struct FundingKey {
    sk: SecretKey,
    pk: CompressedPublicKey,
    pub address: Address,
}

impl FundingKey {
    /// The compressed public key (a swap's Bitcoin-side key).
    pub fn pubkey(&self) -> CompressedPublicKey {
        self.pk
    }

    /// The key pair, for Schnorr signatures of taproot script paths.
    pub fn keypair(&self) -> bitcoin::secp256k1::Keypair {
        bitcoin::secp256k1::Keypair::from_secret_key(&Secp256k1::new(), &self.sk)
    }

    /// ECDSA over a BIP 143 sighash (for script-path spends such as the
    /// swap HTLC).
    pub fn sign(&self, sighash: [u8; 32]) -> bitcoin::ecdsa::Signature {
        let secp = Secp256k1::new();
        bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from_digest(sighash), &self.sk),
            sighash_type: EcdsaSighashType::All,
        }
    }
}

/// Which derivation chain an index lives on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    /// Addresses handed out to be funded.
    Receive,
    /// Addresses that take the change of carriers.
    Change,
}

/// Addresses past the last known index that are still looked up for coins
/// (an address shown but not yet recorded as funded, or change of a carrier
/// built just before a crash).
pub const GAP: u32 = 5;

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

/// A coin together with the key that can spend it.
#[derive(Clone, Debug)]
pub struct Coin {
    pub utxo: Utxo,
    pub chain: Chain,
    pub index: u32,
}

/// The fee wallet: every key of both chains, derived on demand.
pub struct FundingWallet {
    seed: [u8; 32],
    network: Network,
}

/// Counters a wallet persists for its fee wallet: the next receive and the
/// next change index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FundingState {
    pub receive: u32,
    pub change: u32,
}

impl FundingWallet {
    pub fn new(seed: [u8; 32], network: Network) -> Self {
        FundingWallet { seed, network }
    }

    /// HKDF-SHA256(seed, info) → secp256k1 secret key, with
    /// info = `"sb/v1/funding"` for receive index 0 (the pre-HD key, so
    /// wallets funded before fresh addresses existed keep their coins),
    /// `"sb/v1/funding/<i>"` for receive index i ≥ 1 and
    /// `"sb/v1/funding/change/<i>"` for change index i.
    pub fn key(&self, chain: Chain, index: u32) -> Result<FundingKey> {
        let info = match (chain, index) {
            (Chain::Receive, 0) => "sb/v1/funding".to_string(),
            (Chain::Receive, i) => format!("sb/v1/funding/{i}"),
            (Chain::Change, i) => format!("sb/v1/funding/change/{i}"),
        };
        let mut raw = [0u8; 32];
        Hkdf::<Sha256>::new(None, &self.seed)
            .expand(info.as_bytes(), &mut raw)
            .unwrap();
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&raw).context("funding key")?;
        let pk = CompressedPublicKey(sk.public_key(&secp));
        let address = Address::p2wpkh(&pk, self.network);
        Ok(FundingKey { sk, pk, address })
    }

    /// The address to show for funding: the first receive index not yet
    /// recorded as used.
    pub fn receive_address(&self, st: FundingState) -> Result<Address> {
        Ok(self.key(Chain::Receive, st.receive)?.address)
    }

    /// Every coin on both chains up to the known counters plus [`GAP`],
    /// and the counters advanced past any index that holds coins.
    pub fn coins(
        &self,
        publisher: &dyn Publisher,
        st: FundingState,
    ) -> Result<(Vec<Coin>, FundingState)> {
        let mut coins = Vec::new();
        let mut next = st;
        for (chain, upto) in [
            (Chain::Receive, st.receive + GAP),
            (Chain::Change, st.change + GAP),
        ] {
            let addrs: Vec<Address> = (0..=upto)
                .map(|i| self.key(chain, i).map(|k| k.address))
                .collect::<Result<_>>()?;
            for (i, utxos) in publisher.utxos_many(&addrs)?.into_iter().enumerate() {
                let i = i as u32;
                if !utxos.is_empty() {
                    let counter = match chain {
                        Chain::Receive => &mut next.receive,
                        Chain::Change => &mut next.change,
                    };
                    *counter = (*counter).max(i + 1);
                }
                coins.extend(utxos.into_iter().map(|utxo| Coin {
                    utxo,
                    chain,
                    index: i,
                }));
            }
        }
        Ok((coins, next))
    }

    /// Build and sign a transaction paying `outputs`; the fee comes from the
    /// coins (`fee_rate` in sat/vB) and the change goes to a fresh change
    /// address. Returns the transaction and the counters advanced past the
    /// change index it used, if any.
    pub fn build_tx(
        &self,
        coins: &[Coin],
        st: FundingState,
        outputs: Vec<TxOut>,
        fee_rate: u64,
    ) -> Result<(Transaction, FundingState)> {
        let target: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
        let out_bytes: u64 = outputs
            .iter()
            .map(|o| 9 + o.script_pubkey.len() as u64)
            .sum();
        // confirmed first, then largest first: the fewest inputs, so the
        // fewest addresses tied together by one transaction
        let mut sorted: Vec<&Coin> = coins.iter().collect();
        sorted.sort_by(|a, b| {
            b.utxo
                .confirmed
                .cmp(&a.utxo.confirmed)
                .then(b.utxo.value.cmp(&a.utxo.value))
        });
        let mut inputs: Vec<&Coin> = Vec::new();
        let mut total = 0u64;
        let mut fee = 0u64;
        for c in sorted {
            inputs.push(c);
            total += c.utxo.value;
            // P2WPKH input ≈ 68 vB, change output 31 vB, overhead ≈ 11 vB
            let vbytes = 11 + 68 * inputs.len() as u64 + out_bytes + 31;
            fee = vbytes * fee_rate;
            if total >= target + fee + DUST_LIMIT {
                break;
            }
        }
        if inputs.is_empty() {
            bail!(
                "funding address {} has no confirmed coins; fund it first",
                self.receive_address(st)?
            );
        }
        if total < target + fee {
            bail!(
                "fee wallet holds {total} sat; need {target} + fee {fee} (fund {})",
                self.receive_address(st)?
            );
        }
        let change = total - target - fee;
        let mut next = st;
        let mut output = outputs;
        if change >= DUST_LIMIT {
            let key = self.key(Chain::Change, st.change)?;
            next.change = st.change + 1;
            output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: key.address.script_pubkey(),
            });
        }
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|c| TxIn {
                    previous_output: c.utxo.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output,
        };
        let secp = Secp256k1::new();
        let mut cache = SighashCache::new(tx.clone());
        for (i, c) in inputs.iter().enumerate() {
            let key = self.key(c.chain, c.index)?;
            let spk = key.address.script_pubkey();
            let sighash = cache
                .p2wpkh_signature_hash(
                    i,
                    &spk,
                    Amount::from_sat(c.utxo.value),
                    EcdsaSighashType::All,
                )
                .context("sighash")?;
            let sig = secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &key.sk);
            let sig = bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: EcdsaSighashType::All,
            };
            tx.input[i].witness = Witness::p2wpkh(&sig, &key.pk.0);
        }
        Ok((tx, next))
    }

    /// Look the coins up, pay `outputs`, return the signed transaction and
    /// the counters to persist.
    pub fn pay(
        &self,
        publisher: &dyn Publisher,
        st: FundingState,
        outputs: Vec<TxOut>,
        fee_rate: u64,
    ) -> Result<(Transaction, FundingState)> {
        let (coins, st) = self.coins(publisher, st)?;
        self.build_tx(&coins, st, outputs, fee_rate)
    }
}

/// Smallest output this tool will create or pay (Bitcoin Core's dust limit for
/// P2WPKH is 294 sat; 546 covers every standard script type).
pub const DUST_LIMIT: u64 = 546;

/// Where UTXOs are looked up and transactions are broadcast.
pub trait Publisher {
    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>>;
    /// Coins of several addresses, in order; one call where the backend has one.
    fn utxos_many(&self, addresses: &[Address]) -> Result<Vec<Vec<Utxo>>> {
        addresses.iter().map(|a| self.utxos(a)).collect()
    }
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

/// Electrum server: `listunspent` by scripthash and `transaction.broadcast`.
pub struct ElectrumPublisher {
    pub electrum: sb_indexer::chain::electrum::Electrum,
}

impl Publisher for ElectrumPublisher {
    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>> {
        let list = self
            .electrum
            .listunspent(&address.script_pubkey())
            .map_err(|e| anyhow!("electrum listunspent: {e}"))?;
        Ok(list
            .into_iter()
            .map(|(txid, vout, value, confirmed)| Utxo {
                outpoint: OutPoint { txid, vout },
                value,
                confirmed,
            })
            .collect())
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        self.electrum
            .broadcast(tx)
            .map_err(|e| anyhow!("electrum broadcast: {e}"))
    }
}

/// Bitcoin Core RPC without a node wallet: `scantxoutset` for UTXOs (confirmed
/// only) and `sendrawtransaction`.
pub struct RpcPublisher {
    pub rpc: sb_indexer::chain::rpc::BitcoinCoreRpc,
}

impl Publisher for RpcPublisher {
    fn utxos(&self, address: &Address) -> Result<Vec<Utxo>> {
        Ok(self
            .utxos_many(std::slice::from_ref(address))?
            .pop()
            .unwrap_or_default())
    }

    fn utxos_many(&self, addresses: &[Address]) -> Result<Vec<Vec<Utxo>>> {
        let descs: Vec<String> = addresses.iter().map(|a| format!("addr({a})")).collect();
        let res = self
            .rpc
            .call("scantxoutset", serde_json::json!(["start", descs]))
            .map_err(|e| anyhow!("scantxoutset: {e}"))?;
        let mut out = vec![Vec::new(); addresses.len()];
        for u in res["unspents"].as_array().cloned().unwrap_or_default() {
            let txid: Txid = u["txid"].as_str().context("txid")?.parse()?;
            let vout = u["vout"].as_u64().context("vout")? as u32;
            let amount = Amount::from_btc(u["amount"].as_f64().context("amount")?)?;
            let spk = ScriptBuf::from_bytes(hex::decode(
                u["scriptPubKey"].as_str().context("scriptPubKey")?,
            )?);
            let Some(i) = addresses.iter().position(|a| a.script_pubkey() == spk) else {
                continue;
            };
            out[i].push(Utxo {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A publisher over an in-memory coin list.
    struct Coins(RefCell<Vec<(ScriptBuf, Utxo)>>, RefCell<Vec<Transaction>>);

    impl Publisher for Coins {
        fn utxos(&self, address: &Address) -> Result<Vec<Utxo>> {
            let spk = address.script_pubkey();
            Ok(self
                .0
                .borrow()
                .iter()
                .filter(|(s, _)| *s == spk)
                .map(|(_, u)| u.clone())
                .collect())
        }
        fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
            self.1.borrow_mut().push(tx.clone());
            Ok(tx.compute_txid())
        }
    }

    fn utxo(n: u8, value: u64, confirmed: bool) -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            value,
            confirmed,
        }
    }

    #[test]
    fn derivation_is_deterministic_and_index_zero_is_the_legacy_key() {
        let fw = FundingWallet::new([7u8; 32], Network::Regtest);
        let legacy = {
            let mut raw = [0u8; 32];
            Hkdf::<Sha256>::new(None, &[7u8; 32])
                .expand(b"sb/v1/funding", &mut raw)
                .unwrap();
            let sk = SecretKey::from_slice(&raw).unwrap();
            Address::p2wpkh(
                &CompressedPublicKey(sk.public_key(&Secp256k1::new())),
                Network::Regtest,
            )
        };
        assert_eq!(fw.key(Chain::Receive, 0).unwrap().address, legacy);
        let mut seen = std::collections::HashSet::new();
        for chain in [Chain::Receive, Chain::Change] {
            for i in 0..4 {
                assert!(seen.insert(fw.key(chain, i).unwrap().address));
                assert_eq!(
                    fw.key(chain, i).unwrap().address,
                    fw.key(chain, i).unwrap().address
                );
            }
        }
        assert_eq!(
            fw.receive_address(FundingState {
                receive: 2,
                change: 9
            })
            .unwrap(),
            fw.key(Chain::Receive, 2).unwrap().address
        );
    }

    #[test]
    fn coins_are_found_on_both_chains_and_counters_advance() {
        let fw = FundingWallet::new([1u8; 32], Network::Regtest);
        let pubs = Coins(RefCell::new(vec![]), RefCell::new(vec![]));
        let st = FundingState::default();
        let (coins, next) = fw.coins(&pubs, st).unwrap();
        assert!(coins.is_empty());
        assert_eq!(next, st);
        // a coin on receive 3 (within the gap) and on change 1
        pubs.0.borrow_mut().push((
            fw.key(Chain::Receive, 3).unwrap().address.script_pubkey(),
            utxo(1, 10_000, true),
        ));
        pubs.0.borrow_mut().push((
            fw.key(Chain::Change, 1).unwrap().address.script_pubkey(),
            utxo(2, 20_000, false),
        ));
        // beyond the gap: not seen
        pubs.0.borrow_mut().push((
            fw.key(Chain::Receive, GAP + 1)
                .unwrap()
                .address
                .script_pubkey(),
            utxo(3, 99_000, true),
        ));
        let (coins, next) = fw.coins(&pubs, st).unwrap();
        assert_eq!(coins.len(), 2);
        assert_eq!(
            next,
            FundingState {
                receive: 4,
                change: 2
            }
        );
        // with the counters advanced the far coin comes into view
        let (coins, next2) = fw.coins(&pubs, next).unwrap();
        assert_eq!(coins.len(), 3);
        assert_eq!(next2.receive, GAP + 2);
    }

    #[test]
    fn build_tx_signs_every_input_with_its_own_key_and_pays_change_to_a_fresh_address() {
        let fw = FundingWallet::new([2u8; 32], Network::Regtest);
        let a = fw.key(Chain::Receive, 0).unwrap();
        let b = fw.key(Chain::Change, 4).unwrap();
        let coins = vec![
            Coin {
                utxo: utxo(1, 30_000, true),
                chain: Chain::Receive,
                index: 0,
            },
            Coin {
                utxo: utxo(2, 25_000, true),
                chain: Chain::Change,
                index: 4,
            },
            Coin {
                utxo: utxo(3, 90_000, false),
                chain: Chain::Receive,
                index: 1,
            },
        ];
        let st = FundingState {
            receive: 2,
            change: 5,
        };
        let out = TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: ScriptBuf::new_op_return([1u8; 4]),
        };
        let (tx, next) = fw.build_tx(&coins, st, vec![out], 1).unwrap();
        // both confirmed coins (largest first), the unconfirmed one untouched
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.input[0].previous_output, coins[0].utxo.outpoint);
        assert_eq!(tx.input[1].previous_output, coins[1].utxo.outpoint);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(
            tx.output[1].script_pubkey,
            fw.key(Chain::Change, 5).unwrap().address.script_pubkey()
        );
        assert_eq!(
            next,
            FundingState {
                receive: 2,
                change: 6
            }
        );
        // the witnesses verify against their own keys
        let secp = Secp256k1::verification_only();
        let mut cache = SighashCache::new(&tx);
        for (i, key) in [&a, &b].into_iter().enumerate() {
            let sighash = cache
                .p2wpkh_signature_hash(
                    i,
                    &key.address.script_pubkey(),
                    Amount::from_sat(coins[i].utxo.value),
                    EcdsaSighashType::All,
                )
                .unwrap();
            let w = &tx.input[i].witness;
            let sig = bitcoin::ecdsa::Signature::from_slice(&w[0]).unwrap();
            assert_eq!(w[1], key.pk.to_bytes());
            secp.verify_ecdsa(
                &Message::from_digest(sighash.to_byte_array()),
                &sig.signature,
                &key.pk.0,
            )
            .unwrap();
        }
        // exact spend leaves no change output and no counter change
        let fee = 11 + 68 * 2 + (9 + 6) + 31;
        let out = TxOut {
            value: Amount::from_sat(55_000 - fee),
            script_pubkey: ScriptBuf::new_op_return([1u8; 4]),
        };
        let (tx, next) = fw.build_tx(&coins[..2], st, vec![out], 1).unwrap();
        assert_eq!(tx.output.len(), 1);
        assert_eq!(next, st);
        // too little, and nothing at all
        let out = TxOut {
            value: Amount::from_sat(60_000),
            script_pubkey: ScriptBuf::new_op_return([1u8; 4]),
        };
        let e = fw
            .build_tx(&coins[..2], st, vec![out], 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("need 60000"), "{e}");
        let e = fw.build_tx(&[], st, vec![], 1).unwrap_err().to_string();
        assert!(e.contains("no confirmed coins"), "{e}");
    }

    #[test]
    fn pay_looks_coins_up_and_builds() {
        let fw = FundingWallet::new([3u8; 32], Network::Regtest);
        let pubs = Coins(RefCell::new(vec![]), RefCell::new(vec![]));
        pubs.0.borrow_mut().push((
            fw.key(Chain::Receive, 0).unwrap().address.script_pubkey(),
            utxo(1, 10_000, true),
        ));
        let out = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_op_return([0u8; 4]),
        };
        let (tx, next) = fw
            .pay(&pubs, FundingState::default(), vec![out], 2)
            .unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(
            next,
            FundingState {
                receive: 1,
                change: 1
            }
        );
        assert_eq!(pubs.broadcast(&tx).unwrap(), tx.compute_txid());
    }
}
