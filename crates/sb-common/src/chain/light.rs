//! Verified indexer sync (paper §22.2, the "verification of an indexer
//! response against Bitcoin data" option): instead of downloading every
//! block, a client asks an indexer for each block's **carrier candidates**
//! together with a BIP 37 partial merkle tree, checks the tree against the
//! block header, and replays the candidates itself. The indexer can hide
//! carriers from such a client, which makes the client's roots diverge from
//! the network's (it can compare them with the indexer's own claimed roots
//! and with other indexers); it cannot forge, alter or reorder a carrier,
//! because the proofs and the replay rules are checked locally.
//!
//! With a header source next to it (any full chain source), the client does
//! not trust the indexer for chain selection either: the hash the indexer
//! names for a height must be the one the header source has.
//!
//! The paper's light client proper, a succinct proof that `R[h]` is the
//! correct replay, is open research and not what this is.

use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::{Block, BlockHash, Transaction, Txid};
use serde::{Deserialize, Serialize};

use super::{BlockId, ChainError, ChainSource};
use crate::carrier::CarrierMode;

/// What an indexer serves for one block: the header, every transaction the
/// carrier rule would look at, and one partial merkle tree proving their
/// positions. `root_after` is the indexer's own `R[h]` claim, for the
/// client to compare with what it replays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockView {
    pub height: u32,
    pub hash: String,
    /// 80-byte header, hex.
    pub header: String,
    pub tx_count: u32,
    pub carriers: Vec<CarrierView>,
    /// Consensus-encoded `PartialMerkleTree`, hex; empty when there are no carriers.
    pub merkle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_after: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierView {
    /// Position in the block.
    pub index: u32,
    /// Consensus-encoded transaction, hex.
    pub tx: String,
}

/// Does the carrier rule look at this transaction (candidate or probe)?
pub fn is_carrier(mode: CarrierMode, prefix: &[u8], tx: &Transaction) -> bool {
    mode.is_carrier(tx, prefix)
}

impl BlockView {
    /// The view of a full block under a carrier rule: every candidate
    /// (including malformed probes, so rejections replay the same way)
    /// with its proof.
    pub fn from_block(
        mode: CarrierMode,
        prefix: &[u8],
        height: u32,
        block: &Block,
        root_after: Option<String>,
    ) -> Self {
        let txids: Vec<Txid> = block.txdata.iter().map(|t| t.compute_txid()).collect();
        let matches: Vec<bool> = block
            .txdata
            .iter()
            .map(|t| is_carrier(mode, prefix, t))
            .collect();
        let carriers = block
            .txdata
            .iter()
            .enumerate()
            .filter(|(i, _)| matches[*i])
            .map(|(i, t)| CarrierView {
                index: i as u32,
                tx: hex::encode(serialize(t)),
            })
            .collect::<Vec<_>>();
        let merkle = if carriers.is_empty() {
            String::new()
        } else {
            hex::encode(serialize(&PartialMerkleTree::from_txids(&txids, &matches)))
        };
        BlockView {
            height,
            hash: block.block_hash().to_string(),
            header: hex::encode(serialize(&block.header)),
            tx_count: block.txdata.len() as u32,
            carriers,
            merkle,
            root_after,
        }
    }

    /// Check the view against `expected` and turn it into a block the replay
    /// can run on: the real header, the carriers at their proven positions,
    /// and empty placeholder transactions (which the carrier rule skips)
    /// everywhere else so transaction indexes match a full replay.
    pub fn into_block(self, expected: &BlockHash) -> Result<Block, ChainError> {
        let bad = |what: &str| ChainError::Decode(format!("indexer block {}: {what}", self.height));
        let header: Header =
            deserialize(&hex::decode(&self.header).map_err(|_| bad("header hex"))?)
                .map_err(|_| bad("header"))?;
        if header.block_hash() != *expected {
            return Err(bad(&format!(
                "header hashes to {}, expected {expected}",
                header.block_hash()
            )));
        }
        if self.tx_count == 0 {
            return Err(bad("empty block"));
        }
        let mut txs: Vec<(u32, Transaction)> = Vec::with_capacity(self.carriers.len());
        for c in &self.carriers {
            let tx: Transaction = deserialize(&hex::decode(&c.tx).map_err(|_| bad("tx hex"))?)
                .map_err(|_| bad("tx"))?;
            if c.index >= self.tx_count {
                return Err(bad("carrier index past tx_count"));
            }
            txs.push((c.index, tx));
        }
        if !txs.is_empty() {
            let pmt: PartialMerkleTree =
                deserialize(&hex::decode(&self.merkle).map_err(|_| bad("merkle hex"))?)
                    .map_err(|_| bad("merkle tree"))?;
            if pmt.num_transactions() != self.tx_count {
                return Err(bad("merkle tree is for another transaction count"));
            }
            let mut matched = Vec::new();
            let mut indexes = Vec::new();
            let root = pmt
                .extract_matches(&mut matched, &mut indexes)
                .map_err(|e| bad(&format!("merkle tree: {e:?}")))?;
            if root != header.merkle_root {
                return Err(bad("merkle root does not match the header"));
            }
            // exactly the claimed carriers, at exactly the claimed positions
            let proven: Vec<(u32, Txid)> = indexes
                .iter()
                .copied()
                .zip(matched.iter().copied())
                .collect();
            let claimed: Vec<(u32, Txid)> =
                txs.iter().map(|(i, t)| (*i, t.compute_txid())).collect();
            if proven != claimed {
                return Err(bad("carriers are not the proven transactions"));
            }
        }
        let placeholder = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut txdata = vec![placeholder; self.tx_count as usize];
        for (i, tx) in txs {
            txdata[i as usize] = tx;
        }
        Ok(Block { header, txdata })
    }
}

/// A chain source over an indexer's `/tip` and `/block/<height|hash>`
/// routes; `headers`, when given, must agree on every block hash.
pub struct LightSource {
    base: String,
    headers: Option<Box<dyn ChainSource>>,
    views: Mutex<HashMap<BlockHash, BlockView>>,
    /// `R[h]` as the indexer claimed it, per height served.
    claims: Mutex<HashMap<u32, String>>,
}

impl LightSource {
    pub fn new(base: &str, headers: Option<Box<dyn ChainSource>>) -> Self {
        LightSource {
            base: base.trim_end_matches('/').to_string(),
            headers,
            views: Mutex::new(HashMap::new()),
            claims: Mutex::new(HashMap::new()),
        }
    }

    /// Compare every root the indexer claimed with what local replay
    /// produced (`root_hex_at`: the local root after a height, in the
    /// family's hex encoding, `None` when not replayed); the number
    /// compared, or the first height that differs (the indexer hid a
    /// carrier from us, or one of us is wrong).
    pub fn verify_claims(
        &self,
        root_hex_at: impl Fn(u32) -> Option<String>,
    ) -> Result<usize, ChainError> {
        let claims = self.claims.lock().unwrap();
        let mut heights: Vec<&u32> = claims.keys().collect();
        heights.sort();
        let mut n = 0;
        for h in heights {
            let Some(ours) = root_hex_at(*h) else {
                continue;
            };
            if claims[h] != ours {
                return Err(ChainError::Decode(format!(
                    "the indexer claims R[{h}] = {} but local replay gives {ours}: it served a different carrier set",
                    claims[h]
                )));
            }
            n += 1;
        }
        Ok(n)
    }

    fn get(&self, path: &str) -> Result<Option<serde_json::Value>, ChainError> {
        match crate::net::agent()
            .get(&format!("{}{}", self.base, path))
            .call()
        {
            Ok(r) => {
                Ok(Some(r.into_json().map_err(|e| {
                    ChainError::Decode(format!("indexer {path}: {e}"))
                })?))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn view(&self, path: &str) -> Result<Option<BlockView>, ChainError> {
        let Some(v) = self.get(path)? else {
            return Ok(None);
        };
        let view: BlockView = serde_json::from_value(v)
            .map_err(|e| ChainError::Decode(format!("indexer {path}: {e}")))?;
        let hash: BlockHash = view
            .hash
            .parse()
            .map_err(|_| ChainError::Decode(format!("indexer {path}: hash")))?;
        if let Some(h) = &self.headers {
            let ours = h.block_hash(view.height)?;
            if ours != Some(hash) {
                return Err(ChainError::Decode(format!(
                    "indexer names {hash} at {} but the header source has {ours:?}",
                    view.height
                )));
            }
        }
        if let Some(r) = &view.root_after {
            self.claims.lock().unwrap().insert(view.height, r.clone());
        }
        self.views.lock().unwrap().insert(hash, view.clone());
        Ok(Some(view))
    }
}

impl ChainSource for LightSource {
    fn tip(&self) -> Result<BlockId, ChainError> {
        let v = self
            .get("/tip")?
            .ok_or_else(|| ChainError::NotFound("tip".into()))?;
        let height = v["height"]
            .as_u64()
            .ok_or_else(|| ChainError::Decode("indexer tip".into()))? as u32;
        let hash: BlockHash = v["hash"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ChainError::Decode("indexer tip hash".into()))?;
        if let Some(h) = &self.headers {
            // the indexer's tip must be on the header source's chain; a
            // header tip behind the indexer's is fine, replay stops there
            if h.block_hash(height)? != Some(hash) {
                return Err(ChainError::Decode(format!(
                    "indexer tip {hash} at {height} is not on the header source's chain"
                )));
            }
        }
        Ok(BlockId { height, hash })
    }

    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError> {
        Ok(self
            .view(&format!("/block/{height}"))?
            .map(|v| v.hash.parse().expect("checked in view")))
    }

    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        let cached = self.views.lock().unwrap().remove(hash);
        let view = match cached {
            Some(v) => v,
            None => self
                .view(&format!("/block/{hash}"))?
                .ok_or_else(|| ChainError::NotFound(hash.to_string()))?,
        };
        view.into_block(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CANDIDATE_PREFIX: [u8; 4] = *b"btc\x01"; // the paper profile's prefix, for the tests
    use crate::chain::mock::{MockChain, carrier_tx};
    use bitcoin::hashes::Hash;

    fn block_with(n_plain: usize, carriers_at: &[usize]) -> Block {
        let mut txs = Vec::new();
        for i in 0..n_plain {
            if carriers_at.contains(&i) {
                let mut env = vec![0u8; 700];
                env[..4].copy_from_slice(&CANDIDATE_PREFIX);
                env[4] = i as u8;
                txs.push(carrier_tx(&env, i as u32));
            } else {
                txs.push(Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::absolute::LockTime::from_consensus(i as u32),
                    input: vec![],
                    output: vec![bitcoin::TxOut {
                        value: bitcoin::Amount::from_sat(1 + i as u64),
                        script_pubkey: bitcoin::ScriptBuf::new(),
                    }],
                });
            }
        }
        let mut chain = MockChain::new(0);
        chain.push_block(txs);
        chain.blocks()[0].clone()
    }

    #[test]
    fn view_round_trips_and_keeps_positions() {
        for (n, at) in [
            (1, vec![0]),
            (3, vec![1]),
            (6, vec![0, 5]),
            (7, vec![2, 3, 4]),
            (4, vec![]),
        ] {
            let block = block_with(n, &at);
            let view = BlockView::from_block(
                CarrierMode::OpReturn,
                &CANDIDATE_PREFIX,
                9,
                &block,
                Some("rr".into()),
            );
            assert_eq!(view.carriers.len(), at.len());
            let json = serde_json::to_string(&view).unwrap();
            let back: BlockView = serde_json::from_str(&json).unwrap();
            let rebuilt = back.into_block(&block.block_hash()).unwrap();
            assert_eq!(rebuilt.block_hash(), block.block_hash());
            assert_eq!(rebuilt.txdata.len(), block.txdata.len());
            // (the mock chain puts a coinbase first, so every position is +1)
            for (i, tx) in block.txdata.iter().enumerate() {
                if is_carrier(CarrierMode::OpReturn, &CANDIDATE_PREFIX, tx) {
                    assert!(at.contains(&(i - 1)));
                    assert_eq!(&rebuilt.txdata[i], tx);
                } else {
                    assert!(rebuilt.txdata[i].output.is_empty());
                    assert!(!is_carrier(
                        CarrierMode::OpReturn,
                        &CANDIDATE_PREFIX,
                        &rebuilt.txdata[i]
                    ));
                }
            }
        }
    }

    #[test]
    fn tampered_views_are_refused() {
        let block = block_with(6, &[1, 4]);
        let hash = block.block_hash();
        let good = BlockView::from_block(CarrierMode::OpReturn, &CANDIDATE_PREFIX, 1, &block, None);
        let err = |v: BlockView, h: &BlockHash| match v.clone().into_block(h) {
            Ok(_) => panic!(
                "accepted: carriers {:?}, tx_count {}, header {}…, merkle {}…, expected {h}",
                v.carriers.iter().map(|c| c.index).collect::<Vec<_>>(),
                v.tx_count,
                &v.header[..16],
                &v.merkle[..v.merkle.len().min(16)]
            ),
            Err(e) => e.to_string(),
        };
        // wrong expected hash
        assert!(err(good.clone(), &BlockHash::all_zeros()).contains("header hashes to"));
        // a carrier replaced by another transaction
        let mut v = good.clone();
        v.carriers[0].tx = good.carriers[1].tx.clone();
        assert!(err(v, &hash).contains("not the proven"));
        // a carrier moved to another position (the carriers sit at 2 and 5)
        assert_eq!(good.carriers[0].index, 2);
        let mut v = good.clone();
        v.carriers[0].index = 3;
        assert!(err(v, &hash).contains("not the proven"));
        // a carrier dropped
        let mut v = good.clone();
        v.carriers.pop();
        assert!(err(v, &hash).contains("not the proven"));
        // another transaction count (the block has 7: coinbase + 6)
        assert_eq!(good.tx_count, 7);
        let mut v = good.clone();
        v.tx_count = 8;
        assert!(err(v, &hash).contains("another transaction count"));
        let mut v = good.clone();
        v.carriers[1].index = 8;
        v.tx_count = 9;
        assert!(err(v, &hash).contains("another transaction count"));
        let mut v = good.clone();
        v.carriers[1].index = 9;
        assert!(err(v, &hash).contains("past tx_count"));
        // garbage fields
        for (field, needle) in [("header", "header hex"), ("merkle", "merkle hex")] {
            let mut v = good.clone();
            match field {
                "header" => v.header = "zz".into(),
                _ => v.merkle = "zz".into(),
            }
            assert!(err(v, &hash).contains(needle));
        }
        let mut v = good.clone();
        v.header = "00".repeat(10);
        assert!(err(v, &hash).contains("header"));
        let mut v = good.clone();
        v.merkle = "00".repeat(4);
        assert!(err(v, &hash).contains("merkle tree"));
        let mut v = good.clone();
        v.carriers[0].tx = "zz".into();
        assert!(err(v, &hash).contains("tx hex"));
        let mut v = good.clone();
        v.carriers[0].tx = "00".into();
        assert!(err(v, &hash).contains("tx"));
        let mut v = good.clone();
        v.tx_count = 0;
        assert!(err(v, &hash).contains("empty block"));
        // a merkle tree of a different block (same count, other transactions)
        let mut v = good.clone();
        v.merkle = BlockView::from_block(
            CarrierMode::OpReturn,
            &CANDIDATE_PREFIX,
            1,
            &block_with(6, &[4]),
            None,
        )
        .merkle;
        assert!(err(v, &hash).contains("merkle root does not match"));
    }
}
