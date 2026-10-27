//! An in-memory chain for tests: push blocks of transactions, reorganise.

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness,
};

use super::{BlockId, ChainError, ChainSource};
use crate::carrier::carrier_output;

#[derive(Clone, Debug)]
pub struct MockChain {
    start_height: u32,
    blocks: Vec<Block>,
}

fn coinbase(height: u32, salt: u32) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Builder::new()
                .push_int(height as i64)
                .push_int(salt as i64)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn fake_input(nonce: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint::null(),
        script_sig: Builder::new().push_int(nonce as i64).into_script(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

/// A transaction whose only output is the carrier for `envelope`; `nonce`
/// makes repeated publications of the same envelope distinct transactions.
pub fn carrier_tx(envelope: &[u8], nonce: u32) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![fake_input(nonce)],
        output: vec![carrier_output(envelope)],
    }
}

/// A mint carrier: pays `value` to `vault` and carries `envelope`.
pub fn mint_tx(envelope: &[u8], vault: &ScriptBuf, value: u64, nonce: u32) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![fake_input(nonce)],
        output: vec![
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: vault.clone(),
            },
            carrier_output(envelope),
        ],
    }
}

impl MockChain {
    /// An empty chain whose first block will have height `start_height`.
    pub fn new(start_height: u32) -> Self {
        MockChain {
            start_height,
            blocks: Vec::new(),
        }
    }

    pub fn height(&self) -> Option<u32> {
        if self.blocks.is_empty() {
            None
        } else {
            Some(self.start_height + self.blocks.len() as u32 - 1)
        }
    }

    /// Append a block with the given transactions (a coinbase is prepended).
    /// `salt` changes the block hash for otherwise identical blocks (reorg tests).
    pub fn push_block_salted(&mut self, txs: Vec<Transaction>, salt: u32) -> BlockId {
        let height = self.start_height + self.blocks.len() as u32;
        let prev_blockhash = self
            .blocks
            .last()
            .map(|b| b.block_hash())
            .unwrap_or_else(BlockHash::all_zeros);
        let mut txdata = vec![coinbase(height, salt)];
        txdata.extend(txs);
        let mut block = Block {
            header: Header {
                version: BlockVersion::TWO,
                prev_blockhash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: height,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: salt,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().expect("non-empty");
        let id = BlockId {
            height,
            hash: block.block_hash(),
        };
        self.blocks.push(block);
        id
    }

    pub fn push_block(&mut self, txs: Vec<Transaction>) -> BlockId {
        self.push_block_salted(txs, 0)
    }

    /// Drop every block above `height` (then push replacements).
    pub fn reorg_to(&mut self, height: u32) {
        let keep = (height + 1).saturating_sub(self.start_height) as usize;
        self.blocks.truncate(keep);
    }
}

impl ChainSource for MockChain {
    fn tip(&self) -> Result<BlockId, ChainError> {
        let b = self
            .blocks
            .last()
            .ok_or_else(|| ChainError::NotFound("empty chain".into()))?;
        Ok(BlockId {
            height: self.height().unwrap(),
            hash: b.block_hash(),
        })
    }

    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError> {
        if height < self.start_height {
            return Ok(None);
        }
        Ok(self
            .blocks
            .get((height - self.start_height) as usize)
            .map(|b| b.block_hash()))
    }

    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        self.blocks
            .iter()
            .find(|b| b.block_hash() == *hash)
            .cloned()
            .ok_or_else(|| ChainError::NotFound(hash.to_string()))
    }
}
