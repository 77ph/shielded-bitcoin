//! Chain sources: where replay reads blocks from.

pub mod electrum;
pub mod esplora;
/// In-process fake servers for tests (compiled unconditionally so the crate
/// has a single build configuration; nothing here runs unless called).
pub mod fake;
pub mod light;
pub mod mock;
pub mod rpc;

use std::collections::HashSet;

use bitcoin::{Block, BlockHash};

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("http: {0}")]
    Http(String),
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("block {0} not found")]
    NotFound(String),
}

impl From<ureq::Error> for ChainError {
    fn from(e: ureq::Error) -> Self {
        ChainError::Http(format!("{e}{}", crate::net::route()))
    }
}

impl From<std::io::Error> for ChainError {
    fn from(e: std::io::Error) -> Self {
        ChainError::Http(format!("{e}{}", crate::net::route()))
    }
}

/// A block position on the active chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockId {
    pub height: u32,
    pub hash: BlockHash,
}

/// Read access to the active chain. Implementations must return the full
/// block (all transactions, in block order) for a hash.
pub trait ChainSource {
    /// Height and hash of the chain tip.
    fn tip(&self) -> Result<BlockId, ChainError>;
    /// Hash of the active block at `height`, `None` above the tip.
    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError>;
    /// The full block.
    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError>;
    /// Does `block` return the block in part — the transactions the
    /// deployment reads, each proven into the header's merkle root by the
    /// source itself, and placeholders elsewhere — so that the merkle root
    /// and the witness commitment cannot be recomputed from it?
    fn partial_blocks(&self) -> bool {
        false
    }
}

/// A full block as a source hands it over, checked against the hash that
/// named it: the header hashes to it, the transactions hash to the header's
/// merkle root with none repeated (a repeated tail hashes to the same root,
/// CVE-2012-2459), and the coinbase commits to the witnesses (BIP 141). A
/// source is trusted for chain selection, not for block contents.
pub fn check_block(hash: &BlockHash, block: &Block) -> Result<(), ChainError> {
    if block.block_hash() != *hash {
        return Err(ChainError::Decode(format!("block does not hash to {hash}")));
    }
    if !block.check_merkle_root() {
        return Err(ChainError::Decode(format!(
            "block {hash}: the transactions do not hash to the header's merkle root"
        )));
    }
    let mut seen = HashSet::with_capacity(block.txdata.len());
    if !block.txdata.iter().all(|tx| seen.insert(tx.compute_txid())) {
        return Err(ChainError::Decode(format!(
            "block {hash}: a transaction appears twice"
        )));
    }
    if !block.check_witness_commitment() {
        return Err(ChainError::Decode(format!(
            "block {hash}: the coinbase does not commit to the witnesses"
        )));
    }
    Ok(())
}

impl<T: ChainSource + ?Sized> ChainSource for std::rc::Rc<T> {
    fn tip(&self) -> Result<BlockId, ChainError> {
        (**self).tip()
    }
    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError> {
        (**self).block_hash(height)
    }
    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        (**self).block(hash)
    }
    fn partial_blocks(&self) -> bool {
        (**self).partial_blocks()
    }
}
