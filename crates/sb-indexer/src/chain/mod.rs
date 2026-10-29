//! Chain sources: where replay reads blocks from.

pub mod electrum;
pub mod esplora;
/// In-process fake servers for tests (compiled unconditionally so the crate
/// has a single build configuration; nothing here runs unless called).
pub mod fake;
pub mod light;
pub mod mock;
pub mod rpc;

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
}
