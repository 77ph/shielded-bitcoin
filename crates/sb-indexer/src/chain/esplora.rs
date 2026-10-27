//! Esplora HTTP chain source (mempool.space, blockstream.info or a local
//! instance). Raw blocks come from `/block/<hash>/raw`.

use std::io::Read;

use bitcoin::consensus::deserialize;
use bitcoin::{Block, BlockHash};

use super::{BlockId, ChainError, ChainSource};

pub struct Esplora {
    base: String,
}

impl Esplora {
    /// `base` like `https://mempool.space/signet/api`.
    pub fn new(base: &str) -> Self {
        Esplora {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    fn get_text(&self, path: &str) -> Result<Option<String>, ChainError> {
        match ureq::get(&format!("{}{}", self.base, path)).call() {
            Ok(r) => Ok(Some(r.into_string()?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn parse_hash(s: &str) -> Result<BlockHash, ChainError> {
        s.trim()
            .parse()
            .map_err(|e: bitcoin::hex::HexToArrayError| ChainError::Decode(e.to_string()))
    }
}

impl ChainSource for Esplora {
    fn tip(&self) -> Result<BlockId, ChainError> {
        let h = self
            .get_text("/blocks/tip/height")?
            .ok_or_else(|| ChainError::NotFound("tip".into()))?;
        let height: u32 = h.trim().parse().map_err(|_| ChainError::Decode(h))?;
        let hash = self
            .get_text("/blocks/tip/hash")?
            .ok_or_else(|| ChainError::NotFound("tip".into()))?;
        Ok(BlockId {
            height,
            hash: Self::parse_hash(&hash)?,
        })
    }

    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError> {
        match self.get_text(&format!("/block-height/{height}"))? {
            Some(s) => Ok(Some(Self::parse_hash(&s)?)),
            None => Ok(None),
        }
    }

    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        let resp = ureq::get(&format!("{}/block/{hash}/raw", self.base)).call()?;
        let mut bytes = Vec::new();
        resp.into_reader().take(64 << 20).read_to_end(&mut bytes)?;
        deserialize(&bytes).map_err(|e| ChainError::Decode(e.to_string()))
    }
}
