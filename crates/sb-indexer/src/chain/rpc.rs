//! Bitcoin Core JSON-RPC chain source.

use base64::Engine;
use bitcoin::consensus::deserialize;
use bitcoin::{Block, BlockHash};
use serde_json::{Value, json};

use super::{BlockId, ChainError, ChainSource};

pub struct BitcoinCoreRpc {
    url: String,
    auth: String,
}

impl BitcoinCoreRpc {
    /// `url` like `http://127.0.0.1:38332`, credentials from `rpcuser`/`rpcpassword`
    /// or a cookie file's `__cookie__:token`.
    pub fn new(url: &str, user: &str, password: &str) -> Self {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        BitcoinCoreRpc {
            url: url.to_string(),
            auth: format!("Basic {token}"),
        }
    }

    /// Read `~/.bitcoin/<net>/.cookie`-style credentials.
    pub fn with_cookie(url: &str, cookie_path: &std::path::Path) -> Result<Self, ChainError> {
        let cookie = std::fs::read_to_string(cookie_path)?;
        let (user, pass) = cookie
            .trim()
            .split_once(':')
            .ok_or_else(|| ChainError::Rpc("bad cookie".into()))?;
        Ok(Self::new(url, user, pass))
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        let body = json!({ "jsonrpc": "1.0", "id": "sb", "method": method, "params": params });
        let resp: Value = match crate::net::agent()
            .post(&self.url)
            .set("Authorization", &self.auth)
            .set("Content-Type", "application/json")
            .send_json(body)
        {
            Ok(r) => r.into_json()?,
            // Bitcoin Core answers application errors with HTTP 500 and a JSON body.
            Err(ureq::Error::Status(_, r)) => {
                r.into_json().map_err(|e| ChainError::Rpc(e.to_string()))?
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(ChainError::Rpc(err.to_string()));
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| ChainError::Rpc("no result".into()))
    }
}

impl ChainSource for BitcoinCoreRpc {
    fn tip(&self) -> Result<BlockId, ChainError> {
        let height = self
            .call("getblockcount", json!([]))?
            .as_u64()
            .ok_or_else(|| ChainError::Rpc("bad height".into()))? as u32;
        let hash = self
            .block_hash(height)?
            .ok_or_else(|| ChainError::NotFound(height.to_string()))?;
        Ok(BlockId { height, hash })
    }

    fn block_hash(&self, height: u32) -> Result<Option<BlockHash>, ChainError> {
        match self.call("getblockhash", json!([height])) {
            Ok(v) => {
                let s = v
                    .as_str()
                    .ok_or_else(|| ChainError::Rpc("bad hash".into()))?;
                Ok(Some(s.parse().map_err(
                    |e: bitcoin::hex::HexToArrayError| ChainError::Decode(e.to_string()),
                )?))
            }
            Err(ChainError::Rpc(msg)) if msg.contains("-8") => Ok(None), // Block height out of range
            Err(e) => Err(e),
        }
    }

    fn block(&self, hash: &BlockHash) -> Result<Block, ChainError> {
        let v = self.call("getblock", json!([hash.to_string(), 0]))?;
        let hex = v
            .as_str()
            .ok_or_else(|| ChainError::Rpc("bad block".into()))?;
        let bytes = hex::decode(hex).map_err(|e| ChainError::Decode(e.to_string()))?;
        deserialize(&bytes).map_err(|e| ChainError::Decode(e.to_string()))
    }
}
