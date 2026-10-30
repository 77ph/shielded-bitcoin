//! Family-agnostic code shared by the paper implementation and the
//! variants beyond it (`docs/VARIANT-A.md` §6): nothing here depends on the
//! proof system, the field or the curve of a profile. Bitcoin chain sources
//! and carrier extraction (parametrised by a family's candidate prefix), the
//! publication layer (proxy, HTTP), the fee-funding wallet and carrier
//! publishers, the witness commit-and-reveal pair, HTLC scripts, fee-vault
//! authorization messages and keys, and the encrypted-file format.

pub mod carrier;
pub mod chain;
pub mod feeauth;
pub mod filecrypto;
pub mod funding;
pub mod htlc;
pub mod http;
pub mod net;
pub mod witness;

pub use chain::{BlockId, ChainError, ChainSource};
