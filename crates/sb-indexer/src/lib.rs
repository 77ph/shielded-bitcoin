//! Deterministic replay: chain sources, carrier extraction, acceptance and
//! state (paper §8, §11, §15, §A.4, §A.6, §A.7).

pub mod batch;
pub mod deployment;
pub mod hexbytes;
pub mod proof;
pub mod replay;
pub mod state;
pub mod store;

// family-agnostic layers, shared with the variants (`docs/VARIANT-A.md` §6)
pub use sb_common::{carrier, chain, net};

pub use chain::{BlockId, ChainError, ChainSource};
pub use deployment::{Deployment, DeploymentError, Setup};
pub use replay::{BlockReport, Indexer, RejectReason, SyncError, SyncReport, TransferCheck};
pub use state::{BlockCheckpoint, Rejection, ReplayState, StateError};
pub use store::{JsonStore, PgStore, StateStore, StoreError};
