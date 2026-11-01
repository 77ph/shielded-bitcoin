//! Variant A replay: the deployment profile, the replayed state, the
//! acceptance rules and the JSON store, over the chain sources and carrier
//! extraction of `sb-common` (`docs/PROFILE-A.md` §9–§11). The design is the
//! paper indexer's (`sb-indexer`) without the swap, batch and light-proof
//! layers, which come in their own slices.

pub mod deployment;
pub mod hexbytes;
pub mod replay;
pub mod state;
pub mod store;

pub use deployment::{Deployment, DeploymentError, DevBoundary};
pub use replay::{BlockReport, Indexer, RejectReason, SyncError, SyncReport, TransferCheck};
pub use sb_common::{BlockId, ChainError, ChainSource, carrier, chain, net};
pub use state::{BlockCheckpoint, Rejection, ReplayState, StateError};
pub use store::{JsonStore, StateStore, StoreError};
