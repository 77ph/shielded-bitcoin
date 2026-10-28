//! Persistence of the replayed state: a JSON file (small deployments) or
//! PostgreSQL (incremental, one transaction per block).
//!
//! The in-memory [`ReplayState`] stays the source of truth during a sync; a
//! store receives every block as a checkpoint and can rebuild the state on
//! start. Rollbacks delete everything above the fork height.

pub mod json;
pub mod pg;

pub use json::JsonStore;
pub use pg::PgStore;

use crate::state::ReplayState;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state file: {0}")]
    State(#[from] crate::state::StateError),
    #[error("postgres: {0}")]
    Pg(#[from] postgres::Error),
    #[error("corrupt store: {0}")]
    Corrupt(String),
}

pub trait StateStore {
    /// Rebuild the replay state (empty if nothing was stored).
    fn load(&mut self) -> Result<ReplayState, StoreError>;
    /// Persist the block at `state.blocks[index]` together with the leaves,
    /// events, rejections, nullifiers and root it produced.
    fn commit_block(&mut self, state: &ReplayState, index: usize) -> Result<(), StoreError>;
    /// Forget every block above `height` (the in-memory state is already rolled back).
    fn rollback_to(&mut self, state: &ReplayState, height: u32) -> Result<(), StoreError>;
    /// Called once at the end of a sync (whole-file stores write here).
    fn flush(&mut self, state: &ReplayState) -> Result<(), StoreError>;
}
