//! Persistence of the replayed state: a whole-state JSON file.

use std::path::PathBuf;

use crate::state::ReplayState;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state file: {0}")]
    State(#[from] crate::state::StateError),
}

pub trait StateStore {
    /// Rebuild the replay state (empty if nothing was stored).
    fn load(&mut self) -> Result<ReplayState, StoreError>;
    /// Persist the block at `state.blocks[index]`.
    fn commit_block(&mut self, state: &ReplayState, index: usize) -> Result<(), StoreError>;
    /// Forget every block above `height` (the in-memory state is already rolled back).
    fn rollback_to(&mut self, state: &ReplayState, height: u32) -> Result<(), StoreError>;
    /// Called once at the end of a sync.
    fn flush(&mut self, state: &ReplayState) -> Result<(), StoreError>;
}

pub struct JsonStore {
    pub path: PathBuf,
}

impl JsonStore {
    pub fn new(path: PathBuf) -> Self {
        JsonStore { path }
    }
}

impl StateStore for JsonStore {
    fn load(&mut self) -> Result<ReplayState, StoreError> {
        if self.path.exists() {
            Ok(ReplayState::load(&self.path)?)
        } else {
            Ok(ReplayState::new())
        }
    }

    fn commit_block(&mut self, _state: &ReplayState, _index: usize) -> Result<(), StoreError> {
        Ok(())
    }

    fn rollback_to(&mut self, _state: &ReplayState, _height: u32) -> Result<(), StoreError> {
        Ok(())
    }

    fn flush(&mut self, state: &ReplayState) -> Result<(), StoreError> {
        Ok(state.save(&self.path)?)
    }
}
