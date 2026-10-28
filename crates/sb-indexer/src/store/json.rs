//! Whole-state JSON file store (the original persistence).

use std::path::PathBuf;

use super::{StateStore, StoreError};
use crate::state::ReplayState;

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
