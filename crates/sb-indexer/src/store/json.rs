//! Whole-state JSON file store (the original persistence).

use std::path::PathBuf;

use super::{StateStore, StoreError};
use crate::state::ReplayState;

pub struct JsonStore {
    pub path: PathBuf,
    /// Blocks committed since the file was last written.
    unsaved: usize,
}

/// A long replay saves its progress every so many blocks, so that a
/// sync cut short (a rate limit, a lost connection) resumes from there.
const SAVE_EVERY: usize = 32;

impl JsonStore {
    pub fn new(path: PathBuf) -> Self {
        JsonStore { path, unsaved: 0 }
    }
}

impl StateStore for JsonStore {
    fn keeps_light_state(&self) -> bool {
        true
    }

    fn load(&mut self) -> Result<ReplayState, StoreError> {
        if self.path.exists() {
            Ok(ReplayState::load(&self.path)?)
        } else {
            Ok(ReplayState::new())
        }
    }

    fn commit_block(&mut self, state: &ReplayState, _index: usize) -> Result<(), StoreError> {
        self.unsaved += 1;
        if self.unsaved >= SAVE_EVERY {
            self.flush(state)?;
        }
        Ok(())
    }

    fn rollback_to(&mut self, _state: &ReplayState, _height: u32) -> Result<(), StoreError> {
        Ok(())
    }

    fn flush(&mut self, state: &ReplayState) -> Result<(), StoreError> {
        state.save(&self.path)?;
        self.unsaved = 0;
        Ok(())
    }
}
