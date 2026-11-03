//! Shared by the end-to-end tests: a directory under the system temp dir
//! that is removed when the test ends however it ends (an assertion, a
//! panic in a helper, a `?`), so that failed or interrupted runs leave
//! nothing behind (47 `/tmp/sb-*` leftovers of 3 GB were found on 3
//! November 2026). Read-only permissions a test set are undone first.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub struct TempDir(PathBuf);

impl TempDir {
    /// `<temp>/sb-<name>-<pid>`, created empty.
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sb-{name}-{}", std::process::id()));
        let _ = remove(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = remove(&self.0);
    }
}

/// Remove a tree, making read-only parts writable first.
fn remove(dir: &Path) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    writable(dir);
    std::fs::remove_dir_all(dir)
}

#[cfg(unix)]
fn writable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = std::fs::symlink_metadata(p) else {
        return;
    };
    if md.file_type().is_symlink() {
        return;
    }
    let mut perm = md.permissions();
    perm.set_mode(perm.mode() | 0o700);
    let _ = std::fs::set_permissions(p, perm);
    if md.is_dir() {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                writable(&e.path());
            }
        }
    }
}

#[cfg(not(unix))]
fn writable(_p: &Path) {}
