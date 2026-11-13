//! Artifact-state mutation lock.
//!
//! One flock-backed lock at `~/.fuz/run/artifact.lock` serializes every
//! operation that mutates `~/.fuz/artifacts/` or `~/.fuz/current`:
//! `fuz artifact build`, `fuz self bootstrap`, `fuz artifact use`,
//! `fuz artifact prune`, `fuz self upgrade`, `cargo xtask install`. Holding it
//! covers the build phase (creating a new artifact), the switch phase
//! (swapping `current`, rewriting `bin/`, appending to `history.json`), and
//! a prune's read of the store and `current` together with its deletes.
//!
//! `flock` is per-process and *not* recursive: the same process trying
//! to acquire the lock twice would deadlock (or `EWOULDBLOCK` with
//! non-blocking). So the outer caller acquires once and threads the
//! [`FileLock`] guard through helpers that need to assert "you hold the
//! lock" — see [`crate::switch_to_artifact`].

#![expect(
    clippy::missing_errors_doc,
    reason = "every error is a self-explanatory `ArtifactError` variant"
)]

use super::ARTIFACT_LOCK_FILE;
use super::error::ArtifactError;
use fuz_home::get_run_dir;
use fuz_sys::file_lock::{FileLock, LockInfo};

/// Acquire the artifact lock at `~/.fuz/run/artifact.lock`. Non-blocking
/// — returns [`ArtifactError::InProgress`] if another process holds it.
///
/// Drop the returned `FileLock` to release.
pub fn acquire_artifact_lock() -> Result<FileLock, ArtifactError> {
    let path = get_run_dir()?.join(ARTIFACT_LOCK_FILE);
    Ok(FileLock::acquire(&path, &LockInfo::current())?)
}
