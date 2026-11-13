//! Locked `current`-artifact switch.
//!
//! The composed activation that `fuz artifact build`, `fuz artifact use`,
//! `fuz self upgrade`, and `cargo xtask install` all reach: verify →
//! `switch_current` → `setup_bin_symlinks` → `record_switch`. It lives here
//! rather than in a caller so the ordering *and* the "you hold the lock"
//! discipline are stated once. `fuz self bootstrap` activates too, but
//! composes those steps itself around the artifact it just created.

#![expect(
    clippy::missing_errors_doc,
    reason = "every error is a self-explanatory `ArtifactError` variant"
)]

use super::SHORT_HASH_LEN;
use super::error::ArtifactError;
use super::hash::verify_artifact;
use super::history::record_switch;
use super::ops::get_artifact_dir;
use super::store::{StoreSlot, inspect_store_entry};
use super::symlinks::{setup_bin_symlinks, switch_current};
use fuz_home::get_artifacts_dir;
use fuz_sys::file_lock::FileLock;

/// Options for switching artifacts
#[derive(Debug, Clone, Copy)]
pub struct SwitchOptions<'a> {
    /// Target artifact hash
    pub hash: &'a str,
    /// Target artifact version
    pub version: &'a str,
    /// Previous artifact hash (for history and rollback)
    pub previous_hash: Option<&'a str>,
    /// Quiet mode
    pub quiet: bool,
}

/// Switch the `current` artifact and bin symlinks.
///
/// The `_lock` parameter is a compile-time witness that the caller already
/// holds the artifact lock. Every activating command acquires it, because two
/// concurrent switches would otherwise race on the `current` symlink swap and
/// on the read-modify-write of `history.json`. `flock` is not recursive, so
/// the only safe pattern is "outer caller acquires, helpers borrow proof of
/// acquisition."
///
/// Flow:
/// 1. Require a real artifact directory (a symlink or file at
///    `artifacts/v1-<hash>` is refused with [`ArtifactError::StoreEntryNotDir`]
///    and left in place), then verify its integrity
/// 2. Switch the `current` symlink
/// 3. Set up bin symlinks
/// 4. Record in history (only once the on-disk switch is fully consistent)
///
/// History is recorded after the symlinks are in place so a partial switch
/// never appears in `fuz artifact log`.
///
/// **fuz does not drive fuzd's lifecycle** (no proxying, no delegating):
/// it never stops or starts the
/// daemon. The self artifact is fuz-only, so a swap never touches fuzd at all
/// — fuzd is a separately-installed tool, and the "run `fuzd restart`" nudge
/// lives on the tool commands that move its active binary: `fuz tool install
/// fuzd` and `fuz tool upgrade fuzd`.
pub fn switch_to_artifact(opts: SwitchOptions<'_>, _lock: &FileLock) -> Result<(), ArtifactError> {
    // The artifact must be the real directory fuz renamed into place: a link
    // there is refused (and left alone — a switch has nothing to rebuild it
    // from), since verifying through it would vouch for whatever it points at.
    let artifact_dir = get_artifact_dir(opts.hash)?;
    if inspect_store_entry(&get_artifacts_dir()?, opts.hash)? == StoreSlot::Vacant {
        return Err(ArtifactError::NotFound(opts.hash.to_string()));
    }

    // Verify artifact integrity before switching
    verify_artifact(&artifact_dir)?;

    // Switch current symlink
    if !opts.quiet {
        println!(
            "Switching to {}... ({})",
            &opts.hash[..SHORT_HASH_LEN],
            opts.version
        );
    }
    switch_current(opts.hash)?;

    // Ensure bin/ symlinks point through current. The self artifact is
    // fuz-only; fuzd's `bin/` link is owned by the tool-install path and is
    // left untouched here (see `setup_bin_symlinks`).
    setup_bin_symlinks(&["fuz"])?;

    // Record in history only after the on-disk switch is fully complete.
    record_switch(opts.hash, opts.version, opts.previous_hash)?;

    if !opts.quiet {
        println!("Done.");
    }

    Ok(())
}
