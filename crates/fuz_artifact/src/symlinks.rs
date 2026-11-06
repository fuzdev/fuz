//! Symlink management
//!
//! Functions for managing the `current` symlink and bin/ symlinks.

// Allow missing error docs since all errors are self-explanatory ArtifactError variants
#![allow(clippy::missing_errors_doc)]

use super::error::ArtifactError;
use super::store::{StoreSlot, inspect_store_entry, require_current_replaceable};
use fuz_home::{
    CURRENT_LINK, TOOLS_DIR, get_artifacts_dir, get_bin_dir, get_current_link, get_tool_dir,
};
use fuz_sys::SECURE_DIR_MODE;
use std::fs;
use std::path::{Path, PathBuf};

/// Switch `current` symlink to point to artifact.
///
/// The swap is atomic and crash-durable (temp symlink → rename → parent
/// fsync) via [`fuz_sys::fs::replace_symlink_atomic`].
///
/// The target must be a real directory at `artifacts/v1-<hash>`: nothing there is
/// [`ArtifactError::NotFound`], and a symlink (live or dangling) or file is
/// refused with [`ArtifactError::StoreEntryNotDir`] and left in place —
/// `current` is never pointed at an entry that would redirect every read
/// through it. A `current` that is not itself a symlink is refused with
/// [`ArtifactError::CurrentNotStoreLink`] and left in place too.
pub fn switch_current(artifact_hash: &str) -> Result<(), ArtifactError> {
    let current_link = get_current_link()?;
    let artifacts_dir = get_artifacts_dir()?;

    // Relative path from ~/.fuz/ to artifact
    let relative_target = PathBuf::from("artifacts").join(artifact_hash);

    // The artifact must exist as a real directory.
    if inspect_store_entry(&artifacts_dir, artifact_hash)? == StoreSlot::Vacant {
        return Err(ArtifactError::NotFound(artifact_hash.to_string()));
    }

    // A `current` that is not a symlink is not something fuz wrote, and the
    // rename below would fail `EISDIR` on a directory: refuse it, leave it.
    require_current_replaceable(&current_link)?;
    fuz_sys::fs::replace_symlink_atomic(&relative_target, &current_link)
        .map_err(ArtifactError::SymlinkFailed)
}

/// The binaries of the fuz self artifact — the names it owns in `~/.fuz/bin/`.
///
/// [`setup_bin_symlinks`] links each through `current`, and no tool may
/// install a binary under one ([`setup_tool_symlinks`] refuses it).
///
/// The self artifact is fuz-only — `fuzd` is **not** here. fuzd's `bin/fuzd`
/// link is owned by the per-tool install path ([`setup_tool_symlinks`]); if it
/// were in this set, every `fuz artifact build` / `fuz artifact use` /
/// `fuz self upgrade` would unlink the separately-installed fuzd. A `bin/fuzd`
/// pointing into the fuz-only self artifact is left to dangle harmlessly until
/// `fuz tool install fuzd` repoints it (a dangling link reads as "not
/// installed", which is correct).
pub const SELF_BINARIES: &[&str] = &["fuz"];

/// Whether `name` is a self binary's name ([`SELF_BINARIES`]), compared
/// without regard to ASCII case.
///
/// `bin/Fuz` and `bin/fuz` are one directory entry on a case-insensitive
/// filesystem, so the reserved-name refusals — `check_tool_binary_names`
/// here and the tool manifest's in `fuz_release` — share this comparison. It
/// folds the ASCII letters and nothing else: a name that differs from a self
/// binary's by a non-ASCII character is a different name here, whatever a
/// filesystem that folds or normalizes Unicode makes of it.
#[must_use]
pub fn is_self_binary_name(name: &str) -> bool {
    SELF_BINARIES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name))
}

/// Refuse a tool binary set that names a binary that is not a release token
/// ([`is_release_token`](crate::is_release_token)), or that names a self binary
/// ([`SELF_BINARIES`]) in any ASCII case ([`is_self_binary_name`]).
///
/// Every tool binary is linked into the one `~/.fuz/bin/` that holds the self
/// artifact's links, so a tool declaring `fuz` would repoint `bin/fuz` at
/// itself; and every name is a path component and part of the content hash's
/// input, so it must be a token. Both tool install paths call this before they
/// write anything, and [`setup_tool_symlinks`] again before it moves a link.
///
/// # Errors
///
/// [`ArtifactError::InvalidBinaryName`] for the first name that is not a
/// token, else [`ArtifactError::ReservedBinaryName`] for the first self
/// binary's name.
pub fn check_tool_binary_names(tool: &str, binaries: &[&str]) -> Result<(), ArtifactError> {
    if let Some(binary) = binaries.iter().find(|name| !crate::is_release_token(name)) {
        return Err(ArtifactError::InvalidBinaryName {
            tool: tool.to_string(),
            binary: (*binary).to_string(),
        });
    }
    if let Some(binary) = binaries.iter().find(|name| is_self_binary_name(name)) {
        return Err(ArtifactError::ReservedBinaryName {
            tool: tool.to_string(),
            binary: (*binary).to_string(),
        });
    }
    Ok(())
}

/// Set up bin/ symlinks to point through `current`.
///
/// For each requested binary, atomically replaces `bin/<name>` via a
/// temp-symlink + `rename` so a concurrent shell PATH lookup never sees
/// `bin/fuz` missing. Stale binaries (in [`SELF_BINARIES`] but not in the
/// requested set) are unlinked afterward.
///
/// The self artifact is fuz-only, so the only expected call is `&["fuz"]`.
pub fn setup_bin_symlinks(binaries: &[&str]) -> Result<(), ArtifactError> {
    let bin_dir = get_bin_dir()?;
    fuz_sys::fs::create_dir_all_mode(&bin_dir, SECURE_DIR_MODE).map_err(ArtifactError::Io)?;

    // Atomically (re)create each requested link via temp + rename so
    // there's no window where `bin/<name>` is absent.
    for binary in binaries {
        let link_path = bin_dir.join(binary);
        let target = PathBuf::from("..").join("current").join(binary);
        fuz_sys::fs::replace_symlink_atomic(&target, &link_path)
            .map_err(ArtifactError::SymlinkFailed)?;
    }

    // Remove any known binary symlinks that aren't in the requested set
    // (e.g. dropping bin/fuzd when switching to a bootstrap artifact).
    for stale in SELF_BINARIES {
        if binaries.contains(stale) {
            continue;
        }
        let link_path = bin_dir.join(stale);
        let _ = fs::remove_file(&link_path);
    }

    Ok(())
}

/// Point a tool's `current` symlink at `v1-<hash>` and link each of its binaries
/// into `~/.fuz/bin/`.
///
/// Mirrors [`setup_bin_symlinks`] for the per-tool layout:
/// - `~/.fuz/tools/<name>/current` → `v1-<hash>` (relative, within the tool dir)
/// - `~/.fuz/bin/<binary>` → `../tools/<name>/current/<binary>`
///
/// Both swaps are atomic and crash-durable (temp + `rename` + parent fsync) via
/// [`fuz_sys::fs::replace_symlink_atomic`], so a concurrent PATH lookup never
/// sees a missing link. Unlike the self artifact, there's no stale-binary
/// cleanup pass — a tool's binary set is whatever the caller passes (the signed
/// manifest's declared set). Its names are held to `check_tool_binary_names`
/// before any link moves: one that is not a release token is refused with
/// [`ArtifactError::InvalidBinaryName`], and one named for a self binary
/// ([`is_self_binary_name`]: [`SELF_BINARIES`] in any ASCII case) with
/// [`ArtifactError::ReservedBinaryName`], so a
/// tool does not take over `bin/fuz` under such a name; two tools
/// declaring one name are not told apart, and the later link wins. A `current` that is
/// not a symlink is refused ([`ArtifactError::CurrentNotStoreLink`]) and left
/// in place.
pub fn setup_tool_symlinks(name: &str, hash: &str, binaries: &[&str]) -> Result<(), ArtifactError> {
    check_tool_binary_names(name, binaries)?;
    let tool_dir = get_tool_dir(name)?;

    // tools/<name>/current -> v1-<hash>. A `current` that is not a symlink is
    // refused and left in place, as for the self `current`.
    let current_link = tool_dir.join(CURRENT_LINK);
    require_current_replaceable(&current_link)?;
    fuz_sys::fs::replace_symlink_atomic(Path::new(hash), &current_link)
        .map_err(ArtifactError::SymlinkFailed)?;

    let bin_dir = get_bin_dir()?;
    fuz_sys::fs::create_dir_all_mode(&bin_dir, SECURE_DIR_MODE).map_err(ArtifactError::Io)?;
    for binary in binaries {
        let link_path = bin_dir.join(binary);
        let target = PathBuf::from("..")
            .join(TOOLS_DIR)
            .join(name)
            .join(CURRENT_LINK)
            .join(binary);
        fuz_sys::fs::replace_symlink_atomic(&target, &link_path)
            .map_err(ArtifactError::SymlinkFailed)?;
    }

    Ok(())
}
