//! Artifact operations
//!
//! Functions for listing, finding, and managing artifacts.

#![expect(
    clippy::missing_errors_doc,
    reason = "every error is a self-explanatory `ArtifactError` variant"
)]

use super::error::ArtifactError;
use super::store::{StoreSlot, current_link_target, inspect_store_entry, store_entry_path};
use super::types::ArtifactMeta;
use super::{CONTENT_HASH_PREFIX, SHORT_HASH_LEN, strip_content_hash_prefix};
use fuz_home::{get_artifacts_dir, get_current_link};
use fuz_sys::fs::is_real_dir;
use std::fs;
use std::path::PathBuf;

//
// Artifact listing and lookup
//

/// Normalize user-provided prefix by stripping optional `v1-` prefix.
/// User can type `abc123de` or `v1-abc123de` - both work identically.
fn normalize_prefix(prefix: &str) -> &str {
    strip_content_hash_prefix(prefix)
}

/// One committed-artifact directory entry surviving the scan's name filters.
#[derive(Debug)]
struct ArtifactDirEntry {
    /// Full path to the entry (`<artifacts dir>/v1-<hash>`).
    path: PathBuf,
    /// The entry's name (`v1-<hash>`), lossily decoded for matching and
    /// warning messages.
    name: String,
}

impl ArtifactDirEntry {
    /// The content-hash portion of `name` — everything after
    /// `CONTENT_HASH_PREFIX`, which the scan's name filter guarantees is there.
    fn hash_part(&self) -> &str {
        strip_content_hash_prefix(&self.name)
    }
}

/// Scan the artifacts directory for committed-artifact entries.
///
/// The shared dirent half of [`list_artifacts`], [`find_artifact`], and
/// [`find_by_inputs`]: a missing artifacts directory scans as empty (each
/// caller phrases its own "nothing here" answer), an unreadable dirent warns
/// and is skipped rather than failing the whole scan, and names are filtered
/// down to committed artifacts — a leading `.` marks an incomplete build, and
/// a name without `CONTENT_HASH_PREFIX` is not an artifact at all.
///
/// Filtering is by **name only**; a caller that also requires a real directory
/// checks `path` itself.
fn scan_artifact_dirs() -> Result<Vec<ArtifactDirEntry>, ArtifactError> {
    let artifacts_dir = get_artifacts_dir()?;

    if !artifacts_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();

    for entry in fs::read_dir(&artifacts_dir).map_err(ArtifactError::Io)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("warning: skipping unreadable artifact entry: {e}");
                continue;
            }
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip temp directories (incomplete builds)
        if name_str.starts_with('.') {
            continue;
        }

        // Only consider v1- prefixed directories (complete artifacts)
        if !name_str.starts_with(CONTENT_HASH_PREFIX) {
            continue;
        }

        entries.push(ArtifactDirEntry {
            path: entry.path(),
            name: name_str.into_owned(),
        });
    }

    Ok(entries)
}

/// Read a scanned entry's metadata, skipping a corrupt one with a warning.
///
/// The graceful-skip half of the scan, for the callers that read every entry —
/// one unreadable `meta.json` must not abort the sweep. [`find_artifact`] does
/// **not** use it: a read failure on the single artifact the user named is
/// propagated rather than swallowed.
fn read_artifact_meta(entry: &ArtifactDirEntry) -> Option<ArtifactMeta> {
    match ArtifactMeta::read(&entry.path) {
        Ok(meta) => Some(meta),
        Err(e) => {
            eprintln!("warning: skipping corrupt artifact {}: {e}", entry.name);
            None
        }
    }
}

/// List all complete artifacts, sorted by creation time (newest first)
///
/// Gracefully skips unreadable artifacts with a warning rather than failing.
/// Only real directories are listed — a symlink at `v1-<hash>` is skipped,
/// never followed.
pub fn list_artifacts() -> Result<Vec<ArtifactMeta>, ArtifactError> {
    let mut artifacts = Vec::new();

    for entry in scan_artifact_dirs()? {
        // A real directory only: a symlink at `v1-<hash>` — even one aimed at a
        // valid artifact — is not an artifact fuz wrote.
        if !is_real_dir(&entry.path) {
            continue;
        }

        if let Some(meta) = read_artifact_meta(&entry) {
            artifacts.push(meta);
        }
    }

    // Sort by created_at descending (newest first)
    artifacts.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok(artifacts)
}

/// Find artifact by content hash prefix.
///
/// Accepts prefixes with or without the `v1-` prefix (e.g., `abc123de` or `v1-abc123de`).
/// Requires at least 8 characters after normalization.
///
/// Gracefully skips unreadable entries during scan, but returns error if
/// the matched artifact itself is unreadable (user asked for it specifically)
/// or is not a real directory ([`ArtifactError::StoreEntryNotDir`]).
///
/// # Errors
///
/// Returns error if prefix is too short, no artifact matches, or multiple artifacts match.
pub fn find_artifact(prefix: &str) -> Result<ArtifactMeta, ArtifactError> {
    let normalized = normalize_prefix(prefix);
    if normalized.len() < SHORT_HASH_LEN {
        return Err(ArtifactError::PrefixTooShort {
            given: normalized.len(),
            minimum: SHORT_HASH_LEN,
        });
    }

    // Match against hash portion (after v1-)
    let matches: Vec<ArtifactDirEntry> = scan_artifact_dirs()?
        .into_iter()
        .filter(|entry| entry.hash_part().starts_with(normalized))
        .collect();

    match matches.len() {
        0 => Err(ArtifactError::NotFound(prefix.to_string())),
        // Error here IS propagated (user asked for this artifact), and the
        // entry must be a real directory — a symlink there is refused, not read
        // through.
        1 => {
            let entry = &matches[0];
            inspect_store_entry(
                &get_artifacts_dir()?,
                entry.path.file_name().unwrap_or_default(),
            )?;
            ArtifactMeta::read(&entry.path)
        }
        _ => {
            // Show full hashes so user can pick unique prefix
            let candidates: Vec<String> = matches.into_iter().map(|entry| entry.name).collect();
            Err(ArtifactError::AmbiguousPrefix {
                prefix: prefix.to_string(),
                candidates,
            })
        }
    }
}

/// Find artifact with matching input hash (cache lookup).
///
/// Returns the artifact if found, None if no cache hit.
/// Used by `fuz artifact build` to skip building when inputs haven't changed.
///
/// Gracefully skips unreadable artifacts with a warning rather than failing
/// the entire scan. This allows operation to continue even if one artifact
/// is corrupt. An entry that is not a real directory (a symlink, a file) is
/// skipped silently, as [`list_artifacts`] skips it.
pub fn find_by_inputs(input_hash: &str) -> Result<Option<ArtifactMeta>, ArtifactError> {
    for entry in scan_artifact_dirs()? {
        // A link at `v1-<hash>` is never a cache hit: the switch that follows a
        // hit refuses one, so skipping it here lets the build land a real
        // artifact (`create_artifact` unlinks the entry) instead of stranding.
        if !is_real_dir(&entry.path) {
            continue;
        }
        let Some(meta) = read_artifact_meta(&entry) else {
            continue;
        };

        // Only local builds have inputs; remote artifacts don't match cache lookups
        if meta
            .inputs
            .as_ref()
            .is_some_and(|inputs| inputs.input_hash == input_hash)
        {
            return Ok(Some(meta));
        }
    }

    Ok(None)
}

/// Get current artifact (via `current` symlink)
///
/// `Ok(None)` when there is no `current` link or it dangles. `current` must be
/// the link fuz writes — `artifacts/v1-<hash>`, or the absolute path of the same
/// entry ([`current_link_target`]) — and the artifact it names a real
/// directory. Anything else is an error, never read through:
/// [`ArtifactError::CurrentNotStoreLink`] for a `current` that is not a symlink
/// or points outside `artifacts/`, [`ArtifactError::StoreEntryNotDir`] for a
/// symlink (live or dangling) or file at `artifacts/v1-<hash>`.
pub fn get_current_artifact() -> Result<Option<ArtifactMeta>, ArtifactError> {
    let current_link = get_current_link()?;
    let artifacts_dir = get_artifacts_dir()?;
    let Some(name) = current_link_target(&current_link, &artifacts_dir)? else {
        return Ok(None);
    };

    if inspect_store_entry(&artifacts_dir, &name)? == StoreSlot::Vacant {
        return Ok(None);
    }

    Ok(Some(ArtifactMeta::read(&artifacts_dir.join(name))?))
}

/// Clean up incomplete artifacts (`.building-*` and `.bootstrapping-*` dirs).
///
/// Called under the `BuildLock` at the start of `fuz artifact build` and
/// `fuz self bootstrap` to remove orphaned temp directories from previous crashed or
/// interrupted runs. Both prefixes are swept regardless of caller — neither
/// command should ever leave its own stale temp dirs behind, and a previous
/// crash of either command shouldn't pile up over time.
///
/// Best-effort: an unreadable dirent or a failed `remove_dir_all` is logged
/// and skipped rather than aborting the whole sweep, matching the
/// `warning: skipping …` pattern of `scan_artifact_dirs`. It walks the
/// directory itself rather than reusing that scan — its name filter is the
/// scan's inverse in the part that matters (its name filter selects two
/// specific dot-prefixed temp families the scan drops) and it reads
/// no metadata.
pub fn cleanup_incomplete() -> Result<usize, ArtifactError> {
    let artifacts_dir = get_artifacts_dir()?;

    if !artifacts_dir.exists() {
        return Ok(0);
    }

    let mut removed = 0;

    for entry in fs::read_dir(&artifacts_dir).map_err(ArtifactError::Io)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("warning: skipping unreadable artifact entry during cleanup: {e}");
                continue;
            }
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.starts_with(".building-") || name_str.starts_with(".bootstrapping-") {
            match fs::remove_dir_all(entry.path()) {
                Ok(()) => removed += 1,
                Err(e) => {
                    eprintln!("warning: failed to remove incomplete artifact {name_str}: {e}");
                }
            }
        }
    }

    Ok(removed)
}

/// Get artifact directory path for a content hash
///
/// # Errors
///
/// [`ArtifactError::InvalidStoreName`] when `content_hash` is not one plain
/// path component, so the returned path is always a child of the artifacts
/// directory; or a home-resolution error.
pub fn get_artifact_dir(content_hash: &str) -> Result<PathBuf, ArtifactError> {
    store_entry_path(&get_artifacts_dir()?, content_hash)
}
