//! Artifact switch history
//!
//! Tracks artifact switches for `fuz artifact use -` and `fuz artifact log`.

// Allow missing error docs since all errors are self-explanatory ArtifactError variants
#![allow(clippy::missing_errors_doc)]

use super::error::ArtifactError;
use super::meta_file::write_atomic_meta;
use super::{HISTORY_FILE, MAX_HISTORY_ENTRIES};
use fuz_home::get_state_dir;
use fuz_sys::rfc3339_now;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A single entry in the switch history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Artifact hash that was switched to
    pub hash: String,
    /// Version of the artifact
    pub version: String,
    /// When the switch occurred (ISO 8601)
    pub switched_at: String,
    /// Previous artifact hash (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
}

/// Switch history stored in `~/.fuz/state/history.json`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct History {
    /// List of switch entries (newest first)
    pub entries: Vec<HistoryEntry>,
}

impl History {
    /// Read history from disk, returning empty history if file doesn't exist
    pub fn read() -> Result<Self, ArtifactError> {
        let history_path = get_history_path()?;

        if !history_path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&history_path)
            .map_err(|e| ArtifactError::MetadataReadFailed(history_path.clone(), e))?;

        serde_json::from_str(&content)
            .map_err(|e| ArtifactError::MetadataParseFailed(history_path, e))
    }

    /// Write history to disk atomically.
    ///
    /// Delegates to [`fuz_sys::fs::write_atomic`] which handles the
    /// tmp + fsync + rename + parent fsync discipline. A crash mid-write
    /// leaves either the previous history or the new one — never a partial
    /// or lost entry.
    pub fn write(&self) -> Result<(), ArtifactError> {
        let state_dir = get_state_dir()?;
        fuz_sys::fs::create_dir_all_mode(&state_dir, fuz_sys::SECURE_DIR_MODE)
            .map_err(ArtifactError::Io)?;
        // Route through the shared meta writer so an ENOSPC writing history.json
        // surfaces as `InsufficientSpace` (with its free-up-disk hint) rather
        // than a generic `MetadataWriteFailed`, matching the meta.json path.
        write_atomic_meta(self, &state_dir, HISTORY_FILE)
    }

    /// Add a new entry to the history.
    ///
    /// Switching to the artifact that's already newest in the log is a no-op —
    /// it's skipped rather than pushed as a positional duplicate, which would
    /// make [`Self::previous`] (backing `artifact use -`) toggle to the same
    /// artifact. Callers still invoke this unconditionally; the dedup lives here
    /// so every switch path (`build` / `use` / `bootstrap`) is covered.
    pub fn add(&mut self, hash: String, version: String, previous_hash: Option<String>) {
        if self.entries.first().is_some_and(|e| e.hash == hash) {
            return;
        }

        let entry = HistoryEntry {
            hash,
            version,
            switched_at: rfc3339_now(),
            previous_hash,
        };

        // Add at front (newest first)
        self.entries.insert(0, entry);

        // Trim to max size
        if self.entries.len() > MAX_HISTORY_ENTRIES {
            self.entries.truncate(MAX_HISTORY_ENTRIES);
        }
    }

    /// Get the previous artifact hash (for `use -`)
    #[must_use]
    pub fn previous(&self) -> Option<&str> {
        // Current is entries[0], previous is entries[1]
        self.entries.get(1).map(|e| e.hash.as_str())
    }
}

/// Get path to history file
pub fn get_history_path() -> Result<PathBuf, ArtifactError> {
    Ok(get_state_dir()?.join(HISTORY_FILE))
}

/// Record a switch in history.
///
/// Paired with `switch_current` by the artifact-store `use` command:
/// `switch_current` repoints the `current` symlink, this appends the log entry.
/// They are deliberately separate functions — this does not call, and is not
/// called by, `switch_current`.
pub fn record_switch(
    hash: &str,
    version: &str,
    previous_hash: Option<&str>,
) -> Result<(), ArtifactError> {
    let mut history = History::read()?;
    history.add(
        hash.to_string(),
        version.to_string(),
        previous_hash.map(String::from),
    );
    history.write()
}
