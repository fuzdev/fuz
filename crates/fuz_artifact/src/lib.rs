//! fuz distribution domain: content-addressed artifacts + tool installs.
//!
//! The crate root is the artifact model for fuz self-distribution:
//! - Input-derived hashing (git commit + diff + rustc + target + rustflags)
//! - Artifact storage (`~/.fuz/artifacts/v1-<hash>/`)
//! - Metadata management (meta.json)
//! - Symlink switching (`current` → artifact)
//! - Build locking
//! - Binary platform inspection: what a binary's header says it is for, held
//!   to a release target ([`platform`])
//! - Store-entry policy: a slot that must hold a real directory never is read
//!   through a link (`store`'s `reclaim_store_entry` / `inspect_store_entry`)
//!
//! - Release builds through cargo, each binary's path taken from cargo's own
//!   JSON messages ([`cargo_build_release`])
//!
//! Both the CLI (`fuz artifact build`) and bootstrap (`cargo xtask install`)
//! use it.
//! The [`tools`] module carries the parallel first-party tool-install model
//! (`~/.fuz/tools/<name>/v1-<hash>/`).
//!
//! OS/fs leaf utilities live in `fuz_sys`, the `~/.fuz` home layout in
//! `fuz_home`; content hashing lives in `fuz_crypto`.

mod cargo_build;
mod create;
mod error;
mod hash;
mod history;
mod lock;
mod meta_file;
mod ops;
pub mod platform;
mod store;
mod switch;
mod symlinks;
pub mod tools;
mod types;
mod vcs;

#[cfg(test)]
mod tests;

// Re-export public API
pub use cargo_build::{CargoBuildError, CargoBuildOptions, cargo_build_release, check_built_for};
pub use create::{BuildSource, create_artifact, get_cargo_version};
pub use error::{ArtifactError, CurrentLinkProblem};
pub use hash::{hash_binary, verify_artifact};

pub use history::{History, HistoryEntry, get_history_path, record_switch};
pub use lock::acquire_artifact_lock;
pub use meta_file::{MetaIntegrity, read_checked, write_atomic_meta};
pub use ops::{
    cleanup_incomplete, find_artifact, find_by_inputs, get_artifact_dir, get_current_artifact,
    list_artifacts,
};
pub use store::{
    StoreSlot, current_link_target, inspect_store_entry, reclaim_store_entry,
    require_current_replaceable, store_entry_path,
};
pub use switch::{SwitchOptions, switch_to_artifact};
pub use symlinks::{
    SELF_BINARIES, is_self_binary_name, setup_bin_symlinks, setup_tool_symlinks, switch_current,
};
pub use types::{
    ArtifactInputs, ArtifactMeta, ArtifactOutputs, ArtifactSource, MAX_RELEASE_TOKEN_LEN,
    content_hash_from_binaries, is_content_hash, is_release_token, short_content_hash,
    strip_content_hash_prefix,
};

// `ContentHash` is part of this crate's public surface — `ArtifactOutputs.fuz`
// and `ToolMeta.binaries` carry it, so consumers reading those fields need the
// type without taking a separate `fuz_crypto` dependency.
pub use fuz_crypto::ContentHash;

//
// Constants
//

/// Content hash version. Increment when algorithm changes.
/// Used in directory names: `v1-<blake3_hex>`
pub(crate) const CONTENT_HASH_VERSION: u32 = 1;

/// Content hash prefix (e.g., "v1-")
pub const CONTENT_HASH_PREFIX: &str = "v1-";

/// Short hash length (8 hex chars after prefix).
/// Used for: minimum prefix in `fuz artifact use`, display truncation, temp
/// dir naming.
pub const SHORT_HASH_LEN: usize = 8;

/// Full hash length (blake3 = 64 hex chars)
pub const FULL_HASH_LENGTH: usize = 64;

/// Short git commit length (e.g., "abc123d")
pub const SHORT_COMMIT_LENGTH: usize = 7;

/// Artifact lock file name.
///
/// Single lock covering every operation that mutates `~/.fuz/artifacts/`
/// or `~/.fuz/current` — builds, bootstraps, switches, upgrades. The name
/// `artifact.lock` (not `build.lock`) reflects that broader scope.
pub const ARTIFACT_LOCK_FILE: &str = "artifact.lock";

/// Mode a finished artifact directory carries: `0755`.
///
/// Set explicitly after the staging dir is renamed into place, never inherited
/// from the umask, and never before the rename — the staging tree stays
/// [`fuz_sys::SECURE_DIR_MODE`] until it is a real artifact. Both artifact
/// producers hold it: `create_artifact` here (`fuz artifact build`,
/// `fuz self bootstrap`, `cargo xtask install`) and `fuz_release`'s
/// `fetch_version` (`fuz self upgrade`), which is why it is spelled once in the
/// domain crate rather than twice as a literal.
///
/// The enclosing `~/.fuz/artifacts/` is `0700`, so this is defense in depth
/// about the *artifact*, not an access grant: nothing outside the owner can
/// traverse to it in the first place.
pub const ARTIFACT_DIR_MODE: u32 = 0o755;

/// Meta file name within artifact directory
pub const META_FILE: &str = "meta.json";

/// History file name
pub const HISTORY_FILE: &str = "history.json";

/// Maximum history entries to keep
pub(crate) const MAX_HISTORY_ENTRIES: usize = 100;

/// Buffer size for hashing binaries (64KB)
pub(crate) const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum meta.json size (1 MiB) - prevents abuse via huge metadata files.
/// Aliases the shared trusted-metadata ceiling.
pub(crate) const MAX_META_SIZE: u64 = fuz_sys::limits::MAX_METADATA_SIZE;

/// Minimum reasonable binary size (1 KB) - catches empty/truncated files
pub(crate) const MIN_BINARY_SIZE: u64 = 1024;

/// Maximum reasonable binary size (100 MiB) - prevents abuse via huge files.
/// Aliases the shared in-memory buffered ceiling.
pub(crate) const MAX_BINARY_SIZE: u64 = fuz_sys::limits::MAX_BUFFERED_SIZE;
