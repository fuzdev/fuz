//! Release infrastructure for Fuz
//!
//! This crate provides:
//! - Manifest parsing, signature verification, and the shipped-binary checks
//!   (`check_no_test_binaries`, `check_no_self_binaries`)
//! - Tarball hashing, verification, and extraction (over `fuz_archive`'s
//!   hardened extractor), and the SHA-512 sidecars `install.sh` reads
//! - Version safety checks (minimum version, downgrade protection) and the
//!   installed-version resolution they start from
//! - [`ReleaseLayout`], the storage-key layout publish and fetch share
//! - Release log head types and the append-only rules that compare two heads,
//!   and co-signatures ([`co_sign`]) over a head
//! - The release log check: an install, an update check, and a first install
//!   each hold a release to the log before its bytes are used or reported on
//! - Fetch and install workflows, for the fuz self artifact and per-tool
//! - The pure prune selection ([`select_prune_releases`]); listing, signing,
//!   publishing, and deleting live in `fuz_sign`
//!
//! Storage backends are provided by the `fuz_storage` crate.

// Allow missing errors docs for obvious Result functions
#![allow(clippy::missing_errors_doc)]
// Allow implicit hasher - we only use std HashMap
#![allow(clippy::implicit_hasher)]

pub mod checksum;
pub mod co_sign;
pub mod current;
pub mod error;
pub mod fetch;
pub mod layout;
pub mod log_check;
pub mod manifest;
pub mod prune;
pub mod release_log;
pub mod tarball;
pub mod tool;

#[cfg(test)]
mod tests;

pub use checksum::{parse_sidecar, sha512_hex, sidecar_content};
pub use co_sign::{
    CO_SIGN_NAMESPACE, CoSign, CoSignCoverage, CoSignProblem, CoSignReport, MAX_WITNESS_SIZE,
    WITNESS_KEY, compare_co_sign, verify_co_sign,
};
pub use current::{CurrentVersion, resolve_current_self, resolve_current_tool};
pub use error::{LogWriteError, ManifestError, ReleaseError, TarballError};
pub use fetch::{
    FetchOptions, FetchResult, LatestInfo, download_manifest, fetch_latest, fetch_latest_manifest,
    fetch_version,
};
pub use layout::ReleaseLayout;
pub use log_check::{
    EffectiveHead, HEAD_KEY, HeadSource, InstalledStanding, LatestCheck, LocalSelfBinary, LogCheck,
    LogOrigin, LogOrigins, RELEASE_LOG_ENV, RELEASE_LOG_URL_ENV, ReleaseLogPolicy,
    ReleaseLogReport, ReleasePins, ResolvedLog, RowVerdict, WitnessKeys, cached_installed_standing,
    check_bootstrap_binary, check_latest_self, check_latest_tool, check_release_log,
    check_release_log_read_only, head_cache_path, installed_standing, is_revoked, reconcile_heads,
    resolve_log, resolve_log_read_only, row_verdict,
};
pub use manifest::{
    BinaryHashes, Manifest, ManifestUnsigned, TarballInfo, UpdateCheck, UpdateStatus,
    VerifiedManifest, check_no_self_binaries, check_no_test_binaries,
    check_version_safety_with_downgrade, compute_update_check, current_release_target,
    current_target, is_test_binary_name, validate_tarball_path,
};
pub use prune::{RemoteRelease, select_prune_releases};
pub use release_log::{
    CacheProblem, HEAD_FORMAT_VERSION, Head, HeadField, HeadInvalid, HeadOrder, HeadUnsigned,
    HeadViolation, KeyRecord, LogConfigError, LogContradiction, MAX_HEAD_SEQ, MAX_HEAD_SIZE,
    PinnedBy, ReleaseLogError, ReleaseRow, RowStatus, Succession, TargetField, TargetRow,
    UnreachableOrigin, VerifiedHead, check_consistent, check_successor, check_superset,
};
pub use tarball::{
    TarballDigest, create_meta_json, extract_tarball, extract_tarball_reader, pack_tarball_to_file,
    verify_binary_hashes, verify_content_hash, verify_tarball_file, verify_tarball_hash,
};
pub use tool::{
    ToolInstallOptions, ToolInstallOutcome, ToolInstallResult, fetch_tool_manifest, install_tool,
    installed_tool_meta, list_installed_tools, verify_installed_tool,
};

// Re-export what a consumer needs of `fuz_storage` (the canonical source):
// this crate is the fetch/verify/install side, and a consumer binary reaches
// storage through it alone. So the one parse on offer is
// `parse_existing_storage`, which refuses a local directory that is not
// there. A publish, which may target a store that does not exist yet, takes
// `fuz_storage::parse_storage` from `fuz_storage` itself.
pub use fuz_storage::{Storage, StorageBackend, StorageError, parse_existing_storage};

//
// Constants
//

/// Maximum manifest format version this client understands.
/// Clients MUST reject manifests with format > this value.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// Maximum manifest size in bytes (1MB - manifests are small JSON)
pub const MAX_MANIFEST_SIZE: u64 = fuz_sys::limits::MAX_METADATA_SIZE;

// The 10 GiB extraction ceilings are single-sourced in `fuz_sys::limits`
// (shared with `fuz_storage`'s transfer cap) and re-exported here so they
// remain part of `fuz_release`'s public surface. Gzip-bomb protection is the
// independent [`MAX_COMPRESSION_RATIO`] check below, which holds regardless of
// these sizes.
pub use fuz_sys::limits::{MAX_FILE_SIZE, MAX_TOTAL_SIZE};

/// Maximum compression ratio: 100x (prevents gzip bombs).
///
/// A 1MB compressed file can decompress to at most 100MB. Size-independent, so
/// it stays the real bomb guard even with the GB-scale size ceilings above.
pub const MAX_COMPRESSION_RATIO: u64 = 100;

/// Required binaries in a *self* (fuz) manifest — `tool: None` — and the
/// names no tool manifest may declare.
///
/// The self artifact is **fuz-only**: fuzd is a separately-installed tool
/// (`fuz tool install fuzd`), not part of the fuz binary's own artifact. Tool
/// manifests (`tool: Some(name)`) declare their own binary set; the self
/// artifact is pinned to just `fuz`. Defined by `fuz_artifact`, which links
/// these names in `~/.fuz/bin/`.
pub use fuz_artifact::SELF_BINARIES;

/// The self artifact's name: its one binary, the basename of its storage keys,
/// and the name of its rows in the release log.
pub const SELF_NAME: &str = SELF_BINARIES[0];
