//! Artifact type definitions
//!
//! Core types for artifact metadata: inputs, outputs, and combined metadata.

#![expect(
    clippy::missing_errors_doc,
    reason = "every error is a self-explanatory `ArtifactError` variant"
)]

use super::error::ArtifactError;
use super::meta_file::{self, MetaIntegrity};
use super::{
    CONTENT_HASH_PREFIX, CONTENT_HASH_VERSION, FULL_HASH_LENGTH, META_FILE, SHORT_COMMIT_LENGTH,
    SHORT_HASH_LEN,
};
use crate::vcs::{self, VcsError};
use fuz_crypto::{ContentHash, HashAlgo, Hasher};
use fuz_sys::rfc3339_now;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;

//
// Inputs hash
//

/// Inputs used for artifact hash computation (for cache lookup)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInputs {
    /// Computed input hash for cache lookup (raw blake3 hex, no version prefix)
    pub input_hash: String,
    /// Git commit SHA (40 hex chars)
    pub git_commit: String,
    /// Blake3 hash of git diff, or null if clean
    pub git_diff_hash: Option<String>,
    /// Rustc version string (first line of `rustc --version`)
    pub rustc_version: String,
    /// Target triple (e.g., x86_64-unknown-linux-gnu)
    pub target: String,
}

impl ArtifactInputs {
    /// Collect inputs from the given repo directory
    pub fn collect(repo_path: &Path) -> Result<Self, ArtifactError> {
        // Verify git repo exists
        if !vcs::is_repo(repo_path) {
            return Err(VcsError::NotRepo(repo_path.to_path_buf()).into());
        }

        let git_commit = vcs::get_commit(repo_path)?;
        let git_diff_hash = vcs::get_diff_hash(repo_path)?;
        // From the repo, so rustup resolves the toolchain `cargo build` there
        // uses (`rust-toolchain.toml`), not the one of the caller's cwd.
        let rustc_version = get_rustc_version(repo_path)?;
        let target = get_rustc_target(repo_path)?;
        let rustflags: Vec<(&str, Option<OsString>)> = RUSTFLAGS_ENV_VARS
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        let rustflags: Vec<(&str, Option<&[u8]>)> = rustflags
            .iter()
            .map(|(name, value)| (*name, value.as_deref().map(OsStrExt::as_bytes)))
            .collect();

        let input_hash = compute_input_hash(
            &git_commit,
            git_diff_hash.as_deref(),
            &rustc_version,
            &target,
            &rustflags,
        );

        Ok(Self {
            input_hash,
            git_commit,
            git_diff_hash,
            rustc_version,
            target,
        })
    }

    /// Check if repo is dirty (has uncommitted changes)
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.git_diff_hash.is_some()
    }

    /// Get "dirty" or "clean" string for display
    #[must_use]
    pub const fn dirty_str(&self) -> &'static str {
        if self.is_dirty() { "dirty" } else { "clean" }
    }

    /// Get short git commit (first 7 chars, or full string if shorter)
    #[must_use]
    pub fn short_commit(&self) -> &str {
        let len = self.git_commit.len().min(SHORT_COMMIT_LENGTH);
        &self.git_commit[..len]
    }
}

/// The environment variables that set rustc flags for `cargo build`, folded
/// into the input hash: the same source at the same toolchain built with other
/// flags is another build. Listed in cargo's order of precedence.
pub const RUSTFLAGS_ENV_VARS: &[&str] = &[
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
];

/// Compute the input hash from its components (BLAKE3, 64 lowercase hex).
///
/// The hash is over `git_commit \n git_diff \n rustc_version \n target`,
/// where `git_diff` is the diff hash or empty when clean, then one record per
/// entry of `rustflags` (each of [`RUSTFLAGS_ENV_VARS`] with its value, or
/// `None` when unset): `\n`, the name, then `=` with the value's length as a
/// little-endian `u64` and its bytes, or `!` when unset. Set-but-empty and
/// unset are different inputs, as they are to cargo.
///
/// For cache lookup only: a change to the format costs a cache miss and
/// nothing else.
#[must_use]
pub fn compute_input_hash(
    git_commit: &str,
    git_diff_hash: Option<&str>,
    rustc_version: &str,
    target: &str,
    rustflags: &[(&str, Option<&[u8]>)],
) -> String {
    let mut hasher = Hasher::new(HashAlgo::Blake3);

    hasher.update(git_commit.as_bytes());
    hasher.update(b"\n");

    // git_diff: empty string if clean, hash otherwise
    if let Some(diff_hash) = git_diff_hash {
        hasher.update(diff_hash.as_bytes());
    }
    hasher.update(b"\n");

    hasher.update(rustc_version.as_bytes());
    hasher.update(b"\n");

    hasher.update(target.as_bytes());

    for (name, value) in rustflags {
        hasher.update(b"\n");
        hasher.update(name.as_bytes());
        match value {
            Some(bytes) => {
                hasher.update(b"=");
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
            None => hasher.update(b"!"),
        }
    }

    hasher.finalize().to_hex()
}

fn get_rustc_version(repo_path: &Path) -> Result<String, ArtifactError> {
    let output = Command::new("rustc")
        .arg("--version")
        .current_dir(repo_path)
        .output()
        .map_err(|_| ArtifactError::RustcFailed)?;

    if !output.status.success() {
        return Err(ArtifactError::RustcFailed);
    }

    // First line only
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string())
}

fn get_rustc_target(repo_path: &Path) -> Result<String, ArtifactError> {
    let output = Command::new("rustc")
        .arg("-vV")
        .current_dir(repo_path)
        .output()
        .map_err(|_| ArtifactError::RustcFailed)?;

    if !output.status.success() {
        return Err(ArtifactError::RustcFailed);
    }

    // Find "host: <target>" line
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(target) = line.strip_prefix("host: ") {
            return Ok(target.trim().to_string());
        }
    }

    Err(ArtifactError::RustcFailed)
}

//
// Artifact outputs
//

/// Output hashes for the self-artifact binaries.
///
/// The self artifact is **fuz-only** — it ships exactly the `fuz` binary. fuzd
/// and every other tool are separate per-tool artifacts (`fuz tool install`),
/// each carrying their own binary set via `ToolMeta`; they never ride the self
/// artifact. (A `meta.json` whose outputs also carry a `fuzd` hash parses with
/// the key ignored, then fails its content-hash integrity check on read when
/// its stored hash covered both.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactOutputs {
    /// Blake3 hash of the `fuz` binary. Bare-hex on the wire (the meta.json
    /// shape) via the [`fuz_crypto::blake3_hex`] serde adapter.
    #[serde(with = "fuz_crypto::blake3_hex")]
    pub fuz: ContentHash,
}

impl ArtifactOutputs {
    /// Compute content hash from output binary hashes.
    ///
    /// # Stability
    ///
    /// This format is **stable** - changing it invalidates all existing artifacts
    /// and breaks signature verification for published releases.
    ///
    /// Format: `v1-<blake3_hex>` over the input `"fuz:<hash>"` (no trailing
    /// newline). This is the single-binary case of the general
    /// [`content_hash_from_binaries`] algorithm — the self artifact is fuz-only,
    /// so it is the only shape — and delegates to it rather than restating it,
    /// so the two can't drift. The literal is pinned by `content_hash_is_stable`.
    #[must_use]
    pub fn content_hash(&self) -> String {
        content_hash_from_binaries(&BTreeMap::from([("fuz".to_string(), self.fuz.clone())]))
    }
}

/// Compute the content hash for an arbitrary binary set.
///
/// `v1-<blake3>` over `name:hash` for each binary, names in sorted order,
/// joined by a single `\n`. The canonical algorithm, shared by `ToolMeta`,
/// remote manifest verification, and [`ArtifactOutputs::content_hash`] (the
/// one-entry `{"fuz": …}` case — the self artifact is fuz-only; fuzd is its own
/// per-tool artifact). The `BTreeMap` input is already name-sorted, so the
/// output is deterministic.
///
/// The join is unambiguous because every binary name is a release token
/// ([`is_release_token`]), which holds no `:` and no `\n`, and every hash is
/// BLAKE3 (64 hex). The manifest, the release log, and both tool installs
/// refuse any other name before they compute a hash over it. A `meta.json`
/// read back from the store is fuz's own write, checked against its stored
/// hash, and is not held to the rule again.
///
/// Note: this `v1-`-prefixed **aggregate** identifier is a `String`, distinct
/// from a `fuz_crypto::ContentHash` (a single bare digest) — same word
/// ("content hash"), different thing. The per-binary `hash` values *are*
/// `ContentHash`es; this folds them into one versioned artifact address.
#[must_use]
pub fn content_hash_from_binaries(binaries: &BTreeMap<String, ContentHash>) -> String {
    let mut hasher = Hasher::new(HashAlgo::Blake3);
    for (i, (name, hash)) in binaries.iter().enumerate() {
        debug_assert_eq!(hash.algo(), HashAlgo::Blake3, "binary {name:?}");
        if i > 0 {
            hasher.update(b"\n");
        }
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(hash.to_hex().as_bytes());
    }
    format!("v{CONTENT_HASH_VERSION}-{}", hasher.finalize().to_hex())
}

/// Whether `hash` has the shape [`content_hash_from_binaries`] produces:
/// `v1-` followed by exactly 64 lowercase hex characters.
///
/// The single check of the `v1-<hex>` format, for a value fuz did not compute
/// itself — a signed manifest's `content_hash` — before it names a store
/// directory. Shape only: whether it matches the binaries is verified after
/// the download.
#[must_use]
pub fn is_content_hash(hash: &str) -> bool {
    hash.strip_prefix(CONTENT_HASH_PREFIX).is_some_and(|hex| {
        hex.len() == FULL_HASH_LENGTH
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Longest name, version, target triple, or binary name a release carries.
pub const MAX_RELEASE_TOKEN_LEN: usize = 128;

/// Whether `s` is a release token: a name, version, target triple, or binary
/// name a release carries.
///
/// A short ASCII token of letters, digits, and `. _ -`, starting with a
/// letter or digit. Excludes everything that is structure somewhere a release
/// gets read — whitespace, quotes, path separators, a leading `-` or `.`, the
/// `:` and `\n` [`content_hash_from_binaries`] joins with — and `+`: a
/// release's name, version, and target are part of its storage keys, whose
/// characters these are, so a version with semver build metadata
/// (`1.0.0+build.5`) is one no publish produces and no release log head
/// records.
///
/// The one rule for these values: the signed manifest, the release log head,
/// its writers, and both tool installs hold to it. Public so a publisher can
/// hold a value to it before the value is used anywhere it is structure — a
/// file name, a command argument.
#[must_use]
pub fn is_release_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() <= MAX_RELEASE_TOKEN_LEN
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Strip the `v1-` content-hash version prefix, returning the bare hash.
///
/// Tolerant: returns the input unchanged when the prefix is absent (a
/// user-typed prefix that already lacks `v1-`, or a value from before the
/// scheme existed). The single home for "drop the version tag" — used by
/// `fuz artifact use` prefix normalization, the short-hash display helpers, and the
/// bootstrap summary, so the `CONTENT_HASH_PREFIX` literal lives in one place.
#[must_use]
pub fn strip_content_hash_prefix(hash: &str) -> &str {
    hash.strip_prefix(CONTENT_HASH_PREFIX).unwrap_or(hash)
}

/// The bare hash (version prefix stripped) truncated to `len` chars, or the
/// whole bare hash if it is shorter.
///
/// The shared core of [`ArtifactMeta::short_hash`] (8 chars) and the bootstrap
/// summary (16 chars); the caller picks the display width. Hashes are hex
/// (ASCII), so the byte slice never splits a multi-byte char.
#[must_use]
pub fn short_content_hash(hash: &str, len: usize) -> &str {
    let bare = strip_content_hash_prefix(hash);
    &bare[..len.min(bare.len())]
}

//
// Artifact source
//

/// Where an artifact came from.
///
/// Wire format: lowercase string (`"local"` / `"remote"` / `"bootstrap"`).
/// Required in meta.json: a file without it does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSource {
    /// Built locally from source via `fuz artifact build` or `cargo xtask install`.
    Local,
    /// Downloaded from a release server via `fuz self upgrade`.
    Remote,
    /// Installed via `fuz self bootstrap` (fuz binary only, no fuzd).
    Bootstrap,
}

//
// Artifact metadata
//

/// Artifact metadata (meta.json)
///
/// The `hash` field is content-derived (from binary hashes) with version prefix (`v1-...`).
/// The `inputs.input_hash` field is input-derived for cache lookup (raw blake3 hex).
///
/// # Inputs field
///
/// - `Some(...)` - local build with git state
/// - `None` - remote or bootstrap artifact (no git state available)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMeta {
    /// Content-derived hash with version prefix (v1-abc123...)
    /// This is computed from `outputs.content_hash()` and is the primary identifier.
    pub hash: String,
    /// Cargo version from Cargo.toml
    pub version: String,
    /// Creation timestamp (ISO 8601)
    pub created_at: String,
    /// Where the artifact came from. Required.
    pub source: ArtifactSource,
    /// Build inputs (includes `input_hash` for cache lookup).
    /// None for remote and bootstrap artifacts which don't have git state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<ArtifactInputs>,
    /// Output binary hashes
    pub outputs: ArtifactOutputs,
}

impl ArtifactMeta {
    /// Create new metadata for a completed local artifact
    #[must_use]
    pub fn new(version: String, inputs: ArtifactInputs, outputs: ArtifactOutputs) -> Self {
        let hash = outputs.content_hash();
        Self {
            hash,
            version,
            created_at: rfc3339_now(),
            source: ArtifactSource::Local,
            inputs: Some(inputs),
            outputs,
        }
    }

    /// Create new metadata for a remote (downloaded) artifact.
    ///
    /// Remote artifacts don't have git state, so `inputs` is None.
    #[must_use]
    pub fn new_remote(hash: String, version: String, outputs: ArtifactOutputs) -> Self {
        Self {
            hash,
            version,
            created_at: rfc3339_now(),
            source: ArtifactSource::Remote,
            inputs: None,
            outputs,
        }
    }

    /// Create new metadata for a bootstrap-installed artifact (fuz only, no fuzd).
    ///
    /// Bootstrap artifacts have no git state (the installer doesn't carry the
    /// repo) and no fuzd binary (it ships only the CLI).
    #[must_use]
    pub fn new_bootstrap(version: String, fuz_hash: ContentHash) -> Self {
        let outputs = ArtifactOutputs { fuz: fuz_hash };
        let hash = outputs.content_hash();
        Self {
            hash,
            version,
            created_at: rfc3339_now(),
            source: ArtifactSource::Bootstrap,
            inputs: None,
            outputs,
        }
    }

    /// Returns true if this is a bootstrap-installed artifact (fuz only).
    ///
    /// The only `source` with a predicate: `fuz artifact build` and `fuz
    /// artifact list` branch on bootstrap-ness specifically (a bootstrap
    /// artifact carries no git inputs). No production path reads the `Local` /
    /// `Remote` discriminants at all — only tests match on them — so neither
    /// carries an accessor nothing reads.
    #[must_use]
    pub fn is_bootstrap(&self) -> bool {
        self.source == ArtifactSource::Bootstrap
    }

    /// Get short hash (8 chars after v1- prefix)
    #[must_use]
    pub fn short_hash(&self) -> &str {
        short_content_hash(&self.hash, SHORT_HASH_LEN)
    }

    /// Get the full hash with prefix for display
    #[must_use]
    pub fn display_hash(&self) -> String {
        format!("{}{}", CONTENT_HASH_PREFIX, self.short_hash())
    }

    /// Load and verify artifact metadata (metadata-only integrity).
    ///
    /// Verifies that stored hash matches computed hash from stored output hashes.
    /// This catches meta.json corruption/tampering but does NOT verify the actual
    /// binaries on disk match the stored hashes. For full binary verification,
    /// use `verify_artifact()` which re-hashes the binaries.
    pub fn read(artifact_dir: &Path) -> Result<Self, ArtifactError> {
        meta_file::read_checked(artifact_dir, META_FILE)
    }

    /// Write to artifact directory with fsync for durability.
    ///
    /// Delegates to [`meta_file::write_atomic_meta`] (tmp + fsync + rename +
    /// parent fsync, with ENOSPC mapped to
    /// [`ArtifactError::InsufficientSpace`]).
    pub fn write(&self, artifact_dir: &Path) -> Result<(), ArtifactError> {
        meta_file::write_atomic_meta(self, artifact_dir, META_FILE)
    }
}

impl MetaIntegrity for ArtifactMeta {
    fn stored_hash(&self) -> &str {
        &self.hash
    }

    fn compute_hash(&self) -> String {
        self.outputs.content_hash()
    }
}
