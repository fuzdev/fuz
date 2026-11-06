//! First-party tool install model.
//!
//! Parallel to the crate-root artifact model (which manages the fuz
//! *self* artifact): `tools` covers binaries fuz installs via
//! `fuz tool install <name>` into content-addressed per-tool directories
//! `~/.fuz/tools/<name>/v1-<hash>/`, each carrying its own `meta.json`
//! ([`ToolMeta`]). There is **no central index** — `fuz tool list` scans the
//! tools directory and reads each tool's `current/meta.json`.
//!
//! A tool is a named, signed, one-or-more-binary bundle. The signed manifest
//! declares the binary set; fuz does not carry a per-tool "which binaries does
//! X ship" table. The embedded [`FIRST_PARTY_TOOLS`] allowlist gates *names*
//! only — belt-and-suspenders over the ed25519 signature, which is the real
//! trust root.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::hash::hash_source_binary;
use crate::symlinks::check_tool_binary_names;
use crate::{
    ArtifactError, CONTENT_HASH_PREFIX, MetaIntegrity, SHORT_HASH_LEN, StoreSlot,
    content_hash_from_binaries, hash_binary, read_checked, reclaim_store_entry,
    require_current_replaceable, setup_tool_symlinks, short_content_hash, store_entry_path,
    write_atomic_meta,
};
use fuz_crypto::ContentHash;
use fuz_home::{check_fuz_home_not_world_writable, get_tool_current_link, get_tool_dir};
use fuz_sys::fs::CleanupGuard;
use fuz_sys::rand::random_hex_suffix;
use fuz_sys::{EXECUTABLE_FILE_MODE, SECURE_DIR_MODE};

/// Embedded allowlist of installable first-party tool names.
///
/// `fuz tool install <name>` refuses any name outside this set. A new tool
/// becomes installable only via a fuz release that adds it here — the cost of
/// secure-by-default name gating, accepted deliberately. `fuz` itself is not
/// here: fuz self-distribution is the crate-root artifact model's
/// job, not a tool install. `fuzd` is here for the split-install target.
pub const FIRST_PARTY_TOOLS: &[&str] = &[
    "fuzd", "zap", "zzz", "tsv", "fuzi", "fuzp", "fuzb", "fuzf", "fuzfd",
];

/// Returns `true` when `name` is an installable first-party tool.
#[must_use]
pub fn is_first_party_tool(name: &str) -> bool {
    FIRST_PARTY_TOOLS.contains(&name)
}

/// Metadata file name within a per-tool install directory.
pub const TOOL_META_FILE: &str = "meta.json";

/// Temp-dir prefix for an in-flight tool install: `<prefix><random hex>`,
/// created inside `~/.fuz/tools/<name>/` and renamed onto `<content hash>/`
/// once the binaries and `meta.json` are written.
///
/// Spelled once, here in the lower crate, because **both** tool-install paths
/// stage into that same directory and must be recognizable as the same thing:
/// `install_local_tool` below (the no-forge dev path) and `fuz_release`'s
/// `install_tool` (the forge path), which imports this const. Both create it
/// the same way too — non-recursive, at [`fuz_sys::SECURE_DIR_MODE`] — which
/// matters twice over: the dir is *renamed* into place, so the staging mode is
/// the mode the install lands at, and a name already on disk fails `EEXIST`
/// instead of being silently merged into.
///
/// The suffix is **random**, not the process id, and that is what lets the
/// create stand alone with no pre-clean of the name. A pid also separates two
/// live processes, but pids recur: a staging tree abandoned by a crashed run
/// would be adopted by a later install that drew the same number, so the caller
/// would have to `remove_dir_all` the name first — a blind removal that takes a
/// concurrent install's live tree with it. Random draws don't recur, so
/// `EEXIST` means a genuine collision and there is nothing to clear.
///
/// That is *staging* collision-freedom only. Two concurrent installs of the
/// same tool at the same content hash still race: both miss the `v1-<hash>/` cache
/// check, both stage, and the loser's rename lands on a now-populated dir.
///
/// A leftover `<prefix>*` directory is a crashed install. Both paths unwind
/// their own tree via [`fuz_sys::fs::CleanupGuard`], which a SIGKILL (or a
/// panic, under `panic = "abort"`) skips; those leftovers are swept by
/// [`cleanup_stale_tool_staging`], which both paths run before staging.
/// Neither path takes a lock, so the sweep is age-gated rather than
/// unconditional: an unconditional one would delete a concurrent install's
/// live staging tree and turn its rename into `ENOENT`.
pub const TOOL_INSTALL_TEMP_PREFIX: &str = ".installing-";

/// Remove crash-leaked `.installing-*` staging dirs from `tool_dir`
/// (`~/.fuz/tools/<name>/`).
///
/// A dir is taken once it has gone [`fuz_sys::fs::STALE_STAGING_DIR_AGE`]
/// without a write ([`fuz_sys::fs::sweep_stale_staging_dirs`], which dates a
/// dir by its newest direct entry and follows no link).
///
/// No lock serializes tool installs, so a concurrent install's live staging
/// dir sits beside the leaked ones; age is what tells them apart. An install
/// that has only stalled that long, and is swept, fails at its re-verify
/// (`ToolMeta::verify_binaries`) or its rename (`ENOENT`) rather than
/// publishing a partial tree — short of a sweep that overlaps the rename
/// itself, which needs an install idle for the whole window to wake at that
/// instant.
pub fn cleanup_stale_tool_staging(tool_dir: &Path) {
    fuz_sys::fs::sweep_stale_staging_dirs(tool_dir, TOOL_INSTALL_TEMP_PREFIX);
}

/// Install record for one tool version
/// (`~/.fuz/tools/<name>/v1-<hash>/meta.json`).
///
/// The `content_hash` is derived from `binaries` via
/// [`content_hash_from_binaries`]; [`ToolMeta::read`] re-derives and checks it,
/// catching meta.json tampering (the same integrity discipline as
/// [`ArtifactMeta`](crate::ArtifactMeta)).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMeta {
    /// Tool name (matches the install dir under `~/.fuz/tools/`).
    pub tool: String,
    /// Installed version (semver).
    pub version: String,
    /// Content hash (`v1-...`), derived from `binaries`.
    pub content_hash: String,
    /// Install timestamp (ISO 8601).
    pub created_at: String,
    /// Binary name -> blake3 hash. Sorted; the source of truth for which files
    /// this tool ships. Values are bare-hex on the wire (the meta.json shape)
    /// via the [`fuz_crypto::blake3_hex_map`] serde adapter.
    #[serde(with = "fuz_crypto::blake3_hex_map")]
    pub binaries: BTreeMap<String, ContentHash>,
}

impl ToolMeta {
    /// Build metadata for a freshly-installed tool.
    #[must_use]
    pub fn new(tool: String, version: String, binaries: BTreeMap<String, ContentHash>) -> Self {
        let content_hash = content_hash_from_binaries(&binaries);
        Self {
            tool,
            version,
            content_hash,
            created_at: fuz_sys::rfc3339_now(),
            binaries,
        }
    }

    /// Load and integrity-check tool metadata.
    ///
    /// Verifies the stored `content_hash` matches the one derived from the
    /// stored `binaries` map. Does NOT re-hash the binaries on disk — use
    /// [`ToolMeta::verify_binaries`] for that. A `meta.json` that is a symlink
    /// is refused, not read through ([`read_checked`]).
    ///
    /// # Errors
    /// Returns [`ArtifactError`] if the file is missing, too large, malformed,
    /// or fails the integrity check.
    pub fn read(dir: &Path) -> Result<Self, ArtifactError> {
        read_checked(dir, TOOL_META_FILE)
    }

    /// Write metadata atomically (tmp + fsync + rename + parent fsync).
    ///
    /// # Errors
    /// Returns [`ArtifactError::MetadataWriteFailed`] on serialization or IO
    /// failure, or [`ArtifactError::InsufficientSpace`] on ENOSPC.
    pub fn write(&self, dir: &Path) -> Result<(), ArtifactError> {
        write_atomic_meta(self, dir, TOOL_META_FILE)
    }

    /// Re-hash the installed binaries on disk and compare to the stored hashes.
    ///
    /// This is the real integrity check (the equivalent of
    /// [`verify_artifact`](crate::verify_artifact) for the self
    /// artifact) — it catches local tampering or disk corruption that
    /// [`ToolMeta::read`] alone would miss. Each binary is hashed without
    /// following a symlink ([`hash_binary`]).
    ///
    /// # Errors
    /// Returns [`ArtifactError::BinaryIntegrityFailed`] on the first mismatch,
    /// or [`ArtifactError::NotRegularFile`] for a binary that is a symlink or
    /// special file.
    pub fn verify_binaries(&self, dir: &Path) -> Result<(), ArtifactError> {
        for (name, expected) in &self.binaries {
            let actual = hash_binary(&dir.join(name))?;
            if actual != *expected {
                return Err(ArtifactError::BinaryIntegrityFailed {
                    binary: name.clone(),
                    expected: expected.clone(),
                    actual,
                });
            }
        }
        Ok(())
    }

    /// The bare `content_hash` (no `v1-` prefix) cut to [`SHORT_HASH_LEN`]
    /// characters, the same form as
    /// [`ArtifactMeta::short_hash`](crate::ArtifactMeta::short_hash).
    #[must_use]
    pub fn short_hash(&self) -> &str {
        short_content_hash(&self.content_hash, SHORT_HASH_LEN)
    }

    /// [`Self::short_hash`] with the `v1-` prefix back on — the identifier
    /// `fuz tool list` prints, the same form as
    /// [`ArtifactMeta::display_hash`](crate::ArtifactMeta::display_hash) in
    /// `fuz artifact list`.
    #[must_use]
    pub fn display_hash(&self) -> String {
        format!("{CONTENT_HASH_PREFIX}{}", self.short_hash())
    }
}

impl MetaIntegrity for ToolMeta {
    fn stored_hash(&self) -> &str {
        &self.content_hash
    }

    fn compute_hash(&self) -> String {
        content_hash_from_binaries(&self.binaries)
    }
}

/// Install a tool from locally-built binaries — the no-forge dev path.
///
/// `cargo xtask install` uses this to land fuzd as a per-tool artifact
/// alongside the fuz-only self artifact. It mirrors `fuz_release::install_tool`
/// minus the forge (no storage, manifest, or signature): hash the source
/// binaries, derive the content hash, copy them into a content-addressed dir
/// `~/.fuz/tools/<name>/v1-<hash>/` with a [`ToolMeta`], then point the per-tool
/// `current` symlink + `~/.fuz/bin/<binary>` at it.
///
/// Idempotent: an already-present content hash is re-verified on disk and
/// re-linked rather than re-copied. Already-present means a real directory —
/// a symlink (live or dangling) or file at `v1-<hash>/` is unlinked, never its
/// target, and the install proceeds as a fresh one. `binaries` maps each
/// in-tool binary name to its source path.
///
/// # Errors
/// Returns [`ArtifactError::FuzHome`] if `~/.fuz` is world-writable;
/// [`ArtifactError::InvalidBinaryName`] if a binary name is not a release
/// token ([`is_release_token`](crate::is_release_token));
/// [`ArtifactError::ReservedBinaryName`] if a binary is named for one of the
/// self artifact's ([`is_self_binary_name`](crate::is_self_binary_name));
/// [`ArtifactError::CurrentNotStoreLink`] if the tool's `current` is not a
/// symlink; [`ArtifactError::InvalidBinary`] / [`ArtifactError::MissingBinary`]
/// for a source binary that is a symlink, not a regular file, or missing; or
/// [`ArtifactError`] if hashing, copying, metadata I/O, or the symlink swap
/// fails, or if a re-hash of the copied binaries disagrees with the source.
pub fn install_local_tool(
    name: &str,
    version: &str,
    binaries: &[(&str, &Path)],
) -> Result<ToolMeta, ArtifactError> {
    // A write path into `~/.fuz` — refuse a world-writable home before the
    // first filesystem write, so nothing lands in a tree any local user can
    // rewrite. The forge path (`fuz_release`'s `install_tool`) opens with the
    // same call: both install into `~/.fuz/tools/`, so this floor holds
    // whichever caller got there. It is the *only* gate they share, though —
    // `install_tool` also refuses a name outside `FIRST_PARTY_TOOLS` while
    // resolving its manifest, where this one installs whatever name it is
    // handed. Not interchangeable on trust posture.
    check_fuz_home_not_world_writable()?;

    // A binary name that is not a token, or one named for a self binary (which
    // would take the self artifact's link in `bin/`), is refused here, before
    // anything is hashed or copied, as the forge path refuses it at the
    // manifest.
    let bin_names: Vec<&str> = binaries.iter().map(|(b, _)| *b).collect();
    check_tool_binary_names(name, &bin_names)?;

    // A `current` that is not a symlink can't be swapped for one (a directory
    // fails the rename `EISDIR`); refuse before hashing or copying anything,
    // and leave it — fuz did not write it.
    require_current_replaceable(&get_tool_current_link(name)?)?;

    // Hash each source binary; the map is the tool's bill of materials. A
    // source that is a symlink or special file is an invalid input
    // (`InvalidBinary`), refused before anything is copied.
    let mut hashes: BTreeMap<String, ContentHash> = BTreeMap::new();
    for (bin, path) in binaries {
        hashes.insert((*bin).to_string(), hash_source_binary(path, bin)?);
    }
    let content_hash = content_hash_from_binaries(&hashes);

    let tool_dir = get_tool_dir(name)?;
    let install_dir = store_entry_path(&tool_dir, &content_hash)?;

    // Cache hit: re-verify the on-disk binaries, then (re)link. Only a real
    // directory is a cache hit; a symlink (live or dangling) or file at the
    // slot is unlinked — never its target — and the tool installs fresh.
    if reclaim_store_entry(&tool_dir, &content_hash)? == StoreSlot::RealDir {
        let meta = ToolMeta::read(&install_dir)?;
        meta.verify_binaries(&install_dir)?;
        setup_tool_symlinks(name, &content_hash, &bin_names)?;
        return Ok(meta);
    }

    // Copy into a temp dir, write meta, then atomically rename into place.
    // `~/.fuz/tools/` and `~/.fuz/tools/<name>/` are dirs fuz owns, and
    // `ensure_fuz_home` creates neither — this is where they first appear — so
    // the mode is stated rather than taken from the umask.
    fuz_sys::fs::create_dir_all_mode(&tool_dir, SECURE_DIR_MODE).map_err(ArtifactError::Io)?;
    cleanup_stale_tool_staging(&tool_dir);
    let temp_dir = tool_dir.join(format!("{TOOL_INSTALL_TEMP_PREFIX}{}", random_hex_suffix()));
    fs::DirBuilder::new()
        .mode(SECURE_DIR_MODE)
        .create(&temp_dir)
        .map_err(ArtifactError::Io)?;
    // Everything between here and the rename below — the copies, the mode
    // fixups, the meta write, the defensive re-hash — would otherwise leak the
    // whole staging tree on failure.
    let guard = CleanupGuard::new(temp_dir.clone());

    for (bin, path) in binaries {
        let dst = temp_dir.join(bin);
        fs::copy(path, &dst).map_err(ArtifactError::Io)?;
        fs::set_permissions(&dst, fs::Permissions::from_mode(EXECUTABLE_FILE_MODE))
            .map_err(ArtifactError::Io)?;
    }

    let meta = ToolMeta::new(name.to_string(), version.to_string(), hashes);
    meta.write(&temp_dir)?;
    // Defense in depth: re-hash the copies before publishing the dir.
    meta.verify_binaries(&temp_dir)?;

    fs::rename(&temp_dir, &install_dir).map_err(ArtifactError::Io)?;
    guard.defuse();

    setup_tool_symlinks(name, &content_hash, &bin_names)?;

    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_crypto::ContentHash;
    use std::fs;

    #[test]
    fn first_party_allowlist_gates_names() {
        assert!(is_first_party_tool("fuzf"));
        assert!(is_first_party_tool("fuzd"));
        assert!(is_first_party_tool("zap"));
        // `fuz` is the self artifact, not a tool install target.
        assert!(!is_first_party_tool("fuz"));
        assert!(!is_first_party_tool("rando"));
        assert!(!is_first_party_tool(""));
        // `mg` is not on the allowlist.
        assert!(!is_first_party_tool("mg"));
    }

    #[test]
    fn tool_meta_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut binaries = BTreeMap::new();
        binaries.insert("fuzf".to_string(), ContentHash::blake3(b"fuzf"));
        let meta = ToolMeta::new("fuzf".to_string(), "0.1.0".to_string(), binaries);

        meta.write(dir.path()).unwrap();
        let read = ToolMeta::read(dir.path()).unwrap();
        assert_eq!(read.tool, "fuzf");
        assert_eq!(read.version, "0.1.0");
        assert_eq!(read.content_hash, meta.content_hash);
    }

    #[test]
    fn tool_meta_short_hash_is_the_bare_prefix() {
        let mut binaries = BTreeMap::new();
        binaries.insert("fuzf".to_string(), ContentHash::blake3(b"fuzf"));
        let meta = ToolMeta::new("fuzf".to_string(), "0.1.0".to_string(), binaries);
        assert_eq!(meta.short_hash().len(), SHORT_HASH_LEN);
        assert_eq!(
            meta.short_hash(),
            &meta.content_hash[CONTENT_HASH_PREFIX.len()..][..SHORT_HASH_LEN]
        );
        assert_eq!(
            meta.display_hash(),
            meta.content_hash[..CONTENT_HASH_PREFIX.len() + SHORT_HASH_LEN]
        );
    }

    #[test]
    fn tool_meta_read_detects_tampered_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut binaries = BTreeMap::new();
        binaries.insert("fuzf".to_string(), ContentHash::blake3(b"fuzf"));
        let mut meta = ToolMeta::new("fuzf".to_string(), "0.1.0".to_string(), binaries);
        // Tamper: declared content_hash no longer matches the binary set.
        meta.content_hash = "v1-deadbeef".to_string();
        meta.write(dir.path()).unwrap();

        let err = ToolMeta::read(dir.path()).unwrap_err();
        assert!(matches!(err, ArtifactError::IntegrityFailed { .. }));
    }

    #[test]
    fn tool_meta_verify_binaries_detects_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let bin_content = b"fuzf binary content";
        fs::write(dir.path().join("fuzf"), bin_content).unwrap();

        let mut binaries = BTreeMap::new();
        binaries.insert("fuzf".to_string(), ContentHash::blake3(bin_content));
        let meta = ToolMeta::new("fuzf".to_string(), "0.1.0".to_string(), binaries);
        assert!(meta.verify_binaries(dir.path()).is_ok());

        // Corrupt the on-disk binary.
        fs::write(dir.path().join("fuzf"), b"tampered").unwrap();
        let err = meta.verify_binaries(dir.path()).unwrap_err();
        assert!(matches!(err, ArtifactError::BinaryIntegrityFailed { .. }));
    }
}
