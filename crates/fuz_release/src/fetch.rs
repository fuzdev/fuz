//! Fetch workflow: download, verify, and extract releases
//!
//! This module handles the release fetch/upgrade flow:
//! 1. Get latest version (or specific version)
//! 2. Download and verify manifest (signature, size, target)
//! 3. Check version safety (minimum version, downgrade protection)
//! 4. Hold the release to the release log, when a policy enforces it
//!    ([`crate::log_check`])
//! 5. Check local cache (skip download if already have this artifact; a
//!    non-directory entry at the slot is unlinked and re-downloaded)
//! 6. Download and verify tarball
//! 7. Extract with security-hardened extraction, then hold each binary's
//!    header to this client's target (`check_extracted_platform`)
//! 8. Create meta.json for artifact compatibility

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use std::io::Read;

use fuz_artifact::platform::{INSPECT_PREFIX_LEN, check_binary_target, inspect_binary};
use fuz_artifact::{
    ARTIFACT_DIR_MODE, ArtifactError, ArtifactMeta, StoreSlot, get_artifact_dir,
    reclaim_store_entry, verify_artifact,
};
use fuz_home::{check_fuz_home_not_world_writable, get_artifacts_dir};

use serde::{Deserialize, Serialize};

use crate::current::resolve_current_self;
use crate::error::{ManifestError, ReleaseError, TarballError};
use crate::layout::ReleaseLayout;
use crate::log_check::{LogCheck, ReleaseLogPolicy, check_release_log};
use crate::manifest::{
    Manifest, VerifiedManifest, check_version_safety_with_downgrade, current_release_target,
    current_target,
};
use crate::tarball::{
    create_meta_json, extract_tarball_reader, verify_binary_hashes, verify_content_hash,
    verify_tarball_file,
};
use crate::{MAX_MANIFEST_SIZE, SELF_NAME};
use fuz_storage::{Storage, StorageError};
use fuz_sys::SECURE_DIR_MODE;
use fuz_sys::fs::CleanupGuard;
use fuz_sys::rand::random_hex_suffix;

/// Temp filename the tarball is streamed to inside the extraction dir before
/// it's hashed, extracted, and removed. Dot-prefixed so it can never collide
/// with a manifest binary name (extraction is allowlisted to those).
const DOWNLOAD_TARBALL_NAME: &str = ".artifact-download.tar.gz";

/// Temp-dir prefix for an in-flight self-artifact fetch in the artifacts dir:
/// `<prefix><random hex>`, renamed onto `<content hash>/` once verified, and
/// swept by `cleanup_stale_downloads` when a crash leaves one behind.
const DOWNLOAD_TEMP_PREFIX: &str = ".downloading-";

/// `latest-<target>.json` format: a release stream's version pointer for one
/// target.
///
/// Read here on fetch; written by the producer (`fuz_sign`'s publish flow).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestInfo {
    /// Current latest version
    pub version: String,
}

/// Options for fetch operations
#[derive(Debug, Default)]
pub struct FetchOptions {
    /// Allow downgrade to older version
    pub allow_downgrade: bool,
    /// Reinstall over an unreadable current install instead of refusing it (the
    /// `--force` escape hatch — see [`CurrentVersion::for_install`](crate::CurrentVersion::for_install)).
    pub force: bool,
    /// Whether the release is held to the release log before its bytes are
    /// used. The default, [`ReleaseLogPolicy::Inactive`], checks nothing.
    /// Neither `allow_downgrade` nor `force` relaxes an enforced check.
    pub release_log: ReleaseLogPolicy,
}

/// Result of a successful fetch operation
#[derive(Debug)]
pub struct FetchResult {
    /// Version that was fetched
    pub version: String,
    /// Content hash of the artifact
    pub content_hash: String,
    /// Path to the artifact directory
    pub artifact_dir: PathBuf,
    /// Whether this was a cache hit (already had the artifact)
    pub cache_hit: bool,
    /// When `--force` reinstalled over an unreadable current install, the reason
    /// it was unreadable (so the caller can warn it repaired a broken state);
    /// `None` on a normal install.
    pub repaired_unreadable: Option<String>,
    /// What the release log check did: nothing (inactive or opted out), or
    /// the report of the head that confirmed this release.
    pub release_log: LogCheck,
}

/// Download and parse the version pointer for a release stream (self or tool)
/// for this client's own target: its layout's `latest-<target>.json`, so a
/// version published for other targets alone is never the one resolved.
///
/// The pointer is plain JSON, so a parse failure maps to
/// [`StorageError::DownloadFailed`] — a malformed pointer is a storage-side
/// problem, not a manifest one. Shared by the self ([`fetch_latest`]) and tool
/// ([`fetch_tool_manifest`](crate::tool::fetch_tool_manifest)) latest-resolution
/// paths.
pub(crate) async fn resolve_latest_version(
    storage: &impl Storage,
    layout: &ReleaseLayout,
    tool: Option<&str>,
) -> Result<String, ReleaseError> {
    let latest_key = layout.latest_key(current_target());
    // The pointer is a tiny JSON object, read from a host that may serve
    // anything in its place, and read before any signature is checked. The
    // bounded read refuses one past the ceiling the signed manifests share
    // without buffering it — a storage-layer size cap on a storage-resolved
    // pointer (a malformed pointer maps to a storage error too, below).
    let bytes = storage
        .download_capped(&latest_key, MAX_MANIFEST_SIZE)
        .await
        .map_err(|error| match error {
            // No pointer for this target: nothing is published for it here
            // (another target's may be), which the error says by name.
            StorageError::NotFound { .. } => ReleaseError::NoReleaseForTarget {
                tool: tool.map(str::to_string),
                target: current_target().to_string(),
                key: latest_key.clone(),
            },
            error => error.into(),
        })?;
    let latest: LatestInfo =
        serde_json::from_slice(&bytes).map_err(|e| StorageError::DownloadFailed {
            backend: storage.backend_kind(),
            message: format!("failed to parse {latest_key}: {e}"),
        })?;
    Ok(latest.version)
}

/// Download the manifest at `key` as bytes, refusing one past
/// [`MAX_MANIFEST_SIZE`] with [`ManifestError::TooLarge`].
///
/// The one read of a manifest from storage: a bounded one
/// ([`Storage::download_capped`]), so a host serving something huge at a
/// manifest's key is refused without the body being held. The size the error
/// carries is what the backend had read when it stopped — the document's
/// length only where the store declares one.
pub async fn download_manifest(storage: &impl Storage, key: &str) -> Result<Vec<u8>, ReleaseError> {
    match storage.download_capped(key, MAX_MANIFEST_SIZE).await {
        Ok(bytes) => Ok(bytes),
        Err(StorageError::TooLarge { size, .. }) => Err(ManifestError::TooLarge(size).into()),
        Err(error) => Err(error.into()),
    }
}

/// Fetch the latest release from storage.
///
/// Downloads and verifies the latest release, returning the path to the
/// extracted artifact directory.
pub async fn fetch_latest(
    storage: &impl Storage,
    options: &FetchOptions,
) -> Result<FetchResult, ReleaseError> {
    // Every public write entry point re-checks the home itself. Here it must
    // also precede `resolve_latest_version`'s network work, so a world-writable
    // home refuses immediately. The stale-download sweep runs once, in
    // `fetch_version` below (so a failed version resolve skips it — the next
    // run sweeps). The read-only `fetch_latest_manifest` (`--check`)
    // deliberately skips the guard.
    check_fuz_home_not_world_writable()?;

    // 1. Get latest version
    let version = resolve_latest_version(storage, &ReleaseLayout::self_artifact(), None).await?;

    fetch_version(storage, &version, options).await
}

/// Download, parse, target-check, self-guard, signature-verify, and key-check
/// ([`Manifest::check_key`]) the self manifest for `version` — the read-only
/// verification core with **no** side effects under `~/.fuz`.
///
/// Shared by [`fetch_version`] (which then downloads + installs) and
/// [`fetch_latest_manifest`] (which stops at the verified manifest for a
/// read-only `--check`). Does NOT clean up stale downloads, read the cache,
/// download the tarball, take the artifact lock, or write anything.
async fn fetch_self_manifest(
    storage: &impl Storage,
    version: &str,
) -> Result<VerifiedManifest, ReleaseError> {
    let target = current_target();
    let layout = ReleaseLayout::self_artifact();
    let manifest_key = layout.manifest_key(SELF_NAME, version, target);

    // Download and validate manifest
    let manifest_bytes = download_manifest(storage, &manifest_key).await?;

    let manifest = Manifest::for_current_platform(&manifest_bytes)?;
    // The self artifact is fuz-only (`tool: None`). A manifest declaring a tool
    // served at the self key — even validly signed — is the wrong artifact kind;
    // reject it loudly rather than install a per-tool bundle as the fuz self
    // artifact. `validate()` can't enforce this (it's shared with the tool path,
    // which legitimately sets `tool`), so the self callsite owns the invariant.
    if let Some(tool) = &manifest.tool {
        return Err(ManifestError::UnexpectedTool(tool.clone()).into());
    }
    // Verify the signature here, once. The resulting `VerifiedManifest` is the
    // only thing `verify_cached_artifact` / `download_verify_extract` accept, so
    // the trust check can't be skipped on the way to trusting these hashes.
    let manifest = manifest.verify_signature()?;
    // The version asked for — pinned, or named by the latest pointer — is the one
    // the manifest was signed as.
    manifest.check_key(&layout, SELF_NAME, &manifest_key)?;
    Ok(manifest)
}

/// Resolve the latest self version and return its **verified** manifest — the
/// read-only counterpart to [`fetch_latest`], for `fuz self upgrade --check`.
///
/// Resolves this target's `latest-<target>.json`, then downloads + parses + target-checks +
/// signature-verifies the manifest, and stops: no cache read, no tarball
/// download, no temp dir, no artifact lock, and **no** `cleanup_stale_downloads`
/// (that sweep opens [`fetch_version`], which this path never enters) — so a
/// `--check` mutates nothing under `~/.fuz`.
/// The trustworthy version is the returned [`VerifiedManifest`]'s signed
/// `version`; the pointer only selects which manifest to fetch.
/// Mirrors [`fetch_tool_manifest`](crate::tool::fetch_tool_manifest)'s shape.
pub async fn fetch_latest_manifest(
    storage: &impl Storage,
) -> Result<VerifiedManifest, ReleaseError> {
    let version = resolve_latest_version(storage, &ReleaseLayout::self_artifact(), None).await?;
    fetch_self_manifest(storage, &version).await
}

/// Fetch a specific version from storage.
pub async fn fetch_version(
    storage: &impl Storage,
    version: &str,
    options: &FetchOptions,
) -> Result<FetchResult, ReleaseError> {
    // Every public write entry point re-checks the home itself — `fetch_version`
    // is callable directly, so it can't rely on `fetch_latest` having checked.
    check_fuz_home_not_world_writable()?;

    // Clean up stale downloads first
    cleanup_stale_downloads();

    let manifest = fetch_self_manifest(storage, version).await?;

    // 3. Check version safety. The target is the manifest's own version, so the
    // check derives it; we only supply the currently-installed version. A fresh
    // install (`NotInstalled`) skips the floor + downgrade guard; an unreadable
    // current install is refused unless `force` reinstalls over it.
    let current = resolve_current_self()?;
    let (current_version, repaired) = current.for_install(options.force)?;
    check_version_safety_with_downgrade(current_version, &manifest, options.allow_downgrade)?;
    let repaired_unreadable = repaired.map(str::to_string);

    // 4. Hold the release to the release log. After version safety, so a
    // downgrade is reported as a downgrade; before the cache-hit branch, so an
    // artifact that was downloaded before its release was revoked is refused
    // like one that was not.
    let release_log = check_release_log(&options.release_log, &manifest).await?;

    // 5. Check if already have this artifact (cache hit). Only a real
    // directory is a cache hit: a symlink (live or dangling) or file at the
    // slot is unlinked — never its target — and the artifact is downloaded
    // fresh, where a dangling link would otherwise fail the rename below with
    // `ENOTDIR` on every run and a live one would be verified through.
    let artifact_dir = get_artifact_dir(&manifest.content_hash)?;
    if reclaim_store_entry(&get_artifacts_dir()?, &manifest.content_hash)? == StoreSlot::RealDir {
        // Cache integrity: confirm both the stored meta and the on-disk
        // binaries still match the manifest before we hand the cache hit
        // back. This catches local tampering / disk corruption that the
        // mere "directory exists" check would miss.
        verify_cached_artifact(&artifact_dir, &manifest)?;
        let manifest = manifest.into_manifest();
        return Ok(FetchResult {
            version: manifest.version,
            content_hash: manifest.content_hash,
            artifact_dir,
            cache_hit: true,
            repaired_unreadable,
            release_log,
        });
    }

    // 6–7. Stream the tarball to a temp file, verify its hash against the
    // signed manifest, then extract + verify into the temp dir — bounded memory,
    // never the whole artifact in RAM.
    // `~/.fuz/artifacts/` may not exist yet — an upgrade can be the first thing
    // that writes it — so create it here, moded rather than umask-derived, the
    // same as the local build path's own on-demand create.
    let artifacts_dir = get_artifacts_dir()?;
    fuz_sys::fs::create_dir_all_mode(&artifacts_dir, SECURE_DIR_MODE).map_err(TarballError::Io)?;
    let temp_dir = artifacts_dir.join(format!("{DOWNLOAD_TEMP_PREFIX}{}", random_hex_suffix()));
    // Moded and non-recursive — the twin of `fuz_artifact`'s `create_secure_dir`
    // on the local build path, and of `install_tool`'s staging create. This dir
    // is *renamed* into place, so its creation mode is the mode the downloaded
    // artifact lands at until the chmod below; `create_dir_all` would take that
    // from the umask (a world-writable artifact dir under `umask 000`) and would
    // silently adopt a pre-existing directory where `create` fails `EEXIST`,
    // which is what makes the random suffix a real uniqueness claim. The parent
    // is created just above, so recursion buys nothing.
    tokio::fs::DirBuilder::new()
        .mode(SECURE_DIR_MODE)
        .create(&temp_dir)
        .await
        .map_err(TarballError::Io)?;
    let guard = CleanupGuard::new(temp_dir.clone());

    let layout = ReleaseLayout::self_artifact();
    download_verify_extract(
        storage,
        &layout.tarball_key(&manifest.tarball.path),
        &manifest,
        &temp_dir,
    )
    .await?;

    // 8. Create meta.json and finalize
    create_meta_json(&manifest, &temp_dir)?;
    tokio::fs::rename(&temp_dir, &artifact_dir)
        .await
        .map_err(TarballError::Io)?;
    guard.defuse();

    // World-readable/executable, matching what the local build path
    // (`fuz_artifact`'s `create_artifact`) sets on its own artifact dirs, and
    // only after the rename so the staging tree stays 0700 until it is a real
    // artifact. Stated rather than inherited: the mode is a property of the
    // artifact, not of the environment that downloaded it.
    tokio::fs::set_permissions(
        &artifact_dir,
        std::fs::Permissions::from_mode(ARTIFACT_DIR_MODE),
    )
    .await
    .map_err(TarballError::Io)?;

    let manifest = manifest.into_manifest();
    Ok(FetchResult {
        version: manifest.version,
        content_hash: manifest.content_hash,
        artifact_dir,
        cache_hit: false,
        repaired_unreadable,
        release_log,
    })
}

/// Stream a tarball to a temp file, verify its blake3 against the signed
/// `manifest`, then extract + verify its per-binary and content hashes into
/// `extract_dir`. Bounded memory — the artifact is never fully buffered.
///
/// Shared by the self-artifact (`fetch_version`) and per-tool (`install_tool`)
/// download paths. The tarball streams to `<extract_dir>/.artifact-download.tar.gz`,
/// is hashed there (the signed-manifest trust check), extracted, then removed —
/// so `extract_dir` ends up holding only the extracted binaries; the caller adds
/// `meta.json` and renames the dir into place.
pub(crate) async fn download_verify_extract(
    storage: &impl Storage,
    tarball_key: &str,
    manifest: &VerifiedManifest,
    extract_dir: &Path,
) -> Result<(), ReleaseError> {
    let tarball_tmp = extract_dir.join(DOWNLOAD_TARBALL_NAME);

    // Stream to disk (bounded memory), then verify the whole-tarball hash the
    // signed manifest pins before trusting any byte.
    storage.download_to_file(tarball_key, &tarball_tmp).await?;
    let compressed_size = verify_tarball_file(&tarball_tmp, &manifest.tarball.blake3)?;

    // Extract straight from the temp file (still bounded memory — the gzip/tar
    // reader is chunked), verifying per-binary + content hashes.
    let file = std::fs::File::open(&tarball_tmp).map_err(TarballError::Io)?;
    let binary_hashes = extract_tarball_reader(
        std::io::BufReader::new(file),
        compressed_size,
        manifest,
        extract_dir,
    )?;
    verify_binary_hashes(&binary_hashes, manifest)?;
    verify_content_hash(&binary_hashes, &manifest.content_hash)?;

    // Drop the downloaded tarball so the extract dir holds only the binaries.
    let _ = std::fs::remove_file(&tarball_tmp);

    // The bytes are the ones the publisher signed; hold them to the target the
    // manifest names (already checked to be this client's).
    check_extracted_platform(extract_dir, manifest)
}

/// Hold every extracted binary to this client's target: its header
/// ([`inspect_binary`]) must name an executable that runs here
/// ([`check_binary_target`], with the signed label as the named target, so a
/// static binary of this architecture passes on either libc).
///
/// The manifest's `target` is the publisher's assertion — it names the keys
/// the release is stored under — and the signature vouches only that the
/// publisher made it. A release labelled for this platform whose binaries are
/// not would install a `current` that cannot run, and for the self artifact
/// leave no working `fuz` to roll back with. Refused before `meta.json` is
/// written or the install is renamed into place, so nothing moves.
///
/// # Errors
///
/// [`ReleaseError::MislabelledBinary`], or [`TarballError::Io`] when a binary
/// cannot be read back.
fn check_extracted_platform(
    extract_dir: &Path,
    manifest: &VerifiedManifest,
) -> Result<(), ReleaseError> {
    let target = current_release_target()?;
    for name in manifest.binaries.keys() {
        let mut prefix = Vec::with_capacity(INSPECT_PREFIX_LEN);
        std::fs::File::open(extract_dir.join(name))
            .and_then(|file| {
                file.take(INSPECT_PREFIX_LEN as u64)
                    .read_to_end(&mut prefix)
            })
            .map_err(TarballError::Io)?;
        let refused = |error: ArtifactError| ReleaseError::MislabelledBinary { target, error };
        let found = inspect_binary(&prefix).map_err(|reason| {
            refused(ArtifactError::BinaryUnreadable {
                name: name.clone(),
                reason,
            })
        })?;
        check_binary_target(found, target, true).map_err(|mismatch| {
            refused(ArtifactError::BinaryPlatform {
                name: name.clone(),
                target,
                found,
                mismatch,
            })
        })?;
    }
    Ok(())
}

/// Verify a cached artifact still matches the manifest *and* still
/// matches itself on disk.
///
/// Two layers:
/// 1. Stored `meta.outputs.*` agrees with `manifest.binaries.*` — catches
///    "the manifest now claims a different content for this `content_hash`"
///    (which shouldn't be possible with content addressing but worth
///    defending against meta.json tampering).
/// 2. Re-hash the binaries on disk and compare to `meta.outputs.*` — this
///    is the real cache-integrity check. Without it, an attacker who
///    swapped the binaries (or a disk-corruption event) would slip through
///    every cache hit. ~10–20 ms overhead per `fuz self upgrade`, which is
///    interactive anyway.
///
/// A failure here is fatal — we do NOT silently re-download, because that
/// would mask tampering. The user gets a hard error pointing at the
/// problem. (The one entry the fetch does replace is a slot that is not a
/// real directory at all — `reclaim_store_entry` unlinks it before this
/// runs — since fuz never writes one there; a real directory that fails here,
/// including one whose `meta.json` or `fuz` is a symlink, stays an error.)
fn verify_cached_artifact(
    artifact_dir: &Path,
    manifest: &VerifiedManifest,
) -> Result<(), ReleaseError> {
    let meta = ArtifactMeta::read(artifact_dir)?;

    // Layer 1: meta agrees with manifest. The self artifact is fuz-only.
    let manifest_fuz = manifest
        .binaries
        .get("fuz")
        .ok_or_else(|| TarballError::MissingBinary("fuz".to_string()))?;
    if meta.outputs.fuz != *manifest_fuz {
        return Err(TarballError::BinaryHashMismatch {
            name: "fuz".to_string(),
            expected: manifest_fuz.clone(),
            actual: meta.outputs.fuz,
        }
        .into());
    }

    // Layer 2: the on-disk `fuz` binary still hashes to what meta claims. This
    // is the same check `fuz artifact verify` performs.
    verify_artifact(artifact_dir).map_err(ReleaseError::from)?;

    Ok(())
}

/// Clean up crash-leaked `.downloading-*` directories in the artifacts dir.
///
/// A dir is taken once it has gone [`fuz_sys::fs::STALE_STAGING_DIR_AGE`]
/// without a write ([`fuz_sys::fs::sweep_stale_staging_dirs`], which dates a
/// dir by its newest direct entry — the tarball streams into the dir, so a
/// slow download is not mistaken for an abandoned one).
///
/// Called at the start of fetch to remove orphaned temp directories
/// from previous crashed or interrupted downloads.
///
/// Reports nothing, deliberately. The sibling sweeper
/// [`fuz_artifact::cleanup_incomplete`] returns its count because `fuz` prints
/// it (`fuz artifact build`, `fuz self bootstrap`); this one has no such
/// consumer and no logger to reach — `fuz_release` links no `tracing` — so a
/// count would only be dropped at the sole call site, reading as though
/// someone was watching.
fn cleanup_stale_downloads() {
    let Ok(artifacts_dir) = get_artifacts_dir() else {
        return; // No artifacts dir = nothing to clean
    };
    fuz_sys::fs::sweep_stale_staging_dirs(&artifacts_dir, DOWNLOAD_TEMP_PREFIX);
}

// The full fetch_version/fetch_latest/install_tool flows resolve FUZ_HOME and
// run the real ed25519 trust check, so they're driven end to end in
// `fuz_sign/tests/signed_trust.rs` (publish with a trusted key → fetch → verify
// → install, against FileStorage + an in-process FUZ_HOME override). The
// streaming download+verify+extract core (`download_verify_extract`) and the
// `verify_cached_artifact` cache-hit gate are also covered below against
// FileStorage — no FUZ_HOME needed — plus the per-backend streaming unit tests
// in `fuz_storage` and the publish round-trips in `fuz_sign`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{BinaryHashes, ManifestUnsigned, TarballInfo, current_target};
    use crate::tarball::pack_tarball_to_file;
    use fuz_artifact::platform::{Arch, Libc, ReleaseTarget, test_stubs};
    use fuz_crypto::ContentHash;
    use fuz_storage::FileStorage;
    use std::collections::BTreeMap;

    /// Pack a tarball to a temp file and read it back as bytes — the in-memory
    /// form the streaming `pack_tarball_to_file` does not offer directly.
    fn pack_tarball_bytes(binaries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("packed.tar.gz");
        pack_tarball_to_file(binaries, &path).unwrap();
        std::fs::read(&path).unwrap()
    }

    /// A store whose buffered `download` fails by name, so a document that
    /// arrives at all came through the bounded `download_capped`.
    struct BoundedOnly(FileStorage);

    impl Storage for BoundedOnly {
        fn backend_kind(&self) -> fuz_storage::StorageBackendKind {
            self.0.backend_kind()
        }
        async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
            self.0.upload(path, data).await
        }
        #[allow(
            clippy::unused_async_trait_impl,
            reason = "trait conformance: an `async fn` body runs when awaited; the `impl Future` rewrite would run it at call time"
        )]
        async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
            Err(StorageError::DownloadFailed {
                backend: self.0.backend_kind(),
                message: format!("unbounded download of {path}"),
            })
        }
        async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
            self.0.download_capped(path, max).await
        }
        async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
            self.0.download_to_file(path, dest).await
        }
        async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
            self.0.upload_file(path, src).await
        }
        async fn exists(&self, path: &str) -> Result<bool, StorageError> {
            self.0.exists(path).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
            self.0.list(prefix).await
        }
        async fn delete(&self, path: &str) -> Result<(), StorageError> {
            self.0.delete(path).await
        }
    }

    /// One byte past the manifest ceiling. Content is irrelevant: the size
    /// gate fires before any parse.
    fn oversized_document() -> Vec<u8> {
        vec![b' '; usize::try_from(MAX_MANIFEST_SIZE).unwrap() + 1]
    }

    fn assert_pointer_too_large(result: Result<impl std::fmt::Debug, ReleaseError>, key: &str) {
        let err = result.expect_err("an oversized latest pointer is refused");
        assert!(
            matches!(
                &err,
                ReleaseError::Storage(StorageError::TooLarge { path, size, max, .. })
                    if path == key && *max == MAX_MANIFEST_SIZE && *size == MAX_MANIFEST_SIZE + 1
            ),
            "got {err:?}"
        );
    }

    fn assert_manifest_too_large(result: Result<impl std::fmt::Debug, ReleaseError>) {
        let err = result.expect_err("an oversized manifest is refused");
        assert!(
            matches!(
                &err,
                ReleaseError::Manifest(ManifestError::TooLarge(size))
                    if *size == MAX_MANIFEST_SIZE + 1
            ),
            "got {err:?}"
        );
    }

    /// An oversized latest pointer is refused as a storage-layer `TooLarge`,
    /// through the bounded read, on the self and the tool resolution alike.
    #[tokio::test]
    async fn an_oversized_latest_json_is_refused_by_the_bounded_read() {
        let storage_dir = tempfile::tempdir().unwrap();
        let storage = BoundedOnly(FileStorage::new(storage_dir.path()).unwrap());
        let self_key = ReleaseLayout::self_artifact().latest_key(current_target());
        let tool_key = ReleaseLayout::tool("fuzd").latest_key(current_target());
        for key in [&self_key, &tool_key] {
            storage.upload(key, &oversized_document()).await.unwrap();
        }

        assert_pointer_too_large(
            resolve_latest_version(&storage, &ReleaseLayout::self_artifact(), None).await,
            &self_key,
        );
        assert_pointer_too_large(fetch_latest_manifest(&storage).await, &self_key);
        assert_pointer_too_large(
            crate::tool::fetch_tool_manifest(&storage, "fuzd", None).await,
            &tool_key,
        );
    }

    /// An oversized manifest is refused as `ManifestError::TooLarge`, through
    /// the bounded read, whether the self or the tool fetch asks for it.
    #[tokio::test]
    async fn an_oversized_manifest_is_refused_by_the_bounded_read() {
        let storage_dir = tempfile::tempdir().unwrap();
        let storage = BoundedOnly(FileStorage::new(storage_dir.path()).unwrap());
        let target = current_target();
        let pointer = serde_json::to_vec(&LatestInfo {
            version: "0.1.0".to_string(),
        })
        .unwrap();
        for (layout, name) in [
            (ReleaseLayout::self_artifact(), "fuz"),
            (ReleaseLayout::tool("fuzd"), "fuzd"),
        ] {
            storage
                .upload(&layout.latest_key(current_target()), &pointer)
                .await
                .unwrap();
            storage
                .upload(
                    &layout.manifest_key(name, "0.1.0", target),
                    &oversized_document(),
                )
                .await
                .unwrap();
        }

        assert_manifest_too_large(fetch_self_manifest(&storage, "0.1.0").await);
        assert_manifest_too_large(fetch_latest_manifest(&storage).await);
        assert_manifest_too_large(crate::tool::fetch_tool_manifest(&storage, "fuzd", None).await);
        assert_manifest_too_large(
            crate::tool::fetch_tool_manifest(&storage, "fuzd", Some("0.1.0")).await,
        );
    }

    /// A stream with no pointer for this target — nothing published for it,
    /// whatever other targets have — is refused naming the target, with a
    /// hint to publish for it (or, for a tool, to pin a version).
    #[tokio::test]
    async fn a_missing_pointer_names_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(dir.path()).unwrap();
        let other = if current_target() == "aarch64-unknown-linux-gnu" {
            "x86_64-unknown-linux-gnu"
        } else {
            "aarch64-unknown-linux-gnu"
        };
        storage
            .upload(
                &ReleaseLayout::self_artifact().latest_key(other),
                br#"{"version":"0.1.0"}"#,
            )
            .await
            .unwrap();
        let target = current_target();

        let err = fetch_latest_manifest(&storage).await.unwrap_err();
        assert!(
            matches!(&err, ReleaseError::NoReleaseForTarget { tool: None, target: t, .. } if t == target),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("no release of fuz is published for {target}: latest-{target}.json not found")
        );
        assert_eq!(
            err.hint().unwrap().to_string(),
            format!("no release published for {target}; publish one")
        );
        assert!(!err.is_security_violation());

        let err = crate::tool::fetch_tool_manifest(&storage, "fuzd", None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ReleaseError::NoReleaseForTarget { tool: Some(tool), .. } if tool == "fuzd"),
            "{err:?}"
        );
        assert_eq!(
            err.hint().unwrap().to_string(),
            format!(
                "no release published for {target}; publish one, or install a published version \
                 with `fuz tool install fuzd --version <version>`"
            )
        );
    }

    /// Upload a one-binary (`fuz`) tarball of `content` to a fresh
    /// `FileStorage`, with a manifest pinning its hashes for this target.
    /// Returns the store's directory (keep it alive), the store, the tarball's
    /// key, and the manifest.
    async fn stage_release(
        content: &[u8],
    ) -> (tempfile::TempDir, FileStorage, String, VerifiedManifest) {
        let bin_hash = ContentHash::blake3(content);
        let tarball = pack_tarball_bytes(&[("fuz".to_string(), content.to_vec())]);
        let tarball_hash = ContentHash::blake3(&tarball);

        let mut sorted = BTreeMap::new();
        sorted.insert("fuz".to_string(), bin_hash.clone());
        let content_hash = fuz_artifact::content_hash_from_binaries(&sorted);

        let mut binaries = BinaryHashes::new();
        binaries.insert("fuz".to_string(), bin_hash);
        let unsigned = ManifestUnsigned {
            format: crate::MANIFEST_FORMAT_VERSION,
            version: "0.1.0".to_string(),
            content_hash,
            target: current_target().to_string(),
            minimum_version: None,
            tarball: TarballInfo {
                path: "fuz-0.1.0.tar.gz".to_string(),
                blake3: tarball_hash,
                size: tarball.len() as u64,
            },
            binaries,
            tool: None,
        };
        // Signature is irrelevant here — `download_verify_extract` checks the
        // blake3 + content hashes, not the ed25519 sig (that's `fuz_sign`'s).
        let manifest = Manifest::from_parts(
            unsigned,
            fuz_crypto::Signature {
                format: fuz_crypto::SIGNATURE_FORMAT_VERSION,
                public_key: String::new(),
                algorithm: fuz_crypto::SignatureAlgorithm::Ed25519,
                signed_at: "2025-01-15T10:30:00Z".to_string(),
                sig: String::new(),
            },
        );

        let storage_dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();
        let tarball_key = ReleaseLayout::self_artifact().tarball_key(&manifest.tarball.path);
        storage.upload(&tarball_key, &tarball).await.unwrap();
        (
            storage_dir,
            storage,
            tarball_key,
            VerifiedManifest::assume_verified_for_test(manifest),
        )
    }

    /// Streaming consumer path end-to-end: publish a real (packed) tarball +
    /// matching manifest to `FileStorage`, then `download_verify_extract` it —
    /// the binary lands, hashes verify, and the temp download is cleaned up.
    #[tokio::test]
    async fn download_verify_extract_roundtrips_from_storage() {
        let content = test_stubs::host(b"fuz binary bytes for the streaming consumer test");
        let (_dir, storage, tarball_key, manifest) = stage_release(&content).await;

        let extract_dir = tempfile::tempdir().unwrap();
        download_verify_extract(&storage, &tarball_key, &manifest, extract_dir.path())
            .await
            .unwrap();

        // Binary extracted + byte-identical; temp download removed.
        assert_eq!(
            std::fs::read(extract_dir.path().join("fuz")).unwrap(),
            content
        );
        assert!(!extract_dir.path().join(DOWNLOAD_TARBALL_NAME).exists());
    }

    /// A release signed and labelled for this target whose binary is for
    /// another — an architecture, a libc, an OS — or no executable at all is
    /// refused after every hash checks out: exit 1 territory, not a security
    /// violation, with the publisher named as the one to fix it.
    #[tokio::test]
    async fn download_verify_extract_refuses_a_binary_not_for_this_target() {
        let host = test_stubs::host_target();
        let other_arch = match host.arch() {
            Arch::X86_64 => Arch::Aarch64,
            Arch::Aarch64 => Arch::X86_64,
        };
        let mut others = vec![
            test_stubs::for_target(ReleaseTarget::linux(other_arch, Libc::Gnu), b""),
            test_stubs::macho(other_arch, b""),
            b"#!/bin/sh\necho not a binary\n".to_vec(),
        ];
        if let Some(libc) = host.libc() {
            let other_libc = match libc {
                Libc::Gnu => Libc::Musl,
                Libc::Musl => Libc::Gnu,
            };
            others.push(test_stubs::for_target(
                ReleaseTarget::linux(host.arch(), other_libc),
                b"",
            ));
        }
        for content in others {
            let (_dir, storage, tarball_key, manifest) = stage_release(&content).await;
            let extract_dir = tempfile::tempdir().unwrap();
            let err =
                download_verify_extract(&storage, &tarball_key, &manifest, extract_dir.path())
                    .await
                    .unwrap_err();
            assert!(
                matches!(&err, ReleaseError::MislabelledBinary { target, .. } if *target == host),
                "{err:?}"
            );
            assert!(!err.is_security_violation(), "{err:?}");
            assert_eq!(
                err.hint().unwrap().to_string(),
                format!(
                    "this release's binaries are not for {host}: the signature is valid but the \
                     label is wrong; report it to the publisher, don't retry"
                )
            );
        }

        // A static build of this architecture runs here whatever its libc: the
        // signed label names the target, so it is accepted.
        if host.libc().is_some() {
            let content = test_stubs::ElfStub::static_pie(host.arch()).build(b"");
            let (_dir, storage, tarball_key, manifest) = stage_release(&content).await;
            let extract_dir = tempfile::tempdir().unwrap();
            download_verify_extract(&storage, &tarball_key, &manifest, extract_dir.path())
                .await
                .unwrap();
        }
    }

    /// A manifest whose pinned tarball hash doesn't match the bytes is rejected
    /// before any binary is trusted (fail-loud, no partial install).
    #[tokio::test]
    async fn download_verify_extract_rejects_tarball_hash_mismatch() {
        let content = b"some bytes";
        let tarball = pack_tarball_bytes(&[("fuz".to_string(), content.to_vec())]);

        let mut binaries = BinaryHashes::new();
        binaries.insert("fuz".to_string(), ContentHash::blake3(content));
        let unsigned = ManifestUnsigned {
            format: crate::MANIFEST_FORMAT_VERSION,
            version: "0.1.0".to_string(),
            content_hash: "v1-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .to_string(),
            target: current_target().to_string(),
            minimum_version: None,
            tarball: TarballInfo {
                path: "fuz-0.1.0.tar.gz".to_string(),
                blake3: ContentHash::blake3(b"wrong tarball"), // wrong hash
                size: tarball.len() as u64,
            },
            binaries,
            tool: None,
        };
        let manifest = Manifest::from_parts(
            unsigned,
            fuz_crypto::Signature {
                format: fuz_crypto::SIGNATURE_FORMAT_VERSION,
                public_key: String::new(),
                algorithm: fuz_crypto::SignatureAlgorithm::Ed25519,
                signed_at: "2025-01-15T10:30:00Z".to_string(),
                sig: String::new(),
            },
        );

        let storage_dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();
        let tarball_key = ReleaseLayout::self_artifact().tarball_key(&manifest.tarball.path);
        storage.upload(&tarball_key, &tarball).await.unwrap();

        let extract_dir = tempfile::tempdir().unwrap();
        let err = download_verify_extract(
            &storage,
            &tarball_key,
            &VerifiedManifest::assume_verified_for_test(manifest),
            extract_dir.path(),
        )
        .await
        .expect_err("tarball hash mismatch must reject");
        assert!(
            matches!(
                err,
                ReleaseError::Tarball(TarballError::HashMismatch { .. })
            ),
            "got {err:?}"
        );
        // No binary was extracted.
        assert!(!extract_dir.path().join("fuz").exists());
    }

    /// A tarball whose blake3 matches the manifest, but whose extracted binary
    /// hashes the manifest's `binaries` entry lies about, is rejected by the
    /// per-binary verification layer — the defense-in-depth check *behind* the
    /// whole-tarball hash. The roundtrip and tarball-mismatch tests both leave
    /// `verify_binary_hashes` (the line between them) unexercised; a regression
    /// dropping it would pass both yet be caught here. The tarball hash is
    /// honest, so verification reaches the per-binary step (which runs before
    /// the content-hash step) and fails there with the binary's name.
    #[tokio::test]
    async fn download_verify_extract_rejects_binary_hash_mismatch() {
        let content = b"the real fuz bytes";
        let tarball = pack_tarball_bytes(&[("fuz".to_string(), content.to_vec())]);
        let tarball_hash = ContentHash::blake3(&tarball); // honest tarball hash

        let mut binaries = BinaryHashes::new();
        // The manifest lies about the binary's content while the tarball hash
        // (above) is correct, so the tarball-hash gate passes.
        binaries.insert(
            "fuz".to_string(),
            ContentHash::blake3(b"not the real bytes"),
        );
        let unsigned = ManifestUnsigned {
            format: crate::MANIFEST_FORMAT_VERSION,
            version: "0.1.0".to_string(),
            content_hash: "v1-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .to_string(),
            target: current_target().to_string(),
            minimum_version: None,
            tarball: TarballInfo {
                path: "fuz-0.1.0.tar.gz".to_string(),
                blake3: tarball_hash,
                size: tarball.len() as u64,
            },
            binaries,
            tool: None,
        };
        let manifest = Manifest::from_parts(
            unsigned,
            fuz_crypto::Signature {
                format: fuz_crypto::SIGNATURE_FORMAT_VERSION,
                public_key: String::new(),
                algorithm: fuz_crypto::SignatureAlgorithm::Ed25519,
                signed_at: "2025-01-15T10:30:00Z".to_string(),
                sig: String::new(),
            },
        );

        let storage_dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();
        let tarball_key = ReleaseLayout::self_artifact().tarball_key(&manifest.tarball.path);
        storage.upload(&tarball_key, &tarball).await.unwrap();

        let extract_dir = tempfile::tempdir().unwrap();
        let err = download_verify_extract(
            &storage,
            &tarball_key,
            &VerifiedManifest::assume_verified_for_test(manifest),
            extract_dir.path(),
        )
        .await
        .expect_err("binary hash mismatch must reject even when the tarball hash matches");
        assert!(
            matches!(
                err,
                ReleaseError::Tarball(TarballError::BinaryHashMismatch { ref name, .. }) if name == "fuz"
            ),
            "got {err:?}"
        );
    }

    //
    // verify_cached_artifact — the cache-hit integrity gate. Takes an explicit
    // artifact dir + manifest, so it tests directly without touching FUZ_HOME.
    //

    use fuz_artifact::ArtifactOutputs;

    /// Build a self manifest pinning `fuz` to `fuz_hash`. Placeholder signature
    /// — `verify_cached_artifact` checks meta-vs-manifest and an on-disk re-hash,
    /// never the ed25519 signature.
    fn cached_self_manifest(fuz_hash: &ContentHash) -> Manifest {
        let outputs = ArtifactOutputs {
            fuz: fuz_hash.clone(),
        };
        let mut binaries = BinaryHashes::new();
        binaries.insert("fuz".to_string(), fuz_hash.clone());
        let unsigned = ManifestUnsigned {
            format: crate::MANIFEST_FORMAT_VERSION,
            version: "0.1.0".to_string(),
            content_hash: outputs.content_hash(),
            target: current_target().to_string(),
            minimum_version: None,
            tarball: TarballInfo {
                path: "fuz-0.1.0.tar.gz".to_string(),
                blake3: ContentHash::blake3(b"tarball"),
                size: 1,
            },
            binaries,
            tool: None,
        };
        Manifest::from_parts(
            unsigned,
            fuz_crypto::Signature {
                format: fuz_crypto::SIGNATURE_FORMAT_VERSION,
                public_key: String::new(),
                algorithm: fuz_crypto::SignatureAlgorithm::Ed25519,
                signed_at: "2025-01-15T10:30:00Z".to_string(),
                sig: String::new(),
            },
        )
    }

    /// Write a cached self artifact dir: a `fuz` binary + a matching meta.json.
    /// Returns the binary's blake3 so the caller can build a matching manifest.
    fn write_cached_artifact(dir: &Path, content: &[u8]) -> ContentHash {
        let fuz_hash = ContentHash::blake3(content);
        std::fs::write(dir.join("fuz"), content).unwrap();
        let outputs = ArtifactOutputs {
            fuz: fuz_hash.clone(),
        };
        let meta = ArtifactMeta::new_remote(outputs.content_hash(), "0.1.0".to_string(), outputs);
        meta.write(dir).unwrap();
        fuz_hash
    }

    #[test]
    fn verify_cached_artifact_accepts_intact_cache() {
        let dir = tempfile::tempdir().unwrap();
        let fuz_hash = write_cached_artifact(dir.path(), b"cached fuz binary bytes");
        let manifest = cached_self_manifest(&fuz_hash);
        verify_cached_artifact(
            dir.path(),
            &VerifiedManifest::assume_verified_for_test(manifest),
        )
        .expect("intact cache must verify");
    }

    #[test]
    fn verify_cached_artifact_rejects_tampered_binary() {
        let dir = tempfile::tempdir().unwrap();
        let fuz_hash = write_cached_artifact(dir.path(), b"cached fuz binary bytes");
        let manifest = cached_self_manifest(&fuz_hash);
        // Swap the on-disk binary after meta.json was written. Layer 2 (re-hash)
        // must catch it — a cache hit must never silently re-download past tamper.
        std::fs::write(dir.path().join("fuz"), b"swapped malicious binary").unwrap();
        let err = verify_cached_artifact(
            dir.path(),
            &VerifiedManifest::assume_verified_for_test(manifest),
        )
        .expect_err("tamper must reject");
        assert!(
            matches!(
                err,
                ReleaseError::Artifact(ArtifactError::BinaryIntegrityFailed { .. })
            ),
            "got {err:?}"
        );
    }

    /// A real cached directory whose `fuz` or `meta.json` is a symlink — even
    /// one aimed at the bytes the manifest pins — stays the hard error a
    /// tampered cache is: refused, never read through, never silently
    /// re-downloaded (only a slot that is not a real directory at all is).
    #[test]
    fn verify_cached_artifact_refuses_a_symlink_inside_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        let fuz_hash = write_cached_artifact(&cache, b"cached fuz binary bytes");
        let manifest = VerifiedManifest::assume_verified_for_test(cached_self_manifest(&fuz_hash));

        for file in ["fuz", "meta.json"] {
            let outside = dir.path().join(format!("outside-{file}"));
            std::fs::rename(cache.join(file), &outside).unwrap();
            std::os::unix::fs::symlink(&outside, cache.join(file)).unwrap();
            let err = verify_cached_artifact(&cache, &manifest)
                .expect_err("a linked file in the cache must be refused");
            assert!(
                matches!(
                    &err,
                    ReleaseError::Artifact(ArtifactError::NotRegularFile(path))
                        if *path == cache.join(file)
                ),
                "{file}: got {err:?}"
            );
            std::fs::remove_file(cache.join(file)).unwrap();
            std::fs::rename(&outside, cache.join(file)).unwrap();
        }
        verify_cached_artifact(&cache, &manifest).expect("the restored cache verifies");
    }

    #[test]
    fn verify_cached_artifact_rejects_meta_manifest_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        // On-disk binary and meta agree with each other, but the manifest pins a
        // different fuz hash — layer 1 (meta vs manifest) must catch it.
        write_cached_artifact(dir.path(), b"cached fuz binary bytes");
        let manifest = cached_self_manifest(&ContentHash::blake3(b"a different binary entirely"));
        let err = verify_cached_artifact(
            dir.path(),
            &VerifiedManifest::assume_verified_for_test(manifest),
        )
        .expect_err("meta/manifest mismatch must reject");
        assert!(
            matches!(
                err,
                ReleaseError::Tarball(TarballError::BinaryHashMismatch { .. })
            ),
            "got {err:?}"
        );
    }
}
