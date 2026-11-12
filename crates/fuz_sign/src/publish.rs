//! Publish workflow: create tarball, sign manifest, upload to storage
//!
//! This module handles the release publishing flow:
//! 1. Read artifact metadata from local artifact store
//! 2. Refuse a read-only store (`Storage::require_writable`), hold the
//!    release's name, version, and target to the storage-key contract
//!    (`check_release_keys`), and its version and `minimum_version` to semver
//!    (`check_release_versions`), before anything is packed, signed, or logged
//! 3. Create gzip-compressed tarball of binaries, in a scratch directory that
//!    is removed when the publish returns, with a result or an error
//! 4. Check that the release log can take the release, when a log checkout is
//!    given
//! 5. Sign the manifest, built from the artifact metadata
//! 6. Upload tarball and manifest to storage, and confirm they landed
//! 7. Record the release in the release log
//! 8. Update the target's `latest-<target>.json` pointer
//!
//! Every release is labelled with a target ([`PublishOptions::target`], or the
//! publishing binary's own when none is named). The label names every key the
//! release is stored under, so before anything is packed, logged, signed, or
//! uploaded, each binary's header is held to it
//! ([`fuz_artifact::platform::check_binary_target`]) — on the exact bytes that
//! are then signed.
//!
//! The log brackets the upload on purpose. Step 4 runs before any byte is
//! uploaded, so a release the log would refuse leaves storage untouched — and
//! that includes a release that would become the first head of a log while
//! storage already holds others, which a backfill has to log first. Step 7
//! sits between the bytes and the pointer: the release is logged before
//! anything advertises it, and a log write that fails stops the publish with
//! the pointer untouched.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use fuz_artifact::platform::{ReleaseTarget, check_binary_target, inspect_binary};
use fuz_artifact::{ArtifactError, ArtifactMeta, get_artifact_dir, get_current_artifact};

use crate::release_log::{LogEntry, LogOutcome, LogRepo, check_release, record_release};
use crate::scratch::{ScratchDir, ScratchError};
use crate::sign_manifest;
use fuz_crypto::ContentHash;
use fuz_release::{
    BinaryHashes, LatestInfo, MANIFEST_FORMAT_VERSION, ManifestError, ManifestUnsigned,
    ReleaseError, ReleaseLayout, SELF_NAME, TarballDigest, TarballError, TarballInfo, TargetRow,
    check_no_test_binaries, current_release_target, pack_tarball_to_file, sidecar_content,
};
use fuz_storage::{Storage, StorageBackendKind, StorageError, validate_forge_key};

/// Options for publishing a release
#[derive(Debug, Clone, Default)]
pub struct PublishOptions {
    /// Minimum version required to install this release (optional)
    pub minimum_version: Option<String>,
    /// A checkout of the release log repository. When set, the publish checks
    /// before uploading that the log can take the release, then records it
    /// there — extends and signs `head.json`, commits, pushes — after the
    /// release's bytes are uploaded and before the latest pointer moves, and fails
    /// without moving it if the log write fails. A log with no head takes the
    /// release as its first only when storage holds no other release. When
    /// unset, nothing is logged.
    pub log_repo: Option<LogRepo>,
    /// The target to label the release with (`--target`). When unset, the
    /// publishing binary's own target (`fuz_release::current_target`). Either
    /// way every binary is held to it before anything is signed; a statically
    /// linked one passes a defaulted glibc target only when it is named
    /// ([`fuz_artifact::platform::check_binary_target`]).
    pub target: Option<ReleaseTarget>,
}

/// Result of a successful publish operation
#[derive(Debug)]
pub struct PublishResult {
    /// Version that was published
    pub version: String,
    /// Content hash of the artifact
    pub content_hash: String,
    /// Path to the uploaded manifest
    pub manifest_path: String,
    /// Path to the uploaded tarball
    pub tarball_path: String,
    /// The target the release is labelled with.
    pub target: ReleaseTarget,
    /// What was recorded in the release log; `None` when the publish was given
    /// no log checkout.
    pub logged: Option<LogOutcome>,
}

/// The scratch directory a publish packs its tarball in, and the tarball's
/// path inside it.
///
/// The directory is `fuz-publish-<random>` under `scratch_root` (mode 0700);
/// dropping the value removes it and the tarball, so a publish that returns
/// leaves nothing there — after a failed pack, a refusal by the release log,
/// a failed upload, or success. Shared by the self-artifact and per-tool
/// publish paths so the staging lives in one place.
#[derive(Debug)]
pub(crate) struct PublishScratch {
    /// Where the tarball is packed.
    pub(crate) tarball: PathBuf,
    _dir: ScratchDir,
}

impl PublishScratch {
    /// # Errors
    ///
    /// [`TarballError::Io`] when the directory cannot be created: the cause,
    /// of the same kind, with the directory named in front of it.
    pub(crate) fn new_in(scratch_root: &Path) -> Result<Self, ReleaseError> {
        let dir = ScratchDir::new_in(scratch_root, "fuz-publish").map_err(
            |ScratchError { path, source }| {
                TarballError::Io(std::io::Error::new(
                    source.kind(),
                    format!(
                        "failed to create scratch directory {}: {source}",
                        path.display()
                    ),
                ))
            },
        )?;
        Ok(Self {
            tarball: dir.file("tarball.tar.gz"),
            _dir: dir,
        })
    }
}

/// Hold a release to the storage-key contract before any work is done on it.
///
/// A release's name, version, and target become part of every key it is
/// stored under, and every backend refuses a key outside the contract
/// ([`validate_forge_key`]) — so a version carrying semver build metadata
/// (`0.1.0+b1`) could be packed, signed, and logged, and then fail at the
/// first upload. Both publish flows call this first: before packing, before
/// signing, and before the release log checkout is touched.
///
/// Each of the three is checked as one key segment, so the error names the
/// field at fault; then every key the publish writes is checked whole (the
/// flat binary, its `latest` copy, and their sidecars only when `flat`), which
/// catches what no single field shows — a key past the length limit.
///
/// # Errors
///
/// [`ManifestError::UnpublishableField`] naming the field, or
/// [`StorageError::InvalidKey`] for a key that is invalid as a whole.
pub(crate) fn check_release_keys(
    layout: &ReleaseLayout,
    name: &str,
    version: &str,
    target: &str,
    flat: bool,
) -> Result<(), ReleaseError> {
    for (field, value) in [("name", name), ("version", version), ("target", target)] {
        let reason = if value.contains('/') {
            Some("it cannot contain '/'")
        } else {
            match validate_forge_key(value) {
                Ok(()) => None,
                Err(StorageError::InvalidKey { reason, .. }) => Some(reason),
                Err(other) => return Err(other.into()),
            }
        };
        if let Some(reason) = reason {
            return Err(ManifestError::UnpublishableField {
                field,
                value: value.to_string(),
                reason,
            }
            .into());
        }
    }

    let mut keys = vec![
        layout.tarball_key(&ReleaseLayout::tarball_filename(name, version, target)),
        layout.manifest_key(name, version, target),
        layout.latest_key(target),
    ];
    if flat {
        for key in [
            layout.binary_key(name, version, target),
            layout.latest_binary_key(name, target),
        ] {
            keys.push(format!("{key}.sha512"));
            keys.push(key);
        }
    }
    for key in &keys {
        validate_forge_key(key)?;
    }
    Ok(())
}

/// Hold a release's `version` and `minimum_version` to what a client can act
/// on, before any work is done on it.
///
/// Every client parses both as semver — to order a release against the one
/// installed, to check the floor, and, on the producer side, to choose what a
/// prune keeps — and refuses a release whose version does not parse. A
/// publish of one (`1.0`, a `minimum_version` of `banana`) would sign a
/// release no client installs, and once a latest pointer named it, the stream
/// could be neither upgraded nor pruned. A pre-release (`1.0.0-rc.1`) is
/// semver and is accepted.
///
/// The floor is held to two rules more. It carries no build metadata: the
/// semver spec's precedence ignores it but the `semver` crate orders by it,
/// so a floor of `0.1.0+b` would refuse a `0.1.0` client. And it is at most the release's own version: a client below the
/// floor refuses the upgrade, so a floor above the release would refuse
/// every installed client the upgrade to it, and report `update_required`
/// for as long as it is the latest.
///
/// Both publish flows call this beside [`check_release_keys`]: before
/// packing, before signing, and before the release log checkout is touched.
///
/// # Errors
///
/// [`ManifestError::UnpublishableVersion`] naming the field.
pub(crate) fn check_release_versions(
    version: &str,
    minimum_version: Option<&str>,
) -> Result<(), ReleaseError> {
    let refuse = |field, value: &str, reason: String| -> ReleaseError {
        ManifestError::UnpublishableVersion {
            field,
            value: value.to_string(),
            reason,
        }
        .into()
    };
    let release = semver::Version::parse(version)
        .map_err(|error| refuse("version", version, error.to_string()))?;
    let Some(minimum) = minimum_version else {
        return Ok(());
    };
    let floor = semver::Version::parse(minimum)
        .map_err(|error| refuse("minimum_version", minimum, error.to_string()))?;
    if !floor.build.is_empty() {
        return Err(refuse(
            "minimum_version",
            minimum,
            "build metadata is not allowed".to_string(),
        ));
    }
    if floor > release {
        return Err(refuse(
            "minimum_version",
            minimum,
            format!("above the release's own version {version}"),
        ));
    }
    Ok(())
}

/// The target a publish labels its release with, and whether it was named:
/// [`PublishOptions::target`], else the publishing binary's own.
///
/// # Errors
///
/// [`ManifestError::UnsupportedTarget`] when none is named and the publishing
/// binary's own target is outside the supported set.
pub(crate) fn resolve_publish_target(
    options: &PublishOptions,
) -> Result<(ReleaseTarget, bool), ReleaseError> {
    match options.target {
        Some(target) => Ok((target, true)),
        None => Ok((current_release_target()?, false)),
    }
}

/// Hold the binary `name`, as the bytes about to be signed, to the target the
/// release is labelled with ([`check_binary_target`]).
///
/// # Errors
///
/// [`ArtifactError::BinaryUnreadable`] for bytes that are no executable
/// [`inspect_binary`] can place, [`ArtifactError::BinaryPlatform`] for one
/// that is not for `target`; both name the binary.
pub(crate) fn check_publish_binary(
    name: &str,
    bytes: &[u8],
    target: ReleaseTarget,
    explicit: bool,
) -> Result<(), ReleaseError> {
    let found = inspect_binary(bytes).map_err(|reason| ArtifactError::BinaryUnreadable {
        name: name.to_string(),
        reason,
    })?;
    check_binary_target(found, target, explicit).map_err(|mismatch| {
        ArtifactError::BinaryPlatform {
            name: name.to_string(),
            target,
            found,
            mismatch,
        }
    })?;
    Ok(())
}

/// Publish the current artifact to storage.
///
/// Uses the artifact pointed to by `~/.fuz/current`. The self artifact is
/// **fuz-only** — it packages just the `fuz` binary, so any current artifact
/// (built, bootstrap, or remote) is publishable; fuzd ships as its own per-tool
/// artifact (`publish_tool`), not part of the self bundle.
///
/// # Errors
///
/// Returns [`ReleaseError`] if there is no current artifact or
/// signing/packaging/upload fails.
pub async fn publish_current(
    storage: &impl Storage,
    key: &SigningKey,
    options: &PublishOptions,
) -> Result<PublishResult, ReleaseError> {
    let meta = get_current_artifact()?.ok_or_else(|| StorageError::NotFound {
        backend: StorageBackendKind::File,
        path: "current artifact (no current symlink)".to_string(),
    })?;

    let artifact_dir = get_artifact_dir(&meta.hash)?;
    publish_artifact(storage, &meta, &artifact_dir, key, options).await
}

/// Publish a specific artifact to storage as the fuz-only self artifact.
///
/// Packages just the `fuz` binary (`ArtifactOutputs` is fuz-only; fuzd is a
/// separate per-tool artifact — see `publish_tool`).
///
/// # Errors
///
/// Returns [`ReleaseError`] if the store is read-only, the version cannot be
/// part of a storage key, or the version or `minimum_version` is not semver
/// (all refused before anything is packed), the
/// `fuz` binary hash mismatches, or signing, upload, or the post-upload
/// presence check fails.
pub async fn publish_artifact(
    storage: &impl Storage,
    meta: &ArtifactMeta,
    artifact_dir: &Path,
    key: &SigningKey,
    options: &PublishOptions,
) -> Result<PublishResult, ReleaseError> {
    publish_artifact_in(
        storage,
        meta,
        artifact_dir,
        key,
        options,
        &std::env::temp_dir(),
    )
    .await
}

/// [`publish_artifact`] with the directory its scratch directory is created
/// under named: the system temp directory for a publish.
pub(crate) async fn publish_artifact_in(
    storage: &impl Storage,
    meta: &ArtifactMeta,
    artifact_dir: &Path,
    key: &SigningKey,
    options: &PublishOptions,
    scratch_root: &Path,
) -> Result<PublishResult, ReleaseError> {
    let (release_target, explicit) = resolve_publish_target(options)?;
    let target = release_target.triple();
    let layout = ReleaseLayout::self_artifact();

    // 0. Refuse what could only fail at the first upload, before anything is
    //    packed, signed, or logged: a store with no upload, and a version no
    //    store could hold (it becomes part of every key below).
    storage.require_writable("upload")?;
    check_release_keys(&layout, SELF_NAME, &meta.version, target, true)?;
    check_release_versions(&meta.version, options.minimum_version.as_deref())?;

    // 1. Pack the tarball to a scratch file (streamed, hashed in one pass) —
    //    never holds the whole `.tar.gz` in memory. The scratch directory goes
    //    when `scratch` does: on return, by any path.
    let tarball_filename = ReleaseLayout::tarball_filename(SELF_NAME, &meta.version, target);
    let scratch = PublishScratch::new_in(scratch_root)?;
    let packed = create_tarball_file(artifact_dir, meta, &scratch.tarball).await?;
    // The one read of `fuz` — the bytes packed, signed, and uploaded flat — is
    // for the release's target, or nothing is logged, signed, or uploaded.
    check_publish_binary(SELF_NAME, &packed.fuz_bytes, release_target, explicit)?;

    // 2. Create unsigned manifest. The self artifact is fuz-only; the
    //    manifest-declared binary set is just `fuz`, and `content_hash`
    //    (= `meta.hash`) is the fuz-only content hash.
    let mut binaries = BinaryHashes::new();
    binaries.insert(SELF_NAME.to_string(), meta.outputs.fuz.clone());

    // Defense in depth: refuse to package a test binary even at the publish
    // enumeration step. Mirror of the manifest-side check in
    // `Manifest::validate()`.
    check_no_test_binaries(binaries.keys().map(String::as_str))?;

    // 3. Before anything is uploaded, check that the release log can take this
    //    release. A log that would refuse it — an unusable checkout, an
    //    unverifiable head, a version already logged with other bytes, a key
    //    this binary does not trust (whether or not it would sign a head), a
    //    log with no head while storage holds other releases — stops the
    //    publish with storage untouched.
    //
    //    One hash of the one verified read of the binary feeds the log's
    //    `sha512` and both storage sidecars, and one timestamp serves the whole
    //    publish: the manifest's `signed_at` and, in the log, the row's
    //    `published_at` and the head's `signed_at`.
    let fuz_bytes = &packed.fuz_bytes;
    let fuz_sha512 = ContentHash::sha512(fuz_bytes);
    let fuz_sha512_hex = fuz_sha512.to_hex();
    let signed_at = fuz_sys::rfc3339_now();
    let entry = LogEntry {
        name: SELF_NAME.to_string(),
        version: meta.version.clone(),
        target: target.to_string(),
        pins: TargetRow {
            content_hash: meta.hash.clone(),
            // The row's `binaries`, as the manifest about to be signed declares them.
            binaries: binaries.clone().into_iter().collect(),
            sha512: Some(fuz_sha512),
        },
        flat_latest: true,
    };
    check_log(storage, options, &entry, key, &signed_at).await?;

    let unsigned = ManifestUnsigned {
        format: MANIFEST_FORMAT_VERSION,
        version: meta.version.clone(),
        content_hash: meta.hash.clone(),
        target: target.to_string(),
        minimum_version: options.minimum_version.clone(),
        tarball: TarballInfo {
            path: tarball_filename.clone(),
            blake3: packed.digest.blake3,
            size: packed.digest.size,
        },
        binaries,
        tool: None,
    };

    // 4. Sign + upload the manifest and its (streamed) tarball; the scratch
    //    tarball has no use past the upload.
    let tarball_key = layout.tarball_key(&tarball_filename);
    let manifest_key = layout.manifest_key(SELF_NAME, &meta.version, target);
    sign_and_upload(
        storage,
        &manifest_key,
        &tarball_key,
        unsigned,
        &scratch.tarball,
        key,
        &signed_at,
    )
    .await?;
    drop(scratch);

    // 5. Upload the versioned flat-layout fuz binary + SHA-512 sidecar for the
    //    install script (self artifact only). The install script
    //    (`scripts/install.sh`) downloads `fuz-{version}-{target}` and
    //    `fuz-latest-{target}` directly (no manifest parsing) and verifies via
    //    SHA-512 because `b3sum` isn't universally installed. The trust
    //    split: docs/security-model.md § First Binary Bootstrap.
    //
    //    These are the *same* bytes step 1 packed into the signed tarball, and
    //    the only ones the artifact dir was read for — so the manifest's blake3
    //    pin and the flat file's SHA-512 sidecar describe one byte string. A
    //    second read here would let a file changed mid-publish split the two
    //    layouts, and install.sh (which never sees the manifest) would take the
    //    unsigned side.
    let versioned_name = layout.binary_key(SELF_NAME, &meta.version, target);
    let latest_name = layout.latest_binary_key(SELF_NAME, target);

    storage.upload(&versioned_name, fuz_bytes).await?;
    storage
        .upload(
            &format!("{versioned_name}.sha512"),
            sidecar_content(&versioned_name, &fuz_sha512_hex).as_bytes(),
        )
        .await?;

    // 6. The versioned bytes are up and nothing points at them yet: confirm the
    //    tarball + manifest landed, then record the release in the log. The
    //    log write repeats every check of step 3, so a log that changed in
    //    between is still caught.
    confirm_uploaded(storage, &tarball_key, &manifest_key).await?;
    let logged = log_release(storage, options, &entry, key, &signed_at).await?;

    // 7. Advertise the release: the `latest` copy of the flat binary, then the
    //    target's `latest-<target>.json` pointer. Both move only once the
    //    release is logged.
    storage.upload(&latest_name, fuz_bytes).await?;
    storage
        .upload(
            &format!("{latest_name}.sha512"),
            sidecar_content(&latest_name, &fuz_sha512_hex).as_bytes(),
        )
        .await?;
    set_latest(storage, &layout, &meta.version, target).await?;

    Ok(PublishResult {
        version: meta.version.clone(),
        content_hash: meta.hash.clone(),
        manifest_path: manifest_key,
        tarball_path: tarball_key,
        target: release_target,
        logged,
    })
}

/// Check that the release log can take `entry`, when the publish was given a
/// log checkout. Called before the first upload; writes nothing to storage and
/// nothing to the checkout beyond a fast-forward. Storage is listed only when
/// the log has no head.
pub(crate) async fn check_log(
    storage: &impl Storage,
    options: &PublishOptions,
    entry: &LogEntry,
    key: &SigningKey,
    signed_at: &str,
) -> Result<(), ReleaseError> {
    if let Some(repo) = &options.log_repo {
        check_release(storage, repo, entry, key, signed_at).await?;
    }
    Ok(())
}

/// Record `entry` in the release log when the publish was given a log
/// checkout; `None` otherwise.
///
/// The one place both publish flows reach the log, called between confirming
/// the upload and moving the latest pointer. Blocking — it runs `git` — like the
/// tarball packing that precedes it; a publish is a one-shot command.
pub(crate) async fn log_release(
    storage: &impl Storage,
    options: &PublishOptions,
    entry: &LogEntry,
    key: &SigningKey,
    signed_at: &str,
) -> Result<Option<LogOutcome>, ReleaseError> {
    let Some(repo) = &options.log_repo else {
        return Ok(None);
    };
    Ok(Some(
        record_release(storage, repo, entry, key, signed_at).await?,
    ))
}

/// Sign `unsigned`, then upload its tarball followed by the signed manifest to
/// the given storage keys.
///
/// The tarball is uploaded first because the manifest references it; callers
/// publish the `latest-<target>.json` pointer last (via [`confirm_uploaded`] then
/// [`set_latest`]) so a partial upload never becomes the advertised release.
/// Shared by the self-artifact and per-tool publish paths so the upload
/// ordering lives in exactly one place; the caller derives the keys (where the
/// self-vs-tool layout difference lives) and supplies the signing timestamp.
pub(crate) async fn sign_and_upload(
    storage: &impl Storage,
    manifest_key: &str,
    tarball_key: &str,
    unsigned: ManifestUnsigned,
    tarball_path: &Path,
    key: &SigningKey,
    signed_at: &str,
) -> Result<(), ReleaseError> {
    let manifest = sign_manifest(unsigned, key, signed_at)?;
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| StorageError::UploadFailed {
            backend: storage.backend_kind(),
            message: format!("failed to serialize manifest: {e}"),
        })?;

    // Tarball first (the manifest references it), then the manifest. The tarball
    // streams from disk (bounded memory); the manifest is tiny JSON.
    storage.upload_file(tarball_key, tarball_path).await?;
    storage
        .upload(manifest_key, manifest_json.as_bytes())
        .await?;

    Ok(())
}

/// Confirm the uploaded tarball + manifest are present in storage. Run before
/// the release is logged or advertised, so neither names a release whose
/// upload did not land.
///
/// Presence only: nothing is downloaded or re-hashed, so it catches an upload
/// that failed or went to the wrong key, not bytes that changed on the way.
/// The bytes are verified where they are trusted — by every client, against
/// the signed manifest.
pub(crate) async fn confirm_uploaded(
    storage: &impl Storage,
    tarball_key: &str,
    manifest_key: &str,
) -> Result<(), ReleaseError> {
    // HEAD both in parallel — catches network/permission failures without
    // re-downloading. (CDN caching may cause false positives.)
    let (tarball_exists, manifest_exists) =
        tokio::try_join!(storage.exists(tarball_key), storage.exists(manifest_key))?;
    if !tarball_exists {
        return Err(StorageError::UploadFailed {
            backend: storage.backend_kind(),
            message: format!("upload check failed: {tarball_key} not found after upload"),
        }
        .into());
    }
    if !manifest_exists {
        return Err(StorageError::UploadFailed {
            backend: storage.backend_kind(),
            message: format!("upload check failed: {manifest_key} not found after upload"),
        }
        .into());
    }
    Ok(())
}

/// Publish the target's `latest-<target>.json` version pointer — the final
/// "make visible" step. Call only after every artifact byte is uploaded and
/// confirmed present ([`confirm_uploaded`]) and the release is logged, so
/// `latest` never points at an incomplete or unlogged release. Unconditional:
/// every publish moves its target's pointer to the version it published, and
/// no other target's.
pub(crate) async fn set_latest(
    storage: &impl Storage,
    layout: &ReleaseLayout,
    version: &str,
    target: &str,
) -> Result<(), ReleaseError> {
    let latest = LatestInfo {
        version: version.to_string(),
    };
    let latest_json =
        serde_json::to_string_pretty(&latest).map_err(|e| StorageError::UploadFailed {
            backend: storage.backend_kind(),
            message: format!("failed to serialize the latest pointer: {e}"),
        })?;
    storage
        .upload(&layout.latest_key(target), latest_json.as_bytes())
        .await?;
    Ok(())
}

/// A packed self-artifact tarball plus the exact `fuz` bytes it was built from.
///
/// The published release ships that one binary under **two** layouts — inside
/// the signed tarball, and flat as `fuz-<version>-<target>` / `fuz-latest-<target>`
/// with a SHA-512 sidecar. Carrying the bytes out of the single verified read
/// makes the two layouts the same byte string by construction; re-reading the
/// file for the flat upload could publish a manifest pinning one binary and a
/// flat+sidecar pair serving another (and `install.sh` is manifest-blind).
#[derive(Debug)]
struct PackedSelfArtifact {
    /// blake3 + size of the `.tar.gz` on disk, for the manifest.
    digest: TarballDigest,
    /// The `fuz` binary bytes, already verified against `meta.outputs.fuz`.
    fuz_bytes: Vec<u8>,
}

/// Pack the fuz-only self artifact to a gzip tarball at `dest`, streamed +
/// hashed in one pass. Returns the tarball's blake3 + size for the manifest,
/// **and** the verified `fuz` bytes for the flat-layout upload.
///
/// The binary is read once and checked against `meta.outputs.fuz` before
/// packing; every later use of those bytes inherits that verification.
///
/// Tarball contains only the `fuz` binary at root level:
/// ```text
/// fuz       (mode 0755)
/// ```
async fn create_tarball_file(
    artifact_dir: &Path,
    meta: &ArtifactMeta,
    dest: &Path,
) -> Result<PackedSelfArtifact, ReleaseError> {
    let fuz_path = artifact_dir.join("fuz");
    let fuz_content = tokio::fs::read(&fuz_path).await.map_err(|e| {
        StorageError::Io(
            StorageBackendKind::File,
            std::io::Error::other(format!("failed to read fuz: {e}")),
        )
    })?;

    // Verify hash (defense in depth)
    let fuz_hash = ContentHash::blake3(&fuz_content);
    if fuz_hash != meta.outputs.fuz {
        return Err(TarballError::BinaryHashMismatch {
            name: "fuz".to_string(),
            expected: meta.outputs.fuz.clone(),
            actual: fuz_hash,
        }
        .into());
    }

    // The self artifact is a 1-element case of the generic streaming packer.
    // The entries array is destructured afterward to hand the verified bytes
    // back to the caller — no second read, no clone.
    let entries = [("fuz".to_string(), fuz_content)];
    let digest = pack_tarball_to_file(&entries, dest)?;
    let [(_, fuz_bytes)] = entries;

    Ok(PackedSelfArtifact { digest, fuz_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use fuz_artifact::ArtifactOutputs;
    use fuz_artifact::platform::{ReleaseTarget, test_stubs};
    use fuz_release::{
        Manifest, current_target, extract_tarball, verify_binary_hashes, verify_content_hash,
        verify_tarball_hash,
    };
    use fuz_storage::FileStorage;
    use std::fs;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0u8; 32])
    }

    /// Build a fuz-only self artifact on disk (the self artifact is fuz-only;
    /// fuzd is a separate per-tool artifact).
    fn create_test_artifact(dir: &Path, version: &str) -> ArtifactMeta {
        let fuz_content = test_stubs::host(b"fuz binary content for testing");
        fs::write(dir.join("fuz"), &fuz_content).unwrap();

        let outputs = ArtifactOutputs {
            fuz: ContentHash::blake3(&fuz_content),
        };

        let meta = ArtifactMeta::new_remote(outputs.content_hash(), version.to_string(), outputs);
        meta.write(dir).unwrap();
        meta
    }

    #[tokio::test]
    async fn create_tarball_works() {
        let dir = tempfile::tempdir().unwrap();
        let meta = create_test_artifact(dir.path(), "0.1.0");
        let dest = dir.path().join("out.tar.gz");

        let packed = create_tarball_file(dir.path(), &meta, &dest).await.unwrap();
        assert!(packed.digest.size > 0);
        assert_eq!(packed.digest.blake3.to_hex().len(), 64);
        // The on-disk tarball hashes to the returned digest.
        let on_disk = fs::read(&dest).unwrap();
        assert_eq!(ContentHash::blake3(&on_disk), packed.digest.blake3);

        // The returned bytes are the verified `fuz` binary — the single read the
        // flat-layout upload also consumes.
        assert_eq!(packed.fuz_bytes, fs::read(dir.path().join("fuz")).unwrap());
        assert_eq!(ContentHash::blake3(&packed.fuz_bytes), meta.outputs.fuz);

        // Valid gzip with exactly the fuz binary (fuz-only self artifact).
        let gz = flate2::read::GzDecoder::new(fs::File::open(&dest).unwrap());
        let mut archive = tar::Archive::new(gz);
        let entries: Vec<_> = archive.entries().unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    /// A publish is what creates a local store: parsing the location leaves a
    /// missing directory missing, and the first upload brings it — parents
    /// included — into being. After it, the existing-store parse a consumer
    /// uses opens the store.
    #[tokio::test]
    async fn publish_creates_a_local_store_that_is_not_there() {
        let artifact_dir = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("releases").join("fuz");
        let location = root.to_str().unwrap();

        let meta = create_test_artifact(artifact_dir.path(), "0.2.0");
        assert!(matches!(
            fuz_storage::parse_existing_storage(location),
            Err(StorageError::LocalRootNotDir)
        ));
        let storage = fuz_storage::parse_storage(location).unwrap();
        assert!(
            !scratch.path().join("releases").exists(),
            "naming the store created it"
        );

        publish_artifact(
            &storage,
            &meta,
            artifact_dir.path(),
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap();

        let latest_key = format!("latest-{}.json", current_target());
        assert!(root.join(&latest_key).is_file());
        let reader = fuz_storage::parse_existing_storage(location).unwrap();
        let latest: LatestInfo =
            serde_json::from_slice(&reader.download(&latest_key).await.unwrap()).unwrap();
        assert_eq!(latest.version, "0.2.0");
    }

    /// A version no store could hold — semver build metadata, whose `+` is
    /// outside the key contract — is refused before any work: before the
    /// artifact is read and packed (the artifact directory here has no `fuz`
    /// to pack), before the release log checkout is touched (the one given is
    /// not a checkout), and before anything is written to storage.
    #[tokio::test]
    async fn publish_refuses_a_version_no_store_could_hold_before_any_work() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("store");
        let storage = FileStorage::new(&root).unwrap();
        let empty_artifact_dir = scratch.path().join("artifact");
        fs::create_dir(&empty_artifact_dir).unwrap();
        let not_a_checkout = scratch.path().join("log");
        let options = PublishOptions {
            log_repo: Some(LogRepo::new(&not_a_checkout)),
            ..PublishOptions::default()
        };

        for (version, reason) in [
            ("0.2.0+b1", "invalid characters"),
            ("0.2.0+20260101.sha.abc", "invalid characters"),
            ("../0.2.0", "'/'"),
            (".0.2.0", "start with '.'"),
        ] {
            let outputs = ArtifactOutputs {
                fuz: ContentHash::blake3(b"never read"),
            };
            let meta =
                ArtifactMeta::new_remote(outputs.content_hash(), version.to_string(), outputs);
            let err = publish_artifact(&storage, &meta, &empty_artifact_dir, &test_key(), &options)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &err,
                    ReleaseError::Manifest(ManifestError::UnpublishableField {
                        field: "version",
                        value,
                        reason: why,
                    }) if value == version && why.contains(reason)
                ),
                "{version}: {err:?}"
            );
            assert!(
                err.to_string()
                    .contains("release version cannot be part of a storage key"),
                "{err}"
            );
            assert!(err.hint().is_some_and(|hint| hint.contains('+')));
        }
        assert!(!root.exists(), "storage was written to");
        assert!(!not_a_checkout.exists(), "the log checkout was touched");
        assert_eq!(fs::read_dir(&empty_artifact_dir).unwrap().count(), 0);
    }

    /// A pre-release version is within the key contract and publishes.
    /// A read-only store has nothing to upload to: the publish refuses it
    /// with the error its `upload` would give, before any work — before the
    /// artifact directory is read (it is empty), the release log is consulted
    /// (the checkout given is not one), or a scratch directory is made.
    #[tokio::test]
    async fn publish_refuses_a_read_only_store_before_any_work() {
        let scratch = tempfile::tempdir().unwrap();
        let storage = fuz_storage::HttpsStorage::new("https://releases.example.com/fuz").unwrap();
        let empty_artifact_dir = scratch.path().join("artifact");
        fs::create_dir(&empty_artifact_dir).unwrap();
        let scratch_root = scratch.path().join("tmp");
        fs::create_dir(&scratch_root).unwrap();
        let not_a_checkout = scratch.path().join("log");
        let options = PublishOptions {
            log_repo: Some(LogRepo::new(&not_a_checkout)),
            ..PublishOptions::default()
        };
        let outputs = ArtifactOutputs {
            fuz: ContentHash::blake3(b"never read"),
        };
        let meta = ArtifactMeta::new_remote(outputs.content_hash(), "0.2.0".to_string(), outputs);

        let err = publish_artifact_in(
            &storage,
            &meta,
            &empty_artifact_dir,
            &test_key(),
            &options,
            &scratch_root,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &err,
                ReleaseError::Storage(StorageError::Unsupported {
                    backend: StorageBackendKind::Https,
                    operation: "upload",
                })
            ),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "storage error: HTTPS: upload is not supported on a read-only backend"
        );
        assert_eq!(
            err.hint().as_deref(),
            Some("Use a writable backend: a local path, forge://, or ssh://")
        );
        assert_eq!(fs::read_dir(&scratch_root).unwrap().count(), 0);
        assert!(!not_a_checkout.exists(), "the log checkout was touched");
    }

    /// A version or floor no client parses is refused by field; semver ones,
    /// pre-releases included, pass.
    #[test]
    fn release_versions_are_semver() {
        for (version, minimum) in [
            ("0.1.0", None),
            ("1.0.0-rc.1", Some("0.9.0")),
            ("0.2.0", Some("0.2.0-alpha")),
            // A floor at the release's own version.
            ("0.2.0", Some("0.2.0")),
            ("1.0.0-rc.1", Some("1.0.0-rc.1")),
        ] {
            assert!(
                check_release_versions(version, minimum).is_ok(),
                "{version} {minimum:?}"
            );
        }
        for (version, minimum, field, value) in [
            ("1.0", None, "version", "1.0"),
            ("v1.0.0", None, "version", "v1.0.0"),
            ("01.0.0", None, "version", "01.0.0"),
            ("", None, "version", ""),
            ("1.0.0", Some("banana"), "minimum_version", "banana"),
            ("1.0.0", Some("1.0"), "minimum_version", "1.0"),
            ("1.0.0", Some(""), "minimum_version", ""),
            // The version is checked first.
            ("1", Some("banana"), "version", "1"),
            // A floor above the release, or with build metadata.
            ("0.1.0", Some("0.2.0"), "minimum_version", "0.2.0"),
            ("1.0.0-rc.1", Some("1.0.0"), "minimum_version", "1.0.0"),
            ("0.1.0", Some("0.1.0+b"), "minimum_version", "0.1.0+b"),
            // Build metadata is refused on a floor below the release too.
            ("0.2.0", Some("0.1.0+b"), "minimum_version", "0.1.0+b"),
        ] {
            let result = check_release_versions(version, minimum);
            assert!(
                matches!(
                    &result,
                    Err(ReleaseError::Manifest(ManifestError::UnpublishableVersion {
                        field: f,
                        value: v,
                        ..
                    })) if *f == field && v == value
                ),
                "{version} {minimum:?}: {result:?}"
            );
        }
    }

    /// A self publish refuses a version or a `minimum_version` that is not
    /// semver before any work: before the binary is read (the artifact
    /// directory is empty), a scratch directory is made, the release log is
    /// consulted (the checkout given is not one), or storage is written.
    #[tokio::test]
    async fn publish_refuses_a_non_semver_version_or_floor_before_any_work() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("store");
        let storage = FileStorage::new(&root).unwrap();
        let empty_artifact_dir = scratch.path().join("artifact");
        fs::create_dir(&empty_artifact_dir).unwrap();
        let scratch_root = scratch.path().join("tmp");
        fs::create_dir(&scratch_root).unwrap();
        let not_a_checkout = scratch.path().join("log");
        let outputs = ArtifactOutputs {
            fuz: ContentHash::blake3(b"never read"),
        };
        for (version, minimum, field) in [
            ("1.0", None, "version"),
            ("1.0.0", Some("banana"), "minimum_version"),
        ] {
            let meta = ArtifactMeta::new_remote(
                outputs.content_hash(),
                version.to_string(),
                outputs.clone(),
            );
            let options = PublishOptions {
                minimum_version: minimum.map(String::from),
                log_repo: Some(LogRepo::new(&not_a_checkout)),
                target: None,
            };
            let err = publish_artifact_in(
                &storage,
                &meta,
                &empty_artifact_dir,
                &test_key(),
                &options,
                &scratch_root,
            )
            .await
            .unwrap_err();
            assert!(
                matches!(
                    &err,
                    ReleaseError::Manifest(ManifestError::UnpublishableVersion { field: f, .. })
                        if *f == field
                ),
                "{field}: {err:?}"
            );
            assert!(!root.exists(), "{field}: storage was written to");
            assert_eq!(fs::read_dir(&scratch_root).unwrap().count(), 0, "{field}");
            assert!(
                !not_a_checkout.exists(),
                "{field}: the log checkout was touched"
            );
        }
        assert_eq!(
            ManifestError::UnpublishableVersion {
                field: "minimum_version",
                value: "banana".to_string(),
                reason: semver::Version::parse("banana").unwrap_err().to_string(),
            }
            .to_string(),
            "release minimum_version cannot be published: \"banana\" (unexpected character 'b' \
             while parsing major version number)"
        );
        for (minimum, reason) in [
            ("0.2.0", "above the release's own version 0.1.0"),
            ("0.1.0+b", "build metadata is not allowed"),
        ] {
            let error = check_release_versions("0.1.0", Some(minimum)).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "manifest error: release minimum_version cannot be published: \"{minimum}\" \
                     ({reason})"
                )
            );
        }
    }

    #[tokio::test]
    async fn publish_accepts_a_pre_release_version() {
        let artifact_dir = tempfile::tempdir().unwrap();
        let storage_dir = tempfile::tempdir().unwrap();
        let meta = create_test_artifact(artifact_dir.path(), "0.0.2-rc.1");
        let storage = FileStorage::new(storage_dir.path()).unwrap();

        let result = publish_artifact(
            &storage,
            &meta,
            artifact_dir.path(),
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.version, "0.0.2-rc.1");
        assert!(storage.exists(&result.manifest_path).await.unwrap());
        let latest: LatestInfo = serde_json::from_slice(
            &storage
                .download(&ReleaseLayout::self_artifact().latest_key(current_target()))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(latest.version, "0.0.2-rc.1");
    }

    /// Every key a publish writes is checked whole too: a version within the
    /// charset that makes a key too long is refused as that key.
    #[test]
    fn release_keys_are_checked_whole_as_well_as_by_field() {
        let layout = ReleaseLayout::tool("fuzd");
        let target = "x86_64-unknown-linux-gnu";
        assert!(check_release_keys(&layout, "fuzd", "0.1.0", target, false).is_ok());
        assert!(
            check_release_keys(
                &ReleaseLayout::self_artifact(),
                SELF_NAME,
                "0.1.0",
                target,
                true
            )
            .is_ok()
        );
        let long = "1".repeat(500);
        assert!(matches!(
            check_release_keys(&layout, "fuzd", &long, target, false),
            Err(ReleaseError::Storage(StorageError::InvalidKey { .. }))
        ));
        for (name, version, bad_target, field) in [
            ("fu zd", "0.1.0", target, "name"),
            ("fuzd", "0.1.0", "x86_64/linux", "target"),
            ("fuzd", "", target, "version"),
        ] {
            assert!(
                matches!(
                    check_release_keys(&layout, name, version, bad_target, false),
                    Err(ReleaseError::Manifest(ManifestError::UnpublishableField {
                        field: named,
                        ..
                    })) if named == field
                ),
                "{field}"
            );
        }
    }

    /// Write a self artifact holding `bytes` as its `fuz`.
    fn artifact_holding(dir: &Path, version: &str, bytes: &[u8]) -> ArtifactMeta {
        fs::write(dir.join("fuz"), bytes).unwrap();
        let outputs = ArtifactOutputs {
            fuz: ContentHash::blake3(bytes),
        };
        let meta = ArtifactMeta::new_remote(outputs.content_hash(), version.to_string(), outputs);
        meta.write(dir).unwrap();
        meta
    }

    /// A current artifact whose `fuz` is for another target is refused before
    /// anything lands — no manifest, no tarball, no flat file, no pointer —
    /// and the log checkout is untouched. Named with `--target`, the same
    /// artifact publishes under that target: keys, flat files, and pointer.
    #[tokio::test]
    async fn publish_of_a_foreign_fuz_is_refused_unless_its_target_is_named() {
        let host = test_stubs::host_target();
        let other = match host.libc() {
            Some(fuz_artifact::platform::Libc::Gnu) => {
                ReleaseTarget::linux(host.arch(), fuz_artifact::platform::Libc::Musl)
            }
            _ => ReleaseTarget::linux(host.arch(), fuz_artifact::platform::Libc::Gnu),
        };
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("store");
        let storage = FileStorage::new(&root).unwrap();
        let artifact_dir = scratch.path().join("artifact");
        fs::create_dir(&artifact_dir).unwrap();
        let meta = artifact_holding(
            &artifact_dir,
            "0.2.0",
            &test_stubs::for_target(other, b"fuz"),
        );
        let not_a_checkout = scratch.path().join("log");

        let err = publish_artifact(
            &storage,
            &meta,
            &artifact_dir,
            &test_key(),
            &PublishOptions {
                log_repo: Some(LogRepo::new(&not_a_checkout)),
                ..PublishOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &err,
                ReleaseError::Artifact(ArtifactError::BinaryPlatform { name, target, .. })
                    if name == "fuz" && *target == host
            ),
            "{err:?}"
        );
        assert!(
            err.hint()
                .unwrap()
                .starts_with(&format!("pass --target {other} ")),
            "{err:?}"
        );
        assert!(!root.exists(), "storage was written to");
        assert!(!not_a_checkout.exists(), "the log checkout was touched");

        let published = publish_artifact(
            &storage,
            &meta,
            &artifact_dir,
            &test_key(),
            &PublishOptions {
                target: Some(other),
                ..PublishOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(published.target, other);
        let layout = ReleaseLayout::self_artifact();
        for key in [
            layout.manifest_key("fuz", "0.2.0", other.triple()),
            layout.binary_key("fuz", "0.2.0", other.triple()),
            format!(
                "{}.sha512",
                layout.binary_key("fuz", "0.2.0", other.triple())
            ),
            layout.latest_binary_key("fuz", other.triple()),
            layout.latest_key(other.triple()),
        ] {
            assert!(storage.exists(&key).await.unwrap(), "{key}");
        }
        for key in [
            layout.binary_key("fuz", "0.2.0", host.triple()),
            layout.latest_binary_key("fuz", host.triple()),
            layout.latest_key(host.triple()),
        ] {
            assert!(!storage.exists(&key).await.unwrap(), "{key}");
        }
    }

    #[tokio::test]
    async fn publish_to_file_storage() {
        let artifact_dir = tempfile::tempdir().unwrap();
        let storage_dir = tempfile::tempdir().unwrap();

        let meta = create_test_artifact(artifact_dir.path(), "0.2.0");
        let storage = FileStorage::new(storage_dir.path()).unwrap();
        let key = test_key();

        let result = publish_artifact(
            &storage,
            &meta,
            artifact_dir.path(),
            &key,
            &PublishOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(result.version, "0.2.0");

        // Verify files were created
        assert!(storage.exists(&result.tarball_path).await.unwrap());
        assert!(storage.exists(&result.manifest_path).await.unwrap());
        let latest_key = ReleaseLayout::self_artifact().latest_key(current_target());
        assert!(storage.exists(&latest_key).await.unwrap());

        // Verify the pointer's content
        let latest_bytes = storage.download(&latest_key).await.unwrap();
        let latest: LatestInfo = serde_json::from_slice(&latest_bytes).unwrap();
        assert_eq!(latest.version, "0.2.0");

        // Verify manifest can be parsed and verified
        let manifest_bytes = storage.download(&result.manifest_path).await.unwrap();
        let manifest = Manifest::from_json(&manifest_bytes).unwrap();
        assert_eq!(manifest.version, "0.2.0");

        // Self artifact is fuz-only: the manifest declares just `fuz`, no tool.
        assert_eq!(manifest.tool, None);
        assert_eq!(manifest.binaries.len(), 1, "self manifest is fuz-only");
        assert!(manifest.binaries.contains_key("fuz"));
        assert!(!manifest.binaries.contains_key("fuzd"));

        // Round trip: download + extract + verify the tarball end-to-end
        // (signature verification needs a trusted key, exercised end to end in
        // `tests/signed_trust.rs::publish_then_fetch_latest_self_artifact_end_to_end`).
        let tarball = storage
            .download(&ReleaseLayout::self_artifact().tarball_key(&manifest.tarball.path))
            .await
            .unwrap();
        verify_tarball_hash(&tarball, &manifest.tarball.blake3).unwrap();

        let extract_dir = tempfile::tempdir().unwrap();
        let extracted = extract_tarball(&tarball, &manifest, extract_dir.path()).unwrap();
        assert_eq!(extracted.len(), 1, "fuz-only tarball");
        verify_binary_hashes(&extracted, &manifest).unwrap();
        verify_content_hash(&extracted, &manifest.content_hash).unwrap();

        // Verify flat-layout binaries + SHA-512 sidecars for install script
        let target = current_target();
        let versioned = format!("fuz-0.2.0-{target}");
        let latest = format!("fuz-latest-{target}");

        assert!(
            storage.exists(&versioned).await.unwrap(),
            "versioned binary"
        );
        assert!(
            storage
                .exists(&format!("{versioned}.sha512"))
                .await
                .unwrap(),
            "versioned sha512 sidecar"
        );
        assert!(storage.exists(&latest).await.unwrap(), "latest binary");
        assert!(
            storage.exists(&format!("{latest}.sha512")).await.unwrap(),
            "latest sha512 sidecar"
        );

        // Sidecar content matches downloaded binary.
        // TODO: this leans on `sha512_hex` for both sides, so it pins the
        // wiring and the sidecar's format but not the digest itself — a wrong
        // `sha512_hex` would satisfy it. Correctness is pinned instead by the
        // NIST vectors in `fuz_release::checksum`, and cross-tool agreement by
        // `scripts/install-test.sh` (which hashes with real `sha512sum`).
        // Worth an independent digest here so the guarantee is local.
        let fuz_bytes = storage.download(&versioned).await.unwrap();
        let expected_hash = fuz_release::sha512_hex(&fuz_bytes);
        let sidecar_bytes = storage
            .download(&format!("{versioned}.sha512"))
            .await
            .unwrap();
        let sidecar = String::from_utf8(sidecar_bytes).unwrap();
        assert_eq!(sidecar, format!("{expected_hash}  {versioned}\n"));

        // latest copy points at the same bytes
        let latest_bytes = storage.download(&latest).await.unwrap();
        assert_eq!(fuz_bytes, latest_bytes);

        // Cross-layout agreement, the point of publishing from one verified read:
        // the flat-layout bytes are the byte string the *signed manifest* pins,
        // and the same ones inside the tarball. `install.sh` never parses the
        // manifest, so if these could diverge it would install the unsigned side.
        assert_eq!(
            ContentHash::blake3(&fuz_bytes),
            manifest.binaries["fuz"],
            "flat-layout binary must be the manifest-pinned byte string"
        );
        assert_eq!(
            fuz_bytes,
            fs::read(extract_dir.path().join("fuz")).unwrap(),
            "flat-layout binary must be the tarball's binary"
        );
    }

    #[tokio::test]
    async fn publish_with_minimum_version() {
        let artifact_dir = tempfile::tempdir().unwrap();
        let storage_dir = tempfile::tempdir().unwrap();

        let meta = create_test_artifact(artifact_dir.path(), "0.3.0");
        let storage = FileStorage::new(storage_dir.path()).unwrap();
        let key = test_key();

        let options = PublishOptions {
            minimum_version: Some("0.2.0".to_string()),
            ..PublishOptions::default()
        };

        let result = publish_artifact(&storage, &meta, artifact_dir.path(), &key, &options)
            .await
            .unwrap();

        // Verify minimum_version in manifest
        let manifest_bytes = storage.download(&result.manifest_path).await.unwrap();
        let manifest = Manifest::from_json(&manifest_bytes).unwrap();
        assert_eq!(manifest.minimum_version, Some("0.2.0".to_string()));
    }

    #[tokio::test]
    async fn create_tarball_detects_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let meta = create_test_artifact(dir.path(), "0.1.0");

        // Corrupt the binary
        fs::write(dir.path().join("fuz"), b"corrupted content").unwrap();

        let dest = dir.path().join("out.tar.gz");
        let result = create_tarball_file(dir.path(), &meta, &dest).await;
        assert!(matches!(
            result,
            Err(ReleaseError::Tarball(
                TarballError::BinaryHashMismatch { .. }
            ))
        ));
    }

    //
    // The scratch tarball
    //

    /// What a [`Flaky`] store does wrong.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Fault {
        /// Nothing: a store that works.
        None,
        /// The streamed tarball upload fails.
        TarballUpload,
        /// The manifest upload fails, after the tarball's succeeded.
        ManifestUpload,
        /// Every upload succeeds and nothing is there afterwards.
        Unconfirmed,
    }

    /// What a streamed upload was handed: the file, and what was at it.
    #[derive(Debug)]
    struct Staged {
        path: PathBuf,
        is_file: bool,
        dir_mode: u32,
    }

    /// A local store with one fault, recording the file each streamed upload
    /// read from.
    struct Flaky {
        inner: FileStorage,
        fault: Fault,
        staged: std::sync::Mutex<Vec<Staged>>,
    }

    impl Flaky {
        fn new(root: &Path, fault: Fault) -> Self {
            Self {
                inner: FileStorage::new(root).unwrap(),
                fault,
                staged: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn refused(path: &str) -> StorageError {
            StorageError::UploadFailed {
                backend: StorageBackendKind::File,
                message: format!("refused {path}"),
            }
        }
    }

    impl Storage for Flaky {
        fn backend_kind(&self) -> StorageBackendKind {
            self.inner.backend_kind()
        }
        async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
            if self.fault == Fault::ManifestUpload && path.ends_with(".manifest.json") {
                return Err(Self::refused(path));
            }
            self.inner.upload(path, data).await
        }
        async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.download(path).await
        }
        async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
            self.inner.download_capped(path, max).await
        }
        async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
            self.inner.download_to_file(path, dest).await
        }
        async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(src.parent().unwrap())
                .map_or(0, |meta| meta.permissions().mode() & 0o777);
            self.staged.lock().unwrap().push(Staged {
                path: src.to_path_buf(),
                is_file: src.is_file(),
                dir_mode,
            });
            if self.fault == Fault::TarballUpload {
                return Err(Self::refused(path));
            }
            self.inner.upload_file(path, src).await
        }
        async fn exists(&self, path: &str) -> Result<bool, StorageError> {
            if self.fault == Fault::Unconfirmed {
                return Ok(false);
            }
            self.inner.exists(path).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
            self.inner.list(prefix).await
        }
        async fn delete(&self, path: &str) -> Result<(), StorageError> {
            self.inner.delete(path).await
        }
    }

    /// The two publish flows, each run with its scratch directory under a
    /// root the test owns.
    #[derive(Debug, Clone, Copy)]
    enum Flow {
        SelfArtifact,
        Tool,
    }

    /// One publish's world: the inputs, the store's root, and the scratch
    /// root — the directory whose contents are the claim under test.
    struct ScratchCase {
        tmp: tempfile::TempDir,
        scratch_root: PathBuf,
    }

    impl ScratchCase {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let scratch_root = tmp.path().join("scratch-root");
            fs::create_dir(&scratch_root).unwrap();
            fs::create_dir(tmp.path().join("artifact")).unwrap();
            Self { tmp, scratch_root }
        }

        fn store(&self, fault: Fault) -> Flaky {
            Flaky::new(&self.tmp.path().join("store"), fault)
        }

        async fn publish(
            &self,
            flow: Flow,
            storage: &Flaky,
            options: &PublishOptions,
        ) -> Result<PublishResult, ReleaseError> {
            let key = test_key();
            match flow {
                Flow::SelfArtifact => {
                    let artifact_dir = self.tmp.path().join("artifact");
                    let meta = create_test_artifact(&artifact_dir, "0.1.0");
                    publish_artifact_in(
                        storage,
                        &meta,
                        &artifact_dir,
                        &key,
                        options,
                        &self.scratch_root,
                    )
                    .await
                }
                Flow::Tool => {
                    let binary = self.tmp.path().join("fuzd-build");
                    fs::write(
                        &binary,
                        test_stubs::host(b"fuzd binary content for testing"),
                    )
                    .unwrap();
                    crate::tool::publish_tool_in(
                        storage,
                        "fuzd",
                        "0.1.0",
                        &[("fuzd".to_string(), binary)],
                        &key,
                        options,
                        &self.scratch_root,
                    )
                    .await
                }
            }
        }

        /// The names left in the scratch root.
        fn left_behind(&self) -> Vec<String> {
            fs::read_dir(&self.scratch_root)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        }
    }

    #[track_caller]
    fn assert_nothing_left(case: &ScratchCase, context: &str) {
        let left = case.left_behind();
        assert!(left.is_empty(), "{context}: left behind {left:?}");
    }

    /// The tarball a publish uploads is staged in a directory of its own under
    /// the scratch root, private to its owner — the upload's own view of it.
    fn assert_staged_under(case: &ScratchCase, storage: &Flaky, context: &str) {
        let staged = storage.staged.lock().unwrap();
        let [staged] = staged.as_slice() else {
            panic!("{context}: expected one streamed upload, got {staged:?}");
        };
        let dir = staged.path.parent().unwrap();
        assert_eq!(
            dir.parent().unwrap(),
            case.scratch_root,
            "{context}: {staged:?}"
        );
        assert!(
            dir.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("fuz-publish-"),
            "{context}: {staged:?}"
        );
        assert!(staged.is_file, "{context}: {staged:?}");
        assert_eq!(staged.dir_mode, 0o700, "{context}: {staged:?}");
    }

    /// A publish that succeeds leaves nothing in its scratch root.
    #[tokio::test]
    async fn a_publish_leaves_no_scratch_tarball() {
        for flow in [Flow::SelfArtifact, Flow::Tool] {
            let case = ScratchCase::new();
            let storage = case.store(Fault::None);
            let published = case
                .publish(flow, &storage, &PublishOptions::default())
                .await
                .unwrap();
            assert!(storage.inner.exists(&published.tarball_path).await.unwrap());
            assert_staged_under(&case, &storage, &format!("{flow:?}"));
            assert_nothing_left(&case, &format!("{flow:?}"));
        }
    }

    /// A publish whose upload fails — the tarball's, or the manifest's after it
    /// — leaves nothing in its scratch root either, and neither does one whose
    /// upload cannot be confirmed afterwards.
    #[tokio::test]
    async fn a_failed_upload_leaves_no_scratch_tarball() {
        for flow in [Flow::SelfArtifact, Flow::Tool] {
            for fault in [
                Fault::TarballUpload,
                Fault::ManifestUpload,
                Fault::Unconfirmed,
            ] {
                let context = format!("{flow:?} {fault:?}");
                let case = ScratchCase::new();
                let storage = case.store(fault);
                let error = case
                    .publish(flow, &storage, &PublishOptions::default())
                    .await
                    .unwrap_err();
                assert!(
                    matches!(
                        error,
                        ReleaseError::Storage(StorageError::UploadFailed { .. })
                    ),
                    "{context}: {error:?}"
                );
                // The tarball was packed and handed to the upload: there was
                // something to leave.
                assert_staged_under(&case, &storage, &context);
                assert_nothing_left(&case, &context);
            }
        }
    }

    /// The public entry points stage under the system temp directory, and
    /// leave nothing there.
    #[tokio::test]
    async fn the_public_entry_points_stage_under_the_system_temp_directory() {
        let case = ScratchCase::new();
        let key = test_key();
        let options = PublishOptions::default();

        let self_store = Flaky::new(&case.tmp.path().join("self-store"), Fault::TarballUpload);
        let artifact_dir = case.tmp.path().join("artifact");
        let meta = create_test_artifact(&artifact_dir, "0.1.0");
        publish_artifact(&self_store, &meta, &artifact_dir, &key, &options)
            .await
            .unwrap_err();

        let tool_store = Flaky::new(&case.tmp.path().join("tool-store"), Fault::TarballUpload);
        let binary = case.tmp.path().join("fuzd-build");
        fs::write(
            &binary,
            test_stubs::host(b"fuzd binary content for testing"),
        )
        .unwrap();
        crate::tool::publish_tool(
            &tool_store,
            "fuzd",
            "0.1.0",
            &[("fuzd".to_string(), binary)],
            &key,
            &options,
        )
        .await
        .unwrap_err();

        for (flow, store) in [("self", &self_store), ("tool", &tool_store)] {
            let staged = store.staged.lock().unwrap();
            let [staged] = staged.as_slice() else {
                panic!("{flow}: expected one streamed upload, got {staged:?}");
            };
            let dir = staged.path.parent().unwrap();
            assert_eq!(
                dir.parent().unwrap(),
                std::env::temp_dir(),
                "{flow}: {staged:?}"
            );
            assert_eq!(staged.dir_mode, 0o700, "{flow}: {staged:?}");
            assert!(!dir.exists(), "{flow}: {staged:?}");
        }
    }

    /// A publish the release log refuses stops after the tarball is packed and
    /// before anything is uploaded; the packed tarball goes too.
    #[tokio::test]
    async fn a_publish_the_log_refuses_leaves_no_scratch_tarball() {
        for flow in [Flow::SelfArtifact, Flow::Tool] {
            let case = ScratchCase::new();
            let storage = case.store(Fault::None);
            let options = PublishOptions {
                log_repo: Some(LogRepo::new(case.tmp.path().join("not-a-checkout"))),
                ..PublishOptions::default()
            };
            let error = case.publish(flow, &storage, &options).await.unwrap_err();
            assert!(
                matches!(error, ReleaseError::LogWrite(_)),
                "{flow:?}: {error:?}"
            );
            assert!(storage.staged.lock().unwrap().is_empty(), "{flow:?}");
            assert!(!case.tmp.path().join("store").exists(), "{flow:?}");
            assert_nothing_left(&case, &format!("{flow:?}"));
        }
    }

    /// A self artifact whose `fuz` is not the binary its metadata pins fails
    /// while packing, with the scratch directory already made; it goes too.
    #[tokio::test]
    async fn a_failed_pack_leaves_no_scratch_directory() {
        let case = ScratchCase::new();
        let storage = case.store(Fault::None);
        let artifact_dir = case.tmp.path().join("artifact");
        let meta = create_test_artifact(&artifact_dir, "0.1.0");
        fs::write(artifact_dir.join("fuz"), b"not the pinned binary").unwrap();

        let error = publish_artifact_in(
            &storage,
            &meta,
            &artifact_dir,
            &test_key(),
            &PublishOptions::default(),
            &case.scratch_root,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                error,
                ReleaseError::Tarball(TarballError::BinaryHashMismatch { .. })
            ),
            "{error:?}"
        );
        assert_nothing_left(&case, "a failed pack");
    }

    /// A scratch root that is not there is the publish's error, before anything
    /// is packed or uploaded, and the error names the directory that could not
    /// be made.
    #[tokio::test]
    async fn a_scratch_root_that_is_not_there_fails_the_publish() {
        for flow in [Flow::SelfArtifact, Flow::Tool] {
            let mut case = ScratchCase::new();
            case.scratch_root = case.tmp.path().join("absent");
            let storage = case.store(Fault::None);
            let error = case
                .publish(flow, &storage, &PublishOptions::default())
                .await
                .unwrap_err();
            assert!(
                matches!(
                    &error,
                    ReleaseError::Tarball(TarballError::Io(source))
                        if source.kind() == std::io::ErrorKind::NotFound
                ),
                "{flow:?}: {error:?}"
            );
            let message = error.to_string();
            let named = format!(
                "tarball error: I/O error: failed to create scratch directory {}/fuz-publish-",
                case.scratch_root.display()
            );
            assert!(message.starts_with(&named), "{flow:?}: {message}");
            assert!(
                message.ends_with(": No such file or directory (os error 2)"),
                "{flow:?}: {message}"
            );
            assert!(!case.scratch_root.exists(), "{flow:?}");
            assert!(!case.tmp.path().join("store").exists(), "{flow:?}");
        }
    }
}
