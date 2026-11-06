//! Per-tool publish: sign + upload a first-party tool artifact.
//!
//! The producer half of `fuz_release`'s per-tool model. A tool is a named,
//! signed, one-or-more-binary bundle stored under `tools/<name>/` on the
//! forge. The consumer half (`fetch_tool_manifest` / `install_tool` /
//! `verify_installed_tool` / `list_installed_tools`) lives in
//! `fuz_release::tool` — `fuz` installs + verifies; only producers
//! (`fuzf` / `xtask`) publish.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use fuz_artifact::tools::is_first_party_tool;
use fuz_artifact::{content_hash_from_binaries, is_release_token};
use fuz_crypto::ContentHash;

use fuz_release::{
    BinaryHashes, MANIFEST_FORMAT_VERSION, ManifestError, ManifestUnsigned, ReleaseError,
    ReleaseLayout, TarballInfo, TargetRow, check_no_self_binaries, check_no_test_binaries,
    pack_tarball_to_file,
};
use fuz_storage::{Storage, StorageBackendKind, StorageError};

use crate::publish::{
    PublishOptions, PublishResult, PublishScratch, check_log, check_publish_binary,
    check_release_keys, check_release_versions, confirm_uploaded, log_release,
    resolve_publish_target, set_latest, sign_and_upload,
};
use crate::release_log::LogEntry;

/// Publish a tool artifact (one-or-more binaries) under `tools/<name>/`.
///
/// `binaries` maps each binary's in-tarball name to its source path. Refuses
/// names outside the first-party allowlist, a binary name that is not a
/// release token (`fuz_artifact::is_release_token`), any `testing_*` binary,
/// and — up front, before a binary is read — a read-only store, a version that
/// cannot be part of a storage key, and a version or `minimum_version` that is
/// not semver. Then every binary, as the bytes read to be signed, is held to
/// the release's target (`options.target`, else the publishing binary's own),
/// before anything is packed, logged, signed, or uploaded.
///
/// # Errors
///
/// Returns [`ReleaseError`] if the name is not first-party, `binaries` is
/// empty, names a binary that is not a release token, or names a binary of the
/// fuz self artifact, the store is read-only, the version cannot be part of a
/// storage key, the version or `minimum_version` is not semver, a binary is a
/// test binary, a binary is not an executable for the release's target
/// ([`fuz_artifact::ArtifactError::BinaryPlatform`] /
/// [`fuz_artifact::ArtifactError::BinaryUnreadable`], naming it), or
/// reading/signing/upload fails.
pub async fn publish_tool(
    storage: &impl Storage,
    name: &str,
    version: &str,
    binaries: &[(String, PathBuf)],
    key: &SigningKey,
    options: &PublishOptions,
) -> Result<PublishResult, ReleaseError> {
    publish_tool_in(
        storage,
        name,
        version,
        binaries,
        key,
        options,
        &std::env::temp_dir(),
    )
    .await
}

/// [`publish_tool`] with the directory its scratch directory is created under
/// named: the system temp directory for a publish.
pub(crate) async fn publish_tool_in(
    storage: &impl Storage,
    name: &str,
    version: &str,
    binaries: &[(String, PathBuf)],
    key: &SigningKey,
    options: &PublishOptions,
    scratch_root: &Path,
) -> Result<PublishResult, ReleaseError> {
    if !is_first_party_tool(name) {
        return Err(ManifestError::ToolNotAllowed(name.to_string()).into());
    }
    if binaries.is_empty() {
        return Err(ManifestError::EmptyBinaries(name.to_string()).into());
    }
    // Refused by every client at the manifest, so refused here before
    // anything is read, signed, or uploaded.
    if let Some((bin, _)) = binaries.iter().find(|(bin, _)| !is_release_token(bin)) {
        return Err(ManifestError::InvalidBinaryName(bin.clone()).into());
    }
    check_no_self_binaries(name, binaries.iter().map(|(bin, _)| bin.as_str()))?;

    let (release_target, explicit) = resolve_publish_target(options)?;
    let target = release_target.triple();
    let layout = ReleaseLayout::tool(name);

    // Refuse what could only fail at the first upload, before anything is
    // read, packed, signed, or logged: a store with no upload, and a version
    // no store could hold (it becomes part of every key below).
    storage.require_writable("upload")?;
    check_release_keys(&layout, name, version, target, false)?;
    check_release_versions(version, options.minimum_version.as_deref())?;

    // Read + hash each binary.
    let mut hashes: BTreeMap<String, ContentHash> = BTreeMap::new();
    let mut contents: Vec<(String, Vec<u8>)> = Vec::with_capacity(binaries.len());
    for (bin_name, path) in binaries {
        let bytes = tokio::fs::read(path).await.map_err(|e| {
            StorageError::Io(
                StorageBackendKind::File,
                std::io::Error::other(format!("failed to read {bin_name}: {e}")),
            )
        })?;
        hashes.insert(bin_name.clone(), ContentHash::blake3(&bytes));
        contents.push((bin_name.clone(), bytes));
    }
    check_no_test_binaries(hashes.keys().map(String::as_str))?;
    // Every binary, as the bytes about to be packed and signed, against the
    // one target the release is labelled with.
    for (bin_name, bytes) in &contents {
        check_publish_binary(bin_name, bytes, release_target, explicit)?;
    }

    let content_hash = content_hash_from_binaries(&hashes);
    let tarball_name = ReleaseLayout::tarball_filename(name, version, target);
    // Pack to a scratch file (streamed + hashed in one pass), never the whole
    // `.tar.gz` in memory. The scratch directory goes when `scratch` does: on
    // return, by any path.
    let scratch = PublishScratch::new_in(scratch_root)?;
    let digest = pack_tarball_to_file(&contents, &scratch.tarball)?;

    let binary_hashes: BinaryHashes = hashes.clone().into_iter().collect();
    let unsigned = ManifestUnsigned {
        format: MANIFEST_FORMAT_VERSION,
        version: version.to_string(),
        content_hash: content_hash.clone(),
        target: target.to_string(),
        minimum_version: options.minimum_version.clone(),
        tarball: TarballInfo {
            path: tarball_name.clone(),
            blake3: digest.blake3,
            size: digest.size,
        },
        binaries: binary_hashes,
        tool: Some(name.to_string()),
    };
    // One timestamp serves the manifest's signature and the log entry. A tool
    // publishes no flat binary: its row has no `sha512` and no `latest/`
    // pointer in the log.
    let signed_at = fuz_sys::rfc3339_now();
    let entry = LogEntry {
        name: name.to_string(),
        version: version.to_string(),
        target: target.to_string(),
        pins: TargetRow {
            content_hash: content_hash.clone(),
            binaries: hashes,
            sha512: None,
        },
        flat_latest: false,
    };
    // Before anything is uploaded, check that the release log can take this
    // release; a log that would refuse it — one with no head while storage
    // holds other releases included — stops the publish with storage
    // untouched.
    check_log(storage, options, &entry, key, &signed_at).await?;
    // Sign + upload the (streamed) tarball and manifest and confirm they
    // landed, record the release in the log (repeating the checks above, so a
    // log that changed in between is still caught), then publish the per-tool
    // latest pointer for its target — the shared self/tool upload protocol.
    let tarball_key = layout.tarball_key(&tarball_name);
    let manifest_key = layout.manifest_key(name, version, target);
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
    confirm_uploaded(storage, &tarball_key, &manifest_key).await?;
    let logged = log_release(storage, options, &entry, key, &signed_at).await?;
    set_latest(storage, &layout, version, target).await?;

    Ok(PublishResult {
        version: version.to_string(),
        content_hash,
        manifest_path: manifest_key,
        tarball_path: tarball_key,
        target: release_target,
        logged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_artifact::ArtifactError;
    use fuz_artifact::platform::{Libc, PlatformMismatch, ReleaseTarget, test_stubs};
    use fuz_release::{
        LatestInfo, Manifest, extract_tarball, verify_binary_hashes, verify_content_hash,
        verify_tarball_hash,
    };
    use fuz_storage::FileStorage;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0u8; 32])
    }

    /// Publish a single-binary tool, then re-read the manifest and extract +
    /// verify the tarball. Covers the storage-prefix layout, the `tool` field
    /// round trip, and tarball/binary/content-hash verification. Signature
    /// verification (and the `~/.fuz` writes in `install_tool`) need,
    /// respectively, a trusted key and `FUZ_HOME` — both exercised end to end in
    /// `tests/signed_trust.rs` (`publish_then_install_tool_end_to_end`).
    #[tokio::test]
    async fn publish_then_fetch_and_verify_tool() {
        let bin_dir = tempfile::tempdir().unwrap();
        let storage_dir = tempfile::tempdir().unwrap();

        let bin_path = bin_dir.path().join("fuzf");
        std::fs::write(
            &bin_path,
            test_stubs::host(b"fuzf binary content for testing"),
        )
        .unwrap();

        let storage = FileStorage::new(storage_dir.path()).unwrap();
        let key = test_key();

        let published = publish_tool(
            &storage,
            "fuzf",
            "0.1.0",
            &[("fuzf".to_string(), bin_path.clone())],
            &key,
            &PublishOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(published.version, "0.1.0");

        // Stored under the tools/<name>/ prefix.
        assert!(storage.exists(&published.manifest_path).await.unwrap());
        assert!(storage.exists(&published.tarball_path).await.unwrap());
        let latest_key = ReleaseLayout::tool("fuzf").latest_key(fuz_release::current_target());
        assert!(storage.exists(&latest_key).await.unwrap());
        assert_eq!(published.target.triple(), fuz_release::current_target());
        assert!(published.manifest_path.starts_with("tools/fuzf/"));

        // Re-read latest + manifest from storage (skipping signature verify,
        // which needs a trusted key — see test doc), confirm the tool field.
        let latest_bytes = storage.download(&latest_key).await.unwrap();
        let latest: LatestInfo = serde_json::from_slice(&latest_bytes).unwrap();
        assert_eq!(latest.version, "0.1.0");
        let manifest_bytes = storage.download(&published.manifest_path).await.unwrap();
        let manifest = Manifest::from_json(&manifest_bytes).unwrap();
        assert_eq!(manifest.tool.as_deref(), Some("fuzf"));
        assert_eq!(manifest.version, "0.1.0");

        // Download + extract + verify the tarball end-to-end.
        let tarball = storage
            .download(&ReleaseLayout::tool("fuzf").tarball_key(&manifest.tarball.path))
            .await
            .unwrap();
        verify_tarball_hash(&tarball, &manifest.tarball.blake3).unwrap();

        let extract_dir = tempfile::tempdir().unwrap();
        let extracted = extract_tarball(&tarball, &manifest, extract_dir.path()).unwrap();
        verify_binary_hashes(&extracted, &manifest).unwrap();
        verify_content_hash(&extracted, &manifest.content_hash).unwrap();
    }

    /// A read-only store has nothing to upload to: the publish refuses it
    /// with the error its `upload` would give, before any work — before a
    /// binary is read (the path given does not exist), the release log is
    /// consulted (the checkout given is not one), or a scratch directory is
    /// made.
    #[tokio::test]
    async fn publish_tool_refuses_a_read_only_store_before_any_work() {
        let scratch = tempfile::tempdir().unwrap();
        let storage = fuz_storage::HttpsStorage::new("https://releases.example.com/fuz").unwrap();
        let scratch_root = scratch.path().join("tmp");
        std::fs::create_dir(&scratch_root).unwrap();
        let not_a_checkout = scratch.path().join("log");
        let options = PublishOptions {
            log_repo: Some(crate::LogRepo::new(&not_a_checkout)),
            ..PublishOptions::default()
        };

        let err = publish_tool_in(
            &storage,
            "fuzf",
            "0.0.1",
            &[("fuzf".to_string(), scratch.path().join("no-such-binary"))],
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
            err.hint().map(|hint| hint.to_string()).as_deref(),
            Some("Use a writable backend: a local path, forge://, or ssh://")
        );
        assert_eq!(std::fs::read_dir(&scratch_root).unwrap().count(), 0);
        assert!(!not_a_checkout.exists(), "the log checkout was touched");
    }

    /// A version or `minimum_version` that is not semver is refused before
    /// any work: before a binary is read (the path given does not exist), a
    /// scratch directory is made, the release log is consulted (the checkout
    /// given is not one), or storage is written. Every later upgrade or prune
    /// of the stream would fail on it.
    #[tokio::test]
    async fn publish_tool_refuses_a_non_semver_version_or_floor_before_any_work() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("store");
        let storage = FileStorage::new(&root).unwrap();
        let scratch_root = scratch.path().join("tmp");
        std::fs::create_dir(&scratch_root).unwrap();
        let not_a_checkout = scratch.path().join("log");
        for (version, minimum, field) in [
            ("1.0", None, "version"),
            ("1.0.0", Some("banana"), "minimum_version"),
        ] {
            let options = PublishOptions {
                minimum_version: minimum.map(String::from),
                log_repo: Some(crate::LogRepo::new(&not_a_checkout)),
                target: None,
            };
            let err = publish_tool_in(
                &storage,
                "fuzf",
                version,
                &[("fuzf".to_string(), scratch.path().join("no-such-binary"))],
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
            assert_eq!(
                std::fs::read_dir(&scratch_root).unwrap().count(),
                0,
                "{field}"
            );
            assert!(
                !not_a_checkout.exists(),
                "{field}: the log checkout was touched"
            );
        }
    }

    /// A version no store could hold (semver build metadata: `+` is outside
    /// the key contract) is refused before any work: before a binary is read
    /// (the path given does not exist), before the release log is consulted
    /// (the checkout given is not one), and before anything is written to
    /// storage. A pre-release version publishes.
    #[tokio::test]
    async fn publish_tool_refuses_a_version_no_store_could_hold_before_any_work() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("store");
        let storage = FileStorage::new(&root).unwrap();
        let not_a_checkout = scratch.path().join("log");
        let options = PublishOptions {
            log_repo: Some(crate::LogRepo::new(&not_a_checkout)),
            ..PublishOptions::default()
        };
        let no_such_binary = scratch.path().join("no-such-binary");

        let err = publish_tool(
            &storage,
            "fuzf",
            "0.0.1+b1",
            &[("fuzf".to_string(), no_such_binary)],
            &test_key(),
            &options,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &err,
                ReleaseError::Manifest(ManifestError::UnpublishableField {
                    field: "version",
                    value,
                    ..
                }) if value == "0.0.1+b1"
            ),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "manifest error: release version cannot be part of a storage key: \"0.0.1+b1\" \
             (key contains invalid characters (allowed: a-z, A-Z, 0-9, '-', '.', '_', '/'))"
        );
        assert!(!root.exists(), "storage was written to");
        assert!(!not_a_checkout.exists(), "the log checkout was touched");

        // With a binary that reads and packs, it is still the version that is
        // refused, not the log checkout the publish would go on to.
        let bin_path = scratch.path().join("fuzf");
        std::fs::write(&bin_path, test_stubs::host(b"fuzf binary")).unwrap();
        let err = publish_tool(
            &storage,
            "fuzf",
            "0.0.1+b1",
            &[("fuzf".to_string(), bin_path.clone())],
            &test_key(),
            &options,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                ReleaseError::Manifest(ManifestError::UnpublishableField { .. })
            ),
            "{err:?}"
        );
        assert!(!root.exists(), "storage was written to");
        let published = publish_tool(
            &storage,
            "fuzf",
            "0.0.2-rc.1",
            &[("fuzf".to_string(), bin_path)],
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(published.version, "0.0.2-rc.1");
        assert!(storage.exists(&published.manifest_path).await.unwrap());
    }

    /// The target other than the host's on the same architecture's other
    /// libc, or on the other architecture for a darwin host.
    fn foreign_target() -> ReleaseTarget {
        let host = test_stubs::host_target();
        match host.libc() {
            Some(Libc::Gnu) => ReleaseTarget::linux(host.arch(), Libc::Musl),
            Some(Libc::Musl) | None => ReleaseTarget::linux(host.arch(), Libc::Gnu),
        }
    }

    /// `--target` labels the release: a binary built for another target
    /// publishes under that target's keys and latest pointer, and nothing
    /// lands under the host's.
    #[tokio::test]
    async fn publish_tool_with_an_explicit_target_lands_under_it() {
        let scratch = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(scratch.path()).unwrap();
        let other = foreign_target();
        let bin_path = scratch.path().join("fuzf.bin");
        std::fs::write(&bin_path, test_stubs::for_target(other, b"fuzf")).unwrap();
        let layout = ReleaseLayout::tool("fuzf");

        let published = publish_tool(
            &storage,
            "fuzf",
            "0.1.0",
            &[("fuzf".to_string(), bin_path)],
            &test_key(),
            &PublishOptions {
                target: Some(other),
                ..PublishOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(published.target, other);
        assert_eq!(
            published.manifest_path,
            layout.manifest_key("fuzf", "0.1.0", other.triple())
        );
        assert_eq!(
            published.tarball_path,
            layout.tarball_key(&ReleaseLayout::tarball_filename(
                "fuzf",
                "0.1.0",
                other.triple()
            ))
        );
        let manifest =
            Manifest::from_json(&storage.download(&published.manifest_path).await.unwrap())
                .unwrap();
        assert_eq!(manifest.target, other.triple());
        assert!(
            storage
                .exists(&layout.latest_key(other.triple()))
                .await
                .unwrap()
        );
        assert!(
            !storage
                .exists(&layout.latest_key(fuz_release::current_target()))
                .await
                .unwrap()
        );
    }

    /// A binary that contradicts the target — the host's, defaulted, or one
    /// named — is refused naming the binary, with every other binary of the
    /// bundle fine; storage, the scratch root, and the log checkout are
    /// untouched. A bundle whose binaries disagree with each other is refused
    /// the same way: every binary is held to the one target.
    #[tokio::test]
    async fn publish_tool_refuses_a_binary_not_for_the_target_naming_it() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("store");
        let storage = FileStorage::new(&root).unwrap();
        let scratch_root = scratch.path().join("tmp");
        std::fs::create_dir(&scratch_root).unwrap();
        let not_a_checkout = scratch.path().join("log");
        let host = test_stubs::host_target();
        let other = foreign_target();
        let good = scratch.path().join("good");
        std::fs::write(&good, test_stubs::host(b"good")).unwrap();
        let bad = scratch.path().join("bad");
        std::fs::write(&bad, test_stubs::for_target(other, b"bad")).unwrap();
        let text = scratch.path().join("text");
        std::fs::write(&text, b"binary content").unwrap();

        for (target, bins, refused) in [
            // defaulted: the host's target, one binary for another
            (None, vec![("fuzd", &good), ("fuzf", &bad)], "fuzf"),
            // named: the foreign target, the bundle disagreeing with itself
            (Some(other), vec![("fuzd", &good), ("fuzf", &bad)], "fuzd"),
            // no executable at all
            (None, vec![("fuzf", &text)], "fuzf"),
        ] {
            let options = PublishOptions {
                log_repo: Some(crate::LogRepo::new(&not_a_checkout)),
                target,
                ..PublishOptions::default()
            };
            let binaries: Vec<(String, PathBuf)> = bins
                .iter()
                .map(|(name, path)| ((*name).to_string(), (*path).clone()))
                .collect();
            let err = publish_tool_in(
                &storage,
                "fuzf",
                "0.1.0",
                &binaries,
                &test_key(),
                &options,
                &scratch_root,
            )
            .await
            .unwrap_err();
            let named = match &err {
                ReleaseError::Artifact(ArtifactError::BinaryPlatform {
                    name, target: t, ..
                }) => {
                    assert_eq!(*t, target.unwrap_or(host), "{err}");
                    name
                }
                ReleaseError::Artifact(ArtifactError::BinaryUnreadable { name, .. }) => name,
                other => panic!("{other:?}"),
            };
            assert_eq!(named, refused, "{err}");
            assert!(err.to_string().contains(&format!("\"{refused}\"")), "{err}");
            assert!(!err.is_security_violation());
            assert!(!root.exists(), "storage was written to");
            assert_eq!(std::fs::read_dir(&scratch_root).unwrap().count(), 0);
            assert!(!not_a_checkout.exists(), "the log checkout was touched");
        }
    }

    /// A statically linked binary is refused on a glibc host when no target
    /// is named — it is most likely a musl build — with a hint naming both
    /// `--target`s; named, it publishes under either libc.
    #[tokio::test]
    async fn publish_tool_of_a_static_binary_needs_a_named_target_on_glibc() {
        let host = test_stubs::host_target();
        if host.libc() != Some(Libc::Gnu) {
            return;
        }
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().join("store");
        let storage = FileStorage::new(&root).unwrap();
        let bin_path = scratch.path().join("fuzf");
        std::fs::write(
            &bin_path,
            test_stubs::ElfStub::static_pie(host.arch()).build(b""),
        )
        .unwrap();
        let binaries = [("fuzf".to_string(), bin_path)];

        let err = publish_tool(
            &storage,
            "fuzf",
            "0.1.0",
            &binaries,
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &err,
                ReleaseError::Artifact(ArtifactError::BinaryPlatform {
                    mismatch: PlatformMismatch::StaticUnconfirmed,
                    ..
                })
            ),
            "{err:?}"
        );
        let musl = ReleaseTarget::linux(host.arch(), Libc::Musl);
        assert_eq!(
            err.hint().unwrap().to_string(),
            format!("pass --target {musl}, or --target {host} for a static glibc build")
        );
        assert!(!root.exists(), "storage was written to");

        for target in [musl, host] {
            let published = publish_tool(
                &storage,
                "fuzf",
                "0.1.0",
                &binaries,
                &test_key(),
                &PublishOptions {
                    target: Some(target),
                    ..PublishOptions::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(published.target, target);
        }
    }

    /// Publishing one target never moves another's latest pointer.
    #[tokio::test]
    async fn per_target_latest_pointers_move_independently() {
        let scratch = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(scratch.path()).unwrap();
        let layout = ReleaseLayout::tool("fuzf");
        let host = test_stubs::host_target();
        let other = foreign_target();
        let latest = |target: ReleaseTarget| {
            let storage = &storage;
            let key = layout.latest_key(target.triple());
            async move {
                let bytes = storage.download(&key).await.unwrap();
                serde_json::from_slice::<LatestInfo>(&bytes)
                    .unwrap()
                    .version
            }
        };
        let publish = |version: &'static str, target: ReleaseTarget| {
            let storage = &storage;
            let bin_path = scratch.path().join(format!("fuzf-{version}-{target}"));
            async move {
                std::fs::write(
                    &bin_path,
                    test_stubs::for_target(target, version.as_bytes()),
                )
                .unwrap();
                publish_tool(
                    storage,
                    "fuzf",
                    version,
                    &[("fuzf".to_string(), bin_path)],
                    &test_key(),
                    &PublishOptions {
                        target: Some(target),
                        ..PublishOptions::default()
                    },
                )
                .await
                .unwrap()
            }
        };

        publish("0.1.0", host).await;
        publish("0.2.0", other).await;
        assert_eq!(
            latest(host).await,
            "0.1.0",
            "A's latest moved with B's publish"
        );
        assert_eq!(latest(other).await, "0.2.0");
        publish("0.3.0", host).await;
        assert_eq!(latest(host).await, "0.3.0");
        assert_eq!(latest(other).await, "0.2.0");
    }

    #[tokio::test]
    async fn publish_tool_rejects_empty_binaries() {
        let storage_dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();

        let err = publish_tool(
            &storage,
            "fuzf",
            "0.1.0",
            &[],
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ReleaseError::Manifest(ManifestError::EmptyBinaries(_))
        ));
    }

    /// A `testing_*` binary in a tool's bill of materials is refused at publish
    /// time — the producer-side defense-in-depth mirror of the manifest-parse
    /// rejection in `fuz_release` (`reject_manifest_declaring_testing_*`). The
    /// tool *name* is allowlisted (`fuzf`), so this reaches `check_no_test_binaries`
    /// over the binary set rather than stopping at the `is_first_party_tool`
    /// gate ahead of it.
    #[tokio::test]
    async fn publish_tool_rejects_test_binary_in_bundle() {
        let bin_dir = tempfile::tempdir().unwrap();
        let storage_dir = tempfile::tempdir().unwrap();
        let bin_path = bin_dir.path().join("testing_helper");
        std::fs::write(&bin_path, test_stubs::host(b"x")).unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();

        let err = publish_tool(
            &storage,
            "fuzf",
            "0.1.0",
            &[("testing_helper".to_string(), bin_path)],
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ReleaseError::Manifest(ManifestError::TestBinaryRejected { .. })
        ));
    }

    /// A tool bundle naming a binary of the fuz self artifact is refused
    /// before anything is signed or uploaded — the producer side of the
    /// manifest-parse refusal in `fuz_release`, so no manifest is published
    /// that every client would refuse.
    #[tokio::test]
    async fn publish_tool_rejects_a_self_binary_in_the_bundle() {
        let bin_dir = tempfile::tempdir().unwrap();
        let storage_dir = tempfile::tempdir().unwrap();
        let fuzf = bin_dir.path().join("fuzf");
        let fuz = bin_dir.path().join("fuz");
        std::fs::write(&fuzf, test_stubs::host(b"x")).unwrap();
        std::fs::write(&fuz, test_stubs::host(b"y")).unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();

        let err = publish_tool(
            &storage,
            "fuzf",
            "0.1.0",
            &[("fuzf".to_string(), fuzf), ("fuz".to_string(), fuz)],
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &err,
                ReleaseError::Manifest(ManifestError::ReservedBinaryName { tool, binary })
                    if tool == "fuzf" && binary == "fuz"
            ),
            "{err:?}"
        );
        assert_eq!(storage.list("").await.unwrap(), [""; 0], "nothing uploaded");

        // In any ASCII case, as the manifest parse refuses it.
        let cased = bin_dir.path().join("FUZ");
        std::fs::write(&cased, test_stubs::host(b"z")).unwrap();
        let err = publish_tool(
            &storage,
            "fuzf",
            "0.1.0",
            &[
                ("fuzf".to_string(), bin_dir.path().join("fuzf")),
                ("FUZ".to_string(), cased),
            ],
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &err,
                ReleaseError::Manifest(ManifestError::ReservedBinaryName { tool, binary })
                    if tool == "fuzf" && binary == "FUZ"
            ),
            "{err:?}"
        );
        assert_eq!(storage.list("").await.unwrap(), [""; 0], "nothing uploaded");
    }

    /// A binary name every client refuses at the manifest (not a release
    /// token) is refused before anything is read or uploaded.
    #[tokio::test]
    async fn publish_tool_rejects_a_binary_name_that_is_not_a_token() {
        let storage_dir = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();
        for bad in ["a:b", "a\nb", "a b", "-a", "a/b"] {
            // The path does not exist: the name is refused before it is read.
            let err = publish_tool(
                &storage,
                "fuzf",
                "0.1.0",
                &[(bad.to_string(), PathBuf::from("/nonexistent"))],
                &test_key(),
                &PublishOptions::default(),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(
                    &err,
                    ReleaseError::Manifest(ManifestError::InvalidBinaryName(name)) if name == bad
                ),
                "{bad:?}: {err:?}"
            );
        }
        assert_eq!(storage.list("").await.unwrap(), [""; 0], "nothing uploaded");
    }

    #[tokio::test]
    async fn publish_tool_rejects_disallowed_name() {
        let bin_dir = tempfile::tempdir().unwrap();
        let storage_dir = tempfile::tempdir().unwrap();
        let bin_path = bin_dir.path().join("rando");
        std::fs::write(&bin_path, test_stubs::host(b"x")).unwrap();
        let storage = FileStorage::new(storage_dir.path()).unwrap();

        let err = publish_tool(
            &storage,
            "rando",
            "0.1.0",
            &[("rando".to_string(), bin_path)],
            &test_key(),
            &PublishOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            ReleaseError::Manifest(ManifestError::ToolNotAllowed(_))
        ));
    }
}
