//! Remote release pruning (producer-only).
//!
//! Lists a release stream's published manifests, selects the older versions to
//! remove ([`fuz_release::select_prune_releases`] retention), and deletes their
//! manifest + tarball keys. Lives in `fuz_sign` — not the consumer `fuz` graph —
//! because it *mutates* remote storage (`Storage::delete`); `fuz` stays
//! fetch-and-verify only.
//!
//! What it deletes is derived, never read: the manifest key is the one the
//! listing returned, and the tarball key — and, for the self stream, the flat
//! binary and its `.sha512` sidecar — are the ones [`ReleaseLayout`] gives
//! that release. A manifest is read only for its version and target, and
//! checks no signature, so a manifest whose fields do not build its own key
//! back, or whose `tarball.path` is not the tarball the release is stored
//! as, refuses the prune — before anything is deleted — rather than aim a
//! delete at another key (a `latest-<target>.json` pointer, another release's
//! tarball).

use std::collections::HashMap;

use fuz_release::{
    LatestInfo, MAX_MANIFEST_SIZE, ManifestError, ReleaseError, ReleaseLayout, RemoteRelease,
    SELF_NAME, Storage, download_manifest, select_prune_releases,
};

use crate::stream::is_stream_manifest_key;

/// The three manifest fields a prune decides by.
struct PruneFields {
    version: String,
    target: String,
    tarball_path: String,
}

/// Download a manifest and read its [`PruneFields`], size-capped.
///
/// Read leniently, not through `Manifest::from_json`: prune deletes by key and
/// checks no signature, so a release a current `fuz` would refuse — an older
/// self manifest that also declares `fuzd` — must still be prunable. What the
/// fields are trusted for is [`check_prune_fields`]'s to decide.
async fn read_prune_fields(storage: &impl Storage, key: &str) -> Result<PruneFields, ReleaseError> {
    let bytes = download_manifest(storage, key).await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(ManifestError::from)?;
    // A missing field reads as `null`, which the string decode refuses.
    let field = |pointer: &str| {
        let found = value.pointer(pointer).cloned().unwrap_or_default();
        serde_json::from_value::<String>(found).map_err(ManifestError::from)
    };
    Ok(PruneFields {
        version: field("/version")?,
        target: field("/target")?,
        tarball_path: field("/tarball/path")?,
    })
}

/// Hold a manifest's [`PruneFields`] to the key it was listed under, and
/// return the key of its release's tarball.
///
/// The version and target must build `key` back in `layout` for
/// `stream_name`, so the release whose retention is decided is the release at
/// the key that is deleted. The tarball key is then the layout's for that
/// release ([`ReleaseLayout::tarball_filename`]), and `tarball.path` must
/// name that file: it is unsigned here, and a prune deleting what it names
/// would delete whatever key a store wrote there.
///
/// # Errors
///
/// [`ManifestError::KeyMismatch`] or [`ManifestError::TarballMismatch`].
fn check_prune_fields(
    layout: &ReleaseLayout,
    stream_name: &str,
    key: &str,
    fields: &PruneFields,
) -> Result<String, ManifestError> {
    if layout.manifest_key(stream_name, &fields.version, &fields.target) != key {
        return Err(ManifestError::KeyMismatch {
            key: key.to_string(),
            version: fields.version.clone(),
            target: fields.target.clone(),
        });
    }
    let tarball = ReleaseLayout::tarball_filename(stream_name, &fields.version, &fields.target);
    if fields.tarball_path != tarball {
        return Err(ManifestError::TarballMismatch {
            key: key.to_string(),
            expected: tarball,
            actual: fields.tarball_path.clone(),
        });
    }
    Ok(layout.tarball_key(&tarball))
}

/// The keys of a self release's flat binary, as the publish writes them: the
/// `.sha512` sidecar, then the binary (`ReleaseLayout::binary_key`).
///
/// Built from the release's version, which a prune has already held to its
/// manifest key and parsed as semver — so never `latest`, and never the
/// moving `fuz-latest-<target>` copy `install.sh` reads by default.
fn self_flat_keys(layout: &ReleaseLayout, version: &str, target: &str) -> Vec<String> {
    let binary = layout.binary_key(SELF_NAME, version, target);
    vec![format!("{binary}.sha512"), binary]
}

/// A single removed (or, on a dry run, would-be-removed) release artifact.
#[derive(Debug, Clone)]
pub struct PrunedRelease {
    /// The release version.
    pub version: String,
    /// The target triple.
    pub target: String,
    /// The deleted manifest key.
    pub manifest_key: String,
    /// The deleted tarball key.
    pub tarball_key: String,
    /// The deleted flat binary of a self release and its `.sha512` sidecar
    /// (the files `install.sh` downloads), sidecar first; empty for a tool,
    /// which publishes none.
    pub flat_keys: Vec<String>,
}

/// The outcome of a prune sweep over one stream.
#[derive(Debug)]
pub struct PruneReport {
    /// The stream name (`"fuz"` for self, else the tool name).
    pub stream: String,
    /// Distinct versions retained (newest kept + the versions the per-target
    /// `latest-<target>.json` pointers name), for the summary.
    pub kept_versions: Vec<String>,
    /// Releases removed (or, when `dry_run`, that would be removed).
    pub pruned: Vec<PrunedRelease>,
    /// Whether this was a dry run (nothing deleted).
    pub dry_run: bool,
}

/// Prune a release stream to the `keep` most-recent versions.
///
/// Lists `layout`'s manifests, reads each one's `version` / `target` /
/// tarball filename and holds them to its key (`check_prune_fields`),
/// protects the version each of the stream's `latest-<target>.json` pointers
/// names, and (unless `dry_run`)
/// deletes each older release's tarball, then — for the self stream — its
/// flat binary's sidecar and the flat binary, then its manifest (manifest
/// last so a partial failure leaves it discoverable and a re-run completes;
/// `Storage::delete` is idempotent). Every key deleted is derived from the
/// release (`self_flat_keys`); the moving `fuz-latest-<target>` copy and
/// its sidecar are never among them. Every manifest is read and checked before
/// the first delete, so a refusal deletes nothing. Retention is by version,
/// across all targets — keeping `keep` versions keeps every target of those.
///
/// # Errors
///
/// [`ReleaseError`] on a storage failure, an oversized manifest, a manifest
/// that won't parse, or one that does not describe the release at its key
/// ([`ManifestError::KeyMismatch`], [`ManifestError::TarballMismatch`]).
pub async fn prune_stream(
    storage: &impl Storage,
    layout: &ReleaseLayout,
    stream_name: &str,
    keep: usize,
    dry_run: bool,
) -> Result<PruneReport, ReleaseError> {
    let mut releases: Vec<RemoteRelease> = Vec::new();
    // Manifest key → the release's flat-binary keys (self stream only).
    let mut flat_keys: HashMap<String, Vec<String>> = HashMap::new();
    let keys = storage.list(layout.prefix()).await?;
    let pointer_keys: Vec<&String> = keys
        .iter()
        .filter(|key| layout.latest_key_target(key).is_some())
        .collect();
    for key in keys.iter().cloned() {
        if !is_stream_manifest_key(&key, layout, stream_name) {
            continue;
        }
        // The version/target/tarball fields alone — no signature check needed
        // to decide what to delete, since what is deleted is derived from the
        // key they are held to.
        let manifest = read_prune_fields(storage, &key).await?;
        let tarball_key = check_prune_fields(layout, stream_name, &key, &manifest)?;
        let version = semver::Version::parse(&manifest.version)
            .map_err(|_| ManifestError::InvalidVersion(manifest.version.clone()))?;
        if stream_name == SELF_NAME {
            flat_keys.insert(
                key.clone(),
                self_flat_keys(layout, &manifest.version, &manifest.target),
            );
        }
        releases.push(RemoteRelease {
            version,
            target: manifest.target.clone(),
            tarball_key,
            manifest_key: key,
        });
    }

    // Protect the version every per-target pointer names: each target's
    // latest, so pruning for one never strands another's. A garbled pointer
    // protects nothing — the newest `keep` still hold.
    let mut protected: Vec<semver::Version> = Vec::with_capacity(pointer_keys.len());
    for key in pointer_keys {
        let version = storage
            .download_capped(key, MAX_MANIFEST_SIZE)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<LatestInfo>(&bytes).ok())
            .and_then(|l| semver::Version::parse(&l.version).ok());
        protected.extend(version);
    }

    let to_prune = select_prune_releases(&releases, keep, &protected);
    let prune_keys: std::collections::HashSet<&str> =
        to_prune.iter().map(|r| r.manifest_key.as_str()).collect();

    // Kept = distinct versions of the releases not selected for pruning.
    let mut kept_versions: Vec<String> = releases
        .iter()
        .filter(|r| !prune_keys.contains(r.manifest_key.as_str()))
        .map(|r| r.version.to_string())
        .collect();
    kept_versions.sort();
    kept_versions.dedup();

    let mut pruned = Vec::with_capacity(to_prune.len());
    for r in to_prune {
        let flat = flat_keys.remove(&r.manifest_key).unwrap_or_default();
        if !dry_run {
            storage.delete(&r.tarball_key).await?;
            for key in &flat {
                storage.delete(key).await?;
            }
            storage.delete(&r.manifest_key).await?;
        }
        pruned.push(PrunedRelease {
            version: r.version.to_string(),
            target: r.target.clone(),
            manifest_key: r.manifest_key.clone(),
            tarball_key: r.tarball_key.clone(),
            flat_keys: flat,
        });
    }

    Ok(PruneReport {
        stream: stream_name.to_string(),
        kept_versions,
        pruned,
        dry_run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_release::SELF_BINARIES;
    use fuz_storage::FileStorage;
    use fuz_sys::rand::random_hex_suffix;

    /// Publish a minimal manifest declaring `binaries` + a stub tarball, flat
    /// binary, and `.sha512` sidecar for `version`/`target` under the self
    /// layout. Enough to exercise the list → parse → select → delete flow
    /// without signing. `SELF_BINARIES` gives a
    /// manifest `Manifest::from_json` accepts; another set (the older
    /// two-binary `fuz` + `fuzd` shape) gives one it refuses.
    async fn seed_release(storage: &FileStorage, version: &str, target: &str, binaries: &[&str]) {
        let layout = ReleaseLayout::self_artifact();
        let tarball = format!("fuz-{version}-{target}.tar.gz");
        let binaries: serde_json::Map<String, serde_json::Value> = binaries
            .iter()
            .map(|name| ((*name).to_string(), "0".repeat(64).into()))
            .collect();
        let manifest = serde_json::json!({
            "format": 1,
            "version": version,
            "content_hash": "v1-abc1230000000000000000000000000000000000000000000000000000000000",
            "target": target,
            "minimum_version": null,
            "tarball": { "path": tarball, "blake3": "0".repeat(64), "size": 1 },
            "binaries": binaries,
            "signature": {
                "format": 2, "public_key": "", "algorithm": "ed25519",
                "signed_at": "2025-01-01T00:00:00Z", "sig": ""
            }
        });
        storage
            .upload(
                &layout.manifest_key("fuz", version, target),
                serde_json::to_vec(&manifest).unwrap().as_slice(),
            )
            .await
            .unwrap();
        storage
            .upload(&layout.tarball_key(&tarball), b"tarball")
            .await
            .unwrap();
        let binary = layout.binary_key("fuz", version, target);
        storage.upload(&binary, b"flat binary").await.unwrap();
        storage
            .upload(&format!("{binary}.sha512"), b"sidecar")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn prune_removes_a_release_current_fuz_would_refuse() {
        let dir = std::env::temp_dir().join(format!("fuz-prune-{}", random_hex_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = FileStorage::new(&dir).unwrap();
        let layout = ReleaseLayout::self_artifact();
        let target = "x86_64-unknown-linux-gnu";

        seed_release(&storage, "0.1.0", target, &["fuz", "fuzd"]).await;
        seed_release(&storage, "0.2.0", target, SELF_BINARIES).await;
        set_latest(&storage, "0.2.0").await;

        let report = prune_stream(&storage, &layout, "fuz", 1, false)
            .await
            .unwrap();
        assert_eq!(report.pruned.len(), 1);
        assert_eq!(report.pruned[0].version, "0.1.0");
        assert!(
            !storage
                .exists(&layout.manifest_key("fuz", "0.1.0", target))
                .await
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn set_latest(storage: &FileStorage, version: &str) {
        set_latest_for(storage, "x86_64-unknown-linux-gnu", version).await;
    }

    async fn set_latest_for(storage: &FileStorage, target: &str, version: &str) {
        let body = serde_json::json!({ "version": version });
        storage
            .upload(
                &ReleaseLayout::self_artifact().latest_key(target),
                serde_json::to_vec(&body).unwrap().as_slice(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn prune_removes_old_versions_keeps_recent_and_latest() {
        let dir = std::env::temp_dir().join(format!("fuz-prune-{}", random_hex_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = FileStorage::new(&dir).unwrap();
        let layout = ReleaseLayout::self_artifact();
        let target = "x86_64-unknown-linux-gnu";

        for v in ["0.1.0", "0.2.0", "0.3.0", "0.4.0"] {
            seed_release(&storage, v, target, SELF_BINARIES).await;
        }
        set_latest(&storage, "0.4.0").await;

        // Dry run: reports 2 prunes (0.1.0, 0.2.0) but deletes nothing.
        let report = prune_stream(&storage, &layout, "fuz", 2, true)
            .await
            .unwrap();
        assert!(report.dry_run);
        assert_eq!(report.pruned.len(), 2);
        assert!(
            storage
                .exists(&layout.manifest_key("fuz", "0.1.0", target))
                .await
                .unwrap()
        );

        // Wet run: 0.1.0 + 0.2.0 gone; 0.3.0 + 0.4.0 remain.
        let report = prune_stream(&storage, &layout, "fuz", 2, false)
            .await
            .unwrap();
        assert_eq!(report.pruned.len(), 2);
        assert!(
            !storage
                .exists(&layout.manifest_key("fuz", "0.1.0", target))
                .await
                .unwrap()
        );
        assert!(
            !storage
                .exists(&layout.tarball_key("fuz-0.2.0-x86_64-unknown-linux-gnu.tar.gz"))
                .await
                .unwrap()
        );
        assert!(
            storage
                .exists(&layout.manifest_key("fuz", "0.3.0", target))
                .await
                .unwrap()
        );
        assert!(
            storage
                .exists(&layout.manifest_key("fuz", "0.4.0", target))
                .await
                .unwrap()
        );

        // Re-run is a no-op (nothing left to prune past keep=2).
        let report = prune_stream(&storage, &layout, "fuz", 2, false)
            .await
            .unwrap();
        assert!(report.pruned.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn prune_protects_the_latest_pointer_even_when_old() {
        let dir = std::env::temp_dir().join(format!("fuz-prune-{}", random_hex_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = FileStorage::new(&dir).unwrap();
        let layout = ReleaseLayout::self_artifact();
        let target = "x86_64-unknown-linux-gnu";

        for v in ["0.1.0", "0.2.0", "0.3.0"] {
            seed_release(&storage, v, target, SELF_BINARIES).await;
        }
        // latest points at the OLDEST — it must survive keep=1.
        set_latest(&storage, "0.1.0").await;

        prune_stream(&storage, &layout, "fuz", 1, false)
            .await
            .unwrap();
        // Keep newest (0.3.0) + protected (0.1.0); only 0.2.0 pruned.
        assert!(
            storage
                .exists(&layout.manifest_key("fuz", "0.1.0", target))
                .await
                .unwrap()
        );
        assert!(
            !storage
                .exists(&layout.manifest_key("fuz", "0.2.0", target))
                .await
                .unwrap()
        );
        assert!(
            storage
                .exists(&layout.manifest_key("fuz", "0.3.0", target))
                .await
                .unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Seed a minimal tool release under `tools/<tool>/`, as `seed_release`
    /// does for the self stream.
    async fn seed_tool_release(storage: &FileStorage, tool: &str, version: &str, target: &str) {
        let layout = ReleaseLayout::tool(tool);
        let tarball = format!("{tool}-{version}-{target}.tar.gz");
        let manifest = serde_json::json!({
            "format": 1,
            "version": version,
            "content_hash": "v1-abc1230000000000000000000000000000000000000000000000000000000000",
            "target": target,
            "minimum_version": null,
            "tarball": { "path": tarball, "blake3": "0".repeat(64), "size": 1 },
            "binaries": { tool: "0".repeat(64) },
            "tool": tool,
            "signature": {
                "format": 2, "public_key": "", "algorithm": "ed25519",
                "signed_at": "2025-01-01T00:00:00Z", "sig": ""
            }
        });
        storage
            .upload(
                &layout.manifest_key(tool, version, target),
                serde_json::to_vec(&manifest).unwrap().as_slice(),
            )
            .await
            .unwrap();
        storage
            .upload(&layout.tarball_key(&tarball), b"tarball")
            .await
            .unwrap();
    }

    /// Every file under `dir`, as a root-relative path, sorted.
    fn files(root: &std::path::Path) -> Vec<String> {
        fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.push(
                        path.strip_prefix(root)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                    );
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    /// Each target's pointer protects its own version: one target whose
    /// latest lags another's keeps it through a prune, and a garbled pointer
    /// protects nothing (the newest `keep` still hold).
    #[tokio::test]
    async fn prune_keeps_every_per_target_latest() {
        let scratch = tempfile::tempdir().unwrap();
        let storage = FileStorage::new(scratch.path()).unwrap();
        let layout = ReleaseLayout::self_artifact();
        let (gnu, musl, arm) = (
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
        );
        for v in ["0.1.0", "0.2.0", "0.3.0", "0.4.0"] {
            seed_release(&storage, v, gnu, SELF_BINARIES).await;
        }
        seed_release(&storage, "0.1.0", musl, SELF_BINARIES).await;
        seed_release(&storage, "0.2.0", arm, SELF_BINARIES).await;
        set_latest_for(&storage, gnu, "0.4.0").await;
        set_latest_for(&storage, musl, "0.1.0").await;
        set_latest_for(&storage, arm, "0.2.0").await;
        storage
            .upload(&layout.latest_key("aarch64-apple-darwin"), b"not json")
            .await
            .unwrap();

        let report = prune_stream(&storage, &layout, "fuz", 1, false)
            .await
            .unwrap();
        assert_eq!(report.kept_versions, ["0.1.0", "0.2.0", "0.4.0"]);
        let pruned: Vec<&str> = report.pruned.iter().map(|r| r.version.as_str()).collect();
        assert_eq!(pruned, ["0.3.0"]);
        for target in [gnu, musl, arm] {
            assert!(storage.exists(&layout.latest_key(target)).await.unwrap());
        }
    }

    /// A self release pruned takes its flat binary and `.sha512` sidecar with
    /// it — the files `install.sh` downloads — and lists them on a dry run. A
    /// release kept keeps its own, the one its latest pointer names among them, and
    /// the moving `fuz-latest-<target>` copy is never touched.
    #[tokio::test]
    async fn prune_of_the_self_stream_removes_the_pruned_flat_binaries_only() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("store");
        std::fs::create_dir_all(&dir).unwrap();
        let storage = FileStorage::new(&dir).unwrap();
        let layout = ReleaseLayout::self_artifact();
        let target = "x86_64-unknown-linux-gnu";
        for v in ["0.1.0", "0.2.0", "0.3.0"] {
            seed_release(&storage, v, target, SELF_BINARIES).await;
        }
        let latest_binary = layout.latest_binary_key("fuz", target);
        storage.upload(&latest_binary, b"latest").await.unwrap();
        storage
            .upload(&format!("{latest_binary}.sha512"), b"latest sidecar")
            .await
            .unwrap();
        // The pointer names the oldest: kept with the newest; 0.2.0 goes.
        set_latest(&storage, "0.1.0").await;
        let before = files(&dir);
        let gone = [
            format!("fuz-0.2.0-{target}.tar.gz"),
            format!("fuz-0.2.0-{target}.sha512"),
            format!("fuz-0.2.0-{target}"),
            format!("fuz-0.2.0-{target}.manifest.json"),
        ];

        let report = prune_stream(&storage, &layout, "fuz", 1, true)
            .await
            .unwrap();
        assert_eq!(report.pruned.len(), 1);
        let pruned = &report.pruned[0];
        assert_eq!(pruned.tarball_key, gone[0]);
        assert_eq!(pruned.flat_keys, gone[1..3]);
        assert_eq!(pruned.manifest_key, gone[3]);
        assert_eq!(files(&dir), before, "a dry run deletes nothing");

        prune_stream(&storage, &layout, "fuz", 1, false)
            .await
            .unwrap();
        let expected: Vec<String> = before
            .iter()
            .filter(|key| !gone.contains(key))
            .cloned()
            .collect();
        assert_eq!(files(&dir), expected);
        for kept in [
            format!("fuz-0.1.0-{target}"),
            format!("fuz-0.1.0-{target}.sha512"),
            format!("fuz-0.3.0-{target}"),
            format!("fuz-0.3.0-{target}.sha512"),
            latest_binary.clone(),
            format!("{latest_binary}.sha512"),
            format!("latest-{target}.json"),
        ] {
            assert!(expected.contains(&kept), "{kept}");
        }
    }

    /// A tool stream has no flat binary: a pruned tool release lists none,
    /// and the self stream's files with the same version are left alone.
    #[tokio::test]
    async fn prune_of_a_tool_stream_lists_no_flat_binary() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("store");
        std::fs::create_dir_all(&dir).unwrap();
        let storage = FileStorage::new(&dir).unwrap();
        let target = "x86_64-unknown-linux-gnu";
        for v in ["0.1.0", "0.2.0"] {
            seed_tool_release(&storage, "fuzd", v, target).await;
            seed_release(&storage, v, target, SELF_BINARIES).await;
        }
        let report = prune_stream(&storage, &ReleaseLayout::tool("fuzd"), "fuzd", 1, false)
            .await
            .unwrap();
        assert_eq!(report.pruned.len(), 1);
        assert!(report.pruned[0].flat_keys.is_empty());
        assert!(
            storage
                .exists(&format!("fuz-0.1.0-{target}"))
                .await
                .unwrap()
        );
    }

    /// What a prune deletes is derived from the listed key, never read from
    /// the unsigned manifest: one whose `tarball.path` names another file —
    /// a latest pointer, another release's tarball — or whose
    /// version or target build another key refuses the prune, dry run and
    /// wet run alike, before anything is deleted.
    #[tokio::test]
    async fn prune_refuses_a_manifest_that_does_not_describe_its_key() {
        /// Whether a refusal is the one a case expects.
        type Expected = fn(&ManifestError) -> bool;

        let target = "x86_64-unknown-linux-gnu";
        let layout = ReleaseLayout::self_artifact();
        let key = layout.manifest_key("fuz", "0.1.0", target);
        let own_tarball = format!("fuz-0.1.0-{target}.tar.gz");
        let other_tarball = format!("fuz-0.2.0-{target}.tar.gz");
        // (case, version, target, tarball.path, expected refusal)
        let cases: [(&str, &str, &str, &str, Expected); 5] = [
            (
                "latest.json",
                "0.1.0",
                target,
                "latest.json",
                |e| matches!(e, ManifestError::TarballMismatch { actual, .. } if actual == "latest.json"),
            ),
            (
                "another release's tarball",
                "0.1.0",
                target,
                &other_tarball,
                |e| {
                    matches!(e, ManifestError::TarballMismatch { actual, expected, .. }
                    if actual.starts_with("fuz-0.2.0-") && expected.starts_with("fuz-0.1.0-"))
                },
            ),
            ("a path", "0.1.0", target, "../fuz-0.1.0.tar.gz", |e| {
                matches!(e, ManifestError::TarballMismatch { .. })
            }),
            (
                "another version",
                "0.2.0",
                target,
                &other_tarball,
                |e| matches!(e, ManifestError::KeyMismatch { version, .. } if version == "0.2.0"),
            ),
            (
                "another target",
                "0.1.0",
                "aarch64-unknown-linux-gnu",
                &own_tarball,
                |e| {
                    matches!(e, ManifestError::KeyMismatch { target: t, .. }
                    if t == "aarch64-unknown-linux-gnu")
                },
            ),
        ];
        for (case, version, manifest_target, tarball_path, expected) in cases {
            let scratch = tempfile::tempdir().unwrap();
            let dir = scratch.path().join("store");
            std::fs::create_dir_all(&dir).unwrap();
            let storage = FileStorage::new(&dir).unwrap();
            // A release that is pruned, an ordinary one to keep, and the
            // stream's pointer; then the manifest at 0.1.0's key replaced.
            seed_release(&storage, "0.1.0", target, SELF_BINARIES).await;
            seed_release(&storage, "0.2.0", target, SELF_BINARIES).await;
            set_latest(&storage, "0.2.0").await;
            let planted = serde_json::json!({
                "version": version,
                "target": manifest_target,
                "tarball": { "path": tarball_path },
            });
            storage
                .upload(&key, &serde_json::to_vec(&planted).unwrap())
                .await
                .unwrap();
            let before = files(&dir);

            for dry_run in [true, false] {
                let result = prune_stream(&storage, &layout, "fuz", 1, dry_run).await;
                assert!(
                    result
                        .as_ref()
                        .is_err_and(ReleaseError::is_security_violation),
                    "{case} (dry run {dry_run}): {result:?}"
                );
                let Err(ReleaseError::Manifest(error)) = result else {
                    panic!("{case} (dry run {dry_run}): {result:?}");
                };
                assert!(expected(&error), "{case} (dry run {dry_run}): {error:?}");
                assert!(
                    error
                        .to_string()
                        .starts_with(&format!("the manifest at {key} ")),
                    "{case}: {error}"
                );
                assert_eq!(files(&dir), before, "{case} (dry run {dry_run}): deleted");
            }
        }
    }

    /// A stream name is not checked here, so storage is what keeps a sweep
    /// inside its own prefix: a layout whose prefix climbs (`tools/../`, the
    /// store root — the self stream's directory) is refused as an invalid key
    /// before anything is listed, and nothing is deleted. Joined unchecked,
    /// that sweep would take the planted `..-…` manifest for its own and
    /// delete the self stream's tarball it names.
    #[tokio::test]
    async fn prune_of_a_stream_whose_prefix_climbs_is_refused_and_deletes_nothing() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("store");
        std::fs::create_dir_all(dir.join("tools")).unwrap();
        let storage = FileStorage::new(&dir).unwrap();
        let target = "x86_64-unknown-linux-gnu";
        seed_release(&storage, "0.1.0", target, SELF_BINARIES).await;
        let planted = serde_json::json!({
            "version": "0.0.1",
            "target": target,
            "tarball": { "path": format!("fuz-0.1.0-{target}.tar.gz") },
        });
        for at in [dir.clone(), scratch.path().to_path_buf()] {
            std::fs::write(
                at.join(format!("..-0.0.1-{target}.manifest.json")),
                serde_json::to_vec(&planted).unwrap(),
            )
            .unwrap();
        }
        std::fs::write(
            scratch.path().join(format!("fuz-0.1.0-{target}.tar.gz")),
            b"outside",
        )
        .unwrap();
        let before = files(scratch.path());

        for (tool, stream) in [("..", ".."), ("../..", ".."), ("../../x", "x")] {
            let layout = ReleaseLayout::tool(tool);
            let result = prune_stream(&storage, &layout, stream, 0, false).await;
            assert!(
                matches!(
                    &result,
                    Err(ReleaseError::Storage(
                        fuz_storage::StorageError::InvalidKey { key, .. }
                    )) if key == layout.prefix()
                ),
                "{tool}: {result:?}"
            );
            assert_eq!(files(scratch.path()), before, "{tool}");
        }
    }

    /// A tool stream lives in a directory of its own. Pruning it finds its
    /// releases there, keeps the newest and the one its latest pointer names, and
    /// leaves every other stream alone.
    #[tokio::test]
    async fn prune_of_a_tool_stream_finds_its_releases_and_touches_no_other() {
        let dir = std::env::temp_dir().join(format!("fuz-prune-{}", random_hex_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let storage = FileStorage::new(&dir).unwrap();
        let layout = ReleaseLayout::tool("fuzd");
        let target = "x86_64-unknown-linux-gnu";

        for v in ["0.1.0", "0.2.0", "0.3.0", "0.4.0"] {
            seed_tool_release(&storage, "fuzd", v, target).await;
            // The same versions in the self stream and in another tool's.
            seed_release(&storage, v, target, SELF_BINARIES).await;
            seed_tool_release(&storage, "zap", v, target).await;
        }
        set_latest(&storage, "0.4.0").await;
        // The tool's own pointer names its oldest version.
        storage
            .upload(&layout.latest_key(target), br#"{"version":"0.1.0"}"#)
            .await
            .unwrap();
        let before = files(&dir);

        // Dry run: 0.2.0 is the one version past keep=2 that nothing protects.
        let report = prune_stream(&storage, &layout, "fuzd", 2, true)
            .await
            .unwrap();
        assert!(report.dry_run);
        assert_eq!(report.stream, "fuzd");
        assert_eq!(report.kept_versions, ["0.1.0", "0.3.0", "0.4.0"]);
        assert_eq!(report.pruned.len(), 1);
        assert_eq!(report.pruned[0].version, "0.2.0");
        assert_eq!(
            report.pruned[0].manifest_key,
            format!("tools/fuzd/fuzd-0.2.0-{target}.manifest.json")
        );
        assert_eq!(
            report.pruned[0].tarball_key,
            format!("tools/fuzd/fuzd-0.2.0-{target}.tar.gz")
        );
        assert_eq!(files(&dir), before, "a dry run deletes nothing");

        // Wet run: exactly that release's two files are gone.
        let report = prune_stream(&storage, &layout, "fuzd", 2, false)
            .await
            .unwrap();
        assert_eq!(report.pruned.len(), 1);
        let removed = [
            report.pruned[0].manifest_key.clone(),
            report.pruned[0].tarball_key.clone(),
        ];
        let expected: Vec<String> = before
            .iter()
            .filter(|key| !removed.contains(key))
            .cloned()
            .collect();
        assert_eq!(files(&dir), expected);
        assert_eq!(before.len() - expected.len(), 2);

        // Nothing left past the retention.
        let report = prune_stream(&storage, &layout, "fuzd", 2, false)
            .await
            .unwrap();
        assert!(report.pruned.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
