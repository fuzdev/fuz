//! Backfill creates the release log from storage: `backfill_release_log`
//! against release storage populated by the real publish flows and a real git
//! checkout whose upstream is a local bare repository.
//!
//! The fixture is the one `log_publish.rs` uses (`common`): signing keys
//! admitted through the `test_trust_anchor` seam, every `git` process isolated
//! from the developer's configuration, nothing under `~/.fuz`. The tests skip
//! when `git` is absent.
//!
//! A publish signs for the target the test binary was built for. Releases for
//! any other target, and releases that need a chosen `signed_at`, are placed by
//! [`place_self`] / [`place_tool`]: the same tarball packer, manifest signer,
//! layout keys, and sidecar formatter the publish flows call, uploading the
//! same files in the same order.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use common::*;
use fuz_artifact::content_hash_from_binaries;
use fuz_artifact::tools::FIRST_PARTY_TOOLS;
use fuz_crypto::ContentHash;
use fuz_release::{
    BinaryHashes, HEAD_FORMAT_VERSION, HeadUnsigned, KeyRecord, LatestInfo, LogWriteError,
    MANIFEST_FORMAT_VERSION, MAX_HEAD_SIZE, MAX_MANIFEST_SIZE, Manifest, ManifestError,
    ManifestUnsigned, ReleaseError, ReleaseLayout, ReleaseLogError, ReleaseRow, Succession,
    TarballInfo, TargetField, TargetRow, check_successor, current_target, pack_tarball_to_file,
    sidecar_content,
};
use fuz_sign::release_log::HEAD_FILE;
use fuz_sign::{
    BackfillError, BackfillOptions, BackfillProblem, BackfillProblemKind, BackfillReport,
    BackfilledTarget, PublishOptions, SigningKey, backfill_release_log, plan_genesis, publish_tool,
    sign_genesis, sign_manifest,
};
use fuz_storage::{FileStorage, Storage, StorageBackendKind, StorageError};

/// The clock every backfill here runs at.
const CLOCK: &str = "2025-06-01T00:00:00Z";

type ProblemCheck = fn(&BackfillProblemKind) -> bool;
type LogCheck = fn(&LogWriteError) -> bool;

//
// Placing releases
//

/// A manifest's fields before its tarball is packed.
struct Release<'a> {
    layout: ReleaseLayout,
    /// The stream name: the basename of the stream's storage keys.
    name: &'a str,
    version: &'a str,
    target: &'a str,
    /// `None` for the self artifact.
    tool: Option<&'a str>,
    /// The one binary's in-tarball name and bytes.
    binary: (&'a str, &'a [u8]),
    /// The manifest's `content_hash`, when it is not to be the real one.
    content_hash: Option<&'a str>,
}

/// Pack, sign, and upload a release's tarball and manifest, as
/// `sign_and_upload` does.
async fn place_manifest(
    fixture: &Fixture,
    release: Release<'_>,
    key: &SigningKey,
    signed_at: &str,
) {
    let Release {
        layout,
        name,
        version,
        target,
        tool,
        binary: (binary_name, content),
        content_hash,
    } = release;
    let storage = fixture.storage();
    let blake3 = ContentHash::blake3(content);
    let hashes = BTreeMap::from([(binary_name.to_string(), blake3.clone())]);
    let mut binaries = BinaryHashes::new();
    binaries.insert(binary_name.to_string(), blake3);

    let tarball_tmp = fixture.tmp.path().join("placed.tar.gz");
    let digest =
        pack_tarball_to_file(&[(binary_name.to_string(), content.to_vec())], &tarball_tmp).unwrap();
    let tarball_name = format!("{name}-{version}-{target}.tar.gz");
    let unsigned = ManifestUnsigned {
        format: MANIFEST_FORMAT_VERSION,
        version: version.to_string(),
        content_hash: content_hash
            .map_or_else(|| content_hash_from_binaries(&hashes), str::to_string),
        target: target.to_string(),
        minimum_version: None,
        tarball: TarballInfo {
            path: tarball_name.clone(),
            blake3: digest.blake3,
            size: digest.size,
        },
        binaries,
        tool: tool.map(str::to_string),
    };
    let manifest = sign_manifest(unsigned, key, signed_at).unwrap();
    storage
        .upload_file(&layout.tarball_key(&tarball_name), &tarball_tmp)
        .await
        .unwrap();
    storage
        .upload(
            &layout.manifest_key(name, version, target),
            serde_json::to_string_pretty(&manifest).unwrap().as_bytes(),
        )
        .await
        .unwrap();
    std::fs::remove_file(&tarball_tmp).unwrap();
}

/// Place a self release for `target` holding `content`: tarball, signed
/// manifest, and — with `flat` — the versioned flat binary and its sidecar.
/// The files `publish_artifact` uploads before it advertises anything.
async fn place_self(
    fixture: &Fixture,
    version: &str,
    target: &str,
    content: &[u8],
    key: &SigningKey,
    signed_at: &str,
    flat: bool,
) {
    let storage = fixture.storage();
    let layout = ReleaseLayout::self_artifact();
    place_manifest(
        fixture,
        Release {
            layout: layout.clone(),
            name: "fuz",
            version,
            target,
            tool: None,
            binary: ("fuz", content),
            content_hash: None,
        },
        key,
        signed_at,
    )
    .await;
    if flat {
        let binary_key = layout.binary_key("fuz", version, target);
        storage.upload(&binary_key, content).await.unwrap();
        storage
            .upload(
                &format!("{binary_key}.sha512"),
                sidecar_content(&binary_key, &ContentHash::sha512(content).to_hex()).as_bytes(),
            )
            .await
            .unwrap();
    }
}

/// Place a single-binary tool release for `target`, as `publish_tool` uploads
/// it.
async fn place_tool(
    fixture: &Fixture,
    tool: &str,
    version: &str,
    target: &str,
    content: &[u8],
    key: &SigningKey,
    signed_at: &str,
) {
    place_manifest(
        fixture,
        Release {
            layout: ReleaseLayout::tool(tool),
            name: tool,
            version,
            target,
            tool: Some(tool),
            binary: (tool, content),
            content_hash: None,
        },
        key,
        signed_at,
    )
    .await;
}

/// Advertise `version` as the self artifact's latest for `target`: the
/// `latest` copy of the flat binary, its sidecar, and `latest-<target>.json` — the files
/// `publish_artifact` uploads last.
async fn advertise_self(fixture: &Fixture, version: &str, target: &str, content: &[u8]) {
    let storage = fixture.storage();
    let layout = ReleaseLayout::self_artifact();
    let latest_key = layout.latest_binary_key("fuz", target);
    storage.upload(&latest_key, content).await.unwrap();
    storage
        .upload(
            &format!("{latest_key}.sha512"),
            sidecar_content(&latest_key, &ContentHash::sha512(content).to_hex()).as_bytes(),
        )
        .await
        .unwrap();
    set_latest_json_for(&storage, &layout, version, target).await;
}

/// Point the stream's host-target pointer at `version`.
async fn set_latest_json(storage: &FileStorage, layout: &ReleaseLayout, version: &str) {
    set_latest_json_for(storage, layout, version, current_target()).await;
}

async fn set_latest_json_for(
    storage: &FileStorage,
    layout: &ReleaseLayout,
    version: &str,
    target: &str,
) {
    let latest = LatestInfo {
        version: version.to_string(),
    };
    storage
        .upload(
            &layout.latest_key(target),
            serde_json::to_string_pretty(&latest).unwrap().as_bytes(),
        )
        .await
        .unwrap();
}

/// The self stream's pointer for the host target.
fn host_latest() -> String {
    ReleaseLayout::self_artifact().latest_key(current_target())
}

/// The bytes placed for a self release on a target.
fn placed_content(version: &str, target: &str) -> Vec<u8> {
    format!("fuz binary bytes for {version} on {target}").into_bytes()
}

/// Storage the failure tests start from, all on the host target: self 0.1.0
/// and 0.2.0 (0.2.0 advertised as latest), and tool `fuzd` 0.1.0. Each test
/// then breaks one thing.
async fn seed(fixture: &Fixture) {
    let host = current_target();
    let key = trusted_key();
    for (version, signed_at) in [("0.1.0", "2025-01-01T00:00:00Z"), ("0.2.0", LATER)] {
        let content = placed_content(version, host);
        place_self(fixture, version, host, &content, &key, signed_at, true).await;
    }
    advertise_self(fixture, "0.2.0", host, &placed_content("0.2.0", host)).await;
    place_tool(fixture, "fuzd", "0.1.0", host, b"fuzd 0.1.0", &key, NOW).await;
    set_latest_json(&fixture.storage(), &ReleaseLayout::tool("fuzd"), "0.1.0").await;
}

//
// Running and observing
//

/// A dry or real run that has not been told to log a missing flat binary.
const fn options(dry_run: bool) -> BackfillOptions {
    BackfillOptions {
        dry_run,
        allow_missing_flat: false,
    }
}

async fn backfill(fixture: &Fixture, dry_run: bool) -> Result<BackfillReport, BackfillError> {
    backfill_with(fixture, options(dry_run)).await
}

async fn backfill_with(
    fixture: &Fixture,
    options: BackfillOptions,
) -> Result<BackfillReport, BackfillError> {
    backfill_release_log(
        &fixture.storage(),
        &fixture.repo(),
        &trusted_key(),
        CLOCK,
        options,
    )
    .await
}

/// Everything in the log checkout a backfill could touch: the work tree's
/// files with their bytes, the index's entries, the commit checked out, and
/// git's view of what is uncommitted.
fn checkout_state(fixture: &Fixture) -> (Vec<(String, Vec<u8>)>, String, String, String) {
    fn walk(root: &Path, dir: &Path, files: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap() == ".git" {
                continue;
            }
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                let relative = path.strip_prefix(root).unwrap().to_str().unwrap();
                files.push((relative.to_string(), std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut files = Vec::new();
    walk(&fixture.checkout, &fixture.checkout, &mut files);
    files.sort();
    let head = fixture.try_git_in(
        &fixture.checkout,
        &["rev-parse", "--verify", "--quiet", "HEAD"],
    );
    (
        files,
        fixture.git(&["ls-files", "--stage"]),
        String::from_utf8_lossy(&head.stdout).trim().to_string(),
        fixture.git(&["status", "--porcelain", "--untracked-files=all"]),
    )
}

/// Run a real (not dry) backfill that must be refused, and require that it
/// wrote nothing: the checkout, the remote, and storage are as they were.
async fn refused(fixture: &Fixture) -> BackfillError {
    let checkout = checkout_state(fixture);
    let remote = fixture.remote_subjects();
    let storage = fixture.storage_files();
    let error = match backfill(fixture, false).await {
        Err(error) => error,
        Ok(report) => panic!("expected a refusal, got {report:?}"),
    };
    assert_eq!(checkout_state(fixture), checkout, "the checkout changed");
    assert_eq!(fixture.remote_subjects(), remote, "something was pushed");
    assert_eq!(fixture.storage_files(), storage, "storage changed");
    error
}

/// The problems of a refused backfill.
async fn refused_problems(fixture: &Fixture) -> Vec<BackfillProblem> {
    match refused(fixture).await {
        BackfillError::Releases { problems } => problems,
        other => panic!("expected storage problems, got {other:?}"),
    }
}

/// The one problem of a refused backfill, which must be at `key`.
#[track_caller]
fn only(problems: Vec<BackfillProblem>, key: &str) -> BackfillProblemKind {
    assert_eq!(
        problems.iter().map(|p| p.key.as_str()).collect::<Vec<_>>(),
        [key],
        "{problems:?}"
    );
    problems.into_iter().next().unwrap().kind
}

fn manifest_key(version: &str) -> String {
    ReleaseLayout::self_artifact().manifest_key("fuz", version, current_target())
}

fn binary_key(version: &str) -> String {
    ReleaseLayout::self_artifact().binary_key("fuz", version, current_target())
}

fn row_ids(rows: &[ReleaseRow]) -> Vec<(String, String)> {
    rows.iter()
        .map(|row| (row.name.clone(), row.version.clone()))
        .collect()
}

/// Rewrite one file in storage.
fn rewrite(fixture: &Fixture, key: &str, edit: impl FnOnce(Vec<u8>) -> Vec<u8>) {
    let path = fixture.storage_dir.join(key);
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, edit(bytes)).unwrap();
}

fn write_storage(fixture: &Fixture, key: &str, bytes: &[u8]) {
    let path = fixture.storage_dir.join(key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

//
// The backfill
//

/// Storage populated by the real publish flows — several self versions on two
/// targets, two tool streams — becomes one head holding every release, pushed
/// and read back; the publish flow then extends that head like any other.
#[tokio::test]
async fn backfill_logs_every_published_release_and_publish_continues_the_log() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let storage = fixture.storage();
    let key = trusted_key();
    let host = current_target();
    let other = other_target();
    let unlogged = PublishOptions::default();

    // Self: three versions, each published for the host target by the real
    // flow and placed for a second target with an earlier, distinct date.
    let placed_dates = [
        ("0.1.0", "2025-01-01T00:00:00Z"),
        ("0.2.0", "2025-02-01T00:00:00Z"),
        ("0.10.0", "2025-03-01T00:00:00Z"),
    ];
    for (version, placed_at) in placed_dates {
        publish_self_with(&fixture, version, &fuz_content(version), &key, &unlogged)
            .await
            .unwrap();
        let content = placed_content(version, other);
        place_self(&fixture, version, other, &content, &key, placed_at, true).await;
    }
    advertise_self(&fixture, "0.10.0", other, &placed_content("0.10.0", other)).await;

    // Tools: two streams through the real flow.
    for (tool, version) in [("fuzd", "0.1.0"), ("fuzd", "0.2.0"), ("zap", "1.0.0")] {
        let bin_path = fixture.tmp.path().join(tool);
        std::fs::write(
            &bin_path,
            host_binary(format!("{tool} {version} bytes").as_bytes()),
        )
        .unwrap();
        publish_tool(
            &storage,
            tool,
            version,
            &[(tool.to_string(), bin_path)],
            &key,
            &unlogged,
        )
        .await
        .unwrap();
    }
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    let storage_before = fixture.storage_files();

    // The backfill's clock is read after the publishes, as the command reads
    // it: every manifest was signed at or before it.
    let clock = fuz_sys::rfc3339_now();
    let report = backfill_release_log(&storage, &fixture.repo(), &key, &clock, options(false))
        .await
        .unwrap();
    assert!(!report.dry_run);
    assert!(report.pushed);
    assert_eq!(report.seq, 1);
    assert_eq!(report.commit_message, "log: backfill 6 releases seq 1");
    assert_eq!(report.missing_flat_binaries, Vec::<String>::new());
    assert_eq!(report.unaccounted_keys, Vec::<String>::new());
    assert_eq!(report.streams[0], "fuz");
    assert_eq!(&report.streams[1..], FIRST_PARTY_TOOLS);
    assert_eq!(
        fixture.storage_files(),
        storage_before,
        "backfill only reads storage"
    );

    // One commit on the remote: the head and a pointer per target.
    assert_eq!(
        fixture.remote_subjects(),
        std::slice::from_ref(&report.commit_message)
    );
    assert_eq!(
        fixture.remote_tree(),
        [
            HEAD_FILE.to_string(),
            format!("latest/fuz-{}.sha512", host.min(other)),
            format!("latest/fuz-{}.sha512", host.max(other)),
        ]
    );
    assert_eq!(fixture.git(&["status", "--porcelain"]), "");
    assert_eq!(
        fixture.git(&["rev-parse", "HEAD"]),
        fixture.remote_git(&["rev-parse", "main"])
    );

    // The pushed head verifies as a reader verifies it.
    let head = fixture.remote_head("main");
    assert_eq!(head.seq(), 1);
    assert_eq!(head.keys().len(), 1);
    assert_eq!(head.keys()[0].public_key, public_key(&key));
    assert_eq!(head.keys()[0].added_at, clock);
    assert_eq!(head.signature().signed_at, clock);
    assert_eq!(head.rows(), report.rows.as_slice());
    assert_eq!(
        fixture.checkout_head_bytes().unwrap(),
        report.head_json.as_bytes()
    );

    // Every manifest in storage is a target of a row, with storage's digests.
    let mut targets_seen = 0;
    for (stream, layout) in [
        ("fuz", ReleaseLayout::self_artifact()),
        ("fuzd", ReleaseLayout::tool("fuzd")),
        ("zap", ReleaseLayout::tool("zap")),
    ] {
        for (file_key, bytes) in &storage_before {
            let in_stream = file_key.starts_with(&format!("{}{stream}-", layout.prefix()));
            if !in_stream || !file_key.ends_with(".manifest.json") {
                continue;
            }
            targets_seen += 1;
            let manifest = Manifest::from_json(bytes).unwrap();
            let row = head.row(stream, &manifest.version).unwrap();
            let logged = &row.targets[&manifest.target];
            assert_eq!(logged.content_hash, manifest.content_hash);
            assert_eq!(
                logged.binaries,
                manifest
                    .binaries
                    .clone()
                    .into_iter()
                    .collect::<BTreeMap<_, _>>()
            );
            assert!(row.published_at <= manifest.signature.signed_at);
            if stream == "fuz" {
                let flat = storage
                    .download(&layout.binary_key("fuz", &manifest.version, &manifest.target))
                    .await
                    .unwrap();
                assert_eq!(logged.sha512, Some(ContentHash::sha512(&flat)));
            } else {
                assert_eq!(logged.sha512, None);
            }
        }
    }
    assert_eq!(targets_seen, 9);
    assert_eq!(
        head.rows().iter().map(|r| r.targets.len()).sum::<usize>(),
        9
    );

    // Self rows are dated by the earlier — placed — target and so come first,
    // in date order: 0.10.0 after 0.2.0, which string order would reverse.
    // The tool rows follow, dated by their publish.
    for (version, placed_at) in placed_dates {
        let row = head.row("fuz", version).unwrap();
        assert_eq!(row.published_at, placed_at);
        assert_eq!(
            row.targets.keys().map(String::as_str).collect::<Vec<_>>(),
            [host.min(other), host.max(other)]
        );
    }
    let mut expected: Vec<&ReleaseRow> = head.rows().iter().collect();
    expected.sort_by(|a, b| {
        let version = |row: &ReleaseRow| semver::Version::parse(&row.version).unwrap();
        (&a.published_at, &a.name, version(a)).cmp(&(&b.published_at, &b.name, version(b)))
    });
    assert_eq!(
        head.rows().iter().collect::<Vec<_>>(),
        expected,
        "rows are ordered by published_at, name, version"
    );
    assert_eq!(
        row_ids(head.rows())[..3],
        [
            ("fuz".to_string(), "0.1.0".to_string()),
            ("fuz".to_string(), "0.2.0".to_string()),
            ("fuz".to_string(), "0.10.0".to_string()),
        ]
    );

    // The pointers name the advertised version's versioned binary per target.
    for (target, content) in [
        (host, fuz_content("0.10.0")),
        (other, placed_content("0.10.0", other)),
    ] {
        let pointer =
            std::fs::read_to_string(fixture.checkout.join(format!("latest/fuz-{target}.sha512")))
                .unwrap();
        assert_eq!(
            pointer,
            sidecar_content(
                &format!("fuz-0.10.0-{target}"),
                &ContentHash::sha512(&content).to_hex()
            )
        );
    }

    // A publish of a new version extends the backfilled head.
    let published = publish_self(&fixture, "0.11.0").await.unwrap();
    let logged = published.logged.unwrap();
    assert_eq!((logged.seq, logged.advanced), (2, true));
    let next = fixture.remote_head("main");
    assert_eq!(check_successor(&head, &next), Ok(Succession::Advanced));
    assert_eq!(next.rows().len(), 7);
    assert_eq!(next.rows()[..6], *head.rows());

    // Publishing a backfilled release again with the same bytes changes no
    // head; with other bytes it is a conflict.
    let again = publish_self(&fixture, "0.2.0").await.unwrap();
    let logged = again.logged.unwrap();
    assert_eq!((logged.seq, logged.advanced), (2, false));
    let conflict = publish_self_with(
        &fixture,
        "0.2.0",
        &host_binary(b"another build of 0.2.0"),
        &key,
        &fixture.options(),
    )
    .await;
    assert!(matches!(
        conflict,
        Err(ReleaseError::LogWrite(LogWriteError::TargetConflict {
            field: TargetField::ContentHash,
            ..
        }))
    ));
    assert_eq!(fixture.remote_head("main").seq(), 2);
}

/// A dry run reads and checks everything and writes nothing; the real run
/// that follows writes exactly what the dry run reported.
#[tokio::test]
async fn a_dry_run_writes_nothing_and_describes_the_real_run() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let host = current_target();
    let checkout = checkout_state(&fixture);
    let storage = fixture.storage_files();

    let dry = backfill(&fixture, true).await.unwrap();
    assert!(dry.dry_run);
    assert!(!dry.pushed);
    assert_eq!(checkout_state(&fixture), checkout);
    assert_eq!(fixture.storage_files(), storage);
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    assert!(!fixture.checkout.join(HEAD_FILE).exists());
    assert!(!fixture.checkout.join("latest").exists());

    // The report holds the rows and pointers the real run writes.
    assert_eq!(
        row_ids(&dry.rows),
        [
            ("fuz".to_string(), "0.1.0".to_string()),
            ("fuzd".to_string(), "0.1.0".to_string()),
            ("fuz".to_string(), "0.2.0".to_string()),
        ]
    );
    assert_eq!(dry.pointers.len(), 1);
    assert_eq!(dry.pointers[0].path, format!("latest/fuz-{host}.sha512"));
    assert_eq!((dry.pointers[0].version.as_str()), "0.2.0");
    assert_eq!(dry.pointers[0].target, host);
    assert_eq!(dry.commit_message, "log: backfill 3 releases seq 1");
    assert_eq!(dry.head_size_max, MAX_HEAD_SIZE);
    assert!((dry.head_json.len() as u64) < MAX_HEAD_SIZE);

    let wet = backfill(&fixture, false).await.unwrap();
    assert!(wet.pushed);
    assert_eq!(wet.rows, dry.rows);
    assert_eq!(wet.pointers, dry.pointers);
    assert_eq!(wet.head_json, dry.head_json);
    assert_eq!(wet.commit_message, dry.commit_message);
    assert_eq!(
        fixture.remote_subjects(),
        std::slice::from_ref(&dry.commit_message)
    );
    assert_eq!(
        fixture.remote_git(&["show", &format!("main:{HEAD_FILE}")]),
        dry.head_json.trim_end()
    );
    assert_eq!(
        fixture.checkout_head_bytes().unwrap(),
        dry.head_json.as_bytes()
    );
    assert_eq!(
        std::fs::read_to_string(fixture.checkout.join(&dry.pointers[0].path)).unwrap(),
        dry.pointers[0].content
    );
    assert_eq!(fixture.storage_files(), storage);
}

/// Release storage that lists its keys in reverse.
struct Reversed(FileStorage);

impl Storage for Reversed {
    fn backend_kind(&self) -> StorageBackendKind {
        self.0.backend_kind()
    }
    async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        self.0.upload(path, data).await
    }
    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        self.0.download(path).await
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
        let mut keys = self.0.list(prefix).await?;
        keys.reverse();
        Ok(keys)
    }
    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        self.0.delete(path).await
    }
}

/// The same storage, key, and clock give the same `head.json`, byte for byte —
/// into any log repository, and whatever order storage lists its keys in.
#[tokio::test]
async fn the_head_is_the_same_bytes_whatever_the_listing_order() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let other = other_target();
    // Two targets of one release, and two releases that share a date.
    let content = placed_content("0.2.0", other);
    place_self(
        &fixture,
        "0.2.0",
        other,
        &content,
        &trusted_key(),
        NOW,
        true,
    )
    .await;
    advertise_self(&fixture, "0.2.0", other, &content).await;
    place_tool(&fixture, "zap", "1.0.0", other, b"zap", &trusted_key(), NOW).await;
    let storage = fixture.storage_files();

    let first = backfill(&fixture, false).await.unwrap();

    let second_log = Fixture::new();
    let second = backfill_release_log(
        &fixture.storage(),
        &second_log.repo(),
        &trusted_key(),
        CLOCK,
        options(false),
    )
    .await
    .unwrap();

    let reversed_log = Fixture::new();
    let reversed = backfill_release_log(
        &Reversed(fixture.storage()),
        &reversed_log.repo(),
        &trusted_key(),
        CLOCK,
        options(false),
    )
    .await
    .unwrap();

    let pushed = |log: &Fixture| log.checkout_head_bytes().unwrap();
    assert_eq!(pushed(&fixture), first.head_json.as_bytes());
    assert_eq!(pushed(&second_log), pushed(&fixture));
    assert_eq!(pushed(&reversed_log), pushed(&fixture));
    assert_eq!(second.pointers, first.pointers);
    assert_eq!(reversed.pointers, first.pointers);
    assert_eq!(reversed.rows, first.rows);
    assert_eq!(first.pointers.len(), 2);
    for log in [&fixture, &second_log, &reversed_log] {
        assert_eq!(log.remote_tree(), fixture.remote_tree());
    }
    assert_eq!(fixture.storage_files(), storage);
}

//
// What is not a release
//

/// Files beside the releases that no release accounts for are reported and
/// change nothing; streams outside the first-party set are not read at all.
#[tokio::test]
async fn stray_files_are_reported_and_unknown_streams_are_not_walked() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let clean = backfill(&fixture, true).await.unwrap();

    let host = current_target();
    // Under a walked stream's name, but no release's file.
    write_storage(&fixture, "fuz-notes.txt", b"notes");
    write_storage(
        &fixture,
        &format!("fuz-0.1.0-{host}.sha256"),
        b"old sidecar",
    );
    write_storage(&fixture, "tools/fuzd/fuzd-stray", b"stray");
    // Not under a walked stream's name.
    write_storage(&fixture, "README", b"readme");
    write_storage(&fixture, "tools/fuzd/notes.txt", b"notes");
    // Streams outside the first-party set — one holding what would be a
    // manifest, were it walked.
    write_storage(
        &fixture,
        &format!("tools/unknown/unknown-0.1.0-{host}.manifest.json"),
        b"not a manifest",
    );
    write_storage(
        &fixture,
        &format!("tools/testing_tool/testing_tool-0.1.0-{host}.manifest.json"),
        b"not a manifest",
    );

    let report = backfill(&fixture, true).await.unwrap();
    assert_eq!(
        report.unaccounted_keys,
        [
            format!("fuz-0.1.0-{host}.sha256"),
            "fuz-notes.txt".to_string(),
            "tools/fuzd/fuzd-stray".to_string(),
        ]
    );
    assert_eq!(report.rows, clean.rows);
    assert_eq!(report.pointers, clean.pointers);
    assert_eq!(report.head_json, clean.head_json);
    assert!(!report.streams.iter().any(|s| s == "unknown"));
    assert!(!report.streams.iter().any(|s| s == "testing_tool"));
}

/// A self release with no flat binary can only be recorded without a `sha512`,
/// for good — so only when the backfill is told to. It is never recorded that
/// way when it is the version advertised as latest, which the install script
/// must be able to fetch.
#[tokio::test]
async fn a_self_release_without_a_flat_binary_is_logged_without_sha512() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    let key = trusted_key();
    let old = placed_content("0.1.0", host);
    place_self(&fixture, "0.1.0", host, &old, &key, NOW, false).await;
    let new = placed_content("0.2.0", host);
    place_self(&fixture, "0.2.0", host, &new, &key, LATER, true).await;
    advertise_self(&fixture, "0.2.0", host, &new).await;

    // Unasked, that is refused — on a review as on a real run — and the
    // error names the binary that is missing.
    for dry_run in [true, false] {
        let checkout = checkout_state(&fixture);
        let error = backfill(&fixture, dry_run).await.unwrap_err();
        match &error {
            BackfillError::MissingFlatBinaries { keys } => {
                assert_eq!(keys, &[binary_key("0.1.0")]);
            }
            other => panic!("expected the missing flat binary, got {other:?}"),
        }
        assert!(error.to_string().contains(&binary_key("0.1.0")), "{error}");
        assert!(error.hint().unwrap().contains("--allow-missing-flat"));
        assert!(!error.is_security_violation());
        assert_eq!(checkout_state(&fixture), checkout);
        assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    }

    // Asked, the review lists it and the real run logs it.
    let allowed = |dry_run| BackfillOptions {
        dry_run,
        allow_missing_flat: true,
    };
    let review = backfill_with(&fixture, allowed(true)).await.unwrap();
    assert_eq!(review.missing_flat_binaries, [binary_key("0.1.0")]);
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    let report = backfill_with(&fixture, allowed(false)).await.unwrap();
    assert_eq!(report.missing_flat_binaries, [binary_key("0.1.0")]);
    let head = fixture.remote_head("main");
    let old_pins = head.target("fuz", "0.1.0", host).unwrap();
    assert_eq!(old_pins.sha512, None);
    assert_eq!(
        old_pins.binaries,
        BTreeMap::from([("fuz".to_string(), ContentHash::blake3(&old))])
    );
    assert_eq!(
        head.target("fuz", "0.2.0", host).unwrap().sha512,
        Some(ContentHash::sha512(&new))
    );

    // The same gap in the advertised version is a refusal, asked or not.
    let latest_gap = Fixture::new();
    place_self(&latest_gap, "0.1.0", host, &old, &key, NOW, false).await;
    advertise_self(&latest_gap, "0.1.0", host, &old).await;
    let kind = only(refused_problems(&latest_gap).await, &binary_key("0.1.0"));
    assert!(
        matches!(kind, BackfillProblemKind::LatestWithoutFlatBinary { .. }),
        "{kind:?}"
    );
    assert!(matches!(
        backfill_with(&latest_gap, allowed(false)).await,
        Err(BackfillError::Releases { .. })
    ));

    // A sidecar left without its binary is one too.
    let orphan = Fixture::new();
    place_self(&orphan, "0.1.0", host, &old, &key, NOW, true).await;
    std::fs::remove_file(orphan.storage_dir.join(binary_key("0.1.0"))).unwrap();
    let kind = only(
        refused_problems(&orphan).await,
        &format!("{}.sha512", binary_key("0.1.0")),
    );
    assert!(
        matches!(kind, BackfillProblemKind::SidecarWithoutBinary),
        "{kind:?}"
    );
}

//
// Refusals: storage
//

/// A manifest whose signed content was changed after signing.
#[tokio::test]
async fn a_manifest_with_a_bad_signature_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let key = ReleaseLayout::tool("fuzd").manifest_key("fuzd", "0.1.0", current_target());
    // Another well-formed content hash: nothing but the signature can tell.
    rewrite(&fixture, &key, |bytes| {
        let mut manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        manifest["content_hash"] = format!("v1-{}", "0".repeat(64)).into();
        serde_json::to_vec_pretty(&manifest).unwrap()
    });

    let error = refused(&fixture).await;
    assert!(error.is_security_violation());
    assert!(error.to_string().contains(&key), "{error}");
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &key);
    assert!(
        matches!(
            kind,
            BackfillProblemKind::Release(ReleaseError::Manifest(ManifestError::Signature(_)))
        ),
        "{kind:?}"
    );
}

/// A manifest with a valid signature from a key this binary does not trust.
#[tokio::test]
async fn a_manifest_signed_by_an_untrusted_key_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let host = current_target();
    let content = placed_content("0.3.0", host);
    place_self(
        &fixture,
        "0.3.0",
        host,
        &content,
        &untrusted_key(),
        LATER,
        true,
    )
    .await;

    let error = refused(&fixture).await;
    assert!(error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &manifest_key("0.3.0"));
    assert!(
        matches!(
            kind,
            BackfillProblemKind::Release(ReleaseError::Manifest(ManifestError::Signature(_)))
        ),
        "{kind:?}"
    );
}

/// A validly signed manifest stored under a key that names another version,
/// target, or stream is not that release's manifest. Every one is reported.
#[tokio::test]
async fn a_manifest_that_is_not_the_one_its_key_names_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let host = current_target();
    let layout = ReleaseLayout::self_artifact();
    let self_manifest = std::fs::read(fixture.storage_dir.join(manifest_key("0.1.0"))).unwrap();
    let fuzd_layout = ReleaseLayout::tool("fuzd");
    let fuzd_manifest = std::fs::read(
        fixture
            .storage_dir
            .join(fuzd_layout.manifest_key("fuzd", "0.1.0", host)),
    )
    .unwrap();

    let other_version = layout.manifest_key("fuz", "0.9.0", host);
    let other_target_key = layout.manifest_key("fuz", "0.1.0", other_target());
    let self_as_tool = fuzd_layout.manifest_key("fuzd", "0.5.0", host);
    let tool_as_other_tool = ReleaseLayout::tool("zap").manifest_key("zap", "0.1.0", host);
    let tool_as_self = layout.manifest_key("fuz", "0.7.0", host);
    // `tsv` is walked after `zap`, and sorts before it.
    let tool_as_later_tool = ReleaseLayout::tool("tsv").manifest_key("tsv", "0.1.0", host);
    write_storage(&fixture, &other_version, &self_manifest);
    write_storage(&fixture, &other_target_key, &self_manifest);
    write_storage(&fixture, &self_as_tool, &self_manifest);
    write_storage(&fixture, &tool_as_other_tool, &fuzd_manifest);
    write_storage(&fixture, &tool_as_self, &fuzd_manifest);
    write_storage(&fixture, &tool_as_later_tool, &fuzd_manifest);

    let error = refused(&fixture).await;
    assert!(error.is_security_violation());
    let message = error.to_string();
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let mut expected = [
        other_version.clone(),
        other_target_key.clone(),
        self_as_tool.clone(),
        tool_as_other_tool.clone(),
        tool_as_self.clone(),
        tool_as_later_tool.clone(),
    ];
    let walk_order = |tool: &str| FIRST_PARTY_TOOLS.iter().position(|t| *t == tool).unwrap();
    assert!(walk_order("zap") < walk_order("tsv") && "tools/tsv" < "tools/zap");
    expected.sort();
    assert_eq!(
        problems.iter().map(|p| p.key.clone()).collect::<Vec<_>>(),
        expected,
        "every offending key, sorted"
    );
    for key in &expected {
        assert!(message.contains(key), "{message}");
    }
    let kind_of = |key: &str| &problems.iter().find(|p| p.key == key).unwrap().kind;
    for key in [&other_version, &other_target_key] {
        assert!(
            matches!(kind_of(key), BackfillProblemKind::KeyMismatch { version, target }
                if version == "0.1.0" && target == host),
            "{:?}",
            kind_of(key)
        );
    }
    assert!(matches!(
        kind_of(&self_as_tool),
        BackfillProblemKind::StreamMismatch { declared: None }
    ));
    for key in [&tool_as_other_tool, &tool_as_self, &tool_as_later_tool] {
        assert!(
            matches!(kind_of(key), BackfillProblemKind::StreamMismatch { declared: Some(tool) }
                if tool == "fuzd"),
            "{:?}",
            kind_of(key)
        );
    }
}

#[tokio::test]
async fn a_truncated_or_oversized_manifest_is_refused() {
    if !git_available() {
        return;
    }
    let truncated = Fixture::new();
    seed(&truncated).await;
    rewrite(&truncated, &manifest_key("0.1.0"), |bytes| {
        bytes[..bytes.len() / 2].to_vec()
    });
    let kind = only(refused_problems(&truncated).await, &manifest_key("0.1.0"));
    assert!(
        matches!(
            kind,
            BackfillProblemKind::Release(ReleaseError::Manifest(ManifestError::Parse(_)))
        ),
        "{kind:?}"
    );

    // Still valid JSON, still validly signed — and past the size limit.
    let oversized = Fixture::new();
    seed(&oversized).await;
    rewrite(&oversized, &manifest_key("0.1.0"), |mut bytes| {
        bytes.resize(usize::try_from(MAX_MANIFEST_SIZE).unwrap() + 1, b' ');
        bytes
    });
    let error = refused(&oversized).await;
    assert!(!error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &manifest_key("0.1.0"));
    assert!(
        matches!(
            kind,
            BackfillProblemKind::Release(ReleaseError::Manifest(ManifestError::TooLarge(_)))
        ),
        "{kind:?}"
    );
}

/// The flat binary is logged only as the binary the signed manifest pins —
/// even when its sidecar agrees with the bytes that are there.
#[tokio::test]
async fn a_flat_binary_the_manifest_does_not_pin_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let key = binary_key("0.1.0");
    let swapped = b"not the binary that was signed";
    write_storage(&fixture, &key, swapped);
    write_storage(
        &fixture,
        &format!("{key}.sha512"),
        sidecar_content(&key, &ContentHash::sha512(swapped).to_hex()).as_bytes(),
    );

    let error = refused(&fixture).await;
    assert!(error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &key);
    assert!(
        matches!(&kind, BackfillProblemKind::FlatBinaryMismatch { actual }
            if *actual == ContentHash::blake3(swapped)),
        "{kind:?}"
    );
}

#[tokio::test]
async fn a_sidecar_that_disagrees_with_its_binary_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let binary = binary_key("0.1.0");
    let sidecar = format!("{binary}.sha512");
    write_storage(
        &fixture,
        &sidecar,
        sidecar_content(&binary, &ContentHash::sha512(b"other bytes").to_hex()).as_bytes(),
    );

    let error = refused(&fixture).await;
    assert!(error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &sidecar);
    assert!(
        matches!(kind, BackfillProblemKind::SidecarMismatch),
        "{kind:?}"
    );
}

#[tokio::test]
async fn a_sidecar_in_any_other_shape_is_refused() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let binary = binary_key("0.1.0");
    let sidecar = format!("{binary}.sha512");
    let digest = ContentHash::sha512(&placed_content("0.1.0", host)).to_hex();
    let line = sidecar_content(&binary, &digest);

    let cases: [(String, ProblemCheck); 5] = [
        // The right digest, naming another file.
        (
            sidecar_content(&binary_key("0.2.0"), &digest),
            |kind| matches!(kind, BackfillProblemKind::SidecarWrongFile(name) if name.contains("0.2.0")),
        ),
        (
            format!("{line}{line}"),
            |kind| matches!(kind, BackfillProblemKind::SidecarMalformed(reason) if reason.contains("one line")),
        ),
        (line.trim_end().to_string(), |kind| {
            matches!(kind, BackfillProblemKind::SidecarMalformed(_))
        }),
        (format!("{digest} {binary}\n"), |kind| {
            matches!(kind, BackfillProblemKind::SidecarMalformed(_))
        }),
        (String::new(), |kind| {
            matches!(kind, BackfillProblemKind::SidecarMalformed(_))
        }),
    ];
    for (content, is_expected) in cases {
        let fixture = Fixture::new();
        seed(&fixture).await;
        write_storage(&fixture, &sidecar, content.as_bytes());
        let error = refused(&fixture).await;
        assert!(!error.is_security_violation(), "{content:?}");
        let BackfillError::Releases { problems } = error else {
            panic!("expected storage problems, got {error:?}");
        };
        let kind = only(problems, &sidecar);
        assert!(is_expected(&kind), "{content:?}: {kind:?}");
    }
}

/// A sidecar is read through the bounded read at the sidecar limit: one byte
/// past it is refused by storage, whatever it holds, and one at the limit is
/// read and parsed.
#[tokio::test]
async fn a_sidecar_past_the_size_limit_is_refused_by_the_bounded_read() {
    /// The backfill's sidecar limit, which it does not export.
    const MAX_SIDECAR_SIZE: usize = 4096;
    if !git_available() {
        return;
    }
    let binary = binary_key("0.1.0");
    let sidecar = format!("{binary}.sha512");

    let oversized = Fixture::new();
    seed(&oversized).await;
    rewrite(&oversized, &sidecar, |mut bytes| {
        bytes.resize(MAX_SIDECAR_SIZE + 1, b'\n');
        bytes
    });
    let error = refused(&oversized).await;
    assert!(!error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &sidecar);
    assert_eq!(
        kind.to_string(),
        format!("storage error: FileStorage: file too large: {sidecar} (4097 bytes, max 4096)")
    );
    assert!(
        matches!(
            &kind,
            BackfillProblemKind::Release(ReleaseError::Storage(StorageError::TooLarge {
                size: 4097,
                max: 4096,
                ..
            }))
        ),
        "{kind:?}"
    );

    let at_limit = Fixture::new();
    seed(&at_limit).await;
    rewrite(&at_limit, &sidecar, |mut bytes| {
        bytes.resize(MAX_SIDECAR_SIZE, b'\n');
        bytes
    });
    let kind = only(refused_problems(&at_limit).await, &sidecar);
    assert!(
        matches!(kind, BackfillProblemKind::SidecarMalformed(reason) if reason.contains("one line")),
        "{kind:?}"
    );
}

#[tokio::test]
async fn a_latest_json_that_names_no_published_version_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    set_latest_json(&fixture.storage(), &ReleaseLayout::self_artifact(), "0.9.0").await;
    let kind = only(refused_problems(&fixture).await, &host_latest());
    assert!(
        matches!(&kind, BackfillProblemKind::LatestVersionUnknown { version } if version == "0.9.0"),
        "{kind:?}"
    );

    let garbled = Fixture::new();
    seed(&garbled).await;
    write_storage(&garbled, &host_latest(), b"{\"version\": 3}");
    let kind = only(refused_problems(&garbled).await, &host_latest());
    assert!(
        matches!(kind, BackfillProblemKind::LatestUnreadable(_)),
        "{kind:?}"
    );
}

/// What storage serves as the latest binary must be the advertised version's
/// binary, for every target it serves one for.
#[tokio::test]
async fn a_latest_copy_that_is_not_the_advertised_binary_is_refused() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let latest_key = ReleaseLayout::self_artifact().latest_binary_key("fuz", host);

    // The copy is another version's binary, with a sidecar that agrees with it.
    let stale = Fixture::new();
    seed(&stale).await;
    let old = placed_content("0.1.0", host);
    write_storage(&stale, &latest_key, &old);
    write_storage(
        &stale,
        &format!("{latest_key}.sha512"),
        sidecar_content(&latest_key, &ContentHash::sha512(&old).to_hex()).as_bytes(),
    );
    let error = refused(&stale).await;
    assert!(error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &latest_key);
    assert!(
        matches!(&kind, BackfillProblemKind::LatestBinaryMismatch { version } if version == "0.2.0"),
        "{kind:?}"
    );

    // The advertised version's target has no latest copy at all.
    let missing = Fixture::new();
    seed(&missing).await;
    std::fs::remove_file(missing.storage_dir.join(&latest_key)).unwrap();
    std::fs::remove_file(missing.storage_dir.join(format!("{latest_key}.sha512"))).unwrap();
    let kind = only(refused_problems(&missing).await, &latest_key);
    assert!(
        matches!(kind, BackfillProblemKind::LatestBinaryMissing { .. }),
        "{kind:?}"
    );

    // A pointer for a target the version it names was not published for.
    let extra = Fixture::new();
    seed(&extra).await;
    let other = other_target();
    let other_pointer = ReleaseLayout::self_artifact().latest_key(other);
    write_storage(&extra, &other_pointer, br#"{"version":"0.2.0"}"#);
    let kind = only(refused_problems(&extra).await, &other_pointer);
    assert!(
        matches!(&kind, BackfillProblemKind::LatestTargetUnknown { version, target }
            if version == "0.2.0" && target == other),
        "{kind:?}"
    );

    // A latest copy for a target with no pointer: nothing says which version
    // it is.
    let unpointed = Fixture::new();
    seed(&unpointed).await;
    let other_latest = ReleaseLayout::self_artifact().latest_binary_key("fuz", other);
    write_storage(&unpointed, &other_latest, b"some binary");
    let kind = only(refused_problems(&unpointed).await, &other_latest);
    assert!(
        matches!(kind, BackfillProblemKind::LatestCopyWithoutPointer),
        "{kind:?}"
    );
}

/// Releases that are published but not advertised — no `latest-<target>.json` — are
/// logged, with no pointer to write.
#[tokio::test]
async fn unadvertised_releases_are_logged_without_a_pointer() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let host = current_target();
    let content = placed_content("0.1.0", host);
    place_self(&fixture, "0.1.0", host, &content, &trusted_key(), NOW, true).await;

    let report = backfill(&fixture, false).await.unwrap();
    assert_eq!(report.pointers, []);
    assert_eq!(fixture.remote_tree(), [HEAD_FILE]);
    assert!(!fixture.checkout.join("latest").exists());
    assert_eq!(fixture.remote_head("main").rows().len(), 1);
}

#[tokio::test]
async fn empty_storage_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    let error = refused(&fixture).await;
    assert!(
        matches!(error, BackfillError::NothingToBackfill),
        "{error:?}"
    );
    assert!(error.hint().unwrap().contains("--storage"));

    // Files that are not releases of a walked stream are still nothing.
    write_storage(&fixture, "README", b"readme");
    write_storage(&fixture, "tools/unknown/unknown-0.1.0-x.manifest.json", b"");
    assert!(matches!(
        refused(&fixture).await,
        BackfillError::NothingToBackfill
    ));
}

/// The tarball a manifest names is what `fuz` installs from: it must be in
/// storage, and be the bytes the manifest pins.
#[tokio::test]
async fn a_missing_or_altered_tarball_is_refused() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let self_tarball = format!("fuz-0.1.0-{host}.tar.gz");
    let tool_tarball = format!("tools/fuzd/fuzd-0.1.0-{host}.tar.gz");

    let missing = Fixture::new();
    seed(&missing).await;
    std::fs::remove_file(missing.storage_dir.join(&tool_tarball)).unwrap();
    let error = refused(&missing).await;
    assert!(!error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &tool_tarball);
    assert!(
        matches!(kind, BackfillProblemKind::TarballMissing),
        "{kind:?}"
    );

    let altered = Fixture::new();
    seed(&altered).await;
    write_storage(&altered, &self_tarball, b"not the tarball that was signed");
    let error = refused(&altered).await;
    assert!(error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &self_tarball);
    assert!(
        matches!(&kind, BackfillProblemKind::TarballMismatch { actual }
            if *actual == ContentHash::blake3(b"not the tarball that was signed")),
        "{kind:?}"
    );
}

/// `signed_at` becomes a row's `published_at` for good and no signature covers
/// it, so it is held to being a timestamp no later than the backfill's clock.
#[tokio::test]
async fn a_signed_at_that_is_not_a_past_timestamp_is_refused() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let key = trusted_key();
    let content = placed_content("0.3.0", host);
    let cases: [(&str, ProblemCheck); 4] = [
        (
            "9999-12-31T23:59:59Z",
            |kind| matches!(kind, BackfillProblemKind::SignedAtInFuture { signed_at, now } if signed_at == "9999-12-31T23:59:59Z" && now == CLOCK),
        ),
        // One second past the clock.
        ("2025-06-01T00:00:01Z", |kind| {
            matches!(kind, BackfillProblemKind::SignedAtInFuture { .. })
        }),
        (
            "yesterday",
            |kind| matches!(kind, BackfillProblemKind::SignedAt(at) if at == "yesterday"),
        ),
        ("2025-01-01 00:00:00Z", |kind| {
            matches!(kind, BackfillProblemKind::SignedAt(_))
        }),
    ];
    for (signed_at, is_expected) in cases {
        let fixture = Fixture::new();
        seed(&fixture).await;
        place_self(&fixture, "0.3.0", host, &content, &key, signed_at, true).await;
        let error = refused(&fixture).await;
        assert!(!error.is_security_violation(), "{signed_at}");
        let BackfillError::Releases { problems } = error else {
            panic!("expected storage problems, got {error:?}");
        };
        let kind = only(problems, &manifest_key("0.3.0"));
        assert!(is_expected(&kind), "{signed_at}: {kind:?}");
    }

    // The clock itself is not the future.
    let fixture = Fixture::new();
    seed(&fixture).await;
    place_self(&fixture, "0.3.0", host, &content, &key, CLOCK, true).await;
    let report = backfill(&fixture, true).await.unwrap();
    assert_eq!(report.rows.last().unwrap().published_at, CLOCK);
}

/// A validly signed manifest whose `content_hash` is not the `v1-<hex>` form a
/// head carries is refused, reported against the manifest's key. The manifest's
/// own validation catches the shape — the same rule a head row is held to
/// (`fuz_artifact::is_content_hash`), applied before the value can name a path.
#[tokio::test]
async fn a_signed_manifest_a_head_cannot_carry_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let host = current_target();
    place_manifest(
        &fixture,
        Release {
            layout: ReleaseLayout::tool("zap"),
            name: "zap",
            version: "1.0.0",
            target: host,
            tool: Some("zap"),
            binary: ("zap", b"zap"),
            content_hash: Some("v1-abc123"),
        },
        &trusted_key(),
        NOW,
    )
    .await;
    let key = ReleaseLayout::tool("zap").manifest_key("zap", "1.0.0", host);
    let kind = only(refused_problems(&fixture).await, &key);
    assert!(
        matches!(
            &kind,
            BackfillProblemKind::Release(ReleaseError::Manifest(
                ManifestError::InvalidContentHash(_)
            ))
        ),
        "{kind:?}"
    );
    assert!(kind.to_string().contains("content hash"), "{kind}");
}

/// The install script downloads `fuz-latest-<target>` without reading
/// `latest-<target>.json`. With no `latest-<target>.json` to say which version that copy is,
/// the copy cannot be checked — and is not passed over.
#[tokio::test]
async fn a_latest_copy_with_no_latest_json_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    std::fs::remove_file(fixture.storage_dir.join(host_latest())).unwrap();
    let layout = ReleaseLayout::self_artifact();
    let host_copy = layout.latest_binary_key("fuz", current_target());
    let other_copy = layout.latest_binary_key("fuz", other_target());
    write_storage(&fixture, &other_copy, b"some binary");
    // Every copy is reported, each at its own key.
    let problems = refused_problems(&fixture).await;
    let mut expected = [host_copy, other_copy];
    expected.sort();
    assert_eq!(
        problems.iter().map(|p| p.key.clone()).collect::<Vec<_>>(),
        expected,
        "{problems:?}"
    );
    for problem in &problems {
        assert!(
            matches!(problem.kind, BackfillProblemKind::LatestCopyWithoutPointer),
            "{problem:?}"
        );
    }
}

/// The sidecar beside the `latest` copy is held to that copy, like the one
/// beside a versioned binary.
#[tokio::test]
async fn a_latest_sidecar_that_disagrees_with_its_copy_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let latest_key = ReleaseLayout::self_artifact().latest_binary_key("fuz", current_target());
    let sidecar = format!("{latest_key}.sha512");
    write_storage(
        &fixture,
        &sidecar,
        sidecar_content(&latest_key, &ContentHash::sha512(b"other bytes").to_hex()).as_bytes(),
    );
    let error = refused(&fixture).await;
    assert!(error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    let kind = only(problems, &sidecar);
    assert!(
        matches!(kind, BackfillProblemKind::SidecarMismatch),
        "{kind:?}"
    );
}

/// A tool stream's `latest-<target>.json` is read too: it must parse, within the size
/// limit, and name a version the stream has a manifest for. No pointer is
/// written for a tool.
#[tokio::test]
async fn a_tool_latest_json_that_names_no_published_version_is_refused() {
    if !git_available() {
        return;
    }
    let latest_key = &ReleaseLayout::tool("fuzd").latest_key(current_target());

    let unknown = Fixture::new();
    seed(&unknown).await;
    // A version the self stream has and this stream does not.
    set_latest_json(&unknown.storage(), &ReleaseLayout::tool("fuzd"), "0.2.0").await;
    let kind = only(refused_problems(&unknown).await, latest_key);
    assert!(
        matches!(&kind, BackfillProblemKind::LatestVersionUnknown { version } if version == "0.2.0"),
        "{kind:?}"
    );

    let garbled = Fixture::new();
    seed(&garbled).await;
    write_storage(&garbled, latest_key, b"not json");
    let kind = only(refused_problems(&garbled).await, latest_key);
    assert!(
        matches!(kind, BackfillProblemKind::LatestUnreadable(_)),
        "{kind:?}"
    );

    // Valid JSON naming the right version, one byte past the size limit: the
    // bounded read refuses it, so what is reported is the storage error.
    let max = usize::try_from(MAX_MANIFEST_SIZE).unwrap();
    for key in [latest_key.as_str(), host_latest().as_str()] {
        let oversized = Fixture::new();
        seed(&oversized).await;
        rewrite(&oversized, key, |mut bytes| {
            bytes.resize(max + 1, b' ');
            bytes
        });
        let error = refused(&oversized).await;
        assert!(!error.is_security_violation(), "{key}");
        let BackfillError::Releases { problems } = error else {
            panic!("expected storage problems, got {error:?}");
        };
        let kind = only(problems, key);
        assert_eq!(
            kind.to_string(),
            format!(
                "storage error: FileStorage: file too large: {key} ({} bytes, max {MAX_MANIFEST_SIZE})",
                MAX_MANIFEST_SIZE + 1
            )
        );
        assert!(
            matches!(
                &kind,
                BackfillProblemKind::Release(ReleaseError::Storage(StorageError::TooLarge { size, max, .. }))
                    if *size == MAX_MANIFEST_SIZE + 1 && *max == MAX_MANIFEST_SIZE
            ),
            "{key}: {kind:?}"
        );

        // At the limit it is read and parsed.
        let at_limit = Fixture::new();
        seed(&at_limit).await;
        rewrite(&at_limit, key, |mut bytes| {
            bytes.resize(max, b' ');
            bytes
        });
        backfill(&at_limit, true).await.unwrap();
    }

    // A tool with a good `latest-<target>.json` gets a row and no pointer.
    let fixture = Fixture::new();
    seed(&fixture).await;
    let report = backfill(&fixture, true).await.unwrap();
    assert_eq!(report.pointers.len(), 1);
    assert!(report.pointers[0].path.starts_with("latest/fuz-"));
}

/// A storage key is whatever a file in storage is named. One that carries a
/// newline, an escape sequence, and a direction override is reported as one
/// escaped line.
#[tokio::test]
async fn a_hostile_storage_key_is_reported_on_one_line() {
    if !git_available() {
        return;
    }
    let hostile = "fuz-x\n  fuz 9.9.9  published_at 2025-01-01T00:00:00Z\u{1b}[2K\u{202e}";

    // As a manifest: a problem.
    let fixture = Fixture::new();
    seed(&fixture).await;
    let manifest = format!("{hostile}.manifest.json");
    write_storage(&fixture, &manifest, b"{}");
    let error = refused(&fixture).await;
    let message = error.to_string();
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    assert_eq!(problems.len(), 1);
    assert_eq!(
        problems[0].key, manifest,
        "the key is kept as storage spells it"
    );
    let lines: Vec<&str> = message.lines().collect();
    assert_eq!(lines.len(), 2, "{message:?}");
    assert!(
        lines[1].starts_with("  fuz-x\\n  fuz 9.9.9  published_at 2025-01-01T00:00:00Z\\u{1b}[2K\\u{202e}.manifest.json: "),
        "{message:?}"
    );
    for forbidden in ['\u{1b}', '\u{202e}'] {
        assert!(!message.contains(forbidden), "{message:?}");
    }

    // As a file no release accounts for: reported, as storage spells it, for
    // the printer to escape.
    let stray = Fixture::new();
    seed(&stray).await;
    write_storage(&stray, hostile, b"stray");
    let report = backfill(&stray, true).await.unwrap();
    assert_eq!(report.unaccounted_keys, [hostile]);
    assert_eq!(
        fuz_sign::printable(hostile),
        "fuz-x\\n  fuz 9.9.9  published_at 2025-01-01T00:00:00Z\\u{1b}[2K\\u{202e}"
    );
}

/// A refused release keeps its own stream's `latest-<target>.json` from being blamed
/// for naming it — and nothing else: other streams' pointers, and the `latest`
/// copy of the flat binary, are still checked.
#[tokio::test]
async fn a_refused_release_hides_only_the_pointer_that_names_it() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let key = trusted_key();
    let fuzd_tarball = format!("tools/fuzd/fuzd-0.1.0-{host}.tar.gz");
    let self_tarball = format!("fuz-0.1.0-{host}.tar.gz");

    // The tool's latest version is the refused one; a good one sits beside
    // it. The refusal is the one problem.
    let named = Fixture::new();
    seed(&named).await;
    place_tool(&named, "fuzd", "0.2.0", host, b"fuzd 0.2.0", &key, LATER).await;
    std::fs::remove_file(named.storage_dir.join(&fuzd_tarball)).unwrap();
    let kind = only(refused_problems(&named).await, &fuzd_tarball);
    assert!(
        matches!(kind, BackfillProblemKind::TarballMissing),
        "{kind:?}"
    );

    // A refusal in the self stream does not excuse a tool's `latest-<target>.json`.
    let across = Fixture::new();
    seed(&across).await;
    std::fs::remove_file(across.storage_dir.join(&self_tarball)).unwrap();
    set_latest_json(&across.storage(), &ReleaseLayout::tool("fuzd"), "0.9.0").await;
    let problems = refused_problems(&across).await;
    assert_eq!(
        problems.iter().map(|p| p.key.as_str()).collect::<Vec<_>>(),
        [
            self_tarball.as_str(),
            ReleaseLayout::tool("fuzd")
                .latest_key(current_target())
                .as_str(),
        ],
        "{problems:?}"
    );

    // Nor does it excuse a swapped `latest` copy of the flat binary — here
    // with a sidecar that agrees with the swapped bytes.
    let swapped = Fixture::new();
    seed(&swapped).await;
    std::fs::remove_file(swapped.storage_dir.join(&self_tarball)).unwrap();
    let latest_key = ReleaseLayout::self_artifact().latest_binary_key("fuz", host);
    write_storage(&swapped, &latest_key, b"not the advertised binary");
    write_storage(
        &swapped,
        &format!("{latest_key}.sha512"),
        sidecar_content(
            &latest_key,
            &ContentHash::sha512(b"not the advertised binary").to_hex(),
        )
        .as_bytes(),
    );
    let error = refused(&swapped).await;
    assert!(error.is_security_violation());
    let BackfillError::Releases { problems } = error else {
        panic!("expected storage problems, got {error:?}");
    };
    assert_eq!(
        problems.iter().map(|p| p.key.as_str()).collect::<Vec<_>>(),
        [self_tarball.as_str(), latest_key.as_str()],
        "{problems:?}"
    );
    assert!(matches!(
        problems[0].kind,
        BackfillProblemKind::TarballMissing
    ));
    assert!(matches!(
        problems[1].kind,
        BackfillProblemKind::LatestBinaryMismatch { .. }
    ));
}

/// Within the self stream, a refused release excuses only what it could
/// explain: the `latest` copy for a target the advertised version has no
/// verified manifest for. With nothing refused, that copy is reported — also
/// when another copy has a problem of its own.
#[tokio::test]
async fn a_refused_target_excuses_only_its_own_latest_copy() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let other = other_target();
    let key = trusted_key();
    let layout = ReleaseLayout::self_artifact();

    // The advertised version on two targets, both advertised; the second
    // target's release is refused. The refusal is the one problem.
    let refused_target = Fixture::new();
    seed(&refused_target).await;
    let content = placed_content("0.2.0", other);
    place_self(&refused_target, "0.2.0", other, &content, &key, LATER, true).await;
    advertise_self(&refused_target, "0.2.0", other, &content).await;
    let other_tarball = format!("fuz-0.2.0-{other}.tar.gz");
    std::fs::remove_file(refused_target.storage_dir.join(&other_tarball)).unwrap();
    let kind = only(refused_problems(&refused_target).await, &other_tarball);
    assert!(
        matches!(kind, BackfillProblemKind::TarballMissing),
        "{kind:?}"
    );

    // Nothing refused: a swapped copy for the host target does not excuse a
    // copy for a target no pointer names a version for.
    let unexplained = Fixture::new();
    seed(&unexplained).await;
    let host_copy = layout.latest_binary_key("fuz", host);
    let stray_copy = layout.latest_binary_key("fuz", "zzz-unknown-target");
    write_storage(&unexplained, &host_copy, b"not the advertised binary");
    std::fs::remove_file(unexplained.storage_dir.join(format!("{host_copy}.sha512"))).unwrap();
    write_storage(&unexplained, &stray_copy, b"some binary");
    let problems = refused_problems(&unexplained).await;
    assert_eq!(
        problems.iter().map(|p| p.key.as_str()).collect::<Vec<_>>(),
        [host_copy.as_str(), stray_copy.as_str()],
        "{problems:?}"
    );
    assert!(matches!(
        problems[0].kind,
        BackfillProblemKind::LatestBinaryMismatch { .. }
    ));
    assert!(matches!(
        problems[1].kind,
        BackfillProblemKind::LatestCopyWithoutPointer
    ));
}

//
// Refusals: the log
//

/// Backfill writes a log's first head and no other: a log that has one —
/// in this checkout, or only on the remote so far — is refused.
#[tokio::test]
async fn a_log_that_already_has_a_head_is_refused() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    backfill(&fixture, false).await.unwrap();
    let head = fixture.checkout_head_bytes().unwrap();

    for dry_run in [true, false] {
        let remote = fixture.remote_subjects();
        let error = backfill(&fixture, dry_run).await.unwrap_err();
        assert!(matches!(error, BackfillError::HeadExists), "{error:?}");
        assert!(!error.is_security_violation());
        assert!(error.hint().unwrap().contains("--log-repo"));
        assert_eq!(fixture.checkout_head_bytes().unwrap(), head);
        assert_eq!(fixture.remote_subjects(), remote);
    }

    // A second checkout that has never fetched: the head is only on the
    // remote until the backfill's own fast-forward brings it.
    let second = fixture.tmp.path().join("second");
    fixture.init_checkout(&second);
    assert!(!second.join(HEAD_FILE).exists());
    let remote = fixture.remote_subjects();
    let error = backfill_release_log(
        &fixture.storage(),
        &fixture.repo_at(&second),
        &trusted_key(),
        CLOCK,
        options(false),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, BackfillError::HeadExists), "{error:?}");
    assert_eq!(fixture.remote_subjects(), remote);
    assert_eq!(std::fs::read(second.join(HEAD_FILE)).unwrap(), head);

    // A head that does not verify is a head all the same: never overwritten.
    let broken = Fixture::new();
    seed(&broken).await;
    std::fs::write(broken.checkout.join(HEAD_FILE), b"not a head").unwrap();
    broken.commit_all_and_push("a broken head");
    let error = refused(&broken).await;
    assert!(matches!(error, BackfillError::HeadExists), "{error:?}");
    assert_eq!(broken.checkout_head_bytes().unwrap(), b"not a head");

    // And one a local commit removed from the work tree is still on the remote.
    let removed = Fixture::new();
    seed(&removed).await;
    backfill(&removed, false).await.unwrap();
    removed.git(&["rm", "--quiet", HEAD_FILE]);
    removed.git(&["commit", "--quiet", "-m", "remove the head"]);
    let error = backfill(&removed, false).await.unwrap_err();
    assert!(matches!(error, BackfillError::HeadExists), "{error:?}");
    assert!(!removed.checkout.join(HEAD_FILE).exists());
}

/// The checkout requirements of a publish's log write apply to a backfill —
/// dry run included — through the same checks.
#[tokio::test]
async fn an_unfit_checkout_or_key_is_refused_on_a_dry_run_too() {
    if !git_available() {
        return;
    }
    let cases: [(Change, LogCheck); 3] = [
        (
            |f| {
                f.git(&["config", "--unset", "branch.main.merge"]);
            },
            |e| matches!(e, LogWriteError::NoUpstream { .. }),
        ),
        (
            |f| {
                std::fs::create_dir(f.checkout.join("latest")).unwrap();
                std::fs::write(f.checkout.join("latest/stray.sha512"), b"x").unwrap();
            },
            |e| matches!(e, LogWriteError::Dirty { .. }),
        ),
        (
            |f| {
                std::os::unix::fs::symlink("/dev/null", f.checkout.join(HEAD_FILE)).unwrap();
                f.git(&["add", HEAD_FILE]);
                f.git(&["commit", "--quiet", "-m", "a link"]);
            },
            |e| matches!(e, LogWriteError::UnsafePath { .. }),
        ),
    ];
    for (unfit, is_expected) in cases {
        for dry_run in [true, false] {
            let fixture = Fixture::new();
            seed(&fixture).await;
            unfit(&fixture);
            let remote = fixture.remote_subjects();
            let error = backfill(&fixture, dry_run).await.unwrap_err();
            let BackfillError::Log(log_error) = &error else {
                panic!("expected a log write error, got {error:?}");
            };
            assert!(is_expected(log_error), "{log_error:?}");
            assert_eq!(fixture.remote_subjects(), remote);
        }
    }

    // A checkout that is not there at all.
    let fixture = Fixture::new();
    seed(&fixture).await;
    let error = backfill_release_log(
        &fixture.storage(),
        &fixture.repo_at(&fixture.tmp.path().join("no-such-checkout")),
        &trusted_key(),
        CLOCK,
        options(true),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        BackfillError::Log(LogWriteError::CheckoutMissing(_))
    ));

    // A signing key this binary does not trust could sign no head a reader
    // accepts: refused before storage is read, on a dry run as on a real one.
    for dry_run in [true, false] {
        let error = backfill_release_log(
            &fixture.storage(),
            &fixture.repo(),
            &untrusted_key(),
            CLOCK,
            options(dry_run),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                error,
                BackfillError::Log(LogWriteError::UntrustedKey { .. })
            ),
            "{error:?}"
        );
        assert!(error.is_security_violation());
        assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
        assert_eq!(fixture.checkout_head_bytes(), None);
    }
}

/// A push the remote refuses leaves the head committed and unpushed, and the
/// error says so. A later backfill reports the waiting commit as what it is,
/// and the next publish into the log pushes it along with its own.
#[tokio::test]
async fn a_refused_push_leaves_a_head_the_next_publish_pushes() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let host = current_target();
    fixture.reject_pushes();
    let error = backfill(&fixture, false).await.unwrap_err();
    assert!(
        matches!(&error, BackfillError::Unpublished(LogWriteError::Git { command, .. }) if command == "push"),
        "{error:?}"
    );
    let hint = error.hint().unwrap();
    assert!(
        hint.contains("git push") && hint.contains("--log-repo"),
        "{hint}"
    );
    assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    assert_eq!(
        fixture.git(&["log", "--format=%s"]),
        "log: backfill 3 releases seq 1"
    );

    // The remote accepts again. A backfill does not write a second head; it
    // says the first one is waiting.
    fixture.accept_pushes();
    for dry_run in [true, false] {
        let checkout = checkout_state(&fixture);
        let error = backfill(&fixture, dry_run).await.unwrap_err();
        assert!(matches!(error, BackfillError::HeadUnpublished), "{error:?}");
        let hint = error.hint().unwrap();
        assert!(
            hint.contains("git push") && hint.contains("--log-repo"),
            "{hint}"
        );
        assert_eq!(checkout_state(&fixture), checkout);
        assert_eq!(fixture.remote_subjects(), Vec::<String>::new());
    }

    // Publishing the next release pushes both commits and reads the log back.
    let published = publish_self(&fixture, "0.3.0").await.unwrap();
    let logged = published.logged.unwrap();
    assert_eq!(
        (logged.seq, logged.advanced, logged.pushed),
        (2, true, true)
    );
    assert_eq!(
        fixture.remote_subjects(),
        [
            "log: backfill 3 releases seq 1".to_string(),
            format!("log: fuz 0.3.0 {host} seq 2"),
        ]
    );
    let backfilled = fixture.remote_head("main~1");
    let next = fixture.remote_head("main");
    assert_eq!((backfilled.seq(), next.seq()), (1, 2));
    assert_eq!(
        check_successor(&backfilled, &next),
        Ok(Succession::Advanced)
    );
    assert_eq!(next.rows().len(), 4);
}

/// A plain `git push` of the waiting commit completes the backfill too.
#[tokio::test]
async fn a_waiting_head_can_be_pushed_by_hand() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    fixture.reject_pushes();
    backfill(&fixture, false).await.unwrap_err();
    fixture.accept_pushes();
    fixture.git(&["push", "--quiet"]);
    assert_eq!(fixture.remote_head("main").rows().len(), 3);
    // The log has its head: a backfill is refused as for any log with one.
    assert!(matches!(
        backfill(&fixture, false).await,
        Err(BackfillError::HeadExists)
    ));
}

/// A push that goes through with a commit that does not hold the head — a hook
/// rewrote it — is not "unpushed": the commit is public. The error says that,
/// and what it says to do works: revert, push, and backfill again.
#[tokio::test]
async fn a_pushed_commit_without_the_head_is_public_and_recoverable() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        "#!/bin/sh\nprintf 'rewritten by a hook\\n' > head.json\ngit add head.json\n",
    );
    let error = backfill(&fixture, false).await.unwrap_err();
    assert!(
        matches!(
            &error,
            BackfillError::PublishedWrong(LogWriteError::PublishedHead(ReleaseLogError::Parse(_)))
        ),
        "{error:?}"
    );
    let hint = error.hint().unwrap();
    assert!(hint.contains("on the remote"), "{hint}");
    assert!(hint.contains("uncommitted"), "{hint}");
    assert!(hint.contains("git revert --no-edit HEAD"), "{hint}");
    assert_eq!(
        fixture.remote_subjects(),
        ["log: backfill 3 releases seq 1"]
    );
    assert_eq!(
        fixture.remote_git(&["show", &format!("main:{HEAD_FILE}")]),
        "rewritten by a hook"
    );

    // What the hint says, as written.
    std::fs::remove_file(fixture.checkout.join(".git/hooks/pre-commit")).unwrap();
    // The hook's commit left the index holding the head that was written and
    // the work tree holding the hook's: uncommitted changes, discarded first.
    assert_ne!(fixture.git(&["status", "--porcelain"]), "");
    fixture.git(&["reset", "--quiet", "--", "head.json", "latest"]);
    fixture.git(&["checkout", "--", "head.json", "latest"]);
    assert_eq!(fixture.git(&["status", "--porcelain"]), "");
    fixture.git(&["revert", "--no-edit", "HEAD"]);
    fixture.git(&["push", "--quiet"]);
    assert_eq!(fixture.remote_tree(), Vec::<String>::new());

    // The upstream has commits and no head: a log that can take its first.
    let report = backfill(&fixture, false).await.unwrap();
    assert!(report.pushed);
    assert_eq!(fixture.remote_subjects().len(), 3);
    let head = fixture.remote_head("main");
    assert_eq!((head.seq(), head.rows().len()), (1, 3));
    assert_eq!(
        fixture.checkout_head_bytes().unwrap(),
        report.head_json.as_bytes()
    );
}

/// The read-back compares the pushed head's rows with the ones written, not
/// just its signature: a hook that commits some other validly signed head is
/// caught.
#[tokio::test]
async fn a_pushed_head_with_other_rows_is_caught_by_the_read_back() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    let key = trusted_key();
    let blake3 = ContentHash::blake3(b"another release");
    let other = plan_genesis(
        &[BackfilledTarget {
            name: "fuzd".to_string(),
            version: "9.9.9".to_string(),
            target: X86.to_string(),
            signed_at: NOW.to_string(),
            pins: TargetRow {
                content_hash: format!("v1-{}", blake3.to_hex()),
                binaries: BTreeMap::from([("fuzd".to_string(), blake3)]),
                sha512: None,
            },
        }],
        &[],
        &public_key(&key),
        CLOCK,
    )
    .unwrap();
    let other = sign_genesis(other.head, &key, CLOCK).unwrap();
    let swapped = fixture.tmp.path().join("swapped-head.json");
    std::fs::write(&swapped, other.to_json().unwrap()).unwrap();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!(
            "#!/bin/sh\ncp '{}' head.json\ngit add head.json\n",
            swapped.display()
        ),
    );

    let error = backfill(&fixture, false).await.unwrap_err();
    match &error {
        BackfillError::PublishedWrong(LogWriteError::NotPublished {
            name,
            version,
            detail,
            ..
        }) => {
            // The first row the pushed head lacks.
            assert_eq!((name.as_str(), version.as_str()), ("fuz", "0.1.0"));
            assert!(detail.contains("head.json"), "{detail}");
        }
        other => panic!("expected the read-back to fail, got {other:?}"),
    }
    // The pushed head verifies — it is simply not the backfilled one.
    assert_eq!(fixture.remote_head("main").rows().len(), 1);
}

/// A headless log whose last commit tracks a `latest/` file the first head
/// would not write is refused: that file would be a pointer no head vouched
/// for. One the first head does write is simply overwritten.
#[tokio::test]
async fn a_stray_tracked_pointer_is_refused() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let fixture = Fixture::new();
    seed(&fixture).await;
    std::fs::create_dir(fixture.checkout.join("latest")).unwrap();
    std::fs::write(
        fixture.checkout.join("latest/fuz-other-target.sha512"),
        "a pointer\n",
    )
    .unwrap();
    // A path git would quote in its default listing.
    std::fs::write(fixture.checkout.join("latest/fuz-é.sha512"), "a pointer\n").unwrap();
    fixture.commit_all_and_push("a pointer and no head");
    for dry_run in [true, false] {
        let checkout = checkout_state(&fixture);
        let remote = fixture.remote_subjects();
        let error = backfill(&fixture, dry_run).await.unwrap_err();
        match &error {
            BackfillError::StrayPointers { paths } => {
                assert_eq!(
                    paths,
                    &[
                        "latest/fuz-other-target.sha512".to_string(),
                        "latest/fuz-é.sha512".to_string(),
                    ]
                );
            }
            other => panic!("expected the stray pointer, got {other:?}"),
        }
        assert!(error.hint().unwrap().contains("git rm"));
        // Reported as itself: one line, the name as it is.
        assert!(
            error.to_string().ends_with("\n  latest/fuz-é.sha512"),
            "{error}"
        );
        assert_eq!(checkout_state(&fixture), checkout);
        assert_eq!(fixture.remote_subjects(), remote);
    }

    // What the hint says: remove it with a commit, push, run again.
    fixture.git(&[
        "rm",
        "--quiet",
        "latest/fuz-other-target.sha512",
        "latest/fuz-é.sha512",
    ]);
    fixture.git(&["commit", "--quiet", "-m", "remove the pointer"]);
    fixture.git(&["push", "--quiet"]);
    backfill(&fixture, false).await.unwrap();
    assert_eq!(
        fixture.remote_tree(),
        [HEAD_FILE.to_string(), format!("latest/fuz-{host}.sha512")]
    );

    // A tracked file at a path the first head writes is replaced by it.
    let replaced = Fixture::new();
    seed(&replaced).await;
    let pointer = format!("latest/fuz-{host}.sha512");
    std::fs::create_dir(replaced.checkout.join("latest")).unwrap();
    std::fs::write(replaced.checkout.join(&pointer), "stale\n").unwrap();
    replaced.commit_all_and_push("a stale pointer and no head");
    let report = backfill(&replaced, false).await.unwrap();
    assert_eq!(
        replaced.remote_git(&["show", &format!("main:{pointer}")]),
        report.pointers[0].content.trim_end()
    );
}

/// The read-back checks every row and every pointer, to the last: a hook that
/// commits a validly signed head lacking only the last row, or that rewrites
/// only the second target's pointer, is caught.
#[tokio::test]
async fn the_read_back_reaches_the_last_row_and_the_last_pointer() {
    if !git_available() {
        return;
    }
    let host = current_target();
    let other = other_target();
    let key = trusted_key();

    // A head with every row but the last.
    let fixture = Fixture::new();
    seed(&fixture).await;
    let review = backfill(&fixture, true).await.unwrap();
    let (last, rest) = review.rows.split_last().unwrap();
    let shorter = sign_genesis(
        HeadUnsigned {
            format: HEAD_FORMAT_VERSION,
            seq: 1,
            keys: vec![KeyRecord {
                public_key: public_key(&key),
                added_at: CLOCK.to_string(),
                retired_at: None,
            }],
            rows: rest.to_vec(),
        },
        &key,
        CLOCK,
    )
    .unwrap();
    let swapped = fixture.tmp.path().join("shorter-head.json");
    std::fs::write(&swapped, shorter.to_json().unwrap()).unwrap();
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!(
            "#!/bin/sh\ncp '{}' head.json\ngit add head.json\n",
            swapped.display()
        ),
    );
    let error = backfill(&fixture, false).await.unwrap_err();
    match &error {
        BackfillError::PublishedWrong(LogWriteError::NotPublished { name, version, .. }) => {
            assert_eq!((name, version), (&last.name, &last.version));
        }
        other => panic!("expected the read-back to fail, got {other:?}"),
    }
    assert_eq!(fixture.remote_head("main").rows(), rest);

    // Two targets, two pointers; the hook rewrites only the second.
    let fixture = Fixture::new();
    seed(&fixture).await;
    let content = placed_content("0.2.0", other);
    place_self(&fixture, "0.2.0", other, &content, &key, LATER, true).await;
    advertise_self(&fixture, "0.2.0", other, &content).await;
    let second = format!("latest/fuz-{}.sha512", host.max(other));
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        &format!("#!/bin/sh\nprintf 'rewritten\\n' > '{second}'\ngit add '{second}'\n"),
    );
    let error = backfill(&fixture, false).await.unwrap_err();
    assert!(
        matches!(
            &error,
            BackfillError::PublishedWrong(LogWriteError::NotPublished { detail, .. })
                if detail.contains("latest/")
        ),
        "{error:?}"
    );
    // The first pointer and the head were pushed as written.
    assert_eq!(fixture.remote_head("main").rows().len(), 3);
    assert_eq!(
        fixture.remote_git(&["show", &format!("main:{second}")]),
        "rewritten"
    );
}

/// A read-back that cannot read — here the checkout's own copy of the pushed
/// `head.json` object is corrupted while the remote receives the push — is
/// not reported as a pushed head that is wrong. The push landed; what the
/// error says to do is run the backfill again, which finds the log's head.
#[tokio::test]
async fn a_read_back_that_cannot_read_is_reported_as_that() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    // Runs in the remote once it has the commit, before the push returns.
    fixture.install_post_receive(&format!(
        "#!/bin/sh\n\
         unset GIT_DIR GIT_QUARANTINE_PATH GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES\n\
         cd '{checkout}' || exit 0\n\
         blob=$(git rev-parse HEAD:head.json) || exit 0\n\
         file=.git/objects/$(printf %s \"$blob\" | cut -c1-2)/$(printf %s \"$blob\" | cut -c3-)\n\
         chmod u+w \"$file\" && printf 'not an object' > \"$file\"\n",
        checkout = fixture.checkout.display()
    ));

    let error = backfill(&fixture, false).await.unwrap_err();
    assert!(
        matches!(&error, BackfillError::ReadBackFailed(LogWriteError::Git { command, .. }) if command == "cat-file"),
        "{error:?}"
    );
    assert!(!error.is_security_violation());
    let hint = error.hint().unwrap();
    assert!(hint.contains("Run the backfill again"), "{hint}");
    assert!(!hint.contains("revert"), "{hint}");

    // The pushed commit does hold the head.
    assert_eq!(
        fixture.remote_subjects(),
        ["log: backfill 3 releases seq 1"]
    );
    assert_eq!(fixture.remote_head("main").rows().len(), 3);

    // Running it again, as the hint says, from a clone that can read.
    let clone = fixture.tmp.path().join("fresh");
    fixture.init_checkout(&clone);
    let again = backfill_release_log(
        &fixture.storage(),
        &fixture.repo_at(&clone),
        &trusted_key(),
        CLOCK,
        options(false),
    )
    .await
    .unwrap_err();
    assert!(matches!(again, BackfillError::HeadExists), "{again:?}");
}

/// A commit that fails is rolled back: the checkout is as it was, and the
/// backfill runs again once the cause is gone.
#[tokio::test]
async fn a_failed_commit_is_rolled_back_and_the_backfill_can_run_again() {
    if !git_available() {
        return;
    }
    let fixture = Fixture::new();
    seed(&fixture).await;
    Fixture::install_hook(
        &fixture.checkout.join(".git"),
        "pre-commit",
        "#!/bin/sh\necho 'commit refused by the test hook' >&2\nexit 1\n",
    );
    let error = refused(&fixture).await;
    assert!(
        matches!(&error, BackfillError::Log(LogWriteError::Git { command, .. }) if command == "commit"),
        "{error:?}"
    );
    assert!(!fixture.checkout.join(HEAD_FILE).exists());
    assert!(!fixture.checkout.join("latest").exists());

    std::fs::remove_file(fixture.checkout.join(".git/hooks/pre-commit")).unwrap();
    let report = backfill(&fixture, false).await.unwrap();
    assert!(report.pushed);
    assert_eq!(fixture.remote_head("main").rows().len(), 3);
}

//
// Size
//

/// A head past the size limit is refused when it is signed, before anything
/// is written. Built in memory: the limit is on the head document, however
/// the releases were read.
#[test]
fn a_head_past_the_size_limit_is_refused_before_anything_is_written() {
    trust();
    let key = trusted_key();
    let target = |index: usize| {
        let content = format!("fuzd build {index}");
        let blake3 = ContentHash::blake3(content.as_bytes());
        BackfilledTarget {
            name: "fuzd".to_string(),
            version: format!("0.{index}.0"),
            target: X86.to_string(),
            signed_at: NOW.to_string(),
            pins: TargetRow {
                content_hash: format!("v1-{}", blake3.to_hex()),
                binaries: BTreeMap::from([("fuzd".to_string(), blake3)]),
                sha512: None,
            },
        }
    };

    // Comfortably under the limit: signed and verified.
    let few: Vec<BackfilledTarget> = (0..50).map(target).collect();
    let plan = plan_genesis(&few, &[], &public_key(&key), CLOCK).unwrap();
    let head = sign_genesis(plan.head, &key, CLOCK).unwrap();
    let row_size = head.to_json().unwrap().len() / 50;
    assert_eq!(head.rows().len(), 50);

    // Enough rows to pass it.
    let count = usize::try_from(MAX_HEAD_SIZE).unwrap() / row_size + 50;
    let many: Vec<BackfilledTarget> = (0..count).map(target).collect();
    let plan = plan_genesis(&many, &[], &public_key(&key), CLOCK).unwrap();
    let error = sign_genesis(plan.head, &key, CLOCK).unwrap_err();
    match &error {
        BackfillError::HeadTooLarge { size, max } => {
            assert!(size > max, "{size} > {max}");
            assert_eq!(*max, MAX_HEAD_SIZE);
        }
        other => panic!("expected a size refusal, got {other:?}"),
    }
    assert!(!error.is_security_violation());
    assert!(error.hint().unwrap().contains("cargo xtask prune"));

    // An untrusted key signs no head either.
    let plan = plan_genesis(&few, &[], &public_key(&untrusted_key()), CLOCK).unwrap();
    assert!(matches!(
        sign_genesis(plan.head, &untrusted_key(), CLOCK),
        Err(BackfillError::Log(LogWriteError::SignedHead(_)))
    ));
}
