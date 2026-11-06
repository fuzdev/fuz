//! The release log check, end to end: publish a real signed release, serve a
//! real signed head, and install through the two funnels the check guards —
//! `fetch_version` (the self artifact) and `install_tool`.
//!
//! Heads and manifests are signed and verified for real, with the signing key
//! admitted through `fuz_crypto`'s dev-dependency-only `test_trust_anchor`
//! seam, and the fuz home is redirected through `fuz_home`'s
//! `test_home_override` — the seams `signed_trust.rs` uses. A witness is a
//! local directory holding `head.json`, or a loopback HTTP listener where the
//! transport itself is what is under test.
//!
//! The pure halves (`reconcile_heads`, `row_verdict`) are covered here too:
//! they take verified heads and a verified manifest, and only a real signature
//! produces either.
//!
//! The co-signature check is covered here as well: a witness directory also
//! holding a `witness` file, signed by a test SSH key that the policy is
//! handed as that origin's witness key.
//!
//! The other callers of the check are covered at the same level, since the
//! `fuz` binary trusts only its embedded keys and so cannot be handed a head a
//! test signed: the read-only check an update check runs, the check of a local
//! binary that `fuz self bootstrap` runs, the installed release's standing read
//! from the cached head, and an upgrade whose latest release is the installed,
//! revoked one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{
    NOW, host_binary, other_target, other_witness_key, public_key, sign_sshsig, trust, trusted_key,
    untrusted_key, witness_key,
};
use fuz_artifact::{ArtifactMeta, ArtifactOutputs};
use fuz_crypto::ContentHash;
use fuz_home::FuzHomeError;
use fuz_release::{
    CO_SIGN_NAMESPACE, CacheProblem, CoSignCoverage, CoSignProblem, CoSignReport, CurrentVersion,
    FetchOptions, HEAD_KEY, Head, HeadSource, HeadUnsigned, HeadViolation, InstalledStanding,
    KeyRecord, LocalSelfBinary, LogCheck, LogContradiction, LogOrigins, MAX_HEAD_SIZE,
    MAX_WITNESS_SIZE, Manifest, ManifestError, PinnedBy, ReleaseError, ReleaseLayout,
    ReleaseLogError, ReleaseLogPolicy, ReleaseLogReport, ReleasePins, ReleaseRow, RowStatus,
    RowVerdict, SELF_NAME, TargetField, TargetRow, ToolInstallOptions, VerifiedHead,
    VerifiedManifest, WITNESS_KEY, cached_installed_standing, check_bootstrap_binary,
    check_latest_self, check_latest_tool, check_release_log_read_only, current_target,
    fetch_latest, fetch_version, head_cache_path, install_tool, installed_standing, is_revoked,
    reconcile_heads, resolve_current_self, resolve_log, resolve_log_read_only, row_verdict,
};
use fuz_sign::{PublishOptions, publish_artifact, publish_tool, sign_head};
use fuz_storage::{FileStorage, Storage, StorageBackendKind, StorageError};
use fuz_sys::secure_file::SecureFileError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serializes the whole file: the home override is a process global and cargo
/// runs tests on parallel threads. A tokio mutex so it is held across `.await`
/// and does not poison when an assertion panics. The trust anchor needs no
/// serialization — `common::trust` registers once and nothing here clears it.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A predicate over the violation a contradiction carries.
type ExpectViolation = fn(&HeadViolation) -> bool;

/// A predicate over the reason a witness's head is unusable.
type ExpectHeadError = fn(&ReleaseLogError) -> bool;

/// The tool the tool funnel installs.
const TOOL: &str = "fuzf";

//
// World: a home, release storage, and witnesses, in one temp dir
//

struct World {
    tmp: tempfile::TempDir,
    home: PathBuf,
    storage_dir: PathBuf,
    _serial: tokio::sync::MutexGuard<'static, ()>,
}

/// Create `path` at `0700` whatever the process umask is.
fn secure_dir(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

impl World {
    /// Lock the suite, make the dirs with stated modes, trust the test key,
    /// and point the fuz home at this world's.
    async fn new() -> Self {
        let serial = SERIAL.lock().await;
        trust();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let home = tmp.path().join("home");
        let storage_dir = tmp.path().join("storage");
        secure_dir(&home);
        secure_dir(&storage_dir);
        fuz_home::set_fuz_home_override_for_testing(&home);
        Self {
            tmp,
            home,
            storage_dir,
            _serial: serial,
        }
    }

    fn storage(&self) -> FileStorage {
        FileStorage::new(&self.storage_dir).unwrap()
    }

    /// A witness directory (empty until a head is served into it).
    fn witness(&self, name: &str) -> PathBuf {
        let dir = self.tmp.path().join(name);
        if !dir.exists() {
            secure_dir(&dir);
        }
        dir
    }

    fn cache_path(&self) -> PathBuf {
        self.home.join("state").join("release_log").join(HEAD_KEY)
    }

    /// What an install changes: the artifact store, the tool store, `bin/`,
    /// and `current` — every path with its kind and content. The release log
    /// cache is deliberately outside it: a refusal may still record the head
    /// it refused on.
    fn installed(&self) -> BTreeMap<String, String> {
        fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) {
            let Ok(meta) = std::fs::symlink_metadata(path) else {
                return;
            };
            let key = path.strip_prefix(root).unwrap().display().to_string();
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(path).unwrap();
                out.insert(key, format!("-> {}", target.display()));
            } else if meta.is_dir() {
                out.insert(key, "dir".to_string());
                for entry in std::fs::read_dir(path).unwrap() {
                    walk(root, &entry.unwrap().path(), out);
                }
            } else {
                let bytes = std::fs::read(path).unwrap();
                out.insert(key, blake3::hash(&bytes).to_hex().to_string());
            }
        }
        let mut out = BTreeMap::new();
        for top in ["artifacts", "tools", "bin", "current"] {
            walk(&self.home, &self.home.join(top), &mut out);
        }
        out
    }
}

impl Drop for World {
    fn drop(&mut self) {
        fuz_home::clear_fuz_home_override_for_testing();
    }
}

//
// Funnels
//

/// The two install funnels. Every matrix row runs through both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Funnel {
    SelfArtifact,
    Tool,
}

const FUNNELS: [Funnel; 2] = [Funnel::SelfArtifact, Funnel::Tool];

#[derive(Debug, Clone, Copy, Default)]
struct Flags {
    allow_downgrade: bool,
    force: bool,
}

impl Funnel {
    /// The release's row name in the log.
    const fn name(self) -> &'static str {
        match self {
            Self::SelfArtifact => SELF_NAME,
            Self::Tool => TOOL,
        }
    }

    /// Publish `version` (no log repo) and return its signed manifest as
    /// stored. A tool is published with `binaries` (a name each, distinct
    /// bytes); the self artifact always holds exactly `fuz`.
    async fn publish_with(self, world: &World, version: &str, binaries: &[&str]) -> Manifest {
        let storage = world.storage();
        let source = tempfile::tempdir_in(world.tmp.path()).unwrap();
        let options = PublishOptions::default();
        match self {
            Self::SelfArtifact => {
                let content = host_binary(format!("fuz binary bytes for {version}").as_bytes());
                std::fs::write(source.path().join("fuz"), &content).unwrap();
                let outputs = ArtifactOutputs {
                    fuz: ContentHash::blake3(&content),
                };
                let meta =
                    ArtifactMeta::new_remote(outputs.content_hash(), version.to_string(), outputs);
                meta.write(source.path()).unwrap();
                publish_artifact(&storage, &meta, source.path(), &trusted_key(), &options)
                    .await
                    .unwrap();
            }
            Self::Tool => {
                let binaries: Vec<(String, PathBuf)> = binaries
                    .iter()
                    .map(|name| {
                        let path = source.path().join(name);
                        std::fs::write(
                            &path,
                            host_binary(format!("{name} bytes for {version}").as_bytes()),
                        )
                        .unwrap();
                        ((*name).to_string(), path)
                    })
                    .collect();
                publish_tool(&storage, TOOL, version, &binaries, &trusted_key(), &options)
                    .await
                    .unwrap();
            }
        }
        self.manifest(world, version).await
    }

    async fn publish(self, world: &World, version: &str) -> Manifest {
        self.publish_with(world, version, &[TOOL]).await
    }

    /// The stored manifest for `version`.
    async fn manifest(self, world: &World, version: &str) -> Manifest {
        let layout = match self {
            Self::SelfArtifact => ReleaseLayout::self_artifact(),
            Self::Tool => ReleaseLayout::tool(TOOL),
        };
        let key = layout.manifest_key(self.name(), version, current_target());
        Manifest::from_json(&world.storage().download(&key).await.unwrap()).unwrap()
    }

    /// Install `version` through this funnel under `policy`; on success, what
    /// the release log check reported.
    async fn install(
        self,
        storage: &impl Storage,
        version: &str,
        flags: Flags,
        policy: ReleaseLogPolicy,
    ) -> Result<LogCheck, ReleaseError> {
        match self {
            Self::SelfArtifact => {
                let options = FetchOptions {
                    allow_downgrade: flags.allow_downgrade,
                    force: flags.force,
                    release_log: policy,
                };
                Ok(fetch_version(storage, version, &options).await?.release_log)
            }
            Self::Tool => {
                let options = ToolInstallOptions {
                    version: Some(version),
                    allow_downgrade: flags.allow_downgrade,
                    force: flags.force,
                    release_log: policy,
                };
                Ok(install_tool(storage, TOOL, &options).await?.release_log)
            }
        }
    }
}

/// A storage wrapper counting tarball downloads, so a test can assert a
/// refusal came before any release bytes were fetched.
struct Counting<S> {
    inner: S,
    tarballs: AtomicUsize,
}

impl<S> Counting<S> {
    const fn new(inner: S) -> Self {
        Self {
            inner,
            tarballs: AtomicUsize::new(0),
        }
    }

    fn tarballs(&self) -> usize {
        self.tarballs.load(Ordering::SeqCst)
    }
}

impl<S: Storage> Storage for Counting<S> {
    fn backend_kind(&self) -> StorageBackendKind {
        self.inner.backend_kind()
    }
    async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        self.inner.upload(path, data).await
    }
    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.download(path).await
    }
    async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        self.inner.download_capped(path, max).await
    }
    async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
        self.tarballs.fetch_add(1, Ordering::SeqCst);
        self.inner.download_to_file(path, dest).await
    }
    async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
        self.inner.upload_file(path, src).await
    }
    async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        self.inner.exists(path).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        self.inner.list(prefix).await
    }
    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        self.inner.delete(path).await
    }
}

//
// Heads
//

/// What `manifest` pins, as a log row records it.
fn pins(manifest: &Manifest) -> TargetRow {
    TargetRow {
        content_hash: manifest.content_hash.clone(),
        binaries: manifest
            .binaries
            .iter()
            .map(|(name, hash)| (name.clone(), hash.clone()))
            .collect(),
        sha512: None,
    }
}

fn row(name: &str, version: &str, status: RowStatus, targets: &[(&str, TargetRow)]) -> ReleaseRow {
    ReleaseRow {
        name: name.to_string(),
        version: version.to_string(),
        status,
        published_at: NOW.to_string(),
        targets: targets
            .iter()
            .map(|(target, entry)| ((*target).to_string(), entry.clone()))
            .collect(),
    }
}

/// The row a publish records for `manifest`.
fn ok_row(name: &str, manifest: &Manifest) -> ReleaseRow {
    row(
        name,
        &manifest.version,
        RowStatus::Ok,
        &[(current_target(), pins(manifest))],
    )
}

/// A row for some other release, so a head is never empty.
fn filler_row() -> ReleaseRow {
    let hash = ContentHash::blake3(b"zap");
    row(
        "zap",
        "9.9.9",
        RowStatus::Ok,
        &[(
            current_target(),
            TargetRow {
                content_hash: format!("v1-{}", hash.to_hex()),
                binaries: BTreeMap::from([("zap".to_string(), hash)]),
                sha512: None,
            },
        )],
    )
}

fn head(seq: u64, rows: Vec<ReleaseRow>) -> HeadUnsigned {
    HeadUnsigned {
        format: 1,
        seq,
        keys: vec![KeyRecord {
            public_key: public_key(&trusted_key()),
            added_at: NOW.to_string(),
            retired_at: None,
        }],
        rows,
    }
}

fn signed(unsigned: HeadUnsigned) -> Head {
    sign_head(unsigned, &trusted_key(), NOW).unwrap()
}

fn verified(unsigned: HeadUnsigned) -> VerifiedHead {
    signed(unsigned).verify_signature().unwrap()
}

/// Write `unsigned`, signed, as the head a witness directory serves.
fn serve(witness: &Path, unsigned: HeadUnsigned) -> VerifiedHead {
    let head = signed(unsigned);
    std::fs::write(witness.join(HEAD_KEY), head.to_json().unwrap()).unwrap();
    head.verify_signature().unwrap()
}

/// Take the head away: the witness now answers "not found".
fn stop_serving(witness: &Path) {
    std::fs::remove_file(witness.join(HEAD_KEY)).unwrap();
}

fn uri(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn enforced(origins: &[&str]) -> ReleaseLogPolicy {
    enforced_with_keys(origins, &[])
}

/// An enforced policy whose origins are matched against `witness_keys`.
fn enforced_with_keys(origins: &[&str], witness_keys: &[(&str, [u8; 32])]) -> ReleaseLogPolicy {
    let policy =
        ReleaseLogPolicy::from_env_values(Some(&origins.join(",")), None, witness_keys).unwrap();
    assert!(
        matches!(policy, ReleaseLogPolicy::Enforced(_)),
        "{policy:?}"
    );
    policy
}

fn origins(list: &[&str]) -> LogOrigins {
    origins_with_keys(list, &[])
}

fn origins_with_keys(list: &[&str], witness_keys: &[(&str, [u8; 32])]) -> LogOrigins {
    match enforced_with_keys(list, witness_keys) {
        ReleaseLogPolicy::Enforced(origins) => origins,
        other => panic!("expected an enforced policy, got {other:?}"),
    }
}

#[track_caller]
fn confirmed(check: LogCheck) -> ReleaseLogReport {
    match check {
        LogCheck::Confirmed(report) => report,
        other => panic!("expected a confirmed release, got {other:?}"),
    }
}

#[track_caller]
fn log_error(result: Result<LogCheck, ReleaseError>) -> ReleaseLogError {
    match result {
        Err(ReleaseError::ReleaseLog(error)) => error,
        other => panic!("expected a release log error, got {other:?}"),
    }
}

#[track_caller]
fn resolve_error<T: std::fmt::Debug>(result: Result<T, ReleaseError>) -> ReleaseLogError {
    match result {
        Err(ReleaseError::ReleaseLog(error)) => error,
        other => panic!("expected a release log error, got {other:?}"),
    }
}

/// A hard failure: a refusal, classified as a security violation, never the
/// soft "unconfirmed".
#[track_caller]
fn assert_hard(error: &ReleaseLogError) {
    assert!(error.is_security_violation(), "{error}");
    assert!(!error.is_unconfirmed(), "{error}");
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn inode_of(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().ino()
}

/// Put `head` in the cache as an earlier check would have left it.
fn seed_cache(world: &World, head: &VerifiedHead) {
    let path = world.cache_path();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(path.parent().unwrap())
        .unwrap();
    std::fs::write(&path, head.to_json().unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn cached_seq(world: &World) -> u64 {
    Head::from_json(&std::fs::read(world.cache_path()).unwrap())
        .unwrap()
        .verify_signature()
        .unwrap()
        .seq()
}

//
// The state matrix, through both funnels
//

/// Row 1: a reachable witness records the release with the manifest's hashes.
/// The install proceeds, the report says what was consulted, and the head is
/// cached at `0600` in a `0700` directory.
#[tokio::test]
async fn a_logged_release_installs_and_the_head_is_cached() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        let served = serve(
            &witness,
            head(7, vec![filler_row(), ok_row(funnel.name(), &manifest)]),
        );

        let storage = Counting::new(world.storage());
        let report = confirmed(
            funnel
                .install(
                    &storage,
                    "0.3.0",
                    Flags::default(),
                    enforced(&[uri(&witness)]),
                )
                .await
                .unwrap(),
        );
        assert_eq!(
            report,
            ReleaseLogReport {
                seq: 7,
                signed_at: NOW.to_string(),
                source: HeadSource::Witness,
                answered: vec![uri(&witness).to_string()],
                unreachable: Vec::new(),
                cache_written: true,
                co_signs: Vec::new(),
            },
            "{funnel:?}"
        );
        assert_eq!(storage.tarballs(), 1, "{funnel:?}: the release was fetched");
        assert!(!world.installed().is_empty(), "{funnel:?}");

        // The cache is the served head, byte for byte, owner-only.
        let cache = world.cache_path();
        assert_eq!(
            std::fs::read_to_string(&cache).unwrap(),
            served.to_json().unwrap()
        );
        let file_mode = mode_of(&cache);
        assert_eq!(file_mode & 0o077, 0, "{funnel:?}: {file_mode:o}");
        assert_eq!(file_mode & 0o600, 0o600, "{funnel:?}: {file_mode:o}");
        for dir in [cache.parent().unwrap(), &world.home.join("state")] {
            let dir_mode = mode_of(dir);
            assert_eq!(dir_mode & 0o077, 0, "{funnel:?}: {dir_mode:o}");
            assert_eq!(dir_mode & 0o700, 0o700, "{funnel:?}: {dir_mode:o}");
        }
        // No temp file is left beside it.
        let names: Vec<_> = std::fs::read_dir(cache.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [HEAD_KEY], "{funnel:?}");
    }
}

/// Row 2: a revoked release is refused before any of its bytes are fetched,
/// and neither `allow_downgrade` nor `force` changes that. The head that
/// revoked it is cached all the same.
#[tokio::test]
async fn a_revoked_release_is_refused_whatever_the_flags() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        let mut revoked = ok_row(funnel.name(), &manifest);
        revoked.status = RowStatus::Revoked;
        serve(&witness, head(4, vec![revoked]));

        let storage = Counting::new(world.storage());
        for flags in [
            Flags::default(),
            Flags {
                allow_downgrade: true,
                force: false,
            },
            Flags {
                allow_downgrade: false,
                force: true,
            },
            Flags {
                allow_downgrade: true,
                force: true,
            },
        ] {
            let error = log_error(
                funnel
                    .install(&storage, "0.3.0", flags, enforced(&[uri(&witness)]))
                    .await,
            );
            assert!(
                matches!(
                    &error,
                    ReleaseLogError::Revoked { name, version }
                        if name == funnel.name() && version == "0.3.0"
                ),
                "{funnel:?} {flags:?}: {error:?}"
            );
            assert_hard(&error);
        }
        assert_eq!(
            storage.tarballs(),
            0,
            "{funnel:?}: no release bytes fetched"
        );
        assert!(
            world.installed().is_empty(),
            "{funnel:?}: nothing installed"
        );
        // A revocation seen once stays known.
        assert_eq!(cached_seq(&world), 4, "{funnel:?}");
    }
}

/// Row 2 on the cache-hit path: an artifact unpacked while its release was in
/// good standing is refused once the log revokes it — not handed back, not
/// relinked.
#[tokio::test]
async fn a_revoked_release_already_on_disk_is_refused_too() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let storage = Counting::new(world.storage());
        funnel
            .install(
                &storage,
                "0.3.0",
                Flags::default(),
                ReleaseLogPolicy::Inactive,
            )
            .await
            .unwrap();
        assert_eq!(storage.tarballs(), 1);
        let before = world.installed();

        let witness = world.witness("witness");
        let mut revoked = ok_row(funnel.name(), &manifest);
        revoked.status = RowStatus::Revoked;
        serve(&witness, head(4, vec![revoked]));

        let error = log_error(
            funnel
                .install(
                    &storage,
                    "0.3.0",
                    Flags::default(),
                    enforced(&[uri(&witness)]),
                )
                .await,
        );
        assert!(
            matches!(error, ReleaseLogError::Revoked { .. }),
            "{funnel:?}: {error:?}"
        );
        assert_eq!(world.installed(), before, "{funnel:?}: nothing switched");
        assert_eq!(storage.tarballs(), 1, "{funnel:?}: nothing fetched again");
    }
}

/// Rows 3 and 4: a reachable witness's log has no row for the release, or its
/// row lacks this target. The byte host serves something the log does not
/// record — a refusal.
#[tokio::test]
async fn a_release_the_log_does_not_record_is_refused() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let name = funnel.name();
        let witness = world.witness("witness");

        // Another version, another name, another target: none is this release.
        let mut other_version = ok_row(name, &manifest);
        other_version.version = "0.2.0".to_string();
        let mut other_name = ok_row(name, &manifest);
        other_name.name = "zzz".to_string();
        let other_target_only = row(
            name,
            "0.3.0",
            RowStatus::Ok,
            &[(other_target(), pins(&manifest))],
        );
        let cases = [
            ("no row", vec![filler_row()]),
            ("another version", vec![other_version]),
            ("another name", vec![other_name]),
            ("target absent", vec![other_target_only]),
        ];

        let storage = Counting::new(world.storage());
        for (seq, (case, rows)) in (1..).zip(cases) {
            serve(&witness, head(seq, rows));
            // Each case stands alone: no baseline carried between them.
            let _ = std::fs::remove_file(world.cache_path());
            let error = log_error(
                funnel
                    .install(
                        &storage,
                        "0.3.0",
                        Flags::default(),
                        enforced(&[uri(&witness)]),
                    )
                    .await,
            );
            assert!(
                matches!(
                    &error,
                    ReleaseLogError::RowMissing { name: n, version, target, pinned_by: PinnedBy::SignedManifest }
                        if n == name && version == "0.3.0" && target == current_target()
                ),
                "{funnel:?} {case}: {error:?}"
            );
            assert_hard(&error);
        }
        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
    }
}

/// Row 5: the log records the release with other hashes than the signed
/// manifest's. Each field is caught, and `binaries` is compared as a whole
/// map — an extra, a missing, or a renamed binary is a mismatch.
#[tokio::test]
async fn a_release_the_log_records_differently_is_a_contradiction() {
    for funnel in FUNNELS {
        let world = World::new().await;
        // The tool carries two binaries, so the log can list one too few.
        let manifest = funnel.publish_with(&world, "0.3.0", &[TOOL, "fuzfd"]).await;
        let name = funnel.name();
        let witness = world.witness("witness");
        let good = pins(&manifest);
        let other_hash = ContentHash::blake3(b"some other build");
        let first_binary = good.binaries.keys().next().unwrap().clone();

        let mut other_content = good.clone();
        other_content.content_hash = format!("v1-{}", other_hash.to_hex());
        let mut other_binary = good.clone();
        other_binary
            .binaries
            .insert(first_binary.clone(), other_hash.clone());
        let mut extra_binary = good.clone();
        extra_binary
            .binaries
            .insert("extra".to_string(), other_hash.clone());
        // Same count, another name: the manifest's binary is missing.
        let mut renamed_binary = good.clone();
        let hash = renamed_binary.binaries.remove(&first_binary).unwrap();
        renamed_binary.binaries.insert("renamed".to_string(), hash);

        let mut cases = vec![
            ("content_hash", other_content, TargetField::ContentHash),
            ("a binary hash", other_binary, TargetField::Binaries),
            ("an extra binary", extra_binary, TargetField::Binaries),
            ("a renamed binary", renamed_binary, TargetField::Binaries),
        ];
        if good.binaries.len() > 1 {
            let mut missing_binary = good.clone();
            missing_binary.binaries.remove(&first_binary);
            cases.push(("a missing binary", missing_binary, TargetField::Binaries));
        }
        if funnel == Funnel::Tool {
            assert_eq!(cases.len(), 5, "the tool funnel covers the missing binary");
        }

        let storage = Counting::new(world.storage());
        for (seq, (case, target_row, expected)) in (1..).zip(cases) {
            serve(
                &witness,
                head(
                    seq,
                    vec![row(
                        name,
                        "0.3.0",
                        RowStatus::Ok,
                        &[(current_target(), target_row)],
                    )],
                ),
            );
            let _ = std::fs::remove_file(world.cache_path());
            let error = log_error(
                funnel
                    .install(
                        &storage,
                        "0.3.0",
                        Flags::default(),
                        enforced(&[uri(&witness)]),
                    )
                    .await,
            );
            assert!(
                matches!(
                    &error,
                    ReleaseLogError::Contradiction(LogContradiction::HashMismatch { name: n, version, target, field, pinned_by: PinnedBy::SignedManifest })
                        if n == name && version == "0.3.0" && target == current_target() && *field == expected
                ),
                "{funnel:?} {case}: {error:?}"
            );
            assert_hard(&error);
        }
        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
    }
}

/// Row 6: no witness reachable, and the cached head records the release in
/// good standing. The install proceeds, and the report says the verdict came
/// from the cache.
#[tokio::test]
async fn an_unreachable_witness_with_a_covering_cache_proceeds_with_a_warning() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        serve(&witness, head(3, vec![ok_row(funnel.name(), &manifest)]));

        // An earlier check caches the head; then the witness goes away.
        let log = resolve_log(&origins(&[uri(&witness)])).await.unwrap();
        assert!(log.cache_written());
        stop_serving(&witness);
        let cached = std::fs::read(world.cache_path()).unwrap();
        let inode = inode_of(&world.cache_path());

        let report = confirmed(
            funnel
                .install(
                    &world.storage(),
                    "0.3.0",
                    Flags::default(),
                    enforced(&[uri(&witness)]),
                )
                .await
                .unwrap(),
        );
        assert_eq!(
            report.source,
            HeadSource::CacheWitnessUnreachable,
            "{funnel:?}"
        );
        assert_eq!(report.seq, 3);
        assert!(report.answered.is_empty());
        assert_eq!(report.unreachable.len(), 1);
        assert_eq!(report.unreachable[0].origin, uri(&witness));
        assert!(
            report.unreachable[0].reason.contains("path not found"),
            "{:?}",
            report.unreachable
        );
        assert!(!report.cache_written);
        assert!(!world.installed().is_empty(), "{funnel:?}");
        // The cache is left exactly as it was.
        assert_eq!(std::fs::read(world.cache_path()).unwrap(), cached);
        assert_eq!(inode_of(&world.cache_path()), inode);
    }
}

/// Rows 7 and 8: no witness reachable, and the cached head says the release is
/// revoked, or records it with other hashes. Both are refusals — the cache is
/// a verified statement, and being offline does not soften it.
#[tokio::test]
async fn an_unreachable_witness_does_not_soften_what_the_cache_says() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let name = funnel.name();
        let witness = world.witness("witness");
        let policy = || enforced(&[uri(&witness)]);
        let storage = Counting::new(world.storage());

        let mut revoked = ok_row(name, &manifest);
        revoked.status = RowStatus::Revoked;
        seed_cache(&world, &verified(head(5, vec![revoked])));
        let error = log_error(
            funnel
                .install(&storage, "0.3.0", Flags::default(), policy())
                .await,
        );
        assert!(
            matches!(error, ReleaseLogError::Revoked { .. }),
            "{funnel:?}: {error:?}"
        );
        assert_hard(&error);

        let mut other = pins(&manifest);
        other.content_hash = format!("v1-{}", ContentHash::blake3(b"other").to_hex());
        seed_cache(
            &world,
            &verified(head(
                5,
                vec![row(
                    name,
                    "0.3.0",
                    RowStatus::Ok,
                    &[(current_target(), other)],
                )],
            )),
        );
        let error = log_error(
            funnel
                .install(&storage, "0.3.0", Flags::default(), policy())
                .await,
        );
        assert!(
            matches!(
                error,
                ReleaseLogError::Contradiction(LogContradiction::HashMismatch {
                    field: TargetField::ContentHash,
                    ..
                })
            ),
            "{funnel:?}: {error:?}"
        );
        assert_hard(&error);

        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
    }
}

/// Rows 9 and 10: no witness reachable, and nothing cached covers the release
/// — no cache at all, or a cached head without the row or without the target.
/// The one soft failure: not a refusal, not a security violation, and still
/// nothing is installed.
#[tokio::test]
async fn an_unreachable_witness_with_no_covering_cache_is_unconfirmed() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let name = funnel.name();
        let witness = world.witness("witness");
        let storage = Counting::new(world.storage());

        let other_target_only = row(
            name,
            "0.3.0",
            RowStatus::Ok,
            &[(other_target(), pins(&manifest))],
        );
        let caches = [
            ("no cache", None),
            ("cache lacks the row", Some(head(5, vec![filler_row()]))),
            (
                "cache lacks the target",
                Some(head(5, vec![other_target_only])),
            ),
        ];
        for (case, cache) in caches {
            let _ = std::fs::remove_file(world.cache_path());
            if let Some(cache) = cache {
                seed_cache(&world, &verified(cache));
            }
            let result = funnel
                .install(
                    &storage,
                    "0.3.0",
                    Flags::default(),
                    enforced(&[uri(&witness)]),
                )
                .await;
            let Err(release_error) = result else {
                panic!("{funnel:?} {case}: expected the soft failure");
            };
            assert!(release_error.is_unconfirmed(), "{funnel:?} {case}");
            assert!(!release_error.is_security_violation(), "{funnel:?} {case}");
            let ReleaseError::ReleaseLog(error) = release_error else {
                panic!("{funnel:?} {case}: {release_error:?}");
            };
            assert!(
                matches!(
                    &error,
                    ReleaseLogError::Unconfirmed { name: n, version, target, witnesses }
                        if n == name
                            && version == "0.3.0"
                            && target == current_target()
                            && witnesses.len() == 1
                            && witnesses[0].origin == uri(&witness)
                ),
                "{funnel:?} {case}: {error:?}"
            );
            let message = error.to_string();
            assert!(message.contains("cannot confirm"), "{message}");
            assert!(message.contains(uri(&witness)), "{message}");
            assert!(
                error.hint().unwrap_or_default().contains("not a refusal"),
                "{funnel:?} {case}"
            );
        }
        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
    }
}

//
// Policy
//

/// The default policy checks nothing: no report, no cache, and a witness that
/// would refuse the release is never consulted.
#[tokio::test]
async fn an_inactive_policy_checks_and_writes_nothing() {
    for funnel in FUNNELS {
        let world = World::new().await;
        funnel.publish(&world, "0.3.0").await;
        let check = funnel
            .install(
                &world.storage(),
                "0.3.0",
                Flags::default(),
                ReleaseLogPolicy::default(),
            )
            .await
            .unwrap();
        assert_eq!(check, LogCheck::Inactive, "{funnel:?}");
        assert!(!world.installed().is_empty(), "{funnel:?}");
        assert!(
            !world.home.join("state").join("release_log").exists(),
            "{funnel:?}: no cache directory"
        );
    }
}

/// The opt-out checks nothing either: a witness revoking the release does not
/// stop the install, and nothing is cached.
#[tokio::test]
async fn the_opt_out_skips_the_check_and_caches_nothing() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        let mut revoked = ok_row(funnel.name(), &manifest);
        revoked.status = RowStatus::Revoked;
        serve(&witness, head(4, vec![revoked]));

        let policy =
            ReleaseLogPolicy::from_env_values(Some(uri(&witness)), Some("off"), &[]).unwrap();
        assert!(matches!(policy, ReleaseLogPolicy::Off));
        let check = funnel
            .install(&world.storage(), "0.3.0", Flags::default(), policy)
            .await
            .unwrap();
        assert_eq!(check, LogCheck::Off, "{funnel:?}");
        assert!(!world.installed().is_empty(), "{funnel:?}");
        assert!(!world.home.join("state").join("release_log").exists());
    }
}

//
// Cache
//

/// The cache is written only when the head moves: an unchanged head leaves the
/// file as it is (same inode), an advanced head replaces it.
#[tokio::test]
async fn the_cache_is_rewritten_only_when_the_head_advances() {
    let world = World::new().await;
    let witness = world.witness("witness");
    let origins = origins(&[uri(&witness)]);
    let cache = world.cache_path();

    serve(&witness, head(3, vec![filler_row()]));
    assert!(resolve_log(&origins).await.unwrap().cache_written());
    let inode = inode_of(&cache);

    // The same head again: nothing to write.
    let log = resolve_log(&origins).await.unwrap();
    assert!(!log.cache_written());
    assert_eq!(log.source(), Some(HeadSource::Witness));
    assert_eq!(
        inode_of(&cache),
        inode,
        "an unchanged head is not rewritten"
    );

    // The same content signed again at another time is still the same head.
    let resigned = sign_head(head(3, vec![filler_row()]), &trusted_key(), common::LATER).unwrap();
    std::fs::write(witness.join(HEAD_KEY), resigned.to_json().unwrap()).unwrap();
    assert!(!resolve_log(&origins).await.unwrap().cache_written());
    assert_eq!(inode_of(&cache), inode);

    // The log grows: the cache follows.
    let mut tool_row = filler_row();
    tool_row.version = "10.0.0".to_string();
    let advanced = serve(&witness, head(4, vec![filler_row(), tool_row]));
    let log = resolve_log(&origins).await.unwrap();
    assert!(log.cache_written());
    assert_eq!(log.head().map(VerifiedHead::seq), Some(4));
    assert_ne!(
        inode_of(&cache),
        inode,
        "an advanced head replaces the file"
    );
    assert_eq!(
        std::fs::read_to_string(&cache).unwrap(),
        advanced.to_json().unwrap()
    );
    assert_eq!(mode_of(&cache) & 0o077, 0);
}

/// A cache that exists and cannot be used is a hard error naming the file —
/// never read as "no baseline", never replaced. The witness serves a perfectly
/// good head throughout, and it is not allowed to paper over the cache.
#[tokio::test]
async fn an_unusable_cache_is_a_hard_error_through_both_funnels() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        let good = head(3, vec![ok_row(funnel.name(), &manifest)]);
        serve(&witness, good.clone());
        let cache = world.cache_path();
        let storage = Counting::new(world.storage());

        // A valid head, then one byte of a signed field changed.
        let valid = signed(good.clone()).to_json().unwrap();
        let tampered = valid.replace("\"0.3.0\"", "\"0.3.1\"");
        assert_ne!(tampered, valid);
        let untrusted = sign_head(good, &untrusted_key(), NOW)
            .unwrap()
            .to_json()
            .unwrap();
        let oversized = vec![b' '; 2 * 1024 * 1024];

        let contents: [(&str, &[u8]); 5] = [
            ("garbage", b"not a head"),
            ("truncated", &valid.as_bytes()[..valid.len() / 2]),
            ("tampered signature", tampered.as_bytes()),
            ("untrusted key", untrusted.as_bytes()),
            ("2 MiB", &oversized),
        ];
        for (case, bytes) in contents {
            seed_cache(&world, &verified(head(1, vec![filler_row()])));
            std::fs::write(&cache, bytes).unwrap();
            let error = log_error(
                funnel
                    .install(
                        &storage,
                        "0.3.0",
                        Flags::default(),
                        enforced(&[uri(&witness)]),
                    )
                    .await,
            );
            let ReleaseLogError::CacheUnusable { path, problem } = &error else {
                panic!("{funnel:?} {case}: {error:?}");
            };
            assert_eq!(path, &head_cache_path().unwrap(), "{funnel:?} {case}");
            assert_eq!(path, &cache);
            match case {
                "2 MiB" => assert!(
                    matches!(
                        problem,
                        CacheProblem::File(SecureFileError::FileTooLarge(..))
                    ),
                    "{case}: {problem:?}"
                ),
                "tampered signature" | "untrusted key" => {
                    assert!(
                        matches!(problem, CacheProblem::Head(e) if matches!(**e, ReleaseLogError::Signature(_))),
                        "{case}: {problem:?}"
                    );
                    assert!(error.is_security_violation(), "{case}");
                }
                _ => assert!(
                    matches!(problem, CacheProblem::Head(e) if matches!(**e, ReleaseLogError::Parse(_))),
                    "{case}: {problem:?}"
                ),
            }
            assert!(!error.is_unconfirmed(), "{case}");
            assert!(error.to_string().contains(uri(&cache)), "{case}: {error}");
            let hint = error.hint().unwrap_or_default();
            assert!(
                hint.contains("state/release_log/head.json"),
                "{case}: {hint}"
            );
            // The file is exactly what it was: not replaced by the good head.
            assert_eq!(std::fs::read(&cache).unwrap(), bytes, "{funnel:?} {case}");
        }

        // A symlink where the cache belongs: refused, and what it points at is
        // neither read as a head nor written through.
        let target = world.tmp.path().join("elsewhere.json");
        std::fs::write(&target, &valid).unwrap();
        std::fs::remove_file(&cache).unwrap();
        std::os::unix::fs::symlink(&target, &cache).unwrap();
        let error = log_error(
            funnel
                .install(
                    &storage,
                    "0.3.0",
                    Flags::default(),
                    enforced(&[uri(&witness)]),
                )
                .await,
        );
        assert!(
            matches!(
                &error,
                ReleaseLogError::CacheUnusable {
                    problem: CacheProblem::File(SecureFileError::Symlink(_)),
                    ..
                }
            ),
            "{funnel:?}: {error:?}"
        );
        assert_hard(&error);
        assert!(cache.is_symlink(), "{funnel:?}: the link is left in place");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), valid);

        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
    }
}

/// The cached head is the baseline a witness's head must contain. A witness
/// that drops a row, changes what a target pins, reuses a `seq` for other
/// content, or un-revokes a release contradicts it — and the cache survives.
#[tokio::test]
async fn a_witness_that_contradicts_the_cache_is_refused() {
    let world = World::new().await;
    let funnel = Funnel::Tool;
    let manifest = funnel.publish(&world, "0.3.0").await;
    let witness = world.witness("witness");
    let release = || ok_row(TOOL, &manifest);
    let mut revoked = filler_row();
    revoked.name = "zzz".to_string();
    revoked.status = RowStatus::Revoked;
    let baseline = head(5, vec![filler_row(), revoked.clone(), release()]);
    let cached = verified(baseline.clone());

    let mut dropped = baseline.clone();
    dropped.seq = 6;
    dropped.rows.remove(0);
    let mut mutated = baseline.clone();
    mutated.seq = 6;
    mutated.rows[0]
        .targets
        .get_mut(current_target())
        .unwrap()
        .content_hash = format!("v1-{}", ContentHash::blake3(b"swapped").to_hex());
    let mut reused = baseline.clone();
    reused.rows.push({
        let mut extra = filler_row();
        extra.version = "10.0.0".to_string();
        extra
    });
    let mut unrevoked = baseline.clone();
    unrevoked.seq = 6;
    unrevoked.rows[1].status = RowStatus::Ok;
    // Older than the cache and not a prefix of it: lagging is fine, this is not.
    let older_inconsistent = head(4, vec![release()]);
    let cases: [(&str, HeadUnsigned, ExpectViolation); 5] = [
        ("drops a row", dropped, |v| {
            matches!(
                v,
                HeadViolation::RowMoved { .. } | HeadViolation::RowRemoved { .. }
            )
        }),
        ("mutates a target", mutated, |v| {
            matches!(v, HeadViolation::TargetChanged { .. })
        }),
        ("reuses a seq", reused, |v| {
            matches!(v, HeadViolation::SeqReused { seq: 5 })
        }),
        ("un-revokes", unrevoked, |v| {
            matches!(v, HeadViolation::RevocationUndone { .. })
        }),
        ("older and inconsistent", older_inconsistent, |v| {
            matches!(
                v,
                HeadViolation::RowMoved { .. } | HeadViolation::RowRemoved { .. }
            )
        }),
    ];

    let storage = Counting::new(world.storage());
    for (case, fresh, expect) in cases {
        seed_cache(&world, &cached);
        let before = std::fs::read(world.cache_path()).unwrap();
        serve(&witness, fresh);

        let error = log_error(
            funnel
                .install(
                    &storage,
                    "0.3.0",
                    Flags::default(),
                    enforced(&[uri(&witness)]),
                )
                .await,
        );
        let ReleaseLogError::Contradiction(LogContradiction::SupersetViolated {
            origin,
            violation,
        }) = &error
        else {
            panic!("{case}: {error:?}");
        };
        assert_eq!(origin, uri(&witness), "{case}");
        assert!(expect(violation), "{case}: {violation:?}");
        assert_hard(&error);
        assert_eq!(
            std::fs::read(world.cache_path()).unwrap(),
            before,
            "{case}: the baseline survives the head that contradicts it"
        );
        // The same answer from the resolver alone, in either mode.
        for result in [
            resolve_log(&origins(&[uri(&witness)])).await,
            resolve_log_read_only(&origins(&[uri(&witness)])).await,
        ] {
            assert!(
                matches!(
                    resolve_error(result),
                    ReleaseLogError::Contradiction(LogContradiction::SupersetViolated { .. })
                ),
                "{case}"
            );
        }
    }
    assert_eq!(storage.tarballs(), 0);
    assert!(world.installed().is_empty());
}

/// A witness serving an older head of the same history is lagging, not lying.
/// The cached head is the newer verified statement, so the verdict is read
/// from it, the report says so, and the cache is not rewritten.
#[tokio::test]
async fn a_lagging_witness_defers_to_the_cached_head() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");

        // The witness is one row behind: it does not have the release yet.
        serve(&witness, head(5, vec![filler_row()]));
        seed_cache(
            &world,
            &verified(head(
                6,
                vec![filler_row(), ok_row(funnel.name(), &manifest)],
            )),
        );
        let inode = inode_of(&world.cache_path());

        let report = confirmed(
            funnel
                .install(
                    &world.storage(),
                    "0.3.0",
                    Flags::default(),
                    enforced(&[uri(&witness)]),
                )
                .await
                .unwrap(),
        );
        assert_eq!(report.source, HeadSource::CacheAheadOfWitness, "{funnel:?}");
        assert_eq!(report.seq, 6);
        assert_eq!(report.answered, [uri(&witness)]);
        assert!(report.unreachable.is_empty());
        assert!(!report.cache_written);
        assert_eq!(inode_of(&world.cache_path()), inode, "{funnel:?}");
        assert_eq!(cached_seq(&world), 6);
        assert!(!world.installed().is_empty(), "{funnel:?}");
    }
}

/// A lagging witness is still a reachable one: a release that even the newer
/// cached head does not record is refused, not "unconfirmed".
#[tokio::test]
async fn a_lagging_witness_does_not_turn_a_missing_row_soft() {
    let world = World::new().await;
    let funnel = Funnel::SelfArtifact;
    funnel.publish(&world, "0.3.0").await;
    let witness = world.witness("witness");
    serve(&witness, head(5, vec![filler_row()]));
    let mut later = filler_row();
    later.version = "10.0.0".to_string();
    seed_cache(&world, &verified(head(6, vec![filler_row(), later])));

    let error = log_error(
        funnel
            .install(
                &world.storage(),
                "0.3.0",
                Flags::default(),
                enforced(&[uri(&witness)]),
            )
            .await,
    );
    assert!(
        matches!(error, ReleaseLogError::RowMissing { .. }),
        "{error:?}"
    );
}

/// The read-only entry points use the cache and never write it: with nothing
/// cached no directory appears, and with an older head cached the file is left
/// byte for byte — while the writing entry point, given the same inputs,
/// advances it.
#[tokio::test]
async fn the_read_only_check_never_writes_the_cache() {
    let world = World::new().await;
    let funnel = Funnel::SelfArtifact;
    let manifest: VerifiedManifest = funnel
        .publish(&world, "0.3.0")
        .await
        .verify_signature()
        .unwrap();
    let witness = world.witness("witness");
    serve(
        &witness,
        head(4, vec![filler_row(), ok_row(SELF_NAME, &manifest)]),
    );
    let state = world.home.join("state");

    // Nothing cached: nothing is created, the verdict is still given.
    let log = resolve_log_read_only(&origins(&[uri(&witness)]))
        .await
        .unwrap();
    assert_eq!(log.head().map(VerifiedHead::seq), Some(4));
    assert!(!log.cache_written());
    let report = confirmed(
        check_release_log_read_only(&enforced(&[uri(&witness)]), &manifest)
            .await
            .unwrap(),
    );
    assert_eq!(report.seq, 4);
    assert_eq!(report.source, HeadSource::Witness);
    assert!(!report.cache_written);
    assert!(
        !state.exists(),
        "a read-only check creates no state directory"
    );
    assert!(world.installed().is_empty());

    // An older head cached: used as the baseline, and left alone.
    seed_cache(&world, &verified(head(3, vec![filler_row()])));
    let before = std::fs::read(world.cache_path()).unwrap();
    let inode = inode_of(&world.cache_path());
    let listing = |dir: &Path| -> Vec<_> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let cache_dir = world.cache_path().parent().unwrap().to_path_buf();
    let names = listing(&cache_dir);
    for _ in 0..2 {
        let report = confirmed(
            check_release_log_read_only(&enforced(&[uri(&witness)]), &manifest)
                .await
                .unwrap(),
        );
        assert_eq!(report.seq, 4, "the newer witness head gives the verdict");
        assert!(!report.cache_written);
        assert!(
            !resolve_log_read_only(&origins(&[uri(&witness)]))
                .await
                .unwrap()
                .cache_written()
        );
    }
    assert_eq!(std::fs::read(world.cache_path()).unwrap(), before);
    assert_eq!(inode_of(&world.cache_path()), inode);
    assert_eq!(listing(&cache_dir), names);

    // The read-only modes also pass through the opt-out and the default.
    assert_eq!(
        check_release_log_read_only(&ReleaseLogPolicy::Inactive, &manifest)
            .await
            .unwrap(),
        LogCheck::Inactive
    );
    assert_eq!(
        check_release_log_read_only(&ReleaseLogPolicy::Off, &manifest)
            .await
            .unwrap(),
        LogCheck::Off
    );

    // Control: the writing entry point advances the same cache.
    assert!(
        resolve_log(&origins(&[uri(&witness)]))
            .await
            .unwrap()
            .cache_written()
    );
    assert_eq!(cached_seq(&world), 4);
}

/// The read-only check refuses on the same evidence the writing one does, and
/// leaves no trace of the head it refused on.
#[tokio::test]
async fn the_read_only_check_refuses_without_caching() {
    let world = World::new().await;
    let funnel = Funnel::Tool;
    let manifest = funnel
        .publish(&world, "0.3.0")
        .await
        .verify_signature()
        .unwrap();
    let witness = world.witness("witness");
    let mut revoked = ok_row(TOOL, &manifest);
    revoked.status = RowStatus::Revoked;
    serve(&witness, head(4, vec![revoked]));

    let error =
        resolve_error(check_release_log_read_only(&enforced(&[uri(&witness)]), &manifest).await);
    assert!(
        matches!(error, ReleaseLogError::Revoked { .. }),
        "{error:?}"
    );
    assert!(!world.home.join("state").exists());
}

//
// Several witnesses
//

/// Witnesses that agree, a witness that lags, and a witness that is down: all
/// fine — the newest verified head gives the verdict and is what gets cached.
#[tokio::test]
async fn several_witnesses_agree_lag_or_drop_out() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let (a, b) = (world.witness("a"), world.witness("b"));
        let older = head(5, vec![filler_row()]);
        let newer = head(6, vec![filler_row(), ok_row(funnel.name(), &manifest)]);
        let policy = || enforced(&[uri(&a), uri(&b)]);

        // One lags: in either order the newest is used.
        for (first, second) in [(&a, &b), (&b, &a)] {
            let _ = std::fs::remove_file(world.cache_path());
            serve(first, older.clone());
            serve(second, newer.clone());
            let log = resolve_log(&origins(&[uri(&a), uri(&b)])).await.unwrap();
            assert_eq!(log.head().map(VerifiedHead::seq), Some(6), "{funnel:?}");
            assert_eq!(log.answered(), [uri(&a), uri(&b)]);
            assert_eq!(cached_seq(&world), 6);
        }

        // Both agree.
        serve(&a, newer.clone());
        serve(&b, newer.clone());
        let _ = std::fs::remove_file(world.cache_path());
        let report = confirmed(
            funnel
                .install(&world.storage(), "0.3.0", Flags::default(), policy())
                .await
                .unwrap(),
        );
        assert_eq!(report.answered, [uri(&a), uri(&b)], "{funnel:?}");
        assert_eq!(report.source, HeadSource::Witness);
        assert_eq!(report.seq, 6);
        assert!(report.unreachable.is_empty());

        // One is down: noted, not fatal.
        stop_serving(&a);
        let report = confirmed(
            funnel
                .install(&world.storage(), "0.3.0", Flags::default(), policy())
                .await
                .unwrap(),
        );
        assert_eq!(report.answered, [uri(&b)], "{funnel:?}");
        assert_eq!(report.source, HeadSource::Witness);
        assert_eq!(report.unreachable.len(), 1);
        assert_eq!(report.unreachable[0].origin, uri(&a));
    }
}

/// Two witnesses serving valid heads that are not one history: a
/// contradiction naming both, whichever comes first.
#[tokio::test]
async fn witnesses_that_diverge_are_a_contradiction() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let (a, b) = (world.witness("a"), world.witness("b"));
        let release = ok_row(funnel.name(), &manifest);
        // Same seq, different rows: both record the release, neither contains
        // the other.
        serve(&a, head(6, vec![filler_row(), release.clone()]));
        serve(&b, head(6, vec![release]));
        let storage = Counting::new(world.storage());

        for (first, second) in [(&a, &b), (&b, &a)] {
            let error = log_error(
                funnel
                    .install(
                        &storage,
                        "0.3.0",
                        Flags::default(),
                        enforced(&[uri(first), uri(second)]),
                    )
                    .await,
            );
            assert!(
                matches!(
                    &error,
                    ReleaseLogError::Contradiction(LogContradiction::HeadsDiverge { first: f, second: s, violation })
                        if f == uri(first) && s == uri(second)
                            && matches!(**violation, HeadViolation::SeqReused { seq: 6 })
                ),
                "{funnel:?}: {error:?}"
            );
            assert_hard(&error);
        }
        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
        assert!(!world.cache_path().exists(), "{funnel:?}: nothing cached");
    }
}

/// A witness serving a bad head stops the check even when another witness
/// serves a good one that records the release — in either order. A bad head is
/// never skipped as if the witness were merely down.
#[tokio::test]
async fn a_bad_head_is_not_skipped_in_favor_of_another_witness() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let (good, bad) = (world.witness("good"), world.witness("bad"));
        serve(&good, head(6, vec![ok_row(funnel.name(), &manifest)]));
        std::fs::write(bad.join(HEAD_KEY), b"{ not a head").unwrap();
        let storage = Counting::new(world.storage());

        for order in [[&good, &bad], [&bad, &good]] {
            let error = log_error(
                funnel
                    .install(
                        &storage,
                        "0.3.0",
                        Flags::default(),
                        enforced(&[uri(order[0]), uri(order[1])]),
                    )
                    .await,
            );
            assert!(
                matches!(
                    &error,
                    ReleaseLogError::WitnessHead { origin, source }
                        if origin == uri(&bad) && matches!(**source, ReleaseLogError::Parse(_))
                ),
                "{funnel:?}: {error:?}"
            );
            assert!(!error.is_unconfirmed());
        }
        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
        assert!(!world.cache_path().exists(), "{funnel:?}: nothing cached");
    }
}

/// Every witness down: the cache decides, and with none the release is
/// unconfirmed, naming every witness tried.
#[tokio::test]
async fn all_witnesses_unreachable_falls_back_to_the_cache() {
    let world = World::new().await;
    let funnel = Funnel::Tool;
    let manifest = funnel.publish(&world, "0.3.0").await;
    let (a, b) = (world.witness("a"), world.witness("b"));
    let policy = || enforced(&[uri(&a), uri(&b)]);

    let error = log_error(
        funnel
            .install(&world.storage(), "0.3.0", Flags::default(), policy())
            .await,
    );
    let ReleaseLogError::Unconfirmed { witnesses, .. } = &error else {
        panic!("{error:?}");
    };
    let tried: Vec<&str> = witnesses.iter().map(|w| w.origin.as_str()).collect();
    assert_eq!(tried, [uri(&a), uri(&b)]);
    assert!(world.installed().is_empty());

    seed_cache(&world, &verified(head(3, vec![ok_row(TOOL, &manifest)])));
    let report = confirmed(
        funnel
            .install(&world.storage(), "0.3.0", Flags::default(), policy())
            .await
            .unwrap(),
    );
    assert_eq!(report.source, HeadSource::CacheWitnessUnreachable);
    assert_eq!(report.unreachable.len(), 2);
}

//
// Bad heads from a witness
//

/// Every way a served document can fail to be a head is a hard failure naming
/// the witness: nothing is cached, nothing is installed, and none of them is
/// the soft "unconfirmed".
#[tokio::test]
async fn a_bad_head_from_a_witness_is_a_hard_failure() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        let good = head(3, vec![ok_row(funnel.name(), &manifest)]);
        let valid = signed(good.clone()).to_json().unwrap();

        let mut with_unknown_field: serde_json::Value = serde_json::from_str(&valid).unwrap();
        with_unknown_field["extra"] = serde_json::json!("x");
        let mut wrong_format: serde_json::Value = serde_json::from_str(&valid).unwrap();
        wrong_format["format"] = serde_json::json!(2);
        let untrusted = sign_head(good, &untrusted_key(), NOW)
            .unwrap()
            .to_json()
            .unwrap();
        let oversized = vec![b' '; usize::try_from(MAX_HEAD_SIZE).unwrap() + 1];
        let cases: [(&str, Vec<u8>, ExpectHeadError, bool); 6] = [
            (
                "oversized",
                oversized,
                |e| matches!(e, ReleaseLogError::TooLarge(n) if *n == MAX_HEAD_SIZE + 1),
                false,
            ),
            (
                "truncated",
                valid.as_bytes()[..valid.len() - 20].to_vec(),
                |e| matches!(e, ReleaseLogError::Parse(_)),
                false,
            ),
            (
                "unknown field",
                serde_json::to_vec(&with_unknown_field).unwrap(),
                |e| matches!(e, ReleaseLogError::Parse(_)),
                false,
            ),
            (
                "wrong format",
                serde_json::to_vec(&wrong_format).unwrap(),
                |e| matches!(e, ReleaseLogError::UnsupportedFormat(2)),
                false,
            ),
            (
                "bad signature",
                valid.replace("\"0.3.0\"", "\"0.3.1\"").into_bytes(),
                |e| matches!(e, ReleaseLogError::Signature(_)),
                true,
            ),
            (
                "untrusted key",
                untrusted.into_bytes(),
                |e| matches!(e, ReleaseLogError::Signature(_)),
                true,
            ),
        ];

        let storage = Counting::new(world.storage());
        for (case, bytes, expect, security) in cases {
            std::fs::write(witness.join(HEAD_KEY), bytes).unwrap();
            let error = log_error(
                funnel
                    .install(
                        &storage,
                        "0.3.0",
                        Flags::default(),
                        enforced(&[uri(&witness)]),
                    )
                    .await,
            );
            let ReleaseLogError::WitnessHead { origin, source } = &error else {
                panic!("{funnel:?} {case}: {error:?}");
            };
            assert_eq!(origin, uri(&witness), "{case}");
            assert!(expect(source), "{funnel:?} {case}: {source:?}");
            assert_eq!(error.is_security_violation(), security, "{case}");
            assert!(!error.is_unconfirmed(), "{case}");
            assert!(error.hint().is_some(), "{case}");
            assert!(
                !world.cache_path().exists(),
                "{funnel:?} {case}: nothing cached"
            );
        }
        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
    }
}

//
// Transport, over a loopback listener
//

/// What the test witness answers a request with.
#[derive(Clone)]
enum Reply {
    /// A status line with an empty body.
    Status(&'static str),
    /// `200 OK` with this body and a `Content-Length`.
    Body(Vec<u8>),
    /// `200 OK` with no declared length and this many body bytes, then close.
    Unframed(usize),
    /// By request path: `200 OK` with the body, or the status line; `404` for
    /// a path that is not listed.
    Routes(Vec<(&'static str, Result<Vec<u8>, &'static str>)>),
}

/// A loopback HTTP witness answering every request with `reply`. Returns its
/// base URL and the count of requests it has received.
async fn spawn_witness(reply: Reply) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let reply = reply.clone();
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                // The request target, for the replies that depend on it.
                let request = String::from_utf8_lossy(&buffer);
                let path = request.split(' ').nth(1).unwrap_or_default();
                let reply = match reply {
                    Reply::Routes(routes) => routes
                        .into_iter()
                        .find(|(route, _)| *route == path)
                        .map_or(Reply::Status("HTTP/1.1 404 Not Found"), |(_, answer)| {
                            answer.map_or_else(Reply::Status, Reply::Body)
                        }),
                    other => other,
                };
                // A write error is the client hanging up, which the oversize
                // cases expect.
                match reply {
                    Reply::Status(line) => {
                        let head =
                            format!("{line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        let _ = socket.write_all(head.as_bytes()).await;
                    }
                    Reply::Body(body) => {
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = socket.write_all(head.as_bytes()).await;
                        let _ = socket.write_all(&body).await;
                    }
                    Reply::Routes(_) => unreachable!("resolved to a status or a body above"),
                    Reply::Unframed(len) => {
                        let _ = socket
                            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                            .await;
                        let block = [b' '; 4096];
                        let mut sent = 0;
                        while sent < len {
                            if socket.write_all(&block).await.is_err() {
                                return;
                            }
                            sent += block.len();
                        }
                    }
                }
                let _ = socket.flush().await;
            });
        }
    });
    (base, requests)
}

/// A loopback URL nothing listens on.
async fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    base
}

/// How each transport outcome is classified: a witness with no head, a server
/// error, a refused connection, and a refused request are all "unreachable" —
/// noted with a reason, and the soft failure when nothing else covers the
/// release. A body over the limit is a served document, so a bad head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transport_failures_are_unreachable_and_an_oversized_body_is_a_bad_head() {
    let world = World::new().await;
    let funnel = Funnel::SelfArtifact;
    let manifest = funnel.publish(&world, "0.3.0").await;
    let over = usize::try_from(MAX_HEAD_SIZE).unwrap() + 1;

    let unreachable = [
        (
            "404",
            spawn_witness(Reply::Status("HTTP/1.1 404 Not Found"))
                .await
                .0,
            "path not found",
        ),
        (
            "500",
            spawn_witness(Reply::Status("HTTP/1.1 500 Internal Server Error"))
                .await
                .0,
            "HTTP 500",
        ),
        (
            "503",
            spawn_witness(Reply::Status("HTTP/1.1 503 Service Unavailable"))
                .await
                .0,
            "HTTP 503",
        ),
        (
            "403",
            spawn_witness(Reply::Status("HTTP/1.1 403 Forbidden"))
                .await
                .0,
            "permission denied",
        ),
        (
            "401",
            spawn_witness(Reply::Status("HTTP/1.1 401 Unauthorized"))
                .await
                .0,
            "permission denied",
        ),
        ("connection refused", closed_port().await, "download failed"),
    ];
    for (case, base, reason) in &unreachable {
        let log = resolve_log(&origins(&[base])).await.unwrap();
        assert!(log.head().is_none(), "{case}");
        assert!(log.answered().is_empty(), "{case}");
        assert_eq!(log.unreachable().len(), 1, "{case}");
        assert_eq!(&log.unreachable()[0].origin, base, "{case}");
        assert!(
            log.unreachable()[0].reason.contains(reason),
            "{case}: {:?}",
            log.unreachable()[0]
        );
        // Through the funnel: the soft failure, nothing installed.
        let result = funnel
            .install(
                &world.storage(),
                "0.3.0",
                Flags::default(),
                enforced(&[base]),
            )
            .await;
        assert!(log_error(result).is_unconfirmed(), "{case}");
    }
    assert!(world.installed().is_empty());
    assert!(!world.cache_path().exists());

    // Over the limit, declared or not: refused while reading, and a bad head.
    for (case, reply) in [
        ("declared length", Reply::Body(vec![b' '; over])),
        ("no declared length", Reply::Unframed(4 * over)),
    ] {
        let (base, _) = spawn_witness(reply).await;
        let error = log_error(
            funnel
                .install(
                    &world.storage(),
                    "0.3.0",
                    Flags::default(),
                    enforced(&[&base]),
                )
                .await,
        );
        assert!(
            matches!(
                &error,
                ReleaseLogError::WitnessHead { origin, source }
                    if origin == &base && matches!(**source, ReleaseLogError::TooLarge(n) if n > MAX_HEAD_SIZE)
            ),
            "{case}: {error:?}"
        );
        assert!(!error.is_unconfirmed(), "{case}");
    }
    assert!(world.installed().is_empty());
    assert!(!world.cache_path().exists());

    // And a witness that serves the head over HTTP confirms the release.
    let body = signed(head(3, vec![ok_row(SELF_NAME, &manifest)]))
        .to_json()
        .unwrap()
        .into_bytes();
    let (base, requests) = spawn_witness(Reply::Body(body)).await;
    let report = confirmed(
        funnel
            .install(
                &world.storage(),
                "0.3.0",
                Flags::default(),
                enforced(&[&base]),
            )
            .await
            .unwrap(),
    );
    assert_eq!(report.answered, [base]);
    assert_eq!(report.seq, 3);
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "one request per witness"
    );
    assert!(!world.installed().is_empty());
}

//
// Co-signatures
//

/// The statement line a co-signer's cron writes for `head_json`:
/// `<seq> <sha512 of the bytes>\n`.
fn statement(seq: u64, head_json: &[u8]) -> Vec<u8> {
    format!("{seq} {}\n", ContentHash::sha512(head_json).to_hex()).into_bytes()
}

/// A `witness` file: `line`, then its SSH signature by `key`.
fn witness_file(key: &fuz_sign::SigningKey, line: &[u8]) -> Vec<u8> {
    [line, sign_sshsig(key, CO_SIGN_NAMESPACE, line).as_bytes()].concat()
}

/// Publish `line`, signed by `key`, as `witness`'s co-signature.
fn co_sign_line(witness: &Path, key: &fuz_sign::SigningKey, line: &[u8]) {
    std::fs::write(witness.join(WITNESS_KEY), witness_file(key, line)).unwrap();
}

/// Co-sign the head `witness` serves, as its co-signer would: from the bytes
/// of the `head.json` file there, at `seq`.
fn co_sign(witness: &Path, seq: u64) {
    let served = std::fs::read(witness.join(HEAD_KEY)).unwrap();
    co_sign_line(witness, &witness_key(), &statement(seq, &served));
}

fn stop_co_signing(witness: &Path) {
    let _ = std::fs::remove_file(witness.join(WITNESS_KEY));
}

/// The witness key, as the key table pairs it with an origin.
fn witness_public_key() -> [u8; 32] {
    *witness_key().verifying_key().as_bytes()
}

/// A policy over `origins` in which `co_signer` has the witness key.
fn co_signed_policy(origins: &[&str], co_signer: &str) -> ReleaseLogPolicy {
    enforced_with_keys(origins, &[(co_signer, witness_public_key())])
}

fn seen(origin: &Path, seq: u64, coverage: CoSignCoverage) -> CoSignReport {
    CoSignReport {
        origin: uri(origin).to_string(),
        seq,
        coverage,
    }
}

/// `head_json` with the signature's `signed_at` — which the release signature
/// does not cover — rewritten. Still a valid head with the same signed
/// content; other bytes.
fn with_signed_at(head_json: &str, signed_at: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(head_json).unwrap();
    value["signature"]["signed_at"] = serde_json::json!(signed_at);
    let mut json = serde_json::to_string_pretty(&value).unwrap();
    json.push('\n');
    assert_ne!(json, head_json);
    json
}

/// `head_json` re-encoded without whitespace: the same head, other bytes.
fn compact(head_json: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(head_json).unwrap();
    serde_json::to_string(&value).unwrap()
}

/// A co-signature of the head that confirms the release: the install proceeds
/// and the report says who co-signed which `seq`.
#[tokio::test]
async fn a_matching_co_signature_is_reported_and_changes_nothing_else() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        serve(&witness, head(7, vec![ok_row(funnel.name(), &manifest)]));
        co_sign(&witness, 7);

        let report = confirmed(
            funnel
                .install(
                    &world.storage(),
                    "0.3.0",
                    Flags::default(),
                    co_signed_policy(&[uri(&witness)], uri(&witness)),
                )
                .await
                .unwrap(),
        );
        assert_eq!(
            report,
            ReleaseLogReport {
                seq: 7,
                signed_at: NOW.to_string(),
                source: HeadSource::Witness,
                answered: vec![uri(&witness).to_string()],
                unreachable: Vec::new(),
                cache_written: true,
                co_signs: vec![seen(&witness, 7, CoSignCoverage::EffectiveHead)],
            },
            "{funnel:?}"
        );
        assert!(!world.installed().is_empty(), "{funnel:?}");
        // The cache directory holds the head and nothing about a co-signature.
        let names: Vec<_> = std::fs::read_dir(world.cache_path().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [HEAD_KEY], "{funnel:?}");
    }
}

/// The key is matched on the origin up to a trailing slash, and an origin the
/// key table does not name is not asked for a co-signature at all.
#[tokio::test]
async fn the_witness_key_follows_the_origin_it_is_listed_for() {
    let world = World::new().await;
    let funnel = Funnel::Tool;
    let manifest = funnel.publish(&world, "0.3.0").await;
    let witness = world.witness("witness");
    serve(&witness, head(7, vec![ok_row(TOOL, &manifest)]));
    co_sign(&witness, 7);
    let with_slash = format!("{}/", uri(&witness));

    for (configured, listed) in [
        (uri(&witness), with_slash.as_str()),
        (&with_slash, uri(&witness)),
    ] {
        let log = resolve_log_read_only(&origins_with_keys(
            &[configured],
            &[(listed, witness_public_key())],
        ))
        .await
        .unwrap();
        assert_eq!(log.co_signs().len(), 1, "{configured} / {listed}");
        assert_eq!(log.co_signs()[0].origin, configured);
    }
    // Listed for another origin: this one has no key.
    let elsewhere = world.witness("elsewhere");
    let log = resolve_log_read_only(&origins_with_keys(
        &[uri(&witness)],
        &[(uri(&elsewhere), witness_public_key())],
    ))
    .await
    .unwrap();
    assert!(log.co_signs().is_empty());
}

/// A witness with no key is never asked for a co-signature: whatever sits in
/// its `witness` file is not read, so garbage there changes nothing.
#[tokio::test]
async fn without_a_witness_key_the_witness_file_is_ignored() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        serve(&witness, head(7, vec![ok_row(funnel.name(), &manifest)]));
        std::fs::write(witness.join(WITNESS_KEY), vec![b'x'; 64 * 1024]).unwrap();

        let report = confirmed(
            funnel
                .install(
                    &world.storage(),
                    "0.3.0",
                    Flags::default(),
                    enforced(&[uri(&witness)]),
                )
                .await
                .unwrap(),
        );
        assert!(report.co_signs.is_empty(), "{funnel:?}");
        assert_eq!(report.seq, 7);

        // Control: the same file, once the witness has a key, is a refusal.
        let _ = std::fs::remove_file(world.cache_path());
        let error = resolve_error(
            resolve_log(&origins_with_keys(
                &[uri(&witness)],
                &[(uri(&witness), witness_public_key())],
            ))
            .await,
        );
        assert!(
            matches!(error, ReleaseLogError::WitnessCoSign { .. }),
            "{funnel:?}: {error:?}"
        );
    }
}

/// Over HTTP, counted: a witness with no key gets the one request it always
/// got; one with a key gets exactly one more, for `witness`; and a witness
/// that does not serve it, or cannot be reached for it, has no co-signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_co_signature_costs_one_request_and_only_for_a_witness_with_a_key() {
    type Expect = fn(&CoSignProblem) -> bool;
    let world = World::new().await;
    let funnel = Funnel::SelfArtifact;
    let manifest = funnel
        .publish(&world, "0.3.0")
        .await
        .verify_signature()
        .unwrap();
    let served = verified(head(3, vec![ok_row(SELF_NAME, &manifest)]));
    let head_json = served.to_json().unwrap().into_bytes();
    let witness = witness_file(&witness_key(), &statement(3, &head_json));
    let full = || {
        Reply::Routes(vec![
            ("/head.json", Ok(head_json.clone())),
            ("/witness", Ok(witness.clone())),
        ])
    };

    // No key: one request, and no co-signature in the report.
    let (base, requests) = spawn_witness(full()).await;
    let report = confirmed(
        check_release_log_read_only(&enforced(&[&base]), &manifest)
            .await
            .unwrap(),
    );
    assert!(report.co_signs.is_empty());
    assert_eq!(requests.load(Ordering::SeqCst), 1, "no key: the head alone");

    // The same witness with a key: the head and the one file.
    let (base, requests) = spawn_witness(full()).await;
    let report = confirmed(
        check_release_log_read_only(&co_signed_policy(&[&base], &base), &manifest)
            .await
            .unwrap(),
    );
    assert_eq!(
        report.co_signs,
        [CoSignReport {
            origin: base.clone(),
            seq: 3,
            coverage: CoSignCoverage::EffectiveHead,
        }]
    );
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    // No `witness`, or a witness that cannot be reached for it or refuses it:
    // no co-signature, and no error.
    for answer in [
        None,
        Some("HTTP/1.1 500 Internal Server Error"),
        Some("HTTP/1.1 503 Service Unavailable"),
        Some("HTTP/1.1 403 Forbidden"),
        Some("HTTP/1.1 401 Unauthorized"),
    ] {
        let mut routes = vec![("/head.json", Ok(head_json.clone()))];
        if let Some(status) = answer {
            routes.push(("/witness", Err(status)));
        }
        let (base, requests) = spawn_witness(Reply::Routes(routes)).await;
        let report = confirmed(
            check_release_log_read_only(&co_signed_policy(&[&base], &base), &manifest)
                .await
                .unwrap(),
        );
        assert!(report.co_signs.is_empty(), "{answer:?}");
        assert_eq!(report.seq, 3);
        assert_eq!(requests.load(Ordering::SeqCst), 2, "{answer:?}");
    }

    // A witness that does not serve its head is not asked for a co-signature.
    let (base, requests) =
        spawn_witness(Reply::Routes(vec![("/witness", Ok(witness.clone()))])).await;
    let log = resolve_log_read_only(&origins_with_keys(
        &[&base],
        &[(&base, witness_public_key())],
    ))
    .await
    .unwrap();
    assert!(log.head().is_none() && log.co_signs().is_empty());
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    // A served document that is not a co-signature is a refusal: oversized,
    // and a host that answers 200 with a page for a file it does not have.
    let page = b"<!DOCTYPE html>\n<html><body>\x1b[31mNot Found: secret-token</body></html>\n";
    let bad: [(&str, Vec<u8>, Expect); 2] = [
        (
            "oversized",
            vec![b'7'; usize::try_from(MAX_WITNESS_SIZE).unwrap() + 1],
            |p| matches!(p, CoSignProblem::TooLarge { .. }),
        ),
        ("a page", page.to_vec(), |p| {
            matches!(
                p,
                CoSignProblem::Signature(fuz_crypto::SshsigError::Armor(_))
            )
        }),
    ];
    for (case, body, expect) in bad {
        let (base, _) = spawn_witness(Reply::Routes(vec![
            ("/head.json", Ok(head_json.clone())),
            ("/witness", Ok(body)),
        ]))
        .await;
        let error = resolve_error(
            check_release_log_read_only(&co_signed_policy(&[&base], &base), &manifest).await,
        );
        let ReleaseLogError::WitnessCoSign { origin, source } = &error else {
            panic!("{case}: {error:?}");
        };
        assert_eq!(origin, &base, "{case}");
        assert!(expect(source), "{case}: {source:?}");
        assert!(!error.is_security_violation(), "{case}");
        // The cause is legible and repeats nothing the host sent.
        let message = error.to_string();
        assert!(message.contains("witness file"), "{case}: {message}");
        assert!(!message.contains("secret-token"), "{case}: {message}");
        assert!(!message.contains('\u{1b}'), "{case}: {message:?}");
        assert!(message.len() < 512, "{case}: {}", message.len());
    }
}

/// A co-signature is a beacon: none at all is not an error, and neither is one
/// for another `seq` than the head served beside it — older (the co-signer
/// lags) or newer (its copy of the head does).
#[tokio::test]
async fn an_absent_or_lagging_co_signature_is_never_an_error() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        serve(&witness, head(7, vec![ok_row(funnel.name(), &manifest)]));
        let policy = || co_signed_policy(&[uri(&witness)], uri(&witness));
        let install = || async {
            confirmed(
                funnel
                    .install(&world.storage(), "0.3.0", Flags::default(), policy())
                    .await
                    .unwrap(),
            )
        };

        // No `witness` file.
        assert!(install().await.co_signs.is_empty(), "{funnel:?}");

        // A co-signature at another seq than the served head's: verified,
        // compared with nothing, and whatever digest it names.
        for seq in [1, 6, 8, 400] {
            co_sign_line(
                &witness,
                &witness_key(),
                &statement(seq, b"another document"),
            );
            let report = install().await;
            assert_eq!(
                report.co_signs,
                [seen(&witness, seq, CoSignCoverage::Uncompared)],
                "{funnel:?}"
            );
            assert_eq!(report.seq, 7);
        }
    }
}

/// A co-signer whose origin lags covers the older head it serves; the verdict
/// comes from the newer head another witness, or the cache, holds.
#[tokio::test]
async fn a_lagging_co_signer_covers_the_older_head_it_serves() {
    let world = World::new().await;
    let funnel = Funnel::Tool;
    let manifest = funnel.publish(&world, "0.3.0").await;
    let (ahead, co_signer) = (world.witness("ahead"), world.witness("co-signer"));
    let newer = serve(&ahead, head(6, vec![filler_row(), ok_row(TOOL, &manifest)]));
    serve(&co_signer, head(5, vec![filler_row()]));
    co_sign(&co_signer, 5);

    for order in [[&ahead, &co_signer], [&co_signer, &ahead]] {
        let report = confirmed(
            funnel
                .install(
                    &world.storage(),
                    "0.3.0",
                    Flags::default(),
                    co_signed_policy(&[uri(order[0]), uri(order[1])], uri(&co_signer)),
                )
                .await
                .unwrap(),
        );
        assert_eq!(report.seq, 6);
        assert_eq!(
            report.co_signs,
            [seen(&co_signer, 5, CoSignCoverage::OlderHead)]
        );
    }

    // The same against a newer cached head, the other witness gone.
    seed_cache(&world, &newer);
    let log = resolve_log_read_only(&origins_with_keys(
        &[uri(&co_signer)],
        &[(uri(&co_signer), witness_public_key())],
    ))
    .await
    .unwrap();
    assert_eq!(log.source(), Some(HeadSource::CacheAheadOfWitness));
    assert_eq!(
        log.co_signs(),
        [seen(&co_signer, 5, CoSignCoverage::OlderHead)]
    );

    // The co-signer ahead of a lagging keyless witness: the effective head.
    stop_co_signing(&co_signer);
    let _ = std::fs::remove_file(world.cache_path());
    serve(
        &co_signer,
        head(6, vec![filler_row(), ok_row(TOOL, &manifest)]),
    );
    serve(&ahead, head(5, vec![filler_row()]));
    co_sign(&co_signer, 6);
    let log = resolve_log_read_only(&origins_with_keys(
        &[uri(&ahead), uri(&co_signer)],
        &[(uri(&co_signer), witness_public_key())],
    ))
    .await
    .unwrap();
    assert_eq!(
        log.co_signs(),
        [seen(&co_signer, 6, CoSignCoverage::EffectiveHead)]
    );
}

/// A co-signature is compared with its own origin's served bytes and nothing
/// else. A mirror serving the same head as other bytes — the unsigned
/// `signed_at` rewritten, or the JSON re-encoded — is one history with the
/// co-signed head by its signed content, and cannot make a mismatch: not
/// beside the co-signer in either order, and not through the cache.
#[tokio::test]
async fn a_mirror_serving_the_head_as_other_bytes_is_no_co_signature_mismatch() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let (co_signer, mirror) = (world.witness("co-signer"), world.witness("mirror"));
        let genuine = signed(head(7, vec![ok_row(funnel.name(), &manifest)]))
            .to_json()
            .unwrap();
        std::fs::write(co_signer.join(HEAD_KEY), &genuine).unwrap();
        co_sign(&co_signer, 7);
        let effective = || [seen(&co_signer, 7, CoSignCoverage::EffectiveHead)];

        // Each with whether the document the cache then holds differs from
        // the co-signed one: the cache stores a head re-serialized, so a
        // re-encoding alone is cached as the co-signed bytes.
        for (case, mirrored, cached_differs) in [
            (
                "signed_at rewritten",
                with_signed_at(&genuine, common::LATER),
                true,
            ),
            ("re-encoded", compact(&genuine), false),
            (
                "both",
                compact(&with_signed_at(&genuine, common::LATER)),
                true,
            ),
        ] {
            std::fs::write(mirror.join(HEAD_KEY), &mirrored).unwrap();

            // Beside the co-signer, in both orders.
            for order in [[&co_signer, &mirror], [&mirror, &co_signer]] {
                let _ = std::fs::remove_file(world.cache_path());
                let report = confirmed(
                    check_release_log_read_only(
                        &co_signed_policy(&[uri(order[0]), uri(order[1])], uri(&co_signer)),
                        &manifest.clone().verify_signature().unwrap(),
                    )
                    .await
                    .unwrap(),
                );
                assert_eq!(report.co_signs, effective(), "{funnel:?} {case}");
                assert_eq!(report.answered.len(), 2, "{funnel:?} {case}");
            }

            // The mirror's document cached first, then the co-signer alone.
            let _ = std::fs::remove_file(world.cache_path());
            let log = resolve_log(&origins(&[uri(&mirror)])).await.unwrap();
            assert!(log.cache_written(), "{funnel:?} {case}");
            let cached = std::fs::read_to_string(world.cache_path()).unwrap();
            assert_eq!(cached != genuine, cached_differs, "{funnel:?} {case}");
            let log = resolve_log(&origins_with_keys(
                &[uri(&co_signer)],
                &[(uri(&co_signer), witness_public_key())],
            ))
            .await
            .unwrap();
            assert_eq!(log.co_signs(), effective(), "{funnel:?} {case}");
        }

        // And through an install.
        let _ = std::fs::remove_file(world.cache_path());
        let report = confirmed(
            funnel
                .install(
                    &world.storage(),
                    "0.3.0",
                    Flags::default(),
                    co_signed_policy(&[uri(&mirror), uri(&co_signer)], uri(&co_signer)),
                )
                .await
                .unwrap(),
        );
        assert_eq!(report.co_signs, effective(), "{funnel:?}");
    }
}

#[track_caller]
fn assert_mismatch(error: &ReleaseLogError, origin: &Path, seq: u64) {
    assert!(
        matches!(
            error,
            ReleaseLogError::Contradiction(LogContradiction::CoSignMismatch {
                origin: o,
                seq: s,
            }) if o == uri(origin) && *s == seq
        ),
        "{error:?}"
    );
    assert_hard(error);
    assert!(error.hint().is_some_and(|h| h.ends_with("do not install")));
}

/// A co-signer's origin serving, at the co-signed `seq`, bytes its co-signature
/// does not cover is a contradiction naming that origin — whether the bytes
/// are another document, the same head with `signed_at` rewritten, or the same
/// head re-encoded. Nothing is installed and nothing cached.
#[tokio::test]
async fn a_co_signers_origin_serving_bytes_it_did_not_co_sign_is_a_contradiction() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let (co_signer, other) = (world.witness("co-signer"), world.witness("other"));
        let genuine = signed(head(7, vec![ok_row(funnel.name(), &manifest)]))
            .to_json()
            .unwrap();
        std::fs::write(other.join(HEAD_KEY), &genuine).unwrap();
        let storage = Counting::new(world.storage());

        // The co-signature is of the genuine bytes throughout; what the
        // origin serves beside it changes.
        let line = statement(7, genuine.as_bytes());
        for (case, served) in [
            (
                "signed_at rewritten",
                with_signed_at(&genuine, common::LATER),
            ),
            ("re-encoded", compact(&genuine)),
        ] {
            std::fs::write(co_signer.join(HEAD_KEY), &served).unwrap();
            co_sign_line(&co_signer, &witness_key(), &line);
            // Alone, and beside a witness serving the co-signed bytes
            // themselves: another origin's head does not stand in.
            for list in [
                vec![uri(&co_signer)],
                vec![uri(&co_signer), uri(&other)],
                vec![uri(&other), uri(&co_signer)],
            ] {
                let error = log_error(
                    funnel
                        .install(
                            &storage,
                            "0.3.0",
                            Flags::default(),
                            co_signed_policy(&list, uri(&co_signer)),
                        )
                        .await,
                );
                assert_mismatch(&error, &co_signer, 7);
                assert!(
                    error
                        .to_string()
                        .ends_with("its own co-signature does not cover"),
                    "{funnel:?} {case}: {error}"
                );
            }
            assert!(!world.cache_path().exists(), "{funnel:?} {case}");
        }

        // Another document's digest at the served seq.
        std::fs::write(co_signer.join(HEAD_KEY), &genuine).unwrap();
        co_sign_line(
            &co_signer,
            &witness_key(),
            &statement(7, b"another document"),
        );
        let error = log_error(
            funnel
                .install(
                    &storage,
                    "0.3.0",
                    Flags::default(),
                    co_signed_policy(&[uri(&co_signer)], uri(&co_signer)),
                )
                .await,
        );
        assert_mismatch(&error, &co_signer, 7);
        assert!(!world.cache_path().exists(), "{funnel:?}: nothing cached");

        // A cached head is left as it was.
        seed_cache(&world, &verified(head(6, vec![filler_row()])));
        let before = std::fs::read(world.cache_path()).unwrap();
        let _ = funnel
            .install(
                &storage,
                "0.3.0",
                Flags::default(),
                co_signed_policy(&[uri(&co_signer)], uri(&co_signer)),
            )
            .await;
        assert_eq!(std::fs::read(world.cache_path()).unwrap(), before);

        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
    }
}

/// A `witness` file that is present and cannot be used is a hard failure
/// naming the witness, in every way it can fail — and it is not passed over
/// for another witness that serves a good head.
#[tokio::test]
async fn an_unusable_co_signature_is_a_hard_failure_for_its_witness() {
    type Expect = fn(&CoSignProblem) -> bool;
    /// A name, the `witness` bytes, the problem expected, and whether it is a
    /// security violation.
    type Case = (&'static str, Vec<u8>, Expect, bool);
    let world = World::new().await;
    let funnel = Funnel::SelfArtifact;
    let manifest = funnel.publish(&world, "0.3.0").await;
    let (witness, good) = (world.witness("witness"), world.witness("good"));
    let served = serve(&witness, head(7, vec![ok_row(SELF_NAME, &manifest)]));
    serve(&good, head(7, vec![ok_row(SELF_NAME, &manifest)]));
    let line = statement(7, served.to_json().unwrap().as_bytes());
    let sig = |key: &fuz_sign::SigningKey, namespace: &str, message: &[u8]| {
        sign_sshsig(key, namespace, message).into_bytes()
    };
    // `line` with something else's signature after it.
    let with = |signature: Vec<u8>| [line.clone(), signature].concat();
    let good_file = witness_file(&witness_key(), &line);
    let hex = ContentHash::sha512(b"x").to_hex();
    // A line that is validly signed and is not the statement.
    let signed_line = |bad: &[u8]| witness_file(&witness_key(), bad);
    let invalid: Expect = |p| {
        matches!(
            p,
            CoSignProblem::Signature(fuz_crypto::SshsigError::InvalidSignature)
        )
    };
    let armor: Expect = |p| {
        matches!(
            p,
            CoSignProblem::Signature(fuz_crypto::SshsigError::Armor(_))
        )
    };
    let wrong_key: Expect = |p| {
        matches!(
            p,
            CoSignProblem::Signature(fuz_crypto::SshsigError::WrongKey)
        )
    };
    let bad_line: Expect = |p| matches!(p, CoSignProblem::Line(_));

    let cases: Vec<Case> = vec![
        (
            "signature over another line",
            with(sig(&witness_key(), CO_SIGN_NAMESPACE, b"8 x\n")),
            invalid,
            true,
        ),
        (
            "line edited after signing",
            [
                statement(7, b"another document"),
                sig(&witness_key(), CO_SIGN_NAMESPACE, &line),
            ]
            .concat(),
            invalid,
            true,
        ),
        (
            "another namespace",
            with(sig(&witness_key(), "file", &line)),
            |p| {
                matches!(
                    p,
                    CoSignProblem::Signature(fuz_crypto::SshsigError::WrongNamespace)
                )
            },
            true,
        ),
        (
            "another ssh key",
            with(sig(&other_witness_key(), CO_SIGN_NAMESPACE, &line)),
            wrong_key,
            true,
        ),
        (
            "the release key as an ssh key",
            with(sig(&trusted_key(), CO_SIGN_NAMESPACE, &line)),
            wrong_key,
            true,
        ),
        ("the line with no signature", line.clone(), armor, false),
        (
            "the signature with no line",
            sig(&witness_key(), CO_SIGN_NAMESPACE, &line),
            armor,
            false,
        ),
        (
            "garbage after the line",
            with(b"not a signature".to_vec()),
            armor,
            false,
        ),
        ("empty", Vec::new(), armor, false),
        (
            "a blank line between the line and the signature",
            [
                &line[..],
                b"\n",
                &sig(&witness_key(), CO_SIGN_NAMESPACE, &line),
            ]
            .concat(),
            armor,
            false,
        ),
        (
            "text after the signature",
            [&good_file[..], b"more\n"].concat(),
            armor,
            false,
        ),
        (
            "two newlines after the signature",
            [&good_file[..], b"\n"].concat(),
            armor,
            false,
        ),
        (
            "oversized",
            vec![b'7'; usize::try_from(MAX_WITNESS_SIZE).unwrap() + 1],
            |p| matches!(p, CoSignProblem::TooLarge { .. }),
            false,
        ),
        (
            "signed, the sha512sum line",
            signed_line(format!("{hex}  head.json\n").as_bytes()),
            bad_line,
            false,
        ),
        (
            "signed, seq zero",
            signed_line(format!("0 {hex}\n").as_bytes()),
            bad_line,
            false,
        ),
        (
            "signed, uppercase digest",
            signed_line(format!("7 {}\n", hex.to_uppercase()).as_bytes()),
            bad_line,
            false,
        ),
        (
            "signed, a trailing space",
            signed_line(format!("7 {hex} \n").as_bytes()),
            bad_line,
            false,
        ),
    ];

    // Control: the file the cases are built from is a good co-signature, with
    // and without the armor's final newline.
    for file in [&good_file[..], &good_file[..good_file.len() - 1]] {
        std::fs::write(witness.join(WITNESS_KEY), file).unwrap();
        let log = resolve_log_read_only(&origins_with_keys(
            &[uri(&witness)],
            &[(uri(&witness), witness_public_key())],
        ))
        .await
        .unwrap();
        assert_eq!(
            log.co_signs(),
            [seen(&witness, 7, CoSignCoverage::EffectiveHead)]
        );
    }

    let storage = Counting::new(world.storage());
    for (case, file, expect, security) in cases {
        std::fs::write(witness.join(WITNESS_KEY), file).unwrap();
        for order in [[&witness, &good], [&good, &witness]] {
            let error = log_error(
                funnel
                    .install(
                        &storage,
                        "0.3.0",
                        Flags::default(),
                        co_signed_policy(&[uri(order[0]), uri(order[1])], uri(&witness)),
                    )
                    .await,
            );
            let ReleaseLogError::WitnessCoSign { origin, source } = &error else {
                panic!("{case}: {error:?}");
            };
            assert_eq!(origin, uri(&witness), "{case}");
            assert!(expect(source), "{case}: {source:?}");
            assert_eq!(error.is_security_violation(), security, "{case}");
            assert!(!error.is_unconfirmed(), "{case}");
            // The remedy keeps the rest of the check; it is not the opt-out.
            let hint = error.hint().unwrap_or_default();
            assert!(hint.contains("FUZ_RELEASE_LOG_URL"), "{case}: {hint}");
            assert!(!hint.contains("=off"), "{case}: {hint}");
            assert!(!world.cache_path().exists(), "{case}: nothing cached");
        }
    }
    assert_eq!(storage.tarballs(), 0);
    assert!(world.installed().is_empty());

    // The remedy the hint names works: without that origin the release is
    // confirmed by the other witness.
    let report = confirmed(
        funnel
            .install(
                &storage,
                "0.3.0",
                Flags::default(),
                co_signed_policy(&[uri(&good)], uri(&witness)),
            )
            .await
            .unwrap(),
    );
    assert!(report.co_signs.is_empty());
}

/// A co-signature never confirms anything: a release the head revokes or does
/// not record is refused exactly as it is without one, and a head signed by
/// the witness key is not a head.
#[tokio::test]
async fn a_co_signature_rescues_nothing_and_a_witness_key_signs_no_head() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let manifest = funnel.publish(&world, "0.3.0").await;
        let witness = world.witness("witness");
        let policy = || co_signed_policy(&[uri(&witness)], uri(&witness));
        let storage = Counting::new(world.storage());
        let install = || async {
            log_error(
                funnel
                    .install(&storage, "0.3.0", Flags::default(), policy())
                    .await,
            )
        };

        // Revoked, with a matching co-signature of the revoking head.
        let mut revoked = ok_row(funnel.name(), &manifest);
        revoked.status = RowStatus::Revoked;
        serve(&witness, head(7, vec![revoked]));
        co_sign(&witness, 7);
        let error = install().await;
        assert!(
            matches!(error, ReleaseLogError::Revoked { .. }),
            "{funnel:?}: {error:?}"
        );

        // Not recorded, with a matching co-signature. (A fresh log: the
        // revoking head above was cached.)
        let _ = std::fs::remove_file(world.cache_path());
        serve(&witness, head(8, vec![filler_row()]));
        co_sign(&witness, 8);
        let error = install().await;
        assert!(
            matches!(error, ReleaseLogError::RowMissing { .. }),
            "{funnel:?}: {error:?}"
        );

        // A head the witness key signed, recording the release, co-signed by
        // that same key: the key is not a release key, so there is no head.
        let _ = std::fs::remove_file(world.cache_path());
        let forged = sign_head(
            head(9, vec![ok_row(funnel.name(), &manifest)]),
            &witness_key(),
            NOW,
        )
        .unwrap();
        std::fs::write(witness.join(HEAD_KEY), forged.to_json().unwrap()).unwrap();
        co_sign(&witness, 9);
        let error = install().await;
        assert!(
            matches!(
                &error,
                ReleaseLogError::WitnessHead { origin, source }
                    if origin == uri(&witness)
                        && matches!(
                            **source,
                            ReleaseLogError::Signature(fuz_crypto::VerifyError::UntrustedKey(_))
                        )
            ),
            "{funnel:?}: {error:?}"
        );
        assert_hard(&error);
        assert!(!world.cache_path().exists(), "{funnel:?}");

        assert_eq!(storage.tarballs(), 0, "{funnel:?}");
        assert!(world.installed().is_empty(), "{funnel:?}");
    }
}

/// The read-only check sees a co-signature and a co-signature mismatch as the
/// installing one does, and writes nothing: no cache, no state directory, and
/// nothing about the co-signature anywhere under the home.
#[tokio::test]
async fn the_read_only_check_holds_co_signatures_and_writes_nothing() {
    for funnel in FUNNELS {
        let world = World::new().await;
        funnel.publish(&world, "0.3.0").await;
        let manifest = funnel.manifest(&world, "0.3.0").await;
        let witness = world.witness("witness");
        serve(&witness, head(7, vec![ok_row(funnel.name(), &manifest)]));
        let policy = co_signed_policy(&[uri(&witness)], uri(&witness));
        let before = home_snapshot(&world);

        co_sign(&witness, 7);
        let checked = check_latest(funnel, &world, &policy).await.unwrap();
        let LogCheck::Confirmed(report) = checked.release_log() else {
            panic!("{funnel:?}: {:?}", checked.release_log());
        };
        assert_eq!(
            report.co_signs,
            [seen(&witness, 7, CoSignCoverage::EffectiveHead)]
        );
        assert!(!report.cache_written);
        assert_eq!(home_snapshot(&world), before, "{funnel:?}");

        co_sign_line(&witness, &witness_key(), &statement(7, b"another document"));
        let error = resolve_error(check_latest(funnel, &world, &policy).await);
        assert_mismatch(&error, &witness, 7);
        assert_eq!(home_snapshot(&world), before, "{funnel:?}");
        assert!(!world.home.join("state").exists(), "{funnel:?}");
    }
}

/// The digest the client compares is the SHA-512 of the `head.json` bytes the
/// co-signer's origin serves: a co-signer that hashes the file a publish
/// wrote, with `sha512sum`, and serves that file, is confirmed.
#[tokio::test]
async fn the_co_signed_digest_is_the_sha512sum_of_the_served_head_json() {
    if !common::git_available() {
        return;
    }
    let world = World::new().await;
    let fixture = common::Fixture::new();
    let published = common::publish_self(&fixture, "0.3.0").await.unwrap();
    let seq = published.logged.as_ref().unwrap().seq;

    // The file a publish committed, hashed as a co-signer hashes it.
    let head_file = fixture.checkout.join(HEAD_KEY);
    let file_bytes = std::fs::read(&head_file).unwrap();
    let line = statement(seq, &file_bytes);
    if let Ok(output) = std::process::Command::new("sha512sum")
        .arg(&head_file)
        .output()
        && output.status.success()
    {
        let stdout = String::from_utf8(output.stdout).unwrap();
        let hex = stdout.split(' ').next().unwrap();
        assert_eq!(format!("{seq} {hex}\n").into_bytes(), line);
    }

    // Co-signed from the file, and served from the checkout beside it.
    co_sign_line(&fixture.checkout, &witness_key(), &line);
    let options = FetchOptions {
        release_log: co_signed_policy(&[uri(&fixture.checkout)], uri(&fixture.checkout)),
        ..FetchOptions::default()
    };
    let result = fetch_version(&fixture.storage(), "0.3.0", &options)
        .await
        .unwrap();
    assert_eq!(
        confirmed(result.release_log).co_signs,
        [seen(&fixture.checkout, seq, CoSignCoverage::EffectiveHead)]
    );
    assert!(result.artifact_dir.starts_with(&world.home));
}

//
// Ordering
//

/// Version safety is decided before the log is asked: a downgrade is reported
/// as a downgrade even when the log would also refuse the release. Once the
/// downgrade is allowed, the log's refusal is what is left.
#[tokio::test]
async fn version_safety_is_reported_before_the_log() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let old = funnel.publish(&world, "0.3.0").await;
        funnel.publish(&world, "0.5.0").await;
        let storage = Counting::new(world.storage());
        funnel
            .install(
                &storage,
                "0.5.0",
                Flags::default(),
                ReleaseLogPolicy::Inactive,
            )
            .await
            .unwrap();
        // The self funnel only unpacks; the binary's switch makes it current.
        if funnel == Funnel::SelfArtifact {
            let installed = funnel.manifest(&world, "0.5.0").await;
            fuz_artifact::switch_current(&installed.content_hash).unwrap();
        }
        let before = world.installed();

        let witness = world.witness("witness");
        let mut revoked = ok_row(funnel.name(), &old);
        revoked.status = RowStatus::Revoked;
        serve(&witness, head(4, vec![revoked]));

        let result = funnel
            .install(
                &storage,
                "0.3.0",
                Flags::default(),
                enforced(&[uri(&witness)]),
            )
            .await;
        assert!(
            matches!(
                result,
                Err(ReleaseError::Manifest(ManifestError::Downgrade { .. }))
            ),
            "{funnel:?}: {result:?}"
        );
        // The log was not consulted at all: nothing was cached.
        assert!(!world.cache_path().exists(), "{funnel:?}");

        let error = log_error(
            funnel
                .install(
                    &storage,
                    "0.3.0",
                    Flags {
                        allow_downgrade: true,
                        force: false,
                    },
                    enforced(&[uri(&witness)]),
                )
                .await,
        );
        assert!(
            matches!(error, ReleaseLogError::Revoked { .. }),
            "{funnel:?}: {error:?}"
        );
        assert_eq!(world.installed(), before, "{funnel:?}");
        assert_eq!(storage.tarballs(), 1, "{funnel:?}: only 0.5.0 was fetched");
    }
}

/// A world-writable fuz home is refused before any witness is asked — by the
/// funnels and by the resolver itself — and nothing is cached into it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_home_guard_precedes_any_request_to_a_witness() {
    let world = World::new().await;
    let manifest = Funnel::Tool.publish(&world, "0.3.0").await;
    let body = signed(head(3, vec![ok_row(TOOL, &manifest)]))
        .to_json()
        .unwrap()
        .into_bytes();
    let (base, requests) = spawn_witness(Reply::Body(body)).await;
    std::fs::set_permissions(&world.home, std::fs::Permissions::from_mode(0o777)).unwrap();

    let insecure = |result: Result<(), ReleaseError>| {
        assert!(
            matches!(
                result,
                Err(ReleaseError::FuzHome(FuzHomeError::InsecureHome { .. }))
            ),
            "{result:?}"
        );
    };
    insecure(resolve_log(&origins(&[&base])).await.map(|_| ()));
    for funnel in FUNNELS {
        funnel.publish(&world, "0.4.0").await;
        insecure(
            funnel
                .install(
                    &world.storage(),
                    "0.4.0",
                    Flags::default(),
                    enforced(&[&base]),
                )
                .await
                .map(|_| ()),
        );
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0, "no witness was asked");
    assert!(!world.home.join("state").exists());

    // The read-only resolver writes nothing, so it is not guarded.
    let log = resolve_log_read_only(&origins(&[&base])).await.unwrap();
    assert_eq!(log.head().map(VerifiedHead::seq), Some(3));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert!(!world.home.join("state").exists());
}

//
// The real publish path
//

/// A release recorded by a publish given a log checkout is one the client
/// confirms: the checkout's `head.json` is served as the witness, unmodified.
#[tokio::test]
async fn a_release_logged_by_publish_is_confirmed_by_the_client() {
    if !common::git_available() {
        return;
    }
    let world = World::new().await;
    let fixture = common::Fixture::new();
    let published = common::publish_self(&fixture, "0.3.0").await.unwrap();
    let seq = published.logged.as_ref().unwrap().seq;

    let options = FetchOptions {
        release_log: enforced(&[uri(&fixture.checkout)]),
        ..FetchOptions::default()
    };
    let result = fetch_version(&fixture.storage(), "0.3.0", &options)
        .await
        .unwrap();
    let report = confirmed(result.release_log);
    assert_eq!(report.seq, seq);
    assert_eq!(report.source, HeadSource::Witness);
    assert!(report.cache_written);
    assert!(result.artifact_dir.starts_with(&world.home));
    assert_eq!(cached_seq(&world), seq);
}

//
// Pure: reconcile_heads and row_verdict
//

/// The head `reconcile_heads` chooses, as `(seq, source, advances the cache)`.
fn chosen(
    cached: Option<VerifiedHead>,
    witnessed: Vec<(String, VerifiedHead)>,
) -> Option<(u64, HeadSource, bool)> {
    reconcile_heads(cached, witnessed)
        .unwrap()
        .map(|e| (e.head().seq(), e.source(), e.advances_cache()))
}

#[test]
fn reconcile_picks_the_newest_head_and_says_when_the_cache_moves() {
    trust();
    let at = |seq: u64| {
        let rows = (0..seq)
            .map(|n| {
                let mut row = filler_row();
                row.version = format!("{n}.0.0");
                row
            })
            .collect();
        verified(head(seq, rows))
    };
    let witness = |seq| ("w".to_string(), at(seq));

    assert_eq!(chosen(None, Vec::new()), None);
    assert_eq!(
        chosen(None, vec![witness(3)]),
        Some((3, HeadSource::Witness, true))
    );
    assert_eq!(
        chosen(Some(at(3)), Vec::new()),
        Some((3, HeadSource::CacheWitnessUnreachable, false))
    );
    // Identical: the witness's head is used, the cache is left alone.
    assert_eq!(
        chosen(Some(at(3)), vec![witness(3)]),
        Some((3, HeadSource::Witness, false))
    );
    assert_eq!(
        chosen(Some(at(3)), vec![witness(4)]),
        Some((4, HeadSource::Witness, true))
    );
    assert_eq!(
        chosen(Some(at(4)), vec![witness(3)]),
        Some((4, HeadSource::CacheAheadOfWitness, false))
    );
    // Several witnesses: the newest, in any position.
    for order in [[2, 5, 3], [5, 3, 2], [3, 2, 5]] {
        let witnessed = order.into_iter().map(witness).collect();
        assert_eq!(
            chosen(Some(at(1)), witnessed),
            Some((5, HeadSource::Witness, true)),
            "{order:?}"
        );
    }
    // A cache ahead of every witness wins over all of them.
    assert_eq!(
        chosen(Some(at(6)), vec![witness(2), witness(5)]),
        Some((6, HeadSource::CacheAheadOfWitness, false))
    );
}

/// Two stale heads can each be contained in a newer third and still disagree
/// with each other. Comparing every pair catches that whatever the order;
/// comparing each head against the newest alone would not.
#[test]
fn reconcile_compares_every_pair_not_each_against_the_newest() {
    trust();
    let numbered = |n: u32| {
        let mut row = filler_row();
        row.version = format!("{n}.0.0");
        row
    };
    let a = || ("a".to_string(), verified(head(3, vec![numbered(1)])));
    let b = || {
        (
            "b".to_string(),
            verified(head(3, vec![numbered(1), numbered(2)])),
        )
    };
    let c = || {
        (
            "c".to_string(),
            verified(head(5, vec![numbered(1), numbered(2), numbered(3)])),
        )
    };
    // Each stale head alone is consistent with the newest.
    assert!(reconcile_heads(None, vec![a(), c()]).is_ok());
    assert!(reconcile_heads(None, vec![b(), c()]).is_ok());

    for order in [
        vec![a(), c(), b()],
        vec![c(), a(), b()],
        vec![a(), b(), c()],
        vec![b(), c(), a()],
    ] {
        let names: Vec<String> = order.iter().map(|(name, _)| name.clone()).collect();
        let result = reconcile_heads(None, order);
        assert!(
            matches!(
                &result,
                Err(LogContradiction::HeadsDiverge { first, second, violation })
                    if [first.as_str(), second.as_str()].iter().all(|n| ["a", "b"].contains(n))
                        && matches!(**violation, HeadViolation::SeqReused { seq: 3 })
            ),
            "{names:?}: {result:?}"
        );
    }
    // With the same stale head cached, the witness is what contradicts it.
    let result = reconcile_heads(Some(a().1), vec![c(), b()]);
    assert!(
        matches!(
            &result,
            Err(LogContradiction::SupersetViolated { origin, .. }) if origin == "b"
        ),
        "{result:?}"
    );
}

/// `row_verdict` over real signed manifests and heads: the row is looked up by
/// the manifest's own name, version, and target, and a revoked row is revoked
/// whatever its targets say.
#[tokio::test]
async fn row_verdict_reads_the_release_off_the_head() {
    let world = World::new().await;
    for funnel in FUNNELS {
        let manifest = funnel
            .publish(&world, "0.3.0")
            .await
            .verify_signature()
            .unwrap();
        let release = ReleasePins::of(&manifest);
        assert_eq!(release.name(), funnel.name());
        assert_eq!(release.version(), "0.3.0");
        assert_eq!(release.target(), current_target());

        let verdict = |rows| row_verdict(&verified(head(1, rows)), &release);
        let name = funnel.name();
        let good = pins(&manifest);

        assert_eq!(
            verdict(vec![filler_row(), ok_row(name, &manifest)]),
            RowVerdict::Confirmed
        );
        // The row's `sha512` is not part of the comparison.
        let mut with_sha512 = good.clone();
        with_sha512.sha512 = Some(ContentHash::sha512(b"flat binary"));
        assert_eq!(
            verdict(vec![row(
                name,
                "0.3.0",
                RowStatus::Ok,
                &[(current_target(), with_sha512)]
            )]),
            RowVerdict::Confirmed
        );
        assert_eq!(verdict(vec![filler_row()]), RowVerdict::Missing);
        assert_eq!(
            verdict(vec![row(
                name,
                "0.3.0",
                RowStatus::Ok,
                &[(other_target(), good.clone())]
            )]),
            RowVerdict::Missing
        );
        // Revoked wins over a missing target and over mismatched hashes.
        let mut wrong = good.clone();
        wrong.content_hash = format!("v1-{}", ContentHash::blake3(b"x").to_hex());
        for targets in [
            vec![(other_target(), good.clone())],
            vec![(current_target(), wrong.clone())],
            vec![(current_target(), good.clone())],
        ] {
            assert_eq!(
                verdict(vec![row(name, "0.3.0", RowStatus::Revoked, &targets)]),
                RowVerdict::Revoked
            );
        }
        assert_eq!(
            verdict(vec![row(
                name,
                "0.3.0",
                RowStatus::Ok,
                &[(current_target(), wrong)]
            )]),
            RowVerdict::Mismatch(TargetField::ContentHash)
        );
        // The other funnel's row under the same version is not this release.
        let other_name = if funnel == Funnel::Tool {
            SELF_NAME
        } else {
            TOOL
        };
        assert_eq!(
            verdict(vec![row(
                other_name,
                "0.3.0",
                RowStatus::Ok,
                &[(current_target(), good)]
            )]),
            RowVerdict::Missing
        );
    }
}

//
// The read-only check: every verdict, and a home left as it was
//

/// Every path under the fuz home with its kind, mode, and content — the whole
/// tree, the release log cache included.
fn home_snapshot(world: &World) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        let key = path.strip_prefix(root).unwrap().display().to_string();
        let mode = meta.permissions().mode() & 0o7777;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path).unwrap();
            out.insert(key, format!("-> {}", target.display()));
        } else if meta.is_dir() {
            out.insert(key, format!("dir {mode:o}"));
            for entry in std::fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), out);
            }
        } else {
            let bytes = std::fs::read(path).unwrap();
            out.insert(key, format!("{mode:o} {}", blake3::hash(&bytes).to_hex()));
        }
    }
    let mut out = BTreeMap::new();
    walk(&world.home, &world.home, &mut out);
    out
}

/// The rows of a head, given the funnel and its published manifest.
type Rows = fn(Funnel, &Manifest) -> Vec<ReleaseRow>;

fn rows_without(_: Funnel, _: &Manifest) -> Vec<ReleaseRow> {
    vec![filler_row()]
}

fn rows_ok(funnel: Funnel, manifest: &Manifest) -> Vec<ReleaseRow> {
    vec![filler_row(), ok_row(funnel.name(), manifest)]
}

fn rows_revoked(funnel: Funnel, manifest: &Manifest) -> Vec<ReleaseRow> {
    let mut revoked = ok_row(funnel.name(), manifest);
    revoked.status = RowStatus::Revoked;
    vec![filler_row(), revoked]
}

fn rows_other_hash(funnel: Funnel, manifest: &Manifest) -> Vec<ReleaseRow> {
    let mut wrong = pins(manifest);
    wrong.content_hash = format!("v1-{}", ContentHash::blake3(b"other").to_hex());
    vec![
        filler_row(),
        row(
            funnel.name(),
            &manifest.version,
            RowStatus::Ok,
            &[(current_target(), wrong)],
        ),
    ]
}

/// One state of the world a read-only check meets, and what it must conclude.
struct ReadOnlyCase {
    name: &'static str,
    /// The head an earlier check left in the cache.
    cached: Option<(u64, Rows)>,
    /// The head the witness serves; `None` is a witness with no head.
    served: Option<(u64, Rows)>,
    expect: fn(&Result<LogCheck, ReleaseError>) -> bool,
}

fn is_confirmed_from(result: &Result<LogCheck, ReleaseError>, seq: u64, from: HeadSource) -> bool {
    matches!(
        result,
        Ok(LogCheck::Confirmed(report))
            if report.seq == seq && report.source == from && !report.cache_written
    )
}

/// The latest release of `funnel`'s stream, held to the log as an update check
/// holds it: `check_latest_self` / `check_latest_tool`, the whole of what
/// `--check` runs before it reports.
async fn check_latest(
    funnel: Funnel,
    world: &World,
    policy: &ReleaseLogPolicy,
) -> Result<fuz_release::LatestCheck, ReleaseError> {
    match funnel {
        Funnel::SelfArtifact => check_latest_self(&world.storage(), policy).await,
        Funnel::Tool => check_latest_tool(&world.storage(), TOOL, policy).await,
    }
}

/// The check `--check` runs — `check_latest_self` / `check_latest_tool` —
/// gives every verdict the installing check gives, as an error with no report
/// to render when the log refuses the release, and in every case leaves the
/// fuz home byte for byte as it found it: no cache written, no state directory
/// made, even when the witness's head is newer than the cached one.
#[tokio::test]
async fn the_read_only_check_gives_every_verdict_and_leaves_the_home_as_it_was() {
    let cases = [
        ReadOnlyCase {
            name: "confirmed, nothing cached",
            cached: None,
            served: Some((4, rows_ok)),
            expect: |r| is_confirmed_from(r, 4, HeadSource::Witness),
        },
        ReadOnlyCase {
            name: "confirmed by a head newer than the cached one",
            cached: Some((3, rows_without)),
            served: Some((4, rows_ok)),
            expect: |r| is_confirmed_from(r, 4, HeadSource::Witness),
        },
        ReadOnlyCase {
            name: "revoked by a head newer than the cached one",
            cached: Some((3, rows_ok)),
            served: Some((4, rows_revoked)),
            expect: |r| {
                matches!(
                    r,
                    Err(ReleaseError::ReleaseLog(ReleaseLogError::Revoked { .. }))
                )
            },
        },
        ReadOnlyCase {
            name: "not recorded",
            cached: None,
            served: Some((4, rows_without)),
            expect: |r| {
                matches!(
                    r,
                    Err(ReleaseError::ReleaseLog(ReleaseLogError::RowMissing {
                        pinned_by: PinnedBy::SignedManifest,
                        ..
                    }))
                )
            },
        },
        ReadOnlyCase {
            name: "recorded with another hash",
            cached: None,
            served: Some((4, rows_other_hash)),
            expect: |r| {
                matches!(
                    r,
                    Err(ReleaseError::ReleaseLog(ReleaseLogError::Contradiction(
                        LogContradiction::HashMismatch {
                            field: TargetField::ContentHash,
                            pinned_by: PinnedBy::SignedManifest,
                            ..
                        }
                    )))
                )
            },
        },
        ReadOnlyCase {
            name: "no witness reachable, nothing cached",
            cached: None,
            served: None,
            expect: |r| matches!(r, Err(e) if e.is_unconfirmed()),
        },
        ReadOnlyCase {
            name: "no witness reachable, the cache covers the release",
            cached: Some((3, rows_ok)),
            served: None,
            expect: |r| is_confirmed_from(r, 3, HeadSource::CacheWitnessUnreachable),
        },
        ReadOnlyCase {
            name: "no witness reachable, the cache revokes the release",
            cached: Some((3, rows_revoked)),
            served: None,
            expect: |r| {
                matches!(
                    r,
                    Err(ReleaseError::ReleaseLog(ReleaseLogError::Revoked { .. }))
                )
            },
        },
    ];

    for funnel in FUNNELS {
        for case in &cases {
            let world = World::new().await;
            let stored = funnel.publish(&world, "0.3.0").await;
            let witness = world.witness("witness");
            if let Some((seq, rows)) = case.served {
                serve(&witness, head(seq, rows(funnel, &stored)));
            }
            if let Some((seq, rows)) = case.cached {
                seed_cache(&world, &verified(head(seq, rows(funnel, &stored))));
            }

            let before = home_snapshot(&world);
            let latest = check_latest(funnel, &world, &enforced(&[uri(&witness)])).await;
            if let Ok(latest) = &latest {
                // A report exists only for a release the log confirmed.
                assert_eq!(latest.manifest().version, "0.3.0");
                assert!(matches!(latest.current(), CurrentVersion::NotInstalled));
            }
            let result = latest.map(|latest| latest.release_log().clone());
            assert!(
                (case.expect)(&result),
                "{funnel:?} {}: {result:?}",
                case.name
            );
            assert_eq!(home_snapshot(&world), before, "{funnel:?} {}", case.name);
            if case.cached.is_none() {
                assert!(
                    !world.home.join("state").exists(),
                    "{funnel:?} {}",
                    case.name
                );
            }
        }
    }
}

/// An install that is already at the latest release still has that release
/// held to the log: confirmed, the report carries the head that confirmed it;
/// revoked, there is no report at all — never "up to date". Inactive and opted
/// out, the same call reports without asking anything.
#[tokio::test]
async fn an_update_check_on_an_up_to_date_install_still_asks_the_log() {
    for funnel in FUNNELS {
        let world = World::new().await;
        let stored = funnel.publish(&world, "0.3.0").await;
        // Install 0.3.0 with no log configured, and make it current.
        funnel
            .install(
                &world.storage(),
                "0.3.0",
                Flags::default(),
                ReleaseLogPolicy::Inactive,
            )
            .await
            .unwrap();
        if funnel == Funnel::SelfArtifact {
            fuz_artifact::switch_current(&stored.content_hash).unwrap();
        }
        let up_to_date = |latest: &fuz_release::LatestCheck| {
            matches!(
                latest.current(),
                CurrentVersion::Installed(version)
                    if version.to_string() == latest.manifest().version
            )
        };
        let witness = world.witness("witness");
        let before = home_snapshot(&world);

        serve(&witness, head(4, rows_ok(funnel, &stored)));
        let latest = check_latest(funnel, &world, &enforced(&[uri(&witness)]))
            .await
            .unwrap();
        assert!(up_to_date(&latest), "{funnel:?}: {latest:?}");
        assert!(
            is_confirmed_from(&Ok(latest.release_log().clone()), 4, HeadSource::Witness),
            "{funnel:?}: {latest:?}"
        );

        serve(&witness, head(5, rows_revoked(funnel, &stored)));
        let result = check_latest(funnel, &world, &enforced(&[uri(&witness)])).await;
        assert!(
            matches!(
                &result,
                Err(ReleaseError::ReleaseLog(ReleaseLogError::Revoked { name, version }))
                    if name == funnel.name() && version == "0.3.0"
            ),
            "{funnel:?}: {result:?}"
        );

        // The witness is not asked under the other two policies.
        for (policy, expected) in [
            (ReleaseLogPolicy::Inactive, LogCheck::Inactive),
            (ReleaseLogPolicy::Off, LogCheck::Off),
        ] {
            let latest = check_latest(funnel, &world, &policy).await.unwrap();
            assert!(up_to_date(&latest), "{funnel:?}");
            assert_eq!(latest.release_log(), &expected, "{funnel:?}");
        }
        assert_eq!(home_snapshot(&world), before, "{funnel:?}");
    }
}

//
// The check of a local binary: what `fuz self bootstrap` runs
//

/// The bytes of a `fuz` binary for `version`, as `Funnel::publish` writes them.
fn self_bytes(version: &str) -> Vec<u8> {
    format!("fuz binary bytes for {version}").into_bytes()
}

fn local_binary(version: &str, bytes: &[u8]) -> LocalSelfBinary {
    LocalSelfBinary::new(version, ContentHash::blake3(bytes))
}

/// What a self artifact holding `bytes` pins, as a publish records it.
fn self_pins(bytes: &[u8]) -> TargetRow {
    let outputs = ArtifactOutputs {
        fuz: ContentHash::blake3(bytes),
    };
    TargetRow {
        content_hash: outputs.content_hash(),
        binaries: BTreeMap::from([(SELF_NAME.to_string(), outputs.fuz)]),
        sha512: Some(ContentHash::sha512(bytes)),
    }
}

fn self_row(version: &str, status: RowStatus, target: &str, bytes: &[u8]) -> ReleaseRow {
    row(SELF_NAME, version, status, &[(target, self_pins(bytes))])
}

/// A binary whose release was recorded by a real publish is confirmed from the
/// log that publish wrote, by nothing but its own bytes and version — and the
/// same version with other bytes is not.
#[tokio::test]
async fn a_published_binary_is_confirmed_by_the_log_its_publish_wrote() {
    if !common::git_available() {
        return;
    }
    let world = World::new().await;
    let fixture = common::Fixture::new();
    let published = common::publish_self(&fixture, "0.3.0").await.unwrap();
    let seq = published.logged.as_ref().unwrap().seq;
    let policy = || enforced(&[uri(&fixture.checkout)]);

    let report = confirmed(
        check_bootstrap_binary(
            &policy(),
            &local_binary("0.3.0", &common::fuz_content("0.3.0")),
        )
        .await
        .unwrap(),
    );
    assert_eq!(report.seq, seq);
    assert_eq!(report.source, HeadSource::Witness);
    // The caller is installing: the head is cached, owner-only.
    assert!(report.cache_written);
    assert_eq!(cached_seq(&world), seq);
    assert_eq!(mode_of(&world.cache_path()) & 0o077, 0);

    // The published version, with bytes that are not the published ones.
    let error = log_error(
        check_bootstrap_binary(&policy(), &local_binary("0.3.0", b"some other build")).await,
    );
    assert!(
        matches!(
            &error,
            ReleaseLogError::Contradiction(LogContradiction::HashMismatch {
                name,
                version,
                target,
                field: TargetField::ContentHash,
                pinned_by: PinnedBy::LocalBinary,
            }) if name == SELF_NAME && version == "0.3.0" && target == current_target()
        ),
        "{error:?}"
    );
    assert_hard(&error);
    assert!(error.to_string().ends_with("than this binary"), "{error}");
}

/// Every state the check of a local binary can meet. The hashes are compared
/// in full: the binary's own BLAKE3 against the row's `binaries` entry, and
/// the content hash of that one-binary set against the row's `content_hash`.
#[tokio::test]
async fn a_local_binary_is_held_to_the_log_by_its_own_hash() {
    const VERSION: &str = "0.3.0";
    type Expect = fn(&ReleaseLogError) -> bool;
    let bytes = self_bytes(VERSION);
    let good = || self_row(VERSION, RowStatus::Ok, current_target(), &bytes);

    // The row's content hash is this binary's, and its `binaries` entry is not.
    let mut binaries_differ = good();
    for target in binaries_differ.targets.values_mut() {
        target
            .binaries
            .insert(SELF_NAME.to_string(), ContentHash::blake3(b"another build"));
    }
    // The reverse.
    let mut content_hash_differs = good();
    for target in content_hash_differs.targets.values_mut() {
        target.content_hash = self_pins(b"another build").content_hash;
    }
    // The row lists a second binary beside the right one.
    let mut extra_binary = good();
    for target in extra_binary.targets.values_mut() {
        target
            .binaries
            .insert("fuzd".to_string(), ContentHash::blake3(b"fuzd"));
    }

    let mismatch_in_binaries: Expect = |e| {
        matches!(
            e,
            ReleaseLogError::Contradiction(LogContradiction::HashMismatch {
                field: TargetField::Binaries,
                pinned_by: PinnedBy::LocalBinary,
                ..
            })
        )
    };
    let missing: Expect = |e| {
        matches!(
            e,
            ReleaseLogError::RowMissing {
                pinned_by: PinnedBy::LocalBinary,
                ..
            }
        )
    };
    let refusals: [(&str, Vec<ReleaseRow>, Expect); 8] = [
        ("no row at all", vec![filler_row()], missing),
        (
            "another version",
            vec![self_row("0.2.0", RowStatus::Ok, current_target(), &bytes)],
            missing,
        ),
        (
            "this target absent",
            vec![self_row(VERSION, RowStatus::Ok, other_target(), &bytes)],
            missing,
        ),
        (
            "revoked",
            vec![self_row(
                VERSION,
                RowStatus::Revoked,
                current_target(),
                &bytes,
            )],
            |e| matches!(e, ReleaseLogError::Revoked { name, version } if name == SELF_NAME && version == VERSION),
        ),
        (
            "another build of this version",
            vec![self_row(
                VERSION,
                RowStatus::Ok,
                current_target(),
                b"another build",
            )],
            |e| {
                matches!(
                    e,
                    ReleaseLogError::Contradiction(LogContradiction::HashMismatch {
                        field: TargetField::ContentHash,
                        pinned_by: PinnedBy::LocalBinary,
                        ..
                    })
                )
            },
        ),
        ("content_hash differs", vec![content_hash_differs], |e| {
            matches!(
                e,
                ReleaseLogError::Contradiction(LogContradiction::HashMismatch {
                    field: TargetField::ContentHash,
                    ..
                })
            )
        }),
        (
            "binaries entry differs",
            vec![binaries_differ],
            mismatch_in_binaries,
        ),
        (
            "a second binary listed",
            vec![extra_binary],
            mismatch_in_binaries,
        ),
    ];
    for (case, rows, expect) in refusals {
        let world = World::new().await;
        let witness = world.witness("witness");
        serve(&witness, head(4, rows));
        let error = log_error(
            check_bootstrap_binary(&enforced(&[uri(&witness)]), &local_binary(VERSION, &bytes))
                .await,
        );
        assert!(expect(&error), "{case}: {error:?}");
        assert_hard(&error);
        // The head it refused on is kept: a revocation seen once stays known.
        assert_eq!(cached_seq(&world), 4, "{case}");
    }

    // Confirmed by a witness.
    {
        let world = World::new().await;
        let witness = world.witness("witness");
        serve(&witness, head(4, vec![filler_row(), good()]));
        let report = confirmed(
            check_bootstrap_binary(&enforced(&[uri(&witness)]), &local_binary(VERSION, &bytes))
                .await
                .unwrap(),
        );
        assert_eq!(
            (report.seq, report.source, report.cache_written),
            (4, HeadSource::Witness, true)
        );
    }

    // No witness reachable: the cached head decides, and with none the binary
    // is unconfirmed — the soft failure, and still not a confirmation.
    {
        let world = World::new().await;
        let witness = world.witness("witness");
        let policy = || enforced(&[uri(&witness)]);
        let error =
            log_error(check_bootstrap_binary(&policy(), &local_binary(VERSION, &bytes)).await);
        assert!(error.is_unconfirmed(), "{error:?}");
        assert!(!error.is_security_violation());
        assert!(!world.cache_path().exists());

        seed_cache(&world, &verified(head(3, vec![good()])));
        let report = confirmed(
            check_bootstrap_binary(&policy(), &local_binary(VERSION, &bytes))
                .await
                .unwrap(),
        );
        assert_eq!(
            (report.seq, report.source, report.cache_written),
            (3, HeadSource::CacheWitnessUnreachable, false)
        );
        // A cached head that does not cover this version says nothing of it.
        let error =
            log_error(check_bootstrap_binary(&policy(), &local_binary("0.4.0", &bytes)).await);
        assert!(error.is_unconfirmed(), "{error:?}");
    }

    // Inactive and opted out: nothing is asked, nothing is cached, even with a
    // witness that would refuse the binary.
    {
        let world = World::new().await;
        let witness = world.witness("witness");
        serve(
            &witness,
            head(
                4,
                vec![self_row(
                    VERSION,
                    RowStatus::Revoked,
                    current_target(),
                    &bytes,
                )],
            ),
        );
        let before = home_snapshot(&world);
        for (policy, expected) in [
            (ReleaseLogPolicy::Inactive, LogCheck::Inactive),
            (ReleaseLogPolicy::Off, LogCheck::Off),
        ] {
            let check = check_bootstrap_binary(&policy, &local_binary(VERSION, &bytes))
                .await
                .unwrap();
            assert_eq!(check, expected);
        }
        assert_eq!(home_snapshot(&world), before);
    }
}

/// The check of a local binary is a writing caller: a world-writable fuz home
/// is refused before any witness is asked.
#[tokio::test]
async fn a_local_binary_check_refuses_a_world_writable_home() {
    let world = World::new().await;
    let witness = world.witness("witness");
    let bytes = self_bytes("0.3.0");
    serve(
        &witness,
        head(
            4,
            vec![self_row("0.3.0", RowStatus::Ok, current_target(), &bytes)],
        ),
    );
    std::fs::set_permissions(&world.home, std::fs::Permissions::from_mode(0o777)).unwrap();
    let result =
        check_bootstrap_binary(&enforced(&[uri(&witness)]), &local_binary("0.3.0", &bytes)).await;
    assert!(
        matches!(result, Err(ReleaseError::FuzHome(_))),
        "{result:?}"
    );
    assert!(!world.home.join("state").exists());
}

//
// The installed release's standing, from the cached head alone
//

/// `is_revoked` and `installed_standing` over real signed heads: standing is
/// the row's, whatever targets it lists, and a release the head does not
/// record is not revoked.
#[test]
fn installed_standing_reads_a_revocation_off_the_row() {
    trust();
    let bytes = self_bytes("0.3.0");
    let head = verified(head(
        9,
        vec![
            filler_row(),
            self_row("0.2.0", RowStatus::Ok, current_target(), &bytes),
            // Revoked, and recorded for another target only.
            self_row("0.3.0", RowStatus::Revoked, other_target(), &bytes),
            row(
                TOOL,
                "0.4.0",
                RowStatus::Revoked,
                &[(current_target(), self_pins(&bytes))],
            ),
        ],
    ));

    let table = [
        (SELF_NAME, "0.3.0", true),
        (SELF_NAME, "0.2.0", false),
        // Not recorded at all.
        (SELF_NAME, "0.1.0", false),
        // Another release's revocation is not this one's.
        (SELF_NAME, "0.4.0", false),
        (TOOL, "0.4.0", true),
        (TOOL, "0.3.0", false),
        ("zap", "9.9.9", false),
    ];
    for (name, version, expected) in table {
        assert_eq!(
            is_revoked(&head, name, version),
            expected,
            "{name} {version}"
        );
    }

    let standing = |installed| installed_standing(&head, installed);
    assert_eq!(
        standing(Some("0.3.0")),
        InstalledStanding {
            seq: 9,
            revoked: true
        }
    );
    for installed in [Some("0.2.0"), Some("0.1.0"), Some("0.4.0"), Some(""), None] {
        assert_eq!(
            standing(installed),
            InstalledStanding {
                seq: 9,
                revoked: false
            },
            "{installed:?}"
        );
    }
}

/// The standing is read from the cache and from nothing else: no witness is
/// asked, nothing is written, and only an enforced policy reads at all.
#[tokio::test]
async fn the_installed_standing_comes_from_the_cached_head_alone() {
    let world = World::new().await;
    let bytes = self_bytes("0.3.0");
    let witness = world.witness("witness");
    let policy = || enforced(&[uri(&witness)]);
    let ok = || self_row("0.3.0", RowStatus::Ok, current_target(), &bytes);
    let revoked = || self_row("0.3.0", RowStatus::Revoked, current_target(), &bytes);

    // Nothing cached: nothing to say, whatever the witness serves.
    serve(&witness, head(5, vec![revoked()]));
    assert_eq!(
        cached_installed_standing(&policy(), Some("0.3.0")).unwrap(),
        None
    );
    assert!(!world.home.join("state").exists(), "nothing is created");

    // The cache says "ok" while the witness already serves the revocation:
    // the answer is the cache's, so no witness was consulted.
    seed_cache(&world, &verified(head(4, vec![ok()])));
    let before = home_snapshot(&world);
    assert_eq!(
        cached_installed_standing(&policy(), Some("0.3.0")).unwrap(),
        Some(InstalledStanding {
            seq: 4,
            revoked: false
        })
    );
    assert_eq!(home_snapshot(&world), before, "nothing is written");

    // The cache records the revocation, and the witness is gone. No artifact
    // is installed in this home: the version asked about is whichever one the
    // caller reports, the running binary's own included.
    stop_serving(&witness);
    seed_cache(&world, &verified(head(5, vec![revoked()])));
    let before = home_snapshot(&world);
    for (installed, expected) in [(Some("0.3.0"), true), (Some("0.2.0"), false), (None, false)] {
        assert_eq!(
            cached_installed_standing(&policy(), installed).unwrap(),
            Some(InstalledStanding {
                seq: 5,
                revoked: expected
            }),
            "{installed:?}"
        );
    }
    // Inactive and opted out read nothing, cached revocation or not.
    for policy in [ReleaseLogPolicy::Inactive, ReleaseLogPolicy::Off] {
        assert_eq!(
            cached_installed_standing(&policy, Some("0.3.0")).unwrap(),
            None
        );
    }
    assert_eq!(home_snapshot(&world), before);

    // A cache that cannot be used is an error naming the file — the caller
    // decides whether that stops it.
    std::fs::write(world.cache_path(), b"not a head").unwrap();
    let result = cached_installed_standing(&policy(), Some("0.3.0"));
    assert!(
        matches!(
            &result,
            Err(ReleaseError::ReleaseLog(ReleaseLogError::CacheUnusable { path, .. }))
                if *path == world.cache_path()
        ),
        "{result:?}"
    );
    for policy in [ReleaseLogPolicy::Inactive, ReleaseLogPolicy::Off] {
        assert_eq!(
            cached_installed_standing(&policy, Some("0.3.0")).unwrap(),
            None
        );
    }
}

//
// An upgrade whose latest release is the installed one
//

/// When the latest release is the installed version and the log revokes it,
/// the upgrade fails with the revocation: it never reaches the "already at the
/// latest version" outcome, and the update check on the same release fails the
/// same way rather than reporting "up to date".
#[tokio::test]
async fn an_upgrade_does_not_stay_put_on_a_revoked_installed_version() {
    let world = World::new().await;
    let storage = world.storage();
    let stored = Funnel::SelfArtifact.publish(&world, "0.3.0").await;

    // Install 0.3.0 and make it the current artifact, with no log configured.
    let installed = fetch_latest(&storage, &FetchOptions::default())
        .await
        .unwrap();
    fuz_artifact::switch_current(&installed.content_hash).unwrap();
    assert!(
        matches!(
            resolve_current_self().unwrap(),
            CurrentVersion::Installed(version) if version.to_string() == "0.3.0"
        ),
        "0.3.0 is the installed version"
    );
    // Without a log, the same upgrade is a cache hit on the installed artifact.
    let again = fetch_latest(&storage, &FetchOptions::default())
        .await
        .unwrap();
    assert!(again.cache_hit);
    assert_eq!(again.content_hash, installed.content_hash);
    let before = world.installed();

    let witness = world.witness("witness");
    serve(
        &witness,
        head(4, rows_revoked(Funnel::SelfArtifact, &stored)),
    );
    let options = FetchOptions {
        release_log: enforced(&[uri(&witness)]),
        ..FetchOptions::default()
    };
    let result = fetch_latest(&storage, &options).await;
    assert!(
        matches!(
            &result,
            Err(ReleaseError::ReleaseLog(ReleaseLogError::Revoked { name, version }))
                if name == SELF_NAME && version == "0.3.0"
        ),
        "{result:?}"
    );
    assert_eq!(world.installed(), before, "nothing switched");
    // The installing check cached the head it refused on, so the standing
    // read from the cache reports the revocation.
    assert_eq!(
        cached_installed_standing(&enforced(&[uri(&witness)]), Some("0.3.0")).unwrap(),
        Some(InstalledStanding {
            seq: 4,
            revoked: true
        })
    );

    // The update check, on the same latest release.
    let manifest = stored.verify_signature().unwrap();
    let error =
        resolve_error(check_release_log_read_only(&enforced(&[uri(&witness)]), &manifest).await);
    assert!(
        matches!(error, ReleaseLogError::Revoked { .. }),
        "{error:?}"
    );
}
