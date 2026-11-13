//! The fixture the release log suites share: a bare remote, a checkout
//! tracking it, and release storage, in one temp dir, with every `git` process
//! run in an environment that ignores the developer's own configuration.
//!
//! Heads are signed and verified for real, with the signing keys admitted
//! through `fuz_crypto`'s dev-dependency-only `test_trust_anchor` seam.

#![allow(dead_code, reason = "each test binary uses only part of this module")]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Once;

use fuz_artifact::{ArtifactMeta, ArtifactOutputs};
use fuz_crypto::ContentHash;
use fuz_release::{
    Head, HeadUnsigned, LatestInfo, LogWriteError, ReleaseError, ReleaseLayout, TargetRow,
    VerifiedHead, current_target,
};
use fuz_sign::release_log::HEAD_FILE;
use fuz_sign::{
    LogEntry, LogOutcome, LogRepo, PublishOptions, PublishResult, SigningKey, publish_artifact,
};
use fuz_storage::{FileStorage, Storage};

pub const X86: &str = "x86_64-unknown-linux-gnu";
pub const ARM: &str = "aarch64-unknown-linux-gnu";
pub const NOW: &str = "2025-01-15T10:30:00Z";
pub const LATER: &str = "2025-02-01T00:00:00Z";

/// The key every head here is signed with. Admitted by [`trust`].
pub fn trusted_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// A second trusted key, for the key-history tests.
pub fn second_trusted_key() -> SigningKey {
    SigningKey::from_bytes(&[12u8; 32])
}

/// A key this file never registers — it must stay untrusted.
pub fn untrusted_key() -> SigningKey {
    SigningKey::from_bytes(&[22u8; 32])
}

/// Register the trusted keys, once. The registry is process-global and nothing
/// in this file clears it, so the tests need no serialization.
pub fn trust() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        fuz_crypto::add_trusted_key_for_testing(&trusted_key().verifying_key());
        fuz_crypto::add_trusted_key_for_testing(&second_trusted_key().verifying_key());
    });
}

/// `unsigned` as a head signed before domain separation, by [`trusted_key`]:
/// envelope format 1, over the canonical JSON alone. It parses, and no build
/// that reads only the current format verifies it.
pub fn pre_tag_head(unsigned: HeadUnsigned) -> Head {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::Signer;
    let key = trusted_key();
    let canonical = fuz_crypto::canonical_json(&unsigned).unwrap();
    let signature = fuz_crypto::Signature {
        format: 1,
        public_key: STANDARD.encode(key.verifying_key().as_bytes()),
        algorithm: fuz_crypto::SignatureAlgorithm::Ed25519,
        signed_at: NOW.to_string(),
        sig: STANDARD.encode(key.sign(canonical.as_bytes()).to_bytes()),
    };
    Head::from_parts(unsigned, signature)
}

/// A co-signer's SSH key: never registered with [`trust`], so it is a witness
/// key and not a release key.
pub fn witness_key() -> SigningKey {
    SigningKey::from_bytes(&[33u8; 32])
}

/// A second SSH key, belonging to no co-signer.
pub fn other_witness_key() -> SigningKey {
    SigningKey::from_bytes(&[34u8; 32])
}

/// What `ssh-keygen -Y sign -n <namespace>` writes for `message`: an armored
/// `sshsig` signature (sha512), built here so the suites need no `ssh-keygen`.
/// The verifier's own tests hold this construction to real `ssh-keygen`
/// output; nothing outside the test suites signs one.
pub fn sign_sshsig(key: &SigningKey, namespace: &str, message: &[u8]) -> String {
    use base64::Engine;
    use ed25519_dalek::Signer;

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }
    let digest = ContentHash::sha512(message);
    let mut signed = b"SSHSIG".to_vec();
    signed.extend(string(namespace.as_bytes()));
    signed.extend(string(b""));
    signed.extend(string(b"sha512"));
    signed.extend(string(digest.as_bytes()));

    let mut public_key = string(b"ssh-ed25519");
    public_key.extend(string(key.verifying_key().as_bytes()));
    let mut signature = string(b"ssh-ed25519");
    signature.extend(string(&key.sign(&signed).to_bytes()));

    let mut blob = b"SSHSIG".to_vec();
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.extend(string(&public_key));
    blob.extend(string(namespace.as_bytes()));
    blob.extend(string(b""));
    blob.extend(string(b"sha512"));
    blob.extend(string(&signature));

    let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
    let mut armored = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        armored.push_str(std::str::from_utf8(chunk).unwrap());
        armored.push('\n');
    }
    armored.push_str("-----END SSH SIGNATURE-----\n");
    armored
}

pub fn public_key(key: &SigningKey) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes())
}

/// A target that is not the one this test binary was built for — the second
/// target of a two-target release.
pub fn other_target() -> &'static str {
    if current_target() == ARM { X86 } else { ARM }
}

pub fn git_available() -> bool {
    let available = Command::new("git").arg("--version").output().is_ok();
    if !available {
        eprintln!("skipping: git not available");
    }
    available
}

/// Something a test does to a fixture: break it, dirty it, fix it.
pub type Change = fn(&Fixture);

/// A bare remote, a checkout tracking it, and release storage, in one temp dir.
pub struct Fixture {
    pub tmp: tempfile::TempDir,
    /// The bare repository the checkout pushes to.
    pub remote: PathBuf,
    /// The log checkout.
    pub checkout: PathBuf,
    pub storage_dir: PathBuf,
}

impl Fixture {
    pub fn new() -> Self {
        trust();
        let tmp = tempfile::tempdir().unwrap();
        // Stated, not inherited: `tempdir()` takes the process umask.
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self {
            remote: tmp.path().join("log.git"),
            checkout: tmp.path().join("log"),
            storage_dir: tmp.path().join("storage"),
            tmp,
        };
        std::fs::create_dir(fixture.tmp.path().join("home")).unwrap();
        std::fs::create_dir(&fixture.storage_dir).unwrap();
        fixture.git_in(
            fixture.tmp.path(),
            &["init", "--quiet", "--bare", "-b", "main", "log.git"],
        );
        fixture.init_checkout(&fixture.checkout);
        fixture
    }

    /// The environment every git process runs in: no global or system
    /// configuration, and a `HOME` inside the fixture.
    pub fn git_env(&self) -> Vec<(OsString, OsString)> {
        let home = self.tmp.path().join("home");
        vec![
            ("GIT_CONFIG_GLOBAL".into(), "/dev/null".into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("HOME".into(), home.clone().into()),
            ("XDG_CONFIG_HOME".into(), home.into()),
        ]
    }

    /// A work tree on `main` whose upstream is the fixture's bare remote, with
    /// its own identity. Starts with no commits and nothing fetched.
    pub fn init_checkout(&self, path: &Path) {
        std::fs::create_dir(path).unwrap();
        self.git_in(path, &["init", "--quiet", "-b", "main"]);
        self.git_in(path, &["config", "user.name", "Log Test"]);
        self.git_in(path, &["config", "user.email", "log@test.invalid"]);
        self.git_in(path, &["config", "commit.gpgsign", "false"]);
        let remote = self.remote.to_str().unwrap();
        self.git_in(path, &["remote", "add", "origin", remote]);
        self.git_in(path, &["config", "branch.main.remote", "origin"]);
        self.git_in(path, &["config", "branch.main.merge", "refs/heads/main"]);
    }

    pub fn try_git_in(&self, dir: &Path, args: &[&str]) -> Output {
        let mut command = Command::new("git");
        command.args(args).current_dir(dir).envs(self.git_env());
        // Never the enclosing repository: drop what would point git at another
        // one, and stop discovery at the fixture.
        for variable in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
        ] {
            command.env_remove(variable);
        }
        command.env("GIT_CEILING_DIRECTORIES", self.tmp.path());
        command.output().unwrap()
    }

    /// Every file in release storage with its bytes, sorted by key.
    pub fn storage_files(&self) -> Vec<(String, Vec<u8>)> {
        fn walk(root: &Path, dir: &Path, files: &mut Vec<(String, Vec<u8>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, files);
                } else {
                    let key = path.strip_prefix(root).unwrap().to_str().unwrap();
                    files.push((key.to_string(), std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut files = Vec::new();
        walk(&self.storage_dir, &self.storage_dir, &mut files);
        files.sort();
        files
    }

    /// A second bare repository beside the fixture's remote.
    pub fn init_bare(&self, name: &str) -> PathBuf {
        self.git_in(
            self.tmp.path(),
            &["init", "--quiet", "--bare", "-b", "main", name],
        );
        self.tmp.path().join(name)
    }

    pub fn install_hook(git_dir: &Path, hook: &str, script: &str) {
        let path = git_dir.join("hooks").join(hook);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Run git in `dir`, requiring success; returns trimmed stdout.
    #[track_caller]
    pub fn git_in(&self, dir: &Path, args: &[&str]) -> String {
        let output = self.try_git_in(dir, args);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    /// Run git in the log checkout.
    #[track_caller]
    pub fn git(&self, args: &[&str]) -> String {
        self.git_in(&self.checkout, args)
    }

    /// Run git against the bare remote.
    #[track_caller]
    pub fn remote_git(&self, args: &[&str]) -> String {
        self.git_in(&self.remote, args)
    }

    pub fn repo(&self) -> LogRepo {
        self.repo_at(&self.checkout)
    }

    pub fn repo_at(&self, path: &Path) -> LogRepo {
        LogRepo {
            path: path.to_path_buf(),
            git_env: self.git_env(),
        }
    }

    pub fn storage(&self) -> FileStorage {
        FileStorage::new(&self.storage_dir).unwrap()
    }

    pub fn options(&self) -> PublishOptions {
        PublishOptions {
            log_repo: Some(self.repo()),
            ..PublishOptions::default()
        }
    }

    /// Commit subjects on the remote's `main`, oldest first; empty when the
    /// remote has no `main` yet.
    pub fn remote_subjects(&self) -> Vec<String> {
        let output = self.try_git_in(&self.remote, &["log", "--reverse", "--format=%s", "main"]);
        if !output.status.success() {
            return Vec::new();
        }
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The paths a remote commit touched, sorted.
    pub fn remote_commit_files(&self, revision: &str) -> Vec<String> {
        let mut files: Vec<String> = self
            .remote_git(&["show", "--name-only", "--format=", revision])
            .lines()
            .map(str::to_string)
            .collect();
        files.sort();
        files
    }

    /// Every path in the remote's `main` tree, sorted.
    pub fn remote_tree(&self) -> Vec<String> {
        self.remote_git(&["ls-tree", "-r", "--name-only", "main"])
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The verified head at `revision` on the remote.
    #[track_caller]
    pub fn remote_head(&self, revision: &str) -> VerifiedHead {
        let json = self.remote_git(&["show", &format!("{revision}:{HEAD_FILE}")]);
        Head::from_json(json.as_bytes())
            .unwrap()
            .verify_signature()
            .unwrap()
    }

    pub fn checkout_head_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.checkout.join(HEAD_FILE)).ok()
    }

    /// Commit everything in the checkout and push it — how a test puts a
    /// prepared state into the log.
    #[track_caller]
    pub fn commit_all_and_push(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "--quiet", "-m", message]);
        self.git(&["push", "--quiet"]);
    }

    /// Write `head` as the checkout's `head.json`, commit, and push.
    #[track_caller]
    pub fn seed_head(&self, head: &Head) {
        std::fs::write(self.checkout.join(HEAD_FILE), head.to_json().unwrap()).unwrap();
        self.commit_all_and_push("seed head");
    }

    /// A snapshot of everything a refused write must leave alone: the
    /// checkout's `HEAD`, its status, the remote's `main`, and `head.json`.
    pub fn state(&self) -> (String, String, Vec<String>, Option<Vec<u8>>) {
        let head = self.try_git_in(
            &self.checkout,
            &["rev-parse", "--verify", "--quiet", "HEAD"],
        );
        (
            String::from_utf8_lossy(&head.stdout).trim().to_string(),
            self.git(&["status", "--porcelain", "--untracked-files=all"]),
            self.remote_subjects(),
            self.checkout_head_bytes(),
        )
    }

    /// Make the remote refuse every push.
    pub fn reject_pushes(&self) {
        self.install_pre_receive("#!/bin/sh\necho 'push refused by the test hook' >&2\nexit 1\n");
    }

    pub fn install_pre_receive(&self, script: &str) {
        Self::install_hook(&self.remote, "pre-receive", script);
    }

    /// A hook the remote runs once it has taken a push, before the push
    /// returns.
    pub fn install_post_receive(&self, script: &str) {
        Self::install_hook(&self.remote, "post-receive", script);
    }

    pub fn accept_pushes(&self) {
        std::fs::remove_file(self.remote.join("hooks/pre-receive")).unwrap();
    }
}

/// Run `work` on a thread of its own with a tokio runtime to block on, so a
/// plain test and an async one can both wait on a future.
pub fn block_on_thread<T: Send>(work: impl FnOnce(&tokio::runtime::Runtime) -> T + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                work(&runtime)
            })
            .join()
            .unwrap()
    })
}

/// `fuz_sign::record_release` against release storage that holds nothing, run
/// to completion: the log write on its own. The tests of a first head that
/// storage contradicts call the real function with the fixture's storage.
pub fn record_release(
    repo: &LogRepo,
    entry: &LogEntry,
    key: &SigningKey,
    now: &str,
) -> Result<LogOutcome, LogWriteError> {
    let empty = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(empty.path()).unwrap();
    block_on_thread(|runtime| {
        runtime.block_on(fuz_sign::record_release(&storage, repo, entry, key, now))
    })
}

/// The fuz binary bytes for a version — distinct per version, so each is its
/// own build.
pub fn fuz_content(version: &str) -> Vec<u8> {
    host_binary(format!("fuz binary bytes for {version}").as_bytes())
}

/// An executable for the host target holding `payload`: bytes a publish's
/// platform check accepts where a test used to publish placeholder text.
pub fn host_binary(payload: &[u8]) -> Vec<u8> {
    fuz_artifact::platform::test_stubs::host(payload)
}

/// The entry `publish_artifact` records for a self artifact holding `content`.
pub fn self_entry(version: &str, target: &str, content: &[u8]) -> LogEntry {
    let outputs = ArtifactOutputs {
        fuz: ContentHash::blake3(content),
    };
    LogEntry {
        name: "fuz".to_string(),
        version: version.to_string(),
        target: target.to_string(),
        pins: TargetRow {
            content_hash: outputs.content_hash(),
            binaries: BTreeMap::from([("fuz".to_string(), outputs.fuz)]),
            sha512: Some(ContentHash::sha512(content)),
        },
        flat_latest: true,
    }
}

/// Publish a self artifact holding `content` through the real flow.
pub async fn publish_self_with(
    fixture: &Fixture,
    version: &str,
    content: &[u8],
    key: &SigningKey,
    options: &PublishOptions,
) -> Result<PublishResult, ReleaseError> {
    let artifact_dir = tempfile::tempdir_in(fixture.tmp.path()).unwrap();
    std::fs::write(artifact_dir.path().join("fuz"), content).unwrap();
    let outputs = ArtifactOutputs {
        fuz: ContentHash::blake3(content),
    };
    let meta = ArtifactMeta::new_remote(outputs.content_hash(), version.to_string(), outputs);
    meta.write(artifact_dir.path()).unwrap();
    publish_artifact(&fixture.storage(), &meta, artifact_dir.path(), key, options).await
}

/// Publish the self artifact for `version` with the trusted key, logging.
pub async fn publish_self(fixture: &Fixture, version: &str) -> Result<PublishResult, ReleaseError> {
    publish_self_with(
        fixture,
        version,
        &fuz_content(version),
        &trusted_key(),
        &fixture.options(),
    )
    .await
}

pub async fn latest_version(storage: &FileStorage, layout: &ReleaseLayout) -> Option<String> {
    latest_version_for(storage, layout, current_target()).await
}

/// The version `target`'s `latest-<target>.json` pointer names, if any.
pub async fn latest_version_for(
    storage: &FileStorage,
    layout: &ReleaseLayout,
    target: &str,
) -> Option<String> {
    if !storage.exists(&layout.latest_key(target)).await.unwrap() {
        return None;
    }
    let bytes = storage.download(&layout.latest_key(target)).await.unwrap();
    Some(
        serde_json::from_slice::<LatestInfo>(&bytes)
            .unwrap()
            .version,
    )
}
