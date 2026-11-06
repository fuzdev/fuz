//! The real `xtask` binary's `--storage` contract for the producer commands:
//! which of them may meet a local store that is not there, and what a command
//! that deletes will build a storage key from.
//!
//! - `publish` creates a local store with its first upload, and refuses a
//!   path something other than a directory already holds before it packs or
//!   signs anything. A read-only location is refused the same way, before
//!   the signing key is loaded.
//! - `prune` and `release-log backfill` work on a store already there: a path
//!   that is not an existing directory is an error naming it, never "nothing
//!   to prune" or an empty review, and nothing is created. Both list the
//!   store, so a read-only location fails them on that, with the log
//!   checkout untouched.
//! - `prune --tool` takes a first-party tool name and nothing else, so the
//!   name never becomes a key prefix that leaves `tools/<name>/`.
//!
//! Every run gets its own `FUZ_HOME` and `HOME` and works under one scratch
//! directory, compared before and after where the claim is "nothing changed".

// Test harness: the clippy `allow-*-in-tests` config reaches only `#[test]`
// fns, not the shared helpers below, which panic on a setup failure by design.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The host target's latest pointer of `tool`, the one a publish with no
/// `--target` writes.
fn host_latest(tool: &str) -> String {
    format!(
        "tools/{tool}/latest-{}.json",
        fuz_artifact::platform::test_stubs::host_target().triple()
    )
}

/// One test's scratch directory, holding the isolated home.
struct Scratch {
    dir: tempfile::TempDir,
    home: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        // Set, not inherited: the fuz home must not be world-writable under a
        // permissive runner umask.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir, home }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Run `xtask` with the home redirected and none of the caller's
    /// variables that steer storage.
    fn xtask(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run xtask")
    }

    /// [`Scratch::xtask`] with the system temp directory redirected to `tmp`,
    /// so what a command stages there can be looked for.
    fn xtask_with_tmp(&self, tmp: &Path, args: &[&str]) -> Output {
        self.command(args)
            .env("TMPDIR", tmp)
            .output()
            .expect("run xtask")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
        command
            .args(args)
            .current_dir(self.path())
            .env("FUZ_HOME", &self.home)
            .env("FUZ_FORGE_HOME", &self.home)
            .env("HOME", &self.home)
            .env_remove("FUZ_FORGE_TOKEN")
            .env_remove("FUZ_FORGE_BASE_URL")
            .env_remove("FUZ_RELEASE_LOG_URL")
            .env_remove("FUZ_RELEASE_LOG");
        command
    }

    /// A signing key file under the scratch directory.
    fn signing_key(&self) -> String {
        let key = self.path().join("signing.key");
        let out = self.xtask(&["key", "generate", "--output", key.to_str().unwrap()]);
        assert!(
            out.status.success(),
            "key generate: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        key.to_str().unwrap().to_string()
    }

    /// Every file and symlink under the scratch directory outside the home,
    /// by relative path, with its content (a symlink's target; a directory's
    /// marker) — what a command that claims to change nothing must leave equal.
    fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, dir: &Path, skip: &Path, found: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path == skip {
                    continue;
                }
                let relative = path.strip_prefix(root).unwrap().display().to_string();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                if meta.file_type().is_symlink() {
                    let target = std::fs::read_link(&path).unwrap();
                    found.insert(relative, target.display().to_string().into_bytes());
                } else if meta.is_dir() {
                    found.insert(format!("{relative}/"), Vec::new());
                    walk(root, &path, skip, found);
                } else {
                    found.insert(relative, std::fs::read(&path).unwrap());
                }
            }
        }
        let mut found = BTreeMap::new();
        walk(self.path(), self.path(), &self.home, &mut found);
        found
    }
}

/// Assert a failed run: exit 1, the `error:` line, a `hint:` line, and
/// nothing on stdout.
#[track_caller]
fn assert_refused(out: &Output, error: &str, context: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{context}: {stderr}");
    assert!(
        stderr.contains(&format!("error: {error}\n")),
        "{context}: {stderr}"
    );
    assert!(stderr.contains("hint: "), "{context}: {stderr}");
    assert!(
        out.stdout.is_empty(),
        "{context}: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A manifest `prune` reads leniently: the three fields it decides by.
fn manifest(version: &str, target: &str, tarball: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": version,
        "target": target,
        "tarball": { "path": tarball },
    }))
    .unwrap()
}

const TARGET: &str = "x86_64-unknown-linux-gnu";

/// `prune` on a local path that is not an existing directory — missing, as a
/// path and as a `file://` URI, relative to the working directory, or a file
/// — is refused naming the location, dry run and `--wetrun` alike, and
/// creates nothing. A mistyped path never reads as "nothing to prune".
#[test]
fn prune_refuses_a_local_store_that_is_not_there() {
    let scratch = Scratch::new();
    std::fs::write(scratch.path().join("a-file"), b"keep").unwrap();
    let missing = scratch.path().join("no-such").join("store");
    let missing = missing.to_str().unwrap();
    let uri = format!("file://{missing}");
    let file = scratch.path().join("a-file");
    let before = scratch.snapshot();

    for location in [
        missing,
        uri.as_str(),
        "no-such/store",
        file.to_str().unwrap(),
    ] {
        for extra in [&[][..], &["--wetrun"], &["--tool", "fuzd", "--wetrun"]] {
            let mut args = vec!["prune", "--storage", location];
            args.extend_from_slice(extra);
            let out = scratch.xtask(&args);
            assert_refused(
                &out,
                &format!("--storage is not an existing directory: {location}"),
                &format!("{args:?}"),
            );
            assert_eq!(scratch.snapshot(), before, "{args:?}");
        }
    }
}

/// `release-log backfill` reads the releases already in storage, so a local
/// path that is not an existing directory is refused the same way — before
/// the log checkout is looked at — and nothing is created.
#[test]
fn backfill_refuses_a_local_store_that_is_not_there() {
    let scratch = Scratch::new();
    let key = scratch.signing_key();
    let log_repo = scratch.path().join("log");
    std::fs::create_dir(&log_repo).unwrap();
    let missing = scratch.path().join("no-such").join("store");
    let missing = missing.to_str().unwrap();
    let uri = format!("file://{missing}");
    let before = scratch.snapshot();

    for location in [missing, uri.as_str(), "no-such/store"] {
        for wetrun in [false, true] {
            let mut args = vec![
                "release-log",
                "backfill",
                "--storage",
                location,
                "--log-repo",
                log_repo.to_str().unwrap(),
                "--key-file",
                &key,
            ];
            if wetrun {
                args.push("--wetrun");
            }
            let out = scratch.xtask(&args);
            assert_refused(
                &out,
                &format!("--storage is not an existing directory: {location}"),
                &format!("{args:?}"),
            );
            assert_eq!(scratch.snapshot(), before, "{args:?}");
        }
    }
}

/// A store that is there and holds nothing of the stream is still "nothing to
/// prune": the refusal is for the store, not for an empty stream.
#[test]
fn prune_of_an_existing_store_with_no_releases_has_nothing_to_prune() {
    let scratch = Scratch::new();
    let store = scratch.path().join("store");
    std::fs::create_dir(&store).unwrap();
    let before = scratch.snapshot();

    for extra in [&[][..], &["--tool", "fuzd", "--wetrun"]] {
        let mut args = vec!["prune", "--storage", store.to_str().unwrap()];
        args.extend_from_slice(extra);
        let out = scratch.xtask(&args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {stdout}");
        assert!(stdout.contains("nothing to prune"), "{args:?}: {stdout}");
        assert_eq!(scratch.snapshot(), before, "{args:?}");
    }
}

/// `prune --tool` takes a first-party tool name. Anything else is refused
/// before a storage key is built from it, so a name with `..` in it lists and
/// deletes nothing — in the store's other streams or outside the store.
///
/// The store here is seeded so that, were the name joined into keys unchecked,
/// each one would select something to delete with `--keep 0`:
///
/// - `..` sweeps `tools/../` — the store root, the self stream's own
///   directory — for manifests named `..-…`, and the planted one names the
///   self stream's tarball.
/// - `../..` and `../../victim` sweep the directories outside the store.
#[test]
fn prune_refuses_a_tool_name_that_is_not_one_and_deletes_nothing() {
    let scratch = Scratch::new();
    let store = scratch.path().join("store");
    std::fs::create_dir_all(store.join("tools/fuzd")).unwrap();
    // The self stream: one release at the root.
    let self_tarball = format!("fuz-0.1.0-{TARGET}.tar.gz");
    std::fs::write(store.join(&self_tarball), b"self tarball").unwrap();
    std::fs::write(
        store.join(format!("fuz-0.1.0-{TARGET}.manifest.json")),
        manifest("0.1.0", TARGET, &self_tarball),
    )
    .unwrap();
    // A manifest a stream named `..` would claim, naming that tarball.
    std::fs::write(
        store.join(format!("..-0.0.1-{TARGET}.manifest.json")),
        manifest("0.0.1", TARGET, &self_tarball),
    )
    .unwrap();
    // The same shapes beside the store and in a directory beside it.
    for outside in [scratch.path().to_path_buf(), scratch.path().join("victim")] {
        std::fs::create_dir_all(&outside).unwrap();
        for stream in ["..", "victim"] {
            let tarball = format!("{stream}-0.0.1-{TARGET}.tar.gz");
            std::fs::write(outside.join(&tarball), b"outside").unwrap();
            std::fs::write(
                outside.join(format!("{stream}-0.0.1-{TARGET}.manifest.json")),
                manifest("0.0.1", TARGET, &tarball),
            )
            .unwrap();
        }
    }
    let before = scratch.snapshot();

    for tool in [
        "..",
        "../..",
        "../x",
        "../../victim",
        ".",
        "",
        "/abs",
        "fuzd/..",
        "notatool",
    ] {
        for wetrun in [false, true] {
            let mut args = vec![
                "prune",
                "--storage",
                store.to_str().unwrap(),
                "--tool",
                tool,
                "--keep",
                "0",
            ];
            if wetrun {
                args.push("--wetrun");
            }
            let out = scratch.xtask(&args);
            assert_refused(
                &out,
                &format!("--tool is not a first-party tool name: {tool}"),
                &format!("{args:?}"),
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains(
                    "hint: prune works on the stream of a first-party tool; check the name"
                ),
                "{args:?}: {stderr}"
            );
            assert_eq!(scratch.snapshot(), before, "{args:?}");
        }
    }
}

/// A publish is the command that creates a local store — with its first
/// upload — and it refuses, before packing or signing, a path that something
/// other than a directory already holds: a file there, a dangling symlink
/// there (its target is not created), a file where a parent should be.
#[test]
fn publish_creates_a_missing_store_and_refuses_one_that_cannot_be() {
    let scratch = Scratch::new();
    let key = scratch.signing_key();
    let binary = scratch.path().join("fuzd-bin");
    std::fs::write(&binary, fuz_artifact::platform::test_stubs::host(b"stub")).unwrap();
    let publish = |location: &str| {
        scratch.xtask(&[
            "publish",
            "tool",
            "fuzd",
            binary.to_str().unwrap(),
            "--version",
            "0.0.1",
            "--storage",
            location,
            "--key-file",
            &key,
        ])
    };

    let file = scratch.path().join("a-file");
    std::fs::write(&file, b"keep").unwrap();
    let dangling = scratch.path().join("dangling");
    std::os::unix::fs::symlink(scratch.path().join("target-not-there"), &dangling).unwrap();
    let under_a_file = file.join("store");
    let before = scratch.snapshot();
    for location in [&file, &dangling, &under_a_file] {
        let location = location.to_str().unwrap();
        let out = publish(location);
        assert_refused(
            &out,
            &format!("--storage is not a directory, and cannot be created as one: {location}"),
            location,
        );
        assert_eq!(scratch.snapshot(), before, "{location}");
    }

    let missing = scratch.path().join("new").join("store");
    let out = publish(missing.to_str().unwrap());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(missing.join(host_latest("fuzd")).is_file());
}

/// A version carrying semver build metadata cannot be part of a storage key
/// (`+` is outside the key contract every backend holds), so a publish refuses
/// it up front, naming the version — before the binary is read (the path
/// given does not exist) and with nothing written — rather than at the first
/// upload, after packing and signing. A pre-release version publishes.
#[test]
fn publish_refuses_a_version_no_store_could_hold_before_any_work() {
    let scratch = Scratch::new();
    let key = scratch.signing_key();
    let store = scratch.path().join("store");
    let publish = |version: &str, binary: &Path| {
        scratch.xtask(&[
            "publish",
            "tool",
            "fuzd",
            binary.to_str().unwrap(),
            "--version",
            version,
            "--storage",
            store.to_str().unwrap(),
            "--key-file",
            &key,
        ])
    };
    let before = scratch.snapshot();

    let out = publish("0.0.1+b1", &scratch.path().join("no-such-binary"));
    assert_refused(
        &out,
        "manifest error: release version cannot be part of a storage key: \"0.0.1+b1\" \
         (key contains invalid characters (allowed: a-z, A-Z, 0-9, '-', '.', '_', '/'))",
        "0.0.1+b1",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("build metadata"), "{stderr}");
    assert_eq!(scratch.snapshot(), before);

    let binary = scratch.path().join("fuzd-bin");
    std::fs::write(&binary, fuz_artifact::platform::test_stubs::host(b"stub")).unwrap();
    let out = publish("0.0.2-rc.1", &binary);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let latest = std::fs::read_to_string(store.join(host_latest("fuzd"))).unwrap();
    assert!(latest.contains("0.0.2-rc.1"), "{latest}");
}

const READ_ONLY_HINT: &str = "hint: Use a writable backend: a local path, forge://, or ssh://\n";

/// A listener on loopback that nothing should connect to: the `http://` base
/// naming it, and a check that nothing did.
struct Unreached {
    listener: std::net::TcpListener,
    base: String,
}

impl Unreached {
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}/releases", listener.local_addr().unwrap());
        Self { listener, base }
    }

    #[track_caller]
    fn assert_unreached(&self, context: &str) {
        match self.listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("{context}: the store was contacted: {other:?}"),
        }
    }
}

/// A publish has nothing to upload to on a read-only backend. It is refused
/// when `--storage` is resolved, with the error and hint its first upload
/// would give — before the signing key is loaded (there is none here: with
/// no key, and with a `--key-file` that is not there, it is still the store
/// that is refused), before the binary or the current artifact is read
/// (neither exists), and with nothing staged, written, or requested.
#[test]
fn publish_refuses_a_read_only_store_before_the_key_and_any_work() {
    let scratch = Scratch::new();
    let tmp = scratch.path().join("tmp");
    std::fs::create_dir(&tmp).unwrap();
    let loopback = Unreached::new();
    let before = scratch.snapshot();

    for location in ["https://releases.example.com/fuz", loopback.base.as_str()] {
        for key_file in [&[][..], &["--key-file", "keys/absent.key"]] {
            let tool = [
                "publish",
                "tool",
                "fuzd",
                "no-such-binary",
                "--version",
                "0.0.1",
                "--storage",
                location,
            ];
            let this = ["publish", "self", "--storage", location];
            for command in [&tool[..], &this[..]] {
                let mut args = command.to_vec();
                args.extend_from_slice(key_file);
                let out = scratch.xtask_with_tmp(&tmp, &args);
                assert_eq!(
                    String::from_utf8_lossy(&out.stderr),
                    format!(
                        "error: HTTPS: upload is not supported on a read-only backend\n\
                         {READ_ONLY_HINT}"
                    ),
                    "{args:?}"
                );
                assert_eq!(out.status.code(), Some(1), "{args:?}");
                assert!(out.stdout.is_empty(), "{args:?}");
                assert_eq!(scratch.snapshot(), before, "{args:?}");
                assert_eq!(std::fs::read_dir(&scratch.home).unwrap().count(), 0);
                loopback.assert_unreached(&format!("{args:?}"));
            }
        }
    }

    // With a key and a binary that reads, it is still the store.
    let key = scratch.signing_key();
    let binary = scratch.path().join("fuzd-bin");
    std::fs::write(&binary, fuz_artifact::platform::test_stubs::host(b"stub")).unwrap();
    let before = scratch.snapshot();
    let out = scratch.xtask_with_tmp(
        &tmp,
        &[
            "publish",
            "tool",
            "fuzd",
            binary.to_str().unwrap(),
            "--version",
            "0.0.1",
            "--storage",
            &loopback.base,
            "--key-file",
            &key,
        ],
    );
    assert_refused(
        &out,
        "HTTPS: upload is not supported on a read-only backend",
        "with a key",
    );
    assert_eq!(scratch.snapshot(), before);
    loopback.assert_unreached("with a key");
}

/// `prune` and `release-log backfill` list the store, which a read-only
/// backend cannot do: both fail on that, with the hint, dry run and
/// `--wetrun` alike — the backfill before it looks at the log checkout (the
/// directory given is not one) — and nothing is requested or written.
#[test]
fn prune_and_backfill_refuse_a_read_only_store() {
    let scratch = Scratch::new();
    let key = scratch.signing_key();
    let log_repo = scratch.path().join("log");
    std::fs::create_dir(&log_repo).unwrap();
    let loopback = Unreached::new();
    let before = scratch.snapshot();

    for location in ["https://releases.example.com/fuz", loopback.base.as_str()] {
        for wetrun in [false, true] {
            let prune = ["prune", "--storage", location];
            let backfill = [
                "release-log",
                "backfill",
                "--storage",
                location,
                "--log-repo",
                log_repo.to_str().unwrap(),
                "--key-file",
                &key,
            ];
            for command in [&prune[..], &backfill[..]] {
                let mut args = command.to_vec();
                if wetrun {
                    args.push("--wetrun");
                }
                let out = scratch.xtask(&args);
                assert_eq!(
                    String::from_utf8_lossy(&out.stderr),
                    format!(
                        "error: storage error: HTTPS: list is not supported on a read-only \
                         backend\n{READ_ONLY_HINT}"
                    ),
                    "{args:?}"
                );
                assert_eq!(out.status.code(), Some(1), "{args:?}");
                assert!(out.stdout.is_empty(), "{args:?}");
                assert_eq!(scratch.snapshot(), before, "{args:?}");
                loopback.assert_unreached(&format!("{args:?}"));
            }
        }
    }
}
