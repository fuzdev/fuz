//! The real `fuzi` binary's `--json` contract on the failures an agent meets
//! first: each run's exit code, a parseable stdout document, and its `kind`.
//!
//! Every run is in a scratch project with `FUZ_HOME` pointed at a scratch
//! directory that does not exist, so no run reads or writes the user's cache —
//! and each one that must not create the cache asserts it did not. None of
//! them reaches the network: each fails, or (`--dry-run`) succeeds, before the
//! fetch phase.

// Test harness: the clippy `allow-expect-in-tests` config reaches only `#[test]`
// fns, not the shared helpers below, which panic on a setup failure by design.
#![allow(clippy::expect_used, clippy::panic)]
// `Project::run` spawns the built binary under a scoped `#[expect]` of the
// exec-free disallow in this crate's `clippy.toml`: it guards fuzi's own
// source, not the tests that drive it from outside — and scoped, so the rest
// of the file keeps the copied `home_dir` disallow.

use std::path::Path;

use serde_json::{Value, json};

/// A scratch project, and the `FUZ_HOME` the binary is pointed at (absent).
struct Project {
    dir: tempfile::TempDir,
    fuz_home: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            fuz_home: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The `FUZ_HOME` given to the binary: a path under a scratch dir, never
    /// created by the test.
    fn home(&self) -> std::path::PathBuf {
        self.fuz_home.path().join("fuz")
    }

    fn write(&self, name: &str, value: &Value) {
        std::fs::write(self.path().join(name), value.to_string()).expect("write");
    }

    /// Run `fuzi <args>` here; returns the exit code and the parsed stdout.
    fn run(&self, args: &[&str]) -> (i32, Value) {
        self.run_with_home(args, self.home().as_os_str())
    }

    /// [`Project::run`] with `FUZ_HOME` set to `fuz_home`.
    #[expect(
        clippy::disallowed_types,
        clippy::disallowed_methods,
        reason = "the exec-free disallow guards fuzi's own source; this harness drives the built binary from outside"
    )]
    fn run_with_home(&self, args: &[&str], fuz_home: &std::ffi::OsStr) -> (i32, Value) {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_fuzi"))
            .args(args)
            .current_dir(self.path())
            .env("FUZ_HOME", fuz_home)
            .output()
            .expect("run fuzi");
        let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
        let value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "`fuzi {args:?}` stdout is not JSON ({e}): {stdout:?}; stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("exited, not signaled"), value)
    }
}

/// A lockfile placing one registry package `a@1.0.0`, and a `package.json`
/// declaring `a` at `manifest_range`.
fn one_package_project(manifest_range: &str) -> Project {
    let project = Project::new();
    let lock_deps = json!({"a": "1.0.0"});
    project.write(
        "package.json",
        &json!({"name": "app", "dependencies": {"a": manifest_range}}),
    );
    project.write(
        "package-lock.json",
        &json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "dependencies": lock_deps},
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ=="
                }
            }
        }),
    );
    project
}

fn assert_error(value: &Value, code: i32, kind: &str) {
    assert_eq!(value["ok"], json!(false), "{value}");
    assert_eq!(value["error"]["kind"], json!(kind), "{value}");
    assert_eq!(value["error"]["exit_code"], json!(code), "{value}");
}

#[test]
fn install_without_a_lockfile_is_missing_input() {
    let project = Project::new();
    let (code, value) = project.run(&["install", "--json"]);
    assert_eq!(code, 66);
    assert_error(&value, 66, "missing_input");
    assert_eq!(value["error"]["file"], json!("package-lock.json"));
    assert!(!project.home().exists());
}

#[test]
fn install_with_a_drifted_manifest_is_drift() {
    let project = one_package_project("2.0.0");
    let (code, value) = project.run(&["install", "--json"]);
    assert_eq!(code, 65);
    assert_error(&value, 65, "drift");
    assert_eq!(value["error"]["diffs"].as_array().map(Vec::len), Some(1));
    assert!(!project.path().join("node_modules").exists());
    assert!(!project.home().exists());
}

#[test]
fn verify_on_a_tree_never_installed_is_one_absent_problem() {
    let project = one_package_project("1.0.0");
    let (code, value) = project.run(&["verify", "--json"]);
    assert_eq!(code, 65);
    assert_error(&value, 65, "verify_failed");
    let problems = value["error"]["problems"].as_array().expect("problems");
    assert_eq!(problems.len(), 1, "{value}");
    assert_eq!(problems[0]["kind"], json!("node_modules_absent"));
    assert_eq!(problems[0]["package"], json!("node_modules"));
}

/// `--ignore-manifest` skips the drift guard: the project that refuses as drift
/// above dry-runs clean with the flag.
#[test]
fn ignore_manifest_installs_past_a_drifted_manifest() {
    let project = one_package_project("2.0.0");
    let (code, value) = project.run(&["install", "--dry-run", "--ignore-manifest", "--json"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], json!(true));
    assert_eq!(value["placed"], json!(1));
    assert!(!project.home().exists());
}

/// `verify --omit` reaches the check: a lock whose only package is `dev`
/// verifies clean under `--omit dev` with no `node_modules`, and without the
/// flag the same tree is the absent-`node_modules` problem.
#[test]
fn verify_omit_dev_excuses_a_dev_only_lock() {
    let project = Project::new();
    project.write(
        "package.json",
        &json!({"name": "app", "devDependencies": {"a": "1.0.0"}}),
    );
    project.write(
        "package-lock.json",
        &json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "devDependencies": {"a": "1.0.0"}},
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                    "integrity": "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ==",
                    "dev": true
                }
            }
        }),
    );
    let (code, value) = project.run(&["verify", "--omit", "dev", "--json"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], json!(true));
    assert_eq!(value["checked"], json!(0));

    let (code, value) = project.run(&["verify", "--json"]);
    assert_eq!(code, 65, "{value}");
    assert_error(&value, 65, "verify_failed");
    assert_eq!(
        value["error"]["problems"][0]["kind"],
        json!("node_modules_absent")
    );
    assert!(!project.path().join("node_modules").exists());
}

/// A dry run is a read-only probe: it reports the would-fetch set and creates
/// no cache directory.
#[test]
fn dry_run_succeeds_with_the_report_envelope_and_creates_no_cache() {
    let project = one_package_project("1.0.0");
    let (code, value) = project.run(&["install", "--dry-run", "--json"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], json!(true));
    assert_eq!(value["dry_run"], json!(true));
    assert_eq!(value["cached"], json!(0));
    assert_eq!(value["fetched"], json!(1));
    assert_eq!(value["placed"], json!(1));
    assert!(value.get("error").is_none());
    assert!(
        !project.home().exists(),
        "a dry run must not create the cache"
    );
    assert!(!project.path().join("node_modules").exists());
}

/// `node_modules/a`'s cache entry under the project's `FUZ_HOME` (its
/// integrity is the SHA-512 of `a`), seeded with `bytes`.
fn seed_cache_entry(project: &Project, bytes: &[u8]) -> std::path::PathBuf {
    let key = project.home().join("cache/npm/sha512-1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75");
    std::fs::create_dir_all(&key).expect("create key dir");
    let entry = key.join("package.tgz");
    std::fs::write(&entry, bytes).expect("seed entry");
    entry
}

/// An online dry run re-hashes the cache as the real run does: a tampered
/// entry is would-fetch and rides `--json` as `healed`, left in place; an
/// intact one is cached.
#[test]
fn dry_run_reports_a_tampered_cache_entry_as_healed() {
    let project = one_package_project("1.0.0");
    let entry = seed_cache_entry(&project, b"tampered");
    let (code, value) = project.run(&["install", "--dry-run", "--json"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], json!(true));
    assert_eq!(value["cached"], json!(0));
    assert_eq!(value["fetched"], json!(1));
    assert_eq!(value["healed"], json!(["node_modules/a"]));
    assert_eq!(std::fs::read(&entry).expect("read entry"), b"tampered");

    std::fs::write(&entry, b"a").expect("restore entry");
    let (code, value) = project.run(&["install", "--dry-run", "--json"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["cached"], json!(1));
    assert_eq!(value["fetched"], json!(0));
    assert!(value.get("healed").is_none(), "{value}");
    assert!(!project.path().join("node_modules").exists());
}

/// An unreadable cache entry fails the online dry run as it fails the real run
/// (`io`, 74), before any network work.
#[test]
fn dry_run_on_an_unreadable_cache_entry_is_io() {
    use std::os::unix::fs::PermissionsExt as _;
    let project = one_package_project("1.0.0");
    let entry = seed_cache_entry(&project, b"a");
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    // Root reads a mode-000 file anyway: nothing to observe there.
    if std::fs::File::open(&entry).is_ok() {
        return;
    }
    for args in [
        &["install", "--dry-run", "--json"][..],
        &["install", "--json"],
    ] {
        let (code, value) = project.run(args);
        assert_eq!(code, 74, "`fuzi {args:?}`: {value}");
        assert_error(&value, 74, "io");
    }
    assert!(!project.path().join("node_modules").exists());
}

/// An unresolvable `FUZ_HOME` (relative is refused) fails the dry run as it
/// fails the real run — `io`, 74 — online and offline, creating nothing.
#[test]
fn dry_run_with_an_unresolvable_fuz_home_is_io() {
    let project = one_package_project("1.0.0");
    let mut messages = Vec::new();
    for args in [
        &["install", "--dry-run", "--json"][..],
        &["install", "--dry-run", "--offline", "--json"],
        &["install", "--json"],
    ] {
        let (code, value) = project.run_with_home(args, "relative/fuz".as_ref());
        assert_eq!(code, 74, "`fuzi {args:?}`: {value}");
        assert_error(&value, 74, "io");
        messages.push(value["error"]["message"].clone());
    }
    assert!(messages.windows(2).all(|w| w[0] == w[1]), "{messages:?}");
    assert!(!project.path().join("relative").exists());
    assert!(!project.path().join("node_modules").exists());
}

/// What the real `--offline` run refuses, the dry run refuses the same way.
#[test]
fn offline_dry_run_on_a_cold_cache_is_the_offline_miss() {
    let project = one_package_project("1.0.0");
    for args in [
        &["install", "--dry-run", "--offline", "--json"][..],
        &["install", "--offline", "--json"],
    ] {
        let (code, value) = project.run(args);
        assert_eq!(code, 69, "`fuzi {args:?}`: {value}");
        assert_error(&value, 69, "offline_cache_miss");
        assert_eq!(value["error"]["packages"], json!(["node_modules/a"]));
    }
}

/// A symlinked `node_modules` refuses under `--dry-run` as it does for real.
#[test]
fn dry_run_refuses_a_symlinked_node_modules() {
    let project = one_package_project("1.0.0");
    let elsewhere = tempfile::tempdir().expect("tempdir");
    std::os::unix::fs::symlink(elsewhere.path(), project.path().join("node_modules"))
        .expect("symlink");
    for args in [
        &["install", "--dry-run", "--json"][..],
        &["install", "--json"],
    ] {
        let (code, value) = project.run(args);
        assert_eq!(code, 73, "`fuzi {args:?}`: {value}");
        assert_error(&value, 73, "node_modules_not_directory");
        assert_eq!(value["error"]["obstruction"], json!("symlink"));
    }
    assert!(!project.home().exists());
}
