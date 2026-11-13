//! Shared helpers for the `fuz` CLI integration suites: spawn the real binary
//! against a redirected `~/.fuz`, seed artifacts/tools with public constructors,
//! and parse `--json` output. Included via `mod common;` in each `tests/*.rs`;
//! `dead_code` is allowed because no single suite uses every helper.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]
#![allow(dead_code, reason = "each test binary uses only part of this module")]

use std::collections::BTreeMap;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output};

use fuz_artifact::tools::ToolMeta;
use fuz_artifact::{ArtifactMeta, ContentHash};
use fuz_sys::SECURE_DIR_MODE;

/// A throwaway `~/.fuz` for one test, pinned to `0700`.
///
/// The mode is **set**, not inherited. `tempfile::tempdir()` creates at the std
/// default `0o777` masked by the process umask, so under a permissive runner
/// umask (`umask 000`, routine in containers) the home would arrive
/// world-writable — and the real binary these tests spawn refuses one
/// (`ensure_fuz_home` on `self bootstrap`, `check_fuz_home_not_world_writable`
/// on the install paths). Pinning it at [`SECURE_DIR_MODE`] keeps the suites
/// testing `fuz`, not whoever launched cargo.
pub fn fresh_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        home.path(),
        std::fs::Permissions::from_mode(SECURE_DIR_MODE),
    )
    .unwrap();
    home
}

/// A [`fresh_home`] whose path is safe to write into a shell rc line.
///
/// `self bootstrap` only writes (or prints) a PATH line for a bin dir within
/// `[A-Za-z0-9_./+-]`; anything else gets manual instructions instead. A test
/// asserting on that line for a fuz home outside `$HOME` therefore depends on
/// where the tempdir lands. This checks up front, so an unusual `TMPDIR` fails
/// with the cause rather than with a missing-rc assertion.
pub fn fresh_home_rc_safe() -> tempfile::TempDir {
    let home = fresh_home();
    let rc_safe = home.path().to_str().is_some_and(|path| {
        path.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./+-".contains(&byte))
    });
    assert!(
        rc_safe,
        "TMPDIR must match [A-Za-z0-9_./+-] for these tests: {}",
        home.path().display()
    );
    home
}

/// Whether the suite runs as root, for whom permission bits deny nothing — a
/// test that relies on a denial has nothing to observe, and one whose
/// regression would write through a system path must not run.
pub fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::metadata(dir.path()).unwrap().uid() == 0
}

/// Create a FIFO at `path` by shelling out to `mkfifo(1)` — std has no
/// constructor for one. `false` when the tool is unavailable, so the caller
/// can skip.
pub fn make_fifo(path: &Path) -> bool {
    Command::new("mkfifo")
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
}

/// Run the real `fuz` binary with both `FUZ_HOME` and `HOME` redirected at
/// `home` (HOME isolation keeps `self bootstrap`'s shell-rc logic off the real
/// files; harmless for the other verbs).
pub fn run(home: &Path, args: &[&str]) -> Output {
    run_with_env(home, args, &[])
}

/// Like [`run`], plus extra environment variables. Used to drive `self
/// bootstrap`'s shell-rc branch deterministically by pinning `SHELL` (the
/// inherited value is nondeterministic across dev machines / CI).
pub fn run_with_env(home: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fuz"));
    cmd.args(args).env("FUZ_HOME", home).env("HOME", home);
    // The release log variables decide whether an install consults a witness;
    // a test sets them itself or runs without them, never with the caller's.
    cmd.env_remove("FUZ_RELEASE_LOG_URL")
        .env_remove("FUZ_RELEASE_LOG");
    // Likewise the build target `fuz artifact build`'s cargo would obey: a
    // developer's global setting must not decide a build test.
    cmd.env_remove("CARGO_BUILD_TARGET");
    for (key, val) in envs {
        cmd.env(key, val);
    }
    cmd.output().expect("spawn fuz")
}

/// Seed a committed bootstrap artifact into `<home>/artifacts/v1-<hash>/` with an
/// explicit `created_at` (the store clock is second-resolution, so explicit
/// timestamps make newest-first ordering deterministic). Public constructors
/// only, so no `~/.fuz` redirect is needed for seeding.
pub fn seed_artifact(home: &Path, seed: u8, created_at: &str) -> ArtifactMeta {
    let mut bytes = vec![seed; 2048];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    let mut meta = ArtifactMeta::new_bootstrap("0.1.0".to_string(), ContentHash::blake3(&bytes));
    meta.created_at = created_at.to_string();
    let dir = home.join("artifacts").join(&meta.hash);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("fuz"), &bytes).unwrap();
    meta.write(&dir).unwrap();
    meta
}

/// Hand-seed an installed tool under `<home>/tools/<name>/v1-<hash>/` with a single
/// binary and a `current` symlink — the state `tool verify` / `tool list` read.
/// (`install_local_tool` resolves *this* process's home, not the child's, so we
/// place files explicitly.) Returns the `ToolMeta`; its `content_hash` is the
/// install dir name, needed to locate the binary for tamper tests.
pub fn seed_tool(home: &Path, name: &str, version: &str, bin: &str, seed: u8) -> ToolMeta {
    let mut bytes = vec![seed; 2048];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    let mut binaries = BTreeMap::new();
    binaries.insert(bin.to_string(), ContentHash::blake3(&bytes));
    let meta = ToolMeta::new(name.to_string(), version.to_string(), binaries);
    let tool_dir = home.join("tools").join(name);
    let install_dir = tool_dir.join(&meta.content_hash);
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::write(install_dir.join(bin), &bytes).unwrap();
    meta.write(&install_dir).unwrap();
    symlink(&meta.content_hash, tool_dir.join("current")).unwrap();
    meta
}

/// Parse a command's stdout as JSON, asserting success first.
pub fn stdout_json(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout is valid JSON")
}
