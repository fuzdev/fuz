//! The real `xtask` binary's signing-key contract: the commands that load the
//! key — `key info` / `export`, `publish`, `release-log` — find it the same
//! way and say the same thing when they cannot.
//!
//! - No `--key-file`: `signing.key` in the fuz config directory.
//! - `--key-file <path>`: that file; loading it does not resolve the fuz home.
//! - A key that cannot be loaded exits 1 with one `error:` line carrying the
//!   cause (and the file, when it could not be read), and a `hint:` line where
//!   there is something to do.
//!
//! Every run gets its own `FUZ_HOME` and `HOME` and works under one scratch
//! directory; `HOME` is always set, so no run reads the caller's home.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CREATE_HINT: &str =
    "hint: create a signing key with `cargo xtask key generate` in the fuz workspace\n";
const RELATIVE_HOME_ERROR: &str = "error: failed to resolve fuz config directory: \
     FUZ_HOME must be an absolute path, got relhome\n\
     hint: set FUZ_HOME to an absolute path, or unset it to use ~/.fuz\n";

/// One test's scratch directory: the working directory, holding the home.
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

    /// The default key location under this scratch home.
    fn default_key(&self) -> PathBuf {
        self.home.join("config").join("signing.key")
    }

    /// Run `xtask` with the fuz home at `fuz_home`, `HOME` at the scratch
    /// home, and the scratch directory as the working directory.
    fn xtask_with_home(&self, fuz_home: impl AsRef<OsStr>, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(args)
            .current_dir(self.path())
            .env("FUZ_HOME", fuz_home)
            .env("HOME", &self.home)
            .env_remove("FUZ_FORGE_TOKEN")
            .env_remove("FUZ_FORGE_BASE_URL")
            .env_remove("FUZ_RELEASE_LOG_URL")
            .env_remove("FUZ_RELEASE_LOG")
            .output()
            .expect("run xtask")
    }

    fn xtask(&self, args: &[&str]) -> Output {
        self.xtask_with_home(&self.home, args)
    }

    /// The names in the scratch directory.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Assert a run that failed (exit 1) with exactly `expected` on stderr and
/// nothing on stdout.
#[track_caller]
fn assert_failed_with(out: &Output, expected: &str, context: &str) {
    assert_exited_with(out, 1, expected, context);
}

/// Assert a run that exited `code` with exactly `expected` on stderr and
/// nothing on stdout.
#[track_caller]
fn assert_exited_with(out: &Output, code: i32, expected: &str, context: &str) {
    assert_eq!(out.status.code(), Some(code), "{context}: {}", stderr(out));
    assert_eq!(stderr(out), expected, "{context}");
    assert!(out.stdout.is_empty(), "{context}: {}", stdout(out));
}

/// The commands that load the signing key, each with arguments that reach the
/// load and, were the key there, would go on to fail on something else.
fn signing_commands(key_file: Option<&str>) -> Vec<Vec<&str>> {
    let mut commands = vec![
        vec!["key", "info"],
        vec!["key", "export"],
        vec!["publish", "self", "--storage", "store"],
        vec![
            "publish",
            "tool",
            "fuzd",
            "no-such-binary",
            "--version",
            "0.1.0",
            "--storage",
            "store",
        ],
        vec![
            "release-log",
            "backfill",
            "--storage",
            "store",
            "--log-repo",
            "log",
        ],
        vec!["release-log", "revoke", "fuz", "0.1.0", "--log-repo", "log"],
    ];
    if let Some(key_file) = key_file {
        for command in &mut commands {
            command.extend(["--key-file", key_file]);
        }
    }
    commands
}

/// With no key generated, every signing command names the default file, says
/// it is not there, and points at `key generate` — and creates nothing.
#[test]
fn a_missing_default_key_is_named_with_how_to_make_one() {
    let scratch = Scratch::new();
    let key = scratch.default_key();
    let expected = format!(
        "error: failed to read signing key file {0}: file not found: {0}\n{CREATE_HINT}",
        key.display()
    );
    for command in signing_commands(None) {
        let out = scratch.xtask(&command);
        assert_failed_with(&out, &expected, &format!("{command:?}"));
    }
    assert_eq!(scratch.entries(), ["home"]);
    assert_eq!(std::fs::read_dir(&scratch.home).unwrap().count(), 0);
}

/// `--key-file` names the file that is tried, in the message too.
#[test]
fn a_missing_key_file_is_named_as_given() {
    let scratch = Scratch::new();
    let expected = format!(
        "error: failed to read signing key file keys/absent.key: \
         file not found: keys/absent.key\n{CREATE_HINT}"
    );
    for command in signing_commands(Some("keys/absent.key")) {
        let out = scratch.xtask(&command);
        assert_failed_with(&out, &expected, &format!("{command:?}"));
    }
    assert_eq!(scratch.entries(), ["home"]);
}

/// A key file another user could read is refused with its mode and the fix.
#[test]
fn a_key_file_open_to_others_is_refused_with_the_fix() {
    let scratch = Scratch::new();
    let out = scratch.xtask(&["key", "generate"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let key = scratch.default_key();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let expected = format!(
        "error: failed to read signing key file {0}: \
         insecure permissions on {0}: 100644 (expected 0600)\n\
         hint: a signing key file is its owner's alone: `chmod 600` it\n",
        key.display()
    );
    for command in signing_commands(None) {
        let out = scratch.xtask(&command);
        assert_failed_with(&out, &expected, &format!("{command:?}"));
    }
}

/// A file that is not a key file: the parser's message and its hint.
#[test]
fn a_malformed_key_file_carries_the_parser_hint() {
    let scratch = Scratch::new();
    let key = scratch.path().join("bad.key");
    std::fs::write(&key, "not a key file\n").unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

    let expected = "error: failed to parse key file: invalid structure\n\
                    hint: Key file is malformed. Regenerate with `cargo xtask key generate`\n";
    for command in signing_commands(Some("bad.key")) {
        let out = scratch.xtask(&command);
        assert_failed_with(&out, expected, &format!("{command:?}"));
    }
}

/// `key generate` writes the default key, and `key info` / `export` read that
/// same file back.
#[test]
fn the_generated_default_key_is_the_one_read_back() {
    let scratch = Scratch::new();
    let out = scratch.xtask(&["key", "generate"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let key = scratch.default_key();
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let generated = stdout(&out);
    let public_key = generated
        .lines()
        .find_map(|line| line.strip_prefix("Public key: "))
        .expect("the public key line");

    let out = scratch.xtask(&["key", "export"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), format!("{public_key}\n"));

    // `HOME` is the fuz home here, so the default file collapses to `~/…`.
    let out = scratch.xtask(&["key", "info", "--json"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let info = stdout(&out);
    assert!(info.contains(r#""file":"~/config/signing.key""#), "{info}");
    assert!(
        info.contains(&format!(r#""public_key":"{public_key}""#)),
        "{info}"
    );

    // A key elsewhere, named by `--key-file`, is a different key, shown under
    // the path as given.
    let out = scratch.xtask(&["key", "generate", "--output", "./other.key"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = scratch.xtask(&["key", "export", "--key-file", "./other.key"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_ne!(stdout(&out), format!("{public_key}\n"));
    let out = scratch.xtask(&["key", "info", "--key-file", "./other.key"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("File:       ./other.key\n"),
        "{}",
        stdout(&out)
    );
}

/// `--output` given a bare file name writes the key in the working directory
/// and succeeds; the key reads back.
#[test]
fn a_bare_output_name_writes_the_key_in_the_working_directory() {
    let scratch = Scratch::new();
    let out = scratch.xtask(&["key", "generate", "--output", "bare.key"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(scratch.entries(), ["bare.key", "home"]);
    assert_eq!(
        std::fs::metadata(scratch.path().join("bare.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let out = scratch.xtask(&["key", "export", "--key-file", "bare.key"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

/// A relative `FUZ_HOME` has no default key location: the error keeps the home
/// layer's cause and prints its hint, and exits 2 (the caller's environment to
/// fix), from each command that loads the key and from `key generate`, and
/// nothing is created under the working directory. A key named by
/// `--key-file` loads without the home.
#[test]
fn a_relative_fuz_home_is_refused_with_the_home_hint_unless_a_key_file_is_named() {
    let scratch = Scratch::new();
    let mut commands = signing_commands(None);
    commands.push(vec!["key", "generate"]);
    for command in commands {
        let out = scratch.xtask_with_home("relhome", &command);
        assert_exited_with(&out, 2, RELATIVE_HOME_ERROR, &format!("{command:?}"));
    }
    assert_eq!(scratch.entries(), ["home"]);

    let out = scratch.xtask(&["key", "generate", "--output", "./named.key"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let exported = scratch.xtask(&["key", "export", "--key-file", "./named.key"]);
    let out = scratch.xtask_with_home("relhome", &["key", "export", "--key-file", "./named.key"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), stdout(&exported));
    assert_eq!(scratch.entries(), ["home", "named.key"]);
}
