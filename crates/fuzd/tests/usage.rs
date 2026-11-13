//! The real `fuzd` binary's command-line contract: a line argh can't parse
//! exits 2 with the message on stderr — never argh's own exit 1, which `fuzd
//! status` gives "not running" — and a help request prints usage to stdout and
//! exits 0. Every invocation runs against a throwaway `FUZ_HOME` with no daemon,
//! and none of them starts one.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const FUZD: &str = env!("CARGO_BIN_EXE_fuzd");

/// A throwaway home at 0700, whatever the runner's umask: the CLI refuses a
/// world-writable `FUZ_HOME`, and `tempfile` creates the dir from the umask.
fn fresh_home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod home");
    dir
}

fn run_fuzd(home: &Path, args: &[&str]) -> Output {
    Command::new(FUZD)
        .args(args)
        .env("FUZ_HOME", home)
        .output()
        .expect("run fuzd")
}

/// An unknown flag — on a subcommand or on bare `fuzd` — and an unknown
/// subcommand exit 2 with argh's message on stderr.
#[test]
fn unparseable_command_line_exits_2_on_stderr() {
    let home = fresh_home();
    for (args, message) in [
        (
            &["status", "--quiet", "--bogus"][..],
            "Unrecognized argument: --bogus",
        ),
        (&["--bogus"], "Unrecognized argument: --bogus"),
        (&["frobnicate"], "Unrecognized argument: frobnicate"),
    ] {
        let out = run_fuzd(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "`fuzd {args:?}`: {stderr}");
        assert!(stderr.contains(message), "`fuzd {args:?}`: {stderr}");
        assert!(
            stderr.contains("Run fuzd --help for more information."),
            "`fuzd {args:?}` keeps argh's pointer: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "`fuzd {args:?}` prints nothing to stdout"
        );
    }
}

/// The distinction the usage code exists for: with no daemon, `fuzd status
/// --quiet` answers "not running" with exit 1, and the same line with a typo
/// exits 2 — a script can tell the two apart.
#[test]
fn status_not_running_and_usage_error_have_different_codes() {
    let home = fresh_home();
    let answer = run_fuzd(home.path(), &["status", "--quiet"]);
    assert_eq!(answer.status.code(), Some(1), "no daemon: not running");
    let typo = run_fuzd(home.path(), &["status", "--quite"]);
    assert_eq!(typo.status.code(), Some(2), "a typo is a usage error");
}

/// `--help` and the `help` subcommand, at either level, print usage to stdout
/// and exit 0.
#[test]
fn help_request_exits_0_on_stdout() {
    let home = fresh_home();
    for (args, usage) in [
        (&["--help"][..], "Usage: fuzd [<command>]"),
        (&["help"], "Usage: fuzd [<command>]"),
        (&["status", "--help"], "Usage: fuzd status"),
        (&["help", "stop"], "Usage: fuzd stop"),
    ] {
        let out = run_fuzd(home.path(), args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "`fuzd {args:?}`: {stdout}");
        assert!(stdout.starts_with(usage), "`fuzd {args:?}`: {stdout}");
        assert!(
            out.stderr.is_empty(),
            "`fuzd {args:?}` prints nothing to stderr"
        );
    }
}
