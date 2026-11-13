//! The real `fuzi` binary's command-line contract: a line argh can't parse
//! exits `EX_USAGE` (64) with the message on stderr — the code fuzi gives every
//! usage error, not argh's own exit 1 — and a help request prints usage to
//! stdout and exits 0. Each run is in an empty scratch directory, and none of
//! them installs anything.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]
// `run_fuzi` spawns the built binary under a scoped `#[expect]` of the
// exec-free disallow in this crate's `clippy.toml`: it guards fuzi's own
// source, not the tests that drive it from outside — and scoped, so the rest
// of the file keeps the copied `home_dir` disallow.

use std::process::Output;

/// sysexits `EX_USAGE` — fuzi's usage class (`FuziError::Usage`).
const EX_USAGE: i32 = 64;

#[expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "the exec-free disallow guards fuzi's own source; this harness drives the built binary from outside"
)]
fn run_fuzi(args: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("tempdir");
    std::process::Command::new(env!("CARGO_BIN_EXE_fuzi"))
        .args(args)
        .current_dir(dir.path())
        .output()
        .expect("run fuzi")
}

/// An unknown flag, a flag on the wrong verb, an unknown verb, and no verb
/// exit 64 with argh's message on stderr; nothing reaches stdout.
#[test]
fn unparseable_command_line_exits_ex_usage_on_stderr() {
    for (args, message) in [
        (
            &["install", "--bogus"][..],
            "Unrecognized argument: --bogus",
        ),
        (&["clean", "--offline"], "Unrecognized argument: --offline"),
        (&["frobnicate"], "Unrecognized argument: frobnicate"),
        (&[], "One of the following subcommands must be present"),
    ] {
        let out = run_fuzi(args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(EX_USAGE),
            "`fuzi {args:?}`: {stderr}"
        );
        assert!(stderr.contains(message), "`fuzi {args:?}`: {stderr}");
        assert!(
            stderr.contains("Run fuzi --help for more information."),
            "`fuzi {args:?}` keeps argh's pointer: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "`fuzi {args:?}` prints nothing to stdout"
        );
    }
}

/// A parse error and a value fuzi refuses after parsing (an unknown `--omit`
/// class) are one usage class with one exit code.
#[test]
fn parse_error_shares_the_exit_code_of_a_refused_value() {
    let refused = run_fuzi(&["install", "--dry-run", "--omit", "bogus"]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(EX_USAGE), "{stderr}");
    assert!(stderr.contains("bogus"), "{stderr}");
    let unparsed = run_fuzi(&["install", "--dry-run", "--omitt", "dev"]);
    assert_eq!(unparsed.status.code(), refused.status.code());
}

/// `verify --omit` parses its values as `install` does: an unknown class is a
/// usage error, not an omit list that silently drops it.
#[test]
fn verify_refuses_an_unknown_omit_class() {
    let out = run_fuzi(&["verify", "--omit", "bogus"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(EX_USAGE), "{stderr}");
    assert!(stderr.contains("bogus"), "{stderr}");
}

/// `--help` and the `help` subcommand, at either level, print usage to stdout
/// and exit 0.
#[test]
fn help_request_exits_0_on_stdout() {
    for (args, usage) in [
        (&["--help"][..], "Usage: fuzi <command>"),
        (&["help"], "Usage: fuzi <command>"),
        (&["install", "--help"], "Usage: fuzi install"),
        (&["help", "verify"], "Usage: fuzi verify"),
    ] {
        let out = run_fuzi(args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "`fuzi {args:?}`: {stdout}");
        assert!(stdout.starts_with(usage), "`fuzi {args:?}`: {stdout}");
        assert!(
            out.stderr.is_empty(),
            "`fuzi {args:?}` prints nothing to stderr"
        );
    }
}
