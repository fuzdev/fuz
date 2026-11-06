//! The real `xtask` binary's command-line contract: a line argh can't parse
//! exits 2 with the message on stderr — not argh's own exit 1, which every
//! task's failure gives — and a help request prints usage to stdout and exits
//! 0. None of these lines reaches a task.

// Test harness: the clippy `allow-expect-in-tests` config reaches only `#[test]`
// fns, not the shared helpers below, which panic on a setup failure by design.
#![allow(clippy::expect_used)]

use std::process::{Command, Output};

fn run_xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("run xtask")
}

/// An unknown flag, an unknown task, a missing required option, and no task
/// exit 2 with argh's message on stderr; nothing reaches stdout.
#[test]
fn unparseable_command_line_exits_2_on_stderr() {
    for (args, message) in [
        (&["clean", "--bogus"][..], "Unrecognized argument: --bogus"),
        (&["frobnicate"], "Unrecognized argument: frobnicate"),
        (&["publish", "self"], "Required options not provided"),
        (&[], "One of the following subcommands must be present"),
    ] {
        let out = run_xtask(args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "`xtask {args:?}`: {stderr}");
        assert!(stderr.contains(message), "`xtask {args:?}`: {stderr}");
        assert!(
            stderr.contains("Run xtask --help for more information."),
            "`xtask {args:?}` keeps argh's pointer: {stderr}"
        );
        assert!(
            out.stdout.is_empty(),
            "`xtask {args:?}` prints nothing to stdout"
        );
    }
}

/// `--help` and the `help` subcommand, at either level, print usage to stdout
/// and exit 0.
#[test]
fn help_request_exits_0_on_stdout() {
    for (args, usage) in [
        (&["--help"][..], "Usage: xtask <command>"),
        (&["help"], "Usage: xtask <command>"),
        (&["prune", "--help"], "Usage: xtask prune"),
        (&["help", "release-log"], "Usage: xtask release-log"),
    ] {
        let out = run_xtask(args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "`xtask {args:?}`: {stdout}");
        assert!(stdout.starts_with(usage), "`xtask {args:?}`: {stdout}");
        assert!(
            out.stderr.is_empty(),
            "`xtask {args:?}` prints nothing to stderr"
        );
    }
}
