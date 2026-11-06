//! The real `fuzd` binary's lifecycle subcommands on a home the home layer
//! refuses — a relative `FUZ_HOME`, or an unusable `HOME` with `FUZ_HOME`
//! unset: they exit 1 with the error and the home layer's hint, the lines bare
//! `fuzd` prints for the same home, and create nothing.
//!
//! Each case runs with the cwd at a tempdir, where a relative home would
//! resolve if it were ever read as a path, and only subcommands that spawn no
//! daemon. The `HOME` cases run `logs --no-follow` alone, which only reads: a
//! regression to a lookup that takes an empty `HOME` as unset would fall back
//! to the password database's home, the developer's own.

// Test harness: the clippy `allow-expect-in-tests` config reaches only `#[test]`
// fns, not the shared helper below, which panics on a setup failure by design.
#![allow(clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

const FUZD: &str = env!("CARGO_BIN_EXE_fuzd");

/// Spawn `fuzd` in `cwd` with `HOME` and `FUZ_HOME` exactly as given (`None`
/// removes `FUZ_HOME`).
fn run_in(cwd: &Path, home: &str, fuz_home: Option<&str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(FUZD);
    cmd.args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("FUZ_HOME");
    if let Some(fuz_home) = fuz_home {
        cmd.env("FUZ_HOME", fuz_home);
    }
    cmd.output().expect("spawn fuzd")
}

/// Assert the refusal: exit 1, nothing on stdout, and stderr exactly the
/// error line followed by the hint line.
#[track_caller]
fn assert_refused(out: &Output, error: &str, hint: &str, what: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{what}: {stderr}");
    assert_eq!(stderr, format!("error: {error}\nhint: {hint}\n"), "{what}");
    assert!(out.stdout.is_empty(), "{what}: nothing on stdout");
}

fn assert_empty(dir: &Path) {
    let entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read the cwd")
        .map(|entry| entry.expect("a dir entry").file_name())
        .collect();
    assert!(entries.is_empty(), "the cwd gained {entries:?}");
}

/// A relative `FUZ_HOME` is refused by each lifecycle subcommand that spawns
/// nothing, with the hint to make it absolute.
#[test]
fn a_relative_fuz_home_is_refused_with_the_hint() {
    let cwd = tempfile::tempdir().expect("tempdir");
    let home = cwd.path().to_str().expect("a utf-8 tempdir");
    for args in [
        &["status"][..],
        &["status", "--json"],
        &["stop"],
        &["logs", "--no-follow"],
    ] {
        let out = run_in(cwd.path(), home, Some("rel"), args);
        assert_refused(
            &out,
            "FUZ_HOME must be an absolute path, got rel",
            "set FUZ_HOME to an absolute path, or unset it to use ~/.fuz",
            &format!("`fuzd {args:?}`"),
        );
    }
    assert_empty(cwd.path());
}

/// With `FUZ_HOME` unset, an empty or relative `HOME` is refused with the
/// hint naming both variables — not read as a `.fuz` under the cwd.
#[test]
fn an_unusable_home_is_refused_with_the_hint() {
    for (home, reason) in [
        ("", "the home directory (HOME) is empty"),
        ("h", "the home directory (HOME) is not an absolute path: h"),
    ] {
        let cwd = tempfile::tempdir().expect("tempdir");
        let out = run_in(cwd.path(), home, None, &["logs", "--no-follow"]);
        assert_refused(
            &out,
            &format!("cannot resolve ~/.fuz: {reason}"),
            "set HOME to your home directory's absolute path, or FUZ_HOME to an absolute path",
            &format!("HOME={home:?}"),
        );
        assert_empty(cwd.path());
    }
}
