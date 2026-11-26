//! The programs this crate's tests run. The release log suites drive a real
//! `git` and check nothing where it is absent (`common::git_available`), so
//! `cargo test` runs on a machine without it — and this test fails there, so
//! a run that skipped those tests can't pass unnoticed.
//! `FUZ_TEST_ALLOW_NO_GIT=1` accepts its absence.

use std::process::{Command, Stdio};

#[test]
fn the_git_the_release_log_tests_run_is_installed() {
    let found = Command::new("git")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    let allowed = std::env::var_os("FUZ_TEST_ALLOW_NO_GIT").is_some_and(|value| value == "1");
    assert!(
        found || allowed,
        "`git` is not on PATH, so the release log tests that run it checked nothing — install it \
         (or set FUZ_TEST_ALLOW_NO_GIT=1)"
    );
}
