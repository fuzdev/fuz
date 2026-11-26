//! The programs this crate's tests run. `checksum`'s
//! `sidecar_round_trips_through_sha512sum_check` runs a real `sha512sum` and
//! checks nothing where it is absent, so `cargo test` runs on a machine
//! without it — and this test fails there, so a run that skipped that test
//! can't pass unnoticed. `FUZ_TEST_ALLOW_NO_SHA512SUM=1` accepts its absence.

use std::process::{Command, Stdio};

#[test]
fn the_sha512sum_the_sidecar_test_runs_is_installed() {
    let found = Command::new("sha512sum")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    let allowed = std::env::var_os("FUZ_TEST_ALLOW_NO_SHA512SUM").is_some_and(|value| value == "1");
    assert!(
        found || allowed,
        "`sha512sum` is not on PATH, so the sidecar round-trip test that runs it checked nothing \
         — install it (or set FUZ_TEST_ALLOW_NO_SHA512SUM=1)"
    );
}
