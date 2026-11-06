//! The real `fuzd` binary on a `FUZ_HOME` so long its socket path cannot be
//! bound: it exits 1 naming the length limit, prints a hint to shorten
//! `FUZ_HOME`, and creates nothing under the home.

use std::process::Command;

const FUZD: &str = env!("CARGO_BIN_EXE_fuzd");

#[test]
fn an_overlong_fuz_home_is_refused_with_a_hint() {
    let dir = tempfile::tempdir().expect("tempdir");
    // `<home>/run/socket` past the 107-byte limit whatever the tempdir's length.
    let home = dir.path().join("h".repeat(120));

    // A refusal returns at once; nothing here can bind, so no daemon is left.
    let output = Command::new(FUZD)
        .env("FUZ_HOME", &home)
        .output()
        .expect("run fuzd");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("107-byte limit"), "{stderr}");
    assert!(
        stderr
            .lines()
            .any(|l| l.starts_with("hint: ") && l.contains("FUZ_HOME")),
        "{stderr}"
    );
    assert!(!home.exists(), "{} was created", home.display());
}
