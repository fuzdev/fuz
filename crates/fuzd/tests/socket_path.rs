//! The real `fuzd` binary on a `FUZ_HOME` so long its socket path cannot be
//! bound, with no daemon recorded there: bare `fuzd` and every lifecycle
//! subcommand that looks for the daemon exit 2 naming the length limit, print
//! a hint to shorten `FUZ_HOME`, and create nothing under the home — `status`
//! reports the refused home, never "stopped", and `start` spawns nothing. A
//! recorded daemon in such a home is `already_running.rs`'s.

use std::process::Command;

const FUZD: &str = env!("CARGO_BIN_EXE_fuzd");

#[test]
fn an_overlong_fuz_home_is_refused_with_a_hint() {
    let dir = tempfile::tempdir().expect("tempdir");
    // `<home>/run/socket` past the 107-byte limit whatever the tempdir's length.
    let home = dir.path().join("h".repeat(120));

    // A refusal returns at once; nothing here can bind, so no daemon is left.
    for args in [
        &[][..],
        &["start"],
        &["status"],
        &["status", "--json"],
        &["stop"],
        &["restart"],
    ] {
        let output = Command::new(FUZD)
            .args(args)
            .env("FUZ_HOME", &home)
            .output()
            .expect("run fuzd");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let context = format!("`fuzd {args:?}`");

        assert_eq!(output.status.code(), Some(2), "{context}: {stderr}");
        assert!(stderr.contains("107-byte limit"), "{context}: {stderr}");
        assert!(
            stderr
                .lines()
                .any(|l| l.starts_with("hint: ") && l.contains("FUZ_HOME")),
            "{context}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{context}: nothing on stdout");
        assert!(!home.exists(), "{context}: {} was created", home.display());
    }
}
