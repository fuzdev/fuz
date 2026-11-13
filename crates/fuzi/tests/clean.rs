//! `fuzi clean`'s kept-tree contract through the real binary: the restore
//! commands it prints are run through `sh` exactly as a user would paste them,
//! and running every one restores one tree without nesting another inside it.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]
// The process spawns below (the built `fuzi` binary, and `sh`) each carry a
// scoped `#[expect]` of the exec-free disallow in this crate's `clippy.toml`:
// it guards fuzi's own source, not the tests that drive it from outside — and
// scoped, so the rest of the file keeps the copied `home_dir` disallow.

use std::fs;
use std::path::Path;
use std::process::{ExitStatus, Output};

#[expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "the exec-free disallow guards fuzi's own source; this harness drives the built binary from outside"
)]
fn run_fuzi_clean(dir: &Path, json: bool) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_fuzi"));
    cmd.arg("clean").current_dir(dir);
    if json {
        cmd.arg("--json");
    }
    cmd.output().expect("run fuzi")
}

/// Run `command` through `sh -c` in `dir`, as a user pasting it would.
#[expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "the exec-free disallow guards fuzi's own source; this harness drives the built binary from outside"
)]
fn run_sh(command: &str, dir: &Path) -> ExitStatus {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(dir)
        .status()
        .expect("run sh")
}

/// Two parked trees with no `node_modules`: both are kept, the human output
/// says to restore only one and that nothing was swept, and pasting *every*
/// printed command restores the first while the second does nothing.
#[test]
fn kept_trees_restore_one_without_nesting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path();
    for name in [".fuzi-old-a", ".fuzi-old-b"] {
        fs::create_dir(p.join(name)).expect("mkdir");
        fs::write(p.join(name).join("sentinel"), name).expect("write");
    }

    let human = run_fuzi_clean(p, false);
    assert_eq!(human.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(
        stderr.contains("2 displaced trees kept — restore only one of them"),
        "{stderr}"
    );
    assert_eq!(
        String::from_utf8_lossy(&human.stdout).trim_end(),
        "fuzi clean: nothing swept (kept 2 displaced tree(s), see above)"
    );

    let json = run_fuzi_clean(p, true);
    assert_eq!(json.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
    let commands: Vec<String> = report["skipped"]
        .as_array()
        .expect("skipped array")
        .iter()
        .map(|kept| {
            kept["restore_command"]
                .as_str()
                .expect("command")
                .to_owned()
        })
        .collect();
    assert_eq!(commands.len(), 2);
    for command in &commands {
        assert!(run_sh(command, p).success(), "{command}");
    }
    assert_eq!(
        fs::read(p.join("node_modules/sentinel")).expect("restored"),
        b".fuzi-old-a"
    );
    assert!(
        !p.join("node_modules/.fuzi-old-b").exists(),
        "the second command nested its tree inside the first"
    );
    assert!(p.join(".fuzi-old-b").is_dir(), "the second tree stays put");
}
