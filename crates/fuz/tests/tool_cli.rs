//! CLI-level integration tests for `fuz tool {verify,list}` plus the offline
//! negatives of `install` / `upgrade`. They run the real `fuz` binary
//! (`CARGO_BIN_EXE_fuz`) against a throwaway `~/.fuz` pointed at a tempdir via
//! `FUZ_HOME` (honored unconditionally, so no test-only feature reaches the
//! `fuz` graph).
//!
//! Installed tools are hand-seeded with explicit-dir public constructors
//! (`ToolMeta::new` + `write` + a `current` symlink) rather than
//! `install_local_tool`, which resolves `~/.fuz` against *this* process's home
//! (unset here) instead of the child's `FUZ_HOME`.
//!
//! `tool install` / `tool upgrade` *happy paths* pull a signed artifact from a
//! forge, so their end-to-end coverage lives at the library level in
//! `fuz_sign/tests/signed_trust.rs`. Here we cover only the home-seam negatives
//! those verbs decide before touching storage.

mod common;
use common::{fresh_home, run as fuz, seed_tool};

/// Pins `fuz tool list` on a fresh home: exit 0 with the empty-state message.
#[test]
fn tool_list_empty_reports_none() {
    let home = fresh_home();
    let out = fuz(home.path(), &["tool", "list"]);
    assert!(
        out.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no tools installed"),
        "empty list reports the no-tools message"
    );
}

/// Pins that `fuz tool list` reports every installed tool, sorted by name.
#[test]
fn tool_list_reports_installed_tools_sorted() {
    let home = fresh_home();
    // Seed out of order; the listing must come back name-sorted (fuzd < zap).
    seed_tool(home.path(), "zap", "0.3.0", "zap", 0x22);
    seed_tool(home.path(), "fuzd", "0.1.0", "fuzd", 0x11);

    let out = fuz(home.path(), &["tool", "list"]);
    assert!(
        out.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let fuzd_at = stdout.find("fuzd").expect("fuzd listed");
    let zap_at = stdout.find("zap").expect("zap listed");
    assert!(fuzd_at < zap_at, "tools listed name-sorted: {stdout}");
    assert!(
        stdout.contains("0.1.0") && stdout.contains("0.3.0"),
        "versions shown"
    );
    // the hash column is `v1-` + the short hash, the `fuz artifact list` form
    for line in stdout.lines() {
        let hash = line.rsplit("  ").next().expect("hash column");
        assert!(
            hash.strip_prefix("v1-")
                .is_some_and(|h| h.len() == 8 && h.bytes().all(|b| b.is_ascii_hexdigit())),
            "display hash on {line:?}"
        );
    }
}

/// Pins `fuz tool verify <name>`: an intact install re-hashes clean (exit 0,
/// `ok` in the output).
#[test]
fn tool_verify_passes_for_intact_install() {
    let home = fresh_home();
    seed_tool(home.path(), "fuzd", "0.1.0", "fuzd", 0x31);

    let out = fuz(home.path(), &["tool", "verify", "fuzd"]);
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("ok"),
        "verify reports ok"
    );
}

/// Pins the integrity failure path: tampering with the installed binary after
/// seeding makes the re-hash diverge from the stored `ToolMeta`, so `tool
/// verify` must exit non-zero.
#[test]
fn tool_verify_detects_tampered_binary() {
    let home = fresh_home();
    let meta = seed_tool(home.path(), "fuzd", "0.1.0", "fuzd", 0x41);

    let mut tampered = vec![0x42; 2048];
    tampered[0..4].copy_from_slice(b"\x7fELF");
    std::fs::write(
        home.path()
            .join("tools")
            .join("fuzd")
            .join(&meta.content_hash)
            .join("fuzd"),
        &tampered,
    )
    .unwrap();

    let out = fuz(home.path(), &["tool", "verify", "fuzd"]);
    assert!(
        !out.status.success(),
        "verify of a tampered tool must exit non-zero"
    );
    // The same code its `fuz artifact verify` sibling gives for the same
    // `BinaryIntegrityFailed` (pinned in `artifact_cli.rs`). This asserted only
    // "non-zero" while the tool path flattened to 1, so the two nouns
    // disagreed on the signal an agent branches on.
    assert_eq!(
        out.status.code(),
        Some(65),
        "a tampered tool must exit with EX_DATAERR (65): {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Pins that verifying a tool that isn't installed exits non-zero
/// (`ToolNotInstalled`) rather than reporting ok.
#[test]
fn tool_verify_uninstalled_exits_nonzero() {
    let home = fresh_home();
    let out = fuz(home.path(), &["tool", "verify", "fuzd"]);
    assert!(
        !out.status.success(),
        "verifying an uninstalled tool must exit non-zero"
    );
}

/// Pins the `tool upgrade` precondition: upgrading a tool that isn't installed
/// fails fast (`ToolNotInstalled`) *before* touching storage — so it exits
/// non-zero even with a valid local `--storage` that resolves fine.
#[test]
fn tool_upgrade_uninstalled_exits_nonzero_before_storage() {
    let home = fresh_home();
    // A real, resolvable local storage dir so the failure is the not-installed
    // precondition, not a storage-resolution error.
    let storage = tempfile::tempdir().unwrap();

    let out = fuz(
        home.path(),
        &[
            "tool",
            "upgrade",
            "fuzd",
            "--storage",
            storage.path().to_str().unwrap(),
        ],
    );
    assert!(
        !out.status.success(),
        "upgrading an uninstalled tool must exit non-zero"
    );
}

/// Pins the allowlist gate on `tool install`: a non-first-party name is rejected
/// (`ToolNotAllowed`) by `fetch_tool_manifest` before any download, so this
/// exits non-zero offline with a resolvable local `--storage`.
#[test]
fn tool_install_rejects_non_allowlisted_name() {
    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();

    let out = fuz(
        home.path(),
        &[
            "tool",
            "install",
            "notarealtool",
            "--storage",
            storage.path().to_str().unwrap(),
        ],
    );
    assert!(
        !out.status.success(),
        "installing a non-allowlisted tool must exit non-zero"
    );
}

/// Pins that `mg` is outside the allowlist: `tool install mg` is refused with the
/// allowlist error, not attempted against the store.
#[test]
fn tool_install_refuses_mg() {
    let home = fresh_home();
    let storage = tempfile::tempdir().unwrap();

    let out = fuz(
        home.path(),
        &[
            "tool",
            "install",
            "mg",
            "--storage",
            storage.path().to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "installing `mg` must exit non-zero");
    assert!(
        stderr.contains("tool not in first-party allowlist: mg"),
        "{stderr}"
    );
}

/// Pins that `fuz tool upgrade` treats an install that is there but unreadable
/// — here `current` names a slot that is a symlink — as installed, not as "not
/// installed": with and without `--force` it goes on to `install_tool` (whose
/// refuse-unless-forced policy is pinned in `fuz_sign/tests/signed_trust.rs`),
/// which reaches the empty store here.
#[test]
fn tool_upgrade_takes_an_unreadable_install_to_the_installer() {
    let home = fresh_home();
    let meta = seed_tool(home.path(), "fuzd", "0.1.0", "fuzd", 0x51);
    let slot = home.path().join("tools/fuzd").join(&meta.content_hash);
    let decoy = home.path().join("decoy");
    std::fs::rename(&slot, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &slot).unwrap();
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();

    for args in [
        &["tool", "upgrade", "fuzd", "--storage", storage][..],
        &["tool", "upgrade", "fuzd", "--storage", storage, "--force"],
    ] {
        let out = fuz(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(!stderr.contains("not installed"), "{args:?}: {stderr}");
        assert!(stderr.contains("is published for"), "{args:?}: {stderr}");
    }
}

/// Pins that a tool `current` that is a real directory is refused by
/// `fuz tool upgrade` and `install` — `--force` included, before any request —
/// with exit 65, and left in place.
#[test]
fn tool_install_and_upgrade_refuse_a_current_directory() {
    let home = fresh_home();
    std::fs::create_dir_all(home.path().join("tools/fuzd/current")).unwrap();
    let storage = tempfile::tempdir().unwrap();
    let storage = storage.path().to_str().unwrap();

    for verb in ["install", "upgrade"] {
        for force in [false, true] {
            let mut args = vec!["tool", verb, "fuzd", "--storage", storage];
            if force {
                args.push("--force");
            }
            let out = fuz(home.path(), &args);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(65), "{args:?}: {stderr}");
            assert!(stderr.contains("not a symlink"), "{args:?}: {stderr}");
            assert!(!stderr.contains("is published for"), "{args:?}: {stderr}");
        }
    }
    assert!(home.path().join("tools/fuzd/current").is_dir());
}
