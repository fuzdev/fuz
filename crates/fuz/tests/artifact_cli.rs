//! CLI-level integration tests for `fuz artifact {use,prune,verify,list,log}` —
//! the composition the unit/lib suites can't reach: arg parsing → prefix/`-`
//! resolution → switch + history + bin-symlink, the prune keep-N selection, the
//! re-hash integrity check, and the `--json` projections of `list` / `log`.
//!
//! These run the real `fuz` binary (`CARGO_BIN_EXE_fuz`) against a throwaway
//! `~/.fuz` pointed at a tempdir via the `FUZ_HOME` env var — which
//! `fuz_home::get_fuz_home()` honors unconditionally, so no test-only feature is
//! needed here (and none is added to the `fuz` binary's graph). Artifacts are
//! seeded directly with public `fuz_artifact` constructors rather than the heavy
//! `fuz artifact build` (which compiles from source); the one real build runs
//! cargo on a dependency-free one-file binary.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::collections::HashSet;
use std::path::Path;
use std::process::Output;

use fuz_artifact::{ArtifactMeta, History};

mod common;
use common::{fresh_home, seed_artifact as seed, stdout_json};

/// Run the real `fuz` binary with the `artifact` noun prepended and `~/.fuz`
/// redirected at `home`.
fn fuz(home: &Path, args: &[&str]) -> Output {
    let mut full = vec!["artifact"];
    full.extend_from_slice(args);
    common::run(home, &full)
}

/// The `current` symlink target, e.g. `artifacts/v1-…`.
fn current_target(home: &Path) -> String {
    std::fs::read_link(home.join("current"))
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// The on-disk artifact directory names (the `v1-` dirs), ignoring lock files etc.
fn artifact_dirs(home: &Path) -> HashSet<String> {
    std::fs::read_dir(home.join("artifacts"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("v1-"))
        .collect()
}

fn read_history(home: &Path) -> History {
    let contents = std::fs::read_to_string(home.join("state").join("history.json")).unwrap();
    serde_json::from_str(&contents).unwrap()
}

/// Pins that `fuz artifact use` composes the whole switch: it resolves the hash,
/// repoints `current`, sets up `bin/fuz`, and records history (newest-first with
/// the previous-hash link). (The `use -` toggle is covered separately.)
#[test]
fn artifact_use_composes_switch_history_and_symlinks() {
    let home = fresh_home();
    let a = seed(home.path(), 0x11, "2020-01-01T00:00:01Z");
    let b = seed(home.path(), 0x22, "2020-01-01T00:00:02Z");

    let out = fuz(home.path(), &["use", &a.hash]);
    assert!(
        out.status.success(),
        "use A failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        current_target(home.path()),
        format!("artifacts/{}", a.hash),
        "current follows A"
    );

    let out = fuz(home.path(), &["use", &b.hash]);
    assert!(
        out.status.success(),
        "use B failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        current_target(home.path()),
        format!("artifacts/{}", b.hash),
        "current follows B"
    );

    // bin/fuz was set up, pointing through `current`.
    let bin_fuz = home.path().join("bin").join("fuz");
    assert_eq!(
        std::fs::read_link(&bin_fuz).expect("bin/fuz is a symlink"),
        Path::new("../current/fuz"),
        "bin/fuz points through current"
    );

    // History recorded the switch to B newest-first, with A as previous.
    let history = read_history(home.path());
    assert_eq!(
        history.entries[0].hash, b.hash,
        "latest switch (B) is first"
    );
    // Full `v1-<64 hex>`, the same shape as the sibling `hash` field. This
    // pinned the *short* form until the four `record_switch` callers were
    // reconciled — `use` and `build` wrote 8 bare hex, `self upgrade` and
    // `self bootstrap` wrote the full tag, so one field held two shapes and
    // only this half had a test.
    assert_eq!(
        history.entries[0].previous_hash.as_deref(),
        Some(a.hash.as_str()),
        "B records A's full hash as previous"
    );
}

/// Pins `fuz artifact use -` — the `cd -`-style toggle to the previous artifact.
/// A bare `-` can't reach argh, so `main`'s `handle_use_dash` intercept dispatches
/// it; this guards that the documented form actually works end-to-end.
#[test]
fn artifact_use_dash_toggles_to_previous() {
    let home = fresh_home();
    let a = seed(home.path(), 0x71, "2020-01-01T00:00:01Z");
    let b = seed(home.path(), 0x72, "2020-01-01T00:00:02Z");

    assert!(
        fuz(home.path(), &["use", &a.hash]).status.success(),
        "use A"
    );
    assert!(
        fuz(home.path(), &["use", &b.hash]).status.success(),
        "use B"
    );

    let out = fuz(home.path(), &["use", "-"]);
    assert!(
        out.status.success(),
        "use - failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        current_target(home.path()),
        format!("artifacts/{}", a.hash),
        "use - returns to the previous artifact"
    );
}

/// Pins that `fuz artifact use <unknown>` fails (non-zero exit) rather than
/// silently doing nothing.
#[test]
fn artifact_use_unknown_hash_exits_nonzero() {
    let home = fresh_home();
    seed(home.path(), 0x33, "2020-01-01T00:00:01Z");

    let out = fuz(home.path(), &["use", "deadbeefdeadbeef"]);
    assert!(
        !out.status.success(),
        "using an unknown hash must exit non-zero"
    );
}

/// Pins `fuz artifact prune --keep N`: it keeps the N newest plus the current
/// artifact and removes the rest. Fails if a kept artifact is swept or a stale
/// one survives.
#[test]
fn artifact_prune_keeps_recent_and_current() {
    let home = fresh_home();
    // Six artifacts, oldest → newest by explicit created_at.
    let metas: Vec<ArtifactMeta> = (0..6)
        .map(|i| seed(home.path(), 0x40 + i, &format!("2020-01-01T00:00:{i:02}Z")))
        .collect();

    // Make the OLDEST current, so prune must keep it *in addition* to the N newest.
    let out = fuz(home.path(), &["use", &metas[0].hash]);
    assert!(
        out.status.success(),
        "use oldest failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = fuz(home.path(), &["prune", "--keep", "3", "--wetrun"]);
    assert!(
        out.status.success(),
        "prune failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let survivors = artifact_dirs(home.path());
    assert_eq!(survivors.len(), 4, "3 newest + current survive");
    for keep in [&metas[5], &metas[4], &metas[3], &metas[0]] {
        assert!(
            survivors.contains(&keep.hash),
            "{} should survive",
            keep.hash
        );
    }
    for gone in [&metas[2], &metas[1]] {
        assert!(
            !survivors.contains(&gone.hash),
            "{} should be pruned",
            gone.hash
        );
    }
}

/// Pins that a prune without `--wetrun` previews without removing anything,
/// and says how to delete.
#[test]
fn artifact_prune_is_a_dry_run_without_wetrun() {
    const COUNT: u8 = 4;

    let home = fresh_home();
    for i in 0..COUNT {
        seed(home.path(), 0x60 + i, &format!("2020-01-01T00:00:{i:02}Z"));
    }

    let out = fuz(home.path(), &["prune", "--keep", "1"]);
    assert!(
        out.status.success(),
        "dry-run prune failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Would remove 3 artifacts"), "{stdout}");
    assert!(
        stdout.contains("(dry run — pass --wetrun to delete)"),
        "{stdout}"
    );

    assert_eq!(
        artifact_dirs(home.path()).len(),
        usize::from(COUNT),
        "dry-run removes nothing"
    );
}

/// A quiet dry run prints no preview, but still says on stderr that nothing
/// was deleted.
#[test]
fn artifact_prune_quiet_dry_run_still_names_wetrun() {
    let home = fresh_home();
    for i in 0..3u8 {
        seed(home.path(), 0x78 + i, &format!("2020-01-01T00:00:{i:02}Z"));
    }

    let out = fuz(home.path(), &["prune", "--keep", "1", "-q"]);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "(dry run — pass --wetrun to delete)\n"
    );
    assert_eq!(artifact_dirs(home.path()).len(), 3, "nothing removed");
}

/// `prune --dry-run` is a usage error (exit 2) that removes nothing, with a
/// hint naming the dry-run-by-default surface — `--wetrun` alongside it
/// included.
#[test]
fn artifact_prune_refuses_dry_run_with_a_wetrun_hint() {
    let home = fresh_home();
    for i in 0..3u8 {
        seed(home.path(), 0x68 + i, &format!("2020-01-01T00:00:{i:02}Z"));
    }

    for args in [
        &["prune", "--keep", "1", "--dry-run"][..],
        &["prune", "--wetrun", "--dry-run"],
    ] {
        let out = fuz(home.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("--wetrun"), "{args:?}: {stderr}");
        assert_eq!(artifact_dirs(home.path()).len(), 3, "nothing removed");
    }
}

/// `-n` means a count everywhere (`fuz artifact log -n`, `fuzd logs -n`), so
/// prune has no `-n`: `prune -n` is a usage error that removes nothing, never
/// a silent dry run or a count.
#[test]
fn artifact_prune_rejects_n_short() {
    let home = fresh_home();
    for i in 0..3u8 {
        seed(home.path(), 0x70 + i, &format!("2020-01-01T00:00:{i:02}Z"));
    }

    let out = fuz(home.path(), &["prune", "--keep", "1", "--wetrun", "-n"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("Unrecognized argument: -n"), "{stderr}");
    assert_eq!(artifact_dirs(home.path()).len(), 3, "nothing removed");
}

/// `fuz artifact prune` deletes from the store, so it takes the artifact lock
/// like every other mutator: while another process holds it, prune refuses
/// (exit 75, naming the holder) and removes nothing. The preview (no
/// `--wetrun`) deletes nothing and takes no lock.
#[test]
fn artifact_prune_refuses_while_the_artifact_lock_is_held() {
    use fuz_sys::file_lock::{FileLock, LockInfo};
    const COUNT: u8 = 4;

    let home = fresh_home();
    for i in 0..COUNT {
        seed(home.path(), 0x40 + i, &format!("2020-01-01T00:00:{i:02}Z"));
    }
    let lock_path = home.path().join("run").join("artifact.lock");
    let lock = FileLock::acquire(&lock_path, &LockInfo::current()).unwrap();

    let out = fuz(home.path(), &["prune", "--keep", "1", "--wetrun"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(75), "stderr: {stderr}");
    assert!(
        stderr.contains(&format!(
            "artifact operation already in progress (pid {})",
            std::process::id()
        )),
        "stderr: {stderr}"
    );
    assert_eq!(
        artifact_dirs(home.path()).len(),
        usize::from(COUNT),
        "a refused prune removes nothing"
    );

    // The preview mutates nothing, so the held lock does not refuse it.
    let out = fuz(home.path(), &["prune", "--keep", "1"]);
    assert!(
        out.status.success(),
        "dry-run under a held lock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("Would remove 3 artifacts"));

    // Released, the same prune goes through.
    drop(lock);
    let out = fuz(home.path(), &["prune", "--keep", "1", "--wetrun"]);
    assert!(
        out.status.success(),
        "prune after release failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(artifact_dirs(home.path()).len(), 1);
}

/// A prune with no `artifacts/` directory has nothing to delete and creates
/// nothing: it returns before the lock, so a home that does not exist is not
/// minted and one without a store gains no `run/`. An `artifacts/` that is
/// there and empty is the store, and a `--wetrun` prune of it takes the lock.
#[test]
fn artifact_prune_without_a_store_creates_nothing() {
    use fuz_sys::file_lock::{FileLock, LockInfo};

    let root = fresh_home();
    let absent = root.path().join("absent");
    let out = fuz(&absent, &["prune"]);
    assert!(
        out.status.success(),
        "prune of an absent home failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "No artifacts to prune.\n"
    );
    assert!(
        std::fs::symlink_metadata(&absent).is_err(),
        "the home was created"
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);

    // A home with no store in it: nothing is added.
    let home = fresh_home();
    let out = fuz(home.path(), &["prune", "--quiet"]);
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);

    // An empty store is locked like a full one.
    std::fs::create_dir(home.path().join("artifacts")).unwrap();
    let lock_path = home.path().join("run").join("artifact.lock");
    let lock = FileLock::acquire(&lock_path, &LockInfo::current()).unwrap();
    let out = fuz(home.path(), &["prune", "--wetrun"]);
    assert_eq!(
        out.status.code(),
        Some(75),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop(lock);
    let out = fuz(home.path(), &["prune", "--wetrun"]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "No artifacts to prune.\n"
    );
}

/// Only an absent `artifacts/` lets a `--wetrun` prune skip the lock. Anything else there — a link
/// to a directory, a dangling link, a file — is not read as "no store": the
/// prune goes on to the lock, and is refused while it is held.
#[test]
fn artifact_prune_takes_the_lock_when_artifacts_is_not_absent() {
    use fuz_sys::file_lock::{FileLock, LockInfo};

    let elsewhere = fresh_home();
    for what in ["a link to a directory", "a dangling link", "a file"] {
        let home = fresh_home();
        let artifacts = home.path().join("artifacts");
        match what {
            "a link to a directory" => {
                std::os::unix::fs::symlink(elsewhere.path(), &artifacts).unwrap();
            }
            "a dangling link" => std::os::unix::fs::symlink("nowhere", &artifacts).unwrap(),
            _ => std::fs::write(&artifacts, b"").unwrap(),
        }
        let lock_path = home.path().join("run").join("artifact.lock");
        let lock = FileLock::acquire(&lock_path, &LockInfo::current()).unwrap();
        let out = fuz(home.path(), &["prune", "--wetrun"]);
        assert_eq!(
            out.status.code(),
            Some(75),
            "{what}: stdout: {} stderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        drop(lock);
    }
}

/// Pins `fuz artifact verify <hash>`: a seeded artifact whose on-disk `fuz`
/// matches its stored `outputs.fuz` verifies clean (exit 0).
#[test]
fn artifact_verify_passes_for_intact_artifact() {
    let home = fresh_home();
    let a = seed(home.path(), 0x81, "2020-01-01T00:00:01Z");

    let out = fuz(home.path(), &["verify", &a.hash]);
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Pins that `fuz artifact verify` (no hash) defaults to the current artifact —
/// after a `use`, the bare verb re-hashes whatever `current` points at.
#[test]
fn artifact_verify_defaults_to_current() {
    let home = fresh_home();
    let a = seed(home.path(), 0x82, "2020-01-01T00:00:01Z");
    assert!(
        fuz(home.path(), &["use", &a.hash]).status.success(),
        "use A"
    );

    let out = fuz(home.path(), &["verify"]);
    assert!(
        out.status.success(),
        "bare verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Pins the integrity failure path: tampering with the on-disk `fuz` binary
/// after seeding makes the re-hash diverge from the stored `outputs.fuz`, so
/// `verify` must exit non-zero rather than report success.
#[test]
fn artifact_verify_detects_tampered_binary() {
    let home = fresh_home();
    let a = seed(home.path(), 0x83, "2020-01-01T00:00:01Z");

    // Overwrite the binary with different bytes (still ELF + >=1 KiB so it
    // clears the shape guards and fails only on the hash comparison).
    let mut tampered = vec![0x84; 2048];
    tampered[0..4].copy_from_slice(b"\x7fELF");
    std::fs::write(
        home.path().join("artifacts").join(&a.hash).join("fuz"),
        &tampered,
    )
    .unwrap();

    let out = fuz(home.path(), &["verify", &a.hash]);
    assert_eq!(
        out.status.code(),
        Some(65),
        "a tampered artifact must exit with EX_DATAERR (65): {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Pins the `fuz artifact list --json` projection: every seeded artifact appears
/// newest-first, the `current` field + per-entry `is_current` flag track the
/// active artifact, and bootstrap artifacts report `source: "bootstrap"` with
/// their `outputs.fuz` hash.
#[test]
fn artifact_list_json_reports_artifacts_and_current() {
    let home = fresh_home();
    let a = seed(home.path(), 0x91, "2020-01-01T00:00:01Z");
    let b = seed(home.path(), 0x92, "2020-01-01T00:00:02Z");
    assert!(
        fuz(home.path(), &["use", &b.hash]).status.success(),
        "use B"
    );

    let json = stdout_json(&fuz(home.path(), &["list", "--json"]));

    assert_eq!(json["current"], b.hash, "current points at B");
    let artifacts = json["artifacts"].as_array().expect("artifacts array");
    assert_eq!(artifacts.len(), 2, "both seeded artifacts listed");
    // Newest-first ordering: B (created later) before A.
    assert_eq!(artifacts[0]["hash"], b.hash, "newest (B) first");
    assert_eq!(artifacts[1]["hash"], a.hash, "older (A) second");
    assert_eq!(artifacts[0]["is_current"], true, "B is current");
    assert_eq!(artifacts[1]["is_current"], false, "A is not current");
    assert_eq!(
        artifacts[0]["source"], "bootstrap",
        "seeded via new_bootstrap"
    );
    assert!(
        artifacts[0]["outputs"]["fuz"].is_string(),
        "outputs.fuz hash present"
    );
}

/// **The prefix `log` prints is one `use` accepts.**
///
/// `log` sliced `SHORT_HASH_LEN` bytes off the stored `v1-<64 hex>`, which
/// takes the three-byte version tag *with* the hash — printing `v1-` plus five
/// hex digits. `use` strips the tag and then requires eight, so every prefix
/// `log` advertised was refused as `PrefixTooShort`, while its sibling `list`
/// (via `ArtifactMeta::display_hash`) printed usable ones.
///
/// Pins the round trip rather than the string: parse a prefix out of `log`'s
/// own output and feed it back to `use`.
#[test]
fn artifact_log_prints_a_prefix_that_use_accepts() {
    let home = fresh_home();
    let a = seed(home.path(), 0xB1, "2020-01-01T00:00:01Z");
    let b = seed(home.path(), 0xB2, "2020-01-01T00:00:02Z");
    assert!(fuz(home.path(), &["use", &a.hash]).status.success());
    assert!(fuz(home.path(), &["use", &b.hash]).status.success());

    let out = fuz(home.path(), &["log"]);
    assert!(out.status.success(), "log");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    // The rendered prefix for A, lifted out of the human output.
    let printed = text
        .split_whitespace()
        .find(|w| w.starts_with("v1-") && w.contains(&a.hash[3..11]))
        .unwrap_or_else(|| panic!("log did not print a prefix for A:\n{text}"))
        .to_owned();

    let back = fuz(home.path(), &["use", &printed]);
    assert!(
        back.status.success(),
        "`use {printed}` (as printed by `log`) was refused: {}",
        String::from_utf8_lossy(&back.stderr)
    );
}

/// Pins `fuz artifact log --json`: after two switches the log carries both
/// entries newest-first with the previous-hash link, and `-n` truncates.
#[test]
fn artifact_log_json_tracks_switches_and_count() {
    let home = fresh_home();
    let a = seed(home.path(), 0xA1, "2020-01-01T00:00:01Z");
    let b = seed(home.path(), 0xA2, "2020-01-01T00:00:02Z");
    assert!(
        fuz(home.path(), &["use", &a.hash]).status.success(),
        "use A"
    );
    assert!(
        fuz(home.path(), &["use", &b.hash]).status.success(),
        "use B"
    );

    let json = stdout_json(&fuz(home.path(), &["log", "--json"]));
    let entries = json["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 2, "both switches logged");
    assert_eq!(entries[0]["hash"], b.hash, "latest switch (B) first");
    // Full, matching the sibling `hash` field — see the note in
    // `artifact_use_composes_switch_history_and_symlinks`.
    assert_eq!(
        entries[0]["previous_hash"],
        a.hash.as_str(),
        "B records A's full hash as previous"
    );

    // `-n 1` truncates to the most recent entry only.
    let json = stdout_json(&fuz(home.path(), &["log", "-n", "1", "--json"]));
    let entries = json["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1, "-n 1 keeps only the newest entry");
    assert_eq!(entries[0]["hash"], b.hash, "newest entry is B");
}

/// Pins that `fuz artifact log` on a fresh home (no switches yet) is not an
/// error — an empty history reads back as empty and exits 0.
#[test]
fn artifact_log_empty_history_succeeds() {
    let home = fresh_home();
    let out = fuz(home.path(), &["log"]);
    assert!(
        out.status.success(),
        "log on empty history failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Pins the `--keep 0` boundary: every non-current artifact is pruned, but the
/// current one still survives (the current-guard runs before the keep count).
#[test]
fn artifact_prune_keep_zero_keeps_only_current() {
    let home = fresh_home();
    let metas: Vec<ArtifactMeta> = (0..3)
        .map(|i| seed(home.path(), 0xC0 + i, &format!("2020-01-01T00:00:0{i}Z")))
        .collect();
    assert!(
        fuz(home.path(), &["use", &metas[1].hash]).status.success(),
        "use middle artifact"
    );

    let out = fuz(home.path(), &["prune", "--keep", "0", "--wetrun"]);
    assert!(
        out.status.success(),
        "prune --keep 0 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let survivors = artifact_dirs(home.path());
    assert_eq!(
        survivors.len(),
        1,
        "only the current artifact survives keep 0"
    );
    assert!(
        survivors.contains(&metas[1].hash),
        "the current artifact survived"
    );
}

/// Pins idempotence: `use <current-hash>` short-circuits with "Already using",
/// exits 0, and does NOT record another switch in history.
#[test]
fn artifact_use_already_current_is_noop() {
    let home = fresh_home();
    let a = seed(home.path(), 0xD0, "2020-01-01T00:00:01Z");
    assert!(
        fuz(home.path(), &["use", &a.hash]).status.success(),
        "first use"
    );

    let out = fuz(home.path(), &["use", &a.hash]);
    assert!(
        out.status.success(),
        "re-using the current artifact must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Already using"),
        "re-using current reports it"
    );
    assert_eq!(
        read_history(home.path()).entries.len(),
        1,
        "a no-op use does not append a switch"
    );
}

/// Pins the `use -` negative: with no switches recorded there is no previous
/// artifact, so the toggle exits non-zero rather than silently doing nothing.
#[test]
fn artifact_use_dash_with_no_history_exits_nonzero() {
    let home = fresh_home();
    seed(home.path(), 0xE0, "2020-01-01T00:00:01Z");

    let out = fuz(home.path(), &["use", "-"]);
    assert!(
        !out.status.success(),
        "use - with empty history must exit non-zero"
    );
}

/// A minimal source repo `fuz artifact build` accepts up to the build step: a
/// git repo with one commit, a `Cargo.toml` carrying a version, and
/// `crates/fuz/Cargo.toml`. The workspace has no members, so a `cargo build -p
/// fuz` in it fails at once without compiling or fetching anything.
fn fake_source_repo(dir: &Path) {
    std::fs::create_dir_all(dir.join("crates/fuz")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("crates/fuz/Cargo.toml"), "").unwrap();
    git_commit_all(dir);
}

/// `git init` + commit everything in `dir`, with the user's and system git
/// config ignored.
fn git_commit_all(dir: &Path) {
    for args in [
        &["init", "-q"][..],
        &["add", "-A"],
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "init",
        ],
    ] {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }
}

/// Pins that `fuz artifact build` reads `current` before it builds: with
/// `current` naming an artifact whose directory is a symlink, the command fails
/// with exit 65 before any `cargo build` runs (whose failure in the memberless
/// fake repo would read "build failed"), and changes nothing.
#[test]
fn build_fails_on_an_unreadable_current_before_building() {
    let home = fresh_home();
    let a = seed(home.path(), 0x92, "2026-01-01T00:00:00Z");
    std::os::unix::fs::symlink(
        Path::new("artifacts").join(&a.hash),
        home.path().join("current"),
    )
    .unwrap();
    let slot = home.path().join("artifacts").join(&a.hash);
    std::fs::rename(&slot, home.path().join("decoy")).unwrap();
    std::os::unix::fs::symlink(home.path().join("decoy"), &slot).unwrap();
    let repo = tempfile::tempdir().unwrap();
    fake_source_repo(repo.path());

    let out = common::run_with_env(
        home.path(),
        &["artifact", "build", "--quiet"],
        &[("FUZ_DEV_REPO", repo.path().to_str().unwrap())],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(65), "{stderr}");
    assert!(stderr.contains("not a directory"), "{stderr}");
    assert!(!stderr.contains("build failed"), "no build ran: {stderr}");
    assert!(!repo.path().join("target").exists(), "cargo never ran");
    assert!(slot.symlink_metadata().unwrap().file_type().is_symlink());
}

/// `fuz artifact build` does not refuse a set `CARGO_BUILD_TARGET` up front:
/// the binary's path comes from cargo, and a build for another target is
/// caught by the platform check on what cargo built. A dry run builds nothing,
/// so it goes through.
#[test]
fn artifact_build_dry_run_accepts_a_cargo_build_target() {
    let home = fresh_home();
    let repo = tempfile::tempdir().unwrap();
    fake_source_repo(repo.path());
    let out = common::run_with_env(
        home.path(),
        &["artifact", "build", "--dry-run"],
        &[
            ("CARGO_BUILD_TARGET", "x86_64-unknown-linux-musl"),
            ("FUZ_DEV_REPO", repo.path().to_str().unwrap()),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Would build fuz 0.1.0"),
        "{stderr}"
    );
    assert!(!home.path().join("artifacts").exists());
}

/// A source repo whose workspace really builds: one member, a dependency-free
/// `fuz` binary, so a release build is quick and needs no network. The
/// workspace sets `strip` so the binary has no paths that differ per checkout.
fn buildable_source_repo(dir: &Path) {
    std::fs::create_dir_all(dir.join("crates/fuz/src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/fuz\"]\nresolver = \"2\"\n\n\
         [workspace.package]\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("crates/fuz/Cargo.toml"),
        "[package]\nname = \"fuz\"\nversion.workspace = true\nedition = \"2024\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("crates/fuz/src/main.rs"),
        "fn main() { println!(\"fresh\"); }\n",
    )
    .unwrap();
    git_commit_all(dir);
}

/// The artifact is the binary cargo built, wherever it built it: with
/// `CARGO_TARGET_DIR` elsewhere and a stale (but valid, host) `fuz` left at
/// `target/release/fuz`, the stored binary is the fresh one, not the decoy.
/// Runs a real (tiny, dependency-free) `cargo build --release`.
#[test]
fn artifact_build_packages_the_binary_cargo_reports() {
    let home = fresh_home();
    let repo = tempfile::tempdir().unwrap();
    buildable_source_repo(repo.path());
    let decoy = fuz_artifact::platform::test_stubs::host(b"stale decoy");
    std::fs::create_dir_all(repo.path().join("target/release")).unwrap();
    std::fs::write(repo.path().join("target/release/fuz"), &decoy).unwrap();
    let target_dir = tempfile::tempdir().unwrap();

    let out = common::run_with_env(
        home.path(),
        &["artifact", "build", "--no-install", "--quiet"],
        &[
            ("FUZ_DEV_REPO", repo.path().to_str().unwrap()),
            ("CARGO_TARGET_DIR", target_dir.path().to_str().unwrap()),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let built = std::fs::read(target_dir.path().join("release/fuz")).unwrap();
    let dirs: Vec<String> = artifact_dirs(home.path()).into_iter().collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    let stored = std::fs::read(home.path().join("artifacts").join(&dirs[0]).join("fuz")).unwrap();
    assert_ne!(stored, decoy, "the stale target/release/fuz was packaged");
    assert_eq!(stored, built, "the stored binary is the one cargo built");
}

/// Whether this host is `x86_64` glibc with the `x86_64-unknown-linux-musl`
/// standard library installed: what the cross-build test needs to build.
fn musl_target_installed() -> bool {
    if !(cfg!(target_arch = "x86_64") && cfg!(target_env = "gnu")) {
        return false;
    }
    std::process::Command::new("rustc")
        .args([
            "--print",
            "target-libdir",
            "--target",
            "x86_64-unknown-linux-musl",
        ])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| {
            let dir = String::from_utf8(out.stdout).ok()?;
            std::fs::read_dir(dir.trim()).ok()?.next()
        })
        .is_some()
}

/// A `build.target` in the repo's cargo config — which no environment check
/// could see — builds a musl `fuz` on a glibc host: refused naming both
/// targets, and nothing is stored. Skipped where the musl target is not
/// installed.
#[test]
fn artifact_build_refuses_a_binary_built_for_another_target() {
    if !musl_target_installed() {
        eprintln!("skipped: x86_64-unknown-linux-musl is not installed");
        return;
    }
    let home = fresh_home();
    let repo = tempfile::tempdir().unwrap();
    buildable_source_repo(repo.path());
    std::fs::create_dir_all(repo.path().join(".cargo")).unwrap();
    std::fs::write(
        repo.path().join(".cargo/config.toml"),
        "[build]\ntarget = \"x86_64-unknown-linux-musl\"\n",
    )
    .unwrap();
    let target_dir = tempfile::tempdir().unwrap();

    let out = common::run_with_env(
        home.path(),
        &["artifact", "build", "--no-install", "--quiet"],
        &[
            ("FUZ_DEV_REPO", repo.path().to_str().unwrap()),
            ("CARGO_TARGET_DIR", target_dir.path().to_str().unwrap()),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(
            "error: cargo built fuz as a statically linked x86_64 Linux executable \
             (a musl build.target / CARGO_BUILD_TARGET, or `+crt-static` in RUSTFLAGS?), but \
             this host is x86_64-unknown-linux-gnu"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains("hint: unset a musl CARGO_BUILD_TARGET"),
        "{stderr}"
    );
    assert!(artifact_dirs_or_none(home.path()).is_empty());
}

/// [`artifact_dirs`], or none when `artifacts/` was never created.
fn artifact_dirs_or_none(home: &Path) -> HashSet<String> {
    if home.join("artifacts").exists() {
        artifact_dirs(home)
    } else {
        HashSet::new()
    }
}
