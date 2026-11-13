//! Integration coverage for the local content-addressed artifact-store ops that
//! resolve paths through `fuz_home::get_artifacts_dir()` — list / switch /
//! current / cleanup / cache-lookup / history / lookup-errors / store-entry shape, plus
//! the composed `switch_to_artifact` the activating commands share.
//!
//! Companion to `tests/round_trip.rs` (create → find → verify): both drive the
//! real store against an overridden `~/.fuz` via the `fuz_home/test_home_override`
//! dev-dep feature, which resolver-2 keeps out of every shipping binary. The
//! shared harness (`fresh_home`, `fake_fuz`, the serial guard) lives in
//! `tests/common/mod.rs`.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::{fake_fuz, fresh_home, host_triple};
use fuz_artifact::{
    ArtifactError, ArtifactInputs, BuildSource, CONTENT_HASH_PREFIX, History, SHORT_HASH_LEN,
    SwitchOptions, acquire_artifact_lock, cleanup_incomplete, create_artifact, find_artifact,
    find_by_inputs, get_artifact_dir, get_current_artifact, get_history_path, list_artifacts,
    record_switch, setup_bin_symlinks, switch_current, switch_to_artifact,
};
use fuz_home::{
    clear_fuz_home_override_for_testing, ensure_fuz_home, get_bin_dir,
    set_fuz_home_override_for_testing,
};
use fuz_sys::SECURE_DIR_MODE;

/// Mint a committed artifact from distinct bytes via the cheap `Bootstrap` path.
fn bootstrap(seed: u8) -> fuz_artifact::ArtifactMeta {
    create_artifact(
        "0.1.0",
        BuildSource::Bootstrap {
            fuz_bytes: &fake_fuz(seed),
        },
    )
    .expect("bootstrap create_artifact must succeed")
}

/// Pins the mode of every `~/.fuz` directory the store creates on demand.
///
/// `ensure_fuz_home` creates `artifacts/`, `bin/`, and `state/` at
/// [`SECURE_DIR_MODE`], but a flow that never routes through it — `fuz artifact
/// use` on a home whose `bin/` does not exist yet — reaches them through the
/// store's own creates instead. The two must agree, or one directory has two
/// modes depending on which command got there first, and the on-demand one is a
/// **world-writable `~/.fuz/bin`** under a permissive umask: the tree
/// `docs/security-model.md` names as the one an attacker swaps `bin/fuz` into.
///
/// The pin is exact equality, not a world-writable-bit check. An inherited mode
/// differs from 0700 under every common umask (0775 at `002`, 0755 at `022`,
/// 0777 at `000`), so equality catches the regression whoever launched cargo —
/// where a `mode & 0o002 == 0` assertion would pass at `umask 022` and only
/// fail in the container that made it dangerous.
#[test]
fn on_demand_home_dirs_are_created_at_0700() {
    let (home, _guard) = fresh_home();
    // Deliberately no `ensure_fuz_home()` — that is the path this test is *not*
    // covering. Each directory below is created by the op that first needs it.

    let a = bootstrap(0x5A); // creates `artifacts/`
    switch_current(&a.hash).unwrap();
    setup_bin_symlinks(&["fuz"]).unwrap(); // creates `bin/`
    record_switch(&a.hash, "0.1.0", None).unwrap(); // creates `state/`

    for dir in ["artifacts", "bin", "state"] {
        let path = home.path().join(dir);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            SECURE_DIR_MODE,
            "~/.fuz/{dir} must be created at 0700, not at the runner's umask"
        );
    }

    clear_fuz_home_override_for_testing();
}

/// Pins the mode of `~/.fuz` **itself** when the artifact lock is what creates
/// it.
///
/// `fuz artifact build` and `fuz artifact use` never call `ensure_fuz_home`;
/// everything they do before taking the lock only reads. So on a machine where
/// fuz has not run yet, `acquire_artifact_lock` is the first thing that creates
/// anything — and its `~/.fuz/run/artifact.lock` path makes it create
/// **`~/.fuz` and `~/.fuz/run/` both**, since the create is recursive.
///
/// Left to the umask that lands `~/.fuz` at 0775 (`umask 002`) or 0777
/// (`umask 000`). Write permission on `~/.fuz` is all an attacker needs: rename
/// `bin/` aside, substitute a directory holding their own `fuz`, and the next
/// shell resolves it off `PATH` — the hijack `docs/security-model.md` § Local
/// `~/.fuz` Integrity is about, unreachable by that section's guard, which
/// inspects `~/.fuz` *before* the create and checks only the other-write bit.
///
/// The pin is not universal: 0700 is the tightest mode a create can land, so at
/// `umask 077` an unmoded create coincides with it and this assertion is
/// vacuous. It discriminates under every umask that can produce the exposure it
/// guards — 0775 at `002`, 0755 at `022`, 0777 at `000`.
#[test]
fn artifact_lock_creates_the_home_and_run_dir_at_0700() {
    let (home, _guard) = fresh_home();
    // Point the home at a path that does not exist yet — `fresh_home` hands
    // back a directory that does, which is the state *after* a first run.
    let uncreated = home.path().join("uncreated");
    set_fuz_home_override_for_testing(&uncreated);

    let lock = acquire_artifact_lock().expect("the lock creates the home it needs");

    for dir in [uncreated.clone(), uncreated.join("run")] {
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            SECURE_DIR_MODE,
            "{dir:?} must be created at 0700, not at the umask of whoever ran fuz"
        );
    }

    drop(lock);
    clear_fuz_home_override_for_testing();
}

/// Pins `list_artifacts`: an untouched home lists nothing, and after creating
/// three distinct-byte artifacts all three come back (no dedup, no drops). Fails
/// if any created artifact is missing from the listing.
#[test]
fn list_artifacts_reports_each_created_artifact() {
    let (_home, _guard) = fresh_home();

    // Empty home → empty list (the artifacts dir doesn't even exist yet).
    assert!(
        list_artifacts().unwrap().is_empty(),
        "a fresh home lists no artifacts"
    );

    let a = bootstrap(0x01);
    let b = bootstrap(0x02);
    let c = bootstrap(0x03);

    let listed = list_artifacts().unwrap();
    assert_eq!(listed.len(), 3, "all three distinct artifacts are listed");

    let hashes: Vec<&str> = listed.iter().map(|m| m.hash.as_str()).collect();
    for created in [&a, &b, &c] {
        assert!(
            hashes.contains(&created.hash.as_str()),
            "{} must be listed",
            created.hash
        );
    }

    clear_fuz_home_override_for_testing();
}

/// Pins the current pointer: switching to A then B makes `get_current_artifact`
/// follow each switch, and switching to a hash with no artifact dir is a
/// `NotFound` error that leaves the pointer where it was. Fails if the pointer
/// doesn't track the switch or a failed switch clobbers it.
#[test]
fn switch_current_moves_and_reads_back_the_pointer() {
    let (_home, _guard) = fresh_home();

    // Nothing selected on a fresh home.
    assert!(
        get_current_artifact().unwrap().is_none(),
        "nothing is current before any switch"
    );

    let a = bootstrap(0xA0);
    let b = bootstrap(0xB0);

    switch_current(&a.hash).unwrap();
    assert_eq!(
        get_current_artifact().unwrap().unwrap().hash,
        a.hash,
        "current follows the switch to A"
    );

    switch_current(&b.hash).unwrap();
    assert_eq!(
        get_current_artifact().unwrap().unwrap().hash,
        b.hash,
        "current follows the switch to B"
    );

    // A switch to a well-formed but nonexistent hash fails and must not move the
    // pointer off B.
    let missing = format!("{CONTENT_HASH_PREFIX}{}", "0".repeat(64));
    let err = switch_current(&missing).expect_err("switching to an unknown hash must fail");
    assert!(
        matches!(err, ArtifactError::NotFound(_)),
        "expected NotFound, got {err:?}"
    );
    assert_eq!(
        get_current_artifact().unwrap().unwrap().hash,
        b.hash,
        "a failed switch leaves B current"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins `cleanup_incomplete`: `.building-*` and `.bootstrapping-*` temp dirs are
/// swept (and counted) while a committed `v1-` artifact is left intact. Fails if
/// a real artifact is swept or a temp dir survives.
#[test]
fn cleanup_incomplete_sweeps_temp_dirs_only() {
    let (_home, _guard) = fresh_home();

    // A committed artifact creates the artifacts dir and is the thing cleanup
    // must NOT touch.
    let keep = bootstrap(0xCC);
    let artifacts_dir = get_artifact_dir(&keep.hash)
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    // Hand-create the two incomplete-build temp-dir shapes (each holding a file
    // so removal has to recurse) plus an unrelated hidden dir matching neither
    // prefix, which cleanup must leave alone.
    let building = artifacts_dir.join(".building-0123abcd");
    let bootstrapping = artifacts_dir.join(".bootstrapping-4567ef01");
    let unrelated = artifacts_dir.join(".keep-this");
    for dir in [&building, &bootstrapping, &unrelated] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("partial.bin"), b"incomplete").unwrap();
    }

    // Hidden dirs never count as artifacts, so the committed one is the lone
    // listing even before cleanup runs.
    assert_eq!(
        list_artifacts().unwrap().len(),
        1,
        "list ignores hidden/incomplete dirs"
    );

    let removed = cleanup_incomplete().unwrap();
    assert_eq!(removed, 2, "only the two incomplete-build shapes are swept");
    assert!(!building.exists(), ".building-* dir is removed");
    assert!(!bootstrapping.exists(), ".bootstrapping-* dir is removed");
    assert!(unrelated.exists(), "an unrelated hidden dir is left alone");

    // The committed artifact survives untouched.
    assert!(
        get_artifact_dir(&keep.hash)
            .unwrap()
            .join("meta.json")
            .is_file(),
        "the committed artifact survives cleanup"
    );
    assert_eq!(
        list_artifacts().unwrap().len(),
        1,
        "only the committed artifact remains"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins the input-hash cache lookup: a `Local` artifact is found by its recorded
/// `input_hash`, and an unrecorded input hash is a clean cache miss (`Ok(None)`,
/// not an error).
#[test]
fn find_by_inputs_matches_the_recorded_input_hash() {
    let (_home, _guard) = fresh_home();

    // The `Local` path records `ArtifactInputs` as-is; the artifact's own hash
    // still derives from the binary bytes, not from `input_hash`.
    let release = tempfile::tempdir().unwrap();
    std::fs::write(release.path().join("fuz"), fake_fuz(0x44)).unwrap();
    let input_hash = "a".repeat(64);
    let inputs = ArtifactInputs {
        input_hash: input_hash.clone(),
        git_commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        git_diff_hash: None,
        rustc_version: "rustc 1.75.0".to_string(),
        target: host_triple(),
    };
    let meta = create_artifact(
        "0.1.0",
        BuildSource::Local {
            fuz_binary: &release.path().join("fuz"),
            inputs: &inputs,
        },
    )
    .expect("create_artifact(Local) must succeed");

    // A Bootstrap artifact carries `inputs: None`; create one so the lookup has
    // to skip a None-inputs entry rather than match it or choke on it.
    let boot = bootstrap(0x55);
    assert_eq!(
        list_artifacts().unwrap().len(),
        2,
        "both artifacts are stored"
    );

    let hit = find_by_inputs(&input_hash)
        .unwrap()
        .expect("a recorded input hash is a cache hit");
    assert_eq!(hit.hash, meta.hash, "the cache hit is the Local artifact");
    assert_ne!(
        hit.hash, boot.hash,
        "the None-inputs Bootstrap artifact is not matched"
    );
    assert_eq!(
        hit.inputs.as_ref().unwrap().input_hash,
        input_hash,
        "the recorded input hash matches"
    );

    // An input hash nothing was built from misses cleanly.
    assert!(
        find_by_inputs(&"b".repeat(64)).unwrap().is_none(),
        "an unrecorded input hash is a cache miss, not an error"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins `record_switch` + `History` + `get_history_path`: recorded switches land
/// newest-first with the previous-hash links intact, written under the
/// overridden home's state dir. Fails if ordering or the back-link is wrong.
#[test]
fn history_records_switches_newest_first() {
    let (home, _guard) = fresh_home();

    // No history file until the first switch is recorded.
    let history_path = get_history_path().unwrap();
    assert!(
        history_path.starts_with(home.path()),
        "history lives under the overridden home"
    );
    assert!(
        !history_path.exists(),
        "no history file before the first record_switch"
    );

    let a = bootstrap(0x0A);
    let b = bootstrap(0x0B);

    record_switch(&a.hash, "0.1.0", None).unwrap();
    record_switch(&b.hash, "0.1.0", Some(&a.hash)).unwrap();
    assert!(
        history_path.exists(),
        "record_switch writes the history file"
    );

    let history = History::read().unwrap();
    assert_eq!(history.entries.len(), 2, "both switches are recorded");
    // Newest first: B is entry 0, A is entry 1.
    assert_eq!(
        history.entries[0].hash, b.hash,
        "the latest switch is first"
    );
    assert_eq!(
        history.entries[0].previous_hash.as_deref(),
        Some(a.hash.as_str()),
        "B records A as its previous hash"
    );
    assert_eq!(
        history.entries[1].hash, a.hash,
        "the earlier switch is second"
    );
    assert_eq!(
        history.previous(),
        Some(a.hash.as_str()),
        "previous() points at the one before current"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins the history cap: recording past the limit keeps the newest entries and
/// drops the oldest. `MAX_HISTORY_ENTRIES` is `pub(crate)` (unreachable from an
/// integration test), so `CAP` mirrors its value in `src/lib.rs`.
#[test]
fn history_caps_at_max_entries() {
    // `MAX_HISTORY_ENTRIES` is pub(crate), so mirror its value here.
    const CAP: usize = 100;

    let (_home, _guard) = fresh_home();
    let overflow = CAP + 5;

    // `record_switch` doesn't require the hashes to name real artifacts, so
    // synthetic v1- hashes exercise the cap cheaply.
    for i in 0..overflow {
        record_switch(&format!("{CONTENT_HASH_PREFIX}{i:064x}"), "0.1.0", None).unwrap();
    }

    let history = History::read().unwrap();
    assert_eq!(history.entries.len(), CAP, "history is trimmed to the cap");
    assert_eq!(
        history.entries[0].hash,
        format!("{CONTENT_HASH_PREFIX}{:064x}", overflow - 1),
        "the newest recorded switch is first"
    );
    assert_eq!(
        history.entries[CAP - 1].hash,
        format!("{CONTENT_HASH_PREFIX}{:064x}", overflow - CAP),
        "the oldest survivor is the (overflow - cap)th switch; older ones are dropped"
    );

    clear_fuz_home_override_for_testing();
}

/// A no-op switch (recording the artifact that's already newest) is not stored
/// as a positional duplicate — otherwise `previous()` (backing `artifact use -`)
/// would toggle to the same artifact. Consecutive same-hash records collapse; a
/// genuine switch to a different artifact still lands.
#[test]
fn history_skips_consecutive_duplicate_switch() {
    let (_home, _guard) = fresh_home();

    let a = bootstrap(0xA1);
    let b = bootstrap(0xB2);

    record_switch(&a.hash, "0.1.0", None).unwrap();
    record_switch(&a.hash, "0.1.0", None).unwrap(); // no-op re-record
    record_switch(&a.hash, "0.1.0", None).unwrap(); // still a no-op

    let history = History::read().unwrap();
    assert_eq!(
        history.entries.len(),
        1,
        "consecutive same-hash records collapse to one entry"
    );
    assert!(history.previous().is_none(), "no positional previous yet");

    // A genuine switch to a different artifact records; re-recording it is again
    // a no-op, so `previous()` toggles back to A rather than a duplicate B.
    record_switch(&b.hash, "0.1.0", Some(&a.hash)).unwrap();
    record_switch(&b.hash, "0.1.0", Some(&a.hash)).unwrap();

    let history = History::read().unwrap();
    assert_eq!(
        history.entries.len(),
        2,
        "the genuine switch to B is recorded exactly once"
    );
    assert_eq!(
        history.previous(),
        Some(a.hash.as_str()),
        "use - toggles back to A, not to a duplicate B"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins the composed locked switch — the one path `fuz artifact build`,
/// `fuz artifact use`, `fuz self upgrade`, and `cargo xtask install` all take.
/// A single call must leave `current`, `bin/fuz`, and `history.json` mutually
/// consistent, and a tampered artifact must be refused before any of the three
/// move. Fails if the switch activates bytes that no longer match their
/// meta.json, or activates without leaving a rollback target for
/// `fuz artifact use -`.
#[test]
fn switch_to_artifact_activates_verifies_and_logs() {
    let (_home, _guard) = fresh_home();
    // Set the home up the way the commands that create it do. The lock would
    // mint `run/` on its own at the same 0700 (pinned by
    // `artifact_lock_creates_the_home_and_run_dir_at_0700` above), but this
    // test also needs `artifacts/` and `bin/`, and `ensure_fuz_home` is the
    // call every one of these callers makes for real.
    ensure_fuz_home().unwrap();

    let a = bootstrap(0xC1);
    let b = bootstrap(0xC2);

    // `_lock` is a compile-time witness, so acquire it exactly as every real
    // caller does and hold it across the whole flow (flock is not recursive).
    let lock = acquire_artifact_lock().unwrap();

    switch_to_artifact(
        SwitchOptions {
            hash: &a.hash,
            version: &a.version,
            previous_hash: None,
            quiet: true,
        },
        &lock,
    )
    .unwrap();

    assert_eq!(
        get_current_artifact().unwrap().map(|m| m.hash),
        Some(a.hash.clone()),
        "the switch moves `current`"
    );
    let bin_fuz = get_bin_dir().unwrap().join("fuz");
    assert_eq!(
        std::fs::read(&bin_fuz).unwrap(),
        fake_fuz(0xC1),
        "bin/fuz resolves through `current` to the activated artifact's bytes"
    );
    assert_eq!(
        History::read().unwrap().entries.len(),
        1,
        "the switch is logged"
    );

    // A second switch leaves A reachable as the rollback target.
    switch_to_artifact(
        SwitchOptions {
            hash: &b.hash,
            version: &b.version,
            previous_hash: Some(&a.hash),
            quiet: true,
        },
        &lock,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(&bin_fuz).unwrap(),
        fake_fuz(0xC2),
        "bin/fuz follows the second switch"
    );
    assert_eq!(
        History::read().unwrap().previous(),
        Some(a.hash.as_str()),
        "the previous artifact stays reachable for `fuz artifact use -`"
    );
    // `previous()` is positional (`entries[1]`), so it would pass whatever
    // `SwitchOptions::previous_hash` carried. Pin the argument itself — the
    // field `fuz artifact log` renders as "from ..." on the newest entry.
    assert_eq!(
        History::read().unwrap().entries[0].previous_hash.as_deref(),
        Some(a.hash.as_str()),
        "the switch records the `previous_hash` it was handed"
    );

    // Tamper with A's stored binary: the verify step must refuse, leaving
    // `current` and the log on B.
    std::fs::write(
        get_artifact_dir(&a.hash).unwrap().join("fuz"),
        fake_fuz(0xFF),
    )
    .unwrap();
    let err = switch_to_artifact(
        SwitchOptions {
            hash: &a.hash,
            version: &a.version,
            previous_hash: Some(&b.hash),
            quiet: true,
        },
        &lock,
    )
    .unwrap_err();
    assert!(
        matches!(err, ArtifactError::BinaryIntegrityFailed { .. }),
        "a tampered artifact is refused, got {err:?}"
    );
    assert_eq!(
        get_current_artifact().unwrap().map(|m| m.hash),
        Some(b.hash),
        "the refused switch leaves `current` untouched"
    );
    assert_eq!(
        History::read().unwrap().entries.len(),
        2,
        "the refused switch is not logged"
    );

    drop(lock);
    clear_fuz_home_override_for_testing();
}

/// Pins `find_artifact`'s prefix resolution (the core lookup `round_trip.rs`
/// only exercises by full hash): an artifact resolves from an 8-char hash
/// prefix in both the bare and `v1-`-prefixed forms — the `v1-` strip plus the
/// `starts_with` match — returning the same meta as the full hash.
#[test]
fn find_artifact_resolves_by_hash_prefix() {
    let (_home, _guard) = fresh_home();

    let meta = bootstrap(0x9F);
    // `meta.hash` is `v1-<64 hex>`; slice out the first 8 hex chars after `v1-`.
    let start = CONTENT_HASH_PREFIX.len();
    let bare_prefix = &meta.hash[start..start + SHORT_HASH_LEN];
    let prefixed = &meta.hash[..start + SHORT_HASH_LEN];

    assert_eq!(
        find_artifact(bare_prefix).unwrap().hash,
        meta.hash,
        "an 8-char bare prefix resolves to the artifact"
    );
    assert_eq!(
        find_artifact(prefixed).unwrap().hash,
        meta.hash,
        "the same prefix carrying v1- resolves identically"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins `find_artifact` lookup errors: a prefix shorter than `SHORT_HASH_LEN` is
/// `PrefixTooShort` (carrying the measured length), and a well-formed prefix
/// matching nothing is `NotFound`.
#[test]
fn find_artifact_rejects_short_and_missing_prefixes() {
    let (_home, _guard) = fresh_home();

    // Shorter than SHORT_HASH_LEN once the optional v1- prefix is stripped.
    match find_artifact("abc").expect_err("a 3-char prefix is too short") {
        ArtifactError::PrefixTooShort { given, minimum } => {
            assert_eq!(given, 3, "reports the normalized prefix length");
            assert_eq!(minimum, SHORT_HASH_LEN, "reports the minimum prefix length");
        }
        other => panic!("expected PrefixTooShort, got {other:?}"),
    }

    // Long enough to pass the length gate but matching nothing.
    let missing = find_artifact("deadbeef").expect_err("an unmatched prefix is not found");
    assert!(
        matches!(missing, ArtifactError::NotFound(_)),
        "expected NotFound, got {missing:?}"
    );

    // The AmbiguousPrefix arm is pinned separately in
    // `find_artifact_reports_ambiguous_prefix`.

    clear_fuz_home_override_for_testing();
}

/// Pins `find_artifact`'s ambiguous-match arm: a prefix matching more than one
/// artifact dir is `AmbiguousPrefix`. Forced by fabricating a sibling dir that
/// shares the first `SHORT_HASH_LEN` hex chars — `find_artifact` counts dir-name
/// matches before reading any meta, so no real blake3 collision is needed.
#[test]
fn find_artifact_reports_ambiguous_prefix() {
    let (_home, _guard) = fresh_home();

    let real = bootstrap(0xD1);
    let real_dir = get_artifact_dir(&real.hash).unwrap();
    let artifacts_dir = real_dir.parent().unwrap();

    // Sibling sharing the first SHORT_HASH_LEN hex chars after `v1-`, padded out
    // to a full-length hash name with a distinct suffix.
    let shared = &real.hash[..CONTENT_HASH_PREFIX.len() + SHORT_HASH_LEN];
    let sibling = artifacts_dir.join(format!("{shared}{}", "f".repeat(64 - SHORT_HASH_LEN)));
    std::fs::create_dir_all(&sibling).unwrap();
    std::fs::copy(real_dir.join("fuz"), sibling.join("fuz")).unwrap();
    std::fs::copy(real_dir.join("meta.json"), sibling.join("meta.json")).unwrap();

    let prefix = &real.hash[CONTENT_HASH_PREFIX.len()..CONTENT_HASH_PREFIX.len() + SHORT_HASH_LEN];
    match find_artifact(prefix).expect_err("a prefix matching two dirs is ambiguous") {
        ArtifactError::AmbiguousPrefix { candidates, .. } => {
            assert_eq!(candidates.len(), 2, "both colliding dirs are reported");
        }
        other => panic!("expected AmbiguousPrefix, got {other:?}"),
    }

    clear_fuz_home_override_for_testing();
}

/// Pins `list_artifacts`'s graceful skip: a `v1-` dir with a corrupt `meta.json`
/// is skipped (with a stderr warning) while valid artifacts still list. Fails if
/// one bad entry aborts the whole scan.
#[test]
fn list_artifacts_skips_corrupt_entries() {
    let (_home, _guard) = fresh_home();

    let good = bootstrap(0xE1);
    let artifacts_dir = get_artifact_dir(&good.hash)
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    // A `v1-` dir whose meta.json is invalid JSON (so it passes the name filter
    // but fails to parse).
    let corrupt = artifacts_dir.join(format!("{CONTENT_HASH_PREFIX}{}", "c".repeat(64)));
    std::fs::create_dir_all(&corrupt).unwrap();
    std::fs::write(corrupt.join("meta.json"), b"{ not valid json").unwrap();

    let listed = list_artifacts().unwrap();
    assert_eq!(
        listed.len(),
        1,
        "the corrupt entry is skipped, the valid one remains"
    );
    assert_eq!(
        listed[0].hash, good.hash,
        "the surviving listing is the valid artifact"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins `find_artifact`'s error propagation: a corrupt `meta.json` on the ONE
/// artifact the user named must surface as its read/parse error, never degrade
/// to the skip-with-warning path `list_artifacts` / `find_by_inputs` use — the
/// invariant that keeps `find_artifact` off `read_artifact_meta`.
#[test]
fn find_artifact_propagates_a_corrupt_named_artifact() {
    let (_home, _guard) = fresh_home();

    let good = bootstrap(0xE2);
    let artifacts_dir = get_artifact_dir(&good.hash)
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let corrupt = artifacts_dir.join(format!("{CONTENT_HASH_PREFIX}{}", "c".repeat(64)));
    std::fs::create_dir_all(&corrupt).unwrap();
    std::fs::write(corrupt.join("meta.json"), b"{ not valid json").unwrap();

    let err = find_artifact(&"c".repeat(8)).expect_err("a corrupt named artifact must error");
    assert!(
        !matches!(err, ArtifactError::NotFound(_)),
        "the parse failure must propagate, not mask as NotFound: {err:?}"
    );

    clear_fuz_home_override_for_testing();
}

/// Move a created artifact out of the store and leave a symlink to it at its
/// `v1-<hash>` slot, so the slot verifies if read through. Returns the decoy
/// the link points at.
fn replace_with_link(home: &Path, hash: &str) -> std::path::PathBuf {
    let slot = get_artifact_dir(hash).unwrap();
    let decoy = home.join(format!("decoy-{hash}"));
    std::fs::rename(&slot, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &slot).unwrap();
    decoy
}

/// Pins that switching refuses a symlink at `artifacts/v1-<hash>` — live (aimed at
/// a valid artifact, so it verifies if read through) or dangling — and leaves
/// it in place: a switch has nothing to rebuild the artifact from, and pointing
/// `current` at the link would make every later read follow it. Fails if
/// `switch_to_artifact` / `switch_current` verify through the link, unlink it,
/// or read a dangling one as a missing artifact.
#[test]
fn switch_refuses_a_symlink_at_the_artifact_dir() {
    let (home, _guard) = fresh_home();
    ensure_fuz_home().unwrap();

    let a = bootstrap(0xD1);
    let b = bootstrap(0xD2);
    let lock = acquire_artifact_lock().unwrap();
    switch_to_artifact(
        SwitchOptions {
            hash: &a.hash,
            version: &a.version,
            previous_hash: None,
            quiet: true,
        },
        &lock,
    )
    .unwrap();

    let decoy = replace_with_link(home.path(), &b.hash);
    let slot = get_artifact_dir(&b.hash).unwrap();
    let switch_to_b = || {
        switch_to_artifact(
            SwitchOptions {
                hash: &b.hash,
                version: &b.version,
                previous_hash: Some(&a.hash),
                quiet: true,
            },
            &lock,
        )
    };

    let err = switch_to_b().expect_err("a symlinked artifact must be refused");
    assert!(
        matches!(
            &err,
            ArtifactError::StoreEntryNotDir { path, kind: fuz_sys::fs::NonDirKind::Symlink }
                if *path == slot
        ),
        "got {err:?}"
    );
    let err = switch_current(&b.hash).expect_err("switch_current refuses it too");
    assert!(
        matches!(err, ArtifactError::StoreEntryNotDir { .. }),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read_link(&slot).unwrap(),
        decoy,
        "the refused link is left in place"
    );
    assert_eq!(std::fs::read(decoy.join("fuz")).unwrap(), fake_fuz(0xD2));
    assert_eq!(
        get_current_artifact().unwrap().map(|m| m.hash),
        Some(a.hash.clone()),
        "the refused switch leaves `current` on A"
    );
    assert_eq!(History::read().unwrap().entries.len(), 1, "nothing logged");

    // A dangling link is the same refusal, not a "not found".
    std::fs::remove_file(&slot).unwrap();
    std::os::unix::fs::symlink(home.path().join("nowhere"), &slot).unwrap();
    let err = switch_to_b().expect_err("a dangling link must be refused");
    assert!(
        matches!(err, ArtifactError::StoreEntryNotDir { .. }),
        "got {err:?}"
    );
    assert!(slot.symlink_metadata().unwrap().file_type().is_symlink());

    drop(lock);
    clear_fuz_home_override_for_testing();
}

/// Pins that the store scans never take a symlink at `v1-<hash>` for an
/// artifact: `list_artifacts` leaves it out, and `find_by_inputs` does not
/// report it as a build cache hit — a hit would go on to a switch that refuses
/// the link, so `fuz artifact build` / `cargo xtask install` would strand
/// instead of rebuilding (which unlinks the entry). Fails if either scan follows
/// the link.
#[test]
fn store_scans_skip_a_symlink_at_the_artifact_dir() {
    let (home, _guard) = fresh_home();

    let release = tempfile::tempdir().unwrap();
    std::fs::write(release.path().join("fuz"), fake_fuz(0xD3)).unwrap();
    let input_hash = "d".repeat(64);
    let inputs = ArtifactInputs {
        input_hash: input_hash.clone(),
        git_commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
        git_diff_hash: None,
        rustc_version: "rustc 1.75.0".to_string(),
        target: host_triple(),
    };
    let meta = create_artifact(
        "0.1.0",
        BuildSource::Local {
            fuz_binary: &release.path().join("fuz"),
            inputs: &inputs,
        },
    )
    .unwrap();
    assert_eq!(list_artifacts().unwrap().len(), 1, "precondition");
    assert!(
        find_by_inputs(&input_hash).unwrap().is_some(),
        "precondition"
    );

    replace_with_link(home.path(), &meta.hash);
    assert!(
        list_artifacts().unwrap().is_empty(),
        "a symlinked entry is not listed"
    );
    assert!(
        find_by_inputs(&input_hash).unwrap().is_none(),
        "a symlinked entry is not a cache hit"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins that the readers that resolve one named artifact — `get_current_artifact`
/// (what `current` names) and `find_artifact` (a hash the user typed) — refuse a
/// symlink at `artifacts/v1-<hash>` instead of reading its `meta.json` through it,
/// and leave it in place. A dangling link there is the same refusal, not a
/// dangling `current`. Fails if either reader follows the link.
#[test]
fn named_lookups_refuse_a_symlink_at_the_artifact_dir() {
    let (home, _guard) = fresh_home();

    let a = bootstrap(0xD4);
    switch_current(&a.hash).unwrap();
    let decoy = replace_with_link(home.path(), &a.hash);
    let slot = get_artifact_dir(&a.hash).unwrap();

    let err = get_current_artifact().expect_err("current names a symlinked artifact");
    assert!(
        matches!(&err, ArtifactError::StoreEntryNotDir { path, .. } if *path == slot),
        "got {err:?}"
    );
    let err = find_artifact(&a.hash).expect_err("the named artifact is a symlink");
    assert!(
        matches!(err, ArtifactError::StoreEntryNotDir { .. }),
        "got {err:?}"
    );
    assert_eq!(std::fs::read_link(&slot).unwrap(), decoy, "left in place");

    std::fs::remove_dir_all(&decoy).unwrap();
    let err = get_current_artifact().expect_err("a dangling link is refused too");
    assert!(
        matches!(err, ArtifactError::StoreEntryNotDir { .. }),
        "got {err:?}"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins that the self `current` is only followed into `artifacts/`: the
/// relative `artifacts/v1-<hash>` fuz writes and its absolute spelling resolve, a
/// link anywhere else — even at a valid artifact copy — is refused as
/// `OutsideStore` instead of read through, and a `current` that is a real
/// directory is refused as `NotASymlink` and left in place by `switch_current`,
/// whose rename could not replace it.
#[test]
fn current_is_only_followed_into_the_artifact_store() {
    let (home, _guard) = fresh_home();
    let a = bootstrap(0xD5);
    let current = home.path().join("current");
    let slot = get_artifact_dir(&a.hash).unwrap();

    // The absolute spelling of the entry fuz would write.
    std::os::unix::fs::symlink(&slot, &current).unwrap();
    assert_eq!(get_current_artifact().unwrap().unwrap().hash, a.hash);

    // A valid copy outside the store.
    let outside = home.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    for file in ["fuz", "meta.json"] {
        std::fs::copy(slot.join(file), outside.join(file)).unwrap();
    }
    std::fs::remove_file(&current).unwrap();
    std::os::unix::fs::symlink(&outside, &current).unwrap();
    let err = get_current_artifact().expect_err("a current outside the store is refused");
    assert!(
        matches!(
            &err,
            ArtifactError::CurrentNotStoreLink {
                problem: fuz_artifact::CurrentLinkProblem::OutsideStore { target },
                ..
            } if *target == outside
        ),
        "got {err:?}"
    );

    // A `..` that leaves and re-enters lexically is still outside.
    std::fs::remove_file(&current).unwrap();
    std::os::unix::fs::symlink(Path::new("artifacts/../outside"), &current).unwrap();
    assert!(matches!(
        get_current_artifact().unwrap_err(),
        ArtifactError::CurrentNotStoreLink { .. }
    ));

    // A real directory at `current`.
    std::fs::remove_file(&current).unwrap();
    std::fs::create_dir(&current).unwrap();
    assert!(matches!(
        get_current_artifact().unwrap_err(),
        ArtifactError::CurrentNotStoreLink {
            problem: fuz_artifact::CurrentLinkProblem::NotASymlink,
            ..
        }
    ));
    let err = switch_current(&a.hash).expect_err("a current directory can't be swapped");
    assert!(
        matches!(err, ArtifactError::CurrentNotStoreLink { .. }),
        "refused, not EISDIR: {err:?}"
    );
    assert!(current.is_dir(), "left in place");

    clear_fuz_home_override_for_testing();
}

/// Pins that an artifact hash is only ever a name inside `artifacts/`:
/// `get_artifact_dir` and `switch_current` refuse a hash that is not one plain
/// path component before any filesystem access, so nothing outside the store
/// is classified, linked, or read.
#[test]
fn artifact_paths_refuse_a_hash_that_is_not_one_component() {
    let (home, _guard) = fresh_home();
    std::fs::create_dir_all(home.path().join("artifacts")).unwrap();
    std::fs::create_dir(home.path().join("victim")).unwrap();

    for hash in ["../victim", "..", "", "v1-a/", "a/b"] {
        assert!(
            matches!(
                get_artifact_dir(hash),
                Err(ArtifactError::InvalidStoreName { .. })
            ),
            "{hash:?}"
        );
        assert!(
            matches!(
                switch_current(hash),
                Err(ArtifactError::InvalidStoreName { .. })
            ),
            "{hash:?}"
        );
    }
    assert!(
        home.path().join("current").symlink_metadata().is_err(),
        "no current was written"
    );

    clear_fuz_home_override_for_testing();
}
