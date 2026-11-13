//! The world-writable `~/.fuz` refusal on the **repeat** write paths.
//!
//! `ensure_fuz_home` applies the guard when it creates the home (`fuz self
//! bootstrap`, `fuzd start`, `cargo xtask install`), but the paths that later
//! write a fresh binary into an existing home resolve their target dirs
//! directly and never call it. Four of them call
//! `check_fuz_home_not_world_writable` themselves; the three that live in this
//! crate are pinned here — `fuz self upgrade` (`fetch_latest` /
//! `fetch_version`) and `fuz tool install` / `upgrade` (`install_tool`) — along
//! with the read-only `--check` companions (`fetch_latest_manifest` /
//! `fetch_tool_manifest`), which still don't. The fourth is `fuz_artifact`'s
//! `install_local_tool` (the no-forge path behind `cargo xtask install`, which
//! resolves `get_tool_dir` directly the same way); it is pinned in that crate's
//! `tests/tool_install.rs`.
//!
//! The home is redirected through the `fuz_home/test_home_override` dev-dep seam
//! (edition 2024 + `unsafe_code = "forbid"` rule out `std::env::set_var`).
//!
//! **What these pin, exactly.** The storage is an empty `FileStorage`, so a
//! refusal necessarily precedes any network/storage work — and the error *kind*
//! is the pin: `InsecureHome` rather than the `Storage` error an unguarded path
//! would reach. Their `assert_home_untouched` calls are cheap sanity checks, not
//! proof, since with empty storage these flows abort before any home write
//! whether or not the guard is there. The genuine "a real, otherwise-viable
//! install lands nothing" pins live elsewhere: `fuz_sign`'s `signed_trust`
//! suite (`install_tool_refuses_world_writable_home_and_installs_when_fixed`),
//! which has a published signed release to install, and `fuz_artifact`'s
//! `install_local_tool_refuses_world_writable_home`, whose local install needs
//! no storage at all and would otherwise have fully succeeded.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use fuz_home::{FuzHomeError, set_fuz_home_override_for_testing};
use fuz_release::{
    FetchOptions, ReleaseError, ToolInstallOptions, fetch_latest, fetch_latest_manifest,
    fetch_tool_manifest, fetch_version, install_tool,
};
use fuz_storage::FileStorage;

/// Serializes the whole file. The home override is a process global and cargo
/// runs tests on parallel threads. A tokio mutex (not std) so it can be held
/// across `.await` without tripping `await_holding_lock` and without poisoning
/// when an assertion panics.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Lock the serial guard and point `~/.fuz` at a fresh temp home chmod'd to
/// `mode`. The `TempDir` must outlive the test body; the override is left for
/// the next test to overwrite.
async fn home_at_mode(mode: u32) -> (tempfile::TempDir, tokio::sync::MutexGuard<'static, ()>) {
    let guard = SERIAL.lock().await;
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(mode)).unwrap();
    set_fuz_home_override_for_testing(home.path());
    (home, guard)
}

/// An empty release store — a refusal must precede any download, so nothing
/// needs to be published into it.
fn empty_storage() -> (tempfile::TempDir, FileStorage) {
    let dir = tempfile::tempdir().unwrap();
    let storage = FileStorage::new(dir.path()).unwrap();
    (dir, storage)
}

/// Assert `err` is the world-writable refusal, reporting the offending mode.
#[track_caller]
fn assert_refused_world_writable(err: &ReleaseError, expected_mode: u32) {
    assert!(
        matches!(
            err,
            ReleaseError::FuzHome(FuzHomeError::InsecureHome { mode, .. }) if *mode == expected_mode
        ),
        "expected InsecureHome (mode {expected_mode:o}), got {err:?}"
    );
    // The refusal message stays actionable — octal mode + the chmod hint, the
    // same text the bootstrap path prints.
    let rendered = err.to_string();
    assert!(
        rendered.contains(&format!("{expected_mode:04o}")) && rendered.contains("chmod 700"),
        "refusal must carry the octal mode + chmod hint: {rendered}"
    );
}

/// Sanity check that the home is still empty. Weak on its own — with empty
/// storage these flows write nothing regardless — so it backs up the error-kind
/// assertion rather than standing in for it.
#[track_caller]
fn assert_home_untouched(home: &Path) {
    let entries: Vec<_> = std::fs::read_dir(home)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        entries.is_empty(),
        "a refused write path must leave the home empty, found {entries:?}"
    );
}

/// `fuz tool install` / `upgrade` into a world-writable home is refused. The pin
/// is the error kind: with empty storage an unguarded path reaches the manifest
/// fetch and fails in `Storage`, so `InsecureHome` says the guard ran first.
#[tokio::test]
async fn install_tool_refuses_world_writable_home() {
    let (home, _guard) = home_at_mode(0o777).await;
    let (_store, storage) = empty_storage();

    let err = install_tool(&storage, "fuzd", &ToolInstallOptions::default())
        .await
        .expect_err("a world-writable home must refuse the tool install");

    assert_refused_world_writable(&err, 0o777);
    assert_home_untouched(home.path());
}

/// `fuz self upgrade` into a world-writable home is refused — on both public
/// entry points, since `fetch_version` is callable without `fetch_latest`. Same
/// pin as above: `InsecureHome`, not the `Storage` error the empty store would
/// otherwise produce, so the guard precedes the network work.
#[tokio::test]
async fn self_upgrade_refuses_world_writable_home() {
    let (home, _guard) = home_at_mode(0o707).await;
    let (_store, storage) = empty_storage();
    let options = FetchOptions::default();

    let err = fetch_latest(&storage, &options)
        .await
        .expect_err("a world-writable home must refuse the self upgrade");
    assert_refused_world_writable(&err, 0o707);

    let err = fetch_version(&storage, "0.1.0", &options)
        .await
        .expect_err("fetch_version is its own entry point and must refuse too");
    assert_refused_world_writable(&err, 0o707);

    assert_home_untouched(home.path());
}

/// Negative control: the guard is conditional on the mode, not a blanket
/// refusal. On a `0700` home both write paths run past it and fail later, at
/// the store, resolving a release that was never published.
#[tokio::test]
async fn secure_home_passes_the_guard() {
    let (_home, _guard) = home_at_mode(0o700).await;
    let (_store, storage) = empty_storage();

    for err in [
        install_tool(&storage, "fuzd", &ToolInstallOptions::default())
            .await
            .expect_err("empty storage has no release to install"),
        fetch_latest(&storage, &FetchOptions::default())
            .await
            .expect_err("empty storage has no release to fetch"),
    ] {
        assert!(
            matches!(err, ReleaseError::NoReleaseForTarget { .. }),
            "a 0700 home must reach storage, got {err:?}"
        );
    }
}

/// The read-only `--check` companions keep their contract: they write nothing,
/// so a world-writable home must not turn their verdict into a refusal. Both
/// fail at the store (no release published for this target), never with
/// `InsecureHome`.
#[tokio::test]
async fn read_only_check_paths_are_unguarded() {
    let (home, _guard) = home_at_mode(0o777).await;
    let (_store, storage) = empty_storage();

    for err in [
        fetch_latest_manifest(&storage)
            .await
            .expect_err("empty storage has no self manifest"),
        fetch_tool_manifest(&storage, "fuzd", None)
            .await
            .expect_err("empty storage has no tool manifest"),
    ] {
        assert!(
            matches!(err, ReleaseError::NoReleaseForTarget { .. }),
            "a --check path must not gain the write-path refusal, got {err:?}"
        );
    }

    assert_home_untouched(home.path());
}
