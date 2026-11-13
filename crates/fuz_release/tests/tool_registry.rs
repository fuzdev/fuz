//! Integration coverage for the installed-tool registry readers
//! (`fuz_release::{list_installed_tools, verify_installed_tool}`). Both scan
//! `~/.fuz/tools/...` through `fuz_home` (`get_tools_dir` /
//! `get_tool_current_link`), so they need a redirectable home; this drives the
//! `fuz_home/test_home_override` dev-dep seam (the same one `fuz_artifact`'s
//! suites use). Tools are minted with `fuz_artifact::tools::install_local_tool`.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fuz_artifact::ArtifactError;
use fuz_artifact::tools::{ToolMeta, install_local_tool};
use fuz_home::get_tool_dir;
use fuz_home::{
    clear_fuz_home_override_for_testing, get_tool_current_link, set_fuz_home_override_for_testing,
};
use fuz_release::{
    CurrentVersion, ReleaseError, installed_tool_meta, list_installed_tools, resolve_current_tool,
    verify_installed_tool,
};
use fuz_sys::SECURE_DIR_MODE;

/// The home override is process-global and cargo runs `#[test]`s on parallel
/// threads, so serialize the whole file. A lock poisoned by another test's
/// assertion panic is still usable — recover the guard.
static SERIAL: Mutex<()> = Mutex::new(());

/// Lock the serial guard and point `~/.fuz` at a fresh temp home. The `TempDir`
/// must outlive the test body; the guard releases (and the override is left for
/// the next test to overwrite) on drop.
///
/// The mode is **set**, not inherited. `tempfile::tempdir()` creates at the std
/// default `0o777` masked by the process umask, so under a permissive runner
/// umask (`umask 000`, routine in containers) the home would arrive
/// world-writable and `install_local_tool` — which refuses one — would fail
/// every test here for a reason that has nothing to do with the registry
/// readers under test. Pin it at [`SECURE_DIR_MODE`], the mode a real
/// `ensure_fuz_home` creates. The world-writable *refusal* is pinned
/// deliberately elsewhere (`tests/insecure_home.rs`, which chmods every case).
fn fresh_home() -> (tempfile::TempDir, MutexGuard<'static, ()>) {
    let guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        home.path(),
        std::fs::Permissions::from_mode(SECURE_DIR_MODE),
    )
    .unwrap();
    set_fuz_home_override_for_testing(home.path());
    (home, guard)
}

/// Install a tool from a freshly written source binary (distinct `seed` bytes →
/// distinct content hash). `install_local_tool` hashes + copies it into
/// `~/.fuz/tools/<name>/v1-<hash>/` and wires the symlinks.
fn install(name: &str, version: &str, seed: u8) -> ToolMeta {
    let src = tempfile::tempdir().unwrap();
    let bin = src.path().join(name);
    std::fs::write(&bin, vec![seed; 2048]).unwrap();
    install_local_tool(name, version, &[(name, &bin)]).unwrap()
}

/// Pins `list_installed_tools`: an untouched home lists nothing, and after
/// installing tools they come back sorted by name.
#[test]
fn list_installed_tools_reports_installed_sorted() {
    let (_home, _guard) = fresh_home();

    assert!(
        list_installed_tools().unwrap().is_empty(),
        "no tools on a fresh home"
    );

    install("zap", "0.2.0", 0x10);
    install("fuzd", "0.1.0", 0x20);

    let names: Vec<String> = list_installed_tools()
        .unwrap()
        .into_iter()
        .map(|m| m.tool)
        .collect();
    assert_eq!(
        names,
        ["fuzd", "zap"],
        "installed tools are listed, sorted by name"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins `verify_installed_tool`: it reads back the recorded meta for an installed
/// tool, and reports `ToolNotInstalled` for one that isn't.
#[test]
fn verify_installed_tool_matches_install_and_flags_missing() {
    let (_home, _guard) = fresh_home();

    let installed = install("fuzd", "0.1.0", 0x33);
    let verified = verify_installed_tool("fuzd").unwrap();
    assert_eq!(verified.tool, "fuzd", "reads back the tool name");
    assert_eq!(verified.version, "0.1.0", "reads back the version");
    assert_eq!(
        verified.content_hash, installed.content_hash,
        "verify returns the installed meta"
    );

    let err = verify_installed_tool("zap").expect_err("an uninstalled tool must error");
    assert!(
        matches!(err, ReleaseError::ToolNotInstalled(_)),
        "expected ToolNotInstalled, got {err:?}"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins `verify_installed_tool`'s re-hash: tampering with an installed binary
/// surfaces as an integrity failure (a wrapped `ArtifactError`), not a false pass.
#[test]
fn verify_installed_tool_detects_tampered_binary() {
    let (_home, _guard) = fresh_home();

    install("tsv", "0.1.0", 0x44);

    // Corrupt the installed binary out from under its recorded hash (the path
    // resolves through the `current` symlink to the real file).
    let installed_bin = get_tool_current_link("tsv").unwrap().join("tsv");
    std::fs::write(&installed_bin, vec![0xFF; 2048]).unwrap();

    let err = verify_installed_tool("tsv").expect_err("a tampered binary must fail verification");
    assert!(
        matches!(
            err,
            ReleaseError::Artifact(ArtifactError::BinaryIntegrityFailed { .. })
        ),
        "expected BinaryIntegrityFailed, got {err:?}"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins that every installed-tool reader refuses to read through a symlink at
/// the install `current` names (`tools/<name>/v1-<hash>/`) — live, aimed at a valid
/// install that would verify if read through, or dangling. `current` is meant
/// to be a link; what it names must be the real directory fuz renamed into
/// place. Fails if `verify_installed_tool`, `list_installed_tools`,
/// `installed_tool_meta`, or `resolve_current_tool` follow the second link.
#[test]
fn current_readers_refuse_a_symlink_at_the_current_install() {
    let (home, _guard) = fresh_home();

    let installed = install("fuzd", "0.1.0", 0x55);
    let slot = get_tool_dir("fuzd").unwrap().join(&installed.content_hash);
    let decoy = home.path().join("decoy");
    std::fs::rename(&slot, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &slot).unwrap();

    let err = verify_installed_tool("fuzd").expect_err("a symlinked install must be refused");
    assert!(
        matches!(
            &err,
            ReleaseError::Artifact(ArtifactError::StoreEntryNotDir { path, .. }) if *path == slot
        ),
        "got {err:?}"
    );
    assert!(
        list_installed_tools().unwrap().is_empty(),
        "a symlinked install is not listed"
    );
    assert!(
        installed_tool_meta("fuzd").is_none(),
        "nor read as installed"
    );
    assert!(
        matches!(
            resolve_current_tool("fuzd"),
            CurrentVersion::Unreadable { .. }
        ),
        "the version resolver reads it as unreadable, so an install needs --force"
    );
    assert_eq!(
        std::fs::read_link(&slot).unwrap(),
        decoy,
        "the readers leave the link in place"
    );

    // Dangling: the same refusal from the version resolver, and still not
    // installed for the others.
    std::fs::remove_file(&slot).unwrap();
    std::os::unix::fs::symlink(home.path().join("nowhere"), &slot).unwrap();
    assert!(matches!(
        verify_installed_tool("fuzd").unwrap_err(),
        ReleaseError::Artifact(ArtifactError::StoreEntryNotDir { .. })
    ));
    assert!(list_installed_tools().unwrap().is_empty());
    assert!(matches!(
        resolve_current_tool("fuzd"),
        CurrentVersion::Unreadable { .. }
    ));

    clear_fuz_home_override_for_testing();
}

/// Pins that `verify_installed_tool` reads neither `meta.json` nor a binary
/// through a symlink inside the real install `current` names — even one aimed
/// at the bytes the meta records.
#[test]
fn verify_installed_tool_refuses_a_symlink_inside_the_install() {
    let (home, _guard) = fresh_home();

    let installed = install("zap", "0.1.0", 0x66);
    let slot = get_tool_dir("zap").unwrap().join(&installed.content_hash);
    for file in ["zap", "meta.json"] {
        let outside = home.path().join(format!("outside-{file}"));
        std::fs::rename(slot.join(file), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, slot.join(file)).unwrap();

        let err = verify_installed_tool("zap").expect_err("a linked file must be refused");
        assert!(
            matches!(
                &err,
                ReleaseError::Artifact(ArtifactError::NotRegularFile(path)) if *path == slot.join(file)
            ),
            "{file}: got {err:?}"
        );

        std::fs::remove_file(slot.join(file)).unwrap();
        std::fs::rename(&outside, slot.join(file)).unwrap();
    }
    verify_installed_tool("zap").expect("the restored install verifies");

    clear_fuz_home_override_for_testing();
}

/// Pins the shape of a tool's `current` the readers accept: a symlink to a bare
/// `v1-<hash>` (what fuz writes) or the absolute path of the same entry. One that
/// points outside the tool's store — even at a valid install copy — or is a
/// real directory is refused, not read through: fuz only ever writes a link
/// there, and an install could not replace a directory with one.
#[test]
fn current_readers_accept_only_a_link_into_the_tool_store() {
    let (home, _guard) = fresh_home();

    let installed = install("fuzd", "0.1.0", 0x77);
    let tool_dir = get_tool_dir("fuzd").unwrap();
    let slot = tool_dir.join(&installed.content_hash);
    let current = get_tool_current_link("fuzd").unwrap();
    let relink = |target: &std::path::Path| {
        let _ = std::fs::remove_file(&current);
        std::os::unix::fs::symlink(target, &current).unwrap();
    };

    // The absolute spelling of the entry fuz writes is accepted.
    relink(&slot);
    verify_installed_tool("fuzd").expect("an absolute in-store link reads");

    // A valid copy of the install outside the store.
    let outside = home.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    for file in ["fuzd", "meta.json"] {
        std::fs::copy(slot.join(file), outside.join(file)).unwrap();
    }
    for target in [
        outside.clone(),
        std::path::PathBuf::from("../fuzd/x/../../../outside"),
    ] {
        relink(&target);
        let err = verify_installed_tool("fuzd").expect_err("outside the store is refused");
        assert!(
            matches!(
                &err,
                ReleaseError::Artifact(ArtifactError::CurrentNotStoreLink {
                    problem: fuz_artifact::CurrentLinkProblem::OutsideStore { .. },
                    ..
                })
            ),
            "{target:?}: got {err:?}"
        );
        assert!(list_installed_tools().unwrap().is_empty());
        assert!(installed_tool_meta("fuzd").is_none());
        assert!(matches!(
            resolve_current_tool("fuzd"),
            CurrentVersion::Unreadable { .. }
        ));
    }

    // A trailing `/` or `/.` on the target names the same slot and must not
    // make the slot check follow a symlink there.
    std::fs::rename(&slot, home.path().join("moved")).unwrap();
    std::os::unix::fs::symlink(home.path().join("moved"), &slot).unwrap();
    for suffix in ["/", "/."] {
        relink(std::path::Path::new(&format!(
            "{}{suffix}",
            installed.content_hash
        )));
        let err = verify_installed_tool("fuzd").expect_err("the slot is a symlink");
        assert!(
            matches!(
                &err,
                ReleaseError::Artifact(ArtifactError::StoreEntryNotDir { path, .. }) if *path == slot
            ),
            "{suffix:?}: got {err:?}"
        );
    }
    std::fs::remove_file(&slot).unwrap();
    std::fs::rename(home.path().join("moved"), &slot).unwrap();

    // A real directory at `current` (a copy of the install, which would read).
    std::fs::remove_file(&current).unwrap();
    std::fs::rename(&outside, &current).unwrap();
    let err = verify_installed_tool("fuzd").expect_err("a current directory is refused");
    assert!(
        matches!(
            &err,
            ReleaseError::Artifact(ArtifactError::CurrentNotStoreLink {
                problem: fuz_artifact::CurrentLinkProblem::NotASymlink,
                path,
            }) if *path == current
        ),
        "got {err:?}"
    );
    assert!(list_installed_tools().unwrap().is_empty());
    assert!(installed_tool_meta("fuzd").is_none());
    assert!(matches!(
        resolve_current_tool("fuzd"),
        CurrentVersion::Unreadable { .. }
    ));
    assert!(current.is_dir(), "the readers leave it in place");

    clear_fuz_home_override_for_testing();
}

/// Pins that `install_tool` refuses a name outside the first-party allowlist
/// before it inspects anything built from it: a `zz/../x` name resolves
/// `current` to `tools/x/current`, here a real directory that would otherwise be
/// refused as not a symlink — the name refusal must come first.
#[test]
fn install_tool_refuses_a_disallowed_name_before_touching_its_paths() {
    let (home, _guard) = fresh_home();
    std::fs::create_dir_all(home.path().join("tools/zz")).unwrap();
    std::fs::create_dir_all(home.path().join("tools/x/current")).unwrap();
    let storage_dir = tempfile::tempdir().unwrap();
    let storage = fuz_storage::FileStorage::new(storage_dir.path()).unwrap();

    let err = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(fuz_release::install_tool(
            &storage,
            "zz/../x",
            &fuz_release::ToolInstallOptions::default(),
        ))
        .expect_err("a disallowed name is refused");
    assert!(
        matches!(
            &err,
            ReleaseError::Manifest(fuz_release::ManifestError::ToolNotAllowed(name)) if name == "zz/../x"
        ),
        "got {err:?}"
    );

    clear_fuz_home_override_for_testing();
}
