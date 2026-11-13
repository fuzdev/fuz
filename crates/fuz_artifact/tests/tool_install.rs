//! Integration coverage for the per-tool local install path
//! (`fuz_artifact::tools::install_local_tool`) — the no-forge install
//! `cargo xtask install` uses to land fuzd. It resolves through
//! `fuz_home::get_tool_dir`, so like the artifact-store ops it needs a
//! redirectable home; drives the same `test_home_override` seam as
//! `tests/local_store.rs`. See `tests/common/mod.rs` for the shared harness.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::{fake_fuz, fresh_home};
use fuz_artifact::{ArtifactError, tools::install_local_tool};
use fuz_home::{
    FuzHomeError, clear_fuz_home_override_for_testing, get_bin_dir, get_tool_current_link,
    get_tool_dir,
};
use fuz_sys::SECURE_DIR_MODE;

/// Pins `install_local_tool`: it copies the binary under
/// `~/.fuz/tools/<name>/v1-<hash>/`, writes a `ToolMeta`, and wires both the
/// per-tool `current` symlink and the `bin/<binary>` symlink. Fails if any of
/// the install effects is missing.
#[test]
fn install_local_tool_writes_meta_and_wires_symlinks() {
    let (_home, _guard) = fresh_home();

    // A source binary on disk for the tool to install from.
    let src = tempfile::tempdir().unwrap();
    let bin_path = src.path().join("fuzd");
    std::fs::write(&bin_path, fake_fuz(0x10)).unwrap();

    let meta = install_local_tool("fuzd", "0.1.0", &[("fuzd", &bin_path)]).unwrap();
    assert_eq!(meta.tool, "fuzd", "records the tool name");
    assert_eq!(meta.version, "0.1.0", "records the version");
    assert!(
        meta.content_hash.starts_with("v1-"),
        "content hash carries the version prefix"
    );
    assert!(
        meta.binaries.contains_key("fuzd"),
        "records the binary's hash"
    );

    // Installed under ~/.fuz/tools/fuzd/v1-<hash>/ with the binary + meta.json.
    let tool_dir = get_tool_dir("fuzd").unwrap().join(&meta.content_hash);
    assert!(
        tool_dir.join("fuzd").is_file(),
        "the tool binary is copied in"
    );
    assert!(tool_dir.join("meta.json").is_file(), "meta.json is written");

    // `~/.fuz/tools/`, `~/.fuz/tools/<name>/`, and `~/.fuz/bin/` are created on
    // demand — `ensure_fuz_home` makes none of the three — so their mode is
    // stated by the install, not inherited from the runner's umask. Exact
    // equality, since an inherited mode differs from 0700 under every common
    // umask (0775 at `002`, 0755 at `022`, 0777 at `000`).
    let name_dir = get_tool_dir("fuzd").unwrap();
    let tools_dir = name_dir.parent().expect("tools dir").to_path_buf();
    for dir in [&tools_dir, &name_dir, &get_bin_dir().unwrap()] {
        assert_eq!(
            std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
            SECURE_DIR_MODE,
            "{dir:?} must be created at 0700, not at the runner's umask"
        );
    }

    // The staging dir is renamed into place, so its creation mode is the mode
    // the install lands at. The forge path (`fuz_release::install_tool`) must
    // agree on it, and both set it explicitly — so the expected value here
    // doesn't move with the runner's umask.
    assert_eq!(
        std::fs::metadata(&tool_dir).unwrap().permissions().mode() & 0o777,
        SECURE_DIR_MODE,
        "the installed tool dir carries the staging dir's explicit 0700"
    );

    // The per-tool `current` symlink points at the hash dir, and bin/fuzd links
    // through it.
    assert_eq!(
        std::fs::read_link(get_tool_current_link("fuzd").unwrap()).unwrap(),
        Path::new(&meta.content_hash),
        "tools/fuzd/current -> <hash>"
    );
    assert!(
        std::fs::read_link(get_bin_dir().unwrap().join("fuzd")).is_ok(),
        "bin/fuzd is a symlink"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins that re-installing identical bytes dedups onto one content hash (the
/// cache-hit path re-verifies and re-links rather than forking a new dir).
#[test]
fn install_local_tool_dedups_identical_binaries() {
    let (_home, _guard) = fresh_home();

    let src = tempfile::tempdir().unwrap();
    let bin_path = src.path().join("zap");
    std::fs::write(&bin_path, fake_fuz(0x20)).unwrap();

    let first = install_local_tool("zap", "0.1.0", &[("zap", &bin_path)]).unwrap();
    let second = install_local_tool("zap", "0.1.0", &[("zap", &bin_path)]).unwrap();
    assert_eq!(
        first.content_hash, second.content_hash,
        "identical bytes dedup onto one hash"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins the world-writable-`~/.fuz` refusal on the local install path.
///
/// Both tool-install paths write binaries into `~/.fuz/tools/` — the tree an
/// attacker with local write access swaps a binary in — so both hold the same
/// `check_fuz_home_not_world_writable` floor: this one and the forge path
/// (`fuz_release::install_tool`), whichever caller got there.
///
/// The pin is the error *kind*: unguarded, this install has everything it needs
/// and would simply succeed, so `InsecureHome` (with the offending mode) is the
/// only outcome that says the guard ran. `assert!(err.is_err())` would not —
/// nor would a bare `ArtifactError` match.
#[test]
fn install_local_tool_refuses_world_writable_home() {
    let (home, _guard) = fresh_home();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

    let src = tempfile::tempdir().unwrap();
    let bin_path = src.path().join("tsv");
    std::fs::write(&bin_path, fake_fuz(0x30)).unwrap();

    let err = install_local_tool("tsv", "0.1.0", &[("tsv", &bin_path)])
        .expect_err("a world-writable home must refuse the local tool install");
    assert!(
        matches!(
            err,
            ArtifactError::FuzHome(FuzHomeError::InsecureHome { mode: 0o777, .. })
        ),
        "expected InsecureHome (mode 777), got {err:?}"
    );

    // Unlike the storage-backed sibling suite (`fuz_release`'s
    // `tests/insecure_home.rs`, where empty storage aborts the flow anyway),
    // this install would otherwise have fully succeeded — so an empty home is a
    // real assertion that the refusal preceded every write.
    let entries: Vec<_> = std::fs::read_dir(home.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        entries.is_empty(),
        "the refusal must precede every write, found {entries:?}"
    );

    clear_fuz_home_override_for_testing();
}

/// Install `fuzd` once from `seed` bytes and return the source binary path and
/// the installed `tools/fuzd/v1-<hash>/` slot.
fn install_once(src: &Path, seed: u8) -> (std::path::PathBuf, std::path::PathBuf) {
    let bin_path = src.join("fuzd");
    std::fs::write(&bin_path, fake_fuz(seed)).unwrap();
    let meta = install_local_tool("fuzd", "0.1.0", &[("fuzd", &bin_path)]).unwrap();
    let slot = get_tool_dir("fuzd").unwrap().join(&meta.content_hash);
    (bin_path, slot)
}

/// Pins that a **live** symlink at `tools/<name>/v1-<hash>/` — aimed at a valid
/// install, so it would verify if read through — is not a cache hit: the link
/// is unlinked (never its target) and the install lands a real directory.
/// Fails if the cache-hit check follows the link and relinks onto it.
#[test]
fn install_local_tool_replaces_a_symlink_at_the_install_dir() {
    let (home, _guard) = fresh_home();
    let src = tempfile::tempdir().unwrap();
    let (bin_path, slot) = install_once(src.path(), 0x40);

    let decoy = home.path().join("decoy");
    std::fs::rename(&slot, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &slot).unwrap();

    install_local_tool("fuzd", "0.1.0", &[("fuzd", &bin_path)])
        .expect("a symlink at the install dir is replaced, not an error");
    let entry = std::fs::symlink_metadata(&slot).unwrap();
    assert!(
        entry.file_type().is_dir(),
        "the install is a real directory, not the adopted link: {:?}",
        entry.file_type()
    );
    assert_eq!(std::fs::read(slot.join("fuzd")).unwrap(), fake_fuz(0x40));
    assert_eq!(
        std::fs::read(decoy.join("fuzd")).unwrap(),
        fake_fuz(0x40),
        "the link's target is untouched"
    );
    assert!(decoy.join("meta.json").is_file());

    clear_fuz_home_override_for_testing();
}

/// Pins that a **dangling** symlink at `tools/<name>/v1-<hash>/` is unlinked and
/// the install lands. `Path::exists` reads a dangling link as absent, and a
/// staging `rename` onto one fails `ENOTDIR` — so the slot is classified
/// without following it.
#[test]
fn install_local_tool_replaces_a_dangling_symlink_at_the_install_dir() {
    let (home, _guard) = fresh_home();
    let src = tempfile::tempdir().unwrap();
    let (bin_path, slot) = install_once(src.path(), 0x41);

    std::fs::remove_dir_all(&slot).unwrap();
    std::os::unix::fs::symlink(home.path().join("nowhere"), &slot).unwrap();

    install_local_tool("fuzd", "0.1.0", &[("fuzd", &bin_path)])
        .expect("a dangling symlink at the install dir is replaced, not ENOTDIR");
    assert!(
        std::fs::symlink_metadata(&slot)
            .unwrap()
            .file_type()
            .is_dir(),
        "the install is a real directory"
    );
    assert!(
        !home.path().join("nowhere").exists(),
        "nothing is created at the link's target"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins that inside a real install directory the cache-hit verify reads neither
/// a binary nor `meta.json` through a symlink — even one aimed at the bytes the
/// meta records. Fails if `ToolMeta::verify_binaries` / `ToolMeta::read` follow
/// the link.
#[test]
fn install_local_tool_refuses_a_symlink_inside_the_install_dir() {
    let (home, _guard) = fresh_home();
    let src = tempfile::tempdir().unwrap();
    let (bin_path, slot) = install_once(src.path(), 0x42);

    for file in ["fuzd", "meta.json"] {
        let outside = home.path().join(format!("outside-{file}"));
        std::fs::rename(slot.join(file), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, slot.join(file)).unwrap();

        let err = install_local_tool("fuzd", "0.1.0", &[("fuzd", &bin_path)])
            .expect_err("a linked file inside the install must be refused");
        assert!(
            matches!(&err, ArtifactError::NotRegularFile(path) if *path == slot.join(file)),
            "{file}: got {err:?}"
        );
        assert!(outside.is_file(), "{file}: the link's target is untouched");

        std::fs::remove_file(slot.join(file)).unwrap();
        std::fs::rename(&outside, slot.join(file)).unwrap();
    }

    clear_fuz_home_override_for_testing();
}

/// Pins that a tool `current` that is a real directory — not something fuz
/// wrote, and not something a link swap can replace (`EISDIR`) — is refused
/// before anything is hashed or copied, and left in place.
#[test]
fn install_local_tool_refuses_a_current_that_is_not_a_symlink() {
    let (_home, _guard) = fresh_home();
    let src = tempfile::tempdir().unwrap();
    let bin_path = src.path().join("fuzd");
    std::fs::write(&bin_path, fake_fuz(0x43)).unwrap();
    let current = get_tool_current_link("fuzd").unwrap();
    std::fs::create_dir_all(&current).unwrap();

    let err = install_local_tool("fuzd", "0.1.0", &[("fuzd", &bin_path)])
        .expect_err("a current directory must be refused");
    assert!(
        matches!(
            &err,
            ArtifactError::CurrentNotStoreLink {
                problem: fuz_artifact::CurrentLinkProblem::NotASymlink,
                path,
            } if *path == current
        ),
        "refused up front, not EISDIR at the swap: {err:?}"
    );
    assert!(current.is_dir(), "left in place");
    let entries: Vec<_> = std::fs::read_dir(get_tool_dir("fuzd").unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["current"], "nothing was installed beside it");

    clear_fuz_home_override_for_testing();
}

/// Pins that a **source** binary handed to the install that is a symlink is
/// refused as an invalid input — `InvalidBinary`, matching the artifact build's
/// source validation — not as a modified install.
#[test]
fn install_local_tool_refuses_a_symlinked_source_binary() {
    let (_home, _guard) = fresh_home();
    let src = tempfile::tempdir().unwrap();
    let real = src.path().join("real-fuzd");
    std::fs::write(&real, fake_fuz(0x44)).unwrap();
    let link = src.path().join("fuzd");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let err = install_local_tool("fuzd", "0.1.0", &[("fuzd", &link)])
        .expect_err("a symlinked source must be refused");
    assert!(
        matches!(
            &err,
            ArtifactError::InvalidBinary { name, reason }
                if name == "fuzd" && reason == "symlink not allowed"
        ),
        "got {err:?}"
    );

    let missing = src.path().join("absent");
    let err = install_local_tool("fuzd", "0.1.0", &[("fuzd", &missing)])
        .expect_err("a missing source must be refused");
    assert!(
        matches!(&err, ArtifactError::MissingBinary { name, .. } if name == "fuzd"),
        "got {err:?}"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins the backstop in `setup_tool_symlinks` itself (public, and the last
/// step of both install paths): a `current` that is a real directory is refused
/// as `CurrentNotStoreLink` and left in place, never an `EISDIR` from the
/// rename.
#[test]
fn setup_tool_symlinks_refuses_a_current_that_is_not_a_symlink() {
    let (_home, _guard) = fresh_home();
    let current = get_tool_current_link("zap").unwrap();
    std::fs::create_dir_all(&current).unwrap();

    let err = fuz_artifact::setup_tool_symlinks("zap", "v1-abc", &["zap"])
        .expect_err("a current directory is refused");
    assert!(
        matches!(err, ArtifactError::CurrentNotStoreLink { .. }),
        "got {err:?}"
    );
    assert!(current.is_dir(), "left in place");

    clear_fuz_home_override_for_testing();
}

/// A tool whose binary set names a self binary is refused before anything is
/// written: `bin/fuz` is the self artifact's link, and every tool binary is
/// linked into the same `bin/`. Nothing lands under `tools/`, and `bin/fuz`
/// still points through the self artifact's `current`.
#[test]
fn install_local_tool_refuses_a_binary_named_for_a_self_binary() {
    let (_home, _guard) = fresh_home();
    fuz_artifact::setup_bin_symlinks(&["fuz"]).unwrap();
    let bin_fuz = get_bin_dir().unwrap().join("fuz");
    let self_link = std::fs::read_link(&bin_fuz).unwrap();
    assert_eq!(self_link, Path::new("../current/fuz"));

    let src = tempfile::tempdir().unwrap();
    let fuzd = src.path().join("fuzd");
    let fuz = src.path().join("fuz");
    std::fs::write(&fuzd, fake_fuz(0x31)).unwrap();
    std::fs::write(&fuz, fake_fuz(0x32)).unwrap();

    // The name in any ASCII case: on a case-insensitive filesystem `bin/Fuz`
    // is `bin/fuz`.
    for reserved in ["fuz", "Fuz", "FUZ"] {
        let err = install_local_tool("fuzd", "0.1.0", &[("fuzd", &fuzd), (reserved, &fuz)])
            .expect_err("a tool binary named for `fuz` is refused");
        assert!(
            matches!(
                &err,
                ArtifactError::ReservedBinaryName { tool, binary } if tool == "fuzd" && binary == reserved
            ),
            "{reserved}: got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "tool \"fuzd\" declares the binary \"{reserved}\", which belongs to the fuz self artifact"
            )
        );
        assert_eq!(std::fs::read_link(&bin_fuz).unwrap(), self_link);
        assert!(
            !get_tool_dir("fuzd").unwrap().exists(),
            "{reserved}: nothing was installed under tools/"
        );
        assert_eq!(
            std::fs::read_dir(get_bin_dir().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            ["fuz"],
            "{reserved}: no link was made"
        );
    }

    clear_fuz_home_override_for_testing();
}

/// `setup_tool_symlinks` is public and the last step of both install paths:
/// it refuses a self binary's name itself, before the tool's `current` or any
/// `bin/` link moves.
#[test]
fn setup_tool_symlinks_refuses_a_binary_named_for_a_self_binary() {
    let (_home, _guard) = fresh_home();
    fuz_artifact::setup_bin_symlinks(&["fuz"]).unwrap();
    let bin_dir = get_bin_dir().unwrap();
    std::fs::create_dir_all(get_tool_dir("zap").unwrap()).unwrap();

    let err = fuz_artifact::setup_tool_symlinks("zap", "v1-abc", &["zap", "fuz"])
        .expect_err("a tool binary named `fuz` is refused");
    assert!(
        matches!(
            &err,
            ArtifactError::ReservedBinaryName { tool, binary } if tool == "zap" && binary == "fuz"
        ),
        "got {err:?}"
    );
    let err = fuz_artifact::setup_tool_symlinks("zap", "v1-abc", &["zap", "fUZ"])
        .expect_err("in any ASCII case");
    assert!(
        matches!(
            &err,
            ArtifactError::ReservedBinaryName { tool, binary } if tool == "zap" && binary == "fUZ"
        ),
        "got {err:?}"
    );
    assert!(!bin_dir.join("fUZ").exists(), "no link was made");
    assert_eq!(
        std::fs::read_link(bin_dir.join("fuz")).unwrap(),
        Path::new("../current/fuz"),
        "bin/fuz is still the self artifact's"
    );
    assert!(!bin_dir.join("zap").exists(), "no link was made");
    assert!(
        std::fs::symlink_metadata(get_tool_current_link("zap").unwrap()).is_err(),
        "the tool's current was not pointed"
    );

    clear_fuz_home_override_for_testing();
}

/// A binary name that is not a release token — a path, a `:` or newline the
/// content hash joins with, a leading `-` — is refused before anything is
/// hashed, copied, or linked, at the local install and at the link step both
/// install paths share.
#[test]
fn tool_installs_refuse_a_binary_name_that_is_not_a_token() {
    let (_home, _guard) = fresh_home();
    let src = tempfile::tempdir().unwrap();
    let fuzd = src.path().join("fuzd");
    std::fs::write(&fuzd, fake_fuz(0x41)).unwrap();

    for bad in ["a:b", "a\nb", "-a", "a/b", "..", ""] {
        let err = install_local_tool("fuzd", "0.1.0", &[("fuzd", &fuzd), (bad, &fuzd)])
            .expect_err("a binary name that is not a token is refused");
        assert!(
            matches!(
                &err,
                ArtifactError::InvalidBinaryName { tool, binary } if tool == "fuzd" && binary == bad
            ),
            "{bad:?}: got {err:?}"
        );
        assert!(
            !get_tool_dir("fuzd").unwrap().exists(),
            "{bad:?}: nothing was installed under tools/"
        );

        let err = fuz_artifact::setup_tool_symlinks("fuzd", "v1-abc", &["fuzd", bad])
            .expect_err("refused at the link step too");
        assert!(
            matches!(&err, ArtifactError::InvalidBinaryName { .. }),
            "{bad:?}: got {err:?}"
        );
        assert!(
            std::fs::symlink_metadata(get_tool_current_link("fuzd").unwrap()).is_err(),
            "{bad:?}: the tool's current was not pointed"
        );
    }

    clear_fuz_home_override_for_testing();
}
