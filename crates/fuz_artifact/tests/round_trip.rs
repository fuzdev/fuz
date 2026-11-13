//! End-to-end round-trip for the local content-addressed artifact store.
//!
//! Exercises the public create → find → verify path against a real (overridden)
//! `~/.fuz` home — the surface the inline `src/tests.rs` suite can't reach,
//! because resolving `get_artifacts_dir()` needs a redirectable home and edition
//! 2024 + `unsafe_code = "forbid"` rule out `std::env::set_var("FUZ_HOME", …)`.
//! The `fuz_home/test_home_override` dev-dep feature supplies the in-process
//! redirect (the same seam `fuz_sign`'s signed-trust test uses); resolver-2 keeps
//! it out of every shipping binary.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{fake_fuz, fresh_home, host_triple};
use fuz_artifact::{
    ArtifactError, ArtifactInputs, ArtifactSource, BuildSource, create_artifact, find_artifact,
    get_artifact_dir, verify_artifact,
};
use fuz_home::clear_fuz_home_override_for_testing;
use fuz_sys::EXECUTABLE_FILE_MODE;

#[test]
fn create_find_and_verify_round_trip() {
    let (_home, _guard) = fresh_home();

    let bytes = fake_fuz(0xAB);
    let meta = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes })
        .expect("create_artifact must succeed");
    assert!(
        meta.hash.starts_with("v1-"),
        "hash carries the version prefix"
    );

    // The store wrote the binary + meta under the content-hash directory.
    let dir = get_artifact_dir(&meta.hash).expect("artifact dir");
    assert!(dir.join("fuz").is_file(), "the fuz binary must be written");
    assert!(dir.join("meta.json").is_file(), "meta.json must be written");

    // The stored `fuz` is executable at exactly 0755, a property of the
    // artifact rather than of the environment that built it. The `Bootstrap`
    // arm reaches it through `write_atomic`, whose `O_CREAT, mode` is masked by
    // the process umask, so without the explicit set this reads back as
    // `0755 & ~umask`.
    //
    // That masking is a no-op for the umasks with no bits in 0755 — 022, 002,
    // and 000 all leave 0755 alone — so on a typical box and in CI this
    // assertion holds either way. It discriminates at 077 (0700) and 027
    // (0750). What it pins there is *statedness*, not an exposure: `artifacts/`
    // is 0700, so an owner-only `fuz` inside it is still reachable by the only
    // user who can traverse to it. The `Local` arm below is the umask-
    // independent half of this pin.
    assert_eq!(
        std::fs::metadata(dir.join("fuz"))
            .expect("stat the stored fuz")
            .permissions()
            .mode()
            & 0o777,
        EXECUTABLE_FILE_MODE,
        "the stored fuz carries an explicit 0755, not the runner's umask"
    );

    // `find_artifact` resolves the same meta by its hash.
    let found = find_artifact(&meta.hash).expect("find by hash");
    assert_eq!(found.hash, meta.hash);

    // Integrity verifies: the on-disk binary re-hashes to `meta.outputs.fuz`.
    verify_artifact(&dir).expect("a freshly created artifact must verify");

    clear_fuz_home_override_for_testing();
}

#[test]
fn verify_detects_a_tampered_binary() {
    let (_home, _guard) = fresh_home();

    let meta = create_artifact(
        "0.1.0",
        BuildSource::Bootstrap {
            fuz_bytes: &fake_fuz(0x01),
        },
    )
    .unwrap();
    let dir = get_artifact_dir(&meta.hash).unwrap();

    // Corrupt the stored binary out from under its recorded hash.
    let mut tampered = fake_fuz(0x01);
    tampered[100] ^= 0xFF;
    std::fs::write(dir.join("fuz"), &tampered).unwrap();

    let err = verify_artifact(&dir).expect_err("a tampered binary must fail verification");
    assert!(
        matches!(err, ArtifactError::BinaryIntegrityFailed { .. }),
        "expected BinaryIntegrityFailed, got {err:?}"
    );

    clear_fuz_home_override_for_testing();
}

#[test]
fn create_dedups_identical_bytes_onto_one_hash() {
    let (_home, _guard) = fresh_home();

    let bytes = fake_fuz(0x7E);
    let first = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    // A second create of identical bytes is a content-hash collision: the store
    // dedups onto the existing artifact rather than erroring or forking a dir.
    let second = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    assert_eq!(
        first.hash, second.hash,
        "identical bytes must dedup onto one hash"
    );

    clear_fuz_home_override_for_testing();
}

#[test]
fn local_build_records_provenance_and_round_trips() {
    let (_home, _guard) = fresh_home();

    // The `Local` path (what `fuz artifact build` / `cargo xtask install` use) reads
    // the `fuz` binary from the path cargo reported, validates it, and records git/rustc
    // provenance — distinct from `Bootstrap`'s in-memory, provenance-free path.
    let release = tempfile::tempdir().unwrap();
    std::fs::write(release.path().join("fuz"), fake_fuz(0x33)).unwrap();
    let inputs = ArtifactInputs {
        input_hash: "f".repeat(64),
        git_commit: "abc1234deadbeefcafe".to_string(),
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

    // Local records provenance (Bootstrap leaves `inputs` None / source Bootstrap).
    assert!(
        matches!(meta.source, ArtifactSource::Local),
        "Local source recorded"
    );
    let recorded = meta.inputs.as_ref().expect("Local records its inputs");
    assert_eq!(recorded.git_commit, "abc1234deadbeefcafe");
    assert_eq!(recorded.rustc_version, "rustc 1.75.0");

    // Same create→find→verify round-trip as the Bootstrap path.
    let dir = get_artifact_dir(&meta.hash).unwrap();
    assert!(dir.join("fuz").is_file());

    // The umask-independent half of the mode pin. `fs::copy` gives the
    // destination the *source* file's permissions, and the source here was
    // written by `std::fs::write` — `0666 & ~umask`, never executable under any
    // umask. So only the explicit set makes the stored `fuz` runnable, and this
    // assertion fails without it at 000, 002, 022, 027, and 077 alike: a build
    // whose release dir happened to hold a non-executable `fuz` would otherwise
    // store one, and `bin/fuz` would resolve to it.
    assert_eq!(
        std::fs::metadata(dir.join("fuz"))
            .expect("stat the stored fuz")
            .permissions()
            .mode()
            & 0o777,
        EXECUTABLE_FILE_MODE,
        "the Local arm states 0755 rather than carrying the source file's mode"
    );
    assert_eq!(find_artifact(&meta.hash).unwrap().hash, meta.hash);
    verify_artifact(&dir).expect("a freshly built Local artifact must verify");

    clear_fuz_home_override_for_testing();
}

/// Pins that `create_artifact` never adopts a **symlink** at the target
/// `v1-<hash>/`, even one aimed at a directory that reads and verifies as that
/// exact artifact.
///
/// Adopting a link would make every later read of the artifact (verify,
/// `current`, `bin/fuz`) follow it to wherever it points, so the build must
/// unlink the entry and land a real directory, leaving the link's target alone.
#[test]
fn create_never_adopts_a_symlink_at_the_artifact_dir() {
    let (home, _guard) = fresh_home();

    let bytes = fake_fuz(0x5C);
    let meta = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    let final_dir = get_artifact_dir(&meta.hash).unwrap();

    // Move the valid artifact out of the store and aim a link at it, so the
    // entry at `final_dir` verifies if read through.
    let decoy = home.path().join("decoy");
    std::fs::rename(&final_dir, &decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &final_dir).unwrap();
    verify_artifact(&final_dir).expect("precondition: the link reads as a valid artifact");

    let again = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes })
        .expect("a symlink at the target is replaced, not an error");
    assert_eq!(again.hash, meta.hash);

    let entry = std::fs::symlink_metadata(&final_dir).unwrap();
    assert!(
        entry.file_type().is_dir() && !entry.file_type().is_symlink(),
        "the artifact must be a real directory, not the adopted link: {:?}",
        entry.file_type()
    );
    verify_artifact(&final_dir).expect("the rebuilt artifact verifies");

    // The link was removed, never its target.
    assert_eq!(std::fs::read(decoy.join("fuz")).unwrap(), bytes);
    assert!(
        decoy.join("meta.json").is_file(),
        "the link target is untouched"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins that a plain **file** at the target `v1-<hash>` is treated as corrupt
/// and replaced. Removing it takes `remove_file` — the directory removal the
/// corrupt-dir branch uses refuses a file (`ENOTDIR`).
#[test]
fn create_replaces_a_plain_file_at_the_artifact_dir() {
    let (_home, _guard) = fresh_home();

    let bytes = fake_fuz(0x5D);
    let meta = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    let final_dir = get_artifact_dir(&meta.hash).unwrap();
    std::fs::remove_dir_all(&final_dir).unwrap();
    std::fs::write(&final_dir, b"not an artifact").unwrap();

    create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes })
        .expect("a plain file at the target is replaced, not an error");
    assert!(
        std::fs::symlink_metadata(&final_dir)
            .unwrap()
            .file_type()
            .is_dir(),
        "the artifact must be a real directory"
    );
    verify_artifact(&final_dir).expect("the rebuilt artifact verifies");

    clear_fuz_home_override_for_testing();
}

/// Pins that a **dangling** symlink at the target `v1-<hash>` — a link whose
/// target does not exist — is unlinked and the build lands a real directory.
#[test]
fn create_replaces_a_dangling_symlink_at_the_artifact_dir() {
    let (home, _guard) = fresh_home();

    let bytes = fake_fuz(0x5E);
    let meta = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    let final_dir = get_artifact_dir(&meta.hash).unwrap();
    std::fs::remove_dir_all(&final_dir).unwrap();
    std::os::unix::fs::symlink(home.path().join("nowhere"), &final_dir).unwrap();

    create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes })
        .expect("a dangling symlink at the target is replaced, not an error");
    let entry = std::fs::symlink_metadata(&final_dir).unwrap();
    assert!(
        entry.file_type().is_dir() && !entry.file_type().is_symlink(),
        "the artifact must be a real directory: {:?}",
        entry.file_type()
    );
    verify_artifact(&final_dir).expect("the rebuilt artifact verifies");
    assert!(
        !home.path().join("nowhere").exists(),
        "nothing is created at the link's target"
    );

    clear_fuz_home_override_for_testing();
}

/// Pins that `verify_artifact` reads neither `meta.json` nor `fuz` through a
/// symlink inside a real artifact directory — even a link aimed at the very
/// bytes the meta records, which would verify if followed. Fails if either
/// read follows the link.
#[test]
fn verify_refuses_a_symlink_inside_the_artifact_dir() {
    let (home, _guard) = fresh_home();

    let bytes = fake_fuz(0x6A);
    let meta = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    let dir = get_artifact_dir(&meta.hash).unwrap();

    // The binary: move it out and link to it.
    let outside_fuz = home.path().join("outside-fuz");
    std::fs::rename(dir.join("fuz"), &outside_fuz).unwrap();
    std::os::unix::fs::symlink(&outside_fuz, dir.join("fuz")).unwrap();
    let err = verify_artifact(&dir).expect_err("a linked binary must be refused");
    assert!(
        matches!(&err, ArtifactError::NotRegularFile(path) if *path == dir.join("fuz")),
        "got {err:?}"
    );
    assert!(err.hint().is_some(), "the refusal carries a hint");
    std::fs::remove_file(dir.join("fuz")).unwrap();
    std::fs::rename(&outside_fuz, dir.join("fuz")).unwrap();
    verify_artifact(&dir).expect("precondition: restored artifact verifies");

    // The meta: same shape.
    let outside_meta = home.path().join("outside-meta.json");
    std::fs::rename(dir.join("meta.json"), &outside_meta).unwrap();
    std::os::unix::fs::symlink(&outside_meta, dir.join("meta.json")).unwrap();
    let err = verify_artifact(&dir).expect_err("a linked meta.json must be refused");
    assert!(
        matches!(&err, ArtifactError::NotRegularFile(path) if *path == dir.join("meta.json")),
        "got {err:?}"
    );
    assert!(outside_meta.is_file(), "the link's target is untouched");

    clear_fuz_home_override_for_testing();
}

/// Pins that a real artifact directory whose `fuz` is a symlink is not adopted
/// as a duplicate: the verify refuses the link, the directory is removed as
/// corrupt — without following the link — and the build lands a real binary.
#[test]
fn create_rebuilds_over_a_symlinked_binary_in_the_artifact_dir() {
    let (home, _guard) = fresh_home();

    let bytes = fake_fuz(0x6B);
    let meta = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    let dir = get_artifact_dir(&meta.hash).unwrap();
    let outside_fuz = home.path().join("outside-fuz");
    std::fs::rename(dir.join("fuz"), &outside_fuz).unwrap();
    std::os::unix::fs::symlink(&outside_fuz, dir.join("fuz")).unwrap();

    create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes })
        .expect("a linked binary is rebuilt over, not an error");
    assert!(
        std::fs::symlink_metadata(dir.join("fuz"))
            .unwrap()
            .file_type()
            .is_file(),
        "the rebuilt binary is a regular file, not the adopted link"
    );
    verify_artifact(&dir).expect("the rebuilt artifact verifies");
    assert_eq!(
        std::fs::read(&outside_fuz).unwrap(),
        bytes,
        "the link's target is untouched"
    );

    clear_fuz_home_override_for_testing();
}

/// An artifact directory whose `meta.json` is valid and whose `fuz` is gone is
/// a corrupt entry, not a duplicate and not a read that might succeed on a
/// retry: it is removed and the artifact created again, so the hash is not
/// left unbuildable.
#[test]
fn create_rebuilds_an_artifact_dir_whose_binary_is_missing() {
    let (_home, _guard) = fresh_home();

    let bytes = fake_fuz(0x6C);
    let meta = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    let dir = get_artifact_dir(&meta.hash).unwrap();
    std::fs::remove_file(dir.join("fuz")).unwrap();
    // Left by the corrupt entry; a rebuild starts from an empty directory.
    std::fs::write(dir.join("stray"), b"stray").unwrap();

    let rebuilt = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes })
        .expect("a missing binary is rebuilt over, not an error");
    assert_eq!(rebuilt.hash, meta.hash);
    assert_eq!(std::fs::read(dir.join("fuz")).unwrap(), bytes);
    assert!(
        !dir.join("stray").exists(),
        "the corrupt entry was replaced"
    );
    verify_artifact(&dir).expect("the rebuilt artifact verifies");

    clear_fuz_home_override_for_testing();
}

/// A binary that is there and cannot be read is an I/O failure, not
/// corruption: the directory is kept as it is and the error returned.
#[test]
fn create_keeps_an_artifact_dir_whose_binary_it_cannot_read() {
    let (_home, _guard) = fresh_home();

    let bytes = fake_fuz(0x6D);
    let meta = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes }).unwrap();
    let dir = get_artifact_dir(&meta.hash).unwrap();
    let fuz = dir.join("fuz");
    std::fs::set_permissions(&fuz, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&fuz).is_ok() {
        eprintln!("skipping: running as root");
        clear_fuz_home_override_for_testing();
        return;
    }
    std::fs::write(dir.join("marker"), b"kept").unwrap();

    let err = create_artifact("0.1.0", BuildSource::Bootstrap { fuz_bytes: &bytes })
        .expect_err("an unreadable binary is an error");
    assert!(
        matches!(&err, ArtifactError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
    assert!(fuz.exists(), "the binary is still there");
    assert_eq!(std::fs::read(dir.join("marker")).unwrap(), b"kept");

    clear_fuz_home_override_for_testing();
}
