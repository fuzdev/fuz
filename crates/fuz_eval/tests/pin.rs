//! The `fgro` pin: the no-follow open, the hash, the stat-keyed cache and its
//! directory rule, and exec through the held descriptor.
//!
//! A copy of `/bin/true` stands in for `fgro`: any ELF binary exercises the open,
//! the hash, and the exec alike. A copy is written just now, so the real clock
//! never lets it be cached; the cache's hit path runs against `/bin/true` itself,
//! whose times settled long ago. (The crate's unit tests cover the cached path
//! for a fresh file with the clock moved ahead.)
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use fuz_eval::{
    DroppedTo, EvalError, FgroProblem, PinCacheDirProblem, establish_cache_dir, fgro_blake3,
    fgro_verify,
};

use common::Scratch;

/// Copy `/bin/true` to `<dir>/fgro`, executable.
fn elf_in(dir: &Path) -> PathBuf {
    let path = dir.join("fgro");
    std::fs::copy("/bin/true", &path).expect("copy /bin/true");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn blake3_of(path: &Path) -> String {
    blake3::hash(&std::fs::read(path).unwrap())
        .to_hex()
        .to_string()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// The cache directory's entries, temp files included.
fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    found.sort();
    found
}

/// The contents of a cache entry holding `blake3`, for the key its name says.
fn entry_contents(entry: &Path, blake3: &str) -> String {
    format!("{}{blake3}", entry.file_name().unwrap().to_str().unwrap())
}

/// The blake3 part of a cache entry: what follows the key hex its name repeats.
fn entry_blake3(entry: &Path) -> String {
    let name_len = entry.file_name().unwrap().len();
    std::fs::read_to_string(entry).unwrap()[name_len..].to_owned()
}

/// The one cache entry in `dir`.
fn only_entry(dir: &Path) -> PathBuf {
    let found = entries(dir);
    assert_eq!(found.len(), 1, "{found:?}");
    found.into_iter().next().unwrap()
}

/// Run `program`, retrying while it is `ETXTBSY`: a sibling test thread that
/// forks while this binary's copy is open for writing holds that descriptor
/// until its own exec.
fn status_of(program: &Path) -> std::io::Result<std::process::ExitStatus> {
    let mut tries = 0;
    loop {
        match Command::new(program).status() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 50 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            other => return other,
        }
    }
}

fn problem_of(result: Result<String, EvalError>) -> FgroProblem {
    match result {
        Err(EvalError::FgroUnusable { problem, .. }) => problem,
        other => panic!("expected FgroUnusable, got {other:?}"),
    }
}

fn cache_problem_of<T: std::fmt::Debug>(result: Result<T, EvalError>) -> PinCacheDirProblem {
    match result {
        Err(EvalError::PinCacheDir { problem, .. }) => problem,
        other => panic!("expected PinCacheDir, got {other:?}"),
    }
}

#[test]
fn hash_is_blake3_of_the_bytes() {
    let scratch = Scratch::new("pin_hash");
    let fgro = elf_in(scratch.path());
    let expected = blake3_of(&fgro);
    assert_eq!(fgro_blake3(&fgro, None).unwrap(), expected);
    let pinned = fgro_verify(&fgro, &expected, None).unwrap();
    assert_eq!(pinned.blake3(), expected);
    assert_eq!(pinned.path(), fgro);
}

#[test]
fn mismatch_names_path_expected_and_actual() {
    let scratch = Scratch::new("pin_mismatch");
    let fgro = elf_in(scratch.path());
    let wrong = "0".repeat(64);
    match fgro_verify(&fgro, &wrong, None) {
        Err(EvalError::PinMismatch {
            path,
            expected,
            actual,
        }) => {
            assert_eq!(path, fgro.display().to_string());
            assert_eq!(expected, wrong);
            assert_eq!(actual, blake3_of(&fgro));
        }
        other => panic!("expected PinMismatch, got {other:?}"),
    }
}

#[test]
fn symlinked_binary_is_refused() {
    let scratch = Scratch::new("pin_symlink");
    let fgro = elf_in(scratch.path());
    let link = scratch.path().join("link");
    std::os::unix::fs::symlink(&fgro, &link).unwrap();
    assert_eq!(problem_of(fgro_blake3(&link, None)), FgroProblem::Symlink);
    let error = fgro_verify(&link, &blake3_of(&fgro), None).unwrap_err();
    assert!(
        error.to_string().contains("not a wrapper script or a link"),
        "{error}"
    );
}

#[test]
fn unusable_binaries_are_refused() {
    let scratch = Scratch::new("pin_unusable");
    let dir = scratch.path();
    assert_eq!(
        problem_of(fgro_blake3(&dir.join("missing"), None)),
        FgroProblem::NotFound
    );
    assert_eq!(
        problem_of(fgro_blake3(dir, None)),
        FgroProblem::NotRegularFile
    );
    let script = dir.join("script");
    std::fs::write(&script, "#!/bin/sh\nexec fgro \"$@\"\n").unwrap();
    assert_eq!(problem_of(fgro_blake3(&script, None)), FgroProblem::Script);
    let text = dir.join("text");
    std::fs::write(&text, "not a binary").unwrap();
    assert_eq!(problem_of(fgro_blake3(&text, None)), FgroProblem::NotElf);
    let empty = dir.join("empty");
    std::fs::write(&empty, "").unwrap();
    assert_eq!(problem_of(fgro_blake3(&empty, None)), FgroProblem::NotElf);
}

#[test]
fn exec_through_the_held_descriptor_runs_the_binary() {
    let scratch = Scratch::new("pin_exec");
    let fgro = elf_in(scratch.path());
    let pinned = fgro_verify(&fgro, &blake3_of(&fgro), None).unwrap();
    let exec_path = pinned.exec_path();
    assert!(exec_path.starts_with("/proc/self/fd/"), "{exec_path:?}");
    assert!(status_of(&exec_path).unwrap().success());
}

/// The kernel behaviour the script refusal rests on: a `#!` file exec'd through
/// a close-on-exec descriptor starts its interpreter, which can't open the
/// `/proc/self/fd` path it is handed, since the exec closed that descriptor.
/// The spawn itself succeeds, so the refusal has to come before it.
#[test]
fn script_through_a_cloexec_descriptor_cannot_read_itself() {
    let scratch = Scratch::new("pin_script_exec");
    let script = scratch.path().join("script");
    std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A plain run of the script succeeds, so the failure below is the descriptor's.
    assert!(status_of(&script).unwrap().success());
    let held = std::fs::File::open(&script).unwrap();
    let exec_path = PathBuf::from(format!("/proc/self/fd/{}", held.as_raw_fd()));
    let output = Command::new(&exec_path).output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&exec_path.display().to_string()),
        "{stderr}"
    );
}

#[test]
fn spawn_error_names_the_binary_and_hints_at_enoent() {
    let scratch = Scratch::new("pin_spawn_error");
    let fgro = elf_in(scratch.path());
    let pinned = fgro_verify(&fgro, &blake3_of(&fgro), None).unwrap();
    let mapped = pinned.spawn_error(std::io::Error::from(std::io::ErrorKind::NotFound), None);
    assert!(matches!(mapped, EvalError::FgroSpawn { .. }), "{mapped:?}");
    let message = mapped.to_string();
    assert!(message.contains(&fgro.display().to_string()), "{message}");
    assert!(message.contains("dynamic loader"), "{message}");
    assert!(message.contains("not a wrapper script"), "{message}");
    let other = pinned.spawn_error(
        std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        None,
    );
    assert!(!other.to_string().contains("loader"), "{other}");
    assert!(!other.to_string().contains(" as uid "), "{other}");
    // after a drop from root, the message names who it ran as, and a refused
    // exec says that user needs execute permission
    let dropped = pinned.spawn_error(
        std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        Some(DroppedTo {
            uid: 1000,
            gid: 100,
        }),
    );
    let message = dropped.to_string();
    assert!(message.contains(" as uid 1000 (gid 100)"), "{message}");
    assert!(message.contains("execute permission"), "{message}");
    let dropped = pinned.spawn_error(
        std::io::Error::from(std::io::ErrorKind::NotFound),
        Some(DroppedTo {
            uid: 1000,
            gid: 100,
        }),
    );
    assert!(
        dropped.to_string().contains(" as uid 1000 (gid 100)"),
        "{dropped}"
    );
}

/// A set-user-ID or set-group-ID binary is refused, at the pin and when the pin
/// is recorded: its exec would not run with the ids the spawn sets.
#[test]
fn a_set_id_binary_is_refused() {
    let scratch = Scratch::new("pin_set_id");
    let fgro = elf_in(scratch.path());
    let pin = blake3_of(&fgro);
    for mode in [0o4755, 0o2755, 0o6755] {
        std::fs::set_permissions(&fgro, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            std::fs::metadata(&fgro).unwrap().mode() & 0o7777,
            mode,
            "the bit held"
        );
        assert_eq!(
            problem_of(fgro_blake3(&fgro, None)),
            FgroProblem::SetId,
            "{mode:o}"
        );
        let error = fgro_verify(&fgro, &pin, None).unwrap_err();
        assert!(
            matches!(
                error,
                EvalError::FgroUnusable {
                    problem: FgroProblem::SetId,
                    ..
                }
            ),
            "{mode:o}: {error:?}"
        );
    }
    std::fs::set_permissions(&fgro, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(fgro_blake3(&fgro, None).unwrap(), pin);
}

/// `/bin/true` as it is installed: an ELF binary whose mtime and ctime are well
/// past the settle margin, so the real clock caches its hash.
fn settled_elf() -> PathBuf {
    // The real file: `/bin/true` is a symlink on some systems (busybox, NixOS).
    let path = std::fs::canonicalize("/bin/true").unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = i64::try_from(now).unwrap();
    assert!(
        meta.mtime() < now - 10 && meta.ctime() < now - 10,
        "/bin/true was changed in the last few seconds"
    );
    path
}

#[test]
fn invalid_pin_is_refused_before_the_open() {
    let scratch = Scratch::new("pin_invalid");
    let missing = scratch.path().join("missing");
    let real = "0123456789abcdef".repeat(4);
    for pin in [
        String::new(),
        real.to_uppercase(),
        format!("{real}\n"),
        real[..63].to_owned(),
        "g".repeat(64),
    ] {
        match fgro_verify(&missing, &pin, None) {
            Err(EvalError::InvalidPin { pin: given }) => assert_eq!(given, pin),
            other => panic!("expected InvalidPin for {pin:?}, got {other:?}"),
        }
    }
    // A well-formed pin gets as far as the open.
    assert!(matches!(
        fgro_verify(&missing, &real, None),
        Err(EvalError::FgroUnusable {
            problem: FgroProblem::NotFound,
            ..
        })
    ));
}

#[test]
fn held_descriptor_is_close_on_exec() {
    let scratch = Scratch::new("pin_cloexec");
    let fgro = elf_in(scratch.path());
    let pinned = fgro_verify(&fgro, &blake3_of(&fgro), None).unwrap();
    let fd = pinned
        .exec_path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap();
    let flags = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .map(|flags| u32::from_str_radix(flags.trim(), 8).unwrap())
        .unwrap();
    // O_CLOEXEC is 02000000 on every Linux architecture.
    assert_ne!(flags & 0o2_000_000, 0, "flags {flags:o}");
}

#[test]
fn missing_cache_dir_is_created_0700() {
    let scratch = Scratch::new("pin_cache_create");
    let fgro = settled_elf();
    let cache = scratch.path().join("cache");
    assert_eq!(fgro_blake3(&fgro, Some(&cache)).unwrap(), blake3_of(&fgro));
    assert_eq!(mode_of(&cache), 0o700);
    let entry = only_entry(&cache);
    assert_eq!(
        std::fs::read_to_string(&entry).unwrap(),
        entry_contents(&entry, &blake3_of(&fgro))
    );
    assert_eq!(mode_of(&entry), 0o600);
}

/// The racily-clean rule: a binary written within the settle margin is hashed
/// every time and leaves no entry, so a rewrite in the same timestamp tick can't
/// be answered from the cache.
#[test]
fn just_written_binary_leaves_no_entry() {
    let scratch = Scratch::new("pin_cache_fresh");
    let fgro = elf_in(scratch.path());
    let cache = scratch.path().join("cache");
    let first = fgro_blake3(&fgro, Some(&cache)).unwrap();
    assert_eq!(first, blake3_of(&fgro));
    assert!(entries(&cache).is_empty());
    // A same-size rewrite, likely within the same tick, is seen.
    let mut bytes = std::fs::read(&fgro).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    std::fs::write(&fgro, &bytes).unwrap();
    let second = fgro_verify(&fgro, blake3::hash(&bytes).to_hex().as_ref(), Some(&cache));
    assert!(second.is_ok(), "{second:?}");
    assert!(matches!(
        fgro_verify(&fgro, &first, Some(&cache)),
        Err(EvalError::PinMismatch { .. })
    ));
    assert!(entries(&cache).is_empty());
}

#[test]
fn cache_dir_with_a_missing_parent_is_refused() {
    let scratch = Scratch::new("pin_cache_parent");
    let fgro = elf_in(scratch.path());
    let cache = scratch.path().join("absent").join("cache");
    assert_eq!(
        cache_problem_of(fgro_blake3(&fgro, Some(&cache))),
        PinCacheDirProblem::Uncreatable
    );
}

#[test]
fn symlinked_cache_dir_is_refused() {
    let scratch = Scratch::new("pin_cache_symlink");
    let fgro = settled_elf();
    let real = scratch.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    let link = scratch.path().join("cache");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        cache_problem_of(fgro_blake3(&fgro, Some(&link))),
        PinCacheDirProblem::Symlink
    );
    // Nothing went through the link: the target is untouched.
    assert_eq!(mode_of(&real), 0o755);
    assert!(entries(&real).is_empty());
}

#[test]
fn file_as_cache_dir_is_refused() {
    let scratch = Scratch::new("pin_cache_file");
    let cache = scratch.path().join("cache");
    std::fs::write(&cache, "").unwrap();
    assert_eq!(
        cache_problem_of(establish_cache_dir(&cache)),
        PinCacheDirProblem::NotDirectory
    );
}

/// The other-owner refusal for a directory this user can't own: `/`, when the
/// suite isn't running as root. The crate's unit tests cover it for any user,
/// through an owner uid that isn't the euid.
#[test]
fn root_owned_cache_dir_is_refused() {
    let root_owned = std::fs::metadata("/").unwrap();
    let mine = std::fs::metadata(env!("CARGO_TARGET_TMPDIR")).unwrap();
    if mine.uid() == root_owned.uid() {
        return;
    }
    assert_eq!(
        cache_problem_of(establish_cache_dir(Path::new("/"))),
        PinCacheDirProblem::OtherOwner
    );
}

#[test]
fn loose_cache_dir_is_tightened() {
    let scratch = Scratch::new("pin_cache_loose");
    let fgro = settled_elf();
    let cache = scratch.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o777)).unwrap();
    fgro_blake3(&fgro, Some(&cache)).unwrap();
    assert_eq!(mode_of(&cache), 0o700);
}

#[test]
fn cache_hit_skips_the_hash() {
    let scratch = Scratch::new("pin_cache_hit");
    let fgro = settled_elf();
    let cache = scratch.path().join("cache");
    fgro_blake3(&fgro, Some(&cache)).unwrap();
    // An entry the bytes don't match is believed while the stat key holds: the
    // directory is the euid's own record.
    let planted = "a".repeat(64);
    let entry = only_entry(&cache);
    std::fs::write(&entry, entry_contents(&entry, &planted)).unwrap();
    assert_eq!(fgro_blake3(&fgro, Some(&cache)).unwrap(), planted);
    assert_eq!(
        fgro_verify(&fgro, &planted, Some(&cache)).unwrap().blake3(),
        planted
    );
    // Without the cache the bytes are hashed.
    assert_eq!(fgro_blake3(&fgro, None).unwrap(), blake3_of(&fgro));
}

#[test]
fn garbage_cache_entry_is_a_miss() {
    let scratch = Scratch::new("pin_cache_garbage");
    let fgro = settled_elf();
    let cache = scratch.path().join("cache");
    fgro_blake3(&fgro, Some(&cache)).unwrap();
    let entry = only_entry(&cache);
    let real = blake3_of(&fgro);
    for garbage in [
        entry_contents(&entry, "garbage"),
        entry_contents(&entry, &real.to_uppercase()),
        entry_contents(&entry, &format!("{real}\n")),
        entry_contents(&entry, &"z".repeat(64)),
        // The bare blake3, with no key.
        real.clone(),
        String::new(),
    ] {
        std::fs::write(&entry, &garbage).unwrap();
        assert_eq!(
            fgro_blake3(&fgro, Some(&cache)).unwrap(),
            real,
            "{garbage:?}"
        );
        // The miss rewrote the entry.
        assert_eq!(
            std::fs::read_to_string(&entry).unwrap(),
            entry_contents(&entry, &real)
        );
    }
    // A symlink at the entry's name is a miss, and is left in place: the write
    // refuses it, and its target is never written.
    let elsewhere = scratch.path().join("elsewhere");
    let planted = entry_contents(&entry, &"a".repeat(64));
    std::fs::write(&elsewhere, &planted).unwrap();
    std::fs::remove_file(&entry).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &entry).unwrap();
    assert_eq!(fgro_blake3(&fgro, Some(&cache)).unwrap(), real);
    assert!(entry.is_symlink());
    assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), planted);
}

/// An entry another party could still write — a second link to it, or a group-
/// or other-writable mode left from before the directory was tightened — is a
/// miss, and the miss replaces the name with the euid's own file.
#[test]
fn shared_cache_entry_is_a_miss() {
    let scratch = Scratch::new("pin_cache_shared");
    let fgro = settled_elf();
    let cache = scratch.path().join("cache");
    fgro_blake3(&fgro, Some(&cache)).unwrap();
    let entry = only_entry(&cache);
    let real = blake3_of(&fgro);
    let planted = entry_contents(&entry, &"a".repeat(64));

    std::fs::write(&entry, &planted).unwrap();
    let other = scratch.path().join("other");
    std::fs::hard_link(&entry, &other).unwrap();
    assert_eq!(fgro_blake3(&fgro, Some(&cache)).unwrap(), real);
    assert_eq!(entry_blake3(&entry), real);
    assert_eq!(std::fs::read_to_string(&other).unwrap(), planted);

    for mode in [0o620, 0o602] {
        std::fs::write(&entry, &planted).unwrap();
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(fgro_blake3(&fgro, Some(&cache)).unwrap(), real, "{mode:o}");
        assert_eq!(mode_of(&entry), 0o600);
    }
}

#[test]
fn concurrent_writers_leave_one_whole_entry() {
    let scratch = Scratch::new("pin_cache_concurrent");
    let fgro = settled_elf();
    let cache = scratch.path().join("cache");
    establish_cache_dir(&cache).unwrap();
    let real = blake3_of(&fgro);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..20 {
                    // Each round starts cold, so every thread writes.
                    for entry in entries(&cache) {
                        let _ = std::fs::remove_file(entry);
                    }
                    assert_eq!(fgro_blake3(&fgro, Some(&cache)).unwrap(), real);
                }
            });
        }
    });
    fgro_blake3(&fgro, Some(&cache)).unwrap();
    let entry = only_entry(&cache);
    assert_eq!(entry_blake3(&entry), real);
}
