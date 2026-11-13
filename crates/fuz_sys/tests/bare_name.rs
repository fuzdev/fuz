//! The atomic writers given a bare file name — a path with no directory part,
//! which names a file in the working directory.
//!
//! Each writer is run in a child process whose working directory is a fresh
//! tempdir: the parent test spawns this test binary again, running only
//! [`bare_name_child`] there, so no test changes the test process's own
//! working directory or writes beside the sources.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use fuz_sys::file_lock::{FileLock, LockInfo};
use fuz_sys::fs::{replace_symlink_atomic, write_atomic};
use fuz_sys::secure_file::write_secure_file;

/// Names the writer the child runs. Unset in an ordinary test run, where the
/// child test does nothing.
const WRITER_ENV: &str = "FUZ_SYS_BARE_NAME_WRITER";

/// The child half: run one writer on a bare file name in the working
/// directory the parent chose. A failure is a panic, which the parent sees as
/// the child's exit status.
#[test]
#[ignore = "run by the tests below, in a scratch working directory"]
fn bare_name_child() {
    let Some(writer) = std::env::var_os(WRITER_ENV) else {
        return;
    };
    match writer.to_str().unwrap() {
        "write_atomic" => write_atomic(Path::new("bare"), b"atomic", 0o640).unwrap(),
        "write_atomic_dot" => write_atomic(Path::new("./bare"), b"atomic", 0o640).unwrap(),
        "write_atomic_twice" => {
            write_atomic(Path::new("bare"), b"first", 0o640).unwrap();
            write_atomic(Path::new("bare"), b"atomic", 0o640).unwrap();
        }
        "replace_symlink_atomic" => {
            replace_symlink_atomic(Path::new("first"), Path::new("bare")).unwrap();
            replace_symlink_atomic(Path::new("target"), Path::new("bare")).unwrap();
        }
        "write_secure_file" => write_secure_file(Path::new("bare"), b"secret", 0o600).unwrap(),
        "file_lock" => {
            let _lock = FileLock::acquire(Path::new("bare"), &LockInfo::current()).unwrap();
        }
        other => panic!("unknown writer {other}"),
    }
}

/// Run `writer` on the bare name `bare` in a fresh working directory, require
/// that it succeeded, and return that directory.
fn run_writer(writer: &str) -> tempfile::TempDir {
    let cwd = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "bare_name_child"])
        .current_dir(cwd.path())
        .env(WRITER_ENV, writer)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{writer} failed on a bare file name:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // The child test ran, rather than being filtered out.
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "{writer}: the child test did not run"
    );
    cwd
}

/// The names in `dir`, sorted.
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

/// `write_atomic` writes the file in the working directory, at its mode, and
/// leaves no temp file — for a bare name, for `./name`, and when replacing.
#[test]
fn write_atomic_takes_a_bare_file_name() {
    for writer in ["write_atomic", "write_atomic_dot", "write_atomic_twice"] {
        let cwd = run_writer(writer);
        assert_eq!(entries(cwd.path()), ["bare"], "{writer}");
        let file = cwd.path().join("bare");
        assert_eq!(std::fs::read(&file).unwrap(), b"atomic", "{writer}");
        assert_eq!(mode(&file), 0o640, "{writer}");
    }
}

/// `replace_symlink_atomic` creates, then replaces, a link named by a bare
/// file name.
#[test]
fn replace_symlink_atomic_takes_a_bare_link_name() {
    let cwd = run_writer("replace_symlink_atomic");
    assert_eq!(entries(cwd.path()), ["bare"]);
    assert_eq!(
        std::fs::read_link(cwd.path().join("bare")).unwrap(),
        Path::new("target")
    );
}

/// `write_secure_file` writes a bare-named file in the working directory, at
/// its mode, and leaves no temp file.
#[test]
fn write_secure_file_takes_a_bare_file_name() {
    let cwd = run_writer("write_secure_file");
    assert_eq!(entries(cwd.path()), ["bare"]);
    let file = cwd.path().join("bare");
    assert_eq!(std::fs::read(&file).unwrap(), b"secret");
    assert_eq!(mode(&file), 0o600);
}

/// A lock file named by a bare file name is taken in the working directory:
/// its parent directory, which the lock creates when missing, is already there.
#[test]
fn file_lock_takes_a_bare_file_name() {
    let cwd = run_writer("file_lock");
    assert_eq!(entries(cwd.path()), ["bare"]);
}
