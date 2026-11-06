//! Cross-cutting file-lock helper backed by `flock(2)`.
//!
//! `flock` is an advisory, kernel-tracked lock on an open file description.
//! The kernel releases the lock when the file descriptor is closed
//! (including on process exit, even SIGKILL), so there is no stale-lock
//! recovery to do and no PID-reuse confusion.
//!
//! The lock file body holds a JSON [`LockInfo`] payload so a human can run
//! `cat ~/.fuz/run/<name>.lock` and see who holds it. The locking semantics
//! come from `flock`, not from the payload.
//!
//! ## The body as a decision input
//!
//! [`read_lock_holder`] reads the body without locking, and a caller may act on
//! it — `fuzd start` uses it to tell its own child's health answer from another
//! daemon's, and `fuzd stop` to tell a daemon that has let go of its socket path
//! from one still holding it. That is sound only for a holder that keeps a
//! fixed order, as fuzd does: it writes its pid right after taking the lock and
//! before doing anything observable under it (binding its socket), and
//! [`FileLock`]'s `Drop` truncates the body *while still holding* the lock. So
//! anyone who observed the holder's work reads the holder's pid, and an empty
//! body means the lock is released or about to be. What the body cannot say is
//! whether a lock is held at all: a holder killed outright leaves its pid
//! behind (the kernel drops the `flock`, nothing truncates), so a caller pairs
//! a stale-looking pid with a liveness check. Probing with a `flock` of its own
//! instead would be worse — it could make a holder starting at that moment
//! fail its acquire.
//!
//! ## Why the lock file is not removed on release
//!
//! `flock` locks live on the *inode*, not the path. Removing the file in
//! `Drop` (after releasing the flock) creates a race window: another acquirer
//! that already opened the path holds an fd to the original inode and can
//! flock it (we just released), while a *third* acquirer comes in after the
//! unlink, finds the path missing, creates a fresh inode, and flocks that —
//! two processes now hold "the lock" on different inodes. To stay correct we
//! truncate the body on release but leave the dirent in place; the next
//! acquirer reuses the same inode and the kernel arbitrates honestly.

#![allow(clippy::missing_errors_doc)]

use crate::time::rfc3339_now;
use crate::{SECURE_DIR_MODE, SECURE_FILE_MODE};
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// JSON body written into a lock file for human inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub pid: u32,
    pub started_at: String,
}

impl LockInfo {
    /// Build a `LockInfo` for the current process at the current time.
    #[must_use]
    pub fn current() -> Self {
        Self {
            pid: std::process::id(),
            started_at: rfc3339_now(),
        }
    }
}

/// Errors raised when acquiring a file lock.
///
/// Specific call sites (build lock, publish lock) translate these into their
/// own error types so user-facing messages stay domain-appropriate.
#[derive(Debug, thiserror::Error)]
pub enum FileLockError {
    /// Another process holds the lock. `pid` is the holder's pid if the
    /// lock file body was parseable, otherwise `None` (raced acquire
    /// before the holder wrote its content, or someone hand-edited the
    /// lock file).
    #[error("lock held by {}", display_pid(*pid))]
    Held { pid: Option<u32> },

    /// IO error opening, reading, writing, or truncating the lock file.
    #[error("file lock io error: {0}")]
    Io(#[source] std::io::Error),

    /// `flock(2)` itself failed with an unexpected errno (not EWOULDBLOCK).
    #[error("flock failed: {0}")]
    Flock(#[source] nix::Error),
}

/// RAII handle holding an exclusive `flock` on a file.
///
/// On drop we truncate the body (so `cat` of the lock path doesn't surface
/// the previous holder's pid) and then release the kernel flock. We do *not*
/// unlink the file — see the module-level note on why removing it would
/// reintroduce a multi-holder race.
#[derive(Debug)]
pub struct FileLock {
    flock: Option<Flock<File>>,
}

impl FileLock {
    /// Acquire an exclusive non-blocking lock on `path`, writing `info` as
    /// the file body.
    ///
    /// Returns [`FileLockError::Held`] immediately if another process holds
    /// the lock. The holder's pid is read from the existing file body; if the
    /// body is empty or unparseable, the pid is `None`.
    pub fn acquire(path: &Path, info: &LockInfo) -> Result<Self, FileLockError> {
        // Ensure the parent dir exists (e.g. `~/.fuz/run/` before the first
        // build or daemon start), at a stated mode rather than the umask's.
        // The create is recursive, so on a tree that does not exist at all this
        // is what mints its *ancestors* too, and a caller that runs the lock
        // before any other setup would otherwise publish the whole chain at
        // `0o777 & !umask`.
        //
        // The mode is not a parameter and not the caller's business: the lock
        // file itself opens `SECURE_FILE_MODE`, so a directory created solely
        // to hold it is owner-only by the same reasoning. A world-writable one
        // would let another local user unlink the lock file and create their
        // own inode at the path — and `flock` locks the inode, so two holders
        // would each believe they hold the lock, the multi-holder race the
        // module note above explains we keep the dirent to avoid.
        //
        // A pre-existing directory is left exactly as it is.
        if let Some(parent) = path.parent() {
            crate::fs::create_dir_all_mode(parent, SECURE_DIR_MODE).map_err(FileLockError::Io)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(SECURE_FILE_MODE)
            .open(path)
            .map_err(FileLockError::Io)?;

        let mut locked = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(l) => l,
            Err((mut file, errno)) if is_wouldblock(errno) => {
                // Another process holds the lock. Read the existing body
                // for the diagnostic pid; file position is at 0 since we
                // just opened it.
                let pid = read_holder_pid(&mut file);
                return Err(FileLockError::Held { pid });
            }
            Err((_file, errno)) => return Err(FileLockError::Flock(errno)),
        };

        // Truncate any prior content (a previous holder may have left their
        // own pid) and write ours. Seek to 0 first so writes start at the
        // beginning even if the kernel placed us mid-file after open.
        locked.set_len(0).map_err(FileLockError::Io)?;
        locked.seek(SeekFrom::Start(0)).map_err(FileLockError::Io)?;
        let body = serde_json::to_string(info)
            .map_err(|e| FileLockError::Io(std::io::Error::other(e.to_string())))?;
        locked
            .write_all(body.as_bytes())
            .map_err(FileLockError::Io)?;

        Ok(Self {
            flock: Some(locked),
        })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Truncate the body *while still holding the lock* so concurrent
        // readers see "no current holder" without us racing the next
        // acquirer. Then release the flock by dropping the Flock<File>
        // (which closes the fd). Do not unlink the file — see the module
        // doc for why removing it would let two acquirers hold the lock on
        // different inodes simultaneously.
        if let Some(locked) = self.flock.take() {
            let _ = locked.set_len(0);
            drop(locked);
        }
    }
}

/// On Linux (and current macOS) `EWOULDBLOCK == EAGAIN`, so matching the
/// single variant covers both.
const fn is_wouldblock(e: Errno) -> bool {
    matches!(e, Errno::EWOULDBLOCK)
}

/// Read the pid a lock file's body names, without taking the lock.
///
/// `None` when the file is missing or unreadable, or its body is empty (no
/// holder, or a holder between taking the lock and writing its pid) or not a
/// [`LockInfo`]. The body is a holder's self-report, not proof the lock is held
/// — see the module note on using it as a decision input.
#[must_use]
pub fn read_lock_holder(path: &Path) -> Option<u32> {
    let mut file = File::open(path).ok()?;
    read_holder_pid(&mut file)
}

/// Best-effort: read the lock file body and extract the holder pid.
/// Empty or unparseable bodies return `None` so callers can show
/// "pid unknown" rather than "pid 0".
fn read_holder_pid(file: &mut File) -> Option<u32> {
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;
    serde_json::from_str::<LockInfo>(&buf)
        .ok()
        .map(|info| info.pid)
}

/// Format an optional holder pid for error messages.
fn display_pid(pid: Option<u32>) -> String {
    pid.map_or_else(|| "pid unknown".to_string(), |p| format!("pid {p}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn lock_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir();
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(name);
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn acquire_and_release_via_drop() {
        let path = lock_path("file_lock_acquire_release.test.lock");
        let info = LockInfo::current();
        let lock = FileLock::acquire(&path, &info).expect("first acquire");
        drop(lock);
        // After drop, a new acquire must succeed.
        let _lock2 = FileLock::acquire(&path, &info).expect("re-acquire after drop");
    }

    /// The parent directory `acquire` mints carries the stated mode at every
    /// level it creates, not `0o777 & !umask`.
    ///
    /// `acquire` is the *only* thing some flows touch before anything else has
    /// set up the tree (`fuz artifact build` / `use` on a machine where fuz has
    /// never run), so a `create_dir_all` here publishes the whole ancestor
    /// chain at whatever umask launched the process.
    ///
    /// 0700 is the tightest mode a create can land, so at `umask 077` an
    /// unmoded create coincides with the pin and this is vacuous; it
    /// discriminates under every umask that can produce the exposure (0775 at
    /// `002`, 0755 at `022`, 0777 at `000`).
    #[test]
    fn acquire_creates_missing_parents_at_the_stated_mode() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temp dir");
        let nested = root.path().join("outer/run");
        let _lock = FileLock::acquire(&nested.join("x.lock"), &LockInfo::current())
            .expect("acquire creates the parents it needs");

        for dir in [root.path().join("outer"), nested] {
            assert_eq!(
                fs::metadata(&dir).expect("stat").permissions().mode() & 0o777,
                SECURE_DIR_MODE,
                "{dir:?} must carry the stated mode, not the umask's"
            );
        }
    }

    #[test]
    fn concurrent_acquire_returns_held() {
        let path = lock_path("file_lock_concurrent.test.lock");
        let info = LockInfo::current();
        let _held = FileLock::acquire(&path, &info).expect("first acquire");
        match FileLock::acquire(&path, &info) {
            Err(FileLockError::Held { pid }) => {
                assert_eq!(
                    pid,
                    Some(std::process::id()),
                    "held should report our own pid"
                );
            }
            other => panic!("expected Held, got {other:?}"),
        }
    }

    /// The unlocked reader names a live holder, and nothing once it releases,
    /// for a missing file, or for a body that is not a `LockInfo`.
    #[test]
    fn read_lock_holder_reads_the_holder_pid_from_the_body() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("holder.lock");
        assert_eq!(read_lock_holder(&path), None, "missing file");

        let lock = FileLock::acquire(&path, &LockInfo::current()).expect("acquire");
        assert_eq!(read_lock_holder(&path), Some(std::process::id()));
        drop(lock);
        assert_eq!(read_lock_holder(&path), None, "released: body truncated");

        fs::write(&path, r#"{"pid":4242,"started_at":"2020-01-01T00:00:00Z"}"#).expect("seed");
        assert_eq!(
            read_lock_holder(&path),
            Some(4242),
            "an unheld body is still read — the reader is not a liveness check"
        );
        fs::write(&path, "not json").expect("seed garbage");
        assert_eq!(read_lock_holder(&path), None, "unparseable body");
    }

    #[test]
    fn release_truncates_body_but_preserves_dirent() {
        // After Drop, the file should still exist (so the next acquirer
        // reuses the same inode and the kernel arbitrates correctly) and
        // its body should be empty (so `cat` doesn't surface stale info).
        let path = lock_path("file_lock_release_truncates.test.lock");
        let info = LockInfo::current();
        let lock = FileLock::acquire(&path, &info).expect("acquire");
        let before = fs::read_to_string(&path).expect("read held body");
        assert!(
            before.contains(&std::process::id().to_string()),
            "held lock should have our pid in body"
        );
        drop(lock);

        assert!(path.exists(), "lock file should persist after release");
        let after = fs::read_to_string(&path).expect("read released body");
        assert!(
            after.is_empty(),
            "released lock body should be empty, got {after:?}"
        );
    }

    #[test]
    fn stale_unlocked_file_is_overwritten() {
        // Simulate a prior process that crashed before flock release:
        // the file exists with stale content but nobody holds the lock.
        // (In practice flock auto-releases on process death, so this is
        // only possible if a non-flock tool wrote the file — but the
        // behavior we want is the same: take over cleanly.)
        let path = lock_path("file_lock_stale.test.lock");
        fs::write(
            &path,
            r#"{"pid":99999999,"started_at":"2020-01-01T00:00:00Z"}"#,
        )
        .expect("seed stale content");
        let info = LockInfo::current();
        let _lock = FileLock::acquire(&path, &info).expect("acquire over stale file");
        let body = fs::read_to_string(&path).expect("read lock file");
        // Our content should have replaced the stale body.
        assert!(body.contains(&std::process::id().to_string()));
    }
}
