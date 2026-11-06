//! fuzd-specific PID verification.
//!
//! Generic pid liveness / signal sending lives in `fuz_sys::pid`; this is the
//! fuzd-aware check used by the force-kill path to guard against PID reuse.
//!
//! **Linux-only by construction**: the check reads `/proc/<pid>/comm`, and
//! fuzd itself runs only on Linux. The crate still compiles everywhere (plain
//! `std::fs`); where `/proc` is absent (macOS) every pid reads as "not
//! fuzd", which is the fail-closed answer — there is no fuzd there to signal.

use std::fs;
use std::path::Path;

/// Whether `pid` is a running fuzd process, confirmed from
/// `/proc/<pid>/comm`.
///
/// Defense against PID reuse on the force-kill path (`fuzd stop --force`,
/// `cargo xtask clean`) and in the daemon's lock-holder liveness check: a pid
/// recorded for a daemon that has since died may now belong to an unrelated
/// process, and signaling it would kill the wrong thing.
///
/// **Fails closed**: returns `true` only when the command name is read and is
/// exactly `fuzd`. Anything that cannot confirm it — a pid `<= 0`, no such
/// process, an unreadable `comm`, a host without `/proc` — is `false`. No
/// subprocess is spawned.
///
/// This is also the whole "live fuzd" check: `comm` is readable only while
/// `/proc/<pid>` exists, so a separate liveness probe adds nothing. A pid that
/// is alive but no longer fuzd was reused after the daemon died (and the
/// daemon's `flock` died with it), so it counts as gone. A zombie still counts
/// as live — its `/proc` entry and command name remain until its parent reaps
/// it, and a daemon `fuzd start` spawned is reparented on the CLI's exit, so
/// its reaper is prompt.
///
/// The kernel truncates `comm` to 15 bytes; `fuzd` fits, so the match is exact.
#[must_use]
pub fn verify_pid_is_fuzd(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    comm_file_is_fuzd(&Path::new("/proc").join(pid.to_string()).join("comm"))
}

/// Whether the `comm` file at `path` names fuzd; `false` whenever it can't be
/// read.
///
/// Split from [`verify_pid_is_fuzd`] so the fail-closed branch and the
/// positive match are unit-testable against an injected file, without spawning
/// a process named `fuzd`.
fn comm_file_is_fuzd(path: &Path) -> bool {
    fs::read(path).is_ok_and(|comm| comm_is_fuzd(&comm))
}

/// Whether a `/proc/<pid>/comm` value names fuzd, by **exact** match after
/// dropping the one trailing newline the kernel appends.
///
/// Exact, not prefix/substring/whitespace-insensitive: a sibling process named
/// `fuzd-old`, `fuzd_backup`, or ` fuzd` must NOT be mistaken for fuzd on the
/// force-kill path (a false positive kills the wrong process; PID reuse makes
/// this real). A byte compare, so a name that isn't UTF-8 is simply a
/// mismatch. Pure so the rejection contract is unit-testable without spawning
/// such processes.
fn comm_is_fuzd(comm: &[u8]) -> bool {
    comm.strip_suffix(b"\n").unwrap_or(comm) == b"fuzd"
}

#[cfg(test)]
mod tests {
    // The current PID fits i32 on every supported platform; the `as i32` cast
    // reads cleaner than `i32::try_from(...).unwrap()` in these assertions.
    #![allow(clippy::cast_possible_wrap)]
    use super::*;

    #[test]
    fn test_verify_pid_is_fuzd_current_process() {
        // A live process that is not fuzd (the test runner): readable, wrong name.
        let pid = std::process::id() as i32;
        assert!(!verify_pid_is_fuzd(pid));
    }

    #[test]
    fn verify_pid_is_fuzd_confirms_a_live_process_named_fuzd() {
        // The kernel sets `comm` from the exec'd path's basename, so a symlink
        // named `fuzd` gives a stand-in process fuzd's command name.
        let dir = tempfile::tempdir().unwrap();
        let fake_fuzd = dir.path().join("fuzd");
        std::os::unix::fs::symlink("/bin/sleep", &fake_fuzd).unwrap();
        let mut child = std::process::Command::new(&fake_fuzd)
            .arg("30")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Poll briefly: under load, `comm` can still read the pre-exec name
        // right after `spawn` returns.
        let pid = child.id() as i32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut confirmed = verify_pid_is_fuzd(pid);
        while !confirmed && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
            confirmed = verify_pid_is_fuzd(pid);
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(confirmed, "a live process whose comm is `fuzd` is fuzd");
    }

    #[test]
    fn verify_pid_is_fuzd_fails_closed_on_a_missing_pid() {
        // No such process — nothing confirms fuzd, so it is not fuzd.
        assert!(!verify_pid_is_fuzd(i32::MAX));
    }

    #[test]
    fn verify_pid_is_fuzd_refuses_non_positive_pids() {
        // `0` and negatives name process groups to `kill(2)`, never one process.
        assert!(!verify_pid_is_fuzd(0));
        assert!(!verify_pid_is_fuzd(-1));
        assert!(!verify_pid_is_fuzd(i32::MIN));
    }

    #[test]
    fn comm_file_is_fuzd_matches_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();

        let fuzd = dir.path().join("fuzd_comm");
        fs::write(&fuzd, b"fuzd\n").unwrap();
        assert!(comm_file_is_fuzd(&fuzd), "the kernel's `fuzd\\n` is fuzd");

        let other = dir.path().join("other_comm");
        fs::write(&other, b"bash\n").unwrap();
        assert!(!comm_file_is_fuzd(&other));

        assert!(
            !comm_file_is_fuzd(&dir.path().join("missing")),
            "an unreadable comm fails closed"
        );
        assert!(
            !comm_file_is_fuzd(dir.path()),
            "a directory (read error) fails closed"
        );
    }

    #[test]
    fn comm_is_fuzd_matches_exactly() {
        // The contract the doc comment promises: exact match, not prefix /
        // substring / trimmed — so a sibling `fuzd-old` / ` fuzd` is never killed.
        assert!(comm_is_fuzd(b"fuzd"));
        assert!(comm_is_fuzd(b"fuzd\n")); // the kernel appends one newline
        assert!(!comm_is_fuzd(b" fuzd\n"));
        assert!(!comm_is_fuzd(b"fuzd \n"));
        assert!(!comm_is_fuzd(b"fuzd\n\n"));
        assert!(!comm_is_fuzd(b"fuzd-old"));
        assert!(!comm_is_fuzd(b"fuzd_backup"));
        assert!(!comm_is_fuzd(b"fuzdx"));
        assert!(!comm_is_fuzd(b"myfuzd"));
        assert!(!comm_is_fuzd(b"fuzd fuzd"));
        assert!(!comm_is_fuzd(b""));
    }
}
