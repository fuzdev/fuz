//! daemon.json write → read → cleanup lifecycle against a redirected home — the
//! actual file I/O the pure `classify_daemon_json` unit tests can't reach
//! (secure modes, atomic temp+rename, the stale/corrupt cleanup branches).
//!
//! Driven through the dev-only `test_home_override` seam (an in-process
//! `FUZ_HOME` redirect, since edition 2024 + `unsafe_code = forbid` rule out
//! `std::env::set_var`). The override is a process global, so a serial guard
//! keeps these tests from racing each other.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use fuz_home::{
    MaybeDaemonInfo, current_daemon_info, read_daemon_info, read_daemon_info_typed,
    remove_daemon_file, write_daemon_info,
};
use fuz_sys::SECURE_DIR_MODE;

static SERIAL: Mutex<()> = Mutex::new(());

/// A fresh temp home, pinned to `0700` and installed as the process-wide
/// `~/.fuz` override. The returned `TempDir` must outlive the test body.
///
/// The mode is **set**, not inherited. `tempfile::tempdir()` creates at the std
/// default `0o777` masked by the process umask, so under a permissive runner
/// umask (`umask 000`, routine in containers) the home would arrive
/// world-writable and `write_daemon_info` — which routes through
/// `ensure_fuz_home` — would refuse it. `SECURE_DIR_MODE` is what
/// `ensure_fuz_home` itself creates.
fn fresh_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        home.path(),
        std::fs::Permissions::from_mode(SECURE_DIR_MODE),
    )
    .unwrap();
    fuz_home::set_fuz_home_override_for_testing(home.path());
    home
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Our own pid is alive, so a v2 file is never mistaken for stale.
fn live_pid() -> i32 {
    i32::try_from(std::process::id()).unwrap()
}

/// write → read round-trips the current info, and the on-disk modes are secure:
/// daemon.json is owner-only (0600) and its `run/` dir is 0700.
#[test]
fn write_read_roundtrip_and_secure_modes() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _home = fresh_home();

    let info = current_daemon_info(live_pid()).unwrap();
    let path = write_daemon_info(&info).unwrap();

    assert_eq!(mode(&path), 0o600, "daemon.json is owner-only");
    assert_eq!(
        mode(path.parent().unwrap()),
        0o700,
        "the run/ dir ensure_fuz_home created is 0700"
    );

    match read_daemon_info_typed().unwrap() {
        MaybeDaemonInfo::Current(got) => {
            assert_eq!(got.pid, info.pid);
            assert_eq!(got.version, info.version);
            assert_eq!(got.socket_path, info.socket_path);
        }
        other => panic!("expected Current, got {other:?}"),
    }
    assert!(
        read_daemon_info().unwrap().is_some(),
        "the folded reader also returns the info"
    );

    fuz_home::clear_fuz_home_override_for_testing();
}

/// remove deletes the file (and reads back Missing); removing an absent file is
/// a no-op, not an error.
#[test]
fn remove_then_read_is_missing() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _home = fresh_home();

    write_daemon_info(&current_daemon_info(live_pid()).unwrap()).unwrap();
    remove_daemon_file().unwrap();
    assert!(matches!(
        read_daemon_info_typed().unwrap(),
        MaybeDaemonInfo::Missing
    ));
    remove_daemon_file().unwrap(); // idempotent

    fuz_home::clear_fuz_home_override_for_testing();
}

/// A corrupt (non-JSON) daemon.json is deleted in place and reported as Missing,
/// rather than surfacing as an error.
#[test]
fn corrupt_daemon_json_is_deleted_and_read_as_missing() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _home = fresh_home();

    let path = write_daemon_info(&current_daemon_info(live_pid()).unwrap()).unwrap();
    std::fs::write(&path, b"{ not valid json").unwrap();

    assert!(matches!(
        read_daemon_info_typed().unwrap(),
        MaybeDaemonInfo::Missing
    ));
    assert!(!path.exists(), "corrupt daemon.json is deleted on read");

    fuz_home::clear_fuz_home_override_for_testing();
}

/// A stand-in fuzd: `/bin/sleep` run through a symlink named `fuzd`, so the
/// kernel gives it fuzd's command name and `verify_pid_is_fuzd` confirms it.
/// Killed and reaped on drop, pass or fail.
struct StandInFuzd {
    child: std::process::Child,
    _dir: tempfile::TempDir,
}

impl StandInFuzd {
    fn spawn() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fuzd");
        std::os::unix::fs::symlink("/bin/sleep", &fake).unwrap();
        let child = std::process::Command::new(&fake)
            .arg("30")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        Self { child, _dir: dir }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).unwrap()
    }
}

impl Drop for StandInFuzd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The version-skew guard's file I/O: a daemon.json in another schema version
/// whose pid is a live fuzd is reported as `Unrecognized` with the version it
/// declares and **kept** — it is the only record of where that daemon is —
/// while the folded reader sees no current daemon.
#[test]
fn unrecognized_daemon_json_naming_a_live_fuzd_is_kept() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _home = fresh_home();
    let fuzd = StandInFuzd::spawn();

    let path = write_daemon_info(&current_daemon_info(live_pid()).unwrap()).unwrap();
    let body = format!(r#"{{"version":1,"pid":{},"port":1174}}"#, fuzd.pid());
    std::fs::write(&path, &body).unwrap();

    match read_daemon_info_typed().unwrap() {
        MaybeDaemonInfo::Unrecognized { pid, version } => {
            assert_eq!((pid, version), (fuzd.pid(), 1));
        }
        other => panic!("expected Unrecognized, got {other:?}"),
    }
    assert!(read_daemon_info().unwrap().is_none(), "folded into missing");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        body,
        "a live fuzd's record is never deleted"
    );

    fuz_home::clear_fuz_home_override_for_testing();
}

/// An unrecognized daemon.json whose pid is alive but **not fuzd** — reused by
/// another process after a reboot or crash — is stale: deleted and reported as
/// `Missing`, never refused. Refusing would wedge `fuzd start` behind an
/// unrelated process and point its `kill <pid>` hint at it.
#[test]
fn unrecognized_daemon_json_naming_a_live_non_fuzd_pid_is_deleted() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _home = fresh_home();

    let path = write_daemon_info(&current_daemon_info(live_pid()).unwrap()).unwrap();
    // The test process: alive, and not named `fuzd`.
    std::fs::write(&path, format!(r#"{{"version":1,"pid":{}}}"#, live_pid())).unwrap();

    assert!(matches!(
        read_daemon_info_typed().unwrap(),
        MaybeDaemonInfo::Missing
    ));
    assert!(!path.exists(), "a reused pid's record is deleted as stale");

    fuz_home::clear_fuz_home_override_for_testing();
}

/// An unrecognized daemon.json whose pid is dead is stale run-state: deleted in
/// place and reported as `Missing`.
#[test]
fn unrecognized_daemon_json_naming_a_dead_pid_is_deleted() {
    let _guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _home = fresh_home();

    let path = write_daemon_info(&current_daemon_info(live_pid()).unwrap()).unwrap();
    // `i32::MAX` exceeds every `pid_max`, so it names no process.
    std::fs::write(&path, format!(r#"{{"version":99,"pid":{}}}"#, i32::MAX)).unwrap();

    assert!(matches!(
        read_daemon_info_typed().unwrap(),
        MaybeDaemonInfo::Missing
    ));
    assert!(
        !path.exists(),
        "a stale unrecognized daemon.json is deleted"
    );

    fuz_home::clear_fuz_home_override_for_testing();
}
