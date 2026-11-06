//! Daemon file utilities (daemon.json)
//!
//! daemon.json lives at `~/.fuz/run/daemon.json` and is owned by the CLI.
//! The daemon never reads or writes this file.
//!
//! It is ephemeral, regenerable run-state: `fuzd start` rewrites it on every
//! start, so the read path deletes a corrupt or stale file rather than erroring.
//! The one file it keeps is one it can't read that still names a live fuzd
//! (see [`MaybeDaemonInfo::Unrecognized`]) — the only record of where that
//! daemon is.

use crate::error::FuzHomeError;
use crate::paths::{DAEMON_FILE, ensure_fuz_home, get_run_dir, get_socket_path};
use fuz_sys::SECURE_FILE_MODE;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Current daemon.json schema version — bump it with any change to
/// [`DaemonInfo`]'s shape.
///
/// The version-skew guard keys on it: a daemon.json that doesn't read as this
/// version — written by an older or newer fuz — but still names a live fuzd is
/// refused by `fuzd start` (stop that daemon — `kill <pid>` — then re-run); one
/// whose pid is gone or now belongs to another process is removed with a
/// warning. See [`read_daemon_info_typed`].
///
/// Crate-internal — not re-exported. Both sides of the invariant live in this
/// module: [`current_daemon_info`] stamps it and [`DaemonInfo::validate`]
/// checks it on the read path. Nothing re-checks it on write —
/// [`write_daemon_info`] serializes whatever `DaemonInfo` it is handed — so
/// what a caller outside this module reaches for is the constructor, not the
/// constant. The name stays rather than being inlined at those two sites,
/// which would split one version invariant across two literals.
pub const DAEMON_INFO_VERSION: u32 = 2;

/// Information about the running daemon, stored in daemon.json.
///
/// Written by CLI after spawn + health confirmation. Read by CLI for
/// socket discovery across terminal sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonInfo {
    /// Schema version (must be `DAEMON_INFO_VERSION`).
    pub version: u32,
    /// Daemon process ID (i32 matches Linux `pid_t`).
    pub pid: i32,
    /// Path to the UDS socket the daemon is bound to.
    pub socket_path: PathBuf,
}

impl DaemonInfo {
    /// Validate the daemon info.
    const fn validate(&self) -> Result<(), FuzHomeError> {
        if self.version != DAEMON_INFO_VERSION {
            return Err(FuzHomeError::DaemonInfoVersionMismatch {
                expected: DAEMON_INFO_VERSION,
                got: self.version,
            });
        }
        if self.pid <= 0 {
            return Err(FuzHomeError::DaemonInfoInvalidPid(self.pid));
        }
        Ok(())
    }
}

/// The schema-independent core of a daemon.json: the two keys every schema
/// version carries. Decoded only when the file fails to read as the current
/// [`DaemonInfo`], so a file from another schema version still yields the pid
/// of the daemon it records — and a file without both keys reads as corrupt.
#[derive(Debug, Clone, Deserialize)]
struct DaemonInfoProbe {
    version: u32,
    pid: i32,
}

/// Discriminated outcome of reading daemon.json.
///
/// The CLI dispatches on this so a file it can't read whose pid is still a live
/// fuzd produces an actionable error instead of either silently deleting a running
/// daemon's only record or interpreting another schema's fields as this one's.
#[derive(Debug, Clone)]
pub enum MaybeDaemonInfo {
    /// Current-version daemon info, ready to consume.
    Current(DaemonInfo),
    /// A daemon.json that doesn't read as the current schema but names a live
    /// fuzd (alive, and `/proc/<pid>/comm` reads `fuzd`) — the version-skew
    /// guard. Almost always another fuz's schema
    /// version (older or newer) recording a daemon it started; also a
    /// current-version file missing a field. The file is kept, and the caller
    /// must refuse to spawn beside the daemon and surface an actionable error.
    Unrecognized {
        /// The pid the file records, confirmed a live fuzd.
        pid: i32,
        /// The schema version the file declares.
        version: u32,
    },
    /// No daemon.json present (or a corrupt / stale one, deleted on read).
    Missing,
}

/// Get path to daemon.json (in run/ subdirectory).
fn daemon_file_path() -> Result<PathBuf, FuzHomeError> {
    Ok(get_run_dir()?.join(DAEMON_FILE))
}

/// What a daemon.json's contents mean — the pure parse + current / unrecognized
/// / corrupt discrimination core of [`read_daemon_info_typed`], factored out so
/// the branch logic is unit-testable with an injected live-fuzd predicate. The
/// file I/O (reading, deleting a stale/corrupt file) and diagnostics stay in
/// the caller.
#[derive(Debug)]
enum DaemonJsonVerdict {
    /// A valid current-version file, ready to consume.
    Current(DaemonInfo),
    /// Not the current schema, but the probe's pid is a live fuzd — the caller
    /// must refuse to spawn next to it.
    Unrecognized { pid: i32, version: u32 },
    /// Not the current schema, and the probe's pid is not a live fuzd (gone, or
    /// reused by another process) — delete + treat missing.
    StaleUnrecognized { pid: i32, version: u32 },
    /// Not even the probe's `{version, pid}` — delete + treat missing.
    Corrupt,
}

/// Classify daemon.json `content` using `is_live_fuzd` to probe the recorded
/// pid.
///
/// Mirrors the read order: try the current schema (accept only if it also
/// validates), else fall through to the `{version, pid}` probe (so another
/// schema version naming a live fuzd is refused, not misread), else corrupt.
fn classify_daemon_json(content: &str, is_live_fuzd: impl Fn(i32) -> bool) -> DaemonJsonVerdict {
    if let Ok(info) = serde_json::from_str::<DaemonInfo>(content)
        && info.validate().is_ok()
    {
        return DaemonJsonVerdict::Current(info);
    }
    if let Ok(DaemonInfoProbe { version, pid }) = serde_json::from_str(content) {
        if pid > 0 && is_live_fuzd(pid) {
            return DaemonJsonVerdict::Unrecognized { pid, version };
        }
        return DaemonJsonVerdict::StaleUnrecognized { pid, version };
    }
    DaemonJsonVerdict::Corrupt
}

/// Read daemon info from daemon.json.
///
/// `Some(DaemonInfo)` only for the current schema version. Everything
/// else is `None`: a missing file, a corrupt one (deleted in place),
/// and **an unrecognized one — another schema version, live fuzd or not —
/// which is folded into the same "missing" outcome rather than being
/// reshaped into a `DaemonInfo`.**
///
/// That fold is why the live-fuzd case is invisible here. CLI start paths
/// consult [`read_daemon_info_typed`] first, so they can distinguish
/// a stale file (delete and proceed) from one naming a live fuzd
/// (refuse with a hint) before falling back to this function.
///
/// # Errors
/// Returns an error only for unexpected I/O failures.
pub fn read_daemon_info() -> Result<Option<DaemonInfo>, FuzHomeError> {
    match read_daemon_info_typed()? {
        MaybeDaemonInfo::Current(info) => Ok(Some(info)),
        MaybeDaemonInfo::Unrecognized { .. } | MaybeDaemonInfo::Missing => Ok(None),
    }
}

/// Read daemon info with the typed current / unrecognized / missing
/// discriminator.
///
/// Use this in `fuzd start` to refuse to spawn next to a live fuzd whose
/// daemon.json this fuz can't read ([`MaybeDaemonInfo::Unrecognized`]).
/// Other callers can use [`read_daemon_info`] which folds that case into the
/// "missing" arm.
///
/// Regenerable run-state, so removal is the remedy for the rest: corrupt files
/// (non-JSON, or no `version` / `pid` keys) and unrecognized files whose pid
/// is not a live fuzd are deleted in place, with a warning on stderr, and
/// reported as `Missing`.
///
/// "Live fuzd" is [`verify_pid_is_fuzd`](crate::verify_pid_is_fuzd): a pid recorded before a
/// reboot or crash can since belong to an unrelated process, and treating that
/// as the daemon would wedge `fuzd start` and point its `kill <pid>` hint at
/// the wrong process.
///
/// # Errors
/// Returns an error only for unexpected I/O failures.
pub fn read_daemon_info_typed() -> Result<MaybeDaemonInfo, FuzHomeError> {
    let path = daemon_file_path()?;

    if !path.exists() {
        return Ok(MaybeDaemonInfo::Missing);
    }

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MaybeDaemonInfo::Missing);
        }
        Err(e) => return Err(FuzHomeError::ReadFailed { path, source: e }),
    };

    match classify_daemon_json(&content, crate::pid::verify_pid_is_fuzd) {
        DaemonJsonVerdict::Current(info) => Ok(MaybeDaemonInfo::Current(info)),
        DaemonJsonVerdict::Unrecognized { pid, version } => {
            Ok(MaybeDaemonInfo::Unrecognized { pid, version })
        }
        DaemonJsonVerdict::StaleUnrecognized { pid, version } => {
            // Another schema's file whose daemon is gone — nothing left to protect.
            eprintln!(
                "warning: cleaned stale daemon.json from schema version {version} \
                 (pid {pid} is not a running fuzd)"
            );
            let _ = fs::remove_file(&path);
            Ok(MaybeDaemonInfo::Missing)
        }
        DaemonJsonVerdict::Corrupt => {
            eprintln!("warning: corrupt daemon.json, deleting");
            let _ = fs::remove_file(&path);
            Ok(MaybeDaemonInfo::Missing)
        }
    }
}

/// Write daemon info to daemon.json atomically (mode 0600).
///
/// Write-to-temp + `sync_all` (content fsync) + rename. The **parent-dir
/// fsync** that `fuz_sys::fs::write_atomic` performs is **deliberately
/// omitted**: `daemon.json` is ephemeral, regenerable run-state (`fuzd start`
/// rewrites it on every start), so durability of the *directory entry* across a
/// host crash buys nothing — a lost rename just means the next start rewrites
/// it. Authoritative, non-regenerable state (credentials, lock ledgers) uses
/// `write_atomic` instead.
///
/// The temp file is opened without following a link and must be a regular
/// file (`fuz_sys::secure_file::open_truncate_nofollow_regular`), so a link
/// planted at `daemon.json.tmp` is refused rather than written through.
///
/// # Errors
/// Returns an error if the directory cannot be created or the file
/// cannot be written.
#[cfg(unix)]
pub fn write_daemon_info(info: &DaemonInfo) -> Result<PathBuf, FuzHomeError> {
    use std::io::Write;

    ensure_fuz_home()?;
    let path = daemon_file_path()?;
    let temp_path = path.with_extension("json.tmp");

    let json = serde_json::to_string(&info).map_err(FuzHomeError::SerializeFailed)?;

    // No-follow: a link planted at the temp path is refused, not written
    // through, and anything but a regular file there is refused untouched.
    let mut file =
        fuz_sys::secure_file::open_truncate_nofollow_regular(&temp_path, SECURE_FILE_MODE)
            .map_err(|e| FuzHomeError::WriteFailed {
                path: temp_path.clone(),
                source: std::io::Error::other(e),
            })?;

    file.write_all(json.as_bytes())
        .map_err(|source| FuzHomeError::WriteFailed {
            path: temp_path.clone(),
            source,
        })?;
    file.flush().map_err(|source| FuzHomeError::WriteFailed {
        path: temp_path.clone(),
        source,
    })?;
    file.sync_all()
        .map_err(|source| FuzHomeError::WriteFailed {
            path: temp_path.clone(),
            source,
        })?;

    fs::rename(&temp_path, &path).map_err(|source| FuzHomeError::RenameFailed {
        from: temp_path,
        to: path.clone(),
        source,
    })?;

    Ok(path)
}

/// Remove daemon file (idempotent - ignores if already removed).
///
/// # Errors
/// Returns an error if the file exists but cannot be removed.
pub fn remove_daemon_file() -> Result<(), FuzHomeError> {
    let path = daemon_file_path()?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(FuzHomeError::DeleteFailed { path, source: e }),
    }
}

/// Convenience constructor — builds a v2 [`DaemonInfo`] for the
/// currently-bound socket.
///
/// # Errors
/// Returns an error if the socket path can't be resolved.
pub fn current_daemon_info(pid: i32) -> Result<DaemonInfo, FuzHomeError> {
    Ok(DaemonInfo {
        version: DAEMON_INFO_VERSION,
        pid,
        socket_path: get_socket_path()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(version: u32, pid: i32) -> DaemonInfo {
        DaemonInfo {
            version,
            pid,
            socket_path: PathBuf::from("/run/fuz/socket"),
        }
    }

    #[test]
    fn validate_accepts_current_version_and_positive_pid() {
        assert!(info(DAEMON_INFO_VERSION, 1234).validate().is_ok());
    }

    #[test]
    fn validate_rejects_wrong_version() {
        // An older (or future) file must not be accepted as the current schema —
        // misreading its fields, or trusting a future shape, is the bug. (The
        // read path falls back to the `{version, pid}` probe on a mismatch.)
        let err = info(1, 1234).validate().unwrap_err();
        assert!(
            matches!(
                err,
                FuzHomeError::DaemonInfoVersionMismatch { expected, got }
                    if expected == DAEMON_INFO_VERSION && got == 1
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_nonpositive_pid() {
        assert!(matches!(
            info(DAEMON_INFO_VERSION, 0).validate(),
            Err(FuzHomeError::DaemonInfoInvalidPid(0))
        ));
        assert!(matches!(
            info(DAEMON_INFO_VERSION, -5).validate(),
            Err(FuzHomeError::DaemonInfoInvalidPid(-5))
        ));
    }

    #[test]
    fn classify_valid_v2_is_current() {
        let json = serde_json::to_string(&info(DAEMON_INFO_VERSION, 1234)).unwrap();
        match classify_daemon_json(&json, |_| false) {
            DaemonJsonVerdict::Current(i) => assert_eq!(i.pid, 1234),
            other => panic!("expected Current, got {other:?}"),
        }
    }

    #[test]
    fn classify_older_version_naming_a_live_fuzd_refuses() {
        // An older schema's file (here the port-era shape) naming a live fuzd
        // must surface as Unrecognized (the refuse-to-spawn signal), carrying
        // the version it declares — never be silently consumed or deleted.
        match classify_daemon_json(r#"{"version":1,"pid":4321,"port":1174}"#, |pid| pid == 4321) {
            DaemonJsonVerdict::Unrecognized { pid, version } => {
                assert_eq!((pid, version), (4321, 1));
            }
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    #[test]
    fn classify_older_version_naming_no_live_fuzd_is_stale() {
        assert!(matches!(
            classify_daemon_json(r#"{"version":1,"pid":4321}"#, |_| false),
            DaemonJsonVerdict::StaleUnrecognized {
                pid: 4321,
                version: 1
            }
        ));
    }

    #[test]
    fn classify_without_version_or_pid_is_corrupt() {
        // The probe needs both keys: a JSON object missing either is corrupt,
        // not a daemon record to protect.
        assert!(matches!(
            classify_daemon_json(r#"{"pid":4321}"#, |_| true),
            DaemonJsonVerdict::Corrupt
        ));
        assert!(matches!(
            classify_daemon_json(r#"{"version":2}"#, |_| true),
            DaemonJsonVerdict::Corrupt
        ));
    }

    #[test]
    fn classify_corrupt_is_corrupt() {
        assert!(matches!(
            classify_daemon_json("{not valid json", |_| true),
            DaemonJsonVerdict::Corrupt
        ));
    }

    #[test]
    fn classify_newer_version_falls_to_the_probe() {
        // A current-shaped file declaring a newer version, naming a live fuzd, must
        // fall through to the probe and be refused — not misread as the current
        // schema.
        match classify_daemon_json(
            r#"{"version":99,"pid":777,"socket_path":"/run/fuz/socket"}"#,
            |pid| pid == 777,
        ) {
            DaemonJsonVerdict::Unrecognized { pid, version } => {
                assert_eq!((pid, version), (777, 99));
            }
            other => panic!("expected Unrecognized fall-through, got {other:?}"),
        }
    }
}
