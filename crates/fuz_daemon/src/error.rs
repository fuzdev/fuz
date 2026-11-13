//! Daemon lifecycle error type.

use fuz_home::FuzHomeError;
use fuz_sys::cli::EXIT_USAGE;
use std::borrow::Cow;
use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur while managing the fuzd process lifecycle.
///
/// `fuzd`'s own CLI drives these lifecycle operations; the error type lives
/// here and `fuzd` wraps it in its top-level `StartupError`.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// `~/.fuz` operation failed.
    #[error(transparent)]
    FuzHome(#[from] FuzHomeError),

    /// The fuz home's socket path is too long to reach (`refusal`), and
    /// `daemon.json` records a daemon (`recorded_pid`), which may still be
    /// running — for a home renamed past the limit under it. The pid is as
    /// recorded, never verified: nothing is signalled or cleaned up.
    #[error("{refusal}")]
    SocketUnreachable {
        refusal: FuzHomeError,
        recorded_pid: i32,
    },

    /// The daemon log path holds a symlink or something other than a regular
    /// file, or the no-follow open of it failed. Refused before anything is
    /// written there or rotated.
    #[error("cannot open log file: {0}")]
    LogFile(fuz_sys::secure_file::SecureFileError),

    /// Failed to duplicate the daemon log file's descriptor (one for the
    /// child's stdout, one for its stderr).
    #[error("failed to duplicate the descriptor of log file {path}")]
    CloneLogFileFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to locate the fuzd binary to spawn.
    #[error("failed to locate fuzd binary")]
    FindBinaryFailed(#[source] std::io::Error),

    /// Failed to spawn the fuzd process.
    #[error("failed to spawn fuzd")]
    SpawnDaemonFailed(#[source] std::io::Error),

    /// Reading the daemon log for `fuzd logs` failed after it was opened.
    #[error("failed to read log file {path}")]
    ReadLog {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Writing the log to stdout for `fuzd logs` failed. A closed pipe is not
    /// reported: `fuzd logs` takes it as its reader being done.
    #[error("failed to write the log to stdout")]
    WriteOutput(#[source] std::io::Error),

    /// JSON serialization failed.
    #[error("failed to serialize JSON")]
    Json(#[from] serde_json::Error),
}

impl DaemonError {
    /// User-facing hint, printed after the `error:` line: the home layer's own,
    /// and for [`Self::SocketUnreachable`] what the recorded pid may mean.
    #[must_use]
    pub fn hint(&self) -> Option<Cow<'static, str>> {
        match self {
            Self::FuzHome(e) => e.hint().map(Cow::Borrowed),
            Self::SocketUnreachable {
                refusal,
                recorded_pid,
            } => Some(Cow::Owned(format!(
                "{}; a daemon may still be running for this home (pid {recorded_pid}, as \
                 recorded in daemon.json) — reach the home through a shorter path, such as a \
                 symlink, to stop it",
                refusal.hint().unwrap_or("point FUZ_HOME at a shorter path")
            ))),
            Self::LogFile(_)
            | Self::CloneLogFileFailed { .. }
            | Self::FindBinaryFailed(_)
            | Self::SpawnDaemonFailed(_)
            | Self::ReadLog { .. }
            | Self::WriteOutput(_)
            | Self::Json(_) => None,
        }
    }

    /// Exit code for this error (for `ExitCode::from`).
    ///
    /// A fuz home that cannot be used as configured is `2`
    /// ([`EXIT_USAGE`]): the caller must change `HOME`, `FUZ_HOME`, or the
    /// home's mode before running again. Every other lifecycle failure is a
    /// generic failure (`1`) — the daemon takes no other configuration (the
    /// UDS path under `~/.fuz/run/` is canonical).
    pub const fn exit_code(&self) -> u8 {
        if self.is_unusable_home() {
            EXIT_USAGE
        } else {
            1
        }
    }

    /// Returns true if the fuz home cannot be used as configured — the home
    /// layer's [`FuzHomeError::is_unusable_home`], forwarded. No lifecycle
    /// failure of the daemon's own is one.
    ///
    /// Exhaustive, so a new variant is classified where it is added.
    #[must_use]
    pub const fn is_unusable_home(&self) -> bool {
        match self {
            Self::FuzHome(e) | Self::SocketUnreachable { refusal: e, .. } => e.is_unusable_home(),
            Self::LogFile(_)
            | Self::CloneLogFileFailed { .. }
            | Self::FindBinaryFailed(_)
            | Self::SpawnDaemonFailed(_)
            | Self::ReadLog { .. }
            | Self::WriteOutput(_)
            | Self::Json(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lifecycle_failure_exits_1() {
        let err = DaemonError::SpawnDaemonFailed(std::io::Error::other("x"));
        assert_eq!(err.exit_code(), 1);
        // A home-layer failure while using a usable home is a failure too.
        let stale = DaemonError::FuzHome(FuzHomeError::DaemonInfoInvalidPid(0));
        assert_eq!(stale.exit_code(), 1);
    }

    /// A home that cannot be used as configured is the caller's to fix.
    #[test]
    fn an_unusable_home_exits_2() {
        for error in [
            FuzHomeError::HomeDir(fuz_sys::HomeDirError::Empty),
            FuzHomeError::RelativeFuzHome { path: "rel".into() },
            FuzHomeError::InsecureHome {
                path: "/x/.fuz".into(),
                mode: 0o777,
            },
        ] {
            let lifecycle = DaemonError::FuzHome(error);
            assert_eq!(lifecycle.exit_code(), EXIT_USAGE, "{lifecycle}");
        }
    }
}
