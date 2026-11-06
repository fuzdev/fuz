//! Daemon lifecycle error type.

use fuz_home::FuzHomeError;
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
    /// Exit code for this error (for `ExitCode::from`).
    ///
    /// Every lifecycle failure is a generic failure (1) — there is no
    /// caller-must-fix-config class, because the daemon takes no
    /// configuration (the UDS path under `~/.fuz/run/` is canonical).
    pub const fn exit_code(&self) -> u8 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_is_1() {
        let err = DaemonError::SpawnDaemonFailed(std::io::Error::other("x"));
        assert_eq!(err.exit_code(), 1);
    }
}
