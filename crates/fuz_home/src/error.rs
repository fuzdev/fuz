//! Error types for `~/.fuz` operations
//!
//! All operations on `~/.fuz` (paths, daemon.json, log rotation) use this error type.

use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during `~/.fuz` operations
#[derive(Debug, Error)]
pub enum FuzHomeError {
    /// The user's home directory, which `~/.fuz` defaults under, is unusable
    /// (`FUZ_HOME` unset or empty). Not a `#[source]`: the reason is the whole
    /// message, so the display carries it.
    #[error("cannot resolve ~/.fuz: {0}")]
    HomeDir(fuz_sys::HomeDirError),

    /// `FUZ_HOME` names a relative path, which would resolve against each
    /// command's cwd.
    #[error("FUZ_HOME must be an absolute path, got {}", path.display())]
    RelativeFuzHome { path: PathBuf },

    /// Failed to create directory
    #[error("failed to create directory {path}")]
    CreateDirFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to read file
    #[error("failed to read {path}")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to write file
    #[error("failed to write {path}")]
    WriteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to delete file
    #[error("failed to delete {path}")]
    DeleteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to rename file (atomic write or log rotation)
    #[error("failed to rename {from} to {to}")]
    RenameFailed {
        from: PathBuf,
        to: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to serialize data
    #[error("failed to serialize daemon info")]
    SerializeFailed(#[source] serde_json::Error),

    /// daemon.json has wrong version
    #[error("daemon.json version mismatch (expected {expected}, got {got})")]
    DaemonInfoVersionMismatch { expected: u32, got: u32 },

    /// daemon.json has invalid PID
    #[error("daemon.json has invalid pid: {0}")]
    DaemonInfoInvalidPid(i32),

    /// A pre-existing `~/.fuz` is world-writable — any other local user could
    /// replace an installed binary under it. Refused fail-closed rather than
    /// silently trusting or rewriting it. (Group-writable is deliberately *not*
    /// flagged: under the common private-group / `umask 002` scheme a `0775`
    /// directory is routine and benign.)
    #[error(
        "{path} is world-writable (mode {mode:04o}); \
         refusing to use it — run: chmod 700 {path}"
    )]
    InsecureHome { path: PathBuf, mode: u32 },

    /// A tool name that is not a single plain path component — empty, `.`,
    /// `..`, or containing `/` — so a path built from it would leave
    /// `~/.fuz/tools/`.
    #[error("not a tool name: {name:?}")]
    InvalidToolName { name: String },
}

impl FuzHomeError {
    /// User-facing hint for how to fix this error, for the binaries that
    /// render one after the `error:` line.
    ///
    /// Only the home-resolution errors and a malformed tool name carry one:
    /// what to set is the same advice whichever command hit them. [`FuzHomeError::InsecureHome`]'s
    /// remedy is already in its message.
    #[must_use]
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::HomeDir(_) => Some(
                "set HOME to your home directory's absolute path, or FUZ_HOME to an absolute path",
            ),
            Self::RelativeFuzHome { .. } => {
                Some("set FUZ_HOME to an absolute path, or unset it to use ~/.fuz")
            }
            Self::CreateDirFailed { .. }
            | Self::ReadFailed { .. }
            | Self::WriteFailed { .. }
            | Self::DeleteFailed { .. }
            | Self::RenameFailed { .. }
            | Self::SerializeFailed(_)
            | Self::DaemonInfoVersionMismatch { .. }
            | Self::DaemonInfoInvalidPid(_)
            | Self::InsecureHome { .. } => None,
            Self::InvalidToolName { .. } => {
                Some("a tool name is a plain name such as `fuzd`, with no `/` or `..`")
            }
        }
    }
}
