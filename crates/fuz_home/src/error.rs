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

    /// The daemon socket under the fuz home (`$FUZ_HOME/run/socket`) is longer
    /// than a Unix socket address holds, so no daemon can listen there: the
    /// home is refused as configured.
    #[error(
        "socket path {} is {len} bytes, over the {max}-byte limit of a Unix socket address",
        path.display()
    )]
    SocketPathTooLong {
        path: PathBuf,
        len: usize,
        max: usize,
    },

    /// A tool name that is not a single plain path component — empty, `.`,
    /// `..`, or containing `/` — so a path built from it would leave
    /// `~/.fuz/tools/`.
    #[error("not a tool name: {name:?}")]
    InvalidToolName { name: String },
}

impl FuzHomeError {
    /// Returns true if the fuz home cannot be used as configured: the caller
    /// must change its environment before running again, and a re-run
    /// unchanged fails the same way.
    ///
    /// These are a home that cannot be determined (an unset, empty, or
    /// relative `HOME` with `FUZ_HOME` unset, or a relative `FUZ_HOME`) and one
    /// refused as it stands (a world-writable `~/.fuz`, fixed with `chmod`, or
    /// one too long for the daemon socket under it).
    /// A binary in the default exit-code dialect exits `2` for them. The I/O
    /// failures, a `daemon.json` this binary cannot use, and a malformed tool
    /// name are not: none is the caller's environment to fix.
    ///
    /// Exhaustive, so a new variant is classified where it is added. Every
    /// wrapper of this error forwards it.
    #[must_use]
    pub const fn is_unusable_home(&self) -> bool {
        match self {
            Self::HomeDir(_)
            | Self::RelativeFuzHome { .. }
            | Self::InsecureHome { .. }
            | Self::SocketPathTooLong { .. } => true,
            Self::CreateDirFailed { .. }
            | Self::ReadFailed { .. }
            | Self::WriteFailed { .. }
            | Self::DeleteFailed { .. }
            | Self::RenameFailed { .. }
            | Self::SerializeFailed(_)
            | Self::DaemonInfoVersionMismatch { .. }
            | Self::DaemonInfoInvalidPid(_)
            | Self::InvalidToolName { .. } => false,
        }
    }

    /// User-facing hint for how to fix this error, for the binaries that
    /// render one after the `error:` line.
    ///
    /// Only the home-resolution errors, an overlong socket path, and a
    /// malformed tool name carry one: what to set is the same advice whichever
    /// command hit them. [`FuzHomeError::InsecureHome`]'s remedy is already in
    /// its message.
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
            Self::SocketPathTooLong { .. } => Some(
                "the socket lives at `$FUZ_HOME/run/socket` — point FUZ_HOME at a shorter path",
            ),
            Self::InvalidToolName { .. } => {
                Some("a tool name is a plain name such as `fuzd`, with no `/` or `..`")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A home that cannot be determined or is refused as it stands is the
    /// caller's environment to fix; a failure while using a usable one is not.
    #[test]
    fn is_unusable_home_separates_the_environment_from_the_run() {
        let io = || std::io::Error::other("x");
        let unusable = [
            FuzHomeError::HomeDir(fuz_sys::HomeDirError::NotFound),
            FuzHomeError::HomeDir(fuz_sys::HomeDirError::Empty),
            FuzHomeError::HomeDir(fuz_sys::HomeDirError::Relative { path: "h".into() }),
            FuzHomeError::RelativeFuzHome { path: "rel".into() },
            FuzHomeError::InsecureHome {
                path: "/x/.fuz".into(),
                mode: 0o777,
            },
            FuzHomeError::SocketPathTooLong {
                path: "/x/run/socket".into(),
                len: 108,
                max: 107,
            },
        ];
        for error in unusable {
            assert!(error.is_unusable_home(), "{error}");
        }
        let usable = [
            FuzHomeError::CreateDirFailed {
                path: "/x".into(),
                source: io(),
            },
            FuzHomeError::ReadFailed {
                path: "/x".into(),
                source: io(),
            },
            FuzHomeError::WriteFailed {
                path: "/x".into(),
                source: io(),
            },
            FuzHomeError::DeleteFailed {
                path: "/x".into(),
                source: io(),
            },
            FuzHomeError::RenameFailed {
                from: "/x".into(),
                to: "/y".into(),
                source: io(),
            },
            FuzHomeError::DaemonInfoVersionMismatch {
                expected: 2,
                got: 1,
            },
            FuzHomeError::DaemonInfoInvalidPid(0),
            FuzHomeError::InvalidToolName { name: "..".into() },
        ];
        for error in usable {
            assert!(!error.is_unusable_home(), "{error}");
        }
    }
}
