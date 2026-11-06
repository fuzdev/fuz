//! Server error types.

use fuz_sys::file_lock::FileLockError;
use fuz_wire::{ActionId, AuthLevel, ProtoError};
use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during server operations.
#[derive(Debug, Error)]
pub enum ServerError {
    /// Failed to bind the Unix domain socket.
    #[error("failed to bind socket at {path}")]
    Bind {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The socket path is longer than a Unix socket address holds, so it
    /// cannot be bound. Refused before anything is created or locked.
    #[error(
        "socket path {} is {len} bytes, over the {max}-byte limit of a Unix socket address",
        path.display()
    )]
    SocketPathTooLong {
        path: PathBuf,
        len: usize,
        max: usize,
    },

    /// Failed to chmod the socket file.
    #[error("failed to set socket permissions on {path}")]
    SocketPerms {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Another fuzd holds the socket path's lock, so it owns the socket: this
    /// one stops before unlinking or binding anything. `pid` is the holder's,
    /// read from the lock file body (`None` when the body is unreadable).
    #[error("another fuzd is already running on {} ({})", socket_path.display(), format_holder(*pid))]
    AlreadyRunning {
        socket_path: PathBuf,
        pid: Option<u32>,
    },

    /// Failed to take the socket path's lock for a reason other than another
    /// fuzd holding it (opening the lock file, or `flock` itself).
    #[error("failed to lock {path}")]
    Lock {
        path: PathBuf,
        #[source]
        source: FileLockError,
    },

    /// Failed to clean up the previous socket file before bind.
    #[error("failed to remove stale socket at {path}")]
    RemoveStaleSocket {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to determine the daemon's own UID.
    #[error("failed to read daemon UID from /proc/self/status")]
    Uid(#[source] std::io::Error),

    /// Wire codec failure.
    #[error(transparent)]
    Wire(#[from] ProtoError),

    /// Auth denied for an incoming action.
    #[error("auth denied for action {action} (level {have:?}, required {required:?})")]
    AuthDenied {
        action: ActionId,
        have: AuthLevel,
        required: AuthLevel,
    },

    /// Wire dispatch received an `action_id` the server doesn't handle.
    #[error("unknown action {0}")]
    UnknownAction(ActionId),

    /// The connection's writer task is gone (peer closed mid-response), so
    /// a queued response can't be sent. The read loop treats this as a
    /// clean close, not a failure.
    #[error("connection closed")]
    ConnectionClosed,

    /// Generic I/O error during serve.
    #[error("server error")]
    Serve(#[source] std::io::Error),
}

impl ServerError {
    /// User-facing hint for the errors a user can act on.
    #[must_use]
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::SocketPathTooLong { .. } => Some(
                "the socket lives at `$FUZ_HOME/run/socket` — point FUZ_HOME at a shorter path",
            ),
            _ => None,
        }
    }
}

/// Format an optional lock-holder pid for the `AlreadyRunning` message.
fn format_holder(pid: Option<u32>) -> String {
    pid.map_or_else(|| "pid unknown".to_string(), |p| format!("pid {p}"))
}
