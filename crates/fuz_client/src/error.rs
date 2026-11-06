//! Client error types.
//!
//! This crate uses `thiserror` for typed errors that cross crate
//! boundaries. Binary crates (CLI) wrap these in their own typed errors
//! (`CliError`) for consistent handling and display.

use fuz_wire::{ActionId, ProtoError, WatchRefusal};
use thiserror::Error;

/// Hint for [`ClientError::ProtocolMismatch`].
///
/// Names the two remedies — rebuild from source, or pull a published release
/// — as one noun-first string. It was shared with a second protocol-mismatch
/// arm on a `DaemonCheckError` that no consumer ever reached; the constant
/// stays because the wording is worth keeping in one place, not two literals.
pub const PROTOCOL_MISMATCH_HINT: &str =
    "version mismatch — run `fuz artifact build` or `fuz self upgrade`";

/// Hint for [`ClientError::StreamEndedBeforeSnapshot`]: the daemon's log says
/// why it ended the stream.
pub const STREAM_ENDED_HINT: &str = "see `fuzd logs` for why the daemon ended the stream";

/// The message for [`ClientError::WatchRefused`].
fn watch_refusal_message(reason: &WatchRefusal) -> String {
    match reason {
        WatchRefusal::RootsTooLarge { encoded, limit } => format!(
            "the daemon refused the watch: its roots take {encoded} bytes in a frame, over the {limit}-byte limit"
        ),
    }
}

/// Errors that can occur during daemon client operations.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Daemon is not running — no socket file at the expected path.
    #[error("daemon not running (no socket at {path})")]
    DaemonNotRunning { path: String },

    /// Failed to connect to the daemon UDS.
    #[error("failed to connect to daemon at {path}")]
    Connect {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Wire codec failure (frame too large, postcard error, I/O).
    #[error(transparent)]
    Wire(#[from] ProtoError),

    /// Daemon responded with a frame for a different action than
    /// expected — almost always indicates a `PROTOCOL_VERSION` mismatch
    /// or a daemon bug.
    #[error("daemon returned unexpected action {got}, expected {expected}")]
    UnexpectedAction { expected: ActionId, got: ActionId },

    /// The daemon ended a subscription before sending its first snapshot —
    /// a daemon that shut down or failed mid-subscribe, or one that could not
    /// encode or frame the snapshot. Nothing was shown, so it is an error, not
    /// an empty success.
    #[error("the daemon ended the subscription before sending a snapshot")]
    StreamEndedBeforeSnapshot,

    /// The daemon sent a snapshot in several frames that do not assemble into
    /// one — a continuation that is not a pure `added` delta of the snapshot's
    /// domain, or another frame before the snapshot was complete.
    #[error("the daemon sent a malformed snapshot: {reason}")]
    MalformedSnapshot { reason: &'static str },

    /// The daemon refused a watch subscription.
    #[error("{}", watch_refusal_message(reason))]
    WatchRefused { reason: WatchRefusal },

    /// `PROTOCOL_VERSION` advertised by the daemon does not match the
    /// client's.
    #[error("protocol version mismatch: client {ours}, daemon {theirs}")]
    ProtocolMismatch { ours: u32, theirs: u32 },

    /// The fuz home, which holds the daemon's socket, cannot be resolved (a
    /// relative `FUZ_HOME`, an unusable `HOME`). Reads as the home layer's own
    /// error, the line `fuzd` prints for the same home.
    #[error(transparent)]
    FuzHome(#[from] fuz_home::FuzHomeError),
}

impl ClientError {
    /// Returns a hint for how to resolve this error; empty when there is none.
    ///
    /// An unresolvable home carries the home layer's own hint.
    #[must_use]
    pub const fn hint(&self) -> &'static str {
        match self {
            Self::DaemonNotRunning { .. } | Self::Connect { .. } => "fuzd start",
            Self::ProtocolMismatch { .. } => PROTOCOL_MISMATCH_HINT,
            Self::StreamEndedBeforeSnapshot => STREAM_ENDED_HINT,
            Self::FuzHome(e) => match e.hint() {
                Some(hint) => hint,
                None => "",
            },
            Self::WatchRefused {
                reason: WatchRefusal::RootsTooLarge { .. },
            } => "watch fewer or shorter roots per subscription",
            Self::Wire(_) | Self::UnexpectedAction { .. } | Self::MalformedSnapshot { .. } => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_strings() {
        assert_eq!(
            ClientError::DaemonNotRunning {
                path: "/x".to_string()
            }
            .hint(),
            "fuzd start"
        );
        assert_eq!(
            ClientError::ProtocolMismatch { ours: 5, theirs: 4 }.hint(),
            PROTOCOL_MISMATCH_HINT
        );
        assert_eq!(
            ClientError::StreamEndedBeforeSnapshot.hint(),
            STREAM_ENDED_HINT
        );
    }

    /// A home that cannot be resolved reads as the home layer's error and
    /// carries its hint; a home error with no hint adds none.
    #[test]
    fn an_unresolvable_home_keeps_the_home_error_and_its_hint() {
        use fuz_home::FuzHomeError;
        use std::path::PathBuf;

        let relative = || FuzHomeError::RelativeFuzHome {
            path: PathBuf::from("rel"),
        };
        let error = ClientError::from(relative());
        assert_eq!(error.to_string(), relative().to_string());
        let hint = relative().hint().expect("the home error has a hint");
        assert!(hint.contains("FUZ_HOME"), "{hint}");
        assert_eq!(error.hint(), hint);

        let hintless = ClientError::from(FuzHomeError::DaemonInfoInvalidPid(0));
        assert_eq!(hintless.hint(), "");
    }
}
