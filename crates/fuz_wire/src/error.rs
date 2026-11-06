//! Wire protocol error type.

use thiserror::Error;

use super::actions::ActionId;

/// Errors raised by the wire codec.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// Underlying I/O error from the socket.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Frame length prefix exceeds the configured limit.
    ///
    /// Bounded *before* allocation — a forged `len = u32::MAX` cannot
    /// turn into a multi-GiB read buffer.
    #[error("frame too large: declared {declared} bytes, limit {limit}")]
    FrameTooLarge { declared: u32, limit: u32 },

    /// Frame length prefix is smaller than the fixed header.
    #[error("frame too small: declared {declared} bytes, header is {header} bytes")]
    FrameTooSmall { declared: u32, header: u32 },

    /// Failed to postcard-encode an outgoing payload.
    #[error("postcard encode error: {0}")]
    Encode(postcard::Error),

    /// Failed to postcard-decode an incoming payload.
    #[error("postcard decode error for action {action}: {source}")]
    Decode {
        /// Wire id of the action whose payload failed to decode — turns an
        /// opaque postcard error into a shape-skew report against a
        /// specific action.
        action: ActionId,
        #[source]
        source: postcard::Error,
    },
}
