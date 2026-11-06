//! Error types for key-file operations.

use thiserror::Error;

/// Errors that can occur when parsing key files.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Unknown key file format version
    #[error("unknown key file format version: {0}")]
    UnknownFormat(String),

    /// Failed to parse key file structure
    #[error("failed to parse key file: invalid structure")]
    InvalidFormat,

    /// Key file has trailing content
    #[error("key file has trailing content (expected exactly 4 lines)")]
    TrailingContent,

    /// Invalid seed length
    #[error("invalid seed length: expected 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    /// Invalid base64 in key file
    #[error("invalid base64 in key file: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    /// Invalid timestamp format
    #[error("invalid timestamp format: expected RFC 3339")]
    InvalidTimestamp,

    /// Public key doesn't match derived key
    #[error("public key doesn't match derived key (file corrupted or tampered)")]
    PublicKeyMismatch,
}

impl KeyError {
    /// User-facing hint for how to fix the error.
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::UnknownFormat(_) => Some("This key file may be from a newer version of fuz"),
            Self::InvalidFormat => {
                Some("Key file is malformed. Regenerate with `cargo xtask key generate`")
            }
            Self::TrailingContent => Some("Remove extra blank lines at end of key file"),
            Self::InvalidSeedLength(_) | Self::InvalidBase64(_) => {
                Some("Key file is corrupted. Regenerate with `cargo xtask key generate`")
            }
            Self::InvalidTimestamp => {
                Some("Key file has invalid timestamp. Regenerate with `cargo xtask key generate`")
            }
            Self::PublicKeyMismatch => Some(
                "Key file is corrupted or tampered. Regenerate with `cargo xtask key generate`",
            ),
        }
    }
}
