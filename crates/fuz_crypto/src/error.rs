//! Error types for cryptographic operations
//!
//! Pure crypto errors - no file I/O errors here.

use thiserror::Error;

/// Errors that can occur when verifying signatures
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The signature's envelope format is not the one this build reads
    /// ([`crate::signing::SIGNATURE_FORMAT_VERSION`]).
    #[error(
        "unsupported signature format {0} (this build reads format {expected})",
        expected = crate::signing::SIGNATURE_FORMAT_VERSION
    )]
    UnsupportedFormat(u32),

    /// Invalid public key in signature
    #[error("invalid public key in signature")]
    InvalidPublicKey,

    /// Untrusted public key
    #[error("untrusted public key: {0}")]
    UntrustedKey(String),

    /// Signature verification failed
    #[error("signature verification failed")]
    InvalidSignature,

    /// Invalid base64 in signature
    #[error("invalid base64 in signature: {0}")]
    Base64Decode(base64::DecodeError),
}

impl VerifyError {
    /// User-facing hint for how to fix the error.
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedFormat(format)
                if *format < crate::signing::SIGNATURE_FORMAT_VERSION =>
            {
                Some(
                    "Signature predates domain-separated signing; the document must be re-signed by its publisher",
                )
            }
            Self::UnsupportedFormat(_) => Some("Signature may be from a newer version of fuz"),
            Self::InvalidPublicKey | Self::Base64Decode(_) => Some("Signature file is corrupted"),
            Self::UntrustedKey(_) => Some("Signature was made with an unknown key"),
            Self::InvalidSignature => Some("Content was modified or signature is corrupted"),
        }
    }
}

/// Errors that can occur during canonical JSON serialization
#[derive(Debug, Error)]
pub enum CanonicalError {
    /// Non-ASCII string in manifest. The string is the document's own, as
    /// given; the message shows a bounded excerpt of it in ASCII.
    #[error("non-ASCII string in manifest: {}", ascii_excerpt(.0))]
    NonAsciiString(String),

    /// Number not representable as integer
    #[error("number not representable as integer: {0}")]
    NumberNotInteger(String),

    /// Serialization failed
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Most bytes of an offending string `ascii_excerpt` shows.
const MAX_EXCERPT_LEN: usize = 128;

/// `value` in double quotes for an error message, as printable ASCII: cut to
/// `MAX_EXCERPT_LEN` bytes on a character boundary (`...` appended when
/// cut), then every character outside printable ASCII escaped, with `"` and
/// `\`.
///
/// The string is from a document whose signature has not been checked, and
/// the message may be printed to a terminal. This crate depends on no other
/// in the workspace, so it does not take `fuz_sys::text`'s escaping; ASCII
/// alone needs no table of what prints.
fn ascii_excerpt(value: &str) -> String {
    let mut end = value.len().min(MAX_EXCERPT_LEN);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let cut = if end < value.len() { "..." } else { "" };
    format!("\"{}{cut}\"", value[..end].escape_default())
}

impl CanonicalError {
    /// User-facing hint for how to fix the error.
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::NonAsciiString(_) => Some("Manifest fields must be ASCII-only"),
            Self::NumberNotInteger(_) => Some("Manifest numbers must be integers, not floats"),
            Self::Serialize(_) => None,
        }
    }
}

/// Errors parsing or constructing a [`crate::hash::ContentHash`].
///
/// The strings a variant carries are the input as given, and its message
/// shows them unbounded and unescaped: a caller that prints one bounds and
/// escapes it. A document parser that reports one does so in its own error's
/// message, which is bounded and escaped whole where that is rendered.
#[derive(Debug, Error)]
pub enum HashError {
    /// Algorithm token isn't one of `blake3` / `sha256` / `sha512`.
    #[error("unknown hash algorithm: {0}")]
    UnknownAlgorithm(String),

    /// String isn't a recognizable `<algo>:<hex>` or `<algo>-<base64>` form.
    #[error("malformed hash string: {0}")]
    Malformed(String),

    /// Hex portion failed to decode.
    #[error("invalid hex in hash: {0}")]
    InvalidHex(String),

    /// Base64 portion (SRI form) failed to decode.
    #[error("invalid base64 in hash: {0}")]
    InvalidBase64(String),

    /// Bare hex is not the one spelling of a digest: exactly
    /// `2 * algo.digest_len()` characters of `0-9a-f`
    /// ([`crate::hash::ContentHash::from_lower_hex`]). The message does not
    /// repeat the input.
    #[error("expected {} lowercase hex characters for {algo}", .algo.digest_len() * 2)]
    NotLowerHex {
        /// The algorithm the digest was read for.
        algo: crate::hash::HashAlgo,
    },

    /// Not a fact address: exactly `blake3:` followed by 64 characters of
    /// `0-9a-f` ([`crate::hash::ContentHash::parse_fact_hash`]). The message
    /// does not repeat the input.
    #[error("expected a fact hash: blake3: followed by 64 lowercase hex characters")]
    NotFactHash,

    /// Decoded digest length doesn't match the algorithm.
    #[error("wrong digest length for {algo}: expected {expected}, got {got}")]
    WrongLength {
        /// The algorithm token (e.g. `blake3`).
        algo: &'static str,
        /// Digest length the algorithm requires.
        expected: usize,
        /// Digest length actually decoded.
        got: usize,
    },
}

/// Why an SSH signature was not accepted by [`crate::sshsig::verify_sshsig`].
///
/// Three classes, told apart by [`is_verification_failure`](Self::is_verification_failure):
/// a document that is not a signature this parser reads (too large, bad armor,
/// malformed, an unsupported version, key type, or hash), an expected key that
/// is unusable, and a well-formed signature that does not vouch for the
/// message — by another key, under another namespace, or not verifying.
///
/// No message repeats bytes from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SshsigError {
    /// The armored input is over [`crate::sshsig::MAX_ARMORED_SIZE`].
    #[error(
        "SSH signature too large: {size} bytes (max {})",
        crate::sshsig::MAX_ARMORED_SIZE
    )]
    TooLarge {
        /// The input's length in bytes.
        size: usize,
    },
    /// The armor is not the form `ssh-keygen` writes.
    #[error("malformed SSH signature armor: {0}")]
    Armor(&'static str),
    /// The decoded blob does not have the `sshsig` structure.
    #[error("malformed SSH signature: {0}")]
    Malformed(&'static str),
    /// The blob's version is not 1.
    #[error("unsupported SSH signature version: {0} (supported: 1)")]
    UnsupportedVersion(u32),
    /// The signer's key is not an ed25519 key.
    #[error("unsupported SSH key type in signature (only ssh-ed25519 is accepted)")]
    UnsupportedKeyType,
    /// The signature is not an ed25519 signature.
    #[error("unsupported SSH signature type (only ssh-ed25519 is accepted)")]
    UnsupportedSignatureType,
    /// The hash algorithm is neither `sha512` nor `sha256`.
    #[error("unsupported SSH signature hash algorithm (sha512 and sha256 are accepted)")]
    UnsupportedHashAlgorithm,
    /// The expected key is not a valid ed25519 public key.
    #[error("the expected SSH key is not a valid ed25519 public key")]
    InvalidKey,
    /// The signature was made by a key other than the expected one.
    #[error("SSH signature was made by a different key than the expected one")]
    WrongKey,
    /// The signature was made under a namespace other than the expected one.
    #[error("SSH signature was made for a different namespace than the expected one")]
    WrongNamespace,
    /// The signature does not verify over the message.
    #[error("SSH signature verification failed")]
    InvalidSignature,
}

impl SshsigError {
    /// Returns true if a well-formed signature failed to vouch for the
    /// message: it is by another key, for another namespace, or does not
    /// verify. False for a document that could not be read as a signature and
    /// for an unusable expected key — bad input, not on its own evidence of a
    /// forgery.
    #[must_use]
    pub const fn is_verification_failure(&self) -> bool {
        match self {
            Self::WrongKey | Self::WrongNamespace | Self::InvalidSignature => true,
            Self::TooLarge { .. }
            | Self::Armor(_)
            | Self::Malformed(_)
            | Self::UnsupportedVersion(_)
            | Self::UnsupportedKeyType
            | Self::UnsupportedSignatureType
            | Self::UnsupportedHashAlgorithm
            | Self::InvalidKey => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cut is at the bound, not beside it: a string of exactly
    /// `MAX_EXCERPT_LEN` bytes is shown whole, and one byte more is cut.
    #[test]
    fn an_excerpt_is_cut_at_the_bound() {
        let fits = "a".repeat(MAX_EXCERPT_LEN);
        assert_eq!(
            CanonicalError::NonAsciiString(fits.clone()).to_string(),
            format!("non-ASCII string in manifest: \"{fits}\"")
        );
        assert_eq!(
            CanonicalError::NonAsciiString(format!("{fits}b")).to_string(),
            format!("non-ASCII string in manifest: \"{fits}...\"")
        );
    }

    /// The offending string is shown bounded and in printable ASCII: nothing
    /// in it reaches a terminal as a control sequence, a direction override,
    /// or a blank, and it cannot close its quotes.
    #[test]
    fn a_non_ascii_string_is_shown_as_bounded_printable_ascii() {
        assert_eq!(
            CanonicalError::NonAsciiString("caf\u{e9}".to_string()).to_string(),
            "non-ASCII string in manifest: \"caf\\u{e9}\""
        );
        assert_eq!(
            CanonicalError::NonAsciiString("a\u{1b}[2K\r\u{202e}\u{2800}\"\\b".to_string())
                .to_string(),
            "non-ASCII string in manifest: \"a\\u{1b}[2K\\r\\u{202e}\\u{2800}\\\"\\\\b\""
        );
        // Cut on a character boundary, before it is escaped.
        let long = format!(
            "{}\u{e9}{}",
            "a".repeat(MAX_EXCERPT_LEN - 1),
            "b".repeat(4096)
        );
        assert_eq!(
            CanonicalError::NonAsciiString(long).to_string(),
            format!(
                "non-ASCII string in manifest: \"{}...\"",
                "a".repeat(MAX_EXCERPT_LEN - 1)
            )
        );
        let message = CanonicalError::NonAsciiString("\u{1b}".repeat(4096)).to_string();
        assert!(
            message.bytes().all(|b| (0x20..0x7f).contains(&b)),
            "{message}"
        );
        assert_eq!(
            message,
            format!(
                "non-ASCII string in manifest: \"{}...\"",
                "\\u{1b}".repeat(MAX_EXCERPT_LEN)
            )
        );
    }
}
