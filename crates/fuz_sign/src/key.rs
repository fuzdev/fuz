//! Key generation and parsing
//!
//! Ed25519 key operations - all in-memory, no file I/O. Reading the key file
//! from disk is the `key_file` module.

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use fuz_sys::is_rfc3339_utc_seconds;
use zeroize::{Zeroize, Zeroizing};

use crate::error::KeyError;

/// Metadata associated with a signing key
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    /// RFC 3339 timestamp when key was created
    pub created: String,
}

/// Parse key file bytes into signing key and metadata.
///
/// Strict line-based parsing: rejects malformed or extra content.
///
/// # Key File Format
///
/// ```text
/// fuz-signing-key-v1
/// public: <base64-encoded-32-byte-public-key>
/// seed: <base64-encoded-32-byte-seed>
/// created: 2025-01-15T10:30:00Z
/// ```
///
/// # Errors
///
/// Returns [`KeyError`] if:
/// - File is not valid UTF-8 or has wrong number of lines
/// - Format version is unsupported
/// - Base64 decoding fails
/// - Seed length is not 32 bytes
/// - Public key doesn't match derived key (corruption/tampering)
/// - Timestamp format is invalid
pub fn parse_key_file(bytes: &[u8]) -> Result<(SigningKey, KeyMetadata), KeyError> {
    let text = std::str::from_utf8(bytes).map_err(|_| KeyError::InvalidFormat)?;
    let lines: Vec<&str> = text.lines().collect();

    // Exactly 4 lines required
    // Note: .lines() ignores trailing newline, so "a\nb\nc\nd\n" -> 4 lines (correct)
    // But "a\nb\nc\nd\n\n" -> 5 lines (extra blank line, common editor issue)
    if lines.len() < 4 {
        return Err(KeyError::InvalidFormat);
    }
    if lines.len() > 4 {
        // Specific error for common case of extra trailing newlines
        return Err(KeyError::TrailingContent);
    }

    // Line 1: Magic header
    if lines[0] != "fuz-signing-key-v1" {
        if let Some(version) = lines[0].strip_prefix("fuz-signing-key-v") {
            return Err(KeyError::UnknownFormat(version.to_string()));
        }
        return Err(KeyError::InvalidFormat);
    }

    // Line 2: public key
    let public_b64 = lines[1]
        .strip_prefix("public: ")
        .ok_or(KeyError::InvalidFormat)?;
    let public_bytes = STANDARD
        .decode(public_b64)
        .map_err(KeyError::InvalidBase64)?;

    // Line 3: seed
    let seed_b64 = lines[2]
        .strip_prefix("seed: ")
        .ok_or(KeyError::InvalidFormat)?;
    let mut seed_bytes = STANDARD.decode(seed_b64).map_err(KeyError::InvalidBase64)?;
    if seed_bytes.len() != 32 {
        let len = seed_bytes.len();
        seed_bytes.zeroize(); // Zeroize before returning error
        return Err(KeyError::InvalidSeedLength(len));
    }

    // Convert to array immediately and zeroize Vec
    // Safety: we validated seed_bytes.len() == 32 above
    let Ok(mut seed): Result<[u8; 32], _> = seed_bytes.try_into() else {
        unreachable!("seed length validated as 32");
    };
    // Note: seed_bytes is consumed by try_into(), no need to zeroize

    // Line 4: created timestamp (validate RFC 3339 format)
    let created = lines[3]
        .strip_prefix("created: ")
        .ok_or(KeyError::InvalidFormat)?;
    if !is_rfc3339_utc_seconds(created) {
        seed.zeroize(); // Zeroize before returning error
        return Err(KeyError::InvalidTimestamp);
    }
    let created = created.to_string();

    // Build signing key from seed
    let signing_key = SigningKey::from_bytes(&seed);

    // Zeroize seed immediately after use (SigningKey has its own copy)
    seed.zeroize();

    // Verify public key matches derived key (detects corruption or tampering)
    let derived_public = signing_key.verifying_key();
    if derived_public.as_bytes() != public_bytes.as_slice() {
        return Err(KeyError::PublicKeyMismatch);
    }

    Ok((signing_key, KeyMetadata { created }))
}

/// Serialize signing key to key file format.
///
/// Returns a `Zeroizing<Vec<u8>>` to ensure the seed bytes are cleared from memory
/// when the buffer is dropped.
///
/// # Panics
///
/// Panics if `created` is not a valid RFC 3339 timestamp (YYYY-MM-DDTHH:MM:SSZ).
/// This catches programmer errors early - the timestamp should come from
/// `fuz_sys::rfc3339_now()` which always produces valid output.
pub fn serialize_key_file(key: &SigningKey, created: &str) -> Zeroizing<Vec<u8>> {
    assert!(
        is_rfc3339_utc_seconds(created),
        "serialize_key_file: invalid timestamp format: {created}"
    );
    // The public key is not secret; the seed is. Hold the seed and its base64
    // in zeroizing buffers so no plaintext copy survives in freed memory — the
    // returned buffer also contains the seed b64, hence the outer `Zeroizing`.
    let public_b64 = STANDARD.encode(key.verifying_key().as_bytes());
    let mut seed = key.to_bytes();
    let seed_b64 = Zeroizing::new(STANDARD.encode(seed));
    seed.zeroize();
    Zeroizing::new(
        format!(
            "fuz-signing-key-v1\npublic: {public_b64}\nseed: {}\ncreated: {created}\n",
            seed_b64.as_str(),
        )
        .into_bytes(),
    )
}

/// Generate new signing keypair
pub fn generate_keypair() -> SigningKey {
    let mut rng = rand::thread_rng();
    SigningKey::generate(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_parse_round_trip() {
        let key = generate_keypair();
        let created = "2025-01-15T10:30:00Z";
        let serialized = serialize_key_file(&key, created);
        let (parsed_key, meta) = parse_key_file(&serialized).expect("parse should succeed");

        assert_eq!(parsed_key.to_bytes(), key.to_bytes());
        assert_eq!(meta.created, created);
    }

    #[test]
    fn reject_key_unknown_format() {
        let content =
            b"fuz-signing-key-v99\npublic: AAAA\nseed: BBBB\ncreated: 2025-01-15T10:30:00Z\n";
        let result = parse_key_file(content);
        assert!(matches!(result, Err(KeyError::UnknownFormat(v)) if v == "99"));
    }

    #[test]
    fn reject_key_invalid_format() {
        let content = b"not a key file\n";
        let result = parse_key_file(content);
        assert!(matches!(result, Err(KeyError::InvalidFormat)));
    }

    #[test]
    fn reject_key_trailing_content() {
        let key = generate_keypair();
        let created = "2025-01-15T10:30:00Z";
        let mut serialized = serialize_key_file(&key, created);
        serialized.extend_from_slice(b"\n"); // Extra blank line
        let result = parse_key_file(&serialized);
        assert!(matches!(result, Err(KeyError::TrailingContent)));
    }

    #[test]
    fn reject_key_invalid_seed() {
        // Valid base64 but wrong length
        let content = b"fuz-signing-key-v1\npublic: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nseed: AAAA\ncreated: 2025-01-15T10:30:00Z\n";
        let result = parse_key_file(content);
        assert!(matches!(result, Err(KeyError::InvalidSeedLength(_))));
    }

    #[test]
    fn reject_key_invalid_base64() {
        let content = b"fuz-signing-key-v1\npublic: not!valid!base64!\nseed: AAAA\ncreated: 2025-01-15T10:30:00Z\n";
        let result = parse_key_file(content);
        assert!(matches!(result, Err(KeyError::InvalidBase64(_))));
    }

    #[test]
    fn reject_key_invalid_timestamp() {
        let key = generate_keypair();
        let content = format!(
            "fuz-signing-key-v1\npublic: {}\nseed: {}\ncreated: not-a-timestamp\n",
            STANDARD.encode(key.verifying_key().as_bytes()),
            STANDARD.encode(key.to_bytes()),
        );
        let result = parse_key_file(content.as_bytes());
        assert!(matches!(result, Err(KeyError::InvalidTimestamp)));
    }

    #[test]
    fn reject_key_mismatched_public_key() {
        let key = generate_keypair();
        let wrong_key = generate_keypair();
        let content = format!(
            "fuz-signing-key-v1\npublic: {}\nseed: {}\ncreated: 2025-01-15T10:30:00Z\n",
            STANDARD.encode(wrong_key.verifying_key().as_bytes()), // Wrong public key
            STANDARD.encode(key.to_bytes()),
        );
        let result = parse_key_file(content.as_bytes());
        assert!(matches!(result, Err(KeyError::PublicKeyMismatch)));
    }

    #[test]
    #[should_panic(expected = "invalid timestamp format")]
    fn serialize_key_file_panics_on_invalid_timestamp() {
        let key = generate_keypair();
        serialize_key_file(&key, "not-valid");
    }

    #[test]
    fn rfc3339_now_is_an_accepted_key_timestamp() {
        // The validator and `fuz_sys::rfc3339_now()` are coupled by
        // convention: `serialize_key_file` *panics* on a timestamp the validator
        // rejects (see `serialize_key_file_panics_on_invalid_timestamp`). Pin
        // that the live formatter's output is actually accepted, so a format
        // change in `rfc3339_now()` (fractional seconds, an offset) can't turn
        // key generation into a panic without this test catching it first.
        let now = fuz_sys::rfc3339_now();
        assert!(
            is_rfc3339_utc_seconds(&now),
            "rfc3339_now() produced {now:?}, which is_rfc3339_utc_seconds rejects"
        );
        // The panic-guarded path accepts it too.
        let key = generate_keypair();
        let _serialized = serialize_key_file(&key, &now);
    }
}
