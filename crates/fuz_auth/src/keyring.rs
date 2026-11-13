//! Cookie signing keyring (HMAC-SHA256) with key rotation.
//!
//! The first key signs; all keys verify, supporting rolling rotation.
//! Mirrors `fuz_app`'s `src/lib/auth/keyring.ts`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Separator between keys in `SECRET_FUZ_COOKIE_KEYS`.
pub const KEY_SEPARATOR: &str = "__";

/// Minimum keyring key length, in UTF-16 code units — the TS twin's
/// `String.length`, so both spines accept the same keys.
pub const MIN_KEY_LENGTH: usize = 32;

/// One reason a keyring value is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyringError {
    /// The value holds no key once empty entries are skipped.
    #[error("no keys supplied")]
    NoKeys,
    /// A key is shorter than [`MIN_KEY_LENGTH`]. `position` is 1-based, as in
    /// the TS twin's `validate_keyring` message.
    #[error("key {position} is too short ({len} chars, min {MIN_KEY_LENGTH})")]
    KeyTooShort { position: usize, len: usize },
}

/// Every reason [`Keyring::new`] refused a value — never empty.
///
/// `Display` joins the reasons with `"; "`, so a boot error can carry them on
/// one line behind the name of the variable the value came from.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", join_errors(.0))]
pub struct KeyringErrors(Vec<KeyringError>);

impl KeyringErrors {
    /// The individual reasons, in key order.
    #[must_use]
    pub fn errors(&self) -> &[KeyringError] {
        &self.0
    }
}

fn join_errors(errors: &[KeyringError]) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Cookie signing keyring.
///
/// First key signs; all keys verify (supports key rotation). Held by
/// value on the consumer's auth state — one algorithm, no swap point, no
/// trait wrap.
///
/// **Rotation.** Put the new key first and keep the old one after it: new
/// cookies are signed with the new key, and cookies the old key signed keep
/// verifying. Nothing re-signs a cookie, so an old key stays live until the
/// last cookie it signed expires — [`crate::SESSION_AGE_MAX`] after the
/// rotation — and dropping it sooner signs out every session it still
/// carries. A key that leaked is dropped at once, since it can forge cookies
/// for as long as it is listed.
///
/// `Debug` shows the key count, never the key bytes.
#[derive(Clone)]
pub struct Keyring {
    keys: Vec<Vec<u8>>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("key_count", &self.keys.len())
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl Keyring {
    /// Create a keyring from a keys value (conventionally the
    /// `SECRET_FUZ_COOKIE_KEYS` env var, which the caller reads).
    ///
    /// Keys are split on [`KEY_SEPARATOR`]; empty entries are skipped. The
    /// first key signs, every key verifies. Twin of the TS `create_keyring`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyringErrors`] when no key remains, or with one
    /// [`KeyringError::KeyTooShort`] per key shorter than [`MIN_KEY_LENGTH`].
    pub fn new(value: &str) -> Result<Self, KeyringErrors> {
        let keys: Vec<&str> = value
            .split(KEY_SEPARATOR)
            .filter(|k| !k.is_empty())
            .collect();
        if keys.is_empty() {
            return Err(KeyringErrors(vec![KeyringError::NoKeys]));
        }
        let errors: Vec<KeyringError> = keys
            .iter()
            .enumerate()
            .filter_map(|(i, key)| {
                let len = key.encode_utf16().count();
                (len < MIN_KEY_LENGTH).then_some(KeyringError::KeyTooShort {
                    position: i + 1,
                    len,
                })
            })
            .collect();
        if !errors.is_empty() {
            return Err(KeyringErrors(errors));
        }
        Ok(Self {
            keys: keys.iter().map(|k| k.as_bytes().to_vec()).collect(),
        })
    }

    /// Sign `value` with HMAC-SHA256 using the primary (first) key.
    /// Returns `value.base64(signature)`.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: `HmacSha256::new_from_slice` only
    /// returns `Err` if the requested output size is invalid, which is
    /// fixed by the type (`Hmac<Sha256>`). The `expect` is documenting
    /// an invariant the type system already enforces.
    #[must_use]
    pub fn sign(&self, value: &str) -> String {
        #[expect(
            clippy::expect_used,
            reason = "invariant enforced by `Hmac<Sha256>`: it accepts any key length"
        )]
        let mut mac =
            HmacSha256::new_from_slice(&self.keys[0]).expect("HMAC-SHA256 accepts any key length");
        mac.update(value.as_bytes());
        let signature = mac.finalize().into_bytes();
        let sig_b64 = BASE64.encode(signature);
        format!("{value}.{sig_b64}")
    }

    /// Verify a signed value. Tries every key (rotation support).
    /// Returns `(original_value, key_index)` or `None` on failure.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice — see [`Keyring::sign`].
    #[must_use]
    pub fn verify(&self, signed_value: &str) -> Option<(String, usize)> {
        let dot_index = signed_value.rfind('.')?;
        let value = &signed_value[..dot_index];
        let sig_b64 = &signed_value[dot_index + 1..];

        let signature = BASE64.decode(sig_b64).ok()?;

        for (i, key) in self.keys.iter().enumerate() {
            #[expect(
                clippy::expect_used,
                reason = "invariant enforced by `Hmac<Sha256>`: it accepts any key length"
            )]
            let mut mac =
                HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
            mac.update(value.as_bytes());
            if mac.verify_slice(&signature).is_ok() {
                return Some((value.to_owned(), i));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_refuses_an_empty_value() {
        for value in ["", KEY_SEPARATOR, "____"] {
            let errors = Keyring::new(value).unwrap_err();
            assert_eq!(errors.errors(), &[KeyringError::NoKeys], "{value:?}");
            assert_eq!(errors.to_string(), "no keys supplied");
        }
    }

    #[test]
    fn new_refuses_each_short_key_with_its_position() {
        let ok = "a".repeat(MIN_KEY_LENGTH);
        let value = format!("short{KEY_SEPARATOR}{ok}{KEY_SEPARATOR}tiny");
        let errors = Keyring::new(&value).unwrap_err();
        assert_eq!(
            errors.errors(),
            &[
                KeyringError::KeyTooShort {
                    position: 1,
                    len: 5
                },
                KeyringError::KeyTooShort {
                    position: 3,
                    len: 4
                },
            ]
        );
        assert_eq!(
            errors.to_string(),
            "key 1 is too short (5 chars, min 32); key 3 is too short (4 chars, min 32)"
        );
    }

    #[test]
    fn new_skips_empty_entries_when_numbering() {
        let ok = "a".repeat(MIN_KEY_LENGTH);
        let value = format!("{KEY_SEPARATOR}{ok}{KEY_SEPARATOR}{KEY_SEPARATOR}short");
        let errors = Keyring::new(&value).unwrap_err();
        assert_eq!(
            errors.errors(),
            &[KeyringError::KeyTooShort {
                position: 2,
                len: 5
            }]
        );
    }

    #[test]
    fn new_accepts_a_min_length_key_and_refuses_one_less() {
        assert!(Keyring::new(&"a".repeat(MIN_KEY_LENGTH)).is_ok());
        assert!(Keyring::new(&"a".repeat(MIN_KEY_LENGTH - 1)).is_err());
    }

    #[test]
    fn new_counts_utf16_code_units_like_the_twin() {
        // 16 two-byte chars: 32 bytes but 16 code units — short, as on the TS spine
        let errors = Keyring::new(&"\u{e9}".repeat(16)).unwrap_err();
        assert_eq!(
            errors.errors(),
            &[KeyringError::KeyTooShort {
                position: 1,
                len: 16
            }]
        );
    }

    #[test]
    fn debug_redacts_keys() {
        let primary = "primary-secret-key-bytes-0123456789";
        let secondary = "secondary-secret-key-bytes-0123456789";
        let keyring =
            Keyring::new(&format!("{primary}{KEY_SEPARATOR}{secondary}")).expect("valid keyring");
        let rendered = format!("{keyring:?}");
        assert!(!rendered.contains(primary), "{rendered}");
        assert!(!rendered.contains(secondary), "{rendered}");
        assert!(
            !rendered.contains("112, 114"),
            "key bytes leaked: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("key_count: 2"), "{rendered}");
    }

    #[test]
    fn round_trip_sign_verify() {
        let key = "k".repeat(MIN_KEY_LENGTH);
        let keyring = Keyring::new(&key).expect("valid keyring");
        let signed = keyring.sign("payload");
        let (value, idx) = keyring.verify(&signed).expect("verify");
        assert_eq!(value, "payload");
        assert_eq!(idx, 0);
    }

    #[test]
    fn verify_rejects_tampered() {
        let key = "k".repeat(MIN_KEY_LENGTH);
        let keyring = Keyring::new(&key).expect("valid keyring");
        let signed = keyring.sign("payload");
        // Truncate by one char to break the signature
        let tampered = &signed[..signed.len() - 1];
        assert!(keyring.verify(tampered).is_none());
    }

    #[test]
    fn rotation_verifies_with_secondary_key() {
        let primary = "p".repeat(MIN_KEY_LENGTH);
        let secondary = "s".repeat(MIN_KEY_LENGTH);

        // Old keyring with secondary as primary
        let old = Keyring::new(&secondary).expect("valid keyring");
        let signed_with_old = old.sign("payload");

        // New keyring with primary + secondary (both valid)
        let env = format!("{primary}{KEY_SEPARATOR}{secondary}");
        let rotating = Keyring::new(&env).expect("valid keyring");
        let (value, idx) = rotating.verify(&signed_with_old).expect("verify");
        assert_eq!(value, "payload");
        assert_eq!(idx, 1);
    }
}
