//! Session-token hashing.
//!
//! blake3 hex digest used as the storage key for `auth_session`. The
//! function returns a `SessionHash` newtype so callers can't confuse a
//! hash with the raw token. The newtype wraps `String` today; future
//! micro-opt to `ArrayString<64>` lives behind the same constructor.

use std::ops::Deref;

/// blake3 hex digest of a session token. Newtype over `String` so the
/// type system distinguishes hashed and raw tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionHash(String);

impl SessionHash {
    /// Borrow as a `&str` for query parameters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the inner `String`.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for SessionHash {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for SessionHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Hash a session token to its storage key using blake3.
///
/// Mirrors `fuz_app`'s `hash_session_token` from
/// `session_queries.ts`. Output is a 64-character lowercase hex string.
#[must_use]
pub fn hash_session_token(token: &str) -> SessionHash {
    SessionHash(blake3::hash(token.as_bytes()).to_hex().to_string())
}

/// Length of a session id — a blake3-256 digest in hex.
pub const SESSION_ID_LENGTH: usize = 64;

/// Whether `s` is a valid session id — the blake3 hex digest
/// [`hash_session_token`] produces, and the only shape `auth_session.id`
/// ever holds.
///
/// Twin of the TS `SessionId` brand (`Blake3Hash.brand('SessionId')`, whose
/// shape is `z.string().regex(/^[0-9a-f]{64}$/)`): exactly 64 **lowercase**
/// hex characters. Uppercase hex is refused on both spines — a digest that
/// did not come from the hasher is not a session id, whatever it decodes to.
///
/// Like the id grammars in [`crate::primitive_schemas`], this exists so a
/// wire surface refuses the same strings on both spines: without it
/// `account_session_revoke` answers a `{ok: true, revoked: false}` success
/// envelope for input the twin refuses with `invalid_params`.
#[must_use]
pub fn is_valid_session_id(s: &str) -> bool {
    s.len() == SESSION_ID_LENGTH
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_64_chars_lowercase_hex() {
        let h = hash_session_token("abc");
        assert_eq!(h.as_str().len(), 64);
        assert!(
            h.as_str()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(
            hash_session_token("hello").as_str(),
            hash_session_token("hello").as_str(),
        );
    }

    /// The grammar twins the TS `SessionId` brand, and the hasher's own
    /// output is the positive control — a predicate that rejected a real
    /// digest would lock every caller out of their own session list.
    #[test]
    fn session_id_accepts_a_real_digest_and_rejects_everything_else() {
        assert!(is_valid_session_id(hash_session_token("abc").as_str()));
        assert!(is_valid_session_id(&"0".repeat(SESSION_ID_LENGTH)));
        assert!(is_valid_session_id(&"abcdef0123456789".repeat(4)));
        // Wrong length, either side.
        assert!(!is_valid_session_id(""));
        assert!(!is_valid_session_id(&"a".repeat(SESSION_ID_LENGTH - 1)));
        assert!(!is_valid_session_id(&"a".repeat(SESSION_ID_LENGTH + 1)));
        // Uppercase hex — a real digest never renders this way, and the TS
        // regex has no `i` flag.
        assert!(!is_valid_session_id(&"A".repeat(SESSION_ID_LENGTH)));
        // Non-hex characters at full width, and the shapes a caller sends
        // when it has the wrong id.
        assert!(!is_valid_session_id(&"g".repeat(SESSION_ID_LENGTH)));
        assert!(!is_valid_session_id("3f8a1c2e-1234-4abc-9def-0123456789ab"));
        assert!(!is_valid_session_id("' OR 1=1--"));
    }

    #[test]
    fn hash_differs_for_different_inputs() {
        assert_ne!(
            hash_session_token("a").as_str(),
            hash_session_token("b").as_str(),
        );
    }
}
