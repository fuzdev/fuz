//! Session cookie format, parsing, and lifetime helpers.
//!
//! Cookie value: `keyring.sign("{session_token}:{expires_at}")`. The
//! signed payload carries both the raw session token (identity) and an
//! expiry timestamp; the keyring HMAC closes both the token-bind and the
//! freshness check in one signature.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::keyring::Keyring;

/// Default cookie name (`fuz_session`). Matches `fuz_app`'s convention so
/// cookies issued by either backend interoperate at the wire level.
///
/// Consumers thread a per-app name through the route states + the
/// cookie helpers below — most pass this default, but an app with a custom
/// cookie name (e.g. `my_app_session`) passes its own so
/// both its TS and Rust backends emit the same cookie.
pub const SESSION_COOKIE_NAME: &str = "fuz_session";

/// Cookie max-age in seconds — 30 days. Mirrors `fuz_app`'s
/// `AUTH_SESSION_LIFETIME_MS`.
pub const SESSION_AGE_MAX: u64 = 60 * 60 * 24 * 30;

/// Separator between the identity payload and the `expires_at` timestamp.
const VALUE_SEPARATOR: char = ':';

/// A verified, unexpired session cookie: the raw session token it carries and
/// the expiry signed beside it.
///
/// `Debug` redacts the token, a live credential.
pub struct SessionCookie {
    /// The raw session token — its blake3 hash is the `auth_session` row id.
    pub token: String,
    /// The signed expiry, in seconds since the Unix epoch — later than the
    /// moment the cookie was parsed.
    pub expires_at: u64,
}

impl std::fmt::Debug for SessionCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCookie")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SessionCookie {
    /// How long the cookie has left, by this server's wall clock — the clock
    /// that signed it and that [`parse_session_from_cookies`] checked it
    /// against. Measured from the current instant, not the current second, so
    /// it agrees with the TS twin's millisecond reading. An expiry past what a
    /// [`std::time::SystemTime`] holds saturates.
    #[must_use]
    pub fn remaining(&self) -> std::time::Duration {
        std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(self.expires_at))
            .map_or(std::time::Duration::MAX, |expires_at| {
                expires_at
                    .duration_since(std::time::SystemTime::now())
                    .unwrap_or_default()
            })
    }
}

/// Parse the session cookie from a Cookie header.
///
/// Extracts the `cookie_name` cookie, verifies its HMAC signature via
/// the keyring (with rotation support), checks expiration, and returns
/// the embedded session token with its signed expiry. `cookie_name` is the
/// per-app session cookie name (default [`SESSION_COOKIE_NAME`]).
#[must_use]
pub fn parse_session_from_cookies(
    cookie_header: &str,
    keyring: &Keyring,
    cookie_name: &str,
) -> Option<SessionCookie> {
    let signed_value = extract_cookie_value(cookie_header, cookie_name)?;

    let (value, _key_index) = keyring.verify(signed_value)?;

    let last_sep = value.rfind(VALUE_SEPARATOR)?;
    let identity = &value[..last_sep];
    let expires_at_str = &value[last_sep + 1..];

    // ASCII digits only, as the TS twin's `EXPIRES_AT_INTEGER_RE` (`^\d+$`)
    // reads it — `u64::from_str` alone also takes a leading `+`
    if expires_at_str.is_empty() || !expires_at_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let expires_at: u64 = expires_at_str.parse().ok()?;

    if expires_at <= now_secs() {
        return None;
    }

    if identity.is_empty() {
        return None;
    }

    Some(SessionCookie {
        token: identity.to_owned(),
        expires_at,
    })
}

/// Extract a named cookie value from a `Cookie` header string.
fn extract_cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix(name)
            && let Some(value) = rest.strip_prefix('=')
        {
            return Some(value);
        }
    }
    None
}

/// Current time in seconds since the Unix epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a cryptographically random session token (base64url, 32 bytes).
///
/// Uses `getrandom` directly — we want the OS-provided RNG, not a
/// thread-local `rand` ecosystem RNG. The OS source is the only
/// dependency we trust for credential entropy; a wrapper chain
/// (`rand` → `rand_core` → `getrandom`) adds versioning churn and
/// pulls in seeding code we never need. The direct dep is the
/// smaller surface area.
///
/// # Panics
///
/// Panics if `getrandom::fill` fails — effectively unreachable on
/// supported platforms.
#[must_use]
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    #[expect(
        clippy::expect_used,
        reason = "OS RNG availability is a platform invariant"
    )]
    getrandom::fill(&mut bytes).expect("getrandom should always succeed on supported platforms");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Build a signed `Set-Cookie` header value for a session under
/// `cookie_name` (default [`SESSION_COOKIE_NAME`]).
#[must_use]
pub fn sign_session_cookie(keyring: &Keyring, session_token: &str, cookie_name: &str) -> String {
    let cookie_value = keyring.sign(&format!("{session_token}:{}", now_secs() + SESSION_AGE_MAX));
    format!(
        "{cookie_name}={cookie_value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_AGE_MAX}"
    )
}

/// Build a `Set-Cookie` header that clears the `cookie_name` session
/// cookie (default [`SESSION_COOKIE_NAME`]).
#[must_use]
pub fn clear_session_cookie(cookie_name: &str) -> String {
    format!("{cookie_name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::MIN_KEY_LENGTH;

    fn test_keyring() -> Keyring {
        let key = "k".repeat(MIN_KEY_LENGTH);
        Keyring::new(&key).expect("valid keyring")
    }

    #[test]
    fn generate_session_token_is_43_chars() {
        let token = generate_session_token();
        assert_eq!(token.len(), 43, "32 bytes base64url-encoded = 43 chars");
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let keyring = test_keyring();
        let session_token = "raw_token_abc";
        let cookie_header = sign_session_cookie(&keyring, session_token, SESSION_COOKIE_NAME);
        // The Set-Cookie header includes attributes — extract just the value
        let cookie_value = cookie_header
            .strip_prefix(&format!("{SESSION_COOKIE_NAME}="))
            .and_then(|s| s.split(';').next())
            .expect("cookie value");
        let parsed = parse_session_from_cookies(
            &format!("{SESSION_COOKIE_NAME}={cookie_value}"),
            &keyring,
            SESSION_COOKIE_NAME,
        );
        let parsed = parsed.expect("a fresh cookie parses");
        assert_eq!(parsed.token, session_token);
        // the expiry signed beside the token is the cookie's lifetime from now
        let remaining = parsed.remaining().as_secs();
        assert!(
            (SESSION_AGE_MAX - 2..=SESSION_AGE_MAX).contains(&remaining),
            "a fresh cookie has its whole lifetime left, got {remaining}s"
        );
    }

    /// The time left is read from the current instant, not floored to the
    /// current second: it lies between the expiry measured from just before
    /// and from just after the read.
    #[test]
    fn remaining_is_sub_second_precise() {
        let expires_at = now_secs() + 60;
        let cookie = SessionCookie {
            token: String::new(),
            expires_at,
        };
        let expiry = std::time::UNIX_EPOCH + std::time::Duration::from_secs(expires_at);
        let before = std::time::SystemTime::now();
        let remaining = cookie.remaining();
        let after = std::time::SystemTime::now();
        assert!(
            expiry.duration_since(after).expect("expiry is ahead") <= remaining
                && remaining <= expiry.duration_since(before).expect("expiry is ahead"),
            "remaining {remaining:?} is not measured from the current instant"
        );
        // an expiry already passed has nothing left
        let passed = SessionCookie {
            token: String::new(),
            expires_at: 1,
        };
        assert_eq!(passed.remaining(), std::time::Duration::ZERO);
        // one past what a `SystemTime` holds saturates rather than panicking
        let far = SessionCookie {
            token: String::new(),
            expires_at: u64::MAX,
        };
        assert_eq!(far.remaining(), std::time::Duration::MAX);
    }

    #[test]
    fn parse_rejects_missing_cookie() {
        let keyring = test_keyring();
        assert!(parse_session_from_cookies("other=foo", &keyring, SESSION_COOKIE_NAME).is_none());
    }

    /// The expiry is read as the twin reads it: ASCII digits and nothing
    /// else. Each payload is signed with the server's own key, so only the
    /// expiry grammar can refuse it.
    #[test]
    fn parse_reads_the_expiry_as_digits_only() {
        let keyring = test_keyring();
        let parse = |payload: &str| {
            parse_session_from_cookies(
                &format!("{SESSION_COOKIE_NAME}={}", keyring.sign(payload)),
                &keyring,
                SESSION_COOKIE_NAME,
            )
        };
        let expires_at = now_secs() + 60;
        assert!(parse(&format!("tok:{expires_at}")).is_some());
        assert!(parse(&format!("tok:0{expires_at}")).is_some());
        for refused in [
            format!("tok:+{expires_at}"),
            format!("tok:-{expires_at}"),
            format!("tok: {expires_at}"),
            format!("tok:{expires_at} "),
            format!("tok:{expires_at}.0"),
            "tok:".to_owned(),
            "tok:18446744073709551616".to_owned(),
        ] {
            assert!(parse(&refused).is_none(), "{refused:?}");
        }
    }

    #[test]
    fn parse_rejects_invalid_signature() {
        let keyring = test_keyring();
        assert!(
            parse_session_from_cookies(
                &format!("{SESSION_COOKIE_NAME}=bogus.value"),
                &keyring,
                SESSION_COOKIE_NAME,
            )
            .is_none()
        );
    }
}
