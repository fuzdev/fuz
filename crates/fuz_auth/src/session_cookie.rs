//! Session cookie format, parsing, and lifetime helpers.
//!
//! Cookie value: `keyring.sign("{session_token}:{expires_at}")`. The
//! signed payload carries both the raw session token (identity) and an
//! expiry timestamp; the keyring HMAC closes both the token-bind and the
//! freshness check in one signature.

use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::credential_headers::read_session_cookie_value;
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

/// The attributes every session `Set-Cookie` carries, in the order written —
/// `fuz_app`'s `SESSION_COOKIE_ATTRIBUTES`, byte for byte. Fixed: the spine
/// writes one cookie.
pub const SESSION_COOKIE_ATTRIBUTES: &str = "Path=/; HttpOnly; Secure; SameSite=Strict";

/// Why a session `Set-Cookie` could not be written — the name or the value
/// would not read back out of a `Cookie` header as it was written.
///
/// Carries the name (a server constant) and never the value, which is a
/// credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionCookieError {
    /// The cookie name is not an RFC 6265 `cookie-name` ([`is_cookie_name`]).
    #[error("session cookie name {0:?} is not an RFC 6265 cookie-name")]
    InvalidName(String),
    /// The value holds a character outside RFC 6265's `cookie-octet`s
    /// ([`is_cookie_value`]).
    #[error(
        "session cookie {0:?}: the signed value holds a character outside RFC 6265's cookie-octets"
    )]
    InvalidValue(String),
}

/// Whether `name` is an RFC 6265 `cookie-name`.
///
/// An HTTP `token`: one or more characters of visible ASCII less the
/// separators (`=`, `;`, `,`, space, quotes, brackets and the rest). Twin of
/// `fuz_app`'s `is_cookie_name`.
#[must_use]
pub fn is_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Whether `value` is an RFC 6265 `cookie-value` in its unquoted form.
///
/// Only `cookie-octet`s: visible ASCII less `"`, `,`, `;` and `\`. Such a
/// value reads back out of a `Cookie` header exactly as it was written, which
/// is what a reader that decodes nothing needs. Twin of `fuz_app`'s
/// `is_cookie_value`.
#[must_use]
pub fn is_cookie_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
}

/// How a request's `Cookie` lines read for the session cookie — what the
/// cookie alone shows, before any database work.
///
/// `Debug` redacts the token through [`SessionCookie`]'s.
#[derive(Debug)]
pub enum SessionCookieRead {
    /// No pair names the cookie.
    Absent,
    /// A pair names it and its value fails verification: unreadable, a bad
    /// MAC, a signed expiry that has passed, an empty identity, or an empty
    /// value. What the stack clears.
    Invalid,
    /// It verifies under the keyring and its signed expiry is ahead. Says
    /// nothing about the `auth_session` row.
    Valid(SessionCookie),
}

impl SessionCookieRead {
    /// The verified cookie, `None` for an absent or invalid one.
    #[must_use]
    pub fn valid(self) -> Option<SessionCookie> {
        match self {
            Self::Valid(cookie) => Some(cookie),
            Self::Absent | Self::Invalid => None,
        }
    }
}

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

/// Read the session cookie out of a request's headers.
///
/// Reads the `cookie_name` cookie from every `Cookie` line
/// ([`read_session_cookie_value`]), verifies its HMAC signature via the
/// keyring (with rotation support), checks expiration, and answers the
/// embedded session token with its signed expiry. `cookie_name` is the
/// per-app session cookie name (default [`SESSION_COOKIE_NAME`]).
///
/// The three answers are what the cookie alone shows ([`SessionCookieRead`]):
/// no pair names it; a pair does and its value fails verification — a value
/// holding a byte outside ASCII, an empty one, a bad MAC, a signed expiry
/// that has passed, an empty identity; or it is valid. A valid cookie whose
/// `auth_session` row is gone is still valid here.
#[must_use]
pub fn parse_session_from_cookies(
    headers: &HeaderMap,
    keyring: &Keyring,
    cookie_name: &str,
) -> SessionCookieRead {
    let Some(value) = read_session_cookie_value(headers, cookie_name) else {
        return SessionCookieRead::Absent;
    };
    // a signed value is ASCII; anything else is no cookie this server wrote
    let verified = std::str::from_utf8(value)
        .ok()
        .filter(|signed_value| signed_value.is_ascii())
        .and_then(|signed_value| verify_session_cookie_value(signed_value, keyring));
    verified.map_or(SessionCookieRead::Invalid, SessionCookieRead::Valid)
}

/// Verify one signed cookie value: the MAC, the `expires_at` grammar and
/// freshness, and a non-empty identity.
fn verify_session_cookie_value(signed_value: &str, keyring: &Keyring) -> Option<SessionCookie> {
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

/// Build the `Set-Cookie` header value that sets the session cookie.
///
/// `<name>=<value>; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=<max_age>`,
/// `fuz_app`'s string. The value is written as given — never percent-encoded
/// or quoted — so the cookie either spine mints verifies on both.
///
/// # Errors
///
/// [`SessionCookieError`] when the name is not an RFC 6265 `cookie-name` or
/// the value holds anything but `cookie-octet`s — a header that would read
/// back differently is never written.
pub fn format_session_set_cookie(
    cookie_name: &str,
    value: &str,
    max_age: u64,
) -> Result<String, SessionCookieError> {
    if !is_cookie_name(cookie_name) {
        return Err(SessionCookieError::InvalidName(cookie_name.to_owned()));
    }
    if !is_cookie_value(value) {
        return Err(SessionCookieError::InvalidValue(cookie_name.to_owned()));
    }
    Ok(format!(
        "{cookie_name}={value}; {SESSION_COOKIE_ATTRIBUTES}; Max-Age={max_age}"
    ))
}

/// Build the `Set-Cookie` header value that clears the `cookie_name` session
/// cookie (default [`SESSION_COOKIE_NAME`]).
///
/// `<name>=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
/// `fuz_app`'s string.
///
/// # Errors
///
/// [`SessionCookieError::InvalidName`] when the name is not an RFC 6265
/// `cookie-name`.
pub fn format_session_clear_cookie(cookie_name: &str) -> Result<String, SessionCookieError> {
    if !is_cookie_name(cookie_name) {
        return Err(SessionCookieError::InvalidName(cookie_name.to_owned()));
    }
    Ok(format!(
        "{cookie_name}=; {SESSION_COOKIE_ATTRIBUTES}; Max-Age=0"
    ))
}

/// Sign a session token into a session cookie value.
///
/// The keyring's signature of `{session_token}:{expires_at}`, the expiry
/// [`SESSION_AGE_MAX`] from now — what a `Cookie` header carries after
/// `<name>=`. Twin of `fuz_app`'s `create_session_cookie_value`.
#[must_use]
pub fn create_session_cookie_value(keyring: &Keyring, session_token: &str) -> String {
    keyring.sign(&format!("{session_token}:{}", now_secs() + SESSION_AGE_MAX))
}

/// Sign a session token and build the `Set-Cookie` header value that sets it
/// under `cookie_name` (default [`SESSION_COOKIE_NAME`]).
///
/// [`format_session_set_cookie`] over [`create_session_cookie_value`], with
/// [`SESSION_AGE_MAX`] as its lifetime.
///
/// # Errors
///
/// [`SessionCookieError`] when the name, or the signed value (a
/// `session_token` holding a character outside the `cookie-octet`s), cannot
/// be written.
pub fn sign_session_cookie(
    keyring: &Keyring,
    session_token: &str,
    cookie_name: &str,
) -> Result<String, SessionCookieError> {
    format_session_set_cookie(
        cookie_name,
        &create_session_cookie_value(keyring, session_token),
        SESSION_AGE_MAX,
    )
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

    /// The request headers of one `Cookie` line.
    fn cookie_headers(lines: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(
                axum::http::header::COOKIE,
                axum::http::HeaderValue::from_bytes(line).expect("a header value"),
            );
        }
        headers
    }

    fn parse(keyring: &Keyring, lines: &[&[u8]]) -> SessionCookieRead {
        parse_session_from_cookies(&cookie_headers(lines), keyring, SESSION_COOKIE_NAME)
    }

    /// The cookie value of a `Set-Cookie` string.
    fn set_cookie_value(set_cookie: &str) -> &str {
        set_cookie
            .strip_prefix(&format!("{SESSION_COOKIE_NAME}="))
            .and_then(|s| s.split(';').next())
            .expect("cookie value")
    }

    #[test]
    fn sign_and_parse_round_trip() {
        let keyring = test_keyring();
        let session_token = "raw_token_abc";
        let cookie_header = sign_session_cookie(&keyring, session_token, SESSION_COOKIE_NAME)
            .expect("a writable cookie");
        // The Set-Cookie header includes attributes — extract just the value
        let cookie_value = set_cookie_value(&cookie_header);
        let parsed = parse(
            &keyring,
            &[format!("{SESSION_COOKIE_NAME}={cookie_value}").as_bytes()],
        );
        let parsed = parsed.valid().expect("a fresh cookie parses");
        assert_eq!(parsed.token, session_token);
        // the expiry signed beside the token is the cookie's lifetime from now
        let remaining = parsed.remaining().as_secs();
        assert!(
            (SESSION_AGE_MAX - 2..=SESSION_AGE_MAX).contains(&remaining),
            "a fresh cookie has its whole lifetime left, got {remaining}s"
        );
    }

    // Literal copies of the TS spine's strings (`format_session_set_cookie` /
    // `format_session_clear_cookie` in `fuz_app`), which pins the same ones.
    #[test]
    fn the_set_cookie_strings_are_exact() {
        assert_eq!(
            SESSION_COOKIE_ATTRIBUTES,
            "Path=/; HttpOnly; Secure; SameSite=Strict"
        );
        assert_eq!(
            format_session_set_cookie("fuz_session", "tok:1700000000.c2ln+/A=", 2_592_000)
                .as_deref(),
            Ok(
                "fuz_session=tok:1700000000.c2ln+/A=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000"
            )
        );
        assert_eq!(
            format_session_clear_cookie("fuz_session").as_deref(),
            Ok("fuz_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
        );
        // a signed cookie is the formatter over the keyring's own value
        let keyring = test_keyring();
        let signed = sign_session_cookie(&keyring, "raw_token_abc", SESSION_COOKIE_NAME)
            .expect("a writable cookie");
        let value = set_cookie_value(&signed);
        assert!(!value.contains('%'), "nothing is percent-encoded: {value}");
        assert_eq!(
            signed,
            format!(
                "fuz_session={value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_AGE_MAX}"
            )
        );
    }

    #[test]
    fn a_name_or_value_the_cookie_grammar_cannot_carry_is_refused() {
        for value in [
            "a b", "a;b", "a,b", "a\"b", "a\\b", "a\tb", "a\x7fb", "a\u{e9}b",
        ] {
            assert!(!is_cookie_value(value), "{value:?}");
            assert_eq!(
                format_session_set_cookie("fuz_session", value, 60),
                Err(SessionCookieError::InvalidValue("fuz_session".to_owned())),
                "{value:?}"
            );
        }
        for name in ["", "a=b", "a b", "a;b", "caf\u{e9}"] {
            assert!(!is_cookie_name(name), "{name:?}");
            let refused = Err(SessionCookieError::InvalidName(name.to_owned()));
            assert_eq!(format_session_set_cookie(name, "v", 60), refused);
            assert_eq!(format_session_clear_cookie(name), refused);
            assert_eq!(sign_session_cookie(&test_keyring(), "token", name), refused);
        }
        // a refusal names the cookie, never the value
        let error = format_session_set_cookie("fuz_session", "secret value", 60)
            .expect_err("a space is no cookie-octet");
        assert!(!error.to_string().contains("secret"), "{error}");
        // every token character is a name; every cookie-octet a value
        assert!(is_cookie_name("!#$%&'*+-.^_`|~09AZaz"));
        let octets: String = (0x21u8..=0x7e)
            .map(char::from)
            .filter(|c| !"\",;\\".contains(*c))
            .collect();
        assert!(is_cookie_value(&octets));
        assert!(
            is_cookie_value(""),
            "the clear cookie writes an empty value"
        );
    }

    /// What the cookie alone shows: absent, invalid, or valid.
    #[test]
    fn parse_answers_absent_invalid_or_valid() {
        let keyring = test_keyring();
        let name = SESSION_COOKIE_NAME;
        let signed = sign_session_cookie(&keyring, "raw_token_abc", name).expect("a cookie");
        let value = set_cookie_value(&signed);
        let read = |lines: &[String]| {
            let lines: Vec<&[u8]> = lines.iter().map(String::as_bytes).collect();
            match parse(&keyring, &lines) {
                SessionCookieRead::Absent => "absent",
                SessionCookieRead::Invalid => "invalid",
                SessionCookieRead::Valid(_) => "valid",
            }
        };
        assert_eq!(read(&[]), "absent");
        assert_eq!(read(&["other=foo".to_owned()]), "absent");
        assert_eq!(read(&[format!("{name} ={value}")]), "absent");
        assert_eq!(read(&[format!("{name}={value}")]), "valid");
        assert_eq!(read(&[format!("a=1;\t{name}={value} ; b=2")]), "valid");
        // every Cookie line is read, joined in order
        assert_eq!(
            read(&["a=1".to_owned(), format!("{name}={value}")]),
            "valid"
        );
        assert_eq!(
            read(&[format!("{name}=bogus"), format!("{name}={value}")]),
            "invalid"
        );
        // an empty value is present and invalid, not absent
        assert_eq!(read(&[format!("{name}=")]), "invalid");
        // nothing is decoded, unquoted, or trimmed inside the value
        assert_eq!(read(&[format!("{name}=\"{value}\"")]), "invalid");
        assert_eq!(read(&[format!("a=1; {name}= {value}")]), "invalid");
        assert_eq!(
            read(&[format!("{name}={}", value.replace(':', "%3A"))]),
            "invalid"
        );
        // a first pair that fails is not skipped for a later one
        assert_eq!(read(&[format!("{name}=bogus; {name}={value}")]), "invalid");
        assert_eq!(read(&[format!("{name}={value}; {name}=bogus")]), "valid");
    }

    /// The header is read as bytes: a byte outside ASCII in another cookie
    /// hides nothing, and one in the session value makes it invalid.
    #[test]
    fn parse_reads_the_header_as_bytes() {
        let keyring = test_keyring();
        let name = SESSION_COOKIE_NAME;
        let signed = sign_session_cookie(&keyring, "raw_token_abc", name).expect("a cookie");
        let value = set_cookie_value(&signed);
        let sibling = [b"a=caf\xe9; ", format!("{name}={value}").as_bytes()].concat();
        assert!(matches!(
            parse(&keyring, &[&sibling]),
            SessionCookieRead::Valid(_)
        ));
        let in_value = [format!("{name}={value}").as_bytes(), b"\xe9"].concat();
        assert!(matches!(
            parse(&keyring, &[&in_value]),
            SessionCookieRead::Invalid
        ));
        // 0xA0 is no whitespace: before the name it is part of another name
        let nbsp = [b"a=1;\xa0", format!("{name}={value}").as_bytes()].concat();
        assert!(matches!(
            parse(&keyring, &[&nbsp]),
            SessionCookieRead::Absent
        ));
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

    /// The expiry is read as the twin reads it: ASCII digits and nothing
    /// else. Each payload is signed with the server's own key, so only the
    /// expiry grammar can refuse it.
    #[test]
    fn parse_reads_the_expiry_as_digits_only() {
        let keyring = test_keyring();
        let read = |payload: &str| {
            parse(
                &keyring,
                &[format!("{SESSION_COOKIE_NAME}={}", keyring.sign(payload)).as_bytes()],
            )
        };
        let expires_at = now_secs() + 60;
        assert!(matches!(
            read(&format!("tok:{expires_at}")),
            SessionCookieRead::Valid(_)
        ));
        assert!(matches!(
            read(&format!("tok:0{expires_at}")),
            SessionCookieRead::Valid(_)
        ));
        for refused in [
            format!("tok:+{expires_at}"),
            format!("tok:-{expires_at}"),
            format!("tok: {expires_at}"),
            format!("tok:{expires_at} "),
            format!("tok:{expires_at}.0"),
            "tok:".to_owned(),
            "tok:18446744073709551616".to_owned(),
            // a signed expiry that has passed, and an empty identity
            format!("tok:{}", now_secs() - 1),
            format!(":{expires_at}"),
        ] {
            assert!(
                matches!(read(&refused), SessionCookieRead::Invalid),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn parse_rejects_invalid_signature() {
        let keyring = test_keyring();
        assert!(matches!(
            parse(
                &keyring,
                &[format!("{SESSION_COOKIE_NAME}=bogus.value").as_bytes()]
            ),
            SessionCookieRead::Invalid
        ));
    }
}
