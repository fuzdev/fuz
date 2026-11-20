//! The grammar of the three credential headers — the session cookie in
//! `Cookie`, the API token in `Authorization: Bearer`, the daemon token in
//! `X-Daemon-Token` — as pure readers over a request's headers.
//!
//! One spelling per credential, `fuz_app`'s `auth/credential_headers.ts`
//! reading the same one: a value either reads exactly, or it is not that
//! credential. Nothing is decoded, unquoted, or repaired — a lenient side
//! would authenticate a request the other refuses. The shared table
//! `credential_conformance.json` (owned by `fuz_app`, with a byte-identical
//! copy in `fuz_testing`) holds both spines to the same rows.
//!
//! Each reader takes the whole [`HeaderMap`] and reads **every** line of its
//! header ([`HeaderMap::get_all`]), so "sent twice" is something it can see
//! and decide on: `Cookie` lines are joined, and a repeated `Authorization`
//! or `X-Daemon-Token` is discarded.
//!
//! The credential walk ([`crate::AuthGate::resolve_credential`]) calls these,
//! and so does `fuz_testing`'s `_testing_credential_read` action.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use fuz_http::{single_line, trim_optional_whitespace};

use crate::api_token::is_api_token_shaped;
use crate::daemon_token::{DAEMON_TOKEN_HEADER, is_daemon_token_shaped};

/// The `Authorization` scheme of an API token, with the one SP that follows
/// it.
const BEARER_PREFIX: &str = "bearer ";

/// Read the session cookie's value out of the request's `Cookie` lines.
///
/// Several `Cookie` lines read as one value joined with `; ` — what Node and
/// Bun hand the TS twin, and RFC 9113's rule for HTTP/2 cookie crumbs. The
/// value is split on `;`, each pair is stripped of SP and HTAB at both ends
/// ([`fuz_http::trim_optional_whitespace`]), and the first pair that begins with exactly
/// `<cookie_name>=` wins. Its value is the rest of the pair, verbatim: not
/// percent-decoded, not unquoted, whitespace after the `=` kept. A first pair
/// that will not verify is not skipped for a later one.
///
/// The header is read as bytes, so a byte outside ASCII in another cookie
/// hides nothing; whether the value itself is usable is the caller's to say
/// ([`crate::parse_session_from_cookies`] reads a non-ASCII one as invalid).
///
/// A pair with an empty value (`name=`) is present, and reads `Some(b"")` — an
/// invalid cookie to whatever verifies it, not an absent one. `None` when no
/// pair names the cookie.
#[must_use]
pub fn read_session_cookie_value<'h>(
    headers: &'h HeaderMap,
    cookie_name: &str,
) -> Option<&'h [u8]> {
    let name = cookie_name.as_bytes();
    // walking the lines in order is reading their `; ` join: the separator
    // holds the `;` the split is on
    headers
        .get_all(COOKIE)
        .iter()
        .flat_map(|line| line.as_bytes().split(|&b| b == b';'))
        .find_map(|part| {
            trim_optional_whitespace(part)
                .strip_prefix(name)?
                .strip_prefix(b"=")
        })
}

/// Read the API token out of the request's `Authorization` lines.
///
/// The header must be exactly one line: the scheme `Bearer` in any ASCII case,
/// one SP, and a value [`is_api_token_shaped`] accepts — nothing before,
/// between, or after. A header sent twice is discarded whatever its lines
/// hold, never resolved to one of them.
///
/// The TS twin on a runtime with no per-line view reads repeated lines joined
/// with `, `. No token holds a comma, so a lone line holding `, ` fails the
/// shape here too, and both spines discard both spellings.
///
/// `Some` is the token to look up; `None` when the header carries none.
#[must_use]
pub fn read_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = single_line(headers, AUTHORIZATION)?;
    // `get` refuses a split inside a character; the prefix is ASCII, so a
    // value it matches is split on a boundary
    let scheme = value.get(..BEARER_PREFIX.len())?;
    if !scheme.eq_ignore_ascii_case(BEARER_PREFIX) {
        return None;
    }
    let token = value.get(BEARER_PREFIX.len()..)?;
    is_api_token_shaped(token).then_some(token)
}

/// Read the daemon token out of the request's `X-Daemon-Token` lines.
///
/// The header must be exactly one line holding a value
/// [`is_daemon_token_shaped`] accepts. A header sent twice is discarded — an
/// empty second line included — and, as for [`read_bearer_token`], a lone line
/// holding `, ` fails the shape.
///
/// `Some` is the token to compare; `None` when the header carries none.
#[must_use]
pub fn read_daemon_token(headers: &HeaderMap) -> Option<&str> {
    let value = single_line(headers, DAEMON_TOKEN_HEADER)?;
    is_daemon_token_shaped(value).then_some(value)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;
    use crate::api_token::generate_api_token;

    fn headers(lines: &[(&'static str, &[u8])]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in lines {
            headers.append(
                *name,
                HeaderValue::from_bytes(value).expect("a header value"),
            );
        }
        headers
    }

    #[test]
    fn the_cookie_value_is_returned_verbatim() {
        let read = |lines: &[&[u8]]| {
            let headers = headers(&lines.iter().map(|l| ("cookie", *l)).collect::<Vec<_>>());
            read_session_cookie_value(&headers, "s").map(<[u8]>::to_vec)
        };
        assert_eq!(read(&[]), None);
        assert_eq!(read(&[b"a=1"]), None);
        assert_eq!(read(&[b"s="]), Some(b"".to_vec()));
        assert_eq!(read(&[b"s=a%3Ab"]), Some(b"a%3Ab".to_vec()));
        assert_eq!(read(&[b"s=\"q\""]), Some(b"\"q\"".to_vec()));
        assert_eq!(read(&[b"a=1; s= v"]), Some(b" v".to_vec()));
        assert_eq!(read(&[b"s=a=b"]), Some(b"a=b".to_vec()));
        assert_eq!(read(&[b"s =1"]), None);
        assert_eq!(read(&[b"s_x=1", b"xs=1"]), None);
        // every line is read, in order
        assert_eq!(read(&[b"a=1", b"s=2"]), Some(b"2".to_vec()));
        assert_eq!(read(&[b"s=1", b"s=2"]), Some(b"1".to_vec()));
        // a byte outside ASCII in a sibling hides nothing
        assert_eq!(read(&[b"a=\xe9; s=2"]), Some(b"2".to_vec()));
        assert_eq!(read(&[b"a=1;\xa0s=2"]), None);
    }

    #[test]
    fn a_repeated_token_header_is_discarded() {
        let token = generate_api_token().token;
        let bearer = format!("Bearer {token}");
        let one = headers(&[("authorization", bearer.as_bytes())]);
        assert_eq!(read_bearer_token(&one), Some(token.as_str()));
        for second in [bearer.as_bytes(), b"Bearer x", b"Basic x", b""] {
            let two = headers(&[
                ("authorization", bearer.as_bytes()),
                ("authorization", second),
            ]);
            assert_eq!(read_bearer_token(&two), None);
            let reversed = headers(&[
                ("authorization", second),
                ("authorization", bearer.as_bytes()),
            ]);
            assert_eq!(read_bearer_token(&reversed), None);
        }
        let daemon = "d".repeat(43);
        let one = headers(&[("x-daemon-token", daemon.as_bytes())]);
        assert_eq!(read_daemon_token(&one), Some(daemon.as_str()));
        for second in [daemon.as_bytes(), b"garbage", b""] {
            let two = headers(&[
                ("x-daemon-token", daemon.as_bytes()),
                ("x-daemon-token", second),
            ]);
            assert_eq!(read_daemon_token(&two), None);
        }
        assert_eq!(read_bearer_token(&HeaderMap::new()), None);
        assert_eq!(read_daemon_token(&HeaderMap::new()), None);
    }

    /// The bearer value is sliced at the prefix length; a multi-byte character
    /// across that offset must read as no token, never panic.
    #[test]
    fn a_non_ascii_authorization_value_reads_no_token() {
        let token = generate_api_token().token;
        for value in [
            format!("Bearer {token}\u{e9}").into_bytes(),
            format!("Beare\u{e9} {token}").into_bytes(),
            b"Bear\xc3\xa9".to_vec(),
            b"\xc3\xa9\xc3\xa9\xc3\xa9\xc3".to_vec(),
            b"Bearer\xe9".to_vec(),
        ] {
            let headers = headers(&[("authorization", &value)]);
            assert_eq!(read_bearer_token(&headers), None, "{value:?}");
        }
    }

    /// What makes a joined pair read as the repeat it is on a runtime that
    /// shows no per-line view: neither shape can hold a comma or a space.
    #[test]
    fn no_token_grammar_admits_the_join_of_repeated_lines() {
        let token = generate_api_token().token;
        let daemon = "d".repeat(43);
        let joined = headers(&[(
            "authorization",
            format!("Bearer {token}, Bearer {token}").as_bytes(),
        )]);
        assert_eq!(read_bearer_token(&joined), None);
        let joined = headers(&[("x-daemon-token", format!("{daemon}, {daemon}").as_bytes())]);
        assert_eq!(read_daemon_token(&joined), None);
        for separator in [", ", ",", " "] {
            for at in 0..token.len() {
                let mut spliced = token.clone();
                spliced.replace_range(at..(at + separator.len()).min(token.len()), separator);
                assert!(!is_api_token_shaped(&spliced), "{spliced}");
            }
        }
    }
}
