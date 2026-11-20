//! The strict readers of the request target: the query string to its pairs,
//! and one path segment to its text — each percent-decoded, or refused.
//!
//! An escape that doesn't decode is refused, never left literal and never
//! replaced with U+FFFD: a `%` not followed by two hex digits is
//! [`PercentDecodeError::MalformedEscape`], and decoded bytes that are not
//! UTF-8 are [`PercentDecodeError::InvalidUtf8`]. A literal spelling would make
//! `%FF` and `%25FF` one value, and a lossy one (`form_urlencoded`'s, behind
//! axum's `Query`) every invalid sequence the same U+FFFD — either way a
//! handler reads a value the client never sent. `fuz_app`'s
//! `http/request_target.ts` reads by the same rule, and the shared table
//! `request_target_conformance.json` (owned by `fuz_app`, with a
//! byte-identical copy beside this module) holds both spines to the same rows.
//!
//! A handler reads its query through [`read_query_pairs`] over axum's
//! `RawQuery`, at the phase its TS twin reads the query, and its path params
//! through [`RouteParams`], whose every rejection is the flat
//! `invalid_route_params` body — never axum's plain-text one.

use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use axum::response::Response;
use serde::de::DeserializeOwned;

use crate::rest_error::invalid_route_params_response;

/// Why a query string or a path segment doesn't decode. Twin of the TS
/// `PercentDecodeError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PercentDecodeError {
    /// A `%` not followed by two hex digits.
    #[error("a `%` not followed by two hex digits")]
    MalformedEscape,
    /// Percent-decoded bytes that are not UTF-8.
    #[error("percent-decoded bytes that are not UTF-8")]
    InvalidUtf8,
}

impl PercentDecodeError {
    /// The wire name, as the shared table and the TS twin spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedEscape => "malformed_escape",
            Self::InvalidUtf8 => "invalid_utf8",
        }
    }
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `text` strictly. A malformed escape anywhere is reported
/// ahead of invalid bytes: it is found in the scan, and the bytes are judged
/// after it — the TS twin's order.
fn percent_decode_strict(text: &[u8]) -> Result<String, PercentDecodeError> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut i = 0;
    while let Some(&byte) = text.get(i) {
        if byte == b'%' {
            let high = text.get(i + 1).copied().and_then(hex_value);
            let low = text.get(i + 2).copied().and_then(hex_value);
            let (Some(high), Some(low)) = (high, low) else {
                return Err(PercentDecodeError::MalformedEscape);
            };
            bytes.push(high << 4 | low);
            i += 3;
        } else {
            bytes.push(byte);
            i += 1;
        }
    }
    String::from_utf8(bytes).map_err(|_| PercentDecodeError::InvalidUtf8)
}

/// Read one raw path segment to its text: percent-decoded strictly, `+` left
/// a plus (a path is no form encoding).
///
/// # Errors
///
/// [`PercentDecodeError`] when an escape in it doesn't decode.
pub fn read_path_segment(segment: &str) -> Result<String, PercentDecodeError> {
    percent_decode_strict(segment.as_bytes())
}

/// One component of a query pair: `+` read as a space, then decoded strictly.
fn read_query_component(raw: &str) -> Result<String, PercentDecodeError> {
    let spaced: Vec<u8> = raw
        .bytes()
        .map(|b| if b == b'+' { b' ' } else { b })
        .collect();
    percent_decode_strict(&spaced)
}

/// Read a raw query string to its pairs, in order, every escape decoded
/// strictly.
///
/// The string is split on `&` (an empty piece is no pair), each piece at its
/// first `=` (none reads an empty value), `+` read as a space, then name and
/// value percent-decoded.
///
/// Every pair is read, a repeated key's and a nameless one's included, and the
/// first component that doesn't decode refuses the whole string — a key no
/// handler reads included, so no reader of one key sees a query another
/// reader would refuse. What a pair means is the caller's: [`query_first`]
/// takes a key's first occurrence, [`assert_known_query_keys`] the twin of a
/// strict query schema.
///
/// [`query_first`]: crate::query_first
/// [`assert_known_query_keys`]: crate::assert_known_query_keys
///
/// # Errors
///
/// [`PercentDecodeError`] when any name or value doesn't decode.
pub fn read_query_pairs(query: Option<&str>) -> Result<Vec<(String, String)>, PercentDecodeError> {
    let mut pairs = Vec::new();
    for piece in query.unwrap_or("").split('&') {
        if piece.is_empty() {
            continue;
        }
        let (name, value) = piece.split_once('=').unwrap_or((piece, ""));
        let name = read_query_component(name)?;
        let value = read_query_component(value)?;
        pairs.push((name, value));
    }
    Ok(pairs)
}

/// The path params of the matched route, every escape in the request path
/// decoded strictly.
///
/// Every rejection — an escape that doesn't decode, a param that doesn't
/// deserialize, a missing one — answers the flat
/// `400 {"error":"invalid_route_params"}` its TS twin's params stage answers.
///
/// It wraps axum's [`Path`], whose own rejection is a plain-text body and
/// whose decoding leaves a malformed escape (`%G0`, a bare `%`) in the value
/// as text. The whole path is checked rather than each param's segments: the
/// router matches the raw path, so a literal segment holding an escape matches
/// no route, and on a matched route every escape is inside a param.
///
/// Params are the first phase on both spines, ahead of the query and auth, so
/// a handler takes this as its first extractor that can refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteParams<T>(pub T);

impl<T, S> FromRequestParts<S> for RouteParams<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if parts
            .uri
            .path()
            .split('/')
            .any(|segment| read_path_segment(segment).is_err())
        {
            return Err(invalid_route_params_response());
        }
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(params)| Self(params))
            .map_err(|_| invalid_route_params_response())
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    /// The shared table, byte-identical to `fuz_app`'s
    /// `testing/cross_backend/request_target_conformance.json`.
    const TABLE: &str = include_str!("request_target_conformance.json");

    fn table() -> Value {
        serde_json::from_str(TABLE).expect("the table parses")
    }

    fn refused(error: PercentDecodeError) -> Value {
        serde_json::json!({ "refused": error.as_str() })
    }

    #[test]
    fn every_query_row_reads_as_the_table_says() {
        let table = table();
        let rows = table["query"].as_array().expect("a query section");
        assert!(!rows.is_empty());
        let mut failures = Vec::new();
        for row in rows {
            let got = match read_query_pairs(row["query"].as_str()) {
                Ok(pairs) => serde_json::json!({ "pairs": pairs }),
                Err(error) => refused(error),
            };
            if got != row["read"] {
                failures.push(format!(
                    "{}: expected {}, got {got}",
                    row["name"], row["read"]
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "query rows disagree:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn every_param_row_reads_as_the_table_says() {
        let table = table();
        let rows = table["param"].as_array().expect("a param section");
        assert!(!rows.is_empty());
        let mut failures = Vec::new();
        for row in rows {
            let segment = row["segment"].as_str().expect("a segment");
            let got = match read_path_segment(segment) {
                Ok(value) => serde_json::json!({ "value": value }),
                Err(error) => refused(error),
            };
            if got != row["read"] {
                failures.push(format!(
                    "{}: expected {}, got {got}",
                    row["name"], row["read"]
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "param rows disagree:\n{}",
            failures.join("\n")
        );
    }

    async fn answer(router: Router, uri: &str) -> (StatusCode, String) {
        let response = router
            .oneshot(Request::get(uri).body(Body::empty()).expect("a request"))
            .await
            .expect("an answer");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("a body")
            .to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn router() -> Router {
        Router::new()
            .route(
                "/rows/{id}",
                get(|RouteParams(id): RouteParams<String>| async move { id }),
            )
            .route(
                "/count/{n}",
                get(|RouteParams(n): RouteParams<u32>| async move { n.to_string() }),
            )
    }

    /// Every rejection is the flat JSON body, never axum's plain text.
    #[tokio::test]
    async fn route_params_refuse_with_the_flat_body() {
        for uri in [
            "/rows/%FF",
            "/rows/%C3%A9%FF",
            "/rows/%G0",
            "/rows/%",
            "/count/x",
        ] {
            let (status, body) = answer(router(), uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
            assert_eq!(body, r#"{"error":"invalid_route_params"}"#, "{uri}");
        }
    }

    #[tokio::test]
    async fn route_params_decode_once() {
        for (uri, value) in [
            ("/rows/%25FF", "%FF"),
            ("/rows/%C3%A9", "é"),
            ("/rows/a%2Fb", "a/b"),
            ("/rows/a+b", "a+b"),
            ("/count/7", "7"),
        ] {
            let (status, body) = answer(router(), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert_eq!(body, value, "{uri}");
        }
    }

    /// A param the template doesn't name is a deserialize failure, answered
    /// like any other.
    #[tokio::test]
    async fn route_params_missing_param_is_the_flat_body() {
        let router = Router::new().route(
            "/plain",
            get(|RouteParams(id): RouteParams<String>| async move { id }),
        );
        let (status, body) = answer(router, "/plain").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"invalid_route_params"}"#);
    }
}
