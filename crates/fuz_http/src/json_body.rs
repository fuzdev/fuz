//! JSON request bodies, decoded with the TS twin's two refusals.
//!
//! `fuz_app`'s route pipeline (`create_input_validation` in
//! `http/route_spec.ts`) reads a body with `read_json_body` — the body
//! decoded as UTF-8 text (`c.req.text()`), then `parse_json_text` — and answers `400
//! invalid_json_body` when that throws or yields anything but an object
//! (`null`, an array, a scalar). Only an object that fails the input schema is
//! `400 invalid_request_body`. A handler deserializing straight to its input
//! type can't tell the two apart, so the spine's JSON handlers take the raw
//! body and go through [`parse_json_body`].
//!
//! The text decode, [`decode_json_text`], follows the Fetch body's: one
//! leading UTF-8 BOM is dropped and invalid UTF-8 becomes U+FFFD rather than
//! failing. The JSON-RPC `POST` body goes through the same decode, so REST and
//! RPC read the same bytes the same way. Parsing to a `serde_json::Value`
//! first also matches `JSON.parse` on a duplicated key — the last one wins —
//! where a derived `Deserialize` refuses it.
//!
//! `serde_json` refuses three things `JSON.parse` accepts — an escaped lone
//! surrogate (`"\ud800"`), a number out of `f64` range (`1e400`), and nesting
//! 128 deep — and the twin refuses them too (`parse_json_text` in
//! `http/json_text.ts`), so they answer `invalid_json_body` on both spines
//! (`parse_error` on a JSON-RPC body or WS frame). The out-of-range verdict
//! matches `JSON.parse`'s `Infinity` exactly because this crate builds
//! `serde_json` with `float_roundtrip`, which feature unification turns on for
//! every server linking it; without it, `serde_json` refuses a few numbers
//! just under `f64::MAX` that round to it. One divergence remains, the twin's
//! runtime, not the spec: Node's undici strips a second leading BOM, where
//! Deno, Bun, and this decode drop only the one the spec does.
//!
//! `serde_json` accepts `"\u0000"`, as `JSON.parse` does, but Postgres refuses
//! U+0000 in `text` and `jsonb`. So a parsed object holding one in any string
//! or key is `invalid_request_body` (not a parse failure: the JSON is valid),
//! found by the same walk the RPC dispatcher refuses it with
//! ([`crate::scan_json_value`]); the twin's `create_input_validation` does the
//! same ahead of its schema.

use std::borrow::Cow;

use axum::response::Response;
use serde::de::DeserializeOwned;

use crate::rest_error::{invalid_json_body_response, invalid_request_body_response};

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// The ceiling the twin's safe-integer schemas enforce: `Number.MAX_SAFE_INTEGER`.
///
/// The largest integer a JSON number survives a JS round-trip at. An integer input
/// the twin declares `int()` is refused past it on both spines, rather than
/// accepted on Rust as a value the twin cannot represent.
pub const SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;

/// Decode a JSON request body's bytes to text as the Fetch body's `text()`
/// does: one leading UTF-8 BOM dropped, invalid UTF-8 replaced by U+FFFD.
///
/// Borrows when the bytes are valid UTF-8.
#[must_use]
pub fn decode_json_text(body: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(body.strip_prefix(UTF8_BOM).unwrap_or(body))
}

/// Decode a JSON request body into `T`, refusing as the TS twin does.
///
/// Call after the content-type check, as the twin's pipeline does (`415`
/// before `400`).
///
/// # Errors
///
/// Returns the flat 400 denial `Response` (`Err`): `invalid_json_body` when
/// the body doesn't parse as JSON (an empty body included) or isn't an
/// object; `invalid_request_body` when the object holds U+0000 in a string or
/// key ([`crate::scan_json_value`]) or doesn't deserialize to `T`.
#[expect(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine REST handler idiom"
)]
pub fn parse_json_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, Response> {
    let value: serde_json::Value =
        serde_json::from_str(&decode_json_text(body)).map_err(|_| invalid_json_body_response())?;
    if !value.is_object() {
        return Err(invalid_json_body_response());
    }
    // U+0000 in any string or key, which Postgres refuses to store, ahead of
    // the deserialize — the twin's `create_input_validation` walks before its schema
    if crate::scan_json_value(&value).nul {
        return Err(invalid_request_body_response());
    }
    serde_json::from_value(value).map_err(|_| invalid_request_body_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Input {
        name: String,
    }

    async fn refusal(body: &[u8]) -> String {
        let response = parse_json_body::<Input>(body).expect_err("refused");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        String::from_utf8(bytes.to_vec()).expect("body is utf-8")
    }

    const INVALID_JSON: &str = r#"{"error":"invalid_json_body"}"#;
    const INVALID_REQUEST: &str = r#"{"error":"invalid_request_body"}"#;

    #[tokio::test]
    async fn unparseable_or_non_object_is_invalid_json_body() {
        for body in [
            &b""[..],
            b"{",
            b"   ",
            b"not json",
            b"{\"name\":\"a\"} trailing",
            b"null",
            b"[]",
            b"[{\"name\":\"a\"}]",
            b"5",
            b"\"name\"",
            b"true",
            b"\xEF\xBB\xBF\xEF\xBB\xBF{}",
        ] {
            assert_eq!(refusal(body).await, INVALID_JSON, "{}", body.escape_ascii());
        }
    }

    #[tokio::test]
    async fn object_failing_the_schema_is_invalid_request_body() {
        for body in [
            &b"{}"[..],
            b"{\"name\":5}",
            b"{\"name\":\"a\",\"extra\":1}",
            b"{\"name\":null}",
        ] {
            assert_eq!(
                refusal(body).await,
                INVALID_REQUEST,
                "{}",
                body.escape_ascii()
            );
        }
    }

    #[tokio::test]
    async fn a_nul_in_a_string_or_key_is_invalid_request_body() {
        for body in [
            &br#"{"name":"a\u0000"}"#[..],
            br#"{"name":"a","x":{"\u0000":1}}"#,
            // under the kept duplicate
            br#"{"name":"a","name":"\u0000"}"#,
        ] {
            assert_eq!(
                refusal(body).await,
                INVALID_REQUEST,
                "{}",
                body.escape_ascii()
            );
        }
        // an escaped backslash before `u0000` is no NUL, and a NUL under a
        // dropped duplicate is never read
        for body in [
            &br#"{"name":"\\u0000"}"#[..],
            br#"{"name":"\u0000","name":"a"}"#,
        ] {
            assert!(
                parse_json_body::<Input>(body).is_ok(),
                "{}",
                body.escape_ascii()
            );
        }
    }

    #[test]
    fn decodes_as_the_fetch_body_does() {
        let parse = |body: &[u8]| parse_json_body::<Input>(body).expect("parses");
        assert_eq!(parse(b" {\"name\":\"a\"}\n").name, "a");
        // one leading BOM is dropped
        assert_eq!(parse(b"\xEF\xBB\xBF{\"name\":\"a\"}").name, "a");
        // invalid UTF-8 decodes to U+FFFD
        assert_eq!(parse(b"{\"name\":\"a\xFF\"}").name, "a\u{FFFD}");
        // a duplicated key keeps its last value
        assert_eq!(parse(br#"{"name":"a","name":"b"}"#).name, "b");
    }

    /// The three refusals the twin's `parse_json_text` holds to, and the
    /// `float_roundtrip` boundary its `Infinity` matches: a number just past
    /// `f64::MAX` that rounds to it is a number, one that rounds past is not.
    #[test]
    fn refuses_what_the_twin_refuses_as_invalid_json() {
        let refused = |body: &str| {
            parse_json_body::<serde_json::Value>(body.as_bytes())
                .err()
                .map(|r| r.status())
        };
        for body in [
            r#"{"x":"\ud800"}"#,
            r#"{"x":"\udc00"}"#,
            r#"{"\ud800":1}"#,
            r#"{"x":"\ud800","x":1}"#,
            r#"{"x":1e400}"#,
            r#"{"x":-1e400}"#,
            r#"{"x":1.7976931348623159e308}"#,
        ] {
            assert_eq!(refused(body), Some(StatusCode::BAD_REQUEST), "{body}");
        }
        let deep = format!("{{\"x\":{}{}}}", "[".repeat(127), "]".repeat(127));
        assert_eq!(refused(&deep), Some(StatusCode::BAD_REQUEST));
        let shallow = format!("{{\"x\":{}{}}}", "[".repeat(126), "]".repeat(126));
        assert_eq!(refused(&shallow), None);
        for body in [
            r#"{"x":"\ud83d\ude00"}"#,
            r#"{"x":1e-400}"#,
            r#"{"x":1.797693134862315807e308}"#,
        ] {
            assert_eq!(refused(body), None, "{body}");
        }
    }
}
