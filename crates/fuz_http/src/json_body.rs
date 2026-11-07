//! JSON request bodies, decoded with the TS twin's two refusals.
//!
//! `fuz_app`'s route pipeline (`create_input_validation` in
//! `http/route_spec.ts`) reads a body with Hono's `c.req.json()` — the body
//! decoded as UTF-8 text, then `JSON.parse` — and answers `400
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
//! `serde_json` refuses three things `JSON.parse` accepts, so these answer
//! `invalid_json_body` here and `invalid_request_body` (or success) on the
//! twin: an escaped lone surrogate (`"\ud800"`), a number out of `f64` range
//! (`1e400`), and nesting deeper than 128 (on the JSON-RPC `POST` body they
//! answer `parse_error` where the twin dispatches). A fourth divergence is the
//! twin's runtime, not the spec: Node's undici strips a second leading BOM,
//! where Deno, Bun, and this decode drop only the one the spec does.

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
/// object; `invalid_request_body` when the object doesn't deserialize to `T`.
#[allow(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine REST handler idiom"
)]
pub fn parse_json_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, Response> {
    let value: serde_json::Value =
        serde_json::from_str(&decode_json_text(body)).map_err(|_| invalid_json_body_response())?;
    if !value.is_object() {
        return Err(invalid_json_body_response());
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
}
