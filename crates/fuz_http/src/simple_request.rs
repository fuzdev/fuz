//! Refusing CORS simple requests — the cross-origin POSTs a browser sends
//! without asking first.
//!
//! A cross-origin `fetch` or form `POST` skips the CORS preflight when its
//! `Content-Type` is absent or one of the three CORS-safelisted types
//! (`text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`).
//! The browser sends such a request as-is, with whatever cookies apply — only
//! the response is withheld from the page. Any other content type makes the
//! browser send an `OPTIONS` preflight first, and since the spine answers no
//! preflight with CORS headers, the real request is never sent.
//!
//! The session cookie's `SameSite=Strict` doesn't close this on its own:
//! same-site ignores the port, so a page on `http://localhost:8000` is
//! same-site with a daemon on `http://localhost:4460` and its requests carry
//! the cookie. The [`crate::origin_layer`] allowlist refuses such a page unless
//! a wildcard (`http://localhost:*`) admits it; this gate refuses it whatever
//! the allowlist says.
//!
//! JSON endpoints therefore require `application/json`
//! ([`is_json_content_type`]), and endpoints that take other bodies require a
//! type that isn't safelisted ([`is_cors_simple_content_type`]). Only `POST`
//! needs the check: `PUT`, `PATCH`, and `DELETE` are never simple methods, so
//! the browser always preflights them.
//!
//! Both checks rest on the server answering no preflight. A consumer that adds
//! a CORS layer granting cross-origin requests reopens what this closes.
//!
//! Mirrors `fuz_app`'s `http/simple_request.ts`, which has the same two
//! predicates. There the route pipeline applies them to every `POST` route —
//! JSON unless the route is `raw_body`, then just not safelisted; here each
//! spine JSON handler checks [`is_json_content_type`], and consumers mount
//! [`simple_request_layer`] over routes with other bodies.

use axum::Json;
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Canonical error reason for a refused content type. Mirrors `fuz_app`'s
/// `ERROR_UNSUPPORTED_CONTENT_TYPE` (`http/error_schemas.ts`).
pub const UNSUPPORTED_CONTENT_TYPE_REASON: &str = "unsupported_content_type";

/// The content types a browser sends cross-origin without a preflight.
const CORS_SAFELISTED_CONTENT_TYPES: [&str; 3] = [
    "text/plain",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
];

/// Build the canonical content-type refusal: `415` + the flat
/// `{"error": "unsupported_content_type"}` REST body.
#[must_use]
pub fn unsupported_content_type_response() -> Response {
    (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Json(serde_json::json!({ "error": UNSUPPORTED_CONTENT_TYPE_REASON })),
    )
        .into_response()
}

/// The `Content-Type` header's MIME essence (`type/subtype`, lowercased,
/// parameters dropped), or `None` when it's absent or not visible ASCII.
fn content_type_essence(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    let essence = value.split(';').next().unwrap_or_default().trim();
    Some(essence.to_ascii_lowercase())
}

/// True when a browser could have sent a `POST` with these headers
/// cross-origin without a preflight: no `Content-Type`, or a CORS-safelisted
/// one.
///
/// Matches more than browsers do (a value they'd refuse to call safelisted —
/// one with odd bytes, say — counts as safelisted here), so it only ever
/// refuses too much, never too little.
#[must_use]
pub fn is_cors_simple_content_type(headers: &HeaderMap) -> bool {
    // absent, or not visible ASCII — a browser never safelists the latter, but
    // refusing it costs nothing
    let Some(essence) = content_type_essence(headers) else {
        return true;
    };
    CORS_SAFELISTED_CONTENT_TYPES.contains(&essence.as_str())
}

/// True when `Content-Type` is `application/json` (any parameters, such as
/// `charset`, allowed).
#[must_use]
pub fn is_json_content_type(headers: &HeaderMap) -> bool {
    content_type_essence(headers).is_some_and(|essence| essence == "application/json")
}

/// axum middleware refusing `POST`s a browser could send cross-origin without
/// a preflight ([`is_cors_simple_content_type`]) with `415`.
///
/// For routers whose `POST` bodies are never forms or plain text. Don't mount
/// it over a route that takes a `multipart/form-data` upload; give that route
/// its own CSRF defense.
pub async fn simple_request_layer(req: Request, next: Next) -> Response {
    if req.method() == Method::POST && is_cors_simple_content_type(req.headers()) {
        return unsupported_content_type_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn with_content_type(value: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_bytes(value).expect("header value"),
        );
        headers
    }

    #[test]
    fn absent_content_type_is_simple() {
        assert!(is_cors_simple_content_type(&HeaderMap::new()));
        assert!(!is_json_content_type(&HeaderMap::new()));
    }

    #[test]
    fn safelisted_types_are_simple_in_any_spelling() {
        for value in [
            "text/plain",
            "text/plain;charset=UTF-8",
            "TEXT/PLAIN",
            " text/plain ; charset=utf-8",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
        ] {
            assert!(
                is_cors_simple_content_type(&with_content_type(value.as_bytes())),
                "{value}"
            );
        }
    }

    #[test]
    fn other_types_are_not_simple() {
        for value in [
            "application/json",
            "application/json; charset=utf-8",
            "application/octet-stream",
            "audio/webm;codecs=opus",
            "text/html",
        ] {
            assert!(
                !is_cors_simple_content_type(&with_content_type(value.as_bytes())),
                "{value}"
            );
        }
    }

    #[test]
    fn non_ascii_content_type_counts_as_simple() {
        assert!(is_cors_simple_content_type(&with_content_type(
            b"text/plain\xff"
        )));
    }

    #[test]
    fn json_content_type_accepts_parameters_and_case() {
        assert!(is_json_content_type(&with_content_type(
            b"application/json"
        )));
        assert!(is_json_content_type(&with_content_type(
            b"Application/JSON; charset=utf-8"
        )));
        assert!(!is_json_content_type(&with_content_type(b"text/plain")));
        assert!(!is_json_content_type(&with_content_type(
            b"application/json-seq"
        )));
    }
}
