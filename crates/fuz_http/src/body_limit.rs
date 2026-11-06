//! Request body size limit — tower-http layer wrapped to a JSON rejection.
//!
//! Composes `tower_http::limit::RequestBodyLimitLayer` (the actual size
//! enforcement) with an outer response-rewrite map so the over-cap
//! rejection is the canonical `{"error": "payload_too_large"}` JSON body
//! instead of tower-http's plain-text `length limit exceeded`.
//!
//! [`crate::compose_stack`] mounts it in each route group whose cap is
//! [`BodyCap::Bytes`](crate::BodyCap::Bytes), outside the origin check (see
//! the crate doc's mount order), beside a matching axum `DefaultBodyLimit`.
//!
//! ## When the 413 is answered
//!
//! 413-first holds for a declared `Content-Length`; a length-less (chunked)
//! body over the cap is refused too, but which refusal wins when a header
//! check also applies is implementation-defined.
//!
//! - **A declared `Content-Length` over the cap** short-circuits: the layer
//!   answers `413 Payload Too Large` on the header, before any layer or
//!   handler beneath it runs and before a byte of the body is read. hyper
//!   closes the connection.
//! - **A body with no declared length** (`Transfer-Encoding: chunked`) is
//!   counted as it is read, so the outcome belongs to whatever reads it. A
//!   layer beneath that refuses on the headers (the origin check) answers its
//!   own status; a handler that buffers the body (`Bytes`, `Json`) answers
//!   `413` once more than the cap has arrived; a handler that never reads the
//!   body answers its own status, and hyper closes the connection rather than
//!   read the rest. Nothing past the cap reaches a handler either way.
//!
//! The TS spine's limit differs on the second: it reads a length-less body up
//! to the cap before the next middleware runs, so its `413` comes ahead of the
//! origin check, auth, and the handler. Which status an over-cap chunked body
//! gets when a refusal on the headers also applies is implementation-defined
//! across the two spines.
//!
//! hyper refuses a request whose `Content-Length` is malformed or repeated
//! with differing values, and folds a repeat with equal values into one, all
//! before this layer; a request carrying both `Content-Length` and
//! `Transfer-Encoding` reaches it with the `Content-Length` removed and is
//! framed as chunked, and hyper closes the connection after its response.
//! That last is hyper 1.11.1 or later: an older hyper leaves a
//! `Content-Length` that came ahead of `Transfer-Encoding` on the request and
//! keeps the connection. The workspace manifest requires at least that
//! version, so no build of this crate resolves an older one.

use axum::body::Body;
use axum::http::{Response as HttpResponse, StatusCode};
use axum::response::{IntoResponse as _, Response};
use tower::Layer;
use tower::util::{MapResponse, MapResponseLayer};
use tower_http::limit::{RequestBodyLimitLayer, ResponseBody};

use crate::rest_error::payload_too_large_response;

/// Default body limit: 1 MiB.
///
/// Sized for the JSON-RPC dispatch surface where typical request
/// bodies are <1 KiB; the limit catches pathological payloads (e.g.
/// attacker pumping multi-MB JSON to exhaust pool memory) without
/// blocking legitimate API requests.
///
/// Consumers serving binary uploads (file store routes, artifact
/// distribution) put those routes in a [`RouteGroup`](crate::RouteGroup) of
/// their own with a larger [`BodyCap::Bytes`](crate::BodyCap::Bytes), or a
/// [`BodyCap::HandlerOwned`](crate::BodyCap::HandlerOwned) when the handler
/// streams the body against its own cap — the default is for the generic API
/// surface only.
pub const DEFAULT_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Body-size-limit layer that rejects over-cap requests with the canonical
/// JSON 413.
///
/// Composes `tower_http::limit::RequestBodyLimitLayer` (inner — the actual
/// byte cap) with a `tower::util::MapResponseLayer` rewrite (outer — maps the
/// limit layer's plain-text 413 to `{"error": "payload_too_large"}`). A
/// concrete, `Clone`-able `Layer` with a nameable type.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BodyLimitLayer {
    max_bytes: usize,
}

impl<S> Layer<S> for BodyLimitLayer {
    type Service = MapResponse<<RequestBodyLimitLayer as Layer<S>>::Service, RewriteFn>;

    fn layer(&self, service: S) -> Self::Service {
        // `outer.layer(inner.layer(svc))`: the response map (outermost) wraps
        // the limit, observing its 413 and rewriting it.
        let limited = RequestBodyLimitLayer::new(self.max_bytes).layer(service);
        let rewrite: RewriteFn = rewrite_payload_too_large;
        MapResponseLayer::new(rewrite).layer(limited)
    }
}

/// The response-rewrite fn pointer used by the `MapResponseLayer`. A named
/// type so [`BodyLimitLayer::Service`] stays concrete and `Clone`.
///
/// `RequestBodyLimitLayer`'s service wraps the body in `ResponseBody`, so
/// the map's input is `Response<ResponseBody<Body>>`; the output is axum's
/// plain `Response` (`Response<Body>`).
type RewriteFn = fn(HttpResponse<ResponseBody<Body>>) -> Response;

/// Build a tower layer that caps request body size at `max_bytes`.
///
/// Over-cap requests answer the canonical JSON 413
/// ([`crate::rest_error::payload_too_large_response`]) rather than
/// tower-http's plain-text body — at once for a declared `Content-Length`
/// over the cap, and once more than the cap has been read for a body with
/// no declared length (see the module doc). Under-cap requests pass through
/// unchanged.
///
/// A cap above 2 MiB needs a companion `axum::extract::DefaultBodyLimit`
/// on the same router when the handler reads the body through a buffering
/// extractor (`Bytes`, `Json`, `String`, `Multipart`): those apply axum's own
/// 2 MiB default regardless of this layer. [`crate::compose_stack`] mounts
/// one at the same size for every [`BodyCap::Bytes`](crate::BodyCap::Bytes)
/// group.
#[must_use]
pub(crate) const fn body_limit_layer(max_bytes: usize) -> BodyLimitLayer {
    BodyLimitLayer { max_bytes }
}

/// Rewrite a `413 Payload Too Large` from below into the canonical JSON
/// shape; pass every other response through untouched.
///
/// The only source of a 413 beneath this layer is the wrapped
/// `RequestBodyLimitLayer` (over-cap rejection), so status alone is a
/// reliable discriminator — no need to sniff tower-http's plain-text body.
/// Pass-through responses are re-wrapped from `ResponseBody<Body>` into
/// axum's `Body` via `IntoResponse` (a zero-copy body-type unification).
fn rewrite_payload_too_large(response: HttpResponse<ResponseBody<Body>>) -> Response {
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return payload_too_large_response();
    }
    response.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::Request;
    use axum::routing::post;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    /// Echo handler that drains the body — forces the limit layer to count
    /// bytes.
    async fn echo(body: axum::body::Bytes) -> Response {
        (StatusCode::OK, body).into_response()
    }

    fn app(max_bytes: usize) -> Router {
        Router::new()
            .route("/", post(echo))
            .layer(body_limit_layer(max_bytes))
    }

    #[tokio::test]
    async fn under_cap_passes_through() {
        let response = app(1024)
            .oneshot(
                Request::post("/")
                    .body(Body::from("small"))
                    .expect("request builds"),
            )
            .await
            .expect("service responds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        assert_eq!(&body[..], b"small");
    }

    #[tokio::test]
    async fn over_cap_rejects_with_json_413() {
        let oversized = vec![b'x'; 2048];
        let response = app(1024)
            .oneshot(
                Request::post("/")
                    .body(Body::from(oversized))
                    .expect("request builds"),
            )
            .await
            .expect("service responds");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("body is JSON");
        assert_eq!(parsed, serde_json::json!({ "error": "payload_too_large" }));
    }
}
