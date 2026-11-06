//! Flat-REST error response builders.
//!
//! The `{ "error": <reason> }` (+ optional fields) bodies that hand-mounted
//! axum routes return on denial — the REST sibling of [`crate::jsonrpc_error`]
//! (which builds JSON-RPC envelopes). Single source of truth for the flat
//! `ApiError` / `PermissionError` shapes matching `fuz_app`'s
//! `http/error_schemas.ts`, so every consumer's hand-mounted routes reject
//! with one wire body across both spines. Paired with
//! [`crate::origin::forbidden_origin_response`], another flat-REST builder.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Canonical reason for an unauthenticated request. Mirrors `fuz_app`'s
/// `ERROR_AUTHENTICATION_REQUIRED`.
pub const AUTHENTICATION_REQUIRED_REASON: &str = "authentication_required";

/// Canonical reason for an authenticated-but-unauthorized request. Mirrors
/// `fuz_app`'s `ERROR_INSUFFICIENT_PERMISSIONS`.
pub const INSUFFICIENT_PERMISSIONS_REASON: &str = "insufficient_permissions";

/// Canonical reason for an over-cap request body. Mirrors `fuz_app`'s
/// `ERROR_PAYLOAD_TOO_LARGE`.
pub const PAYLOAD_TOO_LARGE_REASON: &str = "payload_too_large";

/// Canonical reason for a malformed query string. Mirrors `fuz_app`'s
/// `ERROR_INVALID_QUERY_PARAMS`.
pub const INVALID_QUERY_PARAMS_REASON: &str = "invalid_query_params";

/// Canonical reason for a malformed path parameter. Mirrors `fuz_app`'s
/// `ERROR_INVALID_ROUTE_PARAMS`.
pub const INVALID_ROUTE_PARAMS_REASON: &str = "invalid_route_params";

/// Canonical reason for a request body that isn't a JSON object — unparseable,
/// empty, or parsing to `null`, an array, or a scalar. Mirrors `fuz_app`'s
/// `ERROR_INVALID_JSON_BODY`.
pub const INVALID_JSON_BODY_REASON: &str = "invalid_json_body";

/// Canonical reason for a JSON-object request body that fails the route's
/// input schema. Mirrors `fuz_app`'s `ERROR_INVALID_REQUEST_BODY`.
pub const INVALID_REQUEST_BODY_REASON: &str = "invalid_request_body";

/// Canonical reason for an unexpected server-side failure. Mirrors the
/// `{error: 'internal_error'}` body `fuz_app`'s route-spec error mapper
/// (`http/route_spec.ts`) returns for a generic caught `Error`.
pub const INTERNAL_ERROR_REASON: &str = "internal_error";

#[derive(Serialize)]
struct PermissionErrorBody<'a> {
    error: &'a str,
    required_roles: &'a [&'a str],
}

/// Build the canonical `401` unauthenticated response.
///
/// Flat `{"error": "authentication_required"}` REST body matching `fuz_app`'s
/// `ApiError` shape — the REST sibling of [`crate::unauthenticated`] (the
/// JSON-RPC envelope form). For hand-mounted routes that resolve auth
/// themselves rather than going through the RPC dispatcher.
#[must_use]
pub fn authentication_required_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": AUTHENTICATION_REQUIRED_REASON })),
    )
        .into_response()
}

/// Build the canonical `403` insufficient-permissions response.
///
/// Flat `{"error": "insufficient_permissions", "required_roles": [...]}` REST
/// body matching `fuz_app`'s `PermissionError` shape — the REST sibling of
/// [`crate::forbidden`]. `required_roles` names the role(s) the route demands.
#[must_use]
pub fn insufficient_permissions_response(required_roles: &[&str]) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(PermissionErrorBody {
            error: INSUFFICIENT_PERMISSIONS_REASON,
            required_roles,
        }),
    )
        .into_response()
}

/// Build the canonical `400` invalid-query-params response.
///
/// Flat `{"error": "invalid_query_params"}` REST body matching `fuz_app`'s
/// query-validation middleware (`create_query_validation` in
/// `http/route_spec.ts` — the TS twin additionally attaches DEV-only
/// `issues`, which cross-impl assertions must not pin). The rejection the
/// [`crate::query`] helpers return for an unknown or malformed query key.
#[must_use]
pub fn invalid_query_params_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": INVALID_QUERY_PARAMS_REASON })),
    )
        .into_response()
}

/// Build the canonical `400` invalid-JSON-body response.
///
/// Flat `{"error": "invalid_json_body"}` REST body matching `fuz_app`'s
/// input-validation middleware (`create_input_validation` in
/// `http/route_spec.ts`) for a body that isn't a JSON object. Built by
/// [`crate::parse_json_body`].
#[must_use]
pub fn invalid_json_body_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": INVALID_JSON_BODY_REASON })),
    )
        .into_response()
}

/// Build the canonical `400` invalid-request-body response.
///
/// Flat `{"error": "invalid_request_body"}` REST body matching `fuz_app`'s
/// input-validation middleware for a JSON object that fails the input schema
/// (the TS twin additionally attaches DEV-only `issues`, which cross-impl
/// assertions must not pin).
#[must_use]
pub fn invalid_request_body_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": INVALID_REQUEST_BODY_REASON })),
    )
        .into_response()
}

/// Build the canonical `400` invalid-route-params response.
///
/// Flat `{"error": "invalid_route_params"}` REST body matching `fuz_app`'s
/// params-validation middleware (`create_params_validation` in
/// `http/route_spec.ts` — the TS twin additionally attaches DEV-only
/// `issues`, which cross-impl assertions must not pin). The rejection a
/// hand-mounted route returns when a path segment fails the grammar its TS
/// twin declares in `spec.params`, before any auth or DB work.
///
/// The sibling of [`invalid_query_params_response`]: a route validates its
/// path params, then its query, then resolves auth — so these two are the
/// only refusals that precede the 401.
#[must_use]
pub fn invalid_route_params_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": INVALID_ROUTE_PARAMS_REASON })),
    )
        .into_response()
}

/// Build the canonical `500` internal-error response.
///
/// Flat `{"error": "internal_error"}` REST body — the fail-closed fallback a
/// hand-mounted route returns when an unexpected internal failure (pool
/// checkout, query, serialization) aborts it. Deliberately carries no
/// `message`: the detail belongs in the server-side `tracing::error!`
/// breadcrumb, never on the wire. (The TS twin attaches a DEV-only `message`
/// on this shape, the same redaction gate as `invalid_query_params`'s
/// `issues`; cross-impl assertions must not pin it.)
#[must_use]
pub fn internal_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": INTERNAL_ERROR_REASON })),
    )
        .into_response()
}

/// The REST reason a failed pool checkout answers with.
pub const SERVICE_UNAVAILABLE_REASON: &str = "service_unavailable";

/// Build the canonical `503` response to a failed pool checkout.
///
/// Flat `{"error": "service_unavailable"}` — what every hand-mounted route,
/// the credential walk, the SSE open, and fact serving answer when
/// `pool.get()` fails (wait or connect timed out, server unreachable, pool
/// closed). A failed query on a client already checked out keeps
/// [`internal_error_response`]. The TS twin answers the same body from its
/// `app.onError` and its route catch, by the JSON-RPC
/// `service_unavailable` code. No `Retry-After`: an exhausted pool has no
/// known reset time.
#[must_use]
pub fn db_unavailable_response() -> Response {
    rest_error_response(StatusCode::SERVICE_UNAVAILABLE, SERVICE_UNAVAILABLE_REASON)
}

/// Log an internal failure's cause chain at `error` and answer
/// [`internal_error_response`].
///
/// The REST twin of [`crate::internal_error_with_source`], with the same
/// fields and level: `error` is [`fuz_sys::cli::format_error_chain`], since a
/// `tokio_postgres::Error`'s own text is only its kind, and `sqlstate` is the
/// chain's SQLSTATE when it has one ([`fuz_db::sqlstate_in_chain`]).
/// `context` names the failed step, as a log field, never on the wire; the
/// event's target is this module, so `context` carries the location. Shaped
/// for `map_err`:
///
/// ```ignore
/// let rows = client.query(sql, &[]).await
///     .map_err(|e| internal_error_response_with_source("db.tables list", &e))?;
/// ```
#[cold]
#[must_use]
pub fn internal_error_response_with_source(
    context: &str,
    error: &(dyn std::error::Error + 'static),
) -> Response {
    tracing::error!(
        error = %fuz_sys::cli::format_error_chain(error),
        sqlstate = fuz_db::sqlstate_in_chain(error),
        context,
        "REST handler internal error"
    );
    internal_error_response()
}

/// Log a failed pool checkout's cause chain at `error` and answer
/// [`db_unavailable_response`] — the REST twin of
/// [`crate::db_unavailable_with_source`].
#[cold]
#[must_use]
pub fn db_unavailable_response_with_source(
    context: &str,
    error: &(dyn std::error::Error + 'static),
) -> Response {
    tracing::error!(
        error = %fuz_sys::cli::format_error_chain(error),
        sqlstate = fuz_db::sqlstate_in_chain(error),
        context,
        "REST handler pool checkout failed"
    );
    db_unavailable_response()
}

/// Build a flat `{"error": <reason>}` REST response at `status` — for a
/// route's own reasons (`table_not_found`, `storage_full`, …); the canonical
/// ones have their own builders here.
#[must_use]
pub fn rest_error_response(status: StatusCode, reason: &str) -> Response {
    (status, Json(serde_json::json!({ "error": reason }))).into_response()
}

/// Build the canonical `413` payload-too-large response.
///
/// Flat `{"error": "payload_too_large"}` REST body matching `fuz_app`'s
/// `bodyLimit` `onError` (`c.json({error: ERROR_PAYLOAD_TOO_LARGE}, 413)`).
/// The over-cap rejection of the body-size layer (see `crate::body_limit`)
/// rewrites tower-http's plain-text rejection into this JSON shape so every
/// consumer's over-cap response matches the TS twin.
#[must_use]
pub fn payload_too_large_response() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(serde_json::json!({ "error": PAYLOAD_TOO_LARGE_REASON })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        StatusCode, insufficient_permissions_response, internal_error_response,
        invalid_query_params_response, invalid_route_params_response,
    };

    /// The role-denial body is pinned **byte-for-byte**, not structurally.
    ///
    /// `fuz_app`'s `require_role` emits `c.json({error, required_roles}, 403)`,
    /// so the wire bytes are `{"error":…,"required_roles":[…]}` in that field
    /// order. A `serde_json::Value` comparison would pass on a reordered or
    /// extra-whitespace body, which is exactly the drift a cross-backend
    /// `deepStrictEqual` on a parsed body also can't see — assert the string.
    #[tokio::test]
    async fn role_denial_body_is_byte_identical_to_the_ts_twin() {
        let response = insufficient_permissions_response(&["admin"]);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        assert_eq!(
            std::str::from_utf8(&body).expect("body is utf-8"),
            r#"{"error":"insufficient_permissions","required_roles":["admin"]}"#,
        );
    }

    /// Multi-role (any-of) gates echo the whole set, in the order the gate
    /// declared it — `required_roles` is what tells a client which of several
    /// roles would have admitted it.
    #[tokio::test]
    async fn role_denial_echoes_every_declared_role_in_order() {
        let response = insufficient_permissions_response(&["admin", "steward"]);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        assert_eq!(
            std::str::from_utf8(&body).expect("body is utf-8"),
            r#"{"error":"insufficient_permissions","required_roles":["admin","steward"]}"#,
        );
    }

    /// The 500 body is pinned byte-for-byte against a consumer's REST gate
    /// outside this workspace (whose 500 this fn builds) and `fuz_app`'s
    /// production route-spec generic-error mapping. It carries **only** `error`
    /// — never the DEV-only `message` the TS mapper can add — so a leaked
    /// exception string can't ride out on this path in any build.
    #[tokio::test]
    async fn internal_error_body_is_the_bare_flat_envelope() {
        let response = internal_error_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        assert_eq!(
            std::str::from_utf8(&body).expect("body is utf-8"),
            r#"{"error":"internal_error"}"#,
        );
    }

    /// The two pre-auth 400s are the same flat envelope with different
    /// reasons, pinned byte-for-byte side by side so neither grows a field the
    /// other lacks. Both omit the TS twin's DEV-only `issues`: the detail is a
    /// Zod artifact, and a cross-impl assertion that pinned it would be
    /// pinning a build mode.
    #[tokio::test]
    async fn the_pre_auth_400_bodies_are_the_bare_flat_envelopes() {
        for (response, expected) in [
            (
                invalid_route_params_response(),
                r#"{"error":"invalid_route_params"}"#,
            ),
            (
                invalid_query_params_response(),
                r#"{"error":"invalid_query_params"}"#,
            ),
        ] {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some("application/json"),
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body collects");
            assert_eq!(std::str::from_utf8(&body).expect("body is utf-8"), expected);
        }
    }
}
