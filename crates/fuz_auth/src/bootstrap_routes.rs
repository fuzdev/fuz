//! `POST /bootstrap` axum handler.
//!
//! Thin wrapper around [`crate::bootstrap::bootstrap_handler`]: maps the
//! typed `BootstrapErrorKind` discriminants to HTTP status codes and sets
//! the session cookie the handler signed inside its transaction.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use fuz_http::{db_unavailable_response_with_source, internal_error_response_with_source};

use crate::auth_gate::AuthGate;
use crate::bootstrap::{BootstrapInput, BootstrapOptions, bootstrap_handler};
use crate::error::{BootstrapError, BootstrapErrorKind};
use crate::route_response::rate_limit_exceeded;
use fuz_http::ClientIp;

/// State for the bootstrap router.
#[derive(Clone)]
pub struct BootstrapRouteState {
    pub options: Arc<BootstrapOptions>,
    /// The origin check this route runs. The keeper session cookie is signed
    /// by the handler, with [`BootstrapOptions::keyring`] under
    /// [`BootstrapOptions::session_cookie_name`] — the spine wires both from
    /// this gate.
    pub gate: AuthGate,
}

impl std::fmt::Debug for BootstrapRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapRouteState")
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

/// Build a `axum::Router` with `POST /bootstrap` mounted at the root.
/// Mount path is the consumer's choice (typically `/api/account/bootstrap`).
pub fn bootstrap_router(state: BootstrapRouteState) -> axum::Router {
    axum::Router::new()
        .route("/bootstrap", post(bootstrap_route))
        .with_state(state)
}

async fn bootstrap_route(
    State(state): State<BootstrapRouteState>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(refused) = state.gate.check_origin(&headers) {
        return refused;
    }
    if !fuz_http::is_json_content_type(&headers) {
        return fuz_http::unsupported_content_type_response();
    }

    // Take the raw body (not `Json<BootstrapInput>`) so the origin and
    // content-type checks run before parsing, and a refused body answers the
    // twin's `400` — mirrors `signup_routes`.
    let input: BootstrapInput = match fuz_http::parse_json_body(&body) {
        Ok(input) => input,
        Err(refused) => return refused,
    };
    let client_ip_str = ClientIp::from_extension(client_ip.as_ref()).map(str::to_owned);

    match bootstrap_handler(&state.options, client_ip_str, input).await {
        Ok(success) => {
            // the cookie was signed inside the bootstrap transaction; a line
            // the grammar already admitted is visible ASCII, which every
            // `HeaderValue` holds
            let response_headers = match axum::http::HeaderValue::try_from(success.set_cookie) {
                Ok(value) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(axum::http::header::SET_COOKIE, value);
                    headers
                }
                Err(e) => {
                    return internal_error_response_with_source(
                        "bootstrap: session cookie header",
                        &e,
                    );
                }
            };
            // Wire shape matches fuz_app's TS `BootstrapOutput`:
            // `{ok, account: {id, username}, actor: {id}}`. Cross-process
            // integration tests read account.id + actor.id from this
            // response to identify what bootstrap created; without
            // returning them here, callers need a follow-up
            // `account_verify` round trip to recover the ids.
            (
                StatusCode::OK,
                response_headers,
                Json(serde_json::json!({
                    "ok": true,
                    "account": {
                        "id": success.account.id.to_string(),
                        "username": success.account.username,
                    },
                    "actor": {
                        "id": success.actor.id.to_string(),
                    },
                })),
            )
                .into_response()
        }
        Err(BootstrapError::Classified { kind }) => match kind {
            BootstrapErrorKind::AlreadyBootstrapped => {
                fuz_http::rest_error_response(StatusCode::FORBIDDEN, kind.as_str())
            }
            BootstrapErrorKind::TokenFileMissing => {
                fuz_http::rest_error_response(StatusCode::NOT_FOUND, kind.as_str())
            }
            BootstrapErrorKind::InvalidToken => {
                fuz_http::rest_error_response(StatusCode::UNAUTHORIZED, kind.as_str())
            }
            BootstrapErrorKind::InvalidInput => {
                fuz_http::rest_error_response(StatusCode::BAD_REQUEST, kind.as_str())
            }
            // a domain 500: the token matched but its file couldn't be burned,
            // so nothing was created — the code names the fix for the operator
            BootstrapErrorKind::TokenFileUndeletable => {
                fuz_http::rest_error_response(StatusCode::INTERNAL_SERVER_ERROR, kind.as_str())
            }
            BootstrapErrorKind::RateLimitExceeded { retry_after } => {
                rate_limit_exceeded(retry_after)
            }
        },
        // a failed checkout is the database unavailable, not a fault: 503
        Err(BootstrapError::Pool(e)) => {
            db_unavailable_response_with_source("bootstrap failed: db pool checkout", &e)
        }
        Err(
            e @ (BootstrapError::Query(_)
            | BootstrapError::PasswordHash(_)
            | BootstrapError::Commit(_)
            | BootstrapError::SessionCookie(_)
            | BootstrapError::Audit(_)
            | BootstrapError::Task(_)),
        ) => internal_error_response_with_source("bootstrap failed", &e),
    }
}
