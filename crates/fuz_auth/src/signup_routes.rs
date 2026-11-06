//! `POST /signup` axum handler.
//!
//! Thin wrapper around [`crate::signup::signup_handler`]: origin gate,
//! JSON decode, signs the session cookie via the keyring, maps the
//! typed [`SignupErrorKind`] discriminants to HTTP status codes.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use fuz_http::internal_error_response;
use serde_json::json;

use crate::auth_gate::AuthGate;
use crate::error::{SignupError, SignupErrorKind};
use crate::route_helpers::session_cookie_header;
use crate::route_response::rate_limit_exceeded;
use crate::signup::{SignupInput, SignupOptions, signup_handler};
use crate::timing::{FailFloor, warn_if_fail_floor_disabled};
use fuz_http::ClientIp;

/// State for the signup router.
#[derive(Clone)]
pub struct SignupRouteState {
    pub options: Arc<SignupOptions>,
    /// The origin check this route runs, and the keyring and session cookie
    /// name (default [`crate::SESSION_COOKIE_NAME`]) the session cookie it issues is
    /// signed with.
    pub gate: AuthGate,
}

impl std::fmt::Debug for SignupRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupRouteState")
            .field("gate", &self.gate)
            .finish_non_exhaustive()
    }
}

/// Build an `axum::Router` with `POST /signup` mounted at the root.
/// Mount path is the consumer's choice (typically `/api/account` so
/// the full URL is `/api/account/signup`).
///
/// A `signup_fail_floor_ms` of `0` prints a once-per-process
/// `SIGNUP FAILURE TIMING FLOOR DISABLED` banner to stderr (and the log) here,
/// at assembly — the floor is a production defense, so turning it off must be
/// loud.
pub fn signup_router(state: SignupRouteState) -> axum::Router {
    warn_if_fail_floor_disabled(FailFloor::Signup, state.options.signup_fail_floor_ms);
    axum::Router::new()
        .route("/signup", post(signup_route))
        .with_state(state)
}

async fn signup_route(
    State(state): State<SignupRouteState>,
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

    // Take the raw body (not `Json<SignupInput>`) so the origin check runs
    // before parsing and a refused body answers the twin's `400`
    // (`fuz_http::parse_json_body`) rather than axum's default `422` — mirrors
    // `account_login` / `account_password`.
    let input: SignupInput = match fuz_http::parse_json_body(&body) {
        Ok(input) => input,
        Err(refused) => return refused,
    };

    let client_ip_str = ClientIp::from_extension(client_ip.as_ref()).map(str::to_owned);

    match signup_handler(&state.options, client_ip_str, input).await {
        Ok(success) => {
            let response_headers = session_cookie_header(
                &state.gate.keyring,
                &success.session_token,
                state.gate.session_cookie_name,
            );
            // Wire shape matches fuz_app's TS `SignupOutput`:
            // `{ok, account: {id, username}, actor: {id}}`.
            // Cross-process integration tests read account.id +
            // actor.id from this response to identify what signup
            // created — see fuz_app's `default_cross_process_setup`.
            (
                StatusCode::OK,
                response_headers,
                Json(json!({
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
        Err(SignupError::Classified { kind }) => match kind {
            SignupErrorKind::NoMatchingInvite => {
                fuz_http::rest_error_response(StatusCode::FORBIDDEN, kind.as_str())
            }
            SignupErrorKind::SignupConflict => {
                fuz_http::rest_error_response(StatusCode::CONFLICT, kind.as_str())
            }
            SignupErrorKind::InvalidInput => {
                fuz_http::rest_error_response(StatusCode::BAD_REQUEST, kind.as_str())
            }
            SignupErrorKind::RateLimitExceeded { retry_after } => rate_limit_exceeded(retry_after),
            SignupErrorKind::InternalError => internal_error_response(),
        },
        // a failed checkout is the database unavailable, not a fault: 503
        Err(SignupError::Pool(e)) => {
            tracing::error!(error = ?e, "signup failed: db pool checkout");
            fuz_http::db_unavailable_response()
        }
        Err(
            e @ (SignupError::Query(_) | SignupError::PasswordHash(_) | SignupError::Commit(_)),
        ) => {
            tracing::error!(error = ?e, "signup failed");
            internal_error_response()
        }
    }
}
