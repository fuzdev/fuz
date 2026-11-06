//! Account REST router factory.
//!
//! Composes the 4 account routes (`/status`, `/login`, `/logout`,
//! `/password`) under one axum [`Router`]. Mount path is the
//! consumer's choice — typically `/api/account` to match `fuz_app`'s
//! convention.
//!
//! The `ClientIp` extension the account handlers read lives in [`fuz_http`].

use axum::Router;
use axum::routing::{get, post};

use crate::account_login::login_handler;
use crate::account_logout::logout_handler;
use crate::account_password::password_handler;
use crate::account_route_state::AccountRouteState;
use crate::account_status::status_handler;
use crate::timing::{FailFloor, warn_if_fail_floor_disabled};

/// Build an `axum::Router` for the account REST surface.
///
/// Routes (relative to the mount path):
/// - `GET /status` — current account info or 401 + bootstrap flag
/// - `POST /login` — username/password → session cookie
/// - `POST /logout` — invalidate session, clear cookie
/// - `POST /password` — change password, revoke sessions/tokens
///
/// A `state.login_fail_floor_ms` of `0` prints a once-per-process
/// `LOGIN FAILURE TIMING FLOOR DISABLED` banner to stderr (and the log) here,
/// at assembly — the floor is a production defense, so turning it off must be
/// loud.
pub fn account_router(state: AccountRouteState) -> Router {
    warn_if_fail_floor_disabled(FailFloor::Login, state.login_fail_floor_ms);
    Router::new()
        .route("/status", get(status_handler))
        .route("/login", post(login_handler))
        .route("/logout", post(logout_handler))
        .route("/password", post(password_handler))
        .with_state(state)
}
