//! Axum router factory for the RPC routes.
//!
//! Wires `POST /rpc` + `GET /rpc` under one router over one
//! [`ActionDispatch`].
//! Mount path is the consumer's choice (typically `/api/rpc`).
//!
//! ## Gates
//!
//! The router carries no layers of its own: a consumer mounts it inside a
//! `fuz_http::RouteGroup` and builds its server with `fuz_http::compose_stack`,
//! which applies the body cap, the origin check, and client-IP resolution in
//! the one order every spine server shares:
//!
//! ```ignore
//! let api = fuz_http::RouteGroup::new(
//!     "api",
//!     axum::Router::new().nest("/api", fuz_actions::create_rpc_router(dispatch)),
//!     fuz_http::BodyCap::Bytes(fuz_http::DEFAULT_BODY_LIMIT_BYTES),
//! );
//! let app = fuz_http::compose_stack([api], fallback, &gate.stack_options(trusted_proxies));
//! ```
//!
//! The handlers check the origin again through the dispatch's
//! `fuz_auth::AuthGate`, so a router mounted outside the stack still refuses
//! a foreign page.

use axum::Router;
use axum::routing::post;

use crate::perform_action::ActionDispatch;
use crate::rpc_dispatch::{rpc_get_handler, rpc_post_handler};

/// Build the RPC router.
///
/// Routes (relative to the mount path):
/// - `POST /rpc` — JSON-RPC envelope in body
/// - `GET /rpc` — method/id/params from query string
///
/// Both delegate to [`fn@crate::perform_action`] via the shared dispatch
/// path in `rpc_dispatch`.
pub fn create_rpc_router(dispatch: ActionDispatch) -> Router {
    // axum's `MethodRouter` supports chaining `.get()` after `.post()`
    // so one route registration handles both method-method pairs.
    Router::new()
        .route("/rpc", post(rpc_post_handler).get(rpc_get_handler))
        .with_state(dispatch)
}
