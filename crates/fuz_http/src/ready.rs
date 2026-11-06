//! Generic `/ready` readiness route — the deploy gate.
//!
//! Twin of `fuz_app`'s TS `create_ready_route_spec`. Returns `200 {ready:
//! true}` when the live DB's columns cover the committed expected map, else
//! `503 {error}` (`schema_drift` when columns are missing, `db_unreachable`
//! when the introspection query throws). The detailed drift goes to the server
//! log only — the public body stays a minimal code so the endpoint doesn't leak
//! schema structure. A deploy poll treats `503` as a failed release and rolls
//! back, turning a silent schema-drift auth outage into a loud blocked deploy.
//!
//! The drift logic + column query live in [`fuz_db::schema_ready`]; this module
//! is just the HTTP binding. Generic (no auth domain), so it lives in
//! `fuz_http` rather than a domain crate — every spine consumer server (and
//! `testing_spine_stub`) `merge`s the router and pass their
//! own committed expected map, the same column-presence fixture the TS twin
//! reads (column-presence is engine-portable, so it's the cross-impl contract).

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use fuz_db::{ExpectedSchema, Pool, check_schema_drift, format_schema_drift, query_ready_columns};

/// State for [`ready_router`]. Cloned per request by axum's `State` extractor —
/// `Pool` is `Arc`-backed and the expected map is shared.
#[derive(Clone)]
pub struct ReadyRouteState {
    /// DB pool the readiness check introspects.
    pub pool: Pool,
    /// Committed expected column map (table → sorted column names) the consumer
    /// loads from its own `expected_schema.json` fixture.
    pub expected: Arc<ExpectedSchema>,
}

impl std::fmt::Debug for ReadyRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadyRouteState")
            .field("expected_tables", &self.expected.len())
            .finish_non_exhaustive()
    }
}

/// Router exposing `GET /ready` at its absolute path.
///
/// Merge (not nest) into the consumer's app router — the route carries its full
/// `/ready` path so it lands correctly under a root `merge`.
///
/// # Panics
///
/// Panics if `state.expected` is empty — a readiness gate with no expected
/// tables would answer `200` for any live DB, silently disabling the gate. This
/// is a boot-time wiring invariant, caught at assembly rather than in
/// production; it is never reachable from a request path.
pub fn ready_router(state: ReadyRouteState) -> Router {
    // Fail loud at assembly (twin of the TS `create_ready_route_spec` throw): an
    // empty expected map makes the drift check vacuously pass, so `/ready` would
    // never block a deploy. Catch the misconfiguration at startup.
    assert!(
        !state.expected.is_empty(),
        "ready_router: expected schema map is empty — a readiness gate with no expected tables \
         passes for any live DB; load a non-empty expected_schema.json"
    );
    Router::new().route("/ready", get(ready)).with_state(state)
}

/// `GET /ready` — column-presence schema-drift gate. Public, body-less.
async fn ready(State(state): State<ReadyRouteState>) -> Response {
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(error = %fuz_sys::cli::format_error_chain(&error), "ready: db pool error");
            return db_unreachable();
        }
    };
    let live = match query_ready_columns(&client, "public").await {
        Ok(live) => live,
        Err(error) => {
            tracing::error!(error = %fuz_sys::cli::format_error_chain(&error), "ready: schema introspection failed");
            return db_unreachable();
        }
    };
    let drift = check_schema_drift(&live, &state.expected);
    if drift.ok {
        return (StatusCode::OK, Json(serde_json::json!({ "ready": true }))).into_response();
    }
    // Detailed drift goes to the server log only — the public body stays a
    // minimal error code so the endpoint doesn't leak schema structure.
    tracing::error!(
        "ready: schema drift detected:\n{}",
        format_schema_drift(&drift)
    );
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "schema_drift" })),
    )
        .into_response()
}

fn db_unreachable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "db_unreachable" })),
    )
        .into_response()
}
