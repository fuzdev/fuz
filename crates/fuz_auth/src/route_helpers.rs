//! Shared helpers for the REST route handlers.
//!
//! Small mechanical steps the REST handlers (and the non-RPC routes in
//! other spine crates) share — building the signed session-cookie response
//! headers and resolving a REST `?acting=` actor. Lifted here so the
//! handlers don't repeat them and the wire output stays identical across
//! routes.
//!
//! [`require_acting_actor`] is the authorization-phase step every
//! actor-resolving REST surface runs between its authority gates and its role
//! gate, with the three denial bodies its TS twin emits.

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::actor_queries::{ResolveActingActorResult, resolve_acting_actor};
use crate::actor_schema::ActorRow;
use crate::keyring::Keyring;
use crate::session_cookie::sign_session_cookie;

/// Build a fresh `HeaderMap` carrying the signed session cookie.
///
/// Signs `{session_token, expiry}` under `cookie_name` via the keyring
/// and inserts it as a `Set-Cookie` header. A parse failure on the signed
/// value yields an empty map (the cookie is dropped rather than emitted
/// malformed) — matching the prior inline behavior.
#[must_use]
pub fn session_cookie_header(keyring: &Keyring, token: &str, cookie_name: &str) -> HeaderMap {
    let cookie = sign_session_cookie(keyring, token, cookie_name);
    let mut headers = HeaderMap::new();
    if let Ok(val) = cookie.parse() {
        headers.insert(axum::http::header::SET_COOKIE, val);
    }
    headers
}

/// Resolve the request's acting actor, or return the denial its TS twin emits.
///
/// The authorization phase of a hand-mounted REST surface, in the pipeline
/// position `401 → channel → scope → **acting** → role`. Wraps
/// [`resolve_acting_actor`] with the flat-REST bodies `fuz_app`'s dispatcher
/// returns for every route declaring `auth.actor !== 'none'`:
///
/// - [`ActorRequired`](ResolveActingActorResult::ActorRequired) → 400
///   `{error: "actor_required", available: [{id, name}]}` — a multi-actor
///   account must pick; never a silent choice.
/// - [`ActorNotOnAccount`](ResolveActingActorResult::ActorNotOnAccount) → 400
///   `{error: "actor_not_on_account"}`, opaque: the available list is
///   deliberately **not** echoed, so a foreign `acting` learns nothing about
///   the account it guessed at.
/// - [`NoActors`](ResolveActingActorResult::NoActors) → 500
///   `{error: "no_actors_on_account"}`. A signup-invariant violation, not a
///   client error, so it is logged and reported as the server fault it is.
///
/// A query failure is the same 500 as any other, with the detail left in the
/// `tracing::error!` breadcrumb rather than on the wire.
///
/// The **returned actor is the one a role gate must read grants from** — the
/// spine's security-critical rule is that the role 403 runs over the resolved
/// actor's `role_grants`, never a credential-bound actor.
/// `fuz_fact_serving`'s bare route, `fuz_realtime`'s audit stream, and
/// `fuz_actions`'s WS upgrade do exactly that. A caller that gates
/// account-grain instead (`fuz_db_admin` and `fuz_forge_server`, deliberately,
/// pending multi-actor) discards the actor and says so at its call site; those two still run this phase, so the
/// selector's semantics hold either way.
///
/// # Errors
///
/// Returns the ready-to-return denial `Response` (`Err`) when the selector
/// fails to resolve or the query fails.
#[expect(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine's REST handler idiom"
)]
pub async fn require_acting_actor(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &Uuid,
    acting: Option<Uuid>,
    context: &'static str,
) -> Result<ActorRow, Response> {
    let resolved = resolve_acting_actor(client, account_id, acting)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, context, "acting-actor resolution failed");
            fuz_http::internal_error_response()
        })?;
    match resolved {
        ResolveActingActorResult::Resolved(actor) => Ok(actor),
        ResolveActingActorResult::ActorNotOnAccount => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "actor_not_on_account"})),
        )
            .into_response()),
        ResolveActingActorResult::ActorRequired { available } => {
            let available: Vec<serde_json::Value> = available
                .iter()
                .map(|a| serde_json::json!({"id": a.id, "name": a.name}))
                .collect();
            Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "actor_required", "available": available})),
            )
                .into_response())
        }
        ResolveActingActorResult::NoActors => {
            tracing::error!(%account_id, context, "account has no active actors");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "no_actors_on_account"})),
            )
                .into_response())
        }
    }
}
