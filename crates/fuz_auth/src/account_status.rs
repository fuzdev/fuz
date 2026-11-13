//! `GET /api/account/status` — current account info or 401 with bootstrap flag.

use std::sync::atomic::Ordering;

use axum::Json;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use fuz_http::{
    db_unavailable_response_with_source, internal_error_response_with_source, query_first,
};
use serde::Serialize;

use crate::account_queries::{ActorSummary, RoleGrantSummary, query_account_summary};
use crate::account_route_state::AccountRouteState;
use crate::actor_queries::{
    ResolveActingActorResult, query_role_grant_summaries_for_actor, resolve_acting_actor,
};
use crate::actor_schema::ActorRow;
use fuz_http::ClientIp;

/// Authenticated `/status` body. Mirrors TS `AccountStatusOutput`:
/// `{account: SessionAccountJson, actor: ActorSummaryJson | null,
/// role_grants: RoleGrantSummaryJson[]}`.
///
/// `account` is always populated for authenticated callers. `actor` /
/// `role_grants` are populated when the account has a single
/// (unambiguous) actor or `?acting=<id>` names one; on multi-actor
/// accounts without `acting`, `actor` is `null` and `role_grants` is
/// empty so the frontend can show a persona picker.
#[derive(Debug, Serialize)]
struct StatusSuccess {
    account: StatusAccount,
    actor: Option<ActorSummary>,
    role_grants: Vec<RoleGrantSummary>,
}

/// `SessionAccountJson`-shaped account (no `password_hash` / audit fields).
#[derive(Debug, Serialize)]
struct StatusAccount {
    id: String,
    username: String,
    email: Option<String>,
    email_verified: bool,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct StatusUnauthenticated {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    bootstrap_available: Option<bool>,
}

/// `GET /status` handler.
///
/// The query is read as raw pairs through `fuz_http::query_first` — the TS
/// twin declares **no** query schema (the handler reads `acting` via Hono's
/// first-occurrence-wins `c.req.query()`), so unknown keys are ignored and a
/// duplicated `acting` reads as its first occurrence — never a pre-auth
/// "duplicate field" 400, which would be an anonymously observable backend
/// fingerprint (the TS twin answers 401 to an anonymous caller regardless).
///
/// A scope-narrowed API token is answered as the anonymous caller, byte for
/// byte — `401` with the bootstrap flag. Rule 3 says a narrowed token reaches
/// no non-RPC surface, and this one hands out the account's email, its
/// verification state, and the acting actor's role grants; a `403` would only
/// tell the holder what dropping the header tells it anyway, so the route's
/// own anonymous answer is the refusal.
pub async fn status_handler(
    State(state): State<AccountRouteState>,
    Query(query_pairs): Query<Vec<(String, String)>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Response {
    // A foreign page is refused before the credential walk — the gate's
    // origin check, as on every other account route.
    let client_ip = ClientIp::as_str_or_unresolved(client_ip.as_ref());
    let resolved = match state.gate.preflight(&headers, client_ip).await {
        Ok(resolved) => resolved,
        Err(refused) => return refused,
    };

    // rule 3 in its anonymous-admitting disposition: a narrowed token is the
    // anonymous caller here, never a refusal
    let Some(r) = resolved.filter(|r| r.scope().admits_non_rpc_surface()) else {
        let bootstrap = if state.bootstrap_available.load(Ordering::Relaxed) {
            Some(true)
        } else {
            None
        };
        return (
            StatusCode::UNAUTHORIZED,
            Json(StatusUnauthenticated {
                error: fuz_http::AUTHENTICATION_REQUIRED_REASON,
                bootstrap_available: bootstrap,
            }),
        )
            .into_response();
    };

    let account_id = r.account.id;

    let client = match state.gate.pool.get().await {
        Ok(c) => c,
        Err(e) => {
            return db_unavailable_response_with_source("status: db pool error", &e);
        }
    };

    // Account detail (email / email_verified / created_at). The resolved
    // context only carries id + username, so fetch the full summary.
    let summary = match query_account_summary(&client, &account_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            // Torn read — account vanished between auth resolution and this
            // fetch. Surface as 401 (matches the unauthenticated body), the
            // closest analogue to the TS `account_vanished` fall-through.
            let bootstrap = if state.bootstrap_available.load(Ordering::Relaxed) {
                Some(true)
            } else {
                None
            };
            return (
                StatusCode::UNAUTHORIZED,
                Json(StatusUnauthenticated {
                    error: fuz_http::AUTHENTICATION_REQUIRED_REASON,
                    bootstrap_available: bootstrap,
                }),
            )
                .into_response();
        }
        Err(e) => {
            return internal_error_response_with_source("status: account summary query failed", &e);
        }
    };

    let account = StatusAccount {
        id: summary.id.to_string(),
        username: summary.username,
        email: summary.email,
        email_verified: summary.email_verified,
        created_at: summary.created_at,
    };

    // Persona resolution via the shared `resolve_acting_actor`, mapping its
    // structured failures to `actor: null` (the frontend's persona-picker
    // branch) rather than an error:
    //   - `?acting=<id>` present + matches an actor on the account → use it.
    //   - `?acting=` absent + exactly one actor → use it.
    //   - `?acting=` absent + multiple actors (ambiguous), foreign id, malformed
    //     id, or zero actors → `actor: null`, `role_grants: []`.
    let resolved = match crate::parse_acting_selector(query_first(&query_pairs, "acting")) {
        Ok(acting) => resolve_status_actor(&client, &account_id, acting).await,
        // A present-but-malformed `?acting=` is a missing persona, not an error
        // and not a default-actor resolve — surface `actor: null` directly.
        Err(_) => Ok(None),
    };
    let resolved_actor = match resolved {
        Ok(a) => a,
        Err(e) => {
            return internal_error_response_with_source("status: actor resolution failed", &e);
        }
    };

    let (actor, role_grants) = match resolved_actor {
        Some(actor) => {
            let role_grants = match query_role_grant_summaries_for_actor(&client, &actor.id).await {
                Ok(g) => g,
                Err(e) => {
                    return internal_error_response_with_source(
                        "status: role grant summaries query failed",
                        &e,
                    );
                }
            };
            (
                Some(ActorSummary {
                    id: actor.id,
                    name: actor.name,
                }),
                role_grants,
            )
        }
        None => (None, Vec::new()),
    };

    Json(StatusSuccess {
        account,
        actor,
        role_grants,
    })
    .into_response()
}

/// Resolve the status persona, mapping every structured non-resolution
/// ([`ResolveActingActorResult`] `ActorRequired` / `ActorNotOnAccount` /
/// `NoActors`) to `None` — `/status` surfaces ambiguity as `actor: null` (the
/// frontend's persona picker), never an error.
async fn resolve_status_actor(
    client: &deadpool_postgres::Client,
    account_id: &uuid::Uuid,
    acting: Option<uuid::Uuid>,
) -> Result<Option<ActorRow>, tokio_postgres::Error> {
    Ok(
        match resolve_acting_actor(client, account_id, acting).await? {
            ResolveActingActorResult::Resolved(actor) => Some(actor),
            ResolveActingActorResult::ActorRequired { .. }
            | ResolveActingActorResult::ActorNotOnAccount
            | ResolveActingActorResult::NoActors => None,
        },
    )
}
