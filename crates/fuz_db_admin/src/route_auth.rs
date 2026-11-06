//! Internal session/bearer auth gating for the db-admin router.
//!
//! Parameterized by the required global role + session cookie name so each
//! consumer supplies its own (e.g. `admin`, or a deployment's own role). Runs
//! the spine pipeline ([`fuz_auth::AuthGate::resolve_credential`]: daemon-token
//! → cookie → bearer) plus a role gate; the origin check is each handler's
//! first step. Error bodies match the spine's flat REST
//! envelope (`{ "error": <code> }`) so the cross-backend round-trip +
//! data-exposure suites see one wire shape on every backend.

use axum::response::{IntoResponse, Response};
use fuz_auth::route_helpers::require_acting_actor;
use fuz_auth::{
    OriginChecked, TokenSurface, credential_type_required_response,
    token_scope_surface_denied_response,
};
use fuz_http::{
    authentication_required_response, db_unavailable_response_with_source,
    insufficient_permissions_response, internal_error_response_with_source,
};
use uuid::Uuid;

/// Resolve the request's auth and require `required_role` at **account
/// grain** — the credential resolves an account (not an actor), so this admits
/// when *any* actor on the account holds the global role. Admission returns
/// the resolved account id (audit attribution for the row-`DELETE`).
///
/// Returns 401 when no credential resolves, then refuses coarse-to-fine in
/// the TS pipeline's phase order: the credential-channel gate
/// (`credential_type_required` 403), the token-scope surface gate
/// (`token_scope_required` 403), the acting-selector resolution
/// (`actor_not_on_account` / `actor_required` 400, `no_actors_on_account`
/// 500 — the authorization phase), and finally the role gate
/// (`insufficient_permissions` 403).
///
/// ## Acting resolution vs the account-grain role gate
///
/// The caller's parsed `?acting=` selector is resolved with the spine's
/// `resolve_acting_actor` semantics and then **discarded** — a foreign actor
/// 400s instead of being silently ignored (the TS twin's
/// `actor_not_on_account`), and a multi-actor account must pick
/// (`actor_required` with the available list) — but the **role** check stays
/// account-grain: any *active* actor on the account holding the global role
/// admits, whichever actor was picked. Tombstoned actors are excluded on both
/// sides of that seam — resolution skips them, and the role read uses the
/// tombstone-aware `query_account_has_active_global_role` — so a grant
/// surviving on a soft-deleted actor cannot admit.
///
/// ## Multi-actor posture (deferred — security consequential)
///
/// Under the current single-actor-per-account model the account-grain role
/// check is equivalent to a per-actor one. Once accounts hold multiple
/// actors with distinct privilege, account-grain admission lets a
/// non-privileged persona inherit the gate role from a sibling on the same
/// account (the resolved acting actor is not the one whose grants are
/// checked). Revisit — treat as a privilege-confusion review point — before
/// real multi-actor accounts ship.
///
/// # Errors
///
/// Returns the denial `Response` (`Err`) when auth is absent, the acting
/// selector fails to resolve, or no actor on the account holds
/// `required_role`.
pub async fn require_role(
    state: &crate::DbAdminRouteState,
    origin: OriginChecked<'_>,
    client_ip: &str,
    acting: Option<Uuid>,
) -> Result<Uuid, Response> {
    // the bearer leg records `client_ip` as `api_token.last_used_ip`
    let auth = match state.gate.resolve_credential(origin, client_ip).await {
        Ok(Some(auth)) => auth,
        Ok(None) => return Err(authentication_required_response()),
        Err(fault) => return Err(fault.into_response()),
    };

    // Credential-channel gate — the axis the spine's `AuthSpec`s declare,
    // expressible on this REST surface too (the TS twin declares
    // `credential_types` on every db route spec). Checked before the scope
    // and role gates: a wrong channel learns nothing about the deployment's
    // token scoping or role structure.
    if !state.credential_gate.admits(Some(auth.credential_type())) {
        return Err(credential_type_required_response(state.credential_gate));
    }

    // Token-scope surface gate — **the reason rule 3 exists**.
    //
    // This router serves paginated rows of every browsable table plus row
    // `DELETE`. The credential tables sit behind the `NON_BROWSABLE_TABLES`
    // floor, but browsable rows still carry secrets in data columns (e.g.
    // a per-repo webhook secret kept in `cell.data`), and the only other
    // gates are the channel and a global role. On a mount whose channel gate
    // admits bearers, a token narrowed to a single RPC method could — without
    // this check — still bulk-read those rows and delete any browsable row,
    // which would make the scope badge in the token UI a lie, and a
    // method-allowlist-only design a false promise.
    if !auth.scope().admits_non_rpc_surface() {
        return Err(token_scope_surface_denied_response(
            TokenSurface::DbAdmin.capability(),
        ));
    }

    let client = state
        .gate
        .pool
        .get()
        .await
        .map_err(|e| db_unavailable_response_with_source("require_role pool", &e))?;

    // Acting-selector resolution — the authorization phase, between the
    // authority gates and the role gate exactly as the TS pipeline orders it
    // (401 → channel → scope → acting → role). The resolved actor is
    // **discarded** (see the doc above): the selector's semantics are
    // enforced, but the role check below stays account-grain.
    require_acting_actor(&client, &auth.account.id, acting, "db_admin").await?;

    // Account-grain gate — any *active* actor on the account holding the global
    // role admits (see the multi-actor-posture note above). The tombstone-aware
    // query is the one that matches TS, where the grant read hangs off the
    // resolved acting actor and a soft-deleted actor never resolves; the
    // tombstone-blind sibling exists for the removability guard, which must
    // over-report on purpose.
    let holds = fuz_auth::actor_queries::query_account_has_active_global_role(
        &client,
        &auth.account.id,
        state.required_role,
    )
    .await
    .map_err(|e| internal_error_response_with_source("require_role role check", &e))?;
    if !holds {
        return Err(insufficient_permissions_response(&[state.required_role]));
    }
    Ok(auth.account.id)
}
