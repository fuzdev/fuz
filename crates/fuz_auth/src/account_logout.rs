//! `POST /api/account/logout` — invalidate session, close live connections.
//!
//! The session delete and the `logout` success row are one transaction, so a
//! refused row ends no session and closes nothing; the account's live
//! connections close once it commits.

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use fuz_db::commit_checked;
use fuz_http::{
    db_unavailable_response_with_source, internal_error_response,
    internal_error_response_with_source,
};
use serde::Serialize;

use crate::account_route_state::AccountRouteState;
use crate::audit_emitter::{AuditLogInput, CollectingAuditPostCommit, route_audit_emit};
use crate::audit_event_type::AuditEventType;
use crate::auth_gate::OriginChecked;
use crate::connection_closer::ConnectionCloseTarget;
use crate::credential_type::CredentialGate;
use crate::route_helpers::clear_session_cookie_header;
use crate::route_response::credential_type_required_response;
use crate::session_queries::query_session_revoke_by_hash_unscoped;
use fuz_http::ClientIp;

#[derive(Debug, Serialize)]
struct OkResponse {
    ok: bool,
    username: String,
}

/// `POST /logout` handler.
pub async fn logout_handler(
    State(state): State<AccountRouteState>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Response {
    let origin = match state.gate.check_origin(&headers) {
        Ok(origin) => origin,
        Err(refused) => return refused,
    };
    if !fuz_http::is_json_content_type(&headers) {
        return fuz_http::unsupported_content_type_response();
    }
    let client_ip_str = ClientIp::as_str_or_unresolved(client_ip.as_ref()).to_owned();
    match logout_inner(&state, client_ip_str, origin).await {
        Ok(response) | Err(response) => response,
    }
}

#[expect(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine's REST handler idiom"
)]
async fn logout_inner(
    state: &AccountRouteState,
    client_ip: String,
    origin: OriginChecked<'_>,
) -> Result<Response, Response> {
    let resolved = state
        .gate
        .resolve_credential(origin, &client_ip)
        .await
        .map_err(IntoResponse::into_response)?
        .ok_or_else(fuz_http::authentication_required_response)?;

    // Logout is a session-bound operation; like `/password` it requires a
    // browser-context session credential (a bearer / daemon token holds no
    // session to end). Same gate the action specs declare, so the REST and RPC
    // halves of credential-channel gating can't drift apart.
    if !CredentialGate::SESSION_ONLY.admits(Some(resolved.credential_type())) {
        return Err(credential_type_required_response(
            CredentialGate::SESSION_ONLY,
        ));
    }

    // the gate admits only a session, which carries its hash
    let session_hash = resolved.session_hash().ok_or_else(|| {
        tracing::error!("logout: the session gate admitted a credential with no session hash");
        internal_error_response()
    })?;

    // Built before the transaction, so a header that can't be written answers
    // the 500 with nothing changed — never for a committed logout.
    let response_headers = clear_session_cookie_header(state.gate.session_cookie_name)?;

    let mut client = state
        .gate
        .pool
        .get()
        .await
        .map_err(|e| db_unavailable_response_with_source("logout: db pool error", &e))?;
    // every early return drops `tx`, which rolls it back
    let tx = client
        .transaction()
        .await
        .map_err(|e| internal_error_response_with_source("logout: transaction begin failed", &e))?;

    query_session_revoke_by_hash_unscoped(&tx, session_hash)
        .await
        .map_err(|e| internal_error_response_with_source("logout: session deletion failed", &e))?;

    // The success row, last before the commit: a refused INSERT rolls the
    // delete back, so the session — and every connection it opened — lives on.
    let post_commit = CollectingAuditPostCommit::default();
    route_audit_emit(
        &state.audit,
        &post_commit,
        &tx,
        AuditLogInput::for_event(AuditEventType::Logout)
            .account(resolved.account.id)
            .ip(Some(client_ip)),
    )
    .await
    .map_err(|_| internal_error_response())?;
    commit_checked(tx)
        .await
        .map_err(|e| internal_error_response_with_source("logout: commit failed", &e))?;

    // Eager account-wide close once the delete has committed — matches
    // `fuz_app`'s widening logout to account-wide invalidation. It reaches
    // every transport the consumer's closer covers (WS and SSE with
    // `fuz_realtime`'s fan-out); an SSE stream never rechecks its credential.
    // The row's listeners, drained next, repeat it (idempotent).
    state
        .connection_closer
        .close_connections(&ConnectionCloseTarget::Account(resolved.account.id));
    post_commit.drain().await;

    tracing::info!(username = %resolved.account.username, "logout successful");

    Ok((
        StatusCode::OK,
        response_headers,
        Json(OkResponse {
            ok: true,
            username: resolved.account.username,
        }),
    )
        .into_response())
}
