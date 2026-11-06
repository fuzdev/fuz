//! `POST /api/account/logout` — invalidate session, close live connections.

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use fuz_http::{db_unavailable_response, internal_error_response};
use serde::Serialize;

use crate::account_route_state::AccountRouteState;
use crate::audit_emitter::AuditLogInput;
use crate::audit_event_type::AuditEventType;
use crate::auth_gate::OriginChecked;
use crate::connection_closer::ConnectionCloseTarget;
use crate::credential_type::CredentialGate;
use crate::route_response::credential_type_required_response;
use crate::session_cookie::clear_session_cookie;
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

#[allow(
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

    let client = state.gate.pool.get().await.map_err(|e| {
        tracing::error!(error = ?e, "logout: db pool error");
        db_unavailable_response()
    })?;

    query_session_revoke_by_hash_unscoped(&client, session_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "logout: session deletion failed");
            internal_error_response()
        })?;

    // Eager account-wide close — matches `fuz_app`'s widening logout to
    // account-wide invalidation. The audit write below is pool-routed and
    // fail-open, so this close is the one that must land: the audit listeners
    // run only on a written row, and an SSE stream never rechecks its
    // credential. It reaches every transport the consumer's closer covers
    // (WS and SSE with `fuz_realtime`'s fan-out). The listeners repeat it on
    // the materialized row (idempotent).
    state
        .connection_closer
        .close_connections(&ConnectionCloseTarget::Account(resolved.account.id));

    let _ = state
        .audit
        .emit(
            AuditLogInput::for_event(AuditEventType::Logout)
                .account(resolved.account.id)
                .ip(Some(client_ip)),
        )
        .await;

    let mut response_headers = HeaderMap::new();
    if let Ok(val) = clear_session_cookie(state.gate.session_cookie_name).parse() {
        response_headers.insert(axum::http::header::SET_COOKIE, val);
    }

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
