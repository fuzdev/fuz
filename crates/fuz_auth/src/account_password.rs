//! `POST /api/account/password` — change password, revoke sessions+tokens.
//!
//! The change is one transaction: the conditional hash update, the session
//! revocation, and the API-token revocation commit together or not at all, so
//! a failed statement or a commit the server refused answers the 500 with the
//! old password, sessions, and tokens all still in place. Mirrors `fuz_app`'s
//! `/password` route, which opens the same transaction around the same three
//! statements.
//!
//! The transaction covers those three statements only. The current-password
//! verify and the new hash — the two Argon2 runs — happen before it opens,
//! on no connection at all: the account read's connection goes back to the
//! pool first.
//!
//! The account's live connections are closed after the commit and before the
//! fail-open audit write, so a change that rolled back closes nothing and a
//! committed one closes as soon as its commit is answered, whatever becomes of
//! its audit row. A commit whose answer never arrives is the gap: a
//! connection lost mid-commit answers the 500 and closes nothing, and a
//! request dropped while the commit is in flight (its client disconnected)
//! reaches neither the close nor the audit write, though the change may have
//! landed.
// TODO: shield the commit-to-close edge from request cancellation (spawn the
// commit and the close as one task) — the same edge exists in `/logout`,
// `/login`'s eviction, and the action dispatcher's post-commit drain

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use fuz_db::{Pool, commit_checked};
use fuz_http::{db_unavailable_response, internal_error_response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::account_queries::{
    query_account_with_password_hash_by_id, query_update_account_password,
};
use crate::account_route_state::AccountRouteState;
use crate::api_token_queries::query_revoke_all_api_tokens_for_account;
use crate::audit_emitter::{AuditLogInput, credential_type_value};
use crate::audit_event_type::AuditEventType;
use crate::auth_gate::OriginChecked;
use crate::connection_closer::ConnectionCloseTarget;
use crate::credential_type::CredentialGate;
use crate::password::{
    PASSWORD_LENGTH_MAX, PASSWORD_LENGTH_MIN, PASSWORD_PROVIDED_LENGTH_MIN, password_length,
};
use crate::rate_limiter::{RESERVATION_WAIT_MAX, reserve_optional};
use crate::route_response::{credential_type_required_response, rate_limit_exceeded};
use crate::session_cookie::clear_session_cookie;
use crate::session_queries::query_session_revoke_all_for_account;
use fuz_http::ClientIp;

/// Password change request body.
///
/// Strict, mirroring the TS `PasswordChangeInput`, a strict `fuz_schema` `object`: an
/// unrecognized key is a refusal, never a silent drop.
///
/// `Debug` redacts both passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordInput {
    pub current_password: String,
    pub new_password: String,
}

impl std::fmt::Debug for PasswordInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordInput")
            .field("current_password", &"<redacted>")
            .field("new_password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct OkResponse {
    ok: bool,
    sessions_revoked: u64,
    tokens_revoked: u64,
}

/// `POST /password` handler.
pub async fn password_handler(
    State(state): State<AccountRouteState>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let origin = match state.gate.check_origin(&headers) {
        Ok(origin) => origin,
        Err(refused) => return refused,
    };
    if !fuz_http::is_json_content_type(&headers) {
        return fuz_http::unsupported_content_type_response();
    }
    let client_ip_str = ClientIp::as_str_or_unresolved(client_ip.as_ref()).to_owned();
    match password_inner(&state, client_ip_str, origin, body).await {
        Ok(response) | Err(response) => response,
    }
}

#[expect(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine's REST handler idiom"
)]
async fn password_inner(
    state: &AccountRouteState,
    client_ip: String,
    origin: OriginChecked<'_>,
    body: Bytes,
) -> Result<Response, Response> {
    // Reserved, not checked: the attempt counts against the shared login
    // limiters from here until it settles, so a concurrent burst of guesses at
    // `current_password` can't all pass before any of it records. Every early
    // return drops — releases — what it holds.
    // Keyed by the address's rate-limit key (an IPv6 client's `/64`).
    let mut ip_reservation = reserve_optional(
        state.login_ip_rate_limiter.as_deref(),
        &fuz_http::rate_limit_ip_key(&client_ip),
        RESERVATION_WAIT_MAX,
    )
    .await
    .map_err(|limited| rate_limit_exceeded(limited.retry_after))?;

    // Auth resolution runs before body parsing so unauthenticated callers
    // (including bearer credentials presented in browser context, which
    // resolve discards) receive 401 rather than the JSON extractor's 400.
    // Matches TS middleware ordering — bearer_auth → request_context →
    // handler body parsing.
    let resolved = state
        .gate
        .resolve_credential(origin, &client_ip)
        .await
        .map_err(IntoResponse::into_response)?
        .ok_or_else(fuz_http::authentication_required_response)?;

    // A leaked bearer must not be able to rotate the password and lock the
    // legitimate user out — the same gate the credential-lifecycle action
    // specs declare, applied to the REST half.
    if !CredentialGate::SESSION_ONLY.admits(Some(resolved.credential_type())) {
        return Err(credential_type_required_response(
            CredentialGate::SESSION_ONLY,
        ));
    }

    let input: PasswordInput = fuz_http::parse_json_body(&body)?;

    // The twin's `PasswordChangeInput` bounds both fields — `current_password`
    // as `PasswordProvided` (1..=300), `new_password` as `Password`
    // (12..=300) — and counts UTF-16 code units, so `password_length` is what
    // makes the same value pass or fail on both spines. Bounding
    // `current_password` also keeps an oversized submission out of the Argon2
    // verify below.
    let current_len = password_length(&input.current_password);
    if !(PASSWORD_PROVIDED_LENGTH_MIN..=PASSWORD_LENGTH_MAX).contains(&current_len) {
        return Err(fuz_http::invalid_request_body_response());
    }
    let new_len = password_length(&input.new_password);
    if !(PASSWORD_LENGTH_MIN..=PASSWORD_LENGTH_MAX).contains(&new_len) {
        // TODO: the twin flattens every body-schema failure to
        // `invalid_request_body`; this bespoke reason is the one place the two
        // spellings differ on this route. Converge it with the `/signup` and
        // `/login` body reasons in one pass rather than one field at a time.
        return Err(fuz_http::rest_error_response(
            StatusCode::BAD_REQUEST,
            "new password must be at least 12 characters",
        ));
    }

    let account_id = resolved.account.id;
    let account_rate_key = account_id.to_string();

    let mut account_reservation = reserve_optional(
        state.login_account_rate_limiter.as_deref(),
        &account_rate_key,
        RESERVATION_WAIT_MAX,
    )
    .await
    .map_err(|limited| rate_limit_exceeded(limited.retry_after))?;

    // The read's connection is scoped to the read: it is back in the pool
    // before the Argon2 verify and hash below, which hold none.
    let account_with_hash = {
        let client = state.gate.pool.get().await.map_err(|e| {
            tracing::error!(error = ?e, "password: db pool error");
            db_unavailable_response()
        })?;
        query_account_with_password_hash_by_id(&client, &account_id)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "password: account query failed");
                internal_error_response()
            })?
    }
    .ok_or_else(|| {
        fuz_http::rest_error_response(StatusCode::UNAUTHORIZED, "invalid_credentials")
    })?;

    let credential_type_meta = credential_type_value(Some(resolved.credential_type()));
    let verified_hash = account_with_hash.password_hash;

    // A request dropped mid-verify is charged to both buckets, as on login
    // (see `RateLimitReservation::charge_if_cancelled`).
    let verify = state
        .password_hasher
        .verify(input.current_password.clone(), verified_hash.clone());
    let current_password_valid = ip_reservation
        .charge_if_cancelled(account_reservation.charge_if_cancelled(verify))
        .await;

    if !current_password_valid {
        ip_reservation.record();
        account_reservation.record();
        let _ = state
            .audit
            .emit(
                AuditLogInput::for_event(AuditEventType::PasswordChange)
                    .failure()
                    .account(account_id)
                    .ip(Some(client_ip.clone()))
                    .metadata(json!({"credential_type": credential_type_meta})),
            )
            .await;
        return Err(fuz_http::rest_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        ));
    }

    let new_hash = state
        .password_hasher
        .hash(input.new_password.clone())
        .await
        .map_err(|e| {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "password: hashing failed"
            );
            internal_error_response()
        })?;

    let change = change_password(
        &state.gate.pool,
        &account_id,
        new_hash.as_str(),
        &verified_hash,
    )
    .await?;

    // The caller proved knowledge of the password, so their account-grain
    // failure history is forgiven — but only now that the hash and the UPDATE
    // have settled: a fault between a reset and the UPDATE (a hashing error, a
    // database outage) would otherwise wipe the budget of a caller who is
    // observing 500s. The lost-race branch below records one attempt on top of
    // the cleared bucket, so its net cost on it stays one. Account-grain only —
    // this shares the `login_ip_rate_limiter` instance with login, so zeroing
    // that here would open the same spray path. See `RateLimiter::reset`.
    if let Some(ref limiter) = state.login_account_rate_limiter {
        limiter.reset(&account_rate_key);
    }
    let PasswordChange::Committed {
        sessions_revoked,
        tokens_revoked,
    } = change
    else {
        ip_reservation.record();
        account_reservation.record();
        let _ = state
            .audit
            .emit(
                AuditLogInput::for_event(AuditEventType::PasswordChange)
                    .failure()
                    .account(account_id)
                    .ip(Some(client_ip.clone()))
                    .metadata(json!({
                        "reason": "concurrent_change",
                        "credential_type": credential_type_meta,
                    })),
            )
            .await;
        return Err(fuz_http::rest_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        ));
    };

    // The change has committed, so close — and before the audit write, not
    // from its listener: the write below is pool-routed and fail-open, so a
    // failed INSERT must not leave the account's connections — an SSE stream
    // above all, which never rechecks — running on credentials just revoked.
    // No await sits between the commit's answer and this close. See
    // `account_logout`.
    state
        .connection_closer
        .close_connections(&ConnectionCloseTarget::Account(account_id));
    // A success records nothing on either bucket.
    ip_reservation.release();
    account_reservation.release();

    let _ = state
        .audit
        .emit(
            AuditLogInput::for_event(AuditEventType::PasswordChange)
                .account(account_id)
                .ip(Some(client_ip))
                .metadata(json!({
                    "sessions_revoked": sessions_revoked,
                    "tokens_revoked": tokens_revoked,
                    "credential_type": credential_type_meta,
                })),
        )
        .await;

    let mut response_headers = HeaderMap::new();
    if let Ok(val) = clear_session_cookie(state.gate.session_cookie_name).parse() {
        response_headers.insert(axum::http::header::SET_COOKIE, val);
    }

    tracing::info!(username = %resolved.account.username, "password changed");

    Ok((
        StatusCode::OK,
        response_headers,
        Json(OkResponse {
            ok: true,
            sessions_revoked,
            tokens_revoked,
        }),
    )
        .into_response())
}

/// What `change_password`'s transaction did.
enum PasswordChange {
    /// The hash was replaced and every session and API token of the account
    /// revoked, in one committed transaction.
    Committed {
        sessions_revoked: u64,
        tokens_revoked: u64,
    },
    /// The stored hash was no longer the verified one — a concurrent change
    /// committed first. Nothing was written.
    Superseded,
}

/// Replace the account's password hash and revoke its sessions and API tokens
/// in one transaction.
///
/// The update is conditional on `verified_hash`, which closes the verify-write
/// race with a concurrent change; when it matches no row the transaction is
/// rolled back with nothing written and the answer is
/// `PasswordChange::Superseded`. The commit is [`commit_checked`], so
/// `PasswordChange::Committed` is returned only for a commit the server
/// acknowledged — never for a transaction a failed statement aborted.
///
/// # Errors
///
/// The flat 500 for a pool checkout, the `BEGIN`, any of the three statements,
/// or the commit. The transaction is rolled back, so the hash, the sessions,
/// and the tokens are all as they were — unless the commit's answer was lost
/// in transit, when the change may have landed.
#[expect(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine's REST handler idiom"
)]
async fn change_password(
    pool: &Pool,
    account_id: &Uuid,
    new_hash: &str,
    verified_hash: &str,
) -> Result<PasswordChange, Response> {
    let mut client = pool.get().await.map_err(|e| {
        tracing::error!(error = ?e, "password: db pool error");
        db_unavailable_response()
    })?;
    let tx = client.transaction().await.map_err(|e| {
        tracing::error!(error = ?e, "password: transaction begin failed");
        internal_error_response()
    })?;

    let revoked = async {
        let updated = query_update_account_password(&tx, account_id, new_hash, verified_hash)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "password: update failed");
                internal_error_response()
            })?;
        if !updated {
            return Ok(None);
        }
        let sessions_revoked = query_session_revoke_all_for_account(&tx, account_id)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "password: session revocation failed");
                internal_error_response()
            })?;
        let tokens_revoked = query_revoke_all_api_tokens_for_account(&tx, account_id)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "password: token revocation failed");
                internal_error_response()
            })?;
        Ok::<_, Response>(Some((sessions_revoked, tokens_revoked)))
    }
    .await;

    match revoked {
        Ok(Some((sessions_revoked, tokens_revoked))) => {
            commit_checked(tx).await.map_err(|e| {
                tracing::error!(error = ?e, "password: commit failed");
                internal_error_response()
            })?;
            Ok(PasswordChange::Committed {
                sessions_revoked,
                tokens_revoked,
            })
        }
        Ok(None) => {
            rollback(tx).await;
            Ok(PasswordChange::Superseded)
        }
        Err(response) => {
            rollback(tx).await;
            Err(response)
        }
    }
}

/// Roll `tx` back, logging a failure rather than returning it: the caller's
/// own outcome is the one to report.
async fn rollback(tx: deadpool_postgres::Transaction<'_>) {
    if let Err(e) = tx.rollback().await {
        tracing::warn!(error = ?e, "password: transaction rollback failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_input_debug_redacts_both_passwords() {
        let input = PasswordInput {
            current_password: "current-password-Bq8mK1".to_owned(),
            new_password: "new-password-Wz2pL9".to_owned(),
        };
        let rendered = format!("{input:?}");
        assert!(!rendered.contains("current-password-Bq8mK1"), "{rendered}");
        assert!(!rendered.contains("new-password-Wz2pL9"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
