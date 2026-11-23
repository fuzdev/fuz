//! `POST /api/account/password` — change password, revoke sessions+tokens.
//!
//! The change is one transaction: the conditional hash update, the session
//! revocation, the API-token revocation, and the `password_change` success
//! row commit together or not at all, so a failed statement, a refused audit
//! row, or a commit the server refused answers the 500 with the old password,
//! sessions, and tokens all still in place. Mirrors `fuz_app`'s `/password`
//! route, which opens the same transaction around the same statements.
//!
//! The transaction covers those statements only. The current-password
//! verify and the new hash — the two Argon2 runs — happen before it opens,
//! on no connection at all: the hash read's connection goes back to the
//! pool first.
//!
//! The account's live connections are closed after the commit, so a change
//! that rolled back closes nothing and a committed one closes as soon as its
//! commit is answered; the row's listener fan-out (the revocation guard's
//! repeat of that close) runs after. A commit whose answer never arrives is
//! the gap: a connection lost mid-commit answers the 500 and closes nothing,
//! and a request dropped while the commit is in flight (its client
//! disconnected) reaches no close, though the change may have landed.
// TODO: shield the commit-to-close edge from request cancellation (spawn the
// commit and the close as one task) — the same edge exists in `/logout`,
// `/login`'s eviction, and the action dispatcher's post-commit drain

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use fuz_db::commit_checked;
use fuz_http::{
    db_unavailable_response_with_source, internal_error_response,
    internal_error_response_with_source,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::account_queries::{query_account_lock_live, query_update_account_password};
use crate::account_route_state::AccountRouteState;
use crate::api_token_queries::query_revoke_all_api_tokens_for_account;
use crate::audit_emitter::{
    AuditLogInput, CollectingAuditPostCommit, credential_type_value, emit_failure_row,
    route_audit_emit,
};
use crate::audit_event_type::AuditEventType;
use crate::auth_gate::OriginChecked;
use crate::connection_closer::ConnectionCloseTarget;
use crate::credential_type::CredentialGate;
use crate::password::{
    PASSWORD_LENGTH_MAX, PASSWORD_LENGTH_MIN, PASSWORD_PROVIDED_LENGTH_MIN, password_length,
};
use crate::rate_limiter::{RESERVATION_WAIT_MAX, RateLimitReservation, reserve_optional};
use crate::route_helpers::clear_session_cookie_header;
use crate::route_response::{credential_type_required_response, rate_limit_exceeded};
use crate::session_queries::{
    query_session_is_live, query_session_live_password_hash, query_session_revoke_all_for_account,
};
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

    let credential_type_meta = credential_type_value(Some(resolved.credential_type()));

    // The hash to verify against, read through the session that authorized the
    // request: a change committed since the credential leg revoked it, so a
    // dead session has no hash to verify — the race was lost before the verify
    // — and a live one names the hash the session was resolved under, never a
    // later change's. A delete or a purge revokes the sessions too. The read's
    // connection is scoped to the read: it is back in the pool before the
    // Argon2 verify and hash below, which hold none. Twin of `fuz_app`'s read
    // at the same step.
    // the gate admits only a session, which carries its hash
    let session_hash = resolved.session_hash().ok_or_else(|| {
        tracing::error!("password: the session gate admitted a credential with no session hash");
        internal_error_response()
    })?;
    let verified_hash = {
        let client = state
            .gate
            .pool
            .get()
            .await
            .map_err(|e| db_unavailable_response_with_source("password: db pool error", &e))?;
        query_session_live_password_hash(&client, session_hash, &account_id)
            .await
            .map_err(|e| internal_error_response_with_source("password: hash read failed", &e))?
    };
    let Some(verified_hash) = verified_hash else {
        return Err(lost_race(
            state,
            ip_reservation,
            account_reservation,
            account_id,
            &client_ip,
            &credential_type_meta,
        ));
    };

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
        emit_failure_row(
            &state.audit,
            AuditLogInput::for_event(AuditEventType::PasswordChange)
                .failure()
                .account(account_id)
                .ip(Some(client_ip.clone()))
                .metadata(json!({"credential_type": credential_type_meta})),
        );
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

    // Built before the transaction, so a header that can't be written answers
    // the 500 with nothing changed — never for a committed change.
    let response_headers = clear_session_cookie_header(state.gate.session_cookie_name)?;

    let post_commit = CollectingAuditPostCommit::default();
    let change = change_password(
        state,
        &post_commit,
        ChangeRequest {
            account_id,
            session_hash,
            new_hash: new_hash.as_str(),
            verified_hash: &verified_hash,
            client_ip: &client_ip,
            credential_type_meta: &credential_type_meta,
        },
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
    // A concurrent change committed after the hash was read — the
    // `current_password` was right then, but the stored hash no longer matches
    // — or a delete or a purge did, and the row is a tombstone or gone.
    let PasswordChange::Committed {
        sessions_revoked,
        tokens_revoked,
    } = change
    else {
        return Err(lost_race(
            state,
            ip_reservation,
            account_reservation,
            account_id,
            &client_ip,
            &credential_type_meta,
        ));
    };

    // The change — and its audit row — has committed, so close, through the
    // closer that reaches every transport (an SSE stream never rechecks). No
    // await sits between the commit's answer and this close. The row's
    // listener fan-out runs after it and repeats it (idempotent). See
    // `account_logout`.
    state
        .connection_closer
        .close_connections(&ConnectionCloseTarget::Account(account_id));
    post_commit.drain().await;
    // A success records nothing on either bucket.
    ip_reservation.release();
    account_reservation.release();

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

/// The answer for a change lost to a concurrent change, a delete or a purge:
/// charged to both limiters as a failed attempt, and audited as
/// `concurrent_change` — the `current_password` may have been right when the
/// request was authorized, so the row says so rather than "a wrong password".
/// The winner already revoked the sessions and tokens; no cookie is cleared.
fn lost_race(
    state: &AccountRouteState,
    ip_reservation: RateLimitReservation<'_>,
    account_reservation: RateLimitReservation<'_>,
    account_id: Uuid,
    client_ip: &str,
    credential_type_meta: &serde_json::Value,
) -> Response {
    ip_reservation.record();
    account_reservation.record();
    emit_failure_row(
        &state.audit,
        AuditLogInput::for_event(AuditEventType::PasswordChange)
            .failure()
            .account(account_id)
            .ip(Some(client_ip.to_owned()))
            .metadata(json!({
                "reason": "concurrent_change",
                "credential_type": credential_type_meta,
            })),
    );
    fuz_http::rest_error_response(StatusCode::UNAUTHORIZED, "invalid_credentials")
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
    /// committed first — or the account or the request's session died since
    /// the hash read. Nothing was written.
    Superseded,
}

/// What [`change_password`] changes, and what its audit row records.
struct ChangeRequest<'a> {
    account_id: Uuid,
    session_hash: &'a str,
    new_hash: &'a str,
    verified_hash: &'a str,
    client_ip: &'a str,
    credential_type_meta: &'a serde_json::Value,
}

/// Replace the account's password hash, revoke its sessions and API tokens,
/// and write the `password_change` success row, in one transaction.
///
/// The account row is locked first and the request's session read again
/// under it, so a delete, a logout or a session revoke committed since the
/// hash read refuses the change, an undelete since included; the update is
/// conditional on `verified_hash` and a live account, which closes the
/// verify-write race with a concurrent change. When either refuses, the
/// transaction is rolled back with nothing written and the answer is
/// `PasswordChange::Superseded`. The audit row is the last statement
/// before the commit, its listener fan-out queued on `post_commit` for the
/// caller to drain after the commit. The commit is [`commit_checked`], so
/// `PasswordChange::Committed` is returned only for a commit the server
/// acknowledged — never for a transaction a failed statement aborted.
///
/// # Errors
///
/// The 503 for a pool checkout; the flat 500 for the `BEGIN`, any of the
/// statements, the audit row, or the commit. The transaction is rolled back,
/// so the hash, the sessions, and the tokens are all as they were — unless the
/// commit's answer was lost in transit, when the change may have landed.
#[expect(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine's REST handler idiom"
)]
async fn change_password(
    state: &AccountRouteState,
    post_commit: &CollectingAuditPostCommit,
    request: ChangeRequest<'_>,
) -> Result<PasswordChange, Response> {
    let ChangeRequest {
        account_id,
        session_hash,
        new_hash,
        verified_hash,
        client_ip,
        credential_type_meta,
    } = request;
    let account_id = &account_id;
    let mut client = state
        .gate
        .pool
        .get()
        .await
        .map_err(|e| db_unavailable_response_with_source("password: db pool error", &e))?;
    let tx = client.transaction().await.map_err(|e| {
        internal_error_response_with_source("password: transaction begin failed", &e)
    })?;

    let revoked = async {
        // The account row first, then the session again under it. The session
        // died between the hash read and here when a delete (an undelete since
        // makes the row live again, with the verified hash) or a logout or a
        // session revoke committed — before the lock was granted, so this read
        // sees it. A change by a revoked session would otherwise land. A logout
        // or a session revoke takes no account row: one after this read meets
        // the revoke-all at the session row, which ends that session with the
        // rest. The same pair the token mint takes. Twin of the TS route's.
        let live = query_account_lock_live(&tx, account_id)
            .await
            .map_err(|e| {
                internal_error_response_with_source("password: account lock failed", &e)
            })?
            && query_session_is_live(&tx, session_hash, account_id)
                .await
                .map_err(|e| {
                    internal_error_response_with_source("password: session read failed", &e)
                })?;
        if !live {
            return Ok(None);
        }
        let updated = query_update_account_password(&tx, account_id, new_hash, verified_hash)
            .await
            .map_err(|e| internal_error_response_with_source("password: update failed", &e))?;
        if !updated {
            return Ok(None);
        }
        let sessions_revoked = query_session_revoke_all_for_account(&tx, account_id)
            .await
            .map_err(|e| {
                internal_error_response_with_source("password: session revocation failed", &e)
            })?;
        let tokens_revoked = query_revoke_all_api_tokens_for_account(&tx, account_id)
            .await
            .map_err(|e| {
                internal_error_response_with_source("password: token revocation failed", &e)
            })?;
        route_audit_emit(
            &state.audit,
            post_commit,
            &tx,
            AuditLogInput::for_event(AuditEventType::PasswordChange)
                .account(*account_id)
                .ip(Some(client_ip.to_owned()))
                .metadata(json!({
                    "sessions_revoked": sessions_revoked,
                    "tokens_revoked": tokens_revoked,
                    "credential_type": credential_type_meta,
                })),
        )
        .await
        .map_err(|_| internal_error_response())?;
        Ok::<_, Response>(Some((sessions_revoked, tokens_revoked)))
    }
    .await;

    match revoked {
        Ok(Some((sessions_revoked, tokens_revoked))) => {
            commit_checked(tx)
                .await
                .map_err(|e| internal_error_response_with_source("password: commit failed", &e))?;
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
        tracing::warn!(
            error = %fuz_sys::cli::format_error_chain(&e),
            "password: transaction rollback failed"
        );
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
