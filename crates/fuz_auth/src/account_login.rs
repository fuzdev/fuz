//! `POST /api/account/login` — username-or-email/password → session cookie.
//!
//! Converged with `fuz_app`: the submitted identifier is matched against username **or** email
//! (`query_account_with_password_hash`), supporting a single login field
//! that accepts either. Identifier canonicalization at the boundary
//! (`fuz_http::trim_js_whitespace` — the JS `String.prototype.trim` set, not
//! Rust's `trim` — then lowercased); per-IP + per-account rate limit before any
//! DB / argon2 work; dummy-hash timing equalization on missing accounts;
//! audit row on both success and failure. The audit `username` metadata
//! field carries the canonicalized identifier as submitted (the email on
//! an email login), matching the TS side.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use fuz_db::commit_checked;
use fuz_http::{db_unavailable_response, internal_error_response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::account_queries::query_account_with_password_hash;
use crate::account_route_state::AccountRouteState;
use crate::audit_emitter::AuditLogInput;
use crate::audit_event_type::AuditEventType;
use crate::connection_closer::ConnectionCloseTarget;
use crate::password::PASSWORD_LENGTH_MAX;
use crate::primitive_schemas::USERNAME_PROVIDED_LENGTH_MAX;
use crate::rate_limiter::{RESERVATION_WAIT_MAX, reserve_optional};
use crate::route_response::rate_limit_exceeded;
use crate::session_cookie::sign_session_cookie;
use crate::session_queries::create_capped_session;
use crate::timing::{compute_fail_deadline, wait_for_deadline};
use fuz_http::ClientIp;

// -- Tunables -------------------------------------------------------------

/// Default minimum wall-clock time (ms) for a login 401 denial response.
///
/// Converges to the TS twin's `DEFAULT_LOGIN_FAIL_FLOOR_MS` in
/// `fuz_app`'s `account_routes.ts`. Floors both 401 paths (no account /
/// wrong password) so the DB-presence + verify timing delta between them
/// isn't an enumeration oracle; 429 stays fast. See [`crate::timing`] for
/// the eager-deadline mechanism that makes the observed response time
/// `max(work, floor)` rather than `work + floor`. Every production consumer
/// (and its `testing_*` binary) passes it as
/// [`AccountRouteState::login_fail_floor_ms`]; only `testing_spine_stub` and
/// in-process tests pass `0`, which [`crate::account_router::account_router`]
/// announces with a stderr banner.
pub const DEFAULT_LOGIN_FAIL_FLOOR_MS: u64 = 250;

/// Default uniform jitter window (±ms) layered on the login floor.
///
/// Converges to the TS twin's `DEFAULT_LOGIN_FAIL_JITTER_MS`. Production
/// consumers pass it as [`AccountRouteState::login_fail_jitter_ms`].
pub const DEFAULT_LOGIN_FAIL_JITTER_MS: u64 = 25;

/// Login request body.
///
/// `deny_unknown_fields` mirrors the TS `LoginInput`, a strict `fuz_schema` `object` — an
/// extra body key fails deserialization and the handler maps it to
/// `400 invalid_request_body` (not silently ignored), matching the TS
/// contract and closing a mass-assignment-style surprise on future fields.
///
/// `Debug` redacts the password.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for LoginInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginInput")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct LoginSuccess {
    ok: bool,
}

/// `POST /login` handler.
///
/// Takes the raw `Bytes` body (not `Json<LoginInput>`) so the origin check
/// runs before body parsing — matching TS middleware order (origin → input
/// validation) — and so a refused body answers the twin's `400`
/// (`fuz_http::parse_json_body`) rather than axum's default `422`. Mirrors
/// `account_password`'s body-handling shape.
pub async fn login_handler(
    State(state): State<AccountRouteState>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(refused) = state.gate.check_origin(&headers) {
        return refused;
    }
    if !fuz_http::is_json_content_type(&headers) {
        return fuz_http::unsupported_content_type_response();
    }

    let input: LoginInput = match fuz_http::parse_json_body(&body) {
        Ok(input) => input,
        Err(refused) => return refused,
    };

    let client_ip_str = ClientIp::as_str_or_unresolved(client_ip.as_ref()).to_owned();
    match login_inner(&state, client_ip_str, input).await {
        Ok(response) | Err(response) => response,
    }
}

#[expect(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine's REST handler idiom"
)]
async fn login_inner(
    state: &AccountRouteState,
    client_ip: String,
    input: LoginInput,
) -> Result<Response, Response> {
    // Input validation mirrors the TS `LoginInput` schema
    // (`UsernameProvided` min 1 / max 255 / non-empty-after-trim;
    // `PasswordProvided` min 1 / max 300) — every violation is a malformed
    // body, so they share the canonical `invalid_request_body` reason rather
    // than bespoke strings or a fall-through to a lookup-miss 401.
    // `UsernameProvided`'s ceiling, in the UTF-16 code units its
    // `bounded_string` counts — the bound runs on the raw string, before the schema's canonicalizing
    // `.trim().toLowerCase()`, so the bound is measured pre-trim here too.
    if input.username.is_empty()
        || input.username.encode_utf16().count() > USERNAME_PROVIDED_LENGTH_MAX
    {
        return Err(fuz_http::invalid_request_body_response());
    }
    // `PasswordProvided`'s bounds, in the UTF-16 code units its
    // `bounded_string` counts — the minimum of 1 is emptiness only, so an account minted under an earlier
    // policy still authenticates.
    let password_len = crate::password_length(&input.password);
    if !(crate::PASSWORD_PROVIDED_LENGTH_MIN..=PASSWORD_LENGTH_MAX).contains(&password_len) {
        return Err(fuz_http::invalid_request_body_response());
    }

    // `UsernameProvided` trims with JS `String.prototype.trim`, whose set is
    // not `str::trim`'s (U+FEFF in, U+0085 out) — trim exactly what it trims.
    let canonical_username = fuz_http::trim_js_whitespace(&input.username).to_lowercase();
    if canonical_username.is_empty() {
        return Err(fuz_http::invalid_request_body_response());
    }

    // Reserve, not check: the attempt counts against the per-IP cap from here
    // until it settles below, so a concurrent burst can't all pass before any
    // of it records. A key at its cap only because of attempts in flight waits
    // briefly for a slot (`RESERVATION_WAIT_MAX`) rather than refusing a burst
    // of correct logins outright. Order: IP, then the lookup, then the account
    // (its key is the looked-up id). A wait on the account bucket keeps the IP
    // slot: it belongs to the same address, the wait is bounded, and giving it
    // up would let that address exceed its cap meanwhile. Every early return
    // drops — releases — what it holds.
    // Keyed by the address's rate-limit key (an IPv6 client's `/64`); the
    // audit rows below keep the full address.
    let mut ip_reservation = reserve_optional(
        state.login_ip_rate_limiter.as_deref(),
        &fuz_http::rate_limit_ip_key(&client_ip),
        RESERVATION_WAIT_MAX,
    )
    .await
    .map_err(|limited| rate_limit_exceeded(limited.retry_after))?;

    // Eager deadline: capture the absolute `Instant` here — after the 429
    // short-circuit (which stays fast) and before the account lookup +
    // password verify — so the wall-clock budget runs concurrently with
    // that work. Floors both 401 paths so the DB-presence + verify timing
    // delta between "no such account" and "account exists, wrong password"
    // can't be used as a username-enumeration oracle. Converges to the TS
    // login floor in `fuz_app`'s `account_routes.ts`. See `crate::timing`
    // for the `max(work, floor)` invariant. 429 and success do not wait.
    // The floor and jitter come from `state` (production passes
    // `DEFAULT_LOGIN_FAIL_FLOOR_MS` / `DEFAULT_LOGIN_FAIL_JITTER_MS`; test
    // binaries may pass `0`), so a floor of `0` yields no deadline.
    // The observable floor is pinned end-to-end by `tests/login.rs`
    // (`login_*_401_takes_at_least_the_floor`, the twin of `fuz_app`'s
    // `login_timing.db.test.ts`, plus `login_zero_floor_401_does_not_wait`
    // for the configured `0`); the `timing.rs` unit tests pin the
    // `max(work, floor)` mechanism under a paused clock.
    let fail_deadline =
        compute_fail_deadline(state.login_fail_floor_ms, state.login_fail_jitter_ms);

    // The lookup's connection is scoped to the lookup: it is back in the pool
    // before the Argon2 verify below, which can wait for a permit (see
    // `password_argon2`) and must not hold a client while it does. Nothing
    // was guarded by holding it: the lookup is a plain read outside any
    // transaction, so the row could change between it and the verify either
    // way, and the session insert below runs in its own transaction.
    let account_with_hash = {
        let client = state.gate.pool.get().await.map_err(|e| {
            tracing::error!(error = ?e, "login: db pool error");
            db_unavailable_response()
        })?;
        query_account_with_password_hash(&client, &canonical_username)
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "login: account query failed");
                internal_error_response()
            })?
    };

    let resolved_account_id: Option<uuid::Uuid> = account_with_hash.as_ref().map(|r| r.id);
    let account_rate_key = account_with_hash
        .as_ref()
        .map_or_else(|| canonical_username.clone(), |row| row.id.to_string());
    let mut account_reservation = reserve_optional(
        state.login_account_rate_limiter.as_deref(),
        &account_rate_key,
        RESERVATION_WAIT_MAX,
    )
    .await
    .map_err(|limited| rate_limit_exceeded(limited.retry_after))?;

    let dummy_hash = state.password_hasher.dummy_hash().to_owned();
    let (password_hash, account) = match account_with_hash {
        Some(row) => (row.password_hash.clone(), Some(row)),
        None => (dummy_hash, None),
    };

    // A request dropped mid-verify (a client that disconnects) is charged to
    // both buckets: the Argon2 work it started runs on regardless, and the
    // twin settles every attempt that reaches its verify.
    let verify = state
        .password_hasher
        .verify(input.password.clone(), password_hash);
    let password_valid = ip_reservation
        .charge_if_cancelled(account_reservation.charge_if_cancelled(verify))
        .await;

    let Some(account) = account.filter(|_| password_valid) else {
        // One failed credential check, charged to both buckets — the account
        // one keyed by the canonical username on the unknown-account path, so
        // misses against a nonexistent account share one bucket too.
        ip_reservation.record();
        account_reservation.record();
        let failure_account_id = resolved_account_id;
        let mut input = AuditLogInput::for_event(AuditEventType::Login)
            .failure()
            .ip(Some(client_ip.clone()))
            .metadata(json!({"username": canonical_username}));
        // `failure_account_id` is `Option<Uuid>` — known when the account
        // resolved before the password check failed, `None` when no such
        // username exists. The builder's `.account` takes `Uuid`; thread
        // the Option through the field directly.
        input.account_id = failure_account_id;
        let _ = state.audit.emit(input).await;
        // Single 401 site for both the no-account and wrong-password paths
        // (they converge through `account.filter(|_| password_valid)`), so
        // the floor wait threads through here once — masking the timing
        // delta between the two. 429 returns above without waiting; the
        // success path below does not wait either.
        wait_for_deadline(fail_deadline).await;
        return Err(fuz_http::rest_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        ));
    };

    // Account-grain only — the IP-aggregate bucket is deliberately left alone.
    // See `RateLimiter::reset`: zeroing it here let an attacker holding any one
    // credential interleave their own successful logins with guesses against
    // arbitrary victim usernames and spray indefinitely from a single address.
    // A success records nothing: both reservations are released.
    ip_reservation.release();
    account_reservation.release();
    if let Some(ref limiter) = state.login_account_rate_limiter {
        limiter.reset(&account_rate_key);
    }

    // `create_capped_session` is an INSERT + a cap eviction, which are only
    // atomic inside a transaction. The transaction is opened here rather than
    // around the whole handler so it never spans the Argon2 verify above — it
    // covers exactly the two statements that must not be observed apart.
    // Bootstrap and signup already held transactions; this is the site that ran
    // on a bare pooled client, where the pair would have had no atomicity at
    // all. It bounds one creator, not concurrent ones — see
    // `query_session_enforce_limit`.
    let mut client = state.gate.pool.get().await.map_err(|e| {
        tracing::error!(error = ?e, "login: db pool error");
        db_unavailable_response()
    })?;
    let session = async {
        let tx = client.transaction().await?;
        let session = create_capped_session(&tx, &account.id).await?;
        commit_checked(tx).await?;
        Ok::<_, fuz_db::DbError>(session)
    }
    .await
    .map_err(|e| {
        tracing::error!(error = ?e, "login: session creation failed");
        internal_error_response()
    })?;

    // The sessions the cap evicted are gone from the table, but not from the
    // connections they opened — a WebSocket keeps the authority it resolved at
    // upgrade, and an SSE stream never rechecks. Close them now that the
    // eviction has committed, before the fail-open audit write, through the
    // closer that reaches both transports. No audit row: fuz_app's event registry
    // has no eviction event, and the `login` row records the cause.
    for evicted_hash in &session.evicted {
        state
            .connection_closer
            .close_connections(&ConnectionCloseTarget::Session(evicted_hash.clone()));
    }

    let cookie = sign_session_cookie(
        &state.gate.keyring,
        &session.token,
        state.gate.session_cookie_name,
    );
    let mut response_headers = HeaderMap::new();
    if let Ok(val) = cookie.parse() {
        response_headers.insert(axum::http::header::SET_COOKIE, val);
    }

    tracing::info!(username = %account.username, "login successful");

    let _ = state
        .audit
        .emit(
            AuditLogInput::for_event(AuditEventType::Login)
                .account(account.id)
                .ip(Some(client_ip)),
        )
        .await;

    Ok((
        StatusCode::OK,
        response_headers,
        Json(LoginSuccess { ok: true }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_input_debug_redacts_the_password() {
        let input = LoginInput {
            username: "returning_user".to_owned(),
            password: "login-password-Ys3dF6".to_owned(),
        };
        let rendered = format!("{input:?}");
        assert!(!rendered.contains("login-password-Ys3dF6"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("returning_user"), "{rendered}");
    }
}
