//! Per-request credential resolution.
//!
//! Walks the daemon-token → cookie → bearer pipeline (matching `fuz_app`'s
//! middleware order) and returns an account-grain [`ResolvedAuth`] when any leg
//! succeeds. A leg whose database read fails ends the walk with a
//! [`CredentialReadFault`] instead of handing the request to the next leg.
//!
//! **No actor is bound here** — the transport resolves account-grain identity
//! (account + credential type) and the dispatcher's authorization phase
//! resolves the acting actor from the request's `acting` input. This is the
//! two-phase identity split: authentication = account (credential resolution);
//! authorization = per-request actor + role grants (dispatch).
//!
//! [`revalidate_resolved_auth`] re-reads a credential the walk already
//! resolved, and [`recheck_admission`] re-reads it with the acting actor and
//! the endpoint's roles — the check a long-lived connection (WebSocket, SSE
//! stream) runs once it is registered, so a revocation racing its open cannot
//! be missed.
//!
//! `build_public_request_context` sits on top of that walk for the spine's
//! pure-public routes: same pipeline, then the public-route rules that bind an
//! actor (or resolve to anonymous — including for a scope-narrowed API token,
//! which a public route downgrades rather than refuses).
//!
//! Both walks are crate-private: a surface reaches them through
//! [`crate::AuthGate`], which holds the origin allowlist beside them.

use crate::account_queries::query_account_by_id;
use crate::account_schema::AccountRow;
use crate::actor_queries::{
    query_active_actor_holds_any_global_role, query_active_actors_by_account,
    query_role_grant_find_active_for_actor,
};
use crate::api_token::{hash_api_token, is_api_token_shaped};
use crate::api_token_queries::{
    query_api_token_live_account, query_validate_api_token, spawn_api_token_touch,
};
use crate::bearer_auth::is_browser_context;
use crate::credential_deadline::credential_deadline_after;
use crate::credential_type::CredentialType;
use crate::daemon_token::{DAEMON_TOKEN_HEADER, SharedDaemonTokenState, validate_daemon_token};
use crate::hash::hash_session_token;
use crate::keyring::Keyring;
use crate::request_context::RequestActorContext;
use crate::session_cookie::parse_session_from_cookies;
use crate::session_queries::query_session_get_valid;
use crate::token_scope::TokenScope;
use std::time::Instant;

/// A credential leg could not finish its read: its pool checkout or a query
/// failed, so whether the request carries that credential is unknown.
///
/// Kept apart from "no credential" so the walk can stop on it. Falling through
/// to the next leg would let a lower-priority credential stand in for the one
/// the read failed on (a bearer for the session cookie beside it, with the
/// bearer's `last_used_*` touched), and a fault on every leg would read as an
/// anonymous caller.
///
/// Every surface answers it with its
/// [`IntoResponse`](axum::response::IntoResponse), the TS twin's answer, split
/// by the phase that failed ([`CredentialFaultKind`]). A failed **checkout**
/// is the database unavailable: 503 `{"error": "service_unavailable"}`
/// ([`fuz_http::db_unavailable_response`]) — there the checkout throws a
/// `DbCheckoutError` out of the auth middleware into the server's `onError`.
/// A failed **query** keeps Hono's default error handler's answer: status 500,
/// `Content-Type: text/plain; charset=UTF-8`, and the body
/// `Internal Server Error`. The cause is logged where it happens; the fault
/// carries only the leg and the phase, so nothing about the database reaches
/// the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the {} credential read failed ({})", .leg.name(), .kind.as_str())]
pub struct CredentialReadFault {
    leg: CredentialType,
    kind: CredentialFaultKind,
}

/// Which phase of a credential leg's read failed — what decides
/// [`CredentialReadFault`]'s answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFaultKind {
    /// The pool checkout failed (timed out, server unreachable, pool closed):
    /// 503.
    Unavailable,
    /// A query on the checked-out client failed: the text 500.
    Read,
}

impl CredentialFaultKind {
    /// The phase's name, for the error message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "checkout",
            Self::Read => "query",
        }
    }
}

impl CredentialReadFault {
    /// The fault of `leg`'s read failing in `kind`'s phase.
    #[must_use]
    pub const fn new(leg: CredentialType, kind: CredentialFaultKind) -> Self {
        Self { leg, kind }
    }

    /// The leg whose read failed.
    #[must_use]
    pub const fn leg(&self) -> CredentialType {
        self.leg
    }

    /// The phase that failed.
    #[must_use]
    pub const fn kind(&self) -> CredentialFaultKind {
        self.kind
    }
}

/// The body of [`CredentialReadFault`]'s response to a failed query — Hono's
/// default error handler's.
pub const CREDENTIAL_READ_FAULT_BODY: &str = "Internal Server Error";

impl axum::response::IntoResponse for CredentialReadFault {
    fn into_response(self) -> axum::response::Response {
        if self.kind == CredentialFaultKind::Unavailable {
            return fuz_http::db_unavailable_response();
        }
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=UTF-8"),
            )],
            CREDENTIAL_READ_FAULT_BODY,
        )
            .into_response()
    }
}

/// [`crate::AuthGate::public_request_context`] could not finish: the caller is
/// unknown, so the route can neither admit nor refuse it.
///
/// The variants answer as the TS twin does. There the credential walk runs
/// in the auth middleware, so its fault answers as [`CredentialReadFault`]
/// does; the actor and role-grant reads that follow run inside the route
/// handler, so a failed checkout there is the route pipeline's flat 503
/// `{"error": "service_unavailable"}` ([`fuz_http::db_unavailable_response`])
/// and a failed read its flat 500 `{"error": "internal_error"}`
/// ([`fuz_http::internal_error_response`]). None reads as an anonymous
/// caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublicContextFault {
    /// The credential walk's read failed.
    #[error(transparent)]
    Credential(#[from] CredentialReadFault),
    /// The credential resolved, and the pool checkout after it failed.
    #[error("the public caller's checkout failed")]
    CallerUnavailable,
    /// The credential resolved, and the actor or role-grant read after it
    /// failed.
    #[error("the public caller's actor read or role-grant read failed")]
    CallerRead,
}

impl axum::response::IntoResponse for PublicContextFault {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Credential(fault) => fault.into_response(),
            Self::CallerUnavailable => fuz_http::db_unavailable_response(),
            Self::CallerRead => fuz_http::internal_error_response(),
        }
    }
}

/// The credential a request authenticated with, and what belongs to it alone.
///
/// One variant per [`CredentialType`], each carrying only its own fields — the
/// session hash on a session, the token id and scope on an API token — so a
/// session with a narrowed scope or a bearer with a session hash cannot be
/// built. Twin of the TS `ResolvedAuth` union's arms.
///
/// `Debug` redacts the session hash (`"<set>"`) — it is the `auth_session.id`,
/// so a `tracing::debug!(?auth)` must not write it to a log. The token id is
/// the token's public id and prints whole.
#[derive(Clone)]
pub enum ResolvedCredential {
    /// A session cookie — full account authority by construction.
    Session {
        /// blake3 hash of the session token — the `auth_session.id` (for a
        /// `ConnectionCloseTarget::Session` close).
        session_hash: String,
    },
    /// An `Authorization: Bearer` API token — the only credential a scope
    /// narrows.
    ApiToken {
        /// `api_token.id` (for a `ConnectionCloseTarget::Token` close).
        api_token_id: String,
        /// The authority the token was minted with, read off its row.
        scope: TokenScope,
    },
    /// The keeper-bound daemon token — full authority, no row, no expiry.
    DaemonToken,
}

impl std::fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session { session_hash: _ } => f
                .debug_struct("Session")
                .field("session_hash", &"<set>")
                .finish(),
            Self::ApiToken {
                api_token_id,
                scope,
            } => f
                .debug_struct("ApiToken")
                .field("api_token_id", api_token_id)
                .field("scope", scope)
                .finish(),
            Self::DaemonToken => f.write_str("DaemonToken"),
        }
    }
}

/// Account-grain identity resolved from the request headers.
///
/// Carries the account, the credential ([`ResolvedCredential`]) with what
/// belongs to it, and the credential's deadline. **No actor** — the acting
/// actor is resolved by the dispatcher's authorization phase from the
/// request's `acting` input.
///
/// `#[non_exhaustive]` makes the three constructors in this module the only
/// origin a `ResolvedAuth` can have outside this crate — a consumer (or a
/// consumer's test) cannot hand-assemble one that skips the credential walk.
/// The field correlations are the enum's, so no mutation of an owned value can
/// produce a shape a gate would misread.
///
/// The seal is on **origin only**: every field stays `pub`, so code holding an
/// owned value can still replace its credential or account — but whatever it
/// builds is a coherent credential, never a misread one.
///
/// `Debug` is derived and redacts through [`ResolvedCredential`]'s.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolvedAuth {
    /// The authenticated account (credential-grain identity).
    pub account: AccountRow,
    /// How the request was authenticated, with what belongs to that credential.
    pub credential: ResolvedCredential,
    /// When the credential stops authenticating — the moment a long-lived
    /// connection opened on it (a WebSocket, an SSE stream) is closed, since
    /// expiry writes nothing a revocation listener could hear.
    ///
    /// The earliest of what the credential carries: for a session, the signed
    /// cookie's expiry and the `auth_session` row's; for an API token, the
    /// row's, and `None` for an eternal one; `None` for the daemon token,
    /// which has no expiry. A row's expiry is read as time remaining on the
    /// database clock and anchored to this process's monotonic clock at the
    /// read, so a skew between the two clocks moves no deadline.
    pub credential_deadline: Option<Instant>,
}

impl ResolvedAuth {
    /// How this request was authenticated.
    #[must_use]
    pub const fn credential_type(&self) -> CredentialType {
        match self.credential {
            ResolvedCredential::Session { .. } => CredentialType::Session,
            ResolvedCredential::ApiToken { .. } => CredentialType::ApiToken,
            ResolvedCredential::DaemonToken => CredentialType::DaemonToken,
        }
    }

    /// What this credential may do — an API token's own scope, and
    /// [`TokenScope::Full`] for a session (a browser session *is* full account
    /// authority — narrowing it is what role grants are for) or the daemon
    /// token (singular, filesystem-proved, keeper-bound). Every token-scope
    /// gate reads this. Twin of the TS `resolved_auth_scope`.
    #[must_use]
    pub const fn scope(&self) -> &TokenScope {
        match &self.credential {
            ResolvedCredential::ApiToken { scope, .. } => scope,
            ResolvedCredential::Session { .. } | ResolvedCredential::DaemonToken => {
                &TokenScope::Full
            }
        }
    }

    /// The session hash of a session credential, `None` for any other.
    #[must_use]
    pub fn session_hash(&self) -> Option<&str> {
        match &self.credential {
            ResolvedCredential::Session { session_hash } => Some(session_hash),
            _ => None,
        }
    }

    /// The token id of an API token credential, `None` for any other.
    #[must_use]
    pub fn api_token_id(&self) -> Option<&str> {
        match &self.credential {
            ResolvedCredential::ApiToken { api_token_id, .. } => Some(api_token_id),
            _ => None,
        }
    }
}

/// Walk the daemon-token → cookie → bearer pipeline: the first leg that
/// authenticates, `Ok(None)` when none does, or the first leg's
/// [`CredentialReadFault`] — a leg whose read fails ends the walk, and the legs
/// after it are not tried.
///
/// `cookie_name` is the per-app session cookie name (default
/// [`crate::SESSION_COOKIE_NAME`]) — the cookie leg reads it. `client_ip` is
/// the resolved client IP, which the bearer leg records as
/// `api_token.last_used_ip` (matching the `fuz_app` bearer path). It is a
/// `&str`, not an `Option`: the touch has no "skip the column" form, so a
/// handler with no `ClientIp` extension in scope passes
/// [`fuz_http::ClientIp::as_str_or_unresolved`]'s sentinel rather
/// than erasing the address an earlier request recorded.
pub(crate) async fn resolve_auth_from_headers(
    headers: &axum::http::HeaderMap,
    keyring: &Keyring,
    pool: &deadpool_postgres::Pool,
    daemon_token_state: Option<&SharedDaemonTokenState>,
    cookie_name: &str,
    client_ip: &str,
) -> Result<Option<ResolvedAuth>, CredentialReadFault> {
    if let Some(state) = daemon_token_state
        && let Some(resolved) = resolve_daemon_token_from_headers(headers, state, pool).await?
    {
        return Ok(Some(resolved));
    }

    if let Some(resolved) = resolve_cookie_from_headers(headers, keyring, pool, cookie_name).await?
    {
        return Ok(Some(resolved));
    }

    resolve_bearer_from_headers(headers, pool, client_ip).await
}

/// Resolve cookie session under `cookie_name` (default `fuz_session`).
async fn resolve_cookie_from_headers(
    headers: &axum::http::HeaderMap,
    keyring: &Keyring,
    pool: &deadpool_postgres::Pool,
    cookie_name: &str,
) -> Result<Option<ResolvedAuth>, CredentialReadFault> {
    const UNAVAILABLE: CredentialReadFault =
        CredentialReadFault::new(CredentialType::Session, CredentialFaultKind::Unavailable);
    const FAULT: CredentialReadFault =
        CredentialReadFault::new(CredentialType::Session, CredentialFaultKind::Read);
    let Some(cookie_header) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };

    let Some(cookie) = parse_session_from_cookies(cookie_header, keyring, cookie_name) else {
        return Ok(None);
    };
    let session_hash = hash_session_token(&cookie.token).as_str().to_owned();

    let client = pool.get().await.map_err(|e| {
        tracing::error!(error = %fuz_sys::cli::format_error_chain(&e), "cookie auth pool error");
        UNAVAILABLE
    })?;

    let Some(session) = query_session_get_valid(&client, &session_hash)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "cookie auth session query failed"
            );
            FAULT
        })?
    else {
        return Ok(None);
    };

    let Some(account) = query_account_by_id(&client, &session.account_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "cookie auth account query failed"
            );
            FAULT
        })?
    else {
        return Ok(None);
    };

    Ok(Some(ResolvedAuth {
        account,
        // A session is full account authority by construction — narrowing what
        // a logged-in human may do is what role grants are for.
        credential: ResolvedCredential::Session { session_hash },
        credential_deadline: credential_deadline_after(
            Instant::now(),
            [Some(cookie.remaining()), Some(session.expires_in)],
        ),
    }))
}

/// Resolve `Authorization: Bearer <token>` header.
///
/// Mirrors `fuz_app`'s `bearer_auth.ts`:
/// - Case-insensitive "Bearer " prefix (RFC 7235 §2.1)
/// - Discards the token on a request with a browser-context header
///   ([`is_browser_context`] has what that does and doesn't prove)
/// - Refuses a value that is not [`is_api_token_shaped`] before any pool
///   checkout or query
/// - Hashes token with blake3 and looks up in `api_token`
async fn resolve_bearer_from_headers(
    headers: &axum::http::HeaderMap,
    pool: &deadpool_postgres::Pool,
    client_ip: &str,
) -> Result<Option<ResolvedAuth>, CredentialReadFault> {
    const UNAVAILABLE: CredentialReadFault =
        CredentialReadFault::new(CredentialType::ApiToken, CredentialFaultKind::Unavailable);
    const FAULT: CredentialReadFault =
        CredentialReadFault::new(CredentialType::ApiToken, CredentialFaultKind::Read);
    let Some(auth_header) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };

    if auth_header.len() < 7 || !auth_header[..7].eq_ignore_ascii_case("bearer ") {
        return Ok(None);
    }

    if is_browser_context(headers) {
        tracing::debug!("bearer auth rejected: browser context (Origin/Referer present)");
        return Ok(None);
    }

    let raw_token = &auth_header[7..];
    if !is_api_token_shaped(raw_token) {
        tracing::debug!("bearer auth soft-fail: malformed token");
        return Ok(None);
    }

    let token_hash = hash_api_token(raw_token);

    let client = pool.get().await.map_err(|e| {
        tracing::error!(error = %fuz_sys::cli::format_error_chain(&e), "bearer auth pool error");
        UNAVAILABLE
    })?;

    let Some(token_row) = query_validate_api_token(&client, &token_hash)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "bearer auth token query failed"
            );
            FAULT
        })?
    else {
        return Ok(None);
    };

    let Some(account) = query_account_by_id(&client, &token_row.account_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "bearer auth account query failed"
            );
            FAULT
        })?
    else {
        return Ok(None);
    };

    // Fire-and-forget last-used-at + last-used-ip update.
    spawn_api_token_touch(pool, &token_row.id, client_ip);

    Ok(Some(ResolvedAuth {
        account,
        // The only credential that can be narrowed. `query_validate_api_token`
        // already refused the token if its stored document was unreadable, so
        // this is a scope someone actually chose.
        credential: ResolvedCredential::ApiToken {
            api_token_id: token_row.id,
            scope: token_row.scope,
        },
        credential_deadline: credential_deadline_after(Instant::now(), [token_row.expires_in]),
    }))
}

/// Resolve `X-Daemon-Token` header. Sync lock — no `.await` inside the
/// critical section.
async fn resolve_daemon_token_from_headers(
    headers: &axum::http::HeaderMap,
    daemon_state: &SharedDaemonTokenState,
    pool: &deadpool_postgres::Pool,
) -> Result<Option<ResolvedAuth>, CredentialReadFault> {
    const UNAVAILABLE: CredentialReadFault = CredentialReadFault::new(
        CredentialType::DaemonToken,
        CredentialFaultKind::Unavailable,
    );
    const FAULT: CredentialReadFault =
        CredentialReadFault::new(CredentialType::DaemonToken, CredentialFaultKind::Read);
    let Some(token_value) = headers
        .get(DAEMON_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };

    if token_value.is_empty() {
        return Ok(None);
    }

    if is_browser_context(headers) {
        tracing::debug!("daemon token auth rejected: browser context (Origin/Referer present)");
        return Ok(None);
    }

    // Critical section: validate + capture keeper id. Sync (parking_lot).
    let keeper_account_id = {
        let state = daemon_state.read();
        if !validate_daemon_token(token_value, &state) {
            tracing::debug!("daemon token validation failed");
            return Ok(None);
        }
        let Some(keeper_account_id) = state.keeper_account_id else {
            return Ok(None);
        };
        keeper_account_id
    };

    let client = pool.get().await.map_err(|e| {
        tracing::error!(
            error = %fuz_sys::cli::format_error_chain(&e),
            "daemon token auth pool error"
        );
        UNAVAILABLE
    })?;

    let Some(account) = query_account_by_id(&client, &keeper_account_id)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "daemon token account query failed"
            );
            FAULT
        })?
    else {
        tracing::warn!("daemon token keeper account not found in DB");
        return Ok(None);
    };

    Ok(Some(ResolvedAuth {
        account,
        // Singular, filesystem-proved, keeper-bound — there is no minting step
        // at which a narrowing could have been chosen.
        credential: ResolvedCredential::DaemonToken,
        // No row, no expiry; a rotation closes no connection.
        credential_deadline: None,
    }))
}

/// Re-check that a resolved credential still authenticates: `Ok(true)` when
/// it does, `Ok(false)` when it has been revoked, has expired, or its account
/// is gone.
///
/// For a connection that outlives its request — a WebSocket, an SSE stream —
/// and is authorized once, at open. Such a connection is closed on revocation
/// by identity, but only once it is *registered*; between the credential read
/// and the registration a revocation closes nothing. So the opener registers
/// first (un-admitted — `fuz_realtime`'s `ConnectionRegistry::register_pending`
/// / `SseRegistry::subscribe_pending`), then calls this, then admits. Because
/// every revocation closes connections only after its write has committed
/// ([`crate::connection_closer`]), a close that missed the registration belongs
/// to a revocation this read sees.
///
/// That argument needs each statement here to see everything committed before
/// it started, so `client` must be an **autocommit** client or a
/// `READ COMMITTED` transaction — never a `REPEATABLE READ` / `SERIALIZABLE`
/// transaction opened before the registration, whose snapshot would predate
/// it.
///
/// What is re-read, per credential — each through the same predicate the
/// resolve walk used, so the two cannot disagree about what "valid" means
/// (the session and account legs call the walk's own queries; the token leg
/// shares its `WHERE` fragment):
///
/// - **Session** — the `auth_session` row still exists, is unexpired, and
///   belongs to the resolved account.
/// - **API token** — the `api_token` row still exists, is unexpired, and
///   belongs to the resolved account (by id; the raw token is not kept).
/// - **Daemon token** — nothing of its own. The token has no row, and no
///   revocation event: rotation closes no connection — a rotated-out token's
///   sockets are meant to keep running — so there is no close an opening
///   connection could have missed. Its keeper account is still re-read.
/// - **Every credential** — the account row still exists and is not
///   soft-deleted.
///
/// It re-checks the **credential**, not what a revocation chose to close: a
/// `logout` closes every connection of the account but deletes only its own
/// session, so another session's connection opening concurrently passes this
/// check and is refused only if that account-wide close found its pending
/// registration — the same two outcomes an already-open connection has.
///
/// **No side effects.** Unlike the resolve walk's bearer leg this never
/// touches `api_token.last_used_at` / `last_used_ip` — re-checking a
/// credential is not using it — and it writes nothing else.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client. The caller
/// must fail closed: an unchecked credential is not a valid one.
pub async fn revalidate_resolved_auth(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    resolved: &ResolvedAuth,
) -> Result<bool, tokio_postgres::Error> {
    let account_id = resolved.account.id;
    let credential_is_live = match &resolved.credential {
        ResolvedCredential::Session { session_hash } => {
            query_session_get_valid(client, session_hash)
                .await?
                .is_some_and(|session| session.account_id == account_id)
        }
        ResolvedCredential::ApiToken { api_token_id, .. } => {
            query_api_token_live_account(client, api_token_id)
                .await?
                .is_some_and(|owner| owner == account_id)
        }
        ResolvedCredential::DaemonToken => true,
    };
    if !credential_is_live {
        return Ok(false);
    }
    Ok(query_account_by_id(client, &account_id).await?.is_some())
}

/// What [`recheck_admission`] found: admitted, or the first check that refused
/// — the credential, the acting actor, or the endpoint's role.
///
/// Twin of `fuz_app`'s `AdmissionRecheck`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRecheck {
    /// Every re-read still admits the connection.
    Admitted,
    /// The credential no longer authenticates ([`revalidate_resolved_auth`]).
    CredentialRevoked,
    /// The acting actor is no longer an active actor of the account.
    ActorInactive,
    /// The acting actor no longer holds any of the required roles globally.
    RoleRevoked,
}

/// Re-read everything a long-lived connection's gates read, once the
/// connection is registered pending.
///
/// The admission step a WebSocket upgrade and the audit stream share — twin
/// of `fuz_app`'s `recheck_admission`.
///
/// In order, stopping at the first refusal:
///
/// 1. **The credential** ([`revalidate_resolved_auth`]) →
///    [`AdmissionRecheck::CredentialRevoked`].
/// 2. **The acting actor** the gates resolved, `acting_actor_id`: it must
///    still be an active actor of the account →
///    [`AdmissionRecheck::ActorInactive`]. A soft-deleted actor keeps its
///    account's credentials and its own grant rows, so neither other re-read
///    would refuse it.
/// 3. **The role**, when `required_roles` is non-empty: the acting actor must
///    hold an active **global** grant of any listed role while it and its
///    account are active ([`query_active_actor_holds_any_global_role`]) →
///    [`AdmissionRecheck::RoleRevoked`]. A scoped grant never admits at a role
///    gate.
///
/// Every read must see what committed before it started, so `client` is an
/// autocommit client (see [`revalidate_resolved_auth`]).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client. The caller
/// must fail closed: an unchecked connection is not an admitted one.
pub async fn recheck_admission(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    resolved: &ResolvedAuth,
    acting_actor_id: &uuid::Uuid,
    required_roles: &[&str],
) -> Result<AdmissionRecheck, tokio_postgres::Error> {
    if !revalidate_resolved_auth(client, resolved).await? {
        return Ok(AdmissionRecheck::CredentialRevoked);
    }
    let actor_is_active = query_active_actors_by_account(client, &resolved.account.id)
        .await?
        .iter()
        .any(|actor| actor.id == *acting_actor_id);
    if !actor_is_active {
        return Ok(AdmissionRecheck::ActorInactive);
    }
    if !required_roles.is_empty()
        && !query_active_actor_holds_any_global_role(client, acting_actor_id, required_roles)
            .await?
    {
        return Ok(AdmissionRecheck::RoleRevoked);
    }
    Ok(AdmissionRecheck::Admitted)
}

/// Resolve the caller's actor context on a **pure-public** route
/// (unauthenticated / multi-actor / narrowed-token → anonymous). Mirrors the TS
/// `build_public_request_context`.
///
/// Walks the same daemon-token → cookie → bearer pipeline as
/// [`resolve_auth_from_headers`] — it delegates to it rather than re-deriving a
/// credential — and then applies the two public-route rules that turn an
/// account-grain credential into an actor-grain context, or into nothing:
///
/// 1. **A scope-narrowed API token resolves to `None`, not a refusal.** Rule 3
///    ([`TokenScope::admits_non_rpc_surface`]) says a narrowed token reaches no
///    non-RPC surface, and this is one — but the route admits anonymous
///    callers, so a `403` would enforce nothing: the holder drops the
///    `Authorization` header and re-reads every public cell anyway. Downgrading
///    gives the credential exactly the reach it could obtain regardless, which
///    is the honest disposition and the fail-safe direction (it can be loosened
///    additively; tightening it later would be the breaking change). Session
///    and daemon-token credentials are [`TokenScope::Full`] by construction, so
///    only a narrowed bearer takes this branch — the rule keys on the scope,
///    not on the credential type.
/// 2. **A public route has no `acting` slot**, so an account with anything
///    other than exactly one *active* actor is anonymous; a single-actor
///    account resolves to that actor plus its `role_grants`. Soft-deleted
///    (tombstoned) actors are excluded from the count
///    (`query_active_actors_by_account`), matching the acting-actor resolution
///    path — a tombstoned actor is never resolvable here.
///
/// `client_ip` is threaded to the bearer leg's `api_token.last_used_ip` touch,
/// exactly as in [`resolve_auth_from_headers`] and under the same
/// non-`Option` rule.
///
/// A fault in the walk is the walk's [`CredentialReadFault`], and a failed
/// pool checkout, actor read, or role-grant read after it is
/// [`PublicContextFault::CallerRead`] — never an anonymous caller.
pub(crate) async fn build_public_request_context(
    headers: &axum::http::HeaderMap,
    keyring: &Keyring,
    pool: &deadpool_postgres::Pool,
    daemon_token_state: Option<&SharedDaemonTokenState>,
    cookie_name: &str,
    client_ip: &str,
) -> Result<Option<RequestActorContext>, PublicContextFault> {
    let Some(resolved) = resolve_auth_from_headers(
        headers,
        keyring,
        pool,
        daemon_token_state,
        cookie_name,
        client_ip,
    )
    .await?
    else {
        return Ok(None);
    };
    public_actor_context(resolved, pool).await
}

/// The public-route rules [`build_public_request_context`] applies to the
/// credential the walk resolved.
async fn public_actor_context(
    resolved: ResolvedAuth,
    pool: &deadpool_postgres::Pool,
) -> Result<Option<RequestActorContext>, PublicContextFault> {
    // Rule 3 in its public-read disposition — anonymous, never a refusal. See
    // rule 1 in the doc comment above for why; `/api/account/status` is the
    // spine's other site that downgrades rather than denies.
    if !resolved.scope().admits_non_rpc_surface() {
        tracing::debug!(
            api_token_id = ?resolved.api_token_id(),
            "public request context: narrowed token downgraded to anonymous",
        );
        return Ok(None);
    }
    let account = resolved.account;

    let client = match pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "public request context pool error"
            );
            return Err(PublicContextFault::CallerUnavailable);
        }
    };
    // Count only **active** actors (`query_active_actors_by_account`): a
    // soft-deleted (tombstoned) actor must neither demote an otherwise
    // single-actor account to anonymous, nor — the hazard — be resolved as the
    // sole actor and carry its `role_grants` into a public read. Same
    // tombstone-exclusion rule the acting-actor path applies
    // (`resolve_acting_actor`).
    let actors = match query_active_actors_by_account(&client, &account.id).await {
        Ok(actors) => actors,
        Err(e) => {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "public request context actor query failed"
            );
            return Err(PublicContextFault::CallerRead);
        }
    };
    // A public route has no `acting` slot — a multi-actor (or zero-actor)
    // account is anonymous here.
    let Ok([actor]) = <[_; 1]>::try_from(actors) else {
        return Ok(None);
    };
    let role_grants = match query_role_grant_find_active_for_actor(&client, &actor.id).await {
        Ok(grants) => grants,
        Err(e) => {
            tracing::error!(
                error = %fuz_sys::cli::format_error_chain(&e),
                "public request context role-grant query failed"
            );
            return Err(PublicContextFault::CallerRead);
        }
    };
    Ok(Some(RequestActorContext {
        account,
        actor,
        role_grants,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_credential(credential: ResolvedCredential) -> ResolvedAuth {
        ResolvedAuth {
            account: AccountRow {
                id: uuid::Uuid::nil(),
                username: "account".to_owned(),
            },
            credential,
            credential_deadline: None,
        }
    }

    fn narrowed() -> TokenScope {
        TokenScope::Methods(std::iter::once("thing_list".to_owned()).collect())
    }

    #[test]
    fn each_credential_answers_its_own_type_scope_and_keys() {
        let session = with_credential(ResolvedCredential::Session {
            session_hash: "hash_1".to_owned(),
        });
        let api_token = with_credential(ResolvedCredential::ApiToken {
            api_token_id: "tok_1".to_owned(),
            scope: narrowed(),
        });
        let daemon_token = with_credential(ResolvedCredential::DaemonToken);

        assert_eq!(session.credential_type(), CredentialType::Session);
        assert_eq!(api_token.credential_type(), CredentialType::ApiToken);
        assert_eq!(daemon_token.credential_type(), CredentialType::DaemonToken);

        assert_eq!(session.scope(), &TokenScope::Full);
        assert_eq!(api_token.scope(), &narrowed());
        assert_eq!(daemon_token.scope(), &TokenScope::Full);

        assert_eq!(session.session_hash(), Some("hash_1"));
        assert_eq!(api_token.session_hash(), None);
        assert_eq!(daemon_token.session_hash(), None);

        assert_eq!(session.api_token_id(), None);
        assert_eq!(api_token.api_token_id(), Some("tok_1"));
        assert_eq!(daemon_token.api_token_id(), None);
    }

    #[test]
    fn a_full_scope_api_token_answers_full() {
        let api_token = with_credential(ResolvedCredential::ApiToken {
            api_token_id: "tok_1".to_owned(),
            scope: TokenScope::Full,
        });
        assert_eq!(api_token.scope(), &TokenScope::Full);
    }

    #[test]
    fn debug_redacts_the_session_hash() {
        let session = with_credential(ResolvedCredential::Session {
            session_hash: "secret_session_hash".to_owned(),
        });
        let printed = format!("{session:?}");
        assert!(
            !printed.contains("secret_session_hash"),
            "the session hash leaked: {printed}"
        );
        assert!(printed.contains(r#"session_hash: "<set>""#), "{printed}");
        let printed = format!("{:?}", session.credential);
        assert!(!printed.contains("secret_session_hash"), "{printed}");

        // the token id is public and prints whole
        let api_token = with_credential(ResolvedCredential::ApiToken {
            api_token_id: "tok_1".to_owned(),
            scope: TokenScope::Full,
        });
        assert!(format!("{api_token:?}").contains("tok_1"));
    }
}
