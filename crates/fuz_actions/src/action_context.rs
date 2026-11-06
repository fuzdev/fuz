//! Per-action [`ActionContext`] handed to handler closures.
//!
//! A borrow-only field set rather than a handle to the consumer's app
//! struct, so a handler sees only the capabilities it needs.
//!
//! ## Field shape
//!
//! - `db` — the request's [`fuz_db::ActionDb`]. **The transaction for
//!   `side_effects: true` actions**, a pooled client for read-only ones. A
//!   handler reaches the concrete client with [`fuz_db::action_db_dispatch!`]
//!   and composes generic query functions from `fuz_auth` / `fuz_db` over it.
//! - `auth` — the [`fuz_auth::ResolvedAuthContext`] built by the dispatcher's
//!   authorization phase: anonymous / account-grain / actor-bound. Public and
//!   unauthenticated-optional callers see `Anonymous`; `actor: Required`
//!   handlers match `Actor`.
//! - `credential_type` — `Session` / `ApiToken` / `DaemonToken`.
//!   Required on every credential-gated audit emit for the
//!   `metadata.credential_type` contract (see `fuz_auth`
//!   `audit_emitter.credential_type_value`).
//! - `request_id` — borrowed from the parsed envelope. Mirrors TS
//!   `ctx.request_id`.
//! - `connection_id` — `Some(id)` on WS; `None` on HTTP. Used by
//!   handlers that target the originating socket directly (e.g.
//!   `completion_create` SSE streaming → originating WS).
//! - `post_commit_effects` — non-DB side-channels (audit listener fan-out,
//!   WS broadcasts). Drained post-commit by [`fn@crate::perform_action`].
//! - `client_ip` — resolved client IP from `fuz_http::client_ip_middleware`.
//!   Plumbed onto every `AuditLogInput.ip` emit site.
//! - `log` — borrowed `&tracing::Span` so handlers can attach fields
//!   without owning a span clone. The dispatchers (`rpc_dispatch.rs`,
//!   `ws_dispatch.rs`) pass `tracing::Span::current()`, mirroring TS
//!   `ctx.log`.
//! - `notify` — **borrowed `&dyn Fn(&str, &Value)`**. HTTP passes
//!   `&fuz_realtime::http_no_op_notify` (zero alloc, zero
//!   capture); WS passes a borrow of the per-socket closure built once
//!   via [`fuz_realtime::ws_notify_for_connection`].
//! - `signal` — `fuz_realtime::SignalToken` (alias of
//!   `tokio_util::sync::CancellationToken`). Per-socket on WS, fresh
//!   per-request on HTTP.
//! - `audit` — borrowed `&Arc<AuditEmitter>` for pool-routed
//!   fire-and-forget emits (`ctx.audit.emit(input)`). For routing-
//!   aware emits that pick pool-vs-in-tx based on the event's
//!   [`fuz_auth::AUDIT_EVENT_SPECS`] row, the action-spec layer's
//!   `AuthenticatedActionContext::audit_emit` does the lookup; this
//!   field is the underlying emitter both paths funnel through.
//! - `post_commit` — `&PostCommitEffects` exposed via the
//!   [`fuz_auth::AuditPostCommit`] trait so in-tx audit emits can
//!   queue listener fan-out for the post-commit drain.
//!
//! ## No `&mut ActionContext`
//!
//! `post_commit_effects` lives behind an internal mutex so handlers see
//! `&ActionContext` everywhere. Mirrors `fuz_app`'s TS shape.

use std::sync::Arc;

use fuz_auth::{AuditEmitter, AuditLogInput, CredentialType, ResolvedAuthContext};
use fuz_db::ActionDb;
use fuz_http::JsonrpcError;
use fuz_realtime::{ActionPeer, DEFAULT_PEER_REQUEST_TIMEOUT, PeerError, SignalToken};
use serde_json::Value;
use tracing::Span;

use crate::post_commit_effects::PostCommitEffects;

/// Per-action handler context.
///
/// Lifetime `'a` keeps every reference borrowed from the request frame
/// — no per-action `Arc` allocations, no clones of large auth state.
pub struct ActionContext<'a> {
    /// The request's database handle — the transaction or a pooled client;
    /// see [`ActionDb`].
    pub db: ActionDb<'a>,
    /// Resolved auth context, built by [`fn@crate::perform_action`]'s
    /// authorization phase. One of anonymous / account-grain / actor-bound —
    /// `actor: Required` handlers match `ResolvedAuthContext::Actor`; identity-
    /// aware reads call [`ResolvedAuthContext::actor`] for the optional actor.
    pub auth: ResolvedAuthContext<'a>,
    /// How the request was authenticated. `None` on anonymous public
    /// callers.
    pub credential_type: Option<CredentialType>,
    /// blake3 hash of the session token the request authenticated with — the
    /// `auth_session.id` of the caller's own session. `None` for a bearer or
    /// daemon-token credential and on anonymous callers.
    pub session_hash: Option<&'a str>,
    /// JSON-RPC request id (borrowed from the parsed envelope). Some
    /// handlers (ping) echo it back; others log it.
    pub request_id: &'a Value,
    /// WS connection id when the request arrived over WS; `None` on HTTP.
    /// Handlers targeting the originating socket (e.g. streaming
    /// completion) check this to detect transport.
    pub connection_id: Option<fuz_realtime::ConnectionId>,
    /// Resolved client IP from `fuz_http::client_ip_middleware`.
    pub client_ip: Option<String>,
    /// Request-scoped tracing span. Handlers attach fields via
    /// `ctx.log.record(...)`.
    pub log: &'a Span,
    /// Borrowed notify closure — `&dyn Fn(&str, &Value)`.
    /// HTTP: `&fuz_realtime::http_no_op_notify`. WS: borrow of the
    /// per-socket closure.
    pub notify: &'a (dyn Fn(&str, &Value) + Send + Sync),
    /// Per-request cancellation token. WS: per-socket (cancelled on
    /// disconnect). HTTP: fresh per-request.
    pub signal: &'a SignalToken,
    /// Effects queued for post-commit drain (audit listener fan-out,
    /// WS broadcasts, log lines).
    pub post_commit_effects: &'a PostCommitEffects,
    /// Shared audit emitter for pool-routed fire-and-forget emits
    /// (`ctx.audit.emit(input)`). For routing-aware emits, action-spec
    /// handlers receive the same emitter via
    /// [`fuz_auth::AuthenticatedActionContext::audit_emit`] which
    /// looks up [`fuz_auth::AUDIT_EVENT_SPECS`] and dispatches to
    /// pool or in-tx routing per the event's spec.
    pub audit: &'a Arc<AuditEmitter>,
    /// Capability to push a server-initiated JSON-RPC notification to
    /// all sockets bound to a target account (role-grant-offer inbox
    /// pushes). The `auth_adapter` forwards this onto
    /// [`fuz_auth::AuthenticatedActionContext`]. `Noop` for WS-less
    /// consumers. Used via the post-commit drain, not inline.
    pub notification_sender: &'a Arc<dyn fuz_auth::NotificationSender>,
    /// Capability to **initiate** a JSON-RPC request to a connected
    /// client and await its typed reply (server→client request/response).
    /// Threaded exactly as [`Self::notification_sender`]: the registry-backed
    /// [`fuz_realtime::ConnectionPeer`] on WS, [`fuz_realtime::NoopActionPeer`]
    /// (→ [`PeerError::NoTransport`]) on HTTP. Use [`Self::request_client`]
    /// for the common originating-socket case.
    pub peer: &'a dyn ActionPeer,
}

impl ActionContext<'_> {
    /// Routing-aware audit emit — the handler-facing API for action
    /// contexts that aren't behind the `auth_adapter`'s
    /// [`fuz_auth::AuthenticatedActionContext`] (e.g. `fuz_cell`, which
    /// builds its specs directly on `fuz_actions`).
    ///
    /// Thin wrapper over [`fuz_auth::route_audit_emit`], passing this context's
    /// `post_commit_effects` as the post-commit queue. See that function for the
    /// full routing contract (pool vs in-tx, looked up from the per-event table).
    ///
    /// # Errors
    ///
    /// Pool routing always returns `Ok(())`. In-tx routing surfaces a
    /// [`JsonrpcError`] on INSERT failure — propagate via `?` so the
    /// handler rolls the audit row back together with the state.
    pub async fn audit_emit<C>(&self, db: &C, input: AuditLogInput) -> Result<(), JsonrpcError>
    where
        C: deadpool_postgres::GenericClient + ?Sized,
    {
        fuz_auth::route_audit_emit(self.audit, self.post_commit_effects, db, input).await
    }

    /// Initiate a JSON-RPC request to the **originating** socket and await
    /// its reply (server→client request/response over WS).
    ///
    /// Returns [`PeerError::NoTransport`] when there's no originating
    /// socket — i.e. on HTTP ([`Self::connection_id`] is `None`) or any
    /// WS-less consumer. Otherwise delegates to [`Self::peer`] with
    /// [`DEFAULT_PEER_REQUEST_TIMEOUT`]. The reply is the raw JSON-RPC `result`;
    /// callers that expect a typed shape (e.g. `peer/ping`) **must**
    /// validate it before use, so a malformed/wrong-shape reply becomes an
    /// error rather than untyped data handed downstream.
    ///
    /// **Never call this inside the `side_effects` transaction window.**
    /// Awaiting an untrusted/slow client while holding an open DB
    /// transaction (and its pooled connection) is a pool-exhaustion +
    /// lock-holding `DoS` — elicit *before* the tx opens or *after* it
    /// commits. (Not statically enforced in v1.)
    ///
    /// The hazard is broader than the tx: a **read-only** handler still holds
    /// the dispatcher's pooled checkout for its whole body (`dispatch_pooled`
    /// acquires it before the handler runs), so awaiting an untrusted client
    /// here parks that connection even with no open tx. Until the dispatcher
    /// acquires the pool client lazily (a codegen-era change), keep the
    /// deadline **bounded** — `peer/ping` clamps its client-supplied
    /// `timeout_ms` to a server default so the hold can't be stretched.
    ///
    /// # Errors
    ///
    /// [`PeerError`] — `NoTransport` / `Timeout` / `ConnectionGone` /
    /// `ClientError` / `TooManyInFlight`.
    pub async fn request_client(&self, method: &str, params: &Value) -> Result<Value, PeerError> {
        let conn = self.connection_id.ok_or(PeerError::NoTransport)?;
        self.peer
            .request(conn, method, params, DEFAULT_PEER_REQUEST_TIMEOUT)
            .await
    }
}

impl std::fmt::Debug for ActionContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionContext")
            .field("auth", &self.auth.account().map(|a| a.id))
            .field("credential_type", &self.credential_type)
            .field("request_id", &self.request_id)
            .field("connection_id", &self.connection_id)
            .field("client_ip", &self.client_ip)
            .field("signal_cancelled", &self.signal.is_cancelled())
            .field("post_commit_effects", &self.post_commit_effects)
            .finish_non_exhaustive()
    }
}
