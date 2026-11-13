//! Shared context for authenticated action handlers.
//!
//! The account / admin / role-grant-offer surfaces all run their
//! handlers with the same set of capabilities: a resolved actor +
//! account, the credential type that authenticated the request, an
//! audit emitter, a connection closer for cascade closes, and the
//! caller's client IP. This module supplies the one canonical struct;
//! each `*_action_specs` module uses it directly rather than
//! redeclaring a same-shape local type.
//!
//! Constructed by the `fuz_actions::auth_adapter` from the
//! `fuz_actions` `ActionContext` at dispatch time. Future surfaces
//! (e.g. `role_grant_revoke` + lifecycle methods) drop in
//! on the same shape.

use std::sync::Arc;

use crate::audit_emitter::{AuditEmitter, AuditLogInput, AuditPostCommit};
use crate::connection_closer::{ConnectionCloseTarget, ConnectionCloser, queue_connection_close};
use crate::credential_type::CredentialType;
use crate::notification_sender::NotificationSender;
use crate::request_context::{RequestActorContext, RequestContext};
use fuz_http::JsonrpcError;

/// Borrowed-refs context handed to every authenticated action handler.
///
/// Fields:
/// - `auth` — resolved actor + account + role grants (the dispatcher
///   guarantees this exists before invoking the handler).
/// - `credential_type` — which credential class authenticated the
///   request (cookie, daemon token, bearer); `None` only when the
///   credential type wasn't surfaced upstream.
/// - `audit` — emitter for forensic-trail rows. Use [`Self::audit_emit`]
///   for routing-aware emits (pool vs in-tx looked up from
///   [`crate::AUDIT_EVENT_SPECS`]) or reach `audit.emit` directly for
///   unconditional pool routing.
/// - `post_commit` — hook the dispatcher's post-commit drain queue
///   implements; [`Self::audit_emit`] uses it when the event's routing
///   is `AuditRouting::InTx` to defer listener fan-out until after
///   the request transaction commits.
/// - `connection_closer` — capability to close all connections bound to a
///   target account (used by admin revoke-all and offer-supersede
///   cascades). In-transaction handlers close through
///   [`AuthenticatedActionContext::close_connections_after_commit`], never
///   inline.
/// - `notification_sender` — capability to push a server-initiated
///   JSON-RPC notification to all sockets bound to a target account
///   (role-grant-offer lifecycle inbox pushes). Used via the
///   post-commit drain, not inline. `Noop` for WS-less consumers.
/// - `client_ip` — caller IP if upstream resolved one; `None`
///   otherwise. Carried into audit rows; gating decisions that
///   require it must check for `None` explicitly.
#[expect(
    missing_debug_implementations,
    reason = "borrowed refs and Arcs; no useful `Debug` shape"
)]
pub struct AuthenticatedActionContext<'a> {
    pub auth: &'a RequestActorContext,
    pub credential_type: Option<CredentialType>,
    pub audit: &'a Arc<AuditEmitter>,
    pub post_commit: &'a dyn AuditPostCommit,
    pub connection_closer: &'a Arc<dyn ConnectionCloser>,
    pub notification_sender: &'a Arc<dyn NotificationSender>,
    pub client_ip: Option<String>,
}

impl AuthenticatedActionContext<'_> {
    /// Routing-aware audit emit — the recommended handler-facing API.
    ///
    /// Thin wrapper over [`route_audit_emit`](crate::route_audit_emit): looks up
    /// `input.event_type`'s routing and either spawns a rollback-surviving pool
    /// write or INSERTs in-tx and defers listener fan-out to `post_commit`. See
    /// that function for the full routing contract.
    ///
    /// # Errors
    ///
    /// Pool routing returns `Ok(())`; in-tx routing surfaces a [`JsonrpcError`]
    /// on INSERT failure — propagate via `?` to roll the audit row back with the
    /// handler's state.
    pub async fn audit_emit<C>(&self, db: &C, input: AuditLogInput) -> Result<(), JsonrpcError>
    where
        C: deadpool_postgres::GenericClient + ?Sized,
    {
        crate::route_audit_emit(self.audit, self.post_commit, db, input).await
    }

    /// Close the `target` sockets once the request transaction commits —
    /// the close every in-transaction revocation uses (see
    /// [`queue_connection_close`]).
    pub fn close_connections_after_commit(&self, target: ConnectionCloseTarget) {
        queue_connection_close(self.post_commit, self.connection_closer, target);
    }
}

/// Borrowed-refs context handed to every **account-grain** action handler.
///
/// The account-grain twin of [`AuthenticatedActionContext`]: an identical
/// capability set, but `auth` is the account-only [`RequestContext`] (no
/// resolved actor / role grants). Handed to the `account_*` self-service,
/// `actor_lookup`, and `actor_search` families — all declared `actor: None`,
/// so the dispatcher never resolves a persona for them. Built by the
/// `fuz_actions::auth_adapter` account-grain bridge from the `Account` variant
/// of [`crate::ResolvedAuthContext`]. The handler bodies are identical to the
/// actor-bound shape — they only read `auth.account` — so the two contexts
/// stay structurally parallel.
#[expect(
    missing_debug_implementations,
    reason = "borrowed refs and Arcs; no useful `Debug` shape"
)]
pub struct AccountActionContext<'a> {
    pub auth: &'a RequestContext,
    pub credential_type: Option<CredentialType>,
    /// blake3 hash of the session token the request authenticated with — the
    /// `auth_session.id` `account_session_list` marks `is_current`. `None` for
    /// a bearer or daemon-token credential.
    pub session_hash: Option<&'a str>,
    pub audit: &'a Arc<AuditEmitter>,
    pub post_commit: &'a dyn AuditPostCommit,
    pub connection_closer: &'a Arc<dyn ConnectionCloser>,
    pub notification_sender: &'a Arc<dyn NotificationSender>,
    pub client_ip: Option<String>,
}

impl AccountActionContext<'_> {
    /// Routing-aware audit emit — the recommended handler-facing API. Identical
    /// contract to [`AuthenticatedActionContext::audit_emit`].
    ///
    /// # Errors
    ///
    /// Pool routing returns `Ok(())`; in-tx routing surfaces a [`JsonrpcError`]
    /// on INSERT failure — propagate via `?` to roll the audit row back with the
    /// handler's state.
    pub async fn audit_emit<C>(&self, db: &C, input: AuditLogInput) -> Result<(), JsonrpcError>
    where
        C: deadpool_postgres::GenericClient + ?Sized,
    {
        crate::route_audit_emit(self.audit, self.post_commit, db, input).await
    }

    /// Close the `target` sockets once the request transaction commits.
    /// Identical contract to
    /// [`AuthenticatedActionContext::close_connections_after_commit`].
    pub fn close_connections_after_commit(&self, target: ConnectionCloseTarget) {
        queue_connection_close(self.post_commit, self.connection_closer, target);
    }
}
