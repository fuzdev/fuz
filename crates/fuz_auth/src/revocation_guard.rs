//! Default audit-event → live-connection revocation guard (WebSocket, and
//! SSE through a fan-out closer).
//!
//! Every spine consumer that runs a WS endpoint needs the same
//! translation: when an auth-state-mutating audit row lands, close the
//! matching live sockets. [`register_revocation_guard`] wires
//! that onto an [`AuditEmitter`] so consumers (the spine servers and
//! `testing_spine_stub`) call one function instead of hand-rolling the
//! closures.
//!
//! Mirrors `fuz_app`'s `create_revocation_guard`, which closes through a
//! `ConnectionCloser` and dispatches on the same `RevocationScope` table.
//!
//! ## Which rows close, and why it isn't a list here
//!
//! The disposition is declared once per event, as
//! [`AuditEventSpec::revocation_scope`](crate::AuditEventSpec), and this
//! listener matches that enum **wildcard-free**
//! ([`ConnectionCloseTarget::from_audit_event`]). The alternative is a
//! hand-written `&str` list against wire literals, and a list kept per
//! transport drifts: `token_revoke` in one and missing from another means
//! revoking an API token closes its socket and leaves its audit stream open.
//! No such list is anything the compiler can see — which is also why there is
//! one listener, closing every transport through the closer it is handed.
//!
//! ## `Role` closes the role-gated sockets
//!
//! [`RevocationScope::Role`] closes the target account's connections whose
//! endpoint gated them on the revoked role ([`ConnectionCloseTarget::Role`]) —
//! when the revoked grant was global: a role gate admits on global grants
//! only, so a scoped revoke took away nothing it admitted on.
//! `perform_action` re-authorizes every *request* against its own action, but
//! the role gate is the only check on what a connection *receives*:
//! broadcasts, notifications, and the audit stream's rows reach every
//! admitted connection of the endpoint with no per-recipient filter, so one
//! left open past the revocation would keep receiving what the gate exists to
//! withhold. No handler closes for a role, so this listener is its only
//! closer — through the closer it is handed, which for a consumer with both
//! transports is the `RealtimeCloser` fan-out reaching the audit streams too.
//!
//! ## Failure-outcome rows never close sockets
//!
//! A `Failure`-outcome row carries caller-submitted metadata (e.g. a
//! failed `session_revoke` records the attacker-supplied `session_id`),
//! so reacting to it would let an authenticated user disconnect another
//! user by guessing a session hash. Only `success` rows drive
//! revocation.

use std::sync::Arc;

use serde_json::Value;

use crate::audit_emitter::AuditEmitter;
use crate::audit_event_type::{RevocationScope, revocation_scope_for_wire};
use crate::connection_closer::{ConnectionCloseTarget, ConnectionCloser};

/// Extract a string field from the row's `metadata` object.
fn metadata_str<'a>(event: &'a crate::AuditLogEvent, key: &str) -> Option<&'a str> {
    event
        .metadata
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|m| m.get(key))
        .and_then(Value::as_str)
}

impl ConnectionCloseTarget {
    /// The connections a revocation row closes, dispatched on the
    /// [`RevocationScope`] its event declares — `None` when it closes nothing:
    ///
    /// - a row whose outcome is not `success` (module doc);
    /// - [`RevocationScope::None`], every event that revokes nothing;
    /// - a row missing the key its scope closes by (an empty string included);
    /// - a [`RevocationScope::Role`] row whose revoked grant was scoped.
    ///
    /// Otherwise:
    ///
    /// - [`Session`](RevocationScope::Session) → [`Self::Session`] of
    ///   `metadata.session_id`
    /// - [`Token`](RevocationScope::Token) → [`Self::Token`] of
    ///   `metadata.token_id`
    /// - [`Account`](RevocationScope::Account) → [`Self::Account`] of
    ///   `target_account_id ?? account_id`
    /// - [`Role`](RevocationScope::Role) → [`Self::Role`] of
    ///   `target_account_id ?? account_id` and a non-empty `metadata.role`,
    ///   when the revoked grant was global. A row with no
    ///   `metadata.scope_id`, or a null one, reads as global: when unsure,
    ///   closing is the safe side.
    ///
    /// Twin of `fuz_app`'s `create_revocation_guard` dispatch (with its
    /// `to_global_role_revocation` for the role arm).
    #[must_use]
    pub fn from_audit_event(event: &crate::AuditLogEvent) -> Option<Self> {
        if event.outcome != "success" {
            return None;
        }
        match revocation_scope_for_wire(&event.event_type) {
            RevocationScope::None => None,
            RevocationScope::Session => metadata_str(event, "session_id")
                .filter(|id| !id.is_empty())
                .map(|id| Self::Session(id.to_owned())),
            RevocationScope::Token => metadata_str(event, "token_id")
                .filter(|id| !id.is_empty())
                .map(|id| Self::Token(id.to_owned())),
            RevocationScope::Account => event
                .target_account_id
                .or(event.account_id)
                .map(Self::Account),
            RevocationScope::Role => {
                let role = metadata_str(event, "role").filter(|role| !role.is_empty())?;
                let scoped = event
                    .metadata
                    .as_ref()
                    .and_then(Value::as_object)
                    .and_then(|m| m.get("scope_id"))
                    .is_some_and(|scope_id| !scope_id.is_null());
                if scoped {
                    return None;
                }
                let account_id = event.target_account_id.or(event.account_id)?;
                Some(Self::Role {
                    account_id,
                    role: role.to_owned(),
                })
            }
        }
    }
}

/// Register the standard auth-event → connection-revocation guard on
/// `emitter`: each row [`ConnectionCloseTarget::from_audit_event`] reads a target
/// from closes it on `closer`.
///
/// The listener body is sync (no `.await`) wrapped in `Box::pin(async {
/// … })` to satisfy the emitter's boxed-future listener signature.
pub fn register_revocation_guard(emitter: &AuditEmitter, closer: &Arc<dyn ConnectionCloser>) {
    let closer = Arc::clone(closer);
    emitter.add_listener(Arc::new(move |event| {
        let closer = Arc::clone(&closer);
        Box::pin(async move {
            let Some(target) = ConnectionCloseTarget::from_audit_event(&event) else {
                return;
            };
            let closed = closer.close_connections(&target);
            if closed > 0 {
                tracing::info!(
                    count = closed,
                    event_type = %event.event_type,
                    "audit listener: closed connection(s)"
                );
            }
        })
    }));
}
