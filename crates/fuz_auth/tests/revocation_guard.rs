//! Dispatch coverage for the revocation guard
//! ([`fuz_auth::register_revocation_guard`]) — the WS half of the
//! pair that dispatches on one shared declaration.
//!
//! What these pin is the mapping from an audit row to a `ConnectionCloser` call:
//! the `RevocationScope`s the listener acts on — `Role` for a global grant
//! only — the `success`-only rule, and the consumer-custom-event default. The listener reads its dispatch from
//! `AUDIT_EVENT_SPECS`, so a variant losing its scope fails in
//! `audit_event_type`'s own table test; what a *table* test cannot see is
//! whether this listener still calls the method that scope names, which is
//! the half that goes silently wrong.
//!
//! No database: `AuditEmitter::notify` fans a row to the listener chain
//! without touching the pool, so the pool here is a never-connected handle.
//!
//! ## `role_grant_revoke` closes by role, global grants only
//!
//! A role gate admits on global grants only, so a revoked global grant closes
//! the target account's sockets gated on the role (`ConnectionCloseTarget::Role`)
//! and a scoped one closes nothing. The one listener reaches the role-gated
//! audit streams the same way, through the closer it is handed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use fuz_auth::{
    AuditEmitter, AuditLogEvent, ConnectionCloseTarget, ConnectionCloser, register_revocation_guard,
};
use parking_lot::Mutex;
use serde_json::json;
use uuid::Uuid;

/// One recorded `ConnectionCloser` call.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Closed {
    Session(String),
    Token(String),
    Account(Uuid),
    Role(Uuid, String),
}

/// Records what the listener asked for instead of closing anything. Counting
/// closes on a real registry would conflate "the listener called the right
/// method" with "the registry matched a subscriber" — this suite is about the
/// first.
#[derive(Debug, Default)]
struct RecordingCloser {
    calls: Mutex<Vec<Closed>>,
}

impl RecordingCloser {
    fn calls(&self) -> Vec<Closed> {
        self.calls.lock().clone()
    }
}

impl fuz_http::ShutdownCloser for RecordingCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for RecordingCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        self.calls.lock().push(match target.clone() {
            ConnectionCloseTarget::Session(hash) => Closed::Session(hash),
            ConnectionCloseTarget::Token(id) => Closed::Token(id),
            ConnectionCloseTarget::Account(id) => Closed::Account(id),
            ConnectionCloseTarget::Role { account_id, role } => Closed::Role(account_id, role),
        });
        1
    }
}

/// An emitter over a pool that is never connected — `notify` fans to the
/// listener chain directly and touches neither.
fn emitter() -> Arc<AuditEmitter> {
    let pool = fuz_db::create_pool(
        "postgres://unused@127.0.0.1:1/unused",
        &fuz_db::PoolOptions::default(),
    )
    .expect("lazy pool");
    Arc::new(AuditEmitter::new(pool))
}

fn event(
    event_type: &str,
    outcome: &str,
    account_id: Option<Uuid>,
    metadata: Option<serde_json::Value>,
) -> Arc<AuditLogEvent> {
    Arc::new(AuditLogEvent {
        id: Uuid::new_v4(),
        seq: 1,
        event_type: event_type.to_owned(),
        outcome: outcome.to_owned(),
        actor_id: None,
        account_id,
        target_account_id: None,
        target_actor_id: None,
        ip: None,
        created_at: "2026-01-01T00:00:00Z".to_owned(),
        metadata,
    })
}

/// Register the listener and fan one row through it; returns what it asked to
/// close.
async fn dispatch(event: Arc<AuditLogEvent>) -> Vec<Closed> {
    let emitter = emitter();
    let recorder = Arc::new(RecordingCloser::default());
    // via a concrete temporary: `Arc::clone` infers its type parameter from
    // the annotation, so cloning straight into the `dyn` binding asks for a
    // clone of an `Arc<dyn ConnectionCloser>` we don't have. The unsize coercion
    // happens on the assignment.
    let cloned = Arc::clone(&recorder);
    let closer: Arc<dyn ConnectionCloser> = cloned;
    register_revocation_guard(&emitter, &closer);
    emitter.notify(event).await;
    recorder.calls()
}

#[tokio::test]
async fn session_revoke_closes_the_named_session() {
    let calls = dispatch(event(
        "session_revoke",
        "success",
        Some(Uuid::new_v4()),
        Some(json!({"session_id": "hash_a"})),
    ))
    .await;
    assert_eq!(calls, vec![Closed::Session("hash_a".to_owned())]);
}

/// The arm whose SSE twin was missing. Kept as a WS-side pin so a future
/// convergence pass can't "align" the two halves by deleting this one.
#[tokio::test]
async fn token_revoke_closes_the_named_token() {
    let calls = dispatch(event(
        "token_revoke",
        "success",
        Some(Uuid::new_v4()),
        Some(json!({"token_id": "tok_abc"})),
    ))
    .await;
    assert_eq!(calls, vec![Closed::Token("tok_abc".to_owned())]);
}

#[tokio::test]
async fn account_wide_events_close_the_whole_account() {
    for event_type in [
        "session_revoke_all",
        "token_revoke_all",
        "password_change",
        "logout",
        // `account_delete` also queues the close from its handler; the event is
        // declared `Account` regardless, and the redundant close is a no-op.
        "account_delete",
        "account_purge",
    ] {
        let account = Uuid::new_v4();
        let calls = dispatch(event(event_type, "success", Some(account), None)).await;
        assert_eq!(
            calls,
            vec![Closed::Account(account)],
            "{event_type} should close the account's sockets"
        );
    }
}

/// An admin's revoke of a global grant closes the target account's sockets
/// gated on the role — the target, not the admin who revoked it.
#[tokio::test]
async fn a_global_role_grant_revoke_closes_the_targets_gated_sockets() {
    let admin = Uuid::new_v4();
    let target = Uuid::new_v4();
    let mut row = event(
        "role_grant_revoke",
        "success",
        Some(admin),
        Some(json!({"role": "admin", "role_grant_id": Uuid::new_v4(), "scope_id": null})),
    );
    Arc::get_mut(&mut row).unwrap().target_account_id = Some(target);
    let calls = dispatch(row).await;
    assert_eq!(calls, vec![Closed::Role(target, "admin".to_owned())]);
}

/// A self-service revoke carries no target column distinct from the actor's,
/// and no `scope_id` key at all reads as global.
#[tokio::test]
async fn a_role_revoke_with_no_scope_id_reads_as_global() {
    let account = Uuid::new_v4();
    let calls = dispatch(event(
        "role_grant_revoke",
        "success",
        Some(account),
        Some(json!({"role": "admin", "self_service": true})),
    ))
    .await;
    assert_eq!(calls, vec![Closed::Role(account, "admin".to_owned())]);
}

/// A role gate admits on global grants only, so revoking a scoped grant takes
/// nothing away from a gated socket.
#[tokio::test]
async fn a_scoped_role_grant_revoke_closes_nothing() {
    let calls = dispatch(event(
        "role_grant_revoke",
        "success",
        Some(Uuid::new_v4()),
        Some(json!({"role": "participant", "scope_id": Uuid::new_v4()})),
    ))
    .await;
    assert!(calls.is_empty(), "a scoped revoke closed {calls:?}");
}

/// A role row that names no role has nothing to close by.
#[tokio::test]
async fn a_role_revoke_without_its_role_closes_nothing() {
    let calls = dispatch(event(
        "role_grant_revoke",
        "success",
        Some(Uuid::new_v4()),
        Some(json!({"role_grant_id": Uuid::new_v4()})),
    ))
    .await;
    assert!(calls.is_empty(), "{calls:?}");
}

/// Failure rows carry caller-submitted metadata, so reacting to one would let
/// a caller disconnect another by guessing an id.
#[tokio::test]
async fn failure_rows_close_nothing() {
    for (event_type, metadata) in [
        ("session_revoke", json!({"session_id": "hash_a"})),
        ("token_revoke", json!({"token_id": "tok_abc"})),
        ("session_revoke_all", json!({})),
        ("role_grant_revoke", json!({"role": "admin"})),
    ] {
        let calls = dispatch(event(
            event_type,
            "failure",
            Some(Uuid::new_v4()),
            Some(metadata),
        ))
        .await;
        assert!(
            calls.is_empty(),
            "{event_type} failure row must close nothing: {calls:?}"
        );
    }
}

/// A consumer's own event name resolves to `RevocationScope::None` rather than
/// falling through to some default close.
#[tokio::test]
async fn non_revoking_and_custom_events_close_nothing() {
    for event_type in [
        "login",
        "token_create",
        "cell_update",
        "fuz_forge_repo_updated",
    ] {
        let calls = dispatch(event(
            event_type,
            "success",
            Some(Uuid::new_v4()),
            Some(json!({"session_id": "hash_a", "token_id": "tok_abc", "role": "admin"})),
        ))
        .await;
        assert!(
            calls.is_empty(),
            "{event_type} must close nothing even with revocation-shaped metadata: {calls:?}"
        );
    }
}

/// An empty id names no connection — the twin of `fuz_app`'s
/// `to_connection_close_target`, which refuses one too.
#[tokio::test]
async fn a_scoped_row_with_an_empty_id_closes_nothing() {
    for (event_type, metadata) in [
        ("session_revoke", json!({"session_id": ""})),
        ("token_revoke", json!({"token_id": ""})),
    ] {
        let calls = dispatch(event(
            event_type,
            "success",
            Some(Uuid::new_v4()),
            Some(metadata),
        ))
        .await;
        assert!(
            calls.is_empty(),
            "{event_type} with an empty id must close nothing: {calls:?}"
        );
    }
}

/// A scoped row whose metadata is missing the id it needs closes nothing —
/// never falling back to the coarser account-wide close.
#[tokio::test]
async fn a_scoped_row_without_its_id_closes_nothing() {
    for event_type in ["session_revoke", "token_revoke"] {
        let calls = dispatch(event(event_type, "success", Some(Uuid::new_v4()), None)).await;
        assert!(
            calls.is_empty(),
            "{event_type} without metadata must not widen to an account close: {calls:?}"
        );
    }
}
