//! Close-on-revoke coverage for the audit stream: the one revocation
//! listener (`fuz_auth::register_revocation_guard`) closing streams
//! through the [`fuz_realtime::SseRegistry`] it is handed, beside the audit
//! fan-out listener ([`fuz_realtime::register_audit_sse_listener`]), which
//! only broadcasts.
//!
//! **The gap these close.** Two transports keeping separate hand-maintained
//! `&str` lists of the events that revoke can drift: with `token_revoke` in
//! the WS list and missing from the stream's, `account_token_revoke` closes a
//! revoked API token's socket while its `GET /api/admin/audit/stream`
//! subscription keeps running — the holder of a killed credential goes on
//! receiving every audit row on the instance, including other accounts'
//! `login` / `password_change` / `session_revoke` metadata. One listener
//! dispatches on the `RevocationScope` each event declares in `fuz_auth`'s
//! `AUDIT_EVENT_SPECS`, and closes every transport through one closer.
//!
//! Registry-level, not route-level: these drive the listeners with a
//! constructed audit row, so they hold whether or not a given mount lets a
//! bearer open a stream at all (the default one does not — see
//! `tests/audit_stream.rs`). No database — `AuditEmitter::notify` fans to the
//! listener chain without touching the pool.
//!
//! The route-level companions (credential gate, cookie-session regression
//! guard, and the end-to-end bearer-stream-closes-on-revoke loop) are the
//! `#[ignore]` Postgres suite in `tests/audit_stream.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures::stream::Stream;
use fuz_auth::{AuditEmitter, AuditLogEvent, ConnectionCloser, register_revocation_guard};
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::{SseRegistry, SseSubscription, register_audit_sse_listener};
use serde_json::json;
use uuid::Uuid;

mod common;

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

/// How long a close is allowed to take before the test calls it "never".
///
/// The listener runs synchronously inside `notify`, so a passing case ends the
/// stream before the `await` returns and never spends this budget. It exists so
/// a *broken* listener fails the suite instead of hanging it: an unbounded
/// `while stream.next().await.is_some() {}` on a stream nothing ever closes
/// blocks forever, which turns a caught regression into a stuck CI job.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Drain `stream` to completion, asserting it actually completes.
///
/// Completion is the observable that matters: dropping the subscriber's sender
/// is what ends the response body, and a client sees the close only as its
/// stream ending. Checking `registry.count()` alone would pass on a registry
/// that forgot the subscriber while leaving the body open.
async fn assert_stream_closes(
    mut stream: impl Stream<Item = Result<String, std::convert::Infallible>> + Unpin,
    what: &str,
) {
    let drained = async { while stream.next().await.is_some() {} };
    assert!(
        tokio::time::timeout(CLOSE_TIMEOUT, drained).await.is_ok(),
        "{what}: the stream was never closed"
    );
}

/// A registry with the audit listeners wired as the spine's backend wires
/// them: the fan-out, then the one revocation listener closing through the
/// registry.
fn guarded_registry() -> (Arc<SseRegistry>, Arc<AuditEmitter>) {
    let registry = Arc::new(SseRegistry::new());
    let emitter = emitter();
    register_audit_sse_listener(&emitter, &registry);
    let closer: Arc<dyn ConnectionCloser> = Arc::<SseRegistry>::clone(&registry);
    register_revocation_guard(&emitter, &closer);
    (registry, emitter)
}

/// The fan-out listener alone closes nothing: a revocation row is broadcast
/// to the stream it revokes, and the stream stays open — closing is the
/// revocation listener's, through the closer.
#[tokio::test]
async fn the_fan_out_listener_alone_closes_nothing() {
    let registry = Arc::new(SseRegistry::new());
    let emitter = emitter();
    register_audit_sse_listener(&emitter, &registry);
    let account = Uuid::new_v4();
    let mut stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                required_roles: vec!["admin"],
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _connect = stream.next().await;

    emitter
        .notify(event("logout", "success", Some(account), None))
        .await;
    let frame = stream.next().await.expect("the row is broadcast").unwrap();
    assert!(frame.starts_with(r#"data: {"method":"logout","#), "{frame}");
    assert_eq!(registry.count(), 1, "the stream is still open");
}

/// **The gap.** A stream opened under an api token is dropped when that token
/// is revoked.
///
/// Before the shared `RevocationScope` column this row hit the listener's
/// `_ => None` arm: the frame was broadcast to the revoked token's stream and
/// nothing closed it.
#[tokio::test]
async fn token_revoke_closes_the_revoked_tokens_stream() {
    let (registry, emitter) = guarded_registry();
    let account = Uuid::new_v4();
    let mut stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                api_token_id: Some("tok_revoked".to_owned()),
                required_roles: vec!["admin"],
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    assert!(stream.next().await.is_some(), "connect comment");
    assert_eq!(registry.count(), 1);

    emitter
        .notify(event(
            "token_revoke",
            "success",
            Some(account),
            Some(json!({"token_id": "tok_revoked"})),
        ))
        .await;

    // The row fans out first (it is an audit row like any other) and the close
    // lands after, so the assertion is that the stream *ends* — not that the
    // next item is absent.
    assert_stream_closes(stream, "token_revoke").await;
    assert_eq!(
        registry.count(),
        0,
        "the revoked token's stream must be closed"
    );
}

/// Token-scoped, not account-scoped: revoking one token leaves the account's
/// other streams open, the same narrowing `session_revoke` gets.
#[tokio::test]
async fn token_revoke_spares_the_accounts_other_streams() {
    let (registry, emitter) = guarded_registry();
    let account = Uuid::new_v4();
    let mut revoked = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                api_token_id: Some("tok_revoked".to_owned()),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let mut kept = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                api_token_id: Some("tok_kept".to_owned()),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let mut cookie = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: Some("session_hash".to_owned()),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _ = revoked.next().await;
    let _ = kept.next().await;
    let _ = cookie.next().await;

    emitter
        .notify(event(
            "token_revoke",
            "success",
            Some(account),
            Some(json!({"token_id": "tok_revoked"})),
        ))
        .await;

    assert_stream_closes(revoked, "token_revoke").await;
    assert_eq!(
        registry.count(),
        2,
        "only the revoked token's stream closed"
    );
    assert_eq!(registry.broadcast("data: kept\n\n"), 2);
}

/// A `token_revoke` failure row records the caller-submitted `token_id`, so
/// acting on it would let any caller close another's stream by guessing an id.
#[tokio::test]
async fn a_failed_token_revoke_closes_nothing() {
    let (registry, emitter) = guarded_registry();
    let account = Uuid::new_v4();
    let mut stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                api_token_id: Some("tok_target".to_owned()),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _ = stream.next().await;

    emitter
        .notify(event(
            "token_revoke",
            "failure",
            Some(Uuid::new_v4()),
            Some(json!({"token_id": "tok_target"})),
        ))
        .await;

    assert_eq!(registry.count(), 1, "a failure row must not close a stream");
}

/// A stream is authorized once at open, so a revoked gating role must drop
/// it. The WS listener closes the sockets gated on the role on the same row.
#[tokio::test]
async fn role_grant_revoke_closes_the_role_gated_stream() {
    let (registry, emitter) = guarded_registry();
    let account = Uuid::new_v4();
    let mut stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: Some("session_hash".to_owned()),
                required_roles: vec!["admin"],
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _ = stream.next().await;

    emitter
        .notify(event(
            "role_grant_revoke",
            "success",
            Some(account),
            Some(json!({"role": "admin"})),
        ))
        .await;

    assert_stream_closes(stream, "role_grant_revoke").await;
    assert_eq!(registry.count(), 0, "the stream lost its gating role");
}

/// The stream's role gate admits on global grants only, so revoking a scoped
/// grant of the gating role closes nothing — and the global one then does.
#[tokio::test]
async fn a_scoped_role_grant_revoke_leaves_the_role_gated_stream_open() {
    let (registry, emitter) = guarded_registry();
    let account = Uuid::new_v4();
    let mut stream = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: Some("session_hash".to_owned()),
                required_roles: vec!["admin"],
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _ = stream.next().await;

    emitter
        .notify(event(
            "role_grant_revoke",
            "success",
            Some(account),
            Some(json!({"role": "admin", "scope_id": Uuid::new_v4()})),
        ))
        .await;
    assert_eq!(registry.count(), 1, "a scoped revoke closed the stream");

    emitter
        .notify(event(
            "role_grant_revoke",
            "success",
            Some(account),
            Some(json!({"role": "admin", "scope_id": null})),
        ))
        .await;
    assert_stream_closes(stream, "role_grant_revoke").await;
    assert_eq!(registry.count(), 0);
}

#[tokio::test]
async fn session_revoke_closes_only_the_revoked_sessions_stream() {
    let (registry, emitter) = guarded_registry();
    let account = Uuid::new_v4();
    let mut revoked = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: Some("hash_a".to_owned()),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let mut kept = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(account),
                session_hash: Some("hash_b".to_owned()),
                ..ConnectionIdentity::default()
            },
            ..SseSubscription::default()
        },
    ));
    let _ = revoked.next().await;
    let _ = kept.next().await;

    emitter
        .notify(event(
            "session_revoke",
            "success",
            Some(account),
            Some(json!({"session_id": "hash_a"})),
        ))
        .await;

    assert_stream_closes(revoked, "session_revoke").await;
    assert_eq!(registry.count(), 1);
}

/// The account-wide scope, including the two rows that reach it only through
/// the declared disposition (`account_delete` / `account_purge` — the
/// handlers close WS sockets inline but have no SSE path of their own, so
/// without it a tombstoned account's audit stream would keep running).
#[tokio::test]
async fn account_wide_events_close_every_stream_on_the_account() {
    for event_type in [
        "session_revoke_all",
        "token_revoke_all",
        "password_change",
        "logout",
        "account_delete",
        "account_purge",
    ] {
        let (registry, emitter) = guarded_registry();
        let account = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut theirs = Box::pin(common::subscribe_admitted(
            &registry,
            SseSubscription {
                identity: ConnectionIdentity {
                    account_id: Some(account),
                    session_hash: Some("hash_a".to_owned()),
                    ..ConnectionIdentity::default()
                },
                ..SseSubscription::default()
            },
        ));
        let mut bystander = Box::pin(common::subscribe_admitted(
            &registry,
            SseSubscription {
                identity: ConnectionIdentity {
                    account_id: Some(other),
                    ..ConnectionIdentity::default()
                },
                ..SseSubscription::default()
            },
        ));
        let _ = theirs.next().await;
        let _ = bystander.next().await;

        emitter
            .notify(event(event_type, "success", Some(account), None))
            .await;

        assert_stream_closes(theirs, event_type).await;
        assert_eq!(
            registry.count(),
            1,
            "{event_type} should close the account's streams and spare others"
        );
    }
}

/// A row that revokes nothing — and a consumer's own event name, which
/// resolves to `RevocationScope::None` rather than any default — must only
/// broadcast.
#[tokio::test]
async fn non_revoking_and_custom_events_only_broadcast() {
    for event_type in [
        "login",
        "token_create",
        "cell_update",
        "fuz_forge_repo_updated",
    ] {
        let (registry, emitter) = guarded_registry();
        let account = Uuid::new_v4();
        let mut stream = Box::pin(common::subscribe_admitted(
            &registry,
            SseSubscription {
                identity: ConnectionIdentity {
                    account_id: Some(account),
                    session_hash: Some("hash_a".to_owned()),
                    api_token_id: Some("tok_abc".to_owned()),
                    required_roles: vec!["admin"],
                },
                credential_deadline: None,
            },
        ));
        let _ = stream.next().await;

        emitter
            .notify(event(
                event_type,
                "success",
                Some(account),
                // revocation-shaped metadata, to catch a listener that reads
                // the ids without first consulting the declared scope
                Some(json!({"session_id": "hash_a", "token_id": "tok_abc", "role": "admin"})),
            ))
            .await;

        assert_eq!(registry.count(), 1, "{event_type} must not close a stream");
        let frame = stream.next().await.unwrap().unwrap();
        assert!(
            frame.starts_with(&format!("data: {{\"method\":\"{event_type}\"")),
            "{event_type} should still fan out: {frame}"
        );
    }
}
