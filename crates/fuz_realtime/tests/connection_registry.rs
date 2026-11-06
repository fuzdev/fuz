//! Integration tests for `ConnectionRegistry` — register/remove/iter,
//! broadcast fan-out, identity-keyed revocation (4001 close-code via
//! signal cancellation observed indirectly through `is_cancelled`), the
//! per-account connection cap (evict-oldest, marked for a 4004 close), and
//! two-phase registration (`register_pending` → `admit`): a pending entry is
//! closeable and otherwise inert, and the cap acts only at admission — and
//! the outbound bound: a send that does not fit a connection's queue closes
//! the connection, without slowing the producer or another recipient.
//!
//! Holds each connection's receiver directly in place of a loop; the WS
//! loop's close frames are pinned in `ws_endpoint`'s unit tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]

use std::num::NonZeroUsize;
use std::sync::{Arc, Barrier};

use fuz_auth::ConnectionCloseTarget;
use fuz_auth::ConnectionCloser;
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::{
    CloseReason, Connection, ConnectionGuard, ConnectionReceiver, ConnectionRegistry,
    DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT, NotAdmitted, OUTBOUND_FRAME_OVERHEAD_BYTES,
    PendingConnection, connection_channel, http_no_op_notify, notify_to_string,
    ws_notify_for_connection,
};
use tokio::sync::mpsc::error::TryRecvError;
use tokio_util::sync::CancellationToken;

fn make_signal() -> CancellationToken {
    CancellationToken::new()
}

#[test]
fn add_and_remove_connection() {
    let registry = ConnectionRegistry::new();
    let (tx, _rx) = connection_channel(1 << 20);
    let conn = registry.add_connection(tx, ConnectionIdentity::default(), make_signal());

    assert_eq!(registry.connection_count(), 1);

    registry.remove_connection(conn.id);
    assert_eq!(registry.connection_count(), 0);
}

#[test]
fn remove_connection_idempotent() {
    let registry = ConnectionRegistry::new();
    let (tx, _rx) = connection_channel(1 << 20);
    let conn = registry.add_connection(tx, ConnectionIdentity::default(), make_signal());

    registry.remove_connection(conn.id);
    registry.remove_connection(conn.id);
    assert_eq!(registry.connection_count(), 0);
}

#[test]
fn connection_ids_are_monotonic() {
    let registry = ConnectionRegistry::new();
    let (tx1, _rx1) = connection_channel(1 << 20);
    let (tx2, _rx2) = connection_channel(1 << 20);
    let (tx3, _rx3) = connection_channel(1 << 20);

    let a = registry
        .add_connection(tx1, ConnectionIdentity::default(), make_signal())
        .id;
    let b = registry
        .add_connection(tx2, ConnectionIdentity::default(), make_signal())
        .id;
    let c = registry
        .add_connection(tx3, ConnectionIdentity::default(), make_signal())
        .id;
    assert!(a < b && b < c);
}

#[test]
fn send_to_delivers_to_specific_connection() {
    let registry = ConnectionRegistry::new();
    let (tx1, mut rx1) = connection_channel(1 << 20);
    let (tx2, mut rx2) = connection_channel(1 << 20);
    let a = registry
        .add_connection(tx1, ConnectionIdentity::default(), make_signal())
        .id;
    let _b = registry
        .add_connection(tx2, ConnectionIdentity::default(), make_signal())
        .id;

    let queued = registry.send_to(a, "hello-a");
    assert!(queued);

    let got = rx1.try_recv().unwrap();
    assert_eq!(got.as_str(), "hello-a");
    assert!(rx2.try_recv().is_err());
}

#[test]
fn send_to_unknown_connection_silently_returns_false() {
    let registry = ConnectionRegistry::new();
    // Build a fake id by allocating + freeing one.
    let (tx, _rx) = connection_channel(1 << 20);
    let conn = registry.add_connection(tx, ConnectionIdentity::default(), make_signal());
    registry.remove_connection(conn.id);
    // Should not panic; should return false.
    assert!(!registry.send_to(conn.id, "ignored"));
    assert_eq!(registry.connection_count(), 0);
}

#[test]
fn broadcast_fans_out_to_every_connection() {
    let registry = ConnectionRegistry::new();
    let (tx1, mut rx1) = connection_channel(1 << 20);
    let (tx2, mut rx2) = connection_channel(1 << 20);
    let (tx3, mut rx3) = connection_channel(1 << 20);
    registry.add_connection(tx1, ConnectionIdentity::default(), make_signal());
    registry.add_connection(tx2, ConnectionIdentity::default(), make_signal());
    registry.add_connection(tx3, ConnectionIdentity::default(), make_signal());

    let count = registry.broadcast("broadcast-msg");
    assert_eq!(count, 3);

    assert_eq!(rx1.try_recv().unwrap().as_str(), "broadcast-msg");
    assert_eq!(rx2.try_recv().unwrap().as_str(), "broadcast-msg");
    assert_eq!(rx3.try_recv().unwrap().as_str(), "broadcast-msg");
}

#[test]
fn broadcast_filtered_respects_predicate() {
    let registry = ConnectionRegistry::new();
    let account_a = uuid::Uuid::new_v4();
    let account_b = uuid::Uuid::new_v4();

    let (tx1, mut rx1) = connection_channel(1 << 20);
    let (tx2, mut rx2) = connection_channel(1 << 20);
    let (tx3, mut rx3) = connection_channel(1 << 20);
    registry.add_connection(
        tx1,
        ConnectionIdentity {
            account_id: Some(account_a),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );
    registry.add_connection(
        tx2,
        ConnectionIdentity {
            account_id: Some(account_b),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );
    registry.add_connection(
        tx3,
        ConnectionIdentity {
            account_id: Some(account_a),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );

    let sent =
        registry.broadcast_filtered("for-a", |info| info.identity.account_id == Some(account_a));
    assert_eq!(sent, 2);
    assert_eq!(rx1.try_recv().unwrap().as_str(), "for-a");
    assert!(rx2.try_recv().is_err());
    assert_eq!(rx3.try_recv().unwrap().as_str(), "for-a");
}

#[test]
fn send_to_account_targets_account_connections() {
    let registry = ConnectionRegistry::new();
    let account_a = uuid::Uuid::new_v4();
    let account_b = uuid::Uuid::new_v4();
    let (tx1, mut rx1) = connection_channel(1 << 20);
    let (tx2, mut rx2) = connection_channel(1 << 20);
    registry.add_connection(
        tx1,
        ConnectionIdentity {
            account_id: Some(account_a),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );
    registry.add_connection(
        tx2,
        ConnectionIdentity {
            account_id: Some(account_b),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );

    let sent = registry.send_to_account(account_a, "hi-a");
    assert_eq!(sent, 1);
    assert_eq!(rx1.try_recv().unwrap().as_str(), "hi-a");
    assert!(rx2.try_recv().is_err());
}

#[test]
fn close_by_session_drops_matching_connections() {
    let registry = ConnectionRegistry::new();
    let (tx1, mut rx1) = connection_channel(1 << 20);
    let (tx2, rx2) = connection_channel(1 << 20);
    let signal_a = make_signal();
    let signal_b = make_signal();
    registry.add_connection(
        tx1,
        ConnectionIdentity {
            session_hash: Some("hash-a".to_owned()),
            ..ConnectionIdentity::default()
        },
        signal_a.clone(),
    );
    registry.add_connection(
        tx2,
        ConnectionIdentity {
            session_hash: Some("hash-b".to_owned()),
            ..ConnectionIdentity::default()
        },
        signal_b.clone(),
    );

    let closed = registry.close_connections(&ConnectionCloseTarget::Session("hash-a".to_owned()));
    assert_eq!(closed, 1);
    assert_eq!(registry.connection_count(), 1);
    assert!(
        signal_a.is_cancelled(),
        "matched signal should be cancelled"
    );
    assert!(!signal_b.is_cancelled(), "non-matched signal stays alive");

    // The retained connection's sender still works.
    assert!(rx1.try_recv().is_err(), "closed: receiver sees nothing");
    drop(rx2); // ok — never sent.
}

#[test]
fn close_by_token_drops_matching_connections() {
    let registry = ConnectionRegistry::new();
    let (tx1, _rx1) = connection_channel(1 << 20);
    let (tx2, _rx2) = connection_channel(1 << 20);
    let signal_a = make_signal();
    registry.add_connection(
        tx1,
        ConnectionIdentity {
            api_token_id: Some("tok_a".to_owned()),
            ..ConnectionIdentity::default()
        },
        signal_a.clone(),
    );
    registry.add_connection(
        tx2,
        ConnectionIdentity {
            api_token_id: Some("tok_b".to_owned()),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );

    let closed = registry.close_connections(&ConnectionCloseTarget::Token("tok_a".to_owned()));
    assert_eq!(closed, 1);
    assert_eq!(registry.connection_count(), 1);
    assert!(signal_a.is_cancelled());
}

#[test]
fn close_by_account_drops_every_connection_for_account() {
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    let (tx1, _rx1) = connection_channel(1 << 20);
    let (tx2, _rx2) = connection_channel(1 << 20);
    let (tx3, _rx3) = connection_channel(1 << 20);
    let s1 = make_signal();
    let s2 = make_signal();
    let s3 = make_signal();
    registry.add_connection(
        tx1,
        ConnectionIdentity {
            account_id: Some(account),
            ..ConnectionIdentity::default()
        },
        s1.clone(),
    );
    registry.add_connection(
        tx2,
        ConnectionIdentity {
            account_id: Some(account),
            ..ConnectionIdentity::default()
        },
        s2.clone(),
    );
    registry.add_connection(
        tx3,
        ConnectionIdentity {
            account_id: Some(other),
            ..ConnectionIdentity::default()
        },
        s3.clone(),
    );

    let closed = registry.close_connections(&ConnectionCloseTarget::Account(account));
    assert_eq!(closed, 2);
    assert_eq!(registry.connection_count(), 1);
    assert!(s1.is_cancelled());
    assert!(s2.is_cancelled());
    assert!(!s3.is_cancelled());
}

/// A connection gated on `required_roles` for `account`, its signal, and its
/// receiver.
fn gated(
    registry: &ConnectionRegistry,
    account: uuid::Uuid,
    required_roles: Vec<&'static str>,
) -> (Connection, CancellationToken, ConnectionReceiver) {
    let (tx, rx) = connection_channel(1 << 20);
    let signal = make_signal();
    let conn = registry.add_connection(
        tx,
        ConnectionIdentity {
            account_id: Some(account),
            required_roles,
            ..ConnectionIdentity::default()
        },
        signal.clone(),
    );
    (conn, signal, rx)
}

#[test]
fn close_by_role_closes_only_the_accounts_connections_gated_on_the_role() {
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    let (admin_gated, admin_signal, mut admin_rx) = gated(&registry, account, vec!["admin"]);
    // an any-of gate closes on the loss of any listed role
    let (any_of, any_of_signal, _any_of_rx) =
        gated(&registry, account, vec!["participant", "admin"]);
    let (ungated, ungated_signal, _ungated_rx) = gated(&registry, account, vec![]);
    let (other_role, other_role_signal, _other_role_rx) =
        gated(&registry, account, vec!["participant"]);
    let (other_account, other_account_signal, _other_account_rx) =
        gated(&registry, other, vec!["admin"]);

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Role {
            account_id: account,
            role: "admin".to_owned()
        }),
        2
    );

    for (conn, signal) in [(&admin_gated, &admin_signal), (&any_of, &any_of_signal)] {
        assert!(signal.is_cancelled());
        assert!(!registry.is_registered(conn.id));
        assert_eq!(
            conn.close_reason.get(),
            Some(&CloseReason::PermissionRevoked),
            "the loop closes with 4006, not 4001"
        );
    }
    assert!(
        admin_rx.try_recv() == Err(TryRecvError::Disconnected),
        "the sender is dropped"
    );
    for (conn, signal) in [
        (&ungated, &ungated_signal),
        (&other_role, &other_role_signal),
        (&other_account, &other_account_signal),
    ] {
        assert!(!signal.is_cancelled());
        assert!(registry.is_registered(conn.id));
    }

    // nothing reaches a closed connection after its close
    assert_eq!(
        registry.send_to_account(account, "{}"),
        2,
        "ungated + participant"
    );
    assert!(!registry.send_to(admin_gated.id, "{}"));
}

#[test]
fn a_role_close_refuses_a_pending_registration_as_permission_revoked() {
    let registry = Arc::new(ConnectionRegistry::new());
    let account = uuid::Uuid::new_v4();
    let (tx, mut rx) = connection_channel(1 << 20);
    let signal = make_signal();
    let pending = registry.register_pending(
        tx,
        ConnectionIdentity {
            account_id: Some(account),
            required_roles: vec!["admin"],
            ..ConnectionIdentity::default()
        },
        signal.clone(),
    );

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Role {
            account_id: account,
            role: "admin".to_owned()
        }),
        1
    );
    assert_pending_closed(&registry, &signal, &mut rx, 0);
    assert_eq!(pending.closed(), Some(NotAdmitted::PermissionRevoked));
    assert_eq!(
        registry.admit(pending).map(|_| ()),
        Err(NotAdmitted::PermissionRevoked)
    );
}

#[test]
fn connection_closer_trait_impl_routes_correctly() {
    // Verify the `Arc<dyn ConnectionCloser>` coercion path works — the
    // audit listener chain requires this.
    let registry: Arc<dyn ConnectionCloser> = Arc::new(ConnectionRegistry::new());
    let count = registry.close_connections(&ConnectionCloseTarget::Session(
        "nonexistent-hash".to_owned(),
    ));
    assert_eq!(count, 0);
}

#[test]
fn http_no_op_notify_is_a_plain_fn() {
    // `fn` pointer — no closure, no Arc, no allocation.
    let f: fn(&str, &serde_json::Value) = http_no_op_notify;
    f("ping", &serde_json::Value::Null);
}

#[test]
fn ws_notify_for_connection_delivers_jsonrpc_notification() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (tx, mut rx) = connection_channel(1 << 20);
    let conn = registry.add_connection(tx, ConnectionIdentity::default(), make_signal());

    let notify = ws_notify_for_connection(Arc::clone(&registry), conn.id);
    notify("evt", &serde_json::json!({"x": 42}));

    let got = rx.try_recv().unwrap();
    let v: serde_json::Value = serde_json::from_str(got.as_str()).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["method"], "evt");
    assert_eq!(v["params"]["x"], 42);
    assert!(v.get("id").is_none(), "notification carries no id");
}

#[test]
fn notify_to_string_builds_notification_envelope() {
    let s = notify_to_string("event", &serde_json::json!({"v": "ok"}));
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["method"], "event");
    assert_eq!(v["params"]["v"], "ok");
}

// -- per-account connection cap ------------------------------------------------

fn capped(max: usize) -> ConnectionRegistry {
    ConnectionRegistry::new().with_max_connections_per_account(NonZeroUsize::new(max))
}

/// Register a connection for `account`, returning the handle and the
/// receiver (kept alive so only the registry's own drop closes the channel).
fn add_for(
    registry: &ConnectionRegistry,
    account: Option<uuid::Uuid>,
) -> (Connection, ConnectionReceiver) {
    let (tx, rx) = connection_channel(1 << 20);
    let conn = registry.add_connection(
        tx,
        ConnectionIdentity {
            account_id: account,
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );
    (conn, rx)
}

/// Assert `conn` was superseded by the cap: removed, signal cancelled, its
/// channel closed, and its reason recorded as `Superseded` (the 4004 close).
fn assert_superseded(
    registry: &ConnectionRegistry,
    conn: &Connection,
    rx: &mut ConnectionReceiver,
) {
    assert!(!registry.is_registered(conn.id), "superseded: removed");
    assert!(conn.signal.is_cancelled(), "superseded: signal cancelled");
    assert!(
        rx.try_recv() == Err(TryRecvError::Disconnected),
        "superseded: sender dropped"
    );
    assert_eq!(conn.close_reason.get(), Some(&CloseReason::Superseded));
}

/// Assert `conn` is still live: registered, signal untouched, no reason.
fn assert_live(registry: &ConnectionRegistry, conn: &Connection) {
    assert!(registry.is_registered(conn.id), "live: registered");
    assert!(!conn.signal.is_cancelled(), "live: signal untouched");
    assert_eq!(conn.close_reason.get(), None, "live: no close reason");
}

#[test]
fn cap_closes_the_oldest_connection() {
    let registry = capped(2);
    let account = uuid::Uuid::new_v4();
    let (c1, mut rx1) = add_for(&registry, Some(account));
    let (c2, _rx2) = add_for(&registry, Some(account));
    let (c3, _rx3) = add_for(&registry, Some(account));

    assert_superseded(&registry, &c1, &mut rx1);
    assert_live(&registry, &c2);
    assert_live(&registry, &c3);
    assert_eq!(registry.connection_count_for_account(account), 2);
}

#[test]
fn cap_leaves_other_accounts_untouched() {
    let registry = capped(1);
    let account_a = uuid::Uuid::new_v4();
    let account_b = uuid::Uuid::new_v4();
    let (a1, mut rx_a1) = add_for(&registry, Some(account_a));
    let (b1, _rx_b1) = add_for(&registry, Some(account_b));
    let (a2, _rx_a2) = add_for(&registry, Some(account_a));

    assert_superseded(&registry, &a1, &mut rx_a1);
    assert_live(&registry, &b1);
    assert_live(&registry, &a2);
    assert_eq!(registry.connection_count(), 2);
}

#[test]
fn cap_never_counts_a_connection_without_an_account() {
    let registry = capped(1);
    let conns: Vec<_> = (0..5).map(|_| add_for(&registry, None)).collect();
    assert_eq!(registry.connection_count(), 5);
    for (conn, _rx) in &conns {
        assert_live(&registry, conn);
    }
}

#[test]
fn disabled_cap_admits_without_closing() {
    let registry = ConnectionRegistry::new().with_max_connections_per_account(None);
    let account = uuid::Uuid::new_v4();
    let conns: Vec<_> = (0..DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT * 2)
        .map(|_| add_for(&registry, Some(account)))
        .collect();
    assert_eq!(
        registry.connection_count_for_account(account),
        DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT * 2
    );
    for (conn, _rx) in &conns {
        assert_live(&registry, conn);
    }
}

#[test]
fn new_applies_the_default_cap() {
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let (first, mut first_rx) = add_for(&registry, Some(account));
    let _rest: Vec<_> = (0..DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT)
        .map(|_| add_for(&registry, Some(account)))
        .collect();
    assert_eq!(
        registry.connection_count_for_account(account),
        DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT
    );
    assert_superseded(&registry, &first, &mut first_rx);
}

/// Concurrent adds for one account never overshoot the cap: check, evict,
/// and insert share one write-lock window, so no interleaving can count
/// stale and insert past the limit.
#[test]
fn concurrent_adds_never_exceed_the_cap() {
    const MAX: usize = 4;
    const THREADS: usize = 32;
    let registry = Arc::new(capped(MAX));
    let account = uuid::Uuid::new_v4();
    let barrier = Arc::new(Barrier::new(THREADS));
    #[allow(
        clippy::needless_collect,
        reason = "every thread must spawn before any join, or the barrier never releases"
    )]
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let added = add_for(&registry, Some(account));
                let seen = registry.connection_count_for_account(account);
                assert!(seen <= MAX, "saw {seen} connections, cap is {MAX}");
                added
            })
        })
        .collect();
    let conns: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("adder thread"))
        .collect();

    assert_eq!(registry.connection_count_for_account(account), MAX);
    let live = conns
        .iter()
        .filter(|(conn, _)| registry.is_registered(conn.id))
        .count();
    assert_eq!(live, MAX);
    for (conn, _rx) in &conns {
        assert_eq!(
            registry.is_registered(conn.id),
            conn.close_reason.get().is_none(),
            "every closed connection was superseded, every live one was not"
        );
    }
}

#[test]
fn guard_drop_removes_the_connection() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (conn, _rx) = add_for(&registry, Some(uuid::Uuid::new_v4()));
    let guard = ConnectionGuard::new(Arc::clone(&registry), conn.id);
    assert!(registry.is_registered(conn.id));
    drop(guard);
    assert!(!registry.is_registered(conn.id));
    assert_eq!(registry.connection_count(), 0);
}

/// A revoked connection gives its slot back at once, and is never
/// re-marked as superseded — its loop closes with 4001, not 4004.
#[test]
fn revocation_frees_a_cap_slot() {
    let registry = capped(2);
    let account = uuid::Uuid::new_v4();
    let (tx1, _rx1) = connection_channel(1 << 20);
    let revoked = registry.add_connection(
        tx1,
        ConnectionIdentity {
            session_hash: Some("hash-revoked".to_owned()),
            account_id: Some(account),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );
    let (kept, _rx2) = add_for(&registry, Some(account));

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Session("hash-revoked".to_owned())),
        1
    );
    assert_eq!(registry.connection_count_for_account(account), 1);

    let (newest, _rx3) = add_for(&registry, Some(account));
    assert_live(&registry, &kept);
    assert_live(&registry, &newest);
    assert_eq!(registry.connection_count_for_account(account), 2);
    assert_eq!(
        revoked.close_reason.get(),
        None,
        "a revoked connection keeps the revocation close"
    );
}

// -- two-phase registration ------------------------------------------------------

/// A registry capped at `max`, shared — `register_pending` hands the pending
/// connection a guard on it.
fn capped_shared(max: usize) -> Arc<ConnectionRegistry> {
    Arc::new(capped(max))
}

/// The identity keys a pending registration is made under.
struct PendingKeys<'a> {
    session_hash: Option<&'a str>,
    account: Option<uuid::Uuid>,
    api_token_id: Option<&'a str>,
}

/// Register a pending connection, returning it, its socket token, and the
/// receiver (kept alive so only the registry's own drop closes the channel).
fn register_pending(
    registry: &Arc<ConnectionRegistry>,
    keys: &PendingKeys<'_>,
) -> (PendingConnection, CancellationToken, ConnectionReceiver) {
    let (tx, rx) = connection_channel(1 << 20);
    let signal = make_signal();
    let pending = registry.register_pending(
        tx,
        ConnectionIdentity {
            session_hash: keys.session_hash.map(str::to_owned),
            account_id: keys.account,
            api_token_id: keys.api_token_id.map(str::to_owned),
            ..ConnectionIdentity::default()
        },
        signal.clone(),
    );
    (pending, signal, rx)
}

/// [`register_pending`] keyed on an account alone.
fn pending_for(
    registry: &Arc<ConnectionRegistry>,
    account: uuid::Uuid,
) -> (PendingConnection, CancellationToken, ConnectionReceiver) {
    register_pending(
        registry,
        &PendingKeys {
            session_hash: None,
            account: Some(account),
            api_token_id: None,
        },
    )
}

/// Assert a pending registration was closed by a revocation: its signal
/// cancelled, its sender dropped, and `remaining` other pending
/// registrations left in the registry.
fn assert_pending_closed(
    registry: &ConnectionRegistry,
    signal: &CancellationToken,
    rx: &mut ConnectionReceiver,
    remaining: usize,
) {
    assert_eq!(registry.pending_connection_count(), remaining);
    assert!(signal.is_cancelled(), "closed: signal cancelled");
    assert!(
        rx.try_recv() == Err(TryRecvError::Disconnected),
        "closed: sender dropped"
    );
}

#[test]
fn a_pending_connection_is_not_a_connection_until_admitted() {
    let registry = capped_shared(4);
    let account = uuid::Uuid::new_v4();
    let (pending, signal, _rx) = pending_for(&registry, account);
    let id = pending.id();

    assert_eq!(registry.pending_connection_count(), 1);
    assert_eq!(registry.connection_count(), 0, "pending: not counted");
    assert_eq!(registry.connection_count_for_account(account), 0);
    assert!(!registry.is_registered(id), "pending: not registered");

    let (conn, _guard) = registry.admit(pending).expect("nothing closed it");
    assert_eq!(conn.id, id, "admission keeps the id");
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count(), 1);
    assert_eq!(registry.connection_count_for_account(account), 1);
    assert!(registry.is_registered(id));
    assert!(!signal.is_cancelled());
    assert_eq!(conn.close_reason.get(), None);
}

/// Nothing is delivered to a pending entry — not a broadcast, not a filtered
/// broadcast whose predicate would match it, not an account fan-out, not an
/// id-addressed send — and the counts each returns leave it out. Once
/// admitted it receives everything.
#[test]
fn a_pending_connection_receives_nothing_until_admitted() {
    let registry = Arc::new(ConnectionRegistry::new());
    let account = uuid::Uuid::new_v4();
    let (_live, mut live_rx) = add_for(&registry, Some(account));
    let (pending, _signal, mut pending_rx) = pending_for(&registry, account);

    assert_eq!(registry.broadcast("all"), 1);
    assert_eq!(registry.broadcast_filtered("filtered", |_| true), 1);
    assert_eq!(registry.send_to_account(account, "account"), 1);
    assert!(!registry.send_to(pending.id(), "direct"));
    assert!(
        pending_rx.try_recv().is_err(),
        "a pending connection's queue stays empty"
    );
    for expected in ["all", "filtered", "account"] {
        assert_eq!(live_rx.try_recv().unwrap().as_str(), expected);
    }

    let (conn, _guard) = registry.admit(pending).unwrap();
    assert_eq!(registry.broadcast("all"), 2);
    assert_eq!(registry.broadcast_filtered("filtered", |_| true), 2);
    assert_eq!(registry.send_to_account(account, "account"), 2);
    assert!(registry.send_to(conn.id, "direct"));
    for expected in ["all", "filtered", "account", "direct"] {
        assert_eq!(pending_rx.try_recv().unwrap().as_str(), expected);
    }
}

/// A `broadcast_filtered` predicate is never even shown a pending entry.
#[test]
fn a_broadcast_predicate_never_sees_a_pending_connection() {
    let registry = Arc::new(ConnectionRegistry::new());
    let account = uuid::Uuid::new_v4();
    let (_pending, _signal, _rx) = pending_for(&registry, account);
    let mut seen = 0;
    registry.broadcast_filtered("m", |_| {
        seen += 1;
        true
    });
    assert_eq!(seen, 0);
}

/// The race this exists for: an account at its cap, an upgrade registered
/// pending, and the upgrade's session revoked before admission. The close
/// finds the pending entry, admission refuses, and the account's live
/// connections are untouched — nothing evicted, nothing marked for 4004.
#[test]
fn a_session_revoked_while_pending_is_refused_and_evicts_nothing() {
    let registry = capped_shared(2);
    let account = uuid::Uuid::new_v4();
    let (first, _rx1) = add_for(&registry, Some(account));
    let (second, _rx2) = add_for(&registry, Some(account));

    let (pending, signal, mut rx) = register_pending(
        &registry,
        &PendingKeys {
            session_hash: Some("revoked-hash"),
            account: Some(account),
            api_token_id: None,
        },
    );
    assert_live(&registry, &first);
    assert_live(&registry, &second);

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Session("revoked-hash".to_owned())),
        1
    );
    assert_pending_closed(&registry, &signal, &mut rx, 0);

    assert_eq!(registry.admit(pending).unwrap_err(), NotAdmitted::Revoked);
    assert_eq!(registry.connection_count_for_account(account), 2);
    assert_live(&registry, &first);
    assert_live(&registry, &second);
}

#[test]
fn an_account_close_reaches_a_pending_connection() {
    let registry = Arc::new(ConnectionRegistry::new());
    let account = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    let (pending, signal, mut rx) = pending_for(&registry, account);
    let (bystander, bystander_signal, _bystander_rx) = pending_for(&registry, other);

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account)),
        1
    );
    assert_pending_closed(&registry, &signal, &mut rx, 1);
    assert_eq!(registry.admit(pending).unwrap_err(), NotAdmitted::Revoked);

    assert!(!bystander_signal.is_cancelled(), "another account's stays");
    let _admitted = registry.admit(bystander).expect("untouched by the close");
}

#[test]
fn a_token_close_reaches_a_pending_connection() {
    let registry = Arc::new(ConnectionRegistry::new());
    let account = uuid::Uuid::new_v4();
    let keys = |token| PendingKeys {
        session_hash: None,
        account: Some(account),
        api_token_id: Some(token),
    };
    let (pending, signal, mut rx) = register_pending(&registry, &keys("tok_revoked"));
    let (bystander, bystander_signal, _bystander_rx) =
        register_pending(&registry, &keys("tok_other"));

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Token("tok_revoked".to_owned())),
        1
    );
    assert_pending_closed(&registry, &signal, &mut rx, 1);
    assert_eq!(registry.admit(pending).unwrap_err(), NotAdmitted::Revoked);

    assert!(!bystander_signal.is_cancelled(), "another token's stays");
    let _admitted = registry.admit(bystander).expect("untouched by the close");
}

/// Registering pending evicts nothing, however far past the cap the account
/// is; the eviction happens at admission, and only then.
#[test]
fn the_cap_evicts_at_admission_not_at_registration() {
    let registry = capped_shared(1);
    let account = uuid::Uuid::new_v4();
    let (live, mut live_rx) = add_for(&registry, Some(account));

    let (pending, _signal, _rx) = pending_for(&registry, account);
    assert_live(&registry, &live);
    assert_eq!(registry.connection_count_for_account(account), 1);

    let (admitted, _guard) = registry.admit(pending).unwrap();
    assert_superseded(&registry, &live, &mut live_rx);
    assert_live(&registry, &admitted);
    assert_eq!(registry.connection_count_for_account(account), 1);
}

/// Pending registrations never weigh on the cap: any number of them on one
/// account leave its admitted connection alone, and a one-step admission
/// beside them evicts by the admitted count only.
#[test]
fn pending_connections_do_not_count_toward_the_cap() {
    let registry = capped_shared(2);
    let account = uuid::Uuid::new_v4();
    let (live, _live_rx) = add_for(&registry, Some(account));
    let pendings: Vec<_> = (0..5).map(|_| pending_for(&registry, account)).collect();
    assert_eq!(registry.pending_connection_count(), 5);

    // one admitted + this one = the cap; counting the pending five would
    // have evicted `live`
    let (second, _second_rx) = add_for(&registry, Some(account));
    assert_live(&registry, &live);
    assert_live(&registry, &second);
    assert_eq!(registry.connection_count_for_account(account), 2);
    assert_eq!(registry.pending_connection_count(), 5, "and none evicted");
    for (_, signal, _) in &pendings {
        assert!(!signal.is_cancelled(), "the cap never closes a pending one");
    }
}

/// A pending registration is never the cap's victim, even though its id is
/// older than the admitted connections that arrived after it.
#[test]
fn the_cap_never_evicts_a_pending_connection() {
    let registry = capped_shared(1);
    let account = uuid::Uuid::new_v4();
    let (pending, signal, _rx) = pending_for(&registry, account);
    let (first, mut first_rx) = add_for(&registry, Some(account));
    let (second, _second_rx) = add_for(&registry, Some(account));

    assert_superseded(&registry, &first, &mut first_rx);
    assert_live(&registry, &second);
    assert!(
        !signal.is_cancelled(),
        "the older pending entry is untouched"
    );
    assert_eq!(registry.pending_connection_count(), 1);
    let _admitted = registry.admit(pending).expect("still registered");
}

/// A pending connection owns its entry: dropped unadmitted — what every
/// refusal path does — the entry is gone, with no guard for a caller to
/// forget.
#[test]
fn dropping_a_pending_connection_removes_its_entry() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (pending, _signal, _rx) = pending_for(&registry, uuid::Uuid::new_v4());
    assert_eq!(registry.pending_connection_count(), 1);
    drop(pending);
    assert_eq!(registry.pending_connection_count(), 0);
}

/// A refused admission leaves nothing behind either: `admit` consumed the
/// pending connection, and its guard went with it.
#[test]
fn a_refused_admission_leaves_no_entry() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (pending, _signal, _rx) = pending_for(&registry, uuid::Uuid::new_v4());
    registry.remove_connection(pending.id());
    assert_eq!(registry.admit(pending).unwrap_err(), NotAdmitted::Revoked);
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count(), 0);
}

/// Admission hands the entry's guard to the caller: the admitted connection
/// lives exactly as long as that guard.
#[test]
fn the_admitted_connections_guard_owns_its_entry() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (pending, _signal, _rx) = pending_for(&registry, uuid::Uuid::new_v4());
    let (conn, guard) = registry.admit(pending).unwrap();
    assert!(registry.is_registered(conn.id));
    drop(guard);
    assert!(!registry.is_registered(conn.id));
}

/// Ids are per-registry counters, so a pending connection handed to the
/// wrong registry names a stranger's entry there. It must not admit it —
/// and its own registration, back in its own registry, is cleaned up.
#[test]
fn admit_refuses_a_pending_connection_from_another_registry() {
    let ours = Arc::new(ConnectionRegistry::new());
    let theirs = Arc::new(ConnectionRegistry::new());
    let account = uuid::Uuid::new_v4();
    let (foreign, _foreign_signal, _foreign_rx) = pending_for(&theirs, account);
    let (local, _local_signal, _local_rx) = pending_for(&ours, account);
    assert_eq!(foreign.id(), local.id(), "the same id in both registries");

    assert_eq!(ours.admit(foreign).unwrap_err(), NotAdmitted::Revoked);
    assert_eq!(
        ours.connection_count(),
        0,
        "the stranger's entry stays pending"
    );
    assert_eq!(ours.pending_connection_count(), 1);
    assert_eq!(theirs.pending_connection_count(), 0, "its own is removed");
    let _admitted = ours.admit(local).expect("its own registration admits");
}

// -- outbound bound ------------------------------------------------------------

/// The byte budget the cases below build their channels with.
const BUDGET: usize = 512;

/// How many [`QUARTER_FRAME_BYTES`] frames fill [`BUDGET`] exactly.
const QUARTERS: usize = 4;

/// The payload of a frame charged exactly a quarter of [`BUDGET`]: the rest
/// of its charge is the per-frame overhead.
const QUARTER_FRAME_BYTES: usize = BUDGET / QUARTERS - OUTBOUND_FRAME_OVERHEAD_BYTES;

/// The payload of a frame charged exactly [`BUDGET`].
const FULL_FRAME_BYTES: usize = BUDGET - OUTBOUND_FRAME_OVERHEAD_BYTES;

/// Register an admitted connection for `account` over a channel with a byte
/// budget of `outbound_queue_bytes`.
fn bounded(
    registry: &ConnectionRegistry,
    account: uuid::Uuid,
    outbound_queue_bytes: usize,
) -> (Connection, ConnectionReceiver) {
    let (tx, rx) = connection_channel(outbound_queue_bytes);
    let conn = registry.add_connection(
        tx,
        ConnectionIdentity {
            account_id: Some(account),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );
    (conn, rx)
}

/// Assert the registry closed `conn` for an outbound overflow and forgot it:
/// the reason recorded, the signal cancelled, the queue dropped, and every
/// reader answering as for a connection it never knew.
fn assert_closed_for_overflow(
    registry: &ConnectionRegistry,
    account: uuid::Uuid,
    conn: &Connection,
    rx: &mut ConnectionReceiver,
) {
    assert_eq!(
        conn.close_reason.get(),
        Some(&CloseReason::OutboundOverflow)
    );
    assert!(
        conn.signal.is_cancelled(),
        "in-flight handlers are cancelled"
    );
    assert!(rx.is_closed());
    assert_eq!(rx.queued_bytes(), 0, "the queue is dropped, not kept");
    assert_eq!(rx.len(), 0);
    assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));

    // an id the registry has let go of by the ordinary path
    let (tx, _rx) = connection_channel(BUDGET);
    let unknown = registry
        .add_connection(tx, ConnectionIdentity::default(), make_signal())
        .id;
    registry.remove_connection(unknown);
    assert!(!registry.is_registered(conn.id));
    assert_eq!(
        registry.send_to(conn.id, "x"),
        registry.send_to(unknown, "x"),
        "send_to answers as for an unknown connection"
    );
    assert!(!registry.send_to(conn.id, "x"));
    assert_eq!(registry.send_to_account(account, "x"), 0);
    assert_eq!(registry.connection_count_for_account(account), 0);
    assert_eq!(registry.connection_count(), 0);
    assert_eq!(registry.pending_connection_count(), 0);
}

/// The byte budget is exact, and each waiting frame is charged its UTF-8
/// length plus the overhead: frames charged the whole budget between them are
/// queued, and the next — even an empty one, which costs its overhead —
/// closes the connection.
#[test]
fn the_outbound_byte_budget_is_exact() {
    assert_eq!(
        OUTBOUND_FRAME_OVERHEAD_BYTES, 64,
        "the wire contract's charge"
    );
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let (conn, mut rx) = bounded(&registry, account, BUDGET);
    // two bytes of UTF-8 per character: the charge is bytes, not characters
    let frame = "é".repeat(QUARTER_FRAME_BYTES / 2);
    assert_eq!(frame.len(), QUARTER_FRAME_BYTES);
    for _ in 0..QUARTERS {
        assert!(registry.send_to(conn.id, &frame));
    }
    assert_eq!(rx.len(), QUARTERS);
    assert_eq!(
        rx.queued_bytes() + rx.len() * OUTBOUND_FRAME_OVERHEAD_BYTES,
        BUDGET,
        "charged exactly the budget"
    );
    assert!(registry.is_registered(conn.id));
    assert_eq!(conn.close_reason.get(), None);

    assert!(!registry.send_to(conn.id, ""), "nothing more is queued");
    assert_closed_for_overflow(&registry, account, &conn, &mut rx);

    // one byte less of budget, and the last of the same frames does not fit
    let (conn, mut rx) = bounded(&registry, account, BUDGET - 1);
    for _ in 1..QUARTERS {
        assert!(registry.send_to(conn.id, &frame));
    }
    assert!(!registry.send_to(conn.id, &frame));
    assert_closed_for_overflow(&registry, account, &conn, &mut rx);
}

/// Bytes alone bound the queue. Thousands of one-byte frames sent with
/// nothing reading in between are all queued while their charges fit, and
/// the connection closes exactly where `N × (len + 64)` crosses the budget.
#[test]
fn small_frames_are_bounded_by_their_charges_alone() {
    const FRAMES: usize = 5000;
    let per_frame = 1 + OUTBOUND_FRAME_OVERHEAD_BYTES;
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let (conn, mut rx) = bounded(&registry, account, FRAMES * per_frame);
    for n in 0..FRAMES {
        assert!(registry.send_to(conn.id, "x"), "frame {n} is queued");
    }
    assert_eq!(rx.len(), FRAMES, "exactly at the budget");
    assert!(registry.is_registered(conn.id));

    assert!(!registry.send_to(conn.id, "x"), "one frame more is not");
    assert_closed_for_overflow(&registry, account, &conn, &mut rx);
}

/// Frames with no payload are bounded as well: each costs its overhead, so
/// an endless run of them closes the connection.
#[test]
fn empty_frames_are_bounded_by_their_overhead() {
    const FIT: usize = 10;
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let (conn, mut rx) = bounded(&registry, account, FIT * OUTBOUND_FRAME_OVERHEAD_BYTES);
    for _ in 0..FIT {
        assert!(registry.send_to(conn.id, ""));
    }
    assert_eq!(rx.len(), FIT);
    assert_eq!(rx.queued_bytes(), 0);

    assert!(!registry.send_to(conn.id, ""));
    assert_closed_for_overflow(&registry, account, &conn, &mut rx);
}

/// One frame larger than the whole budget is delivered into an empty queue —
/// it is a single deliverable message — and closes a connection that already
/// has a frame waiting.
#[test]
fn an_oversized_frame_is_delivered_only_into_an_empty_queue() {
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let oversized = "x".repeat(BUDGET * 3);

    let (empty, mut empty_rx) = bounded(&registry, account, BUDGET);
    assert!(registry.send_to(empty.id, &oversized));
    assert_eq!(empty_rx.try_recv().unwrap().as_str(), oversized);
    assert!(registry.is_registered(empty.id));
    registry.remove_connection(empty.id);

    let (waiting, mut waiting_rx) = bounded(&registry, account, BUDGET);
    assert!(registry.send_to(waiting.id, "x"));
    assert!(!registry.send_to(waiting.id, &oversized));
    assert_closed_for_overflow(&registry, account, &waiting, &mut waiting_rx);
}

/// A frame the receiver took no longer counts: a connection that keeps
/// reading never overflows, however much is sent through it.
#[test]
fn a_draining_connection_never_overflows() {
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let (conn, mut rx) = bounded(&registry, account, BUDGET);
    let frame = "x".repeat(BUDGET);
    for _ in 0..2048 {
        assert!(registry.send_to(conn.id, &frame));
        assert_eq!(rx.try_recv().unwrap().len(), BUDGET);
    }
    assert!(registry.is_registered(conn.id));
}

/// One stalled recipient and one active one under a broadcast: the producer
/// is never blocked (every call returns), the active recipient receives
/// every message in order, and the stalled one is closed at its budget — its
/// queue released, the rest of the fan-out no longer counting it. The close
/// does not touch the active one.
#[test]
fn a_broadcast_closes_a_stalled_recipient_and_spares_an_active_one() {
    let registry = ConnectionRegistry::new();
    let (stalled_account, active_account) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let (stalled, mut stalled_rx) = bounded(&registry, stalled_account, BUDGET);
    let (active, mut active_rx) = bounded(&registry, active_account, BUDGET);
    let frame = "x".repeat(QUARTER_FRAME_BYTES);

    let rounds = QUARTERS * 3;
    for round in 0..rounds {
        let message = format!("{round:02}{}", &frame[2..]);
        let reached = registry.broadcast(&message);
        let expected = if round < QUARTERS { 2 } else { 1 };
        assert_eq!(reached, expected, "round {round}");
        assert_eq!(
            active_rx.try_recv().unwrap().as_str(),
            message,
            "the active recipient receives every message"
        );
    }

    assert_closed_for_overflow_of(&registry, &stalled, &mut stalled_rx);
    assert_eq!(registry.connection_count_for_account(stalled_account), 0);
    assert!(registry.is_registered(active.id));
    assert!(!active.signal.is_cancelled());
    assert_eq!(active.close_reason.get(), None);
    assert_eq!(registry.connection_count(), 1);
    assert_eq!(active_rx.queued_bytes(), 0);
}

/// The per-recipient half of [`assert_closed_for_overflow`], for a registry
/// that still holds other connections.
fn assert_closed_for_overflow_of(
    registry: &ConnectionRegistry,
    conn: &Connection,
    rx: &mut ConnectionReceiver,
) {
    assert_eq!(
        conn.close_reason.get(),
        Some(&CloseReason::OutboundOverflow)
    );
    assert!(conn.signal.is_cancelled());
    assert!(!registry.is_registered(conn.id));
    assert_eq!(rx.queued_bytes(), 0, "the memory held for it is released");
    assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
}

/// A broadcast charges each recipient for the frame in full — the shared
/// buffer is not split between them — and `broadcast_filtered` /
/// `send_to_account` overflow exactly as `broadcast` does.
#[test]
fn every_fan_out_charges_each_recipient_and_closes_on_overflow() {
    let registry = ConnectionRegistry::new();
    let account = uuid::Uuid::new_v4();
    let (first, mut first_rx) = bounded(&registry, account, BUDGET);
    let (second, mut second_rx) = bounded(&registry, account, BUDGET);
    // two frames that fill the budget exactly, so the second is measured
    // against what the first was charged
    let frame = "x".repeat(BUDGET / 2 - OUTBOUND_FRAME_OVERHEAD_BYTES);

    assert_eq!(registry.broadcast(&frame), 2);
    assert_eq!(registry.broadcast(&frame), 2, "each has room for both");
    assert_eq!(first_rx.queued_bytes(), 2 * frame.len());
    assert_eq!(second_rx.queued_bytes(), 2 * frame.len());

    assert_eq!(registry.send_to_account(account, ""), 0);
    assert_closed_for_overflow_of(&registry, &first, &mut first_rx);
    assert_closed_for_overflow_of(&registry, &second, &mut second_rx);
    assert_eq!(registry.connection_count_for_account(account), 0);

    let (third, mut third_rx) = bounded(&registry, account, BUDGET);
    let full = "x".repeat(FULL_FRAME_BYTES);
    assert_eq!(registry.broadcast_filtered(&full, |_| true), 1);
    assert_eq!(registry.broadcast_filtered("", |_| true), 0);
    assert_closed_for_overflow_of(&registry, &third, &mut third_rx);
}

/// A pending registration is never queued to, so the fan-out cannot overflow
/// it, and an overflow frees its account's slot under the cap: the next
/// admission evicts nothing.
#[test]
fn an_overflow_leaves_pending_registrations_and_the_cap_alone() {
    let registry =
        Arc::new(ConnectionRegistry::new().with_max_connections_per_account(NonZeroUsize::new(1)));
    let account = uuid::Uuid::new_v4();
    let (tx, pending_rx) = connection_channel(BUDGET);
    let pending = registry.register_pending(
        tx,
        ConnectionIdentity {
            account_id: Some(account),
            ..ConnectionIdentity::default()
        },
        make_signal(),
    );
    let (live, mut live_rx) = bounded(&registry, account, BUDGET);

    let frame = "x".repeat(BUDGET);
    assert_eq!(registry.broadcast(&frame), 1);
    assert_eq!(registry.broadcast(&frame), 0, "the live one overflowed");
    assert_closed_for_overflow_of(&registry, &live, &mut live_rx);
    assert_eq!(
        pending_rx.len(),
        0,
        "nothing was queued for the pending one"
    );
    assert_eq!(pending.closed(), None);
    assert_eq!(registry.pending_connection_count(), 1);

    let (admitted, _guard) = registry.admit(pending).expect("still admissible");
    assert!(registry.is_registered(admitted.id));
    assert_eq!(registry.connection_count_for_account(account), 1);
    assert_eq!(admitted.close_reason.get(), None, "it superseded nothing");
}

/// Every registry-side close discards what was queued, at the close — a
/// revocation, a supersession, the shutdown, a plain removal — so a closed
/// connection holds no backlog while its loop is still finishing, and the
/// receiver reads the close ahead of anything queued.
#[test]
fn every_close_discards_the_queue_at_once() {
    use fuz_http::ShutdownCloser;

    fn queue_two(registry: &ConnectionRegistry, conn: &Connection, rx: &ConnectionReceiver) {
        assert!(registry.send_to(conn.id, "one"));
        assert!(registry.send_to(conn.id, "two"));
        assert_eq!(rx.len(), 2);
    }
    fn assert_discarded(rx: &mut ConnectionReceiver, what: &str) {
        assert!(rx.is_closed(), "{what}");
        assert_eq!(rx.queued_bytes(), 0, "{what}: the backlog is released");
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected), "{what}");
    }
    let account = uuid::Uuid::new_v4();

    let registry = ConnectionRegistry::new();
    let (conn, mut rx) = bounded(&registry, account, BUDGET);
    queue_two(&registry, &conn, &rx);
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account)),
        1
    );
    assert_discarded(&mut rx, "a revocation");

    let registry = ConnectionRegistry::new().with_max_connections_per_account(NonZeroUsize::new(1));
    let (conn, mut rx) = bounded(&registry, account, BUDGET);
    queue_two(&registry, &conn, &rx);
    let (_newer, _newer_rx) = bounded(&registry, account, BUDGET);
    assert_eq!(conn.close_reason.get(), Some(&CloseReason::Superseded));
    assert_discarded(&mut rx, "a supersession");

    let registry = ConnectionRegistry::new();
    let (conn, mut rx) = bounded(&registry, account, BUDGET);
    queue_two(&registry, &conn, &rx);
    assert_eq!(registry.close_all_connections(), 1);
    assert_discarded(&mut rx, "the shutdown");

    let registry = ConnectionRegistry::new();
    let (conn, mut rx) = bounded(&registry, account, BUDGET);
    queue_two(&registry, &conn, &rx);
    registry.remove_connection(conn.id);
    assert_discarded(&mut rx, "a removal");
}
