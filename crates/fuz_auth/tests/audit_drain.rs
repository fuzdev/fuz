//! PG-backed test for [`fuz_auth::AuditEmitter::drain_inflight`]: a tracked
//! `emit` whose listener panics still settles the in-flight count, so the
//! drain — the barrier the `_testing_drain_effects` action awaits — resolves
//! rather than hanging.
//!
//! Needs Postgres because a listener only hears a row the emit wrote. The
//! aborted-before-it-ran case needs no row and is a unit test beside the
//! emitter.
//!
//! `#[ignore]`-gated — run:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test audit_drain -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fuz_auth::{AuditEmitter, AuditEventType, AuditListenerFn, AuditLogInput};

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_panicking_listener_still_settles_the_drain() {
    let pool = common::fresh_db_pool().await;
    let emitter = Arc::new(AuditEmitter::new_with_inflight_tracking(pool));
    let heard = Arc::new(AtomicBool::new(false));
    let listener: AuditListenerFn = {
        let heard = Arc::clone(&heard);
        Arc::new(move |_event| {
            let heard = Arc::clone(&heard);
            Box::pin(async move {
                heard.store(true, Ordering::SeqCst);
                panic!("intentional listener panic");
            })
        })
    };
    emitter.add_listener(listener);

    let handle = emitter.emit(AuditLogInput::for_event(AuditEventType::Login));
    tokio::time::timeout(Duration::from_secs(10), emitter.drain_inflight())
        .await
        .expect("drain_inflight resolves after a listener panics");

    assert!(
        heard.load(Ordering::SeqCst),
        "the row was written and the listener ran"
    );
    assert!(
        handle.await.is_err_and(|e| e.is_panic()),
        "the panic surfaces on the emit's JoinHandle"
    );
}

/// A pool of one client whose own checkout gives up after 50 ms of waiting —
/// the request bound, made short. Opening and recycling the client keep a
/// generous bound: a cold Postgres connect can take longer than 50 ms, and
/// the bound under test is the wait for a held client.
fn one_client_pool() -> fuz_db::Pool {
    let config: tokio_postgres::Config = common::test_url().parse().expect("test URL parses");
    fuz_db::Pool::builder(deadpool_postgres::Manager::new(
        config,
        tokio_postgres::NoTls,
    ))
    .runtime(deadpool_postgres::Runtime::Tokio1)
    .max_size(1)
    .timeouts(deadpool_postgres::Timeouts {
        wait: Some(Duration::from_millis(50)),
        ..fuz_db::checkout_timeouts(Duration::from_secs(5))
    })
    .build()
    .expect("pool builds")
}

/// Count the rows of `event_type` in `audit_log`.
async fn rows_of(pool: &fuz_db::Pool, event_type: &str) -> i64 {
    pool.get()
        .await
        .expect("pool.get")
        .query_one(
            "SELECT count(*) FROM audit_log WHERE event_type = $1",
            &[&event_type],
        )
        .await
        .expect("count")
        .get(0)
}

/// A pool write waits for the emitter's own checkout bound, not the pool's:
/// with the pool's one client held past the pool's 50 ms, a row emitted under
/// a 5 s audit bound lands once the client comes back, and one under a 50 ms
/// audit bound is dropped.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_pool_write_waits_for_the_audit_checkout_bound() {
    let db = common::fresh_db_pool().await;
    let pool = one_client_pool();

    // the long bound: the write outlasts the held client
    let emitter =
        Arc::new(AuditEmitter::new(pool.clone()).with_checkout_timeout(Duration::from_secs(5)));
    let held = pool.get().await.expect("the one client");
    let handle = emitter.emit(AuditLogInput::for_event(AuditEventType::Login).failure());
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(held);
    handle.await.expect("the write task ends");
    assert_eq!(
        rows_of(&db, "login").await,
        1,
        "the row landed after the wait"
    );

    // the short bound: the write gives up while the client is held
    let emitter =
        Arc::new(AuditEmitter::new(pool.clone()).with_checkout_timeout(Duration::from_millis(50)));
    let held = pool.get().await.expect("the one client");
    emitter
        .emit(AuditLogInput::for_event(AuditEventType::Logout).failure())
        .await
        .expect("the write task ends");
    drop(held);
    assert_eq!(rows_of(&db, "logout").await, 0, "the row was dropped");
}

/// The dropped-row log line carries the whole row.
#[test]
fn the_dropped_row_carries_every_column() {
    let account = uuid::Uuid::nil();
    let row = fuz_auth::dropped_row_json(
        &AuditLogInput::for_event(AuditEventType::Login)
            .failure()
            .account(account)
            .ip(Some("203.0.113.9".to_owned()))
            .metadata(serde_json::json!({"username": "alice"})),
    );
    assert_eq!(
        row,
        serde_json::json!({
            "event_type": "login",
            "outcome": "failure",
            "actor_id": null,
            "account_id": account,
            "target_account_id": null,
            "target_actor_id": null,
            "ip": "203.0.113.9",
            "metadata": {"username": "alice"},
        })
    );
}
