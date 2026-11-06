//! PG-backed tests for `fuz_testing`'s `_testing_reset` action, driven through
//! [`fuz_actions::perform_action`]: the daemon-token keeper cache moves to the
//! freshly seeded keeper only once the reset's transaction commits, and the
//! consumer's domain `reset_state` runs before the auth wipe, so a domain table
//! with a restricting FK to `actor` doesn't make every later reset fail.
//!
//! The cross-backend harness authenticates every reset with the daemon token,
//! which resolves through `DaemonTokenState.keeper_account_id`. A reset that
//! pointed the cache at its new keeper before committing, then rolled back,
//! would leave it on an account that never landed — the daemon token would stop
//! resolving and every later reset would be refused until the binary restarted.
//! Each reset here authenticates the way the harness does
//! ([`fuz_auth::AuthGate::resolve_credential`] over `X-Daemon-Token`), so that
//! failure mode shows as the next reset failing to authenticate. The rollback
//! is forced after the keeper is seeded by an `extra_accounts` entry that
//! reuses the keeper's username (a unique violation).
//!
//! Lives in `fuz_actions` rather than `fuz_testing` for the real dispatcher and
//! the suite database it already has (`FUZ_ACTIONS_TEST_URL`, default
//! `fuz_actions_test`), which it shares with `perform_action_dispatch`.
//!
//! `#[ignore]`-gated — run:
//! ```text
//! createdb fuz_actions_test
//! cargo test -p fuz_actions --test testing_reset_keeper_cache -- --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::HeaderMap;
use fuz_actions::ActionRegistry;
use fuz_actions::perform_action::{PerformActionInput, PerformActionOptions, perform_action};
use fuz_auth::daemon_token::DAEMON_TOKEN_HEADER;
use fuz_auth::{
    AUTH_MIGRATIONS, AuditEmitter, NoopConnectionCloser, NoopNotificationSender,
    SESSION_COOKIE_NAME, SharedDaemonTokenState,
};
use fuz_db::ActionDb;
use fuz_db::Pool;
use fuz_realtime::SignalToken;
use fuz_testing::testing_reset::{
    BoxFutureResetResult, ResetStateFn, TestingResetOptions, create_testing_reset_action_spec,
};
use fuz_testing::{
    TESTING_DAEMON_TOKEN, TestingArgon2idHasher, TestingDbOptions, daemon_token_state,
    fresh_test_db_pool, seed_account_actor, testing_keyring,
};
use serde_json::{Value, json};
use uuid::Uuid;

/// This suite's database — the auth chain, plus one consumer-shaped domain
/// table whose `actor_id` FK restricts deletes (no `ON DELETE` action), like a
/// consumer's `created_by REFERENCES actor(id)`.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_ACTIONS_TEST_URL",
    default_db: "fuz_actions_test",
    migrations: &[AUTH_MIGRATIONS],
    setup_sql: Some(
        "CREATE TABLE domain_row (id SERIAL PRIMARY KEY, \
         actor_id UUID NOT NULL REFERENCES actor(id))",
    ),
};

struct Harness {
    options: PerformActionOptions,
    pool: Pool,
    daemon_token_state: SharedDaemonTokenState,
    /// Makes the reset's `reset_state` hook fail.
    fail_reset_state: Arc<AtomicBool>,
}

/// A fresh database holding one keeper the daemon token resolves to, as a
/// booted test binary has, and a registry carrying `_testing_reset` alone.
async fn setup() -> Harness {
    let pool = fresh_test_db_pool(DB).await;
    let (boot_keeper_id, _) = seed_account_actor(&pool, "boot_keeper").await;
    let daemon_token_state = daemon_token_state(TESTING_DAEMON_TOKEN, Some(boot_keeper_id));
    let fail_reset_state = Arc::new(AtomicBool::new(false));

    let reset_state: ResetStateFn = {
        let fail_reset_state = Arc::clone(&fail_reset_state);
        Arc::new(move |db: ActionDb<'_>| -> BoxFutureResetResult<'_> {
            let fail = fail_reset_state.load(Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    return Err(fuz_http::internal_error("intentional reset_state failure"));
                }
                // the consumer-shaped domain wipe, on the reset's transaction
                db.execute("DELETE FROM domain_row", &[])
                    .await
                    .map_err(|e| fuz_http::internal_error_with_source("domain wipe", &e))?;
                Ok(())
            })
        })
    };
    let spec = create_testing_reset_action_spec(TestingResetOptions {
        password_hasher: Arc::new(TestingArgon2idHasher::new()),
        keyring: Arc::new(testing_keyring()),
        daemon_token_state: Arc::clone(&daemon_token_state),
        session_cookie_name: SESSION_COOKIE_NAME,
        reset_state: Some(reset_state),
    });
    let options = PerformActionOptions {
        pool: pool.clone(),
        registry: Arc::new(ActionRegistry::compile(vec![spec]).expect("compile registry")),
        audit: Arc::new(AuditEmitter::new(pool.clone())),
        connection_closer: Arc::new(NoopConnectionCloser),
        notification_sender: Arc::new(NoopNotificationSender),
        peer: fuz_realtime::noop_action_peer(),
        account_rate_limiter: None,
        ip_rate_limiter: None,
    };
    Harness {
        options,
        pool,
        daemon_token_state,
        fail_reset_state,
    }
}

fn cached_keeper(h: &Harness) -> Option<Uuid> {
    h.daemon_token_state.read().keeper_account_id
}

/// Fire `_testing_reset` the way the cross-backend harness does: resolve the
/// caller from `X-Daemon-Token`, then dispatch as that account.
///
/// # Panics
///
/// When the daemon token no longer resolves — the cache points at an account
/// that isn't in the database.
async fn reset(h: &Harness) -> Result<fuz_actions::ActionOutput, fuz_http::JsonrpcError> {
    reset_with(h, json!({})).await
}

/// [`reset`] with explicit `_testing_reset` params.
///
/// # Panics
///
/// As [`reset`].
async fn reset_with(
    h: &Harness,
    params: Value,
) -> Result<fuz_actions::ActionOutput, fuz_http::JsonrpcError> {
    let mut headers = HeaderMap::new();
    headers.insert(DAEMON_TOKEN_HEADER, TESTING_DAEMON_TOKEN.parse().unwrap());
    let resolved = fuz_auth::AuthGate {
        daemon_token_state: Some(Arc::clone(&h.daemon_token_state)),
        ..fuz_testing::testing_auth_gate(h.pool.clone())
    }
    .preflight(&headers, fuz_http::UNRESOLVED_CLIENT_IP)
    .await
    .expect("the fixture sends no foreign origin")
    .expect("the daemon token resolves to the cached keeper");

    let request_id = json!(1);
    let signal = SignalToken::new();
    let span = tracing::Span::none();
    let notify: &(dyn Fn(&str, &Value) + Send + Sync) = &fuz_realtime::http_no_op_notify;
    let input = PerformActionInput {
        method: "_testing_reset",
        params: &params,
        request_id: &request_id,
        auth: Some(&resolved),
        client_ip: None,
        connection_id: None,
        notify,
        signal: &signal,
        log: &span,
    };
    perform_action(input, &h.options).await
}

/// The seeded keeper's account id from a successful reset's response.
fn seeded_keeper_id(result: Result<fuz_actions::ActionOutput, fuz_http::JsonrpcError>) -> Uuid {
    let Ok(output) = result else {
        panic!("expected the reset to succeed, got {result:?}");
    };
    let value = output.to_value().expect("render reset output");
    let id = value["account"]["id"].as_str().expect("account.id string");
    Uuid::parse_str(id).expect("account.id uuid")
}

async fn account_exists(pool: &Pool, id: Uuid) -> bool {
    let client = pool.get().await.unwrap();
    client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM account WHERE id = $1)",
            &[&id],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn failed_reset_leaves_keeper_cache_and_next_reset_succeeds() {
    let h = setup().await;

    // A committed reset points the cache at its keeper.
    let first = seeded_keeper_id(reset(&h).await);
    assert_eq!(cached_keeper(&h), Some(first), "commit moves the cache");
    assert!(account_exists(&h.pool, first).await);

    // A reset that fails after seeding its keeper — an extra account reusing
    // the keeper's username — rolls that keeper back: the cache stays on the
    // keeper that is still in the database.
    let failed = reset_with(
        &h,
        json!({"extra_accounts": [{"username": "keeper", "roles": []}]}),
    )
    .await;
    assert!(
        failed.is_err(),
        "the duplicate extra fails the reset, got {failed:?}"
    );
    assert_eq!(
        cached_keeper(&h),
        Some(first),
        "a rolled-back reset leaves the cache unchanged"
    );
    assert!(
        account_exists(&h.pool, first).await,
        "the rollback restored the previous keeper"
    );

    // A reset whose `reset_state` fails rolls back the same way.
    h.fail_reset_state.store(true, Ordering::SeqCst);
    let failed = reset(&h).await;
    assert!(
        failed.is_err(),
        "the failing hook fails the reset, got {failed:?}"
    );
    assert_eq!(cached_keeper(&h), Some(first));
    assert!(account_exists(&h.pool, first).await);

    // The next reset still authenticates, and moves the cache on.
    h.fail_reset_state.store(false, Ordering::SeqCst);
    let next = seeded_keeper_id(reset(&h).await);
    assert_ne!(next, first, "each reset seeds a fresh keeper");
    assert_eq!(cached_keeper(&h), Some(next));
}

/// The domain `reset_state` runs before the auth wipe: a domain row that
/// references the current keeper's actor through a restricting FK is gone by
/// the time the wipe deletes that actor, so the reset succeeds — and keeps
/// succeeding. Run after the wipe, the `actor` delete hits the FK and every
/// later reset fails.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn domain_reset_runs_before_the_auth_wipe() {
    let h = setup().await;
    let Ok(output) = reset(&h).await else {
        panic!("expected the first reset to succeed");
    };
    let value = output.to_value().expect("render reset output");
    let actor_id = Uuid::parse_str(value["actor"]["id"].as_str().expect("actor.id")).expect("uuid");
    {
        let client = h.pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO domain_row (actor_id) VALUES ($1)",
                &[&actor_id],
            )
            .await
            .unwrap();
    }

    let second = reset(&h).await;
    assert!(
        second.is_ok(),
        "the domain wipe clears the restricting row before the actor delete, got {second:?}"
    );
    let client = h.pool.get().await.unwrap();
    let remaining: i64 = client
        .query_one("SELECT COUNT(*) FROM domain_row", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(remaining, 0, "the domain row went with the reset");
}
