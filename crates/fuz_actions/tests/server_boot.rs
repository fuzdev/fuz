//! PG-backed tests for the server toolkit's boot, `create_app_backend`: the
//! chain migrates a bare schema, `/ready` answers over the embedded fixture
//! (and a spec without one boots and serves no `/ready`), and a database whose
//! `default_transaction_isolation` is not READ COMMITTED is refused before
//! anything is written. A migration whose body fails gets no connectivity hint.
//! And the other end of a server's life: shutdown waits for a failure row still
//! being written, so it lands before the runtime goes.
//!
//! Each test boots over a database of its own (`fuz_testing::fresh_test_db`).
//! The isolation test changes a database-level setting, which only PostgreSQL
//! has, so it runs on PostgreSQL alone.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fuz_actions::server::{
    AppBackendSpec, BootedAppBackend, SpineBackendOptions, StartupError, create_app_backend,
    ensure_read_committed, fallback_group, probe_router,
};
use fuz_auth::AUTH_MIGRATIONS;
use fuz_db::Pool;
use fuz_http::{BaseServerEnv, ServerEnvOptions};
use fuz_testing::{TestEngine, TestingArgon2idHasher, TestingDbOptions};
use tower::ServiceExt;

const DB: TestingDbOptions<'static> = TestingDbOptions {
    suite: "fuz_actions",
    migrations: &[],
    setup_sql: None,
    engine: TestEngine::Any,
};

const SPEC: AppBackendSpec = AppBackendSpec {
    session_cookie_name: "server_boot_session",
    migration_namespaces: &[AUTH_MIGRATIONS],
    expected_schema_json: Some(r#"{"account": ["id"], "schema_version": ["namespace"]}"#),
    audit_sse: Some(fuz_actions::server::AuditSseSpec::DEFAULT),
    browser_gates: fuz_actions::server::BrowserGateSpec::DEFAULT,
};

fn env_at(url: &str) -> BaseServerEnv {
    BaseServerEnv::from_vars(
        &|k| match k {
            "DATABASE_URL" => Some(url.to_owned()),
            "SECRET_FUZ_COOKIE_KEYS" => Some("server-boot-cookie-key-0123456789abcdef".to_owned()),
            "FUZ_ALLOWED_ORIGINS" => Some("http://localhost".to_owned()),
            _ => None,
        },
        ServerEnvOptions {
            trusted_proxies_var: "FUZ_ACTIONS_TEST_TRUSTED_PROXIES",
        },
    )
    .expect("the env reads")
}

/// Off: these suites hold the auth tables' locks and count their rows, and
/// the cleanup's own suite (`fuz_auth`'s `tests/auth_cleanup.rs`) covers the
/// sweeps.
fn options() -> SpineBackendOptions {
    SpineBackendOptions {
        rate_limiters: fuz_auth::RateLimiterMode::DisabledForTesting,
        ..SpineBackendOptions::production(
            Arc::new(TestingArgon2idHasher::new()),
            fuz_auth::AuthCleanupSchedule::Off,
        )
    }
}

async fn has_schema_version(pool: &Pool) -> bool {
    pool.get()
        .await
        .expect("pool.get")
        .query_one(
            "SELECT to_regclass('public.schema_version') IS NOT NULL",
            &[],
        )
        .await
        .expect("probe schema_version")
        .get(0)
}

#[tokio::test]
async fn boots_a_bare_database_and_serves_ready() {
    let pool = DB.open().await;
    assert!(!has_schema_version(&pool).await);

    let BootedAppBackend { backend, ready } =
        create_app_backend(&env_at(pool.url()), &SPEC, options())
            .await
            .expect("the backend boots");

    assert!(has_schema_version(&backend.pool).await, "the chain ran");
    assert!(backend.audit_sse.is_some());
    assert_eq!(backend.session_cookie_name, "server_boot_session");
    assert!(
        !backend.bootstrap_available.load(Ordering::SeqCst),
        "no token path, no bootstrap"
    );

    let response = ready
        .expect("the spec embeds a fixture")
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .expect("the request builds"),
        )
        .await
        .expect("/ready answers");
    assert_eq!(response.status(), StatusCode::OK);
}

/// A spec with no fixture — a local daemon's — boots, builds no `/ready`, and
/// the router a server composes over the core answers `/ready` `404`.
#[tokio::test]
async fn a_spec_without_a_fixture_boots_and_serves_no_ready() {
    let pool = DB.open().await;
    let BootedAppBackend { backend, ready } = create_app_backend(
        &env_at(pool.url()),
        &AppBackendSpec {
            expected_schema_json: None,
            ..SPEC
        },
        options(),
    )
    .await
    .expect("the backend boots without a fixture");
    assert!(ready.is_none(), "no fixture, no /ready");
    assert!(has_schema_version(&backend.pool).await, "the chain ran");

    let router = fuz_http::compose_stack(
        [fuz_http::RouteGroup::new(
            "api",
            probe_router("server_boot_test").merge(ready.unwrap_or_default()),
            fuz_http::BodyCap::Bytes(fuz_http::DEFAULT_BODY_LIMIT_BYTES),
        )],
        fallback_group(),
        &backend.stack_options(),
    );
    for (path, status) in [
        ("/health", StatusCode::OK),
        ("/ready", StatusCode::NOT_FOUND),
    ] {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("the request builds");
        let response = router.send_for_testing(request, fuz_http::TEST_PEER).await;
        assert_eq!(response.status(), status, "{path}");
    }
}

#[tokio::test]
#[ignore = "postgres-only: a database-level `ALTER DATABASE … SET`"]
async fn refuses_a_database_not_at_read_committed_before_migrating() {
    // a database of its own, so the database-level setting reaches no other test
    let pool = DB.postgres_only().open().await;
    ensure_read_committed(&pool)
        .await
        .expect("the Postgres default passes");
    let client = pool.get().await.expect("pool.get");
    let name: String = client
        .query_one("SELECT current_database()", &[])
        .await
        .expect("read the database name")
        .get(0);
    client
        .batch_execute(&format!(
            "ALTER DATABASE {name} SET default_transaction_isolation = 'repeatable read'"
        ))
        .await
        .expect("set the database default");
    drop(client);

    // new connections see the database-level setting
    let result = create_app_backend(&env_at(pool.url()), &SPEC, options()).await;
    let probe =
        fuz_db::create_pool(pool.url(), &fuz_db::PoolOptions::default()).expect("create_pool");
    let migrated = has_schema_version(&probe).await;
    drop(probe);

    let error = result.expect_err("refused");
    assert!(
        matches!(&error, StartupError::TransactionIsolation { found } if found == "repeatable read"),
        "{error}"
    );
    assert_eq!(error.exit_code(), 2);
    assert!(!migrated, "refused before the chain ran");
}

#[tokio::test]
async fn a_failed_migration_body_gets_no_connectivity_hint() {
    const BROKEN: &[fuz_db::Migration] = &[fuz_db::Migration {
        name: "broken_body",
        sql: "CREATE TABLE server_boot_broken (id NOT_A_TYPE)",
    }];
    let pool = DB.open().await;
    let error = fuz_db::run_migrations(
        &pool,
        &[fuz_db::MigrationNamespace::new(
            "server_boot_broken",
            BROKEN,
        )],
    )
    .await
    .expect_err("the body is invalid");
    let fuz_db::DbError::Migration(fuz_db::MigrationError::Failed { source, .. }) = &error else {
        panic!("expected a failed migration, got {error:?}");
    };
    assert!(
        source.code().is_some(),
        "the server answered with a SQLSTATE"
    );
    // the message carries its own remedy; "check Postgres is running" would mislead
    assert_eq!(StartupError::Database(error).hint(), None);
}

// -- Shutdown drains the audit writes in flight --------------------------------

/// The suite database with the auth chain, for the case that writes a row.
const AUTH_DB: TestingDbOptions<'static> = TestingDbOptions {
    migrations: &[AUTH_MIGRATIONS],
    ..DB
};

/// A failure row spawned just before the shutdown signal — its INSERT held
/// behind a lock on `audit_log` until after the token fires — lands: the
/// serve waits for it before it returns and lets the runtime go.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "postgres-only: stalls a table behind LOCK TABLE"]
async fn shutdown_waits_for_a_failure_row_still_being_written() {
    use std::time::Duration;

    use fuz_actions::server::{
        ServeOptions, boot_only_router, build_app_backend, serve_until_shutdown,
    };
    use fuz_auth::{AuditEventType, AuditLogInput};
    use fuz_testing::TestingTableLock;

    let pool = AUTH_DB.postgres_only().open().await;
    let backend =
        build_app_backend(&env_at(pool.url()), &SPEC, &options()).expect("the backend builds");
    let emitter = Arc::clone(&backend.audit_emitter);
    let lock = TestingTableLock::acquire(&pool, "audit_log").await;
    drop(emitter.emit(AuditLogInput::for_event(AuditEventType::Login).failure()));
    lock.wait_for_waiter().await;

    // fired once the serve is up — a token fired before it would end the serve
    // before the bind, with nothing drained. The extra upkeep starts once the
    // listener is bound, so it is the signal; it reports how many writes were
    // in flight as the token fired, and the lock's release is timed from then.
    // (It must not release the lock itself: the serve joins its upkeep before
    // it drains the writes.)
    let shutdown = fuz_http::CancellationToken::new();
    let (fired_tx, fired_rx) = tokio::sync::oneshot::channel::<usize>();
    let fire_on_bind: fuz_actions::server::UpkeepTask = Box::new({
        let emitter = Arc::clone(&emitter);
        move |token| {
            tokio::spawn(async move {
                let inflight = emitter.inflight_count();
                token.cancel();
                let _ = fired_tx.send(inflight);
            })
        }
    });
    let released = tokio::spawn(async move {
        let inflight = fired_rx.await.expect("the token fired");
        tokio::time::sleep(Duration::from_millis(300)).await;
        lock.release().await;
        inflight
    });
    // the probes serve live here, carrying the duties of the backend whose
    // write is held
    let stack_options = fuz_http::StackOptions {
        serve_duties: Some(backend.serve_duties()),
        ..fuz_http::StackOptions::without_backend(
            fuz_http::AllowedOrigins::parse("http://localhost").expect("the allowlist parses"),
            Arc::new(Vec::new()),
        )
    };
    serve_until_shutdown(
        boot_only_router("audit_drain_test_server", &stack_options),
        ServeOptions {
            server_name: "audit_drain_test_server",
            addr: "127.0.0.1:0".parse().expect("addr"),
            drain_timeout: Duration::from_secs(10),
            shutdown,
            extra_upkeep: vec![fire_on_bind],
        },
    )
    .await
    .expect("a clean end");

    assert_eq!(emitter.inflight_count(), 0, "nothing was given up on");
    let rows: i64 = pool
        .get()
        .await
        .expect("pool.get")
        .query_one(
            "SELECT count(*) FROM audit_log WHERE event_type = 'login' AND outcome = 'failure'",
            &[],
        )
        .await
        .expect("count the rows")
        .get(0);
    assert_eq!(rows, 1, "the failure row landed before the serve returned");
    assert_eq!(
        released.await.expect("the lock was released"),
        1,
        "the failure row was still held when the token fired"
    );
}
