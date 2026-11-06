//! PG-backed tests for the server toolkit's boot, `create_app_backend`: the
//! pre-migration hook runs before the chain, the chain migrates a bare schema,
//! `/ready` answers over the embedded fixture (and a spec without one boots
//! and serves no `/ready`), and a database whose
//! `default_transaction_isolation` is not READ COMMITTED is refused before
//! anything is written. A migration whose body fails gets no connectivity hint.
//!
//! Shares the suite database (`FUZ_ACTIONS_TEST_URL`, default
//! `fuz_actions_test`) with the crate's other PG suites. The isolation test
//! changes a database-level setting, so it does so on a scratch database it
//! creates and drops (`CREATEDB` needed), never on the shared one.
//!
//! `#[ignore]`-gated — run:
//! ```text
//! createdb fuz_actions_test
//! cargo test -p fuz_actions --test server_boot -- --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fuz_actions::server::{
    AppBackendSpec, BootedAppBackend, SpineBackendOptions, StartupError, create_app_backend,
    ensure_read_committed, fallback_group, probe_router,
};
use fuz_auth::AUTH_MIGRATIONS;
use fuz_db::Pool;
use fuz_http::{BaseServerEnv, ServerEnvOptions};
use fuz_testing::{ScratchDb, TestingArgon2idHasher, TestingDbOptions, fresh_test_db_pool};
use tower::ServiceExt;

const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_ACTIONS_TEST_URL",
    default_db: "fuz_actions_test",
    migrations: &[],
    setup_sql: None,
};

/// The isolation test's own database ([`ScratchDb`]); needs `CREATEDB`.
const SCRATCH_DATABASE: &str = "fuz_actions_test_isolation_scratch";

const SPEC: AppBackendSpec = AppBackendSpec {
    session_cookie_name: "server_boot_session",
    migration_namespaces: &[AUTH_MIGRATIONS],
    expected_schema_json: Some(r#"{"account": ["id"], "schema_version": ["namespace"]}"#),
    audit_sse: Some(fuz_actions::server::AuditSseSpec::DEFAULT),
    browser_gates: fuz_actions::server::BrowserGateSpec::DEFAULT,
};

fn env() -> BaseServerEnv {
    env_at(&DB.url())
}

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

fn options() -> SpineBackendOptions {
    SpineBackendOptions {
        rate_limiters: fuz_auth::RateLimiterMode::DisabledForTesting,
        ..SpineBackendOptions::production(Arc::new(TestingArgon2idHasher::new()))
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
#[ignore = "requires PostgreSQL (FUZ_ACTIONS_TEST_URL); run with --ignored --test-threads=1"]
async fn boots_a_bare_database_and_serves_ready() {
    let pool = fresh_test_db_pool(DB).await;
    assert!(!has_schema_version(&pool).await);

    // the hook sees the database before the chain has run
    let hook_saw_migrated = Arc::new(AtomicBool::new(true));
    let seen = Arc::clone(&hook_saw_migrated);
    let BootedAppBackend { backend, ready } = create_app_backend(
        &env(),
        &SPEC,
        SpineBackendOptions {
            pre_migration_hook: Some(Box::new(move |pool: &Pool| {
                Box::pin(async move {
                    seen.store(has_schema_version(pool).await, Ordering::SeqCst);
                    Ok(())
                })
            })),
            ..options()
        },
    )
    .await
    .expect("the backend boots");

    assert!(
        !hook_saw_migrated.load(Ordering::SeqCst),
        "the hook ran first"
    );
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
#[ignore = "requires PostgreSQL (FUZ_ACTIONS_TEST_URL); run with --ignored --test-threads=1"]
async fn a_spec_without_a_fixture_boots_and_serves_no_ready() {
    let _pool = fresh_test_db_pool(DB).await;
    let BootedAppBackend { backend, ready } = create_app_backend(
        &env(),
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
        let mut request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("the request builds");
        request.extensions_mut().insert(axum::extract::ConnectInfo(
            "127.0.0.1:40000"
                .parse::<std::net::SocketAddr>()
                .expect("the peer parses"),
        ));
        let response = router
            .clone()
            .into_router_for_testing()
            .oneshot(request)
            .await
            .expect("the router answers");
        assert_eq!(response.status(), status, "{path}");
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL (FUZ_ACTIONS_TEST_URL) and CREATEDB; run with --ignored"]
async fn refuses_a_database_not_at_read_committed_before_migrating() {
    // a scratch database, so the database-level setting never reaches the
    // suite database the other tests share, even if this test dies mid-way
    let scratch = ScratchDb::create(DB, SCRATCH_DATABASE).await;
    let pool =
        fuz_db::create_pool(scratch.url(), &fuz_db::PoolOptions::default()).expect("create_pool");
    ensure_read_committed(&pool)
        .await
        .expect("the Postgres default passes");
    pool.get()
        .await
        .expect("pool.get")
        .batch_execute(&format!(
            "ALTER DATABASE {SCRATCH_DATABASE} SET default_transaction_isolation = 'repeatable read'"
        ))
        .await
        .expect("set the database default");
    drop(pool);

    // new connections see the database-level setting
    let result = create_app_backend(&env_at(scratch.url()), &SPEC, options()).await;
    let probe =
        fuz_db::create_pool(scratch.url(), &fuz_db::PoolOptions::default()).expect("create_pool");
    let migrated = has_schema_version(&probe).await;
    drop(probe);
    scratch.drop_database().await;

    let error = result.expect_err("refused");
    assert!(
        matches!(&error, StartupError::TransactionIsolation { found } if found == "repeatable read"),
        "{error}"
    );
    assert_eq!(error.exit_code(), 2);
    assert!(!migrated, "refused before the chain ran");
}

#[tokio::test]
#[ignore = "requires PostgreSQL (FUZ_ACTIONS_TEST_URL); run with --ignored --test-threads=1"]
async fn a_failed_migration_body_gets_no_connectivity_hint() {
    const BROKEN: &[fuz_db::Migration] = &[fuz_db::Migration {
        name: "broken_body",
        sql: "CREATE TABLE server_boot_broken (id NOT_A_TYPE)",
    }];
    let pool = fresh_test_db_pool(DB).await;
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
