//! Integration test: `fuz_auth` migration registers cleanly against a
//! real `PostgreSQL`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth -- --ignored --test-threads=1
//! ```
//!
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

// Integration-test helpers assert via `expect`/`unwrap`; `allow-*-in-tests`
// doesn't cover the non-`#[test]` helper fns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use fuz_auth::AUTH_MIGRATIONS;
use fuz_db::{MigrationNamespace, run_migrations};
use fuz_testing::{TestingDbOptions, fresh_test_db_pool};

/// This suite's database: `FUZ_AUTH_TEST_URL` (default `fuz_auth_test`) with
/// an **empty** migration list — the tests below drive `run_migrations`
/// themselves and assert on what it applies, so the fixture must hand back a
/// bare `public` schema.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_AUTH_TEST_URL",
    default_db: "fuz_auth_test",
    migrations: &[],
    setup_sql: None,
};

/// Tear down any previous state for a clean re-migration. Resetting the whole
/// `public` schema wipes every table, type, and sequence — immune to the drift
/// a hand-maintained drop list invites.
async fn fresh_db_pool() -> fuz_db::Pool {
    fresh_test_db_pool(DB).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn migrations_run_once() {
    let pool = fresh_db_pool().await;

    let results = run_migrations(&pool, &[AUTH_MIGRATIONS])
        .await
        .expect("first migration run");
    assert_eq!(results.len(), 1, "one namespace applied");
    let r = &results[0];
    assert_eq!(r.namespace, "fuz_auth");
    // The chain in order. These names are a **cross-spine contract**, not just
    // an ordering: `_testing_migration_tracker` diffs them against `fuz_app`'s
    // `AUTH_MIGRATIONS`, so a rename or reorder here breaks migration-identity
    // parity and the swap-freely invariant.
    assert_eq!(
        r.applied_names,
        vec![
            "full_auth_schema".to_owned(),
            "role_grant_offer_and_scoped_role_grants".to_owned(),
            "api_token_scope".to_owned(),
            "api_token_hash_unique_index".to_owned(),
            "audit_log_metadata_gin_index".to_owned(),
            "drop_session_last_seen_at".to_owned(),
            "role_grant_offer_expire_audited_at".to_owned(),
            "account_username_lowercase".to_owned(),
        ],
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn migrations_idempotent_on_second_run() {
    let pool = fresh_db_pool().await;

    run_migrations(&pool, &[AUTH_MIGRATIONS])
        .await
        .expect("first migration run");

    // Second run: no namespace returned (the result is omitted on
    // already-up-to-date namespaces, per fuz_db's contract).
    let results = run_migrations(&pool, &[AUTH_MIGRATIONS])
        .await
        .expect("second migration run");
    assert!(results.is_empty(), "second run is a no-op");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn auth_tables_exist_after_migration() {
    let pool = fresh_db_pool().await;
    run_migrations(&pool, &[AUTH_MIGRATIONS])
        .await
        .expect("migration run");

    let client = pool.get().await.expect("pool.get");
    for table in [
        "account",
        "actor",
        "role_grant",
        "auth_session",
        "bootstrap_lock",
        "app_settings",
        "api_token",
        "audit_log",
    ] {
        let row = client
            .query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = $1
                )",
                &[&table],
            )
            .await
            .expect("query_one");
        let exists: bool = row.get(0);
        assert!(exists, "table {table} should exist after migration");
    }
}

/// The `api_token_scope` migration's compatibility path, end to end against a
/// real database.
///
/// This is the one step of the design that runs exactly once, on live data,
/// with no second chance — so it is tested against Postgres rather than
/// reasoned about. It reproduces the upgrade an existing deployment sees: a
/// token row that predates the column, then the migration, then the three
/// properties that must hold afterward.
///
/// The properties, in the order they matter:
///
/// 1. **The pre-existing token still works.** Rejecting it would break live
///    automation (`fuzf` against a deployed forge is the only known bearer
///    client), which is why the design grandfathers rather than rejects.
/// 2. **It is marked, not merely permitted.** `grandfathered: true`
///    distinguishes "predates scoping" from "someone chose full authority",
///    which is what makes the debt countable instead of invisible.
/// 3. **`NOT NULL` holds afterward.** This is the load-bearing one: it makes an
///    absent scope unrepresentable, which is precisely the permissive default
///    the scope design refuses.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn api_token_scope_migration_grandfathers_existing_tokens() {
    use fuz_auth::token_scope::{TokenScope, TokenScopeDocument};

    let pool = fresh_db_pool().await;

    // Bring the DB to the state *before* token scoping by running only the
    // chain **prefix** — a faithful stand-in for a deployment that
    // bootstrapped on the older code. The chain is data, so both the prefix
    // and the expected replay tail derive from `AUTH_MIGRATIONS` itself: no
    // hand-written inverse SQL to drift, and appending a future migration
    // costs this test zero edits.
    let scope_idx = AUTH_MIGRATIONS
        .migrations
        .iter()
        .position(|m| m.name == "api_token_scope")
        .expect("api_token_scope is in the released chain");
    let pre_scope_chain = MigrationNamespace::spine(
        AUTH_MIGRATIONS.name,
        &AUTH_MIGRATIONS.migrations[..scope_idx],
    );
    run_migrations(&pool, &[pre_scope_chain])
        .await
        .expect("prefix migration run");
    let client = pool.get().await.expect("pool.get");

    // A token minted before the `api_token_scope` migration: no scope, because
    // the column does not exist yet.
    let account_id = uuid::Uuid::new_v4();
    client
        .execute(
            "INSERT INTO account (id, username, password_hash) VALUES ($1, $2, 'x')",
            &[&account_id, &"legacy-holder"],
        )
        .await
        .expect("seed account");
    client
        .execute(
            "INSERT INTO api_token (id, account_id, name, token_hash)
             VALUES ('tok_legacy', $1, 'pre-scope token', 'legacy-hash')",
            &[&account_id],
        )
        .await
        .expect("seed pre-scope token");
    drop(client);

    // Run the full chain: the outstanding tail replays, in order, starting
    // with the one under test.
    let results = run_migrations(&pool, &[AUTH_MIGRATIONS])
        .await
        .expect("scope migration run");
    let expected_tail: Vec<String> = AUTH_MIGRATIONS.migrations[scope_idx..]
        .iter()
        .map(|m| m.name.to_owned())
        .collect();
    assert_eq!(
        results[0].applied_names, expected_tail,
        "only the outstanding tail applies to an already-migrated DB",
    );

    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "SELECT scope::text FROM api_token WHERE id = 'tok_legacy'",
            &[],
        )
        .await
        .expect("read back the backfilled scope");
    let raw: String = row.get(0);
    let doc = TokenScopeDocument::parse(&raw).expect(
        "the backfilled literal must parse — the parser is fail-closed, so a drift \
                 between migrations/api_token_scope.sql and token_scope.rs silently bricks \
                 every pre-existing token",
    );

    // (1) still full authority, so live automation keeps working...
    assert_eq!(doc.to_scope(), TokenScope::Full);
    // (2) ...but marked as a debt rather than an ordinary choice.
    assert!(doc.grandfathered, "backfilled rows carry the marker");
    assert_eq!(doc.label(), "full (grandfathered)");

    // (3) and the hole is closed going forward: no row can lack a scope.
    let is_nullable: String = client
        .query_one(
            "SELECT is_nullable FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'api_token' AND column_name = 'scope'",
            &[],
        )
        .await
        .expect("column metadata")
        .get(0);
    assert_eq!(
        is_nullable, "NO",
        "an absent scope must be unrepresentable — a nullable column reintroduces \
         exactly the permissive default this design exists to remove",
    );
    let insert_without_scope = client
        .execute(
            "INSERT INTO api_token (id, account_id, name, token_hash)
             VALUES ('tok_no_scope', $1, 'should fail', 'another-hash')",
            &[&account_id],
        )
        .await;
    assert!(
        insert_without_scope.is_err(),
        "the database itself must refuse a scopeless token, not just the mint handler",
    );
}

/// The `account_username_lowercase` migration against a database that already
/// holds accounts: lowercase rows pass, a mixed-case row fails the migration
/// and rolls its chain back, and once that row is lowercased the chain applies
/// and the CHECK refuses a mixed-case insert from then on.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_username_lowercase_migration_refuses_a_mixed_case_row() {
    let pool = fresh_db_pool().await;

    // the chain before the migration under test, its tail derived from the data
    let idx = AUTH_MIGRATIONS
        .migrations
        .iter()
        .position(|m| m.name == "account_username_lowercase")
        .expect("account_username_lowercase is in the released chain");
    let prefix =
        MigrationNamespace::spine(AUTH_MIGRATIONS.name, &AUTH_MIGRATIONS.migrations[..idx]);
    run_migrations(&pool, &[prefix])
        .await
        .expect("prefix migration run");
    let client = pool.get().await.expect("pool.get");
    client
        .execute(
            "INSERT INTO account (username, password_hash) VALUES ('lower_holder', 'x'), ('Mixed_Holder', 'x')",
            &[],
        )
        .await
        .expect("seed accounts");
    drop(client);

    // a mixed-case row fails the CHECK as it is added
    let err = run_migrations(&pool, &[AUTH_MIGRATIONS])
        .await
        .expect_err("a mixed-case username fails the migration");
    let fuz_db::DbError::Migration(fuz_db::MigrationError::Failed { name, source, .. }) = &err
    else {
        panic!("a migration failure: {err}");
    };
    assert_eq!(name, "account_username_lowercase");
    assert_eq!(
        source.code().map(tokio_postgres::error::SqlState::code),
        Some("23514"),
        "check_violation: {err}"
    );
    let client = pool.get().await.expect("pool.get");
    let applied: i64 = client
        .query_one(
            "SELECT count(*) FROM schema_version WHERE namespace = 'fuz_auth' AND name = 'account_username_lowercase'",
            &[],
        )
        .await
        .expect("tracker read")
        .get(0);
    assert_eq!(applied, 0, "the failed migration is not recorded");

    // lowercased, the chain applies
    client
        .execute("UPDATE account SET username = lower(username)", &[])
        .await
        .expect("lowercase the rows");
    drop(client);
    let results = run_migrations(&pool, &[AUTH_MIGRATIONS])
        .await
        .expect("migration run after lowercasing");
    assert_eq!(
        results[0].applied_names,
        vec!["account_username_lowercase".to_owned()]
    );

    let client = pool.get().await.expect("pool.get");
    let insert = client
        .execute(
            "INSERT INTO account (username, password_hash) VALUES ('Another_Mixed', 'x')",
            &[],
        )
        .await
        .expect_err("the CHECK refuses a mixed-case insert");
    assert_eq!(
        insert.code().map(tokio_postgres::error::SqlState::code),
        Some("23514")
    );
}
