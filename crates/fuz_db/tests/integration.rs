//! Integration tests for `fuz_db` against a real `PostgreSQL` instance.
//!
//! All tests are `#[ignore]` so `cargo test --workspace` stays green on
//! machines without postgres; run explicitly with:
//!
//! ```bash
//! createdb fuz_db_test
//! cargo test -p fuz_db -- --ignored --test-threads=1
//! ```
//!
//! Override the connection URL with `FUZ_DB_TEST_URL`:
//!
//! ```bash
//! FUZ_DB_TEST_URL=postgres://localhost/some_db cargo test -p fuz_db -- --ignored --test-threads=1
//! ```
//!
//! Tests share the same database and namespace their work via unique
//! migration namespaces / table names per test, scoped under a fresh
//! `pg_advisory_xact_lock`. Each test cleans up after itself. One test needs a
//! database with no `schema_version` tracker at all, so instead of sharing
//! `fuz_db_test` it creates and drops its own scratch database beside it — the
//! test role needs `CREATEDB`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]
#![expect(
    clippy::items_after_statements,
    reason = "tests declare their fixture items beside the statements that use them"
)]

use std::collections::BTreeMap;
use std::env;

use fuz_db::{
    DbError, Divergence, Migration, MigrationError, MigrationNamespace, PgErrorKind, Pool,
    RESERVED_NAMESPACES, assert_valid_sql_identifier, baseline, check_schema_drift,
    classify_pg_error, commit_checked, create_pool, format_db_status, is_pg_unique_violation,
    query_db_status, query_ready_columns, query_schema_snapshot, run_migrations, sqlstate_in_chain,
};

/// Default test database — must be created out of band:
/// `createdb fuz_db_test`.
fn test_database_url() -> String {
    env::var("FUZ_DB_TEST_URL").unwrap_or_else(|_| "postgres://localhost/fuz_db_test".to_owned())
}

fn build_pool() -> Pool {
    create_pool(&test_database_url(), &fuz_db::PoolOptions::default()).expect("test pool build")
}

/// Reset the tables / `schema_version` rows a test will touch.
async fn clean(pool: &Pool, table_names: &[&str], namespaces: &[&str]) {
    let client = pool.get().await.expect("clean: pool get");
    for table in table_names {
        let stmt = format!("DROP TABLE IF EXISTS {table} CASCADE");
        client
            .batch_execute(&stmt)
            .await
            .expect("clean: drop table");
    }
    for ns in namespaces {
        client
            .execute("DELETE FROM schema_version WHERE namespace = $1", &[ns])
            .await
            .ok();
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn pool_acquire_works() {
    let pool = build_pool();
    let client = pool.get().await.expect("pool get");
    let row = client.query_one("SELECT 42::int4 as v", &[]).await.unwrap();
    let v: i32 = row.get("v");
    assert_eq!(v, 42);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn commit_checked_commits_a_healthy_transaction() {
    let pool = build_pool();
    clean(&pool, &["tx_commit_test"], &[]).await;

    let client = pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE tx_commit_test (id INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    drop(client);

    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute("INSERT INTO tx_commit_test (id) VALUES ($1)", &[&1_i32])
        .await
        .unwrap();
    tx.execute("INSERT INTO tx_commit_test (id) VALUES ($1)", &[&2_i32])
        .await
        .unwrap();
    commit_checked(tx).await.unwrap();
    drop(client);

    let client = pool.get().await.unwrap();
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM tx_commit_test", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 2);

    clean(&pool, &["tx_commit_test"], &[]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn transaction_rolls_back_when_an_error_drops_it() {
    let pool = build_pool();
    clean(&pool, &["tx_rollback_test"], &[]).await;

    let client = pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE tx_rollback_test (id INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    drop(client);

    // The production shape: `?` returns early on the failed statement, and the
    // dropped transaction rolls back — no commit is attempted.
    async fn insert_duplicate(pool: &Pool) -> Result<(), DbError> {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        tx.execute("INSERT INTO tx_rollback_test (id) VALUES ($1)", &[&1_i32])
            .await?;
        // a duplicate-key error mid-transaction
        tx.execute("INSERT INTO tx_rollback_test (id) VALUES ($1)", &[&1_i32])
            .await?;
        commit_checked(tx).await
    }
    let result = insert_duplicate(&pool).await;

    let Err(DbError::Postgres(source)) = &result else {
        panic!("expected the duplicate-key error, got {result:?}");
    };
    assert!(is_pg_unique_violation(source));

    let client = pool.get().await.unwrap();
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM tx_rollback_test", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "rollback should leave the table empty");

    clean(&pool, &["tx_rollback_test"], &[]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn a_healthy_transaction_dropped_before_commit_rolls_back() {
    // An early return on a non-database error leaves the transaction healthy,
    // so only the drop's rollback keeps the insert from persisting.
    let pool = build_pool();
    clean(&pool, &["tx_drop_test"], &[]).await;

    let client = pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE tx_drop_test (id INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    drop(client);

    async fn insert_then_bail(pool: &Pool) -> Result<(), DbError> {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        tx.execute("INSERT INTO tx_drop_test (id) VALUES ($1)", &[&1_i32])
            .await?;
        Err(DbError::InvalidIdentifier("test bail".to_owned()))?;
        commit_checked(tx).await
    }
    let result = insert_then_bail(&pool).await;
    assert!(
        matches!(result, Err(DbError::InvalidIdentifier(_))),
        "expected the bail, got {result:?}"
    );

    let client = pool.get().await.unwrap();
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM tx_drop_test", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "the dropped transaction should roll back");
    drop(client);

    clean(&pool, &["tx_drop_test"], &[]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn commit_checked_refuses_a_transaction_a_swallowed_error_aborted() {
    // Code that drops a failed statement's error and carries on leaves the
    // transaction aborted. `COMMIT` would roll it back without an error;
    // the checked commit reports it instead, and nothing persists.
    let pool = build_pool();
    clean(&pool, &["tx_aborted_test"], &[]).await;

    let client = pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE tx_aborted_test (id INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    drop(client);

    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute("INSERT INTO tx_aborted_test (id) VALUES ($1)", &[&1_i32])
        .await
        .unwrap();
    let duplicate = tx
        .execute("INSERT INTO tx_aborted_test (id) VALUES ($1)", &[&1_i32])
        .await;
    assert!(duplicate.is_err(), "the swallowed statement must fail");
    let result = commit_checked(tx).await;
    drop(client);

    let Err(DbError::TransactionAborted(source)) = result else {
        panic!("expected TransactionAborted, got {result:?}");
    };
    assert_eq!(
        source.code(),
        Some(&tokio_postgres::error::SqlState::IN_FAILED_SQL_TRANSACTION)
    );

    let client = pool.get().await.unwrap();
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM tx_aborted_test", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "the aborted transaction left nothing behind");

    clean(&pool, &["tx_aborted_test"], &[]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn commit_checked_reports_a_commit_time_constraint_failure() {
    // A deferred constraint passes the probe (the transaction is healthy) and
    // fails at `COMMIT` itself, which PostgreSQL reports as an error — the
    // checked commit surfaces it as `DbError::Postgres`, never `Ok`.
    let pool = build_pool();
    clean(&pool, &["tx_deferred_child", "tx_deferred_parent"], &[]).await;

    let client = pool.get().await.unwrap();
    client
        .batch_execute(
            "CREATE TABLE tx_deferred_parent (id INTEGER PRIMARY KEY);
             CREATE TABLE tx_deferred_child (parent_id INTEGER
                 REFERENCES tx_deferred_parent (id) DEFERRABLE INITIALLY DEFERRED)",
        )
        .await
        .unwrap();
    drop(client);

    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "INSERT INTO tx_deferred_child (parent_id) VALUES ($1)",
        &[&1_i32],
    )
    .await
    .unwrap();
    let result = commit_checked(tx).await;
    drop(client);

    let Err(DbError::Postgres(source)) = result else {
        panic!("expected a COMMIT-time Postgres error, got {result:?}");
    };
    assert_eq!(classify_pg_error(&source), PgErrorKind::ForeignKeyViolation);

    let client = pool.get().await.unwrap();
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM tx_deferred_child", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "the failed commit left nothing behind");

    clean(&pool, &["tx_deferred_child", "tx_deferred_parent"], &[]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn migration_runner_applies_two_namespaces() {
    const MIGRATIONS_A: &[Migration] = &[
        Migration {
            name: "create_alpha",
            sql: "CREATE TABLE m_apply_alpha (id SERIAL PRIMARY KEY, name TEXT NOT NULL)",
        },
        Migration {
            name: "add_alpha_index",
            sql: "CREATE INDEX idx_m_apply_alpha_name ON m_apply_alpha (name)",
        },
    ];
    const MIGRATIONS_B: &[Migration] = &[Migration {
        name: "create_beta",
        sql: "CREATE TABLE m_apply_beta (id UUID PRIMARY KEY DEFAULT gen_random_uuid())",
    }];

    let pool = build_pool();
    clean(
        &pool,
        &["m_apply_alpha", "m_apply_beta"],
        &["fuz_db_test_apply_alpha", "fuz_db_test_apply_beta"],
    )
    .await;

    let namespaces = [
        MigrationNamespace::new("fuz_db_test_apply_alpha", MIGRATIONS_A),
        MigrationNamespace::new("fuz_db_test_apply_beta", MIGRATIONS_B),
    ];

    let results = run_migrations(&pool, &namespaces).await.unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].namespace, "fuz_db_test_apply_alpha");
    assert_eq!(
        results[0].applied_names,
        vec!["create_alpha", "add_alpha_index"]
    );
    assert_eq!(results[1].namespace, "fuz_db_test_apply_beta");
    assert_eq!(results[1].applied_names, vec!["create_beta"]);

    // Re-running is idempotent: both namespaces are up-to-date so the
    // result list is empty.
    let results = run_migrations(&pool, &namespaces).await.unwrap();
    assert!(
        results.is_empty(),
        "expected idempotent re-run, got {results:?}"
    );

    // Verify schema_version rows.
    let client = pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT name, sequence FROM schema_version WHERE namespace = $1 ORDER BY sequence",
            &[&"fuz_db_test_apply_alpha"],
        )
        .await
        .unwrap();
    let names: Vec<String> = rows.iter().map(|r| r.get::<_, String>(0)).collect();
    let seqs: Vec<i32> = rows.iter().map(|r| r.get::<_, i32>(1)).collect();
    assert_eq!(names, vec!["create_alpha", "add_alpha_index"]);
    assert_eq!(seqs, vec![0, 1]);

    drop(client);
    clean(
        &pool,
        &["m_apply_alpha", "m_apply_beta"],
        &["fuz_db_test_apply_alpha", "fuz_db_test_apply_beta"],
    )
    .await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn query_ready_columns_reports_columns_and_drift() {
    // Base migration creates the table; an APPENDED migration adds the column
    // (the append-migration discipline `fuz_auth::migrations` documents). The
    // readiness probe should then see the full column set on a fresh bootstrap.
    const MIGRATIONS: &[Migration] = &[
        Migration {
            name: "create_ready_probe",
            sql: "CREATE TABLE m_ready_probe (id SERIAL PRIMARY KEY, name TEXT NOT NULL)",
        },
        Migration {
            name: "add_ready_probe_deleted_at",
            sql: "ALTER TABLE m_ready_probe ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ",
        },
    ];

    let pool = build_pool();
    clean(&pool, &["m_ready_probe"], &["fuz_db_test_ready"]).await;

    run_migrations(
        &pool,
        &[MigrationNamespace::new("fuz_db_test_ready", MIGRATIONS)],
    )
    .await
    .unwrap();

    let client = pool.get().await.unwrap();
    let live = query_ready_columns(&client, "public").await.unwrap();

    // The probe sees the appended column on a fresh bootstrap...
    assert_eq!(
        live.get("m_ready_probe"),
        Some(&vec![
            "deleted_at".to_owned(),
            "id".to_owned(),
            "name".to_owned(),
        ]),
    );
    // ...and keeps schema_version (unlike query_schema_snapshot) so a
    // never-migrated DB fails readiness.
    assert!(
        live.contains_key("schema_version"),
        "query_ready_columns keeps the schema_version tracker"
    );

    let expect = |cols: &[&str]| -> BTreeMap<String, Vec<String>> {
        let mut m = BTreeMap::new();
        m.insert(
            "m_ready_probe".to_owned(),
            cols.iter().map(|c| (*c).to_owned()).collect(),
        );
        m
    };

    // Live covers the expected subset → ready.
    assert!(check_schema_drift(&live, &expect(&["id", "name", "deleted_at"])).ok);

    // A column the deployed code expects but the DB lacks → drift (the outage
    // class: an in-place base-DDL edit that never reached this DB).
    let drift = check_schema_drift(&live, &expect(&["id", "name", "deleted_at", "absent_col"]));
    assert!(!drift.ok);
    assert_eq!(drift.missing_columns.len(), 1);
    assert_eq!(drift.missing_columns[0].columns, vec!["absent_col"]);

    // An expected table the DB lacks → drift.
    let mut absent_table = BTreeMap::new();
    absent_table.insert("m_ready_absent".to_owned(), vec!["id".to_owned()]);
    let drift = check_schema_drift(&live, &absent_table);
    assert!(!drift.ok);
    assert_eq!(drift.missing_tables, vec!["m_ready_absent"]);

    drop(client);
    clean(&pool, &["m_ready_probe"], &["fuz_db_test_ready"]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn migration_runner_detects_name_divergence() {
    const CANONICAL: &[Migration] = &[Migration {
        name: "create_diverge",
        sql: "CREATE TABLE m_diverge (id SERIAL PRIMARY KEY, name TEXT NOT NULL)",
    }];
    const DIVERGED: &[Migration] = &[Migration {
        name: "renamed_diverge",
        sql: "CREATE TABLE m_diverge (id SERIAL)",
    }];

    let pool = build_pool();
    clean(&pool, &["m_diverge"], &["fuz_db_test_diverge"]).await;

    // Apply the canonical chain.
    run_migrations(
        &pool,
        &[MigrationNamespace::new("fuz_db_test_diverge", CANONICAL)],
    )
    .await
    .unwrap();

    // Now run with a divergent first-name and expect the runner to
    // refuse with name-divergence-at-N.
    let err = run_migrations(
        &pool,
        &[MigrationNamespace::new("fuz_db_test_diverge", DIVERGED)],
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("name-divergence-at-N"),
        "expected name-divergence error, got: {msg}"
    );
    match err {
        DbError::Migration(MigrationError::Diverged {
            namespace,
            divergence: Divergence::NameMismatch { position: 0, .. },
        }) => assert_eq!(namespace, "fuz_db_test_diverge"),
        other => panic!("expected a name-mismatch divergence, got {other:?}"),
    }

    clean(&pool, &["m_diverge"], &["fuz_db_test_diverge"]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn migration_runner_detects_binary_older_than_db() {
    const FULL: &[Migration] = &[
        Migration {
            name: "older_step_one",
            sql: "CREATE TABLE m_older (id SERIAL PRIMARY KEY)",
        },
        Migration {
            name: "older_step_two",
            sql: "ALTER TABLE m_older ADD COLUMN name TEXT",
        },
    ];
    const SHORTER: &[Migration] = &[Migration {
        name: "older_step_one",
        sql: "CREATE TABLE m_older (id SERIAL PRIMARY KEY)",
    }];

    let pool = build_pool();
    clean(&pool, &["m_older"], &["fuz_db_test_older"]).await;

    // Apply the full chain.
    run_migrations(&pool, &[MigrationNamespace::new("fuz_db_test_older", FULL)])
        .await
        .unwrap();

    // Now run with a shorter code-side chain and expect the runner to
    // refuse with binary-older-than-db.
    let err = run_migrations(
        &pool,
        &[MigrationNamespace::new("fuz_db_test_older", SHORTER)],
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("binary-older-than-db"),
        "expected binary-older-than-db error, got: {msg}"
    );
    match err {
        DbError::Migration(MigrationError::Diverged {
            divergence: Divergence::BinaryOlder { declared, unknown },
            ..
        }) => {
            assert_eq!(declared, 1);
            assert_eq!(unknown, ["older_step_two"]);
        }
        other => panic!("expected a binary-older divergence, got {other:?}"),
    }

    clean(&pool, &["m_older"], &["fuz_db_test_older"]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn baseline_records_names_without_executing() {
    let pool = build_pool();
    clean(&pool, &["gamma_test"], &["fuz_db_test_gamma"]).await;

    const MIGRATIONS_C: &[Migration] = &[
        Migration {
            name: "step_one",
            sql: "CREATE TABLE gamma_test (id SERIAL)",
        },
        Migration {
            name: "step_two",
            sql: "ALTER TABLE gamma_test ADD COLUMN name TEXT",
        },
    ];
    let ns = MigrationNamespace::new("fuz_db_test_gamma", MIGRATIONS_C);

    // Baseline as if step_one had already been applied out of band.
    baseline(&pool, &ns, &["step_one"]).await.unwrap();

    // schema_version reflects the baseline.
    let client = pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT name FROM schema_version WHERE namespace = $1",
            &[&"fuz_db_test_gamma"],
        )
        .await
        .unwrap();
    let names: Vec<String> = rows.iter().map(|r| r.get::<_, String>(0)).collect();
    assert_eq!(names, vec!["step_one"]);

    // gamma_test was NOT created by baseline — the body wasn't executed.
    let table_exists: bool = client
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'gamma_test'
            )",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!table_exists, "baseline must not execute migration bodies");

    drop(client);
    clean(&pool, &["gamma_test"], &["fuz_db_test_gamma"]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn advisory_lock_smoke_two_concurrent_boots() {
    // Smoke test: two concurrent run_migrations calls on the same
    // namespace must converge to the same end state. With the
    // advisory-lock + chain-tx + PK guard, the loser either no-ops
    // (already-applied case) or hits PK violation and rolls back.
    let pool = build_pool();
    clean(&pool, &["delta_test"], &["fuz_db_test_delta"]).await;

    const MIGRATIONS_D: &[Migration] = &[Migration {
        name: "create_delta",
        sql: "CREATE TABLE delta_test (id SERIAL PRIMARY KEY)",
    }];
    // Spawn two concurrent runners. Both should complete; at most one
    // returns a MigrationResult with applied_names (the winner), or
    // both may report empty (if the second arrives after the first
    // commits and the lock-released window lets it through with a
    // clean already-applied probe).
    let pool_clone = pool.clone();
    let h1 = tokio::spawn(async move {
        run_migrations(
            &pool_clone,
            &[MigrationNamespace::new("fuz_db_test_delta", MIGRATIONS_D)],
        )
        .await
    });
    let pool_clone = pool.clone();
    let h2 = tokio::spawn(async move {
        run_migrations(
            &pool_clone,
            &[MigrationNamespace::new("fuz_db_test_delta", MIGRATIONS_D)],
        )
        .await
    });

    let r1 = h1.await.unwrap();
    let r2 = h2.await.unwrap();

    // Both must succeed. The combined applied_names across both runs
    // either contains "create_delta" once (winner+loser-skip) or once
    // (winner+loser-pk-rollback retry path). What must NOT happen is
    // the migration applying twice — `(namespace, name)` PK guarantees
    // that.
    let r1_names: Vec<&String> = r1
        .as_ref()
        .map(|results| results.iter().flat_map(|r| &r.applied_names).collect())
        .unwrap_or_default();
    let r2_names: Vec<&String> = r2
        .as_ref()
        .map(|results| results.iter().flat_map(|r| &r.applied_names).collect())
        .unwrap_or_default();

    // At least one boot succeeds outright. The other either succeeds
    // (no work) or fails with a PK-violation rollback (acceptable
    // semantics — caller can retry and observe up-to-date state).
    let total = r1_names.len() + r2_names.len();
    assert!(
        total <= 1,
        "create_delta applied {total} times across two boots; advisory lock + PK guard violated"
    );
    assert!(
        r1.is_ok() || r2.is_ok(),
        "expected at least one runner to succeed"
    );

    // Final state: delta_test exists, schema_version has exactly one row.
    let client = pool.get().await.unwrap();
    let rows = client
        .query(
            "SELECT name FROM schema_version WHERE namespace = $1",
            &[&"fuz_db_test_delta"],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "expected exactly one tracker row");

    drop(client);
    clean(&pool, &["delta_test"], &["fuz_db_test_delta"]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn pg_error_classification_unique_violation() {
    let pool = build_pool();
    clean(&pool, &["pg_err_uniq"], &[]).await;

    let client = pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE pg_err_uniq (id INT PRIMARY KEY)")
        .await
        .unwrap();
    client
        .execute("INSERT INTO pg_err_uniq (id) VALUES ($1)", &[&1_i32])
        .await
        .unwrap();
    let err = client
        .execute("INSERT INTO pg_err_uniq (id) VALUES ($1)", &[&1_i32])
        .await
        .unwrap_err();

    assert!(is_pg_unique_violation(&err));
    assert_eq!(classify_pg_error(&err), PgErrorKind::UniqueViolation);
    // the code is found behind a wrapper's `source()` too
    assert_eq!(sqlstate_in_chain(&err), Some("23505"));
    assert_eq!(sqlstate_in_chain(&DbError::Postgres(err)), Some("23505"));

    drop(client);
    clean(&pool, &["pg_err_uniq"], &[]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn pg_error_classification_foreign_key_violation() {
    let pool = build_pool();
    clean(&pool, &["pg_err_fk_child", "pg_err_fk_parent"], &[]).await;

    let client = pool.get().await.unwrap();
    client
        .batch_execute(
            "CREATE TABLE pg_err_fk_parent (id INT PRIMARY KEY);
             CREATE TABLE pg_err_fk_child (
                id INT PRIMARY KEY,
                parent_id INT NOT NULL REFERENCES pg_err_fk_parent(id)
             )",
        )
        .await
        .unwrap();
    let err = client
        .execute(
            "INSERT INTO pg_err_fk_child (id, parent_id) VALUES ($1, $2)",
            &[&1_i32, &999_i32],
        )
        .await
        .unwrap_err();

    assert!(!is_pg_unique_violation(&err));
    assert_eq!(classify_pg_error(&err), PgErrorKind::ForeignKeyViolation);

    drop(client);
    clean(&pool, &["pg_err_fk_child", "pg_err_fk_parent"], &[]).await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn pg_error_classification_restrict_violation() {
    let pool = build_pool();
    clean(
        &pool,
        &["pg_err_restrict_child", "pg_err_restrict_parent"],
        &[],
    )
    .await;

    let client = pool.get().await.unwrap();
    client
        .batch_execute(
            "CREATE TABLE pg_err_restrict_parent (id INT PRIMARY KEY);
             CREATE TABLE pg_err_restrict_child (
                id INT PRIMARY KEY,
                parent_id INT NOT NULL
                    REFERENCES pg_err_restrict_parent(id) ON DELETE RESTRICT
             );
             INSERT INTO pg_err_restrict_parent (id) VALUES (1);
             INSERT INTO pg_err_restrict_child (id, parent_id) VALUES (1, 1);",
        )
        .await
        .unwrap();
    let err = client
        .execute(
            "DELETE FROM pg_err_restrict_parent WHERE id = $1",
            &[&1_i32],
        )
        .await
        .unwrap_err();

    // PG 18+ raises 23001 restrict_violation for `ON DELETE RESTRICT`;
    // PG ≤17 raises 23503 foreign_key_violation for the same refusal — a
    // caller refusing a referencing-row delete must accept either kind, so
    // this pins the classification without pinning the server version.
    let kind = classify_pg_error(&err);
    assert!(
        matches!(
            kind,
            PgErrorKind::RestrictViolation | PgErrorKind::ForeignKeyViolation
        ),
        "RESTRICT delete refusal must classify as a referencing-row violation, got {kind:?}",
    );

    drop(client);
    clean(
        &pool,
        &["pg_err_restrict_child", "pg_err_restrict_parent"],
        &[],
    )
    .await;
}

#[test]
fn sql_identifier_rejects_injection_attempts() {
    // Pure unit-level — duplicates the in-file tests so the integration
    // surface guarantees the export is wired correctly.
    assert!(assert_valid_sql_identifier("account").is_ok());
    assert!(assert_valid_sql_identifier("schema_version").is_ok());
    assert!(assert_valid_sql_identifier("users; DROP TABLE accounts").is_err());
    assert!(assert_valid_sql_identifier("users--").is_err());
    assert!(assert_valid_sql_identifier("1table").is_err());
    assert!(assert_valid_sql_identifier("").is_err());
}

/// A consumer namespace bearing a reserved spine name is refused before the
/// runner touches the database, naming the namespace — the pool here points at
/// nothing, so reaching it would fail differently. A spine-built namespace
/// under an unreserved name is refused the same way.
#[tokio::test]
async fn reserved_namespace_rejection() {
    assert_eq!(RESERVED_NAMESPACES, ["fuz_auth", "fuz_cell", "fuz_facts"]);
    let pool = create_pool(
        "postgres://nobody@127.0.0.1:1/never",
        &fuz_db::PoolOptions::default(),
    )
    .expect("lazy pool");
    for name in RESERVED_NAMESPACES {
        let consumer_list = [
            MigrationNamespace::new("my_app", &[]),
            MigrationNamespace::new(name, &[]),
        ];
        let err = run_migrations(&pool, &consumer_list)
            .await
            .expect_err("a consumer namespace under a reserved name is refused");
        assert!(
            matches!(&err, DbError::Migration(MigrationError::NamespaceReserved { namespace }) if namespace == name)
                && err.to_string().contains(&format!("\"{name}\""))
                && err.to_string().contains("reserved"),
            "refusal names the namespace: {err:?}",
        );
        let err = baseline(&pool, &MigrationNamespace::new(name, &[]), &[])
            .await
            .expect_err("baseline refuses it too");
        assert!(
            matches!(
                &err,
                DbError::Migration(MigrationError::NamespaceReserved { .. })
            ) && err.to_string().contains("reserved"),
            "{err:?}"
        );
    }
    let err = run_migrations(&pool, &[MigrationNamespace::spine("my_app", &[])])
        .await
        .expect_err("a spine-built namespace must use a reserved name");
    assert!(
        matches!(&err, DbError::Migration(MigrationError::NamespaceNotReserved { namespace }) if namespace == "my_app")
            && err.to_string().contains("\"my_app\""),
        "{err:?}"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn schema_snapshot_is_deterministic_and_shaped() {
    const MIGRATIONS: &[Migration] = &[
        Migration {
            name: "create_snap",
            sql: "CREATE TABLE snap_test (\
                  id SERIAL PRIMARY KEY, \
                  name TEXT NOT NULL, \
                  note TEXT)",
        },
        Migration {
            name: "index_snap_name",
            sql: "CREATE INDEX idx_snap_test_name ON snap_test (name)",
        },
    ];

    let pool = build_pool();
    clean(&pool, &["snap_test"], &["fuz_db_test_snapshot"]).await;
    run_migrations(
        &pool,
        &[MigrationNamespace::new("fuz_db_test_snapshot", MIGRATIONS)],
    )
    .await
    .unwrap();

    let client = pool.get().await.unwrap();

    // Determinism: two reads of the same DB state are byte-identical.
    let a = query_schema_snapshot(&client, "public", &[]).await.unwrap();
    let b = query_schema_snapshot(&client, "public", &[]).await.unwrap();
    assert_eq!(a, b, "snapshot must be deterministic");

    // Shape: the table and its columns are captured with correct nullability.
    let table = a.tables.get("snap_test").expect("snap_test present");
    assert!(table.columns.contains_key("id"));
    assert!(
        !table.columns.get("name").unwrap().is_nullable,
        "name is NOT NULL"
    );
    assert!(
        table.columns.get("note").unwrap().is_nullable,
        "note is nullable"
    );
    // SERIAL → int4 udt_name + a nextval default (not an IDENTITY column).
    let id = table.columns.get("id").unwrap();
    assert_eq!(id.udt_name, "int4");
    assert!(
        id.column_default
            .as_deref()
            .unwrap_or("")
            .contains("nextval")
    );
    assert!(!id.is_identity);

    // The PRIMARY KEY constraint is captured with the expanded kind.
    assert!(
        table.constraints.iter().any(|c| c.kind == "PRIMARY KEY"),
        "expected a PRIMARY KEY constraint, got {:?}",
        table.constraints
    );
    // The explicit index is captured (the PK's implicit index too).
    assert!(table.indexes.iter().any(|i| i.name == "idx_snap_test_name"));

    // SERIAL created a sequence.
    assert!(
        a.sequences
            .keys()
            .any(|k| k.starts_with("snap_test_id_seq")),
        "expected snap_test_id_seq, got {:?}",
        a.sequences.keys().collect::<Vec<_>>()
    );

    // The schema_version migration tracker is never present in `tables`.
    assert!(
        !a.tables.contains_key("schema_version"),
        "schema_version tracker must be excluded from tables"
    );

    // exclude_tables drops the table from the snapshot.
    let excluded = query_schema_snapshot(&client, "public", &["snap_test"])
        .await
        .unwrap();
    assert!(
        !excluded.tables.contains_key("snap_test"),
        "snap_test excluded"
    );

    drop(client);
    clean(&pool, &["snap_test"], &["fuz_db_test_snapshot"]).await;
}

/// Seed one `schema_version` row directly — a tracker history the runner would
/// never write (a renamed or binary-older chain), for the status reader to read.
async fn seed_tracker_row(pool: &Pool, namespace: &str, name: &str, sequence: i32) {
    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO schema_version (namespace, name, sequence) VALUES ($1, $2, $3)",
            &[&namespace, &name, &sequence],
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn query_db_status_reads_each_namespace_from_the_tracker() {
    const CLEAN: &[Migration] = &[Migration {
        name: "create_status_widget",
        sql: "CREATE TABLE status_widget (id INTEGER)",
    }];
    const TWO: &[Migration] = &[
        Migration {
            name: "m0",
            sql: "",
        },
        Migration {
            name: "m1",
            sql: "",
        },
    ];
    const RENAMED: &[Migration] = &[Migration {
        name: "full_cell_schema",
        sql: "",
    }];
    const NAMESPACES: &[&str] = &[
        "fuz_db_test_status_clean",
        "fuz_db_test_status_pending",
        "fuz_db_test_status_diverged",
        "fuz_db_test_status_older",
    ];

    let pool = build_pool();
    clean(&pool, &["status_widget"], NAMESPACES).await;

    // The clean namespace migrates for real, which also creates the tracker.
    let clean_ns = MigrationNamespace::new("fuz_db_test_status_clean", CLEAN);
    run_migrations(&pool, &[clean_ns]).await.unwrap();
    pool.get()
        .await
        .unwrap()
        .batch_execute("INSERT INTO status_widget (id) VALUES (1), (2), (3)")
        .await
        .unwrap();
    seed_tracker_row(&pool, "fuz_db_test_status_pending", "m0", 0).await;
    seed_tracker_row(&pool, "fuz_db_test_status_diverged", "cell_v0", 0).await;
    for (sequence, name) in (0..).zip(["m0", "m1", "m2_unknown"]) {
        seed_tracker_row(&pool, "fuz_db_test_status_older", name, sequence).await;
    }

    let status = query_db_status(
        &pool,
        &[
            clean_ns,
            MigrationNamespace::new("fuz_db_test_status_pending", TWO),
            MigrationNamespace::new("fuz_db_test_status_diverged", RENAMED),
            MigrationNamespace::new("fuz_db_test_status_older", TWO),
        ],
    )
    .await
    .unwrap();

    // The shared database holds other tests' tables too — look up by name.
    assert_eq!(status.table_count, status.tables.len());
    let widget = status
        .tables
        .iter()
        .find(|t| t.name == "status_widget")
        .expect("status_widget listed");
    assert_eq!(widget.row_count, 3);
    assert!(status.tables.iter().any(|t| t.name == "schema_version"));

    let namespaces: Vec<&str> = status
        .migrations
        .iter()
        .map(|m| m.namespace.as_str())
        .collect();
    assert_eq!(namespaces, NAMESPACES, "in the order passed");
    let [clean_m, pending_m, diverged_m, older_m] = status.migrations.as_slice() else {
        panic!("one status per namespace");
    };
    assert!(clean_m.up_to_date);
    assert_eq!(clean_m.applied_names, ["create_status_widget"]);
    assert_eq!(clean_m.divergence, None);
    assert!(!pending_m.up_to_date);
    assert_eq!(pending_m.pending_names, ["m1"]);
    assert_eq!(pending_m.divergence, None);
    assert!(!diverged_m.up_to_date);
    assert_eq!(
        diverged_m.divergence,
        Some(Divergence::NameMismatch {
            position: 0,
            applied: "cell_v0".to_owned(),
            expected: "full_cell_schema".to_owned(),
        })
    );
    assert!(!older_m.up_to_date);
    assert!(older_m.pending_names.is_empty());
    assert_eq!(
        older_m.divergence,
        Some(Divergence::BinaryOlder {
            declared: 2,
            unknown: vec!["m2_unknown".to_owned()],
        })
    );

    // The migrations section renders from the tracker alone, so it pins exactly
    // even though the table list above it depends on what else is in the DB.
    let report = format_db_status(&status);
    let (_, migrations) = report
        .split_once("  migrations:\n")
        .expect("migrations header");
    assert_eq!(
        migrations,
        "    fuz_db_test_status_clean     up-to-date   1/1  latest: create_status_widget
    fuz_db_test_status_pending   PENDING 1    1/2  latest: m0
                                   pending: m1
    fuz_db_test_status_diverged  DIVERGED     1/1  latest: cell_v0
                                   diverged: position 0: database has `cell_v0`, code has `full_cell_schema`
    fuz_db_test_status_older     DIVERGED     3/2  latest: m2_unknown
                                   diverged: database has 3 applied but code declares 2 (binary older than database)
"
    );

    clean(&pool, &["status_widget"], NAMESPACES).await;
}

/// `url` with its database name swapped for `name` (query string kept).
fn database_url_with_name(url: &str, name: &str) -> String {
    let path_start = url.find("://").map_or(0, |i| i + 3);
    let db_start = url[path_start..]
        .find('/')
        .map_or(url.len(), |i| path_start + i);
    let db_end = url[db_start..]
        .find('?')
        .map_or(url.len(), |i| db_start + i);
    format!("{}/{name}{}", &url[..db_start], &url[db_end..])
}

#[test]
fn database_url_with_name_swaps_only_the_database() {
    assert_eq!(
        database_url_with_name("postgres://localhost/fuz_db_test", "scratch"),
        "postgres://localhost/scratch"
    );
    assert_eq!(
        database_url_with_name(
            "postgres://u:p@localhost:5432/fuz_db_test?sslmode=disable",
            "scratch"
        ),
        "postgres://u:p@localhost:5432/scratch?sslmode=disable"
    );
}

/// A database this test creates empty and drops after, so the reader meets a
/// database with no `schema_version` at all. Dropping the shared tracker in
/// `fuz_db_test` instead would wipe every namespace's rows out from under the
/// other tests here (and `fuz_http`'s `ready` suite, which shares the
/// database). Needs `CREATEDB`; a run that panics leaves the database behind
/// and the next run drops it first.
const SCRATCH_DATABASE: &str = "fuz_db_test_status_scratch";

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database and CREATEDB"]
async fn query_db_status_without_a_tracker_pends_every_namespace() {
    const FRESH: &[Migration] = &[
        Migration {
            name: "m0",
            sql: "",
        },
        Migration {
            name: "m1",
            sql: "",
        },
    ];
    let drop_scratch = format!("DROP DATABASE IF EXISTS {SCRATCH_DATABASE} WITH (FORCE)");

    let admin_pool = build_pool();
    let admin = admin_pool.get().await.unwrap();
    admin.batch_execute(&drop_scratch).await.unwrap();
    admin
        .batch_execute(&format!(
            "CREATE DATABASE {SCRATCH_DATABASE} TEMPLATE template0"
        ))
        .await
        .unwrap();

    let scratch_pool = create_pool(
        &database_url_with_name(&test_database_url(), SCRATCH_DATABASE),
        &fuz_db::PoolOptions::default(),
    )
    .unwrap();
    let status = query_db_status(&scratch_pool, &[MigrationNamespace::new("fresh", FRESH)]).await;
    drop(scratch_pool);
    admin.batch_execute(&drop_scratch).await.unwrap();
    let status = status.unwrap();

    assert_eq!(status.table_count, 0);
    assert!(status.tables.is_empty());
    let [fresh] = status.migrations.as_slice() else {
        panic!("one status per namespace");
    };
    assert!(fresh.applied_names.is_empty());
    assert_eq!(fresh.pending_names, ["m0", "m1"]);
    assert!(!fresh.up_to_date);
    assert_eq!(fresh.divergence, None);

    assert_eq!(
        format_db_status(&status),
        "  tables: 0

  migrations:
    fresh  PENDING 2    0/2  latest: (none)
             pending: m0, m1
"
    );
}
