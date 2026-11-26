//! Integration tests for `fuz_db` against a live database, a fresh one per
//! test (`fuz_testing::fresh_test_db`): pglet by default, PostgreSQL under
//! `FUZ_TEST_POSTGRES_URL`. The tests that observe what only PostgreSQL has
//! (backend cancellation, lock waits) run on it alone.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]
#![expect(
    clippy::items_after_statements,
    reason = "tests declare their fixture items beside the statements that use them"
)]

use std::collections::BTreeMap;

use fuz_db::{
    DbError, Divergence, Migration, MigrationError, MigrationNamespace, PgErrorKind, Pool,
    RESERVED_NAMESPACES, assert_valid_sql_identifier, baseline, check_schema_drift,
    classify_pg_error, commit_checked, format_db_status, is_pg_unique_violation, query_db_status,
    query_ready_columns, query_schema_snapshot, run_migrations, sqlstate_in_chain,
};
use fuz_testing::{TestEngine, TestingDbOptions};

/// A bare database: no migration chain, no tracker.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    suite: "fuz_db",
    migrations: &[],
    setup_sql: None,
    engine: TestEngine::Any,
};

#[tokio::test]
async fn pool_acquire_works() {
    let pool = DB.open().await;
    let client = pool.get().await.expect("pool get");
    let row = client.query_one("SELECT 42::int4 as v", &[]).await.unwrap();
    let v: i32 = row.get("v");
    assert_eq!(v, 42);
}

#[tokio::test]
async fn commit_checked_commits_a_healthy_transaction() {
    let pool = DB.open().await;

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
}

#[tokio::test]
async fn transaction_rolls_back_when_an_error_drops_it() {
    let pool = DB.open().await;

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
}

#[tokio::test]
async fn a_healthy_transaction_dropped_before_commit_rolls_back() {
    // An early return on a non-database error leaves the transaction healthy,
    // so only the drop's rollback keeps the insert from persisting.
    let pool = DB.open().await;

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
}

#[tokio::test]
async fn commit_checked_refuses_a_transaction_a_swallowed_error_aborted() {
    // Code that drops a failed statement's error and carries on leaves the
    // transaction aborted. `COMMIT` would roll it back without an error;
    // the checked commit reports it instead, and nothing persists.
    let pool = DB.open().await;

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
}

#[tokio::test]
#[ignore = "pglet: DEFERRABLE constraints"]
async fn commit_checked_reports_a_commit_time_constraint_failure() {
    // A deferred constraint passes the probe (the transaction is healthy) and
    // fails at `COMMIT` itself, which PostgreSQL reports as an error — the
    // checked commit surfaces it as `DbError::Postgres`, never `Ok`.
    let pool = DB.postgres_only().open().await;

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
}

#[tokio::test]
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

    let pool = DB.open().await;

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
}

#[tokio::test]
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

    let pool = DB.open().await;

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
}

#[tokio::test]
async fn migration_runner_detects_name_divergence() {
    const CANONICAL: &[Migration] = &[Migration {
        name: "create_diverge",
        sql: "CREATE TABLE m_diverge (id SERIAL PRIMARY KEY, name TEXT NOT NULL)",
    }];
    const DIVERGED: &[Migration] = &[Migration {
        name: "renamed_diverge",
        sql: "CREATE TABLE m_diverge (id SERIAL)",
    }];

    let pool = DB.open().await;

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
}

#[tokio::test]
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

    let pool = DB.open().await;

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
}

#[tokio::test]
async fn baseline_records_names_without_executing() {
    let pool = DB.open().await;

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
}

#[tokio::test]
#[ignore = "postgres-only: stalls concurrent boots with pg_sleep"]
async fn advisory_lock_two_concurrent_boots_both_succeed() {
    // Two runners on one namespace at once, the chain held open by a sleep
    // after its DDL so the two overlap. The advisory lock serializes them:
    // the second waits for the first's commit, reads the migration applied,
    // and succeeds with nothing to do. Without the lock both chains run the
    // `CREATE TABLE` and the loser fails on the catalog's unique index.
    let pool = DB.postgres_only().open().await;

    const MIGRATIONS_D: &[Migration] = &[Migration {
        name: "create_delta",
        sql: "CREATE TABLE delta_test (id SERIAL PRIMARY KEY); SELECT pg_sleep(0.3)",
    }];
    let boot = |pool: Pool| {
        tokio::spawn(async move {
            run_migrations(
                &pool,
                &[MigrationNamespace::new("fuz_db_test_delta", MIGRATIONS_D)],
            )
            .await
        })
    };
    let h1 = boot(pool.clone());
    let h2 = boot(pool.clone());
    let r1 = h1.await.unwrap().expect("first concurrent boot");
    let r2 = h2.await.unwrap().expect("second concurrent boot");

    let applied: Vec<&String> = r1
        .iter()
        .chain(&r2)
        .flat_map(|r| &r.applied_names)
        .collect();
    assert_eq!(
        applied,
        ["create_delta"],
        "one boot applies, the other finds it applied"
    );
}

#[tokio::test]
#[ignore = "postgres-only: reads pg_locks"]
async fn migration_waits_on_the_ts_twins_namespace_lock() {
    // The TS twin takes `pg_advisory_xact_lock` on the same `bigint` key
    // inside its chain transaction. Held here in that form, it keeps this
    // runner waiting until the holder commits — the key's value and the
    // lock's `bigint` binding pinned against a real server. The key is
    // djb2 of the namespace, sign-extended (`namespace_lock_key`).
    const NAMESPACE: &str = "fuz_db_test_lock_wait";
    const KEY: i64 = -1_425_090_598;
    let pool = DB.postgres_only().open().await;

    let mut holder = pool.get().await.expect("holder: pool get");
    let tx = holder.transaction().await.expect("holder: begin");
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&KEY])
        .await
        .expect("holder: lock");

    const MIGRATIONS: &[Migration] = &[Migration {
        name: "create_lock_wait",
        sql: "CREATE TABLE lock_wait_test (id INT)",
    }];
    let runner_pool = pool.clone();
    let runner = tokio::spawn(async move {
        run_migrations(
            &runner_pool,
            &[MigrationNamespace::new(NAMESPACE, MIGRATIONS)],
        )
        .await
    });

    // the runner is seen waiting on an advisory lock, not finished
    let observer = pool.get().await.expect("observer: pool get");
    let mut waiting = false;
    for _ in 0..200 {
        let row = observer
            .query_one(
                "SELECT count(*) FROM pg_locks
                 WHERE locktype = 'advisory' AND NOT granted
                   AND classid = (($1::bigint >> 32) & 4294967295)::oid
                   AND objid = ($1::bigint & 4294967295)::oid
                   AND objsubid = 1",
                &[&KEY],
            )
            .await
            .expect("observer: pg_locks");
        if row.get::<_, i64>(0) > 0 {
            waiting = true;
            break;
        }
        assert!(
            !runner.is_finished(),
            "the runner finished while the lock was held"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(
        waiting,
        "the runner never waited on the namespace's advisory lock"
    );
    assert!(!runner.is_finished());

    tx.commit().await.expect("holder: commit");
    let results = runner
        .await
        .unwrap()
        .expect("runner after the holder commits");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].applied_names, ["create_lock_wait"]);

    drop(observer);
    drop(holder);
}

#[tokio::test]
#[ignore = "postgres-only: cancels a backend (pg_cancel_backend)"]
async fn a_failed_namespace_lock_names_the_namespace_and_keeps_its_sqlstate() {
    // The runner waits on a lock held here until an observer cancels its
    // wait, failing the lock statement with `57014`. The run fails naming
    // the namespace, with the driver error (and its code) as the source.
    const NAMESPACE: &str = "fuz_db_test_lock_fail";
    // djb2 of the namespace, sign-extended (`namespace_lock_key`).
    const KEY: i64 = -1_425_701_535;
    let pool = DB.postgres_only().open().await;

    let mut holder = pool.get().await.expect("holder: pool get");
    let tx = holder.transaction().await.expect("holder: begin");
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&KEY])
        .await
        .expect("holder: lock");

    const MIGRATIONS: &[Migration] = &[Migration {
        name: "create_lock_fail",
        sql: "CREATE TABLE lock_fail_test (id INT)",
    }];
    let runner_pool = pool.clone();
    let runner = tokio::spawn(async move {
        run_migrations(
            &runner_pool,
            &[MigrationNamespace::new(NAMESPACE, MIGRATIONS)],
        )
        .await
    });

    let observer = pool.get().await.expect("observer: pool get");
    let mut cancelled = false;
    for _ in 0..200 {
        let row = observer
            .query_one(
                "SELECT count(pg_cancel_backend(pid)) FROM pg_locks
                 WHERE locktype = 'advisory' AND NOT granted
                   AND classid = (($1::bigint >> 32) & 4294967295)::oid
                   AND objid = ($1::bigint & 4294967295)::oid
                   AND objsubid = 1",
                &[&KEY],
            )
            .await
            .expect("observer: cancel the waiter");
        if row.get::<_, i64>(0) > 0 {
            cancelled = true;
            break;
        }
        assert!(
            !runner.is_finished(),
            "the runner finished while the lock was held"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(cancelled, "the runner never waited on the namespace's lock");

    let err = runner
        .await
        .unwrap()
        .expect_err("a cancelled lock fails the run");
    let DbError::Migration(migration_err) = err else {
        panic!("expected a migration error, got {err:?}");
    };
    assert_eq!(sqlstate_in_chain(&migration_err), Some("57014"));
    let MigrationError::LockFailed { namespace, source } = &migration_err else {
        panic!("expected LockFailed, got {migration_err:?}");
    };
    assert_eq!(namespace, NAMESPACE);
    assert_eq!(
        source.code(),
        Some(&tokio_postgres::error::SqlState::QUERY_CANCELED)
    );
    assert!(
        migration_err
            .to_string()
            .starts_with("migration-lock-failed: namespace \"fuz_db_test_lock_fail\""),
        "{migration_err}"
    );

    tx.commit().await.expect("holder: commit");
    drop(observer);
    drop(holder);
    // nothing ran: the namespace has no rows and the table was never created
    let client = pool.get().await.expect("check: pool get");
    let rows = client
        .query(
            "SELECT 1 FROM schema_version WHERE namespace = $1",
            &[&NAMESPACE],
        )
        .await
        .expect("check: tracker rows");
    assert!(rows.is_empty());
    drop(client);
}

#[tokio::test]
async fn pg_error_classification_unique_violation() {
    let pool = DB.open().await;

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
}

#[tokio::test]
async fn pg_error_classification_foreign_key_violation() {
    let pool = DB.open().await;

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
}

#[tokio::test]
async fn pg_error_classification_restrict_violation() {
    let pool = DB.open().await;

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
    let pool = fuz_testing::unreachable_pool();
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

    let pool = DB.open().await;
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

    let pool = DB.open().await;

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

    // Look up by name: the status lists every table the chains created.
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
}

/// A fresh database has no `schema_version` at all, so the reader meets every
/// namespace pending.
#[tokio::test]
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
    let pool = DB.open().await;
    let status = query_db_status(&pool, &[MigrationNamespace::new("fresh", FRESH)]).await;
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
