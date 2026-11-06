# fuz_db

PostgreSQL pool wrapper, identity-tracked migration runner, and query helpers
for the Rust spine.

Mirrors `fuz_app`'s TypeScript `db/` subsystem (pool wrapper, advisory-lock
migrations, `query_*` helpers over a borrowed client). PostgreSQL only —
there is no embedded backend (PGlite's role in fuz_app).

## Quick reference

```rust
use fuz_db::{
    commit_checked, create_pool, run_migrations, Migration, MigrationNamespace, PoolOptions,
};

// 1. Build a pool — every checkout bounded by `PoolOptions::checkout_timeout`.
let pool = create_pool("postgres://localhost/my_app", &PoolOptions::default())?;

// 2. Run migrations. `run_migrations` refuses a consumer namespace bearing a
//    reserved spine name (`RESERVED_NAMESPACES`).
const MIGRATIONS: &[Migration] = &[
    Migration {
        name: "create_widgets",
        sql: "CREATE TABLE widgets (id SERIAL PRIMARY KEY, name TEXT NOT NULL)",
    },
];
run_migrations(&pool, &[
    MigrationNamespace::new("my_app", MIGRATIONS),
]).await?;

// 3. Run a transaction. An early return drops `tx`, which rolls it back;
//    `commit_checked` refuses a transaction an earlier statement error
//    aborted, where a bare `tx.commit()` would roll it back silently.
let mut client = pool.get().await?;
let tx = client.transaction().await?;
tx.execute("INSERT INTO widgets (name) VALUES ($1)", &[&"foo"]).await?;
tx.execute("INSERT INTO widgets (name) VALUES ($1)", &[&"bar"]).await?;
commit_checked(tx).await?;
```

## Consumer pattern

Query helpers should accept a borrowed client and operate on it — no trait
abstraction layer. Mirrors `fuz_app`'s `QueryDeps` convention.

```rust
use tokio_postgres::GenericClient;

async fn query_widget_count(
    client: &(impl GenericClient + ?Sized),
) -> Result<i64, tokio_postgres::Error> {
    let row = client.query_one("SELECT COUNT(*) FROM widgets", &[]).await?;
    Ok(row.get(0))
}
```

The same function works against a `&deadpool_postgres::Client` (read path) or
a `&tokio_postgres::Transaction<'_>` (mutation path).

## Public API

The crate root exports the pool (`Pool`, `PoolClient`, `create_pool`),
`commit_checked`, the migration runner (`run_migrations`, `baseline`,
`Migration` / `MigrationNamespace` / `MigrationResult`, `RESERVED_NAMESPACES`,
`assert_migration_namespaces`), SQL-identifier validation, SQLSTATE
classification (`PgErrorKind`, `classify_pg_error`), `UntypedTextParam`, schema
readiness / snapshot / status queries, the column-projection drift guard, and
`DbError`. Item docs: `cargo doc -p fuz_db`.

## Testing

`cargo test -p fuz_db` runs the unit tests. The integration tests need a real
PostgreSQL and are `#[ignore]`, so `cargo test --workspace` stays green without
one: `createdb fuz_db_test`, then
`cargo test -p fuz_db -- --ignored --test-threads=1`
(`FUZ_DB_TEST_URL` to point elsewhere). The status test creates and drops its
own scratch database beside it, so the test role needs `CREATEDB`. CI runs them
in the `db-tests` job.

## See also

- [`fuz_app/src/lib/db/`](https://github.com/fuzdev/fuz_app/tree/main/src/lib/db) —
  the TS twin; the twins converge on the better shape and match observably.
