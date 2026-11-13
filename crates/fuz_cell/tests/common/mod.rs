//! Shared test setup for `fuz_cell`'s PG-backed integration tests.
//!
//! Lives under `tests/common/` so Cargo doesn't compile it as its own
//! test binary — each integration test file includes it via `mod common;`.
//! Modeled on `fuz_auth/tests/common/mod.rs`.
//!
//! These tests are `--ignored`-gated (they need a reachable Postgres);
//! run them with `cargo test -p fuz_cell -- --ignored --test-threads=1`.
//! The pool points at a single shared `fuz_cell_test` database (override
//! with `FUZ_CELL_TEST_URL`), so the suite runs single-threaded —
//! concurrent DROP+CREATE on `schema_version` would race. The shared cycle
//! lives in `fuz_testing::fresh_db`.

use fuz_auth::AUTH_MIGRATIONS;
use fuz_cell::CELL_MIGRATIONS;
use fuz_db::Pool;
use fuz_testing::{TestingDbOptions, fresh_test_db_pool, seed_account_actor};

/// This suite's database: `FUZ_CELL_TEST_URL` (default `fuz_cell_test`) over
/// the crate's full DDL surface in FK order — auth first (`cell` FKs into
/// `actor`), then cell.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_CELL_TEST_URL",
    default_db: "fuz_cell_test",
    migrations: &[AUTH_MIGRATIONS, CELL_MIGRATIONS],
    setup_sql: None,
};

/// Reset the `public` schema, then run the auth + cell + cell-history
/// chains. Returns a `Pool` ready for fixture seeding.
pub async fn fresh_db_pool() -> Pool {
    fresh_test_db_pool(DB).await
}

/// Seed an `account` + `actor` pair and return the actor id — the value
/// `created_by` / `updated_by` FK into.
///
/// Drops the account id from `fuz_testing::seed_account_actor`: no cell test
/// needs account-grain identity, so the narrower return keeps the callsites to
/// one binding.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn seed_actor(pool: &Pool, username: &str) -> uuid::Uuid {
    seed_account_actor(pool, username).await.1
}
