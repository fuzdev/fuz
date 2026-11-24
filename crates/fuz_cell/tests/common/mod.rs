//! Shared test setup for `fuz_cell`'s PG-backed integration tests.
//!
//! Lives under `tests/common/` so Cargo doesn't compile it as its own
//! test binary — each integration test file includes it via `mod common;`.
//! Modeled on `fuz_auth/tests/common/mod.rs`.
//!
//! Each test opens a database of its own through `fuz_testing::fresh_test_db`.

use fuz_auth::AUTH_MIGRATIONS;
use fuz_cell::CELL_MIGRATIONS;
use fuz_db::Pool;
use fuz_testing::{TestDb, TestEngine, TestingDbOptions, fresh_test_db, seed_account_actor};

/// This suite's database: the crate's full DDL surface in FK order — auth first (`cell` FKs into
/// `actor`), then cell.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    suite: "fuz_cell",
    migrations: &[AUTH_MIGRATIONS, CELL_MIGRATIONS],
    setup_sql: None,
    engine: TestEngine::Any,
};

/// A fresh database with the auth and cell chains, ready for fixture seeding.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn fresh_db() -> TestDb {
    fresh_test_db(DB).await
}

/// [`fresh_db`] on PostgreSQL alone, for a test of what only PostgreSQL has.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn fresh_postgres_db() -> TestDb {
    fresh_test_db(DB.postgres_only()).await
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
