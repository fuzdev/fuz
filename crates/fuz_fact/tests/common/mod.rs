//! Shared setup for `fuz_fact`'s PG-backed integration tests.
//!
//! Lives under `tests/common/` so Cargo doesn't compile it as its own test
//! binary — included via `mod common;`. `--ignored`-gated (needs a reachable
//! Postgres); run with `cargo test -p fuz_fact -- --ignored --test-threads=1`.
//! Points at a single shared `fuz_fact_test` database (override with
//! `FUZ_FACT_TEST_URL`); single-threaded because the reset drops + recreates
//! the `public` schema. The shared cycle lives in `fuz_testing::fresh_db`.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use fuz_auth::AUTH_MIGRATIONS;
use fuz_db::Pool;
use fuz_fact::{FACT_MIGRATIONS, PutOptions};
use fuz_testing::{TestingDbOptions, fresh_test_db_pool};
use uuid::Uuid;

/// This suite's database: `FUZ_FACT_TEST_URL` (default `fuz_fact_test`), the
/// auth chain (`fact_holder` FKs into `actor`) then the fact chain, plus a
/// minimal `cell` stub — the `(refs, deleted_at)` columns the orphan queries
/// read. The orphan predicate is cell-coupled, but `fuz_fact` has no
/// `fuz_cell` dep, so the suite stands up a stub instead of pulling the cell
/// schema.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_FACT_TEST_URL",
    default_db: "fuz_fact_test",
    migrations: &[AUTH_MIGRATIONS, FACT_MIGRATIONS],
    setup_sql: Some("CREATE TABLE cell (refs TEXT[], deleted_at TIMESTAMPTZ)"),
};

/// Reset the `public` schema, run the auth + fact chains, and create the
/// `cell` stub.
/// Returns a `Pool` ready for the store.
pub async fn fresh_db_pool() -> Pool {
    fresh_test_db_pool(DB).await
}

/// Insert a `cell` stub row referencing `hash` (active unless `deleted` is
/// true), so the orphan predicate sees the fact as live.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn insert_cell_ref(pool: &Pool, hash: &str, deleted: bool) {
    let client = pool.get().await.expect("pool.get");
    let deleted_at: Option<&str> = if deleted {
        Some("2000-01-01T00:00:00Z")
    } else {
        None
    };
    client
        .execute(
            "INSERT INTO cell (refs, deleted_at) VALUES (ARRAY[$1]::text[], $2::text::timestamptz)",
            &[&hash, &deleted_at],
        )
        .await
        .expect("insert cell ref");
}

/// A system put's options — no holder, no refs, no content type.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub const fn system_put() -> PutOptions {
    PutOptions {
        content_type: None,
        refs: None,
        holder: None,
    }
}

/// A put on behalf of `actor` — no refs, no content type.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub const fn held_put(actor: Uuid) -> PutOptions {
    PutOptions {
        content_type: None,
        refs: None,
        holder: Some(actor),
    }
}
