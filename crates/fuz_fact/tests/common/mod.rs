//! Shared setup for `fuz_fact`'s PG-backed integration tests.
//!
//! Lives under `tests/common/` so Cargo doesn't compile it as its own test
//! binary — included via `mod common;`. Each test opens a database of its own
//! through `fuz_testing::fresh_test_db`.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use fuz_auth::AUTH_MIGRATIONS;
use fuz_db::Pool;
use fuz_fact::{FACT_MIGRATIONS, PutOptions};
use fuz_testing::{TestDb, TestEngine, TestingDbOptions, fresh_test_db};
use uuid::Uuid;

/// This suite's database: the auth chain (`fact_holder` FKs into `actor`) then the fact chain, plus a
/// minimal `cell` stub — the `(refs, deleted_at)` columns the orphan queries
/// read. The orphan predicate is cell-coupled, but `fuz_fact` has no
/// `fuz_cell` dep, so the suite stands up a stub instead of pulling the cell
/// schema.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    suite: "fuz_fact",
    migrations: &[AUTH_MIGRATIONS, FACT_MIGRATIONS],
    setup_sql: Some("CREATE TABLE cell (refs TEXT[], deleted_at TIMESTAMPTZ)"),
    engine: TestEngine::Any,
};

/// A fresh database with the auth + fact chains and the `cell` stub, ready for
/// the store.
pub async fn fresh_db() -> TestDb {
    fresh_test_db(DB).await
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
