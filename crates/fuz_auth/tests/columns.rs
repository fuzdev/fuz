//! Registry guard for the per-table projection constants: every live table
//! in the auth migration chain is either a `*_COLUMNS` const naming exactly
//! its live columns or a reasoned exemption.
//!
//! The named projection makes a *dropped* column fail loud at query time;
//! this covers the other direction — a column *added* to the DDL but not to
//! the projection would otherwise silently vanish from every read — and
//! forces every new table into a const-or-exemption decision. The registry
//! itself is the exported [`fuz_auth::AUTH_COLUMN_PROJECTIONS`] set, which
//! downstream `tests/columns.rs` registries (`fuz_cell`'s, the consumers')
//! compose rather than copy; the assertion over it is the shared
//! [`fuz_testing::assert_column_projections`]. Twin of `fuz_app`'s
//! `src/test/db/column_projections.db.test.ts`.
//!
//! `--ignored`-gated (needs Postgres):
//!
//! ```sh
//! cargo test -p fuz_auth --test columns -- --ignored
//! ```

mod common;

use common::fresh_db_pool;
use fuz_auth::AUTH_COLUMN_PROJECTIONS;
use fuz_db::DB_COLUMN_PROJECTIONS;
use fuz_testing::assert_column_projections;

#[tokio::test]
#[ignore = "needs Postgres"]
async fn columns_match_live_schema() {
    let pool = fresh_db_pool().await;
    assert_column_projections(&pool, &[DB_COLUMN_PROJECTIONS, AUTH_COLUMN_PROJECTIONS]).await;
}
