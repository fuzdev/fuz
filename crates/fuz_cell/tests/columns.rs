//! Registry guard for the per-table projection constants over the auth +
//! cell migration chains: every live table is either a `*_COLUMNS` const
//! naming exactly its live columns or a reasoned exemption.
//!
//! Composes the chains' exported registries — `fuz_db`'s tracker set,
//! `fuz_auth`'s, and this crate's [`fuz_cell::CELL_COLUMN_PROJECTIONS`] — so
//! a table added to any chain reaches this guard through the one set its
//! crate exports; the assertion over them is the shared
//! [`fuz_testing::assert_column_projections`].
//! Twin of `fuz_app`'s `src/test/db/column_projections.db.test.ts` (minus the
//! fact tables, which `fuz_fact` migrates and guards separately).
//!
//! `--ignored`-gated (needs Postgres):
//!
//! ```sh
//! cargo test -p fuz_cell --test columns -- --ignored
//! ```

mod common;

use common::fresh_db_pool;
use fuz_auth::AUTH_COLUMN_PROJECTIONS;
use fuz_cell::CELL_COLUMN_PROJECTIONS;
use fuz_db::DB_COLUMN_PROJECTIONS;
use fuz_testing::assert_column_projections;

#[tokio::test]
#[ignore = "needs Postgres"]
async fn columns_match_live_schema() {
    let pool = fresh_db_pool().await;
    assert_column_projections(
        &pool,
        &[
            DB_COLUMN_PROJECTIONS,
            AUTH_COLUMN_PROJECTIONS,
            CELL_COLUMN_PROJECTIONS,
        ],
    )
    .await;
}
