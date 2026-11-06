//! Registry guard for the fact chain's projection constants: every live
//! table is either a `*_COLUMNS` const naming exactly its live columns or a
//! reasoned exemption.
//!
//! Composes `fuz_db`'s tracker set and `fuz_auth`'s set (the fixture runs the
//! auth chain first — `fact_holder` FKs into `actor`) with this crate's
//! exported [`fuz_fact::FACT_COLUMN_PROJECTIONS`] (which carries the
//! `fact_ref` / `memo` exemptions), plus a local exemption for the two-column `cell`
//! stub `common::fresh_db_pool` stands up for the cell-coupled orphan
//! predicate (`fuz_cell` owns the real table and its const). The assertion
//! over the composed registry is the shared
//! [`fuz_testing::assert_column_projections`]. Twin of the fact half of
//! `fuz_app`'s `column_projections.db.test.ts`.
//!
//! `--ignored`-gated (needs Postgres):
//!
//! ```sh
//! cargo test -p fuz_fact --test columns -- --ignored
//! ```

mod common;

use common::fresh_db_pool;
use fuz_auth::AUTH_COLUMN_PROJECTIONS;
use fuz_db::{ColumnProjections, DB_COLUMN_PROJECTIONS};
use fuz_fact::FACT_COLUMN_PROJECTIONS;
use fuz_testing::assert_column_projections;

/// The fixture's `cell` stub — not a fact-chain table.
const FIXTURE_STUB: ColumnProjections = ColumnProjections {
    projections: &[],
    exempt: &["cell"],
};

#[tokio::test]
#[ignore = "needs Postgres"]
async fn columns_match_live_schema() {
    let pool = fresh_db_pool().await;
    assert_column_projections(
        &pool,
        &[
            DB_COLUMN_PROJECTIONS,
            AUTH_COLUMN_PROJECTIONS,
            FACT_COLUMN_PROJECTIONS,
            FIXTURE_STUB,
        ],
    )
    .await;
}
