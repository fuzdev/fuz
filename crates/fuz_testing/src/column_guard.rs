//! The column-projection drift assertion shared by the spine's
//! `tests/columns.rs` guards.
//!
//! Each migrating crate ships a `tests/columns.rs` pinning that every live
//! table is either a `*_COLUMNS` projection const naming exactly its columns or
//! a reasoned exemption. What varies between them is only the *registry* — which
//! [`ColumnProjections`] sets that crate's migration chains contribute, plus any
//! fixture-local exemption. The assertion itself (read the live `public` schema,
//! merge the sets, require no mismatches) is identical across them;
//! [`assert_column_projections`] is that body, and each guard keeps its own
//! registry declaration.
//!
//! Rust twin of the assertion inside `fuz_app`'s
//! `src/test/db/column_projections.db.test.ts`.

// A drift-guard harness: an unreachable pool or a failed introspection query is
// a setup fault whose only useful response is a loud panic naming the step.
// `clippy.toml`'s `allow-expect-in-tests` carve-out covers `#[test]` bodies, not
// a library module, so the allow is explicit.
#![allow(clippy::expect_used)]

use fuz_db::{ColumnProjections, Pool, column_projection_mismatches_merged, query_ready_columns};

/// Assert that `registries`, merged, describe the live `public` schema of
/// `pool` exactly — every table projected or exempt, every projection const
/// naming exactly its live columns, no stale entry.
///
/// `pool` is the suite's `fresh_test_db_pool` handle, so "live" means the
/// schema the crate's migration chains just built.
///
/// # Panics
///
/// Panics if the pool is unreachable or the introspection query fails (setup
/// faults), and — the point of the helper — asserts with every mismatch
/// message on one line each when the registry and the schema disagree.
pub async fn assert_column_projections(pool: &Pool, registries: &[ColumnProjections]) {
    let client = pool.get().await.expect("pool.get");
    let live = query_ready_columns(&client, "public")
        .await
        .expect("query_ready_columns");
    let mismatches = column_projection_mismatches_merged(&live, registries);
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
