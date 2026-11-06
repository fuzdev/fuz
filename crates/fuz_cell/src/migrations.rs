//! Cell subsystem migration namespace.
//!
//! Ships [`CELL_MIGRATIONS`] (`"fuz_cell"`) — the `cell` content primitive +
//! `cell_grant` / `cell_field` / `cell_item` siblings — which consumers
//! splice into [`fuz_db::run_migrations`] after [`fuz_auth::AUTH_MIGRATIONS`]
//! (`cell` FKs into `actor`, so `AUTH_MIGRATIONS` must precede it in the
//! runner's namespace slice).
//!
//! Migration names are descriptive (`full_cell_schema`) — identity, not an
//! ordinal; the `schema_version.sequence` column carries order. The
//! namespace matches the TS shape byte-for-byte (`fuz_app` `db/cell_ddl.ts`)
//! so the two spines record identical tracker rows and a DB bootstrapped by
//! one boots clean on the other. Migration
//! shapes are pre-stable; consumers re-bootstrap dev/test DBs on schema
//! changes per the workspace policy.

use fuz_db::{Migration, MigrationNamespace};

/// Reserved namespace name — matches [`fuz_db::RESERVED_NAMESPACES`].
///
/// Consumers splice [`CELL_MIGRATIONS`] ahead of their own namespaces and
/// must not reuse this name (`fuz_db::run_migrations` refuses a consumer
/// namespace bearing it).
pub const CELL_MIGRATIONS_NAMESPACE: &str = "fuz_cell";

/// Initial DDL: the `cell` content primitive + the `cell_grant` /
/// `cell_field` / `cell_item` sibling tables + the `cell_visibility`
/// enum, byte-identical with the TS backend's DDL for schema-snapshot
/// parity.
const FULL_CELL_SCHEMA: &str = include_str!("migrations/full_cell_schema.sql");

/// Flat ordered migration list. Append-only post-publish; pre-stable
/// today (drop + re-bootstrap dev DBs on schema changes).
const MIGRATIONS: &[Migration] = &[Migration {
    name: "full_cell_schema",
    sql: FULL_CELL_SCHEMA,
}];

/// Cell migration namespace ready to splice into the runner.
///
/// ```ignore
/// use fuz_cell::CELL_MIGRATIONS;
/// use fuz_auth::AUTH_MIGRATIONS;
/// use fuz_db::run_migrations;
///
/// // FK order: auth (creates `actor`) → cell.
/// run_migrations(&pool, &[AUTH_MIGRATIONS, CELL_MIGRATIONS]).await?;
/// ```
pub const CELL_MIGRATIONS: MigrationNamespace =
    MigrationNamespace::spine(CELL_MIGRATIONS_NAMESPACE, MIGRATIONS);

/// The cell chain's columns registry.
///
/// The four tables [`CELL_MIGRATIONS`] creates, each mapped to its
/// `*_COLUMNS` const. No exemptions — every cell-chain table has row-shaped
/// reads. Composed by `tests/columns.rs` registries via
/// `fuz_db::column_projection_mismatches_merged`.
pub const CELL_COLUMN_PROJECTIONS: fuz_db::ColumnProjections = fuz_db::ColumnProjections {
    projections: &[
        ("cell", &crate::cell_queries::CELL_COLUMNS),
        ("cell_grant", &crate::cell_grant_queries::CELL_GRANT_COLUMNS),
        ("cell_field", &crate::cell_field_queries::CELL_FIELD_COLUMNS),
        ("cell_item", &crate::cell_item_queries::CELL_ITEM_COLUMNS),
    ],
    exempt: &[],
};

/// Every table [`CELL_MIGRATIONS`] creates, children first.
///
/// What a `testing_*` server's `_testing_reset` splices ahead of its own
/// tables (`fuz_testing::truncate_reset_state`), so a table the chain adds is
/// emptied between tests everywhere. Twin of `fuz_app`'s `CELL_DROP_TABLES` (`db/cell_ddl.ts`).
pub const CELL_DROP_TABLES: &[&str] = &["cell_field", "cell_item", "cell_grant", "cell"];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The const names exactly the tables the chain's DDL leaves behind, and
    /// the tables of the columns registry (held to the live schema by
    /// `tests/columns.rs`).
    #[test]
    fn the_drop_tables_cover_every_table_the_chain_creates() {
        let consts: BTreeSet<String> = CELL_DROP_TABLES.iter().map(|t| (*t).to_owned()).collect();
        assert_eq!(consts.len(), CELL_DROP_TABLES.len(), "a table listed twice");
        assert_eq!(
            consts,
            fuz_testing::migration_created_tables(&CELL_MIGRATIONS),
            "CELL_DROP_TABLES vs the DDL"
        );
        let registry: BTreeSet<String> = CELL_COLUMN_PROJECTIONS
            .projections
            .iter()
            .map(|(table, _)| *table)
            .chain(CELL_COLUMN_PROJECTIONS.exempt.iter().copied())
            .map(str::to_owned)
            .collect();
        assert_eq!(
            consts, registry,
            "CELL_DROP_TABLES vs CELL_COLUMN_PROJECTIONS"
        );
    }
}
