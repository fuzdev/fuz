//! Fact + memo + possession migration namespace.
//!
//! The namespace is `fuz_facts` (matching the canonical TS
//! `FACT_MIGRATION_NAMESPACE`). It is **not** a reserved namespace, so a
//! consumer splices it in via `run_migrations` alongside the others — **after
//! `fuz_auth`**: `fact_holder.actor_id` references the auth schema's `actor`
//! table (an SQL edge only; the crate still depends on no auth code).
//!
//! **The released chain is frozen — every schema change ships as an appended
//! migration.** Migrations are tracked by `(namespace, name)` with no
//! checksum, so editing a released entry's SQL in place never reruns on a
//! database that already recorded it: the change silently never lands there.
//! Never edit, rename, reorder, or re-purpose an entry in `MIGRATIONS`; add
//! each change as a new appended `Migration` with idempotent DDL, so a fresh
//! bootstrap and a deployed database converge on the same shape. Every entry
//! is twinned with `fuz_app`'s fact migrations at the same position, names
//! byte for byte (the `_testing_migration_tracker` parity gate compares the
//! recorded rows).

use fuz_db::{Migration, MigrationNamespace};

/// Namespace key for the fact + memo tables. Matches the canonical TS
/// `FACT_MIGRATION_NAMESPACE`.
pub const FACT_MIGRATIONS_NAMESPACE: &str = "fuz_facts";

/// Initial DDL: `fact`, `fact_ref`, `memo`. Frozen — see the module doc.
const FULL_FACT_SCHEMA: &str = include_str!("migrations/full_fact_schema.sql");

/// `fact_holder` — which actors hold which facts, the possession record cell
/// ref admission reads. FKs into `actor` (auth) and `fact`, both cascading.
/// `created_at` is the holder's most recent put, not the first.
const FACT_HOLDER: &str = include_str!("migrations/fact_holder.sql");

/// Flat ordered migration list. **Frozen + append-only** — see the module doc.
const MIGRATIONS: &[Migration] = &[
    Migration {
        name: "full_fact_schema",
        sql: FULL_FACT_SCHEMA,
    },
    Migration {
        name: "fact_holder",
        sql: FACT_HOLDER,
    },
];

/// The fact migration namespace. Consumers splice this into
/// [`fuz_db::run_migrations`] — e.g.
/// `run_migrations(&pool, &[fuz_auth::AUTH_MIGRATIONS, fuz_cell::CELL_MIGRATIONS, fuz_fact::FACT_MIGRATIONS])`.
pub const FACT_MIGRATIONS: MigrationNamespace =
    MigrationNamespace::spine(FACT_MIGRATIONS_NAMESPACE, MIGRATIONS);

/// The fact chain's columns registry.
///
/// `fact` and `fact_holder` map to their `*_COLUMNS` consts; `fact_ref` (the
/// edge table, read as `target_hash` lists, never as rows) and `memo`
/// (reserved for `MemoStore` — no reads yet) are exempt. Composed by
/// `tests/columns.rs` registries via
/// `fuz_db::column_projection_mismatches_merged`.
pub const FACT_COLUMN_PROJECTIONS: fuz_db::ColumnProjections = fuz_db::ColumnProjections {
    projections: &[
        ("fact", &crate::fact_queries::FACT_COLUMNS),
        (
            "fact_holder",
            &crate::fact_holder_queries::FACT_HOLDER_COLUMNS,
        ),
    ],
    exempt: &["fact_ref", "memo"],
};

/// Every table [`FACT_MIGRATIONS`] creates, children first.
///
/// What a `testing_*` server's `_testing_reset` splices ahead of its own
/// tables (`fuz_testing::truncate_reset_state`), so a table the chain adds is
/// emptied between tests everywhere. Twin of `fuz_app`'s `FACT_DROP_TABLES` (`db/fact_ddl.ts`).
pub const FACT_DROP_TABLES: &[&str] = &["fact_holder", "memo", "fact_ref", "fact"];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The const names exactly the tables the chain's DDL leaves behind, and
    /// the tables of the columns registry (held to the live schema by
    /// `tests/columns.rs`).
    #[test]
    fn the_drop_tables_cover_every_table_the_chain_creates() {
        let consts: BTreeSet<String> = FACT_DROP_TABLES.iter().map(|t| (*t).to_owned()).collect();
        assert_eq!(consts.len(), FACT_DROP_TABLES.len(), "a table listed twice");
        assert_eq!(
            consts,
            fuz_testing::migration_created_tables(&FACT_MIGRATIONS),
            "FACT_DROP_TABLES vs the DDL"
        );
        let registry: BTreeSet<String> = FACT_COLUMN_PROJECTIONS
            .projections
            .iter()
            .map(|(table, _)| *table)
            .chain(FACT_COLUMN_PROJECTIONS.exempt.iter().copied())
            .map(str::to_owned)
            .collect();
        assert_eq!(
            consts, registry,
            "FACT_DROP_TABLES vs FACT_COLUMN_PROJECTIONS"
        );
    }
}
