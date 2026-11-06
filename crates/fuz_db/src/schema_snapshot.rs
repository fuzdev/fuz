//! Postgres schema introspection — a normalized, comparable snapshot of
//! a database's structure for cross-impl parity checks.
//!
//! Rust twin of `fuz_app`'s `testing/schema_introspect.ts`. Produces the
//! same logical shape (tables → columns / indexes / constraints, and
//! sequences) so a Rust backend's
//! snapshot can be diffed against the TS reference's by the shared
//! `assert_schema_snapshots_equal` comparator (which keys on names +
//! compares field values, so ordering between the two is irrelevant).
//!
//! Lives in `fuz_db` (not a test crate) as a reusable introspection
//! primitive; the JSON serialization that the cross-backend
//! `_testing_schema_snapshot` action emits lives in `fuz_testing`, which
//! keeps `fuz_db` free of a serde dependency.
//!
//! Every `information_schema` / `pg_catalog` column is cast `::text`
//! before decode — those catalogs use domain types (`sql_identifier`,
//! `yes_or_no`, `"char"`) that `tokio_postgres` won't map to `String`
//! directly.

use std::collections::BTreeMap;

use deadpool_postgres::GenericClient;

use crate::error::DbError;

/// Per-column structural metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnSnapshot {
    /// SQL-standard type name (`information_schema.columns.data_type`).
    pub data_type: String,
    /// Postgres-native type name (`udt_name`) — distinguishes `int4`
    /// (SERIAL) from `int8` (BIGSERIAL) where `data_type` collapses both.
    pub udt_name: String,
    /// `true` when the column accepts NULL.
    pub is_nullable: bool,
    /// Default-value expression as Postgres reports it, or `None`.
    pub column_default: Option<String>,
    /// `true` when declared `GENERATED ... AS IDENTITY`.
    pub is_identity: bool,
}

/// One index definition, as `pg_indexes.indexdef` renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSnapshot {
    pub name: String,
    pub definition: String,
}

/// One constraint definition, as `pg_get_constraintdef` renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintSnapshot {
    pub name: String,
    /// Human-readable kind (`PRIMARY KEY`, `FOREIGN KEY`, …) — the
    /// expanded form of `pg_constraint.contype`.
    pub kind: String,
    pub definition: String,
}

/// Per-table structural metadata. Columns keyed by name; indexes +
/// constraints sorted by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSnapshot {
    pub columns: BTreeMap<String, ColumnSnapshot>,
    pub indexes: Vec<IndexSnapshot>,
    pub constraints: Vec<ConstraintSnapshot>,
}

/// Sequence metadata — `data_type` is `bigint` (BIGSERIAL) or `integer`
/// (SERIAL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceSnapshot {
    pub data_type: String,
}

/// Enum-type metadata — the labels of a `CREATE TYPE ... AS ENUM`, captured
/// in `pg_enum.enumsortorder` (declaration) order.
///
/// Order is significant: a
/// Postgres enum's labels are an ordered set, so the parity diff compares the
/// arrays positionally.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnumSnapshot {
    /// Enum labels in declared order.
    pub labels: Vec<String>,
}

/// Normalized database schema snapshot for parity comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaSnapshot {
    /// Tables keyed by name.
    pub tables: BTreeMap<String, TableSnapshot>,
    /// Sequences keyed by name.
    pub sequences: BTreeMap<String, SequenceSnapshot>,
    /// Enum types (`CREATE TYPE ... AS ENUM`) keyed by name; labels in
    /// declared order.
    pub enums: BTreeMap<String, EnumSnapshot>,
}

/// Expand `pg_constraint.contype` into the human-readable kind, matching
/// the TS `contype_to_kind`.
fn contype_to_kind(contype: &str) -> String {
    match contype {
        "p" => "PRIMARY KEY",
        "f" => "FOREIGN KEY",
        "u" => "UNIQUE",
        "c" => "CHECK",
        "x" => "EXCLUSION",
        "t" => "TRIGGER",
        other => other,
    }
    .to_owned()
}

/// Introspect a live database into a deterministic [`SchemaSnapshot`].
///
/// `schema` is the namespace to read (typically `"public"`).
/// `exclude_tables` drops tables from the snapshot. The `schema_version`
/// migration tracker is always excluded from `tables` — it's framework
/// bookkeeping created by the migration runner, identical across impls,
/// and not part of any consumer's domain schema.
///
/// # Errors
///
/// Returns [`DbError`] on any query failure.
pub async fn query_schema_snapshot<C>(
    client: &C,
    schema: &str,
    exclude_tables: &[&str],
) -> Result<SchemaSnapshot, DbError>
where
    C: GenericClient + Sync + ?Sized,
{
    // Base tables in the target schema, minus the excludes + schema_version.
    let table_names: Vec<String> = client
        .query(
            "SELECT table_name::text AS table_name FROM information_schema.tables \
             WHERE table_schema::text = $1 AND table_type::text = 'BASE TABLE' \
             ORDER BY table_name::text ASC",
            &[&schema],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>("table_name"))
        .filter(|name| name != "schema_version" && !exclude_tables.contains(&name.as_str()))
        .collect();

    // Columns — one query, grouped client-side by table.
    let column_rows = client
        .query(
            "SELECT table_name::text AS table_name, column_name::text AS column_name, \
                    data_type::text AS data_type, udt_name::text AS udt_name, \
                    is_nullable::text AS is_nullable, column_default::text AS column_default, \
                    is_identity::text AS is_identity \
             FROM information_schema.columns WHERE table_schema::text = $1 \
             ORDER BY table_name::text ASC, ordinal_position ASC",
            &[&schema],
        )
        .await?;

    // Indexes — `indexdef` is the canonical re-emitted CREATE INDEX text.
    let index_rows = client
        .query(
            "SELECT tablename::text AS tablename, indexname::text AS indexname, indexdef \
             FROM pg_indexes WHERE schemaname::text = $1 \
             ORDER BY tablename::text ASC, indexname::text ASC",
            &[&schema],
        )
        .await?;

    // Constraints — `relname` gives the bare table name (no search_path
    // dependence); `pg_get_constraintdef` the canonical text rendering.
    let constraint_rows = client
        .query(
            // Skip NOT NULL constraints (`contype = 'n'`): PG17+ catalogs
            // them as named `pg_constraint` rows while PGlite / older PG
            // don't, and nullability is already captured per-column by
            // `is_nullable` — including them would report a pure
            // engine-cataloging artifact as cross-backend drift.
            "SELECT cls.relname::text AS table_name, c.conname::text AS conname, \
                    c.contype::text AS contype, pg_get_constraintdef(c.oid) AS definition \
             FROM pg_constraint c \
             JOIN pg_namespace n ON n.oid = c.connamespace \
             JOIN pg_class cls ON cls.oid = c.conrelid \
             WHERE n.nspname::text = $1 AND c.conrelid != 0 AND c.contype <> 'n' \
             ORDER BY table_name ASC, conname ASC",
            &[&schema],
        )
        .await?;

    let mut tables: BTreeMap<String, TableSnapshot> = BTreeMap::new();
    for name in table_names {
        let columns: BTreeMap<String, ColumnSnapshot> = column_rows
            .iter()
            .filter(|r| r.get::<_, String>("table_name") == name)
            .map(|r| {
                (
                    r.get::<_, String>("column_name"),
                    ColumnSnapshot {
                        data_type: r.get("data_type"),
                        udt_name: r.get("udt_name"),
                        is_nullable: r.get::<_, String>("is_nullable") == "YES",
                        column_default: r.get("column_default"),
                        is_identity: r.get::<_, String>("is_identity") == "YES",
                    },
                )
            })
            .collect();
        let indexes = index_rows
            .iter()
            .filter(|r| r.get::<_, String>("tablename") == name)
            .map(|r| IndexSnapshot {
                name: r.get("indexname"),
                definition: r.get("indexdef"),
            })
            .collect();
        let constraints = constraint_rows
            .iter()
            .filter(|r| r.get::<_, String>("table_name") == name)
            .map(|r| ConstraintSnapshot {
                name: r.get("conname"),
                kind: contype_to_kind(&r.get::<_, String>("contype")),
                definition: r.get("definition"),
            })
            .collect();
        tables.insert(
            name,
            TableSnapshot {
                columns,
                indexes,
                constraints,
            },
        );
    }

    let sequences = client
        .query(
            "SELECT sequence_name::text AS sequence_name, data_type::text AS data_type \
             FROM information_schema.sequences WHERE sequence_schema::text = $1 \
             ORDER BY sequence_name::text ASC",
            &[&schema],
        )
        .await?
        .iter()
        .map(|r| {
            (
                r.get::<_, String>("sequence_name"),
                SequenceSnapshot {
                    data_type: r.get("data_type"),
                },
            )
        })
        .collect();

    // Enum types — one row per label, ordered by enumsortorder; grouped
    // client-side so labels accumulate in declared order (mirrors columns).
    let mut enums: BTreeMap<String, EnumSnapshot> = BTreeMap::new();
    for row in client
        .query(
            "SELECT t.typname::text AS enum_name, e.enumlabel::text AS label \
             FROM pg_type t \
             JOIN pg_enum e ON e.enumtypid = t.oid \
             JOIN pg_namespace n ON n.oid = t.typnamespace \
             WHERE n.nspname::text = $1 \
             ORDER BY t.typname::text ASC, e.enumsortorder ASC",
            &[&schema],
        )
        .await?
    {
        enums
            .entry(row.get::<_, String>("enum_name"))
            .or_default()
            .labels
            .push(row.get::<_, String>("label"));
    }

    Ok(SchemaSnapshot {
        tables,
        sequences,
        enums,
    })
}
