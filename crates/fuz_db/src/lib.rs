//! `fuz_db` — `PostgreSQL` pool wrapper, migration runner, and query helpers.
//!
//! Mirrors `fuz_app`'s TypeScript `db/` subsystem
//! (pool wrapper, advisory-lock identity-tracked migrations, `query_*`
//! helpers over a borrowed client). `PostgreSQL` only — there is no Rust
//! analog of `PGlite`, so tests run against a real database.
//!
//! ## Consumer pattern
//!
//! Consumers (the spine servers and `testing_spine_stub`) build a [`Pool`] via
//! [`create_pool`] at startup and pass `&Client` (or `&Transaction`)
//! to their query functions. No trait abstraction layer — query
//! functions are generic over `&(impl GenericClient + ?Sized)` per
//! `fuz_app`'s `QueryDeps` convention. An action handler holds its request's
//! handle as an [`ActionDb`] (a pooled client or the request's transaction)
//! and runs those generic query functions over it with
//! [`action_db_dispatch!`].
//!
//! ## Bring-up
//!
//! Integration tests require a local `PostgreSQL` with a `fuz_db_test`
//! database:
//!
//! ```text
//! createdb fuz_db_test
//! cargo test -p fuz_db -- --ignored --test-threads=1
//! ```
//!
//! One test creates and drops a scratch database beside `fuz_db_test`, so the
//! test role needs `CREATEDB`.
//!
//! Override with `FUZ_DB_TEST_URL=postgres://...`.

pub mod action_db;
pub mod column_projections;
pub mod error;
pub mod migration;
pub mod migration_schema;
pub mod pg_error;
pub mod pg_param;
pub mod pool;
pub mod schema_ready;
pub mod schema_snapshot;
pub mod sql_helpers;
pub mod sql_identifier;
pub mod status;

pub use action_db::ActionDb;
pub use column_projections::{
    ColumnProjections, DB_COLUMN_PROJECTIONS, column_projection_mismatches,
    column_projection_mismatches_merged, columns_not_in,
};
pub use error::{DbError, MigrationError};
pub use migration::{assert_migration_namespaces, baseline, run_migrations};
pub use migration_schema::{Migration, MigrationNamespace, MigrationResult, RESERVED_NAMESPACES};
pub use pg_error::{PgErrorKind, classify_pg_error, is_pg_unique_violation, sqlstate_in_chain};
pub use pg_param::UntypedTextParam;
pub use pool::{
    DEFAULT_AUDIT_CHECKOUT_TIMEOUT, DEFAULT_CHECKOUT_TIMEOUT, Pool, PoolClient, PoolOptions,
    checkout_timeouts, commit_checked, create_pool,
};
pub use schema_ready::{
    ExpectedSchema, MissingColumns, SchemaDriftResult, check_schema_drift, format_schema_drift,
    query_ready_columns,
};
pub use schema_snapshot::{
    ColumnSnapshot, ConstraintSnapshot, EnumSnapshot, IndexSnapshot, SchemaSnapshot,
    SequenceSnapshot, TableSnapshot, query_schema_snapshot,
};
pub use sql_helpers::{
    column_index, iso8601_timestamp_column, iso8601_timestamp_expr, omit_columns, qualify_columns,
};
pub use sql_identifier::{assert_valid_sql_identifier, is_valid_sql_identifier};
pub use status::{
    DbStatus, Divergence, MigrationStatus, TableStatus, format_db_status, query_db_status,
};

/// Re-export of `tokio_postgres` so consumers don't need to declare the
/// dependency themselves when working with row decoders or `GenericClient`
/// bounds.
pub use tokio_postgres;

/// Re-export of `deadpool_postgres` for consumers that need to construct
/// custom pool configurations.
pub use deadpool_postgres;
