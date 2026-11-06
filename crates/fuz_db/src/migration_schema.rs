//! Migration data types: [`Migration`], [`MigrationNamespace`],
//! [`MigrationResult`], the reserved-namespace registry.
//!
//! Identity-tracked: `(namespace, name, sequence, applied_at)`, matching
//! `fuz_app`'s `db/migrate.ts`. The runner verifies the
//! applied list is a strict name-prefix of the code's migration array
//! at boot — see [`crate::migration::run_migrations`] for the
//! algorithm.

use crate::error::{DbError, MigrationError};

/// Reserved namespace names.
///
/// The spine crates own these, each shipping its namespace through
/// [`MigrationNamespace::spine`] for consumers to splice ahead of their own:
/// `fuz_auth` (auth surface), `fuz_cell` (cell substrate), and `fuz_facts`
/// (fact substrate). [`crate::run_migrations`] refuses a namespace bearing one
/// of these names unless the spine crate built it, so a consumer can't mint a
/// name whose tracker rows collide with a spine chain's.
pub const RESERVED_NAMESPACES: &[&str] = &["fuz_auth", "fuz_cell", "fuz_facts"];

/// A single migration: a stable `name` + an SQL `sql` body applied via
/// `client.batch_execute` inside the runner's chain transaction.
///
/// `name` is **descriptive identity, not a version ordinal** (`full_cell_schema`,
/// not `cell_v0`): the runner orders by the `sequence` column and matches `name`
/// by position, so a `_vN` suffix would only duplicate `sequence`. It is half
/// the `schema_version` PK, so it must match the TS twin byte-for-byte (the
/// swap-freely invariant).
///
/// Array index = position in the chain. **Pre-stable**: bodies, names,
/// and positions can change between versions; consumers re-bootstrap
/// dev/test databases on schema-changing upgrades. See
/// `fuz_app/src/lib/db/migrate.ts` module doc.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Stable identity recorded in the `schema_version` tracker.
    pub name: &'static str,
    /// DDL body applied via `client.batch_execute`. Multiple statements
    /// in one string are supported.
    pub sql: &'static str,
}

/// A named group of ordered migrations.
///
/// Built with [`Self::new`] (a consumer namespace) or [`Self::spine`] (a spine
/// crate's own); the private ownership flag keeps a struct literal from
/// skipping that choice.
#[derive(Debug, Clone, Copy)]
pub struct MigrationNamespace {
    /// Namespace key. A [`Self::new`] namespace must not use a
    /// [`RESERVED_NAMESPACES`] name — [`crate::migration::run_migrations`]
    /// refuses it before touching the database.
    pub name: &'static str,
    /// Migrations in execution order. Array index = position in the chain.
    pub migrations: &'static [Migration],
    /// Set by [`Self::spine`] only: the namespace is a spine crate's own.
    spine_owned: bool,
}

impl MigrationNamespace {
    /// Construct a consumer `MigrationNamespace` (`const`-friendly). Its name
    /// must not be one of [`RESERVED_NAMESPACES`].
    #[must_use]
    pub const fn new(name: &'static str, migrations: &'static [Migration]) -> Self {
        Self {
            name,
            migrations,
            spine_owned: false,
        }
    }

    /// Construct a spine crate's own namespace — the one form the runner
    /// admits under a [`RESERVED_NAMESPACES`] name, and it must use one. For
    /// `fuz_auth`, `fuz_cell`, and `fuz_fact` (and their tests that run a
    /// prefix of the chain); consumer code uses [`Self::new`].
    #[must_use]
    pub const fn spine(name: &'static str, migrations: &'static [Migration]) -> Self {
        Self {
            name,
            migrations,
            spine_owned: true,
        }
    }
}

/// Result of running migrations for a single namespace.
///
/// Already-up-to-date namespaces are **omitted** from the runner's
/// return value rather than carrying an empty `applied_names` entry.
#[derive(Debug, Clone)]
pub struct MigrationResult {
    /// Echoes [`MigrationNamespace::name`].
    pub namespace: &'static str,
    /// Migration names applied in this run, sequence-ascending.
    pub applied_names: Vec<String>,
}

/// Check that `ns` names a reserved namespace exactly when a spine crate built
/// it ([`MigrationNamespace::spine`]).
///
/// Used by the runner before it touches the database.
///
/// # Errors
///
/// Returns [`MigrationError::NamespaceReserved`] for a consumer namespace
/// bearing a reserved name, or [`MigrationError::NamespaceNotReserved`] for a
/// spine-built namespace bearing an unreserved one.
pub(crate) fn assert_namespace_ownership(ns: &MigrationNamespace) -> Result<(), DbError> {
    let name = ns.name;
    match (RESERVED_NAMESPACES.contains(&name), ns.spine_owned) {
        (true, false) => Err(MigrationError::NamespaceReserved {
            namespace: name.to_owned(),
        }
        .into()),
        (false, true) => Err(MigrationError::NamespaceNotReserved {
            namespace: name.to_owned(),
        }
        .into()),
        _ => Ok(()),
    }
}
