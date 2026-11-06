//! Identity-tracked migration runner.
//!
//! Algorithm (ported from `fuz_app/src/lib/db/migrate.ts`):
//!
//! 1. Apply the `schema_version` DDL.
//! 2. For each namespace, hold a `pg_advisory_lock` keyed by a djb2 hash
//!    of the namespace name (best-effort — silently falls through on
//!    pools that don't support advisory locks).
//! 3. Read applied rows ordered by `sequence`. **Length-check before
//!    name-verify** — a binary-older case with a rename in the overlap
//!    would otherwise fire `name-divergence-at-N` first and the operator
//!    would chase a phantom source-revert.
//! 4. Name-prefix verify: applied names must equal the first
//!    `applied.len()` entries of the code's migration array.
//! 5. Run the pending tail in a single chain transaction. Each
//!    migration's row is inserted with `sequence = max(sequence) + 1`.
//!    Any failure rolls back the chain.
//!
//! **Forward-only**: no down-migrations. Schema changes are additive.
//!
//! **Concurrency**: per-namespace advisory locks reduce contention in
//! multi-instance deployments but are best-effort on pool drivers. The
//! real serialization comes from chain-tx atomicity + the
//! `(namespace, name)` PK on `schema_version` — the loser's INSERT
//! triggers PK violation and rollback; subsequent boots see the
//! committed state.
//!
//! **Atomicity**: any failure rolls back every migration that ran in
//! that invocation. Namespaces are independent: a later namespace's
//! failure does not roll back an earlier namespace that already
//! committed.

use crate::error::{DbError, MigrationError};
use crate::migration_schema::{
    Migration, MigrationNamespace, MigrationResult, assert_namespace_ownership,
};
use crate::pool::{Pool, commit_checked};
use crate::status::namespace_divergence;

const SCHEMA_VERSION_DDL: &str = "
CREATE TABLE IF NOT EXISTS schema_version (
  namespace  TEXT        NOT NULL,
  name       TEXT        NOT NULL,
  sequence   INTEGER     NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (namespace, name),
  UNIQUE (namespace, sequence)
)";

/// Compute a stable `i32` advisory lock key from a namespace string.
///
/// Uses djb2 hash, masked to `i32` range so the result fits in
/// `pg_advisory_lock(int4)`.
fn namespace_lock_key(namespace: &str) -> i32 {
    let mut hash: i32 = 5381;
    for byte in namespace.bytes() {
        // Wrapping arithmetic mirrors the JS `| 0` int32 coercion.
        hash = hash
            .wrapping_shl(5)
            .wrapping_add(hash)
            .wrapping_add(i32::from(byte));
    }
    hash
}

/// Acquire a session-scoped advisory lock; release in the `Drop`
/// equivalent (explicit unlock here since we're async).
async fn try_acquire_lock(client: &deadpool_postgres::Client, key: i32) {
    // Best-effort: ignore errors (PGlite-style environments may lack
    // `pg_advisory_lock`). Real serialization comes from chain-tx +
    // the `(namespace, name)` PK on `schema_version`.
    let _ = client.execute("SELECT pg_advisory_lock($1)", &[&key]).await;
}

async fn try_release_lock(client: &deadpool_postgres::Client, key: i32) {
    let _ = client
        .execute("SELECT pg_advisory_unlock($1)", &[&key])
        .await;
}

/// Verify each namespace bears a [`crate::RESERVED_NAMESPACES`] name exactly
/// when a spine crate built it ([`MigrationNamespace::spine`]).
///
/// [`run_migrations`] and [`baseline`] run this first; a server assembly calls
/// it to refuse a bad chain before it opens a connection.
///
/// # Errors
///
/// Returns [`DbError::Migration`] ([`MigrationError::NamespaceReserved`] /
/// [`MigrationError::NamespaceNotReserved`]) naming the first offending
/// namespace.
pub fn assert_migration_namespaces(namespaces: &[MigrationNamespace]) -> Result<(), DbError> {
    namespaces.iter().try_for_each(assert_namespace_ownership)
}

/// Run pending migrations for each namespace.
///
/// Refuses the whole list, before touching the database, when a consumer
/// namespace ([`MigrationNamespace::new`]) bears a [`crate::RESERVED_NAMESPACES`]
/// name (e.g. a consumer accidentally choosing `"fuz_cell"`) — only the spine
/// crate's own [`MigrationNamespace::spine`] namespace runs under one.
///
/// # Errors
///
/// [`DbError::Migration`] carrying:
/// - [`MigrationError::NamespaceReserved`] / [`MigrationError::NamespaceNotReserved`]
///   when a reserved name is claimed by a consumer namespace (or a spine-built
///   one is unreserved).
/// - [`MigrationError::Diverged`] when the tracker diverges from the code's
///   list: [`Divergence::BinaryOlder`](crate::Divergence::BinaryOlder)
///   (`binary-older-than-db`) when the database has more applied migrations
///   than the code knows, [`Divergence::NameMismatch`](crate::Divergence::NameMismatch)
///   (`name-divergence-at-N`) when an applied name doesn't match the
///   corresponding code-side name.
/// - [`MigrationError::Failed`] (`migration-failed`) when a DDL body errors
///   during the chain transaction.
///
/// Otherwise:
/// - [`DbError::PoolGet`] / [`DbError::Postgres`] for driver-level
///   failures.
pub async fn run_migrations(
    pool: &Pool,
    namespaces: &[MigrationNamespace],
) -> Result<Vec<MigrationResult>, DbError> {
    assert_migration_namespaces(namespaces)?;

    let client = pool.get().await?;

    // `CREATE TABLE IF NOT EXISTS` is not transactionally race-free
    // against itself in `PostgreSQL` — concurrent boots can both pass
    // the existence check and then collide on the `pg_type` catalog's
    // `(typname, typnamespace)` unique index. Silently swallow the
    // duplicate (23505) and unique-violation (42P07 / 42710) outcomes;
    // any other error propagates.
    if let Err(err) = client.batch_execute(SCHEMA_VERSION_DDL).await {
        let code = err.code().map(tokio_postgres::error::SqlState::code);
        match code {
            Some("23505" | "42P07" | "42710") => {
                tracing::debug!(?code, "schema_version DDL raced; another boot won");
            }
            _ => return Err(err.into()),
        }
    }

    drop(client);

    let mut results: Vec<MigrationResult> = Vec::new();

    for ns in namespaces {
        let result = run_namespace(pool, ns).await?;
        if let Some(r) = result {
            results.push(r);
        }
    }

    Ok(results)
}

async fn run_namespace(
    pool: &Pool,
    ns: &MigrationNamespace,
) -> Result<Option<MigrationResult>, DbError> {
    let mut client = pool.get().await?;
    let lock_key = namespace_lock_key(ns.name);

    try_acquire_lock(&client, lock_key).await;

    // Use a scoped block to ensure we always release the lock even on
    // early-return paths.
    let outcome = run_namespace_locked(&mut client, ns).await;

    try_release_lock(&client, lock_key).await;

    outcome
}

async fn run_namespace_locked(
    client: &mut deadpool_postgres::Client,
    ns: &MigrationNamespace,
) -> Result<Option<MigrationResult>, DbError> {
    let applied_rows = client
        .query(
            "SELECT name, sequence FROM schema_version
             WHERE namespace = $1
             ORDER BY sequence ASC",
            &[&ns.name],
        )
        .await?;

    let applied: Vec<(String, i32)> = applied_rows
        .iter()
        .map(|row| (row.get::<_, String>("name"), row.get::<_, i32>("sequence")))
        .collect();

    // Steps 3-4: length check, then name-prefix verify — the classifier
    // `db status` reports with
    let applied_names: Vec<&str> = applied.iter().map(|(name, _)| name.as_str()).collect();
    if let Some(divergence) = namespace_divergence(ns, &applied_names) {
        return Err(MigrationError::Diverged {
            namespace: ns.name.to_owned(),
            divergence,
        }
        .into());
    }

    // up-to-date case
    if applied.len() == ns.migrations.len() {
        return Ok(None);
    }

    // Step 5: run pending tail in a single chain-tx
    let mut next_sequence: i32 = applied
        .last()
        .map_or(0, |(_, seq)| seq.checked_add(1).unwrap_or(*seq));
    let mut applied_names: Vec<String> = Vec::new();

    let tx = client.transaction().await?;

    for (i, migration) in ns.migrations.iter().enumerate().skip(applied.len()) {
        if let Err(err) = run_one_migration(&tx, ns.name, migration, next_sequence).await {
            // Best-effort: rollback (the `tx` drop also rolls back).
            let _ = tx.rollback().await;
            return Err(MigrationError::Failed {
                namespace: ns.name.to_owned(),
                name: migration.name.to_owned(),
                index: i,
                source: err,
            }
            .into());
        }
        applied_names.push(migration.name.to_owned());
        next_sequence = next_sequence.saturating_add(1);
    }

    commit_checked(tx).await?;

    Ok(Some(MigrationResult {
        namespace: ns.name,
        applied_names,
    }))
}

async fn run_one_migration(
    tx: &tokio_postgres::Transaction<'_>,
    namespace: &str,
    migration: &Migration,
    sequence: i32,
) -> Result<(), tokio_postgres::Error> {
    tx.batch_execute(migration.sql).await?;
    tx.execute(
        "INSERT INTO schema_version (namespace, name, sequence)
         VALUES ($1, $2, $3)",
        &[&namespace, &migration.name, &sequence],
    )
    .await?;
    Ok(())
}

/// Record migration names as already-applied **without executing them**.
///
/// Used to promote an existing schema (e.g. produced by an out-of-band
/// bootstrap, or a hand-applied DDL set) into the identity tracker.
/// `baseline()` **trusts the caller-supplied list** — it does not
/// verify the schema actually matches what the named migrations would
/// have produced. Pair with a schema-assertion script post-baseline
/// before re-enabling traffic.
///
/// Contract:
/// - Creates the `schema_version` table if missing.
/// - Acquires the same per-namespace advisory lock as
///   [`run_migrations`].
/// - Refuses if any tracker rows already exist *for this namespace*
///   (lets multi-call baseline scripts resume after partial failure).
/// - Verifies `names` is a strict prefix of `namespace.migrations[].name`.
/// - Writes sequences `0..names.len()-1` in one transaction.
///
/// # Errors
///
/// - [`DbError::Migration`] carrying the same reserved-name refusal as
///   [`run_migrations`].
/// - [`DbError::Migration`] carrying [`MigrationError::BaselineNameNotInCode`],
///   [`MigrationError::BaselineNameOutOfOrder`],
///   [`MigrationError::BaselineNamespacePopulated`], or
///   [`MigrationError::BaselineTooManyNames`].
/// - Pool / driver errors as elsewhere.
pub async fn baseline(
    pool: &Pool,
    namespace: &MigrationNamespace,
    names: &[&str],
) -> Result<(), DbError> {
    assert_namespace_ownership(namespace)?;

    let mut client = pool.get().await?;

    // Same race-tolerance as `run_migrations`.
    if let Err(err) = client.batch_execute(SCHEMA_VERSION_DDL).await {
        let code = err.code().map(tokio_postgres::error::SqlState::code);
        match code {
            Some("23505" | "42P07" | "42710") => {
                tracing::debug!(?code, "schema_version DDL raced; another boot won");
            }
            _ => return Err(err.into()),
        }
    }

    let code_names: Vec<&str> = namespace.migrations.iter().map(|m| m.name).collect();

    // Validate every supplied name exists in code.
    for name in names {
        if !code_names.contains(name) {
            return Err(MigrationError::BaselineNameNotInCode {
                namespace: namespace.name.to_owned(),
                name: (*name).to_owned(),
            }
            .into());
        }
    }

    // Validate names is a strict prefix of code_names.
    for (i, name) in names.iter().enumerate() {
        if code_names.get(i) != Some(name) {
            return Err(MigrationError::BaselineNameOutOfOrder {
                namespace: namespace.name.to_owned(),
                position: i,
                name: (*name).to_owned(),
                expected: code_names.get(i).map(|n| (*n).to_owned()),
            }
            .into());
        }
    }

    let lock_key = namespace_lock_key(namespace.name);
    try_acquire_lock(&client, lock_key).await;

    let result = baseline_locked(&mut client, namespace, names).await;

    try_release_lock(&client, lock_key).await;

    result
}

async fn baseline_locked(
    client: &mut deadpool_postgres::Client,
    namespace: &MigrationNamespace,
    names: &[&str],
) -> Result<(), DbError> {
    let existing = client
        .query(
            "SELECT name FROM schema_version WHERE namespace = $1 LIMIT 1",
            &[&namespace.name],
        )
        .await?;

    if !existing.is_empty() {
        return Err(MigrationError::BaselineNamespacePopulated {
            namespace: namespace.name.to_owned(),
        }
        .into());
    }

    let tx = client.transaction().await?;
    for (i, name) in names.iter().enumerate() {
        let sequence = i32::try_from(i).map_err(|_| MigrationError::BaselineTooManyNames)?;
        tx.execute(
            "INSERT INTO schema_version (namespace, name, sequence)
             VALUES ($1, $2, $3)",
            &[&namespace.name, name, &sequence],
        )
        .await?;
    }
    commit_checked(tx).await?;

    Ok(())
}
