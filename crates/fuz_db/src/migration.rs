//! Identity-tracked migration runner.
//!
//! Algorithm (ported from `fuz_app/src/lib/db/migrate.ts`):
//!
//! 1. Apply the `schema_version` DDL.
//! 2. For each namespace, hold a session `pg_advisory_lock` on one
//!    pooled client, keyed by a djb2 hash of the namespace name's UTF-8
//!    bytes as a `bigint` — the key the TS twin's transaction-scoped
//!    `pg_advisory_xact_lock` takes, so the two spines serialize against
//!    each other. A lock that fails fails the run, naming the namespace
//!    ([`MigrationError::LockFailed`]).
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
//! **Concurrency**: the per-namespace advisory lock is what serializes
//! concurrent boots, this spine's or the TS twin's, over one database:
//! the second waits for the first's chain to commit, then reads it
//! applied. The `(namespace, name)` PK on `schema_version` only keeps a
//! migration from recording twice; without the lock, two chains running
//! at once collide on their own DDL and the loser's boot fails. The
//! `schema_version` DDL runs before the lock, so its race is tolerated
//! where it runs.
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

/// Compute a stable advisory lock key from a namespace string.
///
/// djb2 over the name's UTF-8 bytes in wrapping `i32` arithmetic, as the TS
/// twin's `namespace_lock_key` computes it, widened to the `bigint`
/// `pg_advisory_lock(bigint)` takes. Sign-extending keeps the TS key's value:
/// TS sends its `int32` number as the same `bigint`.
fn namespace_lock_key(namespace: &str) -> i64 {
    let mut hash: i32 = 5381;
    for byte in namespace.bytes() {
        // Wrapping arithmetic mirrors the JS `| 0` int32 coercion.
        hash = hash
            .wrapping_shl(5)
            .wrapping_add(hash)
            .wrapping_add(i32::from(byte));
    }
    i64::from(hash)
}

/// Run `locked` holding the namespace's session-scoped advisory lock on
/// `client`, taking and releasing it on that one client.
///
/// The lock is bound as `i64`: `pg_advisory_lock($1)` resolves to the
/// `bigint` overload, which an `i32` parameter fails to bind. A failed lock
/// fails the run with [`MigrationError::LockFailed`], since the lock is what
/// serializes concurrent boots. A failed unlock detaches the client from the
/// pool, so its connection closes and the session's lock goes with it rather
/// than staying held on an idle pooled client; the run's own error wins over
/// the unlock's.
/// Cancelling the future while the lock is held returns the client to the
/// pool still holding it; callers run it to completion.
async fn with_namespace_lock<T>(
    mut client: deadpool_postgres::Client,
    namespace: &str,
    locked: impl AsyncFnOnce(&mut deadpool_postgres::Client) -> Result<T, DbError>,
) -> Result<T, DbError> {
    let key = namespace_lock_key(namespace);
    client
        .execute("SELECT pg_advisory_lock($1)", &[&key])
        .await
        .map_err(|source| MigrationError::LockFailed {
            namespace: namespace.to_owned(),
            source,
        })?;
    let outcome = locked(&mut client).await;
    match client
        .execute("SELECT pg_advisory_unlock($1)", &[&key])
        .await
    {
        Ok(_) => outcome,
        Err(err) => {
            tracing::warn!(
                namespace,
                error = %err,
                "migration advisory unlock failed; closing its connection"
            );
            drop(deadpool_postgres::Object::take(client));
            outcome.and(Err(err.into()))
        }
    }
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
/// - [`MigrationError::LockFailed`] (`migration-lock-failed`) when taking a
///   namespace's advisory lock fails; the driver error is its source.
/// - [`MigrationError::Failed`] (`migration-failed`) when a DDL body errors
///   during the chain transaction.
///
/// Otherwise:
/// - [`DbError::PoolGet`] / [`DbError::Postgres`] for driver-level
///   failures.
///
/// A failed advisory unlock after a namespace's chain committed also returns
/// [`DbError::Postgres`], so the caller sees a failed run although that
/// namespace's migrations landed (later namespaces did not run). That is
/// safe: the unlock's connection is closed, releasing the lock, and a re-run
/// finds that namespace applied and goes on to the rest.
pub async fn run_migrations(
    pool: &Pool,
    namespaces: &[MigrationNamespace],
) -> Result<Vec<MigrationResult>, DbError> {
    assert_migration_namespaces(namespaces)?;

    let client = pool.get().await?;

    // `CREATE TABLE IF NOT EXISTS` is not transactionally race-free
    // against itself in `PostgreSQL` — concurrent boots can both pass
    // the existence check and then collide on the `pg_type` catalog's
    // `(typname, typnamespace)` unique index. Tolerate the unique
    // violation (23505) and the duplicate table or object (42P07 /
    // 42710), logged at debug; any other error propagates.
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
    let client = pool.get().await?;
    with_namespace_lock(client, ns.name, async |client| {
        run_namespace_locked(client, ns).await
    })
    .await
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
///   [`MigrationError::BaselineNamespacePopulated`],
///   [`MigrationError::BaselineTooManyNames`], or
///   [`MigrationError::LockFailed`] (as in [`run_migrations`]).
/// - Pool / driver errors as elsewhere.
pub async fn baseline(
    pool: &Pool,
    namespace: &MigrationNamespace,
    names: &[&str],
) -> Result<(), DbError> {
    assert_namespace_ownership(namespace)?;

    let client = pool.get().await?;

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

    with_namespace_lock(client, namespace.name, async |client| {
        baseline_locked(client, namespace, names).await
    })
    .await
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

#[cfg(test)]
mod tests {
    use super::namespace_lock_key;

    /// The same vectors pin the TS twin's `namespace_lock_key`
    /// (`fuz_app`'s `migrate.lock.test.ts`): one namespace, one `bigint`
    /// key on both spines, so their locks conflict. The spine namespaces
    /// hash negative, which pins the sign extension; the non-ASCII name
    /// pins hashing UTF-8 bytes.
    #[test]
    fn namespace_lock_key_matches_the_ts_twin() {
        assert_eq!(namespace_lock_key("fuz_auth"), -271_612_341);
        assert_eq!(namespace_lock_key("fuz_cell"), -271_558_151);
        assert_eq!(namespace_lock_key("fuz_facts"), -368_079_798);
        assert_eq!(namespace_lock_key("café"), 255_161_979);
    }
}
