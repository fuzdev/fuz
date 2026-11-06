//! Typed errors for `fuz_db` operations.
//!
//! Variants follow the operator-actionable taxonomy used by the rest of the
//! spine: pool / driver / transaction / migration / identifier. Consumers
//! match on the variant to choose retry policy or surface a typed JSON-RPC
//! error.

use thiserror::Error;

use crate::status::Divergence;

/// Errors produced by `fuz_db` operations.
#[derive(Debug, Error)]
pub enum DbError {
    /// `DATABASE_URL` could not be parsed by `tokio_postgres::Config`.
    #[error("invalid database URL: {0}")]
    InvalidUrl(String),

    /// `deadpool_postgres` failed to construct the pool from the parsed URL.
    #[error("failed to build connection pool: {0}")]
    PoolBuild(String),

    /// Checking out a client from the pool failed.
    #[error("failed to acquire pooled connection")]
    PoolGet(#[source] deadpool_postgres::PoolError),

    /// Raw `PostgreSQL` driver error (query, BEGIN/COMMIT/ROLLBACK, etc.).
    #[error("postgres error")]
    Postgres(#[from] tokio_postgres::Error),

    /// A commit refused because an earlier statement error aborted the
    /// transaction, which has been rolled back. The source is the `25P02`
    /// (`in_failed_sql_transaction`) the probe in
    /// [`crate::pool::commit_checked`] drew. The statement error that aborted
    /// the transaction was swallowed by the code that ran inside it — a bug
    /// there, since `COMMIT` alone would have rolled back without an error.
    #[error("transaction was aborted by an earlier statement error and rolled back")]
    TransactionAborted(#[source] tokio_postgres::Error),

    /// The migration runner or [`crate::migration::baseline`] refused or
    /// failed — see [`MigrationError`].
    ///
    /// The text renders the [`MigrationError`] whole, a driver failure's
    /// message included, so it is not a `source`: an error-chain printer
    /// would print the migration error twice. Match the variant to reach it
    /// (and through [`MigrationError::Failed`], the driver error).
    #[error("migration error: {0}")]
    Migration(MigrationError),

    /// Identifier rejected by [`crate::sql_identifier::assert_valid_sql_identifier`].
    #[error("invalid SQL identifier: {0}")]
    InvalidIdentifier(String),
}

impl From<MigrationError> for DbError {
    fn from(err: MigrationError) -> Self {
        Self::Migration(err)
    }
}

impl From<deadpool_postgres::PoolError> for DbError {
    fn from(err: deadpool_postgres::PoolError) -> Self {
        Self::PoolGet(err)
    }
}

/// Why the migration runner ([`crate::migration::run_migrations`]) or
/// [`crate::migration::baseline`] refused or failed.
///
/// Every variant renders an operator-facing message. The runner's and
/// baseline's refusals lead with a kebab-case kind (as the TS twin's
/// `MigrationErrorKind` does) and end with their remedy as a `Hint:`; the
/// namespace-ownership refusals ([`Self::NamespaceReserved`],
/// [`Self::NamespaceNotReserved`]) name the fix inline, and
/// [`Self::BaselineTooManyNames`] carries neither. The variants carry the
/// parts so callers branch on the variant, never on the text.
#[derive(Debug, Error)]
pub enum MigrationError {
    /// A consumer namespace ([`crate::MigrationNamespace::new`]) bears a
    /// [`crate::RESERVED_NAMESPACES`] name.
    #[error(
        "migration namespace \"{namespace}\" is reserved for the spine; a consumer namespace must choose a different name"
    )]
    NamespaceReserved { namespace: String },

    /// A spine-built namespace ([`crate::MigrationNamespace::spine`]) bears a
    /// name outside [`crate::RESERVED_NAMESPACES`].
    #[error(
        "migration namespace \"{namespace}\" is built as a spine namespace but is not a reserved spine name; use MigrationNamespace::new"
    )]
    NamespaceNotReserved { namespace: String },

    /// The tracker's history for `namespace` diverges from the code's list —
    /// the state `db status` reports as `DIVERGED`, which the runner refuses
    /// to migrate.
    #[error("{}", render_diverged(namespace, divergence))]
    Diverged {
        namespace: String,
        divergence: Divergence,
    },

    /// Migration `name`, at `index` in `namespace`'s list, failed in the chain
    /// transaction, which rolled back.
    ///
    /// The text already includes the driver error; reach it by matching this
    /// variant, not by walking `source()` from a [`DbError`].
    #[error(
        "migration-failed: {namespace}[\"{name}\"] failed at index {index}: {source}. \
         Hint: fix the migration body and retry; the chain is left at the prior committed version."
    )]
    Failed {
        namespace: String,
        name: String,
        index: usize,
        #[source]
        source: tokio_postgres::Error,
    },

    /// A baseline name is not in `namespace`'s migrations.
    #[error(
        "baseline-name-not-in-code: name \"{name}\" is not in namespace \
         \"{namespace}\" migrations. Hint: confirm the build matches what the cutover \
         script was written against — name drift between build and script is \
         the most common cause."
    )]
    BaselineNameNotInCode { namespace: String, name: String },

    /// The baseline names are not a prefix of `namespace`'s migrations: at
    /// `position` the caller supplied `name` where the code has `expected`
    /// (`None` past the end of the code's list).
    #[error(
        "baseline-name-out-of-order: namespace \"{namespace}\" supplied names are not a prefix \
         of the code's migrations. At position {position}: supplied \"{name}\" but code expects \
         \"{expected}\". Hint: re-order the supplied names to match the code's array order.",
        expected = expected.as_deref().unwrap_or("<beyond end>"),
    )]
    BaselineNameOutOfOrder {
        namespace: String,
        position: usize,
        name: String,
        expected: Option<String>,
    },

    /// `namespace` already has tracker rows, so baseline refuses it.
    #[error(
        "baseline-namespace-already-populated: namespace \"{namespace}\" already has tracker rows. \
         Hint: per-namespace guard for partial-failure resume — completed namespaces self-skip; \
         if you need to re-baseline, manually `DELETE FROM schema_version WHERE namespace = '{namespace}'` first."
    )]
    BaselineNamespacePopulated { namespace: String },

    /// More baseline names than an `i32` sequence can number.
    #[error("baseline: too many names (i32 overflow)")]
    BaselineTooManyNames,
}

/// The [`MigrationError::Diverged`] message, by divergence.
fn render_diverged(namespace: &str, divergence: &Divergence) -> String {
    match divergence {
        Divergence::BinaryOlder { declared, unknown } => {
            let names = unknown
                .iter()
                .map(|n| format!("\"{n}\""))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "binary-older-than-db: namespace \"{namespace}\" has {applied} applied migrations \
                 but the code only knows {declared}. Unknown to this binary: {names}. \
                 Hint: upgrade the code to a version that includes these migrations; \
                 if you must downgrade, manually delete the unknown rows from schema_version.",
                applied = declared + unknown.len(),
            )
        }
        Divergence::NameMismatch {
            position: i,
            applied,
            expected,
        } => format!(
            "name-divergence-at-N: namespace \"{namespace}\" applied[{i}].name = \"{applied}\" \
             but code[{i}].name = \"{expected}\". \
             Hint: the migrations array was reordered or renamed (revert the source change), \
             OR row {i} or earlier was deleted from the tracker (re-insert the missing row \
             with a sequence value lower than the rows that follow it, or delete from row {i} \
             onward to re-apply the tail).",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pure variant's text, byte for byte (the runner's and baseline's
    /// refusals are operator-facing, and tests elsewhere pin them only by
    /// substring).
    #[test]
    fn each_refusal_renders_its_exact_text() {
        let ns = || "app".to_owned();
        let cases: [(MigrationError, &str); 7] = [
            (
                MigrationError::NamespaceReserved {
                    namespace: "fuz_auth".to_owned(),
                },
                "migration namespace \"fuz_auth\" is reserved for the spine; a consumer \
                 namespace must choose a different name",
            ),
            (
                MigrationError::NamespaceNotReserved { namespace: ns() },
                "migration namespace \"app\" is built as a spine namespace but is not a reserved \
                 spine name; use MigrationNamespace::new",
            ),
            (
                MigrationError::BaselineNameNotInCode {
                    namespace: ns(),
                    name: "m9".to_owned(),
                },
                "baseline-name-not-in-code: name \"m9\" is not in namespace \"app\" migrations. \
                 Hint: confirm the build matches what the cutover script was written against — \
                 name drift between build and script is the most common cause.",
            ),
            (
                MigrationError::BaselineNameOutOfOrder {
                    namespace: ns(),
                    position: 1,
                    name: "m2".to_owned(),
                    expected: Some("m1".to_owned()),
                },
                "baseline-name-out-of-order: namespace \"app\" supplied names are not a prefix of \
                 the code's migrations. At position 1: supplied \"m2\" but code expects \"m1\". \
                 Hint: re-order the supplied names to match the code's array order.",
            ),
            (
                MigrationError::BaselineNameOutOfOrder {
                    namespace: ns(),
                    position: 3,
                    name: "m4".to_owned(),
                    expected: None,
                },
                "baseline-name-out-of-order: namespace \"app\" supplied names are not a prefix of \
                 the code's migrations. At position 3: supplied \"m4\" but code expects \
                 \"<beyond end>\". Hint: re-order the supplied names to match the code's array \
                 order.",
            ),
            (
                MigrationError::BaselineNamespacePopulated { namespace: ns() },
                "baseline-namespace-already-populated: namespace \"app\" already has tracker \
                 rows. Hint: per-namespace guard for partial-failure resume — completed \
                 namespaces self-skip; if you need to re-baseline, manually `DELETE FROM \
                 schema_version WHERE namespace = 'app'` first.",
            ),
            (
                MigrationError::BaselineTooManyNames,
                "baseline: too many names (i32 overflow)",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected, "{err:?}");
        }
    }

    /// `Failed` wraps a real driver error, so its text is pinned around the
    /// driver's own message.
    #[tokio::test]
    async fn a_failed_migration_renders_its_place_and_driver_text() {
        let source = tokio_postgres::connect("host=127.0.0.1 port=1", tokio_postgres::NoTls)
            .await
            .err()
            .expect("nothing listens on port 1");
        let driver = source.to_string();
        let err = MigrationError::Failed {
            namespace: "app".to_owned(),
            name: "create_widgets".to_owned(),
            index: 2,
            source,
        };
        assert_eq!(
            err.to_string(),
            format!(
                "migration-failed: app[\"create_widgets\"] failed at index 2: {driver}. Hint: fix \
                 the migration body and retry; the chain is left at the prior committed version."
            )
        );
    }

    #[test]
    fn a_divergence_renders_the_runner_refusal() {
        let older = MigrationError::Diverged {
            namespace: "app".to_owned(),
            divergence: Divergence::BinaryOlder {
                declared: 1,
                unknown: vec!["m1".to_owned(), "m2".to_owned()],
            },
        };
        assert_eq!(
            older.to_string(),
            "binary-older-than-db: namespace \"app\" has 3 applied migrations but the code only \
             knows 1. Unknown to this binary: \"m1\", \"m2\". Hint: upgrade the code to a version \
             that includes these migrations; if you must downgrade, manually delete the unknown \
             rows from schema_version."
        );
        let renamed = MigrationError::Diverged {
            namespace: "app".to_owned(),
            divergence: Divergence::NameMismatch {
                position: 2,
                applied: "old".to_owned(),
                expected: "new".to_owned(),
            },
        };
        assert_eq!(
            renamed.to_string(),
            "name-divergence-at-N: namespace \"app\" applied[2].name = \"old\" but code[2].name = \
             \"new\". Hint: the migrations array was reordered or renamed (revert the source \
             change), OR row 2 or earlier was deleted from the tracker (re-insert the missing row \
             with a sequence value lower than the rows that follow it, or delete from row 2 onward \
             to re-apply the tail)."
        );
        // the wrapper prefixes the text and keeps it out of the source chain,
        // so a chain printer shows it once
        let text = renamed.to_string();
        let wrapped = DbError::from(renamed);
        assert_eq!(wrapped.to_string(), format!("migration error: {text}"));
        assert!(std::error::Error::source(&wrapped).is_none());
    }
}
