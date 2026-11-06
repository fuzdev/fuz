//! `tokio_postgres::Error` classification and SQLSTATE extraction.
//!
//! Maps raw driver errors into a coarse [`PgErrorKind`] enum the spine
//! can match against. Twin of `fuz_app`'s `db/pg_error.ts`, widened to
//! the SQLSTATE checks the spine needs.
//!
//! SQLSTATE codes used here:
//! - `23505` — unique constraint violation
//! - `23503` — foreign key constraint violation
//! - `23001` — restrict violation (`PostgreSQL` 18+ raises this instead of
//!   `23503` for `ON DELETE RESTRICT` constraints; PG ≤17 raises `23503`)
//! - `23502` — not-null constraint violation
//! - `23514` — check constraint violation
//! - `40001` — serialization failure
//! - `40P01` — deadlock detected
//! - `22P02` — invalid text representation
//! - `22003` — numeric value out of range
//! - `22021` — character not in repertoire (e.g. a NUL byte in a text
//!   parameter, rejected by the server encoding)

use tokio_postgres::error::SqlState;

/// Classification of the common `PostgreSQL` error states the spine
/// cares about. Coarse on purpose — call sites that need finer detail
/// match on the raw `tokio_postgres::Error::code()` themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgErrorKind {
    /// 23505 — unique constraint violation.
    UniqueViolation,
    /// 23503 — foreign key constraint violation.
    ForeignKeyViolation,
    /// 23001 — restrict violation. `PostgreSQL` 18+ raises this instead of
    /// 23503 for `ON DELETE RESTRICT` constraints (PG ≤17 raises 23503
    /// for both), so a referencing-row refusal must match either kind.
    RestrictViolation,
    /// 23502 — not-null constraint violation.
    NotNullViolation,
    /// 23514 — check constraint violation.
    CheckViolation,
    /// 40001 — serialization failure (retryable).
    SerializationFailure,
    /// 40P01 — deadlock detected (retryable).
    DeadlockDetected,
    /// 22P02 — invalid text representation (a text-format parameter or
    /// literal the target type's input function rejects).
    InvalidTextRepresentation,
    /// 22003 — numeric value out of range (parses, but overflows the
    /// target numeric type).
    NumericValueOutOfRange,
    /// 22021 — character not in repertoire: a parameter byte sequence the
    /// server encoding rejects (the reachable case is a NUL byte in a text
    /// parameter — no stored value can ever contain one).
    CharacterNotInRepertoire,
    /// Anything else, including non-database errors (connection
    /// failures, decode errors).
    Other,
}

/// Return `true` if the error is a unique constraint violation
/// (SQLSTATE 23505).
#[must_use]
pub fn is_pg_unique_violation(error: &tokio_postgres::Error) -> bool {
    error.code() == Some(&SqlState::UNIQUE_VIOLATION)
}

/// The SQLSTATE code of the first `tokio_postgres::Error` in `error`'s chain.
///
/// The chain is `error` itself, then each `source()`. `None` when no link is
/// a driver error, or the first one carries no code (a connection, timeout,
/// or decode failure).
///
/// For logs: a `tokio_postgres::Error`'s `Display` and the chain's rendered
/// text omit the code, and a wrapper (`DbError`, a pool error, a store error)
/// hides the driver error behind `source()`.
#[must_use]
pub fn sqlstate_in_chain<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a str> {
    std::iter::successors(Some(error), |link| link.source())
        .find_map(|link| link.downcast_ref::<tokio_postgres::Error>())
        .and_then(tokio_postgres::Error::code)
        .map(SqlState::code)
}

/// Classify a `tokio_postgres::Error` into a coarse [`PgErrorKind`].
#[must_use]
pub fn classify_pg_error(error: &tokio_postgres::Error) -> PgErrorKind {
    match error.code() {
        Some(code) if *code == SqlState::UNIQUE_VIOLATION => PgErrorKind::UniqueViolation,
        Some(code) if *code == SqlState::FOREIGN_KEY_VIOLATION => PgErrorKind::ForeignKeyViolation,
        Some(code) if *code == SqlState::RESTRICT_VIOLATION => PgErrorKind::RestrictViolation,
        Some(code) if *code == SqlState::NOT_NULL_VIOLATION => PgErrorKind::NotNullViolation,
        Some(code) if *code == SqlState::CHECK_VIOLATION => PgErrorKind::CheckViolation,
        Some(code) if *code == SqlState::T_R_SERIALIZATION_FAILURE => {
            PgErrorKind::SerializationFailure
        }
        Some(code) if *code == SqlState::T_R_DEADLOCK_DETECTED => PgErrorKind::DeadlockDetected,
        Some(code) if *code == SqlState::INVALID_TEXT_REPRESENTATION => {
            PgErrorKind::InvalidTextRepresentation
        }
        Some(code) if *code == SqlState::NUMERIC_VALUE_OUT_OF_RANGE => {
            PgErrorKind::NumericValueOutOfRange
        }
        Some(code) if *code == SqlState::CHARACTER_NOT_IN_REPERTOIRE => {
            PgErrorKind::CharacterNotInRepertoire
        }
        _ => PgErrorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("wrapper")]
    struct Wrapper(#[source] std::io::Error);

    /// A chain with no driver error has no SQLSTATE. The `Some` path needs a
    /// server-raised `tokio_postgres::Error`, which only the driver can build
    /// — the Postgres-backed `pg_error_classification_unique_violation`
    /// integration test covers it.
    #[test]
    fn sqlstate_in_chain_is_none_without_a_driver_error() {
        let error = Wrapper(std::io::Error::other("connection reset"));
        assert_eq!(sqlstate_in_chain(&error), None);
    }
}
