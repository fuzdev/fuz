//! Typed errors for the auth subsystem.

use thiserror::Error;

/// Errors from [`signup_handler`](crate::signup::signup_handler).
///
/// [`Classified`](Self::Classified) carries the failures the REST wrapper
/// maps to a wire error; every other variant is an unclassified internal
/// failure carrying its cause (a driver, pool or commit error, or the
/// hasher's message), answered `500 internal_error`.
#[derive(Debug, Error)]
pub enum SignupError {
    /// A classified signup failure.
    #[error("signup error: {kind}")]
    Classified { kind: SignupErrorKind },

    /// `deadpool_postgres` pool checkout failed.
    #[error("pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),

    /// Raw `tokio_postgres` driver error.
    #[error("query error: {0}")]
    Query(#[from] tokio_postgres::Error),

    /// The password hasher failed.
    #[error("password hashing error: {0}")]
    PasswordHash(String),

    /// The `COMMIT` failed, or [`fuz_db::commit_checked`]'s pre-commit probe
    /// found the transaction aborted and rolled it back.
    #[error("commit error: {0}")]
    Commit(#[source] fuz_db::DbError),
}

/// Errors from [`bootstrap_handler`](crate::bootstrap::bootstrap_handler).
///
/// [`Classified`](Self::Classified) carries the failures the REST wrapper
/// maps to a wire error; every other variant is an unclassified internal
/// failure carrying its cause (a driver, pool or commit error, or the
/// hasher's message), answered `500 internal_error`.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// A classified bootstrap failure.
    #[error("bootstrap error: {kind}")]
    Classified { kind: BootstrapErrorKind },

    /// `deadpool_postgres` pool checkout failed.
    #[error("pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),

    /// Raw `tokio_postgres` driver error.
    #[error("query error: {0}")]
    Query(#[from] tokio_postgres::Error),

    /// The password hasher failed.
    #[error("password hashing error: {0}")]
    PasswordHash(String),

    /// The `COMMIT` failed, or [`fuz_db::commit_checked`]'s pre-commit probe
    /// found the transaction aborted and rolled it back.
    #[error("commit error: {0}")]
    Commit(#[source] fuz_db::DbError),
}

/// Bootstrap failure discriminants — match the wire-format strings
/// `fuz_app`'s `bootstrap_routes.ts` emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapErrorKind {
    AlreadyBootstrapped,
    TokenFileMissing,
    InvalidToken,
    InvalidInput,
}

impl std::fmt::Display for BootstrapErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl BootstrapErrorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyBootstrapped => "already_bootstrapped",
            Self::TokenFileMissing => "token_file_missing",
            Self::InvalidToken => "invalid_token",
            // the twin's route-schema refusal, `ERROR_INVALID_REQUEST_BODY`
            Self::InvalidInput => fuz_http::INVALID_REQUEST_BODY_REASON,
        }
    }
}

/// Signup failure discriminants — match the wire-format strings
/// `fuz_app`'s `auth/signup_routes.ts` emits via
/// `http/error_schemas.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupErrorKind {
    /// `ERROR_NO_MATCHING_INVITE` — invite-gated signup found no
    /// unclaimed match. Maps to HTTP 403.
    NoMatchingInvite,
    /// `ERROR_SIGNUP_CONFLICT` — PG unique violation on `account.username`
    /// or `account.email`. Maps to HTTP 409.
    SignupConflict,
    /// `ERROR_INVALID_REQUEST_BODY` — username/password failed
    /// validation (length, empty after canonicalization). Maps to
    /// HTTP 400.
    InvalidInput,
    /// `rate_limit_exceeded` — per-IP or per-account bucket
    /// exhausted. Maps to HTTP 429. The wrapper attaches the
    /// `retry_after` value separately.
    RateLimitExceeded { retry_after: u64 },
    /// The invite claim missed despite the `FOR UPDATE` lock — an invariant
    /// breach, refused so the account rolls back. Maps to HTTP 500. Driver
    /// and pool faults are not this variant: they escape as
    /// [`SignupError::Query`] / [`SignupError::Pool`] /
    /// [`SignupError::Commit`]. This kind is also the
    /// `reason: 'internal_error'` of the fallback failure audit the handler
    /// emits for every unclassified failure, a failed commit
    /// ([`SignupError::Commit`]) included — mirrors `fuz_app`'s catch-all
    /// rethrow, whose catch also covers its commit.
    InternalError,
}

impl std::fmt::Display for SignupErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SignupErrorKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoMatchingInvite => "no_matching_invite",
            Self::SignupConflict => "signup_conflict",
            Self::InvalidInput => fuz_http::INVALID_REQUEST_BODY_REASON,
            Self::RateLimitExceeded { .. } => "rate_limit_exceeded",
            Self::InternalError => "internal_error",
        }
    }
}
