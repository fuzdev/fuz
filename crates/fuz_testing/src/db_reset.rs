//! Env-gated startup DB reset for test binaries.
//!
//! Cross-process test harnesses run the same test binary
//! (`testing_zzz_server`, `testing_spine_stub`, and the like)
//! repeatedly against the same Postgres database
//! — but `bootstrap_lock.bootstrapped = true` persists across runs,
//! and migrations refuse to re-bootstrap on a DB that's already been
//! through one. The operator's choice is either "drop the DB
//! manually between runs" or "self-wipe on startup". This module is
//! the second option, env-gated so it can never fire in a
//! production-shaped graph (test binaries are the only consumers; a
//! production binary linking `fuz_testing` is blocked by `cargo
//! xtask check-release`).
//!
//! Set [`FUZ_TESTING_RESET_DB_ON_STARTUP`] to any case-insensitive
//! truthy value (`true/1/yes/on/y/enabled`) and the binary will
//! `DROP SCHEMA public CASCADE; CREATE SCHEMA public` before the
//! migration chain runs, handing the runner a genuinely empty database
//! so every namespace's migrations replay from scratch. The blanket drop
//! is deliberate: it's immune to the schema drift a hand-maintained
//! per-table drop list invites — it resets every table, type, and
//! sequence any consumer's migrations create (auth, cell, forge, …)
//! without this module needing to enumerate their names. Falsy values
//! (`false/0/no/off/n/disabled`) and unset
//! are both no-ops; any other value surfaces a `DbResetError::InvalidEnv`
//! so operator typos don't silently no-op. Truthy/falsy sets are
//! `fuz_sys::env::parse_stringbool`'s.
//!
//! ### Why this is separate from [`crate::testing_reset`]
//!
//! Different semantics, same crate:
//!
//! - [`crate::testing_reset`] is the **per-test** reset (`_testing_reset`
//!   RPC action). It DELETEs rows from a smaller set of 8 data tables,
//!   preserves the keeper account+actor, and leaves the schema intact.
//!   Fires between test cases.
//! - This module is the **per-process-startup** reset. It drops and
//!   recreates the `public` schema (taking `schema_version` with it so
//!   migrations replay), erasing every table + the keeper, and lets the
//!   binary re-bootstrap from nothing. Fires once when the test binary
//!   starts.
//!
//! Keep them independent — the per-test path is a hot loop with
//! correctness invariants (keeper preservation, `audit_log` scoping);
//! the startup path is a coarse wipe with no in-flight state to
//! protect.

use std::fmt;

use tokio_postgres::Error as PgError;

/// Errors surfaced by [`reset_db_on_startup_if_env_set`].
///
/// Two variants because env-value parsing and DB-driver failures want
/// distinct operator messages: a `"maybe"` typo in the env var means
/// "fix your config", a connection error means "fix the DB".
#[derive(Debug)]
pub(crate) enum DbResetError {
    /// `FUZ_TESTING_RESET_DB_ON_STARTUP` was set to a value that's
    /// neither truthy (`true/1/yes/on/y/enabled`) nor falsy
    /// (`false/0/no/off/n/disabled`). String carries the offending
    /// value verbatim so the operator sees the typo.
    InvalidEnv(String),
    /// `tokio_postgres` driver error from the schema reset.
    Pg(PgError),
}

impl fmt::Display for DbResetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnv(raw) => write!(
                f,
                "{FUZ_TESTING_RESET_DB_ON_STARTUP}: expected one of \
                 true/1/yes/on/y/enabled/false/0/no/off/n/disabled \
                 (case-insensitive), got {raw:?}"
            ),
            Self::Pg(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DbResetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEnv(_) => None,
            Self::Pg(e) => Some(e),
        }
    }
}

impl From<PgError> for DbResetError {
    fn from(e: PgError) -> Self {
        Self::Pg(e)
    }
}

/// Env-var name read by the startup reset ([`crate::startup_reset_hook`]).
///
/// Test binaries should set this in the cross-backend harness's per-project
/// backend config `env` block. Unset, or a false `stringbool`
/// (`false`, `0`, `no`, `off`, `n`, `disabled`), is a no-op; a true one
/// (`true`, `1`, `yes`, `on`, `y`, `enabled`) resets; any other value is
/// `DbResetError::InvalidEnv`, so a typo cannot silently skip the reset.
pub const FUZ_TESTING_RESET_DB_ON_STARTUP: &str = "FUZ_TESTING_RESET_DB_ON_STARTUP";

/// Parse a `stringbool`-shaped string value via the spine's canonical
/// [`fuz_sys::env::parse_stringbool`], adapting the error to
/// [`DbResetError::InvalidEnv`] (carrying the offending value).
fn parse_stringbool(raw: &str) -> Result<bool, DbResetError> {
    fuz_sys::env::parse_stringbool(raw).map_err(|e| DbResetError::InvalidEnv(e.value))
}

/// Read `name` from the environment and parse via [`parse_stringbool`].
/// Unset → `Ok(false)`.
fn parse_stringbool_env(name: &str) -> Result<bool, DbResetError> {
    let Ok(raw) = std::env::var(name) else {
        return Ok(false);
    };
    parse_stringbool(&raw)
}

/// Drop + recreate the `public` schema when the reset env var is truthy.
///
/// If [`FUZ_TESTING_RESET_DB_ON_STARTUP`] parses to a truthy value
/// (case-insensitive `true/1/yes/on/y/enabled`), drops and recreates the
/// `public` schema (`DROP SCHEMA public CASCADE; CREATE SCHEMA public`) so
/// migrations replay against an empty database. Falsy and unset are
/// no-ops; any other env value surfaces [`DbResetError::InvalidEnv`].
///
/// Logs a single `tracing::info!` line when the reset fires so the
/// operator can confirm the wipe happened on the targeted DB
/// (matches the test-mode argon2 sentinel pattern).
///
/// # Errors
///
/// [`DbResetError::InvalidEnv`] when the env var is set to a value
/// outside the stringbool set. [`DbResetError::Pg`] on driver failure
/// from the schema reset (e.g. connection-level problems, or the
/// connecting role not owning `public` and so unable to drop/recreate it).
pub(crate) async fn reset_db_on_startup_if_env_set(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<(), DbResetError> {
    if !parse_stringbool_env(FUZ_TESTING_RESET_DB_ON_STARTUP)? {
        return Ok(());
    }

    tracing::info!(
        env = FUZ_TESTING_RESET_DB_ON_STARTUP,
        "[fuz_testing] startup DB reset — dropping + recreating the public schema before migrations"
    );

    // Blanket drop: a pristine `public` schema is immune to the schema
    // drift a hand-maintained per-namespace table list invites. A migration
    // that adds a table the list forgot would either collide loudly (plain
    // `CREATE TABLE`) or — worse — for an `IF NOT EXISTS` migration silently
    // leave a stale table the replay never rebuilds. Recreating the schema
    // resets every table, type, and sequence regardless of which consumer's
    // migrations created them, so the runner always sees an empty DB. Safe
    // as a one-shot wipe because no consumer migration creates a standalone
    // function, trigger, or extension — only tables and the one cell enum,
    // all of which `DROP SCHEMA … CASCADE` removes.
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_truthy_values() {
        for raw in ["true", "TRUE", "1", "yes", "on", "y", "enabled", "Enabled"] {
            assert!(
                matches!(parse_stringbool(raw), Ok(true)),
                "{raw:?} should parse truthy",
            );
        }
    }

    #[test]
    fn parses_falsy_values() {
        for raw in ["false", "FALSE", "0", "no", "off", "n", "disabled"] {
            assert!(
                matches!(parse_stringbool(raw), Ok(false)),
                "{raw:?} should parse falsy",
            );
        }
    }

    #[test]
    fn rejects_unknown_value() {
        assert!(
            matches!(parse_stringbool("maybe"), Err(DbResetError::InvalidEnv(raw)) if raw == "maybe"),
            "'maybe' should be rejected as InvalidEnv carrying the offending value",
        );
    }
}
