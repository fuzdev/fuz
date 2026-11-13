//! `deadpool_postgres` pool wrapper and the checked transaction commit.
//!
//! Builds a pool from a `postgres://` URL via [`create_pool`]. Consumers
//! check out clients with [`Pool::get`] (re-exported from
//! `deadpool_postgres`) and pass them to query functions that take
//! `&(impl tokio_postgres::GenericClient + ?Sized)` — the same shape
//! works against a pooled `Object`, a `&Transaction`, or anything else
//! that implements `GenericClient`. This mirrors `fuz_app`'s `QueryDeps`
//! convention without introducing a trait abstraction layer.
//!
//! A transaction is opened on a checked-out client and committed with
//! [`commit_checked`], which refuses a transaction an earlier statement error
//! aborted rather than letting `COMMIT` roll it back silently:
//!
//! ```ignore
//! use fuz_db::{DbError, Pool, commit_checked};
//!
//! async fn write_pair(pool: &Pool) -> Result<(), DbError> {
//!     let mut client = pool.get().await?;
//!     let tx = client.transaction().await?;
//!     tx.execute("INSERT INTO foo (k) VALUES ($1)", &[&"a"]).await?;
//!     tx.execute("INSERT INTO bar (k) VALUES ($1)", &[&"a"]).await?;
//!     commit_checked(tx).await
//! }
//! ```
//!
//! An error that returns early drops the transaction, which rolls it back;
//! a caller that must act on the rollback's own failure calls
//! `tx.rollback()` explicitly. The caller keeps the client and the
//! transaction in its own scope, so it sequences work around the commit
//! itself — post-commit effects that run only on a successful commit, or
//! releasing the pooled client before a fan-out that takes its own.
//!
//! ## Checkout timeout
//!
//! Every checkout is bounded by [`PoolOptions::checkout_timeout`] (default
//! [`DEFAULT_CHECKOUT_TIMEOUT`], 5 s): the wait for a free client, the connect
//! of a new one, and the recycle check of an idle one each give up after it,
//! so `pool.get()` fails with a `deadpool_postgres::PoolError` instead of
//! queuing forever when the pool is exhausted or the server is unreachable.
//! A request surface answers that failure with a 503 (`fuz_http::db_unavailable`,
//! `db_unavailable_response`), and a failed query on a checked-out client keeps
//! its 500. A caller that must wait longer than the pool's default — the audit
//! emitter's pool writes — checks out with `Pool::timeout_get` and its own
//! `deadpool_postgres::Timeouts`. Twin of the TS `fuz_app` `create_pg_pool`
//! (`connectionTimeoutMillis`).
//!
//! The steps are bounded one by one, so a checkout that waits and then
//! connects can take about twice the bound.

use std::time::Duration;

use deadpool_postgres::{Config, PoolConfig, Runtime, SslMode, Timeouts};
use tokio_postgres::NoTls;
use tokio_postgres::error::SqlState;

use crate::error::DbError;

/// Connection pool type. Re-export of `deadpool_postgres::Pool` — the
/// concrete type is part of the public API (concrete types fine, no
/// traits needed).
pub type Pool = deadpool_postgres::Pool;

/// Pooled client checked out from a [`Pool`].
pub type PoolClient = deadpool_postgres::Client;

/// Default bound on one pool checkout — the wait for a free client, a new
/// client's connect, an idle client's recycle check. Twin of the TS
/// `DEFAULT_DB_CHECKOUT_TIMEOUT_MS`.
pub const DEFAULT_CHECKOUT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default bound on the checkout behind one of the audit emitter's pool writes.
///
/// Longer than [`DEFAULT_CHECKOUT_TIMEOUT`], so a saturated pool that sheds
/// requests with a 503 does not also drop the failure rows recording them.
/// Twin of the TS `DEFAULT_DB_AUDIT_CHECKOUT_TIMEOUT_MS`.
pub const DEFAULT_AUDIT_CHECKOUT_TIMEOUT: Duration = Duration::from_secs(30);

/// Options for [`create_pool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolOptions {
    /// Bound on every checkout: the wait for a free client, the connect of a
    /// new one, and the recycle check of an idle one (module doc, "Checkout
    /// timeout").
    pub checkout_timeout: Duration,
}

impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            checkout_timeout: DEFAULT_CHECKOUT_TIMEOUT,
        }
    }
}

/// The `deadpool_postgres::Timeouts` one checkout bound sets.
///
/// The same value for the wait, the create, and the recycle step. Shared by [`create_pool`]
/// and callers that check out with their own bound (`Pool::timeout_get`).
#[must_use]
pub const fn checkout_timeouts(timeout: Duration) -> Timeouts {
    Timeouts {
        wait: Some(timeout),
        create: Some(timeout),
        recycle: Some(timeout),
    }
}

/// Build a connection pool from a `postgres://` URL.
///
/// Parses the URL into a `tokio_postgres::Config`, then translates it
/// into `deadpool_postgres::Config`. The connection is `NoTls`: the spine
/// assumes a co-located Postgres (localhost TCP or a Unix socket), so a
/// remote-DB deployment needs TLS added here first. Every checkout is
/// bounded by `options.checkout_timeout` (module doc, "Checkout timeout").
///
/// # Errors
///
/// - [`DbError::InvalidUrl`] when the URL fails `tokio_postgres::Config`
///   parsing.
/// - [`DbError::PoolBuild`] when `deadpool_postgres::Config::create_pool`
///   fails.
pub fn create_pool(database_url: &str, options: &PoolOptions) -> Result<Pool, DbError> {
    pool_config_with_options(database_url, options)?
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .map_err(|e| DbError::PoolBuild(format!("{e}")))
}

/// [`pool_config`] plus the pool settings [`create_pool`] applies.
fn pool_config_with_options(database_url: &str, options: &PoolOptions) -> Result<Config, DbError> {
    let mut cfg = pool_config(database_url)?;
    cfg.pool = Some(PoolConfig {
        timeouts: checkout_timeouts(options.checkout_timeout),
        ..PoolConfig::default()
    });
    Ok(cfg)
}

/// Parse `database_url` and reduce it to the `deadpool_postgres::Config`
/// [`create_pool`] dials — the one reduction, which `db-status` also renders its
/// `url:` line from so the line names the server actually dialed.
///
/// Carries the **first** host and the **first** port, the user, the database
/// name, and the password; further hosts and ports (a host list, a `?host=`
/// or `?port=` query parameter, which tokio-postgres appends) and `hostaddr`
/// are dropped. With no host at all, deadpool falls back to its default
/// Unix-socket directories.
///
/// # Errors
///
/// Returns [`DbError::InvalidUrl`] when the URL fails `tokio_postgres::Config`
/// parsing.
pub(crate) fn pool_config(database_url: &str) -> Result<Config, DbError> {
    let pg_config: tokio_postgres::Config = database_url
        .parse()
        .map_err(|e: tokio_postgres::Error| DbError::InvalidUrl(format!("{e}")))?;

    let mut cfg = Config::new();
    if let Some(host) = pg_config.get_hosts().first() {
        match host {
            tokio_postgres::config::Host::Tcp(h) => cfg.host = Some(h.clone()),
            #[cfg(unix)]
            tokio_postgres::config::Host::Unix(p) => {
                cfg.host = Some(p.to_string_lossy().into_owned());
            }
        }
    }
    if let Some(port) = pg_config.get_ports().first() {
        cfg.port = Some(*port);
    }
    if let Some(user) = pg_config.get_user() {
        cfg.user = Some(user.to_owned());
    }
    if let Some(dbname) = pg_config.get_dbname() {
        cfg.dbname = Some(dbname.to_owned());
    }
    if let Some(password) = pg_config.get_password() {
        cfg.password = Some(String::from_utf8_lossy(password).into_owned());
    }
    cfg.ssl_mode = Some(SslMode::Disable);
    Ok(cfg)
}

/// Commit a transaction, refusing one an earlier statement error aborted.
///
/// `PostgreSQL` answers `COMMIT` on an aborted transaction with a rollback and
/// no error — the command tag reads `ROLLBACK` — and `tokio_postgres` discards
/// the tag, so a plain `tx.commit()` returns `Ok` for a transaction whose
/// writes were all thrown away. That happens whenever code inside the
/// transaction swallows a failed statement (`let _ = tx.execute(..)`) and
/// carries on: every later statement fails `25P02`, and the commit looks
/// successful. A caller that reports success or runs post-commit side effects
/// on that `Ok` would announce state that never existed.
///
/// The guard is a `SELECT 1` probe ahead of the `COMMIT`: in an aborted
/// transaction it fails `25P02` (`in_failed_sql_transaction`), and the
/// transaction is rolled back and reported as [`DbError::TransactionAborted`].
/// That costs one extra round trip per commit; the zero-round-trip forms are
/// out of reach — the driver exposes neither the `COMMIT` command tag
/// (`SimpleQueryMessage::CommandComplete` carries only a row count) nor the
/// `ReadyForQuery` transaction status, and sending the probe and `COMMIT` in
/// one query string would leave `deadpool_postgres::Transaction` believing
/// the transaction still open, so its drop would issue a stray `ROLLBACK`.
///
/// A deliberate recovery — `ROLLBACK TO SAVEPOINT` after a failed statement —
/// leaves the transaction healthy, so the probe passes and the commit runs.
///
/// # Errors
///
/// - [`DbError::TransactionAborted`] when the transaction was aborted; it has
///   been rolled back. This is a bug in the code that ran inside it, which
///   swallowed the statement error that aborted it.
/// - [`DbError::Postgres`] when the probe fails for another reason (the
///   transaction is rolled back, best effort) or the `COMMIT` itself fails —
///   a deferred constraint or a serialization failure, which `PostgreSQL`
///   reports as an error.
pub async fn commit_checked(tx: deadpool_postgres::Transaction<'_>) -> Result<(), DbError> {
    if let Err(probe_err) = tx.batch_execute("SELECT 1").await {
        if let Err(rollback_err) = tx.rollback().await {
            let error: &(dyn std::error::Error + 'static) = &rollback_err;
            tracing::warn!(error, "db tx rollback failed");
        }
        return Err(
            if probe_err.code() == Some(&SqlState::IN_FAILED_SQL_TRANSACTION) {
                DbError::TransactionAborted(probe_err)
            } else {
                DbError::Postgres(probe_err)
            },
        );
    }
    tx.commit().await.map_err(DbError::Postgres)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_checkout_timeout_is_five_seconds() {
        assert_eq!(
            PoolOptions::default().checkout_timeout,
            Duration::from_secs(5)
        );
        assert_eq!(DEFAULT_CHECKOUT_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn pool_config_bounds_every_checkout_step() {
        let timeout = Duration::from_millis(250);
        let cfg = pool_config_with_options(
            "postgres://u@localhost/db",
            &PoolOptions {
                checkout_timeout: timeout,
            },
        )
        .unwrap();
        let timeouts = cfg.pool.unwrap().timeouts;
        assert_eq!(timeouts.wait, Some(timeout));
        assert_eq!(timeouts.create, Some(timeout));
        assert_eq!(timeouts.recycle, Some(timeout));
    }
}
