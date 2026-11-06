//! [`ActionDb`] — the database handle a request's action runs against — and
//! [`action_db_dispatch!`](crate::action_db_dispatch), which runs a generic
//! query over it.
//!
//! The dispatcher hands every action handler one of two concrete handles: a
//! pooled client for a read-only action, or the request's transaction for one
//! with side effects. Query functions are generic over
//! `&(impl GenericClient + ?Sized)`, and `GenericClient` is neither dyn-safe
//! nor implementable outside `deadpool_postgres` (it is sealed), so the handle
//! travels as this enum and a caller matches it to reach the concrete client:
//!
//! ```ignore
//! use fuz_db::{ActionDb, action_db_dispatch};
//!
//! async fn read(db: &ActionDb<'_>, id: &uuid::Uuid) -> Result<bool, tokio_postgres::Error> {
//!     action_db_dispatch!(db, client => query_thing_exists(client, id).await)
//! }
//! ```
//!
//! Being a concrete type, `&ActionDb` also rides an object-safe trait method,
//! which is how the spine's consumer hooks receive the request's handle.

/// The database handle a request's action runs against: a pooled client for
/// a read-only action, the request's transaction for one with side effects.
///
/// Exhaustive on purpose: a caller matches it to reach a concrete
/// `GenericClient`, so a new variant must be a compile error at every match,
/// not a runtime fallback. Two shared borrows, so a clone is cheap.
#[derive(Clone)]
pub enum ActionDb<'a> {
    /// `side_effects: false` path — pooled client.
    Pool(&'a deadpool_postgres::Client),
    /// `side_effects: true` path — the request's transaction.
    Tx(&'a deadpool_postgres::Transaction<'a>),
}

impl std::fmt::Debug for ActionDb<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pool(_) => f.write_str("ActionDb::Pool(_)"),
            Self::Tx(_) => f.write_str("ActionDb::Tx(_)"),
        }
    }
}

impl ActionDb<'_> {
    /// Run an INSERT/UPDATE/DELETE statement, returning the affected
    /// row count.
    ///
    /// Forwards to whichever variant is active. Mirrors
    /// `deadpool_postgres::GenericClient::execute`.
    ///
    /// # Errors
    ///
    /// Returns the underlying `tokio_postgres` error.
    pub async fn execute(
        &self,
        query: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<u64, tokio_postgres::Error> {
        use deadpool_postgres::GenericClient as _;
        match self {
            Self::Pool(c) => c.execute(query, params).await,
            Self::Tx(t) => t.execute(query, params).await,
        }
    }

    /// Run a query returning at most one row.
    ///
    /// # Errors
    ///
    /// Returns the underlying `tokio_postgres` error.
    pub async fn query_opt(
        &self,
        query: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Option<tokio_postgres::Row>, tokio_postgres::Error> {
        use deadpool_postgres::GenericClient as _;
        match self {
            Self::Pool(c) => c.query_opt(query, params).await,
            Self::Tx(t) => t.query_opt(query, params).await,
        }
    }

    /// Run a query, returning rows.
    ///
    /// # Errors
    ///
    /// Returns the underlying `tokio_postgres` error.
    pub async fn query(
        &self,
        query: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<tokio_postgres::Row>, tokio_postgres::Error> {
        use deadpool_postgres::GenericClient as _;
        match self {
            Self::Pool(c) => c.query(query, params).await,
            Self::Tx(t) => t.query(query, params).await,
        }
    }
}

/// Evaluate an expression against the concrete client inside an
/// [`ActionDb`].
///
/// `action_db_dispatch!(db, client => body)` binds `client` to the pooled
/// client or the transaction, whichever `db` holds, and evaluates `body` once
/// per arm, so a generic `query_*(client, …)` call monomorphizes for each.
/// `db` is an `ActionDb` or a reference to one; `body` may `.await` and `?`,
/// as it expands inline in the caller's function.
///
/// ```ignore
/// let exists = fuz_db::action_db_dispatch!(db, client => query_thing_exists(client, &id).await)?;
/// ```
#[macro_export]
macro_rules! action_db_dispatch {
    ($db:expr, $client:ident => $body:expr $(,)?) => {
        match $crate::ActionDb::clone(&$db) {
            $crate::ActionDb::Pool($client) => $body,
            $crate::ActionDb::Tx($client) => $body,
        }
    };
}
