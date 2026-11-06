//! [`StartupError`] — why a spine server failed to boot or serve, with the
//! exit-code policy and the operator hints.

use std::net::SocketAddr;

use crate::RegistryBuildError;

/// The one `default_transaction_isolation` a spine server serves under.
///
/// The spine relies on READ COMMITTED: its dispatcher opens transactions
/// with a plain `BEGIN`, so they run at the database's default, and the
/// serializing reads a handler makes after a row lock (a consumer's
/// last-owner rule, say) need the fresh per-statement snapshot only READ
/// COMMITTED takes. `read uncommitted` is refused too, though Postgres runs
/// it as READ COMMITTED: it names a level the spine does not run at, a
/// Postgres-compatible engine might honor it, and dropping it costs nothing.
pub const REQUIRED_TRANSACTION_ISOLATION: &str = "read committed";

/// Errors raised while a spine server starts or serves.
///
/// Each variant's text names what failed and keeps its cause as a `#[source]`
/// rather than in its text, so the binary prints the whole chain once through
/// `fuz_sys::cli::format_error_chain` (`fuz_sys::cli::report_failure` with
/// [`Self::hint`] and [`Self::exit_code`]).
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// An env var or other operator configuration is missing or malformed.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Postgres runs new transactions at a level other than
    /// [`REQUIRED_TRANSACTION_ISOLATION`].
    #[error(
        "Postgres's default_transaction_isolation is {found:?}; the server requires \"read committed\""
    )]
    TransactionIsolation {
        /// The setting as `current_setting` reports it.
        found: String,
    },

    /// The listener could not bind.
    #[error("failed to bind to {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// The serve loop failed.
    #[error("server error")]
    Serve(#[source] std::io::Error),

    /// A database operation failed: the pool, a migration, a boot query.
    #[error("database error")]
    Database(#[from] fuz_db::DbError),

    /// The action registry refused the assembled specs — a duplicate or
    /// malformed method, or a spec breaking a registry invariant. A build
    /// defect: booting an empty registry instead would answer
    /// `method_not_found` to every call.
    #[error("action registry compile failed")]
    ActionRegistry(#[from] RegistryBuildError),

    /// The `expected_schema.json` embedded for `/ready` is not a column map.
    /// A build defect, not configuration: the fixture is compiled in.
    #[error("the embedded expected_schema.json failed to parse")]
    ExpectedSchema(#[source] serde_json::Error),

    /// Anything else.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<fuz_http::ServerEnvError> for StartupError {
    fn from(error: fuz_http::ServerEnvError) -> Self {
        Self::Config(error.0)
    }
}

impl StartupError {
    /// The process exit code: `2` when the operator must change configuration
    /// before the server can boot (an env var, the database's isolation
    /// setting), `1` for everything else.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::TransactionIsolation { .. } => 2,
            Self::Bind { .. }
            | Self::Serve(_)
            | Self::Database(_)
            | Self::ActionRegistry(_)
            | Self::ExpectedSchema(_)
            | Self::Internal(_) => 1,
        }
    }

    /// A remediation hint printed under the error, where there is a general
    /// one. A consumer with a better one for its deploy (an env example to
    /// point at) prints its own.
    ///
    /// A database error gets the connectivity hint only when reaching the
    /// database is what failed — before a migration or during one: a
    /// migration whose driver error carries no SQLSTATE lost its connection
    /// rather than ran a bad body, which the server would have answered with
    /// a code. A migration refusal's own message carries its remedy (a binary
    /// older than the database, a name divergence, a failed body), where the
    /// connectivity hint would mislead an operator who has rolled back; an
    /// invalid identifier or an aborted transaction is a code defect.
    #[must_use]
    pub fn hint(&self) -> Option<&'static str> {
        const CONNECTIVITY: &str =
            "check that Postgres is running and DATABASE_URL points at a database";
        match self {
            Self::Database(
                fuz_db::DbError::InvalidUrl(_)
                | fuz_db::DbError::PoolBuild(_)
                | fuz_db::DbError::PoolGet(_)
                | fuz_db::DbError::Postgres(_),
            ) => Some(CONNECTIVITY),
            Self::Database(fuz_db::DbError::Migration(fuz_db::MigrationError::Failed {
                source,
                ..
            })) if source.code().is_none() => Some(CONNECTIVITY),
            Self::Bind { .. } => {
                Some("another process may hold the port; set PORT to move the server")
            }
            Self::TransactionIsolation { .. } => Some(
                "set default_transaction_isolation back to 'read committed', the Postgres default, \
                 wherever it was changed: postgresql.conf, ALTER DATABASE ... SET, or \
                 ALTER ROLE ... SET (psql's \\drds lists the database and role settings)",
            ),
            Self::ExpectedSchema(_) => {
                Some("regenerate expected_schema.json from a fresh migration run and rebuild")
            }
            Self::Database(
                fuz_db::DbError::Migration(_)
                | fuz_db::DbError::InvalidIdentifier(_)
                | fuz_db::DbError::TransactionAborted(_),
            )
            | Self::Config(_)
            | Self::Serve(_)
            | Self::ActionRegistry(_)
            | Self::Internal(_) => None,
        }
    }
}

/// `Ok` when `value`, a `default_transaction_isolation` setting, is exactly
/// [`REQUIRED_TRANSACTION_ISOLATION`].
///
/// # Errors
///
/// [`StartupError::TransactionIsolation`] for any other value.
pub fn check_transaction_isolation(value: &str) -> Result<(), StartupError> {
    if value == REQUIRED_TRANSACTION_ISOLATION {
        Ok(())
    } else {
        Err(StartupError::TransactionIsolation {
            found: value.to_owned(),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use super::*;

    fn malformed_json() -> serde_json::Error {
        serde_json::from_str::<serde_json::Value>("{").expect_err("malformed")
    }

    #[test]
    fn exit_codes_key_to_the_operator_remedy() {
        let cases: [(StartupError, u8); 8] = [
            (StartupError::Config(String::new()), 2),
            (
                StartupError::TransactionIsolation {
                    found: "serializable".to_owned(),
                },
                2,
            ),
            (
                StartupError::Bind {
                    addr: "127.0.0.1:1".parse().expect("addr"),
                    source: std::io::Error::other("in use"),
                },
                1,
            ),
            (StartupError::Serve(std::io::Error::other("boom")), 1),
            (
                StartupError::Database(fuz_db::DbError::InvalidUrl(String::new())),
                1,
            ),
            (
                StartupError::ActionRegistry(RegistryBuildError::EmptyMethod),
                1,
            ),
            (StartupError::ExpectedSchema(malformed_json()), 1),
            (StartupError::Internal(String::new()), 1),
        ];
        for (error, code) in cases {
            assert_eq!(error.exit_code(), code, "{error}");
        }

        // a database error points at connectivity only when connecting failed;
        // a migration refusal carries its own remedy
        let database = |e| StartupError::Database(e);
        assert!(
            database(fuz_db::DbError::InvalidUrl(String::new()))
                .hint()
                .is_some_and(|h| h.contains("DATABASE_URL"))
        );
        assert!(
            database(fuz_db::DbError::PoolBuild(String::new()))
                .hint()
                .is_some()
        );
        for error in [
            fuz_db::DbError::Migration(fuz_db::MigrationError::Diverged {
                namespace: "app".to_owned(),
                divergence: fuz_db::Divergence::BinaryOlder {
                    declared: 1,
                    unknown: vec!["newer".to_owned()],
                },
            }),
            fuz_db::DbError::InvalidIdentifier("x y".to_owned()),
        ] {
            assert_eq!(database(error).hint(), None);
        }
    }

    #[tokio::test]
    async fn a_migration_that_lost_its_connection_gets_the_connectivity_hint() {
        // a driver error with no SQLSTATE: the server never answered, as when
        // the connection drops mid-chain (a bad body answers with a code — the
        // `server_boot` PG suite pins that it gets no hint)
        let source = tokio_postgres::connect("host=127.0.0.1 port=1", tokio_postgres::NoTls)
            .await
            .err()
            .expect("nothing listens on port 1");
        assert_eq!(source.code(), None);
        let error =
            StartupError::Database(fuz_db::DbError::Migration(fuz_db::MigrationError::Failed {
                namespace: "app".to_owned(),
                name: "create_widget".to_owned(),
                index: 0,
                source,
            }));
        assert!(error.hint().is_some_and(|h| h.contains("DATABASE_URL")));
    }

    #[test]
    fn an_env_error_is_configuration() {
        let error = StartupError::from(fuz_http::ServerEnvError("PORT: bad".to_owned()));
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.to_string(), "invalid configuration: PORT: bad");
    }

    #[test]
    fn a_cause_prints_once_in_the_chain() {
        // the text names the failure and leaves the cause to the source chain
        let error = StartupError::ActionRegistry(RegistryBuildError::DuplicateMethod("x"));
        assert_eq!(error.to_string(), "action registry compile failed");
        let source = std::error::Error::source(&error).expect("a source");
        assert_eq!(source.to_string(), "duplicate method registered: x");
        let error = StartupError::Database(fuz_db::DbError::InvalidUrl("u".to_owned()));
        assert_eq!(error.to_string(), "database error");
    }

    #[test]
    fn only_read_committed_passes_the_isolation_check() {
        check_transaction_isolation("read committed").expect("the Postgres default passes");
        for value in [
            "repeatable read",
            "serializable",
            "read uncommitted",
            "READ COMMITTED",
            "",
        ] {
            let error = check_transaction_isolation(value).expect_err(value);
            assert!(
                matches!(&error, StartupError::TransactionIsolation { found } if found == value),
                "{error}"
            );
            assert!(
                error
                    .hint()
                    .is_some_and(|h| h.contains("default_transaction_isolation"))
            );
        }
    }
}
