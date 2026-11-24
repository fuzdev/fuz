//! The fresh database every spine DB test opens: [`fresh_test_db`].
//!
//! By default each call starts a pglet server of its own, in this process, on
//! a loopback port (`pglet_server`'s library, its in-memory B+tree store), runs
//! the suite's migration chain and scratch DDL, and hands back a [`TestDb`]
//! that stops the server when it drops. A test's database is its own, so the
//! suites run in parallel under a plain `cargo test`, with nothing to create
//! out of band and nothing to wipe.
//!
//! Set [`FUZ_TEST_POSTGRES_URL`] to a PostgreSQL server and a role with
//! `CREATEDB`, and every call instead creates a database of its own there
//! (named from the suite, unique per process and call) and drops it when the
//! [`TestDb`] drops. That's the leg that catches a test passing only because
//! pglet is lenient, and the only one a [`TestEngine::Postgres`] test runs on.
//!
//! ### Postgres-only tests
//!
//! A test that observes what only PostgreSQL has (backends, lock waits,
//! `CREATE DATABASE`, triggers) opens its database with
//! [`TestEngine::Postgres`] and carries `#[ignore = "postgres-only: <why>"]`;
//! one blocked only on a pglet feature still to come carries
//! `#[ignore = "pglet: <feature>"]` and the same engine. Run under
//! `--ignored` without [`FUZ_TEST_POSTGRES_URL`], such a test panics naming the
//! variable rather than passing without having run.
//!
//! ### Dropping a PostgreSQL database
//!
//! `DROP DATABASE` is async work a sync `Drop` must finish. [`TestDb`]'s drop
//! runs it on a thread of its own, with a current-thread runtime and a fresh
//! admin connection of its own, and joins it: nothing it waits on needs the
//! test's runtime, so it can't deadlock a `#[tokio::test]`'s current-thread
//! runtime, and `WITH (FORCE)` ends the test pool's still-open connections
//! server-side (waiting out an autovacuum worker, which `FORCE` can't end for
//! a role that isn't a superuser, and a connection a still-running task opens
//! meanwhile). A drop that still fails is reported on
//! stderr. A process killed before its drops ran leaves its databases;
//! each is named `fuz_testing_<suite>_<pid>_<n>`, so they're found by that
//! prefix.
//!
//! ### Not [`crate::db_reset`]
//!
//! [`crate::db_reset`] is the env-gated *startup* reset a long-running test
//! **binary** performs on itself once, before its own migrations. This module
//! is the *in-process* setup a test calls per test case, against a database it
//! then keeps. See that module's "Why this is separate" section for the third
//! variant ([`crate::testing_reset`], the per-test row wipe over the wire).

#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "a test harness: a setup fault panics loudly naming the step, and the in-tests carve-out doesn't reach a library module"
)]

use std::io::Write as _;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fuz_db::{MigrationNamespace, Pool, create_pool, run_migrations};
use tokio_postgres::error::SqlState;

/// The variable that moves every DB test onto PostgreSQL.
///
/// A connection URL naming a server and a role with `CREATEDB`, through which
/// each test creates and drops a database of its own. Unset, the tests run on
/// pglet.
pub const FUZ_TEST_POSTGRES_URL: &str = "FUZ_TEST_POSTGRES_URL";

/// Which engines a test's database may run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TestEngine {
    /// Whichever the run names: pglet by default, PostgreSQL under
    /// [`FUZ_TEST_POSTGRES_URL`].
    #[default]
    Any,
    /// PostgreSQL only; without [`FUZ_TEST_POSTGRES_URL`] the test panics
    /// naming it. Its test is `#[ignore]`d, so a plain `cargo test` skips it.
    Postgres,
}

/// Per-suite parameters for [`fresh_test_db`].
///
/// `Copy` and const-constructible, so a suite declares one `const` and a
/// Postgres-only test derives its own with [`TestingDbOptions::postgres_only`].
#[derive(Debug, Clone, Copy)]
pub struct TestingDbOptions<'a> {
    /// The suite's name (`fuz_auth`, `fuz_db_status`): the stem of each
    /// PostgreSQL database it creates, `fuz_testing_<suite>_<pid>_<n>`, so a
    /// leftover names its suite. Lowercase ASCII, digits, and `_`, starting
    /// with a letter, at most [`SUITE_NAME_LENGTH_MAX`] bytes.
    pub suite: &'a str,
    /// Migration chains to run on the fresh database, in FK order (auth
    /// before cell, since `cell` FKs into `actor`). An empty slice skips the
    /// migration step entirely, handing back a bare database — what a suite
    /// that drives `run_migrations` itself wants. The skip is load-bearing:
    /// `run_migrations` executes `SCHEMA_VERSION_DDL` even for zero
    /// namespaces, and the bare-database suites assert no tracker exists.
    pub migrations: &'a [MigrationNamespace],
    /// Extra DDL executed after the migrations, for suites that need scratch
    /// tables the chains don't create (a `cell` stub, a `probe` table,
    /// composite-PK fixtures). Passed to `batch_execute`, so multiple
    /// statements in one string are fine.
    pub setup_sql: Option<&'a str>,
    /// The engines the suite's tests may run on.
    pub engine: TestEngine,
}

impl TestingDbOptions<'_> {
    /// These options with [`TestEngine::Postgres`], for a Postgres-only test
    /// in a suite whose const runs on any engine.
    #[must_use]
    pub const fn postgres_only(self) -> Self {
        Self {
            engine: TestEngine::Postgres,
            ..self
        }
    }
}

/// The longest [`TestingDbOptions::suite`]: PostgreSQL truncates a name past
/// 63 bytes, and `fuz_testing_`, `_<pid>`, and `_<n>` take the rest.
pub const SUITE_NAME_LENGTH_MAX: usize = 24;

/// What every database [`fresh_test_db`] creates on PostgreSQL begins with.
const DATABASE_PREFIX: &str = "fuz_testing_";

/// A test's own database: the pool on it, its URL, and what backs it — a
/// pglet server stopped on drop, or a PostgreSQL database dropped on drop.
///
/// Derefs to its [`Pool`], so a test holds the `TestDb` as its `pool` and
/// passes `&pool` wherever a `&Pool` goes; holding it is what keeps the
/// database alive, so a test keeps the `TestDb`, never only a clone of its
/// pool.
#[derive(Debug)]
pub struct TestDb {
    // Field order is drop order: the pool's connections close before the
    // backing goes.
    pool: Pool,
    url: String,
    _backing: Backing,
}

impl TestDb {
    /// The database's connection URL, for a second pool on it (a budgeted
    /// pool, a raw `tokio_postgres` connection) or a `testing_*` binary.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The pool on the database.
    #[must_use]
    pub const fn pool(&self) -> &Pool {
        &self.pool
    }
}

impl Deref for TestDb {
    type Target = Pool;

    fn deref(&self) -> &Pool {
        &self.pool
    }
}

/// What a [`TestDb`] runs on.
#[derive(Debug)]
enum Backing {
    /// A pglet server in this process, stopped when its handle drops.
    Pglet { _server: pglet_server::ServerHandle },
    /// A database created on a PostgreSQL server, dropped when this drops.
    Postgres { _database: PostgresDatabase },
}

/// A database [`fresh_test_db`] created on a PostgreSQL server.
#[derive(Debug)]
struct PostgresDatabase {
    /// The [`FUZ_TEST_POSTGRES_URL`] it was created through.
    admin_url: String,
    name: String,
}

impl Drop for PostgresDatabase {
    fn drop(&mut self) {
        let admin_url = std::mem::take(&mut self.admin_url);
        let name = std::mem::take(&mut self.name);
        let dropped = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(async {
                let (client, connection) =
                    tokio_postgres::connect(&admin_url, tokio_postgres::NoTls)
                        .await
                        .map_err(|e| e.to_string())?;
                let connection = tokio::spawn(connection);
                let drop_sql = format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)");
                let mut result = client.batch_execute(&drop_sql).await;
                // `FORCE` can't end an autovacuum worker for a role that isn't
                // a superuser (`42501`), and a task the test left running can
                // open a connection between its terminations and the drop
                // (`55006`); both pass in moments, so wait them out.
                for _ in 0..DROP_RETRIES {
                    match &result {
                        Err(e)
                            if e.code() == Some(&SqlState::INSUFFICIENT_PRIVILEGE)
                                || e.code() == Some(&SqlState::OBJECT_IN_USE) =>
                        {
                            tokio::time::sleep(DROP_RETRY_DELAY).await;
                            result = client.batch_execute(&drop_sql).await;
                        }
                        _ => break,
                    }
                }
                let result = result.map_err(|e| {
                    e.as_db_error().map_or_else(
                        || e.to_string(),
                        |db| format!("{}: {}", db.code().code(), db.message()),
                    )
                });
                drop(client);
                drop(connection.await);
                result.map_err(|e| format!("{name}: {e}"))
            })
        })
        .join();
        // A drop can't fail the test it ends (a panic while unwinding aborts),
        // so a failed drop is reported and the database left behind — on
        // stderr itself, not through `eprintln!`, which the test harness
        // captures and shows only for a failed test.
        let report = match dropped {
            Ok(Ok(())) => return,
            Ok(Err(e)) => format!("fuz_testing: a test database was left behind: {e}\n"),
            Err(_) => "fuz_testing: a test database's drop panicked\n".to_owned(),
        };
        drop(std::io::stderr().write_all(report.as_bytes()));
    }
}

/// How many times a drop refused for a backend it can't end is retried, and
/// how long apart: a test database's autovacuum worker or straggling
/// connection outlives neither.
const DROP_RETRIES: usize = 50;
const DROP_RETRY_DELAY: Duration = Duration::from_millis(100);

/// The bound on the connection a test's setup opens first, which the
/// migrations, `setup_sql`, and the test's first checkout reuse: long, since
/// setup on a loaded machine is slow, not broken.
const SETUP_CHECKOUT_TIMEOUT: Duration = Duration::from_secs(30);

/// Databases created through [`FUZ_TEST_POSTGRES_URL`] by this process, for
/// the `<n>` that keeps their names unique.
static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

/// Open a fresh database for one test: run `options.migrations`, apply
/// `options.setup_sql`, and return it with its pool.
///
/// On pglet unless [`FUZ_TEST_POSTGRES_URL`] is set (see the module docs).
///
/// # Panics
///
/// With the failing step named: a [`TestEngine::Postgres`] test without
/// [`FUZ_TEST_POSTGRES_URL`], an invalid [`TestingDbOptions::suite`], a pglet
/// server that doesn't start, a database that can't be created or reached, a
/// failed migration, or failed `setup_sql` — setup faults a test body can do
/// nothing about.
pub async fn fresh_test_db(options: TestingDbOptions<'_>) -> TestDb {
    assert_suite_name(options.suite);
    let postgres_url = std::env::var(FUZ_TEST_POSTGRES_URL).ok();
    let (url, backing) = match (postgres_url, options.engine) {
        (Some(admin_url), _) => {
            let database = create_postgres_database(admin_url, options.suite).await;
            let url = database_url_with_name(&database.admin_url, &database.name);
            (
                url,
                Backing::Postgres {
                    _database: database,
                },
            )
        }
        (None, TestEngine::Any) => {
            let handle = pglet_server::Server::open(&pglet_server::ServerOptions::default())
                .expect("open a pglet server")
                .spawn_loopback()
                .expect("start a pglet server on loopback");
            let url = format!("postgres://pglet@{}/pglet", handle.local_addr());
            (url, Backing::Pglet { _server: handle })
        }
        (None, TestEngine::Postgres) => panic!(
            "this test runs only on PostgreSQL: set {FUZ_TEST_POSTGRES_URL} to a server and a \
             role with CREATEDB (e.g. postgres://localhost/postgres)"
        ),
    };
    let pool = create_pool(&url, &fuz_db::PoolOptions::default()).expect("create_pool");
    // Warm the pool with one connection under a long bound, so a loaded
    // machine (parallel tests, each `DROP DATABASE`'s checkpoint) slows setup
    // rather than failing it. The migrations, `setup_sql`, and the test's first
    // checkout reuse that idle connection; the test keeps the default bound.
    drop(
        pool.timeout_get(&fuz_db::checkout_timeouts(SETUP_CHECKOUT_TIMEOUT))
            .await
            .expect("connect for setup"),
    );
    if !options.migrations.is_empty() {
        run_migrations(&pool, options.migrations)
            .await
            .expect("migrations");
    }
    if let Some(sql) = options.setup_sql {
        let client = pool.get().await.expect("pool.get");
        client.batch_execute(sql).await.expect("setup_sql");
    }
    TestDb {
        pool,
        url,
        _backing: backing,
    }
}

/// Create `fuz_testing_<suite>_<pid>_<n>` through `admin_url`, from
/// `template0`.
async fn create_postgres_database(admin_url: String, suite: &str) -> PostgresDatabase {
    let n = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
    let name = format!("{DATABASE_PREFIX}{suite}_{}_{n}", std::process::id());
    let (client, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls)
        .await
        .unwrap_or_else(|e| panic!("connect through {FUZ_TEST_POSTGRES_URL}: {e}"));
    let connection = tokio::spawn(connection);
    client
        .batch_execute(&format!("CREATE DATABASE {name} TEMPLATE template0"))
        .await
        .unwrap_or_else(|e| {
            panic!("create {name} through {FUZ_TEST_POSTGRES_URL} (the role needs CREATEDB): {e}")
        });
    drop(client);
    drop(connection.await);
    PostgresDatabase { admin_url, name }
}

/// Refuse a suite name that wouldn't make a database name PostgreSQL keeps as
/// written: anything but lowercase ASCII, digits, and `_` starting with a
/// letter, or longer than [`SUITE_NAME_LENGTH_MAX`].
fn assert_suite_name(suite: &str) {
    assert!(
        suite.starts_with(|c: char| c.is_ascii_lowercase())
            && suite
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && suite.len() <= SUITE_NAME_LENGTH_MAX,
        "test suite name {suite:?} must be lowercase ASCII, digits, and `_`, start with a letter, \
         and be at most {SUITE_NAME_LENGTH_MAX} bytes"
    );
}

/// A pool on the database at `url` that hands out `checkouts` connections and
/// refuses every checkout after them.
///
/// The fault for a handler that checks a connection out *after* an earlier
/// checkout on the same request succeeded — a credential read, an
/// authorization phase, a lookup: a pool that is simply down fails the first
/// checkout, never the one under test. Both `deadpool` hooks spend from one
/// budget — `post_create` when a checkout opens a connection, `pre_recycle`
/// when it reuses one — and once it is spent a reused connection is discarded
/// and its replacement refused, so `get()` returns the error.
///
/// # Panics
///
/// Panics when `url` does not parse as a `tokio_postgres` config.
#[must_use]
pub fn budgeted_pool(url: &str, checkouts: usize) -> Pool {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use deadpool_postgres::{Hook, HookError, Manager, Runtime};

    let config: tokio_postgres::Config = url.parse().expect("test URL parses");
    let remaining = Arc::new(AtomicUsize::new(checkouts));
    let spend = move || {
        remaining
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .map(drop)
            .map_err(|_| HookError::message("checkout budget spent"))
    };
    let spend_on_recycle = spend.clone();
    Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(Runtime::Tokio1)
        .post_create(Hook::sync_fn(move |_, _| spend()))
        .pre_recycle(Hook::sync_fn(move |_, _| spend_on_recycle()))
        .build()
        .expect("budgeted pool builds")
}

/// `url` with its database name replaced by `name`, keeping the user, host,
/// port, and query.
///
/// Expects a plain `postgres://` URL with the database in the path
/// (`postgres://user@host:5432/db?sslmode=…`) — not a key/value connection
/// string, and not one naming the database with `?dbname=`, which this would
/// leave in place.
fn database_url_with_name(url: &str, name: &str) -> String {
    let path_start = url.find("://").map_or(0, |i| i + 3);
    let db_start = url[path_start..]
        .find('/')
        .map_or(url.len(), |i| path_start + i);
    let db_end = url[db_start..]
        .find('?')
        .map_or(url.len(), |i| db_start + i);
    format!("{}/{name}{}", &url[..db_start], &url[db_end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_url_with_name_swaps_only_the_database() {
        assert_eq!(
            database_url_with_name("postgres://localhost/postgres", "fuz_testing_suite_1_0"),
            "postgres://localhost/fuz_testing_suite_1_0"
        );
        assert_eq!(
            database_url_with_name(
                "postgres://u:p@localhost:5432/postgres?sslmode=disable",
                "fuz_testing_suite_1_0"
            ),
            "postgres://u:p@localhost:5432/fuz_testing_suite_1_0?sslmode=disable"
        );
        assert_eq!(
            database_url_with_name("postgres://localhost", "fuz_testing_suite_1_0"),
            "postgres://localhost/fuz_testing_suite_1_0"
        );
    }

    #[test]
    fn a_lowercase_suite_name_passes() {
        assert_suite_name("fuz_db_status");
    }

    #[test]
    #[should_panic(expected = "must be lowercase ASCII")]
    fn a_mixed_case_suite_name_is_refused() {
        assert_suite_name("Fuz_db");
    }

    #[test]
    #[should_panic(expected = "must be lowercase ASCII")]
    fn a_suite_name_with_a_quote_is_refused() {
        assert_suite_name("fuz\"db");
    }

    #[test]
    #[should_panic(expected = "must be lowercase ASCII")]
    fn a_long_suite_name_is_refused() {
        assert_suite_name(&"a".repeat(SUITE_NAME_LENGTH_MAX + 1));
    }

    #[tokio::test]
    async fn a_fresh_database_runs_its_setup_and_is_its_own() {
        const OPTIONS: TestingDbOptions<'static> = TestingDbOptions {
            suite: "fuz_testing",
            migrations: &[],
            setup_sql: Some("CREATE TABLE probe (id int PRIMARY KEY)"),
            engine: TestEngine::Any,
        };
        let a = fresh_test_db(OPTIONS).await;
        let b = fresh_test_db(OPTIONS).await;
        assert_ne!(a.url(), b.url());
        a.get()
            .await
            .expect("pool.get")
            .batch_execute("INSERT INTO probe VALUES (1)")
            .await
            .expect("insert into a");
        let count: i64 = b
            .get()
            .await
            .expect("pool.get")
            .query_one("SELECT count(*) FROM probe", &[])
            .await
            .expect("count b")
            .get(0);
        assert_eq!(count, 0, "b sees none of a's rows");
    }

    /// Setup's warmed connection is the one the test's first checkout gets:
    /// the pool holds one connection, idle, and a checkout opens no other.
    #[tokio::test]
    async fn the_first_checkout_reuses_setups_connection() {
        let db = fresh_test_db(TestingDbOptions {
            suite: "fuz_testing",
            migrations: &[],
            setup_sql: Some("CREATE TABLE probe (id int PRIMARY KEY)"),
            engine: TestEngine::Any,
        })
        .await;
        let status = db.status();
        assert_eq!((status.size, status.available), (1, 1), "{status:?}");
        let client = db.get().await.expect("pool.get");
        assert_eq!(
            db.status().size,
            1,
            "the checkout reused setup's connection"
        );
        drop(client);
    }
}
