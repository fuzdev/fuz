//! The fresh-database cycle shared by the spine's `#[ignore]` `PostgreSQL`
//! suites.
//!
//! Every spine PG suite except the shared-database `fuz_db` / `fuz_http` ones
//! opens the same way: resolve a connection URL from a per-crate env var, build
//! a pool, wipe the `public` schema, run a migration chain — and some then
//! stand up a scratch table or two.
//! [`fresh_test_db_pool`] is that cycle in one place, so each converged suite
//! declares a [`TestingDbOptions`] const and delegates — from its
//! `tests/common/mod.rs`, a standalone test file, or an in-crate
//! `#[cfg(test)]` module.
//!
//! ### Why the schema is dropped, not truncated
//!
//! `DROP SCHEMA public CASCADE; CREATE SCHEMA public` wipes every table, type,
//! and sequence — `schema_version` included, so the chain replays from zero.
//! A hand-maintained per-table drop list drifts silently as migrations add
//! tables; the blanket drop can't. Safe as a one-shot wipe because no spine
//! migration creates a standalone function, trigger, or extension — only
//! tables and the one cell enum, all of which `DROP SCHEMA … CASCADE` removes.
//!
//! ### Single-threaded, always
//!
//! Every suite built on this helper must run one test at a time: under
//! `--test-threads=1`, or with a single test function per test binary (cargo
//! runs test binaries one after another). The pool points at one shared
//! database per crate, so two tests dropping and recreating `public`
//! concurrently race: one test's migration chain replays into another's
//! half-dropped schema, and `schema_version` disagrees with the live tables
//! either way. `#[ignore]` keeps the suites out of `cargo test --workspace`;
//! the run recipe in `docs/testing.md` § Postgres suites supplies the flag.
//!
//! ### Not [`crate::db_reset`]
//!
//! [`crate::db_reset`] is the env-gated *startup* reset a long-running test
//! **binary** performs on itself once, before its own migrations. This module
//! is the *in-process* setup an `#[ignore]` integration test calls per test
//! case, against a pool it then keeps. Same SQL, different consumer — see
//! that module's "Why this is separate" section for the third variant
//! ([`crate::testing_reset`], the per-test row wipe over the wire).

// This module is a test harness: every failure here is a setup fault (no
// reachable Postgres, a broken migration, bad scratch DDL) whose only useful
// response is a loud panic naming the step. `clippy.toml`'s
// `allow-expect-in-tests` carve-out covers `#[test]` bodies, not a library
// module, so the allow is explicit.
#![allow(clippy::expect_used)]

use fuz_db::{MigrationNamespace, Pool, create_pool, run_migrations};

/// Per-suite parameters for [`fresh_test_db_pool`].
///
/// The four fields are exactly the axes that vary across the spine's PG
/// suites; everything else in the cycle (the pool build, the `public`-schema
/// wipe, the `postgres://localhost/` URL prefix) is invariant and lives in the
/// helper.
///
/// `Copy` and const-constructible, so a suite declares one `const` and both
/// [`TestingDbOptions::url`] and [`fresh_test_db_pool`] read it.
#[derive(Debug, Clone, Copy)]
pub struct TestingDbOptions<'a> {
    /// Env var that overrides the connection URL (e.g. `FUZ_AUTH_TEST_URL`).
    /// Each crate owns its own name because each runs a different migration
    /// chain: separate databases keep a broken run inspectable (the schema on
    /// disk is that crate's alone) and let concurrent developer shells target
    /// different crates safely.
    pub env_var: &'a str,
    /// Database name for the `postgres://localhost/<default_db>` fallback used
    /// when `env_var` is unset (e.g. `fuz_auth_test`). Created out of band —
    /// `createdb <default_db>`.
    pub default_db: &'a str,
    /// Migration chains to run after the wipe, in FK order (auth before cell,
    /// since `cell` FKs into `actor`). An empty slice skips the migration step
    /// entirely, handing back a pool over a bare `public` schema — what a
    /// suite that drives `run_migrations` itself wants. The skip is
    /// load-bearing, not cosmetic: `run_migrations` executes
    /// `SCHEMA_VERSION_DDL` unconditionally even for zero namespaces, and the
    /// bare-schema suite asserts no tracker table pre-exists.
    pub migrations: &'a [MigrationNamespace],
    /// Extra DDL executed after the migrations, for suites that need scratch
    /// tables the chains don't create (a `cell` stub, a `probe` table,
    /// composite-PK fixtures). Passed to `batch_execute`, so multiple
    /// statements in one string are fine.
    pub setup_sql: Option<&'a str>,
}

impl TestingDbOptions<'_> {
    /// Resolve the suite's connection URL: [`Self::env_var`] if set, else
    /// `postgres://localhost/<default_db>`.
    ///
    /// Exposed separately from [`fresh_test_db_pool`] for the tests that want
    /// a pool without the wipe (`fuz_auth`'s `login` suite builds one it never
    /// connects, to exercise the no-Postgres denial paths).
    #[must_use]
    pub fn url(&self) -> String {
        std::env::var(self.env_var)
            .unwrap_or_else(|_| format!("postgres://localhost/{}", self.default_db))
    }
}

/// Reset the `public` schema, run `options.migrations`, apply
/// `options.setup_sql`, and return the `Pool` — the shared open of every
/// `#[ignore]` PG suite in the spine.
///
/// See the module docs for why the reset is a blanket `DROP SCHEMA` and why
/// callers must run one test at a time.
///
/// # Panics
///
/// Panics with the failing step named on an unbuildable pool, an unreachable
/// database, a failed schema reset, a failed migration, or failed
/// `setup_sql` — all setup faults a test body can do nothing about.
pub async fn fresh_test_db_pool(options: TestingDbOptions<'_>) -> Pool {
    let pool = create_pool(&options.url(), &fuz_db::PoolOptions::default()).expect("create_pool");
    {
        let client = pool.get().await.expect("pool.get");
        client
            .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            .await
            .expect("reset schema");
    }
    if !options.migrations.is_empty() {
        run_migrations(&pool, options.migrations)
            .await
            .expect("migrations");
    }
    if let Some(sql) = options.setup_sql {
        let client = pool.get().await.expect("pool.get");
        client.batch_execute(sql).await.expect("setup_sql");
    }
    pool
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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
#[must_use]
pub fn database_url_with_name(url: &str, name: &str) -> String {
    let (db_start, db_end) = database_span(url);
    format!("{}/{name}{}", &url[..db_start], &url[db_end..])
}

/// The byte span of `url`'s `/database` path segment: from its `/` (or the
/// end, when there is none) to the query or the end.
fn database_span(url: &str) -> (usize, usize) {
    let path_start = url.find("://").map_or(0, |i| i + 3);
    let db_start = url[path_start..]
        .find('/')
        .map_or(url.len(), |i| path_start + i);
    let db_end = url[db_start..]
        .find('?')
        .map_or(url.len(), |i| db_start + i);
    (db_start, db_end)
}

/// The database name in `url`'s path, empty when it names none.
fn database_name(url: &str) -> &str {
    let (db_start, db_end) = database_span(url);
    url.get(db_start + 1..db_end).unwrap_or("")
}

/// Refuse a scratch name [`ScratchDb::create`]'s forced drop could aim at
/// anything but a scratch database.
///
/// # Panics
///
/// When `name` is not a valid SQL identifier, is not all lowercase (Postgres
/// folds an unquoted name, so the URL would name a different database than the
/// one created), does not end in `_scratch`, or is the suite database itself.
fn assert_scratch_name(name: &str, suite_database: &str) {
    fuz_db::assert_valid_sql_identifier(name).expect("a valid scratch database name");
    assert!(
        !name.chars().any(|c| c.is_ascii_uppercase()),
        "scratch database name {name:?} must be all lowercase: Postgres folds the unquoted name, \
         so its URL would name another database"
    );
    assert!(
        name.ends_with("_scratch"),
        "scratch database name {name:?} must end in `_scratch`, so the forced drop can only \
         reach a scratch database"
    );
    assert!(
        name != suite_database,
        "scratch database name {name:?} is the suite database itself; the forced drop would \
         destroy it"
    );
}

/// A database a test creates empty and drops after, beside its suite's own.
///
/// For a test that changes something database-wide (an `ALTER DATABASE …
/// SET`) that would otherwise leak into every other test sharing the suite
/// database.
///
/// [`Self::create`] drops a leftover of the same name first, so a run that
/// panicked before [`Self::drop_database`] heals on the next. Needs
/// `CREATEDB` on the suite's role.
#[derive(Debug)]
pub struct ScratchDb {
    admin: Pool,
    name: String,
    url: String,
}

impl ScratchDb {
    /// Create `name` (from `template0`) through the suite database `options`
    /// names.
    ///
    /// # Panics
    ///
    /// When `name` could reach anything but a scratch database — not a valid
    /// SQL identifier, not all lowercase, not ending in `_scratch`, or the
    /// suite database's own name — or the suite database is unreachable, or
    /// the drop or create fails.
    pub async fn create(options: TestingDbOptions<'_>, name: &str) -> Self {
        let suite_url = options.url();
        assert_scratch_name(name, database_name(&suite_url));
        let admin = create_pool(&suite_url, &fuz_db::PoolOptions::default()).expect("create_pool");
        let client = admin.get().await.expect("pool.get");
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .await
            .expect("drop a leftover scratch database");
        client
            .batch_execute(&format!("CREATE DATABASE {name} TEMPLATE template0"))
            .await
            .expect("create the scratch database");
        drop(client);
        Self {
            admin,
            name: name.to_owned(),
            url: database_url_with_name(&suite_url, name),
        }
    }

    /// The scratch database's connection URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Drop the scratch database, closing any connection still open to it.
    ///
    /// # Panics
    ///
    /// When the drop fails.
    pub async fn drop_database(self) {
        self.admin
            .get()
            .await
            .expect("pool.get")
            .batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ))
            .await
            .expect("drop the scratch database");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIONS: TestingDbOptions<'static> = TestingDbOptions {
        env_var: "FUZ_TESTING_FRESH_DB_URL_PROBE",
        default_db: "fuz_probe_test",
        migrations: &[],
        setup_sql: None,
    };

    #[test]
    fn url_falls_back_to_localhost_default_db() {
        // The probe env var is never set by the harness, so this exercises the
        // fallback branch without mutating the process environment (which
        // `unsafe_code = "forbid"` rules out anyway).
        assert_eq!(OPTIONS.url(), "postgres://localhost/fuz_probe_test");
    }

    #[test]
    fn database_url_with_name_swaps_only_the_database() {
        assert_eq!(
            database_url_with_name("postgres://localhost/fuz_probe_test", "scratch"),
            "postgres://localhost/scratch"
        );
        assert_eq!(
            database_url_with_name(
                "postgres://u:p@localhost:5432/fuz_probe_test?sslmode=disable",
                "scratch"
            ),
            "postgres://u:p@localhost:5432/scratch?sslmode=disable"
        );
    }

    #[test]
    fn database_name_reads_the_path_segment() {
        assert_eq!(
            database_name("postgres://localhost/suite_test"),
            "suite_test"
        );
        assert_eq!(
            database_name("postgres://u@h:5432/suite_test?sslmode=disable"),
            "suite_test"
        );
        assert_eq!(database_name("postgres://localhost"), "");
    }

    #[test]
    fn a_lowercase_name_ending_in_scratch_passes() {
        assert_scratch_name("suite_test_isolation_scratch", "suite_test");
    }

    #[test]
    #[should_panic(expected = "must be all lowercase")]
    fn a_mixed_case_name_is_refused() {
        assert_scratch_name("Suite_Isolation_scratch", "suite_test");
    }

    #[test]
    #[should_panic(expected = "must end in `_scratch`")]
    fn a_name_not_ending_in_scratch_is_refused() {
        assert_scratch_name("suite_test_isolation", "suite_test");
    }

    #[test]
    #[should_panic(expected = "is the suite database itself")]
    fn the_suite_database_is_refused() {
        assert_scratch_name("suite_scratch", "suite_scratch");
    }
}
