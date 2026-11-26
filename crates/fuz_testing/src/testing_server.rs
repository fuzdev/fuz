//! What a `testing_*` server binary wires into the spine server toolkit.
//!
//! For `fuz_actions::server`: the test backend options (the test hasher,
//! limiters off, in-flight audit tracking), the daemon-token credential it
//! can't run without, and the harness's backdoors — `_testing_reset`,
//! `_testing_drain_effects` and `_testing_db_invariants` — with the domain
//! truncate the reset runs.

use std::sync::Arc;

use fuz_actions::server::{
    AppBackend, AppBackendSpec, SpineBackendOptions, StartupError, build_app_backend,
};
use fuz_actions::{ActionSpec, ExtraActionSpecsRuntime};
use fuz_auth::SharedDaemonTokenState;

use crate::testing_reset::{ResetStateFn, TestingResetOptions, create_testing_reset_action_spec};

/// The backend options every `testing_*` server binary runs with.
///
/// - [`crate::TestingArgon2idHasher`], fast argon2 (it announces itself);
/// - every spine limiter built through
///   [`fuz_auth::RateLimiterMode::DisabledForTesting`] — the cross-backend
///   suites log in and sign up many times per process, past any per-IP
///   budget — with the once-per-process banner announcing the nulls;
/// - `daemon_token_state`, the keeper credential `_testing_reset`
///   authenticates with;
/// - `auth_cleanup`, the caller's, as in production: a consumer's test binary
///   runs its production server's schedule, and `testing_spine_stub`, held
///   to a TS test server that schedules none, runs `Off`.
///
/// A server that differs sets the field with struct-update syntax: a suite
/// that drives the limiters selects `rate_limiters` from its env gate, and a
/// server's own login bound is its own (`login_ip_rate_limit`).
#[must_use]
pub fn testing_backend_options(
    daemon_token_state: SharedDaemonTokenState,
    auth_cleanup: fuz_auth::AuthCleanupSchedule,
) -> SpineBackendOptions {
    SpineBackendOptions {
        rate_limiters: fuz_auth::RateLimiterMode::DisabledForTesting,
        daemon_token_state: Some(daemon_token_state),
        ..SpineBackendOptions::production(
            Arc::new(crate::TestingArgon2idHasher::new()),
            auth_cleanup,
        )
    }
}

/// `_testing_reset`, `_testing_drain_effects` and `_testing_db_invariants`,
/// the backdoors every `testing_*` server's extra specs start with — what
/// `fuz_app`'s cross-process setups call around each test.
///
/// The reset wipes the auth tables and seeds a fresh keeper as the runtime's
/// daemon-token state, running `reset_state` (the server's domain state —
/// [`truncate_reset_state`] over its tables) on the same transaction; the
/// drain awaits the emitter's in-flight writes, a barrier under
/// [`testing_backend_options`]' tracking; the invariants read answers the rows
/// breaking a database invariant, which the setup checks after each test.
///
/// # Errors
///
/// [`StartupError::Config`] (exit `2`) when `runtime` carries no daemon-token
/// state: the backend was built without one, so the reset has no keeper
/// credential to authenticate.
pub fn testing_reset_specs(
    runtime: &ExtraActionSpecsRuntime,
    reset_state: Option<ResetStateFn>,
) -> Result<Vec<ActionSpec>, StartupError> {
    let daemon_token_state = runtime.daemon_token_state.clone().ok_or_else(|| {
        StartupError::Config(
            "_testing_reset needs a daemon-token credential: the backend was built without one \
             (see `fuz_testing::testing_backend_options`)"
                .into(),
        )
    })?;
    Ok(vec![
        create_testing_reset_action_spec(TestingResetOptions {
            password_hasher: Arc::clone(&runtime.password_hasher),
            keyring: Arc::clone(&runtime.keyring),
            daemon_token_state,
            session_cookie_name: runtime.session_cookie_name,
            reset_state,
        }),
        crate::create_testing_drain_effects_action_spec(Arc::clone(&runtime.background_writes)),
        crate::create_testing_db_invariants_action_spec(),
    ])
}

/// Mint the daemon-token credential under the dir `var` names — the channel
/// the binary's `_testing_reset` authenticates as keeper over, so a test
/// binary refuses to start without it.
///
/// # Errors
///
/// [`StartupError::Config`] (exit `2`) when `var` is unset or empty, or the
/// credential can't be written under it.
pub async fn require_daemon_token_from_env(
    var: &str,
) -> Result<SharedDaemonTokenState, StartupError> {
    match crate::daemon_token::init_daemon_token_from_env(var).await {
        Ok(Some(state)) => Ok(state),
        Ok(None) => Err(StartupError::Config(format!(
            "{var} is required (the daemon-token credential _testing_reset authenticates as \
             keeper with)"
        ))),
        Err(e) => Err(StartupError::Config(format!(
            "daemon token init failed: {e}"
        ))),
    }
}

/// A `_testing_reset` domain callback that empties `tables` in one
/// `TRUNCATE … RESTART IDENTITY CASCADE` on the reset transaction.
///
/// `tables` is the domain state a server's substrates hold: the spine's
/// consts (`fuz_cell::CELL_DROP_TABLES`, `fuz_fact::FACT_DROP_TABLES`) and the
/// server's own tables, joined with `[SPINE, OWN].concat()`. One statement
/// has no order, so CASCADE and FK edges need none; listing the spine's
/// first is only convention.
#[must_use]
pub fn truncate_reset_state(tables: &[&str]) -> ResetStateFn {
    let sql = format!("TRUNCATE {} RESTART IDENTITY CASCADE", tables.join(", "));
    Arc::new(move |db| {
        let sql = sql.clone();
        Box::pin(async move {
            db.execute(&sql, &[]).await.map_err(|e| {
                fuz_http::internal_error_with_source("_testing_reset domain truncate", &e)
            })?;
            Ok(())
        })
    })
}

/// What [`test_app_backend`] builds a spine core over — the inputs an
/// in-process router test varies, each defaulting to the inert core through
/// [`Self::inert`].
#[derive(Debug, Clone)]
pub struct TestAppBackendOptions<'a> {
    /// The origin allowlist the core's gates enforce.
    pub allowed_origins: fuz_http::AllowedOrigins,
    /// The database the core's lazy pool points at:
    /// [`crate::UNREACHABLE_DATABASE_URL`] for a test without one, a
    /// [`crate::TestDb::url`] for one with a database.
    pub database_url: &'a str,
    /// The spine limiters: disabled by default, enforced for a test of a
    /// limiter.
    pub rate_limiters: fuz_auth::RateLimiterMode,
    /// The bootstrap token file, for a test of the bootstrap surface; `None`
    /// mounts none.
    pub bootstrap_token_path: Option<std::path::PathBuf>,
}

impl TestAppBackendOptions<'static> {
    /// The inert core over `allowed_origins`: the unreachable database, the
    /// limiters disabled, no bootstrap token.
    #[must_use]
    pub const fn inert(allowed_origins: fuz_http::AllowedOrigins) -> Self {
        Self {
            allowed_origins,
            database_url: crate::UNREACHABLE_DATABASE_URL,
            rate_limiters: fuz_auth::RateLimiterMode::DisabledForTesting,
            bootstrap_token_path: None,
        }
    }
}

/// A spine core for an in-process router test, built without booting.
///
/// Built through the production `build_app_backend` over `spec`, so the
/// fields are the ones a server boots with, on [`crate::TestingArgon2idHasher`],
/// no daemon token, no auth cleanup, no trusted proxy (the test peer is the
/// client), and a fixture cookie key. The pool is lazy: nothing connects until
/// a request checks a connection out, so over the unreachable database
/// anything that touches it fails, while a gate that refuses first (origin,
/// cap) answers as in production.
///
/// # Panics
///
/// When the core doesn't build (a spec the toolkit refuses).
#[expect(clippy::expect_used, reason = "a core that won't build is a test bug")]
#[must_use]
pub fn test_app_backend(spec: &AppBackendSpec, options: TestAppBackendOptions<'_>) -> AppBackend {
    let env = fuz_http::BaseServerEnv {
        database_url: Some(options.database_url.to_owned()),
        cookie_keys: Some("k".repeat(fuz_auth::keyring::MIN_KEY_LENGTH)),
        host: None,
        port: None,
        allowed_origins: options.allowed_origins,
        allow_origin_wildcards: false,
        trusted_proxies: Vec::new(),
        bootstrap_token_path: options.bootstrap_token_path,
        db_checkout_timeout: fuz_db::DEFAULT_CHECKOUT_TIMEOUT,
        db_audit_checkout_timeout: fuz_db::DEFAULT_AUDIT_CHECKOUT_TIMEOUT,
    };
    build_app_backend(
        &env,
        spec,
        &SpineBackendOptions {
            rate_limiters: options.rate_limiters,
            // never served on a schedule: nothing to sweep beside
            ..SpineBackendOptions::production(
                Arc::new(crate::TestingArgon2idHasher::new()),
                fuz_auth::AuthCleanupSchedule::Off,
            )
        },
    )
    .expect("a test core builds without connecting")
}

/// A spine core over inert handles, for a test without a database:
/// [`test_app_backend`] over [`TestAppBackendOptions::inert`], with
/// `allowed_origins` parsed as `FUZ_ALLOWED_ORIGINS` is.
///
/// For a test that composes a server's routers or reads its spec table.
///
/// # Panics
///
/// When `allowed_origins` doesn't parse.
#[expect(
    clippy::expect_used,
    reason = "a malformed test allowlist is a test bug"
)]
#[must_use]
pub fn inert_app_backend(spec: &AppBackendSpec, allowed_origins: &str) -> AppBackend {
    test_app_backend(
        spec,
        TestAppBackendOptions::inert(
            fuz_http::AllowedOrigins::parse(allowed_origins).expect("the test allowlist parses"),
        ),
    )
}

/// Assert a `testing_*` server binary keeps the strict server command line.
///
/// Runs the real binary at `bin_path` with an empty environment: `--help`
/// and `-h` exit `0` with usage naming `name` on stdout, and an unknown
/// command, a flag, or an extra argument exits `2` with that usage on stderr,
/// before the env is read and before the startup sentinel (`starting`).
///
/// `name` is the binary's name as its usage line prints it; call it with
/// `env!("CARGO_BIN_EXE_<name>")`.
///
/// # Panics
///
/// When the binary can't be spawned, or any of the above doesn't hold.
#[expect(
    clippy::expect_used,
    reason = "a test harness: a spawn fault panics loudly naming the binary"
)]
pub fn assert_strict_server_argv(bin_path: &str, name: &str) {
    let run = |args: &[&str]| {
        std::process::Command::new(bin_path)
            .args(args)
            .env_clear()
            .output()
            .expect("spawn the testing binary")
    };
    let usage = format!("Usage: {name} [command]");
    for flag in ["--help", "-h"] {
        let out = run(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{name} {flag}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.starts_with(&usage), "{name} {flag}: {stdout}");
    }
    for args in [&["strat"][..], &["--port", "1"], &["start", "extra"]] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{name} {args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(&usage), "{name} {args:?}: {stderr}");
        assert!(
            !stderr.contains("starting"),
            "{name} {args:?}: refused before the startup sentinel: {stderr}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unset_daemon_token_dir_refuses_to_start() {
        let error = require_daemon_token_from_env("FUZ_TESTING_UNSET_DAEMON_TOKEN_DIR_FOR_TEST")
            .await
            .expect_err("unset");
        assert_eq!(error.exit_code(), 2);
        assert!(
            error
                .to_string()
                .contains("FUZ_TESTING_UNSET_DAEMON_TOKEN_DIR_FOR_TEST is required"),
            "{error}"
        );
    }

    /// A runtime with no daemon-token state refuses the boot (exit `2`)
    /// rather than mounting a reset with no keeper credential.
    #[tokio::test]
    async fn the_reset_specs_refuse_a_runtime_with_no_daemon_token() {
        const SPEC: AppBackendSpec = AppBackendSpec {
            session_cookie_name: "testing_server_session",
            migration_namespaces: &[],
            expected_schema_json: None,
            audit_sse: None,
            browser_gates: fuz_actions::server::BrowserGateSpec::DEFAULT,
        };
        // the inert backend mounts no daemon token
        let runtime = inert_app_backend(&SPEC, "http://localhost").extra_action_specs_runtime();
        assert!(runtime.daemon_token_state.is_none());
        let error = testing_reset_specs(&runtime, None).expect_err("no daemon token");
        assert_eq!(error.exit_code(), 2);
        assert!(
            error
                .to_string()
                .contains("needs a daemon-token credential"),
            "{error}"
        );
    }
}
