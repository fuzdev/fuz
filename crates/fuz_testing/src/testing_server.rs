//! What a `testing_*` server binary wires into the spine server toolkit.
//!
//! For `fuz_actions::server`: the test backend options (the test hasher,
//! limiters off, the startup schema reset as a pre-migration hook, in-flight
//! audit tracking), the daemon-token credential it can't run without, and the
//! `_testing_reset` + `_testing_drain_effects` pair with the domain truncate
//! the reset runs.

use std::sync::Arc;

use fuz_actions::server::{
    AppBackend, AppBackendSpec, SpineBackendOptions, StartupError, build_app_backend,
};
use fuz_actions::{ActionSpec, ExtraActionSpecsRuntime, PreMigrationHook};
use fuz_auth::SharedDaemonTokenState;
use fuz_db::{DbError, Pool};

use crate::db_reset::{DbResetError, reset_db_on_startup_if_env_set};
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
/// - [`startup_reset_hook`], the env-gated schema wipe, so repeated runs
///   against one database start clean;
/// - in-flight audit tracking, which makes `_testing_drain_effects` a real
///   barrier (over an untracked emitter it returns at once).
///
/// A server that differs sets the field with struct-update syntax: a suite
/// that drives the limiters selects `rate_limiters` from its env gate, and a
/// server's own login bound is its own (`login_ip_rate_limit`).
#[must_use]
pub fn testing_backend_options(daemon_token_state: SharedDaemonTokenState) -> SpineBackendOptions {
    SpineBackendOptions {
        rate_limiters: fuz_auth::RateLimiterMode::DisabledForTesting,
        daemon_token_state: Some(daemon_token_state),
        pre_migration_hook: Some(startup_reset_hook()),
        audit_inflight_tracking: true,
        ..SpineBackendOptions::production(Arc::new(crate::TestingArgon2idHasher::new()))
    }
}

/// `_testing_reset` and `_testing_drain_effects`, the pair every `testing_*`
/// server's extra specs start with.
///
/// The reset wipes the auth tables and seeds a fresh keeper as the runtime's
/// daemon-token state, running `reset_state` (the server's domain state —
/// [`truncate_reset_state`] over its tables) on the same transaction; the
/// drain awaits the emitter's in-flight writes, a barrier under
/// [`testing_backend_options`]' tracking.
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
        crate::create_testing_drain_effects_action_spec(Arc::clone(&runtime.audit_emitter)),
    ])
}

/// The pre-migration hook that fires the env-gated startup reset
/// (`crate::db_reset`).
///
/// That is the env-gated (`FUZ_TESTING_RESET_DB_ON_STARTUP`) wipe of the `public` schema,
/// so a cross-process run re-bootstraps from nothing against a shared database.
/// A no-op when the var is unset.
///
/// A malformed var is [`StartupError::Config`]; a database failure
/// [`StartupError::Database`].
pub fn startup_reset_hook() -> PreMigrationHook<StartupError> {
    Box::new(|pool: &Pool| {
        Box::pin(async move {
            let client = pool.get().await.map_err(DbError::PoolGet)?;
            reset_db_on_startup_if_env_set(&client)
                .await
                .map_err(|e| match e {
                    DbResetError::InvalidEnv(_) => StartupError::Config(e.to_string()),
                    DbResetError::Pg(e) => StartupError::Database(DbError::Postgres(e)),
                })
        })
    })
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

/// A spine core over inert handles, for a test without a database.
///
/// A lazy pool at an unreachable address that never connects, limiters
/// disabled, no daemon token — for a test that composes a server's routers or
/// reads its spec table.
///
/// Built through the production `build_app_backend` over `spec`, so the
/// fields are the ones a server boots with. Anything that touches the
/// database fails; a gate that refuses first (origin, cap) answers as in
/// production.
///
/// # Panics
///
/// When `allowed_origins` doesn't parse.
#[allow(
    clippy::expect_used,
    reason = "a malformed test allowlist is a test bug"
)]
#[must_use]
pub fn inert_app_backend(spec: &AppBackendSpec, allowed_origins: &str) -> AppBackend {
    let env = fuz_http::BaseServerEnv::from_vars(
        &|key| match key {
            "DATABASE_URL" => Some("postgres://inert@127.0.0.1:1/inert_app_backend".to_owned()),
            "SECRET_FUZ_COOKIE_KEYS" => Some("k".repeat(fuz_auth::keyring::MIN_KEY_LENGTH)),
            "FUZ_ALLOWED_ORIGINS" => Some(allowed_origins.to_owned()),
            "FUZ_INERT_APP_BACKEND_TRUSTED_PROXIES" => Some(",".to_owned()),
            _ => None,
        },
        fuz_http::ServerEnvOptions {
            trusted_proxies_var: "FUZ_INERT_APP_BACKEND_TRUSTED_PROXIES",
        },
    )
    .expect("the test allowlist parses");
    build_app_backend(
        &env,
        spec,
        &SpineBackendOptions {
            rate_limiters: fuz_auth::RateLimiterMode::DisabledForTesting,
            ..SpineBackendOptions::production(Arc::new(crate::TestingArgon2idHasher::new()))
        },
    )
    .expect("an inert core builds")
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "tests panic on assertion failure by design"
)]
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
