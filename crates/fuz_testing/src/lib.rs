//! `fuz_testing` — test-only fixtures for the fuz spine.
//!
//! **NEVER link this crate from a production binary.** Types here
//! deliberately weaken security-critical parameters (e.g. argon2 cost)
//! for fast cross-process integration test feedback. The crate lives
//! separately from `fuz_auth` (not behind a feature flag) so Cargo's
//! workspace feature unification can't accidentally route the
//! weakened forms into a production build graph — no production binary
//! crate lists `fuz_testing` under `[dependencies]`, so no symbol here is
//! reachable from one. A `[dev-dependencies]` entry (the Postgres suites of
//! the spine crates and of consumer servers) reaches test targets only.
//!
//! Naming doesn't enumerate the test-only surface — the crate boundary does.
//! The swap-in fixtures and option structs carry a `Testing` prefix
//! (`TestingArgon2idHasher`, `TestingDbOptions`, `TestingResetOptions`), the
//! `_testing_*` action specs come from `create_testing_*_action_spec`
//! factories, and the rest — the seeding and credential helpers, the
//! daemon-token producer, the reset callback aliases — mostly take ordinary names.

use fuz_auth::{AuthSpec, CredentialGate, CredentialType};

/// Shared `auth` axis for every `_testing_*` action: keeper-only via the
/// daemon-token credential, no acting actor. This is the entire structural
/// fence on the backdoor surface (these actions run direct DB writes the
/// production wire never exposes), so every `_testing_*` action spec references
/// this one const rather than re-declaring it. Mirrors `fuz_app`'s TS
/// `TESTING_ACTION_AUTH`.
pub(crate) const TESTING_ACTION_AUTH: AuthSpec =
    AuthSpec::account_grain(CredentialGate::Only(&[CredentialType::DaemonToken]));

pub mod column_guard;
pub mod credentials;
pub mod daemon_token;
pub mod db_reset;
pub mod fresh_db;
pub mod migration_tables;
pub mod password_argon2;
pub mod schema_fixture;
pub mod seed;
pub mod table_lock;
pub mod testing_action_manifest;
pub mod testing_drain;
pub mod testing_flood_notifications;
pub mod testing_migration_tracker;
pub mod testing_mint_session;
pub mod testing_origin_check;
pub mod testing_put_fact;
pub mod testing_reset;
pub mod testing_schema_snapshot;
pub mod testing_server;
pub mod testing_shorten_credential_expiry;

pub use column_guard::assert_column_projections;
pub use credentials::{
    TESTING_ALLOWED_ORIGIN, TESTING_DAEMON_TOKEN, daemon_token_state, mint_api_token,
    mint_session_cookie, narrowed_scope, resolve_test_credential, testing_auth_gate,
    testing_keyring,
};
pub use daemon_token::{init_daemon_token, init_daemon_token_from_env};
pub use db_reset::FUZ_TESTING_RESET_DB_ON_STARTUP;
pub use fresh_db::{
    ScratchDb, TestingDbOptions, budgeted_pool, database_url_with_name, fresh_test_db_pool,
};
pub use migration_tables::migration_created_tables;
pub use password_argon2::TestingArgon2idHasher;
pub use schema_fixture::{UPDATE_SCHEMA_READY, assert_expected_schema_fixture};
pub use seed::{
    grant_role, grant_scoped_role, refuse_audit_rows, seed_account_actor, seed_extra_actor,
};
pub use table_lock::TestingTableLock;
pub use testing_action_manifest::create_testing_action_manifest_action_spec;
pub use testing_drain::create_testing_drain_effects_action_spec;
pub use testing_flood_notifications::{
    TESTING_FLOOD_NOTIFICATION_METHOD, create_testing_flood_notifications_action_spec,
};
pub use testing_migration_tracker::create_testing_migration_tracker_action_spec;
pub use testing_mint_session::create_testing_mint_session_action_spec;
pub use testing_origin_check::create_testing_origin_check_action_spec;
pub use testing_put_fact::create_testing_put_fact_action_spec;
pub use testing_reset::{
    BoxFutureResetResult, ResetStateFn, TestingResetOptions, create_testing_reset_action_spec,
};
pub use testing_schema_snapshot::create_testing_schema_snapshot_action_spec;
pub use testing_server::{
    inert_app_backend, require_daemon_token_from_env, startup_reset_hook, testing_backend_options,
    testing_reset_specs, truncate_reset_state,
};
pub use testing_shorten_credential_expiry::create_testing_shorten_credential_expiry_action_spec;

#[cfg(test)]
mod auth_gate_tests {
    //! Pins that **every** `_testing_*` backdoor spec carries the
    //! daemon-token gate (`TESTING_ACTION_AUTH`) — the Rust twin of
    //! `fuz_app`'s `src/test/testing/testing_actions_auth.test.ts`. Each
    //! constructor passes the shared const today; a future edit handing one
    //! a different `AuthSpec` (e.g. dropping the daemon-token credential
    //! gate or admitting an actor) fails loud here. Covers
    //! `_testing_drain_effects` too — the one spec the cross-backend
    //! negative-credential suite never fires, so this is its only gate pin.

    use std::sync::Arc;

    use fuz_auth::{
        AuditEmitter, AuthAxis, CredentialGate, CredentialType, DaemonTokenState, Keyring,
    };
    use parking_lot::RwLock;

    use super::{
        TESTING_ACTION_AUTH, TestingArgon2idHasher, TestingResetOptions,
        create_testing_action_manifest_action_spec, create_testing_drain_effects_action_spec,
        create_testing_flood_notifications_action_spec,
        create_testing_migration_tracker_action_spec, create_testing_mint_session_action_spec,
        create_testing_origin_check_action_spec, create_testing_put_fact_action_spec,
        create_testing_reset_action_spec, create_testing_schema_snapshot_action_spec,
        create_testing_shorten_credential_expiry_action_spec,
    };

    /// Keyring needed to build the reset / mint specs; never exercised (the
    /// tests only read `.auth`), so any valid key suffices.
    fn test_keyring() -> Arc<Keyring> {
        Arc::new(Keyring::new("test-cookie-key-not-a-real-secret").expect("one valid key"))
    }

    /// A never-connected lazy pool — `create_pool` builds the deadpool config
    /// without dialing Postgres, and the drain handler (its only consumer)
    /// never runs in this test.
    fn unused_pool() -> deadpool_postgres::Pool {
        fuz_db::create_pool(
            "postgresql://test@localhost/test",
            &fuz_db::PoolOptions::default(),
        )
        .expect("lazy pool builds")
    }

    fn daemon_token_state() -> Arc<RwLock<DaemonTokenState>> {
        // Never validated here — these tests read only `.auth` off the specs.
        super::daemon_token_state("", None)
    }

    /// Build every spec the way a test binary's registry does. The manifest
    /// action takes the assembled mount; an empty slice suffices here (the
    /// tests read only its `.method` / `.auth`, not the manifest it serves).
    fn all_testing_specs() -> Vec<fuz_actions::ActionSpec> {
        vec![
            create_testing_reset_action_spec(TestingResetOptions {
                password_hasher: Arc::new(TestingArgon2idHasher),
                keyring: test_keyring(),
                daemon_token_state: daemon_token_state(),
                session_cookie_name: "fuz_session",
                reset_state: None,
            }),
            create_testing_drain_effects_action_spec(Arc::new(
                AuditEmitter::new_with_inflight_tracking(unused_pool()),
            )),
            create_testing_mint_session_action_spec(test_keyring(), "fuz_session"),
            create_testing_put_fact_action_spec(),
            create_testing_schema_snapshot_action_spec(),
            create_testing_migration_tracker_action_spec(),
            create_testing_flood_notifications_action_spec(),
            create_testing_origin_check_action_spec(),
            create_testing_shorten_credential_expiry_action_spec(),
            create_testing_action_manifest_action_spec(&[]),
        ]
    }

    #[test]
    fn testing_action_auth_is_daemon_token_only() {
        // The single shared fence: keeper-only via daemon token, no acting
        // actor, no role axis. Mirrors fuz_app's TS `TESTING_ACTION_AUTH`.
        assert_eq!(TESTING_ACTION_AUTH.account, AuthAxis::Required);
        assert_eq!(TESTING_ACTION_AUTH.actor, AuthAxis::None);
        assert_eq!(TESTING_ACTION_AUTH.roles, None);
        assert_eq!(
            TESTING_ACTION_AUTH.credentials,
            CredentialGate::Only(&[CredentialType::DaemonToken]),
        );
    }

    #[test]
    fn every_testing_spec_carries_the_daemon_token_gate() {
        let specs = all_testing_specs();
        assert_eq!(specs.len(), 10, "every _testing_* spec must be covered");
        for spec in &specs {
            assert!(
                spec.method.starts_with("_testing_"),
                "{}: method must carry the reserved _testing_ backdoor prefix",
                spec.method,
            );
            assert_eq!(
                spec.auth, TESTING_ACTION_AUTH,
                "{}: auth must be the daemon-token gate (TESTING_ACTION_AUTH)",
                spec.method,
            );
        }
    }

    /// The parameterless introspection reads declare a void input, as their
    /// TS twins' `z.void()` inputs do, and the whole set still compiles: the
    /// daemon-token gate resolves no actor, so `VoidInputWithActor` holds off.
    #[test]
    fn parameterless_reads_declare_a_void_input() {
        let specs = all_testing_specs();
        for method in ["_testing_migration_tracker", "_testing_action_manifest"] {
            let spec = specs
                .iter()
                .find(|s| s.method == method)
                .unwrap_or_else(|| panic!("{method} is built"));
            assert_eq!(spec.input, fuz_http::InputShape::Void, "{method}");
        }
        fuz_actions::ActionRegistry::compile(specs)
            .unwrap_or_else(|e| panic!("every _testing_* spec compiles: {e}"));
    }
}
