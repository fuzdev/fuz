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
//! daemon-token producer, the reset callback aliases — mostly take ordinary
//! names.
//!
//! The API is the crate root, one path per item: the modules are private, and
//! each public item is named at the root (`fuz_testing::seed_account_actor`).
//! What it holds:
//!
//! - **Databases** — [`fresh_test_db`] / [`TestingDbOptions::open`], a pglet
//!   fork per test or a PostgreSQL database of its own; [`budgeted_pool`] and
//!   [`unreachable_pool`] for checkout faults; the schema guards
//!   ([`assert_column_projections`], [`assert_expected_schema_fixture`],
//!   [`migration_created_tables`]).
//! - **Fixtures** — the seeding ([`seed_account_actor`], [`grant_role`],
//!   [`refuse_audit_rows`]) and the credential mints ([`mint_session_cookie`],
//!   [`mint_api_token`], [`resolve_test_credential`]).
//! - **Races** — [`TestingTableLock`], the lock-wait observers
//!   ([`until_lock_waiters`], [`until_blocked_by`]), and the [`in_tx!`] and
//!   [`race!`] macros.
//! - **Doubles and the dispatcher harness** — [`RecordingConnectionCloser`],
//!   [`dispatch_options`], [`perform_as`], [`assert_rpc_ok`],
//!   [`assert_rpc_err`].
//! - **Servers** — a `testing_*` binary's wiring ([`testing_backend_options`],
//!   [`testing_reset_specs`], the `_testing_*` specs,
//!   [`assert_strict_server_argv`]) and an in-process router test's core
//!   ([`test_app_backend`], [`inert_app_backend`]).
//! - **The request-reads census** —
//!   [`assert_clippy_configs_disallow_lenient_readers`] and its siblings.
//!
//! ## Lock waits
//!
//! A race test holds a lock in one transaction, starts the call under test,
//! and needs to know the call has reached the lock before it changes anything
//! else. A sleep followed by `!is_finished()` passes for a call that never
//! reached the lock but was merely slow; these waits pass only once the
//! server reports the wait.
//!
//! Two scopes, for the two shapes the suites take:
//!
//! - **This database** ([`lock_waiters`], [`until_lock_waiters`],
//!   [`until_lock_waiters_or`]): every session of the test's database waiting
//!   on a lock. Each test has a database of its own, so the count is the
//!   test's own sessions; a wait for `n` waiters observes a chain (a call
//!   waiting on the holder, a second waiting on the first).
//! - **One holder** ([`blocked_by`], [`until_blocked_by`],
//!   [`until_blocked_by_or`]): sessions blocked by the backend `holder_pid`
//!   names ([`backend_pid`] reads it off the holding transaction), so another
//!   session's wait can't pass for the one under test.
//!
//! The `_or` forms also end when the caller's `finished` returns `true` — the
//! call under test finished without waiting — and report which happened, for
//! a case that holds in either order. Every wait is bounded by
//! [`LOCK_WAIT_DEADLINE`], a bound on a hang only, and panics naming what it
//! awaited. [`in_tx!`](crate::in_tx) and [`race!`](crate::race) are the
//! transaction kit the race suites build on these.
//!
//! ### PostgreSQL only
//!
//! pglet has neither view nor function these read: `pg_stat_activity` and
//! `pg_locks` are unknown relations (`42P01`), and `pg_blocking_pids` and
//! `pg_backend_pid` are unsupported functions (`0A000`), so a test that
//! observes a lock wait opens its database with
//! [`crate::TestEngine::Postgres`] and carries
//! `#[ignore = "postgres-only: observes a lock wait"]`.
//!
//! ## The dispatcher harness
//!
//! [`dispatch_options`] builds the dispatcher's options over a registry with
//! inert side channels; [`perform_as`] mints and resolves a real credential for
//! an account ([`crate::resolve_test_credential`]) and dispatches one call as
//! it; [`perform_with_auth`] dispatches with a credential the test resolved
//! itself, or none. [`assert_rpc_ok`], [`assert_rpc_err`], and
//! [`rpc_refusal`] read the result.
//!
//! Each call carries what an HTTP request does: request id `1`, a fresh
//! [`fuz_realtime::SignalToken`], no span, the HTTP no-op notify, and no
//! client IP or connection id.
//!
//! ## The request-reads census
//!
//! A handler reads its query and its path params only through `fuz_http`'s
//! strict readers — `fuz_http::read_query_pairs` over axum's `RawQuery`, and
//! `fuz_http::RouteParams` — never a lenient extractor that leaves an escape
//! that doesn't decode as text or writes U+FFFD for it. Twin of the query and
//! path-param half of `fuz_app`'s `request_reads_census.test.ts` (its header
//! half has no Rust twin here).
//!
//! The enforcement is clippy's `disallowed-types` / `disallowed-methods` in a
//! workspace's `clippy.toml` (`-D warnings` makes a hit an error), each entry
//! one of the lenient readers the census names. Clippy resolves the paths, so an aliased or
//! grouped import is caught. These checks hold that enforcement in place, each
//! over a workspace root (the directory holding its `Cargo.toml` and
//! `crates/`):
//!
//!  - **the config** ([`assert_clippy_configs_disallow_lenient_readers`]): the
//!    root `clippy.toml` and every one under `crates/` or a crate directory, by
//!    either name (a nearer one replaces the root file rather than merging with
//!    it), lists each lenient reader with its canonical reason, spelled exactly
//!    — a misspelled path is only a clippy warning (`does not refer to a
//!    reachable type`) that `-D warnings` does not promote, and a dropped entry
//!    turns the census off with clippy green;
//!  - **suppressions** ([`assert_suppressions_listed`]): every `.rs` file under
//!    `crates/` that names the disallow lints, a clippy group holding them, or
//!    `warnings` in an `allow`/`expect` is one the workspace's [`Suppression`]
//!    list names, with its count of sites and its reason;
//!  - **`[lints]` tables** ([`assert_no_lints_table_allows_disallows`]): no
//!    `Cargo.toml` `[lints]` table, root or crate, allows them.
//!
//! What stays in each workspace's own test crate is **resolution**: positive
//! controls that use each disallowed item under an `#[expect]`, so a path that
//! stops resolving (an axum upgrade moving it) leaves the expectation
//! unfulfilled — an error under `-D warnings`. A control proves resolution
//! only under the clippy config of the workspace it compiles in, so it can't
//! live here; its `#[expect]` is a suppression site the workspace lists.
//!
//! What it cannot see:
//!
//!  - a hand-split query or path — `RawQuery`, `Uri::query()`, `OriginalUri`
//!    or `Uri::path()` read and decoded by hand outside the strict readers;
//!  - a lenient reader no entry names (another crate's query decoder), and a
//!    suppression from outside the source (`-A` flags, `CLIPPY_CONF_DIR`);
//!  - a `lints` key written under `[workspace]` or at a manifest's root rather
//!    than under a `[lints…]` header;
//!  - a lint written as its own sub-table (`[lints.clippy.all]` with
//!    `level = "allow"` under it) or a header spelled with spaces
//!    (`[ lints ]`);
//!  - a `"` in a trailing comment inside a multi-line `allow(…)` list, which
//!    unbalances the string scan;
//!  - a workspace member outside `crates/<name>/`, which is neither scanned
//!    nor config-checked;
//!  - a workspace that doesn't run it — the spine, zzz,
//!    visionesdelcaribe.org and `fuz_forge` do; the other spine consumers
//!    read nothing leniently today.

use fuz_auth::{AuthSpec, CredentialGate, CredentialType};

/// Shared `auth` axis for every `_testing_*` action: keeper-only via the
/// daemon-token credential, no acting actor. This is the entire structural
/// fence on the backdoor surface (these actions run direct DB writes the
/// production wire never exposes), so every `_testing_*` action spec references
/// this one const rather than re-declaring it. Mirrors `fuz_app`'s TS
/// `TESTING_ACTION_AUTH`.
pub(crate) const TESTING_ACTION_AUTH: AuthSpec =
    AuthSpec::account_grain(CredentialGate::Only(&[CredentialType::DaemonToken]));

mod column_guard;
mod credentials;
mod daemon_token;
mod dispatch;
mod doubles;
mod fresh_db;
mod lock_wait;
mod migration_tables;
mod password_argon2;
mod request_reads_census;
mod schema_fixture;
mod seed;
mod table_lock;
mod testing_action_manifest;
mod testing_credential_read;
mod testing_db_invariants;
mod testing_drain;
mod testing_flood_notifications;
mod testing_migration_tracker;
mod testing_mint_session;
mod testing_origin_check;
mod testing_put_fact;
mod testing_reset;
mod testing_room_evict;
mod testing_schema_snapshot;
mod testing_server;
mod testing_shorten_credential_expiry;

pub use column_guard::assert_column_projections;
pub use credentials::{
    TESTING_ALLOWED_ORIGIN, TESTING_DAEMON_TOKEN, daemon_token_state, mint_api_token,
    mint_session_cookie, narrowed_scope, resolve_test_credential, testing_auth_gate,
    testing_keyring,
};
pub use daemon_token::{init_daemon_token, init_daemon_token_from_env};
pub use dispatch::{
    assert_rpc_err, assert_rpc_ok, dispatch_options, perform_as, perform_with_auth, rpc_refusal,
};
pub use doubles::{RecordingConnectionCloser, UNREACHABLE_DATABASE_URL, unreachable_pool};
pub use fresh_db::{
    FUZ_TEST_POSTGRES_URL, SUITE_NAME_LENGTH_MAX, TestDb, TestEngine, TestingDbOptions,
    budgeted_pool, fresh_test_db,
};
pub use lock_wait::{
    LOCK_WAIT_DEADLINE, backend_pid, blocked_by, lock_waiters, until_blocked_by,
    until_blocked_by_or, until_lock_waiters, until_lock_waiters_or,
};
pub use migration_tables::migration_created_tables;
pub use password_argon2::{TESTING_DUMMY_HASH, TestingArgon2idHasher};
pub use request_reads_census::{
    Suppression, assert_clippy_configs_disallow_lenient_readers,
    assert_no_lints_table_allows_disallows, assert_suppressions_listed,
};
pub use schema_fixture::{UPDATE_SCHEMA_READY, assert_expected_schema_fixture};
pub use seed::{
    grant_role, grant_scoped_role, refuse_audit_rows, seed_account_actor,
    seed_account_actor_with_email, seed_extra_actor,
};
pub use table_lock::TestingTableLock;
pub use testing_action_manifest::create_testing_action_manifest_action_spec;
pub use testing_credential_read::create_testing_credential_read_action_spec;
pub use testing_db_invariants::create_testing_db_invariants_action_spec;
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
pub use testing_room_evict::create_testing_room_evict_action_spec;
pub use testing_schema_snapshot::create_testing_schema_snapshot_action_spec;
pub use testing_server::{
    TestAppBackendOptions, assert_strict_server_argv, inert_app_backend,
    require_daemon_token_from_env, test_app_backend, testing_backend_options, testing_reset_specs,
    truncate_reset_state,
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

    use fuz_auth::{AuthAxis, CredentialGate, CredentialType, DaemonTokenState, Keyring};
    use parking_lot::RwLock;

    use super::{
        TESTING_ACTION_AUTH, TestingArgon2idHasher, TestingResetOptions,
        create_testing_action_manifest_action_spec, create_testing_credential_read_action_spec,
        create_testing_db_invariants_action_spec, create_testing_drain_effects_action_spec,
        create_testing_flood_notifications_action_spec,
        create_testing_migration_tracker_action_spec, create_testing_mint_session_action_spec,
        create_testing_origin_check_action_spec, create_testing_put_fact_action_spec,
        create_testing_reset_action_spec, create_testing_room_evict_action_spec,
        create_testing_schema_snapshot_action_spec,
        create_testing_shorten_credential_expiry_action_spec,
    };

    /// Keyring needed to build the reset / mint specs; never exercised (the
    /// tests only read `.auth`).
    fn test_keyring() -> Arc<Keyring> {
        Arc::new(crate::testing_keyring())
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
            create_testing_drain_effects_action_spec(Arc::default()),
            create_testing_mint_session_action_spec(test_keyring(), "fuz_session"),
            create_testing_put_fact_action_spec(),
            create_testing_schema_snapshot_action_spec(),
            create_testing_migration_tracker_action_spec(),
            create_testing_db_invariants_action_spec(),
            create_testing_flood_notifications_action_spec(),
            create_testing_origin_check_action_spec(),
            create_testing_credential_read_action_spec(test_keyring(), "fuz_session"),
            create_testing_shorten_credential_expiry_action_spec(),
            create_testing_room_evict_action_spec(Arc::new(fuz_realtime::RoomRegistry::new(
                Arc::new(fuz_realtime::ConnectionRegistry::new()),
                fuz_realtime::RoomRegistryOptions::default(),
            ))),
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
        assert_eq!(specs.len(), 13, "every _testing_* spec must be covered");
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
    /// TS twins' `s.void` inputs do, and the whole set still compiles: the
    /// daemon-token gate resolves no actor, so `VoidInputWithActor` holds off.
    #[test]
    fn parameterless_reads_declare_a_void_input() {
        let specs = all_testing_specs();
        for method in [
            "_testing_migration_tracker",
            "_testing_db_invariants",
            "_testing_action_manifest",
        ] {
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
