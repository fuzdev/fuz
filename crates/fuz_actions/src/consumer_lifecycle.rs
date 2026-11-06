//! Shared `run_app` injection shapes for spine HTTP-server consumers.
//!
//! Every spine server drives the same `run_app(RunAppOptions)` lifecycle, and
//! each one with a `testing_*` sibling binary — plus the test-only
//! `testing_spine_stub` — exposes the same two test-binary swap points: a
//! factory that folds extra `ActionSpec`s into the registry after the standard
//! set, and an async hook fired before migrations. This module owns the
//! canonical, app/error-generic forms of those shapes so each consumer
//! instantiates them with a one-line concrete alias.
//!
//! The signal/drain half of the lifecycle lives in `fuz_http::lifecycle` —
//! it's transport-only and depends on no spine crate. These shapes can't join
//! it: [`ExtraActionSpecsRuntime`] carries `fuz_auth` types and the factory
//! returns [`crate::ActionSpec`], so they belong here, atop the spine graph.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::ActionSpec;
use crate::server::StartupError;

/// Runtime state surfaced to an [`ExtraActionSpecsFactory`].
///
/// The keyring, password hasher, and daemon-token state a test binary's
/// `_testing_reset` action needs to seed a fresh keeper inline, and the audit
/// emitter its `_testing_drain_effects` awaits.
///
/// A consumer builds these refs during its normal assembly and threads them
/// in so `fuz_testing` doesn't have to re-derive the production shapes.
/// Production passes no factory and never constructs this struct.
#[allow(missing_debug_implementations)] // Arc-of-dyn fields don't auto-derive Debug
pub struct ExtraActionSpecsRuntime {
    /// Argon2 hasher — the same instance the live server signs + verifies
    /// with. A test binary swaps in `fuz_testing::TestingArgon2idHasher` for
    /// ~1-5 ms argon2; production wires `fuz_auth::Argon2idHasher`.
    pub password_hasher: Arc<dyn fuz_auth::PasswordHasher>,
    /// Cookie-signing keyring — the same instance the live server uses.
    pub keyring: Arc<fuz_auth::Keyring>,
    /// Daemon-token runtime state — `Some(_)` when a daemon token is
    /// mounted. `_testing_reset` refreshes `keeper_account_id` here once its
    /// re-seed commits.
    pub daemon_token_state: Option<fuz_auth::SharedDaemonTokenState>,
    /// Per-app session cookie name (default
    /// [`fuz_auth::SESSION_COOKIE_NAME`]) — `_testing_reset` signs the seeded
    /// keeper's cookie under this so the harness jars it under the same name
    /// the live server reads.
    pub session_cookie_name: &'static str,
    /// The audit emitter — the live server's instance, whose in-flight writes
    /// `_testing_drain_effects` awaits.
    pub audit_emitter: Arc<fuz_auth::AuditEmitter>,
}

/// Factory that constructs extra action specs to fold into the registry after
/// a consumer's standard specs, generic over the consumer's `App` type.
///
/// Production passes `None`. A test binary passes `Some(_)` to inject
/// `_testing_reset` (which captures `Arc<App>` for the consumer-side reset
/// closure), so the production crate stays clean of any `fuz_testing` dep —
/// the factory closes over `fuz_testing` types in the test binary's process
/// only, keeping the `cargo xtask check-release` dep-graph audit green.
///
/// The factory receives an [`ExtraActionSpecsRuntime`] so it can wire the
/// action-handler's required state (keyring, password hasher, daemon-token
/// state, audit emitter) without re-deriving the production shapes. An error
/// refuses the boot, as a registry compile failure does.
pub type ExtraActionSpecsFactory<App> = Box<
    dyn FnOnce(Arc<App>, ExtraActionSpecsRuntime) -> Result<Vec<ActionSpec>, StartupError> + Send,
>;

/// Async hook fired between pool creation and migrations, generic over the
/// consumer's startup-error type `E`.
///
/// Production passes `None`. A test binary passes `Some(_)` to fire
/// `fuz_testing::startup_reset_hook` — an env-gated schema wipe so
/// cross-process tests don't have to drop the DB manually between runs. The
/// production crate stays clean of any `fuz_testing` dep this way.
///
/// The hook receives a borrowed [`fuz_db::Pool`]; cloning is cheap (`Arc`
/// internally) when an owned handle is needed. Errors surface as the
/// consumer's `E` so the startup chain fails the same way a real migration
/// error would.
pub type PreMigrationHook<E> = Box<
    dyn FnOnce(&fuz_db::Pool) -> Pin<Box<dyn Future<Output = Result<(), E>> + Send + '_>> + Send,
>;
