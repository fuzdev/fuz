//! The spine-consumer server toolkit: the pieces every spine server's
//! `run_app` composes, so each consumer keeps only what is its own — its
//! domain state, its action specs, and its final `Router`.
//!
//! The Rust twin of `fuz_app`'s `server/app_backend.ts` +
//! `server/app_server.ts` (`create_app_backend` / `create_app_server`):
//!
//! - [`create_app_backend`] boots an [`AppBackend`] — pool, keyring, audit
//!   emitter, limiters, realtime registries — against the database; its doc
//!   owns the boot order. [`AppBackendSpec`] is what a consumer is (its
//!   cookie, chain, optional schema fixture, its audit stream's
//!   [`AuditSseSpec`], and its [`BrowserGateSpec`]);
//!   [`SpineBackendOptions`] its swap points (the `testing_*` seams and the
//!   per-IP login bound).
//! - [`AppBackend`]'s route-state builders (`account_route_state`,
//!   `bootstrap_route_state`, `signup_route_state`, `action_dispatch`,
//!   `ws_route_state`), the mounted pieces every server shares (the account
//!   REST surface as [`AuthRestRoutes`], `audit_stream_router`),
//!   [`crate::ActionRateLimits`] (the action limiter pair, one budget across
//!   RPC, WS, and the auth set), and [`compile_action_registry`].
//! - [`serve_until_shutdown`] (bind → upkeep → serve → join), with
//!   [`spawn_upkeep`], [`boot_only`] (the no-database branch, over
//!   [`boot_only_router`]), and [`SpineRunOptions`], which a consumer's
//!   `RunAppOptions` embeds.
//! - [`StartupError`] with the exit-code policy, and
//!   [`server_invocation`] over [`parse_server_invocation`], the strict server
//!   command line.
//!
//! The env reader is `fuz_http::BaseServerEnv`. Final router assembly stays
//! the consumer's: which groups it mounts, under which caps and origin
//! policy, is where servers differ.

mod args;
mod backend;
mod route_states;
mod serve;
mod startup_error;

pub use args::{
    ServerInvocation, StartCommand, parse_server_invocation, server_invocation, server_usage,
};
pub use backend::{
    AppBackend, AppBackendSpec, AuditSseSpec, BootedAppBackend, BrowserGateSpec,
    SpineBackendOptions, build_app_backend, create_app_backend, ensure_read_committed,
    parse_expected_schema,
};
pub use route_states::{AuthRestRoutes, compile_action_registry};
pub use serve::{
    ServeOptions, SpineRunOptions, UpkeepOptions, UpkeepTask, boot_only, boot_only_router,
    fallback_group, not_found_response, probe_router, serve_until_shutdown, spawn_upkeep,
};
pub use startup_error::{REQUIRED_TRANSACTION_ISOLATION, StartupError};
