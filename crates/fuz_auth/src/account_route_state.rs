//! State struct consumed by the account REST router.
//!
//! The consumer assembles these from its own auth state (composed from
//! `*Deps` traits). Held as `Arc` and cheaply cloned by axum's `State`
//! extractor.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::audit_emitter::AuditEmitter;
use crate::auth_gate::AuthGate;
use crate::connection_closer::ConnectionCloser;
use crate::password_hasher::PasswordHasher;
use crate::rate_limiter::RateLimiter;

/// Capabilities consumed by the account REST handlers.
///
/// Built once at startup, wrapped in `Arc`, passed as `axum::State`.
/// `Clone` is cheap: every field is an `Arc` (or an `Option` of one), the
/// [`AuthGate`] (an Arc-backed `Pool` clone, `Arc`s, and a `&'static str`), or
/// a plain `u64`.
#[derive(Clone)]
pub struct AccountRouteState {
    /// The front door every account route checks a request at — the origin
    /// allowlist and the credential walk — and the pool, keyring, and session
    /// cookie name the handlers read. The cookie name is threaded into login
    /// (sign), logout/password (clear), and the walk (parse), so an app with a
    /// custom cookie name keeps its TS and Rust backends emitting the same
    /// cookie.
    pub gate: AuthGate,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub audit: Arc<AuditEmitter>,
    pub connection_closer: Arc<dyn ConnectionCloser>,
    pub bootstrap_available: Arc<AtomicBool>,
    pub login_ip_rate_limiter: Option<Arc<RateLimiter>>,
    pub login_account_rate_limiter: Option<Arc<RateLimiter>>,
    /// Minimum wall-clock time (ms) for login 401 denial responses — the
    /// username-enumeration defense described on
    /// [`DEFAULT_LOGIN_FAIL_FLOOR_MS`](crate::account_login::DEFAULT_LOGIN_FAIL_FLOOR_MS).
    /// Production passes that default; set to `0` to disable (tests), which
    /// [`account_router`](crate::account_router::account_router) announces
    /// once per process with a `LOGIN FAILURE TIMING FLOOR DISABLED` stderr
    /// banner. 429 responses are not floored.
    pub login_fail_floor_ms: u64,
    /// Uniform jitter window (±ms) layered on the floor. Production passes
    /// [`DEFAULT_LOGIN_FAIL_JITTER_MS`](crate::account_login::DEFAULT_LOGIN_FAIL_JITTER_MS);
    /// set to `0` to disable jitter while keeping the floor.
    pub login_fail_jitter_ms: u64,
}

impl std::fmt::Debug for AccountRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountRouteState")
            .field("gate", &self.gate)
            .field(
                "has_login_ip_limiter",
                &self.login_ip_rate_limiter.is_some(),
            )
            .field(
                "has_login_account_limiter",
                &self.login_account_rate_limiter.is_some(),
            )
            .field("login_fail_floor_ms", &self.login_fail_floor_ms)
            .field("login_fail_jitter_ms", &self.login_fail_jitter_ms)
            .finish_non_exhaustive()
    }
}
