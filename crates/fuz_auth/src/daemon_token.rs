//! Daemon token state, validation, and keeper resolution.
//!
//! In-memory token used by `X-Daemon-Token` authentication. This module
//! holds only the **consuming** half — the state vessel, the constant-time
//! compare, and the keeper-account adapters. The **producing** half
//! (generate / write the secret file) lives in
//! `fuz_testing::daemon_token`, deliberately out of this crate.
//!
//! ## Why the split
//!
//! No @fuzdev consumer authenticates with `X-Daemon-Token` in production —
//! the only callers are the cross-backend test harness and the
//! `_testing_*` backdoor specs, which are already confined to `fuz_testing`
//! by the same dep-graph rule. Leaving the token *producer* in this crate
//! meant every spine consumer shipped code that mints a keeper-grade
//! credential and writes it to disk, for a credential nothing calls.
//!
//! With the producer in `fuz_testing`, a production binary cannot generate
//! or persist a daemon token: the symbols aren't in its dependency
//! graph, and `cargo xtask check-release` fails the build if `fuz_testing`
//! ever enters one. [`SharedDaemonTokenState`] stays `None` on every
//! production assembly, so the daemon-token leg of
//! the credential walk ([`crate::AuthGate::resolve_credential`]) is
//! unreachable there.
//!
//! [`DaemonTokenState`]'s fields stay public so `fuz_testing` can build one.
//! That leaves a hand-written struct literal as a theoretical way to mount a
//! fixed token from production code — it writes no file, and no code does
//! it. Sealing that too means moving the struct itself
//! behind a `fuz_auth`-declared trait, which is a wider refactor than the
//! residual justifies.
//!
//! The lock is [`parking_lot::RwLock`] (not `tokio::sync::RwLock`): there
//! are no `.await` points inside any critical section, so async
//! semantics buy nothing.

use std::path::PathBuf;
use std::sync::Arc;

use deadpool_postgres::Pool;
use futures::future::BoxFuture;
use parking_lot::RwLock;
use subtle::ConstantTimeEq;

use crate::actor_queries::query_keeper_account_id;
use crate::bootstrap_keeper_resolved::BootstrapKeeperResolved;

/// In-memory daemon token state.
///
/// Built by `fuz_testing::daemon_token::init_daemon_token` — this crate
/// exposes no constructor (see the module docs for why).
///
/// `Debug` redacts both tokens.
#[derive(Clone)]
pub struct DaemonTokenState {
    pub current_token: String,
    pub previous_token: Option<String>,
    /// Resolved after bootstrap completes. The keeper account is the
    /// `account_id` whose actor holds the `keeper` role grant.
    pub keeper_account_id: Option<uuid::Uuid>,
    pub token_path: PathBuf,
}

impl std::fmt::Debug for DaemonTokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonTokenState")
            .field("current_token", &"<redacted>")
            .field(
                "previous_token",
                &self.previous_token.as_ref().map(|_| "<redacted>"),
            )
            .field("keeper_account_id", &self.keeper_account_id)
            .field("token_path", &self.token_path)
            .finish()
    }
}

/// Shared handle to daemon token state.
///
/// **Locking choice**: `parking_lot::RwLock` (sync). Every critical
/// section is synchronous (clone the token string, update fields, drop
/// the guard before any `.await`). Swapping from `tokio::sync::RwLock`
/// saves one runtime hop per authed request that ships `X-Daemon-Token`.
pub type SharedDaemonTokenState = Arc<RwLock<DaemonTokenState>>;

/// HTTP header name carrying the daemon token.
pub const DAEMON_TOKEN_HEADER: &str = "x-daemon-token";

/// Validate a provided token against the current and previous tokens
/// using constant-time comparison.
///
/// Returns `true` if either matches. `fuz_testing` mints one token and never
/// rotates it, so `previous_token` is `None` there; the field keeps the shape
/// of the TS twin's state, whose rotating producer keeps the displaced token
/// valid through its flip.
#[must_use]
pub fn validate_daemon_token(provided: &str, state: &DaemonTokenState) -> bool {
    if provided
        .as_bytes()
        .ct_eq(state.current_token.as_bytes())
        .into()
    {
        return true;
    }
    if let Some(ref previous) = state.previous_token {
        return provided.as_bytes().ct_eq(previous.as_bytes()).into();
    }
    false
}

/// Canonical [`BootstrapKeeperResolved`] adapter — wires the post-bootstrap
/// keeper-account id into a [`SharedDaemonTokenState`].
///
/// The bootstrap pipeline fires `on_keeper_resolved` once it creates the
/// keeper account; this records the id so subsequent daemon-token-authenticated
/// calls (notably `_testing_reset` on test binaries) resolve the keeper. Every
/// daemon-token consumer wires the same adapter — construct one with
/// [`DaemonTokenKeeperResolved::new`] and hand it to `BootstrapOptions`.
///
/// The derived `Debug` prints the state through its lock, so it redacts the
/// tokens the way [`DaemonTokenState`]'s does.
#[derive(Debug, Clone)]
pub struct DaemonTokenKeeperResolved {
    state: SharedDaemonTokenState,
}

impl DaemonTokenKeeperResolved {
    /// Wrap a [`SharedDaemonTokenState`] as a keeper-resolved callback.
    #[must_use]
    pub const fn new(state: SharedDaemonTokenState) -> Self {
        Self { state }
    }
}

impl BootstrapKeeperResolved for DaemonTokenKeeperResolved {
    fn on_keeper_resolved(&self, account_id: uuid::Uuid) -> BoxFuture<'static, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.write().keeper_account_id = Some(account_id);
            tracing::info!(%account_id, "daemon token: keeper account set by bootstrap");
        })
    }
}

/// Resolve the already-bootstrapped keeper account (if any) into `state` at boot.
///
/// Best-effort: on a fresh, not-yet-bootstrapped DB there is no keeper and a
/// transient pool error simply leaves `keeper_account_id` unset — the
/// post-bootstrap [`DaemonTokenKeeperResolved`] callback fills it in when the
/// keeper is created. This covers the already-bootstrapped-DB case, where
/// bootstrap won't fire on this boot.
pub async fn resolve_keeper_into(state: &SharedDaemonTokenState, pool: &Pool) {
    if let Ok(client) = pool.get().await
        && let Ok(Some(account_id)) = query_keeper_account_id(&client).await
    {
        state.write().keeper_account_id = Some(account_id);
        tracing::info!(%account_id, "daemon token: keeper account resolved");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_SECRET: &str = "current-daemon-secret-Zq7xV2";
    const PREVIOUS_SECRET: &str = "previous-daemon-secret-Kp4wM9";

    fn state_with_secrets() -> DaemonTokenState {
        DaemonTokenState {
            current_token: CURRENT_SECRET.to_owned(),
            previous_token: Some(PREVIOUS_SECRET.to_owned()),
            keeper_account_id: None,
            token_path: PathBuf::from("/run/daemon_token"),
        }
    }

    fn assert_redacted(rendered: &str) {
        assert!(!rendered.contains(CURRENT_SECRET), "{rendered}");
        assert!(!rendered.contains(PREVIOUS_SECRET), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn state_debug_redacts_tokens() {
        let rendered = format!("{:?}", state_with_secrets());
        assert_redacted(&rendered);
        assert!(rendered.contains("/run/daemon_token"), "{rendered}");
    }

    #[test]
    fn keeper_resolved_debug_redacts_tokens_through_the_lock() {
        let resolved = DaemonTokenKeeperResolved::new(Arc::new(RwLock::new(state_with_secrets())));
        assert_redacted(&format!("{resolved:?}"));
    }

    #[test]
    fn validate_current_token_accepts() {
        let state = DaemonTokenState {
            current_token: "abc".to_owned(),
            previous_token: None,
            keeper_account_id: None,
            token_path: PathBuf::new(),
        };
        assert!(validate_daemon_token("abc", &state));
    }

    #[test]
    fn validate_previous_token_accepts() {
        let state = DaemonTokenState {
            current_token: "new".to_owned(),
            previous_token: Some("old".to_owned()),
            keeper_account_id: None,
            token_path: PathBuf::new(),
        };
        assert!(validate_daemon_token("old", &state));
    }

    #[test]
    fn validate_rejects_unknown_token() {
        let state = DaemonTokenState {
            current_token: "abc".to_owned(),
            previous_token: Some("def".to_owned()),
            keeper_account_id: None,
            token_path: PathBuf::new(),
        };
        assert!(!validate_daemon_token("xyz", &state));
    }

    #[test]
    fn validate_rejects_different_lengths() {
        let state = DaemonTokenState {
            current_token: "abc".to_owned(),
            previous_token: None,
            keeper_account_id: None,
            token_path: PathBuf::new(),
        };
        // ct_eq returns Choice(0) when lengths differ
        assert!(!validate_daemon_token("abcd", &state));
    }
}
