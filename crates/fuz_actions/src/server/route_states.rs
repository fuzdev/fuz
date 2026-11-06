//! The route states a spine server builds from its [`AppBackend`], and the
//! registry compile.
//!
//! Each builder reads only what its router needs and takes the server's one
//! [`AuthGate`] ([`AppBackend::auth_gate`]) rather than minting its own.

use std::sync::Arc;

use axum::Router;
use fuz_auth::{
    AccountRouteState, AuthGate, BootstrapRouteState, OfferCreateAuthorize, RoleRegistry,
    SignupRouteState,
};

use crate::{ActionDispatch, ActionRateLimits, ActionRegistry, ActionSpec, WsRouteState};

use super::backend::AppBackend;
use super::startup_error::StartupError;

/// Compile the assembled specs, refusing to boot on failure — an empty
/// registry instead would answer `method_not_found` to every call.
///
/// # Errors
///
/// [`StartupError::ActionRegistry`] with the registry's reason.
pub fn compile_action_registry(
    specs: impl IntoIterator<Item = ActionSpec>,
) -> Result<Arc<ActionRegistry>, StartupError> {
    Ok(Arc::new(ActionRegistry::compile(specs)?))
}

/// The account REST surface's route states, built by
/// [`AppBackend::auth_rest_routes`]; [`Self::into_router`] mounts them.
///
/// A server that differs on one route sets that field with struct-update
/// syntax over the builder's result, and one with no signup surface sets
/// `signup: None`.
#[derive(Debug)]
pub struct AuthRestRoutes {
    /// `/status`, `/login`, `/logout`, `/password`.
    pub account: AccountRouteState,
    /// `/bootstrap`.
    pub bootstrap: BootstrapRouteState,
    /// `/signup`; `None` mounts none, for a server whose every account is
    /// operator-minted.
    pub signup: Option<SignupRouteState>,
}

impl AuthRestRoutes {
    /// The routes at their paths under the account prefix: nest the router
    /// at `/api/account`.
    pub fn into_router(self) -> Router {
        let Self {
            account,
            bootstrap,
            signup,
        } = self;
        let router = fuz_auth::account_router(account)
            .merge(fuz_auth::bootstrap_routes::bootstrap_router(bootstrap));
        match signup {
            Some(signup) => router.merge(fuz_auth::signup_routes::signup_router(signup)),
            None => router,
        }
    }
}

impl AppBackend {
    /// The account REST surface — account, bootstrap, and signup — each route
    /// state at the spine defaults through `gate` ([`AuthRestRoutes`]).
    #[must_use]
    pub fn auth_rest_routes(&self, gate: AuthGate) -> AuthRestRoutes {
        AuthRestRoutes {
            account: self.account_route_state(gate.clone()),
            bootstrap: self.bootstrap_route_state(gate.clone()),
            signup: Some(self.signup_route_state(gate)),
        }
    }

    /// `GET /api/admin/audit/stream`, the admin audit-log SSE stream at the
    /// spine defaults ([`fuz_realtime::AuditStreamRouteState::new`]: the
    /// admin role, a cookie session only), over [`AppBackend::audit_sse`].
    /// Merge it at the root: the route carries its absolute path.
    ///
    /// # Errors
    ///
    /// [`StartupError::Internal`] when the backend built no stream registry —
    /// its spec's [`super::AppBackendSpec::audit_sse`] is `None`.
    pub fn audit_stream_router(&self, gate: AuthGate) -> Result<Router, StartupError> {
        let audit_sse = self.audit_sse.clone().ok_or_else(|| {
            StartupError::Internal(
                "the audit stream registry is unbuilt (the backend spec's `audit_sse` is None)"
                    .into(),
            )
        })?;
        Ok(fuz_realtime::audit_stream_router(
            fuz_realtime::AuditStreamRouteState::new(gate, audit_sse),
        ))
    }

    /// `/api/account/{status,login,logout,password}` — the login limiters and
    /// the spine's default failure floor and jitter.
    #[must_use]
    pub fn account_route_state(&self, gate: AuthGate) -> AccountRouteState {
        AccountRouteState {
            gate,
            password_hasher: Arc::clone(&self.password_hasher),
            audit: Arc::clone(&self.audit_emitter),
            connection_closer: self.connection_closer(),
            bootstrap_available: Arc::clone(&self.bootstrap_available),
            login_ip_rate_limiter: self.login_ip_rate_limiter.clone(),
            login_account_rate_limiter: self.login_account_rate_limiter.clone(),
            login_fail_floor_ms: fuz_auth::DEFAULT_LOGIN_FAIL_FLOOR_MS,
            login_fail_jitter_ms: fuz_auth::DEFAULT_LOGIN_FAIL_JITTER_MS,
        }
    }

    /// `/api/account/bootstrap` — the token file at
    /// [`AppBackend::bootstrap_token_path`], and, when the server holds
    /// daemon-token state, the callback that teaches it the keeper a
    /// bootstrap creates.
    #[must_use]
    pub fn bootstrap_route_state(&self, gate: AuthGate) -> BootstrapRouteState {
        BootstrapRouteState {
            options: Arc::new(fuz_auth::BootstrapOptions {
                pool: self.pool.clone(),
                password_hasher: Arc::clone(&self.password_hasher),
                audit: Arc::clone(&self.audit_emitter),
                bootstrap_available: Arc::clone(&self.bootstrap_available),
                token_store: self.bootstrap_token_path.as_ref().map(|p| {
                    let store: Arc<dyn fuz_auth::BootstrapTokenStore> =
                        Arc::new(fuz_auth::FileBootstrapTokenStore::new(p.clone()));
                    store
                }),
                on_keeper_resolved: self.daemon_token_state.as_ref().map(|state| {
                    let callback: Arc<dyn fuz_auth::BootstrapKeeperResolved> =
                        Arc::new(fuz_auth::DaemonTokenKeeperResolved::new(Arc::clone(state)));
                    callback
                }),
            }),
            gate,
        }
    }

    /// `/api/account/signup` — its own limiters, not the login buckets (a
    /// signup flood must not spend the budget bounding credential guessing),
    /// at the login bounds, as the TS twin does: the spine has no
    /// signup-specific defaults.
    #[must_use]
    pub fn signup_route_state(&self, gate: AuthGate) -> SignupRouteState {
        SignupRouteState {
            options: Arc::new(fuz_auth::SignupOptions {
                pool: self.pool.clone(),
                password_hasher: Arc::clone(&self.password_hasher),
                audit: Arc::clone(&self.audit_emitter),
                signup_ip_rate_limiter: self
                    .rate_limiters
                    .limiter(fuz_auth::DEFAULT_LOGIN_IP_RATE_LIMIT),
                signup_account_rate_limiter: self
                    .rate_limiters
                    .limiter(fuz_auth::DEFAULT_LOGIN_ACCOUNT_RATE_LIMIT),
                signup_fail_floor_ms: fuz_auth::DEFAULT_SIGNUP_FAIL_FLOOR_MS,
                signup_fail_jitter_ms: fuz_auth::DEFAULT_SIGNUP_FAIL_JITTER_MS,
            }),
            gate,
        }
    }

    /// The spine's auth action families (account self-service, admin,
    /// role-grant offers, `role_grant_assign`). Their rate-limit classes ride
    /// the specs, so the dispatcher's limiters charge them — one budget across
    /// the auth set and the rest of the registry.
    #[must_use]
    pub fn auth_spec_set(
        &self,
        authorize: Arc<dyn OfferCreateAuthorize>,
        roles: Arc<RoleRegistry>,
    ) -> Vec<ActionSpec> {
        crate::auth_adapter::build_auth_spec_set(
            Arc::clone(&self.audit_emitter),
            self.connection_closer(),
            authorize,
            roles,
        )
    }

    /// The dispatcher both transports run through: `registry`, charging
    /// `limits`, through `gate` — what [`crate::create_rpc_router`] takes and
    /// [`Self::ws_route_state`] wraps.
    #[must_use]
    pub fn action_dispatch(
        &self,
        gate: AuthGate,
        registry: Arc<ActionRegistry>,
        limits: &ActionRateLimits,
    ) -> ActionDispatch {
        ActionDispatch {
            gate,
            registry,
            audit: Arc::clone(&self.audit_emitter),
            connection_closer: self.connection_closer(),
            notification_sender: self.notification_sender(),
            rate_limits: limits.clone(),
        }
    }

    /// The WebSocket endpoint over `dispatch` and the backend's connection
    /// registry.
    ///
    /// `required_roles` is who may hold a socket (any-of; empty = any
    /// authenticated, unscoped credential). A socket receives every
    /// unfiltered broadcast, so a server whose broadcasts are privileged
    /// gates the socket itself, not just the verbs.
    #[must_use]
    pub fn ws_route_state(
        &self,
        dispatch: ActionDispatch,
        required_roles: Vec<&'static str>,
    ) -> WsRouteState {
        WsRouteState {
            dispatch,
            connection_registry: Arc::clone(&self.realtime),
            required_roles,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use fuz_http::BaseServerEnv;
    use tower::ServiceExt;

    use super::*;
    use crate::server::{AppBackendSpec, BrowserGateSpec, SpineBackendOptions, build_app_backend};

    /// A core over a pool nothing answers at (port 1), with the audit stream
    /// when `audit_sse` says.
    fn backend(audit_sse: bool) -> AppBackend {
        let env = BaseServerEnv::from_vars(
            &|k| match k {
                "DATABASE_URL" => Some("postgres://unused@127.0.0.1:1/unused".to_owned()),
                "SECRET_FUZ_COOKIE_KEYS" => Some("0123456789abcdef0123456789abcdef".to_owned()),
                "FUZ_ALLOWED_ORIGINS" => Some("http://localhost".to_owned()),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads");
        build_app_backend(
            &env,
            &AppBackendSpec {
                session_cookie_name: "spine_test_session",
                migration_namespaces: &[],
                expected_schema_json: None,
                audit_sse: audit_sse.then_some(crate::server::AuditSseSpec::DEFAULT),
                browser_gates: BrowserGateSpec::DEFAULT,
            },
            &SpineBackendOptions {
                rate_limiters: fuz_auth::RateLimiterMode::DisabledForTesting,
                ..SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new()))
            },
        )
        .expect("the core builds without the database")
    }

    /// The status a bodiless `POST` to `path` answers: a mounted JSON route
    /// refuses the missing content type (415) before reading anything, and an
    /// unmounted one is axum's 404.
    async fn post_status(router: Router, path: &str) -> StatusCode {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .body(Body::empty())
            .expect("the request builds");
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000"
                .parse::<SocketAddr>()
                .expect("the peer parses"),
        ));
        router
            .oneshot(request)
            .await
            .expect("the router answers")
            .status()
    }

    #[tokio::test]
    async fn the_auth_rest_routes_mount_signup_unless_it_is_none() {
        let backend = backend(false);
        let mounted = || {
            Router::new().nest(
                "/api/account",
                backend.auth_rest_routes(backend.auth_gate()).into_router(),
            )
        };
        for path in [
            "/api/account/login",
            "/api/account/bootstrap",
            "/api/account/signup",
        ] {
            assert_ne!(
                post_status(mounted(), path).await,
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        let without_signup = Router::new().nest(
            "/api/account",
            AuthRestRoutes {
                signup: None,
                ..backend.auth_rest_routes(backend.auth_gate())
            }
            .into_router(),
        );
        assert_ne!(
            post_status(without_signup.clone(), "/api/account/login").await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            post_status(without_signup, "/api/account/signup").await,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn the_audit_stream_router_needs_the_specs_stream() {
        let backend_with = backend(true);
        let _router = backend_with
            .audit_stream_router(backend_with.auth_gate())
            .expect("the spec mounts the stream");
        let backend_without = backend(false);
        let error = backend_without
            .audit_stream_router(backend_without.auth_gate())
            .expect_err("no registry");
        assert!(matches!(error, StartupError::Internal(_)), "{error}");
    }
}
