//! Serving: the run options a consumer embeds, the probes and the boot-only
//! router, the upkeep beside the server, and [`serve_until_shutdown`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use fuz_auth::ConnectionCloser;
use fuz_http::{
    BaseServerEnv, BodyCap, CancellationToken, DEFAULT_BODY_LIMIT_BYTES, GatedRouter, RouteGroup,
    StackOptions, compose_stack,
};
use serde::Serialize;
use tokio::task::JoinHandle;

use super::backend::{AppBackendSpec, SpineBackendOptions};
use super::startup_error::StartupError;

/// The run options every spine server shares — embed it in the consumer's
/// `RunAppOptions` beside the consumer's own swap points.
#[allow(missing_debug_implementations)] // carries `SpineBackendOptions`
pub struct SpineRunOptions {
    /// The backend's swap points, handed to
    /// [`super::backend::create_app_backend`].
    pub backend: SpineBackendOptions,
    /// The bind when `HOST` / `PORT` are unset, and the half a set one leaves
    /// out. A loopback consumer passes `127.0.0.1:<port>`; its test binary a
    /// neighboring port, so both can run.
    pub default_addr: SocketAddr,
    /// Bounds the graceful-shutdown drain ([`fuz_http::DEFAULT_DRAIN_TIMEOUT`]).
    pub drain_timeout: Duration,
}

impl SpineRunOptions {
    /// The production options at `default_addr`
    /// ([`SpineBackendOptions::production`], the default drain timeout).
    #[must_use]
    pub fn production(
        password_hasher: Arc<dyn fuz_auth::PasswordHasher>,
        default_addr: SocketAddr,
    ) -> Self {
        Self {
            backend: SpineBackendOptions::production(password_hasher),
            default_addr,
            drain_timeout: fuz_http::DEFAULT_DRAIN_TIMEOUT,
        }
    }
}

/// The body of `GET /health`, the spine's one shape (`{"status":"ok"}`), so
/// cross-backend round-trips see one wire shape.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// `GET /health` and `GET /`, the liveness probes: `/` answers
/// `<server_name> (rust) — see /health`.
pub fn probe_router(server_name: &'static str) -> Router {
    Router::new().route("/health", get(health)).route(
        "/",
        get(move || async move { format!("{server_name} (rust) — see /health\n") }),
    )
}

/// The `404` every unrouted path answers.
#[must_use]
pub fn not_found_response() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

async fn not_found() -> Response {
    not_found_response()
}

/// The fallback group: [`not_found_response`] for every unrouted path, behind
/// the 1 MiB cap and the origin check, like the routed groups.
#[must_use]
pub fn fallback_group() -> RouteGroup {
    RouteGroup::new(
        "fallback",
        Router::new().fallback(not_found),
        BodyCap::Bytes(DEFAULT_BODY_LIMIT_BYTES),
    )
}

/// The router a server serves with no database.
///
/// The probes ([`probe_router`]) and the fallback, through the same stack as
/// the full router (1 MiB cap, origin-checked). Without a database there is no
/// `AuthGate`, so `stack_options` comes from the env's allowlist and proxies.
#[must_use]
pub fn boot_only_router(server_name: &'static str, stack_options: &StackOptions) -> GatedRouter {
    compose_stack(
        [RouteGroup::new(
            "probes",
            probe_router(server_name),
            BodyCap::Bytes(DEFAULT_BODY_LIMIT_BYTES),
        )],
        fallback_group(),
        stack_options,
    )
}

/// The boot-only branch, for a server started with no `DATABASE_URL`: the
/// router it serves in place of the full one.
///
/// In order, as the full boot would: the allowlist's wildcards refused unless
/// `FUZ_ALLOW_ORIGIN_WILDCARDS=true`, each warned of when admitted
/// ([`super::BrowserGateSpec::admit_origin_wildcards`] over the spec's
/// gates); then the boot-only warning; then [`boot_only_router`] over the
/// env's allowlist and proxies and the spec's host gate. A misconfigured
/// list is loud before any database exists.
///
/// # Errors
///
/// [`StartupError::Config`] (exit `2`) for a wildcard entry without the
/// opt-in.
pub fn boot_only(
    env: &BaseServerEnv,
    spec: &AppBackendSpec,
    server_name: &'static str,
) -> Result<GatedRouter, StartupError> {
    spec.browser_gates.admit_origin_wildcards(env)?;
    tracing::warn!("DATABASE_URL not set; running in boot-only mode (no /api/*, no /ready)");
    Ok(boot_only_router(
        server_name,
        &StackOptions {
            host_gate: spec.browser_gates.host_gate,
            allowed_origins_var: spec.browser_gates.allowed_origins_var,
            ..StackOptions::new(
                env.allowed_origins.clone(),
                Arc::new(env.trusted_proxies.clone()),
            )
        },
    ))
}

/// A periodic task the server runs beside itself, spawned once the listener
/// is bound: it takes the shutdown token and returns its handle.
pub type UpkeepTask = Box<dyn FnOnce(CancellationToken) -> JoinHandle<()> + Send>;

/// What [`spawn_upkeep`] schedules.
#[allow(missing_debug_implementations)] // boxed-closure field
pub struct UpkeepOptions {
    /// The spine's auth cleanup ([`fuz_auth::spawn_auth_cleanup`]), every
    /// [`fuz_auth::DEFAULT_AUTH_CLEANUP_INTERVAL`]: expired sessions deleted
    /// and their connections closed, expired role-grant offers audited once.
    /// Built by `AppBackend::auth_cleanup_options`.
    pub auth_cleanup: fuz_auth::AuthCleanupOptions,
    /// The consumer's own tasks on the same token — a disk fact store's
    /// `fuz_fact::spawn_orphan_temp_sweeper`, an invite-expiry sweep.
    pub extra: Vec<UpkeepTask>,
}

/// Spawn the upkeep tasks.
///
/// Each runs a startup pass and then one per interval until `shutdown`
/// fires; cancelling drops a pass in progress, so the
/// handles resolve at once. Call it once migrations have run — the startup
/// passes read the schema.
///
/// # Panics
///
/// When called outside a tokio runtime.
#[must_use]
pub fn spawn_upkeep(options: UpkeepOptions, shutdown: &CancellationToken) -> Vec<JoinHandle<()>> {
    let UpkeepOptions {
        auth_cleanup,
        extra,
    } = options;
    let mut handles = vec![fuz_auth::spawn_auth_cleanup(
        auth_cleanup,
        fuz_auth::DEFAULT_AUTH_CLEANUP_INTERVAL,
        shutdown.clone(),
    )];
    handles.extend(extra.into_iter().map(|task| task(shutdown.clone())));
    handles
}

/// What [`serve_until_shutdown`] serves with.
#[allow(missing_debug_implementations)] // Arc-of-dyn + boxed-closure fields
pub struct ServeOptions {
    /// Names the startup and shutdown sentinels (`<name> listening on …`).
    pub server_name: &'static str,
    pub addr: SocketAddr,
    pub drain_timeout: Duration,
    /// The process's shutdown token (`fuz_http::shutdown_token`).
    pub shutdown: CancellationToken,
    /// The closer over every live transport, which shutdown closes them
    /// through (`AppBackend::connection_closer`). `None` in boot-only mode, which
    /// mounts nothing live.
    pub connection_closer: Option<Arc<dyn ConnectionCloser>>,
    /// The upkeep to run beside the server. `None` in boot-only mode.
    pub upkeep: Option<UpkeepOptions>,
}

/// Bind, start the upkeep, serve until the shutdown token fires, then join
/// the upkeep.
///
/// On the token, `fuz_http::serve_with_shutdown` closes every live WebSocket
/// with 1001 and ends every SSE stream through the closer, then drains
/// in-flight requests, bounded by the drain timeout. It returns only once the
/// token has fired, so the upkeep is already stopping. Two `eprintln!`
/// sentinels, which no log filter suppresses, mark the bind and the end.
///
/// # Errors
///
/// [`StartupError::Bind`] when the listener cannot bind;
/// [`StartupError::Serve`] when the serve loop fails.
pub async fn serve_until_shutdown(
    router: GatedRouter,
    options: ServeOptions,
) -> Result<(), StartupError> {
    let ServeOptions {
        server_name,
        addr,
        drain_timeout,
        shutdown,
        connection_closer,
        upkeep,
    } = options;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| StartupError::Bind { addr, source })?;
    let upkeep = upkeep.map(|upkeep| spawn_upkeep(upkeep, &shutdown));

    eprintln!("{server_name} listening on http://{addr}");

    let closer: &dyn fuz_http::ShutdownCloser = match &connection_closer {
        Some(closer) => closer.as_ref(),
        None => &fuz_http::NoopShutdownCloser,
    };
    let served =
        fuz_http::serve_with_shutdown(listener, router, shutdown, closer, drain_timeout).await;

    for task in upkeep.into_iter().flatten() {
        if let Err(e) = task.await {
            tracing::warn!(error = %e, "an upkeep task failed");
        }
    }
    served.map_err(StartupError::Serve)?;

    eprintln!("{server_name} shutdown complete");
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    use super::*;

    const FOREIGN_ORIGIN: &str = "http://evil.invalid";

    async fn send(
        method: &str,
        path: &str,
        headers: &[(header::HeaderName, &str)],
    ) -> (StatusCode, String) {
        let stack_options = StackOptions::new(
            fuz_http::AllowedOrigins::parse("http://localhost:*").expect("the allowlist parses"),
            Arc::new(Vec::new()),
        );
        let mut builder = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(name, *value);
        }
        let mut request = builder.body(Body::empty()).expect("the request builds");
        // `serve_with_shutdown` inserts the peer; a `oneshot` has no connection
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000"
                .parse::<SocketAddr>()
                .expect("the peer parses"),
        ));
        let response = boot_only_router("probe_test_server", &stack_options)
            .into_router_for_testing()
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body reads");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn the_probes_answer_and_name_the_server() {
        assert_eq!(
            send("GET", "/health", &[]).await,
            (StatusCode::OK, r#"{"status":"ok"}"#.to_owned())
        );
        assert_eq!(
            send("GET", "/", &[]).await,
            (
                StatusCode::OK,
                "probe_test_server (rust) — see /health\n".to_owned()
            )
        );
        assert_eq!(
            send("GET", "/nope", &[]).await,
            (StatusCode::NOT_FOUND, "not found\n".to_owned())
        );
    }

    #[tokio::test]
    async fn every_path_is_behind_the_origin_check_and_the_cap() {
        for path in ["/health", "/", "/nope"] {
            assert_eq!(
                send("GET", path, &[(header::ORIGIN, FOREIGN_ORIGIN)])
                    .await
                    .0,
                StatusCode::FORBIDDEN,
                "{path}"
            );
            let over_cap = (DEFAULT_BODY_LIMIT_BYTES + 1).to_string();
            assert_eq!(
                send(
                    "POST",
                    path,
                    &[
                        (header::ORIGIN, FOREIGN_ORIGIN),
                        (header::CONTENT_LENGTH, &over_cap)
                    ],
                )
                .await
                .0,
                StatusCode::PAYLOAD_TOO_LARGE,
                "{path}"
            );
        }
    }

    /// The env for a boot with no database over `origins`, the wildcard
    /// flag as given.
    fn boot_only_env(origins: &str, flag: Option<&str>) -> BaseServerEnv {
        BaseServerEnv::from_vars(
            &|k| match k {
                "FUZ_ALLOWED_ORIGINS" => Some(origins.to_owned()),
                "FUZ_ALLOW_ORIGIN_WILDCARDS" => flag.map(str::to_owned),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads")
    }

    fn boot_only_spec(host_gate: bool) -> AppBackendSpec {
        AppBackendSpec {
            session_cookie_name: "spine_test_session",
            migration_namespaces: &[],
            expected_schema_json: None,
            audit_sse: None,
            browser_gates: super::super::BrowserGateSpec {
                allowed_origins_var: "APP_ALLOWED_ORIGINS",
                host_gate,
                ..super::super::BrowserGateSpec::DEFAULT
            },
        }
    }

    async fn boot_only_status(router: GatedRouter, host: &str) -> StatusCode {
        let mut request = Request::builder()
            .uri("/health")
            .header(header::HOST, host)
            .body(Body::empty())
            .expect("the request builds");
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000"
                .parse::<SocketAddr>()
                .expect("the peer parses"),
        ));
        router
            .into_router_for_testing()
            .oneshot(request)
            .await
            .expect("the router answers")
            .status()
    }

    /// The boot-only branch refuses a wildcard allowlist without the opt-in,
    /// naming the spec's var, as the full boot does.
    #[test]
    fn boot_only_refuses_a_wildcard_origin_without_the_opt_in() {
        for flag in [None, Some("false")] {
            let Err(error) = boot_only(
                &boot_only_env("http://localhost:*", flag),
                &boot_only_spec(false),
                "probe_test_server",
            ) else {
                panic!("{flag:?}: a wildcard without the opt-in boots");
            };
            let StartupError::Config(message) = &error else {
                panic!("{flag:?}: expected a config error, got {error:?}");
            };
            assert!(
                message.starts_with(
                    "APP_ALLOWED_ORIGINS holds a wildcard entry, refused unless \
                     FUZ_ALLOW_ORIGIN_WILDCARDS=true"
                ),
                "{message}"
            );
        }
    }

    /// With the opt-in, or an exact list, it serves the probes, through the
    /// spec's host gate.
    #[tokio::test]
    async fn boot_only_serves_the_probes_behind_the_specs_gates() {
        for (origins, flag) in [
            ("http://localhost:*", Some("true")),
            ("http://localhost", None),
        ] {
            let router = boot_only(
                &boot_only_env(origins, flag),
                &boot_only_spec(false),
                "probe_test_server",
            )
            .expect("boots");
            assert_eq!(
                boot_only_status(router, "rebound.example").await,
                StatusCode::OK,
                "{origins}: no host gate"
            );
        }
        let env = boot_only_env("http://localhost", None);
        let gated = || boot_only(&env, &boot_only_spec(true), "probe_test_server").expect("boots");
        assert_eq!(boot_only_status(gated(), "localhost").await, StatusCode::OK);
        assert_eq!(
            boot_only_status(gated(), "rebound.example").await,
            StatusCode::FORBIDDEN,
            "the spec's host gate"
        );
    }

    #[tokio::test]
    async fn a_taken_port_is_a_bind_error() {
        let held = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral port");
        let addr = held.local_addr().expect("the bound address");
        let stack_options = StackOptions::new(
            fuz_http::AllowedOrigins::parse("http://localhost").expect("the allowlist parses"),
            Arc::new(Vec::new()),
        );
        let error = serve_until_shutdown(
            boot_only_router("bind_test_server", &stack_options),
            ServeOptions {
                server_name: "bind_test_server",
                addr,
                drain_timeout: Duration::from_secs(1),
                shutdown: CancellationToken::new(),
                connection_closer: None,
                upkeep: None,
            },
        )
        .await
        .expect_err("the port is held");
        assert!(
            matches!(error, StartupError::Bind { addr: a, .. } if a == addr),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_cancelled_token_ends_the_serve() {
        let stack_options = StackOptions::new(
            fuz_http::AllowedOrigins::parse("http://localhost").expect("the allowlist parses"),
            Arc::new(Vec::new()),
        );
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        tokio::time::timeout(
            Duration::from_secs(10),
            serve_until_shutdown(
                boot_only_router("cancel_test_server", &stack_options),
                ServeOptions {
                    server_name: "cancel_test_server",
                    addr: "127.0.0.1:0".parse().expect("addr"),
                    drain_timeout: Duration::from_secs(1),
                    shutdown,
                    connection_closer: None,
                    upkeep: None,
                },
            ),
        )
        .await
        .expect("the serve ends")
        .expect("a clean end");
    }
}
