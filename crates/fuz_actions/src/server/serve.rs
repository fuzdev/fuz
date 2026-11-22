//! Serving: the run options a consumer embeds, the probes and the boot-only
//! router, the upkeep beside the server, and [`serve_until_shutdown`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
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
#[expect(
    missing_debug_implementations,
    reason = "carries `SpineBackendOptions`, which has no `Debug`"
)]
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

/// The body of the `404` an unrouted path outside the auth scope answers —
/// `fuz_app`'s `NOT_FOUND_TEXT`, byte for byte, so the two spines answer one
/// plain-text `404`.
pub const NOT_FOUND_TEXT: &str = "404 Not Found";

/// The `404` of a path outside the auth scope that nothing serves:
/// [`NOT_FOUND_TEXT`] as `text/plain`.
#[must_use]
pub fn not_found_response() -> Response {
    (StatusCode::NOT_FOUND, NOT_FOUND_TEXT).into_response()
}

/// The `404` of a path no route serves, by where the raw path is.
///
/// Under the auth scope ([`fuz_auth::auth_middleware_applies`]) the JSON
/// [`fuz_http::route_not_found_response`], like every other refusal there,
/// and [`not_found_response`] elsewhere. Twin of `fuz_app`'s unmatched-route
/// handler, which decides by the same scope over the same raw path.
#[must_use]
pub fn unmatched_route_response(path: &str) -> Response {
    if fuz_auth::auth_middleware_applies(path) {
        fuz_http::route_not_found_response()
    } else {
        not_found_response()
    }
}

async fn unmatched_route(uri: Uri) -> Response {
    unmatched_route_response(uri.path())
}

/// The fallback group: [`unmatched_route_response`] for every unrouted path, behind
/// the 1 MiB cap and the origin check, like the routed groups.
#[must_use]
pub fn fallback_group() -> RouteGroup {
    RouteGroup::new(
        "fallback",
        Router::new().fallback(unmatched_route),
        BodyCap::Bytes(DEFAULT_BODY_LIMIT_BYTES),
    )
}

/// The router a server serves with no database: the probes and the fallback,
/// and nothing live.
///
/// The probes ([`probe_router`]) and the fallback, through the same stack as
/// the full router (1 MiB cap, origin-checked). Without a database there is no
/// backend, so `stack_options` comes from the env's allowlist and proxies
/// ([`StackOptions::without_backend`]), and the router carries no shutdown duties — it
/// has no live connection to close and no detached write to drain.
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
            ..StackOptions::without_backend(
                env.allowed_origins.clone(),
                Arc::new(env.trusted_proxies.clone()),
            )
        },
    ))
}

/// A periodic task the server runs beside itself, spawned once the listener
/// is bound: it takes the shutdown token and returns its handle.
///
/// The task must stop on the token — the shutdown joins it within its one
/// bound and aborts it past that.
pub type UpkeepTask = Box<dyn FnOnce(CancellationToken) -> JoinHandle<()> + Send>;

/// What [`spawn_upkeep`] schedules.
#[expect(
    missing_debug_implementations,
    reason = "a boxed-closure field has no `Debug`"
)]
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
/// fires. For the auth cleanup, cancelling drops a pass in progress, so its
/// handle resolves at once; a consumer's own task resolves when it stops on
/// the token. Call it once migrations have run — the startup passes read the
/// schema.
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

/// What [`serve_until_shutdown`] serves with, beside the router.
#[expect(
    missing_debug_implementations,
    reason = "`UpkeepOptions` holds boxed closures, which have no `Debug`"
)]
pub struct ServeOptions {
    /// Names the startup and shutdown sentinels (`<name> listening on …`).
    pub server_name: &'static str,
    pub addr: SocketAddr,
    /// Bounds the whole shutdown ([`fuz_http::DEFAULT_DRAIN_TIMEOUT`]).
    pub drain_timeout: Duration,
    /// The process's shutdown token (`fuz_http::shutdown_token`).
    pub shutdown: CancellationToken,
    /// The upkeep to run beside the server, from the bind until shutdown —
    /// `None` for a boot-only server, which has nothing to sweep.
    pub upkeep: Option<UpkeepOptions>,
}

/// Bind, start the upkeep, and serve `router` until the shutdown token fires,
/// then shut down within one drain timeout.
///
/// The router carries what its shutdown owes (`fuz_http::ShutdownDuties`):
/// a router composed over [`super::AppBackend::stack_options`] closes the
/// backend's live connections and drains its detached writes, and the
/// boot-only router ([`boot_only_router`]) owes nothing. The drain timeout
/// is counted from when the serve sees the token — the moment it fires —
/// and bounds, in
/// order (`fuz_http::serve_with_shutdown`):
///
/// 1. Every live WebSocket closed with 1001 and every SSE stream ended, every
///    HTTP request already dispatched answered, and every connection
///    finished closing. A WebSocket's in-flight dispatches are dropped with
///    its loop: one dropped in its handler rolls back, and one whose commit
///    has returned has its post-commit effects on the backend's tracker. The
///    TS twin differs here — it waits for an in-flight WS handler at
///    shutdown and refuses its reply; here it is dropped and rolls back.
/// 2. The upkeep joined. The spine's auth cleanup stops on the token at once;
///    a consumer's own task ([`UpkeepOptions::extra`]) should too, and one
///    still running at the bound is aborted.
/// 3. The backend's detached writes (`AppBackend::background_writes`)
///    drained: a failure row or a token touch, the post-commit effects of a
///    dispatch, the write of a request that answered in step 1. They follow
///    steps 1 and 2, so every write those spawned is seen.
///
/// What is still running when the bound runs out is given up on and counted
/// in the log — handlers still running and connections still open, closes
/// not finished, upkeep tasks aborted, writes still in flight — and dies with
/// the runtime. Two `eprintln!` sentinels, which no log filter suppresses,
/// mark the bind and the end. A token that fired during boot ends this
/// before the bind, with neither sentinel.
///
/// # Errors
///
/// [`StartupError::Config`] when `upkeep` is set but the router carries no
/// shutdown duties — upkeep means a backend, so the router was composed over
/// `StackOptions::without_backend` where it needed
/// [`super::AppBackend::stack_options`], and would serve with no close and
/// no drain; [`StartupError::Bind`] when the listener cannot bind;
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
        upkeep,
    } = options;
    if upkeep.is_some() && !router.has_shutdown_duties() {
        return Err(StartupError::Config(format!(
            "{server_name}: a router served with upkeep has a backend, but carries no shutdown \
             duties — compose it over `AppBackend::stack_options`, not \
             `StackOptions::without_backend`"
        )));
    }
    if shutdown.is_cancelled() {
        tracing::info!("{server_name}: shutdown signalled during boot; not serving");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| StartupError::Bind { addr, source })?;
    eprintln!("{server_name} listening on http://{addr}");
    let upkeep = upkeep.map_or_else(Vec::new, |upkeep| spawn_upkeep(upkeep, &shutdown));
    fuz_http::serve_with_shutdown(listener, router, shutdown, upkeep, drain_timeout)
        .await
        .map_err(StartupError::Serve)?;
    eprintln!("{server_name} shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode, header};
    use std::future::Future;

    use fuz_http::BackgroundWrites;
    use tower::ServiceExt;

    use super::*;

    const FOREIGN_ORIGIN: &str = "http://evil.invalid";

    async fn send(
        method: &str,
        path: &str,
        headers: &[(header::HeaderName, &str)],
    ) -> (StatusCode, String) {
        let stack_options = StackOptions::without_backend(
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
            (StatusCode::NOT_FOUND, NOT_FOUND_TEXT.to_owned())
        );
    }

    /// An unrouted path's 404 is JSON under the auth scope, read on the raw
    /// path, and the one plain text elsewhere.
    #[tokio::test]
    async fn an_unrouted_path_answers_by_its_place_in_the_auth_scope() {
        for path in [
            "/api",
            "/api/",
            "/api/nope",
            "/api//x",
            "/api/%2e%2e/health",
        ] {
            assert_eq!(
                send("GET", path, &[]).await,
                (
                    StatusCode::NOT_FOUND,
                    r#"{"error":"route_not_found"}"#.to_owned()
                ),
                "{path}"
            );
        }
        for path in ["/apix", "/API/x", "/%61pi/x", "//api/x", "/api%2Fx"] {
            assert_eq!(
                send("GET", path, &[]).await,
                (StatusCode::NOT_FOUND, NOT_FOUND_TEXT.to_owned()),
                "{path}"
            );
        }
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
        let stack_options = StackOptions::without_backend(
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
        let stack_options = StackOptions::without_backend(
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
                    upkeep: None,
                },
            ),
        )
        .await
        .expect("the serve ends")
        .expect("a clean end");
    }

    /// A server handed upkeep has a backend, so a router with no shutdown
    /// duties is one composed over the bare options by mistake: refused
    /// before it binds, rather than served with no close and no drain.
    #[tokio::test]
    async fn upkeep_beside_a_router_with_no_duties_is_refused() {
        let env = BaseServerEnv::from_vars(
            &|k| match k {
                "DATABASE_URL" => Some("postgres://spine:spine@127.0.0.1:1/unused".to_owned()),
                "SECRET_FUZ_COOKIE_KEYS" => Some("0123456789abcdef0123456789abcdef".to_owned()),
                "FUZ_ALLOWED_ORIGINS" => Some("http://localhost".to_owned()),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads");
        let backend = super::super::build_app_backend(
            &env,
            &boot_only_spec(false),
            &SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new())),
        )
        .expect("the core builds without the database");
        let bare = StackOptions::without_backend(
            fuz_http::AllowedOrigins::parse("http://localhost").expect("the allowlist parses"),
            Arc::new(Vec::new()),
        );
        let served = serve_until_shutdown(
            boot_only_router("duties_test_server", &bare),
            ServeOptions {
                server_name: "duties_test_server",
                addr: "127.0.0.1:0".parse().expect("addr"),
                drain_timeout: Duration::from_secs(1),
                shutdown: CancellationToken::new(),
                upkeep: Some(UpkeepOptions {
                    auth_cleanup: backend.auth_cleanup_options(),
                    extra: Vec::new(),
                }),
            },
        );
        let error = tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .expect("refused at once, not served")
            .expect_err("a live server with no duties is refused");
        let StartupError::Config(message) = &error else {
            panic!("expected a config error, got {error:?}");
        };
        assert!(message.contains("shutdown duties"), "{message}");
    }

    /// A token that fired during boot ends the serve before it binds: no
    /// listener, no `listening on` sentinel — here proven by a port already
    /// held, which a bind would refuse.
    #[tokio::test]
    async fn a_token_fired_during_boot_returns_before_the_bind() {
        let held = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral port");
        let stack_options = StackOptions::without_backend(
            fuz_http::AllowedOrigins::parse("http://localhost").expect("the allowlist parses"),
            Arc::new(Vec::new()),
        );
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        serve_until_shutdown(
            boot_only_router("early_test_server", &stack_options),
            ServeOptions {
                server_name: "early_test_server",
                addr: held.local_addr().expect("the bound address"),
                drain_timeout: Duration::from_secs(1),
                shutdown,
                upkeep: None,
            },
        )
        .await
        .expect("a clean end, with no bind attempted");
    }

    /// Await `writes`' drain for at most `ms`, then report how many are in
    /// flight — `0` once the drain resolved.
    async fn in_flight_after(writes: &BackgroundWrites, ms: u64) -> usize {
        match tokio::time::timeout(Duration::from_millis(ms), writes.drain()).await {
            Ok(()) => 0,
            Err(_) => writes.inflight_count(),
        }
    }

    /// A failure row is a tracked write: one in flight — here stuck dialing a
    /// server that accepts the connection and never answers — holds the
    /// shutdown drain.
    #[tokio::test]
    async fn an_audit_failure_row_is_a_tracked_write() {
        use fuz_auth::{AuditEventType, AuditLogInput};

        let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let pool = fuz_db::create_pool(
            &format!(
                "postgres://spine:spine@{}/spine_unused",
                silent.local_addr().expect("has an address")
            ),
            &fuz_db::PoolOptions::default(),
        )
        .expect("a lazily-built pool");
        let writes = Arc::new(BackgroundWrites::default());
        let emitter = Arc::new(fuz_auth::AuditEmitter::new(pool, Arc::clone(&writes)));
        let write = emitter.emit(AuditLogInput::for_event(AuditEventType::Login).failure());

        assert_eq!(in_flight_after(&writes, 100).await, 1);
        write.abort();
        assert_eq!(
            in_flight_after(&writes, 5000).await,
            0,
            "nothing left once the write ends"
        );
    }

    /// A bearer token's use is a tracked write too.
    #[tokio::test]
    async fn a_token_touch_is_a_tracked_write() {
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let pool = fuz_db::create_pool(
            &format!(
                "postgres://spine:spine@{}/spine_unused",
                silent.local_addr().expect("has an address")
            ),
            &fuz_db::PoolOptions::default(),
        )
        .expect("a lazily-built pool");
        let writes = Arc::new(BackgroundWrites::default());
        let touch = fuz_auth::api_token_queries::spawn_api_token_touch(
            &writes,
            &pool,
            "tok_unused",
            "127.0.0.1",
        );

        assert_eq!(
            in_flight_after(&writes, 100).await,
            1,
            "the touch in flight holds the drain"
        );
        touch.abort();
        assert_eq!(
            in_flight_after(&writes, 5000).await,
            0,
            "nothing left once the touch ends"
        );
    }

    /// A router whose shutdown duties are `writes` (and a closer with no
    /// connections), with `GET /block` running `handler`.
    fn live_router<F, Fut>(writes: &Arc<BackgroundWrites>, handler: F) -> GatedRouter
    where
        F: Fn() -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let closer: Arc<dyn fuz_http::ShutdownCloser> = Arc::new(fuz_auth::NoopConnectionCloser);
        let writes = Arc::clone(writes);
        let stack_options = StackOptions {
            shutdown: Some(fuz_http::ShutdownDuties::new(closer, writes)),
            ..StackOptions::without_backend(
                fuz_http::AllowedOrigins::parse("http://localhost").expect("the allowlist parses"),
                Arc::new(Vec::new()),
            )
        };
        compose_stack(
            [RouteGroup::new(
                "block",
                Router::new().route(
                    "/block",
                    get(move || {
                        let handler = handler.clone();
                        async move {
                            handler().await;
                            "done"
                        }
                    }),
                ),
                BodyCap::Bytes(DEFAULT_BODY_LIMIT_BYTES),
            )],
            fallback_group(),
            &stack_options,
        )
    }

    /// Serve `router` on an ephemeral port and send `GET /block`, returning
    /// the serve's handle and the request's socket (held so the request stays
    /// in flight).
    async fn serve_blocked(
        router: GatedRouter,
        shutdown: &CancellationToken,
        upkeep: Vec<JoinHandle<()>>,
        drain_timeout: Duration,
    ) -> (
        JoinHandle<Result<fuz_http::ServeShutdown, std::io::Error>>,
        tokio::net::TcpStream,
    ) {
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral port");
        let addr = listener.local_addr().expect("the bound address");
        let served = tokio::spawn(fuz_http::serve_with_shutdown(
            listener,
            router,
            shutdown.clone(),
            upkeep,
            drain_timeout,
        ));
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connects");
        stream
            .write_all(b"GET /block HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("the request writes");
        (served, stream)
    }

    /// A request already running when the shutdown starts is waited for, and
    /// so is the write it spawns on its way out: the router's write drain
    /// follows the request drain, so it sees what every finished request left
    /// behind.
    #[tokio::test]
    async fn the_shutdown_awaits_the_write_of_a_request_running_at_the_token() {
        let writes = Arc::new(BackgroundWrites::default());
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let landed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let router = live_router(&writes, {
            let (writes, started, release, landed) = (
                Arc::clone(&writes),
                Arc::clone(&started),
                Arc::clone(&release),
                Arc::clone(&landed),
            );
            move || {
                let (writes, started, release, landed) = (
                    Arc::clone(&writes),
                    Arc::clone(&started),
                    Arc::clone(&release),
                    Arc::clone(&landed),
                );
                async move {
                    started.notify_one();
                    release.notified().await;
                    writes.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        landed.store(true, std::sync::atomic::Ordering::SeqCst);
                    });
                }
            }
        });
        let shutdown = CancellationToken::new();
        let (served, _request) =
            serve_blocked(router, &shutdown, Vec::new(), Duration::from_secs(30)).await;
        started.notified().await;
        shutdown.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !served.is_finished(),
            "the running request holds the shutdown"
        );
        release.notify_one();
        let given_up = tokio::time::timeout(Duration::from_secs(60), served)
            .await
            .expect("the shutdown ends")
            .expect("the serve task ran")
            .expect("a clean end");
        assert_eq!(given_up, fuz_http::ServeShutdown::default());
        assert!(
            landed.load(std::sync::atomic::Ordering::SeqCst),
            "the request's write landed before the shutdown returned"
        );
    }

    /// One drain bound covers the whole shutdown — the requests, the upkeep,
    /// then the writes — counted from when the serve sees the token, and each
    /// phase's leftovers are counted. A request, an upkeep task and a write
    /// that never end get one bound between them, not one each.
    #[tokio::test]
    async fn one_bound_covers_the_requests_the_upkeep_and_the_writes() {
        let writes = Arc::new(BackgroundWrites::default());
        let started = Arc::new(tokio::sync::Notify::new());
        let router = live_router(&writes, {
            let started = Arc::clone(&started);
            move || {
                let started = Arc::clone(&started);
                async move {
                    started.notify_one();
                    std::future::pending::<()>().await;
                }
            }
        });
        let stuck_write = writes.spawn(std::future::pending::<()>());
        let stuck_upkeep = tokio::spawn(std::future::pending::<()>());
        let shutdown = CancellationToken::new();
        let bound = Duration::from_secs(1);
        let (served, _request) = serve_blocked(router, &shutdown, vec![stuck_upkeep], bound).await;
        started.notified().await;
        let fired = tokio::time::Instant::now();
        shutdown.cancel();
        let given_up = tokio::time::timeout(Duration::from_secs(60), served)
            .await
            .expect("the shutdown ends")
            .expect("the serve task ran")
            .expect("a clean end");
        let elapsed = fired.elapsed();
        assert_eq!(
            given_up,
            fuz_http::ServeShutdown {
                closes_given_up: true,
                requests_given_up: 1,
                connections_given_up: 1,
                upkeep_given_up: 1,
                writes_given_up: 1,
            }
        );
        // a bound per phase would take at least three; anything under two is
        // one shared bound, however loaded the machine
        assert!(
            elapsed >= bound && elapsed < bound * 2,
            "the shutdown took {elapsed:?} against a {bound:?} bound"
        );
        stuck_write.abort();
    }
}
