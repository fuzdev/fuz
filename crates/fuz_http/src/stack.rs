//! The composition root — one function that turns a server's route groups
//! into the router it serves, every request gated in one fixed order.
//!
//! A consumer hands [`compose_stack`] its routes split into [`RouteGroup`]s,
//! a fallback group for everything unrouted, and the [`StackOptions`] every
//! group shares. The stack owns the order and the defaults; a group chooses
//! its body cap, whether it refuses CORS-simple requests, and, by an explicit
//! named carve-out, whether the origin check applies.
//!
//! ## The order
//!
//! Outermost first — the order a request meets the layers:
//!
//! ```text
//! request_tracing_layer (optional, the whole router)
//!   → catch_panic (the whole router)
//!   → per group: body cap → host_layer (on by default) → origin_layer
//!       → simple_request_layer (optional, per group) → client_ip_middleware
//!       → handler
//! ```
//!
//! **The body cap sits outside the origin check in every group**, so a
//! request that declares a `Content-Length` over its group's cap answers
//! `413` whatever else is wrong with it — a foreign `Origin` included. That
//! has to be per group: one outer cap sized to the largest group, with
//! tighter caps inside, would put each tighter cap inside the origin check
//! and answer such a request `403`. A group whose handler owns its cap
//! ([`BodyCap::HandlerOwned`]) has no cap layer, so there a refusal on the
//! headers comes first.
//!
//! Tracing wraps everything, so a refusal from any layer below is logged like
//! any other response. `client_ip_middleware` sits innermost: no layer above
//! it reads the `ClientIp` extension, and every handler gets it.
//!
//! ## A panic answers 500
//!
//! A panic anywhere below the tracing layer — a handler, a gate, the
//! fallback — is caught and answered with the generic
//! [`internal_error_response`] (`500 {"error":"internal_error"}`), the
//! panic message logged at `error`; the connection and the process go on.
//! It needs the binary built with `panic = "unwind"` (under `abort` the
//! process dies before anything can catch), so every production spine
//! server's release profile unwinds (this workspace's `testing_spine_stub`
//! keeps the workspace's `abort`; a stub panic fails the harness loudly).
//!
//! The TS twin answers an unhandled throw in a REST handler with this body.
//! Its JSON-RPC dispatcher answers a `-32603` envelope instead; the layer
//! sees no request — not the route kind, not the call's `id` — so here a
//! JSON-RPC route gets the flat body too, at the same `500`.
//!
//! Not covered: a panic after the response head has gone out (while a
//! streamed body is polled) or in a task the handler spawned — a WebSocket
//! or SSE connection's task after the upgrade. Under unwind it ends that
//! task, or that connection, and nothing else.
//!
//! ## The origin check covers every path
//!
//! Every group, the fallback included, is checked unless it carries an
//! [`OriginScope::CarvedOut`] with a stated reason — the one way to take a
//! group out, and greppable as `origin_carve_out(`. A request with no
//! `Origin` passes the check ([`AllowedOrigins::allows_request`]), so probes,
//! CLI clients and server-to-server callers are unaffected by the default;
//! what it refuses is a browser page from a foreign origin, on any path.
//!
//! ## The fallback is gated
//!
//! The fallback is a [`RouteGroup`] like the others, with its own cap and
//! origin scope, mounted as the router's fallback service. Unrouted paths
//! therefore pass the same gates as routed ones: a fallback attached after
//! the layers would answer outside every gate.
//!
//! ## The composed router is closed
//!
//! [`compose_stack`] returns a [`GatedRouter`], not an `axum::Router`. It has
//! no `route`, `merge`, `fallback` or `layer`, and it is not a `tower`
//! service, so nothing can be added outside the gates after composition;
//! [`crate::serve_with_shutdown`] serves only a `GatedRouter`, so a router
//! that skipped the stack cannot be served through it.

use std::any::Any;
use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::Response;
use tower_http::catch_panic::CatchPanicLayer;

use crate::body_limit::body_limit_layer;
use crate::host::{HostGate, host_layer};
use crate::ip_resolve::client_ip_middleware;
use crate::origin::{AllowedOrigins, origin_layer};
use crate::parsed_proxy::ParsedProxy;
use crate::rest_error::internal_error_response;
use crate::server_env::ALLOWED_ORIGINS_VAR;
use crate::simple_request::simple_request_layer;
use crate::tracing_layer::request_tracing_layer;

/// How a [`RouteGroup`] bounds request bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyCap {
    /// Cap request bodies at this many bytes: `body_limit_layer` outside the
    /// origin check (a declared `Content-Length` over it is a `413` before any
    /// other gate runs), plus axum's [`DefaultBodyLimit`] at the same size so a
    /// buffering extractor (`Bytes`, `Json`, `Multipart`) is held to it rather
    /// than to axum's own 2 MiB default.
    ///
    /// A body with no declared length (chunked) over the cap is refused too,
    /// but which refusal it gets when a header check also applies is
    /// implementation-defined (see [`crate::body_limit`]).
    Bytes(usize),
    /// The group's handlers bound their bodies themselves — a streamed upload
    /// that answers its own, more informative `413`, or a body piped to a
    /// subprocess that owns its limits. No cap layer is mounted, so a refusal
    /// on the headers (a foreign `Origin`) answers before the handler's cap:
    /// the one exception to cap-first, which `reason` records.
    ///
    /// axum's 2 MiB [`DefaultBodyLimit`] still holds for any buffering
    /// extractor such a handler uses.
    HandlerOwned {
        /// Why the handler, not the stack, owns the cap.
        reason: &'static str,
    },
}

/// Whether a [`RouteGroup`] is behind the origin check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginScope {
    /// Behind [`origin_layer`] — the default for every group.
    Checked,
    /// Out of the origin check, for the stated reason. Made with
    /// [`RouteGroup::origin_carve_out`].
    CarvedOut {
        /// Why the group is safe without the check — typically a stricter
        /// browser-context refusal of its own.
        reason: &'static str,
    },
}

/// A set of routes that share one body cap, one origin scope, and one
/// simple-request policy.
///
/// The router carries its own state and **no fallback of its own** — the
/// fallback is a group of its own, [`compose_stack`]'s second argument, and
/// a group router with a top-level `.fallback()` is refused at composition.
/// `name` labels the group in the boot log and in errors.
pub struct RouteGroup {
    name: &'static str,
    router: Router,
    cap: BodyCap,
    origin: OriginScope,
    refuse_simple_requests: bool,
}

impl std::fmt::Debug for RouteGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteGroup")
            .field("name", &self.name)
            .field("cap", &self.cap)
            .field("origin", &self.origin)
            .field("refuse_simple_requests", &self.refuse_simple_requests)
            .finish_non_exhaustive()
    }
}

impl RouteGroup {
    /// A group behind the origin check ([`OriginScope::Checked`]) with the
    /// given cap, admitting CORS-simple requests.
    #[must_use]
    pub const fn new(name: &'static str, router: Router, cap: BodyCap) -> Self {
        Self {
            name,
            router,
            cap,
            origin: OriginScope::Checked,
            refuse_simple_requests: false,
        }
    }

    /// Take this group out of the origin check, for the stated reason.
    ///
    /// The only way a group leaves the default. The reason is logged at boot
    /// beside the group's name, so every carve-out a server makes is visible
    /// in its startup output as well as in its source.
    #[must_use]
    pub const fn origin_carve_out(mut self, reason: &'static str) -> Self {
        self.origin = OriginScope::CarvedOut { reason };
        self
    }

    /// Mount [`simple_request_layer`] in this group, refusing a `POST` a
    /// browser could send cross-origin without a preflight (a form or
    /// multipart body). For a group whose routes take only JSON; a group with
    /// a form or multipart upload leaves it off.
    #[must_use]
    pub const fn refuse_simple_requests(mut self) -> Self {
        self.refuse_simple_requests = true;
        self
    }

    /// The group's name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The group's body cap.
    #[must_use]
    pub const fn cap(&self) -> BodyCap {
        self.cap
    }

    /// The group's origin scope.
    #[must_use]
    pub const fn origin(&self) -> OriginScope {
        self.origin
    }

    /// Whether the group refuses CORS-simple requests
    /// ([`refuse_simple_requests`](Self::refuse_simple_requests)).
    #[must_use]
    pub const fn refuses_simple_requests(&self) -> bool {
        self.refuse_simple_requests
    }
}

/// What every group of a [`compose_stack`] router shares.
///
/// A server with a `fuz_auth::AuthGate` builds these from the gate
/// (`AuthGate::stack_options`), so the stack's origin check and the gate's
/// in-handler one read the same allowlist; a server with no gate (a
/// boot-only router) uses [`StackOptions::new`].
#[derive(Debug, Clone)]
pub struct StackOptions {
    /// The allowlist the origin check (and, when on, the host gate) reads.
    pub allowed_origins: AllowedOrigins,
    /// The env var the allowlist was read from, which the host gate's
    /// refusal warning names. [`ALLOWED_ORIGINS_VAR`] unless the server
    /// reads its own.
    pub allowed_origins_var: &'static str,
    /// The trusted-proxy set `client_ip_middleware` resolves `X-Forwarded-For`
    /// against. Empty is the conservative setting, not a disabled one: every
    /// peer is untrusted, so the TCP peer is the client IP.
    pub trusted_proxies: Arc<Vec<ParsedProxy>>,
    /// Mount [`host_layer`] in every group — the DNS-rebinding gate (see
    /// [`crate::host`]). On by default; a server reached by names its
    /// allowlist doesn't hold (and that accepts the rebinding exposure)
    /// clears it.
    pub host_gate: bool,
    /// Wrap the router in [`request_tracing_layer`] — one access-log line per
    /// request. Off for a server whose request volume would drown its log.
    pub request_tracing: bool,
}

impl StackOptions {
    /// Options with the given allowlist (read from [`ALLOWED_ORIGINS_VAR`])
    /// and trusted proxies, request tracing on, and the host gate on.
    #[must_use]
    pub const fn new(
        allowed_origins: AllowedOrigins,
        trusted_proxies: Arc<Vec<ParsedProxy>>,
    ) -> Self {
        Self {
            allowed_origins,
            allowed_origins_var: ALLOWED_ORIGINS_VAR,
            trusted_proxies,
            host_gate: true,
            request_tracing: true,
        }
    }
}

/// A router [`compose_stack`] built — every route, and the fallback, behind
/// the gates.
///
/// Closed to extension: it offers no way to add a route, a fallback, or a
/// layer, and it is not a `tower` service, so it cannot be nested or
/// mounted inside another router either. It is served by
/// [`crate::serve_with_shutdown`], which takes nothing else. Cloning is
/// cheap (an `axum::Router` is `Arc`-backed).
#[derive(Clone)]
pub struct GatedRouter {
    router: Router,
}

impl std::fmt::Debug for GatedRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatedRouter").finish_non_exhaustive()
    }
}

impl GatedRouter {
    /// The composed router, for the serve loop.
    pub(crate) fn into_router(self) -> Router {
        self.router
    }

    /// Wrap a router that did not go through [`compose_stack`] — for this
    /// crate's own serve-loop tests, which exercise the loop, not the gates.
    #[cfg(test)]
    pub(crate) const fn ungated_for_tests(router: Router) -> Self {
        Self { router }
    }

    /// The composed router, to drive in-process (`tower::ServiceExt::oneshot`)
    /// in a test.
    ///
    /// Present only under the test-only `test_router_access` feature. Enabled
    /// from a `[dev-dependencies]` entry, it stays out of a build that
    /// compiles no tests, so a binary from that build cannot reach the
    /// composed router to extend it; a normal edge enabling it — from any
    /// package in the build — would compile it into every binary, and
    /// `cargo xtask check-release` refuses one.
    #[cfg(any(test, feature = "test_router_access"))]
    pub fn into_router_for_testing(self) -> Router {
        self.router
    }
}

/// Compose a server's router: each group gated in the fixed order (module doc
/// § The order), the fallback group gated the same way, and the optional
/// tracing layer around it all.
///
/// A panic anywhere inside the tracing layer answers the generic `500`
/// (module doc § A panic answers 500).
///
/// Every carve-out — a group out of the origin check, or a cap its handler
/// owns — is logged at `info` with its reason, and so is how client IPs
/// resolve: from `X-Forwarded-For` behind the trusted proxies, or the TCP peer
/// when there are none.
///
/// **One path, one group.** Route each path in exactly one group. axum merges
/// a path routed in two groups by method into one method router, so a method
/// neither group routes answers that router's `405` outside the gates of the
/// group a request would otherwise reach — a path split across a checked and
/// a carved-out group leaks a `405` past the origin check.
///
/// # Panics
///
/// At boot, before anything is served:
///
/// - when the fallback group is carved out of the origin check
///   ([`RouteGroup::origin_carve_out`]) — it answers every unrouted path, so
///   a carve-out there would admit a foreign `Origin` on all of them; the
///   message names the group;
/// - when a group's router carries a top-level fallback of its own (axum's
///   "Cannot merge two `Router`s that both have a fallback") — the stack
///   mounts the fallback group first, so a group's own fallback cannot be
///   silently replaced by it; put that fallback in the fallback group;
/// - when two groups route the same path and method (axum's overlapping-route
///   panic).
///
/// A fallback nested under a path prefix (`Router::nest`) is part of its
/// group and passes that group's gates; only a top-level one is refused.
#[allow(
    clippy::panic,
    reason = "a carved-out fallback is a boot-time misconfiguration, refused before anything is served"
)]
pub fn compose_stack(
    groups: impl IntoIterator<Item = RouteGroup>,
    fallback: RouteGroup,
    options: &StackOptions,
) -> GatedRouter {
    if let OriginScope::CarvedOut { reason } = fallback.origin {
        panic!(
            "compose_stack: the fallback group `{}` is carved out of the origin check \
             ({reason}) — the fallback answers every unrouted path, so a foreign Origin \
             would pass on all of them; route the paths that need the carve-out in a \
             group of their own",
            fallback.name
        );
    }
    log_trusted_proxies(&options.trusted_proxies);
    // the fallback goes in first: merging a group that carries a top-level
    // fallback into a router that already has one panics, where the reverse
    // order would silently replace the group's
    let router = groups.into_iter().fold(
        Router::new().fallback_service(gate_group(fallback, options)),
        |router, group| router.merge(gate_group(group, options)),
    );
    let router = router.layer(CatchPanicLayer::custom(
        |panic: Box<dyn Any + Send + 'static>| panic_response(&*panic),
    ));
    let router = if options.request_tracing {
        router.layer(request_tracing_layer())
    } else {
        router
    };
    GatedRouter { router }
}

/// Log how the stack resolves client IPs. An empty set is the conservative
/// posture, not a disabled one: every peer fails the trust check, so
/// `X-Forwarded-For` is never believed and `ClientIp` is the TCP peer.
fn log_trusted_proxies(trusted_proxies: &[ParsedProxy]) {
    if trusted_proxies.is_empty() {
        tracing::info!("no trusted proxies configured — XFF ignored, client IP is the TCP peer");
    } else {
        tracing::info!(
            count = trusted_proxies.len(),
            "trusted proxies configured — XFF resolution enabled"
        );
    }
}

/// The response to a request whose handling panicked: the generic `500`,
/// with the panic's message logged. Only the message — the request is not
/// in reach here, so nothing of it is logged.
fn panic_response(panic: &(dyn Any + Send)) -> Response {
    let message = panic
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("(non-string panic payload)");
    tracing::error!(panic = message, "request handling panicked; answered 500");
    internal_error_response()
}

/// One group's router behind its gates, innermost layer first.
fn gate_group(group: RouteGroup, options: &StackOptions) -> Router {
    let RouteGroup {
        name,
        router,
        cap,
        origin,
        refuse_simple_requests,
    } = group;

    let mut router = router.layer(from_fn_with_state(
        Arc::clone(&options.trusted_proxies),
        client_ip_middleware,
    ));
    if refuse_simple_requests {
        router = router.layer(from_fn(simple_request_layer));
    }
    match origin {
        OriginScope::Checked => {
            router = router.layer(from_fn_with_state(
                options.allowed_origins.clone(),
                origin_layer,
            ));
        }
        OriginScope::CarvedOut { reason } => {
            tracing::info!(
                group = name,
                reason,
                "route group carved out of the origin check"
            );
        }
    }
    if options.host_gate {
        router = router.layer(from_fn_with_state(
            HostGate::new(options.allowed_origins.clone(), options.allowed_origins_var),
            host_layer,
        ));
    }
    match cap {
        BodyCap::Bytes(max_bytes) => router
            .layer(DefaultBodyLimit::max(max_bytes))
            .layer(body_limit_layer(max_bytes)),
        BodyCap::HandlerOwned { reason } => {
            tracing::info!(
                group = name,
                reason,
                "route group's body cap is owned by its handlers"
            );
            router
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::extract::{ConnectInfo, Extension};
    use axum::http::{Request, StatusCode, header};
    use axum::routing::{get, post};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::ip_resolve::ClientIp;

    const ALLOWED: &str = "https://app.example";
    const FOREIGN: &str = "https://evil.example";
    const SMALL_CAP: usize = 64;
    const LARGE_CAP: usize = 4096;

    async fn ok() -> &'static str {
        "ok"
    }

    async fn echo_body(body: axum::body::Bytes) -> String {
        format!("{}", body.len())
    }

    async fn echo_client_ip(Extension(ClientIp(ip)): Extension<ClientIp>) -> String {
        ip
    }

    async fn panics() -> &'static str {
        panic!("test: the handler panicked")
    }

    async fn not_found() -> (StatusCode, &'static str) {
        (StatusCode::NOT_FOUND, "nothing here")
    }

    fn base_options() -> StackOptions {
        StackOptions::new(
            AllowedOrigins::parse(ALLOWED).unwrap(),
            Arc::new(Vec::new()),
        )
    }

    /// The groups every test composes: two capped groups with caps far apart
    /// (so a body over one is under the other), a handler-owned group, a
    /// carved-out group, and a group that refuses CORS-simple requests.
    fn groups() -> Vec<RouteGroup> {
        vec![
            RouteGroup::new(
                "small",
                Router::new()
                    .route("/small", post(echo_body))
                    .route("/ip", get(echo_client_ip))
                    .route("/panic", get(panics)),
                BodyCap::Bytes(SMALL_CAP),
            ),
            RouteGroup::new(
                "json_only",
                Router::new().route("/json_only", post(echo_body)),
                BodyCap::Bytes(SMALL_CAP),
            )
            .refuse_simple_requests(),
            RouteGroup::new(
                "large",
                Router::new().route("/large", post(echo_body)),
                BodyCap::Bytes(LARGE_CAP),
            ),
            RouteGroup::new(
                "owned",
                Router::new().route("/owned", post(ok)),
                BodyCap::HandlerOwned {
                    reason: "test: the handler bounds its own body",
                },
            ),
            RouteGroup::new(
                "carved",
                Router::new().route("/carved", post(echo_body)),
                BodyCap::Bytes(SMALL_CAP),
            )
            .origin_carve_out("test: refuses browser callers itself"),
        ]
    }

    fn fallback() -> RouteGroup {
        RouteGroup::new(
            "fallback",
            Router::new().fallback(not_found),
            BodyCap::Bytes(SMALL_CAP),
        )
    }

    fn app(options: &StackOptions) -> GatedRouter {
        compose_stack(groups(), fallback(), options)
    }

    /// A `POST` with a declared length of `len` bytes.
    fn post_req(path: &str, len: usize, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, len.to_string());
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let mut req = builder.body(Body::from(vec![b'x'; len])).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))));
        req
    }

    async fn send(app: GatedRouter, req: Request<Body>) -> (StatusCode, String) {
        let response = app.into_router_for_testing().oneshot(req).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    async fn status(app: GatedRouter, req: Request<Body>) -> StatusCode {
        send(app, req).await.0
    }

    #[tokio::test]
    async fn a_panic_answers_the_generic_500_and_the_router_serves_on() {
        let router = app(&base_options());
        let mut req = Request::get("/panic").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))));
        let response = router
            .clone()
            .into_router_for_testing()
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, r#"{"error":"internal_error"}"#);
        // the same router answers the next request
        assert_eq!(
            send(router, post_req("/small", 1, &[])).await,
            (StatusCode::OK, "1".to_owned())
        );
    }

    #[tokio::test]
    async fn every_capped_group_answers_413_before_403() {
        let options = base_options();
        for (path, cap) in [
            ("/small", SMALL_CAP),
            ("/large", LARGE_CAP),
            ("/carved", SMALL_CAP),
            ("/unrouted", SMALL_CAP),
        ] {
            let over = post_req(path, cap + 1, &[("origin", FOREIGN)]);
            let (status, body) = send(app(&options), over).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
            assert_eq!(body, r#"{"error":"payload_too_large"}"#, "{path}");
        }
    }

    #[tokio::test]
    async fn each_group_is_held_to_its_own_cap() {
        let options = base_options();
        // over the small cap, under the large one: only the small group refuses
        let len = SMALL_CAP * 2;
        assert_eq!(
            status(app(&options), post_req("/small", len, &[])).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            send(app(&options), post_req("/large", len, &[])).await,
            (StatusCode::OK, len.to_string())
        );
        // at the cap passes
        assert_eq!(
            status(app(&options), post_req("/small", SMALL_CAP, &[])).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_foreign_origin_is_refused_on_every_checked_group_and_the_fallback() {
        let options = base_options();
        for path in ["/small", "/large", "/owned", "/unrouted"] {
            let (status, body) =
                send(app(&options), post_req(path, 1, &[("origin", FOREIGN)])).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(body, r#"{"error":"forbidden_origin"}"#, "{path}");
        }
    }

    #[tokio::test]
    async fn a_handler_owned_cap_answers_the_origin_check_first() {
        // the recorded exception: no cap layer, so the header refusal wins
        let options = base_options();
        assert_eq!(
            status(
                app(&options),
                post_req("/owned", LARGE_CAP * 4, &[("origin", FOREIGN)])
            )
            .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(app(&options), post_req("/owned", LARGE_CAP * 4, &[])).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_carved_out_group_admits_a_foreign_origin_and_only_that_group() {
        let options = base_options();
        assert_eq!(
            status(
                app(&options),
                post_req("/carved", 1, &[("origin", FOREIGN)])
            )
            .await,
            StatusCode::OK
        );
        // the carve-out does not leak to a sibling or to the fallback
        assert_eq!(
            status(app(&options), post_req("/small", 1, &[("origin", FOREIGN)])).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(
                app(&options),
                post_req("/nowhere", 1, &[("origin", FOREIGN)])
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn an_absent_or_allowed_origin_passes_everywhere() {
        let options = base_options();
        for path in ["/small", "/large", "/owned", "/carved"] {
            for headers in [&[][..], &[("origin", ALLOWED)][..]] {
                assert_eq!(
                    status(app(&options), post_req(path, 1, headers)).await,
                    StatusCode::OK,
                    "{path} {headers:?}"
                );
            }
        }
        // the fallback answers its own 404, not a gate's
        assert_eq!(
            send(app(&options), post_req("/unrouted", 1, &[])).await,
            (StatusCode::NOT_FOUND, "nothing here".to_owned())
        );
    }

    #[tokio::test]
    async fn an_empty_fallback_router_is_gated_too() {
        // a consumer with no fallback of its own passes an empty router, whose
        // default 404 must still sit behind the gates
        let options = base_options();
        let router = compose_stack(
            groups(),
            RouteGroup::new("fallback", Router::new(), BodyCap::Bytes(SMALL_CAP)),
            &options,
        );
        assert_eq!(
            status(router.clone(), post_req("/x", 1, &[("origin", FOREIGN)])).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(
                router.clone(),
                post_req("/x", SMALL_CAP + 1, &[("origin", FOREIGN)])
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            status(router, post_req("/x", 1, &[])).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn the_host_gate_sits_inside_the_cap() {
        let options = base_options();
        let foreign_host = [("host", "rebind.example")];
        assert_eq!(
            send(app(&options), post_req("/small", 1, &foreign_host)).await,
            (
                StatusCode::FORBIDDEN,
                r#"{"error":"forbidden_host"}"#.to_owned()
            )
        );
        assert_eq!(
            status(
                app(&options),
                post_req("/small", SMALL_CAP + 1, &foreign_host)
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // loopback passes; a cleared gate passes anything
        assert_eq!(
            status(
                app(&options),
                post_req("/small", 1, &[("host", "localhost:4000")])
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            status(
                app(&StackOptions {
                    host_gate: false,
                    ..base_options()
                }),
                post_req("/small", 1, &foreign_host)
            )
            .await,
            StatusCode::OK
        );
    }

    /// A form `POST` of `len` bytes to `path`, from `origin` when given.
    fn form_req(path: &str, len: usize, origin: Option<&str>) -> Request<Body> {
        let mut req = post_req(path, len, &[]);
        req.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        if let Some(origin) = origin {
            req.headers_mut()
                .insert(header::ORIGIN, origin.parse().unwrap());
        }
        req
    }

    #[tokio::test]
    async fn the_simple_request_gate_sits_inside_the_origin_check() {
        let options = base_options();
        assert_eq!(
            status(app(&options), form_req("/json_only", 1, None)).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            status(app(&options), form_req("/json_only", 1, Some(FOREIGN))).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(
                app(&options),
                form_req("/json_only", SMALL_CAP + 1, Some(FOREIGN))
            )
            .await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // JSON still passes the group that refuses forms
        assert_eq!(
            status(app(&options), post_req("/json_only", 1, &[])).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn the_simple_request_gate_is_per_group() {
        // a group that takes a form or multipart upload leaves it off, while a
        // sibling refuses — neither leaks to the other, nor to the fallback
        let options = base_options();
        assert_eq!(
            status(app(&options), form_req("/small", 1, None)).await,
            StatusCode::OK
        );
        assert_eq!(
            status(app(&options), form_req("/json_only", 1, None)).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            status(app(&options), form_req("/unrouted", 1, None)).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn handlers_see_the_resolved_client_ip() {
        let options = base_options();
        let mut req = Request::get("/ip").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 1, 2, 3], 4000))));
        assert_eq!(
            send(app(&options), req).await,
            (StatusCode::OK, "10.1.2.3".to_owned())
        );
    }

    #[tokio::test]
    async fn the_default_body_limit_follows_the_cap() {
        // a cap above axum's 2 MiB default holds a buffering extractor to the
        // cap, not to the default
        const BIG: usize = 3 * 1024 * 1024;
        let router = compose_stack(
            vec![RouteGroup::new(
                "big",
                Router::new().route("/big", post(echo_body)),
                BodyCap::Bytes(BIG),
            )],
            fallback(),
            &base_options(),
        );
        let len = BIG - 1;
        assert_eq!(
            send(router, post_req("/big", len, &[])).await,
            (StatusCode::OK, len.to_string())
        );
    }

    #[test]
    fn a_group_is_checked_until_carved_out() {
        let group = RouteGroup::new("g", Router::new(), BodyCap::Bytes(1));
        assert_eq!(group.origin(), OriginScope::Checked);
        assert!(!group.refuses_simple_requests());
        let group = group.origin_carve_out("why").refuse_simple_requests();
        assert_eq!(group.origin(), OriginScope::CarvedOut { reason: "why" });
        assert!(group.refuses_simple_requests());
        assert_eq!(group.name(), "g");
        assert_eq!(group.cap(), BodyCap::Bytes(1));
    }

    #[test]
    #[should_panic(expected = "both have a fallback")]
    fn a_group_with_its_own_fallback_is_refused_at_composition() {
        // a group's top-level fallback would otherwise be replaced by the
        // fallback group's without a word — a consumer's SPA fallback gone
        let spa = RouteGroup::new(
            "spa",
            Router::new().route("/app", get(ok)).fallback(ok),
            BodyCap::Bytes(SMALL_CAP),
        );
        let _ = compose_stack([spa], fallback(), &base_options());
    }

    #[test]
    #[should_panic(expected = "the fallback group `static` is carved out of the origin check")]
    fn a_carved_out_fallback_is_refused_at_composition() {
        // the fallback answers every unrouted path — carved out, a foreign
        // Origin would pass on all of them
        let carved = RouteGroup::new(
            "static",
            Router::new().fallback(not_found),
            BodyCap::Bytes(SMALL_CAP),
        )
        .origin_carve_out("test: a carve-out where none may go");
        let _ = compose_stack(groups(), carved, &base_options());
    }

    #[tokio::test]
    async fn a_nested_fallback_stays_inside_its_group() {
        // a fallback under a prefix is part of the group: it composes, answers
        // that prefix's unrouted paths, and passes the group's gates
        let nested = RouteGroup::new(
            "nested",
            Router::new().nest(
                "/api",
                Router::new().route("/a", get(ok)).fallback(not_found),
            ),
            BodyCap::Bytes(SMALL_CAP),
        );
        let router = compose_stack([nested], fallback(), &base_options());
        assert_eq!(
            status(
                router.clone(),
                post_req("/api/x", 1, &[("origin", FOREIGN)])
            )
            .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(router, post_req("/api/x", 1, &[])).await,
            StatusCode::NOT_FOUND
        );
    }
}
