//! axum service-level proxy + origin tests.
//!
//! Exercises [`fuz_http::client_ip_middleware`] and
//! [`fuz_http::origin_layer`] through a real `axum::Router` so the
//! middleware composition (state, `ConnectInfo` plumbing, layer order)
//! is covered end-to-end. The unit tests in each module cover the
//! pure-function surface; this file covers the wiring.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration tests panic on assertion failure by design"
)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Extension};
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use http_body_util::BodyExt;
use tower::ServiceExt;

use fuz_http::{AllowedOrigins, ClientIp, client_ip_middleware, origin_layer, parse_proxy_list};

async fn echo_client_ip(Extension(client_ip): Extension<ClientIp>) -> String {
    client_ip.0
}

async fn ok() -> &'static str {
    "ok"
}

fn build_proxy_app(proxy_list: &str) -> Router {
    let proxies = Arc::new(parse_proxy_list(proxy_list).expect("proxy list parses"));
    Router::new()
        .route("/ip", get(echo_client_ip))
        .layer(from_fn_with_state(proxies, client_ip_middleware))
}

async fn issue(app: Router, addr: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let peer: SocketAddr = addr.parse().expect("peer addr parses");
    let mut builder = Request::builder().uri("/ip").method("GET");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::empty()).expect("request builds");

    // Inject ConnectInfo into request extensions so the middleware's
    // `ConnectInfo<SocketAddr>` extractor finds it. axum's
    // `serve_with_connect_info` does this for real connections; in
    // tower::ServiceExt-driven tests we plumb manually.
    let mut req = req;
    req.extensions_mut().insert(ConnectInfo(peer));

    let resp = app.oneshot(req).await.expect("response");
    let status = resp.status();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    let body_str = String::from_utf8(body.to_vec()).expect("utf8 body");
    (status, body_str)
}

#[tokio::test]
async fn client_ip_no_xff_uses_connection_ip() {
    let app = build_proxy_app("127.0.0.1");
    let (status, body) = issue(app, "203.0.113.5:12345", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "203.0.113.5");
}

#[tokio::test]
async fn client_ip_trusted_xff_resolves_to_originator() {
    let app = build_proxy_app("127.0.0.1");
    let (status, body) = issue(
        app,
        "127.0.0.1:12345",
        &[("x-forwarded-for", "203.0.113.5")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "203.0.113.5");
}

#[tokio::test]
async fn client_ip_untrusted_connection_ignores_xff() {
    // XFF is present but the TCP peer is not trusted — middleware
    // ignores the spoofable header and keys on the peer IP.
    let app = build_proxy_app("127.0.0.1");
    let (status, body) = issue(app, "203.0.113.5:12345", &[("x-forwarded-for", "1.2.3.4")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "203.0.113.5");
}

#[tokio::test]
async fn client_ip_multi_hop_stops_at_first_untrusted() {
    let app = build_proxy_app("127.0.0.1, 10.0.0.0/8");
    let (status, body) = issue(
        app,
        "127.0.0.1:12345",
        &[("x-forwarded-for", "203.0.113.5, 10.0.0.5, 127.0.0.1")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "203.0.113.5");
}

#[tokio::test]
async fn client_ip_malformed_xff_entry_stops_the_walk() {
    // Rate-limit-key poisoning defense — a malformed XFF entry is never the
    // resolved client IP, and neither is the client-written entry left of
    // it: the walk stops and the request keys on the connection IP.
    let app = build_proxy_app("127.0.0.1");
    for header in [
        "198.51.100.7, attacker-controlled",
        "198.51.100.7, 203.0.113.9:5555",
        "198.51.100.7, unknown, 127.0.0.1",
        "garbage, also-bad",
    ] {
        let (status, body) = issue(
            app.clone(),
            "127.0.0.1:12345",
            &[("x-forwarded-for", header)],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "127.0.0.1", "{header}");
    }
}

#[tokio::test]
async fn client_ip_ipv6_canonicalized() {
    // Different equivalent forms of ::1 must produce one bucket key.
    let app = build_proxy_app("127.0.0.1");
    let (status, body) = issue(app, "127.0.0.1:12345", &[("x-forwarded-for", "::01")]).await;
    assert_eq!(status, StatusCode::OK);
    // RFC 5952 canonical form is `::1`.
    assert_eq!(body, "::1");
}

#[tokio::test]
async fn client_ip_empty_xff_uses_connection_ip() {
    // Empty XFF header must be treated as absent. Otherwise the
    // trusted-XFF arm would substitute the connection IP and
    // spuriously fire the "all entries trusted" warn.
    let app = build_proxy_app("127.0.0.1");
    let (status, body) = issue(app, "127.0.0.1:12345", &[("x-forwarded-for", "")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "127.0.0.1");
}

#[tokio::test]
async fn client_ip_walks_every_xff_line() {
    // The client writes the first line; the trusted proxy appends the
    // address it saw on a line of its own. Reading the first line alone would
    // key the request on whatever the client chose.
    let app = build_proxy_app("127.0.0.1");
    let (status, body) = issue(
        app,
        "127.0.0.1:12345",
        &[
            ("x-forwarded-for", "198.51.100.77"),
            ("x-forwarded-for", "203.0.113.6"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "203.0.113.6");
}

#[tokio::test]
async fn client_ip_non_ascii_xff_still_resolves() {
    // A non-ASCII byte used to drop the whole header, keying the request on
    // the proxy; read as Latin-1 it is one malformed entry, left of the
    // untrusted entry the walk returns.
    let app = build_proxy_app("127.0.0.1");
    let mut req = Request::builder()
        .uri("/ip")
        .method("GET")
        .header(
            "x-forwarded-for",
            axum::http::HeaderValue::from_bytes(b"\xe9vil, 203.0.113.6").unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
    ));
    let resp = app.oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"203.0.113.6");
}

// -- Origin layer integration -------------------------------------------------

fn build_origin_app(allowed: &str) -> Router {
    let state = AllowedOrigins::parse(allowed).expect("valid allowlist");
    Router::new()
        .route("/api/ping", get(ok))
        .layer(from_fn_with_state(state, origin_layer))
}

async fn issue_origin(app: Router, origin: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().uri("/api/ping").method("GET");
    if let Some(o) = origin {
        builder = builder.header("origin", o);
    }
    let req = builder.body(Body::empty()).expect("request builds");
    app.oneshot(req).await.expect("response").status()
}

#[tokio::test]
async fn origin_layer_allows_no_origin() {
    let app = build_origin_app("https://app.example.com");
    assert_eq!(issue_origin(app, None).await, StatusCode::OK);
}

#[tokio::test]
async fn origin_layer_allows_exact_match() {
    let app = build_origin_app("https://app.example.com");
    assert_eq!(
        issue_origin(app, Some("https://app.example.com")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn origin_layer_rejects_unmatched() {
    let app = build_origin_app("https://app.example.com");
    assert_eq!(
        issue_origin(app, Some("https://evil.example.com")).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn origin_layer_allows_port_wildcard() {
    let app = build_origin_app("http://localhost:*");
    assert_eq!(
        issue_origin(app, Some("http://localhost:5173")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn origin_layer_allows_subdomain_wildcard() {
    let app = build_origin_app("https://*.fuz.dev");
    assert_eq!(
        issue_origin(app, Some("https://staging.fuz.dev")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn origin_layer_refuses_a_duplicated_origin() {
    let app = build_origin_app("https://app.example.com");
    let req = Request::builder()
        .uri("/api/ping")
        .method("GET")
        .header("origin", "https://app.example.com")
        .header("origin", "https://app.example.com")
        .body(Body::empty())
        .expect("request builds");
    assert_eq!(
        app.oneshot(req).await.expect("response").status(),
        StatusCode::FORBIDDEN
    );
}
