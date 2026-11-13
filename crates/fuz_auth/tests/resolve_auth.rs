//! No-Postgres unit tests for the [`AuthGate`] — the per-request front door
//! (`fuz_auth/src/auth_gate.rs`) — and the credential walk behind it
//! (`fuz_auth/src/resolve.rs`).
//!
//! [`AuthGate::resolve_credential`] walks **daemon-token → cookie → bearer** and
//! returns the first leg that authenticates. The *success* legs all reach the
//! DB (cookie → session lookup, bearer → api-token lookup, daemon → keeper
//! account), so success-precedence is exercised by the cross-backend suite.
//! What's pinnable **without Postgres** is the rejection walk + the
//! security-consequential short-circuits that fire *before* any pool access:
//!
//! - all-absent credentials → `None`;
//! - the **bearer browser-context rejection** (a `Bearer` token presented with
//!   an `Origin`/`Referer` is refused — defense-in-depth against tokens leaking
//!   into browser-attached requests), the bearer scheme/empty-token parse
//!   guards, and the shape precheck that refuses a value that cannot be a
//!   token without a pool checkout;
//! - daemon-token validation failure and the no-keeper-bound short-circuit;
//! - the gate's origin check, which [`AuthGate::preflight`] runs ahead of the
//!   walk — a foreign `Origin` is refused before the pool dials, even beside a
//!   credential that would;
//! - a leg whose read fails: the walk ends there with that leg's
//!   [`CredentialReadFault`] and its 500, and the legs after it are not tried.
//!
//! The pool is a never-connecting handle, so the suite runs in the fast
//! (no-`#[ignore]`) lane. The precheck case swaps in a pool that dials a local
//! listener counting connection attempts: a malformed bearer makes none, and
//! its control — a well-formed unknown token — makes at least one, and fails
//! the read.
//! `is_browser_context` itself — the heart of the bearer rejection — is
//! unit-tested inline in `bearer_auth.rs`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE, ORIGIN, REFERER};
use fuz_auth::daemon_token::DAEMON_TOKEN_HEADER;
use fuz_auth::{
    API_TOKEN_PREFIX, AuthGate, CREDENTIAL_READ_FAULT_BODY, CredentialFaultKind,
    CredentialReadFault, CredentialType, SharedDaemonTokenState, generate_api_token,
    generate_session_token, sign_session_cookie,
};
use fuz_db::{Pool, create_pool};
use uuid::Uuid;

/// A pool that never connects — every case below short-circuits before
/// `pool.get()`, so the URL only needs to parse.
fn pool_no_db() -> Pool {
    create_pool(
        "postgres://localhost/fuz_auth_resolve_unused",
        &fuz_db::PoolOptions::default(),
    )
    .expect("create_pool")
}

/// A daemon-token state with `current_token` and an optional bound keeper.
fn daemon_state(current_token: &str, keeper_account_id: Option<Uuid>) -> SharedDaemonTokenState {
    fuz_testing::daemon_token_state(current_token, keeper_account_id)
}

async fn resolve(headers: &HeaderMap, daemon: Option<&SharedDaemonTokenState>) -> bool {
    resolve_with_pool(headers, daemon, &pool_no_db()).await
}

async fn resolve_with_pool(
    headers: &HeaderMap,
    daemon: Option<&SharedDaemonTokenState>,
    pool: &Pool,
) -> bool {
    gate(pool, daemon)
        .preflight(headers, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect("the fixture sends no foreign origin")
        .is_some()
}

/// The fault the walk over `pool` ends with. Panics if it resolves instead.
async fn fault_with_pool(
    headers: &HeaderMap,
    daemon: Option<&SharedDaemonTokenState>,
    pool: &Pool,
) -> CredentialReadFault {
    let gate = gate(pool, daemon);
    let origin = gate
        .check_origin(headers)
        .expect("the fixture sends no foreign origin");
    gate.resolve_credential(origin, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect_err("the leg's read fails")
}

/// Assert `response` is a failed credential checkout's: the 503
/// `{"error":"service_unavailable"}`, byte for byte — the TS twin's `onError`
/// answer to a `DbCheckoutError`.
async fn assert_unavailable_response(response: axum::response::Response) {
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&axum::http::HeaderValue::from_static("application/json")),
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, &br#"{"error":"service_unavailable"}"#[..]);
}

/// Assert `response` is a failed credential query's: the TS twin's unhandled
/// error answer, byte for byte.
async fn assert_fault_response(response: axum::response::Response) {
    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        response.headers().get(axum::http::header::CONTENT_TYPE),
        Some(&axum::http::HeaderValue::from_static(
            "text/plain; charset=UTF-8"
        )),
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, CREDENTIAL_READ_FAULT_BODY.as_bytes());
    assert_eq!(CREDENTIAL_READ_FAULT_BODY, "Internal Server Error");
}

/// A request `Authorization` value carrying a well-formed (unknown) API token —
/// the bearer leg dials the pool to look it up.
fn well_formed_bearer() -> String {
    format!("Bearer {}", generate_api_token().token)
}

/// A gate over `pool` with `daemon` mounted and the fixture allowlist
/// ([`fuz_testing::TESTING_ALLOWED_ORIGIN`]).
fn gate(pool: &Pool, daemon: Option<&SharedDaemonTokenState>) -> AuthGate {
    AuthGate {
        daemon_token_state: daemon.cloned(),
        session_cookie_name: "fuz_session",
        ..fuz_testing::testing_auth_gate(pool.clone())
    }
}

/// A request `Cookie` value carrying a validly signed (unknown) session — the
/// cookie leg verifies it and then dials the pool to look the session up.
fn signed_cookie() -> String {
    let set_cookie = sign_session_cookie(
        &fuz_testing::testing_keyring(),
        &generate_session_token(),
        "fuz_session",
    );
    set_cookie.split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn no_credentials_resolves_to_none() {
    // Every leg parse-fails before touching the pool.
    assert!(!resolve(&HeaderMap::new(), None).await);
}

#[tokio::test]
async fn bearer_in_browser_context_is_rejected() {
    // The defense-in-depth guard: a `Bearer` token presented with an `Origin`
    // (or `Referer`) is refused *before* the token is ever looked up — so a
    // token leaked into a browser-attached request can't authenticate.
    for browser_header in [ORIGIN, REFERER] {
        let mut headers = HeaderMap::new();
        // well-formed, so the refusal is the browser-context guard's, not the
        // shape precheck's
        let bearer = format!("Bearer {}", generate_api_token().token);
        headers.insert(AUTHORIZATION, bearer.parse().unwrap());
        // an allowed origin, so the gate's origin check admits the request and
        // the refusal is the walk's own browser-context guard
        headers.insert(
            &browser_header,
            fuz_testing::TESTING_ALLOWED_ORIGIN.parse().unwrap(),
        );
        assert!(
            !resolve(&headers, None).await,
            "bearer + {browser_header:?} must be rejected"
        );
    }
}

#[tokio::test]
async fn non_bearer_scheme_is_ignored() {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
    assert!(!resolve(&headers, None).await);
}

#[tokio::test]
async fn empty_bearer_token_is_ignored() {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer ".parse().unwrap());
    assert!(!resolve(&headers, None).await);
}

/// A pool whose server is a local listener that counts the connections it
/// accepts and drops each one, so a checkout fails fast and leaves a count.
async fn counting_pool() -> (Pool, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let pool = create_pool(
        &format!("postgres://fuz@127.0.0.1:{port}/fuz_auth_resolve_unused"),
        &fuz_db::PoolOptions::default(),
    )
    .expect("create_pool");
    (pool, accepted)
}

#[tokio::test]
async fn malformed_bearer_is_refused_without_a_pool_checkout() {
    let well_formed = generate_api_token().token;
    let malformed = [
        "some-token-value".to_owned(),
        well_formed[..well_formed.len() - 1].to_owned(),
        format!("{well_formed}A"),
        format!("{API_TOKEN_PREFIX}{}", "=".repeat(43)),
    ];
    for value in malformed {
        let (pool, accepted) = counting_pool().await;
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {value}").parse().unwrap());
        assert!(!resolve_with_pool(&headers, None, &pool).await);
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "{value:?} must be refused before the pool dials"
        );
    }

    // the control: a well-formed (unknown) token does dial, so the count above
    // is a live probe rather than a listener nothing could reach
    let (pool, accepted) = counting_pool().await;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {well_formed}").parse().unwrap(),
    );
    let fault = fault_with_pool(&headers, None, &pool).await;
    assert_eq!(fault.leg(), CredentialType::ApiToken);
    assert!(
        accepted.load(Ordering::SeqCst) > 0,
        "a well-formed token reaches the pool"
    );
}

#[tokio::test]
async fn a_leg_whose_checkout_fails_ends_the_walk_with_the_503() {
    let keeper = Uuid::new_v4();
    let state = daemon_state("the-real-token", Some(keeper));
    let daemon = || {
        let mut headers = HeaderMap::new();
        headers.insert(DAEMON_TOKEN_HEADER, "the-real-token".parse().unwrap());
        headers
    };
    let cookie = || {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, signed_cookie().parse().unwrap());
        headers
    };
    let bearer = || {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, well_formed_bearer().parse().unwrap());
        headers
    };
    let all = || {
        let mut headers = daemon();
        headers.extend(cookie());
        headers.extend(bearer());
        headers
    };
    let cookie_and_bearer = || {
        let mut headers = cookie();
        headers.extend(bearer());
        headers
    };

    // each leg alone, then the first of several: the leg whose read failed is
    // the fault's, never a later one the walk went on to try
    let cases = [
        (
            "daemon",
            daemon(),
            Some(&state),
            CredentialType::DaemonToken,
        ),
        ("cookie", cookie(), None, CredentialType::Session),
        ("bearer", bearer(), None, CredentialType::ApiToken),
        (
            "every leg",
            all(),
            Some(&state),
            CredentialType::DaemonToken,
        ),
        (
            "cookie and bearer",
            cookie_and_bearer(),
            None,
            CredentialType::Session,
        ),
    ];
    for (name, headers, daemon, leg) in cases {
        let (pool, accepted) = counting_pool().await;
        let fault = fault_with_pool(&headers, daemon, &pool).await;
        assert_eq!(fault.leg(), leg, "{name}");
        assert_eq!(fault.kind(), CredentialFaultKind::Unavailable, "{name}");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "{name}: one checkout, and no leg after the failed one dials"
        );

        let (pool, _) = counting_pool().await;
        let refused = gate(&pool, daemon)
            .preflight(&headers, fuz_http::UNRESOLVED_CLIENT_IP)
            .await
            .expect_err("a failed read is no credential");
        assert_unavailable_response(refused).await;
    }
}

/// A failed query on a leg's checked-out client keeps the text 500 — only a
/// failed checkout is the 503.
#[tokio::test]
async fn a_failed_credential_query_answers_the_text_500() {
    for leg in [
        CredentialType::Session,
        CredentialType::ApiToken,
        CredentialType::DaemonToken,
    ] {
        let response = axum::response::IntoResponse::into_response(CredentialReadFault::new(
            leg,
            CredentialFaultKind::Read,
        ));
        assert_fault_response(response).await;
        let response = axum::response::IntoResponse::into_response(CredentialReadFault::new(
            leg,
            CredentialFaultKind::Unavailable,
        ));
        assert_unavailable_response(response).await;
    }
}

/// The public caller's checkout and read faults answer by phase: the flat 503
/// for a failed checkout, the flat 500 for a failed read.
#[tokio::test]
async fn a_public_context_fault_answers_by_phase() {
    use axum::response::IntoResponse as _;
    assert_unavailable_response(fuz_auth::PublicContextFault::CallerUnavailable.into_response())
        .await;
    let response = fuz_auth::PublicContextFault::CallerRead.into_response();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, &br#"{"error":"internal_error"}"#[..]);
}

#[tokio::test]
async fn unparseable_cookie_leg_falls_through_to_none() {
    // A `Cookie` header with no valid signed session under `fuz_session` yields
    // no token at the parse stage (before any DB lookup), and with no other
    // credential the walk ends at `None`.
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, "fuz_session=not-a-signed-value".parse().unwrap());
    assert!(!resolve(&headers, None).await);
}

#[tokio::test]
async fn invalid_daemon_token_is_rejected() {
    // Daemon-token leg runs first; an invalid token fails constant-time
    // validation and the walk falls through (no pool access).
    let state = daemon_state("the-real-token", Some(Uuid::new_v4()));
    let mut headers = HeaderMap::new();
    headers.insert(DAEMON_TOKEN_HEADER, "wrong-token".parse().unwrap());
    assert!(!resolve(&headers, Some(&state)).await);
}

#[tokio::test]
async fn valid_daemon_token_without_bound_keeper_is_none() {
    // A valid token but no keeper account resolved yet (pre-bootstrap) →
    // `None`, short-circuiting at `keeper_account_id?` before any pool access.
    let state = daemon_state("the-real-token", None);
    let mut headers = HeaderMap::new();
    headers.insert(DAEMON_TOKEN_HEADER, "the-real-token".parse().unwrap());
    assert!(!resolve(&headers, Some(&state)).await);
}

#[tokio::test]
async fn the_gate_refuses_a_foreign_origin_before_the_walk_dials() {
    // a signed cookie is the one leg an `Origin` does not refuse on its own, so
    // without the origin check this request would reach the pool
    let (pool, accepted) = counting_pool().await;
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, signed_cookie().parse().unwrap());
    headers.insert(ORIGIN, "https://evil.example".parse().unwrap());
    let gate = gate(&pool, None);

    let refused = gate.check_origin(&headers).expect_err("a foreign origin");
    assert_eq!(refused.status(), axum::http::StatusCode::FORBIDDEN);
    let refused = gate
        .preflight(&headers, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect_err("a foreign origin");
    assert_eq!(refused.status(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "the refusal comes before the credential walk"
    );

    // the control: the allowed origin passes the check and the walk dials,
    // and fails its checkout on a pool that drops every connection
    headers.insert(ORIGIN, fuz_testing::TESTING_ALLOWED_ORIGIN.parse().unwrap());
    assert!(gate.check_origin(&headers).is_ok());
    let refused = gate
        .preflight(&headers, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect_err("the cookie leg's checkout fails");
    assert_eq!(
        refused.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        accepted.load(Ordering::SeqCst) > 0,
        "the cookie leg reaches the pool"
    );
}

#[tokio::test]
async fn the_gate_admits_a_request_with_no_origin() {
    let gate = gate(&pool_no_db(), None);
    assert!(gate.check_origin(&HeaderMap::new()).is_ok());
    assert!(
        gate.preflight(&HeaderMap::new(), fuz_http::UNRESOLVED_CLIENT_IP)
            .await
            .expect("no origin passes")
            .is_none()
    );
}
