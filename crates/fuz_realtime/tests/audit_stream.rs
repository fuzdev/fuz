//! Route-level tests for `GET /api/admin/audit/stream`
//! ([`fuz_realtime::audit_stream_router`]) against a real `PostgreSQL`.
//!
//! **What the credential gate is for.** The route is role-gated and
//! token-scope-gated, and neither gate is about the credential *channel*: the
//! scope gate refuses a **narrowed** token and the role gate is account-grain,
//! so without a channel gate a **full-scope** API token on an admin account
//! opens the stream. The route carries the same credential-channel gate as
//! its sibling non-RPC surface `fuz_db_admin` (`DbAdminRouteState`),
//! session-only by default.
//!
//! Covered here:
//!
//! - the credential gate refuses a full-scope bearer with the canonical
//!   `credential_type_required` 403 — and refuses it **ahead of** the scope
//!   and role gates, so a wrong channel learns nothing about the deployment's
//!   token scoping or role structure;
//! - a cookie session on an admin account still opens the stream (**the
//!   regression guard** — a gate that refused everything would pass every
//!   negative above);
//! - a consumer that widens the gate gets the second lock: a bearer-opened
//!   stream is dropped when that token is revoked, which is the
//!   `api_token_id` threading from the handler into
//!   [`fuz_realtime::SseSubscription`] end to end.
//!
//! - a stream on a widened gate ends when its API token **expires** — the
//!   token × SSE credential deadline, carried from the resolve into
//!   [`fuz_realtime::SseSubscription::credential_deadline`].
//!
//! - **a revocation whose audit write fails still closes the stream**: REST
//!   `/logout` and `/password` write their audit row on the pool, fail-open,
//!   so the revocation listener — which fires only on a written row — never
//!   sees a failed one. With the audit INSERT refused by a `CHECK`, the
//!   stream must still end, closed by the handler through the consumer's
//!   [`fuz_realtime::RealtimeCloser`]. A WS-only closer leaves it open for
//!   its lifetime.
//!
//! - **a login past the session cap closes the evicted session's
//!   connections**: the cap deletes the oldest session row, and the login
//!   handler closes that session's SSE stream and WS socket through the same
//!   closer — no audit row is involved (`login` revokes nothing), so the
//!   close is the handler's alone. The newer sessions' connections stay open.
//!
//! - **the auth cleanup sweep closes the connections of the sessions it
//!   deletes**: a session that expires under an open stream and socket is
//!   refused everywhere, but neither connection reads it again, and once
//!   `fuz_auth::run_auth_cleanup` deletes the row `account_session_revoke`
//!   has nothing to close for. The sweep closes them itself, through the same
//!   closer — the stream ends and the socket gets the revocation close —
//!   while another session of the same account keeps both of its own.
//!
//! - **a revocation racing the request opens no stream**: the route runs its
//!   gates, registers the stream pending, re-reads the credential, the acting
//!   actor, and the role, and only then admits it. A request held at its
//!   gates (a lock on `role_grant`, which the role gate reads first) is
//!   refused 401 when its session row is gone by the time it resumes — under
//!   a real `/logout` too; one held at its re-read (then a lock on
//!   `auth_session`) is refused 401 when its acting actor was deleted, 403
//!   when its role was, and ends right after its connect comment when a close
//!   found the pending registration. A re-read that errors answers 500 and
//!   opens nothing.
//!
//! - **the server's shutdown racing the request opens no stream and answers
//!   no 500 of its own**: the gates answer their refusals as they always do,
//!   a request registering after the close-all skips its re-read and is
//!   answered with the connect comment, and a re-read that fails once the
//!   close-all reached the pending registration answers the same — while the
//!   same failure on a live registration, or one a revocation closed, stays a
//!   500.
//!
//! The transport-independent dispatch coverage (every `RevocationScope`, the
//! `success`-only rule, the `role_grant_revoke` role match)
//! is in `tests/sse_revocation.rs` and `fuz_auth`'s
//! `tests/revocation_guard.rs`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_realtime_test
//! cargo test -p fuz_realtime --test audit_stream -- --ignored --test-threads=1
//! ```
//!
//! Override the DB URL with `FUZ_REALTIME_TEST_URL=postgres://...`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderName, Request, StatusCode, header};
use axum::response::Response;
use futures::StreamExt;
use fuz_auth::ConnectionCloseTarget;
use fuz_auth::{
    AUTH_MIGRATIONS, AccountRouteState, AuditEmitter, AuditLogEvent, AuthCleanupOptions,
    AuthCleanupResult, ConnectionCloser, CredentialGate, Keyring, PasswordHasher, ROLE_ADMIN,
    SESSION_COOKIE_NAME, TokenScopeDocument, account_router, register_revocation_guard,
    run_auth_cleanup,
};
use fuz_db::Pool;
use fuz_http::ShutdownCloser;
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::{
    AuditStreamRouteState, ConnectionRegistry, RealtimeCloser, SSE_CONNECTED_COMMENT, SseRegistry,
    audit_stream_router, register_audit_sse_listener,
};
use fuz_testing::{
    TestingArgon2idHasher, TestingDbOptions, TestingTableLock, fresh_test_db_pool, grant_role,
    grant_scoped_role, mint_api_token, mint_session_cookie, narrowed_scope, refuse_audit_rows,
    seed_account_actor, seed_extra_actor, testing_keyring,
};
use serde_json::json;
use tower::ServiceExt; // for `oneshot`
use uuid::Uuid;

const STREAM_PATH: &str = "/api/admin/audit/stream";

/// This suite's database: `FUZ_REALTIME_TEST_URL` (default
/// `fuz_realtime_test`). The route resolves credentials and role grants, so it
/// needs the auth chain and nothing else.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_REALTIME_TEST_URL",
    default_db: "fuz_realtime_test",
    migrations: &[AUTH_MIGRATIONS],
    setup_sql: None,
};

async fn fresh_db_pool() -> Pool {
    fresh_test_db_pool(DB).await
}

fn keyring() -> Arc<Keyring> {
    Arc::new(testing_keyring())
}

/// Route state as a consumer mounts it: spine defaults, plus the shared SSE
/// registry. `credential_gate` comes from `new` — session-only.
fn state(pool: Pool, keyring: Arc<Keyring>, registry: &Arc<SseRegistry>) -> AuditStreamRouteState {
    AuditStreamRouteState::new(gate(pool, keyring), Arc::clone(registry))
}

/// The suite's gate: the fixture allowlist ([`ORIGIN`] alone) over `pool`,
/// resolving under `keyring`.
fn gate(pool: Pool, keyring: Arc<Keyring>) -> fuz_auth::AuthGate {
    fuz_auth::AuthGate {
        keyring,
        allowed_origins: fuz_http::AllowedOrigins::parse(ORIGIN).expect("valid allowlist"),
        ..fuz_testing::testing_auth_gate(pool)
    }
}

/// GET the stream path with an explicit header list. No `Origin`/`Referer` on
/// any case here — the bearer leg refuses a browser-context request outright,
/// which would make a bearer case pass for the wrong reason.
async fn get_stream(router: Router, headers: &[(HeaderName, String)]) -> Response {
    get_stream_at(router, STREAM_PATH, headers).await
}

/// [`get_stream`] with the URI spelled out — the query-string cases.
async fn get_stream_at(router: Router, uri: &str, headers: &[(HeaderName, String)]) -> Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    router
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// How long a close is allowed to take before the test calls it "never". The
/// listener runs synchronously inside `notify`, so a passing case never spends
/// this; it is here so a broken listener fails the suite instead of hanging it.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Drain a response body to completion, asserting it actually completes — the
/// only thing a stream client observes when the server drops its sender.
async fn assert_body_ends(mut body: axum::body::BodyDataStream, what: &str) {
    let drained = async { while body.next().await.is_some() {} };
    assert!(
        tokio::time::timeout(CLOSE_TIMEOUT, drained).await.is_ok(),
        "{what}: the stream was never closed"
    );
}

async fn body_json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// A seeded admin account plus a session cookie for it.
struct AdminFixture {
    cookie: String,
    account_id: Uuid,
    /// The account's single actor — the one holding [`ROLE_ADMIN`]. The
    /// multi-actor cases below seed a second actor beside it.
    actor_id: Uuid,
}

async fn seed_admin(pool: &Pool, keyring: &Keyring, username: &str) -> AdminFixture {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    grant_role(pool, actor_id, ROLE_ADMIN).await;
    let cookie = mint_session_cookie(pool, keyring, account_id, SESSION_COOKIE_NAME).await;
    AdminFixture {
        cookie,
        account_id,
        actor_id,
    }
}

/// The query shape is checked **before** auth, so a malformed query answers
/// the same on every backend whatever the caller holds — the TS pipeline's
/// phase order (params → query → 401/403), and the reason this case sends no
/// credentials at all.
///
/// `?acting=` is the only key the twin's `AuditStreamQuery`
/// (`object({acting})`) declares; the strict object 400s an
/// undeclared one, and before this route read its query at all it answered
/// `200` to `?foo=bar` — a shape divergence with no test that could see it.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn an_unknown_query_key_is_refused_before_auth() {
    let pool = fresh_db_pool().await;
    let registry = Arc::new(SseRegistry::new());
    let router = audit_stream_router(state(pool, keyring(), &registry));

    let response = get_stream_at(router, &format!("{STREAM_PATH}?foo=bar"), &[]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_query_params");
}

/// A present-but-malformed selector is a client error, not a silently ignored
/// one — the disposition `parse_acting_query` carries across every REST family
/// that resolves an actor.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_malformed_acting_selector_is_refused() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_malformed_acting").await;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream_at(
        router,
        &format!("{STREAM_PATH}?acting=not-a-uuid"),
        &[(header::COOKIE, admin.cookie)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_query_params");
}

/// A multi-actor account must **pick** — 400 with the available list, never a
/// silent choice and never a 403.
///
/// A 403 would be the visible symptom of a deeper divergence: a route that
/// ignores its query string entirely, leaving the twin's documented
/// "multi-actor admins pass `?acting=<uuid>`" with no implementation here.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_multi_actor_account_must_pick_an_acting_actor() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_multi_pick").await;
    seed_extra_actor(&pool, admin.account_id, "second_persona").await;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream(router, &[(header::COOKIE, admin.cookie)]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"], "actor_required");
    assert_eq!(
        body["available"].as_array().map(Vec::len),
        Some(2),
        "the denial carries the list the client prompts from"
    );
}

/// …and picking opens the stream. The half that makes the case above a
/// *routing* result rather than a route that refuses multi-actor outright.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_multi_actor_admin_opens_the_stream_by_picking_its_actor() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_multi_picks").await;
    seed_extra_actor(&pool, admin.account_id, "second_persona").await;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream_at(
        router,
        &format!("{STREAM_PATH}?acting={}", admin.actor_id),
        &[(header::COOKIE, admin.cookie)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(registry.count(), 1);
}

/// **The role read follows the picked actor, not the account.** The second
/// persona holds no grant, so naming it is a 403 even though a sibling actor
/// on the same account is an admin.
///
/// This is the spine's privilege-confusion rule, and the property that
/// separates this route from `fuz_db_admin`'s deliberately account-grain gate
/// — a caller cannot borrow a sibling's role by acting as itself.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn acting_as_a_persona_without_the_role_is_refused() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_sibling").await;
    let plain = seed_extra_actor(&pool, admin.account_id, "no_grant_persona").await;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream_at(
        router,
        &format!("{STREAM_PATH}?acting={plain}"),
        &[(header::COOKIE, admin.cookie)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await["error"],
        "insufficient_permissions"
    );
    assert_eq!(registry.count(), 0);
}

/// An actor on someone else's account is an **opaque** 400 — the available
/// list is deliberately not echoed, so a guessed id learns nothing about the
/// account it named.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_foreign_acting_actor_is_refused_opaquely() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_foreign").await;
    let (_, stranger_actor) = seed_account_actor(&pool, "stranger").await;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream_at(
        router,
        &format!("{STREAM_PATH}?acting={stranger_actor}"),
        &[(header::COOKIE, admin.cookie)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"], "actor_not_on_account");
    assert!(
        body.get("available").is_none(),
        "a foreign selector must not be told what the account holds"
    );
}

/// **The regression guard.** A cookie session on an admin account still opens
/// the stream — without this every refusal below would pass on a route that
/// simply stopped working.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_cookie_session_on_an_admin_account_opens_the_stream() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_opens").await;

    let router = audit_stream_router(state(pool, Arc::clone(&keyring), &registry));
    let response = get_stream(router, &[(header::COOKIE, admin.cookie)]).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    let mut body = response.into_body().into_data_stream();
    let first = body.next().await.unwrap().unwrap();
    assert_eq!(
        std::str::from_utf8(&first).unwrap(),
        SSE_CONNECTED_COMMENT,
        "the stream opens with the connect comment"
    );
    assert_eq!(registry.count(), 1, "the stream registered as a subscriber");
}

/// The role gate reads the **global** grant: a scoped `admin` row (legacy
/// data — no grant path mints one) doesn't open the instance-wide stream.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_scoped_admin_is_refused() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let (account_id, actor_id) = seed_account_actor(&pool, "scoped_admin").await;
    grant_scoped_role(&pool, actor_id, ROLE_ADMIN, "space", Uuid::new_v4()).await;
    let cookie = mint_session_cookie(&pool, &keyring, account_id, SESSION_COOKIE_NAME).await;

    let router = audit_stream_router(state(pool, Arc::clone(&keyring), &registry));
    let response = get_stream(router, &[(header::COOKIE, cookie)]).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(registry.count(), 0, "no subscriber registered");
}

/// **The gap.** A full-scope bearer on the *same admin account* that opens the
/// stream above is refused — the case the scope gate could not catch and the
/// role gate had no reason to.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_full_scope_bearer_is_refused_at_the_credential_gate() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_bearer").await;
    let token = mint_api_token(&pool, admin.account_id, &TokenScopeDocument::full())
        .await
        .token;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream(
        router,
        &[(header::AUTHORIZATION, format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await,
        json!({
            "error": "credential_type_required",
            "required_credential_types": ["session"],
        }),
    );
    assert_eq!(registry.count(), 0, "no stream opened");
}

/// The gate is checked **before** the scope gate: a narrowed bearer hears
/// `credential_type_required`, not `token_scope_required`. A refused channel
/// must not be told about the deployment's token scoping — the same
/// coarse-to-fine ordering `fuz_db_admin::require_role` runs.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn the_credential_gate_precedes_the_scope_gate() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_narrowed").await;
    let token = mint_api_token(
        &pool,
        admin.account_id,
        &narrowed_scope(&["account_verify"]),
    )
    .await
    .token;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream(
        router,
        &[(header::AUTHORIZATION, format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(
        body["error"], "credential_type_required",
        "the channel gate answers first: {body}"
    );
}

/// ...and before the role gate too: a bearer on an account with no role hears
/// about its channel, not about the deployment's role structure.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn the_credential_gate_precedes_the_role_gate() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let (account_id, _) = seed_account_actor(&pool, "no_role_bearer").await;
    let token = mint_api_token(&pool, account_id, &TokenScopeDocument::full())
        .await
        .token;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream(
        router,
        &[(header::AUTHORIZATION, format!("Bearer {token}"))],
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await["error"],
        "credential_type_required"
    );
}

/// The role gate still runs for the channel the gate admits — the gate
/// narrowed the door, it did not replace the lock.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_session_without_the_role_is_still_refused_on_role_grounds() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let (account_id, _) = seed_account_actor(&pool, "no_role_session").await;
    let cookie = mint_session_cookie(&pool, &keyring, account_id, SESSION_COOKIE_NAME).await;

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream(router, &[(header::COOKIE, cookie)]).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await,
        json!({"error": "insufficient_permissions", "required_roles": [ROLE_ADMIN]}),
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn an_unauthenticated_request_is_refused_before_anything_else() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream(router, &[]).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A credential read that fails is not an unauthenticated request: the
/// session lookup fails (`auth_session` renamed away) under a real admin
/// cookie, and the stream answers the fault's plain-text 500 — the TS twin's,
/// where the read throws out of the auth middleware — not the 401.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_failed_credential_read_answers_the_500() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_read_fails").await;
    pool.get()
        .await
        .unwrap()
        .batch_execute("ALTER TABLE auth_session RENAME TO auth_session_gone")
        .await
        .unwrap();

    let router = audit_stream_router(state(pool, keyring, &registry));
    let response = get_stream(router, &[(header::COOKIE, admin.cookie)]).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; charset=UTF-8")
    );
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"Internal Server Error");
    assert_eq!(registry.count(), 0, "no stream opened");
}

/// The credential resolves on the request's first checkout and the route's
/// own checkout after it is refused: the flat 503, not the 500 of a failed
/// read, and no stream opened.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_failed_route_checkout_answers_the_503() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let admin = seed_admin(&pool, &keyring, "admin_checkout_fails").await;

    let budgeted = fuz_testing::budgeted_pool(&DB.url(), 1);
    let router = audit_stream_router(state(budgeted, keyring, &registry));
    let response = get_stream(router, &[(header::COOKIE, admin.cookie)]).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(&bytes[..], br#"{"error":"service_unavailable"}"#);
    assert_eq!(registry.count(), 0, "no stream opened");
}

/// **The second lock.** A consumer that widens `credential_gate` to admit
/// bearers gets a stream that `token_revoke` can actually close — which is
/// what the handler's `api_token_id` threading buys, and the thing that was
/// missing when the route admitted bearers by default.
///
/// End-to-end: mount with `CredentialGate::Any`, open a stream with a
/// full-scope bearer, fan a real `token_revoke` row through the registered
/// listener, and watch the response body end.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_bearer_stream_on_a_widened_gate_closes_on_token_revoke() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());
    let emitter = Arc::new(AuditEmitter::new(pool.clone()));
    register_audit_sse_listener(&emitter, &registry);
    let closer: Arc<dyn ConnectionCloser> = Arc::<SseRegistry>::clone(&registry);
    register_revocation_guard(&emitter, &closer);

    let admin = seed_admin(&pool, &keyring, "admin_widened").await;
    let minted = mint_api_token(&pool, admin.account_id, &TokenScopeDocument::full()).await;

    let mut widened = state(pool, keyring, &registry);
    widened.credential_gate = CredentialGate::Any;
    let router = audit_stream_router(widened);

    let response = get_stream(
        router,
        &[(header::AUTHORIZATION, format!("Bearer {}", minted.token))],
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a widened gate admits the bearer"
    );
    let mut body = response.into_body().into_data_stream();
    assert!(body.next().await.is_some(), "connect comment");
    assert_eq!(registry.count(), 1);

    // The row `account_token_revoke` emits, delivered through the real
    // listener chain rather than by closing the token directly — so
    // this fails if the handler stopped threading `api_token_id`, if the
    // listener stopped dispatching `token_revoke`, or if the spec row lost
    // its `RevocationScope::Token`.
    emitter
        .notify(Arc::new(AuditLogEvent {
            id: Uuid::new_v4(),
            seq: 1,
            event_type: "token_revoke".to_owned(),
            outcome: "success".to_owned(),
            actor_id: None,
            account_id: Some(admin.account_id),
            target_account_id: None,
            target_actor_id: None,
            ip: None,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            metadata: Some(json!({"token_id": minted.id})),
        }))
        .await;

    assert_body_ends(body, "token_revoke").await;
    assert_eq!(
        registry.count(),
        0,
        "the revoked token's stream must be closed"
    );
}

/// A bearer-opened stream on a widened gate ends when its API token expires
/// — the token × SSE credential deadline, which the cross-backend suite
/// cannot reach (the stock stream admits sessions only). The token's expiry
/// is pulled in to seconds before the open; the stream runs until then, and
/// its body ends with no revocation row written.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_bearer_stream_on_a_widened_gate_ends_when_its_token_expires() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let registry = Arc::new(SseRegistry::new());

    let admin = seed_admin(&pool, &keyring, "admin_expiring").await;
    let minted = mint_api_token(&pool, admin.account_id, &TokenScopeDocument::full()).await;
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE api_token SET expires_at = NOW() + INTERVAL '2 seconds' WHERE id = $1",
            &[&minted.id],
        )
        .await
        .unwrap();

    let mut widened = state(pool, keyring, &registry);
    widened.credential_gate = CredentialGate::Any;
    let opened = std::time::Instant::now();
    let response = get_stream(
        audit_stream_router(widened),
        &[(header::AUTHORIZATION, format!("Bearer {}", minted.token))],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    assert!(body.next().await.is_some(), "connect comment");
    assert_eq!(registry.count(), 1);

    assert_body_ends(body, "token expiry").await;
    let elapsed = opened.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1500),
        "the stream ended before its token expired: {elapsed:?}"
    );
    assert_eq!(registry.count(), 0, "the expired token's stream is gone");
}

// -- A failed audit write must not keep a revoked stream open ---------------

/// The browser origin the REST cases send, and the one allowlist entry.
const ORIGIN: &str = "http://localhost:5173";

/// The seeded admin's password for the `/password` case.
const CURRENT_PASSWORD: &str = "current-password-0123";

async fn audit_row_count(pool: &Pool, event_type: &str) -> i64 {
    pool.get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_log WHERE event_type = $1",
            &[&event_type],
        )
        .await
        .unwrap()
        .get(0)
}

/// A consumer's assembly of the two surfaces under test: the audit stream
/// route and the account REST router, sharing one emitter with both audit
/// listeners on it, and the account handlers closing through the fan-out
/// closer over the same WS and SSE registries.
struct RevocationHarness {
    pool: Pool,
    registry: Arc<SseRegistry>,
    ws: Arc<ConnectionRegistry>,
    /// The emitter and the fan-out closer the account handlers hold — what a
    /// consumer also hands its auth cleanup.
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
    stream_router: Router,
    account_router: Router,
}

fn revocation_harness(pool: Pool, keyring: &Arc<Keyring>) -> RevocationHarness {
    let registry = Arc::new(SseRegistry::new());
    let ws = Arc::new(ConnectionRegistry::new());
    let connection_closer = RealtimeCloser::connection_closer(&ws, &registry);
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    register_audit_sse_listener(&audit, &registry);
    register_revocation_guard(&audit, &connection_closer);

    let account_state = AccountRouteState {
        gate: gate(pool.clone(), Arc::clone(keyring)),
        password_hasher: Arc::new(TestingArgon2idHasher::new()),
        audit: Arc::clone(&audit),
        connection_closer: Arc::clone(&connection_closer),
        bootstrap_available: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        login_ip_rate_limiter: None,
        login_account_rate_limiter: None,
        // no revocation case asserts the denial floor
        login_fail_floor_ms: 0,
        login_fail_jitter_ms: 0,
    };
    RevocationHarness {
        stream_router: audit_stream_router(state(pool.clone(), Arc::clone(keyring), &registry)),
        account_router: account_router(account_state),
        pool,
        registry,
        ws,
        audit,
        connection_closer,
    }
}

/// Open the audit stream under `cookie` and read past the connect comment.
async fn open_stream(h: &RevocationHarness, cookie: &str) -> axum::body::BodyDataStream {
    let response = get_stream(
        h.stream_router.clone(),
        &[
            (header::COOKIE, cookie.to_owned()),
            (header::ORIGIN, ORIGIN.to_owned()),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    assert!(body.next().await.is_some(), "connect comment");
    assert_eq!(h.registry.count(), 1);
    body
}

/// POST `body` to the account router at `path` as a browser would.
async fn post_account(h: &RevocationHarness, path: &str, cookie: &str, body: Body) -> Response {
    h.account_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::COOKIE, cookie)
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap()
}

/// **`/logout` with a failing audit write still closes the stream.**
///
/// The handler awaits its pool-routed audit write, so by the response the
/// INSERT has been refused and the revocation listener has had its only
/// chance — and had nothing to react to. The stream ending is the handler's own close.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn logout_closes_the_stream_when_its_audit_write_fails() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_logout_refused").await;
    let h = revocation_harness(pool, &keyring);
    let body = open_stream(&h, &admin.cookie).await;
    refuse_audit_rows(&h.pool, &["logout"]).await;

    let response = post_account(&h, "/logout", &admin.cookie, Body::empty()).await;
    assert_eq!(response.status(), StatusCode::OK, "logout is fail-open");
    assert_eq!(
        audit_row_count(&h.pool, "logout").await,
        0,
        "the audit write was refused, so no listener saw a row"
    );

    assert_body_ends(body, "logout with a refused audit write").await;
    assert_eq!(h.registry.count(), 0);
}

/// **`/password` with a failing audit write still closes the stream** — the
/// same contract on the other pool-routed revocation, which also deletes every
/// session and token on the account.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn password_change_closes_the_stream_when_its_audit_write_fails() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_password_refused").await;
    set_current_password(&pool, admin.account_id).await;
    let h = revocation_harness(pool, &keyring);
    let body = open_stream(&h, &admin.cookie).await;
    refuse_audit_rows(&h.pool, &["password_change"]).await;

    let input = json!({
        "current_password": CURRENT_PASSWORD,
        "new_password": "a-new-password-0123",
    });
    let response = post_account(
        &h,
        "/password",
        &admin.cookie,
        Body::from(input.to_string()),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the password change is fail-open"
    );
    assert_eq!(
        audit_row_count(&h.pool, "password_change").await,
        0,
        "the audit write was refused, so no listener saw a row"
    );

    assert_body_ends(body, "password change with a refused audit write").await;
    assert_eq!(h.registry.count(), 0);
}

// -- The session cap closes what it evicts ------------------------------------

/// Set the seeded admin's password to [`CURRENT_PASSWORD`] (a real Argon2
/// hash, since the harness verifies with the testing hasher).
async fn set_current_password(pool: &Pool, account_id: Uuid) {
    let hash = TestingArgon2idHasher::new()
        .hash(CURRENT_PASSWORD.to_owned())
        .await
        .unwrap();
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE account SET password_hash = $1 WHERE id = $2",
            &[&hash.as_str(), &account_id],
        )
        .await
        .unwrap();
}

/// POST `/login` as a browser would and return the new session's `Cookie`
/// header value.
async fn login(h: &RevocationHarness, username: &str) -> String {
    let body = json!({"username": username, "password": CURRENT_PASSWORD});
    let response = h
        .account_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "login");
    let set_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    set_cookie.split(';').next().unwrap().to_owned()
}

/// The account's session hashes, oldest first.
async fn session_hashes(pool: &Pool, account_id: Uuid) -> Vec<String> {
    pool.get()
        .await
        .unwrap()
        .query(
            "SELECT id FROM auth_session WHERE account_id = $1 ORDER BY created_at ASC",
            &[&account_id],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

/// Register a WS connection for `session_hash` the way the upgrade does, and
/// return it — its `signal` is what a revocation cancels.
fn add_ws(h: &RevocationHarness, account_id: Uuid, session_hash: &str) -> fuz_realtime::Connection {
    let (tx, _rx) = fuz_realtime::connection_channel(1 << 20);
    h.ws.add_connection(
        tx,
        ConnectionIdentity {
            session_hash: Some(session_hash.to_owned()),
            account_id: Some(account_id),
            ..ConnectionIdentity::default()
        },
        tokio_util::sync::CancellationToken::new(),
    )
}

/// **A login that evicts the oldest session closes that session's
/// connections.** The cap deletes the row, but a stream is authorized once at
/// open and a WS socket keeps its upgrade-time authority, so only a close ends
/// them. `login` carries no revocation scope, so neither audit listener reacts
/// to it — the stream ending is the login handler's own close. The newest
/// session's stream and socket stay open: the close names the evicted session,
/// not the account.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_login_past_the_session_cap_closes_the_evicted_sessions_connections() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_capped").await;
    set_current_password(&pool, admin.account_id).await;
    let h = revocation_harness(pool, &keyring);

    // The seeded session is the oldest; fill the cap behind it.
    let cap = usize::try_from(fuz_auth::DEFAULT_MAX_SESSIONS).unwrap();
    let mut newest_cookie = String::new();
    for _ in 1..cap {
        newest_cookie = login(&h, "admin_capped").await;
    }
    let hashes = session_hashes(&h.pool, admin.account_id).await;
    assert_eq!(hashes.len(), cap, "at the cap, nothing evicted yet");
    let (oldest, newest) = (&hashes[0], &hashes[cap - 1]);

    let oldest_stream = open_stream(&h, &admin.cookie).await;
    let response = get_stream(
        h.stream_router.clone(),
        &[
            (header::COOKIE, newest_cookie),
            (header::ORIGIN, ORIGIN.to_owned()),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut newest_stream = response.into_body().into_data_stream();
    assert!(newest_stream.next().await.is_some(), "connect comment");
    assert_eq!(h.registry.count(), 2);
    let oldest_ws = add_ws(&h, admin.account_id, oldest);
    let newest_ws = add_ws(&h, admin.account_id, newest);

    // One login past the cap evicts the oldest session.
    login(&h, "admin_capped").await;
    let hashes = session_hashes(&h.pool, admin.account_id).await;
    assert_eq!(hashes.len(), cap);
    assert!(!hashes.contains(oldest), "the oldest session was evicted");

    assert_body_ends(oldest_stream, "the evicted session's stream").await;
    assert!(
        oldest_ws.signal.is_cancelled(),
        "the evicted session's WS socket must be closed"
    );
    assert_eq!(h.registry.count(), 1, "the newest session's stream stays");
    assert!(
        !newest_ws.signal.is_cancelled(),
        "the newest session's WS socket stays"
    );
    let frame = tokio::time::timeout(CLOSE_TIMEOUT, newest_stream.next())
        .await
        .expect("the surviving stream receives the evicting login's audit row")
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&frame).contains(r#""event_type":"login""#),
        "the surviving stream is still live: {frame:?}"
    );
}

/// **The auth cleanup sweep closes the connections of the sessions it
/// deletes.** A session expiring under an open stream and socket ends
/// neither — a stream is authorized once at open, a WS socket re-authorizes
/// the actor per message and never the session — and the sweep then deletes
/// the row, which was the only per-session handle on them
/// (`account_session_revoke` closes for a row it deletes). So the sweep closes
/// them, through the closer the consumer's revocation handlers hold: the
/// stream ends and the socket is closed as a revocation closes it. The
/// account's other session keeps its stream and socket: the close names the
/// swept session, not the account. No audit row is written, so neither audit
/// listener is involved.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn the_auth_cleanup_sweep_closes_an_expired_sessions_connections() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_expiring").await;
    set_current_password(&pool, admin.account_id).await;
    let h = revocation_harness(pool, &keyring);

    // A second session on the same account, opened after the seeded one.
    let live_cookie = login(&h, "admin_expiring").await;
    let hashes = session_hashes(&h.pool, admin.account_id).await;
    assert_eq!(hashes.len(), 2);
    let (expiring, live) = (&hashes[0], &hashes[1]);

    let expiring_stream = open_stream(&h, &admin.cookie).await;
    let response = get_stream(
        h.stream_router.clone(),
        &[
            (header::COOKIE, live_cookie),
            (header::ORIGIN, ORIGIN.to_owned()),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut live_stream = response.into_body().into_data_stream();
    assert!(live_stream.next().await.is_some(), "connect comment");
    let expiring_ws = add_ws(&h, admin.account_id, expiring);
    let live_ws = add_ws(&h, admin.account_id, live);

    // The first session expires under its open connections. Expiry alone
    // ends nothing: nothing rereads the row.
    h.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE auth_session SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
            &[expiring],
        )
        .await
        .unwrap();
    assert_eq!(h.registry.count(), 2);
    assert!(h.ws.is_registered(expiring_ws.id));

    let options = AuthCleanupOptions {
        pool: h.pool.clone(),
        audit: Arc::clone(&h.audit),
        connection_closer: Arc::clone(&h.connection_closer),
    };
    assert_eq!(
        run_auth_cleanup(&options).await.unwrap(),
        AuthCleanupResult {
            expired_sessions: 1,
            expired_offers: 0,
        }
    );
    assert_eq!(
        session_hashes(&h.pool, admin.account_id).await,
        std::slice::from_ref(live),
        "the sweep deleted the expired session's row"
    );

    assert_body_ends(expiring_stream, "the swept session's stream").await;
    assert!(
        expiring_ws.signal.is_cancelled(),
        "the swept session's WS socket must be closed"
    );
    assert!(!h.ws.is_registered(expiring_ws.id));
    assert_eq!(
        expiring_ws.close_reason.get(),
        None,
        "closed as a revocation is (4001), not as a superseded socket"
    );

    assert_eq!(h.registry.count(), 1, "the live session's stream stays");
    assert!(
        !live_ws.signal.is_cancelled(),
        "the live session's WS socket stays"
    );
    assert!(h.ws.is_registered(live_ws.id));
    assert_eq!(h.registry.broadcast("data: kept\n\n"), 1);
    let frame = tokio::time::timeout(CLOSE_TIMEOUT, live_stream.next())
        .await
        .expect("the surviving stream still receives the fan-out")
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&frame).contains("kept"),
        "the surviving stream is still live: {frame:?}"
    );

    // A second pass has nothing to sweep and closes nothing more.
    assert_eq!(
        run_auth_cleanup(&options).await.unwrap(),
        AuthCleanupResult::default()
    );
    assert_eq!(h.registry.count(), 1);
    assert!(h.ws.is_registered(live_ws.id));
}

// -- A revocation racing the request must not open a stream ------------------

/// A stream request stalled at one read: [`stall_at_the_gate`] or
/// [`stall_at_the_re_read`].
struct StalledRequest {
    /// Holds the handler at its read of the locked table until released.
    lock: TestingTableLock,
    response: tokio::task::JoinHandle<Response>,
}

impl StalledRequest {
    /// Let the handler resume, and take its response.
    async fn resume(self) -> Response {
        self.lock.release().await;
        tokio::time::timeout(CLOSE_TIMEOUT, self.response)
            .await
            .expect("the released request completes")
            .expect("the handler task does not panic")
    }
}

/// Start a stream request under `cookie` and hold it at the role gate — past
/// the credential resolution and the acting-actor read, before the stream is
/// registered. `role_grant` is read by the role gate first, so the lock
/// stalls exactly there. A revocation made here has committed before the
/// registration, so its close finds nothing: only the re-read can refuse it.
async fn stall_at_the_gate(h: &RevocationHarness, cookie: &str) -> StalledRequest {
    let lock = TestingTableLock::acquire(&h.pool, "role_grant").await;
    let router = h.stream_router.clone();
    let headers = [
        (header::COOKIE, cookie.to_owned()),
        (header::ORIGIN, ORIGIN.to_owned()),
    ];
    let response = tokio::spawn(async move { get_stream(router, &headers).await });
    lock.wait_for_waiter().await;
    assert_eq!(
        h.registry.pending_count(),
        0,
        "the stream is not registered before its gates pass"
    );
    StalledRequest { lock, response }
}

/// Start a stream request under `cookie` and hold it at the re-read — its
/// gates passed and its stream registered pending, nothing after that run.
/// Held at the role gate first ([`stall_at_the_gate`]), then `auth_session`
/// is locked and the gate let go: the re-read's credential read is the
/// request's next read of `auth_session`.
async fn stall_at_the_re_read(h: &RevocationHarness, cookie: &str) -> StalledRequest {
    let at_the_gate = stall_at_the_gate(h, cookie).await;
    let lock = TestingTableLock::acquire(&h.pool, "auth_session").await;
    at_the_gate.lock.release().await;
    lock.wait_for_waiter().await;
    assert_eq!(
        h.registry.pending_count(),
        1,
        "the stream is registered pending before the re-read"
    );
    assert_eq!(h.registry.count(), 0, "and is not open yet");
    StalledRequest {
        lock,
        response: at_the_gate.response,
    }
}

/// **The control.** A stalled request no revocation touches still opens its
/// stream — so the refusals below are the revocation's doing, not the stall's.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_stalled_request_with_no_revocation_opens_the_stream() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_stall_control").await;
    let h = revocation_harness(pool, &keyring);

    let stalled = stall_at_the_re_read(&h, &admin.cookie).await;
    let response = stalled.resume().await;

    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    assert!(body.next().await.is_some(), "connect comment");
    assert_eq!(h.registry.count(), 1, "admitted");
    assert_eq!(h.registry.pending_count(), 0);
}

/// **The re-read, alone.** The session row is deleted while the request is
/// held at its gates, and *no* close is delivered — the shape of a revocation
/// whose close ran before the stream registered and so found nothing. Only
/// the credential re-read can refuse it: 401, and no stream opens.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_session_revoked_during_the_request_opens_no_stream() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_revoked_mid_request").await;
    let h = revocation_harness(pool, &keyring);

    let stalled = stall_at_the_gate(&h, &admin.cookie).await;
    h.pool
        .get()
        .await
        .unwrap()
        .execute(
            "DELETE FROM auth_session WHERE account_id = $1",
            &[&admin.account_id],
        )
        .await
        .unwrap();
    let response = stalled.resume().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await["error"],
        "authentication_required"
    );
    assert_eq!(
        h.registry.count(),
        0,
        "no stream opened on the dead session"
    );
    assert_eq!(h.registry.pending_count(), 0, "the registration is removed");
}

/// **The acting actor, at the re-read.** The actor the gates resolved is
/// soft-deleted while the request is held at its re-read: its account's
/// session and its own grant rows are still there, so only the actor re-read
/// refuses it — 401, as the twin answers, and no stream opens.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn an_actor_deleted_during_the_request_opens_no_stream() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_actor_deleted_mid_request").await;
    let h = revocation_harness(pool, &keyring);

    let stalled = stall_at_the_re_read(&h, &admin.cookie).await;
    h.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE actor SET deleted_at = NOW() WHERE id = $1",
            &[&admin.actor_id],
        )
        .await
        .unwrap();
    let response = stalled.resume().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await["error"],
        "authentication_required"
    );
    assert_eq!(
        h.registry.count(),
        0,
        "no stream opened for the deleted actor"
    );
    assert_eq!(h.registry.pending_count(), 0, "the registration is removed");
}

/// **The role, at the re-read.** The actor's admin grant is deleted while the
/// request is held at its re-read — no close delivered — so only the role
/// re-read refuses it: 403 naming the role, and no stream opens.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_role_lost_during_the_request_opens_no_stream() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_role_lost_mid_request").await;
    let h = revocation_harness(pool, &keyring);

    let stalled = stall_at_the_re_read(&h, &admin.cookie).await;
    h.pool
        .get()
        .await
        .unwrap()
        .execute(
            "DELETE FROM role_grant WHERE actor_id = $1",
            &[&admin.actor_id],
        )
        .await
        .unwrap();
    let response = stalled.resume().await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await,
        json!({"error": "insufficient_permissions", "required_roles": [ROLE_ADMIN]}),
    );
    assert_eq!(h.registry.count(), 0);
    assert_eq!(h.registry.pending_count(), 0);
}

/// **The pending registration, alone.** A close reaches the stalled request's
/// registration while its session row is still there — an account-wide close
/// from another session's logout does exactly this. The re-read passes, so
/// only admission can refuse: the response is a stream that ends right after
/// its connect comment, and nothing stays registered.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_stream_closed_while_pending_ends_after_its_connect_comment() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_closed_pending").await;
    let h = revocation_harness(pool, &keyring);

    let stalled = stall_at_the_re_read(&h, &admin.cookie).await;
    assert_eq!(
        h.registry
            .close_connections(&ConnectionCloseTarget::Account(admin.account_id)),
        1,
        "the close finds the pending registration"
    );
    let response = stalled.resume().await;

    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    let first = body.next().await.unwrap().unwrap();
    assert_eq!(std::str::from_utf8(&first).unwrap(), SSE_CONNECTED_COMMENT);
    assert_body_ends(body, "a stream closed while pending").await;
    assert_eq!(h.registry.count(), 0, "never admitted");
    assert_eq!(h.registry.pending_count(), 0);
}

/// **Fail closed.** The re-read itself errors — `auth_session` is renamed out
/// from under it while the request is held at its gates (the next case's
/// fresh schema restores it). A credential that could not be re-checked is
/// not a valid one: 500, and no stream opens.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_failing_recheck_opens_no_stream() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_recheck_fails").await;
    let h = revocation_harness(pool, &keyring);

    let stalled = stall_at_the_gate(&h, &admin.cookie).await;
    h.pool
        .get()
        .await
        .unwrap()
        .batch_execute("ALTER TABLE auth_session RENAME TO auth_session_gone")
        .await
        .unwrap();
    let response = stalled.resume().await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.registry.count(), 0, "no stream opened unchecked");
    assert_eq!(h.registry.pending_count(), 0, "the registration is removed");
}

/// **A real revocation.** `/logout` lands while the request is held at its
/// gates: it deletes the session and closes the account's connections
/// through the consumer's closer — finding nothing registered yet. The
/// re-read then refuses: 401, and the stream never opens.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_logout_during_the_request_opens_no_stream() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_logout_mid_request").await;
    let h = revocation_harness(pool, &keyring);

    let stalled = stall_at_the_gate(&h, &admin.cookie).await;
    let logout = post_account(&h, "/logout", &admin.cookie, Body::empty()).await;
    assert_eq!(logout.status(), StatusCode::OK);
    let response = stalled.resume().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(h.registry.count(), 0);
    assert_eq!(h.registry.pending_count(), 0);
}

// -- The server's shutdown racing the request --------------------------------

/// Read a closed-stream answer: a `200` whose body is the connect comment
/// alone, ending at once — to an `EventSource`, a stream closed an instant
/// after it opened.
async fn assert_connect_comment_alone(response: Response, what: &str) {
    assert_eq!(response.status(), StatusCode::OK, "{what}");
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream",
        "{what}"
    );
    let mut body = response.into_body().into_data_stream();
    let first = body.next().await.unwrap().unwrap();
    assert_eq!(std::str::from_utf8(&first).unwrap(), SSE_CONNECTED_COMMENT);
    assert_body_ends(body, what).await;
}

/// **Gates answer during a shutdown.** The gates run before the stream is
/// registered, so a shutdown changes nothing about a refused caller's answer:
/// a session without the role hears its 403, an actor-less account its 500,
/// a multi-actor account that picked none its 400 — not the connect comment
/// a registration the shutdown closed would get. The twin's pipeline answers
/// the same.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn the_gates_answer_their_refusals_during_a_shutdown() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let h = revocation_harness(pool.clone(), &keyring);
    assert_eq!(h.registry.close_all_connections(), 0);
    let router = h.stream_router.clone();
    let get = |cookie: String| {
        let router = router.clone();
        async move {
            get_stream(
                router,
                &[
                    (header::COOKIE, cookie),
                    (header::ORIGIN, ORIGIN.to_owned()),
                ],
            )
            .await
        }
    };

    let (no_role, _) = seed_account_actor(&pool, "no_role_shutdown").await;
    let cookie = mint_session_cookie(&pool, &keyring, no_role, SESSION_COOKIE_NAME).await;
    let response = get(cookie).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(response).await,
        json!({"error": "insufficient_permissions", "required_roles": [ROLE_ADMIN]}),
    );

    let multi = seed_admin(&pool, &keyring, "admin_multi_shutdown").await;
    seed_extra_actor(&pool, multi.account_id, "second_persona_shutdown").await;
    let response = get(multi.cookie).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "actor_required");

    let actorless = seed_admin(&pool, &keyring, "admin_actorless_shutdown").await;
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE actor SET deleted_at = NOW() WHERE id = $1",
            &[&actorless.actor_id],
        )
        .await
        .unwrap();
    let response = get(actorless.cookie).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body_json(response).await["error"], "no_actors_on_account");

    assert_eq!(h.registry.pending_count(), 0, "none was registered");
}

/// **Born closed.** A request whose gates pass after the shutdown's close-all
/// registers born closed and is answered with the connect comment without
/// its re-read: with `auth_session` locked once the request is past its
/// credential read, a handler that went on to the re-read would hang there,
/// so a prompt answer proves it never did. Nothing stays registered.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_request_born_closed_skips_the_re_read() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_born_closed").await;
    let h = revocation_harness(pool, &keyring);

    assert_eq!(h.registry.close_all_connections(), 0);
    let at_the_gate = stall_at_the_gate(&h, &admin.cookie).await;
    let lock = TestingTableLock::acquire(&h.pool, "auth_session").await;
    at_the_gate.lock.release().await;
    let response = tokio::time::timeout(CLOSE_TIMEOUT, at_the_gate.response)
        .await
        .expect("answered without reaching the locked re-read")
        .unwrap();
    lock.release().await;

    assert_connect_comment_alone(response, "a request born closed").await;
    assert_eq!(h.registry.count(), 0);
    assert_eq!(h.registry.pending_count(), 0);
}

/// **A re-read failing under the shutdown.** The close-all reaches the
/// registration of a request held at its re-read, then the re-read errors
/// past its credential read (the `actor` table renamed away) — a shutdown
/// tearing the database down beside the request. The failure is the
/// shutdown's doing: the answer is the connect comment alone, not 500. The
/// control half — the same failure on a live registration — is the 500.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_recheck_failing_after_the_shutdown_answers_the_connect_comment() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_recheck_fails_shutdown").await;
    let h = revocation_harness(pool, &keyring);
    let break_the_actor_read = || async {
        h.pool
            .get()
            .await
            .unwrap()
            .batch_execute("ALTER TABLE actor RENAME TO actor_gone")
            .await
            .unwrap();
    };
    let restore_the_actor_read = || async {
        h.pool
            .get()
            .await
            .unwrap()
            .batch_execute("ALTER TABLE actor_gone RENAME TO actor")
            .await
            .unwrap();
    };

    let stalled = stall_at_the_re_read(&h, &admin.cookie).await;
    break_the_actor_read().await;
    let response = stalled.resume().await;
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "the control: a live registration gets the 500"
    );
    assert_eq!(h.registry.pending_count(), 0);
    restore_the_actor_read().await;

    let stalled = stall_at_the_re_read(&h, &admin.cookie).await;
    assert_eq!(
        h.registry.close_all_connections(),
        1,
        "the close-all finds the pending registration"
    );
    break_the_actor_read().await;
    let response = stalled.resume().await;

    assert_connect_comment_alone(response, "a re-check failing after the shutdown").await;
    assert_eq!(h.registry.count(), 0, "never admitted");
    assert_eq!(h.registry.pending_count(), 0);
}

/// **A revocation is not the shutdown.** A registration a revocation closed
/// while the request ran, whose re-read then fails, is the read's 500 — only
/// the shutdown's close answers for a failed read, as the twin's
/// `registry.closing` check does.
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn a_recheck_failing_after_a_revocation_is_a_500() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let admin = seed_admin(&pool, &keyring, "admin_recheck_fails_revoked").await;
    let h = revocation_harness(pool, &keyring);

    let stalled = stall_at_the_re_read(&h, &admin.cookie).await;
    assert_eq!(
        h.registry
            .close_connections(&ConnectionCloseTarget::Account(admin.account_id)),
        1
    );
    h.pool
        .get()
        .await
        .unwrap()
        .batch_execute("ALTER TABLE actor RENAME TO actor_gone")
        .await
        .unwrap();
    let response = stalled.resume().await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h.registry.count(), 0);
    assert_eq!(h.registry.pending_count(), 0);
}
