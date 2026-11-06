//! The auth REST routes' internal-failure answer, one arm at a time.
//!
//! A handler's own internal failure — a query, a password hash — answers
//! [`fuz_http::internal_error_response`] on `/status`, `/login`, `/logout`,
//! `/password`, `/bootstrap`, and `/signup`: status 500,
//! `Content-Type: application/json`, and the body
//! `{"error":"internal_error"}` byte for byte. A failed pool checkout is the
//! database unavailable, not a fault: it answers
//! [`fuz_http::db_unavailable_response`], status 503 and the body
//! `{"error":"service_unavailable"}`. Each `*_answers_the_flat_500` /
//! `*_answers_the_503` test injects one fault that reaches one arm and nothing
//! before it:
//!
//! - **a pool checkout** — a pool that cannot connect at all for the routes
//!   that resolve no credential first, and a pool with a checkout budget
//!   ([`common::budgeted_pool`]) for the ones that do, so the credential read
//!   gets its connection and the handler's own checkout is the one refused;
//! - **a `BEGIN`** — a pool that hands out one dead connection
//!   ([`pool_with_dead_checkout`]), so the checkout succeeds and the first
//!   statement on it is the one that fails;
//! - **a read or write** — a rename of something that statement names and no
//!   earlier one does, or, where the earlier statements name everything it
//!   does, a statement trigger that refuses it ([`refuse_statement`]);
//! - **a commit** — a deferred constraint trigger ([`refuse_commit`]), which
//!   lets every statement through and fails the `COMMIT`;
//! - **a hash** — a [`PasswordHasher`] whose `hash` fails.
//!
//! Every database case starts from a fresh schema, so no fault outlives its
//! test. The remaining tests pin the answers that sit beside those arms — the
//! refusals and the successes — so no failure arm absorbs or reshapes them.
//! They pin those answers as this spine gives them; whether each reason is
//! the TS twin's is not their claim.
//!
//! `/password` writes three things — the hash, the session revocation, the
//! API-token revocation — so its failures have a second half: what they leave
//! behind. The `/password is one transaction` cases read the account's
//! [`Credentials`] back over their own connection and record every close the
//! route asks its [`ConnectionCloser`] for: a failed change leaves the hash, the
//! sessions, and the tokens as seeded and closes nothing, and a committed one
//! closes once, after the commit, whatever becomes of its audit row. One more
//! case watches the pool from inside the hasher: the verify and the hash run
//! with no connection checked out.
//!
//! The database cases are gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test rest_internal_errors -- --ignored --test-threads=1
//! ```
//!
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

// Integration-test helpers assert via `expect`/`unwrap` (panic-on-failure is
// the test mechanism); `allow-*-in-tests` only covers `#[test]` fns, not the
// shared helper fns these files call.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::{Extension, Router};
use deadpool_postgres::{ClientWrapper, Hook, Manager, Runtime};
use futures::future::{BoxFuture, FutureExt};
use fuz_auth::bootstrap_routes::bootstrap_router;
use fuz_auth::signup_routes::signup_router;
use fuz_auth::{
    AccountRouteState, AuditEmitter, BootstrapOptions, BootstrapRouteState, BootstrapTokenStore,
    ConnectionCloseTarget, ConnectionCloser, HashedPassword, NoopConnectionCloser, PasswordHasher,
    RateLimitResult, RateLimiter, RateLimiterOptions, SESSION_COOKIE_NAME, SignupOptions,
    SignupRouteState, TokenScopeDocument, account_router,
};
use fuz_db::{Pool, create_pool};
use fuz_http::ClientIp;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

mod common;
use common::{fresh_db_pool, seed_account_actor};

/// The body every internal failure answers, byte for byte.
const INTERNAL_ERROR_BODY: &str = r#"{"error":"internal_error"}"#;

/// The body every failed pool checkout answers, byte for byte.
const DB_UNAVAILABLE_BODY: &str = r#"{"error":"service_unavailable"}"#;

/// A password the creation-site bounds accept (`PASSWORD_LENGTH_MIN` is 12).
const NEW_PASSWORD: &str = "a-new-password-of-length";

/// The hash the stub hashers mint for a new password — distinct from the
/// `x` every seeded account stores.
const STUB_HASH: &str = "stub-hash";

/// The bootstrap token the in-memory store holds.
const BOOTSTRAP_TOKEN: &str = "bootstrap-token-fixture-0123456789";

// -- Fixtures -----------------------------------------------------------------

/// A [`PasswordHasher`] with both answers chosen by the test: `verify`
/// returns `verifies` for every password, and `hash` fails when `hash_fails`.
/// Stands in for Argon2 so a case reaches the arm past the verify (or fails
/// exactly at the hash) without the hashing cost.
struct StubHasher {
    verifies: bool,
    hash_fails: bool,
}

impl StubHasher {
    /// Accepts every password and hashes without fault.
    fn accepting() -> Arc<dyn PasswordHasher> {
        Arc::new(Self {
            verifies: true,
            hash_fails: false,
        })
    }

    /// Refuses every password.
    fn refusing() -> Arc<dyn PasswordHasher> {
        Arc::new(Self {
            verifies: false,
            hash_fails: false,
        })
    }

    /// Accepts every password, then fails to hash the new one.
    fn failing_to_hash() -> Arc<dyn PasswordHasher> {
        Arc::new(Self {
            verifies: true,
            hash_fails: true,
        })
    }
}

impl PasswordHasher for StubHasher {
    fn hash(&self, _password: String) -> BoxFuture<'static, Result<HashedPassword, String>> {
        let fails = self.hash_fails;
        async move {
            if fails {
                Err("injected hashing fault".to_owned())
            } else {
                Ok(HashedPassword::new(STUB_HASH.to_owned()))
            }
        }
        .boxed()
    }

    fn verify(&self, _password: String, _hash: String) -> BoxFuture<'static, bool> {
        let verifies = self.verifies;
        async move { verifies }.boxed()
    }

    fn dummy_hash(&self) -> &'static str {
        "stub-dummy-hash"
    }
}

/// A [`PasswordHasher`] that accepts every password and, while hashing the new
/// one, replaces the account's stored hash over its own connection — a
/// concurrent password change that commits between the route's verify and its
/// update.
struct SupersedingHasher {
    pool: Pool,
    account_id: Uuid,
}

/// The hash [`SupersedingHasher`] stores.
const SUPERSEDING_HASH: &str = "superseding-hash";

impl PasswordHasher for SupersedingHasher {
    fn hash(&self, _password: String) -> BoxFuture<'static, Result<HashedPassword, String>> {
        let pool = self.pool.clone();
        let account_id = self.account_id;
        async move {
            pool.get()
                .await
                .expect("pool.get")
                .execute(
                    "UPDATE account SET password_hash = $1 WHERE id = $2",
                    &[&SUPERSEDING_HASH, &account_id],
                )
                .await
                .expect("the concurrent change commits");
            Ok(HashedPassword::new(STUB_HASH.to_owned()))
        }
        .boxed()
    }

    fn verify(&self, _password: String, _hash: String) -> BoxFuture<'static, bool> {
        async { true }.boxed()
    }

    fn dummy_hash(&self) -> &'static str {
        "stub-dummy-hash"
    }
}

/// A [`PasswordHasher`] that accepts every password and records, at each
/// `verify` and each `hash`, how many of the pool's connections are checked
/// out at that moment.
struct PoolWatchingHasher {
    pool: Pool,
    in_use: Arc<Mutex<Vec<(&'static str, usize)>>>,
}

impl PoolWatchingHasher {
    fn record(&self, step: &'static str) {
        let status = self.pool.status();
        self.in_use
            .lock()
            .unwrap()
            .push((step, status.size - status.available));
    }
}

impl PasswordHasher for PoolWatchingHasher {
    fn hash(&self, _password: String) -> BoxFuture<'static, Result<HashedPassword, String>> {
        self.record("hash");
        async { Ok(HashedPassword::new(STUB_HASH.to_owned())) }.boxed()
    }

    fn verify(&self, _password: String, _hash: String) -> BoxFuture<'static, bool> {
        self.record("verify");
        async { true }.boxed()
    }

    fn dummy_hash(&self) -> &'static str {
        "stub-dummy-hash"
    }
}

/// In-memory [`BootstrapTokenStore`]: holds [`BOOTSTRAP_TOKEN`], or fails the
/// read when `read_fails` (a missing or unreadable token file).
struct StubTokenStore {
    read_fails: bool,
}

impl BootstrapTokenStore for StubTokenStore {
    fn read_token(&self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        let fails = self.read_fails;
        async move {
            if fails {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token file missing",
                ))
            } else {
                Ok(BOOTSTRAP_TOKEN.as_bytes().to_vec())
            }
        }
        .boxed()
    }

    fn delete_token(&self) -> BoxFuture<'_, io::Result<()>> {
        async { Ok(()) }.boxed()
    }
}

/// A pool that cannot connect: nothing listens on the port its URL names, so
/// every checkout fails. `create_pool` only parses the URL — `deadpool`
/// connects on the first `get()` — so building one needs no database.
fn unreachable_pool() -> Pool {
    create_pool(
        "postgres://rest_internal_errors@127.0.0.1:1/none",
        &fuz_db::PoolOptions::default(),
    )
    .expect("pool builds without connecting")
}

/// A pool on the suite's database whose `nth` checkout (counted from one)
/// hands out a connection that is already dead: its backend is terminated
/// after the pool has passed it as healthy.
///
/// The fault for a `BEGIN`. The checkout itself succeeds, so the handler's
/// pool arm is not the one reached; the first statement sent on the
/// connection fails.
fn pool_with_dead_checkout(nth: usize) -> Pool {
    let config: tokio_postgres::Config = common::test_url().parse().expect("test URL parses");
    let checkouts = Arc::new(AtomicUsize::new(0));
    let hook = || {
        let checkouts = Arc::clone(&checkouts);
        Hook::async_fn(move |client: &mut ClientWrapper, _| {
            let dies = checkouts.fetch_add(1, Ordering::SeqCst) + 1 == nth;
            Box::pin(async move {
                if dies {
                    // answered with the FATAL that ends the session
                    let ended = client
                        .batch_execute("SELECT pg_terminate_backend(pg_backend_pid())")
                        .await;
                    assert!(ended.is_err(), "the backend outlived its termination");
                }
                Ok(())
            })
        })
    };
    Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(Runtime::Tokio1)
        .post_create(hook())
        .post_recycle(hook())
        .build()
        .expect("dead-checkout pool builds")
}

/// Run fault-injecting DDL on the suite's database.
async fn execute(pool: &Pool, sql: &str) {
    pool.get()
        .await
        .expect("pool.get")
        .batch_execute(sql)
        .await
        .expect("fault DDL runs");
}

/// Make every `operation` (`DELETE`, `UPDATE`, …) on `table` fail, leaving
/// reads of it working.
///
/// A statement-level trigger, so it fires whether or not a row matches. The
/// fault for a write whose table and columns an earlier read in the same
/// request already names, where no rename can fail the one without the other.
/// Both arguments are spliced in as SQL, so pass only fixed test constants.
async fn refuse_statement(pool: &Pool, operation: &str, table: &str) {
    execute(
        pool,
        &format!(
            "CREATE FUNCTION refuse_statement() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'injected fault'; END $$; \
             CREATE TRIGGER refuse_statement BEFORE {operation} ON {table} \
             FOR EACH STATEMENT EXECUTE FUNCTION refuse_statement();"
        ),
    )
    .await;
}

/// Make every transaction that updates a row of `table` fail at its `COMMIT`,
/// with each of its statements succeeding.
///
/// A deferred constraint trigger: queued by the `UPDATE`, run when the
/// transaction commits. `table` is spliced in as SQL, so pass only a fixed
/// test constant.
async fn refuse_commit(pool: &Pool, table: &str) {
    execute(
        pool,
        &format!(
            "CREATE FUNCTION refuse_commit() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'injected commit fault'; END $$; \
             CREATE CONSTRAINT TRIGGER refuse_commit AFTER UPDATE ON {table} \
             DEFERRABLE INITIALLY DEFERRED \
             FOR EACH ROW EXECUTE FUNCTION refuse_commit();"
        ),
    )
    .await;
}

/// What `/password` changes for one account: the stored hash and how many
/// sessions and API tokens it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Credentials {
    password_hash: String,
    sessions: i64,
    api_tokens: i64,
}

impl Credentials {
    /// What [`seed_credentials`] leaves: the seeded hash, one session, one
    /// API token.
    fn seeded() -> Self {
        Self {
            password_hash: "x".to_owned(),
            sessions: 1,
            api_tokens: 1,
        }
    }

    /// What a committed change leaves: the new hash and nothing to
    /// authenticate with.
    fn changed() -> Self {
        Self {
            password_hash: STUB_HASH.to_owned(),
            sessions: 0,
            api_tokens: 0,
        }
    }

    /// Read the account's state over a connection of its own, which sees
    /// committed rows only.
    async fn read(pool: &Pool, account_id: Uuid) -> Self {
        let row = pool
            .get()
            .await
            .expect("pool.get")
            .query_one(
                "SELECT password_hash, \
                   (SELECT count(*) FROM auth_session WHERE account_id = account.id), \
                   (SELECT count(*) FROM api_token WHERE account_id = account.id) \
                 FROM account WHERE id = $1",
                &[&account_id],
            )
            .await
            .expect("account row");
        Self {
            password_hash: row.get(0),
            sessions: row.get(1),
            api_tokens: row.get(2),
        }
    }
}

/// A [`ConnectionCloser`] that records each account close with the account's
/// committed [`Credentials`] at the moment it was asked — read over a
/// separate connection, so a close issued inside the change's transaction
/// records the state from before it.
struct ProbingCloser {
    pool: Pool,
    closes: Mutex<Vec<(Uuid, Credentials)>>,
}

impl ProbingCloser {
    fn new(pool: Pool) -> Arc<Self> {
        Arc::new(Self {
            pool,
            closes: Mutex::new(Vec::new()),
        })
    }

    /// Every close asked for so far, in order.
    fn closes(&self) -> Vec<(Uuid, Credentials)> {
        self.closes.lock().unwrap().clone()
    }
}

impl fuz_http::ShutdownCloser for ProbingCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for ProbingCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        let &ConnectionCloseTarget::Account(target_id) = target else {
            unreachable!("the password route closes by account")
        };
        // `ConnectionCloser` is sync; `block_in_place` lets it read the database
        // from a multi-thread runtime.
        let seen = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(Credentials::read(&self.pool, target_id))
        });
        self.closes.lock().unwrap().push((target_id, seen));
        0
    }
}

/// Account-router state over `pool`: no rate limiters, no daemon token, and a
/// one-origin allowlist (a request with no `Origin` is allowed).
fn account_state(pool: Pool, hasher: Arc<dyn PasswordHasher>) -> AccountRouteState {
    AccountRouteState {
        audit: Arc::new(AuditEmitter::new(pool.clone())),
        gate: fuz_testing::testing_auth_gate(pool),
        password_hasher: hasher,
        connection_closer: Arc::new(NoopConnectionCloser),
        bootstrap_available: Arc::new(AtomicBool::new(false)),
        login_ip_rate_limiter: None,
        login_account_rate_limiter: None,
        // no internal-error case asserts the denial floor
        login_fail_floor_ms: 0,
        login_fail_jitter_ms: 0,
    }
}

/// The account router over `pool` with a hasher that accepts every password.
fn account_routes(pool: Pool) -> Router {
    account_router(account_state(pool, StubHasher::accepting()))
}

/// Seed a single-actor account and a live session for it. Returns the account
/// id, the actor id, and the request `Cookie` header value.
async fn seed_session(pool: &Pool, username: &str) -> (Uuid, Uuid, String) {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    let cookie = fuz_testing::mint_session_cookie(
        pool,
        &fuz_testing::testing_keyring(),
        account_id,
        SESSION_COOKIE_NAME,
    )
    .await;
    (account_id, actor_id, cookie)
}

/// Seed an account holding everything `/password` revokes — one session and
/// one API token — and return its id and the session's `Cookie` header value.
///
/// The account reads back as [`Credentials::seeded`].
async fn seed_credentials(pool: &Pool, username: &str) -> (Uuid, String) {
    let (account_id, _, cookie) = seed_session(pool, username).await;
    fuz_testing::mint_api_token(pool, account_id, &TokenScopeDocument::full()).await;
    (account_id, cookie)
}

/// The account router over `pool` with `hasher`, its closes going to the
/// returned [`ProbingCloser`].
fn probed_routes(pool: &Pool, hasher: Arc<dyn PasswordHasher>) -> (Router, Arc<ProbingCloser>) {
    let closer = ProbingCloser::new(pool.clone());
    let mut state = account_state(pool.clone(), hasher);
    state.connection_closer = Arc::<ProbingCloser>::clone(&closer);
    (account_router(state), closer)
}

/// Bootstrap-router state over `pool` with the window open, a stub hasher,
/// and `token_store` as given.
fn bootstrap_state(
    pool: Pool,
    token_store: Option<Arc<dyn BootstrapTokenStore>>,
    available: bool,
) -> BootstrapRouteState {
    BootstrapRouteState {
        gate: fuz_testing::testing_auth_gate(pool.clone()),
        options: Arc::new(BootstrapOptions {
            audit: Arc::new(AuditEmitter::new(pool.clone())),
            pool,
            password_hasher: StubHasher::accepting(),
            bootstrap_available: Arc::new(AtomicBool::new(available)),
            token_store,
            on_keeper_resolved: None,
        }),
    }
}

/// A token store holding [`BOOTSTRAP_TOKEN`], or one whose read fails.
fn token_store(read_fails: bool) -> Arc<dyn BootstrapTokenStore> {
    Arc::new(StubTokenStore { read_fails })
}

/// Signup-router state over `pool`: a stub hasher, no rate limiters, and no
/// denial floor.
fn signup_state(pool: Pool) -> SignupRouteState {
    SignupRouteState {
        gate: fuz_testing::testing_auth_gate(pool.clone()),
        options: Arc::new(SignupOptions {
            audit: Arc::new(AuditEmitter::new(pool.clone())),
            pool,
            password_hasher: StubHasher::accepting(),
            signup_ip_rate_limiter: None,
            signup_account_rate_limiter: None,
            signup_fail_floor_ms: 0,
            signup_fail_jitter_ms: 0,
        }),
    }
}

// -- Requests -----------------------------------------------------------------

/// What a route answered: status, `Content-Type`, `Set-Cookie`, and the body
/// as text.
#[derive(Debug)]
struct Reply {
    status: StatusCode,
    content_type: Option<String>,
    set_cookie: Option<String>,
    body: String,
}

impl Reply {
    /// The body parsed as JSON.
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("body is JSON")
    }
}

/// Send one request through `router`. `headers` are name/value pairs; a
/// `body` is sent as JSON with its `Content-Type`, which a bodyless `POST`
/// carries too, as the spine's JSON routes require it.
async fn send(
    router: Router,
    method: &str,
    uri: &str,
    headers: &[(header::HeaderName, &str)],
    body: Option<&Value>,
) -> Reply {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(name, *value);
    }
    let request = match body {
        Some(value) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string())),
        None if method == "POST" => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::empty()),
        None => request.body(Body::empty()),
    }
    .expect("request builds");
    let response = router.oneshot(request).await.expect("router responds");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().expect("content-type is ascii").to_owned());
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().expect("set-cookie is ascii").to_owned());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collects");
    Reply {
        status,
        content_type,
        set_cookie,
        body: String::from_utf8(bytes.to_vec()).expect("body is utf-8"),
    }
}

/// `GET /status` under `cookie`.
async fn get_status(router: Router, cookie: &str) -> Reply {
    send(router, "GET", "/status", &[(header::COOKIE, cookie)], None).await
}

/// `POST /login` with a well-formed body for `username`.
async fn post_login(router: Router, username: &str) -> Reply {
    let body = json!({"username": username, "password": "any-password"});
    send(router, "POST", "/login", &[], Some(&body)).await
}

/// `POST /logout` under `cookie`.
async fn post_logout(router: Router, cookie: &str) -> Reply {
    send(router, "POST", "/logout", &[(header::COOKIE, cookie)], None).await
}

/// `POST /password` under `cookie` with a well-formed body.
async fn post_password(router: Router, cookie: &str) -> Reply {
    let body = json!({"current_password": "the-current-password", "new_password": NEW_PASSWORD});
    send(
        router,
        "POST",
        "/password",
        &[(header::COOKIE, cookie)],
        Some(&body),
    )
    .await
}

/// `POST /bootstrap` with a well-formed body carrying `token`.
async fn post_bootstrap(router: Router, token: &str) -> Reply {
    let body = json!({"token": token, "username": "keeper", "password": NEW_PASSWORD});
    send(router, "POST", "/bootstrap", &[], Some(&body)).await
}

/// `POST /signup` with a well-formed body.
async fn post_signup(router: Router) -> Reply {
    let body = json!({"username": "newcomer", "password": NEW_PASSWORD});
    send(router, "POST", "/signup", &[], Some(&body)).await
}

/// Assert the flat 500: status, `Content-Type`, and body byte for byte, and
/// no `Set-Cookie` — a failed request neither mints nor clears a session
/// cookie.
#[track_caller]
fn assert_flat_500(reply: &Reply) {
    assert_eq!(
        (
            reply.status,
            reply.content_type.as_deref(),
            reply.set_cookie.as_deref(),
            reply.body.as_str()
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("application/json"),
            None,
            INTERNAL_ERROR_BODY
        ),
    );
}

/// Assert the flat 503 of a failed pool checkout: status, `Content-Type`, and
/// body byte for byte, and no `Set-Cookie`.
#[track_caller]
fn assert_flat_503(reply: &Reply) {
    assert_eq!(
        (
            reply.status,
            reply.content_type.as_deref(),
            reply.set_cookie.as_deref(),
            reply.body.as_str()
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("application/json"),
            None,
            DB_UNAVAILABLE_BODY
        ),
    );
}

/// Assert a JSON answer: status, `Content-Type`, and body byte for byte.
#[track_caller]
fn assert_json(reply: &Reply, status: StatusCode, body: &str) {
    assert_eq!(
        (
            reply.status,
            reply.content_type.as_deref(),
            reply.body.as_str()
        ),
        (status, Some("application/json"), body),
    );
}

// -- /status ------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn status_pool_checkout_failure_answers_the_503() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "status_pool").await;
    // One checkout: the credential read's. The handler's own is refused.
    let reply = get_status(account_routes(common::budgeted_pool(1)), &cookie).await;
    assert_flat_503(&reply);
}

/// A refused checkout on the credential walk's first leg answers the 503 and
/// ends the walk: the bearer sent beside the cookie is never looked up, so
/// its `last_used_at` stays unset.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn status_credential_checkout_failure_answers_the_503_and_ends_the_walk() {
    let pool = fresh_db_pool().await;
    let (account_id, _, cookie) = seed_session(&pool, "status_walk_checkout").await;
    let token = fuz_testing::mint_api_token(&pool, account_id, &TokenScopeDocument::full()).await;
    let bearer = format!("Bearer {}", token.token);
    let reply = send(
        account_routes(common::budgeted_pool(0)),
        "GET",
        "/status",
        &[(header::COOKIE, &cookie), (header::AUTHORIZATION, &bearer)],
        None,
    )
    .await;
    assert_flat_503(&reply);
    // the bearer leg's touch is spawned; give it the time it would take
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let touched: Option<String> = pool
        .get()
        .await
        .expect("pool.get")
        .query_one(
            "SELECT last_used_at::text FROM api_token WHERE account_id = $1",
            &[&account_id],
        )
        .await
        .expect("token row")
        .get(0);
    assert_eq!(touched, None, "the walk stopped at the faulted cookie leg");
}

/// A failed query on the credential walk's checked-out client keeps the text
/// 500 — only the checkout phase is the 503.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn status_credential_query_failure_answers_the_text_500() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "status_walk_query").await;
    execute(
        &pool,
        "ALTER TABLE auth_session RENAME TO auth_session_gone",
    )
    .await;
    let reply = get_status(account_routes(pool), &cookie).await;
    assert_eq!(
        (
            reply.status,
            reply.content_type.as_deref(),
            reply.body.as_str()
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("text/plain; charset=UTF-8"),
            fuz_auth::CREDENTIAL_READ_FAULT_BODY
        ),
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn status_account_summary_failure_answers_the_flat_500() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "status_summary").await;
    // The summary projects `email_verified`; the credential read does not.
    execute(
        &pool,
        "ALTER TABLE account RENAME COLUMN email_verified TO email_verified_gone",
    )
    .await;
    let reply = get_status(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn status_actor_resolution_failure_answers_the_flat_500() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "status_actor").await;
    execute(&pool, "ALTER TABLE actor RENAME TO actor_gone").await;
    let reply = get_status(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn status_role_grant_read_failure_answers_the_flat_500() {
    // A single-actor account, so the persona resolves and its grants are read.
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "status_grants").await;
    execute(&pool, "ALTER TABLE role_grant RENAME TO role_grant_gone").await;
    let reply = get_status(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

// -- /login -------------------------------------------------------------------

/// Login resolves no credential, so its checkout is the request's first: a
/// pool that cannot connect reaches it, and the case needs no database.
#[tokio::test]
async fn login_pool_checkout_failure_answers_the_503() {
    let reply = post_login(account_routes(unreachable_pool()), "anyone").await;
    assert_flat_503(&reply);
}

/// The login identifier trims JS `String.prototype.trim`'s set, the twin's:
/// U+FEFF alone is empty after the trim (`400`, before any checkout), while
/// U+0085 is not whitespace there, so it reaches the lookup — here, the
/// unreachable pool's `503`.
#[tokio::test]
async fn login_trims_the_js_whitespace_set() {
    for blank in ["\u{FEFF}", " \u{FEFF}\t"] {
        let reply = post_login(account_routes(unreachable_pool()), blank).await;
        assert_json(
            &reply,
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_request_body"}"#,
        );
    }
    let reply = post_login(account_routes(unreachable_pool()), "\u{85}").await;
    assert_flat_503(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_account_lookup_failure_answers_the_flat_500() {
    let pool = fresh_db_pool().await;
    execute(&pool, "ALTER TABLE account RENAME TO account_gone").await;
    let reply = post_login(account_routes(pool), "anyone").await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_session_creation_failure_answers_the_flat_500() {
    // The account resolves and the stub hasher accepts the password, so the
    // request reaches the session insert — into a table that is gone.
    let pool = fresh_db_pool().await;
    seed_account_actor(&pool, "login_session").await;
    execute(
        &pool,
        "ALTER TABLE auth_session RENAME TO auth_session_gone",
    )
    .await;
    let reply = post_login(account_routes(pool), "login_session").await;
    assert_flat_500(&reply);
}

/// The session insert checks out a second connection after the lookup's is
/// back in the pool; a refused second checkout is the 503, not the 500 of a
/// failed insert.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_session_checkout_failure_answers_the_503() {
    let pool = fresh_db_pool().await;
    seed_account_actor(&pool, "login_session_checkout").await;
    let reply = post_login(
        account_routes(common::budgeted_pool(1)),
        "login_session_checkout",
    )
    .await;
    assert_flat_503(&reply);
}

// -- /logout ------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn logout_pool_checkout_failure_answers_the_503() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "logout_pool").await;
    // One checkout: the credential read's. The handler's own is refused.
    let reply = post_logout(account_routes(common::budgeted_pool(1)), &cookie).await;
    assert_flat_503(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn logout_session_delete_failure_answers_the_flat_500() {
    // The credential read selects from `auth_session`, so the table stays and
    // only its DELETE is refused.
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "logout_delete").await;
    refuse_statement(&pool, "DELETE", "auth_session").await;
    let reply = post_logout(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

// -- /password ----------------------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_pool_checkout_failure_answers_the_503() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_pool").await;
    // One checkout: the credential read's. The handler's own is refused.
    let reply = post_password(account_routes(common::budgeted_pool(1)), &cookie).await;
    assert_flat_503(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_account_lookup_failure_answers_the_flat_500() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_lookup").await;
    // The lookup projects `password_hash`; the credential read does not.
    execute(
        &pool,
        "ALTER TABLE account RENAME COLUMN password_hash TO password_hash_gone",
    )
    .await;
    let reply = post_password(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_hash_failure_answers_the_flat_500() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_hash").await;
    let router = account_router(account_state(pool, StubHasher::failing_to_hash()));
    let reply = post_password(router, &cookie).await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_transaction_checkout_failure_answers_the_503() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_tx_pool").await;
    // Two checkouts: the credential read's and the account lookup's. The
    // change's own, taken after the hash, is refused.
    let reply = post_password(account_routes(common::budgeted_pool(2)), &cookie).await;
    assert_flat_503(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_transaction_begin_failure_answers_the_flat_500() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_begin").await;
    // The third checkout is the change's: the credential read and the account
    // lookup each took and returned one before it.
    let reply = post_password(account_routes(pool_with_dead_checkout(3)), &cookie).await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_update_failure_answers_the_flat_500() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_update").await;
    // The UPDATE sets `updated_at`; no read before it names the column.
    execute(
        &pool,
        "ALTER TABLE account RENAME COLUMN updated_at TO updated_at_gone",
    )
    .await;
    let reply = post_password(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_session_revocation_failure_answers_the_flat_500() {
    // The credential read selects from `auth_session`, so the table stays and
    // only its DELETE is refused.
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_sessions").await;
    refuse_statement(&pool, "DELETE", "auth_session").await;
    let reply = post_password(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_token_revocation_failure_answers_the_flat_500() {
    // Nothing before the token revocation touches `api_token` on a session.
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_tokens").await;
    execute(&pool, "ALTER TABLE api_token RENAME TO api_token_gone").await;
    let reply = post_password(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_commit_failure_answers_the_flat_500() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "password_commit").await;
    refuse_commit(&pool, "account").await;
    let reply = post_password(account_routes(pool), &cookie).await;
    assert_flat_500(&reply);
}

// -- /password is one transaction ---------------------------------------------

/// A session revocation that fails after the update has run undoes the
/// update: the stored hash is still the old one, and the old session still
/// authenticates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_refused_session_revocation_changes_nothing() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_atomic_sessions").await;
    let (router, closer) = probed_routes(&pool, StubHasher::accepting());
    refuse_statement(&pool, "DELETE", "auth_session").await;

    let reply = post_password(router, &cookie).await;

    assert_flat_500(&reply);
    assert_eq!(
        Credentials::read(&pool, account_id).await,
        Credentials::seeded()
    );
    assert_eq!(closer.closes(), [], "a failed change closes nothing");
    let reply = get_status(account_routes(pool), &cookie).await;
    assert_eq!(reply.status, StatusCode::OK, "the session is still live");
}

/// A token revocation that fails is the last statement of the change, and it
/// undoes the two before it: the hash and the sessions are as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_refused_token_revocation_changes_nothing() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_atomic_tokens").await;
    let (router, closer) = probed_routes(&pool, StubHasher::accepting());
    refuse_statement(&pool, "DELETE", "api_token").await;

    let reply = post_password(router, &cookie).await;

    assert_flat_500(&reply);
    assert_eq!(
        Credentials::read(&pool, account_id).await,
        Credentials::seeded()
    );
    assert_eq!(closer.closes(), [], "a failed change closes nothing");
}

/// A commit that fails after all three statements succeeded changes nothing
/// and closes nothing — the close waits for the commit's answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_failed_commit_changes_nothing_and_closes_nothing() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_atomic_commit").await;
    let (router, closer) = probed_routes(&pool, StubHasher::accepting());
    refuse_commit(&pool, "account").await;

    let reply = post_password(router, &cookie).await;

    assert_flat_500(&reply);
    assert_eq!(
        Credentials::read(&pool, account_id).await,
        Credentials::seeded()
    );
    assert_eq!(closer.closes(), [], "a failed commit closes nothing");
}

/// The change that commits: the new hash is stored, every session and token
/// is gone, the cookie is cleared, and the account's connections are closed
/// once — at a moment when a separate connection already reads the change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_committed_change_closes_once_after_the_commit() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_committed").await;
    // A second account, which the change must not reach.
    let (bystander_id, _) = seed_credentials(&pool, "password_bystander").await;
    let (router, closer) = probed_routes(&pool, StubHasher::accepting());

    let reply = post_password(router, &cookie).await;

    assert_json(
        &reply,
        StatusCode::OK,
        r#"{"ok":true,"sessions_revoked":1,"tokens_revoked":1}"#,
    );
    let cleared = reply.set_cookie.as_deref().expect("the cookie is cleared");
    assert!(
        cleared.starts_with(&format!("{SESSION_COOKIE_NAME}=;")) && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
    assert_eq!(
        Credentials::read(&pool, account_id).await,
        Credentials::changed()
    );
    assert_eq!(
        closer.closes(),
        [(account_id, Credentials::changed())],
        "one close, for a change already committed when it ran"
    );
    assert_eq!(
        Credentials::read(&pool, bystander_id).await,
        Credentials::seeded(),
        "another account keeps its hash, sessions, and tokens"
    );
}

/// The audit write is fail-open: with every `password_change` row refused,
/// the committed change still answers its success and still closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_failed_audit_write_still_answers_and_closes() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_audit_refused").await;
    let (router, closer) = probed_routes(&pool, StubHasher::accepting());
    fuz_testing::seed::refuse_audit_rows(&pool, &["password_change"]).await;

    let reply = post_password(router, &cookie).await;

    assert_json(
        &reply,
        StatusCode::OK,
        r#"{"ok":true,"sessions_revoked":1,"tokens_revoked":1}"#,
    );
    assert_eq!(
        closer.closes(),
        [(account_id, Credentials::changed())],
        "the close does not wait on the audit row"
    );
    let audited: i64 = pool
        .get()
        .await
        .expect("pool.get")
        .query_one(
            "SELECT count(*) FROM audit_log WHERE event_type = 'password_change'",
            &[],
        )
        .await
        .expect("audit count")
        .get(0);
    assert_eq!(audited, 0, "the audit write was refused");
}

/// The two Argon2 runs — the verify and the hash — happen with no connection
/// checked out: the account read has returned its own, and the change's
/// transaction is not open yet.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_verifies_and_hashes_holding_no_connection() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_no_connection").await;
    let in_use = Arc::new(Mutex::new(Vec::new()));
    let hasher = Arc::new(PoolWatchingHasher {
        pool: pool.clone(),
        in_use: Arc::clone(&in_use),
    });

    let reply = post_password(account_router(account_state(pool.clone(), hasher)), &cookie).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(*in_use.lock().unwrap(), [("verify", 0), ("hash", 0)]);
    assert_eq!(
        Credentials::read(&pool, account_id).await,
        Credentials::changed()
    );
}

/// A concurrent change that commits between the verify and the update wins:
/// the route answers the wrong-password 401, writes nothing over the winner's
/// hash, revokes nothing, closes nothing, and audits the failure with its
/// reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_superseded_change_answers_the_401_and_writes_nothing() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_superseded").await;
    let (router, closer) = probed_routes(
        &pool,
        Arc::new(SupersedingHasher {
            pool: pool.clone(),
            account_id,
        }),
    );

    let reply = post_password(router, &cookie).await;

    assert_json(
        &reply,
        StatusCode::UNAUTHORIZED,
        r#"{"error":"invalid_credentials"}"#,
    );
    assert_eq!(reply.set_cookie, None, "a refused change clears no cookie");
    assert_eq!(
        Credentials::read(&pool, account_id).await,
        Credentials {
            password_hash: SUPERSEDING_HASH.to_owned(),
            ..Credentials::seeded()
        }
    );
    assert_eq!(closer.closes(), [], "a refused change closes nothing");
    let row = pool
        .get()
        .await
        .expect("pool.get")
        .query_one(
            "SELECT outcome, metadata->>'reason' FROM audit_log \
             WHERE event_type = 'password_change'",
            &[],
        )
        .await
        .expect("one password_change row");
    assert_eq!(
        (row.get::<_, String>(0), row.get::<_, Option<String>>(1)),
        ("failure".to_owned(), Some("concurrent_change".to_owned()))
    );
}

// -- /bootstrap and /signup ---------------------------------------------------

/// Bootstrap reads its token from the store and hashes before it touches the
/// pool, so a pool that cannot connect is a failure the pipeline does not
/// classify — the database unavailable. Needs no database.
#[tokio::test]
async fn bootstrap_pool_checkout_failure_answers_the_503() {
    let router = bootstrap_router(bootstrap_state(
        unreachable_pool(),
        Some(token_store(false)),
        true,
    ));
    let reply = post_bootstrap(router, BOOTSTRAP_TOKEN).await;
    assert_flat_503(&reply);
}

/// Signup's first database work is a checkout, and a failed one is the
/// database unavailable. Needs no database.
#[tokio::test]
async fn signup_pool_checkout_failure_answers_the_503() {
    let reply = post_signup(signup_router(signup_state(unreachable_pool()))).await;
    assert_flat_503(&reply);
}

/// The resolved client address the signup tests below send from, so the IP
/// reservation is live (an unresolved address reserves nothing on that bucket).
const SIGNUP_CLIENT_IP: &str = "10.0.0.20";

/// `signup_router` over `pool` with both buckets limited, every request
/// arriving from [`SIGNUP_CLIENT_IP`].
fn limited_signup_router(pool: Pool, ip: &Arc<RateLimiter>, account: &Arc<RateLimiter>) -> Router {
    let state = SignupRouteState {
        gate: fuz_testing::testing_auth_gate(pool.clone()),
        options: Arc::new(SignupOptions {
            audit: Arc::new(AuditEmitter::new(pool.clone())),
            pool,
            password_hasher: StubHasher::accepting(),
            signup_ip_rate_limiter: Some(Arc::clone(ip)),
            signup_account_rate_limiter: Some(Arc::clone(account)),
            signup_fail_floor_ms: 0,
            signup_fail_jitter_ms: 0,
        }),
    };
    signup_router(state).layer(Extension(ClientIp(SIGNUP_CLIENT_IP.to_owned())))
}

/// An unclassified signup failure costs no attempt on either bucket, wherever
/// it lands: the checkout before the hash, the one after it, or the `BEGIN` —
/// a request dropped at those same steps is charged, so each one releases
/// explicitly. The control beside them is a classified denial from the same
/// address, which is charged to both, so the IP half is live.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn signup_unclassified_failure_costs_no_attempt() {
    let db = fresh_db_pool().await;
    for step in [
        "the checkout before the hash",
        "the checkout after the hash",
        "the BEGIN",
    ] {
        let ip = limiter(ATTEMPTS_MAX);
        let account = limiter(ATTEMPTS_MAX);
        let pool = match step {
            "the checkout before the hash" => unreachable_pool(),
            "the checkout after the hash" => common::budgeted_pool(1),
            _ => pool_with_dead_checkout(2),
        };
        let reply = post_signup(limited_signup_router(pool, &ip, &account)).await;
        if step == "the BEGIN" {
            assert_flat_500(&reply);
        } else {
            assert_flat_503(&reply);
        }
        assert_eq!(
            (
                attempts(&ip, SIGNUP_CLIENT_IP),
                attempts(&account, "newcomer")
            ),
            (0, 0),
            "{step}"
        );
    }

    // control: closed signup and no invite — the classified 403 is charged
    let ip = limiter(ATTEMPTS_MAX);
    let account = limiter(ATTEMPTS_MAX);
    let reply = post_signup(limited_signup_router(db, &ip, &account)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
    assert_eq!(
        (
            attempts(&ip, SIGNUP_CLIENT_IP),
            attempts(&account, "newcomer")
        ),
        (1, 1),
        "a classified denial from the same address is charged"
    );
}

// -- The answers beside the 500 -----------------------------------------------

/// `/status` answers a scope-narrowed API token as the anonymous caller, byte
/// for byte, with the bootstrap window closed and open: rule 3, in the
/// disposition of a route that answers anonymous callers. The full-scope token
/// beside it reads the account, so the 401 is the scope, not the bearer.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn status_answers_a_narrowed_token_as_anonymous() {
    let pool = fresh_db_pool().await;
    let (account_id, _, _) = seed_session(&pool, "status_narrowed").await;
    let narrowed_scope = fuz_testing::narrowed_scope(&["account_verify"]);
    let narrowed = fuz_testing::mint_api_token(&pool, account_id, &narrowed_scope).await;
    let narrowed = format!("Bearer {}", narrowed.token);
    let full = fuz_testing::mint_api_token(&pool, account_id, &TokenScopeDocument::full()).await;
    let full = format!("Bearer {}", full.token);
    let routes = |available: bool| {
        let state = account_state(pool.clone(), StubHasher::accepting());
        state
            .bootstrap_available
            .store(available, Ordering::Relaxed);
        account_router(state)
    };

    for (available, body) in [
        (false, r#"{"error":"authentication_required"}"#),
        (
            true,
            r#"{"error":"authentication_required","bootstrap_available":true}"#,
        ),
    ] {
        let anonymous = send(routes(available), "GET", "/status", &[], None).await;
        assert_json(&anonymous, StatusCode::UNAUTHORIZED, body);
        let as_narrowed = send(
            routes(available),
            "GET",
            "/status",
            &[(header::AUTHORIZATION, &narrowed)],
            None,
        )
        .await;
        assert_json(&as_narrowed, StatusCode::UNAUTHORIZED, body);
    }
    let as_full = send(
        routes(false),
        "GET",
        "/status",
        &[(header::AUTHORIZATION, &full)],
        None,
    )
    .await;
    assert_eq!(as_full.status, StatusCode::OK, "{}", as_full.body);
    assert!(as_full.body.contains("status_narrowed"), "{}", as_full.body);
}

/// The refusals each route gives before it needs a connection keep their
/// status, `Content-Type`, and body, over a pool that cannot connect — so none
/// of them is the internal-failure arm in disguise.
#[tokio::test]
async fn refusals_before_any_connection_keep_their_answers() {
    let foreign_origin = [(header::ORIGIN, "https://foreign.example")];
    let account = || account_state(unreachable_pool(), StubHasher::accepting());
    let gated = |mut state: AccountRouteState| {
        state.gate.allowed_origins =
            fuz_http::AllowedOrigins::parse("https://allowed.example").expect("valid allowlist");
        account_router(state)
    };

    // /status: anonymous, with and without an open bootstrap window.
    let reply = send(account_router(account()), "GET", "/status", &[], None).await;
    assert_json(
        &reply,
        StatusCode::UNAUTHORIZED,
        r#"{"error":"authentication_required"}"#,
    );
    let open = account();
    open.bootstrap_available.store(true, Ordering::Relaxed);
    let reply = send(account_router(open), "GET", "/status", &[], None).await;
    assert_json(
        &reply,
        StatusCode::UNAUTHORIZED,
        r#"{"error":"authentication_required","bootstrap_available":true}"#,
    );
    // …and a foreign origin, refused at the gate ahead of the credential walk
    let reply = send(gated(account()), "GET", "/status", &foreign_origin, None).await;
    assert_json(
        &reply,
        StatusCode::FORBIDDEN,
        r#"{"error":"forbidden_origin"}"#,
    );

    // /bootstrap and /signup: a foreign origin is refused before the body is read
    let foreign_gate = |pool| fuz_auth::AuthGate {
        allowed_origins: fuz_http::AllowedOrigins::parse("https://allowed.example")
            .expect("valid allowlist"),
        ..fuz_testing::testing_auth_gate(pool)
    };
    let bootstrap = BootstrapRouteState {
        gate: foreign_gate(unreachable_pool()),
        ..bootstrap_state(unreachable_pool(), Some(token_store(false)), true)
    };
    let signup = SignupRouteState {
        gate: foreign_gate(unreachable_pool()),
        ..signup_state(unreachable_pool())
    };
    for (router, path) in [
        (bootstrap_router(bootstrap), "/bootstrap"),
        (signup_router(signup), "/signup"),
    ] {
        let reply = send(router, "POST", path, &foreign_origin, Some(&json!({}))).await;
        assert_json(
            &reply,
            StatusCode::FORBIDDEN,
            r#"{"error":"forbidden_origin"}"#,
        );
    }

    // /login: a foreign origin, then a body that is not the input shape.
    let body = json!({"username": "anyone", "password": "any-password"});
    let reply = send(
        gated(account()),
        "POST",
        "/login",
        &foreign_origin,
        Some(&body),
    )
    .await;
    assert_json(
        &reply,
        StatusCode::FORBIDDEN,
        r#"{"error":"forbidden_origin"}"#,
    );
    let body = json!({"username": "anyone"});
    let reply = send(
        account_router(account()),
        "POST",
        "/login",
        &[],
        Some(&body),
    )
    .await;
    assert_json(
        &reply,
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request_body"}"#,
    );

    // /logout and /password: a foreign origin, then no credential.
    for path in ["/logout", "/password"] {
        let reply = send(gated(account()), "POST", path, &foreign_origin, None).await;
        assert_json(
            &reply,
            StatusCode::FORBIDDEN,
            r#"{"error":"forbidden_origin"}"#,
        );
        let reply = send(account_router(account()), "POST", path, &[], None).await;
        assert_json(
            &reply,
            StatusCode::UNAUTHORIZED,
            r#"{"error":"authentication_required"}"#,
        );
    }

    // /bootstrap: each classified refusal the pipeline reaches before the pool.
    for (state, token, status, body) in [
        (
            bootstrap_state(unreachable_pool(), None, true),
            BOOTSTRAP_TOKEN,
            StatusCode::FORBIDDEN,
            r#"{"error":"already_bootstrapped"}"#,
        ),
        (
            bootstrap_state(unreachable_pool(), Some(token_store(false)), false),
            BOOTSTRAP_TOKEN,
            StatusCode::FORBIDDEN,
            r#"{"error":"already_bootstrapped"}"#,
        ),
        (
            bootstrap_state(unreachable_pool(), Some(token_store(true)), true),
            BOOTSTRAP_TOKEN,
            StatusCode::NOT_FOUND,
            r#"{"error":"token_file_missing"}"#,
        ),
        (
            bootstrap_state(unreachable_pool(), Some(token_store(false)), true),
            "not-the-token",
            StatusCode::UNAUTHORIZED,
            r#"{"error":"invalid_token"}"#,
        ),
    ] {
        let reply = post_bootstrap(bootstrap_router(state), token).await;
        assert_json(&reply, status, body);
    }
    // A body outside `BootstrapInput`'s bounds is refused `400` with the twin's
    // route-schema reason, ahead of the window and token checks: a padded
    // username is refused, never trimmed, and a closed or unconfigured window
    // answers the same `400` for it.
    for (body, store, available) in [
        (
            json!({"token": BOOTSTRAP_TOKEN, "username": "keeper", "password": "short"}),
            Some(token_store(false)),
            true,
        ),
        (
            json!({"token": BOOTSTRAP_TOKEN, "username": " keeper ", "password": NEW_PASSWORD}),
            Some(token_store(false)),
            true,
        ),
        (
            json!({"token": "", "username": "keeper", "password": NEW_PASSWORD}),
            Some(token_store(false)),
            true,
        ),
        (
            json!({"token": "x", "username": "keeper\u{85}", "password": NEW_PASSWORD}),
            Some(token_store(false)),
            false,
        ),
        (
            json!({"token": "x", "username": "\tkeeper", "password": NEW_PASSWORD}),
            None,
            true,
        ),
    ] {
        let router = bootstrap_router(bootstrap_state(unreachable_pool(), store, available));
        let reply = send(router, "POST", "/bootstrap", &[], Some(&body)).await;
        assert_json(
            &reply,
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_request_body"}"#,
        );
    }

    // /signup: a body that is not the input shape, then ones that fail its
    // bounds — a padded username is refused, never trimmed into a legal one.
    for body in [
        json!({"username": "newcomer"}),
        json!({"username": "newcomer", "password": "short"}),
        json!({"username": " newcomer ", "password": NEW_PASSWORD}),
        json!({"username": "newcomer\t", "password": NEW_PASSWORD}),
        json!({"username": "\u{85}newcomer", "password": NEW_PASSWORD}),
    ] {
        let router = signup_router(signup_state(unreachable_pool()));
        let reply = send(router, "POST", "/signup", &[], Some(&body)).await;
        assert_json(
            &reply,
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_request_body"}"#,
        );
    }
}

/// `POST path` with `body` as its raw text and a JSON `Content-Type`.
async fn post_raw(
    router: Router,
    path: &str,
    headers: &[(header::HeaderName, &str)],
    body: &'static str,
) -> Reply {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(name, *value);
    }
    let request = request.body(Body::from(body)).expect("request builds");
    let response = router.oneshot(request).await.expect("router responds");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .map(|v| v.to_str().expect("content-type is ascii").to_owned());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collects");
    Reply {
        status,
        content_type,
        set_cookie: None,
        body: String::from_utf8(bytes.to_vec()).expect("body is utf-8"),
    }
}

/// The bodies that don't parse, or parse to anything but an object — the
/// twin's `invalid_json_body`, never the schema refusal `invalid_request_body`.
const NON_OBJECT_BODIES: [&str; 6] = ["{", "", "[]", "null", "5", "\"name\""];

/// `/signup` and `/bootstrap` answer a non-object body `invalid_json_body`
/// before any connection — `/bootstrap` ahead of its window and token checks
/// too — and `/password` answers a caller with no credential its 401 first,
/// whatever the body.
#[tokio::test]
async fn non_object_bodies_answer_invalid_json_body() {
    for body in NON_OBJECT_BODIES {
        let reply = post_raw(
            signup_router(signup_state(unreachable_pool())),
            "/signup",
            &[],
            body,
        )
        .await;
        assert_json(
            &reply,
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_json_body"}"#,
        );
        for (store, available) in [
            (Some(token_store(false)), true),
            (Some(token_store(false)), false),
            (None, true),
        ] {
            let router = bootstrap_router(bootstrap_state(unreachable_pool(), store, available));
            let reply = post_raw(router, "/bootstrap", &[], body).await;
            assert_json(
                &reply,
                StatusCode::BAD_REQUEST,
                r#"{"error":"invalid_json_body"}"#,
            );
        }
        let router = account_router(account_state(unreachable_pool(), StubHasher::accepting()));
        let reply = post_raw(router, "/password", &[], body).await;
        assert_json(
            &reply,
            StatusCode::UNAUTHORIZED,
            r#"{"error":"authentication_required"}"#,
        );
    }
}

/// Assert the credential-read fault's answer: the TS twin's, where the failed
/// read throws out of the auth middleware into Hono's default error handler —
/// status 500, a plain-text `Internal Server Error`, and no `Set-Cookie`.
#[track_caller]
fn assert_credential_read_500(reply: &Reply) {
    assert_eq!(
        (
            reply.status,
            reply.content_type.as_deref(),
            reply.set_cookie.as_deref(),
            reply.body.as_str()
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("text/plain; charset=UTF-8"),
            None,
            "Internal Server Error"
        ),
    );
}

/// The `last_used_at` of the API token `token_id`.
async fn token_last_used_at(pool: &Pool, token_id: &str) -> Option<String> {
    pool.get()
        .await
        .expect("pool.get")
        .query_one(
            "SELECT last_used_at::text FROM api_token WHERE id = $1",
            &[&token_id],
        )
        .await
        .expect("the token row reads")
        .get(0)
}

/// A credential checkout that fails is not "no credential": the walk stops
/// there and each route answers the database-unavailable 503, not the 401 it
/// gives a caller with no credential. The session is real — the same cookie is
/// served over a pool that connects — and the fault is a pool that refuses the
/// read's checkout. (A failed query on the leg is the text 500 —
/// `status_credential_query_failure_answers_the_text_500`.)
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_failed_credential_checkout_answers_the_503() {
    let pool = fresh_db_pool().await;
    let (_, _, cookie) = seed_session(&pool, "credential_read").await;
    let reply = get_status(account_routes(pool), &cookie).await;
    assert_eq!(reply.status, StatusCode::OK, "the session is live");

    let reply = get_status(account_routes(common::budgeted_pool(0)), &cookie).await;
    assert_flat_503(&reply);
    let reply = post_logout(account_routes(common::budgeted_pool(0)), &cookie).await;
    assert_flat_503(&reply);
    let reply = post_password(account_routes(common::budgeted_pool(0)), &cookie).await;
    assert_flat_503(&reply);
}

/// A failed cookie read does not hand the request to the bearer beside it:
/// the walk stops at the cookie leg, so the bearer neither authenticates the
/// request nor has its `last_used_at` touched. The pool hands the cookie leg
/// a dead connection and every later checkout a live one, so the bearer leg
/// would read its token if the walk went on to it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_failed_cookie_read_does_not_fall_through_to_the_bearer() {
    let pool = fresh_db_pool().await;
    let (account_id, _, cookie) = seed_session(&pool, "fall_through").await;
    let control = fuz_testing::mint_api_token(&pool, account_id, &TokenScopeDocument::full()).await;
    let token = fuz_testing::mint_api_token(&pool, account_id, &TokenScopeDocument::full()).await;

    // the control: the bearer alone authenticates, and its touch lands
    let bearer = format!("Bearer {}", control.token);
    let reply = send(
        account_routes(pool.clone()),
        "GET",
        "/status",
        &[(header::AUTHORIZATION, &bearer)],
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "the bearer is live");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while token_last_used_at(&pool, &control.id).await.is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the control's touch never landed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let bearer = format!("Bearer {}", token.token);
    let reply = send(
        account_routes(pool_with_dead_checkout(1)),
        "GET",
        "/status",
        &[(header::COOKIE, &cookie), (header::AUTHORIZATION, &bearer)],
        None,
    )
    .await;
    assert_credential_read_500(&reply);
    // a touch the walk spawned would land well inside this window: the
    // control's did above
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        token_last_used_at(&pool, &token.id).await,
        None,
        "the bearer's last_used_at stays untouched"
    );
}

/// The answers that need the database — the denials past the credential read
/// and each account route's success — on a schema with no fault in it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn answers_past_the_credential_read_keep_their_shape() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id, cookie) = seed_session(&pool, "neighbour").await;
    let refusing = || account_router(account_state(pool.clone(), StubHasher::refusing()));

    // /status: the authenticated body.
    let reply = get_status(account_routes(pool.clone()), &cookie).await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    assert_eq!(
        body["account"]["id"],
        json!(account_id.to_string()),
        "{body}"
    );
    assert_eq!(body["account"]["username"], json!("neighbour"));
    assert_eq!(
        body["actor"],
        json!({"id": actor_id.to_string(), "name": "neighbour"})
    );
    assert_eq!(body["role_grants"], json!([]));

    // /login: a refused password, then an accepted one.
    let reply = post_login(refusing(), "neighbour").await;
    assert_json(
        &reply,
        StatusCode::UNAUTHORIZED,
        r#"{"error":"invalid_credentials"}"#,
    );
    let reply = post_login(account_routes(pool.clone()), "neighbour").await;
    assert_json(&reply, StatusCode::OK, r#"{"ok":true}"#);

    // /password: a body that is not the input shape, a refused current
    // password, then the change — which revokes the seeded session and the
    // one the login above minted.
    let reply = send(
        account_routes(pool.clone()),
        "POST",
        "/password",
        &[(header::COOKIE, cookie.as_str())],
        Some(&json!({"current_password": "the-current-password"})),
    )
    .await;
    assert_json(
        &reply,
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_request_body"}"#,
    );
    // …and a body that is not an object, refused past the credential read
    for body in NON_OBJECT_BODIES {
        let reply = post_raw(
            account_routes(pool.clone()),
            "/password",
            &[(header::COOKIE, cookie.as_str())],
            body,
        )
        .await;
        assert_json(
            &reply,
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_json_body"}"#,
        );
    }
    let reply = post_password(refusing(), &cookie).await;
    assert_json(
        &reply,
        StatusCode::UNAUTHORIZED,
        r#"{"error":"invalid_credentials"}"#,
    );
    let reply = post_password(account_routes(pool.clone()), &cookie).await;
    assert_json(
        &reply,
        StatusCode::OK,
        r#"{"ok":true,"sessions_revoked":2,"tokens_revoked":0}"#,
    );

    // /logout: a bearer token holds no session to end; a session does.
    let token = fuz_testing::mint_api_token(&pool, account_id, &TokenScopeDocument::full()).await;
    let bearer = format!("Bearer {}", token.token);
    let reply = send(
        account_routes(pool.clone()),
        "POST",
        "/logout",
        &[(header::AUTHORIZATION, bearer.as_str())],
        None,
    )
    .await;
    assert_json(
        &reply,
        StatusCode::FORBIDDEN,
        r#"{"error":"credential_type_required","required_credential_types":["session"]}"#,
    );
    let cookie = fuz_testing::mint_session_cookie(
        &pool,
        &fuz_testing::testing_keyring(),
        account_id,
        SESSION_COOKIE_NAME,
    )
    .await;
    let reply = post_logout(account_routes(pool), &cookie).await;
    assert_json(
        &reply,
        StatusCode::OK,
        r#"{"ok":true,"username":"neighbour"}"#,
    );
}

// -- /password: audit rows and rate limits -------------------------------------

/// Every `password_change` audit row, oldest first: its outcome, its account,
/// and its metadata.
async fn password_change_audits(pool: &Pool) -> Vec<(String, Option<Uuid>, Value)> {
    pool.get()
        .await
        .expect("pool.get")
        .query(
            "SELECT outcome, account_id, COALESCE(metadata::text, 'null') FROM audit_log \
             WHERE event_type = 'password_change' ORDER BY seq",
            &[],
        )
        .await
        .expect("audit rows")
        .iter()
        .map(|row| {
            let metadata = serde_json::from_str(row.get(2)).expect("metadata is JSON");
            (row.get(0), row.get(1), metadata)
        })
        .collect()
}

/// A [`ConnectionCloser`] that records, at each account close, how many
/// `password_change` audit rows a separate connection already reads.
struct AuditWatchingCloser {
    pool: Pool,
    audited_at_close: Mutex<Vec<usize>>,
}

impl fuz_http::ShutdownCloser for AuditWatchingCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for AuditWatchingCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        assert!(
            matches!(target, ConnectionCloseTarget::Account(_)),
            "the password route closes by account"
        );
        let audited = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(password_change_audits(&self.pool))
        });
        self.audited_at_close.lock().unwrap().push(audited.len());
        0
    }
}

/// A change that fails writes no `password_change` row of either outcome —
/// the success row is written after the commit, never ahead of it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_failed_change_audits_nothing() {
    for fault in ["session revocation", "token revocation", "commit"] {
        let pool = fresh_db_pool().await;
        let (_, cookie) = seed_credentials(&pool, "password_unaudited").await;
        match fault {
            "session revocation" => refuse_statement(&pool, "DELETE", "auth_session").await,
            "token revocation" => refuse_statement(&pool, "DELETE", "api_token").await,
            _ => refuse_commit(&pool, "account").await,
        }

        let reply = post_password(account_routes(pool.clone()), &cookie).await;

        assert_flat_500(&reply);
        assert_eq!(password_change_audits(&pool).await, [], "a failed {fault}");
    }
}

/// The committed change is audited once, as a success on the account, with
/// the counts it revoked and the credential type it arrived on — and the
/// close has already run when that row is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_committed_change_closes_before_it_audits_its_counts() {
    let pool = fresh_db_pool().await;
    // Two sessions and one token, so the two counts cannot stand in for each
    // other.
    let (account_id, cookie) = seed_credentials(&pool, "password_audited").await;
    fuz_testing::mint_session_cookie(
        &pool,
        &fuz_testing::testing_keyring(),
        account_id,
        SESSION_COOKIE_NAME,
    )
    .await;
    let closer = Arc::new(AuditWatchingCloser {
        pool: pool.clone(),
        audited_at_close: Mutex::new(Vec::new()),
    });
    let mut state = account_state(pool.clone(), StubHasher::accepting());
    state.connection_closer = Arc::<AuditWatchingCloser>::clone(&closer);

    let reply = post_password(account_router(state), &cookie).await;

    assert_json(
        &reply,
        StatusCode::OK,
        r#"{"ok":true,"sessions_revoked":2,"tokens_revoked":1}"#,
    );
    assert_eq!(
        *closer.audited_at_close.lock().unwrap(),
        [0],
        "one close, before the audit row exists"
    );
    assert_eq!(
        password_change_audits(&pool).await,
        [(
            "success".to_owned(),
            Some(account_id),
            json!({"sessions_revoked": 2, "tokens_revoked": 1, "credential_type": "session"}),
        )]
    );
}

/// A rate limiter with a cap of `max_attempts` over a window no test outlives.
fn limiter(max_attempts: u32) -> Arc<RateLimiter> {
    Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts,
        window_ms: 60 * 60_000,
        max_keys: None,
    }))
}

/// The cap every limiter in the rate-limit cases is built with.
const ATTEMPTS_MAX: u32 = 5;

/// How many attempts `limiter` holds for `key`, found by spending the rest of
/// its budget — so read each bucket once, at the end of a case.
fn attempts(limiter: &RateLimiter, key: &str) -> u32 {
    let mut spent = 0;
    while matches!(limiter.check(key), RateLimitResult::Allowed) {
        limiter.record(key);
        spent += 1;
    }
    ATTEMPTS_MAX - spent
}

/// The two buckets `/password` shares with `/login`, and a router over them.
struct Limited {
    ip: Arc<RateLimiter>,
    account: Arc<RateLimiter>,
}

impl Limited {
    fn new() -> Self {
        Self {
            ip: limiter(ATTEMPTS_MAX),
            account: limiter(ATTEMPTS_MAX),
        }
    }

    fn routes(&self, pool: &Pool, hasher: Arc<dyn PasswordHasher>) -> Router {
        let mut state = account_state(pool.clone(), hasher);
        state.login_ip_rate_limiter = Some(Arc::clone(&self.ip));
        state.login_account_rate_limiter = Some(Arc::clone(&self.account));
        account_router(state)
    }

    /// The attempts held on the IP bucket and on `account_id`'s bucket. No
    /// request here carries a resolved client IP, so the IP key is the shared
    /// unresolved one.
    fn attempts(&self, account_id: Uuid) -> (u32, u32) {
        (
            attempts(&self.ip, fuz_http::UNRESOLVED_CLIENT_IP),
            attempts(&self.account, &account_id.to_string()),
        )
    }
}

/// A refused current password costs one attempt on each bucket.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_refused_current_password_costs_an_attempt_on_each_bucket() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_limited_wrong").await;
    let limited = Limited::new();

    let reply = post_password(limited.routes(&pool, StubHasher::refusing()), &cookie).await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_eq!(limited.attempts(account_id), (1, 1));
}

/// A change that goes through clears the account's bucket and leaves the IP
/// bucket — the one `/login` spends from the same address — as it was.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_change_clears_the_account_bucket_and_not_the_ip_bucket() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_limited_ok").await;
    let limited = Limited::new();
    let reply = post_password(limited.routes(&pool, StubHasher::refusing()), &cookie).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);

    let reply = post_password(limited.routes(&pool, StubHasher::accepting()), &cookie).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(limited.attempts(account_id), (1, 0));
}

/// A change whose new-password hash fails keeps the account's failure
/// history: the bucket is cleared only once the hash and the UPDATE have
/// settled, so a caller observing 500s can't wipe it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_change_that_fails_to_hash_keeps_the_account_bucket() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_limited_hash_fault").await;
    let limited = Limited::new();
    let reply = post_password(limited.routes(&pool, StubHasher::refusing()), &cookie).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);

    let reply = post_password(
        limited.routes(&pool, StubHasher::failing_to_hash()),
        &cookie,
    )
    .await;

    assert_eq!(
        reply.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        reply.body
    );
    assert_eq!(limited.attempts(account_id), (1, 1));
}

/// A concurrent burst of refused changes gets at most the cap past the
/// limiter: each attempt is reserved before the credential walk, so the burst
/// can't all pass before any of it records.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_burst_of_refused_changes_spends_at_most_the_cap() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_limited_burst").await;
    let limited = Limited::new();
    let router = limited.routes(&pool, StubHasher::refusing());

    let replies = futures::future::join_all(
        (0..ATTEMPTS_MAX * 2).map(|_| post_password(router.clone(), &cookie)),
    )
    .await;

    let refused = replies
        .iter()
        .filter(|r| r.status == StatusCode::UNAUTHORIZED)
        .count();
    let limited_replies = replies
        .iter()
        .filter(|r| r.status == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!(refused, ATTEMPTS_MAX as usize, "{replies:?}");
    assert_eq!(limited_replies, ATTEMPTS_MAX as usize, "{replies:?}");
    assert_eq!(limited.attempts(account_id), (ATTEMPTS_MAX, ATTEMPTS_MAX));
}

/// A superseded change is a failed attempt: the settled UPDATE cleared the
/// account's bucket, and the refusal then costs one attempt on each.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_superseded_change_costs_an_attempt_on_each_bucket() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_limited_raced").await;
    let limited = Limited::new();
    let reply = post_password(limited.routes(&pool, StubHasher::refusing()), &cookie).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    let superseding = Arc::new(SupersedingHasher {
        pool: pool.clone(),
        account_id,
    });

    let reply = post_password(limited.routes(&pool, superseding), &cookie).await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_eq!(limited.attempts(account_id), (2, 1));
}

/// A [`PasswordHasher`] whose `verify` and `hash` never finish, signalling
/// `started` once they are first polled — the Argon2 work a request is
/// dropped in the middle of.
struct ParkedHasher {
    started: Arc<tokio::sync::Notify>,
}

impl ParkedHasher {
    fn new() -> (Arc<Self>, Arc<tokio::sync::Notify>) {
        let started = Arc::new(tokio::sync::Notify::new());
        let hasher = Arc::new(Self {
            started: Arc::clone(&started),
        });
        (hasher, started)
    }
}

impl PasswordHasher for ParkedHasher {
    fn hash(&self, _password: String) -> BoxFuture<'static, Result<HashedPassword, String>> {
        let started = Arc::clone(&self.started);
        async move {
            started.notify_one();
            std::future::pending().await
        }
        .boxed()
    }

    fn verify(&self, _password: String, _hash: String) -> BoxFuture<'static, bool> {
        let started = Arc::clone(&self.started);
        async move {
            started.notify_one();
            std::future::pending().await
        }
        .boxed()
    }

    fn dummy_hash(&self) -> &'static str {
        "parked-dummy-hash"
    }
}

/// Drive `request` until the hasher starts, then drop it — a client that
/// disconnects mid-verify. False if the request finished first.
async fn drop_once_parked(
    started: &tokio::sync::Notify,
    request: impl Future<Output = Reply>,
) -> bool {
    tokio::select! {
        _ = request => false,
        () = started.notified() => true,
    }
}

/// A login dropped mid-verify costs an attempt on each bucket, as a refused
/// one does: the Argon2 work it started runs on regardless, so releasing the
/// slots would let one address keep every Argon2 permit busy uncharged.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_dropped_mid_verify_costs_an_attempt_on_each_bucket() {
    let pool = fresh_db_pool().await;
    let (account_id, _) = seed_credentials(&pool, "login_dropped_mid_verify").await;
    let limited = Limited::new();
    let (hasher, started) = ParkedHasher::new();
    let router = limited.routes(&pool, hasher);

    let parked = drop_once_parked(&started, post_login(router, "login_dropped_mid_verify")).await;

    assert!(parked, "the login finished before its verify started");
    assert_eq!(limited.attempts(account_id), (1, 1));
}

/// A password change dropped mid-verify of the current password costs an
/// attempt on each bucket, as on login.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn password_dropped_mid_verify_costs_an_attempt_on_each_bucket() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_credentials(&pool, "password_dropped_mid_verify").await;
    let limited = Limited::new();
    let (hasher, started) = ParkedHasher::new();
    let router = limited.routes(&pool, hasher);

    let parked = drop_once_parked(&started, post_password(router, &cookie)).await;

    assert!(parked, "the change finished before its verify started");
    assert_eq!(limited.attempts(account_id), (1, 1));
}
