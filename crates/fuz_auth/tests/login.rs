//! Integration tests for the login handler against a real `PostgreSQL`.
//!
//! Twin of `fuz_app`'s `src/test/auth/login_timing.db.test.ts` plus the
//! rate-limit + audit legs of `account_routes.ts`'s `POST /login`. The TS
//! spine is canonical for shape; these pin the same observable contract on
//! the Rust side:
//!
//! - **Enumeration prevention / dummy-hash equalization** — a missing account
//!   still runs a password `verify` against the pre-computed dummy hash, so
//!   present-vs-absent timing doesn't leak. The Rust shape selects the hash
//!   (real or dummy) then calls one `verify`, where TS has separate
//!   `verify_password` / `verify_dummy` methods; the behavior pinned here is
//!   identical (`fuz_app` `docs/security.md` §"Account Enumeration Prevention").
//! - **Record-on-failure / reset-on-success, account-grain only** — both
//!   counters record on a failed attempt; only the per-account one is cleared
//!   by a success. The IP aggregate is the distributed-spray backstop, so a
//!   success must not refund it — see
//!   `login_ip_budget_survives_interleaved_successes`.
//! - **Audit rows** — both success and failure write a `login` audit row
//!   (failure carries `account_id` only when the account resolved).
//! - **Per-account session cap** — logging in past `DEFAULT_MAX_SESSIONS`
//!   evicts the oldest session rather than refusing the login, so the durable
//!   count stays at the cap and the survivors are the newest.
//! - **Rate-limit fast path** — an exhausted bucket returns 429 *before* any
//!   `verify` / DB work runs.
//! - **Denial timing floor** — both 401 paths elapse at least the configured
//!   floor, so the residual DB-presence delta between "no such account" and
//!   "account exists, wrong password" isn't an enumeration oracle (the
//!   `timing.rs` unit tests pin the `max(work, floor)` mechanism under a
//!   paused clock; these pin that the handler applies it end-to-end).
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test login -- --ignored --test-threads=1
//! ```
//!
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode, header::CONTENT_TYPE, header::ORIGIN, header::SET_COOKIE};
use axum::response::Response;
use futures::future::{BoxFuture, FutureExt};
use fuz_auth::account_login::{DEFAULT_LOGIN_FAIL_FLOOR_MS, DEFAULT_LOGIN_FAIL_JITTER_MS};
use fuz_auth::{
    AccountRouteState, AuditEmitter, ConnectionCloseTarget, ConnectionCloser, DEFAULT_MAX_SESSIONS,
    HashedPassword, NoopConnectionCloser, PASSWORD_LENGTH_MAX, PasswordHashError, PasswordHasher,
    RateLimitResult, RateLimiter, RateLimiterOptions, USERNAME_PROVIDED_LENGTH_MAX, login_handler,
    query_session_enforce_limit,
};
use fuz_db::{Pool, create_pool};
use fuz_http::ClientIp;

mod common;
use common::fresh_db_pool;

/// Sentinel returned by [`RecordingHasher::dummy_hash`] — the login handler
/// feeds this to `verify` on the account-not-found path, so a recorded value
/// equal to it proves the miss was equalized against a dummy verify.
const DUMMY_HASH_SENTINEL: &str = "$argon2id$dummy$recording-sentinel";

/// A `PasswordHasher` that records every hash passed to `verify` and accepts a
/// single configured password. Lets the tests assert *which* stored hash the
/// handler verified against (the equalization mechanism) deterministically,
/// without a flaky wall-clock measurement — the same role the TS twin's
/// `verify_password` / `verify_dummy` call counters play.
struct RecordingHasher {
    /// `verify` returns `true` exactly when the supplied password equals this.
    accept_password: String,
    /// Each `verify` call appends the `hash` argument it received.
    verify_hashes: Arc<Mutex<Vec<String>>>,
}

impl RecordingHasher {
    fn new(accept_password: &str) -> (Arc<Self>, Arc<Mutex<Vec<String>>>) {
        let verify_hashes = Arc::new(Mutex::new(Vec::new()));
        let hasher = Arc::new(Self {
            accept_password: accept_password.to_owned(),
            verify_hashes: Arc::clone(&verify_hashes),
        });
        (hasher, verify_hashes)
    }
}

impl PasswordHasher for RecordingHasher {
    fn hash(
        &self,
        _password: String,
    ) -> BoxFuture<'static, Result<HashedPassword, PasswordHashError>> {
        async move { Ok(HashedPassword::new("recording-hash".to_owned())) }.boxed()
    }

    fn verify(&self, password: String, hash: String) -> BoxFuture<'static, bool> {
        self.verify_hashes.lock().unwrap().push(hash);
        let ok = password == self.accept_password;
        async move { ok }.boxed()
    }

    fn dummy_hash(&self) -> &'static str {
        DUMMY_HASH_SENTINEL
    }
}

/// Build an `AccountRouteState` with the supplied hasher + rate limiters and
/// no-op everything else. The fixture gate's one-origin allowlist (no `Origin`
/// header ⇒ allowed); `bootstrap_available` is irrelevant to login.
fn build_state(
    pool: Pool,
    hasher: Arc<dyn PasswordHasher>,
    audit: Arc<AuditEmitter>,
    login_ip_rate_limiter: Option<Arc<RateLimiter>>,
    login_account_rate_limiter: Option<Arc<RateLimiter>>,
) -> AccountRouteState {
    let connection_closer: Arc<dyn ConnectionCloser> = Arc::new(NoopConnectionCloser);
    AccountRouteState {
        gate: fuz_testing::testing_auth_gate(pool),
        password_hasher: hasher,
        audit,
        connection_closer,
        bootstrap_available: Arc::new(AtomicBool::new(false)),
        login_ip_rate_limiter,
        login_account_rate_limiter,
        // production values: the denial-floor tests below pin them end to end
        login_fail_floor_ms: DEFAULT_LOGIN_FAIL_FLOOR_MS,
        login_fail_jitter_ms: DEFAULT_LOGIN_FAIL_JITTER_MS,
    }
}

/// Serialize a `{username, password}` login body to `Bytes` (the handler
/// takes the raw body so it controls the parse-error → 400 mapping).
fn login_body(username: &str, password: &str) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&serde_json::json!({ "username": username, "password": password }))
            .expect("serialize login body"),
    )
}

/// Headers for a JSON body, as every real login request carries.
fn json_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    headers
}

/// Drive `login_handler` directly. Returns the raw `Response` — the tests read
/// `.status()` / `.headers()` (no body parse needed for these assertions).
async fn call_login(
    state: &AccountRouteState,
    ip: Option<&str>,
    username: &str,
    password: &str,
) -> Response {
    let client_ip = ip.map(|s| Extension(ClientIp(s.to_owned())));
    login_handler(
        State(state.clone()),
        client_ip,
        json_headers(),
        login_body(username, password),
    )
    .await
}

/// Seed an `account` row with a chosen `password_hash` (canonical lowercase
/// username) and return its id. The `RecordingHasher` makes the stored hash's
/// *value* the assertion target, so it's a literal here, not a real Argon2 string.
async fn seed_account_with_hash(pool: &Pool, username: &str, password_hash: &str) -> uuid::Uuid {
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "INSERT INTO account (username, password_hash) VALUES ($1, $2) RETURNING id",
            &[&username, &password_hash],
        )
        .await
        .expect("insert account");
    row.get(0)
}

/// Seed an `account` row with a chosen email + `password_hash` and return its
/// id. Backs the username-or-email lookup tests — the email is stored with its
/// original case so the case-insensitive lookup assertion is meaningful.
async fn seed_account_with_email_and_hash(
    pool: &Pool,
    username: &str,
    email: &str,
    password_hash: &str,
) -> uuid::Uuid {
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "INSERT INTO account (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
            &[&username, &email, &password_hash],
        )
        .await
        .expect("insert account");
    row.get(0)
}

/// A pool that never connects — the pre-DB guards below return before any DB
/// access, so those tests run in the fast (no-Postgres) lane. `create_pool`
/// only parses the URL; `deadpool` connects lazily on first `get()`.
fn pool_no_db() -> Pool {
    create_pool(&common::test_url(), &fuz_db::PoolOptions::default()).expect("create_pool")
}

// -- Pre-DB guards (no Postgres) --------------------------------------------

#[tokio::test]
async fn login_rejects_invalid_input() {
    // The input guards at the top of the handler mirror the TS `LoginInput`
    // schema (`UsernameProvided` non-empty / max 255 / non-empty-after-trim,
    // `PasswordProvided` non-empty / max 300): every malformed-body shape 400s
    // *before* any DB lookup or password verify, never falling through to a
    // lookup-miss 401.
    let (hasher, verify_hashes) = RecordingHasher::new("unused");
    let audit = Arc::new(AuditEmitter::new(pool_no_db()));
    let state = build_state(pool_no_db(), hasher, audit, None, None);

    let oversized_password = "a".repeat(PASSWORD_LENGTH_MAX + 1);
    let oversized_username = "a".repeat(USERNAME_PROVIDED_LENGTH_MAX + 1);
    // 256 `\u{00FC}` is 512 bytes and 256 UTF-16 code units — over the
    // ceiling in the units the twin counts, not merely in bytes.
    let oversized_multibyte_username = "\u{00FC}".repeat(USERNAME_PROVIDED_LENGTH_MAX + 1);
    for (label, username, password) in [
        ("empty username", "", "valid-password-123"),
        ("whitespace-only username", "   ", "valid-password-123"),
        ("oversized password", "alice", oversized_password.as_str()),
        (
            "oversized username",
            oversized_username.as_str(),
            "valid-password-123",
        ),
        (
            "oversized multibyte username",
            oversized_multibyte_username.as_str(),
            "valid-password-123",
        ),
        ("empty password", "alice", ""),
    ] {
        let response = call_login(&state, None, username, password).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{label} must be rejected with 400"
        );
    }
    assert!(
        verify_hashes.lock().unwrap().is_empty(),
        "rejected input must not reach the password verify"
    );
}

#[tokio::test]
async fn login_rejects_unknown_body_field() {
    // `deny_unknown_fields` on `LoginInput` mirrors the TS `object`: an
    // extra body key fails deserialization and the handler maps it to 400
    // `invalid_request_body` (not axum's default 422, not a silent ignore),
    // before any DB / verify work.
    let (hasher, verify_hashes) = RecordingHasher::new("unused");
    let audit = Arc::new(AuditEmitter::new(pool_no_db()));
    let state = build_state(pool_no_db(), hasher, audit, None, None);

    let body = Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "username": "alice",
            "password": "valid-password-123",
            "foo": "bar",
        }))
        .expect("serialize login body"),
    );
    let response = login_handler(State(state), None, json_headers(), body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        verify_hashes.lock().unwrap().is_empty(),
        "unknown-field body must not reach the password verify"
    );
}

#[tokio::test]
async fn login_answers_invalid_json_body_for_a_non_object_body() {
    // The twin's input validation: a body that doesn't parse, or parses to
    // anything but an object, is `invalid_json_body` — never the schema
    // refusal `invalid_request_body`.
    let (hasher, verify_hashes) = RecordingHasher::new("unused");
    let audit = Arc::new(AuditEmitter::new(pool_no_db()));
    let state = build_state(pool_no_db(), hasher, audit, None, None);

    for body in ["{", "", "[]", "null", "5"] {
        let response = login_handler(
            State(state.clone()),
            None,
            json_headers(),
            Bytes::from(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body:?}");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        assert_eq!(&bytes[..], br#"{"error":"invalid_json_body"}"#, "{body:?}");
    }
    assert!(
        verify_hashes.lock().unwrap().is_empty(),
        "a non-object body must not reach the password verify"
    );
}

#[tokio::test]
async fn login_rejects_disallowed_origin() {
    // The origin gate runs first in `login_handler`: a request whose `Origin`
    // isn't in the allowlist is refused 403 before any DB / verify work. The
    // predicate itself is fuz_http-tested; this pins that it's *wired in*.
    let (hasher, verify_hashes) = RecordingHasher::new("unused");
    let connection_closer: Arc<dyn ConnectionCloser> = Arc::new(NoopConnectionCloser);
    let state = AccountRouteState {
        gate: fuz_testing::testing_auth_gate(pool_no_db()),
        password_hasher: hasher,
        audit: Arc::new(AuditEmitter::new(pool_no_db())),
        connection_closer,
        bootstrap_available: Arc::new(AtomicBool::new(false)),
        login_ip_rate_limiter: None,
        login_account_rate_limiter: None,
        login_fail_floor_ms: DEFAULT_LOGIN_FAIL_FLOOR_MS,
        login_fail_jitter_ms: DEFAULT_LOGIN_FAIL_JITTER_MS,
    };

    let mut headers = json_headers();
    headers.insert(ORIGIN, "http://evil.example".parse().unwrap());
    let response = login_handler(
        State(state),
        None,
        headers,
        login_body("alice", "correct-password"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        verify_hashes.lock().unwrap().is_empty(),
        "origin-denied request must not reach the password verify"
    );
}

#[tokio::test]
async fn login_refuses_bodies_a_browser_sends_without_a_preflight() {
    // a `text/plain` (or untyped) POST reaches the server from any page with
    // no CORS preflight, carrying the session cookie when the page is
    // same-site (another localhost port), so the handler refuses it before
    // the body is read
    let (hasher, verify_hashes) = RecordingHasher::new("unused");
    let audit = Arc::new(AuditEmitter::new(pool_no_db()));
    let state = build_state(pool_no_db(), hasher, audit, None, None);

    let mut text_plain = HeaderMap::new();
    text_plain.insert(CONTENT_TYPE, "text/plain;charset=UTF-8".parse().unwrap());
    for headers in [HeaderMap::new(), text_plain] {
        let response = login_handler(
            State(state.clone()),
            None,
            headers,
            login_body("alice", "correct-password"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    assert!(
        verify_hashes.lock().unwrap().is_empty(),
        "a refused content type must not reach the password verify"
    );
}

// -- Enumeration prevention / dummy-hash equalization -----------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_missing_account_verifies_against_dummy_hash() {
    // The account-not-found path must still run `verify` against the dummy
    // hash so its timing matches a real wrong-password attempt. Deterministic
    // shadow of the wall-clock property: the recorded hash is the dummy.
    let pool = fresh_db_pool().await;
    let (hasher, verify_hashes) = RecordingHasher::new("unused");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool, hasher, audit, None, None);

    let response = call_login(&state, Some("1.2.3.4"), "ghost", "any-password-123").await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let recorded = verify_hashes.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec![DUMMY_HASH_SENTINEL.to_owned()],
        "missing account must run exactly one verify, against the dummy hash"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_username_ceiling_counts_utf16_code_units() {
    // `UsernameProvided` caps at 255 on `String.length` — UTF-16 code
    // units. 200 `\u{00FC}` is 400 bytes but only 200 units, so a byte count
    // refused a username the twin admits. Admitted here means the guard falls
    // through to the lookup: a miss 401 against the dummy hash, not a 400.
    let pool = fresh_db_pool().await;
    let (hasher, verify_hashes) = RecordingHasher::new("unused");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool, hasher, audit, None, None);

    let username = "\u{00FC}".repeat(200);
    assert_eq!(username.len(), 400, "bytes");
    let response = call_login(&state, Some("1.2.3.4"), &username, "any-password-123").await;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "200 code units is under the {USERNAME_PROVIDED_LENGTH_MAX} ceiling"
    );
    assert_eq!(
        verify_hashes.lock().unwrap().clone(),
        vec![DUMMY_HASH_SENTINEL.to_owned()],
        "an admitted username reaches the lookup, not the malformed-body 400"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_wrong_password_verifies_against_real_hash() {
    // The non-diverging sibling of the dummy-hash test: an existing account
    // with a wrong password verifies against the *real* stored hash. Both this
    // and the missing-account path run one verify — that's the equalization.
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, verify_hashes) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool, hasher, audit, None, None);

    let response = call_login(&state, Some("1.2.3.4"), "alice", "wrong-password").await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let recorded = verify_hashes.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["stored-hash-alice".to_owned()],
        "existing account must verify against its real stored hash, not the dummy"
    );
}

// -- Username-or-email lookup -----------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_by_email_case_insensitively_resolves_account() {
    // Convergence to fuz_app's `query_account_by_username_or_email`: the login
    // identifier matches against email as well as username, case-insensitively.
    // Seed a mixed-case email, log in with the all-lowercase form + correct
    // password ⇒ 200 + Set-Cookie, and the recorded verify hash is the *real*
    // stored hash (proving the email lookup resolved the account, not the
    // dummy-hash miss path). Cross-impl parity is pinned end-to-end by
    // `fuz_app`'s `username_parity` cross suite; this is the Rust-native pin.
    let pool = fresh_db_pool().await;
    let alice_id =
        seed_account_with_email_and_hash(&pool, "alice", "Alice@Example.com", "stored-hash-alice")
            .await;
    let (hasher, verify_hashes) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool.clone(), hasher, audit, None, None);

    let response = call_login(
        &state,
        Some("1.2.3.4"),
        "alice@example.com",
        "correct-password",
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "login by the lowercased form of a mixed-case stored email must succeed"
    );
    assert!(
        response.headers().contains_key(SET_COOKIE),
        "successful email login must set the session cookie"
    );
    let recorded = verify_hashes.lock().unwrap().clone();
    assert_eq!(
        recorded,
        vec!["stored-hash-alice".to_owned()],
        "email lookup must resolve the real account (verify its stored hash, not the dummy)"
    );

    let client = pool.get().await.expect("pool.get");
    let session_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM auth_session WHERE account_id = $1",
            &[&alice_id],
        )
        .await
        .expect("session count")
        .get(0);
    assert_eq!(session_count, 1, "exactly one session row created");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_by_username_still_resolves_when_account_has_email() {
    // Regression guard for the `OR`-query: adding the email branch must not
    // break the username branch. An account that also carries an email still
    // logs in by its username.
    let pool = fresh_db_pool().await;
    seed_account_with_email_and_hash(&pool, "alice", "alice@example.com", "stored-hash-alice")
        .await;
    let (hasher, verify_hashes) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool, hasher, audit, None, None);

    let response = call_login(&state, Some("1.2.3.4"), "alice", "correct-password").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        verify_hashes.lock().unwrap().clone(),
        vec!["stored-hash-alice".to_owned()],
        "username lookup must still resolve the account when it also has an email"
    );
}

// -- Record-on-failure / account-grain reset-on-success ---------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_failure_records_rate_limit() {
    // A failed attempt records against both the IP and per-account buckets.
    // `max_attempts: 1` makes the post-failure `check` observably `Limited`.
    let pool = fresh_db_pool().await;
    let alice_id = seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let one = || {
        Arc::new(RateLimiter::new(RateLimiterOptions {
            max_attempts: 1,
            window_ms: 60_000,
            max_keys: None,
        }))
    };
    let ip_limiter = one();
    let account_limiter = one();
    let state = build_state(
        pool,
        hasher,
        audit,
        Some(Arc::clone(&ip_limiter)),
        Some(Arc::clone(&account_limiter)),
    );

    // First (and only) attempt: pre-checks pass at count 0, verify fails,
    // both buckets record.
    let response = call_login(&state, Some("10.0.0.5"), "alice", "wrong-password").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    assert!(
        matches!(
            ip_limiter.check("10.0.0.5"),
            RateLimitResult::Limited { .. }
        ),
        "IP bucket must record the failed attempt"
    );
    // Existing account ⇒ the per-account key is the account id string.
    assert!(
        matches!(
            account_limiter.check(&alice_id.to_string()),
            RateLimitResult::Limited { .. }
        ),
        "per-account bucket must record the failed attempt"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_success_resets_rate_limit() {
    // A successful login resets the per-account bucket. Counterfactual that
    // makes the reset observable: with `max_attempts: 3`, pre-seed 2 records
    // (pre-check still passes), succeed, then record 2 more — `Allowed` only
    // if the reset cleared the prior 2 (2 < 3); without the reset it would be
    // 4 ≥ 3 ⇒ `Limited`.
    //
    // The IP bucket is deliberately *not* symmetric — success must never clear
    // it. `login_ip_budget_survives_interleaved_successes` below is that half.
    let pool = fresh_db_pool().await;
    let alice_id = seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let account_limiter = Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts: 3,
        window_ms: 60_000,
        max_keys: None,
    }));
    let account_key = alice_id.to_string();
    account_limiter.record(&account_key);
    account_limiter.record(&account_key);
    let state = build_state(
        pool,
        hasher,
        audit,
        None,
        Some(Arc::clone(&account_limiter)),
    );

    let response = call_login(&state, Some("10.0.0.5"), "alice", "correct-password").await;
    assert_eq!(response.status(), StatusCode::OK);

    account_limiter.record(&account_key);
    account_limiter.record(&account_key);
    assert!(
        account_limiter.check(&account_key).is_allowed(),
        "success must have reset the per-account bucket (else 2 pre + 2 post ≥ 3 ⇒ Limited)"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_success_records_nothing_on_the_ip_bucket() {
    // A success neither clears the IP bucket nor charges it: both reservations
    // are released. With `max_attempts: 1`, one success that charged the
    // bucket would leave it `Limited`.
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let ip_limiter = limiter_of(1);
    let state = build_state(pool, hasher, audit, Some(Arc::clone(&ip_limiter)), None);

    let response = call_login(&state, Some("10.0.0.12"), "alice", "correct-password").await;
    assert_eq!(response.status(), StatusCode::OK);

    assert!(
        ip_limiter.check("10.0.0.12").is_allowed(),
        "a success must not charge the IP bucket"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_burst_of_correct_logins_all_succeed_past_the_ip_cap() {
    // Attempts count while in flight whatever their outcome, so a burst of
    // correct logins from one address meets the cap too. The ones past it wait
    // for a slot (up to `RESERVATION_WAIT_MAX`, at most the cap of them) rather
    // than being refused: a burst of twice the cap all succeeds, later.
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let ip_limiter = limiter_of(3);
    let state = build_state(pool, hasher, audit, Some(Arc::clone(&ip_limiter)), None);

    let responses = futures::future::join_all(
        (0..6).map(|_| call_login(&state, Some("10.0.0.13"), "alice", "correct-password")),
    )
    .await;

    let statuses: Vec<StatusCode> = responses.iter().map(Response::status).collect();
    assert!(
        statuses.iter().all(|s| *s == StatusCode::OK),
        "{statuses:?}"
    );
    assert!(ip_limiter.check("10.0.0.13").is_allowed());
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_ip_budget_survives_interleaved_successes() {
    // The distributed-spray backstop, stated adversarially: N failed guesses
    // against *distinct* usernames from one IP, interleaved with the attacker's
    // own successful logins, must still 429 within a bounded total-request
    // budget.
    //
    // This is the shape the reset made unbounded — the attacker needs only one
    // credential of their own (or, under open signup, none at all), and each
    // success zeroed the budget shared by every account reachable from that
    // address. The `budget` bound is what makes the test adversarial rather than
    // a behavior snapshot: a "decrement instead of zero" implementation still
    // loops forever at the cap and fails here, which is the point — that
    // alternative reads as a moderate compromise and is not one.
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "attacker", "stored-hash-attacker").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let max_attempts = 3_u32;
    let ip_limiter = Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts,
        window_ms: 60_000,
        max_keys: None,
    }));
    let state = build_state(pool, hasher, audit, Some(Arc::clone(&ip_limiter)), None);

    // Either leg may be the one that trips: the aggregate governs the *address*,
    // so once it fills, the attacker's own login is refused alongside the
    // guesses. That is the property — there is no move from this IP that buys
    // more attempts.
    let attacker_ip = Some("10.0.0.5");
    let mut budget = 0_u32;
    let mut limited = false;

    'spray: for i in 0..12 {
        // The attacker's own successful login — the move that must not refund
        // the whole IP window — then one guess against a fresh victim username,
        // so the per-account bucket never accumulates and only the IP aggregate
        // can stop this.
        for (username, password, expected) in [
            ("attacker".to_owned(), "correct-password", StatusCode::OK),
            (format!("victim_{i}"), "wrong", StatusCode::UNAUTHORIZED),
        ] {
            let response = call_login(&state, attacker_ip, &username, password).await;
            budget += 1;
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                limited = true;
                break 'spray;
            }
            assert_eq!(
                response.status(),
                expected,
                "unexpected status for {username}"
            );
        }
    }

    assert!(
        limited,
        "the per-IP aggregate must eventually 429 the spray"
    );
    assert!(
        budget <= 8,
        "interleaved successes must not extend the per-IP budget (spent {budget} requests)"
    );
}

// -- Audit rows -------------------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_failure_missing_account_audits_without_account_id() {
    // Failure on the account-not-found path: a `login` failure row carrying the
    // submitted (canonical) username and the client IP, but **no** `account_id`
    // (there is no account to attribute it to).
    let pool = fresh_db_pool().await;
    let (hasher, _) = RecordingHasher::new("unused");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool.clone(), hasher, audit, None, None);

    let response = call_login(&state, Some("9.9.9.9"), "Ghost", "any-password-123").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The handler awaits the emit `JoinHandle`, so the row is committed by the
    // time the response returns — no poll/sleep needed.
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "SELECT outcome, account_id, ip, metadata::text FROM audit_log
             WHERE event_type = 'login' AND outcome = 'failure'
             ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .expect("audit row");
    let outcome: String = row.get(0);
    let account_id: Option<uuid::Uuid> = row.get(1);
    let ip: Option<String> = row.get(2);
    let metadata: serde_json::Value =
        serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(3)).expect("metadata json");
    assert_eq!(outcome, "failure");
    assert_eq!(
        account_id, None,
        "missing account ⇒ no account_id attribution"
    );
    assert_eq!(ip.as_deref(), Some("9.9.9.9"));
    assert_eq!(
        metadata.get("username").and_then(|v| v.as_str()),
        Some("ghost"),
        "audit records the canonicalized username"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_failure_wrong_password_audits_with_account_id() {
    // The sibling failure path: an existing account with a wrong password
    // attributes the failure row to `account_id` (the account resolved before
    // the password check failed).
    let pool = fresh_db_pool().await;
    let alice_id = seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool.clone(), hasher, audit, None, None);

    let response = call_login(&state, Some("9.9.9.9"), "alice", "wrong-password").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "SELECT account_id, metadata::text FROM audit_log
             WHERE event_type = 'login' AND outcome = 'failure'
             ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .expect("audit row");
    let account_id: Option<uuid::Uuid> = row.get(0);
    let metadata: serde_json::Value =
        serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(1)).expect("metadata json");
    assert_eq!(
        account_id,
        Some(alice_id),
        "found-but-wrong-password failure attributes to the account"
    );
    assert_eq!(
        metadata.get("username").and_then(|v| v.as_str()),
        Some("alice")
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_success_audits_and_creates_session() {
    // The success chain: 200 + `Set-Cookie`, a real `auth_session` row keyed by
    // the blake3 hash of the issued token, and a `login` success audit row
    // attributed to the account.
    let pool = fresh_db_pool().await;
    let alice_id = seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool.clone(), hasher, audit, None, None);

    let response = call_login(&state, Some("9.9.9.9"), "alice", "correct-password").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().contains_key(SET_COOKIE),
        "successful login must set the session cookie"
    );

    let client = pool.get().await.expect("pool.get");
    // Exactly one active session for the account.
    let session_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM auth_session WHERE account_id = $1",
            &[&alice_id],
        )
        .await
        .expect("session count")
        .get(0);
    assert_eq!(session_count, 1, "exactly one session row created");

    let row = client
        .query_one(
            "SELECT outcome, account_id FROM audit_log
             WHERE event_type = 'login' AND outcome = 'success'
             ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .expect("audit row");
    let outcome: String = row.get(0);
    let account_id: Option<uuid::Uuid> = row.get(1);
    assert_eq!(outcome, "success");
    assert_eq!(account_id, Some(alice_id));
}

// -- Per-account session cap ------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_beyond_the_cap_evicts_the_oldest_sessions() {
    // The per-account concurrent-session cap. `login_success_audits_and_creates_session`
    // above pins one login ⇒ one row; this pins the bound: `DEFAULT_MAX_SESSIONS + 1`
    // logins leave exactly `DEFAULT_MAX_SESSIONS` durable rows, and the survivors are
    // the newest ones — the first login's session is the one evicted, so its cookie no
    // longer resolves.
    //
    // Both halves matter. The count alone would pass against an implementation that
    // evicted the row it just inserted; asserting *which* hashes survive is what pins
    // evict-oldest rather than evict-something. Deleting the
    // `query_session_enforce_limit` call in `account_login.rs` fails this on the count
    // assertion (6 rows, not 5).
    //
    // Each login is its own transaction, so the `created_at` values are distinct and
    // the `id DESC` tie-breaker never engages here — this pins the cap, not the
    // tie-break. It does **not** pin the concurrent-creator race: two simultaneous
    // logins can each evict against a stale count and both commit, which a sequential
    // test cannot observe (see `query_session_enforce_limit`'s race note).
    //
    // The evicted session is also *closed*: the handler hands its hash to the
    // `ConnectionCloser` (and no other), so the connections it opened end with the
    // row. The cap's first `DEFAULT_MAX_SESSIONS` logins close nothing.
    let pool = fresh_db_pool().await;
    let alice_id = seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let mut state = build_state(pool.clone(), hasher, audit, None, None);
    let closer = Arc::new(RecordingCloser::default());
    state.connection_closer = Arc::<RecordingCloser>::clone(&closer);

    // One more login than the cap admits. Each returns its own `Set-Cookie`, so the
    // stored hashes are recovered from the DB in creation order rather than by
    // re-deriving them from the cookie (which would need the signing format).
    let logins = usize::try_from(DEFAULT_MAX_SESSIONS).expect("cap fits usize") + 1;
    let mut created_hashes = Vec::with_capacity(logins);
    for i in 0..logins {
        let response = call_login(&state, Some("9.9.9.9"), "alice", "correct-password").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "login {} of {logins} must succeed — the cap evicts, it never refuses",
            i + 1
        );
        assert!(
            response.headers().contains_key(SET_COOKIE),
            "every login past the cap still issues a working session cookie"
        );
        created_hashes.push(newest_session_hash(&pool, &alice_id).await);
        if i + 1 < logins {
            assert!(
                closer.closed().is_empty(),
                "login {} of {logins} is within the cap and must close nothing",
                i + 1
            );
        }
    }

    let client = pool.get().await.expect("pool.get");
    let session_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM auth_session WHERE account_id = $1",
            &[&alice_id],
        )
        .await
        .expect("session count")
        .get(0);
    assert_eq!(
        session_count, DEFAULT_MAX_SESSIONS,
        "{logins} logins must leave exactly the cap ({DEFAULT_MAX_SESSIONS}) durable sessions"
    );

    // The survivors are the newest `DEFAULT_MAX_SESSIONS` — i.e. every hash except
    // the first one created.
    let surviving: Vec<String> = client
        .query(
            "SELECT id FROM auth_session WHERE account_id = $1 ORDER BY created_at ASC",
            &[&alice_id],
        )
        .await
        .expect("session ids")
        .into_iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        surviving,
        created_hashes[1..],
        "the oldest session must be the evicted one; the newest {DEFAULT_MAX_SESSIONS} survive"
    );
    assert!(
        !surviving.contains(&created_hashes[0]),
        "the first login's session must no longer resolve"
    );
    assert_eq!(
        closer.closed(),
        [ConnectionCloseTarget::Session(created_hashes[0].clone())],
        "the evicted session's connections — and only its — must be closed"
    );
}

/// Read back the most recently created session hash for an account.
///
/// The handler returns the raw token inside a *signed* cookie, so recovering
/// the stored hash from the response would mean re-implementing the cookie
/// format in the test. Reading the newest row is equivalent for this purpose
/// and keeps the assertion on the durable state, which is what the cap
/// governs.
async fn newest_session_hash(pool: &Pool, account_id: &uuid::Uuid) -> String {
    let client = pool.get().await.expect("pool.get");
    client
        .query_one(
            "SELECT id FROM auth_session WHERE account_id = $1 ORDER BY created_at DESC LIMIT 1",
            &[account_id],
        )
        .await
        .expect("newest session")
        .get(0)
}

/// A `ConnectionCloser` that, when asked to close a session, counts that
/// session's row over a **separate** pool connection — so it sees only
/// committed state. A close issued inside login's transaction would still
/// find the evicted row.
struct CommitProbingCloser {
    pool: Pool,
    seen_at_close: Mutex<Vec<i64>>,
}

impl CommitProbingCloser {
    fn probe(&self, session_hash: &str) -> usize {
        let pool = self.pool.clone();
        let session_hash = session_hash.to_owned();
        // `ConnectionCloser` is sync; `block_in_place` lets it read the DB from a
        // multi-thread runtime.
        let seen = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                pool.get()
                    .await
                    .unwrap()
                    .query_one(
                        "SELECT count(*) FROM auth_session WHERE id = $1",
                        &[&session_hash],
                    )
                    .await
                    .unwrap()
                    .get::<_, i64>(0)
            })
        });
        self.seen_at_close.lock().unwrap().push(seen);
        0
    }
}

impl fuz_http::ShutdownCloser for CommitProbingCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for CommitProbingCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        let ConnectionCloseTarget::Session(target_hash) = target else {
            unreachable!("login closes sessions only")
        };
        self.probe(target_hash)
    }
}

/// **Login closes an evicted session only once the eviction has committed.**
/// A client told 4001 rechecks its session straight away; closed inside the
/// transaction, the evicted row would still be there and the recheck would
/// read "valid".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_closes_an_evicted_session_after_the_eviction_commits() {
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let mut state = build_state(pool.clone(), hasher, audit, None, None);
    let closer = Arc::new(CommitProbingCloser {
        pool: pool.clone(),
        seen_at_close: Mutex::new(Vec::new()),
    });
    state.connection_closer = Arc::<CommitProbingCloser>::clone(&closer);

    let logins = usize::try_from(DEFAULT_MAX_SESSIONS).expect("cap fits usize") + 1;
    for _ in 0..logins {
        let response = call_login(&state, Some("9.9.9.9"), "alice", "correct-password").await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(
        *closer.seen_at_close.lock().unwrap(),
        [0],
        "one close, for a row already gone when it ran"
    );
}

/// **The session cap returns exactly the ids it evicted** — the oldest token
/// hashes past `max_sessions`, nothing else — since login closes the live
/// connections of each hash it returns. A second pass over a capped account
/// evicts and returns nothing; another account's sessions are never counted.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn enforce_limit_returns_exactly_the_evicted_session_ids() {
    let pool = fresh_db_pool().await;
    let alice_id = seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let bob_id = seed_account_with_hash(&pool, "bob", "stored-hash-bob").await;
    let client = pool.get().await.expect("pool.get");

    // Oldest first, with explicit `created_at`s so the order is the test's.
    let sessions = [
        ("session_0", alice_id),
        ("session_1", alice_id),
        ("session_2", alice_id),
        ("session_3", alice_id),
        ("session_bob", bob_id),
    ];
    for (i, (id, owner)) in sessions.iter().enumerate() {
        let minutes_ago = 10 - i32::try_from(i).unwrap();
        client
            .execute(
                "INSERT INTO auth_session (id, account_id, created_at, expires_at)
                 VALUES ($1, $2, NOW() - make_interval(mins => $3), NOW() + INTERVAL '1 day')",
                &[id, owner, &minutes_ago],
            )
            .await
            .expect("seed session");
    }

    let mut evicted = query_session_enforce_limit(&client, &alice_id, 2)
        .await
        .expect("enforce limit");
    evicted.sort();
    assert_eq!(
        evicted,
        ["session_0", "session_1"],
        "the two oldest of four, and only them"
    );

    let again = query_session_enforce_limit(&client, &alice_id, 2)
        .await
        .expect("enforce limit again");
    assert!(
        again.is_empty(),
        "a capped account evicts nothing: {again:?}"
    );

    let surviving: Vec<String> = client
        .query("SELECT id FROM auth_session ORDER BY id", &[])
        .await
        .expect("survivors")
        .into_iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(surviving, ["session_2", "session_3", "session_bob"]);
}

/// A `ConnectionCloser` recording every close it is asked for, by target.
#[derive(Default)]
struct RecordingCloser {
    closed: Mutex<Vec<ConnectionCloseTarget>>,
}

impl RecordingCloser {
    fn closed(&self) -> Vec<ConnectionCloseTarget> {
        self.closed.lock().unwrap().clone()
    }

    fn record(&self, target: ConnectionCloseTarget) -> usize {
        self.closed.lock().unwrap().push(target);
        0
    }
}

impl fuz_http::ShutdownCloser for RecordingCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for RecordingCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        self.record(target.clone())
    }
}

// -- Rate-limit fast path ---------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_rate_limited_short_circuits_before_verify() {
    // An exhausted IP bucket returns 429 *before* any DB lookup or `verify`
    // runs — the work-amplification guard. Assert 429 and that the recording
    // hasher saw zero verify calls.
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, verify_hashes) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let ip_limiter = Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts: 1,
        window_ms: 60_000,
        max_keys: None,
    }));
    ip_limiter.record("10.0.0.5"); // burn the bucket
    let state = build_state(pool, hasher, audit, Some(Arc::clone(&ip_limiter)), None);

    let response = call_login(&state, Some("10.0.0.5"), "alice", "correct-password").await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        verify_hashes.lock().unwrap().is_empty(),
        "rate-limited request must not reach the password verify"
    );
}

/// Run `2 × max` concurrent wrong-password logins as alice and count the
/// 401s and 429s.
async fn burst_of_wrong_logins(state: &AccountRouteState, max: u32) -> (usize, usize) {
    let responses = futures::future::join_all(
        (0..max * 2).map(|_| call_login(state, Some("10.0.0.9"), "alice", "wrong-password")),
    )
    .await;
    let count = |status| responses.iter().filter(|r| r.status() == status).count();
    (
        count(StatusCode::UNAUTHORIZED),
        count(StatusCode::TOO_MANY_REQUESTS),
    )
}

fn limiter_of(max_attempts: u32) -> Arc<RateLimiter> {
    Arc::new(RateLimiter::new(RateLimiterOptions {
        max_attempts,
        window_ms: 60_000,
        max_keys: None,
    }))
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_burst_gets_at_most_the_ip_cap_past_the_limiter() {
    // Every attempt of a concurrent burst would pass a check made before the
    // lookup; the reservation counts each one in flight, so the burst gets
    // exactly the cap through and the rest are refused.
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let ip_limiter = limiter_of(3);
    let state = build_state(pool, hasher, audit, Some(Arc::clone(&ip_limiter)), None);

    assert_eq!(burst_of_wrong_logins(&state, 3).await, (3, 3));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_burst_gets_at_most_the_account_cap_past_the_limiter() {
    let pool = fresh_db_pool().await;
    let alice_id = seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let account_limiter = limiter_of(3);
    let state = build_state(
        pool,
        hasher,
        audit,
        None,
        Some(Arc::clone(&account_limiter)),
    );

    assert_eq!(burst_of_wrong_logins(&state, 3).await, (3, 3));
    assert!(!account_limiter.check(&alice_id.to_string()).is_allowed());
}

// -- Denial timing floor ----------------------------------------------------
//
// The dummy-hash equalization above closes the dominant Argon2 oracle, but the
// residual DB-presence + verify delta between "no such account" and "account
// exists, wrong password" is still a (sub-ms) timing signal. Both 401 paths
// converge through one `wait_for_deadline` site in `account_login`, so each
// elapses at least `floor - jitter`, masking that delta. These pin the
// *observable* floor end-to-end — the Rust twin of `fuz_app`'s
// `login_timing.db.test.ts` §"login denial timing floor" — where the
// `timing.rs` unit tests pin only the `max(work, floor)` mechanism under a
// paused clock. The `RecordingHasher` is near-instant, so the handler work is
// far below the floor and the observed time is dominated by it.
// `login_zero_floor_401_does_not_wait` pins the other direction: the floor is
// the configured `AccountRouteState::login_fail_floor_ms`, so `0` disables it.

/// Lower bound for a floored 401. The smallest possible deadline is
/// `floor - jitter`; subtract a small slack for measurement/scheduling
/// granularity. The bound stays far above the few ms a floorless 401 would
/// take, so it cleanly proves the floor engaged rather than just measuring noise.
const fn floor_lower_bound() -> std::time::Duration {
    let min_ms = DEFAULT_LOGIN_FAIL_FLOOR_MS
        .saturating_sub(DEFAULT_LOGIN_FAIL_JITTER_MS)
        .saturating_sub(15);
    std::time::Duration::from_millis(min_ms)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_missing_account_401_takes_at_least_the_floor() {
    // The cheap not-found path (`verify` against the dummy hash, no further DB
    // work) must still elapse the floor, so it can't be distinguished from the
    // expensive found-wrong-password sibling below.
    let pool = fresh_db_pool().await;
    let (hasher, _) = RecordingHasher::new("unused");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool, hasher, audit, None, None);

    let t0 = std::time::Instant::now();
    let response = call_login(&state, Some("1.2.3.4"), "ghost-floor", "any-password-123").await;
    let elapsed = t0.elapsed();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        elapsed >= floor_lower_bound(),
        "missing-account 401 elapsed {elapsed:?}, expected >= {:?} \
         (floor {DEFAULT_LOGIN_FAIL_FLOOR_MS}ms ± {DEFAULT_LOGIN_FAIL_JITTER_MS}ms)",
        floor_lower_bound()
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_wrong_password_401_takes_at_least_the_floor() {
    // The expensive sibling: an existing account verified against its real
    // stored hash. Same convergence site, same floor — that's what masks the
    // present-vs-absent delta.
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = build_state(pool, hasher, audit, None, None);

    let t0 = std::time::Instant::now();
    let response = call_login(&state, Some("1.2.3.4"), "alice", "wrong-password").await;
    let elapsed = t0.elapsed();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        elapsed >= floor_lower_bound(),
        "wrong-password 401 elapsed {elapsed:?}, expected >= {:?} \
         (floor {DEFAULT_LOGIN_FAIL_FLOOR_MS}ms ± {DEFAULT_LOGIN_FAIL_JITTER_MS}ms)",
        floor_lower_bound()
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn login_zero_floor_401_does_not_wait() {
    // The floor is read from `AccountRouteState`, not the constants: test
    // binaries (the spine stub) pass `0` so denied logins answer at once. A
    // handler that ignored the field would still sleep the default floor here.
    let pool = fresh_db_pool().await;
    seed_account_with_hash(&pool, "alice", "stored-hash-alice").await;
    let (hasher, _) = RecordingHasher::new("correct-password");
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let state = AccountRouteState {
        login_fail_floor_ms: 0,
        login_fail_jitter_ms: 0,
        ..build_state(pool, hasher, audit, None, None)
    };

    for (username, password) in [
        ("ghost-floor", "any-password-123"),
        ("alice", "wrong-password"),
    ] {
        let t0 = std::time::Instant::now();
        let response = call_login(&state, Some("1.2.3.4"), username, password).await;
        let elapsed = t0.elapsed();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            elapsed < floor_lower_bound(),
            "{username} 401 with a zero floor elapsed {elapsed:?}, expected < {:?} \
             (the default floor must not apply)",
            floor_lower_bound()
        );
    }
}
