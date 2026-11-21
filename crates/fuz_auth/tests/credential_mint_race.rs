//! A credential minted while the account's authorization state changes under
//! it: a login or an `account_token_create` racing a password change or an
//! account delete, against a real `PostgreSQL`.
//!
//! A token create is authorized by a session resolved before its transaction;
//! the mint re-checks that session after taking the account lock, so a change
//! that committed first is seen revoking it, and one still to commit waits on
//! the lock and then revokes the token.
//!
//! The race is made exact, not hammered. A login is held inside its password
//! verify ([`LatchHasher`]) while the change or the delete runs to completion,
//! then released: it must be refused exactly as a wrong password is, with no
//! session row and no cookie. The mirror order — the mint commits first — ends
//! with the credential revoked. And the lock is shown to serialize: a mint
//! waits on an uncommitted change's row lock, and a change waits on an
//! uncommitted mint's — so the change's revoke, which runs after its account
//! write, reaches the session the mint inserted. Two mints of one account at
//! its cap take turns: the second waits on the first's commit and then counts
//! the first's row, so the account ends at the cap, not one over.
//!
//! Twin of `fuz_app`'s `src/test/auth/credential_mint_race.db.test.ts`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test credential_mint_race -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE, header::COOKIE};
use axum::response::Response;
use futures::future::{BoxFuture, FutureExt};
use fuz_auth::account_action_specs::DEFAULT_MAX_TOKENS;
use fuz_auth::account_queries::{query_account_lock_verified, query_account_soft_delete};
use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::ROLE_ADMIN;
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{
    AccountActionContext, AccountActionSpecs, AccountRouteState, AccountRow, AuditEmitter,
    ConnectionCloser, CredentialType, DEFAULT_MAX_SESSIONS, HashedPassword, NoopAuditPostCommit,
    NoopConnectionCloser, PasswordHashError, PasswordHasher, RequestContext, create_capped_session,
    hash_session_token, login_handler, password_handler,
};
use fuz_db::Pool;
use serde_json::{Value, json};
use tokio::sync::oneshot;

mod common;
use common::{fresh_db_pool, seed_account_actor, seed_admin};

const OLD_PASSWORD: &str = "old-password-race-1";
const NEW_PASSWORD: &str = "new-password-race-2";

/// How long a blocked statement is given to show it is blocked before the
/// transaction holding its row commits.
const HOLD: Duration = Duration::from_millis(300);

/// The latch a [`LatchHasher`] verify waits on: `reached` fires when the verify
/// is entered, and the verify returns once `release` is sent.
struct Latch {
    reached: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

/// A `PasswordHasher` whose stored form is `h:<password>`, and whose next
/// `verify` after [`LatchHasher::hold`] waits until the test releases it — the
/// window between a login's verify and its session insert, made exact.
#[derive(Default)]
struct LatchHasher {
    latch: Mutex<Option<Latch>>,
}

impl LatchHasher {
    /// Arm the latch: returns the `reached` signal and the `release` handle.
    fn hold(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        *self.latch.lock().unwrap() = Some(Latch {
            reached: reached_tx,
            release: release_rx,
        });
        (reached_rx, release_tx)
    }
}

fn stored_hash(password: &str) -> String {
    format!("h:{password}")
}

impl PasswordHasher for LatchHasher {
    fn hash(
        &self,
        password: String,
    ) -> BoxFuture<'static, Result<HashedPassword, PasswordHashError>> {
        async move { Ok(HashedPassword::new(stored_hash(&password))) }.boxed()
    }

    fn verify(&self, password: String, hash: String) -> BoxFuture<'static, bool> {
        let latch = self.latch.lock().unwrap().take();
        async move {
            if let Some(latch) = latch {
                let _ = latch.reached.send(());
                let _ = latch.release.await;
            }
            hash == stored_hash(&password)
        }
        .boxed()
    }

    fn dummy_hash(&self) -> &'static str {
        "h:<dummy>"
    }
}

fn build_state(pool: Pool, hasher: Arc<LatchHasher>) -> AccountRouteState {
    let connection_closer: Arc<dyn ConnectionCloser> = Arc::new(NoopConnectionCloser);
    AccountRouteState {
        gate: fuz_testing::testing_auth_gate(pool.clone()),
        password_hasher: hasher,
        audit: Arc::new(AuditEmitter::new(pool)),
        connection_closer,
        bootstrap_available: Arc::new(AtomicBool::new(false)),
        login_ip_rate_limiter: None,
        login_account_rate_limiter: None,
        login_fail_floor_ms: 0,
        login_fail_jitter_ms: 0,
    }
}

fn json_headers(cookie: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Some(cookie) = cookie {
        headers.insert(COOKIE, HeaderValue::from_str(cookie).unwrap());
    }
    headers
}

/// What a REST answer carried: its status, body, and `Set-Cookie` lines.
struct Answer {
    status: StatusCode,
    body: Value,
    set_cookie: Vec<String>,
}

impl Answer {
    /// The `name=value` pair of the cookie the answer set.
    fn cookie(&self) -> String {
        self.set_cookie[0].split(';').next().unwrap().to_owned()
    }
}

async fn read_answer(response: Response) -> Answer {
    let status = response.status();
    let set_cookie = response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Answer {
        status,
        body,
        set_cookie,
    }
}

async fn login(state: &AccountRouteState, username: &str, password: &str) -> Answer {
    let body = Bytes::from(
        serde_json::to_vec(&json!({ "username": username, "password": password })).unwrap(),
    );
    read_answer(login_handler(State(state.clone()), None, json_headers(None), body).await).await
}

async fn change_password(state: &AccountRouteState, cookie: &str) -> Answer {
    let body = Bytes::from(
        serde_json::to_vec(&json!({
            "current_password": OLD_PASSWORD,
            "new_password": NEW_PASSWORD,
        }))
        .unwrap(),
    );
    read_answer(
        password_handler(State(state.clone()), None, json_headers(Some(cookie)), body).await,
    )
    .await
}

/// Seed the account the races are about, its password `OLD_PASSWORD`.
async fn seed_victim(pool: &Pool) -> uuid::Uuid {
    let (account_id, _actor_id) = seed_account_actor(pool, "victim").await;
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE account SET password_hash = $1 WHERE id = $2",
            &[&stored_hash(OLD_PASSWORD), &account_id],
        )
        .await
        .unwrap();
    account_id
}

async fn session_count(pool: &Pool, account_id: &uuid::Uuid) -> i64 {
    let client = pool.get().await.unwrap();
    client
        .query_one(
            "SELECT COUNT(*) FROM auth_session WHERE account_id = $1",
            &[account_id],
        )
        .await
        .unwrap()
        .get(0)
}

async fn token_count(pool: &Pool, account_id: &uuid::Uuid) -> i64 {
    let client = pool.get().await.unwrap();
    client
        .query_one(
            "SELECT COUNT(*) FROM api_token WHERE account_id = $1",
            &[account_id],
        )
        .await
        .unwrap()
        .get(0)
}

async fn failed_login_rows(pool: &Pool, account_id: &uuid::Uuid) -> i64 {
    let client = pool.get().await.unwrap();
    client
        .query_one(
            "SELECT COUNT(*) FROM audit_log
             WHERE event_type = 'login' AND outcome = 'failure' AND account_id = $1",
            &[account_id],
        )
        .await
        .unwrap()
        .get(0)
}

/// An admin context, its admin grant in hand (the tests dispatch past the
/// action-auth gates).
async fn seed_admin_with_grant(pool: &Pool) -> RequestActorContext {
    let mut auth = seed_admin(pool).await;
    auth.role_grants.push(RoleGrantRow {
        id: uuid::Uuid::new_v4(),
        actor_id: auth.actor.id,
        role: ROLE_ADMIN.to_owned(),
        scope_id: None,
    });
    auth
}

/// Run an admin action in a transaction of its own and commit it, as the
/// dispatcher does.
async fn admin_action(pool: &Pool, auth: &RequestActorContext, method: &str, params: &Value) {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = common::ctx(auth, &audit, &closer);
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    common::admin_dispatch(method, params, &ctx, &tx)
        .await
        .expect(method);
    tx.commit().await.unwrap();
}

/// Seed a live session for `account_id` and return its id (the token hash) —
/// the session a token create is authorized by.
async fn seed_session(pool: &Pool, account_id: &uuid::Uuid) -> String {
    let client = pool.get().await.unwrap();
    let session = create_capped_session(&client, account_id).await.unwrap();
    hash_session_token(&session.token).as_str().to_owned()
}

/// Run `account_token_create` for `account_id` in `tx`, as the dispatcher does
/// once `session_hash`'s session has authorized it, leaving the commit to the
/// caller.
async fn token_create_in(
    pool: &Pool,
    tx: &deadpool_postgres::Transaction<'_>,
    account_id: uuid::Uuid,
    session_hash: &str,
) -> Result<Value, fuz_http::JsonrpcError> {
    let auth = RequestContext {
        account: AccountRow {
            id: account_id,
            username: "victim".to_owned(),
        },
    };
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = AccountActionContext {
        auth: &auth,
        credential_type: Some(CredentialType::Session),
        session_hash: Some(session_hash),
        audit: &audit,
        post_commit: &NoopAuditPostCommit,
        connection_closer: &closer,
        notification_sender: common::noop_notification_sender(),
        client_ip: Some("127.0.0.1".to_owned()),
    };
    let params =
        json!({ "name": "race", "scope": {"kind": "full"}, "lifetime": {"kind": "eternal"} });
    AccountActionSpecs::dispatch("account_token_create", &params, &ctx, tx).await
}

/// Run `account_token_create` for `account_id` in a transaction of its own,
/// committed when it succeeds.
async fn token_create(
    pool: &Pool,
    account_id: uuid::Uuid,
    session_hash: &str,
) -> Result<Value, fuz_http::JsonrpcError> {
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let result = token_create_in(pool, &tx, account_id, session_hash).await;
    if result.is_ok() {
        tx.commit().await.unwrap();
    }
    result
}

fn assert_refused_as_wrong_password(answer: &Answer, label: &str) {
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{label}");
    assert_eq!(
        answer.body,
        json!({"error": "invalid_credentials"}),
        "{label}: the wrong-password body"
    );
    assert!(answer.set_cookie.is_empty(), "{label}: no cookie is set");
}

// -- A login held in its verify ------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_login_held_across_a_password_change_is_refused_as_a_wrong_password() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let hasher = Arc::new(LatchHasher::default());
    let state = build_state(pool.clone(), Arc::clone(&hasher));
    let first = login(&state, "victim", OLD_PASSWORD).await;
    assert_eq!(first.status, StatusCode::OK);
    let wrong = login(&state, "victim", "not-the-password").await;
    assert_refused_as_wrong_password(&wrong, "the control: a wrong password");
    let failures_before = failed_login_rows(&pool, &account_id).await;

    let (reached, release) = hasher.hold();
    let held = tokio::spawn({
        let state = state.clone();
        async move { login(&state, "victim", OLD_PASSWORD).await }
    });
    reached.await.unwrap();
    let change = change_password(&state, &first.cookie()).await;
    assert_eq!(change.status, StatusCode::OK, "{:?}", change.body);
    release.send(()).unwrap();
    let raced = held.await.unwrap();

    assert_refused_as_wrong_password(&raced, "the login verified before the change");
    assert_eq!(
        session_count(&pool, &account_id).await,
        0,
        "no session row survives"
    );
    assert_eq!(
        failed_login_rows(&pool, &account_id).await,
        failures_before + 1,
        "audited as a failed login, as the wrong password was"
    );
    let fresh = login(&state, "victim", NEW_PASSWORD).await;
    assert_eq!(fresh.status, StatusCode::OK, "the new password logs in");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_login_held_across_a_delete_is_refused_and_the_undelete_restores_nothing() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let admin = seed_admin_with_grant(&pool).await;
    let hasher = Arc::new(LatchHasher::default());
    let state = build_state(pool.clone(), Arc::clone(&hasher));

    let (reached, release) = hasher.hold();
    let held = tokio::spawn({
        let state = state.clone();
        async move { login(&state, "victim", OLD_PASSWORD).await }
    });
    reached.await.unwrap();
    admin_action(
        &pool,
        &admin,
        "account_delete",
        &json!({"account_id": account_id}),
    )
    .await;
    release.send(()).unwrap();
    let raced = held.await.unwrap();

    assert_refused_as_wrong_password(&raced, "the login verified before the delete");
    assert_eq!(session_count(&pool, &account_id).await, 0, "no session row");
    admin_action(
        &pool,
        &admin,
        "account_undelete",
        &json!({"account_id": account_id}),
    )
    .await;
    assert_eq!(
        session_count(&pool, &account_id).await,
        0,
        "the undelete restores no session"
    );
    let fresh = login(&state, "victim", OLD_PASSWORD).await;
    assert_eq!(fresh.status, StatusCode::OK, "a fresh login authenticates");
}

// -- The mirror order: the mint commits first -----------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_login_committed_before_a_password_change_is_revoked_by_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let state = build_state(pool.clone(), Arc::new(LatchHasher::default()));
    let first = login(&state, "victim", OLD_PASSWORD).await;
    let second = login(&state, "victim", OLD_PASSWORD).await;
    assert_eq!(second.status, StatusCode::OK);
    let change = change_password(&state, &first.cookie()).await;
    assert_eq!(change.status, StatusCode::OK);
    assert_eq!(change.body["sessions_revoked"], json!(2));
    assert_eq!(session_count(&pool, &account_id).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_login_committed_before_a_delete_is_revoked_and_stays_dead_after_the_undelete() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let admin = seed_admin_with_grant(&pool).await;
    let state = build_state(pool.clone(), Arc::new(LatchHasher::default()));
    assert_eq!(
        login(&state, "victim", OLD_PASSWORD).await.status,
        StatusCode::OK
    );
    admin_action(
        &pool,
        &admin,
        "account_delete",
        &json!({"account_id": account_id}),
    )
    .await;
    assert_eq!(session_count(&pool, &account_id).await, 0);
    admin_action(
        &pool,
        &admin,
        "account_undelete",
        &json!({"account_id": account_id}),
    )
    .await;
    assert_eq!(session_count(&pool, &account_id).await, 0);
}

// -- The lock serializes --------------------------------------------------------

/// Run `blocked` beside a holder that commits after [`HOLD`]; returns
/// `blocked`'s output and whether it finished only after the commit.
async fn race_against_commit<T>(
    blocked: impl Future<Output = T>,
    commit: impl Future<Output = ()>,
) -> (T, bool) {
    let blocked = async {
        let out = blocked.await;
        (out, Instant::now())
    };
    let commit = async {
        tokio::time::sleep(HOLD).await;
        let at = Instant::now();
        commit.await;
        at
    };
    let ((out, finished_at), committed_at) = tokio::join!(blocked, commit);
    (out, finished_at > committed_at)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_login_waits_on_an_uncommitted_password_change_and_is_then_refused() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let state = build_state(pool.clone(), Arc::new(LatchHasher::default()));

    // the change's account write, uncommitted: its row lock held
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let updated = fuz_auth::account_queries::query_update_account_password(
        &tx,
        &account_id,
        &stored_hash(NEW_PASSWORD),
        &stored_hash(OLD_PASSWORD),
    )
    .await
    .unwrap();
    assert!(updated);

    let (raced, waited) = race_against_commit(login(&state, "victim", OLD_PASSWORD), async {
        tx.commit().await.unwrap();
    })
    .await;
    assert!(waited, "the login's mint waits on the change's row lock");
    assert_refused_as_wrong_password(&raced, "the login that waited");
    assert_eq!(session_count(&pool, &account_id).await, 0);
}

/// Hold a login's mint uncommitted — the lock taken, the session inserted —
/// and return the transaction.
async fn hold_a_mint<'a>(
    client: &'a mut deadpool_postgres::Object,
    account_id: &uuid::Uuid,
) -> deadpool_postgres::Transaction<'a> {
    let tx = client.transaction().await.unwrap();
    assert!(
        query_account_lock_verified(&tx, account_id, &stored_hash(OLD_PASSWORD))
            .await
            .unwrap()
    );
    let minted = create_capped_session(&tx, account_id).await.unwrap();
    assert!(minted.evicted.is_empty());
    tx
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_password_change_waits_on_an_uncommitted_mint_and_then_revokes_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let state = build_state(pool.clone(), Arc::new(LatchHasher::default()));
    let first = login(&state, "victim", OLD_PASSWORD).await;

    let mut client = pool.get().await.unwrap();
    let tx = hold_a_mint(&mut client, &account_id).await;
    let (change, waited) = race_against_commit(change_password(&state, &first.cookie()), async {
        tx.commit().await.unwrap();
    })
    .await;
    assert!(
        waited,
        "the change's account write waits on the mint's lock"
    );
    assert_eq!(change.status, StatusCode::OK, "{:?}", change.body);
    assert_eq!(
        session_count(&pool, &account_id).await,
        0,
        "the change's revoke, after its account write, reaches the minted session"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_delete_waits_on_an_uncommitted_mint_and_then_revokes_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let admin = seed_admin_with_grant(&pool).await;

    let mut client = pool.get().await.unwrap();
    let tx = hold_a_mint(&mut client, &account_id).await;
    let ((), waited) = race_against_commit(
        admin_action(
            &pool,
            &admin,
            "account_delete",
            &json!({"account_id": account_id}),
        ),
        async {
            tx.commit().await.unwrap();
        },
    )
    .await;
    assert!(waited, "the delete's tombstone waits on the mint's lock");
    assert_eq!(
        session_count(&pool, &account_id).await,
        0,
        "the delete's revoke, after its tombstone, reaches the minted session"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_login_at_the_cap_waits_on_an_uncommitted_mint_and_then_evicts_past_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let state = build_state(pool.clone(), Arc::new(LatchHasher::default()));
    while session_count(&pool, &account_id).await < DEFAULT_MAX_SESSIONS {
        seed_session(&pool, &account_id).await;
    }

    // a login's mint at the cap, uncommitted: the lock taken, its session
    // inserted, the oldest evicted
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(
        query_account_lock_verified(&tx, &account_id, &stored_hash(OLD_PASSWORD))
            .await
            .unwrap()
    );
    let minted = create_capped_session(&tx, &account_id).await.unwrap();
    assert_eq!(minted.evicted.len(), 1, "the held mint evicts the oldest");
    let (raced, waited) = race_against_commit(login(&state, "victim", OLD_PASSWORD), async {
        tx.commit().await.unwrap();
    })
    .await;
    assert!(waited, "the login's mint waits on the held mint's lock");
    assert_eq!(raced.status, StatusCode::OK, "{:?}", raced.body);
    assert_eq!(
        session_count(&pool, &account_id).await,
        DEFAULT_MAX_SESSIONS,
        "the second mint's eviction counts the first's session"
    );
}

// -- account_token_create -------------------------------------------------------

fn assert_unauthenticated(result: Result<Value, fuz_http::JsonrpcError>, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(
        error.code,
        fuz_http::JsonrpcErrorCode::Unauthenticated,
        "{label}"
    );
    assert_eq!(
        error.data,
        Some(json!({"reason": "authentication_required"})),
        "{label}: the 401 a dead session gets"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_create_authorized_before_a_delete_mints_nothing_after_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let admin = seed_admin_with_grant(&pool).await;
    let session_hash = seed_session(&pool, &account_id).await;
    admin_action(
        &pool,
        &admin,
        "account_delete",
        &json!({"account_id": account_id}),
    )
    .await;
    assert_unauthenticated(
        token_create(&pool, account_id, &session_hash).await,
        "a mint after the delete",
    );
    admin_action(
        &pool,
        &admin,
        "account_undelete",
        &json!({"account_id": account_id}),
    )
    .await;
    assert_eq!(token_count(&pool, &account_id).await, 0, "no token row");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_committed_before_a_delete_is_revoked_by_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let admin = seed_admin_with_grant(&pool).await;
    let session_hash = seed_session(&pool, &account_id).await;
    token_create(&pool, account_id, &session_hash)
        .await
        .unwrap();
    admin_action(
        &pool,
        &admin,
        "account_delete",
        &json!({"account_id": account_id}),
    )
    .await;
    admin_action(
        &pool,
        &admin,
        "account_undelete",
        &json!({"account_id": account_id}),
    )
    .await;
    assert_eq!(token_count(&pool, &account_id).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_create_waits_on_an_uncommitted_delete_and_is_then_refused() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let session_hash = seed_session(&pool, &account_id).await;

    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(
        query_account_soft_delete(&tx, &account_id, None)
            .await
            .unwrap()
            .is_some()
    );
    let (result, waited) =
        race_against_commit(token_create(&pool, account_id, &session_hash), async {
            tx.commit().await.unwrap();
        })
        .await;
    assert!(waited, "the mint waits on the tombstone's row lock");
    assert_unauthenticated(result, "the mint that waited");
    assert_eq!(token_count(&pool, &account_id).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_create_authorized_before_a_password_change_mints_nothing_after_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let state = build_state(pool.clone(), Arc::new(LatchHasher::default()));
    let changer = login(&state, "victim", OLD_PASSWORD).await;
    // the session the mint was authorized by, resolved before the change
    let session_hash = seed_session(&pool, &account_id).await;
    let change = change_password(&state, &changer.cookie()).await;
    assert_eq!(change.status, StatusCode::OK, "{:?}", change.body);
    assert_unauthenticated(
        token_create(&pool, account_id, &session_hash).await,
        "a mint after the change",
    );
    assert_eq!(token_count(&pool, &account_id).await, 0, "no token row");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_committed_before_a_password_change_is_revoked_by_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let state = build_state(pool.clone(), Arc::new(LatchHasher::default()));
    let changer = login(&state, "victim", OLD_PASSWORD).await;
    let session_hash = seed_session(&pool, &account_id).await;
    token_create(&pool, account_id, &session_hash)
        .await
        .unwrap();
    let change = change_password(&state, &changer.cookie()).await;
    assert_eq!(change.status, StatusCode::OK);
    assert_eq!(change.body["tokens_revoked"], json!(1));
    assert_eq!(token_count(&pool, &account_id).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_create_waits_on_an_uncommitted_password_change_and_is_then_refused() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let session_hash = seed_session(&pool, &account_id).await;

    // the change's writes in its order, uncommitted: the account row first,
    // then the revokes
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    assert!(
        fuz_auth::account_queries::query_update_account_password(
            &tx,
            &account_id,
            &stored_hash(NEW_PASSWORD),
            &stored_hash(OLD_PASSWORD),
        )
        .await
        .unwrap()
    );
    fuz_auth::session_queries::query_session_revoke_all_for_account(&tx, &account_id)
        .await
        .unwrap();
    let (result, waited) =
        race_against_commit(token_create(&pool, account_id, &session_hash), async {
            tx.commit().await.unwrap();
        })
        .await;
    assert!(waited, "the mint waits on the change's row lock");
    assert_unauthenticated(
        result,
        "the mint that waited, its session revoked under the lock",
    );
    assert_eq!(token_count(&pool, &account_id).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_minted_by_a_session_later_logged_out_keeps_working() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let session_hash = seed_session(&pool, &account_id).await;
    token_create(&pool, account_id, &session_hash)
        .await
        .unwrap();
    let client = pool.get().await.unwrap();
    client
        .execute("DELETE FROM auth_session WHERE id = $1", &[&session_hash])
        .await
        .unwrap();
    assert_eq!(
        token_count(&pool, &account_id).await,
        1,
        "the token outlives the logout"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_token_create_at_the_cap_waits_on_an_uncommitted_token_create_and_then_evicts_past_it() {
    let pool = fresh_db_pool().await;
    let account_id = seed_victim(&pool).await;
    let session_hash = seed_session(&pool, &account_id).await;
    while token_count(&pool, &account_id).await < DEFAULT_MAX_TOKENS {
        token_create(&pool, account_id, &session_hash)
            .await
            .unwrap();
    }

    // a token mint at the cap, uncommitted: the lock taken, its token
    // inserted, the oldest evicted
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    token_create_in(&pool, &tx, account_id, &session_hash)
        .await
        .unwrap();
    let (result, waited) =
        race_against_commit(token_create(&pool, account_id, &session_hash), async {
            tx.commit().await.unwrap();
        })
        .await;
    assert!(waited, "the token mint waits on the held mint's lock");
    result.expect("the token create that waited mints");
    assert_eq!(
        token_count(&pool, &account_id).await,
        DEFAULT_MAX_TOKENS,
        "the second mint's eviction counts the first's token"
    );
}
