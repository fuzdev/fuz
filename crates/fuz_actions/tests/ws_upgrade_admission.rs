//! PG-backed tests for the WS upgrade's **admission** step —
//! [`fuz_actions::admit_upgrade`] and the real upgrade handler around it.
//!
//! The race: an upgrade resolves its credential before the socket exists and
//! registers the socket afterward. A revocation landing in between closes
//! every *registered* socket of the revoked credential and misses this one —
//! which would then be admitted on a dead credential, keep it for the
//! socket's lifetime (per-message dispatch never re-reads the session or
//! token), and could evict a live socket of the same account past the
//! connection cap on its way in.
//!
//! Admission closes it with two defenses, and each is pinned alone here:
//!
//! - **the re-read** — every case resolves a real credential, applies one
//!   revocation's database effect (session delete, password change, token
//!   revoke, account soft-delete, acting-actor soft-delete) with *no* close
//!   delivered — the shape of a
//!   close that ran before the socket registered — and asserts
//!   `admit_upgrade` refuses with 4001, admits nothing, evicts nothing;
//! - **the pending registration** — a close that lands while the upgrade is
//!   stalled inside its re-read finds the registration, and admission then
//!   refuses though the re-read itself passed.
//!
//! The server's shutdown reaches admission the same two ways — a close-all
//! that finds the registration pending, and a registration that comes after
//! the close-all and is born closed — and either is refused with 1001, not
//! the 4001 a revocation gets; the born-closed one before any database work.
//!
//! The upgrade's `required_roles` gate is re-read the same way, beside the
//! credential: a global grant revoked with no close delivered, or a scoped
//! grant alone, refuses with 4006 (an acting actor soft-deleted under its
//! live account is refused with 4001 first, gated or not, and the grant read
//! counts no tombstoned actor's grants either); a role close that finds the pending
//! registration refuses with 4006 too, not the 4001 a revocation gets; a role
//! read that fails refuses with 1011.
//!
//! Plus the control (another session's revocation still admits), fail-closed
//! (1011) on an unreachable database and on a re-check query that errors, and
//! the whole thing through the real
//! handler over a real socket: an upgrade stalled at its role gate whose
//! session is revoked there answers `101` and then a 4001 close frame.
//!
//! Then the **acting-actor phase** in front of admission, the twin of
//! `fuz_app`'s upgrade-time authorization: an omitted, foreign, malformed, or
//! unresolvable `?acting=` answers the twin's statuses and bodies, the role
//! gate reads the acting actor's grants, and so does the admission re-read.
//!
//! Last, the **outbound bound** through the same assembled handler: a
//! connection's queue budget is the default whatever message cap the router
//! was built with, or the one the router's options set, and a connection
//! pushed past it — by another producer, or by its own
//! `_testing_flood_notifications` call — is closed with 4005 and forgotten.
//! One case there needs no database: a zero budget is refused when the
//! router is built.
//!
//! Shares `FUZ_ACTIONS_TEST_URL` (default `fuz_actions_test`) with
//! `perform_action_dispatch.rs` — cargo runs a crate's test binaries one
//! after another.
//!
//! `#[ignore]`-gated — run:
//! ```text
//! createdb fuz_actions_test
//! cargo test -p fuz_actions --test ws_upgrade_admission -- --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use fuz_actions::{
    ActionRegistry, ActionWsOptions, DEFAULT_WS_OUTBOUND_QUEUE_BYTES, WsRouteState, admit_upgrade,
    register_action_ws, register_action_ws_with_options,
};
use fuz_auth::ConnectionCloseTarget;
use fuz_auth::account_queries::query_account_soft_delete;
use fuz_auth::actor_queries::{
    query_active_actor_holds_any_global_role, query_actor_soft_delete, query_actor_undelete,
};
use fuz_auth::api_token_queries::{
    query_revoke_all_api_tokens_for_account, query_revoke_api_token_for_account,
};
use fuz_auth::session_queries::{
    query_session_revoke_all_for_account, query_session_revoke_for_account,
};
use fuz_auth::token_scope::TokenScopeDocument;
use fuz_auth::{
    AUTH_MIGRATIONS, AuditEmitter, ConnectionCloser, NoopConnectionCloser, NoopNotificationSender,
    ROLE_ADMIN, ResolvedAuth, SESSION_COOKIE_NAME,
};
use fuz_db::Pool;
use fuz_http::ShutdownCloser;
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::{
    CloseReason, Connection, ConnectionReceiver, ConnectionRegistry, OUTBOUND_FRAME_OVERHEAD_BYTES,
    UpgradeRefusal, WS_CLOSE_GOING_AWAY, WS_CLOSE_GOING_AWAY_REASON, WS_CLOSE_INTERNAL_ERROR,
    WS_CLOSE_OUTBOUND_OVERFLOW, WS_CLOSE_OUTBOUND_OVERFLOW_REASON, WS_CLOSE_PERMISSION_REVOKED,
    WS_CLOSE_SESSION_REVOKED, WS_CLOSE_SESSION_REVOKED_REASON, connection_channel,
};
use fuz_testing::{
    TESTING_DAEMON_TOKEN, TESTING_FLOOD_NOTIFICATION_METHOD, TestingDbOptions, TestingTableLock,
    create_testing_flood_notifications_action_spec, daemon_token_state, fresh_test_db_pool,
    grant_role, grant_scoped_role, mint_api_token, mint_session_cookie, seed_account_actor,
    seed_extra_actor, testing_keyring,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// The suite's database — the auth chain is all an upgrade reads.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_ACTIONS_TEST_URL",
    default_db: "fuz_actions_test",
    migrations: &[AUTH_MIGRATIONS],
    setup_sql: None,
};

/// Bound on every wait a broken admission could otherwise turn into a hang.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

async fn fresh_db_pool() -> Pool {
    fresh_test_db_pool(DB).await
}

/// A registry capped at `max` connections per account.
fn capped_registry(max: usize) -> Arc<ConnectionRegistry> {
    Arc::new(ConnectionRegistry::new().with_max_connections_per_account(NonZeroUsize::new(max)))
}

/// Resolve `headers` the way the upgrade handler does. Panics if they don't
/// authenticate — every case starts from a credential that does.
async fn resolve(pool: &Pool, headers: &HeaderMap) -> ResolvedAuth {
    fuz_testing::testing_auth_gate(pool.clone())
        .preflight(headers, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect("the fixture sends no foreign origin")
        .expect("the fixture credential authenticates")
}

/// Mint a session for `account_id`, returning its request cookie and the
/// resolved credential.
async fn resolve_session(pool: &Pool, account_id: Uuid) -> (String, ResolvedAuth) {
    let cookie =
        mint_session_cookie(pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, cookie.parse().unwrap());
    let resolved = resolve(pool, &headers).await;
    (cookie, resolved)
}

/// Mint a full-scope API token for `account_id` and resolve it.
async fn resolve_api_token(pool: &Pool, account_id: Uuid) -> ResolvedAuth {
    let minted = mint_api_token(pool, account_id, &TokenScopeDocument::full()).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", minted.token).parse().unwrap(),
    );
    resolve(pool, &headers).await
}

fn session_hash(resolved: &ResolvedAuth) -> &str {
    resolved.session_hash().expect("a session carries its hash")
}

/// Run the admission step for `resolved`, keeping the receiver so a refusal
/// can be checked for having delivered nothing.
async fn admit(
    registry: &Arc<ConnectionRegistry>,
    pool: &Pool,
    resolved: &ResolvedAuth,
    actor_id: Uuid,
) -> (
    Result<(Connection, fuz_realtime::ConnectionGuard), UpgradeRefusal>,
    ConnectionReceiver,
) {
    let (tx, rx) = connection_channel(1 << 20);
    let outcome = tokio::time::timeout(
        STEP_TIMEOUT,
        admit_upgrade(registry, pool, resolved, &actor_id, &[], tx),
    )
    .await
    .expect("admission completes");
    (outcome, rx)
}

/// A live socket of `account_id`, registered the way an earlier, legitimate
/// upgrade left it — the bystander a refused upgrade must not evict.
fn live_socket(
    registry: &ConnectionRegistry,
    account_id: Uuid,
) -> (Connection, ConnectionReceiver) {
    let (tx, rx) = connection_channel(1 << 20);
    let conn = registry.add_connection(
        tx,
        ConnectionIdentity {
            account_id: Some(account_id),
            ..ConnectionIdentity::default()
        },
        CancellationToken::new(),
    );
    (conn, rx)
}

/// Assert `conn` was neither revoked nor superseded.
fn assert_untouched(registry: &ConnectionRegistry, conn: &Connection) {
    assert!(registry.is_registered(conn.id), "still registered");
    assert!(!conn.signal.is_cancelled(), "signal untouched");
    assert_eq!(conn.close_reason.get(), None, "no 4004 queued for it");
}

/// Assert admission refused `resolved` as revoked: a 4001, nothing left in
/// the registry for it, nothing queued on its channel — and the account's
/// live socket, sitting at a cap of one, not evicted to make room.
async fn assert_refused_as_revoked(
    pool: &Pool,
    resolved: &ResolvedAuth,
    actor_id: Uuid,
    what: &str,
) {
    let registry = capped_registry(1);
    let (bystander, _bystander_rx) = live_socket(&registry, resolved.account.id);

    let (outcome, mut rx) = admit(&registry, pool, resolved, actor_id).await;
    let refusal = outcome.expect_err(what);
    assert_eq!(refusal, UpgradeRefusal::Revoked, "{what}");
    assert_eq!(refusal.close_code(), WS_CLOSE_SESSION_REVOKED, "{what}");
    assert_eq!(
        registry.pending_connection_count(),
        0,
        "{what}: unregistered"
    );
    assert_eq!(registry.connection_count(), 1, "{what}: only the bystander");
    assert!(rx.try_recv().is_err(), "{what}: nothing was delivered");
    assert_untouched(&registry, &bystander);
}

// -- the re-read: a revocation whose close missed the registration -----------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_revoked_session_is_refused_at_admission() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_session_revoked").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;

    let client = pool.get().await.unwrap();
    assert!(
        query_session_revoke_for_account(&client, session_hash(&resolved), &account_id)
            .await
            .unwrap()
    );
    drop(client);

    assert_refused_as_revoked(&pool, &resolved, actor_id, "session revoke").await;
}

/// A password change deletes every session and token of the account — the
/// case where an admitted zombie session socket could go on to mint a fresh
/// API token.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_password_change_refuses_sessions_and_tokens_at_admission() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_password_changed").await;
    let (_, session) = resolve_session(&pool, account_id).await;
    let token = resolve_api_token(&pool, account_id).await;

    let client = pool.get().await.unwrap();
    query_session_revoke_all_for_account(&client, &account_id)
        .await
        .unwrap();
    query_revoke_all_api_tokens_for_account(&client, &account_id)
        .await
        .unwrap();
    drop(client);

    assert_refused_as_revoked(&pool, &session, actor_id, "password change, session").await;
    assert_refused_as_revoked(&pool, &token, actor_id, "password change, api token").await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_revoked_api_token_is_refused_at_admission() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_token_revoked").await;
    let resolved = resolve_api_token(&pool, account_id).await;
    let token_id = resolved
        .api_token_id()
        .expect("a bearer carries its id")
        .to_owned();

    let client = pool.get().await.unwrap();
    assert!(
        query_revoke_api_token_for_account(&client, &token_id, &account_id)
            .await
            .unwrap()
    );
    drop(client);

    assert_refused_as_revoked(&pool, &resolved, actor_id, "token revoke").await;
}

/// The session and token rows are left in place, so the account read alone
/// refuses.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_soft_deleted_account_is_refused_at_admission() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_account_deleted").await;
    let (_, session) = resolve_session(&pool, account_id).await;
    let token = resolve_api_token(&pool, account_id).await;

    let client = pool.get().await.unwrap();
    assert!(
        query_account_soft_delete(&client, &account_id, None)
            .await
            .unwrap()
            .is_some()
    );
    drop(client);

    assert_refused_as_revoked(&pool, &session, actor_id, "account delete, session").await;
    assert_refused_as_revoked(&pool, &token, actor_id, "account delete, api token").await;
}

// -- the control --------------------------------------------------------------

/// Revoking **another** session of the account leaves this upgrade valid: it
/// is admitted, receives the fan-out, and — at the cap — supersedes the
/// account's oldest socket, which a refused upgrade never does.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn another_sessions_revocation_still_admits() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_control").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;
    let (_, other) = resolve_session(&pool, account_id).await;

    let client = pool.get().await.unwrap();
    assert!(
        query_session_revoke_for_account(&client, session_hash(&other), &account_id)
            .await
            .unwrap()
    );
    drop(client);

    let registry = capped_registry(1);
    let (oldest, _oldest_rx) = live_socket(&registry, account_id);
    let (outcome, mut rx) = admit(&registry, &pool, &resolved, actor_id).await;
    let (conn, _guard) = outcome.expect("a live credential is admitted");

    assert!(registry.is_registered(conn.id));
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count_for_account(account_id), 1);
    assert_eq!(
        oldest.close_reason.get(),
        Some(&CloseReason::Superseded),
        "admission is where the cap evicts"
    );
    assert_eq!(registry.broadcast("hello"), 1);
    assert_eq!(rx.try_recv().unwrap().as_str(), "hello");

    // and the session it was admitted under closes it like any other socket
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Session(
            session_hash(&resolved).to_owned()
        )),
        1
    );
    assert!(conn.signal.is_cancelled());
}

/// Dropping the guard `admit_upgrade` returns removes the admitted entry.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn the_returned_guard_owns_the_admitted_entry() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_guard").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;
    let registry = Arc::new(ConnectionRegistry::new());

    let (outcome, _rx) = admit(&registry, &pool, &resolved, actor_id).await;
    let (conn, guard) = outcome.unwrap();
    assert!(registry.is_registered(conn.id));
    drop(guard);
    assert!(!registry.is_registered(conn.id));
}

// -- the role re-read: a role revocation whose close missed the registration ---

/// [`admit`] for an endpoint gated on `admin`.
async fn admit_admin_gated(
    registry: &Arc<ConnectionRegistry>,
    pool: &Pool,
    resolved: &ResolvedAuth,
    actor_id: Uuid,
) -> (
    Result<(Connection, fuz_realtime::ConnectionGuard), UpgradeRefusal>,
    ConnectionReceiver,
) {
    let (tx, rx) = connection_channel(1 << 20);
    let outcome = tokio::time::timeout(
        STEP_TIMEOUT,
        admit_upgrade(registry, pool, resolved, &actor_id, &[ROLE_ADMIN], tx),
    )
    .await
    .expect("admission completes");
    (outcome, rx)
}

/// Seed an account whose actor holds a global `admin` grant, and resolve a
/// session for it — the upgrade the gate in front admitted.
async fn seed_admin_upgrade(pool: &Pool, username: &str) -> (Uuid, Uuid, ResolvedAuth) {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    grant_role(pool, actor_id, ROLE_ADMIN).await;
    let (_, resolved) = resolve_session(pool, account_id).await;
    (account_id, actor_id, resolved)
}

/// A held role admits, and the registration carries the endpoint's roles: a
/// role close reaches the admitted connection and marks it for 4006.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_held_role_is_admitted_under_the_endpoint_roles() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id, resolved) = seed_admin_upgrade(&pool, "ws_role_held").await;
    let registry = Arc::new(ConnectionRegistry::new());

    let (outcome, _rx) = admit_admin_gated(&registry, &pool, &resolved, actor_id).await;
    let (conn, _guard) = outcome.expect("the role is held");
    assert!(registry.is_registered(conn.id));
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Role {
            account_id,
            role: ROLE_ADMIN.to_owned()
        }),
        1
    );
    assert_eq!(
        conn.close_reason.get(),
        Some(&CloseReason::PermissionRevoked)
    );
}

/// The role is revoked between the gate and the registration, and *no* close
/// is delivered — the shape of a role revocation whose close ran before the
/// socket registered. The re-read alone refuses: 4006, not 4001.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_revoked_role_is_refused_at_admission_with_4006() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id, resolved) = seed_admin_upgrade(&pool, "ws_role_revoked").await;
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE role_grant SET revoked_at = NOW() WHERE actor_id = $1",
            &[&actor_id],
        )
        .await
        .unwrap();

    let registry = capped_registry(1);
    let (bystander, _bystander_rx) = live_socket(&registry, account_id);
    let (outcome, mut rx) = admit_admin_gated(&registry, &pool, &resolved, actor_id).await;
    let refusal = outcome.expect_err("a lost role is not admitted");
    assert_eq!(refusal, UpgradeRefusal::PermissionRevoked);
    assert_eq!(refusal.close_code(), WS_CLOSE_PERMISSION_REVOKED);
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count(), 1, "only the bystander");
    assert!(rx.try_recv().is_err(), "nothing was delivered");
    assert_untouched(&registry, &bystander);
}

/// A scoped grant of the role never admits at a role gate.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_scoped_grant_is_refused_at_admission_with_4006() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_role_scoped").await;
    grant_scoped_role(&pool, actor_id, ROLE_ADMIN, "space", Uuid::new_v4()).await;
    let (_, resolved) = resolve_session(&pool, account_id).await;

    let registry = Arc::new(ConnectionRegistry::new());
    let (outcome, _rx) = admit_admin_gated(&registry, &pool, &resolved, actor_id).await;
    assert_eq!(outcome.map(|_| ()), Err(UpgradeRefusal::PermissionRevoked));
}

/// The acting actor is soft-deleted between the gate and the registration —
/// the account and its credential stay live, and soft delete revokes no
/// `role_grant` row — with no close delivered. The actor re-read refuses on
/// an endpoint gated on a role it still holds a row for: 4001, a dead
/// identity rather than a lost role. The grant read alone counts none of a
/// tombstoned actor's grants either, and counts them again on undelete.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_soft_deleted_actor_is_refused_at_admission_with_4001() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id, resolved) = seed_admin_upgrade(&pool, "ws_actor_deleted").await;
    let client = pool.get().await.unwrap();
    assert!(
        query_active_actor_holds_any_global_role(&client, &actor_id, &[ROLE_ADMIN])
            .await
            .unwrap()
    );
    assert!(
        query_actor_soft_delete(&client, &actor_id, None)
            .await
            .unwrap()
    );
    assert!(
        !query_active_actor_holds_any_global_role(&client, &actor_id, &[ROLE_ADMIN])
            .await
            .unwrap(),
        "a tombstoned actor's grants count for nothing"
    );
    drop(client);

    let registry = capped_registry(1);
    let (bystander, _bystander_rx) = live_socket(&registry, account_id);
    let (outcome, mut rx) = admit_admin_gated(&registry, &pool, &resolved, actor_id).await;
    let refusal = outcome.expect_err("a tombstoned actor is not admitted");
    assert_eq!(refusal, UpgradeRefusal::Revoked);
    assert_eq!(refusal.close_code(), WS_CLOSE_SESSION_REVOKED);
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count(), 1, "only the bystander");
    assert!(rx.try_recv().is_err(), "nothing was delivered");
    assert_untouched(&registry, &bystander);

    let client = pool.get().await.unwrap();
    assert!(query_actor_undelete(&client, &actor_id).await.unwrap());
    assert!(
        query_active_actor_holds_any_global_role(&client, &actor_id, &[ROLE_ADMIN])
            .await
            .unwrap(),
        "undelete restores the grants"
    );
}

/// The same tombstone on an **ungated** endpoint: no role is re-read, so the
/// actor re-read alone refuses — 4001, nothing admitted, nothing evicted.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_soft_deleted_actor_is_refused_at_ungated_admission() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_actor_deleted_ungated").await;
    let (_, session) = resolve_session(&pool, account_id).await;
    let token = resolve_api_token(&pool, account_id).await;
    assert!(
        query_actor_soft_delete(&pool.get().await.unwrap(), &actor_id, None)
            .await
            .unwrap()
    );

    assert_refused_as_revoked(&pool, &session, actor_id, "actor delete, session").await;
    assert_refused_as_revoked(&pool, &token, actor_id, "actor delete, api token").await;
}

/// A role close reaches the upgrade while it is stalled inside its re-read:
/// the role row is untouched, so only the pending registration can refuse —
/// with 4006, the reason its closer recorded, not a revocation's 4001.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_role_close_during_admission_refuses_the_upgrade_with_4006() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id, resolved) =
        seed_admin_upgrade(&pool, "ws_role_closed_pending").await;
    let registry = Arc::new(ConnectionRegistry::new());

    // `auth_session` is the re-read's first statement
    let lock = TestingTableLock::acquire(&pool, "auth_session").await;
    let (tx, mut rx) = connection_channel(1 << 20);
    let admission = tokio::spawn({
        let registry = Arc::clone(&registry);
        let pool = pool.clone();
        async move { admit_upgrade(&registry, &pool, &resolved, &actor_id, &[ROLE_ADMIN], tx).await }
    });
    lock.wait_for_waiter().await;
    assert_eq!(registry.pending_connection_count(), 1, "registered pending");
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Role {
            account_id,
            role: ROLE_ADMIN.to_owned()
        }),
        1,
        "the role close finds the pending registration"
    );
    lock.release().await;

    let refusal = tokio::time::timeout(STEP_TIMEOUT, admission)
        .await
        .expect("admission completes")
        .unwrap()
        .expect_err("closed while pending");
    assert_eq!(refusal, UpgradeRefusal::PermissionRevoked);
    assert_eq!(registry.pending_connection_count(), 0);
    assert!(rx.recv().await.is_none(), "its sender was dropped, unused");
}

/// A role re-read that fails is not "held": 1011, never admitted unchecked.
/// `role_grant` is renamed out from under it — the credential re-read before
/// it reads no `role_grant`, so it passes.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_failing_role_recheck_refuses_the_upgrade_with_1011() {
    let pool = fresh_db_pool().await;
    let (_, actor_id, resolved) = seed_admin_upgrade(&pool, "ws_role_recheck_fails").await;
    pool.get()
        .await
        .unwrap()
        .batch_execute("ALTER TABLE role_grant RENAME TO role_grant_gone")
        .await
        .unwrap();

    let registry = Arc::new(ConnectionRegistry::new());
    let (outcome, _rx) = admit_admin_gated(&registry, &pool, &resolved, actor_id).await;
    let refusal = outcome.expect_err("an unchecked role is not admitted");
    assert_eq!(refusal, UpgradeRefusal::Unavailable);
    assert_eq!(refusal.close_code(), WS_CLOSE_INTERNAL_ERROR);
    assert_eq!(registry.pending_connection_count(), 0);
}

// -- the pending registration: a close that lands mid-admission ----------------

/// A close reaches the upgrade while it is stalled inside its re-read — the
/// credential itself untouched, as when another session's logout closes the
/// whole account. The re-read passes, so only the pending registration can
/// refuse it: 4001, and the account's live socket at the cap is not evicted.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_close_during_admission_refuses_the_upgrade() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_closed_pending").await;
    let other_account = seed_account_actor(&pool, "ws_closed_pending_other").await.0;
    let (_, resolved) = resolve_session(&pool, account_id).await;

    let registry = capped_registry(1);
    let (bystander, _bystander_rx) = live_socket(&registry, other_account);

    // `auth_session` is the re-read's first statement
    let lock = TestingTableLock::acquire(&pool, "auth_session").await;
    let (tx, mut rx) = connection_channel(1 << 20);
    let admission = tokio::spawn({
        let registry = Arc::clone(&registry);
        let pool = pool.clone();
        async move { admit_upgrade(&registry, &pool, &resolved, &actor_id, &[], tx).await }
    });
    lock.wait_for_waiter().await;
    assert_eq!(registry.pending_connection_count(), 1, "registered pending");
    assert_eq!(registry.connection_count_for_account(account_id), 0);

    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account_id)),
        1,
        "the close finds the pending registration"
    );
    lock.release().await;

    let refusal = tokio::time::timeout(STEP_TIMEOUT, admission)
        .await
        .expect("admission completes")
        .unwrap()
        .expect_err("closed while pending");
    assert_eq!(refusal.close_code(), WS_CLOSE_SESSION_REVOKED);
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count_for_account(account_id), 0);
    assert!(rx.recv().await.is_none(), "its sender was dropped, unused");
    assert_untouched(&registry, &bystander);
}

// -- the shutdown: a close-all that lands mid-admission or before it ----------

/// The server's close-all reaches the upgrade while it is stalled inside its
/// re-read. The re-read passes; the pending registration was closed for the
/// shutdown, so the upgrade is refused with 1001 — the client reconnects,
/// rather than giving its credential up as a 4001 would make it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_shutdown_during_admission_refuses_the_upgrade_with_1001() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_shutdown_pending").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;
    let registry = Arc::new(ConnectionRegistry::new());

    let lock = TestingTableLock::acquire(&pool, "auth_session").await;
    let (tx, mut rx) = connection_channel(1 << 20);
    let admission = tokio::spawn({
        let registry = Arc::clone(&registry);
        let pool = pool.clone();
        async move { admit_upgrade(&registry, &pool, &resolved, &actor_id, &[], tx).await }
    });
    lock.wait_for_waiter().await;
    assert_eq!(registry.pending_connection_count(), 1, "registered pending");
    assert_eq!(
        registry.close_all_connections(),
        1,
        "the close-all finds it"
    );
    lock.release().await;

    let refusal = tokio::time::timeout(STEP_TIMEOUT, admission)
        .await
        .expect("admission completes")
        .unwrap()
        .expect_err("closed while pending");
    assert_eq!(refusal, UpgradeRefusal::ShuttingDown);
    assert_eq!(refusal.close_code(), WS_CLOSE_GOING_AWAY);
    assert_eq!(registry.connection_count(), 0);
    assert!(rx.recv().await.is_none(), "its sender was dropped, unused");
}

/// An upgrade whose admission starts after the close-all is born closed and
/// refused with 1001, though its credential is live.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn an_admission_after_the_shutdown_is_refused_with_1001() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_shutdown_after").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;
    let registry = Arc::new(ConnectionRegistry::new());
    assert_eq!(registry.close_all_connections(), 0);

    let (outcome, mut rx) = admit(&registry, &pool, &resolved, actor_id).await;
    assert_eq!(
        outcome.expect_err("born closed"),
        UpgradeRefusal::ShuttingDown
    );
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count(), 0);
    assert!(rx.recv().await.is_none());
}

/// A registration born closed is refused before any database work: with the
/// re-read's table locked, the pool closed, or the pool's one client held,
/// the refusal still comes at once — the shutdown's 1001 never waits on, or
/// depends on, the database.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn an_admission_after_the_shutdown_needs_no_database() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_shutdown_no_db").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;
    let registry = Arc::new(ConnectionRegistry::new());
    assert_eq!(registry.close_all_connections(), 0);

    let lock = TestingTableLock::acquire(&pool, "auth_session").await;
    let (tx, mut rx) = connection_channel(1 << 20);
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        admit_upgrade(&registry, &pool, &resolved, &actor_id, &[], tx),
    )
    .await
    .expect("refused without waiting on the locked re-read");
    lock.release().await;
    let refusal = outcome.expect_err("born closed");
    assert_eq!(refusal, UpgradeRefusal::ShuttingDown);
    assert_eq!(refusal.close_code(), WS_CLOSE_GOING_AWAY);
    assert_eq!(registry.pending_connection_count(), 0);
    assert!(rx.recv().await.is_none());

    // nor on the pool: with no database to check out from at all, the
    // refusal is still the shutdown's, not unavailable
    let dead_pool = fuz_db::create_pool(&DB.url(), &fuz_db::PoolOptions::default()).unwrap();
    dead_pool.close();
    let (tx, _rx) = connection_channel(1 << 20);
    let refusal = admit_upgrade(&registry, &dead_pool, &resolved, &actor_id, &[], tx)
        .await
        .expect_err("born closed");
    assert_eq!(refusal, UpgradeRefusal::ShuttingDown);

    // nor on a checkout: with the pool's one client held, the refusal comes
    // at once instead of waiting for a client to come back
    let pg_config: tokio_postgres::Config = DB.url().parse().unwrap();
    let manager = deadpool_postgres::Manager::new(pg_config, tokio_postgres::NoTls);
    let busy_pool = Pool::builder(manager).max_size(1).build().unwrap();
    let held = busy_pool.get().await.unwrap();
    let (tx, _rx) = connection_channel(1 << 20);
    let refusal = tokio::time::timeout(
        Duration::from_secs(2),
        admit_upgrade(&registry, &busy_pool, &resolved, &actor_id, &[], tx),
    )
    .await
    .expect("refused without waiting on the checkout")
    .expect_err("born closed");
    assert_eq!(refusal, UpgradeRefusal::ShuttingDown);
    drop(held);
}

/// A shutdown that closes the registration while its re-read is running, and
/// the re-read then failing — the database going away under the same
/// shutdown — is refused for the shutdown (1001), not as unavailable (1011).
/// The re-read's backend is terminated while it waits on the lock.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_recheck_failing_after_the_shutdown_closed_it_is_refused_with_1001() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_shutdown_recheck_fails").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;
    let registry = Arc::new(ConnectionRegistry::new());

    let lock = TestingTableLock::acquire(&pool, "auth_session").await;
    let (tx, _rx) = connection_channel(1 << 20);
    let admission = tokio::spawn({
        let registry = Arc::clone(&registry);
        let pool = pool.clone();
        async move { admit_upgrade(&registry, &pool, &resolved, &actor_id, &[], tx).await }
    });
    lock.wait_for_waiter().await;
    assert_eq!(
        registry.close_all_connections(),
        1,
        "the close-all finds it"
    );
    let terminated: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(pg_terminate_backend(pid)) FROM pg_locks
             WHERE NOT granted AND relation = to_regclass('auth_session')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(terminated, 1, "the re-read's backend");

    let refusal = tokio::time::timeout(STEP_TIMEOUT, admission)
        .await
        .expect("admission completes")
        .unwrap()
        .expect_err("closed while pending, re-read failed");
    lock.release().await;
    assert_eq!(refusal, UpgradeRefusal::ShuttingDown);
    assert_eq!(refusal.close_code(), WS_CLOSE_GOING_AWAY);
}

// -- fail closed ---------------------------------------------------------------

/// When the re-read cannot run, the upgrade is refused with 1011 rather than
/// admitted unchecked — and still evicts nothing.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn an_unreachable_database_refuses_the_upgrade() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_unavailable").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;

    let registry = capped_registry(1);
    let (bystander, _bystander_rx) = live_socket(&registry, account_id);
    let dead_pool = fuz_db::create_pool(&DB.url(), &fuz_db::PoolOptions::default()).unwrap();
    dead_pool.close();

    let (outcome, _rx) = admit(&registry, &dead_pool, &resolved, actor_id).await;
    let refusal = outcome.expect_err("an unchecked credential is not admitted");
    assert_eq!(refusal, UpgradeRefusal::Unavailable);
    assert_eq!(refusal.close_code(), WS_CLOSE_INTERNAL_ERROR);
    assert_eq!(registry.pending_connection_count(), 0);
    assert_untouched(&registry, &bystander);
}

/// The same when the pool hands out a client and the re-check's own query
/// fails: a query error is not "live". `auth_session` is renamed out from
/// under the re-read (the next case's fresh schema restores it).
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_failing_recheck_query_refuses_the_upgrade() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_recheck_fails").await;
    let (_, resolved) = resolve_session(&pool, account_id).await;

    let registry = capped_registry(1);
    let (bystander, _bystander_rx) = live_socket(&registry, account_id);
    pool.get()
        .await
        .unwrap()
        .batch_execute("ALTER TABLE auth_session RENAME TO auth_session_gone")
        .await
        .unwrap();

    let (outcome, mut rx) = admit(&registry, &pool, &resolved, actor_id).await;
    let refusal = outcome.expect_err("an unchecked credential is not admitted");
    assert_eq!(refusal, UpgradeRefusal::Unavailable);
    assert_eq!(refusal.close_code(), WS_CLOSE_INTERNAL_ERROR);
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count(), 1, "only the bystander");
    assert!(rx.try_recv().is_err(), "nothing was delivered");
    assert_untouched(&registry, &bystander);
}

// -- through the real upgrade handler -----------------------------------------

/// Serve [`register_action_ws`] over `registry`, gated on [`ROLE_ADMIN`] so
/// the upgrade has a database read between resolving its credential and
/// registering the socket.
async fn serve(pool: &Pool, registry: &Arc<ConnectionRegistry>) -> SocketAddr {
    serve_gated(pool, registry, vec![ROLE_ADMIN]).await
}

/// Serve [`register_action_ws`] over `registry`, gated on `required_roles`
/// (empty: no role gate).
async fn serve_gated(
    pool: &Pool,
    registry: &Arc<ConnectionRegistry>,
    required_roles: Vec<&'static str>,
) -> SocketAddr {
    let app = ws_app(pool, registry, required_roles);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// The real upgrade handler over `registry`, role-gated on `required_roles`.
fn ws_app(
    pool: &Pool,
    registry: &Arc<ConnectionRegistry>,
    required_roles: Vec<&'static str>,
) -> axum::Router {
    let state = WsRouteState {
        dispatch: fuz_actions::ActionDispatch {
            gate: fuz_testing::testing_auth_gate(pool.clone()),
            registry: Arc::new(ActionRegistry::compile([]).unwrap()),
            audit: Arc::new(AuditEmitter::new(pool.clone())),
            connection_closer: Arc::new(NoopConnectionCloser),
            notification_sender: Arc::new(NoopNotificationSender),
            rate_limits: fuz_actions::ActionRateLimits::defaults(
                fuz_auth::RateLimiterMode::DisabledForTesting,
            ),
        },
        connection_registry: Arc::clone(registry),
        required_roles,
    };
    register_action_ws(state)
}

/// Open a TCP connection and send the upgrade request under `cookie`.
async fn send_upgrade(addr: SocketAddr, cookie: &str) -> tokio::net::TcpStream {
    send_upgrade_with(addr, &format!("Cookie: {cookie}")).await
}

/// Open a TCP connection and send the upgrade request carrying
/// `credential_header` (one `Name: value` line).
async fn send_upgrade_with(addr: SocketAddr, credential_header: &str) -> tokio::net::TcpStream {
    send_upgrade_to(addr, "/ws", credential_header).await
}

/// Open a TCP connection and send the upgrade request for `target` (path and
/// query) carrying `credential_header` (one `Name: value` line).
async fn send_upgrade_to(
    addr: SocketAddr,
    target: &str,
    credential_header: &str,
) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
         {credential_header}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream
}

/// Read the handshake response's status line, consuming exactly its header
/// block.
async fn read_status_line(stream: &mut tokio::net::TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    let read = async {
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, read)
        .await
        .expect("the handshake answers");
    let head = String::from_utf8(head).unwrap();
    head.lines().next().unwrap().to_owned()
}

/// Read one unmasked server frame with a short payload: `(opcode, payload)`.
async fn read_frame(stream: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
    let read = async {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0] & 0x80, 0x80, "a final frame");
        assert_eq!(header[1] & 0x80, 0, "an unmasked server frame");
        let len = match header[1] {
            126 => {
                let mut extended = [0u8; 2];
                stream.read_exact(&mut extended).await.unwrap();
                usize::from(u16::from_be_bytes(extended))
            }
            127 => {
                let mut extended = [0u8; 8];
                stream.read_exact(&mut extended).await.unwrap();
                usize::try_from(u64::from_be_bytes(extended)).unwrap()
            }
            short => usize::from(short),
        };
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        (header[0] & 0x0f, payload)
    };
    tokio::time::timeout(STEP_TIMEOUT, read)
        .await
        .expect("the server writes a frame")
}

const OPCODE_TEXT: u8 = 0x1;
const OPCODE_CLOSE: u8 = 0x8;

/// **The upgrade checks the origin first.** A foreign `Origin` is refused `403`
/// before the credential walk — over a pool that cannot connect, so a request
/// that reached the walk would show it — and an allowed origin with no
/// credential reaches the next gate, the `401`. No database: the refusals
/// both come before any checkout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_upgrade_refuses_a_foreign_origin_at_the_gate() {
    let pool = fuz_db::create_pool(
        "postgres://nobody@127.0.0.1:1/nothing",
        &fuz_db::PoolOptions::default(),
    )
    .unwrap();
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve(&pool, &registry).await;

    let mut stream = send_upgrade_with(addr, "Origin: https://evil.example").await;
    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 403 Forbidden"
    );

    let allowed = format!("Origin: {}", fuz_testing::TESTING_ALLOWED_ORIGIN);
    let mut stream = send_upgrade_with(addr, &allowed).await;
    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 401 Unauthorized"
    );
    assert_eq!(registry.pending_connection_count(), 0);
}

/// **An admitted request that asks for no upgrade is the path's 404.** The
/// gates pass — a live admin session on an admin-gated endpoint — and only
/// then is the upgrade looked at: a `GET` without `Upgrade: websocket`, and a
/// `HEAD` (which axum serves through the `GET` route), answer the not-found
/// the twin's upgrade helper falls through to, and nothing is registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn an_admitted_request_without_an_upgrade_is_not_found() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_admin_session(&pool, "ws_no_upgrade").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve(&pool, &registry).await;

    for method in ["GET", "HEAD"] {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!("{method} /ws HTTP/1.1\r\nHost: {addr}\r\nCookie: {cookie}\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        assert_eq!(
            read_status_line(&mut stream).await,
            "HTTP/1.1 404 Not Found",
            "{method}"
        );
    }
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count_for_account(account_id), 0);
}

/// **A refused checkout in the actor phase is the 503.** The credential
/// resolves on the request's first checkout and the acting-actor phase's own
/// checkout is refused: the flat 503 before any upgrade, never the 500 of a
/// failed read, and nothing registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_refused_actor_phase_checkout_answers_the_503() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_admin_session(&pool, "ws_actor_checkout").await;
    let budgeted = fuz_testing::budgeted_pool(&DB.url(), 1);
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve(&budgeted, &registry).await;

    let mut stream = send_upgrade(addr, &cookie).await;
    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 503 Service Unavailable"
    );
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count_for_account(account_id), 0);
}

/// Seed an admin account and a session cookie for it.
async fn seed_admin_session(pool: &Pool, username: &str) -> (Uuid, String) {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    grant_role(pool, actor_id, ROLE_ADMIN).await;
    let cookie =
        mint_session_cookie(pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    (account_id, cookie)
}

/// **The regression guard.** An untouched credential upgrades, is admitted,
/// and its loop runs — a broadcast reaches the socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_live_session_upgrades_and_is_admitted() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_admin_session(&pool, "ws_e2e_live").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve(&pool, &registry).await;

    let mut stream = send_upgrade(addr, &cookie).await;
    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 101 Switching Protocols"
    );
    let admitted = async {
        while registry.connection_count_for_account(account_id) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, admitted)
        .await
        .expect("the upgrade is admitted");
    assert_eq!(registry.pending_connection_count(), 0);

    assert_eq!(registry.broadcast("hello"), 1);
    let (opcode, payload) = read_frame(&mut stream).await;
    assert_eq!(opcode, OPCODE_TEXT);
    assert_eq!(payload, b"hello");
}

/// **The race, end to end.** The upgrade is held at its role gate — after the
/// credential resolved, before the socket registers — and its session is
/// revoked there, the revocation's close finding nothing to close. The
/// handshake still completes (the gates all passed), and the socket is then
/// closed with 4001 instead of being admitted: nothing registers, the
/// account's live socket at the cap is not evicted, and a broadcast sent
/// meanwhile never reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_session_revoked_mid_upgrade_is_closed_with_4001() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_admin_session(&pool, "ws_e2e_revoked").await;
    let registry = capped_registry(1);
    let (bystander, _bystander_rx) = live_socket(&registry, account_id);
    let addr = serve(&pool, &registry).await;

    // `role_grant` is read by the role gate alone
    let lock = TestingTableLock::acquire(&pool, "role_grant").await;
    let mut stream = send_upgrade(addr, &cookie).await;
    lock.wait_for_waiter().await;
    assert_eq!(registry.pending_connection_count(), 0, "not registered yet");

    // the revocation commits, and its close runs — against a registry that
    // does not hold the upgrade yet
    pool.get()
        .await
        .unwrap()
        .execute(
            "DELETE FROM auth_session WHERE account_id = $1",
            &[&account_id],
        )
        .await
        .unwrap();
    lock.release().await;

    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 101 Switching Protocols"
    );
    registry.broadcast("must not reach a refused socket");
    let (opcode, payload) = read_frame(&mut stream).await;
    assert_eq!(opcode, OPCODE_CLOSE, "the first frame is the refusal");
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        WS_CLOSE_SESSION_REVOKED
    );
    assert_eq!(&payload[2..], WS_CLOSE_SESSION_REVOKED_REASON.as_bytes());

    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count_for_account(account_id), 1);
    assert_untouched(&registry, &bystander);
}

/// **The shutdown race, end to end.** The upgrade is held at its role gate
/// when the server's token fires, so the close-all finds nothing; released,
/// it answers `101`, registers into a closing registry, and is refused with
/// a 1001 close frame. `serve_with_shutdown` returns only after that
/// refusal has been written and has lingered — the hold the handler takes
/// before the handshake keeps the shutdown's wait open for a socket no
/// registration covers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn an_upgrade_in_flight_at_shutdown_is_refused_with_1001_before_serve_returns() {
    let pool = fresh_db_pool().await;
    let (account_id, cookie) = seed_admin_session(&pool, "ws_e2e_shutdown").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let app = ws_app(&pool, &registry, vec![ROLE_ADMIN]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let token = CancellationToken::new();
    let closer = Arc::new(AnnouncingCloser {
        inner: Arc::clone(&registry),
        closed: tokio::sync::Notify::new(),
    });
    let (returned_tx, returned_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn({
        let token = token.clone();
        let closer = Arc::clone(&closer);
        let pool_for_stack = pool.clone();
        async move {
            // `serve_with_shutdown` serves only a composed stack: the one
            // group, with the testing gate's allowlist
            let cap = fuz_http::BodyCap::Bytes(fuz_http::DEFAULT_BODY_LIMIT_BYTES);
            let gated = fuz_http::compose_stack(
                [fuz_http::RouteGroup::new("ws", app, cap)],
                fuz_http::RouteGroup::new("fallback", axum::Router::new(), cap),
                &fuz_testing::testing_auth_gate(pool_for_stack).stack_options(Arc::new(Vec::new())),
            );
            let served = fuz_http::serve_with_shutdown(
                listener,
                gated,
                token,
                closer.as_ref(),
                Duration::from_secs(30),
            )
            .await;
            let _ = returned_tx.send(std::time::Instant::now());
            served
        }
    });

    let lock = TestingTableLock::acquire(&pool, "role_grant").await;
    let mut stream = send_upgrade(addr, &cookie).await;
    lock.wait_for_waiter().await;
    token.cancel();
    tokio::time::timeout(STEP_TIMEOUT, closer.closed.notified())
        .await
        .expect("the token fires the close-all");
    let released = std::time::Instant::now();
    lock.release().await;

    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 101 Switching Protocols"
    );
    let (opcode, payload) = read_frame(&mut stream).await;
    assert_eq!(opcode, OPCODE_CLOSE);
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        WS_CLOSE_GOING_AWAY
    );
    assert_eq!(&payload[2..], WS_CLOSE_GOING_AWAY_REASON.as_bytes());

    let returned = tokio::time::timeout(STEP_TIMEOUT, returned_rx)
        .await
        .expect("serve returns")
        .unwrap();
    server.await.unwrap().unwrap();
    assert!(
        returned.duration_since(released) >= Duration::from_millis(800),
        "serve waited out the refusal's linger, returned {:?} after the release",
        returned.duration_since(released)
    );
    assert_eq!(registry.connection_count_for_account(account_id), 0);
}

/// The registry as the server's closer, announcing each close-all so a test
/// can let a held upgrade go on only after it.
struct AnnouncingCloser {
    inner: Arc<ConnectionRegistry>,
    closed: tokio::sync::Notify,
}

impl ShutdownCloser for AnnouncingCloser {
    fn close_all_connections(&self) -> usize {
        let closed = self.inner.close_all_connections();
        self.closed.notify_one();
        closed
    }

    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        self.inner.wait_closed()
    }
}

// -- the stall fixture ----------------------------------------------------------

/// A [`TestingTableLock`] dropped without `release` — a case that panicked
/// while holding one — frees the table: its connection is closed rather than
/// handed back to the pool with the locking transaction still open. Pinned
/// here, in a suite that uses the fixture, because `fuz_testing` has no
/// database suite of its own.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_dropped_table_lock_frees_the_table() {
    let pool = fresh_db_pool().await;
    // checked out first, so the read below can't be served by the lock's own
    // connection coming back out of the pool
    let reader = pool.get().await.unwrap();

    let lock = TestingTableLock::acquire(&pool, "auth_session").await;
    drop(lock);

    let read = reader.query_one("SELECT count(*) FROM auth_session", &[]);
    let row = tokio::time::timeout(STEP_TIMEOUT, read)
        .await
        .expect("the dropped lock no longer blocks the table")
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 0);
}

// -- the outbound bound, through the assembled handler -------------------------

/// The outbound queue budget the bounded router sets — small, so a handful
/// of short frames passes it.
const BOUNDED_QUEUE_BYTES: usize = 4096;

/// A message cap unrelated to any budget the cases use.
const BOUNDED_MESSAGE_BYTES: usize = 1024;

/// The state of a router over `registry` with the
/// `_testing_flood_notifications` action mounted and the daemon token bound
/// to `keeper`. No role gate.
fn bounded_state(pool: &Pool, registry: &Arc<ConnectionRegistry>, keeper: Uuid) -> WsRouteState {
    WsRouteState {
        dispatch: fuz_actions::ActionDispatch {
            gate: fuz_auth::AuthGate {
                daemon_token_state: Some(daemon_token_state(TESTING_DAEMON_TOKEN, Some(keeper))),
                ..fuz_testing::testing_auth_gate(pool.clone())
            },
            registry: Arc::new(
                ActionRegistry::compile([create_testing_flood_notifications_action_spec()])
                    .unwrap(),
            ),
            audit: Arc::new(AuditEmitter::new(pool.clone())),
            connection_closer: Arc::new(NoopConnectionCloser),
            notification_sender: Arc::new(NoopNotificationSender),
            rate_limits: fuz_actions::ActionRateLimits::defaults(
                fuz_auth::RateLimiterMode::DisabledForTesting,
            ),
        },
        connection_registry: Arc::clone(registry),
        required_roles: Vec::new(),
    }
}

/// Serve `app` on a loopback port.
async fn serve_app(app: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Serve [`register_action_ws_with_options`] with the outbound queue budget
/// set to [`BOUNDED_QUEUE_BYTES`] ([`bounded_state`]).
async fn serve_bounded(
    pool: &Pool,
    registry: &Arc<ConnectionRegistry>,
    keeper: Uuid,
) -> SocketAddr {
    let options = ActionWsOptions {
        max_message_bytes: BOUNDED_MESSAGE_BYTES,
        outbound_queue_bytes: BOUNDED_QUEUE_BYTES,
        ..ActionWsOptions::default()
    };
    serve_app(register_action_ws_with_options(
        bounded_state(pool, registry, keeper),
        options,
    ))
    .await
}

/// Upgrade a session socket for `account_id` against `addr` and wait until
/// the registry has admitted it.
async fn upgrade_admitted(
    pool: &Pool,
    registry: &ConnectionRegistry,
    addr: SocketAddr,
    account_id: Uuid,
) -> tokio::net::TcpStream {
    let cookie =
        mint_session_cookie(pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    let mut stream = send_upgrade(addr, &cookie).await;
    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 101 Switching Protocols"
    );
    wait_admitted(registry, account_id).await;
    stream
}

/// Assert `account_id`'s one connection has a budget of exactly `budget`:
/// two frames charged the whole of it between them are queued, and the next
/// frame — an empty one, which costs its overhead — closes the socket with
/// 4005, the queued frames discarded, the account left with no connection.
///
/// The sends run with no await between them, so on the single-threaded test
/// runtime the loop cannot take one before the next arrives.
async fn assert_budget_is_exactly(
    registry: &ConnectionRegistry,
    account_id: Uuid,
    stream: &mut tokio::net::TcpStream,
    budget: usize,
) {
    // two frames, so the second is measured against the budget rather than
    // admitted into an empty queue
    let half = "x".repeat(budget / 2 - OUTBOUND_FRAME_OVERHEAD_BYTES);
    assert_eq!(registry.send_to_account(account_id, &half), 1);
    assert_eq!(
        registry.send_to_account(account_id, &half),
        1,
        "exactly the budget is queued"
    );
    assert_eq!(
        registry.send_to_account(account_id, ""),
        0,
        "nothing past it is"
    );
    assert_eq!(registry.connection_count_for_account(account_id), 0);
    assert_eq!(registry.send_to_account(account_id, "x"), 0);

    assert_overflow_close(stream).await;
}

/// Wait until `account_id` holds one admitted connection.
async fn wait_admitted(registry: &ConnectionRegistry, account_id: Uuid) {
    let admitted = async {
        while registry.connection_count_for_account(account_id) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, admitted)
        .await
        .expect("the upgrade is admitted");
}

/// Assert `stream`'s next frame is the 4005 close and that the server then
/// drops the socket.
async fn assert_overflow_close(stream: &mut tokio::net::TcpStream) {
    let (opcode, payload) = read_frame(stream).await;
    assert_eq!(opcode, OPCODE_CLOSE, "nothing queued is written first");
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        WS_CLOSE_OUTBOUND_OVERFLOW
    );
    assert_eq!(&payload[2..], WS_CLOSE_OUTBOUND_OVERFLOW_REASON.as_bytes());
    let mut rest = Vec::new();
    tokio::time::timeout(STEP_TIMEOUT, stream.read_to_end(&mut rest))
        .await
        .expect("the server drops the socket")
        .unwrap();
    assert!(rest.is_empty(), "nothing follows the close: {rest:?}");
}

/// Write one masked client text frame carrying `text` (under 126 bytes). An
/// all-zero mask leaves the payload as it is.
async fn write_text_frame(stream: &mut tokio::net::TcpStream, text: &str) {
    assert!(text.len() < 126, "a short frame");
    let mut frame = vec![0x81, 0x80 | u8::try_from(text.len()).unwrap(), 0, 0, 0, 0];
    frame.extend_from_slice(text.as_bytes());
    stream.write_all(&frame).await.unwrap();
}

/// **The default.** A router built with a message cap and the default
/// outbound budget ([`ActionWsOptions::default`]) gives each connection
/// [`DEFAULT_WS_OUTBOUND_QUEUE_BYTES`], whatever the cap: a small cap does
/// not shrink the budget and a large one does not grow it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn the_default_outbound_budget_does_not_follow_the_message_cap() {
    assert_eq!(DEFAULT_WS_OUTBOUND_QUEUE_BYTES, 4 * 1024 * 1024);
    let pool = fresh_db_pool().await;
    for (case, max_message_bytes) in [("small", 1024), ("large", 16 * 1024 * 1024)] {
        let (account_id, _actor_id) =
            seed_account_actor(&pool, &format!("ws_e2e_default_{case}")).await;
        let registry = Arc::new(ConnectionRegistry::new());
        let addr = serve_app(register_action_ws_with_options(
            bounded_state(&pool, &registry, account_id),
            ActionWsOptions {
                max_message_bytes,
                ..ActionWsOptions::default()
            },
        ))
        .await;
        let mut stream = upgrade_admitted(&pool, &registry, addr, account_id).await;
        assert_budget_is_exactly(
            &registry,
            account_id,
            &mut stream,
            DEFAULT_WS_OUTBOUND_QUEUE_BYTES,
        )
        .await;
    }

    // and `register_action_ws` itself
    let (account_id, _actor_id) = seed_account_actor(&pool, "ws_e2e_default_plain").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_app(register_action_ws(bounded_state(
        &pool, &registry, account_id,
    )))
    .await;
    let mut stream = upgrade_admitted(&pool, &registry, addr, account_id).await;
    assert_budget_is_exactly(
        &registry,
        account_id,
        &mut stream,
        DEFAULT_WS_OUTBOUND_QUEUE_BYTES,
    )
    .await;
}

/// **The override.** The budget a router's options set is the budget of the
/// connections it admits, exactly.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn an_explicit_outbound_budget_is_honored() {
    let pool = fresh_db_pool().await;
    let (account_id, _actor_id) = seed_account_actor(&pool, "ws_e2e_overflow").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_bounded(&pool, &registry, account_id).await;
    let mut stream = upgrade_admitted(&pool, &registry, addr, account_id).await;
    assert_budget_is_exactly(&registry, account_id, &mut stream, BOUNDED_QUEUE_BYTES).await;
}

/// **The empty-queue exception.** One frame larger than the whole budget is
/// still delivered when nothing is waiting, and the connection stays open.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_frame_larger_than_the_budget_is_delivered_into_an_empty_queue() {
    let pool = fresh_db_pool().await;
    let (account_id, _actor_id) = seed_account_actor(&pool, "ws_e2e_oversized").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_bounded(&pool, &registry, account_id).await;
    let mut stream = upgrade_admitted(&pool, &registry, addr, account_id).await;

    let oversized = "x".repeat(BOUNDED_QUEUE_BYTES * 3);
    for round in 0..2 {
        assert_eq!(
            registry.send_to_account(account_id, &oversized),
            1,
            "round {round}: queued into the empty queue"
        );
        let (opcode, payload) = read_frame(&mut stream).await;
        assert_eq!(opcode, OPCODE_TEXT);
        assert_eq!(payload, oversized.as_bytes(), "round {round}");
    }
    assert_eq!(registry.connection_count_for_account(account_id), 1);
}

/// **Assembly.** A zero outbound budget is refused when the router is built,
/// not at a connection's first send. Needs no database: the pool is never
/// connected.
#[tokio::test]
#[should_panic(expected = "outbound_queue_bytes is zero")]
async fn a_zero_outbound_budget_is_refused_at_registration() {
    let pool = fuz_db::create_pool(&DB.url(), &fuz_db::PoolOptions::default()).unwrap();
    let registry = Arc::new(ConnectionRegistry::new());
    let options = ActionWsOptions {
        outbound_queue_bytes: 0,
        ..ActionWsOptions::default()
    };
    let _router =
        register_action_ws_with_options(bounded_state(&pool, &registry, Uuid::new_v4()), options);
}

/// **From outside.** `_testing_flood_notifications`, called over the socket
/// it floods: a burst inside the budget arrives in order ahead of its
/// response, and a burst whose bytes pass it closes the socket with 4005 —
/// no part of the burst and no response written. A call whose `count` ×
/// `size` is past the action's total cap is refused and floods nothing.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_flood_past_the_budget_closes_the_callers_socket_with_4005() {
    let pool = fresh_db_pool().await;
    let (keeper, _actor_id) = seed_account_actor(&pool, "ws_e2e_flood").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_bounded(&pool, &registry, keeper).await;

    let mut stream = send_upgrade_with(
        addr,
        &format!("{}: {TESTING_DAEMON_TOKEN}", fuz_auth::DAEMON_TOKEN_HEADER),
    )
    .await;
    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 101 Switching Protocols"
    );
    wait_admitted(&registry, keeper).await;

    // a malformed call is refused and floods nothing
    write_text_frame(
        &mut stream,
        r#"{"jsonrpc":"2.0","id":0,"method":"_testing_flood_notifications","params":{"count":-1,"size":8}}"#,
    )
    .await;
    let (opcode, payload) = read_frame(&mut stream).await;
    assert_eq!(opcode, OPCODE_TEXT);
    let refusal: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(refusal["id"], 0);
    assert_eq!(
        refusal["error"]["code"], -32602,
        "invalid_params: {refusal}"
    );

    // so is one whose total is past the cap (65 MiB against 64), though
    // each field is in range
    write_text_frame(
        &mut stream,
        r#"{"jsonrpc":"2.0","id":"big","method":"_testing_flood_notifications","params":{"count":65,"size":1048576}}"#,
    )
    .await;
    let (opcode, payload) = read_frame(&mut stream).await;
    assert_eq!(opcode, OPCODE_TEXT);
    let refusal: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(refusal["id"], "big");
    assert_eq!(
        refusal["error"]["code"], -32602,
        "invalid_params: {refusal}"
    );
    assert_eq!(registry.connection_count_for_account(keeper), 1);

    // inside the budget: every notification, in order, then the response
    write_text_frame(
        &mut stream,
        r#"{"jsonrpc":"2.0","id":1,"method":"_testing_flood_notifications","params":{"count":3,"size":8}}"#,
    )
    .await;
    for index in 0..3 {
        let (opcode, payload) = read_frame(&mut stream).await;
        assert_eq!(opcode, OPCODE_TEXT);
        let frame: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(frame["method"], TESTING_FLOOD_NOTIFICATION_METHOD);
        assert_eq!(frame["params"]["index"], index);
        assert_eq!(frame["params"]["payload"], "x".repeat(8));
    }
    let (opcode, payload) = read_frame(&mut stream).await;
    assert_eq!(opcode, OPCODE_TEXT);
    let response: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"], serde_json::json!({"queued": 3}));
    assert_eq!(registry.connection_count_for_account(keeper), 1);

    // exactly at the action's total cap (64 MiB), so the call is accepted,
    // and far past a budget of 4096: the close, and nothing else
    write_text_frame(
        &mut stream,
        r#"{"jsonrpc":"2.0","id":2,"method":"_testing_flood_notifications","params":{"count":64,"size":1048576}}"#,
    )
    .await;
    assert_overflow_close(&mut stream).await;
    assert_eq!(registry.connection_count_for_account(keeper), 0);
}

// -- the acting-actor phase ----------------------------------------------------

/// Send an upgrade for `target` under `cookie` and read a refusal: its status
/// line and JSON body.
async fn upgrade_refusal(
    addr: SocketAddr,
    target: &str,
    cookie: &str,
) -> (String, serde_json::Value) {
    let mut stream = send_upgrade_to(addr, target, &format!("Cookie: {cookie}")).await;
    let read = async {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let length: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .expect("a refusal carries its body length");
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.unwrap();
        (
            head.lines().next().unwrap().to_owned(),
            serde_json::from_slice(&body).unwrap(),
        )
    };
    tokio::time::timeout(STEP_TIMEOUT, read)
        .await
        .expect("the handshake answers")
}

/// Send an upgrade for `target` under `cookie`, assert it answers `101`, and
/// wait until `account_id` holds the admitted connection.
async fn upgrade_admitted_at(
    registry: &ConnectionRegistry,
    addr: SocketAddr,
    target: &str,
    cookie: &str,
    account_id: Uuid,
) -> tokio::net::TcpStream {
    let mut stream = send_upgrade_to(addr, target, &format!("Cookie: {cookie}")).await;
    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 101 Switching Protocols"
    );
    wait_admitted(registry, account_id).await;
    stream
}

/// Seed an account with two actors and a session cookie for it:
/// `(account_id, first_actor, second_actor, cookie)`.
async fn seed_two_actor_session(pool: &Pool, username: &str) -> (Uuid, Uuid, Uuid, String) {
    let (account_id, first) = seed_account_actor(pool, username).await;
    let second = seed_extra_actor(pool, account_id, &format!("{username}_second")).await;
    let cookie =
        mint_session_cookie(pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    (account_id, first, second, cookie)
}

/// A multi-actor account that omits `acting` is refused with the twin's 400
/// `actor_required`, listing the account's actors — on an endpoint with no
/// role gate, so the phase runs whether or not a role is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_multi_actor_upgrade_without_acting_is_refused_actor_required() {
    let pool = fresh_db_pool().await;
    let (_, first, second, cookie) = seed_two_actor_session(&pool, "ws_acting_required").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_gated(&pool, &registry, Vec::new()).await;

    let (status, body) = upgrade_refusal(addr, "/ws", &cookie).await;
    assert_eq!(status, "HTTP/1.1 400 Bad Request");
    assert_eq!(body["error"], "actor_required");
    let mut available: Vec<&str> = body["available"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    available.sort_unstable();
    let mut expected = vec![first.to_string(), second.to_string()];
    expected.sort_unstable();
    assert_eq!(available, expected);
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count(), 0);
}

/// `?acting=` picks one of the account's actors, and the upgrade proceeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn acting_as_an_own_actor_upgrades() {
    let pool = fresh_db_pool().await;
    let (account_id, _, second, cookie) = seed_two_actor_session(&pool, "ws_acting_own").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_gated(&pool, &registry, Vec::new()).await;

    upgrade_admitted_at(
        &registry,
        addr,
        &format!("/ws?acting={second}"),
        &cookie,
        account_id,
    )
    .await;
}

/// A selector naming another account's actor, or no actor at all, is the
/// twin's 400 `actor_not_on_account`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn acting_as_a_foreign_actor_is_refused_actor_not_on_account() {
    let pool = fresh_db_pool().await;
    let (account_id, _) = seed_account_actor(&pool, "ws_acting_foreign").await;
    let (_, foreign_actor) = seed_account_actor(&pool, "ws_acting_foreign_other").await;
    let cookie =
        mint_session_cookie(&pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_gated(&pool, &registry, Vec::new()).await;

    for acting in [foreign_actor, Uuid::new_v4()] {
        let (status, body) = upgrade_refusal(addr, &format!("/ws?acting={acting}"), &cookie).await;
        assert_eq!(status, "HTTP/1.1 400 Bad Request");
        assert_eq!(body, serde_json::json!({"error": "actor_not_on_account"}));
    }
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(registry.connection_count(), 0);
}

/// A malformed selector reads as omitted, as the twin's `parse_acting` reads
/// it: a single-actor account upgrades, a multi-actor one is told to pick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_malformed_acting_reads_as_omitted() {
    let pool = fresh_db_pool().await;
    let (single, _) = seed_account_actor(&pool, "ws_acting_malformed_single").await;
    let single_cookie =
        mint_session_cookie(&pool, &testing_keyring(), single, SESSION_COOKIE_NAME).await;
    let (_, _, _, multi_cookie) = seed_two_actor_session(&pool, "ws_acting_malformed_multi").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_gated(&pool, &registry, Vec::new()).await;

    upgrade_admitted_at(
        &registry,
        addr,
        "/ws?acting=not-a-uuid",
        &single_cookie,
        single,
    )
    .await;
    let (status, body) = upgrade_refusal(addr, "/ws?acting=not-a-uuid", &multi_cookie).await;
    assert_eq!(status, "HTTP/1.1 400 Bad Request");
    assert_eq!(body["error"], "actor_required");
}

/// An account whose only actor is soft-deleted has no actor to act as: the
/// twin's 500 `no_actors_on_account`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn an_account_with_no_active_actor_is_refused_no_actors_on_account() {
    let pool = fresh_db_pool().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "ws_acting_no_actors").await;
    let cookie =
        mint_session_cookie(&pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    assert!(
        query_actor_soft_delete(&pool.get().await.unwrap(), &actor_id, None)
            .await
            .unwrap()
    );
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_gated(&pool, &registry, Vec::new()).await;

    let (status, body) = upgrade_refusal(addr, "/ws", &cookie).await;
    assert_eq!(status, "HTTP/1.1 500 Internal Server Error");
    assert_eq!(body, serde_json::json!({"error": "no_actors_on_account"}));
    assert_eq!(registry.connection_count(), 0);
}

/// The role gate reads the **acting** actor's grants: on an admin-gated
/// endpoint, an account whose first actor is admin is refused 403 acting as
/// its roleless sibling, and upgrades acting as the admin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn the_role_gate_reads_the_acting_actors_grants() {
    let pool = fresh_db_pool().await;
    let (account_id, admin, roleless, cookie) =
        seed_two_actor_session(&pool, "ws_acting_role").await;
    grant_role(&pool, admin, ROLE_ADMIN).await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve(&pool, &registry).await;

    let (status, body) = upgrade_refusal(addr, &format!("/ws?acting={roleless}"), &cookie).await;
    assert_eq!(status, "HTTP/1.1 403 Forbidden");
    assert_eq!(
        body,
        serde_json::json!({"error": "insufficient_permissions", "required_roles": [ROLE_ADMIN]})
    );
    assert_eq!(registry.connection_count(), 0);

    upgrade_admitted_at(
        &registry,
        addr,
        &format!("/ws?acting={admin}"),
        &cookie,
        account_id,
    )
    .await;
}

/// The admission re-read reads the acting actor's grants too: a role held
/// only by a sibling actor of the account does not admit.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_role_held_by_a_sibling_actor_is_refused_at_admission_with_4006() {
    let pool = fresh_db_pool().await;
    let (account_id, roleless) = seed_account_actor(&pool, "ws_acting_sibling_role").await;
    let admin = seed_extra_actor(&pool, account_id, "ws_acting_sibling_role_admin").await;
    grant_role(&pool, admin, ROLE_ADMIN).await;
    let (_, resolved) = resolve_session(&pool, account_id).await;
    let registry = Arc::new(ConnectionRegistry::new());

    let (outcome, _rx) = admit_admin_gated(&registry, &pool, &resolved, roleless).await;
    assert_eq!(outcome.map(|_| ()), Err(UpgradeRefusal::PermissionRevoked));
    assert_eq!(registry.pending_connection_count(), 0);

    let (outcome, _rx) = admit_admin_gated(&registry, &pool, &resolved, admin).await;
    assert!(outcome.is_ok(), "the admin actor is admitted");
}

/// A duplicated `acting` key reads its first occurrence, as Hono's
/// `c.req.query('acting')` does: the later one is never consulted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_duplicated_acting_reads_its_first_occurrence() {
    let pool = fresh_db_pool().await;
    let (account_id, _, second, cookie) = seed_two_actor_session(&pool, "ws_acting_dup").await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_gated(&pool, &registry, Vec::new()).await;
    let (status, body) = upgrade_refusal(
        addr,
        &format!("/ws?acting={}&acting={second}", Uuid::new_v4()),
        &cookie,
    )
    .await;
    assert_eq!(status, "HTTP/1.1 400 Bad Request");
    assert_eq!(body, serde_json::json!({"error": "actor_not_on_account"}));
    upgrade_admitted_at(
        &registry,
        addr,
        &format!("/ws?acting={second}&acting={}", Uuid::new_v4()),
        &cookie,
        account_id,
    )
    .await;
}

/// The scope gate runs ahead of the acting-actor phase: a narrowed token on a
/// multi-actor account omitting `acting` is told about its scope, not asked
/// to pick an actor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn the_scope_gate_answers_before_the_acting_actor_phase() {
    let pool = fresh_db_pool().await;
    let (account_id, _, _, _) = seed_two_actor_session(&pool, "ws_acting_scope_order").await;
    let narrowed = TokenScopeDocument::methods(std::collections::BTreeSet::from([
        "account_status".to_owned(),
    ]));
    let minted = mint_api_token(&pool, account_id, &narrowed).await;
    let registry = Arc::new(ConnectionRegistry::new());
    let addr = serve_gated(&pool, &registry, Vec::new()).await;
    let mut stream = send_upgrade_to(
        addr,
        "/ws",
        &format!("Authorization: Bearer {}", minted.token),
    )
    .await;
    assert_eq!(
        read_status_line(&mut stream).await,
        "HTTP/1.1 403 Forbidden"
    );
    assert_eq!(registry.connection_count(), 0);
}
