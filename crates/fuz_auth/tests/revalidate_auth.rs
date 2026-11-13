//! PG-backed tests for [`fuz_auth::revalidate_resolved_auth`] — the re-check a
//! long-lived connection runs on its credential once it is registered, so a
//! revocation racing its open cannot be missed.
//!
//! Each case resolves a real credential through
//! [`fuz_auth::AuthGate::resolve_credential`] (a [`ResolvedAuth`] has no other
//! origin), applies one revocation's database effect, and asserts the
//! re-check now refuses:
//!
//! - **session** — revoked, expired, wiped by a password change, or moved to
//!   another account;
//! - **API token** — revoked, expired, wiped by a password change;
//! - **every credential** — its account soft-deleted while the session /
//!   token row is still there, which is the one case only the account read
//!   can see;
//! - **daemon token** — nothing of its own to revoke (a rotation does not
//!   refuse it), but its keeper account is still re-read.
//!
//! And the two properties that keep the re-check from over-reaching: a
//! revocation of *another* session leaves this one valid (it re-checks the
//! credential, not the account's other credentials), and it has no side
//! effects — in particular it never touches `api_token.last_used_at`, which
//! the resolve walk's bearer leg does.
//!
//! Then [`fuz_auth::recheck_admission`], the admission step built on it: each
//! of its outcomes, in its order — the credential first, then the acting
//! actor, then the endpoint's roles (global grants only).
//!
//! `#[ignore]`-gated — run:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test revalidate_auth -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::time::Duration;

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use fuz_auth::account_queries::query_account_soft_delete;
use fuz_auth::actor_queries::query_actor_soft_delete;
use fuz_auth::api_token_queries::{
    query_revoke_all_api_tokens_for_account, query_revoke_api_token_for_account,
};
use fuz_auth::daemon_token::DAEMON_TOKEN_HEADER;
use fuz_auth::session_queries::{
    query_session_revoke_all_for_account, query_session_revoke_for_account,
};
use fuz_auth::token_scope::TokenScopeDocument;
use fuz_auth::{
    AdmissionRecheck, AuthGate, CredentialType, ResolvedAuth, SESSION_COOKIE_NAME,
    SharedDaemonTokenState, recheck_admission, revalidate_resolved_auth,
};
use fuz_db::Pool;
use fuz_testing::{
    TESTING_DAEMON_TOKEN, daemon_token_state, mint_api_token, mint_session_cookie, testing_keyring,
};
use uuid::Uuid;

/// Resolve `headers` the way a handler does. Panics if they don't
/// authenticate — every case starts from a credential that does.
async fn resolve(
    pool: &Pool,
    headers: &HeaderMap,
    daemon: Option<&SharedDaemonTokenState>,
) -> ResolvedAuth {
    AuthGate {
        daemon_token_state: daemon.cloned(),
        ..fuz_testing::testing_auth_gate(pool.clone())
    }
    .preflight(headers, fuz_http::UNRESOLVED_CLIENT_IP)
    .await
    .expect("the fixture sends no foreign origin")
    .expect("the fixture credential authenticates")
}

/// Mint a session for `account_id` and resolve it.
async fn resolve_session(pool: &Pool, account_id: Uuid) -> ResolvedAuth {
    let cookie =
        mint_session_cookie(pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, cookie.parse().unwrap());
    let resolved = resolve(pool, &headers, None).await;
    assert_eq!(resolved.credential_type(), CredentialType::Session);
    resolved
}

/// Mint a full-scope API token for `account_id`, resolve it, and wait for the
/// `last_used_at` touch the resolve spawned to land — so no touch is still in
/// flight when a case looks at the row.
async fn resolve_api_token(pool: &Pool, account_id: Uuid) -> ResolvedAuth {
    let minted = mint_api_token(pool, account_id, &TokenScopeDocument::full()).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", minted.token).parse().unwrap(),
    );
    let resolved = resolve(pool, &headers, None).await;
    assert_eq!(resolved.credential_type(), CredentialType::ApiToken);
    assert_eq!(resolved.api_token_id(), Some(minted.id.as_str()));
    let touched = async {
        while !token_was_touched(pool, &minted.id).await {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), touched)
        .await
        .expect("the resolve walk's token touch lands");
    resolved
}

/// Whether `api_token.last_used_at` is set on `token_id`.
async fn token_was_touched(pool: &Pool, token_id: &str) -> bool {
    pool.get()
        .await
        .unwrap()
        .query_one(
            "SELECT last_used_at IS NOT NULL FROM api_token WHERE id = $1",
            &[&token_id],
        )
        .await
        .unwrap()
        .get(0)
}

/// Run the re-check on a fresh autocommit client.
async fn is_live(pool: &Pool, resolved: &ResolvedAuth) -> bool {
    let client = pool.get().await.unwrap();
    revalidate_resolved_auth(&client, resolved)
        .await
        .expect("the re-check query runs")
}

/// Run one statement on a pooled client.
async fn execute(pool: &Pool, sql: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) {
    pool.get()
        .await
        .unwrap()
        .execute(sql, params)
        .await
        .unwrap();
}

fn session_hash(resolved: &ResolvedAuth) -> &str {
    resolved.session_hash().expect("a session carries its hash")
}

fn token_id(resolved: &ResolvedAuth) -> &str {
    resolved
        .api_token_id()
        .expect("a bearer carries its token id")
}

// -- session -------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_live_session_revalidates() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "session_live").await;
    let resolved = resolve_session(&pool, account_id).await;
    assert!(is_live(&pool, &resolved).await);
    assert!(is_live(&pool, &resolved).await, "and keeps revalidating");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_revoked_session_does_not_revalidate() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "session_revoked").await;
    let resolved = resolve_session(&pool, account_id).await;

    let client = pool.get().await.unwrap();
    assert!(
        query_session_revoke_for_account(&client, session_hash(&resolved), &account_id)
            .await
            .unwrap()
    );
    drop(client);

    assert!(!is_live(&pool, &resolved).await);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_expired_session_does_not_revalidate() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "session_expired").await;
    let resolved = resolve_session(&pool, account_id).await;

    execute(
        &pool,
        "UPDATE auth_session SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        &[&session_hash(&resolved)],
    )
    .await;

    assert!(!is_live(&pool, &resolved).await);
}

/// The row a session hash names must still belong to the resolved account —
/// the re-check reads the owner, not just the row's existence.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_session_now_owned_by_another_account_does_not_revalidate() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "session_owner").await;
    let (other_id, _) = common::seed_account_actor(&pool, "session_other").await;
    let resolved = resolve_session(&pool, account_id).await;

    execute(
        &pool,
        "UPDATE auth_session SET account_id = $2 WHERE id = $1",
        &[&session_hash(&resolved), &other_id],
    )
    .await;

    assert!(!is_live(&pool, &resolved).await);
}

/// **The control.** Revoking another session of the same account — what a
/// logout elsewhere deletes — leaves this credential valid.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn revoking_another_session_leaves_this_one_valid() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "session_sibling").await;
    let resolved = resolve_session(&pool, account_id).await;
    let other = resolve_session(&pool, account_id).await;

    let client = pool.get().await.unwrap();
    assert!(
        query_session_revoke_for_account(&client, session_hash(&other), &account_id)
            .await
            .unwrap()
    );
    drop(client);

    assert!(is_live(&pool, &resolved).await, "this session is untouched");
    assert!(!is_live(&pool, &other).await, "the revoked one is not");
}

// -- API token -----------------------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_live_api_token_revalidates() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "token_live").await;
    let resolved = resolve_api_token(&pool, account_id).await;
    assert!(is_live(&pool, &resolved).await);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_revoked_api_token_does_not_revalidate() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "token_revoked").await;
    let resolved = resolve_api_token(&pool, account_id).await;
    let sibling = resolve_api_token(&pool, account_id).await;

    let client = pool.get().await.unwrap();
    assert!(
        query_revoke_api_token_for_account(&client, token_id(&resolved), &account_id)
            .await
            .unwrap()
    );
    drop(client);

    assert!(!is_live(&pool, &resolved).await);
    assert!(
        is_live(&pool, &sibling).await,
        "the account's other token stays"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_expired_api_token_does_not_revalidate() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "token_expired").await;
    let resolved = resolve_api_token(&pool, account_id).await;

    execute(
        &pool,
        "UPDATE api_token SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        &[&token_id(&resolved)],
    )
    .await;

    assert!(!is_live(&pool, &resolved).await);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_api_token_now_owned_by_another_account_does_not_revalidate() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "token_owner").await;
    let (other_id, _) = common::seed_account_actor(&pool, "token_other").await;
    let resolved = resolve_api_token(&pool, account_id).await;

    execute(
        &pool,
        "UPDATE api_token SET account_id = $2 WHERE id = $1",
        &[&token_id(&resolved), &other_id],
    )
    .await;

    assert!(!is_live(&pool, &resolved).await);
}

// -- revocations that span credentials -----------------------------------------

/// A password change deletes every session and every API token of the
/// account — neither credential type survives the re-check.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_password_change_invalidates_sessions_and_tokens() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "password_changed").await;
    let session = resolve_session(&pool, account_id).await;
    let token = resolve_api_token(&pool, account_id).await;

    let client = pool.get().await.unwrap();
    query_session_revoke_all_for_account(&client, &account_id)
        .await
        .unwrap();
    query_revoke_all_api_tokens_for_account(&client, &account_id)
        .await
        .unwrap();
    drop(client);

    assert!(!is_live(&pool, &session).await);
    assert!(!is_live(&pool, &token).await);
}

/// A soft-deleted account refuses every credential — with the session and
/// token rows left in place, so only the account read can be what refuses.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_soft_deleted_account_invalidates_every_credential() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "account_deleted").await;
    let session = resolve_session(&pool, account_id).await;
    let token = resolve_api_token(&pool, account_id).await;
    let daemon_state = daemon_token_state(TESTING_DAEMON_TOKEN, Some(account_id));
    let daemon = resolve_daemon_token(&pool, &daemon_state).await;

    let client = pool.get().await.unwrap();
    assert!(
        query_account_soft_delete(&client, &account_id, None)
            .await
            .unwrap()
            .is_some()
    );
    drop(client);

    assert!(!is_live(&pool, &session).await, "session");
    assert!(!is_live(&pool, &token).await, "api token");
    assert!(!is_live(&pool, &daemon).await, "daemon token");
}

// -- daemon token --------------------------------------------------------------

/// Resolve the fixture daemon token against `state`.
async fn resolve_daemon_token(pool: &Pool, state: &SharedDaemonTokenState) -> ResolvedAuth {
    let mut headers = HeaderMap::new();
    headers.insert(DAEMON_TOKEN_HEADER, TESTING_DAEMON_TOKEN.parse().unwrap());
    let resolved = resolve(pool, &headers, Some(state)).await;
    assert_eq!(resolved.credential_type(), CredentialType::DaemonToken);
    resolved
}

/// A daemon token has no row and no revocation event: a rotation that drops
/// the token it authenticated with closes no connection, and the re-check
/// does not refuse it either. (Its keeper account is still re-read — the
/// soft-delete case above.)
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_daemon_token_revalidates_across_a_rotation() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "keeper").await;
    let state = daemon_token_state(TESTING_DAEMON_TOKEN, Some(account_id));
    let resolved = resolve_daemon_token(&pool, &state).await;
    assert!(is_live(&pool, &resolved).await);

    // two rotations: the token the connection authenticated with is neither
    // current nor previous
    {
        let mut guard = state.write();
        guard.previous_token = Some("rotated-once".to_owned());
        guard.current_token = "rotated-twice".to_owned();
    }
    assert!(is_live(&pool, &resolved).await);
}

// -- no side effects -----------------------------------------------------------

/// The re-check is not a use: it never touches `api_token.last_used_at`. The
/// resolve walk's own touch has landed by the time `resolve_api_token`
/// returns, so the column is cleared here and must stay cleared.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn the_recheck_does_not_touch_the_api_token() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "token_untouched").await;
    let resolved = resolve_api_token(&pool, account_id).await;
    execute(
        &pool,
        "UPDATE api_token SET last_used_at = NULL, last_used_ip = NULL WHERE id = $1",
        &[&token_id(&resolved)],
    )
    .await;

    for _ in 0..3 {
        assert!(is_live(&pool, &resolved).await);
    }
    // long enough for a spawned touch — the form the resolve walk uses — to
    // have landed
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !token_was_touched(&pool, token_id(&resolved)).await,
        "the re-check must not record a use"
    );
}

/// The re-check writes nothing to the session either: the row is byte-for-byte
/// what it was.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn the_recheck_leaves_the_session_row_unchanged() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "session_untouched").await;
    let resolved = resolve_session(&pool, account_id).await;
    let row = || async {
        pool.get()
            .await
            .unwrap()
            .query_one(
                "SELECT auth_session::text FROM auth_session WHERE id = $1",
                &[&session_hash(&resolved)],
            )
            .await
            .unwrap()
            .get::<_, String>(0)
    };

    let before = row().await;
    for _ in 0..3 {
        assert!(is_live(&pool, &resolved).await);
    }
    assert_eq!(row().await, before);
}

// -- recheck_admission ----------------------------------------------------------

/// Run the admission re-check on a fresh autocommit client.
async fn recheck(
    pool: &Pool,
    resolved: &ResolvedAuth,
    actor_id: &Uuid,
    required_roles: &[&str],
) -> AdmissionRecheck {
    let client = pool.get().await.unwrap();
    recheck_admission(&client, resolved, actor_id, required_roles)
        .await
        .expect("the re-check queries run")
}

/// A live credential, an active actor, and a held global grant admit; an
/// ungated re-check reads no role.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_live_connection_is_admitted() {
    let pool = common::fresh_db_pool().await;
    let (account_id, actor_id) = common::seed_account_actor(&pool, "recheck_live").await;
    common::seed_role_grant_direct(&pool, actor_id, "admin", None).await;
    let resolved = resolve_session(&pool, account_id).await;
    assert_eq!(
        recheck(&pool, &resolved, &actor_id, &["admin"]).await,
        AdmissionRecheck::Admitted
    );
    assert_eq!(
        recheck(&pool, &resolved, &actor_id, &[]).await,
        AdmissionRecheck::Admitted
    );
}

/// A revoked credential refuses first — ahead of an actor and a role that
/// would refuse too.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_revoked_credential_refuses_first() {
    let pool = common::fresh_db_pool().await;
    let (account_id, actor_id) = common::seed_account_actor(&pool, "recheck_revoked").await;
    let resolved = resolve_session(&pool, account_id).await;
    let client = pool.get().await.unwrap();
    assert!(
        query_session_revoke_for_account(&client, session_hash(&resolved), &account_id)
            .await
            .unwrap()
    );
    assert!(
        query_actor_soft_delete(&client, &actor_id, None)
            .await
            .unwrap()
    );
    drop(client);
    assert_eq!(
        recheck(&pool, &resolved, &actor_id, &["admin"]).await,
        AdmissionRecheck::CredentialRevoked
    );
}

/// An acting actor soft-deleted under its live account refuses — on an
/// ungated re-check too, and ahead of the role it also lost. A sibling actor
/// staying active does not admit it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_tombstoned_actor_refuses() {
    let pool = common::fresh_db_pool().await;
    let (account_id, actor_id) = common::seed_account_actor(&pool, "recheck_tombstoned").await;
    common::seed_extra_actor(&pool, account_id, "recheck_sibling").await;
    common::seed_role_grant_direct(&pool, actor_id, "admin", None).await;
    let resolved = resolve_session(&pool, account_id).await;
    let client = pool.get().await.unwrap();
    assert!(
        query_actor_soft_delete(&client, &actor_id, None)
            .await
            .unwrap()
    );
    drop(client);
    assert!(
        is_live(&pool, &resolved).await,
        "the credential still holds"
    );
    assert_eq!(
        recheck(&pool, &resolved, &actor_id, &[]).await,
        AdmissionRecheck::ActorInactive
    );
    assert_eq!(
        recheck(&pool, &resolved, &actor_id, &["admin"]).await,
        AdmissionRecheck::ActorInactive
    );
}

/// A required role the actor no longer holds globally refuses — a scoped
/// grant of it does not admit, and any listed role does.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_lost_role_refuses() {
    let pool = common::fresh_db_pool().await;
    let (account_id, actor_id) = common::seed_account_actor(&pool, "recheck_role").await;
    let resolved = resolve_session(&pool, account_id).await;
    assert_eq!(
        recheck(&pool, &resolved, &actor_id, &["admin"]).await,
        AdmissionRecheck::RoleRevoked
    );
    execute(
        &pool,
        "INSERT INTO role_grant (actor_id, role, scope_kind, scope_id) \
         VALUES ($1, 'admin', 'cell', gen_random_uuid())",
        &[&actor_id],
    )
    .await;
    assert_eq!(
        recheck(&pool, &resolved, &actor_id, &["admin"]).await,
        AdmissionRecheck::RoleRevoked,
        "a scoped grant never admits at a role gate"
    );
    common::seed_role_grant_direct(&pool, actor_id, "keeper", None).await;
    assert_eq!(
        recheck(&pool, &resolved, &actor_id, &["admin", "keeper"]).await,
        AdmissionRecheck::Admitted,
        "any-of"
    );
}
