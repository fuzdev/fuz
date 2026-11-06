//! Integration tests for the `role_grant` writes and reads in
//! `actor_queries` against a real `PostgreSQL`: the idempotent grant over an
//! expired row and the global-only keeper resolution. Twin of `fuz_app`'s
//! `auth/role_grant_queries.db.test.ts`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test role_grant_queries -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required because every test drops + recreates
//! the shared schema; parallel runs race on the `schema_version` table.

// Integration-test helpers assert via `expect`/`unwrap`; `allow-*-in-tests`
// doesn't cover the non-`#[test]` helper fns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, SystemTime};

use fuz_auth::actor_queries::{query_create_role_grant, query_keeper_account_id};
use fuz_auth::role::{ROLE_ADMIN, ROLE_KEEPER};

mod common;
use common::{fresh_db_pool, seed_account_actor};

/// The revoke columns of one `role_grant` row: `(revoked, revoked_by, revoked_reason)`.
async fn revoke_state(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    id: uuid::Uuid,
) -> (bool, Option<uuid::Uuid>, Option<String>) {
    let row = client
        .query_one(
            "SELECT revoked_at IS NOT NULL, revoked_by, revoked_reason FROM role_grant WHERE id = $1",
            &[&id],
        )
        .await
        .expect("read role_grant revoke state");
    (row.get(0), row.get(1), row.get(2))
}

/// An expired-but-unrevoked grant still holds the partial unique slot; a
/// re-grant revokes it and inserts a fresh active row instead of handing the
/// dead row back as the "existing" grant.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn grant_over_expired_row_revokes_it_and_inserts_fresh() {
    let pool = fresh_db_pool().await;
    let (_, actor_id) = seed_account_actor(&pool, "expired_regrant").await;
    let client = pool.get().await.expect("pool.get");
    let past = SystemTime::now() - Duration::from_secs(60);
    let expired =
        query_create_role_grant(&client, &actor_id, ROLE_ADMIN, None, None, None, Some(past))
            .await
            .expect("seed expired grant");
    let fresh = query_create_role_grant(&client, &actor_id, ROLE_ADMIN, None, None, None, None)
        .await
        .expect("re-grant");
    assert_ne!(
        fresh.id, expired.id,
        "re-grant over an expired row mints a fresh grant"
    );
    assert_eq!(revoke_state(&client, fresh.id).await, (false, None, None));
    assert_eq!(
        revoke_state(&client, expired.id).await,
        (true, None, Some("expired".to_owned())),
        "the expired row is revoked as 'expired' with no revoking actor",
    );
}

/// An unexpired grant with an expiry is still the active grant: the re-grant
/// returns the same row.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn grant_over_unexpired_row_returns_same_row() {
    let pool = fresh_db_pool().await;
    let (_, actor_id) = seed_account_actor(&pool, "unexpired_regrant").await;
    let client = pool.get().await.expect("pool.get");
    let future = SystemTime::now() + Duration::from_secs(3600);
    let first = query_create_role_grant(
        &client,
        &actor_id,
        ROLE_ADMIN,
        None,
        None,
        None,
        Some(future),
    )
    .await
    .expect("seed unexpired grant");
    let second = query_create_role_grant(&client, &actor_id, ROLE_ADMIN, None, None, None, None)
        .await
        .expect("re-grant");
    assert_eq!(second.id, first.id, "idempotent over the active grant");
    assert_eq!(revoke_state(&client, first.id).await, (false, None, None));
}

/// Grant `teacher` globally (`scope_id: None`) or at a `class` scope.
async fn grant_teacher(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: uuid::Uuid,
    scope_id: Option<&uuid::Uuid>,
    expires_at: Option<SystemTime>,
) -> fuz_auth::RoleGrantRow {
    let scope_kind = scope_id.map(|_| "class");
    query_create_role_grant(
        client, &actor_id, "teacher", scope_kind, scope_id, None, expires_at,
    )
    .await
    .expect("grant teacher")
}

/// The expired-row revoke is scoped to the exact `(actor, role, scope)` slot.
/// Every seeded row is expired, so only the scope clauses can spare a
/// neighbor: a scoped re-grant leaves the global grant and another scope
/// alone, and a global re-grant leaves the scoped rows alone.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn expired_row_revoke_touches_only_its_own_slot() {
    let pool = fresh_db_pool().await;
    let (_, actor_id) = seed_account_actor(&pool, "expired_scoped_regrant").await;
    let client = pool.get().await.expect("pool.get");
    let scope_a = uuid::Uuid::new_v4();
    let scope_b = uuid::Uuid::new_v4();
    let past = SystemTime::now() - Duration::from_secs(60);
    let global = grant_teacher(&client, actor_id, None, Some(past)).await;
    let expired_a = grant_teacher(&client, actor_id, Some(&scope_a), Some(past)).await;
    let expired_b = grant_teacher(&client, actor_id, Some(&scope_b), Some(past)).await;

    let fresh_a = grant_teacher(&client, actor_id, Some(&scope_a), None).await;
    assert_ne!(fresh_a.id, expired_a.id);
    assert!(revoke_state(&client, expired_a.id).await.0);
    assert!(
        !revoke_state(&client, global.id).await.0,
        "a scoped re-grant spares the global grant",
    );
    assert!(
        !revoke_state(&client, expired_b.id).await.0,
        "a scoped re-grant spares another scope",
    );

    let fresh_global = grant_teacher(&client, actor_id, None, None).await;
    assert_ne!(fresh_global.id, global.id);
    assert!(revoke_state(&client, global.id).await.0);
    assert!(
        !revoke_state(&client, expired_b.id).await.0,
        "a global re-grant spares a scoped row",
    );
}

/// Keeper resolution reads the global grant only: a scoped keeper row (which no
/// grant verb writes, but direct SQL or a consumer can) must not resolve the
/// daemon-token identity.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn scoped_keeper_grant_does_not_resolve_keeper() {
    let pool = fresh_db_pool().await;
    let (_, scoped_actor) = seed_account_actor(&pool, "scoped_keeper").await;
    let client = pool.get().await.expect("pool.get");
    let scope_id = uuid::Uuid::new_v4();
    query_create_role_grant(
        &client,
        &scoped_actor,
        ROLE_KEEPER,
        Some("class"),
        Some(&scope_id),
        None,
        None,
    )
    .await
    .expect("seed scoped keeper grant");
    assert_eq!(
        query_keeper_account_id(&client)
            .await
            .expect("resolve keeper"),
        None,
        "a scoped keeper grant must not resolve the keeper account",
    );

    // Control: the global keeper resolves even with the scoped row present.
    let (keeper_account, keeper_actor) = seed_account_actor(&pool, "global_keeper").await;
    query_create_role_grant(&client, &keeper_actor, ROLE_KEEPER, None, None, None, None)
        .await
        .expect("seed global keeper grant");
    assert_eq!(
        query_keeper_account_id(&client)
            .await
            .expect("resolve keeper"),
        Some(keeper_account),
    );
}
