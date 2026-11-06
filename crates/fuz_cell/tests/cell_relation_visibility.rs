//! PG-backed integration tests for `filter_visible_targets` — the strict
//! relation-read visibility filter.
//!
//! The `cell_get` bundle and the deep-clone walk run every candidate target id
//! through this filter so an editor of a public parent can't enumerate private
//! children by id, and a public cell can't leak the existence of private
//! linked cells (the relation lists apply the same predicate in SQL — see
//! `cell_view_sql.rs`). The `cell_authz` *predicates* are
//! unit-tested in `cell_authz.rs`; this pins the *batched DB wiring* around them
//! — the bulk cell + grant loads, the auth-gated grant skip, and the
//! soft-deleted / absent → not-viewable collapse.
//!
//! `fuz_cell_actions`' verb-layer use of this filter (the `cell_get` bundle
//! drop, the clone silent-drop) stays exercised by `fuz_app`'s cross-backend
//! `cell.cross.test.ts` against `testing_spine_stub`; this is the primitive's
//! own crate-local coverage, which the survey flagged as missing.
//!
//! `--ignored`-gated (needs Postgres). Run single-threaded against the shared
//! `fuz_cell_test` DB:
//!
//! ```sh
//! cargo test -p fuz_cell -- --ignored --test-threads=1
//! ```

// Integration-test helpers assert via `expect`/`unwrap`; `allow-*-in-tests`
// doesn't cover the non-`#[test]` helper fns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::fresh_db_pool;
use fuz_auth::{AccountRow, ActorRow, ROLE_ADMIN, RequestActorContext, RoleGrantRow};
use fuz_cell::cell_grant_queries::query_cell_grant_create;
use fuz_cell::cell_grant_schema::{CellGrantLevel, CellGrantPrincipalInput};
use fuz_cell::cell_queries::{query_cell_create, query_cell_delete};
use fuz_cell::cell_relation_visibility::filter_visible_targets;
use fuz_cell::cell_schema::CellVisibility;
use fuz_db::Pool;
use fuz_testing::seed_account_actor;
use serde_json::json;
use uuid::Uuid;

/// Seed an `account` + `actor` and return a `RequestActorContext` for that
/// actor carrying `roles` as actor-scoped role grants. The context's
/// `actor.id` is the value cells stamp into `created_by` for ownership.
async fn seed_caller(pool: &Pool, username: &str, roles: &[&str]) -> RequestActorContext {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    RequestActorContext {
        account: AccountRow {
            id: account_id,
            username: username.to_owned(),
        },
        actor: ActorRow {
            id: actor_id,
            account_id,
            name: username.to_owned(),
        },
        role_grants: roles
            .iter()
            .map(|r| RoleGrantRow {
                id: Uuid::nil(),
                actor_id,
                role: (*r).to_owned(),
                scope_id: None,
            })
            .collect(),
    }
}

/// Seed a cell with the given visibility + owner; returns its id.
async fn seed_cell(pool: &Pool, visibility: CellVisibility, owner: Option<Uuid>) -> Uuid {
    let client = pool.get().await.unwrap();
    query_cell_create(
        &client,
        &json!({}),
        Some("note"),
        Some(visibility),
        None,
        None,
        None,
        None,
        None,
        owner,
    )
    .await
    .expect("create cell")
    .id
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn public_target_is_visible_to_anonymous() {
    // A public cell admits via the public branch alone — no auth, no grant load.
    let pool = fresh_db_pool().await;
    let cell = seed_cell(&pool, CellVisibility::Public, None).await;
    let client = pool.get().await.unwrap();
    let visible = filter_visible_targets(&client, None, &[cell])
        .await
        .unwrap();
    assert!(visible.contains(&cell));
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn private_target_is_hidden_from_a_non_owner() {
    // A private cell owned by someone else, with no grant to the caller, is not
    // viewable — the core enumeration guard.
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let stranger = seed_caller(&pool, "stranger", &[]).await;
    let cell = seed_cell(&pool, CellVisibility::Private, Some(owner.actor.id)).await;
    let client = pool.get().await.unwrap();
    let visible = filter_visible_targets(&client, Some(&stranger), &[cell])
        .await
        .unwrap();
    assert!(!visible.contains(&cell));
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn private_target_is_visible_to_its_owner() {
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let cell = seed_cell(&pool, CellVisibility::Private, Some(owner.actor.id)).await;
    let client = pool.get().await.unwrap();
    let visible = filter_visible_targets(&client, Some(&owner), &[cell])
        .await
        .unwrap();
    assert!(visible.contains(&cell));
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn private_target_is_visible_to_admin_without_a_grant() {
    // Admin short-circuits `can_view_cell` — visible with neither ownership nor
    // a grant.
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let admin = seed_caller(&pool, "admin", &[ROLE_ADMIN]).await;
    let cell = seed_cell(&pool, CellVisibility::Private, Some(owner.actor.id)).await;
    let client = pool.get().await.unwrap();
    let visible = filter_visible_targets(&client, Some(&admin), &[cell])
        .await
        .unwrap();
    assert!(visible.contains(&cell));
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn viewer_grant_admits_the_grantee() {
    // A `viewer` grant to the caller's actor admits a private target — exercises
    // the auth-gated grant load (skipped entirely for anonymous callers).
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let grantee = seed_caller(&pool, "grantee", &[]).await;
    let cell = seed_cell(&pool, CellVisibility::Private, Some(owner.actor.id)).await;
    {
        let client = pool.get().await.unwrap();
        query_cell_grant_create(
            &client,
            cell,
            CellGrantLevel::Viewer,
            &CellGrantPrincipalInput::Actor {
                actor_id: grantee.actor.id,
            },
            Some(owner.actor.id),
        )
        .await
        .expect("grant");
    }
    let client = pool.get().await.unwrap();
    let visible = filter_visible_targets(&client, Some(&grantee), &[cell])
        .await
        .unwrap();
    assert!(visible.contains(&cell));
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn soft_deleted_target_is_absent_even_for_the_owner() {
    // The bulk load only returns active cells, so a soft-deleted target is
    // not-viewable for anyone — including its owner.
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let cell = seed_cell(&pool, CellVisibility::Public, Some(owner.actor.id)).await;
    {
        let client = pool.get().await.unwrap();
        assert!(
            query_cell_delete(&client, cell, Some(owner.actor.id))
                .await
                .unwrap()
        );
    }
    let client = pool.get().await.unwrap();
    let visible = filter_visible_targets(&client, Some(&owner), &[cell])
        .await
        .unwrap();
    assert!(!visible.contains(&cell));
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn nonexistent_id_is_absent() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.unwrap();
    let visible = filter_visible_targets(&client, None, &[Uuid::new_v4()])
        .await
        .unwrap();
    assert!(visible.is_empty());
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn mixed_set_returns_only_the_viewable_subset_and_dedups() {
    // A mixed id-set (with a duplicate) returns exactly the viewable ids:
    // anonymous sees the public cell (once), not the private one.
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let public = seed_cell(&pool, CellVisibility::Public, None).await;
    let private = seed_cell(&pool, CellVisibility::Private, Some(owner.actor.id)).await;
    let client = pool.get().await.unwrap();
    // `public` listed twice to exercise the dedup before the bulk load.
    let visible = filter_visible_targets(&client, None, &[public, private, public])
        .await
        .unwrap();
    assert!(visible.contains(&public));
    assert!(!visible.contains(&private));
    assert_eq!(visible.len(), 1);
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn moderation_gates_the_public_and_grant_arms() {
    // A pending public target and a rejected granted one admit only their
    // owner — the filter runs `can_view_cell`, moderation admission included.
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let grantee = seed_caller(&pool, "grantee", &[]).await;
    let seed_moderated = async |visibility, moderation| {
        let client = pool.get().await.unwrap();
        query_cell_create(
            &client,
            &json!({}),
            Some("note"),
            Some(visibility),
            None,
            None,
            None,
            Some(moderation),
            None,
            Some(owner.actor.id),
        )
        .await
        .expect("create moderated cell")
        .id
    };
    let pending_public = seed_moderated(CellVisibility::Public, "pending").await;
    let rejected_granted = seed_moderated(CellVisibility::Private, "rejected").await;
    {
        let client = pool.get().await.unwrap();
        query_cell_grant_create(
            &client,
            rejected_granted,
            CellGrantLevel::Viewer,
            &CellGrantPrincipalInput::Actor {
                actor_id: grantee.actor.id,
            },
            Some(owner.actor.id),
        )
        .await
        .expect("grant");
    }
    let ids = [pending_public, rejected_granted];
    let client = pool.get().await.unwrap();
    let anon = filter_visible_targets(&client, None, &ids).await.unwrap();
    assert!(anon.is_empty(), "anon sees neither");
    let granted = filter_visible_targets(&client, Some(&grantee), &ids)
        .await
        .unwrap();
    assert!(
        granted.is_empty(),
        "the grant admits nothing while rejected"
    );
    let own = filter_visible_targets(&client, Some(&owner), &ids)
        .await
        .unwrap();
    assert_eq!(own.len(), 2, "the owner sees both");
}
