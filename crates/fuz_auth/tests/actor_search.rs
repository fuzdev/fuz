//! `actor_search` admission-gate integration tests.
//!
//! The unbounded-search branch (`scope_ids` absent or empty) is admin-only,
//! and its admin check is account-grain: the account-grain posture never
//! resolves an actor, so the gate reads the grant off the *account* rather
//! than off a resolved actor the way an actor-grain spec would. That makes it
//! the one place a tombstoned actor's surviving `role_grant` could admit —
//! soft-delete is reversible and deliberately does not revoke grants — so the
//! handler reads the tombstone-aware `query_account_has_active_global_role`.
//!
//! There is no wire-level probe for this: the isolating state is a live
//! credential whose granting actor is tombstoned, and the account-grain
//! search has no `acting` slot to name an actor with. The gate is therefore
//! pinned here, against the DB, with the live-actor case as the control —
//! swap the query back to the tombstone-blind sibling and the tombstoned case
//! answers a result set where it expects `-32602`.

// `allow-*-in-tests` doesn't cover the non-`#[test]` helper fns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use fuz_auth::actor_queries::query_actor_soft_delete;
use fuz_auth::{
    AccountActionContext, AccountRow, ActorSearchActionSpecs, AuditEmitter, ConnectionCloser,
    ERROR_ACTOR_SEARCH_SCOPE_REQUIRED, NoopAuditPostCommit, ROLE_ADMIN, RequestContext,
};
use fuz_http::JsonrpcErrorCode;
use serde_json::{Value, json};

/// Build the account-grain context `actor_search` dispatches under.
fn account_ctx<'a>(
    auth: &'a RequestContext,
    audit: &'a Arc<AuditEmitter>,
    closer: &'a Arc<dyn ConnectionCloser>,
) -> AccountActionContext<'a> {
    AccountActionContext {
        auth,
        credential_type: None,
        session_hash: None,
        audit,
        post_commit: &NoopAuditPostCommit,
        connection_closer: closer,
        notification_sender: common::noop_notification_sender(),
        client_ip: Some("127.0.0.1".to_owned()),
    }
}

/// Seed an account with one actor holding a global `admin` grant, and return
/// the caller's context alongside that actor's id.
async fn seed_admin_account(pool: &fuz_db::Pool, username: &str) -> (RequestContext, uuid::Uuid) {
    let (account_id, actor_id) = common::seed_account_actor(pool, username).await;
    common::seed_role_grant_direct(pool, actor_id, ROLE_ADMIN, None).await;
    (
        RequestContext {
            account: AccountRow {
                id: account_id,
                username: username.to_owned(),
            },
        },
        actor_id,
    )
}

async fn search(
    pool: &fuz_db::Pool,
    auth: &RequestContext,
    params: &Value,
) -> Result<Value, fuz_http::JsonrpcError> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = account_ctx(auth, &audit, &closer);
    let client = pool.get().await.expect("pool.get");
    ActorSearchActionSpecs::dispatch("actor_search", params, &ctx, &client).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn unbounded_search_admits_an_admin_and_refuses_a_tombstoned_one() {
    let pool = common::fresh_db_pool().await;
    let (auth, actor_id) = seed_admin_account(&pool, "search_admin").await;
    common::seed_account_actor(&pool, "search_target").await;
    let params = json!({"query": "search"});

    // Control: the grant is live, so the unbounded arm runs and finds rows.
    let admitted = search(&pool, &auth, &params).await.expect("admin admitted");
    let actors = admitted["actors"].as_array().expect("actors array");
    assert!(
        !actors.is_empty(),
        "the live-actor control must reach the search: {admitted}"
    );

    // Tombstone the granting actor. The `role_grant` row survives — that is
    // what makes the blind query fail open here.
    let client = pool.get().await.expect("pool.get");
    assert!(
        query_actor_soft_delete(&client, &actor_id, None)
            .await
            .expect("soft delete"),
        "an active actor row must have flipped"
    );
    drop(client);

    let refused = search(&pool, &auth, &params)
        .await
        .expect_err("a tombstoned grant must not admit the unbounded arm");
    assert_eq!(refused.code, JsonrpcErrorCode::InvalidParams);
    assert_eq!(
        refused.data.expect("data carries the reason")["reason"],
        ERROR_ACTOR_SEARCH_SCOPE_REQUIRED
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scoped_search_needs_no_admin_grant_at_all() {
    // The other side of the gate: `scope_ids` present means the admin check
    // never runs, so the tombstone has nothing to do with it. Without this the
    // case above could pass on a backend that refused every search.
    let pool = common::fresh_db_pool().await;
    let (auth, actor_id) = seed_admin_account(&pool, "scoped_searcher").await;
    let client = pool.get().await.expect("pool.get");
    query_actor_soft_delete(&client, &actor_id, None)
        .await
        .expect("soft delete");
    drop(client);

    let scoped = json!({"query": "scoped", "scope_ids": [uuid::Uuid::new_v4()]});
    let result = search(&pool, &auth, &scoped)
        .await
        .expect("a scoped search skips the admin gate");
    assert!(
        result["actors"]
            .as_array()
            .expect("actors array")
            .is_empty(),
        "an unknown scope matches no actors: {result}"
    );
}

/// Neither resolver returns a tombstone: `query_actor_search` (admin-global
/// and scoped paths) and `query_actors_by_ids` drop a soft-deleted actor and
/// every actor of a soft-deleted account, beside a live control.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn search_and_lookup_exclude_soft_deleted_actors_and_accounts() {
    let pool = common::fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let scope = uuid::Uuid::new_v4();
    let mut actors = Vec::new();
    for username in ["tomb_live", "tomb_actor_gone", "tomb_account_gone"] {
        let (account_id, actor_id) = common::seed_account_actor(&pool, username).await;
        client
            .execute(
                "INSERT INTO role_grant (actor_id, role, scope_kind, scope_id)
                 VALUES ($1, 'classroom_student', 'classroom', $2)",
                &[&actor_id, &scope],
            )
            .await
            .expect("scoped grant");
        actors.push((account_id, actor_id));
    }
    let [(_, live), (_, actor_gone), (account_gone, of_gone_account)] = actors[..] else {
        unreachable!()
    };
    assert!(
        query_actor_soft_delete(&client, &actor_gone, None)
            .await
            .expect("actor soft delete")
    );
    assert!(
        fuz_auth::account_queries::query_account_soft_delete(&client, &account_gone, None)
            .await
            .expect("account soft delete")
            .is_some()
    );

    for scope_ids in [vec![], vec![scope]] {
        let rows =
            fuz_auth::actor_search_queries::query_actor_search(&client, "tomb_", &scope_ids, 10)
                .await
                .expect("search");
        let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![live], "scope_ids {scope_ids:?}");
    }
    let rows =
        fuz_auth::actor_queries::query_actors_by_ids(&client, &[live, actor_gone, of_gone_account])
            .await
            .expect("lookup");
    let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![live]);
}
