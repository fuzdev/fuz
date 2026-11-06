//! Integration tests for the `account_delete` (soft, self-or-admin) /
//! `account_purge` (hard, keeper) RPC actions against a real
//! `PostgreSQL`. Pins the delete = soft, purge = hard contract: soft-delete
//! tombstones + audits + blocks auth resolution; purge removes the rows
//! but the audit ids survive (no FK) with identity snapshotted in metadata.
//! A self-delete is session-only (handler-enforced, ahead of the keeper /
//! last-admin guards); an admin deleting another account keeps any credential.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test account_delete -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required because every test drops + recreates
//! the shared schema; parallel runs race on the `schema_version` table.

// Integration-test helpers assert via `expect`/`unwrap`; `allow-*-in-tests`
// doesn't cover the non-`#[test]` helper fns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use fuz_auth::account_queries::query_account_by_id;
use fuz_auth::actor_queries::{
    ResolveActingActorResult, query_account_has_active_global_role, query_account_has_global_role,
    query_active_actors_by_account, query_actor_soft_delete, query_actors_by_account,
    query_count_active_accounts_with_global_role_for_update, query_keeper_account_id,
    resolve_acting_actor,
};
use fuz_auth::admin_action_specs::{
    ERROR_CANNOT_DELETE_KEEPER, ERROR_CANNOT_DELETE_LAST_ADMIN, ERROR_PURGE_NOT_CONFIRMED,
};
use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::{ROLE_ADMIN, ROLE_KEEPER};
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{CredentialGate, CredentialType, credential_type_required};
use fuz_http::JsonrpcErrorCode;
use serde_json::{Value, json};

mod common;
use common::{
    build_audit, closer, ctx, fresh_db_pool, seed_account_actor, seed_admin, seed_extra_actor,
    seed_role_grant_direct,
};

/// Give a seeded context an active admin role grant — `account_delete`
/// elevates to admin in-handler for cross-account deletes, so the context
/// must actually hold the role (tests bypass the action-auth gates, so the
/// dispatcher's gate isn't what's exercised here).
fn with_admin(mut auth: RequestActorContext) -> RequestActorContext {
    auth.role_grants.push(RoleGrantRow {
        id: uuid::Uuid::new_v4(),
        actor_id: auth.actor.id,
        role: ROLE_ADMIN.to_owned(),
        scope_id: None,
    });
    auth
}

/// Count audit rows of a given `event_type` whose `target_account_id`
/// matches (raw id — survives a purge since the column carries no FK).
async fn audit_rows_for_target(
    pool: &fuz_db::Pool,
    event_type: &str,
    target_account_id: uuid::Uuid,
) -> Vec<Value> {
    let client = pool.get().await.expect("pool.get");
    let rows = client
        .query(
            "SELECT metadata::text FROM audit_log
             WHERE event_type = $1 AND target_account_id = $2",
            &[&event_type, &target_account_id],
        )
        .await
        .expect("query audit_log");
    rows.into_iter()
        .map(|r| {
            let text: Option<String> = r.get(0);
            text.map_or(Value::Null, |t| {
                serde_json::from_str(&t).unwrap_or(Value::Null)
            })
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_delete_soft_deletes_and_audits() {
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (account_id, actor_id) = seed_account_actor(&pool, "doomed").await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": account_id }),
        &ctx,
        &client,
    )
    .await
    .expect("account_delete");
    assert_eq!(out["ok"], Value::Bool(true));
    assert_eq!(out["deleted"], Value::Bool(true));

    // Account is tombstoned: auth-resolution lookup no longer finds it.
    let resolved = query_account_by_id(&client, &account_id)
        .await
        .expect("query_account_by_id");
    assert!(resolved.is_none(), "soft-deleted account must not resolve");

    // The row + actor survive with deleted_at stamped.
    let acct = client
        .query_one(
            "SELECT deleted_at IS NOT NULL FROM account WHERE id = $1",
            &[&account_id],
        )
        .await
        .expect("account row survives");
    assert!(acct.get::<_, bool>(0), "account.deleted_at stamped");
    let actor = client
        .query_one(
            "SELECT deleted_at IS NOT NULL FROM actor WHERE id = $1",
            &[&actor_id],
        )
        .await
        .expect("actor row survives");
    assert!(actor.get::<_, bool>(0), "actor.deleted_at stamped");

    // account_delete audit row snapshots username; actor_delete snapshots name.
    let account_events = audit_rows_for_target(&pool, "account_delete", account_id).await;
    assert_eq!(account_events.len(), 1, "one account_delete row");
    assert_eq!(
        account_events[0]["username"],
        Value::String("doomed".into())
    );
    let actor_events = audit_rows_for_target(&pool, "actor_delete", account_id).await;
    assert_eq!(actor_events.len(), 1, "one actor_delete row");
    assert_eq!(actor_events[0]["name"], Value::String("doomed".into()));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_undelete_reactivates_and_audits() {
    // Admin soft-deletes then reactivates — the tombstone clears, auth
    // resolution finds the account again, and undelete events are emitted.
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (account_id, _actor_id) = seed_account_actor(&pool, "reborn").await;

    let client = pool.get().await.expect("pool.get");
    common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": account_id }),
        &ctx,
        &client,
    )
    .await
    .expect("account_delete");
    assert!(
        query_account_by_id(&client, &account_id)
            .await
            .expect("query")
            .is_none(),
        "soft-deleted account excluded from auth lookup"
    );

    let out = common::admin_dispatch(
        "account_undelete",
        &json!({ "account_id": account_id }),
        &ctx,
        &client,
    )
    .await
    .expect("account_undelete");
    assert_eq!(out["ok"], Value::Bool(true));
    assert_eq!(out["undeleted"], Value::Bool(true));

    // Tombstone cleared on account + actor; auth resolution finds it again.
    let resolved = query_account_by_id(&client, &account_id)
        .await
        .expect("query_account_by_id");
    assert!(resolved.is_some(), "reactivated account resolves again");

    let account_events = audit_rows_for_target(&pool, "account_undelete", account_id).await;
    assert_eq!(account_events.len(), 1, "one account_undelete row");
    assert_eq!(
        account_events[0]["username"],
        Value::String("reborn".into())
    );
    let actor_events = audit_rows_for_target(&pool, "actor_undelete", account_id).await;
    assert_eq!(actor_events.len(), 1, "one actor_undelete row");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_undelete_missing_or_active_404() {
    // Undeleting an account that isn't soft-deleted is a not-found no-op.
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (account_id, _) = seed_account_actor(&pool, "still_active").await;

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "account_undelete",
        &json!({ "account_id": account_id }),
        &ctx,
        &client,
    )
    .await
    .expect_err("undelete of a non-deleted account must 404");
    assert_eq!(err.code, JsonrpcErrorCode::NotFound);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_delete_self_without_account_id() {
    // Self-delete: omit `account_id` → the caller's own account is
    // tombstoned (no admin role needed) — over a session, `ctx`'s default.
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let self_account_id = auth.account.id;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("account_delete", &json!({}), &ctx, &client)
        .await
        .expect("self account_delete");
    assert_eq!(out["deleted"], Value::Bool(true));
    let resolved = query_account_by_id(&client, &self_account_id)
        .await
        .expect("query_account_by_id");
    assert!(resolved.is_none(), "self-deleted account must not resolve");
}

/// A self-delete over a token — API or daemon, with `account_id` omitted or
/// naming the caller in either case — is refused with the dispatcher's own
/// `credential_type_required` body, and the account survives.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_delete_self_refuses_a_token() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let self_account_id = auth.account.id;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let client = pool.get().await.expect("pool.get");

    let refusal = credential_type_required(CredentialGate::SESSION_ONLY);
    for credential_type in [CredentialType::ApiToken, CredentialType::DaemonToken] {
        let mut ctx = ctx(&auth, &audit, &closer);
        ctx.credential_type = Some(credential_type);
        for params in [
            json!({}),
            json!({ "account_id": self_account_id }),
            json!({ "account_id": self_account_id.to_string().to_uppercase() }),
        ] {
            let err = common::admin_dispatch("account_delete", &params, &ctx, &client)
                .await
                .expect_err("a token must not self-delete");
            assert_eq!(
                serde_json::to_value(&err).unwrap(),
                serde_json::to_value(&refusal).unwrap(),
                "{credential_type:?} {params}"
            );
        }
    }
    let resolved = query_account_by_id(&client, &self_account_id)
        .await
        .expect("query_account_by_id");
    assert!(
        resolved.is_some(),
        "the account survives the refused deletes"
    );
}

/// The self path's credential check runs before the keeper guard: a keeper
/// self-deleting over a token learns `credential_type_required`, not
/// `cannot_delete_keeper`.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_delete_self_credential_check_precedes_the_keeper_guard() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    seed_role_grant_direct(&pool, auth.actor.id, ROLE_KEEPER, None).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let client = pool.get().await.expect("pool.get");

    let mut token_ctx = ctx(&auth, &audit, &closer);
    token_ctx.credential_type = Some(CredentialType::DaemonToken);
    let err = common::admin_dispatch("account_delete", &json!({}), &token_ctx, &client)
        .await
        .expect_err("a token must not self-delete");
    assert_eq!(
        serde_json::to_value(&err).unwrap(),
        serde_json::to_value(credential_type_required(CredentialGate::SESSION_ONLY)).unwrap()
    );

    // Over a session the keeper guard answers.
    let session_ctx = ctx(&auth, &audit, &closer);
    let err = common::admin_dispatch("account_delete", &json!({}), &session_ctx, &client)
        .await
        .expect_err("a keeper must not self-delete");
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_CANNOT_DELETE_KEEPER)
    );
}

/// An admin deleting **another** account keeps any credential — the spec
/// gate is `Any` and the handler's session check is the self path's alone.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_delete_other_admits_a_token() {
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let client = pool.get().await.expect("pool.get");

    for (credential_type, username) in [
        (CredentialType::ApiToken, "target_by_api_token"),
        (CredentialType::DaemonToken, "target_by_daemon_token"),
    ] {
        let mut ctx = ctx(&auth, &audit, &closer);
        ctx.credential_type = Some(credential_type);
        let (account_id, _) = seed_account_actor(&pool, username).await;
        let out = common::admin_dispatch(
            "account_delete",
            &json!({ "account_id": account_id }),
            &ctx,
            &client,
        )
        .await
        .expect("an admin token deletes another account");
        assert_eq!(out["deleted"], Value::Bool(true));
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_delete_missing_account_404() {
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": uuid::Uuid::new_v4() }),
        &ctx,
        &client,
    )
    .await
    .expect_err("must 404 on missing account");
    assert_eq!(err.code, JsonrpcErrorCode::NotFound);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_delete_refuses_keeper() {
    // The keeper account is never API-removable — soft-delete is refused
    // with cannot_delete_keeper and the row is untouched.
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (account_id, actor_id) = seed_account_actor(&pool, "the_keeper").await;
    seed_role_grant_direct(&pool, actor_id, ROLE_KEEPER, None).await;

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": account_id }),
        &ctx,
        &client,
    )
    .await
    .expect_err("must refuse deleting a keeper account");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_CANNOT_DELETE_KEEPER)
    );
    // Keeper row untouched — still resolves through auth.
    let resolved = query_account_by_id(&client, &account_id)
        .await
        .expect("query_account_by_id");
    assert!(
        resolved.is_some(),
        "keeper account must survive the blocked delete"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_purge_refuses_keeper() {
    // Even keeper-authorized purge refuses to remove a keeper account —
    // purging the last keeper would brick keeper/daemon auth.
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (account_id, actor_id) = seed_account_actor(&pool, "last_keeper").await;
    seed_role_grant_direct(&pool, actor_id, ROLE_KEEPER, None).await;

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "account_purge",
        &json!({ "account_id": account_id, "confirm": true }),
        &ctx,
        &client,
    )
    .await
    .expect_err("must refuse purging a keeper account");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_CANNOT_DELETE_KEEPER)
    );
    let resolved = query_account_by_id(&client, &account_id)
        .await
        .expect("query_account_by_id");
    assert!(
        resolved.is_some(),
        "keeper account must survive the blocked purge"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_delete_refuses_last_admin_then_allows_with_a_second() {
    // The sole active admin can't be deleted; adding a second lifts the guard.
    // `seed_admin` creates the caller account but no admin role_grant row, so
    // the only DB admin is the one we seed directly.
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (account_id, actor_id) = seed_account_actor(&pool, "sole_admin").await;
    seed_role_grant_direct(&pool, actor_id, ROLE_ADMIN, None).await;

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": account_id }),
        &ctx,
        &client,
    )
    .await
    .expect_err("must refuse deleting the last admin");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_CANNOT_DELETE_LAST_ADMIN)
    );
    assert!(
        query_account_by_id(&client, &account_id)
            .await
            .expect("query")
            .is_some(),
        "last admin survives the blocked delete"
    );

    // Seed a second admin → neither is the last admin now.
    let (_second_id, second_actor) = seed_account_actor(&pool, "second_admin").await;
    seed_role_grant_direct(&pool, second_actor, ROLE_ADMIN, None).await;
    let out = common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": account_id }),
        &ctx,
        &client,
    )
    .await
    .expect("delete allowed once a second admin exists");
    assert_eq!(out["deleted"], Value::Bool(true));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_purge_requires_confirm() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (account_id, _) = seed_account_actor(&pool, "keep_me").await;

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "account_purge",
        &json!({ "account_id": account_id }), // no confirm
        &ctx,
        &client,
    )
    .await
    .expect_err("purge without confirm must fail loud");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_PURGE_NOT_CONFIRMED)
    );
    // Account untouched.
    let resolved = query_account_by_id(&client, &account_id)
        .await
        .expect("query_account_by_id");
    assert!(resolved.is_some(), "unconfirmed purge is a no-op");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn purge_soft_deleted_admin_succeeds_with_another_active_admin() {
    // Regression: a last-admin guard that tests the target with the
    // tombstone-blind `query_account_has_global_role` disagrees with the
    // active count, which excludes soft-deleted admins. Purging a tombstoned
    // admin with exactly one *other* active admin would see `holds_role=true` +
    // `count=1` and be falsely blocked as `cannot_delete_last_admin`, even
    // though a tombstoned admin can't lower the active count. The admin branch
    // uses the active-account predicate (`query_account_has_active_global_role`).
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    // Two DB admins (seed_admin grants the caller no DB role).
    let (admin_a, actor_a) = seed_account_actor(&pool, "active_admin").await;
    seed_role_grant_direct(&pool, actor_a, ROLE_ADMIN, None).await;
    let (admin_b, actor_b) = seed_account_actor(&pool, "soft_admin").await;
    seed_role_grant_direct(&pool, actor_b, ROLE_ADMIN, None).await;
    let _ = admin_a;

    let client = pool.get().await.expect("pool.get");

    // Soft-delete admin B while both are active (count = 2 → allowed).
    let deleted = common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": admin_b }),
        &ctx,
        &client,
    )
    .await
    .expect("soft-delete of one admin while two exist is allowed");
    assert_eq!(deleted["deleted"], Value::Bool(true));

    // B is now a tombstoned admin; A is the only active admin (count = 1).
    // Purging B must NOT be blocked as the last admin.
    let purged = common::admin_dispatch(
        "account_purge",
        &json!({ "account_id": admin_b, "confirm": true }),
        &ctx,
        &client,
    )
    .await
    .expect("purging a soft-deleted admin must not be blocked as the last admin");
    assert_eq!(purged["purged"], Value::Bool(true));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn last_active_admin_blocked_even_with_a_tombstoned_admin() {
    // Safety counterpart: the active-account predicate must not swing too far.
    // A tombstoned admin doesn't rescue the sole *active* admin — deleting it
    // would leave no admin that can authenticate, so it stays blocked.
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let (admin_a, actor_a) = seed_account_actor(&pool, "active_admin").await;
    seed_role_grant_direct(&pool, actor_a, ROLE_ADMIN, None).await;
    let (admin_b, actor_b) = seed_account_actor(&pool, "soft_admin").await;
    seed_role_grant_direct(&pool, actor_b, ROLE_ADMIN, None).await;

    let client = pool.get().await.expect("pool.get");

    // Soft-delete B → A is the sole active admin.
    common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": admin_b }),
        &ctx,
        &client,
    )
    .await
    .expect("soft-delete of one admin while two exist is allowed");

    // Deleting A must still be refused as the last admin.
    let err = common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": admin_a }),
        &ctx,
        &client,
    )
    .await
    .expect_err("the sole active admin stays blocked even with a tombstoned admin present");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_CANNOT_DELETE_LAST_ADMIN)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn last_admin_guard_ignores_an_admin_grant_on_a_tombstoned_actor() {
    // End-to-end fail-open closure, at the guard (not just the query). An
    // account that is *active* but whose only admin grant sits on a *tombstoned
    // actor* must not inflate the active-admin count — otherwise deleting the
    // sole *usable* admin would be wrongly allowed (the count would read 2).
    // Distinct from `last_active_admin_blocked_even_with_a_tombstoned_admin`,
    // which tombstones the whole *account*; here the account stays active and
    // only its actor is soft-deleted (the latent per-actor-delete state, which
    // the handler can't yet produce, so it's seeded directly). Without the
    // `act.deleted_at IS NULL` filter the delete would be allowed.
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    // The sole usable admin: an active actor holding admin.
    let (admin_a, actor_a) = seed_account_actor(&pool, "usable_admin").await;
    seed_role_grant_direct(&pool, actor_a, ROLE_ADMIN, None).await;

    // A second *active* account whose only admin grant is on a tombstoned actor
    // (its base actor holds no admin).
    let (ghost_account, _ghost_base) = seed_account_actor(&pool, "ghost_admin").await;
    let ghost_extra = seed_extra_actor(&pool, ghost_account, "to_delete").await;
    seed_role_grant_direct(&pool, ghost_extra, ROLE_ADMIN, None).await;
    let client = pool.get().await.expect("pool.get");
    assert!(
        query_actor_soft_delete(&client, &ghost_extra, None)
            .await
            .expect("query_actor_soft_delete"),
        "ghost admin actor soft-deleted",
    );

    // Deleting the only usable admin must be refused — the tombstoned-actor admin
    // grant does not count, so `admin_a` is the last active admin.
    let err = common::admin_dispatch(
        "account_delete",
        &json!({ "account_id": admin_a }),
        &ctx,
        &client,
    )
    .await
    .expect_err("the last usable admin stays blocked despite a tombstoned-actor admin grant");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_CANNOT_DELETE_LAST_ADMIN)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_purge_removes_rows_but_audit_id_survives() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (account_id, _actor_id) = seed_account_actor(&pool, "purged").await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch(
        "account_purge",
        &json!({ "account_id": account_id, "confirm": true }),
        &ctx,
        &client,
    )
    .await
    .expect("account_purge");
    assert_eq!(out["ok"], Value::Bool(true));
    assert_eq!(out["purged"], Value::Bool(true));

    // Account + actor rows are gone (cascading hard delete).
    let acct = client
        .query_opt("SELECT 1 FROM account WHERE id = $1", &[&account_id])
        .await
        .expect("account query");
    assert!(acct.is_none(), "purged account row removed");

    // Audit ids survive (no FK) with identity snapshotted in metadata.
    let account_events = audit_rows_for_target(&pool, "account_purge", account_id).await;
    assert_eq!(account_events.len(), 1, "account_purge row survives purge");
    assert_eq!(
        account_events[0]["username"],
        Value::String("purged".into())
    );
    let actor_events = audit_rows_for_target(&pool, "actor_purge", account_id).await;
    assert_eq!(actor_events.len(), 1, "actor_purge row survives purge");
    assert_eq!(actor_events[0]["name"], Value::String("purged".into()));
}

/// A soft-deleted (tombstoned) actor must not be resolvable as the acting
/// actor: `query_active_actors_by_account` (and therefore
/// `resolve_acting_actor`) filters `deleted_at IS NULL`, while the unfiltered
/// `query_actors_by_account` the admin/snapshot handlers use still sees it.
/// Guards against the multi-actor privilege-confusion hazard where a
/// tombstoned actor's `role_grants` leak into the role gate.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn soft_deleted_actor_not_resolved_as_acting_actor() {
    let pool = fresh_db_pool().await;
    let (account_id, primary_actor_id) = seed_account_actor(&pool, "two_actor").await;
    let extra_actor_id = seed_extra_actor(&pool, account_id, "tombstoned").await;
    let client = pool.get().await.expect("pool.get");

    // Tombstone the extra actor (soft delete).
    let flipped = query_actor_soft_delete(&client, &extra_actor_id, None)
        .await
        .expect("query_actor_soft_delete");
    assert!(flipped, "extra actor soft-deleted");

    // The active query excludes the tombstoned actor; the unfiltered query
    // (used by admin/snapshot handlers) still returns both.
    let active = query_active_actors_by_account(&client, &account_id)
        .await
        .expect("query_active_actors_by_account");
    assert_eq!(active.len(), 1, "only the active actor is listed");
    assert_eq!(active[0].id, primary_actor_id);

    let all = query_actors_by_account(&client, &account_id)
        .await
        .expect("query_actors_by_account");
    assert_eq!(all.len(), 2, "unfiltered query still sees the tombstone");

    // Naming the tombstoned actor as `acting` is rejected — it is no longer
    // on the account from the resolver's perspective.
    let by_id = resolve_acting_actor(&client, &account_id, Some(extra_actor_id))
        .await
        .expect("resolve_acting_actor (tombstoned acting)");
    assert!(
        matches!(by_id, ResolveActingActorResult::ActorNotOnAccount),
        "tombstoned actor must not resolve as acting actor, got {by_id:?}",
    );

    // With one active actor remaining, the omitted-`acting` path resolves
    // transparently to the surviving actor (not `ActorRequired`).
    let resolved = resolve_acting_actor(&client, &account_id, None)
        .await
        .expect("resolve_acting_actor (omitted acting)");
    match resolved {
        ResolveActingActorResult::Resolved(actor) => assert_eq!(actor.id, primary_actor_id),
        other => panic!("expected the single active actor to resolve, got {other:?}"),
    }
}

/// The admin-removability guards must not count a grant held by a *tombstoned*
/// actor. Soft-delete doesn't revoke `role_grant` rows (it's reversible), so an
/// account whose only admin grant sits on a soft-deleted actor would otherwise
/// be counted as a usable admin — letting the last *active* admin be deleted
/// (fail-open). Same tombstone-exclusion the acting-actor / public-read
/// resolution paths apply, pushed down to the account-grain role guards.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn tombstoned_actor_admin_grant_excluded_from_last_admin_guards() {
    let pool = fresh_db_pool().await;

    // Account 1: an active actor holding admin — a genuinely usable admin.
    let (a1, a1_actor) = seed_account_actor(&pool, "usable_admin").await;
    seed_role_grant_direct(&pool, a1_actor, ROLE_ADMIN, None).await;

    // Account 2: its only admin grant sits on an extra actor we then tombstone.
    let (a2, a2_base) = seed_account_actor(&pool, "ghost_admin").await;
    let a2_extra = seed_extra_actor(&pool, a2, "to_delete").await;
    seed_role_grant_direct(&pool, a2_extra, ROLE_ADMIN, None).await;
    {
        let client = pool.get().await.expect("pool.get");
        assert!(
            query_actor_soft_delete(&client, &a2_extra, None)
                .await
                .expect("query_actor_soft_delete"),
            "extra admin actor soft-deleted",
        );
    }

    // Only account 1 is a usable admin; account 2's admin grant is on a tombstone.
    {
        let client = pool.get().await.expect("pool.get");
        assert_eq!(
            query_count_active_accounts_with_global_role_for_update(&client, ROLE_ADMIN, None)
                .await
                .expect("count active admins"),
            1,
            "a tombstoned-actor admin grant must not be counted",
        );
        assert!(
            query_account_has_active_global_role(&client, &a1, ROLE_ADMIN)
                .await
                .expect("holds_active a1"),
            "the usable admin still reads as an active admin",
        );
        assert!(
            !query_account_has_active_global_role(&client, &a2, ROLE_ADMIN)
                .await
                .expect("holds_active a2"),
            "an admin grant only on a tombstoned actor must not read as active",
        );
    }

    // Activating account 2's base actor restores a usable admin → the count
    // rises to 2 (no over-exclusion of accounts that hold both an active and a
    // tombstoned admin grant).
    seed_role_grant_direct(&pool, a2_base, ROLE_ADMIN, None).await;
    {
        let client = pool.get().await.expect("pool.get");
        assert_eq!(
            query_count_active_accounts_with_global_role_for_update(&client, ROLE_ADMIN, None)
                .await
                .expect("count active admins after activating a2 base"),
            2,
            "an account with an active admin actor counts again",
        );
    }
}

/// Keeper queries take *opposite* tombstone postures, by design.
/// [`query_keeper_account_id`] *resolves* the daemon-token identity, so it must
/// exclude a tombstoned keeper actor (a deleted actor can't grant keeper auth).
/// [`query_account_has_global_role`] is the removability guard — it stays
/// unconditional so the keeper is never deleted out from under daemon auth, even
/// when its keeper actor is already tombstoned.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn tombstoned_keeper_actor_excluded_from_resolution_not_removability() {
    let pool = fresh_db_pool().await;
    let (k_account, k_base) = seed_account_actor(&pool, "keeper_host").await;
    let k_extra = seed_extra_actor(&pool, k_account, "keeper_actor").await;
    seed_role_grant_direct(&pool, k_extra, ROLE_KEEPER, None).await;
    {
        let client = pool.get().await.expect("pool.get");
        assert!(
            query_actor_soft_delete(&client, &k_extra, None)
                .await
                .expect("query_actor_soft_delete"),
            "keeper actor soft-deleted",
        );
    }

    {
        let client = pool.get().await.expect("pool.get");
        // Resolution excludes the tombstoned keeper actor → no keeper resolves.
        let resolved = query_keeper_account_id(&client)
            .await
            .expect("query_keeper_account_id");
        assert!(
            resolved.is_none(),
            "a keeper grant on a tombstoned actor must not resolve the daemon keeper, got {resolved:?}",
        );
        // The removability guard stays unconditional → still sees the keeper, so
        // the account can't be deleted out from under daemon auth.
        assert!(
            query_account_has_global_role(&client, &k_account, ROLE_KEEPER)
                .await
                .expect("holds_global keeper"),
            "removability guard must still treat the account as a keeper (fail-safe)",
        );
    }

    // Control: granting keeper to the active base actor makes resolution find it.
    seed_role_grant_direct(&pool, k_base, ROLE_KEEPER, None).await;
    {
        let client = pool.get().await.expect("pool.get");
        assert_eq!(
            query_keeper_account_id(&client)
                .await
                .expect("query_keeper_account_id after active keeper grant"),
            Some(k_account),
            "an active keeper actor resolves the keeper account",
        );
    }
}

/// Stand up a pending offer of `admin` from `grantor_actor` to `to_account`.
async fn offer_from(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    grantor_actor: uuid::Uuid,
    to_account: uuid::Uuid,
) -> uuid::Uuid {
    fuz_auth::query_role_grant_offer_create(
        client,
        fuz_auth::CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: to_account,
            to_actor_id: None,
            role: ROLE_ADMIN.to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: fuz_auth::default_expiry_from_now(),
        },
    )
    .await
    .expect("offer")
    .id
}

/// The `role_grant_offer_supersede` audit rows' metadata for `offer_id`.
async fn supersede_rows(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    offer_id: uuid::Uuid,
) -> Vec<Value> {
    client
        .query(
            "SELECT metadata::text FROM audit_log
             WHERE event_type = 'role_grant_offer_supersede'
               AND metadata->>'offer_id' = $1",
            &[&offer_id.to_string()],
        )
        .await
        .expect("audit rows")
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).expect("metadata"))
        .collect()
}

/// Removing an account ends the pending offers its actors made — soft delete
/// supersedes them, purge supersedes them before its cascade deletes them —
/// each with a `role_grant_offer_supersede` row (`reason: account_deleted`,
/// `cause_id`: the account). Another grantor's offer is untouched.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn account_removal_supersedes_the_accounts_outgoing_offers() {
    let pool = fresh_db_pool().await;
    let auth = with_admin(seed_admin(&pool).await);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let client = pool.get().await.expect("pool.get");
    let (recipient, _) = seed_account_actor(&pool, "offer_recipient").await;
    let (bystander, bystander_actor) = seed_account_actor(&pool, "other_grantor").await;
    let control = offer_from(&client, bystander_actor, recipient).await;

    for (method, username) in [
        ("account_delete", "deleted_grantor"),
        ("account_purge", "purged_grantor"),
    ] {
        let (grantor, grantor_actor) = seed_account_actor(&pool, username).await;
        let extra_actor = seed_extra_actor(&pool, grantor, "second_persona").await;
        let offers = [
            offer_from(&client, grantor_actor, recipient).await,
            offer_from(&client, extra_actor, bystander).await,
        ];
        let params = if method == "account_purge" {
            json!({ "account_id": grantor, "confirm": true })
        } else {
            json!({ "account_id": grantor })
        };
        common::admin_dispatch(method, &params, &ctx, &client)
            .await
            .expect(method);
        for offer in offers {
            let rows = supersede_rows(&client, offer).await;
            assert_eq!(rows.len(), 1, "{method}: one supersede row");
            assert_eq!(rows[0]["reason"], json!("account_deleted"), "{method}");
            assert_eq!(rows[0]["cause_id"], json!(grantor.to_string()), "{method}");
            let pending: Option<bool> = client
                .query_opt(
                    "SELECT superseded_at IS NULL FROM role_grant_offer WHERE id = $1",
                    &[&offer],
                )
                .await
                .expect("offer row")
                .map(|r| r.get(0));
            let expected = if method == "account_purge" {
                None
            } else {
                Some(false)
            };
            assert_eq!(
                pending, expected,
                "{method}: the offer is no longer pending"
            );
        }
    }
    let control_pending: bool = client
        .query_one(
            "SELECT superseded_at IS NULL FROM role_grant_offer WHERE id = $1",
            &[&control],
        )
        .await
        .expect("control")
        .get(0);
    assert!(control_pending, "another grantor's offer stays pending");
    assert!(supersede_rows(&client, control).await.is_empty());
}

/// The last-admin count locks what it counted: a second guard counting while
/// the first's transaction removes an admin waits for its commit and then
/// counts one — so two removals racing for the last two admins can't both
/// pass.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn the_admin_count_locks_what_it_counted() {
    let pool = fresh_db_pool().await;
    let (_a1, a1_actor) = seed_account_actor(&pool, "racing_admin_one").await;
    seed_role_grant_direct(&pool, a1_actor, ROLE_ADMIN, None).await;
    let (a2, a2_actor) = seed_account_actor(&pool, "racing_admin_two").await;
    seed_role_grant_direct(&pool, a2_actor, ROLE_ADMIN, None).await;

    let mut first_client = pool.get().await.expect("pool.get");
    let first = first_client.transaction().await.expect("begin");
    assert_eq!(
        query_count_active_accounts_with_global_role_for_update(&first, ROLE_ADMIN, None)
            .await
            .expect("count"),
        2
    );
    assert!(
        fuz_auth::account_queries::query_account_soft_delete(&first, &a2, None)
            .await
            .expect("soft delete")
            .is_some()
    );

    let second = tokio::spawn({
        let pool = pool.clone();
        async move {
            let mut client = pool.get().await.expect("pool.get");
            let tx = client.transaction().await.expect("begin");
            let count =
                query_count_active_accounts_with_global_role_for_update(&tx, ROLE_ADMIN, None)
                    .await
                    .expect("count");
            tx.rollback().await.expect("rollback");
            count
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !second.is_finished(),
        "the second count waits on the rows the first locked"
    );
    first.commit().await.expect("commit");
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), second)
            .await
            .expect("the second count completes")
            .expect("join"),
        1,
        "after the first commits, one admin is left"
    );
}
