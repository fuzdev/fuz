//! Integration tests for the `invite_create` / `invite_list` /
//! `invite_delete` admin RPC actions against a real `PostgreSQL`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test invite_admin -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required because every test drops + recreates
//! the shared schema (same shape as `tests/signup.rs`); parallel runs
//! race on the `schema_version` table.
//!
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

use fuz_auth::admin_action_specs::{
    ERROR_INVITE_ACCOUNT_EXISTS_EMAIL, ERROR_INVITE_ACCOUNT_EXISTS_USERNAME,
    ERROR_INVITE_DUPLICATE, ERROR_INVITE_NOT_FOUND,
};
use fuz_http::JsonrpcErrorCode;
use serde_json::{Value, json};

mod common;
use common::{build_audit, closer, ctx, fresh_db_pool, seed_account, seed_admin};

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_create_success() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let params = json!({"email": "new@example.com", "username": "new_user"});
    let out = common::admin_dispatch("invite_create", &params, &ctx, &client)
        .await
        .expect("invite_create");

    assert_eq!(out["ok"], Value::Bool(true));
    assert_eq!(
        out["invite"]["email"],
        Value::String("new@example.com".into())
    );
    assert_eq!(out["invite"]["username"], Value::String("new_user".into()));
    assert_eq!(out["invite"]["claimed_at"], Value::Null);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_create_requires_email_or_username() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch("invite_create", &json!({}), &ctx, &client)
        .await
        .expect_err("must reject empty input");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_create_rejects_username_collision() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    seed_account(&pool, "taken_user", None).await;

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "invite_create",
        &json!({"username": "TAKEN_USER"}), // case-insensitive
        &ctx,
        &client,
    )
    .await
    .expect_err("must reject username collision");
    assert_eq!(err.code, JsonrpcErrorCode::Conflict);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_INVITE_ACCOUNT_EXISTS_USERNAME)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_create_rejects_email_collision() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    seed_account(&pool, "user_with_email", Some("collide@example.com")).await;

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "invite_create",
        &json!({"email": "COLLIDE@example.com"}), // case-insensitive
        &ctx,
        &client,
    )
    .await
    .expect_err("must reject email collision");
    assert_eq!(err.code, JsonrpcErrorCode::Conflict);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_INVITE_ACCOUNT_EXISTS_EMAIL)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_create_rejects_duplicate_unclaimed_invite() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    common::admin_dispatch(
        "invite_create",
        &json!({"username": "dup_user"}),
        &ctx,
        &client,
    )
    .await
    .expect("first create");

    let err = common::admin_dispatch(
        "invite_create",
        &json!({"username": "dup_user"}),
        &ctx,
        &client,
    )
    .await
    .expect_err("must reject duplicate unclaimed invite");
    assert_eq!(err.code, JsonrpcErrorCode::Conflict);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_INVITE_DUPLICATE)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_list_returns_rows_with_usernames() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    common::admin_dispatch(
        "invite_create",
        &json!({"username": "list_user_a"}),
        &ctx,
        &client,
    )
    .await
    .expect("first create");
    common::admin_dispatch(
        "invite_create",
        &json!({"email": "list_b@example.com"}),
        &ctx,
        &client,
    )
    .await
    .expect("second create");

    let out = common::admin_dispatch("invite_list", &json!({}), &ctx, &client)
        .await
        .expect("invite_list");

    let invites = out["invites"].as_array().expect("invites array");
    assert_eq!(invites.len(), 2, "two unclaimed invites visible");
    // ORDER BY created_at DESC → second create (email-only) comes first.
    assert_eq!(
        invites[0]["email"],
        Value::String("list_b@example.com".into())
    );
    assert_eq!(
        invites[0]["created_by_username"],
        Value::String("admin_keeper".into())
    );
    assert_eq!(invites[0]["claimed_by_username"], Value::Null);
    assert_eq!(invites[1]["username"], Value::String("list_user_a".into()));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_delete_removes_unclaimed() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let created = common::admin_dispatch(
        "invite_create",
        &json!({"username": "del_user"}),
        &ctx,
        &client,
    )
    .await
    .expect("create");
    let invite_id = created["invite"]["id"].as_str().expect("invite id");

    let out = common::admin_dispatch(
        "invite_delete",
        &json!({"invite_id": invite_id}),
        &ctx,
        &client,
    )
    .await
    .expect("delete");
    assert_eq!(out, json!({"ok": true}));

    let listed = common::admin_dispatch("invite_list", &json!({}), &ctx, &client)
        .await
        .expect("list");
    assert_eq!(listed["invites"].as_array().expect("array").len(), 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_delete_rejects_missing_invite() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "invite_delete",
        &json!({"invite_id": uuid::Uuid::new_v4().to_string()}),
        &ctx,
        &client,
    )
    .await
    .expect_err("missing invite");
    assert_eq!(err.code, JsonrpcErrorCode::NotFound);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_INVITE_NOT_FOUND)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn invite_delete_rejects_claimed_invite() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let claimer_id = seed_account(&pool, "claimer", None).await;
    let invite_row = client
        .query_one(
            "INSERT INTO invite (username, claimed_by, claimed_at)
             VALUES ('claimed_user', $1, NOW()) RETURNING id",
            &[&claimer_id],
        )
        .await
        .expect("insert claimed invite");
    let invite_id: uuid::Uuid = invite_row.get(0);

    let err = common::admin_dispatch(
        "invite_delete",
        &json!({"invite_id": invite_id.to_string()}),
        &ctx,
        &client,
    )
    .await
    .expect_err("must reject claimed invite delete");
    assert_eq!(err.code, JsonrpcErrorCode::NotFound);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_INVITE_NOT_FOUND)
    );
}
