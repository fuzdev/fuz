//! Integration tests for the four admin-read RPC methods —
//! `admin_account_list`, `admin_session_list`, `audit_log_list`,
//! `audit_log_role_grant_history` — against a real `PostgreSQL`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test admin_lists -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required because every test drops + recreates
//! the shared schema (same shape as `tests/signup.rs` and
//! `tests/invite_admin.rs`); parallel runs race on the `schema_version`
//! table. Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

use fuz_auth::ROLE_ADMIN;
use fuz_auth::admin_action_specs::{ADMIN_ACCOUNT_LIST_LIMIT_MAX, ERROR_ACCOUNT_NOT_FOUND};
use fuz_auth::audit_log_queries::AUDIT_LOG_LIST_LIMIT_MAX;
use fuz_auth::params_helpers::{ERROR_LIMIT_INVALID, ERROR_OFFSET_INVALID};
use fuz_http::JsonrpcErrorCode;
use serde_json::{Value, json};

mod common;
use common::{
    build_audit, closer, ctx, fresh_db_pool, seed_account_actor, seed_admin, seed_audit_log_row,
    seed_role_grant_direct,
};

// ============================================================
// admin_account_list
// ============================================================

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn admin_account_list_returns_seeded_accounts_and_grantable_roles() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (_, _) = seed_account_actor(&pool, "user_one").await;
    let (_, _) = seed_account_actor(&pool, "user_two").await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("admin_account_list", &json!({}), &ctx, &client)
        .await
        .expect("admin_account_list");

    let accounts = out["accounts"].as_array().expect("accounts array");
    // admin_keeper + user_one + user_two = 3
    assert!(
        accounts.len() >= 3,
        "expected >=3 accounts, got {}",
        accounts.len()
    );

    let grantable_roles = out["grantable_roles"]
        .as_array()
        .expect("grantable_roles array");
    assert_eq!(grantable_roles.len(), 1, "v1 hardcodes one grantable role");
    assert_eq!(grantable_roles[0], Value::String(ROLE_ADMIN.into()));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn admin_account_list_each_entry_has_account_actor_and_lists() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    seed_account_actor(&pool, "u1").await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("admin_account_list", &json!({}), &ctx, &client)
        .await
        .expect("admin_account_list");

    for entry in out["accounts"].as_array().expect("accounts array") {
        assert!(entry["account"]["id"].is_string(), "account.id missing");
        assert!(
            entry["account"]["username"].is_string(),
            "account.username missing"
        );
        assert!(
            entry["account"]["created_at"].is_string(),
            "account.created_at missing"
        );
        assert!(
            entry["account"]["updated_at"].is_string(),
            "account.updated_at missing"
        );
        // ISO-8601 with trailing Z
        let created_at = entry["account"]["created_at"].as_str().unwrap();
        assert!(
            created_at.ends_with('Z'),
            "created_at should be ISO-8601 UTC, got: {created_at}"
        );
        assert!(entry["role_grants"].is_array(), "role_grants missing");
        assert!(entry["pending_offers"].is_array(), "pending_offers missing");
        // `actor` is nullable — admin_keeper has one, plain accounts may not.
    }
}

/// Rows written in one transaction share `created_at` (`NOW()` is the
/// transaction's start), so the listing's order rests on its tiebreak keys —
/// data keys (`username`, `name`, `role`), never the random `id` alone, which
/// differs between two backends holding the same rows. Each row's key order
/// is the reverse of its id and insertion order, so a tiebreak on either
/// shows. The keys are plain lowercase, so a locale and a bytewise collation
/// order them alike. The TS twin's
/// `account_queries.db.test.ts` seeds the same rows and asserts the same order.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn admin_account_list_orders_rows_sharing_created_at_by_shared_keys() {
    let id = |n: u128| uuid::Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0000 | n);
    let (account_1, account_2) = (id(0x01), id(0x02));
    let (actor_1, actor_2) = (id(0x11), id(0x12));
    let (grant_1, grant_2, grant_3) = (id(0x21), id(0x22), id(0x23));
    let (offer_1, offer_2, offer_3) = (id(0x31), id(0x32), id(0x33));
    let (scope_1, scope_2) = (id(0x41), id(0x42));

    let pool = fresh_db_pool().await;
    let mut client = pool.get().await.expect("pool.get");
    let tx = client.transaction().await.expect("begin");
    tx.execute(
        "INSERT INTO account (id, username, password_hash) VALUES ($1, 'tie_b', 'x'), ($2, 'tie_a', 'x')",
        &[&account_1, &account_2],
    )
    .await
    .expect("insert accounts");
    tx.execute(
        "INSERT INTO actor (id, account_id, name) VALUES ($1, $3, 'second'), ($2, $3, 'first')",
        &[&actor_1, &actor_2, &account_2],
    )
    .await
    .expect("insert actors");
    tx.execute(
        "INSERT INTO role_grant (id, actor_id, role)
         VALUES ($1, $4, 'role_c'), ($2, $4, 'role_b'), ($3, $4, 'role_a')",
        &[&grant_1, &grant_2, &grant_3, &actor_2],
    )
    .await
    .expect("insert role_grants");
    // one `expires_at`, so the offers order on `role`, then `scope_id`
    tx.execute(
        "INSERT INTO role_grant_offer
           (id, from_actor_id, to_account_id, role, scope_kind, scope_id, expires_at)
         VALUES ($1, $4, $5, 'role_b', 'space', $7, '2999-01-01T00:00:00Z'),
                ($2, $4, $5, 'role_b', 'space', $6, '2999-01-01T00:00:00Z'),
                ($3, $4, $5, 'role_a', NULL, NULL, '2999-01-01T00:00:00Z')",
        &[
            &offer_1, &offer_2, &offer_3, &actor_1, &account_2, &scope_1, &scope_2,
        ],
    )
    .await
    .expect("insert role_grant_offers");
    tx.commit().await.expect("commit");

    let entries = fuz_auth::query_admin_account_list(&client, 50, 0, false)
        .await
        .expect("admin_account_list");
    let usernames: Vec<&str> = entries
        .iter()
        .map(|e| e.account.username.as_str())
        .collect();
    assert_eq!(usernames, ["tie_a", "tie_b"]);
    let entry = &entries[0];
    assert_eq!(
        entry.actor.as_ref().map(|a| a.name.as_str()),
        Some("first"),
        "the oldest actor, by name on a tie"
    );
    let roles: Vec<&str> = entry.role_grants.iter().map(|g| g.role.as_str()).collect();
    assert_eq!(roles, ["role_a", "role_b", "role_c"]);
    let offers: Vec<uuid::Uuid> = entry.pending_offers.iter().map(|o| o.id).collect();
    assert_eq!(
        offers,
        [offer_3, offer_2, offer_1],
        "pending offers by role, then scope_id"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn admin_account_list_pagination_default_and_max_ok() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    // Default limit (50, but no pagination param) — should succeed.
    common::admin_dispatch("admin_account_list", &json!({}), &ctx, &client)
        .await
        .expect("default page ok");

    // Max-limit page — should succeed.
    common::admin_dispatch(
        "admin_account_list",
        &json!({"limit": ADMIN_ACCOUNT_LIST_LIMIT_MAX}),
        &ctx,
        &client,
    )
    .await
    .expect("max-limit page ok");

    // Explicit offset >= 0 ok.
    common::admin_dispatch(
        "admin_account_list",
        &json!({"limit": 10, "offset": 0}),
        &ctx,
        &client,
    )
    .await
    .expect("offset=0 ok");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn admin_account_list_rejects_limit_over_max() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "admin_account_list",
        &json!({"limit": ADMIN_ACCOUNT_LIST_LIMIT_MAX + 1}),
        &ctx,
        &client,
    )
    .await
    .expect_err("limit > max should reject");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_LIMIT_INVALID)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn admin_account_list_rejects_negative_offset() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch("admin_account_list", &json!({"offset": -1}), &ctx, &client)
        .await
        .expect_err("negative offset should reject");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_OFFSET_INVALID)
    );
}

// ============================================================
// admin_session_list
// ============================================================

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn admin_session_list_returns_active_sessions_with_usernames() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (acct_one, _) = seed_account_actor(&pool, "alice").await;

    // Seed an active session for alice.
    let session_client = pool.get().await.expect("pool.get");
    session_client
        .execute(
            "INSERT INTO auth_session (id, account_id, expires_at)
             VALUES ('session-hash-alice', $1, NOW() + INTERVAL '30 days')",
            &[&acct_one],
        )
        .await
        .expect("insert session");
    drop(session_client);

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("admin_session_list", &json!({}), &ctx, &client)
        .await
        .expect("admin_session_list");

    let sessions = out["sessions"].as_array().expect("sessions array");
    assert_eq!(sessions.len(), 1);
    let entry = &sessions[0];
    assert_eq!(entry["id"], Value::String("session-hash-alice".into()));
    assert_eq!(entry["username"], Value::String("alice".into()));
    assert!(entry["created_at"].as_str().unwrap().ends_with('Z'));
    assert!(entry["expires_at"].as_str().unwrap().ends_with('Z'));
    assert!(
        entry.get("last_seen_at").is_none(),
        "last_seen_at must stay off the wire"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn admin_session_list_excludes_expired() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (acct_one, _) = seed_account_actor(&pool, "alice").await;

    let session_client = pool.get().await.expect("pool.get");
    // Already-expired row should be hidden by the `expires_at > NOW()`
    // filter.
    session_client
        .execute(
            "INSERT INTO auth_session (id, account_id, expires_at)
             VALUES ('session-hash-expired', $1, NOW() - INTERVAL '1 day')",
            &[&acct_one],
        )
        .await
        .expect("insert expired session");
    drop(session_client);

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("admin_session_list", &json!({}), &ctx, &client)
        .await
        .expect("admin_session_list");

    assert_eq!(out["sessions"].as_array().expect("sessions array").len(), 0);
}

// ============================================================
// audit_log_list
// ============================================================

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_list_returns_seeded_rows_newest_first() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    seed_audit_log_row(
        &pool,
        "login",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;
    seed_audit_log_row(
        &pool,
        "logout",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("audit_log_list", &json!({}), &ctx, &client)
        .await
        .expect("audit_log_list");

    let events = out["events"].as_array().expect("events array");
    assert!(events.len() >= 2);
    // ORDER BY seq DESC — logout (inserted second) should come first.
    assert_eq!(events[0]["event_type"], Value::String("logout".into()));
    assert_eq!(events[1]["event_type"], Value::String("login".into()));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_list_filters_by_event_type() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    seed_audit_log_row(
        &pool,
        "login",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;
    seed_audit_log_row(
        &pool,
        "logout",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;
    seed_audit_log_row(
        &pool,
        "session_revoke_all",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch(
        "audit_log_list",
        &json!({"event_type": "logout"}),
        &ctx,
        &client,
    )
    .await
    .expect("audit_log_list event_type filter");

    let events = out["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], Value::String("logout".into()));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_list_filters_by_outcome() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    seed_audit_log_row(
        &pool,
        "login",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;
    seed_audit_log_row(
        &pool,
        "login",
        "failure",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch(
        "audit_log_list",
        &json!({"outcome": "failure"}),
        &ctx,
        &client,
    )
    .await
    .expect("audit_log_list outcome filter");

    let events = out["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["outcome"], Value::String("failure".into()));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_list_filters_by_account_id_matches_either_direction() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (target_acct, _) = seed_account_actor(&pool, "target_user").await;
    let (other_acct, _) = seed_account_actor(&pool, "other_user").await;

    // Row where target is the actor (account_id = target).
    seed_audit_log_row(
        &pool,
        "login",
        "success",
        None,
        Some(target_acct),
        None,
        None,
        None,
    )
    .await;
    // Row where target is the *target_account_id* (other actor probes target).
    seed_audit_log_row(
        &pool,
        "session_revoke_all",
        "success",
        None,
        Some(other_acct),
        Some(target_acct),
        None,
        None,
    )
    .await;
    // Unrelated row.
    seed_audit_log_row(
        &pool,
        "login",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch(
        "audit_log_list",
        &json!({"account_id": target_acct.to_string()}),
        &ctx,
        &client,
    )
    .await
    .expect("audit_log_list account_id filter");

    let events = out["events"].as_array().expect("events array");
    // Both target-as-actor and target-as-target should match.
    assert_eq!(events.len(), 2);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_list_since_seq_cursor_advances() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    seed_audit_log_row(
        &pool,
        "login",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;
    seed_audit_log_row(
        &pool,
        "logout",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;

    let client = pool.get().await.expect("pool.get");

    // First read — get the max seq.
    let out = common::admin_dispatch("audit_log_list", &json!({}), &ctx, &client)
        .await
        .expect("audit_log_list");
    let first_seq = out["events"][0]["seq"].as_i64().expect("seq number");

    // Since-seq gap-fill from the max — should return nothing new.
    let out2 = common::admin_dispatch(
        "audit_log_list",
        &json!({"since_seq": first_seq}),
        &ctx,
        &client,
    )
    .await
    .expect("audit_log_list since_seq");
    assert_eq!(out2["events"].as_array().expect("events array").len(), 0);

    // Insert a new row; since-seq from the previous max returns just it.
    seed_audit_log_row(
        &pool,
        "password_change",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;
    let out3 = common::admin_dispatch(
        "audit_log_list",
        &json!({"since_seq": first_seq}),
        &ctx,
        &client,
    )
    .await
    .expect("audit_log_list since_seq after insert");
    let events = out3["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]["event_type"],
        Value::String("password_change".into())
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_list_resolves_usernames_via_actor_chain() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (acct, actor) = seed_account_actor(&pool, "probe_subject").await;

    // Actor-stamped row — username should resolve via actor.account_id JOIN.
    seed_audit_log_row(
        &pool,
        "login",
        "success",
        Some(actor),
        Some(acct),
        None,
        None,
        None,
    )
    .await;
    // Account-only row — username should fall back to direct account JOIN.
    seed_audit_log_row(
        &pool,
        "session_revoke_all",
        "success",
        None,
        Some(auth.account.id),
        Some(acct),
        None,
        None,
    )
    .await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("audit_log_list", &json!({}), &ctx, &client)
        .await
        .expect("audit_log_list");
    let events = out["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2);

    // Newest is session_revoke_all (target_username = probe_subject).
    assert_eq!(
        events[0]["target_username"],
        Value::String("probe_subject".into())
    );
    assert_eq!(events[0]["username"], Value::String("admin_keeper".into()));
    // Oldest is login (username = probe_subject via actor chain).
    assert_eq!(events[1]["username"], Value::String("probe_subject".into()));
    assert_eq!(events[1]["target_username"], Value::Null);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_list_rejects_limit_over_max() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let err = common::admin_dispatch(
        "audit_log_list",
        &json!({"limit": AUDIT_LOG_LIST_LIMIT_MAX + 1}),
        &ctx,
        &client,
    )
    .await
    .expect_err("limit > max should reject");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_LIMIT_INVALID)
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_list_empty_result_on_no_rows() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("audit_log_list", &json!({}), &ctx, &client)
        .await
        .expect("audit_log_list");
    assert_eq!(out["events"].as_array().expect("events array").len(), 0);
}

// ============================================================
// audit_log_role_grant_history
// ============================================================

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_role_grant_history_returns_grant_and_revoke_only() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (acct, actor) = seed_account_actor(&pool, "user_alpha").await;
    let _grant_id = seed_role_grant_direct(&pool, actor, ROLE_ADMIN, Some(auth.actor.id)).await;

    // Seed three audit rows: a role_grant_create, a role_grant_revoke,
    // and an unrelated login (should be excluded).
    seed_audit_log_row(
        &pool,
        "role_grant_create",
        "success",
        Some(auth.actor.id),
        Some(auth.account.id),
        Some(acct),
        Some(actor),
        None,
    )
    .await;
    seed_audit_log_row(
        &pool,
        "role_grant_revoke",
        "success",
        Some(auth.actor.id),
        Some(auth.account.id),
        Some(acct),
        Some(actor),
        None,
    )
    .await;
    seed_audit_log_row(
        &pool,
        "login",
        "success",
        None,
        Some(acct),
        None,
        None,
        None,
    )
    .await;
    // Offer-side events should also be excluded.
    seed_audit_log_row(
        &pool,
        "role_grant_offer_create",
        "success",
        Some(auth.actor.id),
        Some(auth.account.id),
        Some(acct),
        Some(actor),
        None,
    )
    .await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("audit_log_role_grant_history", &json!({}), &ctx, &client)
        .await
        .expect("audit_log_role_grant_history");

    let events = out["events"].as_array().expect("events array");
    assert_eq!(events.len(), 2);
    let types: Vec<&str> = events
        .iter()
        .map(|e| e["event_type"].as_str().unwrap())
        .collect();
    // ORDER BY seq DESC — revoke (inserted after create) comes first.
    assert_eq!(types, vec!["role_grant_revoke", "role_grant_create"]);

    // Username resolution flows through.
    for e in events {
        assert_eq!(e["username"], Value::String("admin_keeper".into()));
        assert_eq!(e["target_username"], Value::String("user_alpha".into()));
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_role_grant_history_empty_when_no_role_grant_events() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);

    // Seed only unrelated rows.
    seed_audit_log_row(
        &pool,
        "login",
        "success",
        None,
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;
    seed_audit_log_row(
        &pool,
        "role_grant_offer_create",
        "success",
        Some(auth.actor.id),
        Some(auth.account.id),
        None,
        None,
        None,
    )
    .await;

    let client = pool.get().await.expect("pool.get");
    let out = common::admin_dispatch("audit_log_role_grant_history", &json!({}), &ctx, &client)
        .await
        .expect("audit_log_role_grant_history");
    assert_eq!(out["events"].as_array().expect("events array").len(), 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn audit_log_role_grant_history_pagination_respects_offset() {
    let pool = fresh_db_pool().await;
    let auth = seed_admin(&pool).await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&auth, &audit, &closer);
    let (acct, actor) = seed_account_actor(&pool, "user_alpha").await;

    for _ in 0..3 {
        seed_audit_log_row(
            &pool,
            "role_grant_create",
            "success",
            Some(auth.actor.id),
            Some(auth.account.id),
            Some(acct),
            Some(actor),
            None,
        )
        .await;
    }

    let client = pool.get().await.expect("pool.get");
    // limit=1 offset=1 should return exactly 1 row (the 2nd-newest).
    let out = common::admin_dispatch(
        "audit_log_role_grant_history",
        &json!({"limit": 1, "offset": 1}),
        &ctx,
        &client,
    )
    .await
    .expect("audit_log_role_grant_history paginated");
    assert_eq!(out["events"].as_array().expect("events array").len(), 1);
}

// ============================================================
// Misc — confirms the unused-param ERROR_ACCOUNT_NOT_FOUND import
// isn't accidentally tripping a dead-code warning under
// --warnings-as-errors. Read-side methods don't emit account-not-found
// audits; the constant exists for `admin_session_revoke_all` etc.
// ============================================================

#[test]
fn error_constant_compiles() {
    assert!(!ERROR_ACCOUNT_NOT_FOUND.is_empty());
}
