//! `account_session_list` marks the caller's own session `is_current` — the
//! row whose id is the request's session hash — and none for a credential no
//! session authenticated (bearer, daemon token).

// `allow-*-in-tests` doesn't cover the non-`#[test]` helper fns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use fuz_auth::{
    AccountActionContext, AccountActionSpecs, AccountRow, CredentialType, NoopAuditPostCommit,
    RequestContext, create_capped_session, hash_session_token,
};
use serde_json::Value;

/// The listed sessions as `(id, is_current)`, for a caller whose session hash
/// is `session_hash`.
async fn list_sessions(
    pool: &fuz_db::Pool,
    auth: &RequestContext,
    credential_type: CredentialType,
    session_hash: Option<&str>,
) -> Vec<(String, bool)> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = AccountActionContext {
        auth,
        credential_type: Some(credential_type),
        session_hash,
        audit: &audit,
        post_commit: &NoopAuditPostCommit,
        connection_closer: &closer,
        notification_sender: common::noop_notification_sender(),
        client_ip: None,
    };
    let client = pool.get().await.expect("pool.get");
    let result = AccountActionSpecs::dispatch("account_session_list", &Value::Null, &ctx, &client)
        .await
        .expect("account_session_list");
    result["sessions"]
        .as_array()
        .expect("sessions array")
        .iter()
        .map(|s| {
            (
                s["id"].as_str().expect("id").to_owned(),
                s["is_current"].as_bool().expect("is_current is a boolean"),
            )
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn session_list_marks_the_callers_session_current() {
    let pool = common::fresh_db_pool().await;
    let account_id = common::seed_account(&pool, "session_list_user", None).await;
    let client = pool.get().await.expect("pool.get");
    let first = create_capped_session(&client, &account_id)
        .await
        .expect("first session");
    let second = create_capped_session(&client, &account_id)
        .await
        .expect("second session");
    let auth = RequestContext {
        account: AccountRow {
            id: account_id,
            username: "session_list_user".to_owned(),
        },
    };

    for token in [&first.token, &second.token] {
        let hash = hash_session_token(token);
        let listed = list_sessions(&pool, &auth, CredentialType::Session, Some(&hash)).await;
        let current: Vec<&str> = listed
            .iter()
            .filter(|(_, is_current)| *is_current)
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(current, [hash.as_str()], "exactly the caller's own session");
        assert_eq!(listed.len(), 2);
    }

    let listed = list_sessions(&pool, &auth, CredentialType::ApiToken, None).await;
    assert_eq!(listed.len(), 2);
    assert!(
        listed.iter().all(|(_, is_current)| !is_current),
        "no session authenticated a bearer caller"
    );
}
