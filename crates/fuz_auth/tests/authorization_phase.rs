//! The authorization phase builds on the account the credential resolved and
//! never reads it again, against a live database — and an account removed
//! after the credential read answers the dead credential's 401, never a 500.
//!
//! [`apply_authorization_phase`] takes the [`AccountRow`] the credential walk
//! read. An account removed after that read is no torn read between two reads:
//! an account-grain spec gets its context built on the carried row, as for
//! any request a removal lands behind. Twin of `fuz_app`'s
//! `src/test/auth/authorization_phase.carried_account.db.test.ts`.

use fuz_auth::account_queries::{
    query_account_by_id, query_account_soft_delete, query_account_summary, query_purge_account,
};
use fuz_auth::action_auth::AuthSpec;
use fuz_auth::actor_queries::query_actor_soft_delete;
use fuz_auth::{
    AccountActionContext, AccountActionSpecs, CredentialGate, CredentialType, NoopAuditPostCommit,
    RequestContext, ResolvedAuthOwned, apply_authorization_phase,
};
use fuz_http::JsonrpcErrorCode;
use serde_json::json;

mod common;
use common::{fresh_db, seed_account_actor};

#[tokio::test]
async fn an_account_grain_phase_builds_on_the_carried_account_without_reading_it() {
    let pool = fresh_db().await;
    let (account_id, _actor_id) = seed_account_actor(&pool, "carried").await;
    let client = pool.get().await.unwrap();
    // the row the credential walk read
    let account = query_account_by_id(&client, &account_id)
        .await
        .unwrap()
        .expect("the account is live");
    // removed after the walk, before the phase
    assert!(
        query_account_soft_delete(&client, &account_id, None)
            .await
            .unwrap()
            .is_some()
    );

    let resolved = apply_authorization_phase(
        &client,
        Some(&account),
        &AuthSpec::account_grain(CredentialGate::Any),
        None,
    )
    .await
    .expect("the phase builds on the carried row");
    let ResolvedAuthOwned::Account(ctx) = resolved else {
        panic!("an account-grain spec resolves the account-grain context");
    };
    assert_eq!(ctx.account.id, account_id);
    assert_eq!(ctx.account.username, account.username);
}

/// An actor-grain phase on an account removed after its credential was read
/// finds the account's actors gone and answers the dead credential's 401 —
/// soft-deleted (the account and its actors tombstoned) or purged.
#[tokio::test]
async fn an_actor_grain_phase_on_a_removed_account_answers_the_dead_credentials_401() {
    for purge in [false, true] {
        let pool = fresh_db().await;
        let (account_id, actor_id) = seed_account_actor(&pool, "removed").await;
        let client = pool.get().await.unwrap();
        let account = query_account_by_id(&client, &account_id)
            .await
            .unwrap()
            .expect("the account is live");
        if purge {
            assert!(
                query_purge_account(&client, &account_id)
                    .await
                    .unwrap()
                    .is_some()
            );
        } else {
            query_account_soft_delete(&client, &account_id, None)
                .await
                .unwrap();
            assert!(
                query_actor_soft_delete(&client, &actor_id, None)
                    .await
                    .unwrap()
            );
        }
        let error = apply_authorization_phase(
            &client,
            Some(&account),
            &AuthSpec::authenticated(CredentialGate::Any),
            None,
        )
        .await
        .expect_err("a removed account resolves no actor");
        assert_eq!(
            error.code,
            JsonrpcErrorCode::Unauthenticated,
            "purge: {purge}"
        );
        assert_eq!(
            error.data,
            Some(json!({ "reason": "authentication_required" })),
            "purge: {purge}"
        );
    }
}

/// A live account with no active actor is still the 500 — the signup
/// invariant broken, not a removed account.
#[tokio::test]
async fn a_live_account_with_no_actor_is_still_the_500() {
    let pool = fresh_db().await;
    let (account_id, actor_id) = seed_account_actor(&pool, "actorless").await;
    let client = pool.get().await.unwrap();
    let account = query_account_by_id(&client, &account_id)
        .await
        .unwrap()
        .expect("the account is live");
    assert!(
        query_actor_soft_delete(&client, &actor_id, None)
            .await
            .unwrap()
    );
    let error = apply_authorization_phase(
        &client,
        Some(&account),
        &AuthSpec::authenticated(CredentialGate::Any),
        None,
    )
    .await
    .expect_err("no actor to resolve");
    assert_eq!(error.code, JsonrpcErrorCode::InternalError);
    assert_eq!(error.message, "no_actors_on_account");
}

/// `account_verify` on an account purged after its credential was read
/// answers the dead credential's 401, not a 500: its summary read finds no
/// row.
#[tokio::test]
async fn account_verify_on_a_purged_account_answers_the_dead_credentials_401() {
    let pool = fresh_db().await;
    let (account_id, _actor_id) = seed_account_actor(&pool, "verified").await;
    let client = pool.get().await.unwrap();
    let account = query_account_by_id(&client, &account_id)
        .await
        .unwrap()
        .expect("the account is live");
    assert!(
        query_purge_account(&client, &account_id)
            .await
            .unwrap()
            .is_some()
    );
    let auth = RequestContext { account };
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = AccountActionContext {
        auth: &auth,
        credential_type: Some(CredentialType::Session),
        session_hash: None,
        audit: &audit,
        post_commit: &NoopAuditPostCommit,
        connection_closer: &closer,
        notification_sender: common::noop_notification_sender(),
        client_ip: Some("127.0.0.1".to_owned()),
    };
    let error = AccountActionSpecs::dispatch("account_verify", &json!({}), &ctx, &client)
        .await
        .expect_err("the purged account");
    assert_eq!(error.code, JsonrpcErrorCode::Unauthenticated);
}

/// `account_verify` on an account deleted after its credential was read
/// answers the dead credential's 401: its summary read finds no live row.
#[tokio::test]
async fn account_verify_on_a_deleted_account_answers_the_dead_credentials_401() {
    let pool = fresh_db().await;
    let (account_id, _actor_id) = seed_account_actor(&pool, "verified_deleted").await;
    let client = pool.get().await.unwrap();
    let account = query_account_by_id(&client, &account_id)
        .await
        .unwrap()
        .expect("the account is live");
    query_account_soft_delete(&client, &account_id, None)
        .await
        .unwrap();
    let auth = RequestContext { account };
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = AccountActionContext {
        auth: &auth,
        credential_type: Some(CredentialType::Session),
        session_hash: None,
        audit: &audit,
        post_commit: &NoopAuditPostCommit,
        connection_closer: &closer,
        notification_sender: common::noop_notification_sender(),
        client_ip: Some("127.0.0.1".to_owned()),
    };
    let error = AccountActionSpecs::dispatch("account_verify", &json!({}), &ctx, &client)
        .await
        .expect_err("the deleted account");
    assert_eq!(error.code, JsonrpcErrorCode::Unauthenticated);
}

/// The account summary `account_verify` and `/status` answer with is a live
/// account's: a tombstoned one reads as gone, so both answer the dead
/// credential's 401.
#[tokio::test]
async fn the_account_summary_of_a_deleted_account_is_none() {
    let pool = fresh_db().await;
    let (account_id, _actor_id) = seed_account_actor(&pool, "summary_deleted").await;
    let client = pool.get().await.unwrap();
    assert!(
        query_account_summary(&client, &account_id)
            .await
            .unwrap()
            .is_some()
    );
    query_account_soft_delete(&client, &account_id, None)
        .await
        .unwrap();
    assert!(
        query_account_summary(&client, &account_id)
            .await
            .unwrap()
            .is_none()
    );
}
