//! `self_service_role_set` in flight across a removal of the caller's account,
//! against a live database.
//!
//! The rule is the dead credential's: a toggle authorized before its account is
//! deleted or purged writes nothing after it — no grant enabled or revoked on
//! the tombstone (where an undelete would bring it back), no success row, and
//! no foreign-key 500 on a purged actor. The handler takes the caller's account
//! row first (`query_account_lock_live`), the row a delete's tombstone and a
//! purge's `DELETE` write, so the two are ordered: the toggle is refused with
//! the dead credential's 401, or the removal waits for it to commit.
//!
//! A toggle authorized before a removal (its context resolved, then the
//! removal committed) is refused. The lock is shown to serialize in both
//! directions, and replayed against the writers that take the caller's row
//! beside other rows — another admin's removal, whose last-admin guard locks
//! every admin's account in id order, and an admin-offer accept that
//! share-locks the caller as its grantor: each commits on both sides, in both
//! orders.
//!
//! Twin of `fuz_app`'s `src/test/auth/self_service_role_actions.races.db.test.ts`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::collections::HashSet;

use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::ROLE_ADMIN;
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{
    AdminOfferAuthorize, RoleGrantOfferActionSpecs, RoleRegistry, SelfServiceRoleActionSpecs,
};
use fuz_db::{ActionDb, Pool};
use fuz_http::{JsonrpcError, JsonrpcErrorCode};
use fuz_testing::{in_tx, race};
use serde_json::{Value, json};

mod common;
use common::{fresh_db, fresh_postgres_db, seed_actor_context, seed_admin, seed_role_grant_direct};

/// The self-service-eligible role the caller toggles.
const ROLE: &str = "race_self_role";

fn eligible() -> HashSet<String> {
    HashSet::from([ROLE.to_owned()])
}

/// Push an in-memory global grant of `role` with `id` onto `auth` — the
/// handlers are called directly, so a context carries exactly what a test
/// hands it.
fn with_grant(mut auth: RequestActorContext, role: &str, id: uuid::Uuid) -> RequestActorContext {
    auth.role_grants.push(RoleGrantRow {
        id,
        actor_id: auth.actor.id,
        role: role.to_owned(),
        scope_id: None,
    });
    auth
}

/// An account holding the global `admin` grant, in the database and in hand.
async fn seed_admin_actor(pool: &Pool, username: &str) -> RequestActorContext {
    let auth = seed_actor_context(pool, username).await;
    let id = seed_role_grant_direct(pool, auth.actor.id, ROLE_ADMIN, None).await;
    with_grant(auth, ROLE_ADMIN, id)
}

/// The keeper: an admin, in the database too, so no removal here meets the
/// last-admin refusal.
async fn seed_keeper(pool: &Pool) -> RequestActorContext {
    let keeper = seed_admin(pool).await;
    let id = seed_role_grant_direct(pool, keeper.actor.id, ROLE_ADMIN, None).await;
    with_grant(keeper, ROLE_ADMIN, id)
}

/// `self_service_role_set` by `auth`, on `tx`.
async fn toggle(
    pool: &Pool,
    auth: &RequestActorContext,
    enabled: bool,
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<Value, JsonrpcError> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = common::ctx(auth, &audit, &closer);
    SelfServiceRoleActionSpecs::dispatch(
        "self_service_role_set",
        &json!({ "role": ROLE, "enabled": enabled }),
        &ctx,
        tx,
        &eligible(),
    )
    .await
}

/// An admin action by `auth`, on `tx`: `account_delete`, or `account_purge`
/// confirmed.
async fn remove(
    pool: &Pool,
    auth: &RequestActorContext,
    method: &str,
    account_id: uuid::Uuid,
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<Value, JsonrpcError> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = common::ctx(auth, &audit, &closer);
    let params = if method == "account_purge" {
        json!({ "account_id": account_id, "confirm": true })
    } else {
        json!({ "account_id": account_id })
    };
    common::admin_dispatch(method, &params, &ctx, tx).await
}

async fn count(
    pool: &Pool,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> i64 {
    let client = pool.get().await.unwrap();
    client.query_one(sql, params).await.unwrap().get(0)
}

/// `auth`'s unrevoked grants of [`ROLE`].
async fn active_grants(pool: &Pool, auth: &RequestActorContext) -> i64 {
    count(
        pool,
        "SELECT COUNT(*) FROM role_grant WHERE actor_id = $1 AND role = $2 AND revoked_at IS NULL",
        &[&auth.actor.id, &ROLE],
    )
    .await
}

/// Success rows of `event_type` naming `auth`'s account.
async fn success_rows(pool: &Pool, auth: &RequestActorContext, event_type: &str) -> i64 {
    count(
        pool,
        "SELECT COUNT(*) FROM audit_log
         WHERE event_type = $1 AND outcome = 'success' AND account_id = $2",
        &[&event_type, &auth.account.id],
    )
    .await
}

fn assert_ok(result: &Result<Value, JsonrpcError>, label: &str) {
    assert!(result.is_ok(), "{label}: {result:?}");
}

fn assert_unauthenticated(result: Result<Value, JsonrpcError>, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(error.code, JsonrpcErrorCode::Unauthenticated, "{label}");
    assert_eq!(
        error.data,
        Some(json!({"reason": "authentication_required"})),
        "{label}: the 401 a dead credential gets"
    );
}

// -- authorized before the removal ---------------------------------------------

#[tokio::test]
async fn an_enable_authorized_before_a_delete_is_refused_writing_nothing() {
    let pool = fresh_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_actor_context(&pool, "race_caller").await;
    let deleted = in_tx!(pool, |tx| remove(
        &pool,
        &keeper,
        "account_delete",
        caller.account.id,
        &tx
    ));
    assert_ok(&deleted, "the delete");
    assert_unauthenticated(
        in_tx!(pool, |tx| toggle(&pool, &caller, true, &tx)),
        "the enable on the tombstone",
    );
    assert_eq!(
        active_grants(&pool, &caller).await,
        0,
        "no grant on the tombstone"
    );
    assert_eq!(
        success_rows(&pool, &caller, "role_grant_create").await,
        0,
        "no success row"
    );
}

#[tokio::test]
async fn a_disable_authorized_before_a_delete_is_refused_revoking_nothing() {
    let pool = fresh_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_actor_context(&pool, "race_caller").await;
    let grant = seed_role_grant_direct(&pool, caller.actor.id, ROLE, None).await;
    let caller = with_grant(caller, ROLE, grant);
    let deleted = in_tx!(pool, |tx| remove(
        &pool,
        &keeper,
        "account_delete",
        caller.account.id,
        &tx
    ));
    assert_ok(&deleted, "the delete");
    assert_unauthenticated(
        in_tx!(pool, |tx| toggle(&pool, &caller, false, &tx)),
        "the disable on the tombstone",
    );
    assert_eq!(
        active_grants(&pool, &caller).await,
        1,
        "the grant is as the delete left it"
    );
    assert_eq!(
        success_rows(&pool, &caller, "role_grant_revoke").await,
        0,
        "no success row"
    );
}

#[tokio::test]
async fn an_enable_authorized_before_a_purge_is_refused_writing_nothing() {
    let pool = fresh_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_actor_context(&pool, "race_caller").await;
    let purged = in_tx!(pool, |tx| remove(
        &pool,
        &keeper,
        "account_purge",
        caller.account.id,
        &tx
    ));
    assert_ok(&purged, "the purge");
    assert_unauthenticated(
        in_tx!(pool, |tx| toggle(&pool, &caller, true, &tx)),
        "the enable on the purged account",
    );
    assert_eq!(
        success_rows(&pool, &caller, "role_grant_create").await,
        0,
        "no success row"
    );
}

// -- the account lock serializes ------------------------------------------------

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_enable_waits_on_an_uncommitted_delete_of_its_account_and_is_then_refused() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_actor_context(&pool, "race_caller").await;
    let (deleted, toggled, waited) = race!(
        &pool,
        first: |held| remove(&pool, &keeper, "account_delete", caller.account.id, &held),
        second: in_tx!(pool, |tx| toggle(&pool, &caller, true, &tx))
    );
    assert_ok(&deleted, "the delete");
    assert!(waited, "the enable waits on the tombstone");
    assert_unauthenticated(toggled, "the enable that waited");
    assert_eq!(
        active_grants(&pool, &caller).await,
        0,
        "no grant on the tombstone"
    );
    assert_eq!(
        success_rows(&pool, &caller, "role_grant_create").await,
        0,
        "no success row"
    );
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn a_disable_waits_on_an_uncommitted_delete_of_its_account_and_is_then_refused() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_actor_context(&pool, "race_caller").await;
    let grant = seed_role_grant_direct(&pool, caller.actor.id, ROLE, None).await;
    let caller = with_grant(caller, ROLE, grant);
    let (deleted, toggled, waited) = race!(
        &pool,
        first: |held| remove(&pool, &keeper, "account_delete", caller.account.id, &held),
        second: in_tx!(pool, |tx| toggle(&pool, &caller, false, &tx))
    );
    assert_ok(&deleted, "the delete");
    assert!(waited, "the disable waits on the tombstone");
    assert_unauthenticated(toggled, "the disable that waited");
    assert_eq!(
        active_grants(&pool, &caller).await,
        1,
        "the grant is as the delete left it"
    );
    assert_eq!(
        success_rows(&pool, &caller, "role_grant_revoke").await,
        0,
        "no success row"
    );
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn a_delete_waits_on_an_uncommitted_enable_which_commits_on_the_live_account() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_actor_context(&pool, "race_caller").await;
    let (toggled, deleted, waited) = race!(
        &pool,
        first: |held| toggle(&pool, &caller, true, &held),
        second: in_tx!(pool, |tx| remove(&pool, &keeper, "account_delete", caller.account.id, &tx))
    );
    assert_ok(&toggled, "the enable");
    assert!(waited, "the delete waits on the enable's account lock");
    assert_ok(&deleted, "the delete");
    assert_eq!(
        success_rows(&pool, &caller, "role_grant_create").await,
        1,
        "one enable, while live"
    );
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn a_purge_waits_on_an_uncommitted_enable_then_removes_its_grant_with_the_account() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_actor_context(&pool, "race_caller").await;
    let (toggled, purged, waited) = race!(
        &pool,
        first: |held| toggle(&pool, &caller, true, &held),
        second: in_tx!(pool, |tx| remove(&pool, &keeper, "account_purge", caller.account.id, &tx))
    );
    assert_ok(&toggled, "the enable");
    assert!(waited, "the purge waits on the enable's account lock");
    assert_ok(&purged, "the purge");
    assert_eq!(
        active_grants(&pool, &caller).await,
        0,
        "the purge removed the grant"
    );
}

// -- the writers that lock the caller's row beside others -----------------------

/// An admin caller's enable and another admin's removal, whose last-admin guard
/// locks every admin's account row — the caller's among them — in id order:
/// both commit, the enable first and then the removal first.
async fn an_admins_enable_and_another_admins_removal_commit_in_either_order(method: &str) {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let other = seed_admin_actor(&pool, "race_other_admin").await;
    let (toggled, removed, waited) = race!(
        &pool,
        first: |held| toggle(&pool, &caller, true, &held),
        second: in_tx!(pool, |tx| remove(&pool, &keeper, method, other.account.id, &tx))
    );
    assert_ok(&toggled, "the enable");
    assert!(waited, "{method}: the guard waits on the caller's row");
    assert_ok(&removed, method);

    // the other order, against a third admin's removal; the caller's context
    // holds no grant of the role, so its enable writes again once disabled
    let third = seed_admin_actor(&pool, "race_third_admin").await;
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE role_grant SET revoked_at = NOW() WHERE actor_id = $1 AND role = $2",
            &[&caller.actor.id, &ROLE],
        )
        .await
        .unwrap();
    drop(client);
    let (removed, toggled, waited) = race!(
        &pool,
        first: |held| remove(&pool, &keeper, method, third.account.id, &held),
        second: in_tx!(pool, |tx| toggle(&pool, &caller, true, &tx))
    );
    assert_ok(&removed, method);
    assert!(
        waited,
        "{method}: the enable waits on the guard's lock on its row"
    );
    assert_ok(&toggled, "the enable");
    assert_eq!(active_grants(&pool, &caller).await, 1, "the enable landed");
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_admins_enable_and_another_admins_delete_commit_in_either_order() {
    an_admins_enable_and_another_admins_removal_commit_in_either_order("account_delete").await;
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_admins_enable_and_another_admins_purge_commit_in_either_order() {
    an_admins_enable_and_another_admins_removal_commit_in_either_order("account_purge").await;
}

/// `role_grant_offer_accept` of `offer_id` by `recipient`, on `tx`.
async fn accept(
    pool: &Pool,
    recipient: &RequestActorContext,
    offer_id: &str,
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<Value, JsonrpcError> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = common::ctx(recipient, &audit, &closer);
    RoleGrantOfferActionSpecs::dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": offer_id }),
        &ctx,
        &ActionDb::Tx(tx),
        &AdminOfferAuthorize,
        &RoleRegistry::default(),
    )
    .await
}

/// An admin caller's enable and an accept of an admin offer the caller made,
/// which share-locks the caller's row as its grantor's: both commit, the
/// enable first and then the accept first.
#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_admins_enable_and_an_accept_of_the_admin_offer_it_made_commit_in_either_order() {
    let pool = fresh_postgres_db().await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let offer = || async {
        let made = in_tx!(pool, |tx| async {
            let audit = common::build_audit(pool.clone());
            let closer = common::closer();
            let ctx = common::ctx(&caller, &audit, &closer);
            RoleGrantOfferActionSpecs::dispatch(
                "role_grant_offer_create",
                &json!({ "to_account_id": recipient.account.id, "role": ROLE_ADMIN }),
                &ctx,
                &ActionDb::Tx(&tx),
                &AdminOfferAuthorize,
                &RoleRegistry::default(),
            )
            .await
        })
        .expect("the offer");
        made["offer"]["id"].as_str().unwrap().to_owned()
    };
    let first_offer = offer().await;
    let (toggled, accepted, waited) = race!(
        &pool,
        first: |held| toggle(&pool, &caller, true, &held),
        second: in_tx!(pool, |tx| accept(&pool, &recipient, &first_offer, &tx))
    );
    assert_ok(&toggled, "the enable");
    assert!(waited, "the accept waits on its grantor's row");
    assert_ok(&accepted, "the accept");

    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE role_grant SET revoked_at = NOW() WHERE actor_id = $1 AND role = $2",
            &[&caller.actor.id, &ROLE],
        )
        .await
        .unwrap();
    drop(client);
    let second_offer = offer().await;
    let (accepted, toggled, waited) = race!(
        &pool,
        first: |held| accept(&pool, &recipient, &second_offer, &held),
        second: in_tx!(pool, |tx| toggle(&pool, &caller, true, &tx))
    );
    assert_ok(&accepted, "the accept");
    assert!(waited, "the enable waits on the accept's share lock");
    assert_ok(&toggled, "the enable");
}
