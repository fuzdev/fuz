//! `role_grant_assign` in flight across a removal of either party's account,
//! against a live database.
//!
//! The rule is offer-create's: an assign writes no grant to a recipient
//! deleted or purged before it — none on the tombstone, where an undelete would
//! bring it back, and no foreign-key 500 on a purged actor — and none by a
//! caller whose own account was removed since its credential was read. The
//! handler locks both parties' account rows in one statement in id order
//! (`query_account_lock_live_many`, `FOR SHARE`) after its authority gates and
//! before it reads the recipient's actors, so the two are ordered: a removed
//! recipient answers as a missing one (404, or the actor mismatch when an
//! actor was named), a removed caller as the dead credential (401), neither
//! audited — or the removal waits for the assign to commit.
//!
//! An assign authorized before its caller is deleted, or before its caller's
//! actor is tombstoned by hand with its account left live (its context
//! resolved, then that committed), is refused; and an admin assigns to its own
//! account, one id twice in the lock statement. The lock is shown to serialize
//! in both directions against a delete of the recipient, and an assign is shown
//! to wait on a purge (a purge waits on an uncommitted assign through the
//! grant's foreign key, lock or not); the lock is replayed in both orders
//! against the writers that take one of the parties' rows: another admin's
//! removal, whose last-admin guard locks every admin's account in id order, the
//! caller's among them, and the recipient's accept, a revoke of its other
//! grant, and its own toggle — each commits on both sides.
//!
//! One mutation these tests can't see: the lock split into one statement per
//! party, which opens a lock-order cycle only against a transaction that takes
//! both rows in the opposite order between the two statements.
//!
//! Twin of `fuz_app`'s `src/test/auth/role_grant_offer_actions.assign_races.db.test.ts`.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::collections::HashSet;

use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::{GrantPath, ROLE_ADMIN, RoleSpec};
use fuz_auth::role_grant_offer_action_specs::ERROR_ROLE_GRANT_OFFER_ACTOR_ACCOUNT_MISMATCH;
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{
    AdminOfferAuthorize, RoleGrantOfferActionSpecs, RoleRegistry, SelfServiceRoleActionSpecs,
};
use fuz_db::{ActionDb, Pool};
use fuz_http::{JsonrpcError, JsonrpcErrorCode};
use serde_json::{Value, json};

mod common;
use common::{
    fresh_db, fresh_postgres_db, in_tx, race, seed_actor_context, seed_admin,
    seed_role_grant_direct,
};

/// The admin-grantable role the caller assigns.
const ROLE: &str = "race_assign_role";

/// Admin-grantable roles the recipient holds or is offered beside it.
const OTHER_ROLES: [&str; 2] = ["race_other_one", "race_other_two"];

/// The self-service-eligible role the recipient toggles.
const SELF_ROLE: &str = "race_self_role";

fn registry() -> RoleRegistry {
    RoleRegistry::new(
        std::iter::once(ROLE)
            .chain(OTHER_ROLES)
            .map(|name| RoleSpec::new(name, vec![GrantPath::Admin]))
            .collect(),
    )
    .unwrap()
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

/// A role-grant-offer verb by `auth`, on `tx`, with [`registry`]. Drains the
/// emitter's pool writes (a failure row) before it returns, so a count after
/// it sees them.
async fn offer_verb(
    pool: &Pool,
    auth: &RequestActorContext,
    method: &str,
    params: Value,
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<Value, JsonrpcError> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = common::ctx(auth, &audit, &closer);
    let result = RoleGrantOfferActionSpecs::dispatch(
        method,
        &params,
        &ctx,
        &ActionDb::Tx(tx),
        &AdminOfferAuthorize,
        &registry(),
    )
    .await;
    audit.drain_inflight().await;
    result
}

/// `role_grant_assign` of [`ROLE`] by `caller` to `recipient`, naming its actor
/// when `named`, on `tx`.
async fn assign(
    pool: &Pool,
    caller: &RequestActorContext,
    recipient: &RequestActorContext,
    named: bool,
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<Value, JsonrpcError> {
    let mut params = json!({ "to_account_id": recipient.account.id, "role": ROLE });
    if named {
        params["to_actor_id"] = json!(recipient.actor.id);
    }
    offer_verb(pool, caller, "role_grant_assign", params, tx).await
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

/// `self_service_role_set` of [`SELF_ROLE`] by `auth`, on `tx`.
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
        &json!({ "role": SELF_ROLE, "enabled": enabled }),
        &ctx,
        tx,
        &HashSet::from([SELF_ROLE.to_owned()]),
    )
    .await
}

async fn count(
    pool: &Pool,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> i64 {
    let client = pool.get().await.unwrap();
    client.query_one(sql, params).await.unwrap().get(0)
}

/// `recipient`'s unrevoked grants of [`ROLE`].
async fn active_grants(pool: &Pool, recipient: &RequestActorContext) -> i64 {
    count(
        pool,
        "SELECT COUNT(*) FROM role_grant WHERE actor_id = $1 AND role = $2 AND revoked_at IS NULL",
        &[&recipient.actor.id, &ROLE],
    )
    .await
}

/// `role_grant_create` success rows targeting `recipient`'s account.
async fn success_rows(pool: &Pool, recipient: &RequestActorContext) -> i64 {
    count(
        pool,
        "SELECT COUNT(*) FROM audit_log
         WHERE event_type = 'role_grant_create' AND outcome = 'success'
         AND target_account_id = $1",
        &[&recipient.account.id],
    )
    .await
}

/// `role_grant_create` rows of any outcome targeting `recipient`'s account —
/// a refusal here writes none, failure rows included.
async fn audit_rows(pool: &Pool, recipient: &RequestActorContext) -> i64 {
    count(
        pool,
        "SELECT COUNT(*) FROM audit_log
         WHERE event_type = 'role_grant_create' AND target_account_id = $1",
        &[&recipient.account.id],
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

/// The answer a missing recipient gets, with no actor named.
fn assert_recipient_not_found(result: Result<Value, JsonrpcError>, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(error.code, JsonrpcErrorCode::NotFound, "{label}: {error:?}");
}

/// The answer a missing recipient gets, with an actor named.
fn assert_actor_mismatch(result: Result<Value, JsonrpcError>, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(
        error.code,
        JsonrpcErrorCode::InvalidParams,
        "{label}: {error:?}"
    );
    assert_eq!(
        error.data,
        Some(json!({"reason": ERROR_ROLE_GRANT_OFFER_ACTOR_ACCOUNT_MISMATCH})),
        "{label}"
    );
}

/// Play the assign and `$other` in both orders — `$other` with `$order` bound
/// to `0`, then `1` — each waiting on the one held, both committing.
macro_rules! both_orders {
    ($pool:expr, $caller:expr, $recipient:expr, $label:expr, |$order:ident, $otx:ident| $other:expr) => {{
        let pool: &Pool = $pool;
        let label: &str = $label;
        let (assigned, other, waited) = race!(
            pool,
            first: |held| assign(pool, $caller, $recipient, false, &held),
            second: in_tx!(pool, |$otx| { let $order = 0_usize; $other })
        );
        assert_ok(&assigned, "the assign");
        assert!(waited, "{label} waits on the assign");
        assert_ok(&other, label);
        let (other, assigned, waited) = race!(
            pool,
            first: |$otx| { let $order = 1_usize; $other },
            second: in_tx!(pool, |tx| assign(pool, $caller, $recipient, false, &tx))
        );
        assert_ok(&other, label);
        assert!(waited, "the assign waits on {label}");
        assert_ok(&assigned, "the assign");
        assert_eq!(active_grants(pool, $recipient).await, 1, "the grant landed");
    }};
}

// -- authorized before the caller's removal -------------------------------------

#[tokio::test]
async fn an_assign_authorized_before_a_delete_of_its_caller_is_refused_writing_nothing() {
    let pool = fresh_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let deleted = in_tx!(pool, |tx| remove(
        &pool,
        &keeper,
        "account_delete",
        caller.account.id,
        &tx
    ));
    assert_ok(&deleted, "the delete");
    assert_unauthenticated(
        in_tx!(pool, |tx| assign(&pool, &caller, &recipient, false, &tx)),
        "the assign by the deleted admin",
    );
    assert_eq!(active_grants(&pool, &recipient).await, 0, "no grant");
    assert_eq!(success_rows(&pool, &recipient).await, 0, "no success row");
    assert_eq!(
        audit_rows(&pool, &recipient).await,
        0,
        "no audit row, failure rows included"
    );
}

#[tokio::test]
async fn an_assign_authorized_before_its_caller_actor_is_tombstoned_is_refused_writing_nothing() {
    let pool = fresh_db().await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    // the actor alone, its account left live — a state no handler produces yet
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE actor SET deleted_at = NOW() WHERE id = $1",
            &[&caller.actor.id],
        )
        .await
        .unwrap();
    drop(client);
    assert_unauthenticated(
        in_tx!(pool, |tx| assign(&pool, &caller, &recipient, false, &tx)),
        "the assign by the tombstoned actor",
    );
    assert_eq!(active_grants(&pool, &recipient).await, 0, "no grant");
    assert_eq!(success_rows(&pool, &recipient).await, 0, "no success row");
    assert_eq!(
        audit_rows(&pool, &recipient).await,
        0,
        "no audit row, failure rows included"
    );
}

#[tokio::test]
async fn an_admin_assigns_to_its_own_account_by_account_and_by_actor() {
    let pool = fresh_db().await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    // one id twice in the lock statement
    for named in [false, true] {
        assert_ok(
            &in_tx!(pool, |tx| assign(&pool, &caller, &caller, named, &tx)),
            &format!("the self-assign, actor named: {named}"),
        );
    }
    assert_eq!(
        active_grants(&pool, &caller).await,
        1,
        "one grant, on the caller"
    );
}

// -- an assign across a removal of the recipient --------------------------------

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_assign_waits_on_an_uncommitted_delete_of_its_recipient_then_404s() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let (deleted, assigned, waited) = race!(
        &pool,
        first: |held| remove(&pool, &keeper, "account_delete", recipient.account.id, &held),
        second: in_tx!(pool, |tx| assign(&pool, &caller, &recipient, false, &tx))
    );
    assert_ok(&deleted, "the delete");
    assert!(waited, "the assign waits on the tombstone");
    assert_recipient_not_found(assigned, "the assign that waited");
    assert_eq!(
        active_grants(&pool, &recipient).await,
        0,
        "no grant on the tombstone"
    );
    assert_eq!(success_rows(&pool, &recipient).await, 0, "no success row");
    assert_eq!(
        audit_rows(&pool, &recipient).await,
        0,
        "no audit row, failure rows included"
    );
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_assign_naming_an_actor_waits_on_an_uncommitted_delete_of_its_recipient_then_is_the_mismatch()
 {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let (deleted, assigned, waited) = race!(
        &pool,
        first: |held| remove(&pool, &keeper, "account_delete", recipient.account.id, &held),
        second: in_tx!(pool, |tx| assign(&pool, &caller, &recipient, true, &tx))
    );
    assert_ok(&deleted, "the delete");
    assert!(waited, "the assign waits on the tombstone");
    assert_actor_mismatch(assigned, "the assign that waited");
    assert_eq!(
        active_grants(&pool, &recipient).await,
        0,
        "no grant on the tombstone"
    );
    assert_eq!(success_rows(&pool, &recipient).await, 0, "no success row");
    assert_eq!(
        audit_rows(&pool, &recipient).await,
        0,
        "no audit row, failure rows included"
    );
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_assign_waits_on_an_uncommitted_purge_of_its_recipient_then_404s_not_500s() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let (purged, assigned, waited) = race!(
        &pool,
        first: |held| remove(&pool, &keeper, "account_purge", recipient.account.id, &held),
        second: in_tx!(pool, |tx| assign(&pool, &caller, &recipient, false, &tx))
    );
    assert_ok(&purged, "the purge");
    assert!(waited, "the assign waits on the purge");
    assert_recipient_not_found(assigned, "the assign that waited");
    assert_eq!(success_rows(&pool, &recipient).await, 0, "no success row");
    assert_eq!(
        audit_rows(&pool, &recipient).await,
        0,
        "no audit row, failure rows included"
    );
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn a_delete_of_the_recipient_waits_on_an_uncommitted_assign_which_commits_while_live() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let (assigned, deleted, waited) = race!(
        &pool,
        first: |held| assign(&pool, &caller, &recipient, false, &held),
        second: in_tx!(pool, |tx| remove(&pool, &keeper, "account_delete", recipient.account.id, &tx))
    );
    assert_ok(&assigned, "the assign");
    assert!(waited, "the delete waits on the assign's lock");
    assert_ok(&deleted, "the delete");
    assert_eq!(
        success_rows(&pool, &recipient).await,
        1,
        "one assign, while live"
    );
    assert_eq!(
        active_grants(&pool, &recipient).await,
        1,
        "the grant is kept with the tombstoned account's other grants"
    );
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn a_purge_of_the_recipient_waits_on_an_uncommitted_assign_then_removes_its_grant() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let (assigned, purged, waited) = race!(
        &pool,
        first: |held| assign(&pool, &caller, &recipient, false, &held),
        second: in_tx!(pool, |tx| remove(&pool, &keeper, "account_purge", recipient.account.id, &tx))
    );
    assert_ok(&assigned, "the assign");
    assert!(waited, "the purge waits on the assign");
    assert_ok(&purged, "the purge");
    assert_eq!(
        success_rows(&pool, &recipient).await,
        1,
        "the assign committed: its audit row, which names no foreign key, outlives the purge"
    );
    assert_eq!(
        active_grants(&pool, &recipient).await,
        0,
        "the purge removed the grant"
    );
}

// -- beside the writers of either party: no cycle -------------------------------

/// An assign and another admin's removal, whose last-admin guard locks every
/// admin's account row — the caller's among them — in id order: both commit,
/// in either order.
async fn an_assign_and_another_admins_removal_commit_in_either_order(method: &str) {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let others = [
        seed_admin_actor(&pool, "race_other_admin").await,
        seed_admin_actor(&pool, "race_third_admin").await,
    ];
    both_orders!(&pool, &caller, &recipient, method, |order, tx| remove(
        &pool,
        &keeper,
        method,
        others[order].account.id,
        &tx
    ));
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_assign_and_another_admins_delete_commit_in_either_order() {
    an_assign_and_another_admins_removal_commit_in_either_order("account_delete").await;
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_assign_and_another_admins_purge_commit_in_either_order() {
    an_assign_and_another_admins_removal_commit_in_either_order("account_purge").await;
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_assign_and_the_recipients_accept_commit_in_either_order() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let mut offer_ids = Vec::new();
    for role in OTHER_ROLES {
        let made = in_tx!(pool, |tx| offer_verb(
            &pool,
            &keeper,
            "role_grant_offer_create",
            json!({ "to_account_id": recipient.account.id, "role": role }),
            &tx
        ))
        .expect("the offer");
        offer_ids.push(made["offer"]["id"].as_str().unwrap().to_owned());
    }
    both_orders!(&pool, &caller, &recipient, "the accept", |order, tx| {
        offer_verb(
            &pool,
            &recipient,
            "role_grant_offer_accept",
            json!({ "offer_id": offer_ids[order] }),
            &tx,
        )
    });
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_assign_and_a_revoke_of_the_recipients_other_grant_commit_in_either_order() {
    let pool = fresh_postgres_db().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    let mut grant_ids = Vec::new();
    for role in OTHER_ROLES {
        grant_ids.push(seed_role_grant_direct(&pool, recipient.actor.id, role, None).await);
    }
    both_orders!(&pool, &caller, &recipient, "the revoke", |order, tx| {
        offer_verb(
            &pool,
            &keeper,
            "role_grant_revoke",
            json!({ "actor_id": recipient.actor.id, "role_grant_id": grant_ids[order] }),
            &tx,
        )
    });
}

#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_assign_and_the_recipients_own_toggle_commit_in_either_order() {
    let pool = fresh_postgres_db().await;
    let caller = seed_admin_actor(&pool, "race_caller").await;
    let recipient = seed_actor_context(&pool, "race_recipient").await;
    both_orders!(&pool, &caller, &recipient, "the toggle", |order, tx| {
        toggle(&pool, &recipient, order == 0, &tx)
    });
}
