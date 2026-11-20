//! An offer-create or an invite-create in flight while an account it names is
//! deleted — the offer's recipient, the offer's grantor, the invite's issuer —
//! against a real `PostgreSQL`.
//!
//! The rule is that nothing is left standing for a deleted account: an offer
//! pending to or from it, an invite it issued. `query_role_grant_offer_create`
//! reads both parties' account rows under `FOR SHARE`, and `invite_create` its
//! issuer's, before they insert; a delete writes its tombstone first, so the two
//! are ordered: the create is refused, or the delete supersedes the offer or
//! deletes the invite.
//!
//! A create authorized before a delete (its context resolved, then the delete
//! committed) is refused — 404 `not_found` for a deleted recipient, the dead
//! credential's 401 for a deleted grantor or issuer — and writes nothing. And
//! each lock is shown to serialize, on two connections: a create waits on an
//! uncommitted delete and is then refused, and a delete waits on an uncommitted
//! create and then ends what it wrote.
//!
//! Twin of `fuz_app`'s `src/test/auth/account_delete.races.db.test.ts`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test account_delete_races -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::time::{Duration, Instant};

use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::ROLE_ADMIN;
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{AdminOfferAuthorize, RoleGrantOfferActionSpecs, RoleRegistry};
use fuz_db::{ActionDb, Pool};
use fuz_http::{JsonrpcError, JsonrpcErrorCode};
use serde_json::{Value, json};

mod common;
use common::{
    fresh_db_pool, seed_account_actor, seed_actor_context, seed_admin, seed_role_grant_direct,
};

/// How long a blocked call is given to show it is blocked.
const HOLD: Duration = Duration::from_millis(300);

/// `auth` with an in-memory global `admin` grant — the handlers are called
/// directly, so a context carries exactly what a test hands it.
fn with_admin(mut auth: RequestActorContext) -> RequestActorContext {
    auth.role_grants.push(RoleGrantRow {
        id: uuid::Uuid::new_v4(),
        actor_id: auth.actor.id,
        role: ROLE_ADMIN.to_owned(),
        scope_id: None,
    });
    auth
}

/// The fixture's accounts: the deleter (an admin), a grantor and an issuer
/// holding `admin`, and a recipient.
struct Fixture {
    pool: Pool,
    deleter: RequestActorContext,
    grantor: RequestActorContext,
    issuer: RequestActorContext,
    recipient: uuid::Uuid,
}

async fn setup() -> Fixture {
    let pool = fresh_db_pool().await;
    let deleter = with_admin(seed_admin(&pool).await);
    let grantor = with_admin(seed_actor_context(&pool, "race_grantor").await);
    let issuer = with_admin(seed_actor_context(&pool, "race_issuer").await);
    let (recipient, _) = seed_account_actor(&pool, "race_recipient").await;
    Fixture {
        pool,
        deleter,
        grantor,
        issuer,
        recipient,
    }
}

/// `role_grant_offer_create` from `grantor` to `recipient`, on `tx`.
async fn offer(
    pool: &Pool,
    grantor: &RequestActorContext,
    recipient: uuid::Uuid,
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<Value, JsonrpcError> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = common::ctx(grantor, &audit, &closer);
    RoleGrantOfferActionSpecs::dispatch(
        "role_grant_offer_create",
        &json!({ "to_account_id": recipient, "role": ROLE_ADMIN }),
        &ctx,
        &ActionDb::Tx(tx),
        &AdminOfferAuthorize,
        &RoleRegistry::default(),
    )
    .await
}

/// An admin action by `auth`, on `tx`.
async fn admin_action(
    pool: &Pool,
    auth: &RequestActorContext,
    method: &str,
    params: &Value,
    tx: &deadpool_postgres::Transaction<'_>,
) -> Result<Value, JsonrpcError> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = common::ctx(auth, &audit, &closer);
    common::admin_dispatch(method, params, &ctx, tx).await
}

/// Run `call` in a transaction of its own, committed when it succeeds, as the
/// dispatcher does.
macro_rules! in_tx {
    ($pool:expr, |$tx:ident| $call:expr) => {{
        let mut client = $pool.get().await.unwrap();
        let $tx = client.transaction().await.unwrap();
        let result = $call.await;
        if result.is_ok() {
            $tx.commit().await.unwrap();
        }
        result
    }};
}

async fn delete(f: &Fixture, account_id: uuid::Uuid) {
    in_tx!(f.pool, |tx| admin_action(
        &f.pool,
        &f.deleter,
        "account_delete",
        &json!({ "account_id": account_id }),
        &tx
    ))
    .expect("account_delete");
}

async fn count(pool: &Pool, sql: &str, id: uuid::Uuid) -> i64 {
    let client = pool.get().await.unwrap();
    client.query_one(sql, &[&id]).await.unwrap().get(0)
}

/// Pending offers to the recipient or from the grantor.
async fn pending_offers(f: &Fixture) -> i64 {
    let client = f.pool.get().await.unwrap();
    client
        .query_one(
            "SELECT COUNT(*) FROM role_grant_offer
             WHERE (to_account_id = $1 OR from_actor_id = $2)
               AND accepted_at IS NULL AND declined_at IS NULL
               AND retracted_at IS NULL AND superseded_at IS NULL",
            &[&f.recipient, &f.grantor.actor.id],
        )
        .await
        .unwrap()
        .get(0)
}

async fn invites(f: &Fixture) -> i64 {
    count(
        &f.pool,
        "SELECT COUNT(*) FROM invite WHERE created_by = $1",
        f.issuer.actor.id,
    )
    .await
}

fn assert_recipient_not_found(result: Result<Value, JsonrpcError>, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(error.code, JsonrpcErrorCode::NotFound, "{label}");
    assert_eq!(error.data, None, "{label}");
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

/// Run `blocked` beside a holder that commits after [`HOLD`]; returns
/// `blocked`'s output and whether it finished only after the commit.
async fn race_against_commit<T>(
    blocked: impl Future<Output = T>,
    commit: impl Future<Output = ()>,
) -> (T, bool) {
    let blocked = async {
        let out = blocked.await;
        (out, Instant::now())
    };
    let commit = async {
        tokio::time::sleep(HOLD).await;
        let at = Instant::now();
        commit.await;
        at
    };
    let ((out, finished_at), committed_at) = tokio::join!(blocked, commit);
    (out, finished_at > committed_at)
}

// -- authorized before the delete ----------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_offer_create_authorized_before_its_recipient_is_deleted_is_refused() {
    let f = setup().await;
    delete(&f, f.recipient).await;
    assert_recipient_not_found(
        in_tx!(f.pool, |tx| offer(&f.pool, &f.grantor, f.recipient, &tx)),
        "the offer to the deleted recipient",
    );
    assert_eq!(pending_offers(&f).await, 0, "no pending offer");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_offer_create_authorized_before_its_grantor_is_deleted_is_refused() {
    let f = setup().await;
    delete(&f, f.grantor.account.id).await;
    assert_unauthenticated(
        in_tx!(f.pool, |tx| offer(&f.pool, &f.grantor, f.recipient, &tx)),
        "the offer from the deleted grantor",
    );
    assert_eq!(pending_offers(&f).await, 0, "no pending offer");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_invite_create_authorized_before_its_issuer_is_deleted_is_refused() {
    let f = setup().await;
    delete(&f, f.issuer.account.id).await;
    assert_unauthenticated(
        in_tx!(f.pool, |tx| admin_action(
            &f.pool,
            &f.issuer,
            "invite_create",
            &json!({ "username": "race_invitee" }),
            &tx
        )),
        "the invite from the deleted issuer",
    );
    assert_eq!(invites(&f).await, 0, "no invite row");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_invite_committed_before_its_issuer_is_deleted_is_deleted_by_it() {
    let f = setup().await;
    in_tx!(f.pool, |tx| admin_action(
        &f.pool,
        &f.issuer,
        "invite_create",
        &json!({ "username": "race_invitee" }),
        &tx
    ))
    .expect("invite_create");
    assert_eq!(invites(&f).await, 1);
    delete(&f, f.issuer.account.id).await;
    assert_eq!(invites(&f).await, 0, "the delete deleted it");
}

// -- the locks serialize -------------------------------------------------------

/// A delete of `account_id`, uncommitted on `tx`: its tombstone's row lock held.
async fn hold_a_delete(
    f: &Fixture,
    account_id: uuid::Uuid,
    tx: &deadpool_postgres::Transaction<'_>,
) {
    admin_action(
        &f.pool,
        &f.deleter,
        "account_delete",
        &json!({ "account_id": account_id }),
        tx,
    )
    .await
    .expect("account_delete");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_delete_waits_on_an_uncommitted_offer_to_the_account_and_then_supersedes_it() {
    let f = setup().await;
    let mut client = f.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    offer(&f.pool, &f.grantor, f.recipient, &tx)
        .await
        .expect("offer");
    let ((), waited) = race_against_commit(delete(&f, f.recipient), async {
        tx.commit().await.unwrap();
    })
    .await;
    assert!(waited, "the delete's tombstone waits on the offer's lock");
    assert_eq!(
        pending_offers(&f).await,
        0,
        "the delete superseded the offer"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_offer_create_waits_on_an_uncommitted_delete_of_its_recipient_and_is_then_refused() {
    let f = setup().await;
    let mut client = f.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    hold_a_delete(&f, f.recipient, &tx).await;
    let (result, waited) = race_against_commit(
        async {
            in_tx!(f.pool, |offer_tx| offer(
                &f.pool,
                &f.grantor,
                f.recipient,
                &offer_tx
            ))
        },
        async {
            tx.commit().await.unwrap();
        },
    )
    .await;
    assert!(waited, "the offer waits on the tombstone's row lock");
    assert_recipient_not_found(result, "the offer that waited");
    assert_eq!(pending_offers(&f).await, 0, "nothing pending");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_delete_waits_on_an_uncommitted_offer_from_the_account_and_then_supersedes_it() {
    let f = setup().await;
    let mut client = f.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    offer(&f.pool, &f.grantor, f.recipient, &tx)
        .await
        .expect("offer");
    let ((), waited) = race_against_commit(delete(&f, f.grantor.account.id), async {
        tx.commit().await.unwrap();
    })
    .await;
    assert!(waited, "the delete's tombstone waits on the offer's lock");
    assert_eq!(
        pending_offers(&f).await,
        0,
        "the delete superseded the offer"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_offer_create_waits_on_an_uncommitted_delete_of_its_grantor_and_is_then_refused() {
    let f = setup().await;
    let mut client = f.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    hold_a_delete(&f, f.grantor.account.id, &tx).await;
    let (result, waited) = race_against_commit(
        async {
            in_tx!(f.pool, |offer_tx| offer(
                &f.pool,
                &f.grantor,
                f.recipient,
                &offer_tx
            ))
        },
        async {
            tx.commit().await.unwrap();
        },
    )
    .await;
    assert!(waited, "the offer waits on the tombstone's row lock");
    assert_unauthenticated(result, "the offer that waited");
    assert_eq!(pending_offers(&f).await, 0, "nothing pending");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_delete_waits_on_an_uncommitted_invite_from_the_account_and_then_deletes_it() {
    let f = setup().await;
    let mut client = f.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    admin_action(
        &f.pool,
        &f.issuer,
        "invite_create",
        &json!({ "username": "race_invitee" }),
        &tx,
    )
    .await
    .expect("invite_create");
    let ((), waited) = race_against_commit(delete(&f, f.issuer.account.id), async {
        tx.commit().await.unwrap();
    })
    .await;
    assert!(waited, "the delete's tombstone waits on the invite's lock");
    assert_eq!(invites(&f).await, 0, "the delete deleted the invite");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_invite_create_waits_on_an_uncommitted_delete_of_its_issuer_and_is_then_refused() {
    let f = setup().await;
    let mut client = f.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    hold_a_delete(&f, f.issuer.account.id, &tx).await;
    let (result, waited) = race_against_commit(
        async {
            in_tx!(f.pool, |invite_tx| admin_action(
                &f.pool,
                &f.issuer,
                "invite_create",
                &json!({ "username": "race_invitee" }),
                &invite_tx
            ))
        },
        async {
            tx.commit().await.unwrap();
        },
    )
    .await;
    assert!(waited, "the invite waits on the tombstone's row lock");
    assert_unauthenticated(result, "the invite that waited");
    assert_eq!(invites(&f).await, 0, "no invite row");
}

// -- the last-admin guard --------------------------------------------------------

/// Backends waiting on a lock in this database.
async fn lock_waiters(pool: &Pool) -> i64 {
    let client = pool.get().await.unwrap();
    client
        .query_one(
            "SELECT COUNT(*) FROM pg_stat_activity
             WHERE wait_event_type = 'Lock' AND datname = current_database()",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

/// An offer between two admins and a third admin's delete never deadlock.
///
/// Another holder of the recipient's row (a login's `FOR SHARE`) makes the
/// guard of the third admin's delete stop at that row while holding the rows it
/// locked before it — the grantor's, when it reaches the grantor first. The
/// offer then runs into the guard. Locked in the guard's order, it waits holding
/// nothing the guard needs; locked one account at a time, it held the recipient
/// while waiting on the grantor — a deadlock. Run in both directions, so each
/// party is once the lower id and once the higher. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_offer_between_two_admins_and_a_third_admins_delete_never_deadlock() {
    let f = setup().await;
    // Two admins written in the reverse of their id order: an unordered guard
    // reaches them in the order they were written, so it disagrees with an
    // id-ordered offer — the case where only both orders hold.
    let mut earlier = with_admin(seed_actor_context(&f.pool, "guard_admin_0").await);
    seed_role_grant_direct(&f.pool, earlier.actor.id, ROLE_ADMIN, None).await;
    let mut pair = None;
    for i in 1..12 {
        let later = with_admin(seed_actor_context(&f.pool, &format!("guard_admin_{i}")).await);
        seed_role_grant_direct(&f.pool, later.actor.id, ROLE_ADMIN, None).await;
        if earlier.account.id > later.account.id {
            pair = Some((earlier, later));
            break;
        }
        earlier = later;
    }
    let (a, b) = pair.expect("an admin pair written against its id order");

    for (grantor, recipient, third) in [(&a, &b, "guard_third_1"), (&b, &a, "guard_third_2")] {
        let (removed, removed_actor) = seed_account_actor(&f.pool, third).await;
        seed_role_grant_direct(&f.pool, removed_actor, ROLE_ADMIN, None).await;

        let mut holder_client = f.pool.get().await.unwrap();
        let holder = holder_client.transaction().await.unwrap();
        holder
            .query_one(
                "SELECT id FROM account WHERE id = $1 FOR SHARE",
                &[&recipient.account.id],
            )
            .await
            .unwrap();

        let delete = async {
            in_tx!(f.pool, |tx| admin_action(
                &f.pool,
                &f.deleter,
                "account_delete",
                &json!({ "account_id": removed }),
                &tx
            ))
        };
        let offer_then_release = async {
            let deadline = Instant::now() + Duration::from_secs(2);
            while lock_waiters(&f.pool).await < 1 {
                assert!(
                    Instant::now() < deadline,
                    "the delete's guard waits on the held row"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let create = async {
                in_tx!(f.pool, |offer_tx| offer(
                    &f.pool,
                    grantor,
                    recipient.account.id,
                    &offer_tx
                ))
            };
            // past Postgres's `deadlock_timeout` (one second by default), so a
            // cycle would have been found and broken by now
            let release = async {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                holder.commit().await.unwrap();
            };
            let (created, ()) = tokio::join!(create, release);
            created
        };
        let (deleted, created) = tokio::join!(delete, offer_then_release);
        deleted.expect("the third admin's delete");
        created.expect("the offer");
        let pending = count(
            &f.pool,
            "SELECT COUNT(*) FROM role_grant_offer
             WHERE to_account_id = $1 AND accepted_at IS NULL AND declined_at IS NULL
               AND retracted_at IS NULL AND superseded_at IS NULL",
            recipient.account.id,
        )
        .await;
        assert_eq!(pending, 1, "the offer is pending");
    }
}
