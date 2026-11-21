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
//! And the last-admin guard against an admin-offer accept: the accept holds
//! its grantor's grant and key-shares the grantor's actor, the guard locks the
//! actor and then the grant, and neither may deadlock the other. The other
//! interleaving, the removal ahead of the accept, takes the grantor's grant
//! before the offer row on both sides, so the accept waits holding nothing and
//! is refused.
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

use fuz_auth::actor_queries::query_count_active_accounts_with_global_role_locked;
use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::ROLE_ADMIN;
use fuz_auth::role_grant_offer_queries::query_role_grant_offer_supersede_outgoing;
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

/// An admin-offer accept and a removal of its grantor never deadlock.
///
/// The accept share-locks its grantor's admin grant, then inserts a grant
/// naming the grantor's actor — a foreign-key key share on it. The removal's
/// last-admin guard locks the grantor's actor, then its grant. A holder of the
/// recipient's actor stalls the accept's insert after its share lock, and the
/// guard then stalls on the grant holding the actor; released, the accept's key
/// share on the actor must not wait on the guard — a `FOR UPDATE` guard
/// deadlocks there, `FOR NO KEY UPDATE` does not. One delete, one revoke of the
/// grantor's grant, one purge. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_admin_offer_accept_and_a_removal_of_its_grantor_never_deadlock() {
    for removal in ["delete", "revoke", "purge"] {
        let f = setup().await;
        // the deleter's grant is in the database too, so the grantor is not
        // the last admin the guard counts
        seed_role_grant_direct(&f.pool, f.deleter.actor.id, ROLE_ADMIN, None).await;
        let grantor = with_admin(seed_actor_context(&f.pool, "accept_grantor").await);
        let grant_id = seed_role_grant_direct(&f.pool, grantor.actor.id, ROLE_ADMIN, None).await;
        let recipient = seed_actor_context(&f.pool, "accept_recipient").await;
        let offered = in_tx!(f.pool, |tx| offer(
            &f.pool,
            &grantor,
            recipient.account.id,
            &tx
        ))
        .expect("the admin offer");
        let offer_id = offered["offer"]["id"].as_str().unwrap().to_owned();

        let mut holder_client = f.pool.get().await.unwrap();
        let holder = holder_client.transaction().await.unwrap();
        holder
            .query_one(
                "SELECT id FROM actor WHERE id = $1 FOR UPDATE",
                &[&recipient.actor.id],
            )
            .await
            .unwrap();

        let until_waiters = |n: i64, what: &'static str| {
            let pool = f.pool.clone();
            async move {
                let deadline = Instant::now() + Duration::from_secs(2);
                while lock_waiters(&pool).await < n {
                    assert!(Instant::now() < deadline, "{what}");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        };
        let accept = async {
            in_tx!(f.pool, |tx| async {
                let audit = common::build_audit(f.pool.clone());
                let closer = common::closer();
                let ctx = common::ctx(&recipient, &audit, &closer);
                RoleGrantOfferActionSpecs::dispatch(
                    "role_grant_offer_accept",
                    &json!({ "offer_id": offer_id }),
                    &ctx,
                    &ActionDb::Tx(&tx),
                    &AdminOfferAuthorize,
                    &RoleRegistry::default(),
                )
                .await
            })
        };
        let remove_then_release = async {
            until_waiters(
                1,
                "the accept holds the grantor's grant and waits at its insert",
            )
            .await;
            let remove = async {
                match removal {
                    "delete" => in_tx!(f.pool, |tx| admin_action(
                        &f.pool,
                        &f.deleter,
                        "account_delete",
                        &json!({ "account_id": grantor.account.id }),
                        &tx
                    )),
                    "purge" => in_tx!(f.pool, |tx| admin_action(
                        &f.pool,
                        &f.deleter,
                        "account_purge",
                        &json!({ "account_id": grantor.account.id, "confirm": true }),
                        &tx
                    )),
                    _ => in_tx!(f.pool, |tx| async {
                        let audit = common::build_audit(f.pool.clone());
                        let closer = common::closer();
                        let ctx = common::ctx(&f.deleter, &audit, &closer);
                        RoleGrantOfferActionSpecs::dispatch(
                            "role_grant_revoke",
                            &json!({ "actor_id": grantor.actor.id, "role_grant_id": grant_id }),
                            &ctx,
                            &ActionDb::Tx(&tx),
                            &AdminOfferAuthorize,
                            &RoleRegistry::default(),
                        )
                        .await
                    }),
                }
            };
            let release = async {
                until_waiters(
                    2,
                    "the guard holds the grantor's actor and waits on the grant",
                )
                .await;
                holder.commit().await.unwrap();
            };
            let (removed, ()) = tokio::join!(remove, release);
            removed
        };
        let (accepted, removed) = tokio::join!(accept, remove_then_release);
        accepted.unwrap_or_else(|e| panic!("the accept ({removal}): {e:?}"));
        removed.unwrap_or_else(|e| panic!("the {removal}: {e:?}"));

        let client = f.pool.get().await.unwrap();
        let conferred: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM role_grant rg JOIN actor act ON act.id = rg.actor_id
                 WHERE act.account_id = $1 AND rg.role = $2 AND rg.revoked_at IS NULL",
                &[&recipient.account.id, &ROLE_ADMIN],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(conferred, 1, "the recipient is an admin ({removal})");
        let grantor_row = client
            .query_opt(
                "SELECT a.deleted_at IS NOT NULL,
                        (SELECT revoked_at IS NOT NULL FROM role_grant WHERE id = $2)
                 FROM account a WHERE a.id = $1",
                &[&grantor.account.id, &grant_id],
            )
            .await
            .unwrap();
        match removal {
            "purge" => assert!(grantor_row.is_none(), "the grantor is purged"),
            "delete" => assert!(
                grantor_row.unwrap().get::<_, bool>(0),
                "the grantor is deleted"
            ),
            _ => assert!(
                grantor_row.unwrap().get::<_, bool>(1),
                "the grantor's grant is revoked"
            ),
        }
    }
}

/// An admin-offer accept sent across a removal of its grantor is refused.
///
/// The other interleaving: the removal ahead. Its guard locks the grantor's
/// grant and its write runs; the accept is sent and waits; the removal then
/// ends the grantor's pending offers (a delete or revoke supersedes them, a
/// purge's cascade deletes them) and commits. The accept takes the grantor's
/// grant before it claims the offer, so it waits there holding nothing and is
/// refused once the removal commits; one that claimed the offer first would
/// hold the row the removal's supersede needs, and the two deadlock. Twin of
/// the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_admin_offer_accept_sent_across_a_removal_of_its_grantor_is_refused() {
    for removal in ["delete", "revoke", "purge"] {
        let f = setup().await;
        seed_role_grant_direct(&f.pool, f.deleter.actor.id, ROLE_ADMIN, None).await;
        let grantor = with_admin(seed_actor_context(&f.pool, "ahead_grantor").await);
        let grant_id = seed_role_grant_direct(&f.pool, grantor.actor.id, ROLE_ADMIN, None).await;
        let recipient = seed_actor_context(&f.pool, "ahead_recipient").await;
        let offered = in_tx!(f.pool, |tx| offer(
            &f.pool,
            &grantor,
            recipient.account.id,
            &tx
        ))
        .expect("the admin offer");
        let offer_id = offered["offer"]["id"].as_str().unwrap().to_owned();

        let mut removal_client = f.pool.get().await.unwrap();
        let removal_tx = removal_client.transaction().await.unwrap();
        query_count_active_accounts_with_global_role_locked(&removal_tx, ROLE_ADMIN, None)
            .await
            .unwrap();
        match removal {
            "delete" => {
                removal_tx
                    .execute(
                        "UPDATE account SET deleted_at = NOW() WHERE id = $1",
                        &[&grantor.account.id],
                    )
                    .await
                    .unwrap();
                removal_tx
                    .execute(
                        "UPDATE actor SET deleted_at = NOW() WHERE account_id = $1",
                        &[&grantor.account.id],
                    )
                    .await
                    .unwrap();
            }
            "revoke" => {
                removal_tx
                    .execute(
                        "UPDATE role_grant SET revoked_at = NOW() WHERE id = $1",
                        &[&grant_id],
                    )
                    .await
                    .unwrap();
            }
            _ => {}
        }

        let accept = async {
            in_tx!(f.pool, |tx| async {
                let audit = common::build_audit(f.pool.clone());
                let closer = common::closer();
                let ctx = common::ctx(&recipient, &audit, &closer);
                RoleGrantOfferActionSpecs::dispatch(
                    "role_grant_offer_accept",
                    &json!({ "offer_id": offer_id }),
                    &ctx,
                    &ActionDb::Tx(&tx),
                    &AdminOfferAuthorize,
                    &RoleRegistry::default(),
                )
                .await
            })
        };
        let finish = async {
            until_lock_waiters(&f.pool, 1, "the accept waits on the removal").await;
            if removal == "purge" {
                removal_tx
                    .execute("DELETE FROM account WHERE id = $1", &[&grantor.account.id])
                    .await
                    .unwrap_or_else(|e| panic!("the purge's delete: {e}"));
            } else {
                query_role_grant_offer_supersede_outgoing(&removal_tx, &[grantor.actor.id])
                    .await
                    .unwrap_or_else(|e| panic!("the {removal}'s supersede: {e}"));
            }
            removal_tx.commit().await.unwrap();
        };
        let (accepted, ()) = tokio::join!(accept, finish);
        let refused = accepted.expect_err("the accept is refused");
        assert_ne!(
            refused.code,
            JsonrpcErrorCode::InternalError,
            "the accept is refused, not failed ({removal}): {refused:?}"
        );

        let client = f.pool.get().await.unwrap();
        let conferred: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM role_grant rg JOIN actor act ON act.id = rg.actor_id
                 WHERE act.account_id = $1 AND rg.role = $2",
                &[&recipient.account.id, &ROLE_ADMIN],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(conferred, 0, "no admin grant conferred ({removal})");
    }
}

/// Wait until `n` sessions of the database wait on a lock. The deadline fails a
/// wait that never comes; it is no timing assertion, so it is set far past any
/// scheduling delay.
async fn until_lock_waiters(pool: &Pool, n: i64, what: &str) {
    let deadline = Instant::now() + LOCK_WAIT_DEADLINE;
    while lock_waiters(pool).await < n {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// How long a lock wait a test arranged may take to show, a bound on a hang only.
const LOCK_WAIT_DEADLINE: Duration = Duration::from_secs(20);
