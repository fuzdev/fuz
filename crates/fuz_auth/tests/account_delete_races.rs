//! An offer-create or an invite-create in flight while an account it names is
//! deleted — the offer's recipient, the offer's grantor, the invite's issuer —
//! against a real `PostgreSQL`.
//!
//! The rule is that nothing is left standing for a deleted account: an offer
//! pending to or from it, an invite it issued. `query_role_grant_offer_create`
//! reads both parties' account rows under `FOR SHARE`, and `query_create_invite`
//! its issuer's, before they insert; a delete writes its tombstone first, so the
//! two are ordered: the create is refused, or the delete supersedes the offer or
//! deletes the invite. The invite rule is pinned through the handler and through
//! the query called directly, as a consumer minting invites on its own path
//! calls it.
//!
//! A create authorized before a delete (its context resolved, then the delete
//! committed) is refused — 404 `not_found` for a deleted recipient, the dead
//! credential's 401 for a deleted grantor or issuer — and writes nothing. And
//! each lock is shown to serialize, on two connections: a create waits on an
//! uncommitted delete and is then refused, and a delete waits on an uncommitted
//! create and then ends what it wrote.
//!
//! And the last-admin guard against an admin-offer accept: the accept holds
//! its grantor's account row shared, the guard takes the grantor's account
//! first, and neither may deadlock the other. The other interleaving, the
//! removal ahead of the accept, takes the grantor's account before the offer
//! row on both sides, so the accept waits holding nothing the removal needs
//! and is refused.
//!
//! And the accept's own locks and the multi-row offer writes, each against a
//! transaction played over raw SQL: two sibling accepts take turns at the
//! recipient's row; an admin recipient sorting below its grantor waits on a
//! guard holding its row; a purge of a recipient whose actor granted the
//! grantor's admin never writes that grant; the expiry sweep takes its offers
//! in id order; a revoke and a scope teardown lock their offers before their
//! grants; a revoke takes its revokee's account first, and a scope teardown
//! supersedes only the offers its lock took.
//!
//! And a purge against the rows its cascade reaches, each pinned mid-cascade
//! by a third transaction holding one row of it: an admin's revoke of a grant
//! they granted, across their purge, stamps `revoked_by` without waiting on the
//! purged actor; two purges whose accounts' offers and invites cross take turns
//! at the purge lock.
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
use fuz_auth::admin_action_specs::ERROR_CANNOT_DELETE_LAST_ADMIN;
use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::ROLE_ADMIN;
use fuz_auth::role_grant_offer_queries::{
    AcceptOfferInput, RoleGrantOfferError, query_accept_offer, query_revoke_role_grant,
    query_role_grant_offer_supersede_outgoing, query_role_grant_offer_sweep_expired,
    query_role_grant_revoke_for_scope,
};
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{AdminOfferAuthorize, InviteCreateError, RoleGrantOfferActionSpecs, RoleRegistry};
use fuz_db::{ActionDb, Pool};
use fuz_http::{JsonrpcError, JsonrpcErrorCode};
use serde_json::{Value, json};

mod common;
use common::{
    LOCK_WAIT_DEADLINE, fresh_db_pool, in_tx, seed_account_actor, seed_actor_context, seed_admin,
    seed_role_grant_direct,
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

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn query_create_invite_refuses_an_issuer_deleted_before_it() {
    let f = setup().await;
    delete(&f, f.issuer.account.id).await;
    let result = in_tx!(f.pool, |tx| fuz_auth::query_create_invite(
        &tx,
        None,
        Some("race_invitee"),
        &f.issuer.actor.id
    ));
    assert!(
        matches!(result, Err(InviteCreateError::IssuerNotActive)),
        "the query refuses a deleted issuer: {result:?}"
    );
    assert_eq!(invites(&f).await, 0, "no invite row");
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

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn query_create_invite_waits_on_an_uncommitted_delete_of_its_issuer_and_is_then_refused() {
    let f = setup().await;
    let mut client = f.pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    hold_a_delete(&f, f.issuer.account.id, &tx).await;
    let (result, waited) = race_against_commit(
        async {
            in_tx!(f.pool, |invite_tx| fuz_auth::query_create_invite(
                &invite_tx,
                None,
                Some("race_invitee"),
                &f.issuer.actor.id
            ))
        },
        async {
            tx.commit().await.unwrap();
        },
    )
    .await;
    assert!(waited, "the query waits on the tombstone's row lock");
    assert!(
        matches!(result, Err(InviteCreateError::IssuerNotActive)),
        "the query that waited is refused: {result:?}"
    );
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
/// Another holder of the recipient's row (an offer create's `FOR SHARE`) makes the
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
/// The accept share-locks its grantor's account row, then inserts the grant to
/// the recipient's actor — a foreign-key key share on that actor (`actor_id`
/// keeps its foreign key; the grant's `granted_by` stamp has none). A holder of
/// the recipient's actor stalls the accept's insert after its locks, and the
/// removal's last-admin guard then stalls at the grantor's account; released,
/// the accept commits and the removal goes on. One delete, one revoke of the
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

        let until_waiters = |n: i64, what: &'static str| until_lock_waiters(&f.pool, n, what);
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
                "the accept holds the grantor's account and waits at its insert",
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
                until_waiters(2, "the guard waits on the grantor's account").await;
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
/// account, actor and grant, and its write runs; the accept is sent and waits;
/// the removal then ends the grantor's pending offers (a delete or revoke
/// supersedes them, a purge's cascade deletes them) and commits. The accept
/// takes the grantor's account before it reads the grantor's authority or
/// claims the offer, so it waits there holding nothing the removal needs and
/// is refused once the removal commits; one that claimed the offer first would
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

// -- the accept's account locks and the multi-row offer writes ------------------

/// The role the lock-order cases offer and grant.
const LOCK_ORDER_ROLE: &str = "lock_order_role";

/// `n` fresh ids, ascending — the order every multi-row offer write takes.
fn ascending_ids(n: usize) -> Vec<uuid::Uuid> {
    let mut ids: Vec<uuid::Uuid> = (0..n).map(|_| uuid::Uuid::new_v4()).collect();
    ids.sort();
    ids
}

/// Insert a pending offer, `scope_id` set or global, expired or not.
async fn insert_offer(
    pool: &Pool,
    id: uuid::Uuid,
    from_actor: uuid::Uuid,
    to_account: uuid::Uuid,
    role: &str,
    scope_id: Option<uuid::Uuid>,
    expired: bool,
) {
    let client = pool.get().await.unwrap();
    let scope_kind: Option<&str> = scope_id.map(|_| "lock_scope");
    let expiry = if expired { "-1 hour" } else { "1 day" };
    client
        .execute(
            &format!(
                "INSERT INTO role_grant_offer
                   (id, from_actor_id, to_account_id, role, scope_kind, scope_id, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '{expiry}')"
            ),
            &[&id, &from_actor, &to_account, &role, &scope_kind, &scope_id],
        )
        .await
        .unwrap();
}

/// Insert an active grant, `scope_id` set or global.
async fn insert_grant(
    pool: &Pool,
    actor: uuid::Uuid,
    role: &str,
    scope_id: Option<uuid::Uuid>,
    granted_by: Option<uuid::Uuid>,
) -> uuid::Uuid {
    let client = pool.get().await.unwrap();
    let scope_kind: Option<&str> = scope_id.map(|_| "lock_scope");
    client
        .query_one(
            "INSERT INTO role_grant (actor_id, role, scope_kind, scope_id, granted_by)
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
            &[&actor, &role, &scope_kind, &scope_id, &granted_by],
        )
        .await
        .unwrap()
        .get(0)
}

/// `(accepted, superseded)` of an offer.
async fn offer_state(pool: &Pool, id: uuid::Uuid) -> (bool, bool) {
    let client = pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT accepted_at IS NOT NULL, superseded_at IS NOT NULL
             FROM role_grant_offer WHERE id = $1",
            &[&id],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}

/// Wait until a session waits on a lock or `done` is set — the query under
/// test either waits or has finished. A bound on a hang only.
async fn until_waiting_or_done(pool: &Pool, done: &std::sync::atomic::AtomicBool) {
    let deadline = Instant::now() + LOCK_WAIT_DEADLINE;
    while !done.load(std::sync::atomic::Ordering::SeqCst) && lock_waiters(pool).await < 1 {
        assert!(
            Instant::now() < deadline,
            "the query neither waits nor finishes"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Hold `held`'s statements in a transaction, run `query` in one of its own,
/// then — once the query waits or has finished — run `then` on the held
/// transaction and commit it. Every statement is one with no parameters but
/// the ids it names, built by the caller (a `String` or a `&str`). Returns
/// the query's result.
macro_rules! against_held {
    ($pool:expr, held: [$($held:expr),* $(,)?], query: |$tx:ident| $query:expr, then: [$($then:expr),* $(,)?]) => {{
        let pool: &Pool = $pool;
        let mut holder_client = pool.get().await.unwrap();
        let holder = holder_client.transaction().await.unwrap();
        $(holder.batch_execute(AsRef::<str>::as_ref(&$held)).await.unwrap();)*
        let done = std::sync::atomic::AtomicBool::new(false);
        let run = async {
            let result = in_tx!(pool, |$tx| $query);
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            result
        };
        let finish = async {
            until_waiting_or_done(pool, &done).await;
            $(holder
                .batch_execute(AsRef::<str>::as_ref(&$then))
                .await
                .unwrap_or_else(|e| panic!("the held transaction: {e}"));)*
            holder.commit().await.unwrap();
        };
        let (result, ()) = tokio::join!(run, finish);
        result
    }};
}

/// Two sibling accepts take turns at the recipient: the second is refused.
///
/// A sibling accept played: the recipient's row shared (the weakest lock an
/// account's writer takes — an accept takes it harder), its offer claimed, its
/// grant written; once the accept under test waits, it supersedes the tested
/// one's offer. The tested offer sorts first, so an accept passing the
/// recipient's row claims it and then waits on the played offer while holding
/// the row the played supersede needs. Twin of the TS case in
/// `role_grant_offer.lock_order.db.test.ts`.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn two_sibling_accepts_take_turns_at_the_recipient() {
    let pool = fresh_db_pool().await;
    let (_, g1) = seed_account_actor(&pool, "lo_sib_g1").await;
    let (_, g2) = seed_account_actor(&pool, "lo_sib_g2").await;
    let (r_account, r_actor) = seed_account_actor(&pool, "lo_sib_r").await;
    let ids = ascending_ids(2);
    let (sent, played) = (ids[0], ids[1]);
    insert_offer(&pool, played, g1, r_account, LOCK_ORDER_ROLE, None, false).await;
    insert_offer(&pool, sent, g2, r_account, LOCK_ORDER_ROLE, None, false).await;
    let result = against_held!(
        &pool,
        held: [
            format!("SELECT id FROM account WHERE id = '{r_account}' FOR SHARE"),
            format!("SELECT id FROM role_grant_offer WHERE id = '{played}' FOR UPDATE"),
            format!(
                "WITH g AS (
                   INSERT INTO role_grant (actor_id, role, granted_by, source_offer_id)
                   VALUES ('{r_actor}', '{LOCK_ORDER_ROLE}', '{g1}', '{played}') RETURNING id
                 )
                 UPDATE role_grant_offer SET accepted_at = NOW(),
                   resulting_role_grant_id = (SELECT id FROM g) WHERE id = '{played}'"
            ),
        ],
        query: |tx| query_accept_offer(
            &tx,
            AcceptOfferInput { offer_id: sent, to_account_id: r_account, actor_id: r_actor }
        ),
        then: [format!("UPDATE role_grant_offer SET superseded_at = NOW() WHERE id = '{sent}'")]
    );
    assert!(
        matches!(result, Err(RoleGrantOfferError::AlreadyTerminal(_))),
        "the second accept is refused as terminal: {result:?}"
    );
    assert_eq!(offer_state(&pool, sent).await, (false, true));
}

/// An accept by an admin recipient whose account sorts below its grantor's
/// waits on a last-admin guard holding the recipient's row, holding neither.
///
/// The guard of a third admin's removal takes account rows in id order, the
/// recipient's before the grantor's: played, its first row, then — once the
/// accept waits — the rest of it and the write. An accept taking its two
/// accounts in id order waits at the recipient's; one taking the grantor's
/// first holds it while the guard reaches it, and the two deadlock. Twin of
/// the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_admin_recipient_sorting_below_its_grantor_waits_on_the_guard_holding_neither() {
    let pool = fresh_db_pool().await;
    let a = seed_account_actor(&pool, "lo_cyc_a").await;
    let b = seed_account_actor(&pool, "lo_cyc_b").await;
    let third = seed_account_actor(&pool, "lo_cyc_c").await;
    let (r, g) = if a.0 < b.0 { (a, b) } else { (b, a) };
    for admin in [r.1, g.1, third.1] {
        insert_grant(&pool, admin, ROLE_ADMIN, None, None).await;
    }
    let offer_id = ascending_ids(1)[0];
    insert_offer(&pool, offer_id, g.1, r.0, ROLE_ADMIN, None, false).await;
    let third_account = third.0;
    let result = against_held!(
        &pool,
        held: [format!("SELECT id FROM account WHERE id = '{}' FOR NO KEY UPDATE", r.0)],
        query: |tx| query_accept_offer(
            &tx,
            AcceptOfferInput { offer_id, to_account_id: r.0, actor_id: r.1 }
        ),
        then: [
            "SELECT a.id FROM account a
             JOIN actor act ON act.account_id = a.id
             JOIN role_grant rg ON rg.actor_id = act.id
             WHERE a.deleted_at IS NULL AND act.deleted_at IS NULL
               AND rg.role = 'admin' AND rg.scope_id IS NULL AND rg.revoked_at IS NULL
             ORDER BY a.id, act.id, rg.id
             FOR NO KEY UPDATE",
            format!("UPDATE account SET deleted_at = NOW() WHERE id = '{third_account}'"),
        ]
    );
    result.unwrap_or_else(|e| panic!("the accept: {e:?}"));
    assert_eq!(offer_state(&pool, offer_id).await, (true, false));
}

/// An accept across a purge of its recipient whose actor granted the grantor's
/// admin is refused, and the purge's cascade never waits on it.
///
/// The grantor's account sorts below the recipient's, and the grantor's admin
/// grant names the recipient's actor (`granted_by`). The purge played: its
/// account row, its offers superseded; once the accept waits — holding the
/// grantor's account — its delete. The cascade never writes the grantor's
/// grant: `granted_by` is a provenance stamp, with no foreign key, so it keeps
/// the purged actor's id. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_accept_across_a_purge_of_a_recipient_whose_actor_granted_the_grantors_admin() {
    let pool = fresh_db_pool().await;
    let a = seed_account_actor(&pool, "lo_gb_a").await;
    let b = seed_account_actor(&pool, "lo_gb_b").await;
    let (g, r) = if a.0 < b.0 { (a, b) } else { (b, a) };
    let grant = insert_grant(&pool, g.1, ROLE_ADMIN, None, Some(r.1)).await;
    let offer_id = ascending_ids(1)[0];
    insert_offer(&pool, offer_id, g.1, r.0, ROLE_ADMIN, None, false).await;
    let result = against_held!(
        &pool,
        held: [
            format!("SELECT id FROM account WHERE id = '{}' FOR UPDATE", r.0),
            format!(
                "UPDATE role_grant_offer SET superseded_at = NOW() WHERE to_account_id = '{}'",
                r.0
            ),
        ],
        query: |tx| query_accept_offer(
            &tx,
            AcceptOfferInput { offer_id, to_account_id: r.0, actor_id: r.1 }
        ),
        then: [format!("DELETE FROM account WHERE id = '{}'", r.0)]
    );
    assert!(
        matches!(result, Err(RoleGrantOfferError::RecipientNotActive)),
        "the accept by the purged recipient is refused: {result:?}"
    );
    let client = pool.get().await.unwrap();
    let granted_by: Option<uuid::Uuid> = client
        .query_one("SELECT granted_by FROM role_grant WHERE id = $1", &[&grant])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        granted_by,
        Some(r.1),
        "the cascade never writes the grantor's grant"
    );
}

/// The expiry sweep takes its offers in id order.
///
/// Seeded against id order on every plan: the higher id stored first,
/// expiring first, and first in the pending-offer index (one recipient, its
/// grantor's actor sorting first). A holder of the lower row, then the higher:
/// an id-ordered sweep waits holding neither. No spine serves the sweep over
/// the wire. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn the_expiry_sweep_takes_its_offers_in_id_order() {
    let pool = fresh_db_pool().await;
    let a = seed_account_actor(&pool, "lo_sweep_a").await;
    let b = seed_account_actor(&pool, "lo_sweep_b").await;
    let (x, _) = seed_account_actor(&pool, "lo_sweep_x").await;
    let (first, second) = if a.1 < b.1 { (a.1, b.1) } else { (b.1, a.1) };
    let ids = ascending_ids(2);
    let (low, high) = (ids[0], ids[1]);
    insert_offer(&pool, high, first, x, LOCK_ORDER_ROLE, None, true).await;
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE role_grant_offer SET expires_at = expires_at - INTERVAL '1 hour' WHERE id = $1",
            &[&high],
        )
        .await
        .unwrap();
    insert_offer(&pool, low, second, x, LOCK_ORDER_ROLE, None, true).await;
    let result = against_held!(
        &pool,
        held: [format!("SELECT id FROM role_grant_offer WHERE id = '{low}' FOR UPDATE")],
        query: |tx| query_role_grant_offer_sweep_expired(&tx),
        then: [format!("SELECT id FROM role_grant_offer WHERE id = '{high}' FOR UPDATE")]
    );
    let mut swept: Vec<uuid::Uuid> = result
        .unwrap_or_else(|e| panic!("the sweep: {e}"))
        .iter()
        .map(|o| o.id)
        .collect();
    swept.sort();
    assert_eq!(swept, vec![low, high]);
}

/// A revoke locks the offers it supersedes before it updates its grant.
///
/// An accept played: its offer claimed, then — once the revoke waits — the
/// successor grant inserted, whose unique slot is the revoked grant's. A
/// revoke that locks the offer first waits holding nothing the insert needs;
/// one that updates the grant first holds the slot the insert waits on while
/// waiting on the offer, and the two deadlock. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_revoke_locks_its_offers_before_its_grant() {
    let pool = fresh_db_pool().await;
    let (_, g) = seed_account_actor(&pool, "lo_rv_g").await;
    let (r_account, r_actor) = seed_account_actor(&pool, "lo_rv_r").await;
    let held_grant = insert_grant(&pool, r_actor, LOCK_ORDER_ROLE, None, None).await;
    let offer_id = ascending_ids(1)[0];
    insert_offer(&pool, offer_id, g, r_account, LOCK_ORDER_ROLE, None, false).await;
    let result = against_held!(
        &pool,
        held: [format!("SELECT id FROM role_grant_offer WHERE id = '{offer_id}' FOR UPDATE")],
        query: |tx| query_revoke_role_grant(&tx, held_grant, r_actor, None, None),
        then: [format!(
            "INSERT INTO role_grant (actor_id, role, granted_by, source_offer_id)
             VALUES ('{r_actor}', '{LOCK_ORDER_ROLE}', '{g}', '{offer_id}') ON CONFLICT DO NOTHING"
        )]
    );
    let revoked = result.unwrap_or_else(|e| panic!("the revoke: {e}"));
    assert!(revoked.is_some(), "the grant is revoked");
    assert_eq!(offer_state(&pool, offer_id).await, (false, true));
}

/// A scope teardown locks the offers it supersedes before it updates its
/// grants — the revoke's order, for the same reason. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scope_teardown_locks_its_offers_before_its_grants() {
    let pool = fresh_db_pool().await;
    let (_, g) = seed_account_actor(&pool, "lo_sc_g").await;
    let (r_account, r_actor) = seed_account_actor(&pool, "lo_sc_r").await;
    let scope_id = uuid::Uuid::new_v4();
    insert_grant(&pool, r_actor, LOCK_ORDER_ROLE, Some(scope_id), None).await;
    let offer_id = ascending_ids(1)[0];
    insert_offer(
        &pool,
        offer_id,
        g,
        r_account,
        LOCK_ORDER_ROLE,
        Some(scope_id),
        false,
    )
    .await;
    let result = against_held!(
        &pool,
        held: [format!("SELECT id FROM role_grant_offer WHERE id = '{offer_id}' FOR UPDATE")],
        query: |tx| query_role_grant_revoke_for_scope(&tx, scope_id, None, None),
        then: [format!(
            "INSERT INTO role_grant (actor_id, role, scope_kind, scope_id, granted_by, source_offer_id)
             VALUES ('{r_actor}', '{LOCK_ORDER_ROLE}', 'lock_scope', '{scope_id}', '{g}', '{offer_id}')
             ON CONFLICT DO NOTHING"
        )]
    );
    let torn_down = result.unwrap_or_else(|e| panic!("the teardown: {e}"));
    assert_eq!(torn_down.revoked.len(), 1);
    assert_eq!(offer_state(&pool, offer_id).await, (false, true));
}

/// A revoke takes its revokee's account before its offers.
///
/// A re-offer to the revokee played: both parties' rows shared, as an offer
/// create takes them; once the revoke waits, the upsert of the pending offer it
/// refreshes. The query takes the revokee's row first (its callers but the
/// spine's handler take no lock of their own), so it waits there and then
/// supersedes the refreshed offer; one that takes no account row supersedes it
/// before the upsert commits, which then writes a fresh pending offer after the
/// revoke. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_revoke_takes_its_revokees_account_before_its_offers() {
    let pool = fresh_db_pool().await;
    let (g_account, g) = seed_account_actor(&pool, "lo_rva_g").await;
    let (r_account, r_actor) = seed_account_actor(&pool, "lo_rva_r").await;
    let held_grant = insert_grant(&pool, r_actor, LOCK_ORDER_ROLE, None, None).await;
    let offer_id = ascending_ids(1)[0];
    insert_offer(&pool, offer_id, g, r_account, LOCK_ORDER_ROLE, None, false).await;
    let result = against_held!(
        &pool,
        held: [format!(
            "SELECT id FROM account WHERE id IN ('{g_account}', '{r_account}') ORDER BY id FOR SHARE"
        )],
        query: |tx| query_revoke_role_grant(&tx, held_grant, r_actor, None, None),
        then: [format!(
            "INSERT INTO role_grant_offer (from_actor_id, to_account_id, role, expires_at)
             VALUES ('{g}', '{r_account}', '{LOCK_ORDER_ROLE}', NOW() + INTERVAL '2 days')
             ON CONFLICT (to_account_id, role, COALESCE(scope_kind, 'GLOBAL'),
               COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid), from_actor_id)
               WHERE accepted_at IS NULL AND declined_at IS NULL
                 AND retracted_at IS NULL AND superseded_at IS NULL
             DO UPDATE SET expires_at = EXCLUDED.expires_at"
        )]
    );
    let revoked = result.unwrap_or_else(|e| panic!("the revoke: {e}"));
    assert!(revoked.is_some(), "the grant is revoked");
    let pending = count(
        &pool,
        "SELECT COUNT(*) FROM role_grant_offer
         WHERE to_account_id = $1 AND accepted_at IS NULL AND declined_at IS NULL
           AND retracted_at IS NULL AND superseded_at IS NULL",
        r_account,
    )
    .await;
    assert_eq!(pending, 0, "no offer to the revokee left pending");
}

/// A scope teardown supersedes only the offers its lock took.
///
/// A holder of the scope's grant stalls the teardown's grant update after its
/// offer lock; the holder then writes a new offer at the scope and commits. The
/// teardown supersedes the offers its lock took and leaves the new one pending:
/// nothing keeps an offer at a scope out, so an offer it didn't lock is one it
/// would take out of order. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scope_teardown_supersedes_only_the_offers_its_lock_took() {
    let pool = fresh_db_pool().await;
    let (g_account, g) = seed_account_actor(&pool, "lo_sco_g").await;
    let (r_account, r_actor) = seed_account_actor(&pool, "lo_sco_r").await;
    let scope_id = uuid::Uuid::new_v4();
    let grant = insert_grant(&pool, r_actor, LOCK_ORDER_ROLE, Some(scope_id), None).await;
    let ids = ascending_ids(2);
    let (locked, late) = (ids[0], ids[1]);
    insert_offer(
        &pool,
        locked,
        g,
        r_account,
        LOCK_ORDER_ROLE,
        Some(scope_id),
        false,
    )
    .await;
    let result = against_held!(
        &pool,
        held: [format!("SELECT id FROM role_grant WHERE id = '{grant}' FOR NO KEY UPDATE")],
        query: |tx| query_role_grant_revoke_for_scope(&tx, scope_id, None, None),
        then: [format!(
            "INSERT INTO role_grant_offer
               (id, from_actor_id, to_account_id, role, scope_kind, scope_id, expires_at)
             VALUES ('{late}', '{r_actor}', '{g_account}', '{LOCK_ORDER_ROLE}', 'lock_scope',
                     '{scope_id}', NOW() + INTERVAL '1 day')"
        )]
    );
    let torn_down = result.unwrap_or_else(|e| panic!("the teardown: {e}"));
    let superseded: Vec<uuid::Uuid> = torn_down
        .superseded_offers
        .iter()
        .map(|o| o.offer.id)
        .collect();
    assert_eq!(superseded, vec![locked]);
    assert_eq!(offer_state(&pool, late).await, (false, false));
}

// -- a purge against the rows its cascade reaches --------------------------------

/// Hold `pin` (one row the cascade reaches) in a transaction of its own, run
/// `first`, and once it waits on the pin, `second`; once `second` waits too or
/// has finished, commit the pin. Returns both results.
macro_rules! pinned {
    ($pool:expr, pin: $pin:expr, first: $first:expr, second: $second:expr) => {{
        let pool: &Pool = $pool;
        let mut pin_client = pool.get().await.unwrap();
        let pin = pin_client.transaction().await.unwrap();
        pin.batch_execute(AsRef::<str>::as_ref(&$pin))
            .await
            .unwrap();
        let second_done = std::sync::atomic::AtomicBool::new(false);
        let first = async { $first };
        let then = async {
            until_lock_waiters(pool, 1, "the first waits on the pinned row").await;
            let second = async {
                let result = $second;
                second_done.store(true, std::sync::atomic::Ordering::SeqCst);
                result
            };
            let release = async {
                let deadline = Instant::now() + LOCK_WAIT_DEADLINE;
                while !second_done.load(std::sync::atomic::Ordering::SeqCst)
                    && lock_waiters(pool).await < 2
                {
                    assert!(
                        Instant::now() < deadline,
                        "the second neither waits nor finishes"
                    );
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                pin.commit().await.unwrap();
            };
            let (second, ()) = tokio::join!(second, release);
            second
        };
        tokio::join!(first, then)
    }};
}

async fn purge(
    pool: &Pool,
    keeper: &RequestActorContext,
    account_id: uuid::Uuid,
) -> Result<Value, JsonrpcError> {
    in_tx!(pool, |tx| admin_action(
        pool,
        keeper,
        "account_purge",
        &json!({ "account_id": account_id, "confirm": true }),
        &tx
    ))
}

/// An admin's revoke of a grant they granted, across their purge: both commit.
///
/// The admin's own grant pinned, so the purge waits in its cascade, past its
/// delete of the admin's actor; the revoke, authorized before the purge, then
/// writes the grant it revokes and stamps `revoked_by` with the admin's actor.
/// With a foreign key on the stamp, the write waited on the deleted actor while
/// holding the grant, whose `granted_by` the cascade then set null: a deadlock.
/// The stamp has none, so the revoke commits, the purge's cascade never writes
/// the grant, and the stamps keep the purged actor's id. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_admins_revoke_of_a_grant_they_granted_across_their_purge_both_commit() {
    let pool = fresh_db_pool().await;
    let keeper = with_admin(seed_admin(&pool).await);
    seed_role_grant_direct(&pool, keeper.actor.id, ROLE_ADMIN, None).await;
    let admin = seed_actor_context(&pool, "purged_admin").await;
    seed_role_grant_direct(&pool, admin.actor.id, ROLE_ADMIN, None).await;
    let own = insert_grant(&pool, admin.actor.id, LOCK_ORDER_ROLE, None, None).await;
    let (_, grantee) = seed_account_actor(&pool, "purged_admins_grantee").await;
    let granted = insert_grant(&pool, grantee, LOCK_ORDER_ROLE, None, Some(admin.actor.id)).await;

    let (purged, revoked) = pinned!(
        &pool,
        pin: format!("SELECT id FROM role_grant WHERE id = '{own}' FOR UPDATE"),
        first: purge(&pool, &keeper, admin.account.id).await,
        second: in_tx!(pool, |tx| query_revoke_role_grant(
            &tx,
            granted,
            grantee,
            Some(admin.actor.id),
            None
        ))
    );
    purged.expect("the purge");
    let revoked = revoked.expect("the revoke");
    assert!(revoked.is_some(), "the revoke found the grant");

    let client = pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT granted_by, revoked_by, revoked_at IS NOT NULL FROM role_grant WHERE id = $1",
            &[&granted],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, Option<uuid::Uuid>>(0),
        Some(admin.actor.id),
        "granted_by kept"
    );
    assert_eq!(
        row.get::<_, Option<uuid::Uuid>>(1),
        Some(admin.actor.id),
        "revoked_by stamped"
    );
    assert!(row.get::<_, bool>(2), "the grant is revoked");
    let left: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM account WHERE id = $1",
            &[&admin.account.id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, 0, "the admin is purged");
}

/// Two purges whose accounts' rows cross — offers each made the other,
/// accepted or declined, and invites each issued and the other claimed — take
/// turns: both commit.
///
/// A third transaction pins the offer or invite of the account purged second,
/// so the first purge waits in its cascade; the second is sent. Each cascade
/// deletes its own account's offers and invites and its counterpart's, in its
/// plan's order, and with no lock ahead of them the two met in opposite orders
/// and deadlocked. Every purge first takes the advisory lock only purges take,
/// so the second waits there holding nothing. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn two_purges_whose_accounts_rows_cross_both_commit() {
    for shape in ["accepted", "declined", "invites"] {
        let pool = fresh_db_pool().await;
        let keeper = with_admin(seed_admin(&pool).await);
        seed_role_grant_direct(&pool, keeper.actor.id, ROLE_ADMIN, None).await;
        let x = seed_account_actor(&pool, "crossed_x").await;
        let z = seed_account_actor(&pool, "crossed_z").await;
        let ids = ascending_ids(2);
        let (from_x, from_z) = (ids[0], ids[1]);
        let client = pool.get().await.unwrap();
        let pin = if shape == "invites" {
            for (id, issuer, claimer, name) in [
                (from_x, x.1, z.0, "crossed_iz"),
                (from_z, z.1, x.0, "crossed_ix"),
            ] {
                client
                    .execute(
                        "INSERT INTO invite (id, username, created_by, claimed_by, claimed_at)
                         VALUES ($1, $2, $3, $4, NOW())",
                        &[&id, &name, &issuer, &claimer],
                    )
                    .await
                    .unwrap();
            }
            format!("SELECT id FROM invite WHERE id = '{from_x}' FOR UPDATE")
        } else {
            for (id, from, to) in [(from_x, x.1, z), (from_z, z.1, x)] {
                insert_offer(&pool, id, from, to.0, LOCK_ORDER_ROLE, None, false).await;
                if shape == "accepted" {
                    client
                        .execute(
                            "INSERT INTO role_grant (id, actor_id, role, granted_by, source_offer_id)
                             VALUES ($1, $2, $3, $4, $1)",
                            &[&id, &to.1, &LOCK_ORDER_ROLE, &from],
                        )
                        .await
                        .unwrap();
                    client
                        .execute(
                            "UPDATE role_grant_offer SET accepted_at = NOW(), resulting_role_grant_id = $1
                             WHERE id = $1",
                            &[&id],
                        )
                        .await
                        .unwrap();
                } else {
                    client
                        .execute(
                            "UPDATE role_grant_offer SET declined_at = NOW() WHERE id = $1",
                            &[&id],
                        )
                        .await
                        .unwrap();
                }
            }
            format!("SELECT id FROM role_grant_offer WHERE id = '{from_x}' FOR UPDATE")
        };
        drop(client);

        let (first, second) = pinned!(
            &pool,
            pin: pin,
            first: purge(&pool, &keeper, z.0).await,
            second: purge(&pool, &keeper, x.0).await
        );
        first.unwrap_or_else(|e| panic!("the first purge ({shape}): {e:?}"));
        second.unwrap_or_else(|e| panic!("the second purge ({shape}): {e:?}"));
        let left = count(
            &pool,
            "SELECT COUNT(*) FROM account WHERE id = $1 OR username = 'crossed_x'",
            z.0,
        )
        .await;
        assert_eq!(left, 0, "both purged ({shape})");
    }
}

/// Remove `target_account` by `method` (`account_purge` or `account_delete`)
/// while a held transaction makes it the last admin: an accept making it an
/// admin (its account row held, as an accept holds its recipient's) and the
/// revoke of every other admin that the guard of the revoke allowed, counting
/// the target. The removal's guard reads a non-admin unlocked and waits at the
/// target's row — the purge's `query_account_lock_for_purge`, the delete's
/// `query_account_lock_live` — then resumes on the commit with the target the
/// last admin: its guard runs again under the row lock and refuses.
async fn a_removal_whose_target_turns_the_last_admin_is_refused(method: &str) {
    let pool = fresh_db_pool().await;
    let keeper = with_admin(seed_admin(&pool).await);
    seed_role_grant_direct(&pool, keeper.actor.id, ROLE_ADMIN, None).await;
    let (target_account, target_actor) = seed_account_actor(&pool, "turned_admin").await;

    let mut held_client = pool.get().await.unwrap();
    let held = held_client.transaction().await.unwrap();
    held.execute(
        "SELECT id FROM account WHERE id = $1 FOR NO KEY UPDATE",
        &[&target_account],
    )
    .await
    .unwrap();
    held.execute(
        "INSERT INTO role_grant (actor_id, role) VALUES ($1, $2)",
        &[&target_actor, &ROLE_ADMIN],
    )
    .await
    .unwrap();
    held.execute(
        "UPDATE role_grant SET revoked_at = NOW()
         WHERE role = $1 AND scope_id IS NULL AND revoked_at IS NULL AND actor_id <> $2",
        &[&ROLE_ADMIN, &target_actor],
    )
    .await
    .unwrap();
    let release = async {
        until_lock_waiters(&pool, 1, "the removal waits at its target's row").await;
        held.commit().await.unwrap();
    };
    let params = if method == "account_purge" {
        json!({ "account_id": target_account, "confirm": true })
    } else {
        json!({ "account_id": target_account })
    };
    let remove = async {
        in_tx!(pool, |tx| admin_action(
            &pool, &keeper, method, &params, &tx
        ))
    };
    let (removed, ()) = tokio::join!(remove, release);

    let err = removed.expect_err("the removal is refused");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden, "{method}");
    assert_eq!(
        err.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str),
        Some(ERROR_CANNOT_DELETE_LAST_ADMIN),
        "{method}"
    );
    let admins = count(
        &pool,
        "SELECT COUNT(*) FROM role_grant rg JOIN actor act ON act.id = rg.actor_id
         JOIN account a ON a.id = act.account_id
         WHERE rg.role = 'admin' AND rg.scope_id IS NULL AND rg.revoked_at IS NULL
           AND a.deleted_at IS NULL AND a.id = $1",
        target_account,
    )
    .await;
    assert_eq!(admins, 1, "the last admin stands ({method})");
}

/// A purge whose target turns the last admin while it waits at its row is
/// refused. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_purge_whose_target_turns_the_last_admin_while_it_waits_at_its_row_is_refused() {
    a_removal_whose_target_turns_the_last_admin_is_refused("account_purge").await;
}

/// A delete whose target turns the last admin while it waits at its row is
/// refused. Twin of the TS case.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_delete_whose_target_turns_the_last_admin_while_it_waits_at_its_row_is_refused() {
    a_removal_whose_target_turns_the_last_admin_is_refused("account_delete").await;
}
