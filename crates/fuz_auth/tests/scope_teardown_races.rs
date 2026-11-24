//! A scope's teardown against the writes that bring a grant or an offer into
//! the scope, against a real `PostgreSQL`.
//!
//! The scope lock (`query_scope_lock_shared` / `query_scope_lock_exclusive`)
//! orders them: `query_role_grant_revoke_for_scope` takes it exclusive first;
//! scoped `role_grant_offer_create` and `role_grant_assign` take it shared
//! before the consumer's `OfferCreateAuthorize` reads the scope,
//! `query_role_grant_offer_create` and `query_create_role_grant` take it shared
//! first thing, and `query_accept_offer` after its unlocked head read, before
//! any row. The predicate here reads a test scope table through the request's
//! `ActionDb`, as a consumer's scope-existence check does, and the teardown
//! played is a consumer's: the cascade, then the scope row's delete.
//!
//! - **A teardown held uncommitted** — an assign and an offer create wait on
//!   it, then read the scope gone and answer the 403
//!   `role_grant_offer_not_authorized` with its failure row, writing nothing;
//!   an accept waits on it, then finds its offer superseded.
//! - **A writer held uncommitted** — an assign, an offer create, an accept,
//!   and a direct `query_create_role_grant` or `query_role_grant_offer_create`
//!   (no handler around it): the teardown waits on it, then revokes its grant
//!   or supersedes its offer.
//! - **An accept takes the lock before its claim** — it waits on a scope lock
//!   held exclusive; the `fuz_app` twin shows the cycle an accept taking it
//!   only at its grant insert would close.
//! - **Another scope** — a teardown of one scope holds no write at another.
//! - **Shared** — an offer create at a scope answers while an assign at it is
//!   uncommitted: writers take turns with a teardown only.
//! - **No cycle** — a teardown against a delete, a purge and a revoke reaching
//!   its rows, and a scoped assign and offer create against a delete and a
//!   purge of their recipient, in both orders: the second waits, and neither
//!   fails on a deadlock.
//! - **The key** — the lock lands in `pg_locks` under the two-`int4` form with
//!   the folded key, asserted as literals; the vectors themselves are a unit
//!   test in `role_grant_offer_queries`.
//!
//! Twin of `fuz_app`'s `src/test/auth/role_grant_scope_teardown_races.db.test.ts`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test scope_teardown_races -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::time::{Duration, SystemTime};

use futures::future::BoxFuture;
use fuz_auth::actor_queries::query_create_role_grant;
use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::{GrantPath, ROLE_ADMIN, RoleSpec};
use fuz_auth::role_grant_offer_action_specs::{
    ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED, ERROR_ROLE_GRANT_OFFER_TERMINAL,
};
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{
    CreateRoleGrantOfferInput, OfferCreateAuthorize, OfferCreateAuthorizeInput,
    RevokeForScopeResult, RoleGrantOfferActionSpecs, RoleRegistry, query_role_grant_offer_create,
    query_role_grant_revoke_for_scope, query_scope_lock_exclusive,
};
use fuz_db::{ActionDb, Pool};
use fuz_http::{JsonrpcError, JsonrpcErrorCode};
use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{fresh_db_pool, in_tx, race, seed_actor_context, seed_admin, seed_role_grant_direct};

/// The admin-grantable role every scoped write here confers.
const ROLE: &str = "scope_race_role";

/// The scope kind every scoped write here names.
const SCOPE_KIND: &str = "race_scope";

fn registry() -> RoleRegistry {
    RoleRegistry::new(vec![RoleSpec::new(ROLE, vec![GrantPath::Admin])]).unwrap()
}

/// A consumer's scope-existence check: a scoped input is admitted only while
/// its scope row exists, read through the request's `ActionDb`.
struct ScopeTableAuthorize;

impl OfferCreateAuthorize for ScopeTableAuthorize {
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        input: &'a OfferCreateAuthorizeInput,
        db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>> {
        Box::pin(async move {
            let Some(scope_id) = input.scope_id else {
                return Ok(true);
            };
            let rows = db
                .query("SELECT 1 FROM scope_race_scope WHERE id = $1", &[&scope_id])
                .await
                .unwrap();
            Ok(!rows.is_empty())
        })
    }
}

/// Push an in-memory global grant of `role` onto `auth` — the handlers are
/// called directly, so a context carries exactly what a test hands it.
fn with_grant(mut auth: RequestActorContext, role: &str, id: Uuid) -> RequestActorContext {
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

/// The fixture's scope table, and a fresh live scope in it.
async fn create_scope(pool: &Pool) -> Uuid {
    let client = pool.get().await.unwrap();
    client
        .execute(
            "CREATE TABLE IF NOT EXISTS scope_race_scope (id uuid PRIMARY KEY)",
            &[],
        )
        .await
        .unwrap();
    let id = Uuid::new_v4();
    client
        .execute("INSERT INTO scope_race_scope (id) VALUES ($1)", &[&id])
        .await
        .unwrap();
    id
}

/// A role-grant-offer verb by `auth`, on `tx`, with [`registry`] and
/// [`ScopeTableAuthorize`]. Drains the emitter's pool writes (a failure row)
/// before it returns, so a count after it sees them.
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
        &ScopeTableAuthorize,
        &registry(),
    )
    .await;
    audit.drain_inflight().await;
    result
}

/// The scoped params of an assign or an offer create to `to` at `scope_id`.
fn scoped(to: &RequestActorContext, scope_id: Uuid) -> Value {
    json!({
        "to_account_id": to.account.id,
        "role": ROLE,
        "scope_kind": SCOPE_KIND,
        "scope_id": scope_id,
    })
}

/// A consumer's teardown, on `tx`: the cascade first, then the scope row.
async fn teardown(
    tx: &deadpool_postgres::Transaction<'_>,
    scope_id: Uuid,
) -> Result<RevokeForScopeResult, tokio_postgres::Error> {
    let result =
        query_role_grant_revoke_for_scope(tx, scope_id, None, Some("scope_destroyed")).await?;
    tx.execute("DELETE FROM scope_race_scope WHERE id = $1", &[&scope_id])
        .await?;
    Ok(result)
}

/// An admin action by `auth`, on `tx`: `account_delete`, or `account_purge`
/// confirmed.
async fn remove(
    pool: &Pool,
    auth: &RequestActorContext,
    method: &str,
    account_id: Uuid,
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

/// Unrevoked grants at `scope_id`.
async fn active_grants(pool: &Pool, scope_id: Uuid) -> i64 {
    count(
        pool,
        "SELECT COUNT(*) FROM role_grant WHERE scope_id = $1 AND revoked_at IS NULL",
        &[&scope_id],
    )
    .await
}

/// Pending offers at `scope_id`.
async fn pending_offers(pool: &Pool, scope_id: Uuid) -> i64 {
    count(
        pool,
        "SELECT COUNT(*) FROM role_grant_offer
         WHERE scope_id = $1 AND accepted_at IS NULL AND declined_at IS NULL
           AND retracted_at IS NULL AND superseded_at IS NULL",
        &[&scope_id],
    )
    .await
}

/// Grants and offers at `scope_id`, of any state.
async fn rows_at(pool: &Pool, scope_id: Uuid) -> i64 {
    count(
        pool,
        "SELECT (SELECT COUNT(*) FROM role_grant WHERE scope_id = $1)
              + (SELECT COUNT(*) FROM role_grant_offer WHERE scope_id = $1)",
        &[&scope_id],
    )
    .await
}

/// Audit rows of `event_type` and `outcome` naming `scope_id` in their metadata.
async fn audit_rows(pool: &Pool, event_type: &str, outcome: &str, scope_id: Uuid) -> i64 {
    count(
        pool,
        "SELECT COUNT(*) FROM audit_log
         WHERE event_type = $1 AND outcome = $2 AND metadata->>'scope_id' = $3",
        &[&event_type, &outcome, &scope_id.to_string()],
    )
    .await
}

/// A pending offer from `caller` to `recipient` at a new live scope.
async fn offer_at_new_scope(
    pool: &Pool,
    caller: &RequestActorContext,
    recipient: &RequestActorContext,
) -> (Uuid, Uuid) {
    let scope_id = create_scope(pool).await;
    let made = in_tx!(pool, |tx| offer_verb(
        pool,
        caller,
        "role_grant_offer_create",
        scoped(recipient, scope_id),
        &tx
    ))
    .expect("the offer");
    let offer_id = made["offer"]["id"].as_str().unwrap().parse().unwrap();
    (scope_id, offer_id)
}

fn assert_ok<T: std::fmt::Debug, E: std::fmt::Debug>(result: &Result<T, E>, label: &str) {
    assert!(result.is_ok(), "{label}: {result:?}");
}

/// The refusal a write authorized against a torn-down scope gets.
fn assert_not_authorized(result: Result<Value, JsonrpcError>, label: &str) {
    let error = result.expect_err(label);
    assert_eq!(
        error.code,
        JsonrpcErrorCode::Forbidden,
        "{label}: {error:?}"
    );
    assert_eq!(
        error.data,
        Some(json!({"reason": ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED})),
        "{label}"
    );
}

/// No deadlock (40P01) or other server error: a success or a client refusal.
fn assert_no_server_error(result: &Result<Value, JsonrpcError>, label: &str) {
    if let Err(error) = result {
        assert_ne!(
            error.code,
            JsonrpcErrorCode::InternalError,
            "{label}: {error:?}"
        );
    }
}

/// The fixture: the keeper removes; `caller` (a global admin) assigns and
/// offers to `recipient`.
async fn setup() -> (
    Pool,
    RequestActorContext,
    RequestActorContext,
    RequestActorContext,
) {
    let pool = fresh_db_pool().await;
    let keeper = seed_keeper(&pool).await;
    let caller = seed_admin_actor(&pool, "scope_caller").await;
    let recipient = seed_actor_context(&pool, "scope_recipient").await;
    (pool, keeper, caller, recipient)
}

// -- a teardown held: a write authorized against the scope waits, then is refused

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_assign_waits_on_an_uncommitted_teardown_then_answers_403_writing_nothing() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let scope_id = create_scope(&pool).await;
    let (torn_down, assigned, waited) = race!(
        &pool,
        first: |held| teardown(&held, scope_id),
        second: in_tx!(pool, |tx| offer_verb(&pool, &caller, "role_grant_assign", scoped(&recipient, scope_id), &tx))
    );
    assert_ok(&torn_down, "the teardown");
    assert!(waited, "the assign waits on the teardown");
    assert_not_authorized(assigned, "the assign that waited");
    assert_eq!(
        rows_at(&pool, scope_id).await,
        0,
        "no grant at the dead scope"
    );
    assert_eq!(
        audit_rows(&pool, "role_grant_create", "success", scope_id).await,
        0
    );
    assert_eq!(
        audit_rows(&pool, "role_grant_create", "failure", scope_id).await,
        1,
        "the refusal is audited"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_offer_create_waits_on_an_uncommitted_teardown_then_answers_403_writing_nothing() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let scope_id = create_scope(&pool).await;
    let (torn_down, offered, waited) = race!(
        &pool,
        first: |held| teardown(&held, scope_id),
        second: in_tx!(pool, |tx| offer_verb(&pool, &caller, "role_grant_offer_create", scoped(&recipient, scope_id), &tx))
    );
    assert_ok(&torn_down, "the teardown");
    assert!(waited, "the offer create waits on the teardown");
    assert_not_authorized(offered, "the offer create that waited");
    assert_eq!(
        rows_at(&pool, scope_id).await,
        0,
        "no offer at the dead scope"
    );
    assert_eq!(
        audit_rows(&pool, "role_grant_offer_create", "success", scope_id).await,
        0
    );
    assert_eq!(
        audit_rows(&pool, "role_grant_offer_create", "failure", scope_id).await,
        1,
        "the refusal is audited"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_accept_waits_on_an_uncommitted_teardown_then_finds_its_offer_superseded() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let (scope_id, offer_id) = offer_at_new_scope(&pool, &caller, &recipient).await;
    let (torn_down, accepted, waited) = race!(
        &pool,
        first: |held| teardown(&held, scope_id),
        second: in_tx!(pool, |tx| offer_verb(&pool, &recipient, "role_grant_offer_accept", json!({ "offer_id": offer_id }), &tx))
    );
    let torn_down = torn_down.expect("the teardown");
    assert!(waited, "the accept waits on the teardown");
    let error = accepted.expect_err("the accept is refused");
    assert_eq!(error.code, JsonrpcErrorCode::InvalidRequest, "{error:?}");
    assert_eq!(
        error.data,
        Some(json!({"reason": ERROR_ROLE_GRANT_OFFER_TERMINAL}))
    );
    assert_eq!(
        torn_down
            .superseded_offers
            .iter()
            .map(|o| o.offer.id)
            .collect::<Vec<_>>(),
        vec![offer_id]
    );
    assert_eq!(
        active_grants(&pool, scope_id).await,
        0,
        "no grant at the dead scope"
    );
}

// -- a write held: the teardown waits, then ends what it wrote -----------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_teardown_waits_on_an_uncommitted_assign_then_revokes_its_grant() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let scope_id = create_scope(&pool).await;
    let (assigned, torn_down, waited) = race!(
        &pool,
        first: |held| offer_verb(&pool, &caller, "role_grant_assign", scoped(&recipient, scope_id), &held),
        second: in_tx!(pool, |tx| teardown(&tx, scope_id))
    );
    assert_ok(&assigned, "the assign");
    assert!(waited, "the teardown waits on the assign");
    assert_eq!(torn_down.expect("the teardown").revoked.len(), 1);
    assert_eq!(active_grants(&pool, scope_id).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_teardown_waits_on_an_uncommitted_offer_create_then_supersedes_the_offer() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let scope_id = create_scope(&pool).await;
    let (offered, torn_down, waited) = race!(
        &pool,
        first: |held| offer_verb(&pool, &caller, "role_grant_offer_create", scoped(&recipient, scope_id), &held),
        second: in_tx!(pool, |tx| teardown(&tx, scope_id))
    );
    assert_ok(&offered, "the offer create");
    assert!(waited, "the teardown waits on the offer create");
    assert_eq!(torn_down.expect("the teardown").superseded_offers.len(), 1);
    assert_eq!(pending_offers(&pool, scope_id).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_teardown_waits_on_an_uncommitted_accept_then_revokes_its_grant() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let (scope_id, offer_id) = offer_at_new_scope(&pool, &caller, &recipient).await;
    let (accepted, torn_down, waited) = race!(
        &pool,
        first: |held| offer_verb(&pool, &recipient, "role_grant_offer_accept", json!({ "offer_id": offer_id }), &held),
        second: in_tx!(pool, |tx| teardown(&tx, scope_id))
    );
    assert_ok(&accepted, "the accept");
    assert!(waited, "the teardown waits on the accept");
    assert_eq!(torn_down.expect("the teardown").revoked.len(), 1);
    assert_eq!(active_grants(&pool, scope_id).await, 0);
}

// No handler around the query: the lock the query takes itself is all that
// orders it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_teardown_waits_on_an_uncommitted_direct_query_create_role_grant_then_revokes_it() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let scope_id = create_scope(&pool).await;
    let (granted, torn_down, waited) = race!(
        &pool,
        first: |held| query_create_role_grant(
            &held,
            &recipient.actor.id,
            ROLE,
            Some(SCOPE_KIND),
            Some(&scope_id),
            Some(&caller.actor.id),
            None
        ),
        second: in_tx!(pool, |tx| teardown(&tx, scope_id))
    );
    let granted = granted.expect("the grant");
    assert!(waited, "the teardown waits on the grant");
    assert_eq!(
        torn_down
            .expect("the teardown")
            .revoked
            .iter()
            .map(|g| g.role_grant_id)
            .collect::<Vec<_>>(),
        vec![granted.id]
    );
    assert_eq!(active_grants(&pool, scope_id).await, 0);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_teardown_waits_on_an_uncommitted_direct_query_role_grant_offer_create_then_supersedes_it()
 {
    let (pool, _keeper, caller, recipient) = setup().await;
    let scope_id = create_scope(&pool).await;
    let (offered, torn_down, waited) = race!(
        &pool,
        first: |held| query_role_grant_offer_create(
            &held,
            CreateRoleGrantOfferInput {
                from_actor_id: caller.actor.id,
                to_account_id: recipient.account.id,
                to_actor_id: None,
                role: ROLE.to_owned(),
                scope_kind: Some(SCOPE_KIND.to_owned()),
                scope_id: Some(scope_id),
                message: None,
                expires_at: SystemTime::now() + Duration::from_secs(60),
            }
        ),
        second: in_tx!(pool, |tx| teardown(&tx, scope_id))
    );
    let offered = offered.expect("the offer");
    assert!(waited, "the teardown waits on the offer");
    assert_eq!(
        torn_down
            .expect("the teardown")
            .superseded_offers
            .iter()
            .map(|o| o.offer.id)
            .collect::<Vec<_>>(),
        vec![offered.id]
    );
    assert_eq!(pending_offers(&pool, scope_id).await, 0);
}

// -- an accept takes the scope lock before its claim ---------------------------

// A teardown holding the scope lock and no offer yet: the accept waits at the
// lock, before it claims the offer the teardown would lock next.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_accept_waits_on_a_scope_lock_held_exclusive_before_its_claim() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let (scope_id, offer_id) = offer_at_new_scope(&pool, &caller, &recipient).await;
    let (locked, accepted, waited) = race!(
        &pool,
        first: |held| query_scope_lock_exclusive(&held, scope_id),
        second: in_tx!(pool, |tx| offer_verb(&pool, &recipient, "role_grant_offer_accept", json!({ "offer_id": offer_id }), &tx))
    );
    assert_ok(&locked, "the lock");
    assert!(waited, "the accept waits on the scope lock");
    assert_ok(&accepted, "the accept");
    assert_eq!(active_grants(&pool, scope_id).await, 1);
}

// -- a teardown of one scope holds no write at another --------------------------

async fn a_write_at_scope_b_answers_while_a_teardown_of_scope_a_is_uncommitted(method: &str) {
    let (pool, _keeper, caller, recipient) = setup().await;
    let scope_a = create_scope(&pool).await;
    let scope_b = create_scope(&pool).await;
    let (torn_down, written, waited) = race!(
        &pool,
        first: |held| teardown(&held, scope_a),
        second: in_tx!(pool, |tx| offer_verb(&pool, &caller, method, scoped(&recipient, scope_b), &tx))
    );
    assert_ok(&torn_down, "the teardown");
    assert!(!waited, "{method} at another scope does not wait");
    assert_ok(&written, method);
    assert_eq!(
        active_grants(&pool, scope_b).await + pending_offers(&pool, scope_b).await,
        1
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_assign_at_scope_b_answers_while_a_teardown_of_scope_a_is_uncommitted() {
    a_write_at_scope_b_answers_while_a_teardown_of_scope_a_is_uncommitted("role_grant_assign")
        .await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_offer_create_at_scope_b_answers_while_a_teardown_of_scope_a_is_uncommitted() {
    a_write_at_scope_b_answers_while_a_teardown_of_scope_a_is_uncommitted(
        "role_grant_offer_create",
    )
    .await;
}

// -- writers at one scope share its lock ---------------------------------------

// Shared, not exclusive: two writes into one scope take turns with a teardown
// only, never with each other.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_offer_create_answers_while_an_assign_at_the_same_scope_is_uncommitted() {
    let (pool, _keeper, caller, recipient) = setup().await;
    let scope_id = create_scope(&pool).await;
    let (assigned, offered, waited) = race!(
        &pool,
        first: |held| offer_verb(&pool, &caller, "role_grant_assign", scoped(&recipient, scope_id), &held),
        second: in_tx!(pool, |tx| offer_verb(&pool, &caller, "role_grant_offer_create", scoped(&recipient, scope_id), &tx))
    );
    assert_ok(&assigned, "the assign");
    assert!(!waited, "the offer create does not wait on the assign");
    assert_ok(&offered, "the offer create");
    assert_eq!(active_grants(&pool, scope_id).await, 1);
    assert_eq!(pending_offers(&pool, scope_id).await, 1);
}

// -- the scope lock beside the other writers: no cycle --------------------------

/// Two scopes, each holding a grant of `recipient`'s and a pending offer to it
/// — what a teardown and a removal or revoke of the recipient both reach.
/// Returns the scopes and the grants.
async fn two_scopes_reaching(
    pool: &Pool,
    caller: &RequestActorContext,
    recipient: &RequestActorContext,
) -> ([Uuid; 2], [Uuid; 2]) {
    let mut scopes = [Uuid::nil(); 2];
    let mut grants = [Uuid::nil(); 2];
    for i in 0..2 {
        let (scope_id, _) = offer_at_new_scope(pool, caller, recipient).await;
        let client = pool.get().await.unwrap();
        grants[i] = query_create_role_grant(
            &client,
            &recipient.actor.id,
            ROLE,
            Some(SCOPE_KIND),
            Some(&scope_id),
            Some(&caller.actor.id),
            None,
        )
        .await
        .unwrap()
        .id;
        scopes[i] = scope_id;
    }
    (scopes, grants)
}

async fn a_teardown_and_a_removal_of_the_recipient_commit_in_either_order(method: &str) {
    let (pool, keeper, caller, recipient) = setup().await;
    let (scopes, _) = two_scopes_reaching(&pool, &caller, &recipient).await;
    // a second recipient for the second order, the first one being gone; it
    // reaches the second scope too
    let second = seed_actor_context(&pool, "scope_recipient_two").await;
    assert_ok(
        &in_tx!(pool, |tx| offer_verb(
            &pool,
            &caller,
            "role_grant_offer_create",
            scoped(&second, scopes[1]),
            &tx
        )),
        "the offer to the second recipient",
    );
    let targets = [&recipient, &second];

    let (torn_down, removed, waited) = race!(
        &pool,
        first: |held| teardown(&held, scopes[0]),
        second: in_tx!(pool, |tx| remove(&pool, &keeper, method, targets[0].account.id, &tx))
    );
    assert_ok(&torn_down, "the teardown");
    assert!(waited, "the {method} waits on the teardown");
    assert_no_server_error(&removed, method);
    let (removed, torn_down, waited) = race!(
        &pool,
        first: |held| remove(&pool, &keeper, method, targets[1].account.id, &held),
        second: in_tx!(pool, |tx| teardown(&tx, scopes[1]))
    );
    assert_ok(&removed, method);
    assert!(waited, "the teardown waits on the {method}");
    assert_ok(&torn_down, "the teardown");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_teardown_and_a_delete_of_the_recipient_commit_in_either_order() {
    a_teardown_and_a_removal_of_the_recipient_commit_in_either_order("account_delete").await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_teardown_and_a_purge_of_the_recipient_commit_in_either_order() {
    a_teardown_and_a_removal_of_the_recipient_commit_in_either_order("account_purge").await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_teardown_and_a_revoke_of_the_recipients_grant_at_the_scope_commit_in_either_order() {
    let (pool, keeper, caller, recipient) = setup().await;
    let (scopes, grants) = two_scopes_reaching(&pool, &caller, &recipient).await;
    let revoke = |grant: Uuid| json!({ "actor_id": recipient.actor.id, "role_grant_id": grant });

    let (torn_down, revoked, waited) = race!(
        &pool,
        first: |held| teardown(&held, scopes[0]),
        second: in_tx!(pool, |tx| offer_verb(&pool, &keeper, "role_grant_revoke", revoke(grants[0]), &tx))
    );
    assert_ok(&torn_down, "the teardown");
    assert!(waited, "the revoke waits on the teardown");
    assert_no_server_error(&revoked, "the revoke");
    let (revoked, torn_down, waited) = race!(
        &pool,
        first: |held| offer_verb(&pool, &keeper, "role_grant_revoke", revoke(grants[1]), &held),
        second: in_tx!(pool, |tx| teardown(&tx, scopes[1]))
    );
    assert_ok(&revoked, "the revoke");
    assert!(waited, "the teardown waits on the revoke");
    assert_ok(&torn_down, "the teardown");
}

async fn a_scoped_write_and_a_removal_of_its_recipient_commit_in_either_order(
    write: &str,
    removal: &str,
) {
    let (pool, keeper, caller, recipient) = setup().await;
    let scope_id = create_scope(&pool).await;
    // one recipient per order, the first one being gone for the second
    let second = seed_actor_context(&pool, "scope_recipient_two").await;
    let targets = [&recipient, &second];

    let (written, removed, waited) = race!(
        &pool,
        first: |held| offer_verb(&pool, &caller, write, scoped(targets[0], scope_id), &held),
        second: in_tx!(pool, |tx| remove(&pool, &keeper, removal, targets[0].account.id, &tx))
    );
    assert_ok(&written, write);
    assert!(waited, "the {removal} waits on the {write}");
    assert_ok(&removed, removal);
    let (removed, written, waited) = race!(
        &pool,
        first: |held| remove(&pool, &keeper, removal, targets[1].account.id, &held),
        second: in_tx!(pool, |tx| offer_verb(&pool, &caller, write, scoped(targets[1], scope_id), &tx))
    );
    assert_ok(&removed, removal);
    assert!(waited, "the {write} waits on the {removal}");
    assert_no_server_error(&written, write);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scoped_assign_and_a_delete_of_its_recipient_commit_in_either_order() {
    a_scoped_write_and_a_removal_of_its_recipient_commit_in_either_order(
        "role_grant_assign",
        "account_delete",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scoped_assign_and_a_purge_of_its_recipient_commit_in_either_order() {
    a_scoped_write_and_a_removal_of_its_recipient_commit_in_either_order(
        "role_grant_assign",
        "account_purge",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scoped_offer_create_and_a_delete_of_its_recipient_commit_in_either_order() {
    a_scoped_write_and_a_removal_of_its_recipient_commit_in_either_order(
        "role_grant_offer_create",
        "account_delete",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scoped_offer_create_and_a_purge_of_its_recipient_commit_in_either_order() {
    a_scoped_write_and_a_removal_of_its_recipient_commit_in_either_order(
        "role_grant_offer_create",
        "account_purge",
    )
    .await;
}

// -- the key --------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn the_scope_lock_lands_in_pg_locks_as_the_two_int4_form_the_folded_key() {
    let pool = fresh_db_pool().await;
    let scope_id: Uuid = "019a8f2e-4b3c-7d10-9e2f-3a4b5c6d7e8f".parse().unwrap();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    query_role_grant_revoke_for_scope(&tx, scope_id, None, None)
        .await
        .unwrap();
    let rows = tx
        .query(
            "SELECT classid::text, objid::text, objsubid::int4, mode FROM pg_locks
             WHERE locktype = 'advisory' AND pid = pg_backend_pid()",
            &[],
        )
        .await
        .unwrap();
    let locks: Vec<(String, String, i32, String)> = rows
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    // literals, not the function under test: `oid` columns read the `int4`
    // halves unsigned — `fuzs` (0x66757a73) and the fold, 0x88e4b6fa
    assert_eq!(
        locks,
        vec![(
            "1718975091".to_owned(),
            "2296690426".to_owned(),
            2,
            "ExclusiveLock".to_owned(),
        )]
    );
    tx.rollback().await.unwrap();
}
