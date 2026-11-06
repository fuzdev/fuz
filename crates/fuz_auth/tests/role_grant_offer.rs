//! Integration tests for `query_role_grant_offer_create` and
//! `query_accept_offer` against a real `PostgreSQL`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test role_grant_offer -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required because every test drops + recreates
//! the shared schema; parallel runs race on the `schema_version` table.
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

use std::time::{Duration, SystemTime};

use futures::future::BoxFuture;
use fuz_auth::actor_queries::query_create_role_grant;
use fuz_auth::request_context::RequestActorContext;
use fuz_auth::role::{GrantPath, RoleSpec};
use fuz_auth::role_grant_offer_action_specs::{
    ERROR_ROLE_GRANT_BUILTIN_SCOPED, ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED,
    ERROR_ROLE_GRANT_OFFER_NOT_FOUND, ERROR_ROLE_GRANT_OFFER_ROLE_NOT_GRANTABLE,
    ERROR_ROLE_GRANT_OFFER_TERMINAL, ERROR_ROLE_NOT_WEB_GRANTABLE,
};
use fuz_auth::role_grant_schema::RoleGrantRow;
use fuz_auth::{
    AcceptOfferInput, AdminOfferAuthorize, AuditEmitter, AuthenticatedActionContext,
    BuiltinOfferRefusal, CreateRoleGrantOfferInput, OfferCreateAuthorize,
    OfferCreateAuthorizeInput, ROLE_ADMIN, RoleGrantOfferActionSpecs, RoleGrantOfferError,
    RoleRegistry, default_expiry_from_now, query_accept_offer, query_role_grant_offer_create,
};
use fuz_db::ActionDb;
use fuz_http::{JsonrpcError, JsonrpcErrorCode};
use serde_json::{Value, json};
mod common;
use common::{
    build_audit, closer, ctx, fresh_db_pool, seed_account_actor, seed_actor_context, seed_admin,
    seed_extra_actor, seed_role_grant_direct,
};

/// Dispatch an offer verb with the builtin registry and the default
/// admin-only create predicate.
///
/// The lifecycle verbs (`_decline` / `_retract`) ignore the `authorize`
/// argument entirely — it gates `_create` only — so the seam keeps the
/// terminal-state cases down to the one line each of them is.
async fn offer_dispatch(
    method: &str,
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: ActionDb<'_>,
) -> Result<Value, JsonrpcError> {
    RoleGrantOfferActionSpecs::dispatch(
        method,
        params,
        ctx,
        &db,
        &AdminOfferAuthorize,
        &RoleRegistry::default(),
    )
    .await
}

/// Give a seeded context an in-memory active grant of `role` at `scope`.
///
/// The handler-level suites dispatch directly (no dispatcher role gate), so a
/// context carries exactly the grants a test hands it — `role_grant_assign`
/// re-checks the **global** admin grant in-handler, and the list/history
/// verbs gate cross-account reads on it.
fn with_grant(
    mut auth: RequestActorContext,
    role: &str,
    scope: Option<uuid::Uuid>,
) -> RequestActorContext {
    auth.role_grants.push(RoleGrantRow {
        id: uuid::Uuid::new_v4(),
        actor_id: auth.actor.id,
        role: role.to_owned(),
        scope_id: scope,
    });
    auth
}

/// An offer-create predicate that admits everything — proves a refusal
/// happens in the spine, ahead of any consumer authorizer.
struct AdmitAll;

impl OfferCreateAuthorize for AdmitAll {
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        _input: &'a OfferCreateAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>> {
        Box::pin(async { Ok(true) })
    }
}

/// A consumer registry with one admin-grantable app role, the shape a
/// classroom- or space-scoped consumer declares.
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
fn app_registry() -> RoleRegistry {
    RoleRegistry::new(vec![RoleSpec::new("teacher", vec![GrantPath::Admin])])
        .expect("valid registry")
}

/// The machine-readable `error.data.reason`.
fn reason(err: &JsonrpcError) -> &str {
    err.data
        .as_ref()
        .and_then(|d| d.get("reason"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// The `metadata.reason` of the failed `role_grant_offer_accept` audit row for
/// `offer_id`, if one was written.
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
async fn accept_failure_reason(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    offer_id: uuid::Uuid,
) -> Option<String> {
    client
        .query_opt(
            "SELECT metadata->>'reason' FROM audit_log
             WHERE event_type = 'role_grant_offer_accept' AND outcome = 'failure'
               AND metadata->>'offer_id' = $1",
            &[&offer_id.to_string()],
        )
        .await
        .expect("audit lookup")
        .map(|row| row.get(0))
}

/// Whether the offer is still pending (not accepted).
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
async fn is_pending(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    offer_id: uuid::Uuid,
) -> bool {
    client
        .query_one(
            "SELECT accepted_at IS NULL FROM role_grant_offer WHERE id = $1",
            &[&offer_id],
        )
        .await
        .expect("offer row")
        .get(0)
}

/// Stand up a pending offer of `role` from `grantor_actor` to `to_account` by
/// direct query — the query layer has no builtin guard on create (the verb
/// does), so this is how the accept-side refusals get their rows.
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
async fn offer_directly(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    grantor_actor: uuid::Uuid,
    to_account: uuid::Uuid,
    role: &str,
) -> uuid::Uuid {
    query_role_grant_offer_create(
        client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: to_account,
            to_actor_id: None,
            role: role.to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("direct offer")
    .id
}

/// Count `role_grant` rows for `actor_id` with `role`, split by scope.
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
async fn count_grants(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: uuid::Uuid,
    role: &str,
    scoped: bool,
) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM role_grant
             WHERE actor_id = $1 AND role = $2 AND (scope_id IS NOT NULL) = $3",
            &[&actor_id, &role, &scoped],
        )
        .await
        .expect("count role_grant")
        .get(0)
}

// Use `default_expiry_from_now()` directly in the test inputs — there's
// no test-specific expiry shape worth a local helper.

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_offer_create_succeeds_with_minimal_input() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: Some("welcome".to_owned()),
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create ok");

    assert_eq!(offer.from_actor_id, grantor_actor);
    assert_eq!(offer.to_account_id, recipient_account);
    assert_eq!(offer.role, "admin");
    assert_eq!(offer.message.as_deref(), Some("welcome"));
    assert!(offer.scope_id.is_none());
    assert!(offer.scope_kind.is_none());
    assert!(offer.accepted_at.is_none());
    assert!(offer.declined_at.is_none());
    assert!(offer.retracted_at.is_none());
    assert!(offer.superseded_at.is_none());
    assert!(offer.resulting_role_grant_id.is_none());
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_assign_grants_admin_grantable_role() {
    let pool = fresh_db_pool().await;
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&admin, &audit, &closer);
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;
    let client = pool.get().await.expect("pool.get");

    // `admin` is admin-grantable in the default registry; the recipient is a
    // single-actor account, so `to_actor_id` is resolved.
    let out = offer_dispatch(
        "role_grant_assign",
        &json!({ "to_account_id": recipient_account, "role": "admin" }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect("assign admin role");

    assert_eq!(out["ok"], json!(true));
    assert!(out["role_grant_id"].is_string(), "returns the new grant id");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_assign_rejects_non_grantable_role() {
    let pool = fresh_db_pool().await;
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&admin, &audit, &closer);
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;
    let client = pool.get().await.expect("pool.get");

    // `keeper` carries the bootstrap grant path only — never web-assignable.
    let err = offer_dispatch(
        "role_grant_assign",
        &json!({ "to_account_id": recipient_account, "role": "keeper" }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("keeper is not admin-grantable");

    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_offer_create_rejects_self_target() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (grantor_account, grantor_actor) = seed_account_actor(&pool, "loner").await;

    let err = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: grantor_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect_err("self-target should reject");

    assert!(matches!(err, RoleGrantOfferError::SelfTarget));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_offer_create_rejects_actor_account_mismatch() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;
    // The "wrong" actor — lives on a different account than `recipient_account`.
    let (_, stranger_actor) = seed_account_actor(&pool, "stranger").await;

    let err = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: Some(stranger_actor),
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect_err("actor not on recipient account should reject");

    assert!(matches!(err, RoleGrantOfferError::ActorAccountMismatch));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_offer_create_upserts_existing_pending() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;

    let first = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: Some("first message".to_owned()),
            expires_at: SystemTime::now() + Duration::from_secs(60),
        },
    )
    .await
    .expect("first offer");

    let second = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: Some("refreshed".to_owned()),
            expires_at: SystemTime::now() + Duration::from_hours(24),
        },
    )
    .await
    .expect("upsert second offer");

    // Same row — id preserved across the upsert.
    assert_eq!(first.id, second.id);
    assert_eq!(second.message.as_deref(), Some("refreshed"));
    // expires_at refreshed to the second value (later than the first).
    assert!(second.expires_at >= first.expires_at);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_offer_creates_role_grant_and_marks_offer_accepted() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    // a builtin-role offer needs a grantor who still holds a global admin
    fuz_testing::grant_role(&pool, grantor_actor, ROLE_ADMIN).await;
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "recipient").await;

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");

    let result = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient_account,
            actor_id: recipient_actor,
        },
    )
    .await
    .expect("accept ok");

    assert!(result.created);
    assert_eq!(result.offer.id, offer.id);
    assert!(result.offer.accepted_at.is_some());
    assert_eq!(
        result.offer.resulting_role_grant_id,
        Some(result.role_grant_id)
    );
    assert!(result.superseded_offers.is_empty());

    // Sanity: the role_grant row exists, binds the recipient actor +
    // role, and points back at the offer.
    let role_grant_row = client
        .query_one(
            "SELECT actor_id, role, source_offer_id FROM role_grant WHERE id = $1",
            &[&result.role_grant_id],
        )
        .await
        .expect("role_grant lookup");
    let actor_id: uuid::Uuid = role_grant_row.get(0);
    let role: String = role_grant_row.get(1);
    let source_offer_id: Option<uuid::Uuid> = role_grant_row.get(2);
    assert_eq!(actor_id, recipient_actor);
    assert_eq!(role, "admin");
    assert_eq!(source_offer_id, Some(offer.id));
}

/// An expired, unrevoked grant still holds the slot the offer confers: the
/// accept revokes it and mints a fresh grant, so `resulting_role_grant_id`
/// names a live grant rather than the dead one.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_offer_over_expired_grant_mints_fresh_grant() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "recipient").await;
    let past = SystemTime::now() - Duration::from_secs(60);
    let expired = query_create_role_grant(
        &client,
        &recipient_actor,
        "teacher",
        None,
        None,
        None,
        Some(past),
    )
    .await
    .expect("seed expired grant");

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "teacher".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");
    let result = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient_account,
            actor_id: recipient_actor,
        },
    )
    .await
    .expect("accept ok");

    assert_ne!(
        result.role_grant_id, expired.id,
        "the accept mints a fresh grant over the expired row",
    );
    let row = client
        .query_one(
            "SELECT revoked_at IS NULL, expires_at IS NULL, source_offer_id FROM role_grant WHERE id = $1",
            &[&result.role_grant_id],
        )
        .await
        .expect("resulting grant lookup");
    assert!(row.get::<_, bool>(0), "the resulting grant is unrevoked");
    assert!(row.get::<_, bool>(1), "and non-expiring");
    assert_eq!(row.get::<_, Option<uuid::Uuid>>(2), Some(offer.id));
    let reason: Option<String> = client
        .query_one(
            "SELECT revoked_reason FROM role_grant WHERE id = $1",
            &[&expired.id],
        )
        .await
        .expect("expired grant lookup")
        .get(0);
    assert_eq!(reason.as_deref(), Some("expired"));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_offer_idempotent_on_second_call() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    // a builtin-role offer needs a grantor who still holds a global admin
    fuz_testing::grant_role(&pool, grantor_actor, ROLE_ADMIN).await;
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "recipient").await;

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");

    let first = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient_account,
            actor_id: recipient_actor,
        },
    )
    .await
    .expect("first accept");
    let second = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient_account,
            actor_id: recipient_actor,
        },
    )
    .await
    .expect("second accept idempotent");

    assert!(first.created);
    assert!(!second.created);
    assert_eq!(first.role_grant_id, second.role_grant_id);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_offer_rejects_terminal_offer() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "recipient").await;

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");

    // Force the offer into a terminal `declined` state directly.
    client
        .execute(
            "UPDATE role_grant_offer SET declined_at = NOW() WHERE id = $1",
            &[&offer.id],
        )
        .await
        .expect("manual decline");

    let err = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient_account,
            actor_id: recipient_actor,
        },
    )
    .await
    .expect_err("terminal offer must reject");

    assert!(matches!(err, RoleGrantOfferError::AlreadyTerminal(id) if id == offer.id));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_offer_rejects_expired_offer() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "recipient").await;

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            // Create with a non-expired stamp first to satisfy the
            // initial CHECK; then manually backdate.
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");

    client
        .execute(
            "UPDATE role_grant_offer SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
            &[&offer.id],
        )
        .await
        .expect("backdate expiry");

    let err = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient_account,
            actor_id: recipient_actor,
        },
    )
    .await
    .expect_err("expired offer must reject");

    assert!(matches!(err, RoleGrantOfferError::Expired(id) if id == offer.id));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_offer_rejects_wrong_actor_on_actor_targeted_offer() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    // a builtin-role offer needs a grantor who still holds a global admin
    fuz_testing::grant_role(&pool, grantor_actor, ROLE_ADMIN).await;
    let (recipient_account, primary_actor) = seed_account_actor(&pool, "primary").await;
    // Second actor on the same recipient account.
    let secondary_actor = seed_extra_actor(&pool, recipient_account, "secondary").await;

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient_account,
            to_actor_id: Some(primary_actor),
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("actor-targeted offer create");

    // Try to accept as the wrong actor on the same account.
    let err = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient_account,
            actor_id: secondary_actor,
        },
    )
    .await
    .expect_err("wrong actor must reject");

    assert!(matches!(err, RoleGrantOfferError::ActorMismatch(id) if id == offer.id));

    // The named actor can still accept.
    let ok_result = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient_account,
            actor_id: primary_actor,
        },
    )
    .await
    .expect("named actor accepts");
    assert!(ok_result.created);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_offer_supersedes_sibling_pending_offers() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (grantor_a_account, grantor_a_actor) = seed_account_actor(&pool, "grantor_a").await;
    let (_, grantor_b_actor) = seed_account_actor(&pool, "grantor_b").await;
    // a builtin-role offer needs a grantor who still holds a global admin
    fuz_testing::grant_role(&pool, grantor_a_actor, ROLE_ADMIN).await;
    fuz_testing::grant_role(&pool, grantor_b_actor, ROLE_ADMIN).await;
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "recipient").await;

    let offer_a = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_a_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer a");

    let offer_b = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_b_actor,
            to_account_id: recipient_account,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer b");

    // Accept A — B should be superseded with grantor_a's account_id
    // on the result.
    let result = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer_a.id,
            to_account_id: recipient_account,
            actor_id: recipient_actor,
        },
    )
    .await
    .expect("accept offer a");

    assert!(result.created);
    assert_eq!(result.superseded_offers.len(), 1);
    let superseded = &result.superseded_offers[0];
    assert_eq!(superseded.offer.id, offer_b.id);
    // Grantor B's account is on the row (not A's — A is the accepter side).
    assert_ne!(superseded.from_account_id, grantor_a_account);

    // Sanity: row in DB shows superseded_at set on B.
    let b_row = client
        .query_one(
            "SELECT superseded_at IS NOT NULL FROM role_grant_offer WHERE id = $1",
            &[&offer_b.id],
        )
        .await
        .expect("offer b lookup");
    let b_superseded: bool = b_row.get(0);
    assert!(b_superseded);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn decline_of_already_declined_offer_reports_terminal() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let grantor = seed_actor_context(&pool, "grantor").await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let recipient_ctx = ctx(&recipient, &audit, &closer);

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor.actor.id,
            to_account_id: recipient.account.id,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");

    let params = json!({ "offer_id": offer.id });
    let declined = offer_dispatch(
        "role_grant_offer_decline",
        &params,
        &recipient_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect("first decline");
    // the decline answers the terminal offer, as accept answers its own
    assert_eq!(declined["offer"]["id"], json!(offer.id));
    assert!(declined["offer"]["declined_at"].is_string());
    assert!(declined["offer"]["retracted_at"].is_null());

    // The retry (double-click, client retry) — the conditional UPDATE
    // misses on a row that exists AND belongs to the caller, the one
    // shape that reaches `classify_missed_transition`'s row-present
    // branch. Must surface as the terminal wire error, never a decode
    // panic.
    let err = offer_dispatch(
        "role_grant_offer_decline",
        &params,
        &recipient_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("declining a declined offer is terminal");

    assert_eq!(err.code, JsonrpcErrorCode::InvalidRequest);
    assert_eq!(
        err.data,
        Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_TERMINAL }))
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn retract_of_already_retracted_offer_reports_terminal() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let grantor = seed_actor_context(&pool, "grantor").await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let grantor_ctx = ctx(&grantor, &audit, &closer);

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor.actor.id,
            to_account_id: recipient.account.id,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");

    let params = json!({ "offer_id": offer.id });
    let retracted = offer_dispatch(
        "role_grant_offer_retract",
        &params,
        &grantor_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect("first retract");
    // the retract answers the terminal offer, as accept answers its own
    assert_eq!(retracted["offer"]["id"], json!(offer.id));
    assert!(retracted["offer"]["retracted_at"].is_string());
    assert!(retracted["offer"]["declined_at"].is_null());

    let err = offer_dispatch(
        "role_grant_offer_retract",
        &params,
        &grantor_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("retracting a retracted offer is terminal");

    assert_eq!(err.code, JsonrpcErrorCode::InvalidRequest);
    assert_eq!(
        err.data,
        Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_TERMINAL }))
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn retract_of_accepted_offer_reports_terminal() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let grantor = seed_actor_context(&pool, "grantor").await;
    // a builtin-role offer needs a grantor who still holds a global admin
    fuz_testing::grant_role(&pool, grantor.actor.id, ROLE_ADMIN).await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let grantor_ctx = ctx(&grantor, &audit, &closer);

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor.actor.id,
            to_account_id: recipient.account.id,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");

    query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient.account.id,
            actor_id: recipient.actor.id,
        },
    )
    .await
    .expect("recipient accepts");

    // Grantor retracts an offer the recipient already took — the other
    // terminal column (`accepted_at`) on the same resolution path.
    let err = offer_dispatch(
        "role_grant_offer_retract",
        &json!({ "offer_id": offer.id }),
        &grantor_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("retracting an accepted offer is terminal");

    assert_eq!(err.code, JsonrpcErrorCode::InvalidRequest);
    assert_eq!(
        err.data,
        Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_TERMINAL }))
    );
}

/// Accept answers the two refusals every transition out of `pending` shares
/// the way decline and retract do: an offer the caller already declined is
/// the terminal `invalid_request`, and one that is not in the caller's inbox
/// — another account's, or no offer at all — is the masked `not_found`.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_reports_a_terminal_offer_and_masks_foreign_and_unknown_ones() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let grantor = seed_actor_context(&pool, "grantor").await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let stranger = seed_actor_context(&pool, "stranger").await;
    let recipient_ctx = ctx(&recipient, &audit, &closer);
    let stranger_ctx = ctx(&stranger, &audit, &closer);

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor.actor.id,
            to_account_id: recipient.account.id,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");
    let params = json!({ "offer_id": offer.id });

    // Still pending, and not the stranger's; then an id that never existed.
    for params in [&params, &json!({ "offer_id": uuid::Uuid::new_v4() })] {
        let err = offer_dispatch(
            "role_grant_offer_accept",
            params,
            &stranger_ctx,
            ActionDb::Pool(&client),
        )
        .await
        .expect_err("a stranger's accept must not succeed");
        assert_eq!(err.code, JsonrpcErrorCode::NotFound, "{params}");
        assert_eq!(
            err.data,
            Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_NOT_FOUND })),
            "{params}"
        );
    }
    assert!(
        is_pending(&client, offer.id).await,
        "the offer is untouched"
    );

    offer_dispatch(
        "role_grant_offer_decline",
        &params,
        &recipient_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect("the recipient declines");
    let err = offer_dispatch(
        "role_grant_offer_accept",
        &params,
        &recipient_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("accepting a declined offer is terminal");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidRequest);
    assert_eq!(
        err.data,
        Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_TERMINAL }))
    );
    // the stranger never learns the foreign offer is now terminal
    let err = offer_dispatch(
        "role_grant_offer_accept",
        &params,
        &stranger_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("a stranger's accept of a terminal offer must not succeed");
    assert_eq!(err.code, JsonrpcErrorCode::NotFound);
    assert_eq!(
        err.data,
        Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_NOT_FOUND }))
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn decline_and_retract_mask_foreign_unknown_and_terminal_offers() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let grantor = seed_actor_context(&pool, "grantor").await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let stranger = seed_actor_context(&pool, "stranger").await;
    let recipient_ctx = ctx(&recipient, &audit, &closer);
    let stranger_ctx = ctx(&stranger, &audit, &closer);

    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor.actor.id,
            to_account_id: recipient.account.id,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");

    // The IDOR masks: a real, still-pending offer that belongs to
    // neither the stranger's inbox nor their outbox reads exactly like an
    // id that never existed. Both legs exercise the owner-filter
    // placeholder wiring on the terminal-state resolution query.
    for (method, params) in [
        ("role_grant_offer_decline", json!({ "offer_id": offer.id })),
        ("role_grant_offer_retract", json!({ "offer_id": offer.id })),
        (
            "role_grant_offer_decline",
            json!({ "offer_id": uuid::Uuid::new_v4() }),
        ),
        (
            "role_grant_offer_retract",
            json!({ "offer_id": uuid::Uuid::new_v4() }),
        ),
    ] {
        let err = offer_dispatch(method, &params, &stranger_ctx, ActionDb::Pool(&client))
            .await
            .expect_err("a stranger's offer verb must not succeed");
        assert_eq!(err.code, JsonrpcErrorCode::NotFound, "{method}");
        assert_eq!(
            err.data,
            Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_NOT_FOUND })),
            "{method}"
        );
    }

    // A terminal offer is masked too: the stranger never learns that a
    // foreign offer has been resolved (the owner filter, not the row's state,
    // decides between `not_found` and the terminal error).
    offer_dispatch(
        "role_grant_offer_decline",
        &json!({ "offer_id": offer.id }),
        &recipient_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect("the recipient declines");
    for method in ["role_grant_offer_decline", "role_grant_offer_retract"] {
        let err = offer_dispatch(
            method,
            &json!({ "offer_id": offer.id }),
            &stranger_ctx,
            ActionDb::Pool(&client),
        )
        .await
        .expect_err("a stranger's verb on a terminal offer must not succeed");
        assert_eq!(err.code, JsonrpcErrorCode::NotFound, "{method}");
        assert_eq!(
            err.data,
            Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_NOT_FOUND })),
            "{method}"
        );
    }
}

/// The `metadata` of the one `event_type` audit row whose `metadata.<key>`
/// is `id`.
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
async fn audit_row_metadata(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    event_type: &str,
    key: &str,
    id: uuid::Uuid,
) -> Value {
    let row = client
        .query_one(
            "SELECT metadata::text FROM audit_log WHERE event_type = $1 AND metadata->>$2 = $3",
            &[&event_type, &key, &id.to_string()],
        )
        .await
        .expect("one audit row");
    serde_json::from_str(row.get::<_, &str>(0)).expect("metadata is JSON")
}

/// A decline or revoke without a reason records no `reason` key — absent, as
/// the TS spine writes it and the audit schema declares it, never `null`.
/// With one, the key carries it.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn decline_and_revoke_audit_metadata_omit_an_absent_reason() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let grantor = seed_actor_context(&pool, "grantor").await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let recipient_ctx = ctx(&recipient, &audit, &closer);

    // one pending offer at a time: a grantor's second pending offer of a
    // role to one account upserts the first
    for reason in [None, Some("not now")] {
        let offer_id =
            offer_directly(&client, grantor.actor.id, recipient.account.id, "admin").await;
        let mut params = json!({ "offer_id": offer_id });
        if let Some(reason) = reason {
            params["reason"] = json!(reason);
        }
        offer_dispatch(
            "role_grant_offer_decline",
            &params,
            &recipient_ctx,
            ActionDb::Pool(&client),
        )
        .await
        .expect("decline");
        let mut expected = json!({ "offer_id": offer_id, "role": "admin", "scope_id": null });
        if let Some(reason) = reason {
            expected["reason"] = json!(reason);
        }
        assert_eq!(
            audit_row_metadata(&client, "role_grant_offer_decline", "offer_id", offer_id).await,
            expected,
            "decline reason {reason:?}"
        );
    }

    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    // a second active admin, so the revokee's grant isn't the last admin's
    seed_role_grant_direct(&pool, admin.actor.id, ROLE_ADMIN, None).await;
    let admin_ctx = ctx(&admin, &audit, &closer);
    let (_, revokee_actor) = seed_account_actor(&pool, "revokee").await;
    for reason in [None, Some("cleanup")] {
        let role_grant_id =
            seed_role_grant_direct(&pool, revokee_actor, ROLE_ADMIN, Some(admin.actor.id)).await;
        let mut params = json!({ "actor_id": revokee_actor, "role_grant_id": role_grant_id });
        if let Some(reason) = reason {
            params["reason"] = json!(reason);
        }
        offer_dispatch(
            "role_grant_revoke",
            &params,
            &admin_ctx,
            ActionDb::Pool(&client),
        )
        .await
        .expect("revoke");
        let mut expected =
            json!({ "role": ROLE_ADMIN, "role_grant_id": role_grant_id, "scope_id": null });
        if let Some(reason) = reason {
            expected["reason"] = json!(reason);
        }
        assert_eq!(
            audit_row_metadata(&client, "role_grant_revoke", "role_grant_id", role_grant_id).await,
            expected,
            "revoke reason {reason:?}"
        );
    }
}

// --- builtin roles are global-only; scoped app-role assigns ----------------

/// **The escalation vector, handler-side.** A caller holding only a scoped
/// `admin` can't `role_grant_assign` anything — least of all a global `admin`
/// to itself. The dispatcher's gate refuses it first; the handler re-checks.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_assign_refuses_a_scoped_admin_caller() {
    let pool = fresh_db_pool().await;
    let scoped_admin = with_grant(
        seed_actor_context(&pool, "scoped_admin").await,
        ROLE_ADMIN,
        Some(uuid::Uuid::new_v4()),
    );
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&scoped_admin, &audit, &closer);
    let client = pool.get().await.expect("pool.get");

    let err = offer_dispatch(
        "role_grant_assign",
        &json!({ "to_account_id": scoped_admin.account.id, "role": ROLE_ADMIN }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("a scoped admin can't assign");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&err), "insufficient_permissions");
    assert_eq!(
        count_grants(&client, scoped_admin.actor.id, ROLE_ADMIN, false).await,
        0,
        "no global admin grant was written"
    );
}

/// A builtin role is never granted with a scope: `role_grant_assign` refuses a
/// scoped `admin` (`-32602` `role_grant_builtin_scoped`) and still
/// answers a scoped `keeper` with the grant-path denial it always had.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_assign_refuses_a_scoped_builtin_role() {
    let pool = fresh_db_pool().await;
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&admin, &audit, &closer);
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "recipient").await;
    let client = pool.get().await.expect("pool.get");
    let scope = uuid::Uuid::new_v4();

    let err = offer_dispatch(
        "role_grant_assign",
        &json!({
            "to_account_id": recipient_account,
            "role": ROLE_ADMIN,
            "scope_kind": "space",
            "scope_id": scope,
        }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("a scoped admin grant is refused");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
    assert_eq!(reason(&err), ERROR_ROLE_GRANT_BUILTIN_SCOPED);
    assert_eq!(
        count_grants(&client, recipient_actor, ROLE_ADMIN, true).await,
        0
    );
    let keeper = offer_dispatch(
        "role_grant_assign",
        &json!({
            "to_account_id": recipient_account,
            "role": "keeper",
            "scope_kind": "space",
            "scope_id": scope,
        }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("keeper is never web-assignable");
    assert_eq!(keeper.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&keeper), ERROR_ROLE_NOT_WEB_GRANTABLE);
}

/// A consumer policy: an app role exists only scoped to a `classroom`. Records
/// every input it sees.
struct ClassroomScopedOnly(std::sync::Mutex<Vec<OfferCreateAuthorizeInput>>);

impl OfferCreateAuthorize for ClassroomScopedOnly {
    #[allow(clippy::expect_used)] // test predicate outside a `#[test]` fn
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        input: &'a OfferCreateAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>> {
        self.0.lock().expect("lock").push(input.clone());
        let admits = input.scope_kind.as_deref() == Some("classroom") && input.scope_id.is_some();
        Box::pin(async move { Ok(admits) })
    }
}

/// `role_grant_assign` runs the consumer's offer predicate: a grant it refuses
/// is refused with `role_grant_offer_not_authorized` — as offer-create refuses
/// it — and writes nothing; an admitted scoped grant lands, the predicate
/// having seen its `scope_kind`.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_assign_runs_the_offer_authorize_predicate() {
    let pool = fresh_db_pool().await;
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&admin, &audit, &closer);
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "pupil").await;
    let client = pool.get().await.expect("pool.get");
    let registry = app_registry();
    let policy = ClassroomScopedOnly(std::sync::Mutex::new(Vec::new()));

    let global = json!({"to_account_id": recipient_account, "role": "teacher"});
    for method in ["role_grant_assign", "role_grant_offer_create"] {
        let err = RoleGrantOfferActionSpecs::dispatch(
            method,
            &global,
            &ctx,
            &ActionDb::Pool(&client),
            &policy,
            &registry,
        )
        .await
        .expect_err("the policy refuses an unscoped teacher");
        assert_eq!(err.code, JsonrpcErrorCode::Forbidden, "{method}");
        assert_eq!(
            reason(&err),
            ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED,
            "{method}"
        );
    }
    let written: i64 = client
        .query_one(
            "SELECT count(*) FROM role_grant WHERE actor_id = $1 AND role = 'teacher'",
            &[&recipient_actor],
        )
        .await
        .expect("count")
        .get(0);
    assert_eq!(written, 0, "the refused assign wrote no grant");

    policy.0.lock().expect("lock").clear();
    let scope = uuid::Uuid::new_v4();
    RoleGrantOfferActionSpecs::dispatch(
        "role_grant_assign",
        &json!({"to_account_id": recipient_account, "role": "teacher",
                "scope_kind": "classroom", "scope_id": scope}),
        &ctx,
        &ActionDb::Pool(&client),
        &policy,
        &registry,
    )
    .await
    .expect("the policy admits a classroom-scoped teacher");
    let seen = policy.0.lock().expect("lock");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].scope_kind.as_deref(), Some("classroom"));
    assert_eq!(seen[0].scope_id, Some(scope));
    assert_eq!(seen[0].to_account_id, recipient_account);
}

/// A scoped **app** role assigns: the row carries the `(scope_kind, scope_id)`
/// pair the input named (satisfying `role_grant_scope_kind_paired`, where a
/// lone `scope_id` is a constraint violation), re-assigning is idempotent, and
/// the global grant of the same role is a distinct row.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_assign_scoped_app_role_writes_the_paired_scope() {
    let pool = fresh_db_pool().await;
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&admin, &audit, &closer);
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "teacher").await;
    let client = pool.get().await.expect("pool.get");
    let registry = app_registry();
    let scope = uuid::Uuid::new_v4();
    let assign = |params: Value| {
        let ctx = &ctx;
        let client = &client;
        let registry = &registry;
        async move {
            RoleGrantOfferActionSpecs::dispatch(
                "role_grant_assign",
                &params,
                ctx,
                &ActionDb::Pool(client),
                &AdminOfferAuthorize,
                registry,
            )
            .await
        }
    };
    let scoped_params = json!({
        "to_account_id": recipient_account,
        "role": "teacher",
        "scope_kind": "classroom",
        "scope_id": scope,
    });

    let first = assign(scoped_params.clone()).await.expect("scoped assign");
    let row = client
        .query_one(
            "SELECT scope_kind, scope_id FROM role_grant WHERE id = $1::text::uuid",
            &[&first["role_grant_id"].as_str().expect("id")],
        )
        .await
        .expect("grant row");
    assert_eq!(
        row.get::<_, Option<String>>(0).as_deref(),
        Some("classroom")
    );
    assert_eq!(row.get::<_, Option<uuid::Uuid>>(1), Some(scope));

    // The audit row names the scope pair the grant carries.
    let audited_kind: Option<String> = client
        .query_one(
            "SELECT metadata->>'scope_kind' FROM audit_log
             WHERE event_type = 'role_grant_create' AND outcome = 'success'
               AND metadata->>'role_grant_id' = $1",
            &[&first["role_grant_id"].as_str().expect("id")],
        )
        .await
        .expect("audit row")
        .get(0);
    assert_eq!(audited_kind.as_deref(), Some("classroom"));

    let again = assign(scoped_params).await.expect("idempotent re-assign");
    assert_eq!(again["role_grant_id"], first["role_grant_id"]);

    let global = assign(json!({ "to_account_id": recipient_account, "role": "teacher" }))
        .await
        .expect("global assign");
    assert_ne!(global["role_grant_id"], first["role_grant_id"]);
    assert_eq!(
        count_grants(&client, recipient_actor, "teacher", true).await,
        1
    );
    assert_eq!(
        count_grants(&client, recipient_actor, "teacher", false).await,
        1
    );

    // A half-scoped input is `-32602`, never the paired-CHECK 500.
    let unpaired = assign(json!({
        "to_account_id": recipient_account,
        "role": "teacher",
        "scope_id": uuid::Uuid::new_v4(),
    }))
    .await
    .expect_err("scope_id without scope_kind");
    assert_eq!(unpaired.code, JsonrpcErrorCode::InvalidParams);
}

/// The index's `'GLOBAL'` token as a `scope_kind`, with the all-zeros uuid —
/// a global grant's key in the partial unique index — is off the scope-kind
/// grammar and refused `-32602` on an actor holding the role globally, not
/// the 500 of an idempotent re-select that misses; and it plants no row, so a
/// later global grant still lands.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_assign_refuses_the_index_token_as_a_scope_kind() {
    let pool = fresh_db_pool().await;
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&admin, &audit, &closer);
    let (held_account, held_actor) = seed_account_actor(&pool, "held").await;
    let (fresh_account, fresh_actor) = seed_account_actor(&pool, "fresh").await;
    let client = pool.get().await.expect("pool.get");
    let registry = app_registry();
    let assign = |params: Value| {
        let ctx = &ctx;
        let client = &client;
        let registry = &registry;
        async move {
            RoleGrantOfferActionSpecs::dispatch(
                "role_grant_assign",
                &params,
                ctx,
                &ActionDb::Pool(client),
                &AdminOfferAuthorize,
                registry,
            )
            .await
        }
    };
    let token = |account: uuid::Uuid| {
        json!({
            "to_account_id": account,
            "role": "teacher",
            "scope_kind": "GLOBAL",
            "scope_id": "00000000-0000-0000-0000-000000000000",
        })
    };
    let kinds = |actor: uuid::Uuid| {
        let client = &client;
        async move {
            client
                .query(
                    "SELECT scope_kind FROM role_grant WHERE actor_id = $1 AND role = 'teacher'",
                    &[&actor],
                )
                .await
                .expect("grant rows")
                .iter()
                .map(|row| row.get::<_, Option<String>>(0))
                .collect::<Vec<_>>()
        }
    };

    assign(json!({ "to_account_id": held_account, "role": "teacher" }))
        .await
        .expect("global assign");
    let err = assign(token(held_account))
        .await
        .expect_err("the token on an actor holding the role globally");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
    assert!(err.data.is_none(), "a validation refusal carries no reason");
    assert_eq!(kinds(held_actor).await, vec![None], "only the global grant");

    let err = assign(token(fresh_account))
        .await
        .expect_err("the token on a fresh actor");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
    assign(json!({ "to_account_id": fresh_account, "role": "teacher" }))
        .await
        .expect("a later global assign lands");
    assert_eq!(
        kinds(fresh_actor).await,
        vec![None],
        "only the global grant"
    );
}

/// `role_grant_offer_create` refuses a scoped builtin role **before** the
/// injected predicate — even an admit-everything consumer authorizer can't
/// open that door — and writes no offer.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn role_grant_offer_create_refuses_a_scoped_builtin_role() {
    let pool = fresh_db_pool().await;
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&admin, &audit, &closer);
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;
    let client = pool.get().await.expect("pool.get");

    let err = RoleGrantOfferActionSpecs::dispatch(
        "role_grant_offer_create",
        &json!({
            "to_account_id": recipient_account,
            "role": ROLE_ADMIN,
            "scope_kind": "space",
            "scope_id": uuid::Uuid::new_v4(),
        }),
        &ctx,
        &ActionDb::Pool(&client),
        &AdmitAll,
        &RoleRegistry::default(),
    )
    .await
    .expect_err("a scoped admin offer is refused");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidParams);
    assert_eq!(reason(&err), ERROR_ROLE_GRANT_BUILTIN_SCOPED);
    let offers: i64 = client
        .query_one("SELECT count(*) FROM role_grant_offer", &[])
        .await
        .expect("offer count")
        .get(0);
    assert_eq!(offers, 0);
}

/// A pending scoped builtin offer — legacy data, since create refuses one —
/// never becomes a grant: the query refuses it (`BuiltinRefused` / `Scoped`), the verb
/// answers `role_grant_builtin_scoped`, and the offer stays pending.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_refuses_a_legacy_scoped_builtin_offer() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    let recipient = seed_actor_context(&pool, "recipient").await;

    // The query layer has no builtin guard on create (the verb does), so it
    // stands up the legacy row directly.
    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient.account.id,
            to_actor_id: None,
            role: ROLE_ADMIN.to_owned(),
            scope_kind: Some("space".to_owned()),
            scope_id: Some(uuid::Uuid::new_v4()),
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("legacy scoped admin offer");

    let direct = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id: offer.id,
            to_account_id: recipient.account.id,
            actor_id: recipient.actor.id,
        },
    )
    .await
    .expect_err("the query refuses it");
    assert!(matches!(
        direct,
        RoleGrantOfferError::BuiltinRefused { ref offer, refusal: BuiltinOfferRefusal::Scoped }
            if offer.role == ROLE_ADMIN
    ));

    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&recipient, &audit, &closer);
    let err = offer_dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": offer.id }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("the verb refuses it");
    assert_eq!(err.code, JsonrpcErrorCode::InvalidRequest);
    assert_eq!(reason(&err), ERROR_ROLE_GRANT_BUILTIN_SCOPED);

    assert_eq!(
        count_grants(&client, recipient.actor.id, ROLE_ADMIN, true).await,
        0
    );
    let accepted: bool = client
        .query_one(
            "SELECT accepted_at IS NOT NULL FROM role_grant_offer WHERE id = $1",
            &[&offer.id],
        )
        .await
        .expect("offer row")
        .get(0);
    assert!(!accepted, "the offer stays pending");
}

/// Cross-account inbox reads are global-admin authority: a scoped `admin`
/// can't list or page another account's offers.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn offer_inbox_reads_of_another_account_require_a_global_admin() {
    let pool = fresh_db_pool().await;
    let scoped_admin = with_grant(
        seed_actor_context(&pool, "scoped_admin").await,
        ROLE_ADMIN,
        Some(uuid::Uuid::new_v4()),
    );
    let (other_account, _) = seed_account_actor(&pool, "other").await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let ctx = ctx(&scoped_admin, &audit, &closer);
    let client = pool.get().await.expect("pool.get");

    for method in ["role_grant_offer_list", "role_grant_offer_history"] {
        let err = offer_dispatch(
            method,
            &json!({ "account_id": other_account }),
            &ctx,
            ActionDb::Pool(&client),
        )
        .await
        .expect_err("a scoped admin can't read another inbox");
        assert_eq!(err.code, JsonrpcErrorCode::Forbidden, "{method}");
    }
}

/// Offering a builtin role is global-admin authority the spine decides, not
/// the consumer predicate: a caller whose only `admin` is scoped is refused a
/// **global** `admin` offer even under an admit-everything predicate (the
/// shape of a consumer answering with a scope-blind role check), while a
/// global admin still offers under the same predicate.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn offering_a_builtin_role_requires_a_global_admin_caller() {
    let pool = fresh_db_pool().await;
    let scoped_admin = with_grant(
        seed_actor_context(&pool, "scoped_admin").await,
        ROLE_ADMIN,
        Some(uuid::Uuid::new_v4()),
    );
    let global_admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let (puppet_account, _) = seed_account_actor(&pool, "puppet").await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    let client = pool.get().await.expect("pool.get");
    let offer_admin = |auth| {
        let ctx = ctx(auth, &audit, &closer);
        let client = &client;
        async move {
            RoleGrantOfferActionSpecs::dispatch(
                "role_grant_offer_create",
                &json!({ "to_account_id": puppet_account, "role": ROLE_ADMIN }),
                &ctx,
                &ActionDb::Pool(client),
                &AdmitAll,
                &RoleRegistry::default(),
            )
            .await
        }
    };

    let err = offer_admin(&scoped_admin)
        .await
        .expect_err("a scoped admin can't offer a global admin");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&err), ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED);
    let offers: i64 = client
        .query_one("SELECT count(*) FROM role_grant_offer", &[])
        .await
        .expect("offer count")
        .get(0);
    assert_eq!(offers, 0, "no offer was written");

    offer_admin(&global_admin)
        .await
        .expect("a global admin still offers admin");
}

/// Accepting a builtin-role offer re-checks the grantor: the grant is minted
/// only while the grantor holds an active **global** `admin`. A pending global
/// `admin` offer from a grantor whose only `admin` is scoped (an offer made
/// under a since-closed path) is refused and stays pending; once the grantor
/// holds the global grant, the same offer accepts.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accepting_a_builtin_offer_rechecks_the_grantor() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    fuz_testing::grant_scoped_role(
        &pool,
        grantor_actor,
        ROLE_ADMIN,
        "space",
        uuid::Uuid::new_v4(),
    )
    .await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let offer = query_role_grant_offer_create(
        &client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor_actor,
            to_account_id: recipient.account.id,
            to_actor_id: None,
            role: ROLE_ADMIN.to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("pending global admin offer");

    let audit = std::sync::Arc::new(AuditEmitter::new_with_inflight_tracking(pool.clone()));
    let closer = closer();
    let ctx = ctx(&recipient, &audit, &closer);
    let err = offer_dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": offer.id }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("a grantor without a global admin confers nothing");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&err), ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED);
    audit.drain_inflight().await;
    assert_eq!(
        accept_failure_reason(&client, offer.id).await.as_deref(),
        Some(ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED),
        "the refusal is audited as a failed accept"
    );
    assert_eq!(
        count_grants(&client, recipient.actor.id, ROLE_ADMIN, false).await,
        0
    );

    fuz_testing::grant_role(&pool, grantor_actor, ROLE_ADMIN).await;
    offer_dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": offer.id }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect("the refused offer stayed pending and now accepts");
    assert_eq!(
        count_grants(&client, recipient.actor.id, ROLE_ADMIN, false).await,
        1
    );
}

/// `keeper` is bootstrap-only: a pending offer of it never accepts, even from
/// a grantor who holds a global admin. The query refuses it
/// (`BootstrapOnly`), the verb answers the offer-create denial for a role no
/// offer may confer, the refusal is audited, and the offer stays pending.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_refuses_a_keeper_offer_even_from_a_global_admin() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "grantor").await;
    fuz_testing::grant_role(&pool, grantor_actor, ROLE_ADMIN).await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let offer_id = offer_directly(&client, grantor_actor, recipient.account.id, "keeper").await;

    let direct = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id,
            to_account_id: recipient.account.id,
            actor_id: recipient.actor.id,
        },
    )
    .await
    .expect_err("the query refuses a keeper offer");
    assert!(matches!(
        direct,
        RoleGrantOfferError::BuiltinRefused {
            refusal: BuiltinOfferRefusal::BootstrapOnly,
            ..
        }
    ));

    let audit = std::sync::Arc::new(AuditEmitter::new_with_inflight_tracking(pool.clone()));
    let closer = closer();
    let ctx = ctx(&recipient, &audit, &closer);
    let err = offer_dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": offer_id }),
        &ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("the verb refuses a keeper offer");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&err), ERROR_ROLE_GRANT_OFFER_ROLE_NOT_GRANTABLE);
    audit.drain_inflight().await;
    assert_eq!(
        accept_failure_reason(&client, offer_id).await.as_deref(),
        Some(ERROR_ROLE_GRANT_OFFER_ROLE_NOT_GRANTABLE)
    );
    assert_eq!(
        count_grants(&client, recipient.actor.id, "keeper", false).await,
        0
    );
    assert!(
        is_pending(&client, offer_id).await,
        "the offer stays pending"
    );
}

/// Every branch of the grantor re-check refuses a builtin-role accept: a
/// grantor whose global `admin` was revoked, has expired, sits on a
/// tombstoned actor, or on a tombstoned account. Each offer stays pending.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_rechecks_every_grantor_branch() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let cases: [(&str, &str); 4] = [
        (
            "revoked",
            "UPDATE role_grant SET revoked_at = NOW() WHERE actor_id = $1",
        ),
        (
            "expired",
            "UPDATE role_grant SET expires_at = NOW() - INTERVAL '1 second' WHERE actor_id = $1",
        ),
        (
            "actor_tombstoned",
            "UPDATE actor SET deleted_at = NOW() WHERE id = $1",
        ),
        (
            "account_tombstoned",
            "UPDATE account SET deleted_at = NOW()
             WHERE id = (SELECT account_id FROM actor WHERE id = $1)",
        ),
    ];
    for (label, lapse) in cases {
        let (_, grantor_actor) = seed_account_actor(&pool, &format!("grantor_{label}")).await;
        fuz_testing::grant_role(&pool, grantor_actor, ROLE_ADMIN).await;
        let (recipient_account, recipient_actor) =
            seed_account_actor(&pool, &format!("recipient_{label}")).await;
        let offer_id = offer_directly(&client, grantor_actor, recipient_account, ROLE_ADMIN).await;
        client
            .execute(lapse, &[&grantor_actor])
            .await
            .expect("lapse the grantor");

        let err = query_accept_offer(
            &client,
            AcceptOfferInput {
                offer_id,
                to_account_id: recipient_account,
                actor_id: recipient_actor,
            },
        )
        .await
        .expect_err(label);
        assert!(
            matches!(
                err,
                RoleGrantOfferError::BuiltinRefused {
                    refusal: BuiltinOfferRefusal::GrantorNotAuthorized,
                    ..
                }
            ),
            "{label}: {err:?}"
        );
        assert!(
            is_pending(&client, offer_id).await,
            "{label}: stays pending"
        );
        assert_eq!(
            count_grants(&client, recipient_actor, ROLE_ADMIN, false).await,
            0,
            "{label}"
        );
    }
}

/// The grantor re-check is builtin-only: an app-role offer from a grantor who
/// holds no admin at all still accepts (its authority was the consumer
/// predicate's call at create time).
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_of_an_app_role_offer_needs_no_grantor_admin() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let (_, grantor_actor) = seed_account_actor(&pool, "teacher").await;
    let (recipient_account, recipient_actor) = seed_account_actor(&pool, "student").await;
    let offer_id = offer_directly(&client, grantor_actor, recipient_account, "student").await;

    let result = query_accept_offer(
        &client,
        AcceptOfferInput {
            offer_id,
            to_account_id: recipient_account,
            actor_id: recipient_actor,
        },
    )
    .await
    .expect("an app-role offer accepts");
    assert!(result.created);
    assert_eq!(
        count_grants(&client, recipient_actor, "student", false).await,
        1
    );
}

/// How many `audit_log` rows there are, of any event.
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
async fn count_audit_rows(client: &(impl deadpool_postgres::GenericClient + ?Sized)) -> i64 {
    client
        .query_one("SELECT count(*) FROM audit_log", &[])
        .await
        .expect("count audit_log")
        .get(0)
}

/// Role strings outside the `RoleName` grammar: an authenticated caller can
/// send any of them as a grant input's `role`.
fn off_grammar_roles() -> Vec<String> {
    vec![
        String::new(),
        "Admin".to_owned(),
        "not a role".to_owned(),
        "role-name".to_owned(),
        "_admin".to_owned(),
        "admin_".to_owned(),
        "ad__min".to_owned(),
        "admin\n".to_owned(),
        "r\u{f4}le".to_owned(),
        format!("{} ", "x".repeat(64 * 1024)),
    ]
}

/// A `role` outside the role-name grammar is a malformed input on both grant
/// verbs — `invalid_params` with no `reason`, the answer the twin's `RoleName`
/// input schema gives — refused before any gate that audits its refusal, so
/// the string a caller chose never reaches `audit_log`. A well-formed role
/// that is not grantable is still the audited denial.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_off_grammar_role_is_invalid_params_and_is_not_audited() {
    let pool = fresh_db_pool().await;
    let caller = seed_actor_context(&pool, "caller").await;
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let (recipient_account, _) = seed_account_actor(&pool, "recipient").await;
    let audit = std::sync::Arc::new(AuditEmitter::new_with_inflight_tracking(pool.clone()));
    let closer = closer();
    let caller_ctx = ctx(&caller, &audit, &closer);
    let admin_ctx = ctx(&admin, &audit, &closer);
    let client = pool.get().await.expect("pool.get");
    audit.drain_inflight().await;
    let before = count_audit_rows(&client).await;

    for role in off_grammar_roles() {
        for (method, ctx) in [
            ("role_grant_offer_create", &caller_ctx),
            ("role_grant_offer_create", &admin_ctx),
            ("role_grant_assign", &admin_ctx),
        ] {
            let err = offer_dispatch(
                method,
                &json!({ "to_account_id": recipient_account, "role": role }),
                ctx,
                ActionDb::Pool(&client),
            )
            .await
            .expect_err("an off-grammar role is refused");
            let shown: String = role.chars().take(32).collect();
            assert_eq!(
                err.code,
                JsonrpcErrorCode::InvalidParams,
                "{method} {shown:?}"
            );
            assert_eq!(reason(&err), "", "{method} {shown:?}");
            assert!(err.data.is_none(), "{method} {shown:?}: {:?}", err.data);
        }
    }
    audit.drain_inflight().await;
    assert_eq!(
        count_audit_rows(&client).await,
        before,
        "a malformed role wrote an audit row"
    );

    // Well-formed and not grantable: the denial, with its forensic row.
    let err = offer_dispatch(
        "role_grant_offer_create",
        &json!({ "to_account_id": recipient_account, "role": "no_such_role" }),
        &caller_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("an unregistered role is not grantable");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&err), ERROR_ROLE_GRANT_OFFER_ROLE_NOT_GRANTABLE);
    audit.drain_inflight().await;
    let row = client
        .query_one(
            "SELECT metadata->>'role' FROM audit_log
             WHERE event_type = 'role_grant_offer_create' AND outcome = 'failure'",
            &[],
        )
        .await
        .expect("the one failed create row");
    assert_eq!(row.get::<_, String>(0), "no_such_role");
    assert_eq!(count_audit_rows(&client).await, before + 1);
}

/// Counts the closures a handler queues for after its commit — the audit
/// listener fan-out and the WS notifications both go through it.
#[derive(Default)]
struct CountingPostCommit(std::sync::atomic::AtomicUsize);

impl fuz_auth::AuditPostCommit for CountingPostCommit {
    fn queue_notify(&self, _notify: fuz_auth::AuditNotifyFn) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// An admin offer from `grantor` to `recipient`, accepted once through the verb.
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
async fn offer_accepted_once(
    client: &deadpool_postgres::Client,
    grantor: &RequestActorContext,
    recipient_ctx: &AuthenticatedActionContext<'_>,
) -> (uuid::Uuid, Value) {
    let offer = query_role_grant_offer_create(
        client,
        CreateRoleGrantOfferInput {
            from_actor_id: grantor.actor.id,
            to_account_id: recipient_ctx.auth.account.id,
            to_actor_id: None,
            role: "admin".to_owned(),
            scope_kind: None,
            scope_id: None,
            message: None,
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    .expect("offer create");
    let accepted = offer_dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": offer.id }),
        recipient_ctx,
        ActionDb::Pool(client),
    )
    .await
    .expect("first accept");
    (offer.id, accepted)
}

/// Re-accepting an accepted offer whose grant still stands answers the same
/// grant and writes nothing: no audit row, nothing queued for after the
/// commit (no audit fan-out, no `role_grant_offer_accepted` to the grantor).
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_replay_answers_the_same_grant_and_writes_nothing() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let grantor = seed_actor_context(&pool, "grantor").await;
    fuz_testing::grant_role(&pool, grantor.actor.id, ROLE_ADMIN).await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let first_post_commit = CountingPostCommit::default();
    let mut first_ctx = ctx(&recipient, &audit, &closer);
    first_ctx.post_commit = &first_post_commit;
    let (offer_id, accepted) = offer_accepted_once(&client, &grantor, &first_ctx).await;
    assert!(
        first_post_commit
            .0
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0,
        "the accept itself queues its fan-out"
    );
    let rows_after_accept = count_audit_rows(&client).await;

    let replay_post_commit = CountingPostCommit::default();
    let mut replay_ctx = ctx(&recipient, &audit, &closer);
    replay_ctx.post_commit = &replay_post_commit;
    let replayed = offer_dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": offer_id }),
        &replay_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect("a replay of a held grant succeeds");

    assert_eq!(replayed["role_grant_id"], accepted["role_grant_id"]);
    assert_eq!(count_audit_rows(&client).await, rows_after_accept);
    assert_eq!(
        replay_post_commit
            .0
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a replay queues no audit fan-out and no notification"
    );
}

/// Once the grant an accept minted is revoked, replaying the accept is
/// terminal — never an OK carrying the revoked grant's id.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn accept_replay_after_the_grant_is_revoked_is_terminal() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let grantor = seed_actor_context(&pool, "grantor").await;
    fuz_testing::grant_role(&pool, grantor.actor.id, ROLE_ADMIN).await;
    let recipient = seed_actor_context(&pool, "recipient").await;
    let recipient_ctx = ctx(&recipient, &audit, &closer);
    let (offer_id, accepted) = offer_accepted_once(&client, &grantor, &recipient_ctx).await;
    let role_grant_id: uuid::Uuid = accepted["role_grant_id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .expect("role_grant_id");
    client
        .execute(
            "UPDATE role_grant SET revoked_at = NOW() WHERE id = $1",
            &[&role_grant_id],
        )
        .await
        .expect("revoke");
    let rows_after_revoke = count_audit_rows(&client).await;

    let err = offer_dispatch(
        "role_grant_offer_accept",
        &json!({ "offer_id": offer_id }),
        &recipient_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect_err("a replay after revoke must be refused");

    assert_eq!(err.code, JsonrpcErrorCode::InvalidRequest);
    assert_eq!(
        err.data,
        Some(json!({ "reason": ERROR_ROLE_GRANT_OFFER_TERMINAL }))
    );
    assert_eq!(count_audit_rows(&client).await, rows_after_revoke);
}

// --- role_grant_revoke: the revokee's outgoing offers, the admin guards ----

/// Whether the offer is still pending (no terminal column set).
#[allow(clippy::expect_used)] // test helper outside a `#[test]` fn
async fn offer_is_open(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    offer_id: uuid::Uuid,
) -> bool {
    client
        .query_one(
            "SELECT accepted_at IS NULL AND declined_at IS NULL
                AND retracted_at IS NULL AND superseded_at IS NULL
             FROM role_grant_offer WHERE id = $1",
            &[&offer_id],
        )
        .await
        .expect("offer row")
        .get(0)
}

/// Revoking a grant supersedes every pending offer its actor made — an offer
/// records no authority, so one made under the revoked grant would still
/// confer on accept — each audited `role_grant_revoked` with the revoked
/// grant as its cause. Another grantor's offer and the revokee's decided
/// offers are untouched.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
#[allow(clippy::expect_used)]
async fn role_grant_revoke_supersedes_the_revokees_outgoing_offers() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    seed_role_grant_direct(&pool, admin.actor.id, ROLE_ADMIN, None).await;
    let admin_ctx = ctx(&admin, &audit, &closer);
    let grantor = seed_actor_context(&pool, "revoked_grantor").await;
    let grant = seed_role_grant_direct(&pool, grantor.actor.id, ROLE_ADMIN, None).await;
    let (recipient_a, _) = seed_account_actor(&pool, "recipient_a").await;
    let (recipient_b, _) = seed_account_actor(&pool, "recipient_b").await;

    let outgoing = [
        offer_directly(&client, grantor.actor.id, recipient_a, ROLE_ADMIN).await,
        offer_directly(&client, grantor.actor.id, recipient_b, ROLE_ADMIN).await,
    ];
    let declined = offer_directly(&client, grantor.actor.id, admin.account.id, ROLE_ADMIN).await;
    client
        .execute(
            "UPDATE role_grant_offer SET declined_at = NOW() WHERE id = $1",
            &[&declined],
        )
        .await
        .expect("decline");
    let control = offer_directly(&client, admin.actor.id, recipient_a, ROLE_ADMIN).await;

    offer_dispatch(
        "role_grant_revoke",
        &json!({"actor_id": grantor.actor.id, "role_grant_id": grant}),
        &admin_ctx,
        ActionDb::Pool(&client),
    )
    .await
    .expect("revoke");

    for offer in outgoing {
        assert!(
            !offer_is_open(&client, offer).await,
            "the revokee's offer is superseded"
        );
        let superseded: bool = client
            .query_one(
                "SELECT superseded_at IS NOT NULL FROM role_grant_offer WHERE id = $1",
                &[&offer],
            )
            .await
            .expect("offer")
            .get(0);
        assert!(superseded);
        let metadata =
            audit_row_metadata(&client, "role_grant_offer_supersede", "offer_id", offer).await;
        assert_eq!(metadata["reason"], json!("role_grant_revoked"));
        assert_eq!(metadata["cause_id"], json!(grant.to_string()));
    }
    assert!(
        offer_is_open(&client, control).await,
        "another grantor's offer stays pending"
    );
    let declined_superseded: bool = client
        .query_one(
            "SELECT superseded_at IS NOT NULL FROM role_grant_offer WHERE id = $1",
            &[&declined],
        )
        .await
        .expect("declined")
        .get(0);
    assert!(!declined_superseded, "a decided offer is left as it was");
}

/// `role_grant_revoke` refuses the keeper account's global `admin` grant — no
/// web path grants it back — and the last active admin's; a second active
/// admin lifts the last-admin guard, never the keeper one. A refusal leaves
/// the grant active.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
#[allow(clippy::expect_used)]
async fn role_grant_revoke_guards_the_keeper_and_the_last_admin() {
    use fuz_auth::role::ROLE_KEEPER;
    use fuz_auth::role_grant_offer_action_specs::{
        ERROR_CANNOT_REVOKE_KEEPER_ADMIN, ERROR_CANNOT_REVOKE_LAST_ADMIN,
    };
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    // the caller holds admin in memory only: the DB's admins are seeded below
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let admin_ctx = ctx(&admin, &audit, &closer);
    let revoke = |actor_id: uuid::Uuid, role_grant_id: uuid::Uuid| {
        let admin_ctx = &admin_ctx;
        let client = &client;
        async move {
            offer_dispatch(
                "role_grant_revoke",
                &json!({"actor_id": actor_id, "role_grant_id": role_grant_id}),
                admin_ctx,
                ActionDb::Pool(client),
            )
            .await
        }
    };
    let active = |role_grant_id: uuid::Uuid| {
        let client = &client;
        async move {
            client
                .query_one(
                    "SELECT revoked_at IS NULL FROM role_grant WHERE id = $1",
                    &[&role_grant_id],
                )
                .await
                .expect("grant")
                .get::<_, bool>(0)
        }
    };

    // the keeper, the only admin: the keeper guard answers first
    let (_, keeper_actor) = seed_account_actor(&pool, "the_keeper").await;
    seed_role_grant_direct(&pool, keeper_actor, ROLE_KEEPER, None).await;
    let keeper_admin = seed_role_grant_direct(&pool, keeper_actor, ROLE_ADMIN, None).await;
    let err = revoke(keeper_actor, keeper_admin)
        .await
        .expect_err("keeper");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&err), ERROR_CANNOT_REVOKE_KEEPER_ADMIN);
    assert!(active(keeper_admin).await);

    // a sole non-keeper admin (the keeper's admin aside, tombstoned here so it
    // doesn't count)
    client
        .execute(
            "UPDATE account SET deleted_at = NOW()
             WHERE id = (SELECT account_id FROM actor WHERE id = $1)",
            &[&keeper_actor],
        )
        .await
        .expect("tombstone the keeper");
    let (_, sole_actor) = seed_account_actor(&pool, "sole_admin").await;
    let sole_admin = seed_role_grant_direct(&pool, sole_actor, ROLE_ADMIN, None).await;
    let err = revoke(sole_actor, sole_admin)
        .await
        .expect_err("last admin");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&err), ERROR_CANNOT_REVOKE_LAST_ADMIN);
    assert!(active(sole_admin).await);

    // a second active admin lifts the last-admin guard
    let (_, second_actor) = seed_account_actor(&pool, "second_admin").await;
    seed_role_grant_direct(&pool, second_actor, ROLE_ADMIN, None).await;
    revoke(sole_actor, sole_admin)
        .await
        .expect("not the last admin now");
    assert!(!active(sole_admin).await);

    // and never the keeper's: with other admins around it still refuses
    client
        .execute(
            "UPDATE account SET deleted_at = NULL
             WHERE id = (SELECT account_id FROM actor WHERE id = $1)",
            &[&keeper_actor],
        )
        .await
        .expect("restore the keeper");
    let err = revoke(keeper_actor, keeper_admin)
        .await
        .expect_err("keeper again");
    assert_eq!(reason(&err), ERROR_CANNOT_REVOKE_KEEPER_ADMIN);
    assert!(active(keeper_admin).await);
}

/// The last-admin guard counts admin accounts without the grant being revoked:
/// on the sole admin account, an admin grant on a second actor — active or
/// tombstoned — goes while the first actor's remains, and the last remaining
/// one is refused.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
#[allow(clippy::expect_used)]
async fn role_grant_revoke_last_admin_counts_without_the_revoked_grant() {
    use fuz_auth::role_grant_offer_action_specs::ERROR_CANNOT_REVOKE_LAST_ADMIN;
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let audit = build_audit(pool.clone());
    let closer = closer();
    // the caller holds admin in memory only: the DB's admins are seeded below
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let admin_ctx = ctx(&admin, &audit, &closer);
    let revoke = |actor_id: uuid::Uuid, role_grant_id: uuid::Uuid| {
        let admin_ctx = &admin_ctx;
        let client = &client;
        async move {
            offer_dispatch(
                "role_grant_revoke",
                &json!({"actor_id": actor_id, "role_grant_id": role_grant_id}),
                admin_ctx,
                ActionDb::Pool(client),
            )
            .await
        }
    };
    let active = |role_grant_id: uuid::Uuid| {
        let client = &client;
        async move {
            client
                .query_one(
                    "SELECT revoked_at IS NULL FROM role_grant WHERE id = $1",
                    &[&role_grant_id],
                )
                .await
                .expect("grant")
                .get::<_, bool>(0)
        }
    };

    // the sole admin account, its admin grant on three actors
    let (account_id, first_actor) = seed_account_actor(&pool, "multi_actor_admin").await;
    let first_admin = seed_role_grant_direct(&pool, first_actor, ROLE_ADMIN, None).await;
    let second_actor = seed_extra_actor(&pool, account_id, "second_persona").await;
    let second_admin = seed_role_grant_direct(&pool, second_actor, ROLE_ADMIN, None).await;
    let tombstoned_actor = seed_extra_actor(&pool, account_id, "tombstoned_persona").await;
    let tombstoned_admin = seed_role_grant_direct(&pool, tombstoned_actor, ROLE_ADMIN, None).await;
    client
        .execute(
            "UPDATE actor SET deleted_at = NOW() WHERE id = $1",
            &[&tombstoned_actor],
        )
        .await
        .expect("tombstone the actor");

    revoke(tombstoned_actor, tombstoned_admin)
        .await
        .expect("a tombstoned actor's grant, an active admin remaining");
    assert!(!active(tombstoned_admin).await);

    revoke(second_actor, second_admin)
        .await
        .expect("the first actor's grant keeps the account an admin");
    assert!(!active(second_admin).await);

    let err = revoke(first_actor, first_admin)
        .await
        .expect_err("the last remaining admin grant");
    assert_eq!(err.code, JsonrpcErrorCode::Forbidden);
    assert_eq!(reason(&err), ERROR_CANNOT_REVOKE_LAST_ADMIN);
    assert!(active(first_admin).await);
}

/// Two concurrent `role_grant_revoke`s of each other's global `admin` grant,
/// the last two admin accounts: the last-admin guard's locked count serializes
/// them, so exactly one lands and the other is refused 403
/// `cannot_revoke_last_admin` — never a deadlock surfacing as an internal
/// error. A holder transaction locks both grants first so both revokes park
/// inside the guard's count, then releases them together. Twin of `fuz_app`'s
/// `role_grant_offer_actions.revoke_race.db.test.ts`.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
#[allow(clippy::expect_used)]
async fn cross_revokes_of_the_last_two_admins_serialize() {
    use fuz_auth::role_grant_offer_action_specs::ERROR_CANNOT_REVOKE_LAST_ADMIN;
    let pool = fresh_db_pool().await;
    let audit = build_audit(pool.clone());
    let closer = closer();
    // the caller holds admin in memory only: the DB's admins are seeded below
    let admin = with_grant(seed_admin(&pool).await, ROLE_ADMIN, None);
    let admin_ctx = ctx(&admin, &audit, &closer);
    let (_, one_actor) = seed_account_actor(&pool, "cross_admin_one").await;
    let one_admin = seed_role_grant_direct(&pool, one_actor, ROLE_ADMIN, None).await;
    let (_, two_actor) = seed_account_actor(&pool, "cross_admin_two").await;
    let two_admin = seed_role_grant_direct(&pool, two_actor, ROLE_ADMIN, None).await;

    // hold both grants so each revoke parks inside the guard's locked count
    let mut holder_client = pool.get().await.expect("pool.get");
    let holder = holder_client.transaction().await.expect("begin");
    holder
        .execute(
            "SELECT id FROM role_grant WHERE id = ANY($1) FOR UPDATE",
            &[&vec![one_admin, two_admin]],
        )
        .await
        .expect("hold the grants");

    let revoke = |actor_id: uuid::Uuid, role_grant_id: uuid::Uuid| {
        let pool = pool.clone();
        let admin_ctx = &admin_ctx;
        async move {
            let mut client = pool.get().await.expect("pool.get");
            let tx = client.transaction().await.expect("begin");
            let result = offer_dispatch(
                "role_grant_revoke",
                &json!({"actor_id": actor_id, "role_grant_id": role_grant_id}),
                admin_ctx,
                ActionDb::Tx(&tx),
            )
            .await;
            if result.is_ok() {
                tx.commit().await.expect("commit");
            } else {
                tx.rollback().await.expect("rollback");
            }
            result
        }
    };
    let release = async {
        // both revokes are waiting on the holder's row locks
        let observer = pool.get().await.expect("pool.get");
        let mut polls = 0;
        loop {
            let waiting: i64 = observer
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity
                     WHERE datname = current_database() AND wait_event_type = 'Lock'",
                    &[],
                )
                .await
                .expect("pg_stat_activity")
                .get(0);
            if waiting >= 2 {
                break;
            }
            polls += 1;
            assert!(polls < 1000, "both revokes reach the guard");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        holder.commit().await.expect("release");
    };
    let (first, second, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            revoke(two_actor, two_admin),
            revoke(one_actor, one_admin),
            release
        )
    })
    .await
    .expect("the revokes complete");

    let results = [first, second];
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "exactly one revoke lands: {results:?}"
    );
    let refusal = results
        .iter()
        .find_map(|r| r.as_ref().err())
        .expect("one refusal");
    assert_eq!(refusal.code, JsonrpcErrorCode::Forbidden, "{refusal:?}");
    assert_eq!(reason(refusal), ERROR_CANNOT_REVOKE_LAST_ADMIN);

    let client = pool.get().await.expect("pool.get");
    let active: i64 = client
        .query_one(
            "SELECT count(*) FROM role_grant WHERE id = ANY($1) AND revoked_at IS NULL",
            &[&vec![one_admin, two_admin]],
        )
        .await
        .expect("active grants")
        .get(0);
    assert_eq!(active, 1, "one admin grant survives");
}
