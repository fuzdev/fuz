//! Shared test setup for `fuz_auth`'s PG-backed integration tests.
//!
//! Lives under `tests/common/` so Cargo doesn't compile it as its own
//! test binary — each PG-backed integration test file includes it via
//! `mod common;` and pulls the helpers it needs.
//!
//! Helpers here cover:
//! - The fresh database every DB test opens ([`fresh_db`], and
//!   [`fresh_postgres_db`] for a Postgres-only test), thin calls into the
//!   shared `fuz_testing::fresh_test_db`.
//! - Account / actor / audit-row seeding shared across the PG-backed
//!   integration-test files ([`seed_admin`], [`seed_account`],
//!   [`seed_audit_log_row`], [`seed_role_grant_direct`]), over the spine-wide
//!   `fuz_testing::seed_account_actor` the suites also call directly.
//! - The [`AuthenticatedActionContext`] construction triad
//!   ([`build_audit`], [`closer`], [`ctx`]) for tests that dispatch
//!   through `AdminActionSpecs`.
//! - [`budgeted_pool`], the fault for a checkout made after the credential
//!   walk's own.
//!
//! The lock-race kit the race suites share (`in_tx!`, `race!`, and the
//! lock-wait observers) is `fuz_testing`'s.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::Arc;

use fuz_auth::request_context::RequestActorContext;
use fuz_auth::{
    AUTH_MIGRATIONS, AccountRow, ActorRow, AuditEmitter, AuthenticatedActionContext,
    CollectingAuditPostCommit, ConnectionCloser, CredentialType, NoopAuditPostCommit,
    NoopConnectionCloser, NoopNotificationSender, NotificationSender,
};
use fuz_db::Pool;
use fuz_testing::{TestDb, TestEngine, TestingDbOptions, seed_account_actor};
use serde_json::Value;

/// This suite's database: the auth chain, no scratch DDL.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    suite: "fuz_auth",
    migrations: &[AUTH_MIGRATIONS],
    setup_sql: None,
    engine: TestEngine::Any,
};

/// Dispatch an admin action with the builtin-only [`fuz_auth::RoleRegistry`].
///
/// The thin test seam over `AdminActionSpecs::dispatch` so the registry param
/// (added for registry-driven grantability) doesn't thread through every
/// callsite — these suites exercise the builtin roles, where the default
/// registry is exactly right.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn admin_dispatch(
    method: &str,
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, fuz_http::JsonrpcError> {
    fuz_auth::admin_action_specs::AdminActionSpecs::dispatch(
        method,
        params,
        ctx,
        db,
        &fuz_auth::RoleRegistry::default(),
    )
    .await
}

/// A fresh database with the auth chain, ready for the test body's own
/// fixture seeding.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn fresh_db() -> TestDb {
    DB.open().await
}

/// [`fresh_db`] on PostgreSQL alone, for a test of what only PostgreSQL has.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn fresh_postgres_db() -> TestDb {
    DB.postgres_only().open().await
}

/// Seed an admin (`account` + `actor`) and return a `RequestActorContext`
/// usable as `AuthenticatedActionContext::auth`.
///
/// Tests bypass the action-auth gates and dispatch directly, so the seeded
/// `role_grant` row is omitted — `AdminActionSpecs::dispatch` doesn't
/// re-check role grants. The fixture is just here so `auth.account.id`
/// / `auth.actor.id` line up with real DB rows for audit-emit FKs.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn seed_admin(pool: &Pool) -> RequestActorContext {
    seed_actor_context(pool, "admin_keeper").await
}

/// Seed an `account` + `actor` pair and return a `RequestActorContext`
/// bound to them.
///
/// [`seed_admin`]'s participant-shaped sibling — same two rows, but the
/// username is the caller's and no admin framing is implied. Lifecycle
/// suites need one context per *side* of a flow (the grantor retracts, the
/// recipient declines), so both sides come from here.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn seed_actor_context(pool: &Pool, username: &str) -> RequestActorContext {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    RequestActorContext {
        account: AccountRow {
            id: account_id,
            username: username.to_owned(),
        },
        actor: ActorRow {
            id: actor_id,
            account_id,
            name: username.to_owned(),
        },
        role_grants: Vec::new(),
    }
}

/// Seed a plain account (no actor) with a given username and optional
/// email. Returns the account id.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn seed_account(pool: &Pool, username: &str, email: Option<&str>) -> uuid::Uuid {
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "INSERT INTO account (username, password_hash, email)
             VALUES ($1, 'x', $2) RETURNING id",
            &[&username, &email],
        )
        .await
        .expect("insert account");
    row.get(0)
}

/// Seed an `audit_log` row directly, bypassing the emitter. Used by
/// `admin_lists.rs` to populate forensic data for `audit_log_list`
/// filter tests without driving real handler flows.
///
/// `metadata` is passed as `serde_json::Value`; the column is JSONB.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the audit row's natural FK fan-out"
)]
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn seed_audit_log_row(
    pool: &Pool,
    event_type: &str,
    outcome: &str,
    actor_id: Option<uuid::Uuid>,
    account_id: Option<uuid::Uuid>,
    target_account_id: Option<uuid::Uuid>,
    target_actor_id: Option<uuid::Uuid>,
    metadata: Option<Value>,
) -> uuid::Uuid {
    let client = pool.get().await.expect("pool.get");
    let metadata_text = metadata.map(|v| v.to_string());
    let row = client
        .query_one(
            "INSERT INTO audit_log (event_type, outcome, actor_id, account_id,
                                    target_account_id, target_actor_id, metadata)
             VALUES ($1, $2, $3, $4, $5, $6, $7::text::jsonb)
             RETURNING id",
            &[
                &event_type,
                &outcome,
                &actor_id,
                &account_id,
                &target_account_id,
                &target_actor_id,
                &metadata_text,
            ],
        )
        .await
        .expect("insert audit_log");
    row.get(0)
}

/// Seed a `role_grant` row directly (no offer/accept flow). Used by
/// `audit_log_role_grant_history` tests that need a real `role_grant`
/// referenced by a `role_grant_create` audit row.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub async fn seed_role_grant_direct(
    pool: &Pool,
    actor_id: uuid::Uuid,
    role: &str,
    granted_by: Option<uuid::Uuid>,
) -> uuid::Uuid {
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "INSERT INTO role_grant (actor_id, role, granted_by)
             VALUES ($1, $2, $3) RETURNING id",
            &[&actor_id, &role, &granted_by],
        )
        .await
        .expect("insert role_grant");
    row.get(0)
}

/// Build an `Arc<AuditEmitter>` pointed at the test pool — handlers fire
/// audit emissions through this; the spawned write tasks hit the same
/// shared DB and become visible to subsequent queries (after a small
/// settle, since emit is fire-and-forget).
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub fn build_audit(pool: Pool) -> Arc<AuditEmitter> {
    Arc::new(AuditEmitter::new(pool, Arc::default()))
}

/// Default no-op connection closer for handler tests.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub fn closer() -> Arc<dyn ConnectionCloser> {
    Arc::new(NoopConnectionCloser)
}

/// Build an `AuthenticatedActionContext` from the seeded auth + audit + closer
/// triad. Sets `client_ip: Some("127.0.0.1")` matching the integration
/// tests' default, and `credential_type: Some(Session)` — the browser caller,
/// which every handler admits; a test of a handler's own credential gate
/// overrides the field.
///
/// `post_commit` is fixed at `&NoopAuditPostCommit` — tests dispatch
/// handlers directly (no transaction wrap), so in-tx audit emits
/// INSERT immediately on the pool client and the post-commit notify
/// has nowhere to drain to. Tests that read `audit_log` rows directly
/// continue to work; tests that depend on listener fan-out would need
/// a synchronous test post-commit (none exist today).
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub fn ctx<'a>(
    auth: &'a RequestActorContext,
    audit: &'a Arc<AuditEmitter>,
    closer: &'a Arc<dyn ConnectionCloser>,
) -> AuthenticatedActionContext<'a> {
    AuthenticatedActionContext {
        auth,
        credential_type: Some(CredentialType::Session),
        audit,
        post_commit: &NoopAuditPostCommit,
        connection_closer: closer,
        notification_sender: noop_notification_sender(),
        client_ip: Some("127.0.0.1".to_owned()),
    }
}

/// Shared `'static` no-op notification sender for the test context
/// helper — lets `ctx()` keep its 3-arg signature while supplying the
/// new `notification_sender` field (tests don't observe WS fan-out).
/// `pub` so account-grain contexts (`api_token.rs`) can borrow it too.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub fn noop_notification_sender() -> &'static Arc<dyn NotificationSender> {
    static SENDER: std::sync::OnceLock<Arc<dyn NotificationSender>> = std::sync::OnceLock::new();
    SENDER.get_or_init(|| Arc::new(NoopNotificationSender))
}

/// A [`NotificationSender`] that records every send — the target account and
/// the frame parsed back to JSON — so a test reads what a handler's post-commit
/// drain sent, in order.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
#[derive(Debug, Default)]
pub struct RecordingNotificationSender {
    sent: parking_lot::Mutex<Vec<(uuid::Uuid, Value)>>,
}

#[allow(dead_code, reason = "each test binary uses only part of this module")]
impl RecordingNotificationSender {
    /// Take every send recorded so far, in order, leaving none.
    pub fn take(&self) -> Vec<(uuid::Uuid, Value)> {
        std::mem::take(&mut *self.sent.lock())
    }
}

impl NotificationSender for RecordingNotificationSender {
    fn send_to_account(&self, account_id: uuid::Uuid, message: &str) -> usize {
        let frame = serde_json::from_str(message).expect("a notification frame is JSON");
        self.sent.lock().push((account_id, frame));
        1
    }
}

/// [`ctx`] with a post-commit that collects the handler's queued effects and
/// a sender of the test's own — a test that observes fan-out runs the
/// handler, drains `post_commit` as the dispatcher would after its commit,
/// then reads the sender.
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub fn ctx_observed<'a>(
    auth: &'a RequestActorContext,
    audit: &'a Arc<AuditEmitter>,
    closer: &'a Arc<dyn ConnectionCloser>,
    post_commit: &'a CollectingAuditPostCommit,
    notification_sender: &'a Arc<dyn NotificationSender>,
) -> AuthenticatedActionContext<'a> {
    AuthenticatedActionContext {
        post_commit,
        notification_sender,
        ..ctx(auth, audit, closer)
    }
}

/// [`fuz_testing::budgeted_pool`] on `db`: `checkouts` connections, then every
/// checkout refused — the fault for a handler that checks a connection out
/// *after* its credential was resolved on an earlier one (a pool that is simply
/// down fails the credential read first, and that is the credential-read
/// fault's answer, never the handler's own arm).
#[allow(dead_code, reason = "each test binary uses only part of this module")]
pub fn budgeted_pool(db: &TestDb, checkouts: usize) -> Pool {
    fuz_testing::budgeted_pool(db.url(), checkouts)
}
