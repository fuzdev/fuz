//! PG-backed end-to-end tests for [`fuz_actions::perform_action`] — the
//! integrated dispatch path the sibling `perform_action.rs` (no-DB) unit tests
//! deliberately don't reach.
//!
//! These drive `perform_action` itself with a real pool + registry, pinning the
//! two properties that are **invisible to the cross-backend suite** (which sees
//! only the wire envelope, never the transaction): the **transactional-audit
//! boundary** and **rollback-discards-effects through a real tx**. The
//! enforcement order (`method_not_found` → 401 → authz → 403 → 429 → 400 → handler) is also
//! driven here against the dispatcher, where the cross-backend suite drives it
//! over HTTP/WS. So is the **revocation close order**: the auth spec set's
//! revocation handlers — and `account_token_create`, for the token its cap
//! evicts — close sockets only once their deletion has committed
//! (`fuz_auth::queue_connection_close`), which the wire can only observe as a race.
//!
//! ## Rollback semantics
//!
//! On a handler that pushes a post-commit effect and then fails, the effect is
//! **discarded** — the dispatcher's `settle_effects` calls
//! `post_commit_effects.clear()` without draining, so a rolled-back
//! transaction never announces state that didn't commit. `fuz_app`'s TS twin
//! holds the same contract (`dispatch_with_post_commit_rollback`).
//!
//! A failed commit is a rollback too, including the one `PostgreSQL` hides: a
//! handler that swallows a failed statement and returns `Ok` leaves the
//! transaction aborted, and `COMMIT` then rolls back without an error. The
//! dispatcher commits through `fuz_db::commit_checked`, which detects the
//! aborted transaction, so the action fails and its effects are discarded.
//! The TS twin's `COMMIT` (node-postgres and `PGlite` alike) has no such check.
//!
//! The suite has its own `FUZ_ACTIONS_TEST_URL` (default `fuz_actions_test`)
//! database — cross-crate `#[ignore]` test binaries run in parallel and would
//! clobber a shared schema. It runs only the auth migrations (for `audit_log` +
//! `account` / `actor` / `role_grant`) plus a scratch `probe` table.
//!
//! `#[ignore]`-gated — run:
//! ```text
//! createdb fuz_actions_test
//! cargo test -p fuz_actions --test perform_action_dispatch -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::StatusCode;
use futures::StreamExt;
use fuz_actions::perform_action::{PerformActionInput, PerformActionOptions, perform_action};
use fuz_actions::{
    ActionHandler, ActionOutput, ActionOutputHandler, ActionRegistry, ActionSpec,
    write_success_response,
};
use fuz_auth::ConnectionCloseTarget;
use fuz_auth::{
    AUTH_MIGRATIONS, AccountRow, AuditEmitter, AuditEventType, AuditLogInput, AuthSpec,
    CredentialGate, CredentialType, NoopConnectionCloser, NoopNotificationSender, ROLE_ADMIN,
    RateLimitClass, RateLimiter, RateLimiterOptions,
};
use fuz_db::ActionDb;
use fuz_db::Pool;
use fuz_http::InputShape;
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::SignalToken;
use fuz_testing::{
    TestingDbOptions, fresh_test_db_pool, grant_role, grant_scoped_role, refuse_audit_rows,
    seed_account_actor,
};
use serde_json::{Value, json};

const ADMIN_ROLES: &[&str] = &[ROLE_ADMIN];

/// This suite's database: `FUZ_ACTIONS_TEST_URL` (default
/// `fuz_actions_test`), the auth chain (for `audit_log` + `account` /
/// `actor` / `role_grant`), plus the scratch `probe` table the
/// side-effecting test handler writes into.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_ACTIONS_TEST_URL",
    default_db: "fuz_actions_test",
    migrations: &[AUTH_MIGRATIONS],
    setup_sql: Some("CREATE TABLE probe (id serial PRIMARY KEY)"),
};

/// Reset the schema, run the auth chain, and stand up the scratch `probe`
/// table. Single-threaded (the reset drops + recreates `public`).
async fn fresh_db_pool() -> Pool {
    fresh_test_db_pool(DB).await
}

/// Test harness: the dispatcher options + the pool + a flag the `probe`
/// handler's queued post-commit effect flips when it runs.
struct Harness {
    options: PerformActionOptions,
    pool: Pool,
    effect_fired: Arc<AtomicBool>,
}

/// Build the registry of test specs:
/// - `probe` (public, side-effecting): writes a `probe` row, emits an in-tx
///   audit row (`cell_create` → `InTx` routing), queues a post-commit effect
///   that flips `effect_fired`, then fails iff `params.fail == true`.
/// - `probe_swallow` (public, side-effecting): `probe`'s writes and effect,
///   then a failing statement whose error it drops before returning `Ok` —
///   the handler bug the dispatcher's checked commit catches. With
///   `params.recover == true` it recovers properly instead, through a
///   savepoint, so the commit goes through.
/// - `probe_ro` (public, read-only): queues the same effect, fails iff
///   `params.fail == true` (drives the no-tx `dispatch_pooled` Ok/Err arms).
/// - `needs_account` (authenticated): trivial `Ok` — for the 401 gate.
/// - `needs_admin` (authenticated + `roles: [admin]`): trivial `Ok` — for the
///   403 role gate over the *resolved* actor + the admit (200) path.
/// - `throttled` (authenticated + `rate_limit: Account`): trivial `Ok` — for
///   the 429-before-400 ordering, driven against a budget-1 account limiter.
/// - `probe_void` (public, read-only, [`InputShape::Void`]): queues the same
///   effect and never reads `params` — for the dispatcher's void rule.
/// - `needs_account_void` (account-grain, [`InputShape::Void`]): trivial `Ok`
///   — for the void rule sitting behind the 401.
/// - `throttled_void` (account-grain + `rate_limit: Account`,
///   [`InputShape::Void`]): trivial `Ok` — for the void rule sitting behind
///   the 429, driven against a budget-1 account limiter.
/// - `typed_output` (public, read-only, [`ActionSpec::new_output`]): queues the
///   same effect and returns a typed [`ActionOutput`] — for the output-handler
///   arm of the dispatcher.
fn build_registry(effect_fired: &Arc<AtomicBool>) -> ActionRegistry {
    let probe_handler: ActionHandler = {
        let effect_fired = Arc::clone(effect_fired);
        Arc::new(move |params, ctx| {
            let effect_fired = Arc::clone(&effect_fired);
            Box::pin(async move {
                // side_effects: true ⇒ the dispatcher hands an in-tx client.
                let ActionDb::Tx(tx) = &ctx.db else {
                    return Err(fuz_http::internal_error("probe expects an in-tx client"));
                };
                let tx = *tx;
                tx.execute("INSERT INTO probe DEFAULT VALUES", &[])
                    .await
                    .map_err(|e| fuz_http::internal_error_with_source("probe insert", &e))?;
                // In-tx audit emit (cell_create routes InTx on success) — joins
                // the handler's tx, so it commits or rolls back atomically.
                ctx.audit_emit(
                    tx,
                    AuditLogInput::for_event(AuditEventType::CellCreate)
                        .metadata(json!({"probe": true})),
                )
                .await?;
                // Queue a post-commit effect — drained on commit, discarded on
                // rollback.
                ctx.post_commit_effects
                    .push_fn(move || async move { effect_fired.store(true, Ordering::SeqCst) });
                if params.get("fail").and_then(Value::as_bool) == Some(true) {
                    return Err(fuz_http::internal_error(
                        "intentional probe failure (rollback)",
                    ));
                }
                Ok(json!({ "ok": true }))
            })
        })
    };

    let swallow_handler: ActionHandler = {
        let effect_fired = Arc::clone(effect_fired);
        Arc::new(move |params, ctx| {
            let effect_fired = Arc::clone(&effect_fired);
            Box::pin(async move {
                let ActionDb::Tx(tx) = &ctx.db else {
                    return Err(fuz_http::internal_error("probe expects an in-tx client"));
                };
                let tx = *tx;
                tx.execute("INSERT INTO probe DEFAULT VALUES", &[])
                    .await
                    .map_err(|e| fuz_http::internal_error_with_source("probe insert", &e))?;
                ctx.audit_emit(
                    tx,
                    AuditLogInput::for_event(AuditEventType::CellCreate)
                        .metadata(json!({"probe": true})),
                )
                .await?;
                ctx.post_commit_effects
                    .push_fn(move || async move { effect_fired.store(true, Ordering::SeqCst) });
                let recover = params.get("recover").and_then(Value::as_bool) == Some(true);
                if recover {
                    tx.batch_execute("SAVEPOINT before_failure")
                        .await
                        .map_err(|e| fuz_http::internal_error_with_source("savepoint", &e))?;
                }
                // The bug under test: a failed statement whose error is
                // dropped. The division fails at execution, aborting the tx.
                let failed = tx.execute("SELECT 1 / 0", &[]).await;
                assert!(failed.is_err(), "the swallowed statement must fail");
                if recover {
                    tx.batch_execute("ROLLBACK TO SAVEPOINT before_failure")
                        .await
                        .map_err(|e| fuz_http::internal_error_with_source("rollback to", &e))?;
                }
                Ok(json!({ "ok": true }))
            })
        })
    };

    let ro_handler: ActionHandler = {
        let effect_fired = Arc::clone(effect_fired);
        Arc::new(move |params, ctx| {
            let effect_fired = Arc::clone(&effect_fired);
            Box::pin(async move {
                ctx.post_commit_effects
                    .push_fn(move || async move { effect_fired.store(true, Ordering::SeqCst) });
                if params.get("fail").and_then(Value::as_bool) == Some(true) {
                    return Err(fuz_http::internal_error("intentional read-only failure"));
                }
                Ok(json!({ "ok": true }))
            })
        })
    };

    let typed_output_handler: ActionOutputHandler = {
        let effect_fired = Arc::clone(effect_fired);
        Arc::new(move |_params, ctx| {
            let effect_fired = Arc::clone(&effect_fired);
            Box::pin(async move {
                ctx.post_commit_effects
                    .push_fn(move || async move { effect_fired.store(true, Ordering::SeqCst) });
                Ok(ActionOutput::serialize(TypedOutput {
                    files: vec!["a".to_owned(), "b".to_owned()],
                    ok: true,
                }))
            })
        })
    };

    let ok_handler = || -> ActionHandler {
        Arc::new(|_params, _ctx| Box::pin(async move { Ok(json!({ "ok": true })) }))
    };

    // Ignores `params` entirely, as a parameterless handler may — the void
    // refusal is the dispatcher's, from the spec's declared shape.
    let void_handler: ActionHandler = {
        let effect_fired = Arc::clone(effect_fired);
        Arc::new(move |_params, ctx| {
            let effect_fired = Arc::clone(&effect_fired);
            Box::pin(async move {
                ctx.post_commit_effects
                    .push_fn(move || async move { effect_fired.store(true, Ordering::SeqCst) });
                Ok(json!({ "ok": true }))
            })
        })
    };

    ActionRegistry::compile(vec![
        ActionSpec::with_side_effects(
            "probe",
            AuthSpec::public(),
            InputShape::Object,
            probe_handler,
        ),
        ActionSpec::with_side_effects(
            "probe_swallow",
            AuthSpec::public(),
            InputShape::Object,
            swallow_handler,
        ),
        ActionSpec::read_only(
            "probe_ro",
            AuthSpec::public(),
            InputShape::Object,
            ro_handler,
        ),
        ActionSpec::with_side_effects(
            "needs_account",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            ok_handler(),
        ),
        ActionSpec::with_side_effects(
            "needs_admin",
            AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
            InputShape::Object,
            ok_handler(),
        ),
        ActionSpec::with_side_effects(
            "throttled",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            ok_handler(),
        )
        .with_rate_limit(RateLimitClass::Account),
        ActionSpec::read_only(
            "probe_void",
            AuthSpec::public(),
            InputShape::Void,
            void_handler,
        ),
        ActionSpec::read_only(
            "needs_account_void",
            AuthSpec::account_grain(CredentialGate::Any),
            InputShape::Void,
            ok_handler(),
        ),
        ActionSpec::read_only(
            "throttled_void",
            AuthSpec::account_grain(CredentialGate::Any),
            InputShape::Void,
            ok_handler(),
        )
        .with_rate_limit(RateLimitClass::Account),
        ActionSpec::new_output(
            "typed_output",
            AuthSpec::public(),
            InputShape::Object,
            false,
            typed_output_handler,
        ),
    ])
    .expect("compile registry")
}

/// The `typed_output` handler's result.
#[derive(serde::Serialize)]
struct TypedOutput {
    files: Vec<String>,
    ok: bool,
}

async fn setup() -> Harness {
    setup_with_account_budget(None).await
}

/// `setup` with an optional per-account action budget, for the rate-limit
/// ordering case. `Some(n)` wires a limiter of `n` attempts over a window long
/// enough that nothing expires mid-test; `None` leaves both axes unlimited.
async fn setup_with_account_budget(max_attempts: Option<u32>) -> Harness {
    let pool = fresh_db_pool().await;
    let effect_fired = Arc::new(AtomicBool::new(false));
    let account_rate_limiter = max_attempts.map(|max_attempts| {
        Arc::new(RateLimiter::new(RateLimiterOptions {
            max_attempts,
            window_ms: 60_000,
            max_keys: None,
        }))
    });
    let options = PerformActionOptions {
        pool: pool.clone(),
        registry: Arc::new(build_registry(&effect_fired)),
        audit: Arc::new(AuditEmitter::new(pool.clone())),
        connection_closer: Arc::new(NoopConnectionCloser),
        notification_sender: Arc::new(NoopNotificationSender),
        // This suite drives HTTP-shaped dispatch (no socket); the Noop peer
        // returns NoTransport, which no spec under test invokes.
        peer: fuz_realtime::noop_action_peer(),
        account_rate_limiter,
        ip_rate_limiter: None,
    };
    Harness {
        options,
        pool,
        effect_fired,
    }
}

/// Drive one `perform_action` call. Borrows live on this frame for the
/// borrowed `PerformActionInput`.
async fn run(
    options: &PerformActionOptions,
    method: &str,
    params: Value,
    account: Option<&AccountRow>,
    credential_type: Option<CredentialType>,
) -> Result<ActionOutput, fuz_http::JsonrpcError> {
    let request_id = json!(1);
    let signal = SignalToken::new();
    let span = tracing::Span::none();
    let notify: &(dyn Fn(&str, &Value) + Send + Sync) = &fuz_realtime::http_no_op_notify;
    // A real credential on the account, resolved through the walk. These cases
    // exercise the dispatch pipeline (tx boundary, audit, rollback), not the
    // scope axis — a full-scope credential keeps the scope gate transparent.
    // The scope gate's own cases live in `fuz_auth`'s `action_auth` unit
    // tests, where they need no DB.
    let auth = match (account, credential_type) {
        (Some(account), Some(credential_type)) => Some(
            fuz_testing::resolve_test_credential(&options.pool, account.id, credential_type).await,
        ),
        (None, None) => None,
        _ => panic!("an account and its credential type come together"),
    };
    let input = PerformActionInput {
        method,
        params: &params,
        request_id: &request_id,
        auth: auth.as_ref(),
        client_ip: None,
        connection_id: None,
        notify,
        signal: &signal,
        log: &span,
    };
    perform_action(input, options).await
}

/// Seed an `account` + a single `actor` (so the authorization phase resolves it
/// without an `acting` selector) plus `roles` as actor role grants. Returns the
/// `AccountRow` the dispatcher takes as account-grain identity.
async fn seed_account(pool: &Pool, username: &str, roles: &[&str]) -> AccountRow {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    for role in roles {
        grant_role(pool, actor_id, role).await;
    }
    AccountRow {
        id: account_id,
        username: username.to_owned(),
    }
}

async fn count(pool: &Pool, table: &str) -> i64 {
    let client = pool.get().await.unwrap();
    client
        .query_one(&format!("SELECT count(*) FROM {table}"), &[])
        .await
        .unwrap()
        .get(0)
}

fn assert_status(result: &Result<ActionOutput, fuz_http::JsonrpcError>, expected: StatusCode) {
    match result {
        Err(error) => {
            let status = fuz_http::error_code_to_http_status(error.code);
            assert_eq!(status, expected, "unexpected error: {error:?}");
        }
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
    }
}

// -- Transactional boundary: commit drains, rollback discards ----------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn output_handler_result_renders_its_typed_output() {
    // An `ActionSpec::new_output` handler runs through the same pipeline — its
    // post-commit effect drains — and its typed output renders as the JSON a
    // `Value` handler returning the same object would.
    let h = setup().await;
    let Ok(output) = run(&h.options, "typed_output", json!({}), None, None).await else {
        panic!("expected Ok");
    };
    assert!(
        h.effect_fired.load(Ordering::SeqCst),
        "post-commit effect drained on success"
    );
    let rendered = write_success_response(&json!(1), &output).expect("render");
    assert_eq!(
        std::str::from_utf8(&rendered).expect("utf-8"),
        r#"{"jsonrpc":"2.0","id":1,"result":{"files":["a","b"],"ok":true}}"#
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn side_effect_commit_writes_state_and_audit_and_drains_effects() {
    // The success path: the handler's state INSERT + its in-tx audit row commit
    // together, and the queued post-commit effect drains after the commit.
    let h = setup().await;
    let result = run(&h.options, "probe", json!({}), None, None).await;
    assert!(result.is_ok());
    assert_eq!(count(&h.pool, "probe").await, 1, "state row committed");
    assert_eq!(
        count(&h.pool, "audit_log").await,
        1,
        "in-tx audit row committed"
    );
    assert!(
        h.effect_fired.load(Ordering::SeqCst),
        "post-commit effect drained on success"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn side_effect_rollback_discards_state_audit_and_effects() {
    // The rollback contract (see the module header). A handler that writes
    // state + an in-tx audit row + queues a post-commit effect, then FAILS,
    // rolls all three back: no probe row, no audit row, and the effect never
    // fires.
    let h = setup().await;
    let result = run(&h.options, "probe", json!({ "fail": true }), None, None).await;
    assert!(result.is_err());
    assert_eq!(
        count(&h.pool, "probe").await,
        0,
        "handler state INSERT rolled back"
    );
    assert_eq!(
        count(&h.pool, "audit_log").await,
        0,
        "transactional-audit boundary: the in-tx audit row rolled back with the handler"
    );
    assert!(
        !h.effect_fired.load(Ordering::SeqCst),
        "rollback-discards-effects: the queued post-commit effect must not fire"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn swallowed_statement_error_fails_the_action_and_discards_effects() {
    // A handler that drops a failed statement's error and returns `Ok` leaves
    // the tx aborted; a bare `COMMIT` would roll it back without an error and
    // the dispatcher would report success and drain the effect for rows that
    // never committed. The checked commit refuses it: an internal error, no
    // effect, and nothing written — state row and in-tx audit row alike.
    let h = setup().await;
    let result = run(&h.options, "probe_swallow", json!({}), None, None).await;
    let Err(error) = &result else {
        panic!("expected an error, got {result:?}");
    };
    let status = fuz_http::error_code_to_http_status(error.code);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InternalError);
    assert_eq!(
        error.message, "db tx commit failed",
        "the same opaque answer as any failed commit"
    );
    assert!(
        !h.effect_fired.load(Ordering::SeqCst),
        "the post-commit effect must not fire for a rolled-back tx"
    );
    assert_eq!(count(&h.pool, "probe").await, 0, "state row rolled back");
    assert_eq!(
        count(&h.pool, "audit_log").await,
        0,
        "in-tx audit row rolled back"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn savepoint_recovered_statement_error_still_commits() {
    // The checked commit refuses only an aborted tx: a handler that recovers
    // from a failed statement through `ROLLBACK TO SAVEPOINT` leaves the tx
    // healthy, so it commits and the effect drains.
    let h = setup().await;
    let result = run(
        &h.options,
        "probe_swallow",
        json!({ "recover": true }),
        None,
        None,
    )
    .await;
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    assert_eq!(count(&h.pool, "probe").await, 1, "state row committed");
    assert_eq!(
        count(&h.pool, "audit_log").await,
        1,
        "in-tx audit row committed"
    );
    assert!(
        h.effect_fired.load(Ordering::SeqCst),
        "post-commit effect drained"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn read_only_ok_drains_effects_but_failure_discards_them() {
    // The non-transactional (`dispatch_pooled`) path still honors the
    // "effects run iff the handler returns Ok" contract.
    let h = setup().await;
    let ok = run(&h.options, "probe_ro", json!({}), None, None).await;
    assert!(ok.is_ok());
    assert!(
        h.effect_fired.load(Ordering::SeqCst),
        "read-only Ok drains effects"
    );

    // Fresh harness for the failure leg (independent flag).
    let h = setup().await;
    let err = run(&h.options, "probe_ro", json!({ "fail": true }), None, None).await;
    assert!(err.is_err());
    assert!(
        !h.effect_fired.load(Ordering::SeqCst),
        "read-only failure discards effects"
    );
}

// -- Enforcement order driven through the dispatcher ------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn unknown_method_is_method_not_found_404() {
    let h = setup().await;
    let result = run(&h.options, "does_not_exist", json!({}), None, None).await;
    assert_status(&result, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn account_required_without_account_is_401() {
    // Pre-authorization 401 fires before the authorization phase ever runs.
    let h = setup().await;
    let result = run(&h.options, "needs_account", json!({}), None, None).await;
    assert_status(&result, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn role_gate_denies_a_resolved_non_admin_actor_403() {
    // Authenticated, actor resolves from the single-actor account, but the
    // resolved actor lacks `admin` → post-authorization 403. Proves authz runs
    // (and denies) before the handler — the handler would have returned Ok.
    let h = setup().await;
    let account = seed_account(&h.pool, "plain_user", &[]).await;
    let result = run(
        &h.options,
        "needs_admin",
        json!({}),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&result, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn role_gate_admits_a_resolved_admin_actor_and_runs_the_handler() {
    // Full chain to the handler: the resolved actor holds `admin`, the gate
    // passes, the handler runs and returns Ok.
    let h = setup().await;
    let account = seed_account(&h.pool, "boss", &[ROLE_ADMIN]).await;
    let result = run(
        &h.options,
        "needs_admin",
        json!({}),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert!(result.is_ok());
}

/// Seed a single-actor account whose only grant is a **scoped** `admin` — a row
/// no grant verb writes (builtin roles are global-only) but a database can
/// still hold, e.g. from an accepted scoped offer. Returns the account and its
/// actor id.
async fn seed_scoped_admin(pool: &Pool, username: &str) -> (AccountRow, uuid::Uuid) {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    grant_scoped_role(pool, actor_id, ROLE_ADMIN, "thing", uuid::Uuid::new_v4()).await;
    (
        AccountRow {
            id: account_id,
            username: username.to_owned(),
        },
        actor_id,
    )
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn role_gate_denies_a_scoped_admin_403() {
    // The spec names `admin` with no scope, so only the global grant passes:
    // a scoped `admin` is denied at the dispatcher, the handler never runs.
    let h = setup().await;
    let (account, _) = seed_scoped_admin(&h.pool, "scoped_boss").await;
    let result = run(
        &h.options,
        "needs_admin",
        json!({}),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&result, StatusCode::FORBIDDEN);
}

/// Dispatch options over the standard auth spec set with no-op side channels —
/// the spine surface a consumer mounts, for the escalation cases.
fn plain_auth_spec_options(pool: &Pool) -> PerformActionOptions {
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let connection_closer: Arc<dyn fuz_auth::ConnectionCloser> = Arc::new(NoopConnectionCloser);
    let specs = fuz_actions::auth_adapter::build_auth_spec_set(
        Arc::clone(&audit),
        Arc::clone(&connection_closer),
        Arc::new(fuz_auth::AdminOfferAuthorize),
        Arc::new(fuz_auth::RoleRegistry::default()),
    );
    PerformActionOptions {
        pool: pool.clone(),
        registry: Arc::new(ActionRegistry::compile(specs).expect("compile auth specs")),
        audit,
        connection_closer,
        notification_sender: Arc::new(NoopNotificationSender),
        peer: fuz_realtime::noop_action_peer(),
        account_rate_limiter: None,
        ip_rate_limiter: None,
    }
}

/// **The escalation regression.** A scoped `admin` holder can't reach the
/// spine's admin surface, and in particular can't `role_grant_assign` itself a
/// global `admin` — the scoped-admin → global-admin escalation. Driven through
/// the real dispatcher over the standard auth spec set, so the role gate and
/// the handler are both in the path.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_scoped_admin_cannot_escalate_or_reach_admin_actions() {
    let pool = fresh_db_pool().await;
    let options = plain_auth_spec_options(&pool);
    let (account, actor_id) = seed_scoped_admin(&pool, "scoped_admin").await;

    let assign = run(
        &options,
        "role_grant_assign",
        json!({"to_account_id": account.id, "role": ROLE_ADMIN}),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&assign, StatusCode::FORBIDDEN);
    let global_grants: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM role_grant WHERE actor_id = $1 AND scope_id IS NULL",
            &[&actor_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(global_grants, 0, "no global grant was written");

    // Every admin-gated spine verb refuses it, reads and writes alike.
    for (method, params) in [
        ("admin_account_list", json!({})),
        ("admin_session_list", json!({})),
        ("invite_list", json!({})),
        ("audit_log_list", json!({})),
        (
            "role_grant_revoke",
            json!({"actor_id": actor_id, "role_grant_id": uuid::Uuid::new_v4()}),
        ),
    ] {
        let result = run(
            &options,
            method,
            params,
            Some(&account),
            Some(CredentialType::Session),
        )
        .await;
        assert_status(&result, StatusCode::FORBIDDEN);
    }

    // The offer path's default authorizer reads the global grant too: offering
    // a global `admin` to a sock-puppet account is refused.
    let (puppet_account, _) = seed_account_actor(&pool, "puppet").await;
    let offer = run(
        &options,
        "role_grant_offer_create",
        json!({"to_account_id": puppet_account, "role": ROLE_ADMIN}),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&offer, StatusCode::FORBIDDEN);
}

/// The positive control for the escalation case: a **global** admin assigns
/// through the same dispatcher path, so the refusal above is the scope, not
/// the harness.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_global_admin_assigns_through_the_dispatcher() {
    let pool = fresh_db_pool().await;
    let options = plain_auth_spec_options(&pool);
    let admin = seed_account(&pool, "global_admin", &[ROLE_ADMIN]).await;
    let (recipient, _) = seed_account_actor(&pool, "recipient").await;
    let result = run(
        &options,
        "role_grant_assign",
        json!({"to_account_id": recipient, "role": ROLE_ADMIN}),
        Some(&admin),
        Some(CredentialType::Session),
    )
    .await;
    assert!(result.is_ok(), "a global admin assigns");
}

/// `role_grant_offer_create` is session-only: a global admin's API token (or
/// daemon token) is refused at the credential gate — `403
/// credential_type_required`, before the handler, writing no offer and no audit
/// row — while the same admin's session offers. Twin of the TS
/// `role_grant_offer_actions.create.db.test.ts` credential-channel cases.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn role_grant_offer_create_is_session_only() {
    let pool = fresh_db_pool().await;
    let options = plain_auth_spec_options(&pool);
    let admin = seed_account(&pool, "offer_admin", &[ROLE_ADMIN]).await;
    let (recipient, _) = seed_account_actor(&pool, "offer_recipient").await;
    let params = json!({"to_account_id": recipient, "role": ROLE_ADMIN});
    let audit_rows_before = count(&pool, "audit_log").await;

    for credential in [CredentialType::ApiToken, CredentialType::DaemonToken] {
        let refused = run(
            &options,
            "role_grant_offer_create",
            params.clone(),
            Some(&admin),
            Some(credential),
        )
        .await;
        let Err(error) = &refused else {
            panic!("{credential:?} must be refused, got {refused:?}");
        };
        let status = fuz_http::error_code_to_http_status(error.code);
        assert_eq!(status, StatusCode::FORBIDDEN, "{credential:?}");
        let data = error.data.as_ref().expect("refusal data");
        assert_eq!(data["reason"], "credential_type_required", "{credential:?}");
        assert_eq!(data["required_credential_types"], json!(["session"]));
    }
    assert_eq!(
        count(&pool, "role_grant_offer").await,
        0,
        "no offer written"
    );
    assert_eq!(
        count(&pool, "audit_log").await,
        audit_rows_before,
        "the gate refuses before the handler, so nothing is audited"
    );

    let offered = run(
        &options,
        "role_grant_offer_create",
        params,
        Some(&admin),
        Some(CredentialType::Session),
    )
    .await;
    assert!(offered.is_ok(), "a session offers: {offered:?}");
    assert_eq!(count(&pool, "role_grant_offer").await, 1);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn rate_limit_is_charged_ahead_of_the_acting_grammar_check() {
    // The 429-before-400 ordering, driven end to end: a malformed `acting`
    // must burn the budget it would otherwise dodge, and an over-cap caller
    // must be throttled rather than told its input is malformed.
    let h = setup_with_account_budget(Some(1)).await;
    let account = seed_account(&h.pool, "throttled_user", &[]).await;
    let malformed = json!({ "acting": "not-a-uuid" });

    // Within budget: the limiter admits and records, then the grammar check
    // refuses the selector — the 400 is what a first malformed call answers.
    let first = run(
        &h.options,
        "throttled",
        malformed.clone(),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&first, StatusCode::BAD_REQUEST);

    // Over cap on the same malformed shape: 429, not the 400 again. This is
    // the ordering proof — the first call was charged despite never reaching
    // the handler, and this one is refused before validation runs.
    let second = run(
        &h.options,
        "throttled",
        malformed,
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&second, StatusCode::TOO_MANY_REQUESTS);

    // A well-formed call shares the budget the malformed flood burned, so it
    // is throttled too — one budget per account, whatever the params look like.
    let third = run(
        &h.options,
        "throttled",
        json!({}),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&third, StatusCode::TOO_MANY_REQUESTS);
}

/// The JSON non-objects a `GET /rpc` `?params=` can carry past the envelope —
/// one per JSON type that isn't an object or `null`.
const NON_OBJECT_PARAMS: [&str; 4] = ["42", "[1]", "\"x\"", "true"];

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn non_object_params_are_invalid_params_and_reach_no_handler() {
    // `GET /rpc` reads `?params=` as any JSON value, so the dispatcher is what
    // holds `params` to absent-or-object: a non-object is the twin's
    // schema refusal — -32602 "invalid params", no reason — and the handler
    // (which would queue its effect and answer Ok) never runs.
    let h = setup().await;
    for raw in NON_OBJECT_PARAMS {
        let params: Value = serde_json::from_str(raw).unwrap();
        let result = run(&h.options, "probe_ro", params, None, None).await;
        let Err(error) = &result else {
            panic!("params {raw}: expected a refusal, got {result:?}");
        };
        let status = fuz_http::error_code_to_http_status(error.code);
        assert_eq!(status, StatusCode::BAD_REQUEST, "params {raw}");
        assert_eq!(
            error.code,
            fuz_http::JsonrpcErrorCode::InvalidParams,
            "params {raw}"
        );
        assert_eq!(
            error.message,
            fuz_http::INVALID_PARAMS_MESSAGE,
            "params {raw}"
        );
        assert!(
            error.data.is_none(),
            "params {raw}: no reason, got {:?}",
            error.data
        );
    }
    assert!(
        !h.effect_fired.load(Ordering::SeqCst),
        "a refused call must not reach the handler"
    );
    // absent and object params still dispatch
    let absent = run(&h.options, "probe_ro", Value::Null, None, None).await;
    assert!(absent.is_ok(), "{absent:?}");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn non_object_params_from_an_anonymous_caller_are_the_401() {
    // The shape check is input validation, so it sits behind the authority
    // gates: an anonymous caller hears the 401 of any anonymous call, never a
    // 400 that confirms the method takes input — the twin's order.
    let h = setup().await;
    for raw in NON_OBJECT_PARAMS {
        let params: Value = serde_json::from_str(raw).unwrap();
        let result = run(&h.options, "needs_account", params, None, None).await;
        assert_status(&result, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_void_spec_takes_only_the_no_arg_call() {
    // The twin's `void` input: absent, `null`, and `{}` are the call; a
    // declared key, a scalar, and any array are -32602 "invalid params" with no
    // reason — refused by the dispatcher from the spec's `InputShape::Void`,
    // so the handler, which never reads `params`, does not run.
    let h = setup().await;
    for params in [
        json!({"x": 1}),
        json!({"x": null}),
        json!({"acting": "3f8a1c2e-1234-4abc-9def-0123456789ab"}),
        json!([]),
        json!(1),
        json!("x"),
    ] {
        let result = run(&h.options, "probe_void", params.clone(), None, None).await;
        let Err(error) = &result else {
            panic!("params {params}: expected a refusal, got {result:?}");
        };
        assert_eq!(
            error.code,
            fuz_http::JsonrpcErrorCode::InvalidParams,
            "params {params}"
        );
        assert_eq!(
            error.message,
            fuz_http::INVALID_PARAMS_MESSAGE,
            "params {params}"
        );
        assert!(error.data.is_none(), "params {params}: {:?}", error.data);
    }
    assert!(
        !h.effect_fired.load(Ordering::SeqCst),
        "a refused void call must not reach the handler"
    );
    for empty in [Value::Null, json!({})] {
        let result = run(&h.options, "probe_void", empty.clone(), None, None).await;
        assert!(result.is_ok(), "params {empty}: {result:?}");
    }
    assert!(
        h.effect_fired.load(Ordering::SeqCst),
        "the no-arg call reaches the handler"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_void_refusal_sits_behind_the_authority_gates() {
    // The void rule is input validation: an anonymous caller hears the 401,
    // never a 400 confirming the method takes no params.
    let h = setup().await;
    let result = run(
        &h.options,
        "needs_account_void",
        json!({"x": 1}),
        None,
        None,
    )
    .await;
    assert_status(&result, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn an_own_proto_key_anywhere_in_params_is_refused_with_its_reason() {
    // The dispatcher's walk, the twin's step-5 refusal: every spec, void and
    // object alike, at any depth, ahead of the `acting` check and the void
    // rule — one reason for every `__proto__` refusal. The handler never runs.
    let h = setup().await;
    for (method, raw) in [
        ("probe_void", r#"{"__proto__":{"x":1}}"#),
        ("probe_ro", r#"{"__proto__":null}"#),
        ("probe_ro", r#"{"data":{"a":[{"__proto__":{}}]}}"#),
        ("probe", r#"{"data":{"__proto__":{"x":1},"label":"l"}}"#),
        ("probe_ro", r#"{"acting":"bad","x":{"__proto__":1}}"#),
    ] {
        let params: Value = serde_json::from_str(raw).unwrap();
        let result = run(&h.options, method, params, None, None).await;
        let Err(error) = &result else {
            panic!("{method} {raw}: expected a refusal, got {result:?}");
        };
        assert_eq!(
            error.code,
            fuz_http::JsonrpcErrorCode::InvalidParams,
            "{raw}"
        );
        assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE, "{raw}");
        assert_eq!(
            error.data,
            Some(json!({"reason": fuz_http::ERROR_PARAMS_PROTO_KEY})),
            "{raw}"
        );
    }
    assert!(
        !h.effect_fired.load(Ordering::SeqCst),
        "a refused call must not reach the handler"
    );
    // a non-object `params` is the shape check's reasonless refusal, as the
    // twin answers it from its schema
    let params: Value = serde_json::from_str(r#"[{"__proto__":1}]"#).unwrap();
    let result = run(&h.options, "probe_ro", params, None, None).await;
    let Err(error) = &result else {
        panic!("expected a refusal, got {result:?}");
    };
    assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);
    assert!(error.data.is_none(), "{:?}", error.data);
    // `constructor` and `prototype` are ordinary keys
    let params = json!({"constructor": {"prototype": {"x": 1}}});
    let result = run(&h.options, "probe_ro", params, None, None).await;
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_proto_key_refusal_sits_behind_the_authority_gates() {
    // input validation: an anonymous caller hears the 401 of any anonymous
    // call, never the walk's 400
    let h = setup().await;
    let params: Value = serde_json::from_str(r#"{"__proto__":{"x":1}}"#).unwrap();
    let result = run(&h.options, "needs_account", params, None, None).await;
    assert_status(&result, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_proto_key_refusal_sits_behind_the_role_gate() {
    // a caller the role gate refuses hears the 403, never the walk's 400
    let h = setup().await;
    let account = seed_account(&h.pool, "plain_proto_user", &[]).await;
    let params: Value = serde_json::from_str(r#"{"__proto__":{"x":1}}"#).unwrap();
    let result = run(
        &h.options,
        "needs_admin",
        params,
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&result, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_proto_key_refusal_sits_behind_the_rate_limit() {
    // the walk is input validation, so it runs after the 429 gate: the first
    // call is within budget and answers the walk's refusal, the second is
    // over cap and answers 429
    let h = setup_with_account_budget(Some(1)).await;
    let account = seed_account(&h.pool, "throttled_proto_user", &[]).await;
    let params: Value = serde_json::from_str(r#"{"__proto__":{"x":1}}"#).unwrap();
    let first = run(
        &h.options,
        "throttled_void",
        params.clone(),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    let Err(error) = &first else {
        panic!("expected the walk's refusal, got {first:?}");
    };
    assert_eq!(
        error.data,
        Some(json!({"reason": fuz_http::ERROR_PARAMS_PROTO_KEY}))
    );
    let second = run(
        &h.options,
        "throttled_void",
        params,
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&second, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_void_refusal_sits_behind_the_rate_limit() {
    // The void rule is input validation, so it runs after the 429 gate: the
    // first stray-key call is within budget and answers the void refusal; the
    // second is over cap and answers 429, not the refusal again.
    let h = setup_with_account_budget(Some(1)).await;
    let account = seed_account(&h.pool, "throttled_void_user", &[]).await;
    let stray = json!({"x": 1});

    let first = run(
        &h.options,
        "throttled_void",
        stray.clone(),
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    let Err(error) = &first else {
        panic!("expected the void refusal, got {first:?}");
    };
    assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);

    let second = run(
        &h.options,
        "throttled_void",
        stray,
        Some(&account),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&second, StatusCode::TOO_MANY_REQUESTS);
}

// -- Revocations close sockets only after the commit ------------------------

/// A `ConnectionCloser` that, at the moment it is asked to close, runs a probe
/// query over a **separate** pool connection — so it sees only committed
/// state — and records the count. A close issued inside the request
/// transaction would see the revoked rows still there.
struct CommitProbingCloser {
    pool: Pool,
    /// `SELECT count(*) …` the next close runs.
    probe_sql: std::sync::Mutex<String>,
    seen_at_close: std::sync::Mutex<Vec<i64>>,
}

impl CommitProbingCloser {
    fn new(pool: &Pool) -> Self {
        Self {
            pool: pool.clone(),
            probe_sql: std::sync::Mutex::new(String::new()),
            seen_at_close: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Probe with `sql` on the next closes, forgetting earlier records.
    fn arm(&self, sql: String) {
        *self.probe_sql.lock().unwrap() = sql;
        self.seen_at_close.lock().unwrap().clear();
    }

    fn seen(&self) -> Vec<i64> {
        self.seen_at_close.lock().unwrap().clone()
    }

    fn record(&self) -> usize {
        let pool = self.pool.clone();
        let sql = self.probe_sql.lock().unwrap().clone();
        // The closer is sync (`ConnectionCloser` runs on the emit fan-out);
        // `block_in_place` lets it read the DB from a multi-thread runtime.
        let seen = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let client = pool.get().await.unwrap();
                client.query_one(&sql, &[]).await.unwrap().get::<_, i64>(0)
            })
        });
        self.seen_at_close.lock().unwrap().push(seen);
        0
    }
}

impl fuz_http::ShutdownCloser for CommitProbingCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> fuz_http::WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl fuz_auth::ConnectionCloser for CommitProbingCloser {
    fn close_connections(&self, _target: &ConnectionCloseTarget) -> usize {
        self.record()
    }
}

/// Dispatch options over the standard auth spec set, with `connection_closer` as
/// the closer the revocation handlers close through. No audit listeners are
/// registered, so every recorded close is the handler's own.
fn auth_spec_options(
    pool: &Pool,
    connection_closer: Arc<dyn fuz_auth::ConnectionCloser>,
) -> PerformActionOptions {
    let audit = Arc::new(AuditEmitter::new(pool.clone()));
    let specs = fuz_actions::auth_adapter::build_auth_spec_set(
        Arc::clone(&audit),
        Arc::clone(&connection_closer),
        Arc::new(fuz_auth::AdminOfferAuthorize),
        Arc::new(fuz_auth::RoleRegistry::default()),
    );
    PerformActionOptions {
        pool: pool.clone(),
        registry: Arc::new(ActionRegistry::compile(specs).expect("compile auth specs")),
        audit,
        connection_closer,
        notification_sender: Arc::new(NoopNotificationSender),
        peer: fuz_realtime::noop_action_peer(),
        account_rate_limiter: None,
        ip_rate_limiter: None,
    }
}

/// Seed `count` sessions for `account_id`, returning their token hashes.
async fn seed_sessions(pool: &Pool, account_id: uuid::Uuid, count: usize) -> Vec<String> {
    let client = pool.get().await.unwrap();
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let session = fuz_auth::session_queries::create_capped_session(&client, &account_id)
            .await
            .unwrap();
        hashes.push(
            fuz_auth::hash_session_token(&session.token)
                .as_str()
                .to_owned(),
        );
    }
    hashes
}

/// Seed one API token for `account_id`, returning its public id.
async fn seed_token(pool: &Pool, account_id: uuid::Uuid) -> String {
    let client = pool.get().await.unwrap();
    let generated = fuz_auth::generate_api_token();
    fuz_auth::api_token_queries::query_create_api_token(
        &client,
        &generated.id,
        &account_id,
        "probe",
        &generated.token_hash,
        r#"{"version":1,"kind":"full"}"#,
        None,
    )
    .await
    .unwrap();
    generated.id
}

fn sessions_of(account_id: uuid::Uuid) -> String {
    format!("SELECT count(*) FROM auth_session WHERE account_id = '{account_id}'")
}

fn tokens_of(account_id: uuid::Uuid) -> String {
    format!("SELECT count(*) FROM api_token WHERE account_id = '{account_id}'")
}

/// Dispatch `method` and assert it succeeded.
async fn run_ok(
    options: &PerformActionOptions,
    method: &str,
    params: Value,
    account: &AccountRow,
    credential_type: CredentialType,
) {
    let result = run(
        options,
        method,
        params,
        Some(account),
        Some(credential_type),
    )
    .await;
    if let Err(error) = result {
        let status = fuz_http::error_code_to_http_status(error.code);
        panic!("{method} failed: {status} {error:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn revocations_close_connections_after_the_transaction_commits() {
    // A client whose socket is closed as revoked rechecks its session at once;
    // if the close lands before the commit, that recheck still finds the
    // session and the client keeps a dead socket. So by the time the closer
    // is asked to close, every revocation's deletion must already be
    // committed — probed per handler below.
    let pool = fresh_db_pool().await;
    let closer = Arc::new(CommitProbingCloser::new(&pool));
    let options = auth_spec_options(&pool, Arc::<CommitProbingCloser>::clone(&closer));
    let session = CredentialType::Session;

    // self-service: one session, one token, every session
    let user = seed_account(&pool, "closer_user", &[]).await;
    let hashes = seed_sessions(&pool, user.id, 2).await;
    closer.arm(sessions_of(user.id));
    let params = json!({ "session_id": hashes[0] });
    run_ok(&options, "account_session_revoke", params, &user, session).await;
    // the other seeded session, and the one the call authenticated with
    assert_eq!(closer.seen(), vec![2], "account_session_revoke");

    let token_id = seed_token(&pool, user.id).await;
    closer.arm(tokens_of(user.id));
    let params = json!({ "token_id": token_id });
    run_ok(&options, "account_token_revoke", params, &user, session).await;
    assert_eq!(closer.seen(), vec![0], "account_token_revoke");

    closer.arm(sessions_of(user.id));
    run_ok(
        &options,
        "account_session_revoke_all",
        json!(null),
        &user,
        session,
    )
    .await;
    assert_eq!(closer.seen(), vec![0], "account_session_revoke_all");

    // admin: revoke-alls and a soft delete of another account
    let admin = seed_account(&pool, "closer_admin", &[ROLE_ADMIN]).await;
    let target = seed_account(&pool, "closer_target", &[]).await;
    seed_sessions(&pool, target.id, 1).await;
    seed_token(&pool, target.id).await;
    let params = json!({ "account_id": target.id });

    closer.arm(sessions_of(target.id));
    run_ok(
        &options,
        "admin_session_revoke_all",
        params.clone(),
        &admin,
        session,
    )
    .await;
    assert_eq!(closer.seen(), vec![0], "admin_session_revoke_all");

    closer.arm(tokens_of(target.id));
    run_ok(
        &options,
        "admin_token_revoke_all",
        params.clone(),
        &admin,
        session,
    )
    .await;
    assert_eq!(closer.seen(), vec![0], "admin_token_revoke_all");

    seed_sessions(&pool, target.id, 1).await;
    closer.arm(format!(
        "SELECT count(*) FROM account WHERE id = '{}' AND deleted_at IS NULL",
        target.id
    ));
    run_ok(&options, "account_delete", params, &admin, session).await;
    assert_eq!(closer.seen(), vec![0], "account_delete");

    // keeper: hard purge (daemon-token credential only)
    let keeper = seed_account(&pool, "closer_keeper", &[fuz_auth::ROLE_KEEPER]).await;
    let doomed = seed_account(&pool, "closer_doomed", &[]).await;
    seed_sessions(&pool, doomed.id, 1).await;
    closer.arm(format!(
        "SELECT count(*) FROM account WHERE id = '{}'",
        doomed.id
    ));
    let params = json!({ "account_id": doomed.id, "confirm": true });
    run_ok(
        &options,
        "account_purge",
        params,
        &keeper,
        CredentialType::DaemonToken,
    )
    .await;
    assert_eq!(closer.seen(), vec![0], "account_purge");

    // the token cap: a mint past it evicts the oldest token, closed after commit
    let minter = seed_account(&pool, "closer_minter", &[]).await;
    let token_ids = seed_capped_tokens(&pool, minter.id).await;
    closer.arm(format!(
        "SELECT count(*) FROM api_token WHERE id = '{}'",
        token_ids[0]
    ));
    run_ok(
        &options,
        "account_token_create",
        token_create_params(),
        &minter,
        session,
    )
    .await;
    assert_eq!(closer.seen(), vec![0], "account_token_create past the cap");
}

/// Seed [`DEFAULT_MAX_TOKENS`](fuz_auth::account_action_specs::DEFAULT_MAX_TOKENS)
/// tokens for `account_id` — a full cap — returning their ids oldest first.
/// Backdated a minute apart so the eviction order is the test's, not the
/// clock's.
async fn seed_capped_tokens(pool: &Pool, account_id: uuid::Uuid) -> Vec<String> {
    let cap = fuz_auth::account_action_specs::DEFAULT_MAX_TOKENS;
    let client = pool.get().await.unwrap();
    let mut ids = Vec::new();
    for i in 0..cap {
        let id = seed_token(pool, account_id).await;
        let minutes_ago = i32::try_from(cap - i).unwrap();
        client
            .execute(
                "UPDATE api_token SET created_at = NOW() - make_interval(mins => $2)
                 WHERE id = $1",
                &[&id, &minutes_ago],
            )
            .await
            .unwrap();
        ids.push(id);
    }
    ids
}

/// A well-formed `account_token_create` input.
fn token_create_params() -> Value {
    json!({
        "name": "past the cap",
        "scope": {"kind": "full"},
        "lifetime": {"kind": "eternal"},
    })
}

// -- The token cap closes what it evicts --------------------------------------

/// **A token mint past the cap closes the evicted token's connections.** The
/// cap deletes the oldest token row, but a WS socket keeps its upgrade-time
/// authority and an SSE stream never rechecks, so only a close ends the
/// connections that token opened. `token_create` carries no revocation scope,
/// so neither audit listener reacts — the close is the handler's own, queued
/// for after the commit. The newest token's connections stay open: the close
/// names the evicted token, not the account.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_token_mint_past_the_cap_closes_the_evicted_tokens_connections() {
    let pool = fresh_db_pool().await;
    let ws = Arc::new(fuz_realtime::ConnectionRegistry::new());
    let sse = Arc::new(fuz_realtime::SseRegistry::new());
    let options = auth_spec_options(
        &pool,
        fuz_realtime::RealtimeCloser::connection_closer(&ws, &sse),
    );
    // A consumer's full wiring: both audit listeners beside the direct close,
    // in the production order (fan-out, then revocation).
    fuz_realtime::register_audit_sse_listener(&options.audit, &sse);
    fuz_auth::register_revocation_guard(&options.audit, &options.connection_closer);

    let user = seed_account(&pool, "capped_minter", &[]).await;
    let token_ids = seed_capped_tokens(&pool, user.id).await;
    let (oldest, newest) = (&token_ids[0], &token_ids[token_ids.len() - 1]);

    // A bearer connection on each of the two tokens, on both transports.
    let subscribe = |token_id: &str| {
        Box::pin(
            sse.admit(sse.subscribe_pending(fuz_realtime::SseSubscription {
                identity: ConnectionIdentity {
                    account_id: Some(user.id),
                    api_token_id: Some(token_id.to_owned()),
                    ..ConnectionIdentity::default()
                },
                ..fuz_realtime::SseSubscription::default()
            }))
            .expect("a live registry admits"),
        )
    };
    let mut oldest_stream = subscribe(oldest);
    let mut newest_stream = subscribe(newest);
    assert!(oldest_stream.next().await.is_some(), "connect comment");
    assert!(newest_stream.next().await.is_some(), "connect comment");
    let add_ws = |token_id: &str| {
        let (tx, _rx) = fuz_realtime::connection_channel(1 << 20);
        ws.add_connection(
            tx,
            ConnectionIdentity {
                account_id: Some(user.id),
                api_token_id: Some(token_id.to_owned()),
                ..ConnectionIdentity::default()
            },
            tokio_util::sync::CancellationToken::new(),
        )
    };
    let oldest_ws = add_ws(oldest);
    let newest_ws = add_ws(newest);

    run_ok(
        &options,
        "account_token_create",
        token_create_params(),
        &user,
        CredentialType::Session,
    )
    .await;

    let client = pool.get().await.unwrap();
    let remaining: i64 = client
        .query_one(&tokens_of(user.id), &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        remaining,
        fuz_auth::account_action_specs::DEFAULT_MAX_TOKENS,
        "the mint stays within the cap"
    );
    let oldest_rows: i64 = client
        .query_one("SELECT count(*) FROM api_token WHERE id = $1", &[oldest])
        .await
        .unwrap()
        .get(0);
    assert_eq!(oldest_rows, 0, "the oldest token was evicted");

    let drained = async { while oldest_stream.next().await.is_some() {} };
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), drained)
            .await
            .is_ok(),
        "the evicted token's stream must be closed"
    );
    assert!(
        oldest_ws.signal.is_cancelled(),
        "the evicted token's WS socket must be closed"
    );
    assert_eq!(sse.count(), 1, "the newest token's stream stays");
    assert!(
        !newest_ws.signal.is_cancelled(),
        "the newest token's WS socket stays"
    );
    let frame = newest_stream.next().await.unwrap().unwrap();
    assert!(
        frame.contains(r#""event_type":"token_create""#),
        "the surviving stream still receives the mint's audit row: {frame}"
    );
}

// -- An in-tx revocation's failed audit write rolls the revocation back ------

/// **An action-path revocation cannot strand an open stream on a failed audit
/// write.** Its success audit routes in-tx and propagates the INSERT error, so
/// the refused row fails the handler, the transaction — the session deletion
/// with it — rolls back, and the post-commit close never runs. The credential
/// is still valid, so the stream it opened rightly stays open.
///
/// The contrast is the REST `/logout` / `/password` pair, whose pool-routed
/// audit write fails open after the revocation has committed — those close
/// directly (`fuz_realtime`'s `audit_stream` suite). `fuz_auth`'s
/// `the_pool_routed_revocations_are_logout_and_password_change` keeps every
/// other revocation on this side of the line.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_revocation_whose_in_tx_audit_write_fails_is_rolled_back() {
    let pool = fresh_db_pool().await;
    let ws = Arc::new(fuz_realtime::ConnectionRegistry::new());
    let sse = Arc::new(fuz_realtime::SseRegistry::new());
    let options = auth_spec_options(
        &pool,
        fuz_realtime::RealtimeCloser::connection_closer(&ws, &sse),
    );
    // A consumer's full wiring: both audit listeners beside the direct close,
    // in the production order (fan-out, then revocation).
    fuz_realtime::register_audit_sse_listener(&options.audit, &sse);
    fuz_auth::register_revocation_guard(&options.audit, &options.connection_closer);

    let user = seed_account(&pool, "refused_revocation", &[]).await;
    let hashes = seed_sessions(&pool, user.id, 1).await;
    let mut stream = Box::pin(
        sse.admit(sse.subscribe_pending(fuz_realtime::SseSubscription {
            identity: ConnectionIdentity {
                account_id: Some(user.id),
                session_hash: Some(hashes[0].clone()),
                ..ConnectionIdentity::default()
            },
            ..fuz_realtime::SseSubscription::default()
        }))
        .expect("a live registry admits"),
    );
    assert!(stream.next().await.is_some(), "connect comment");

    refuse_audit_rows(&pool, &["session_revoke_all"]).await;

    let result = run(
        &options,
        "account_session_revoke_all",
        json!(null),
        Some(&user),
        Some(CredentialType::Session),
    )
    .await;
    assert_status(&result, StatusCode::INTERNAL_SERVER_ERROR);

    let client = pool.get().await.unwrap();
    let sessions: i64 = client
        .query_one(&sessions_of(user.id), &[])
        .await
        .unwrap()
        .get(0);
    // the seeded session and the one the call authenticated with
    assert_eq!(sessions, 2, "the revocation rolled back with its audit row");
    assert_eq!(sse.count(), 1, "a still-valid session's stream stays open");
    assert_eq!(sse.broadcast("data: kept\n\n"), 1);
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        "data: kept\n\n",
        "the stream still receives the fan-out"
    );
}

/// A pool on the suite's database that hands out `checkouts` connections and
/// refuses every checkout after them — `post_create` and `pre_recycle` spend
/// from one budget, so once it is spent a reused connection is discarded and
/// its replacement refused.
fn budgeted_pool(checkouts: usize) -> Pool {
    fuz_testing::budgeted_pool(&DB.url(), checkouts)
}

/// **A failed checkout is the database unavailable, at every phase.** The
/// authorization phase's checkout (no budget), the side-effecting dispatch's
/// (one checkout, spent by the authorization phase), and the read-only
/// dispatch's each answer `service_unavailable` (-32007, 503) with the message
/// `database unavailable` and no `data` — and nothing runs past the refused
/// checkout.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_actions_test database"]
async fn a_failed_checkout_answers_service_unavailable_at_every_phase() {
    let h = setup().await;
    for (phase, method, budget) in [
        ("the authorization phase", "probe", 0),
        ("the side-effecting dispatch", "probe", 1),
        ("the read-only dispatch", "probe_ro", 1),
    ] {
        let options = PerformActionOptions {
            pool: budgeted_pool(budget),
            ..h.options.clone()
        };
        let error = run(&options, method, json!({}), None, None)
            .await
            .expect_err(phase);
        assert_eq!(
            fuz_http::error_code_to_http_status(error.code),
            StatusCode::SERVICE_UNAVAILABLE,
            "{phase}"
        );
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            json!({"code": -32007, "message": "database unavailable"}),
            "{phase}"
        );
        assert!(
            !h.effect_fired.load(Ordering::SeqCst),
            "{phase}: no handler ran"
        );
    }
    let probes: i64 = h
        .pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM probe", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(probes, 0, "nothing was written");
}
