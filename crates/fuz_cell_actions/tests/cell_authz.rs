//! Dispatcher-driven authz tests for the cell verbs — the admin bypass and the
//! creation gate on `cell_clone`, run through [`fuz_actions::perform_action`]
//! so the transaction wrap (a refused deep clone leaves nothing behind) is in
//! the path.
//!
//! - **The admin bypass is the global grant.** A scoped `admin` row (legacy
//!   data — builtin roles are global-only, so no grant path mints one) gets
//!   none of admin's reach: `cell_get` 404-masks a private cell, `cell_list`
//!   leaves it out, and a `path` write is `cell_path_admin_only`.
//! - **`cell_list` refuses an out-of-range page.** A `limit` below 1 or past
//!   `CELL_LIST_LIMIT_MAX`, or an `offset` outside `0..=SAFE_INTEGER_MAX`, is
//!   `invalid_params` with no reason, as on the TS twin — never clamped; a page
//!   in bounds honors both.
//! - **Write data is `CellData`.** A non-object `data` / `with_data_patch`, or
//!   a non-string `label` / `summary`, is `invalid_params` with no reason on
//!   `cell_create`, `cell_update` and `cell_clone`, ahead of the 404 mask on a
//!   missing or hidden cell, as on the TS twin.
//! - **`cell_clone` runs the create authorizer.** Every cell a clone writes is
//!   a parentless creation of the source's kind, so a caller the authorizer
//!   denies that root can't mint one by cloning a viewable cell.
//! - **The hooks see the kinds.** The data validator gets the cell's `kind`
//!   with the `data`: the input's on `cell_create`, the existing cell's on a
//!   `cell_update` carrying `data` (none carrying no `data` reaches it), the
//!   source's for every row a `cell_clone` writes. The create authorizer gets
//!   the parent's `kind` as `parent_kind` — `None` for a root, a typeless
//!   parent, and every clone row.
//! - **A tombstoned root refuses contributions.** Soft delete doesn't cascade,
//!   so a live parent can sit under a deleted root; a create under it answers
//!   `cell_not_found` with or without an authorizer mounted, and a mounted one
//!   is never consulted.
//! - **Moderation gates the grant arms past reads.** An editor grant minted
//!   while a contribution was approved admits no write once it is rejected —
//!   `cell_update`, `cell_field_set`, `cell_item_insert`, and `cell_delete`
//!   answer the read's 404 — while the author keeps the owner arm; a holder
//!   leaving a rejected cell hears `still_admitted: false` despite a remaining
//!   role grant.
//! - **A grant needs an admitted cell.** `cell_grant_create` on a cell whose
//!   `moderation` doesn't admit an audience (pending, rejected, unknown) is
//!   `403 cell_grant_unapproved` for the owner and a global admin alike, actor-
//!   and role-shaped, after the manage gate (a non-manager keeps the 404).
//! - **The steward arm.** A non-admin root owner reads a pending contribution
//!   under their root through `cell_get` (with `can_edit` / `can_grant`
//!   false) and the `cell_list` queue, and moderates it; the author still
//!   hears `cell_moderate_forbidden`, a stranger the 404. The arm stops at
//!   those surfaces: `cell_clone` of the contribution and a create under it
//!   are the 404 a stranger gets.
//! - **`cell_moderate` transitions carry their from-state.** Approval moves
//!   only a pending contribution, rejection a pending or approved one (the
//!   takedown); any other transition is `400 cell_not_pending` and leaves the
//!   cell as it was — a root owner a private approved contribution was shared
//!   with can't publish it by "approving" it.
//! - **The steward is the governing root's manager.** A nested pending
//!   comment under another author's approved post is read and moderated by
//!   the root's owner, not the post's author. Unknown markers admit nobody
//!   past the author and steward no one, an author-narrowed approved
//!   contribution isn't stewarded, an author's self-flip to public is inert,
//!   and the arm closes on `cell_get`, `cell_list`, and `cell_moderate` once
//!   the root is tombstoned.
//! - **A new fact ref needs possession.** A non-admin `cell_create`,
//!   `cell_update`, or `cell_clone` whose `data` introduces a ref its acting
//!   actor holds no `fact_holder` row for is `403 cell_ref_not_held`, the same
//!   answer for a stored and an unstored hash; putting identical bytes makes
//!   an actor a holder; refs a cell already carries (an update) or its source
//!   carries (each row of a clone, shallow or deep) stay admitted; a global
//!   admin is not gated; a hash inside prose is not a ref; and a database
//!   without the fact chain refuses a new ref the same way.
//! - **A root's policy is the manager's, and opaque.** A non-null policy write
//!   — at a root's `cell_create` or through `cell_policy_set` — is
//!   `cell_policy_unsupported` with no authorizer mounted or one keeping the
//!   default `validate_policy`, and the mounted one's refusal otherwise;
//!   clearing needs no authorizer. `cell_policy_set` 404-masks a non-viewer,
//!   answers `403 cell_policy_manage_only` to an editor-grant holder, and
//!   `cell_policy_root_only` on a contribution (as `cell_create` does for a
//!   policy beside a `parent_id`); the authorizer reads the column, so an
//!   editor rewriting the root's `data.policy` changes nothing, and each set is
//!   audited with the new and the previous policy. A clone is born without one.
//! - **The grant authorizer sees only managers.** A mounted
//!   `CellGrantCreateAuthorize` runs after the manage, moderation and role
//!   gates — a non-manager's 404 and an unknown role's 400 never reach it — for
//!   a new grant and a level change alike; its refusal is
//!   `403 cell_grant_not_authorized` with no grant row and no audit row.
//! - **The revoke authorizer sees only a scope's would-be steward.** A mounted
//!   `CellGrantRevokeAuthorize` is asked only when the caller neither manages
//!   the cell nor holds the grant, and only for a role-shaped grant with a
//!   scope; its allow revokes with a `steward: true` audit row, its refusal is
//!   the same `404 cell_grant_not_found` as no hook, and a soft-deleted cell
//!   404s before it runs.
//!
//! The suite has its own `FUZ_CELL_ACTIONS_TEST_URL` (default
//! `fuz_cell_actions_test`) database, over the auth + cell chains — plus the
//! fact chain for the ref-admission cases.
//! `#[ignore]`-gated — run:
//! ```text
//! createdb fuz_cell_actions_test
//! cargo test -p fuz_cell_actions --test cell_authz -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use fuz_actions::ActionRegistry;
use fuz_actions::perform_action::{PerformActionInput, PerformActionOptions, perform_action};
use fuz_auth::{
    AUTH_MIGRATIONS, AccountRow, AuditEmitter, CredentialType, NoopConnectionCloser,
    NoopNotificationSender, ROLE_ADMIN, RequestActorContext, RoleRegistry, RoleSpec,
};
use fuz_cell::cell_item_queries::query_cell_item_insert;
use fuz_cell::cell_queries::{CELL_LIST_LIMIT_MAX, query_cell_create};
use fuz_cell::{CELL_MIGRATIONS, CellVisibility};
use fuz_cell_actions::{
    CellCreateAuthorize, CellCreateAuthorizeInput, CellDataValidator, CellGrantCreateAuthorize,
    CellGrantCreateAuthorizeInput, CellGrantRevokeAuthorize, CellGrantRevokeAuthorizeInput,
    CellSpecSetOptions, ERROR_CELL_POLICY_INVALID, Verdict, build_cell_spec_set,
};
use fuz_db::{ActionDb, Pool};
use fuz_fact::{
    FACT_MIGRATIONS, FactStore, PgFactStore, PutOptions, query_orphan_facts_select_for_delete,
};
use fuz_http::JsonrpcError;
use fuz_realtime::SignalToken;
use fuz_testing::{
    TestingDbOptions, fresh_test_db_pool, grant_role, grant_scoped_role, seed_account_actor,
};
use serde_json::{Value, json};
use uuid::Uuid;

/// A registered non-builtin role, for role-shaped grants.
const ROLE_MEMBER: &str = "member";

const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_CELL_ACTIONS_TEST_URL",
    default_db: "fuz_cell_actions_test",
    migrations: &[AUTH_MIGRATIONS, CELL_MIGRATIONS],
    setup_sql: None,
};

/// [`DB`] plus the fact chain — the ref-admission cases need `fact_holder`.
const DB_WITH_FACTS: TestingDbOptions<'static> = TestingDbOptions {
    migrations: &[AUTH_MIGRATIONS, CELL_MIGRATIONS, FACT_MIGRATIONS],
    ..DB
};

/// A creation policy in the directory model's shape: a `space` root is
/// admin-only (the global grant), every other parentless create is open.
struct SpaceRootsAdminOnly;

impl CellCreateAuthorize for SpaceRootsAdminOnly {
    fn authorize<'a>(
        &'a self,
        auth: &'a RequestActorContext,
        input: &'a CellCreateAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<Verdict, JsonrpcError>> {
        let deny = input.root_id.is_none()
            && input.kind.as_deref() == Some("space")
            && !auth.has_scoped_role(ROLE_ADMIN, None);
        Box::pin(async move {
            Ok(if deny {
                Verdict::Deny
            } else {
                Verdict::Allow {
                    moderation_required: false,
                }
            })
        })
    }
}

/// An authorizer that admits everything and counts its calls — for asserting
/// a refusal lands before the authorizer is consulted.
#[derive(Default)]
struct CountingAllow {
    calls: AtomicUsize,
}

impl CellCreateAuthorize for CountingAllow {
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        _input: &'a CellCreateAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<Verdict, JsonrpcError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(Verdict::Allow {
                moderation_required: false,
            })
        })
    }
}

fn options(pool: &Pool) -> PerformActionOptions {
    options_with(pool, Some(Arc::new(SpaceRootsAdminOnly)))
}

fn options_with(
    pool: &Pool,
    authorizer: Option<Arc<dyn CellCreateAuthorize>>,
) -> PerformActionOptions {
    options_full(pool, authorizer, None)
}

fn options_full(
    pool: &Pool,
    create_authorizer: Option<Arc<dyn CellCreateAuthorize>>,
    grant_create_authorizer: Option<Arc<dyn CellGrantCreateAuthorize>>,
) -> PerformActionOptions {
    options_all(pool, create_authorizer, grant_create_authorizer, None)
}

fn options_all(
    pool: &Pool,
    create_authorizer: Option<Arc<dyn CellCreateAuthorize>>,
    grant_create_authorizer: Option<Arc<dyn CellGrantCreateAuthorize>>,
    grant_revoke_authorizer: Option<Arc<dyn CellGrantRevokeAuthorize>>,
) -> PerformActionOptions {
    options_from(
        pool,
        CellSpecSetOptions {
            roles: test_roles(),
            validator: None,
            create_authorizer,
            grant_create_authorizer,
            grant_revoke_authorizer,
        },
    )
}

fn test_roles() -> Arc<RoleRegistry> {
    Arc::new(RoleRegistry::new(vec![RoleSpec::new(ROLE_MEMBER, vec![])]).expect("valid registry"))
}

fn options_from(pool: &Pool, cell_options: CellSpecSetOptions) -> PerformActionOptions {
    let specs = build_cell_spec_set(cell_options);
    PerformActionOptions {
        pool: pool.clone(),
        registry: Arc::new(ActionRegistry::compile(specs).expect("compile cell specs")),
        audit: Arc::new(AuditEmitter::new(pool.clone())),
        connection_closer: Arc::new(NoopConnectionCloser),
        notification_sender: Arc::new(NoopNotificationSender),
        peer: fuz_realtime::noop_action_peer(),
        account_rate_limiter: None,
        ip_rate_limiter: None,
    }
}

/// Seed a single-actor account; returns the account row and its actor id.
async fn seed(pool: &Pool, username: &str) -> (AccountRow, Uuid) {
    let (account_id, actor_id) = seed_account_actor(pool, username).await;
    (
        AccountRow {
            id: account_id,
            username: username.to_owned(),
        },
        actor_id,
    )
}

/// Seed a cell owned by `created_by`.
async fn seed_cell(pool: &Pool, kind: &str, visibility: CellVisibility, created_by: Uuid) -> Uuid {
    let client = pool.get().await.unwrap();
    query_cell_create(
        &client,
        &json!({"label": kind}),
        Some(kind),
        Some(visibility),
        None,
        None,
        None,
        None,
        None,
        Some(created_by),
    )
    .await
    .expect("seed cell")
    .id
}

async fn run(
    options: &PerformActionOptions,
    method: &str,
    params: Value,
    account: &AccountRow,
) -> Result<fuz_actions::ActionOutput, JsonrpcError> {
    let request_id = json!(1);
    let signal = SignalToken::new();
    let span = tracing::Span::none();
    let notify: &(dyn Fn(&str, &Value) + Send + Sync) = &fuz_realtime::http_no_op_notify;
    let auth =
        fuz_testing::resolve_test_credential(&options.pool, account.id, CredentialType::Session)
            .await;
    perform_action(
        PerformActionInput {
            method,
            params: &params,
            request_id: &request_id,
            auth: Some(&auth),
            client_ip: None,
            connection_id: None,
            notify,
            signal: &signal,
            log: &span,
        },
        options,
    )
    .await
}

/// The `(status, data.reason)` of a refused call.
fn refusal(result: &Result<fuz_actions::ActionOutput, JsonrpcError>) -> (u16, String) {
    match result {
        Err(error) => {
            let status = fuz_http::error_code_to_http_status(error.code);
            (
                status.as_u16(),
                error
                    .data
                    .as_ref()
                    .and_then(|d| d.get("reason"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            )
        }
        Ok(_) => panic!("expected a refusal, got Ok"),
    }
}

/// The success payload of a call.
fn ok_value(result: Result<fuz_actions::ActionOutput, JsonrpcError>) -> Value {
    match result {
        Ok(output) => {
            let out = fuz_actions::write_success_response(&json!(1), &output).expect("render");
            let envelope: Value = serde_json::from_slice(&out).expect("json");
            envelope["result"].clone()
        }
        Err(error) => {
            let status = fuz_http::error_code_to_http_status(error.code);
            panic!("expected Ok, got {status} {error:?}")
        }
    }
}

async fn count_cells(pool: &Pool) -> i64 {
    pool.get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM cell", &[])
        .await
        .unwrap()
        .get(0)
}

/// `cell_list` refuses an out-of-range page — `limit` below 1 or past
/// `CELL_LIST_LIMIT_MAX`, an `offset` outside `0..=SAFE_INTEGER_MAX` — rather
/// than clamping it, as the TS twin's schema does: 400 `invalid_params` with
/// the generic message and no `data` — and so are the enum-valued filters'
/// other values (`shared_with`, `order_by`, `order_direction`). A page inside the bounds is served,
/// `limit` and `offset` honored.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn cell_list_refuses_an_out_of_range_page() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(seed_cell(&pool, "note", CellVisibility::Private, owner_actor).await);
    }

    for params in [
        json!({"limit": 0}),
        json!({"limit": CELL_LIST_LIMIT_MAX + 1}),
        json!({"limit": -1}),
        json!({"offset": -1}),
        json!({"offset": fuz_http::SAFE_INTEGER_MAX + 1}),
        json!({"shared_with": "bogus"}),
        json!({"order_by": "bogus"}),
        json!({"order_direction": "bogus"}),
    ] {
        match run(&options, "cell_list", params.clone(), &owner).await {
            Err(error) => {
                let status = fuz_http::error_code_to_http_status(error.code);
                assert_eq!(status.as_u16(), 400, "{params}");
                assert_eq!(
                    error.code,
                    fuz_http::JsonrpcErrorCode::InvalidParams,
                    "{params}"
                );
                assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE, "{params}");
                assert!(error.data.is_none(), "{params}: {error:?}");
            }
            Ok(_) => panic!("{params}: an out-of-range page was served"),
        }
    }

    let at_max = ok_value(
        run(
            &options,
            "cell_list",
            json!({"limit": CELL_LIST_LIMIT_MAX}),
            &owner,
        )
        .await,
    );
    assert_eq!(at_max["cells"].as_array().unwrap().len(), 3);
    let paged = ok_value(
        run(
            &options,
            "cell_list",
            json!({"limit": 1, "offset": 1, "order_direction": "asc"}),
            &owner,
        )
        .await,
    );
    let paged = paged["cells"].as_array().unwrap();
    assert_eq!(paged.len(), 1);
    assert_eq!(paged[0]["id"], json!(ids[1]));
}

/// The cell content a write carries must be `CellData` — an object whose
/// `label` and `summary`, when present, are strings — or the verb answers 400
/// `invalid_params` with the generic message and no `data`, as the TS twin's
/// schema does. The refusal comes ahead of every handler check: nothing is
/// written, and `cell_update` / `cell_clone` refuse a mistyped `data` before
/// the existence and visibility check that 404-masks a missing or hidden cell.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn cell_data_of_the_wrong_type_is_refused_before_any_cell_check() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (stranger, _) = seed(&pool, "stranger").await;
    let hidden = seed_cell(&pool, "note", CellVisibility::Private, owner_actor).await;
    let missing = Uuid::new_v4();

    let bad_data = [
        json!("not_an_object"),
        json!(42),
        json!(true),
        json!([1]),
        json!({"label": 123}),
        json!({"label": Value::Null}),
        json!({"summary": {}}),
        json!({"summary": false}),
    ];
    let assert_invalid_params = |result: Result<fuz_actions::ActionOutput, JsonrpcError>,
                                 label: &str| match result {
        Err(error) => {
            let status = fuz_http::error_code_to_http_status(error.code);
            assert_eq!(status.as_u16(), 400, "{label}");
            assert_eq!(
                error.code,
                fuz_http::JsonrpcErrorCode::InvalidParams,
                "{label}"
            );
            assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE, "{label}");
            assert!(error.data.is_none(), "{label}: {error:?}");
        }
        Ok(_) => panic!("{label}: mistyped data was admitted"),
    };
    let before = count_cells(&pool).await;
    for data in bad_data {
        assert_invalid_params(
            run(&options, "cell_create", json!({"data": data}), &owner).await,
            &format!("cell_create data {data}"),
        );
        for (cell_id, as_who) in [(missing, &owner), (hidden, &stranger)] {
            assert_invalid_params(
                run(
                    &options,
                    "cell_update",
                    json!({"cell_id": cell_id, "data": data}),
                    as_who,
                )
                .await,
                &format!("cell_update {cell_id} data {data}"),
            );
            assert_invalid_params(
                run(
                    &options,
                    "cell_clone",
                    json!({"source_id": cell_id, "with_data_patch": data}),
                    as_who,
                )
                .await,
                &format!("cell_clone {cell_id} with_data_patch {data}"),
            );
        }
    }
    assert_eq!(
        count_cells(&pool).await,
        before,
        "a refused write wrote a cell"
    );

    // the loose schema's extras pass through, and well-typed data still meets
    // the 404 mask on a missing cell
    let created = ok_value(
        run(
            &options,
            "cell_create",
            json!({"data": {"label": "l", "summary": "s", "extra": [1, null]}}),
            &owner,
        )
        .await,
    );
    assert_eq!(
        created["cell"]["data"],
        json!({"label": "l", "summary": "s", "extra": [1, null]})
    );
    let result = run(
        &options,
        "cell_update",
        json!({"cell_id": missing, "data": {"label": "l"}}),
        &owner,
    )
    .await;
    assert_eq!(refusal(&result), (404, "cell_not_found".to_owned()));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn the_cell_admin_bypass_requires_a_global_admin() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (_, owner) = seed(&pool, "owner").await;
    let private = seed_cell(&pool, "note", CellVisibility::Private, owner).await;

    let (scoped_admin, scoped_actor) = seed(&pool, "scoped_admin").await;
    grant_scoped_role(&pool, scoped_actor, ROLE_ADMIN, "space", private).await;
    let (global_admin, global_actor) = seed(&pool, "global_admin").await;
    grant_role(&pool, global_actor, ROLE_ADMIN).await;

    // cell_get: 404-masked for the scoped admin, served to the global one.
    let get = run(&options, "cell_get", json!({"id": private}), &scoped_admin).await;
    assert_eq!(refusal(&get).0, 404);
    let got = ok_value(run(&options, "cell_get", json!({"id": private}), &global_admin).await);
    assert_eq!(got["cell"]["id"], json!(private));

    // cell_list: the admin visibility branch is global-only.
    let listed = |value: &Value| {
        value["cells"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == json!(private))
    };
    let scoped_list = ok_value(run(&options, "cell_list", json!({}), &scoped_admin).await);
    assert!(!listed(&scoped_list), "a scoped admin doesn't list it");
    let global_list = ok_value(run(&options, "cell_list", json!({}), &global_admin).await);
    assert!(listed(&global_list), "the global admin does");

    // `path` writes are admin-only — the global admin.
    let path_write = run(
        &options,
        "cell_create",
        json!({"kind": "note", "data": {}, "path": "/scoped"}),
        &scoped_admin,
    )
    .await;
    assert_eq!(
        refusal(&path_write),
        (403, "cell_path_admin_only".to_owned())
    );
    ok_value(
        run(
            &options,
            "cell_create",
            json!({"kind": "note", "data": {}, "path": "/global"}),
            &global_admin,
        )
        .await,
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn cell_clone_runs_the_create_authorizer() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (admin, admin_actor) = seed(&pool, "admin").await;
    grant_role(&pool, admin_actor, ROLE_ADMIN).await;
    let (member, _) = seed(&pool, "member").await;

    // An admin-created public space, and a public note holding a space child.
    let space = seed_cell(&pool, "space", CellVisibility::Public, admin_actor).await;
    let note = seed_cell(&pool, "note", CellVisibility::Public, admin_actor).await;
    {
        let client = pool.get().await.unwrap();
        query_cell_item_insert(&client, note, "a0", space)
            .await
            .expect("attach child");
    }
    let before = count_cells(&pool).await;

    // The member may not create a `space` root, so it may not clone one.
    let denied = run(&options, "cell_clone", json!({"source_id": space}), &member).await;
    assert_eq!(refusal(&denied), (403, "cell_create_forbidden".to_owned()));
    // A deep clone gates every cell it writes: the `space` child is refused and
    // the transaction takes the already-written root with it.
    let deep = run(
        &options,
        "cell_clone",
        json!({"source_id": note, "deep": true}),
        &member,
    )
    .await;
    assert_eq!(refusal(&deep), (403, "cell_create_forbidden".to_owned()));
    assert_eq!(count_cells(&pool).await, before, "nothing was written");

    // What the policy admits still clones: a shallow note clone (the child is
    // an edge, not a new cell), and the admin's space clone.
    let shallow = ok_value(run(&options, "cell_clone", json!({"source_id": note}), &member).await);
    assert_ne!(shallow["cell"]["id"], json!(note));
    ok_value(run(&options, "cell_clone", json!({"source_id": space}), &admin).await);
}

/// Seed a public space with a post under it through the dispatcher, assert a
/// comment under the post lands with the space as its root (the live-root
/// control), then soft-delete the space. Returns the post id.
async fn seed_post_under_deleted_space(
    options: &PerformActionOptions,
    member: &AccountRow,
) -> Uuid {
    let create = |params: Value| run(options, "cell_create", params, member);
    let space =
        ok_value(create(json!({"kind": "space", "data": {}, "visibility": "public"})).await);
    let space_id = space["cell"]["id"].clone();
    let post = ok_value(create(json!({"kind": "post", "data": {}, "parent_id": space_id})).await);
    let post_id = post["cell"]["id"].clone();
    let comment =
        ok_value(create(json!({"kind": "comment", "data": {}, "parent_id": post_id})).await);
    assert_eq!(comment["cell"]["root_id"], space_id, "live root: governed");
    ok_value(run(options, "cell_delete", json!({"cell_id": space_id}), member).await);
    serde_json::from_value(post_id).unwrap()
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn create_under_a_deleted_root_is_not_found_without_an_authorizer() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options_with(&pool, None);
    let (member, _) = seed(&pool, "member").await;
    let post = seed_post_under_deleted_space(&options, &member).await;
    let before = count_cells(&pool).await;

    let refused = run(
        &options,
        "cell_create",
        json!({"kind": "comment", "data": {}, "parent_id": post}),
        &member,
    )
    .await;
    assert_eq!(refusal(&refused), (404, "cell_not_found".to_owned()));
    assert_eq!(count_cells(&pool).await, before, "nothing was written");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn create_under_a_deleted_root_never_reaches_the_authorizer() {
    let pool = fresh_test_db_pool(DB).await;
    let authorizer = Arc::new(CountingAllow::default());
    let mounted: Arc<dyn CellCreateAuthorize> = Arc::<CountingAllow>::clone(&authorizer);
    let options = options_with(&pool, Some(mounted));
    let (member, _) = seed(&pool, "member").await;
    let post = seed_post_under_deleted_space(&options, &member).await;
    let before = count_cells(&pool).await;
    let calls_before = authorizer.calls.load(Ordering::SeqCst);

    let refused = run(
        &options,
        "cell_create",
        json!({"kind": "comment", "data": {}, "parent_id": post}),
        &member,
    )
    .await;
    assert_eq!(refusal(&refused), (404, "cell_not_found".to_owned()));
    assert_eq!(count_cells(&pool).await, before, "nothing was written");
    assert_eq!(
        authorizer.calls.load(Ordering::SeqCst),
        calls_before,
        "the authorizer is not consulted"
    );
}

/// A validator call: the `kind` it got, and the `data`.
type KindAndData = (Option<String>, Value);

/// An authorizer that admits everything and records each call's
/// `(kind, parent_kind)`.
#[derive(Default)]
struct RecordingAllow {
    seen: Mutex<Vec<(Option<String>, Option<String>)>>,
}

impl CellCreateAuthorize for RecordingAllow {
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        input: &'a CellCreateAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<Verdict, JsonrpcError>> {
        self.seen
            .lock()
            .unwrap()
            .push((input.kind.clone(), input.parent_kind.clone()));
        Box::pin(async {
            Ok(Verdict::Allow {
                moderation_required: false,
            })
        })
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn the_hooks_see_the_cell_and_parent_kinds() {
    let pool = fresh_test_db_pool(DB).await;
    let validated: Arc<Mutex<Vec<KindAndData>>> = Arc::default();
    let validator: CellDataValidator = {
        let validated = Arc::clone(&validated);
        Arc::new(move |kind, data| {
            validated
                .lock()
                .unwrap()
                .push((kind.map(str::to_owned), data.clone()));
            Ok(())
        })
    };
    let authorizer = Arc::new(RecordingAllow::default());
    let mounted: Arc<dyn CellCreateAuthorize> = Arc::<RecordingAllow>::clone(&authorizer);
    let options = options_from(
        &pool,
        CellSpecSetOptions {
            roles: test_roles(),
            validator: Some(validator),
            create_authorizer: Some(mounted),
            grant_create_authorizer: None,
            grant_revoke_authorizer: None,
        },
    );
    let (member, _) = seed(&pool, "member").await;
    let take_validated = || std::mem::take(&mut *validated.lock().unwrap());
    let take_authorized = || std::mem::take(&mut *authorizer.seen.lock().unwrap());
    let s = |v: &str| Some(v.to_owned());

    // create: the input's kind to the validator, the parent's to the authorizer
    let create = |params: Value| run(&options, "cell_create", params, &member);
    let space = ok_value(create(json!({"kind": "space", "data": {"label": "s"}})).await);
    let space_id = space["cell"]["id"].clone();
    let post = ok_value(
        create(json!({"kind": "post", "data": {"label": "p"}, "parent_id": space_id})).await,
    );
    let post_id = post["cell"]["id"].clone();
    let note = ok_value(create(json!({"data": {}, "parent_id": post_id})).await);
    let note_id = note["cell"]["id"].clone();
    ok_value(create(json!({"kind": "comment", "data": {}, "parent_id": note_id})).await);
    assert_eq!(
        take_validated(),
        [
            (s("space"), json!({"label": "s"})),
            (s("post"), json!({"label": "p"})),
            (None, json!({})),
            (s("comment"), json!({})),
        ]
    );
    assert_eq!(
        take_authorized(),
        [
            (s("space"), None),
            (s("post"), s("space")),
            (None, s("post")),
            (s("comment"), None),
        ],
        "a typeless parent hands over no kind"
    );

    // update: the existing cell's kind, and only when `data` is present
    let update = |params: Value| run(&options, "cell_update", params, &member);
    ok_value(update(json!({"cell_id": post_id, "data": {"label": "p2"}})).await);
    ok_value(update(json!({"cell_id": post_id, "visibility": "public"})).await);
    assert_eq!(take_validated(), [(s("post"), json!({"label": "p2"}))]);

    // clone: the source's kind for every row, each asked as a parentless create
    {
        let client = pool.get().await.unwrap();
        let space_id: Uuid = serde_json::from_value(space_id.clone()).unwrap();
        let post_id: Uuid = serde_json::from_value(post_id.clone()).unwrap();
        query_cell_item_insert(&client, space_id, "a0", post_id)
            .await
            .expect("attach child");
    }
    ok_value(
        run(
            &options,
            "cell_clone",
            json!({"source_id": space_id, "deep": true, "with_data_patch": {"summary": "x"}}),
            &member,
        )
        .await,
    );
    assert_eq!(
        take_validated(),
        [
            (s("space"), json!({"label": "s", "summary": "x"})),
            (s("post"), json!({"label": "p2"})),
        ]
    );
    assert_eq!(take_authorized(), [(s("space"), None), (s("post"), None)]);
}

/// Set a cell's `moderation` marker directly — the column has no CHECK, so an
/// unknown marker is writable too.
async fn set_moderation(pool: &Pool, cell_id: Uuid, moderation: Option<&str>) {
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE cell SET moderation = $2 WHERE id = $1",
            &[&cell_id, &moderation],
        )
        .await
        .expect("set moderation");
}

/// Seed a contribution under `root` with an explicit moderation marker.
async fn seed_contribution(
    pool: &Pool,
    root: Uuid,
    visibility: CellVisibility,
    moderation: Option<&str>,
    author: Uuid,
) -> Uuid {
    let client = pool.get().await.unwrap();
    query_cell_create(
        &client,
        &json!({"secret": "contribution body"}),
        Some("post"),
        Some(visibility),
        None,
        Some(root),
        Some(root),
        moderation,
        None,
        Some(author),
    )
    .await
    .expect("seed contribution")
    .id
}

/// An editor grant minted while a contribution was approved stops admitting
/// once the root owner rejects it — on every write verb, since each echoes or
/// reveals the row it touches (`cell_update` returns the full cell).
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn editor_grant_on_a_rejected_contribution_stops_admitting_writes() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (root_owner, root_owner_actor) = seed(&pool, "root_owner").await;
    let (author, author_actor) = seed(&pool, "author").await;
    let (editor, editor_actor) = seed(&pool, "editor").await;
    let root = seed_cell(&pool, "forum", CellVisibility::Public, root_owner_actor).await;
    let post = seed_contribution(
        &pool,
        root,
        CellVisibility::Public,
        Some("approved"),
        author_actor,
    )
    .await;
    let other = seed_cell(&pool, "note", CellVisibility::Public, editor_actor).await;
    ok_value(
        run(
            &options,
            "cell_grant_create",
            json!({"cell_id": post, "level": "editor",
                   "principal": {"kind": "actor", "actor_id": editor_actor}}),
            &author,
        )
        .await,
    );
    // control: the grant admits a write while the post is approved
    ok_value(run(&options, "cell_update", json!({"cell_id": post}), &editor).await);
    // the root owner holds an editor grant too, so after the rejection the
    // steward arm reads the row while the grant arm stays shut
    ok_value(
        run(
            &options,
            "cell_grant_create",
            json!({"cell_id": post, "level": "editor",
                   "principal": {"kind": "actor", "actor_id": root_owner_actor}}),
            &author,
        )
        .await,
    );
    ok_value(
        run(
            &options,
            "cell_moderate",
            json!({"cell_id": post, "moderation": "rejected"}),
            &root_owner,
        )
        .await,
    );
    let masked = (404, "cell_not_found".to_owned());
    let writes = [
        ("cell_get", json!({"id": post})),
        ("cell_update", json!({"cell_id": post})),
        (
            "cell_field_set",
            json!({"source_id": post, "name": "link", "target_id": other}),
        ),
        (
            "cell_item_insert",
            json!({"parent_id": post, "child_id": other, "position": "a0"}),
        ),
        ("cell_delete", json!({"cell_id": post})),
    ];
    for (method, params) in writes {
        let result = run(&options, method, params, &editor).await;
        assert_eq!(refusal(&result), masked, "{method}");
    }
    // a steward's pre-rejection editor grant: `cell_get` admits, `can_edit` is false
    let stewarded = ok_value(run(&options, "cell_get", json!({"id": post}), &root_owner).await);
    assert_eq!(
        stewarded["can_edit"],
        json!(false),
        "steward with an editor grant"
    );
    // the author keeps the owner arm
    ok_value(run(&options, "cell_update", json!({"cell_id": post}), &author).await);
}

/// `cell_grant_revoke`'s `still_admitted` recompute follows moderation: a
/// holder leaving a rejected cell is not still admitted by a remaining role
/// grant.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn self_revoke_on_a_rejected_cell_is_not_still_admitted() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (holder, holder_actor) = seed(&pool, "holder").await;
    grant_role(&pool, holder_actor, ROLE_MEMBER).await;
    let cell = seed_cell(&pool, "note", CellVisibility::Private, owner_actor).await;
    let actor_grant = ok_value(
        run(
            &options,
            "cell_grant_create",
            json!({"cell_id": cell, "level": "viewer",
                   "principal": {"kind": "actor", "actor_id": holder_actor}}),
            &owner,
        )
        .await,
    );
    ok_value(
        run(
            &options,
            "cell_grant_create",
            json!({"cell_id": cell, "level": "viewer",
                   "principal": {"kind": "role", "role": ROLE_MEMBER}}),
            &owner,
        )
        .await,
    );
    set_moderation(&pool, cell, Some("rejected")).await;
    let revoked = ok_value(
        run(
            &options,
            "cell_grant_revoke",
            json!({"grant_id": actor_grant["grant"]["id"]}),
            &holder,
        )
        .await,
    );
    assert_eq!(revoked["still_admitted"], json!(false));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn grant_create_refuses_an_unapproved_cell_after_the_manage_gate() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (admin, admin_actor) = seed(&pool, "admin").await;
    grant_role(&pool, admin_actor, ROLE_ADMIN).await;
    let (stranger, _) = seed(&pool, "stranger").await;
    let (_, target) = seed(&pool, "target").await;
    let post = seed_cell(&pool, "post", CellVisibility::Private, owner_actor).await;
    let actor_shaped = json!({
        "cell_id": post,
        "level": "viewer",
        "principal": {"kind": "actor", "actor_id": target},
    });
    let role_shaped = json!({
        "cell_id": post,
        "level": "viewer",
        "principal": {"kind": "role", "role": ROLE_MEMBER},
    });

    for moderation in ["pending", "rejected", "unknown"] {
        set_moderation(&pool, post, Some(moderation)).await;
        for granter in [&owner, &admin] {
            for params in [&actor_shaped, &role_shaped] {
                let refused = run(&options, "cell_grant_create", params.clone(), granter).await;
                assert_eq!(
                    refusal(&refused),
                    (403, "cell_grant_unapproved".to_owned()),
                    "{moderation} {}",
                    granter.username
                );
            }
        }
        // A non-manager keeps the 404 mask — the refusal comes after it.
        let masked = run(
            &options,
            "cell_grant_create",
            actor_shaped.clone(),
            &stranger,
        )
        .await;
        assert_eq!(
            refusal(&masked),
            (404, "cell_not_found".to_owned()),
            "{moderation}"
        );
    }
    let listed = ok_value(
        run(
            &options,
            "cell_grant_list",
            json!({"cell_id": post}),
            &owner,
        )
        .await,
    );
    assert_eq!(listed["grants"], json!([]), "no refused grant wrote a row");

    for moderation in [Some("approved"), None] {
        set_moderation(&pool, post, moderation).await;
        ok_value(run(&options, "cell_grant_create", actor_shaped.clone(), &owner).await);
        ok_value(run(&options, "cell_grant_create", role_shaped.clone(), &admin).await);
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn the_root_owner_stewards_a_pending_contribution() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (root_owner, root_owner_actor) = seed(&pool, "root_owner").await;
    let (author, author_actor) = seed(&pool, "author").await;
    let (stranger, _) = seed(&pool, "stranger").await;
    let root = seed_cell(&pool, "forum", CellVisibility::Public, root_owner_actor).await;
    let post = {
        let client = pool.get().await.unwrap();
        query_cell_create(
            &client,
            &json!({}),
            Some("post"),
            Some(CellVisibility::Private),
            None,
            Some(root),
            Some(root),
            Some("pending"),
            None,
            Some(author_actor),
        )
        .await
        .expect("seed pending post")
        .id
    };

    // cell_get: the steward reads it, with the base predicates' flags.
    let got = ok_value(run(&options, "cell_get", json!({"id": post}), &root_owner).await);
    assert_eq!(got["cell"]["id"], json!(post));
    assert_eq!(got["can_edit"], json!(false), "a steward does not edit");
    assert_eq!(got["can_grant"], json!(false), "a steward does not manage");
    let masked = run(&options, "cell_get", json!({"id": post}), &stranger).await;
    assert_eq!(refusal(&masked), (404, "cell_not_found".to_owned()));

    // cell_list: the queue under the steward's root.
    let queue = ok_value(
        run(
            &options,
            "cell_list",
            json!({"root_id": root, "moderation": "pending"}),
            &root_owner,
        )
        .await,
    );
    let ids: Vec<&Value> = queue["cells"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| &c["id"])
        .collect();
    assert_eq!(ids, vec![&json!(post)], "the steward reads the queue");

    // The arm stops at the moderator's surfaces: a clone and a contribution
    // under the pending post are the stranger's 404.
    let clone = run(
        &options,
        "cell_clone",
        json!({"source_id": post}),
        &root_owner,
    )
    .await;
    assert_eq!(refusal(&clone), (404, "cell_not_found".to_owned()), "clone");
    let under = run(
        &options,
        "cell_create",
        json!({"kind": "comment", "data": {}, "parent_id": post}),
        &root_owner,
    )
    .await;
    assert_eq!(
        refusal(&under),
        (404, "cell_not_found".to_owned()),
        "create under"
    );

    // cell_moderate: the author is refused at the root check, a stranger is
    // masked, the steward reaches the root check and passes it.
    let moderate = |account| {
        run(
            &options,
            "cell_moderate",
            json!({"cell_id": post, "moderation": "approved"}),
            account,
        )
    };
    assert_eq!(
        refusal(&moderate(&author).await),
        (403, "cell_moderate_forbidden".to_owned())
    );
    assert_eq!(
        refusal(&moderate(&stranger).await),
        (404, "cell_not_found".to_owned())
    );
    let approved = ok_value(moderate(&root_owner).await);
    assert_eq!(approved["cell"]["moderation"], json!("approved"));
}

fn status_of(result: &Result<fuz_actions::ActionOutput, JsonrpcError>) -> u16 {
    match result {
        Err(error) => {
            let status = fuz_http::error_code_to_http_status(error.code);
            status.as_u16()
        }
        Ok(_) => 200,
    }
}

/// The steward arm keys on the governing root, not the parent: the root
/// owner reads a nested pending comment under another author's post, and
/// the post's author does not.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn steward_arm_reaches_a_nested_contribution_through_the_root() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (root_owner, root_owner_actor) = seed(&pool, "root_owner").await;
    let (post_author, post_author_actor) = seed(&pool, "post_author").await;
    let (_, commenter_actor) = seed(&pool, "commenter").await;
    let root = seed_cell(&pool, "forum", CellVisibility::Public, root_owner_actor).await;
    let post = seed_contribution(
        &pool,
        root,
        CellVisibility::Public,
        Some("approved"),
        post_author_actor,
    )
    .await;
    let comment = {
        let client = pool.get().await.unwrap();
        query_cell_create(
            &client,
            &json!({}),
            Some("comment"),
            Some(CellVisibility::Private),
            None,
            Some(post),
            Some(root),
            Some("pending"),
            None,
            Some(commenter_actor),
        )
        .await
        .expect("seed nested comment")
        .id
    };
    let got = run(&options, "cell_get", json!({"id": comment}), &root_owner).await;
    assert_eq!(
        status_of(&got),
        200,
        "the root owner stewards the nested comment"
    );
    let by_parent = run(&options, "cell_get", json!({"id": comment}), &post_author).await;
    assert_eq!(
        refusal(&by_parent),
        (404, "cell_not_found".to_owned()),
        "the parent's author is not the steward"
    );
    let moderated = run(
        &options,
        "cell_moderate",
        json!({"cell_id": comment, "moderation": "approved"}),
        &root_owner,
    )
    .await;
    assert_eq!(status_of(&moderated), 200, "the root owner moderates it");
}

/// `cell_moderate` transitions carry their from-state. A root owner granted a
/// view of a private contribution that was never pending — approved at birth,
/// as a policy without moderation stamps it — is refused 400
/// `cell_not_pending` on approval and the cell stays private (without the
/// from-state an approval would force it public). An approved contribution is
/// not approved again but is taken down by a rejection (visibility
/// untouched); a rejected or unmarked one moves neither way.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn cell_moderate_transitions_carry_their_from_state() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (root_owner, root_owner_actor) = seed(&pool, "root_owner").await;
    let (author, author_actor) = seed(&pool, "author").await;
    let root = seed_cell(&pool, "forum", CellVisibility::Public, root_owner_actor).await;
    let not_pending = (400, "cell_not_pending".to_owned());
    let moderate = |cell: Uuid, moderation: &'static str| {
        let options = &options;
        let root_owner = &root_owner;
        async move {
            run(
                options,
                "cell_moderate",
                json!({"cell_id": cell, "moderation": moderation}),
                root_owner,
            )
            .await
        }
    };
    let read_cell = |cell: Uuid| {
        let options = &options;
        let author = &author;
        async move {
            ok_value(run(options, "cell_get", json!({"id": cell}), author).await)["cell"].clone()
        }
    };

    // the repro: a private approved contribution its author shares with the
    // root owner, who then "approves" it
    let shared = seed_contribution(
        &pool,
        root,
        CellVisibility::Private,
        Some("approved"),
        author_actor,
    )
    .await;
    ok_value(
        run(
            &options,
            "cell_grant_create",
            json!({"cell_id": shared, "level": "viewer",
                   "principal": {"kind": "actor", "actor_id": root_owner_actor}}),
            &author,
        )
        .await,
    );
    assert_eq!(refusal(&moderate(shared, "approved").await), not_pending);
    let after = read_cell(shared).await;
    assert_eq!(
        after["visibility"],
        json!("private"),
        "the refusal publishes nothing"
    );
    assert_eq!(after["moderation"], json!("approved"));

    // no marker at all: neither way
    let unmarked = seed_contribution(&pool, root, CellVisibility::Public, None, author_actor).await;
    for decision in ["approved", "rejected"] {
        assert_eq!(
            refusal(&moderate(unmarked, decision).await),
            not_pending,
            "unmarked, {decision}"
        );
    }
    assert_eq!(read_cell(unmarked).await["moderation"], Value::Null);

    // approved: not approved again, but taken down; then rejected is final
    let pending = seed_contribution(
        &pool,
        root,
        CellVisibility::Private,
        Some("pending"),
        author_actor,
    )
    .await;
    let approved = ok_value(moderate(pending, "approved").await);
    assert_eq!(approved["cell"]["visibility"], json!("public"));
    assert_eq!(
        refusal(&moderate(pending, "approved").await),
        not_pending,
        "approve twice"
    );
    let taken_down = ok_value(moderate(pending, "rejected").await);
    assert_eq!(taken_down["cell"]["moderation"], json!("rejected"));
    assert_eq!(
        taken_down["cell"]["visibility"],
        json!("public"),
        "visibility untouched"
    );
    for decision in ["approved", "rejected"] {
        assert_eq!(
            refusal(&moderate(pending, decision).await),
            not_pending,
            "taken down, {decision}"
        );
    }

    // rejected from pending: final either way
    let rejected = seed_contribution(
        &pool,
        root,
        CellVisibility::Private,
        Some("pending"),
        author_actor,
    )
    .await;
    ok_value(moderate(rejected, "rejected").await);
    for decision in ["approved", "rejected"] {
        assert_eq!(
            refusal(&moderate(rejected, decision).await),
            not_pending,
            "rejected, {decision}"
        );
    }
    let after = read_cell(rejected).await;
    assert_eq!(after["moderation"], json!("rejected"));
    assert_eq!(after["visibility"], json!("private"));

    // the query alone carries the from-state too
    let client = pool.get().await.unwrap();
    for (cell, marker) in [(shared, Some("approved")), (unmarked, None)] {
        let moved = fuz_cell::cell_queries::query_cell_set_moderation(
            &client, cell, "approved", true, None,
        )
        .await
        .expect("query");
        assert!(moved.is_none(), "approve {marker:?}");
        assert_eq!(read_cell(cell).await["moderation"], json!(marker));
    }
    for (cell, marker) in [(rejected, Some("rejected")), (unmarked, None)] {
        let moved = fuz_cell::cell_queries::query_cell_set_moderation(
            &client, cell, "rejected", false, None,
        )
        .await
        .expect("query");
        assert!(moved.is_none(), "reject {marker:?}");
        assert_eq!(read_cell(cell).await["moderation"], json!(marker));
    }
    assert_eq!(read_cell(shared).await["visibility"], json!("private"));
}

/// Unknown markers admit nobody past the author (and steward no one); an
/// author-narrowed approved contribution isn't stewarded; an author's
/// self-flip to public is inert; the steward arm covers the `ids` batch read
/// and closes on every surface once the root is tombstoned.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn unknown_markers_and_tombstoned_root() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options(&pool);
    let (root_owner, root_owner_actor) = seed(&pool, "root_owner").await;
    let (author, author_actor) = seed(&pool, "author").await;
    let (stranger, _) = seed(&pool, "stranger").await;
    let root = seed_cell(&pool, "forum", CellVisibility::Public, root_owner_actor).await;
    for marker in ["Pending", "approved ", "", "PENDING", "rejected\n"] {
        let c = seed_contribution(
            &pool,
            root,
            CellVisibility::Public,
            Some(marker),
            author_actor,
        )
        .await;
        for (who, acct) in [("stranger", &stranger), ("root_owner", &root_owner)] {
            let got = run(&options, "cell_get", json!({"id": c}), acct).await;
            let listed = ok_value(run(&options, "cell_list", json!({"ids": [c]}), acct).await);
            assert_eq!(status_of(&got), 404, "{marker:?} {who}");
            assert!(
                listed["cells"].as_array().unwrap().is_empty(),
                "{marker:?} {who}"
            );
        }
        let own = run(&options, "cell_get", json!({"id": c}), &author).await;
        assert_eq!(status_of(&own), 200, "author reads own {marker:?}");
    }
    // The author narrowing an approved contribution: not stewarded.
    let narrowed = seed_contribution(
        &pool,
        root,
        CellVisibility::Private,
        Some("approved"),
        author_actor,
    )
    .await;
    let m = run(
        &options,
        "cell_moderate",
        json!({"cell_id": narrowed, "moderation": "rejected"}),
        &root_owner,
    )
    .await;
    assert_eq!(status_of(&m), 404, "narrowed approved is not stewarded");
    // The author setting their own pending contribution public is inert.
    let pending = seed_contribution(
        &pool,
        root,
        CellVisibility::Private,
        Some("pending"),
        author_actor,
    )
    .await;
    ok_value(
        run(
            &options,
            "cell_update",
            json!({"cell_id": pending, "visibility": "public"}),
            &author,
        )
        .await,
    );
    let s = run(&options, "cell_get", json!({"id": pending}), &stranger).await;
    assert_eq!(status_of(&s), 404, "author-published pending stays hidden");
    // Steward via the ids batch.
    let listed = ok_value(
        run(
            &options,
            "cell_list",
            json!({"ids": [pending]}),
            &root_owner,
        )
        .await,
    );
    assert_eq!(
        listed["cells"].as_array().unwrap().len(),
        1,
        "steward ids read"
    );
    // Tombstone the root: the steward arm closes on every surface.
    pool.get()
        .await
        .unwrap()
        .execute("UPDATE cell SET deleted_at = now() WHERE id = $1", &[&root])
        .await
        .unwrap();
    let got = run(&options, "cell_get", json!({"id": pending}), &root_owner).await;
    assert_eq!(status_of(&got), 404, "tombstoned root: get");
    let listed = ok_value(
        run(
            &options,
            "cell_list",
            json!({"ids": [pending]}),
            &root_owner,
        )
        .await,
    );
    assert!(
        listed["cells"].as_array().unwrap().is_empty(),
        "tombstoned root: list"
    );
    let m = run(
        &options,
        "cell_moderate",
        json!({"cell_id": pending, "moderation": "approved"}),
        &root_owner,
    )
    .await;
    assert_eq!(status_of(&m), 404, "tombstoned root: moderate");
}

// -- possession-gated ref admission --

/// Put `bytes` on behalf of `holder` (`None` = a system put); returns the
/// wire hash.
async fn put_fact(pool: &Pool, bytes: &[u8], holder: Option<Uuid>) -> String {
    PgFactStore::new(pool.clone())
        .put(
            bytes,
            PutOptions {
                content_type: None,
                refs: None,
                holder,
            },
        )
        .await
        .expect("put fact")
        .to_prefixed()
}

/// A well-formed hash no fact is stored under.
fn unstored_hash() -> String {
    format!("blake3:{}", "e".repeat(64))
}

/// Seed a cell owned by `created_by` with the given `data` — a raw insert, so
/// no admission runs (the way seeds and pre-existing rows got their refs).
async fn seed_cell_with_data(
    pool: &Pool,
    data: &Value,
    visibility: CellVisibility,
    created_by: Uuid,
) -> Uuid {
    let client = pool.get().await.unwrap();
    query_cell_create(
        &client,
        data,
        Some("note"),
        Some(visibility),
        None,
        None,
        None,
        None,
        None,
        Some(created_by),
    )
    .await
    .expect("seed cell")
    .id
}

/// The whole wire error of a refused call, for comparing two refusals.
fn refusal_body(result: &Result<fuz_actions::ActionOutput, JsonrpcError>) -> (u16, Value) {
    match result {
        Err(error) => {
            let status = fuz_http::error_code_to_http_status(error.code);
            (status.as_u16(), serde_json::to_value(error).expect("error"))
        }
        Ok(_) => panic!("expected a refusal, got Ok"),
    }
}

/// The sorted refs of every live cell `created_by` wrote.
async fn refs_created_by(pool: &Pool, created_by: Uuid) -> Vec<Vec<String>> {
    let rows = pool
        .get()
        .await
        .unwrap()
        .query(
            "SELECT COALESCE(refs, '{}') FROM cell WHERE created_by = $1 ORDER BY refs",
            &[&created_by],
        )
        .await
        .unwrap();
    rows.iter().map(|r| r.get(0)).collect()
}

const NOT_HELD: (u16, &str) = (403, "cell_ref_not_held");

fn not_held(result: &Result<fuz_actions::ActionOutput, JsonrpcError>) -> bool {
    refusal(result) == (NOT_HELD.0, NOT_HELD.1.to_owned())
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn create_admits_a_new_ref_only_for_a_holder() {
    let pool = fresh_test_db_pool(DB_WITH_FACTS).await;
    let options = options_with(&pool, None);
    let (alice, alice_actor) = seed(&pool, "alice").await;
    let (bob, bob_actor) = seed(&pool, "bob").await;
    let uploaded = put_fact(&pool, b"alice's photo", Some(alice_actor)).await;
    let seeded = put_fact(&pool, b"seeded bytes", None).await;
    let unstored = unstored_hash();
    let before = count_cells(&pool).await;

    // Bob names a stored fact he never put, and a hash nothing is stored
    // under: both refused, with one identical answer — no existence oracle.
    let stored_refusal = run(
        &options,
        "cell_create",
        json!({"data": {"cover": uploaded}, "visibility": "public"}),
        &bob,
    )
    .await;
    let unstored_refusal = run(
        &options,
        "cell_create",
        json!({"data": {"cover": unstored}, "visibility": "public"}),
        &bob,
    )
    .await;
    assert!(not_held(&stored_refusal), "{:?}", refusal(&stored_refusal));
    assert_eq!(
        refusal_body(&stored_refusal),
        refusal_body(&unstored_refusal)
    );
    // A system-put fact has no holder at all.
    let seeded_refusal = run(
        &options,
        "cell_create",
        json!({"data": {"files": [seeded]}}),
        &bob,
    )
    .await;
    assert!(not_held(&seeded_refusal));
    assert_eq!(count_cells(&pool).await, before, "nothing was written");

    // The uploader holds it.
    let created = ok_value(
        run(
            &options,
            "cell_create",
            json!({"data": {"cover": uploaded}, "visibility": "public"}),
            &alice,
        )
        .await,
    );
    assert_eq!(created["cell"]["refs"], json!([uploaded]));

    // Bob puts identical bytes himself: possession, so he holds it too.
    assert_eq!(
        put_fact(&pool, b"alice's photo", Some(bob_actor)).await,
        uploaded
    );
    ok_value(
        run(
            &options,
            "cell_create",
            json!({"data": {"cover": uploaded}}),
            &bob,
        )
        .await,
    );

    // A hash inside prose is not a ref, so it needs no holding.
    let prose = ok_value(
        run(
            &options,
            "cell_create",
            json!({"data": {"body": format!("see {seeded} and ![x]({unstored})")}}),
            &bob,
        )
        .await,
    );
    assert_eq!(prose["cell"]["refs"], Value::Null);
}

/// Run the orphan sweep the way an admin delete does — select past a one-hour
/// cutoff, then drop each row (cascading its holders) — returning the swept
/// hashes, sorted.
async fn sweep_orphans_past_an_hour(pool: &Pool) -> Vec<String> {
    let client = pool.get().await.unwrap();
    let cutoff: String = client
        .query_one("SELECT (NOW() - INTERVAL '1 hour')::text", &[])
        .await
        .unwrap()
        .get(0);
    let mut swept: Vec<String> = query_orphan_facts_select_for_delete(&client, &cutoff)
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.hash)
        .collect();
    for hash in &swept {
        client
            .execute("DELETE FROM fact WHERE hash = $1", &[hash])
            .await
            .unwrap();
    }
    swept.sort();
    swept
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn a_sweep_between_a_reupload_and_its_cell_write_keeps_the_fact() {
    // An old orphan re-uploaded (a dedup hit: the `fact` row keeps its old
    // `created_at`) must survive a sweep that runs before the cell write
    // naming it — else the sweep cascades the fresh holder row away and the
    // write is refused as unheld.
    let pool = fresh_test_db_pool(DB_WITH_FACTS).await;
    let options = options_with(&pool, None);
    let (alice, alice_actor) = seed(&pool, "alice").await;
    let (bob, bob_actor) = seed(&pool, "bob").await;
    let photo = put_fact(&pool, b"alice's photo", Some(alice_actor)).await;
    let draft = put_fact(&pool, b"alice's draft", Some(alice_actor)).await;
    let stale = put_fact(&pool, b"alice's stale file", Some(alice_actor)).await;
    let client = pool.get().await.unwrap();
    for table in ["fact", "fact_holder"] {
        client
            .execute(
                &format!("UPDATE {table} SET created_at = NOW() - INTERVAL '2 days'"),
                &[],
            )
            .await
            .unwrap();
    }

    // Bob re-uploads the photo; Alice repeats her put of the draft.
    assert_eq!(
        put_fact(&pool, b"alice's photo", Some(bob_actor)).await,
        photo
    );
    assert_eq!(
        put_fact(&pool, b"alice's draft", Some(alice_actor)).await,
        draft
    );
    assert_eq!(sweep_orphans_past_an_hour(&pool).await, vec![stale.clone()]);

    // Both writes land after the sweep.
    let bobs = ok_value(
        run(
            &options,
            "cell_create",
            json!({"data": {"cover": photo}}),
            &bob,
        )
        .await,
    );
    assert_eq!(bobs["cell"]["refs"], json!([photo]));
    let alices = ok_value(
        run(
            &options,
            "cell_create",
            json!({"data": {"file": draft}}),
            &alice,
        )
        .await,
    );
    assert_eq!(alices["cell"]["refs"], json!([draft]));
    // The swept fact took its possession with it.
    let gone = run(
        &options,
        "cell_create",
        json!({"data": {"file": stale}}),
        &alice,
    )
    .await;
    assert!(not_held(&gone), "{:?}", refusal(&gone));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn update_keeps_existing_refs_and_refuses_new_unheld_ones() {
    let pool = fresh_test_db_pool(DB_WITH_FACTS).await;
    let options = options_with(&pool, None);
    let (bob, bob_actor) = seed(&pool, "bob").await;
    let (_, alice_actor) = seed(&pool, "alice").await;
    let seeded = put_fact(&pool, b"seeded bytes", None).await;
    let alices = put_fact(&pool, b"alice's file", Some(alice_actor)).await;
    let bobs = put_fact(&pool, b"bob's file", Some(bob_actor)).await;
    // Bob owns a cell already carrying a ref he doesn't hold (a seed).
    let cell = seed_cell_with_data(
        &pool,
        &json!({"cover": seeded}),
        CellVisibility::Private,
        bob_actor,
    )
    .await;

    // Keeping it — beside an edit, beside a ref he does hold — is admitted.
    let kept = ok_value(
        run(
            &options,
            "cell_update",
            json!({"cell_id": cell, "data": {"cover": seeded, "label": "edited", "file": bobs}}),
            &bob,
        )
        .await,
    );
    let mut expected = vec![seeded.clone(), bobs.clone()];
    expected.sort();
    assert_eq!(kept["cell"]["refs"], json!(expected));

    // Adding one he doesn't hold is refused, and the cell is unchanged.
    for added in [alices.clone(), unstored_hash()] {
        let refused = run(
            &options,
            "cell_update",
            json!({"cell_id": cell, "data": {"cover": seeded, "file": added}}),
            &bob,
        )
        .await;
        assert!(not_held(&refused), "{:?}", refusal(&refused));
    }
    // Dropping a ref and adding it back is a new ref — the base is what the
    // cell carries now.
    ok_value(
        run(
            &options,
            "cell_update",
            json!({"cell_id": cell, "data": {"label": "dropped"}}),
            &bob,
        )
        .await,
    );
    let restored = run(
        &options,
        "cell_update",
        json!({"cell_id": cell, "data": {"cover": seeded}}),
        &bob,
    )
    .await;
    assert!(not_held(&restored));
    // A visibility-only update writes no data and reads no holders.
    ok_value(
        run(
            &options,
            "cell_update",
            json!({"cell_id": cell, "visibility": "public"}),
            &bob,
        )
        .await,
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn clone_carries_source_refs_per_row_without_holding() {
    let pool = fresh_test_db_pool(DB_WITH_FACTS).await;
    let options = options_with(&pool, None);
    let (_, alice_actor) = seed(&pool, "alice").await;
    let (bob, bob_actor) = seed(&pool, "bob").await;
    let cover = put_fact(&pool, b"cover bytes", Some(alice_actor)).await;
    let attachment = put_fact(&pool, b"attachment bytes", Some(alice_actor)).await;
    let source = seed_cell_with_data(
        &pool,
        &json!({"cover": cover}),
        CellVisibility::Public,
        alice_actor,
    )
    .await;
    let child = seed_cell_with_data(
        &pool,
        &json!({"file": attachment}),
        CellVisibility::Public,
        alice_actor,
    )
    .await;
    query_cell_item_insert(&pool.get().await.unwrap(), source, "a0", child)
        .await
        .expect("attach child");

    // Shallow: the root row carries the source's ref.
    ok_value(run(&options, "cell_clone", json!({"source_id": source}), &bob).await);
    assert_eq!(
        refs_created_by(&pool, bob_actor).await,
        vec![vec![cover.clone()]]
    );

    // Deep: each child row is checked against its own source row, so the
    // child's ref — not on the root — is carried too.
    ok_value(
        run(
            &options,
            "cell_clone",
            json!({"source_id": source, "deep": true}),
            &bob,
        )
        .await,
    );
    let mut refs = refs_created_by(&pool, bob_actor).await;
    refs.sort();
    let mut expected = vec![
        vec![cover.clone()],
        vec![cover.clone()],
        vec![attachment.clone()],
    ];
    expected.sort();
    assert_eq!(refs, expected);

    // A patch introducing an unheld ref is refused, and the deep clone's
    // already-written rows roll back with it.
    let before = count_cells(&pool).await;
    let patched = run(
        &options,
        "cell_clone",
        json!({"source_id": source, "deep": true, "with_data_patch": {"extra": unstored_hash()}}),
        &bob,
    )
    .await;
    assert!(not_held(&patched), "{:?}", refusal(&patched));
    // The child's ref is not on the root: carrying it onto the root through a
    // patch is a new ref there.
    let moved = run(
        &options,
        "cell_clone",
        json!({"source_id": source, "with_data_patch": {"extra": attachment}}),
        &bob,
    )
    .await;
    assert!(not_held(&moved));
    assert_eq!(count_cells(&pool).await, before, "nothing was written");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn a_global_admin_is_not_gated_on_refs() {
    let pool = fresh_test_db_pool(DB_WITH_FACTS).await;
    let options = options_with(&pool, None);
    let (admin, admin_actor) = seed(&pool, "admin").await;
    grant_role(&pool, admin_actor, ROLE_ADMIN).await;
    let (scoped_admin, scoped_actor) = seed(&pool, "scoped_admin").await;
    let space = seed_cell(&pool, "space", CellVisibility::Private, scoped_actor).await;
    grant_scoped_role(&pool, scoped_actor, ROLE_ADMIN, "space", space).await;
    let seeded = put_fact(&pool, b"seeded bytes", None).await;

    let created = ok_value(
        run(
            &options,
            "cell_create",
            json!({"data": {"cover": seeded}}),
            &admin,
        )
        .await,
    );
    assert_eq!(created["cell"]["refs"], json!([seeded]));
    // A scoped admin row is not the global grant.
    let scoped = run(
        &options,
        "cell_create",
        json!({"data": {"cover": seeded}}),
        &scoped_admin,
    )
    .await;
    assert!(not_held(&scoped));
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn a_new_ref_is_refused_without_the_fact_chain() {
    // The auth + cell chains alone: no `fact_holder` table, so nobody holds
    // anything — refused as unheld, not a failed query.
    let pool = fresh_test_db_pool(DB).await;
    let options = options_with(&pool, None);
    let (bob, _) = seed(&pool, "bob").await;
    let refused = run(
        &options,
        "cell_create",
        json!({"data": {"cover": unstored_hash()}}),
        &bob,
    )
    .await;
    assert!(not_held(&refused), "{:?}", refusal(&refused));
    // A write with no refs is untouched.
    ok_value(run(&options, "cell_create", json!({"data": {"n": 1}}), &bob).await);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn ref_refusal_answers_after_the_masks_and_the_create_policy() {
    // Admission is the last gate: a hidden cell answers its 404 mask whatever
    // `data` names (so the refusal says nothing about a hidden cell's refs),
    // and the create policy answers ahead of it.
    let pool = fresh_test_db_pool(DB_WITH_FACTS).await;
    let options = options(&pool);
    let (_, alice_actor) = seed(&pool, "alice").await;
    let (bob, _) = seed(&pool, "bob").await;
    let alices = put_fact(&pool, b"alice's private file", Some(alice_actor)).await;
    let hidden = seed_cell_with_data(
        &pool,
        &json!({"file": alices}),
        CellVisibility::Private,
        alice_actor,
    )
    .await;
    let unstored = unstored_hash();

    // update of a hidden cell: an unheld new ref and the hidden cell's own
    // ref both answer the mask
    for named in [unstored.clone(), alices.clone()] {
        let r = run(
            &options,
            "cell_update",
            json!({"cell_id": hidden, "data": {"file": named}}),
            &bob,
        )
        .await;
        assert_eq!(status_of(&r), 404, "update of a hidden cell naming {named}");
    }
    // create under a hidden parent
    let r = run(
        &options,
        "cell_create",
        json!({"data": {"file": unstored}, "parent_id": hidden}),
        &bob,
    )
    .await;
    assert_eq!(status_of(&r), 404, "create under a hidden parent");
    // clone of a hidden source with a patch
    let r = run(
        &options,
        "cell_clone",
        json!({"source_id": hidden, "with_data_patch": {"extra": unstored}}),
        &bob,
    )
    .await;
    assert_eq!(status_of(&r), 404, "clone of a hidden source");
    // the create policy answers first
    let r = run(
        &options,
        "cell_create",
        json!({"data": {"file": unstored}, "kind": "space"}),
        &bob,
    )
    .await;
    assert_eq!(
        refusal(&r),
        (403, "cell_create_forbidden".to_owned()),
        "policy before admission"
    );
}

// -- Root policy -------------------------------------------------------------

/// A directory policy reading the root's `policy` column: a contribution is
/// admitted when `root_policy[kind]` exists, born pending when that entry's
/// `moderation_required` is true. It accepts a policy whose entries are all
/// objects and refuses any other with `cell_policy_invalid`.
struct ReadsRootPolicy;

impl CellCreateAuthorize for ReadsRootPolicy {
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        input: &'a CellCreateAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<Verdict, JsonrpcError>> {
        let verdict = if input.root_id.is_none() {
            Verdict::Allow {
                moderation_required: false,
            }
        } else {
            let kind = input.kind.as_deref().unwrap_or_default();
            input
                .root_policy
                .as_ref()
                .and_then(|p| p.get(kind))
                .map_or(Verdict::Deny, |rule| Verdict::Allow {
                    moderation_required: rule
                        .get("moderation_required")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                })
        };
        Box::pin(async move { Ok(verdict) })
    }

    fn validate_policy(&self, policy: &Value) -> Result<(), JsonrpcError> {
        if policy
            .as_object()
            .is_some_and(|rules| rules.values().all(Value::is_object))
        {
            Ok(())
        } else {
            Err(fuz_http::invalid_params(
                "invalid policy",
                Some(ERROR_CELL_POLICY_INVALID),
            ))
        }
    }
}

/// The `cell_policy_set` audit rows' metadata, oldest first.
async fn policy_set_audit_metadata(pool: &Pool) -> Vec<Value> {
    pool.get()
        .await
        .unwrap()
        .query(
            "SELECT metadata::text FROM audit_log WHERE event_type = 'cell_policy_set' ORDER BY seq",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| serde_json::from_str(&row.get::<_, String>(0)).unwrap())
        .collect()
}

/// A non-null policy write needs an authorizer that accepts it: none mounted,
/// or one keeping the default `validate_policy`, refuses it
/// `cell_policy_unsupported`; the mounted validator's own refusal answers
/// otherwise. Clearing a policy needs no authorizer.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn policy_writes_need_an_authorizer_that_accepts_them() {
    let pool = fresh_test_db_pool(DB).await;
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let root = seed_cell(&pool, "forum", CellVisibility::Public, owner_actor).await;
    let policy = json!({"post": {"moderation_required": true}});
    let unsupported = (400, "cell_policy_unsupported".to_owned());

    for (label, options) in [
        ("no authorizer", options_with(&pool, None)),
        ("default validate_policy", options(&pool)),
    ] {
        let created = run(
            &options,
            "cell_create",
            json!({"kind": "forum", "data": {}, "policy": policy}),
            &owner,
        )
        .await;
        assert_eq!(refusal(&created), unsupported, "{label}: create");
        let set = run(
            &options,
            "cell_policy_set",
            json!({"cell_id": root, "policy": policy}),
            &owner,
        )
        .await;
        assert_eq!(refusal(&set), unsupported, "{label}: set");
        let cleared = ok_value(
            run(
                &options,
                "cell_policy_set",
                json!({"cell_id": root, "policy": null}),
                &owner,
            )
            .await,
        );
        assert_eq!(cleared["cell"]["policy"], Value::Null, "{label}: clear");
        // An explicit null on create is no policy.
        ok_value(
            run(
                &options,
                "cell_create",
                json!({"kind": "forum", "data": {}, "policy": null}),
                &owner,
            )
            .await,
        );
    }
    assert_eq!(count_cells(&pool).await, 3, "no refused create wrote a row");

    let options = options_with(&pool, Some(Arc::new(ReadsRootPolicy)));
    for bad in [json!({"post": true}), json!({"post": [1]})] {
        let created = run(
            &options,
            "cell_create",
            json!({"kind": "forum", "data": {}, "policy": bad}),
            &owner,
        )
        .await;
        assert_eq!(
            refusal(&created),
            (400, ERROR_CELL_POLICY_INVALID.to_owned()),
            "{bad}"
        );
    }
    // A non-object is the schema's refusal, before any handler check.
    for bad in [json!([]), json!("post"), json!(1)] {
        match run(
            &options,
            "cell_policy_set",
            json!({"cell_id": root, "policy": bad}),
            &owner,
        )
        .await
        {
            Err(error) => {
                let status = fuz_http::error_code_to_http_status(error.code);
                assert_eq!(status.as_u16(), 400, "{bad}");
                assert!(error.data.is_none(), "{bad}: {error:?}");
            }
            Ok(_) => panic!("{bad}: a non-object policy was stored"),
        }
    }
    // `policy` is required on `cell_policy_set` (`null` clears; absent is no answer).
    match run(
        &options,
        "cell_policy_set",
        json!({"cell_id": root}),
        &owner,
    )
    .await
    {
        Err(error) => {
            let status = fuz_http::error_code_to_http_status(error.code);
            assert_eq!(status.as_u16(), 400);
        }
        Ok(_) => panic!("an absent policy was read as a clear"),
    }
    let created = ok_value(
        run(
            &options,
            "cell_create",
            json!({"kind": "forum", "data": {}, "policy": policy}),
            &owner,
        )
        .await,
    );
    assert_eq!(
        created["cell"]["policy"], policy,
        "the accepted policy is stored"
    );
}

/// `cell_policy_set` is manage-tier and root-only, and the policy is the
/// column — an editor rewriting the root's `data.policy` loosens nothing.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn the_root_policy_is_the_managers_alone() {
    let pool = fresh_test_db_pool(DB).await;
    let options = options_with(&pool, Some(Arc::new(ReadsRootPolicy)));
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (editor, editor_actor) = seed(&pool, "editor").await;
    let (stranger, _) = seed(&pool, "stranger").await;
    let (author, _) = seed(&pool, "author").await;
    let moderated = json!({"post": {"moderation_required": true}});
    let root = ok_value(
        run(
            &options,
            "cell_create",
            json!({"kind": "forum", "data": {}, "visibility": "public", "policy": moderated}),
            &owner,
        )
        .await,
    )["cell"]["id"]
        .as_str()
        .unwrap()
        .parse::<Uuid>()
        .unwrap();
    let hidden_root = seed_cell(&pool, "forum", CellVisibility::Private, owner_actor).await;
    ok_value(
        run(
            &options,
            "cell_grant_create",
            json!({
                "cell_id": root,
                "level": "editor",
                "principal": {"kind": "actor", "actor_id": editor_actor},
            }),
            &owner,
        )
        .await,
    );

    // The editor edits the root's content but not its policy.
    let open = json!({"post": {"moderation_required": false}});
    let refused = run(
        &options,
        "cell_policy_set",
        json!({"cell_id": root, "policy": open}),
        &editor,
    )
    .await;
    assert_eq!(
        refusal(&refused),
        (403, "cell_policy_manage_only".to_owned())
    );
    let edited = ok_value(
        run(
            &options,
            "cell_update",
            json!({"cell_id": root, "data": {"policy": open}}),
            &editor,
        )
        .await,
    );
    assert_eq!(
        edited["cell"]["policy"], moderated,
        "a data write leaves the policy"
    );
    // A contribution still reads the column: born pending.
    let post = ok_value(
        run(
            &options,
            "cell_create",
            json!({"kind": "post", "data": {}, "parent_id": root}),
            &author,
        )
        .await,
    );
    assert_eq!(
        post["cell"]["moderation"], "pending",
        "the policy the authorizer reads is the column, not `data.policy`"
    );
    let post_id = post["cell"]["id"].as_str().unwrap().to_owned();

    // A stranger who can't view the root gets the mask.
    let masked = run(
        &options,
        "cell_policy_set",
        json!({"cell_id": hidden_root, "policy": open}),
        &stranger,
    )
    .await;
    assert_eq!(refusal(&masked), (404, "cell_not_found".to_owned()));

    // Root-only, on the verb and at create.
    let on_contribution = run(
        &options,
        "cell_policy_set",
        json!({"cell_id": post_id, "policy": open}),
        &author,
    )
    .await;
    assert_eq!(
        refusal(&on_contribution),
        (400, "cell_policy_root_only".to_owned())
    );
    let beside_parent = run(
        &options,
        "cell_create",
        json!({"kind": "post", "data": {}, "parent_id": root, "policy": open}),
        &author,
    )
    .await;
    assert_eq!(
        refusal(&beside_parent),
        (400, "cell_policy_root_only".to_owned())
    );
    assert!(
        policy_set_audit_metadata(&pool).await.is_empty(),
        "no refused set is audited"
    );

    // The owner sets it; the row and the audit agree.
    let set = ok_value(
        run(
            &options,
            "cell_policy_set",
            json!({"cell_id": root, "policy": open}),
            &owner,
        )
        .await,
    );
    assert_eq!(set["cell"]["policy"], open);
    let live = ok_value(
        run(
            &options,
            "cell_create",
            json!({"kind": "post", "data": {}, "parent_id": root}),
            &author,
        )
        .await,
    );
    assert_eq!(
        live["cell"]["moderation"], "approved",
        "the new policy governs"
    );
    ok_value(
        run(
            &options,
            "cell_policy_set",
            json!({"cell_id": root, "policy": null}),
            &owner,
        )
        .await,
    );
    assert_eq!(
        policy_set_audit_metadata(&pool).await,
        vec![
            json!({"cell_id": root, "policy": open, "previous_policy": moderated}),
            json!({"cell_id": root, "policy": null, "previous_policy": open}),
        ]
    );
    let denied = run(
        &options,
        "cell_create",
        json!({"kind": "post", "data": {}, "parent_id": root}),
        &author,
    )
    .await;
    assert_eq!(
        refusal(&denied),
        (403, "cell_create_forbidden".to_owned()),
        "a cleared policy admits nothing under this authorizer"
    );

    // A clone of a root with a policy is born without one.
    ok_value(
        run(
            &options,
            "cell_policy_set",
            json!({"cell_id": root, "policy": moderated}),
            &owner,
        )
        .await,
    );
    let clone = ok_value(
        run(
            &options,
            "cell_clone",
            json!({"source_id": root}),
            &stranger,
        )
        .await,
    );
    assert_eq!(
        clone["cell"]["policy"],
        Value::Null,
        "a clone has no policy"
    );
}

// -- Grant-create authorizer ---------------------------------------------------

/// A grant authorizer answering `allow` and counting its calls.
struct CountingGrantAuthorize {
    allow: bool,
    calls: AtomicUsize,
}

impl CellGrantCreateAuthorize for CountingGrantAuthorize {
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        _input: &'a CellGrantCreateAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let allow = self.allow;
        Box::pin(async move { Ok(allow) })
    }
}

async fn count_grant_rows(pool: &Pool) -> (i64, i64) {
    let client = pool.get().await.unwrap();
    let grants: i64 = client
        .query_one("SELECT count(*) FROM cell_grant", &[])
        .await
        .unwrap()
        .get(0);
    let audits: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE event_type = 'cell_grant_create'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    (grants, audits)
}

/// The grant authorizer runs only for a manager past the spine's gates, and its
/// refusal writes nothing.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn the_grant_authorizer_gates_a_manager_after_the_spine_gates() {
    let pool = fresh_test_db_pool(DB).await;
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (stranger, _) = seed(&pool, "stranger").await;
    let (_, target) = seed(&pool, "target").await;
    let cell = seed_cell(&pool, "note", CellVisibility::Public, owner_actor).await;
    let grant = |level: &str| {
        json!({
            "cell_id": cell,
            "level": level,
            "principal": {"kind": "actor", "actor_id": target},
        })
    };

    let deny = Arc::new(CountingGrantAuthorize {
        allow: false,
        calls: AtomicUsize::new(0),
    });
    let deny_dyn: Arc<dyn CellGrantCreateAuthorize> = Arc::<CountingGrantAuthorize>::clone(&deny);
    let options = options_full(&pool, None, Some(deny_dyn));
    let masked = run(&options, "cell_grant_create", grant("viewer"), &stranger).await;
    assert_eq!(refusal(&masked), (404, "cell_not_found".to_owned()));
    let unknown_role = run(
        &options,
        "cell_grant_create",
        json!({"cell_id": cell, "level": "viewer", "principal": {"kind": "role", "role": "nobody"}}),
        &owner,
    )
    .await;
    assert_eq!(
        refusal(&unknown_role),
        (400, "cell_grant_unknown_role".to_owned())
    );
    assert_eq!(
        deny.calls.load(Ordering::SeqCst),
        0,
        "the hook sees only managers past the gates"
    );
    let refused = run(&options, "cell_grant_create", grant("viewer"), &owner).await;
    assert_eq!(
        refusal(&refused),
        (403, "cell_grant_not_authorized".to_owned())
    );
    assert_eq!(deny.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        count_grant_rows(&pool).await,
        (0, 0),
        "a refusal writes no grant and no audit"
    );

    // No authorizer: today's behavior.
    let open = options_full(&pool, None, None);
    ok_value(run(&open, "cell_grant_create", grant("viewer"), &owner).await);
    assert_eq!(count_grant_rows(&pool).await, (1, 1));

    // A level change goes through it too.
    let refused = run(&options, "cell_grant_create", grant("editor"), &owner).await;
    assert_eq!(
        refusal(&refused),
        (403, "cell_grant_not_authorized".to_owned())
    );
    let allow = Arc::new(CountingGrantAuthorize {
        allow: true,
        calls: AtomicUsize::new(0),
    });
    let allow_dyn: Arc<dyn CellGrantCreateAuthorize> = Arc::<CountingGrantAuthorize>::clone(&allow);
    let allowing = options_full(&pool, None, Some(allow_dyn));
    let upserted = ok_value(run(&allowing, "cell_grant_create", grant("editor"), &owner).await);
    assert_eq!(upserted["grant"]["level"], "editor");
    assert_eq!(allow.calls.load(Ordering::SeqCst), 1);
    assert_eq!(count_grant_rows(&pool).await, (1, 2));
}

// -- Grant-revoke authorizer ---------------------------------------------------

/// A revoke authorizer answering `allow`, recording every input it saw.
struct RecordingRevokeAuthorize {
    allow: bool,
    seen: Mutex<Vec<CellGrantRevokeAuthorizeInput>>,
}

impl RecordingRevokeAuthorize {
    fn new(allow: bool) -> Arc<Self> {
        Arc::new(Self {
            allow,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl CellGrantRevokeAuthorize for RecordingRevokeAuthorize {
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        input: &'a CellGrantRevokeAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>> {
        self.seen.lock().unwrap().push(input.clone());
        let allow = self.allow;
        Box::pin(async move { Ok(allow) })
    }
}

fn revoke_options(pool: &Pool, hook: &Arc<RecordingRevokeAuthorize>) -> PerformActionOptions {
    let hook: Arc<dyn CellGrantRevokeAuthorize> = Arc::<RecordingRevokeAuthorize>::clone(hook);
    options_all(pool, None, None, Some(hook))
}

/// The `cell_grant_revoke` audit rows' metadata, oldest first.
async fn revoke_audit_metadata(pool: &Pool) -> Vec<Value> {
    pool.get()
        .await
        .unwrap()
        .query(
            "SELECT metadata::text FROM audit_log WHERE event_type = 'cell_grant_revoke' ORDER BY seq",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| serde_json::from_str(row.get::<_, &str>(0)).unwrap())
        .collect()
}

async fn grant_exists(pool: &Pool, grant_id: &Value) -> bool {
    let id: Uuid = grant_id.as_str().unwrap().parse().unwrap();
    pool.get()
        .await
        .unwrap()
        .query_opt("SELECT 1 FROM cell_grant WHERE id = $1", &[&id])
        .await
        .unwrap()
        .is_some()
}

/// Owner-made grant on `cell`, returning its id.
async fn create_grant(
    options: &PerformActionOptions,
    owner: &AccountRow,
    cell: Uuid,
    principal: Value,
) -> Value {
    ok_value(
        run(
            options,
            "cell_grant_create",
            json!({"cell_id": cell, "level": "viewer", "principal": principal}),
            owner,
        )
        .await,
    )["grant"]["id"]
        .clone()
}

/// No hook: a scope's would-be steward gets the 404 mask, as before the seam.
/// An allowing hook admits them — the row goes, and the audit row stamps
/// `steward: true` — after being asked with the grant's own fields.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn the_revoke_authorizer_admits_a_scope_steward() {
    let pool = fresh_test_db_pool(DB).await;
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (steward, _) = seed(&pool, "steward").await;
    let scope = Uuid::new_v4();
    let cell = seed_cell(&pool, "note", CellVisibility::Private, owner_actor).await;
    let open = options_full(&pool, None, None);
    let grant_id = create_grant(
        &open,
        &owner,
        cell,
        json!({"kind": "role", "role": ROLE_MEMBER, "scope_id": scope}),
    )
    .await;
    let revoke = json!({"grant_id": grant_id});

    let unmounted = run(&open, "cell_grant_revoke", revoke.clone(), &steward).await;
    assert_eq!(
        refusal(&unmounted),
        (404, "cell_grant_not_found".to_owned())
    );
    assert!(grant_exists(&pool, &grant_id).await);

    let allow = RecordingRevokeAuthorize::new(true);
    let revoked = ok_value(
        run(
            &revoke_options(&pool, &allow),
            "cell_grant_revoke",
            revoke,
            &steward,
        )
        .await,
    );
    assert_eq!(revoked["ok"], json!(true));
    assert_eq!(revoked["still_admitted"], json!(false));
    assert!(!grant_exists(&pool, &grant_id).await, "the grant is gone");
    let seen = allow.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let asked = &seen[0];
    assert_eq!(json!(asked.grant_id), grant_id);
    assert_eq!(asked.cell_id, cell);
    assert_eq!(asked.cell_created_by, Some(owner_actor));
    assert_eq!(asked.role, ROLE_MEMBER);
    assert_eq!(asked.scope_id, scope);
    assert_eq!(json!(asked.level), json!("viewer"));
    let audits = revoke_audit_metadata(&pool).await;
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0]["steward"], json!(true));
    assert_eq!(audits[0]["grant_id"], grant_id);
    assert!(audits[0].get("self").is_none());
}

/// A refusing hook answers the same 404 mask — no 403, no audit row, the grant
/// kept.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn a_revoke_authorizer_refusal_is_the_404_mask() {
    let pool = fresh_test_db_pool(DB).await;
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (stranger, _) = seed(&pool, "stranger").await;
    let cell = seed_cell(&pool, "note", CellVisibility::Public, owner_actor).await;
    let deny = RecordingRevokeAuthorize::new(false);
    let options = revoke_options(&pool, &deny);
    let grant_id = create_grant(
        &options,
        &owner,
        cell,
        json!({"kind": "role", "role": ROLE_MEMBER, "scope_id": Uuid::new_v4()}),
    )
    .await;
    let refused = run(
        &options,
        "cell_grant_revoke",
        json!({"grant_id": grant_id}),
        &stranger,
    )
    .await;
    assert_eq!(refusal(&refused), (404, "cell_grant_not_found".to_owned()));
    assert_eq!(deny.calls(), 1);
    assert!(grant_exists(&pool, &grant_id).await, "the grant is kept");
    assert!(
        revoke_audit_metadata(&pool).await.is_empty(),
        "no audit row"
    );
}

/// A steward hook that admits after a level change lands on the grant it was
/// asked about — standing in for a concurrent `cell_grant_create` upsert
/// between the hook's read and the delete. It writes through the request's own
/// handle, which a real hook must never do; here that is the point.
struct LevelRaceRevokeAuthorize;

impl CellGrantRevokeAuthorize for LevelRaceRevokeAuthorize {
    fn authorize<'a>(
        &'a self,
        _auth: &'a RequestActorContext,
        input: &'a CellGrantRevokeAuthorizeInput,
        db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>> {
        Box::pin(async move {
            assert!(
                matches!(db, ActionDb::Tx(_)),
                "the revoke hook runs in the request transaction"
            );
            db.execute(
                "UPDATE cell_grant SET level = 'editor' WHERE id = $1",
                &[&input.grant_id],
            )
            .await
            .unwrap();
            Ok(true)
        })
    }
}

/// A steward's revoke deletes the grant the hook decided on: when the grant's
/// level moved after the hook read it, the delete matches nothing and the
/// steward gets the 404 mask, no audit row — the grant kept at its old level.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn a_steward_revoke_fences_the_delete_to_the_judged_level() {
    let pool = fresh_test_db_pool(DB).await;
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (steward, _) = seed(&pool, "steward").await;
    let cell = seed_cell(&pool, "note", CellVisibility::Private, owner_actor).await;
    let hook: Arc<dyn CellGrantRevokeAuthorize> = Arc::new(LevelRaceRevokeAuthorize);
    let options = options_all(&pool, None, None, Some(hook));
    let grant_id = create_grant(
        &options,
        &owner,
        cell,
        json!({"kind": "role", "role": ROLE_MEMBER, "scope_id": Uuid::new_v4()}),
    )
    .await;

    let raced = run(
        &options,
        "cell_grant_revoke",
        json!({"grant_id": grant_id}),
        &steward,
    )
    .await;
    assert_eq!(refusal(&raced), (404, "cell_grant_not_found".to_owned()));
    assert!(grant_exists(&pool, &grant_id).await, "the grant is kept");
    assert!(
        revoke_audit_metadata(&pool).await.is_empty(),
        "no audit row"
    );
    // the hook's UPDATE rode the request transaction, so the refusal rolled it
    // back with everything else
    let id: Uuid = grant_id.as_str().unwrap().parse().unwrap();
    let level: String = pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT level FROM cell_grant WHERE id = $1", &[&id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(level, "viewer", "the hook's level change rolled back");
}

/// The fence: an actor-shaped grant, a scopeless role grant, a manager's
/// revoke, a self-revoke, and a soft-deleted cell never reach the hook — even
/// an allowing one.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_cell_actions_test database"]
async fn the_revoke_authorizer_is_fenced_to_scoped_role_grants_of_non_managers() {
    let pool = fresh_test_db_pool(DB).await;
    let (owner, owner_actor) = seed(&pool, "owner").await;
    let (stranger, _) = seed(&pool, "stranger").await;
    let (holder, holder_actor) = seed(&pool, "holder").await;
    let cell = seed_cell(&pool, "note", CellVisibility::Private, owner_actor).await;
    let allow = RecordingRevokeAuthorize::new(true);
    let options = revoke_options(&pool, &allow);

    let actor_shaped = create_grant(
        &options,
        &owner,
        cell,
        json!({"kind": "actor", "actor_id": holder_actor}),
    )
    .await;
    let scopeless = create_grant(
        &options,
        &owner,
        cell,
        json!({"kind": "role", "role": ROLE_MEMBER}),
    )
    .await;
    for grant_id in [&actor_shaped, &scopeless] {
        let refused = run(
            &options,
            "cell_grant_revoke",
            json!({"grant_id": grant_id}),
            &stranger,
        )
        .await;
        assert_eq!(refusal(&refused), (404, "cell_grant_not_found".to_owned()));
    }
    assert_eq!(allow.calls(), 0, "neither grant shape reaches the hook");

    // self-revoke and a manager's revoke take their own paths
    ok_value(
        run(
            &options,
            "cell_grant_revoke",
            json!({"grant_id": actor_shaped}),
            &holder,
        )
        .await,
    );
    let scoped = create_grant(
        &options,
        &owner,
        cell,
        json!({"kind": "role", "role": ROLE_MEMBER, "scope_id": Uuid::new_v4()}),
    )
    .await;
    ok_value(
        run(
            &options,
            "cell_grant_revoke",
            json!({"grant_id": scoped}),
            &owner,
        )
        .await,
    );
    assert_eq!(
        allow.calls(),
        0,
        "a self-closer and a manager never consult it"
    );
    let audits = revoke_audit_metadata(&pool).await;
    assert_eq!(audits.len(), 2);
    assert_eq!(audits[0]["self"], json!(true));
    for audit in &audits {
        assert!(audit.get("steward").is_none(), "{audit}");
    }

    // a soft-deleted cell 404s before the hook
    let scoped = create_grant(
        &options,
        &owner,
        cell,
        json!({"kind": "role", "role": ROLE_MEMBER, "scope_id": Uuid::new_v4()}),
    )
    .await;
    ok_value(run(&options, "cell_delete", json!({"cell_id": cell}), &owner).await);
    let gone = run(
        &options,
        "cell_grant_revoke",
        json!({"grant_id": scoped}),
        &stranger,
    )
    .await;
    assert_eq!(refusal(&gone), (404, "cell_grant_not_found".to_owned()));
    assert_eq!(allow.calls(), 0, "a deleted cell never reaches the hook");
}
