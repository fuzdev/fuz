//! PG-backed integration tests for the `fuz_cell` query layer.
//!
//! Exercises the raw SQL the unit tests can't reach: the JSONB
//! `::text`/`::jsonb` round-trip, the `to_char` timestamp projection, the
//! `CASE WHEN provided` partial update (including tri-state `path` clear),
//! soft-delete freeing the partial-unique `path`, the duplicate-`path`
//! unique violation, the first-cut `cell_list` visibility predicate, and the
//! root-only, object-only `policy` column.
//!
//! `--ignored`-gated (needs Postgres). Run single-threaded against the
//! shared `fuz_cell_test` DB:
//!
//! ```sh
//! cargo test -p fuz_cell -- --ignored --test-threads=1
//! ```

mod common;

use common::{fresh_db_pool, seed_actor};
use fuz_cell::CellVisibility;
use fuz_cell::cell_queries::{
    CELL_LIST_LIMIT_MAX, CellListParams, query_cell_create, query_cell_delete, query_cell_get,
    query_cell_get_by_path, query_cell_list, query_cell_list_by_kind, query_cell_set_policy,
    query_cell_update,
};
use fuz_cell::cell_view_sql::CellViewer;
use fuz_db::is_pg_unique_violation;
use serde_json::json;

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn create_then_get_round_trips_wire_shape() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let actor = seed_actor(&pool, "creator").await;

    let data = json!({"label": "hi", "cover": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
    let created = query_cell_create(
        &client,
        &data,
        Some("doc"),
        Some(CellVisibility::Public),
        Some("docs/intro"),
        None,
        None,
        None,
        None,
        Some(actor),
    )
    .await
    .expect("create");

    assert_eq!(created.data, data);
    assert_eq!(created.kind.as_deref(), Some("doc"));
    assert_eq!(created.visibility, CellVisibility::Public);
    assert_eq!(created.path.as_deref(), Some("docs/intro"));
    assert_eq!(
        created.refs,
        Some(vec![
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()
        ])
    );
    assert_eq!(created.created_by, Some(actor));
    assert_eq!(created.updated_by, None);
    assert!(created.updated_at.is_none());
    assert!(created.deleted_at.is_none());
    assert_eq!(created.grant_count, 0);
    // Second-precision UTC ISO-8601, `Z`-suffixed.
    assert!(created.created_at.ends_with('Z'), "{}", created.created_at);
    assert_eq!(created.created_at.len(), "2026-01-01T00:00:00Z".len());

    let by_id = query_cell_get(&client, created.id)
        .await
        .expect("get by id")
        .expect("present");
    assert_eq!(by_id.id, created.id);

    let by_path = query_cell_get_by_path(&client, "docs/intro")
        .await
        .expect("get by path")
        .expect("present");
    assert_eq!(by_path.id, created.id);
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn update_partial_keeps_then_clears_path() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let actor = seed_actor(&pool, "editor").await;

    let created = query_cell_create(
        &client,
        &json!({"n": 1}),
        Some("note"),
        None,
        Some("notes/a"),
        None,
        None,
        None,
        None,
        Some(actor),
    )
    .await
    .expect("create");
    assert_eq!(created.visibility, CellVisibility::Private);

    // data-only update: `path` absent (None) keeps it; refs re-derived.
    let new_data = json!({"n": 2, "ref": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"});
    let updated = query_cell_update(
        &client,
        created.id,
        Some(&new_data),
        None,
        None,
        Some(actor),
    )
    .await
    .expect("update")
    .expect("present");
    assert_eq!(updated.data, new_data);
    assert_eq!(
        updated.refs,
        Some(vec![
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
        ])
    );
    assert_eq!(updated.path.as_deref(), Some("notes/a"));
    assert_eq!(updated.updated_by, Some(actor));
    assert!(updated.updated_at.is_some());

    // tri-state clear: Some(None) nulls the path.
    let cleared = query_cell_update(&client, created.id, None, None, Some(None), Some(actor))
        .await
        .expect("clear path")
        .expect("present");
    assert_eq!(cleared.path, None);
    // data untouched by the clear.
    assert_eq!(cleared.data, new_data);

    assert!(
        query_cell_get_by_path(&client, "notes/a")
            .await
            .expect("get by path")
            .is_none(),
        "path freed after clear"
    );
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn soft_delete_hides_row_and_is_idempotent() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let actor = seed_actor(&pool, "deleter").await;

    let created = query_cell_create(
        &client,
        &json!({}),
        Some("x"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(actor),
    )
    .await
    .expect("create");

    assert!(
        query_cell_delete(&client, created.id, Some(actor))
            .await
            .expect("delete"),
        "first delete tombstones"
    );
    assert!(
        query_cell_get(&client, created.id)
            .await
            .expect("get")
            .is_none(),
        "tombstoned row excluded from reads"
    );
    assert!(
        !query_cell_delete(&client, created.id, Some(actor))
            .await
            .expect("delete again"),
        "second delete matches nothing"
    );
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn path_reuse_allowed_after_soft_delete() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let actor = seed_actor(&pool, "reuser").await;

    let first = query_cell_create(
        &client,
        &json!({}),
        Some("x"),
        None,
        Some("shared/path"),
        None,
        None,
        None,
        None,
        Some(actor),
    )
    .await
    .expect("create first");
    query_cell_delete(&client, first.id, Some(actor))
        .await
        .expect("delete first");

    // The partial unique index excludes tombstones, so the path is free.
    let second = query_cell_create(
        &client,
        &json!({}),
        Some("y"),
        None,
        Some("shared/path"),
        None,
        None,
        None,
        None,
        Some(actor),
    )
    .await
    .expect("create second reuses freed path");
    assert_ne!(second.id, first.id);
    assert_eq!(second.path.as_deref(), Some("shared/path"));
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn duplicate_active_path_is_unique_violation() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let actor = seed_actor(&pool, "dupes").await;

    query_cell_create(
        &client,
        &json!({}),
        Some("x"),
        None,
        Some("taken"),
        None,
        None,
        None,
        None,
        Some(actor),
    )
    .await
    .expect("create first");

    let err = query_cell_create(
        &client,
        &json!({}),
        Some("y"),
        None,
        Some("taken"),
        None,
        None,
        None,
        None,
        Some(actor),
    )
    .await
    .expect_err("duplicate active path rejected");

    match err {
        fuz_cell::CellError::Db(e) => {
            assert!(is_pg_unique_violation(&e), "expected 23505, got {e:?}");
        }
        other @ fuz_cell::CellError::Decode(_) => {
            panic!("expected Db unique violation, got {other:?}")
        }
    }
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn list_visibility_predicate_filters_by_viewer() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let stranger = seed_actor(&pool, "stranger").await;

    let private = query_cell_create(
        &client,
        &json!({}),
        Some("secret"),
        Some(CellVisibility::Private),
        None,
        None,
        None,
        None,
        None,
        Some(owner),
    )
    .await
    .expect("create private");
    let public = query_cell_create(
        &client,
        &json!({}),
        Some("open"),
        Some(CellVisibility::Public),
        None,
        None,
        None,
        None,
        None,
        Some(owner),
    )
    .await
    .expect("create public");

    let params = |actor: Option<uuid::Uuid>, is_admin: bool| CellListParams {
        viewer: match (actor, is_admin) {
            (_, true) => CellViewer::unrestricted(),
            (Some(actor), false) => CellViewer::for_actor(actor, []),
            (None, false) => CellViewer::default(),
        },
        limit: 50,
        ..Default::default()
    };

    // Anonymous: public only.
    let anon = query_cell_list(&client, &params(None, false))
        .await
        .expect("anon list");
    let anon_ids: Vec<_> = anon.iter().map(|c| c.id).collect();
    assert!(anon_ids.contains(&public.id));
    assert!(!anon_ids.contains(&private.id), "private hidden from anon");

    // Owner: own private + public.
    let owner_ids: Vec<_> = query_cell_list(&client, &params(Some(owner), false))
        .await
        .expect("owner list")
        .iter()
        .map(|c| c.id)
        .collect();
    assert!(owner_ids.contains(&public.id));
    assert!(owner_ids.contains(&private.id), "owner sees own private");

    // Stranger: public only (holds no grant).
    let stranger_ids: Vec<_> = query_cell_list(&client, &params(Some(stranger), false))
        .await
        .expect("stranger list")
        .iter()
        .map(|c| c.id)
        .collect();
    assert!(stranger_ids.contains(&public.id));
    assert!(
        !stranger_ids.contains(&private.id),
        "stranger cannot see another's private cell"
    );

    // Admin: everything.
    let admin_ids: Vec<_> = query_cell_list(&client, &params(None, true))
        .await
        .expect("admin list")
        .iter()
        .map(|c| c.id)
        .collect();
    assert!(admin_ids.contains(&public.id));
    assert!(admin_ids.contains(&private.id), "admin sees all");

    // `kind` filter matches the top-level `cell.kind` column (not `data`).
    let by_kind = query_cell_list(
        &client,
        &CellListParams {
            kind: Some("open"),
            viewer: CellViewer::unrestricted(),
            limit: 50,
            ..Default::default()
        },
    )
    .await
    .expect("kind-filtered list");
    let kind_ids: Vec<_> = by_kind.iter().map(|c| c.id).collect();
    assert!(
        kind_ids.contains(&public.id),
        "kind=open matches the open cell"
    );
    assert!(
        !kind_ids.contains(&private.id),
        "kind=open excludes the secret cell"
    );
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn list_by_kind_is_unbounded_newest_first_and_skips_tombstones() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "kind_owner").await;

    // Past the paged `CELL_LIST_LIMIT_MAX`, so a `limit: None` read that
    // silently inherited that cap would come back short.
    let total = usize::try_from(CELL_LIST_LIMIT_MAX).expect("cap fits usize") + 1;
    let mut created = Vec::with_capacity(total);
    for i in 0..total {
        created.push(
            query_cell_create(
                &client,
                &json!({"n": i}),
                Some("bulk"),
                Some(CellVisibility::Private),
                Some(&format!("bulk/{i}")),
                None,
                None,
                None,
                None,
                Some(owner),
            )
            .await
            .expect("create bulk"),
        );
    }
    // A different kind that must never appear in the `bulk` listing.
    query_cell_create(
        &client,
        &json!({}),
        Some("other"),
        Some(CellVisibility::Private),
        None,
        None,
        None,
        None,
        None,
        Some(owner),
    )
    .await
    .expect("create other");

    let all = query_cell_list_by_kind(&client, "bulk", None, 0)
        .await
        .expect("unbounded list");
    assert_eq!(all.len(), total, "no limit means no truncation");
    assert!(all.iter().all(|c| c.kind.as_deref() == Some("bulk")));
    // `created_at DESC` — ties on the second-precision column keep every row,
    // which is what the count above already pins; the boundary rows are what
    // the order claim rests on.
    let newest = all.first().expect("non-empty").created_at.clone();
    let oldest = all.last().expect("non-empty").created_at.clone();
    assert!(newest >= oldest, "newest first ({newest} then {oldest})");

    // `limit` / `offset` page the same set.
    let page = query_cell_list_by_kind(&client, "bulk", Some(10), 5)
        .await
        .expect("paged list");
    assert_eq!(page.len(), 10);
    assert_eq!(page[0].id, all[5].id, "offset skips the first 5");

    // Tombstones are excluded, like every other read.
    query_cell_delete(&client, created[0].id, Some(owner))
        .await
        .expect("delete");
    let after = query_cell_list_by_kind(&client, "bulk", None, 0)
        .await
        .expect("list after delete");
    assert_eq!(after.len(), total - 1);
    assert!(!after.iter().any(|c| c.id == created[0].id));
}

/// `policy` round-trips on a root, and the table CHECK holds it to roots and
/// to JSON objects; `query_cell_set_policy` writes only a root and
/// `query_cell_update` never touches it.
#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn policy_is_a_roots_json_object() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let actor = seed_actor(&pool, "owner").await;
    let policy = json!({"post": {"moderation_required": true}});

    let root = query_cell_create(
        &client,
        &json!({}),
        Some("forum"),
        None,
        None,
        None,
        None,
        None,
        Some(&policy),
        Some(actor),
    )
    .await
    .expect("a root takes a policy");
    assert_eq!(root.policy.as_ref(), Some(&policy));
    let child = query_cell_create(
        &client,
        &json!({}),
        Some("post"),
        None,
        None,
        Some(root.id),
        Some(root.id),
        None,
        None,
        Some(actor),
    )
    .await
    .expect("a contribution without a policy");
    assert_eq!(child.policy, None);

    // The CHECK: no policy beside a parent, and none that isn't an object.
    for (parent, bad) in [
        (Some(root.id), policy.clone()),
        (None, json!([1])),
        (None, json!("x")),
        (None, json!([{}])),
    ] {
        let refused = query_cell_create(
            &client,
            &json!({}),
            None,
            None,
            None,
            parent,
            parent,
            None,
            Some(&bad),
            Some(actor),
        )
        .await;
        assert!(refused.is_err(), "{parent:?} {bad}");
    }

    // The dedicated write moves a root and refuses a contribution.
    let open = json!({"post": {"moderation_required": false}});
    let set = query_cell_set_policy(&client, root.id, Some(&open), Some(actor))
        .await
        .expect("set")
        .expect("a root matches");
    assert_eq!(set.cell.policy.as_ref(), Some(&open));
    assert_eq!(set.cell.updated_by, Some(actor));
    assert_eq!(set.previous_policy.as_ref(), Some(&policy));
    assert!(
        query_cell_set_policy(&client, child.id, Some(&open), Some(actor))
            .await
            .expect("set on a contribution")
            .is_none(),
        "a contribution never matches"
    );
    // A `data` write leaves the column.
    let updated = query_cell_update(
        &client,
        root.id,
        Some(&json!({"policy": policy})),
        None,
        None,
        Some(actor),
    )
    .await
    .expect("update")
    .expect("present");
    assert_eq!(updated.policy.as_ref(), Some(&open));
    let cleared = query_cell_set_policy(&client, root.id, None, Some(actor))
        .await
        .expect("clear")
        .expect("present");
    assert_eq!(cleared.cell.policy, None);
    assert_eq!(cleared.previous_policy.as_ref(), Some(&open));
    let again = query_cell_set_policy(&client, root.id, Some(&policy), Some(actor))
        .await
        .expect("set after clear")
        .expect("present");
    assert_eq!(again.previous_policy, None);
    assert_eq!(again.cell.policy.as_ref(), Some(&policy));
}

/// A `query_cell_set_policy` waiting on a concurrent set's row lock answers
/// the policy that set committed, not the one its own snapshot held — so
/// `cell_policy_set`'s audited `previous_policy` is what the write replaced.
/// Twin of `fuz_app`'s `cell_queries.set_policy.db.test.ts`.
#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn policy_set_reads_the_previous_policy_under_its_lock() {
    let pool = fresh_db_pool().await;
    let actor = seed_actor(&pool, "owner").await;
    let first_policy = json!({"post": {"moderation_required": true}});
    let second_policy = json!({"post": {"moderation_required": false}});
    let third_policy = json!({"comment": {"moderation_required": true}});
    let root = {
        let client = pool.get().await.expect("pool.get");
        query_cell_create(
            &client,
            &json!({}),
            Some("forum"),
            None,
            None,
            None,
            None,
            None,
            Some(&first_policy),
            Some(actor),
        )
        .await
        .expect("create")
    };

    let mut first_client = pool.get().await.expect("pool.get");
    let first = first_client.transaction().await.expect("begin");
    let set = query_cell_set_policy(&first, root.id, Some(&second_policy), Some(actor))
        .await
        .expect("first set")
        .expect("present");
    assert_eq!(set.previous_policy.as_ref(), Some(&first_policy));

    let second = tokio::spawn({
        let pool = pool.clone();
        let third_policy = third_policy.clone();
        async move {
            let mut client = pool.get().await.expect("pool.get");
            let tx = client.transaction().await.expect("begin");
            let set = query_cell_set_policy(&tx, root.id, Some(&third_policy), Some(actor))
                .await
                .expect("second set")
                .expect("present");
            tx.commit().await.expect("commit");
            set
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !second.is_finished(),
        "the second set waits on the first's row lock"
    );
    first.commit().await.expect("commit");
    let set = tokio::time::timeout(std::time::Duration::from_secs(10), second)
        .await
        .expect("the second set completes")
        .expect("join");
    assert_eq!(
        set.previous_policy.as_ref(),
        Some(&second_policy),
        "the committed value, not the snapshot"
    );
    assert_eq!(set.cell.policy.as_ref(), Some(&third_policy));
}
