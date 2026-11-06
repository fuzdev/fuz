//! PG-backed integration tests for the `fuz_cell` grant / field / item /
//! audit query layers + `query_cell_load_many`.
//!
//! Exercises the raw SQL the unit tests can't reach: the grant UPSERT on
//! the two partial unique indexes, the `(source_id, name)` field UPSERT +
//! soft-delete JOIN filtering, the `(parent_id, position)` item collision
//! (`23505`), fractional-index lex ordering + cursor pagination, the bulk
//! id load, and the metadata-GIN `cell_audit` containment OR.
//!
//! `--ignored`-gated (needs Postgres). Run single-threaded against the
//! shared `fuz_cell_test` DB:
//!
//! ```sh
//! cargo test -p fuz_cell -- --ignored --test-threads=1
//! ```

// Integration-test helpers assert via `expect`/`unwrap`; `allow-*-in-tests`
// doesn't cover the non-`#[test]` helper fns.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{fresh_db_pool, seed_actor};
use fuz_cell::cell_audit_queries::query_audit_log_list_by_cell;
use fuz_cell::cell_field_queries::{
    query_cell_field_delete, query_cell_field_list_for_source, query_cell_field_list_for_target,
    query_cell_field_set,
};
use fuz_cell::cell_grant_queries::{
    query_cell_grant_create, query_cell_grant_delete, query_cell_grant_get,
    query_cell_grant_list_for_cell, query_cell_grant_list_for_cells,
    query_cell_grants_for_caller_in_cells,
};
use fuz_cell::cell_grant_schema::{CellGrantLevel, CellGrantPrincipalInput};
use fuz_cell::cell_item_queries::{
    query_cell_item_delete, query_cell_item_insert, query_cell_item_list_for_child,
    query_cell_item_list_for_parent, query_cell_item_move,
};
use fuz_cell::cell_queries::{query_cell_create, query_cell_delete, query_cell_load_many};
use fuz_cell::cell_view_sql::CellViewer;
use fuz_db::{Pool, is_pg_unique_violation};
use serde_json::json;
use uuid::Uuid;

/// Seed a private cell owned by `owner` and return its id.
async fn seed_cell(pool: &Pool, owner: Uuid) -> Uuid {
    let client = pool.get().await.expect("pool.get");
    query_cell_create(
        &client,
        &json!({}),
        Some("note"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(owner),
    )
    .await
    .expect("create cell")
    .id
}

// -- cell_grant -------------------------------------------------------------

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn grant_actor_upserts_and_round_trips() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let viewer = seed_actor(&pool, "viewer").await;
    let cell = seed_cell(&pool, owner).await;

    let principal = CellGrantPrincipalInput::Actor { actor_id: viewer };
    let created = query_cell_grant_create(
        &client,
        cell,
        CellGrantLevel::Viewer,
        &principal,
        Some(owner),
    )
    .await
    .expect("grant create");
    assert_eq!(created.cell_id, cell);
    assert_eq!(created.actor_id, Some(viewer));
    assert_eq!(created.level, CellGrantLevel::Viewer);
    assert!(created.role.is_none());

    // Re-grant the same actor → UPSERT updates level in place (no dup row).
    let releveled = query_cell_grant_create(
        &client,
        cell,
        CellGrantLevel::Editor,
        &principal,
        Some(owner),
    )
    .await
    .expect("grant re-create");
    assert_eq!(releveled.id, created.id, "UPSERT should reuse the row");
    assert_eq!(releveled.level, CellGrantLevel::Editor);

    let fetched = query_cell_grant_get(&client, created.id)
        .await
        .expect("grant get")
        .expect("present");
    assert_eq!(fetched.level, CellGrantLevel::Editor);

    let listed = query_cell_grant_list_for_cell(&client, cell)
        .await
        .expect("list_for_cell");
    assert_eq!(listed.len(), 1);

    // A delete fenced to a level the grant no longer holds matches nothing.
    assert!(
        query_cell_grant_delete(&client, created.id, Some(CellGrantLevel::Viewer))
            .await
            .expect("level-fenced delete")
            .is_none(),
        "an editor grant survives a delete fenced to viewer"
    );
    let deleted = query_cell_grant_delete(&client, created.id, Some(CellGrantLevel::Editor))
        .await
        .expect("grant delete")
        .expect("returned row");
    assert_eq!(deleted.id, created.id);
    assert!(
        query_cell_grant_get(&client, created.id)
            .await
            .expect("get after delete")
            .is_none()
    );
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn grant_role_and_bulk_list_for_cells() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let cell_a = seed_cell(&pool, owner).await;
    let cell_b = seed_cell(&pool, owner).await;
    let scope = Uuid::new_v4();

    let role_principal = CellGrantPrincipalInput::Role {
        role: "teacher".to_owned(),
        scope_id: Some(scope),
    };
    let g_a = query_cell_grant_create(
        &client,
        cell_a,
        CellGrantLevel::Viewer,
        &role_principal,
        Some(owner),
    )
    .await
    .expect("role grant a");
    assert_eq!(g_a.role.as_deref(), Some("teacher"));
    assert_eq!(g_a.scope_id, Some(scope));
    assert!(g_a.actor_id.is_none());
    query_cell_grant_create(
        &client,
        cell_b,
        CellGrantLevel::Editor,
        &role_principal,
        Some(owner),
    )
    .await
    .expect("role grant b");

    let bulk = query_cell_grant_list_for_cells(&client, &[cell_a, cell_b])
        .await
        .expect("list_for_cells");
    assert_eq!(bulk.len(), 2);
    // Empty input → empty result, no query.
    assert!(
        query_cell_grant_list_for_cells(&client, &[])
            .await
            .expect("empty bulk")
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn grants_for_caller_in_cells_matches_actor_and_role() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let viewer = seed_actor(&pool, "viewer").await;
    let stranger = seed_actor(&pool, "stranger").await;
    let cell_a = seed_cell(&pool, owner).await;
    let cell_b = seed_cell(&pool, owner).await;
    let scope = Uuid::new_v4();

    // cell_a: actor-shaped grant to viewer; cell_b: role-shaped grant the
    // viewer holds via a (teacher, scope) role-grant.
    query_cell_grant_create(
        &client,
        cell_a,
        CellGrantLevel::Viewer,
        &CellGrantPrincipalInput::Actor { actor_id: viewer },
        Some(owner),
    )
    .await
    .expect("actor grant");
    query_cell_grant_create(
        &client,
        cell_b,
        CellGrantLevel::Editor,
        &CellGrantPrincipalInput::Role {
            role: "teacher".to_owned(),
            scope_id: Some(scope),
        },
        Some(owner),
    )
    .await
    .expect("role grant");

    // The viewer (actor + the teacher@scope role-grant) is admitted to both.
    let caller = CellViewer::for_actor(viewer, [("teacher", Some(scope))]);
    let matched = query_cell_grants_for_caller_in_cells(&client, &[cell_a, cell_b], &caller)
        .await
        .expect("caller-matched");
    assert_eq!(matched.len(), 2, "actor grant + role-admitted grant");

    // A stranger with no role-grants matches neither grant.
    let none = query_cell_grants_for_caller_in_cells(
        &client,
        &[cell_a, cell_b],
        &CellViewer::for_actor(stranger, []),
    )
    .await
    .expect("stranger");
    assert!(none.is_empty(), "no actor grant, no role admit");

    // Empty cell-id input short-circuits to empty.
    assert!(
        query_cell_grants_for_caller_in_cells(&client, &[], &caller)
            .await
            .expect("empty")
            .is_empty()
    );
}

// -- cell_field -------------------------------------------------------------

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn field_set_upserts_and_soft_delete_filters() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let source = seed_cell(&pool, owner).await;
    let target_a = seed_cell(&pool, owner).await;
    let target_b = seed_cell(&pool, owner).await;

    let row = query_cell_field_set(&client, source, "author", target_a)
        .await
        .expect("field set");
    assert_eq!(row.target_id, target_a);

    // Re-set the same name → re-points target (UPSERT on (source, name)).
    let repointed = query_cell_field_set(&client, source, "author", target_b)
        .await
        .expect("field re-set");
    assert_eq!(repointed.target_id, target_b);

    query_cell_field_set(&client, source, "cover", target_a)
        .await
        .expect("second field");

    // Forward list is name-ordered; both targets active.
    let fwd =
        query_cell_field_list_for_source(&client, &CellViewer::unrestricted(), source, None, None)
            .await
            .expect("list_for_source");
    assert_eq!(fwd.len(), 2);
    assert_eq!(fwd[0].name, "author");
    assert_eq!(fwd[1].name, "cover");

    // Reverse list: target_a is pointed at by `cover` only now.
    let rev =
        query_cell_field_list_for_target(&client, &CellViewer::unrestricted(), target_a, None)
            .await
            .expect("list_for_target");
    assert_eq!(rev.len(), 1);
    assert_eq!(rev[0].name, "cover");
    // `limit` caps the reverse list too
    query_cell_field_set(&client, source, "badge", target_a)
        .await
        .expect("third field");
    let rev_all =
        query_cell_field_list_for_target(&client, &CellViewer::unrestricted(), target_a, None)
            .await
            .expect("list_for_target unbounded");
    assert_eq!(rev_all.len(), 2);
    let rev_page =
        query_cell_field_list_for_target(&client, &CellViewer::unrestricted(), target_a, Some(1))
            .await
            .expect("list_for_target limited");
    assert_eq!(rev_page.len(), 1);
    assert_eq!(rev_page[0].name, rev_all[0].name, "the oldest field first");
    query_cell_field_delete(&client, source, "badge")
        .await
        .expect("drop the third field");

    // Soft-delete target_b → `author` edge drops from the forward list
    // (the JOIN filters `deleted_at IS NULL` on the target).
    query_cell_delete(&client, target_b, Some(owner))
        .await
        .expect("soft delete target_b");
    let fwd_after =
        query_cell_field_list_for_source(&client, &CellViewer::unrestricted(), source, None, None)
            .await
            .expect("list after delete");
    assert_eq!(fwd_after.len(), 1);
    assert_eq!(fwd_after[0].name, "cover");

    // Delete returns the prior row; idempotent on a missing name.
    let deleted = query_cell_field_delete(&client, source, "cover")
        .await
        .expect("field delete")
        .expect("returned row");
    assert_eq!(deleted.target_id, target_a);
    assert!(
        query_cell_field_delete(&client, source, "cover")
            .await
            .expect("idempotent delete")
            .is_none()
    );
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn field_forward_list_cursor_and_limit() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let source = seed_cell(&pool, owner).await;
    let target = seed_cell(&pool, owner).await;
    for name in ["a", "b", "c", "d"] {
        query_cell_field_set(&client, source, name, target)
            .await
            .expect("set");
    }
    let page = query_cell_field_list_for_source(
        &client,
        &CellViewer::unrestricted(),
        source,
        Some(2),
        None,
    )
    .await
    .expect("limited");
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].name, "a");
    assert_eq!(page[1].name, "b");
    // Cursor: names strictly after "b".
    let next = query_cell_field_list_for_source(
        &client,
        &CellViewer::unrestricted(),
        source,
        Some(2),
        Some("b"),
    )
    .await
    .expect("cursor");
    assert_eq!(next[0].name, "c");
    assert_eq!(next[1].name, "d");
}

// -- cell_item --------------------------------------------------------------

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn item_insert_collision_move_delete() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let parent = seed_cell(&pool, owner).await;
    let child = seed_cell(&pool, owner).await;

    query_cell_item_insert(&client, parent, "a0", child)
        .await
        .expect("insert a0");
    // Duplicate (parent, position) → unique violation (23505).
    let collision = query_cell_item_insert(&client, parent, "a0", child).await;
    match collision {
        Err(fuz_cell::CellError::Db(e)) => assert!(is_pg_unique_violation(&e), "expected 23505"),
        other => panic!("expected unique violation, got {other:?}"),
    }

    // Move a0 → m0 (fresh slot) succeeds, returns the moved row.
    let moved = query_cell_item_move(&client, parent, "a0", "m0")
        .await
        .expect("move")
        .expect("row present");
    assert_eq!(moved.position, "m0");
    // Moving a missing source slot → None (raced delete).
    assert!(
        query_cell_item_move(&client, parent, "a0", "z9")
            .await
            .expect("move missing")
            .is_none()
    );

    // Delete returns the prior row; idempotent.
    let deleted = query_cell_item_delete(&client, parent, "m0")
        .await
        .expect("delete")
        .expect("returned row");
    assert_eq!(deleted.child_id, child);
    assert!(
        query_cell_item_delete(&client, parent, "m0")
            .await
            .expect("idempotent")
            .is_none()
    );
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn item_lists_lex_order_cursor_and_soft_delete() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let parent = seed_cell(&pool, owner).await;
    let child_a = seed_cell(&pool, owner).await;
    let child_b = seed_cell(&pool, owner).await;

    // Insert out of lex order; the list must come back sorted by position.
    query_cell_item_insert(&client, parent, "c", child_a)
        .await
        .expect("c");
    query_cell_item_insert(&client, parent, "a", child_a)
        .await
        .expect("a");
    query_cell_item_insert(&client, parent, "b", child_b)
        .await
        .expect("b");

    let items =
        query_cell_item_list_for_parent(&client, &CellViewer::unrestricted(), parent, None, None)
            .await
            .expect("list_for_parent");
    let positions: Vec<&str> = items.iter().map(|i| i.position.as_str()).collect();
    assert_eq!(positions, vec!["a", "b", "c"]);

    // Cursor + limit.
    let page = query_cell_item_list_for_parent(
        &client,
        &CellViewer::unrestricted(),
        parent,
        Some(1),
        Some("a"),
    )
    .await
    .expect("cursor");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].position, "b");

    // Reverse list: child_a is at two positions under one parent.
    let rev = query_cell_item_list_for_child(&client, &CellViewer::unrestricted(), child_a, None)
        .await
        .expect("list_for_child");
    assert_eq!(rev.len(), 2);
    // `limit` caps the reverse list too, oldest item first
    let rev_page =
        query_cell_item_list_for_child(&client, &CellViewer::unrestricted(), child_a, Some(1))
            .await
            .expect("list_for_child limited");
    assert_eq!(rev_page.len(), 1);
    assert_eq!(rev_page[0].position, rev[0].position);

    // Soft-delete child_b → its item drops from the forward list.
    query_cell_delete(&client, child_b, Some(owner))
        .await
        .expect("delete child_b");
    let after =
        query_cell_item_list_for_parent(&client, &CellViewer::unrestricted(), parent, None, None)
            .await
            .expect("list after delete");
    assert_eq!(after.len(), 2);
    assert!(after.iter().all(|i| i.position != "b"));
}

// -- load_many --------------------------------------------------------------

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn load_many_returns_active_only() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let a = seed_cell(&pool, owner).await;
    let b = seed_cell(&pool, owner).await;
    query_cell_delete(&client, b, Some(owner))
        .await
        .expect("delete b");

    let loaded = query_cell_load_many(&client, &[a, b, Uuid::new_v4()])
        .await
        .expect("load_many");
    // Only `a` is active; `b` is tombstoned, the random id is absent.
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, a);
    assert!(
        query_cell_load_many(&client, &[])
            .await
            .expect("empty")
            .is_empty()
    );
}

// -- cell_audit -------------------------------------------------------------

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn audit_list_by_cell_matches_each_metadata_key() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let actor = seed_actor(&pool, "actor").await;
    let cell = Uuid::new_v4();

    // Insert one audit row per cell-domain metadata key naming `cell`.
    for (i, key) in [
        "cell_id",
        "source_id",
        "new_id",
        "parent_id",
        "child_id",
        "target_id",
    ]
    .iter()
    .enumerate()
    {
        let metadata = json!({ *key: cell, "n": i }).to_string();
        client
            .execute(
                "INSERT INTO audit_log (event_type, outcome, actor_id, metadata)
                 VALUES ($1, 'success', $2, $3::text::jsonb)",
                &[&format!("cell_event_{i}"), &actor, &metadata],
            )
            .await
            .expect("insert audit row");
    }
    // A row that names a different cell must NOT match.
    client
        .execute(
            "INSERT INTO audit_log (event_type, outcome, actor_id, metadata)
             VALUES ('other', 'success', $1, $2::text::jsonb)",
            &[&actor, &json!({ "cell_id": Uuid::new_v4() }).to_string()],
        )
        .await
        .expect("insert unrelated row");

    let events = query_audit_log_list_by_cell(&client, cell, 50)
        .await
        .expect("audit list");
    assert_eq!(events.len(), 6, "one match per cell-domain key");
    // Newest-first by seq (the last-inserted matching row leads).
    assert!(
        events.windows(2).all(|w| w[0].seq > w[1].seq),
        "must be ordered by seq DESC"
    );
    assert!(events.iter().all(|e| e.outcome == "success"));

    // Limit caps the page.
    let capped = query_audit_log_list_by_cell(&client, cell, 2)
        .await
        .expect("capped");
    assert_eq!(capped.len(), 2);
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn reverse_lists_break_a_created_at_tie_by_the_edge_key() {
    let pool = fresh_db_pool().await;
    let owner = seed_actor(&pool, "owner").await;
    let hub = seed_cell(&pool, owner).await;
    let mut ends = [seed_cell(&pool, owner).await, seed_cell(&pool, owner).await];
    ends.sort();
    let [low, high] = ends;
    let client = pool.get().await.expect("pool.get");
    // inserted against key order, then given one instant
    for end in [high, low] {
        for key in ["a2", "a1"] {
            query_cell_item_insert(&client, end, key, hub)
                .await
                .expect("item");
            query_cell_field_set(&client, end, key, hub)
                .await
                .expect("field");
        }
    }
    for table in ["cell_item", "cell_field"] {
        client
            .execute(
                &format!("UPDATE {table} SET created_at = '2026-01-01T00:00:00Z'"),
                &[],
            )
            .await
            .expect("tie the instants");
    }
    let expected = vec![
        (low, "a1".to_owned()),
        (low, "a2".to_owned()),
        (high, "a1".to_owned()),
        (high, "a2".to_owned()),
    ];
    let viewer = CellViewer::unrestricted();
    let items = query_cell_item_list_for_child(&client, &viewer, hub, None)
        .await
        .expect("list_for_child");
    assert_eq!(
        items
            .iter()
            .map(|i| (i.parent_id, i.position.clone()))
            .collect::<Vec<_>>(),
        expected,
        "items: parent, then position"
    );
    let fields = query_cell_field_list_for_target(&client, &viewer, hub, None)
        .await
        .expect("list_for_target");
    assert_eq!(
        fields
            .iter()
            .map(|f| (f.source_id, f.name.clone()))
            .collect::<Vec<_>>(),
        expected,
        "fields: source, then name"
    );
}
