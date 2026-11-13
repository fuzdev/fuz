//! PG-backed equivalence of `can_view_cell_sql` with `can_view_cell`.
//!
//! The relation lists and `cell_list` filter in SQL, before their limit, with
//! the predicate `cell_view_sql` builds; the verb gates and the `cell_get`
//! bundle run `can_view_cell` in memory. The two must admit exactly the same
//! cells, so this seeds a matrix — every moderation marker (unset, approved,
//! pending, rejected, an unknown one) × visibility × grant (none, actor-shaped,
//! role-shaped) × owner (an actor, system) — links each cell into all four
//! relation lists, and checks, for every caller kind (anonymous, owner, actor
//! grant holder, role grant holder, stranger, admin), that each list and
//! `cell_list` return exactly the cells `can_view_cell` admits. A tombstoned
//! cell rides along to pin the liveness clause.
//!
//! `--ignored`-gated (needs Postgres):
//!
//! ```sh
//! cargo test -p fuz_cell --test cell_view_sql -- --ignored --test-threads=1
//! ```

mod common;

use std::collections::{BTreeSet, HashMap};

use common::fresh_db_pool;
use fuz_auth::{AccountRow, ActorRow, ROLE_ADMIN, RequestActorContext, RoleGrantRow};
use fuz_cell::can_view_cell;
use fuz_cell::cell_field_queries::{
    query_cell_field_list_for_source, query_cell_field_list_for_target, query_cell_field_set,
};
use fuz_cell::cell_grant_queries::{query_cell_grant_create, query_cell_grant_list_for_cells};
use fuz_cell::cell_grant_schema::{CellGrantLevel, CellGrantPrincipalInput, CellGrantRow};
use fuz_cell::cell_item_queries::{
    query_cell_item_insert, query_cell_item_list_for_child, query_cell_item_list_for_parent,
};
use fuz_cell::cell_queries::{
    CellListParams, query_cell_create, query_cell_delete, query_cell_list, query_cell_load_many,
};
use fuz_cell::cell_schema::CellVisibility;
use fuz_cell::cell_view_sql::CellViewer;
use fuz_db::Pool;
use fuz_testing::seed_account_actor;
use serde_json::json;
use uuid::Uuid;

/// The role a role-shaped grant in the matrix names.
const MEMBER_ROLE: &str = "member";

async fn seed_caller(pool: &Pool, username: &str, roles: &[&str]) -> RequestActorContext {
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
        role_grants: roles
            .iter()
            .map(|r| RoleGrantRow {
                id: Uuid::nil(),
                actor_id,
                role: (*r).to_owned(),
                scope_id: None,
            })
            .collect(),
    }
}

#[derive(Clone, Copy)]
enum Grant {
    None,
    Actor,
    Role,
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn the_sql_view_filter_admits_exactly_what_can_view_cell_admits() {
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let grantee = seed_caller(&pool, "grantee", &[]).await;
    let member = seed_caller(&pool, "member", &[MEMBER_ROLE]).await;
    let stranger = seed_caller(&pool, "stranger", &[]).await;
    let admin = seed_caller(&pool, "admin", &[ROLE_ADMIN]).await;
    let client = pool.get().await.unwrap();

    let create = async |visibility, moderation: Option<&str>, created_by| {
        query_cell_create(
            &client,
            &json!({}),
            Some("note"),
            Some(visibility),
            None,
            None,
            None,
            moderation,
            None,
            created_by,
        )
        .await
        .expect("create cell")
        .id
    };

    // The hubs every matrix cell links to and from — public, unmoderated,
    // ownerless, so each caller passes the gate the verbs put on them.
    let source = create(CellVisibility::Public, None, None).await;
    let target = create(CellVisibility::Public, None, None).await;
    let parent = create(CellVisibility::Public, None, None).await;
    let child = create(CellVisibility::Public, None, None).await;

    let mut matrix: Vec<Uuid> = Vec::new();
    for moderation in [
        None,
        Some("approved"),
        Some("pending"),
        Some("rejected"),
        Some("Approved"),
    ] {
        for visibility in [CellVisibility::Public, CellVisibility::Private] {
            for grant in [Grant::None, Grant::Actor, Grant::Role] {
                for created_by in [Some(owner.actor.id), None] {
                    let cell = create(visibility, moderation, created_by).await;
                    let principal = match grant {
                        Grant::None => None,
                        Grant::Actor => Some(CellGrantPrincipalInput::Actor {
                            actor_id: grantee.actor.id,
                        }),
                        Grant::Role => Some(CellGrantPrincipalInput::Role {
                            role: MEMBER_ROLE.to_owned(),
                            scope_id: None,
                        }),
                    };
                    if let Some(principal) = principal {
                        query_cell_grant_create(
                            &client,
                            cell,
                            CellGrantLevel::Viewer,
                            &principal,
                            Some(owner.actor.id),
                        )
                        .await
                        .expect("grant");
                    }
                    matrix.push(cell);
                }
            }
        }
    }
    // A tombstoned public cell: live for nobody.
    let tombstoned = create(CellVisibility::Public, None, Some(owner.actor.id)).await;
    matrix.push(tombstoned);

    for (i, cell) in matrix.iter().enumerate() {
        let name = format!("f{i:03}");
        let position = format!("p{i:03}");
        query_cell_field_set(&client, source, &name, *cell)
            .await
            .unwrap();
        query_cell_field_set(&client, *cell, "link", target)
            .await
            .unwrap();
        query_cell_item_insert(&client, parent, &position, *cell)
            .await
            .unwrap();
        query_cell_item_insert(&client, *cell, "a0", child)
            .await
            .unwrap();
    }
    assert!(
        query_cell_delete(&client, tombstoned, Some(owner.actor.id))
            .await
            .unwrap()
    );

    // What `can_view_cell` admits, over the rows and grants the verbs load.
    let rows = query_cell_load_many(&client, &matrix).await.unwrap();
    let grants = query_cell_grant_list_for_cells(&client, &matrix)
        .await
        .unwrap();
    let mut grants_by_cell: HashMap<Uuid, Vec<CellGrantRow>> = HashMap::new();
    for g in grants {
        grants_by_cell.entry(g.cell_id).or_default().push(g);
    }

    let callers: [(&str, Option<&RequestActorContext>); 6] = [
        ("anonymous", None),
        ("owner", Some(&owner)),
        ("actor grant holder", Some(&grantee)),
        ("role grant holder", Some(&member)),
        ("stranger", Some(&stranger)),
        ("admin", Some(&admin)),
    ];
    for (label, auth) in callers {
        let expected: BTreeSet<Uuid> = rows
            .iter()
            .filter(|row| {
                let grants = grants_by_cell.get(&row.id).map_or(&[][..], Vec::as_slice);
                can_view_cell(auth, *row, Some(grants))
            })
            .map(|row| row.id)
            .collect();
        assert!(!expected.is_empty(), "{label}: the matrix admits something");
        assert!(
            !expected.contains(&tombstoned),
            "{label}: a tombstone is never admitted"
        );
        if label != "admin" {
            assert!(
                expected.len() < rows.len(),
                "{label}: the matrix refuses something"
            );
        }

        let viewer = CellViewer::new(auth);
        let forward_fields: BTreeSet<Uuid> =
            query_cell_field_list_for_source(&client, &viewer, source, None, None)
                .await
                .unwrap()
                .iter()
                .map(|f| f.target_id)
                .collect();
        assert_eq!(forward_fields, expected, "{label}: forward fields");
        let reverse_fields: BTreeSet<Uuid> =
            query_cell_field_list_for_target(&client, &viewer, target, None)
                .await
                .unwrap()
                .iter()
                .map(|f| f.source_id)
                .collect();
        assert_eq!(reverse_fields, expected, "{label}: reverse fields");
        let forward_items: BTreeSet<Uuid> =
            query_cell_item_list_for_parent(&client, &viewer, parent, None, None)
                .await
                .unwrap()
                .iter()
                .map(|i| i.child_id)
                .collect();
        assert_eq!(forward_items, expected, "{label}: forward items");
        let reverse_items: BTreeSet<Uuid> =
            query_cell_item_list_for_child(&client, &viewer, child, None)
                .await
                .unwrap()
                .iter()
                .map(|i| i.parent_id)
                .collect();
        assert_eq!(reverse_items, expected, "{label}: reverse items");

        // `cell_list` embeds the same predicate; with no governing roots in
        // the matrix its steward arm admits nothing more.
        let listed: BTreeSet<Uuid> = query_cell_list(
            &client,
            &CellListParams {
                ids: Some(&matrix),
                viewer: CellViewer::new(auth),
                limit: 1_000,
                ..CellListParams::default()
            },
        )
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
        assert_eq!(listed, expected, "{label}: cell_list");
    }
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn the_view_filter_runs_before_the_limit() {
    // Hidden sources older than a visible one never crowd it out of a page.
    let pool = fresh_db_pool().await;
    let owner = seed_caller(&pool, "owner", &[]).await;
    let client = pool.get().await.unwrap();
    let create = async |visibility| {
        query_cell_create(
            &client,
            &json!({}),
            Some("note"),
            Some(visibility),
            None,
            None,
            None,
            None,
            None,
            Some(owner.actor.id),
        )
        .await
        .expect("create cell")
        .id
    };
    let target = create(CellVisibility::Public).await;
    let child = create(CellVisibility::Public).await;
    for _ in 0..5 {
        let hidden = create(CellVisibility::Private).await;
        query_cell_field_set(&client, hidden, "link", target)
            .await
            .unwrap();
        query_cell_item_insert(&client, hidden, "a0", child)
            .await
            .unwrap();
    }
    let visible = create(CellVisibility::Public).await;
    query_cell_field_set(&client, visible, "link", target)
        .await
        .unwrap();
    query_cell_item_insert(&client, visible, "a0", child)
        .await
        .unwrap();

    let anonymous = CellViewer::new(None);
    let fields = query_cell_field_list_for_target(&client, &anonymous, target, Some(1))
        .await
        .unwrap();
    assert_eq!(
        fields.iter().map(|f| f.source_id).collect::<Vec<_>>(),
        [visible]
    );
    let items = query_cell_item_list_for_child(&client, &anonymous, child, Some(1))
        .await
        .unwrap();
    assert_eq!(
        items.iter().map(|i| i.parent_id).collect::<Vec<_>>(),
        [visible]
    );
}

/// A caller holding `grants` — `(role, scope)` pairs, so scoped role grants
/// and a scoped admin grant ride the matrix.
async fn seed_scoped_caller(
    pool: &Pool,
    username: &str,
    grants: &[(&str, Option<Uuid>)],
) -> RequestActorContext {
    let mut caller = seed_caller(pool, username, &[]).await;
    let actor_id = caller.actor.id;
    caller.role_grants = grants
        .iter()
        .map(|(role, scope_id)| RoleGrantRow {
            id: Uuid::nil(),
            actor_id,
            role: (*role).to_owned(),
            scope_id: *scope_id,
        })
        .collect();
    caller
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn scoped_principals_admit_the_same_cells_in_sql_and_in_memory() {
    // Scoped role grants on both sides, a scoped (non-global) admin grant, an
    // editor-level grant, a multi-role caller, and an empty-string marker.
    let pool = fresh_db_pool().await;
    let scope_a = Uuid::new_v4();
    let scope_b = Uuid::new_v4();
    let owner = seed_caller(&pool, "owner", &[]).await;
    let grantee = seed_caller(&pool, "grantee", &[]).await;
    let scoped_admin =
        seed_scoped_caller(&pool, "scoped_admin", &[(ROLE_ADMIN, Some(scope_a))]).await;
    let member_a = seed_scoped_caller(&pool, "member_a", &[(MEMBER_ROLE, Some(scope_a))]).await;
    let member_b = seed_scoped_caller(&pool, "member_b", &[(MEMBER_ROLE, Some(scope_b))]).await;
    let member_global = seed_scoped_caller(&pool, "member_global", &[(MEMBER_ROLE, None)]).await;
    let multi = seed_scoped_caller(
        &pool,
        "multi",
        &[
            ("other", Some(scope_b)),
            (MEMBER_ROLE, Some(scope_a)),
            ("third", None),
        ],
    )
    .await;
    let client = pool.get().await.unwrap();
    let create = async |visibility, moderation: Option<&str>| {
        query_cell_create(
            &client,
            &json!({}),
            Some("note"),
            Some(visibility),
            None,
            None,
            None,
            moderation,
            None,
            Some(owner.actor.id),
        )
        .await
        .expect("create cell")
        .id
    };
    let source = create(CellVisibility::Public, None).await;
    let target = create(CellVisibility::Public, None).await;
    let parent = create(CellVisibility::Public, None).await;
    let child = create(CellVisibility::Public, None).await;

    let principals: Vec<(CellGrantLevel, CellGrantPrincipalInput)> = vec![
        (
            CellGrantLevel::Viewer,
            CellGrantPrincipalInput::Role {
                role: MEMBER_ROLE.to_owned(),
                scope_id: None,
            },
        ),
        (
            CellGrantLevel::Viewer,
            CellGrantPrincipalInput::Role {
                role: MEMBER_ROLE.to_owned(),
                scope_id: Some(scope_a),
            },
        ),
        (
            CellGrantLevel::Viewer,
            CellGrantPrincipalInput::Role {
                role: MEMBER_ROLE.to_owned(),
                scope_id: Some(scope_b),
            },
        ),
        (
            CellGrantLevel::Viewer,
            CellGrantPrincipalInput::Role {
                role: "other".to_owned(),
                scope_id: Some(scope_a),
            },
        ),
        (
            CellGrantLevel::Editor,
            CellGrantPrincipalInput::Actor {
                actor_id: grantee.actor.id,
            },
        ),
    ];
    let mut matrix: Vec<Uuid> = Vec::new();
    for moderation in [None, Some("approved"), Some("")] {
        // no grant
        matrix.push(create(CellVisibility::Private, moderation).await);
        for (level, principal) in &principals {
            let cell = create(CellVisibility::Private, moderation).await;
            query_cell_grant_create(&client, cell, *level, principal, Some(owner.actor.id))
                .await
                .expect("grant");
            matrix.push(cell);
        }
    }
    for (i, cell) in matrix.iter().enumerate() {
        query_cell_field_set(&client, source, &format!("f{i:03}"), *cell)
            .await
            .unwrap();
        query_cell_field_set(&client, *cell, "link", target)
            .await
            .unwrap();
        query_cell_item_insert(&client, parent, &format!("p{i:03}"), *cell)
            .await
            .unwrap();
        query_cell_item_insert(&client, *cell, "a0", child)
            .await
            .unwrap();
    }
    let rows = query_cell_load_many(&client, &matrix).await.unwrap();
    let mut grants_by_cell: HashMap<Uuid, Vec<CellGrantRow>> = HashMap::new();
    for g in query_cell_grant_list_for_cells(&client, &matrix)
        .await
        .unwrap()
    {
        grants_by_cell.entry(g.cell_id).or_default().push(g);
    }
    let callers: [(&str, &RequestActorContext); 6] = [
        ("scoped admin", &scoped_admin),
        ("member global", &member_global),
        ("member @a", &member_a),
        ("member @b", &member_b),
        ("multi-role", &multi),
        ("editor grantee", &grantee),
    ];
    for (label, auth) in callers {
        let auth = Some(auth);
        let expected: BTreeSet<Uuid> = rows
            .iter()
            .filter(|row| {
                let grants = grants_by_cell.get(&row.id).map_or(&[][..], Vec::as_slice);
                can_view_cell(auth, *row, Some(grants))
            })
            .map(|row| row.id)
            .collect();
        // a scoped admin grant is no admin: every matrix cell is private
        assert_eq!(
            expected.is_empty(),
            label == "scoped admin",
            "{label}: admits"
        );
        assert!(expected.len() < rows.len(), "{label}: refuses something");
        let viewer = CellViewer::new(auth);
        let got: BTreeSet<Uuid> =
            query_cell_field_list_for_source(&client, &viewer, source, None, None)
                .await
                .unwrap()
                .iter()
                .map(|f| f.target_id)
                .collect();
        assert_eq!(got, expected, "{label}: forward fields");
        let got: BTreeSet<Uuid> = query_cell_field_list_for_target(&client, &viewer, target, None)
            .await
            .unwrap()
            .iter()
            .map(|f| f.source_id)
            .collect();
        assert_eq!(got, expected, "{label}: reverse fields");
        let got: BTreeSet<Uuid> =
            query_cell_item_list_for_parent(&client, &viewer, parent, None, None)
                .await
                .unwrap()
                .iter()
                .map(|i| i.child_id)
                .collect();
        assert_eq!(got, expected, "{label}: forward items");
        let got: BTreeSet<Uuid> = query_cell_item_list_for_child(&client, &viewer, child, None)
            .await
            .unwrap()
            .iter()
            .map(|i| i.parent_id)
            .collect();
        assert_eq!(got, expected, "{label}: reverse items");
    }
}
