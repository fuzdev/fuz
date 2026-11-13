//! PG-backed tests for how `cell.moderation` gates the `query_cell_list`
//! read arms — the SQL twin of `can_view_cell`'s moderation rule.
//!
//! A cell's effective audience is its visibility or grants **and** its
//! moderation admission (unmoderated or `approved`): the public and grant
//! arms of the general predicate and the `shared_with` semi-join require it,
//! the owner and admin arms don't. The general predicate's steward arm (the
//! SQL twin of `can_steward_cell`) admits the owner of a live governing root
//! to the pending and rejected contributions under it — the moderation queue
//! — and the `shared_with` semi-join has no steward arm.
//!
//! `--ignored`-gated (needs Postgres):
//!
//! ```sh
//! cargo test -p fuz_cell --test cell_moderation_reads -- --ignored --test-threads=1
//! ```

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::collections::HashSet;

use common::{fresh_db_pool, seed_actor};
use fuz_cell::cell_grant_queries::query_cell_grant_create;
use fuz_cell::cell_grant_schema::{CellGrantLevel, CellGrantPrincipalInput};
use fuz_cell::cell_queries::{
    CellListParams, query_cell_create, query_cell_delete, query_cell_list,
};
use fuz_cell::cell_view_sql::CellViewer;
use fuz_cell::{CellVisibility, cell_moderation_admits_audience, cell_moderation_is_stewardable};
use serde_json::json;
use uuid::Uuid;

/// The moderation states tabled: unmoderated, the three literals, and a
/// marker no rule names (the column has no CHECK).
const MODERATIONS: [Option<&str>; 5] = [
    None,
    Some("approved"),
    Some("pending"),
    Some("rejected"),
    Some("unknown"),
];

const ROLE: &str = "member";

async fn list_ids(
    client: &deadpool_postgres::Object,
    params: &CellListParams<'_>,
) -> HashSet<Uuid> {
    query_cell_list(client, params)
        .await
        .expect("list")
        .iter()
        .map(|c| c.id)
        .collect()
}

/// One moderation state's three cells, all owned by the same author.
struct Cells {
    moderation: Option<&'static str>,
    public: Uuid,
    actor_granted: Uuid,
    role_granted: Uuid,
}

async fn seed_cells(
    client: &deadpool_postgres::Object,
    owner: Uuid,
    holder: Uuid,
    moderation: Option<&'static str>,
) -> Cells {
    let create = async |visibility| {
        query_cell_create(
            client,
            &json!({}),
            Some("post"),
            Some(visibility),
            None,
            None,
            None,
            moderation,
            None,
            Some(owner),
        )
        .await
        .expect("create")
        .id
    };
    let public = create(CellVisibility::Public).await;
    let actor_granted = create(CellVisibility::Private).await;
    let role_granted = create(CellVisibility::Private).await;
    query_cell_grant_create(
        client,
        actor_granted,
        CellGrantLevel::Viewer,
        &CellGrantPrincipalInput::Actor { actor_id: holder },
        Some(owner),
    )
    .await
    .expect("actor grant");
    query_cell_grant_create(
        client,
        role_granted,
        CellGrantLevel::Viewer,
        &CellGrantPrincipalInput::Role {
            role: ROLE.to_owned(),
            scope_id: None,
        },
        Some(owner),
    )
    .await
    .expect("role grant");
    Cells {
        moderation,
        public,
        actor_granted,
        role_granted,
    }
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn list_gates_the_public_and_grant_arms_on_moderation() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let owner = seed_actor(&pool, "owner").await;
    let stranger = seed_actor(&pool, "stranger").await;
    let holder = seed_actor(&pool, "holder").await;
    let role_holder = seed_actor(&pool, "role_holder").await;

    let mut all = Vec::new();
    for moderation in MODERATIONS {
        all.push(seed_cells(&client, owner, holder, moderation).await);
    }

    let viewer = |actor: Option<Uuid>| CellListParams {
        viewer: actor.map_or_else(CellViewer::default, |a| CellViewer::for_actor(a, [])),
        limit: 500,
        ..Default::default()
    };
    let as_role_holder = || CellViewer::for_actor(role_holder, [(ROLE, None)]);
    let anon = list_ids(&client, &viewer(None)).await;
    let strangers = list_ids(&client, &viewer(Some(stranger))).await;
    let holders = list_ids(&client, &viewer(Some(holder))).await;
    let role_holders = list_ids(
        &client,
        &CellListParams {
            viewer: as_role_holder(),
            ..viewer(None)
        },
    )
    .await;
    let owners = list_ids(&client, &viewer(Some(owner))).await;
    let admins = list_ids(
        &client,
        &CellListParams {
            viewer: CellViewer::unrestricted(),
            ..viewer(None)
        },
    )
    .await;
    let shared_with_holder = list_ids(
        &client,
        &CellListParams {
            shared_with_caller_only: true,
            ..viewer(Some(holder))
        },
    )
    .await;
    let shared_with_role_holder = list_ids(
        &client,
        &CellListParams {
            shared_with_caller_only: true,
            viewer: as_role_holder(),
            ..viewer(None)
        },
    )
    .await;

    for cells in &all {
        let admitted = cell_moderation_admits_audience(cells.moderation);
        let m = cells.moderation;
        assert_eq!(anon.contains(&cells.public), admitted, "anon public {m:?}");
        assert_eq!(
            strangers.contains(&cells.public),
            admitted,
            "stranger public {m:?}"
        );
        assert!(
            !strangers.contains(&cells.actor_granted),
            "stranger granted {m:?}"
        );
        assert_eq!(
            holders.contains(&cells.actor_granted),
            admitted,
            "actor grant holder {m:?}"
        );
        assert_eq!(
            role_holders.contains(&cells.role_granted),
            admitted,
            "role grant holder {m:?}"
        );
        assert_eq!(
            shared_with_holder.contains(&cells.actor_granted),
            admitted,
            "shared_with actor grant {m:?}"
        );
        assert_eq!(
            shared_with_role_holder.contains(&cells.role_granted),
            admitted,
            "shared_with role grant {m:?}"
        );
        for id in [cells.public, cells.actor_granted, cells.role_granted] {
            assert!(owners.contains(&id), "owner reads own {m:?}");
            assert!(admins.contains(&id), "admin reads {m:?}");
        }
    }
}

/// Create a private cell owned by `owner`, under `tree = (parent, root)`.
async fn create_in_tree(
    client: &deadpool_postgres::Object,
    owner: Uuid,
    kind: &str,
    tree: Option<(Uuid, Uuid)>,
    moderation: Option<&str>,
) -> Uuid {
    query_cell_create(
        client,
        &json!({}),
        Some(kind),
        Some(CellVisibility::Private),
        None,
        tree.map(|(parent, _)| parent),
        tree.map(|(_, root)| root),
        moderation,
        None,
        Some(owner),
    )
    .await
    .expect("create")
    .id
}

#[tokio::test]
#[ignore = "needs Postgres (FUZ_CELL_TEST_URL)"]
async fn list_steward_arm_admits_the_root_owner_to_pending_and_rejected() {
    let pool = fresh_db_pool().await;
    let client = pool.get().await.expect("pool.get");
    let root_owner = seed_actor(&pool, "root_owner").await;
    let other_root_owner = seed_actor(&pool, "other_root_owner").await;
    let author = seed_actor(&pool, "author").await;
    let commenter = seed_actor(&pool, "commenter").await;
    let stranger = seed_actor(&pool, "stranger").await;

    let root = create_in_tree(&client, root_owner, "forum", None, None).await;
    create_in_tree(&client, other_root_owner, "forum", None, None).await;
    let mut posts = Vec::new();
    for moderation in MODERATIONS {
        let post = create_in_tree(&client, author, "post", Some((root, root)), moderation).await;
        posts.push((moderation, post));
    }
    let pending_post = posts
        .iter()
        .find(|(m, _)| *m == Some("pending"))
        .expect("a pending post")
        .1;
    // Nested: another author's pending comment under the pending post — its
    // governing root is the forum, so the forum's owner stewards it and the
    // post's author does not.
    let comment = create_in_tree(
        &client,
        commenter,
        "comment",
        Some((pending_post, root)),
        Some("pending"),
    )
    .await;

    let viewer = |actor: Uuid| CellListParams {
        viewer: CellViewer::for_actor(actor, []),
        root_id: Some(root),
        limit: 500,
        ..Default::default()
    };
    let root_owners = list_ids(&client, &viewer(root_owner)).await;
    for (moderation, post) in &posts {
        // An approved or unmoderated contribution narrowed to private is not
        // stewarded — it reads like any cell its author narrowed.
        assert_eq!(
            root_owners.contains(post),
            cell_moderation_is_stewardable(*moderation),
            "root owner {moderation:?}"
        );
    }
    assert!(
        root_owners.contains(&comment),
        "root owner reads a nested pending comment"
    );
    assert!(
        list_ids(&client, &viewer(other_root_owner))
            .await
            .is_empty(),
        "another root's owner stewards nothing here"
    );
    assert!(
        list_ids(&client, &viewer(stranger)).await.is_empty(),
        "stranger"
    );
    let authors = list_ids(&client, &viewer(author)).await;
    assert!(
        !authors.contains(&comment),
        "a post's author is not the steward of a comment under it"
    );
    assert_eq!(
        authors.len(),
        posts.len(),
        "the author reads their own posts"
    );

    let queue = list_ids(
        &client,
        &CellListParams {
            moderation: Some("pending"),
            ..viewer(root_owner)
        },
    )
    .await;
    assert_eq!(
        queue,
        HashSet::from([pending_post, comment]),
        "the moderation queue"
    );
    let shared = list_ids(
        &client,
        &CellListParams {
            shared_with_caller_only: true,
            ..viewer(root_owner)
        },
    )
    .await;
    assert!(shared.is_empty(), "shared_with has no steward arm");

    // A tombstoned root stewards nothing; its contributions stay live.
    assert!(
        query_cell_delete(&client, root, Some(root_owner))
            .await
            .expect("delete root")
    );
    assert!(
        list_ids(&client, &viewer(root_owner)).await.is_empty(),
        "no steward arm under a deleted root"
    );
    assert_eq!(
        list_ids(&client, &viewer(author)).await.len(),
        posts.len(),
        "the author still reads their own posts"
    );
}
