//! A cell write naming an actor while that actor's account is purged, against
//! a live database.
//!
//! The provenance stamps `cell.updated_by` and `cell_grant.granted_by` carry
//! no foreign key, so a write stamping a purged actor neither waits on the
//! purge nor fails after it, and the purge's cascade never writes a stamp. The
//! purge is its account `DELETE` (`query_purge_account`), its cascade pinned by
//! a third transaction holding the purged actor's grant, a row it reaches
//! before any cell row.
//!
//! Twin of `fuz_app`'s `src/test/db/cell_queries.races.db.test.ts`.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::time::{Duration, Instant};

use common::{fresh_db, fresh_postgres_db};
use fuz_auth::account_queries::query_purge_account;
use fuz_cell::cell_grant_queries::query_cell_grant_create;
use fuz_cell::cell_grant_schema::{CellGrantLevel, CellGrantPrincipalInput};
use fuz_cell::cell_queries::{query_cell_create, query_cell_get, query_cell_update};
use fuz_db::Pool;
use fuz_testing::seed_account_actor;
use serde_json::json;

/// How long a lock wait the test arranged may take to show, a bound on a hang
/// only.
const LOCK_WAIT_DEADLINE: Duration = Duration::from_secs(20);

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

/// A grant held by `actor`, the row the pin holds.
async fn insert_grant(pool: &Pool, actor: uuid::Uuid) -> uuid::Uuid {
    let client = pool.get().await.unwrap();
    client
        .query_one(
            "INSERT INTO role_grant (actor_id, role) VALUES ($1, 'cell_race_role') RETURNING id",
            &[&actor],
        )
        .await
        .unwrap()
        .get(0)
}

/// An owner's first edit of their own cell across their purge: both commit.
///
/// The owner's grant pinned, so the purge waits in its cascade, past its
/// delete of the owner's actor; the edit then writes the cell and stamps
/// `updated_by` with the owner's actor. With a foreign key on the stamp, the
/// edit waited on the deleted actor while holding the cell, whose `created_by`
/// the cascade then set null: a deadlock. The stamp has none, so the edit
/// commits, the cascade sets `created_by` null after it (the owner keeps its
/// foreign key), and `updated_by` keeps the purged actor's id. Twin of the TS
/// case.
#[tokio::test]
#[ignore = "postgres-only: observes a lock wait (pg_stat_activity, pg_backend_pid)"]
async fn an_owners_first_edit_of_their_cell_across_their_purge_both_commit() {
    let pool = fresh_postgres_db().await;
    let (owner_account, owner) = seed_account_actor(&pool, "cell_race_owner").await;
    let pinned = insert_grant(&pool, owner).await;
    let client = pool.get().await.unwrap();
    let cell = query_cell_create(
        &client,
        &json!({"v": 1}),
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
    .unwrap();
    assert_eq!(cell.updated_by, None, "the owner's edit is the first");
    drop(client);

    let mut pin_client = pool.get().await.unwrap();
    let pin = pin_client.transaction().await.unwrap();
    pin.execute(
        "SELECT id FROM role_grant WHERE id = $1 FOR UPDATE",
        &[&pinned],
    )
    .await
    .unwrap();
    let edited = std::sync::atomic::AtomicBool::new(false);
    let purge = async {
        let mut client = pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        let purged = query_purge_account(&tx, &owner_account).await;
        match purged {
            Ok(_) => tx.commit().await,
            Err(e) => Err(e),
        }
    };
    let edit_then_release = async {
        let deadline = Instant::now() + LOCK_WAIT_DEADLINE;
        while lock_waiters(&pool).await < 1 {
            assert!(
                Instant::now() < deadline,
                "the purge waits on the pinned grant"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let edit = async {
            let mut client = pool.get().await.unwrap();
            let tx = client.transaction().await.unwrap();
            let result = query_cell_update(
                &tx,
                cell.id,
                Some(&json!({"v": 2})),
                None,
                None,
                Some(owner),
            )
            .await;
            let result = match result {
                Ok(row) => tx.commit().await.map(|()| row).map_err(Into::into),
                Err(e) => Err(e),
            };
            edited.store(true, std::sync::atomic::Ordering::SeqCst);
            result
        };
        let release = async {
            while !edited.load(std::sync::atomic::Ordering::SeqCst) && lock_waiters(&pool).await < 2
            {
                assert!(
                    Instant::now() < deadline,
                    "the edit neither waits nor finishes"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            pin.commit().await.unwrap();
        };
        let (edit, ()) = tokio::join!(edit, release);
        edit
    };
    let (purged, edit) = tokio::join!(purge, edit_then_release);
    purged.expect("the purge");
    let edit = edit.expect("the edit").expect("the cell is live");
    assert_eq!(edit.updated_by, Some(owner), "the edit stamped the owner");

    let client = pool.get().await.unwrap();
    let after = query_cell_get(&client, cell.id)
        .await
        .unwrap()
        .expect("the cell stands");
    assert_eq!(after.created_by, None, "the cascade set the owner null");
    assert_eq!(
        after.updated_by,
        Some(owner),
        "the stamp keeps the purged actor's id"
    );
    assert_eq!(after.data, json!({"v": 2}), "the edit stands");
}

/// A cell grant by a granter purged after its request was authorized is
/// written, its `granted_by` naming the purged actor: the stamp carries no
/// foreign key, so the insert no longer fails on it (`23503` with one). Twin
/// of the TS case.
#[tokio::test]
async fn a_cell_grant_by_a_purged_granter_is_written() {
    let pool = fresh_db().await;
    let (granter_account, granter) = seed_account_actor(&pool, "cell_race_granter").await;
    let (_, grantee) = seed_account_actor(&pool, "cell_race_grantee").await;
    let client = pool.get().await.unwrap();
    let cell = query_cell_create(
        &client,
        &json!({}),
        Some("note"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    query_purge_account(&client, &granter_account)
        .await
        .unwrap()
        .expect("the granter is purged");

    let grant = query_cell_grant_create(
        &client,
        cell.id,
        CellGrantLevel::Viewer,
        &CellGrantPrincipalInput::Actor { actor_id: grantee },
        Some(granter),
    )
    .await
    .expect("the grant is written");
    assert_eq!(
        grant.granted_by,
        Some(granter),
        "the stamp names the purged granter"
    );
}
