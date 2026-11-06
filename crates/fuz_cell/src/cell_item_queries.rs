//! Raw queries against the `cell_item` table.
//!
//! Mirrors `fuz_app`'s `db/cell_item_queries.ts`. `insert` throws the
//! underlying `23505` on a `(parent_id, position)` collision (the handler
//! translates it to `cell_item_position_taken`); `move` is an UPDATE on the
//! PK with the same collision shape. `delete` returns the deleted row so the
//! handler can audit `child_id` without a pre-fetch. Reads JOIN `cell` on
//! the far endpoint with `deleted_at IS NULL` so items dangling off a
//! soft-deleted cell don't surface, and apply [`can_view_cell_sql`] to it for
//! the [`CellViewer`] — before `LIMIT`, so a page is up to `limit` edges whose
//! far end the caller can view.
//!
//! `created_at` projects SQL-side as a UTC ISO-8601 string (the workspace
//! `tokio-postgres` has no time-type feature).

use deadpool_postgres::GenericClient;
use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};
use uuid::Uuid;

use crate::cell_item_schema::CellItemRow;
use crate::cell_view_sql::{
    CellViewer, CellViewerSqlParams, caller_role_grants_cte, can_view_cell_sql,
};
use crate::error::CellError;

/// The `cell_item` table's columns, in projection order.
///
/// `item_columns` projects them in this order and `decode_item_row`
/// reads them positionally. Twin of `fuz_app`'s `CELL_ITEM_COLUMNS`; the
/// PG-gated `columns` integration test asserts it names every live column.
pub const CELL_ITEM_COLUMNS: [&str; 4] = ["parent_id", "position", "child_id", "created_at"];

/// The 4-column `CellItemRow` projection (decoded positionally by
/// [`decode_item_row`]): [`CELL_ITEM_COLUMNS`] qualified by `alias`.
/// `alias` qualifies the row — the table name (`"cell_item"`) for
/// `RETURNING`, the join alias (`"i"`) for list reads.
fn item_columns(alias: &str) -> String {
    qualify_columns(
        &CELL_ITEM_COLUMNS,
        alias,
        iso8601_timestamp_expr(&CELL_ITEM_COLUMNS, &["created_at"], alias),
    )
}

/// Decode the [`item_columns`] projection positionally.
fn decode_item_row(row: &tokio_postgres::Row) -> CellItemRow {
    CellItemRow {
        parent_id: row.get(col!(CELL_ITEM_COLUMNS, "parent_id")),
        position: row.get(col!(CELL_ITEM_COLUMNS, "position")),
        child_id: row.get(col!(CELL_ITEM_COLUMNS, "child_id")),
        created_at: row.get(col!(CELL_ITEM_COLUMNS, "created_at")),
    }
}

/// Insert one item row at the caller-supplied `position`.
///
/// # Errors
///
/// [`CellError::Db`] on driver / constraint failure — a `(parent_id,
/// position)` collision is a Postgres `23505` the handler detects via
/// [`fuz_db::is_pg_unique_violation`] and surfaces as
/// `cell_item_position_taken`.
pub async fn query_cell_item_insert<C: GenericClient + ?Sized>(
    client: &C,
    parent_id: Uuid,
    position: &str,
    child_id: Uuid,
) -> Result<CellItemRow, CellError> {
    let sql = format!(
        "INSERT INTO cell_item (parent_id, position, child_id)
         VALUES ($1, $2, $3)
         RETURNING {cols}",
        cols = item_columns("cell_item"),
    );
    let row = client
        .query_one(&sql, &[&parent_id, &position, &child_id])
        .await?;
    Ok(decode_item_row(&row))
}

/// Move an item from `position_old` to `position_new` (same parent).
///
/// Returns `None` when the source row was missing (raced with a deleter).
///
/// # Errors
///
/// [`CellError::Db`] on driver / constraint failure — a collision with an
/// existing row at `position_new` is a `23505` surfaced as
/// `cell_item_position_taken`.
pub async fn query_cell_item_move<C: GenericClient + ?Sized>(
    client: &C,
    parent_id: Uuid,
    position_old: &str,
    position_new: &str,
) -> Result<Option<CellItemRow>, CellError> {
    let sql = format!(
        "UPDATE cell_item SET position = $3
         WHERE parent_id = $1 AND position = $2
         RETURNING {cols}",
        cols = item_columns("cell_item"),
    );
    let row = client
        .query_opt(&sql, &[&parent_id, &position_old, &position_new])
        .await?;
    Ok(row.as_ref().map(decode_item_row))
}

/// Delete one item row by `(parent_id, position)`, returning the deleted
/// row (or `None` when nothing matched — idempotent delete).
///
/// # Errors
///
/// [`CellError::Db`] on driver failure.
pub async fn query_cell_item_delete<C: GenericClient + ?Sized>(
    client: &C,
    parent_id: Uuid,
    position: &str,
) -> Result<Option<CellItemRow>, CellError> {
    let sql = format!(
        "DELETE FROM cell_item WHERE parent_id = $1 AND position = $2 RETURNING {cols}",
        cols = item_columns("cell_item"),
    );
    let row = client.query_opt(&sql, &[&parent_id, &position]).await?;
    Ok(row.as_ref().map(decode_item_row))
}

/// Forward items list (`parent.items[]`), lex-ordered by `position`.
///
/// Up to `limit` (`None` = unbounded) items whose child is live and one
/// `viewer` may view; `position_after` (cursor — rows whose `position` sorts
/// after it) pages on. The parent-view gate is the caller's responsibility.
///
/// # Errors
///
/// [`CellError::Db`] on driver failure.
pub async fn query_cell_item_list_for_parent<C: GenericClient + ?Sized>(
    client: &C,
    viewer: &CellViewer<'_>,
    parent_id: Uuid,
    limit: Option<i64>,
    position_after: Option<&str>,
) -> Result<Vec<CellItemRow>, CellError> {
    let sql = format!(
        "WITH {caller_role_grants}
         SELECT {cols} FROM cell_item i
         JOIN cell c ON c.id = i.child_id
         WHERE i.parent_id = $1
           AND c.deleted_at IS NULL
           AND {can_view}
           AND ($3::text IS NULL OR i.position > $3)
         ORDER BY i.position ASC
         LIMIT $2",
        caller_role_grants = caller_role_grants_cte("$6", "$7"),
        can_view = can_view_cell_sql(
            "c",
            CellViewerSqlParams {
                is_admin: "$4",
                actor_id: "$5",
            }
        ),
        cols = item_columns("i"),
    );
    let [is_admin, actor_id, roles, scope_ids] = viewer.sql_params();
    let rows = client
        .query(
            &sql,
            &[
                &parent_id,
                &limit,
                &position_after,
                is_admin,
                actor_id,
                roles,
                scope_ids,
            ],
        )
        .await?;
    Ok(rows.iter().map(decode_item_row).collect())
}

/// Reverse items list (`child.lists[]`), oldest item first (the item row's
/// `created_at`, then its key).
///
/// Up to `limit` (`None` = unbounded) items whose parent is live and one
/// `viewer` may view — filtered before the limit, so parents the caller can't
/// see never crowd out ones it can. The child-view gate is the caller's
/// responsibility.
///
/// # Errors
///
/// [`CellError::Db`] on driver failure.
pub async fn query_cell_item_list_for_child<C: GenericClient + ?Sized>(
    client: &C,
    viewer: &CellViewer<'_>,
    child_id: Uuid,
    limit: Option<i64>,
) -> Result<Vec<CellItemRow>, CellError> {
    let sql = format!(
        "WITH {caller_role_grants}
         SELECT {cols} FROM cell_item i
         JOIN cell p ON p.id = i.parent_id
         WHERE i.child_id = $1
           AND p.deleted_at IS NULL
           AND {can_view}
         ORDER BY i.created_at ASC, i.parent_id ASC, i.position ASC
         LIMIT $2",
        caller_role_grants = caller_role_grants_cte("$5", "$6"),
        can_view = can_view_cell_sql(
            "p",
            CellViewerSqlParams {
                is_admin: "$3",
                actor_id: "$4",
            }
        ),
        cols = item_columns("i"),
    );
    let [is_admin, actor_id, roles, scope_ids] = viewer.sql_params();
    let rows = client
        .query(
            &sql,
            &[&child_id, &limit, is_admin, actor_id, roles, scope_ids],
        )
        .await?;
    Ok(rows.iter().map(decode_item_row).collect())
}
