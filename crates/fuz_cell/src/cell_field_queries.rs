//! Raw queries against the `cell_field` table.
//!
//! Mirrors `fuz_app`'s `db/cell_field_queries.ts`. `set` upserts on the
//! `(source_id, name)` PK so re-pointing a name updates `target_id` in
//! place (JSON-object semantics). `delete` returns the deleted row so the
//! handler can audit the prior target without a pre-fetch. Reads JOIN
//! `cell` on the far endpoint with `deleted_at IS NULL` so relations
//! dangling off a soft-deleted cell don't surface, and apply
//! [`can_view_cell_sql`] to it for the [`CellViewer`] — before `LIMIT`, so a
//! page is up to `limit` edges whose far end the caller can view.
//!
//! `created_at` projects SQL-side as a UTC ISO-8601 string (the workspace
//! `tokio-postgres` has no time-type feature).

use deadpool_postgres::GenericClient;
use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};
use uuid::Uuid;

use crate::cell_field_schema::CellFieldRow;
use crate::cell_view_sql::{
    CellViewer, CellViewerSqlParams, caller_role_grants_cte, can_view_cell_sql,
};
use crate::error::CellError;

/// The `cell_field` table's columns, in projection order.
///
/// `field_columns` projects them in this order and `decode_field_row`
/// reads them positionally. Twin of `fuz_app`'s `CELL_FIELD_COLUMNS`; the
/// PG-gated `columns` integration test asserts it names every live column.
pub const CELL_FIELD_COLUMNS: [&str; 4] = ["source_id", "name", "target_id", "created_at"];

/// The 4-column `CellFieldRow` projection (decoded positionally by
/// [`decode_field_row`]): [`CELL_FIELD_COLUMNS`] qualified by `alias`.
/// `alias` qualifies the row — the table name (`"cell_field"`) for
/// `RETURNING`, the join alias (`"f"`) for list reads.
fn field_columns(alias: &str) -> String {
    qualify_columns(
        &CELL_FIELD_COLUMNS,
        alias,
        iso8601_timestamp_expr(&CELL_FIELD_COLUMNS, &["created_at"], alias),
    )
}

/// Decode the [`field_columns`] projection positionally.
fn decode_field_row(row: &tokio_postgres::Row) -> CellFieldRow {
    CellFieldRow {
        source_id: row.get(col!(CELL_FIELD_COLUMNS, "source_id")),
        name: row.get(col!(CELL_FIELD_COLUMNS, "name")),
        target_id: row.get(col!(CELL_FIELD_COLUMNS, "target_id")),
        created_at: row.get(col!(CELL_FIELD_COLUMNS, "created_at")),
    }
}

/// Insert or update a field row (UPSERT on `(source_id, name)`).
///
/// Re-setting the same name updates `target_id` and bumps `created_at`.
/// Idempotent at the row level.
///
/// # Errors
///
/// [`CellError::Db`] on driver / constraint failure.
pub async fn query_cell_field_set<C: GenericClient + ?Sized>(
    client: &C,
    source_id: Uuid,
    name: &str,
    target_id: Uuid,
) -> Result<CellFieldRow, CellError> {
    let sql = format!(
        "INSERT INTO cell_field (source_id, name, target_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (source_id, name)
         DO UPDATE SET target_id = EXCLUDED.target_id, created_at = NOW()
         RETURNING {cols}",
        cols = field_columns("cell_field"),
    );
    let row = client
        .query_one(&sql, &[&source_id, &name, &target_id])
        .await?;
    Ok(decode_field_row(&row))
}

/// Delete a field row by `(source_id, name)`, returning the deleted row (or
/// `None` when nothing matched — idempotent delete).
///
/// # Errors
///
/// [`CellError::Db`] on driver failure.
pub async fn query_cell_field_delete<C: GenericClient + ?Sized>(
    client: &C,
    source_id: Uuid,
    name: &str,
) -> Result<Option<CellFieldRow>, CellError> {
    let sql = format!(
        "DELETE FROM cell_field WHERE source_id = $1 AND name = $2 RETURNING {cols}",
        cols = field_columns("cell_field"),
    );
    let row = client.query_opt(&sql, &[&source_id, &name]).await?;
    Ok(row.as_ref().map(decode_field_row))
}

/// Forward fields list (`source.fields[]`), name-ordered.
///
/// Up to `limit` (`None` = unbounded) fields whose target is live and one
/// `viewer` may view; `name_after` (cursor — rows whose `name` sorts after
/// it) pages on. The source-view gate is the caller's responsibility.
///
/// # Errors
///
/// [`CellError::Db`] on driver failure.
pub async fn query_cell_field_list_for_source<C: GenericClient + ?Sized>(
    client: &C,
    viewer: &CellViewer<'_>,
    source_id: Uuid,
    limit: Option<i64>,
    name_after: Option<&str>,
) -> Result<Vec<CellFieldRow>, CellError> {
    let sql = format!(
        "WITH {caller_role_grants}
         SELECT {cols} FROM cell_field f
         JOIN cell t ON t.id = f.target_id
         WHERE f.source_id = $1
           AND t.deleted_at IS NULL
           AND {can_view}
           AND ($3::text IS NULL OR f.name > $3)
         ORDER BY f.name ASC
         LIMIT $2",
        caller_role_grants = caller_role_grants_cte("$6", "$7"),
        can_view = can_view_cell_sql(
            "t",
            CellViewerSqlParams {
                is_admin: "$4",
                actor_id: "$5",
            }
        ),
        cols = field_columns("f"),
    );
    let [is_admin, actor_id, roles, scope_ids] = viewer.sql_params();
    let rows = client
        .query(
            &sql,
            &[
                &source_id,
                &limit,
                &name_after,
                is_admin,
                actor_id,
                roles,
                scope_ids,
            ],
        )
        .await?;
    Ok(rows.iter().map(decode_field_row).collect())
}

/// Reverse fields list (`target.upfields[]`), oldest field first (the
/// field row's `created_at`, then its key).
///
/// Up to `limit` (`None` = unbounded) fields whose source is live and one
/// `viewer` may view — filtered before the limit, so sources the caller can't
/// see never crowd out ones it can. The target-view gate is the caller's
/// responsibility.
///
/// # Errors
///
/// [`CellError::Db`] on driver failure.
pub async fn query_cell_field_list_for_target<C: GenericClient + ?Sized>(
    client: &C,
    viewer: &CellViewer<'_>,
    target_id: Uuid,
    limit: Option<i64>,
) -> Result<Vec<CellFieldRow>, CellError> {
    let sql = format!(
        "WITH {caller_role_grants}
         SELECT {cols} FROM cell_field f
         JOIN cell s ON s.id = f.source_id
         WHERE f.target_id = $1
           AND s.deleted_at IS NULL
           AND {can_view}
         ORDER BY f.created_at ASC, f.source_id ASC, f.name ASC
         LIMIT $2",
        caller_role_grants = caller_role_grants_cte("$5", "$6"),
        can_view = can_view_cell_sql(
            "s",
            CellViewerSqlParams {
                is_admin: "$3",
                actor_id: "$4",
            }
        ),
        cols = field_columns("f"),
    );
    let [is_admin, actor_id, roles, scope_ids] = viewer.sql_params();
    let rows = client
        .query(
            &sql,
            &[&target_id, &limit, is_admin, actor_id, roles, scope_ids],
        )
        .await?;
    Ok(rows.iter().map(decode_field_row).collect())
}
