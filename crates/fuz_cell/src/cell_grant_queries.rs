//! Raw queries against the `cell_grant` table.
//!
//! Mirrors `fuz_app`'s `db/cell_grant_queries.ts`. `create` upserts on the
//! relevant partial unique index (actor-shaped on `(cell_id, actor_id)`,
//! role-shaped on `(cell_id, role, scope_id)` with `NULLS NOT DISTINCT`),
//! so re-granting the same principal updates `level` + `granted_by` rather
//! than duplicating. `delete` returns the deleted row so the handler can
//! audit the principal + recompute `still_admitted` without a second
//! fetch. `created_at` projects SQL-side as a UTC ISO-8601 string.

use deadpool_postgres::GenericClient;
use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};
use uuid::Uuid;

use crate::cell_grant_schema::{CellGrantLevel, CellGrantPrincipalInput, CellGrantRow};
use crate::cell_view_sql::CellViewer;
use crate::error::CellError;

/// The `cell_grant` table's columns, in projection order.
///
/// `grant_columns` projects them in this order and `decode_grant_row`
/// reads them positionally. Twin of `fuz_app`'s `CELL_GRANT_COLUMNS`; the
/// PG-gated `columns` integration test asserts it names every live column.
pub const CELL_GRANT_COLUMNS: [&str; 8] = [
    "id",
    "cell_id",
    "level",
    "actor_id",
    "role",
    "scope_id",
    "granted_by",
    "created_at",
];

/// The 8-column `CellGrantRow` projection (decoded positionally by
/// [`decode_grant_row`]): [`CELL_GRANT_COLUMNS`] qualified by `alias`.
/// `alias` qualifies the row — the table name (`"cell_grant"`) for
/// single-table reads + `RETURNING`, the join alias (`"g"`) for the
/// caller-match read. `created_at` projects through `fuz_db`'s
/// `iso8601_timestamp_column` for the spine's canonical second-precision UTC
/// ISO-8601 wire shape.
fn grant_columns(alias: &str) -> String {
    qualify_columns(
        &CELL_GRANT_COLUMNS,
        alias,
        iso8601_timestamp_expr(&CELL_GRANT_COLUMNS, &["created_at"], alias),
    )
}

/// Decode the [`grant_columns`] projection positionally.
fn decode_grant_row(row: &tokio_postgres::Row) -> Result<CellGrantRow, CellError> {
    let level_text: String = row.get(col!(CELL_GRANT_COLUMNS, "level"));
    let level = CellGrantLevel::from_db(&level_text)
        .ok_or_else(|| CellError::Decode(format!("level: {level_text:?}")))?;
    Ok(CellGrantRow {
        id: row.get(col!(CELL_GRANT_COLUMNS, "id")),
        cell_id: row.get(col!(CELL_GRANT_COLUMNS, "cell_id")),
        level,
        actor_id: row.get(col!(CELL_GRANT_COLUMNS, "actor_id")),
        role: row.get(col!(CELL_GRANT_COLUMNS, "role")),
        scope_id: row.get(col!(CELL_GRANT_COLUMNS, "scope_id")),
        granted_by: row.get(col!(CELL_GRANT_COLUMNS, "granted_by")),
        created_at: row.get(col!(CELL_GRANT_COLUMNS, "created_at")),
    })
}

/// Insert a grant (or update an existing one's `level` + `granted_by`).
///
/// Upserts when a row already exists for the same `(cell_id, principal)`.
/// Idempotent re-share via UPSERT on the principal's partial unique index.
/// The two principal shapes use different indexes (matching the DDL): the
/// actor arm conflicts on `(cell_id, actor_id)`, the role arm on
/// `(cell_id, role, scope_id)`.
///
/// # Errors
///
/// [`CellError::Db`] on driver / constraint failure; [`CellError::Decode`]
/// if the returned row is malformed.
pub async fn query_cell_grant_create<C: GenericClient + ?Sized>(
    client: &C,
    cell_id: Uuid,
    level: CellGrantLevel,
    principal: &CellGrantPrincipalInput,
    granted_by: Option<Uuid>,
) -> Result<CellGrantRow, CellError> {
    let level = level.as_str();
    let row = match principal {
        CellGrantPrincipalInput::Actor { actor_id } => {
            let sql = format!(
                "INSERT INTO cell_grant (cell_id, level, actor_id, granted_by)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (cell_id, actor_id) WHERE actor_id IS NOT NULL
                 DO UPDATE SET level = EXCLUDED.level, granted_by = EXCLUDED.granted_by
                 RETURNING {cols}",
                cols = grant_columns("cell_grant"),
            );
            client
                .query_one(&sql, &[&cell_id, &level, actor_id, &granted_by])
                .await?
        }
        CellGrantPrincipalInput::Role { role, scope_id } => {
            let sql = format!(
                "INSERT INTO cell_grant (cell_id, level, role, scope_id, granted_by)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (cell_id, role, scope_id) WHERE role IS NOT NULL
                 DO UPDATE SET level = EXCLUDED.level, granted_by = EXCLUDED.granted_by
                 RETURNING {cols}",
                cols = grant_columns("cell_grant"),
            );
            client
                .query_one(&sql, &[&cell_id, &level, role, scope_id, &granted_by])
                .await?
        }
    };
    decode_grant_row(&row)
}

/// Fetch a grant by id.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_grant_get<C: GenericClient + ?Sized>(
    client: &C,
    grant_id: Uuid,
) -> Result<Option<CellGrantRow>, CellError> {
    let sql = format!(
        "SELECT {cols} FROM cell_grant WHERE id = $1",
        cols = grant_columns("cell_grant"),
    );
    let row = client.query_opt(&sql, &[&grant_id]).await?;
    row.as_ref().map(decode_grant_row).transpose()
}

/// Delete a grant by id, returning the deleted row (or `None` when no row
/// matched).
///
/// With `expected_level`, only a grant still at that level is deleted — a
/// caller whose decision read the level fences the delete to the row it
/// decided on, so a level change landing in between deletes nothing.
///
/// Returning the row lets the caller audit the principal + recompute
/// `still_admitted` against the remaining grants without a second fetch.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_grant_delete<C: GenericClient + ?Sized>(
    client: &C,
    grant_id: Uuid,
    expected_level: Option<CellGrantLevel>,
) -> Result<Option<CellGrantRow>, CellError> {
    let sql = format!(
        "DELETE FROM cell_grant WHERE id = $1 AND ($2::text IS NULL OR level = $2) \
         RETURNING {cols}",
        cols = grant_columns("cell_grant"),
    );
    let level = expected_level.map(CellGrantLevel::as_str);
    let row = client.query_opt(&sql, &[&grant_id, &level]).await?;
    row.as_ref().map(decode_grant_row).transpose()
}

/// List all grants on a cell, oldest first. Used by `cell_grant_list` and
/// by the CRUD handlers that need grants alongside the cell row for the
/// authorize predicate.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_grant_list_for_cell<C: GenericClient + ?Sized>(
    client: &C,
    cell_id: Uuid,
) -> Result<Vec<CellGrantRow>, CellError> {
    let sql = format!(
        "SELECT {cols} FROM cell_grant WHERE cell_id = $1 ORDER BY created_at ASC",
        cols = grant_columns("cell_grant"),
    );
    let rows = client.query(&sql, &[&cell_id]).await?;
    rows.iter().map(decode_grant_row).collect()
}

/// Bulk-list grants across many cells, oldest first.
///
/// Feeds the batched relation-read visibility filter
/// ([`crate::cell_relation_visibility::filter_visible_targets`]) so a
/// per-cell `query_cell_grant_list_for_cell` N+1 is avoided. The caller
/// buckets the flat result by `cell_id`.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_grant_list_for_cells<C: GenericClient + ?Sized>(
    client: &C,
    cell_ids: &[Uuid],
) -> Result<Vec<CellGrantRow>, CellError> {
    if cell_ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT {cols} FROM cell_grant WHERE cell_id = ANY($1::uuid[]) ORDER BY created_at ASC",
        cols = grant_columns("cell_grant"),
    );
    let rows = client.query(&sql, &[&cell_ids]).await?;
    rows.iter().map(decode_grant_row).collect()
}

/// Caller-matched grant enrichment across many cells.
///
/// Returns only the grants in `cell_ids` that admit `viewer` — the
/// actor-shaped grant on its actor, or a role-shaped grant matching one of
/// its `(role, scope_id)` role-grant pairs (a NULL grant scope matches any);
/// its admin flag is not consulted. Feeds `cell_list`'s `cell_grants` map on the
/// `shared_with: 'me'` path so the UI can label each shared cell with the
/// caller's own admit grants. Twin of the TS
/// `query_cell_grants_for_caller_in_cells`.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_grants_for_caller_in_cells<C: GenericClient + ?Sized>(
    client: &C,
    cell_ids: &[Uuid],
    viewer: &CellViewer<'_>,
) -> Result<Vec<CellGrantRow>, CellError> {
    if cell_ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT {cols} FROM cell_grant g
         WHERE g.cell_id = ANY($1::uuid[])
           AND (
             g.actor_id = $2
             OR EXISTS (
               SELECT 1
               FROM unnest($3::text[], $4::uuid[]) AS p(role, scope_id)
               WHERE g.role = p.role
                 AND (g.scope_id IS NULL OR g.scope_id IS NOT DISTINCT FROM p.scope_id)
             )
           )
         ORDER BY g.cell_id, g.created_at ASC",
        cols = grant_columns("g"),
    );
    let [_, actor_id, role_grant_roles, role_grant_scope_ids] = viewer.sql_params();
    let rows = client
        .query(
            &sql,
            &[&cell_ids, actor_id, role_grant_roles, role_grant_scope_ids],
        )
        .await?;
    rows.iter().map(decode_grant_row).collect()
}
