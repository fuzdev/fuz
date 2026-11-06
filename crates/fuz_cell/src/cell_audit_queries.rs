//! Audit-log query for the per-cell timeline.
//!
//! Matches `audit_log` rows whose `metadata` jsonb names the cell on any of
//! the keys cell-domain event envelopes use — `cell_id` (cell mutations +
//! grants), `source_id` / `new_id` (clone), `source_id` / `target_id`
//! (field events), `parent_id` / `child_id` (item events). Each
//! `metadata @> jsonb_build_object(...)` clause hits `idx_audit_log_metadata`
//! (the `jsonb_path_ops` GIN on `audit_log.metadata`, shipped by `fuz_auth`'s
//! `audit_log_metadata_gin_index` migration); Postgres bitmap-ORs the index
//! scans. Mirrors `fuz_app`'s `db/cell_audit_queries.ts`.

use deadpool_postgres::GenericClient;
use fuz_db::iso8601_timestamp_column;
use uuid::Uuid;

use crate::cell_audit_schema::CellAuditEventRow;
use crate::error::CellError;

/// Metadata-jsonb keys cell-domain events use to name the cell.
///
/// These are interpolated directly into `jsonb_build_object('<key>', ...)`
/// (no SQL parameterization), so the list is a frozen const — never
/// caller-controllable. Extending it means extending the audit metadata
/// envelopes too.
const CELL_AUDIT_METADATA_KEYS: &[&str] = &[
    "cell_id",
    "source_id",
    "new_id",
    "parent_id",
    "child_id",
    "target_id",
];

/// Fetch the most-recent audit rows mentioning `cell_id` on any cell-domain
/// metadata key, newest-first by `seq`, capped at `limit`.
///
/// # Errors
///
/// [`CellError::Db`] on driver failure.
pub async fn query_audit_log_list_by_cell<C: GenericClient + ?Sized>(
    client: &C,
    cell_id: Uuid,
    limit: i64,
) -> Result<Vec<CellAuditEventRow>, CellError> {
    // The cell id is shared across every containment clause, so reuse `$1`
    // rather than allocating a placeholder per key — keeps the param list
    // small and the prepared-statement plan stable.
    let containment = CELL_AUDIT_METADATA_KEYS
        .iter()
        .map(|key| format!("metadata @> jsonb_build_object('{key}', $1::text)"))
        .collect::<Vec<_>>()
        .join(" OR ");
    // TODO: the one `fuz_cell` projection outside the `*_COLUMNS` / `col!`
    // discipline — a hand-listed SELECT decoded by hand-written index. The
    // table's const is `fuz_auth::audit_log_queries::AUDIT_LOG_COLUMNS` and
    // this read is a narrowing of it, so the shape it should take is a
    // derived const pinned by `omit_columns` with the decoder on `col!`.
    let sql = format!(
        "SELECT id, seq, event_type, outcome, actor_id, {created_at}
         FROM audit_log
         WHERE ({containment})
         ORDER BY seq DESC
         LIMIT $2",
        created_at = iso8601_timestamp_column("", "created_at"),
    );
    let cell_id_text = cell_id.to_string();
    let rows = client.query(&sql, &[&cell_id_text, &limit]).await?;
    Ok(rows
        .iter()
        .map(|row| CellAuditEventRow {
            id: row.get(0),
            seq: row.get(1),
            event_type: row.get(2),
            outcome: row.get(3),
            actor_id: row.get(4),
            created_at: row.get(5),
        })
        .collect())
}
