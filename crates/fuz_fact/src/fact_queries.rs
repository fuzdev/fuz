//! Raw queries against `fact` and `fact_ref`.
//!
//! Twin of the canonical TS `db/fact_queries.ts`: `deps`-first (here: a
//! `GenericClient`, so the same fn runs over a pooled client or a
//! transaction), no audit side effects, idempotent mutations
//! (`ON CONFLICT DO NOTHING`). Higher-level lifecycle (verify-on-read,
//! embedded-vs-disk routing, the streaming CAS) lives in
//! [`crate::fact_store`]; these are deliberately mechanical.
//!
//! Hashes bind as their `blake3:<hex>` prefixed string; callers hold a
//! [`fuz_crypto::ContentHash`] and the functions stringify internally.

use deadpool_postgres::GenericClient;
use fuz_crypto::ContentHash;
use fuz_db::{col, iso8601_timestamp_column, iso8601_timestamp_expr, qualify_columns};

use crate::error::FactError;

/// The `fact` table's columns.
///
/// Twin of `fuz_app`'s `FACT_COLUMNS` (same names, same order). The PG-gated
/// `columns` integration test asserts this names every live column. The row
/// reads below derive their projections from it (`omit_columns`), so a
/// column added to the DDL reaches them through the const; `fact_ref` and
/// `memo` carry no const — they're read as hash lists, never as rows.
pub const FACT_COLUMNS: [&str; 6] = [
    "hash",
    "bytes",
    "external_url",
    "content_type",
    "size",
    "created_at",
];

/// Full `fact` row including the embedded `bytes` payload.
#[derive(Debug, Clone)]
pub struct FactRow {
    pub bytes: Option<Vec<u8>>,
    pub external_url: Option<String>,
    pub content_type: Option<String>,
    pub size: i64,
    pub created_at: String,
}

/// Metadata-only `fact` row — skips the (potentially large) `bytes` column.
#[derive(Debug, Clone)]
pub struct FactMetaRow {
    pub external_url: Option<String>,
    pub content_type: Option<String>,
    pub size: i64,
    pub created_at: String,
}

/// The [`FactRow`] column list — [`FACT_COLUMNS`] minus `hash` (the caller
/// looked the row up by it). A literal so [`decode_fact_row`] can `col!`
/// into it; the unit test pins it to the `omit_columns` derivation.
const FACT_ROW_COLUMNS: [&str; 5] = [
    "bytes",
    "external_url",
    "content_type",
    "size",
    "created_at",
];

/// The [`FactRow`] projection ([`FACT_ROW_COLUMNS`]), `created_at` as the
/// ISO-8601 wire string.
fn fact_row_columns() -> String {
    qualify_columns(
        &FACT_ROW_COLUMNS,
        "fact",
        iso8601_timestamp_expr(&FACT_ROW_COLUMNS, &["created_at"], "fact"),
    )
}

/// Decode the [`fact_row_columns`] projection positionally.
fn decode_fact_row(row: &tokio_postgres::Row) -> FactRow {
    FactRow {
        bytes: row.get(col!(FACT_ROW_COLUMNS, "bytes")),
        external_url: row.get(col!(FACT_ROW_COLUMNS, "external_url")),
        content_type: row.get(col!(FACT_ROW_COLUMNS, "content_type")),
        size: row.get(col!(FACT_ROW_COLUMNS, "size")),
        created_at: row.get(col!(FACT_ROW_COLUMNS, "created_at")),
    }
}

/// The [`FactMetaRow`] column list — [`FACT_COLUMNS`] minus `hash` and the
/// payload `bytes`. A literal so [`decode_fact_meta_row`] can `col!` into
/// it; the unit test pins it to the `omit_columns` derivation.
const FACT_META_COLUMNS: [&str; 4] = ["external_url", "content_type", "size", "created_at"];

/// The [`FactMetaRow`] projection ([`FACT_META_COLUMNS`]), `created_at` as
/// the ISO-8601 wire string.
fn fact_meta_columns() -> String {
    qualify_columns(
        &FACT_META_COLUMNS,
        "fact",
        iso8601_timestamp_expr(&FACT_META_COLUMNS, &["created_at"], "fact"),
    )
}

/// Decode the [`fact_meta_columns`] projection positionally.
fn decode_fact_meta_row(row: &tokio_postgres::Row) -> FactMetaRow {
    FactMetaRow {
        external_url: row.get(col!(FACT_META_COLUMNS, "external_url")),
        content_type: row.get(col!(FACT_META_COLUMNS, "content_type")),
        size: row.get(col!(FACT_META_COLUMNS, "size")),
        created_at: row.get(col!(FACT_META_COLUMNS, "created_at")),
    }
}

/// The `(size, external_url)` of a deleted fact — the caller unlinks the disk
/// file (if any) and tallies freed bytes.
#[derive(Debug, Clone)]
pub struct FactDeleted {
    pub size: i64,
    pub external_url: Option<String>,
}

/// Bind params for [`query_put_fact`].
///
/// The `fact_storage_present` CHECK requires *at least one* of `bytes` /
/// `external_url` (it's an `OR`, byte-identical to the canonical TS DDL); the
/// store writes exactly one by discipline (embedded XOR disk), so the caller
/// passes one and leaves the other `None`.
#[derive(Debug)]
pub struct PutFactInput<'a> {
    pub hash: &'a ContentHash,
    pub bytes: Option<&'a [u8]>,
    pub external_url: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub size: i64,
}

/// Idempotently insert a fact row. Returns `true` when a new row landed,
/// `false` when one already existed (the caller uses this to decide whether to
/// also write `fact_ref`).
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_put_fact<C: GenericClient + ?Sized>(
    client: &C,
    input: &PutFactInput<'_>,
) -> Result<bool, FactError> {
    let hash = input.hash.to_prefixed();
    let inserted = client
        .query_opt(
            "INSERT INTO fact (hash, bytes, external_url, content_type, size) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (hash) DO NOTHING \
             RETURNING hash",
            &[
                &hash,
                &input.bytes,
                &input.external_url,
                &input.content_type,
                &input.size,
            ],
        )
        .await?;
    Ok(inserted.is_some())
}

/// Idempotently insert declared refs. No-ops on collisions; skips the round
/// trip when `targets` is empty.
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_put_fact_refs<C: GenericClient + ?Sized>(
    client: &C,
    source: &ContentHash,
    targets: &[ContentHash],
) -> Result<(), FactError> {
    if targets.is_empty() {
        return Ok(());
    }
    let source = source.to_prefixed();
    let target_strings: Vec<String> = targets.iter().map(ContentHash::to_prefixed).collect();
    client
        .execute(
            "INSERT INTO fact_ref (source_hash, target_hash) \
             SELECT $1::text, unnest($2::text[]) \
             ON CONFLICT (source_hash, target_hash) DO NOTHING",
            &[&source, &target_strings],
        )
        .await?;
    Ok(())
}

/// Fetch a fact's full row (including embedded `bytes`).
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_get_fact<C: GenericClient + ?Sized>(
    client: &C,
    hash: &ContentHash,
) -> Result<Option<FactRow>, FactError> {
    let hash = hash.to_prefixed();
    let sql = format!(
        "SELECT {columns} FROM fact WHERE hash = $1",
        columns = fact_row_columns(),
    );
    let row = client.query_opt(&sql, &[&hash]).await?;
    Ok(row.map(|row| decode_fact_row(&row)))
}

/// Fetch metadata only — skips the `bytes` column.
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_get_fact_meta<C: GenericClient + ?Sized>(
    client: &C,
    hash: &ContentHash,
) -> Result<Option<FactMetaRow>, FactError> {
    let hash = hash.to_prefixed();
    let sql = format!(
        "SELECT {columns} FROM fact WHERE hash = $1",
        columns = fact_meta_columns(),
    );
    let row = client.query_opt(&sql, &[&hash]).await?;
    Ok(row.map(|row| decode_fact_meta_row(&row)))
}

/// Cheap existence check, backed by the `fact` PK index.
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_has_fact<C: GenericClient + ?Sized>(
    client: &C,
    hash: &ContentHash,
) -> Result<bool, FactError> {
    let hash = hash.to_prefixed();
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM fact WHERE hash = $1) AS exists",
            &[&hash],
        )
        .await?;
    Ok(row.get::<_, bool>(0))
}

/// List declared target hashes for a source fact (order unspecified).
///
/// Returns the raw stored strings — `fact_ref.target_hash` is unconstrained
/// (federation: a target may be a fact stored on another instance, in any hash
/// form), so this does not force a `ContentHash` parse.
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_get_fact_refs<C: GenericClient + ?Sized>(
    client: &C,
    source: &ContentHash,
) -> Result<Vec<String>, FactError> {
    let source = source.to_prefixed();
    let rows = client
        .query(
            "SELECT target_hash FROM fact_ref WHERE source_hash = $1",
            &[&source],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Drop a fact row. Cascades `fact_ref` rows via the `source_hash` FK. Returns
/// the deleted row's `(size, external_url)` for disk unlink + byte tallying, or
/// `None` when no row matched (idempotent).
///
/// Low-level: callers MUST verify the fact is truly orphan (see
/// [`query_orphan_facts_select_for_delete`]) before calling.
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_delete_fact<C: GenericClient + ?Sized>(
    client: &C,
    hash: &ContentHash,
) -> Result<Option<FactDeleted>, FactError> {
    let hash = hash.to_prefixed();
    let row = client
        .query_opt(
            "DELETE FROM fact WHERE hash = $1 RETURNING size, external_url",
            &[&hash],
        )
        .await?;
    Ok(row.map(|row| FactDeleted {
        size: row.get(0),
        external_url: row.get(1),
    }))
}

/// A single orphan-fact candidate (no active cell references it).
#[derive(Debug, Clone)]
pub struct OrphanFact {
    pub hash: String,
    pub size: i64,
    pub external_url: Option<String>,
}

/// Summary + sample of the orphan set, for the admin preview.
#[derive(Debug, Clone)]
pub struct OrphanFactsListResult {
    pub count: i64,
    pub total_size_bytes: i64,
    pub sample: Vec<OrphanFactSample>,
}

/// A sampled orphan row shown in the admin preview.
#[derive(Debug, Clone)]
pub struct OrphanFactSample {
    pub hash: String,
    pub size: i64,
    pub created_at: String,
    pub external_url: Option<String>,
}

/// Correlated `NOT EXISTS` over `cell` — a fact is orphaned when no active
/// (non-tombstone) cell's `refs` array contains its hash. Spliced into the
/// three orphan queries (count / sample / select-for-delete) so the predicate
/// lives in one place; each query keeps its own `older_than` filter, which
/// pairs `fact.created_at` with [`ORPHAN_FACT_NOT_RECENTLY_HELD`].
const ORPHAN_FACT_NOT_REFERENCED: &str = "NOT EXISTS ( \
       SELECT 1 FROM cell c \
       WHERE c.refs @> ARRAY[f.hash]::text[] \
         AND c.deleted_at IS NULL \
     )";

/// The grace-window half of the orphan cutoff: no `fact_holder` row was
/// recorded (or refreshed) at or after `$1`. A dedup put adds no `fact` row,
/// so `fact.created_at` stays at the first insert — without this, an old
/// orphan an actor re-uploads looks stale, and a sweep between the upload and
/// the cell write that references it deletes the fact (and, by cascade, the
/// possession the write needs). A fact counts as recent when its own
/// `created_at` or any holder's is within the window. Served by
/// `idx_fact_holder_hash`.
const ORPHAN_FACT_NOT_RECENTLY_HELD: &str = "NOT EXISTS ( \
       SELECT 1 FROM fact_holder h \
       WHERE h.hash = f.hash \
         AND h.created_at >= $1::text::timestamptz \
     )";

/// Compute the orphan-fact set: rows in `fact` no active (non-tombstone)
/// `cell.refs` array contains.
///
/// The `cell` join is deliberately app-coupled — `fact` lives in `fuz_facts`
/// and `cell.refs` in `fuz_cell` — but `fuz_fact` references the `cell` *table*
/// only in this SQL string, never the `fuz_cell` *crate* (the layering rule
/// holds). The orphan predicate only makes sense in apps routing content
/// through cells; the cell layer is the only fact consumer today.
///
/// `older_than` (RFC3339, or `None` to skip the filter) is the grace cutoff: a
/// fact passes it when both its `created_at` and every `fact_holder` row's are
/// older (a re-put refreshes the holder row); `sample_limit` caps the returned
/// sample.
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_orphan_facts_list<C: GenericClient + ?Sized>(
    client: &C,
    older_than: Option<&str>,
    sample_limit: i64,
) -> Result<OrphanFactsListResult, FactError> {
    let summary = client
        .query_one(
            &format!(
                "SELECT COUNT(*)::bigint AS count, COALESCE(SUM(size), 0)::bigint AS total \
                 FROM fact f \
                 WHERE {ORPHAN_FACT_NOT_REFERENCED} \
                 AND ($1::text::timestamptz IS NULL \
                      OR (f.created_at < $1::text::timestamptz AND {ORPHAN_FACT_NOT_RECENTLY_HELD}))"
            ),
            &[&older_than],
        )
        .await?;
    let sample_rows = client
        .query(
            &format!(
                "SELECT hash, size, {}, external_url \
                 FROM fact f \
                 WHERE {ORPHAN_FACT_NOT_REFERENCED} \
                 AND ($1::text::timestamptz IS NULL \
                      OR (f.created_at < $1::text::timestamptz AND {ORPHAN_FACT_NOT_RECENTLY_HELD})) \
                 ORDER BY f.created_at ASC \
                 LIMIT $2",
                iso8601_timestamp_column("f", "created_at")
            ),
            &[&older_than, &sample_limit],
        )
        .await?;
    Ok(OrphanFactsListResult {
        count: summary.get(0),
        total_size_bytes: summary.get(1),
        sample: sample_rows
            .iter()
            .map(|r| OrphanFactSample {
                hash: r.get(0),
                size: r.get(1),
                created_at: r.get(2),
                external_url: r.get(3),
            })
            .collect(),
    })
}

/// Select orphan-fact rows for deletion (no row-count limit — callers iterate
/// to unlink disk files).
///
/// `older_than` (RFC3339) is required: bulk delete is always operator-scoped
/// to a time window (a "delete all" sweep passes a far-future cutoff, not a
/// skip). It is the same grace cutoff as [`query_orphan_facts_list`]: a fact
/// put — or re-put, deduplicated — by an actor within the window is kept,
/// whatever its own `created_at`.
///
/// # Errors
///
/// [`FactError::Db`] on query failure.
pub async fn query_orphan_facts_select_for_delete<C: GenericClient + ?Sized>(
    client: &C,
    older_than: &str,
) -> Result<Vec<OrphanFact>, FactError> {
    let rows = client
        .query(
            &format!(
                "SELECT hash, size, external_url \
                 FROM fact f \
                 WHERE {ORPHAN_FACT_NOT_REFERENCED} \
                 AND f.created_at < $1::text::timestamptz \
                 AND {ORPHAN_FACT_NOT_RECENTLY_HELD}"
            ),
            &[&older_than],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| OrphanFact {
            hash: r.get(0),
            size: r.get(1),
            external_url: r.get(2),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_db::omit_columns;

    #[test]
    fn row_column_lists_pin_to_their_derivations() {
        assert_eq!(
            FACT_ROW_COLUMNS.to_vec(),
            omit_columns(&FACT_COLUMNS, &["hash"])
        );
        assert_eq!(
            FACT_META_COLUMNS.to_vec(),
            omit_columns(&FACT_COLUMNS, &["hash", "bytes"])
        );
    }

    #[test]
    fn row_projections_follow_the_const_order() {
        let created_at = iso8601_timestamp_column("fact", "created_at");
        assert_eq!(
            fact_row_columns(),
            format!("fact.bytes, fact.external_url, fact.content_type, fact.size, {created_at}")
        );
        assert_eq!(
            fact_meta_columns(),
            format!("fact.external_url, fact.content_type, fact.size, {created_at}")
        );
    }
}
