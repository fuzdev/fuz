//! Raw queries against the `cell` table.
//!
//! Mirrors `fuz_app`'s `db/cell_queries.ts` for the 5 first-cut verbs.
//! `refs` is auto-derived from `data` on create / update (depth-first
//! walk for string values that are exactly a fact hash — callers never pass
//! `refs`).
//! Soft delete via `deleted_at`; reads exclude tombstones. `path`
//! uniqueness is global (`idx_cell_path_unique`, partial on active rows).
//!
//! Timestamps project SQL-side as UTC ISO-8601 strings (the workspace
//! `tokio-postgres` has no time-type feature) and `data` round-trips
//! through `::text` (no `with-serde_json` feature). `grant_count` is a
//! correlated subquery over the cell's `cell_grant` rows.

use std::collections::HashSet;

use deadpool_postgres::GenericClient;
use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};
use serde_json::Value;
use uuid::Uuid;

use crate::cell_moderation::{
    CELL_MODERATION_APPROVED, CELL_MODERATION_PENDING, CELL_MODERATION_REJECTED,
    cell_moderation_admits_audience_sql, cell_moderation_is_stewardable_sql,
};
use crate::cell_schema::{CellListOrderBy, CellListOrderDir, CellRow, CellViewRow, CellVisibility};
use crate::cell_view_sql::{
    CellViewer, CellViewerSqlParams, caller_role_grants_cte, can_view_cell_sql,
    cell_grant_admits_caller_sql,
};
use crate::error::CellError;

/// Soft cap on a `cell_list` page (mirrors TS `CELL_LIST_LIMIT_MAX`).
pub const CELL_LIST_LIMIT_MAX: i64 = 200;
/// Default `cell_list` page size when the caller omits `limit` (mirrors
/// TS `CELL_LIST_LIMIT_DEFAULT`).
pub const CELL_LIST_LIMIT_DEFAULT: i64 = 50;

/// Depth-first collect the string values in `data` that are exactly a fact
/// hash. Returns `None` (not `Some([])`) when empty — the column is nullable
/// and `idx_cell_refs` is partial on `refs IS NOT NULL`.
///
/// A ref is a **whole** string value matching the wire fact-hash grammar —
/// `blake3:` followed by exactly sixty-four lowercase hex characters
/// ([`fuz_auth::is_valid_fact_hash`], the twin of `fuz_util`'s
/// `FACT_HASH_EXACT`). A hash inside prose, an uppercase-hex digest, or a
/// `blake3:` string of any other length is not a ref. Refs are what fact
/// serving admits a read through and what ref admission gates on a write, so
/// the grammar is exact on both spines: a string either is an address or
/// isn't one.
///
/// Object keys are not walked — only values.
///
/// The deduped refs are sorted lexicographically before returning so the
/// stored `text[]` is deterministic and byte-identical to the TS twin
/// (`fuz_app`'s `derive_cell_refs`, which sorts the same element form): a
/// `HashSet` collect alone would yield non-deterministic iteration order,
/// diverging the two spines for identical `data`.
#[must_use]
pub fn extract_refs(data: &Value) -> Option<Vec<String>> {
    fn walk<'a>(value: &'a Value, seen: &mut HashSet<&'a str>) {
        match value {
            Value::String(s) if fuz_auth::is_valid_fact_hash(s) => {
                seen.insert(s);
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, seen)),
            Value::Object(map) => map.values().for_each(|v| walk(v, seen)),
            _ => {}
        }
    }
    let mut seen = HashSet::new();
    walk(data, &mut seen);
    if seen.is_empty() {
        None
    } else {
        let mut refs: Vec<String> = seen.into_iter().map(str::to_owned).collect();
        refs.sort_unstable();
        Some(refs)
    }
}

/// The `cell` table's columns, in projection order.
///
/// `cell_columns` projects them in this order and `decode_row` reads them
/// positionally (the derived `grant_count` is appended after the last
/// column). `kind` is the top-level capability-tag column projected right
/// after `data`; `parent_id` / `root_id` / `moderation` / `policy` (the
/// directory tree, the lifecycle marker, and a root's contribution policy)
/// project right after `refs`.
///
/// Twin of `fuz_app`'s `CELL_COLUMNS`. The PG-gated `columns` integration
/// test asserts this names every live column, so a column added to the DDL
/// but not here fails loud instead of silently vanishing from every read.
pub const CELL_COLUMNS: [&str; 15] = [
    "id",
    "data",
    "kind",
    "visibility",
    "path",
    "refs",
    "parent_id",
    "root_id",
    "moderation",
    "policy",
    "created_at",
    "updated_at",
    "deleted_at",
    "created_by",
    "updated_by",
];

/// The `CellRow` projection (decoded positionally by [`decode_row`]):
/// [`CELL_COLUMNS`] qualified by `alias` plus the correlated `grant_count`
/// subquery. `alias` is the row qualifier — the table name (`"cell"`) for
/// single-table reads + `RETURNING`, the query alias (`"c"`) for `cell_list`.
/// `data` / `policy` / `visibility` project through `::text` (no
/// `with-serde_json` feature; the enum decodes by label) and the
/// timestamps through `fuz_db`'s `iso8601_timestamp_column` for the spine's
/// canonical second-precision UTC ISO-8601 wire shape.
fn cell_columns(alias: &str) -> String {
    let timestamps = iso8601_timestamp_expr(
        &CELL_COLUMNS,
        &["created_at", "updated_at", "deleted_at"],
        alias,
    );
    let columns = qualify_columns(&CELL_COLUMNS, alias, |col| match col {
        "data" | "policy" | "visibility" => Some(format!("{alias}.{col}::text")),
        _ => timestamps(col),
    });
    format!(
        "{columns}, (SELECT COUNT(*)::int FROM cell_grant WHERE cell_id = {alias}.id) AS grant_count"
    )
}

/// Decode the [`cell_columns`] projection positionally — each index resolved
/// by column name at compile time (`fuz_db::col!`), so it follows
/// [`CELL_COLUMNS`] however that const evolves; the appended `grant_count`
/// indexes from the const's length.
fn decode_row(row: &tokio_postgres::Row) -> Result<CellRow, CellError> {
    let data_text: String = row.get(col!(CELL_COLUMNS, "data"));
    let data: Value =
        serde_json::from_str(&data_text).map_err(|e| CellError::Decode(format!("data: {e}")))?;
    let visibility_text: String = row.get(col!(CELL_COLUMNS, "visibility"));
    let visibility = CellVisibility::from_db(&visibility_text)
        .ok_or_else(|| CellError::Decode(format!("visibility: {visibility_text:?}")))?;
    let policy_text: Option<String> = row.get(col!(CELL_COLUMNS, "policy"));
    let policy: Option<Value> = policy_text
        .map(|text| serde_json::from_str(&text))
        .transpose()
        .map_err(|e| CellError::Decode(format!("policy: {e}")))?;
    Ok(CellRow {
        id: row.get(col!(CELL_COLUMNS, "id")),
        data,
        kind: row.get(col!(CELL_COLUMNS, "kind")),
        visibility,
        path: row.get(col!(CELL_COLUMNS, "path")),
        refs: row.get(col!(CELL_COLUMNS, "refs")),
        parent_id: row.get(col!(CELL_COLUMNS, "parent_id")),
        root_id: row.get(col!(CELL_COLUMNS, "root_id")),
        moderation: row.get(col!(CELL_COLUMNS, "moderation")),
        policy,
        created_at: row.get(col!(CELL_COLUMNS, "created_at")),
        updated_at: row.get(col!(CELL_COLUMNS, "updated_at")),
        deleted_at: row.get(col!(CELL_COLUMNS, "deleted_at")),
        created_by: row.get(col!(CELL_COLUMNS, "created_by")),
        updated_by: row.get(col!(CELL_COLUMNS, "updated_by")),
        grant_count: row.get(CELL_COLUMNS.len()),
    })
}

/// Insert a cell, deriving `refs` from `data`.
///
/// `policy` is a root's contribution policy (the table CHECK refuses one on a
/// cell with a parent, or one that isn't a JSON object). `updated_by` is left
/// NULL (meaningful only after a real edit). `path`
/// collisions surface as the `tokio_postgres` unique-violation error for
/// the handler to translate.
///
/// # Errors
///
/// [`CellError::Db`] on driver / constraint failure; [`CellError::Decode`]
/// if the returned row is malformed.
#[expect(
    clippy::too_many_arguments,
    reason = "positional create params mirror the kind hoist + the directory-tree columns; a struct would add ceremony for two callsites"
)]
pub async fn query_cell_create<C: GenericClient + ?Sized>(
    client: &C,
    data: &Value,
    kind: Option<&str>,
    visibility: Option<CellVisibility>,
    path: Option<&str>,
    parent_id: Option<Uuid>,
    root_id: Option<Uuid>,
    moderation: Option<&str>,
    policy: Option<&Value>,
    created_by: Option<Uuid>,
) -> Result<CellRow, CellError> {
    let refs = extract_refs(data);
    let data_text = data.to_string();
    let policy_text = policy.map(Value::to_string);
    let visibility = visibility.map(CellVisibility::as_str);
    let sql = format!(
        "INSERT INTO cell (data, kind, visibility, path, refs, parent_id, root_id, moderation, policy, created_by)
         VALUES ($1::text::jsonb, $2, COALESCE($3::text::cell_visibility, 'private'::cell_visibility), $4, $5::text[], $6, $7, $8, $9::text::jsonb, $10)
         RETURNING {cols}",
        cols = cell_columns("cell"),
    );
    let row = client
        .query_one(
            &sql,
            &[
                &data_text,
                &kind,
                &visibility,
                &path,
                &refs,
                &parent_id,
                &root_id,
                &moderation,
                &policy_text,
                &created_by,
            ],
        )
        .await?;
    decode_row(&row)
}

/// Fetch a cell by id, excluding tombstones.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_get<C: GenericClient + ?Sized>(
    client: &C,
    id: Uuid,
) -> Result<Option<CellRow>, CellError> {
    let sql = format!(
        "SELECT {cols} FROM cell WHERE id = $1 AND deleted_at IS NULL",
        cols = cell_columns("cell"),
    );
    let row = client.query_opt(&sql, &[&id]).await?;
    row.as_ref().map(decode_row).transpose()
}

/// Fetch a cell by `path`, excluding tombstones. The global partial
/// unique index guarantees at most one active row.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_get_by_path<C: GenericClient + ?Sized>(
    client: &C,
    path: &str,
) -> Result<Option<CellRow>, CellError> {
    let sql = format!(
        "SELECT {cols} FROM cell WHERE path = $1 AND deleted_at IS NULL",
        cols = cell_columns("cell"),
    );
    let row = client.query_opt(&sql, &[&path]).await?;
    row.as_ref().map(decode_row).transpose()
}

/// Bulk-load active cells by id (no visibility filter).
///
/// Tombstones and unmatched ids are simply absent — the caller indexes the
/// result by `id` and decides viewability per row. A caller that needs only
/// the view check reads [`query_cell_view_load_many`] instead.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_load_many<C: GenericClient + ?Sized>(
    client: &C,
    ids: &[Uuid],
) -> Result<Vec<CellRow>, CellError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT {cols} FROM cell WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL",
        cols = cell_columns("cell"),
    );
    let rows = client.query(&sql, &[&ids]).await?;
    rows.iter().map(decode_row).collect()
}

/// The columns a view check reads ([`CellViewRow`]) — a subset of
/// [`CELL_COLUMNS`], pinned to it by a unit test, so the base const's drift
/// guard covers it. Twin of `fuz_app`'s `CELL_VIEW_COLUMNS`.
pub const CELL_VIEW_COLUMNS: [&str; 4] = ["id", "visibility", "moderation", "created_by"];

/// Decode the [`CELL_VIEW_COLUMNS`] projection (`visibility` read as text).
fn decode_view_row(row: &tokio_postgres::Row) -> Result<CellViewRow, CellError> {
    let visibility_text: String = row.get(col!(CELL_VIEW_COLUMNS, "visibility"));
    let visibility = CellVisibility::from_db(&visibility_text)
        .ok_or_else(|| CellError::Decode(format!("visibility: {visibility_text:?}")))?;
    Ok(CellViewRow {
        id: row.get(col!(CELL_VIEW_COLUMNS, "id")),
        visibility,
        moderation: row.get(col!(CELL_VIEW_COLUMNS, "moderation")),
        created_by: row.get(col!(CELL_VIEW_COLUMNS, "created_by")),
    })
}

/// Bulk-load the active cells among `ids` for a view check.
///
/// Reads the [`CELL_VIEW_COLUMNS`] alone, not the payload. Soft-deleted cells
/// and ids with no row are absent. Backs the batched relation-read filter
/// ([`crate::cell_relation_visibility::filter_visible_targets`]).
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_view_load_many<C: GenericClient + ?Sized>(
    client: &C,
    ids: &[Uuid],
) -> Result<Vec<CellViewRow>, CellError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT {cols} FROM cell WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL",
        cols = qualify_columns(&CELL_VIEW_COLUMNS, "cell", |col| match col {
            "visibility" => Some("cell.visibility::text".to_owned()),
            _ => None,
        }),
    );
    let rows = client.query(&sql, &[&ids]).await?;
    rows.iter().map(decode_view_row).collect()
}

/// Partial update via per-field `CASE WHEN provided`. `refs` is re-derived
/// when `data` is provided; `updated_at` always bumps. Returns `None`
/// when no active row matched (deleted or never existed).
///
/// `path` is tri-state: `None` keeps it, `Some(None)` clears it,
/// `Some(Some(v))` sets it. `updated_by` is always stamped.
///
/// # Errors
///
/// [`CellError`] on driver / constraint / decode failure.
pub async fn query_cell_update<C: GenericClient + ?Sized>(
    client: &C,
    id: Uuid,
    data: Option<&Value>,
    visibility: Option<CellVisibility>,
    path: Option<Option<&str>>,
    updated_by: Option<Uuid>,
) -> Result<Option<CellRow>, CellError> {
    let data_provided = data.is_some();
    let refs = data.and_then(extract_refs);
    let data_text = data.map(Value::to_string);
    let path_provided = path.is_some();
    let path_value = path.flatten();
    let visibility_provided = visibility.is_some();
    let visibility = visibility.map(CellVisibility::as_str);
    let sql = format!(
        "UPDATE cell SET
           data       = CASE WHEN $2::bool THEN $3::text::jsonb ELSE data END,
           refs       = CASE WHEN $2::bool THEN $4::text[] ELSE refs END,
           path       = CASE WHEN $5::bool THEN $6 ELSE path END,
           updated_by = $7,
           visibility = CASE WHEN $8::bool THEN $9::text::cell_visibility ELSE visibility END,
           updated_at = NOW()
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING {cols}",
        cols = cell_columns("cell"),
    );
    let row = client
        .query_opt(
            &sql,
            &[
                &id,
                &data_provided,
                &data_text,
                &refs,
                &path_provided,
                &path_value,
                &updated_by,
                &visibility_provided,
                &visibility,
            ],
        )
        .await?;
    row.as_ref().map(decode_row).transpose()
}

/// Transition a contribution's `moderation` marker (the `cell_moderate`
/// verb's write).
///
/// The `WHERE` carries the allowed from-states: an approval moves only a
/// `pending` row, and a rejection a `pending` or `approved` one (the
/// moderator's takedown). A rejected or unmoderated cell never moves, and
/// nothing already approved is approved again — without the from-state an
/// approval would force any cell its caller can reach public. On
/// `set_visibility_public` (an approval) it also flips `visibility` to
/// `public` so the approved contribution goes live; a rejection leaves
/// visibility untouched — a pending post stays as its author set it, and a
/// taken-down one keeps its visibility, hidden by the marker alone.
/// `updated_at` / `updated_by` are stamped. Returns `None` when no active row
/// in an allowed from-state matched (a raced delete or decision, or a refused
/// transition).
///
/// `moderation` is **not** writable through [`query_cell_update`] — gating the
/// transition on a dedicated query (with the manage-tier authority check in the
/// handler) is what stops an author self-approving their own pending cell.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_set_moderation<C: GenericClient + ?Sized>(
    client: &C,
    id: Uuid,
    moderation: &str,
    set_visibility_public: bool,
    updated_by: Option<Uuid>,
) -> Result<Option<CellRow>, CellError> {
    let sql = format!(
        "UPDATE cell SET
           moderation = $2,
           visibility = CASE WHEN $3::bool THEN 'public'::cell_visibility ELSE visibility END,
           updated_by = $4,
           updated_at = NOW()
         WHERE id = $1 AND deleted_at IS NULL
           AND (moderation = '{CELL_MODERATION_PENDING}'
             OR ($2::text = '{CELL_MODERATION_REJECTED}' AND moderation = '{CELL_MODERATION_APPROVED}'))
         RETURNING {cols}",
        cols = cell_columns("cell"),
    );
    let row = client
        .query_opt(
            &sql,
            &[&id, &moderation, &set_visibility_public, &updated_by],
        )
        .await?;
    row.as_ref().map(decode_row).transpose()
}

/// What [`query_cell_set_policy`] answers: the updated root and the policy it
/// replaced. Twin of `fuz_app`'s `CellSetPolicyResult`.
#[derive(Debug, Clone)]
pub struct CellSetPolicyResult {
    pub cell: CellRow,
    /// The root's `policy` as the `UPDATE` found it, under the row lock it
    /// writes with.
    pub previous_policy: Option<Value>,
}

/// Replace a root's contribution `policy` (the `cell_policy_set` verb's
/// write); `None` clears it.
///
/// The `WHERE` carries `parent_id IS NULL`, so only a root ever takes a
/// policy, the table CHECK's rule restated where the write is. `updated_at` /
/// `updated_by` are stamped. Returns `None` when no active root matched (a
/// raced delete).
///
/// The replaced policy is read by the statement that writes, from a
/// `FOR UPDATE` subquery: a concurrent set waits on that row lock and then
/// reads the committed value, so the audit's `previous_policy` is the value
/// this write replaced, never one a racing set already overwrote.
///
/// `policy` is **not** writable through [`query_cell_update`] — `data` writes
/// gate on edit authority, which an editor grant carries, and the policy is
/// what decides who may contribute under the root, so it changes only through
/// this dedicated query behind the handler's manage-tier check.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_set_policy<C: GenericClient + ?Sized>(
    client: &C,
    id: Uuid,
    policy: Option<&Value>,
    updated_by: Option<Uuid>,
) -> Result<Option<CellSetPolicyResult>, CellError> {
    let policy_text = policy.map(Value::to_string);
    let sql = format!(
        "UPDATE cell SET
           policy = $2::text::jsonb,
           updated_by = $3,
           updated_at = NOW()
         FROM (
           SELECT p.id, p.policy AS previous_policy FROM cell p
           WHERE p.id = $1 AND p.deleted_at IS NULL AND p.parent_id IS NULL
           FOR UPDATE
         ) prev
         WHERE cell.id = prev.id
         RETURNING {cols}, prev.previous_policy::text",
        cols = cell_columns("cell"),
    );
    let Some(row) = client
        .query_opt(&sql, &[&id, &policy_text, &updated_by])
        .await?
    else {
        return Ok(None);
    };
    let cell = decode_row(&row)?;
    // after the projection's columns and its appended `grant_count`
    let previous_text: Option<String> = row.get(CELL_COLUMNS.len() + 1);
    let previous_policy = previous_text
        .map(|text| serde_json::from_str(&text))
        .transpose()
        .map_err(|e| CellError::Decode(format!("previous_policy: {e}")))?;
    Ok(Some(CellSetPolicyResult {
        cell,
        previous_policy,
    }))
}

/// Soft-delete a cell. Returns `true` when an active row was tombstoned,
/// `false` when none matched (already deleted / never existed).
///
/// # Errors
///
/// [`CellError::Db`] on driver failure.
pub async fn query_cell_delete<C: GenericClient + ?Sized>(
    client: &C,
    id: Uuid,
    deleted_by: Option<Uuid>,
) -> Result<bool, CellError> {
    let row = client
        .query_opt(
            "UPDATE cell SET deleted_at = NOW(), updated_at = NOW(), updated_by = $2
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING id",
            &[&id, &deleted_by],
        )
        .await?;
    Ok(row.is_some())
}

/// List active cells of one `kind`, newest first, with **no** visibility
/// predicate.
///
/// Twin of `fuz_app`'s `query_cell_list_by_kind` (`db/cell_queries.ts`) —
/// same `kind = $1 AND deleted_at IS NULL` filter, same `created_at DESC`
/// order, same nullable `LIMIT $2 OFFSET $3`, and the same projection as
/// [`query_cell_list`]. `limit: None` is `LIMIT NULL`, i.e. unbounded: a
/// consumer whose cell kind *is* its resource namespace (the forge's file
/// store) lists the whole namespace, where [`query_cell_list`]'s paged
/// `limit` would silently truncate it.
///
/// Deliberately unfiltered by viewer: a caller reaching for a whole kind has
/// already made the authority decision at its own gate. Use
/// [`query_cell_list`] where the visibility predicate is the point.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_list_by_kind<C: GenericClient + ?Sized>(
    client: &C,
    kind: &str,
    limit: Option<i64>,
    offset: i64,
) -> Result<Vec<CellRow>, CellError> {
    let sql = format!(
        "SELECT {cols} FROM cell
         WHERE kind = $1
           AND deleted_at IS NULL
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3",
        cols = cell_columns("cell"),
    );
    let rows = client.query(&sql, &[&kind, &limit, &offset]).await?;
    rows.iter().map(decode_row).collect()
}

/// Filter + visibility params for [`query_cell_list`].
///
/// The general predicate mirrors `can_view_cell || can_steward_cell`: admit
/// when admin, owner, or — while the cell's `moderation` admits an audience
/// ([`crate::cell_moderation`]) — `public` or a `cell_grant` admits the
/// caller (actor- or role-shaped); or when the caller owns the live governing
/// root of a pending or rejected contribution (the steward arm — the global
/// admin is already admitted). `shared_with_caller_only` switches to a
/// grant-driven semi-join returning only cells the caller has a grant on,
/// under the same moderation admission and without the steward arm.
#[derive(Debug, Default)]
pub struct CellListParams<'a> {
    pub ids: Option<&'a [Uuid]>,
    pub kind: Option<&'a str>,
    pub visibility: Option<CellVisibility>,
    pub ref_hash: Option<&'a str>,
    pub created_by: Option<Uuid>,
    pub path_prefix: Option<&'a str>,
    /// Scope to a directory subtree by governing root (feed + mod-queue key).
    pub root_id: Option<Uuid>,
    /// Filter by moderation lifecycle marker (`pending` = the mod queue).
    ///
    /// The visibility predicate still applies, so `{root_id, moderation:
    /// "pending"}` is the queue for the callers who moderate it — a global
    /// admin, and the governing root's owner through the steward arm — while
    /// each author sees only their own entries.
    pub moderation: Option<&'a str>,
    /// The caller the visibility predicate binds — one value for the owner,
    /// admin, grant and steward arms, so visibility and grant admission can't
    /// be read for two different callers. The default is anonymous.
    pub viewer: CellViewer<'a>,
    /// Restrict the result to cells the caller has a grant on
    /// (`shared_with: 'me'`). Switches to the grant-driven semi-join; the
    /// admin bypass is intentionally not consulted.
    pub shared_with_caller_only: bool,
    pub order_by: CellListOrderBy,
    pub order_dir: CellListOrderDir,
    pub limit: i64,
    pub offset: i64,
}

/// List cells under the visibility predicate, or — when
/// `shared_with_caller_only` — only cells the caller has a grant on.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure.
pub async fn query_cell_list<C: GenericClient + ?Sized>(
    client: &C,
    params: &CellListParams<'_>,
) -> Result<Vec<CellRow>, CellError> {
    let order_column = params.order_by.column();
    let order_direction = params.order_dir.sql();
    let visibility = params.visibility.map(CellVisibility::as_str);
    let cols = cell_columns("c");
    // The caller's `(role, scope_id)` pairs, materialized once per query.
    let caller_role_grants = caller_role_grants_cte("$11", "$12");
    let grant_admits = cell_grant_admits_caller_sql("g", "$8");
    let can_view = can_view_cell_sql(
        "c",
        CellViewerSqlParams {
            is_admin: "$7",
            actor_id: "$8",
        },
    );
    let audience_admitted = cell_moderation_admits_audience_sql("c");
    let stewardable = cell_moderation_is_stewardable_sql("c");
    // The caller's `(role, scope_id)` pairs materialize once via a CTE so
    // the role-grant predicate doesn't re-scan `unnest()` per outer row.
    // `starts_with(path, $5)` (not `LIKE`) so caller wildcards match
    // literally. Column refs + validated order tokens are interpolated;
    // user values flow only through the param array.
    let sql = if params.shared_with_caller_only {
        // Grant-driven semi-join: walk `cell_grant` via the partial indexes,
        // probe `cell` by id. `$7` (admin bypass) is intentionally not
        // consulted — "what's shared with me" is the caller's grant
        // footprint, not every cell — but is referenced as `IS NOT NULL` to
        // keep the shared 12-param layout valid. `created_by IS DISTINCT
        // FROM $8` excludes the caller's own cells (owner ≠ sharee). A grant
        // admits only while the cell's moderation admits an audience, as in
        // `can_view_cell`.
        format!(
            "WITH {caller_role_grants}
             SELECT {cols} FROM cell c
             WHERE c.deleted_at IS NULL
               AND ($1::text IS NULL OR c.kind = $1::text)
               AND ($2::text::cell_visibility IS NULL OR c.visibility = $2::text::cell_visibility)
               AND ($3::text IS NULL OR c.refs @> ARRAY[$3]::text[])
               AND ($4::uuid IS NULL OR c.created_by = $4)
               AND ($5::text IS NULL OR starts_with(c.path, $5))
               AND ($6::uuid[] IS NULL OR c.id = ANY($6))
               AND ($13::uuid IS NULL OR c.root_id = $13)
               AND ($14::text IS NULL OR c.moderation = $14::text)
               AND $8::uuid IS NOT NULL
               AND c.created_by IS DISTINCT FROM $8
               AND {audience_admitted}
               AND c.id IN (SELECT g.cell_id FROM cell_grant g WHERE {grant_admits})
               AND $7::bool IS NOT NULL
             ORDER BY c.{order_column} {order_direction} NULLS LAST
             LIMIT $9 OFFSET $10"
        )
    } else {
        // The `can_view_cell` arms, then the steward arm (`can_steward_cell`):
        // the caller owns the live governing root of a pending or rejected
        // contribution. A global admin is already in through `$7`.
        format!(
            "WITH {caller_role_grants}
             SELECT {cols} FROM cell c
             WHERE c.deleted_at IS NULL
               AND ($1::text IS NULL OR c.kind = $1::text)
               AND ($2::text::cell_visibility IS NULL OR c.visibility = $2::text::cell_visibility)
               AND ($3::text IS NULL OR c.refs @> ARRAY[$3]::text[])
               AND ($4::uuid IS NULL OR c.created_by = $4)
               AND ($5::text IS NULL OR starts_with(c.path, $5))
               AND ($6::uuid[] IS NULL OR c.id = ANY($6))
               AND ($13::uuid IS NULL OR c.root_id = $13)
               AND ($14::text IS NULL OR c.moderation = $14::text)
               AND (
                 {can_view}
                 OR ($8::uuid IS NOT NULL AND c.root_id IS NOT NULL AND {stewardable}
                     AND EXISTS (
                       SELECT 1 FROM cell r
                       WHERE r.id = c.root_id AND r.deleted_at IS NULL AND r.created_by = $8
                     ))
               )
             ORDER BY c.{order_column} {order_direction} NULLS LAST
             LIMIT $9 OFFSET $10"
        )
    };
    let [is_admin, actor_id, role_grant_roles, role_grant_scope_ids] = params.viewer.sql_params();
    let rows = client
        .query(
            &sql,
            &[
                &params.kind,
                &visibility,
                &params.ref_hash,
                &params.created_by,
                &params.path_prefix,
                &params.ids,
                is_admin,
                actor_id,
                &params.limit,
                &params.offset,
                role_grant_roles,
                role_grant_scope_ids,
                &params.root_id,
                &params.moderation,
            ],
        )
        .await?;
    rows.iter().map(decode_row).collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CELL_COLUMNS, CELL_VIEW_COLUMNS, extract_refs};
    use crate::cell_schema::CellVisibility;

    #[test]
    fn view_columns_are_a_subset_of_the_cell_columns() {
        // the base const's drift guard covers the narrow read through this pin
        assert!(fuz_db::columns_not_in(&CELL_VIEW_COLUMNS, &CELL_COLUMNS).is_empty());
    }

    /// A well-formed fact hash whose digest is `c` repeated.
    fn hash_of(c: char) -> String {
        format!("blake3:{}", c.to_string().repeat(64))
    }

    #[test]
    fn extract_refs_walks_nested_strings() {
        let (a, b, c) = (hash_of('a'), hash_of('b'), hash_of('c'));
        let data = json!({
            "kind": "doc",
            "cover": a,
            "nested": {"attachments": [b, "not-a-ref", c]},
            "count": 3,
        });
        let refs = extract_refs(&data).unwrap();
        assert_eq!(refs, vec![a, b, c]);
    }

    #[test]
    fn extract_refs_returns_lexicographically_sorted() {
        // Traversal order would surface `c…` before `a…`; the result must
        // be sorted regardless of input order (and regardless of `HashSet`
        // iteration order) so the stored `text[]` is byte-identical to the TS
        // twin's `derive_cell_refs` output for the same `data`.
        let data = json!({
            "cover": hash_of('c'),
            "nested": {"attachments": [hash_of('a'), hash_of('b')]},
        });
        let refs = extract_refs(&data).unwrap();
        assert_eq!(refs, vec![hash_of('a'), hash_of('b'), hash_of('c')]);
    }

    #[test]
    fn extract_refs_dedupes_and_returns_none_when_empty() {
        let x = hash_of('0');
        let dup = json!([x, x, {"a": x}]);
        assert_eq!(extract_refs(&dup).unwrap(), vec![x]);
        assert!(extract_refs(&json!({"kind": "note", "n": 1})).is_none());
        assert!(extract_refs(&json!("plain string")).is_none());
    }

    #[test]
    fn extract_refs_takes_whole_exact_hashes_only() {
        let exact = format!("blake3:{}", "0123456789abcdef".repeat(4));
        // The exact grammar: a whole string, `blake3:` + 64 lowercase hex.
        assert_eq!(
            extract_refs(&json!({"f": exact})).unwrap(),
            vec![exact.clone()]
        );
        for not_a_ref in [
            // a short or malformed digest
            "blake3:zz".to_owned(),
            "blake3:".to_owned(),
            format!("blake3:{}", "a".repeat(63)),
            format!("blake3:{}", "a".repeat(65)),
            // uppercase hex — off-grammar on the TS twin's `FACT_HASH_EXACT`
            exact.to_uppercase().replacen("BLAKE3:", "blake3:", 1),
            // a hash inside prose, or wrapped in markup or whitespace
            format!("see {exact} for details"),
            format!("![cover]({exact})"),
            format!(" {exact}"),
            format!("{exact}\n"),
            // another algorithm token
            format!("sha256:{}", "a".repeat(64)),
        ] {
            assert!(
                extract_refs(&json!({"f": not_a_ref})).is_none(),
                "{not_a_ref:?} is not a ref"
            );
        }
        // An object key is never a ref, only values are.
        assert!(extract_refs(&json!({ exact: 1 })).is_none());
    }

    #[test]
    fn visibility_round_trips_through_db_token() {
        for v in [CellVisibility::Private, CellVisibility::Public] {
            assert_eq!(CellVisibility::from_db(v.as_str()), Some(v));
        }
        assert_eq!(CellVisibility::from_db("bogus"), None);
    }
}
