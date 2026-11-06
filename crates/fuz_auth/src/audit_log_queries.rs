//! Queries against the `audit_log` table.
//!
//! The audit emitter writes via [`crate::audit_emitter::AuditEmitter`];
//! these queries are for read-side surfaces (admin listing, scheduled
//! cleanup). Both sides project [`AUDIT_LOG_COLUMNS`] through
//! `audit_log_columns` and decode through `decode_audit_log_row` — the
//! emitter's `INSERT … RETURNING` reads the same list, so the row a
//! listener sees and the row an admin lists are one shape.

use serde::Serialize;
use serde_json::Value;

use crate::audit_event_schema::AuditLogEvent;
use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};

/// The `audit_log` table's columns.
///
/// Twin of `fuz_app`'s `AUDIT_LOG_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live
/// column.
pub const AUDIT_LOG_COLUMNS: [&str; 11] = [
    "id",
    "seq",
    "event_type",
    "outcome",
    "actor_id",
    "account_id",
    "target_account_id",
    "target_actor_id",
    "ip",
    "created_at",
    "metadata",
];

/// The [`AuditLogEvent`] projection (decoded positionally by
/// [`decode_audit_log_row`]): [`AUDIT_LOG_COLUMNS`] qualified by `alias`,
/// `created_at` as the ISO-8601 wire string and `metadata` through `::text`
/// (round-tripped as TEXT so `tokio-postgres` needs no `serde_json`
/// feature).
pub(crate) fn audit_log_columns(alias: &str) -> String {
    let timestamps = iso8601_timestamp_expr(&AUDIT_LOG_COLUMNS, &["created_at"], alias);
    qualify_columns(&AUDIT_LOG_COLUMNS, alias, |col| match col {
        "metadata" => Some(format!("{alias}.metadata::text")),
        _ => timestamps(col),
    })
}

/// Decode the [`audit_log_columns`] projection positionally. An
/// unparseable `metadata` document decodes as `None` rather than failing
/// the row.
pub(crate) fn decode_audit_log_row(row: &tokio_postgres::Row) -> AuditLogEvent {
    let metadata_text: Option<String> = row.get(col!(AUDIT_LOG_COLUMNS, "metadata"));
    let metadata = metadata_text.and_then(|s| serde_json::from_str::<Value>(&s).ok());
    AuditLogEvent {
        id: row.get(col!(AUDIT_LOG_COLUMNS, "id")),
        seq: row.get(col!(AUDIT_LOG_COLUMNS, "seq")),
        event_type: row.get(col!(AUDIT_LOG_COLUMNS, "event_type")),
        outcome: row.get(col!(AUDIT_LOG_COLUMNS, "outcome")),
        actor_id: row.get(col!(AUDIT_LOG_COLUMNS, "actor_id")),
        account_id: row.get(col!(AUDIT_LOG_COLUMNS, "account_id")),
        target_account_id: row.get(col!(AUDIT_LOG_COLUMNS, "target_account_id")),
        target_actor_id: row.get(col!(AUDIT_LOG_COLUMNS, "target_actor_id")),
        ip: row.get(col!(AUDIT_LOG_COLUMNS, "ip")),
        created_at: row.get(col!(AUDIT_LOG_COLUMNS, "created_at")),
        metadata,
    }
}

/// Default page size for [`query_audit_log_list_with_usernames`] and
/// [`query_audit_log_list_role_grant_history`]. Mirrors TS
/// `AUDIT_LOG_DEFAULT_LIMIT`.
pub const AUDIT_LOG_DEFAULT_LIMIT: i64 = 50;

/// Hard cap on `limit` for both `audit_log_list` and
/// `audit_log_role_grant_history`. Mirrors TS `AUDIT_LOG_LIST_LIMIT_MAX`.
pub const AUDIT_LOG_LIST_LIMIT_MAX: i64 = 200;

/// Optional filters for [`query_audit_log_list_with_usernames`].
///
/// Mirrors TS `AuditLogListOptions` (the subset the cross-process wire
/// surfaces — `event_type_in` is in-process-only on the TS side; not
/// ported here because no RPC method exposes it).
#[derive(Debug, Clone, Default)]
pub struct AuditLogListFilters {
    pub event_type: Option<String>,
    pub outcome: Option<String>,
    /// Matches against both `account_id` AND `target_account_id` —
    /// callers asking "events for this account" want both directions.
    pub account_id: Option<uuid::Uuid>,
    /// SSE reconnection gap-fill — returns rows with `seq > since_seq`. `seq`
    /// is assigned at INSERT; an in-transaction row commits later, so a row
    /// can become visible after a higher `seq` — a gap fill can miss one that
    /// commits while the stream is down.
    pub since_seq: Option<i64>,
}

/// Wire-shape audit-log row with LEFT-JOINed usernames — mirrors TS
/// `AuditLogEventWithUsernamesJson`.
///
/// `username` is the originating
/// actor's account username; `target_username` is the target's. Both
/// nullable: LEFT JOIN through `actor.account_id` (Stage-4-stamped
/// events) OR direct `account_id` (account-grain events) — null when
/// the row's principal has neither (or the referenced account was
/// hard-deleted, since the FK is `ON DELETE SET NULL`).
///
/// Same shape used for [`query_audit_log_list_role_grant_history`] — TS
/// distinguishes `AuditLogEventWithUsernamesJson` from
/// `RoleGrantHistoryEventJson` but they have identical fields. The
/// Rust port unifies on this struct.
#[derive(Debug, Clone, Serialize)]
pub struct AuditLogEventWithUsernames {
    #[serde(flatten)]
    pub event: AuditLogEvent,
    pub username: Option<String>,
    pub target_username: Option<String>,
}

/// Delete audit rows older than `cutoff_iso`. Returns the count.
///
/// `cutoff_iso` must be ISO 8601 / RFC 3339 — the SQL `::timestamptz` cast
/// validates the shape and surfaces an error if the caller mistyped.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_audit_log_cleanup_before(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    cutoff_iso: &str,
) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            "DELETE FROM audit_log WHERE created_at < $1::timestamptz",
            &[&cutoff_iso],
        )
        .await
}

/// Select list + 6-way LEFT JOIN used by both
/// [`query_audit_log_list_with_usernames`] and
/// [`query_audit_log_list_role_grant_history`]: [`audit_log_columns`] on the
/// `al` alias, then the two resolved usernames. Owned `String` because the
/// projection helpers return owned and splicing into a constant `&str`
/// would require either `format!` per call or a `LazyLock` — both more
/// code than helper composition.
fn audit_log_with_usernames_select() -> String {
    format!(
        "SELECT {columns},
                COALESCE(origin_act_acc.username, origin_acc.username) AS username,
                COALESCE(target_act_acc.username, target_acc.username) AS target_username
         FROM audit_log al
         LEFT JOIN actor origin_act ON origin_act.id = al.actor_id
         LEFT JOIN account origin_act_acc ON origin_act_acc.id = origin_act.account_id
         LEFT JOIN account origin_acc ON origin_acc.id = al.account_id
         LEFT JOIN actor target_act ON target_act.id = al.target_actor_id
         LEFT JOIN account target_act_acc ON target_act_acc.id = target_act.account_id
         LEFT JOIN account target_acc ON target_acc.id = al.target_account_id",
        columns = audit_log_columns("al"),
    )
}

/// Decode [`audit_log_columns`] + the two trailing username expressions
/// positionally.
fn decode_with_usernames_row(row: &tokio_postgres::Row) -> AuditLogEventWithUsernames {
    AuditLogEventWithUsernames {
        event: decode_audit_log_row(row),
        username: row.get(AUDIT_LOG_COLUMNS.len()),
        target_username: row.get(AUDIT_LOG_COLUMNS.len() + 1),
    }
}

/// List audit-log rows with LEFT-JOINed usernames, newest first.
/// Mirrors `fuz_app`'s `query_audit_log_list_with_usernames`.
///
/// 6-way LEFT JOIN through `actor` (for Stage-4-stamped events with
/// `actor_id` set) falling back to the direct `account` JOIN for
/// events whose principal has no actor binding. Under the v1 1:1
/// account:actor binding both branches resolve to the same username;
/// the chain is forensic future-proofing for N:1 multi-actor.
///
/// `account_id` filter matches both `al.account_id` and
/// `al.target_account_id` — "events for this account" wants both
/// directions.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_audit_log_list_with_usernames(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    filters: &AuditLogListFilters,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditLogEventWithUsernames>, tokio_postgres::Error> {
    // Build dynamic WHERE. Each filter is a placeholder; we track the
    // next param index to keep the SQL string and the `params` vec in
    // sync.
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
    let mut next: usize = 1;

    if let Some(ref event_type) = filters.event_type {
        conditions.push(format!("al.event_type = ${next}"));
        params.push(event_type);
        next += 1;
    }
    if let Some(ref account_id) = filters.account_id {
        conditions.push(format!(
            "(al.account_id = ${next} OR al.target_account_id = ${next})"
        ));
        params.push(account_id);
        next += 1;
    }
    if let Some(ref outcome) = filters.outcome {
        conditions.push(format!("al.outcome = ${next}"));
        params.push(outcome);
        next += 1;
    }
    // TODO: `seq` is assigned at INSERT and an in-transaction row
    // (`AuditEmitter::emit_in_tx`) commits later, so a strict `seq >` cursor
    // can miss a row that commits while the stream is down — anchor the gap
    // fill at the cursor minus a margin, or on `created_at`, and de-dupe by
    // `id` (the TS UI already does)
    if let Some(ref since_seq) = filters.since_seq {
        conditions.push(format!("al.seq > ${next}"));
        params.push(since_seq);
        next += 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let limit_placeholder = next;
    let offset_placeholder = next + 1;
    params.push(&limit);
    params.push(&offset);

    let sql = format!(
        "{select}{where_clause}
         ORDER BY al.seq DESC
         LIMIT ${limit_p} OFFSET ${offset_p}",
        select = audit_log_with_usernames_select(),
        where_clause = where_clause,
        limit_p = limit_placeholder,
        offset_p = offset_placeholder,
    );

    let rows = client.query(sql.as_str(), &params).await?;
    Ok(rows.iter().map(decode_with_usernames_row).collect())
}

/// List `role_grant` grant/revoke audit events with LEFT-JOINed
/// usernames, newest first. Mirrors `fuz_app`'s
/// `query_audit_log_list_role_grant_history`.
///
/// Hardcoded `WHERE al.event_type IN ('role_grant_create',
/// 'role_grant_revoke')` — deliberately narrower than the offer-side
/// audit family (`role_grant_offer_*`) which lives on a separate
/// surface. See `fuz_app/src/lib/auth/audit_log_queries.ts` lines
/// 259–282 for the TS-side scoping rationale.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_audit_log_list_role_grant_history(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditLogEventWithUsernames>, tokio_postgres::Error> {
    let sql = format!(
        "{select}
         WHERE al.event_type IN ('role_grant_create', 'role_grant_revoke')
         ORDER BY al.seq DESC
         LIMIT $1 OFFSET $2",
        select = audit_log_with_usernames_select(),
    );
    let rows = client.query(sql.as_str(), &[&limit, &offset]).await?;
    Ok(rows.iter().map(decode_with_usernames_row).collect())
}
