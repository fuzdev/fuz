//! Queries against the `account` table.
//!
//! Every row shape this module reads has exactly one projection and one
//! decoder: [`ACCOUNT_COLUMNS`] (the table — the twin of `fuz_app`'s const,
//! guarded against the live schema by the `columns` integration test) for
//! the wire-row reads, and a private per-shape column list for each narrow
//! purpose row ([`AccountRow`], [`AccountWithPasswordHash`], …), checked as
//! a subset of the table const by this module's unit test. A read never
//! spells its own column list, and the decoders resolve their indices from
//! the const by name at compile time (`fuz_db::col!`), so a reordered
//! SELECT can't silently transpose two same-typed columns at one site. See
//! the crate docs § Named projections.

use std::collections::HashMap;

use serde::Serialize;

use crate::account_schema::{AccountRow, AccountSummaryRow, AccountWithPasswordHash};
use fuz_db::{col, iso8601_timestamp_column, iso8601_timestamp_expr, qualify_columns};

/// The `account` table's columns.
///
/// Twin of `fuz_app`'s `ACCOUNT_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live
/// column, so a column added to the DDL but not here fails loud instead of
/// silently vanishing from every projection derived from it.
pub const ACCOUNT_COLUMNS: [&str; 11] = [
    "id",
    "username",
    "email",
    "email_verified",
    "password_hash",
    "created_at",
    "created_by",
    "updated_at",
    "updated_by",
    "deleted_at",
    "deleted_by",
];

/// [`AccountRow`] projection — the identity pair every lookup and
/// `RETURNING` reads.
const ACCOUNT_ROW_COLUMNS: [&str; 2] = ["id", "username"];

/// [`AccountWithPasswordHash`] projection — the login / password-change
/// lookup.
const ACCOUNT_WITH_PASSWORD_HASH_COLUMNS: [&str; 3] = ["id", "username", "password_hash"];

/// [`AccountSummaryRow`] projection — the `account_verify` /
/// `SessionAccountJson` fields; excludes `password_hash` and the audit
/// columns by construction.
const ACCOUNT_SUMMARY_COLUMNS: [&str; 5] =
    ["id", "username", "email", "email_verified", "created_at"];

/// [`AccountIdentitySnapshot`] projection — what the delete / purge /
/// undelete `RETURNING` clauses read for the audit event.
const ACCOUNT_IDENTITY_SNAPSHOT_COLUMNS: [&str; 2] = ["username", "email"];

/// The [`ACCOUNT_ROW_COLUMNS`] projection on the bare table.
fn account_row_columns() -> String {
    qualify_columns(&ACCOUNT_ROW_COLUMNS, "account", |_| None)
}

/// Decode the [`account_row_columns`] projection positionally.
fn decode_account_row(row: &tokio_postgres::Row) -> AccountRow {
    AccountRow {
        id: row.get(col!(ACCOUNT_ROW_COLUMNS, "id")),
        username: row.get(col!(ACCOUNT_ROW_COLUMNS, "username")),
    }
}

/// The [`ACCOUNT_WITH_PASSWORD_HASH_COLUMNS`] projection on the bare table.
fn account_with_password_hash_columns() -> String {
    qualify_columns(&ACCOUNT_WITH_PASSWORD_HASH_COLUMNS, "account", |_| None)
}

/// Decode the [`account_with_password_hash_columns`] projection positionally.
fn decode_account_with_password_hash_row(row: &tokio_postgres::Row) -> AccountWithPasswordHash {
    AccountWithPasswordHash {
        id: row.get(col!(ACCOUNT_WITH_PASSWORD_HASH_COLUMNS, "id")),
        username: row.get(col!(ACCOUNT_WITH_PASSWORD_HASH_COLUMNS, "username")),
        password_hash: row.get(col!(ACCOUNT_WITH_PASSWORD_HASH_COLUMNS, "password_hash")),
    }
}

/// The [`ACCOUNT_SUMMARY_COLUMNS`] projection on the bare table, with
/// `created_at` as the spine's ISO-8601 wire string.
fn account_summary_columns() -> String {
    qualify_columns(
        &ACCOUNT_SUMMARY_COLUMNS,
        "account",
        iso8601_timestamp_expr(&ACCOUNT_SUMMARY_COLUMNS, &["created_at"], "account"),
    )
}

/// Decode the [`account_summary_columns`] projection positionally.
fn decode_account_summary_row(row: &tokio_postgres::Row) -> AccountSummaryRow {
    AccountSummaryRow {
        id: row.get(col!(ACCOUNT_SUMMARY_COLUMNS, "id")),
        username: row.get(col!(ACCOUNT_SUMMARY_COLUMNS, "username")),
        email: row.get(col!(ACCOUNT_SUMMARY_COLUMNS, "email")),
        email_verified: row.get(col!(ACCOUNT_SUMMARY_COLUMNS, "email_verified")),
        created_at: row.get(col!(ACCOUNT_SUMMARY_COLUMNS, "created_at")),
    }
}

/// The [`ACCOUNT_IDENTITY_SNAPSHOT_COLUMNS`] projection on the bare table.
fn account_identity_snapshot_columns() -> String {
    qualify_columns(&ACCOUNT_IDENTITY_SNAPSHOT_COLUMNS, "account", |_| None)
}

/// Decode the [`account_identity_snapshot_columns`] projection positionally.
/// Shared by the soft-delete / purge / undelete queries, which all return
/// the same two columns.
fn decode_account_identity_snapshot(row: &tokio_postgres::Row) -> AccountIdentitySnapshot {
    AccountIdentitySnapshot {
        username: row.get(col!(ACCOUNT_IDENTITY_SNAPSHOT_COLUMNS, "username")),
        email: row.get(col!(ACCOUNT_IDENTITY_SNAPSHOT_COLUMNS, "email")),
    }
}

/// The [`AdminAccount`] column list — [`ACCOUNT_COLUMNS`] minus the
/// credential and the two actor-provenance columns the admin listing doesn't
/// surface. A literal so [`decode_admin_account_row`] can `col!` into it;
/// the unit test pins it to the `omit_columns` derivation.
const ADMIN_ACCOUNT_COLUMNS: [&str; 8] = [
    "id",
    "username",
    "email",
    "email_verified",
    "created_at",
    "updated_at",
    "updated_by",
    "deleted_at",
];

/// The [`AdminAccount`] projection ([`ADMIN_ACCOUNT_COLUMNS`]), timestamps
/// as ISO-8601 wire strings.
fn admin_account_columns(alias: &str) -> String {
    qualify_columns(
        &ADMIN_ACCOUNT_COLUMNS,
        alias,
        iso8601_timestamp_expr(
            &ADMIN_ACCOUNT_COLUMNS,
            &["created_at", "updated_at", "deleted_at"],
            alias,
        ),
    )
}

/// Decode the [`admin_account_columns`] projection positionally.
fn decode_admin_account_row(row: &tokio_postgres::Row) -> AdminAccount {
    AdminAccount {
        id: row.get(col!(ADMIN_ACCOUNT_COLUMNS, "id")),
        username: row.get(col!(ADMIN_ACCOUNT_COLUMNS, "username")),
        email: row.get(col!(ADMIN_ACCOUNT_COLUMNS, "email")),
        email_verified: row.get(col!(ADMIN_ACCOUNT_COLUMNS, "email_verified")),
        created_at: row.get(col!(ADMIN_ACCOUNT_COLUMNS, "created_at")),
        updated_at: row.get(col!(ADMIN_ACCOUNT_COLUMNS, "updated_at")),
        updated_by: row.get(col!(ADMIN_ACCOUNT_COLUMNS, "updated_by")),
        deleted_at: row.get(col!(ADMIN_ACCOUNT_COLUMNS, "deleted_at")),
    }
}

/// Wire-shape admin-facing account row — mirrors TS `AdminAccountJson`.
///
/// Extends the session-account fields with `updated_at` / `updated_by`
/// audit metadata that admins use for "last modified" UX. Timestamps
/// are ISO-8601 strings for cross-impl parity with the TS reference.
#[derive(Debug, Clone, Serialize)]
pub struct AdminAccount {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub created_at: String,
    pub updated_at: String,
    pub updated_by: Option<uuid::Uuid>,
    /// Soft-delete tombstone (ISO-8601), non-null when the account is
    /// deleted. Surfaced so the admin UI can mark tombstoned rows in the
    /// `include_deleted` listing. Mirrors TS `AdminAccountJson.deleted_at`.
    pub deleted_at: Option<String>,
}

/// Actor summary returned inside an admin account listing entry —
/// mirrors TS `ActorSummaryJson`.
///
/// v1 surfaces a single actor per
/// account (1:1 today; multi-actor lands when an `account_actor_list`
/// RPC ships).
#[derive(Debug, Clone, Serialize)]
pub struct ActorSummary {
    pub id: uuid::Uuid,
    pub name: String,
}

/// Active `role_grant` summary inside an admin account listing entry —
/// mirrors TS `RoleGrantSummaryJson`. Filtered to non-revoked, non-
/// expired grants only.
#[derive(Debug, Clone, Serialize)]
pub struct RoleGrantSummary {
    pub id: uuid::Uuid,
    pub role: String,
    pub scope_kind: Option<String>,
    pub scope_id: Option<uuid::Uuid>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub granted_by: Option<uuid::Uuid>,
}

/// Pending `role_grant` offer summary inside an admin account listing
/// entry — mirrors TS `PendingOfferSummaryJson`.
///
/// Deliberately narrower
/// than the offer-specific RPC surface: omits `message` and
/// `decline_reason` so cross-admin visibility of the listing doesn't
/// expose grantor-authored text that the audit log also withholds.
/// `from_username` is server-resolved so the admin UI can name the
/// blocking offer at a glance.
#[derive(Debug, Clone, Serialize)]
pub struct PendingOfferSummary {
    pub id: uuid::Uuid,
    pub role: String,
    pub scope_kind: Option<String>,
    pub scope_id: Option<uuid::Uuid>,
    pub from_actor_id: uuid::Uuid,
    pub from_username: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Top-level admin account listing entry — mirrors TS
/// `AdminAccountEntryJson`. One entry per account in the page.
#[derive(Debug, Clone, Serialize)]
pub struct AdminAccountEntry {
    pub account: AdminAccount,
    pub actor: Option<ActorSummary>,
    pub role_grants: Vec<RoleGrantSummary>,
    pub pending_offers: Vec<PendingOfferSummary>,
}

/// Look up an **active** account by id (`deleted_at IS NULL`).
///
/// This is the auth-resolution workhorse (session / bearer / keeper
/// resolve) and the admin-target lookup, so it deliberately excludes
/// soft-deleted accounts: a tombstoned account must not authenticate
/// (delete = soft, purge = hard). Purge, which must operate on
/// soft-deleted rows too, uses [`query_purge_account`] directly rather
/// than this check.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_by_id(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Option<AccountRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM account WHERE id = $1 AND deleted_at IS NULL",
        columns = account_row_columns(),
    );
    let row = client.query_opt(&sql, &[account_id]).await?;
    Ok(row.map(|r| decode_account_row(&r)))
}

/// Load the client-safe account summary for `account_verify`.
///
/// Returns `SessionAccountJson`-shaped fields. Excludes `password_hash`
/// and audit columns.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_summary(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Option<AccountSummaryRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM account WHERE id = $1",
        columns = account_summary_columns(),
    );
    let row = client.query_opt(&sql, &[account_id]).await?;
    Ok(row.map(|r| decode_account_summary_row(&r)))
}

/// Look up an account by username (case-insensitive).
///
/// Existence-check companion to [`query_account_with_password_hash`] —
/// returns only the `id` + `username` projection. Used by
/// `invite_create` to reject pre-existing-account collisions before
/// the INSERT. Mirrors `fuz_app`'s `query_account_by_username`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_by_username(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    username: &str,
) -> Result<Option<AccountRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM account WHERE LOWER(username) = LOWER($1)",
        columns = account_row_columns(),
    );
    let row = client.query_opt(&sql, &[&username]).await?;
    Ok(row.map(|r| decode_account_row(&r)))
}

/// Look up an account by email (case-insensitive).
///
/// Sibling to [`query_account_by_username`]. Used by `invite_create` to
/// reject pre-existing-account email collisions. Mirrors `fuz_app`'s
/// `query_account_by_email`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_by_email(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    email: &str,
) -> Result<Option<AccountRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM account WHERE LOWER(email) = LOWER($1)",
        columns = account_row_columns(),
    );
    let row = client.query_opt(&sql, &[&email]).await?;
    Ok(row.map(|r| decode_account_row(&r)))
}

/// Look up an active account by username **or** email (case-insensitive)
/// with password hash — the login lookup, supporting a single login field
/// that accepts either identifier.
///
/// Mirrors `fuz_app`'s `query_account_by_username_or_email`. That TS helper
/// reads username and email separately and `??`-combines them (email-first
/// when the input contains `@`, username-first otherwise); a single `OR`
/// query is observably equivalent because the two value-spaces are disjoint
/// on `@` — the `Username` creation regex forbids `@`, so a username never
/// looks like an email, and an email always contains one. At most one row
/// can therefore match either identifier, so the combiner's lookup order
/// never changes the result.
///
/// Excludes soft-deleted accounts (`deleted_at IS NULL`): a tombstoned
/// account must not authenticate.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_with_password_hash(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    username_or_email: &str,
) -> Result<Option<AccountWithPasswordHash>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM account
         WHERE (LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1))
           AND deleted_at IS NULL",
        columns = account_with_password_hash_columns(),
    );
    let row = client.query_opt(&sql, &[&username_or_email]).await?;
    Ok(row.map(|r| decode_account_with_password_hash_row(&r)))
}

/// Look up an account by id with password hash.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_with_password_hash_by_id(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Option<AccountWithPasswordHash>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM account WHERE id = $1",
        columns = account_with_password_hash_columns(),
    );
    let row = client.query_opt(&sql, &[account_id]).await?;
    Ok(row.map(|r| decode_account_with_password_hash_row(&r)))
}

/// Create an account and return the row.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_create_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    username: &str,
    password_hash: &str,
) -> Result<AccountRow, tokio_postgres::Error> {
    let sql = format!(
        "INSERT INTO account (username, password_hash) VALUES ($1, $2)
         RETURNING {columns}",
        columns = account_row_columns(),
    );
    let row = client.query_one(&sql, &[&username, &password_hash]).await?;
    Ok(decode_account_row(&row))
}

/// Create an account + its single actor inside the same transaction.
///
/// Mirrors `fuz_app`'s `query_create_account_with_actor`. v1 mints
/// exactly one actor per account, naming it after the username. Email
/// is optional; when supplied it lands on the `account` row and the
/// case-insensitive partial unique on `LOWER(email)` enforces
/// uniqueness across unclaimed accounts.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client. The
/// signup handler classifies `is_pg_unique_violation` as
/// [`SignupErrorKind::SignupConflict`](crate::error::SignupErrorKind).
pub async fn query_create_account_with_actor(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    username: &str,
    password_hash: &str,
    email: Option<&str>,
) -> Result<(AccountRow, crate::actor_schema::ActorRow), tokio_postgres::Error> {
    let sql = format!(
        "INSERT INTO account (username, password_hash, email)
         VALUES ($1, $2, $3)
         RETURNING {columns}",
        columns = account_row_columns(),
    );
    let row = client
        .query_one(&sql, &[&username, &password_hash, &email])
        .await?;
    let account = decode_account_row(&row);

    let actor = crate::actor_queries::query_create_actor(client, &account.id, username).await?;

    Ok((account, actor))
}

/// Update an account's password hash conditional on the current hash.
///
/// Returns `true` when the row was updated, `false` when `expected_hash`
/// no longer matched (concurrent change won the race). Closes the
/// verify-write race per `fuz_app`'s
/// `query_update_account_password`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_update_account_password(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    new_password_hash: &str,
    expected_hash: &str,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "UPDATE account SET password_hash = $1, updated_at = NOW()
             WHERE id = $2 AND password_hash = $3 RETURNING id",
            &[&new_password_hash, account_id, &expected_hash],
        )
        .await?;
    Ok(row.is_some())
}

/// Identifying values snapshotted into a deletion/purge audit event so
/// the identity behind a now-orphaned `audit_log` id isn't lost. Mirrors
/// the TS `account_delete` / `account_purge` metadata snapshot.
#[derive(Debug, Clone)]
pub struct AccountIdentitySnapshot {
    pub username: String,
    pub email: Option<String>,
}

/// Soft-delete an account (the reversible tombstone — `delete = soft`).
///
/// Stamps `deleted_at` + `deleted_by` (the initiator's actor) on the active
/// row — paired like `role_grant`'s `revoked_at` / `revoked_by`, leaving
/// `updated_at` / `updated_by` untouched (deletion isn't a content edit).
/// Returns the identity snapshot for the `account_delete` audit event, or
/// `None` when no active row matched (missing or already soft-deleted).
/// Sessions/tokens are revoked by the caller; auth resolution
/// ([`query_account_by_id`]) already excludes soft-deleted accounts.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_soft_delete(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    deleted_by: Option<&uuid::Uuid>,
) -> Result<Option<AccountIdentitySnapshot>, tokio_postgres::Error> {
    let sql = format!(
        "UPDATE account SET deleted_at = NOW(), deleted_by = $2
         WHERE id = $1 AND deleted_at IS NULL
         RETURNING {columns}",
        columns = account_identity_snapshot_columns(),
    );
    let row = client.query_opt(&sql, &[account_id, &deleted_by]).await?;
    Ok(row.map(|r| decode_account_identity_snapshot(&r)))
}

/// Hard-purge an account (irreversible cascading removal — `purge = hard`).
///
/// Physically deletes the row, cascading to actor / `role_grant` /
/// `auth_session` / `api_token` (FK `ON DELETE CASCADE`). Operates on active
/// OR already-soft-deleted rows. Returns the identity snapshot for the
/// `account_purge` audit event, or `None` when no row matched. The
/// `audit_log` identity columns carry no FK, so the purged id survives on
/// historical rows for forensic correlation back to the purge event.
///
/// **Keeper-gated, loud, irreversible** — callers must restrict this to
/// the keeper credential and confirm explicitly. The `query_purge_*`
/// name flags the danger at every call site.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_purge_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Option<AccountIdentitySnapshot>, tokio_postgres::Error> {
    let sql = format!(
        "DELETE FROM account WHERE id = $1 RETURNING {columns}",
        columns = account_identity_snapshot_columns(),
    );
    let row = client.query_opt(&sql, &[account_id]).await?;
    Ok(row.map(|r| decode_account_identity_snapshot(&r)))
}

/// Reactivate a soft-deleted account — clears the `deleted_at` /
/// `deleted_by` tombstone (the inverse of `query_account_soft_delete`).
///
/// Operates only on a currently soft-deleted row (`deleted_at IS NOT
/// NULL`) and returns the identity snapshot for the `account_undelete`
/// audit event, or `None` when no soft-deleted row matched (missing or
/// already active). Does **not** restore revoked sessions/tokens — the
/// account is live again but its principals re-auth fresh.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_undelete(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Option<AccountIdentitySnapshot>, tokio_postgres::Error> {
    let sql = format!(
        "UPDATE account SET deleted_at = NULL, deleted_by = NULL
         WHERE id = $1 AND deleted_at IS NOT NULL
         RETURNING {columns}",
        columns = account_identity_snapshot_columns(),
    );
    let row = client.query_opt(&sql, &[account_id]).await?;
    Ok(row.map(|r| decode_account_identity_snapshot(&r)))
}

/// The [`PendingOfferSummary`] projection over the `po`-aliased
/// `role_grant_offer` JOIN — a positive hand-spelled subset of
/// `ROLE_GRANT_OFFER_COLUMNS` plus the grantor's username, kept explicit
/// rather than derived (eight omissions would obscure what the listing
/// carries; mirrors TS `PendingOfferRow`). Decoded positionally by
/// [`decode_pending_offer_row`], which also returns the recipient
/// `to_account_id` the caller groups by.
fn pending_offer_columns() -> String {
    format!(
        "po.id, po.to_account_id, po.from_actor_id, po.role, po.scope_kind, po.scope_id,
         {created_at}, {expires_at}, a.username AS from_username",
        created_at = iso8601_timestamp_column("po", "created_at"),
        expires_at = iso8601_timestamp_column("po", "expires_at"),
    )
}

/// Decode the [`pending_offer_columns`] projection positionally into
/// `(to_account_id, summary)`.
fn decode_pending_offer_row(row: &tokio_postgres::Row) -> (uuid::Uuid, PendingOfferSummary) {
    (
        row.get(1),
        PendingOfferSummary {
            id: row.get(0),
            from_actor_id: row.get(2),
            role: row.get(3),
            scope_kind: row.get(4),
            scope_id: row.get(5),
            created_at: row.get(6),
            expires_at: row.get(7),
            from_username: row.get(8),
        },
    )
}

/// List accounts with their actors, active `role_grants`, and pending
/// inbound `role_grant` offers for admin display. Mirrors `fuz_app`'s
/// `query_admin_account_list`.
///
/// Sequential four-query fan-out: account page → actors batch →
/// `role_grants` batch → `pending_offers` batch. The TS reference runs the
/// last three in parallel via `Promise.all` against a pool; the Rust
/// signature takes a single `GenericClient` (sibling to every other
/// query in this module) so they run sequentially on one connection.
/// PG round-trip cost is the dominant factor either way; the parallel
/// shape isn't part of the wire contract.
///
/// Every list is ordered as the twin orders it, on data keys rather than the
/// random `id` alone: accounts by `created_at, username`, each entry's
/// `role_grants` by `created_at, role, scope_id`, its `pending_offers` by
/// `expires_at, role, scope_id` (`id` last, for a tie no data key breaks).
/// The order is deterministic on each engine, so rows written in one
/// transaction (one `created_at`) list stably. Two backends holding the same
/// rows list them alike only under the same text collation: a locale one
/// (Postgres `en_US.UTF-8`, which passes over `_` and `-` at first) and a
/// bytewise compare (pglet, under the twin) can order the text keys differently.
///
/// `actor_by_account` indexes by `account_id`, keeping each account's oldest
/// actor (`created_at, name, id`) — this mirrors the "Multi-actor TODO" note in the
/// TS twin's `query_admin_account_list` (`auth/account_queries.ts`): when a
/// single account hosts more than one actor, the entry shows only that one.
/// The admin row shape will need to change to "account → `Vec<Actor>`"
/// at that time.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_admin_account_list(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    limit: i64,
    offset: i64,
    include_deleted: bool,
) -> Result<Vec<AdminAccountEntry>, tokio_postgres::Error> {
    // Active-only by default; the admin UI's "show deleted" view passes
    // `include_deleted` to surface tombstoned rows for reactivation.
    let where_clause = if include_deleted {
        ""
    } else {
        "WHERE deleted_at IS NULL"
    };
    let account_sql = format!(
        "SELECT {columns}
         FROM account
         {where_clause}
         ORDER BY created_at ASC, username ASC
         LIMIT $1 OFFSET $2",
        columns = admin_account_columns("account"),
    );
    let account_rows = client
        .query(account_sql.as_str(), &[&limit, &offset])
        .await?;
    if account_rows.is_empty() {
        return Ok(Vec::new());
    }
    let accounts: Vec<AdminAccount> = account_rows.iter().map(decode_admin_account_row).collect();
    let account_ids: Vec<uuid::Uuid> = accounts.iter().map(|a| a.id).collect();

    let actor_rows = crate::actor_queries::query_actors_for_accounts(client, &account_ids).await?;

    let role_grant_sql = format!(
        "SELECT {columns}
         FROM role_grant
         WHERE actor_id IN (SELECT id FROM actor WHERE account_id = ANY($1::uuid[]))
           AND {active}
         ORDER BY created_at ASC, role ASC, scope_id ASC, id ASC",
        columns = crate::actor_queries::role_grant_summary_columns("role_grant"),
        active = crate::role_grant_active_sql("role_grant"),
    );
    let role_grant_rows = client
        .query(role_grant_sql.as_str(), &[&account_ids])
        .await?;

    let offer_sql = format!(
        "SELECT {columns}
         FROM role_grant_offer po
         JOIN actor act ON act.id = po.from_actor_id
         JOIN account a ON a.id = act.account_id
         WHERE po.to_account_id = ANY($1::uuid[])
           AND po.accepted_at IS NULL
           AND po.declined_at IS NULL
           AND po.retracted_at IS NULL
           AND po.superseded_at IS NULL
           AND po.expires_at > NOW()
         ORDER BY po.expires_at ASC, po.role ASC, po.scope_id ASC, po.id ASC",
        columns = pending_offer_columns(),
    );
    let offer_rows = client.query(offer_sql.as_str(), &[&account_ids]).await?;

    // the first actor wins: the rows arrive `created_at, name, id`, so an account's
    // entry carries its oldest actor (and that actor's grants), as the twin's does
    let mut actor_by_account: HashMap<uuid::Uuid, ActorSummary> = HashMap::new();
    for actor in actor_rows {
        actor_by_account
            .entry(actor.account_id)
            .or_insert(ActorSummary {
                id: actor.id,
                name: actor.name,
            });
    }

    let mut role_grants_by_actor: HashMap<uuid::Uuid, Vec<RoleGrantSummary>> = HashMap::new();
    for row in &role_grant_rows {
        let (actor_id, summary) = crate::actor_queries::decode_role_grant_summary_row(row);
        role_grants_by_actor
            .entry(actor_id)
            .or_default()
            .push(summary);
    }

    let mut offers_by_account: HashMap<uuid::Uuid, Vec<PendingOfferSummary>> = HashMap::new();
    for row in &offer_rows {
        let (to_account_id, summary) = decode_pending_offer_row(row);
        offers_by_account
            .entry(to_account_id)
            .or_default()
            .push(summary);
    }

    Ok(accounts
        .into_iter()
        .map(|account| {
            let actor = actor_by_account.remove(&account.id);
            let role_grants = actor
                .as_ref()
                .and_then(|a| role_grants_by_actor.remove(&a.id))
                .unwrap_or_default();
            let pending_offers = offers_by_account.remove(&account.id).unwrap_or_default();
            AdminAccountEntry {
                account,
                actor,
                role_grants,
                pending_offers,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_db::columns_not_in;
    use fuz_db::omit_columns;

    #[test]
    fn shape_projections_are_subsets_of_the_table() {
        for shape in [
            &ACCOUNT_ROW_COLUMNS[..],
            &ACCOUNT_WITH_PASSWORD_HASH_COLUMNS[..],
            &ACCOUNT_SUMMARY_COLUMNS[..],
            &ACCOUNT_IDENTITY_SNAPSHOT_COLUMNS[..],
        ] {
            let strays = columns_not_in(shape, &ACCOUNT_COLUMNS);
            assert!(
                strays.is_empty(),
                "{shape:?}: not in ACCOUNT_COLUMNS: {strays:?}"
            );
        }
    }

    #[test]
    fn admin_account_columns_pin_to_the_derivation() {
        assert_eq!(
            ADMIN_ACCOUNT_COLUMNS.to_vec(),
            omit_columns(
                &ACCOUNT_COLUMNS,
                &["password_hash", "created_by", "deleted_by"]
            )
        );
    }

    #[test]
    fn admin_account_columns_follows_the_const_order() {
        assert_eq!(
            admin_account_columns("account"),
            format!(
                "account.id, account.username, account.email, account.email_verified, {}, {}, account.updated_by, {}",
                iso8601_timestamp_column("account", "created_at"),
                iso8601_timestamp_column("account", "updated_at"),
                iso8601_timestamp_column("account", "deleted_at"),
            )
        );
    }
}
