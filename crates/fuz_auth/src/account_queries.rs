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

/// Load the client-safe summary of a live account, for `account_verify` and
/// `/status`.
///
/// Returns `SessionAccountJson`-shaped fields. Excludes `password_hash`
/// and audit columns. A tombstoned account reads as gone, as a purged one
/// does: both callers answer an account removed since its credential was read
/// as the dead credential, which is what `fuz_app` answers.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_summary(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Option<AccountSummaryRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM account WHERE id = $1 AND deleted_at IS NULL",
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
/// no longer matched (concurrent change won the race) or the account is
/// tombstoned (a delete committed after the credential leg; a waiting `UPDATE`
/// rereads the row the delete committed). Closes the verify-write race per
/// `fuz_app`'s `query_update_account_password`.
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
             WHERE id = $2 AND password_hash = $3 AND deleted_at IS NULL
             RETURNING id",
            &[&new_password_hash, account_id, &expected_hash],
        )
        .await?;
    Ok(row.is_some())
}

/// Lock an account row for a credential mint, when the account is live and
/// still holds the password hash its authorization verified.
///
/// A login verifies the password outside any transaction, so a password
/// change or an account delete can commit between the verify and the session
/// insert — and revoke "every session" before the new one exists. Run first
/// in the mint's transaction, this read waits on the row lock either writer
/// holds and then rereads the row as they committed it, so the mint is
/// refused when the hash changed or the tombstone landed; and once it holds
/// the lock, either writer waits for the mint to commit and then revokes what
/// it minted. Both writers write the account row before they revoke, which is
/// what makes the lock order them.
///
/// `FOR NO KEY UPDATE`, the strength of their `UPDATE`s, so it also conflicts
/// with itself: the mints of one account take turns. The session cap needs
/// that. A mint inserts its session and evicts the oldest past the cap in one
/// transaction, and two mints running together each count without the
/// other's uncommitted row — both commit above the cap — while their
/// evictions lock the same old rows in orders the query plan picks, and can
/// deadlock. Taken in turn, the second mint runs its statements after the
/// first commits and counts its row. The foreign-key `FOR KEY SHARE` of a row
/// inserted under the account does not conflict with it, so no write that
/// merely references the account waits on a login. Besides the writers it
/// orders against, it conflicts with [`query_account_lock_live`] (the token
/// mint, the same strength), the `FOR SHARE` of
/// [`query_account_lock_live_many`] (an offer, invite or assign create), an offer
/// accept's locks ([`query_account_lock_for_offer_accept`], the recipient's at
/// this strength, a grantor's shared), and the last-admin guard's
/// `FOR NO KEY UPDATE`. None of those waits on an account
/// row while holding a session row, and once a mint holds the lock it waits
/// on nothing but the session rows its eviction deletes, so no cycle runs
/// through it. Twin of `fuz_app`'s `query_account_lock_verified`.
///
/// Returns `true` when the row is locked and current, `false` when it was
/// deleted, tombstoned, or its hash changed.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_lock_verified(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    password_hash: &str,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT id FROM account
             WHERE id = $1 AND deleted_at IS NULL AND password_hash = $2
             FOR NO KEY UPDATE",
            &[account_id, &password_hash],
        )
        .await?;
    Ok(row.is_some())
}

/// The key of the advisory lock every purge takes
/// ([`query_account_purge_advisory_lock`]): the ASCII of `fuz_` and `purg`.
///
/// The two-`int4` form, `pg_advisory_xact_lock(int4, int4)`, a key space apart
/// from the single `bigint` key the migration runner's per-namespace
/// `pg_advisory_lock(bigint)` takes, so no namespace's hash can collide with it.
/// Twin of `fuz_app`'s `ACCOUNT_PURGE_ADVISORY_LOCK_KEY`.
pub const ACCOUNT_PURGE_ADVISORY_LOCK_KEY: (i32, i32) = (0x6675_7a5f, 0x7075_7267);

/// Take, for a purge, the transaction-scoped advisory lock every purge takes,
/// so two purges take turns.
///
/// Two purges' cascades write rows both reach — the offers each account made
/// to the other, accepted and declined as well as pending, and the invites
/// each issued and the other claimed — in whatever order their plans walk
/// them, and no row lock a purge takes ahead of its cascade covers every such
/// row. Held from the purge's first statement, the lock makes a second purge
/// wait before it holds any row. Only purges take it, and a purge takes it
/// holding nothing, so it orders purges against each other and nothing else:
/// every other writer meets a purge at the rows it locks after this — the
/// last-admin guard's (an admin target's only), its account row
/// ([`query_account_lock_for_purge`]), its offers. Released when the
/// transaction ends. Run first in the purge's transaction.
/// Twin of `fuz_app`'s `query_account_purge_advisory_lock`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_purge_advisory_lock(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<(), tokio_postgres::Error> {
    let (class, id) = ACCOUNT_PURGE_ADVISORY_LOCK_KEY;
    client
        .query("SELECT pg_advisory_xact_lock($1, $2)", &[&class, &id])
        .await?;
    Ok(())
}

/// Lock the account row of a revoke's revokee, by its actor, tombstoned or
/// not, `FOR NO KEY UPDATE`.
///
/// Every revoke of a grant takes it, before it locks the offers it supersedes
/// and before it updates the grant. It keeps those offers from growing: an
/// offer to or from the account takes the row `FOR SHARE`
/// ([`query_account_lock_live_many`]), so none is made while the revoke runs,
/// and an accept by the account takes it `FOR NO KEY UPDATE`
/// ([`query_account_lock_for_offer_accept`]), so none claims one. And it is the
/// lock an accept of an offer from the revokee is ordered by: the accept reads
/// its grantor's authority under the grantor's account row, and a revoke of
/// that authority takes the row here whether or not its last-admin guard ran
/// (the guard runs only while the account holds an active global `admin`). A
/// revoke of an admin grant takes it after the guard, which holds it already
/// among the admins' rows in id order. Twin of `fuz_app`'s
/// `query_account_lock_for_revoke`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_lock_for_revoke(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: &uuid::Uuid,
) -> Result<(), tokio_postgres::Error> {
    client
        .query(
            "SELECT a.id FROM actor act JOIN account a ON a.id = act.account_id
             WHERE act.id = $1
             FOR NO KEY UPDATE OF a",
            &[actor_id],
        )
        .await?;
    Ok(())
}

/// Lock an account row for its purge, tombstoned or not.
///
/// Every writer of an account takes the account row before its other rows — a
/// credential mint its lock, a password change or a delete its `UPDATE` — and
/// a purge takes it first as well, ahead of the credential rows its revokes and
/// its cascade delete. A purge reaching the row only at its `DELETE` would hold
/// the account's sessions and tokens while waiting on a writer that holds the
/// row and goes on to those same rows: a login evicting at the cap, a password
/// change or a delete revoking. `FOR UPDATE`, the lock the purge's `DELETE`
/// takes anyway: it conflicts with every other lock on the row, so a writer
/// holding one is waited out, and a writer arriving later waits for the purge
/// and then finds no row. No `deleted_at` filter — a purge removes a
/// tombstoned account too. Run after [`query_account_purge_advisory_lock`] and,
/// for an admin target, the last-admin guard, which takes the row
/// `FOR NO KEY UPDATE` among every admin's in id order, so for an admin this
/// only strengthens a lock the purge already holds. The guards run again
/// after it: they read whether the target is an admin unlocked, and a
/// non-admin target's row is the first the purge holds of it, so an accept
/// making it an admin commits before this lock is granted. Twin of `fuz_app`'s
/// `query_account_lock_for_purge`.
///
/// Returns `true` when the row is locked, `false` when there is no such
/// account.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_lock_for_purge(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT id FROM account WHERE id = $1 FOR UPDATE",
            &[account_id],
        )
        .await?;
    Ok(row.is_some())
}

/// Lock a live account row for a credential mint authorized by a credential
/// the account already holds (`account_token_create`).
///
/// The request's credential was resolved outside the mint's transaction, so
/// an account delete can commit between that read and the insert, revoking
/// every token before the new one exists. Run first in the mint's
/// transaction, this read waits on the delete's row lock and then sees its
/// tombstone; once it holds the lock, a delete waits for the mint to commit
/// and then revokes the token. The password is not re-checked: the mint
/// verified none. Taken `FOR NO KEY UPDATE` for the token cap, as the
/// login's lock is for the session cap — [`query_account_lock_verified`] has
/// why, and what it conflicts with; a token mint and a login of one account
/// take turns too. A write that only needs ordering against a delete takes
/// [`query_account_lock_live_many`], which lets such writes run together. A
/// delete takes it too, after its last-admin guard and before the guards'
/// second pass (`handle_account_delete`): the guard reads whether the target
/// is an admin unlocked. And `self_service_role_set` takes it first, so a
/// toggle is refused on a removed account, or a removal waits for it. Twin of
/// `fuz_app`'s `query_account_lock_live`.
///
/// Returns `true` when the row is locked and not tombstoned, `false` when it
/// was deleted or tombstoned.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_lock_live(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT id FROM account WHERE id = $1 AND deleted_at IS NULL FOR NO KEY UPDATE",
            &[account_id],
        )
        .await?;
    Ok(row.is_some())
}

/// Lock live account rows in one statement, in id order, for a write that
/// must be ordered against a delete of any of them.
///
/// An offer locks its two parties ([`crate::query_role_grant_offer_create`]),
/// an invite its issuer ([`crate::query_create_invite`], one id), a
/// `role_grant_assign` its recipient and its caller
/// ([`crate::RoleGrantOfferActionSpecs`]).
///
/// `FOR SHARE`: the weakest lock that conflicts with a delete's `UPDATE` of
/// the row, so these writes don't wait on one another. It also waits on a
/// credential mint's `FOR NO KEY UPDATE` ([`query_account_lock_verified`]),
/// and a mint waits on it — but a mint holding its lock waits on no row these
/// writes hold.
///
/// The rows are locked as the sort returns them, so every caller takes them in
/// id order, as the last-admin guard
/// ([`crate::actor_queries::query_count_active_accounts_with_global_role_locked`])
/// takes its account rows: two transactions locking two of the same accounts
/// never wait on each other in opposite orders. Taken one statement per
/// account, an offer between two admins could hold one party's row while the
/// guard held the other's, each waiting on the other. Ids never change, so the
/// sort key a concurrent update could move is not one of them. As with
/// [`query_account_lock_live`], a delete committed before the read is waited
/// for and its tombstone seen; one after it waits for the caller's commit.
/// Twin of `fuz_app`'s `query_account_lock_live_many`.
///
/// Returns the ids locked: those of the accounts neither deleted nor
/// tombstoned.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_lock_live_many(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_ids: &[uuid::Uuid],
) -> Result<std::collections::HashSet<uuid::Uuid>, tokio_postgres::Error> {
    if account_ids.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let rows = client
        .query(
            "SELECT id FROM account WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL ORDER BY id FOR SHARE",
            &[&account_ids],
        )
        .await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// Lock the account rows an offer accept is ordered by, in id order.
///
/// The recipient's `FOR NO KEY UPDATE`, and — when the offer confers the
/// global `admin` its grantor must still hold — the grantor's `FOR SHARE`.
///
/// The recipient's lock is a credential mint's strength
/// ([`query_account_lock_verified`]), so it conflicts with itself: two
/// accepts by one recipient take turns, and the second claims after the first
/// has superseded its siblings. It conflicts with a delete's or a purge's
/// first write of the account (the soft-delete `UPDATE`,
/// [`query_account_lock_for_purge`], the last-admin guard), so a removal
/// of the recipient waits here or is waited for whole, and never meets the
/// accept at its offers or its actor; with a revoke's
/// [`query_account_lock_for_revoke`], so a revoke of the recipient's grant and
/// the accept take turns; and with [`query_account_lock_live_many`], so no
/// offer to the recipient is made or refreshed while the accept holds it.
/// Cost: an accept waits behind the recipient's own logins and token mints,
/// which take the same lock.
///
/// The grantor's share lock is what the grantor's authority is read under (an
/// unlocked read after this one): every write that ends a grantor's global
/// `admin` takes the grantor's account row first — a revoke of the grant
/// through [`query_account_lock_for_revoke`] (whether or not its last-admin
/// guard ran), a delete through its write of the row, a purge through the
/// last-admin guard and [`query_account_lock_for_purge`] — so it either commits
/// before the read, which sees it, or waits for the accept to commit. A share
/// lock on the account, not on the grant: every removal takes the account
/// first, so it waits there holding nothing the accept needs.
///
/// Two statements, as the two strengths can't share one locking clause, the
/// lower id first — the order the last-admin guard
/// ([`crate::actor_queries::query_count_active_accounts_with_global_role_locked`])
/// and [`query_account_lock_live_many`] take account rows in — so an accept
/// and a guard over an admin recipient and its grantor never wait on each
/// other in opposite orders. Neither is filtered on the grantor's tombstone:
/// the authority read judges it. Twin of `fuz_app`'s
/// `query_account_lock_for_offer_accept`.
///
/// Returns `true` when the recipient's row is locked and live, `false` when
/// it was deleted or tombstoned.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_lock_for_offer_accept(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    recipient_id: &uuid::Uuid,
    grantor_id: Option<&uuid::Uuid>,
) -> Result<bool, tokio_postgres::Error> {
    const GRANTOR_LOCK: &str = "SELECT id FROM account WHERE id = $1 FOR SHARE";
    if let Some(grantor_id) = grantor_id
        && grantor_id < recipient_id
    {
        client.query_opt(GRANTOR_LOCK, &[grantor_id]).await?;
    }
    let recipient = client
        .query_opt(
            "SELECT id FROM account WHERE id = $1 AND deleted_at IS NULL FOR NO KEY UPDATE",
            &[recipient_id],
        )
        .await?;
    if let Some(grantor_id) = grantor_id
        && grantor_id > recipient_id
    {
        client.query_opt(GRANTOR_LOCK, &[grantor_id]).await?;
    }
    Ok(recipient.is_some())
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
