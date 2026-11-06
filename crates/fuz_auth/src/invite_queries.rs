//! Queries against the `invite` table.
//!
//! Mirrors `fuz_app`'s `auth/invite_queries.ts`. Ships the two queries
//! the signup handler needs (the FOR UPDATE match-finder + the unscoped
//! claim) plus the admin CRUD set (`query_create_invite`,
//! `query_invite_list_all_with_usernames`, `query_invite_delete_unclaimed`)
//! that backs the `invite_*` admin RPC actions.

use serde::Serialize;

use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};

/// The `invite` table's columns.
///
/// Twin of `fuz_app`'s `INVITE_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live
/// column.
pub const INVITE_COLUMNS: [&str; 7] = [
    "id",
    "email",
    "username",
    "claimed_by",
    "claimed_at",
    "created_at",
    "created_by",
];

/// Locked invite id returned by the FOR UPDATE finder.
///
/// Signup only needs the invite id (for audit metadata + the follow-up
/// claim); the admin CRUD path uses [`Invite`] / [`InviteWithUsernames`]
/// for the wider projection.
#[derive(Debug, Clone, Copy)]
pub struct LockedInvite {
    pub id: uuid::Uuid,
}

/// Wire-shape invite row — mirrors `fuz_app`'s `InviteJson`.
///
/// Timestamp columns are serialized as ISO-8601 strings so the wire
/// format matches the TS impl byte-for-byte through cross-process
/// suites. `claimed_by` and `created_by` carry FK ids verbatim; the
/// referenced rows can be soft-deleted (`ON DELETE SET NULL` on both
/// FKs), so consumers must treat a non-null id as a stable
/// historical pointer, not a guarantee that the referenced row is
/// still resolvable. The `InviteWithUsernames` companion is the
/// resolved-name path that LEFT-JOINs through and returns nulls for
/// dangling refs.
#[derive(Debug, Clone, Serialize)]
pub struct Invite {
    pub id: uuid::Uuid,
    pub email: Option<String>,
    pub username: Option<String>,
    pub claimed_by: Option<uuid::Uuid>,
    pub claimed_at: Option<String>,
    pub created_at: String,
    pub created_by: Option<uuid::Uuid>,
}

/// Invite row enriched with LEFT-JOINed creator/claimer usernames —
/// mirrors `fuz_app`'s `InviteWithUsernamesJson`.
///
/// Both join targets are
/// nullable: `created_by_username` is null when the creating actor was
/// soft-deleted (`ON DELETE SET NULL` on the FK); `claimed_by_username`
/// is null for unclaimed invites.
#[derive(Debug, Clone, Serialize)]
pub struct InviteWithUsernames {
    #[serde(flatten)]
    pub invite: Invite,
    pub created_by_username: Option<String>,
    pub claimed_by_username: Option<String>,
}

/// The [`Invite`] projection (decoded positionally by [`decode_invite_row`]):
/// [`INVITE_COLUMNS`] qualified by `alias`, with the two timestamps as
/// ISO-8601 wire strings.
fn invite_columns(alias: &str) -> String {
    qualify_columns(
        &INVITE_COLUMNS,
        alias,
        iso8601_timestamp_expr(&INVITE_COLUMNS, &["claimed_at", "created_at"], alias),
    )
}

fn sql_create_invite() -> String {
    format!(
        "INSERT INTO invite (email, username, created_by) VALUES ($1, $2, $3)
         RETURNING {columns}",
        columns = invite_columns("invite"),
    )
}

fn sql_list_invites_with_usernames() -> String {
    format!(
        "SELECT {columns},
                act.name AS created_by_username,
                a.username AS claimed_by_username
         FROM invite i
         LEFT JOIN actor act ON act.id = i.created_by
         LEFT JOIN account a ON a.id = i.claimed_by
         ORDER BY i.created_at DESC",
        columns = invite_columns("i"),
    )
}

/// Decode the [`invite_columns`] projection positionally.
fn decode_invite_row(row: &tokio_postgres::Row) -> Invite {
    Invite {
        id: row.get(col!(INVITE_COLUMNS, "id")),
        email: row.get(col!(INVITE_COLUMNS, "email")),
        username: row.get(col!(INVITE_COLUMNS, "username")),
        claimed_by: row.get(col!(INVITE_COLUMNS, "claimed_by")),
        claimed_at: row.get(col!(INVITE_COLUMNS, "claimed_at")),
        created_at: row.get(col!(INVITE_COLUMNS, "created_at")),
        created_by: row.get(col!(INVITE_COLUMNS, "created_by")),
    }
}

/// Insert an invite and return the created row.
///
/// Callers that pre-check for account collisions on `email` /
/// `username` do so upstream — this query returns the row directly and
/// surfaces the partial-unique violation on `idx_invite_email_unclaimed`
/// / `idx_invite_username_unclaimed` as a [`tokio_postgres::Error`]
/// that callers classify via [`fuz_db::is_pg_unique_violation`].
///
/// Mirrors `fuz_app`'s `query_create_invite`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client — in
/// particular SQLSTATE `23505` (`unique_violation`) when an unclaimed
/// invite with the same email or username already exists.
pub async fn query_create_invite(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    email: Option<&str>,
    username: Option<&str>,
    created_by: Option<&uuid::Uuid>,
) -> Result<Invite, tokio_postgres::Error> {
    let row = client
        .query_one(&sql_create_invite(), &[&email, &username, &created_by])
        .await?;
    Ok(decode_invite_row(&row))
}

/// List every invite with creator/claimer usernames joined in, newest
/// first.
///
/// No pagination (matches `fuz_app`'s `query_invite_list_all_with_usernames`).
/// The admin RPC's rate-limit gate is what bounds scraping; when the
/// invite table grows past a few hundred rows, a paginated admin
/// listing replaces this — same approach taken by
/// `admin_account_list`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_invite_list_all_with_usernames(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Vec<InviteWithUsernames>, tokio_postgres::Error> {
    let rows = client
        .query(&sql_list_invites_with_usernames(), &[])
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| InviteWithUsernames {
            invite: decode_invite_row(&row),
            created_by_username: row.get(INVITE_COLUMNS.len()),
            claimed_by_username: row.get(INVITE_COLUMNS.len() + 1),
        })
        .collect())
}

/// Delete an unclaimed invite by id.
///
/// Returns `true` when a row was deleted, `false` when the invite was
/// already claimed or did not exist. The `claimed_at IS NULL` filter
/// is what prevents an admin from undoing a successful signup's invite
/// record — claimed invites stay around as forensic / audit context.
/// Mirrors `fuz_app`'s `query_invite_delete_unclaimed`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_invite_delete_unclaimed(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    invite_id: &uuid::Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "DELETE FROM invite WHERE id = $1 AND claimed_at IS NULL RETURNING id",
            &[invite_id],
        )
        .await?;
    Ok(row.is_some())
}

/// Find an unclaimed invite matching email and/or username, taking a
/// row-level write lock on the matched row.
///
/// Three scoping modes mirror `fuz_app`'s
/// `query_invite_find_unclaimed_match_for_update`:
///
/// - **Email-only invite** (email set, username NULL) → matches only if
///   the signup supplies a matching email.
/// - **Username-only invite** (username set, email NULL) → matches only
///   if the signup supplies a matching username.
/// - **Both-field invite** (both set) → requires BOTH email and username
///   to match.
///
/// Must run inside the signup transaction so `FOR UPDATE` makes find +
/// claim atomic. A concurrent signup matching the same invite blocks on
/// the lock until this transaction commits / rolls back; after commit
/// the loser's `find_for_update` returns no row (winner flipped
/// `claimed_at`) and falls through to `no_match` — no race window.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_invite_find_unclaimed_match_for_update(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    email: Option<&str>,
    username: &str,
) -> Result<Option<LockedInvite>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT id FROM invite WHERE claimed_at IS NULL AND (
                (email IS NOT NULL AND username IS NULL
                 AND $1::text IS NOT NULL AND LOWER(email) = LOWER($1::text))
                OR
                (username IS NOT NULL AND email IS NULL
                 AND LOWER(username) = LOWER($2))
                OR
                (email IS NOT NULL AND username IS NOT NULL
                 AND $1::text IS NOT NULL AND LOWER(email) = LOWER($1::text)
                 AND LOWER(username) = LOWER($2))
             ) ORDER BY created_at ASC, id ASC LIMIT 1
             FOR UPDATE",
            &[&email, &username],
        )
        .await?;

    Ok(row.map(|r| LockedInvite { id: r.get(0) }))
}

/// Claim an invite by setting `claimed_by` and `claimed_at`.
///
/// The `_unscoped` suffix is the safety signal: SQL only checks the row
/// state (`claimed_at IS NULL`), not whether the claiming account's
/// email or username matches the invite. Production scoping is enforced
/// upstream by [`query_invite_find_unclaimed_match_for_update`] running
/// inside the same transaction — the row lock makes find + claim
/// atomic, so skipping the find step would let a caller claim any
/// unclaimed invite by id. Mirrors `query_invite_claim_unscoped` in
/// `fuz_app`'s `auth/invite_queries.ts`.
///
/// Returns `true` when the row was claimed, `false` when the invite was
/// already claimed or did not exist.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_invite_claim_unscoped(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    invite_id: &uuid::Uuid,
    account_id: &uuid::Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "UPDATE invite SET claimed_by = $1, claimed_at = NOW()
             WHERE id = $2 AND claimed_at IS NULL
             RETURNING id",
            &[account_id, invite_id],
        )
        .await?;
    Ok(row.is_some())
}
