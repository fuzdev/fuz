//! Queries against the `invite` table.
//!
//! Mirrors `fuz_app`'s `auth/invite_queries.ts`. Ships the two queries
//! the signup handler needs (the FOR UPDATE match-finder + the unscoped
//! claim) plus the admin CRUD set (`query_create_invite`,
//! `query_invite_list_all_with_usernames`, `query_invite_delete_unclaimed`)
//! that backs the `invite_*` admin RPC actions.

use serde::Serialize;

use fuz_db::{col, is_pg_unique_violation, iso8601_timestamp_expr, qualify_columns};

use crate::account_queries::query_account_lock_live_many;

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

/// Why [`query_create_invite`] created no invite.
#[derive(Debug, thiserror::Error)]
pub enum InviteCreateError {
    /// An unclaimed invite already reserves the email or the username: the
    /// partial unique index `idx_invite_email_unclaimed` or
    /// `idx_invite_username_unclaimed` refused the insert (SQLSTATE `23505`),
    /// which aborts the caller's transaction. Twin of TS
    /// `InviteDuplicateError`.
    #[error("an unclaimed invite already exists")]
    Duplicate,
    /// The issuer is not an active account: its actor is missing or
    /// tombstoned, or its account soft-deleted — a delete that committed
    /// while the invite was in flight. Twin of TS
    /// `InviteIssuerNotActiveError`.
    #[error("the issuer is not an active account")]
    IssuerNotActive,
    /// Tx-level driver failure.
    #[error("query error: {0}")]
    Query(#[from] tokio_postgres::Error),
}

/// Insert an invite issued by the actor `created_by` and return the created
/// row.
///
/// The issuer must be an active actor of a live account, checked here so every
/// caller — the spine's `invite_create` handler and a consumer minting invites
/// on its own path — gets the rule: an invite records no authority, so one
/// minted for an issuer deleted mid-flight would outlive the delete that
/// should have voided it. The issuer's account row is read under `FOR SHARE`
/// ([`query_account_lock_live_many`]) before the insert: an account delete
/// writes its tombstone first, so a delete that wrote its tombstone before the
/// read is waited for if uncommitted and seen (the invite is refused), and one
/// that reaches the row after it waits for this
/// transaction to commit and then deletes the invite with the account's other
/// unclaimed ones ([`query_invite_delete_unclaimed_by_creators`]). The actor's
/// tombstone is read after the lock, so a delete waited on is seen there too.
///
/// Run it inside the caller's transaction, which the lock spans — on a bare
/// client the lock ends with its statement and orders nothing. Lock order:
/// account rows come before actor and `role_grant` rows, as the last-admin
/// guard
/// ([`crate::actor_queries::query_count_active_accounts_with_global_role_locked`])
/// takes them (account, then actor, then grant). So take it before the
/// transaction locks any actor or `role_grant` row — or lock the issuer's
/// account row first yourself ([`query_account_lock_live_many`]), which this
/// query then re-takes without waiting: a transaction holding a lock on the
/// issuer's admin grant while it waits here on an account row a removal holds,
/// while the removal's guard waits on that grant, deadlocks.
///
/// Callers that pre-check for account collisions on `email` / `username` do
/// so upstream. Mirrors `fuz_app`'s `query_create_invite`.
///
/// # Errors
///
/// [`InviteCreateError::IssuerNotActive`] when `created_by` names no actor, a
/// tombstoned one, or one whose account is soft-deleted; nothing is inserted.
/// [`InviteCreateError::Duplicate`] when an unclaimed invite with the same
/// email or username already exists.
/// [`InviteCreateError::Query`] on any other driver error.
pub async fn query_create_invite(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    email: Option<&str>,
    username: Option<&str>,
    created_by: &uuid::Uuid,
) -> Result<Invite, InviteCreateError> {
    // An actor's account never changes, so it is read unlocked.
    let Some(issuer_account) = client
        .query_opt("SELECT account_id FROM actor WHERE id = $1", &[created_by])
        .await?
        .map(|row| row.get::<_, uuid::Uuid>(0))
    else {
        return Err(InviteCreateError::IssuerNotActive);
    };
    if !query_account_lock_live_many(client, &[issuer_account])
        .await?
        .contains(&issuer_account)
    {
        return Err(InviteCreateError::IssuerNotActive);
    }
    // After the lock, so a delete it waited on is seen.
    let issuer_actor_active = client
        .query_opt(
            "SELECT id FROM actor WHERE id = $1 AND deleted_at IS NULL",
            &[created_by],
        )
        .await?
        .is_some();
    if !issuer_actor_active {
        return Err(InviteCreateError::IssuerNotActive);
    }
    match client
        .query_one(&sql_create_invite(), &[&email, &username, created_by])
        .await
    {
        Ok(row) => Ok(decode_invite_row(&row)),
        Err(err) if is_pg_unique_violation(&err) => Err(InviteCreateError::Duplicate),
        Err(err) => Err(err.into()),
    }
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

/// Delete every unclaimed invite issued by one of `created_by_actor_ids` —
/// the invite cascade of an account delete or purge.
///
/// An invite records no authority, so one outliving its issuer's account
/// would still admit a signup. Deleting is how an invite is revoked
/// ([`query_invite_delete_unclaimed`]), so a voided invite answers a signup
/// as a revoked or unknown one does, and an undelete has nothing to bring
/// back. A claimed invite stays, as the record of the signup it admitted.
/// Returns the deleted invites' ids. Mirrors `fuz_app`'s
/// `query_invite_delete_unclaimed_by_creators`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_invite_delete_unclaimed_by_creators(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    created_by_actor_ids: &[uuid::Uuid],
) -> Result<Vec<uuid::Uuid>, tokio_postgres::Error> {
    if created_by_actor_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = client
        .query(
            "DELETE FROM invite
             WHERE created_by = ANY($1::uuid[]) AND claimed_at IS NULL
             RETURNING id",
            &[&created_by_actor_ids],
        )
        .await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
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
