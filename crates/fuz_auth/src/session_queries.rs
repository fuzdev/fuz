//! Queries against the `auth_session` table, plus the one composite every
//! session-creation site goes through ([`create_capped_session`]).
//!
//! Server-side sessions: blake3 hash of the random token is the primary
//! key (`id`), the raw token never touches the DB. Mirrors `fuz_app`'s
//! `session_queries.ts` (and its `create_session_and_set_cookie`, minus the
//! cookie half — Rust's three creation sites each do their own thing with the
//! returned token).

use serde::Serialize;

use crate::credential_deadline::{EXPIRES_IN_MS_SQL, remaining_from_db_ms};
use crate::hash::hash_session_token;
use crate::session_cookie::generate_session_token;
use crate::session_schema::{AuthSessionRow, SessionListRow};
use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};

/// The `auth_session` table's columns.
///
/// Twin of `fuz_app`'s `AUTH_SESSION_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live
/// column.
pub const AUTH_SESSION_COLUMNS: [&str; 4] = ["id", "account_id", "created_at", "expires_at"];

/// The [`AdminSession`] projection — [`AUTH_SESSION_COLUMNS`] qualified by
/// `alias` with the timestamps as ISO-8601 wire strings; the admin listing
/// appends the joined `username` after it. Decoded positionally by
/// [`decode_admin_session_row`].
fn auth_session_columns(alias: &str) -> String {
    qualify_columns(
        &AUTH_SESSION_COLUMNS,
        alias,
        iso8601_timestamp_expr(&AUTH_SESSION_COLUMNS, &["created_at", "expires_at"], alias),
    )
}

/// Decode [`auth_session_columns`] + the trailing joined `username`
/// positionally.
fn decode_admin_session_row(row: &tokio_postgres::Row) -> AdminSession {
    AdminSession {
        id: row.get(col!(AUTH_SESSION_COLUMNS, "id")),
        account_id: row.get(col!(AUTH_SESSION_COLUMNS, "account_id")),
        created_at: row.get(col!(AUTH_SESSION_COLUMNS, "created_at")),
        expires_at: row.get(col!(AUTH_SESSION_COLUMNS, "expires_at")),
        username: row.get(AUTH_SESSION_COLUMNS.len()),
    }
}

/// The [`SessionListRow`] column list — [`AUTH_SESSION_COLUMNS`] minus
/// `account_id` (the caller scopes by it). A literal so
/// [`decode_session_list_row`] can `col!` into it; the unit test pins it to
/// the `omit_columns` derivation.
const SESSION_LIST_COLUMNS: [&str; 3] = ["id", "created_at", "expires_at"];

/// The [`SessionListRow`] projection ([`SESSION_LIST_COLUMNS`]), timestamps
/// as ISO-8601 wire strings.
fn session_list_columns() -> String {
    qualify_columns(
        &SESSION_LIST_COLUMNS,
        "auth_session",
        iso8601_timestamp_expr(
            &SESSION_LIST_COLUMNS,
            &["created_at", "expires_at"],
            "auth_session",
        ),
    )
}

/// Decode the [`session_list_columns`] projection positionally.
fn decode_session_list_row(row: &tokio_postgres::Row) -> SessionListRow {
    SessionListRow {
        id: row.get(col!(SESSION_LIST_COLUMNS, "id")),
        created_at: row.get(col!(SESSION_LIST_COLUMNS, "created_at")),
        expires_at: row.get(col!(SESSION_LIST_COLUMNS, "expires_at")),
    }
}

/// Hard cap on `admin_session_list` results — mirrors TS
/// `query_session_list_all_active`'s `limit = 200` default.
///
/// No
/// pagination on the wire; an admin with > 200 active sessions
/// across all accounts hits this cap and the admin UI surfaces
/// "showing 200 of N" once that listing wraps. Trigger to lift to
/// offset/limit pagination is a real consumer hitting the cap.
pub const ADMIN_SESSION_LIST_LIMIT: i64 = 200;

/// Per-account concurrent-session cap enforced at every session-creation
/// site. Matches `fuz_app`'s `DEFAULT_MAX_SESSIONS`.
///
/// A `const`, not a field on `AccountRouteState`, for the same reason
/// [`crate::account_action_specs::DEFAULT_MAX_TOKENS`] is one: the struct has
/// no `Default`, so a new field is a breaking change across every exhaustive
/// literal in every consumer workspace, and no consumer overrides the TS
/// twin's value. The TS side keeps the knob (`max_sessions`, `null` =
/// unlimited) because its option struct is partial; both spines ship 5, so
/// the observable behavior converges. Retuning is a one-line edit here plus
/// the TS default.
///
/// 5 is adopted from the TS twin rather than re-derived: it already carries a
/// test matrix and doc claims, and it clears the multi-device stressor that
/// motivated the number (phone + laptop + shared desktop + spare, with room
/// for a second browser profile). Sessions are browser-grain — CLI and
/// machine clients authenticate with API tokens, which have their own
/// [`DEFAULT_MAX_TOKENS`](crate::account_action_specs::DEFAULT_MAX_TOKENS)
/// cap of 10 — so nothing programmatic churns against this bound.
pub const DEFAULT_MAX_SESSIONS: i64 = 5;

/// Wire-shape admin-facing session row — mirrors TS `AdminSessionJson`.
///
/// `AuthSessionJson`'s row fields (`{id, account_id, created_at,
/// expires_at}`, without `is_current`) plus the joined-in `username` so the
/// admin UI can label rows without a follow-up `account_lookup`. `id` is
/// the blake3 hash (`TEXT PRIMARY KEY`), not a UUID — matches TS
/// `AuthSessionJson.id`, a `SessionId` (a branded `Blake3Hash`, 64 lowercase
/// hex digits).
#[derive(Debug, Clone, Serialize)]
pub struct AdminSession {
    pub id: String,
    pub account_id: uuid::Uuid,
    pub created_at: String,
    pub expires_at: String,
    pub username: String,
}

/// Look up a valid (non-expired) session by its token hash, with how long it
/// has left.
///
/// The remaining lifetime is read in the same statement that checks the
/// expiry, on the database clock ([`crate::ResolvedAuth::credential_deadline`]), so it
/// agrees with the check whatever the server's clock says.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_session_get_valid(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_hash: &str,
) -> Result<Option<AuthSessionRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT account_id, {EXPIRES_IN_MS_SQL} FROM auth_session WHERE id = $1 AND expires_at > NOW()"
    );
    let row = client.query_opt(&sql, &[&token_hash]).await?;

    Ok(row.map(|r| AuthSessionRow {
        account_id: r.get(0),
        expires_in: remaining_from_db_ms(r.get(1)),
    }))
}

/// A session minted by [`create_capped_session`]: the raw token for the
/// caller's cookie, and the sessions the cap evicted to make room for it.
///
/// `Debug` redacts the raw token; the evicted ids are hashes and stay visible.
#[must_use = "the evicted sessions' live connections must be closed — see `CappedSession::evicted`"]
pub struct CappedSession {
    /// The raw session token — never stored; its blake3 hash is the row id.
    pub token: String,
    /// The ids (token hashes) of the sessions the cap evicted, as
    /// [`query_session_enforce_limit`] returned them — the keys
    /// [`ConnectionCloseTarget::Session`] closes by. Deleting the
    /// rows does not end the connections they opened: a WebSocket keeps the
    /// authority it resolved at upgrade and an SSE stream never rechecks, so
    /// the caller closes each one once the transaction has committed.
    ///
    /// [`ConnectionCloseTarget::Session`]: crate::ConnectionCloseTarget::Session
    pub evicted: Vec<String>,
}

impl std::fmt::Debug for CappedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CappedSession")
            .field("token", &"<redacted>")
            .field("evicted", &self.evicted)
            .finish()
    }
}

impl CappedSession {
    /// The token of a session minted for an account created in the same
    /// transaction or call — bootstrap, signup, and `_testing_reset`'s seed.
    ///
    /// The cap eviction is structurally a no-op there: the account was just
    /// minted, so this is its only session, and there is no evicted session
    /// whose connections need closing (hence no `ConnectionCloser` at those
    /// sites). Debug builds assert it.
    #[must_use]
    pub fn into_token_for_new_account(self) -> String {
        debug_assert!(
            self.evicted.is_empty(),
            "a session for an account minted in this transaction or call evicted {:?}",
            self.evicted
        );
        self.token
    }
}

/// Mint a session for `account_id` under the per-account cap, returning the
/// raw token for the caller to put in a cookie and the sessions the cap
/// evicted.
///
/// The **only** way production code creates a session — login, bootstrap,
/// signup, and `_testing_reset`'s seed route through here, and the raw INSERT
/// it wraps is module-private. `fuz_testing`'s `mint_session_cookie` and
/// `_testing_mint_session` insert directly, uncapped, on purpose. It exists
/// because the pair it performs must not come apart: an INSERT without the
/// eviction is the missing cap, not a smaller version of it, and a hand-written
/// copy of the pair at each creation site is one chance per site to write the
/// first and forget the second.
///
/// Runs in whatever transaction the caller has open — and the caller **must**
/// have one, since the pair is only atomic inside it. See
/// [`query_session_enforce_limit`] for what that buys and what it doesn't.
/// After that transaction commits, the caller closes the live connections of
/// every [`CappedSession::evicted`] session (login does, through its
/// `ConnectionCloser`); a site that mints for an account created in the same
/// transaction can evict nothing, since no other session can reference it.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn create_capped_session(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<CappedSession, tokio_postgres::Error> {
    let token = generate_session_token();
    let token_hash = hash_session_token(&token);
    query_create_session(client, token_hash.as_str(), account_id).await?;
    let evicted = query_session_enforce_limit(client, account_id, DEFAULT_MAX_SESSIONS).await?;
    Ok(CappedSession { token, evicted })
}

/// Create a new auth session.
///
/// **Private on purpose** — the raw INSERT without the cap is the defect
/// [`create_capped_session`] exists to prevent, so it isn't reachable from
/// outside this module and no production path creates a session that skips
/// the eviction. Make it `pub` again only alongside a caller that has a stated
/// reason to want an uncapped session.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
async fn query_create_session(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_hash: &str,
    account_id: &uuid::Uuid,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "INSERT INTO auth_session (id, account_id, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '30 days')",
            &[&token_hash, account_id],
        )
        .await?;
    Ok(())
}

/// Evict the oldest sessions past `max_sessions` for an account.
///
/// Returns the evicted sessions' ids — the token hashes their live connections
/// are registered under, so the caller can close them once the transaction
/// commits (see [`CappedSession::evicted`]). Mirrors `fuz_app`'s
/// `query_session_enforce_limit` (whose `DELETE … RETURNING id` it shares),
/// and is the session twin of [`query_api_token_enforce_limit`].
///
/// Ordering is `created_at DESC, id DESC`. The `id` leg is a **stability**
/// tie-breaker, not a recency one: `created_at` defaults to `NOW()`, which is
/// the *transaction* timestamp, so two sessions born in one transaction — or
/// in two transactions that started in the same microsecond — tie, and an
/// untied `OFFSET` may keep a different set on two evaluations of the same
/// rows. `id` is the blake3 token hash, so the tie-break is arbitrary but
/// deterministic; it makes the survivors reproducible, it does not make the
/// row you just inserted a guaranteed survivor.
///
/// Expired-but-unreaped rows count toward the cap (the predicate is
/// `account_id` alone), matching the TS twin.
///
/// # Race safety
///
/// Caller must wrap this and the preceding INSERT in one transaction. **A
/// transaction is necessary but not sufficient.** It makes one creator's
/// INSERT + evict pair atomic; it does not serialize concurrent creators.
/// Under Read Committed two transactions cannot see each other's uncommitted
/// session row, so each computes its `OFFSET` against a stale count, each
/// preserves its own row, and both commit above `max_sessions`. Closing that
/// needs one serialization point per `(account_id, credential_kind)` — a
/// locked parent row or a transaction-scoped advisory lock — taken before
/// count/evict/insert. This function does not close it, and neither does the
/// TS twin.
///
/// [`query_api_token_enforce_limit`]: crate::api_token_queries::query_api_token_enforce_limit
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_session_enforce_limit(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    max_sessions: i64,
) -> Result<Vec<String>, tokio_postgres::Error> {
    let rows = client
        .query(
            "DELETE FROM auth_session
             WHERE id IN (
               SELECT id FROM auth_session
               WHERE account_id = $1
               ORDER BY created_at DESC, id DESC
               OFFSET $2
             )
             RETURNING id",
            &[account_id, &max_sessions],
        )
        .await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// Delete a session by token hash.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_session_revoke_by_hash_unscoped(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_hash: &str,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute("DELETE FROM auth_session WHERE id = $1", &[&token_hash])
        .await?;
    Ok(())
}

/// Delete a session by token hash, scoped to an account.
///
/// Returns `true` when a row was deleted (IDOR guard: ID-bearing
/// requests for someone else's session see `false` rather than a leak).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_session_revoke_for_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_hash: &str,
    account_id: &uuid::Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let count = client
        .execute(
            "DELETE FROM auth_session WHERE id = $1 AND account_id = $2",
            &[&token_hash, account_id],
        )
        .await?;
    Ok(count > 0)
}

/// Delete every expired session, returning the ids (token hashes) of the rows
/// it deleted. Mirrors TS `query_session_cleanup_expired`.
///
/// The ids are the keys [`ConnectionCloseTarget::Session`] closes
/// by. A row past `expires_at` already fails [`query_session_get_valid`], but
/// deleting it does not end the connections it opened: a WebSocket keeps the
/// authority it resolved at upgrade and an SSE stream never rechecks. The row
/// was also the only per-session handle on those connections —
/// `account_session_revoke` closes only for a row it deleted — so the caller
/// closes each returned session's connections once the delete has committed.
/// [`crate::auth_cleanup::cleanup_expired_sessions`] is that caller; reach for
/// it rather than this query.
///
/// One statement, so the returned ids are exactly the rows this call removed:
/// a concurrent pass gets a disjoint set. Run it in a transaction, as the
/// caller above does, so the ids are read before the delete commits — on an
/// autocommit client a connection lost on the response leaves the rows
/// deleted and their ids unread. Served by
/// `idx_auth_session_expires`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
///
/// [`ConnectionCloseTarget::Session`]: crate::ConnectionCloseTarget::Session
pub async fn query_session_cleanup_expired(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Vec<String>, tokio_postgres::Error> {
    let rows = client
        .query(
            "DELETE FROM auth_session WHERE expires_at <= NOW() RETURNING id",
            &[],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Delete all sessions for an account, returning the deletion count.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_session_revoke_all_for_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<u64, tokio_postgres::Error> {
    client
        .execute(
            "DELETE FROM auth_session WHERE account_id = $1",
            &[account_id],
        )
        .await
}

/// List every active session across all accounts with usernames joined
/// in. Mirrors `fuz_app`'s `query_session_list_all_active`.
///
/// Ordered by `created_at DESC` (newest session first), matching the
/// per-account listing; capped at [`ADMIN_SESSION_LIST_LIMIT`]. Cross-account
/// read — auth is enforced upstream via `roles: [ROLE_ADMIN]` on the action
/// spec.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_session_list_all_active(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Vec<AdminSession>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns}, a.username
         FROM auth_session s
         JOIN account a ON a.id = s.account_id
         WHERE s.expires_at > NOW()
         ORDER BY s.created_at DESC, s.id DESC
         LIMIT $1",
        columns = auth_session_columns("s"),
    );
    let rows = client
        .query(sql.as_str(), &[&ADMIN_SESSION_LIST_LIMIT])
        .await?;
    Ok(rows.iter().map(decode_admin_session_row).collect())
}

/// List sessions for an account (for `account_session_list`).
///
/// Ordered by `created_at DESC` with a 50-row cap, matching
/// `fuz_app`'s `query_session_list_for_account`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_session_list_for_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Vec<SessionListRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns}
         FROM auth_session
         WHERE account_id = $1
         ORDER BY created_at DESC
         LIMIT 50",
        columns = session_list_columns(),
    );
    let rows = client.query(&sql, &[account_id]).await?;
    Ok(rows.iter().map(decode_session_list_row).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_db::omit_columns;

    #[test]
    fn session_list_columns_pin_to_the_derivation() {
        assert_eq!(
            SESSION_LIST_COLUMNS.to_vec(),
            omit_columns(&AUTH_SESSION_COLUMNS, &["account_id"])
        );
    }

    #[test]
    fn capped_session_debug_redacts_the_token() {
        let secret = "raw-session-token-Vb8nQ3";
        let session = CappedSession {
            token: secret.to_owned(),
            evicted: vec!["evicted-hash".to_owned()],
        };
        let rendered = format!("{session:?}");
        assert!(!rendered.contains(secret), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("evicted-hash"), "{rendered}");
    }
}
