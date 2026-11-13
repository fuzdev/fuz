//! Queries against the `api_token` table.

use crate::api_token_schema::{ApiTokenListRow, ApiTokenMintedRow, ApiTokenRow};
use crate::credential_deadline::{EXPIRES_IN_MS_SQL, remaining_from_db_ms};
use crate::token_scope::TokenScopeDocument;
use fuz_db::{col, iso8601_timestamp_column, iso8601_timestamp_expr, qualify_columns};

/// The `api_token` table's columns.
///
/// Twin of `fuz_app`'s `API_TOKEN_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live
/// column, so a column added to the DDL but not here fails loud — which
/// is also what keeps the client listing below honest: a new column joins
/// `api_token_client_columns` by default and has to be omitted
/// deliberately to stay off the wire.
pub const API_TOKEN_COLUMNS: [&str; 9] = [
    "id",
    "account_id",
    "name",
    "token_hash",
    "expires_at",
    "last_used_at",
    "last_used_ip",
    "created_at",
    "scope",
];

/// The [`ApiTokenListRow`] column list — [`API_TOKEN_COLUMNS`] minus
/// `token_hash` (the client-safe listing; mirrors TS
/// `API_TOKEN_CLIENT_COLUMNS`). A literal so [`decode_api_token_list_row`]
/// can `col!` into it; the unit test pins it to the `omit_columns`
/// derivation, whose unknown-name panic keeps a typo from leaving the hash
/// on the wire.
const API_TOKEN_CLIENT_COLUMNS: [&str; 8] = [
    "id",
    "account_id",
    "name",
    "expires_at",
    "last_used_at",
    "last_used_ip",
    "created_at",
    "scope",
];

/// The [`ApiTokenListRow`] projection ([`API_TOKEN_CLIENT_COLUMNS`]),
/// timestamps as ISO-8601 wire strings and `scope` as text — Postgres's spaced
/// form, which [`TokenScopeDocument::parse`] holds to the cap by its compact
/// serialization.
fn api_token_client_columns() -> String {
    let timestamps = iso8601_timestamp_expr(
        &API_TOKEN_CLIENT_COLUMNS,
        &["expires_at", "last_used_at", "created_at"],
        "api_token",
    );
    qualify_columns(&API_TOKEN_CLIENT_COLUMNS, "api_token", |col| match col {
        "scope" => Some("api_token.scope::text".to_owned()),
        _ => timestamps(col),
    })
}

/// Decode the [`api_token_client_columns`] projection positionally.
fn decode_api_token_list_row(row: &tokio_postgres::Row) -> ApiTokenListRow {
    let scope_text: String = row.get(col!(API_TOKEN_CLIENT_COLUMNS, "scope"));
    ApiTokenListRow {
        id: row.get(col!(API_TOKEN_CLIENT_COLUMNS, "id")),
        account_id: row.get(col!(API_TOKEN_CLIENT_COLUMNS, "account_id")),
        name: row.get(col!(API_TOKEN_CLIENT_COLUMNS, "name")),
        expires_at: row.get(col!(API_TOKEN_CLIENT_COLUMNS, "expires_at")),
        last_used_at: row.get(col!(API_TOKEN_CLIENT_COLUMNS, "last_used_at")),
        last_used_ip: row.get(col!(API_TOKEN_CLIENT_COLUMNS, "last_used_ip")),
        created_at: row.get(col!(API_TOKEN_CLIENT_COLUMNS, "created_at")),
        // Display-only, so an unreadable document degrades to a marker
        // rather than failing the whole list — the opposite of the
        // resolve path, and deliberately so: this is the surface an
        // operator uses to *find* a bad token, so it must still render.
        scope: TokenScopeDocument::parse(&scope_text)
            .map_or_else(|_| "unreadable".to_owned(), |doc| doc.label()),
    }
}

/// The `WHERE` fragment that makes an `api_token` row **live**: not expired
/// (an eternal token has no expiry).
///
/// One definition for every query that decides whether a token authenticates —
/// the resolve walk's [`query_validate_api_token`] and the re-check's
/// [`query_api_token_live_account`] — so a condition added to one is added to
/// both, and the re-check can never admit a token resolution would refuse.
/// A new liveness condition (a `revoked_at`, a `disabled` flag) goes here.
const API_TOKEN_IS_LIVE: &str = "(expires_at IS NULL OR expires_at > NOW())";

/// Look up a valid (non-expired) API token by its blake3 hash, with how long
/// it has left.
///
/// The remaining lifetime is read in the same statement that checks the
/// expiry, on the database clock ([`crate::ResolvedAuth::credential_deadline`]); an eternal
/// token has none.
///
/// Reads `scope` alongside the identity columns — one query, no join, because
/// the scope lives on the owning table rather than in a side table. (`fuz_forge`
/// pays a second `SELECT` per request for the same information, and its
/// side-table shape is what makes "no row" mean "allow everything".)
///
/// A token whose stored scope document is unreadable resolves to `None` — the
/// same outcome as an unknown token hash. **Fail-closed by construction**: the
/// scope *is* the gate here, so a parse failure must not fall through to full
/// authority. The lost forensic detail is logged, not swallowed silently.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_validate_api_token(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_hash: &str,
) -> Result<Option<ApiTokenRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT id, account_id, scope::text, {EXPIRES_IN_MS_SQL} FROM api_token
         WHERE token_hash = $1 AND {API_TOKEN_IS_LIVE}"
    );
    let row = client.query_opt(&sql, &[&token_hash]).await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let id: String = row.get(0);
    let scope_text: String = row.get(2);
    let scope = match TokenScopeDocument::parse(&scope_text) {
        Ok(doc) => doc.to_scope(),
        Err(e) => {
            tracing::warn!(
                api_token_id = %id,
                error = %fuz_sys::cli::format_error_chain(&e),
                "api_token.scope is unreadable; refusing the credential",
            );
            return Ok(None);
        }
    };

    let expires_in: Option<f64> = row.get(3);
    Ok(Some(ApiTokenRow {
        id,
        account_id: row.get(1),
        scope,
        expires_in: expires_in.map(remaining_from_db_ms),
    }))
}

/// Look up the owning account of a live API token — one that still exists
/// and has not expired — by its public id.
///
/// The by-id counterpart of [`query_validate_api_token`], for re-checking a
/// token that already authenticated
/// ([`crate::revalidate_resolved_auth`]): no hash, no scope decode, and no
/// touch — a re-check is not a use. "Live" is the same predicate in both
/// (`API_TOKEN_IS_LIVE`). The scope document is not re-read: the resolved
/// credential carries the scope it was admitted with, and nothing rewrites
/// the column after the mint.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_api_token_live_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_id: &str,
) -> Result<Option<uuid::Uuid>, tokio_postgres::Error> {
    let sql = format!("SELECT account_id FROM api_token WHERE id = $1 AND {API_TOKEN_IS_LIVE}");
    let row = client.query_opt(&sql, &[&token_id]).await?;
    Ok(row.map(|r| r.get(0)))
}

/// Touch an API token (update `last_used_at` + `last_used_ip`). Fire-and-forget.
///
/// `ip` is bound **unconditionally** — the statement has no "leave the column
/// alone" form — which is why it is `&str` and not `Option<&str>`: an absent
/// address would write SQL `NULL` over whatever a previous request recorded,
/// erasing the forensics for every token in a route's traffic mix. A caller
/// with no resolved client IP passes [`fuz_http::UNRESOLVED_CLIENT_IP`], the
/// same sentinel the audit rows record. The column is `TEXT`, matching the lax
/// `fuz_app` storage.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_api_token_touch(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_id: &str,
    ip: &str,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE api_token SET last_used_at = NOW(), last_used_ip = $2 WHERE id = $1",
            &[&token_id, &ip],
        )
        .await?;
    Ok(())
}

/// Spawn a fire-and-forget [`query_api_token_touch`] on a background task.
///
/// The request path never blocks on the `last_used_at` / `last_used_ip` write,
/// and a pool/query failure is logged (not propagated). Owns `token_id` + `ip`
/// internally, so callers pass borrows that needn't outlive the task. The
/// single home for "record a token use" — shared by the spine bearer resolve
/// and the forge git-auth path (which would otherwise duplicate this block).
pub fn spawn_api_token_touch(pool: &deadpool_postgres::Pool, token_id: &str, ip: &str) {
    let pool = pool.clone();
    let token_id = token_id.to_owned();
    let ip = ip.to_owned();
    tokio::spawn(async move {
        if let Ok(client) = pool.get().await
            && let Err(e) = query_api_token_touch(&client, &token_id, &ip).await
        {
            tracing::warn!(error = %fuz_sys::cli::format_error_chain(&e), "api token touch failed");
        }
    });
}

/// Insert a new API token row and return its mint-time timestamps
/// (UTC ISO 8601).
///
/// `expires_at` is `None` for a deliberately eternal token; the validate
/// chokepoint (`query_validate_api_token`) enforces the bound, so a stored
/// expiry needs no further wiring to take effect. Twin of `fuz_app`'s
/// `query_create_api_token` (`expires_at?: Date | null`).
///
/// `scope_json` is required, not defaulted: default-deny at mint means the
/// caller has already decided, and there is no permissive value to fall into.
/// Serialize it with [`TokenScopeDocument::to_json`](crate::TokenScopeDocument::to_json)
/// so the size cap is enforced before the write.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_create_api_token(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_id: &str,
    account_id: &uuid::Uuid,
    name: &str,
    token_hash: &str,
    scope_json: &str,
    expires_at: Option<std::time::SystemTime>,
) -> Result<ApiTokenMintedRow, tokio_postgres::Error> {
    let sql = format!(
        // `$5::text::jsonb`, not `$5::jsonb`: a bare `::jsonb` cast makes
        // Postgres infer the bound parameter's type as `jsonb`, which
        // tokio-postgres cannot serialize a Rust `String` into. The double cast
        // keeps the parameter `text` and casts server-side — the same idiom the
        // audit-log insert uses.
        "INSERT INTO api_token (id, account_id, name, token_hash, scope, expires_at)
         VALUES ($1, $2, $3, $4, $5::text::jsonb, $6)
         RETURNING {created_at}, {expires_at}",
        created_at = iso8601_timestamp_column("", "created_at"),
        expires_at = iso8601_timestamp_column("", "expires_at"),
    );
    let row = client
        .query_one(
            &sql,
            &[
                &token_id,
                account_id,
                &name,
                &token_hash,
                &scope_json,
                &expires_at,
            ],
        )
        .await?;
    Ok(ApiTokenMintedRow {
        created_at: row.get(0),
        expires_at: row.get(1),
    })
}

/// List all API tokens for an account in `ClientApiTokenJson` shape.
///
/// Projects `api_token_client_columns` — [`API_TOKEN_COLUMNS`] minus
/// `token_hash` — so a column added to `api_token` reaches this listing
/// through the const and has to be omitted deliberately to stay off the
/// wire.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_api_token_list_for_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Vec<ApiTokenListRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns}
         FROM api_token
         WHERE account_id = $1
         ORDER BY created_at DESC",
        columns = api_token_client_columns(),
    );
    let rows = client.query(&sql, &[account_id]).await?;
    Ok(rows.iter().map(decode_api_token_list_row).collect())
}

/// Evict the oldest tokens past `max_tokens` for an account, returning the
/// evicted tokens' public ids.
///
/// Mirrors `fuz_app`'s `query_api_token_enforce_limit` (whose
/// `DELETE … RETURNING id` it shares). Caller must wrap this + the preceding
/// INSERT in one transaction.
///
/// The ids are what
/// [`ConnectionCloseTarget::Token`](crate::ConnectionCloseTarget::Token) keys on:
/// deleting a token row does not end the connections it opened, so the
/// caller closes each evicted token's connections once the transaction
/// commits (`account_token_create` queues them on the post-commit queue).
///
/// Ordering carries the same `id DESC` stability tie-breaker, with the same
/// caveat, as the session twin — see
/// [`query_session_enforce_limit`](crate::session_queries::query_session_enforce_limit)
/// for what it does and does not buy, and for why the transaction is
/// necessary but not sufficient against concurrent creators.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_api_token_enforce_limit(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    max_tokens: i64,
) -> Result<Vec<String>, tokio_postgres::Error> {
    let rows = client
        .query(
            "DELETE FROM api_token
             WHERE id IN (
               SELECT id FROM api_token
               WHERE account_id = $1
               ORDER BY created_at DESC, id DESC
               OFFSET $2
             )
             RETURNING id",
            &[account_id, &max_tokens],
        )
        .await?;
    Ok(rows.iter().map(|row| row.get(0)).collect())
}

/// Delete an API token by id, scoped to an account.
///
/// Returns `true` when a row was deleted (account-scoping is the IDOR
/// guard).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_revoke_api_token_for_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    token_id: &str,
    account_id: &uuid::Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let count = client
        .execute(
            "DELETE FROM api_token WHERE id = $1 AND account_id = $2",
            &[&token_id, account_id],
        )
        .await?;
    Ok(count > 0)
}

/// Delete all API tokens for an account.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_revoke_all_api_tokens_for_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<u64, tokio_postgres::Error> {
    let count = client
        .execute("DELETE FROM api_token WHERE account_id = $1", &[account_id])
        .await?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_db::omit_columns;

    #[test]
    fn client_columns_pin_to_the_derivation() {
        assert_eq!(
            API_TOKEN_CLIENT_COLUMNS.to_vec(),
            omit_columns(&API_TOKEN_COLUMNS, &["token_hash"])
        );
    }

    #[test]
    fn client_columns_omit_the_hash_and_follow_the_const_order() {
        let projection = api_token_client_columns();
        assert!(!projection.contains("token_hash"), "{projection}");
        assert_eq!(
            projection,
            format!(
                "api_token.id, api_token.account_id, api_token.name, {}, {}, api_token.last_used_ip, {}, api_token.scope::text",
                iso8601_timestamp_column("api_token", "expires_at"),
                iso8601_timestamp_column("api_token", "last_used_at"),
                iso8601_timestamp_column("api_token", "created_at"),
            )
        );
    }
}
