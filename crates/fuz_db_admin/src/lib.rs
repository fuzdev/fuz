//! Db-admin REST routes (`/db/*`) — an allowlist-gated `public`-schema table
//! browser for an admin dashboard, as a reusable spine crate.
//!
//! The access gate is **parameterized**: a consumer supplies the global role
//! required ([`DbAdminRouteState::required_role`], e.g. `admin`), the
//! credential channels admitted ([`DbAdminRouteState::credential_gate`]), and
//! the [`AuthGate`] — origin allowlist, session cookie name, credential walk —
//! every route checks a request at first.
//!
//! | Method | Path | Returns |
//! |---|---|---|
//! | `GET` | `/health` | `{connected, type, name, table_count}` (503 on failure) |
//! | `GET` | `/tables` | `{tables: [{name, row_count}]}` |
//! | `GET` | `/tables/{name}` | columns + paginated rows + total + pk + deletable |
//! | `DELETE` | `/tables/{name}/rows/{id}` | `{success: true}` |
//!
//! **The allowlist gates everything but `/health`.** A consumer declares
//! [`DbAdminRouteState::browsable_tables`] — required, no "all" escape hatch —
//! and the credential floor [`NON_BROWSABLE_TABLES`] is subtracted even when
//! named; an unlisted table answers exactly like one that doesn't exist.
//! Reads are bounded: the browse/delete transactions run under
//! `SET LOCAL statement_timeout` and bytea values are returned as `<N bytes>`
//! placeholders.
//!
//! Row deletion is additionally refused for the tables in
//! [`NON_DELETABLE_TABLES`] (plus any consumer extension via
//! [`DbAdminRouteState::non_deletable_tables`]) and for any table whose
//! primary key is not exactly one column. Every successful row delete emits a
//! `db_admin_row_delete` audit event (account-grain, metadata
//! `{table, pk_column, id}`, the resolved client IP when the consumer mounts
//! `client_ip_middleware`) through [`DbAdminRouteState::audit`].
//!
//! Every table name is validated against [`fuz_db::is_valid_sql_identifier`]
//! before it is interpolated into SQL — that validation is the only reason the
//! `"{name}"` interpolation is safe; the row id is always parameterized (`$1`).
//! Wire shapes + error codes mirror the TS spine schemas so the cross-backend
//! suites see one contract on every backend. Mount under `/api/db`.

#![expect(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the crate-wide REST handler idiom"
)]

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use deadpool_postgres::GenericClient;
use fuz_auth::{
    AuditEmitter, AuditEventType, AuditLogInput, AuthGate, CredentialGate, OriginChecked,
    parse_acting_query,
};
use fuz_db::{
    PgErrorKind, UntypedTextParam, classify_pg_error, commit_checked, is_valid_sql_identifier,
};
use fuz_http::{
    ClientIp, assert_known_query_keys, invalid_query_params_response,
    invalid_route_params_response, query_first,
};
use serde::Serialize;
use serde_json::{Value, json};

use fuz_http::{
    db_unavailable_response_with_source, internal_error_response,
    internal_error_response_with_source, rest_error_response,
};

mod route_auth;

/// Default page size for `GET /tables/{name}` rows (mirrors TS
/// `DB_TABLE_ROWS_DEFAULT_LIMIT`).
const DB_TABLE_ROWS_DEFAULT_LIMIT: i64 = 100;
/// Maximum page size for `GET /tables/{name}` rows (mirrors TS
/// `DB_TABLE_ROWS_LIMIT_MAX`).
const DB_TABLE_ROWS_LIMIT_MAX: i64 = 1000;

/// Per-statement timeout applied (`SET LOCAL statement_timeout`) inside the
/// table-list, table-detail, and row-`DELETE` transactions — no single
/// statement outlives it. (Per statement, not per request: the table
/// listing's one-`COUNT(*)`-per-table loop can still take several in
/// sequence.) Milliseconds — mirrors TS `DB_ADMIN_STATEMENT_TIMEOUT_MS`.
const DB_ADMIN_STATEMENT_TIMEOUT_MS: i32 = 5000;

/// The credential floor: tables the browser can never expose.
///
/// Subtracted from [`DbAdminRouteState::browsable_tables`] whatever the
/// consumer names there — not overridable (mirrors TS `NON_BROWSABLE_TABLES`):
///
/// - `account` — the one surface that would return the argon2 password-hash
///   corpus in bulk (every other read path excludes the hash by projection).
/// - `auth_session` / `api_token` — credential digests plus per-account
///   session/token metadata.
/// - `bootstrap_lock` — the first-admin gate; its row is load-bearing state,
///   not content.
///
/// A table on the floor answers exactly like one that doesn't exist (404
/// `table_not_found`) so the browser doesn't confirm its presence.
pub const NON_BROWSABLE_TABLES: &[&str] =
    &["account", "auth_session", "api_token", "bootstrap_lock"];

/// Whether the browser exposes `name` — in the consumer's allowlist and not
/// on the [`NON_BROWSABLE_TABLES`] credential floor.
fn is_browsable(name: &str, browsable: &[&str]) -> bool {
    browsable.contains(&name) && !NON_BROWSABLE_TABLES.contains(&name)
}

/// Tables the row-`DELETE` refuses to act on, whatever their key shape
/// (mirrors TS `NON_DELETABLE_TABLES`).
///
/// Two kinds, one rule — a generic storage endpoint has no business deleting
/// a row whose meaning lives in the domain layer:
///
/// - `audit_log` — the trail and the tamper path would otherwise be the same
///   surface. It is also how revocation propagates: the revocation guard
///   (`fuz_auth::register_revocation_guard`) on [`fuz_auth::AuditEmitter`] closes live
///   connections by listening to audit events, so a raw row delete here is
///   invisible to them.
/// - `bootstrap_lock` — deleting the singleton leaves
///   [`fuz_auth::is_bootstrap_available`] advertising an open bootstrap
///   window on the next boot that `bootstrap_handler`'s atomic flip then
///   always refuses.
/// - `app_settings` — deleting the singleton breaks every settings read.
/// - `schema_version` — the migration tracker. Already refused by the
///   single-column-primary-key rule (its key is `(namespace, name)`), but
///   that is incidental: naming it here keeps the protection if the key
///   shape ever changes.
///
/// Consumers extend this with [`DbAdminRouteState::non_deletable_tables`] —
/// the builtin set is a floor, never replaced.
pub const NON_DELETABLE_TABLES: &[&str] = &[
    "audit_log",
    "bootstrap_lock",
    "app_settings",
    "schema_version",
];

/// Whether `name` is excluded from row deletion — in the builtin
/// [`NON_DELETABLE_TABLES`] floor or the consumer's
/// [`DbAdminRouteState::non_deletable_tables`] extension.
fn is_non_deletable(name: &str, extra: &[&str]) -> bool {
    NON_DELETABLE_TABLES.contains(&name) || extra.contains(&name)
}

/// State for the db-admin router.
#[derive(Clone)]
pub struct DbAdminRouteState {
    /// The front door every route checks a request at — the origin check,
    /// then the credential walk (session cookie, bearer, daemon token) — and
    /// the pool the browser reads and mutates.
    pub gate: AuthGate,
    /// Global role required to access the browser (consumer-specific — e.g.
    /// `admin`). Any actor on the resolved account holding it admits.
    pub required_role: &'static str,
    /// Credential channels that may reach the browser — the credential axis
    /// the spine's `AuthSpec`s declare, expressed on this REST surface too.
    /// A resolved credential outside the gate is refused with 403
    /// `credential_type_required`.
    pub credential_gate: CredentialGate,
    /// The tables the browser exposes — an explicit allowlist gating the
    /// table list, detail, and row-`DELETE` alike. Required with no "all"
    /// escape hatch, so a future secret-bearing table stays unlisted until a
    /// consumer names it; the credential floor [`NON_BROWSABLE_TABLES`] is
    /// subtracted even when named. An unlisted table 404s as
    /// `table_not_found` — the same answer as a table that doesn't exist.
    pub browsable_tables: &'static [&'static str],
    /// Consumer tables to exclude from row deletion, unioned with the
    /// builtin [`NON_DELETABLE_TABLES`] floor (which this extends, never
    /// replaces). Usually empty.
    pub non_deletable_tables: &'static [&'static str],
    /// Audit emitter for the `db_admin_row_delete` event every successful
    /// row delete emits (pool-routed fire-and-forget).
    pub audit: Arc<AuditEmitter>,
}

impl std::fmt::Debug for DbAdminRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbAdminRouteState").finish_non_exhaustive()
    }
}

impl DbAdminRouteState {
    /// Admit only callers on an admitted credential channel whose account
    /// holds [`Self::required_role`]. Returns the resolved account id — the
    /// row-`DELETE` handler threads it into the `db_admin_row_delete` audit
    /// emission; the read handlers discard it (they act on the pool, not the
    /// caller's actor). `origin` is the handler's origin-check witness;
    /// `client_ip` reaches the bearer leg's `last_used_ip` recording.
    async fn require_role(
        &self,
        origin: OriginChecked<'_>,
        client_ip: &str,
        acting: Option<uuid::Uuid>,
    ) -> Result<uuid::Uuid, Response> {
        route_auth::require_role(self, origin, client_ip, acting).await
    }
}

/// One row of `GET /tables`.
#[derive(Debug, Serialize)]
struct TableWithCount {
    name: String,
    row_count: i64,
}

/// One column of `GET /tables/{name}` (from `information_schema.columns`).
#[derive(Debug, Serialize)]
struct ColumnInfo {
    column_name: String,
    data_type: String,
    is_nullable: String,
    /// `pg_type` name (`bytea`, `_bytea` for `bytea[]`, …) — drives the
    /// byte-value placeholder projection; internal, never serialized
    /// (`data_type` reports `ARRAY` for array columns, hiding the element
    /// type this needs).
    #[serde(skip)]
    udt_name: String,
}

/// Build the db-admin axum router (mount under `/api/db`).
///
/// The access gate is configured via [`DbAdminRouteState::required_role`] +
/// [`DbAdminRouteState::credential_gate`], behind the [`AuthGate`] in
/// [`DbAdminRouteState::gate`].
pub fn db_admin_router(state: DbAdminRouteState) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/tables", get(handle_tables))
        .route("/tables/{name}", get(handle_table_detail))
        .route("/tables/{name}/rows/{id}", delete(handle_row_delete))
        .with_state(state)
}

async fn handle_health(
    State(state): State<DbAdminRouteState>,
    Query(query_pairs): Query<Vec<(String, String)>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    // The gate's origin check first — a foreign page is refused before its
    // params or query are read, as the TS twin's origin middleware refuses it
    // ahead of the route.
    let origin = state.gate.check_origin(&headers)?;
    // Query shape before auth — the TS pipeline's phase order (params →
    // query → 401/403), so the two backends answer a malformed query
    // identically whatever the caller's credentials.
    assert_known_query_keys(&query_pairs, &["acting"])?;
    let acting = parse_acting_query(query_first(&query_pairs, "acting"))?;

    state
        .require_role(
            origin,
            ClientIp::as_str_or_unresolved(client_ip.as_ref()),
            acting,
        )
        .await?;

    // Any connectivity failure is an expected operational state → 503,
    // not a 500.
    let Ok(client) = state.gate.pool.get().await else {
        return Ok(db_unavailable());
    };
    if client.query_one("SELECT 1", &[]).await.is_err() {
        return Ok(db_unavailable());
    }
    // Deliberately schema-wide (not allowlist-filtered): the count is a
    // did-migrations-run diagnostic, and a bare number leaks no table
    // contents or names.
    let Ok(count_row) = client
        .query_one(
            "SELECT COUNT(*)::bigint FROM information_schema.tables WHERE table_schema = 'public'",
            &[],
        )
        .await
    else {
        return Ok(db_unavailable());
    };
    let table_count: i64 = count_row.get(0);
    let name: String = client
        .query_one("SELECT current_database()", &[])
        .await
        .map(|row| row.get(0))
        .unwrap_or_default();

    Ok(Json(json!({
        "connected": true,
        "type": "pg",
        "name": name,
        "table_count": table_count,
    }))
    .into_response())
}

/// Open a transaction on `client` and apply
/// [`DB_ADMIN_STATEMENT_TIMEOUT_MS`] via `SET LOCAL` — the value is a module
/// constant, never input, which is the only reason the interpolation is safe.
async fn timed_transaction<'a>(
    client: &'a mut deadpool_postgres::Client,
    context: &'static str,
) -> Result<deadpool_postgres::Transaction<'a>, Response> {
    let tx = client
        .transaction()
        .await
        .map_err(|e| internal_error_response_with_source(context, &e))?;
    tx.batch_execute(&format!(
        "SET LOCAL statement_timeout = {DB_ADMIN_STATEMENT_TIMEOUT_MS}"
    ))
    .await
    .map_err(|e| internal_error_response_with_source(context, &e))?;
    Ok(tx)
}

/// The shared masked gate prologue for the detail and row-`DELETE` cores:
/// allowlist check (before any catalog read), then a [`timed_transaction`],
/// then existence — an unbrowsable table and a missing one produce the same
/// 404 `table_not_found` from the same place, so the masking invariant has
/// one home.
///
/// # Errors
///
/// Returns the masked 404 `table_not_found` denial `Response` (`Err`) for a
/// missing, unlisted, or [`NON_BROWSABLE_TABLES`]-floor table, or a logged
/// 500.
async fn open_browsable_tx<'a>(
    client: &'a mut deadpool_postgres::Client,
    name: &str,
    browsable_tables: &[&str],
    context: &'static str,
) -> Result<deadpool_postgres::Transaction<'a>, Response> {
    if !is_browsable(name, browsable_tables) {
        return Err(rest_error_response(
            StatusCode::NOT_FOUND,
            "table_not_found",
        ));
    }
    let tx = timed_transaction(client, context).await?;
    if !table_exists(&tx, name).await? {
        return Err(rest_error_response(
            StatusCode::NOT_FOUND,
            "table_not_found",
        ));
    }
    Ok(tx)
}

/// 503 `{connected: false, type: "pg", error: "database_connection_failed"}`
/// — mirrors the TS health-failure body.
fn db_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "connected": false,
            "type": "pg",
            "error": "database_connection_failed",
        })),
    )
        .into_response()
}

async fn handle_tables(
    State(state): State<DbAdminRouteState>,
    Query(query_pairs): Query<Vec<(String, String)>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    // The gate's origin check first — a foreign page is refused before its
    // params or query are read, as the TS twin's origin middleware refuses it
    // ahead of the route.
    let origin = state.gate.check_origin(&headers)?;
    // Query shape before auth — see `handle_health`.
    assert_known_query_keys(&query_pairs, &["acting"])?;
    let acting = parse_acting_query(query_first(&query_pairs, "acting"))?;

    state
        .require_role(
            origin,
            ClientIp::as_str_or_unresolved(client_ip.as_ref()),
            acting,
        )
        .await?;

    let mut client = state
        .gate
        .pool
        .get()
        .await
        .map_err(|e| db_unavailable_response_with_source("db.tables pool", &e))?;
    let tx = timed_transaction(&mut client, "db.tables tx").await?;
    // Existence still comes from `information_schema` — a listed table that
    // hasn't migrated in yet is silently absent, not a 500.
    let rows = tx
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' ORDER BY table_name",
            &[],
        )
        .await
        .map_err(|e| internal_error_response_with_source("db.tables list", &e))?;

    let mut tables: Vec<TableWithCount> = Vec::with_capacity(rows.len());
    for row in &rows {
        let table_name: String = row.get(0);
        if !is_browsable(&table_name, state.browsable_tables) {
            continue;
        }
        // `table_name` is a real identifier from `information_schema`;
        // validate defensively before interpolation anyway.
        if !is_valid_sql_identifier(&table_name) {
            continue;
        }
        // Propagate a count failure — inside a transaction a swallowed
        // statement error would abort the tx and silently zero every
        // remaining table's count ("current transaction is aborted"). The TS
        // twin throws → 500 here too.
        let row_count: i64 = tx
            .query_one(
                &format!("SELECT COUNT(*)::bigint FROM \"{table_name}\""),
                &[],
            )
            .await
            .map(|r| r.get(0))
            .map_err(|e| internal_error_response_with_source("db.tables count", &e))?;
        tables.push(TableWithCount {
            name: table_name,
            row_count,
        });
    }

    Ok(Json(json!({"tables": tables})).into_response())
}

/// Parse an optional integer query param — absent ⇒ `default`, malformed ⇒
/// 400 `invalid_query_params` in the flat envelope (twinning the TS
/// `query_int`'s 400, which reads the same `[+-]?digits` spellings).
fn parse_query_i64(raw: Option<&str>, default: i64) -> Result<i64, Response> {
    raw.map_or(Ok(default), |s| {
        s.parse().map_err(|_| invalid_query_params_response())
    })
}

/// The largest offset the TS twin accepts, `Number.MAX_SAFE_INTEGER`.
const DB_TABLE_ROWS_OFFSET_MAX: i64 = (1 << 53) - 1;

/// Parse and bound the paging params — absent ⇒ defaults, malformed or
/// out-of-range ⇒ 400 `invalid_query_params`. Strict bounds, not a silent
/// clamp: out-of-range is a caller bug the TS twin's query schema already 400s
/// on, and hiding it here made the twins diverge.
///
/// # Errors
///
/// Returns the 400 denial `Response` (`Err`) on a malformed number, an offset
/// outside `[0, 2^53−1]`, or a limit outside `[1, DB_TABLE_ROWS_LIMIT_MAX]`.
fn parse_paging(offset_raw: Option<&str>, limit_raw: Option<&str>) -> Result<(i64, i64), Response> {
    let offset = parse_query_i64(offset_raw, 0)?;
    let limit = parse_query_i64(limit_raw, DB_TABLE_ROWS_DEFAULT_LIMIT)?;
    if !(0..=DB_TABLE_ROWS_OFFSET_MAX).contains(&offset)
        || !(1..=DB_TABLE_ROWS_LIMIT_MAX).contains(&limit)
    {
        return Err(invalid_query_params_response());
    }
    Ok((offset, limit))
}

#[cfg(test)]
mod query_param_tests {
    use super::*;

    #[test]
    fn absent_uses_default() {
        assert_eq!(parse_query_i64(None, 7).unwrap(), 7);
    }

    #[test]
    fn numeric_parses() {
        assert_eq!(parse_query_i64(Some("42"), 7).unwrap(), 42);
    }

    #[test]
    fn malformed_is_enveloped_400() {
        // an axum serde rejection would be a plain-text 400
        let resp = parse_query_i64(Some("abc"), 7).unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn paging_defaults() {
        assert_eq!(
            parse_paging(None, None).unwrap(),
            (0, DB_TABLE_ROWS_DEFAULT_LIMIT)
        );
    }

    #[test]
    fn paging_bounds_are_strict_400s() {
        for (offset, limit) in [
            (None, Some("0")),
            (None, Some("1001")),
            (None, Some("1e2")),
            (None, Some("-5")),
            (Some("-1"), None),
            (Some("9007199254740992"), None),
        ] {
            let resp = parse_paging(offset, limit).unwrap_err();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "offset={offset:?} limit={limit:?}",
            );
        }
        assert_eq!(parse_paging(Some("+5"), Some("1000")).unwrap(), (5, 1000));
        assert_eq!(
            parse_paging(Some("9007199254740991"), None).unwrap(),
            ((1 << 53) - 1, DB_TABLE_ROWS_DEFAULT_LIMIT)
        );
    }
}

async fn handle_table_detail(
    State(state): State<DbAdminRouteState>,
    Path(name): Path<String>,
    Query(query_pairs): Query<Vec<(String, String)>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    // The gate's origin check first — a foreign page is refused before its
    // params or query are read, as the TS twin's origin middleware refuses it
    // ahead of the route.
    let origin = state.gate.check_origin(&headers)?;
    // Params then query shape before auth — the TS pipeline's phase order.
    // `acting` is the spine actor selector, validated then discarded (the
    // raw-SQL row read is not actor-stamped) — mirrors the TS handler's
    // `void validated`.
    if !is_valid_sql_identifier(&name) {
        return Err(invalid_route_params_response());
    }
    assert_known_query_keys(&query_pairs, &["acting", "offset", "limit"])?;
    let acting = parse_acting_query(query_first(&query_pairs, "acting"))?;
    let (offset, limit) = parse_paging(
        query_first(&query_pairs, "offset"),
        query_first(&query_pairs, "limit"),
    )?;

    state
        .require_role(
            origin,
            ClientIp::as_str_or_unresolved(client_ip.as_ref()),
            acting,
        )
        .await?;

    let mut client = state
        .gate
        .pool
        .get()
        .await
        .map_err(|e| db_unavailable_response_with_source("db.detail pool", &e))?;

    perform_table_detail(
        &mut client,
        TableDetailOptions {
            name: &name,
            offset,
            limit,
            browsable_tables: state.browsable_tables,
            non_deletable_tables: state.non_deletable_tables,
        },
    )
    .await
}

/// Inputs for [`perform_table_detail`] beyond the DB handle — the request
/// values plus the two policy sets the mount declared. A struct rather than
/// positional params: `offset`/`limit` and the two table slices are adjacent
/// same-type values, silent-swap hazards as positionals.
struct TableDetailOptions<'a> {
    name: &'a str,
    offset: i64,
    limit: i64,
    browsable_tables: &'a [&'a str],
    non_deletable_tables: &'a [&'a str],
}

/// The auth-free core of [`handle_table_detail`] (the caller owns the role
/// gate, `acting` validation, and bounds checks; `name` is already a
/// validated SQL identifier). Split out so the PG-backed tests can drive the
/// real catalog + row SQL — allowlist masking, the composite-PK `null`
/// report, the bytea placeholder — without standing up the auth fixtures the
/// HTTP gate requires.
///
/// Runs inside a [`timed_transaction`] so no scan outlives
/// [`DB_ADMIN_STATEMENT_TIMEOUT_MS`].
///
/// # Errors
///
/// Returns the denial `Response` (`Err`): 404 `table_not_found` (missing,
/// unlisted, or on the [`NON_BROWSABLE_TABLES`] floor — masked identically),
/// or a logged 500.
async fn perform_table_detail(
    client: &mut deadpool_postgres::Client,
    options: TableDetailOptions<'_>,
) -> Result<Response, Response> {
    let TableDetailOptions {
        name,
        offset,
        limit,
        browsable_tables,
        non_deletable_tables,
    } = options;

    let tx = open_browsable_tx(client, name, browsable_tables, "db.detail tx").await?;

    let columns: Vec<ColumnInfo> = tx
        .query(
            "SELECT column_name, data_type, is_nullable, udt_name \
             FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position",
            &[&name],
        )
        .await
        .map_err(|e| internal_error_response_with_source("db.detail columns", &e))?
        .iter()
        .map(|r| ColumnInfo {
            column_name: r.get(0),
            data_type: r.get(1),
            is_nullable: r.get(2),
            udt_name: r.get(3),
        })
        .collect();

    // Propagate a count failure — a swallowed statement error would abort
    // the transaction and turn the next query into a confusing
    // "current transaction is aborted" 500.
    let total: i64 = tx
        .query_one(&format!("SELECT COUNT(*)::bigint FROM \"{name}\""), &[])
        .await
        .map(|r| r.get(0))
        .map_err(|e| internal_error_response_with_source("db.detail count", &e))?;

    // Surface a single-column primary key for the delete affordance; a
    // composite (or absent) PK has no single column this endpoint can delete
    // by, so report `null` — twinning the row-`DELETE`'s single-column-only
    // rule. Keeps the wire shape `primary_key: string | null` unchanged.
    let pk_columns = query_primary_key(&tx, name)
        .await
        .map_err(|e| internal_error_response_with_source("db.detail pk", &e))?;
    let primary_key: Option<&str> = match pk_columns.as_slice() {
        [only] => Some(only),
        _ => None,
    };
    // `deletable` is exactly what the row-`DELETE` will accept, so a client
    // can hide the affordance rather than discover the refusal.
    // `primary_key` stays a truthful report of the key shape — a policy
    // exclusion must not masquerade as one.
    let deletable = primary_key.is_some() && !is_non_deletable(name, non_deletable_tables);

    // bytea values never leave the server — a full page of e.g. `fact.bytes`
    // would otherwise materialize GiBs in one response. The column stays in
    // the result with a `<N bytes>` placeholder per cell (NULL stays NULL);
    // `columns` metadata is untouched. Catalog column names are held to the
    // same identifier invariant as the table name before interpolation.
    let select_list = if columns.is_empty() {
        // zero-column tables are legal PG
        "*".to_owned()
    } else {
        let mut parts: Vec<String> = Vec::with_capacity(columns.len());
        for col in &columns {
            if !is_valid_sql_identifier(&col.column_name) {
                tracing::error!(
                    table = %name,
                    column = %col.column_name,
                    "db.detail: catalog returned a non-identifier column name",
                );
                return Err(internal_error_response());
            }
            let ident = &col.column_name;
            parts.push(match col.udt_name.as_str() {
                // scalar bytea: the honest byte length
                "bytea" => {
                    format!("('<' || octet_length(\"{ident}\") || ' bytes>') AS \"{ident}\"")
                }
                // bytea[] (`data_type` says only `ARRAY`; `udt_name` carries
                // the element type): `octet_length` doesn't take arrays, so
                // report the stored size via `pg_column_size`
                "_bytea" => {
                    format!("('<' || pg_column_size(\"{ident}\") || ' bytes>') AS \"{ident}\"")
                }
                _ => format!("\"{ident}\""),
            });
        }
        parts.join(", ")
    };

    // `to_jsonb(t)::text` yields one JSON object per row — avoids
    // per-column type decoding for an arbitrary table shape.
    let rows_sql = format!(
        "SELECT to_jsonb(t)::text FROM (SELECT {select_list} FROM \"{name}\" LIMIT $1 OFFSET $2) t"
    );
    let row_rows = tx
        .query(&rows_sql, &[&limit, &offset])
        .await
        .map_err(|e| internal_error_response_with_source("db.detail rows", &e))?;
    let mut rows: Vec<Value> = Vec::with_capacity(row_rows.len());
    for r in &row_rows {
        let text: String = r.get(0);
        rows.push(
            serde_json::from_str(&text)
                .map_err(|e| internal_error_response_with_source("db.detail row decode", &e))?,
        );
    }

    Ok(Json(json!({
        "columns": columns,
        "rows": rows,
        "total": total,
        "offset": offset,
        "limit": limit,
        "primary_key": primary_key,
        "deletable": deletable,
    }))
    .into_response())
}

async fn handle_row_delete(
    State(state): State<DbAdminRouteState>,
    Path((name, id)): Path<(String, String)>,
    Query(query_pairs): Query<Vec<(String, String)>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    // The gate's origin check first — a foreign page is refused before its
    // params or query are read, as the TS twin's origin middleware refuses it
    // ahead of the route.
    let origin = state.gate.check_origin(&headers)?;
    // Params then query shape before auth — the TS pipeline's phase order.
    // `acting` is validated then discarded (the delete is raw SQL, not
    // actor-stamped).
    if !is_valid_sql_identifier(&name) {
        return Err(invalid_route_params_response());
    }
    assert_known_query_keys(&query_pairs, &["acting"])?;
    let acting = parse_acting_query(query_first(&query_pairs, "acting"))?;

    let ip = ClientIp::as_str_or_unresolved(client_ip.as_ref());
    let account_id = state.require_role(origin, ip, acting).await?;

    let mut client = state
        .gate
        .pool
        .get()
        .await
        .map_err(|e| db_unavailable_response_with_source("db.delete pool", &e))?;

    perform_row_delete(
        &mut client,
        &state.audit,
        RowDeleteOptions {
            name: &name,
            id: &id,
            browsable_tables: state.browsable_tables,
            non_deletable_tables: state.non_deletable_tables,
            account_id,
            ip,
        },
    )
    .await
}

/// Inputs for [`perform_row_delete`] beyond its capabilities — the request
/// data plus the policy sets the mount declared. A struct rather than
/// positional params: `name`/`id` and the two table slices are adjacent
/// same-type values, silent-swap hazards as positionals.
struct RowDeleteOptions<'a> {
    name: &'a str,
    id: &'a str,
    browsable_tables: &'a [&'a str],
    non_deletable_tables: &'a [&'a str],
    account_id: uuid::Uuid,
    /// Client IP for the audit row — [`fuz_http::UNRESOLVED_CLIENT_IP`] when
    /// the router runs outside `fuz_http::compose_stack`
    /// ([`ClientIp::as_str_or_unresolved`]).
    ip: &'a str,
}

/// Delete one row by primary key — the auth-free core of [`handle_row_delete`]
/// (the caller owns the role gate + `acting` validation, and threads the
/// resolved account id in for audit attribution). Split out so the PG-backed
/// test can drive the real `DELETE` + audit path — composite-PK refusal +
/// single-PK success — without standing up the auth fixtures the HTTP gate
/// requires.
///
/// `name` must already be a validated SQL identifier ([`handle_row_delete`]
/// checks it before acquiring the pool); it is interpolated into the `DELETE`.
///
/// **The allowlist gate fires first, masked** — an unbrowsable table
/// (unlisted, or on the [`NON_BROWSABLE_TABLES`] floor) answers exactly like
/// a missing one, before any catalog read.
///
/// **Non-deletable tables are refused next.** `non_deletable_tables` is the
/// consumer's extension of the builtin [`NON_DELETABLE_TABLES`] floor; a
/// table in either set is refused with `table_not_deletable` before the key
/// shape is even read.
///
/// **Single-column primary keys only.** This endpoint deletes by
/// `WHERE "<pk>" = $1`, which is safe *only* when the PK is exactly one
/// column. A composite PK (`> 1` columns) makes that filter match every row
/// sharing the one column's value — deleting a single `cell_field` row would
/// wipe every field of that name on every cell — and an absent PK (`0` columns)
/// has nothing to target. Both are refused with `table_no_primary_key` rather
/// than deleting and reporting success.
///
/// **Typed compare.** The id is bound as an [`UntypedTextParam`], so PG
/// infers the parameter as the PK column's type and coerces the string with
/// that type's input function (the same wire semantics as the TS backend's
/// `pg` driver): index-scan deletes and canonical per-type semantics — any
/// valid uuid spelling matches, citext keeps case-insensitivity, `'007'`
/// matches bigint row `7`. An id that cannot be a value of the PK type
/// (`22P02`/`22003`) maps to the same masked 404 as a typed miss.
///
/// The delete runs inside a [`timed_transaction`], committed **before** the
/// audit emit so the trail never claims a delete that failed at commit.
/// Every successful delete emits a `db_admin_row_delete` audit event
/// (pool-routed, account-grain — the gate resolves no actor; metadata
/// `{table, pk_column, id}` — `id` being the deleted row's canonical
/// `::text` rendering read back via `RETURNING`, not the URL-supplied
/// spelling — plus the client IP when one is threaded): the trail for the
/// trail-adjacent surface. Refusals emit nothing.
///
/// # Errors
///
/// Returns the denial `Response` (`Err`): 404 `table_not_found` (missing,
/// unlisted, or floor — masked identically) / `row_not_found`, 400
/// `table_not_deletable` (policy exclusion) / `table_no_primary_key` (absent
/// or composite PK), 409 `foreign_key_violation`, or a logged 500.
async fn perform_row_delete(
    client: &mut deadpool_postgres::Client,
    audit: &Arc<AuditEmitter>,
    options: RowDeleteOptions<'_>,
) -> Result<Response, Response> {
    let RowDeleteOptions {
        name,
        id,
        browsable_tables,
        non_deletable_tables,
        account_id,
        ip,
    } = options;

    // An unbrowsable table exposes no rows to delete either — same masked
    // gate prologue as the detail read.
    let tx = open_browsable_tx(client, name, browsable_tables, "db.delete tx").await?;

    // Policy exclusion, checked before the key shape: the trail and the
    // framework's singleton bookkeeping rows are never row-deletable through
    // a generic storage endpoint (see [`NON_DELETABLE_TABLES`]). 400 rather
    // than 403 — this says nothing about the caller's authority; like the
    // key-shape refusal below it answers "this table exposes no deletable
    // row here".
    if is_non_deletable(name, non_deletable_tables) {
        return Err(rest_error_response(
            StatusCode::BAD_REQUEST,
            "table_not_deletable",
        ));
    }

    let pk_columns = query_primary_key(&tx, name)
        .await
        .map_err(|e| internal_error_response_with_source("db.delete pk", &e))?;
    // Exactly one PK column, or refuse — a composite/absent PK is not safely
    // single-column-deletable through this generic endpoint (see the fn doc).
    let [primary_key] = pk_columns.as_slice() else {
        return Err(rest_error_response(
            StatusCode::BAD_REQUEST,
            "table_no_primary_key",
        ));
    };

    // Defense-in-depth: the PK column name comes from `information_schema` for an
    // already-validated table, but it's still interpolated into the DELETE, so
    // hold it to the same identifier invariant the table name passes — never
    // trust a catalog string blindly into raw SQL.
    if !is_valid_sql_identifier(primary_key) {
        tracing::error!(
            table = %name,
            column = %primary_key,
            "db.delete: catalog returned a non-identifier primary key column",
        );
        return Err(internal_error_response());
    }

    // Typed compare — the id travels as an untyped text-format parameter
    // ([`UntypedTextParam`]), so the server coerces it to the PK column's
    // type (uuid / int / text / …) and the delete index-scans. `RETURNING
    // "<pk>"::text` reads back only the PK cell — the deleted row's other
    // values (e.g. a bytea column) are never materialized — giving the
    // audit trail the row's canonical PK rendering.
    let delete_sql = format!(
        "DELETE FROM \"{name}\" WHERE \"{primary_key}\" = $1 RETURNING \"{primary_key}\"::text AS pk_text"
    );
    match tx.query(&delete_sql, &[&UntypedTextParam(id)]).await {
        Ok(rows) if rows.is_empty() => {
            Err(rest_error_response(StatusCode::NOT_FOUND, "row_not_found"))
        }
        Ok(rows) => {
            let deleted_id: String = rows[0].get(0);
            // Commit before emitting — the audit row must never claim a
            // delete that failed at commit.
            commit_checked(tx)
                .await
                .map_err(|e| internal_error_response_with_source("db.delete commit", &e))?;
            // Awaited so the row is observable by response time (the spine
            // REST idiom — see `account_login`).
            let _ = audit
                .emit(
                    AuditLogInput::for_event(AuditEventType::DbAdminRowDelete)
                        .account(account_id)
                        .ip(Some(ip.to_owned()))
                        .metadata(
                            json!({"table": name, "pk_column": primary_key, "id": deleted_id}),
                        ),
                )
                .await;
            Ok(Json(json!({"success": true})).into_response())
        }
        // 22P02 invalid_text_representation / 22003 numeric_value_out_of_range
        // / 22021 character_not_in_repertoire (a NUL byte in the id): the id
        // cannot be coerced to the PK column's type — or cannot even be a
        // text value — so no row can match; the same masked 404 as a typed
        // miss.
        Err(e)
            if matches!(
                classify_pg_error(&e),
                PgErrorKind::InvalidTextRepresentation
                    | PgErrorKind::NumericValueOutOfRange
                    | PgErrorKind::CharacterNotInRepertoire
            ) =>
        {
            Err(rest_error_response(StatusCode::NOT_FOUND, "row_not_found"))
        }
        // 23503 foreign_key_violation / 23001 restrict_violation — the same
        // referencing-row refusal. Which one depends on the constraint: `ON
        // DELETE RESTRICT` raises 23001 on PG 18 (23503 on ≤17), and `NO
        // ACTION` — the default, when the constraint names no action — raises
        // 23503 on every version. The TS twin's in-memory engines (PGlite,
        // pglet) raise the same codes as PG 18.
        Err(e)
            if matches!(
                classify_pg_error(&e),
                PgErrorKind::ForeignKeyViolation | PgErrorKind::RestrictViolation
            ) =>
        {
            Err(rest_error_response(
                StatusCode::CONFLICT,
                "foreign_key_violation",
            ))
        }
        Err(e) => Err(internal_error_response_with_source("db.delete exec", &e)),
    }
}

/// Whether a `public`-schema table exists. `Err` is a logged 500. Generic
/// over [`GenericClient`] so both pooled clients and open transactions work.
async fn table_exists(client: &impl GenericClient, name: &str) -> Result<bool, Response> {
    client
        .query_opt(
            "SELECT 1 FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = $1",
            &[&name],
        )
        .await
        .map(|row| row.is_some())
        .map_err(|e| internal_error_response_with_source("db.table_exists", &e))
}

/// Resolve a table's primary-key column names, in key order
/// (`key_column_usage.ordinal_position`). Empty when the table has no primary
/// key; length `> 1` for a composite primary key.
///
/// Every column is returned (no `LIMIT`) so callers can see the full key shape:
/// the row-`DELETE` endpoint acts **only** on a single-column primary key, and
/// a `LIMIT 1` (with no `ORDER BY`) would hide a composite PK behind one
/// arbitrary column, causing single-column deletes to over-match — see
/// [`perform_row_delete`].
async fn query_primary_key(
    client: &impl GenericClient,
    table: &str,
) -> Result<Vec<String>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT kcu.column_name \
             FROM information_schema.table_constraints tc \
             JOIN information_schema.key_column_usage kcu \
               ON tc.constraint_name = kcu.constraint_name \
               AND tc.table_schema = kcu.table_schema \
               AND tc.table_name = kcu.table_name \
             WHERE tc.constraint_type = 'PRIMARY KEY' \
               AND tc.table_schema = 'public' AND tc.table_name = $1 \
             ORDER BY kcu.ordinal_position",
            &[&table],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// PG-backed pins for the row-`DELETE` path (`FUZ_DB_ADMIN_TEST_URL`, default
/// `postgres://localhost/fuz_db_admin_test`). `#[ignore]`-gated, single-threaded
/// (each test drops + recreates `public`):
///
/// ```text
/// createdb fuz_db_admin_test
/// FUZ_DB_ADMIN_TEST_URL=postgres://localhost/fuz_db_admin_test \
///   cargo test -p fuz_db_admin -- --ignored --test-threads=1
/// ```
///
/// These drive [`perform_row_delete`] directly (the auth gate is exercised by
/// the cross-backend suites) so the real `DELETE` SQL runs against real
/// Postgres: the safety property is that a composite-PK delete is refused and
/// deletes **nothing** — a `LIMIT 1` (no `ORDER BY`) PK query would
/// pick one arbitrary column and `WHERE "<col>" = $1` would over-delete
/// every row sharing its value.
/// The origin check comes first on every route — no database: the pool below
/// never dials, and a refusal at the gate comes before any checkout.
#[cfg(test)]
mod origin_gate_tests {
    use super::*;

    fn state() -> DbAdminRouteState {
        let pool = fuz_db::create_pool(
            "postgres://nobody@127.0.0.1:1/nothing",
            &fuz_db::PoolOptions::default(),
        )
        .unwrap();
        DbAdminRouteState {
            gate: fuz_testing::testing_auth_gate(pool.clone()),
            required_role: fuz_auth::ROLE_ADMIN,
            credential_gate: CredentialGate::SESSION_ONLY,
            browsable_tables: &["scratch"],
            non_deletable_tables: &[],
            audit: Arc::new(AuditEmitter::new(pool)),
        }
    }

    fn headers(origin: Option<&'static str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(origin) = origin {
            headers.insert(
                axum::http::header::ORIGIN,
                axum::http::HeaderValue::from_static(origin),
            );
        }
        headers
    }

    async fn body(response: Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// Each handler answers `Result<Response, Response>`; either arm is the
    /// response.
    async fn answer(result: Result<Response, Response>) -> (StatusCode, String) {
        body(result.unwrap_or_else(|response| response)).await
    }

    /// Every route refuses a foreign `Origin` with the flat `forbidden_origin`
    /// 403 — ahead of the params gate (an invalid table name beside it) and
    /// the query gate (an unknown key beside it) — and the row `DELETE` among
    /// them.
    #[tokio::test]
    async fn every_route_refuses_a_foreign_origin_first() {
        let forbidden = (
            StatusCode::FORBIDDEN,
            r#"{"error":"forbidden_origin"}"#.to_owned(),
        );
        let foreign = || headers(Some("https://evil.example"));
        let bad_query = || Query(vec![("nope".to_owned(), "1".to_owned())]);
        assert_eq!(
            answer(handle_health(State(state()), bad_query(), None, foreign()).await).await,
            forbidden
        );
        assert_eq!(
            answer(handle_tables(State(state()), bad_query(), None, foreign()).await).await,
            forbidden
        );
        assert_eq!(
            answer(
                handle_table_detail(
                    State(state()),
                    Path("not a table".to_owned()),
                    bad_query(),
                    None,
                    foreign(),
                )
                .await
            )
            .await,
            forbidden
        );
        assert_eq!(
            answer(
                handle_row_delete(
                    State(state()),
                    Path(("not a table".to_owned(), "1".to_owned())),
                    bad_query(),
                    None,
                    foreign(),
                )
                .await
            )
            .await,
            forbidden
        );
    }

    /// The control: an allowed origin, or none, reaches the next gate — the
    /// query refusal here.
    #[tokio::test]
    async fn an_allowed_or_absent_origin_reaches_the_next_gate() {
        for origin in [None, Some(fuz_testing::TESTING_ALLOWED_ORIGIN)] {
            let response = handle_tables(
                State(state()),
                Query(vec![("nope".to_owned(), "1".to_owned())]),
                None,
                headers(origin),
            )
            .await;
            assert_eq!(
                answer(response).await.0,
                StatusCode::BAD_REQUEST,
                "{origin:?}"
            );
        }
    }

    /// A credential checkout that fails is not an unauthenticated request: a
    /// signed cookie sends the cookie leg to the dead pool, and the route
    /// answers the database-unavailable 503 — the TS twin's, where the
    /// `DbCheckoutError` throws out of the auth middleware into `onError` —
    /// not the 401.
    #[tokio::test]
    async fn a_failed_credential_checkout_answers_the_503() {
        let set_cookie = fuz_auth::sign_session_cookie(
            &fuz_testing::testing_keyring(),
            &fuz_auth::generate_session_token(),
            fuz_auth::SESSION_COOKIE_NAME,
        );
        let mut headers = headers(None);
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(set_cookie.split(';').next().unwrap()).unwrap(),
        );
        let response = handle_tables(State(state()), Query(Vec::new()), None, headers).await;
        let response = response.unwrap_or_else(|response| response);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            body(response).await,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"service_unavailable"}"#.to_owned()
            )
        );
    }
}

#[cfg(test)]
mod row_delete_pg_tests {
    use super::*;
    use fuz_db::Pool;
    use fuz_testing::{TestingDbOptions, fresh_test_db_pool};

    /// This suite's database: `FUZ_DB_ADMIN_TEST_URL` (default
    /// `fuz_db_admin_test`), the real `fuz_auth::AUTH_MIGRATIONS`
    /// (single-sourced spine DDL — a hand-copied
    /// `audit_log`/`schema_version` snippet could drift silently; this also
    /// creates the credential-floor tables, so the masking tests exercise the
    /// real names), then one single-PK + one composite-PK + one bytea scratch
    /// table (text keys — the multi-column PK count, not the column types, is
    /// what the delete logic turns on; the real spine composite tables
    /// `cell_field (source_id, name)` etc. are the motivation) plus uuid- and
    /// bigint-keyed scratch tables for the typed-compare semantics (coercion
    /// failure → masked 404, non-canonical spellings match, canonical audit
    /// `id`) and a RESTRICT-FK pair for the 409 path.
    const DB: TestingDbOptions<'static> = TestingDbOptions {
        env_var: "FUZ_DB_ADMIN_TEST_URL",
        default_db: "fuz_db_admin_test",
        migrations: &[fuz_auth::AUTH_MIGRATIONS],
        setup_sql: Some(
            "CREATE TABLE scratch_single (id text PRIMARY KEY, label text); \
             CREATE TABLE scratch_composite \
               (source_id text, name text, value text, PRIMARY KEY (source_id, name)); \
             CREATE DOMAIN scratch_blob_dom AS bytea; \
             CREATE TABLE scratch_bytea \
               (id text PRIMARY KEY, data bytea, data_dom scratch_blob_dom, note text); \
             CREATE TABLE scratch_uuid (id uuid PRIMARY KEY, label text); \
             CREATE TABLE scratch_int (id bigint PRIMARY KEY, label text); \
             CREATE TABLE scratch_fk_parent (id text PRIMARY KEY, name text); \
             CREATE TABLE scratch_fk_child \
               (id text PRIMARY KEY, parent_id text NOT NULL \
                REFERENCES scratch_fk_parent(id) ON DELETE RESTRICT); \
             CREATE TABLE scratch_fk_no_action_child \
               (id text PRIMARY KEY, parent_id text NOT NULL \
                REFERENCES scratch_fk_parent(id));",
        ),
    };

    /// Reset `public`, run the auth chain, and stand up the scratch tables.
    async fn fresh_pool() -> Pool {
        fresh_test_db_pool(DB).await
    }

    /// Default allowlist for the suite. Deliberately includes `account` — the
    /// credential floor must subtract it even when listed. `actor` exists
    /// (via the auth migrations) but is deliberately absent, as the
    /// unlisted-but-existing masking target.
    const TEST_BROWSABLE: &[&str] = &[
        "scratch_single",
        "scratch_composite",
        "scratch_bytea",
        "scratch_uuid",
        "scratch_int",
        "scratch_fk_parent",
        "scratch_fk_child",
        "audit_log",
        "schema_version",
        "account",
    ];

    /// [`RowDeleteOptions`] with the suite's allowlist and an unresolved IP.
    fn delete_options<'a>(
        name: &'a str,
        id: &'a str,
        non_deletable_tables: &'a [&'a str],
        account_id: uuid::Uuid,
    ) -> RowDeleteOptions<'a> {
        RowDeleteOptions {
            name,
            id,
            browsable_tables: TEST_BROWSABLE,
            non_deletable_tables,
            account_id,
            ip: fuz_http::UNRESOLVED_CLIENT_IP,
        }
    }

    /// [`TableDetailOptions`] with the suite's allowlist and default paging.
    fn detail_options(name: &str) -> TableDetailOptions<'_> {
        TableDetailOptions {
            name,
            offset: 0,
            limit: DB_TABLE_ROWS_DEFAULT_LIMIT,
            browsable_tables: TEST_BROWSABLE,
            non_deletable_tables: &[],
        }
    }

    /// Consume a success `Response`, returning its JSON body.
    async fn body_json(resp: Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    /// Audit emitter over the scratch pool + a fixed account id for
    /// attribution assertions.
    fn test_audit(pool: &Pool) -> (Arc<AuditEmitter>, uuid::Uuid) {
        (
            Arc::new(AuditEmitter::new(pool.clone())),
            uuid::Uuid::from_u128(0xdb_ad),
        )
    }

    /// Consume a denial `Response`, returning its `error` code string.
    async fn error_code(resp: Response) -> String {
        body_json(resp)
            .await
            .get("error")
            .and_then(Value::as_str)
            .expect("error field")
            .to_owned()
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn primary_key_query_returns_all_columns_in_key_order() {
        let pool = fresh_pool().await;
        let client = pool.get().await.unwrap();
        assert_eq!(
            query_primary_key(&client, "scratch_single").await.unwrap(),
            vec!["id".to_owned()],
        );
        assert_eq!(
            query_primary_key(&client, "scratch_composite")
                .await
                .unwrap(),
            vec!["source_id".to_owned(), "name".to_owned()],
            "composite PK returns every column, ordered — not one arbitrary column",
        );
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn single_pk_delete_removes_only_the_targeted_row() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO scratch_single (id, label) VALUES ('keep-1', 'keep'), ('target-1', 'target')",
                &[],
            )
            .await
            .unwrap();

        let (audit, account_id) = test_audit(&pool);
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_single", "target-1", &[], account_id),
        )
        .await
        .expect("single-PK delete succeeds");
        assert_eq!(resp.status(), StatusCode::OK);

        let remaining = client
            .query("SELECT id FROM scratch_single", &[])
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1, "exactly one row deleted");
        let remaining_id: String = remaining[0].get(0);
        assert_eq!(remaining_id, "keep-1", "the untargeted row survives");
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn uncoercible_id_is_the_masked_row_not_found() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .batch_execute(
                "INSERT INTO scratch_uuid (id, label) \
                   VALUES ('a3bb189e-8bf9-3888-9912-ace4e6543002', 'kept'); \
                 INSERT INTO scratch_int (id, label) VALUES (7, 'kept');",
            )
            .await
            .unwrap();
        let (audit, account_id) = test_audit(&pool);

        // 22P02 invalid_text_representation — not a uuid at all
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_uuid", "not-a-uuid", &[], account_id),
        )
        .await
        .expect_err("uncoercible uuid id refuses");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(resp).await, "row_not_found");

        // 22003 numeric_value_out_of_range — digits beyond int8
        let mut client = pool.get().await.unwrap();
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_int", "99999999999999999999", &[], account_id),
        )
        .await
        .expect_err("over-range int id refuses");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(resp).await, "row_not_found");

        // 22021 character_not_in_repertoire — a NUL byte is rejected by the
        // server encoding before any type coercion, even against a text PK
        let mut client = pool.get().await.unwrap();
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_single", "\u{0}abc", &[], account_id),
        )
        .await
        .expect_err("NUL-byte id refuses");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(resp).await, "row_not_found");

        let client = pool.get().await.unwrap();
        let counts: i64 = client
            .query_one(
                "SELECT (SELECT COUNT(*) FROM scratch_uuid) + (SELECT COUNT(*) FROM scratch_int)",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(counts, 2, "no row deleted by an uncoercible id");
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn typed_compare_matches_spellings_and_audits_the_canonical_id() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .batch_execute(
                "INSERT INTO scratch_uuid (id, label) \
                   VALUES ('a3bb189e-8bf9-3888-9912-ace4e6543002', 'target'); \
                 INSERT INTO scratch_int (id, label) VALUES (7, 'target');",
            )
            .await
            .unwrap();
        let (audit, account_id) = test_audit(&pool);

        // Any valid uuid spelling matches (the `::text` compare this replaced
        // would 404 — uuid renders lowercase); the trail records the canonical
        // rendering via `RETURNING "<pk>"::text`.
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options(
                "scratch_uuid",
                "A3BB189E-8BF9-3888-9912-ACE4E6543002",
                &[],
                account_id,
            ),
        )
        .await
        .expect("uppercase uuid spelling deletes");
        assert_eq!(resp.status(), StatusCode::OK);

        // '007' coerces to 7 and matches — the accepted cost of the typed
        // compare; the audit id is canonical, not the padded spelling.
        let mut client = pool.get().await.unwrap();
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_int", "007", &[], account_id),
        )
        .await
        .expect("zero-padded int spelling deletes");
        assert_eq!(resp.status(), StatusCode::OK);

        let client = pool.get().await.unwrap();
        let rows = client
            .query(
                "SELECT metadata->>'table', metadata->>'id' FROM audit_log \
                 WHERE event_type = 'db_admin_row_delete' ORDER BY metadata->>'table'",
                &[],
            )
            .await
            .unwrap();
        let audited: Vec<(String, String)> = rows
            .iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
            .collect();
        assert_eq!(
            audited,
            vec![
                ("scratch_int".to_owned(), "7".to_owned()),
                (
                    "scratch_uuid".to_owned(),
                    "a3bb189e-8bf9-3888-9912-ace4e6543002".to_owned(),
                ),
            ],
            "the audited id is the row's canonical PK rendering, not the URL spelling",
        );
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn restricted_fk_delete_is_a_409_and_deletes_nothing() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .batch_execute(
                "INSERT INTO scratch_fk_parent (id, name) VALUES ('p-1', 'parent'); \
                 INSERT INTO scratch_fk_child (id, parent_id) VALUES ('c-1', 'p-1');",
            )
            .await
            .unwrap();
        let (audit, account_id) = test_audit(&pool);

        // The RESTRICT-referenced parent refuses with the scrubbed 409 (the
        // TS twin has the same case; PG detail/constraint never leak).
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_fk_parent", "p-1", &[], account_id),
        )
        .await
        .expect_err("RESTRICT-referenced parent refuses");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(
            body,
            json!({"error": "foreign_key_violation"}),
            "scrubbed envelope only"
        );

        let client = pool.get().await.unwrap();
        let count: i64 = client
            .query_one("SELECT COUNT(*)::bigint FROM scratch_fk_parent", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "the referenced parent survives");
        let audited: i64 = client
            .query_one(
                "SELECT COUNT(*)::bigint FROM audit_log WHERE event_type = 'db_admin_row_delete'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(audited, 0, "a refused delete is not audited");
    }

    /// The other referencing-row refusal: a constraint that names no action is
    /// `NO ACTION`, which raises 23503 `foreign_key_violation` where `RESTRICT`
    /// raises 23001 on PG 18. Same scrubbed 409 either way.
    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn no_action_fk_delete_is_a_409_and_deletes_nothing() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .batch_execute(
                "INSERT INTO scratch_fk_parent (id, name) VALUES ('p-1', 'parent'); \
                 INSERT INTO scratch_fk_no_action_child (id, parent_id) VALUES ('c-1', 'p-1');",
            )
            .await
            .unwrap();

        // The arm under test is the 23503 one: confirm the engine raises it
        // for this constraint, so the case can't pass on the 23001 arm alone.
        let raw = client
            .execute("DELETE FROM scratch_fk_parent WHERE id = 'p-1'", &[])
            .await
            .expect_err("the referenced parent refuses a raw delete");
        assert_eq!(
            raw.code(),
            Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION),
            "a NO ACTION constraint raises 23503"
        );

        let (audit, account_id) = test_audit(&pool);
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_fk_parent", "p-1", &[], account_id),
        )
        .await
        .expect_err("NO ACTION-referenced parent refuses");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(
            body,
            json!({"error": "foreign_key_violation"}),
            "scrubbed envelope only"
        );

        let client = pool.get().await.unwrap();
        let count: i64 = client
            .query_one("SELECT COUNT(*)::bigint FROM scratch_fk_parent", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "the referenced parent survives");
        let audited: i64 = client
            .query_one(
                "SELECT COUNT(*)::bigint FROM audit_log WHERE event_type = 'db_admin_row_delete'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(audited, 0, "a refused delete is not audited");
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn composite_pk_delete_is_refused_and_deletes_nothing() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        // Three rows sharing the SAME `name` across different `source_id`s — the
        // exact over-delete trap: a single-column `WHERE "name" = 'title'`
        // would wipe all three.
        client
            .execute(
                "INSERT INTO scratch_composite (source_id, name, value) \
                 VALUES ('s1', 'title', 'a'), ('s2', 'title', 'b'), ('s3', 'title', 'c')",
                &[],
            )
            .await
            .unwrap();

        let (audit, account_id) = test_audit(&pool);
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_composite", "title", &[], account_id),
        )
        .await
        .expect_err("composite-PK delete must be refused");
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "composite PK is refused, not deleted",
        );
        assert_eq!(error_code(resp).await, "table_no_primary_key");

        let count: i64 = client
            .query_one("SELECT COUNT(*)::bigint FROM scratch_composite", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 3, "the composite-PK refusal must delete NOTHING");
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn builtin_non_deletable_table_is_refused_and_deletes_nothing() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        // Single-column PK — the key-shape gate would pass, so the refusal
        // must be the policy exclusion.
        let trail_id: String = client
            .query_one(
                "INSERT INTO audit_log (event_type) VALUES ('login') RETURNING id::text",
                &[],
            )
            .await
            .unwrap()
            .get(0);

        let (audit, account_id) = test_audit(&pool);
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("audit_log", &trail_id, &[], account_id),
        )
        .await
        .expect_err("builtin non-deletable table must be refused");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(resp).await, "table_not_deletable");

        let count: i64 = client
            .query_one("SELECT COUNT(*)::bigint FROM audit_log", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "the policy refusal must delete NOTHING");
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn non_deletable_refusal_precedes_the_key_shape_check() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        // `schema_version` is both excluded AND composite-keyed — the policy
        // exclusion is checked first, so its code wins (mirrors the TS
        // handler's ordering).
        let (audit, account_id) = test_audit(&pool);
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("schema_version", "fuz_auth", &[], account_id),
        )
        .await
        .expect_err("excluded table must be refused");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            error_code(resp).await,
            "table_not_deletable",
            "policy exclusion fires before the key-shape check",
        );
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn consumer_extension_unions_with_the_builtin_floor() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO scratch_single (id, label) VALUES ('target-1', 'x')",
                &[],
            )
            .await
            .unwrap();

        // The extension excludes a table the builtin floor doesn't…
        let (audit, account_id) = test_audit(&pool);
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options(
                "scratch_single",
                "target-1",
                &["scratch_single"],
                account_id,
            ),
        )
        .await
        .expect_err("consumer-excluded table must be refused");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(resp).await, "table_not_deletable");
        let count: i64 = client
            .query_one("SELECT COUNT(*)::bigint FROM scratch_single", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "the extension refusal must delete NOTHING");

        // …and never replaces the floor: builtin tables stay excluded with a
        // non-empty extension.
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("audit_log", "any-id", &["scratch_single"], account_id),
        )
        .await
        .expect_err("builtin floor must survive a consumer extension");
        assert_eq!(error_code(resp).await, "table_not_deletable");
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn successful_delete_emits_the_db_admin_row_delete_audit_event() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO scratch_single (id, label) VALUES ('target-1', 'x')",
                &[],
            )
            .await
            .unwrap();

        let (audit, account_id) = test_audit(&pool);
        let resp = perform_row_delete(
            &mut client,
            &audit,
            RowDeleteOptions {
                ip: "203.0.113.9",
                ..delete_options("scratch_single", "target-1", &[], account_id)
            },
        )
        .await
        .expect("single-PK delete succeeds");
        assert_eq!(resp.status(), StatusCode::OK);

        // The emit is awaited inside `perform_row_delete`, so the row is
        // already queryable.
        let row = client
            .query_one(
                "SELECT account_id::text, outcome, ip, metadata::text FROM audit_log \
                 WHERE event_type = 'db_admin_row_delete'",
                &[],
            )
            .await
            .expect("exactly one db_admin_row_delete audit row");
        let got_account: String = row.get(0);
        assert_eq!(got_account, account_id.to_string());
        let outcome: String = row.get(1);
        assert_eq!(outcome, "success");
        let ip: Option<String> = row.get(2);
        assert_eq!(
            ip.as_deref(),
            Some("203.0.113.9"),
            "the threaded client IP lands on the audit row (the closed last_used_ip residual)",
        );
        let metadata: Value = serde_json::from_str(row.get(3)).unwrap();
        assert_eq!(
            metadata,
            json!({"table": "scratch_single", "pk_column": "id", "id": "target-1"}),
        );
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn refused_deletes_emit_nothing() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        let (audit, account_id) = test_audit(&pool);

        // policy exclusion + composite-PK refusal + row-not-found
        let _ = perform_row_delete(
            &mut client,
            &audit,
            delete_options("schema_version", "x", &[], account_id),
        )
        .await
        .expect_err("excluded");
        let _ = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_composite", "x", &[], account_id),
        )
        .await
        .expect_err("composite");
        let _ = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_single", "missing", &[], account_id),
        )
        .await
        .expect_err("row not found");

        let count: i64 = client
            .query_one(
                "SELECT COUNT(*)::bigint FROM audit_log WHERE event_type = 'db_admin_row_delete'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 0, "only a successful delete is audited");
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn unbrowsable_delete_masks_as_table_not_found() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO account (username, password_hash) VALUES ('u', 'h')",
                &[],
            )
            .await
            .unwrap();

        let (audit, account_id) = test_audit(&pool);
        // exists (auth migrations) but absent from the allowlist
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("actor", "x", &[], account_id),
        )
        .await
        .expect_err("unlisted table must be masked");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(resp).await, "table_not_found");
        // exists AND listed in TEST_BROWSABLE, but on the credential floor
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("account", "x", &[], account_id),
        )
        .await
        .expect_err("floor table must be masked even when listed");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(resp).await, "table_not_found");
        // on BOTH floors — `bootstrap_lock` is non-browsable AND
        // non-deletable; the browsable mask must answer first (a 400
        // `table_not_deletable` here would confirm the credential table
        // exists and is specially protected)
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("bootstrap_lock", "x", &[], account_id),
        )
        .await
        .expect_err("double-floor table must be masked, not policy-refused");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(resp).await, "table_not_found");
        // truly missing — the masking reference: same status, same code
        let resp = perform_row_delete(
            &mut client,
            &audit,
            delete_options("scratch_missing", "x", &[], account_id),
        )
        .await
        .expect_err("missing table");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(resp).await, "table_not_found");

        let count: i64 = client
            .query_one("SELECT COUNT(*)::bigint FROM account", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "the floor row must survive");
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn detail_reports_null_primary_key_for_composite() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        let resp = perform_table_detail(&mut client, detail_options("scratch_composite"))
            .await
            .expect("detail succeeds");
        let body = body_json(resp).await;
        assert_eq!(
            body["primary_key"],
            Value::Null,
            "composite PK has no single deletable column",
        );
        assert_eq!(body["deletable"], Value::Bool(false));

        let resp = perform_table_detail(&mut client, detail_options("scratch_single"))
            .await
            .expect("detail succeeds");
        let body = body_json(resp).await;
        assert_eq!(body["primary_key"], json!("id"));
        assert_eq!(body["deletable"], Value::Bool(true));
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn detail_placeholders_bytea_values() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO scratch_bytea (id, data, data_dom, note) \
                 VALUES ('a', decode('deadbeef', 'hex'), decode('cafebabe99', 'hex'), 'x'), \
                        ('b', NULL, NULL, 'y')",
                &[],
            )
            .await
            .unwrap();

        let resp = perform_table_detail(&mut client, detail_options("scratch_bytea"))
            .await
            .expect("detail succeeds");
        let body = body_json(resp).await;
        // column metadata stays truthful
        let data_col = body["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["column_name"] == "data")
            .expect("data column present");
        assert_eq!(data_col["data_type"], json!("bytea"));
        // values are size placeholders; NULL stays NULL; neighbors untouched
        let rows = body["rows"].as_array().unwrap();
        let by_id = |id: &str| {
            rows.iter()
                .find(|r| r["id"] == json!(id))
                .unwrap_or_else(|| panic!("row {id}"))
        };
        assert_eq!(by_id("a")["data"], json!("<4 bytes>"));
        assert_eq!(by_id("a")["note"], json!("x"));
        assert_eq!(by_id("b")["data"], Value::Null);
        assert_eq!(by_id("b")["note"], json!("y"));
        // a DOMAIN over bytea resolves to `udt_name = 'bytea'` in
        // `information_schema.columns`, so the placeholder holds — pinned so
        // a consumer's domain-typed blob column can't silently reopen the
        // bytea egress amplification
        assert_eq!(by_id("a")["data_dom"], json!("<5 bytes>"));
        assert_eq!(by_id("b")["data_dom"], Value::Null);
    }

    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn detail_masks_unbrowsable_tables() {
        let pool = fresh_pool().await;
        let mut client = pool.get().await.unwrap();
        // unlisted-but-existing, floor-listed, and truly missing all answer
        // with the same masked 404 code
        for table in ["actor", "account", "scratch_missing"] {
            let resp = perform_table_detail(&mut client, detail_options(table))
                .await
                .expect_err("unbrowsable table must be masked");
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{table}");
            assert_eq!(error_code(resp).await, "table_not_found", "{table}");
        }
    }

    /// Route state over `pool` with the suite's allowlist — the shape a
    /// consumer mounts, session-only and admin-gated.
    fn route_state(pool: Pool) -> DbAdminRouteState {
        DbAdminRouteState {
            gate: fuz_testing::testing_auth_gate(pool.clone()),
            required_role: fuz_auth::ROLE_ADMIN,
            credential_gate: CredentialGate::SESSION_ONLY,
            browsable_tables: TEST_BROWSABLE,
            non_deletable_tables: &[],
            audit: Arc::new(AuditEmitter::new(pool)),
        }
    }

    /// Request headers carrying a session cookie for a seeded admin.
    async fn admin_headers(pool: &Pool, username: &str) -> HeaderMap {
        let (account_id, actor_id) = fuz_testing::seed_account_actor(pool, username).await;
        fuz_testing::grant_role(pool, actor_id, fuz_auth::ROLE_ADMIN).await;
        let cookie = fuz_testing::mint_session_cookie(
            pool,
            &fuz_testing::testing_keyring(),
            account_id,
            fuz_auth::SESSION_COOKIE_NAME,
        )
        .await;
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&cookie).unwrap(),
        );
        headers
    }

    /// Assert `result` is the flat 503 `service_unavailable`.
    async fn assert_unavailable(result: Result<Response, Response>, what: &str) {
        let response = result.unwrap_or_else(|response| response);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{what}");
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "{what}"
        );
        assert_eq!(
            body_json(response).await,
            json!({"error": "service_unavailable"}),
            "{what}"
        );
    }

    /// Every checkout after the credential's answers 503 when refused: the
    /// role gate's (a budget of one, spent by the credential read) on each
    /// route, then each handler's own (a budget of two, the role gate's
    /// spent too) — never the 500 of a failed read.
    #[tokio::test]
    #[ignore = "needs Postgres (FUZ_DB_ADMIN_TEST_URL)"]
    async fn a_refused_checkout_after_the_credential_answers_the_503() {
        let pool = fresh_pool().await;
        let headers = admin_headers(&pool, "db_admin_checkout").await;
        for (budget, phase) in [(1, "the role gate"), (2, "the handler")] {
            let state = || State(route_state(fuz_testing::budgeted_pool(&DB.url(), budget)));
            assert_unavailable(
                handle_tables(state(), Query(Vec::new()), None, headers.clone()).await,
                &format!("tables, {phase}"),
            )
            .await;
            assert_unavailable(
                handle_table_detail(
                    state(),
                    Path("scratch_single".to_owned()),
                    Query(Vec::new()),
                    None,
                    headers.clone(),
                )
                .await,
                &format!("detail, {phase}"),
            )
            .await;
            assert_unavailable(
                handle_row_delete(
                    state(),
                    Path(("scratch_single".to_owned(), "a".to_owned())),
                    Query(Vec::new()),
                    None,
                    headers.clone(),
                )
                .await,
                &format!("delete, {phase}"),
            )
            .await;
        }
    }
}
