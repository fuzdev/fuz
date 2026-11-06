//! Queries against the `actor` and `role_grant` tables.
//!
//! Owns both tables' [`ACTOR_COLUMNS`] / [`ROLE_GRANT_COLUMNS`] consts (the
//! twins of `fuz_app`'s, guarded against the live schema by the `columns`
//! integration test) and the one projection + one decoder each row shape
//! reads through — [`ActorRow`], [`RoleGrantRow`], the admin
//! [`RoleGrantSummary`] derived from the table const, and the two-table
//! [`ActorLookupRow`] shared with `actor_search_queries`. See
//! `account_queries` and the crate docs § Named projections for the
//! discipline.

use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};

use crate::account_queries::RoleGrantSummary;
use crate::actor_schema::ActorRow;
use crate::role_grant_schema::RoleGrantRow;

/// The `actor` table's columns.
///
/// Twin of `fuz_app`'s `ACTOR_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live
/// column.
pub const ACTOR_COLUMNS: [&str; 8] = [
    "id",
    "account_id",
    "name",
    "created_at",
    "updated_at",
    "updated_by",
    "deleted_at",
    "deleted_by",
];

/// The `role_grant` table's columns.
///
/// Twin of `fuz_app`'s `ROLE_GRANT_COLUMNS` (same names, same order). The
/// PG-gated `columns` integration test asserts this names every live
/// column. `role_grant_offer_queries` projects its narrow revoke shapes
/// from this table too; Rust module cycles don't bite, so the const stays
/// in this module rather than a DDL home (the TS placement exception).
pub const ROLE_GRANT_COLUMNS: [&str; 12] = [
    "id",
    "actor_id",
    "role",
    "scope_kind",
    "scope_id",
    "created_at",
    "expires_at",
    "revoked_at",
    "revoked_by",
    "revoked_reason",
    "granted_by",
    "source_offer_id",
];

/// [`ActorRow`] projection — the identity triple every actor read and
/// `RETURNING` carries.
const ACTOR_ROW_COLUMNS: [&str; 3] = ["id", "account_id", "name"];

/// [`RoleGrantRow`] projection — the narrow active-grant row the
/// per-request auth context carries for ACL checks.
const ROLE_GRANT_ROW_COLUMNS: [&str; 4] = ["id", "actor_id", "role", "scope_id"];

/// The [`ACTOR_ROW_COLUMNS`] projection on the bare table.
fn actor_row_columns() -> String {
    qualify_columns(&ACTOR_ROW_COLUMNS, "actor", |_| None)
}

/// Decode the [`actor_row_columns`] projection positionally.
fn decode_actor_row(row: &tokio_postgres::Row) -> ActorRow {
    ActorRow {
        id: row.get(col!(ACTOR_ROW_COLUMNS, "id")),
        account_id: row.get(col!(ACTOR_ROW_COLUMNS, "account_id")),
        name: row.get(col!(ACTOR_ROW_COLUMNS, "name")),
    }
}

/// The [`ROLE_GRANT_ROW_COLUMNS`] projection on the bare table.
fn role_grant_row_columns() -> String {
    qualify_columns(&ROLE_GRANT_ROW_COLUMNS, "role_grant", |_| None)
}

/// Decode the [`role_grant_row_columns`] projection positionally.
fn decode_role_grant_row(row: &tokio_postgres::Row) -> RoleGrantRow {
    RoleGrantRow {
        id: row.get(col!(ROLE_GRANT_ROW_COLUMNS, "id")),
        actor_id: row.get(col!(ROLE_GRANT_ROW_COLUMNS, "actor_id")),
        role: row.get(col!(ROLE_GRANT_ROW_COLUMNS, "role")),
        scope_id: row.get(col!(ROLE_GRANT_ROW_COLUMNS, "scope_id")),
    }
}

/// The [`RoleGrantSummary`] column list — [`ROLE_GRANT_COLUMNS`] minus the
/// revocation + provenance columns an active-grant summary doesn't carry
/// (mirrors TS `ADMIN_ROLE_GRANT_COLUMNS`); keeps `actor_id` so the admin
/// listing can group by it. A literal so [`decode_role_grant_summary_row`]
/// can `col!` into it; the unit test pins it to the `omit_columns`
/// derivation.
const ROLE_GRANT_SUMMARY_COLUMNS: [&str; 8] = [
    "id",
    "actor_id",
    "role",
    "scope_kind",
    "scope_id",
    "created_at",
    "expires_at",
    "granted_by",
];

/// The [`RoleGrantSummary`] projection ([`ROLE_GRANT_SUMMARY_COLUMNS`]),
/// timestamps as ISO-8601 wire strings.
pub(crate) fn role_grant_summary_columns(alias: &str) -> String {
    qualify_columns(
        &ROLE_GRANT_SUMMARY_COLUMNS,
        alias,
        iso8601_timestamp_expr(
            &ROLE_GRANT_SUMMARY_COLUMNS,
            &["created_at", "expires_at"],
            alias,
        ),
    )
}

/// Decode the [`role_grant_summary_columns`] projection positionally into
/// `(actor_id, summary)`.
pub(crate) fn decode_role_grant_summary_row(
    row: &tokio_postgres::Row,
) -> (uuid::Uuid, RoleGrantSummary) {
    (
        row.get(col!(ROLE_GRANT_SUMMARY_COLUMNS, "actor_id")),
        RoleGrantSummary {
            id: row.get(col!(ROLE_GRANT_SUMMARY_COLUMNS, "id")),
            role: row.get(col!(ROLE_GRANT_SUMMARY_COLUMNS, "role")),
            scope_kind: row.get(col!(ROLE_GRANT_SUMMARY_COLUMNS, "scope_kind")),
            scope_id: row.get(col!(ROLE_GRANT_SUMMARY_COLUMNS, "scope_id")),
            created_at: row.get(col!(ROLE_GRANT_SUMMARY_COLUMNS, "created_at")),
            expires_at: row.get(col!(ROLE_GRANT_SUMMARY_COLUMNS, "expires_at")),
            granted_by: row.get(col!(ROLE_GRANT_SUMMARY_COLUMNS, "granted_by")),
        },
    )
}

/// The [`ActorLookupRow`] projection over the `act`-aliased `actor` ⨝
/// `a`-aliased `account` JOIN — a two-table shape, so spelled once here
/// rather than derived from either table const. Shared with
/// `actor_search_queries` (which sorts by the `display_name` alias); decoded
/// positionally by [`decode_actor_lookup_row`].
pub(crate) const ACTOR_LOOKUP_PROJECTION: &str = "act.id, a.username, act.name AS display_name";

/// Decode the [`ACTOR_LOOKUP_PROJECTION`] positionally.
pub(crate) fn decode_actor_lookup_row(row: &tokio_postgres::Row) -> ActorLookupRow {
    ActorLookupRow {
        id: row.get(0),
        username: row.get(1),
        display_name: row.get(2),
    }
}

/// Result of [`resolve_acting_actor`] — the resolved actor or a structured
/// failure the dispatcher's authorization phase maps to a wire error.
///
/// Ports `fuz_app`'s `ResolveActingActorResult`. The actor binds at the
/// authorization phase from the request's `acting` input, not eagerly at
/// credential resolution.
#[derive(Debug)]
pub enum ResolveActingActorResult {
    /// The acting actor — a single-actor account, or `acting` named one on it.
    Resolved(ActorRow),
    /// The account enumerated zero actors (server-invariant violation → 500).
    NoActors,
    /// Multiple actors and no `acting` pick → 400 with the available list.
    ActorRequired {
        /// Every actor on the account, in stable `(created_at, id)` order.
        available: Vec<ActorRow>,
    },
    /// `acting` named an actor that isn't on the account → 400 (opaque).
    ActorNotOnAccount,
}

/// Resolve the acting actor for an authenticated request.
///
/// Ports `fuz_app`'s `resolve_acting_actor`. Rules:
///
/// - `acting` omitted + 1 actor → use it.
/// - `acting` omitted + 0 actors → [`NoActors`](ResolveActingActorResult::NoActors).
/// - `acting` omitted + >1 actor → [`ActorRequired`](ResolveActingActorResult::ActorRequired)
///   with the available list — never a silent pick.
/// - `acting` present + on the account → use it.
/// - `acting` present + foreign → [`ActorNotOnAccount`](ResolveActingActorResult::ActorNotOnAccount).
///
/// Resolves over [`query_active_actors_by_account`] (`deleted_at IS NULL`):
/// a soft-deleted (tombstoned) actor is never resolvable as the acting actor,
/// so it can't carry its `role_grants` into the role gate.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn resolve_acting_actor(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    acting: Option<uuid::Uuid>,
) -> Result<ResolveActingActorResult, tokio_postgres::Error> {
    let mut actors = query_active_actors_by_account(client, account_id).await?;
    if actors.is_empty() {
        return Ok(ResolveActingActorResult::NoActors);
    }
    if let Some(acting_id) = acting {
        return Ok(actors.into_iter().find(|a| a.id == acting_id).map_or(
            ResolveActingActorResult::ActorNotOnAccount,
            ResolveActingActorResult::Resolved,
        ));
    }
    if actors.len() == 1 {
        Ok(ResolveActingActorResult::Resolved(actors.remove(0)))
    } else {
        Ok(ResolveActingActorResult::ActorRequired { available: actors })
    }
}

/// List every actor on an account (newest-deterministic order), **including
/// soft-deleted (tombstoned) rows**.
///
/// Used by the account delete/purge/undelete handlers to emit a per-actor
/// `actor_delete` / `actor_purge` / `actor_undelete` event carrying each
/// actor's name snapshot. Includes already-soft-deleted actors so a purge
/// still records every actor that ever existed on the account; the
/// soft-delete path no-ops on rows already tombstoned via the per-actor
/// UPDATE guard. For the acting-actor resolution path — which must never
/// resolve a tombstoned actor — use [`query_active_actors_by_account`].
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_actors_by_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Vec<ActorRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM actor
         WHERE account_id = $1
         ORDER BY created_at ASC, id ASC",
        columns = actor_row_columns(),
    );
    let rows = client.query(&sql, &[account_id]).await?;
    Ok(rows.iter().map(decode_actor_row).collect())
}

/// List **active** (non-tombstoned) actors on an account, newest-deterministic
/// order.
///
/// Filters `deleted_at IS NULL` so a soft-deleted actor can never be resolved
/// as the acting actor (and carry its `role_grants` into the role gate). Used
/// by [`resolve_acting_actor`] — the security-relevant resolution path. The
/// admin/snapshot handlers that legitimately need tombstoned rows stay on the
/// unfiltered [`query_actors_by_account`].
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_active_actors_by_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
) -> Result<Vec<ActorRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM actor
         WHERE account_id = $1
           AND deleted_at IS NULL
         ORDER BY created_at ASC, id ASC",
        columns = actor_row_columns(),
    );
    let rows = client.query(&sql, &[account_id]).await?;
    Ok(rows.iter().map(decode_actor_row).collect())
}

/// Batch-list every actor on any of `account_ids` (tombstoned included).
///
/// The admin account listing's actors fan-out, ordered `created_at, name, id`,
/// so the caller indexing by `account_id` can keep each account's oldest.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_actors_for_accounts(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_ids: &[uuid::Uuid],
) -> Result<Vec<ActorRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM actor WHERE account_id = ANY($1::uuid[])
         ORDER BY created_at ASC, name ASC, id ASC",
        columns = actor_row_columns(),
    );
    let rows = client.query(&sql, &[&account_ids]).await?;
    Ok(rows.iter().map(decode_actor_row).collect())
}

/// Soft-delete one actor (sets `deleted_at`).
///
/// Returns `true` when an
/// active row flipped, `false` when none matched (missing or already
/// soft-deleted). Mirrors [`crate::account_queries::query_account_soft_delete`]
/// at the actor grain.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_actor_soft_delete(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: &uuid::Uuid,
    deleted_by: Option<&uuid::Uuid>,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "UPDATE actor SET deleted_at = NOW(), deleted_by = $2
             WHERE id = $1 AND deleted_at IS NULL
             RETURNING id",
            &[actor_id, &deleted_by],
        )
        .await?;
    Ok(row.is_some())
}

/// Reactivate one soft-deleted actor (clears `deleted_at` / `deleted_by`).
///
/// Returns `true` when a soft-deleted row flipped back, `false` when none
/// matched. Emitted per actor alongside the account-level reactivation.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_actor_undelete(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: &uuid::Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "UPDATE actor SET deleted_at = NULL, deleted_by = NULL
             WHERE id = $1 AND deleted_at IS NOT NULL
             RETURNING id",
            &[actor_id],
        )
        .await?;
    Ok(row.is_some())
}

/// Look up active (non-revoked, non-expired) role grants for an actor.
///
/// Tombstone-blind — call only off a resolved active actor.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_role_grant_find_active_for_actor(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: &uuid::Uuid,
) -> Result<Vec<RoleGrantRow>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns} FROM role_grant
         WHERE actor_id = $1
           AND {active}
         ORDER BY created_at",
        columns = role_grant_row_columns(),
        active = crate::role_grant_active_sql("role_grant"),
    );
    let rows = client.query(&sql, &[actor_id]).await?;
    Ok(rows.iter().map(decode_role_grant_row).collect())
}

/// Whether `actor_id` holds an active **global** (`scope_id IS NULL`) grant
/// for any of `roles`, counting it only while the **actor and its account are
/// both active** (`deleted_at IS NULL`).
///
/// The WS upgrade's `required_roles` gate and its admission re-read
/// (`fuz_actions`'s `register_action_ws`). The gate resolves an active acting
/// actor first, but the re-read runs after the handshake: an actor
/// soft-deleted in between keeps its `role_grant` rows (soft delete is
/// reversible, so it revokes nothing). Admission re-checks the acting actor
/// itself before this read, on every endpoint, and refuses a tombstoned one
/// as a dead credential; the filter here keeps the grant read from counting
/// such an actor's grants wherever it is called.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_active_actor_holds_any_global_role(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: &uuid::Uuid,
    roles: &[&str],
) -> Result<bool, tokio_postgres::Error> {
    let sql = format!(
        "SELECT EXISTS(
            SELECT 1 FROM role_grant rg
            JOIN actor act ON act.id = rg.actor_id
            JOIN account a ON a.id = act.account_id
            WHERE act.id = $1
              AND act.deleted_at IS NULL
              AND a.deleted_at IS NULL
              AND rg.role = ANY($2)
              AND rg.scope_id IS NULL
              AND {rg_active}
         ) AS exists",
        rg_active = crate::role_grant_active_sql("rg"),
    );
    let row = client.query_one(&sql, &[actor_id, &roles]).await?;
    Ok(row.get(0))
}

/// List active role-grant **summaries** for an actor.
///
/// Returns the full [`RoleGrantSummary`] shape (`id, role, scope_kind,
/// scope_id, created_at, expires_at, granted_by`), mirroring TS
/// `RoleGrantSummaryJson`. Same active filter and projection
/// (`role_grant_summary_columns`) as the admin account-listing query
/// (`query_admin_account_list`), scoped to one actor. Used by
/// `GET /api/account/status` (which returns the full summary), distinct
/// from [`query_role_grant_find_active_for_actor`] (the narrow `RoleGrantRow` the
/// per-request auth context carries for ACL checks).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_role_grant_summaries_for_actor(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: &uuid::Uuid,
) -> Result<Vec<RoleGrantSummary>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {columns}
         FROM role_grant
         WHERE actor_id = $1
           AND {active}
         ORDER BY created_at",
        columns = role_grant_summary_columns("role_grant"),
        active = crate::role_grant_active_sql("role_grant"),
    );
    let rows = client.query(sql.as_str(), &[actor_id]).await?;
    Ok(rows
        .iter()
        .map(|r| decode_role_grant_summary_row(r).1)
        .collect())
}

/// Account-grain check: does any actor on `account_id` hold an active
/// global (`scope_id IS NULL`) role grant for `role`?
///
/// Mirrors `fuz_app`'s `query_account_has_global_role`. Used by the
/// delete/purge keeper guard — auth resolution and daemon-token
/// resolution both pivot on the keeper account, so it is never removable
/// through the API.
///
/// Deliberately **unconditional** — no `deleted_at` filter on either the
/// account or the granting actor. The keeper must be non-removable *even if*
/// its account or keeper-actor is already tombstoned: deleting it would brick
/// keeper/daemon auth with no in-band recovery. The fail-safe direction here is
/// to over-report keeper presence, the opposite of
/// [`query_keeper_account_id`], which *resolves* the daemon-token identity and
/// so excludes a tombstoned keeper actor.
///
/// **Not the default for admission gates — and today it backs none of them.**
/// Over-reporting is fail-*open* for anything deciding whether to let a request
/// through, so every admission gate reads
/// [`query_account_has_active_global_role`] instead: `fuz_db_admin`'s
/// `require_role`, `fuz_forge`'s `require_admin_role` REST gate and its git
/// smart-HTTP auth, and the unbounded-search branch of
/// [`crate::actor_search_action_specs`]. Each has a TS twin whose grant read
/// hangs off a *resolved* — therefore non-tombstoned — acting actor, so the
/// active query is what matches TS. (The WS upgrade's `required_roles` gate
/// reads neither: it resolves the acting actor and reads that actor's active
/// global grants through the tombstone-aware
/// [`query_active_actor_holds_any_global_role`], at the gate and again at
/// admission.)
///
/// The exception rule for anything that reaches for this query in future: a
/// gate whose TS twin is itself tombstone-blind may keep it, because parity is
/// the binding constraint and a one-sided tightening would refuse requests the
/// twin admits. Tighten such a gate on both sides at once, never on one.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_has_global_role(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    role: &str,
) -> Result<bool, tokio_postgres::Error> {
    let sql = format!(
        "SELECT EXISTS(
            SELECT 1 FROM role_grant
            WHERE actor_id IN (SELECT id FROM actor WHERE account_id = $1)
              AND role = $2
              AND scope_id IS NULL
              AND {active}
         ) AS exists",
        active = crate::role_grant_active_sql("role_grant"),
    );
    let row = client.query_one(&sql, &[account_id, &role]).await?;
    Ok(row.get(0))
}

/// Like `query_account_has_global_role`, but only counts the grant when the
/// **account and the granting actor are both active** (`deleted_at IS NULL`).
///
/// Mirrors `fuz_app`'s `query_account_has_active_global_role`. The query every
/// account-grain **admission gate** uses — `fuz_db_admin`'s `require_role`
/// and `fuz_forge`'s `require_admin_role` — because over-reporting a role is fail-open
/// when the answer decides whether a request proceeds, and because TS reads
/// grants off a *resolved* acting actor, which a tombstoned actor never is.
///
/// Also used by the last-admin branch of the removability guard: a soft-deleted
/// admin is excluded from `query_count_active_accounts_with_global_role_for_update`, so
/// the guard must use the same active predicate when testing whether the target
/// is an admin — otherwise removing an already-tombstoned admin is falsely
/// blocked as `cannot_delete_last_admin`. Soft-delete does **not** revoke `role_grant`
/// rows (it's reversible — undelete restores them), so the actor join filters
/// `deleted_at IS NULL` too: a grant held only by a tombstoned actor must not
/// keep the account counted as an admin (the same tombstone-exclusion the
/// acting-actor resolution applies). The keeper branch keeps the unconditional
/// `query_account_has_global_role` (a keeper is never removable regardless of
/// tombstone state).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_account_has_active_global_role(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    role: &str,
) -> Result<bool, tokio_postgres::Error> {
    let sql = format!(
        "SELECT EXISTS(
            SELECT 1 FROM role_grant rg
            JOIN actor act ON act.id = rg.actor_id
            JOIN account a ON a.id = act.account_id
            WHERE a.id = $1
              AND a.deleted_at IS NULL
              AND act.deleted_at IS NULL
              AND rg.role = $2
              AND rg.scope_id IS NULL
              AND {rg_active}
         ) AS exists",
        rg_active = crate::role_grant_active_sql("rg"),
    );
    let row = client.query_one(&sql, &[account_id, &role]).await?;
    Ok(row.get(0))
}

/// Count **active** accounts (`deleted_at IS NULL`) holding an active
/// global (`scope_id IS NULL`) role grant for `role`, counting only grants on
/// **active actors** (`act.deleted_at IS NULL`) — and lock what it counted.
///
/// Mirrors `fuz_app`'s `query_count_active_accounts_with_global_role_for_update`.
/// Used by the last-admin guards — on `account_delete` / `account_purge` and on
/// `role_grant_revoke` of an `admin` grant: soft-delete revokes neither a
/// tombstoned account's nor a tombstoned actor's admin grant, so an unfiltered
/// count would include unusable admins — this joins `account` *and* filters the
/// actor, so an account whose only admin grant sits on a tombstoned actor no
/// longer counts (otherwise the guard could fail-open and let the last *usable*
/// admin be removed).
///
/// **Locks** every counted `role_grant`, `actor`, and `account` row
/// (`FOR UPDATE`) until the caller's transaction ends, so two guards racing to
/// remove the last two admins serialize: the second waits for the first to
/// commit, re-reads the rows it changed, and counts one. Run it inside the
/// transaction that does the removal — outside one, the locks end with the
/// statement.
///
/// `exclude_role_grant_id` leaves one grant out of the count, so a revoke asks
/// whether any active admin account would remain without that grant — an
/// account holding the grant on two actors keeps counting through the other.
/// The excluded grant is still locked, so two revokes of each other's grant
/// serialize rather than deadlock.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_count_active_accounts_with_global_role_for_update(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    role: &str,
    exclude_role_grant_id: Option<&uuid::Uuid>,
) -> Result<i64, tokio_postgres::Error> {
    // `FOR UPDATE` refuses an aggregate, so the rows come back and are
    // counted here. The excluded grant is dropped in code, not SQL: filtering
    // it in the WHERE would leave it unlocked, and two cross-revokes (each
    // locking only the other's grant, then updating it) would deadlock
    // instead of serializing
    let sql = format!(
        "SELECT a.id, rg.id FROM account a
         JOIN actor act ON act.account_id = a.id
         JOIN role_grant rg ON rg.actor_id = act.id
         WHERE a.deleted_at IS NULL
           AND act.deleted_at IS NULL
           AND rg.role = $1
           AND rg.scope_id IS NULL
           AND {rg_active}
         FOR UPDATE",
        rg_active = crate::role_grant_active_sql("rg"),
    );
    let rows = client.query(&sql, &[&role]).await?;
    let accounts: std::collections::HashSet<uuid::Uuid> = rows
        .iter()
        .filter(|row| exclude_role_grant_id != Some(&row.get::<_, uuid::Uuid>(1)))
        .map(|row| row.get(0))
        .collect();
    Ok(i64::try_from(accounts.len()).unwrap_or(i64::MAX))
}

/// Create an actor for an account.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_create_actor(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    name: &str,
) -> Result<ActorRow, tokio_postgres::Error> {
    let sql = format!(
        "INSERT INTO actor (account_id, name) VALUES ($1, $2)
         RETURNING {columns}",
        columns = actor_row_columns(),
    );
    let row = client.query_one(&sql, &[account_id, &name]).await?;
    Ok(decode_actor_row(&row))
}

/// Create an actor with an explicit `clock_timestamp()` `created_at`.
///
/// Unlike [`query_create_actor`] — which relies on the `actor.created_at`
/// `DEFAULT NOW()` column default, transaction-fixed so every actor minted in
/// one tx shares a `created_at` and `query_actors_by_account`'s
/// `ORDER BY created_at ASC, id ASC` tiebreaks on a random UUID — this advances
/// `created_at` per call within a transaction. `_testing_reset` uses it to seed
/// `extra_actors` so the keeper's bootstrap actor (at the fixed transaction
/// timestamp) sorts first and the extras sort in insert order, making the
/// multi-actor `available` list snapshot-stable.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
// hidden, not moved: reset-only, but its row projection + decode are crate-private
#[doc(hidden)]
pub async fn query_create_actor_with_clock_timestamp(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: &uuid::Uuid,
    name: &str,
) -> Result<ActorRow, tokio_postgres::Error> {
    let sql = format!(
        "INSERT INTO actor (account_id, name, created_at)
         VALUES ($1, $2, clock_timestamp())
         RETURNING {columns}",
        columns = actor_row_columns(),
    );
    let row = client.query_one(&sql, &[account_id, &name]).await?;
    Ok(decode_actor_row(&row))
}

/// Revoke an expired but unrevoked grant holding the `(actor, role, scope)`
/// slot, so a fresh grant can take it.
///
/// The partial unique index covers `revoked_at IS NULL`, so an expired row
/// still holds the slot: an insert would conflict with it and the idempotent
/// fallback would return a grant that confers nothing. Marks the row
/// `revoked_reason = 'expired'` with `revoked_by` null (nobody chose to revoke
/// it) and emits no audit event — the caller's grant records the transition.
/// Every path that inserts a grant into a slot calls this first:
/// [`query_create_role_grant`] and the offer accept
/// ([`crate::role_grant_offer_queries::query_accept_offer`]).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub(crate) async fn revoke_expired_role_grant_slot(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: &uuid::Uuid,
    role: &str,
    scope_kind: Option<&str>,
    scope_id: Option<&uuid::Uuid>,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE role_grant SET revoked_at = NOW(), revoked_by = NULL, revoked_reason = 'expired'
             WHERE actor_id = $1 AND role = $2
               AND scope_kind IS NOT DISTINCT FROM $3
               AND scope_id IS NOT DISTINCT FROM $4
               AND revoked_at IS NULL
               AND expires_at <= NOW()",
            &[actor_id, &role, &scope_kind, &scope_id],
        )
        .await?;
    Ok(())
}

/// Create a role grant for an actor (idempotent — `ON CONFLICT DO NOTHING`).
///
/// Idempotent over the *active* (unrevoked and unexpired) grant: an expired
/// but unrevoked row in the slot is first revoked (`revoked_reason =
/// 'expired'`, `revoked_by` null — nobody chose to revoke it) so the fresh
/// grant can take its place, since returning the expired row would report a
/// grant that confers nothing (see `revoke_expired_role_grant_slot`, which
/// the offer accept calls too). The revoke and the insert are two statements,
/// atomic when `client` is a transaction (the action path passes one).
///
/// Scope-aware: pass `scope_kind` + `scope_id` for a scoped grant (e.g. a
/// classroom-scoped `classroom_teacher`), or `None`/`None` for a global
/// grant. The pair is collapsed via the same `COALESCE` sentinel the partial
/// unique index uses, and the idempotent fallback `SELECT` matches the scope
/// with `IS NOT DISTINCT FROM` so a re-grant returns the existing scoped row
/// rather than minting a duplicate. Mirrors TS `query_create_role_grant`.
///
/// `granted_by` records the granting actor (audit trail); `expires_at` sets an
/// optional absolute expiry (`None` = non-expiring).
///
/// A builtin role (`admin` / `keeper`) is global-only: pass it with
/// `None`/`None`. The spine's grant verbs refuse a scoped builtin before they
/// reach this query, and every builtin gate reads the global grant, so a
/// scoped builtin row written here would confer nothing.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_create_role_grant(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    actor_id: &uuid::Uuid,
    role: &str,
    scope_kind: Option<&str>,
    scope_id: Option<&uuid::Uuid>,
    granted_by: Option<&uuid::Uuid>,
    expires_at: Option<std::time::SystemTime>,
) -> Result<RoleGrantRow, tokio_postgres::Error> {
    revoke_expired_role_grant_slot(client, actor_id, role, scope_kind, scope_id).await?;

    // Scope-aware partial unique index from the
    // `role_grant_offer_and_scoped_role_grants` migration:
    // `role_grant_actor_role_scope_active_unique` indexes
    // (actor_id, role, COALESCE(scope_kind, 'GLOBAL'),
    //  COALESCE(scope_id, sentinel-uuid))
    // WHERE revoked_at IS NULL. The ON CONFLICT predicate must match
    // the index expression literally — Postgres infers no implicit
    // unique on (actor_id, role) alone after the index swap. Global
    // grants pass NULL scope, collapsing to the global sentinel pair.
    let insert_sql = format!(
        "INSERT INTO role_grant (actor_id, role, scope_kind, scope_id, granted_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (
           actor_id,
           role,
           COALESCE(scope_kind, 'GLOBAL'),
           COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid)
         ) WHERE revoked_at IS NULL
         DO NOTHING
         RETURNING {columns}",
        columns = role_grant_row_columns(),
    );
    let inserted = client
        .query_opt(
            &insert_sql,
            &[
                actor_id,
                &role,
                &scope_kind,
                &scope_id,
                &granted_by,
                &expires_at,
            ],
        )
        .await?;

    if let Some(row) = inserted {
        return Ok(decode_role_grant_row(&row));
    }

    let existing_sql = format!(
        "SELECT {columns} FROM role_grant
         WHERE actor_id = $1 AND role = $2
           AND scope_kind IS NOT DISTINCT FROM $3
           AND scope_id IS NOT DISTINCT FROM $4
           AND revoked_at IS NULL",
        columns = role_grant_row_columns(),
    );
    let row = client
        .query_one(&existing_sql, &[actor_id, &role, &scope_kind, &scope_id])
        .await?;
    Ok(decode_role_grant_row(&row))
}

/// Find the account id for the keeper role (first active **global** keeper
/// grant on an active account + active actor).
///
/// Global-only (`scope_id IS NULL`), like every builtin read: a scoped keeper
/// row confers nothing, so it must not resolve the daemon-token identity.
///
/// Used at startup to resolve the daemon token's keeper account. Filters
/// `deleted_at IS NULL` on both the account and the granting actor: this
/// *resolves* the daemon-token identity, so a tombstoned keeper actor must not
/// grant keeper auth (the same tombstone-exclusion the acting-actor and
/// public-read resolution paths apply). This is the opposite posture from the
/// removability guard [`query_account_has_global_role`], which stays
/// unconditional so the keeper is never deleted out from under daemon auth.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_keeper_account_id(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Option<uuid::Uuid>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT a.id FROM account a
         JOIN actor ac ON ac.account_id = a.id
         JOIN role_grant p ON p.actor_id = ac.id
         WHERE p.role = 'keeper'
           AND p.scope_id IS NULL
           AND a.deleted_at IS NULL
           AND ac.deleted_at IS NULL
           AND {p_active}
         ORDER BY a.id ASC
         LIMIT 1",
        p_active = crate::role_grant_active_sql("p"),
    );
    let row = client.query_opt(&sql, &[]).await?;

    Ok(row.map(|r| r.get(0)))
}

/// Wire row for the actor-lookup resolver: `(id, username, display_name)`
/// joined `actor` ⨝ `account`.
///
/// Mirrors `fuz_app`'s `ActorLookupRow`. `account`
/// is `NOT NULL` on `actor` and `actor.name` is `NOT NULL`, so the join
/// resolves one row per id and `display_name` is a (possibly empty) string —
/// the action layer omits it from the wire when blank.
#[derive(Debug, Clone)]
pub struct ActorLookupRow {
    pub id: uuid::Uuid,
    pub username: String,
    pub display_name: String,
}

/// Render an actor summary (`{id, username, display_name?}`) to the wire
/// shape shared by `actor_lookup` and `actor_search`.
///
/// Omits `display_name` (not `null`) when it trims to empty — matching the
/// TS wire shape `display_name?` so clients see `undefined` rather than a
/// sentinel string.
#[must_use]
pub fn actor_summary_to_value(
    id: uuid::Uuid,
    username: &str,
    display_name: &str,
) -> serde_json::Value {
    match display_name.trim() {
        "" => serde_json::json!({"id": id, "username": username}),
        dn => serde_json::json!({"id": id, "username": username, "display_name": dn}),
    }
}

/// Resolve a batch of actor ids to `(id, username, display_name)`.
///
/// Empty
/// input fast-paths to `[]`. Hard-deleted and soft-deleted actors — and the
/// actors of a soft-deleted account — drop out of the result silently,
/// indistinguishable from never-existed (no tombstone oracle). The caller (action layer) caps
/// `ids.len()`; this query does not. Mirrors `fuz_app`'s `query_actors_by_ids`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_actors_by_ids(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    ids: &[uuid::Uuid],
) -> Result<Vec<ActorLookupRow>, tokio_postgres::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT {ACTOR_LOOKUP_PROJECTION}
         FROM actor act
         JOIN account a ON a.id = act.account_id
         WHERE act.id = ANY($1::uuid[])
           AND act.deleted_at IS NULL
           AND a.deleted_at IS NULL"
    );
    let rows = client.query(&sql, &[&ids]).await?;
    Ok(rows.iter().map(decode_actor_lookup_row).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_db::columns_not_in;
    use fuz_db::iso8601_timestamp_column;
    use fuz_db::omit_columns;

    #[test]
    fn shape_projections_are_subsets_of_their_tables() {
        let strays = columns_not_in(&ACTOR_ROW_COLUMNS, &ACTOR_COLUMNS);
        assert!(strays.is_empty(), "not in ACTOR_COLUMNS: {strays:?}");
        let strays = columns_not_in(&ROLE_GRANT_ROW_COLUMNS, &ROLE_GRANT_COLUMNS);
        assert!(strays.is_empty(), "not in ROLE_GRANT_COLUMNS: {strays:?}");
    }

    #[test]
    fn role_grant_summary_columns_pin_to_the_derivation() {
        assert_eq!(
            ROLE_GRANT_SUMMARY_COLUMNS.to_vec(),
            omit_columns(
                &ROLE_GRANT_COLUMNS,
                &[
                    "revoked_at",
                    "revoked_by",
                    "revoked_reason",
                    "source_offer_id"
                ]
            )
        );
    }

    #[test]
    fn role_grant_summary_columns_follows_the_const_order() {
        assert_eq!(
            role_grant_summary_columns("rg"),
            format!(
                "rg.id, rg.actor_id, rg.role, rg.scope_kind, rg.scope_id, {}, {}, rg.granted_by",
                iso8601_timestamp_column("rg", "created_at"),
                iso8601_timestamp_column("rg", "expires_at"),
            )
        );
    }
}
