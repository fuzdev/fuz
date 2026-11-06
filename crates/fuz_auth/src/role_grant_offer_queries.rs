//! Queries against the `role_grant_offer` table.
//!
//! Mirrors `fuz_app`'s `auth/role_grant_offer_queries.ts` across the full
//! offer lifecycle: create (upsert on the pending unique index), the atomic
//! accept+insert+supersede helper, decline, retract, the inbox list,
//! per-account history, the expiry sweep, and the revoke cascades that
//! supersede pending siblings.
//!
//! Wire-shape fidelity: every column but the server-only
//! `expire_audited_at` maps to a TS `RoleGrantOfferJson` field; timestamps
//! round-trip as ISO-8601 strings via the same
//! `to_char(... AT TIME ZONE 'UTC', '...')` pattern as
//! `invite_queries.rs`. See `../fuz_app/src/lib/auth/role_grant_offer_schema.ts`
//! for the canonical schema and DDL comments. Every offer-row read projects
//! [`ROLE_GRANT_OFFER_COLUMNS`] through `role_grant_offer_columns` and
//! decodes through `decode_offer_row`; the CTE-joined shapes append their
//! extra expressions after the const's columns.
//!
//! Audit rows: [`query_accept_offer`] returns the data the handler needs,
//! and the handler writes the `role_grant_offer_accept` /
//! `role_grant_create` / per-sibling `role_grant_offer_supersede` rows
//! through `ctx.audit_emit`, which routes them per
//! [`crate::AUDIT_EVENT_SPECS`]: a success row is written inside the
//! request transaction, its listener fan-out queued behind the commit — the
//! rows TS `query_accept_offer` writes in-tx.

use std::time::SystemTime;

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use fuz_db::{col, iso8601_timestamp_expr, qualify_columns};

use crate::actor_queries::revoke_expired_role_grant_slot;
use crate::role::{ROLE_ADMIN, ROLE_KEEPER, is_builtin_role};

/// Index-side token used in the `COALESCE(scope_kind, 'GLOBAL')`
/// expression on the partial-unique index.
///
/// Mirrors TS
/// `ROLE_GRANT_OFFER_SCOPE_KIND_GLOBAL_TOKEN` (kept literal in the SQL
/// for index-expression match — Postgres requires the `ON CONFLICT`
/// target expression to be byte-identical to the index expression).
pub const ROLE_GRANT_OFFER_SCOPE_KIND_GLOBAL_TOKEN: &str = "GLOBAL";

/// All-zeros sentinel UUID used in the `COALESCE(scope_id, sentinel)`
/// expression. Mirrors TS `ROLE_GRANT_OFFER_SCOPE_SENTINEL_UUID`.
pub const ROLE_GRANT_OFFER_SCOPE_SENTINEL_UUID: &str = "00000000-0000-0000-0000-000000000000";

/// Default TTL for a newly-created offer — 30 days. Matches TS
/// `ROLE_GRANT_OFFER_DEFAULT_TTL_MS` and GitHub's org-invite expiry.
pub const ROLE_GRANT_OFFER_DEFAULT_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// `SystemTime::now() + ROLE_GRANT_OFFER_DEFAULT_TTL_MS`. Single
/// source for the handler + integration tests' "some pending future
/// expiry" timestamp.
#[must_use]
pub fn default_expiry_from_now() -> SystemTime {
    SystemTime::now() + std::time::Duration::from_millis(ROLE_GRANT_OFFER_DEFAULT_TTL_MS as u64)
}

/// Wire-shape `role_grant_offer` row — mirrors `fuz_app`'s
/// `RoleGrantOfferJson`.
///
/// Timestamps are pre-formatted ISO-8601 strings
/// so cross-process assertions on the wire payload diff byte-for-byte
/// against the TS impl.
#[derive(Debug, Clone, Serialize)]
pub struct RoleGrantOffer {
    pub id: Uuid,
    pub from_actor_id: Uuid,
    pub to_account_id: Uuid,
    pub to_actor_id: Option<Uuid>,
    pub role: String,
    pub scope_kind: Option<String>,
    pub scope_id: Option<Uuid>,
    pub message: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub accepted_at: Option<String>,
    pub declined_at: Option<String>,
    pub decline_reason: Option<String>,
    pub retracted_at: Option<String>,
    pub superseded_at: Option<String>,
    pub resulting_role_grant_id: Option<Uuid>,
    /// When the expiry sweep audited this offer's `role_grant_offer_expire` —
    /// the claim stamp [`query_role_grant_offer_sweep_expired`] sets in the
    /// same transaction as the audit row, so each expiry is audited once. Not
    /// a lifecycle state (an expired offer is still pending by the terminal
    /// columns), cleared by a re-offer, and **server-only**: skipped on
    /// serialize, so it never reaches the wire (TS `to_role_grant_offer_json`
    /// drops it, and the strict `RoleGrantOfferJson` would reject it).
    #[serde(skip)]
    pub expire_audited_at: Option<String>,
}

/// Offer row annotated with the grantor's `account_id`, populated via
/// the CTE join on `actor` in the supersede UPDATE.
///
/// Lets the handler
/// fan out `role_grant_offer_supersede` notifications without a
/// second round-trip.
#[derive(Debug, Clone, Serialize)]
pub struct SupersededOffer {
    #[serde(flatten)]
    pub offer: RoleGrantOffer,
    pub from_account_id: Uuid,
}

/// Declined-offer projection — the offer row plus the grantor's
/// `account_id`.
///
/// Joined in via CTE so the decline handler can populate both
/// `target_actor_id` and `target_account_id` on its audit envelope and
/// fan out a notification to the grantor without a second round-trip.
/// Mirrors TS `DeclinedOffer`.
#[derive(Debug, Clone, Serialize)]
pub struct DeclinedOffer {
    #[serde(flatten)]
    pub offer: RoleGrantOffer,
    pub from_account_id: Uuid,
}

/// Input for [`query_role_grant_offer_create`].
///
/// Owned strings (no borrow lifetime) — the handler constructs this
/// from owned `String`s anyway and the lifetime annotation wasn't
/// saving allocations. `expires_at` rides as `SystemTime`
/// (tokio-postgres maps natively to TIMESTAMPTZ).
#[derive(Debug, Clone)]
pub struct CreateRoleGrantOfferInput {
    pub from_actor_id: Uuid,
    pub to_account_id: Uuid,
    pub to_actor_id: Option<Uuid>,
    pub role: String,
    pub scope_kind: Option<String>,
    pub scope_id: Option<Uuid>,
    pub message: Option<String>,
    /// Absolute expiry — call [`default_expiry_from_now`] for the
    /// canonical default, or supply a caller-specific value.
    pub expires_at: SystemTime,
}

/// Input for [`query_accept_offer`].
#[derive(Debug, Clone, Copy)]
pub struct AcceptOfferInput {
    pub offer_id: Uuid,
    /// IDOR guard — `query_accept_offer` rejects if `offer.to_account_id`
    /// doesn't match this.
    pub to_account_id: Uuid,
    /// Accepting actor — must belong to `to_account_id`. Enforced via a
    /// SELECT defense-in-depth (the dispatcher's auth phase already
    /// resolved this from the session, but the query enforces the
    /// invariant for direct callers).
    pub actor_id: Uuid,
}

/// Result of [`query_accept_offer`].
#[derive(Debug, Clone)]
pub struct AcceptOfferResult {
    /// The `role_grant` row produced (new on first call; pre-existing on
    /// idempotent race).
    pub role_grant_id: Uuid,
    /// The accepted offer (always populated; `accepted_at` set and
    /// `resulting_role_grant_id == role_grant_id`).
    pub offer: RoleGrantOffer,
    /// The grantor's `account_id` (the lead offer's `from_actor_id` →
    /// account), joined in via the accept UPDATE's CTE so the handler can
    /// fan out a `role_grant_offer_accepted` notification to the grantor
    /// without a second round-trip. (TS resolves this with one extra
    /// SELECT; widening the RETURNING is the cleaner shape and matches
    /// `DeclinedOffer` / `SupersededOffer` in this module.)
    pub from_account_id: Uuid,
    /// `true` when this call wrote the `role_grant`; `false` on a replay
    /// (or a race loser) returning the pre-existing, still-held
    /// `role_grant`. The handler audits and notifies only on `true`.
    pub created: bool,
    /// Sibling pending offers superseded by this accept. Empty on the
    /// race-loser path (the race winner already supersedes).
    pub superseded_offers: Vec<SupersededOffer>,
}

/// Why [`query_accept_offer`] refused to mint a builtin-role grant.
///
/// Each is a row no current grant path creates but a database can still hold
/// (a direct [`query_role_grant_offer_create`] call, or an offer made under a
/// since-closed path), so accept — the chokepoint where an offer becomes a
/// `role_grant` — checks them itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinOfferRefusal {
    /// The offer is of `keeper`, which is bootstrap-only: never conferred
    /// through an offer, whoever made it.
    BootstrapOnly,
    /// The offer binds a builtin role to a scope; builtin roles are
    /// global-only.
    Scoped,
    /// The grantor no longer holds an active **global** `admin` on an active
    /// actor of an active account. Conferring a builtin role is global-admin
    /// authority, so it is re-checked when the grant is minted, not only when
    /// the offer was made.
    GrantorNotAuthorized,
}

/// Errors surfaced by the offer query layer.
#[derive(Debug, Error)]
pub enum RoleGrantOfferError {
    /// Offer does not exist, or belongs to a different recipient (IDOR
    /// guard). The standard 404-over-403 pattern that avoids
    /// disclosing whether an offer id exists.
    #[error("offer {0} not found")]
    NotFound(Uuid),
    /// Offer is in a terminal state (accepted / declined / retracted /
    /// superseded).
    #[error("offer {0} is already in a terminal state")]
    AlreadyTerminal(Uuid),
    /// Offer is pending but past `expires_at`.
    #[error("offer {0} has expired")]
    Expired(Uuid),
    /// Grantor attempted to offer a role to their own account.
    #[error("cannot offer a role_grant to your own account")]
    SelfTarget,
    /// `to_actor_id` does not exist or does not belong to
    /// `to_account_id`.
    #[error("to_actor_id does not belong to to_account_id")]
    ActorAccountMismatch,
    /// Actor-targeted offer being accepted by a different actor on the
    /// same recipient account.
    #[error("offer {0} is targeted to a different actor on this account")]
    ActorMismatch(Uuid),
    /// Offer confers a builtin role (`admin` / `keeper`) that this accept must
    /// not mint — see [`BuiltinOfferRefusal`] for which rule refused it.
    ///
    /// Carries the locked (still pending, untouched) offer so the caller can
    /// audit the refusal with the offer's role and scope.
    #[error("offer {} is refused: {refusal:?}", .offer.id)]
    BuiltinRefused {
        /// The pending offer, as locked.
        offer: Box<RoleGrantOffer>,
        /// Which builtin-role rule refused it.
        refusal: BuiltinOfferRefusal,
    },
    /// Tx-level driver failure. Caller propagates as JSON-RPC 500.
    #[error("query error: {0}")]
    Query(#[from] tokio_postgres::Error),
}

/// The `role_grant_offer` table's columns.
///
/// Twin of `fuz_app`'s `ROLE_GRANT_OFFER_COLUMNS` (same names, same order —
/// on the TS side it lives in the offer DDL module to keep two query
/// modules acyclic; Rust module cycles don't bite, so it lives here with
/// the queries). The PG-gated `columns` integration test asserts this
/// names every live column. `expire_audited_at` is last: the appended
/// `role_grant_offer_expire_audited_at` migration adds it after the frozen
/// `CREATE TABLE`.
pub const ROLE_GRANT_OFFER_COLUMNS: [&str; 17] = [
    "id",
    "from_actor_id",
    "to_account_id",
    "to_actor_id",
    "role",
    "scope_kind",
    "scope_id",
    "message",
    "created_at",
    "expires_at",
    "accepted_at",
    "declined_at",
    "decline_reason",
    "retracted_at",
    "superseded_at",
    "resulting_role_grant_id",
    "expire_audited_at",
];

/// The [`RoleGrantOffer`] projection (decoded positionally by
/// [`decode_offer_row`]): [`ROLE_GRANT_OFFER_COLUMNS`] qualified by `alias`
/// — the table name for the bare-table reads + `RETURNING`, `o` / `u` for
/// the locked-row SELECT and the supersede / decline CTEs — with every
/// timestamp as an ISO-8601 string. Returns an owned `String`; the
/// per-query allocation is negligible against the network round-trip.
fn role_grant_offer_columns(alias: &str) -> String {
    qualify_columns(
        &ROLE_GRANT_OFFER_COLUMNS,
        alias,
        iso8601_timestamp_expr(
            &ROLE_GRANT_OFFER_COLUMNS,
            &[
                "created_at",
                "expires_at",
                "accepted_at",
                "declined_at",
                "retracted_at",
                "superseded_at",
                "expire_audited_at",
            ],
            alias,
        ),
    )
}

/// Index of the first expression a CTE-joined read appends after the
/// offer columns (`from_account_id`, `still_valid`).
const OFFER_EXTRA_COLUMN: usize = ROLE_GRANT_OFFER_COLUMNS.len();

/// The four terminal-state columns. An offer is *pending* exactly when all
/// four are `NULL`, and every lifecycle statement gates on that: the create
/// upsert's `ON CONFLICT` predicate (which must keep matching the partial
/// unique index `role_grant_offer_pending_unique`), the decline / retract
/// UPDATEs (accept's own UPDATE is gated by the `FOR UPDATE` claim lock
/// instead), the inbox list, the expiry sweep, all three supersede cascades
/// (accept, revoke, revoke-for-scope), and
/// [`classify_missed_transition`]'s classification of a missed UPDATE.
///
/// Nothing projects these columns raw — the const reaches SQL only through
/// [`offer_pending_predicate`], so pending/terminal has exactly one spelling
/// in this module and the classification can't drift from the gate.
const OFFER_TERMINAL_COLUMNS: [&str; 4] = [
    "accepted_at",
    "declined_at",
    "retracted_at",
    "superseded_at",
];

/// `AND`-joiner for the one-line `ON CONFLICT ... WHERE` index predicate.
const PENDING_JOIN_INLINE: &str = " AND ";
/// `AND`-joiner for a top-level `WHERE` chain's continuation indent.
const PENDING_JOIN_WHERE: &str = "\n           AND ";
/// `AND`-joiner for a `WHERE` chain nested one level inside a CTE body.
const PENDING_JOIN_NESTED: &str = "\n              AND ";

/// The still-pending predicate — every [`OFFER_TERMINAL_COLUMNS`] entry
/// `IS NULL`, joined by `separator`.
///
/// `alias` qualifies the columns (`"o"` inside the `UPDATE ... FROM`
/// cascades, `""` for the unqualified reads). `separator` is one of the
/// `PENDING_JOIN_*` constants, which carry only the indentation of the
/// `WHERE` chain the predicate lands in — modulo `alias`, the predicate
/// text itself is the same at every callsite.
fn offer_pending_predicate(alias: &str, separator: &str) -> String {
    let dot = if alias.is_empty() { "" } else { "." };
    OFFER_TERMINAL_COLUMNS
        .iter()
        .map(|col| format!("{alias}{dot}{col} IS NULL"))
        .collect::<Vec<_>>()
        .join(separator)
}

/// The tail every offer-terminating `UPDATE` CTE shares: project the
/// `updated` CTE's rows through [`role_grant_offer_columns`] and join `actor`
/// for each row's grantor `account_id`. The three supersede cascades decode
/// it via [`decode_superseded_row`] to fan out notifications without a second
/// round-trip; the decline `UPDATE` shares the same positionally-identical
/// projection via `decode_declined_row`.
///
/// The continuation indent is baked rather than parameterized the way
/// [`offer_pending_predicate`]'s is: this fragment lands at exactly one
/// syntactic position at all four callsites — top level, immediately after
/// the `WITH updated AS (…)` — whereas the pending predicate lands at three
/// different nesting depths. A knob with one possible value is worse than
/// the literal.
fn updated_offer_select() -> String {
    format!(
        "SELECT {returning}, grantor.account_id AS from_account_id
         FROM updated u
         JOIN actor grantor ON grantor.id = u.from_actor_id",
        returning = role_grant_offer_columns("u"),
    )
}

/// Decode the [`role_grant_offer_columns`] projection positionally.
fn decode_offer_row(row: &tokio_postgres::Row) -> RoleGrantOffer {
    RoleGrantOffer {
        id: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "id")),
        from_actor_id: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "from_actor_id")),
        to_account_id: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "to_account_id")),
        to_actor_id: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "to_actor_id")),
        role: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "role")),
        scope_kind: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "scope_kind")),
        scope_id: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "scope_id")),
        message: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "message")),
        created_at: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "created_at")),
        expires_at: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "expires_at")),
        accepted_at: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "accepted_at")),
        declined_at: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "declined_at")),
        decline_reason: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "decline_reason")),
        retracted_at: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "retracted_at")),
        superseded_at: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "superseded_at")),
        resulting_role_grant_id: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "resulting_role_grant_id")),
        expire_audited_at: row.get(col!(ROLE_GRANT_OFFER_COLUMNS, "expire_audited_at")),
    }
}

/// Decode [`role_grant_offer_columns`] + the CTE's trailing
/// `from_account_id` positionally.
fn decode_superseded_row(row: &tokio_postgres::Row) -> SupersededOffer {
    SupersededOffer {
        offer: decode_offer_row(row),
        from_account_id: row.get(OFFER_EXTRA_COLUMN),
    }
}

/// Create a new `role_grant` offer, or upsert the existing pending offer
/// for the same `(to_account_id, role, scope_kind, scope_id, from_actor_id)`
/// tuple. Mirrors TS `query_role_grant_offer_create`.
///
/// Pre-checks:
/// 1. Self-target — looks up the grantor's `actor.account_id` and
///    rejects if it matches `to_account_id`. Multi-actor-correct: the
///    grantor → account binding is 1:1 by definition of `actor`.
/// 2. Actor-account binding — when `to_actor_id` is supplied, verifies
///    the named actor belongs to `to_account_id`.
///
/// On the pending unique-index conflict, refreshes `to_actor_id`,
/// `message`, and `expires_at` (matches TS upsert semantics — a second
/// offer for the same tuple is a "refresh", not a duplicate) and clears
/// `expire_audited_at`, so a re-offer of an expired, already-audited row gets
/// its own `role_grant_offer_expire` when the refreshed expiry passes.
///
/// # Errors
///
/// [`RoleGrantOfferError::SelfTarget`] when the offering actor's
/// account matches `to_account_id`.
/// [`RoleGrantOfferError::ActorAccountMismatch`] when `to_actor_id` is
/// supplied but doesn't belong to `to_account_id`.
/// [`RoleGrantOfferError::Query`] on any underlying driver error.
pub async fn query_role_grant_offer_create(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    input: CreateRoleGrantOfferInput,
) -> Result<RoleGrantOffer, RoleGrantOfferError> {
    // Self-target check — resolve the GRANTOR actor's account_id.
    // Multi-actor-correct: a single account may host many actors, and
    // self-target means "the offering actor's account == the recipient
    // account", regardless of how many other actors live on either
    // account. Mirrors the TS comment in `query_role_grant_offer_create`.
    let grantor_row = client
        .query_opt(
            "SELECT account_id FROM actor WHERE id = $1",
            &[&input.from_actor_id],
        )
        .await?;
    if let Some(row) = grantor_row {
        let grantor_account: Uuid = row.get(0);
        if grantor_account == input.to_account_id {
            return Err(RoleGrantOfferError::SelfTarget);
        }
    }

    // Actor-account binding check when `to_actor_id` is supplied — the
    // FK alone allows the actor to exist on any account; we need
    // membership on `to_account_id` specifically.
    if let Some(target_actor_id) = input.to_actor_id {
        let target_row = client
            .query_opt(
                "SELECT account_id FROM actor WHERE id = $1",
                &[&target_actor_id],
            )
            .await?;
        let belongs = target_row.is_some_and(|r| {
            let account_id: Uuid = r.get(0);
            account_id == input.to_account_id
        });
        if !belongs {
            return Err(RoleGrantOfferError::ActorAccountMismatch);
        }
    }

    // Upsert via the partial unique index `role_grant_offer_pending_unique`.
    // The conflict-target expression list must be byte-identical to the
    // index expression — including the partial WHERE predicate, which
    // Postgres requires for inference against a partial unique index.
    // `expires_at` rides as a native `SystemTime` (tokio-postgres maps
    // it to TIMESTAMPTZ).
    let sql = format!(
        "INSERT INTO role_grant_offer
             (from_actor_id, to_account_id, to_actor_id, role, scope_kind, scope_id, message, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (
           to_account_id,
           role,
           COALESCE(scope_kind, '{global}'),
           COALESCE(scope_id, '{sentinel}'::uuid),
           from_actor_id
         )
           WHERE {pending}
         DO UPDATE SET
             to_actor_id = EXCLUDED.to_actor_id,
             message = EXCLUDED.message,
             expires_at = EXCLUDED.expires_at,
             expire_audited_at = NULL
         RETURNING {returning}",
        global = ROLE_GRANT_OFFER_SCOPE_KIND_GLOBAL_TOKEN,
        sentinel = ROLE_GRANT_OFFER_SCOPE_SENTINEL_UUID,
        pending = offer_pending_predicate("", PENDING_JOIN_INLINE),
        returning = role_grant_offer_columns("role_grant_offer"),
    );

    let row = client
        .query_one(
            &sql,
            &[
                &input.from_actor_id,
                &input.to_account_id,
                &input.to_actor_id,
                &input.role,
                &input.scope_kind,
                &input.scope_id,
                &input.message,
                &input.expires_at,
            ],
        )
        .await?;

    Ok(decode_offer_row(&row))
}

/// Whether `grantor_actor_id` holds an active **global** `admin` on an active
/// actor of an active account — the authority a builtin-role offer needs at
/// the moment its grant is minted.
///
/// A locking read: `FOR SHARE OF rg` takes a share lock on the grant row that
/// admits, so a concurrent revoke (an `UPDATE` of that row) is strictly
/// ordered against this accept — it either commits first, and the recheck of
/// the locked row sees `revoked_at` set and excludes it, or it waits for this
/// transaction to commit the grant it authorized. A plain `EXISTS` could read
/// the grant as active while a revoke commits in between. The actor and
/// account tombstones are read but not locked — ordering a delete racing an
/// accept isn't worth locking two more tables.
async fn grantor_holds_global_admin(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    grantor_actor_id: Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let sql = format!(
        "SELECT 1 FROM role_grant rg
         JOIN actor act ON act.id = rg.actor_id
         JOIN account a ON a.id = act.account_id
         WHERE rg.actor_id = $1
           AND rg.role = $2
           AND rg.scope_id IS NULL
           AND {rg_active}
           AND act.deleted_at IS NULL
           AND a.deleted_at IS NULL
         LIMIT 1
         FOR SHARE OF rg",
        rg_active = crate::role_grant_active_sql("rg"),
    );
    let row = client
        .query_opt(&sql, &[&grantor_actor_id, &ROLE_ADMIN])
        .await?;
    Ok(row.is_some())
}

/// Accept an offer atomically.
///
/// In-transaction sequence (matches TS `query_accept_offer`):
/// 1. `SELECT ... FOR UPDATE` lock on the offer row, IDOR-guarded by
///    `to_account_id`. Subsequent concurrent callers block on the
///    lock until this transaction commits.
/// 2. If already accepted — return the pre-existing `role_grant` row
///    idempotently while that grant is still held (`created: false`): a
///    grant revoked since, or gone, makes the offer terminal, and so does
///    the multi-actor guard (the accepted `role_grant` belongs to a
///    different actor on the same account).
/// 3. If declined / retracted / superseded — [`RoleGrantOfferError::AlreadyTerminal`]. If
///    pending but past `expires_at` — [`RoleGrantOfferError::Expired`].
/// 4. Actor-targeted gate: when `offer.to_actor_id IS NOT NULL` and
///    differs from `actor_id`, surface [`RoleGrantOfferError::ActorMismatch`] even if the
///    actor belongs to `to_account_id`. A builtin-role offer that must not
///    mint — `keeper` at all, a builtin bound to a scope, or one whose grantor
///    no longer holds an active global `admin` (read under `FOR SHARE`) —
///    surfaces [`RoleGrantOfferError::BuiltinRefused`].
/// 5. Verify `actor_id` belongs to `to_account_id`
///    (defense-in-depth — handler passes a session-bound actor, but
///    the query enforces for direct callers).
/// 6. INSERT the `role_grant` with `scope_kind`/`scope_id`/`granted_by`
///    (= grantor actor id)/`source_offer_id` (= offer id), idempotent
///    via `ON CONFLICT DO NOTHING` on the scope-aware partial unique
///    index. Falls back to a SELECT when ON CONFLICT skips, so the
///    return value always carries the active `role_grant` id.
/// 7. UPDATE the offer — `accepted_at = NOW()` + `resulting_role_grant_id`
///    in a single statement so the
///    `role_grant_offer_role_grant_iff_accepted` CHECK constraint is
///    satisfied at row-visibility time.
/// 8. Supersede sibling pending offers for the same
///    `(to_account, role, scope_id)` via a CTE that joins `actor` for
///    each sibling's grantor `account_id`.
///
/// Returns enough data for the handler to emit
/// `role_grant_offer_accept` + `role_grant_create` + per-sibling
/// `role_grant_offer_supersede` audit events through `ctx.audit_emit`
/// (in the request transaction — see the module docs) — on `created: true`
/// only; a replay wrote nothing, so it audits and notifies nothing.
///
/// # Errors
///
/// [`RoleGrantOfferError::NotFound`] when the offer id is missing or
/// the recipient account doesn't match.
/// [`RoleGrantOfferError::AlreadyTerminal`] / [`RoleGrantOfferError::Expired`] /
/// [`RoleGrantOfferError::ActorMismatch`] on the corresponding pre-checks.
/// [`RoleGrantOfferError::BuiltinRefused`] when a builtin-role offer must not
/// mint (see [`BuiltinOfferRefusal`]).
/// [`RoleGrantOfferError::Query`] on driver errors or invariant
/// violations (e.g. accepting actor not on recipient account, which
/// is unreachable under the FK invariant).
pub async fn query_accept_offer(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    input: AcceptOfferInput,
) -> Result<AcceptOfferResult, RoleGrantOfferError> {
    let AcceptOfferInput {
        offer_id,
        to_account_id,
        actor_id,
    } = input;

    // Claim the offer with a row-level lock. We defer writing
    // `accepted_at` until the role_grant row exists — the
    // `role_grant_offer_role_grant_iff_accepted` CHECK demands both be
    // set (or neither) at row-visibility time.
    //
    // Trailing `o.expires_at > NOW() AS still_valid` rides on the
    // FOR UPDATE row so the expiry check uses PG's clock without a
    // second round-trip. `locked.expires_at` is the ISO string for
    // the wire shape; `still_valid` (the first position after
    // `role_grant_offer_columns("o")`'s columns) is the
    // comparison-result bool. `from_account_id` (the next position) is the
    // grantor's account, joined off `from_actor_id` so the accept can fan
    // out the `role_grant_offer_accepted` notification to the grantor
    // without a second round-trip — the grantor binding is immutable
    // across the accept so reading it from the locked row is authoritative.
    let locked_sql = format!(
        "SELECT {returning}, o.expires_at > NOW() AS still_valid, grantor.account_id AS from_account_id
         FROM role_grant_offer o
         JOIN actor grantor ON grantor.id = o.from_actor_id
         WHERE o.id = $1 AND o.to_account_id = $2
         FOR UPDATE OF o",
        returning = role_grant_offer_columns("o"),
    );
    let locked_row = client
        .query_opt(&locked_sql, &[&offer_id, &to_account_id])
        .await?;
    let Some(locked_row) = locked_row else {
        return Err(RoleGrantOfferError::NotFound(offer_id));
    };
    let locked = decode_offer_row(&locked_row);
    let still_valid: bool = locked_row.get(OFFER_EXTRA_COLUMN);
    let from_account_id: Uuid = locked_row.get(OFFER_EXTRA_COLUMN + 1);

    if locked.accepted_at.is_some() {
        // Race winner already committed; return the pre-existing
        // role_grant. The `role_grant_offer_role_grant_iff_accepted`
        // CHECK guarantees `resulting_role_grant_id` is non-null.
        let Some(role_grant_id) = locked.resulting_role_grant_id else {
            // The `role_grant_offer_role_grant_iff_accepted` CHECK guarantees
            // this is non-null whenever `accepted_at` is set (the branch
            // above). A null here would mean the DB violated its own
            // constraint — mirror the `map_offer_error` invariant guards
            // that `unreachable!` on a convergence regression.
            unreachable!(
                "CHECK constraint guarantees resulting_role_grant_id when accepted_at is set"
            );
        };

        // The idempotent answer stands only while the grant it names does.
        // A grant revoked since the accept (or gone) makes a replay
        // terminal: answering OK with the revoked grant's id would tell
        // the caller "you hold this role" when they don't.
        //
        // Multi-actor guard: two actors on the same recipient account
        // may both race an account-grain offer — the loser must not
        // silently receive the winner's role_grant. Treat as terminal
        // when the role_grant binds to a different actor.
        let grant_row = client
            .query_opt(
                "SELECT actor_id, revoked_at IS NOT NULL FROM role_grant WHERE id = $1",
                &[&role_grant_id],
            )
            .await?;
        let Some(grant_row) = grant_row else {
            return Err(RoleGrantOfferError::AlreadyTerminal(offer_id));
        };
        let granted_actor_id: Uuid = grant_row.get(0);
        let revoked: bool = grant_row.get(1);
        if revoked || granted_actor_id != actor_id {
            return Err(RoleGrantOfferError::AlreadyTerminal(offer_id));
        }
        return Ok(AcceptOfferResult {
            role_grant_id,
            offer: locked,
            from_account_id,
            created: false,
            superseded_offers: Vec::new(),
        });
    }

    if locked.declined_at.is_some()
        || locked.retracted_at.is_some()
        || locked.superseded_at.is_some()
    {
        return Err(RoleGrantOfferError::AlreadyTerminal(offer_id));
    }

    // Expiry check fires AFTER the accepted-path so a validly-accepted
    // offer past its `expires_at` still returns the role_grant
    // idempotently. Only pending offers past expiry reach this branch.
    // `still_valid` rode on the FOR UPDATE row above so the
    // comparison stays authoritative on PG's clock without a second
    // round-trip.
    if !still_valid {
        return Err(RoleGrantOfferError::Expired(offer_id));
    }

    // Actor-targeted gate — when the offer named an actor, reject any
    // other actor on the same account.
    if let Some(target_actor_id) = locked.to_actor_id
        && target_actor_id != actor_id
    {
        return Err(RoleGrantOfferError::ActorMismatch(offer_id));
    }

    // Builtin-role offers — checked here, the chokepoint where an offer turns
    // into a `role_grant`, so a direct caller of this query can't skip them.
    // No current grant path creates a refused shape, but a pending row can
    // still carry one (a direct `query_role_grant_offer_create`, or an offer
    // made under a since-closed path).
    if is_builtin_role(&locked.role) {
        let refusal = if locked.role == ROLE_KEEPER {
            // `keeper` is bootstrap-only — never conferred through an offer,
            // even from a global admin.
            Some(BuiltinOfferRefusal::BootstrapOnly)
        } else if locked.scope_id.is_some() {
            // Builtin roles are global-only.
            Some(BuiltinOfferRefusal::Scoped)
        } else if !grantor_holds_global_admin(client, locked.from_actor_id).await? {
            Some(BuiltinOfferRefusal::GrantorNotAuthorized)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return Err(RoleGrantOfferError::BuiltinRefused {
                offer: Box::new(locked),
                refusal,
            });
        }
    }

    // Defense-in-depth: verify the accepting actor belongs to
    // `to_account_id`. The action handler already passes
    // session-bound `auth.actor.id`, but enforcing here protects
    // direct callers from cross-account binding bugs that would
    // silently grant a role to the wrong actor.
    let actor_check_row = client
        .query_opt(
            "SELECT id FROM actor WHERE id = $1 AND account_id = $2",
            &[&actor_id, &to_account_id],
        )
        .await?;
    if actor_check_row.is_none() {
        // Unreachable under the FK invariant + handler discipline.
        // Logged at error level for forensics; surfaced as
        // `NotFound` so the wire shape mirrors the IDOR 404 the rest
        // of the path uses (matches `signup_routes` / `account_*`
        // convention of not minting bespoke 500-shaped errors for
        // FK-defended invariants).
        tracing::error!(
            actor_id = %actor_id,
            account_id = %to_account_id,
            offer_id = %offer_id,
            "role_grant_offer accept: FK invariant violation \
             (accepting actor does not belong to recipient account)",
        );
        return Err(RoleGrantOfferError::NotFound(offer_id));
    }

    // An expired row still holds the slot — revoke it first, as
    // `query_create_role_grant` does, so the accept mints a live grant
    // rather than pointing `resulting_role_grant_id` at a dead one.
    revoke_expired_role_grant_slot(
        client,
        &actor_id,
        &locked.role,
        locked.scope_kind.as_deref(),
        locked.scope_id.as_ref(),
    )
    .await?;

    // INSERT the role_grant. Uses the scope-aware partial unique index
    // `role_grant_actor_role_scope_active_unique` for idempotency — the
    // same insert TS `query_accept_offer` reaches through
    // `query_create_role_grant` (inlined here to record `source_offer_id`).
    // ON CONFLICT DO NOTHING returns no row on the conflict path; a
    // follow-up SELECT recovers the pre-existing role_grant id.
    let insert_sql = format!(
        "INSERT INTO role_grant
             (actor_id, role, scope_kind, scope_id, granted_by, source_offer_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (
           actor_id,
           role,
           COALESCE(scope_kind, '{ROLE_GRANT_OFFER_SCOPE_KIND_GLOBAL_TOKEN}'),
           COALESCE(scope_id, '{ROLE_GRANT_OFFER_SCOPE_SENTINEL_UUID}'::uuid)
         )
           WHERE revoked_at IS NULL
         DO NOTHING
         RETURNING id",
    );
    let inserted = client
        .query_opt(
            &insert_sql,
            &[
                &actor_id,
                &locked.role,
                &locked.scope_kind,
                &locked.scope_id,
                &locked.from_actor_id,
                &locked.id,
            ],
        )
        .await?;
    let role_grant_id: Uuid = if let Some(row) = inserted {
        row.get(0)
    } else {
        let existing_row = client
            .query_one(
                "SELECT id FROM role_grant
                 WHERE actor_id = $1
                   AND role = $2
                   AND scope_kind IS NOT DISTINCT FROM $3
                   AND scope_id IS NOT DISTINCT FROM $4
                   AND revoked_at IS NULL",
                &[
                    &actor_id,
                    &locked.role,
                    &locked.scope_kind,
                    &locked.scope_id,
                ],
            )
            .await?;
        existing_row.get(0)
    };

    // Single UPDATE sets both sides of the
    // `role_grant_offer_role_grant_iff_accepted` CHECK constraint at
    // once.
    let accepted_sql = format!(
        "UPDATE role_grant_offer
         SET accepted_at = NOW(), resulting_role_grant_id = $2
         WHERE id = $1
         RETURNING {returning}",
        returning = role_grant_offer_columns("role_grant_offer"),
    );
    let accepted_row = client
        .query_one(&accepted_sql, &[&locked.id, &role_grant_id])
        .await?;
    let offer = decode_offer_row(&accepted_row);

    // Supersede sibling pending offers for the same
    // `(to_account, role, scope_id)`. CTE joins `actor` to surface
    // each sibling's grantor `account_id` for the caller's
    // notification fan-out. Forecloses the "accept this other sibling
    // later to get the role back after a revoke" path.
    let supersede_sql = format!(
        "WITH updated AS (
            UPDATE role_grant_offer
            SET superseded_at = NOW()
            WHERE to_account_id = $1
              AND role = $2
              AND scope_id IS NOT DISTINCT FROM $3
              AND id <> $4
              AND {pending}
            RETURNING *
         )
         {select}",
        pending = offer_pending_predicate("", PENDING_JOIN_NESTED),
        select = updated_offer_select(),
    );
    let supersede_rows = client
        .query(
            &supersede_sql,
            &[&to_account_id, &offer.role, &offer.scope_id, &offer.id],
        )
        .await?;
    let superseded_offers: Vec<SupersededOffer> =
        supersede_rows.iter().map(decode_superseded_row).collect();

    Ok(AcceptOfferResult {
        role_grant_id,
        offer,
        from_account_id,
        created: true,
        superseded_offers,
    })
}

/// Decode [`role_grant_offer_columns`] + the CTE's trailing
/// `from_account_id` positionally.
fn decode_declined_row(row: &tokio_postgres::Row) -> DeclinedOffer {
    DeclinedOffer {
        offer: decode_offer_row(row),
        from_account_id: row.get(OFFER_EXTRA_COLUMN),
    }
}

/// The party whose conditional `UPDATE` missed, and the column its IDOR
/// guard pinned: the recipient's `to_account_id` (decline) or the grantor's
/// `from_actor_id` (retract).
#[derive(Debug, Clone, Copy)]
enum OfferParty {
    Recipient(Uuid),
    Grantor(Uuid),
}

/// Distinguish "not found / different owner" from "already terminal" —
/// matches TS `resolve_terminal_or_missing`. Called from `_decline` and
/// `_retract` after the conditional UPDATE returned no row, so it only
/// ever produces the error the caller returns.
///
/// Asks Postgres for the *negation of the pending predicate* rather than
/// projecting the four raw `TIMESTAMPTZ` columns and re-deriving terminality
/// here: one `bool` to decode, and the caller's missed `UPDATE ... AND
/// {pending}` and this classification are then the same expression by
/// construction, not two spellings that have to be kept in agreement.
/// `IS NULL` is never itself null, so the `NOT (...)` is total — no
/// three-valued-logic gap between `terminal` and pending.
async fn classify_missed_transition(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    offer_id: Uuid,
    party: OfferParty,
) -> RoleGrantOfferError {
    let (owner_column, owner_id) = match party {
        OfferParty::Recipient(id) => ("to_account_id", id),
        OfferParty::Grantor(id) => ("from_actor_id", id),
    };
    let sql = format!(
        "SELECT NOT ({pending}) AS terminal FROM role_grant_offer WHERE id = $1 \
         AND {owner_column} = $2",
        pending = offer_pending_predicate("", PENDING_JOIN_INLINE),
    );
    let row = match client.query_opt(&sql, &[&offer_id, &owner_id]).await {
        Ok(row) => row,
        Err(err) => return err.into(),
    };
    let Some(row) = row else {
        return RoleGrantOfferError::NotFound(offer_id);
    };
    let terminal: bool = row.get(0);
    if terminal {
        RoleGrantOfferError::AlreadyTerminal(offer_id)
    } else {
        // Row exists, owner matches, no terminal column set — caller's
        // UPDATE predicate was satisfied. Race conditions reach here
        // only when a concurrent caller raced ahead and was rolled back
        // mid-flight; surface as NotFound rather than the false-positive
        // AlreadyTerminal.
        RoleGrantOfferError::NotFound(offer_id)
    }
}

/// Mark an offer declined by the recipient.
///
/// IDOR-guarded by `to_account_id`. CTE joins `actor` so the returned
/// row carries the grantor's `account_id` for audit-envelope population
/// (decline is *to* the grantor) without a second round-trip. Mirrors
/// TS `query_role_grant_offer_decline`.
///
/// # Errors
///
/// [`RoleGrantOfferError::NotFound`] when the offer id is missing or
/// belongs to a different recipient. [`RoleGrantOfferError::AlreadyTerminal`]
/// when the offer exists for the caller but is already in a terminal
/// state. [`RoleGrantOfferError::Query`] on driver errors.
pub async fn query_role_grant_offer_decline(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    offer_id: Uuid,
    to_account_id: Uuid,
    reason: Option<&str>,
) -> Result<DeclinedOffer, RoleGrantOfferError> {
    let sql = format!(
        "WITH updated AS (
            UPDATE role_grant_offer
            SET declined_at = NOW(), decline_reason = $3
            WHERE id = $1
              AND to_account_id = $2
              AND {pending}
            RETURNING *
         )
         {select}",
        pending = offer_pending_predicate("", PENDING_JOIN_NESTED),
        select = updated_offer_select(),
    );
    let row = client
        .query_opt(&sql, &[&offer_id, &to_account_id, &reason])
        .await?;
    if let Some(row) = row {
        return Ok(decode_declined_row(&row));
    }
    Err(classify_missed_transition(client, offer_id, OfferParty::Recipient(to_account_id)).await)
}

/// Mark an offer retracted by the grantor.
///
/// IDOR-guarded by `from_actor_id`. Mirrors TS
/// `query_role_grant_offer_retract`.
///
/// # Errors
///
/// [`RoleGrantOfferError::NotFound`] when the offer id is missing or
/// belongs to a different grantor. [`RoleGrantOfferError::AlreadyTerminal`]
/// when the offer exists for the caller but is already in a terminal
/// state. [`RoleGrantOfferError::Query`] on driver errors.
pub async fn query_role_grant_offer_retract(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    offer_id: Uuid,
    from_actor_id: Uuid,
) -> Result<RoleGrantOffer, RoleGrantOfferError> {
    let sql = format!(
        "UPDATE role_grant_offer
         SET retracted_at = NOW()
         WHERE id = $1
           AND from_actor_id = $2
           AND {pending}
         RETURNING {returning}",
        pending = offer_pending_predicate("", PENDING_JOIN_WHERE),
        returning = role_grant_offer_columns("role_grant_offer"),
    );
    let row = client.query_opt(&sql, &[&offer_id, &from_actor_id]).await?;
    if let Some(row) = row {
        return Ok(decode_offer_row(&row));
    }
    Err(classify_missed_transition(client, offer_id, OfferParty::Grantor(from_actor_id)).await)
}

/// List pending, non-expired offers for an account, soonest expiry
/// first.
///
/// Expired offers are filtered server-side so the inbox never
/// surfaces a row that can no longer be accepted. Mirrors TS
/// `query_role_grant_offer_list`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_role_grant_offer_list(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    to_account_id: Uuid,
) -> Result<Vec<RoleGrantOffer>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {returning} FROM role_grant_offer
         WHERE to_account_id = $1
           AND {pending}
           AND expires_at > NOW()
         ORDER BY expires_at ASC",
        pending = offer_pending_predicate("", PENDING_JOIN_WHERE),
        returning = role_grant_offer_columns("role_grant_offer"),
    );
    let rows = client.query(&sql, &[&to_account_id]).await?;
    Ok(rows.iter().map(decode_offer_row).collect())
}

/// List every offer involving an account (either direction), newest
/// first. Includes terminal offers — used by the history view. Mirrors
/// TS `query_role_grant_offer_history_for_account`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_role_grant_offer_history_for_account(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    account_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<RoleGrantOffer>, tokio_postgres::Error> {
    let sql = format!(
        "SELECT {returning} FROM role_grant_offer o
         LEFT JOIN actor a ON a.id = o.from_actor_id
         WHERE o.to_account_id = $1 OR a.account_id = $1
         ORDER BY o.created_at DESC
         LIMIT $2 OFFSET $3",
        returning = role_grant_offer_columns("o"),
    );
    let rows = client.query(&sql, &[&account_id, &limit, &offset]).await?;
    Ok(rows.iter().map(decode_offer_row).collect())
}

/// Claim the expired, not-yet-audited pending offers.
///
/// Stamps `expire_audited_at` on each pending offer whose `expires_at` has
/// passed and whose expiry has not been audited yet, and returns them
/// soonest-expiry first. Mirrors TS `query_role_grant_offer_sweep_expired`.
///
/// The stamp is the sweep's idempotency: a claimed row never matches again,
/// so each expiry is audited exactly once. **It must share a transaction
/// with the caller's `role_grant_offer_expire` audit inserts** — committed
/// together, or rolled back together so the next sweep retries. Concurrent
/// sweeps claim disjoint rows without an advisory lock: a row another sweep
/// has stamped but not committed blocks on its row lock, then fails the
/// re-checked `expire_audited_at IS NULL`.
/// [`crate::auth_cleanup::cleanup_expired_role_grant_offers`] is the caller.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_role_grant_offer_sweep_expired(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Vec<RoleGrantOffer>, tokio_postgres::Error> {
    // the inner `RETURNING` projects raw columns; the outer select formats
    // them, as the supersede / decline CTEs do
    let sql = format!(
        "WITH claimed AS (
           UPDATE role_grant_offer
           SET expire_audited_at = NOW()
           WHERE {pending}
             AND expires_at <= NOW()
             AND expire_audited_at IS NULL
           RETURNING *
         )
         SELECT {returning} FROM claimed c
         ORDER BY c.expires_at ASC, c.id ASC",
        pending = offer_pending_predicate("", PENDING_JOIN_NESTED),
        returning = role_grant_offer_columns("c"),
    );
    let rows = client.query(&sql, &[]).await?;
    Ok(rows.iter().map(decode_offer_row).collect())
}

/// Find an active role grant for `(role_grant_id, actor_id)`, joining
/// `actor` for the grant's `account_id`.
///
/// Drives the `role_grant_revoke`
/// IDOR check + audit envelope `target_account_id`. Mirrors TS
/// `query_role_grant_find_active_role_for_actor`.
///
/// Returns `None` when the role grant is missing, revoked, or belongs
/// to a different actor.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_role_grant_find_active_role_for_actor(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    role_grant_id: Uuid,
    actor_id: Uuid,
) -> Result<Option<ActiveRoleGrantForActor>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT p.id, p.role, p.scope_kind, p.scope_id, a.account_id
             FROM role_grant p
             JOIN actor a ON a.id = p.actor_id
             WHERE p.id = $1
               AND p.actor_id = $2
               AND p.revoked_at IS NULL",
            &[&role_grant_id, &actor_id],
        )
        .await?;
    Ok(row.map(|r| ActiveRoleGrantForActor {
        id: r.get(0),
        role: r.get(1),
        scope_kind: r.get(2),
        scope_id: r.get(3),
        account_id: r.get(4),
    }))
}

/// Result of [`query_role_grant_find_active_role_for_actor`].
#[derive(Debug, Clone)]
pub struct ActiveRoleGrantForActor {
    pub id: Uuid,
    pub role: String,
    pub scope_kind: Option<String>,
    pub scope_id: Option<Uuid>,
    pub account_id: Uuid,
}

/// Result of [`query_revoke_role_grant`] — the revoked grant plus any
/// pending offers superseded by the revoke.
#[derive(Debug, Clone)]
pub struct RevokeRoleGrantResult {
    pub id: Uuid,
    pub role: String,
    pub scope_kind: Option<String>,
    pub scope_id: Option<Uuid>,
    /// Pending offers for the same `(account, role, scope)` that were
    /// marked superseded as a side effect. Empty when no siblings were
    /// pending. The caller emits a `role_grant_offer_supersede` audit
    /// event per entry with `reason: 'role_grant_revoked'` +
    /// `cause_id: <revoked role_grant id>`.
    pub superseded_offers: Vec<SupersededOffer>,
}

/// Revoke an active role grant by id, constrained to a specific actor
/// (IDOR guard).
///
/// Supersedes pending offers for the revoked grant's
/// `(to_account, role, scope)` in the same transaction. Mirrors TS
/// `query_revoke_role_grant`.
///
/// Returns `None` when the grant is missing, already revoked, or
/// belongs to a different actor — the caller raises `NotFound` either
/// way (avoids disclosing whether the id exists).
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_revoke_role_grant(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    role_grant_id: Uuid,
    actor_id: Uuid,
    revoked_by: Option<Uuid>,
    reason: Option<&str>,
) -> Result<Option<RevokeRoleGrantResult>, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "UPDATE role_grant
             SET revoked_at = NOW(), revoked_by = $3, revoked_reason = $4
             WHERE id = $1 AND actor_id = $2 AND revoked_at IS NULL
             RETURNING id, role, scope_kind, scope_id",
            &[&role_grant_id, &actor_id, &revoked_by, &reason],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let revoked_id: Uuid = row.get(0);
    let revoked_role: String = row.get(1);
    let revoked_scope_kind: Option<String> = row.get(2);
    let revoked_scope_id: Option<Uuid> = row.get(3);

    // CTE join on `actor` after the supersede UPDATE — each row carries
    // the grantor's `account_id` for the caller's notification fan-out.
    // The pair-CHECK on `(scope_kind, scope_id)` makes matching on
    // `scope_id` alone equivalent to matching on both columns.
    let supersede_sql = format!(
        "WITH updated AS (
            UPDATE role_grant_offer o
            SET superseded_at = NOW()
            FROM actor a
            WHERE a.id = $1
              AND o.to_account_id = a.account_id
              AND o.role = $2
              AND o.scope_id IS NOT DISTINCT FROM $3
              AND {pending}
            RETURNING o.*
         )
         {select}",
        pending = offer_pending_predicate("o", PENDING_JOIN_NESTED),
        select = updated_offer_select(),
    );
    let supersede_rows = client
        .query(
            &supersede_sql,
            &[&actor_id, &revoked_role, &revoked_scope_id],
        )
        .await?;
    let superseded_offers: Vec<SupersededOffer> =
        supersede_rows.iter().map(decode_superseded_row).collect();

    Ok(Some(RevokeRoleGrantResult {
        id: revoked_id,
        role: revoked_role,
        scope_kind: revoked_scope_kind,
        scope_id: revoked_scope_id,
        superseded_offers,
    }))
}

/// Supersede every pending offer **made by** one of `from_actor_ids` — the
/// grantor-side cascade.
///
/// An offer carries no record of the authority it was made under, so one
/// outliving that authority would still confer its role on accept. Revoking a
/// grant (`role_grant_revoke`, the revokee's actor) and removing an account
/// (`account_delete` / `account_purge`, every actor of the account) end the
/// grantor's outgoing pending offers in the same transaction. Each row carries
/// the grantor's `account_id`, as every supersede cascade's does. The caller
/// emits a `role_grant_offer_supersede` audit per entry, and the revoke caller
/// also sends the supersede notification. Mirrors TS `query_role_grant_offer_supersede_outgoing`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_role_grant_offer_supersede_outgoing(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    from_actor_ids: &[Uuid],
) -> Result<Vec<SupersededOffer>, tokio_postgres::Error> {
    if from_actor_ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "WITH updated AS (
            UPDATE role_grant_offer o
            SET superseded_at = NOW()
            WHERE o.from_actor_id = ANY($1::uuid[])
              AND {pending}
            RETURNING o.*
         )
         {select}",
        pending = offer_pending_predicate("o", PENDING_JOIN_NESTED),
        select = updated_offer_select(),
    );
    let rows = client.query(&sql, &[&from_actor_ids]).await?;
    Ok(rows.iter().map(decode_superseded_row).collect())
}

/// One `role_grant` revoked by [`query_role_grant_revoke_for_scope`].
///
/// Carries the revokee's `actor_id` (drives `target_actor_id` audit envelopes)
/// and `account_id` (drives `target_account_id` + WS/SSE socket-close fan-out).
#[derive(Debug, Clone)]
pub struct RevokedGrantAtScope {
    pub role_grant_id: Uuid,
    pub role: String,
    pub scope_kind: Option<String>,
    pub scope_id: Uuid,
    pub actor_id: Uuid,
    pub account_id: Uuid,
}

/// Result of [`query_role_grant_revoke_for_scope`] — every `role_grant` revoked
/// plus every pending offer superseded by the scope-wide cascade.
#[derive(Debug, Clone)]
pub struct RevokeForScopeResult {
    /// One entry per `role_grant` revoked at the scope. Empty when none were active.
    pub revoked: Vec<RevokedGrantAtScope>,
    /// Every pending offer at the scope, superseded in the same cascade. Each
    /// carries its grantor's `from_account_id` for supersede-notification
    /// fan-out. The caller emits a `role_grant_offer_supersede` audit per entry
    /// (`reason: 'scope_destroyed'`, `cause_id: <destroyed scope row id>`).
    pub superseded_offers: Vec<SupersededOffer>,
}

/// Revoke every active `role_grant` bound to a scope and supersede every pending
/// offer at that scope, in one cascade.
///
/// Use from a consumer's parent-scope delete handler (e.g. classroom deletion):
/// `role_grant.scope_id` / `role_grant_offer.scope_id` are polymorphic with no
/// FK, so a parent-row delete would otherwise orphan grants and offers. The
/// cascade is role-agnostic — anything attached to the destroyed scope is
/// cleaned up. Both halves run as separate statements inside the caller's
/// transaction; the supersede half always runs (orphan pending offers can exist
/// at a scope with no active grants). Mirrors TS `query_role_grant_revoke_for_scope`.
///
/// # Errors
///
/// Propagates `tokio_postgres::Error` from the underlying client.
pub async fn query_role_grant_revoke_for_scope(
    client: &(impl deadpool_postgres::GenericClient + ?Sized),
    scope_id: Uuid,
    revoked_by: Option<Uuid>,
    reason: Option<&str>,
) -> Result<RevokeForScopeResult, tokio_postgres::Error> {
    // Revoke every active grant at the scope. CTE returns `actor_id` from the
    // grant row; the join resolves `account_id` for the audit/fan-out envelope.
    let revoked_rows = client
        .query(
            "WITH updated AS (
                UPDATE role_grant
                SET revoked_at = NOW(), revoked_by = $2, revoked_reason = $3
                WHERE scope_id = $1 AND revoked_at IS NULL
                RETURNING id, role, scope_kind, scope_id, actor_id
             )
             SELECT u.id, u.role, u.scope_kind, u.scope_id, u.actor_id, a.account_id
             FROM updated u
             JOIN actor a ON a.id = u.actor_id",
            &[&scope_id, &revoked_by, &reason],
        )
        .await?;
    let revoked: Vec<RevokedGrantAtScope> = revoked_rows
        .iter()
        .map(|row| RevokedGrantAtScope {
            role_grant_id: row.get(0),
            role: row.get(1),
            scope_kind: row.get(2),
            scope_id: row.get(3),
            actor_id: row.get(4),
            account_id: row.get(5),
        })
        .collect();

    // Supersede every pending offer at the scope — tuple-matched or orphan, no
    // distinction (the scope deletion is the cause of all of them).
    let supersede_sql = format!(
        "WITH updated AS (
            UPDATE role_grant_offer o
            SET superseded_at = NOW()
            WHERE o.scope_id = $1
              AND {pending}
            RETURNING o.*
         )
         {select}",
        pending = offer_pending_predicate("o", PENDING_JOIN_NESTED),
        select = updated_offer_select(),
    );
    let supersede_rows = client.query(&supersede_sql, &[&scope_id]).await?;
    let superseded_offers: Vec<SupersededOffer> =
        supersede_rows.iter().map(decode_superseded_row).collect();

    Ok(RevokeForScopeResult {
        revoked,
        superseded_offers,
    })
}

#[cfg(test)]
mod tests {
    use super::{ROLE_GRANT_OFFER_COLUMNS, RoleGrantOffer, SupersededOffer};
    use uuid::Uuid;

    fn offer_with_every_field_set() -> RoleGrantOffer {
        RoleGrantOffer {
            id: Uuid::new_v4(),
            from_actor_id: Uuid::new_v4(),
            to_account_id: Uuid::new_v4(),
            to_actor_id: Some(Uuid::new_v4()),
            role: "teacher".to_owned(),
            scope_kind: Some("classroom".to_owned()),
            scope_id: Some(Uuid::new_v4()),
            message: Some("hi".to_owned()),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            expires_at: "2026-01-02T00:00:00Z".to_owned(),
            accepted_at: None,
            declined_at: None,
            decline_reason: None,
            retracted_at: None,
            superseded_at: Some("2026-01-01T12:00:00Z".to_owned()),
            resulting_role_grant_id: None,
            expire_audited_at: Some("2026-01-02T00:10:00Z".to_owned()),
        }
    }

    fn serialized_keys(value: &impl serde::Serialize) -> Vec<String> {
        let serde_json::Value::Object(map) = serde_json::to_value(value).unwrap() else {
            panic!("an offer serializes as an object");
        };
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// The wire shape is every column but the server-only stamp — the strict
    /// TS `RoleGrantOfferJson` would reject an `expire_audited_at` key.
    #[test]
    fn the_expire_audited_at_stamp_stays_off_the_wire() {
        let mut expected: Vec<String> = ROLE_GRANT_OFFER_COLUMNS
            .iter()
            .filter(|c| **c != "expire_audited_at")
            .map(|c| (*c).to_owned())
            .collect();
        expected.sort();
        assert_eq!(expected.len(), 16);

        let offer = offer_with_every_field_set();
        assert_eq!(serialized_keys(&offer), expected);

        // the flattened supersede / decline shapes inherit the skip
        let superseded = SupersededOffer {
            offer,
            from_account_id: Uuid::new_v4(),
        };
        expected.push("from_account_id".to_owned());
        expected.sort();
        assert_eq!(serialized_keys(&superseded), expected);
    }
}
