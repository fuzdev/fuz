//! Auth subsystem migration namespace.
//!
//! Ships the reserved `"fuz_auth"` namespace ([`AUTH_MIGRATIONS_NAMESPACE`]),
//! built with [`fuz_db::MigrationNamespace::spine`] so the
//! [`fuz_db::run_migrations`] runner admits it under the reserved name.
//! Consumers splice their own namespaces after it; the runner refuses one
//! bearing a reserved name.
//!
//! A single namespace with one flat migration list, matching the TS
//! shape (one `"fuz_auth"` namespace, flat array).
//!
//! **The released chain is frozen — every schema change ships as an
//! appended migration.** Once a consumer holds a long-lived production
//! database, an already-bootstrapped DB has recorded the existing
//! migrations as applied, so editing a released migration's SQL in place is
//! a silent no-op there: the `CREATE TABLE IF NOT EXISTS` doesn't re-run,
//! the runner sees nothing new, and the new column never lands — a silent,
//! total auth outage. (The `deleted_at` / `deleted_by` soft-delete columns
//! were baked into `full_auth_schema.sql` this way; an older deployed DB
//! never got them and every login broke.) So never edit, rename, reorder,
//! or re-purpose an entry in `MIGRATIONS`: add every additive change as a
//! NEW appended `Migration` (its own `.sql` file) using idempotent
//! `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so a fresh bootstrap and an
//! old deployed DB converge on the same shape. The `/ready` schema-drift
//! probe is the runtime net (fails the deploy loud on a missing column);
//! discipline prevents the drift, the probe catches a lapse before cutover.
//! Dev/test DBs (no long-lived data) may still drop + re-bootstrap freely.
//!
//! **Every entry is twinned with `fuz_app`'s `AUTH_MIGRATIONS` at the same
//! position**, and the two names must match byte for byte: the
//! `_testing_migration_tracker` parity gate compares the
//! `(namespace, name, sequence)` rows both spines record, and a divergence
//! there breaks the swap-freely invariant (a consumer pointing either
//! implementation at one database). Append on both sides in the same change,
//! so no entry below repeats the rule.

use fuz_db::{Migration, MigrationNamespace};

/// Reserved namespace name — matches [`fuz_db::RESERVED_NAMESPACES`].
pub const AUTH_MIGRATIONS_NAMESPACE: &str = "fuz_auth";

/// Initial DDL: identity tables (`account`, `actor`, `role_grant`),
/// sessions, bootstrap lock, app settings, API tokens, audit log.
///
/// Uses `IF NOT EXISTS` defensively, but the identity tracker enforces
/// run-once semantics — the body executes exactly once per database, which
/// is exactly why it is **frozen**: a column added here never reaches an
/// already-bootstrapped DB. Add columns via an appended `Migration`, never
/// by editing this file. See the module doc.
const FULL_AUTH_SCHEMA: &str = include_str!("migrations/full_auth_schema.sql");

/// Consentful `role_grants` — `role_grant_offer` table + scoped `role_grants`
/// (`scope_kind`/`scope_id`/`source_offer_id`/`revoked_reason` columns on
/// `role_grant`).
const ROLE_GRANT_OFFER_AND_SCOPED_ROLE_GRANTS: &str =
    include_str!("migrations/role_grant_offer_and_scoped_role_grants.sql");

/// Per-credential token scoping — `api_token.scope JSONB NOT NULL`, with
/// pre-existing tokens backfilled as `grandfathered` full authority.
const API_TOKEN_SCOPE: &str = include_str!("migrations/api_token_scope.sql");

/// `UNIQUE` index on `api_token(token_hash)` — the column every bearer request
/// resolves through, unindexed since the table shipped.
const API_TOKEN_HASH_UNIQUE_INDEX: &str =
    include_str!("migrations/api_token_hash_unique_index.sql");

/// GIN on `audit_log.metadata` (`jsonb_path_ops`) — the index the per-cell
/// audit timeline's `metadata @>` containment queries assume.
const AUDIT_LOG_METADATA_GIN_INDEX: &str =
    include_str!("migrations/audit_log_metadata_gin_index.sql");

/// Drops `auth_session.last_seen_at` — decorative: nothing updates it after
/// mint on either spine, and it has no wire field.
const DROP_SESSION_LAST_SEEN_AT: &str = include_str!("migrations/drop_session_last_seen_at.sql");

/// `role_grant_offer.expire_audited_at` + the partial index serving the expiry
/// sweep — the claim stamp that audits each offer expiry exactly once.
const ROLE_GRANT_OFFER_EXPIRE_AUDITED_AT: &str =
    include_str!("migrations/role_grant_offer_expire_audited_at.sql");

/// `CHECK (username = lower(username))` on `account` — every stored username
/// lowercase, as the creation paths canonicalize it. Fails on a database
/// already holding a mixed-case username.
const ACCOUNT_USERNAME_LOWERCASE: &str = include_str!("migrations/account_username_lowercase.sql");

/// Flat ordered migration list. **Frozen + append-only** — entries here are
/// never edited, renamed, or reordered; every schema change is a new appended
/// `Migration`. See the module doc for the silent-outage rationale.
const MIGRATIONS: &[Migration] = &[
    Migration {
        name: "full_auth_schema",
        sql: FULL_AUTH_SCHEMA,
    },
    Migration {
        name: "role_grant_offer_and_scoped_role_grants",
        sql: ROLE_GRANT_OFFER_AND_SCOPED_ROLE_GRANTS,
    },
    Migration {
        name: "api_token_scope",
        sql: API_TOKEN_SCOPE,
    },
    Migration {
        name: "api_token_hash_unique_index",
        sql: API_TOKEN_HASH_UNIQUE_INDEX,
    },
    Migration {
        name: "audit_log_metadata_gin_index",
        sql: AUDIT_LOG_METADATA_GIN_INDEX,
    },
    Migration {
        name: "drop_session_last_seen_at",
        sql: DROP_SESSION_LAST_SEEN_AT,
    },
    Migration {
        name: "role_grant_offer_expire_audited_at",
        sql: ROLE_GRANT_OFFER_EXPIRE_AUDITED_AT,
    },
    Migration {
        name: "account_username_lowercase",
        sql: ACCOUNT_USERNAME_LOWERCASE,
    },
];

/// Auth migration namespace ready to splice into the runner.
///
/// ```ignore
/// use fuz_auth::AUTH_MIGRATIONS;
/// use fuz_db::run_migrations;
///
/// // ... after acquiring `Pool`:
/// run_migrations(&pool, &[AUTH_MIGRATIONS, consumer_namespace]).await?;
/// ```
pub const AUTH_MIGRATIONS: MigrationNamespace =
    MigrationNamespace::spine(AUTH_MIGRATIONS_NAMESPACE, MIGRATIONS);

/// The auth chain's columns registry.
///
/// Every table [`AUTH_MIGRATIONS`] creates, mapped to the `*_COLUMNS`
/// const its reads project — plus `bootstrap_lock`, exempt (the single-row
/// lock, read as the `bootstrapped` flag and flipped by conditional
/// UPDATE).
///
/// Composed with the other chains' sets — `fuz_db`'s
/// `DB_COLUMN_PROJECTIONS`, `fuz_cell`'s, `fuz_fact`'s, a consumer's own —
/// by each `tests/columns.rs` via
/// `fuz_db::column_projection_mismatches_merged`, so an auth table added
/// here reaches every downstream registry without per-repo edits.
pub const AUTH_COLUMN_PROJECTIONS: fuz_db::ColumnProjections = fuz_db::ColumnProjections {
    projections: &[
        ("account", &crate::account_queries::ACCOUNT_COLUMNS),
        ("actor", &crate::actor_queries::ACTOR_COLUMNS),
        ("role_grant", &crate::actor_queries::ROLE_GRANT_COLUMNS),
        (
            "role_grant_offer",
            &crate::role_grant_offer_queries::ROLE_GRANT_OFFER_COLUMNS,
        ),
        (
            "auth_session",
            &crate::session_queries::AUTH_SESSION_COLUMNS,
        ),
        ("invite", &crate::invite_queries::INVITE_COLUMNS),
        ("api_token", &crate::api_token_queries::API_TOKEN_COLUMNS),
        ("audit_log", &crate::audit_log_queries::AUDIT_LOG_COLUMNS),
        (
            "app_settings",
            &crate::app_settings_queries::APP_SETTINGS_COLUMNS,
        ),
    ],
    exempt: &["bootstrap_lock"],
};

/// The auth tables `_testing_reset` empties between tests, children first.
///
/// Every table [`AUTH_MIGRATIONS`] creates but the two singletons the reset
/// rewrites in place instead: `app_settings` (its one row back to the
/// production defaults) and `bootstrap_lock` (flipped to bootstrapped, since
/// the reset seeds a keeper). Children come before the rows they reference, so
/// each `DELETE FROM` the reset issues is FK-safe in turn.
///
/// Twin of `fuz_app`'s `auth_integration_truncate_tables`
/// (`testing/db.ts`): the same tables, in an order of its own there (a
/// `TRUNCATE … CASCADE` list). Both spines' `_testing_reset` delete this list
/// in this order — `fuz_testing`'s iterates it, `fuz_app`'s spells the same
/// sequence out.
pub const AUTH_INTEGRATION_TRUNCATE_TABLES: &[&str] = &[
    "audit_log",
    "role_grant_offer",
    "invite",
    "api_token",
    "auth_session",
    "role_grant",
    "actor",
    "account",
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The singletons [`AUTH_INTEGRATION_TRUNCATE_TABLES`] leaves out: `_testing_reset`
    /// rewrites each one's row rather than deleting it.
    const RESET_IN_PLACE: &[&str] = &["app_settings", "bootstrap_lock"];

    /// The reset list plus its in-place singletons names exactly the tables
    /// the chain's DDL leaves behind, and the tables of the columns registry
    /// (held to the live schema by `tests/columns.rs`).
    #[test]
    fn the_reset_tables_cover_every_table_the_chain_creates() {
        let reset: BTreeSet<String> = AUTH_INTEGRATION_TRUNCATE_TABLES
            .iter()
            .map(|t| (*t).to_owned())
            .collect();
        assert_eq!(
            reset.len(),
            AUTH_INTEGRATION_TRUNCATE_TABLES.len(),
            "a table listed twice"
        );
        let in_place: BTreeSet<String> = RESET_IN_PLACE.iter().map(|t| (*t).to_owned()).collect();
        assert!(
            reset.is_disjoint(&in_place),
            "a table both deleted and kept"
        );
        let covered: BTreeSet<String> = reset.union(&in_place).cloned().collect();
        assert_eq!(
            covered,
            fuz_testing::migration_created_tables(&AUTH_MIGRATIONS),
            "AUTH_INTEGRATION_TRUNCATE_TABLES + the in-place singletons vs the DDL"
        );
        let registry: BTreeSet<String> = AUTH_COLUMN_PROJECTIONS
            .projections
            .iter()
            .map(|(table, _)| *table)
            .chain(AUTH_COLUMN_PROJECTIONS.exempt.iter().copied())
            .map(str::to_owned)
            .collect();
        assert_eq!(
            covered, registry,
            "AUTH_INTEGRATION_TRUNCATE_TABLES + the in-place singletons vs AUTH_COLUMN_PROJECTIONS"
        );
    }
}
