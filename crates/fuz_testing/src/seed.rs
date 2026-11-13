//! The account / actor / role-grant fixture rows shared by the spine's
//! `#[ignore]` `PostgreSQL` suites.
//!
//! Sibling of [`crate::fresh_db`]: that module hands a suite a migrated pool,
//! this one seeds the identity rows nearly every case then needs, and
//! [`crate::credentials`] mints the credential those identities authenticate
//! with. `fuz_auth`, `fuz_cell`, `fuz_actions`, and `fuz_fact_serving` each
//! hand-copied the same two-statement `account` → `actor` insert (five
//! copies), the second-actor insert (two), and the two-column `role_grant`
//! insert (two); they live here once and each suite keeps only the wrapper it
//! needs, if any (an actor id alone, a `RequestActorContext`, an `AccountRow`
//! — or direct calls). [`refuse_audit_rows`] rides along: the `CHECK` that
//! makes an audit write fail, shared by the `fuz_actions` and `fuz_realtime`
//! revocation suites.
//!
//! ### The `'x'` password hash is load-bearing
//!
//! Every seeded account stores the literal `'x'` in `password_hash`. That is
//! not a placeholder to tidy up: it is not a parseable PHC string, so
//! `PasswordHasher::verify` returns `false` for *any* candidate password
//! (it reports `false` on a parse error, not just a mismatch). A fixture
//! account therefore cannot be logged into, which is what lets suites that
//! never exercise `/login` seed identities freely without minting a real
//! credential. Keep the literal exactly as it is.
//!
//! ### Actor `name` mirrors the account `username`
//!
//! [`seed_account_actor`] uses one `username` argument for both rows — the
//! convention all five copies shared. Suites that need a divergent actor name
//! (a second persona on the same account) use [`seed_extra_actor`].

#![expect(
    clippy::expect_used,
    reason = "a test harness: a setup fault panics loudly naming the step, and the in-tests carve-out doesn't reach a library module"
)]

use fuz_db::Pool;
use uuid::Uuid;

/// Seed an `account` plus its single `actor` and return `(account_id,
/// actor_id)`.
///
/// The actor's `name` is the `username` argument, so an account seeded here is
/// single-actor — the shape the authorization phase resolves without an
/// `acting` selector. Both are stored lowercased, as every creation path
/// stores a username (the `account_username_lowercase` CHECK requires it). See
/// the module docs on the `'x'` password hash.
///
/// # Panics
///
/// Panics with the failing step named if the pool is unreachable or either
/// insert fails (a duplicate fixture `username` being the usual cause) — setup
/// faults a test body can do nothing about.
pub async fn seed_account_actor(pool: &Pool, username: &str) -> (Uuid, Uuid) {
    let username = username.to_lowercase();
    let client = pool.get().await.expect("pool.get");
    let account_row = client
        .query_one(
            "INSERT INTO account (username, password_hash) VALUES ($1, 'x') RETURNING id",
            &[&username],
        )
        .await
        .expect("insert account");
    let account_id: Uuid = account_row.get(0);
    let actor_row = client
        .query_one(
            "INSERT INTO actor (account_id, name) VALUES ($1, $2) RETURNING id",
            &[&account_id, &username],
        )
        .await
        .expect("insert actor");
    (account_id, actor_row.get(0))
}

/// Seed a second `actor` on an existing account and return its id — the
/// multi-actor fixture the acting-selector and account-deletion cases need.
///
/// # Panics
///
/// Panics if the pool is unreachable or the insert fails (an unknown
/// `account_id`, or a `name` already taken on that account).
pub async fn seed_extra_actor(pool: &Pool, account_id: Uuid, name: &str) -> Uuid {
    let client = pool.get().await.expect("pool.get");
    let actor_row = client
        .query_one(
            "INSERT INTO actor (account_id, name) VALUES ($1, $2) RETURNING id",
            &[&account_id, &name],
        )
        .await
        .expect("insert extra actor");
    actor_row.get(0)
}

/// Grant `role` to `actor_id` by direct insert, bypassing the offer/accept
/// flow.
///
/// Unscoped and un-attributed — `scope_kind` / `scope_id` / `granted_by` /
/// `expires_at` take their column defaults. A suite that needs any of those
/// populated writes its own insert (`fuz_auth`'s `seed_role_grant_direct`
/// does, for the grant-history audit cases).
///
/// # Panics
///
/// Panics if the pool is unreachable or the insert fails (an unknown
/// `actor_id`, or the role already granted).
pub async fn grant_role(pool: &Pool, actor_id: Uuid, role: &str) {
    let client = pool.get().await.expect("pool.get");
    client
        .execute(
            "INSERT INTO role_grant (actor_id, role) VALUES ($1, $2)",
            &[&actor_id, &role],
        )
        .await
        .expect("insert role_grant");
}

/// Grant `role` to `actor_id` bound to a scope, by direct insert — the
/// paired `(scope_kind, scope_id)` the `role_grant_scope_kind_paired` CHECK
/// demands.
///
/// Writes what the grant verbs refuse too: a scoped **builtin** role (a scoped
/// `admin`) is how the suites stand up the legacy row the global-only gates
/// must ignore.
///
/// # Panics
///
/// Panics if the pool is unreachable or the insert fails (an unknown
/// `actor_id`, or the role already granted at that scope).
pub async fn grant_scoped_role(
    pool: &Pool,
    actor_id: Uuid,
    role: &str,
    scope_kind: &str,
    scope_id: Uuid,
) {
    let client = pool.get().await.expect("pool.get");
    client
        .execute(
            "INSERT INTO role_grant (actor_id, role, scope_kind, scope_id) VALUES ($1, $2, $3, $4)",
            &[&actor_id, &role, &scope_kind, &scope_id],
        )
        .await
        .expect("insert scoped role_grant");
}

/// Refuse every future `audit_log` INSERT whose `event_type` is one of
/// `event_types`, with a `CHECK` constraint — for the suites that drive a
/// revocation whose audit write fails.
///
/// `NOT VALID` skips the existing rows. A `CHECK` rather than `REVOKE INSERT`
/// because the suite's role may be a superuser, which privileges don't bind.
/// The event types are spliced in as SQL literals, so pass only fixed test
/// constants.
///
/// # Panics
///
/// Panics if the pool is unreachable or the `ALTER TABLE` fails (no
/// `audit_log` table, or the constraint already added).
pub async fn refuse_audit_rows(pool: &Pool, event_types: &[&str]) {
    let list = event_types
        .iter()
        .map(|t| format!("'{t}'"))
        .collect::<Vec<_>>()
        .join(", ");
    pool.get()
        .await
        .expect("pool.get")
        .batch_execute(&format!(
            "ALTER TABLE audit_log ADD CONSTRAINT refuse_revocation_audit \
             CHECK (event_type NOT IN ({list})) NOT VALID"
        ))
        .await
        .expect("add the audit-refusing CHECK constraint");
}
