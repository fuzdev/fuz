//! Integration tests for `AuthGate::public_request_context` — the pure-public
//! resolver's tombstone handling and its credential dispositions.
//!
//! The resolver walks the shared daemon-token → cookie → bearer pipeline and
//! then applies two public-route rules, both pinned here:
//!
//! - **Active actors only.** A soft-deleted (tombstoned) actor must neither
//!   (a) demote an otherwise single-actor account to anonymous, nor (b) — the
//!   hazard — get resolved as the sole actor and carry its `role_grants` into
//!   a public read. The acting-actor path's equivalent rule is pinned by
//!   `account_delete.rs`'s `soft_deleted_actor_not_resolved_as_acting_actor`.
//! - **A scope-narrowed API token is anonymous, not refused.** A public route
//!   has an anonymous reading, so a 403 would enforce nothing against a holder
//!   who drops the `Authorization` header; the credential is downgraded to the
//!   reach it could obtain anyway. Session and daemon-token credentials are
//!   `TokenScope::Full` by construction and must keep full visibility — the
//!   regression these cases guard is a scope rule that reads as "not full →
//!   anonymous" for *every* credential and silently blanks out logged-in
//!   readers.
//!
//! It also pins that a failed read never reads as anonymous: a fault in the
//! credential walk is that leg's `PublicContextFault::Credential`, whichever
//! of the leg's reads failed, and a failed actor or role-grant read after the
//! walk resolved is `PublicContextFault::CallerRead`.
//!
//! Twin of `fuz_app`'s `serve_fact_route.ts` `build_public_request_context`.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test public_request_context -- --ignored --test-threads=1
//! ```
//!
//! Override the DB URL with `FUZ_AUTH_TEST_URL=postgres://...`.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use axum::http::{HeaderMap, header::AUTHORIZATION, header::COOKIE};
use fuz_auth::daemon_token::DAEMON_TOKEN_HEADER;
use fuz_auth::request_context::RequestActorContext;
use fuz_auth::{
    AuthGate, Keyring, PublicContextFault, SESSION_COOKIE_NAME, SharedDaemonTokenState,
    TokenScopeDocument,
};
use fuz_db::Pool;
use fuz_testing::{
    TESTING_DAEMON_TOKEN, daemon_token_state, mint_api_token, mint_session_cookie, narrowed_scope,
    testing_keyring,
};

mod common;
use common::{fresh_db_pool, seed_account_actor, seed_extra_actor};

/// Resolve with no daemon-token state and no client IP — the shape every
/// cookie / bearer case below wants.
async fn resolve(
    pool: &Pool,
    keyring: &Keyring,
    headers: &HeaderMap,
) -> Option<RequestActorContext> {
    let gate = gate(pool, keyring, None);
    let origin = gate.check_origin(headers).expect("no foreign origin");
    gate.public_request_context(origin, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect("the credential walk reads")
}

/// A gate over `pool` resolving under `keyring`, with `daemon` mounted.
fn gate(pool: &Pool, keyring: &Keyring, daemon: Option<&SharedDaemonTokenState>) -> AuthGate {
    AuthGate {
        keyring: std::sync::Arc::new(keyring.clone()),
        daemon_token_state: daemon.cloned(),
        session_cookie_name: SESSION_COOKIE_NAME,
        ..fuz_testing::testing_auth_gate(pool.clone())
    }
}

/// Mint an `api_token` row under `scope` and return the `Authorization` header
/// carrying its raw token.
///
/// No `Origin` / `Referer` is set: the bearer leg refuses a browser-context
/// request outright, which would make every bearer case below pass for the
/// wrong reason.
async fn bearer_headers(
    pool: &Pool,
    account_id: uuid::Uuid,
    scope: &TokenScopeDocument,
) -> HeaderMap {
    let minted = mint_api_token(pool, account_id, scope).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", minted.token)
            .parse()
            .expect("authorization header"),
    );
    headers
}

/// Daemon-token state bound to `keeper_account_id`, plus the matching header.
fn daemon_state_and_headers(keeper_account_id: uuid::Uuid) -> (SharedDaemonTokenState, HeaderMap) {
    let state = daemon_token_state(TESTING_DAEMON_TOKEN, Some(keeper_account_id));
    let mut headers = HeaderMap::new();
    headers.insert(
        DAEMON_TOKEN_HEADER,
        TESTING_DAEMON_TOKEN.parse().expect("daemon header"),
    );
    (state, headers)
}

/// Seed a valid (future-expiry) `auth_session` row for `account_id` and return
/// the matching `Cookie` request header.
async fn session_headers(pool: &Pool, keyring: &Keyring, account_id: uuid::Uuid) -> HeaderMap {
    let cookie = mint_session_cookie(pool, keyring, account_id, SESSION_COOKIE_NAME).await;
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, cookie.parse().expect("cookie header"));
    headers
}

/// Soft-delete (tombstone) one actor — only `deleted_at` matters to the
/// active-actor filter.
async fn tombstone_actor(pool: &Pool, actor_id: uuid::Uuid) {
    let client = pool.get().await.expect("pool.get");
    client
        .execute(
            "UPDATE actor SET deleted_at = NOW() WHERE id = $1",
            &[&actor_id],
        )
        .await
        .expect("tombstone actor");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn public_context_resolves_single_active_actor() {
    // Control: an account with exactly one (active) actor resolves to that
    // actor — the normal single-actor path the tombstone cases must preserve.
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    let (account_id, actor_id) = seed_account_actor(&pool, "solo").await;
    let headers = session_headers(&pool, &keyring, account_id).await;

    let ctx = resolve(&pool, &keyring, &headers)
        .await
        .expect("single active actor must resolve to a context");
    assert_eq!(ctx.actor.id, actor_id);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn public_context_ignores_tombstoned_actor_in_count() {
    // Functional half: 1 active + 1 tombstoned is still a single-actor account.
    // The tombstone must not push the count to 2 and demote the owner to
    // anonymous (denying them their own actor's view on a public read).
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    let (account_id, active_id) = seed_account_actor(&pool, "primary").await;
    let extra_id = seed_extra_actor(&pool, account_id, "to_delete").await;
    tombstone_actor(&pool, extra_id).await;
    let headers = session_headers(&pool, &keyring, account_id).await;

    let ctx = resolve(&pool, &keyring, &headers)
        .await
        .expect("1 active + 1 tombstoned must resolve the single active actor");
    assert_eq!(
        ctx.actor.id, active_id,
        "must resolve the active actor, not fall back to anonymous"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn public_context_does_not_resolve_a_tombstoned_only_account() {
    // Security half (the hazard the active-actor filter closes): an account whose only actor is
    // tombstoned has *zero* active actors → anonymous. An unfiltered count
    // would see one actor, resolve the deleted actor, and carry its
    // `role_grants` into a public read.
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    let (account_id, actor_id) = seed_account_actor(&pool, "ghost").await;
    tombstone_actor(&pool, actor_id).await;
    let headers = session_headers(&pool, &keyring, account_id).await;

    let ctx = resolve(&pool, &keyring, &headers).await;
    assert!(
        ctx.is_none(),
        "a tombstoned-only account must resolve to anonymous, not the deleted actor"
    );
}

// -- Credential dispositions: scope narrowing downgrades, nothing else ------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn public_context_resolves_a_full_scope_bearer() {
    // The leg the Rust side was missing entirely: a `Full` bearer is a
    // first-class caller here, exactly as the session cookie is.
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    let (account_id, actor_id) = seed_account_actor(&pool, "full_bearer").await;
    let headers = bearer_headers(&pool, account_id, &TokenScopeDocument::full()).await;

    let ctx = resolve(&pool, &keyring, &headers)
        .await
        .expect("a full-scope bearer must resolve to its account's single actor");
    assert_eq!(ctx.actor.id, actor_id);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn public_context_downgrades_a_narrowed_bearer_to_anonymous() {
    // The hole this closed. `Methods(∅)` is the sharpest case — a token that
    // can call no RPC method at all read every fact its account's viewable
    // cells referenced — but the rule is blanket, so a token that *does* name
    // a method downgrades identically. A REST fact read has no RPC method name
    // to test a scope against, and inventing a route→method mapping is the
    // coupling the blanket rule declines.
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    let (account_id, _actor_id) = seed_account_actor(&pool, "narrow_bearer").await;

    for names in [&[][..], &["cell_get"][..], &["cell_get", "cell_list"][..]] {
        let headers = bearer_headers(&pool, account_id, &narrowed_scope(names)).await;
        assert!(
            resolve(&pool, &keyring, &headers).await.is_none(),
            "a narrowed bearer must be anonymous here, scope = {names:?}",
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn public_context_resolves_the_daemon_token_keeper() {
    // The other converged leg: `X-Daemon-Token` is `TokenScope::Full` by
    // construction (no minting step at which a narrowing could be chosen), so
    // it keeps full visibility rather than tripping the downgrade.
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    let (account_id, actor_id) = seed_account_actor(&pool, "keeper").await;
    let (state, headers) = daemon_state_and_headers(account_id);

    let gate = gate(&pool, &keyring, Some(&state));
    let origin = gate.check_origin(&headers).expect("no foreign origin");
    let ctx = gate
        .public_request_context(origin, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect("the credential walk reads")
        .expect("the daemon token resolves the keeper account");
    assert_eq!(ctx.actor.id, actor_id);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn public_context_ignores_an_unknown_bearer() {
    // An unknown token is anonymous, not an error — the same disposition an
    // absent credential gets, so a caller can't probe token existence here.
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    seed_account_actor(&pool, "somebody").await;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        "Bearer fuz_not_a_real_token".parse().expect("header"),
    );

    assert!(resolve(&pool, &keyring, &headers).await.is_none());
}

/// The walk under `headers` over `pool`, `daemon` mounted: the leg whose read
/// failed. Panics if the walk resolves or finds nothing.
async fn failed_leg(
    pool: &Pool,
    keyring: &Keyring,
    daemon: Option<&SharedDaemonTokenState>,
    headers: &HeaderMap,
) -> fuz_auth::CredentialType {
    let gate = gate(pool, keyring, daemon);
    let origin = gate.check_origin(headers).expect("no foreign origin");
    let walk = gate
        .resolve_credential(origin, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect_err("the walk's read fails");
    let origin = gate.check_origin(headers).expect("no foreign origin");
    let public = gate
        .public_request_context(origin, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect_err("the public context is the walk's fault, not anonymous");
    assert_eq!(public, PublicContextFault::Credential(walk));
    walk.leg()
}

/// **A read past the leg's first query is a fault too.** The checkout and the
/// leg's own lookup succeed, and the account read after it fails: each leg
/// ends the walk with its fault rather than resolving nothing, and so does a
/// bearer whose token lookup fails. The fast-lane cases fail the checkout, so
/// none of them reaches these reads.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_failed_read_past_the_lookup_ends_the_walk() {
    use fuz_auth::CredentialType;
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    let (account_id, _) = seed_account_actor(&pool, "read_fails").await;
    let (state, daemon) = daemon_state_and_headers(account_id);
    let cookie = session_headers(&pool, &keyring, account_id).await;
    let bearer = bearer_headers(&pool, account_id, &TokenScopeDocument::full()).await;
    let ddl = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            pool.get()
                .await
                .expect("pool.get")
                .batch_execute(sql)
                .await
                .expect("fault DDL");
        }
    };

    // the control: each leg resolves
    for (headers, daemon) in [(&daemon, Some(&state)), (&cookie, None), (&bearer, None)] {
        let gate = gate(&pool, &keyring, daemon);
        let origin = gate.check_origin(headers).expect("no foreign origin");
        assert!(
            gate.resolve_credential(origin, fuz_http::UNRESOLVED_CLIENT_IP)
                .await
                .expect("the walk reads")
                .is_some()
        );
    }

    // the account read fails after each leg's lookup succeeded
    ddl("ALTER TABLE account RENAME TO account_gone").await;
    let mut daemon_and_cookie = daemon.clone();
    daemon_and_cookie.extend(cookie.clone());
    let mut cookie_and_bearer = cookie.clone();
    cookie_and_bearer.extend(bearer.clone());
    for (name, headers, daemon, leg) in [
        ("daemon", &daemon, Some(&state), CredentialType::DaemonToken),
        ("cookie", &cookie, None, CredentialType::Session),
        ("bearer", &bearer, None, CredentialType::ApiToken),
        (
            "daemon and cookie",
            &daemon_and_cookie,
            Some(&state),
            CredentialType::DaemonToken,
        ),
        (
            "cookie and bearer",
            &cookie_and_bearer,
            None,
            CredentialType::Session,
        ),
    ] {
        assert_eq!(
            failed_leg(&pool, &keyring, daemon, headers).await,
            leg,
            "{name}"
        );
    }
    ddl("ALTER TABLE account_gone RENAME TO account").await;

    // the bearer's own lookup fails
    ddl("ALTER TABLE api_token RENAME TO api_token_gone").await;
    assert_eq!(
        failed_leg(&pool, &keyring, None, &bearer).await,
        CredentialType::ApiToken
    );
}

/// **A failed read past the walk is a fault, not anonymous.** The credential
/// resolves, and the actor read, the role-grant read, or the checkout they
/// share fails: the public
/// context is `CallerRead` — the route's flat 500 — never the anonymous caller
/// that a public cell would still serve.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_failed_caller_read_past_the_walk_is_a_fault() {
    for (label, ddl) in [
        ("actor read", "ALTER TABLE actor RENAME TO actor_gone"),
        (
            "role-grant read",
            "ALTER TABLE role_grant RENAME TO role_grant_gone",
        ),
    ] {
        let pool = fresh_db_pool().await;
        let keyring = testing_keyring();
        let (account_id, actor_id) = seed_account_actor(&pool, "caller_read_fails").await;
        let headers = session_headers(&pool, &keyring, account_id).await;

        // the control: the cookie resolves its single actor
        let ctx = resolve(&pool, &keyring, &headers)
            .await
            .expect("the single-actor account resolves");
        assert_eq!(ctx.actor.id, actor_id, "{label}");

        pool.get()
            .await
            .expect("pool.get")
            .batch_execute(ddl)
            .await
            .expect("fault DDL");
        let gate = gate(&pool, &keyring, None);
        let origin = gate.check_origin(&headers).expect("no foreign origin");
        assert!(
            gate.resolve_credential(origin, fuz_http::UNRESOLVED_CLIENT_IP)
                .await
                .expect("the walk still reads")
                .is_some(),
            "{label}: the credential still resolves"
        );
        let origin = gate.check_origin(&headers).expect("no foreign origin");
        let fault = gate
            .public_request_context(origin, fuz_http::UNRESOLVED_CLIENT_IP)
            .await
            .expect_err("a failed caller read is a fault, not anonymous");
        assert_eq!(fault, PublicContextFault::CallerRead, "{label}");
    }

    // the walk spends the one checkout the pool allows, and the caller read's
    // own checkout is refused
    let pool = fresh_db_pool().await;
    let keyring = testing_keyring();
    let (account_id, _) = seed_account_actor(&pool, "caller_checkout_fails").await;
    let headers = session_headers(&pool, &keyring, account_id).await;
    let gate = gate(&common::budgeted_pool(1), &keyring, None);
    let origin = gate.check_origin(&headers).expect("no foreign origin");
    let fault = gate
        .public_request_context(origin, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect_err("a refused caller checkout is a fault, not anonymous");
    assert_eq!(
        fault,
        PublicContextFault::CallerUnavailable,
        "the caller checkout is the database unavailable"
    );
}
