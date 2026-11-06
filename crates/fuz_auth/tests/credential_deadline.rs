//! PG-backed tests for [`fuz_auth::ResolvedAuth::credential_deadline`] — when
//! a resolved credential stops authenticating, which a long-lived connection
//! opened on it must not outlive.
//!
//! Each case resolves a real credential through [`fuz_auth::AuthGate`] and
//! checks its deadline against the stored expiry:
//!
//! - **session** — the earlier of the signed cookie's expiry and the
//!   `auth_session` row's, whichever is sooner;
//! - **API token** — the row's expiry, and none for an eternal token;
//! - **daemon token** — none.
//!
//! The row's expiry is set relative to the database's `NOW()` and the
//! deadline is read against the server's monotonic clock, so the deadline
//! following the row is the DB-relative read.
//!
//! `#[ignore]`-gated — run:
//! ```text
//! createdb fuz_auth_test
//! cargo test -p fuz_auth --test credential_deadline -- --ignored --test-threads=1
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use fuz_auth::daemon_token::DAEMON_TOKEN_HEADER;
use fuz_auth::token_scope::TokenScopeDocument;
use fuz_auth::{
    AuthGate, CredentialType, ResolvedAuth, SESSION_AGE_MAX, SESSION_COOKIE_NAME,
    SharedDaemonTokenState,
};
use fuz_db::Pool;
use fuz_testing::{
    TESTING_DAEMON_TOKEN, daemon_token_state, mint_api_token, mint_session_cookie, testing_keyring,
};

const DAY: Duration = Duration::from_hours(24);

/// Slack for the clock reads and the round trip between the row's `NOW()`
/// and the server's `Instant::now()` — and the cookie's whole-second expiry.
const SLACK: Duration = Duration::from_secs(5);

async fn resolve(
    pool: &Pool,
    headers: &HeaderMap,
    daemon: Option<&SharedDaemonTokenState>,
) -> ResolvedAuth {
    AuthGate {
        daemon_token_state: daemon.cloned(),
        ..fuz_testing::testing_auth_gate(pool.clone())
    }
    .preflight(headers, fuz_http::UNRESOLVED_CLIENT_IP)
    .await
    .expect("the fixture sends no foreign origin")
    .expect("the fixture credential authenticates")
}

/// Assert `resolved`'s deadline is `remaining` from now, within [`SLACK`].
fn assert_deadline_in(resolved: &ResolvedAuth, remaining: Duration) {
    let deadline = resolved
        .credential_deadline
        .expect("the credential has a deadline");
    let left = deadline.saturating_duration_since(Instant::now());
    assert!(
        remaining.checked_sub(left).is_some_and(|gap| gap <= SLACK),
        "expected a deadline {remaining:?} out, got {left:?}"
    );
}

async fn set_expiry(pool: &Pool, table: &str, interval: &str) {
    pool.get()
        .await
        .unwrap()
        .execute(
            &format!("UPDATE {table} SET expires_at = NOW() + INTERVAL '{interval}'"),
            &[],
        )
        .await
        .unwrap();
}

/// A session's deadline is the earlier of its cookie and its row: the
/// fixture row (a day) under the cookie's 30 days, then the cookie's once
/// the row outlives it, then the row again once it is pulled in to seconds.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_session_deadline_is_the_earlier_of_its_cookie_and_its_row() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "alice").await;
    let cookie =
        mint_session_cookie(&pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, cookie.parse().unwrap());

    let resolved = resolve(&pool, &headers, None).await;
    assert_eq!(resolved.credential_type(), CredentialType::Session);
    assert_deadline_in(&resolved, DAY);

    set_expiry(&pool, "auth_session", "40 days").await;
    assert_deadline_in(
        &resolve(&pool, &headers, None).await,
        Duration::from_secs(SESSION_AGE_MAX),
    );

    set_expiry(&pool, "auth_session", "3 seconds").await;
    assert_deadline_in(
        &resolve(&pool, &headers, None).await,
        Duration::from_secs(3),
    );
}

/// An API token's deadline is its row's expiry; an eternal token has none.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn an_api_token_deadline_is_its_row_and_an_eternal_token_has_none() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "bob").await;
    let minted = mint_api_token(&pool, account_id, &TokenScopeDocument::full()).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", minted.token).parse().unwrap(),
    );

    let eternal = resolve(&pool, &headers, None).await;
    assert_eq!(eternal.credential_type(), CredentialType::ApiToken);
    assert_eq!(eternal.credential_deadline, None);

    // seconds, not days: a day interval is calendar arithmetic in the
    // session's time zone, an hour off across a DST change
    set_expiry(&pool, "api_token", "3153600000 seconds").await;
    assert_deadline_in(&resolve(&pool, &headers, None).await, 36_500 * DAY);

    set_expiry(&pool, "api_token", "3 seconds").await;
    assert_deadline_in(
        &resolve(&pool, &headers, None).await,
        Duration::from_secs(3),
    );
}

/// The daemon token has no row and no expiry, so no deadline.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn the_daemon_token_has_no_deadline() {
    let pool = common::fresh_db_pool().await;
    let (account_id, _) = common::seed_account_actor(&pool, "keeper").await;
    let state = daemon_token_state(TESTING_DAEMON_TOKEN, Some(account_id));
    let mut headers = HeaderMap::new();
    headers.insert(DAEMON_TOKEN_HEADER, TESTING_DAEMON_TOKEN.parse().unwrap());
    let resolved = resolve(&pool, &headers, Some(&state)).await;
    assert_eq!(resolved.credential_type(), CredentialType::DaemonToken);
    assert_eq!(resolved.credential_deadline, None);
}
