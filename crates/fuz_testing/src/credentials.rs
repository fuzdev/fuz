//! The credential fixtures — a signed session cookie, an `api_token` row, and
//! a daemon-token state — shared by the spine's `#[ignore]` `PostgreSQL`
//! suites.
//!
//! Third sibling of [`crate::fresh_db`] and [`crate::seed`], one layer further
//! into the request: `fresh_db` hands a suite a migrated pool, `seed` gives it
//! an identity, and this module mints the credential that identity
//! authenticates with — one per channel the credential walk
//! (`AuthGate::resolve_credential`) tries — and the [`testing_auth_gate`] a
//! suite resolves it through.
//! `fuz_auth`'s `public_request_context` and `resolve_auth`,
//! `fuz_fact_serving`'s `serve`, and `fuz_realtime`'s `audit_stream` each
//! hand-copied the session-cookie mint (three copies), the `api_token` mint
//! (three), the `TokenScope::Methods` document (three), the keyring (six), and
//! the daemon-token state literal (four) — the same duplication `seed` was
//! extracted to end.
//!
//! ### The cookie mint returns a *request* header value
//!
//! [`sign_session_cookie`] builds a **`Set-Cookie`** value — `name=value`
//! followed by `; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=…`. A
//! request `Cookie` header is only the `name=value` pair, so
//! [`mint_session_cookie`] strips the attributes and every caller can hand the
//! result straight to a `Cookie` header. The three copies each re-derived
//! that, two by splitting on `;` and one by stripping the name prefix and
//! re-adding it.
//!
//! ### The daemon-token state is built as a literal, and must be
//!
//! `fuz_auth` exposes no constructor for [`DaemonTokenState`] — the producer
//! lives in [`crate::daemon_token`] by dep-graph rule, so no production binary
//! can mint or persist the credential. A test that only needs the *shape*
//! (a bound keeper and a token to send) would otherwise spell the struct
//! literal itself. [`daemon_token_state`] is that
//! literal, once: a field added to the struct is one compile error, not
//! one per suite.
//!
//! ### A bearer fixture carries no `Origin` / `Referer`
//!
//! Not enforced here — it is a property of the *request* a suite builds, not
//! of the token — but it belongs with the mint: the bearer leg of
//! the credential walk refuses a browser-context request outright, so
//! a case that sets either header passes for the wrong reason. Every suite
//! consuming [`mint_api_token`] builds its headers without them.

#![expect(
    clippy::expect_used,
    reason = "a test harness: a setup fault panics loudly naming the step, and the in-tests carve-out doesn't reach a library module"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use fuz_auth::api_token_queries::query_create_api_token;
use fuz_auth::keyring::MIN_KEY_LENGTH;
use fuz_auth::{
    AuthGate, CredentialType, DAEMON_TOKEN_HEADER, DaemonTokenState, GeneratedApiToken, Keyring,
    ResolvedAuth, SESSION_COOKIE_NAME, SharedDaemonTokenState, TokenScopeDocument,
    generate_api_token, generate_session_token, hash_session_token, sign_session_cookie,
};
use fuz_db::Pool;
use parking_lot::RwLock;
use uuid::Uuid;

/// A fixture [`Keyring`] — a single key of [`MIN_KEY_LENGTH`] `k`s, the
/// shortest key [`Keyring::new`] accepts. Cookies signed with it verify
/// against it and nothing else, which is all any suite needs.
///
/// # Panics
///
/// Never reached — one key at the minimum length is a value
/// [`Keyring::new`] accepts.
#[must_use]
pub fn testing_keyring() -> Keyring {
    Keyring::new(&"k".repeat(MIN_KEY_LENGTH)).expect("a minimum-length key builds a keyring")
}

/// The one origin a [`testing_auth_gate`] allows — loopback, so it is never a
/// real deployment's, and disjoint from the foreign origin a suite sends.
pub const TESTING_ALLOWED_ORIGIN: &str = "http://localhost:5173";

/// A fixture [`AuthGate`] over `pool`.
///
/// It holds [`testing_keyring`], no daemon-token state,
/// [`SESSION_COOKIE_NAME`], and an allowlist of [`TESTING_ALLOWED_ORIGIN`]
/// alone. A suite that needs another field sets it
/// with the struct-update syntax
/// (`AuthGate { daemon_token_state: Some(state), ..testing_auth_gate(pool) }`).
///
/// # Panics
///
/// Never reached — [`TESTING_ALLOWED_ORIGIN`] is a valid allowlist.
#[must_use]
pub fn testing_auth_gate(pool: Pool) -> AuthGate {
    AuthGate {
        pool,
        keyring: Arc::new(testing_keyring()),
        daemon_token_state: None,
        session_cookie_name: SESSION_COOKIE_NAME,
        allowed_origins: fuz_http::AllowedOrigins::parse(TESTING_ALLOWED_ORIGIN)
            .expect("a loopback origin is a valid allowlist"),
    }
}

/// Mint a session for `account_id` under `cookie_name`, inserting the backing
/// `auth_session` row, and return the **request** `Cookie` header value.
///
/// The row is keyed by the blake3 hash of the token, exactly as
/// `query_create_session` stores it, and expires a day out — comfortably
/// future so the server-side row gate (`WHERE expires_at > NOW()`) passes. A
/// suite that wants the *expired* case wants
/// [`crate::testing_mint_session`]'s backdated mint instead, which is
/// constrained to only ever produce a dead row.
///
/// Bypasses `create_capped_session`, so no concurrent-session eviction runs —
/// the point of a fixture is a credential, not the capping policy, which has
/// its own coverage in `fuz_auth`.
///
/// # Panics
///
/// Panics with the failing step named if the pool is unreachable or the insert
/// fails (an unknown `account_id` being the usual cause).
pub async fn mint_session_cookie(
    pool: &Pool,
    keyring: &Keyring,
    account_id: Uuid,
    cookie_name: &str,
) -> String {
    let token = generate_session_token();
    let token_hash = hash_session_token(&token);
    let client = pool.get().await.expect("pool.get");
    client
        .execute(
            "INSERT INTO auth_session (id, account_id, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '1 day')",
            &[&token_hash.as_str(), &account_id],
        )
        .await
        .expect("insert auth_session");
    let set_cookie = sign_session_cookie(keyring, &token, cookie_name);
    // Drop the `; Path=/; …` attributes — a request header is `name=value`.
    set_cookie
        .split(';')
        .next()
        .expect("split always yields one element")
        .to_owned()
}

/// Mint an `api_token` row for `account_id` under `scope` and return the
/// generated credential: `.token` is the raw bearer a request carries, `.id`
/// the public `tok_…` id a `token_revoke` audit row names.
///
/// Returns [`GeneratedApiToken`] rather than a narrower fixture type so the
/// mint has no shape of its own to keep in sync — it is the production
/// generator's output, persisted.
///
/// The row takes the column default for `expires_at` (none). A suite pinning
/// expiry behaviour writes its own insert; `fuz_auth`'s `api_token` suite
/// does, since bounded-vs-eternal lifetime is the thing it tests.
///
/// # Panics
///
/// Panics with the failing step named if the pool is unreachable, the scope
/// document fails to serialize, or the insert fails.
pub async fn mint_api_token(
    pool: &Pool,
    account_id: Uuid,
    scope: &TokenScopeDocument,
) -> GeneratedApiToken {
    let minted = generate_api_token();
    let client = pool.get().await.expect("pool.get");
    query_create_api_token(
        &client,
        &minted.id,
        &account_id,
        "test-token",
        &minted.token_hash,
        &scope.to_json().expect("scope serializes"),
        None,
    )
    .await
    .expect("insert api_token");
    minted
}

/// A `TokenScope::Methods` document over `names`.
///
/// The empty set is included and is the interesting one: it leaves a token a
/// valid credential that admits no RPC method at all, which is what separates
/// the credential gate from the scope gate in a denial-ordering case.
#[must_use]
pub fn narrowed_scope(names: &[&str]) -> TokenScopeDocument {
    let methods: BTreeSet<String> = names.iter().map(|n| (*n).to_owned()).collect();
    TokenScopeDocument::methods(methods)
}

/// The daemon token every fixture sends. A fixed literal — validation is a
/// constant-time compare against the state below, so the value carries no
/// requirement beyond both halves agreeing on it.
pub const TESTING_DAEMON_TOKEN: &str = "daemon-token-fixture";

/// Daemon-token state holding `current_token`, optionally bound to a keeper
/// account.
///
/// `previous_token` is `None` (no rotation window) and `token_path` is empty:
/// nothing here writes the token file, which is the half
/// [`crate::daemon_token`] owns. A suite exercising persistence wants that
/// module's real producer, not this.
#[must_use]
pub fn daemon_token_state(
    current_token: &str,
    keeper_account_id: Option<Uuid>,
) -> SharedDaemonTokenState {
    Arc::new(RwLock::new(DaemonTokenState {
        current_token: current_token.to_owned(),
        previous_token: None,
        keeper_account_id,
        token_path: PathBuf::new(),
    }))
}

/// Mint a credential of `credential_type` for `account_id` and resolve it
/// through the credential walk, as a request carrying it would be.
///
/// For a suite that drives the dispatcher directly (`perform_action`) and
/// needs the [`ResolvedAuth`] a transport would hand it — a value only the
/// walk builds, so this goes through it rather than around it. A session is a
/// fresh signed cookie ([`mint_session_cookie`]), an API token a fresh
/// full-scope row ([`mint_api_token`]), and a daemon token
/// [`TESTING_DAEMON_TOKEN`] with `account_id` as its keeper.
///
/// # Panics
///
/// When the account does not exist (or is soft-deleted), so the credential
/// does not resolve, or on any database fault — a setup fault either way.
pub async fn resolve_test_credential(
    pool: &Pool,
    account_id: Uuid,
    credential_type: CredentialType,
) -> ResolvedAuth {
    let mut headers = HeaderMap::new();
    let mut gate = testing_auth_gate(pool.clone());
    match credential_type {
        CredentialType::Session => {
            let cookie =
                mint_session_cookie(pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME)
                    .await;
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&cookie).expect("cookie header"),
            );
        }
        CredentialType::ApiToken => {
            let minted = mint_api_token(pool, account_id, &TokenScopeDocument::full()).await;
            let bearer = format!("Bearer {}", minted.token);
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&bearer).expect("bearer header"),
            );
        }
        CredentialType::DaemonToken => {
            gate.daemon_token_state =
                Some(daemon_token_state(TESTING_DAEMON_TOKEN, Some(account_id)));
            headers.insert(
                DAEMON_TOKEN_HEADER,
                HeaderValue::from_static(TESTING_DAEMON_TOKEN),
            );
        }
    }
    let resolved = gate
        .preflight(&headers, fuz_http::UNRESOLVED_CLIENT_IP)
        .await
        .expect("the fixture sends no origin")
        .expect("the fixture credential resolves");
    assert_eq!(
        resolved.credential_type(),
        credential_type,
        "the walk resolved the minted channel"
    );
    resolved
}
