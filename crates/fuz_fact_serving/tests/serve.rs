//! Integration tests for `fuz_fact_serving::serve` against a real `PostgreSQL`.
//!
//! `serve.rs` is the sole authz'd reader-facade over `fuz_fact` — the axum twin
//! of `fuz_app`'s `serve_fact_route.ts`. These pin the security-consequential
//! behaviors the survey flagged as Rust-side-untested (relying only on the
//! cross-backend suite): the **404-mask** (missing fact / cell / edge / unviewable
//! all collapse to 404), the **`refs ∋ hash` edge check** (run after the view
//! check, so an unviewable cell answers alike whatever it references), the
//! **multi-actor → anonymous** public-route downgrade, the **credential
//! dispositions on the cell-scoped route** (session / daemon-token / full
//! bearer all resolve; a scope-narrowed bearer is downgraded to anonymous
//! rather than refused — including on an *admin* account, whose
//! `can_view_cell` short-circuit the downgrade must precede, and behind a
//! session cookie, which wins the leg precedence and keeps full visibility),
//! the bare-hash route's **admin gate + `?acting=`
//! resolution**, the **`X-Accel-Redirect`** emission for external facts,
//! the **untrusted-content hardening headers** (`X-Content-Type-Options` +
//! `Content-Security-Policy`) on served facts, and the **flat 500** the
//! cell-scoped route answers when one of its own reads fails.
//!
//! The suite spans three migration namespaces (auth + cell + fact) in one
//! database, so it has its own `FUZ_FACT_SERVING_TEST_URL` (default
//! `fuz_fact_serving_test`) rather than sharing another crate's DB — cross-crate
//! test binaries run in parallel and would clobber a shared schema.
//!
//! Gated behind `#[ignore]` — run with:
//! ```text
//! createdb fuz_fact_serving_test
//! cargo test -p fuz_fact_serving --test serve -- --ignored --test-threads=1
//! ```
//!
//! Override the DB URL with `FUZ_FACT_SERVING_TEST_URL=postgres://...`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderName, Request, StatusCode, header};
use axum::response::Response;
use fuz_auth::daemon_token::DAEMON_TOKEN_HEADER;
use fuz_auth::{AUTH_MIGRATIONS, Keyring, ROLE_ADMIN, SharedDaemonTokenState, TokenScopeDocument};
use fuz_cell::CELL_MIGRATIONS;
use fuz_crypto::ContentHash;
use fuz_db::Pool;
use fuz_fact::{FACT_MIGRATIONS, mint_fact_file_url};
use fuz_fact_serving::{FactServingRouteState, bare_fact_router, cell_fact_router};
use fuz_testing::{
    TESTING_DAEMON_TOKEN, TestingDbOptions, fresh_test_db_pool, grant_role, grant_scoped_role,
    mint_api_token, narrowed_scope, seed_account_actor, seed_extra_actor, testing_keyring,
};
use tower::ServiceExt; // for `oneshot`
use uuid::Uuid;

const COOKIE_NAME: &str = "fuz_session";

/// This suite's database: `FUZ_FACT_SERVING_TEST_URL` (default
/// `fuz_fact_serving_test`) over all three namespaces this facade spans, in
/// FK order — auth first (`cell` FKs into `actor`), then cell, then fact.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    env_var: "FUZ_FACT_SERVING_TEST_URL",
    default_db: "fuz_fact_serving_test",
    migrations: &[AUTH_MIGRATIONS, CELL_MIGRATIONS, FACT_MIGRATIONS],
    setup_sql: None,
};

/// Reset the `public` schema, run the auth + cell + fact chains.
/// Single-threaded: the reset drops + recreates the schema.
async fn fresh_db_pool() -> Pool {
    fresh_test_db_pool(DB).await
}

fn keyring() -> Arc<Keyring> {
    Arc::new(testing_keyring())
}

/// [`fuz_testing::mint_session_cookie`] under this suite's cookie name — the
/// one argument every call here would otherwise repeat.
async fn mint_session_cookie(pool: &Pool, keyring: &Keyring, account_id: Uuid) -> String {
    fuz_testing::mint_session_cookie(pool, keyring, account_id, COOKIE_NAME).await
}

/// An nginx config whose `/internal_facts/` location passes the X-Accel
/// validator: `internal;` plus the exported fact hardening header lines.
fn internal_facts_nginx_config() -> String {
    format!(
        "server {{ location ^~ /internal_facts/ {{ internal; {} }} }}",
        fuz_fact_serving::fact_security_header_directives().join(" ")
    )
}

/// Route state with no daemon token; `x_accel` toggles the external-fact
/// handoff (production) vs. disk streaming (dev / tests).
fn state(
    pool: Pool,
    keyring: Arc<Keyring>,
    x_accel: Option<fuz_fact_serving::XAccelConfig>,
) -> FactServingRouteState {
    state_with_daemon_token(pool, keyring, x_accel, None)
}

/// [`state`] with the daemon-token leg mounted — the shape a `testing_*` binary
/// assembles, and the only way to exercise `X-Daemon-Token` on either route
/// (every production assembly leaves this `None`).
fn state_with_daemon_token(
    pool: Pool,
    keyring: Arc<Keyring>,
    x_accel: Option<fuz_fact_serving::XAccelConfig>,
    daemon_token_state: Option<SharedDaemonTokenState>,
) -> FactServingRouteState {
    FactServingRouteState {
        gate: fuz_auth::AuthGate {
            keyring,
            daemon_token_state,
            session_cookie_name: COOKIE_NAME,
            ..fuz_testing::testing_auth_gate(pool)
        },
        facts_dir: PathBuf::from("/nonexistent-facts-dir"),
        x_accel,
    }
}

/// Daemon-token state bound to `keeper_account_id`, plus the raw token this
/// suite sends in `X-Daemon-Token`.
fn daemon_token_state(keeper_account_id: Uuid) -> (SharedDaemonTokenState, String) {
    let state = fuz_testing::daemon_token_state(TESTING_DAEMON_TOKEN, Some(keeper_account_id));
    (state, TESTING_DAEMON_TOKEN.to_owned())
}

/// Seed an active `cell` with the given visibility, refs, and owner. Returns the
/// cell id.
async fn seed_cell(pool: &Pool, visibility: &str, refs: &[&str], created_by: Option<Uuid>) -> Uuid {
    let refs_vec: Vec<String> = refs.iter().map(|s| (*s).to_owned()).collect();
    let client = pool.get().await.unwrap();
    client
        .query_one(
            "INSERT INTO cell (data, visibility, refs, created_by)
             VALUES ('{}'::jsonb, $1::text::cell_visibility, $2::text[], $3) RETURNING id",
            &[&visibility, &refs_vec, &created_by],
        )
        .await
        .unwrap()
        .get(0)
}

/// Seed an embedded fact (bytes live in the row).
async fn seed_embedded_fact(pool: &Pool, hash: &ContentHash, bytes: &[u8], content_type: &str) {
    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO fact (hash, bytes, content_type, size) VALUES ($1, $2, $3, $4)",
            &[
                &hash.to_prefixed(),
                &bytes,
                &content_type,
                &i64::try_from(bytes.len()).expect("size fits i64"),
            ],
        )
        .await
        .unwrap();
}

/// Seed an external fact (`file:<shard>/<rest>` URL, bytes off-row).
async fn seed_external_fact(pool: &Pool, hash: &ContentHash, content_type: &str) -> String {
    let url = mint_fact_file_url(hash).expect("mint file url");
    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO fact (hash, external_url, content_type, size) VALUES ($1, $2, $3, $4)",
            &[&hash.to_prefixed(), &url, &content_type, &123_i64],
        )
        .await
        .unwrap();
    url
}

/// GET `uri` through `router` with an explicit header list.
///
/// The credential-carrying form: the routes read `Cookie`, `Authorization`, and
/// `X-Daemon-Token`, and no case here sets `Origin`/`Referer` — the bearer and
/// daemon-token legs refuse a browser-context request outright, which would
/// make a bearer case pass for the wrong reason.
async fn get_with_headers(router: Router, uri: &str, headers: &[(HeaderName, String)]) -> Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    router
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// GET `uri` through `router`, optionally with a `Cookie` header.
async fn get(router: Router, uri: &str, cookie: Option<&str>) -> Response {
    let headers: Vec<(HeaderName, String)> = cookie
        .map(|c| vec![(header::COOKIE, c.to_owned())])
        .unwrap_or_default();
    get_with_headers(router, uri, &headers).await
}

/// GET `uri` through `router` with an `Authorization: Bearer` header.
async fn get_bearer(router: Router, uri: &str, token: &str) -> Response {
    get_with_headers(
        router,
        uri,
        &[(header::AUTHORIZATION, format!("Bearer {token}"))],
    )
    .await
}

/// GET `uri` through `router` with an `X-Daemon-Token` header.
async fn get_daemon_token(router: Router, uri: &str, token: &str) -> Response {
    get_with_headers(
        router,
        uri,
        &[(
            HeaderName::from_static(DAEMON_TOKEN_HEADER),
            token.to_owned(),
        )],
    )
    .await
}

fn hash_of(data: &[u8]) -> ContentHash {
    ContentHash::blake3(data)
}

/// The flat params refusal both routes answer, byte for byte — the body
/// `fuz_app`'s params middleware emits for a `spec.params` mismatch.
const INVALID_ROUTE_PARAMS_BODY: &str = r#"{"error":"invalid_route_params"}"#;

/// The response body as JSON, for asserting a denial's body alongside its
/// status.
async fn body_json(response: Response) -> serde_json::Value {
    serde_json::from_str(&body_string(response).await).expect("a JSON denial body")
}

/// Collect a response body as a `String`.
async fn body_string(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// -- Cell-scoped route: hash parse + 404-mask + edge check ------------------

/// The off-grammar `{hash}` spellings both routes refuse, where the TS
/// `FactHashSchema` (`^blake3:[0-9a-f]{64}$`) answers 400.
fn off_grammar_hashes() -> Vec<String> {
    vec![
        "not-a-valid-hash".to_owned(),
        // Uppercase hex — the same digest as the lowercase spelling, in a
        // spelling the grammar refuses.
        format!("blake3:{}", "A".repeat(64)),
        // The other algorithm tokens the type knows.
        format!("sha256:{}", "0".repeat(64)),
        format!("sha512:{}", "0".repeat(128)),
        // Digest length, either side of the bound.
        format!("blake3:{}", "0".repeat(63)),
        format!("blake3:{}", "0".repeat(65)),
        // The bare hex, with no algorithm prefix at all.
        "0".repeat(64),
    ]
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_malformed_hash_is_400() {
    let pool = fresh_db_pool().await;
    let router = cell_fact_router(state(pool, keyring(), None));
    for hash in off_grammar_hashes() {
        let uri = format!("/api/cells/{}/facts/{hash}", Uuid::new_v4());
        let response = get(router.clone(), &uri, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{hash}");
        assert_eq!(
            body_string(response).await,
            INVALID_ROUTE_PARAMS_BODY,
            "{hash}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_uppercase_hex_of_a_served_hash_is_400() {
    // The same fact the lowercase spelling serves 200 for, asked for in
    // uppercase hex: one digest, but a spelling the TS twin refuses before it
    // reaches the store, so this route refuses it too.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"case-sensitive-bytes");
    seed_embedded_fact(&pool, &hash, b"case-sensitive-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    let router = cell_fact_router(state(pool, keyring(), None));

    let lowercase = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    assert_eq!(
        get(router.clone(), &lowercase, None).await.status(),
        StatusCode::OK,
        "the lowercase spelling is the positive control"
    );

    let uppercase = format!(
        "/api/cells/{cell_id}/facts/blake3:{}",
        hash.to_hex().to_uppercase()
    );
    let response = get(router, &uppercase, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_string(response).await, INVALID_ROUTE_PARAMS_BODY);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_malformed_cell_id_is_400() {
    // The `{cell_id}` half of the params gate: judged under the `z.uuid()`
    // grammar the TS twin declares, so the hyphenless spelling of a real id —
    // which `Uuid::parse_str` and Postgres both accept — is refused too, with
    // the same body a garbage segment gets.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"bytes");
    let router = cell_fact_router(state(pool, keyring(), None));
    let real_id = Uuid::new_v4().to_string();
    for cell_id in [
        "not-a-uuid".to_owned(),
        real_id.replace('-', ""),
        format!("{{{real_id}}}"),
    ] {
        let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
        let response = get(router.clone(), &uri, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{cell_id}");
        assert_eq!(
            body_string(response).await,
            INVALID_ROUTE_PARAMS_BODY,
            "{cell_id}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_missing_cell_is_404() {
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"bytes");
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{}/facts/{}", Uuid::new_v4(), hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_edge_absent_is_404() {
    // Cell exists + is public + the fact exists, but the cell doesn't reference
    // the hash → 404 (the `refs ∋ hash` edge check, never "exists elsewhere").
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"the-bytes");
    let other = hash_of(b"a-different-fact");
    seed_embedded_fact(&pool, &hash, b"the-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "public", &[&other.to_prefixed()], None).await;
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_public_cell_serves_embedded_200() {
    // Positive control: a public cell that references the hash serves the
    // embedded fact to an anonymous caller.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"hello-bytes");
    seed_embedded_fact(&pool, &hash, b"hello-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain")
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_served_response_carries_security_headers() {
    // Untrusted-content hardening: every served fact carries
    // `X-Content-Type-Options: nosniff` + `Content-Security-Policy:
    // default-src 'none'; sandbox` so a fact stored as (or sniffable to)
    // `text/html` can't execute as stored XSS. Asserted on the embedded
    // serve branch; the disk-stream + X-Accel-Redirect branches share the
    // same `body_response` funnel. These values must stay byte-identical to
    // the TS twin (`serve_fact_route.ts`) for cross-backend parity.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"html-bytes");
    seed_embedded_fact(&pool, &hash, b"<script>alert(1)</script>", "text/html").await;
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
    );
    assert_eq!(
        response
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'none'; sandbox"),
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_external_response_carries_security_headers() {
    // The same hardening headers on the external (`X-Accel-Redirect`) branch —
    // a different `body_response` call site, so pin it independently.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"external-html");
    seed_external_fact(&pool, &hash, "text/html").await;
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    // The X-Accel handoff is reachable only through a validated `internal;`
    // location (make-impossible-states): build the config from a matching nginx.
    let x_accel =
        fuz_fact_serving::XAccelConfig::new("/internal_facts/", &internal_facts_nginx_config())
            .expect("internal location validates");
    let router = cell_fact_router(state(pool, keyring(), Some(x_accel)));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-accel-redirect"));
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
    );
    assert_eq!(
        response
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'none'; sandbox"),
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_private_cell_anonymous_is_404() {
    // A private cell that references the hash is masked from an anonymous caller
    // as 404 (never 403 — the cell→fact edge must not leak).
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"secret-bytes");
    let (_account, owner) = seed_account_actor(&pool, "owner").await;
    seed_embedded_fact(&pool, &hash, b"secret-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_unviewable_cell_answers_alike_whatever_it_references() {
    // The view check runs before the edge check, so a signed-in caller that
    // can't view a private cell gets one answer whether or not the cell
    // references the hash: the masked 404 on a healthy database, and — with the
    // grant read broken, so the view check's own work shows — the flat 500 for
    // both, never a 404 for the hash the cell doesn't reference.
    for break_grants in [false, true] {
        let pool = fresh_db_pool().await;
        let keyring = keyring();
        let hash = hash_of(b"unviewable-bytes");
        let unreferenced = hash_of(b"never-referenced");
        let (_owner_account, owner) = seed_account_actor(&pool, "owner").await;
        let (other_account, _other) = seed_account_actor(&pool, "other").await;
        seed_embedded_fact(&pool, &hash, b"unviewable-bytes", "text/plain").await;
        let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
        let cookie = mint_session_cookie(&pool, &keyring, other_account).await;
        if break_grants {
            execute(
                &pool,
                "ALTER TABLE cell_grant RENAME COLUMN granted_by TO granted_by_gone",
            )
            .await;
        }
        let router = cell_fact_router(state(pool, keyring, None));
        let mut answers = Vec::new();
        for asked in [&hash, &unreferenced] {
            let uri = format!("/api/cells/{cell_id}/facts/{}", asked.to_prefixed());
            let response = get(router.clone(), &uri, Some(&cookie)).await;
            let status = response.status();
            answers.push((status, body_string(response).await));
        }
        let expected_status = if break_grants {
            StatusCode::INTERNAL_SERVER_ERROR
        } else {
            StatusCode::NOT_FOUND
        };
        assert_eq!(answers[0].0, expected_status, "break_grants={break_grants}");
        assert_eq!(answers[1], answers[0], "break_grants={break_grants}");
    }
}

// -- Public-route auth model: owner vs. multi-actor → anonymous -------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_private_cell_single_actor_owner_serves_200() {
    // A single-actor owner resolves from the session cookie and can view their
    // own private cell's fact.
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"owner-bytes");
    let (account, owner) = seed_account_actor(&pool, "owner").await;
    seed_embedded_fact(&pool, &hash, b"owner-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = cell_fact_router(state(pool, keyring, None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_multi_actor_is_treated_as_anonymous_404() {
    // Same private cell + owner, but the account is now multi-actor. The public
    // route has no `acting` slot, so a multi-actor caller is downgraded to
    // anonymous → the private cell is 404 even with a valid session.
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"owner-bytes");
    let (account, owner) = seed_account_actor(&pool, "owner").await;
    seed_extra_actor(&pool, account, "owner_persona_2").await; // now multi-actor
    seed_embedded_fact(&pool, &hash, b"owner-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = cell_fact_router(state(pool, keyring, None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -- Public-route auth model: credential dispositions -----------------------
//
// The cell-scoped route walks the full daemon-token → cookie → bearer pipeline.
// The session-cookie leg's 200 is `cell_fact_private_cell_single_actor_owner_serves_200`
// above — it is also the regression guard for the scope rule, since a rule that
// read "scope is not full → anonymous" for *every* credential would blank out
// every logged-in reader on this route while every other assertion here passed.

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_full_scope_bearer_serves_private_cell_200() {
    // A `TokenScope::Full` bearer is a first-class caller here — the leg the
    // Rust side answered 404 for before, where the TS twin answered 200.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"owner-bytes");
    let (account, owner) = seed_account_actor(&pool, "owner").await;
    seed_embedded_fact(&pool, &hash, b"owner-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
    let token = mint_api_token(&pool, account, &TokenScopeDocument::full())
        .await
        .token;
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get_bearer(router, &uri, &token).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_narrowed_bearer_is_anonymous_on_a_private_cell_404() {
    // The hole this closed. `Methods(∅)` — a token that can call no RPC method
    // at all — read every fact any of its account's viewable cells referenced.
    // The rule is blanket, so a token that *does* name a method downgrades
    // identically: a REST fact read has no RPC method name to test a scope
    // against, and inventing a route→method mapping is the coupling the
    // blanket rule declines.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"owner-bytes");
    let (account, owner) = seed_account_actor(&pool, "owner").await;
    seed_embedded_fact(&pool, &hash, b"owner-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());

    for names in [&[][..], &["cell_get"][..], &["cell_get", "cell_list"][..]] {
        let token = mint_api_token(&pool, account, &narrowed_scope(names))
            .await
            .token;
        let router = cell_fact_router(state(pool.clone(), keyring(), None));
        let response = get_bearer(router, &uri, &token).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "narrowed bearer (scope = {names:?}) must be masked, not served",
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_narrowed_bearer_still_reads_a_public_cell_200() {
    // The half that pins *downgrade* rather than *refuse*: the same inert
    // `Methods(∅)` token reads a public cell's fact, because an anonymous
    // caller may — which is exactly why a 403 here would enforce nothing (the
    // holder would simply drop the header and get this 200 anyway).
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"public-bytes");
    let (account, _actor) = seed_account_actor(&pool, "owner").await;
    seed_embedded_fact(&pool, &hash, b"public-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    let token = mint_api_token(&pool, account, &narrowed_scope(&[]))
        .await
        .token;
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get_bearer(router, &uri, &token).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_narrowed_bearer_on_an_admin_account_is_404() {
    // The most adversarial input the rule faces. `can_view_cell` short-circuits
    // on the global admin grant (`has_scoped_role(ROLE_ADMIN, None)`) *before*
    // the public-visibility branch, so an admin context sees every cell —
    // which means the downgrade has to happen upstream, at context
    // construction, or a `Methods(∅)` token on an admin account reads every
    // private cell in the database.
    //
    // Structurally impossible today: `build_public_request_context` applies the
    // scope rule and returns `None` before it ever loads the actor or its role
    // grants, so no admin context exists to short-circuit on. That ordering is
    // exactly what a later refactor could invert (resolving the actor first,
    // then filtering by scope), and this pins it.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"admin-owned-bytes");
    let (account, admin_actor) = seed_account_actor(&pool, "admin_user").await;
    grant_role(&pool, admin_actor, ROLE_ADMIN).await;
    seed_embedded_fact(&pool, &hash, b"admin-owned-bytes", "text/plain").await;
    // Owned by nobody the admin is, and private — visible to the admin *only*
    // through the admin short-circuit, so a 200 here could mean nothing else.
    let (_other_account, other_actor) = seed_account_actor(&pool, "stranger").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(other_actor)).await;
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());

    // Control: the same admin, on a session cookie, does see it.
    let keyring = keyring();
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = cell_fact_router(state(pool.clone(), Arc::clone(&keyring), None));
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the admin short-circuit must admit this cell, or the bearer case below proves nothing",
    );

    // The assertion: a narrowed bearer on that same admin account is anonymous,
    // so the admin short-circuit never runs and the private cell stays masked.
    let token = mint_api_token(&pool, account, &narrowed_scope(&[]))
        .await
        .token;
    let router = cell_fact_router(state(pool, keyring, None));
    let response = get_bearer(router, &uri, &token).await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a narrowed bearer must not inherit its admin account's cell visibility",
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_cookie_wins_over_a_narrowed_bearer_200() {
    // Leg precedence is daemon-token → cookie → bearer, first match wins, so a
    // request carrying both a session cookie and a narrowed bearer resolves on
    // the cookie and never reaches the bearer leg — the session keeps its full
    // visibility. The regression this guards is a scope rule applied after the
    // walk rather than to the credential the walk returned: a browser that
    // happens to also send an `Authorization` header would silently lose access
    // to its own private cells.
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"owner-bytes");
    let (account, owner) = seed_account_actor(&pool, "owner").await;
    seed_embedded_fact(&pool, &hash, b"owner-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let token = mint_api_token(&pool, account, &narrowed_scope(&[]))
        .await
        .token;
    let router = cell_fact_router(state(pool, keyring, None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get_with_headers(
        router,
        &uri,
        &[
            (header::COOKIE, cookie),
            (header::AUTHORIZATION, format!("Bearer {token}")),
        ],
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the cookie leg matches first; a narrowed bearer alongside it must not demote the session",
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_daemon_token_serves_private_cell_200() {
    // The other converged leg: `X-Daemon-Token` resolves the keeper account and
    // is `TokenScope::Full` by construction, so it keeps full visibility rather
    // than tripping the narrowed-token downgrade.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"keeper-bytes");
    let (account, keeper_actor) = seed_account_actor(&pool, "keeper").await;
    seed_embedded_fact(&pool, &hash, b"keeper-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(keeper_actor)).await;
    let (daemon_state, token) = daemon_token_state(account);
    let router = cell_fact_router(state_with_daemon_token(
        pool,
        keyring(),
        None,
        Some(daemon_state),
    ));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get_daemon_token(router, &uri, &token).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_unknown_bearer_is_404_not_500() {
    // An unrecognized token is anonymous, not an error: the private cell stays
    // masked as 404, and a caller learns nothing about token validity from the
    // status.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"owner-bytes");
    let (_account, owner) = seed_account_actor(&pool, "owner").await;
    seed_embedded_fact(&pool, &hash, b"owner-bytes", "text/plain").await;
    let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get_bearer(router, &uri, "fuz_not_a_real_token").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -- External facts: X-Accel-Redirect ---------------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_external_emits_x_accel_redirect() {
    // An external fact under a production `XAccelConfig` hands off to nginx via
    // an `X-Accel-Redirect` header (no disk read).
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"external-bytes");
    let url = seed_external_fact(&pool, &hash, "image/png").await;
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    // The X-Accel handoff is reachable only through a validated `internal;`
    // location (make-impossible-states): build the config from a matching nginx.
    let x_accel =
        fuz_fact_serving::XAccelConfig::new("/internal_facts/", &internal_facts_nginx_config())
            .expect("internal location validates");
    let router = cell_fact_router(state(pool, keyring(), Some(x_accel)));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    // url is `file:<shard>/<rest>`; the redirect drops the `file:` and prefixes.
    let suffix = url.strip_prefix("file:").unwrap();
    assert_eq!(
        response
            .headers()
            .get("x-accel-redirect")
            .and_then(|v| v.to_str().ok()),
        Some(format!("/internal_facts/{suffix}").as_str())
    );
}

// -- Bare-hash route: admin gate + ?acting= ---------------------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_no_credentials_is_401() {
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"bytes");
    let router = bare_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // The flat body the TS `require_auth` middleware returns. This route used
    // to answer a bare status with no body at all, and every case on both
    // spines asserted only the code — so nothing saw it.
    assert_eq!(
        body_json(response).await["error"],
        "authentication_required"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_non_admin_is_403() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"bytes");
    seed_embedded_fact(&pool, &hash, b"bytes", "text/plain").await;
    let (account, _actor) = seed_account_actor(&pool, "plain_user").await; // no admin grant
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = bare_fact_router(state(pool, keyring, None));
    let uri = format!("/api/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_json(response).await;
    assert_eq!(body["error"], "insufficient_permissions");
    assert_eq!(body["required_roles"][0], ROLE_ADMIN);
}

/// The bare route reads the **global** admin grant: a scoped `admin` row
/// (legacy data — no grant path mints one) reads no fact.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_scoped_admin_is_403() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"scoped-bytes");
    seed_embedded_fact(&pool, &hash, b"scoped-bytes", "text/plain").await;
    let (account, actor) = seed_account_actor(&pool, "scoped_admin").await;
    grant_scoped_role(&pool, actor, ROLE_ADMIN, "space", Uuid::new_v4()).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = bare_fact_router(state(pool, keyring, None));
    let uri = format!("/api/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_single_actor_admin_serves_200() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"admin-bytes");
    seed_embedded_fact(&pool, &hash, b"admin-bytes", "text/plain").await;
    let (account, actor) = seed_account_actor(&pool, "admin_user").await;
    grant_role(&pool, actor, ROLE_ADMIN).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = bare_fact_router(state(pool, keyring, None));
    let uri = format!("/api/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// The credential resolves on the request's first checkout and the route's
/// own checkout after it is refused: the flat 503, as on the cell-scoped
/// route, not the 500 of a failed read.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_refused_checkout_is_503() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let (account, actor) = seed_account_actor(&pool, "admin_checkout").await;
    grant_role(&pool, actor, ROLE_ADMIN).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let budgeted = fuz_testing::budgeted_pool(&DB.url(), 1);
    let router = bare_fact_router(state(budgeted, keyring, None));
    let uri = format!("/api/facts/{}", hash_of(b"unread").to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        body_string(response).await,
        r#"{"error":"service_unavailable"}"#
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_multi_actor_admin_requires_acting() {
    // A multi-actor account whose admin actor needs disambiguation: without
    // `?acting=` it must **pick** (400 `actor_required`, with the list to pick
    // from); naming the admin actor resolves it (200).
    //
    // A bare 403 would be a local reading ("no persona, so not
    // admin") rather than the authorization-phase denial the twin emits for a
    // route declaring `actor: 'required'`.
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"admin-bytes");
    seed_embedded_fact(&pool, &hash, b"admin-bytes", "text/plain").await;
    let (account, admin_actor) = seed_account_actor(&pool, "admin_user").await;
    seed_extra_actor(&pool, account, "second_persona").await; // multi-actor
    grant_role(&pool, admin_actor, ROLE_ADMIN).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let hash_prefixed = hash.to_prefixed();

    // No `acting` → multi-actor must pick → 400 with the available list.
    let router = bare_fact_router(state(pool.clone(), Arc::clone(&keyring), None));
    let response = get(
        router,
        &format!("/api/facts/{hash_prefixed}"),
        Some(&cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"], "actor_required");
    assert_eq!(body["available"].as_array().map(Vec::len), Some(2));

    // `?acting=<admin actor>` → resolves to the admin actor → 200.
    let router = bare_fact_router(state(pool, keyring, None));
    let uri = format!("/api/facts/{hash_prefixed}?acting={admin_actor}");
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_foreign_acting_actor_is_400_opaquely() {
    // A selector naming someone else's actor is the twin's opaque
    // `actor_not_on_account` — 400, and deliberately no `available` list, so a
    // guessed id learns nothing about the account it named. (A bare 403
    // before, which is the shape a *role* denial has.)
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"admin-bytes");
    seed_embedded_fact(&pool, &hash, b"admin-bytes", "text/plain").await;
    let (account, admin_actor) = seed_account_actor(&pool, "admin_foreign").await;
    grant_role(&pool, admin_actor, ROLE_ADMIN).await;
    let (_, stranger_actor) = seed_account_actor(&pool, "stranger_actor").await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;

    let router = bare_fact_router(state(pool, keyring, None));
    let uri = format!("/api/facts/{}?acting={stranger_actor}", hash.to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert_eq!(body["error"], "actor_not_on_account");
    assert!(body.get("available").is_none());
}

// -- Bare-hash route: query shape (TS z.strictObject twin) ------------------

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_malformed_hash_is_400() {
    let pool = fresh_db_pool().await;
    let router = bare_fact_router(state(pool, keyring(), None));
    for hash in off_grammar_hashes() {
        let uri = format!("/api/facts/{hash}");
        let response = get(router.clone(), &uri, None).await;
        // Ahead of the 401, like the params gate on the cell-scoped route.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{hash}");
        assert_eq!(
            body_string(response).await,
            INVALID_ROUTE_PARAMS_BODY,
            "{hash}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_unknown_query_key_is_400_before_auth() {
    // The TS twin's strict query schema refuses an unknown key in the
    // params → query → 401 phase order, so even an anonymous caller hears
    // 400 — while a clean anonymous request stays the 401 control
    // (`bare_fact_no_credentials_is_401`).
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"bytes");
    let router = bare_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/facts/{}?foo=1", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_duplicated_acting_takes_the_first() {
    // First occurrence is the admin's real actor, the second garbage —
    // first-wins resolves and serves (a derived-serde extractor would
    // 400 the duplication pre-handler; last-wins would 400 the garbage).
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"dup-acting-bytes");
    seed_embedded_fact(&pool, &hash, b"dup-acting-bytes", "text/plain").await;
    let (account, actor) = seed_account_actor(&pool, "dup_admin").await;
    grant_role(&pool, actor, ROLE_ADMIN).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = bare_fact_router(state(pool, keyring, None));
    let uri = format!(
        "/api/facts/{}?acting={actor}&acting=not-a-uuid",
        hash.to_prefixed()
    );
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_malformed_acting_is_400() {
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"bad-acting-bytes");
    seed_embedded_fact(&pool, &hash, b"bad-acting-bytes", "text/plain").await;
    let (account, actor) = seed_account_actor(&pool, "bad_acting_admin").await;
    grant_role(&pool, actor, ROLE_ADMIN).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = bare_fact_router(state(pool, keyring, None));
    let uri = format!("/api/facts/{}?acting=not-a-uuid", hash.to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_nameless_query_pair_is_ignored_and_serves_200() {
    // `?=x` names no key: the TS twin's strict schema never sees it (Hono
    // leaves a nameless pair out of the query record), so it is no unknown
    // key here either, and the `acting` beside it is still the one read.
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"nameless-pair-bytes");
    seed_embedded_fact(&pool, &hash, b"nameless-pair-bytes", "text/plain").await;
    let (account, actor) = seed_account_actor(&pool, "nameless_admin").await;
    grant_role(&pool, actor, ROLE_ADMIN).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let router = bare_fact_router(state(pool, keyring, None));
    let uri = format!("/api/facts/{}?=x&acting={actor}", hash.to_prefixed());
    let response = get(router, &uri, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

// -- Internal failures: one flat 500 body -----------------------------------

/// The flat 500 both routes answer for a failure of their own, byte for byte.
const INTERNAL_ERROR_BODY: &str = r#"{"error":"internal_error"}"#;

/// Run one statement against the suite database — here, the DDL that breaks
/// the single read a case is about.
async fn execute(pool: &Pool, sql: &str) {
    pool.get().await.unwrap().execute(sql, &[]).await.unwrap();
}

/// `Some(description)` unless `response` is the flat 500: status,
/// `Content-Type`, and body.
async fn internal_error_mismatch(response: Response) -> Option<String> {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = body_string(response).await;
    let matches = status == StatusCode::INTERNAL_SERVER_ERROR
        && content_type.as_deref() == Some("application/json")
        && body == INTERNAL_ERROR_BODY;
    (!matches).then(|| format!("{status}, content-type {content_type:?}, body {body:?}"))
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_internal_failures_answer_the_flat_500_body() {
    // Each read the cell-scoped route makes after its pool checkout, failed in
    // turn by renaming something that read selects and the reads before it do
    // not (every case starts from a fresh schema). All of them answer the
    // envelope the bare route's own failures do — never a bodyless 500 — and
    // none is masked as a 404. Every mismatch is collected, so one run names
    // each arm that drifted.
    let mut mismatches: Vec<String> = Vec::new();

    // The cell read.
    {
        let pool = fresh_db_pool().await;
        let hash = hash_of(b"cell-read-fails");
        let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
        execute(&pool, "ALTER TABLE cell RENAME TO cell_gone").await;
        let router = cell_fact_router(state(pool, keyring(), None));
        let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
        if let Some(m) = internal_error_mismatch(get(router, &uri, None).await).await {
            mismatches.push(format!("cell read: {m}"));
        }
    }

    // The grant list — read only for a resolved caller, so the owner asks.
    // The cell read counts the cell's `cell_grant` rows, so the table has to
    // stay: a column only the grant projection names is what goes.
    {
        let pool = fresh_db_pool().await;
        let keyring = keyring();
        let hash = hash_of(b"grant-list-fails");
        let (account, owner) = seed_account_actor(&pool, "owner").await;
        seed_embedded_fact(&pool, &hash, b"grant-list-fails", "text/plain").await;
        let cell_id = seed_cell(&pool, "private", &[&hash.to_prefixed()], Some(owner)).await;
        let cookie = mint_session_cookie(&pool, &keyring, account).await;
        execute(
            &pool,
            "ALTER TABLE cell_grant RENAME COLUMN granted_by TO granted_by_gone",
        )
        .await;
        let router = cell_fact_router(state(pool, keyring, None));
        let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
        if let Some(m) = internal_error_mismatch(get(router, &uri, Some(&cookie)).await).await {
            mismatches.push(format!("grant list: {m}"));
        }
    }

    // The fact's metadata read.
    {
        let pool = fresh_db_pool().await;
        let hash = hash_of(b"meta-read-fails");
        seed_embedded_fact(&pool, &hash, b"meta-read-fails", "text/plain").await;
        let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
        execute(&pool, "ALTER TABLE fact RENAME TO fact_gone").await;
        let router = cell_fact_router(state(pool, keyring(), None));
        let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
        if let Some(m) = internal_error_mismatch(get(router, &uri, None).await).await {
            mismatches.push(format!("fact metadata read: {m}"));
        }
    }

    // The embedded bytes read: the metadata projection leaves `bytes` out, so
    // renaming that column fails this read and not the one before it.
    {
        let pool = fresh_db_pool().await;
        let hash = hash_of(b"bytes-read-fails");
        seed_embedded_fact(&pool, &hash, b"bytes-read-fails", "text/plain").await;
        let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
        execute(&pool, "ALTER TABLE fact RENAME COLUMN bytes TO bytes_gone").await;
        let router = cell_fact_router(state(pool, keyring(), None));
        let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
        if let Some(m) = internal_error_mismatch(get(router, &uri, None).await).await {
            mismatches.push(format!("embedded bytes read: {m}"));
        }
    }

    // Opening an external fact's file, failing some way other than "no such
    // file" (which is the masked 404): the facts directory is a regular file,
    // so the open is refused as not-a-directory.
    {
        let pool = fresh_db_pool().await;
        let hash = hash_of(b"disk-open-fails");
        seed_external_fact(&pool, &hash, "text/plain").await;
        let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
        let router = cell_fact_router(FactServingRouteState {
            facts_dir: PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")),
            ..state(pool, keyring(), None)
        });
        let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
        if let Some(m) = internal_error_mismatch(get(router, &uri, None).await).await {
            mismatches.push(format!("disk open: {m}"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "arms not answering the flat 500:\n{}",
        mismatches.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_referenced_hash_with_no_fact_row_is_404() {
    // The cell admits the caller and references the hash, but no `fact` row
    // exists: the masked 404, bodyless — not the flat 500 a failed read gets.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"referenced-but-never-stored");
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    let router = cell_fact_router(state(pool, keyring(), None));
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_string(response).await, "");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_external_file_absent_is_404() {
    // An external fact whose file is not on disk is the masked 404 — the one
    // open failure that is not the flat 500. The facts directory exists and is
    // a directory, so the open fails as "no such file" and nothing else.
    let pool = fresh_db_pool().await;
    let hash = hash_of(b"external-file-absent");
    seed_external_fact(&pool, &hash, "text/plain").await;
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    let router = cell_fact_router(FactServingRouteState {
        facts_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        ..state(pool, keyring(), None)
    });
    let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let response = get(router, &uri, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_string(response).await, "");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_external_url_of_another_fact_is_404() {
    // A row for one hash whose `external_url` is another fact's canonical
    // `file:` URL, the other fact's bytes on disk. The shape is valid, the cell
    // is public and references the hash, so only the hash-to-path binding
    // stands between the request and the other fact's bytes — on the disk
    // branch and on the X-Accel branch alike.
    let pool = fresh_db_pool().await;
    let facts_dir = tempfile::tempdir().unwrap();
    let other = hash_of(b"bytes of another fact");
    let other_url = fuz_fact::write_fact_atomic(facts_dir.path(), &other, b"bytes of another fact")
        .await
        .unwrap();
    let hash = hash_of(b"bytes this row claims");
    {
        let client = pool.get().await.unwrap();
        for (h, url) in [(&other, &other_url), (&hash, &other_url)] {
            client
                .execute(
                    "INSERT INTO fact (hash, external_url, content_type, size) VALUES ($1, $2, $3, $4)",
                    &[&h.to_prefixed(), url, &"text/plain", &21_i64],
                )
                .await
                .unwrap();
        }
    }
    let cell_id = seed_cell(
        &pool,
        "public",
        &[&other.to_prefixed(), &hash.to_prefixed()],
        None,
    )
    .await;
    let x_accel =
        fuz_fact_serving::XAccelConfig::new("/internal_facts/", &internal_facts_nginx_config())
            .expect("internal location validates");
    for x_accel in [None, Some(x_accel)] {
        let router = cell_fact_router(FactServingRouteState {
            facts_dir: facts_dir.path().to_path_buf(),
            ..state(pool.clone(), keyring(), x_accel)
        });
        // positive control: the other fact serves through its own address
        let uri = format!("/api/cells/{cell_id}/facts/{}", other.to_prefixed());
        assert_eq!(
            get(router.clone(), &uri, None).await.status(),
            StatusCode::OK
        );
        let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
        let response = get(router, &uri, None).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get("x-accel-redirect").is_none());
        assert_eq!(body_string(response).await, "");
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn bare_fact_internal_failures_answer_the_flat_500_body() {
    // The bare route's own reads past credential resolution, failed in turn:
    // the acting-actor read, then the role read. Same envelope as the
    // cell-scoped route's.
    let mut mismatches: Vec<String> = Vec::new();
    for (label, ddl) in [
        ("actor read", "ALTER TABLE actor RENAME TO actor_gone"),
        (
            "role read",
            "ALTER TABLE role_grant RENAME TO role_grant_gone",
        ),
    ] {
        let pool = fresh_db_pool().await;
        let keyring = keyring();
        let hash = hash_of(b"bare-internal-failure");
        seed_embedded_fact(&pool, &hash, b"bare-internal-failure", "text/plain").await;
        let (account, actor) = seed_account_actor(&pool, "bare_admin").await;
        grant_role(&pool, actor, ROLE_ADMIN).await;
        let cookie = mint_session_cookie(&pool, &keyring, account).await;
        execute(&pool, ddl).await;
        let router = bare_fact_router(state(pool, keyring, None));
        let uri = format!("/api/facts/{}", hash.to_prefixed());
        if let Some(m) = internal_error_mismatch(get(router, &uri, Some(&cookie)).await).await {
            mismatches.push(format!("{label}: {m}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "arms not answering the flat 500:\n{}",
        mismatches.join("\n")
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn a_failed_credential_read_answers_the_500_on_both_routes() {
    // The session lookup fails (`auth_session` renamed away) under a real
    // cookie. The walk stops there with its fault: the cell-scoped route does
    // not go on as anonymous and serve the public cell, and the bare route
    // does not answer the 401 of a caller with no credential. Both answer the
    // fault's plain-text 500, the TS twin's unhandled-error answer.
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"credential-read-fails");
    seed_embedded_fact(&pool, &hash, b"credential-read-fails", "text/plain").await;
    let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
    let (account, actor) = seed_account_actor(&pool, "fault_admin").await;
    grant_role(&pool, actor, ROLE_ADMIN).await;
    let cookie = mint_session_cookie(&pool, &keyring, account).await;
    let cell_uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());
    let bare_uri = format!("/api/facts/{}", hash.to_prefixed());

    // the control: both routes serve under the cookie
    let cell = cell_fact_router(state(pool.clone(), Arc::clone(&keyring), None));
    let bare = bare_fact_router(state(pool.clone(), Arc::clone(&keyring), None));
    assert_eq!(
        get(cell.clone(), &cell_uri, Some(&cookie)).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        get(bare.clone(), &bare_uri, Some(&cookie)).await.status(),
        StatusCode::OK
    );

    execute(
        &pool,
        "ALTER TABLE auth_session RENAME TO auth_session_gone",
    )
    .await;
    for (label, router, uri) in [("cell", cell, &cell_uri), ("bare", bare, &bare_uri)] {
        let response = get(router, uri, Some(&cookie)).await;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{label}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=UTF-8"),
            "{label}"
        );
        assert_eq!(
            body_string(response).await,
            "Internal Server Error",
            "{label}"
        );
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_failed_caller_reads_answer_the_flat_500_body() {
    // The cookie's credential resolves, then the public context's actor read,
    // or its role-grant read, fails. The cell-scoped route answers the flat
    // 500 — the twin's handler throws there — and does not go on as anonymous
    // and serve the public cell.
    let mut mismatches: Vec<String> = Vec::new();
    for (label, ddl) in [
        ("actor read", "ALTER TABLE actor RENAME TO actor_gone"),
        (
            "role-grant read",
            "ALTER TABLE role_grant RENAME TO role_grant_gone",
        ),
    ] {
        let pool = fresh_db_pool().await;
        let keyring = keyring();
        let hash = hash_of(b"caller-read-fails");
        seed_embedded_fact(&pool, &hash, b"caller-read-fails", "text/plain").await;
        let cell_id = seed_cell(&pool, "public", &[&hash.to_prefixed()], None).await;
        let (account, _actor) = seed_account_actor(&pool, "caller_read").await;
        let cookie = mint_session_cookie(&pool, &keyring, account).await;
        let router = cell_fact_router(state(pool.clone(), keyring, None));
        let uri = format!("/api/cells/{cell_id}/facts/{}", hash.to_prefixed());

        // the control: the public cell serves under the cookie
        assert_eq!(
            get(router.clone(), &uri, Some(&cookie)).await.status(),
            StatusCode::OK,
            "{label}"
        );

        execute(&pool, ddl).await;
        if let Some(m) = internal_error_mismatch(get(router, &uri, Some(&cookie)).await).await {
            mismatches.push(format!("{label}: {m}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "arms not answering the flat 500:\n{}",
        mismatches.join("\n")
    );
}

// -- Moderation: the read gate and the steward arm --------------------------

/// Seed a contribution under `root` with the given visibility and moderation,
/// referencing `refs`. Returns the cell id.
async fn seed_contribution(
    pool: &Pool,
    root: Uuid,
    visibility: &str,
    moderation: &str,
    refs: &[&str],
    created_by: Uuid,
) -> Uuid {
    let refs_vec: Vec<String> = refs.iter().map(|s| (*s).to_owned()).collect();
    let client = pool.get().await.unwrap();
    client
        .query_one(
            "INSERT INTO cell (data, visibility, refs, parent_id, root_id, moderation, created_by)
             VALUES ('{}'::jsonb, $1::text::cell_visibility, $2::text[], $3, $3, $4, $5) RETURNING id",
            &[&visibility, &refs_vec, &root, &moderation, &created_by],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_fact_serving_test database"]
async fn cell_fact_pending_contribution_serves_its_steward_only() {
    // A pending contribution flipped public reaches no audience — anonymous and
    // a stranger 404 — while the governing root's (non-admin) owner reads its
    // fact through the steward arm, and the author through the owner arm.
    let pool = fresh_db_pool().await;
    let keyring = keyring();
    let hash = hash_of(b"pending-bytes");
    let (root_owner_account, root_owner) = seed_account_actor(&pool, "root_owner").await;
    let (author_account, author) = seed_account_actor(&pool, "author").await;
    let (stranger_account, _) = seed_account_actor(&pool, "stranger").await;
    seed_embedded_fact(&pool, &hash, b"pending-bytes", "text/plain").await;
    let root = seed_cell(&pool, "public", &[], Some(root_owner)).await;
    let post = seed_contribution(
        &pool,
        root,
        "public",
        "pending",
        &[&hash.to_prefixed()],
        author,
    )
    .await;
    let root_owner_cookie = mint_session_cookie(&pool, &keyring, root_owner_account).await;
    let author_cookie = mint_session_cookie(&pool, &keyring, author_account).await;
    let stranger_cookie = mint_session_cookie(&pool, &keyring, stranger_account).await;
    let router = cell_fact_router(state(pool.clone(), keyring, None));
    let uri = format!("/api/cells/{post}/facts/{}", hash.to_prefixed());

    let status = |cookie: Option<&str>| {
        let router = router.clone();
        let uri = uri.clone();
        let cookie = cookie.map(str::to_owned);
        async move { get(router, &uri, cookie.as_deref()).await.status() }
    };
    assert_eq!(status(None).await, StatusCode::NOT_FOUND, "anonymous");
    assert_eq!(
        status(Some(&stranger_cookie)).await,
        StatusCode::NOT_FOUND,
        "stranger"
    );
    assert_eq!(status(Some(&author_cookie)).await, StatusCode::OK, "author");
    assert_eq!(
        status(Some(&root_owner_cookie)).await,
        StatusCode::OK,
        "steward"
    );

    // A tombstoned root stewards nothing.
    pool.get()
        .await
        .unwrap()
        .execute("UPDATE cell SET deleted_at = NOW() WHERE id = $1", &[&root])
        .await
        .unwrap();
    assert_eq!(
        status(Some(&root_owner_cookie)).await,
        StatusCode::NOT_FOUND,
        "steward of a deleted root"
    );
}
