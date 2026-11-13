//! API-token lifetime integration tests — the mint + expiry-enforcement pair.
//!
//! `expired_api_token_is_refused` pins the validate chokepoint's expiry
//! predicate (it existed unexercised since the frozen v0 schema — the state
//! was enforced-but-unsettable until `query_create_api_token` gained its
//! `expires_at` parameter). The dispatch tests pin the `lifetime` param
//! end-to-end: a ttl mint stores a bounded expiry, an eternal mint stores
//! NULL, and an omitted lifetime is refused rather than silently defaulted —
//! the divergence class the cross-backend `token_lifetime` suite watches from
//! the wire side. `enforce_limit_returns_exactly_the_evicted_token_ids` pins
//! the cap query's return — the ids `account_token_create` closes connections
//! for. The scope-cap tests pin `MAX_TOKEN_SCOPE_BYTES` as compact UTF-8 bytes
//! on both legs: a document at the cap, written as either spine writes it,
//! resolves and lists although `scope::text` prints it past the cap, and one
//! byte past it is refused at mint and failed closed at read.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fuz_auth::{
    AccountActionContext, AccountActionSpecs, AccountRow, AuditEmitter, ConnectionCloser,
    NoopAuditPostCommit, RequestContext,
    api_token_queries::{
        query_api_token_enforce_limit, query_api_token_list_for_account, query_create_api_token,
        query_validate_api_token,
    },
    generate_api_token,
    token_scope::{MAX_TOKEN_SCOPE_BYTES, TokenScope, TokenScopeDocument},
};
use serde_json::{Value, json};

/// Build an `AccountActionContext` over a seeded account row — the
/// account-grain sibling of `common::ctx` (account actions never resolve an
/// actor).
fn account_ctx<'a>(
    auth: &'a RequestContext,
    audit: &'a Arc<AuditEmitter>,
    closer: &'a Arc<dyn ConnectionCloser>,
) -> AccountActionContext<'a> {
    AccountActionContext {
        auth,
        credential_type: None,
        session_hash: None,
        audit,
        post_commit: &NoopAuditPostCommit,
        connection_closer: closer,
        notification_sender: common::noop_notification_sender(),
        client_ip: Some("127.0.0.1".to_owned()),
    }
}

async fn seed_request_context(pool: &fuz_db::Pool, username: &str) -> RequestContext {
    let account_id = common::seed_account(pool, username, None).await;
    RequestContext {
        account: AccountRow {
            id: account_id,
            username: username.to_owned(),
        },
    }
}

fn full_scope_json() -> String {
    TokenScopeDocument::full().to_json().expect("scope json")
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn expired_api_token_is_refused() {
    let pool = common::fresh_db_pool().await;
    let account_id = common::seed_account(&pool, "token_expiry_user", None).await;
    let client = pool.get().await.expect("pool.get");

    let expired = generate_api_token();
    query_create_api_token(
        &client,
        &expired.id,
        &account_id,
        "expired",
        &expired.token_hash,
        &full_scope_json(),
        Some(SystemTime::now() - Duration::from_secs(3600)),
    )
    .await
    .expect("mint expired token");

    let live = generate_api_token();
    query_create_api_token(
        &client,
        &live.id,
        &account_id,
        "live",
        &live.token_hash,
        &full_scope_json(),
        Some(SystemTime::now() + Duration::from_secs(3600)),
    )
    .await
    .expect("mint live token");

    let refused = query_validate_api_token(&client, &expired.token_hash)
        .await
        .expect("validate query");
    assert!(
        refused.is_none(),
        "a token past its expires_at must not resolve"
    );

    // Control: the same predicate admits an unexpired bounded token, so the
    // refusal above is the expiry gate and not a broken mint.
    let resolved = query_validate_api_token(&client, &live.token_hash)
        .await
        .expect("validate query");
    assert!(
        resolved.is_some_and(|t| t.id == live.id),
        "an unexpired bounded token must resolve"
    );
}

async fn dispatch_token_create(
    pool: &fuz_db::Pool,
    auth: &RequestContext,
    params: &Value,
) -> Result<Value, fuz_http::JsonrpcError> {
    let audit = common::build_audit(pool.clone());
    let closer = common::closer();
    let ctx = account_ctx(auth, &audit, &closer);
    let client = pool.get().await.expect("pool.get");
    AccountActionSpecs::dispatch("account_token_create", params, &ctx, &client).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn mint_with_ttl_lifetime_stores_a_bounded_expiry() {
    let pool = common::fresh_db_pool().await;
    let auth = seed_request_context(&pool, "ttl_minter").await;
    let before = SystemTime::now();

    let result = dispatch_token_create(
        &pool,
        &auth,
        &json!({
            "name": "bounded",
            "scope": {"kind": "full"},
            "lifetime": {"kind": "ttl", "days": 30},
        }),
    )
    .await
    .expect("ttl mint dispatches");

    let expires_at = result
        .get("expires_at")
        .and_then(Value::as_str)
        .expect("ttl mint must report a non-null expires_at");
    assert!(expires_at.ends_with('Z'), "wire form is UTC ISO 8601");

    // The stored row carries the bound (read as SystemTime for arithmetic).
    let id = result.get("id").and_then(Value::as_str).expect("token id");
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one("SELECT expires_at FROM api_token WHERE id = $1", &[&id])
        .await
        .expect("read row");
    let stored: Option<SystemTime> = row.get(0);
    let stored = stored.expect("stored expires_at must be non-NULL");
    let lower = before + Duration::from_hours(29 * 24);
    let upper = before + Duration::from_hours(31 * 24);
    assert!(
        stored > lower && stored < upper,
        "expires_at must land ~30 days out"
    );
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn mint_with_eternal_lifetime_stores_null() {
    let pool = common::fresh_db_pool().await;
    let auth = seed_request_context(&pool, "eternal_minter").await;

    let result = dispatch_token_create(
        &pool,
        &auth,
        &json!({
            "name": "eternal",
            "scope": {"kind": "full"},
            "lifetime": {"kind": "eternal"},
        }),
    )
    .await
    .expect("eternal mint dispatches");

    assert!(
        result.get("expires_at").is_some_and(Value::is_null),
        "an eternal mint must report expires_at: null (present, not omitted)"
    );

    let id = result.get("id").and_then(Value::as_str).expect("token id");
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one("SELECT expires_at FROM api_token WHERE id = $1", &[&id])
        .await
        .expect("read row");
    let stored: Option<SystemTime> = row.get(0);
    assert!(stored.is_none(), "eternal token stores NULL expires_at");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn mint_without_lifetime_is_refused_not_defaulted() {
    let pool = common::fresh_db_pool().await;
    let auth = seed_request_context(&pool, "lifetime_omitter").await;

    let err = dispatch_token_create(
        &pool,
        &auth,
        &json!({"name": "no-lifetime", "scope": {"kind": "full"}}),
    )
    .await
    .expect_err("a mint without lifetime must be refused, never defaulted to eternal");
    assert_eq!(err.code, fuz_http::JsonrpcErrorCode::InvalidParams);

    // And nothing was inserted — the refusal precedes the mint.
    let client = pool.get().await.expect("pool.get");
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM api_token WHERE account_id = $1",
            &[&auth.account.id],
        )
        .await
        .expect("count");
    let count: i64 = row.get(0);
    assert_eq!(count, 0, "the refused mint must not have inserted a row");
}

/// **The token cap returns exactly the ids it evicted** — the oldest past
/// `max_tokens`, nothing else — since `account_token_create` closes the live
/// connections of each id it returns. A second pass over a capped account
/// evicts and returns nothing; another account's tokens are never counted.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn enforce_limit_returns_exactly_the_evicted_token_ids() {
    let pool = common::fresh_db_pool().await;
    let account_id = common::seed_account(&pool, "token_cap_user", None).await;
    let bystander_id = common::seed_account(&pool, "token_cap_bystander", None).await;
    let client = pool.get().await.expect("pool.get");

    // Oldest first, with explicit `created_at`s so the order is the test's.
    let mut ids = Vec::new();
    for (i, owner) in [account_id, account_id, account_id, account_id, bystander_id]
        .iter()
        .enumerate()
    {
        let token = generate_api_token();
        query_create_api_token(
            &client,
            &token.id,
            owner,
            "capped",
            &token.token_hash,
            &full_scope_json(),
            None,
        )
        .await
        .expect("mint token");
        let minutes_ago = 10 - i32::try_from(i).unwrap();
        client
            .execute(
                "UPDATE api_token SET created_at = NOW() - make_interval(mins => $2)
                 WHERE id = $1",
                &[&token.id, &minutes_ago],
            )
            .await
            .expect("backdate token");
        ids.push(token.id);
    }

    let mut evicted = query_api_token_enforce_limit(&client, &account_id, 2)
        .await
        .expect("enforce limit");
    evicted.sort();
    let mut expected = vec![ids[0].clone(), ids[1].clone()];
    expected.sort();
    assert_eq!(evicted, expected, "the two oldest of four, and only them");

    let again = query_api_token_enforce_limit(&client, &account_id, 2)
        .await
        .expect("enforce limit again");
    assert!(
        again.is_empty(),
        "a capped account evicts nothing: {again:?}"
    );

    let surviving: i64 = client
        .query_one(
            "SELECT count(*) FROM api_token WHERE id = ANY($1)",
            &[&ids[2..].to_vec()],
        )
        .await
        .expect("survivor count")
        .get(0);
    assert_eq!(surviving, 3, "the newest two and the bystander's survive");
}

/// The compact JSON of a `methods` document over `methods`, in the order
/// given, as `fuz_app`'s `JSON.stringify` writes it.
fn compact_methods_json(methods: &[String]) -> String {
    serde_json::to_string(&json!({"version": 1, "kind": "methods", "methods": methods})).unwrap()
}

/// Method names whose `methods` document is exactly `bytes` compact UTF-8
/// bytes: `account_token_list`, names ending in `filler`, and an ASCII pad —
/// the list `fuz_app`'s tests build.
fn methods_at_bytes(bytes: usize, filler: &str) -> Vec<String> {
    let mut methods = vec!["account_token_list".to_owned()];
    for i in 0.. {
        let next = format!("scope_cap_{i:03}_{filler}");
        let mut trial = methods.clone();
        trial.extend([next.clone(), String::new()]);
        if compact_methods_json(&trial).len() > bytes {
            break;
        }
        methods.push(next);
    }
    let mut trial = methods.clone();
    trial.push(String::new());
    methods.push("x".repeat(bytes - compact_methods_json(&trial).len()));
    methods
}

/// Store `scope_json` on a fresh token of `account_id` through the mint query,
/// which writes the text as given, and return the token's hash.
async fn store_scope_text(
    client: &deadpool_postgres::Object,
    account_id: &uuid::Uuid,
    name: &str,
    scope_json: &str,
) -> String {
    let token = generate_api_token();
    query_create_api_token(
        client,
        &token.id,
        account_id,
        name,
        &token.token_hash,
        scope_json,
        None,
    )
    .await
    .expect("store the scope text");
    token.token_hash
}

/// **A scope at the byte cap reads on this spine whichever spine wrote it.**
/// The two-byte document is exactly `MAX_TOKEN_SCOPE_BYTES` compact, far under
/// it in UTF-16 code units, and `scope::text` prints it past the cap. Written
/// as this spine writes it (methods sorted) and as the twin does (in the
/// caller's order), it resolves to its methods and lists as `N methods`; one
/// byte past the cap, stored directly, fails closed on both reads.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scope_at_the_byte_cap_reads_whichever_spine_wrote_it() {
    let pool = common::fresh_db_pool().await;
    let account_id = common::seed_account(&pool, "scope_cap_reader", None).await;
    let client = pool.get().await.expect("pool.get");

    let at_cap = methods_at_bytes(MAX_TOKEN_SCOPE_BYTES, &"\u{00E9}".repeat(40));
    let rust_json = TokenScopeDocument::methods(at_cap.iter().cloned().collect())
        .to_json()
        .expect("at the cap mints");
    let mut ts_order = at_cap.clone();
    ts_order.reverse();
    let ts_json = compact_methods_json(&ts_order);
    let over = methods_at_bytes(MAX_TOKEN_SCOPE_BYTES + 1, &"\u{00E9}".repeat(40));
    let over_json = compact_methods_json(&over);
    assert_eq!(rust_json.len(), MAX_TOKEN_SCOPE_BYTES);
    assert_eq!(ts_json.len(), MAX_TOKEN_SCOPE_BYTES);
    assert_eq!(over_json.len(), MAX_TOKEN_SCOPE_BYTES + 1);
    assert!(rust_json.encode_utf16().count() < MAX_TOKEN_SCOPE_BYTES);

    let rust_hash = store_scope_text(&client, &account_id, "rust", &rust_json).await;
    let ts_hash = store_scope_text(&client, &account_id, "ts", &ts_json).await;
    let over_hash = store_scope_text(&client, &account_id, "over", &over_json).await;

    let printed: i32 = client
        .query_one(
            "SELECT octet_length(scope::text) FROM api_token WHERE token_hash = $1",
            &[&ts_hash],
        )
        .await
        .expect("printed length")
        .get(0);
    assert!(
        usize::try_from(printed).unwrap() > MAX_TOKEN_SCOPE_BYTES,
        "scope::text prints the document past the cap ({printed} bytes)"
    );

    let expected = TokenScope::Methods(at_cap.iter().cloned().collect());
    for hash in [&rust_hash, &ts_hash] {
        let row = query_validate_api_token(&client, hash)
            .await
            .expect("validate query")
            .expect("a scope at the cap resolves");
        assert_eq!(row.scope, expected);
    }
    assert!(
        query_validate_api_token(&client, &over_hash)
            .await
            .expect("validate query")
            .is_none(),
        "a scope past the cap fails closed"
    );

    let labels: Vec<(String, String)> = query_api_token_list_for_account(&client, &account_id)
        .await
        .expect("list")
        .into_iter()
        .map(|row| (row.name, row.scope))
        .collect();
    let label_of = |name: &str| {
        labels
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, scope)| scope.as_str())
    };
    let methods_label = format!("{} methods", at_cap.len());
    assert_eq!(label_of("rust"), Some(methods_label.as_str()));
    assert_eq!(label_of("ts"), Some(methods_label.as_str()));
    assert_eq!(label_of("over"), Some("unreadable"));
}

/// **An ASCII scope under the cap whose printed text is past it reads** — the
/// document the read measured as Postgres printed it, and refused, before the
/// cap counted the compact JSON.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn a_scope_under_the_cap_reads_although_its_printed_text_is_past_it() {
    let pool = common::fresh_db_pool().await;
    let account_id = common::seed_account(&pool, "scope_spaced_reader", None).await;
    let client = pool.get().await.expect("pool.get");

    let methods = methods_at_bytes(MAX_TOKEN_SCOPE_BYTES - 50, "m");
    let json = compact_methods_json(&methods);
    let hash = store_scope_text(&client, &account_id, "spaced", &json).await;
    let printed: i32 = client
        .query_one(
            "SELECT octet_length(scope::text) FROM api_token WHERE token_hash = $1",
            &[&hash],
        )
        .await
        .expect("printed length")
        .get(0);
    assert!(usize::try_from(printed).unwrap() > MAX_TOKEN_SCOPE_BYTES);
    let row = query_validate_api_token(&client, &hash)
        .await
        .expect("validate query")
        .expect("a scope under the cap resolves");
    assert_eq!(
        row.scope,
        TokenScope::Methods(methods.into_iter().collect())
    );
}

/// **The mint refuses a scope one byte past the cap** with the scope reason,
/// though it is far under the cap in UTF-16 code units, and mints the one at
/// the cap.
#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_auth_test database"]
async fn mint_measures_the_scope_cap_in_utf8_bytes() {
    let pool = common::fresh_db_pool().await;
    let auth = seed_request_context(&pool, "scope_cap_minter").await;
    let filler = "\u{00E9}".repeat(40);
    let mint = |methods: Vec<String>| {
        json!({
            "name": "cap",
            "scope": {"kind": "methods", "methods": methods},
            "lifetime": {"kind": "eternal"},
        })
    };

    let minted = dispatch_token_create(
        &pool,
        &auth,
        &mint(methods_at_bytes(MAX_TOKEN_SCOPE_BYTES, &filler)),
    )
    .await
    .expect("a scope at the cap mints");
    assert!(minted.get("token").is_some());

    let err = dispatch_token_create(
        &pool,
        &auth,
        &mint(methods_at_bytes(MAX_TOKEN_SCOPE_BYTES + 1, &filler)),
    )
    .await
    .expect_err("a scope past the cap is refused");
    assert_eq!(err.code, fuz_http::JsonrpcErrorCode::InvalidParams);
    assert_eq!(
        err.data.as_ref().and_then(|d| d.get("reason")),
        Some(&json!(
            fuz_auth::account_action_specs::ERROR_TOKEN_SCOPE_INVALID
        ))
    );
}
