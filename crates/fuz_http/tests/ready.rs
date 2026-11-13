//! Integration test for the `/ready` route against a real `PostgreSQL`.
//!
//! `#[ignore]` so `cargo test --workspace` stays green without postgres; run
//! with:
//!
//! ```bash
//! createdb fuz_db_test
//! cargo test -p fuz_http -- --ignored
//! ```
//!
//! Override the connection URL with `FUZ_DB_TEST_URL`.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fuz_db::create_pool;
use fuz_http::{ReadyRouteState, ready_router};
use http_body_util::BodyExt;
use tower::ServiceExt; // for `oneshot`

fn test_database_url() -> String {
    env::var("FUZ_DB_TEST_URL").unwrap_or_else(|_| "postgres://localhost/fuz_db_test".to_owned())
}

async fn get_ready(state: ReadyRouteState) -> (StatusCode, serde_json::Value) {
    let response = ready_router(state)
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, body)
}

fn expected(cols: &[&str]) -> Arc<BTreeMap<String, Vec<String>>> {
    let mut map = BTreeMap::new();
    map.insert(
        "ready_http_probe".to_owned(),
        cols.iter().map(|c| (*c).to_owned()).collect(),
    );
    Arc::new(map)
}

#[test]
#[should_panic(expected = "empty")]
fn ready_router_rejects_empty_expected() {
    // Boot-time fail-loud (twin of the TS factory throw): an empty expected map
    // would answer 200 for any live DB. The pool is never used — the assert
    // fires at router construction — so this needs no PostgreSQL and is not
    // `#[ignore]`d.
    let pool = create_pool(&test_database_url(), &fuz_db::PoolOptions::default()).unwrap();
    let _ = ready_router(ReadyRouteState {
        pool,
        expected: Arc::new(BTreeMap::new()),
    });
}

#[tokio::test]
#[ignore = "requires PostgreSQL with fuz_db_test database"]
async fn ready_returns_200_on_match_and_503_on_drift() {
    let pool = create_pool(&test_database_url(), &fuz_db::PoolOptions::default()).unwrap();
    let client = pool.get().await.unwrap();
    client
        .batch_execute(
            "DROP TABLE IF EXISTS ready_http_probe CASCADE; \
             CREATE TABLE ready_http_probe (id SERIAL PRIMARY KEY, name TEXT)",
        )
        .await
        .unwrap();
    drop(client);

    // Live schema covers the expected columns → 200 {ready: true}.
    let (status, body) = get_ready(ReadyRouteState {
        pool: pool.clone(),
        expected: expected(&["id", "name"]),
    })
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({ "ready": true }));

    // An expected column the live DB lacks → 503 schema_drift (minimal body —
    // detailed drift is logged server-side only).
    let (status, body) = get_ready(ReadyRouteState {
        pool: pool.clone(),
        expected: expected(&["id", "absent_col"]),
    })
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, serde_json::json!({ "error": "schema_drift" }));

    let client = pool.get().await.unwrap();
    client
        .batch_execute("DROP TABLE IF EXISTS ready_http_probe CASCADE")
        .await
        .unwrap();
}
