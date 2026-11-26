//! Integration test for the `/ready` route against a live database, a fresh
//! one per test (`fuz_testing::fresh_test_db`).

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fuz_http::{ReadyRouteState, ready_router};
use fuz_testing::{TestEngine, TestingDbOptions};
use http_body_util::BodyExt;
use tower::ServiceExt; // for `oneshot`

/// A bare database with the probe table the expected maps name.
const DB: TestingDbOptions<'static> = TestingDbOptions {
    suite: "fuz_http",
    migrations: &[],
    setup_sql: Some("CREATE TABLE ready_http_probe (id SERIAL PRIMARY KEY, name TEXT)"),
    engine: TestEngine::Any,
};

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
    // fires at router construction — so this needs no database.
    let pool = fuz_testing::unreachable_pool();
    let _ = ready_router(ReadyRouteState {
        pool,
        expected: Arc::new(BTreeMap::new()),
    });
}

#[tokio::test]
async fn ready_returns_200_on_match_and_503_on_drift() {
    let pool = DB.open().await;

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
}
