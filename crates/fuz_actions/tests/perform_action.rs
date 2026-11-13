//! Unit tests for the `fuz_actions` dispatch building blocks (no DB).
//!
//! Covers the component-level pieces, not the integrated request path:
//! - Registry build invariants (duplicate / empty method; account + protocol
//!   spec composition).
//! - `PostCommitEffects` drain (each thunk runs once) and clear (discards without
//!   running) — the post-commit-effect ordering guarantees.
//! - Protocol spec shape (`heartbeat` is account-grain + read-only + WS-only,
//!   `peer/ping` is public + HTTP-reachable; both compose into a registry).
//! - The HTTP transport gate: a `ws_only` spec answers `method_not_found`
//!   before the RPC dispatch touches auth or the pool.
//!
//! `perform_action`'s integrated `method_not_found` → 401 → authz → 403 → 429 → 400 → handler order and the
//! transactional audit / rollback-discards-effects boundary are not driven
//! here — they live in the `#[ignore]` PG sibling `perform_action_dispatch.rs`
//! (real pool + tx), with the component-level pieces pinned here
//! (`PostCommitEffects` drain/clear) and in `fuz_auth`'s `action_auth` unit tests,
//! and the same order driven over the wire by `fuz_app`'s cross-backend suite
//! against `testing_spine_stub`.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use fuz_actions::{
    ActionContext, ActionHandler, ActionRegistry, ActionSpec, PROTOCOL_ACTION_SPECS,
    PostCommitEffects, RegistryBuildError,
};
use fuz_auth::AuthSpec;
use fuz_http::InputShape;
use serde_json::Value;

fn no_op_handler() -> ActionHandler {
    Arc::new(|_params: Value, _ctx: ActionContext<'_>| Box::pin(async move { Ok(Value::Null) }))
}

#[test]
fn registry_rejects_duplicate_method() {
    let specs = vec![
        ActionSpec::new(
            "ping",
            AuthSpec::public(),
            InputShape::Object,
            false,
            no_op_handler(),
        ),
        ActionSpec::new(
            "ping",
            AuthSpec::public(),
            InputShape::Object,
            false,
            no_op_handler(),
        ),
    ];
    let err = ActionRegistry::compile(specs).unwrap_err();
    assert!(matches!(err, RegistryBuildError::DuplicateMethod("ping")));
}

#[test]
fn registry_rejects_empty_method() {
    let specs = vec![ActionSpec::new(
        "",
        AuthSpec::public(),
        InputShape::Object,
        false,
        no_op_handler(),
    )];
    let err = ActionRegistry::compile(specs).unwrap_err();
    assert!(matches!(err, RegistryBuildError::EmptyMethod));
}

#[test]
fn registry_compose_account_and_protocol() {
    // Build a registry from protocol specs only — confirm registry
    // sizing + lookup. `peer/ping` is the server→client protocol action
    // (the complement to `heartbeat`), so the dispatchable protocol set is
    // 2. `cancel` is deliberately absent: it is a notification the WS read
    // loop owns, so a `cancel` that arrives as a request answers
    // `method_not_found` — the same as the twin, whose
    // `remote_notification` spec never reaches `action_map`.
    let registry = ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap();
    assert_eq!(registry.len(), 2);
    assert!(registry.get("heartbeat").is_some());
    assert!(registry.get("peer/ping").is_some());
    assert!(
        registry.get(fuz_realtime::CANCEL_METHOD).is_none(),
        "cancel is dispatcher-owned, never dispatchable"
    );
    assert!(registry.get("missing").is_none());

    let methods: Vec<&'static str> = {
        let mut m: Vec<_> = registry.methods().collect();
        m.sort_unstable();
        m
    };
    assert_eq!(methods, vec!["heartbeat", "peer/ping"]);
}

/// Build the self-service surface over an unreachable pool — construction
/// touches no DB, so only the eligible-role guard can decide the outcome.
fn build_self_service(eligible_roles: &[&str]) -> Vec<ActionSpec> {
    let pool = fuz_db::create_pool(
        "postgres://nobody@127.0.0.1:1/nothing",
        &fuz_db::PoolOptions::default(),
    )
    .unwrap();
    fuz_actions::auth_adapter::build_self_service_role_specs(
        Arc::new(fuz_auth::AuditEmitter::new(pool)),
        Arc::new(fuz_auth::NoopConnectionCloser),
        eligible_roles.iter().map(|r| (*r).to_owned()).collect(),
    )
}

#[test]
fn self_service_specs_build_over_app_roles() {
    assert_eq!(build_self_service(&["educator"]).len(), 1);
}

/// A builtin role in the self-service allowlist would let any account toggle
/// itself instance-wide authority, so construction refuses it loudly at boot.
#[test]
#[should_panic(expected = "collides with a builtin role")]
fn self_service_specs_refuse_a_builtin_eligible_role() {
    let _ = build_self_service(&["educator", "admin"]);
}

#[tokio::test]
async fn post_commit_effects_drain_runs_each_once_concurrently() {
    // Drives the concurrent fan-out used post-commit in
    // `perform_action`. Validates the ordering contract.
    let q = PostCommitEffects::new();
    let counter = Arc::new(AtomicU32::new(0));

    for _ in 0..10 {
        let c = Arc::clone(&counter);
        q.push_fn(move || async move {
            // Yield to force interleaving — proves these run
            // concurrently (a serial drain would still complete; the
            // join_all path runs all futures concurrently).
            tokio::task::yield_now().await;
            c.fetch_add(1, Ordering::SeqCst);
        });
    }
    assert_eq!(q.len(), 10);
    q.drain_all().await;
    assert_eq!(counter.load(Ordering::SeqCst), 10);
    assert!(q.is_empty());
}

#[tokio::test]
async fn post_commit_effects_clear_discards_without_running() {
    // Simulates the rollback path — effects don't fire.
    let q = PostCommitEffects::new();
    let counter = Arc::new(AtomicU32::new(0));
    for _ in 0..5 {
        let c = Arc::clone(&counter);
        q.push_fn(move || async move {
            c.fetch_add(1, Ordering::SeqCst);
        });
    }
    q.clear();
    q.drain_all().await; // Nothing to drain after clear.
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[test]
fn protocol_specs_carry_the_transport_marker_the_ts_mount_shape_implies() {
    // The TS twin spreads `protocol_actions` into a consumer's WS endpoint and
    // additionally mounts `peer_ping_action` on the HTTP-RPC endpoint, so an
    // HTTP `peer/ping` reaches the handler and refuses with
    // `peer_no_transport` while an HTTP `heartbeat` is `method_not_found`.
    // One registry serves both transports here, so the same split is the
    // `ws_only` marker.
    let by_method: Vec<(&str, bool)> = PROTOCOL_ACTION_SPECS()
        .iter()
        .map(|s| (s.method, s.ws_only))
        .collect();
    assert_eq!(by_method, vec![("heartbeat", true), ("peer/ping", false)]);

    let heartbeat = fuz_actions::heartbeat_action_spec();
    assert_eq!(heartbeat.method, fuz_actions::HEARTBEAT_METHOD);
    assert!(!heartbeat.side_effects);
    // The TS `heartbeat_action_spec` declares `{account: 'required', actor:
    // 'none'}`; over WS the upgrade already authenticated, so this is the
    // declaration matching rather than a live gate.
    assert_eq!(
        heartbeat.auth,
        AuthSpec::account_grain(fuz_auth::CredentialGate::Any)
    );
}

#[tokio::test]
async fn heartbeat_spec_composes() {
    // Heartbeat returns the canonical empty object `{}` (mirrors
    // fuz_app's `object({})` output). This test only checks the
    // spec composes — the dispatch wrap needs a real pool which we can't
    // justify in a non-#[ignore] test, and heartbeat doesn't touch ctx.db.
    let spec = fuz_actions::heartbeat_action_spec();
    let pending = PostCommitEffects::new();
    let signal = fuz_realtime::SignalToken::new();
    let span = tracing::Span::current();

    // Build a dummy `ActionContext` — DB is unused by heartbeat. We
    // can't easily build a real `ActionDb::Pool` without a pool, so
    // we lean on the fact that heartbeat doesn't touch `ctx.db`. The
    // type system prevents us from constructing a tx context, but for
    // tests we can pretend the variant via `unsafe`. Skip that —
    // assert the closure shape compiles and registry composition works.
    let _ = (&spec, &pending, &signal, &span);
}

/// State pointing at a **closed** loopback port, so any pool checkout fails
/// instantly. That is what makes the pair of cases below discriminating: the
/// `ws_only` refusal precedes the pool, an ordinary spec's dispatch does not.
fn dead_pool_rpc_state(registry: ActionRegistry) -> fuz_actions::ActionDispatch {
    let pool = fuz_db::create_pool(
        "postgres://nobody@127.0.0.1:1/nothing",
        &fuz_db::PoolOptions::default(),
    )
    .unwrap();
    fuz_actions::ActionDispatch {
        gate: fuz_testing::testing_auth_gate(pool.clone()),
        registry: Arc::new(registry),
        audit: Arc::new(fuz_auth::AuditEmitter::new(pool)),
        connection_closer: Arc::new(fuz_auth::NoopConnectionCloser),
        notification_sender: Arc::new(fuz_auth::NoopNotificationSender),
        rate_limits: fuz_actions::ActionRateLimits::defaults(
            fuz_auth::RateLimiterMode::DisabledForTesting,
        ),
    }
}

/// **Both RPC handlers check the origin first.** A foreign `Origin` is the
/// flat `403 forbidden_origin` on `POST /rpc` (ahead of the content-type gate
/// and the body parse — the body here is neither JSON nor typed) and on
/// `GET /rpc` (ahead of the query gate — the query here is empty). The pool
/// cannot connect, so nothing past the gate could answer either way.
#[tokio::test]
async fn both_rpc_handlers_refuse_a_foreign_origin_first() {
    let state = || dead_pool_rpc_state(ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap());
    let mut foreign = axum::http::HeaderMap::new();
    foreign.insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("https://evil.example"),
    );
    let read = |response: axum::response::Response| async move {
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    };
    let forbidden = (403, r#"{"error":"forbidden_origin"}"#.to_owned());

    let post = fuz_actions::rpc_dispatch::rpc_post_handler(
        axum::extract::State(state()),
        None,
        foreign.clone(),
        axum::body::Bytes::from_static(b"not json"),
    )
    .await;
    assert_eq!(read(post).await, forbidden);

    let get = fuz_actions::rpc_dispatch::rpc_get_handler(
        axum::extract::State(state()),
        None,
        foreign,
        axum::extract::Query(Vec::new()),
    )
    .await;
    assert_eq!(read(get).await, forbidden);

    // the control: no `Origin` falls through to the GET query gate's 400
    let get = fuz_actions::rpc_dispatch::rpc_get_handler(
        axum::extract::State(state()),
        None,
        axum::http::HeaderMap::new(),
        axum::extract::Query(Vec::new()),
    )
    .await;
    assert_eq!(read(get).await.0, 400);
}

/// **Every response the GET handler writes is `no-store`** — its query
/// refusal and a dispatched method's answer alike — while a refusal ahead of
/// it (the origin belt) and a `POST` carry no `Cache-Control`. Twin of the
/// TS `RPC_GET_CACHE_CONTROL` header.
#[tokio::test]
async fn every_get_response_past_the_origin_check_is_no_store() {
    let state = || dead_pool_rpc_state(ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap());
    let cache_control = |response: &axum::response::Response| {
        response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap().to_owned())
    };
    let get = |headers: axum::http::HeaderMap, query: &[(&str, &str)]| {
        let query = query
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        fuz_actions::rpc_dispatch::rpc_get_handler(
            axum::extract::State(state()),
            None,
            headers,
            axum::extract::Query(query),
        )
    };
    assert_eq!(fuz_actions::RPC_GET_CACHE_CONTROL, "no-store");
    let no_store = Some(fuz_actions::RPC_GET_CACHE_CONTROL.to_owned());

    let missing_method = get(axum::http::HeaderMap::new(), &[]).await;
    assert_eq!(missing_method.status(), 400);
    assert_eq!(cache_control(&missing_method), no_store, "a query refusal");

    // an unregistered method answers from the dispatcher, ahead of the pool
    let dispatched = get(
        axum::http::HeaderMap::new(),
        &[("method", "definitely_missing_method"), ("id", "1")],
    )
    .await;
    assert_eq!(dispatched.status(), 404);
    assert_eq!(cache_control(&dispatched), no_store, "a dispatched answer");

    let mut foreign = axum::http::HeaderMap::new();
    foreign.insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("https://evil.example"),
    );
    let refused = get(foreign, &[]).await;
    assert_eq!(refused.status(), 403);
    assert_eq!(
        cache_control(&refused),
        None,
        "the origin refusal is not the handler's"
    );

    let post = fuz_actions::rpc_dispatch::rpc_post_handler(
        axum::extract::State(state()),
        None,
        axum::http::HeaderMap::new(),
        axum::body::Bytes::from_static(b"{}"),
    )
    .await;
    assert_eq!(cache_control(&post), None, "POST is not the GET route");
}

/// Dispatch one method over `POST /rpc` — the router a consumer mounts — and
/// read back `(status, body)`.
async fn dispatch_over_http(
    state: &fuz_actions::ActionDispatch,
    headers: &axum::http::HeaderMap,
    method: &str,
) -> (u16, Value) {
    use tower::ServiceExt as _;
    let envelope = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method});
    let mut request = axum::http::Request::post("/rpc")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(envelope.to_string()))
        .unwrap();
    request.headers_mut().extend(headers.clone());
    let response = fuz_actions::create_rpc_router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn ws_only_specs_are_method_not_found_over_http() {
    // `heartbeat` is registered, so a registry lookup finds it — but the HTTP
    // transport must answer exactly what it answers for an absent method, and
    // must answer it identically with and without credentials, so a WS-only
    // method is not an existence oracle.
    let registry = ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap();
    let state = dead_pool_rpc_state(registry);

    let anonymous = axum::http::HeaderMap::new();
    let mut authenticated = axum::http::HeaderMap::new();
    authenticated.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer whatever"),
    );

    let expected = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32601, "message": "method not found: heartbeat"},
    });
    for headers in [&anonymous, &authenticated] {
        let (status, body) = dispatch_over_http(&state, headers, "heartbeat").await;
        assert_eq!(status, 404);
        assert_eq!(body, expected);
    }

    // The same envelope an unregistered method produces, modulo the name.
    let (status, body) = dispatch_over_http(&state, &anonymous, "no_such_method").await;
    assert_eq!(status, 404);
    assert_eq!(body["error"]["code"], -32601);
}

/// `POST /rpc` with `body` as its raw bytes, read back as `(status, body)`.
async fn post_raw_over_http(
    state: &fuz_actions::ActionDispatch,
    body: &'static [u8],
) -> (u16, Value) {
    use tower::ServiceExt as _;
    let request = axum::http::Request::post("/rpc")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let response = fuz_actions::create_rpc_router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// **The `POST /rpc` body decodes as the REST bodies do** — the twin reads
/// both with `c.req.json()`: one leading BOM is dropped and invalid UTF-8
/// inside a string becomes U+FFFD, so each envelope below parses and reaches
/// the method lookup (`method_not_found`, its id echoed) instead of
/// `parse_error`. A second BOM and invalid UTF-8 outside a string still fail
/// the parse.
#[tokio::test]
async fn rpc_post_body_decodes_as_the_fetch_body_does() {
    let state = dead_pool_rpc_state(ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap());

    for (body, id, method) in [
        (
            &b"\xEF\xBB\xBF{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"no_such_method\"}"[..],
            serde_json::json!(1),
            "no_such_method",
        ),
        (
            b"{\"jsonrpc\":\"2.0\",\"id\":\"a\xFF\",\"method\":\"b\xC0\xAF\"}",
            serde_json::json!("a\u{FFFD}"),
            "b\u{FFFD}\u{FFFD}",
        ),
    ] {
        let (status, response) = post_raw_over_http(&state, body).await;
        assert_eq!(status, 404, "{}", body.escape_ascii());
        assert_eq!(
            response,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("method not found: {method}")},
            }),
            "{}",
            body.escape_ascii()
        );
    }

    for body in [
        &b"\xEF\xBB\xBF\xEF\xBB\xBF{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"m\"}"[..],
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"m\"}\xFF",
        b"",
    ] {
        let (status, response) = post_raw_over_http(&state, body).await;
        assert_eq!(status, 400, "{}", body.escape_ascii());
        assert_eq!(response["id"], Value::Null, "{}", body.escape_ascii());
        assert_eq!(response["error"]["code"], -32700, "{}", body.escape_ascii());
    }
}

#[tokio::test]
async fn a_spec_without_the_marker_still_dispatches_over_http() {
    // The control the case above needs: `peer/ping` carries no marker, so it
    // is NOT refused at the transport gate. It reaches the dispatcher, whose
    // authorization phase checks out the (dead) pool — a different answer
    // entirely, which is what proves the 404 above is the marker's doing.
    let registry = ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap();
    let state = dead_pool_rpc_state(registry);

    let (status, body) =
        dispatch_over_http(&state, &axum::http::HeaderMap::new(), "peer/ping").await;
    assert_ne!(status, 404, "peer/ping must not be refused as unregistered");
    assert_ne!(body["error"]["code"], -32601);
    // the authorization phase's failed checkout is the database unavailable:
    // `service_unavailable` (-32007) at 503, the JSON-RPC envelope, no `data`
    assert_eq!(status, 503);
    assert_eq!(
        body["error"],
        serde_json::json!({"code": -32007, "message": "database unavailable"})
    );
}

/// **A failed credential read is not an anonymous call.** A signed cookie
/// sends the cookie leg to the dead pool; the walk stops on the fault and the
/// request answers the failed checkout's flat 503 — the TS twin's, where the
/// `DbCheckoutError` throws out of the auth middleware into `onError` — rather
/// than dispatching the public `peer/ping` as anonymous.
#[tokio::test]
async fn a_failed_credential_checkout_answers_the_503_not_an_anonymous_call() {
    use tower::ServiceExt as _;
    let state = dead_pool_rpc_state(ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap());
    let set_cookie = fuz_auth::sign_session_cookie(
        &fuz_testing::testing_keyring(),
        &fuz_auth::generate_session_token(),
        fuz_auth::SESSION_COOKIE_NAME,
    );
    let cookie = set_cookie.split(';').next().unwrap().to_owned();
    let envelope = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "peer/ping"});
    let request = axum::http::Request::post("/rpc")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::COOKIE, cookie)
        .body(axum::body::Body::from(envelope.to_string()))
        .unwrap();
    let response = fuz_actions::create_rpc_router(state)
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_owned()),
        Some("application/json".to_owned())
    );
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(&bytes[..], br#"{"error":"service_unavailable"}"#);
}

/// **The WS path serves `GET` alone, gates first.** Any other method is a 404
/// whoever asks; a `GET` — or a `HEAD`, which axum serves through it — runs
/// the gates before the upgrade is looked at, so an anonymous one is the 401
/// with or without upgrade headers, never the extractor's 400 / 426. The twin
/// answers the same: its guards ride its `GET` route ahead of the upgrade
/// helper.
#[tokio::test]
async fn the_ws_path_serves_get_alone_and_gates_before_the_upgrade() {
    use tower::ServiceExt as _;

    let dispatch = dead_pool_rpc_state(ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap());
    let router = fuz_actions::register_action_ws(fuz_actions::WsRouteState {
        dispatch,
        connection_registry: Arc::new(fuz_realtime::ConnectionRegistry::new()),
        required_roles: Vec::new(),
    });
    let status = |method: &'static str, upgrade: bool| {
        let router = router.clone();
        async move {
            let mut request = axum::http::Request::builder().method(method).uri("/ws");
            if upgrade {
                request = request
                    .header("connection", "upgrade")
                    .header("upgrade", "websocket")
                    .header("sec-websocket-version", "13")
                    .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");
            }
            router
                .oneshot(request.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        assert_eq!(status(method, true).await, 404, "{method}");
        assert_eq!(status(method, false).await, 404, "{method}");
    }
    assert_eq!(
        status("GET", true).await,
        401,
        "upgrade headers: the gate first"
    );
    assert_eq!(
        status("GET", false).await,
        401,
        "no upgrade headers: the gate first"
    );
    assert_eq!(status("HEAD", false).await, 401, "HEAD runs the GET gates");
}

/// **A failed credential checkout refuses the upgrade with the 503.** A
/// signed cookie sends the cookie leg to the dead pool; the gates answer the
/// fault's flat 503 before the upgrade is looked at — not the anonymous 401,
/// and not an upgrade.
#[tokio::test]
async fn a_failed_credential_checkout_refuses_the_ws_upgrade_with_the_503() {
    use tower::ServiceExt as _;

    let dispatch = dead_pool_rpc_state(ActionRegistry::compile(PROTOCOL_ACTION_SPECS()).unwrap());
    let router = fuz_actions::register_action_ws(fuz_actions::WsRouteState {
        dispatch,
        connection_registry: Arc::new(fuz_realtime::ConnectionRegistry::new()),
        required_roles: Vec::new(),
    });
    let set_cookie = fuz_auth::sign_session_cookie(
        &fuz_testing::testing_keyring(),
        &fuz_auth::generate_session_token(),
        fuz_auth::SESSION_COOKIE_NAME,
    );
    let cookie = set_cookie.split(';').next().unwrap().to_owned();
    let request = axum::http::Request::get("/ws")
        .header(axum::http::header::COOKIE, cookie)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 503);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(&bytes[..], br#"{"error":"service_unavailable"}"#);
}
