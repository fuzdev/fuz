//! PG-backed tests of a request dropped during its commit: once the commit
//! has started, dropping the request — a WebSocket loop ending with its
//! socket, an HTTP client going away, the shutdown's close-all — must not
//! separate the committed transaction from what follows it (post-commit
//! effects, a revocation's connection close). The request finishes on the
//! server's write tracker instead, so that work runs and the shutdown drain
//! waits for it. A request dropped before its commit rolls back.
//!
//! The commit is held open by deferred constraint triggers that sleep at
//! `COMMIT`, so a case can drop the request while the commit's round trip is
//! in flight — it waits for that `COMMIT` to show in `pg_stat_activity`.
//!
//! The slow commit is a deferred plpgsql trigger, so the suite runs on
//! PostgreSQL alone.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fuz_actions::{ActionHandler, ActionRegistry, ActionSpec, WsRouteState, register_action_ws};
use fuz_auth::{
    AUTH_MIGRATIONS, AccountRouteState, AuditEmitter, AuthSpec, ConnectionCloseTarget,
    ConnectionCloser, NoopConnectionCloser, SESSION_COOKIE_NAME,
};
use fuz_db::{ActionDb, Pool};
use fuz_http::{BackgroundWrites, CancellationToken, InputShape, ServeShutdown};
use fuz_realtime::ConnectionRegistry;
use fuz_testing::{
    RecordingConnectionCloser, TestEngine, TestingDbOptions, mint_session_cookie,
    seed_account_actor, testing_keyring,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Every insert into `slow_commit` or `audit_log` makes its transaction's
/// `COMMIT` sleep: the deferred constraint triggers fire at commit, so the
/// commit's round trip is held open for the sleep.
const SLOW_COMMIT_SQL: &str = "
CREATE TABLE slow_commit (id serial PRIMARY KEY);
CREATE FUNCTION slow_commit_sleep() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_sleep(1);
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER slow_commit_at_commit
  AFTER INSERT ON slow_commit
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION slow_commit_sleep();
CREATE CONSTRAINT TRIGGER audit_log_slow_commit
  AFTER INSERT ON audit_log
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION slow_commit_sleep();
";

const DB: TestingDbOptions<'static> = TestingDbOptions {
    suite: "fuz_actions",
    migrations: &[AUTH_MIGRATIONS],
    setup_sql: Some(SLOW_COMMIT_SQL),
    engine: TestEngine::Postgres,
};

/// Bound on every wait a broken case could otherwise turn into a hang.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// What a case watches: the handler reaching its end and the post-commit
/// effect running.
#[derive(Default)]
struct Probe {
    handled: Notify,
    effect_ran: AtomicBool,
}

/// Two actions over one handler, which inserts a row (so its commit sleeps),
/// queues a post-commit effect that records it ran, and announces it has
/// reached its end: `slow_commit` then returns, and `held_in_handler` waits
/// there forever, so its dispatch is only ever dropped in its handler.
fn registry(probe: &Arc<Probe>) -> ActionRegistry {
    let handler = |hold: bool| -> ActionHandler {
        let probe = Arc::clone(probe);
        Arc::new(move |_params, ctx| {
            let probe = Arc::clone(&probe);
            Box::pin(async move {
                let ActionDb::Tx(tx) = &ctx.db else {
                    return Err(fuz_http::internal_error("expects an in-tx client"));
                };
                tx.execute("INSERT INTO slow_commit DEFAULT VALUES", &[])
                    .await
                    .map_err(|e| fuz_http::internal_error_with_source("insert", &e))?;
                let effect_probe = Arc::clone(&probe);
                ctx.post_commit_effects.push_fn(move || async move {
                    effect_probe.effect_ran.store(true, Ordering::SeqCst);
                });
                probe.handled.notify_one();
                if hold {
                    std::future::pending::<()>().await;
                }
                Ok(json!({"ok": true}))
            })
        })
    };
    ActionRegistry::compile(vec![
        ActionSpec::with_side_effects(
            "slow_commit",
            AuthSpec::public(),
            InputShape::Object,
            handler(false),
        ),
        ActionSpec::with_side_effects(
            "held_in_handler",
            AuthSpec::public(),
            InputShape::Object,
            handler(true),
        ),
    ])
    .unwrap()
}

/// The dispatch a case serves through, every tracked write — the gate's, the
/// audit emitter's — on `writes`.
fn action_dispatch(
    pool: &Pool,
    probe: &Arc<Probe>,
    writes: &Arc<BackgroundWrites>,
    connections: &Arc<ConnectionRegistry>,
) -> fuz_actions::ActionDispatch {
    let notification_sender: Arc<dyn fuz_auth::NotificationSender> =
        Arc::<ConnectionRegistry>::clone(connections);
    fuz_actions::ActionDispatch {
        gate: gate(pool, writes),
        registry: Arc::new(registry(probe)),
        audit: Arc::new(AuditEmitter::new(pool.clone(), Arc::clone(writes))),
        connection_closer: Arc::new(NoopConnectionCloser),
        notification_sender,
        rate_limits: fuz_actions::ActionRateLimits::defaults(
            fuz_auth::RateLimiterMode::DisabledForTesting,
        ),
    }
}

fn gate(pool: &Pool, writes: &Arc<BackgroundWrites>) -> fuz_auth::AuthGate {
    fuz_auth::AuthGate {
        background_writes: Arc::clone(writes),
        ..fuz_testing::testing_auth_gate(pool.clone())
    }
}

/// Serve `groups` under `serve_with_shutdown`, the router carrying `closer`
/// and `writes` as its duties; returns the address and the serve's task.
async fn serve(
    pool: &Pool,
    groups: Vec<fuz_http::RouteGroup>,
    closer: Arc<dyn fuz_http::ShutdownCloser>,
    writes: &Arc<BackgroundWrites>,
    shutdown: &CancellationToken,
) -> (
    SocketAddr,
    JoinHandle<Result<ServeShutdown, std::io::Error>>,
) {
    let stack_options = fuz_http::StackOptions {
        serve_duties: Some(fuz_http::ServeDuties::new(closer, Arc::clone(writes))),
        ..fuz_http::StackOptions::without_backend(
            gate(pool, writes).allowed_origins,
            Arc::new(Vec::new()),
        )
    };
    let cap = fuz_http::BodyCap::Bytes(fuz_http::DEFAULT_BODY_LIMIT_BYTES);
    let router = fuz_http::compose_stack(
        groups,
        fuz_http::RouteGroup::new("fallback", axum::Router::new(), cap),
        &stack_options,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = tokio::spawn(fuz_http::serve_with_shutdown(
        listener,
        router,
        shutdown.clone(),
        Vec::new(),
        STEP_TIMEOUT,
    ));
    (addr, served)
}

const fn group(name: &'static str, router: axum::Router) -> fuz_http::RouteGroup {
    fuz_http::RouteGroup::new(
        name,
        router,
        fuz_http::BodyCap::Bytes(fuz_http::DEFAULT_BODY_LIMIT_BYTES),
    )
}

/// The RPC route over `dispatch`, at `/api/rpc`.
fn rpc_group(dispatch: fuz_actions::ActionDispatch) -> fuz_http::RouteGroup {
    group(
        "api",
        axum::Router::new().nest("/api", fuz_actions::create_rpc_router(dispatch)),
    )
}

/// Wait until a `COMMIT` is under way on the database — the deferred
/// trigger holding it open.
async fn until_committing(pool: &Pool) {
    tokio::time::timeout(STEP_TIMEOUT, async {
        loop {
            let committing: i64 = pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity \
                     WHERE datname = current_database() AND state = 'active' \
                     AND query = 'COMMIT'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if committing > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a commit starts");
}

/// The dropped request was handed to the tracker — counted in flight while
/// its `COMMIT` still sleeps — rather than finishing on its own: what makes
/// a past-commit case tell the hand-off from a request that simply ran on.
async fn assert_handed_off(writes: &Arc<BackgroundWrites>) {
    until("the request was handed to the tracker", || {
        writes.inflight_count() >= 1
    })
    .await;
}

/// Wait until `check` holds.
async fn until(what: &str, check: impl Fn() -> bool + Send + Sync) {
    let reached = tokio::time::timeout(STEP_TIMEOUT, async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(reached.is_ok(), "{what}");
}

async fn slow_commit_rows(pool: &Pool) -> i64 {
    pool.get()
        .await
        .unwrap()
        .query_one("SELECT count(*) FROM slow_commit", &[])
        .await
        .unwrap()
        .get(0)
}

/// The dispatch's effect runs, its row is committed, and the tracker drains.
/// The drop reaches the server after the client lets go, so the effect is
/// waited for rather than read at once.
async fn assert_finished(pool: &Pool, probe: &Probe, writes: &BackgroundWrites) {
    until("the committed dispatch's post-commit effect ran", || {
        probe.effect_ran.load(Ordering::SeqCst)
    })
    .await;
    tokio::time::timeout(STEP_TIMEOUT, writes.drain())
        .await
        .expect("the tracker drains");
    assert_eq!(slow_commit_rows(pool).await, 1, "the dispatch committed");
}

/// The dispatch dropped in its handler rolled back: its transaction ended, no
/// row, no effect, nothing left on the tracker.
async fn assert_rolled_back(pool: &Pool, probe: &Probe, writes: &BackgroundWrites) {
    tokio::time::timeout(STEP_TIMEOUT, async {
        loop {
            let open: i64 = pool
                .get()
                .await
                .unwrap()
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity \
                     WHERE datname = current_database() \
                     AND state LIKE 'idle in transaction%'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            if open == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the dropped transaction ended");
    tokio::time::timeout(STEP_TIMEOUT, writes.drain())
        .await
        .expect("nothing was handed to the tracker");
    assert!(!probe.effect_ran.load(Ordering::SeqCst), "no effect ran");
    assert_eq!(slow_commit_rows(pool).await, 0, "the dispatch rolled back");
}

/// Serve the WS endpoint on a plain `axum::serve` — the WS loop owns the
/// dispatch's drop — and open a socket on it.
async fn ws_socket(pool: &Pool, probe: &Arc<Probe>, writes: &Arc<BackgroundWrites>) -> TcpStream {
    let connections = Arc::new(ConnectionRegistry::new());
    let state = WsRouteState {
        dispatch: action_dispatch(pool, probe, writes, &connections),
        connection_registry: Arc::clone(&connections),
        required_roles: Vec::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = register_action_ws(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    open_socket(pool, addr).await
}

async fn send_ws_request(stream: &mut TcpStream, method: &str) {
    write_text_frame(
        stream,
        &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).to_string(),
    )
    .await;
}

/// Send `POST /api/rpc` calling `method`, returning the open connection.
async fn send_rpc_request(addr: SocketAddr, method: &str) -> TcpStream {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).to_string();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST /api/rpc HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream
}

/// A WebSocket closed by its client while a dispatch's commit is in flight:
/// the loop ends and lets go of its in-flight dispatches, and the one past
/// its commit finishes on the tracker — its effects run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "postgres-only: a plpgsql trigger"]
async fn a_ws_dispatch_dropped_mid_commit_still_runs_its_effects() {
    let pool = DB.open().await;
    let probe = Arc::new(Probe::default());
    let writes = Arc::new(BackgroundWrites::default());
    let mut stream = ws_socket(&pool, &probe, &writes).await;
    send_ws_request(&mut stream, "slow_commit").await;
    until_committing(&pool).await;
    // the client goes away mid-commit: the loop's read fails and it exits
    drop(stream);
    assert_handed_off(&writes).await;

    assert_finished(&pool, &probe, &writes).await;
}

/// A WebSocket closed by its client while a dispatch is still in its
/// handler: the dispatch is dropped with the loop and rolls back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "postgres-only: a plpgsql trigger"]
async fn a_ws_dispatch_dropped_in_its_handler_rolls_back() {
    let pool = DB.open().await;
    let probe = Arc::new(Probe::default());
    let writes = Arc::new(BackgroundWrites::default());
    let mut stream = ws_socket(&pool, &probe, &writes).await;
    send_ws_request(&mut stream, "held_in_handler").await;
    tokio::time::timeout(STEP_TIMEOUT, probe.handled.notified())
        .await
        .expect("the handler runs");
    drop(stream);

    assert_rolled_back(&pool, &probe, &writes).await;
}

/// The shutdown's close-all ends a socket's loop while a dispatch's commit is
/// in flight: the dispatch finishes on the tracker, and the shutdown's write
/// drain waits for it — nothing given up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "postgres-only: a plpgsql trigger"]
async fn the_shutdown_waits_for_a_ws_dispatch_past_its_commit() {
    let pool = DB.open().await;
    let probe = Arc::new(Probe::default());
    let writes = Arc::new(BackgroundWrites::default());
    let connections = Arc::new(ConnectionRegistry::new());
    let state = WsRouteState {
        dispatch: action_dispatch(&pool, &probe, &writes, &connections),
        connection_registry: Arc::clone(&connections),
        required_roles: Vec::new(),
    };
    let shutdown = CancellationToken::new();
    let closer: Arc<dyn fuz_http::ShutdownCloser> = Arc::<ConnectionRegistry>::clone(&connections);
    let (addr, served) = serve(
        &pool,
        vec![group("ws", register_action_ws(state))],
        closer,
        &writes,
        &shutdown,
    )
    .await;
    let mut stream = open_socket(&pool, addr).await;
    send_ws_request(&mut stream, "slow_commit").await;
    until_committing(&pool).await;
    shutdown.cancel();
    assert_handed_off(&writes).await;

    let given_up = tokio::time::timeout(STEP_TIMEOUT * 2, served)
        .await
        .expect("the shutdown ends")
        .unwrap()
        .unwrap();
    assert_eq!(given_up, ServeShutdown::default(), "nothing given up");
    assert!(
        probe.effect_ran.load(Ordering::SeqCst),
        "the shutdown returned after the dispatch's effect ran"
    );
    assert_eq!(slow_commit_rows(&pool).await, 1, "the dispatch committed");
}

/// An HTTP client gone while its RPC dispatch's commit is in flight: the
/// request is dropped with its connection, and the dispatch past its commit
/// finishes on the router's tracker — its effects run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "postgres-only: a plpgsql trigger"]
async fn an_rpc_dispatch_dropped_mid_commit_still_runs_its_effects() {
    let pool = DB.open().await;
    let probe = Arc::new(Probe::default());
    let writes = Arc::new(BackgroundWrites::default());
    let connections = Arc::new(ConnectionRegistry::new());
    let dispatch = action_dispatch(&pool, &probe, &writes, &connections);
    let (addr, _served) = serve(
        &pool,
        vec![rpc_group(dispatch)],
        Arc::new(NoopConnectionCloser),
        &writes,
        &CancellationToken::new(),
    )
    .await;
    let stream = send_rpc_request(addr, "slow_commit").await;
    until_committing(&pool).await;
    // the client goes away mid-commit: hyper drops the request with its
    // connection
    drop(stream);
    assert_handed_off(&writes).await;

    assert_finished(&pool, &probe, &writes).await;
}

/// An HTTP client gone while its RPC dispatch is still in its handler: the
/// request is dropped and rolls back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "postgres-only: a plpgsql trigger"]
async fn an_rpc_dispatch_dropped_in_its_handler_rolls_back() {
    let pool = DB.open().await;
    let probe = Arc::new(Probe::default());
    let writes = Arc::new(BackgroundWrites::default());
    let connections = Arc::new(ConnectionRegistry::new());
    let dispatch = action_dispatch(&pool, &probe, &writes, &connections);
    let (addr, _served) = serve(
        &pool,
        vec![rpc_group(dispatch)],
        Arc::new(NoopConnectionCloser),
        &writes,
        &CancellationToken::new(),
    )
    .await;
    let stream = send_rpc_request(addr, "held_in_handler").await;
    tokio::time::timeout(STEP_TIMEOUT, probe.handled.notified())
        .await
        .expect("the handler runs");
    drop(stream);

    assert_rolled_back(&pool, &probe, &writes).await;
}

/// A layer that drains the tracker after the request answers — what
/// `testing_spine_stub`'s `await_background_writes_layer` does.
async fn drain_after(
    axum::extract::State(writes): axum::extract::State<Arc<BackgroundWrites>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let response = next.run(request).await;
    writes.drain().await;
    response
}

/// A request dropped past its commit hands its whole rest to the tracker,
/// a layer that drains after it included: that drain runs inside a tracked
/// write and returns at once, or it would wait on itself and the tracker
/// would never empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "postgres-only: a plpgsql trigger"]
async fn a_drain_inside_a_handed_off_request_does_not_wait_on_itself() {
    let pool = DB.open().await;
    let probe = Arc::new(Probe::default());
    let writes = Arc::new(BackgroundWrites::default());
    let connections = Arc::new(ConnectionRegistry::new());
    let dispatch = action_dispatch(&pool, &probe, &writes, &connections);
    let draining = axum::Router::new()
        .nest("/api", fuz_actions::create_rpc_router(dispatch))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&writes),
            drain_after,
        ));
    let (addr, _served) = serve(
        &pool,
        vec![group("api", draining)],
        Arc::new(NoopConnectionCloser),
        &writes,
        &CancellationToken::new(),
    )
    .await;
    let stream = send_rpc_request(addr, "slow_commit").await;
    until_committing(&pool).await;
    drop(stream);
    assert_handed_off(&writes).await;

    assert_finished(&pool, &probe, &writes).await;
}

/// `POST /logout` dropped by its client while its commit is in flight: the
/// request finishes on the tracker, so the ended session's connections are
/// still closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "postgres-only: a plpgsql trigger"]
async fn a_logout_dropped_mid_commit_still_closes_the_session() {
    let pool = DB.open().await;
    let writes = Arc::new(BackgroundWrites::default());
    let closer = Arc::new(RecordingConnectionCloser::default());
    let connection_closer: Arc<dyn ConnectionCloser> =
        Arc::<RecordingConnectionCloser>::clone(&closer);
    let state = AccountRouteState {
        gate: gate(&pool, &writes),
        password_hasher: Arc::new(fuz_auth::Argon2idHasher::new()),
        audit: Arc::new(AuditEmitter::new(pool.clone(), Arc::clone(&writes))),
        connection_closer,
        bootstrap_available: Arc::new(AtomicBool::new(false)),
        login_ip_rate_limiter: None,
        login_account_rate_limiter: None,
        login_fail_floor_ms: fuz_auth::DEFAULT_LOGIN_FAIL_FLOOR_MS,
        login_fail_jitter_ms: fuz_auth::DEFAULT_LOGIN_FAIL_JITTER_MS,
    };
    let account = axum::Router::new().nest("/api/account", fuz_auth::account_router(state));
    let (addr, _served) = serve(
        &pool,
        vec![group("account", account)],
        Arc::new(NoopConnectionCloser),
        &writes,
        &CancellationToken::new(),
    )
    .await;
    let (account_id, _actor_id) = seed_account_actor(&pool, "logout_mid_commit").await;
    let cookie =
        mint_session_cookie(&pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST /api/account/logout HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/json\r\nContent-Length: 2\r\nCookie: {cookie}\r\n\r\n{{}}"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    until_committing(&pool).await;
    drop(stream);
    assert_handed_off(&writes).await;

    until("the logout closed its session's connections", || {
        closer
            .closed()
            .iter()
            .any(|target| matches!(target, ConnectionCloseTarget::Session(_)))
    })
    .await;
    tokio::time::timeout(STEP_TIMEOUT, writes.drain())
        .await
        .expect("the tracker drains");
}

/// Open an upgraded socket on `/ws` under a fresh session.
async fn open_socket(pool: &Pool, addr: SocketAddr) -> TcpStream {
    let (account_id, _actor_id) = seed_account_actor(pool, "past_commit").await;
    let cookie =
        mint_session_cookie(pool, &testing_keyring(), account_id, SESSION_COOKIE_NAME).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
         Cookie: {cookie}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    stream
}

/// Write one masked text frame (an all-zero mask leaves the payload as it
/// is); the payloads here are short.
async fn write_text_frame(stream: &mut TcpStream, text: &str) {
    let mut frame = vec![0x81, 0x80 | u8::try_from(text.len()).unwrap()];
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(text.as_bytes());
    stream.write_all(&frame).await.unwrap();
}
