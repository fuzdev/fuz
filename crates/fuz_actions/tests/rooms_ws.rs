//! PG-backed tests of the room verbs through the real WebSocket endpoint:
//! sessions upgrade over loopback TCP, and every frame runs the dispatcher —
//! the actor resolution the specs require reads the database, which is why
//! the suite needs one. The registry's own rules are its unit tests'
//! (`fuz_realtime`'s `room_registry`); these pin the wire: the answers, the
//! notifications each socket hears, the refusals' envelopes, a disconnect's
//! release, a client `cancel`, a leave, and a socket's close reaching a join
//! held in its authorizer, an authorizer reading revoked authority live,
//! eviction, and both limiters.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fuz_actions::room::{
    RoomAccess, RoomAuthorize, RoomAuthorizeInput, RoomRateLimitOptions, RoomRateLimiter,
    RoomSpecSetOptions, RoomVerdict, build_room_spec_set,
};
use fuz_actions::{ActionRegistry, WsRouteState, register_action_ws};
use fuz_auth::actor_queries::{query_active_actor_holds_any_global_role, query_create_role_grant};
use fuz_auth::{
    AUTH_MIGRATIONS, AuditEmitter, NoopConnectionCloser, RateLimiterMode, RateLimiterOptions,
    SESSION_COOKIE_NAME,
};
use fuz_db::Pool;
use fuz_realtime::{
    ConnectionRegistry, RoomEvictReason, RoomEvictTarget, RoomId, RoomRegistry,
    RoomRegistryOptions, RoomScope,
};
use fuz_testing::{
    TestEngine, TestingDbOptions, mint_session_cookie, seed_account_actor, testing_keyring,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use uuid::Uuid;

const DB: TestingDbOptions<'static> = TestingDbOptions {
    suite: "fuz_actions",
    migrations: &[AUTH_MIGRATIONS],
    setup_sql: None,
    engine: TestEngine::Any,
};

/// Bound on every wait a broken case could otherwise turn into a hang.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// The suite's authorizer, by the room id's prefix:
///
/// - `ok:<scope>:<rest>` — allowed under `<scope>`;
/// - `gate:<rest>` — a join is allowed once the case releases it, after
///   announcing it has been reached; a watch is allowed at once;
/// - `live:<rest>` — gated the same, then allowed only if the actor holds
///   the global `admin` role **as the database says once released** — a
///   live read inside the reserve window;
/// - anything else — denied.
#[derive(Default)]
struct SuiteAuthorize {
    reached: Notify,
    release: Notify,
    /// Signalled when a held gate is dropped before its release — the request
    /// future cancelled mid-authorizer.
    dropped: Notify,
}

impl SuiteAuthorize {
    async fn gate(&self) {
        self.reached.notify_one();
        let mut held = HeldGate(Some(&self.dropped));
        self.release.notified().await;
        held.0 = None;
    }
}

/// Signals its `Notify` when dropped while still armed: a gate whose future
/// was dropped before the release reached it.
struct HeldGate<'a>(Option<&'a Notify>);

impl Drop for HeldGate<'_> {
    fn drop(&mut self) {
        if let Some(dropped) = self.0 {
            dropped.notify_one();
        }
    }
}

const ALLOW: RoomVerdict = RoomVerdict::Allow {
    scope: None,
    max_members: None,
};

impl RoomAuthorize for SuiteAuthorize {
    fn authorize<'a>(
        &'a self,
        input: &'a RoomAuthorizeInput<'a>,
        db: &'a fuz_db::ActionDb<'a>,
    ) -> futures::future::BoxFuture<'a, Result<RoomVerdict, fuz_http::JsonrpcError>> {
        Box::pin(async move {
            let id = input.room_id.as_str();
            if let Some(rest) = id.strip_prefix("ok:") {
                let scope = rest.split(':').next().unwrap_or_default();
                return Ok(RoomVerdict::Allow {
                    scope: Some(RoomScope::new(scope)),
                    max_members: None,
                });
            }
            if id.starts_with("gate:") {
                if input.access == RoomAccess::Join {
                    self.gate().await;
                }
                return Ok(ALLOW);
            }
            if id.starts_with("live:") {
                self.gate().await;
                let roles = [fuz_auth::ROLE_ADMIN];
                let holds = match db {
                    fuz_db::ActionDb::Pool(client) => {
                        query_active_actor_holds_any_global_role(*client, &input.actor_id, &roles)
                            .await
                    }
                    fuz_db::ActionDb::Tx(tx) => {
                        query_active_actor_holds_any_global_role(*tx, &input.actor_id, &roles).await
                    }
                }
                .map_err(|e| fuz_http::internal_error_with_source("authorize", &e))?;
                return Ok(if holds { ALLOW } else { RoomVerdict::Deny });
            }
            Ok(RoomVerdict::Deny)
        })
    }
}

struct Server {
    addr: SocketAddr,
    connections: Arc<ConnectionRegistry>,
    rooms: Arc<RoomRegistry>,
    authorize: Arc<SuiteAuthorize>,
}

/// The suite's limits: the room limiter's budgets, and the dispatcher's
/// per-account attempts (`None` leaves the dispatcher's limiters off).
#[derive(Default)]
struct Limits {
    room: Option<RoomRateLimitOptions>,
    account_attempts: Option<u32>,
}

/// Serve the room verbs on the real WS endpoint over a fresh registry.
async fn serve(pool: &Pool, limits: Limits) -> Server {
    let connections = Arc::new(ConnectionRegistry::new());
    let rooms = Arc::new(RoomRegistry::new(
        Arc::clone(&connections),
        RoomRegistryOptions {
            exclusive: true,
            max_payload_bytes: 64,
            ..RoomRegistryOptions::default()
        },
    ));
    let authorize = Arc::new(SuiteAuthorize::default());
    let authorizer: Arc<dyn RoomAuthorize> = Arc::<SuiteAuthorize>::clone(&authorize);
    let specs = build_room_spec_set(RoomSpecSetOptions {
        registry: Arc::clone(&rooms),
        authorizer,
        limiter: limits
            .room
            .map(|options| Arc::new(RoomRateLimiter::new(options))),
        join_extra: Some(Arc::new(|input| json!({"member": input.member_id}))),
    })
    .unwrap();
    let rate_limits = limits.account_attempts.map_or_else(
        || fuz_actions::ActionRateLimits::defaults(RateLimiterMode::DisabledForTesting),
        |max_attempts| {
            fuz_actions::ActionRateLimits::new(
                RateLimiterMode::Enforced,
                RateLimiterOptions {
                    max_attempts,
                    window_ms: 60_000,
                    max_keys: None,
                },
                fuz_auth::DEFAULT_ACTION_IP_RATE_LIMIT,
            )
        },
    );
    let notification_sender: Arc<dyn fuz_auth::NotificationSender> =
        Arc::<ConnectionRegistry>::clone(&connections);
    let state = WsRouteState {
        dispatch: fuz_actions::ActionDispatch {
            gate: fuz_testing::testing_auth_gate(pool.clone()),
            registry: Arc::new(ActionRegistry::compile(specs).unwrap()),
            audit: Arc::new(AuditEmitter::new(pool.clone(), Arc::default())),
            connection_closer: Arc::new(NoopConnectionCloser),
            notification_sender,
            rate_limits,
        },
        connection_registry: Arc::clone(&connections),
        required_roles: Vec::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = register_action_ws(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server {
        addr,
        connections,
        rooms,
        authorize,
    }
}

/// One client socket, speaking JSON-RPC frames by hand.
struct Socket {
    stream: TcpStream,
    actor_id: Uuid,
    next_id: u64,
}

impl Socket {
    /// Seed an account and open an upgraded socket under its session.
    async fn open(pool: &Pool, addr: SocketAddr, username: &str) -> Self {
        let (account_id, actor_id) = seed_account_actor(pool, username).await;
        Self::open_as(pool, addr, account_id, actor_id).await
    }

    /// Open an upgraded socket under a fresh session of `account_id`.
    async fn open_as(pool: &Pool, addr: SocketAddr, account_id: Uuid, actor_id: Uuid) -> Self {
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
        Self {
            stream,
            actor_id,
            next_id: 0,
        }
    }

    /// Write one masked text frame (an all-zero mask leaves the payload as
    /// it is).
    async fn write(&mut self, message: &Value) {
        let text = message.to_string();
        let len = text.len();
        let mut frame = vec![0x81];
        if len < 126 {
            frame.push(0x80 | u8::try_from(len).unwrap());
        } else if let Ok(len) = u16::try_from(len) {
            frame.push(0x80 | 0x7e);
            frame.extend_from_slice(&len.to_be_bytes());
        } else {
            frame.push(0x80 | 0x7f);
            frame.extend_from_slice(&u64::try_from(len).unwrap().to_be_bytes());
        }
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(text.as_bytes());
        self.stream.write_all(&frame).await.unwrap();
    }

    /// Read one text frame, parsed.
    async fn read(&mut self) -> Value {
        let read = async {
            let mut header = [0u8; 2];
            self.stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0] & 0x0f, 0x1, "a text frame");
            let len = match header[1] & 0x7f {
                126 => {
                    let mut extended = [0u8; 2];
                    self.stream.read_exact(&mut extended).await.unwrap();
                    usize::from(u16::from_be_bytes(extended))
                }
                127 => {
                    let mut extended = [0u8; 8];
                    self.stream.read_exact(&mut extended).await.unwrap();
                    usize::try_from(u64::from_be_bytes(extended)).unwrap()
                }
                short => usize::from(short),
            };
            let mut payload = vec![0u8; len];
            self.stream.read_exact(&mut payload).await.unwrap();
            serde_json::from_slice(&payload).unwrap()
        };
        tokio::time::timeout(STEP_TIMEOUT, read)
            .await
            .expect("the server writes a frame")
    }

    /// Send a request, returning its id.
    async fn send(&mut self, method: &str, params: Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.write(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        id
    }

    /// Read until the response to `id`, failing on any notification first.
    async fn response(&mut self, id: u64) -> Value {
        let message = self.read().await;
        assert_eq!(
            message["id"],
            json!(id),
            "the answer comes first: {message}"
        );
        message
    }

    /// A request's result, failing on an error.
    async fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.send(method, params).await;
        let response = self.response(id).await;
        assert!(response.get("error").is_none(), "{method}: {response}");
        response["result"].clone()
    }

    /// A request's error.
    async fn refused(&mut self, method: &str, params: Value) -> Value {
        let id = self.send(method, params).await;
        let response = self.response(id).await;
        assert!(
            response.get("error").is_some(),
            "{method} answered {response}"
        );
        response["error"].clone()
    }

    /// The next frame, a notification of `method`; its params.
    async fn heard(&mut self, method: &str) -> Value {
        let message = self.read().await;
        assert_eq!(message["method"], json!(method), "{message}");
        assert!(message.get("id").is_none());
        message["params"].clone()
    }
}

fn reason(error: &Value) -> &str {
    error["data"]["reason"].as_str().unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn members_join_relay_set_state_and_leave_over_the_socket() {
    let pool = DB.open().await;
    let server = serve(&pool, Limits::default()).await;
    let mut a = Socket::open(&pool, server.addr, "rooms_a").await;
    let mut b = Socket::open(&pool, server.addr, "rooms_b").await;
    let room = "ok:g1:line";

    let joined_a = a
        .call("room_join", json!({"room_id": room, "state": "muted"}))
        .await;
    let member_a = joined_a["member_id"].clone();
    assert_eq!(
        joined_a,
        json!({
            "room_id": room,
            "member_id": member_a,
            "seq": 1,
            "members": [{"member_id": member_a, "actor_id": a.actor_id, "state": "muted"}],
            "topology": "mesh",
            "extra": {"member": member_a},
        })
    );

    let joined_b = b.call("room_join", json!({"room_id": room})).await;
    let member_b = joined_b["member_id"].clone();
    assert_eq!(joined_b["seq"], 2);
    assert_eq!(joined_b["members"].as_array().unwrap().len(), 2);
    assert_eq!(
        a.heard("room_member_joined").await,
        json!({
            "room_id": room,
            "seq": 2,
            "member": {"member_id": member_b, "actor_id": b.actor_id, "state": null},
        })
    );

    // to one member, then to the room
    assert_eq!(
        b.call(
            "room_send",
            json!({"room_id": room, "to": member_a, "payload": "offer"})
        )
        .await,
        Value::Null
    );
    assert_eq!(
        a.heard("room_message").await,
        json!({"room_id": room, "seq": 3, "from": member_b, "to": member_a, "payload": "offer"})
    );
    b.call(
        "room_send",
        json!({"room_id": room, "to": null, "payload": "hi"}),
    )
    .await;
    assert_eq!(a.heard("room_message").await["payload"], "hi");

    assert_eq!(
        a.call("room_state_set", json!({"room_id": room, "state": "live"}))
            .await,
        json!({"seq": 5})
    );
    assert_eq!(
        b.heard("room_member_state").await,
        json!({"room_id": room, "seq": 5, "member_id": member_a, "state": "live"})
    );

    assert_eq!(
        a.call("room_leave", json!({"room_id": room})).await,
        json!({"left": true})
    );
    assert_eq!(
        b.heard("room_member_left").await,
        json!({"room_id": room, "seq": 6, "member_id": member_a, "reason": "left"})
    );
    assert_eq!(
        a.call("room_leave", json!({"room_id": room})).await,
        json!({"left": false})
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusals_answer_their_reasons() {
    let pool = DB.open().await;
    let server = serve(&pool, Limits::default()).await;
    let mut a = Socket::open(&pool, server.addr, "rooms_refusals").await;

    // denied and missing read the same
    let denied = a.refused("room_join", json!({"room_id": "closed:x"})).await;
    assert_eq!(denied["code"], -32003);
    assert_eq!(reason(&denied), "room_not_found");
    assert_eq!(
        reason(
            &a.refused("room_watch", json!({"room_id": "closed:x"}))
                .await
        ),
        "room_not_found"
    );
    // a malformed room id is the input schema's refusal
    let malformed = a
        .refused("room_join", json!({"room_id": "has space"}))
        .await;
    assert_eq!(malformed["code"], -32602);
    assert_eq!(malformed["message"], "invalid params");

    let room = "ok:g1:refusals";
    assert_eq!(
        reason(
            &a.refused(
                "room_send",
                json!({"room_id": room, "to": null, "payload": "x"})
            )
            .await
        ),
        "room_not_joined"
    );
    let member = a.call("room_join", json!({"room_id": room})).await["member_id"].clone();
    let too_large = a
        .refused(
            "room_send",
            json!({"room_id": room, "to": null, "payload": "x".repeat(65)}),
        )
        .await;
    assert_eq!(too_large["code"], -32602);
    assert_eq!(reason(&too_large), "room_payload_too_large");
    assert_eq!(
        reason(
            &a.refused(
                "room_send",
                json!({"room_id": room, "to": Uuid::new_v4(), "payload": "x"})
            )
            .await
        ),
        "room_member_not_found"
    );
    // nor may a member address itself
    assert_eq!(
        reason(
            &a.refused(
                "room_send",
                json!({"room_id": room, "to": member, "payload": "x"})
            )
            .await
        ),
        "room_member_not_found"
    );
}

/// A socket that closes is released: its room hears `room_member_left` with
/// reason `disconnected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_socket_leaves_its_rooms() {
    let pool = DB.open().await;
    let server = serve(&pool, Limits::default()).await;
    let mut a = Socket::open(&pool, server.addr, "rooms_stays").await;
    let mut b = Socket::open(&pool, server.addr, "rooms_goes").await;
    let room = "ok:g1:disconnect";
    a.call("room_join", json!({"room_id": room})).await;
    let member_b = b.call("room_join", json!({"room_id": room})).await["member_id"].clone();
    a.heard("room_member_joined").await;

    drop(b);
    assert_eq!(
        a.heard("room_member_left").await,
        json!({"room_id": room, "seq": 3, "member_id": member_b, "reason": "disconnected"})
    );
}

/// A watch hears the members come and go without a seat, and a watcher's
/// eviction ends it; a member's eviction tells it its seat is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watches_and_evictions_over_the_socket() {
    let pool = DB.open().await;
    let server = serve(&pool, Limits::default()).await;
    let mut watcher = Socket::open(&pool, server.addr, "rooms_watcher").await;
    let mut member = Socket::open(&pool, server.addr, "rooms_member").await;
    let room = "ok:g1:watched";

    assert_eq!(
        watcher.call("room_watch", json!({"room_id": room})).await,
        json!({"room_id": room, "seq": 0, "members": []})
    );
    let member_id = member.call("room_join", json!({"room_id": room})).await["member_id"].clone();
    assert_eq!(
        watcher.heard("room_member_joined").await["member"]["member_id"],
        member_id
    );

    let evicted = server.rooms.evict(
        &RoomEvictTarget::Scope(RoomScope::new("g1")),
        RoomEvictReason::Evicted,
    );
    assert_eq!((evicted.seats, evicted.watches), (1, 1));
    assert_eq!(
        member.heard("room_seat_lost").await,
        json!({"room_id": room, "member_id": member_id, "reason": "evicted", "moved_to": null})
    );
    assert_eq!(
        watcher.heard("room_watch_ended").await,
        json!({"room_id": room, "reason": "evicted"})
    );
    assert!(
        server
            .rooms
            .occupancy(&RoomId::parse(room).unwrap())
            .is_none()
    );
    assert_eq!(
        watcher.call("room_unwatch", json!({"room_id": room})).await,
        json!({"unwatched": false})
    );
}

/// A client `cancel` of a join held in its authorizer drops the join: the
/// handler reads its signal after the authorizer and answers
/// `request_cancelled`, seating no one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_join_is_not_seated() {
    let pool = DB.open().await;
    let server = serve(&pool, Limits::default()).await;
    let mut a = Socket::open(&pool, server.addr, "rooms_cancel").await;
    let room = "gate:cancel";

    let join = a.send("room_join", json!({"room_id": room})).await;
    tokio::time::timeout(STEP_TIMEOUT, server.authorize.reached.notified())
        .await
        .expect("the join reaches its authorizer");
    a.write(&json!({"jsonrpc": "2.0", "method": "cancel", "params": {"request_id": join}}))
        .await;
    // a round trip behind the cancel: the loop reads frames in order, so the
    // cancel has fired once this answers
    a.call("room_leave", json!({"room_id": "ok:g1:barrier"}))
        .await;
    server.authorize.release.notify_one();

    let response = a.response(join).await;
    assert_eq!(response["error"]["code"], -32010, "{response}");
    assert!(
        server
            .rooms
            .occupancy(&RoomId::parse(room).unwrap())
            .is_none()
    );
}

/// The connection's own leave of a room overtakes its join held in the
/// authorizer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leave_supersedes_a_join_in_flight() {
    let pool = DB.open().await;
    let server = serve(&pool, Limits::default()).await;
    let mut a = Socket::open(&pool, server.addr, "rooms_superseded").await;
    let room = "gate:superseded";

    let join = a.send("room_join", json!({"room_id": room})).await;
    tokio::time::timeout(STEP_TIMEOUT, server.authorize.reached.notified())
        .await
        .expect("the join reaches its authorizer");
    assert_eq!(
        a.call("room_leave", json!({"room_id": room})).await,
        json!({"left": true})
    );
    server.authorize.release.notify_one();
    let response = a.response(join).await;
    assert_eq!(reason(&response["error"]), "room_join_superseded");
}

/// The room limiter counts joins and sends per connection, outside the
/// account budget, and answers `rate_limited` with `retry_after`; a watch
/// and a leave cost it nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_limiter_refuses_past_its_budget() {
    let pool = DB.open().await;
    let server = serve(
        &pool,
        Limits {
            // bytes enough for a max-size state at its worst, which the
            // spec set requires
            room: Some(RoomRateLimitOptions {
                max_requests: 3,
                max_bytes: 8 * 1024,
                window: Duration::from_secs(60),
            }),
            account_attempts: None,
        },
    )
    .await;
    let mut a = Socket::open(&pool, server.addr, "rooms_limited").await;
    let mut b = Socket::open(&pool, server.addr, "rooms_unlimited").await;
    let room = "ok:g1:limited";
    a.call("room_join", json!({"room_id": room})).await;
    for _ in 0..2 {
        a.call(
            "room_send",
            json!({"room_id": room, "to": null, "payload": "x"}),
        )
        .await;
    }
    let limited = a
        .refused(
            "room_send",
            json!({"room_id": room, "to": null, "payload": "x"}),
        )
        .await;
    assert_eq!(limited["code"], -32006);
    assert_eq!(limited["data"]["retry_after"], 20);
    // watching and leaving are never limited here, and another connection
    // has its own budget
    a.call("room_leave", json!({"room_id": room})).await;
    a.call("room_watch", json!({"room_id": room})).await;
    b.call("room_join", json!({"room_id": room})).await;
}

/// Joins and watches charge the dispatcher's per-account budget, shared by
/// every socket of the account; sends and state sets don't.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn joins_and_watches_share_the_account_budget() {
    let pool = DB.open().await;
    let server = serve(
        &pool,
        Limits {
            room: None,
            account_attempts: Some(2),
        },
    )
    .await;
    let (account_id, actor_id) = seed_account_actor(&pool, "rooms_account").await;
    let mut tab_1 = Socket::open_as(&pool, server.addr, account_id, actor_id).await;
    let mut tab_2 = Socket::open_as(&pool, server.addr, account_id, actor_id).await;
    let room = "ok:g1:account";
    tab_1.call("room_join", json!({"room_id": room})).await;
    tab_2.call("room_watch", json!({"room_id": room})).await;
    // the third, on either socket, is over the account's budget
    let limited = tab_2
        .refused("room_join", json!({"room_id": "ok:g1:other"}))
        .await;
    assert_eq!(limited["code"], -32006, "{limited}");
    assert!(limited["data"]["retry_after"].as_u64().unwrap() >= 1);
    // sends and state sets ride the room limiter alone
    for _ in 0..3 {
        tab_1
            .call("room_state_set", json!({"room_id": room, "state": "s"}))
            .await;
        assert_eq!(tab_2.heard("room_member_state").await["state"], "s");
    }
    // another account has its own budget
    let mut other = Socket::open(&pool, server.addr, "rooms_account_other").await;
    other.call("room_join", json!({"room_id": room})).await;
}

/// The authorizer's verdict rests on what the database says inside the
/// reserve window, not on the grants the dispatcher loaded for the request.
///
/// The revoke here commits after the dispatcher's grant load (the request is
/// already in the authorizer) and is followed by no registry eviction: an
/// eviction landing before the reserve finds no join in flight to reach, so
/// this is the window's state. The live read denies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoke_before_the_authorizer_reads_leaves_no_seat() {
    let pool = DB.open().await;
    let server = serve(&pool, Limits::default()).await;
    let (account_id, actor_id) = seed_account_actor(&pool, "rooms_revoked").await;
    {
        let client = pool.get().await.unwrap();
        query_create_role_grant(
            &client,
            &actor_id,
            fuz_auth::ROLE_ADMIN,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    }
    let mut a = Socket::open_as(&pool, server.addr, account_id, actor_id).await;

    // while the grant holds, the live read admits
    let join = a.send("room_join", json!({"room_id": "live:held"})).await;
    tokio::time::timeout(STEP_TIMEOUT, server.authorize.reached.notified())
        .await
        .expect("the join reaches its authorizer");
    server.authorize.release.notify_one();
    let held = a.response(join).await;
    assert!(held.get("error").is_none(), "{held}");

    let room = "live:revoked";
    let join = a.send("room_join", json!({"room_id": room})).await;
    tokio::time::timeout(STEP_TIMEOUT, server.authorize.reached.notified())
        .await
        .expect("the join reaches its authorizer");
    // the dispatcher loaded the grant before the handler; revoke it now
    let revoked = pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE role_grant SET revoked_at = NOW() WHERE actor_id = $1 AND revoked_at IS NULL",
            &[&actor_id],
        )
        .await
        .unwrap();
    assert_eq!(revoked, 1);
    server.authorize.release.notify_one();
    let response = a.response(join).await;
    assert_eq!(reason(&response["error"]), "room_not_found", "{response}");
    assert!(
        server
            .rooms
            .occupancy(&RoomId::parse(room).unwrap())
            .is_none()
    );
}

/// A socket that closes while its join is held in the authorizer leaves no
/// seat: a watcher of the room hears no one join, before or after the
/// authorizer is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socket_closed_mid_authorizer_leaves_no_seat() {
    let pool = DB.open().await;
    let server = serve(&pool, Limits::default()).await;
    let mut watcher = Socket::open(&pool, server.addr, "rooms_drop_watcher").await;
    let mut a = Socket::open(&pool, server.addr, "rooms_drop").await;
    let room = "gate:dropped";
    assert_eq!(
        watcher.call("room_watch", json!({"room_id": room})).await["members"],
        json!([])
    );

    a.send("room_join", json!({"room_id": room})).await;
    tokio::time::timeout(STEP_TIMEOUT, server.authorize.reached.notified())
        .await
        .expect("the join reaches its authorizer");
    drop(a);
    // the server has seen the close once the socket leaves its registry
    tokio::time::timeout(STEP_TIMEOUT, async {
        while server.connections.connection_count() > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the server sees the close");
    // the close dropped the held join's future; a join that outlived it would
    // pass the gate on this release instead, disarmed, and nothing would signal
    server.authorize.release.notify_one();
    tokio::time::timeout(STEP_TIMEOUT, server.authorize.dropped.notified())
        .await
        .expect("the close drops the join held in its authorizer");
    assert_eq!(
        watcher.call("room_watch", json!({"room_id": room})).await,
        json!({"room_id": room, "seq": 0, "members": []})
    );
    assert_eq!(
        server
            .rooms
            .occupancy(&RoomId::parse(room).unwrap())
            .unwrap()
            .members,
        []
    );
}
