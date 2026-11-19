//! Unit tests of the room specs' shapes, inputs, refusals, and limiter. The
//! verbs over a live socket are `tests/rooms_ws.rs`.

use std::sync::Arc;
use std::time::Duration;

use fuz_auth::{AuthAxis, CredentialGate, RateLimitClass};
use fuz_http::{InputShape, JsonrpcErrorCode};
use fuz_realtime::{
    ConnectionId, ConnectionIdentity, ConnectionReceiver, ConnectionRegistry, MemberId,
    ROOM_ID_MAX_LENGTH, RoomError, RoomId, RoomRegistry, RoomRegistryOptions, RoomSeatAdmit,
    RoomSeatRequest, connection_channel,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    DEFAULT_ROOM_RATE_LIMIT, JSON_ESCAPE_MAX_EXPANSION, RoomAuthorize, RoomAuthorizeInput,
    RoomIdInput, RoomJoinInput, RoomRateLimitOptions, RoomRateLimited, RoomRateLimiter,
    RoomSendInput, RoomSpecSetError, RoomSpecSetOptions, RoomVerdict, build_room_spec_set,
    check_limits, json_escaped_len, room_error,
};

struct DenyAll;

impl RoomAuthorize for DenyAll {
    fn authorize<'a>(
        &'a self,
        _input: &'a RoomAuthorizeInput<'a>,
        _db: &'a fuz_db::ActionDb<'a>,
    ) -> futures::future::BoxFuture<'a, Result<RoomVerdict, fuz_http::JsonrpcError>> {
        Box::pin(async { Ok(RoomVerdict::Deny) })
    }
}

fn connection_ids(count: usize) -> (Arc<ConnectionRegistry>, Vec<ConnectionId>) {
    let registry = Arc::new(ConnectionRegistry::new());
    let ids = (0..count)
        .map(|_| {
            let (sender, receiver) = connection_channel(1024);
            // the receiver is dropped: only the id is wanted
            drop(receiver);
            registry
                .add_connection(
                    sender,
                    ConnectionIdentity::default(),
                    CancellationToken::new(),
                )
                .id
        })
        .collect();
    (registry, ids)
}

#[test]
fn the_specs_are_ws_only_actor_required_and_without_side_effects() {
    let connections = Arc::new(ConnectionRegistry::new());
    let specs = build_room_spec_set(RoomSpecSetOptions {
        registry: Arc::new(RoomRegistry::new(
            connections,
            RoomRegistryOptions::default(),
        )),
        authorizer: Arc::new(DenyAll),
        limiter: None,
        join_extra: None,
    })
    .unwrap();
    let methods: Vec<&str> = specs.iter().map(|s| s.method).collect();
    assert_eq!(
        methods,
        [
            "room_join",
            "room_leave",
            "room_send",
            "room_state_set",
            "room_watch",
            "room_unwatch"
        ]
    );
    for spec in &specs {
        assert!(spec.ws_only, "{}", spec.method);
        assert!(!spec.side_effects, "{}", spec.method);
        assert_eq!(spec.input, InputShape::Object, "{}", spec.method);
        // join and watch run the consumer's database authorizer, so the
        // account budget bounds them; the rest ride the connection's limiter
        let expected =
            matches!(spec.method, "room_join" | "room_watch").then_some(RateLimitClass::Account);
        assert_eq!(spec.rate_limit, expected, "{}", spec.method);
        assert_eq!(spec.auth.account, AuthAxis::Required);
        assert_eq!(spec.auth.actor, AuthAxis::Required);
        assert_eq!(spec.auth.roles, None);
        assert_eq!(spec.auth.credentials, CredentialGate::Any);
    }
    crate::ActionRegistry::compile(specs).expect("the specs compile");
}

#[test]
fn the_inputs_are_strict() {
    let parse_send = |params: Value| {
        fuz_http::parse_strict_params_allowing_null::<RoomSendInput>(params, &["to"])
    };
    assert!(parse_send(json!({"room_id": "r", "to": null, "payload": "p"})).is_ok());
    let member = "0b4f5b0e-1c8a-4d63-9a51-1f0c2a3b4c5d";
    let input = parse_send(json!({"room_id": "r", "to": member, "payload": "p"})).unwrap();
    assert_eq!(input.to.unwrap().to_string(), member);
    // `to` is required, and nullable only
    assert!(parse_send(json!({"room_id": "r", "payload": "p"})).is_err());
    assert!(parse_send(json!({"room_id": "r", "to": "nope", "payload": "p"})).is_err());
    assert!(parse_send(json!({"room_id": "r", "to": null, "payload": 1})).is_err());
    assert!(parse_send(json!({"room_id": "r", "to": null, "payload": "p", "x": 1})).is_err());

    let parse_join = |params: Value| fuz_http::parse_strict_params::<RoomJoinInput>(params);
    assert!(parse_join(json!({"room_id": "r"})).is_ok());
    assert!(
        parse_join(json!({"room_id": "r", "state": "s", "rejoin_of": member, "acting": member}))
            .is_ok()
    );
    assert!(
        parse_join(json!({"room_id": "r", "state": null})).is_err(),
        "optional, not nullable"
    );
    assert!(parse_join(json!({"room_id": "r", "rejoin_of": "nope"})).is_err());

    let parse_id = |params: Value| fuz_http::parse_strict_params::<RoomIdInput>(params);
    assert!(parse_id(json!({"room_id": "r", "acting": member})).is_ok());
    assert!(parse_id(json!({})).is_err());
    assert!(super::parse_room_id("has space").is_err());
    assert!(super::parse_room_id(&"x".repeat(129)).is_err());
}

#[test]
fn each_refusal_names_its_reason() {
    let reason = |error: RoomError| {
        let error = room_error(error);
        (
            error.code,
            error
                .data
                .and_then(|d| d["reason"].as_str().map(ToOwned::to_owned)),
        )
    };
    let named = |code, reason: &str| (code, Some(reason.to_owned()));
    assert_eq!(
        reason(RoomError::Evicted),
        named(JsonrpcErrorCode::NotFound, "room_not_found")
    );
    assert_eq!(
        reason(RoomError::Full),
        named(JsonrpcErrorCode::Conflict, "room_full")
    );
    assert_eq!(
        reason(RoomError::JoinSuperseded),
        named(JsonrpcErrorCode::Conflict, "room_join_superseded")
    );
    assert_eq!(
        reason(RoomError::SeatMoved),
        named(JsonrpcErrorCode::Conflict, "room_seat_moved")
    );
    assert_eq!(
        reason(RoomError::NotJoined),
        named(JsonrpcErrorCode::Conflict, "room_not_joined")
    );
    assert_eq!(
        reason(RoomError::MemberNotFound),
        named(JsonrpcErrorCode::NotFound, "room_member_not_found")
    );
    assert_eq!(
        reason(RoomError::PayloadTooLarge),
        named(JsonrpcErrorCode::InvalidParams, "room_payload_too_large")
    );
    assert_eq!(
        reason(RoomError::StateTooLarge),
        named(JsonrpcErrorCode::InvalidParams, "room_state_too_large")
    );
    assert_eq!(
        reason(RoomError::WatchLimit),
        named(JsonrpcErrorCode::Conflict, "room_watch_limit")
    );
    assert_eq!(
        reason(RoomError::ConnectionClosed),
        (JsonrpcErrorCode::RequestCancelled, None)
    );
}

/// The charge is the length `serde_json` writes, character class by class.
#[test]
fn the_escaped_length_is_what_serde_json_writes() {
    let written = |text: &str| serde_json::to_string(text).unwrap().len() - 2;
    for code in 0u8..=0x7f {
        let text = char::from(code).to_string();
        assert_eq!(json_escaped_len(&text), written(&text), "U+{code:04X}");
    }
    for text in [
        "",
        "plain",
        "\u{e9}",
        "\u{20ac}",
        "\u{1f600}",
        "\u{2028}\u{2029}",
        "\u{feff}",
        "a\"b\\c\nd\u{0}e\u{1f}\u{7f}",
    ] {
        assert_eq!(json_escaped_len(text), written(text), "{text:?}");
    }
    // the classes the twin mirrors
    assert_eq!(json_escaped_len("\"\\"), 4);
    assert_eq!(json_escaped_len("\u{8}\u{c}\n\r\t"), 10);
    assert_eq!(json_escaped_len("\u{0}\u{b}\u{1f}"), 18);
    assert_eq!(json_escaped_len("\u{7f}\u{e9}\u{1f600}"), 1 + 2 + 4);
    assert_eq!(
        json_escaped_len(&"\u{1}".repeat(10)),
        10 * usize::try_from(JSON_ESCAPE_MAX_EXPANSION).unwrap()
    );
}

/// A limiter that could never cover a max-size payload or state, or any
/// request, is refused at construction.
#[test]
fn a_limiter_below_the_registry_bounds_is_refused() {
    let registry = RoomRegistryOptions::default();
    check_limits(&registry, &DEFAULT_ROOM_RATE_LIMIT).expect("the defaults fit");
    let worst = |bytes: usize| u64::try_from(bytes).unwrap() * JSON_ESCAPE_MAX_EXPANSION;
    let at = |max_bytes| RoomRateLimitOptions {
        max_bytes,
        ..DEFAULT_ROOM_RATE_LIMIT
    };
    check_limits(&registry, &at(worst(registry.max_payload_bytes))).expect("exactly enough");
    assert_eq!(
        check_limits(&registry, &at(worst(registry.max_payload_bytes) - 1)),
        Err(RoomSpecSetError::ByteBudgetBelowBound {
            bound: "payload",
            charge: worst(registry.max_payload_bytes),
            max_bytes: worst(registry.max_payload_bytes) - 1,
        })
    );
    let big_state = RoomRegistryOptions {
        max_payload_bytes: 10,
        max_state_bytes: 100,
        ..RoomRegistryOptions::default()
    };
    assert!(matches!(
        check_limits(&big_state, &at(599)),
        Err(RoomSpecSetError::ByteBudgetBelowBound { bound: "state", .. })
    ));
    assert_eq!(
        check_limits(
            &registry,
            &RoomRateLimitOptions {
                max_requests: 0,
                ..DEFAULT_ROOM_RATE_LIMIT
            }
        ),
        Err(RoomSpecSetError::NoRequestBudget)
    );

    // the builder runs the check
    let refused = build_room_spec_set(RoomSpecSetOptions {
        registry: Arc::new(RoomRegistry::new(
            Arc::new(ConnectionRegistry::new()),
            registry,
        )),
        authorizer: Arc::new(DenyAll),
        limiter: Some(Arc::new(RoomRateLimiter::new(at(1024)))),
        join_extra: None,
    });
    assert!(matches!(
        refused,
        Err(RoomSpecSetError::ByteBudgetBelowBound { .. })
    ));
}

/// One socket for the burst test: its id, actor, and queue.
struct Socket {
    id: ConnectionId,
    actor: Uuid,
    rx: ConnectionReceiver,
    signal: CancellationToken,
}

fn open(connections: &ConnectionRegistry) -> Socket {
    let (sender, rx) = connection_channel(crate::DEFAULT_WS_OUTBOUND_QUEUE_BYTES);
    let signal = CancellationToken::new();
    let id = connections
        .add_connection(sender, ConnectionIdentity::default(), signal.clone())
        .id;
    Socket {
        id,
        actor: Uuid::new_v4(),
        rx,
        signal,
    }
}

fn join(rooms: &Arc<RoomRegistry>, socket: &Socket, room_id: &RoomId) -> MemberId {
    let pending = rooms
        .reserve_seat(RoomSeatRequest {
            connection_id: socket.id,
            actor_id: socket.actor,
            room_id: room_id.clone(),
            rejoin_of: None,
        })
        .unwrap();
    rooms
        .admit_seat(pending, RoomSeatAdmit::default())
        .unwrap()
        .member_id
}

/// The length of the next frame queued for `socket`, waiting for it.
async fn next_frame_len(socket: &mut Socket) -> usize {
    let frame = tokio::time::timeout(Duration::from_secs(5), socket.rx.recv())
        .await
        .expect("a frame")
        .expect("the queue is open");
    frame.as_str().len()
}

/// The default budgets hold their claim against the registry's own frames
/// at their worst: one member's full burst — `max_bytes` of content, plus
/// four frames' fixed overhead for each of `max_requests` — stays under half
/// a reader's default outbound queue.
#[tokio::test]
async fn a_full_burst_stays_under_half_a_readers_queue() {
    let connections = Arc::new(ConnectionRegistry::new());
    let options = RoomRegistryOptions::default();
    let rooms = Arc::new(RoomRegistry::new(Arc::clone(&connections), options));
    // a max-length room id whose every character escapes
    let room_id = RoomId::parse(&"\"".repeat(ROOM_ID_MAX_LENGTH)).unwrap();
    let mut reader = open(&connections);
    let sender = open(&connections);
    let reader_member = join(&rooms, &reader, &room_id);

    // each frame a member's requests put in the reader's queue, empty of
    // content: a join (state `null`, longer than any empty state), a state
    // set, an addressed send (a `to`, longer than `null`), a moved seat's
    // `room_seat_lost`, and a disconnect (the longest leave reason)
    let mut fixed = Vec::new();
    join(&rooms, &sender, &room_id);
    fixed.push(next_frame_len(&mut reader).await);
    rooms
        .set_state(sender.id, sender.actor, &room_id, String::new())
        .unwrap();
    fixed.push(next_frame_len(&mut reader).await);
    rooms
        .send(sender.id, sender.actor, &room_id, Some(reader_member), "")
        .unwrap();
    let message_fixed = next_frame_len(&mut reader).await;
    fixed.push(message_fixed);
    // a max-size payload of the characters with the longest escape adds its
    // charge to the frame, exactly
    let payload = "\u{1}".repeat(options.max_payload_bytes);
    rooms
        .send(
            sender.id,
            sender.actor,
            &room_id,
            Some(reader_member),
            &payload,
        )
        .unwrap();
    assert_eq!(
        next_frame_len(&mut reader).await,
        message_fixed + json_escaped_len(&payload)
    );
    // a seat moved within its room hears `room_seat_lost`, which names a
    // room twice (`room_id`, `moved_to`): the longest fixed frame
    join(&rooms, &reader, &room_id);
    fixed.push(next_frame_len(&mut reader).await);
    sender.signal.cancel();
    fixed.push(next_frame_len(&mut reader).await);

    // the seqs measured are one digit; the longest is u64::MAX's twenty
    let overhead = u64::try_from(fixed.into_iter().max().unwrap() + 19).unwrap();
    let limit = DEFAULT_ROOM_RATE_LIMIT;
    let burst = limit.max_bytes + u64::from(limit.max_requests) * 4 * overhead;
    let queue = u64::try_from(crate::DEFAULT_WS_OUTBOUND_QUEUE_BYTES).unwrap();
    assert!(
        burst * 2 <= queue,
        "a burst of {burst} bytes (frame overhead {overhead}) against a {queue}-byte queue"
    );
    // and the budget covers a max-size payload at its worst
    assert!(
        u64::try_from(json_escaped_len(&payload)).unwrap() <= limit.max_bytes,
        "a max-size send is never refused forever"
    );
}

const SMALL: RoomRateLimitOptions = RoomRateLimitOptions {
    max_requests: 3,
    max_bytes: 100,
    window: Duration::from_secs(10),
};

#[tokio::test(start_paused = true)]
async fn the_request_budget_bursts_then_refills_over_its_window() {
    let (_registry, ids) = connection_ids(2);
    let limiter = RoomRateLimiter::new(SMALL);
    for _ in 0..3 {
        limiter.charge(ids[0], 0).unwrap();
    }
    // one request refills every window / max = 3.33 s
    assert_eq!(
        limiter.charge(ids[0], 0),
        Err(RoomRateLimited { retry_after: 4 })
    );
    assert!(limiter.charge(ids[1], 0).is_ok(), "per connection");
    tokio::time::advance(Duration::from_millis(3334)).await;
    limiter.charge(ids[0], 0).unwrap();
    assert!(limiter.charge(ids[0], 0).is_err());
}

#[tokio::test(start_paused = true)]
async fn the_byte_budget_refuses_without_spending() {
    let (_registry, ids) = connection_ids(1);
    let limiter = RoomRateLimiter::new(SMALL);
    limiter.charge(ids[0], 90).unwrap();
    // 20 bytes need 10 more: one second at 10 bytes a second
    assert_eq!(
        limiter.charge(ids[0], 20),
        Err(RoomRateLimited { retry_after: 1 })
    );
    // the refusal spent no request: two remain
    limiter.charge(ids[0], 10).unwrap();
    limiter.charge(ids[0], 0).unwrap();
    assert!(limiter.charge(ids[0], 0).is_err());
    // a charge past the whole budget waits a window, and never passes
    let (_registry, fresh) = connection_ids(1);
    assert_eq!(
        limiter.charge(fresh[0], 101),
        Err(RoomRateLimited { retry_after: 10 })
    );
}

#[tokio::test(start_paused = true)]
async fn full_buckets_are_forgotten() {
    let (_registry, ids) = connection_ids(200);
    let limiter = RoomRateLimiter::new(SMALL);
    for id in &ids[..100] {
        limiter.charge(*id, 1).unwrap();
    }
    assert_eq!(limiter.tracked(), 100);
    tokio::time::advance(SMALL.window).await;
    // the map sweeps as it grows: the refilled hundred go, the rest stay
    for id in &ids[100..] {
        limiter.charge(*id, 1).unwrap();
    }
    assert_eq!(limiter.tracked(), 100);
}
