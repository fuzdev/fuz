//! `fuz_realtime` — realtime primitives for the fuz spine.
//!
//! Provides the per-connection vocabulary that `fuz_actions`
//! and consumer wiring (the spine servers and `testing_spine_stub`)
//! compose into a working WebSocket surface:
//!
//! - [`ConnectionRegistry`] — concrete struct holding per-connection state
//!   keyed by [`ConnectionId`], with identity-keyed revocation — a role
//!   revocation closing only the connections whose endpoint required the
//!   role, with 4006 ([`WS_CLOSE_PERMISSION_REVOKED`]) — and
//!   broadcast, a per-account connection cap (evict-oldest, closing the
//!   superseded socket with 4004), and two-phase registration
//!   (`register_pending` → credential re-check → `admit`) so a revocation
//!   racing an upgrade can't leave a socket on a dead credential. Implements
//!   [`fuz_auth::ConnectionCloser`] for its WS sockets (bind [`RealtimeCloser`]
//!   to cover SSE streams as well), and so the shutdown close-all
//!   ([`fuz_http::ShutdownCloser`]): every socket closed with 1001, every later
//!   registration refused, and a wait for the loops to finish. The
//!   methods (`broadcast`, `broadcast_filtered`, `send_to`,
//!   `send_to_account`, `close_connections`) are the surface. Every send
//!   queues onto the recipient's outbound channel ([`connection_channel`]),
//!   which holds a byte budget of waiting frames, and never waits; one that
//!   does not fit closes that connection with 4005
//!   ([`WS_CLOSE_OUTBOUND_OVERFLOW`]).
//! - Notify primitive ([`notify`] module) — the **borrowed `&dyn Fn`
//!   shape**. HTTP supplies a static no-op
//!   ([`notify::http_no_op_notify`]); WS supplies a closure capturing
//!   `Arc<ConnectionRegistry>` + [`ConnectionId`] via
//!   [`notify::ws_notify_for_connection`]. Stack-only on HTTP (no per-request
//!   `Arc`); WS captures the registry + connection id into one long-lived
//!   closure and passes a borrow at each dispatch site, and the borrowed
//!   `&Value` spares every notify site a `params.clone()`.
//! - [`ws_endpoint`] — the per-socket loop ([`run_ws_connection`]) and a
//!   refused upgrade's close ([`refuse_upgrade`]); the upgrade handler itself
//!   is the consumer's (`fuz_actions::register_action_ws`, or its own over
//!   `fuz_actions::admit_upgrade`). The dispatch arm
//!   delegates to a consumer-supplied callback so `fuz_realtime` stays
//!   free of `ActionSpec` knowledge (that's `fuz_actions`' job). Its read
//!   loop owns the client `cancel` notification, and bounds every write it
//!   makes ([`WS_WRITE_STALL_TIMEOUT`]): a client that stops reading is
//!   dropped at the deadline instead of holding the loop.
//! - [`ws_signals`] — the per-request cancellation hierarchy
//!   ([`PendingRequestSignals`]): each in-flight request gets a child token a
//!   `cancel` fires into; the socket token is reserved for teardown.
//! - [`peer`] — server-initiated requests over an open socket (`peer/ping`),
//!   with the pending one-shot the read loop drains on close.
//! - [`SseRegistry`] — the SSE half: open streams, close-on-revoke (reached
//!   through [`RealtimeCloser`]), the same two-phase registration, and a
//!   per-stream queue budget ([`SSE_OUTBOUND_QUEUE_BYTES`]) past which the
//!   stream ends. Also a [`fuz_auth::ConnectionCloser`]. The audit stream's
//!   route and its fan-out listener are [`audit_stream`]'s.
//! - [`credential_deadline`] — both halves end a connection when the
//!   credential it was opened with expires
//!   ([`fuz_auth::ResolvedAuth::credential_deadline`]): a socket closes with
//!   4001 and [`WS_CLOSE_CREDENTIAL_EXPIRED_REASON`], a stream ends as a
//!   revoked one does. The wait sleeps in bounded steps
//!   ([`CREDENTIAL_DEADLINE_SLEEP_CAP`]), so a far deadline never meets
//!   tokio's sleep ceiling, and checks the wall clock on each wake-up, so a
//!   host suspend does not hold a connection past its credential.
//! - [`RealtimeCloser`] — the `ConnectionCloser` a consumer with both
//!   transports binds: each close fans to the WS and SSE registries, so a
//!   revocation handler's direct close reaches open streams without waiting
//!   on (or depending on) the audit write — and so does the shutdown
//!   close-all `fuz_http::serve_with_shutdown` runs through it.
//!
//! ## Postcard note
//!
//! WS messages are JSON-shaped (via `fuz_http::JsonrpcRequest` /
//! `JsonrpcResponse` / `JsonrpcNotification`). The postcard
//! constraint (`#[serde(skip_serializing_if)]` breaks postcard
//! roundtripping) does not apply to wire types in this crate. Future
//! consumers routing realtime types over postcard transports must keep
//! the `Option` fields plain.

// === WebSocket connection registry ===
pub mod connection;
pub mod connection_registry;
mod outbound_queue;

// === notify seam ===
pub mod notify;

// === server-initiated request capability ===
pub mod peer;

// === connection credential deadline ===
pub mod credential_deadline;

// === WS endpoint primitive ===
pub mod ws_close_codes;
pub mod ws_endpoint;
pub mod ws_signals;

// === SSE endpoint primitive ===
pub mod sse;

// === WS + SSE revocation fan-out ===
pub mod realtime_closer;

// === audit-log SSE route ===
pub mod audit_stream;

// -- Public API re-exports ---------------------------------------------------

pub use audit_stream::{
    AUDIT_LOG_SSE_MAX_PER_SCOPE, AuditStreamRouteState, audit_stream_router,
    register_audit_sse_listener,
};
pub use connection::{
    CloseReason, Connection, ConnectionId, ConnectionIdentity, ConnectionInfo, ConnectionReceiver,
    ConnectionSender, NotAdmitted, connection_channel,
};
pub use connection_registry::{
    ConnectionGuard, ConnectionRegistry, DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT, PendingConnection,
    UpgradeHold,
};
pub use credential_deadline::CREDENTIAL_DEADLINE_SLEEP_CAP;
pub use notify::{http_no_op_notify, notify_to_string, ws_notify_for_connection};
pub use outbound_queue::OUTBOUND_FRAME_OVERHEAD_BYTES;
pub use peer::{
    ActionPeer, ConnectionPeer, DEFAULT_MAX_IN_FLIGHT_PEER_REQUESTS_PER_CONNECTION,
    DEFAULT_PEER_REQUEST_TIMEOUT, NoopActionPeer, PeerError, PeerRequestId, PendingPeerRequests,
    noop_action_peer,
};
pub use realtime_closer::RealtimeCloser;
pub use sse::{
    PendingSseStream, SSE_CONNECTED_COMMENT, SSE_KEEP_ALIVE_COMMENT, SSE_KEEP_ALIVE_INTERVAL,
    SSE_KEEP_ALIVE_INTERVAL_MAX, SSE_OUTBOUND_QUEUE_BYTES, SseRegistry, SseSubscription,
    sse_keep_alive_is_valid,
};
pub use ws_close_codes::{
    WS_CLOSE_CONNECTION_LIMIT, WS_CLOSE_CONNECTION_LIMIT_REASON,
    WS_CLOSE_CREDENTIAL_EXPIRED_REASON, WS_CLOSE_GOING_AWAY, WS_CLOSE_GOING_AWAY_REASON,
    WS_CLOSE_INTERNAL_ERROR, WS_CLOSE_INTERNAL_ERROR_REASON, WS_CLOSE_MESSAGE_TOO_BIG,
    WS_CLOSE_MESSAGE_TOO_BIG_REASON, WS_CLOSE_OUTBOUND_OVERFLOW, WS_CLOSE_OUTBOUND_OVERFLOW_REASON,
    WS_CLOSE_PERMISSION_REVOKED, WS_CLOSE_PERMISSION_REVOKED_REASON,
    WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT, WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT_REASON,
    WS_CLOSE_SESSION_REVOKED, WS_CLOSE_SESSION_REVOKED_REASON,
};
pub use ws_endpoint::{
    CANCEL_METHOD, ERROR_DUPLICATE_REQUEST_ID, MAX_INBOUND_DISPATCHES_PER_CONNECTION, ReplyOwed,
    UpgradeRefusal, WS_INBOUND_DISPATCH_OVERFLOW_MESSAGE, WS_WRITE_STALL_TIMEOUT, WsDispatchFn,
    WsLoopOptions, refuse_upgrade, run_ws_connection,
};
pub use ws_signals::PendingRequestSignals;

/// Cancellation seam — semantic alias for the realtime vocabulary.
///
/// The `ActionContext.signal` field uses this name; the alias
/// keeps the call site vocabulary stable even if the underlying
/// primitive ever changes (e.g. a hand-rolled controller to drop the
/// `tokio_util` dep). It is a transparent alias.
pub type SignalToken = tokio_util::sync::CancellationToken;
