//! `ActionPeer` — server-initiated JSON-RPC request/response over WS.
//!
//! The capability for a backend to **initiate** a request to a connected
//! client and await its typed reply (with timeout / cancel). The three
//! load-bearing pieces — the [`PendingPeerRequests`] registry, the
//! namespaced [`PeerRequestId`] allocation, and the [`ActionPeer`] trait
//! plus its [`NoopActionPeer`] / [`ConnectionPeer`] impls — sit beside the
//! [`ConnectionRegistry`] they reuse. The inbound-`Response` demux that
//! resolves a pending one-shot lives in [`crate::ws_endpoint`].
//!
//! ## Home: `fuz_realtime`, not beside `NotificationSender`
//!
//! [`ActionPeer::request`] takes an explicit [`ConnectionId`] (a
//! `fuz_realtime` type), so the trait can't live in `fuz_auth` beside
//! [`fuz_auth::NotificationSender`] without a dependency cycle
//! (`fuz_realtime` → `fuz_auth`). `fuz_realtime` is the cycle-free home —
//! it already owns [`ConnectionId`] / [`ConnectionRegistry`] and depends
//! on `fuz_http` for [`JsonrpcError`]. `fuz_actions::ActionContext`
//! threads `&dyn ActionPeer` exactly as it threads
//! `&Arc<dyn NotificationSender>`.
//!
//! ## Lock discipline
//!
//! The pending-map lock ([`parking_lot::Mutex`]) is taken **only** to
//! insert / remove / take an entry — never held across the one-shot
//! `.await`. `parking_lot` is not async-aware; holding it across an await
//! would deadlock the registry the moment two requests overlap.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::future::BoxFuture;
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::oneshot;

use fuz_http::JsonrpcError;

use crate::connection::ConnectionId;
use crate::connection_registry::ConnectionRegistry;

/// Default deadline for a server-initiated request awaiting a client reply.
///
/// A real retry / timeout policy needs concrete consumers to design
/// against; this is the v1 default `ctx.request_client` uses. It is also the
/// deadline on each frame the WS loop writes
/// ([`WS_WRITE_STALL_TIMEOUT`](crate::WS_WRITE_STALL_TIMEOUT)): a request
/// that cannot be written within its own reply deadline has already failed.
pub const DEFAULT_PEER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default cap on concurrently-pending **outbound** server-initiated
/// requests **per connection** — the value the spine's WS wiring passes to
/// [`PendingPeerRequests::new`].
///
/// A client that never replies can't exhaust memory past this bound — the
/// next request fails fast with [`PeerError::TooManyInFlight`]. The
/// opposite direction — inbound client dispatches — is bounded separately
/// inside [`crate::ws_endpoint`]. The request frames themselves wait in the
/// connection's outbound queue and are charged against its byte budget like
/// every other frame ([`connection_channel`](crate::connection_channel)).
pub const DEFAULT_MAX_IN_FLIGHT_PEER_REQUESTS_PER_CONNECTION: usize = 256;

/// Server-allocated, **namespaced** request id for a server-initiated
/// request.
///
/// Monotonic per process; serializes to `"s{n}"` so it can never collide
/// with a client-chosen id on the same socket (defence + debuggability).
/// The demux only resolves a reply whose echoed id parses back through
/// `PeerRequestId::parse_value` — a client echoing a non-`s` id matches
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRequestId(u64);

impl PeerRequestId {
    /// The wire id value — `"s{n}"`.
    #[must_use]
    pub fn to_value(self) -> Value {
        Value::String(format!("s{}", self.0))
    }

    /// Recover the raw counter from an echoed wire id, requiring the `"s"`
    /// namespace prefix. `None` for any non-string / non-`s`-prefixed /
    /// non-numeric id — the security boundary that rejects client-chosen
    /// ids at the demux.
    fn parse_value(id: &Value) -> Option<u64> {
        id.as_str()?.strip_prefix('s')?.parse().ok()
    }
}

/// Total error model for a server-initiated request.
///
/// `Unsupported(Capability)` is intentionally absent — it arrives with the
/// deferred client-declared capability layer; nothing gates on a capability
/// in v1, so a precondition-check variant would be dead code.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// The client replied with a JSON-RPC error envelope.
    #[error("peer replied with a JSON-RPC error: {0}")]
    ClientError(JsonrpcError),
    /// No reply within the deadline.
    #[error("server-initiated request timed out")]
    Timeout,
    /// The socket closed (clean close or revocation) before the reply.
    #[error("connection closed before the peer replied")]
    ConnectionGone,
    /// Called on an HTTP / WS-less ([`NoopActionPeer`]) context.
    #[error("no peer transport on this context")]
    NoTransport,
    /// The per-connection pending bound was hit (backpressure).
    #[error("too many in-flight server-initiated requests for this connection")]
    TooManyInFlight,
}

/// Outbound requests awaiting a client reply, nested by connection then by
/// raw request id.
///
/// Resolution is strictly per-connection: a reply arriving on socket B can
/// never resolve a request issued on socket A (it lands in a different inner
/// map). The nesting also makes the in-flight count (`register`'s bound check)
/// and the close-time drain O(1) — the inner map's `len()` is the
/// per-connection count, and `drain_connection` removes the whole inner map in
/// one hop instead of scanning the flat key set. The inner map is keyed by the
/// **raw** [`PeerRequestId`] counter rather than the wire `Value` —
/// `serde_json::Value` is not `Hash` (it carries floats), and the raw counter
/// is the same namespaced identity minus the `"s"` prefix the demux validates.
/// An inner map is removed as soon as it empties, so an idle connection holds
/// no entry.
type PendingMap = HashMap<ConnectionId, HashMap<u64, oneshot::Sender<Result<Value, JsonrpcError>>>>;

#[derive(Debug)]
pub struct PendingPeerRequests {
    inner: Mutex<PendingMap>,
    next_id: AtomicU64,
    max_in_flight_per_connection: usize,
}

impl PendingPeerRequests {
    /// Build an empty registry with the given per-connection outbound
    /// peer-request cap.
    #[must_use]
    pub fn new(max_in_flight_per_connection: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_in_flight_per_connection,
        }
    }

    /// Allocate a [`PeerRequestId`] and register a pending one-shot for
    /// `conn`, returning the id + the receiver the caller awaits.
    ///
    /// `None` when the connection is already at its in-flight cap
    /// (→ [`PeerError::TooManyInFlight`]). Lock held only for the count +
    /// insert; the per-connection count is the inner map's `len()` (O(1), no
    /// scan of the whole pending set).
    #[must_use]
    pub fn register(
        &self,
        conn: ConnectionId,
    ) -> Option<(
        PeerRequestId,
        oneshot::Receiver<Result<Value, JsonrpcError>>,
    )> {
        let mut map = self.inner.lock();
        let in_flight = map.get(&conn).map_or(0, HashMap::len);
        if in_flight >= self.max_in_flight_per_connection {
            return None;
        }
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        map.entry(conn).or_default().insert(n, tx);
        Some((PeerRequestId(n), rx))
    }

    /// Remove a pending entry (cleanup on timeout / cancel / send failure).
    /// Idempotent — dropping the sender wakes any still-awaiting receiver
    /// with a recv error. The inner map is dropped once its last entry goes,
    /// so an idle connection holds no entry.
    pub fn remove(&self, conn: ConnectionId, id: PeerRequestId) {
        let mut map = self.inner.lock();
        if let Some(conn_map) = map.get_mut(&conn) {
            conn_map.remove(&id.0);
            if conn_map.is_empty() {
                map.remove(&conn);
            }
        }
    }

    /// Resolve a pending request for `conn` from an inbound response.
    ///
    /// Returns `true` iff `id` parsed through the namespace and matched a
    /// pending entry **on this connection**. A `false` return is the
    /// security signal the read loop audits: an unsolicited reply, a
    /// cross-connection id echo, or a late/duplicate reply for an
    /// already-settled id. Sending on the one-shot can't fail meaningfully
    /// — a dropped receiver (already timed out) just discards the value.
    #[must_use]
    pub fn resolve(
        &self,
        conn: ConnectionId,
        id: &Value,
        outcome: Result<Value, JsonrpcError>,
    ) -> bool {
        let Some(n) = PeerRequestId::parse_value(id) else {
            return false;
        };
        let sender = {
            let mut map = self.inner.lock();
            let Some(conn_map) = map.get_mut(&conn) else {
                return false;
            };
            let sender = conn_map.remove(&n);
            if conn_map.is_empty() {
                map.remove(&conn);
            }
            sender
        };
        // A dropped receiver (already timed out / cancelled) just discards
        // the value — resolution is idempotent.
        sender.is_some_and(|tx| {
            let _ = tx.send(outcome);
            true
        })
    }

    /// Drop every pending entry for a closing / revoked connection.
    ///
    /// Dropping each sender wakes its awaiting receiver with a recv error,
    /// which [`ConnectionPeer::request`] maps to [`PeerError::ConnectionGone`].
    /// Returns the number drained. Called by the WS read loop on exit. O(1) —
    /// removing the connection's inner map drops every one-shot sender in it
    /// (waking each receiver with a recv error) in one hop.
    pub fn drain_connection(&self, conn: ConnectionId) -> usize {
        self.inner
            .lock()
            .remove(&conn)
            .map_or(0, |conn_map| conn_map.len())
    }

    /// Currently-pending request count across all connections (telemetry / tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().values().map(HashMap::len).sum()
    }

    /// Whether no requests are pending on any connection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().values().all(HashMap::is_empty)
    }
}

/// Initiate a JSON-RPC request to a connected client and await its reply.
///
/// **Object-safe** — returns a [`BoxFuture`] (not RPITIT) so it can be
/// threaded as `&dyn ActionPeer` on the cold-path `ActionContext`. It is
/// *not* the sync `NotificationSender` trait (which must not `.await`);
/// this one awaits a reply.
///
/// The trait takes an explicit [`ConnectionId`] rather than "the current
/// socket" because an admin- or connect-time-triggered request runs
/// outside any handler context, and future fan-out elicitation targets a
/// chosen connection. `ctx.request_client` is the originating-socket
/// convenience over this.
pub trait ActionPeer: Send + Sync {
    /// Send `method`/`params` as a request to `conn` and await the typed
    /// reply (or [`PeerError`]).
    fn request<'a>(
        &'a self,
        conn: ConnectionId,
        method: &'a str,
        params: &'a Value,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Value, PeerError>>;
}

/// HTTP / WS-less consumers: every `request` is [`PeerError::NoTransport`].
///
/// The HTTP RPC path installs this — an HTTP request has no return socket,
/// so a handler reaching for `ctx.request_client` gets a clean error rather
/// than a panic or a hang.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopActionPeer;

impl ActionPeer for NoopActionPeer {
    fn request<'a>(
        &'a self,
        _conn: ConnectionId,
        _method: &'a str,
        _params: &'a Value,
        _timeout: Duration,
    ) -> BoxFuture<'a, Result<Value, PeerError>> {
        Box::pin(async { Err(PeerError::NoTransport) })
    }
}

/// A process-shared [`NoopActionPeer`] as `Arc<dyn ActionPeer>`.
///
/// The HTTP RPC path clones this into each request's dispatch options
/// (a refcount bump, no allocation) rather than minting a fresh `Arc`
/// per request — keeping the WS-less path's overhead at zero, in the
/// spirit of the borrowed-notify reshape.
#[must_use]
pub fn noop_action_peer() -> Arc<dyn ActionPeer> {
    static NOOP: std::sync::LazyLock<Arc<NoopActionPeer>> =
        std::sync::LazyLock::new(|| Arc::new(NoopActionPeer));
    // Deref the `LazyLock` to the inner `Arc`, clone (refcount bump) into a
    // concrete handle, then return-coerce `Arc<NoopActionPeer>` →
    // `Arc<dyn ActionPeer>`.
    let noop: Arc<NoopActionPeer> = Arc::clone(&NOOP);
    noop
}

/// The concrete WS [`ActionPeer`] over an accepted socket.
///
/// Composes [`ConnectionRegistry::send_to`] (write the framed request),
/// [`PendingPeerRequests`] (register the one-shot), and `tokio::time::timeout`.
/// A dying socket ends the await by dropping the pending sender, not through a
/// cancellation token. Holds `Arc`s to the *same* registry + pending map the
/// WS read loop demuxes into.
#[derive(Debug, Clone)]
pub struct ConnectionPeer {
    registry: Arc<ConnectionRegistry>,
    pending: Arc<PendingPeerRequests>,
}

impl ConnectionPeer {
    /// Build a peer over a shared connection registry + pending map.
    #[must_use]
    pub const fn new(registry: Arc<ConnectionRegistry>, pending: Arc<PendingPeerRequests>) -> Self {
        Self { registry, pending }
    }
}

impl ActionPeer for ConnectionPeer {
    fn request<'a>(
        &'a self,
        conn: ConnectionId,
        method: &'a str,
        params: &'a Value,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<Value, PeerError>> {
        Box::pin(async move {
            // 1. The socket must still be registered (else there's no one to
            //    send to). Teardown is observed via the pending one-shot in
            //    step 4, not by racing a cancellation token: socket close /
            //    revocation drops the pending sender (`drain_connection`) → a
            //    recv error. Keep it that way — a token a client `cancel` can
            //    reach (a dispatch's per-request child) must never gate a
            //    server-initiated request, or one `cancel` would fail it with a
            //    false `ConnectionGone`. `is_registered` is presence-only.
            if !self.registry.is_registered(conn) {
                return Err(PeerError::ConnectionGone);
            }

            // 2. Register the pending one-shot (bound check). Lock held
            //    only inside `register`.
            let (id, rx) = self
                .pending
                .register(conn)
                .ok_or(PeerError::TooManyInFlight)?;
            let id_value = id.to_value();

            // 3. Frame + send. A send failure means the socket vanished
            //    between the lookup and now, or the frame overflowed its
            //    outbound queue and closed it — clean up the entry.
            let frame = fuz_http::request_frame(method, params, &id_value);
            if !self.registry.send_to(conn, &frame) {
                self.pending.remove(conn, id);
                return Err(PeerError::ConnectionGone);
            }

            // 4. Await the reply against the deadline. No lock is held across
            //    this await. On socket teardown the read loop drops the pending
            //    sender (recv error → `ConnectionGone`) and drops the in-flight
            //    dispatch future with the loop, so the await can't outlive the
            //    socket.
            match tokio::time::timeout(timeout, rx).await {
                // Deadline elapsed — clean up and report.
                Err(_elapsed) => {
                    self.pending.remove(conn, id);
                    Err(PeerError::Timeout)
                }
                // Resolved by the demux.
                Ok(Ok(Ok(value))) => Ok(value),
                Ok(Ok(Err(jsonrpc_err))) => Err(PeerError::ClientError(jsonrpc_err)),
                // Sender dropped (drain on close / revocation) before a reply.
                Ok(Err(_recv)) => Err(PeerError::ConnectionGone),
            }
        })
    }
}

/// Sampled, bounded audit for an inbound response that matched no pending
/// request on its connection.
///
/// An unsolicited `{id, result}`, a cross-connection id echo, or a
/// late/duplicate reply all land here. Auditing **every** rejected frame
/// would let a flood of junk turn the audit log into the `DoS` target, so
/// this logs the first few then samples 1-in-N.
pub fn audit_unmatched_response(conn: ConnectionId, id: &Value) {
    static DROPPED: AtomicU64 = AtomicU64::new(0);
    let n = DROPPED.fetch_add(1, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(256) {
        tracing::warn!(
            conn_id = conn.get(),
            ?id,
            total = n + 1,
            "ws: dropped unmatched peer response (unsolicited, cross-connection, or already settled)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn conn(n: u64) -> ConnectionId {
        ConnectionId::new(n)
    }

    #[test]
    fn peer_request_id_round_trips_through_the_namespace() {
        let id = PeerRequestId(42);
        let v = id.to_value();
        assert_eq!(v, json!("s42"));
        assert_eq!(PeerRequestId::parse_value(&v), Some(42));
    }

    #[test]
    fn parse_value_rejects_client_chosen_ids() {
        // Non-`s` prefix, numeric ids, and garbage all fail the namespace.
        assert_eq!(PeerRequestId::parse_value(&json!("c42")), None);
        assert_eq!(PeerRequestId::parse_value(&json!(42)), None);
        assert_eq!(PeerRequestId::parse_value(&json!("s")), None);
        assert_eq!(PeerRequestId::parse_value(&json!("sxyz")), None);
        assert_eq!(PeerRequestId::parse_value(&json!(null)), None);
    }

    #[tokio::test]
    async fn register_then_resolve_delivers_the_outcome() {
        let pending = PendingPeerRequests::new(8);
        let (id, rx) = pending.register(conn(1)).expect("register");
        assert_eq!(pending.len(), 1);
        assert!(pending.resolve(conn(1), &id.to_value(), Ok(json!({"ok": true}))));
        assert_eq!(rx.await.unwrap().unwrap(), json!({"ok": true}));
        assert!(pending.is_empty(), "resolve removes the entry");
    }

    #[tokio::test]
    async fn resolve_is_per_connection_isolated() {
        let pending = PendingPeerRequests::new(8);
        let (id, _rx) = pending.register(conn(1)).expect("register");
        // A reply on a different connection must not resolve conn 1's request.
        assert!(!pending.resolve(conn(2), &id.to_value(), Ok(json!(1))));
        assert_eq!(pending.len(), 1, "the conn-1 entry stays pending");
    }

    #[test]
    fn resolve_rejects_unknown_and_unparseable_ids() {
        let pending = PendingPeerRequests::new(8);
        let _ = pending.register(conn(1)).expect("register");
        // Never-issued namespaced id.
        assert!(!pending.resolve(conn(1), &json!("s9999"), Ok(json!(1))));
        // Client-chosen (non-namespaced) id.
        assert!(!pending.resolve(conn(1), &json!("c1"), Ok(json!(1))));
    }

    #[test]
    fn register_enforces_the_per_connection_bound() {
        let pending = PendingPeerRequests::new(2);
        let _a = pending.register(conn(1)).expect("first");
        let _b = pending.register(conn(1)).expect("second");
        assert!(pending.register(conn(1)).is_none(), "third over the cap");
        // A different connection has its own budget.
        assert!(pending.register(conn(2)).is_some());
    }

    #[tokio::test]
    async fn drain_connection_resolves_pending_as_recv_error() {
        let pending = PendingPeerRequests::new(8);
        let (_id, rx) = pending.register(conn(1)).expect("register");
        let drained = pending.drain_connection(conn(1));
        assert_eq!(drained, 1);
        // The dropped sender wakes the receiver with an error → ConnectionGone.
        assert!(rx.await.is_err());
    }

    #[tokio::test]
    async fn noop_peer_is_no_transport() {
        let peer = NoopActionPeer;
        let err = peer
            .request(
                conn(1),
                "peer/ping",
                &json!({}),
                DEFAULT_PEER_REQUEST_TIMEOUT,
            )
            .await
            .expect_err("noop has no transport");
        assert!(matches!(err, PeerError::NoTransport));
    }

    // -- ConnectionPeer round-trip (per-impl mechanism) --------------------
    //
    // Exercises the real `request` path — `send_to` framing → `register` →
    // demux `resolve`, plus timeout / cancel / bound — without a live WS
    // socket: a `ConnectionRegistry` connection backed by an mpsc channel
    // stands in for the upgraded socket, and the test plays the read loop's
    // `resolve` directly. The lock-across-await invariant is exercised
    // implicitly (the request awaits while the test concurrently resolves).

    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    /// Register a stand-in connection; return the peer + the id + the
    /// outbound frame receiver + the socket's cancel token.
    fn wire_peer() -> (
        ConnectionPeer,
        ConnectionId,
        crate::ConnectionReceiver,
        CancellationToken,
        Arc<PendingPeerRequests>,
    ) {
        let registry = Arc::new(ConnectionRegistry::new());
        let pending = Arc::new(PendingPeerRequests::new(8));
        let (tx, rx) = crate::connection_channel(1 << 20);
        let signal = CancellationToken::new();
        let conn =
            registry.add_connection(tx, crate::ConnectionIdentity::default(), signal.clone());
        let peer = ConnectionPeer::new(registry, Arc::clone(&pending));
        (peer, conn.id, rx, signal, pending)
    }

    #[tokio::test]
    async fn request_round_trips_via_send_then_resolve() {
        let (peer, id, mut rx, _signal, pending) = wire_peer();
        let params = json!({ "nonce": 1 });

        let request_fut = peer.request(id, "peer/ping", &params, Duration::from_secs(5));
        let client_fut = async {
            // The outbound frame the peer sent over the socket's channel.
            let frame = rx.recv().await.expect("a framed request was sent");
            let v: Value = serde_json::from_str(frame.as_str()).expect("valid JSON frame");
            assert_eq!(v["jsonrpc"], "2.0");
            assert_eq!(v["method"], "peer/ping");
            assert_eq!(v["params"]["nonce"], 1);
            // Server-allocated namespaced id.
            assert_eq!(v["id"], json!("s1"));
            // Play the read loop: demux the client's reply.
            assert!(pending.resolve(
                id,
                &v["id"],
                Ok(json!({ "nonce": 1, "protocol_version": 1 })),
            ));
        };
        let (result, ()) = tokio::join!(request_fut, client_fut);
        assert_eq!(
            result.unwrap(),
            json!({ "nonce": 1, "protocol_version": 1 })
        );
    }

    #[tokio::test]
    async fn request_forwards_a_client_error_reply() {
        let (peer, id, mut rx, _signal, pending) = wire_peer();
        let params = json!({ "nonce": 1 });
        let request_fut = peer.request(id, "peer/ping", &params, Duration::from_secs(5));
        let client_fut = async {
            let frame = rx.recv().await.expect("frame");
            let v: Value = serde_json::from_str(frame.as_str()).unwrap();
            assert!(pending.resolve(id, &v["id"], Err(fuz_http::forbidden("no", Some("denied")))));
        };
        let (result, ()) = tokio::join!(request_fut, client_fut);
        match result {
            Err(PeerError::ClientError(je)) => {
                assert_eq!(je.data.unwrap()["reason"], "denied");
            }
            other => panic!("expected ClientError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn request_times_out_when_no_reply() {
        let (peer, id, _rx, _signal, _pending) = wire_peer();
        let err = peer
            .request(id, "peer/ping", &json!({}), Duration::from_millis(30))
            .await
            .expect_err("no reply within the deadline");
        assert!(matches!(err, PeerError::Timeout));
    }

    #[tokio::test]
    async fn request_is_connection_gone_when_socket_drains() {
        let (peer, id, mut rx, _signal, pending) = wire_peer();
        let params = json!({ "nonce": 1 });
        let request_fut = peer.request(id, "peer/ping", &params, Duration::from_secs(5));
        let client_fut = async {
            let _frame = rx.recv().await.expect("frame");
            // The socket tears down (close / revocation): the read loop drains
            // pending requests, dropping their one-shot senders. (A client
            // `cancel` deliberately does NOT abort the request — only teardown.)
            pending.drain_connection(id);
        };
        let (result, ()) = tokio::join!(request_fut, client_fut);
        assert!(matches!(result, Err(PeerError::ConnectionGone)));
    }

    #[tokio::test]
    async fn request_survives_a_client_cancel_on_the_socket() {
        // A client `cancel` message cancels the per-socket signal token; a
        // server-initiated request must NOT observe it (else one cancel would
        // permanently poison every later request on the socket). The request
        // still resolves normally through the demux.
        let (peer, id, mut rx, signal, pending) = wire_peer();
        let params = json!({ "nonce": 1 });
        let request_fut = peer.request(id, "peer/ping", &params, Duration::from_secs(5));
        let client_fut = async {
            let frame = rx.recv().await.expect("frame");
            let v: Value = serde_json::from_str(frame.as_str()).unwrap();
            // The socket's cancel token fires — must not abort the request.
            signal.cancel();
            assert!(pending.resolve(
                id,
                &v["id"],
                Ok(json!({ "nonce": 1, "protocol_version": 1 }))
            ));
        };
        let (result, ()) = tokio::join!(request_fut, client_fut);
        assert_eq!(
            result.unwrap(),
            json!({ "nonce": 1, "protocol_version": 1 })
        );
    }

    #[tokio::test]
    async fn request_is_connection_gone_for_an_unknown_socket() {
        // No connection registered → `is_registered` is false → ConnectionGone.
        let registry = Arc::new(ConnectionRegistry::new());
        let pending = Arc::new(PendingPeerRequests::new(8));
        let peer = ConnectionPeer::new(registry, pending);
        let err = peer
            .request(
                conn(999),
                "peer/ping",
                &json!({}),
                DEFAULT_PEER_REQUEST_TIMEOUT,
            )
            .await
            .expect_err("unknown socket");
        assert!(matches!(err, PeerError::ConnectionGone));
    }

    #[tokio::test]
    async fn request_is_too_many_in_flight_at_the_bound() {
        let registry = Arc::new(ConnectionRegistry::new());
        let pending = Arc::new(PendingPeerRequests::new(1));
        let (tx, _rx) = crate::connection_channel(1 << 20);
        let conn = registry.add_connection(
            tx,
            crate::ConnectionIdentity::default(),
            CancellationToken::new(),
        );
        let peer = ConnectionPeer::new(Arc::clone(&registry), Arc::clone(&pending));
        // Hold the single slot so the peer's own `register` overflows.
        let _held = pending.register(conn.id).expect("first slot");
        let err = peer
            .request(
                conn.id,
                "peer/ping",
                &json!({}),
                DEFAULT_PEER_REQUEST_TIMEOUT,
            )
            .await
            .expect_err("bound hit");
        assert!(matches!(err, PeerError::TooManyInFlight));
    }
}
