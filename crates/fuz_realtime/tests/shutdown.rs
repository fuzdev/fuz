//! The shutdown close-all — `fuz_http::ShutdownCloser` on the realtime
//! registries and [`RealtimeCloser`], and the whole of it through the real
//! `fuz_http::serve_with_shutdown`.
//!
//! Registry level: `close_all_connections` closes pending and admitted entries
//! and counts them, every registration after it is born closed and refused
//! as shutting down (a revocation's refusal stays a revocation), and
//! `wait_closed` resolves only once every registration is gone — at once
//! when there were none.
//!
//! Server level, each server on its own runtime in its own thread so the
//! process exit that follows `serve_with_shutdown` in production can be
//! reproduced by dropping that runtime the moment serve returns: an open SSE
//! stream ends cleanly and no longer holds the drain to its timeout; an open
//! WebSocket reads a 1001 close frame, not a reset; and an upgrade still in
//! flight when the token fires — registered pending, or not yet registered —
//! is refused with 1001.

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::http::header;
use axum::response::Response;
use axum::routing::get;
use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt};
use fuz_auth::ConnectionCloseTarget;
use fuz_auth::ConnectionCloser;
use fuz_http::{CancellationToken, ShutdownCloser, WaitClosedFuture};
use fuz_realtime::ConnectionIdentity;
use fuz_realtime::ws_endpoint::WsDispatchInput;
use fuz_realtime::{
    CloseReason, ConnectionGuard, ConnectionRegistry, NotAdmitted, PendingPeerRequests,
    RealtimeCloser, SSE_CONNECTED_COMMENT, SseRegistry, SseSubscription, UpgradeRefusal,
    WS_CLOSE_GOING_AWAY, WS_CLOSE_GOING_AWAY_REASON, WsDispatchFn, refuse_upgrade,
    run_ws_connection,
};
use tokio::sync::Notify;

mod common;

/// Generous on purpose: every server-level assertion that serve returned
/// promptly is "well under this", never a tight bound.
const DRAIN: Duration = Duration::from_secs(10);

/// What "well under the drain" means for the timing assertions.
const PROMPT: Duration = Duration::from_secs(3);

fn account() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

/// Register a WS connection pending, returning it with its receiver.
fn ws_pending(
    registry: &Arc<ConnectionRegistry>,
) -> (
    fuz_realtime::PendingConnection,
    CancellationToken,
    fuz_realtime::ConnectionReceiver,
) {
    let (tx, rx) = fuz_realtime::connection_channel(1 << 20);
    let signal = CancellationToken::new();
    let pending = registry.register_pending(
        tx,
        ConnectionIdentity {
            account_id: Some(account()),
            ..ConnectionIdentity::default()
        },
        signal.clone(),
    );
    (pending, signal, rx)
}

// -- ConnectionRegistry --------------------------------------------------------

/// The close-all closes pending and admitted connections alike, counts them,
/// marks the admitted one so its loop closes with 1001, and refuses the
/// pending one as shutting down. A second call closes nothing.
#[tokio::test]
async fn ws_close_all_closes_pending_and_admitted() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (admitted_tx, mut admitted_rx) = fuz_realtime::connection_channel(1 << 20);
    let admitted_signal = CancellationToken::new();
    let admitted = registry.add_connection(
        admitted_tx,
        ConnectionIdentity {
            account_id: Some(account()),
            ..ConnectionIdentity::default()
        },
        admitted_signal.clone(),
    );
    let (pending, pending_signal, mut pending_rx) = ws_pending(&registry);

    assert_eq!(registry.close_all_connections(), 2);
    assert_eq!(registry.connection_count(), 0);
    assert_eq!(registry.pending_connection_count(), 0);
    assert_eq!(
        admitted.close_reason.get(),
        Some(&CloseReason::ShuttingDown)
    );
    assert!(admitted_signal.is_cancelled());
    assert!(admitted_rx.recv().await.is_none(), "the sender was dropped");
    assert!(pending_signal.is_cancelled());
    assert!(pending_rx.recv().await.is_none());
    assert_eq!(
        registry.admit(pending).unwrap_err(),
        NotAdmitted::ShuttingDown
    );
    assert_eq!(registry.close_all_connections(), 0, "idempotent");
}

/// Once closing, every registration is born closed: never counted, its
/// signal cancelled, its sender dropped, refused or closed as shutting down.
/// This is what an upgrade that answered 101 before the close-all but
/// registers after it meets.
#[tokio::test]
async fn ws_registrations_after_the_close_all_are_born_closed() {
    let registry = Arc::new(ConnectionRegistry::new());
    assert_eq!(registry.close_all_connections(), 0);

    let (pending, signal, mut rx) = ws_pending(&registry);
    assert_eq!(registry.pending_connection_count(), 0, "never inserted");
    assert!(signal.is_cancelled());
    assert!(rx.recv().await.is_none());
    assert_eq!(
        registry.admit(pending).unwrap_err(),
        NotAdmitted::ShuttingDown
    );

    let (tx, mut rx) = fuz_realtime::connection_channel(1 << 20);
    let signal = CancellationToken::new();
    let conn = registry.add_connection(
        tx,
        ConnectionIdentity {
            account_id: Some(account()),
            ..ConnectionIdentity::default()
        },
        signal.clone(),
    );
    assert_eq!(registry.connection_count(), 0, "never inserted");
    assert_eq!(conn.close_reason.get(), Some(&CloseReason::ShuttingDown));
    assert!(signal.is_cancelled());
    assert!(rx.recv().await.is_none());
}

/// A pending registration a revocation closed before the shutdown is still
/// refused as revoked — the client must not take a 4001 for a 1001 or the
/// reverse.
#[tokio::test]
async fn ws_a_revoked_pending_registration_stays_revoked_after_the_close_all() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (tx, _rx) = fuz_realtime::connection_channel(1 << 20);
    let account_id = uuid::Uuid::new_v4();
    let pending = registry.register_pending(
        tx,
        ConnectionIdentity {
            account_id: Some(account_id),
            ..ConnectionIdentity::default()
        },
        CancellationToken::new(),
    );
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account_id)),
        1
    );
    assert_eq!(registry.close_all_connections(), 0);
    assert_eq!(registry.admit(pending).unwrap_err(), NotAdmitted::Revoked);
}

/// `PendingConnection::closed` reads a closed registration's refusal without
/// the lock — what the upgrade checks before its database re-check: none
/// while it is live, shutting down once the close-all closed it or it was
/// born closed, revoked once a revocation closed it.
#[test]
fn ws_a_pending_registration_reports_why_it_closed() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (live, _, _rx) = ws_pending(&registry);
    assert_eq!(live.closed(), None);

    let (tx, _revoked_rx) = fuz_realtime::connection_channel(1 << 20);
    let account_id = account();
    let revoked = registry.register_pending(
        tx,
        ConnectionIdentity {
            account_id: Some(account_id),
            ..ConnectionIdentity::default()
        },
        CancellationToken::new(),
    );
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account_id)),
        1
    );
    assert_eq!(revoked.closed(), Some(NotAdmitted::Revoked));

    registry.close_all_connections();
    assert_eq!(live.closed(), Some(NotAdmitted::ShuttingDown));
    assert_eq!(
        revoked.closed(),
        Some(NotAdmitted::Revoked),
        "stays revoked"
    );
    let (born_closed, _, _born_rx) = ws_pending(&registry);
    assert_eq!(born_closed.closed(), Some(NotAdmitted::ShuttingDown));
}

/// With nothing registered, the wait resolves as soon as the close-all ran.
#[tokio::test]
async fn ws_wait_closed_resolves_at_once_when_empty() {
    let registry = ConnectionRegistry::new();
    registry.close_all_connections();
    assert!(registry.wait_closed().now_or_never().is_some());
}

/// The wait holds while anything that will write a close is alive — each
/// alone: an admitted connection's guard, a pending registration, an upgrade
/// hold — and resolves once it is gone.
#[tokio::test]
async fn ws_wait_closed_waits_for_each_guard_pending_and_hold() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (tx, _rx) = fuz_realtime::connection_channel(1 << 20);
    let conn = registry.add_connection(
        tx,
        ConnectionIdentity {
            account_id: Some(account()),
            ..ConnectionIdentity::default()
        },
        CancellationToken::new(),
    );
    let guard = ConnectionGuard::new(Arc::clone(&registry), conn.id);
    registry.close_all_connections();
    assert!(
        registry.wait_closed().now_or_never().is_none(),
        "an admitted connection's guard holds the wait"
    );
    drop(guard);
    assert!(registry.wait_closed().now_or_never().is_some());

    let registry = Arc::new(ConnectionRegistry::new());
    let (pending, _signal, _rx) = ws_pending(&registry);
    registry.close_all_connections();
    assert!(
        registry.wait_closed().now_or_never().is_none(),
        "a pending registration holds the wait"
    );
    drop(pending);
    assert!(registry.wait_closed().now_or_never().is_some());

    let registry = ConnectionRegistry::new();
    let hold = registry.hold_upgrade();
    registry.close_all_connections();
    assert!(
        registry.wait_closed().now_or_never().is_none(),
        "an upgrade hold holds the wait"
    );
    drop(hold);
    assert!(registry.wait_closed().now_or_never().is_some());
}

// -- SseRegistry ---------------------------------------------------------------

/// The close-all ends every stream — an admitted one yields its connect
/// comment and then ends — and refuses a pending one as shutting down.
#[tokio::test]
async fn sse_close_all_ends_admitted_and_refuses_pending() {
    let registry = Arc::new(SseRegistry::new());
    let mut open = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription::default(),
    ));
    let pending = registry.subscribe_pending(SseSubscription::default());

    assert_eq!(registry.close_all_connections(), 2);
    assert_eq!(registry.count(), 0);
    assert_eq!(registry.pending_count(), 0);
    assert_eq!(
        open.next().await.unwrap().unwrap(),
        SSE_CONNECTED_COMMENT,
        "the stream opened before it closed"
    );
    assert!(open.next().await.is_none(), "and then ended");
    assert!(matches!(
        registry.admit(pending),
        Err(NotAdmitted::ShuttingDown)
    ));
    assert_eq!(registry.close_all_connections(), 0, "idempotent");
}

/// Once closing, a registration is born closed: it is not counted, and it is
/// refused as shutting down.
#[tokio::test]
async fn sse_registrations_after_the_close_all_are_born_closed() {
    let registry = Arc::new(SseRegistry::new());
    registry.close_all_connections();

    let pending = registry.subscribe_pending(SseSubscription::default());
    assert_eq!(registry.pending_count(), 0);
    assert!(matches!(
        registry.admit(pending),
        Err(NotAdmitted::ShuttingDown)
    ));
    assert_eq!(registry.count(), 0);
}

/// `PendingSseStream::closed` reads a closed registration's refusal without
/// the lock — what the audit route checks before its database reads, and
/// again when one fails: none while it is live, revoked once a revocation
/// closed it, shutting down once the close-all closed it or it was born
/// closed. A revoked one reads as shutting down after the close-all, as
/// `admit` refuses it — the route's answer is the same either way.
#[test]
fn sse_a_pending_stream_reports_why_it_closed() {
    let registry = Arc::new(SseRegistry::new());
    let live = registry.subscribe_pending(SseSubscription::default());
    assert_eq!(live.closed(), None);

    let account_id = account();
    let revoked = registry.subscribe_pending(SseSubscription {
        identity: ConnectionIdentity {
            account_id: Some(account_id),
            ..ConnectionIdentity::default()
        },
        ..SseSubscription::default()
    });
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account_id)),
        1
    );
    assert_eq!(revoked.closed(), Some(NotAdmitted::Revoked));
    assert_eq!(live.closed(), None, "the revocation closed only its own");

    registry.close_all_connections();
    assert_eq!(live.closed(), Some(NotAdmitted::ShuttingDown));
    assert_eq!(revoked.closed(), Some(NotAdmitted::ShuttingDown));
    let born_closed = registry.subscribe_pending(SseSubscription::default());
    assert_eq!(born_closed.closed(), Some(NotAdmitted::ShuttingDown));
}

/// A pending stream revoked before any shutdown is refused as revoked.
#[tokio::test]
async fn sse_a_revoked_pending_stream_is_refused_as_revoked() {
    let registry = Arc::new(SseRegistry::new());
    let account_id = uuid::Uuid::new_v4();
    let pending = registry.subscribe_pending(SseSubscription {
        identity: ConnectionIdentity {
            account_id: Some(account_id),
            ..ConnectionIdentity::default()
        },
        ..SseSubscription::default()
    });
    assert_eq!(
        registry.close_connections(&ConnectionCloseTarget::Account(account_id)),
        1
    );
    assert!(matches!(registry.admit(pending), Err(NotAdmitted::Revoked)));
}

/// The wait holds while a stream body or a pending registration is alive,
/// and resolves at once when there are none.
#[tokio::test]
async fn sse_wait_closed_waits_for_every_body_and_pending() {
    let empty = SseRegistry::new();
    empty.close_all_connections();
    assert!(empty.wait_closed().now_or_never().is_some());

    let registry = Arc::new(SseRegistry::new());
    let mut body = Box::pin(common::subscribe_admitted(
        &registry,
        SseSubscription::default(),
    ));
    let pending = registry.subscribe_pending(SseSubscription::default());
    registry.close_all_connections();

    assert!(registry.wait_closed().now_or_never().is_none());
    drop(pending);
    assert!(
        registry.wait_closed().now_or_never().is_none(),
        "the body has not ended"
    );
    while body.next().await.is_some() {}
    assert!(
        registry.wait_closed().now_or_never().is_some(),
        "an ended body releases the wait"
    );
}

// -- RealtimeCloser -----------------------------------------------------------

/// The fan-out closes both registries, sums them, and waits for both.
#[tokio::test]
async fn realtime_closer_closes_and_waits_for_both_transports() {
    let ws = Arc::new(ConnectionRegistry::new());
    let sse = Arc::new(SseRegistry::new());
    let closer = RealtimeCloser::connection_closer(&ws, &sse);
    let (tx, _rx) = fuz_realtime::connection_channel(1 << 20);
    let conn = ws.add_connection(
        tx,
        ConnectionIdentity {
            account_id: Some(account()),
            ..ConnectionIdentity::default()
        },
        CancellationToken::new(),
    );
    let guard = ConnectionGuard::new(Arc::clone(&ws), conn.id);
    let body = common::subscribe_admitted(&sse, SseSubscription::default());

    assert_eq!(closer.close_all_connections(), 2);
    assert_eq!(ws.connection_count() + sse.count(), 0);
    assert!(closer.wait_closed().now_or_never().is_none());
    drop(guard);
    assert!(
        closer.wait_closed().now_or_never().is_none(),
        "the SSE body is still alive"
    );
    drop(body);
    assert!(closer.wait_closed().now_or_never().is_some());
}

// -- through serve_with_shutdown -----------------------------------------------

/// A [`ShutdownCloser`] over `inner` that announces each close-all, so a test
/// can act between the close and the wait.
struct Observed {
    inner: Arc<dyn ShutdownCloser>,
    closed_tx: std_mpsc::Sender<usize>,
}

impl ShutdownCloser for Observed {
    fn close_all_connections(&self) -> usize {
        let closed = self.inner.close_all_connections();
        let _ = self.closed_tx.send(closed);
        closed
    }

    fn wait_closed(&self) -> WaitClosedFuture<'_> {
        self.inner.wait_closed()
    }
}

struct Server {
    addr: SocketAddr,
    token: CancellationToken,
    /// Each close-all's count.
    closed_rx: std_mpsc::Receiver<usize>,
    /// The instant `serve_with_shutdown` returned; the server runtime is
    /// dropped right after, as a process would exit.
    returned_rx: std_mpsc::Receiver<Instant>,
    thread: std::thread::JoinHandle<()>,
}

impl Server {
    /// Fire the token; return how long serve took to return after it.
    fn shut_down(self) -> Duration {
        let fired = Instant::now();
        self.token.cancel();
        let returned = self
            .returned_rx
            .recv_timeout(DRAIN * 2)
            .expect("serve returns");
        self.thread.join().expect("server thread");
        returned.saturating_duration_since(fired)
    }
}

/// `router` composed by `fuz_http::compose_stack` as one checked group — the
/// only shape `serve_with_shutdown` serves. The requests here send no
/// `Origin` and no body, so the gates pass them all.
fn gated(router: axum::Router) -> fuz_http::GatedRouter {
    let cap = fuz_http::BodyCap::Bytes(fuz_http::DEFAULT_BODY_LIMIT_BYTES);
    fuz_http::compose_stack(
        [fuz_http::RouteGroup::new("test", router, cap)],
        fuz_http::RouteGroup::new("fallback", axum::Router::new(), cap),
        &fuz_http::StackOptions::new(
            fuz_http::AllowedOrigins::parse("https://app.example").unwrap(),
            Arc::new(Vec::new()),
        ),
    )
}

/// Run `router` under `serve_with_shutdown` with `closer` on a runtime of its
/// own, dropped (no grace) the moment serve returns.
fn start(router: axum::Router, closer: Arc<dyn ShutdownCloser>) -> Server {
    let token = CancellationToken::new();
    let (addr_tx, addr_rx) = std_mpsc::channel();
    let (closed_tx, closed_rx) = std_mpsc::channel();
    let (returned_tx, returned_rx) = std_mpsc::channel();
    let server_token = token.clone();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            addr_tx.send(listener.local_addr().unwrap()).unwrap();
            let closer = Observed {
                inner: closer,
                closed_tx,
            };
            let served = fuz_http::serve_with_shutdown(
                listener,
                gated(router),
                server_token,
                &closer,
                DRAIN,
            )
            .await;
            returned_tx.send(Instant::now()).unwrap();
            served.unwrap();
        });
        runtime.shutdown_timeout(Duration::ZERO);
    });
    Server {
        addr: addr_rx.recv().unwrap(),
        token,
        closed_rx,
        returned_rx,
        thread,
    }
}

fn sse_router(registry: Arc<SseRegistry>) -> axum::Router {
    axum::Router::new().route(
        "/sse",
        get(move || {
            let registry = Arc::clone(&registry);
            async move {
                // a registration the shutdown refuses answers the connect
                // comment alone, as the audit route does
                let body = registry
                    .admit(registry.subscribe_pending(SseSubscription::default()))
                    .map_or_else(|_| Body::from(SSE_CONNECTED_COMMENT), Body::from_stream);
                Response::builder()
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(body)
                    .unwrap()
            }
        }),
    )
}

/// Open `/sse` and read through the connect comment.
fn sse_open(addr: SocketAddr) -> (TcpStream, Vec<u8>) {
    sse_read_open(TcpStream::connect(addr).unwrap(), addr)
}

/// Request `/sse` on `stream`, connected to `addr`, and read through the
/// connect comment.
fn sse_read_open(mut stream: TcpStream, addr: SocketAddr) -> (TcpStream, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream, "GET /sse HTTP/1.1\r\nHost: {addr}\r\n\r\n").unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains(SSE_CONNECTED_COMMENT) {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "connection ended before the connect comment");
        seen.extend_from_slice(&buf[..n]);
    }
    assert!(seen.starts_with(b"HTTP/1.1 200"));
    (stream, seen)
}

/// An open stream ends cleanly — the chunked body's terminator, then EOF —
/// and serve returns well under the drain instead of waiting it out.
#[test]
fn an_open_sse_stream_ends_cleanly_and_does_not_hold_the_drain() {
    let registry = Arc::new(SseRegistry::new());
    let server = start(
        sse_router(Arc::clone(&registry)),
        Arc::<SseRegistry>::clone(&registry),
    );
    let (mut client, mut seen) = sse_open(server.addr);
    assert_eq!(registry.count(), 1);

    let took = server.shut_down();
    assert!(took < PROMPT, "serve returned after {took:?}");

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.read_to_end(&mut seen).expect("EOF, not a reset");
    assert!(
        String::from_utf8_lossy(&seen).ends_with("0\r\n\r\n"),
        "the chunked body ended cleanly: {:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// A stream whose client stopped reading — its socket's buffers full, so
/// hyper never polls the body again and never sees it end. Its queue stops
/// growing at its budget: the frame that does not fit ends the registration.
/// The connection itself stays open, unpolled — the write-progress deadline
/// that would end it is far longer than this test — until the shutdown cuts
/// it once a close-timeout window passes with nothing written: serve returns
/// well under the drain, and the registry's wait resolves because the cut
/// dropped the body holding its guard.
#[test]
fn an_sse_stream_whose_client_stopped_reading_is_cut_not_waited_out() {
    let registry = Arc::new(SseRegistry::new());
    let server = start(
        sse_router(Arc::clone(&registry)),
        Arc::<SseRegistry>::clone(&registry),
    );
    // a small receive buffer, so the server's writes stall sooner
    let client = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.set_recv_buffer_size(4096).unwrap();
            socket
                .connect(server.addr)
                .await
                .unwrap()
                .into_std()
                .unwrap()
        });
    client.set_nonblocking(false).unwrap();
    let (client, _seen) = sse_read_open(client, server.addr);
    assert_eq!(registry.count(), 1);

    // stop reading. One frame far larger than the socket's buffers — taken
    // into the empty queue whatever its size — stalls the body's write
    let stalling = format!("data: {}\n\n", "x".repeat(16 * 1024 * 1024));
    assert_eq!(registry.broadcast(&stalling), 1);
    std::thread::sleep(Duration::from_millis(300));

    // nothing takes a frame now, so the queue fills to its budget and stops
    let frame = format!("data: {}\n\n", "x".repeat(64 * 1024));
    let offered = 256;
    let queued = (0..offered)
        .take_while(|_| registry.broadcast(&frame) == 1)
        .count();
    assert!(
        queued > 0 && queued < offered,
        "a stream nobody reads stops taking frames at its budget, took {queued}"
    );
    assert_eq!(registry.count(), 0, "the overflow ended its registration");
    assert_eq!(registry.broadcast(&frame), 0, "and nothing more is queued");

    let took = server.shut_down();
    assert!(
        took >= fuz_http::SHUTDOWN_CLOSE_TIMEOUT && took < PROMPT,
        "serve returned after {took:?}"
    );
    assert_eq!(registry.count(), 0);
    assert!(
        registry.wait_closed().now_or_never().is_some(),
        "the cut released the stream's registration"
    );
    drop(client);
}

fn noop_dispatch() -> WsDispatchFn {
    Arc::new(
        |_input: WsDispatchInput<'_>| -> BoxFuture<'_, Option<String>> { Box::pin(async { None }) },
    )
}

/// Where a gated upgrade waits for the test's go-ahead.
#[derive(Clone, Copy)]
enum Gate {
    /// No gate: register and admit at once, then run the loop.
    None,
    /// Register pending, then wait — the close-all finds the pending entry.
    AfterRegister,
    /// Wait before registering — the registration comes after the close-all.
    BeforeRegister,
}

/// `/ws`: the two-phase admission an upgrade handler runs (minus the
/// credential), with an optional gate, a refusal closed by
/// [`refuse_upgrade`], and an upgrade hold taken before the handshake.
/// `reached` is told when the upgraded task reaches the gate.
fn ws_router(
    registry: Arc<ConnectionRegistry>,
    gate: Gate,
    go: Arc<Notify>,
    reached: std_mpsc::Sender<()>,
) -> axum::Router {
    axum::Router::new().route(
        "/ws",
        get(move |ws: WebSocketUpgrade| {
            let registry = Arc::clone(&registry);
            let go = Arc::clone(&go);
            let reached = reached.clone();
            async move {
                let hold = registry.hold_upgrade();
                ws.on_upgrade(move |socket| async move {
                    let _hold = hold;
                    if matches!(gate, Gate::BeforeRegister) {
                        reached.send(()).unwrap();
                        go.notified().await;
                    }
                    let (notify_tx, notify_rx) = fuz_realtime::connection_channel(1 << 20);
                    let pending = registry.register_pending(
                        notify_tx,
                        ConnectionIdentity {
                            account_id: Some(account()),
                            ..ConnectionIdentity::default()
                        },
                        CancellationToken::new(),
                    );
                    if matches!(gate, Gate::AfterRegister) {
                        reached.send(()).unwrap();
                        go.notified().await;
                    }
                    let (conn, _guard) = match registry.admit(pending) {
                        Ok(admitted) => admitted,
                        Err(not_admitted) => {
                            refuse_upgrade(socket, UpgradeRefusal::from(not_admitted)).await;
                            return;
                        }
                    };
                    if matches!(gate, Gate::None) {
                        reached.send(()).unwrap();
                    }
                    run_ws_connection(
                        socket,
                        registry,
                        conn,
                        notify_rx,
                        Arc::new(PendingPeerRequests::new(8)),
                        noop_dispatch(),
                        fuz_realtime::WsLoopOptions::default(),
                    )
                    .await;
                })
            }
        }),
    )
}

/// Upgrade `/ws` and return the client socket once the 101 is read.
fn ws_open(addr: SocketAddr) -> tungstenite::WebSocket<TcpStream> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET /ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"), "{head:?}");
    tungstenite::WebSocket::from_raw_socket(stream, tungstenite::protocol::Role::Client, None)
}

/// Read until the server's close frame; panics on a reset or a timeout.
fn read_close(ws: &mut tungstenite::WebSocket<TcpStream>) -> (u16, String) {
    loop {
        match ws.read() {
            Ok(tungstenite::Message::Close(Some(frame))) => {
                return (u16::from(frame.code), frame.reason.to_string());
            }
            Ok(tungstenite::Message::Close(None)) => panic!("close frame carried no code"),
            Ok(_) => {}
            Err(e) => panic!("no close frame (a browser would see 1006): {e:?}"),
        }
    }
}

fn going_away() -> (u16, String) {
    (WS_CLOSE_GOING_AWAY, WS_CLOSE_GOING_AWAY_REASON.to_owned())
}

/// An open WebSocket gets a 1001 close frame even though the server's
/// runtime is dropped the moment serve returns — serve waited for the loop
/// to write it.
#[test]
fn an_open_websocket_gets_a_1001_close_frame_not_a_reset() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (reached_tx, reached_rx) = std_mpsc::channel();
    let server = start(
        ws_router(
            Arc::clone(&registry),
            Gate::None,
            Arc::new(Notify::new()),
            reached_tx,
        ),
        Arc::<ConnectionRegistry>::clone(&registry),
    );
    let mut ws = ws_open(server.addr);
    reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    let took = server.shut_down();
    assert!(took < PROMPT, "serve returned after {took:?}");
    assert_eq!(read_close(&mut ws), going_away());
}

/// An upgrade that registered pending before the token fired, and reaches
/// admission after the close-all, is refused with 1001 — not 4001.
#[test]
fn a_pending_upgrade_at_shutdown_is_refused_with_1001() {
    gated_upgrade_is_refused_with_1001(Gate::AfterRegister, 1);
}

/// An upgrade that answered 101 before the token fired but registers after
/// the close-all is born closed and refused with 1001 — it never slips past
/// to run a loop the shutdown does not know about.
#[test]
fn an_upgrade_registering_after_the_close_all_is_refused_with_1001() {
    gated_upgrade_is_refused_with_1001(Gate::BeforeRegister, 0);
}

fn gated_upgrade_is_refused_with_1001(gate: Gate, expected_closed: usize) {
    let registry = Arc::new(ConnectionRegistry::new());
    let go = Arc::new(Notify::new());
    let (reached_tx, reached_rx) = std_mpsc::channel();
    let server = start(
        ws_router(Arc::clone(&registry), gate, Arc::clone(&go), reached_tx),
        Arc::<ConnectionRegistry>::clone(&registry),
    );
    let mut ws = ws_open(server.addr);
    reached_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    let fired = Instant::now();
    server.token.cancel();
    let closed = server
        .closed_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the token fires the close-all");
    assert_eq!(closed, expected_closed);
    // only now does the upgrade go on to admission
    go.notify_one();

    let returned = server
        .returned_rx
        .recv_timeout(DRAIN * 2)
        .expect("serve returns");
    server.thread.join().expect("server thread");
    let took = returned.saturating_duration_since(fired);
    assert!(took < PROMPT, "serve returned after {took:?}");
    assert_eq!(read_close(&mut ws), going_away());
}

/// An admission racing the close-all is refused as shutting down, never as
/// revoked: the close-all records each entry's reason under the same write
/// lock that removes it, so an `admit` that finds its entry gone already
/// reads `ShuttingDown`. Racy by nature — several threads admit while the
/// close-all runs, over enough rounds to land in the window.
#[test]
fn ws_an_admission_racing_the_close_all_is_never_refused_as_revoked() {
    for round in 0..200 {
        let registry = Arc::new(ConnectionRegistry::new());
        let racers: Vec<_> = (0..4)
            .map(|_| {
                let registry = Arc::clone(&registry);
                std::thread::spawn(move || {
                    let mut admitted = Vec::new();
                    for _ in 0..200 {
                        let (pending, signal, _rx) = ws_pending(&registry);
                        match registry.admit(pending) {
                            Ok((_conn, guard)) => admitted.push((signal, guard)),
                            Err(NotAdmitted::ShuttingDown) => {}
                            Err(NotAdmitted::Revoked | NotAdmitted::PermissionRevoked) => {
                                panic!("round {round}: a shutdown refusal read as a revocation")
                            }
                        }
                    }
                    admitted
                })
            })
            .collect();
        std::thread::sleep(Duration::from_micros(200));
        registry.close_all_connections();
        for racer in racers {
            for (signal, _guard) in racer.join().unwrap() {
                assert!(
                    signal.is_cancelled(),
                    "round {round}: an admitted connection outlived the close-all"
                );
            }
        }
        assert_eq!(
            registry.connection_count() + registry.pending_connection_count(),
            0
        );
    }
}
