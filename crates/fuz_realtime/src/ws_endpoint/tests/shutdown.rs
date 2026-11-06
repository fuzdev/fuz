//! Pins the loop's side of the shutdown close-all
//! (`ConnectionRegistry::close_all_connections`): a running loop discards
//! what was queued and closes with 1001, the registry's `wait_closed`
//! resolves only once the loop has written that close, and the loop's
//! writes from the fire on — one already blocked, the close — share one
//! bound, so a client that stopped reading cannot hold the shutdown.
//! Drives
//! [`run_ws_loop`] over in-memory channels standing in for the socket.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Message;
use futures::FutureExt;
use futures::channel::mpsc;
use futures_util::{Sink, StreamExt};
use fuz_http::ShutdownCloser;
use tokio_util::sync::CancellationToken;

use crate::connection_registry::{ConnectionGuard, ConnectionRegistry};
use crate::outbound_queue::Push;
use crate::peer::PendingPeerRequests;
use crate::ws_close_codes::{WS_CLOSE_GOING_AWAY, WS_CLOSE_GOING_AWAY_REASON};
use crate::ws_endpoint::{SHUTDOWN_CLOSE_TIMEOUT, WsDispatchFn, run_ws_loop};

fn unreachable_dispatch() -> WsDispatchFn {
    Arc::new(|_| Box::pin(async { panic!("no request is sent") }))
}

/// Register a connection one-step and spawn its loop over `server_tx`,
/// holding the [`ConnectionGuard`] until the loop returns — as an upgrade
/// handler does. Returns the connection id, the client's inbound sender
/// (kept so the loop's read never ends), and the loop task.
fn spawn_loop<S>(
    registry: &Arc<ConnectionRegistry>,
    server_tx: S,
) -> (
    crate::connection::ConnectionId,
    mpsc::UnboundedSender<Result<Message, axum::Error>>,
    tokio::task::JoinHandle<()>,
)
where
    S: Sink<Message> + Unpin + Send + 'static,
{
    spawn_loop_for(registry, server_tx, None)
}

/// [`spawn_loop`] for a connection owned by `account`, so a test can
/// revoke it.
fn spawn_loop_for<S>(
    registry: &Arc<ConnectionRegistry>,
    server_tx: S,
    account: Option<uuid::Uuid>,
) -> (
    crate::connection::ConnectionId,
    mpsc::UnboundedSender<Result<Message, axum::Error>>,
    tokio::task::JoinHandle<()>,
)
where
    S: Sink<Message> + Unpin + Send + 'static,
{
    let (notify_tx, notify_rx) = crate::connection_channel(1 << 20);
    let conn = registry.add_connection(
        notify_tx,
        crate::ConnectionIdentity {
            account_id: account,
            ..crate::ConnectionIdentity::default()
        },
        CancellationToken::new(),
    );
    let id = conn.id;
    let guard = ConnectionGuard::new(Arc::clone(registry), id);
    let (client_tx, server_rx) = mpsc::unbounded();
    let registry = Arc::clone(registry);
    let task = tokio::spawn(async move {
        run_ws_loop(
            server_tx,
            server_rx,
            registry,
            conn,
            notify_rx,
            Arc::new(PendingPeerRequests::new(8)),
            unreachable_dispatch(),
            crate::ws_endpoint::WsLoopOptions::default(),
        )
        .await;
        drop(guard);
    });
    (id, client_tx, task)
}

fn assert_going_away(frame: Option<&Message>) {
    match frame {
        Some(Message::Close(Some(frame))) => {
            assert_eq!(frame.code, WS_CLOSE_GOING_AWAY);
            assert_eq!(frame.reason.as_str(), WS_CLOSE_GOING_AWAY_REASON);
        }
        other => panic!("expected a 1001 close frame, got {other:?}"),
    }
}

/// The close-all closes a running loop with 1001 and nothing else: the
/// frames still queued for it are discarded with the close, not written
/// ahead of it.
#[tokio::test]
async fn a_running_loop_discards_its_queue_and_closes_with_1001() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (server_tx, client_rx) = mpsc::unbounded();
    let (id, _client_tx, task) = spawn_loop(&registry, server_tx);
    assert!(registry.send_to(id, "queued"));
    assert_eq!(registry.close_all_connections(), 1);

    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the loop exits")
        .expect("loop task");
    let frames: Vec<Message> = client_rx.collect().await;
    match frames.as_slice() {
        [close] => assert_going_away(Some(close)),
        other => panic!("expected only a 1001 close, got {other:?}"),
    }
}

/// `wait_closed` resolves only once the loop has written its close frame
/// — not when the close-all empties the map, which happens at once, nor
/// when the loop removes its entry, which it does before the write. On a
/// single-threaded runtime the loop has not run at all when the close-all
/// returns, so a wait that resolved early would find no frame written.
#[tokio::test(flavor = "current_thread")]
async fn wait_closed_resolves_after_the_loop_wrote_its_close() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (server_tx, mut client_rx) = mpsc::unbounded();
    let (_id, _client_tx, _task) = spawn_loop(&registry, server_tx);
    assert_eq!(registry.close_all_connections(), 1);
    assert_eq!(registry.connection_count(), 0, "the map empties at once");
    assert!(
        registry.wait_closed().now_or_never().is_none(),
        "the loop has not closed yet"
    );

    tokio::time::timeout(Duration::from_secs(5), registry.wait_closed())
        .await
        .expect("the wait resolves once the loop is done");
    let written = client_rx.try_next().expect("a frame was already written");
    assert_going_away(written.as_ref());
}

/// The 1001 write is bounded: a client whose send buffer is full — it
/// stopped reading — cannot hold the loop, and so the shutdown's wait,
/// open past [`SHUTDOWN_CLOSE_TIMEOUT`].
#[tokio::test(start_paused = true)]
async fn a_shutdown_close_write_that_cannot_proceed_is_bounded() {
    let registry = Arc::new(ConnectionRegistry::new());
    // one slot, filled now and never read — the close write pends
    let (mut server_tx, _client_rx) = mpsc::channel::<Message>(0);
    server_tx
        .try_send(Message::Text("unread".into()))
        .expect("fill the slot");
    let (_id, _client_tx, task) = spawn_loop(&registry, server_tx);
    let started = tokio::time::Instant::now();
    registry.close_all_connections();

    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("the bounded close lets the loop exit")
        .expect("loop task");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= SHUTDOWN_CLOSE_TIMEOUT,
        "the loop tried the write for its bound, exited after {elapsed:?}"
    );
    tokio::time::timeout(Duration::from_secs(1), registry.wait_closed())
        .await
        .expect("nothing else holds the wait");
}

/// Run `task` to completion under paused time and return how long it
/// took, failing past a minute — far beyond any bound under test.
async fn time_to_exit(task: tokio::task::JoinHandle<()>) -> Duration {
    let started = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(60), task)
        .await
        .expect("the shutdown bound lets the loop exit")
        .expect("loop task");
    started.elapsed()
}

/// A loop already blocked writing an ordinary frame when the shutdown
/// fires — its client stopped reading, the frame never accepted — is held
/// only to the shutdown bound, not to the drain timeout: the write in
/// progress is abandoned at the bound and the loop exits, with no close
/// frame after the cut-off write.
#[tokio::test(start_paused = true)]
async fn a_loop_blocked_mid_write_exits_at_the_shutdown_bound() {
    let registry = Arc::new(ConnectionRegistry::new());
    // one slot, never read: the first frame fills it, the second pends
    let (server_tx, _client_rx) = mpsc::channel::<Message>(0);
    let (id, _client_tx, task) = spawn_loop(&registry, server_tx);
    assert!(registry.send_to(id, "fills the one slot"));
    assert!(registry.send_to(id, "pends forever"));
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(
        !task.is_finished(),
        "the loop is blocked on the second write"
    );
    registry.close_all_connections();

    let elapsed = time_to_exit(task).await;
    assert!(
        elapsed <= SHUTDOWN_CLOSE_TIMEOUT,
        "the blocked write is cut off at the bound, took {elapsed:?}"
    );
    tokio::time::timeout(Duration::from_secs(1), registry.wait_closed())
        .await
        .expect("nothing else holds the wait");
}

/// The bound is one budget from the fire, not one per write: a client
/// draining slowly — the frame in progress taken well inside the bound —
/// still cannot stretch that write and the close past it. The close-all
/// discards what was queued behind the frame in progress.
#[tokio::test(start_paused = true)]
async fn the_write_in_progress_and_the_close_share_one_budget() {
    let registry = Arc::new(ConnectionRegistry::new());
    let (server_tx, mut client_rx) = mpsc::channel::<Message>(0);
    let (id, _client_tx, task) = spawn_loop(&registry, server_tx);
    // a write completes when the client takes its frame: the frame in
    // progress at 0.6 of the bound, and the close would at 1.2
    let per_frame = SHUTDOWN_CLOSE_TIMEOUT * 6 / 10;
    let reader = tokio::spawn(async move {
        let mut read = Vec::new();
        loop {
            tokio::time::sleep(per_frame).await;
            match client_rx.next().await {
                Some(frame) => read.push(frame),
                None => break read,
            }
        }
    });
    for i in 0..8 {
        assert!(registry.send_to(id, &format!("frame {i}")));
    }
    // the loop takes frame 0 and blocks writing it
    tokio::time::sleep(Duration::from_millis(10)).await;
    registry.close_all_connections();

    let elapsed = time_to_exit(task).await;
    assert_eq!(
        elapsed, SHUTDOWN_CLOSE_TIMEOUT,
        "the write in progress and the close share one bound"
    );
    let read = reader.await.expect("reader task");
    let texts: Vec<&str> = read
        .iter()
        .filter_map(|frame| match frame {
            Message::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        texts,
        ["frame 0"],
        "the frames queued behind the write in progress were discarded"
    );
}

/// Outside a shutdown a close frame's write is bounded too: a loop
/// revoked while its client is not reading gives the 4001 its own short
/// deadline, then drops the socket. A shutdown that fires meanwhile
/// leaves nothing waiting on it.
#[tokio::test(start_paused = true)]
async fn a_revoked_loop_blocked_on_its_close_exits_at_the_close_deadline() {
    use fuz_auth::ConnectionCloser;

    let registry = Arc::new(ConnectionRegistry::new());
    let account = uuid::Uuid::new_v4();
    let (mut server_tx, _client_rx) = mpsc::channel::<Message>(0);
    server_tx
        .try_send(Message::Text("unread".into()))
        .expect("fill the slot");
    let (_id, _client_tx, task) = spawn_loop_for(&registry, server_tx, Some(account));
    assert_eq!(
        registry.close_connections(&fuz_auth::ConnectionCloseTarget::Account(account)),
        1
    );

    let elapsed = time_to_exit(task).await;
    assert_eq!(
        elapsed,
        crate::ws_endpoint::WS_CLOSE_WRITE_TIMEOUT,
        "the 4001 write is given its deadline and no longer"
    );
    registry.close_all_connections();
    tokio::time::timeout(Duration::from_secs(1), registry.wait_closed())
        .await
        .expect("nothing else holds the wait");
}

/// A sink that takes every frame it is offered and never finishes
/// flushing — a socket whose client stopped reading, its send buffer
/// full. Records what was offered, so a test sees every write the loop
/// *started*, cut off or not.
#[derive(Clone, Default)]
pub(super) struct StalledSink {
    pub(super) offered: Arc<std::sync::Mutex<Vec<Message>>>,
}

impl Sink<Message> for StalledSink {
    type Error = axum::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.offered.lock().expect("offered").push(item);
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Pending
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Pending
    }
}

/// A write cut off at the shutdown bound is the last thing the socket is
/// offered: a frame abandoned part-way leaves the stream where no further
/// frame — the queued ones, or a close — could follow it intact.
#[tokio::test(start_paused = true)]
async fn nothing_is_written_after_a_cut_off_write() {
    let registry = Arc::new(ConnectionRegistry::new());
    let sink = StalledSink::default();
    let offered = Arc::clone(&sink.offered);
    let (id, _client_tx, task) = spawn_loop(&registry, sink);
    assert!(registry.send_to(id, "stalls"));
    assert!(registry.send_to(id, "queued behind it"));
    tokio::time::sleep(Duration::from_millis(10)).await;
    registry.close_all_connections();

    let elapsed = time_to_exit(task).await;
    assert!(elapsed <= SHUTDOWN_CLOSE_TIMEOUT, "took {elapsed:?}");
    let offered = offered.lock().expect("offered");
    match offered.as_slice() {
        [Message::Text(text)] => assert_eq!(text.as_str(), "stalls"),
        other => panic!("expected only the cut-off frame, got {other:?}"),
    }
}

/// A response cut off at the shutdown bound ends the loop too: the
/// dispatch path's writes (the queued flush, the response) stop at the
/// cut-off like the notification path's, with no close after them.
#[tokio::test(start_paused = true)]
async fn nothing_is_written_after_a_cut_off_response() {
    let registry = Arc::new(ConnectionRegistry::new());
    let sink = StalledSink::default();
    let offered = Arc::clone(&sink.offered);
    let (notify_tx, notify_rx) = crate::connection_channel(1 << 20);
    let conn = registry.add_connection(
        notify_tx,
        crate::ConnectionIdentity::default(),
        CancellationToken::new(),
    );
    let guard = ConnectionGuard::new(Arc::clone(&registry), conn.id);
    let (client_tx, server_rx) = mpsc::unbounded();
    let dispatch: WsDispatchFn = Arc::new(|_| Box::pin(async { Some("the response".to_owned()) }));
    let task = tokio::spawn({
        let registry = Arc::clone(&registry);
        async move {
            run_ws_loop(
                sink,
                server_rx,
                registry,
                conn,
                notify_rx,
                Arc::new(PendingPeerRequests::new(8)),
                dispatch,
                crate::ws_endpoint::WsLoopOptions::default(),
            )
            .await;
            drop(guard);
        }
    });
    client_tx
        .unbounded_send(Ok(Message::Text(
            r#"{"jsonrpc":"2.0","id":1,"method":"m"}"#.into(),
        )))
        .expect("client send");
    tokio::time::sleep(Duration::from_millis(10)).await;
    registry.close_all_connections();

    let elapsed = time_to_exit(task).await;
    assert!(elapsed <= SHUTDOWN_CLOSE_TIMEOUT, "took {elapsed:?}");
    let offered = offered.lock().expect("offered");
    match offered.as_slice() {
        [Message::Text(text)] => assert_eq!(text.as_str(), "the response"),
        other => panic!("expected only the cut-off response, got {other:?}"),
    }
}

/// The queued flush stops at a cut-off write: what is still queued
/// behind it is never offered to the socket.
#[tokio::test(start_paused = true)]
async fn a_queued_flush_stops_at_a_cut_off_write() {
    let closing = CancellationToken::new();
    closing.cancel();
    let open = CancellationToken::new();
    let mut budget = crate::ws_endpoint::WriteBudget::new(&closing, &open);
    let (notify_tx, mut notify_rx) = crate::connection_channel(1 << 20);
    let queue = notify_tx.handle();
    assert_eq!(queue.push("stalls".into()), Push::Queued);
    assert_eq!(queue.push("queued behind it".into()), Push::Queued);
    let mut sink = StalledSink::default();
    let offered = Arc::clone(&sink.offered);

    let flushed =
        crate::ws_endpoint::flush_queued_frames(&mut notify_rx, &mut sink, &mut budget).await;
    assert_eq!(
        flushed,
        crate::ws_endpoint::QueuedFlush::SendFailed(crate::ws_endpoint::WriteError::ShutdownCut)
    );
    let offered = offered.lock().expect("offered");
    match offered.as_slice() {
        [Message::Text(text)] => assert_eq!(text.as_str(), "stalls"),
        other => panic!("expected only the cut-off frame, got {other:?}"),
    }
}
