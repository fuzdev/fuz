//! Pins the loop's side of the two outbound bounds: a connection the
//! registry closed for an **outbound overflow** writes a 4005 close and
//! nothing queued, and a **write that makes no progress** ends the loop
//! at its deadline with no frame — shutdown or not — leaving nothing
//! behind it (no registry entry, no in-flight handler, no pending
//! server-initiated request). Also that any registry-side close discards
//! the backlog, so a revocation's 4001 does not wait behind it.
//!
//! Drives [`run_ws_loop`] over in-memory sinks under tokio's paused
//! clock, so every deadline is exact and costs no wall time.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::ws::Message;
use futures::channel::mpsc;
use futures_util::{Sink, StreamExt};
use fuz_auth::ConnectionCloser;
use fuz_http::ShutdownCloser;
use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::shutdown::StalledSink;
use crate::connection::{CloseReason, Connection};
use crate::connection_registry::{ConnectionGuard, ConnectionRegistry};
use crate::peer::PendingPeerRequests;
use crate::ws_close_codes::{
    WS_CLOSE_OUTBOUND_OVERFLOW, WS_CLOSE_OUTBOUND_OVERFLOW_REASON, WS_CLOSE_SESSION_REVOKED,
};
use crate::ws_endpoint::{
    SHUTDOWN_CLOSE_TIMEOUT, WS_WRITE_STALL_TIMEOUT, WsDispatchFn, run_ws_loop,
};

/// The queue budget the cases run under — small, so a case passes it
/// with a handful of short frames.
const MAX_BYTES: usize = 512;

/// One connection, its loop, and everything a case asserts on.
struct Harness {
    registry: Arc<ConnectionRegistry>,
    conn: Connection,
    pending: Arc<PendingPeerRequests>,
    /// Dispatches started and not yet dropped — a `hold` request counts
    /// from its first poll until its future is dropped.
    running: Arc<AtomicUsize>,
    client_tx: mpsc::UnboundedSender<Result<Message, axum::Error>>,
    task: tokio::task::JoinHandle<()>,
    started: tokio::time::Instant,
}

/// Decrements the running count when a dispatch future is dropped.
struct Running(Arc<AtomicUsize>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Harness {
    /// Register a connection on `account` and spawn its loop over
    /// `server_tx`, holding the [`ConnectionGuard`] until the loop
    /// returns. The dispatch holds every request until the test ends.
    fn start<S>(server_tx: S, account: uuid::Uuid) -> Self
    where
        S: Sink<Message> + Unpin + Send + 'static,
    {
        Self::start_with_budget(server_tx, account, MAX_BYTES)
    }

    /// [`Self::start`] over a queue with a budget of
    /// `outbound_queue_bytes`.
    fn start_with_budget<S>(server_tx: S, account: uuid::Uuid, outbound_queue_bytes: usize) -> Self
    where
        S: Sink<Message> + Unpin + Send + 'static,
    {
        let registry = Arc::new(ConnectionRegistry::new());
        let (notify_tx, notify_rx) = crate::connection_channel(outbound_queue_bytes);
        let conn = registry.add_connection(
            notify_tx,
            crate::ConnectionIdentity {
                account_id: Some(account),
                ..crate::ConnectionIdentity::default()
            },
            CancellationToken::new(),
        );
        let guard = ConnectionGuard::new(Arc::clone(&registry), conn.id);
        let pending = Arc::new(PendingPeerRequests::new(8));
        let running = Arc::new(AtomicUsize::new(0));
        let dispatch: WsDispatchFn = Arc::new({
            let running = Arc::clone(&running);
            move |input| {
                let running = Arc::clone(&running);
                Box::pin(async move {
                    running.fetch_add(1, Ordering::SeqCst);
                    let _running = Running(running);
                    if input.method == "hold" {
                        std::future::pending::<()>().await;
                    }
                    // `until_cancelled`: answer once the socket is closed
                    input.signal.cancelled().await;
                    Some(
                        json!({"jsonrpc": "2.0", "id": input.request_id, "result": "late"})
                            .to_string(),
                    )
                })
            }
        });
        let (client_tx, server_rx) = mpsc::unbounded();
        let task = tokio::spawn({
            let registry = Arc::clone(&registry);
            let conn = conn.clone();
            let pending = Arc::clone(&pending);
            async move {
                run_ws_loop(
                    server_tx,
                    server_rx,
                    registry,
                    conn,
                    notify_rx,
                    pending,
                    dispatch,
                    crate::ws_endpoint::WsLoopOptions::default(),
                )
                .await;
                drop(guard);
            }
        });
        Self {
            registry,
            conn,
            pending,
            running,
            client_tx,
            task,
            started: tokio::time::Instant::now(),
        }
    }

    fn request(&self, method: &str, id: u64) {
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method});
        self.client_tx
            .unbounded_send(Ok(Message::Text(frame.to_string().into())))
            .expect("loop is reading");
    }

    /// Let every task run until it has nothing left to do at this
    /// instant — the paused clock does not advance.
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// Wait for the loop to exit and return when it did, measured from
    /// the harness's start. Fails past a minute of tokio time.
    async fn exited_after(&mut self) -> Duration {
        tokio::time::timeout(Duration::from_secs(60), &mut self.task)
            .await
            .expect("a bound lets the loop exit")
            .expect("loop task");
        self.started.elapsed()
    }

    /// Assert the loop left nothing behind: no registry entry, no
    /// running dispatch, no pending server-initiated request.
    fn assert_torn_down(&self) {
        assert!(!self.registry.is_registered(self.conn.id), "entry removed");
        assert_eq!(self.registry.connection_count(), 0);
        assert!(self.conn.signal.is_cancelled(), "socket signal cancelled");
        assert_eq!(
            self.running.load(Ordering::SeqCst),
            0,
            "in-flight handlers dropped"
        );
        assert!(self.pending.is_empty(), "pending peer requests settled");
    }
}

fn assert_overflow_close(frame: &Message) {
    match frame {
        Message::Close(Some(frame)) => {
            assert_eq!(frame.code, WS_CLOSE_OUTBOUND_OVERFLOW);
            assert_eq!(frame.code, 4005, "the wire value");
            assert_eq!(frame.reason.as_str(), WS_CLOSE_OUTBOUND_OVERFLOW_REASON);
            assert_eq!(frame.reason.as_str(), "outbound queue overflow");
        }
        other => panic!("expected a 4005 close frame, got {other:?}"),
    }
}

/// A frame past the queue's budget closes the connection with 4005: the
/// backlog is discarded, not written, and the loop tears down with the
/// socket still writable.
#[tokio::test(start_paused = true)]
async fn an_overflow_closes_with_4005_and_writes_no_backlog() {
    let (server_tx, client_rx) = mpsc::unbounded();
    let account = uuid::Uuid::new_v4();
    let mut harness = Harness::start(server_tx, account);
    let id = harness.conn.id;
    let (_peer_id, peer_rx) = harness.pending.register(id).expect("a pending request");
    // the loop has not run: everything sent here waits in the queue
    assert!(harness.registry.send_to(id, &"a".repeat(MAX_BYTES)));
    assert!(
        !harness.registry.send_to(id, "b"),
        "a frame behind one that fills the budget is not queued"
    );
    assert_eq!(
        harness.conn.close_reason.get(),
        Some(&CloseReason::OutboundOverflow)
    );

    let elapsed = harness.exited_after().await;
    assert_eq!(elapsed, Duration::ZERO, "a writable socket closes at once");
    let frames: Vec<Message> = client_rx.collect().await;
    match frames.as_slice() {
        [close] => assert_overflow_close(close),
        other => panic!("expected only the 4005 close, got {other:?}"),
    }
    harness.assert_torn_down();
    assert!(
        peer_rx.await.is_err(),
        "the pending request reads the connection gone"
    );
}

/// The 4005 close has the close deadline, not the frame deadline: a
/// client that overflowed because it is not reading holds the socket for
/// `SHUTDOWN_CLOSE_TIMEOUT` and no longer, and gets no frame. The
/// in-flight handler is not held for that write: it is dropped as soon
/// as the loop sees the close.
#[tokio::test(start_paused = true)]
async fn an_overflow_close_that_cannot_be_written_is_cut_at_the_close_deadline() {
    let sink = StalledSink::default();
    let offered = Arc::clone(&sink.offered);
    let mut harness = Harness::start(sink, uuid::Uuid::new_v4());
    let id = harness.conn.id;
    harness.request("hold", 1);
    Harness::settle().await;
    assert_eq!(
        harness.running.load(Ordering::SeqCst),
        1,
        "the handler runs"
    );
    assert!(harness.registry.send_to(id, &"a".repeat(MAX_BYTES)));
    assert!(!harness.registry.send_to(id, "b"));

    tokio::time::sleep(SHUTDOWN_CLOSE_TIMEOUT / 2).await;
    assert!(!harness.task.is_finished(), "the close write is pending");
    assert_eq!(
        harness.running.load(Ordering::SeqCst),
        0,
        "the handler is dropped ahead of the close write"
    );

    let elapsed = harness.exited_after().await;
    assert_eq!(elapsed, SHUTDOWN_CLOSE_TIMEOUT);
    let offered = offered.lock().expect("offered");
    match offered.as_slice() {
        [close] => assert_overflow_close(close),
        other => panic!("expected only the 4005 close to be attempted, got {other:?}"),
    }
    harness.assert_torn_down();
}

/// A write that makes no progress ends the loop at exactly
/// [`WS_WRITE_STALL_TIMEOUT`], with no shutdown anywhere: no frame
/// follows the stalled one, the in-flight handler is dropped, the
/// pending server-initiated request is settled, and the entry is gone.
/// Until the deadline all of that is still held.
#[tokio::test(start_paused = true)]
async fn a_stalled_write_ends_the_loop_at_the_write_deadline() {
    let sink = StalledSink::default();
    let offered = Arc::clone(&sink.offered);
    let mut harness = Harness::start(sink, uuid::Uuid::new_v4());
    let id = harness.conn.id;
    harness.request("hold", 1);
    Harness::settle().await;
    assert_eq!(
        harness.running.load(Ordering::SeqCst),
        1,
        "the handler runs"
    );
    let (_peer_id, peer_rx) = harness.pending.register(id).expect("a pending request");

    assert!(harness.registry.send_to(id, "stalls"));
    assert!(harness.registry.send_to(id, "queued behind it"));
    tokio::time::sleep(WS_WRITE_STALL_TIMEOUT.saturating_sub(Duration::from_millis(1))).await;
    assert!(!harness.task.is_finished(), "held until the deadline");
    assert!(harness.registry.is_registered(id));
    assert_eq!(harness.running.load(Ordering::SeqCst), 1);

    let elapsed = harness.exited_after().await;
    assert_eq!(elapsed, WS_WRITE_STALL_TIMEOUT, "exactly the deadline");
    match offered.lock().expect("offered").as_slice() {
        [Message::Text(text)] => assert_eq!(text.as_str(), "stalls"),
        other => panic!("expected only the stalled frame, got {other:?}"),
    }
    harness.assert_torn_down();
    assert!(
        peer_rx.await.is_err(),
        "the pending request reads the connection gone"
    );
    assert!(
        !harness.registry.send_to(id, "after"),
        "unknown from then on"
    );
}

/// During a shutdown the shorter bound applies to a write already
/// stalled: the loop exits `SHUTDOWN_CLOSE_TIMEOUT` after the close-all,
/// not at the write's own deadline.
#[tokio::test(start_paused = true)]
async fn a_stalled_write_is_cut_sooner_by_a_shutdown() {
    let mut harness = Harness::start(StalledSink::default(), uuid::Uuid::new_v4());
    let id = harness.conn.id;
    assert!(harness.registry.send_to(id, "stalls"));
    let before_shutdown = Duration::from_secs(3);
    tokio::time::sleep(before_shutdown).await;
    harness.registry.close_all_connections();

    let elapsed = harness.exited_after().await;
    assert_eq!(elapsed, before_shutdown + SHUTDOWN_CLOSE_TIMEOUT);
    assert!(elapsed < WS_WRITE_STALL_TIMEOUT);
    harness.assert_torn_down();
}

/// The write's own deadline still holds once a shutdown has fired: a
/// write whose deadline falls before the shutdown bound ends there.
#[tokio::test(start_paused = true)]
async fn a_shutdown_does_not_extend_a_stalled_write() {
    let mut harness = Harness::start(StalledSink::default(), uuid::Uuid::new_v4());
    let id = harness.conn.id;
    assert!(harness.registry.send_to(id, "stalls"));
    // the shutdown bound would end half a close-timeout past the write's
    tokio::time::sleep(WS_WRITE_STALL_TIMEOUT.saturating_sub(SHUTDOWN_CLOSE_TIMEOUT / 2)).await;
    harness.registry.close_all_connections();

    let elapsed = harness.exited_after().await;
    assert_eq!(elapsed, WS_WRITE_STALL_TIMEOUT);
    harness.assert_torn_down();
}

/// Each write gets its own deadline: a client that takes every frame,
/// each just inside the deadline, is never dropped.
#[tokio::test(start_paused = true)]
async fn a_slow_reader_inside_the_deadline_is_not_dropped() {
    // a write to this sink completes when the client takes its frame
    let (server_tx, mut client_rx) = mpsc::channel::<Message>(0);
    let harness = Harness::start(server_tx, uuid::Uuid::new_v4());
    let id = harness.conn.id;
    let per_frame = WS_WRITE_STALL_TIMEOUT.saturating_sub(Duration::from_millis(1));
    for i in 0..4 {
        let frame = format!("frame {i}");
        assert!(harness.registry.send_to(id, &frame));
        tokio::time::sleep(per_frame).await;
        match client_rx.next().await {
            Some(Message::Text(text)) => assert_eq!(text.as_str(), frame),
            other => panic!("expected {frame}, got {other:?}"),
        }
    }
    assert!(!harness.task.is_finished(), "each write met its deadline");
    assert!(harness.registry.is_registered(id));
}

/// A revocation behind a backlog: the frames still queued are discarded
/// with the close, and the 4001 follows the one frame whose write was
/// already in progress.
#[tokio::test(start_paused = true)]
async fn a_revocation_is_not_held_behind_a_backlog() {
    let account = uuid::Uuid::new_v4();
    let (mut server_tx, client_rx) = mpsc::channel::<Message>(0);
    server_tx
        .try_send(Message::Text("unread".into()))
        .expect("fill the slot");
    let mut harness = Harness::start(server_tx, account);
    let id = harness.conn.id;
    for frame in ["in progress", "backlog 1", "backlog 2"] {
        assert!(harness.registry.send_to(id, frame));
    }
    // the loop takes "in progress" and blocks writing it
    Harness::settle().await;
    assert_eq!(
        harness
            .registry
            .close_connections(&fuz_auth::ConnectionCloseTarget::Account(account)),
        1
    );

    let frames: Vec<Message> = client_rx.collect().await;
    match frames.as_slice() {
        [
            Message::Text(unread),
            Message::Text(in_progress),
            Message::Close(Some(close)),
        ] => {
            assert_eq!(unread.as_str(), "unread");
            assert_eq!(in_progress.as_str(), "in progress");
            assert_eq!(close.code, WS_CLOSE_SESSION_REVOKED);
        }
        other => panic!("expected the frame in progress then a 4001, got {other:?}"),
    }
    assert_eq!(
        harness.exited_after().await,
        Duration::ZERO,
        "the close waited on nothing"
    );
    harness.assert_torn_down();
}

/// A connection the registry closed writes nothing but its close,
/// whichever of the loop's arms is ready when it looks: a dispatch that
/// completes because of the close has its response dropped, and a
/// client frame that would be answered inline — here one that does not
/// parse — is not answered.
#[tokio::test(start_paused = true)]
async fn a_closed_connection_writes_nothing_but_its_close() {
    for _ in 0..32 {
        let account = uuid::Uuid::new_v4();
        let (server_tx, client_rx) = mpsc::unbounded();
        let mut harness = Harness::start(server_tx, account);
        harness.request("until_cancelled", 1);
        Harness::settle().await;
        assert_eq!(harness.running.load(Ordering::SeqCst), 1);
        assert_eq!(
            harness
                .registry
                .close_connections(&fuz_auth::ConnectionCloseTarget::Account(account)),
            1
        );
        harness
            .client_tx
            .unbounded_send(Ok(Message::Text("not json".into())))
            .expect("loop is reading");

        harness.exited_after().await;
        let frames: Vec<Message> = client_rx.collect().await;
        match frames.as_slice() {
            [Message::Close(Some(close))] => assert_eq!(close.code, WS_CLOSE_SESSION_REVOKED),
            other => panic!("expected only the 4001 close, got {other:?}"),
        }
        harness.assert_torn_down();
    }
}

/// A registry close does not wait out a write already stalled: the write
/// and the close share one `WS_CLOSE_WRITE_TIMEOUT` from the close, so a
/// revoked or overflowed connection whose client stopped reading gives
/// up its handlers then, not at the write's own deadline. No close frame
/// follows the abandoned write.
#[tokio::test(start_paused = true)]
async fn a_registry_close_cuts_a_stalled_write_at_the_close_bound() {
    let before_close = Duration::from_secs(2);

    // a revocation
    let account = uuid::Uuid::new_v4();
    let sink = StalledSink::default();
    let offered = Arc::clone(&sink.offered);
    let mut revoked = Harness::start(sink, account);
    revoked.request("hold", 1);
    Harness::settle().await;
    assert!(revoked.registry.send_to(revoked.conn.id, "stalls"));
    tokio::time::sleep(before_close).await;
    assert_eq!(
        revoked
            .registry
            .close_connections(&fuz_auth::ConnectionCloseTarget::Account(account)),
        1
    );
    assert_eq!(
        revoked.exited_after().await,
        before_close + crate::ws_endpoint::WS_CLOSE_WRITE_TIMEOUT
    );
    match offered.lock().expect("offered").as_slice() {
        [Message::Text(text)] => assert_eq!(text.as_str(), "stalls"),
        other => panic!("expected only the stalled frame, got {other:?}"),
    }
    revoked.assert_torn_down();

    // an overflow behind the stalled write
    let sink = StalledSink::default();
    let offered = Arc::clone(&sink.offered);
    let mut overflowed = Harness::start(sink, uuid::Uuid::new_v4());
    let id = overflowed.conn.id;
    assert!(overflowed.registry.send_to(id, "stalls"));
    tokio::time::sleep(before_close).await;
    assert!(overflowed.registry.send_to(id, &"a".repeat(MAX_BYTES)));
    assert!(!overflowed.registry.send_to(id, "b"));
    assert_eq!(
        overflowed.exited_after().await,
        before_close + crate::ws_endpoint::WS_CLOSE_WRITE_TIMEOUT
    );
    match offered.lock().expect("offered").as_slice() {
        [Message::Text(text)] => assert_eq!(text.as_str(), "stalls"),
        other => panic!("expected only the stalled frame, got {other:?}"),
    }
    overflowed.assert_torn_down();
}

/// A close that lands mid-write does not cut a write the client is still
/// taking: the frame in progress finishes inside the close bound and the
/// close frame follows it, sharing what is left of that one bound.
#[tokio::test(start_paused = true)]
async fn a_write_finishing_inside_the_close_bound_is_followed_by_the_close() {
    let account = uuid::Uuid::new_v4();
    // a write to this sink completes when the client takes its frame
    let (mut server_tx, mut client_rx) = mpsc::channel::<Message>(0);
    server_tx
        .try_send(Message::Text("unread".into()))
        .expect("fill the slot");
    let mut harness = Harness::start(server_tx, account);
    assert!(harness.registry.send_to(harness.conn.id, "in progress"));
    Harness::settle().await;
    assert_eq!(
        harness
            .registry
            .close_connections(&fuz_auth::ConnectionCloseTarget::Account(account)),
        1
    );

    // the client takes the frames half a close bound later
    let half = crate::ws_endpoint::WS_CLOSE_WRITE_TIMEOUT / 2;
    tokio::time::sleep(half).await;
    assert!(!harness.task.is_finished(), "the write is still pending");
    let mut frames = Vec::new();
    while let Some(frame) = client_rx.next().await {
        frames.push(frame);
    }
    match frames.as_slice() {
        [
            Message::Text(unread),
            Message::Text(in_progress),
            Message::Close(Some(close)),
        ] => {
            assert_eq!(unread.as_str(), "unread");
            assert_eq!(in_progress.as_str(), "in progress");
            assert_eq!(close.code, WS_CLOSE_SESSION_REVOKED);
        }
        other => panic!("expected the frame in progress then a 4001, got {other:?}"),
    }
    assert_eq!(harness.exited_after().await, half);
    harness.assert_torn_down();
}

/// The close bound is one budget from the close, not one per write: a
/// client draining slowly — the frame in progress taken well inside the
/// bound — cannot stretch that write and the close frame past it.
#[tokio::test(start_paused = true)]
async fn a_write_in_progress_and_the_close_frame_share_the_close_bound() {
    let account = uuid::Uuid::new_v4();
    let (server_tx, mut client_rx) = mpsc::channel::<Message>(0);
    let mut harness = Harness::start(server_tx, account);
    // a write completes when the client takes its frame: the frame in
    // progress at 0.6 of the bound, and the close would at 1.2
    let per_frame = crate::ws_endpoint::WS_CLOSE_WRITE_TIMEOUT * 6 / 10;
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
    for frame in ["in progress", "backlog"] {
        assert!(harness.registry.send_to(harness.conn.id, frame));
    }
    // the loop takes "in progress" and blocks writing it
    Harness::settle().await;
    assert_eq!(
        harness
            .registry
            .close_connections(&fuz_auth::ConnectionCloseTarget::Account(account)),
        1
    );

    assert_eq!(
        harness.exited_after().await,
        crate::ws_endpoint::WS_CLOSE_WRITE_TIMEOUT,
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
    assert_eq!(texts, ["in progress"], "the backlog was discarded");
    harness.assert_torn_down();
}

/// A producer that sends several thousand small frames to one connection
/// with no await between them — a `broadcast` loop, a handler's burst —
/// gives the loop no turn to write, so every frame waits at once, however
/// fast the client reads. The queue is bounded by bytes alone, so a burst
/// whose charges fit is accepted whole and then delivered in order, and
/// the connection stays open.
#[tokio::test(start_paused = true)]
async fn a_synchronous_burst_of_small_frames_is_accepted_and_delivered_in_order() {
    const FRAMES: usize = 5000;
    const BUDGET: usize = 4 * 1024 * 1024;
    let (server_tx, mut client_rx) = mpsc::unbounded();
    let harness = Harness::start_with_budget(server_tx, uuid::Uuid::new_v4(), BUDGET);
    let id = harness.conn.id;

    // no await from here to the end of the burst: the loop is not polled
    for n in 0..FRAMES {
        let frame = format!(r#"{{"jsonrpc":"2.0","method":"tick","params":{n}}}"#);
        let queued = if n % 2 == 0 {
            harness.registry.broadcast(&frame) == 1
        } else {
            harness.registry.send_to(id, &frame)
        };
        assert!(queued, "frame {n} is queued");
    }
    assert!(harness.registry.is_registered(id), "still open");
    assert_eq!(harness.conn.close_reason.get(), None);
    assert!(client_rx.try_next().is_err(), "nothing was written yet");

    for n in 0..FRAMES {
        match client_rx.next().await {
            Some(Message::Text(text)) => assert_eq!(
                text.as_str(),
                format!(r#"{{"jsonrpc":"2.0","method":"tick","params":{n}}}"#)
            ),
            other => panic!("expected frame {n}, got {other:?}"),
        }
    }
    Harness::settle().await;
    assert!(!harness.task.is_finished(), "the connection stays open");
    assert!(harness.registry.is_registered(id));
}

/// The same burst against a budget its charges pass closes the
/// connection with 4005 at the frame that crosses it, and writes none of
/// the burst.
#[tokio::test(start_paused = true)]
async fn a_synchronous_burst_past_the_byte_budget_closes_with_4005() {
    const FRAME: &str = "tick";
    let per_frame = FRAME.len() + crate::OUTBOUND_FRAME_OVERHEAD_BYTES;
    let fit = MAX_BYTES / per_frame;
    let (server_tx, client_rx) = mpsc::unbounded();
    let mut harness = Harness::start(server_tx, uuid::Uuid::new_v4());
    let id = harness.conn.id;
    for n in 0..fit {
        assert!(harness.registry.send_to(id, FRAME), "frame {n} fits");
    }
    assert!(!harness.registry.send_to(id, FRAME), "the next does not");

    assert_eq!(harness.exited_after().await, Duration::ZERO);
    let frames: Vec<Message> = client_rx.collect().await;
    match frames.as_slice() {
        [close] => assert_overflow_close(close),
        other => panic!("expected only the 4005 close, got {other:?}"),
    }
    harness.assert_torn_down();
}

/// An overflow leaves the shutdown nothing to wait for: the close-all
/// that follows finds no entry, and `wait_closed` resolves.
#[tokio::test(start_paused = true)]
async fn wait_closed_resolves_after_an_overflow_and_after_a_stall() {
    let (server_tx, _client_rx) = mpsc::unbounded();
    let mut overflowed = Harness::start(server_tx, uuid::Uuid::new_v4());
    let id = overflowed.conn.id;
    assert!(overflowed.registry.send_to(id, &"a".repeat(MAX_BYTES)));
    assert!(!overflowed.registry.send_to(id, "b"));
    overflowed.exited_after().await;
    assert_eq!(overflowed.registry.close_all_connections(), 0);
    tokio::time::timeout(Duration::from_secs(1), overflowed.registry.wait_closed())
        .await
        .expect("an overflowed loop released its guard");

    let mut stalled = Harness::start(StalledSink::default(), uuid::Uuid::new_v4());
    assert!(stalled.registry.send_to(stalled.conn.id, "stalls"));
    stalled.exited_after().await;
    assert_eq!(stalled.registry.close_all_connections(), 0);
    tokio::time::timeout(Duration::from_secs(1), stalled.registry.wait_closed())
        .await
        .expect("a stalled loop released its guard");
}
