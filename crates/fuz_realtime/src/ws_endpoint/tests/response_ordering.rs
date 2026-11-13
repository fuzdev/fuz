//! Pins the loop's **response-ordering** guarantee: a dispatch's
//! response is never written ahead of frames its handler queued to its
//! own connection before resolving.
//!
//! The handlers here queue their frames synchronously in the same poll
//! that resolves them — the exact shape that makes the completion arm
//! and the `notify_rx` arm ready together, so without the pre-response
//! flush the response deterministically overtakes the frames. Drives
//! [`run_ws_loop`] over in-memory channels standing in for the split
//! socket halves.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Message;
use futures::channel::mpsc;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use std::num::NonZeroUsize;

use fuz_auth::ConnectionCloser;

use crate::connection::ConnectionId;
use crate::connection_registry::ConnectionRegistry;
use crate::peer::PendingPeerRequests;
use crate::ws_close_codes::{
    WS_CLOSE_CONNECTION_LIMIT, WS_CLOSE_CONNECTION_LIMIT_REASON, WS_CLOSE_PERMISSION_REVOKED,
    WS_CLOSE_PERMISSION_REVOKED_REASON, WS_CLOSE_SESSION_REVOKED,
};
use crate::ws_endpoint::{WsDispatchFn, run_ws_loop};

const CHUNKS: [&str; 3] = ["one", "two", "three"];

/// Client-side ends of one in-memory connection plus the loop task.
struct Harness {
    client_tx: mpsc::UnboundedSender<Result<Message, axum::Error>>,
    client_rx: mpsc::UnboundedReceiver<Message>,
    loop_task: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Register a connection and spawn the loop, building the dispatch
    /// from the registry + the new connection's id.
    fn start(
        build_dispatch: impl FnOnce(Arc<ConnectionRegistry>, ConnectionId) -> WsDispatchFn,
    ) -> Self {
        Self::start_on(Arc::new(ConnectionRegistry::new()), None, build_dispatch)
    }

    /// [`Self::start`] over a given registry, registering the connection
    /// under `account_id`.
    fn start_on(
        registry: Arc<ConnectionRegistry>,
        account_id: Option<uuid::Uuid>,
        build_dispatch: impl FnOnce(Arc<ConnectionRegistry>, ConnectionId) -> WsDispatchFn,
    ) -> Self {
        Self::start_as(
            registry,
            crate::ConnectionIdentity {
                account_id,
                ..crate::ConnectionIdentity::default()
            },
            build_dispatch,
        )
    }

    /// [`Self::start`] over a given registry, registering the connection
    /// under `identity`.
    fn start_as(
        registry: Arc<ConnectionRegistry>,
        identity: crate::ConnectionIdentity,
        build_dispatch: impl FnOnce(Arc<ConnectionRegistry>, ConnectionId) -> WsDispatchFn,
    ) -> Self {
        Self::start_with(
            registry,
            identity,
            crate::ws_endpoint::WsLoopOptions::default(),
            build_dispatch,
        )
    }

    /// [`Self::start_as`] with the loop's [`crate::WsLoopOptions`].
    fn start_with(
        registry: Arc<ConnectionRegistry>,
        identity: crate::ConnectionIdentity,
        options: crate::ws_endpoint::WsLoopOptions,
        build_dispatch: impl FnOnce(Arc<ConnectionRegistry>, ConnectionId) -> WsDispatchFn,
    ) -> Self {
        let (notify_tx, notify_rx) = crate::connection_channel(1 << 20);
        let signal = CancellationToken::new();
        let conn = registry.add_connection(notify_tx, identity, signal);
        let dispatch = build_dispatch(Arc::clone(&registry), conn.id);
        let (client_tx, server_rx) = mpsc::unbounded();
        let (server_tx, client_rx) = mpsc::unbounded();
        let loop_task = tokio::spawn(run_ws_loop(
            server_tx,
            server_rx,
            registry,
            conn,
            notify_rx,
            Arc::new(PendingPeerRequests::new(8)),
            dispatch,
            options,
        ));
        Self {
            client_tx,
            client_rx,
            loop_task,
        }
    }

    fn send_request(&self, id: u64) {
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": "stream", "params": {}});
        self.client_tx
            .unbounded_send(Ok(Message::Text(frame.to_string().into())))
            .expect("loop is reading");
    }

    async fn next_frame(&mut self) -> Option<Message> {
        tokio::time::timeout(Duration::from_secs(5), self.client_rx.next())
            .await
            .expect("frame within timeout")
    }

    async fn next_json(&mut self) -> Value {
        match self.next_frame().await {
            Some(Message::Text(text)) => serde_json::from_str(&text).expect("JSON frame"),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }
}

/// A dispatch that `notify`s one `progress` frame per chunk to its own
/// connection, optionally runs `after_notify`, then resolves with a
/// response — all in one poll.
fn streaming_dispatch(after_notify: Option<Arc<dyn Fn() + Send + Sync>>) -> WsDispatchFn {
    Arc::new(move |input| {
        let after_notify = after_notify.clone();
        Box::pin(async move {
            for chunk in CHUNKS {
                (input.notify)("progress", &json!({"chunk": chunk}));
            }
            if let Some(after_notify) = after_notify {
                after_notify();
            }
            Some(json!({"jsonrpc": "2.0", "id": input.request_id, "result": "done"}).to_string())
        })
    })
}

fn assert_progress_frames(frames: &[Value]) {
    let chunks: Vec<&str> = frames
        .iter()
        .map(|frame| {
            assert_eq!(frame["method"], "progress", "frame: {frame}");
            frame["params"]["chunk"].as_str().expect("chunk string")
        })
        .collect();
    assert_eq!(chunks, CHUNKS, "progress frames arrive in queue order");
}

/// Notifications a handler queued to its own connection before
/// resolving reach the client ahead of its response.
#[tokio::test]
async fn response_follows_frames_queued_by_its_handler() {
    let mut harness = Harness::start(|_, _| streaming_dispatch(None));
    harness.send_request(1);

    let mut progress = Vec::new();
    for _ in CHUNKS {
        progress.push(harness.next_json().await);
    }
    assert_progress_frames(&progress);

    let response = harness.next_json().await;
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"], "done");

    harness.client_tx.close_channel();
    harness.loop_task.await.expect("loop exits cleanly");
}

/// A revocation observed while flushing ahead of a response behaves
/// like the `notify_rx` arm's: the close discarded the frames the
/// handler had queued, so the 4001 close is all that is written —
/// neither those frames nor the response, which the handler never
/// claimed ([`crate::ws_endpoint::ReplyOwed`]).
#[tokio::test]
async fn revocation_during_flush_closes_without_the_response() {
    let mut harness = Harness::start(|registry, conn_id| {
        streaming_dispatch(Some(Arc::new(move || registry.remove_connection(conn_id))))
    });
    harness.send_request(1);

    match harness.next_frame().await {
        Some(Message::Close(Some(frame))) => assert_eq!(frame.code, WS_CLOSE_SESSION_REVOKED),
        other => panic!("expected a 4001 close frame, got {other:?}"),
    }
    assert!(
        harness.next_frame().await.is_none(),
        "nothing follows the close"
    );
    harness.loop_task.await.expect("loop exits cleanly");
}

/// A connection whose account lost a role its endpoint required closes
/// with 4006 and its reason, not 4001 — and nothing follows the close:
/// the frames queued for it before the role close are discarded with it,
/// and a send after it is refused.
#[tokio::test]
async fn a_role_close_writes_4006_and_nothing_after() {
    let account = uuid::Uuid::new_v4();
    let registry = Arc::new(ConnectionRegistry::new());
    let mut conn_id = None;
    let mut harness = Harness::start_as(
        Arc::clone(&registry),
        crate::ConnectionIdentity {
            account_id: Some(account),
            required_roles: vec!["admin"],
            ..crate::ConnectionIdentity::default()
        },
        |_, id| {
            conn_id = Some(id);
            streaming_dispatch(None)
        },
    );
    let conn_id = conn_id.expect("the dispatch was built");
    // queued with no await between them and the close, so the loop has
    // no turn to write them first
    assert!(registry.send_to(conn_id, "{\"queued\": 1}"));
    assert_eq!(
        registry.close_connections(&fuz_auth::ConnectionCloseTarget::Role {
            account_id: account,
            role: "admin".to_owned()
        }),
        1
    );
    assert!(
        !registry.send_to(conn_id, "{\"after\": 1}"),
        "refused after the close"
    );

    match harness.next_frame().await {
        Some(Message::Close(Some(frame))) => {
            assert_eq!(frame.code, WS_CLOSE_PERMISSION_REVOKED);
            assert_eq!(frame.reason.as_str(), WS_CLOSE_PERMISSION_REVOKED_REASON);
        }
        other => panic!("expected a 4006 close frame, got {other:?}"),
    }
    assert!(
        harness.next_frame().await.is_none(),
        "nothing follows the close"
    );
    harness.loop_task.await.expect("loop exits cleanly");
}

/// Start a harness whose loop has `receive_timeout`, on a fresh registry.
fn start_with_receive_timeout(receive_timeout: Option<Duration>) -> Harness {
    Harness::start_with(
        Arc::new(ConnectionRegistry::new()),
        crate::ConnectionIdentity::default(),
        crate::ws_endpoint::WsLoopOptions {
            receive_timeout,
            ..crate::ws_endpoint::WsLoopOptions::default()
        },
        |_, _| streaming_dispatch(None),
    )
}

/// The next frame the client reads within `wait`, or `None` once the loop
/// has ended; panics past `wait`.
async fn next_frame_within(harness: &mut Harness, wait: Duration) -> Option<Message> {
    tokio::time::timeout(wait, harness.client_rx.next())
        .await
        .expect("a frame within the wait")
}

fn assert_receive_timeout_close(frame: Option<Message>) {
    match frame {
        Some(Message::Close(Some(frame))) => {
            assert_eq!(frame.code, crate::WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT);
            assert_eq!(
                frame.reason.as_str(),
                crate::WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT_REASON
            );
        }
        other => panic!("expected a 4003 close frame, got {other:?}"),
    }
}

/// A client that sends nothing is closed with 4003 "server heartbeat
/// timeout" once the receive timeout has passed since admission — not
/// before it, and by one and a half of it (the check runs on a tick of
/// half the timeout, as on the twin).
#[tokio::test(start_paused = true)]
async fn a_silent_socket_closes_with_4003_after_the_receive_timeout() {
    let started = tokio::time::Instant::now();
    let mut harness = start_with_receive_timeout(Some(Duration::from_secs(60)));
    let frame = next_frame_within(&mut harness, Duration::from_secs(120)).await;
    let elapsed = started.elapsed();
    assert_receive_timeout_close(frame);
    assert!(
        elapsed >= Duration::from_secs(60) && elapsed <= Duration::from_secs(90),
        "closed {elapsed:?} in"
    );
    assert!(
        next_frame_within(&mut harness, Duration::from_secs(5))
            .await
            .is_none()
    );
    harness.loop_task.await.expect("loop exits cleanly");
}

/// Every data frame the client sends resets the silence: a socket heard
/// from every 40 s is never closed, and once it goes quiet it is closed a
/// timeout after its last frame.
#[tokio::test(start_paused = true)]
async fn a_frame_from_the_client_resets_the_receive_timeout() {
    let mut harness = start_with_receive_timeout(Some(Duration::from_secs(60)));
    // a notification the loop answers with nothing, so no frame comes back
    let quiet = json!({"jsonrpc": "2.0", "method": "noop"}).to_string();
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(40)).await;
        harness
            .client_tx
            .unbounded_send(Ok(Message::Text(quiet.clone().into())))
            .expect("loop is reading");
    }
    let last = tokio::time::Instant::now();
    let frame = next_frame_within(&mut harness, Duration::from_secs(120)).await;
    let quiet_for = last.elapsed();
    assert_receive_timeout_close(frame);
    assert!(
        quiet_for >= Duration::from_secs(60) && quiet_for <= Duration::from_secs(90),
        "closed {quiet_for:?} after the last frame"
    );
    harness.loop_task.await.expect("loop exits cleanly");
}

/// A binary frame is a data frame the client sent, ignored but heard, as
/// the twin's handler hears it: binary frames every 40 s hold the socket
/// open, and it is closed a timeout after the last.
#[tokio::test(start_paused = true)]
async fn a_binary_frame_resets_the_receive_timeout() {
    let mut harness = start_with_receive_timeout(Some(Duration::from_secs(60)));
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(40)).await;
        harness
            .client_tx
            .unbounded_send(Ok(Message::Binary(vec![1, 2, 3].into())))
            .expect("loop is reading");
    }
    let last = tokio::time::Instant::now();
    let frame = next_frame_within(&mut harness, Duration::from_secs(120)).await;
    let quiet_for = last.elapsed();
    assert_receive_timeout_close(frame);
    assert!(
        quiet_for >= Duration::from_secs(60) && quiet_for <= Duration::from_secs(90),
        "closed {quiet_for:?} after the last frame"
    );
    harness.loop_task.await.expect("loop exits cleanly");
}

/// A ping is not a client message — the twin's handler never sees one —
/// so pings alone do not hold a socket open.
#[tokio::test(start_paused = true)]
async fn pings_do_not_reset_the_receive_timeout() {
    let started = tokio::time::Instant::now();
    let mut harness = start_with_receive_timeout(Some(Duration::from_secs(60)));
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(20)).await;
        harness
            .client_tx
            .unbounded_send(Ok(Message::Ping(Vec::new().into())))
            .expect("loop is reading");
    }
    let frame = next_frame_within(&mut harness, Duration::from_secs(120)).await;
    assert_receive_timeout_close(frame);
    assert!(started.elapsed() <= Duration::from_secs(90));
    harness.loop_task.await.expect("loop exits cleanly");
}

/// No receive timeout keeps a silent socket open.
#[tokio::test(start_paused = true)]
async fn no_receive_timeout_keeps_a_silent_socket_open() {
    let mut harness = start_with_receive_timeout(None);
    assert!(
        tokio::time::timeout(Duration::from_secs(3600), harness.client_rx.next())
            .await
            .is_err(),
        "a silent socket with no receive timeout was closed"
    );
}

/// A connection whose credential expires is closed with 4001 and
/// "Credential expired" at its deadline — open until then, gone from the
/// registry after, and nothing follows the close.
#[tokio::test]
async fn an_expired_credential_closes_with_4001_credential_expired() {
    let account = uuid::Uuid::new_v4();
    let registry = Arc::new(ConnectionRegistry::new());
    let mut conn_id = None;
    let mut harness = Harness::start_with(
        Arc::clone(&registry),
        crate::ConnectionIdentity {
            account_id: Some(account),
            ..crate::ConnectionIdentity::default()
        },
        crate::ws_endpoint::WsLoopOptions {
            credential_deadline: Some(std::time::Instant::now() + Duration::from_millis(300)),
            ..crate::ws_endpoint::WsLoopOptions::default()
        },
        |_, id| {
            conn_id = Some(id);
            streaming_dispatch(None)
        },
    );
    let conn_id = conn_id.expect("the dispatch was built");
    // open before the deadline: a frame sent to it arrives
    assert!(registry.send_to(conn_id, "{\"before\": 1}"));
    assert!(matches!(harness.next_frame().await, Some(Message::Text(_))));

    match harness.next_frame().await {
        Some(Message::Close(Some(frame))) => {
            assert_eq!(frame.code, WS_CLOSE_SESSION_REVOKED);
            assert_eq!(
                frame.reason.as_str(),
                crate::WS_CLOSE_CREDENTIAL_EXPIRED_REASON
            );
        }
        other => panic!("expected a 4001 close frame, got {other:?}"),
    }
    assert!(
        harness.next_frame().await.is_none(),
        "nothing follows the close"
    );
    harness.loop_task.await.expect("loop exits cleanly");
    assert_eq!(registry.connection_count_for_account(account), 0);
    assert!(!registry.send_to(conn_id, "{\"after\": 1}"));
}

/// A connection superseded by the per-account cap while a dispatch is in
/// flight closes with 4004, not 4001, on the completion arm's flush path
/// as well as the `notify_rx` arm's — the dispatch registers a newer
/// connection on its own account (cap 1), then resolves, so the flush
/// ahead of its response finds the sender gone. `select!` is unbiased,
/// so the scenario repeats to cover whichever arm observes the drop.
#[tokio::test]
async fn superseded_mid_dispatch_closes_with_4004() {
    for _ in 0..32 {
        let account = uuid::Uuid::new_v4();
        let registry = Arc::new(
            ConnectionRegistry::new().with_max_connections_per_account(NonZeroUsize::new(1)),
        );
        let mut harness = Harness::start_on(registry, Some(account), |registry, _| {
            Arc::new(move |input| {
                let registry = Arc::clone(&registry);
                Box::pin(async move {
                    let (tx, _rx) = crate::connection_channel(1 << 20);
                    registry.add_connection(
                        tx,
                        crate::ConnectionIdentity {
                            account_id: Some(account),
                            ..crate::ConnectionIdentity::default()
                        },
                        CancellationToken::new(),
                    );
                    Some(
                        json!({"jsonrpc": "2.0", "id": input.request_id, "result": "done"})
                            .to_string(),
                    )
                })
            })
        });
        harness.send_request(1);

        let mut frames = Vec::new();
        while let Some(frame) = harness.next_frame().await {
            frames.push(frame);
        }
        match frames.last() {
            Some(Message::Close(Some(frame))) => {
                assert_eq!(frame.code, WS_CLOSE_CONNECTION_LIMIT, "frames: {frames:?}");
                assert_eq!(frame.reason.as_str(), WS_CLOSE_CONNECTION_LIMIT_REASON);
            }
            other => panic!("expected a 4004 close frame last, got {other:?}"),
        }
        harness.loop_task.await.expect("loop exits cleanly");
    }
}

/// A dispatch that queues progress frames, marks its reply owed (when
/// `mark`), runs `close` — standing in for its post-commit drain
/// revoking its own connection — and resolves with a response.
fn self_closing_dispatch(close: Arc<dyn Fn() + Send + Sync>, mark: bool) -> WsDispatchFn {
    Arc::new(move |input| {
        let close = Arc::clone(&close);
        Box::pin(async move {
            for chunk in CHUNKS {
                (input.notify)("progress", &json!({"chunk": chunk}));
            }
            if mark {
                input.reply_owed.mark();
            }
            close();
            Some(json!({"jsonrpc": "2.0", "id": input.request_id, "result": "done"}).to_string())
        })
    })
}

/// Collect every frame until the client side sees the stream end.
async fn drain_frames(harness: &mut Harness) -> Vec<Message> {
    let mut frames = Vec::new();
    while let Some(frame) = harness.next_frame().await {
        frames.push(frame);
    }
    frames
}

/// A request that revokes its own connection's credential gets its
/// response, then the 4001 close, and nothing else — the frames it
/// queued before the close are discarded with the rest of the queue.
/// (The dispatch resolves in the poll that closes, so this is the
/// completion arm's flush path; the wait path is the next test.)
#[tokio::test]
async fn a_self_revoking_request_gets_its_response_then_4001() {
    let mut harness = Harness::start(|registry, conn_id| {
        self_closing_dispatch(Arc::new(move || registry.remove_connection(conn_id)), true)
    });
    harness.send_request(1);
    let frames = drain_frames(&mut harness).await;
    match frames.as_slice() {
        [Message::Text(text), Message::Close(Some(close))] => {
            let response: Value = serde_json::from_str(text).expect("JSON frame");
            assert_eq!(response["id"], 1, "frames: {frames:?}");
            assert_eq!(response["result"], "done");
            assert_eq!(close.code, WS_CLOSE_SESSION_REVOKED);
        }
        other => panic!("expected the response then a 4001 close, got {other:?}"),
    }
    harness.loop_task.await.expect("loop exits cleanly");
}

/// While the loop waits for an owed response, an unmarked dispatch that
/// lands meanwhile is dropped: only the owed response precedes the close.
#[tokio::test]
async fn an_unmarked_response_landing_during_the_wait_is_dropped() {
    let mut harness = Harness::start(|registry, conn_id| {
        Arc::new(move |input| {
            let registry = Arc::clone(&registry);
            Box::pin(async move {
                let owed = input.request_id == &json!(1);
                if owed {
                    input.reply_owed.mark();
                    registry.remove_connection(conn_id);
                    tokio::time::sleep(Duration::from_millis(40)).await;
                } else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Some(
                    json!({"jsonrpc": "2.0", "id": input.request_id, "result": "done"}).to_string(),
                )
            })
        })
    });
    harness.send_request(2);
    harness.send_request(1);
    let frames = drain_frames(&mut harness).await;
    match frames.as_slice() {
        [Message::Text(text), Message::Close(Some(close))] => {
            let response: Value = serde_json::from_str(text).expect("JSON frame");
            assert_eq!(response["id"], 1, "frames: {frames:?}");
            assert_eq!(close.code, WS_CLOSE_SESSION_REVOKED);
        }
        other => panic!("expected only the owed response then a 4001 close, got {other:?}"),
    }
    harness.loop_task.await.expect("loop exits cleanly");
}

/// The owed response is still written when the close lands before the
/// dispatch resolves — the loop waits for it, briefly.
#[tokio::test]
async fn an_owed_response_that_resolves_after_the_close_is_written() {
    let mut harness = Harness::start(|registry, conn_id| {
        Arc::new(move |input| {
            let registry = Arc::clone(&registry);
            Box::pin(async move {
                input.reply_owed.mark();
                registry.remove_connection(conn_id);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Some(
                    json!({"jsonrpc": "2.0", "id": input.request_id, "result": "late"}).to_string(),
                )
            })
        })
    });
    harness.send_request(1);
    let frames = drain_frames(&mut harness).await;
    match frames.as_slice() {
        [Message::Text(text), Message::Close(Some(close))] => {
            let response: Value = serde_json::from_str(text).expect("JSON frame");
            assert_eq!(response["result"], "late");
            assert_eq!(close.code, WS_CLOSE_SESSION_REVOKED);
        }
        other => panic!("expected the late response then a 4001 close, got {other:?}"),
    }
    harness.loop_task.await.expect("loop exits cleanly");
}

/// An owed response that never arrives costs the close one bounded
/// wait, then the 4001 is written alone.
#[tokio::test(start_paused = true)]
async fn an_owed_response_that_never_resolves_closes_alone_after_the_wait() {
    let mut harness = Harness::start(|registry, conn_id| {
        Arc::new(move |input| {
            let registry = Arc::clone(&registry);
            Box::pin(async move {
                input.reply_owed.mark();
                registry.remove_connection(conn_id);
                std::future::pending::<Option<String>>().await
            })
        })
    });
    harness.send_request(1);
    let frames = drain_frames(&mut harness).await;
    match frames.as_slice() {
        [Message::Close(Some(close))] => assert_eq!(close.code, WS_CLOSE_SESSION_REVOKED),
        other => panic!("expected a lone 4001 close, got {other:?}"),
    }
    harness.loop_task.await.expect("loop exits cleanly");
}

/// A request that revokes a role its own connection's endpoint requires
/// gets its response, then the 4006 close.
#[tokio::test]
async fn a_self_revoking_role_request_gets_its_response_then_4006() {
    let account = uuid::Uuid::new_v4();
    let mut harness = Harness::start_as(
        Arc::new(ConnectionRegistry::new()),
        crate::ConnectionIdentity {
            account_id: Some(account),
            required_roles: vec!["admin"],
            ..crate::ConnectionIdentity::default()
        },
        |registry, _| {
            self_closing_dispatch(
                Arc::new(move || {
                    registry.close_connections(&fuz_auth::ConnectionCloseTarget::Role {
                        account_id: account,
                        role: "admin".to_owned(),
                    });
                }),
                true,
            )
        },
    );
    harness.send_request(1);
    let frames = drain_frames(&mut harness).await;
    match frames.as_slice() {
        [Message::Text(text), Message::Close(Some(close))] => {
            let response: Value = serde_json::from_str(text).expect("JSON frame");
            assert_eq!(response["result"], "done");
            assert_eq!(close.code, WS_CLOSE_PERMISSION_REVOKED);
        }
        other => panic!("expected the response then a 4006 close, got {other:?}"),
    }
    harness.loop_task.await.expect("loop exits cleanly");
}

/// Only a revocation honours a claim: a connection superseded by the
/// per-account cap writes its 4004 close and no response, owed or not.
#[tokio::test]
async fn a_superseded_connection_writes_no_owed_response() {
    for _ in 0..16 {
        let account = uuid::Uuid::new_v4();
        let registry = Arc::new(
            ConnectionRegistry::new().with_max_connections_per_account(NonZeroUsize::new(1)),
        );
        let mut harness = Harness::start_on(registry, Some(account), |registry, _| {
            self_closing_dispatch(
                Arc::new(move || {
                    let (tx, _rx) = crate::connection_channel(1 << 20);
                    registry.add_connection(
                        tx,
                        crate::ConnectionIdentity {
                            account_id: Some(account),
                            ..crate::ConnectionIdentity::default()
                        },
                        CancellationToken::new(),
                    );
                }),
                true,
            )
        });
        harness.send_request(1);
        let frames = drain_frames(&mut harness).await;
        match frames.as_slice() {
            [Message::Close(Some(close))] => assert_eq!(close.code, WS_CLOSE_CONNECTION_LIMIT),
            other => panic!("expected a lone 4004 close, got {other:?}"),
        }
        harness.loop_task.await.expect("loop exits cleanly");
    }
}
