//! Wire-level coverage for the generic workload-control verbs and graceful
//! shutdown over a real UDS — the request/response arms `tests/streaming.rs`
//! (which only drives `WorkloadList`) leaves untested. Each maps a wire action
//! to a registry call (`status` / `stop`) or the drain path; a wrong
//! response-id wiring or a swapped outcome would otherwise slip through.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::time::timeout;

use fuz_wire::{
    DaemonShutdownRequest, DaemonShutdownResponse, MAX_FRAME, ObserverDomain,
    ObserverSnapshotFrame, ObserverSubscribeRequest, ShutdownStatus, WorkloadKind,
    WorkloadStatusRequest, WorkloadStatusResponse, WorkloadStopOutcome, WorkloadStopRequest,
    WorkloadStopResponse, decode_payload, ids, read_frame, write_frame,
};

mod common;
use common::{block_mid_dispatch, connect_hello, read_to_eof, spawn_server};

/// Assert the server closed this connection (clean FIN → `Ok(0)`, or a reset).
async fn assert_connection_closed(stream: &mut UnixStream) {
    let mut buf = [0u8; 1];
    let result = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("server closed the connection in time");
    if let Ok(n) = result {
        assert_eq!(n, 0, "expected the connection to be closed, read {n} bytes");
    }
}

#[tokio::test]
async fn workload_status_and_stop_round_trip() {
    let (_dir, socket, shutdown, server) = spawn_server();

    // conn_a subscribes to an observer domain, establishing a workload, and
    // holds the stream open. Its snapshot carries the workload id.
    let mut conn_a = connect_hello(&socket).await;
    write_frame(
        &mut conn_a,
        7,
        &ObserverSubscribeRequest {
            domain: ObserverDomain::Process,
        },
        MAX_FRAME,
    )
    .await
    .expect("subscribe");
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut conn_a, MAX_FRAME))
        .await
        .expect("snapshot in time")
        .expect("read snapshot");
    assert_eq!(header.action, ids::OBSERVER_SNAPSHOT_FRAME);
    let snap: ObserverSnapshotFrame = decode_payload(&body).expect("decode snapshot");
    let id = snap.workload_id;

    // conn_b drives the generic control verbs (no stream of its own, so its
    // responses aren't interleaved with deltas).
    let mut conn_b = connect_hello(&socket).await;

    // status → Some(Observer) for the live workload.
    write_frame(&mut conn_b, 2, &WorkloadStatusRequest { id }, MAX_FRAME)
        .await
        .expect("status request");
    let (header, body) = read_frame(&mut conn_b, MAX_FRAME)
        .await
        .expect("status response");
    assert_eq!(header.action, ids::WORKLOAD_STATUS_RESPONSE);
    assert!(header.flags.is_final());
    let resp: WorkloadStatusResponse = decode_payload(&body).expect("decode status");
    let info = resp.workload.expect("the live workload must be reported");
    assert_eq!(info.id, id);
    assert_eq!(info.kind, WorkloadKind::Observer);

    // stop → Stopped, regardless of conn_a still holding the subscription.
    write_frame(&mut conn_b, 3, &WorkloadStopRequest { id }, MAX_FRAME)
        .await
        .expect("stop request");
    let (header, body) = read_frame(&mut conn_b, MAX_FRAME)
        .await
        .expect("stop response");
    assert_eq!(header.action, ids::WORKLOAD_STOP_RESPONSE);
    assert!(header.flags.is_final());
    let resp: WorkloadStopResponse = decode_payload(&body).expect("decode stop");
    assert_eq!(resp.outcome, WorkloadStopOutcome::Stopped);

    // status again → None: stop removes the registry entry synchronously.
    write_frame(&mut conn_b, 4, &WorkloadStatusRequest { id }, MAX_FRAME)
        .await
        .expect("status request 2");
    let (_header, body) = read_frame(&mut conn_b, MAX_FRAME)
        .await
        .expect("status response 2");
    let resp: WorkloadStatusResponse = decode_payload(&body).expect("decode status 2");
    assert!(
        resp.workload.is_none(),
        "a stopped workload must no longer be reported"
    );

    // stop again → NotFound.
    write_frame(&mut conn_b, 5, &WorkloadStopRequest { id }, MAX_FRAME)
        .await
        .expect("stop request 2");
    let (_header, body) = read_frame(&mut conn_b, MAX_FRAME)
        .await
        .expect("stop response 2");
    let resp: WorkloadStopResponse = decode_payload(&body).expect("decode stop 2");
    assert_eq!(resp.outcome, WorkloadStopOutcome::NotFound);

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn daemon_shutdown_request_answers_then_closes() {
    let (_dir, socket, _shutdown, server) = spawn_server();
    let mut stream = connect_hello(&socket).await;

    // The wire shutdown request acks with ShuttingDown (FINAL) ...
    write_frame(&mut stream, 2, &DaemonShutdownRequest, MAX_FRAME)
        .await
        .expect("shutdown request");
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("shutdown response in time")
        .expect("read shutdown response");
    assert_eq!(header.action, ids::DAEMON_SHUTDOWN_RESPONSE);
    assert!(header.flags.is_final());
    let resp: DaemonShutdownResponse = decode_payload(&body).expect("decode shutdown");
    assert!(matches!(resp.status, ShutdownStatus::ShuttingDown));

    // ... then closes the connection, and the server task drains and exits
    // (the wire request cancelled the server's own shutdown token).
    assert_connection_closed(&mut stream).await;
    let joined = timeout(Duration::from_secs(5), server)
        .await
        .expect("server task drains and exits after the wire shutdown");
    assert!(joined.is_ok(), "server join: {joined:?}");
}

/// How long a test lets `run` take to return after shutdown when a connection
/// is stuck: the server's one-second flush budget plus slack, and well under
/// the ten-second drain timeout a regression would fall back to.
const STUCK_CONNECTION_BOUND: Duration = Duration::from_secs(4);

/// `run` returns only after every connection task has finished, and a
/// connection gets a flush budget after shutdown to finish the dispatch it is
/// in. A client that pauses reading leaves its connection blocked mid-dispatch
/// (the response can't be written); the server waits for it rather than return
/// — in the binary, `main` returning ends the process and would drop that
/// response — and a client that resumes reading within the budget gets it.
#[tokio::test]
async fn shutdown_waits_for_a_connection_mid_dispatch() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let stream = connect_hello(&socket).await;
    // The socket buffers fill, the conn's writer blocks, its out channel fills,
    // and the dispatch in progress blocks on its response.
    let (mut reader, flood) = block_mid_dispatch(stream).await;

    shutdown.cancel();
    let mut server = server;
    assert!(
        timeout(Duration::from_millis(300), &mut server)
            .await
            .is_err(),
        "run returned while a connection was still blocked mid-dispatch"
    );
    // The socket is unlinked before the drain, not after it: a restarting CLI
    // reads the closed listener as "stopped" and may start a new daemon on the
    // same path, whose socket a late unlink would delete.
    assert!(
        !socket.exists(),
        "socket path still present while the drain waits"
    );

    // Start reading, inside the flush budget: the blocked dispatch completes,
    // the conn tears down, and the server finishes its drain.
    let drain = tokio::spawn(async move { read_to_eof(&mut reader).await });
    let joined = timeout(Duration::from_secs(5), server)
        .await
        .expect("server drains once the client reads");
    assert!(joined.is_ok(), "server join: {joined:?}");
    flood.abort();
    timeout(Duration::from_secs(5), drain)
        .await
        .expect("connection closed after the drain")
        .expect("drain task");
}

/// A client that never resumes reading holds its blocked dispatch past the flush
/// budget: the server tears the connection down and returns, instead of waiting
/// out the drain timeout for it.
#[tokio::test]
async fn shutdown_drops_a_mid_dispatch_connection_after_the_flush_budget() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let stream = connect_hello(&socket).await;
    let (mut reader, flood) = block_mid_dispatch(stream).await;

    shutdown.cancel();
    let joined = timeout(STUCK_CONNECTION_BOUND, server)
        .await
        .expect("run returns within the flush budget, not the drain timeout");
    assert!(matches!(joined, Ok(Ok(()))), "server join: {joined:?}");
    flood.abort();

    // The connection is closed: what was buffered reads out, then EOF.
    timeout(Duration::from_secs(5), read_to_eof(&mut reader))
        .await
        .expect("the dropped connection reaches EOF");
}

/// A subscriber that never reads its stream: its read loop ends on shutdown at
/// once (subscription frames are pushed by the collector, not awaited by the
/// dispatch), but its writer is blocked on the full socket. The server aborts
/// the writer after the flush budget instead of waiting out the drain timeout.
#[tokio::test]
async fn shutdown_drops_a_non_reading_subscriber_after_the_flush_budget() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let mut stream = connect_hello(&socket).await;

    // Many subscriptions on one connection, each served a process snapshot at
    // once — far more bytes than the socket buffers hold, so the writer blocks.
    // Fewer than the out channel's depth, so the subscribe dispatches never
    // wait on it: this is the writer-stuck case, not the mid-dispatch one.
    for request_id in 2..202 {
        write_frame(
            &mut stream,
            request_id,
            &ObserverSubscribeRequest {
                domain: ObserverDomain::Process,
            },
            MAX_FRAME,
        )
        .await
        .expect("subscribe");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    shutdown.cancel();
    let joined = timeout(STUCK_CONNECTION_BOUND, server)
        .await
        .expect("run returns within the flush budget, not the drain timeout");
    assert!(matches!(joined, Ok(Ok(()))), "server join: {joined:?}");
    drop(stream);
}

/// The `DaemonShutdownRequest` response reaches a client that is reading, even
/// when it is queued behind a backlog the writer is still flushing: the flush
/// budget covers it. The client pauses before reading so the response sits
/// behind subscription snapshots the socket can't yet take — a budget that cut
/// the writer at once would drop it.
#[tokio::test]
async fn shutdown_response_reaches_a_reading_client_behind_a_backlog() {
    const SHUTDOWN_ID: u32 = 9_999;

    let (_dir, socket, _shutdown, server) = spawn_server();
    let mut stream = connect_hello(&socket).await;

    // Snapshots far past the socket buffers, so the writer blocks; fewer than
    // the out channel's depth, so the read loop stays free to take the request.
    for request_id in 2..102 {
        write_frame(
            &mut stream,
            request_id,
            &ObserverSubscribeRequest {
                domain: ObserverDomain::Process,
            },
            MAX_FRAME,
        )
        .await
        .expect("subscribe");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    write_frame(&mut stream, SHUTDOWN_ID, &DaemonShutdownRequest, MAX_FRAME)
        .await
        .expect("shutdown request");
    // Well inside the budget, but long enough that the writer is still blocked.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let found = timeout(Duration::from_secs(5), async {
        loop {
            match read_frame(&mut stream, MAX_FRAME).await {
                Ok((header, body)) if header.request_id == SHUTDOWN_ID => {
                    assert_eq!(header.action, ids::DAEMON_SHUTDOWN_RESPONSE);
                    let resp: DaemonShutdownResponse =
                        decode_payload(&body).expect("decode shutdown");
                    assert!(matches!(resp.status, ShutdownStatus::ShuttingDown));
                    return true;
                }
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .expect("the stream ends in time");
    assert!(found, "the connection closed without the shutdown response");

    let joined = timeout(STUCK_CONNECTION_BOUND, server)
        .await
        .expect("server finishes its drain");
    assert!(matches!(joined, Ok(Ok(()))), "server join: {joined:?}");
}
