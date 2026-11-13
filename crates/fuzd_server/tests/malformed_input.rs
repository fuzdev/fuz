//! Server-side reaction to malformed / adversarial frames over a real UDS.
//!
//! The codec *guards* (oversized-before-alloc, too-small) are unit-tested in
//! `fuz_wire::codec`; this suite asserts the *server's reaction* to bad input
//! over a live socket: it drops the offending connection, never panics, and
//! keeps serving other connections (no partial / corrupt shared state). A
//! fresh connection completing a Hello + `WorkloadList` round-trip after each
//! bad frame is the "daemon survived" proof.
//!
//! Protocol-version mismatch is the one malformed input the server handles
//! *gracefully* — it answers `HelloOutcome::VersionMismatch` and leaves the
//! connection open — so its assertion is the inverse: a well-formed response
//! and a still-usable socket.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside `#[test]` fns panic on a failed setup or check"
)]

use std::time::Duration;

use fuz_wire::{
    ActionId, FrameFlags, HelloOutcome, HelloRequest, HelloResponse, MAX_FRAME, PROTOCOL_VERSION,
    Ping, Pong, WorkloadListRequest, WorkloadListResponse, decode_payload, ids, read_frame,
    write_frame, write_raw_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

mod common;
use common::{connect, spawn_server};

/// Assert the server closed this connection: the next read sees EOF (a clean
/// FIN → `Ok(0)`) or a reset. Either way no further frame arrives.
async fn assert_connection_closed(stream: &mut UnixStream) {
    let mut buf = [0u8; 1];
    let result = timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("server closed the connection in time");
    // A clean FIN reads `Ok(0)`; a reset reads `Err` — both mean "closed".
    // Any actual bytes would mean the server replied instead of dropping us.
    if let Ok(n) = result {
        assert_eq!(n, 0, "expected the connection to be closed, read {n} bytes");
    }
}

/// Open a *fresh* connection and drive a full Hello + `WorkloadList` round-trip.
/// Proves the daemon survived a prior bad frame: it still accepts connections,
/// completes the handshake `Ok`, and serves a real request from clean state.
async fn assert_server_healthy(socket: &std::path::Path) {
    let mut stream = connect(socket).await;

    write_frame(
        &mut stream,
        1,
        &HelloRequest {
            protocol_version: PROTOCOL_VERSION,
        },
        MAX_FRAME,
    )
    .await
    .expect("write hello");
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("hello response in time")
        .expect("read hello");
    assert_eq!(header.action, ids::HELLO_RESPONSE);
    let resp: HelloResponse = decode_payload(&body).expect("decode hello");
    assert!(
        matches!(resp.outcome, HelloOutcome::Ok),
        "fresh handshake should be Ok, got {:?}",
        resp.outcome
    );

    write_frame(&mut stream, 2, &WorkloadListRequest, MAX_FRAME)
        .await
        .expect("write workload list");
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("list response in time")
        .expect("read list");
    assert_eq!(header.action, ids::WORKLOAD_LIST_RESPONSE);
    let list: WorkloadListResponse = decode_payload(&body).expect("decode list");
    assert!(
        list.workloads.is_empty(),
        "a freshly-spawned server holds no workloads"
    );
}

#[tokio::test]
async fn unknown_action_id_closes_connection_then_server_serves_others() {
    let (_dir, socket, shutdown, server) = spawn_server();

    // A frame carrying an action id the dispatch table doesn't know
    // (0xFFFF is well past the highest assigned id).
    let mut bad = connect(&socket).await;
    write_raw_frame(
        &mut bad,
        1,
        ActionId(0xFFFF),
        FrameFlags::FINAL,
        &[],
        MAX_FRAME,
    )
    .await
    .expect("write unknown-action frame");
    assert_connection_closed(&mut bad).await;

    // A separate connection is unaffected — no panic, no corrupt state.
    assert_server_healthy(&socket).await;

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn undecodable_payload_closes_connection_then_server_serves_others() {
    let (_dir, socket, shutdown, server) = spawn_server();

    // A known action id (HELLO) carrying a body that doesn't postcard-decode
    // to its payload type: five 0xFF bytes are an overlong varint, never a
    // valid `u32` `protocol_version`.
    let mut bad = connect(&socket).await;
    write_raw_frame(
        &mut bad,
        1,
        ids::HELLO_REQUEST,
        FrameFlags::FINAL,
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        MAX_FRAME,
    )
    .await
    .expect("write garbage-payload frame");
    assert_connection_closed(&mut bad).await;

    assert_server_healthy(&socket).await;

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn oversized_frame_rejected_before_alloc_closes_connection() {
    let (_dir, socket, shutdown, server) = spawn_server();

    // Just the 4-byte length prefix, claiming a frame far larger than
    // MAX_FRAME. `read_frame` rejects it (FrameTooLarge) *before* allocating a
    // buffer, and the read loop drops the connection — so the declared
    // multi-GiB length never turns into a multi-GiB read.
    let mut bad = connect(&socket).await;
    bad.write_u32(u32::MAX)
        .await
        .expect("write oversized length prefix");
    bad.flush().await.expect("flush");
    assert_connection_closed(&mut bad).await;

    assert_server_healthy(&socket).await;

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn protocol_version_mismatch_is_answered_not_closed() {
    let (_dir, socket, shutdown, server) = spawn_server();

    let mut stream = connect(&socket).await;
    // A Hello carrying a protocol version the server doesn't speak.
    let their_version = PROTOCOL_VERSION + 1;
    write_frame(
        &mut stream,
        1,
        &HelloRequest {
            protocol_version: their_version,
        },
        MAX_FRAME,
    )
    .await
    .expect("write hello");

    // The server answers with a VersionMismatch outcome — it does NOT close.
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("hello response in time")
        .expect("read hello response");
    assert_eq!(header.action, ids::HELLO_RESPONSE);
    let resp: HelloResponse = decode_payload(&body).expect("decode hello response");
    assert_eq!(resp.server_protocol_version, PROTOCOL_VERSION);
    match resp.outcome {
        HelloOutcome::VersionMismatch { ours, theirs } => {
            assert_eq!(ours, PROTOCOL_VERSION);
            assert_eq!(theirs, their_version);
        }
        other @ HelloOutcome::Ok => panic!("expected VersionMismatch, got {other:?}"),
    }

    // The connection stays usable: a follow-up request still gets a response.
    write_frame(&mut stream, 2, &Ping, MAX_FRAME)
        .await
        .expect("write ping");
    let (header, body) = timeout(Duration::from_secs(5), read_frame(&mut stream, MAX_FRAME))
        .await
        .expect("pong in time")
        .expect("read pong");
    assert_eq!(header.action, ids::PONG);
    let _: Pong = decode_payload(&body).expect("decode pong");

    shutdown.cancel();
    let _ = server.await;
}
