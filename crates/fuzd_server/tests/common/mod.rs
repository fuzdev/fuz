//! Shared harness for `fuzd_server`'s live-socket integration tests.
//!
//! Lives under `tests/common/` so Cargo doesn't compile it as its own test
//! binary — each integration file (`tests/streaming.rs`, `tests/watcher.rs`,
//! `tests/malformed_input.rs`) includes it via `mod common;` and pulls the
//! helpers it needs. The three were each carrying their own byte-identical
//! copy of [`spawn_server`] / `connect_hello`; this is the single source.
//!
//! - [`spawn_server`] — an isolated server on a tempdir socket (empty sidecar
//!   pool), returning the socket path, shutdown token, and join handle;
//!   [`spawn_server_at`] is the same on a socket path the caller names.
//! - [`connect`] — connect to the socket, retrying until the server binds it,
//!   driving no handshake (the caller sends the possibly-malformed first frame).
//! - [`connect_hello`] — [`connect`] plus a full Hello handshake, for the
//!   streaming suites that need an established session.
//! - [`block_mid_dispatch`] — flood a connection with unread requests until its
//!   dispatch blocks, holding the server in its shutdown drain.
//! - [`read_to_eof`] — read a connection out until it closes.

// Test harness: panicking via expect on setup failure is the intended
// behavior; the clippy `allow-expect-in-tests` config only reaches `#[test]`
// fns, not these shared helpers.
#![allow(clippy::expect_used)]

use std::time::Duration;

use fuz_sidecar::SidecarPool;
use fuz_wire::{
    DaemonStatusRequest, HelloRequest, HelloResponse, MAX_FRAME, PROTOCOL_VERSION, decode_payload,
    ids, read_frame, write_frame,
};
use fuzd_server::{RequestLogger, ServerConfig, run};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedReadHalf;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Spawn an isolated server on a tempdir socket; returns the tempdir guard, the
/// socket path, the shutdown token, and the server join handle.
#[allow(dead_code)] // the socket-path suite names its own socket path
pub fn spawn_server() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    CancellationToken,
    tokio::task::JoinHandle<Result<(), fuzd_server::ServerError>>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("socket");
    let (shutdown, handle) = spawn_server_at(&socket);
    (dir, socket, shutdown, handle)
}

/// Spawn a server on a caller-chosen socket path — a second daemon on a path
/// another one already uses; returns the shutdown token and the join handle.
pub fn spawn_server_at(
    socket: &std::path::Path,
) -> (
    CancellationToken,
    tokio::task::JoinHandle<Result<(), fuzd_server::ServerError>>,
) {
    let shutdown = CancellationToken::new();
    let handle = tokio::spawn(run(
        SidecarPool::new(vec![]),
        ServerConfig {
            socket_path: socket.to_path_buf(),
            version: "test".to_string(),
        },
        shutdown.clone(),
        RequestLogger::new(),
    ));
    (shutdown, handle)
}

/// Connect to the socket, retrying until the server has bound it. No Hello
/// handshake — the caller drives the (possibly malformed) first frame.
pub async fn connect(socket: &std::path::Path) -> UnixStream {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(s) = UnixStream::connect(socket).await {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server bound socket in time")
}

/// [`connect`] plus a completed Hello handshake.
#[allow(dead_code)] // the malformed-input suite drives its own first frame
pub async fn connect_hello(socket: &std::path::Path) -> UnixStream {
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
    let (header, body) = read_frame(&mut stream, MAX_FRAME)
        .await
        .expect("read hello");
    assert_eq!(header.action, ids::HELLO_RESPONSE);
    let resp: HelloResponse = decode_payload(&body).expect("decode hello");
    assert_eq!(resp.server_protocol_version, PROTOCOL_VERSION);
    stream
}

/// Pipeline status requests on `stream` without reading any response, until
/// the connection's dispatch blocks on its full out channel. Returns the read
/// half (kept, unread, so the connection stays open) and the flood task.
#[allow(dead_code)] // only the shutdown-drain suites block a dispatch
pub async fn block_mid_dispatch(
    stream: UnixStream,
) -> (OwnedReadHalf, tokio::task::JoinHandle<()>) {
    let (reader, mut writer) = stream.into_split();
    let flood = tokio::spawn(async move {
        for request_id in 2.. {
            if write_frame(&mut writer, request_id, &DaemonStatusRequest, MAX_FRAME)
                .await
                .is_err()
            {
                return;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    (reader, flood)
}

/// Read `reader` until it reaches EOF or fails, discarding what it reads.
#[allow(dead_code)] // only the shutdown-drain suites read a connection out
pub async fn read_to_eof(reader: &mut (impl AsyncRead + Unpin)) {
    let mut buf = vec![0u8; 64 * 1024];
    while matches!(reader.read(&mut buf).await, Ok(n) if n > 0) {}
}
