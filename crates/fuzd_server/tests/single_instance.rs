//! One daemon per socket path: `run` takes an exclusive lock beside the socket
//! before it unlinks or binds anything, and gives it up with the socket at
//! shutdown, ahead of the connection drain.
//!
//! The bind unlinks a leftover socket first, so without the lock a second
//! daemon on the same path silently takes a running one's socket. The release
//! timing matters as much as the lock: a restarting CLI starts the next daemon
//! while this one is still draining, and a lock held to exit would refuse it.

use std::time::Duration;

use tokio::time::timeout;

use fuz_sidecar::SidecarPool;
use fuzd_server::{RequestLogger, ServerConfig, ServerError, run};
use tokio_util::sync::CancellationToken;

mod common;
use common::{block_mid_dispatch, connect_hello, read_to_eof, spawn_server, spawn_server_at};

/// A second `run` on a live daemon's socket path refuses with `AlreadyRunning`
/// naming the holder, and the first keeps the path: a fresh connection still
/// completes a Hello with it.
#[tokio::test]
async fn a_second_run_on_a_live_socket_path_refuses() {
    let (_dir, socket, shutdown, server) = spawn_server();
    // The first daemon is bound and answering, so it holds the lock.
    let _first = connect_hello(&socket).await;

    // `run` returns only at shutdown once it binds, so a refusal is the only
    // way it finishes inside the timeout.
    let second = timeout(
        Duration::from_secs(5),
        run(
            SidecarPool::new(vec![]),
            ServerConfig {
                socket_path: socket.clone(),
                version: "test".to_string(),
            },
            CancellationToken::new(),
            RequestLogger::new(),
        ),
    )
    .await
    .expect("the second run refuses instead of serving");
    match second {
        Err(ServerError::AlreadyRunning { socket_path, pid }) => {
            assert_eq!(socket_path, socket);
            assert_eq!(pid, Some(std::process::id()), "the holder's pid");
        }
        other => panic!("expected AlreadyRunning, got {other:?}"),
    }

    // Nothing was unlinked or rebound: the path still reaches the first daemon.
    let _again = connect_hello(&socket).await;

    shutdown.cancel();
    let joined = timeout(Duration::from_secs(5), server)
        .await
        .expect("first server shuts down");
    assert!(
        matches!(joined, Ok(Ok(()))),
        "first server join: {joined:?}"
    );
}

/// The lock goes with the socket at shutdown, not with the process: while the
/// first daemon is still draining a stuck connection, a second `run` on the same
/// path takes it and serves, and the first finishing its drain leaves the
/// second's socket alone.
#[tokio::test]
async fn the_socket_lock_is_released_before_the_drain() {
    let (_dir, socket, shutdown, server) = spawn_server();
    let stream = connect_hello(&socket).await;
    // The connection blocks mid-dispatch and holds the first daemon in its
    // drain.
    let (mut reader, flood) = block_mid_dispatch(stream).await;

    // The drain lasts at most the server's one-second flush budget, so the
    // steps up to the `is_finished` check below are kept short.
    shutdown.cancel();
    let mut server = server;
    assert!(
        timeout(Duration::from_millis(100), &mut server)
            .await
            .is_err(),
        "the first server finished instead of draining the stuck connection"
    );

    // A new daemon on the same path while the first drains: it must not be
    // refused as already running (a refusal returns at once).
    let (second_shutdown, mut second) = spawn_server_at(&socket);
    let early = timeout(Duration::from_millis(100), &mut second).await;
    assert!(
        early.is_err(),
        "the second server exited while the first drained: {early:?}"
    );
    let _hello = connect_hello(&socket).await;
    assert!(
        !server.is_finished(),
        "the first server must still be draining for this to test the release timing"
    );

    // Let the first finish its drain — a flush if the read starts inside the
    // budget, a teardown otherwise; the second's socket survives either.
    let drain = tokio::spawn(async move { read_to_eof(&mut reader).await });
    let joined = timeout(Duration::from_secs(5), server)
        .await
        .expect("first server drains once the client reads");
    assert!(
        matches!(joined, Ok(Ok(()))),
        "first server join: {joined:?}"
    );
    flood.abort();
    timeout(Duration::from_secs(5), drain)
        .await
        .expect("connection closed after the drain")
        .expect("drain task");
    let _still_served = connect_hello(&socket).await;

    second_shutdown.cancel();
    let joined = timeout(Duration::from_secs(5), second)
        .await
        .expect("second server shuts down");
    assert!(
        matches!(joined, Ok(Ok(()))),
        "second server join: {joined:?}"
    );
}
