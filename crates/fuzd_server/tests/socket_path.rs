//! The socket path's length limit: `run` refuses a path longer than a Unix
//! socket address holds with [`ServerError::SocketPathTooLong`] before it
//! creates, locks, or binds anything, and serves on a path exactly at
//! [`SOCKET_PATH_MAX`].
//!
//! Without the up-front check the kernel's refusal surfaces as the generic
//! [`ServerError::Bind`], whose message names no cause — and only after the run
//! dir and the lock file were made.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::time::timeout;

use fuz_sidecar::SidecarPool;
use fuzd_server::{RequestLogger, SOCKET_PATH_MAX, ServerConfig, ServerError, run};
use tokio_util::sync::CancellationToken;

mod common;
use common::{connect_hello, spawn_server_at};

/// A socket path of exactly `len` bytes under `base`: `<base>/<padding>/socket`.
fn socket_path_of_len(base: &Path, len: usize) -> PathBuf {
    let fixed = base.as_os_str().len() + "/".len() + "/socket".len();
    assert!(
        len > fixed,
        "tempdir {} leaves no room for padding",
        base.display()
    );
    let path = base.join("p".repeat(len - fixed)).join("socket");
    assert_eq!(path.as_os_str().len(), len);
    path
}

#[tokio::test]
async fn an_overlong_socket_path_is_refused_before_anything_is_created() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = socket_path_of_len(dir.path(), SOCKET_PATH_MAX + 1);

    // A refusal is the only way `run` returns inside the timeout.
    let result = timeout(
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
    .expect("an overlong path is refused, not served");

    let error = result.expect_err("an overlong path is refused");
    match &error {
        ServerError::SocketPathTooLong { path, len, max } => {
            assert_eq!(*path, socket);
            assert_eq!(*len, SOCKET_PATH_MAX + 1);
            assert_eq!(*max, SOCKET_PATH_MAX);
        }
        other => panic!("expected SocketPathTooLong, got {other:?}"),
    }
    // The message names the cause and the hint names the fix.
    let message = error.to_string();
    assert!(message.contains("108 bytes"), "{message}");
    assert!(message.contains("107-byte limit"), "{message}");
    let hint = error.hint().expect("a hint");
    assert!(hint.contains("FUZ_HOME"), "{hint}");

    // Nothing was made: not the run dir, so not the lock file or the socket.
    let run_dir = socket.parent().expect("parent");
    assert!(!run_dir.exists(), "{} was created", run_dir.display());
}

#[tokio::test]
async fn the_limit_counts_bytes_not_chars() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Padding of two-byte `é`s: at most `SOCKET_PATH_MAX` chars, over it in
    // bytes — `sun_path` holds bytes.
    let fixed = dir.path().as_os_str().len() + "/".len() + "/socket".len();
    let pad_chars = SOCKET_PATH_MAX - fixed;
    let socket = dir.path().join("é".repeat(pad_chars)).join("socket");
    let bytes = socket.as_os_str().len();
    let chars = socket.to_str().expect("utf-8").chars().count();
    assert!(
        chars <= SOCKET_PATH_MAX && bytes > SOCKET_PATH_MAX,
        "{chars} chars, {bytes} bytes"
    );

    let result = timeout(
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
    .expect("an overlong path is refused, not served");
    match result {
        Err(ServerError::SocketPathTooLong { path, len, max }) => {
            assert_eq!(path, socket);
            assert_eq!(len, bytes);
            assert_eq!(max, SOCKET_PATH_MAX);
        }
        other => panic!("expected SocketPathTooLong, got {other:?}"),
    }
}

#[tokio::test]
async fn a_socket_path_at_the_limit_serves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = socket_path_of_len(dir.path(), SOCKET_PATH_MAX);

    let (shutdown, server) = spawn_server_at(&socket);
    let _conn = connect_hello(&socket).await;

    shutdown.cancel();
    let joined = timeout(Duration::from_secs(5), server)
        .await
        .expect("server shuts down");
    assert!(matches!(joined, Ok(Ok(()))), "server join: {joined:?}");
}
