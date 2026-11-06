//! The UDS is created owner-only (mode 0600) inside an owner-only run dir
//! (mode 0700). Together with the `SO_PEERCRED` same-uid gate this is the
//! daemon's entire access boundary, so pin both modes against accidental
//! loosening.

// Test harness: panicking via expect on setup failure is the intended behavior.
#![allow(clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use fuz_sidecar::SidecarPool;
use fuzd_server::{RequestLogger, ServerConfig, run};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn socket_and_run_dir_are_owner_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let run_dir = dir.path().join("run");
    let socket = run_dir.join("socket");
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(run(
        SidecarPool::new(vec![]),
        ServerConfig {
            socket_path: socket.clone(),
            version: "test".to_string(),
        },
        shutdown.clone(),
        RequestLogger::new(),
    ));

    // The socket file appears at `bind()` and is chmod'd to 0600 immediately
    // after, so poll until the mode settles — this also closes the microscopic
    // bind→chmod window the assertion would otherwise race. A regression that
    // leaves the socket world-readable shows up as a timeout here.
    let socket_mode = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(meta) = std::fs::metadata(&socket) {
                let mode = meta.permissions().mode() & 0o777;
                if mode == 0o600 {
                    return mode;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("socket reached mode 0600 in time");
    assert_eq!(socket_mode, 0o600, "socket must be owner read/write only");

    // The run dir is chmod'd before the socket binds, so by now it's settled.
    let dir_mode = std::fs::metadata(&run_dir)
        .expect("run dir metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "run dir must be owner-only");

    shutdown.cancel();
    let _ = server.await;
}
