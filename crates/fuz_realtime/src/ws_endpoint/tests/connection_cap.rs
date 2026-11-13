//! Pins the per-account connection cap end to end over real upgraded
//! sockets: the superseded socket gets a 4004 close frame (not 4001 —
//! its credential is still good), the newer socket stays open, and a
//! plain revocation still closes with 4001.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use fuz_auth::ConnectionCloser;

use super::read_error::{serve, upgrade};
use crate::connection_registry::ConnectionRegistry;
use crate::ws_close_codes::{
    WS_CLOSE_CONNECTION_LIMIT, WS_CLOSE_CONNECTION_LIMIT_REASON, WS_CLOSE_SESSION_REVOKED,
};

type ClientSocket = tungstenite::WebSocket<std::net::TcpStream>;

/// Upgrade a tungstenite client against `addr`.
fn connect(addr: std::net::SocketAddr) -> ClientSocket {
    tungstenite::WebSocket::from_raw_socket(
        upgrade(addr),
        tungstenite::protocol::Role::Client,
        None,
    )
}

/// Read until the server's close frame and return its code and reason;
/// panics if the read times out or the stream ends without one.
fn read_close(ws: &mut ClientSocket) -> (u16, String) {
    loop {
        match ws.read().expect("read until the close frame") {
            tungstenite::Message::Close(Some(frame)) => {
                return (u16::from(frame.code), frame.reason.to_string());
            }
            tungstenite::Message::Close(None) => panic!("close frame carried no code"),
            _ => {}
        }
    }
}

/// Poll until `account` holds `expected` registered connections — the
/// server registers in `on_upgrade`, after the 101 the client has
/// already read.
async fn wait_for_count(registry: &ConnectionRegistry, account: uuid::Uuid, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while registry.connection_count_for_account(account) != expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("connection count reached within timeout");
}

/// With a cap of 1, a second socket on the account closes the first with
/// 4004 [`WS_CLOSE_CONNECTION_LIMIT_REASON`] and stays open itself — shown by its first
/// frame being the 4001 a later revocation sends, not a 4004.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_socket_supersedes_the_first_with_4004() {
    let account = uuid::Uuid::new_v4();
    let registry =
        Arc::new(ConnectionRegistry::new().with_max_connections_per_account(NonZeroUsize::new(1)));
    let (addr, server) = serve(Arc::clone(&registry), 1024, Some(account)).await;

    let mut first = tokio::task::spawn_blocking(move || connect(addr))
        .await
        .expect("first client");
    wait_for_count(&registry, account, 1).await;

    let mut second = tokio::task::spawn_blocking(move || connect(addr))
        .await
        .expect("second client");
    let (first, first_close) = tokio::task::spawn_blocking(move || {
        let close = read_close(&mut first);
        (first, close)
    })
    .await
    .expect("first client read");
    assert_eq!(
        first_close,
        (
            WS_CLOSE_CONNECTION_LIMIT,
            WS_CLOSE_CONNECTION_LIMIT_REASON.to_owned()
        ),
        "the superseded socket closes with 4004, not 4001"
    );
    drop(first);

    wait_for_count(&registry, account, 1).await;
    assert_eq!(
        registry.close_connections(&fuz_auth::ConnectionCloseTarget::Account(account)),
        1
    );
    let (code, _) = tokio::task::spawn_blocking(move || read_close(&mut second))
        .await
        .expect("second client read");
    assert_eq!(
        code, WS_CLOSE_SESSION_REVOKED,
        "the newer socket stayed open, and a plain revocation still closes with 4001"
    );
    server.abort();
}
