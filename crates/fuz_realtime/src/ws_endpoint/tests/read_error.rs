//! Pins the close frame a failed socket read owes the client: 1009 for a
//! message over the upgrade's size cap, nothing for any other failure —
//! and the echo a client's own close frame gets.
//!
//! The in-memory tests drive [`run_ws_loop`] with hand-built read
//! errors; the real-socket test runs [`run_ws_connection`] behind an
//! axum upgrade with a small cap and a raw tungstenite client, so it
//! also pins that axum still boxes the same `tungstenite::Error` type
//! this crate downcasts — a drift between the two tungstenite versions
//! fails here instead of silently regressing to an abnormal drop.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocketUpgrade};
use futures::channel::mpsc;
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;
use tungstenite::error::{CapacityError, ProtocolError};

use crate::connection_registry::{ConnectionGuard, ConnectionRegistry};
use crate::peer::PendingPeerRequests;
use crate::ws_close_codes::{WS_CLOSE_MESSAGE_TOO_BIG, WS_CLOSE_MESSAGE_TOO_BIG_REASON};
use crate::ws_endpoint::{
    MESSAGE_TOO_BIG_CLOSE_LINGER, WsDispatchFn, run_ws_connection, run_ws_loop,
};

/// A dispatch no test here reaches — every frame the tests send fails
/// the read before classification.
fn unreachable_dispatch() -> WsDispatchFn {
    Arc::new(|_| Box::pin(async { panic!("no request reaches dispatch") }))
}

/// Run the loop over in-memory halves, feed it one read error, and
/// return every frame it wrote before exiting plus how long it took to
/// exit (on tokio's clock — the callers pause it, so a linger costs no
/// wall time).
async fn frames_after_read_error(error: tungstenite::Error) -> (Vec<Message>, Duration) {
    let registry = Arc::new(ConnectionRegistry::new());
    let (notify_tx, notify_rx) = crate::connection_channel(1 << 20);
    let signal = CancellationToken::new();
    let conn = registry.add_connection(
        notify_tx,
        crate::ConnectionIdentity::default(),
        signal.clone(),
    );
    let conn_id = conn.id;
    let (client_tx, server_rx) = mpsc::unbounded();
    let (server_tx, client_rx) = mpsc::unbounded();
    let loop_task = tokio::spawn(run_ws_loop(
        server_tx,
        server_rx,
        Arc::clone(&registry),
        conn,
        notify_rx,
        Arc::new(PendingPeerRequests::new(8)),
        unreachable_dispatch(),
        crate::ws_endpoint::WsLoopOptions::default(),
    ));
    let started = tokio::time::Instant::now();
    client_tx
        .unbounded_send(Err(axum::Error::new(error)))
        .expect("loop is reading");
    tokio::time::timeout(Duration::from_secs(5), loop_task)
        .await
        .expect("loop exits within timeout")
        .expect("loop exits cleanly");
    let elapsed = started.elapsed();
    assert!(signal.is_cancelled(), "teardown cancels the socket token");
    assert!(
        !registry.is_registered(conn_id),
        "teardown removes the connection"
    );
    (client_rx.collect().await, elapsed)
}

/// An over-cap read closes with 1009, nothing follows the close, and the
/// socket is held for the linger before it's dropped.
#[tokio::test(start_paused = true)]
async fn oversized_message_closes_with_1009() {
    let (frames, elapsed) = frames_after_read_error(tungstenite::Error::Capacity(
        CapacityError::MessageTooLong {
            size: 2048,
            max_size: 1024,
        },
    ))
    .await;
    match frames.as_slice() {
        [Message::Close(Some(frame))] => {
            assert_eq!(frame.code, WS_CLOSE_MESSAGE_TOO_BIG);
            assert_eq!(frame.reason.as_str(), WS_CLOSE_MESSAGE_TOO_BIG_REASON);
        }
        other => panic!("expected exactly a 1009 close frame, got {other:?}"),
    }
    assert!(
        elapsed >= MESSAGE_TOO_BIG_CLOSE_LINGER,
        "the socket lingers after the 1009 close, exited after {elapsed:?}"
    );
}

/// Any other read failure ends the connection at once without a close
/// frame — the size cap is the only read error with a registered code to
/// send, and the only exit that lingers.
#[tokio::test(start_paused = true)]
async fn other_read_errors_close_without_a_frame() {
    let (frames, elapsed) = frames_after_read_error(tungstenite::Error::Protocol(
        ProtocolError::UnmaskedFrameFromClient,
    ))
    .await;
    assert!(frames.is_empty(), "no close frame, got {frames:?}");
    assert!(
        elapsed < MESSAGE_TOO_BIG_CLOSE_LINGER,
        "no linger, exited after {elapsed:?}"
    );
}

/// Serve [`run_ws_connection`] at `/ws` behind an upgrade capped at
/// `cap` bytes per message and frame; returns the bound address and the
/// server task.
async fn serve_capped(cap: usize) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    serve(Arc::new(ConnectionRegistry::new()), cap, None).await
}

/// Serve [`run_ws_connection`] at `/ws` over `registry`, registering
/// every connection under `account_id` in one step — `add_connection`,
/// then a [`ConnectionGuard`] held for the socket's lifetime. There is no
/// credential behind these connections, so the spine handler's two-phase
/// admission has nothing to re-check here.
pub(super) async fn serve(
    registry: Arc<ConnectionRegistry>,
    cap: usize,
    account_id: Option<uuid::Uuid>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let handler = move |ws: WebSocketUpgrade| {
        let registry = Arc::clone(&registry);
        async move {
            ws.max_message_size(cap)
                .max_frame_size(cap)
                .on_upgrade(move |socket| async move {
                    let (notify_tx, notify_rx) = crate::connection_channel(1 << 20);
                    let conn = registry.add_connection(
                        notify_tx,
                        crate::ConnectionIdentity {
                            account_id,
                            ..crate::ConnectionIdentity::default()
                        },
                        CancellationToken::new(),
                    );
                    let _guard = ConnectionGuard::new(Arc::clone(&registry), conn.id);
                    run_ws_connection(
                        socket,
                        registry,
                        conn,
                        notify_rx,
                        Arc::new(PendingPeerRequests::new(8)),
                        unreachable_dispatch(),
                        crate::ws_endpoint::WsLoopOptions::default(),
                    )
                    .await;
                })
        }
    };
    let app = axum::Router::new().route("/ws", axum::routing::get(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (addr, server)
}

/// Complete the HTTP upgrade by hand (the tungstenite dep carries no
/// client handshake) and hand back the upgraded stream.
pub(super) fn upgrade(addr: std::net::SocketAddr) -> std::net::TcpStream {
    let mut stream = std::net::TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    write!(
        stream,
        "GET /ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .expect("write upgrade request");
    // byte-at-a-time so nothing past the header block is consumed
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read upgrade response");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).expect("utf-8 response head");
    assert!(head.starts_with("HTTP/1.1 101"), "upgrade refused: {head}");
    stream
}

/// Small case over a real upgraded socket, through a tungstenite client:
/// a message over the cap that fits in one read gets a 1009 close frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_message_on_a_real_socket_closes_with_1009() {
    const CAP: usize = 64;
    let (addr, server) = serve_capped(CAP).await;

    let code = tokio::task::spawn_blocking(move || {
        let mut ws = tungstenite::WebSocket::from_raw_socket(
            upgrade(addr),
            tungstenite::protocol::Role::Client,
            None,
        );
        ws.send(tungstenite::Message::text("x".repeat(CAP * 4)))
            .expect("send oversized message");
        loop {
            match ws.read().expect("read until the close frame") {
                tungstenite::Message::Close(Some(frame)) => return u16::from(frame.code),
                tungstenite::Message::Close(None) => panic!("close frame carried no code"),
                _ => {}
            }
        }
    })
    .await
    .expect("client task");

    assert_eq!(code, WS_CLOSE_MESSAGE_TOO_BIG);
    server.abort();
}

/// A client-initiated close is answered with a close frame echoing the
/// client's code — the closing handshake completes, so the client sees a
/// clean close rather than an abnormal 1006.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_close_on_a_real_socket_is_echoed() {
    let (addr, server) = serve_capped(1024).await;

    let reply = tokio::task::spawn_blocking(move || {
        let mut ws = tungstenite::WebSocket::from_raw_socket(
            upgrade(addr),
            tungstenite::protocol::Role::Client,
            None,
        );
        ws.close(Some(tungstenite::protocol::CloseFrame {
            code: tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "bye".into(),
        }))
        .expect("send close");
        loop {
            match ws.read() {
                Ok(tungstenite::Message::Close(frame)) => {
                    return frame.map(|f| (u16::from(f.code), f.reason.to_string()));
                }
                Ok(_) => {}
                Err(e) => panic!("connection ended without a close reply: {e}"),
            }
        }
    })
    .await
    .expect("client task");

    assert_eq!(reply, Some((1000, "bye".to_owned())));
    server.abort();
}

/// Read one server frame off `stream` and return its close code, or
/// `None` if the stream fails first — what a browser reports as 1006.
fn read_close_code(stream: &mut std::net::TcpStream) -> Option<u16> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).ok()?;
    assert_eq!(header[0], 0x88, "expected a FIN close frame first");
    let len = usize::from(header[1]);
    assert!((2..126).contains(&len), "unmasked short close payload");
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).ok()?;
    Some(u16::from_be_bytes([payload[0], payload[1]]))
}

/// How long the modeled client takes to get to its read — the window in
/// which a busy client (an event loop mid-write) can see its write fail
/// before it reads what arrived.
const CLIENT_READ_DELAY: Duration = Duration::from_millis(200);

/// Large case, the shape a real client hits: an 8 MiB message against a
/// 64 KiB cap, far past what one read (or the socket buffers) holds.
/// tungstenite refuses at the frame header while the payload is still in
/// flight, so the server tears down with unread inbound bytes — a RST on
/// Linux. The client models Node's `ws`: it keeps writing on one thread,
/// and if a write fails before it gets to its read, the socket is
/// destroyed and the close frame is never seen (1006). Without the
/// linger the RST lands inside [`CLIENT_READ_DELAY`]; with it the write
/// is still pending (or done) when the client reads the 1009.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_multi_read_message_on_a_real_socket_closes_with_1009() {
    const CAP: usize = 64 * 1024;
    const MESSAGE_BYTES: usize = 8 * 1024 * 1024;
    let (addr, server) = serve_capped(CAP).await;

    let code = tokio::task::spawn_blocking(move || {
        let mut reader = upgrade(addr);
        let mut writer = reader.try_clone().expect("clone stream");
        let write_failed = Arc::new(AtomicBool::new(false));
        let write_task = std::thread::spawn({
            let write_failed = Arc::clone(&write_failed);
            move || {
                // one masked text frame; an all-zero mask leaves the payload as-is
                let mut frame = vec![0x81, 0x80 | 127];
                frame.extend_from_slice(&(MESSAGE_BYTES as u64).to_be_bytes());
                frame.extend_from_slice(&[0, 0, 0, 0]);
                frame.resize(frame.len() + MESSAGE_BYTES, b'x');
                if writer.write_all(&frame).is_err() {
                    write_failed.store(true, Ordering::SeqCst);
                }
            }
        });
        std::thread::sleep(CLIENT_READ_DELAY);
        let code = if write_failed.load(Ordering::SeqCst) {
            None
        } else {
            read_close_code(&mut reader)
        };
        write_task.join().expect("writer thread");
        code
    })
    .await
    .expect("client task");

    assert_eq!(
        code,
        Some(WS_CLOSE_MESSAGE_TOO_BIG),
        "the close frame must reach the client before the connection resets"
    );
    server.abort();
}
