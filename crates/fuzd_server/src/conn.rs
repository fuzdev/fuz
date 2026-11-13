//! UDS accept loop + per-connection read/dispatch loop.
//!
//! Each connection runs two tasks. The **read loop** parses inbound
//! frames and dispatches them; the **writer task** owns the socket's write
//! half and serializes every outgoing frame pulled off a bounded channel.
//! Splitting them is what makes streaming possible: a workload collector
//! can push frames for a subscription while the read loop is parked on the
//! next request, and a slow socket backs up onto the channel instead of
//! blocking the daemon.

use std::sync::Arc;
use std::time::Duration;

use fuz_sidecar::Sidecar;
use fuz_wire::{MAX_FRAME, ProtoError, read_frame, write_raw_frame};
use tokio::io::AsyncWrite;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, trace, warn};

use crate::AppState;
use crate::auth::AuthContext;
use crate::dispatch;
use crate::error::ServerError;
use crate::out::{OUT_CHANNEL_CAP, OutFrame, OutRx};

const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// How long a connection may keep running once shutdown fires: to finish the
/// dispatch it is in and flush its writer. A client that is reading — the one
/// that sent `DaemonShutdownRequest` above all — gets everything queued for it
/// well inside this; a client that has stopped reading would otherwise hold its
/// connection, and so the daemon's drain, until the drain timeout.
const SHUTDOWN_FLUSH_BUDGET: Duration = Duration::from_secs(1);

/// Decide whether a UDS peer should be admitted, given its kernel-reported
/// `SO_PEERCRED` uid (`None` when the credential could not be read) and the
/// daemon's own uid.
///
/// fuzd is single-user: only a peer whose uid matches the daemon's is
/// admitted. A peer whose credential is **unavailable** (`None`) is rejected
/// fail-closed — never defaulted to a concrete uid — so a `peer_cred()`
/// failure cannot masquerade as uid 0 and slip past a root-run daemon. This
/// is the daemon's entire authentication boundary, so it is a pure function
/// pinned by unit tests rather than inline accept-loop logic.
#[must_use]
fn should_accept_peer(peer_uid: Option<u32>, daemon_uid: u32) -> bool {
    peer_uid == Some(daemon_uid)
}

/// Accept connections on the bound UDS, spawning a per-connection task
/// for each one on `connections`, so shutdown can wait for them to finish.
/// Rejects cross-uid peers at accept (fuzd is single-user).
pub async fn accept_uds<S>(
    listener: UnixListener,
    state: Arc<AppState<S>>,
    daemon_uid: u32,
    shutdown: CancellationToken,
    connections: TaskTracker,
) -> Result<(), ServerError>
where
    S: Sidecar + 'static,
{
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                debug!("uds accept loop: shutdown");
                return Ok(());
            }
            res = listener.accept() => match res {
                Ok((stream, _addr)) => {
                    let cred = stream.peer_cred().ok();
                    let peer_uid = cred.as_ref().map(tokio::net::unix::UCred::uid);
                    let peer_pid = cred.and_then(|c| c.pid());
                    // fuzd is single-user: cross-uid peers (and peers whose
                    // credential could not be read) have no use case and any
                    // such connection signals misconfiguration or attack.
                    // Close at accept.
                    if !should_accept_peer(peer_uid, daemon_uid) {
                        warn!(uid = ?peer_uid, "rejected uds peer: uid mismatch or unreadable credential");
                        drop(stream);
                        continue;
                    }
                    // `should_accept_peer` guarantees `peer_uid == Some(daemon_uid)`.
                    let ctx = AuthContext {
                        level: fuz_wire::AuthLevel::Keeper,
                    };
                    trace!(uid = daemon_uid, ?peer_pid, "uds accepted");
                    let state = Arc::clone(&state);
                    let shutdown = shutdown.clone();
                    connections.spawn(async move {
                        if let Err(err) = run_conn(stream, ctx, state, shutdown).await {
                            warn!(
                                error = %fuz_sys::cli::format_error_chain(&err),
                                "uds conn ended with error"
                            );
                        }
                    });
                }
                Err(err) => {
                    warn!(error = %fuz_sys::cli::format_error_chain(&err), "uds accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            }
        }
    }
}

/// The per-connection writer task: own the write half and serialize every
/// outgoing frame. Exits when the channel closes (all senders dropped) or
/// a write fails (peer gone).
///
/// Every producer sizes its frames to the frame limit before queueing them
/// (`OutFrame::response`, the collectors' frame splitting), so a frame the
/// limit refuses is a daemon bug. Nothing about a pre-encoded frame can be cut
/// to fit, and skipping it would leave a gap the peer can't see, so the writer
/// closes the connection — loudly, at warn, since the peer only sees it end.
pub async fn writer_task<W>(mut writer: W, mut rx: OutRx)
where
    W: AsyncWrite + Unpin + Send,
{
    while let Some(frame) = rx.recv().await {
        match write_raw_frame(
            &mut writer,
            frame.request_id,
            frame.action,
            frame.flags,
            &frame.body,
            MAX_FRAME,
        )
        .await
        {
            Ok(()) => {}
            Err(err @ ProtoError::FrameTooLarge { .. }) => {
                warn!(
                    error = %fuz_sys::cli::format_error_chain(&err),
                    action = %frame.action,
                    "conn writer: an outgoing frame exceeds the frame limit, closing the connection"
                );
                break;
            }
            Err(err) => {
                debug!(
                    error = %fuz_sys::cli::format_error_chain(&err),
                    "conn writer: write failed, closing"
                );
                break;
            }
        }
    }
}

/// Serve one connection until the peer closes it, a handler ends it, or
/// shutdown does.
///
/// The peer-closed path waits for the writer to flush everything queued. Once
/// shutdown fires, the whole connection — a dispatch blocked on a full out
/// channel as much as a writer blocked on a socket nobody reads — gets
/// [`SHUTDOWN_FLUSH_BUDGET`], then is torn down: the read loop is dropped
/// mid-dispatch, the writer aborted with whatever it still holds.
async fn run_conn<S>(
    stream: tokio::net::UnixStream,
    ctx: AuthContext,
    state: Arc<AppState<S>>,
    shutdown: CancellationToken,
) -> Result<(), ServerError>
where
    S: Sidecar + 'static,
{
    let (mut reader, writer) = stream.into_split();
    let (out_tx, out_rx) = mpsc::channel::<OutFrame>(OUT_CHANNEL_CAP);
    let mut writer_handle = tokio::spawn(writer_task(writer, out_rx));
    let conn_id = state.workloads.next_conn_id();

    // Never completes until shutdown; then completes one budget later. Polled
    // by both races below, but never again once it has completed.
    let flush_deadline = async {
        shutdown.cancelled().await;
        tokio::time::sleep(SHUTDOWN_FLUSH_BUDGET).await;
    };
    tokio::pin!(flush_deadline);

    let result = tokio::select! {
        biased;
        result = read_loop(&mut reader, ctx, &state, &out_tx, conn_id, &shutdown) => Some(result),
        () = &mut flush_deadline => None,
    };

    // Tear down this connection's subscriptions (refcount--, idle-grace),
    // then drop our sender so the writer task drains and exits. Collector
    // clones of `out_tx` drop as they process the DropConnection command.
    state.workloads.drop_connection(conn_id).await;
    drop(out_tx);
    let flushed = match result {
        Some(_) => tokio::select! {
            biased;
            _ = &mut writer_handle => true,
            () = &mut flush_deadline => false,
        },
        None => false,
    };
    if !flushed {
        warn!(
            conn_id,
            "conn: shutdown flush budget spent, dropping the connection with frames unsent"
        );
        writer_handle.abort();
        // Returns as soon as the abort lands, closing the write half before
        // the connection task ends.
        let _ = writer_handle.await;
    }
    result.unwrap_or(Ok(()))
}

async fn read_loop<S>(
    reader: &mut tokio::net::unix::OwnedReadHalf,
    ctx: AuthContext,
    state: &AppState<S>,
    out_tx: &crate::out::OutTx,
    conn_id: u64,
    shutdown: &CancellationToken,
) -> Result<(), ServerError>
where
    S: Sidecar + 'static,
{
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                debug!("conn: shutdown");
                return Ok(());
            }
            res = read_frame(reader, MAX_FRAME) => {
                let (header, payload) = match res {
                    Ok(v) => v,
                    Err(ProtoError::Io(err)) if matches!(
                        err.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset,
                    ) => {
                        debug!("conn: peer closed");
                        return Ok(());
                    }
                    Err(err) => return Err(err.into()),
                };
                match dispatch::dispatch(header, &payload, ctx, state, out_tx, conn_id).await {
                    Ok(true) => {}
                    // Handler signalled "done" (Goodbye / shutdown), or the
                    // writer task is gone (peer closed mid-response).
                    Ok(false) | Err(ServerError::ConnectionClosed) => return Ok(()),
                    Err(err) => return Err(err),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::should_accept_peer;

    #[test]
    fn accepts_same_uid_peer() {
        assert!(should_accept_peer(Some(1000), 1000));
    }

    #[test]
    fn rejects_cross_uid_peer() {
        assert!(!should_accept_peer(Some(1001), 1000));
        // a uid-0 (root) peer is still rejected by a non-root daemon
        assert!(!should_accept_peer(Some(0), 1000));
    }

    #[test]
    fn rejects_peer_with_unreadable_credential() {
        // A `peer_cred()` failure must fail closed — never defaulted to a
        // concrete uid that could match the daemon's own.
        assert!(!should_accept_peer(None, 1000));
        // ...and crucially not even when the daemon runs as root (uid 0):
        // an unreadable credential must not masquerade as uid 0 and be
        // admitted. This is the regression guard against a `map_or(0, …)`
        // default, which would accept such a peer.
        assert!(!should_accept_peer(None, 0));
    }

    #[test]
    fn accepts_root_peer_only_for_root_daemon() {
        assert!(should_accept_peer(Some(0), 0));
        assert!(!should_accept_peer(Some(0), 1000));
    }

    #[tokio::test]
    async fn the_writer_closes_the_connection_on_a_frame_past_the_limit() {
        use crate::out::OutFrame;
        use fuz_wire::{FrameFlags, HEADER_BYTES, MAX_FRAME, ids};
        use tokio::io::AsyncReadExt;
        let (daemon_end, mut client) = tokio::net::UnixStream::pair().unwrap();
        let (_read, write) = daemon_end.into_split();
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let writer = tokio::spawn(super::writer_task(write, rx));
        let frame = |len: usize| OutFrame {
            request_id: 1,
            action: ids::WATCHER_EVENT_FRAME,
            flags: FrameFlags::EMPTY,
            body: vec![0; len],
        };
        tx.send(frame((MAX_FRAME - HEADER_BYTES) as usize + 1))
            .await
            .unwrap();
        tx.send(frame(1)).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), writer)
            .await
            .expect("the writer ends on the refused frame, its sender still alive")
            .unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(
            rest.is_empty(),
            "nothing after the refused frame: {} bytes",
            rest.len()
        );
        drop(tx);
    }
}
