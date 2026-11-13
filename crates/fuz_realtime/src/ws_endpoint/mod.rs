//! WS upgrade + dispatch loop primitive.
//!
//! The transport "bones" — origin / auth resolution happens in the
//! consumer's axum handler (before calling [`run_ws_connection`]);
//! parsing, classification, the `select!` loop, and revocation-aware
//! close are owned here. The per-request `perform_action` dispatch
//! body lives in `fuz_actions` — this crate exposes a
//! callback hook so the realtime crate stays free of action-spec
//! knowledge.
//!
//! An upgrade the consumer's handler refuses at admission is closed here
//! too: [`refuse_upgrade`] writes the [`UpgradeRefusal`]'s close frame (4001,
//! 4006, 1001, or 1011) and lingers briefly, so the client reads the code, not
//! a reset.
//!
//! Three shape decisions:
//!
//! 1. **Connection state owned by [`ConnectionRegistry`]**, not by the
//!    consumer's app struct.
//! 2. **Dispatch via consumer-supplied [`WsDispatchFn`]** — closure
//!    over the consumer's action registry; the WS loop only knows
//!    "give me wire text for this classified request, please."
//! 3. **`signal` cancellation propagated through the registry** so
//!    audit-driven revocation cancels streaming handlers without the
//!    WS loop needing to observe revocation directly (already wired
//!    through the `ConnectionRegistry::close_connections` path via the per-
//!    connection token stored in `ConnectionInfo.signal`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc::error::TryRecvError;
use tokio_util::sync::CancellationToken;

use fuz_http::{Classified, SHUTDOWN_CLOSE_TIMEOUT, classify, error_response, jsonrpc_error};

use crate::connection::{CloseReason, Connection, ConnectionReceiver, NotAdmitted};
use crate::connection_registry::ConnectionRegistry;
use crate::credential_deadline::credential_deadline_reached;
use crate::notify::ws_notify_for_connection;
use crate::peer::{DEFAULT_PEER_REQUEST_TIMEOUT, PendingPeerRequests, audit_unmatched_response};
use crate::ws_close_codes::{
    WS_CLOSE_CONNECTION_LIMIT, WS_CLOSE_CONNECTION_LIMIT_REASON,
    WS_CLOSE_CREDENTIAL_EXPIRED_REASON, WS_CLOSE_GOING_AWAY, WS_CLOSE_GOING_AWAY_REASON,
    WS_CLOSE_INTERNAL_ERROR, WS_CLOSE_INTERNAL_ERROR_REASON, WS_CLOSE_MESSAGE_TOO_BIG,
    WS_CLOSE_MESSAGE_TOO_BIG_REASON, WS_CLOSE_OUTBOUND_OVERFLOW, WS_CLOSE_OUTBOUND_OVERFLOW_REASON,
    WS_CLOSE_PERMISSION_REVOKED, WS_CLOSE_PERMISSION_REVOKED_REASON,
    WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT, WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT_REASON,
    WS_CLOSE_SESSION_REVOKED, WS_CLOSE_SESSION_REVOKED_REASON,
};
use crate::ws_signals::PendingRequestSignals;

/// The `cancel` protocol method's wire name.
///
/// The frontend sends `{jsonrpc, method: "cancel", params: {request_id}}` — a
/// JSON-RPC **notification**, no `id` — to abort an in-flight request on the
/// same socket. Mirrors `fuz_app/src/lib/actions/cancel.ts`.
///
/// `cancel` is owned by the read loop, not by a handler: the
/// `{request_id → cancellation token}` map lives here
/// ([`run_ws_connection`]), which intercepts the notification and fires only
/// the named request's child token. An unknown / already-completed id and
/// malformed params are silent no-ops, and no frame is ever written back — a
/// notification has no id to answer on.
///
/// So the method is deliberately **absent from every action registry**, the
/// dispatch map on both transports: a `cancel` carrying an `id` is a client
/// error and answers `method_not_found`, on WS and over HTTP POST alike. The
/// twin lands in the same place from the other direction: the TS
/// `cancel_action_spec` is `kind: 'remote_notification'`, and
/// `compile_action_registry` admits only `request_response` specs into
/// `action_map`.
pub const CANCEL_METHOD: &str = "cancel";

/// Params of a `cancel` notification — `{request_id: <string|number>}`.
///
/// Twin of the TS `CancelNotificationParams`, an
/// `object({request_id: JsonrpcRequestId})`, so the strictness
/// matches on both halves: `deny_unknown_fields` refuses an extra key the
/// way `object` does, a missing `request_id` refuses outright, and
/// the id's own string|number shape is checked when it is keyed (see
/// `PendingRequestSignals::cancel`). A frame that fails any of these names
/// no request and is dropped, exactly as the twin's parse failure
/// path does.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelParams {
    request_id: Value,
}

/// Apply an inbound client **notification** (a frame with a `method` and no
/// `id`), returning whether it cancelled an in-flight request.
///
/// The whole notification surface is one rule: `cancel` aborts the request
/// named by `params.request_id`, everything else is silence. No arm writes
/// a frame — a notification has no id to answer on, so a miss (unknown or
/// already-completed target, junk `params`, an unrecognized method) is
/// indistinguishable on the wire from a hit. Twin of the interception block
/// in `fuz_app`'s `actions/register_action_ws.ts`, which aborts the
/// matching pending `AbortController` and silences every other
/// notification.
///
/// The return value exists for the unit tests + the `trace!` line; the
/// read loop ignores it.
fn apply_client_notification(
    method: &str,
    params: &Value,
    signals: &PendingRequestSignals,
) -> bool {
    if method != CANCEL_METHOD {
        return false;
    }
    let Ok(parsed) = CancelParams::deserialize(params) else {
        return false;
    };
    signals.cancel(&parsed.request_id)
}

/// Cap on concurrently-running inbound client dispatches for a single socket.
///
/// Dispatch is concurrent (see [`run_ws_connection`]), not a
/// one-at-a-time inline await, so without a ceiling a flooding client could
/// grow the in-flight set (and its queued responses + pooled DB checkouts)
/// unbounded. Past the cap, **new requests are shed** with a `QueueOverflow`
/// error rather than blocking `rx` — the read loop keeps demuxing inbound
/// `Response` frames, so an in-flight server-initiated request's reply is never
/// starved (blocking `rx` at the cap would deadlock that case). Generous so
/// legitimate pipelining never trips it; only an abusive flood does.
///
/// The opposite direction — server-initiated requests awaiting a client
/// reply — is bounded separately by
/// [`crate::DEFAULT_MAX_IN_FLIGHT_PEER_REQUESTS_PER_CONNECTION`].
///
/// Counted are the requests dispatched and not yet answered — the entries of
/// `inflight`. Twin of `fuz_app`'s `MAX_INBOUND_DISPATCHES_PER_CONNECTION`:
/// same value, same `queue_overflow` message
/// ([`WS_INBOUND_DISPATCH_OVERFLOW_MESSAGE`]), and the same order against the
/// duplicate-id refusal (that one first).
pub const MAX_INBOUND_DISPATCHES_PER_CONNECTION: usize = 128;

/// The `queue_overflow` message a request gets past
/// [`MAX_INBOUND_DISPATCHES_PER_CONNECTION`]. Same text as the `fuz_app` twin's
/// `WS_INBOUND_DISPATCH_OVERFLOW_MESSAGE`.
pub const WS_INBOUND_DISPATCH_OVERFLOW_MESSAGE: &str =
    "too many concurrent requests on this connection";

/// The `data.reason` of the `invalid_request` a request gets when its id
/// names a request still in flight on the same socket.
///
/// The duplicate is not dispatched. The running request keeps the id — its
/// cancellation entry (see [`PendingRequestSignals`]) and its reply stay its
/// own — and the id is free again once that request has been answered. Same
/// literal as the `fuz_app` twin's `ERROR_DUPLICATE_REQUEST_ID`.
pub const ERROR_DUPLICATE_REQUEST_ID: &str = "duplicate_request_id";

/// The error a request reusing a live id gets: `invalid_request` with
/// `data.reason` [`ERROR_DUPLICATE_REQUEST_ID`].
fn duplicate_request_id_error() -> fuz_http::JsonrpcError {
    jsonrpc_error::invalid_request(Some(ERROR_DUPLICATE_REQUEST_ID))
}

/// Write one JSON-RPC error response for `id` to `tx`.
///
/// `Err` only when the socket write failed — the peer is gone — or was cut
/// off at a deadline ([`WriteBudget`]). An envelope that fails to serialize
/// writes nothing and is not an error, as at the loop's other error writes.
async fn send_error_frame<S>(
    tx: &mut S,
    budget: &mut WriteBudget<'_>,
    id: Value,
    error: fuz_http::JsonrpcError,
) -> Result<(), WriteError>
where
    S: Sink<Message> + Unpin,
{
    let Ok(json) = serde_json::to_string(&error_response(id, error)) else {
        return Ok(());
    };
    budget.send(tx, Message::Text(json.into())).await
}

/// Outcome of [`flush_queued_frames`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueuedFlush {
    /// The frames queued at flush time were written; the socket is live.
    Flushed,
    /// The registry dropped the connection's sender (a revocation, the
    /// per-account cap, an outbound overflow, the shutdown), which discarded
    /// whatever was still queued. Same meaning as `notify_rx.recv()` yielding
    /// `None`: stop writing and close with the frame [`sender_dropped_exit`]
    /// picks.
    SenderDropped,
    /// A socket write failed — the peer is gone — or was cut off at a
    /// deadline ([`WriteBudget`]).
    SendFailed(WriteError),
}

/// Write the frames queued on `notify_rx` to `tx`, in order, without
/// waiting for more.
///
/// The completion arm of the WS loop calls this before writing a dispatch's
/// response, so frames the handler queued to its own connection (via
/// `notify` / [`ConnectionRegistry::send_to`]) before it resolved reach the
/// client ahead of the response — the `select!` alone can't promise that,
/// since a handler that queues a frame and resolves in the same poll makes
/// both arms ready at once.
///
/// The drain is bounded by the queue length at completion. Every frame the
/// handler queued before resolving is inside that bound; frames arriving
/// during the drain are left to the `notify_rx.recv()` arm, so an
/// independent producer (e.g. a busy terminal's output broadcasts) can't
/// hold the loop here and starve `rx` or other dispatches.
///
/// The bound is inclusive — one `try_recv` past the queued frames — because
/// `len()` doesn't count the close: without the extra probe a connection
/// closed after the handler's frames were written would read as `Flushed`
/// and the response would still be written. That probe either hits `Empty` /
/// `Disconnected` or picks up at most one frame queued mid-drain. A close
/// discards the queue, so one that lands mid-drain ends the flush at the next
/// `try_recv` with nothing more written.
async fn flush_queued_frames<S>(
    notify_rx: &mut ConnectionReceiver,
    tx: &mut S,
    budget: &mut WriteBudget<'_>,
) -> QueuedFlush
where
    S: Sink<Message> + Unpin,
{
    for _ in 0..=notify_rx.len() {
        match notify_rx.try_recv() {
            Ok(frame) => {
                if let Err(error) = budget.send(tx, Message::Text(frame)).await {
                    return QueuedFlush::SendFailed(error);
                }
            }
            Err(TryRecvError::Empty) => return QueuedFlush::Flushed,
            Err(TryRecvError::Disconnected) => return QueuedFlush::SenderDropped,
        }
    }
    QueuedFlush::Flushed
}

/// Why [`run_ws_loop`] ended — the one value its cleanup reads to pick the
/// close frame.
///
/// Every exit `break`s with one of these, so the teardown below the loop is
/// written once and the close frame can't disagree with the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopExit {
    /// The client went away, a write failed or was cut off at the shutdown
    /// bound, or a read failed for a reason other than size — no close frame.
    Ended,
    /// A write did not complete within [`WS_WRITE_STALL_TIMEOUT`] — the
    /// client stopped reading. No close frame: the abandoned write leaves
    /// nothing a frame could follow, and the client is not reading anyway.
    Stalled,
    /// The registry closed the connection while a write was in progress,
    /// and that write was still pending at the close bound ([`WriteBudget`]).
    /// No close frame, for the same reason as [`Self::Stalled`] — the client
    /// does not learn why it was closed.
    CloseCut,
    /// The client sent a close frame — flush the reply tungstenite queued
    /// when it read it (echoing the client's code), bounded by
    /// [`CLOSE_REPLY_TIMEOUT`].
    ClosedByClient,
    /// A revocation path dropped the connection's sender — close with
    /// [`WS_CLOSE_SESSION_REVOKED`].
    Revoked,
    /// The per-account connection cap dropped the connection's sender to
    /// admit a newer one — close with [`WS_CLOSE_CONNECTION_LIMIT`].
    Superseded,
    /// An inbound message or frame exceeded the upgrade's size cap — close
    /// with [`WS_CLOSE_MESSAGE_TOO_BIG`], then hold the socket for
    /// [`MESSAGE_TOO_BIG_CLOSE_LINGER`].
    MessageTooBig,
    /// The server is shutting down — the registry's close-all dropped the
    /// connection's sender. Close with [`WS_CLOSE_GOING_AWAY`], the write
    /// inside the loop's shutdown bound ([`WriteBudget`]).
    ShuttingDown,
    /// A frame did not fit the connection's outbound queue and the registry
    /// closed it — close with [`WS_CLOSE_OUTBOUND_OVERFLOW`].
    OutboundOverflow,
    /// The account lost a role the connection's endpoint requires and the
    /// registry closed it — close with [`WS_CLOSE_PERMISSION_REVOKED`].
    PermissionRevoked,
    /// The credential the socket was opened with expired
    /// ([`WsLoopOptions::credential_deadline`]) — close with
    /// [`WS_CLOSE_SESSION_REVOKED`] and [`WS_CLOSE_CREDENTIAL_EXPIRED_REASON`].
    CredentialExpired,
    /// Nothing was read from the client for the receive timeout
    /// ([`WsLoopOptions::receive_timeout`]) — close with
    /// [`WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`].
    ReceiveTimeout,
}

/// How long a socket closed with an **unread inbound tail** is held open
/// after its close frame is written, before it's dropped.
///
/// Dropping a TCP socket that still has unread inbound bytes makes Linux
/// answer with a RST — and a client whose write fails on that RST before it
/// has read the close frame (Node's `ws` destroys the socket on the write
/// error) reports an abnormal 1006 instead of the code it was sent. Holding
/// the socket lets the client read the frame first; the eventual RST no
/// longer matters once it has. Bounded, and applied only to the two closes
/// that leave a tail behind ([`MESSAGE_TOO_BIG_CLOSE_LINGER`],
/// [`REFUSED_UPGRADE_CLOSE_LINGER`]) — a revocation of a running socket and
/// the normal paths close a socket the loop has been reading all along.
const UNREAD_TAIL_CLOSE_LINGER: Duration = Duration::from_secs(1);

/// How long the socket is held open after the 1009 close frame is written
/// ([`UNREAD_TAIL_CLOSE_LINGER`]).
///
/// tungstenite refuses an over-cap message at its frame header, while most
/// of the payload is still arriving, and the stream reads nothing after that
/// error — so the rest of the message is an unread tail.
const MESSAGE_TOO_BIG_CLOSE_LINGER: Duration = UNREAD_TAIL_CLOSE_LINGER;

/// How long a socket refused at admission is held open after its close frame
/// is written ([`UNREAD_TAIL_CLOSE_LINGER`]).
///
/// A refused upgrade is never read at all, and clients routinely send a
/// first frame the moment the handshake completes — so it usually has an
/// unread tail. Without the linger such a client sees 1006 rather than the
/// 4001 that tells it to stop, and reconnects in a loop.
const REFUSED_UPGRADE_CLOSE_LINGER: Duration = UNREAD_TAIL_CLOSE_LINGER;

/// How long the teardown waits to write the reply to a client's close frame.
///
/// tungstenite answers a client's close itself — it queues a reply echoing
/// the client's code when it reads the frame — but only writes it on the next
/// write or flush, so the teardown flushes it; without that the client sees
/// the connection drop mid-handshake (1006). Bounded so a client that stops
/// reading can't hold the connection open.
const CLOSE_REPLY_TIMEOUT: Duration = Duration::from_secs(1);

/// How long one write to a connection's socket may take before the loop
/// gives the socket up.
///
/// Every write the loop makes — a queued frame, a response, an error frame —
/// is awaited inline, so while one is pending nothing else on the connection
/// moves: its in-flight handlers are not polled (and keep whatever they hold,
/// a pooled database client included), its queue is not drained, a close
/// cannot be written. A client that stops reading fills its receive window
/// and leaves the write pending for as long as it likes; this is the bound on
/// that. A write still pending when it elapses ends the loop — the socket is
/// dropped with no close frame (the client sees an abnormal close, 1006 in a
/// browser), the connection leaves the registry, its in-flight handlers are
/// cancelled, and its pending server-initiated requests fail as
/// `ConnectionGone`. One `warn` line names the connection.
///
/// The deadline is per write and total, not a progress check: a frame the
/// client is taking, but too slowly to finish inside it, ends the connection
/// the same way, and the client reconnects.
///
/// Shorter than `fuz_http::WRITE_PROGRESS_TIMEOUT`, the progress deadline the
/// serve loop keeps under every socket, so this one is what a stalled
/// WebSocket write meets.
///
/// Equal to [`DEFAULT_PEER_REQUEST_TIMEOUT`]: a server-initiated request that cannot
/// even be written within its own reply deadline has already failed. Once
/// the registry has closed the connection, or the server is shutting down,
/// the shorter `SHUTDOWN_CLOSE_TIMEOUT` applies as well
/// ([`run_ws_connection`], "The close bound" and "The shutdown bound").
pub const WS_WRITE_STALL_TIMEOUT: Duration = DEFAULT_PEER_REQUEST_TIMEOUT;

// The serve loop's write-progress deadline sits under every socket, this
// loop's included; it has to stay the longer one, or it would fail a frame
// before this deadline could report the stall.
const _: () =
    assert!(WS_WRITE_STALL_TIMEOUT.as_millis() < fuz_http::WRITE_PROGRESS_TIMEOUT.as_millis());

/// How long the loop waits to write the close frame a server-side close owes
/// the client (4001, 4004, 4005, 1001, 1009) before dropping the socket
/// without it.
///
/// A close frame is a few bytes following frames that were each flushed, so a
/// client that is reading takes it at once; one that is not must not hold a
/// closed connection's socket. Equal to [`SHUTDOWN_CLOSE_TIMEOUT`], the bound
/// the shutdown puts on the same write.
const WS_CLOSE_WRITE_TIMEOUT: Duration = SHUTDOWN_CLOSE_TIMEOUT;

/// How long a loop closed for a revocation waits for the responses it still
/// owes ([`ReplyOwed`]) before writing the close without them.
///
/// The revoking request closes its own connection from its post-commit drain,
/// so its response can still be finishing that drain when the loop sees the
/// close. Short: the drain's remaining work (the audit fan-out) is quick, and a
/// response that misses the wait is dropped, the client seeing the close alone
/// — the behaviour before replies were owed.
const SELF_CLOSE_REPLY_WAIT: Duration = Duration::from_millis(500);

// The wait sits inside the close bound, so an owed reply and the close frame
// still share the one `WS_CLOSE_WRITE_TIMEOUT` counted from the close.
const _: () = assert!(SELF_CLOSE_REPLY_WAIT.as_millis() < WS_CLOSE_WRITE_TIMEOUT.as_millis());

/// A request's claim to have its response written after its own connection
/// closes.
///
/// A handler that revokes the credential of the connection it runs on — its
/// own session, its own token, its account, a role the endpoint requires —
/// closes that connection from its post-commit drain, before its response
/// reaches the loop, and the close discards whatever was queued. The
/// dispatcher marks the request ([`Self::mark`]) after the handler settles and
/// before the drain runs, while the connection is still open; a loop closed for
/// a revocation (`Revoked` / `PermissionRevoked` — not a credential expiry,
/// which closes with 4001 too) then writes each marked request's response
/// ahead of the close frame — the TS twin's order — and drops everything else.
/// The mark is gated on the request's own token, so a request already closing,
/// or one its client cancelled, is not owed.
#[derive(Debug, Default)]
pub struct ReplyOwed(AtomicBool);

impl ReplyOwed {
    /// Claim this request's response past a revocation close of its own
    /// connection.
    pub fn mark(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_marked(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Why a write the loop started did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteError {
    /// The sink refused it — the peer is gone.
    Failed,
    /// It was still pending at its own deadline — the client is not reading.
    Stalled,
    /// It was still pending at the shutdown bound.
    ShutdownCut,
    /// It was still pending at the close bound — the registry closed the
    /// connection while it was in progress.
    CloseCut,
}

impl WriteError {
    /// The loop exit a failed write of an ordinary frame forces. Every
    /// variant leaves the socket taking nothing more: a refused write has no
    /// peer, and a write abandoned part-way leaves nothing a frame could
    /// follow.
    const fn loop_exit(self) -> LoopExit {
        match self {
            Self::Failed | Self::ShutdownCut => LoopExit::Ended,
            Self::Stalled => LoopExit::Stalled,
            Self::CloseCut => LoopExit::CloseCut,
        }
    }
}

/// The deadlines on a connection loop's writes.
///
/// Every write the loop makes — a notification, a queued frame, a response,
/// an error frame, the close and the reply to a client's close — runs
/// through [`Self::run`] under three bounds:
///
/// - **Its own deadline**, always: the `timeout` the caller passes, counted
///   from the start of that write ([`WS_WRITE_STALL_TIMEOUT`] for a frame,
///   `WS_CLOSE_WRITE_TIMEOUT` for a close). A client that stopped reading
///   holds the loop for one such deadline.
/// - **The shutdown bound**, once the registry's close-all fires. The
///   shutdown waits for every loop to finish closing, so one socket whose
///   client stopped reading must not hold the whole shutdown to its drain
///   timeout. One bound, [`SHUTDOWN_CLOSE_TIMEOUT`] (shared with the HTTP
///   connections `fuz_http::serve_with_shutdown` cuts), covers the whole
///   tail, not one per frame: a write already in progress when the shutdown
///   fires and the close frame (the close-all discards what was queued).
///   The moment the close-all fires (observed mid-write, or before a write
///   starts) a deadline that far out is fixed, and that one deadline bounds
///   every write from then on. It watches the registry's signal, not the
///   connection's close reason, so a loop closing for any cause is held to
///   it.
/// - **The close bound**, once this connection's socket signal is cancelled
///   — by a registry-side close (a revocation, the per-account cap, an
///   outbound overflow, the shutdown), each of which cancels it, or by the
///   loop's own teardown. A write in progress at that moment would otherwise
///   keep the loop, its in-flight handlers and what they hold for the rest
///   of its own deadline. So the first time the signal is seen cancelled one
///   deadline `WS_CLOSE_WRITE_TIMEOUT` out is fixed, and the write in progress
///   and the close frame after it share it.
///
/// A write takes whichever bound comes first. Past any of them, the write is
/// abandoned wherever it was and the socket must take nothing more — no
/// close frame after a cut-off write, since a frame abandoned part-way
/// leaves nothing a close could follow. A refused upgrade's close
/// ([`refuse_upgrade`]) runs no loop and is under none of them.
#[derive(Debug)]
struct WriteBudget<'a> {
    closing: &'a CancellationToken,
    shutdown_deadline: Option<tokio::time::Instant>,
    /// The connection's socket signal.
    closed: &'a CancellationToken,
    close_deadline: Option<tokio::time::Instant>,
}

impl<'a> WriteBudget<'a> {
    /// `closing` is the registry's shutdown signal, `closed` the
    /// connection's socket signal.
    const fn new(closing: &'a CancellationToken, closed: &'a CancellationToken) -> Self {
        Self {
            closing,
            shutdown_deadline: None,
            closed,
            close_deadline: None,
        }
    }

    /// The shutdown deadline, fixed on first sight of the shutdown; `None`
    /// while the server is not shutting down.
    fn shutdown_deadline(&mut self) -> Option<tokio::time::Instant> {
        if self.shutdown_deadline.is_none() && self.closing.is_cancelled() {
            self.shutdown_deadline = Some(tokio::time::Instant::now() + SHUTDOWN_CLOSE_TIMEOUT);
        }
        self.shutdown_deadline
    }

    /// The close deadline, fixed on first sight of the connection's close;
    /// `None` while the connection is open.
    fn close_deadline(&mut self) -> Option<tokio::time::Instant> {
        if self.close_deadline.is_none() && self.closed.is_cancelled() {
            self.close_deadline = Some(tokio::time::Instant::now() + WS_CLOSE_WRITE_TIMEOUT);
        }
        self.close_deadline
    }

    /// Run `write` to completion, or to the earliest of its own deadline —
    /// `timeout` from now — the shutdown bound, and the close bound. `Err`
    /// names the bound that cut it off; the write is abandoned wherever it
    /// was.
    async fn run<F: Future>(
        &mut self,
        timeout: Duration,
        write: F,
    ) -> Result<F::Output, WriteError> {
        let mut write = std::pin::pin!(write);
        let own_deadline = tokio::time::Instant::now() + timeout;
        let (closing, closed) = (self.closing, self.closed);
        loop {
            // each bound is fixed the first time its signal is seen fired;
            // the earliest deadline cuts, a tie going to the bound over the
            // write's own deadline, and to the shutdown's over the close's
            let shutdown_deadline = self.shutdown_deadline();
            let close_deadline = self.close_deadline();
            let (mut deadline, mut cut) = (own_deadline, WriteError::Stalled);
            for (bound, error) in [
                (close_deadline, WriteError::CloseCut),
                (shutdown_deadline, WriteError::ShutdownCut),
            ] {
                if let Some(bound) = bound
                    && bound <= deadline
                {
                    (deadline, cut) = (bound, error);
                }
            }
            tokio::select! {
                biased;
                out = &mut write => return Ok(out),
                // a signal firing fixes its deadline on the next pass
                () = closing.cancelled(), if shutdown_deadline.is_none() => {}
                () = closed.cancelled(), if close_deadline.is_none() => {}
                () = tokio::time::sleep_until(deadline) => {
                    if cut == WriteError::ShutdownCut {
                        tracing::debug!("ws: write abandoned at the shutdown bound");
                    }
                    return Err(cut);
                }
            }
        }
    }

    /// Write one frame under [`WS_WRITE_STALL_TIMEOUT`], the shutdown bound
    /// and the close bound. `Err` when the write failed — the peer is gone —
    /// or was abandoned at a deadline.
    async fn send<S>(&mut self, tx: &mut S, msg: Message) -> Result<(), WriteError>
    where
        S: Sink<Message> + Unpin,
    {
        match self.run(WS_WRITE_STALL_TIMEOUT, tx.send(msg)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(WriteError::Failed),
            Err(cut) => Err(cut),
        }
    }

    /// Hold the socket for `linger` after a close frame — cut short only by
    /// the shutdown bound.
    async fn linger(&mut self, linger: Duration) {
        let mut sleep = std::pin::pin!(tokio::time::sleep(linger));
        if self.shutdown_deadline().is_none() {
            let closing = self.closing;
            tokio::select! {
                biased;
                () = &mut sleep => return,
                () = closing.cancelled() => {}
            }
        }
        if let Some(deadline) = self.shutdown_deadline() {
            let _ = tokio::time::timeout_at(deadline, sleep).await;
        }
    }
}

impl LoopExit {
    /// The close frame this exit owes the client, if any.
    fn close_frame(self) -> Option<CloseFrame> {
        match self {
            Self::Ended | Self::Stalled | Self::CloseCut | Self::ClosedByClient => None,
            Self::Revoked => Some(revoked_close_frame()),
            Self::Superseded => Some(CloseFrame {
                code: WS_CLOSE_CONNECTION_LIMIT,
                reason: WS_CLOSE_CONNECTION_LIMIT_REASON.into(),
            }),
            Self::MessageTooBig => Some(CloseFrame {
                code: WS_CLOSE_MESSAGE_TOO_BIG,
                reason: WS_CLOSE_MESSAGE_TOO_BIG_REASON.into(),
            }),
            Self::ShuttingDown => Some(going_away_close_frame()),
            Self::OutboundOverflow => Some(CloseFrame {
                code: WS_CLOSE_OUTBOUND_OVERFLOW,
                reason: WS_CLOSE_OUTBOUND_OVERFLOW_REASON.into(),
            }),
            Self::PermissionRevoked => Some(permission_revoked_close_frame()),
            Self::CredentialExpired => Some(CloseFrame {
                code: WS_CLOSE_SESSION_REVOKED,
                reason: WS_CLOSE_CREDENTIAL_EXPIRED_REASON.into(),
            }),
            Self::ReceiveTimeout => Some(CloseFrame {
                code: WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT,
                reason: WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT_REASON.into(),
            }),
        }
    }

    /// How long to hold the socket after this exit's close frame is written.
    const fn close_linger(self) -> Option<Duration> {
        match self {
            Self::Ended
            | Self::Stalled
            | Self::CloseCut
            | Self::ClosedByClient
            | Self::Revoked
            | Self::Superseded
            | Self::ShuttingDown
            | Self::OutboundOverflow
            | Self::PermissionRevoked
            | Self::CredentialExpired
            | Self::ReceiveTimeout => None,
            Self::MessageTooBig => Some(MESSAGE_TOO_BIG_CLOSE_LINGER),
        }
    }
}

/// The 4001 close frame — one definition, so a socket revoked mid-life
/// ([`LoopExit::Revoked`]) and an upgrade refused at admission
/// ([`UpgradeRefusal::Revoked`]) are indistinguishable on the wire.
fn revoked_close_frame() -> CloseFrame {
    CloseFrame {
        code: WS_CLOSE_SESSION_REVOKED,
        reason: WS_CLOSE_SESSION_REVOKED_REASON.into(),
    }
}

/// The 4006 close frame — one definition, so a socket whose account lost a
/// gating role mid-life ([`LoopExit::PermissionRevoked`]) and an upgrade
/// refused at admission for it ([`UpgradeRefusal::PermissionRevoked`]) are
/// indistinguishable on the wire.
fn permission_revoked_close_frame() -> CloseFrame {
    CloseFrame {
        code: WS_CLOSE_PERMISSION_REVOKED,
        reason: WS_CLOSE_PERMISSION_REVOKED_REASON.into(),
    }
}

/// The 1001 close frame — one definition, so a socket closed by the shutdown
/// ([`LoopExit::ShuttingDown`]) and an upgrade refused because of it
/// ([`UpgradeRefusal::ShuttingDown`]) are indistinguishable on the wire.
fn going_away_close_frame() -> CloseFrame {
    CloseFrame {
        code: WS_CLOSE_GOING_AWAY,
        reason: WS_CLOSE_GOING_AWAY_REASON.into(),
    }
}

/// Why an upgraded socket is closed at admission, before its loop starts.
///
/// The upgrade handler registers the connection pending, re-checks its
/// credential, and admits it (`ConnectionRegistry`'s "Two-phase
/// registration"); by then the handshake has answered `101`, so a refusal can
/// only be a close frame. [`refuse_upgrade`] writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeRefusal {
    /// The credential no longer authenticates — its session or token was
    /// revoked, expired, or its account deleted while the upgrade was in
    /// flight, or a revocation closed the pending registration. Closes with
    /// [`WS_CLOSE_SESSION_REVOKED`], the frame a socket revoked a moment
    /// later would get.
    Revoked,
    /// The credential is good but the account no longer holds a role the
    /// endpoint requires — a global grant was revoked while the upgrade was
    /// in flight (the admission role re-read refused, or a role close closed
    /// the pending registration). Closes with [`WS_CLOSE_PERMISSION_REVOKED`],
    /// the frame a socket that lost the role a moment later would get.
    PermissionRevoked,
    /// The re-check could not run (pool checkout or query failure) — refused
    /// rather than admitted unchecked. Closes with
    /// [`WS_CLOSE_INTERNAL_ERROR`].
    Unavailable,
    /// The server is shutting down — its close-all closed the pending
    /// registration, or the registration came after it and was born closed.
    /// Closes with [`WS_CLOSE_GOING_AWAY`], the frame an admitted socket gets
    /// from the same shutdown.
    ShuttingDown,
}

impl UpgradeRefusal {
    /// The close code this refusal sends.
    #[must_use]
    pub const fn close_code(self) -> u16 {
        match self {
            Self::Revoked => WS_CLOSE_SESSION_REVOKED,
            Self::PermissionRevoked => WS_CLOSE_PERMISSION_REVOKED,
            Self::Unavailable => WS_CLOSE_INTERNAL_ERROR,
            Self::ShuttingDown => WS_CLOSE_GOING_AWAY,
        }
    }

    /// The close frame this refusal sends.
    fn close_frame(self) -> CloseFrame {
        match self {
            Self::Revoked => revoked_close_frame(),
            Self::PermissionRevoked => permission_revoked_close_frame(),
            Self::Unavailable => CloseFrame {
                code: WS_CLOSE_INTERNAL_ERROR,
                reason: WS_CLOSE_INTERNAL_ERROR_REASON.into(),
            },
            Self::ShuttingDown => going_away_close_frame(),
        }
    }
}

/// A registration [`ConnectionRegistry::admit`] refused is closed for the
/// same reason it was refused: revoked → 4001, permission revoked → 4006,
/// shutting down → 1001.
impl From<NotAdmitted> for UpgradeRefusal {
    fn from(not_admitted: NotAdmitted) -> Self {
        match not_admitted {
            NotAdmitted::Revoked => Self::Revoked,
            NotAdmitted::PermissionRevoked => Self::PermissionRevoked,
            NotAdmitted::ShuttingDown => Self::ShuttingDown,
        }
    }
}

/// Write `frame` as the socket's close and, when it was written and `linger`
/// is set, hold the socket that long before returning — the one close path
/// for a socket the server ends, so every exit that leaves an unread inbound
/// tail lingers the same way ([`UNREAD_TAIL_CLOSE_LINGER`]).
///
/// Best-effort — the connection may already be gone, and a failed write
/// skips the linger: there is no frame for the client to read. `send`
/// flushes, so on success the frame is in the kernel's send buffer.
async fn send_close<S>(tx: &mut S, frame: CloseFrame, linger: Option<Duration>)
where
    S: Sink<Message> + Unpin,
{
    if tx.send(Message::Close(Some(frame))).await.is_ok()
        && let Some(linger) = linger
    {
        tokio::time::sleep(linger).await;
    }
}

/// Close an upgraded socket that was refused at admission.
///
/// Writes the refusal's close frame, holds the socket for a short bounded
/// linger (`REFUSED_UPGRADE_CLOSE_LINGER`) so the client can read it — a refused
/// socket was never read, and a client that sent a frame on open would
/// otherwise see the connection reset (1006) instead of the refusal — and
/// returns; the caller then drops the socket. Nothing else is ever written
/// to it: no loop ran, and nothing was delivered to its pending registration.
/// The registration itself is already gone, so the linger holds a socket,
/// not a slot.
///
/// The close write is not held to the loop's shutdown bound
/// (`SHUTDOWN_CLOSE_TIMEOUT`): during a shutdown, a write that cannot
/// complete (a client whose receive window is closed) stays pending and keeps
/// its [`ConnectionRegistry::hold_upgrade`] alive, so it can hold the drain to
/// the server's drain timeout.
///
/// Generic over the sink so it takes the upgraded `WebSocket` directly and a
/// channel in tests.
pub async fn refuse_upgrade<S>(mut socket: S, refusal: UpgradeRefusal)
where
    S: Sink<Message> + Unpin,
{
    send_close(
        &mut socket,
        refusal.close_frame(),
        Some(REFUSED_UPGRADE_CLOSE_LINGER),
    )
    .await;
}

/// The exit for a connection whose sender the registry dropped.
///
/// The channel closing says only *that* the registry let go, so the loop
/// reads the reason the registry recorded before the drop: superseded by the
/// per-account cap, closed by the shutdown, closed for an outbound overflow,
/// closed for a lost gating role, or — the cell unset — revoked.
fn sender_dropped_exit(close_reason: &OnceLock<CloseReason>) -> LoopExit {
    match close_reason.get() {
        Some(CloseReason::Superseded) => LoopExit::Superseded,
        Some(CloseReason::ShuttingDown) => LoopExit::ShuttingDown,
        Some(CloseReason::OutboundOverflow) => LoopExit::OutboundOverflow,
        Some(CloseReason::PermissionRevoked) => LoopExit::PermissionRevoked,
        None => LoopExit::Revoked,
    }
}

/// Classify a failed socket read into the loop's exit.
///
/// An over-cap message surfaces as tungstenite's
/// `Error::Capacity(CapacityError::MessageTooLong)` — for both the upgrade's
/// `max_message_size` and its `max_frame_size` — boxed inside the
/// `axum::Error`, which exposes no accessor for it, so this downcasts the
/// boxed source. Every other read failure (protocol violation, transport
/// error) ends the connection without a close frame, as before.
fn classify_read_error(error: axum::Error) -> LoopExit {
    let inner = error.into_inner();
    let too_big = matches!(
        inner.downcast_ref::<tungstenite::Error>(),
        Some(tungstenite::Error::Capacity(
            tungstenite::error::CapacityError::MessageTooLong { .. }
        ))
    );
    if too_big {
        tracing::warn!(error = %inner, "ws: closing socket, message exceeds the size cap");
        LoopExit::MessageTooBig
    } else {
        tracing::debug!(error = %inner, "ws: read failed, closing");
        LoopExit::Ended
    }
}

/// Per-message dispatch callback shape.
///
/// The WS loop calls this with the classified request and the borrowed
/// `notify` closure; the callback returns the JSON wire text of the
/// response (success or error). Implementations live in `fuz_actions`
/// (`ws_dispatch.rs`) where they call into `perform_action`
/// with the consumer's `ActionRegistry`.
///
/// Returns `None` to silence a response (e.g. notification handling).
pub type WsDispatchFn =
    Arc<dyn for<'a> Fn(WsDispatchInput<'a>) -> BoxFuture<'a, Option<String>> + Send + Sync>;

/// Borrowed dispatch input handed to the consumer's [`WsDispatchFn`].
///
/// The lifetime ties to the WS message frame (request stays valid
/// until the loop sends the response). Fields are borrowed because
/// `params` is decoded once per message and shared between
/// classify + dispatch.
pub struct WsDispatchInput<'a> {
    pub method: &'a str,
    pub params: &'a Value,
    pub request_id: &'a Value,
    /// Borrowed `notify` reference for per-request dispatch sites.
    /// The owning closure lives in the WS loop frame.
    pub notify: &'a (dyn Fn(&str, &Value) + Send + Sync),
    /// Per-**request** cancellation token — a child of the socket-scoped
    /// token, fired by a `cancel` message naming this request's id, or by
    /// teardown / revocation (which cancels the socket parent and so every
    /// child). Handlers observe via `.is_cancelled()` / `.cancelled().await`.
    /// Scoped per request so one `cancel` (or a sibling's cancel) never
    /// poisons another request — or any future request — on the socket.
    pub signal: &'a CancellationToken,
    /// The request's claim to its response past a revocation close of its own
    /// connection — the dispatcher marks it between the handler settling and
    /// the post-commit drain, while `signal` is not yet cancelled.
    pub reply_owed: &'a ReplyOwed,
}

impl std::fmt::Debug for WsDispatchInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsDispatchInput")
            .field("method", &self.method)
            .field("params", &self.params)
            .field("request_id", &self.request_id)
            .field("signal_cancelled", &self.signal.is_cancelled())
            .finish_non_exhaustive()
    }
}

/// What ends one connection's loop besides its client and the registry —
/// the per-connection argument to [`run_ws_connection`].
///
/// [`Default`] ends it on neither: no credential deadline and no receive
/// timeout. `fuz_actions::register_action_ws` builds one per socket, with the
/// router's receive timeout (60 s unless the consumer sets its own).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WsLoopOptions {
    /// When the credential the socket was opened with expires
    /// ([`fuz_auth::ResolvedAuth::credential_deadline`]). The loop closes the
    /// socket then with [`WS_CLOSE_SESSION_REVOKED`] (4001) and
    /// [`WS_CLOSE_CREDENTIAL_EXPIRED_REASON`], as a revocation closes it:
    /// expiry writes nothing a revocation listener could hear, so the loop
    /// watches the clock itself. The wait sleeps in bounded steps
    /// ([`crate::CREDENTIAL_DEADLINE_SLEEP_CAP`]), so a deadline years out
    /// never meets tokio's sleep ceiling, and ends at the wall-clock deadline
    /// too, so a host suspend does not extend it (see
    /// [`crate::credential_deadline`]). `None` (a daemon token, an eternal API
    /// token) never fires.
    pub credential_deadline: Option<std::time::Instant>,
    /// Receive silence past which the loop closes the socket with
    /// [`WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`] (4003) and
    /// [`WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT_REASON`] — the twin of `fuz_app`'s
    /// server heartbeat (`register_action_ws`'s `heartbeat.timeout`), and the
    /// same rules: the silence is counted from admission (the loop's start)
    /// and from every text or binary frame read since, so a chatty client never
    /// trips it and the first window is grace; control frames (ping, pong) do
    /// not count, as they never reach the twin's handler; and it is checked
    /// on a tick of half the timeout (at least 100 ms), so a silent socket
    /// closes between one and one and a half timeouts in. `None` never closes.
    pub receive_timeout: Option<Duration>,
}

/// The receive-silence check of [`WsLoopOptions::receive_timeout`]: when the
/// client was last heard from, and the tick that looks.
struct ReceiveSilence {
    timeout: Duration,
    last_receive: tokio::time::Instant,
    tick: tokio::time::Interval,
}

impl ReceiveSilence {
    /// The floor on the check's tick, as on the twin.
    const MIN_TICK: Duration = Duration::from_millis(100);

    fn start(timeout: Duration) -> Self {
        let period = (timeout / 2).max(Self::MIN_TICK);
        let now = tokio::time::Instant::now();
        let mut tick = tokio::time::interval_at(now + period, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            timeout,
            last_receive: now,
            tick,
        }
    }

    /// A frame was read from the client.
    fn heard(&mut self) {
        self.last_receive = tokio::time::Instant::now();
    }

    /// Resolve on the next tick at which the silence has reached the timeout.
    /// Cancel-safe: a dropped call loses at most one tick.
    async fn expired(&mut self) {
        loop {
            self.tick.tick().await;
            if self.last_receive.elapsed() >= self.timeout {
                return;
            }
        }
    }
}

/// Resolve when `silence` has expired; never, when there is no timeout.
async fn receive_silence_expired(silence: &mut Option<ReceiveSilence>) {
    match silence {
        Some(silence) => silence.expired().await,
        None => std::future::pending().await,
    }
}

/// Run the WS message loop for one upgraded connection.
///
/// Caller is responsible for:
///
/// 1. Authenticating the upgrade request (origin + cookie / bearer /
///    daemon-token resolution via `fuz_auth::resolve_auth_from_headers`).
/// 2. Building the connection's outbound channel
///    ([`connection_channel`](crate::connection_channel), with the byte
///    budget its queue is held to) and registering the
///    connection in two phases (`ConnectionRegistry`'s "Two-phase
///    registration"):
///    [`ConnectionRegistry::register_pending`] with the auth metadata
///    (its [`ConnectionIdentity`](crate::ConnectionIdentity) and the
///    socket-scoped `CancellationToken`), a re-check of the credential, then
///    [`ConnectionRegistry::admit`] — which enforces the per-account
///    connection cap, so it must run only after every gate in step 1 and the
///    re-check — holding the [`crate::ConnectionGuard`] it returns for the
///    socket's lifetime, and dropped only once this future returns, since it
///    also holds the registry's shutdown wait open until the loop has written
///    its close, or given up at the shutdown bound. A refusal is closed
///    with [`refuse_upgrade`] instead of reaching this loop, under a
///    [`ConnectionRegistry::hold_upgrade`] taken before the handshake so
///    the shutdown waits for that frame too.
///    (`fuz_actions::admit_upgrade` is this step.)
/// 3. Spawning this future on the upgraded socket with the admitted
///    [`Connection`].
///
/// The loop owns:
///
/// - The `select!` between server-pushed notifications
///   (`notify_rx.recv()`), completed dispatches, and client messages
///   (`rx.next()`).
/// - **Response ordering** — a dispatch's response is never written ahead
///   of frames its handler queued to this connection before completing
///   (e.g. streaming `completion_progress` chunks sent via `notify`): the
///   completion arm flushes everything already queued on `notify_rx`
///   before the response. Frames queued *after* completion (a task the
///   handler spawned and left running) carry no such guarantee.
/// - JSON parse-error handling with a wire envelope.
/// - JSON-RPC classification + delegation to `dispatch`.
/// - **Per-request cancellation** — each dispatched request gets a child
///   of the socket token as its `ctx.signal` (see [`PendingRequestSignals`]).
///   A `cancel` **notification** (method == [`CANCEL_METHOD`], no `id`) is
///   handled **here**, not dispatched: it cancels only the child named by
///   its `params.request_id` (a no-op for an unknown / completed id) and
///   answers no frame. A `cancel` carrying an `id` is not a cancel at all —
///   it falls through to dispatch and gets `method_not_found`, since the
///   method is notification-only. The socket-scoped token is reserved
///   for teardown / revocation, so one `cancel` never poisons the
///   connection.
/// - **Duplicate live ids** — a request whose id names a request still in
///   flight on this socket is answered `invalid_request` with `data.reason`
///   [`ERROR_DUPLICATE_REQUEST_ID`] and not dispatched; the running request
///   keeps its token and its cancellation entry.
/// - **The in-flight ceiling** — past [`MAX_INBOUND_DISPATCHES_PER_CONNECTION`]
///   running requests a new one is answered `queue_overflow` and not
///   dispatched; the socket stays open. The duplicate check runs first.
/// - **Inbound `Response` demux** — an `{id, result|error}` reply to a
///   server-initiated request is routed to `pending` for *this*
///   connection; a reply whose id isn't pending here is dropped + audited
///   (never resolves anything — the unsolicited-response invariant).
/// - 4001 close frame on revocation (sender dropped by
///   `ConnectionRegistry::close_connections`), a
///   [`WS_CLOSE_CONNECTION_LIMIT`] (4004) close frame when the per-account
///   cap superseded the connection (sender dropped by a newer
///   admission for the same account), a [`WS_CLOSE_GOING_AWAY`] (1001)
///   close frame when the server shuts down (sender dropped by the
///   registry's close-all), a [`WS_CLOSE_OUTBOUND_OVERFLOW`] (4005) close
///   frame when a frame did not fit the connection's outbound queue (sender
///   dropped by the send that overflowed it), and a
///   [`WS_CLOSE_MESSAGE_TOO_BIG`] (1009) close frame when a read fails on
///   the upgrade's size cap (`max_message_size` / `max_frame_size`) — twin
///   of `fuz_app`'s `register_action_ws` size check — after which the socket
///   is held for a short bounded linger so the frame outruns the reset an
///   unread inbound tail provokes. Other read failures end the connection
///   without a frame. A client's own close frame is answered with one
///   echoing its code (the reply tungstenite queues, flushed on exit), so
///   the closing handshake completes.
/// - **A closed connection's backlog is discarded** — whatever closes the
///   connection from the registry's side (a revocation, the cap, an outbound
///   overflow, the shutdown) discards the frames still queued for it, and
///   the loop, once it sees the close, writes only the close frame: no
///   queued frame, no response of a dispatch still in flight, no answer to
///   a client frame it reads after the close (which it does not dispatch
///   either). A close therefore does not wait behind a backlog. The one
///   exception is a revocation's owed responses: a request that revoked its
///   own connection's credential ([`ReplyOwed`]) gets its response written
///   just ahead of the 4001 / 4006 close, inside the close bound. Each arm of
///   the loop checks for the close before it starts writing; a frame whose
///   write was already in progress may finish first, inside the close bound
///   below.
/// - **The write deadline** — every write is bounded, shutdown or not: a
///   frame by [`WS_WRITE_STALL_TIMEOUT`], a server-side close frame by
///   `SHUTDOWN_CLOSE_TIMEOUT`. A write still pending at its deadline ends
///   the loop with no close frame, the socket dropped as it stands (a
///   browser reports 1006), with one `warn` line naming the connection, its
///   account, and what was queued for it. So a client that stops reading
///   costs the server one write deadline of a frozen loop — its in-flight
///   handlers unpolled, their pooled clients held — and is then dropped.
///   The deadline is per write, not a throughput floor: a client that takes
///   each frame just inside it is not dropped.
/// - **The close bound** — once the registry closes the connection (a
///   revocation, the cap, an outbound overflow), a write already in progress
///   and the close frame after it share one `SHUTDOWN_CLOSE_TIMEOUT` counted
///   from the close, so a closed connection whose client stopped reading
///   gives up its in-flight handlers and their pooled clients then, not at
///   the write's own deadline. A write still pending at that bound ends the
///   loop with no close frame — the client sees an abnormal close, not the
///   code — and one `info` line saying a close cut a stalled write.
/// - **The shutdown bound** — once the registry's close-all fires, every
///   write the loop has left (one already in progress, the close) shares one
///   `SHUTDOWN_CLOSE_TIMEOUT` as well, whatever the loop is closing for, so
///   a client that stopped reading cannot hold the shutdown past it. A write
///   cut off at the bound ends the loop without a close frame. A refusal's
///   close ([`refuse_upgrade`]) is outside all three bounds.
/// - Final `signal.cancel()` + `remove_connection` + `drain_connection`
///   on exit, on every path — any still-pending server-initiated request on
///   this socket resolves `PeerError::ConnectionGone`, and the in-flight
///   dispatches are dropped before the close frame is written.
/// - **The credential deadline** ([`WsLoopOptions::credential_deadline`]) —
///   when it passes, the loop ends and closes the socket with 4001 and
///   [`WS_CLOSE_CREDENTIAL_EXPIRED_REASON`]; the teardown above runs as for
///   any other exit.
/// - **The receive timeout** ([`WsLoopOptions::receive_timeout`]) — a client
///   silent that long is closed with [`WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`]
///   (4003); every text or binary frame read resets it.
pub async fn run_ws_connection(
    socket: WebSocket,
    registry: Arc<ConnectionRegistry>,
    conn: Connection,
    notify_rx: ConnectionReceiver,
    pending: Arc<PendingPeerRequests>,
    dispatch: WsDispatchFn,
    options: WsLoopOptions,
) {
    let (tx, rx) = socket.split();
    run_ws_loop(
        tx, rx, registry, conn, notify_rx, pending, dispatch, options,
    )
    .await;
}

/// One finished dispatch: its request id (to drop its cancellation entry), its
/// response text, if any, and its [`ReplyOwed`] claim.
struct DispatchDone {
    request_id: Value,
    response: Option<String>,
    reply_owed: Arc<ReplyOwed>,
}

/// Drop a finished dispatch's claim from the outstanding set.
fn forget_claim(owed: &mut Vec<Arc<ReplyOwed>>, claim: &Arc<ReplyOwed>) {
    owed.retain(|other| !Arc::ptr_eq(other, claim));
}

/// Write the responses a loop closed for a revocation still owes, then hand
/// back the exit.
///
/// Only [`LoopExit::Revoked`] and [`LoopExit::PermissionRevoked`] owe
/// anything — the two closes a request's own post-commit drain can cause
/// ([`ReplyOwed`]); every other exit is returned as it is. `completed` is a
/// dispatch the completion arm already holds. Then, while any dispatch still
/// in flight is marked, the loop waits — at most [`SELF_CLOSE_REPLY_WAIT`], and
/// never past the shutdown bound — writing each marked response as it lands and
/// dropping every unmarked one. Nothing queued is written: the close already
/// discarded the queue. A failed write ends the loop as any failed write does,
/// with no close frame after it.
async fn write_owed_replies<S>(
    exit: LoopExit,
    completed: Option<DispatchDone>,
    inflight: &mut FuturesUnordered<BoxFuture<'static, DispatchDone>>,
    owed: &mut Vec<Arc<ReplyOwed>>,
    tx: &mut S,
    budget: &mut WriteBudget<'_>,
) -> LoopExit
where
    S: Sink<Message> + Unpin,
{
    if !matches!(exit, LoopExit::Revoked | LoopExit::PermissionRevoked) {
        return exit;
    }
    let mut pending = completed;
    let mut wait_until = tokio::time::Instant::now() + SELF_CLOSE_REPLY_WAIT;
    // the close bound starts at the close, not at the first owed write
    for bound in [budget.close_deadline(), budget.shutdown_deadline()]
        .into_iter()
        .flatten()
    {
        wait_until = wait_until.min(bound);
    }
    loop {
        if let Some(done) = pending.take() {
            forget_claim(owed, &done.reply_owed);
            if done.reply_owed.is_marked()
                && let Some(json) = done.response
                && let Err(error) = budget.send(tx, Message::Text(json.into())).await
            {
                return error.loop_exit();
            }
        }
        if !owed.iter().any(|claim| claim.is_marked()) {
            return exit;
        }
        let Ok(Some(done)) = tokio::time::timeout_at(wait_until, inflight.next()).await else {
            tracing::debug!("ws: closing without a reply still owed past the wait");
            return exit;
        };
        pending = Some(done);
    }
}

/// The [`run_ws_connection`] loop over the socket's split halves.
///
/// Generic over the sink/stream so the unit tests can drive it with
/// in-memory channels instead of a live upgraded `WebSocket`.
#[expect(
    clippy::too_many_arguments,
    reason = "the split socket halves plus the connection's parts, each owned by a different layer: the registry and its entry, the notification receiver and pending peer requests, the dispatch, and the loop options"
)]
async fn run_ws_loop<S, R>(
    mut tx: S,
    mut rx: R,
    registry: Arc<ConnectionRegistry>,
    conn: Connection,
    mut notify_rx: ConnectionReceiver,
    pending: Arc<PendingPeerRequests>,
    dispatch: WsDispatchFn,
    options: WsLoopOptions,
) where
    S: Sink<Message> + Unpin,
    R: Stream<Item = Result<Message, axum::Error>> + Unpin,
{
    let Connection {
        id: conn_id,
        account_id,
        signal,
        close_reason,
    } = conn;

    // Per-request cancellation map, parented by the socket-scoped `signal`.
    // Each dispatched request gets a child token here; a `cancel` message
    // fires only the matching child. `signal` itself stays reserved for
    // teardown / revocation (the final `signal.cancel()` below).
    let mut signals = PendingRequestSignals::new(signal.clone());

    // In-flight per-message dispatches. A request handler is **not** awaited
    // inline in the `rx` arm — a handler that initiates a server→client
    // request (`ctx.request_client`) must await the client's reply, which
    // requires the loop to keep flushing `notify_rx` (to send the outbound
    // request) and reading `rx` (to demux the inbound reply). Awaiting
    // inline would self-deadlock. Instead each dispatch becomes an owned
    // future pushed here and polled as a third `select!` arm, so dispatches
    // run concurrently per socket — the natural interleaving the TS event
    // loop already gives the twin. The set is dropped on loop exit, so an
    // in-flight handler is cancelled with the socket (no detached task).
    //
    // Each future yields a [`DispatchDone`] — the id lets the completion arm
    // drop the request's entry from `signals` (so a late `cancel` for a
    // finished id is a silent no-op, and the map can't grow unbounded), and
    // the claim says whether its response is owed past a revocation close.
    let mut inflight: FuturesUnordered<BoxFuture<'static, DispatchDone>> = FuturesUnordered::new();
    // The claims of the dispatches still in `inflight`, so a loop closed for a
    // revocation knows whether a response is still owed ([`ReplyOwed`]).
    let mut owed: Vec<Arc<ReplyOwed>> = Vec::new();

    // Every write below goes through the budget: each under its own
    // deadline, and once the registry has closed this connection or the
    // server is shutting down, the rest of this socket's writes — the one in
    // progress, the close — under one bound.
    let mut budget = WriteBudget::new(registry.closing_signal(), &signal);

    // Pinned once, so each pass of the loop polls the same wait rather than
    // starting a new one.
    let credential_expiry = credential_deadline_reached(options.credential_deadline);
    tokio::pin!(credential_expiry);
    // Counted from now — the connection was admitted just before the loop
    // started — so the first window is the twin's cold-start grace.
    let mut silence = options.receive_timeout.map(ReceiveSilence::start);

    let exit = loop {
        tokio::select! {
            // The credential the socket was opened with expired. Nothing
            // closed the connection from the registry's side, so the loop
            // ends it as a revocation would.
            () = &mut credential_expiry => break LoopExit::CredentialExpired,
            // The client has been silent for the receive timeout.
            () = receive_silence_expired(&mut silence) => break LoopExit::ReceiveTimeout,
            // Server-initiated message (broadcast / send_to / a server-
            // initiated request frame / a dispatch's response routed back
            // through the registry). `None` means the registry dropped the
            // sender — a revocation (4001), the per-account cap (4004), an
            // outbound overflow (4005), the shutdown (1001); `close_reason`
            // says which. The drop discarded whatever was still queued.
            notify_msg = notify_rx.recv() => {
                let Some(msg) = notify_msg else {
                    let exit = sender_dropped_exit(&close_reason);
                    break write_owed_replies(exit, None, &mut inflight, &mut owed, &mut tx, &mut budget).await;
                };
                if let Err(error) = budget.send(&mut tx, Message::Text(msg)).await {
                    break error.loop_exit();
                }
            }
            // A per-message dispatch completed — drop its cancellation entry,
            // flush the frames already queued on `notify_rx`, then write its
            // response (if any). The flush is the ordering guarantee: a
            // handler that `notify`s its own connection and then resolves
            // makes this arm and the `notify_rx` arm ready in the same poll,
            // and `select!` (biased or not) could pick this one first,
            // writing the response ahead of the handler's last frames.
            // Guarded so an empty set doesn't busy-spin (`next()` would
            // yield `None` immediately).
            Some(done) = inflight.next(), if !inflight.is_empty() => {
                signals.complete(&done.request_id);
                match flush_queued_frames(&mut notify_rx, &mut tx, &mut budget).await {
                    QueuedFlush::Flushed => {}
                    QueuedFlush::SenderDropped => {
                        let exit = sender_dropped_exit(&close_reason);
                        break write_owed_replies(exit, Some(done), &mut inflight, &mut owed, &mut tx, &mut budget).await;
                    }
                    QueuedFlush::SendFailed(error) => break error.loop_exit(),
                }
                forget_claim(&mut owed, &done.reply_owed);
                let response_text = done.response;
                if let Some(json) = response_text
                    && let Err(error) = budget.send(&mut tx, Message::Text(json.into())).await
                {
                    break error.loop_exit();
                }
            }
            // Client message.
            msg = rx.next() => {
                let msg = match msg {
                    Some(Ok(msg)) => msg,
                    // a message over the upgrade's size cap (close 1009), or a
                    // protocol violation / transport failure (no close frame) —
                    // the socket is done either way
                    Some(Err(e)) => break classify_read_error(e),
                    None => break LoopExit::Ended,
                };
                // A connection the registry closed takes nothing more from
                // its client: `select!` can pick this arm ahead of the
                // closed channel, and a frame read then is neither
                // dispatched nor answered.
                if notify_rx.is_closed() {
                    let exit = sender_dropped_exit(&close_reason);
                    break write_owed_replies(exit, None, &mut inflight, &mut owed, &mut tx, &mut budget).await;
                }
                let text = match msg {
                    Message::Text(t) => {
                        if let Some(silence) = silence.as_mut() {
                            silence.heard();
                        }
                        t
                    }
                    Message::Close(_) => break LoopExit::ClosedByClient,
                    Message::Binary(_) => {
                        // a data frame the client sent, as on the twin, whose
                        // handler hears binary messages too
                        if let Some(silence) = silence.as_mut() {
                            silence.heard();
                        }
                        tracing::debug!("ws: ignored binary frame (expected text)");
                        continue;
                    }
                    Message::Ping(_) | Message::Pong(_) => continue,
                };

                // 1. Parse JSON. On failure send parse_error envelope
                //    (matches fuz_app + zzz wire shape).
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    tracing::debug!("ws: JSON parse error");
                    if let Ok(json) =
                        serde_json::to_string(&error_response(Value::Null, jsonrpc_error::parse_error()))
                        && let Err(error) = budget.send(&mut tx, Message::Text(json.into())).await
                    {
                        break error.loop_exit();
                    }
                    continue;
                };

                // 2. Classify. Requests dispatch concurrently (pushed to
                //    `inflight`); responses demux synchronously; errors write
                //    inline (no external await).
                match classify(&value) {
                    Classified::Request { method, id, params } => {
                        // `cancel` is NOT special-cased here — it is a
                        // notification-kind action, so a `cancel` carrying an
                        // `id` is a client error and falls through to dispatch,
                        // where the registry (which does not mount it) answers
                        // `method_not_found`. The twin does the same: the TS
                        // `cancel_action_spec` is `kind: 'remote_notification'`,
                        // so it never reaches `action_map`.
                        //
                        // A request is live from here until its response is
                        // written. One reusing a live id is refused, not
                        // dispatched: two requests under one id would share a
                        // cancel entry and a reply id, and the first to finish
                        // would clear the other's. Checked before the cap — a
                        // duplicate is the client's error whatever the load,
                        // and retrying it cannot succeed while the first runs.
                        // Neither refusal reaches the dispatcher, so neither
                        // charges the action rate limiters (as on the twin).
                        if signals.is_live(&id) {
                            if let Err(error) = send_error_frame(&mut tx, &mut budget, id, duplicate_request_id_error()).await {
                                break error.loop_exit();
                            }
                            continue;
                        }
                        // Backpressure: shed new requests past the per-socket
                        // cap instead of growing the in-flight set unbounded.
                        // Responses + control frames keep flowing (we don't stop
                        // reading `rx`), so an in-flight elicitation's reply
                        // still demuxes — only fresh dispatches are refused.
                        if inflight.len() >= MAX_INBOUND_DISPATCHES_PER_CONNECTION {
                            let error =
                                jsonrpc_error::queue_overflow(WS_INBOUND_DISPATCH_OVERFLOW_MESSAGE);
                            if let Err(error) = send_error_frame(&mut tx, &mut budget, id, error).await {
                                break error.loop_exit();
                            }
                            continue;
                        }
                        // Mint this request's child token — `cancel` fires it
                        // by id, teardown fires it via the parent. The handler
                        // sees it as `ctx.signal` (per-request, never the
                        // shared socket token). `None` only for a live id, which
                        // the check above already refused.
                        let Some(req_token) = signals.begin(&id) else {
                            if let Err(error) = send_error_frame(&mut tx, &mut budget, id, duplicate_request_id_error()).await {
                                break error.loop_exit();
                            }
                            continue;
                        };
                        // Move the borrowed frame fields into an owned future
                        // so it can outlive this `rx` iteration. The notify
                        // closure is rebuilt per request (cheap — one Arc
                        // clone) so the future owns everything (`'static`).
                        // The future yields `id` back so the completion arm
                        // can drop this request's `signals` entry.
                        let dispatch = Arc::clone(&dispatch);
                        let registry = Arc::clone(&registry);
                        let method = method.to_owned();
                        let params = params.clone();
                        let reply_owed = Arc::new(ReplyOwed::default());
                        owed.push(Arc::clone(&reply_owed));
                        inflight.push(Box::pin(async move {
                            let notify_closure = ws_notify_for_connection(registry, conn_id);
                            let input = WsDispatchInput {
                                method: &method,
                                params: &params,
                                request_id: &id,
                                notify: &notify_closure,
                                signal: &req_token,
                                reply_owed: &reply_owed,
                            };
                            let response = dispatch(input).await;
                            DispatchDone { request_id: id, response, reply_owed }
                        }));
                    }
                    Classified::Response { id, outcome } => {
                        // Inbound reply to a server-initiated request.
                        // Resolve it against the pending registry for THIS
                        // connection; an id not pending here (unsolicited,
                        // cross-connection, or already settled) is dropped
                        // + audited and resolves nothing.
                        if !pending.resolve(conn_id, &id, outcome) {
                            audit_unmatched_response(conn_id, &id);
                        }
                    }
                    Classified::Invalid { id, error } => {
                        if let Ok(json) = serde_json::to_string(&error_response(id, error))
                            && let Err(error) = budget.send(&mut tx, Message::Text(json.into())).await
                        {
                            break error.loop_exit();
                        }
                    }
                    Classified::Notification { method, params } => {
                        // Silent by contract — no arm here writes a frame.
                        // `cancel` fires only the child token of the request
                        // named by `params.request_id`, never the socket
                        // parent, so one cancel can't poison the connection;
                        // an unknown / already-completed target and junk
                        // params are no-ops, and every other notification is
                        // dropped.
                        let cancelled =
                            apply_client_notification(method, params, &signals);
                        tracing::trace!(method, cancelled, "ws: client notification");
                    }
                }
            }
        }
    };

    // Disconnect: cancel any in-flight streaming, drop the connection, and
    // resolve any still-pending server-initiated requests on this socket as
    // `ConnectionGone` (dropping their one-shot senders). `signal` is the
    // socket-scoped parent, so cancelling it cancels every per-request child
    // still in `signals` (and aborts an in-flight `request` await via its
    // `select!` arm) — belt-and-suspenders with the drain.
    if exit == LoopExit::Stalled {
        // read before `remove_connection` below discards the queue
        tracing::warn!(
            conn_id = conn_id.get(),
            account_id = account_id.map(tracing::field::display),
            queued_bytes = notify_rx.queued_bytes(),
            queued_frames = notify_rx.len(),
            "ws: write stalled, dropping the connection"
        );
    }
    if exit == LoopExit::CloseCut {
        // the registry recorded why it closed the connection; an unset cell
        // is a revocation or a plain removal
        tracing::info!(
            conn_id = conn_id.get(),
            account_id = account_id.map(tracing::field::display),
            close_reason = ?close_reason.get(),
            "ws: a close cut a stalled write, dropping the connection without its close frame"
        );
    }
    signal.cancel();
    registry.remove_connection(conn_id);
    pending.drain_connection(conn_id);
    // The in-flight dispatches go now, not when this function returns: none
    // is polled again, and what one holds (a pooled client) must not wait
    // out the close write and its linger.
    drop(inflight);
    // best-effort, both — the client may already be gone, and past a
    // deadline the socket drops without the frame
    if exit == LoopExit::ClosedByClient {
        let _ = budget.run(CLOSE_REPLY_TIMEOUT, tx.close()).await;
    }
    if let Some(frame) = exit.close_frame() {
        let written = matches!(
            budget
                .run(WS_CLOSE_WRITE_TIMEOUT, tx.send(Message::Close(Some(frame))))
                .await,
            Ok(Ok(()))
        );
        if written && let Some(linger) = exit.close_linger() {
            budget.linger(linger).await;
        }
    }
    tracing::debug!(conn_id = conn_id.get(), "ws: connection closed");
}

#[cfg(test)]
mod tests;
