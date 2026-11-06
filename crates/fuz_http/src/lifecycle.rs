//! Graceful-shutdown lifecycle harness for spine HTTP servers.
//!
//! Every spine consumer server (and the test-only `testing_spine_stub`)
//! drives the same graceful-shutdown shape: select on SIGINT / SIGTERM, flip
//! a [`CancellationToken`], stop accepting, then drain in-flight connections
//! up to a timeout. The signal-select half lives in [`fuz_sys::signal`]
//! (shared with `fuzd`); this module re-exports it and adds the HTTP serve
//! and drain on top, so consumers stop hand-rolling either.
//!
//! [`serve_with_shutdown`] runs its own accept loop over hyper rather than
//! `axum::serve`, serving each connection as axum does (HTTP/1 with
//! upgrades, `ConnectInfo<SocketAddr>` for handlers), because axum's drain
//! waits on every connection with no way to let one go, and its connections
//! carry no deadline of any kind.
//!
//! ## Live connections close when the token fires
//!
//! A drain alone handles neither long-lived transport. An open SSE stream is
//! a response body that never ends, so the drain waits on it until the
//! timeout; an upgraded WebSocket has left hyper for a detached task the
//! drain does not see, so the process exits under it and the client reads a
//! reset (a browser's 1006) instead of a close frame. So
//! [`serve_with_shutdown`] takes a required [`ShutdownCloser`] — in a spine
//! server the `fuz_auth::ConnectionCloser` it already holds, which extends this
//! trait — and when the token fires it closes every live connection
//! ([`ShutdownCloser::close_all_connections`]) beside the drain, then waits for
//! the connections to finish closing ([`ShutdownCloser::wait_closed`]), the
//! whole shutdown bounded by the drain timeout. A server with no live
//! connections passes [`NoopShutdownCloser`].
//!
//! Closing a stream is not always enough to end its connection: hyper polls
//! a response body only while the socket takes writes, so a stream — SSE, a
//! file download — whose client stopped reading never sees its own end. A
//! connection still open [`SHUTDOWN_CLOSE_TIMEOUT`] after the close-all is
//! cut once a whole window of that length passes with no handler running on
//! it and no byte written to it: its socket closed, its body dropped, and
//! with the body whatever registration it held, so the wait can resolve. A
//! stream still being written to its client keeps going, bounded by the
//! drain timeout.
//!
//! ## A write that makes no progress ends its connection
//!
//! The same fact holds outside shutdown: a response whose client stopped
//! reading is never polled again, so nothing in the handler or the body can
//! time it out, and the connection would hold its socket, its task, and what
//! its body holds — an SSE stream's queue, a file handle — for as long as the
//! client keeps the socket open. So every connection's socket carries a
//! write-progress deadline: while a write is waiting on the socket, a
//! [`WRITE_PROGRESS_TIMEOUT`] with no byte accepted fails the write, and
//! hyper drops the connection, body and all. Bytes accepted start the wait
//! over, so the deadline is on progress and not on the response as a whole,
//! and it runs only while a write is waiting: a connection with nothing to
//! send — an idle keep-alive connection, a quiet stream — is never cut by it.
//!
//! "Accepted" is the kernel taking bytes into the socket's send buffer, which
//! is coarser than the client reading: Linux reports a full socket writable
//! again once about a third of what it holds has been acknowledged. A reader
//! is cut when it stays that far behind for a whole deadline — the rule
//! nginx's `send_timeout` applies between two writes.
//!
//! An upgraded connection keeps the same socket, so the deadline is under a
//! WebSocket too, behind the shorter per-frame deadline its own loop keeps
//! (`fuz_realtime`'s `WS_WRITE_STALL_TIMEOUT`), which fires first.
//!
//! The TS twin has no such deadline, and cannot keep one: a Deno, Bun, or
//! Node handler under `fuz_app` is handed a response stream, not the socket,
//! so how long a stalled response is held there is the runtime's. This is
//! this spine's own, not shared behavior.
//!
//! ## A request's headers have a deadline
//!
//! A connection that is not in the middle of a request is waiting for one,
//! and that wait is bounded by [`HEADER_READ_TIMEOUT`]. A client that opens a
//! socket and never sends a request, or never finishes its headers, is
//! dropped with no response — the unauthenticated way to hold a socket, a
//! task, and a file descriptor. An idle keep-alive connection is closed after
//! the same wait, with a clean end of stream, so the constant is also the
//! server's keep-alive idle time. Nothing is timed while a request is in
//! progress — the handler running, the request body arriving, the response
//! being written — and an upgraded connection is no longer hyper's to time.
//!
//! Two timers make the one deadline. hyper's own (`header_read_timeout`)
//! starts when its HTTP/1 connection is ready to read a request head and
//! stops when the head is complete, and it starts again when a response
//! finishes on a kept-alive connection. But the connection builder
//! (hyper-util's, the one `axum::serve` uses) creates that HTTP/1 connection
//! only after reading the socket's first bytes itself, to tell an HTTP/2
//! preface from HTTP/1, and a client that sends nothing — or part of a
//! preface — waits there with no hyper timer. So the serve loop times the
//! first request itself: a connection that has dispatched no request one
//! deadline after its accept is dropped.
//!
//! Like the write-progress deadline, this has no TS twin: under `fuz_app` the
//! runtime owns the socket and its timeouts.
//!
//! Consumer-specific teardown — zzz's PTY `kill_all` — stays in the
//! consumer and runs **after** [`serve_with_shutdown`] returns. The harness
//! routes the signal, closes the live connections, and bounds the drain; it
//! never absorbs domain cleanup.
//!
//! Background upkeep runs beside the server on the same token:
//! [`spawn_periodic`] (re-exported from [`fuz_sys::periodic`]) is the loop a
//! sweep runs on — `fuz_auth::spawn_auth_cleanup` is built on it — and each
//! task is joined after the drain. [`serve_with_shutdown`] returns only once
//! the token has fired, so those tasks stop with it.
//!
//! ```no_run
//! # use std::time::Duration;
//! # async fn run(
//! #     listener: tokio::net::TcpListener,
//! #     router: fuz_http::GatedRouter,
//! #     closer: &dyn fuz_http::ShutdownCloser,
//! # ) {
//! # async fn sweep() -> Result<(), std::io::Error> { Ok(()) }
//! let token = fuz_http::shutdown_token();
//! let upkeep =
//!     fuz_http::spawn_periodic("sweep", Duration::from_secs(600), token.clone(), sweep);
//! let served = fuz_http::serve_with_shutdown(
//!     listener,
//!     router,
//!     token.clone(),
//!     closer,
//!     Duration::from_secs(10),
//! )
//! .await;
//! // consumer-specific teardown runs here, post-drain
//! let _ = upkeep.await;
//! served.expect("serve");
//! # }
//! ```

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::task::TaskTracker;
use tower::Service as _;

use crate::stack::GatedRouter;

/// Default graceful-shutdown connection-drain timeout (10 s).
///
/// The single source for every spine consumer's `RunAppOptions.drain_timeout`
/// — the spine servers and `testing_spine_stub` all pass this to
/// [`serve_with_shutdown`], so operators see one consistent shutdown UX
/// across the ecosystem. Bounds how long the drain waits for in-flight
/// connections before returning.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The transport-free SIGINT/SIGTERM → [`CancellationToken`] primitive,
/// re-exported from [`fuz_sys::signal`] — single-sourced there because `fuzd`
/// (UDS, no axum) builds its graceful shutdown on the same select. Pair it
/// with [`serve_with_shutdown`] to drive an axum server's graceful shutdown;
/// clone the token to observe the same shutdown from other tasks.
pub use fuz_sys::signal::shutdown_token;

/// The periodic background task loop — a startup pass, then one per interval,
/// until the token is cancelled — re-exported from [`fuz_sys::periodic`],
/// where it is single-sourced beside the shutdown token it stops on. A spine
/// server runs its sweeps on it and joins each handle after
/// [`serve_with_shutdown`] returns.
pub use fuz_sys::periodic::spawn_periodic;

/// The token type [`shutdown_token`] returns and [`serve_with_shutdown`] /
/// [`spawn_periodic`] take, re-exported so a consumer can name it — a
/// `shutdown` parameter on its own sweep, a fresh token in a test — without a
/// direct `tokio-util` dependency.
pub use tokio_util::sync::CancellationToken;

/// The future [`ShutdownCloser::wait_closed`] returns — boxed so the trait
/// stays object-safe.
pub type WaitClosedFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Close every live connection a server holds open past its HTTP requests —
/// WebSocket connections, SSE streams — when it shuts down.
///
/// [`serve_with_shutdown`] calls [`Self::close_all_connections`] the moment its
/// token fires, beside the drain, then awaits [`Self::wait_closed`], all
/// within the drain timeout. A spine server passes its
/// `fuz_auth::ConnectionCloser`, a subtrait of this one, so the registries
/// that close connections on revocation close them on shutdown too.
///
/// Both methods are required: closing only signals each connection, and its
/// close frame or final chunk is written by the connection's own task — a
/// shutdown that does not wait for those tasks exits under them, and the
/// client reads a reset instead of a close.
///
/// **Object-safe** — consumed as `&dyn ShutdownCloser`.
pub trait ShutdownCloser: Send + Sync {
    /// Close every live connection — pending admission or admitted — and
    /// refuse every connection that would open from now on, returning how
    /// many were closed. Sync and idempotent; a second call closes nothing.
    fn close_all_connections(&self) -> usize;

    /// Resolve once every connection closed by [`Self::close_all_connections`]
    /// has finished closing — at once when there were none. Waits forever if
    /// `close_all_connections` never ran, so a caller bounds it (as
    /// [`serve_with_shutdown`] does).
    fn wait_closed(&self) -> WaitClosedFuture<'_>;
}

/// The [`ShutdownCloser`] of a server with no live connections: closes
/// nothing and has nothing to wait for.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopShutdownCloser;

impl ShutdownCloser for NoopShutdownCloser {
    fn close_all_connections(&self) -> usize {
        0
    }

    fn wait_closed(&self) -> WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

/// How long a live connection gets to finish once the server begins shutting
/// down (1 s), measured from the close-all.
///
/// One bound for both transports. A WebSocket loop gives up its remaining
/// writes and its close frame past it (`fuz_realtime`'s shutdown budget). An
/// HTTP connection still open past it — a response body hyper is still
/// writing, typically a stream whose client stopped reading — is cut by
/// [`serve_with_shutdown`] at the first window of this length with no
/// handler running on it and no byte written to it: its socket is closed and
/// its body dropped. A connection still being written to, or whose
/// handler is still running, is checked again a window later, the drain
/// timeout bounding them all.
pub const SHUTDOWN_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a write may wait on a connection's socket with no byte accepted
/// before the connection is dropped (60 s).
///
/// A progress deadline, not a total one: it starts when a write first waits
/// on the socket — the client's receive window and the kernel's send buffer
/// are both full — and starts over whenever the socket accepts a byte. A
/// client that stopped reading a response (an SSE stream, a download) loses
/// the connection one such wait later, and with it the response body and
/// whatever that body holds; one that keeps taking bytes keeps it (the module
/// docs say how coarse "taking" is). A connection with no write waiting is
/// not timed at all.
///
/// It covers every connection [`serve_with_shutdown`] accepts, an upgraded
/// one included, and is deliberately the longest of the write bounds: a
/// WebSocket loop's own per-frame deadline and [`SHUTDOWN_CLOSE_TIMEOUT`] are
/// both shorter and fire first where they apply. The value is nginx's default
/// `send_timeout`, which is the same rule.
pub const WRITE_PROGRESS_TIMEOUT: Duration = Duration::from_secs(60);

const _: () = assert!(SHUTDOWN_CLOSE_TIMEOUT.as_millis() < WRITE_PROGRESS_TIMEOUT.as_millis());

/// How long a connection may wait for a complete request head before it is
/// closed (75 s).
///
/// The wait runs from the accept, or from the end of the previous response,
/// until the last header line of the next request has arrived.
///
/// One deadline with two jobs (the module docs name the timers that keep it):
///
/// - **Slow headers.** A client that connects and sends nothing, or starts a
///   request and never finishes its headers, is dropped at the deadline with
///   no response. It is a total, not a progress deadline — a byte now and
///   then does not extend it.
/// - **Keep-alive idle time.** The wait for the next request on a kept-alive
///   connection is the same wait, so an idle connection is closed, cleanly,
///   this long after its last response.
///
/// It stops when the head is complete and is not running while a request is
/// being handled, its body read, or its response written, however long those
/// take, and an upgraded connection has left HTTP for good: a slow handler,
/// an SSE stream, and a WebSocket are never cut by it.
///
/// The value is set by the second job. A reverse proxy that pools upstream
/// connections must be the side that closes an idle one, or it can send a
/// request into a connection the server is closing at that moment; nginx's
/// upstream `keepalive_timeout` defaults to 60 s, so this is longer. For the
/// first job that is the order of nginx's own `client_header_timeout` (60 s).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(75);

/// The deadlines [`serve_connection`] keeps on each connection —
/// [`ConnectionTimeouts::DEFAULT`] in a server, shorter ones in this module's
/// tests.
#[derive(Debug, Clone, Copy)]
struct ConnectionTimeouts {
    /// [`WRITE_PROGRESS_TIMEOUT`].
    write_progress: Duration,
    /// [`HEADER_READ_TIMEOUT`].
    header_read: Duration,
}

impl ConnectionTimeouts {
    const DEFAULT: Self = Self {
        write_progress: WRITE_PROGRESS_TIMEOUT,
        header_read: HEADER_READ_TIMEOUT,
    };
}

/// How long the accept loop pauses after an accept error that is not about a
/// single connection — running out of file descriptors (`EMFILE`) above all —
/// before trying again, as axum's serve does.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// Serve `router` on `listener` until `token` fires, then close `closer`'s
/// live connections and drain, bounded by `drain_timeout`.
///
/// `router` is a [`GatedRouter`] — the output of [`crate::compose_stack`] —
/// so every request this loop serves has passed the stack's gates; a router
/// assembled outside the stack has no way in.
///
/// Each accepted connection is served by hyper (HTTP/1, with upgrades, so a
/// WebSocket handshake hands its socket to the handler), as `axum::serve`
/// serves it, with the raw TCP peer address in every request's extensions as
/// [`ConnectInfo<SocketAddr>`] (loopback gates, trusted-proxy client-IP
/// resolution). An accept error about one connection (refused, aborted,
/// reset) is skipped, and any other — running out of file descriptors —
/// pauses the loop a second before it accepts again; neither ends it.
///
/// A connection whose client stops taking bytes while a write is waiting is
/// dropped after [`WRITE_PROGRESS_TIMEOUT`] with none accepted (module docs,
/// "A write that makes no progress ends its connection") — at any time, not
/// only during shutdown. A connection with no request in progress is closed
/// once [`HEADER_READ_TIMEOUT`] passes without a complete request head: a
/// client that never sends one, and an idle keep-alive connection alike.
///
/// On `token` cancellation:
///
/// 1. Stop accepting, ask every connection to finish gracefully (hyper's
///    graceful shutdown: the request in flight completes, keep-alive ends),
///    and close every live connection through
///    [`ShutdownCloser::close_all_connections`] — an SSE stream ends, so its
///    response completes, and a WebSocket gets its close frame.
/// 2. Wait for every connection to finish, then for the closed connections
///    to finish closing ([`ShutdownCloser::wait_closed`]). The wait follows
///    the drain so it also covers an upgrade whose request was still in
///    flight when the token fired.
/// 3. [`SHUTDOWN_CLOSE_TIMEOUT`] after the close-all, and every
///    [`SHUTDOWN_CLOSE_TIMEOUT`] after that, cut each connection still open
///    that had no handler running and no byte written in the window just
///    past: its socket is closed and its response body dropped. A response
///    body is polled only while the socket takes writes, so a stream whose
///    client stopped reading never sees its own end; the cut is what lets
///    that connection, and the registration its body holds, go. A
///    connection whose handler is still running, or whose stream is still
///    being written to its client, is not cut — the drain timeout bounds it.
/// 4. Return once everything has finished, or once `drain_timeout` has
///    elapsed since the token fired (whichever first). Connections still
///    open then are left running, as the process exits under them.
///
/// Consumer-specific teardown runs after this returns.
///
/// # Errors
///
/// None in practice — accept errors are retried, never returned, as
/// `axum::serve` treats them — but the [`std::io::Error`] stays in the
/// signature for consumers to map into their startup-error variant.
/// Reaching the drain timeout is not an error.
pub async fn serve_with_shutdown(
    listener: TcpListener,
    router: GatedRouter,
    token: CancellationToken,
    closer: &dyn ShutdownCloser,
    drain_timeout: Duration,
) -> Result<(), std::io::Error> {
    serve_with_timeouts(
        listener,
        router.into_router(),
        token,
        closer,
        drain_timeout,
        ConnectionTimeouts::DEFAULT,
    )
    .await
}

/// [`serve_with_shutdown`], with each connection's deadlines given.
async fn serve_with_timeouts(
    listener: TcpListener,
    router: Router,
    token: CancellationToken,
    closer: &dyn ShutdownCloser,
    drain_timeout: Duration,
    timeouts: ConnectionTimeouts,
) -> Result<(), std::io::Error> {
    let connections = TaskTracker::new();
    let cut = CancellationToken::new();
    accept_until_cancelled(&listener, &router, &token, &cut, &connections, timeouts).await;
    drop(listener);
    connections.close();

    let closed = closer.close_all_connections();
    eprintln!("Shutting down: closed {closed} live connection(s), draining...");

    // the wait follows the drain (doc, step 2); the cut timer never finishes
    // on its own, so the select ends with the drain or the timeout
    let drained = tokio::time::timeout(drain_timeout, async {
        let drain = async {
            connections.wait().await;
            closer.wait_closed().await;
        };
        let cut_after_close = async {
            tokio::time::sleep(SHUTDOWN_CLOSE_TIMEOUT).await;
            cut.cancel();
            std::future::pending::<()>().await;
        };
        tokio::select! {
            () = drain => {}
            () = cut_after_close => {}
        }
    })
    .await
    .is_ok();
    if drained {
        eprintln!("All connections drained");
    } else {
        eprintln!("Drain timeout, some connections still active");
    }
    Ok(())
}

/// Accept connections and serve each on its own task in `connections` until
/// `token` fires.
async fn accept_until_cancelled(
    listener: &TcpListener,
    router: &Router,
    token: &CancellationToken,
    cut: &CancellationToken,
    connections: &TaskTracker,
    timeouts: ConnectionTimeouts,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            () = token.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                connections.spawn(serve_connection(
                    stream,
                    peer,
                    router.clone(),
                    token.clone(),
                    cut.clone(),
                    timeouts,
                ));
            }
            Err(error) if is_connection_error(&error) => {}
            Err(error) => {
                tracing::error!("accept error: {error}");
                tokio::select! {
                    () = token.cancelled() => return,
                    () = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                }
            }
        }
    }
}

/// An accept error about the one connection being accepted, which the loop
/// skips — the same set `axum::serve` skips.
fn is_connection_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

/// Serve one connection until it ends — asked to finish gracefully once
/// `token` fires, and dropped from `cut` on at the first close-timeout window
/// with no handler running on it and nothing written to it
/// ([`serve_with_shutdown`], steps 1 and 3). At any time, a write that waits
/// `timeouts.write_progress` with no byte accepted fails, which ends the
/// connection, and so does `timeouts.header_read` without a complete request
/// head while no request is in progress.
async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    router: Router,
    token: CancellationToken,
    cut: CancellationToken,
    timeouts: ConnectionTimeouts,
) {
    let handlers = Arc::new(AtomicUsize::new(0));
    // set by the connection's first request, and never cleared
    let dispatched = Arc::new(AtomicBool::new(false));
    let service = tower::service_fn({
        let handlers = Arc::clone(&handlers);
        let dispatched = Arc::clone(&dispatched);
        move |mut request: axum::http::Request<Incoming>| {
            dispatched.store(true, Ordering::Release);
            request.extensions_mut().insert(ConnectInfo(peer));
            let running = HandlerRunning::start(&handlers);
            let response = router.clone().call(request);
            async move {
                let response = response.await;
                drop(running);
                response
            }
        }
    });
    let wrote = Arc::new(AtomicBool::new(false));
    let io = WriteProgress::new(
        TokioIo::new(stream),
        Arc::clone(&wrote),
        timeouts.write_progress,
    );
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(timeouts.header_read);
    let connection = builder.serve_connection_with_upgrades(io, TowerToHyperService::new(service));
    let mut connection = std::pin::pin!(connection);

    // hyper's timer starts with its HTTP/1 connection, which the builder
    // creates only once it has read the connection's first bytes; until a
    // first request arrives the wait is timed here (module docs, "A request's
    // headers have a deadline")
    let first_head = tokio::time::sleep(timeouts.header_read);
    let mut first_head = std::pin::pin!(first_head);
    let mut awaiting_first_head = true;
    loop {
        tokio::select! {
            // a connection's own error ends only that connection
            _ = connection.as_mut() => return,
            () = token.cancelled() => break,
            () = first_head.as_mut(), if awaiting_first_head => {
                if !dispatched.load(Ordering::Acquire) {
                    tracing::debug!(
                        "connection dropped: no request head in {:?}",
                        timeouts.header_read
                    );
                    return;
                }
                awaiting_first_head = false;
            }
        }
    }
    connection.as_mut().graceful_shutdown();
    wrote.store(false, Ordering::Relaxed);
    tokio::select! {
        _ = connection.as_mut() => return,
        () = cut.cancelled() => {}
    }
    // cut at the first close-timeout window with no handler running and no
    // byte written; a handler still running, or a write still landing, keeps
    // the connection to the next window, the drain timeout bounding them all
    loop {
        let wrote = wrote.swap(false, Ordering::Relaxed);
        if handlers.load(Ordering::Acquire) == 0 && !wrote {
            return;
        }
        tokio::select! {
            _ = connection.as_mut() => return,
            () = tokio::time::sleep(SHUTDOWN_CLOSE_TIMEOUT) => {}
        }
    }
}

/// A connection's socket that watches its writes: it records each one that
/// moves bytes, so the shutdown cut tells a client still reading from one
/// that stopped, and it fails a write that has waited `timeout` with no byte
/// accepted ([`WRITE_PROGRESS_TIMEOUT`]).
struct WriteProgress<I> {
    io: I,
    wrote: Arc<AtomicBool>,
    timeout: Duration,
    /// Set while a write is waiting on the socket: when that wait runs out.
    /// Cleared by the next byte the socket accepts. `None` whenever no write
    /// is waiting, so a connection with nothing to send is not timed.
    stalled: Option<Pin<Box<tokio::time::Sleep>>>,
    /// The wait ran out. Every later write fails the same way.
    timed_out: bool,
}

impl<I> WriteProgress<I> {
    const fn new(io: I, wrote: Arc<AtomicBool>, timeout: Duration) -> Self {
        Self {
            io,
            wrote,
            timeout,
            stalled: None,
            timed_out: false,
        }
    }

    /// Account for one poll of a write: bytes accepted end the wait, and a
    /// write left waiting starts it or checks it.
    fn observe_write(
        &mut self,
        cx: &mut Context<'_>,
        polled: Poll<std::io::Result<usize>>,
    ) -> Poll<std::io::Result<usize>> {
        match polled {
            Poll::Ready(Ok(n)) if n > 0 => {
                self.wrote.store(true, Ordering::Relaxed);
                self.stalled = None;
                polled
            }
            Poll::Pending => self.poll_stalled(cx).map(Err),
            Poll::Ready(_) => polled,
        }
    }

    /// A write is waiting: start the wait if none is running, and resolve
    /// with the timeout error once it has run out. Registers `cx` on the
    /// timer, so the connection is polled again when it fires.
    fn poll_stalled(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Error> {
        let timeout = self.timeout;
        let wait = self
            .stalled
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        if wait.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        self.stalled = None;
        self.timed_out = true;
        tracing::debug!("connection dropped: no write progress in {timeout:?}");
        Poll::Ready(write_timed_out())
    }
}

/// The error a write fails with once it has waited out the progress deadline.
fn write_timed_out() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "the client accepted no bytes within the write-progress deadline",
    )
}

impl<I: hyper::rt::Read + Unpin> hyper::rt::Read for WriteProgress<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<I: hyper::rt::Write + Unpin> hyper::rt::Write for WriteProgress<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.timed_out {
            return Poll::Ready(Err(write_timed_out()));
        }
        let polled = Pin::new(&mut self.io).poll_write(cx, buf);
        self.observe_write(cx, polled)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        if self.timed_out {
            return Poll::Ready(Err(write_timed_out()));
        }
        let polled = Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        self.observe_write(cx, polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    /// A flush left waiting is a write left waiting. A flush that completes
    /// does not end the wait — on a TCP socket it completes at once, having
    /// moved nothing.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.timed_out {
            return Poll::Ready(Err(write_timed_out()));
        }
        match Pin::new(&mut self.io).poll_flush(cx) {
            Poll::Pending => self.poll_stalled(cx).map(Err),
            polled @ Poll::Ready(_) => polled,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Counts a handler running on its connection while it lives — from the
/// request's dispatch until its response (head and body) is returned to
/// hyper, or the handler is dropped.
struct HandlerRunning(Arc<AtomicUsize>);

impl HandlerRunning {
    fn start(handlers: &Arc<AtomicUsize>) -> Self {
        handlers.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(handlers))
    }
}

impl Drop for HandlerRunning {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;

    use super::*;

    /// A closer whose closes and waits a test can watch and release.
    #[derive(Default)]
    struct TestCloser {
        /// Signalled by every `close_all_connections` call.
        closed: Notify,
        close_calls: AtomicUsize,
        /// `wait_closed` resolves once this is signalled — never, unless the
        /// test does.
        release_wait: Notify,
        wait_finished: AtomicUsize,
    }

    impl ShutdownCloser for TestCloser {
        fn close_all_connections(&self) -> usize {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            self.closed.notify_one();
            0
        }

        fn wait_closed(&self) -> WaitClosedFuture<'_> {
            Box::pin(async move {
                self.release_wait.notified().await;
                self.wait_finished.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    /// One HTTP/1.1 `GET path` on `addr`, returning the whole response.
    async fn get_once(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    /// A cancelled-before-serve token drains immediately and returns
    /// `Ok` without the timeout branch hanging.
    #[tokio::test]
    async fn pre_cancelled_token_returns_immediately() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let router = Router::new().route("/health", get(|| async { "ok" }));
        let token = CancellationToken::new();
        token.cancel();

        // A generous drain timeout — the serve branch should win the race
        // (graceful shutdown completes with no in-flight connections), so
        // this returns well under the timeout.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            serve_with_shutdown(
                listener,
                GatedRouter::ungated_for_tests(router),
                token,
                &NoopShutdownCloser,
                Duration::from_secs(30),
            ),
        )
        .await
        .expect("serve_with_shutdown returns before the test timeout");
        assert!(result.is_ok());
    }

    /// The close runs when the token fires, beside the drain — not after it.
    /// A response that ends only once the server closes its live connections
    /// (an SSE stream, in a real server) would otherwise hold the drain to
    /// its timeout.
    #[tokio::test]
    async fn live_connections_close_when_the_token_fires_not_after_the_drain() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let closer = Arc::new(TestCloser::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let router = Router::new().route(
            "/held",
            get({
                let closer = Arc::clone(&closer);
                move || async move {
                    let started = started_tx.lock().unwrap().take();
                    if let Some(tx) = started {
                        let _ = tx.send(());
                    }
                    // held until the server closes its live connections
                    closer.closed.notified().await;
                    "closed"
                }
            }),
        );
        closer.release_wait.notify_one();
        let token = CancellationToken::new();
        let server = tokio::spawn({
            let token = token.clone();
            let closer = Arc::clone(&closer);
            async move {
                serve_with_shutdown(
                    listener,
                    GatedRouter::ungated_for_tests(router),
                    token,
                    closer.as_ref(),
                    Duration::from_secs(30),
                )
                .await
            }
        });

        let client = tokio::spawn(get_once(addr, "/held"));
        started_rx.await.unwrap();
        let fired = std::time::Instant::now();
        token.cancel();

        let response = tokio::time::timeout(Duration::from_secs(10), client)
            .await
            .expect("the held request is answered once the token fires")
            .unwrap();
        assert!(response.ends_with("closed"), "response: {response}");
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("serve returns well before the drain timeout")
            .unwrap()
            .unwrap();
        assert!(
            fired.elapsed() < Duration::from_secs(10),
            "the drain did not wait on the held response"
        );
        assert_eq!(closer.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(closer.wait_finished.load(Ordering::SeqCst), 1);
    }

    /// `serve_with_shutdown` does not return until the closed connections
    /// have finished closing.
    #[tokio::test]
    async fn returns_only_after_the_closed_connections_finish() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let closer = Arc::new(TestCloser::default());
        let token = CancellationToken::new();
        let server = tokio::spawn({
            let token = token.clone();
            let closer = Arc::clone(&closer);
            async move {
                serve_with_shutdown(
                    listener,
                    GatedRouter::ungated_for_tests(Router::new()),
                    token,
                    closer.as_ref(),
                    Duration::from_secs(30),
                )
                .await
            }
        });
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), closer.closed.notified())
            .await
            .expect("the token fires the close");

        // an idle server drains in microseconds — only the wait holds it
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!server.is_finished(), "returned before the wait resolved");

        closer.release_wait.notify_one();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("returns once the wait resolves")
            .unwrap()
            .unwrap();
        assert_eq!(closer.wait_finished.load(Ordering::SeqCst), 1);
    }

    /// A close that never finishes is bounded by the drain timeout, which is
    /// not an error.
    #[tokio::test]
    async fn a_wait_that_never_resolves_is_bounded_by_the_drain_timeout() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let closer = TestCloser::default();
        let token = CancellationToken::new();
        token.cancel();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            serve_with_shutdown(
                listener,
                GatedRouter::ungated_for_tests(Router::new()),
                token,
                &closer,
                Duration::from_millis(200),
            ),
        )
        .await
        .expect("the drain timeout bounds the wait");
        assert!(result.is_ok());
        assert_eq!(closer.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(closer.wait_finished.load(Ordering::SeqCst), 0);
    }

    /// The drain and the wait share one budget, measured from the fire: a
    /// response that never ends holds the drain to the timeout, and the wait
    /// that follows gets no fresh timeout of its own.
    #[tokio::test]
    async fn the_drain_and_the_wait_share_one_budget_from_the_fire() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let closer = Arc::new(TestCloser::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let router = Router::new().route(
            "/never",
            get(move || async move {
                let started = started_tx.lock().unwrap().take();
                if let Some(tx) = started {
                    let _ = tx.send(());
                }
                std::future::pending::<&str>().await
            }),
        );
        let drain_timeout = Duration::from_millis(500);
        let token = CancellationToken::new();
        let server = tokio::spawn({
            let token = token.clone();
            let closer = Arc::clone(&closer);
            async move {
                serve_with_shutdown(
                    listener,
                    GatedRouter::ungated_for_tests(router),
                    token,
                    closer.as_ref(),
                    drain_timeout,
                )
                .await
            }
        });
        let _client = tokio::spawn(get_once(addr, "/never"));
        started_rx.await.unwrap();
        let fired = std::time::Instant::now();
        token.cancel();

        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("the drain timeout bounds the shutdown")
            .unwrap()
            .unwrap();
        let took = fired.elapsed();
        assert!(
            took < drain_timeout * 3 / 2,
            "one budget from the fire, not one per phase: took {took:?}"
        );
        assert_eq!(closer.wait_finished.load(Ordering::SeqCst), 0);
    }

    /// Run `router` under [`serve_with_shutdown`] with `drain_timeout` on a
    /// task, returning its address, its token, and the task — which reports
    /// when serve returned.
    async fn spawn_server(
        router: Router,
        drain_timeout: Duration,
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<std::time::Instant>,
    ) {
        spawn_server_with(router, drain_timeout, ConnectionTimeouts::DEFAULT).await
    }

    /// [`spawn_server`], with each connection's deadlines given.
    async fn spawn_server_with(
        router: Router,
        drain_timeout: Duration,
        timeouts: ConnectionTimeouts,
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<std::time::Instant>,
    ) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        spawn_server_on(listener, router, drain_timeout, timeouts)
    }

    /// [`spawn_server_with`], on a listener the test made.
    fn spawn_server_on(
        listener: TcpListener,
        router: Router,
        drain_timeout: Duration,
        timeouts: ConnectionTimeouts,
    ) -> (
        SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<std::time::Instant>,
    ) {
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let server = tokio::spawn({
            let token = token.clone();
            async move {
                serve_with_timeouts(
                    listener,
                    router,
                    token,
                    &NoopShutdownCloser,
                    drain_timeout,
                    timeouts,
                )
                .await
                .unwrap();
                std::time::Instant::now()
            }
        });
        (addr, token, server)
    }

    /// Handlers see the TCP peer of their connection as
    /// `ConnectInfo<SocketAddr>`.
    #[tokio::test]
    async fn handlers_see_the_peer_address_as_connect_info() {
        let router = Router::new().route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
        );
        let (addr, token, server) = spawn_server(router, Duration::from_secs(10)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let local = stream.local_addr().unwrap();
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        assert!(
            response.ends_with(&local.to_string()),
            "response: {response}"
        );

        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }

    /// An idle keep-alive connection is closed as the token fires — the
    /// graceful shutdown hyper is asked for — rather than held to the cut.
    #[tokio::test]
    async fn an_idle_keep_alive_connection_closes_when_the_token_fires() {
        let router = Router::new().route("/health", get(|| async { "ok" }));
        let (addr, token, server) = spawn_server(router, Duration::from_secs(10)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&response).ends_with("ok") {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection ended before the response");
            response.extend_from_slice(&buf[..n]);
        }

        let fired = std::time::Instant::now();
        token.cancel();
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("the idle connection is closed")
            .unwrap();
        assert_eq!(n, 0, "EOF, no further bytes");
        let returned = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        let took = returned.saturating_duration_since(fired);
        assert!(
            took < SHUTDOWN_CLOSE_TIMEOUT / 2,
            "closed by the graceful shutdown, not the cut: took {took:?}"
        );
    }

    /// A response body that never ends, to a client that stopped reading, is
    /// cut [`SHUTDOWN_CLOSE_TIMEOUT`] after the close-all: serve returns well
    /// before the drain timeout instead of waiting it out.
    #[tokio::test]
    async fn an_endless_body_to_a_stalled_reader_is_cut_before_the_drain_timeout() {
        let router = Router::new().route(
            "/endless",
            get(|| async {
                let chunk = axum::body::Bytes::from(vec![b'x'; 64 * 1024]);
                axum::body::Body::from_stream(futures::stream::repeat_with(move || {
                    Ok::<_, std::io::Error>(chunk.clone())
                }))
            }),
        );
        let drain_timeout = Duration::from_secs(10);
        let (addr, token, server) = spawn_server(router, drain_timeout).await;

        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut stream = socket.connect(addr).await.unwrap();
        stream
            .write_all(b"GET /endless HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&head).contains("\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection ended before the response head");
            head.extend_from_slice(&buf[..n]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200"));
        // stop reading; let the buffers on both sides fill
        tokio::time::sleep(Duration::from_millis(300)).await;

        let fired = std::time::Instant::now();
        token.cancel();
        let returned = tokio::time::timeout(drain_timeout * 2, server)
            .await
            .unwrap()
            .unwrap();
        let took = returned.saturating_duration_since(fired);
        // the buffers filled before the fire, so the first window, which
        // starts at the fire, saw nothing written
        assert!(
            took >= SHUTDOWN_CLOSE_TIMEOUT && took < SHUTDOWN_CLOSE_TIMEOUT * 2,
            "cut at the first close-timeout window, not held to the drain: took {took:?}"
        );
        drop(stream);
    }

    /// The cut spares a connection whose handler is still running: the
    /// handler finishes past [`SHUTDOWN_CLOSE_TIMEOUT`], its response arrives
    /// whole, and serve waits for the connection.
    #[tokio::test]
    async fn a_running_handler_is_not_cut_and_the_drain_waits_for_it() {
        let handler_time = SHUTDOWN_CLOSE_TIMEOUT + Duration::from_millis(700);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let router = Router::new().route(
            "/slow",
            get(move || async move {
                let started = started_tx.lock().unwrap().take();
                if let Some(tx) = started {
                    let _ = tx.send(());
                }
                tokio::time::sleep(handler_time).await;
                "finished"
            }),
        );
        let (addr, token, server) = spawn_server(router, Duration::from_secs(10)).await;

        let client = tokio::spawn(get_once(addr, "/slow"));
        started_rx.await.unwrap();
        let fired = std::time::Instant::now();
        token.cancel();

        let returned = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(10), client)
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        assert!(response.ends_with("finished"), "response: {response}");
        // the handler ends past the cut; serve returning before it would
        // mean the drain did not wait for the connection
        let took = returned.saturating_duration_since(fired);
        assert!(
            took > SHUTDOWN_CLOSE_TIMEOUT,
            "serve returned before the running handler finished: took {took:?}"
        );
    }

    /// The listener closes as the token fires: a connection attempt while
    /// serve is still draining is refused, not parked in the accept backlog
    /// until serve returns.
    #[tokio::test]
    async fn the_listener_closes_when_the_token_fires() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let release = Arc::new(Notify::new());
        let router = Router::new().route(
            "/hold",
            get({
                let release = Arc::clone(&release);
                move || async move {
                    let started = started_tx.lock().unwrap().take();
                    if let Some(tx) = started {
                        let _ = tx.send(());
                    }
                    release.notified().await;
                    "released"
                }
            }),
        );
        let (addr, token, server) = spawn_server(router, Duration::from_secs(10)).await;

        let client = tokio::spawn(get_once(addr, "/hold"));
        started_rx.await.unwrap();
        token.cancel();

        // the held handler keeps serve draining; an attempt that raced the
        // fire may land in the backlog and be reset, so retry until one is
        // refused outright
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match TcpStream::connect(addr).await {
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => break,
                    _ => tokio::time::sleep(Duration::from_millis(10)).await,
                }
            }
        })
        .await
        .expect("a connection attempt during the drain is refused");
        assert!(!server.is_finished(), "serve is still draining");

        release.notify_one();
        let response = tokio::time::timeout(Duration::from_secs(10), client)
            .await
            .unwrap()
            .unwrap();
        assert!(response.ends_with("released"), "response: {response}");
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }

    /// A stream whose client keeps reading is not cut: it is still
    /// delivering when [`SHUTDOWN_CLOSE_TIMEOUT`] passes, and arrives whole.
    #[tokio::test]
    async fn a_stream_still_being_delivered_is_not_cut() {
        use futures::StreamExt as _;

        const CHUNKS: usize = 25;
        let router = Router::new().route(
            "/trickle",
            get(|| async {
                let chunks = futures::stream::iter(0..CHUNKS).then(|_| async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"chunk;"))
                });
                axum::body::Body::from_stream(chunks)
            }),
        );
        let (addr, token, server) = spawn_server(router, Duration::from_secs(10)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /trickle HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&head).contains("\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection ended before the response head");
            head.extend_from_slice(&buf[..n]);
        }
        let fired = std::time::Instant::now();
        token.cancel();

        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        let mut body = head;
        body.extend_from_slice(&rest);
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body.matches("chunk;").count(), CHUNKS, "body: {body}");
        assert!(body.ends_with("0\r\n\r\n"), "the chunked body ends: {body}");
        let returned = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        assert!(returned.saturating_duration_since(fired) > SHUTDOWN_CLOSE_TIMEOUT);
    }

    /// A handler that finishes past the cut and returns an endless body to a
    /// client that stopped reading is cut a window later, not held to the
    /// drain timeout.
    #[tokio::test]
    async fn a_stalled_stream_from_a_handler_that_outlived_the_cut_is_cut() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let router = Router::new().route(
            "/late-endless",
            get(move || async move {
                let started = started_tx.lock().unwrap().take();
                if let Some(tx) = started {
                    let _ = tx.send(());
                }
                tokio::time::sleep(SHUTDOWN_CLOSE_TIMEOUT + Duration::from_millis(300)).await;
                let chunk = axum::body::Bytes::from(vec![b'x'; 64 * 1024]);
                axum::body::Body::from_stream(futures::stream::repeat_with(move || {
                    Ok::<_, std::io::Error>(chunk.clone())
                }))
            }),
        );
        let drain_timeout = Duration::from_secs(20);
        let (addr, token, server) = spawn_server(router, drain_timeout).await;

        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut stream = socket.connect(addr).await.unwrap();
        stream
            .write_all(b"GET /late-endless HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        started_rx.await.unwrap();
        let fired = std::time::Instant::now();
        token.cancel();
        // never read: the response fills both buffers once the handler returns

        let returned = tokio::time::timeout(drain_timeout * 2, server)
            .await
            .unwrap()
            .unwrap();
        let took = returned.saturating_duration_since(fired);
        assert!(
            took < drain_timeout / 4,
            "cut a window after the handler, not held to the drain: took {took:?}"
        );
        drop(stream);
    }

    // -- the write-progress deadline -----------------------------------------

    /// A [`WriteProgress`] over one end of an in-memory pipe that holds
    /// `buffer` bytes, with the real deadline, and the other end to read from.
    fn progress_pipe(
        buffer: usize,
    ) -> (
        WriteProgress<TokioIo<tokio::io::DuplexStream>>,
        tokio::io::DuplexStream,
    ) {
        let (near, far) = tokio::io::duplex(buffer);
        let io = WriteProgress::new(
            TokioIo::new(near),
            Arc::new(AtomicBool::new(false)),
            WRITE_PROGRESS_TIMEOUT,
        );
        (io, far)
    }

    /// Far past any deadline under test: a write or flush that has not
    /// resolved by then never will, and fails its test instead of hanging it.
    const NEVER: Duration = Duration::from_hours(24);

    async fn write<I: hyper::rt::Write + Unpin>(io: &mut I, buf: &[u8]) -> std::io::Result<usize> {
        let write = std::future::poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, buf));
        tokio::time::timeout(NEVER, write)
            .await
            .expect("the write resolves")
    }

    async fn flush<I: hyper::rt::Write + Unpin>(io: &mut I) -> std::io::Result<()> {
        let flush = std::future::poll_fn(|cx| Pin::new(&mut *io).poll_flush(cx));
        tokio::time::timeout(NEVER, flush)
            .await
            .expect("the flush resolves")
    }

    const PIPE: usize = 64;

    /// A write that waits the whole deadline with no byte accepted fails
    /// with `TimedOut`, at the deadline, and the socket stays failed.
    #[tokio::test(start_paused = true)]
    async fn a_write_that_makes_no_progress_times_out_at_the_deadline() {
        let (mut io, _far) = progress_pipe(PIPE);
        assert_eq!(write(&mut io, &[b'x'; PIPE]).await.unwrap(), PIPE);

        let stalled = tokio::time::Instant::now();
        let error = write(&mut io, b"more").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(stalled.elapsed(), WRITE_PROGRESS_TIMEOUT);

        let again = tokio::time::Instant::now();
        let error = write(&mut io, b"more").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            flush(&mut io).await.unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(again.elapsed(), Duration::ZERO, "failed for good");
    }

    /// Bytes accepted start the wait over: a write that waits, moves, and
    /// waits again is timed from the second wait, not the first.
    #[tokio::test(start_paused = true)]
    async fn progress_starts_the_wait_over() {
        let most = WRITE_PROGRESS_TIMEOUT * 2 / 3;
        let (mut io, mut far) = progress_pipe(PIPE);
        assert_eq!(write(&mut io, &[b'x'; PIPE]).await.unwrap(), PIPE);

        // waits most of a deadline, then the reader takes what was written
        tokio::time::timeout(most, write(&mut io, &[b'y'; PIPE]))
            .await
            .expect_err("the write is still waiting");
        let mut taken = [0u8; PIPE];
        far.read_exact(&mut taken).await.unwrap();
        assert_eq!(write(&mut io, &[b'y'; PIPE]).await.unwrap(), PIPE);

        // the pipe is full again: this wait began at the progress, so most
        // of a deadline more — past one deadline from the first wait — is
        // still inside it
        let progressed = tokio::time::Instant::now();
        tokio::time::timeout(most, write(&mut io, b"more"))
            .await
            .expect_err("the wait started over at the progress");
        let error = write(&mut io, b"more").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(progressed.elapsed(), WRITE_PROGRESS_TIMEOUT);
    }

    /// The deadline runs only while a write is waiting: a connection that
    /// wrote, then had nothing to send for many deadlines, is not failed —
    /// and a write that then waits gets a whole deadline of its own.
    #[tokio::test(start_paused = true)]
    async fn a_connection_with_no_write_waiting_is_never_timed_out() {
        let (mut io, _far) = progress_pipe(PIPE);
        assert_eq!(write(&mut io, b"head").await.unwrap(), 4);
        flush(&mut io).await.unwrap();

        tokio::time::sleep(WRITE_PROGRESS_TIMEOUT * 10).await;
        assert_eq!(
            write(&mut io, &[b'x'; PIPE - 4]).await.unwrap(),
            PIPE - 4,
            "an idle connection still writes"
        );
        flush(&mut io).await.unwrap();

        // quiet again, with the pipe now full: the wait a later write gets is
        // timed from when that write begins to wait, not from the last byte
        // the socket accepted
        tokio::time::sleep(WRITE_PROGRESS_TIMEOUT * 10).await;
        let stalled = tokio::time::Instant::now();
        let error = write(&mut io, b"more").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            stalled.elapsed(),
            WRITE_PROGRESS_TIMEOUT,
            "timed from when the write began to wait, not from the last write or the idle"
        );
    }

    /// A flush that completes moved nothing, so it does not end the wait.
    #[tokio::test(start_paused = true)]
    async fn a_completed_flush_does_not_start_the_wait_over() {
        let most = WRITE_PROGRESS_TIMEOUT * 2 / 3;
        let (mut io, _far) = progress_pipe(PIPE);
        assert_eq!(write(&mut io, &[b'x'; PIPE]).await.unwrap(), PIPE);

        let stalled = tokio::time::Instant::now();
        tokio::time::timeout(most, write(&mut io, b"more"))
            .await
            .expect_err("the write is still waiting");
        flush(&mut io).await.unwrap();
        let error = write(&mut io, b"more").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(stalled.elapsed(), WRITE_PROGRESS_TIMEOUT);
    }

    /// A socket that takes every write and never finishes a flush.
    struct FlushNeverCompletes;

    impl hyper::rt::Write for FlushNeverCompletes {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A flush left waiting is timed like a write left waiting.
    #[tokio::test(start_paused = true)]
    async fn a_flush_that_makes_no_progress_times_out_at_the_deadline() {
        let mut io = WriteProgress::new(
            FlushNeverCompletes,
            Arc::new(AtomicBool::new(false)),
            WRITE_PROGRESS_TIMEOUT,
        );
        assert_eq!(write(&mut io, b"head").await.unwrap(), 4);
        let stalled = tokio::time::Instant::now();
        let error = flush(&mut io).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(stalled.elapsed(), WRITE_PROGRESS_TIMEOUT);
    }

    /// The default deadlines, with the write-progress one cut to `timeout` so
    /// a test can wait it out.
    const fn short_write_progress(timeout: Duration) -> ConnectionTimeouts {
        ConnectionTimeouts {
            write_progress: timeout,
            ..ConnectionTimeouts::DEFAULT
        }
    }

    /// Signals when it is dropped — carried in a response body to report the
    /// body being dropped.
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }

    /// A router whose `/endless` answers with a body that never ends, and a
    /// receiver that resolves when that body is dropped.
    fn endless_router() -> (Router, tokio::sync::oneshot::Receiver<()>) {
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel::<()>();
        let dropped_tx = Arc::new(std::sync::Mutex::new(Some(dropped_tx)));
        let router = Router::new().route(
            "/endless",
            get(move || async move {
                let signal = DropSignal(dropped_tx.lock().unwrap().take());
                let chunk = axum::body::Bytes::from(vec![b'x'; 64 * 1024]);
                axum::body::Body::from_stream(futures::stream::repeat_with(move || {
                    let _held = &signal;
                    Ok::<_, std::io::Error>(chunk.clone())
                }))
            }),
        );
        (router, dropped_rx)
    }

    /// Connect with a small receive buffer, request `path`, and read the
    /// response head — the rest is left unread.
    async fn request_and_read_head(addr: SocketAddr, path: &str) -> TcpStream {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut stream = socket.connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&head).contains("\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection ended before the response head");
            head.extend_from_slice(&buf[..n]);
        }
        stream
    }

    /// With no shutdown in sight, a response whose client stopped reading is
    /// dropped — body and all — once a write has waited out the deadline.
    #[tokio::test]
    async fn a_stalled_reader_loses_its_connection_at_the_write_progress_deadline() {
        let timeouts = short_write_progress(Duration::from_millis(400));
        let (router, body_dropped) = endless_router();
        let (addr, token, server) =
            spawn_server_with(router, Duration::from_secs(10), timeouts).await;

        let opened = std::time::Instant::now();
        let stream = request_and_read_head(addr, "/endless").await;
        // never read again: the buffers fill, and the write waits

        tokio::time::timeout(Duration::from_secs(10), body_dropped)
            .await
            .expect("the connection is dropped at the write-progress deadline")
            .unwrap();
        assert!(
            opened.elapsed() >= timeouts.write_progress,
            "not before a whole deadline with a write waiting"
        );
        assert!(!server.is_finished(), "the server is not shutting down");

        drop(stream);
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }

    /// A client that reads slowly, but keeps reading, keeps its connection
    /// for many deadlines: the bytes it takes start the wait over.
    #[tokio::test]
    async fn a_slow_reader_keeps_its_connection_past_the_deadline() {
        let timeouts = short_write_progress(Duration::from_millis(400));
        let (router, mut body_dropped) = endless_router();
        // A small send buffer on the accepted sockets (inherited from the
        // listener): the kernel takes more from the server only once a share
        // of what it holds has been acknowledged, and with the default
        // megabytes a trickle would not get there within this test's deadline.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(4096).unwrap();
        socket.bind(([127, 0, 0, 1], 0).into()).unwrap();
        let listener = socket.listen(16).unwrap();
        let (addr, token, server) =
            spawn_server_on(listener, router, Duration::from_secs(10), timeouts);

        let mut stream = request_and_read_head(addr, "/endless").await;
        let reading = std::time::Instant::now();
        let mut buf = [0u8; 2048];
        // a trickle, each pause a fraction of the deadline, for several
        // deadlines; the server's writes wait on the full buffers throughout
        while reading.elapsed() < timeouts.write_progress * 5 {
            tokio::time::sleep(timeouts.write_progress / 8).await;
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "the connection was cut under a client still reading");
        }
        assert!(
            body_dropped.try_recv().is_err(),
            "the body is still being written"
        );

        drop(stream);
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }

    /// A keep-alive connection with nothing being written to it is idle far
    /// past the write-progress deadline and still serves its next request.
    #[tokio::test]
    async fn an_idle_keep_alive_connection_outlives_the_write_progress_deadline() {
        let timeouts = short_write_progress(Duration::from_millis(100));
        let router = Router::new().route("/health", get(|| async { "ok" }));
        let (addr, token, server) =
            spawn_server_with(router, Duration::from_secs(10), timeouts).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        for _ in 0..2 {
            stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: test\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            let mut buf = [0u8; 1024];
            while !String::from_utf8_lossy(&response).ends_with("ok") {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0, "the idle connection was closed");
                response.extend_from_slice(&buf[..n]);
            }
            tokio::time::sleep(timeouts.write_progress * 6).await;
        }

        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }

    /// An upgraded connection writes through the same socket: a write on it
    /// that waits out the deadline fails with `TimedOut`.
    #[tokio::test]
    async fn an_upgraded_connection_is_under_the_write_progress_deadline() {
        let timeouts = short_write_progress(Duration::from_millis(400));
        let (failed_tx, failed_rx) =
            tokio::sync::oneshot::channel::<(std::io::ErrorKind, Duration)>();
        let failed_tx = Arc::new(std::sync::Mutex::new(Some(failed_tx)));
        let router = Router::new().route(
            "/upgrade",
            get(move |request: axum::extract::Request| async move {
                let failed_tx = failed_tx.lock().unwrap().take();
                tokio::spawn(async move {
                    let upgraded = hyper::upgrade::on(request).await.unwrap();
                    let mut io = TokioIo::new(upgraded);
                    let chunk = vec![b'x'; 64 * 1024];
                    let mut last_write = std::time::Instant::now();
                    let error = loop {
                        match io.write_all(&chunk).await {
                            Ok(()) => last_write = std::time::Instant::now(),
                            Err(error) => break error,
                        }
                    };
                    if let Some(tx) = failed_tx {
                        let _ = tx.send((error.kind(), last_write.elapsed()));
                    }
                });
                axum::http::Response::builder()
                    .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
                    .header(axum::http::header::CONNECTION, "upgrade")
                    .header(axum::http::header::UPGRADE, "test")
                    .body(axum::body::Body::empty())
                    .unwrap()
            }),
        );
        let (addr, token, server) =
            spawn_server_with(router, Duration::from_secs(10), timeouts).await;

        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        let mut stream = socket.connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /upgrade HTTP/1.1\r\nHost: test\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\n",
            )
            .await
            .unwrap();
        // never read: the upgraded side's writes fill both buffers

        let (kind, waited) = tokio::time::timeout(Duration::from_secs(10), failed_rx)
            .await
            .expect("the upgraded write fails at the deadline")
            .unwrap();
        assert_eq!(kind, std::io::ErrorKind::TimedOut);
        assert!(
            waited >= timeouts.write_progress,
            "the failing write waited a whole deadline: {waited:?}"
        );

        drop(stream);
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }

    // -- the header-read deadline --------------------------------------------

    /// The header-read deadline the tests below run under.
    const SHORT_HEADER_READ: Duration = Duration::from_millis(400);

    /// The default deadlines, with the header-read one cut to
    /// [`SHORT_HEADER_READ`] so a test can wait it out.
    const fn short_header_read() -> ConnectionTimeouts {
        ConnectionTimeouts {
            header_read: SHORT_HEADER_READ,
            ..ConnectionTimeouts::DEFAULT
        }
    }

    /// Read until the server ends the connection, returning what arrived and
    /// whether the end was clean (an end of stream, not a reset).
    async fn read_until_closed(stream: &mut TcpStream) -> (Vec<u8>, bool) {
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
                .await
                .expect("the server closes the connection")
            {
                Ok(0) => return (received, true),
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(_) => return (received, false),
            }
        }
    }

    async fn shut_down(
        token: CancellationToken,
        server: tokio::task::JoinHandle<std::time::Instant>,
    ) {
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }

    fn health_router() -> Router {
        Router::new().route("/health", get(|| async { "ok" }))
    }

    /// A client that connects and sends nothing — or the start of an HTTP/2
    /// preface, which the connection builder waits on the rest of before any
    /// HTTP connection exists — is dropped at the deadline, with no response.
    #[tokio::test]
    async fn a_client_that_sends_no_request_is_closed_at_the_header_read_deadline() {
        let (addr, token, server) = spawn_server_with(
            health_router(),
            Duration::from_secs(10),
            short_header_read(),
        )
        .await;

        for sent in [&b""[..], &b"PRI * HTTP/2.0\r\n"[..]] {
            // the clock starts before the connect, so before the server's wait does
            let connected = std::time::Instant::now();
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(sent).await.unwrap();
            let (received, _) = read_until_closed(&mut stream).await;
            let took = connected.elapsed();
            let sent = String::from_utf8_lossy(sent);
            assert!(received.is_empty(), "no response to {sent:?}: {received:?}");
            assert!(
                took >= SHORT_HEADER_READ && took < SHORT_HEADER_READ * 4,
                "closed at the deadline after {sent:?}: took {took:?}"
            );
        }
        shut_down(token, server).await;
    }

    /// A client that starts a request and keeps its headers trickling is
    /// dropped at the deadline all the same: the deadline is on the whole
    /// head, not on the gap between bytes.
    #[tokio::test]
    async fn a_client_that_never_finishes_its_headers_is_closed_at_the_deadline() {
        let (addr, token, server) = spawn_server_with(
            health_router(),
            Duration::from_secs(10),
            short_header_read(),
        )
        .await;

        // the clock starts before the connect, so before the server's wait does
        let connected = std::time::Instant::now();
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        let trickle = tokio::spawn(async move {
            let _ = writer
                .write_all(b"GET /health HTTP/1.1\r\nHost: test\r\nX-Slow: ")
                .await;
            // a byte per eighth of a deadline, for as long as the server takes them
            while writer.write_all(b"x").await.is_ok() {
                tokio::time::sleep(SHORT_HEADER_READ / 8).await;
            }
        });
        let mut received = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut buf = [0u8; 1024];
            while let Ok(n) = reader.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
        })
        .await;
        let took = connected.elapsed();
        trickle.abort();
        closed.expect("the server closes the connection");
        assert!(received.is_empty(), "no response: {received:?}");
        assert!(
            took >= SHORT_HEADER_READ && took < SHORT_HEADER_READ * 4,
            "closed at the deadline though bytes kept arriving: took {took:?}"
        );
        shut_down(token, server).await;
    }

    /// An idle keep-alive connection is closed — cleanly, nothing more sent —
    /// one deadline after its last response.
    #[tokio::test]
    async fn an_idle_keep_alive_connection_is_closed_at_the_header_read_deadline() {
        let (addr, token, server) = spawn_server_with(
            health_router(),
            Duration::from_secs(10),
            short_header_read(),
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        // two requests, the second after most of a deadline: the wait starts
        // over at each response. The clock is read before each request is
        // sent, so before the server's wait for the one after it begins.
        let mut requested = std::time::Instant::now();
        for request in 0..2 {
            if request > 0 {
                tokio::time::sleep(SHORT_HEADER_READ * 3 / 4).await;
            }
            requested = std::time::Instant::now();
            stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: test\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            let mut buf = [0u8; 1024];
            while !String::from_utf8_lossy(&response).ends_with("ok") {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0, "connection ended before the response");
                response.extend_from_slice(&buf[..n]);
            }
        }
        let (received, clean) = read_until_closed(&mut stream).await;
        let took = requested.elapsed();
        assert!(received.is_empty(), "nothing follows the response");
        assert!(clean, "an end of stream, not a reset");
        // a wait that had not started over would end a quarter of a deadline
        // after the second request
        assert!(
            took >= SHORT_HEADER_READ && took < SHORT_HEADER_READ * 4,
            "closed one deadline after the last response: took {took:?}"
        );
        shut_down(token, server).await;
    }

    /// The deadline holds for a later request on a kept-alive connection as
    /// for the first: headers that never finish end the connection one
    /// deadline after the response before them.
    #[tokio::test]
    async fn a_later_request_that_never_finishes_its_headers_is_closed_at_the_deadline() {
        let (addr, token, server) = spawn_server_with(
            health_router(),
            Duration::from_secs(10),
            short_header_read(),
        )
        .await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        // read before the request is sent, so before the server's wait for
        // the next one begins
        let requested = std::time::Instant::now();
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&response).ends_with("ok") {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection ended before the response");
            response.extend_from_slice(&buf[..n]);
        }
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: te")
            .await
            .unwrap();
        let (received, _) = read_until_closed(&mut stream).await;
        let took = requested.elapsed();
        assert!(received.is_empty(), "no second response: {received:?}");
        assert!(
            took >= SHORT_HEADER_READ && took < SHORT_HEADER_READ * 4,
            "closed one deadline after the first response: took {took:?}"
        );
        shut_down(token, server).await;
    }

    /// A request whose handler runs for several deadlines is answered whole:
    /// nothing is timed once the head is in.
    #[tokio::test]
    async fn a_request_in_flight_outlives_the_header_read_deadline() {
        let router = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(SHORT_HEADER_READ * 4).await;
                "finished"
            }),
        );
        let (addr, token, server) =
            spawn_server_with(router, Duration::from_secs(10), short_header_read()).await;

        let response = tokio::time::timeout(Duration::from_secs(10), get_once(addr, "/slow"))
            .await
            .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
        assert!(response.ends_with("finished"), "response: {response}");
        shut_down(token, server).await;
    }

    /// A response that streams for several deadlines — an SSE stream's shape —
    /// arrives whole.
    #[tokio::test]
    async fn a_streaming_response_outlives_the_header_read_deadline() {
        use futures::StreamExt as _;

        const CHUNKS: usize = 16;
        let router = Router::new().route(
            "/trickle",
            get(|| async {
                let chunks = futures::stream::iter(0..CHUNKS).then(|_| async {
                    tokio::time::sleep(SHORT_HEADER_READ / 4).await;
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"chunk;"))
                });
                axum::body::Body::from_stream(chunks)
            }),
        );
        let (addr, token, server) =
            spawn_server_with(router, Duration::from_secs(10), short_header_read()).await;

        let response = tokio::time::timeout(Duration::from_secs(10), get_once(addr, "/trickle"))
            .await
            .unwrap();
        assert_eq!(
            response.matches("chunk;").count(),
            CHUNKS,
            "response: {response}"
        );
        assert!(response.ends_with("0\r\n\r\n"), "the chunked body ends");
        shut_down(token, server).await;
    }

    /// An upgraded connection that is silent for several deadlines still
    /// carries bytes both ways afterwards.
    #[tokio::test]
    async fn an_upgraded_connection_outlives_the_header_read_deadline() {
        let router = Router::new().route(
            "/upgrade",
            get(|request: axum::extract::Request| async move {
                tokio::spawn(async move {
                    let upgraded = hyper::upgrade::on(request).await.unwrap();
                    let mut io = TokioIo::new(upgraded);
                    let mut ping = [0u8; 4];
                    io.read_exact(&mut ping).await.unwrap();
                    io.write_all(b"pong").await.unwrap();
                });
                axum::http::Response::builder()
                    .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
                    .header(axum::http::header::CONNECTION, "upgrade")
                    .header(axum::http::header::UPGRADE, "test")
                    .body(axum::body::Body::empty())
                    .unwrap()
            }),
        );
        let (addr, token, server) =
            spawn_server_with(router, Duration::from_secs(10), short_header_read()).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /upgrade HTTP/1.1\r\nHost: test\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\n",
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !String::from_utf8_lossy(&head).contains("\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection ended before the 101");
            head.extend_from_slice(&buf[..n]);
        }
        assert!(head.starts_with(b"HTTP/1.1 101"));

        tokio::time::sleep(SHORT_HEADER_READ * 4).await;
        stream.write_all(b"ping").await.unwrap();
        let mut pong = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut pong))
            .await
            .expect("the upgraded connection is still open")
            .unwrap();
        assert_eq!(&pong, b"pong");
        shut_down(token, server).await;
    }

    /// A connection that has sent nothing is closed as the token fires, like
    /// an idle keep-alive one — not held to the cut.
    #[tokio::test]
    async fn a_connection_that_sent_nothing_closes_when_the_token_fires() {
        let (addr, token, server) = spawn_server(health_router(), Duration::from_secs(10)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        // let the accept loop take it and start serving
        tokio::time::sleep(Duration::from_millis(100)).await;
        let fired = std::time::Instant::now();
        token.cancel();
        let (received, _) = read_until_closed(&mut stream).await;
        assert!(received.is_empty());
        let returned = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        let took = returned.saturating_duration_since(fired);
        assert!(
            took < SHUTDOWN_CLOSE_TIMEOUT / 2,
            "closed by the graceful shutdown, not the cut: took {took:?}"
        );
    }
}
