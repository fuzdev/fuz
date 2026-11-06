//! Server-Sent Events (SSE) primitives for the fuz spine — the one-way
//! fan-out half of the realtime surface, parallel to the bidirectional
//! WebSocket [`crate::ConnectionRegistry`].
//!
//! A consumer mounts an admin-gated `text/event-stream` route, opens each
//! stream on an [`SseRegistry`] — [`SseRegistry::subscribe_pending`] then
//! [`SseRegistry::admit`], see "Two-phase registration" below — and wires
//! [`register_audit_sse_listener`](crate::register_audit_sse_listener) onto
//! its audit emitter so every audit row fans to every open stream as one
//! `data:` frame. Revocations close streams through the registry's
//! [`ConnectionCloser`] impl (below).
//!
//! ## Wire parity
//!
//! Byte-identical to the TS reference (`fuz_app`'s `create_sse_response` +
//! `create_audit_log_sse`) so the cross-backend SSE suite sees one contract
//! on both backends:
//!
//! - the connect comment is exactly [`SSE_CONNECTED_COMMENT`]
//!   (`: connected\n\n`), flushed first to push the response headers through
//!   proxies so the client sees the open without waiting for an event;
//! - each event frame is `data: {"method":<event_type>,"params":<row>}\n\n`,
//!   the JSON-RPC-shaped notification the TS `SseNotification` emits.
//!
//! ## Close-on-revoke
//!
//! [`SseRegistry`] implements [`ConnectionCloser`]: a close ends every stream
//! whose [`ConnectionIdentity`] matches its [`ConnectionCloseTarget`]
//! ([`ConnectionIdentity::matches`], the predicate the WS registry closes by
//! too), pending or admitted. A consumer binds it through
//! [`RealtimeCloser`](crate::RealtimeCloser), which fans each close to the
//! WS registry as well, so every closer reaches the streams through it:
//!
//! - the revocation handlers' own closes — after the commit on the action
//!   path, before the fail-open audit write on the REST `/logout` /
//!   `/password` path, so a failed audit INSERT cannot leave a revoked
//!   account's stream open;
//! - the one audit listener, `fuz_auth::register_revocation_guard`,
//!   which repeats a revocation's close on its materialized row
//!   (`fuz_auth::ConnectionCloseTarget::from_audit_event` — a no-op repeat when a
//!   handler closed first) and is the only closer of a role revocation: a
//!   stream gated on the revoked role ([`ConnectionIdentity::required_roles`])
//!   ends on the same rows as a socket gated on it.
//!
//! The audit fan-out listener ([`register_audit_sse_listener`](crate::register_audit_sse_listener))
//! only broadcasts; it closes nothing. Over-closing a one-way admin feed is
//! cheap (the client reconnects if still authorized).
//!
//! ## Keep-alive
//!
//! Every [`SSE_KEEP_ALIVE_INTERVAL`] an admitted stream writes
//! [`SSE_KEEP_ALIVE_COMMENT`], so a proxy that cuts a connection idle past its
//! read timeout (nginx's default is 60 s) keeps an open stream open;
//! `EventSource` ignores comments. Per stream, from its admission, whether or
//! not data frames were written in between — the TS `create_sse_response`'s
//! `setInterval`, with the same bytes. A consumer sets another interval, or
//! turns keep-alives off, with [`SseRegistry::with_keep_alive`].
//!
//! The body writes the comment itself, when it is polled, rather than queueing
//! it: it never waits in the queue and is not charged to the budget below. The
//! TS twin writes its comment through the stream's budget instead; the outcome
//! is the same, since a client that stopped reading is never polled here, so no
//! keep-alive piles up behind it, and the serve loop's write deadline ends the
//! connection as it does for any stalled body. A tick missed while the body
//! was not polled is not made up: the next one comes an interval after the
//! late one.
//!
//! ## Credential deadline
//!
//! A stream is authorized once, at open, and expiry writes nothing a
//! revocation listener could hear. So each stream carries the deadline of
//! the credential it was opened with
//! ([`SseSubscription::credential_deadline`], from
//! [`fuz_auth::ResolvedAuth::credential_deadline`]), and its body watches it:
//! when it passes, the body removes its own registration — the close a
//! revocation makes — writes what was already queued, and ends with no final
//! frame. A client reconnecting on the expired credential meets the gates.
//! The wait sleeps in bounded steps
//! ([`CREDENTIAL_DEADLINE_SLEEP_CAP`](crate::CREDENTIAL_DEADLINE_SLEEP_CAP)),
//! so a deadline years out never meets tokio's sleep ceiling, and ends at the
//! wall-clock deadline too, so a host suspend does not extend it (see
//! [`crate::credential_deadline`]). Twin of the TS
//! `create_audit_log_route_specs` stream, which closes the stream at the same
//! deadline.
//!
//! ## Per-session stream cap
//!
//! At most `max_per_scope` streams per session
//! ([`AUDIT_LOG_SSE_MAX_PER_SCOPE`] unless the consumer overrides it via
//! [`SseRegistry::with_max_per_scope`]; `None` disables). The cap's *scope* is the stream's
//! [`ConnectionIdentity::session_hash`] — the slot the TS `SseRegistry`
//! calls `scope`, which the audit route fills with the session token hash. So
//! it limits tabs per session: an account's streams across its sessions are
//! bounded only transitively, by the session cap times this one, and a stream
//! with no session hash (a bearer or daemon-token caller on a consumer that
//! widened the credential gate) is never counted — both as in the TS twin.
//!
//! The policy is **evict-oldest**, like the WS
//! [`ConnectionRegistry`](crate::ConnectionRegistry)'s per-account cap: a
//! stream past the cap is always admitted, and the session's oldest streams
//! are dropped to make room. Check-and-evict runs at **admission** —
//! [`SseRegistry::admit`] — under the map's write lock, so concurrent admissions for
//! one session can never overshoot; the route admits only after every gate
//! passed and the credential was re-checked, so a refused request never
//! closes another stream.
//!
//! An evicted stream ends the way a revoked one does — its sender is dropped,
//! it drains whatever was already queued, and the body ends with no final
//! frame (the TS `do_close`). Nothing on the wire says *why*, and a browser
//! `EventSource` reconnects on its own: a client holding one tab more than the
//! cap can ping-pong, each reconnect evicting the next-oldest tab. A closing
//! frame that says "superseded" would let the client stop retrying, but it is
//! a wire change both twins would have to make together.
//!
//! ## Outbound bound
//!
//! [`SseRegistry::broadcast`] never waits on a stream: each frame is queued
//! for the stream's body to write when its client reads. One buffer is shared
//! by every stream it is queued for, and each stream's queue is charged for
//! the frame in full: its bytes plus
//! [`OUTBOUND_FRAME_OVERHEAD_BYTES`](crate::OUTBOUND_FRAME_OVERHEAD_BYTES).
//! The charges waiting for one stream stay within
//! [`SSE_OUTBOUND_QUEUE_BYTES`], except that a frame is always accepted into
//! an empty queue, so a single row larger than the budget is still
//! deliverable.
//!
//! A frame that does not fit **ends the stream**: its queue is discarded,
//! its registration removed, and the body ends with no final frame the next
//! time it is polled — as a cap eviction ends one, minus the backlog. One
//! `warn` line names the stream's account and what was queued; no audit row
//! is written, since each one would itself be fanned to every stream. A
//! client that is reading reconnects and misses the rows in between; the
//! audit log itself is the record.
//!
//! The budget bounds memory, not the connection: a stream whose client
//! stopped reading is never polled again, so the body does not see its own
//! end, whether an overflow ended it (its queue already discarded) or a
//! close did (its queue, which a close leaves for the body to write, still
//! held). What ends the connection is the serve loop: a response write that
//! has waited `fuz_http::WRITE_PROGRESS_TIMEOUT` with no byte accepted fails,
//! and the connection is dropped with the body and what it holds. A stream
//! with nothing waiting to be written is not timed, so one whose client
//! vanished while the feed was quiet stays until a frame is sent to it —
//! or until the server shuts down (below).
//!
//! ## Two-phase registration
//!
//! A stream is authorized once, at open, so a revocation has to be able to
//! reach it from the moment its credential is read. The route's gates run
//! before the stream exists, and each revocation closes only the streams
//! *registered* under what it revoked — admitting straight after the gates
//! would leave a window in which a revocation closes nothing and the stream
//! then opens on a dead session, or under a role its actor no longer holds.
//!
//! So registration is split, the same way as the WS registry's (see
//! `connection_registry`'s module doc for the argument in full). After its
//! gates the route registers the stream with
//! [`SseRegistry::subscribe_pending`] **un-admitted** — closeable by every
//! matching close, and otherwise inert: no frame is fanned to it, the cap
//! neither counts nor evicts for it, and [`SseRegistry::count`] does not see
//! it. It then checks for the shutdown ([`PendingSseStream::closed`], below),
//! re-reads the credential, the acting actor, and its role grants
//! (`fuz_auth::recheck_admission`), and only then calls
//! [`SseRegistry::admit`], which opens the feed, or refuses with
//! [`NotAdmitted`] when a revocation closed the registration in between.
//! Every close fires after its revocation committed, so it either precedes
//! the registration — and the re-reads see it — or finds the entry.
//! `crate::audit_stream`'s "Admission" has the route half.
//!
//! ## Shutdown
//!
//! An open stream is a response body that never ends, so the server's
//! graceful drain would wait on it until its timeout. [`SseRegistry`] is a
//! [`fuz_http::ShutdownCloser`] (through [`ConnectionCloser`]):
//! `fuz_http::serve_with_shutdown` calls `close_all_connections` when its token
//! fires, which drops every stream's sender, pending or admitted — each body
//! drains what was queued and ends cleanly — and sets the registry closing,
//! under the same write lock, so every later registration is born closed: a
//! pending one reads as closed ([`PendingSseStream::closed`], which the
//! route checks right after registering, before its re-reads) and is refused at
//! [`SseRegistry::admit`] with [`NotAdmitted::ShuttingDown`] (the route
//! answers the connect comment alone, a stream that ends at once, and the
//! client reconnects). `wait_closed` resolves once every body has ended: each
//! registration's guard, which rides in its body, holds a token of the
//! registry's task tracker. A body whose client stopped reading is never
//! polled again, so it never sees its sender dropped; `serve_with_shutdown`
//! cuts that connection once a `fuz_http::SHUTDOWN_CLOSE_TIMEOUT` window
//! passes with nothing written to it, dropping the body and its guard with
//! it.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use futures::Stream;
use parking_lot::RwLock;
use tokio_util::task::TaskTracker;
use tokio_util::task::task_tracker::TaskTrackerToken;
use uuid::Uuid;

use fuz_auth::{ConnectionCloseTarget, ConnectionCloser};
use fuz_http::{ShutdownCloser, WaitClosedFuture};

use crate::audit_stream::AUDIT_LOG_SSE_MAX_PER_SCOPE;
use crate::connection::{ConnectionIdentity, NotAdmitted};
use crate::credential_deadline::credential_deadline_reached;
use crate::outbound_queue::{
    OnClose, Overflow, Push, QueueHandle, QueueReceiver, QueueSender, outbound_queue,
};

/// A queued SSE frame: one buffer, shared by every stream it is queued for.
type SseFrame = Arc<str>;

/// Connect comment flushed first on every stream.
///
/// Byte-identical to the TS `SSE_CONNECTED_COMMENT` (`: connected\n\n`), so
/// the cross-backend SSE suite's connected-comment assertion passes on both
/// backends.
pub const SSE_CONNECTED_COMMENT: &str = ": connected\n\n";

/// The byte budget of one SSE stream's outbound queue — what may wait for
/// the stream's client to read it (module doc, "Outbound bound").
///
/// Equal to [`fuz_http::DEFAULT_BODY_LIMIT_BYTES`], the default cap on one
/// request body. An audit row is bounded by the request that produced it,
/// so on a server that keeps that default the budget holds a burst of
/// ordinary rows or one at the largest. A server that raises its body limit
/// can produce a row larger than the whole budget, which is delivered only
/// into an empty queue: the value is fixed and does not follow the server's
/// body limit.
///
/// Each waiting frame is charged its bytes as written to the stream, `data: `
/// prefix and blank-line terminator included, plus
/// [`OUTBOUND_FRAME_OVERHEAD_BYTES`](crate::OUTBOUND_FRAME_OVERHEAD_BYTES).
/// A frame that does not fit ends the stream; a frame is always accepted
/// into an empty queue.
pub const SSE_OUTBOUND_QUEUE_BYTES: usize = fuz_http::DEFAULT_BODY_LIMIT_BYTES;

/// The comment an admitted stream writes every [`SSE_KEEP_ALIVE_INTERVAL`]
/// (module doc, "Keep-alive").
///
/// Byte-identical to the TS `SSE_KEEP_ALIVE_COMMENT` (`: keepalive\n\n`).
pub const SSE_KEEP_ALIVE_COMMENT: &str = ": keepalive\n\n";

/// How often an admitted stream writes [`SSE_KEEP_ALIVE_COMMENT`] — 15 s, a
/// quarter of nginx's default 60 s read timeout, the TS
/// `SSE_KEEP_ALIVE_INTERVAL_MS`. [`SseRegistry::new`] applies it.
pub const SSE_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// The longest keep-alive interval [`SseRegistry::with_keep_alive`] takes —
/// 2³¹ − 1 ms, about 24.8 days, the TS `SSE_KEEP_ALIVE_INTERVAL_MS_MAX`.
pub const SSE_KEEP_ALIVE_INTERVAL_MAX: Duration = Duration::from_millis(2_147_483_647);

/// Whether [`SseRegistry::with_keep_alive`] takes `interval`: `None` (off), or
/// a positive interval up to [`SSE_KEEP_ALIVE_INTERVAL_MAX`].
///
/// Zero would write keep-alives as fast as the body is polled, and a far-off
/// one overflows the tick's `Instant`. The check of the TS
/// `validate_sse_keep_alive_ms`, so a server's boot can refuse a bad interval
/// with a configuration error before it builds the registry.
#[must_use]
pub const fn sse_keep_alive_is_valid(interval: Option<Duration>) -> bool {
    match interval {
        None => true,
        Some(interval) => {
            !interval.is_zero() && interval.as_nanos() <= SSE_KEEP_ALIVE_INTERVAL_MAX.as_nanos()
        }
    }
}

/// Unique id for one registered SSE stream — [`SseRegistry`]'s map key,
/// private to this module. Ordered, because ids are monotonic and the
/// per-session cap evicts the smallest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct SseConnectionId(u64);

/// Per-subscriber delivery sink + identity.
#[derive(Debug)]
struct SseSubscriber {
    /// Frames queued for this stream — each already a complete SSE frame
    /// including its trailing `\n\n` — bounded at
    /// [`SSE_OUTBOUND_QUEUE_BYTES`]. Dropping it ends the stream once the
    /// body has written what was queued.
    sender: QueueSender<SseFrame>,
    /// What the stream registered under — every close matches it
    /// ([`ConnectionIdentity::matches`]), and the per-session cap counts its
    /// `session_hash`.
    identity: ConnectionIdentity,
    /// Whether the stream has been admitted — `false` between
    /// [`SseRegistry::subscribe_pending`] and [`SseRegistry::admit`]. An
    /// un-admitted subscriber is closeable and nothing else (module doc,
    /// "Two-phase registration").
    admitted: bool,
}

/// What one stream registers under — the argument to
/// [`SseRegistry::subscribe_pending`].
#[derive(Debug, Clone, Default)]
pub struct SseSubscription {
    /// The identity every revocation close matches
    /// ([`ConnectionIdentity::matches`]), the same shape a WebSocket registers
    /// under: a role-gated stream lists its role in `required_roles`. Its
    /// `session_hash` is also the scope the per-session stream cap counts
    /// (module doc); `None` there (bearer / daemon-token auth) leaves the
    /// stream uncapped.
    pub identity: ConnectionIdentity,
    /// When the credential the stream was opened with expires
    /// ([`fuz_auth::ResolvedAuth::credential_deadline`]) — the stream ends
    /// then, the way a revoked one does (module doc, "Credential deadline").
    /// `None` (a daemon token, an eternal API token) never ends it. Not an
    /// identity key: no close matches on it.
    pub credential_deadline: Option<std::time::Instant>,
}

/// Registry of open SSE streams.
///
/// Parallel to [`crate::ConnectionRegistry`] (the WS half) and shares its
/// discipline: collect senders under a brief read lock, then send outside
/// the lock so the lock window stays O(subscribers), not
/// O(subscribers × per-channel contention).
///
/// Every stream in a registry receives every [`Self::broadcast`] — there is no
/// channel filter — so one registry is one feed: in the spine, the audit log
/// ([`register_audit_sse_listener`](crate::register_audit_sse_listener)). That
/// is why its per-session cap defaults to the audit stream's
/// [`AUDIT_LOG_SSE_MAX_PER_SCOPE`].
#[derive(Debug)]
pub struct SseRegistry {
    /// Monotonic id allocator — never reused, so a stale
    /// [`SubscriberGuard`] can only miss, never remove a newer stream.
    next_id: AtomicU64,
    subscribers: RwLock<HashMap<SseConnectionId, SseSubscriber>>,
    /// Per-session stream cap; `None` = uncapped. See the module doc.
    max_per_scope: Option<NonZeroUsize>,
    /// Each admitted stream's keep-alive interval; `None` writes none (module
    /// doc, "Keep-alive").
    keep_alive: Option<Duration>,
    /// Set by `close_all_connections` under the `subscribers` write lock, and
    /// read under it by every registration (module doc, "Shutdown").
    closing: AtomicBool,
    /// One token per live [`SubscriberGuard`]; `wait_closed` waits for it to
    /// be closed and empty.
    closers: TaskTracker,
}

impl Default for SseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SseRegistry {
    /// Construct an empty registry with the per-session stream cap at
    /// [`AUDIT_LOG_SSE_MAX_PER_SCOPE`] and keep-alives every
    /// [`SSE_KEEP_ALIVE_INTERVAL`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            subscribers: RwLock::new(HashMap::new()),
            max_per_scope: NonZeroUsize::new(AUDIT_LOG_SSE_MAX_PER_SCOPE),
            keep_alive: Some(SSE_KEEP_ALIVE_INTERVAL),
            closing: AtomicBool::new(false),
            closers: TaskTracker::new(),
        }
    }

    /// Replace the per-session stream cap; `None` disables it — the TS
    /// `create_audit_log_sse({max_per_scope: null})`.
    ///
    /// Builder-style, for the composition root:
    /// `SseRegistry::new().with_max_per_scope(…)`.
    #[must_use]
    pub const fn with_max_per_scope(mut self, max: Option<NonZeroUsize>) -> Self {
        self.max_per_scope = max;
        self
    }

    /// Replace each admitted stream's keep-alive interval; `None` writes no
    /// keep-alives — the TS `create_audit_log_sse({keep_alive_ms})`, `null`
    /// for off. Builder-style, like [`Self::with_max_per_scope`].
    ///
    /// # Panics
    ///
    /// Panics on an interval [`sse_keep_alive_is_valid`] refuses — zero, or
    /// past [`SSE_KEEP_ALIVE_INTERVAL_MAX`] — as the twin throws on one. A
    /// boot-time wiring invariant, caught at assembly.
    #[must_use]
    pub const fn with_keep_alive(mut self, interval: Option<Duration>) -> Self {
        if let Some(interval) = interval {
            assert!(
                !interval.is_zero(),
                "SseRegistry::with_keep_alive: a zero interval — pass a positive one, or None to \
                 turn keep-alives off"
            );
        }
        assert!(
            sse_keep_alive_is_valid(interval),
            "SseRegistry::with_keep_alive: an interval past SSE_KEEP_ALIVE_INTERVAL_MAX \
             (2^31 - 1 ms) — pass a shorter one, or None to turn keep-alives off"
        );
        self.keep_alive = interval;
        self
    }

    /// Number of open — **admitted** — streams. A registration still pending
    /// admission is counted by [`Self::pending_count`] instead.
    #[must_use]
    pub fn count(&self) -> usize {
        self.subscribers
            .read()
            .values()
            .filter(|sub| sub.admitted)
            .count()
    }

    /// Number of registrations awaiting admission — between
    /// [`Self::subscribe_pending`] and [`Self::admit`] (or their refusal).
    /// For telemetry and tests.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.subscribers
            .read()
            .values()
            .filter(|sub| !sub.admitted)
            .count()
    }

    /// Register a subscriber pending admission — only inserted: the cap is
    /// [`Self::admit`]'s to enforce. Once the registry is closing it is not
    /// inserted: the subscriber is dropped — its sender with it — and the id
    /// names nothing (module doc, "Shutdown").
    fn add_pending_subscriber(
        &self,
        sender: QueueSender<SseFrame>,
        subscription: SseSubscription,
    ) -> SseConnectionId {
        let id = SseConnectionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let subscriber = SseSubscriber {
            sender,
            identity: subscription.identity,
            admitted: false,
        };
        let mut subs = self.subscribers.write();
        if !self.closing.load(Ordering::Acquire) {
            subs.insert(id, subscriber);
        }
        id
    }

    /// Make room under the per-session cap for one more admitted stream on
    /// `session_hash`, returning how many streams were removed — zero for a
    /// stream with no session hash or a disabled cap. The caller holds the
    /// write lock.
    fn evict_for_admission(
        &self,
        subs: &mut HashMap<SseConnectionId, SseSubscriber>,
        session_hash: Option<&str>,
    ) -> usize {
        match (session_hash, self.max_per_scope) {
            (Some(session_hash), Some(max)) => evict_oldest_for_scope(subs, session_hash, max),
            _ => 0,
        }
    }

    /// Log a cap eviction — `closed` streams on `account_id`'s session.
    fn log_cap_eviction(&self, account_id: Option<Uuid>, closed: usize) {
        if closed > 0
            && let Some(max) = self.max_per_scope
        {
            // the session hash is a credential lookup key — log the account
            tracing::info!(
                account_id = account_id.map(tracing::field::display),
                closed,
                max = max.get(),
                "sse: stream cap closed oldest"
            );
        }
    }

    fn remove_subscriber(&self, id: SseConnectionId) {
        self.subscribers.write().remove(&id);
    }

    /// Fan `frame` (a complete SSE frame, including its `\n\n` terminator)
    /// to every open stream. Returns the number of streams it was queued
    /// for. A registration pending admission is not an open stream and is
    /// skipped — no audit row is queued toward a subscriber not yet
    /// authorized.
    ///
    /// Never waits on a stream, and queues one shared copy of the frame
    /// however many streams take it. A stream whose queue it does not fit is
    /// ended and not counted (module doc, "Outbound bound"); the others are
    /// unaffected.
    pub fn broadcast(&self, frame: &str) -> usize {
        let frame: SseFrame = Arc::from(frame);
        let recipients: Vec<(SseConnectionId, Option<Uuid>, QueueHandle<SseFrame>)> = {
            let subs = self.subscribers.read();
            subs.iter()
                .filter(|(_, sub)| sub.admitted)
                .map(|(id, sub)| (*id, sub.identity.account_id, sub.sender.handle()))
                .collect()
        };
        let mut count = 0;
        for (id, account_id, handle) in recipients {
            match handle.push(Arc::clone(&frame)) {
                Push::Queued => count += 1,
                Push::Refused => {}
                Push::Overflow(overflow) => self.close_overflowed(id, account_id, overflow),
            }
        }
        count
    }

    /// End a stream whose outbound queue just overflowed (module doc,
    /// "Outbound bound"). The queue has already discarded its frames and is
    /// refusing more; removing the subscriber drops its sender, so the body
    /// ends when it is next polled.
    fn close_overflowed(&self, id: SseConnectionId, account_id: Option<Uuid>, overflow: Overflow) {
        // gone already: another close ended the stream first
        if self.subscribers.write().remove(&id).is_none() {
            return;
        }
        tracing::warn!(
            stream_id = id.0,
            account_id = account_id.map(tracing::field::display),
            queued_bytes = overflow.queued_bytes,
            queued_frames = overflow.queued_frames,
            frame_bytes = overflow.frame_bytes,
            "sse: outbound queue overflow, ending the stream"
        );
    }

    /// Shared internals for [`ConnectionCloser::close_connections`].
    ///
    /// Removes every subscriber matching `predicate`, dropping its sender —
    /// the stream's receiver then yields `None`, ending the response body.
    /// Matches every entry, pending or admitted — never filter on admission
    /// here: reaching a registration in flight is the point of the pending
    /// phase, and [`Self::admit`] then refuses it.
    /// Returns the number of streams closed. The WS twin is
    /// `connection_registry`'s `close_matching`, which additionally cancels
    /// the per-connection signal token (SSE streams carry no token).
    fn close_matching(&self, mut predicate: impl FnMut(&SseSubscriber) -> bool) -> usize {
        let mut closed = 0;
        self.subscribers.write().retain(|_, sub| {
            let matches = predicate(sub);
            if matches {
                closed += 1;
            }
            !matches
        });
        closed
    }

    /// Register a stream **un-admitted** — phase one of the two-phase
    /// registration the audit route runs (module doc).
    ///
    /// The registration is closeable at once by every close whose target
    /// `subscription.identity` matches, and until [`Self::admit`] it receives no frame, is not
    /// counted, and evicts nothing. Dropping the returned
    /// [`PendingSseStream`] — a gate that then refuses the request — removes
    /// it.
    pub fn subscribe_pending(self: &Arc<Self>, subscription: SseSubscription) -> PendingSseStream {
        let (tx, rx) = sse_queue();
        let credential_deadline = subscription.credential_deadline;
        let id = self.add_pending_subscriber(tx, subscription);
        PendingSseStream {
            rx,
            guard: SubscriberGuard::new(Arc::clone(self), id),
            credential_deadline,
        }
    }

    /// Admit a pending stream and return its body stream — phase two.
    ///
    /// Under one write lock: if the registration is gone — a revocation
    /// closed it while it was pending — nothing is evicted and the stream is
    /// refused. Otherwise the per-session cap is enforced (module doc,
    /// "Per-session stream cap"), counting only admitted streams, and the
    /// stream starts receiving [`Self::broadcast`] frames. The body's first
    /// item is the connect comment ([`SSE_CONNECTED_COMMENT`]); dropping it
    /// (client disconnect) removes the subscriber.
    ///
    /// # Errors
    ///
    /// When the registration is no longer in this registry:
    /// [`NotAdmitted::ShuttingDown`] once the registry is closing (the
    /// shutdown closed it, or it was born closed), [`NotAdmitted::Revoked`]
    /// otherwise.
    pub fn admit(
        &self,
        pending: PendingSseStream,
    ) -> Result<impl Stream<Item = Result<String, Infallible>> + Send + 'static, NotAdmitted> {
        let PendingSseStream {
            rx,
            guard,
            credential_deadline,
        } = pending;
        // ids are per-registry counters, so a pending stream from another
        // registry could name a stranger's entry here
        if !std::ptr::eq(Arc::as_ptr(&guard.registry), self) {
            return Err(NotAdmitted::Revoked);
        }
        let (account_id, closed) = {
            let mut subs = self.subscribers.write();
            let Some(sub) = subs.get(&guard.id) else {
                // a revocation that closed it before the shutdown began reads
                // as the shutdown — the route's answer is the same either way
                return Err(if self.closing.load(Ordering::Acquire) {
                    NotAdmitted::ShuttingDown
                } else {
                    NotAdmitted::Revoked
                });
            };
            let account_id = sub.identity.account_id;
            let session_hash = sub.identity.session_hash.clone();
            // the entry itself is un-admitted, so the eviction neither counts
            // nor removes it
            let closed = self.evict_for_admission(&mut subs, session_hash.as_deref());
            if let Some(sub) = subs.get_mut(&guard.id) {
                sub.admitted = true;
            }
            (account_id, closed)
        };
        self.log_cap_eviction(account_id, closed);
        let keep_alive = self.keep_alive;
        Ok(body_stream(rx, guard, credential_deadline, keep_alive))
    }
}

/// A registered stream awaiting admission — what
/// [`SseRegistry::subscribe_pending`] returns and [`SseRegistry::admit`]
/// consumes. Dropping it removes the registration.
#[must_use = "admit it with `SseRegistry::admit`; dropping it removes the registration"]
pub struct PendingSseStream {
    rx: QueueReceiver<SseFrame>,
    guard: SubscriberGuard,
    credential_deadline: Option<std::time::Instant>,
}

impl PendingSseStream {
    /// Why the registration is already closed, if it is — read without the
    /// registry's lock, so the route can answer before costlier work (its
    /// admission re-read): [`NotAdmitted::ShuttingDown`] once
    /// the registry is closing (the shutdown closed it, or it was born
    /// closed), [`NotAdmitted::Revoked`] for one a revocation closed. A
    /// revocation that closed it before the shutdown began reads as the
    /// shutdown, as [`SseRegistry::admit`] answers it. `None` promises
    /// nothing — `admit` decides under the lock.
    #[must_use]
    pub fn closed(&self) -> Option<NotAdmitted> {
        // the receiver first, the flag last: the close-all sets the flag under
        // its lock before it drops the senders, so a receiver its drop closed
        // has the flag visible too, and a flag set in the gap reads alone
        let receiver_closed = self.rx.is_closed();
        if self.guard.registry.closing.load(Ordering::Acquire) {
            Some(NotAdmitted::ShuttingDown)
        } else if receiver_closed {
            Some(NotAdmitted::Revoked)
        } else {
            None
        }
    }
}

impl std::fmt::Debug for PendingSseStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingSseStream")
            .field("id", &self.guard.id)
            .finish_non_exhaustive()
    }
}

/// One stream's outbound queue: a budget of [`SSE_OUTBOUND_QUEUE_BYTES`],
/// and a close that lets the body write what was queued before it ends.
fn sse_queue() -> (QueueSender<SseFrame>, QueueReceiver<SseFrame>) {
    outbound_queue(SSE_OUTBOUND_QUEUE_BYTES, OnClose::Drain)
}

/// The response body of one stream: the connect comment, then every frame
/// queued on `rx` until its sender is dropped, with a keep-alive comment every
/// `keep_alive` (module doc, "Keep-alive"). `guard` rides in the stream's
/// state, so the subscriber is removed when the body is dropped or completes.
/// A frame leaves the queue's budget when the body takes it, and is copied
/// out of its shared buffer only then.
///
/// At `credential_deadline` the body removes its own subscriber — the close a
/// revocation makes, dropping the sender — then writes what was already
/// queued and ends (module doc, "Credential deadline").
fn body_stream(
    rx: QueueReceiver<SseFrame>,
    guard: SubscriberGuard,
    credential_deadline: Option<std::time::Instant>,
    keep_alive: Option<Duration>,
) -> impl Stream<Item = Result<String, Infallible>> + Send + 'static {
    let expiry = credential_deadline.map(|deadline| -> CredentialExpiry {
        Box::pin(credential_deadline_reached(Some(deadline)))
    });
    let body = BodyState {
        rx,
        guard,
        expiry,
        keep_alive,
        ticks: None,
    };
    futures::stream::unfold(
        (StreamPhase::Connect, body),
        |(phase, mut body)| async move {
            match phase {
                StreamPhase::Connect => {
                    // the keep-alive clock starts as the stream opens, on the
                    // runtime that polls it
                    body.ticks = body.keep_alive.map(|period| {
                        let mut ticks =
                            tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        ticks
                    });
                    Some((
                        Ok(SSE_CONNECTED_COMMENT.to_owned()),
                        (StreamPhase::Data, body),
                    ))
                }
                StreamPhase::Data => loop {
                    tokio::select! {
                        frame = body.rx.recv() => {
                            return frame.map(|frame| {
                                (Ok(String::from(&*frame)), (StreamPhase::Data, body))
                            });
                        }
                        () = until_expired(&mut body.expiry) => {
                            // the credential expired: close the stream as a
                            // revocation does — the sender goes, and what was
                            // queued is still written by the arm above
                            body.guard.registry.remove_subscriber(body.guard.id);
                            tracing::info!(stream_id = body.guard.id.0, "sse: credential expired, ending the stream");
                            body.expiry = None;
                        }
                        () = next_tick(&mut body.ticks) => {
                            return Some((
                                Ok(SSE_KEEP_ALIVE_COMMENT.to_owned()),
                                (StreamPhase::Data, body),
                            ));
                        }
                    }
                },
            }
        },
    )
}

/// What one stream's body holds between items.
struct BodyState {
    rx: QueueReceiver<SseFrame>,
    guard: SubscriberGuard,
    expiry: Option<CredentialExpiry>,
    /// The keep-alive interval, `None` for off.
    keep_alive: Option<Duration>,
    /// Its clock, started when the connect comment is written.
    ticks: Option<tokio::time::Interval>,
}

/// Resolve when the stream's credential deadline passes; never, without one.
async fn until_expired(expiry: &mut Option<CredentialExpiry>) {
    match expiry {
        Some(wait) => wait.as_mut().await,
        None => std::future::pending().await,
    }
}

/// Resolve at the stream's next keep-alive; never, with keep-alives off.
async fn next_tick(ticks: &mut Option<tokio::time::Interval>) {
    match ticks {
        Some(ticks) => {
            ticks.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// The pending wait on one stream's credential deadline.
type CredentialExpiry = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

// -- ConnectionCloser impl --------------------------------------------------------
//
// How every revocation reaches a stream (module doc, "Close-on-revoke"):
// consumers bind this through `RealtimeCloser`, which fans each close to the
// WS registry too, and hand that one closer to the handlers and to the audit
// listener alike.

impl ShutdownCloser for SseRegistry {
    /// End every stream, pending or admitted, by dropping its sender, and
    /// set the registry closing so every later registration is born closed
    /// (module doc, "Shutdown"). Returns how many streams were closed; a
    /// second call closes nothing.
    fn close_all_connections(&self) -> usize {
        let closed: Vec<SseSubscriber> = {
            let mut subs = self.subscribers.write();
            self.closing.store(true, Ordering::Release);
            subs.drain().map(|(_, sub)| sub).collect()
        };
        let count = closed.len();
        drop(closed);
        self.closers.close();
        count
    }

    /// Resolve once `close_all_connections` has run and every stream body — and
    /// every pending registration — is gone.
    fn wait_closed(&self) -> WaitClosedFuture<'_> {
        Box::pin(self.closers.wait())
    }
}

impl ConnectionCloser for SseRegistry {
    /// End every stream, pending or admitted, whose identity matches
    /// `target`, by dropping its sender — its receiver then yields `None`,
    /// ending the response body. Returns the number of streams closed.
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        self.close_matching(|sub| sub.identity.matches(target))
    }
}

/// Remove `session_hash`'s oldest **admitted** streams until one more fits
/// under `max`, returning how many were removed. Dropping each removed
/// subscriber drops its sender, so its body drains what was queued and ends.
/// The caller holds the write lock and inserts — or admits — the new stream
/// in the same window. Pending registrations are neither counted nor removed.
///
/// O(open streams) per call — a scan of the map, cheap next to the gate
/// pipeline the route runs before subscribing. Twin of the TS
/// `SseRegistry`'s `#enforce_scope_limit`.
fn evict_oldest_for_scope(
    subs: &mut HashMap<SseConnectionId, SseSubscriber>,
    session_hash: &str,
    max: NonZeroUsize,
) -> usize {
    let mut owned: Vec<SseConnectionId> = subs
        .iter()
        .filter(|(_, sub)| {
            sub.admitted && sub.identity.session_hash.as_deref() == Some(session_hash)
        })
        .map(|(id, _)| *id)
        .collect();
    if owned.len() < max.get() {
        return 0;
    }
    owned.sort_unstable();
    let excess = owned.len() + 1 - max.get();
    for id in &owned[..excess] {
        subs.remove(id);
    }
    excess
}

/// Whether the connect comment or a queued frame is next.
enum StreamPhase {
    Connect,
    Data,
}

/// Removes the subscriber from the registry when the stream ends — client
/// disconnect (the body stream is dropped), server-side close (the sender
/// was dropped, `recv` returned `None`, the stream completed), or a pending
/// registration dropped unadmitted.
///
/// A server-side close already removed the entry, so the guard's removal is a
/// no-op then — and only ever a no-op, since ids are never reused.
///
/// It also holds the registry's shutdown wait open while it lives (module
/// doc, "Shutdown").
struct SubscriberGuard {
    registry: Arc<SseRegistry>,
    id: SseConnectionId,
    _closer: TaskTrackerToken,
}

impl SubscriberGuard {
    fn new(registry: Arc<SseRegistry>, id: SseConnectionId) -> Self {
        let closer = registry.closers.token();
        Self {
            registry,
            id,
            _closer: closer,
        }
    }
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        self.registry.remove_subscriber(self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use super::{NotAdmitted, SseRegistry, SseSubscription};

    /// The close-all sets the registry closing under its lock and drops the
    /// senders only after releasing it. A registration read in that gap —
    /// the registry closing, its receiver not yet closed — is already
    /// shutting down: a route whose re-read fails there answers the connect
    /// comment, not 500. The gap is built directly, since no public call
    /// stops the close-all inside it.
    #[test]
    fn a_pending_stream_reads_the_shutdown_before_its_receiver() {
        let registry = Arc::new(SseRegistry::new());
        let pending = registry.subscribe_pending(SseSubscription::default());
        assert_eq!(pending.closed(), None);

        registry.closing.store(true, Ordering::Release);
        assert!(!pending.rx.is_closed());
        assert_eq!(pending.closed(), Some(NotAdmitted::ShuttingDown));
    }
}
