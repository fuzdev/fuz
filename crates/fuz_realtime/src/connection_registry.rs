//! Concrete connection registry.
//!
//! Owns every connection-tracking method, so a consumer's app struct
//! holds a handle to this rather than the connection map itself.
//!
//! ## Backing store
//!
//! `parking_lot::RwLock<HashMap<ConnectionId, ConnectionInfo>>`.
//! Read-locked on every WS send (per
//! frame); write-locked on add/remove and revocation paths. **Hidden
//! behind the concrete struct's public surface** so a future `DashMap`
//! swap (justified by a WS load benchmark) is a
//! non-breaking internal change.
//!
//! ## Broadcast lock discipline
//!
//! `broadcast` / `broadcast_filtered` / `send_to_account` follow the
//! **collect-then-send** pattern: gather a pushing handle to each matching
//! connection's queue under a brief read lock, drop the lock, then push to
//! each outside it. Each queue takes its own mutex; holding the registry
//! read lock across N pushes serializes the entire fan-out behind whichever
//! queue contends first. The split keeps the registry lock window
//! `O(matched_count)` instead of `O(matched_count` ×
//! `per_queue_contention`).
//!
//! ## Outbound bound
//!
//! Every send here — `send_to`, `broadcast`, `broadcast_filtered`,
//! `send_to_account`, and through `send_to` the notify closure and
//! `ActionPeer` request frames — queues onto the recipient's outbound channel
//! ([`connection_channel`](crate::connection_channel)), which holds a byte
//! budget of waiting frames: each is charged its UTF-8 length plus
//! [`OUTBOUND_FRAME_OVERHEAD_BYTES`](crate::OUTBOUND_FRAME_OVERHEAD_BYTES),
//! and a frame is always accepted into an empty queue. Nothing else limits
//! how many frames wait, so a burst queued with no await in it — which gives
//! the connection's loop no turn to write — is accepted while its charges
//! fit. A send never waits: `broadcast` is called from anywhere, and one
//! recipient that stopped reading must not slow a producer or another
//! recipient.
//!
//! A frame that does not fit **closes the connection** rather than being
//! dropped alone, in two steps. The push marks the queue overflowed: it
//! discards what it held and refuses every later frame, so from that push
//! on nothing is delivered to the connection — `send_to` answers `false` and
//! a fan-out does not count it, the overflowing send included. The registry
//! then takes its write lock, removes the entry, records
//! [`CloseReason::OutboundOverflow`], cancels the socket's signal, and drops
//! the sender, so the loop reads the close and ends the socket with
//! [`WS_CLOSE_OUTBOUND_OVERFLOW`](crate::WS_CLOSE_OUTBOUND_OVERFLOW) (4005).
//! Between the two steps the entry is still in the map: `is_registered`, the
//! count accessors and the per-account cap see it until the removal, which
//! the overflowing send performs before it returns.
//!
//! One `warn` line names the connection, its account, and what was queued;
//! no audit row is written — a client can provoke an overflow at will, and
//! an audit write per overflow would amplify it. A close that reached the
//! entry first (a revocation, the cap, the shutdown) keeps its own reason,
//! and the overflow then logs at `debug` that the connection was already
//! closed.
//!
//! ## Per-account connection cap
//!
//! At most `max_connections_per_account` connections per `account_id`
//! ([`DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT`] unless the consumer overrides it
//! via [`ConnectionRegistry::with_max_connections_per_account`]; `None`
//! disables). The policy is **evict-oldest**: a connection past the cap is
//! always admitted, and the account's oldest connections are closed with
//! [`WS_CLOSE_CONNECTION_LIMIT`](crate::WS_CLOSE_CONNECTION_LIMIT) (4004)
//! to make room. Refusing the new one instead would let half-open sockets
//! (there is no server heartbeat timeout) lock a user out with their own
//! dead connections, and would let a stolen credential fill the slots ahead
//! of the real user — revocation is the fix for a stolen credential, and
//! evict-oldest never stands in its way.
//!
//! The cap keys on `account_id` across every credential type (session, API
//! token, daemon token — none exempt); a connection registered with no
//! account is never counted. Check-and-evict runs at **admission** —
//! [`ConnectionRegistry::admit`], or [`ConnectionRegistry::add_connection`]
//! for a one-step registration — under the map's write lock, so concurrent
//! upgrades for one account can never overshoot. The upgrade handler admits
//! only after every gate passed *and* the credential was re-checked, so an
//! unauthenticated, forbidden, or just-revoked request can never close
//! someone else's socket.
//!
//! ## Two-phase registration
//!
//! An upgrade handler resolves its credential before the socket exists, and
//! every revocation closes the connections *registered* under the revoked
//! credential. A one-step registration therefore has a window: a revocation
//! that lands between the credential check and the insert closes nothing,
//! and the upgrade is admitted on a dead credential — for the socket's
//! lifetime, since per-message dispatch never re-reads the session or token.
//!
//! Registration is split to close it:
//!
//! 1. [`ConnectionRegistry::register_pending`] inserts the entry
//!    **un-admitted** and returns a [`PendingConnection`] that owns it —
//!    dropping that value, on any refusal, removes the entry, so a pending
//!    registration cannot be leaked. It is closeable from this instant —
//!    `close_connections` matches pending entries deliberately — and is
//!    otherwise inert: it evicts nothing, the cap does not count it, no
//!    broadcast / `send_to_account` / `send_to` is delivered to it, and the
//!    count accessors and [`ConnectionRegistry::is_registered`] do not see it
//!    ([`ConnectionRegistry::pending_connection_count`] does).
//! 2. The caller re-checks the credential against the database
//!    (`fuz_auth::revalidate_resolved_auth`).
//! 3. [`ConnectionRegistry::admit`] flips the entry to admitted under one
//!    write lock and hands back the [`Connection`] with the
//!    [`ConnectionGuard`] that owns it from then on — or refuses with
//!    [`NotAdmitted`] when a revocation closed it in the meantime, evicting
//!    nothing. The cap's eviction happens here, so
//!    a connection that is never admitted never closes a live one, and any
//!    number of pending registrations on one account leave its admitted
//!    connections alone.
//!
//! Why this is race-free: every revocation closes sockets only **after** its
//! write has committed (`fuz_auth::connection_closer`), and the re-check in step 2
//! runs statements that start after the insert in step 1 and, under
//! `PostgreSQL`'s `READ COMMITTED`, see everything committed before they
//! start. So for any revocation, its close either ran **before** the insert —
//! then its commit also precedes the re-check, which sees it and refuses — or
//! **after** the insert — then it found the entry, pending or admitted, and
//! closed it. Either way the connection does not survive.
//!
//! Nothing is delivered to a pending entry rather than queued for it: the
//! refusal path never has to promise that a queue a revoked credential would
//! have read is dropped unread, and a broadcast's returned count names only
//! connections that can receive it. The cost is a slightly wider blind spot
//! at connect. A client sees its socket open when the handshake answers, and
//! a server-initiated message sent between then and admission — one
//! credential re-check later — is not delivered to it, just as one sent
//! before the handshake is not. Requests the client sends in that window are
//! not lost: they wait in the socket for the loop, which starts at admission.
//!
//! [`ConnectionRegistry::add_connection`] stays as the one-step form
//! (register + admit in one lock window) for a connection with no revocable
//! credential behind it — tests, and a surface that registers without an
//! account. An upgrade handler that authenticated a session or token must
//! use the two-phase form.
//!
//! ## Shutdown
//!
//! [`ConnectionRegistry`] is also a [`fuz_http::ShutdownCloser`] (through
//! [`ConnectionCloser`], its subtrait), so `fuz_http::serve_with_shutdown`
//! closes every socket through it when the server's token fires.
//! `close_all_connections` closes every entry, pending or admitted, marking each
//! [`CloseReason::ShuttingDown`] under the write lock that removes it, so an
//! [`ConnectionRegistry::admit`] that finds its entry gone reads the shutdown,
//! never an unset reason it would refuse as a revocation. An admitted socket's
//! loop then closes with
//! [`WS_CLOSE_GOING_AWAY`](crate::WS_CLOSE_GOING_AWAY) (1001), and a pending
//! one is refused at [`ConnectionRegistry::admit`] with
//! [`NotAdmitted::ShuttingDown`], which the upgrade handler closes with the
//! same code.
//!
//! The same write lock sets the registry **closing**, and from then on every
//! registration — [`ConnectionRegistry::register_pending`] and
//! [`ConnectionRegistry::add_connection`] alike — is closed from birth: never
//! inserted, its signal cancelled, its sender dropped, its reason
//! `ShuttingDown`. That is what closes the shutdown's own race: an upgrade
//! that answered `101` but has not registered yet registers either before the
//! close-all's lock, and is closed by it, or after, and is born closed. None
//! slips past to run a loop the shutdown does not know about.
//!
//! `wait_closed` waits for the connections to finish closing, not merely to
//! leave the map: the close-all empties the map at once, and a loop removes
//! its own entry *before* it writes its close frame. So every
//! [`ConnectionGuard`] — which a pending registration carries and the upgrade
//! holds until its loop has written the close, or given up at the shutdown
//! bound — holds a token of the registry's task tracker, and `wait_closed`
//! resolves once the close-all has run and every token is gone. An upgrade
//! handler can take a [`ConnectionRegistry::hold_upgrade`] before the
//! handshake to cover its refusal frame as well. What the wait waits on is
//! bounded too: from the close-all on, a loop's remaining writes — one
//! already blocked on a client that stopped reading, and the close (what
//! was queued is discarded with the close-all) — share one short bound
//! ([`run_ws_connection`](crate::run_ws_connection)), whatever the loop is
//! closing for. A refused upgrade's close write is not under that bound: a
//! write that cannot complete (a client whose receive window is closed)
//! holds its hold, and so the wait, to the server's drain timeout
//! ([`refuse_upgrade`](crate::refuse_upgrade)).
//!
//! ## `ConnectionCloser` impl
//!
//! `ConnectionRegistry` is the WS impl of `fuz_auth::ConnectionCloser`, so the
//! revocation handlers and the audit listener chain can route revocation
//! events into socket closure without any `App`-coupling. A consumer with
//! both transports binds [`RealtimeCloser`](crate::RealtimeCloser), which
//! fans each close to this registry and [`SseRegistry`](crate::SseRegistry).

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use axum::extract::ws::Utf8Bytes;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tokio_util::task::task_tracker::TaskTrackerToken;

use fuz_auth::{ConnectionCloseTarget, ConnectionCloser, NotificationSender};
use fuz_http::{ShutdownCloser, WaitClosedFuture};

use crate::connection::{
    CloseReason, Connection, ConnectionId, ConnectionIdentity, ConnectionInfo, ConnectionSender,
    NotAdmitted,
};
use crate::outbound_queue::{Overflow, Push, QueueHandle};

/// What a fan-out collects per recipient under the read lock: the id and
/// account to close and log an overflow by, and the handle to push through.
type Recipient = (ConnectionId, Option<uuid::Uuid>, QueueHandle<Utf8Bytes>);

/// Default per-account WebSocket connection cap, applied by
/// [`ConnectionRegistry::new`].
///
/// Matches the account-wide ceiling the audit SSE cap implies (the default
/// session cap, `fuz_auth::DEFAULT_MAX_SESSIONS`, times
/// [`AUDIT_LOG_SSE_MAX_PER_SCOPE`](crate::AUDIT_LOG_SSE_MAX_PER_SCOPE)
/// streams per session), generous enough that a
/// user's tabs and tools never meet it; only an abusive or leaking client
/// does. Override or disable via
/// [`ConnectionRegistry::with_max_connections_per_account`].
pub const DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT: usize = 50;

/// Per-connection state store.
///
/// Constructed once at the consumer's composition root (typically
/// `Arc::new(ConnectionRegistry::new())`) and shared across the auth
/// audit listeners, the action dispatchers, and the WS upgrade
/// handler.
#[derive(Debug)]
pub struct ConnectionRegistry {
    /// Monotonic id allocator. `Relaxed` ordering — no
    /// inter-thread synchronization other than uniqueness.
    next_id: AtomicU64,
    connections: RwLock<HashMap<ConnectionId, ConnectionInfo>>,
    /// Per-account connection cap; `None` = uncapped. See the module doc.
    max_connections_per_account: Option<NonZeroUsize>,
    /// Cancelled by `close_all_connections`, under the `connections` write lock,
    /// and read under it by every registration — so a registration either
    /// precedes the close-all and is closed by it, or follows it and is born
    /// closed (module doc, "Shutdown"). The connection loops watch it too:
    /// once it fires, every write a loop makes shares one bound.
    closing: CancellationToken,
    /// One token per live [`ConnectionGuard`] (and [`UpgradeHold`]);
    /// `wait_closed` waits for it to be closed and empty.
    closers: TaskTracker,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionRegistry {
    /// Build an empty registry with the per-account connection cap at
    /// [`DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            connections: RwLock::new(HashMap::new()),
            max_connections_per_account: NonZeroUsize::new(DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT),
            closing: CancellationToken::new(),
            closers: TaskTracker::new(),
        }
    }

    /// Replace the per-account connection cap; `None` disables it.
    ///
    /// Builder-style, for the composition root:
    /// `ConnectionRegistry::new().with_max_connections_per_account(…)`.
    #[must_use]
    pub const fn with_max_connections_per_account(mut self, max: Option<NonZeroUsize>) -> Self {
        self.max_connections_per_account = max;
        self
    }

    /// The registry's shutdown signal — cancelled once `close_all_connections`
    /// has run. The connection loop bounds its writes by it (module doc,
    /// "Shutdown").
    pub(crate) const fn closing_signal(&self) -> &CancellationToken {
        &self.closing
    }

    /// Allocate a fresh [`ConnectionId`] and build the entry + handle for it.
    fn new_entry(
        &self,
        sender: ConnectionSender,
        identity: ConnectionIdentity,
        signal: CancellationToken,
        admitted: bool,
    ) -> (Connection, ConnectionInfo) {
        let id = ConnectionId::new(self.next_id.fetch_add(1, Ordering::Relaxed));
        let close_reason = Arc::new(OnceLock::new());
        let account_id = identity.account_id;
        let info = ConnectionInfo {
            sender,
            identity,
            signal: signal.clone(),
            close_reason: Arc::clone(&close_reason),
            admitted,
        };
        let conn = Connection {
            id,
            account_id,
            signal,
            close_reason,
        };
        (conn, info)
    }

    /// The cap that applies to `account_id` — `None` for a connection with no
    /// account, or when the cap is disabled.
    fn cap_for(&self, account_id: Option<uuid::Uuid>) -> Option<(uuid::Uuid, NonZeroUsize)> {
        account_id.zip(self.max_connections_per_account)
    }

    /// Register a connection **un-admitted** — phase one of the two-phase
    /// registration an upgrade handler runs (module doc).
    ///
    /// The entry is closeable at once: a `close_connections` whose target matches
    /// `identity` removes it, cancels `signal`, and drops `sender`, and the
    /// later [`Self::admit`] then refuses. Until admitted it evicts nothing, is not counted toward the
    /// per-account cap, and receives no message.
    ///
    /// The returned [`PendingConnection`] owns the entry: dropping it without
    /// admitting — every refusal path — removes the entry.
    ///
    /// Once the registry is closing (`close_all_connections`), the registration
    /// is closed from birth — not inserted, `signal` cancelled, `sender`
    /// dropped — and [`Self::admit`] refuses it with
    /// [`NotAdmitted::ShuttingDown`] (module doc, "Shutdown").
    ///
    /// `signal` must be cancelled only by the registry: a caller-held clone
    /// cancelled elsewhere reads as [`NotAdmitted::Revoked`] in
    /// [`PendingConnection::closed`] while the registration is still live.
    pub fn register_pending(
        self: &Arc<Self>,
        sender: ConnectionSender,
        identity: ConnectionIdentity,
        signal: CancellationToken,
    ) -> PendingConnection {
        let (conn, info) = self.new_entry(sender, identity, signal, false);
        let born_closed = {
            let mut conns = self.connections.write();
            if self.closing.is_cancelled() {
                Some(info)
            } else {
                conns.insert(conn.id, info);
                None
            }
        };
        if let Some(info) = born_closed {
            close_entry(info, CloseReason::ShuttingDown);
        }
        let guard = ConnectionGuard::new(Arc::clone(self), conn.id);
        PendingConnection { conn, guard }
    }

    /// Admit a pending connection — phase two (module doc).
    ///
    /// Under one write lock: if the entry is gone — a revocation closed it
    /// while it was pending — nothing is evicted and the connection is
    /// refused. Otherwise the per-account cap is enforced exactly as in
    /// [`Self::add_connection`], counting only **admitted** connections, and
    /// the entry becomes admitted: it now receives messages, is counted, and
    /// can itself be superseded.
    ///
    /// Returns the [`Connection`] the WS loop takes and the
    /// [`ConnectionGuard`] that owned the pending entry, now owning the
    /// admitted one — the caller holds it for the socket's lifetime.
    ///
    /// # Errors
    ///
    /// When the entry is no longer registered: [`NotAdmitted::ShuttingDown`]
    /// if the shutdown close-all closed it or it was born closed,
    /// [`NotAdmitted::PermissionRevoked`] if a role close closed it,
    /// [`NotAdmitted::Revoked`] otherwise — a revocation closed it, or
    /// `pending` was registered with another registry (its own entry is
    /// removed there). The caller closes the socket with the matching
    /// [`UpgradeRefusal`](crate::UpgradeRefusal).
    pub fn admit(
        &self,
        pending: PendingConnection,
    ) -> Result<(Connection, ConnectionGuard), NotAdmitted> {
        let PendingConnection { conn, guard } = pending;
        // ids are per-registry counters, so a pending connection from another
        // registry could name a stranger's entry here
        if !std::ptr::eq(Arc::as_ptr(&guard.registry), self) {
            return Err(NotAdmitted::Revoked);
        }
        let (cap, closed) = {
            let mut conns = self.connections.write();
            let Some(info) = conns.get(&conn.id) else {
                // a closer that records a reason (cap eviction, close-all,
                // role close) sets it under this lock, before removing the
                // entry
                return Err(not_admitted_for(conn.close_reason.get()));
            };
            let account_id = info.identity.account_id;
            let cap = self.cap_for(account_id);
            // the entry itself is un-admitted, so the eviction neither counts
            // nor removes it
            let closed = cap.map_or(0, |(account, max)| {
                evict_oldest_for_account(&mut conns, account, max)
            });
            if let Some(info) = conns.get_mut(&conn.id) {
                info.admitted = true;
            }
            (cap, closed)
        };
        log_cap_eviction(cap, closed);
        Ok((conn, guard))
    }

    /// Allocate a fresh [`ConnectionId`] and register a connection, admitted
    /// at once — the one-step form of [`Self::register_pending`] +
    /// [`Self::admit`].
    ///
    /// **Not for an upgrade handler that authenticated a revocable
    /// credential**: a revocation landing between that handler's credential
    /// check and this call closes nothing, and the connection would be
    /// admitted on a dead credential (module doc, "Two-phase registration").
    /// This is for a connection with nothing to revoke behind it.
    ///
    /// Returns a [`Connection`] handle holding the id, a clone of the
    /// socket-scoped `CancellationToken` — the WS loop uses it to observe
    /// close-driven cancellation from the audit revocation path — and the
    /// close-reason cell.
    ///
    /// Enforces the per-account cap (module doc): when `account_id`
    /// already holds the maximum, its oldest admitted connections — smallest
    /// [`ConnectionId`], since ids are monotonic — are closed first, each
    /// marked [`CloseReason::Superseded`] (so its loop closes with 4004), its
    /// signal cancelled, and its sender dropped. The check, the evictions,
    /// and the insert share one write-lock window, so concurrent adds for one
    /// account never overshoot. The new connection is always admitted —
    /// unless the registry is closing (`close_all_connections`): then it is closed
    /// from birth, never inserted, its reason [`CloseReason::ShuttingDown`],
    /// so its loop exits at once with 1001.
    pub fn add_connection(
        &self,
        sender: ConnectionSender,
        identity: ConnectionIdentity,
        signal: CancellationToken,
    ) -> Connection {
        let (conn, info) = self.new_entry(sender, identity, signal, true);
        let cap = self.cap_for(conn.account_id);
        let (closed, born_closed) = {
            let mut conns = self.connections.write();
            if self.closing.is_cancelled() {
                (0, Some(info))
            } else {
                let closed = cap.map_or(0, |(account, max)| {
                    evict_oldest_for_account(&mut conns, account, max)
                });
                conns.insert(conn.id, info);
                (closed, None)
            }
        };
        if let Some(info) = born_closed {
            close_entry(info, CloseReason::ShuttingDown);
        }
        log_cap_eviction(cap, closed);
        conn
    }

    /// Hold [`ShutdownCloser::wait_closed`] open until the returned value is
    /// dropped.
    ///
    /// Every registration already holds the wait through its
    /// [`ConnectionGuard`], from `register_pending` until the upgrade drops
    /// the guard after its loop has written the close, or given up at the
    /// shutdown bound. An upgrade handler
    /// takes this before the handshake answers, and keeps it for the whole
    /// upgraded future, so the wait also covers what no guard does: a refused
    /// upgrade's close frame and linger, and the moment between the handshake
    /// and the registration. Taken in the handler — inside the HTTP request
    /// the server's drain waits for — it exists before the drain can finish,
    /// so a wait that follows the drain always sees it.
    #[must_use = "the hold lasts only while the value is alive"]
    pub fn hold_upgrade(&self) -> UpgradeHold {
        UpgradeHold {
            _token: self.closers.token(),
        }
    }

    /// Remove a connection by id, pending or admitted. Idempotent — safe to
    /// call after the connection has already been dropped by revocation.
    /// Dropping the entry closes its outbound channel and discards what was
    /// queued on it.
    pub fn remove_connection(&self, id: ConnectionId) {
        self.connections.write().remove(&id);
    }

    /// Number of currently **admitted** connections.
    ///
    /// A registration still pending admission is not a connection yet and is
    /// counted by [`Self::pending_connection_count`] instead. Entries may
    /// briefly persist after peer disconnect until the WS loop's exit path
    /// runs [`Self::remove_connection`]. Intended for telemetry, logging,
    /// and tests.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections
            .read()
            .values()
            .filter(|info| info.admitted)
            .count()
    }

    /// Number of currently admitted connections bound to `account_id` —
    /// what the per-account cap counts. Same lag caveat as
    /// [`Self::connection_count`]; for telemetry and tests.
    #[must_use]
    pub fn connection_count_for_account(&self, account_id: uuid::Uuid) -> usize {
        self.connections
            .read()
            .values()
            .filter(|info| info.admitted && info.identity.account_id == Some(account_id))
            .count()
    }

    /// Number of registrations awaiting admission — between
    /// [`Self::register_pending`] and [`Self::admit`] (or their refusal).
    /// Each lives for one credential re-check, so a count that stays high
    /// means upgrades are stalling there. For telemetry and tests.
    #[must_use]
    pub fn pending_connection_count(&self) -> usize {
        self.connections
            .read()
            .values()
            .filter(|info| !info.admitted)
            .count()
    }

    /// Send a message to a specific connection.
    ///
    /// Builds the `Utf8Bytes` from `message` and queues it on the
    /// connection's outbound channel. Silently drops if the id is unknown
    /// (already removed), still pending admission, or the receiver was
    /// dropped (revocation race). Returns `true` if the message was queued.
    ///
    /// A message that does not fit the connection's queue is not queued:
    /// the connection is closed for the overflow (module doc, "Outbound
    /// bound") and this returns `false`, as it does for that id from then on.
    /// A message of any size fits an empty queue.
    pub fn send_to(&self, id: ConnectionId, message: &str) -> bool {
        let recipient = {
            let conns = self.connections.read();
            conns
                .get(&id)
                .filter(|info| info.admitted)
                .map(|info| (id, info.identity.account_id, info.sender.handle()))
        };
        recipient
            .is_some_and(|recipient| self.deliver(&recipient, Utf8Bytes::from(message.to_owned())))
    }

    /// Queue `frame` for one collected recipient, outside the registry lock.
    /// `true` when it was queued; an overflow closes the connection.
    fn deliver(&self, (id, account_id, handle): &Recipient, frame: Utf8Bytes) -> bool {
        match handle.push(frame) {
            Push::Queued => true,
            Push::Refused => false,
            Push::Overflow(overflow) => {
                self.close_overflowed(*id, *account_id, overflow);
                false
            }
        }
    }

    /// Queue `frame` for every collected recipient, returning how many it
    /// was queued for. The buffer is shared: each recipient holds a
    /// refcounted handle and is charged for the frame in full.
    fn deliver_all(&self, recipients: &[Recipient], frame: &Utf8Bytes) -> usize {
        recipients
            .iter()
            .filter(|recipient| self.deliver(recipient, frame.clone()))
            .count()
    }

    /// Close a connection whose outbound queue just overflowed (module doc,
    /// "Outbound bound"). The queue has already discarded its frames and is
    /// refusing more; this removes the entry, records the reason, and wakes
    /// the loop.
    ///
    /// The reason is recorded before the sender is dropped — the loop reads
    /// it once the dropped sender closes its channel. An entry already gone
    /// was closed by another path, whose reason stands: this call then
    /// closes nothing, and says so at `debug` instead of the `warn` an
    /// overflow close gets.
    fn close_overflowed(
        &self,
        id: ConnectionId,
        account_id: Option<uuid::Uuid>,
        overflow: Overflow,
    ) {
        let removed = self.connections.write().remove(&id);
        let Some(info) = removed else {
            tracing::debug!(
                conn_id = id.get(),
                account_id = account_id.map(tracing::field::display),
                queued_bytes = overflow.queued_bytes,
                queued_frames = overflow.queued_frames,
                frame_bytes = overflow.frame_bytes,
                "ws: outbound queue overflow on a connection already closed"
            );
            return;
        };
        tracing::warn!(
            conn_id = id.get(),
            account_id = account_id.map(tracing::field::display),
            queued_bytes = overflow.queued_bytes,
            queued_frames = overflow.queued_frames,
            frame_bytes = overflow.frame_bytes,
            "ws: outbound queue overflow, closing the connection"
        );
        close_entry(info, CloseReason::OutboundOverflow);
    }

    /// Whether a connection is still registered — and admitted: a
    /// registration pending admission answers `false`, like every other
    /// reader of the registry.
    ///
    /// The presence check `ActionPeer::request` needs before issuing a
    /// server-initiated request — a pure membership test that never touches
    /// the per-socket [`CancellationToken`]. Presence and cancellation stay
    /// decoupled on purpose: `request` observes teardown via the pending
    /// one-shot the read loop drains on close, not via the token. (The socket
    /// token is never the client `cancel` channel — that is a per-request
    /// child token — so a presence test can never be tripped by an unrelated
    /// `cancel` into permanently reporting `ConnectionGone`; keeping the
    /// presence check token-free stops that coupling from creeping back even
    /// though `cancel` fires a per-request child and the socket token is
    /// reserved for teardown / revocation.)
    #[must_use]
    pub fn is_registered(&self, id: ConnectionId) -> bool {
        self.connections
            .read()
            .get(&id)
            .is_some_and(|info| info.admitted)
    }

    /// Broadcast a message to every admitted connection.
    ///
    /// Builds one `Utf8Bytes` and clones it (refcount bump) per
    /// recipient — N receivers cost one allocation, not N. Collects the
    /// recipients under a brief read lock, then queues outside the lock so
    /// per-queue contention doesn't serialize the whole fan-out.
    ///
    /// Never waits on a recipient. One whose queue the message does not fit
    /// is closed for the overflow (module doc, "Outbound bound") and not
    /// counted; the others are unaffected.
    ///
    /// Returns the number of recipients the message was queued for.
    pub fn broadcast(&self, message: &str) -> usize {
        let bytes: Utf8Bytes = message.to_owned().into();
        let recipients: Vec<Recipient> = {
            let conns = self.connections.read();
            conns
                .iter()
                .filter(|(_, info)| info.admitted)
                .map(|(id, info)| (*id, info.identity.account_id, info.sender.handle()))
                .collect()
        };
        self.deliver_all(&recipients, &bytes)
    }

    /// Broadcast a message to admitted connections matching a predicate
    /// over their auth identity. A registration pending admission is skipped
    /// before the predicate runs.
    ///
    /// Mirrors `fuz_app`'s `broadcast_filtered` — used by the broadcast
    /// API when a consumer supplies a per-connection ACL hook
    /// (e.g. zap's `zap_run_created` only reaches the account that
    /// owns the run). Returns the number of sockets the message was
    /// queued for. Recipients are collected under a brief read lock and
    /// the queueing runs outside the lock, with [`Self::broadcast`]'s
    /// overflow handling.
    ///
    /// A predicate that picks a cell- or grant-scoped audience must decide it
    /// on each send from the grants live then: no connection is gated on a
    /// cell grant, and no cell-grant revoke closes one (its audit event
    /// carries no close target), so a connection keeps running after the
    /// grant that once admitted it to the audience is gone.
    pub fn broadcast_filtered<P>(&self, message: &str, mut predicate: P) -> usize
    where
        P: FnMut(&ConnectionInfo) -> bool,
    {
        let bytes: Utf8Bytes = message.to_owned().into();
        let recipients: Vec<Recipient> = {
            let conns = self.connections.read();
            conns
                .iter()
                .filter(|(_, info)| info.admitted && predicate(info))
                .map(|(id, info)| (*id, info.identity.account_id, info.sender.handle()))
                .collect()
        };
        self.deliver_all(&recipients, &bytes)
    }

    /// Send a message to every admitted connection bound to the given
    /// account.
    ///
    /// Wraps [`Self::broadcast_filtered`] with the account-id
    /// predicate. Convenience for the common per-account fan-out
    /// pattern (matches `fuz_app`'s `send_to_account` shape).
    pub fn send_to_account(&self, account_id: uuid::Uuid, message: &str) -> usize {
        self.broadcast_filtered(message, |info| info.identity.account_id == Some(account_id))
    }
}

/// Close `account`'s oldest **admitted** connections until one more fits
/// under `max`, returning how many were closed. The caller holds the write
/// lock and inserts — or admits — the new connection in the same window.
/// Pending registrations are neither counted nor closed: a connection that
/// may yet be refused must not cost a live one its slot.
///
/// O(total connections) per call — a scan of the map, cheap next to the
/// upgrade handshake it runs behind.
fn evict_oldest_for_account(
    conns: &mut HashMap<ConnectionId, ConnectionInfo>,
    account: uuid::Uuid,
    max: NonZeroUsize,
) -> usize {
    let mut owned: Vec<ConnectionId> = conns
        .iter()
        .filter(|(_, info)| info.admitted && info.identity.account_id == Some(account))
        .map(|(id, _)| *id)
        .collect();
    if owned.len() < max.get() {
        return 0;
    }
    owned.sort_unstable();
    let excess = owned.len() + 1 - max.get();
    for id in &owned[..excess] {
        if let Some(info) = conns.remove(id) {
            // Reason first: the loop reads it once the sender drop below
            // closes its channel. A fresh entry's cell is never already set.
            let _ = info.close_reason.set(CloseReason::Superseded);
            info.signal.cancel();
            drop(info);
        }
    }
    excess
}

/// Log a cap eviction — `closed` connections on `cap`'s account.
fn log_cap_eviction(cap: Option<(uuid::Uuid, NonZeroUsize)>, closed: usize) {
    if closed > 0
        && let Some((account_id, max)) = cap
    {
        tracing::info!(
            %account_id,
            closed,
            max = max.get(),
            "ws: connection cap closed oldest"
        );
    }
}

/// A registered connection awaiting admission — what
/// [`ConnectionRegistry::register_pending`] returns and
/// [`ConnectionRegistry::admit`] consumes.
///
/// Its entry is already in the registry, so every revocation close can reach
/// it, but nothing is delivered to it and it does not count toward the
/// per-account cap until it is admitted. Not `Clone`, and consumed by
/// `admit`, so one registration is admitted at most once.
///
/// It **owns** its entry through a [`ConnectionGuard`]: dropped unadmitted —
/// the credential re-check refused, failed, or the upgrade's future was
/// dropped — the entry is removed, so no refusal path can leak a registration
/// that nothing counts and nothing delivers to. `admit` passes the same guard
/// on to the caller.
#[derive(Debug)]
#[must_use = "admit it with `ConnectionRegistry::admit`; dropping it removes the registration"]
pub struct PendingConnection {
    conn: Connection,
    guard: ConnectionGuard,
}

impl PendingConnection {
    /// The id the entry is registered under.
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.conn.id
    }

    /// Why the registration is already closed, if it is — read without the
    /// registry's lock, so a caller can refuse before costlier work (the
    /// upgrade's credential re-check): [`NotAdmitted::ShuttingDown`] for a
    /// registration born closed or closed by the shutdown,
    /// [`NotAdmitted::PermissionRevoked`] for one a role close closed,
    /// [`NotAdmitted::Revoked`] for one a revocation closed. `None` promises
    /// nothing — [`ConnectionRegistry::admit`] decides under the lock.
    #[must_use]
    pub fn closed(&self) -> Option<NotAdmitted> {
        // the signal first, the reason last: the close-all records
        // `ShuttingDown` under its lock and cancels the signal only after
        // releasing it, so a signal its cancel reached has the reason visible
        // too, and a reason set in the gap, before the cancel, reads alone.
        // Read the other way round, a close-all landing between the two reads
        // would show a cancelled signal with no reason — a revocation
        let cancelled = self.conn.signal.is_cancelled();
        match self.conn.close_reason.get() {
            Some(CloseReason::ShuttingDown) => Some(NotAdmitted::ShuttingDown),
            Some(CloseReason::PermissionRevoked) => Some(NotAdmitted::PermissionRevoked),
            _ if cancelled => Some(NotAdmitted::Revoked),
            _ => None,
        }
    }
}

/// Why a registration whose entry is gone was not admitted, from the reason
/// its closer recorded: the shutdown and a role close record theirs; a
/// revocation leaves the cell unset.
const fn not_admitted_for(reason: Option<&CloseReason>) -> NotAdmitted {
    match reason {
        Some(CloseReason::ShuttingDown) => NotAdmitted::ShuttingDown,
        Some(CloseReason::PermissionRevoked) => NotAdmitted::PermissionRevoked,
        Some(CloseReason::Superseded | CloseReason::OutboundOverflow) | None => {
            NotAdmitted::Revoked
        }
    }
}

/// Removes a connection from its registry on drop.
///
/// A two-phase registration gets one built in: it rides inside the
/// [`PendingConnection`] and comes out of [`ConnectionRegistry::admit`], and
/// the upgrade handler holds it for the socket's lifetime. A one-step
/// [`ConnectionRegistry::add_connection`] caller makes its own with
/// [`Self::new`]. Either way an entry can't outlive its connection — whether
/// the upgrade is refused before admission or the WS future
/// is dropped before the loop's own exit path runs (the loop still removes
/// explicitly; [`ConnectionRegistry::remove_connection`] is idempotent and
/// ids are never reused, so the guard can never remove another connection).
/// Twin of the SSE half's subscriber guard.
///
/// It also holds the registry's shutdown wait open while it lives (module
/// doc, "Shutdown"), so drop it only once the socket's close has been written
/// — after its loop returns.
#[derive(Debug)]
pub struct ConnectionGuard {
    registry: Arc<ConnectionRegistry>,
    id: ConnectionId,
    _closer: TaskTrackerToken,
}

impl ConnectionGuard {
    /// Guard `id` in `registry`.
    #[must_use]
    pub fn new(registry: Arc<ConnectionRegistry>, id: ConnectionId) -> Self {
        let closer = registry.closers.token();
        Self {
            registry,
            id,
            _closer: closer,
        }
    }
}

/// Keeps a [`ConnectionRegistry`]'s shutdown wait open while it lives — what
/// [`ConnectionRegistry::hold_upgrade`] returns.
#[derive(Debug)]
pub struct UpgradeHold {
    _token: TaskTrackerToken,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.registry.remove_connection(self.id);
    }
}

// -- ConnectionCloser impl --------------------------------------------------------
//
// The cold-path trait that the audit listener chain calls into.
// `ConnectionRegistry` is the WS impl; a consumer with both transports
// binds `RealtimeCloser`, which fans each close to this registry and
// `SseRegistry`.
//
// Each method drops the matched sender, which closes the connection's
// channel — discarding what was queued — so the WS loop's receiver reads the
// close and the loop breaks, sending a 4001 close frame on exit (the
// credential paths leave `close_reason` unset; the role close sets it for
// 4006, the cap's eviction for 4004, the shutdown close-all for 1001, an
// outbound overflow for 4005, each under the lock that removes the entry). The `signal` token is also cancelled
// belt-and-suspenders so streaming handlers bail out before the loop exits.
//
// Closes are idempotent, and a revocation closes more than once by design:
// its handler (once the write has committed — queued with
// `fuz_auth::queue_connection_close` in a dispatched action, inline on a REST
// path) and then the audit listener on the materialized row.
//
// Every close matches a registration still pending admission as well as an
// admitted connection — that is what lets a revocation reach an upgrade in
// flight (module doc, "Two-phase registration"). A closed pending entry has
// no loop yet; `ConnectionRegistry::admit` finds it gone and refuses.

impl ShutdownCloser for ConnectionRegistry {
    /// Close every socket, pending or admitted, with
    /// [`CloseReason::ShuttingDown`], and set the registry closing so every
    /// later registration is born closed (module doc, "Shutdown"). Returns
    /// how many entries were closed; a second call closes nothing.
    fn close_all_connections(&self) -> usize {
        let closed: Vec<ConnectionInfo> = {
            let mut conns = self.connections.write();
            self.closing.cancel();
            // the reason is recorded under the lock that removes the entry,
            // so an `admit` that finds it gone reads `ShuttingDown`, never
            // an unset cell (which it would refuse as a revocation)
            conns
                .drain()
                .map(|(_, info)| {
                    let _ = info.close_reason.set(CloseReason::ShuttingDown);
                    info
                })
                .collect()
        };
        let count = closed.len();
        for info in closed {
            close_entry(info, CloseReason::ShuttingDown);
        }
        self.closers.close();
        count
    }

    /// Resolve once `close_all_connections` has run and every [`ConnectionGuard`]
    /// and [`UpgradeHold`] is gone — every loop has written its close frame
    /// or given up at the shutdown bound, every refused upgrade has written
    /// its refusal.
    fn wait_closed(&self) -> WaitClosedFuture<'_> {
        Box::pin(self.closers.wait())
    }
}

impl ConnectionCloser for ConnectionRegistry {
    /// Close the connections whose [`ConnectionIdentity`] matches `target`,
    /// pending or admitted. A [`ConnectionCloseTarget::Role`] close marks each
    /// [`CloseReason::PermissionRevoked`], so its loop closes with
    /// [`WS_CLOSE_PERMISSION_REVOKED`](crate::WS_CLOSE_PERMISSION_REVOKED)
    /// (4006) and a pending one is refused at [`ConnectionRegistry::admit`]
    /// the same way; the credential closes leave the cell unset, for 4001.
    /// The account's connections on endpoints that did not list the role,
    /// and on ungated ones, stay open on a role close.
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        let reason = matches!(target, ConnectionCloseTarget::Role { .. })
            .then_some(CloseReason::PermissionRevoked);
        close_matching(&self.connections, reason, |info| {
            info.identity.matches(target)
        })
    }
}

/// Shared internals for the `close_connections` paths.
///
/// Records `reason` (when the close has one) before anything else, under the
/// write lock that removes the entry — the loop reads it once the dropped
/// sender closes its channel, and an [`ConnectionRegistry::admit`] that finds
/// the entry gone reads it under the same lock. Then cancels the
/// per-connection signal token, so any streaming handler observing
/// `ctx.signal.is_cancelled()` exits before the WS loop notices the dropped
/// sender. Matches every entry, pending or admitted — never filter on
/// admission here.
fn close_matching<P>(
    connections: &RwLock<HashMap<ConnectionId, ConnectionInfo>>,
    reason: Option<CloseReason>,
    mut predicate: P,
) -> usize
where
    P: FnMut(&ConnectionInfo) -> bool,
{
    let mut count = 0;
    connections.write().retain(|_, info| {
        let matches = predicate(info);
        if matches {
            if let Some(reason) = reason {
                let _ = info.close_reason.set(reason);
            }
            info.signal.cancel();
            count += 1;
        }
        !matches
    });
    count
}

/// Close an entry the registry has let go of: record `reason` for the loop,
/// cancel the socket signal, and drop the sender — in that order, since the
/// loop reads the reason once the dropped sender closes its channel. A cell
/// already set (a superseded entry is removed before anything else can reach
/// it) keeps its reason.
fn close_entry(info: ConnectionInfo, reason: CloseReason) {
    let _ = info.close_reason.set(reason);
    info.signal.cancel();
    drop(info);
}

// -- NotificationSender impl ---------------------------------------------------
//
// Server-initiated notification push (role-grant-offer inbox, …). Delegates
// to the inherent `send_to_account` (must name it explicitly — the trait
// method shares the name and `self.send_to_account` would recurse).

impl NotificationSender for ConnectionRegistry {
    fn send_to_account(&self, account_id: uuid::Uuid, message: &str) -> usize {
        Self::send_to_account(self, account_id, message)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio_util::sync::CancellationToken;

    use super::{CloseReason, ConnectionIdentity, ConnectionRegistry, NotAdmitted};

    /// The close-all records `ShuttingDown` under its lock and cancels the
    /// signal only after releasing it. A registration read in that gap —
    /// the reason set, the signal not yet cancelled — is already shutting
    /// down: an upgrade whose re-check fails there refuses with 1001, not as
    /// unavailable. The gap is built directly, since no public call stops
    /// the close-all inside it.
    #[test]
    fn a_pending_registration_reads_the_shutdown_before_its_signal() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (tx, _rx) = crate::connection_channel(1024);
        let pending =
            registry.register_pending(tx, ConnectionIdentity::default(), CancellationToken::new());
        assert_eq!(pending.closed(), None);

        let _ = pending.conn.close_reason.set(CloseReason::ShuttingDown);
        assert!(!pending.conn.signal.is_cancelled());
        assert_eq!(pending.closed(), Some(NotAdmitted::ShuttingDown));

        // and once the close-all has cancelled it too
        pending.conn.signal.cancel();
        assert_eq!(pending.closed(), Some(NotAdmitted::ShuttingDown));
    }
}
