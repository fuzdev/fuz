//! Per-connection state for the WebSocket registry.
//!
//! The `ConnectionInfo` shape stays close to TS
//! `fuz_app/src/lib/actions/connection_registry.ts`'s `ConnectionEntry`
//! (socket, `ConnectionIdentity`, admission state): both spines keep one map
//! keyed by connection id — `HashMap<ConnectionId, ConnectionInfo>` here.

use std::fmt;
use std::sync::{Arc, OnceLock};

use axum::extract::ws::Utf8Bytes;
use tokio::sync::mpsc::error::TryRecvError;
use tokio_util::sync::CancellationToken;

use fuz_auth::ConnectionCloseTarget;

use crate::outbound_queue::{OnClose, QueueHandle, QueueReceiver, QueueSender, outbound_queue};

/// Unique id for a WebSocket connection.
///
/// Newtype around `u64` so a bare `u64` (e.g. an `account_id` mistakenly
/// passed as a connection handle) can't compile against the registry's
/// `send_to` / `remove_connection` surface. Allocated by the registry
/// ([`ConnectionRegistry::register_pending`] /
/// [`ConnectionRegistry::add_connection`]) via an internal `AtomicU64`
/// counter — monotonically increasing, never reused within a process
/// lifetime.
///
/// [`ConnectionRegistry::register_pending`]: crate::ConnectionRegistry::register_pending
/// [`ConnectionRegistry::add_connection`]: crate::ConnectionRegistry::add_connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Construct from a raw counter value. Internal use only —
    /// `ConnectionRegistry` is the canonical mint site.
    #[inline]
    #[must_use]
    pub(crate) const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Borrow the underlying counter value (useful for logging / tracing).
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Build the outbound channel for one WebSocket connection: the sender the
/// registry takes at registration and the receiver its loop
/// ([`run_ws_connection`](crate::run_ws_connection)) writes from.
///
/// `outbound_queue_bytes` is the queue's byte budget — a size of its own,
/// independent of the connection's inbound message cap (the spine's upgrade
/// handler passes `fuz_actions::DEFAULT_WS_OUTBOUND_QUEUE_BYTES` unless its
/// consumer set another). Each waiting frame is charged its payload bytes —
/// the UTF-8 length of its text, charged in full to every recipient of a
/// fan-out while the buffer itself is shared — plus
/// [`OUTBOUND_FRAME_OVERHEAD_BYTES`](crate::OUTBOUND_FRAME_OVERHEAD_BYTES),
/// and a frame is queued while the charges waiting stay within the budget.
/// A frame is always queued into an **empty** queue, so one message larger
/// than the whole budget is still deliverable; a budget of zero therefore
/// holds one frame at a time. Nothing limits the number of frames but their
/// charges. A frame counts from the moment it is queued until the loop takes
/// it to write.
///
/// A push that does not fit closes the connection instead of waiting or
/// dropping the frame alone: the registry discards the queue, removes the
/// entry, and the loop closes the socket with
/// [`WS_CLOSE_OUTBOUND_OVERFLOW`](crate::WS_CLOSE_OUTBOUND_OVERFLOW) (4005).
/// A producer is never slowed by a recipient that stopped reading.
#[must_use]
pub fn connection_channel(outbound_queue_bytes: usize) -> (ConnectionSender, ConnectionReceiver) {
    let (sender, receiver) = outbound_queue(outbound_queue_bytes, OnClose::Discard);
    (ConnectionSender(sender), ConnectionReceiver(receiver))
}

/// Sender half of a connection's outbound channel ([`connection_channel`]) —
/// what [`ConnectionRegistry::register_pending`] and
/// [`ConnectionRegistry::add_connection`] take.
///
/// The registry owns it: frames are queued only through the registry's
/// `send_to` / `broadcast*` / `send_to_account`, which is where the queue's
/// bounds are enforced, and dropping it — every registry-side close — closes
/// the channel and discards what was queued. Not `Clone`.
///
/// Frames are `Utf8Bytes`, which wraps `bytes::Bytes`: a broadcast builds
/// one buffer and each recipient's queue holds a refcounted handle to it,
/// charged for the frame in full.
///
/// [`ConnectionRegistry::register_pending`]: crate::ConnectionRegistry::register_pending
/// [`ConnectionRegistry::add_connection`]: crate::ConnectionRegistry::add_connection
#[derive(Debug)]
pub struct ConnectionSender(QueueSender<Utf8Bytes>);

impl ConnectionSender {
    /// A pushing handle for a fan-out that sends outside the registry lock.
    pub(crate) fn handle(&self) -> QueueHandle<Utf8Bytes> {
        self.0.handle()
    }
}

/// Receiver half of a connection's outbound channel ([`connection_channel`])
/// — what [`run_ws_connection`](crate::run_ws_connection) takes.
///
/// It reads the channel's close — `recv` yielding `None` — as soon as the
/// registry lets the connection go, whatever was still queued: a closed
/// connection's backlog is discarded, never written, so its close frame does
/// not wait behind it. Dropping the receiver discards the queue and makes
/// every later send report the connection gone.
#[derive(Debug)]
pub struct ConnectionReceiver(QueueReceiver<Utf8Bytes>);

impl ConnectionReceiver {
    /// The next queued frame, waiting for one; `None` once the registry has
    /// closed the connection. Cancel-safe.
    pub async fn recv(&mut self) -> Option<Utf8Bytes> {
        self.0.recv().await
    }

    /// The next frame if one is queued, without waiting.
    ///
    /// # Errors
    ///
    /// [`TryRecvError::Empty`] when nothing is queued,
    /// [`TryRecvError::Disconnected`] once the registry has closed the
    /// connection.
    pub fn try_recv(&mut self) -> Result<Utf8Bytes, TryRecvError> {
        self.0.try_recv()
    }

    /// Frames waiting in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no frame is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// Payload bytes waiting in the queue — the frames' text, without the
    /// per-frame overhead the budget also charges.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.0.queued_bytes()
    }

    /// Whether the registry has closed the connection.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

/// The identity a connection registers under — what every targeted close
/// matches on ([`Self::matches`]).
///
/// A WebSocket's ([`ConnectionRegistry::register_pending`],
/// [`ConnectionRegistry::add_connection`]) and an SSE stream's
/// ([`SseSubscription::identity`](crate::SseSubscription::identity)) alike.
///
/// Twin of `fuz_app`'s `ConnectionIdentity`. `Default` is a connection with
/// no identity at all: no credential to revoke and no role gate — tests, and a
/// surface that registers without an account.
///
/// Every field is optional because each keys one *narrower* close than
/// `account_id`; a field left `None` leaves the connection reachable only by
/// the closes above it, which is why a route fills in everything its
/// credential resolved.
///
/// [`ConnectionRegistry::register_pending`]: crate::ConnectionRegistry::register_pending
/// [`ConnectionRegistry::add_connection`]: crate::ConnectionRegistry::add_connection
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionIdentity {
    /// blake3 hash of the session-cookie token, for session-level revocation
    /// ([`ConnectionCloseTarget::Session`]). `None` for non-session credentials
    /// (bearer / daemon token).
    pub session_hash: Option<String>,
    /// The authenticated account, for account-level revocation
    /// ([`ConnectionCloseTarget::Account`]) and the per-account cap.
    pub account_id: Option<uuid::Uuid>,
    /// `api_token.id` for a bearer-authenticated connection, for per-token
    /// revocation ([`ConnectionCloseTarget::Token`]).
    pub api_token_id: Option<String>,
    /// The roles the connection's endpoint gated it on (any-of), or empty for
    /// an ungated endpoint — what [`ConnectionCloseTarget::Role`] matches, with
    /// `account_id`. Per registration, not per registry: endpoints with
    /// different gates can share one registry.
    pub required_roles: Vec<&'static str>,
}

impl ConnectionIdentity {
    /// Whether a revocation closing `target` closes this connection — the one
    /// predicate both registries close by.
    ///
    /// A [`ConnectionCloseTarget::Role`] matches the account's connections whose
    /// endpoint listed the role, so an any-of gate over-closes: the loss of
    /// any listed role matches, whether or not the account holds another.
    #[must_use]
    pub fn matches(&self, target: &ConnectionCloseTarget) -> bool {
        match target {
            ConnectionCloseTarget::Session(hash) => self.session_hash.as_deref() == Some(hash),
            ConnectionCloseTarget::Token(id) => self.api_token_id.as_deref() == Some(id),
            ConnectionCloseTarget::Account(id) => self.account_id == Some(*id),
            ConnectionCloseTarget::Role { account_id, role } => {
                self.account_id == Some(*account_id)
                    && self.required_roles.iter().any(|gate| gate == role)
            }
        }
    }
}

/// Why the registry dropped a connection's sender, when it was not a
/// revocation.
///
/// Recorded in the connection's shared `close_reason` cell *before* its sender
/// is dropped, so the WS loop — which sees only its receiver reading the
/// close — can tell the server-side closes apart. An unset cell means a
/// revocation path (or a plain `remove_connection`) dropped the sender, and the
/// loop closes with [`WS_CLOSE_SESSION_REVOKED`]; a set one picks the frame
/// below.
///
/// [`WS_CLOSE_SESSION_REVOKED`]: crate::WS_CLOSE_SESSION_REVOKED
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Closed to admit a newer connection on the same account past the
    /// per-account cap (see `ConnectionRegistry`'s module doc) — the loop
    /// closes with [`WS_CLOSE_CONNECTION_LIMIT`], not 4001, so the client
    /// knows its credential is still good.
    ///
    /// [`WS_CLOSE_CONNECTION_LIMIT`]: crate::WS_CLOSE_CONNECTION_LIMIT
    Superseded,
    /// Closed because the server is shutting down
    /// (`ConnectionRegistry::close_all_connections`), or registered after that
    /// and so closed from birth — the loop closes with
    /// [`WS_CLOSE_GOING_AWAY`], and the client reconnects under its ordinary
    /// backoff.
    ///
    /// [`WS_CLOSE_GOING_AWAY`]: crate::WS_CLOSE_GOING_AWAY
    ShuttingDown,
    /// Closed because a frame did not fit the connection's outbound queue
    /// ([`connection_channel`]) — its client is reading slower than the
    /// server is sending to it, or not at all. The loop closes with
    /// [`WS_CLOSE_OUTBOUND_OVERFLOW`], not 4001: the credential is still
    /// good, and the client reconnects under its ordinary backoff.
    ///
    /// [`WS_CLOSE_OUTBOUND_OVERFLOW`]: crate::WS_CLOSE_OUTBOUND_OVERFLOW
    OutboundOverflow,
    /// Closed because the account lost a role the connection's endpoint
    /// requires (a `ConnectionCloseTarget::Role` close) — the loop closes with
    /// [`WS_CLOSE_PERMISSION_REVOKED`], not 4001: the credential is still
    /// good, and the client stays closed until the user acts.
    ///
    /// [`WS_CLOSE_PERMISSION_REVOKED`]: crate::WS_CLOSE_PERMISSION_REVOKED
    PermissionRevoked,
}

/// Auth metadata + delivery sink for one connection.
///
/// The [`ConnectionIdentity`] it registered under drives targeted revocation
/// ([`ConnectionIdentity::matches`]) and the per-account cap; a
/// `broadcast_filtered` predicate reads it too.
#[derive(Debug)]
pub struct ConnectionInfo {
    /// Outbound delivery sink — dropping it closes the connection's channel
    /// and discards what was queued, so the WS loop's receiver reads the
    /// close and the loop closes the socket. The frame it sends is read from
    /// [`Self::close_reason`]: 4004 when the per-account cap superseded the
    /// connection, 1001 when the server is shutting down, 4005 when its
    /// outbound queue overflowed, 4006 when its account lost a gating role,
    /// 4001 (revocation) when the cell is unset.
    /// Crate-private: frames are queued only through the registry, which is
    /// where the queue's bounds are enforced.
    pub(crate) sender: ConnectionSender,
    /// Who the connection authenticated as, and the roles its endpoint gated
    /// it on.
    pub identity: ConnectionIdentity,
    /// Socket-scoped cancellation token. The owning WS loop holds the
    /// canonical [`CancellationToken`]; the registry keeps a clone so
    /// `close_*` paths can cancel in-flight streaming handlers without
    /// needing to reach across to the loop. Mirrors `fuz_app`'s
    /// `socket_abort_controller` driving every handler's `ctx.signal`.
    pub signal: CancellationToken,
    /// Why the registry closed this connection, set before the sender is
    /// dropped; unset for a revocation. Shared with the [`Connection`] handle
    /// the WS loop holds.
    pub close_reason: Arc<OnceLock<CloseReason>>,
    /// Whether the connection has been admitted — `false` between
    /// [`ConnectionRegistry::register_pending`] and
    /// [`ConnectionRegistry::admit`]. An un-admitted entry exists only so a
    /// revocation can find and close it: it receives nothing, is not counted,
    /// and never weighs on the per-account cap (see the registry's module
    /// doc). Crate-private, so a `broadcast_filtered` predicate — which only
    /// ever sees admitted entries — has nothing to branch on.
    ///
    /// [`ConnectionRegistry::register_pending`]: crate::ConnectionRegistry::register_pending
    /// [`ConnectionRegistry::admit`]: crate::ConnectionRegistry::admit
    pub(crate) admitted: bool,
}

/// A pending registration could not be admitted: its entry is gone, and the
/// variant says why.
///
/// The error of [`ConnectionRegistry::admit`] and
/// [`SseRegistry::admit`](crate::SseRegistry::admit). The caller refuses the
/// connection — nothing was evicted to make room for it, and the registration
/// is gone. A WS caller closes the socket with the matching
/// [`UpgradeRefusal`](crate::UpgradeRefusal) (`From<NotAdmitted>`).
///
/// [`ConnectionRegistry::admit`]: crate::ConnectionRegistry::admit
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NotAdmitted {
    /// A revocation closed the registration while it waited (or its guard
    /// removed it, or it belongs to another registry) — refused as revoked.
    #[error("the connection was closed while it awaited admission")]
    Revoked,
    /// The server is shutting down: the registry closed the registration with
    /// every other connection, or it was registered after that and closed
    /// from birth — refused as going away.
    #[error("the server is shutting down")]
    ShuttingDown,
    /// The account lost a role the endpoint requires while the registration
    /// waited (a `ConnectionCloseTarget::Role` close) — refused as permission revoked, not
    /// as a revocation of the credential.
    #[error("the connection's account lost a role its endpoint requires")]
    PermissionRevoked,
}

/// Handle to an admitted connection, returned by
/// [`ConnectionRegistry::admit`] (beside the guard that owns its entry) and
/// [`ConnectionRegistry::add_connection`].
///
/// Holds the allocated [`ConnectionId`], the account the connection was
/// registered under, a clone of the socket-scoped `CancellationToken` the
/// caller passed in, and the close-reason cell the registry shares with the
/// connection's [`ConnectionInfo`]. The WS loop takes the whole handle: the
/// id to remove the connection on disconnect, the account to name in its
/// logs, the token to observe revocation-driven cancellation, the cell to
/// pick the close frame when its sender is dropped.
///
/// [`ConnectionRegistry::admit`]: crate::ConnectionRegistry::admit
/// [`ConnectionRegistry::add_connection`]: crate::ConnectionRegistry::add_connection
#[derive(Debug, Clone)]
pub struct Connection {
    pub id: ConnectionId,
    /// The account the connection was registered under, if any.
    pub account_id: Option<uuid::Uuid>,
    pub signal: CancellationToken,
    /// Why the registry closed the connection — see [`CloseReason`].
    pub close_reason: Arc<OnceLock<CloseReason>>,
}

#[cfg(test)]
mod tests {
    use fuz_auth::ConnectionCloseTarget;

    use super::ConnectionIdentity;

    /// Each target matches on its own key and nothing else, and a role target
    /// needs both the account and a listed role.
    #[test]
    fn an_identity_matches_each_target_by_its_own_key() {
        let account = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let identity = ConnectionIdentity {
            session_hash: Some("hash".to_owned()),
            account_id: Some(account),
            api_token_id: Some("tok".to_owned()),
            required_roles: vec!["admin", "keeper"],
        };
        let role = |account_id, role: &str| ConnectionCloseTarget::Role {
            account_id,
            role: role.to_owned(),
        };
        for (target, expected) in [
            (ConnectionCloseTarget::Session("hash".to_owned()), true),
            (ConnectionCloseTarget::Session("tok".to_owned()), false),
            (ConnectionCloseTarget::Token("tok".to_owned()), true),
            (ConnectionCloseTarget::Token("hash".to_owned()), false),
            (ConnectionCloseTarget::Account(account), true),
            (ConnectionCloseTarget::Account(other), false),
            (role(account, "admin"), true),
            (role(account, "keeper"), true),
            (role(account, "other"), false),
            (role(other, "admin"), false),
        ] {
            assert_eq!(identity.matches(&target), expected, "{target:?}");
        }

        // the default identity is reachable by nothing
        let none = ConnectionIdentity::default();
        for target in [
            ConnectionCloseTarget::Session(String::new()),
            ConnectionCloseTarget::Token(String::new()),
            ConnectionCloseTarget::Account(account),
            role(account, "admin"),
        ] {
            assert!(!none.matches(&target), "{target:?}");
        }
    }
}
