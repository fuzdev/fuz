//! WebSocket close-code constants.
//!
//! 4001, 4004, 4005 and 4006 are application-defined codes (RFC 6455 §7.4.2
//! leaves 4000–4999 to applications), all shared with
//! `fuz_app/src/lib/actions/transports.ts`: `WS_CLOSE_SESSION_REVOKED` — so
//! the frontend `FrontendWebsocketClient` can mark the connection as
//! permanently revoked and skip reconnection — `WS_CLOSE_CONNECTION_LIMIT`,
//! `WS_CLOSE_OUTBOUND_OVERFLOW`, and `WS_CLOSE_PERMISSION_REVOKED`;
//! 4002 is that module's client-side heartbeat timeout, which a server never
//! sends, and 4003 ([`WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`]) its server-side
//! one, which this spine sends too. 1001, 1009 and 1011 are RFC 6455 §7.4.1
//! registered codes, shared with the same module's `WS_CLOSE_GOING_AWAY`,
//! `WS_CLOSE_MESSAGE_TOO_BIG` and `WS_CLOSE_INTERNAL_ERROR`.
//! Its 1008 (`WS_CLOSE_POLICY_VIOLATION`, a socket that sent too much before
//! it was admitted) has no sender here: frames sent before admission wait in
//! the socket for the loop, not in a queue.
//!
//! Every close this spine sends carries a reason, each byte-identical to the
//! `fuz_app` constant of the same name — the text rides the close frame, so
//! it is wire-observable (a browser's `CloseEvent.reason`):
//!
//! | Code | Reason |
//! |---|---|
//! | 4001 | [`WS_CLOSE_SESSION_REVOKED_REASON`], [`WS_CLOSE_CREDENTIAL_EXPIRED_REASON`] |
//! | 4003 | [`WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT_REASON`] |
//! | 4004 | [`WS_CLOSE_CONNECTION_LIMIT_REASON`] |
//! | 4005 | [`WS_CLOSE_OUTBOUND_OVERFLOW_REASON`] |
//! | 4006 | [`WS_CLOSE_PERMISSION_REVOKED_REASON`] |
//! | 1001 | [`WS_CLOSE_GOING_AWAY_REASON`] |
//! | 1009 | [`WS_CLOSE_MESSAGE_TOO_BIG_REASON`] |
//! | 1011 | [`WS_CLOSE_INTERNAL_ERROR_REASON`] |

/// Server revoked auth — session revoke, token revoke, password change,
/// account logout, admin force-logout — or the credential expired while the
/// socket was open ([`WS_CLOSE_CREDENTIAL_EXPIRED_REASON`]).
///
/// Also the close for an upgrade refused at admission because its credential
/// was revoked while the upgrade was in flight
/// ([`UpgradeRefusal::Revoked`](crate::UpgradeRefusal::Revoked)) — the same
/// outcome, reached a moment earlier.
///
/// One generic code for every revocation outcome. The client enters a
/// permanent `revoked` state and skips the reconnect loop. Granularity
/// at the close-frame level is intentionally not exposed: a malicious
/// peer could harvest the distinction (e.g. "this token was revoked but
/// the account isn't dead yet") to map account/token relationships.
/// Forensic granularity lives in `audit_log`, not on the WS frame.
pub const WS_CLOSE_SESSION_REVOKED: u16 = 4001;

/// The close reason sent with [`WS_CLOSE_SESSION_REVOKED`] for a revocation —
/// byte-identical to `fuz_app`'s `WS_CLOSE_SESSION_REVOKED_REASON`.
///
/// One text for a socket revoked mid-life and an upgrade refused at
/// admission, so the two are indistinguishable on the wire.
pub const WS_CLOSE_SESSION_REVOKED_REASON: &str = "Session revoked";

/// The close reason sent with [`WS_CLOSE_SESSION_REVOKED`] when the socket's
/// credential expired while it was open.
///
/// Its session or API token passed its expiry
/// ([`fuz_auth::ResolvedAuth::credential_deadline`]). Byte-identical to
/// `fuz_app`'s `WS_CLOSE_CREDENTIAL_EXPIRED_REASON`.
///
/// The code is the revocation's on purpose: the client cannot reconnect on
/// the credential either way, so it enters the same permanent `revoked`
/// state. The reason text says which, and leaks nothing the client does not
/// already hold — it knows when its own credential expires.
pub const WS_CLOSE_CREDENTIAL_EXPIRED_REASON: &str = "Credential expired";

/// The server heard nothing from the client for the socket's receive timeout.
///
/// No frame was read since the connection was admitted, or since the last one,
/// for `fuz_actions::ActionWsOptions`'s `receive_timeout` (60 s by default).
///
/// Not a revocation: the client reconnects under its ordinary backoff. A live
/// `FrontendWebsocketClient` sends a heartbeat whenever either direction has
/// been idle for its interval (30 s by default), so it never meets the
/// default. The reason text is [`WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT_REASON`].
/// Twin of `fuz_app`'s `WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`.
pub const WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT: u16 = 4003;

/// The close reason sent with [`WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`] —
/// byte-identical to the reason `fuz_app`'s `register_action_ws` sends.
pub const WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT_REASON: &str = "server heartbeat timeout";

/// The socket was closed to admit a newer connection on the same account,
/// past the registry's per-account connection cap (see
/// `fuz_realtime::connection_registry`, evict-oldest).
///
/// Distinct from [`WS_CLOSE_SESSION_REVOKED`] on purpose: the credential is
/// still good, so a client must not enter its `revoked` state — but it must
/// not auto-reconnect either, since a reconnect would supersede the newer
/// socket in turn and two tabs would close each other in a loop. The client
/// treats it as closed until the user acts. Twin of `fuz_app`'s
/// `WS_CLOSE_CONNECTION_LIMIT`; its `FrontendWebsocketClient` stays closed,
/// with `superseded` set, until `connect()` is called.
pub const WS_CLOSE_CONNECTION_LIMIT: u16 = 4004;

/// The close reason sent with [`WS_CLOSE_CONNECTION_LIMIT`] — byte-identical
/// to `fuz_app`'s `WS_CLOSE_CONNECTION_LIMIT_REASON`.
pub const WS_CLOSE_CONNECTION_LIMIT_REASON: &str = "connection limit";

/// The connection's outbound queue overflowed.
///
/// The server had more queued for this socket than its byte budget holds,
/// because the client is reading slower than the server is sending to it, or
/// not at all (see [`connection_channel`](crate::connection_channel) for the
/// budget and what a frame is charged). The registry discards the queue and
/// removes the connection; the loop writes this close and drops the socket.
/// What was queued is lost, so the frame is the client's notice that it
/// missed messages.
///
/// Distinct from [`WS_CLOSE_SESSION_REVOKED`] on purpose: the credential is
/// still good, so a client must not enter its `revoked` state. Unlike
/// [`WS_CLOSE_CONNECTION_LIMIT`], nothing took its place: the client
/// reconnects under its ordinary backoff and re-reads whatever state it
/// tracks. The reason text is [`WS_CLOSE_OUTBOUND_OVERFLOW_REASON`].
///
/// A client that reads nothing at all may never see the frame: a socket
/// whose write makes no progress is dropped without one — a frame's write at
/// [`WS_WRITE_STALL_TIMEOUT`](crate::WS_WRITE_STALL_TIMEOUT), or sooner once
/// the connection is closed — which a browser reports as 1006.
pub const WS_CLOSE_OUTBOUND_OVERFLOW: u16 = 4005;

/// The close reason sent with [`WS_CLOSE_OUTBOUND_OVERFLOW`] — byte-identical
/// to `fuz_app`'s `WS_CLOSE_OUTBOUND_OVERFLOW_REASON`.
pub const WS_CLOSE_OUTBOUND_OVERFLOW_REASON: &str = "outbound queue overflow";

/// The socket's account lost a role its endpoint requires.
///
/// A global grant of one of the upgrade gate's roles
/// (`fuz_actions::WsRouteState`'s `required_roles`) was revoked while the
/// socket was open
/// ([`CloseReason::PermissionRevoked`](crate::CloseReason::PermissionRevoked)),
/// or while its upgrade was in flight
/// ([`UpgradeRefusal::PermissionRevoked`](crate::UpgradeRefusal::PermissionRevoked)).
/// Nothing more is written to the socket.
///
/// Distinct from [`WS_CLOSE_SESSION_REVOKED`] on purpose: the credential is
/// still good, so a client must not enter its `revoked` state — but a
/// reconnect would be refused at the role gate, so the client stays closed
/// until the user acts. The reason text is
/// [`WS_CLOSE_PERMISSION_REVOKED_REASON`]. Twin of `fuz_app`'s
/// `WS_CLOSE_PERMISSION_REVOKED`.
pub const WS_CLOSE_PERMISSION_REVOKED: u16 = 4006;

/// The close reason sent with [`WS_CLOSE_PERMISSION_REVOKED`] —
/// byte-identical to `fuz_app`'s `WS_CLOSE_PERMISSION_REVOKED_REASON`.
pub const WS_CLOSE_PERMISSION_REVOKED_REASON: &str = "Permission revoked";

/// The server is shutting down — RFC 6455 §7.4.1 "Going Away".
///
/// Sent to every live socket, pending admission or admitted, when the server
/// closes all of them on shutdown
/// (`fuz_http::ShutdownCloser::close_all_connections`, which
/// [`ConnectionRegistry`](crate::ConnectionRegistry) implements), and to an
/// upgrade that reaches admission after that
/// ([`UpgradeRefusal::ShuttingDown`](crate::UpgradeRefusal::ShuttingDown)).
/// Not a revocation: the client reconnects under its ordinary backoff. Twin of
/// `fuz_app`'s `WS_CLOSE_GOING_AWAY`, with the same reason text
/// ([`WS_CLOSE_GOING_AWAY_REASON`]).
pub const WS_CLOSE_GOING_AWAY: u16 = 1001;

/// The close reason sent with [`WS_CLOSE_GOING_AWAY`] — byte-identical to
/// `fuz_app`'s `WS_CLOSE_GOING_AWAY_REASON`.
pub const WS_CLOSE_GOING_AWAY_REASON: &str = "Server shutting down";

/// An inbound message exceeded the receiver's size cap — RFC 6455 §7.4.1
/// "Message Too Big".
///
/// Sent by the WS read loop when a message or frame is over the upgrade's
/// `max_message_size` / `max_frame_size` (see
/// `fuz_actions::DEFAULT_WS_MAX_MESSAGE_BYTES`), then the connection ends —
/// there is no per-message error reply. Twin of `fuz_app`'s
/// `WS_CLOSE_MESSAGE_TOO_BIG`, so a client sees the same close code from
/// either spine rather than an abnormal drop (1006).
pub const WS_CLOSE_MESSAGE_TOO_BIG: u16 = 1009;

/// The close reason sent with [`WS_CLOSE_MESSAGE_TOO_BIG`] — byte-identical to
/// `fuz_app`'s `WS_CLOSE_MESSAGE_TOO_BIG_REASON`.
pub const WS_CLOSE_MESSAGE_TOO_BIG_REASON: &str = "message too big";

/// The server hit an unexpected condition — RFC 6455 §7.4.1 "Internal Error".
///
/// Sent when an upgraded socket cannot be admitted because its credential
/// re-check itself failed (pool checkout or query —
/// [`UpgradeRefusal::Unavailable`](crate::UpgradeRefusal::Unavailable)). The
/// handshake has already answered `101`, so the HTTP `500` the other
/// infrastructure failures of the upgrade return is no longer available.
/// Not a revocation: the client's credential may be fine, so it reconnects
/// under its ordinary backoff rather than entering its `revoked` state.
///
/// Twin of `fuz_app`'s `WS_CLOSE_INTERNAL_ERROR`, which also sends it from
/// paths with no counterpart here, such as an `on_socket_open` hook that
/// throws.
pub const WS_CLOSE_INTERNAL_ERROR: u16 = 1011;

/// The close reason sent with [`WS_CLOSE_INTERNAL_ERROR`] — byte-identical to
/// `fuz_app`'s `WS_CLOSE_INTERNAL_ERROR_REASON`.
pub const WS_CLOSE_INTERNAL_ERROR_REASON: &str = "internal error";

#[cfg(test)]
mod tests {
    use super::*;

    /// The reasons are wire-observable and shared with `fuz_app`, so a text
    /// change fails here rather than only on the other spine.
    #[test]
    fn reasons_pin_their_text() {
        assert_eq!(WS_CLOSE_SESSION_REVOKED_REASON, "Session revoked");
        assert_eq!(WS_CLOSE_CONNECTION_LIMIT_REASON, "connection limit");
        assert_eq!(WS_CLOSE_MESSAGE_TOO_BIG_REASON, "message too big");
        assert_eq!(WS_CLOSE_INTERNAL_ERROR_REASON, "internal error");
    }
}
