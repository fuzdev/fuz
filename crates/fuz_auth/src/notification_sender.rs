//! `NotificationSender` capability — push a server-initiated JSON-RPC
//! notification to every WebSocket connection bound to an account.
//!
//! Parallels [`crate::ConnectionCloser`]: a cold-path capability trait
//! declared in `fuz_auth`, implemented over `fuz_realtime`'s
//! `ConnectionRegistry`, with a no-op impl for consumers lacking a WS
//! surface.
//!
//! Unlike `ConnectionCloser` — which reacts to audit rows needing only
//! identity ids, all present in audit metadata — a notification carries
//! the full domain payload (e.g. the offer object), which the flat
//! audit metadata does not hold. So handlers build the message from
//! in-scope state and queue the send on the post-commit drain
//! (`ctx.post_commit.queue_notify`), rather than deriving it from the
//! audit listener chain. The trait is the **send capability only**, not
//! a fan-out driver.

/// Push a pre-serialized JSON-RPC notification frame to a recipient's
/// connections.
///
/// Sync — implementations must not `.await` (the send is a non-blocking
/// channel push, invoked from the post-commit drain on the dispatch
/// task; an internal `.await` could stall the drain).
///
/// **Object-safe** — consumed as `Arc<dyn NotificationSender>`.
pub trait NotificationSender: Send + Sync {
    /// Send `message` (a serialized JSON-RPC notification) to every
    /// connection bound to `account_id`. Returns the number of sockets
    /// the frame was queued to (bookkeeping, not a delivery receipt).
    fn send_to_account(&self, account_id: uuid::Uuid, message: &str) -> usize;
}

/// No-op implementation for consumers without a WebSocket surface
/// (headless CLIs, smoke-test binaries). Drops every notification.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopNotificationSender;

impl NotificationSender for NoopNotificationSender {
    fn send_to_account(&self, _: uuid::Uuid, _: &str) -> usize {
        0
    }
}
