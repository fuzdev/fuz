//! Notify seam — borrowed `&dyn Fn` shape.
//!
//! ## Shape
//!
//! An owned `Arc<dyn Fn(&str, Value) + Send + Sync>` would allocate an `Arc`
//! per HTTP request even though HTTP never invokes the closure outside
//! `_test_*` paths. The shape is **borrowed** instead:
//! a function pointer for the HTTP no-op (zero alloc, zero indirection)
//! and a stack reference to the WS closure during dispatch.
//!
//! Two cost wins:
//!
//! 1. **HTTP per-request allocation eliminated.** [`http_no_op_notify`]
//!    is a `fn` constant — no Arc, no closure capture, no per-request
//!    allocation. The HTTP dispatcher passes `&http_no_op_notify`
//!    (free; converts to `&dyn Fn(&str, &Value)` implicitly).
//! 2. **Owned `Value` → borrowed `&Value`.** Avoids the `params.clone()`
//!    every WS notify site would pay on an owned shape. Callers serialize from
//!    the borrow directly.
//!
//! ## Usage
//!
//! ```ignore
//! // HTTP dispatcher — zero alloc, zero capture.
//! let notify: &dyn Fn(&str, &serde_json::Value) = &http_no_op_notify;
//!
//! // WS dispatcher — capture `Arc<ConnectionRegistry>` + connection id
//! // once per socket, hand a reference to each dispatched request.
//! let notify_closure = ws_notify_for_connection(registry.clone(), conn_id);
//! let notify: &dyn Fn(&str, &serde_json::Value) = &notify_closure;
//! ```

use std::sync::Arc;

use serde_json::Value;

use fuz_http::notification;

use crate::connection::ConnectionId;
use crate::connection_registry::ConnectionRegistry;

/// HTTP no-op notify — a `fn`, not a closure.
///
/// HTTP has no return channel for server-pushed notifications, so the
/// only sites that fire `notify` on HTTP are the gated `_test_*`
/// actions (which observe via tracing). In production HTTP traffic
/// this fires zero times per request; the function-pointer shape
/// guarantees we don't pay for what we don't use.
///
/// Logs at `debug` so tests can observe the call without leaking into
/// release logs.
pub fn http_no_op_notify(method: &str, _params: &Value) {
    tracing::debug!(method, "http: notify is a no-op");
}

/// Build a WS-side notify closure for one connection.
///
/// Captures `Arc<ConnectionRegistry>` + the connection's
/// [`ConnectionId`] **once per socket**, with no per-request `Arc::new`.
/// Each invocation builds the JSON-RPC notification text via
/// [`fuz_http::notification`] from the borrowed `&Value` and dispatches
/// it through the registry's `send_to`, so it never waits: a notification
/// that does not fit the connection's outbound queue closes the connection
/// (`ConnectionRegistry`'s "Outbound bound"), and one sent after any close
/// goes nowhere.
///
/// The closure is owned by the caller (e.g. the WS loop). Consumers
/// pass `&notify_closure` into the dispatcher so the borrow shape
/// propagates through `ActionContext.notify`.
pub fn ws_notify_for_connection(
    registry: Arc<ConnectionRegistry>,
    conn_id: ConnectionId,
) -> impl Fn(&str, &Value) + Send + Sync + 'static {
    move |method: &str, params: &Value| {
        let n = notification(method, params);
        registry.send_to(conn_id, &n);
    }
}

/// Serialize a notification to wire text via [`fuz_http::notification`]
/// without sending it.
///
/// Re-exported so callers building a notification once and dispatching
/// it through multiple paths (e.g. broadcast + per-connection) don't
/// pay the build cost twice.
pub fn notify_to_string(method: &str, params: &Value) -> String {
    notification(method, params)
}
