//! WebSocket per-message dispatch wrapping [`perform_action`](crate::perform_action::perform_action).
//!
//! Builds the `WsDispatchFn` shape that `fuz_realtime::run_ws_connection`
//! calls per message. Each WS frame becomes one [`perform_action`](crate::perform_action::perform_action) call;
//! the consumer's [`crate::ActionRegistry`] is closed over the dispatch
//! closure so individual frames look up + dispatch without re-resolving
//! the auth state.
//!
//! ## `cancel` interception
//!
//! `cancel` is **not** dispatched here — `fuz_realtime::run_ws_connection`
//! intercepts the notification `{method: "cancel", params: {request_id:
//! ...}}` at the loop level (where the per-request cancellation map lives)
//! and fires only the named request's child token, leaving every other
//! request — and every future request — on the socket live. The method is
//! absent from the registry entirely, so a `cancel` that arrives as a
//! request (carrying an `id`) reaches this dispatcher and answers
//! `method_not_found`, matching the twin. See `fuz_realtime`'s
//! `ws_signals` for the per-request token hierarchy and
//! [`fuz_realtime::CANCEL_METHOD`] for why there is no spec.

use std::sync::Arc;

use fuz_auth::ResolvedAuth;
use fuz_http::{error_response, internal_error_with_source};
use fuz_realtime::WsDispatchFn;

use crate::action_output::write_success_response;
use crate::perform_action::{PerformActionInput, PerformActionOptions, perform_action_with};

/// Per-socket state captured by the WS dispatch closure.
///
/// Constructed once per WS upgrade, then handed to
/// `fuz_realtime::run_ws_connection` as part of the `WsDispatchFn`.
pub struct WsConnectionState {
    /// The credential the socket upgraded on, passed to every message's
    /// dispatch. The per-message authorization phase resolves the acting actor
    /// from its account + the frame's `acting` input — auth does not bind an
    /// actor at upgrade time. Its scope is consulted per message: a narrowed
    /// token cannot upgrade at all (rule 3), so in practice it is
    /// `TokenScope::Full` on every live socket — but the per-message check
    /// runs regardless, so the invariant is enforced rather than assumed.
    pub auth: ResolvedAuth,
    pub client_ip: Option<String>,
    pub connection_id: fuz_realtime::ConnectionId,
}

impl std::fmt::Debug for WsConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnectionState")
            .field("account_id", &self.auth.account.id)
            .field("credential_type", &self.auth.credential_type())
            // the hash names a live session — say only whether there is one
            .field("session_hash", &self.auth.session_hash().map(|_| "<set>"))
            .field("scope", self.auth.scope())
            .field("client_ip", &self.client_ip)
            .field("connection_id", &self.connection_id)
            .finish()
    }
}

/// Build the [`WsDispatchFn`] shape `fuz_realtime` consumes.
///
/// `options` holds the long-lived state (pool, registry, audit, closer) —
/// [`crate::ActionDispatch::perform_action_options`] over the connection's
/// peer, cheap to `Arc::clone` into the closure. `state` is the per-socket
/// auth context — also cloned in.
///
/// Each invocation:
/// 1. Calls `perform_action` with the borrowed envelope (a `cancel`
///    *notification* never reaches here — the WS loop intercepts it).
/// 2. Serializes the success/error envelope to wire text.
///
/// Returns `None` only on serialization failure (essentially impossible
/// for in-shape inputs); errors are serialized into the envelope.
#[must_use]
pub(crate) fn ws_dispatch_fn(
    options: PerformActionOptions,
    state: Arc<WsConnectionState>,
) -> WsDispatchFn {
    let options = Arc::new(options);

    Arc::new(move |input| {
        let options = Arc::clone(&options);
        let state = Arc::clone(&state);
        Box::pin(async move { dispatch_one(input, &options, &state).await })
    })
}

async fn dispatch_one(
    input: fuz_realtime::ws_endpoint::WsDispatchInput<'_>,
    options: &Arc<PerformActionOptions>,
    state: &Arc<WsConnectionState>,
) -> Option<String> {
    let log = tracing::Span::current();
    let perform_input = PerformActionInput {
        method: input.method,
        params: input.params,
        request_id: input.request_id,
        auth: Some(&state.auth),
        client_ip: state.client_ip.clone(),
        connection_id: Some(state.connection_id),
        notify: input.notify,
        signal: input.signal,
        log: &log,
    };

    // Mark the request owed while its connection is still open: a handler
    // revoking its own connection's credential closes it from the drain that
    // follows, and the loop then writes this response ahead of the close.
    let signal = input.signal;
    let reply_owed = input.reply_owed;
    let mark_owed = move || {
        if !signal.is_cancelled() {
            reply_owed.mark();
        }
    };
    match perform_action_with(perform_input, options, &mark_owed).await {
        Ok(output) => {
            match write_success_response(input.request_id, &output) {
                // serde_json writes UTF-8, so this never refuses
                Ok(frame) => String::from_utf8(frame).ok(),
                Err(e) => {
                    let error = internal_error_with_source("result serialization failed", &e);
                    serde_json::to_string(&error_response(input.request_id.clone(), error)).ok()
                }
            }
        }
        Err(error) => serde_json::to_string(&error_response(input.request_id.clone(), error)).ok(),
    }
}
