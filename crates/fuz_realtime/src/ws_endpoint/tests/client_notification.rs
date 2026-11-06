//! Pins the **notification-form** `cancel` the WS read loop owns.
//!
//! The client sends `cancel` as a JSON-RPC notification (no `id`) —
//! `fuz_app`'s `FrontendWebsocketClient` has no other form — so the
//! notification arm, not the request arm, is what makes cancellation
//! reach a handler. These drive [`apply_client_notification`], the
//! whole decision that arm makes, against a real
//! [`PendingRequestSignals`]; the loop's cancel wiring is covered
//! cross-process.
//!
//! "No frame written" is structural rather than asserted here: the
//! notification arm has no `tx.send`, and this helper returns a `bool`
//! the loop only traces. The wire half — a cancel notification is
//! followed by no frame on either backend — is pinned by a consumer's
//! cross-backend suite, not in this workspace.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]

use serde_json::json;
use tokio_util::sync::CancellationToken;

use crate::ws_endpoint::{PendingRequestSignals, apply_client_notification};

const CANCEL: &str = "cancel";

/// A `cancel` notification naming an in-flight request cancels **that
/// request's** token, and only that one — siblings and the socket
/// parent stay live. This is the arm the whole client-cancel path
/// runs through, so a notification the loop merely drops would make
/// every client cancel a no-op.
#[test]
fn cancel_notification_cancels_the_named_inflight_request() {
    let socket = CancellationToken::new();
    let mut signals = PendingRequestSignals::new(socket.clone());
    let target = json!("req-1");
    let sibling = json!(7);
    let token_target = signals.begin(&target).expect("a fresh id begins");
    let token_sibling = signals.begin(&sibling).expect("a fresh id begins");

    assert!(apply_client_notification(
        CANCEL,
        &json!({"request_id": "req-1"}),
        &signals
    ));

    assert!(
        token_target.is_cancelled(),
        "the named request is cancelled"
    );
    assert!(!token_sibling.is_cancelled(), "a sibling stays live");
    assert!(!socket.is_cancelled(), "the socket parent is untouched");
}

/// An unknown / already-completed `request_id` is a silent no-op —
/// the race between a response landing and a late cancel needs no
/// coordination.
#[test]
fn cancel_notification_unknown_id_is_a_noop() {
    let socket = CancellationToken::new();
    let mut signals = PendingRequestSignals::new(socket.clone());
    let live = json!("live");
    let token_live = signals.begin(&live).expect("a fresh id begins");
    let done = json!("done");
    let token_done = signals.begin(&done).expect("a fresh id begins");
    signals.complete(&done);

    assert!(!apply_client_notification(
        CANCEL,
        &json!({"request_id": "never-existed"}),
        &signals
    ));
    assert!(!apply_client_notification(
        CANCEL,
        &json!({"request_id": "done"}),
        &signals
    ));

    assert!(!token_live.is_cancelled());
    assert!(!token_done.is_cancelled());
    assert!(!socket.is_cancelled());
}

/// Malformed params — a missing `request_id`, a non-object `params`,
/// an absent `params` (the classifier's null sentinel) — are no-ops
/// too. The twin's `CancelNotificationParams.safeParse` failure path
/// ignores the frame the same way.
#[test]
fn cancel_notification_malformed_params_is_a_noop() {
    let socket = CancellationToken::new();
    let mut signals = PendingRequestSignals::new(socket.clone());
    let live = json!("live");
    let token_live = signals.begin(&live).expect("a fresh id begins");

    for params in [
        json!({}),
        json!({"bogus": "live"}),
        json!([]),
        json!("live"),
        json!(null),
    ] {
        assert!(
            !apply_client_notification(CANCEL, &params, &signals),
            "params: {params}"
        );
    }

    assert!(!token_live.is_cancelled(), "nothing was cancelled");
    assert!(!socket.is_cancelled());
}

/// An **extra key** alongside a valid `request_id` fails the parse and
/// cancels nothing — the twin's params schema is a
/// `z.strictObject`, so a frame it rejects must be rejected here too.
/// Reading `request_id` out of the object and ignoring the rest would
/// honor a frame the reference impl drops.
#[test]
fn cancel_notification_extra_key_is_a_noop() {
    let socket = CancellationToken::new();
    let mut signals = PendingRequestSignals::new(socket.clone());
    let live = json!("live");
    let token_live = signals.begin(&live).expect("a fresh id begins");

    assert!(!apply_client_notification(
        CANCEL,
        &json!({"request_id": "live", "bogus": 1}),
        &signals
    ));

    assert!(!token_live.is_cancelled(), "the named request survives");
    assert!(!socket.is_cancelled());
}

/// A `request_id` outside the `JsonrpcRequestId` (string|number) space
/// names nothing — it can't be keyed, so it misses rather than
/// matching some entry by its text form.
#[test]
fn cancel_notification_non_id_shaped_request_id_is_a_noop() {
    let socket = CancellationToken::new();
    let mut signals = PendingRequestSignals::new(socket.clone());
    let live = json!("live");
    let token_live = signals.begin(&live).expect("a fresh id begins");

    for request_id in [json!(null), json!(true), json!(["live"]), json!({})] {
        assert!(
            !apply_client_notification(CANCEL, &json!({ "request_id": request_id }), &signals),
            "request_id: {request_id}"
        );
    }

    assert!(!token_live.is_cancelled());
    assert!(!socket.is_cancelled());
}

/// A numeric in-flight id is cancelled by the number, not by the
/// string of its digits — the key is typed (see
/// `crate::ws_signals`), so the two never collide.
#[test]
fn cancel_notification_matches_the_id_type() {
    let socket = CancellationToken::new();
    let mut signals = PendingRequestSignals::new(socket.clone());
    let numeric = json!(7);
    let token_numeric = signals.begin(&numeric).expect("a fresh id begins");

    assert!(!apply_client_notification(
        CANCEL,
        &json!({"request_id": "7"}),
        &signals
    ));
    assert!(!token_numeric.is_cancelled(), "request 7 survives");

    assert!(apply_client_notification(
        CANCEL,
        &json!({"request_id": 7}),
        &signals
    ));
    assert!(token_numeric.is_cancelled());
    assert!(!socket.is_cancelled());
}

/// Every other notification is dropped — including one whose params
/// happen to name a live request, so the method check is what gates
/// cancellation, not the payload shape.
#[test]
fn other_notifications_are_dropped() {
    let socket = CancellationToken::new();
    let mut signals = PendingRequestSignals::new(socket.clone());
    let live = json!("live");
    let token_live = signals.begin(&live).expect("a fresh id begins");

    for method in ["heartbeat", "peer/ping", "totally_unknown"] {
        assert!(
            !apply_client_notification(method, &json!({"request_id": "live"}), &signals),
            "method: {method}"
        );
    }

    assert!(!token_live.is_cancelled());
    assert!(!socket.is_cancelled());
}
