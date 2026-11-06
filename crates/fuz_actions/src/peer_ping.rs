//! `peer/ping` protocol action — the first consumer of `ActionPeer`.
//!
//! The server→client complement to the client→server [`crate::heartbeat`]
//! (`initiator: both` — both directions exist, this module adds the new
//! one). A client invokes `peer/ping`; the handler turns around and
//! **initiates** a `peer/ping` request back to that same socket via
//! [`ActionContext::request_client`], awaits the client's echo, **validates
//! it against [`PingResponse`]**, and returns the validated shape. That one
//! round-trip exercises the whole mechanism with zero placeholders — the
//! `Classified::Response` demux, the per-`(conn, id)` pending registry,
//! the async `&dyn ActionPeer`, response validation, and every
//! [`PeerError`] variant — so the abstraction has no stubbed parts waiting
//! for a "real" consumer.
//!
//! ## Protocol-level, not declared-surface
//!
//! `peer/ping` joins [`crate::PROTOCOL_ACTION_SPECS`] beside `heartbeat`,
//! so — like it — it is **excluded from the cross-impl action-manifest**
//! (the two impls organize protocol actions differently: the TS spine
//! keeps `heartbeat` WS-only and mounts `peer/ping` on both transports; the
//! Rust spine registers both on one shared registry and marks `heartbeat`
//! `ws_only`, so only `peer/ping` is HTTP-reachable on either). Its
//! wire-shape parity is proven by the behavioral
//! `describe_peer_ping_ws_tests` cross-backend suite, not the manifest
//! gate.
//!
//! ## Not a capability
//!
//! You don't advertise "I can echo" — any peer implementing the responder
//! half answers a ping. The server pings *optimistically*; a timeout means
//! "dead or doesn't respond," which is exactly the liveness signal. No
//! capability gate, no precondition check; `auth: public` (a liveness echo
//! is non-sensitive). Public is not ungoverned, though: the spec carries an
//! IP rate-limit class, the one throttle an unauthenticated method can be
//! given — see [`peer_ping_action_spec`].

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use fuz_auth::RateLimitClass;
use fuz_http::{
    InputShape, JsonrpcError, JsonrpcErrorCode, internal_error_with_source, validation_error,
};
use fuz_realtime::{DEFAULT_PEER_REQUEST_TIMEOUT, PeerError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::action_context::ActionContext;
use crate::action_spec::{ActionSpec, public_readonly_spec};

/// The wire method name (shared by both directions).
pub const PEER_PING_METHOD: &str = "peer/ping";

// -- Stable `data.reason` discriminators (cross-impl contract) ---------------
//
// The cross-backend security negatives assert on these, so they're part of
// the wire contract. The TS test side keeps its own copies, parity by test.

/// The server-initiated ping timed out (the canonical liveness-failure
/// signal — "dead or doesn't respond").
pub const REASON_PEER_TIMEOUT: &str = "peer_timeout";
/// The socket closed (clean close or revocation) before the client replied.
pub const REASON_PEER_CONNECTION_GONE: &str = "peer_connection_gone";
/// `peer/ping` was invoked on a context with no return socket (HTTP / WS-less).
pub const REASON_PEER_NO_TRANSPORT: &str = "peer_no_transport";
/// The per-connection in-flight bound was hit (backpressure).
pub const REASON_PEER_TOO_MANY_IN_FLIGHT: &str = "peer_too_many_in_flight";
/// The client's reply did not match [`PingResponse`] (wrong/oversized
/// shape) — rejected at the validation boundary, never handed to the
/// caller as untyped data.
pub const REASON_PEER_PING_INVALID_REPLY: &str = "peer_ping_invalid_reply";
/// The client echoed a different nonce than the one issued — not a valid
/// liveness echo.
pub const REASON_PEER_PING_NONCE_MISMATCH: &str = "peer_ping_nonce_mismatch";

// -- Transport-refusal `message` strings (cross-impl contract) --------------
//
// The `message` is the third field of the refusal envelope, beside the code
// and the `data.reason`, and it is the one a developer reads. Each of these
// — the four transport arms and the two reply-validation refusals — is
// byte-identical to the TS twin's literal in `actions/peer_ping.ts`, and a
// consumer's cross-backend suite, not in this workspace, pins the
// no-transport one across both backends.

/// The `message` on the timed-out arm.
pub const PEER_TIMEOUT_MESSAGE: &str = "peer request timed out";
/// The `message` on the socket-closed arm.
pub const PEER_CONNECTION_GONE_MESSAGE: &str = "peer connection gone";
/// The `message` the no-transport refusal carries. Named because the
/// handler's own early return raises it too, not only the [`PeerError`]
/// mapping.
pub const PEER_NO_TRANSPORT_MESSAGE: &str = "peer/ping has no return transport";
/// The `message` on the in-flight-cap arm.
pub const PEER_TOO_MANY_IN_FLIGHT_MESSAGE: &str = "too many in-flight peer requests";
/// The `message` when the client's reply fails [`PingResponse`] validation.
pub const PEER_PING_INVALID_REPLY_MESSAGE: &str = "peer/ping reply failed validation";
/// The `message` when the client echoes a different nonce than issued.
pub const PEER_PING_NONCE_MISMATCH_MESSAGE: &str = "peer/ping reply nonce mismatch";

/// The server→client request payload — a nonce the client echoes back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRequest {
    pub nonce: i64,
}

/// The client's reply payload: the echoed nonce + the client's protocol
/// version. The inbound reply is **validated against this** before it
/// resolves the awaiting caller.
///
/// Both fields read as the twin's `z.number().int()` does
/// ([`fuz_http::deserialize_wire_int`]), so a client that writes `7.0` is
/// answered alike on both spines. `protocol_version` stays a `u32`, stricter
/// than the twin's sign-free `int()` by refusing a negative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_int")]
    pub nonce: i64,
    #[serde(deserialize_with = "fuz_http::deserialize_wire_int")]
    pub protocol_version: u32,
}

/// Optional knobs on the client→server `peer/ping` *invocation* (distinct
/// from the server→client [`PingRequest`] wire shape). Both default:
/// the server allocates a monotonic nonce when absent and uses
/// [`DEFAULT_PEER_REQUEST_TIMEOUT`] when `timeout_ms` is absent. `timeout_ms` lets
/// the conformance suite drive a short deadline for the never-replying
/// `Timeout` negative without waiting the full default.
///
/// `timeout_ms` is **shorten-only** — clamped to [`DEFAULT_PEER_REQUEST_TIMEOUT`]
/// (see [`handle`]). The pingee can make the server give up *sooner*, never
/// hold its resources *longer*; a server-side caller that wants a longer
/// deadline passes it to [`fuz_realtime::ActionPeer::request`] directly,
/// where the deadline is a server policy rather than a remote-client input.
///
/// Strict, mirroring the TS `PingActionInput`'s `z.strictObject`. `peer/ping`
/// is `auth: public` and so declares no `acting` field, which makes a
/// well-formed `acting` an unrecognized key here — the same `-32602` the twin
/// gives, rather than a value the dispatcher's `check_acting_selector` waves
/// through on a spec that has no actor axis to spend it on.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PingActionInput {
    /// `z.number().int().optional()` on the twin, which admits negatives and
    /// zero — hence `i64`, not `u64`. The adapter holds `.int()` itself: any
    /// integral spelling, within the safe-integer range.
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_int")]
    nonce: Option<i64>,
    /// `z.number().int().positive().optional()` on the twin. The adapter holds
    /// `.int()` and `u64` the sign half (a negative is `-32602` from serde);
    /// the zero half is in [`PingActionInput::check_bounds`].
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_int")]
    timeout_ms: Option<u64>,
}

impl PingActionInput {
    /// Enforce the bound the twin's zod declares past `.int()`, which the
    /// field types and the wire-int adapter do not express: `.positive()` on
    /// `timeout_ms`.
    ///
    /// # Errors
    ///
    /// [`fuz_http::invalid_input_params`] (-32602), the code `z.number()`'s
    /// `too_small` issue produces.
    fn check_bounds(&self) -> Result<(), JsonrpcError> {
        if self.timeout_ms == Some(0) {
            return Err(fuz_http::invalid_input_params(
                "timeout_ms must be a positive safe integer",
                None,
            ));
        }
        Ok(())
    }
}

/// Monotonic nonce source for server-initiated pings whose invocation
/// didn't pin one. Uniqueness across a socket's pings is a nice-to-have
/// (the `(conn, id)` correlation is the real anti-confusion guard); a
/// counter is sufficient and dependency-free.
fn next_nonce() -> i64 {
    static COUNTER: AtomicI64 = AtomicI64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Map a [`PeerError`] to the wire [`JsonrpcError`] the `peer/ping` action
/// returns, each carrying a stable `data.reason` the cross-backend
/// negatives assert on. A [`PeerError::ClientError`] forwards the client's
/// own error envelope verbatim (the client replied with an error → that
/// *is* the action's error).
fn peer_error_to_jsonrpc(err: PeerError) -> JsonrpcError {
    let (code, message, reason) = match err {
        PeerError::ClientError(je) => return je,
        PeerError::Timeout => (
            JsonrpcErrorCode::Timeout,
            PEER_TIMEOUT_MESSAGE,
            REASON_PEER_TIMEOUT,
        ),
        PeerError::ConnectionGone => (
            JsonrpcErrorCode::ServiceUnavailable,
            PEER_CONNECTION_GONE_MESSAGE,
            REASON_PEER_CONNECTION_GONE,
        ),
        // No return socket (HTTP / WS-less): `peer/ping` isn't available over
        // this transport. `invalid_request`'s generic `"invalid request"` is
        // not used here — the arm carries the twin's own message, like the
        // other three, so the wire text matches TS.
        PeerError::NoTransport => (
            JsonrpcErrorCode::InvalidRequest,
            PEER_NO_TRANSPORT_MESSAGE,
            REASON_PEER_NO_TRANSPORT,
        ),
        PeerError::TooManyInFlight => (
            JsonrpcErrorCode::QueueOverflow,
            PEER_TOO_MANY_IN_FLIGHT_MESSAGE,
            REASON_PEER_TOO_MANY_IN_FLIGHT,
        ),
    };
    JsonrpcError {
        code,
        message: message.to_owned(),
        data: Some(serde_json::json!({ "reason": reason })),
    }
}

/// Run the server→client ping round-trip for one invocation.
async fn handle(params: Value, ctx: ActionContext<'_>) -> Result<Value, JsonrpcError> {
    // `parse_strict_params` maps absent params (and a direct `Value::Null` caller)
    // to `{}`, and every field is optional, so an argument-less ping needs no
    // special case here.
    let input: PingActionInput = fuz_http::parse_strict_params(params)?;
    input.check_bounds()?;

    let nonce = input.nonce.unwrap_or_else(next_nonce);
    // Shorten-only: clamp the client-supplied deadline to the server default so
    // a remote client can't make the dispatcher hold its pooled connection (and
    // the pending entry) awaiting the client's *own* reply for longer than the
    // server's own liveness window — the resource-holding lever a long
    // attacker-chosen `timeout_ms` would otherwise be.
    let timeout = input
        .timeout_ms
        .map_or(DEFAULT_PEER_REQUEST_TIMEOUT, Duration::from_millis)
        .min(DEFAULT_PEER_REQUEST_TIMEOUT);

    // No originating socket → no one to ping (HTTP / WS-less). Routed through
    // the same mapping the peer layer's own `NoTransport` takes, so the two
    // paths can't drift on code, message, or reason.
    let Some(conn) = ctx.connection_id else {
        return Err(peer_error_to_jsonrpc(PeerError::NoTransport));
    };

    let request_params = serde_json::to_value(PingRequest { nonce })
        .map_err(|e| internal_error_with_source("serialize peer/ping request", &e))?;

    // Initiate the server→client request and await the reply. The explicit
    // `peer.request` (vs `ctx.request_client`) threads the per-invocation
    // timeout the conformance suite drives.
    let reply_value = ctx
        .peer
        .request(conn, PEER_PING_METHOD, &request_params, timeout)
        .await
        .map_err(peer_error_to_jsonrpc)?;

    // VALIDATE against `PingResponse` before the reply crosses into typed
    // server code — a malformed/wrong-shape reply becomes an error here,
    // never an unvalidated `Value` handed downstream, never a panic.
    let reply: PingResponse = serde_json::from_value(reply_value).map_err(|e| {
        tracing::debug!(error = %e, "peer/ping reply did not match PingResponse");
        let mut err = validation_error(PEER_PING_INVALID_REPLY_MESSAGE);
        err.data = Some(serde_json::json!({ "reason": REASON_PEER_PING_INVALID_REPLY }));
        err
    })?;

    // A reply echoing a different nonce isn't a valid liveness echo.
    if reply.nonce != nonce {
        let mut err = validation_error(PEER_PING_NONCE_MISMATCH_MESSAGE);
        err.data = Some(serde_json::json!({ "reason": REASON_PEER_PING_NONCE_MISMATCH }));
        return Err(err);
    }

    serde_json::to_value(reply)
        .map_err(|e| internal_error_with_source("serialize peer/ping response", &e))
}

/// Build the `peer/ping` spec — public, `side_effects: false`, IP rate-limited.
///
/// The IP class is the one gate an `auth: public` method can carry. Without
/// it an anonymous HTTP POST passes the 401 gate and spends the
/// authorization phase's pool checkout *and* the handler's own before the
/// refusal, so the cheapest method on the surface is also the one an
/// unauthenticated caller can loop hardest; the class makes a throttled call
/// cost one checkout instead of two. It gates the socket path equally, where
/// the method does real work.
///
/// A consumer opts in by wiring an IP limiter into its `ActionDispatch`; an
/// unwired axis skips the gate. Pick the limiter's bounds
/// deliberately rather than inheriting a backstop — the per-deployment
/// options are the only place the budget is stated.
#[must_use]
pub fn peer_ping_action_spec() -> ActionSpec {
    public_readonly_spec(PEER_PING_METHOD, InputShape::Object, |params, ctx| {
        Box::pin(async move { handle(params, ctx).await })
    })
    .with_rate_limit(RateLimitClass::Ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_auth::AuthSpec;
    use fuz_http::SAFE_INTEGER_MAX;
    use serde_json::json;

    #[test]
    fn ping_response_round_trips() {
        let r = PingResponse {
            nonce: 7,
            protocol_version: 1,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v, json!({"nonce": 7, "protocol_version": 1}));
        let back: PingResponse = serde_json::from_value(v).unwrap();
        assert_eq!(back.nonce, 7);
        assert_eq!(back.protocol_version, 1);
    }

    #[test]
    fn ping_response_rejects_wrong_shape() {
        // Missing protocol_version → validation failure (the wrong-shape
        // negative the handler maps to REASON_PEER_PING_INVALID_REPLY).
        assert!(serde_json::from_value::<PingResponse>(json!({"nonce": 1})).is_err());
        // Wrong type.
        assert!(
            serde_json::from_value::<PingResponse>(json!({"nonce": "x", "protocol_version": 1}))
                .is_err()
        );
    }

    #[test]
    fn action_input_defaults_and_parses() {
        let empty: PingActionInput = serde_json::from_value(json!({})).unwrap();
        assert_eq!(empty.nonce, None);
        assert_eq!(empty.timeout_ms, None);

        let filled: PingActionInput =
            serde_json::from_value(json!({"nonce": 5, "timeout_ms": 200})).unwrap();
        assert_eq!(filled.nonce, Some(5));
        assert_eq!(filled.timeout_ms, Some(200));
    }

    /// `nonce` is `z.number().int()` on the twin — signed, so a negative and a
    /// zero are ordinary values, not refusals. `i64` carries them; a `u64`
    /// field answers `-32602` where the twin issues the ping.
    #[test]
    fn a_negative_nonce_is_a_nonce() {
        let signed: PingActionInput = serde_json::from_value(json!({"nonce": -5})).unwrap();
        assert_eq!(signed.nonce, Some(-5));
        assert!(signed.check_bounds().is_ok());

        let zero: PingActionInput = serde_json::from_value(json!({"nonce": 0})).unwrap();
        assert_eq!(zero.nonce, Some(0));
        assert!(zero.check_bounds().is_ok());
    }

    /// The bounds `.int()` and `.positive()` declare, on both fields. Each row
    /// is a value one of the two integer types would otherwise take silently.
    #[test]
    fn numeric_bounds_match_the_ts_twin() {
        // `.int()`: the adapter refuses past the safe range at decode, the
        // extremes of the field's own integer type included
        for params in [
            json!({"nonce": SAFE_INTEGER_MAX + 1}),
            json!({"nonce": -SAFE_INTEGER_MAX - 1}),
            json!({"nonce": i64::MAX}),
            json!({"nonce": i64::MIN}),
            json!({"nonce": 1.5}),
            json!({"timeout_ms": SAFE_INTEGER_MAX + 1}),
            json!({"timeout_ms": 2.5}),
            // the sign half `u64` carries
            json!({"timeout_ms": -1}),
        ] {
            assert!(
                serde_json::from_value::<PingActionInput>(params.clone()).is_err(),
                "{params} must be refused at decode"
            );
        }

        // `.positive()` refuses zero, which `u64` and the adapter accept
        let zero: PingActionInput = serde_json::from_value(json!({"timeout_ms": 0})).unwrap();
        let error = zero.check_bounds().expect_err("a zero timeout is refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);

        // The edges the twin admits, integral float spellings included.
        for params in [
            json!({"nonce": SAFE_INTEGER_MAX}),
            json!({"nonce": -SAFE_INTEGER_MAX}),
            json!({"nonce": 5.0}),
            json!({"timeout_ms": 1}),
            json!({"timeout_ms": 1.0}),
            json!({"timeout_ms": SAFE_INTEGER_MAX}),
        ] {
            let input: PingActionInput = serde_json::from_value(params.clone()).unwrap();
            assert!(input.check_bounds().is_ok(), "params: {params}");
        }
        let input: PingActionInput =
            serde_json::from_str(r#"{"nonce":-0,"timeout_ms":1e3}"#).unwrap();
        assert_eq!((input.nonce, input.timeout_ms), (Some(0), Some(1000)));
    }

    /// The client's reply reads `.int()` as the twin does.
    #[test]
    fn ping_response_reads_integral_floats() {
        let reply: PingResponse =
            serde_json::from_str(r#"{"nonce":7.0,"protocol_version":1e0}"#).unwrap();
        assert_eq!((reply.nonce, reply.protocol_version), (7, 1));
        assert!(
            serde_json::from_str::<PingResponse>(r#"{"nonce":7.5,"protocol_version":1}"#).is_err()
        );
    }

    /// The strict-object half: `peer/ping` declares two fields and no
    /// `acting`, so an unrecognized key — a well-formed acting selector very
    /// much included — is refused at the input rather than dropped. The
    /// dispatcher's `check_acting_selector` judges only the *value*, so
    /// without `deny_unknown_fields` a valid v4 would sail through to the
    /// handler where the TS twin's `z.strictObject` answers `-32602`.
    #[test]
    fn action_input_refuses_an_unrecognized_key() {
        assert!(
            serde_json::from_value::<PingActionInput>(
                json!({"nonce": 5, "acting": "3f8a1c2e-1234-4abc-9def-0123456789ab"})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<PingActionInput>(json!({"nope": 1})).is_err());
        // A `null` on an optional key is refused by `parse_strict_params`'
        // null walk ahead of decode, and by the wire-int adapter itself.
        assert!(serde_json::from_value::<PingActionInput>(json!({"nonce": null})).is_err());
    }

    /// Every arm carries its own `message` as well as its `data.reason`, and
    /// each `message` is the TS twin's string character for character (the
    /// literals here, not the constants, so a rename on either side of the
    /// twin shows up as a failing assertion rather than a silent follow).
    /// A paraphrase would pass the cross case's code + reason assertions and
    /// still diverge on the wire.
    #[test]
    fn peer_error_mapping_carries_stable_reasons() {
        let cases = [
            (
                PeerError::Timeout,
                JsonrpcErrorCode::Timeout,
                "peer request timed out",
                REASON_PEER_TIMEOUT,
            ),
            (
                PeerError::ConnectionGone,
                JsonrpcErrorCode::ServiceUnavailable,
                "peer connection gone",
                REASON_PEER_CONNECTION_GONE,
            ),
            (
                PeerError::NoTransport,
                JsonrpcErrorCode::InvalidRequest,
                "peer/ping has no return transport",
                REASON_PEER_NO_TRANSPORT,
            ),
            (
                PeerError::TooManyInFlight,
                JsonrpcErrorCode::QueueOverflow,
                "too many in-flight peer requests",
                REASON_PEER_TOO_MANY_IN_FLIGHT,
            ),
        ];
        for (err, code, message, reason) in cases {
            let je = peer_error_to_jsonrpc(err);
            assert_eq!(je.code, code);
            assert_eq!(je.message, message);
            assert_eq!(je.data.unwrap()["reason"], reason);
        }
    }

    /// The named message constants are the same literals the mapping table
    /// above pins, so a caller reaching for a constant and a test reading the
    /// table can't drift apart.
    #[test]
    fn message_constants_match_the_ts_twin() {
        assert_eq!(PEER_TIMEOUT_MESSAGE, "peer request timed out");
        assert_eq!(PEER_CONNECTION_GONE_MESSAGE, "peer connection gone");
        assert_eq!(
            PEER_NO_TRANSPORT_MESSAGE,
            "peer/ping has no return transport"
        );
        assert_eq!(
            PEER_TOO_MANY_IN_FLIGHT_MESSAGE,
            "too many in-flight peer requests"
        );
        assert_eq!(
            PEER_PING_INVALID_REPLY_MESSAGE,
            "peer/ping reply failed validation"
        );
        assert_eq!(
            PEER_PING_NONCE_MISMATCH_MESSAGE,
            "peer/ping reply nonce mismatch"
        );
    }

    #[test]
    fn client_error_is_forwarded_verbatim() {
        let original = fuz_http::forbidden("nope", Some("denied"));
        let mapped = peer_error_to_jsonrpc(PeerError::ClientError(original));
        assert_eq!(mapped.code, JsonrpcErrorCode::Forbidden);
        assert_eq!(mapped.data.unwrap()["reason"], "denied");
    }

    #[test]
    fn spec_is_public_read_only() {
        let spec = peer_ping_action_spec();
        assert_eq!(spec.method, PEER_PING_METHOD);
        assert!(!spec.side_effects);
        assert_eq!(spec.auth, AuthSpec::public());
        // The one gate a public method can carry: an anonymous caller is
        // bucketed by IP, so the no-transport refusal can't be looped for two
        // pool checkouts apiece.
        assert_eq!(spec.rate_limit, Some(RateLimitClass::Ip));
        // Not `ws_only`: an HTTP invocation must reach the handler and refuse
        // with `peer_no_transport`, which is what the TS twin's HTTP-RPC mount
        // of `peer_ping_action` exists to produce.
        assert!(!spec.ws_only);
    }
}
