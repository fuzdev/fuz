//! JSON-RPC 2.0 envelopes — request, response, notification, and
//! classifier.
//!
//! Only the envelope half lives here; the HTTP-handler half
//! (`rpc_post_handler`, `rpc_get_handler`) lives in `fuz_actions` — so the
//! framework primitives here have zero consumer coupling.
//!
//! Mirrors `fuz_app`'s `http/jsonrpc.ts` Zod schemas + MCP `_meta`
//! superset shape.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::jsonrpc_error::{JsonrpcError, JsonrpcErrorCode, invalid_request};

/// JSON-RPC 2.0 version string. Always `"2.0"` on every envelope.
pub const JSONRPC_VERSION: &str = "2.0";

// -- Envelopes ----------------------------------------------------------------

/// JSON-RPC 2.0 request envelope.
///
/// Deserialization-only — handlers receive a parsed `Value` and call
/// [`classify`] for spec-conformant dispatch. The named struct is
/// provided for consumers (test fixtures, codegen) that prefer the
/// typed shape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonrpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Request id — must be string or number per the MCP superset; the
    /// classifier rejects bool/null/array/object ids as
    /// `invalid_request`.
    pub id: Value,
}

/// Successful JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct JsonrpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    pub result: Value,
}

/// JSON-RPC 2.0 error response (full envelope).
#[derive(Debug, Serialize)]
pub struct JsonrpcErrorResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    pub error: JsonrpcError,
}

/// JSON-RPC 2.0 notification (no `id` field — server-initiated push).
///
/// Generic over the params type — most callers pass a `&SomeStruct`
/// holding the notification-specific shape; the WS notify closure
/// passes `&Value` because the params come from a dynamic dispatch
/// callback. Both go through one serialization path.
#[derive(Debug, Serialize)]
pub struct JsonrpcNotification<'a, T: ?Sized> {
    pub jsonrpc: &'static str,
    pub method: &'a str,
    pub params: &'a T,
}

// -- Builders -----------------------------------------------------------------

#[inline]
#[must_use]
pub const fn success_response(id: Value, result: Value) -> JsonrpcResponse {
    JsonrpcResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        result,
    }
}

#[inline]
#[must_use]
pub const fn error_response(id: Value, error: JsonrpcError) -> JsonrpcErrorResponse {
    JsonrpcErrorResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        error,
    }
}

/// The HTTP response for a JSON-RPC error.
///
/// The error envelope on `id` as an `application/json` body, at the status
/// the error's code maps to ([`crate::error_code_to_http_status`]) — the one
/// rendering every HTTP RPC refusal and dispatch error shares.
#[must_use]
pub fn jsonrpc_error_http_response(id: Value, error: JsonrpcError) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let status = crate::error_code_to_http_status(error.code);
    (status, axum::Json(error_response(id, error))).into_response()
}

/// Build a JSON-RPC notification string for broadcasting to WebSocket
/// clients.
///
/// Generic over the params type so callers don't have to round-trip
/// through `serde_json::to_value` first — one serialization, one site
/// of failure handling. Serialization failure is essentially impossible
/// for in-shape inputs (`serde_json::Value` rejects NaN/Inf, struct
/// derives can't fail), but the warn-and-empty path keeps that contract
/// honest: a future shape slip surfaces in logs instead of silently
/// emitting an empty WS frame.
#[must_use]
pub fn notification<T: ?Sized + Serialize>(method: &str, params: &T) -> String {
    let n = JsonrpcNotification {
        jsonrpc: JSONRPC_VERSION,
        method,
        params,
    };
    match serde_json::to_string(&n) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, method, "failed to serialize JSON-RPC notification");
            String::new()
        }
    }
}

/// Build a JSON-RPC **request** frame string for a server-initiated
/// request to a connected client.
///
/// Mirrors [`notification`] but carries an `id` — the per-connection
/// correlation key the client echoes on its reply, which the WS read loop
/// demuxes back to the awaiting caller (see `Classified::Response`). Like
/// [`notification`], serialization failure is essentially impossible for
/// in-shape inputs; the warn-and-empty path keeps the contract honest
/// rather than emitting a malformed frame silently.
#[must_use]
pub fn request_frame(method: &str, params: &Value, id: &Value) -> String {
    // The envelope contract [`classify`] enforces on inbound frames applies
    // to the ones we emit too: a present `params` must be an object, or the
    // peer's own classifier would answer `invalid_request`.
    debug_assert!(
        params.is_object(),
        "request_frame params must be an object, got {params}"
    );
    let r = JsonrpcRequest {
        jsonrpc: JSONRPC_VERSION.to_owned(),
        method: method.to_owned(),
        params: Some(params.clone()),
        id: id.clone(),
    };
    match serde_json::to_string(&r) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, method, "failed to serialize JSON-RPC request frame");
            String::new()
        }
    }
}

// -- Classification -----------------------------------------------------------

/// Default params when the JSON-RPC envelope **omits** the `params` field.
///
/// A sentinel, not a wire value: [`classify`] refuses an explicit
/// `"params": null` at the envelope, so this `Null` reaches a handler only
/// for an absent key, and `parse_params` maps it to `{}`.
///
/// Public because it is the value a caller observes: both
/// [`Classified::Request`] and [`Classified::Notification`] borrow it for
/// their `params` when the key is absent, so the two `Null`s a caller can
/// hold — this sentinel and a notification's literal `"params": null` —
/// are documented as one contract rather than an unnameable internal.
pub static NULL_PARAMS: Value = Value::Null;

/// Classification result from [`classify`].
///
/// Transport-agnostic — callers apply transport-specific semantics:
/// - HTTP: `Notification` → reject as `invalid_request`; `Response` →
///   `invalid_request` (HTTP issues no server-initiated requests, so an
///   inbound response is unexpected); error → mapped HTTP status
/// - WS: `Notification` → silence (no response sent), except `cancel`,
///   which aborts the named in-flight request without answering a frame;
///   `Response` → demux to the pending-peer-request registry; error →
///   send envelope
#[derive(Debug)]
pub enum Classified<'a> {
    /// Valid request — method, validated id, and params ready for
    /// dispatch.
    Request {
        method: &'a str,
        id: Value,
        params: &'a Value,
    },
    /// Inbound **response** to a server-initiated request — `{id,
    /// result}` or `{id, error}` with no `method`. The WS read loop
    /// demuxes it to the `PendingPeerRequests` registry keyed by
    /// `(ConnectionId, id)`; a response whose id isn't pending for that
    /// connection is dropped + audited (never resolves anything). HTTP
    /// has no server-initiated requests, so this arm only arises over WS.
    /// `outcome` is `Ok(result)` for `{id, result}` and
    /// `Err(JsonrpcError)` for `{id, error}` (the error coerced through
    /// the base set by `parse_inbound_error`).
    Response {
        id: Value,
        outcome: Result<Value, JsonrpcError>,
    },
    /// Error — id and error object for the error response envelope.
    Invalid { id: Value, error: JsonrpcError },
    /// Notification (has method, no id) — caller decides behavior.
    ///
    /// `params` is handed back **unvalidated**: the envelope's
    /// absent-or-object contract governs requests only (a notification
    /// carries no id to answer an error frame on), so junk `params`
    /// reaches the caller as-is and an **absent** one is the
    /// [`NULL_PARAMS`] sentinel. The WS read loop needs the pair to route
    /// a `cancel` notification to its target request; every other
    /// notification stays silent.
    Notification { method: &'a str, params: &'a Value },
}

/// Classify a parsed JSON value as a JSON-RPC message.
///
/// Distinguishes between:
/// - Request (has `method` + valid `id`) → `Classified::Request`
/// - Notification (has `method`, no `id`) → `Classified::Notification`
/// - Response (no `method`, valid `id`, exactly one of `result` /
///   `error`) → `Classified::Response` — an inbound reply to a
///   server-initiated request
/// - Invalid (bad `jsonrpc`, non-object, no-method-no-response, null id,
///   non-object `params`) → `Classified::Invalid`
///
/// Twin of `fuz_app`'s `classify_jsonrpc_message` (`http/jsonrpc_helpers.ts`).
///
/// Id validation matches `fuz_app`: id must be string or number
/// (excludes null per the MCP superset). Non-object values always get
/// `id: null`, as `classify_jsonrpc_message` answers them.
///
/// # The two-layer `params` contract
///
/// `params` is validated across two layers, mirroring the TS twin:
///
/// 1. **Envelope (here).** `params` may be **absent or an object**, and
///    nothing else — `JsonrpcRequest.params` is a
///    `z.looseObject({}).optional()`, so an explicit `null`, an array, or
///    a scalar fails request validation before dispatch. A present
///    non-object is therefore `Classified::Invalid` with `invalid_request`
///    (-32600) and the request's own id, matching
///    `classify_jsonrpc_message`. An **absent** `params` yields
///    the [`NULL_PARAMS`] sentinel.
///
///    Because both transports classify here, this guard runs on the POST
///    path *and* the WS read loop, as it does on the TS twin, whose
///    `classify_jsonrpc_message` both of its transports run too.
/// 2. **Handler (`parse_params`).** The sentinel deserializes as
///    `{}` — that pairing *is* the TS dispatcher's `raw_params ?? {}`, so
///    an all-optional input needs no caller-side `is_null()` branch.
///    `parse_params` keeps its own non-object guard as defense for direct
///    callers (query-string params, tests, peer frames) that never pass
///    through this classifier.
///
/// **Notifications are not validated further.** A method-without-id
/// returns `Classified::Notification { method, params }` carrying `params`
/// exactly as it arrived, so the envelope contract above does not apply to
/// it — matching the TS twin, whose WS notification path never runs the
/// request schema. What a caller does with one is transport-specific and
/// its own concern: the WS read loop (`fuz_realtime::run_ws_connection`)
/// routes a `cancel` notification to the named in-flight request and drops
/// every other notification, while the POST path answers
/// `invalid_request`.
// TODO: Support batch requests (JSON arrays)
#[must_use]
pub fn classify(value: &Value) -> Classified<'_> {
    let Some(obj) = value.as_object() else {
        // non-object body: no object to read an id from, so id: null, as
        // `classify_jsonrpc_message` answers it
        return Classified::Invalid {
            id: Value::Null,
            error: invalid_request(None),
        };
    };

    let jsonrpc = obj.get("jsonrpc").and_then(Value::as_str);
    if jsonrpc != Some(JSONRPC_VERSION) {
        let id = extract_id(obj);
        return Classified::Invalid {
            id,
            error: invalid_request(None),
        };
    }

    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        // No `method`: either an inbound response to a server-initiated
        // request (`{id, result|error}`) or a malformed frame. A response
        // carries a valid (string|number) id and **exactly one** of
        // `result` / `error` (both-present is malformed).
        let id = extract_id(obj);
        let has_result = obj.contains_key("result");
        let has_error = obj.contains_key("error");
        if !id.is_null() && (has_result ^ has_error) {
            let outcome = if has_result {
                Ok(obj.get("result").cloned().unwrap_or(Value::Null))
            } else {
                Err(parse_inbound_error(obj.get("error")))
            };
            return Classified::Response { id, outcome };
        }
        return Classified::Invalid {
            id,
            error: invalid_request(None),
        };
    };

    // No `id` field → notification (caller decides behavior). `params` is
    // passed through unvalidated — see the `Notification` variant's doc.
    let Some(id_val) = obj.get("id") else {
        return Classified::Notification {
            method,
            params: obj.get("params").unwrap_or(&NULL_PARAMS),
        };
    };

    // Validate id is string or number (`fuz_app`'s JsonrpcRequestId
    // excludes null, per MCP).
    let id = if id_val.is_string() || id_val.is_number() {
        id_val.clone()
    } else {
        // null, bool, array, object ids → invalid request.
        return Classified::Invalid {
            id: Value::Null,
            error: invalid_request(None),
        };
    };

    // Envelope-level `params` contract: absent, or an object. A **present**
    // non-object — explicit `null`, an array, a scalar — is `invalid_request`
    // here, before any handler is reached (see the doc comment above).
    let params = match obj.get("params") {
        None => &NULL_PARAMS,
        Some(params) if params.is_object() => params,
        Some(_) => {
            return Classified::Invalid {
                id,
                error: invalid_request(None),
            };
        }
    };

    Classified::Request { method, id, params }
}

/// Extract `id` from a JSON-RPC message object for error responses.
///
/// Matches `fuz_app`'s `classify_jsonrpc_message`: extracts id only if
/// it's a string or number, otherwise returns null.
fn extract_id(obj: &Map<String, Value>) -> Value {
    match obj.get("id") {
        Some(id) if id.is_string() || id.is_number() => id.clone(),
        _ => Value::Null,
    }
}

/// Build a [`JsonrpcError`] from an inbound response's `error` member.
///
/// The peer that replies to a server-initiated request is **untrusted**,
/// so this is deliberately lenient: a `code` outside the base set (a
/// consumer-declared code included — the wire carries no status to rebuild
/// it with) coerces to [`JsonrpcErrorCode::InternalError`], a missing/non-string
/// `message` defaults, and `data` passes through verbatim. The result is
/// always a valid base-set error, so a malformed error object can
/// never panic the read loop — it just surfaces to the awaiting caller as
/// `PeerError::ClientError`.
fn parse_inbound_error(error: Option<&Value>) -> JsonrpcError {
    let obj = error.and_then(Value::as_object);
    let code = obj
        .and_then(|o| o.get("code"))
        .and_then(Value::as_i64)
        .and_then(|n| i32::try_from(n).ok())
        .and_then(|n| JsonrpcErrorCode::try_from(n).ok())
        .unwrap_or(JsonrpcErrorCode::InternalError);
    let message = obj
        .and_then(|o| o.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("peer error")
        .to_owned();
    let data = obj.and_then(|o| o.get("data")).cloned();
    JsonrpcError {
        code,
        message,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_valid_request() {
        let v = json!({"jsonrpc": "2.0", "method": "ping", "id": 1, "params": {"x": 1}});
        match classify(&v) {
            Classified::Request { method, id, params } => {
                assert_eq!(method, "ping");
                assert_eq!(id, json!(1));
                assert_eq!(params, &json!({"x": 1}));
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn classify_request_with_string_id() {
        let v = json!({"jsonrpc": "2.0", "method": "ping", "id": "req-1"});
        match classify(&v) {
            Classified::Request { id, .. } => assert_eq!(id, json!("req-1")),
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn classify_missing_params_defaults_to_null() {
        let v = json!({"jsonrpc": "2.0", "method": "ping", "id": 1});
        match classify(&v) {
            Classified::Request { params, .. } => assert_eq!(params, &Value::Null),
            _ => panic!("expected Request"),
        }
    }

    /// The envelope's `params` contract: absent or object, nothing else.
    /// Twin of `JsonrpcRequest.params: z.looseObject({}).optional()`, which
    /// fails request validation on a present non-object — so the refusal is
    /// `invalid_request` (-32600), not `invalid_params`, and carries the
    /// request's own id (the TS POST handler re-extracts it off the raw body).
    #[test]
    fn classify_present_non_object_params_is_invalid_request() {
        for params in [
            json!(null),
            json!([]),
            json!(["3f8a1c2e"]),
            json!("x"),
            json!(1),
            json!(true),
        ] {
            let v = json!({"jsonrpc": "2.0", "method": "ping", "id": 7, "params": params});
            match classify(&v) {
                Classified::Invalid { id, error } => {
                    assert_eq!(id, json!(7), "params: {params}");
                    assert_eq!(
                        error.code,
                        JsonrpcErrorCode::InvalidRequest,
                        "params: {params}"
                    );
                }
                other => panic!("expected Invalid for params {params}, got {other:?}"),
            }
        }
    }

    /// An empty object is a *valid* envelope — only non-objects are refused.
    #[test]
    fn classify_empty_object_params_is_a_request() {
        let v = json!({"jsonrpc": "2.0", "method": "ping", "id": 1, "params": {}});
        match classify(&v) {
            Classified::Request { params, .. } => assert_eq!(params, &json!({})),
            _ => panic!("expected Request"),
        }
    }

    /// Notifications stop at the `method`-without-`id` shape: `params` is
    /// never validated, so a junk-params notification classifies as one
    /// rather than becoming an error frame, and the junk value is handed
    /// through verbatim. What a transport then does with it is the
    /// caller's concern (the WS loop's `cancel` routing treats a
    /// non-object as an unknown target — a silent no-op).
    #[test]
    fn classify_notification_non_object_params_stays_a_notification() {
        for params in [json!(null), json!([1]), json!("x")] {
            let v = json!({"jsonrpc": "2.0", "method": "evt", "params": params});
            match classify(&v) {
                Classified::Notification {
                    method,
                    params: got,
                } => {
                    assert_eq!(method, "evt");
                    assert_eq!(got, &params, "params passed through verbatim");
                }
                other => panic!("expected Notification for {params}, got {other:?}"),
            }
        }
    }

    #[test]
    fn classify_notification_no_id() {
        let v = json!({"jsonrpc": "2.0", "method": "evt"});
        match classify(&v) {
            Classified::Notification { method, params } => {
                assert_eq!(method, "evt");
                // Absent `params` yields the sentinel, same as a request's.
                assert_eq!(params, &Value::Null);
            }
            other => panic!("expected Notification, got {other:?}"),
        }
    }

    /// The `cancel` wire shape the WS read loop routes on — the classifier
    /// must surface both halves so the loop can find `params.request_id`
    /// without re-parsing the frame.
    #[test]
    fn classify_notification_carries_method_and_params() {
        let v = json!({"jsonrpc": "2.0", "method": "cancel", "params": {"request_id": "r-9"}});
        match classify(&v) {
            Classified::Notification { method, params } => {
                assert_eq!(method, "cancel");
                assert_eq!(params, &json!({"request_id": "r-9"}));
            }
            other => panic!("expected Notification, got {other:?}"),
        }
    }

    #[test]
    fn classify_response_with_result() {
        let v = json!({"jsonrpc": "2.0", "id": "s7", "result": {"nonce": 9}});
        match classify(&v) {
            Classified::Response { id, outcome } => {
                assert_eq!(id, json!("s7"));
                assert_eq!(outcome.unwrap(), json!({"nonce": 9}));
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn classify_response_with_null_result() {
        // `{id, result: null}` is a valid success response (result present).
        let v = json!({"jsonrpc": "2.0", "id": 3, "result": null});
        match classify(&v) {
            Classified::Response { id, outcome } => {
                assert_eq!(id, json!(3));
                assert_eq!(outcome.unwrap(), Value::Null);
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn classify_response_with_error() {
        let v = json!({
            "jsonrpc": "2.0",
            "id": "s1",
            "error": {"code": -32603, "message": "boom", "data": {"x": 1}},
        });
        match classify(&v) {
            Classified::Response { id, outcome } => {
                assert_eq!(id, json!("s1"));
                let err = outcome.expect_err("error outcome");
                assert_eq!(err.code, JsonrpcErrorCode::InternalError);
                assert_eq!(err.message, "boom");
                assert_eq!(err.data, Some(json!({"x": 1})));
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn classify_response_unknown_error_code_coerces_to_internal() {
        // An untrusted peer can send any code; out-of-taxonomy coerces.
        let v = json!({"jsonrpc": "2.0", "id": "s1", "error": {"code": 12345, "message": "x"}});
        match classify(&v) {
            Classified::Response { outcome, .. } => {
                assert_eq!(
                    outcome.expect_err("error").code,
                    JsonrpcErrorCode::InternalError
                );
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn classify_response_both_result_and_error_is_invalid() {
        // Malformed: a JSON-RPC reply carries exactly one of result|error.
        let v = json!({"jsonrpc": "2.0", "id": "s1", "result": 1, "error": {"code": -32603, "message": "x"}});
        assert!(matches!(classify(&v), Classified::Invalid { .. }));
    }

    #[test]
    fn classify_response_null_id_is_invalid() {
        // A response must carry a valid (string|number) id to be demuxable.
        let v = json!({"jsonrpc": "2.0", "id": null, "result": 1});
        assert!(matches!(classify(&v), Classified::Invalid { .. }));
    }

    #[test]
    fn classify_non_object_invalid() {
        let v = json!([1, 2, 3]);
        match classify(&v) {
            Classified::Invalid { id, error } => {
                assert_eq!(id, Value::Null);
                assert_eq!(error.code, JsonrpcErrorCode::InvalidRequest);
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn classify_missing_jsonrpc_invalid() {
        let v = json!({"method": "ping", "id": 1});
        match classify(&v) {
            Classified::Invalid { id, error } => {
                // id extracted because it's a number.
                assert_eq!(id, json!(1));
                assert_eq!(error.code, JsonrpcErrorCode::InvalidRequest);
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn classify_wrong_jsonrpc_version_invalid() {
        let v = json!({"jsonrpc": "1.0", "method": "ping", "id": 1});
        assert!(matches!(classify(&v), Classified::Invalid { .. }));
    }

    #[test]
    fn classify_null_id_invalid() {
        let v = json!({"jsonrpc": "2.0", "method": "ping", "id": null});
        match classify(&v) {
            Classified::Invalid { id, .. } => assert_eq!(id, Value::Null),
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn classify_bool_id_invalid() {
        let v = json!({"jsonrpc": "2.0", "method": "ping", "id": true});
        match classify(&v) {
            Classified::Invalid { id, .. } => assert_eq!(id, Value::Null),
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn classify_missing_method_invalid() {
        let v = json!({"jsonrpc": "2.0", "id": 1});
        match classify(&v) {
            Classified::Invalid { id, .. } => assert_eq!(id, json!(1)),
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn notification_builder_round_trip() {
        let s = notification("event", &json!({"x": 1}));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "event");
        assert_eq!(v["params"]["x"], 1);
        assert!(v.get("id").is_none(), "notification carries no id");
    }

    #[test]
    fn success_response_shape() {
        let r = success_response(json!(1), json!({"ok": true}));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["result"]["ok"], true);
    }

    /// The HTTP rendering is the envelope at the code's status.
    #[tokio::test]
    async fn the_http_rendering_is_the_envelope_at_the_codes_status() {
        let response = jsonrpc_error_http_response(json!(7), invalid_request(None));
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/json"
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            serde_json::to_value(error_response(json!(7), invalid_request(None))).unwrap()
        );
        let response = jsonrpc_error_http_response(Value::Null, crate::method_not_found("x"));
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn error_response_shape() {
        let r = error_response(json!(1), invalid_request(None));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["error"]["code"], -32600);
    }
}
