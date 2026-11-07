//! HTTP RPC dispatch — JSON-RPC envelope ↔ `perform_action` bridge.
//!
//! Each transport (POST body / GET query string) classifies the
//! envelope via [`fuz_http::classify`], then funnels through one
//! shared dispatch path that calls [`fn@crate::perform_action`].
//!
//! ## What lives here vs `rpc_router.rs`
//!
//! - `rpc_dispatch.rs` (this file) — handler bodies, request → envelope
//!   → `perform_action` plumbing.
//! - `rpc_router.rs` — `create_rpc_router(dispatch) -> Router` factory
//!   that wires the handlers under `GET /rpc` + `POST /rpc` over one
//!   [`ActionDispatch`].
//!
//! ## WS-only specs
//!
//! One registry serves both transports, so `rpc_dispatch` is where a
//! [`crate::ActionSpec::ws_only`] spec is refused: `method_not_found`, before
//! auth, byte-identical **on the wire** to an unregistered method's answer.
//! Not indistinguishable in every channel — refusing ahead of auth skips the
//! credential lookup, so a bearer-carrying request is measurably faster than
//! one that dispatches; the set of WS-only methods is a published protocol
//! constant, so there is nothing for that side channel to disclose.
//! `heartbeat` is the only such spec today.
//!
//! ## The GET transport
//!
//! `GET /rpc` reads `method` / `id` / `params` out of the query string, so
//! [`fuz_http::classify`] never runs and its envelope contracts do not apply.
//! Two rules restore the twin's behavior there: `parse_get_params` reads an
//! explicit `?params=null` as the empty object (the twin's `raw_params ??
//! {}`), and `side_effects_require_post` refuses a
//! [`crate::ActionSpec::side_effects`] method with `-32600`, since the GET
//! half of the endpoint serves reads only.
//!
//! Every response the GET handler writes, its refusals included, carries
//! `Cache-Control: no-store` ([`RPC_GET_CACHE_CONTROL`]): a read answers for
//! one caller at one moment, so no cache — the browser's, a proxy's — may keep
//! it. A refusal ahead of the handler (the stack's origin layer, and the
//! handler's own origin belt, its twin) does not carry it, as on the twin.

use axum::body::Bytes;
use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use fuz_auth::OriginChecked;
use fuz_http::{
    Classified, ClientIp, JsonrpcError, classify, internal_error_with_source, invalid_params,
    invalid_request, jsonrpc_error_http_response, method_not_found, parse_error,
};
use fuz_realtime::{SignalToken, http_no_op_notify, noop_action_peer};
use serde_json::Value;

use crate::action_output::{ActionOutput, write_success_response};
use crate::perform_action::{ActionDispatch, PerformActionInput, perform_action};

/// Which half of `/rpc` a request arrived on.
///
/// The two HTTP verbs differ in one observable way, so the transport is the
/// axis rather than a bare flag: [`RpcTransport::Get`] serves the endpoint's
/// reads and so refuses a
/// [`crate::ActionSpec::side_effects`] method, which is what the TS shim's
/// own `restrict_to_reads` flag expresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RpcTransport {
    /// `GET /rpc` — reads only.
    Get,
    /// `POST /rpc` — the full method surface.
    Post,
}

impl RpcTransport {
    /// Whether this transport refuses a [`crate::ActionSpec::side_effects`]
    /// method with `-32600`.
    #[must_use]
    pub(crate) const fn restricts_to_reads(self) -> bool {
        matches!(self, Self::Get)
    }
}

/// Internal dispatch entry — used by both the POST and GET handlers.
///
/// Pulled out so the request-shape parsing stays in the entry handlers
/// while the cross-transport contract (auth → dispatch → response) is
/// one path. Crate-private, and it takes the handler's `OriginChecked`
/// witness in place of the headers: the credential walk below is entered
/// only through a handler that ran the gate's origin check.
pub(crate) async fn rpc_dispatch(
    dispatch: &ActionDispatch,
    origin: OriginChecked<'_>,
    client_ip: Option<&Extension<ClientIp>>,
    method: &str,
    params: &Value,
    request_id: Value,
    transport: RpcTransport,
) -> Response {
    // One registry lookup serves both transport gates below; the method is
    // resolved again inside `perform_action`, which owns the absent-method
    // answer.
    let spec = dispatch.registry.get(method).map(|entry| &entry.spec);

    // A `ws_only` spec is unreachable over HTTP. Refuse it here, **before**
    // auth, so the wire answer is byte-identical to an unregistered method's
    // for anonymous and authenticated callers alike — a transport restriction
    // must not be an oracle for which methods exist. (Timing still separates
    // the two for a credential-carrying request, since this path skips the
    // token lookup; the WS-only set is a published constant, so there is
    // nothing to learn from that.)
    if spec.is_some_and(|spec| spec.ws_only) {
        return jsonrpc_error_http_response(request_id, method_not_found(method));
    }

    // Read-only transport gate. `GET /rpc` is the reads half of the endpoint,
    // so a `side_effects: true` method is refused here — after the method
    // lookup (an absent method is still `method_not_found`, which wins) and
    // before the credential resolution below, the same phase the TS shim
    // places it at.
    if transport.restricts_to_reads() && spec.is_some_and(|spec| spec.side_effects) {
        return jsonrpc_error_http_response(request_id, side_effects_require_post(method));
    }

    // A failed credential read answers its own 503 (checkout) or 500 (query)
    // rather than dispatching the call as anonymous.
    let resolved = match dispatch
        .gate
        .resolve_credential(
            origin,
            // The bearer leg's `api_token` touch has no skip-the-column form, so an
            // absent `ClientIp` extension records the sentinel rather than erasing.
            ClientIp::as_str_or_unresolved(client_ip),
        )
        .await
    {
        Ok(resolved) => resolved,
        Err(fault) => return fault.into_response(),
    };

    // HTTP has no return socket — a handler reaching for
    // `ctx.request_client` gets `PeerError::NoTransport`.
    let options = dispatch.perform_action_options(noop_action_peer());

    // HTTP signal — fresh per request. WS shares a per-socket token;
    // HTTP can't observe disconnect granularly so a fresh token is
    // fine.
    let signal = SignalToken::new();
    let log = tracing::Span::current();
    let client_ip_value = ClientIp::from_extension(client_ip).map(str::to_owned);

    let input = PerformActionInput {
        method,
        params,
        request_id: &request_id,
        auth: resolved.as_ref(),
        client_ip: client_ip_value,
        connection_id: None,
        notify: &http_no_op_notify,
        signal: &signal,
        log: &log,
    };

    match perform_action(input, &options).await {
        Ok(output) => success_http_response(request_id, &output),
        Err(error) => jsonrpc_error_http_response(request_id, error),
    }
}

/// The HTTP response for a successful dispatch: the success envelope rendered
/// once ([`write_success_response`]) as an `application/json` body — the
/// bytes and content type `Json(success_response(..))` would give. A result
/// that fails to serialize answers `internal_error` (HTTP 500).
fn success_http_response(request_id: Value, output: &ActionOutput) -> Response {
    match write_success_response(&request_id, output) {
        Ok(body) => (
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response(),
        Err(e) => jsonrpc_error_http_response(
            request_id,
            internal_error_with_source("result serialization failed", &e),
        ),
    }
}

// -- POST handler ------------------------------------------------------------

/// Axum handler for `POST /rpc`.
pub async fn rpc_post_handler(
    State(dispatch): State<ActionDispatch>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The gate's origin check — the in-handler half of the belt the stack's
    // `origin_layer` also wears (`fuz_http::compose_stack`).
    let origin = match dispatch.gate.check_origin(&headers) {
        Ok(origin) => origin,
        Err(refused) => return refused,
    };
    // a body a browser could send cross-origin without a preflight is refused
    // whatever the origin allowlist admits — see `fuz_http::simple_request`
    if !fuz_http::is_json_content_type(&headers) {
        return fuz_http::unsupported_content_type_response();
    }

    // decoded as the REST bodies are (`fuz_http::decode_json_text`) — the
    // twin reads both with `c.req.json()`
    let Ok(value) = serde_json::from_str::<Value>(&fuz_http::decode_json_text(&body)) else {
        return jsonrpc_error_http_response(Value::Null, parse_error());
    };

    match classify(&value) {
        Classified::Request { method, id, params } => {
            rpc_dispatch(
                &dispatch,
                origin,
                client_ip.as_ref(),
                method,
                params,
                id,
                RpcTransport::Post,
            )
            .await
        }
        Classified::Invalid { id, error } => jsonrpc_error_http_response(id, error),
        // HTTP issues no server-initiated requests, so an inbound response
        // (`{id, result|error}`) is unexpected — reject like a notification.
        Classified::Notification { .. } | Classified::Response { .. } => {
            jsonrpc_error_http_response(Value::Null, invalid_request(None))
        }
    }
}

// -- GET handler -------------------------------------------------------------

/// The `Cache-Control` every response of `GET /rpc` carries once its origin
/// check passed — a read is per caller and per moment, so nothing may store
/// it. Twin of `fuz_app`'s `RPC_GET_CACHE_CONTROL`.
pub const RPC_GET_CACHE_CONTROL: &str = "no-store";

/// `data.reason` when `GET /rpc` carries no usable `?method=`.
///
/// The literal `fuz_app`'s `action_rpc.ts` sends, so the two backends refuse
/// the same request with the same discriminator.
const REASON_MISSING_METHOD_QUERY_PARAM: &str = "missing method query parameter";

/// `data.reason` when `GET /rpc` carries a `?method=` but no usable `?id=`.
///
/// The twin of [`REASON_MISSING_METHOD_QUERY_PARAM`] for the second half of
/// the query contract.
const REASON_MISSING_ID_QUERY_PARAM: &str = "missing id query parameter";

/// Axum handler for `GET /rpc`. Parses method/id/params from query.
///
/// The query is read as raw pairs through `fuz_http::query_first` — the TS
/// twin reads `method` / `id` / `params` via Hono's first-occurrence-wins
/// `c.req.query()`, so a duplicated key resolves to its first value and
/// unknown keys are ignored — first-occurrence-wins is the contract, so the
/// two backends dispatch the same method on the same request.
pub async fn rpc_get_handler(
    State(dispatch): State<ActionDispatch>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    Query(query_pairs): Query<Vec<(String, String)>>,
) -> Response {
    let origin = match dispatch.gate.check_origin(&headers) {
        Ok(origin) => origin,
        Err(refused) => return refused,
    };
    let mut response = rpc_get_dispatch(&dispatch, origin, client_ip, &query_pairs).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static(RPC_GET_CACHE_CONTROL),
    );
    response
}

/// `GET /rpc` past its origin check: the query contract, then the dispatch.
/// Every response it answers is one [`rpc_get_handler`] marks
/// [`RPC_GET_CACHE_CONTROL`].
async fn rpc_get_dispatch(
    dispatch: &ActionDispatch,
    origin: OriginChecked<'_>,
    client_ip: Option<Extension<ClientIp>>,
    query_pairs: &[(String, String)],
) -> Response {
    // Empty values count as missing — the TS twin's `!value` check treats
    // `?method=` / `?id=` the same as the absent key. Each refusal carries the
    // twin's `data.reason` so a client can tell the two missing halves apart.
    let Some(method) = fuz_http::query_first(query_pairs, "method").filter(|m| !m.is_empty())
    else {
        return jsonrpc_error_http_response(
            Value::Null,
            invalid_request(Some(REASON_MISSING_METHOD_QUERY_PARAM)),
        );
    };
    let Some(id_raw) = fuz_http::query_first(query_pairs, "id").filter(|v| !v.is_empty()) else {
        return jsonrpc_error_http_response(
            Value::Null,
            invalid_request(Some(REASON_MISSING_ID_QUERY_PARAM)),
        );
    };

    let id = parse_get_id(id_raw);

    let params = match parse_get_params(fuz_http::query_first(query_pairs, "params")) {
        Ok(params) => params,
        Err(error) => return jsonrpc_error_http_response(id, error),
    };

    rpc_dispatch(
        dispatch,
        origin,
        client_ip.as_ref(),
        method,
        &params,
        id,
        RpcTransport::Get,
    )
    .await
}

/// Decode a GET `?params=` value into the `params` a handler sees, mapping an
/// explicit `null` to an empty object and passing every other shape through
/// as parsed.
///
/// The mapping is the twin's `raw_params ?? {}` for a non-void input, so a
/// hand-decoded handler reads `?params=null` exactly as `?params={}`. A void
/// input reads either one — and an absent `params`, which reaches the handler
/// as `Value::Null` — as the no-arg call: `fuz_http::require_void_params`
/// accepts `null` and `{}`, as the TS twin's dispatcher does for a `void` input.
///
/// The GET query string is not a JSON-RPC envelope, so [`fuz_http::classify`]
/// never runs over it and its `params` contract (present ⇒ object) is not
/// applied here; the TS twin likewise reads the query parameter with a bare
/// `JSON.parse`. An array, a scalar and a string therefore pass through here
/// and are refused by `perform_action`'s params-shape check — `-32602`
/// `invalid params`, the twin's schema refusal — which runs with input
/// validation, after the authority gates, so an anonymous caller still hears
/// the 401 first, as on the twin. No handler sees a non-object.
///
/// # Errors
///
/// [`invalid_params`] (-32602) when the value is not valid JSON — the same
/// `params query parameter is not valid JSON` the TS twin answers.
fn parse_get_params(raw: Option<&str>) -> Result<Value, JsonrpcError> {
    let Some(raw) = raw else {
        return Ok(Value::Null);
    };
    let value: Value = serde_json::from_str(raw)
        .map_err(|_| invalid_params("params query parameter is not valid JSON", None))?;
    Ok(if value.is_null() {
        Value::Object(serde_json::Map::new())
    } else {
        value
    })
}

/// The `-32600` a [`crate::ActionSpec::side_effects`] method answers over
/// `GET /rpc`.
///
/// Wire twin of the TS shim's refusal: `message` is the canonical `"invalid
/// request"` and `data.reason` carries the method name, so a caller reading
/// either backend's envelope gets the same instruction.
fn side_effects_require_post(method: &str) -> JsonrpcError {
    invalid_request(Some(&format!(
        "method '{method}' has side effects and must use POST"
    )))
}

/// Normalize a GET `?id=` value the way the TS twin does: numeric only when
/// `String(Number(raw)) === raw` with an integral value — so `42` / `0` /
/// `-1` come back as JSON numbers while `042`, `+5`, `3.14`, `1e5`, and
/// integers that don't survive the f64 round-trip (e.g. 2^53 + 1) stay
/// strings, matching `GET ?id=42` to `POST {id: 42}` behavior on both
/// backends. (Residue: an integer beyond i64 range that IS f64-exact, e.g.
/// 10^19, stays a string here but is numeric on TS — unreachable for the
/// monotonic small-int ids every shipped client generates.)
fn parse_get_id(id_raw: &str) -> Value {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "the lossy f64 round-trip is the point — it mirrors the TS Number() check"
    )]
    const fn f64_round_trips(n: i64) -> bool {
        (n as f64) as i64 == n
    }
    match id_raw.parse::<i64>() {
        Ok(n) if n.to_string() == id_raw && f64_round_trips(n) => Value::Number(n.into()),
        _ => Value::String(id_raw.to_owned()),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]
mod get_transport_tests {
    use serde_json::json;

    use super::*;

    /// The two GET query-contract refusals carry the twin's own
    /// discriminators, so a client can tell a missing `?method=` from a
    /// missing `?id=` on either backend rather than reading one bare
    /// `invalid request` for both.
    #[test]
    fn the_missing_query_param_reasons_are_the_ts_literals() {
        assert_eq!(
            REASON_MISSING_METHOD_QUERY_PARAM,
            "missing method query parameter"
        );
        assert_eq!(REASON_MISSING_ID_QUERY_PARAM, "missing id query parameter");

        for reason in [
            REASON_MISSING_METHOD_QUERY_PARAM,
            REASON_MISSING_ID_QUERY_PARAM,
        ] {
            let error = invalid_request(Some(reason));
            assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidRequest);
            assert_eq!(error.message, "invalid request");
            assert_eq!(error.data, Some(json!({"reason": reason})));
        }
    }

    #[test]
    fn canonical_integers_are_numeric() {
        assert_eq!(parse_get_id("42"), Value::Number(42.into()));
        assert_eq!(parse_get_id("0"), Value::Number(0.into()));
        assert_eq!(parse_get_id("-1"), Value::Number((-1).into()));
    }

    #[test]
    fn non_canonical_and_non_integral_forms_stay_strings() {
        // each pins a TS `String(Number(raw)) !== raw` case
        assert_eq!(parse_get_id("042"), Value::String("042".into()));
        assert_eq!(parse_get_id("+5"), Value::String("+5".into()));
        assert_eq!(parse_get_id("3.14"), Value::String("3.14".into()));
        assert_eq!(parse_get_id("1e5"), Value::String("1e5".into()));
        assert_eq!(parse_get_id("abc-123"), Value::String("abc-123".into()));
    }

    #[test]
    fn integers_past_f64_precision_stay_strings() {
        // 2^53 + 1 doesn't survive the TS Number() round-trip
        assert_eq!(
            parse_get_id("9007199254740993"),
            Value::String("9007199254740993".into())
        );
        // 2^53 itself does
        assert_eq!(
            parse_get_id("9007199254740992"),
            Value::Number(9_007_199_254_740_992_i64.into())
        );
    }

    /// An **absent** `?params=` stays `Value::Null`, while an explicit
    /// `?params=null` becomes `{}` — the empty object the TS twin's
    /// `raw_params ?? {}` gives a non-void input.
    #[test]
    fn an_explicit_null_reads_as_the_empty_object() {
        assert_eq!(parse_get_params(None).unwrap(), Value::Null);
        assert_eq!(parse_get_params(Some("null")).unwrap(), json!({}));
        assert_eq!(parse_get_params(Some("{}")).unwrap(), json!({}));
    }

    /// Every other shape passes through as parsed. The GET query string is not
    /// an envelope, so `classify`'s present-⇒-object contract does not apply:
    /// the TS twin forwards the `JSON.parse` result unchanged, and the
    /// dispatcher's params-shape check refuses a non-object at input
    /// validation, behind the authority gates.
    #[test]
    fn non_object_params_pass_through_to_the_dispatcher() {
        assert_eq!(parse_get_params(Some("[1]")).unwrap(), json!([1]));
        assert_eq!(parse_get_params(Some("1")).unwrap(), json!(1));
        assert_eq!(parse_get_params(Some("\"x\"")).unwrap(), json!("x"));
        assert_eq!(
            parse_get_params(Some("{\"a\":1}")).unwrap(),
            json!({"a": 1})
        );
    }

    #[test]
    fn unparseable_params_are_invalid_params() {
        let error = parse_get_params(Some("{oops")).unwrap_err();
        assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);
        assert_eq!(error.message, "params query parameter is not valid JSON");
    }

    /// The read-only gate's envelope, character for character with the TS
    /// twin's `jsonrpc_error_messages.invalid_request({reason})`.
    #[test]
    fn the_read_only_gate_names_the_method_and_the_verb() {
        let error = side_effects_require_post("account_session_revoke_all");
        assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidRequest);
        assert_eq!(error.message, "invalid request");
        assert_eq!(
            error.data.expect("carries a reason")["reason"],
            "method 'account_session_revoke_all' has side effects and must use POST"
        );
        assert_eq!(fuz_http::error_code_to_http_status(error.code), 400);
    }
}
