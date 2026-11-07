//! `fuz_http` — HTTP framework primitives for the fuz spine.
//!
//! Twin of `fuz_app`'s TypeScript `http/` subsystem (JSON-RPC envelopes +
//! error taxonomy, the flat-REST error bodies in `rest_error`, origin
//! verification, the CORS simple-request gate, trusted-proxy + XFF
//! resolution, body-size limits, the raw-query helpers in `query`, the
//! JSON-body decoder in `json_body`, readiness + lifecycle, request
//! tracing); the twins converge on the better shape and match observably
//! (this side canonicalizes IPv6). The origin allowlist grammar is shared
//! with the TS twin entry for entry. `host` (the DNS-rebinding gate) has no
//! TS twin yet.
//!
//! An input-validation refusal ([`invalid_input_params`]) answers the generic
//! `invalid params` and logs what was refused at `debug`
//! (`RUST_LOG=fuz_http=debug`); that log line can include raw input values.
//!
//! ## Public surface
//!
//! Modules are deep-importable; `lib.rs` only re-exports the canonical
//! API. A server assembles its router through [`compose_stack`] — the one
//! composition root, which owns the layer order and the defaults — and
//! composes `axum::Router`s with the other primitives inside its groups. The
//! result is a [`GatedRouter`], closed to further routes or layers, and
//! [`serve_with_shutdown`] serves nothing else.
//!
//! ## Mount ordering
//!
//! [`compose_stack`] applies the layers in one fixed order, outermost first —
//! the order a request meets them:
//!
//! ```text
//! request_tracing_layer → per group: body cap → host_layer → origin_layer
//!     → simple_request_layer → client_ip_middleware → handler
//! ```
//!
//! Tracing is outermost so a refusal from any layer below is logged like any
//! other response. The body cap comes ahead of the origin check in every
//! route group, as on the TS spine: a declared `Content-Length` over the
//! group's cap answers `413` whatever the request's origin or credentials (a
//! body with no declared length is still refused, but which refusal wins is
//! implementation-defined — see [`body_limit`]). Host and origin reject
//! requests from foreign pages before any per-request work; the origin check
//! covers every group, the fallback included, unless a group is carved out by
//! name with a reason (the fallback group never can be). `host_layer` is
//! on by default and off through [`StackOptions::host_gate`] (see [`host`]'s
//! module doc), tracing is on by default and off through
//! [`StackOptions::request_tracing`], and `simple_request_layer` is a
//! per-group opt-in ([`RouteGroup::refuse_simple_requests`]) that fits only
//! groups with no form or multipart uploads — the spine's own JSON handlers
//! check their content type themselves.
//! `client_ip_middleware` populates the `ClientIp` extension every handler
//! downstream relies on (rate limiter keys, audit rows); no layer above it
//! reads it. The detail is [`stack`]'s module doc.
//!
//! ## `RouteSpec` / `AppSurface` intentionally absent
//!
//! `fuz_app`'s data-driven `RouteSpec` doesn't port to Rust. `axum`'s
//! `Router` + typed extractors achieve the declarative shape natively.
//! `AppSurface` (runtime route-walker) is deferred — no Rust consumer
//! needs runtime surface introspection today; revisit when one does.

// === trusted proxy + IP ===
pub mod ip_canonical;
pub mod ip_resolve;
pub mod parsed_proxy;
pub mod proxy;

// === request-source verification: origin, host, CORS simple requests ===
pub mod host;
pub mod origin;
pub mod origin_wildcard;
pub mod simple_request;

// === JSON-RPC envelope + errors ===
pub mod jsonrpc;
pub mod jsonrpc_error;

// === hand-decoded params: field helpers, wire-UUID grammar, the input shape ===
pub mod params;

// === strict typed-params decoding (the `optional`-refuses-null half) ===
pub mod strict_params;

// === flat-REST error responses ===
pub mod rest_error;

// === query-string shape (TS-twin duplicate/unknown-key semantics) ===
pub mod query;

// === JSON request bodies (TS-twin `invalid_json_body` / `invalid_request_body`) ===
pub mod json_body;

// === JS `trim` whitespace, for inputs the TS twin trims ===
pub mod js_whitespace;

// === request body size limit ===
pub mod body_limit;

// === readiness probe (schema-drift deploy gate) ===
pub mod ready;

// === graceful-shutdown lifecycle ===
pub mod lifecycle;

// === server env ===
pub mod server_env;

// === request tracing ===
pub mod tracing_layer;

// === the composition root: route groups behind the gates, in one order ===
pub mod stack;

// -- Public API re-exports ---------------------------------------------------

pub use body_limit::DEFAULT_BODY_LIMIT_BYTES;
pub use host::{
    FORBIDDEN_HOST_REASON, HOST_REFUSAL_WARN_INTERVAL, HostGate, forbidden_host_response,
    format_host_refusal_warning, host_layer, is_loopback_host,
};
pub use ip_canonical::{IpFamily, normalize_ip, rate_limit_ip_key, validate_ip_strict};
pub use ip_resolve::{
    ClientIp, UNRESOLVED_CLIENT_IP, client_ip_middleware, forwarded_for_value, resolve_client_ip,
};
pub use js_whitespace::trim_js_whitespace;
pub use json_body::{SAFE_INTEGER_MAX, decode_json_text, parse_json_body};
pub use jsonrpc::{
    Classified, JSONRPC_VERSION, JsonrpcErrorResponse, JsonrpcNotification, JsonrpcRequest,
    JsonrpcResponse, NULL_PARAMS, classify, error_response, jsonrpc_error_http_response,
    notification, request_frame, success_response,
};
pub use jsonrpc_error::{
    BASE_JSONRPC_ERROR_CODES, ConsumerErrorCode, DB_UNAVAILABLE_MESSAGE, INVALID_PARAMS_MESSAGE,
    JsonrpcError, JsonrpcErrorCode, UnknownJsonrpcErrorCode, conflict, consumer_error,
    db_unavailable, db_unavailable_with_source, error_code_to_http_status, forbidden,
    internal_error, internal_error_with_source, invalid_input_params, invalid_params,
    invalid_request, method_not_found, not_found, parse_error, queue_overflow, rate_limited,
    request_cancelled, service_unavailable, timeout, unauthenticated, validation_error,
};
pub use lifecycle::{
    CancellationToken, DEFAULT_DRAIN_TIMEOUT, HEADER_READ_TIMEOUT, NoopShutdownCloser,
    SHUTDOWN_CLOSE_TIMEOUT, ShutdownCloser, WRITE_PROGRESS_TIMEOUT, WaitClosedFuture,
    serve_with_shutdown, shutdown_token, spawn_periodic,
};
pub use origin::{
    ALLOWED_ORIGINS_SEPARATOR, AllowedOrigins, AllowedOriginsError, AllowedOriginsErrors,
    FORBIDDEN_ORIGIN_REASON, HostWildcard, OriginPattern, OriginPatternError, OriginWildcard,
    forbidden_origin_response, origin_layer,
};
pub use origin_wildcard::{
    ALLOW_ORIGIN_WILDCARDS_VAR, OriginWildcardOptions, admit_origin_wildcards,
    origin_wildcard_warning, parse_allow_origin_wildcards,
};
pub use params::{
    ERROR_PARAMS_NUL, ERROR_PARAMS_PROTO_KEY, InputShape, JsonValueScan, as_integral_i64,
    deserialize_nullish_wire_int, deserialize_nullish_wire_uuid, deserialize_optional_wire_int,
    deserialize_optional_wire_uuid, deserialize_optional_wire_uuid_vec, deserialize_wire_int,
    deserialize_wire_uuid, deserialize_wire_uuid_vec, is_valid_uuid, parse_optional_bool_param,
    parse_optional_enum_param, parse_optional_i64_param, parse_optional_str_param,
    parse_optional_uuid_param, parse_str_param, parse_uuid_param, reject_null_keys,
    reject_unknown_keys, require_void_params, scan_json_value, serialize_result,
};
pub use parsed_proxy::{ParsedProxy, ProxyParseError};
pub use proxy::{is_trusted_ip, parse_proxy_entry, parse_proxy_list};
pub use query::{assert_known_query_keys, query_first};
pub use ready::{ReadyRouteState, ready_router};
pub use rest_error::{
    AUTHENTICATION_REQUIRED_REASON, INSUFFICIENT_PERMISSIONS_REASON, INTERNAL_ERROR_REASON,
    INVALID_JSON_BODY_REASON, INVALID_QUERY_PARAMS_REASON, INVALID_REQUEST_BODY_REASON,
    INVALID_ROUTE_PARAMS_REASON, PAYLOAD_TOO_LARGE_REASON, SERVICE_UNAVAILABLE_REASON,
    authentication_required_response, db_unavailable_response, db_unavailable_response_with_source,
    insufficient_permissions_response, internal_error_response,
    internal_error_response_with_source, invalid_json_body_response, invalid_query_params_response,
    invalid_request_body_response, invalid_route_params_response, payload_too_large_response,
    rest_error_response,
};
pub use server_env::{
    ALLOWED_ORIGINS_VAR, BaseServerEnv, DB_AUDIT_CHECKOUT_TIMEOUT_VAR, DB_CHECKOUT_TIMEOUT_MAX_MS,
    DB_CHECKOUT_TIMEOUT_VAR, DEFAULT_TRUSTED_PROXIES, ServerEnvError, ServerEnvOptions,
    parse_checkout_timeout,
};
pub use simple_request::{
    UNSUPPORTED_CONTENT_TYPE_REASON, is_cors_simple_content_type, is_json_content_type,
    simple_request_layer, unsupported_content_type_response,
};
pub use stack::{BodyCap, GatedRouter, OriginScope, RouteGroup, StackOptions, compose_stack};
pub use strict_params::{parse_strict_params, parse_strict_params_allowing_null};
pub use tracing_layer::request_tracing_layer;
