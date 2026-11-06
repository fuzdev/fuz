//! JSON-RPC 2.0 error taxonomy + envelope.
//!
//! Canonical error type for the spine — mirrors `fuz_app`'s
//! `http/jsonrpc_errors.ts` taxonomy (the standard JSON-RPC 2.0 codes
//! plus the ecosystem extensions in the `-32099..=-32000` server-error
//! range), and a consumer's own codes declared on top of it
//! ([`ConsumerErrorCode`], built with [`consumer_error`]).
//!
//! ## Wire shape (stable)
//!
//! ```json
//! {"code": -32603, "message": "internal error", "data": "..."}
//! ```
//!
//! `data` is omitted from the wire when `None` (serde's
//! `skip_serializing_if`). The struct is consumed only over JSON-HTTP
//! today; if a future transport routes it over postcard (e.g. fuzd's
//! UDS), drop the `skip_serializing_if` — postcard can't represent the
//! skipped field.
//!
//! ## Reason-bearing constructors
//!
//! Some constructors carry the `reason: Option<&str>` shape that
//! sets `data: {reason: "..."}` when `Some`: [`not_found`],
//! [`conflict`], [`forbidden`], [`invalid_params`], [`invalid_request`].
//! Mirrors `fuz_app`'s `jsonrpc_errors.<name>(message, {reason})`
//! pattern. Action-spec handlers wire the reason from a per-handler
//! `ERROR_*` constant; consumers pattern-match `data.reason` to
//! discriminate failure causes within a single status code.
//! They all take the reason as a trailing `Option<&str>`, so every
//! callsite constructs reasons the same way.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use axum::http::StatusCode;

/// JSON-RPC 2.0 error.
///
/// Matches `fuz_app`'s `JsonrpcErrorObject`. Stable wire shape — `zzz`
/// and `fuz_app` integration tests assert on `code` / `message` / `data` directly.
/// `code` is a [`JsonrpcErrorCode`] that serializes as the bare `i32` the
/// wire contract requires.
#[derive(Debug, Clone, Serialize, thiserror::Error)]
#[error("jsonrpc error {code}: {message}")]
pub struct JsonrpcError {
    pub code: JsonrpcErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// -- Error codes --------------------------------------------------------------

/// JSON-RPC 2.0 error code — the `code` values the spine emits.
///
/// The standard JSON-RPC 2.0 codes plus the ecosystem extensions in the
/// `-32099..=-32000` server-error range — the base set, twin of `fuz_app`'s
/// `JSONRPC_ERROR_CODES` — and [`Consumer`](Self::Consumer), a code a
/// consumer declares on top of it ([`ConsumerErrorCode`]). Modeled as an
/// enum rather than scattered `pub const … : i32` so
/// [`error_code_to_http_status`] is an exhaustive match — a new base code is
/// a compile error there, not a silent `500` fallthrough — and
/// [`JsonrpcError`]'s `code` field cannot hold a value outside the contract:
/// a consumer code carries the HTTP status it was declared with.
///
/// The wire representation is the bare `i32` the JSON-RPC contract
/// requires: [`JsonrpcError`] serializes `code` through this enum's
/// `Serialize` impl ([`as_i32`](Self::as_i32)), so the byte shape is
/// unchanged. `TryFrom<i32>` recovers a base-set variant from a wire value
/// (returning [`UnknownJsonrpcErrorCode`] for anything else, a consumer's
/// code included, since the wire carries no status) — the non-panicking
/// boundary a future deserialize path would use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonrpcErrorCode {
    // -- Standard JSON-RPC 2.0 codes --
    /// `-32700`.
    ParseError,
    /// `-32600`.
    InvalidRequest,
    /// `-32601`.
    MethodNotFound,
    /// `-32602`.
    InvalidParams,
    /// `-32603`.
    InternalError,

    // -- General application extensions (-32000 to -32099) --
    /// `-32001`. Same as HTTP 401 "unauthorized", but correctly named.
    Unauthenticated,
    /// `-32002`. Named to match HTTP 403 — avoids confusion with 401's HTTP
    /// misnomer.
    Forbidden,
    /// `-32003`.
    NotFound,
    /// `-32004`.
    Conflict,
    /// `-32005`. Application-level validation failures (business logic). Use
    /// [`InvalidParams`](Self::InvalidParams) (-32602) for schema/parsing
    /// failures.
    ValidationError,
    /// `-32006`.
    RateLimited,
    /// `-32007`.
    ServiceUnavailable,
    /// `-32008`.
    Timeout,
    /// `-32009`. Client-side backpressure — an outbound buffer refused a new
    /// request because it was full. Distinct from
    /// [`RateLimited`](Self::RateLimited) (server-side policy).
    QueueOverflow,
    /// `-32010`. Caller-initiated cancellation (e.g. `AbortSignal` fired).
    RequestCancelled,

    // -- Consumer-declared codes --
    /// A code a consumer declares on top of the base set, with its HTTP
    /// status (see [`ConsumerErrorCode`]).
    Consumer(ConsumerErrorCode),
}

/// Every base-set code — what `TryFrom<i32>` recovers, and the numbers a
/// [`ConsumerErrorCode`] may not reuse.
pub const BASE_JSONRPC_ERROR_CODES: [JsonrpcErrorCode; 15] = [
    JsonrpcErrorCode::ParseError,
    JsonrpcErrorCode::InvalidRequest,
    JsonrpcErrorCode::MethodNotFound,
    JsonrpcErrorCode::InvalidParams,
    JsonrpcErrorCode::InternalError,
    JsonrpcErrorCode::Unauthenticated,
    JsonrpcErrorCode::Forbidden,
    JsonrpcErrorCode::NotFound,
    JsonrpcErrorCode::Conflict,
    JsonrpcErrorCode::ValidationError,
    JsonrpcErrorCode::RateLimited,
    JsonrpcErrorCode::ServiceUnavailable,
    JsonrpcErrorCode::Timeout,
    JsonrpcErrorCode::QueueOverflow,
    JsonrpcErrorCode::RequestCancelled,
];

impl JsonrpcErrorCode {
    /// The bare `i32` wire value for this code.
    #[inline]
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::Unauthenticated => -32001,
            Self::Forbidden => -32002,
            Self::NotFound => -32003,
            Self::Conflict => -32004,
            Self::ValidationError => -32005,
            Self::RateLimited => -32006,
            Self::ServiceUnavailable => -32007,
            Self::Timeout => -32008,
            Self::QueueOverflow => -32009,
            Self::RequestCancelled => -32010,
            Self::Consumer(code) => code.code,
        }
    }
}

impl From<ConsumerErrorCode> for JsonrpcErrorCode {
    fn from(code: ConsumerErrorCode) -> Self {
        Self::Consumer(code)
    }
}

impl std::fmt::Display for JsonrpcErrorCode {
    /// Renders the numeric wire code (e.g. `-32602`) — the JSON-RPC
    /// convention, and what [`JsonrpcError`]'s `Display` interpolates.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_i32())
    }
}

impl Serialize for JsonrpcErrorCode {
    /// Serializes as the bare `i32` — the wire contract the cross-backend
    /// parity tests assert byte-for-byte.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(self.as_i32())
    }
}

/// Returned by `TryFrom<i32>` for [`JsonrpcErrorCode`] when the integer is
/// not one of the spine's base-set codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown JSON-RPC error code: {0}")]
pub struct UnknownJsonrpcErrorCode(pub i32);

impl TryFrom<i32> for JsonrpcErrorCode {
    type Error = UnknownJsonrpcErrorCode;

    fn try_from(code: i32) -> Result<Self, Self::Error> {
        BASE_JSONRPC_ERROR_CODES
            .into_iter()
            .find(|base| base.as_i32() == code)
            .ok_or(UnknownJsonrpcErrorCode(code))
    }
}

// -- Consumer-declared codes --------------------------------------------------

/// A JSON-RPC error code a consumer declares on top of the base set, with
/// the HTTP status it answers.
///
/// Twin of how a `fuz_app` consumer extends the TS taxonomy: it spreads
/// `JSONRPC_ERROR_CODES` into its own object with a new code
/// (`ai_provider_error: -32020`) and registers its status with
/// `register_jsonrpc_error_code(-32020, 502)`. Here the two are one value,
/// declared once as a `const`:
///
/// ```
/// use axum::http::StatusCode;
/// use fuz_http::{ConsumerErrorCode, consumer_error};
///
/// pub const AI_PROVIDER_ERROR: ConsumerErrorCode =
///     ConsumerErrorCode::new(-32020, StatusCode::BAD_GATEWAY);
///
/// let error = consumer_error(AI_PROVIDER_ERROR, "claude: needs API key", None);
/// assert_eq!(error.code.as_i32(), -32020);
/// ```
///
/// [`new`](Self::new) holds a declaration to the rules
/// `register_jsonrpc_error_code` checks at runtime on the TS side: the code
/// is a new number (a base-set number would remap a base code), it sits in
/// the `-32099..=-32000` range reserved for application codes, and it
/// answers a 4xx or 5xx. Declared as a `const`, a refused code is a compile
/// error. The fields are private, so every value passed those
/// checks.
///
/// ```compile_fail,E0080
/// use axum::http::StatusCode;
/// use fuz_http::ConsumerErrorCode;
///
/// // -32003 is the base set's `not_found`
/// const SHADOW: ConsumerErrorCode = ConsumerErrorCode::new(-32003, StatusCode::BAD_GATEWAY);
/// let _ = SHADOW;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumerErrorCode {
    code: i32,
    http_status: StatusCode,
}

impl ConsumerErrorCode {
    /// Declare a consumer error code answering `http_status`.
    ///
    /// # Panics
    ///
    /// When `code` is a base-set code ([`BASE_JSONRPC_ERROR_CODES`]) or
    /// outside `-32099..=-32000`, or `http_status` isn't a 4xx or 5xx —
    /// at compile time when the value is a `const`.
    #[must_use]
    pub const fn new(code: i32, http_status: StatusCode) -> Self {
        assert!(
            code >= -32099 && code <= -32000,
            "a consumer JSON-RPC error code must be in -32099..=-32000"
        );
        let mut i = 0;
        while i < BASE_JSONRPC_ERROR_CODES.len() {
            assert!(
                BASE_JSONRPC_ERROR_CODES[i].as_i32() != code,
                "a consumer JSON-RPC error code may not reuse a base-set code"
            );
            i += 1;
        }
        let status = http_status.as_u16();
        assert!(
            status >= 400 && status <= 599,
            "a consumer JSON-RPC error code must answer a 4xx or 5xx status"
        );
        Self { code, http_status }
    }

    /// The bare `i32` wire value.
    #[inline]
    #[must_use]
    pub const fn code(self) -> i32 {
        self.code
    }

    /// The HTTP status the code answers.
    #[inline]
    #[must_use]
    pub const fn http_status(self) -> StatusCode {
        self.http_status
    }
}

// -- Constructors -------------------------------------------------------------
//
// `#[cold]` on every constructor — these are error paths, instruct LLVM
// to skip inlining them on the hot path.
//
// `data: None` by default — `fuz_app`'s TS includes Zod validation issues
// in `invalid_params.data`, which can leak schema info to unauthenticated
// callers. Rust ships `None` and lets the caller opt in via the explicit
// variants when the data is safe to disclose (e.g. internal_error with a
// debug string).

#[cold]
#[must_use]
pub fn parse_error() -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::ParseError,
        message: "parse error".to_owned(),
        data: None,
    }
}

/// Build an `invalid_request` JSON-RPC error.
///
/// Wire shape mirrors `fuz_app`'s `jsonrpc_errors.invalid_request({reason})`:
/// fixed `message = "invalid request"`, `data = {reason}` when `Some`.
#[cold]
#[must_use]
pub fn invalid_request(reason: Option<&str>) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::InvalidRequest,
        message: "invalid request".to_owned(),
        data: reason.map(|r| serde_json::json!({"reason": r})),
    }
}

#[cold]
#[must_use]
pub fn method_not_found(method: &str) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::MethodNotFound,
        message: format!("method not found: {method}"),
        data: None,
    }
}

/// Build an `invalid_params` JSON-RPC error.
///
/// Wire shape mirrors `fuz_app`'s `jsonrpc_errors.invalid_params(detail,
/// {reason})`. Caller controls the message; `data.reason` is the
/// machine-readable discriminator (omitted on `None`).
#[cold]
#[must_use]
pub fn invalid_params(detail: &str, reason: Option<&str>) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::InvalidParams,
        message: detail.to_owned(),
        data: reason.map(|r| serde_json::json!({"reason": r})),
    }
}

/// The message every input-validation refusal answers: what `fuz_app`'s
/// dispatcher sends when an action's input schema refuses its params.
pub const INVALID_PARAMS_MESSAGE: &str = "invalid params";

/// Build the `invalid_params` an **input-validation** refusal answers — a
/// check the TS twin makes in the action's input schema rather than in its
/// handler.
///
/// The wire carries the generic [`INVALID_PARAMS_MESSAGE`], as on the twin,
/// which never names the field or the rule a schema refused. `detail` goes to a
/// `tracing::debug!` line instead, so the cause is kept for debugging without
/// describing the input shape to the caller. `reason` is the machine-readable
/// discriminator, sent as `data.reason` when given. A handler-level refusal the
/// twin also answers with its own message uses [`invalid_params`].
#[cold]
#[must_use]
pub fn invalid_input_params(detail: &str, reason: Option<&str>) -> JsonrpcError {
    tracing::debug!(detail, reason, "invalid params");
    invalid_params(INVALID_PARAMS_MESSAGE, reason)
}

/// Parse JSON-RPC `params` into a typed input, mapping a deserialize failure to
/// [`invalid_input_params`] (`-32602`).
///
/// The bare typed-params decode under [`crate::parse_strict_params`], which
/// handlers call: a `#[derive(Deserialize)]` input struct decoded through it
/// rather than per-field `params.get().and_then(Value::as_*)` chains.
///
/// `params` is **object-or-null** here, the handler half of a two-layer
/// contract the TS twin splits the same way:
///
/// 1. The **envelope** (`fuz_http::jsonrpc::classify`, twin of
///    `JsonrpcRequest.params: z.looseObject({}).optional()`) admits
///    `params` absent or an object, and refuses a present non-object —
///    explicit `null`, an array, a scalar — as `invalid_request`
///    (`-32600`) before dispatch. An absent `params` arrives here as
///    `Value::Null`.
/// 2. **This function** turns that `Null` into `{}`, which *is* the TS
///    dispatcher's `raw_params ?? {}`, so an all-optional input needs no
///    caller-side `is_null()` branch.
///
/// The non-object guard below is therefore defense for **direct callers**
/// that bypass the classifier — the GET query-string path, unit tests,
/// peer frames — not a second envelope check; on a classified transport it
/// is unreachable. It matters because serde fills a derived struct's named
/// fields *positionally* from a sequence, a path
/// `#[serde(deny_unknown_fields)]` does not guard, so without it a
/// positional array would smuggle values past the strict-object contract
/// the TS twin enforces.
///
/// # Errors
///
/// [`invalid_input_params`] when `params` is a non-null non-object, or when it
/// doesn't deserialize into `T`.
pub(crate) fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, JsonrpcError> {
    let params = match params {
        Value::Null => Value::Object(serde_json::Map::new()),
        p @ Value::Object(_) => p,
        _ => {
            return Err(invalid_input_params("params must be an object", None));
        }
    };
    serde_json::from_value(params)
        .map_err(|e| invalid_input_params(&format!("params do not deserialize: {e}"), None))
}

#[cold]
#[must_use]
pub fn internal_error(detail: &str) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::InternalError,
        message: detail.to_owned(),
        data: None,
    }
}

/// Build an `internal_error` AND log the source error's cause chain at `error`
/// level — every caller is a server fault the client can't fix, as the TS
/// twin logs an unhandled handler error with `log.error`.
///
/// Used at handler boundaries that map a `tokio_postgres::Error` /
/// `serde_json::Error` etc. into the client-facing `-32603` envelope.
/// Logging the underlying cause keeps operators able to debug "X
/// failed" from logs while clients see only the opaque message. The log
/// carries [`fuz_sys::cli::format_error_chain`], not the error's `Display`:
/// a `tokio_postgres::Error` (and `fuz_db::DbError`) prints only its kind,
/// and Postgres's message, DETAIL, and HINT are reachable only through
/// `source()`. The chain's text omits the SQLSTATE, so the first
/// `tokio_postgres::Error` link's code, when present, is logged as its own
/// `sqlstate` field ([`fuz_db::sqlstate_in_chain`]). A caller with no error
/// value logs on its own and uses [`internal_error`].
///
/// Takes `&dyn Error` not generics to keep monomorphization off the
/// many call sites — the dynamic dispatch is one indirect call vs.
/// dozens of inlined formatter bodies.
#[cold]
#[must_use]
pub fn internal_error_with_source(
    detail: &str,
    error: &(dyn std::error::Error + 'static),
) -> JsonrpcError {
    tracing::error!(
        error = %fuz_sys::cli::format_error_chain(error),
        sqlstate = fuz_db::sqlstate_in_chain(error),
        "{detail}"
    );
    JsonrpcError {
        code: JsonrpcErrorCode::InternalError,
        message: detail.to_owned(),
        data: None,
    }
}

/// Build an `unauthenticated` (401) JSON-RPC error.
///
/// Carries `data.reason = "authentication_required"` — the canonical 401
/// reason, symmetric with the 403 [`forbidden`] shape — so a caller can
/// assert on the reason, not just the status. The single source of truth
/// for the unauthenticated wire shape across every emit site (the action
/// dispatcher's pre-validation gate and the handler-side `ctx.auth`
/// defensive re-checks). Mirrors `fuz_app`'s `ERROR_AUTHENTICATION_REQUIRED`.
#[cold]
#[must_use]
pub fn unauthenticated() -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::Unauthenticated,
        message: "unauthenticated".to_owned(),
        data: Some(serde_json::json!({ "reason": "authentication_required" })),
    }
}

/// Build a `forbidden` JSON-RPC error.
///
/// Mirrors `fuz_app`'s `jsonrpc_errors.forbidden(message, {reason})` —
/// parallels [`conflict`] / [`not_found`] shape.
#[cold]
#[must_use]
pub fn forbidden(message: &str, reason: Option<&str>) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::Forbidden,
        message: message.to_owned(),
        data: reason.map(|r| serde_json::json!({"reason": r})),
    }
}

/// Build a `not_found` JSON-RPC error.
///
/// Wire shape matches `fuz_app`'s `jsonrpc_errors.not_found(resource,
/// {reason})`:
/// - `message = "{resource} not found"`
/// - `data = {reason}` when `reason` is `Some`; omitted otherwise
#[cold]
#[must_use]
pub fn not_found(resource: &str, reason: Option<&str>) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::NotFound,
        message: format!("{resource} not found"),
        data: reason.map(|r| serde_json::json!({"reason": r})),
    }
}

/// Build a `conflict` JSON-RPC error.
///
/// Wire shape matches `fuz_app`'s `jsonrpc_errors.conflict(message,
/// {reason})`:
/// - `message` is the caller-supplied conflict description
/// - `data = {reason}` when `reason` is `Some`; omitted otherwise
///
/// Mirrors [`not_found`]'s shape — both carry a `data.reason`
/// discriminator so consumers can pattern-match on the conflict cause.
#[cold]
#[must_use]
pub fn conflict(message: &str, reason: Option<&str>) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::Conflict,
        message: message.to_owned(),
        data: reason.map(|r| serde_json::json!({"reason": r})),
    }
}

#[cold]
#[must_use]
pub fn validation_error(message: &str) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::ValidationError,
        message: message.to_owned(),
        data: None,
    }
}

/// JSON-RPC `-32006` (rate limited) constructor.
///
/// `data` carries a
/// caller-defined payload — typically `Some(json!({"retry_after": N}))`
/// so consumers know how long to wait before retrying. Mirrors TS
/// `jsonrpc_error_messages.rate_limited('rate limited', {retry_after})`.
#[cold]
#[must_use]
pub fn rate_limited(message: &str, data: Option<Value>) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::RateLimited,
        message: message.to_owned(),
        data,
    }
}

#[cold]
#[must_use]
pub fn service_unavailable(message: &str) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::ServiceUnavailable,
        message: message.to_owned(),
        data: None,
    }
}

/// The message every pool-checkout failure answers with, on both twins.
pub const DB_UNAVAILABLE_MESSAGE: &str = "database unavailable";

/// The JSON-RPC answer to a failed pool checkout.
///
/// `service_unavailable` (-32007, HTTP 503) with [`DB_UNAVAILABLE_MESSAGE`]
/// and no `data`. A failed
/// query on a client already checked out keeps its `internal_error`. Twin of
/// the TS `to_thrown_jsonrpc_error` arm for a `DbCheckoutError`.
#[cold]
#[must_use]
pub fn db_unavailable() -> JsonrpcError {
    service_unavailable(DB_UNAVAILABLE_MESSAGE)
}

/// Log a failed pool checkout's cause chain (and `sqlstate`, when present)
/// at `error` and answer [`db_unavailable`] — the request-surface twin of
/// [`internal_error_with_source`] for the checkout phase.
#[cold]
#[must_use]
pub fn db_unavailable_with_source(
    detail: &str,
    error: &(dyn std::error::Error + 'static),
) -> JsonrpcError {
    tracing::error!(
        error = %fuz_sys::cli::format_error_chain(error),
        sqlstate = fuz_db::sqlstate_in_chain(error),
        "{detail}"
    );
    db_unavailable()
}

#[cold]
#[must_use]
pub fn timeout(message: &str) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::Timeout,
        message: message.to_owned(),
        data: None,
    }
}

#[cold]
#[must_use]
pub fn queue_overflow(message: &str) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::QueueOverflow,
        message: message.to_owned(),
        data: None,
    }
}

#[cold]
#[must_use]
pub fn request_cancelled(message: &str) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::RequestCancelled,
        message: message.to_owned(),
        data: None,
    }
}

/// Build an error with a consumer-declared code ([`ConsumerErrorCode`]).
///
/// The twin of a `fuz_app` consumer's own constructor
/// (`jsonrpc_error_messages.ai_provider_error(…)`): the caller supplies the
/// message and `data`, and the HTTP status is the one the code was declared
/// with ([`error_code_to_http_status`]).
#[cold]
#[must_use]
pub fn consumer_error(code: ConsumerErrorCode, message: &str, data: Option<Value>) -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::Consumer(code),
        message: message.to_owned(),
        data,
    }
}

// -- HTTP status mapping ------------------------------------------------------

/// Map a JSON-RPC error code to an HTTP status code.
///
/// Matches `fuz_app`'s `jsonrpc_error_code_to_http_status` (canonical
/// taxonomy in `http/jsonrpc_errors.ts`).
///
/// Exhaustive over [`JsonrpcErrorCode`] — no catch-all arm, so a new code
/// is a compile error here rather than a silent 500. A consumer code
/// answers the status it was declared with (the twin of a consumer's
/// `register_jsonrpc_error_code` call).
///
/// `#[inline]` — small `match` with no allocation, hot path on every
/// error response. Not `const`: `request_cancelled`'s 499 has no
/// `StatusCode` constant and `StatusCode::from_u16` is not `const`.
#[inline]
#[must_use]
pub fn error_code_to_http_status(code: JsonrpcErrorCode) -> StatusCode {
    use JsonrpcErrorCode as C;
    match code {
        C::ParseError | C::InvalidRequest | C::InvalidParams => StatusCode::BAD_REQUEST,
        // -32601 → 404 (method_not_found); -32003 → 404 (not_found)
        C::MethodNotFound | C::NotFound => StatusCode::NOT_FOUND,
        C::Unauthenticated => StatusCode::UNAUTHORIZED,
        C::Forbidden => StatusCode::FORBIDDEN,
        C::Conflict => StatusCode::CONFLICT,
        // 422 Unprocessable Entity
        C::ValidationError => StatusCode::UNPROCESSABLE_ENTITY,
        // 429 Too Many Requests — queue_overflow + rate_limited share
        // the same status code per `fuz_app`'s reverse mapping.
        C::RateLimited | C::QueueOverflow => StatusCode::TOO_MANY_REQUESTS,
        C::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        C::Timeout => StatusCode::GATEWAY_TIMEOUT,
        C::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        // 499 — nginx's "client closed request", as `fuz_app` maps it. No
        // `StatusCode` constant names it; 499 is in range, so `from_u16`
        // cannot fail and the fallback is unreachable.
        C::RequestCancelled => {
            StatusCode::from_u16(499).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        }
        // the status the consumer declared the code with
        C::Consumer(code) => code.http_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `DbError`-shaped chain: fixed top-level text, the server's message
    /// reachable only through `source()`.
    #[derive(Debug, thiserror::Error)]
    #[error("db error")]
    struct OpaqueDbError(#[source] ServerMessage);

    #[derive(Debug, thiserror::Error)]
    #[error("ERROR: duplicate key value violates unique constraint \"account_username_key\"")]
    struct ServerMessage;

    /// Everything `run` logs, captured.
    fn captured_log(run: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    /// The `*_with_source` helpers log the cause chain, not the top-level
    /// `Display` a `tokio_postgres::Error` / `DbError` reduces to its kind.
    #[test]
    fn with_source_helpers_log_the_cause_chain() {
        let error = OpaqueDbError(ServerMessage);
        let log = captured_log(|| {
            let _ = internal_error_with_source("rpc step failed", &error);
            let _ = db_unavailable_with_source("rpc checkout failed", &error);
            let _ = crate::internal_error_response_with_source("rest step", &error);
            let _ = crate::db_unavailable_response_with_source("rest checkout", &error);
        });
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 4, "{log}");
        for line in &lines {
            assert!(
                line.contains("db error: ERROR: duplicate key value"),
                "{line}"
            );
            // no driver error in the chain, so no `sqlstate` field
            assert!(!line.contains("sqlstate"), "{line}");
        }
        assert!(
            lines[0].trim_start().starts_with("ERROR") && lines[0].contains("rpc step failed"),
            "{log}"
        );
        assert!(
            lines[1].trim_start().starts_with("ERROR") && lines[1].contains("rpc checkout failed"),
            "{log}"
        );
        assert!(
            lines[2].trim_start().starts_with("ERROR")
                && lines[2].contains("context=\"rest step\""),
            "{log}"
        );
        assert!(
            lines[3].trim_start().starts_with("ERROR")
                && lines[3].contains("context=\"rest checkout\""),
            "{log}"
        );
    }

    #[test]
    fn standard_codes_have_canonical_values() {
        // Snapshot against the JSON-RPC 2.0 spec values.
        assert_eq!(JsonrpcErrorCode::ParseError.as_i32(), -32700);
        assert_eq!(JsonrpcErrorCode::InvalidRequest.as_i32(), -32600);
        assert_eq!(JsonrpcErrorCode::MethodNotFound.as_i32(), -32601);
        assert_eq!(JsonrpcErrorCode::InvalidParams.as_i32(), -32602);
        assert_eq!(JsonrpcErrorCode::InternalError.as_i32(), -32603);
    }

    #[test]
    fn extension_codes_are_in_server_error_range() {
        // JSON-RPC 2.0 §5.1: -32099..=-32000 reserved for application.
        for code in [
            JsonrpcErrorCode::Unauthenticated,
            JsonrpcErrorCode::Forbidden,
            JsonrpcErrorCode::NotFound,
            JsonrpcErrorCode::Conflict,
            JsonrpcErrorCode::ValidationError,
            JsonrpcErrorCode::RateLimited,
            JsonrpcErrorCode::ServiceUnavailable,
            JsonrpcErrorCode::Timeout,
            JsonrpcErrorCode::QueueOverflow,
            JsonrpcErrorCode::RequestCancelled,
        ] {
            let raw = code.as_i32();
            assert!((-32099..=-32000).contains(&raw), "out of range: {raw}");
        }
    }

    #[test]
    fn try_from_round_trips_and_rejects_unknown() {
        // Every variant survives i32 → enum → i32.
        for code in [
            JsonrpcErrorCode::ParseError,
            JsonrpcErrorCode::InvalidRequest,
            JsonrpcErrorCode::MethodNotFound,
            JsonrpcErrorCode::InvalidParams,
            JsonrpcErrorCode::InternalError,
            JsonrpcErrorCode::Unauthenticated,
            JsonrpcErrorCode::Forbidden,
            JsonrpcErrorCode::NotFound,
            JsonrpcErrorCode::Conflict,
            JsonrpcErrorCode::ValidationError,
            JsonrpcErrorCode::RateLimited,
            JsonrpcErrorCode::ServiceUnavailable,
            JsonrpcErrorCode::Timeout,
            JsonrpcErrorCode::QueueOverflow,
            JsonrpcErrorCode::RequestCancelled,
        ] {
            assert_eq!(JsonrpcErrorCode::try_from(code.as_i32()), Ok(code));
        }
        assert_eq!(
            JsonrpcErrorCode::try_from(-99_999),
            Err(UnknownJsonrpcErrorCode(-99_999))
        );
    }

    /// zzz's `ai_provider_error`, the declaration the consumer-code path
    /// exists for.
    const TEST_CONSUMER_CODE: ConsumerErrorCode =
        ConsumerErrorCode::new(-32020, StatusCode::BAD_GATEWAY);

    #[test]
    fn base_set_lists_every_base_code_once() {
        // exhaustive, so a new base variant is a compile error here until it
        // is listed
        const fn is_base(code: JsonrpcErrorCode) -> bool {
            use JsonrpcErrorCode as C;
            match code {
                C::ParseError
                | C::InvalidRequest
                | C::MethodNotFound
                | C::InvalidParams
                | C::InternalError
                | C::Unauthenticated
                | C::Forbidden
                | C::NotFound
                | C::Conflict
                | C::ValidationError
                | C::RateLimited
                | C::ServiceUnavailable
                | C::Timeout
                | C::QueueOverflow
                | C::RequestCancelled => true,
                C::Consumer(_) => false,
            }
        }
        let mut numbers = std::collections::HashSet::new();
        for code in BASE_JSONRPC_ERROR_CODES {
            assert!(is_base(code), "{code:?}");
            assert!(numbers.insert(code.as_i32()), "{code:?} listed twice");
        }
    }

    #[test]
    fn consumer_error_carries_its_code_message_data_and_declared_status() {
        let error = consumer_error(
            TEST_CONSUMER_CODE,
            "claude: needs API key",
            Some(serde_json::json!({"reason": "x"})),
        );
        assert_eq!(error.code, JsonrpcErrorCode::Consumer(TEST_CONSUMER_CODE));
        assert_eq!(error.code.as_i32(), -32020);
        assert_eq!(error.code.to_string(), "-32020");
        assert_eq!(error.message, "claude: needs API key");
        assert_eq!(
            error_code_to_http_status(error.code),
            StatusCode::BAD_GATEWAY
        );
        // the envelope: a bare integer code, like every base code
        let envelope =
            serde_json::to_value(crate::jsonrpc::error_response(serde_json::json!(7), error))
                .unwrap();
        assert_eq!(
            envelope,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 7,
                "error": {"code": -32020, "message": "claude: needs API key", "data": {"reason": "x"}},
            })
        );
        let bare = serde_json::to_value(consumer_error(TEST_CONSUMER_CODE, "m", None)).unwrap();
        assert_eq!(bare, serde_json::json!({"code": -32020, "message": "m"}));
    }

    #[test]
    fn a_consumer_code_is_not_recovered_from_the_wire() {
        // the wire carries no status, so only base codes round-trip
        assert_eq!(
            JsonrpcErrorCode::try_from(TEST_CONSUMER_CODE.code()),
            Err(UnknownJsonrpcErrorCode(-32020))
        );
    }

    #[test]
    fn consumer_codes_accept_the_application_range_outside_the_base_set() {
        for code in [-32000, -32011, -32020, -32099] {
            let declared = ConsumerErrorCode::new(code, StatusCode::BAD_REQUEST);
            assert_eq!(declared.code(), code);
            assert_eq!(declared.http_status(), StatusCode::BAD_REQUEST);
        }
        let _ = ConsumerErrorCode::new(-32020, StatusCode::from_u16(599).unwrap());
    }

    #[test]
    fn consumer_codes_may_not_reuse_a_base_code() {
        for base in BASE_JSONRPC_ERROR_CODES {
            let refused = std::panic::catch_unwind(|| {
                ConsumerErrorCode::new(base.as_i32(), StatusCode::BAD_GATEWAY)
            });
            assert!(refused.is_err(), "{base:?} must be refused");
        }
    }

    #[test]
    #[should_panic(expected = "must be in -32099..=-32000")]
    fn consumer_codes_stay_in_the_application_range() {
        let _ = ConsumerErrorCode::new(-32100, StatusCode::BAD_GATEWAY);
    }

    #[test]
    #[should_panic(expected = "must be in -32099..=-32000")]
    fn consumer_codes_stay_below_the_range_top() {
        let _ = ConsumerErrorCode::new(-31999, StatusCode::BAD_GATEWAY);
    }

    #[test]
    #[should_panic(expected = "must answer a 4xx or 5xx status")]
    fn consumer_codes_answer_an_error_status() {
        let _ = ConsumerErrorCode::new(-32020, StatusCode::OK);
    }

    #[test]
    fn serializes_as_bare_i32() {
        // The wire contract: `code` is the bare integer, not a string or
        // tagged object.
        let e = invalid_params("bad", None);
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["code"], serde_json::json!(-32602));
    }

    #[test]
    fn status_mapping_covers_standard_codes() {
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::ParseError),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::InvalidRequest),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::InvalidParams),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::MethodNotFound),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::InternalError),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn status_mapping_covers_extensions() {
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::Unauthenticated),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::Forbidden),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::NotFound),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::Conflict),
            StatusCode::CONFLICT
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::ValidationError),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::RateLimited),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::QueueOverflow),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::ServiceUnavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::Timeout),
            StatusCode::GATEWAY_TIMEOUT
        );
    }

    #[test]
    fn request_cancelled_maps_to_499() {
        // request_cancelled (-32010) → 499 "client closed request", the
        // status `fuz_app`'s `jsonrpc_error_code_to_http_status` answers
        assert_eq!(
            error_code_to_http_status(JsonrpcErrorCode::RequestCancelled).as_u16(),
            499
        );
    }

    #[test]
    fn constructors_set_canonical_code_and_message() {
        let e = invalid_params("missing field 'x'", None);
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.message, "missing field 'x'");

        let e = not_found("user", None);
        assert_eq!(e.code, JsonrpcErrorCode::NotFound);
        assert_eq!(e.message, "user not found");
        assert!(e.data.is_none());

        let e = not_found("session", Some("expired"));
        assert_eq!(e.message, "session not found");
        let data = e.data.expect("data present when reason supplied");
        assert_eq!(data["reason"], "expired");
    }

    #[test]
    fn wire_shape_omits_none_data() {
        let e = invalid_request(None);
        let json = serde_json::to_value(&e).unwrap();
        assert!(json.get("data").is_none(), "data key omitted when None");
    }

    #[test]
    fn wire_shape_includes_some_data() {
        let e = not_found("repo", Some("private"));
        let json = serde_json::to_value(&e).unwrap();
        assert!(json.get("data").is_some());
    }

    #[test]
    fn forbidden_invalid_params_invalid_request_carry_reason() {
        let e = forbidden("role not grantable", Some("role_not_grantable"));
        assert_eq!(e.code, JsonrpcErrorCode::Forbidden);
        assert_eq!(e.message, "role not grantable");
        assert_eq!(e.data.unwrap()["reason"], "role_not_grantable");

        let e = invalid_params("bad uuid", Some("offer_self_target"));
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.data.unwrap()["reason"], "offer_self_target");

        let e = invalid_request(Some("offer_terminal"));
        assert_eq!(e.code, JsonrpcErrorCode::InvalidRequest);
        assert_eq!(e.data.unwrap()["reason"], "offer_terminal");
    }

    #[test]
    fn invalid_input_params_sends_the_generic_message_and_keeps_the_reason() {
        let e = invalid_input_params("'limit' must be between 1 and 200", Some("limit_invalid"));
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.message, INVALID_PARAMS_MESSAGE);
        assert_eq!(e.data, Some(serde_json::json!({"reason": "limit_invalid"})));

        let e = invalid_input_params("unknown field `junk`", None);
        assert_eq!(e.message, INVALID_PARAMS_MESSAGE);
        assert_eq!(e.data, None);
    }

    #[test]
    fn parse_params_does_not_pass_serde_text_to_the_wire() {
        let e =
            parse_params::<RequiredInput>(serde_json::json!({"id": "x", "junk": 1})).unwrap_err();
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.message, INVALID_PARAMS_MESSAGE);
        assert_eq!(e.data, None);
    }

    /// All-optional input, the `.default({})` wire shape — the case a caller
    /// would otherwise hand-roll an `is_null()` branch for.
    #[derive(Debug, Default, PartialEq, serde::Deserialize)]
    #[serde(default, deny_unknown_fields)]
    struct OptionalInput {
        limit: Option<i64>,
        kind: Option<String>,
    }

    /// Required-field input — the strict shape a positional array would
    /// otherwise satisfy through serde's `visit_seq`.
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RequiredInput {
        #[allow(dead_code, reason = "shape only — the parse result is the assertion")]
        id: String,
    }

    #[test]
    fn parse_params_maps_null_to_empty_object() {
        // An all-optional input decodes from `null` exactly as from `{}`.
        let from_null: OptionalInput = parse_params(Value::Null).expect("null parses as {}");
        assert_eq!(from_null, OptionalInput::default());

        // A required field is still missing — `{}` doesn't satisfy it.
        let e = parse_params::<RequiredInput>(Value::Null).unwrap_err();
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
    }

    #[test]
    fn parse_params_rejects_positional_array_params() {
        // Without the object guard serde's `visit_seq` would fill `id`
        // positionally, bypassing `deny_unknown_fields` (which guards
        // `visit_map` only).
        let e = parse_params::<RequiredInput>(serde_json::json!(["x"])).unwrap_err();
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.message, INVALID_PARAMS_MESSAGE);

        let e = parse_params::<OptionalInput>(serde_json::json!([])).unwrap_err();
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
    }

    #[test]
    fn parse_params_rejects_scalar_params() {
        for scalar in [
            serde_json::json!("x"),
            serde_json::json!(1),
            serde_json::json!(true),
        ] {
            let e = parse_params::<OptionalInput>(scalar.clone()).unwrap_err();
            assert_eq!(e.code, JsonrpcErrorCode::InvalidParams, "scalar: {scalar}");
            assert_eq!(e.message, INVALID_PARAMS_MESSAGE);
        }
    }

    #[test]
    fn parse_params_passes_objects_through_unchanged() {
        let input: OptionalInput =
            parse_params(serde_json::json!({"limit": 5, "kind": "note"})).expect("object parses");
        assert_eq!(input.limit, Some(5));
        assert_eq!(input.kind.as_deref(), Some("note"));

        // Unknown keys still fail the strict-object contract.
        let e = parse_params::<OptionalInput>(serde_json::json!({"nope": 1})).unwrap_err();
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
    }
}
