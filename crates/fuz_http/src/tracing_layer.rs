//! Request tracing — thin wrapper over `tower_http::trace::TraceLayer`.
//!
//! Provides a single named factory so every consumer's wiring picks up
//! the same tracing posture: one access-log line per request at `info`,
//! carrying method + uri + status + latency.
//!
//! ## Level posture
//!
//! `tower_http` emits up to four events per request — span-open
//! (`make_span`), `on_request` ("started processing request"),
//! `on_response` (status + latency), and `on_failure` for a response its
//! classifier calls a failure (a 5xx, or an error from the inner service).
//! The response line is the useful access-log heartbeat; the request line
//! carries nothing the span + response don't, so it sits at `debug` to
//! avoid 3× the volume for no information. The span stays at `info` so the
//! response line keeps its method + uri fields when the subscriber filters
//! at `info` — a span below the active filter is disabled and its fields
//! drop off the response event.
//!
//! The failure line sits at `warn`, not `tower_http`'s `error`: a 5xx is
//! the status of an answer, and a designed one (`service_unavailable`, a
//! refused bootstrap's 500) is no fault. On the spine, whatever made an
//! undesigned one logs its own `error` where it happened
//! (`internal_error_with_source`, the panic catcher), so `error` stays the
//! line that needs a look — as in the TS twin, whose request log is no error
//! either. A consumer's handler that answers a 5xx of its own logs whatever
//! it logs; with this layer's line at `warn`, an undesigned one it doesn't
//! log reaches no `error` line.
//!
//! [`crate::compose_stack`] wraps the whole router in it, outermost, when
//! [`StackOptions::request_tracing`](crate::StackOptions::request_tracing) is
//! set (the [`StackOptions::without_backend`](crate::StackOptions::without_backend) default).

use tower_http::trace::HttpMakeClassifier;
use tower_http::trace::{
    DefaultMakeSpan, DefaultOnBodyChunk, DefaultOnEos, DefaultOnFailure, DefaultOnRequest,
    DefaultOnResponse, TraceLayer,
};
use tracing::Level;

/// Build a tower layer that logs one access-log line per request at
/// `info`.
///
/// The span carries the `Method` + `Uri` extracted at make-time (at
/// `info`, so the fields survive an `info` filter) and is closed with
/// the response status + latency at `info`. The redundant "started
/// processing request" event sits at `debug` — enable it with
/// `RUST_LOG=tower_http=debug` when tracing a request's full lifecycle —
/// and a failed response's line (a 5xx) at `warn` (§ Level posture).
///
/// The stack offers this shape or none: a consumer that wants finer
/// control (per-route levels, body capture) turns
/// [`StackOptions::request_tracing`](crate::StackOptions::request_tracing)
/// off and layers its own `TraceLayer` on its route groups' routers —
/// inside the gates there, so it does not see their refusals.
#[must_use]
pub fn request_tracing_layer() -> TraceLayer<
    HttpMakeClassifier,
    DefaultMakeSpan,
    DefaultOnRequest,
    DefaultOnResponse,
    DefaultOnBodyChunk,
    DefaultOnEos,
    DefaultOnFailure,
> {
    TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::DEBUG))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
        .on_failure(DefaultOnFailure::new().level(Level::WARN))
}
