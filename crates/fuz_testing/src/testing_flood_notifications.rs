//! `_testing_flood_notifications` action spec.
//!
//! Test binaries register this on their `ActionRegistry` alongside
//! `_testing_reset`. It queues a burst of notifications onto the **caller's
//! own WebSocket connection**, all inside one handler poll, so a suite
//! driving the server from outside can push a connection's outbound queue
//! past its byte budget deterministically — without a second producer, and
//! whether or not its client is reading: the connection's loop writes
//! nothing while the handler runs, so the whole burst waits at once. The
//! queue's budget is the one its router was built with
//! (`fuz_realtime::connection_channel`), each waiting notification charged
//! its frame's UTF-8 length plus
//! `fuz_realtime::OUTBOUND_FRAME_OVERHEAD_BYTES`; past it the server closes
//! the socket with `fuz_realtime::WS_CLOSE_OUTBOUND_OVERFLOW` (4005). Only
//! bytes bound the queue, so a burst overflows by its total size, however
//! many notifications carry it.
//!
//! ## Wire
//!
//! Params, a strict object:
//!
//! - `count` — how many notifications to queue: an integer from 0 through
//!   `TESTING_FLOOD_MAX_COUNT`.
//! - `size` — the byte length of each notification's `payload` string: an
//!   integer from 0 through `TESTING_FLOOD_MAX_SIZE`.
//!
//! `count` × `size` may be at most `TESTING_FLOOD_MAX_TOTAL_BYTES`: every
//! notification is serialized whether or not the queue still takes it, so
//! the product is the work one call does inside one poll. A call past any of
//! the three limits is refused with `invalid_params` and queues nothing.
//!
//! Each notification is
//! `{"jsonrpc":"2.0","method":"_testing_flood","params":{"index":<i>,"payload":"<size × 'x'>"}}`
//! with `index` counting from 0, so every frame is a little longer than
//! `size` bytes and a client can tell which frames reached it.
//!
//! The result is `{"queued": <count>}` — the number asked for, not the
//! number that fit: when the burst overflows the queue the connection is
//! closed and this response is never written, and the close frame is what
//! the caller observes. A burst that fits arrives in order, ahead of the
//! response.
//!
//! Over HTTP there is no connection to queue onto, so the request is refused
//! with `invalid_params`, reason `ERROR_TESTING_FLOOD_NO_CONNECTION`,
//! rather than answering as though it had flooded something.
//!
//! Gated on the daemon-token credential — effectively keeper-only without
//! forcing the `actor: 'required'` biconditional, matching `_testing_reset`.

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_http::{InputShape, invalid_input_params, invalid_params};
use serde_json::{Value, json};

/// The wire method of each notification the flood queues.
pub const TESTING_FLOOD_NOTIFICATION_METHOD: &str = "_testing_flood";

/// The most notifications one call queues.
///
/// Empty ones (`size` 0) at this count are charged more than
/// `fuz_actions::DEFAULT_WS_OUTBOUND_QUEUE_BYTES` between them — each
/// frame's envelope and its overhead — so a burst of tiny frames can
/// overflow a connection on a default router too.
pub(crate) const TESTING_FLOOD_MAX_COUNT: u64 = 65_536;

/// The largest `payload` one call builds, in bytes.
pub(crate) const TESTING_FLOOD_MAX_SIZE: u64 = 16 * 1024 * 1024;

/// The most payload bytes one call builds across all its notifications.
///
/// It bounds `count` × `size`: the handler serializes each notification
/// without yielding, so the product is how long one call holds its worker
/// thread. `count` and `size` at their own limits together would be about a
/// tebibyte.
pub(crate) const TESTING_FLOOD_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// The `data.reason` of the refusal a call over HTTP gets.
pub(crate) const ERROR_TESTING_FLOOD_NO_CONNECTION: &str = "no_connection";

/// Declared input keys — a strict object.
const TESTING_FLOOD_KEYS: &[&str] = &["count", "size"];

/// Read `key` as an integer from 0 through `max`.
fn bounded_integer(params: &Value, key: &str, max: u64) -> Result<u64, fuz_http::JsonrpcError> {
    params
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= max)
        .ok_or_else(|| {
            invalid_input_params(&format!("{key} must be an integer from 0 to {max}"), None)
        })
}

/// Build the `_testing_flood_notifications` action spec.
///
/// The handler queues `count` notifications of `size` payload bytes each
/// onto the calling connection through `ctx.notify`, without yielding, and
/// answers `{"queued": count}` (module doc, "Wire"). It refuses a call whose
/// `count` × `size` is past `TESTING_FLOOD_MAX_TOTAL_BYTES`.
#[must_use]
pub fn create_testing_flood_notifications_action_spec() -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
        Box::pin(async move {
            fuz_http::reject_unknown_keys(&params, TESTING_FLOOD_KEYS)?;
            let count = bounded_integer(&params, "count", TESTING_FLOOD_MAX_COUNT)?;
            let size = bounded_integer(&params, "size", TESTING_FLOOD_MAX_SIZE)?;
            if count.saturating_mul(size) > TESTING_FLOOD_MAX_TOTAL_BYTES {
                return Err(invalid_params(
                    &format!("count * size must be at most {TESTING_FLOOD_MAX_TOTAL_BYTES}"),
                    None,
                ));
            }
            if ctx.connection_id.is_none() {
                return Err(invalid_params(
                    "_testing_flood_notifications needs a WebSocket connection",
                    Some(ERROR_TESTING_FLOOD_NO_CONNECTION),
                ));
            }
            let size = usize::try_from(size)
                .map_err(|_| invalid_params("size does not fit this platform", None))?;
            let mut notification = json!({ "index": 0, "payload": "x".repeat(size) });
            for index in 0..count {
                notification["index"] = json!(index);
                (ctx.notify)(TESTING_FLOOD_NOTIFICATION_METHOD, &notification);
            }
            Ok(json!({ "queued": count }))
        })
    });

    ActionSpec::read_only(
        "_testing_flood_notifications",
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}
