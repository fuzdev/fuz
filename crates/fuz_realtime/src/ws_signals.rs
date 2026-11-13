//! Per-request cancellation bookkeeping for the WS read loop.
//!
//! Ports `fuz_app`'s `actions/register_action_ws.ts` per-connection
//! `{request_id → AbortController}` map to Rust's
//! [`CancellationToken`] hierarchy.
//!
//! ## Why per-request, not per-socket
//!
//! A WS connection mints **one** socket-scoped token at upgrade
//! (`ConnectionInfo.signal`) reserved for **teardown / revocation** — when
//! the connection is force-closed (`ConnectionRegistry::close_connections`)
//! or the loop exits, cancelling that parent cancels every in-flight child.
//!
//! Per-request cancellation needs finer grain: a `cancel` message naming a
//! single `request_id` must abort **only** that request, leaving its
//! siblings — and every future request on the socket — live. Cancelling the
//! shared socket token instead would poison the whole connection: the
//! `CancellationToken` is one-shot / irreversible, so one `cancel` would
//! make every subsequent handler observe `is_cancelled() == true` forever.
//!
//! The fix is the token hierarchy: each dispatched request gets a
//! `socket_token.child_token()`. Cancelling a child fires only that child
//! (and any of *its* descendants); cancelling the parent fires all children.
//! Fresh requests parent off the still-live socket token, so they are never
//! poisoned by a sibling's cancel.
//!
//! [`PendingRequestSignals`] is the single-task owner of that map. It lives
//! in the `run_ws_connection` loop frame — one task per connection, so all
//! access stays inside the loop and no `Mutex` is needed. It is bounded by
//! the loop's in-flight dispatch cap (entries are inserted on dispatch,
//! removed on completion).
//!
//! ## One live request per id
//!
//! An id names at most one running request. The loop refuses a request whose
//! id is already live ([`PendingRequestSignals::is_live`]) before it
//! dispatches, and [`PendingRequestSignals::begin`] never replaces an entry —
//! so a `cancel` naming the id, and the completion that removes it, always
//! belong to the request that took the id first.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use serde_json::Value;
use tokio_util::sync::CancellationToken;

/// Canonical map key for a JSON-RPC request id.
///
/// `serde_json::Value` is not `Hash`, so the map keys on the id's value —
/// but **tagged by JSON type**, because the two halves of the
/// `JsonrpcRequestId` space share a text form: request `7` and request
/// `"7"` are different requests, and an untagged key would let a `cancel`
/// naming one abort the other. The TS twin keys its
/// `{request_id -> AbortController}` map by the raw id value, where `7` and
/// `"7"` are already distinct `Map` keys; the tag is how this map matches
/// that.
///
/// Inside the numeric half the twin needs the opposite: JS has one number
/// type, so `7`, `7.0` and `7e0` — and `1e2` and `100` — are already the
/// *same* `Map` key there. A number is therefore keyed by its `f64` value
/// (`serde_json::Number::as_f64`) rather than its JSON text, with `-0`
/// normalized to `0` for `SameValueZero`. That inherits the twin's limit
/// too: an integer id above 2^53 loses precision, so two ids differing
/// only beyond the mantissa collide here exactly as they do on TS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RequestKey {
    /// A numeric id, keyed by the bits of its `f64` value.
    Number(u64),
    /// A string id, keyed by its contents.
    Str(String),
}

/// Key a wire id, or `None` when it is neither a string nor a number.
///
/// `fuz_http::classify` admits only those two shapes for a request id, so
/// the `None` arm is unreachable from the dispatch path; it exists because
/// [`PendingRequestSignals::cancel`] takes an id straight off an inbound
/// `cancel` frame, where a client can send anything. An unkeyable id
/// therefore misses every entry — a silent no-op, the same answer an
/// unknown id gets.
fn id_key(request_id: &Value) -> Option<RequestKey> {
    match request_id {
        Value::String(s) => Some(RequestKey::Str(s.clone())),
        Value::Number(n) => n.as_f64().map(|f| {
            // SameValueZero, as in the twin's `Map`: `-0` and `0` are one
            // key. Compared as bits, so no float equality is involved.
            let bits = f.to_bits();
            RequestKey::Number(if bits == (-0.0f64).to_bits() {
                0.0f64.to_bits()
            } else {
                bits
            })
        }),
        _ => None,
    }
}

/// Per-connection request-id → child-token map, parented by the socket token.
///
/// Owns the per-request cancellation grain for one WS connection. Created
/// from the socket-scoped token; hands each dispatched request a child
/// token to use as its `ctx.signal`, and routes a `cancel` message to the
/// matching child without touching the parent.
///
/// Single-task: the `run_ws_connection` loop is the sole owner, so the inner
/// `HashMap` needs no synchronization.
#[derive(Debug)]
pub struct PendingRequestSignals {
    /// Per-socket parent token — fires on teardown / revocation, cancelling
    /// every live child. Reserved for connection-wide cancellation; a
    /// `cancel` message must **never** fire this.
    socket_token: CancellationToken,
    /// In-flight request id → that request's child token.
    pending: HashMap<RequestKey, CancellationToken>,
}

impl PendingRequestSignals {
    /// Build over the connection's socket-scoped token.
    #[must_use]
    pub fn new(socket_token: CancellationToken) -> Self {
        Self {
            socket_token,
            pending: HashMap::new(),
        }
    }

    /// Whether `request_id` names a request still in flight.
    ///
    /// Keyed like every other lookup here (`RequestKey`: `7` and `"7"` are
    /// different ids, `7` and `7.0` the same one). An id outside the
    /// string|number space is never live.
    #[must_use]
    pub fn is_live(&self, request_id: &Value) -> bool {
        id_key(request_id).is_some_and(|key| self.pending.contains_key(&key))
    }

    /// Register a freshly-dispatched request and return its child token, or
    /// `None` when `request_id` is already live.
    ///
    /// Mints `socket_token.child_token()`, records it under `request_id`,
    /// and returns a clone for the handler's `ctx.signal`. A live id is
    /// never replaced: the request holding it keeps its token, so a `cancel`
    /// for the id still reaches it and its completion removes its own entry.
    /// The loop checks [`Self::is_live`] first and refuses the duplicate
    /// before the in-flight cap, so the `None` arm is its fallback, not its
    /// gate.
    ///
    /// An id outside the string|number space is untrackable (see
    /// `id_key`) and so goes unrecorded — the handler still gets a live
    /// child token, it just cannot be cancelled by name. `classify` never
    /// produces one.
    #[must_use]
    pub fn begin(&mut self, request_id: &Value) -> Option<CancellationToken> {
        let Some(key) = id_key(request_id) else {
            return Some(self.socket_token.child_token());
        };
        match self.pending.entry(key) {
            Entry::Occupied(_) => None,
            Entry::Vacant(slot) => {
                let token = self.socket_token.child_token();
                slot.insert(token.clone());
                Some(token)
            }
        }
    }

    /// Forget a completed request so the map can't grow unbounded.
    ///
    /// Called from the dispatch-completion arm. Dropping the stored clone
    /// here is harmless — the handler already holds its own clone, and the
    /// request is done, so nothing observes a later cancel of this id (a
    /// `cancel` for a completed id is a silent no-op, matching the TS twin).
    pub fn complete(&mut self, request_id: &Value) {
        if let Some(key) = id_key(request_id) {
            self.pending.remove(&key);
        }
    }

    /// Cancel the in-flight request named by `request_id`, if any.
    ///
    /// Fires **only** that request's child token (and its descendants),
    /// never the socket parent. Returns `true` if a matching request was
    /// found and cancelled, `false` if the id is unknown / already
    /// completed — an unknown id is a silent no-op, matching the TS twin
    /// (races between a response and a late `cancel` are safe with no extra
    /// coordination).
    ///
    /// The id is matched by type as well as value, so a `cancel` naming
    /// `"7"` never aborts request `7` (and vice versa), while `7.0` and `7`
    /// do name the same request (see `RequestKey`); an id that is neither
    /// a string nor a number misses outright.
    pub fn cancel(&self, request_id: &Value) -> bool {
        id_key(request_id)
            .and_then(|key| self.pending.get(&key))
            .is_some_and(|token| {
                token.cancel();
                true
            })
    }

    /// Number of in-flight requests currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether any request is currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    //! Pins the per-request-cancellation regression: the `cancel` wire
    //! method must abort **only** its target request, never the socket-wide
    //! token. These exercise [`PendingRequestSignals`] directly — the same
    //! map + token hierarchy the `run_ws_connection` loop drives — without a
    //! live `WebSocket` (the loop itself is integration-tested at the
    //! consumer layer; the cancellation *logic* lives here so it is unit-
    //! testable in isolation).

    use serde_json::json;
    use tokio_util::sync::CancellationToken;

    use super::PendingRequestSignals;

    /// Two concurrent requests A and B on one connection; cancelling A does
    /// **not** cancel B. (No cross-request poisoning.)
    #[test]
    fn cancel_one_request_leaves_siblings_live() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket.clone());

        let a = json!("req-a");
        let b = json!(42); // numeric id, exercises the non-string key path
        let token_a = signals.begin(&a).expect("a fresh id begins");
        let token_b = signals.begin(&b).expect("a fresh id begins");
        assert_eq!(signals.len(), 2);

        assert!(signals.cancel(&a), "A was in-flight, cancel reports a hit");

        assert!(token_a.is_cancelled(), "A's token fires");
        assert!(!token_b.is_cancelled(), "B's token stays live");
        assert!(!socket.is_cancelled(), "socket parent untouched");
    }

    /// After a `cancel`, a subsequently-dispatched request on the SAME
    /// connection gets a live (non-cancelled) token. (The core regression:
    /// no socket poisoning.)
    #[test]
    fn cancel_does_not_poison_future_requests() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket.clone());

        let first = json!("first");
        let token_first = signals.begin(&first).expect("a fresh id begins");
        assert!(signals.cancel(&first));
        assert!(token_first.is_cancelled());
        signals.complete(&first);

        // A fresh request dispatched after the cancel must NOT inherit the
        // cancelled state — a shared one-shot socket token would
        // stay cancelled forever.
        let second = json!("second");
        let token_second = signals.begin(&second).expect("a fresh id begins");
        assert!(
            !token_second.is_cancelled(),
            "a request after a cancel gets a fresh, live token"
        );
        assert!(!socket.is_cancelled(), "socket parent never fired");
    }

    /// Cancelling an unknown / already-completed request id is a silent
    /// no-op — no panic, no socket-wide effect, reports `false`.
    #[test]
    fn cancel_unknown_id_is_a_silent_noop() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket.clone());

        let live = json!("live");
        let token_live = signals.begin(&live).expect("a fresh id begins");

        // Never-seen id.
        assert!(
            !signals.cancel(&json!("never-existed")),
            "unknown id misses"
        );
        // Completed id — begin, complete, then a late cancel arrives.
        let done = json!("done");
        let token_done = signals.begin(&done).expect("a fresh id begins");
        signals.complete(&done);
        assert!(!signals.cancel(&done), "already-completed id misses");

        assert!(!token_live.is_cancelled(), "the live request is untouched");
        assert!(
            !token_done.is_cancelled(),
            "the completed token never fired"
        );
        assert!(!socket.is_cancelled(), "no socket-wide effect");
    }

    /// Cancelling the per-socket parent (the revocation / teardown path)
    /// cancels an in-flight request's child token.
    #[test]
    fn socket_teardown_cancels_inflight_children() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket.clone());

        let a = json!("a");
        let b = json!("b");
        let token_a = signals.begin(&a).expect("a fresh id begins");
        let token_b = signals.begin(&b).expect("a fresh id begins");

        // Force-close / revocation cancels the socket-scoped parent.
        socket.cancel();

        assert!(token_a.is_cancelled(), "child A cancelled by parent");
        assert!(token_b.is_cancelled(), "child B cancelled by parent");
    }

    /// `complete` drops the entry so a late cancel for that id can't fire a
    /// fresh request that reused the id, and the map can't grow unbounded.
    #[test]
    fn complete_removes_the_tracked_entry() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket);

        let id = json!("x");
        let _token = signals.begin(&id).expect("a fresh id begins");
        assert_eq!(signals.len(), 1);
        assert!(!signals.is_empty());

        signals.complete(&id);
        assert_eq!(signals.len(), 0);
        assert!(signals.is_empty());
        // Completing again (or completing an unknown id) is harmless.
        signals.complete(&id);
        assert_eq!(signals.len(), 0);
    }

    /// A string id and a number id that share a text form are different
    /// requests: `cancel {"request_id": "7"}` must not abort request `7`.
    /// The TS twin keys its `Map` by the raw id value, where the two are
    /// already distinct; an untagged text key here would let one cancel the
    /// other.
    #[test]
    fn string_and_number_ids_never_collide() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket.clone());

        let numeric = json!(7);
        let token_numeric = signals.begin(&numeric).expect("a fresh id begins");

        assert!(
            !signals.cancel(&json!("7")),
            "the string 7 names no request"
        );
        assert!(
            !token_numeric.is_cancelled(),
            "request 7 survives a cancel for the string 7"
        );

        assert!(signals.cancel(&numeric), "request 7 cancels by its own id");
        assert!(token_numeric.is_cancelled());
        assert!(!socket.is_cancelled(), "socket parent untouched");
    }

    /// The mirror direction — a string-keyed request is not cancelled by
    /// the number sharing its text.
    #[test]
    fn a_number_does_not_cancel_the_string_of_its_digits() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket);

        let text = json!("7");
        let token_text = signals.begin(&text).expect("a fresh id begins");

        assert!(!signals.cancel(&json!(7)), "the number 7 names no request");
        assert!(!token_text.is_cancelled());

        assert!(signals.cancel(&text));
        assert!(token_text.is_cancelled());
    }

    /// JS has one number type, so the twin's `Map` already treats `7`,
    /// `7.0` and `7e0` — and `1e2` and `100` — as one key. Keying on the
    /// `f64` value rather than the JSON text is how this map matches that,
    /// with `-0` folded onto `0` for `SameValueZero`. The string|number split
    /// is unaffected.
    #[test]
    fn numeric_ids_key_by_value_like_the_twin() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket);

        // `7.0` and `7` are one id.
        let token_seven = signals.begin(&json!(7.0)).expect("a fresh id begins");
        assert!(
            signals.cancel(&json!(7)),
            "7 names the request begun as 7.0"
        );
        assert!(token_seven.is_cancelled());

        // So are `1e2` and `100`.
        let token_hundred = signals.begin(&json!(1e2)).expect("a fresh id begins");
        assert!(
            signals.cancel(&json!(100)),
            "100 names the request begun as 1e2"
        );
        assert!(token_hundred.is_cancelled());

        // And `-0` and `0` — SameValueZero.
        let token_zero = signals.begin(&json!(-0.0)).expect("a fresh id begins");
        assert!(signals.cancel(&json!(0)), "0 names the request begun as -0");
        assert!(token_zero.is_cancelled());

        // The type tag still splits the two halves of the id space —
        // fresh state, so no numeric `7` above can answer for the string.
        let mut split = PendingRequestSignals::new(CancellationToken::new());
        let token_text = split.begin(&json!("7")).expect("a fresh id begins");
        assert!(
            !split.cancel(&json!(7)),
            "the number 7 still names no string request"
        );
        assert!(!token_text.is_cancelled());
    }

    /// An id outside the string|number space can't be keyed, so it misses
    /// every entry rather than matching one by its text form.
    #[test]
    fn unkeyable_ids_miss() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket);

        let live = json!("live");
        let token_live = signals.begin(&live).expect("a fresh id begins");

        for id in [json!(null), json!(true), json!([]), json!({})] {
            assert!(!signals.cancel(&id), "id: {id}");
        }
        assert!(!token_live.is_cancelled());
    }

    /// A live id is never replaced: a second `begin` for it is refused, the
    /// first request keeps its token — a `cancel` for the id fires the
    /// original — and once it completes the id begins again.
    #[test]
    fn begin_refuses_a_live_id() {
        let socket = CancellationToken::new();
        let mut signals = PendingRequestSignals::new(socket.clone());

        let id = json!("dup");
        let first = signals.begin(&id).expect("a fresh id begins");
        assert!(signals.is_live(&id));
        assert!(signals.begin(&id).is_none(), "a live id is refused");
        assert_eq!(signals.len(), 1, "the refusal records nothing");

        assert!(signals.cancel(&id));
        assert!(first.is_cancelled(), "the cancel reaches the first request");

        signals.complete(&id);
        assert!(!signals.is_live(&id));
        let again = signals.begin(&id).expect("a completed id begins again");
        assert!(!again.is_cancelled());
        assert!(!socket.is_cancelled());
    }

    /// `is_live` keys like every other lookup: the string of a number's
    /// digits is another id, while numeric spellings of one value (and `-0`
    /// and `0`) are the same id — so the duplicate refusal covers exactly the
    /// ids the twin's `Map` would collide.
    #[test]
    fn is_live_keys_like_the_twin() {
        let mut signals = PendingRequestSignals::new(CancellationToken::new());
        let _seven = signals.begin(&json!(7)).expect("a fresh id begins");
        let _zero = signals.begin(&json!(-0.0)).expect("a fresh id begins");

        assert!(signals.is_live(&json!(7)));
        assert!(signals.is_live(&json!(7.0)), "7.0 is the id 7");
        assert!(signals.is_live(&json!(0)), "0 is the id -0");
        assert!(!signals.is_live(&json!("7")), "the string 7 is another id");
        assert!(signals.begin(&json!(7.0)).is_none());
        assert!(signals.begin(&json!(0)).is_none());
        assert!(signals.begin(&json!("7")).is_some());

        for id in [json!(null), json!(true), json!([]), json!({})] {
            assert!(!signals.is_live(&id), "id: {id}");
        }
    }
}
