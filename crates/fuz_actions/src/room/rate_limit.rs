//! The room verbs' per-connection limiter: a count budget and a byte budget,
//! each a token bucket refilled over a window — and [`json_escaped_len`],
//! what a payload or state charges.

use std::collections::HashMap;
use std::time::Duration;

use fuz_realtime::ConnectionId;
use parking_lot::Mutex;
use tokio::time::Instant;

/// A [`RoomRateLimiter`]'s budgets.
///
/// Each is a bucket holding at most its maximum, refilled at that maximum
/// per `window`: a burst may spend it all at once, and the sustained rate is
/// the maximum per window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomRateLimitOptions {
    /// Joins, sends, and state sets — each costs one.
    pub max_requests: u32,
    /// Payload and state bytes as their frames carry them
    /// ([`json_escaped_len`]). At least a max-size payload's and state's
    /// worst case ([`JSON_ESCAPE_MAX_EXPANSION`] times the registry's bound),
    /// or `build_room_spec_set` refuses the pair.
    pub max_bytes: u64,
    pub window: Duration,
}

/// The default budgets.
///
/// Room for a join into a full-mesh room (an offer and its candidates to
/// every member) several times over. A full burst stays under half of a
/// reader's default outbound queue (`fuz_actions::DEFAULT_WS_OUTBOUND_QUEUE_BYTES`,
/// 4 MiB), by construction: a charge is exactly the bytes the payload or
/// state adds to its frame, and each charged request puts at most four
/// frames in any other reader's queue (for a join, which moves at most one
/// seat: the moved seat leaving, its `room_seat_lost`, the join's
/// `room_member_joined`, and the uncharged leave that later ends the new
/// seat), so one member's burst queues at most `max_bytes` plus four
/// frames' fixed overhead per request. The
/// room-verb tests pin the sum against the worst-case frames.
pub const DEFAULT_ROOM_RATE_LIMIT: RoomRateLimitOptions = RoomRateLimitOptions {
    max_requests: 300,
    max_bytes: 1024 * 1024,
    window: Duration::from_secs(10),
};

/// The most bytes one byte of a string can take escaped in a JSON frame:
/// `\u00XX`, for a control character without a two-byte escape.
pub const JSON_ESCAPE_MAX_EXPANSION: u64 = 6;

/// The bytes `text` takes inside a JSON string in the frames the registry
/// builds — `serde_json`'s compact escaping, which `JSON.stringify` matches
/// for well-formed text.
///
/// `"` and `\` take 2; backspace, form feed, newline, carriage return, and
/// tab take 2 (`\b \f \n \r \t`); every other control character below
/// U+0020 takes 6 (`\u00XX`); everything else is its UTF-8 length — U+007F
/// and non-ASCII text are not escaped. Byte-wise is exact: every escaped
/// character is one ASCII byte, and no byte of a multi-byte character is
/// ASCII.
#[must_use]
pub fn json_escaped_len(text: &str) -> usize {
    text.bytes()
        .map(|byte| match byte {
            b'"' | b'\\' | 0x08 | 0x0c | b'\n' | b'\r' | b'\t' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        })
        .sum()
}

/// The fewest connections the limiter tracks before it sweeps the full
/// buckets; it sweeps again at twice what a sweep leaves.
const SWEEP_FLOOR: usize = 64;

/// A charge the budgets can't cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomRateLimited {
    /// Whole seconds, at least one, until the budgets would cover it.
    pub retry_after: u64,
}

/// The room verbs' limiter, one budget pair per connection
/// ([`RoomRateLimitOptions`]).
///
/// A connection's buckets are forgotten once full again — a full bucket is
/// what a fresh one is — so the map holds only connections that spent
/// recently, swept as it grows. Time is tokio's clock, so a test with the
/// clock paused drives the refill.
#[derive(Debug)]
pub struct RoomRateLimiter {
    options: RoomRateLimitOptions,
    state: Mutex<LimiterState>,
}

#[derive(Debug, Default)]
struct LimiterState {
    buckets: HashMap<ConnectionId, Buckets>,
    sweep_at: usize,
}

/// A connection's two buckets, as credit scaled by the window's length in
/// nanoseconds, so the refill is exact integer arithmetic: a request costs
/// `window` credit and a byte `window` credit, and each elapsed nanosecond
/// adds the maximum.
#[derive(Debug, Clone, Copy)]
struct Buckets {
    requests: u128,
    bytes: u128,
    at: Instant,
}

impl RoomRateLimiter {
    #[must_use]
    pub fn new(options: RoomRateLimitOptions) -> Self {
        Self {
            options,
            state: Mutex::new(LimiterState::default()),
        }
    }

    /// The budgets.
    #[must_use]
    pub const fn options(&self) -> &RoomRateLimitOptions {
        &self.options
    }

    /// Spend one request and `bytes` from `connection_id`'s budgets, both or
    /// neither.
    ///
    /// # Errors
    ///
    /// [`RoomRateLimited`] when either budget can't cover it; nothing is
    /// spent then.
    pub fn charge(&self, connection_id: ConnectionId, bytes: usize) -> Result<(), RoomRateLimited> {
        let now = Instant::now();
        let window = self.window_nanos();
        let max_requests = u128::from(self.options.max_requests);
        let max_bytes = u128::from(self.options.max_bytes);
        let need_requests = window;
        let need_bytes = u128::try_from(bytes)
            .unwrap_or(u128::MAX)
            .saturating_mul(window);

        let mut state = self.state.lock();
        let buckets = state
            .buckets
            .entry(connection_id)
            .or_insert_with(|| self.full(now));
        self.refill(buckets, now);
        if buckets.requests >= need_requests && buckets.bytes >= need_bytes {
            buckets.requests -= need_requests;
            buckets.bytes -= need_bytes;
            self.sweep(&mut state, now);
            return Ok(());
        }
        let wait_nanos = deficit_nanos(buckets.requests, need_requests, max_requests, window)
            .max(deficit_nanos(buckets.bytes, need_bytes, max_bytes, window));
        let retry_after = u64::try_from(wait_nanos.div_ceil(1_000_000_000))
            .unwrap_or(u64::MAX)
            .max(1);
        Err(RoomRateLimited { retry_after })
    }

    fn window_nanos(&self) -> u128 {
        self.options.window.as_nanos().max(1)
    }

    fn full(&self, now: Instant) -> Buckets {
        let window = self.window_nanos();
        Buckets {
            requests: u128::from(self.options.max_requests).saturating_mul(window),
            bytes: u128::from(self.options.max_bytes).saturating_mul(window),
            at: now,
        }
    }

    /// Credit what elapsed since the buckets were last read, up to full.
    fn refill(&self, buckets: &mut Buckets, now: Instant) {
        let full = self.full(now);
        let elapsed = now.saturating_duration_since(buckets.at).as_nanos();
        buckets.requests = buckets
            .requests
            .saturating_add(elapsed.saturating_mul(u128::from(self.options.max_requests)))
            .min(full.requests);
        buckets.bytes = buckets
            .bytes
            .saturating_add(elapsed.saturating_mul(u128::from(self.options.max_bytes)))
            .min(full.bytes);
        buckets.at = now;
    }

    /// Forget the connections whose buckets are full again, once the map
    /// has grown past the last sweep's mark.
    fn sweep(&self, state: &mut LimiterState, now: Instant) {
        if state.buckets.len() <= state.sweep_at.max(SWEEP_FLOOR) {
            return;
        }
        let full = self.full(now);
        state.buckets.retain(|_, buckets| {
            self.refill(buckets, now);
            buckets.requests < full.requests || buckets.bytes < full.bytes
        });
        state.sweep_at = state.buckets.len() * 2;
    }

    /// Connections tracked.
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.state.lock().buckets.len()
    }
}

/// Nanoseconds until a bucket holding `have` covers `need`, refilling at
/// `max` per nanosecond; a need past the bucket's whole size waits a window.
const fn deficit_nanos(have: u128, need: u128, max: u128, window: u128) -> u128 {
    if have >= need {
        return 0;
    }
    if max == 0 || need > max.saturating_mul(window) {
        return window;
    }
    (need - have).div_ceil(max)
}
