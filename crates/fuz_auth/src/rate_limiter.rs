//! In-memory sliding-window rate limiter.
//!
//! Uses a synchronous [`parking_lot::Mutex`] rather than `tokio::sync`'s
//! async locks, never held across an `.await`: `check` / `record` / `reset` /
//! `try_reserve` are synchronous, and [`RateLimiter::reserve`] takes the lock
//! only between its waits. Saves one runtime hop per `/login` and `/password`
//! request. A `Mutex`, not an `RwLock`, because every method mutates: `check`
//! and `record` both promote LRU recency and prune expired timestamps, so
//! there is no read-only path worth sharing.
//!
//! **Reserve, then settle.** A handler that checks the limiter, awaits work,
//! and records afterwards lets every request of a concurrent burst pass the
//! check before any of them records — a burst of any size gets through.
//! [`RateLimiter::try_reserve`] closes that: it admits a request and counts it
//! in flight in one locked step, and the attempt counts against the cap until
//! its [`RateLimitReservation`] is settled — [`record`](RateLimitReservation::record)
//! keeps it as an attempt, [`release`](RateLimitReservation::release) (or
//! dropping the reservation) gives it back. Every handler whose outcome decides
//! whether the attempt counts reserves. `check` + `record` takes the lock
//! twice, so on a multi-threaded runtime concurrent callers can all pass the
//! check before any records (an overshoot up to the worker count) even with no
//! await between them; a caller that counts every pass reserves and records at
//! once, as the action gate does.
//!
//! **Attempts count while in flight, whatever their outcome** — so a burst of
//! *correct* concurrent attempts from one key is capped too. The password
//! surfaces therefore reserve with [`RateLimiter::reserve`], which waits up to
//! [`RESERVATION_WAIT_MAX`] for a slot when the cap is reached only by
//! attempts in flight, and refuses at once when it is reached by recorded
//! ones.
//!
//! Defaults match `fuz_app`'s `default_login_*_rate_limit`, including the
//! `max_keys` LRU cap: the backing store is a bounded [`LruCache`] so an
//! attacker rotating source IPs / usernames on misses can't grow the map
//! indefinitely (login/signup key the account axis by attacker-chosen
//! canonical username on a miss). Every `check` / `record` marks the key
//! most-recently-used, so a key under active attack stays resident and can't
//! force its own eviction to reset its budget. Twin of `fuz_app`'s
//! `LruMap`-backed limiter; `max_keys: None` falls back to an unbounded cache
//! for closed key sets.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lru::LruCache;
use parking_lot::Mutex;
use tokio::sync::Notify;

/// Default tracked-key cap. Bounds worst-case memory under a key-enumeration
/// attack while comfortably fitting real single-instance traffic. Mirrors
/// `fuz_app`'s `DEFAULT_RATE_LIMITER_MAX_KEYS`.
pub const DEFAULT_RATE_LIMITER_MAX_KEYS: usize = 100_000;

/// Configuration for a [`RateLimiter`] instance.
#[derive(Debug, Clone, Copy)]
pub struct RateLimiterOptions {
    /// Maximum allowed attempts within the window. `0` refuses every
    /// attempt — `check`, `try_reserve`, and `reserve` answer at once with
    /// the window's length as `retry_after`, tracking nothing.
    pub max_attempts: u32,
    /// Sliding-window duration in milliseconds.
    pub window_ms: u64,
    /// Maximum tracked keys. `Some(n)` (n > 0) caps the backing
    /// [`LruCache`], evicting the least-recently-used key past the cap;
    /// `None` disables the cap (unbounded cache — only for closed key sets,
    /// e.g. a per-account limiter keyed to a bounded account table).
    /// `Some(0)` is rejected by [`RateLimiter::new`] (a zero cap holds
    /// nothing) — pass `None` for unbounded. Default
    /// `Some(DEFAULT_RATE_LIMITER_MAX_KEYS)`.
    pub max_keys: Option<usize>,
}

/// Default per-IP login rate limit (5 attempts / 15 min). Matches
/// `fuz_app`'s `default_login_ip_rate_limit`.
pub const DEFAULT_LOGIN_IP_RATE_LIMIT: RateLimiterOptions = RateLimiterOptions {
    max_attempts: 5,
    window_ms: 15 * 60_000,
    max_keys: Some(DEFAULT_RATE_LIMITER_MAX_KEYS),
};

/// Default per-account login rate limit (10 attempts / 30 min).
/// Matches `fuz_app`'s `default_login_account_rate_limit`.
pub const DEFAULT_LOGIN_ACCOUNT_RATE_LIMIT: RateLimiterOptions = RateLimiterOptions {
    max_attempts: 10,
    window_ms: 30 * 60_000,
    max_keys: Some(DEFAULT_RATE_LIMITER_MAX_KEYS),
};

/// Default per-account action-dispatcher rate limit (1200 attempts / 15 min).
///
/// Matches `fuz_app`'s `default_action_account_rate_limit`. Keyed by account
/// id on the authenticated action surface (admin + role-grant-offer), shared
/// by the HTTP RPC and WebSocket dispatchers (one budget per action, not per
/// transport). Permissive — sustained ~80/min is well above any human admin
/// workflow, slow enough that an oracle probe still surfaces in audit. Tighten
/// downstream for stricter deployments.
pub const DEFAULT_ACTION_ACCOUNT_RATE_LIMIT: RateLimiterOptions = RateLimiterOptions {
    max_attempts: 1200,
    window_ms: 15 * 60_000,
    max_keys: Some(DEFAULT_RATE_LIMITER_MAX_KEYS),
};

/// Default per-IP action-dispatcher rate limit (600 attempts / 15 min).
///
/// Matches `fuz_app`'s `default_action_ip_rate_limit`. The `Ip`-classed spine
/// methods — `peer/ping` and the four cell reads (`cell_get` / `cell_list` /
/// `cell_field_list` / `cell_item_list`) — are live at this bound on every
/// consumer that mounts them and wires this constant into its RPC/WS
/// transport state. Keyed by the canonicalized client IP, with an unresolved
/// address bucketing under `fuz_http::UNRESOLVED_CLIENT_IP` rather than
/// skipping the axis.
///
/// The bound is per-caller, so a deployment whose anonymous readers share one
/// NAT egress (a school lab, a CI fleet, an office) spends it collectively and
/// forks the constant per surface: 600 has run a 150-seat lab dry a few
/// minutes into a class period.
pub const DEFAULT_ACTION_IP_RATE_LIMIT: RateLimiterOptions = RateLimiterOptions {
    max_attempts: 600,
    window_ms: 15 * 60_000,
    max_keys: Some(DEFAULT_RATE_LIMITER_MAX_KEYS),
};

/// Retry-after reported while a key is at its cap only because of attempts
/// still in flight.
///
/// Those settle within a request's lifetime, so the earliest
/// moment worth retrying is the next second, not the oldest recorded
/// attempt's expiry. Mirrors `fuz_app`'s `IN_FLIGHT_RETRY_AFTER_SECONDS`.
pub const IN_FLIGHT_RETRY_AFTER_SECONDS: u64 = 1;

/// Result of a [`RateLimiter::check`] call.
///
/// Enum rather than `{ allowed: bool, retry_after: u64 }` so the
/// retry-after value is only present when meaningful — under the
/// previous struct shape `retry_after` was zero on the allowed path,
/// which let callers accidentally read it as if it carried information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    /// The request is under the cap.
    Allowed,
    /// The request is rate-limited; carries the seconds until the
    /// oldest active attempt expires.
    Limited { retry_after: u64 },
}

impl RateLimitResult {
    /// Convenience: `true` when the request is allowed.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// How long a password-surface reservation waits for a slot when the key is
/// at its cap only because of attempts still in flight, before answering
/// `429`. Mirrors `fuz_app`'s `RESERVATION_WAIT_MAX_MS`.
///
/// Counting attempts while they are in flight caps *successful* concurrent
/// attempts from one key too — a class behind one NAT logging in together.
/// Those attempts settle within a request's lifetime (an Argon2 verify plus the
/// work around it), so a short wait turns most of those refusals into a late
/// success, while a key at its cap on *recorded* attempts is still refused at
/// once.
pub const RESERVATION_WAIT_MAX: Duration = Duration::from_secs(5);

/// A reservation refusal: the key is at its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited {
    /// Seconds until a retry can be admitted.
    pub retry_after: u64,
}

impl RateLimited {
    const IN_FLIGHT: Self = Self {
        retry_after: IN_FLIGHT_RETRY_AFTER_SECONDS,
    };
}

/// Sliding-window rate limiter.
pub struct RateLimiter {
    options: RateLimiterOptions,
    state: Mutex<LimiterState>,
    /// Wakes a [`Self::reserve`] has taken (tests only), to pin that a settle
    /// wakes only its own key's waiters.
    #[cfg(test)]
    wakes: std::sync::atomic::AtomicUsize,
}

/// The locked state: the per-key entries, the id counter that tells an entry
/// from a later one under the same key, and the parked waiters per key.
struct LimiterState {
    entries: LruCache<String, Entry>,
    next_entry_id: u64,
    /// Reservations parked on a key at its in-flight cap, with the [`Notify`]
    /// that key's settles, records, and resets wake. Held outside the LRU so
    /// evicting a key's entry strands none of its waiters; removed when the
    /// key's last waiter leaves. Per key, so a settle wakes only the waiters
    /// it can admit or refuse — never every waiter on the limiter.
    waiters: HashMap<String, KeyWaiters>,
}

/// The reservations parked on one key and the [`Notify`] that wakes them.
struct KeyWaiters {
    notify: Arc<Notify>,
    count: u32,
}

impl LimiterState {
    /// The [`Notify`] for `key`'s parked waiters, if it has any.
    fn waker(&self, key: &str) -> Option<Arc<Notify>> {
        self.waiters
            .get(key)
            .map(|waiters| Arc::clone(&waiters.notify))
    }
}

/// Wake `key`'s parked waiters, found under the lock just released.
fn wake(waker: Option<Arc<Notify>>) {
    if let Some(waker) = waker {
        waker.notify_waiters();
    }
}

/// One key's attempts: recorded timestamps plus attempts reserved and not yet
/// settled. `id` is unique per entry for the limiter's lifetime, so a
/// reservation whose entry was evicted (LRU) or reset away never settles
/// against a newer entry under the same key.
struct Entry {
    id: u64,
    timestamps: Vec<u64>,
    in_flight: u32,
}

impl Entry {
    const fn is_idle(&self) -> bool {
        self.timestamps.is_empty() && self.in_flight == 0
    }
}

impl LimiterState {
    const fn new_entry(&mut self, timestamps: Vec<u64>) -> Entry {
        let id = self.next_entry_id;
        self.next_entry_id += 1;
        Entry {
            id,
            timestamps,
            in_flight: 0,
        }
    }
}

/// Where a key stands against its cap.
enum Load {
    /// Below the cap: an attempt can be admitted.
    Free,
    /// At the cap on recorded attempts alone; a retry waits for the oldest.
    Recorded { retry_after: u64 },
    /// At the cap only with the attempts in flight counted; one settling
    /// frees a slot.
    InFlight,
}

/// An attempt admitted by [`RateLimiter::try_reserve`] or
/// [`RateLimiter::reserve`], counted against the key's cap until settled.
///
/// [`record`](Self::record) keeps it as an attempt (a failure, on the
/// failure-counting surfaces); [`release`](Self::release) gives it back.
/// Dropping an unsettled reservation releases it, so an early return, an
/// error, or a cancelled request never leaks an in-flight slot — except
/// while [`charge_if_cancelled`](Self::charge_if_cancelled) runs its work, or
/// once [`arm_charge_on_drop`](Self::arm_charge_on_drop) has armed it: a
/// request dropped then is recorded. When the
/// key's entry was evicted or reset meanwhile, `record` still records (into
/// the key's current entry) and `release` is a no-op. A reservation made
/// against no limiter ([`try_reserve_optional`] / [`reserve_optional`] with
/// `None`) is inert: settling it does nothing.
#[must_use = "an unsettled reservation is released on drop; settle it with `record` or `release`"]
pub struct RateLimitReservation<'a> {
    limiter: Option<&'a RateLimiter>,
    key: String,
    entry_id: u64,
    settled: bool,
    /// Drop records instead of releasing — set while
    /// [`charge_if_cancelled`](Self::charge_if_cancelled) awaits its work, and
    /// from [`arm_charge_on_drop`](Self::arm_charge_on_drop) until settled.
    /// A panic unwinding past an armed reservation records it too: a panic is
    /// a server bug, and charging is the limiter's fail-closed answer.
    charge_on_drop: bool,
}

impl std::fmt::Debug for RateLimitReservation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is a username or an address; keep it out of logs, as the
        // limiter's own `Debug` does.
        f.debug_struct("RateLimitReservation")
            .field("limited", &self.limiter.is_some())
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl<'a> RateLimitReservation<'a> {
    const fn inert() -> Self {
        Self {
            limiter: None,
            key: String::new(),
            entry_id: 0,
            settled: true,
            charge_on_drop: false,
        }
    }

    fn admitted(limiter: &'a RateLimiter, key: &str, entry_id: u64) -> Self {
        Self {
            limiter: Some(limiter),
            key: key.to_owned(),
            entry_id,
            settled: false,
            charge_on_drop: false,
        }
    }

    /// Settle the reservation as a recorded attempt.
    pub fn record(mut self) {
        self.settle(true);
    }

    /// Settle the reservation without recording an attempt.
    pub fn release(mut self) {
        self.settle(false);
    }

    /// Await `work` with the reservation recorded if the request is dropped
    /// before `work` finishes; once it finishes, the reservation's drop
    /// behavior is restored to what it was before the wrap — releasing, unless
    /// [`arm_charge_on_drop`](Self::arm_charge_on_drop) armed it earlier — and
    /// the caller settles it by the outcome as usual.
    ///
    /// Login and the password change wrap their Argon2 verify in this. A
    /// dropped request future (a client that disconnects) does not stop
    /// started work — it runs to completion on the blocking pool, holding an
    /// Argon2 permit — so releasing the slot would let one address keep every
    /// permit busy while never being charged. The wrap covers the whole verify
    /// future, so a request dropped while its verify is started or still
    /// queued for a permit is charged alike. The twin's handler is never
    /// cancelled by a client abort, so every attempt that reaches the verify
    /// settles there; a cancelled one here has no outcome to settle by, and
    /// counts as a failure.
    pub async fn charge_if_cancelled<F: Future>(&mut self, work: F) -> F::Output {
        let armed = std::mem::replace(&mut self.charge_on_drop, true);
        let output = work.await;
        self.charge_on_drop = armed;
        output
    }

    /// Record the reservation if it is dropped unsettled from here on, for a
    /// handler whose spent work is followed by more awaits before it settles:
    /// signup arms both reservations before its Argon2 hash, so a request
    /// dropped during the hash, its wait for a permit, or the database steps
    /// after it is charged as a failure (see
    /// [`charge_if_cancelled`](Self::charge_if_cancelled) for why). Settling
    /// by [`record`](Self::record) or [`release`](Self::release) still decides
    /// the outcome, so a path that should cost nothing releases explicitly.
    pub const fn arm_charge_on_drop(&mut self) {
        self.charge_on_drop = true;
    }

    fn settle(&mut self, record: bool) {
        if self.settled {
            return;
        }
        self.settled = true;
        let Some(limiter) = self.limiter else {
            return;
        };
        let now = now_ms();
        let waker = {
            let mut state = limiter.state.lock();
            RateLimiter::settle_inner(
                &mut state,
                &self.key,
                self.entry_id,
                record,
                now,
                &limiter.options,
            );
            state.waker(&self.key)
        };
        wake(waker);
    }
}

impl Drop for RateLimitReservation<'_> {
    fn drop(&mut self) {
        self.settle(self.charge_on_drop);
    }
}

/// A [`RateLimiter::reserve`] parked on a key: counted in the key's waiters
/// until it leaves, by any path — a dropped (cancelled) future included,
/// through `Drop`.
struct WaitRegistration<'a> {
    limiter: &'a RateLimiter,
    key: &'a str,
    parked: bool,
}

impl WaitRegistration<'_> {
    fn leave(&mut self, state: &mut LimiterState) {
        if !std::mem::take(&mut self.parked) {
            return;
        }
        if let Some(waiters) = state.waiters.get_mut(self.key) {
            waiters.count = waiters.count.saturating_sub(1);
            if waiters.count == 0 {
                state.waiters.remove(self.key);
            }
        }
    }
}

impl Drop for WaitRegistration<'_> {
    fn drop(&mut self) {
        if self.parked {
            let mut state = self.limiter.state.lock();
            self.leave(&mut state);
        }
    }
}

/// [`RateLimiter::try_reserve`] against a limiter that may be absent.
///
/// An inert reservation when `limiter` is `None` (the consumer built it
/// through [`RateLimiterMode::DisabledForTesting`]), so a handler reserves and
/// settles the same way whether or not the surface is limited.
///
/// # Errors
///
/// [`RateLimited`] when the key is at its cap.
pub fn try_reserve_optional<'a>(
    limiter: Option<&'a RateLimiter>,
    key: &str,
) -> Result<RateLimitReservation<'a>, RateLimited> {
    limiter.map_or(Ok(RateLimitReservation::inert()), |limiter| {
        limiter.try_reserve(key)
    })
}

/// [`RateLimiter::reserve`] against a limiter that may be absent — an inert
/// reservation when `limiter` is `None`.
///
/// # Errors
///
/// [`RateLimited`] when the key is at its cap (see [`RateLimiter::reserve`]).
pub async fn reserve_optional<'a>(
    limiter: Option<&'a RateLimiter>,
    key: &str,
    max_wait: Duration,
) -> Result<RateLimitReservation<'a>, RateLimited> {
    match limiter {
        Some(limiter) => limiter.reserve(key, max_wait).await,
        None => Ok(RateLimitReservation::inert()),
    }
}

#[cfg(test)]
impl RateLimiter {
    /// Keys holding a parked-waiter slot (tests only): each is removed with its
    /// last waiter.
    fn waiter_keys(&self) -> usize {
        self.state.lock().waiters.len()
    }

    /// Reservations parked waiting on `key` (tests only).
    fn waiting_on(&self, key: &str) -> u32 {
        self.state
            .lock()
            .waiters
            .get(key)
            .map_or(0, |waiters| waiters.count)
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omits the key set (usernames / IPs are sensitive and
        // unbounded); `options` is the stable shape worth printing.
        f.debug_struct("RateLimiter")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Build a limiter from `options`.
    ///
    /// # Panics
    ///
    /// Panics if `options.max_keys` is `Some(0)` — a zero cap holds nothing,
    /// so it's a misconfiguration; pass `None` for unbounded.
    #[must_use]
    #[allow(clippy::panic)] // boot-time config guard: a zero cap is a misconfig, fail loud
    pub fn new(options: RateLimiterOptions) -> Self {
        // `None` is unbounded; `Some(n > 0)` caps at `n`. `Some(0)` is a
        // misconfigured cap that holds nothing — refuse it loudly (the TS twin
        // throws on a zero `LruMap`) rather than silently reopening the
        // unbounded-growth DoS this cap exists to close.
        let cache = match options.max_keys.map(NonZeroUsize::new) {
            None => LruCache::unbounded(),
            // `sparse`, not `new`: identical eviction semantics, but the
            // backing table grows lazily instead of reserving `cap` slots up
            // front — most limiters (login, dormant transport backstops) track
            // a handful of keys against a cap sized for an attack.
            Some(Some(cap)) => LruCache::sparse(cap),
            Some(None) => panic!(
                "RateLimiterOptions.max_keys must be None (unbounded) or a positive cap, not Some(0)"
            ),
        };
        Self {
            options,
            state: Mutex::new(LimiterState {
                entries: cache,
                next_entry_id: 0,
                waiters: HashMap::new(),
            }),
            #[cfg(test)]
            wakes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Number of currently-tracked keys (after any in-line pruning). Bounded
    /// by `options.max_keys` when set.
    #[cfg(test)]
    #[must_use]
    fn tracked_keys(&self) -> usize {
        self.state.lock().entries.len()
    }

    /// Check whether `key` is currently below the cap, counting recorded
    /// attempts and reserved ones still in flight. Prunes expired
    /// timestamps as a side effect so the backing map stays bounded
    /// under read-only traffic, and marks the key most-recently-used.
    ///
    /// A check followed by an awaited operation and then a [`record`] lets a
    /// concurrent burst past the cap; reserve with [`try_reserve`] instead.
    ///
    /// [`record`]: Self::record
    /// [`try_reserve`]: Self::try_reserve
    #[must_use]
    pub fn check(&self, key: &str) -> RateLimitResult {
        let now = now_ms();
        let mut state = self.state.lock();
        Self::check_inner(&mut state, key, now, &self.options)
    }

    /// Record an attempt for `key`. Prunes expired entries first and marks
    /// the key most-recently-used; evicts the least-recently-used key when a
    /// fresh key pushes the cache past `max_keys`.
    pub fn record(&self, key: &str) {
        let now = now_ms();
        let waker = {
            let mut state = self.state.lock();
            Self::record_inner(&mut state, key, now, &self.options);
            state.waker(key)
        };
        // A parked reservation re-decides: the key may now be at its cap on
        // recorded attempts, which refuses it at once.
        wake(waker);
    }

    /// Admit an attempt for `key` and count it in flight, in one locked step.
    ///
    /// The attempt counts against the cap — for this request and every
    /// concurrent one — until the returned reservation is settled: recorded
    /// as an attempt, or released. So no burst of concurrent requests gets
    /// more than `max_attempts` past the limiter between them. Never waits:
    /// for a caller that settles in the same step (the action gate);
    /// password surfaces use [`Self::reserve`].
    ///
    /// # Errors
    ///
    /// [`RateLimited`] when recorded plus in-flight attempts already reach
    /// the cap. Nothing is reserved then.
    pub fn try_reserve(&self, key: &str) -> Result<RateLimitReservation<'_>, RateLimited> {
        let now = now_ms();
        let mut state = self.state.lock();
        let entry_id = Self::try_reserve_inner(&mut state, key, now, &self.options)?;
        Ok(RateLimitReservation::admitted(self, key, entry_id))
    }

    /// [`Self::try_reserve`], waiting up to `max_wait` for a slot when the
    /// key is at its cap only because of attempts still in flight.
    ///
    /// Each settle (and record and reset) on the key wakes its waiters to
    /// re-decide — that key's only, so a settle costs nothing for waiters
    /// parked elsewhere: a freed slot is reserved; recorded attempts reaching the
    /// cap refuse at once with their real `retry_after`; reaching `max_wait`
    /// refuses with [`IN_FLIGHT_RETRY_AFTER_SECONDS`]. At most `max_attempts`
    /// reservations wait on one key — one more is refused at once — so a
    /// flood can't park requests without bound. A waiter dropped mid-wait (a
    /// cancelled request) leaves the key's waiter count as it found it. A
    /// waiter holds no place in a queue: each wake, every waiter re-decides,
    /// so one can lose every race for a freed slot until `max_wait` refuses
    /// it.
    ///
    /// # Errors
    ///
    /// [`RateLimited`] as described. Nothing is reserved then.
    pub async fn reserve(
        &self,
        key: &str,
        max_wait: Duration,
    ) -> Result<RateLimitReservation<'_>, RateLimited> {
        let deadline = tokio::time::Instant::now() + max_wait;
        let mut waiter = WaitRegistration {
            limiter: self,
            key,
            parked: false,
        };
        loop {
            let notify: Arc<Notify>;
            let mut notified;
            {
                let now = now_ms();
                let mut state = self.state.lock();
                match Self::load(&mut state, key, now, &self.options) {
                    Load::Free => {
                        waiter.leave(&mut state);
                        let entry_id = Self::admit(&mut state, key);
                        return Ok(RateLimitReservation::admitted(self, key, entry_id));
                    }
                    Load::Recorded { retry_after } => {
                        waiter.leave(&mut state);
                        return Err(RateLimited { retry_after });
                    }
                    Load::InFlight => {}
                }
                if !waiter.parked {
                    let parked = state.waiters.get(key).map_or(0, |waiters| waiters.count);
                    if parked >= self.options.max_attempts {
                        return Err(RateLimited::IN_FLIGHT);
                    }
                    state
                        .waiters
                        .entry(key.to_owned())
                        .or_insert_with(|| KeyWaiters {
                            notify: Arc::new(Notify::new()),
                            count: 0,
                        })
                        .count += 1;
                    waiter.parked = true;
                }
                // Registered for a wake before the lock is released, so a
                // settle landing between the read and the wait is not missed:
                // a settler changes the state under this lock and wakes after.
                notify = state.waker(key).unwrap_or_else(|| Arc::new(Notify::new()));
                notified = Box::pin(notify.notified());
                notified.as_mut().enable();
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                waiter.leave(&mut self.state.lock());
                return Err(RateLimited::IN_FLIGHT);
            }
            #[cfg(test)]
            self.wakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Where `key` stands against the cap, pruning expired timestamps first.
    fn load(state: &mut LimiterState, key: &str, now: u64, options: &RateLimiterOptions) -> Load {
        let max_attempts = options.max_attempts as usize;
        // A cap of zero refuses before reading the key: no entry is created
        // or promoted, and no reservation parks. The wait it names is the
        // whole window, at least a second.
        if max_attempts == 0 {
            return Load::Recorded {
                retry_after: options.window_ms.div_ceil(1_000).max(1),
            };
        }
        let cutoff = now.saturating_sub(options.window_ms);
        // `get_mut` marks the key most-recently-used — a key being actively
        // probed stays resident and can't be evicted to reset its budget.
        let Some(entry) = state.entries.get_mut(key) else {
            return Load::Free;
        };
        entry.timestamps.retain(|t| *t > cutoff);
        // A key with attempts in flight stays even with no live timestamp:
        // popping it would drop the count it carries.
        if entry.is_idle() {
            state.entries.pop(key);
            return Load::Free;
        }
        let recorded = entry.timestamps.len();
        match entry.timestamps.first() {
            Some(oldest) if recorded >= max_attempts => Load::Recorded {
                retry_after: oldest
                    .saturating_add(options.window_ms)
                    .saturating_sub(now)
                    .div_ceil(1_000),
            },
            _ if recorded + (entry.in_flight as usize) >= max_attempts => Load::InFlight,
            _ => Load::Free,
        }
    }

    fn check_inner(
        state: &mut LimiterState,
        key: &str,
        now: u64,
        options: &RateLimiterOptions,
    ) -> RateLimitResult {
        match Self::load(state, key, now, options) {
            Load::Free => RateLimitResult::Allowed,
            Load::Recorded { retry_after } => RateLimitResult::Limited { retry_after },
            Load::InFlight => RateLimitResult::Limited {
                retry_after: IN_FLIGHT_RETRY_AFTER_SECONDS,
            },
        }
    }

    /// Count one more attempt in flight on `key`, already found [`Load::Free`].
    fn admit(state: &mut LimiterState, key: &str) -> u64 {
        if let Some(entry) = state.entries.get_mut(key) {
            entry.in_flight += 1;
            return entry.id;
        }
        // A fresh key past `max_keys` evicts the least-recently-used entry,
        // in-flight attempts and all; their reservations settle as no-ops
        // (release) or into a fresh entry (record).
        let mut entry = state.new_entry(Vec::new());
        entry.in_flight = 1;
        let id = entry.id;
        state.entries.put(key.to_owned(), entry);
        id
    }

    fn record_inner(state: &mut LimiterState, key: &str, now: u64, options: &RateLimiterOptions) {
        let cutoff = now.saturating_sub(options.window_ms);
        if let Some(entry) = state.entries.get_mut(key) {
            entry.timestamps.retain(|t| *t > cutoff);
            entry.timestamps.push(now);
        } else {
            // A fresh key past `max_keys` evicts the least-recently-used entry.
            let entry = state.new_entry(vec![now]);
            state.entries.put(key.to_owned(), entry);
        }
    }

    fn try_reserve_inner(
        state: &mut LimiterState,
        key: &str,
        now: u64,
        options: &RateLimiterOptions,
    ) -> Result<u64, RateLimited> {
        if let RateLimitResult::Limited { retry_after } =
            Self::check_inner(state, key, now, options)
        {
            return Err(RateLimited { retry_after });
        }
        Ok(Self::admit(state, key))
    }

    fn settle_inner(
        state: &mut LimiterState,
        key: &str,
        entry_id: u64,
        record: bool,
        now: u64,
        options: &RateLimiterOptions,
    ) {
        // `get_mut` marks the key most-recently-used, as `record` does.
        match state.entries.get_mut(key) {
            Some(entry) if entry.id == entry_id => {
                entry.in_flight = entry.in_flight.saturating_sub(1);
                if record {
                    let cutoff = now.saturating_sub(options.window_ms);
                    entry.timestamps.retain(|t| *t > cutoff);
                    entry.timestamps.push(now);
                } else if entry.is_idle() {
                    state.entries.pop(key);
                }
            }
            // The reserved entry is gone — evicted, or reset with nothing in
            // flight but this — so there is no in-flight count to give back. A
            // record still counts, against whatever the key holds now.
            _ => {
                if record {
                    Self::record_inner(state, key, now, options);
                }
            }
        }
    }

    /// Clear all attempts for `key`.
    ///
    /// **Account-grain keys only.** Called after a successful auth to forgive a
    /// user's own typos, which is safe because the key *is* the account being
    /// attacked — clearing it requires that account's credential and can only
    /// widen the budget against an account the caller already holds.
    ///
    /// Never call this on an **IP-aggregate** key. That bucket is the
    /// distributed-spray backstop, and success on one account must not zero the
    /// budget shared by every other account reachable from the same IP;
    /// otherwise an attacker interleaves their own logins with guesses against
    /// arbitrary victims and sprays indefinitely from one address. The only
    /// success that records on an IP bucket is an open signup (charged like a
    /// failure); no success clears one, so with no reset each is a
    /// monotone-within-window counter that only time clears.
    ///
    /// Attempts still in flight on `key` (reserved by concurrent requests) are
    /// kept: a reset forgives what was recorded, not what is still running.
    pub fn reset(&self, key: &str) {
        let waker = {
            let mut state = self.state.lock();
            Self::reset_inner(&mut state, key);
            state.waker(key)
        };
        wake(waker);
    }

    fn reset_inner(state: &mut LimiterState, key: &str) {
        match state.entries.peek_mut(key) {
            Some(entry) if entry.in_flight > 0 => entry.timestamps.clear(),
            Some(_) => {
                state.entries.pop(key);
            }
            None => {}
        }
    }
}

/// Whether this process builds the spine's rate limiters.
///
/// A production server is always [`Self::Enforced`].
/// [`Self::DisabledForTesting`] is the cross-process harnesses' seam: they
/// drive many login round-trips from one host, and the per-IP bucket is
/// monotone within its window — a success never refunds it (see
/// [`RateLimiter::reset`]) — so a suite's failed-login cases accumulate until
/// every later login is refused. Twin of `fuz_app`'s `RateLimiterMode`
/// (`'enforced' | 'disabled_for_testing'`, `AppServerOptions.rate_limiters`),
/// where a limiter passed explicitly wins over the mode; here the mode decides
/// every limiter built through [`Self::limiter`].
///
/// **Test binaries only, by convention.** Only the `testing_*` crates construct
/// [`Self::DisabledForTesting`]; the variant is public, so nothing in the type
/// stops a production server from choosing it — `cargo xtask check-release`
/// audits crates and features, not this value. [`Self::limiter`] is the line of
/// defense: a process that nulls even one limiter announces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimiterMode {
    /// Build every limiter. The only mode a production server uses.
    Enforced,
    /// Build no limiters. Test binaries only.
    DisabledForTesting,
}

impl RateLimiterMode {
    /// The limiter for `options`, or `None` under
    /// [`Self::DisabledForTesting`].
    ///
    /// Consumers build every spine limiter through this rather than
    /// constructing one and nulling it afterwards, so a newly wired surface
    /// can't be left enforcing while the rest of the process is disabled —
    /// and so the first null announces itself.
    #[must_use]
    pub fn limiter(self, options: RateLimiterOptions) -> Option<Arc<RateLimiter>> {
        match self {
            Self::Enforced => Some(Arc::new(RateLimiter::new(options))),
            Self::DisabledForTesting => {
                warn_rate_limiters_disabled();
                None
            }
        }
    }
}

/// Announce, once per process, that rate limiting is off.
///
/// Deliberately loud and on stderr as well as the log: a deployment that
/// somehow reached this state is unprotected on every password-bearing route,
/// and that must be legible in the first lines of its output rather than
/// inferred from an absence.
fn warn_rate_limiters_disabled() {
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "!!! RATE LIMITERS DISABLED — test-only mode. A production server must never print this."
        );
        tracing::warn!("rate limiters disabled — test-only mode");
    });
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> RateLimiter {
        RateLimiter::new(RateLimiterOptions {
            max_attempts: 3,
            window_ms: 60_000,
            max_keys: None,
        })
    }

    /// Build a limiter with an explicit small key cap for the eviction tests.
    fn capped_limiter(max_attempts: u32, max_keys: usize) -> RateLimiter {
        RateLimiter::new(RateLimiterOptions {
            max_attempts,
            window_ms: 60_000,
            max_keys: Some(max_keys),
        })
    }

    #[test]
    fn fresh_key_is_allowed() {
        let l = limiter();
        assert_eq!(l.check("alice"), RateLimitResult::Allowed);
    }

    #[test]
    fn expired_attempts_age_out_of_window() {
        // The sliding-window core: attempts older than `now - window_ms` are
        // pruned, so a key at the cap becomes allowed once its attempts age out,
        // and a fully-expired key is popped (keeping the map bounded under
        // read-only traffic). Driven through `check_inner`/`record_inner` with an
        // explicit `now` — no clock dependency. Timestamps stay clear of the
        // `saturating_sub` floor so the boundary is the real cutoff, not 0.
        let opts = RateLimiterOptions {
            max_attempts: 2,
            window_ms: 1000,
            max_keys: None,
        };
        let mut state = unbounded_state();
        RateLimiter::record_inner(&mut state, "k", 2000, &opts);
        RateLimiter::record_inner(&mut state, "k", 2200, &opts);

        // Both attempts are within the 1000ms window at t=2500 → at the cap.
        assert!(matches!(
            RateLimiter::check_inner(&mut state, "k", 2500, &opts),
            RateLimitResult::Limited { .. }
        ));

        // At t=4000 both attempts are older than the window → allowed again, and
        // the now-empty key is evicted rather than left to leak.
        assert!(RateLimiter::check_inner(&mut state, "k", 4000, &opts).is_allowed());
        assert_eq!(
            state.entries.len(),
            0,
            "a fully-expired key must be popped, not leaked"
        );
    }

    fn unbounded_state() -> LimiterState {
        LimiterState {
            entries: LruCache::unbounded(),
            next_entry_id: 0,
            waiters: HashMap::new(),
        }
    }

    #[test]
    fn reservations_count_against_the_cap_until_settled() {
        let l = limiter(); // max 3
        let first = l.try_reserve("alice").expect("first");
        let second = l.try_reserve("alice").expect("second");
        let third = l.try_reserve("alice").expect("third");
        // Nothing is recorded yet: the cap is reached by attempts in flight.
        assert_eq!(
            l.try_reserve("alice").unwrap_err(),
            RateLimited {
                retry_after: IN_FLIGHT_RETRY_AFTER_SECONDS
            },
        );
        assert_eq!(
            l.check("alice"),
            RateLimitResult::Limited {
                retry_after: IN_FLIGHT_RETRY_AFTER_SECONDS
            },
            "check counts in-flight attempts too",
        );
        // Releasing gives the slot back.
        first.release();
        let fourth = l.try_reserve("alice").expect("a released slot is reusable");
        second.record();
        third.record();
        fourth.record();
        // Three recorded: limited until the oldest expires, not for one second.
        match l.try_reserve("alice") {
            Err(RateLimited { retry_after }) => assert!(retry_after > 1, "{retry_after}"),
            Ok(_) => panic!("three recorded attempts must refuse a fourth"),
        }
        assert!(l.try_reserve("bob").is_ok(), "other keys are unaffected");
    }

    #[test]
    fn a_dropped_reservation_is_released() {
        let l = limiter();
        for _ in 0..10 {
            let reservation = l.try_reserve("alice").expect("each drop frees the slot");
            drop(reservation);
        }
        assert!(l.check("alice").is_allowed());
        assert_eq!(
            l.tracked_keys(),
            0,
            "a released, empty key is not left behind"
        );
    }

    #[tokio::test]
    async fn a_reservation_dropped_inside_charge_if_cancelled_is_recorded() {
        let l = capped_limiter(1, 10);
        {
            let mut reservation = l.try_reserve("alice").expect("first");
            let work = reservation.charge_if_cancelled(std::future::pending::<()>());
            // poll the work once, then drop it and the reservation — a request
            // cancelled mid-verify
            assert!(futures::poll!(Box::pin(work)).is_pending());
        }
        assert!(
            l.try_reserve("alice").is_err(),
            "the cancelled attempt was recorded"
        );
    }

    #[tokio::test]
    async fn a_reservation_releases_on_drop_once_charge_if_cancelled_finishes() {
        let l = capped_limiter(1, 10);
        {
            let mut reservation = l.try_reserve("alice").expect("first");
            reservation.charge_if_cancelled(async {}).await;
        }
        assert!(
            l.check("alice").is_allowed(),
            "a finished wrap leaves drop releasing"
        );
        assert_eq!(l.tracked_keys(), 0);
    }

    #[tokio::test]
    async fn charge_if_cancelled_keeps_an_earlier_arm() {
        let l = capped_limiter(1, 10);
        {
            let mut reservation = l.try_reserve("alice").expect("first");
            reservation.arm_charge_on_drop();
            reservation.charge_if_cancelled(async {}).await;
        }
        assert!(
            l.try_reserve("alice").is_err(),
            "a finished wrap does not disarm a reservation armed before it"
        );
    }

    #[test]
    fn a_burst_of_reservations_admits_at_most_the_cap() {
        // The race the reservation closes: every request of a burst checks
        // before any records. With reservations, a burst of 2 × max across
        // threads admits exactly max.
        let l = Arc::new(limiter());
        let barrier = Arc::new(std::sync::Barrier::new(6));
        // Every thread is spawned before any is joined, so all six contend.
        let mut handles = Vec::new();
        for _ in 0..6 {
            let l = Arc::clone(&l);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let reservation = l.try_reserve("burst");
                // Hold every admitted reservation until all six tried.
                barrier.wait();
                reservation.map(RateLimitReservation::record).is_ok()
            }));
        }
        let admitted = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(admitted, 3);
        assert!(!l.check("burst").is_allowed());
    }

    #[test]
    fn a_key_with_attempts_in_flight_survives_pruning() {
        let opts = RateLimiterOptions {
            max_attempts: 2,
            window_ms: 1000,
            max_keys: None,
        };
        let mut state = unbounded_state();
        RateLimiter::record_inner(&mut state, "k", 2000, &opts);
        let id = RateLimiter::try_reserve_inner(&mut state, "k", 2100, &opts).expect("reserve");
        // Every recorded attempt has expired, but one is still in flight: the
        // entry must stay, or its count would be lost.
        assert!(RateLimiter::check_inner(&mut state, "k", 5000, &opts).is_allowed());
        assert_eq!(state.entries.len(), 1);
        RateLimiter::try_reserve_inner(&mut state, "k", 5000, &opts).expect("second reserve");
        assert!(
            matches!(
                RateLimiter::check_inner(&mut state, "k", 5000, &opts),
                RateLimitResult::Limited { .. }
            ),
            "both in-flight attempts still count",
        );
        RateLimiter::settle_inner(&mut state, "k", id, true, 5100, &opts);
        assert_eq!(state.entries.peek("k").map(|e| e.timestamps.len()), Some(1));
    }

    #[test]
    fn reset_keeps_attempts_in_flight() {
        let l = limiter(); // max 3
        l.record("alice");
        l.record("alice");
        let held = l.try_reserve("alice").expect("third slot");
        l.reset("alice");
        // The recorded two are forgiven; the in-flight one still counts.
        let a = l.try_reserve("alice").expect("forgiven slot");
        let b = l.try_reserve("alice").expect("forgiven slot");
        assert!(
            l.try_reserve("alice").is_err(),
            "three in flight is the cap"
        );
        drop((held, a, b));
        assert!(l.check("alice").is_allowed());
    }

    #[test]
    fn a_reservation_outliving_its_entry_settles_safely() {
        // max_keys 1: reserving a second key evicts the first, in-flight
        // count and all.
        let l = capped_limiter(2, 1);
        let evicted = l.try_reserve("a").expect("a");
        let _b = l.try_reserve("b").expect("b evicts a");
        // A newer entry under the same key, with its own reservation.
        let newer = l.try_reserve("a").expect("a again, evicting b");
        // Releasing the stale reservation must not give back the newer
        // entry's in-flight slot.
        evicted.release();
        let second = l.try_reserve("a").expect("one slot left");
        assert!(
            l.try_reserve("a").is_err(),
            "the stale release must not have freed a slot"
        );
        newer.record();
        second.record();
        assert!(!l.check("a").is_allowed());

        // A stale record still counts, against the key's current entry.
        let l = capped_limiter(1, 1);
        let stale = l.try_reserve("a").expect("a");
        let other = l.try_reserve("b").expect("b evicts a");
        other.release();
        stale.record();
        assert!(!l.check("a").is_allowed(), "the stale record still counts");
    }

    fn zero_cap_limiter(window_ms: u64) -> RateLimiter {
        RateLimiter::new(RateLimiterOptions {
            max_attempts: 0,
            window_ms,
            max_keys: Some(8),
        })
    }

    #[test]
    fn a_zero_cap_refuses_a_fresh_key_and_tracks_nothing() {
        let l = zero_cap_limiter(60_000);
        assert_eq!(l.check("k"), RateLimitResult::Limited { retry_after: 60 });
        assert_eq!(
            l.try_reserve("k").map(|_| ()),
            Err(RateLimited { retry_after: 60 })
        );
        assert_eq!(l.tracked_keys(), 0);
        // a window under a second still says to wait one
        let l = zero_cap_limiter(0);
        assert_eq!(l.check("k"), RateLimitResult::Limited { retry_after: 1 });
        let l = zero_cap_limiter(1);
        assert_eq!(l.check("k"), RateLimitResult::Limited { retry_after: 1 });
        let l = zero_cap_limiter(1_500);
        assert_eq!(l.check("k"), RateLimitResult::Limited { retry_after: 2 });
    }

    #[test]
    fn a_zero_cap_refuses_a_key_with_attempts_recorded() {
        let l = zero_cap_limiter(60_000);
        l.record("k");
        assert_eq!(l.check("k"), RateLimitResult::Limited { retry_after: 60 });
        assert!(l.try_reserve("k").is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_cap_reserve_refuses_without_waiting() {
        let l = zero_cap_limiter(60_000);
        let started = tokio::time::Instant::now();
        let refused = l.reserve("k", RESERVATION_WAIT_MAX).await.map(|_| ());
        assert_eq!(refused, Err(RateLimited { retry_after: 60 }));
        assert_eq!(tokio::time::Instant::now(), started);
        assert_eq!(l.waiter_keys(), 0);
        assert_eq!(l.tracked_keys(), 0);
    }

    #[test]
    fn a_cap_of_one_still_admits_one() {
        let l = RateLimiter::new(RateLimiterOptions {
            max_attempts: 1,
            window_ms: 60_000,
            max_keys: None,
        });
        assert!(l.check("k").is_allowed());
        l.try_reserve("k").expect("the one attempt").record();
        assert!(!l.check("k").is_allowed());
    }

    #[test]
    fn blocks_after_max_attempts() {
        let l = limiter();
        for _ in 0..3 {
            l.record("alice");
        }
        match l.check("alice") {
            RateLimitResult::Limited { retry_after } => assert!(retry_after > 0),
            RateLimitResult::Allowed => panic!("expected Limited after 3 records"),
        }
    }

    #[test]
    fn reset_clears_attempts() {
        let l = limiter();
        for _ in 0..3 {
            l.record("alice");
        }
        l.reset("alice");
        assert!(l.check("alice").is_allowed());
    }

    #[test]
    fn separate_keys_independent() {
        let l = limiter();
        for _ in 0..3 {
            l.record("alice");
        }
        assert!(!l.check("alice").is_allowed());
        assert!(l.check("bob").is_allowed());
    }

    #[test]
    fn caps_tracked_keys_and_evicts_lru() {
        let l = capped_limiter(3, 2);
        l.record("a"); // {a}
        l.record("b"); // {a, b} — a is LRU
        l.record("c"); // inserts c, evicts a (LRU) → {b, c}
        assert_eq!(l.tracked_keys(), 2, "key count is bounded by max_keys");
        // The evicted key starts fresh; the survivors are unaffected.
        assert!(l.check("a").is_allowed());
    }

    #[test]
    fn actively_probed_key_is_not_evicted() {
        // The security property: a key under active attack stays resident, so
        // an attacker can't churn fresh keys to force their own eviction and
        // reset their budget.
        let l = capped_limiter(3, 2);
        for _ in 0..3 {
            l.record("attacker"); // hits the cap
        }
        assert!(!l.check("attacker").is_allowed(), "attacker is at the cap");

        l.record("noise1"); // {attacker, noise1} — attacker now LRU
        let _ = l.check("attacker"); // re-marks attacker MRU → noise1 is LRU
        l.record("noise2"); // inserts noise2, evicts noise1 (not attacker)

        assert_eq!(l.tracked_keys(), 2);
        assert!(
            !l.check("attacker").is_allowed(),
            "attacker's budget survived the key churn",
        );
    }

    #[test]
    fn unbounded_when_max_keys_none() {
        let l = limiter(); // max_keys: None
        for i in 0..50 {
            l.record(&format!("k{i}"));
        }
        assert_eq!(l.tracked_keys(), 50, "None disables the cap");
    }

    #[test]
    #[should_panic(expected = "must be None (unbounded) or a positive cap")]
    fn some_zero_max_keys_panics() {
        let _ = RateLimiter::new(RateLimiterOptions {
            max_attempts: 3,
            window_ms: 60_000,
            max_keys: Some(0),
        });
    }

    #[test]
    fn defaults_carry_the_key_cap() {
        assert_eq!(
            DEFAULT_LOGIN_IP_RATE_LIMIT.max_keys,
            Some(DEFAULT_RATE_LIMITER_MAX_KEYS),
        );
        assert_eq!(
            DEFAULT_LOGIN_ACCOUNT_RATE_LIMIT.max_keys,
            Some(DEFAULT_RATE_LIMITER_MAX_KEYS),
        );
        assert_eq!(
            DEFAULT_ACTION_ACCOUNT_RATE_LIMIT.max_keys,
            Some(DEFAULT_RATE_LIMITER_MAX_KEYS),
        );
    }

    #[test]
    fn enforced_mode_builds_a_working_limiter() {
        // Not just `is_some()`: the enforced arm must hand back a limiter that
        // actually counts, since it is the only thing standing between a
        // production deployment and unbounded credential guessing.
        let limiter = RateLimiterMode::Enforced
            .limiter(RateLimiterOptions {
                max_attempts: 1,
                window_ms: 60_000,
                max_keys: None,
            })
            .expect("enforced builds a limiter");
        limiter.record("key");
        assert!(matches!(
            limiter.check("key"),
            RateLimitResult::Limited { .. }
        ));
    }

    #[test]
    fn disabled_mode_builds_no_limiter() {
        assert!(
            RateLimiterMode::DisabledForTesting
                .limiter(DEFAULT_LOGIN_IP_RATE_LIMIT)
                .is_none()
        );
    }

    /// Wait until `n` reservations are parked on `key`.
    async fn parked(l: &RateLimiter, key: &str, n: u32) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while l.waiting_on(key) != n {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the waiters park");
    }

    #[tokio::test]
    async fn reserve_waits_for_an_in_flight_slot() {
        let l = Arc::new(capped_limiter(2, 10));
        let a = l.try_reserve("k").expect("a");
        let _b = l.try_reserve("k").expect("b");
        assert!(l.try_reserve("k").is_err(), "try_reserve never waits");
        let waiter = {
            let l = Arc::clone(&l);
            tokio::spawn(async move {
                l.reserve("k", Duration::from_secs(30))
                    .await
                    .map(RateLimitReservation::release)
            })
        };
        parked(&l, "k", 1).await;
        a.release();
        assert_eq!(
            waiter.await.unwrap(),
            Ok(()),
            "the freed slot goes to the waiter"
        );
        assert_eq!(l.waiting_on("k"), 0);
    }

    #[tokio::test]
    async fn reserve_refuses_at_once_when_failures_fill_the_cap() {
        let l = Arc::new(capped_limiter(2, 10));
        let a = l.try_reserve("k").expect("a");
        let b = l.try_reserve("k").expect("b");
        let waiter = {
            let l = Arc::clone(&l);
            tokio::spawn(async move {
                l.reserve("k", Duration::from_secs(30))
                    .await
                    .map(RateLimitReservation::release)
            })
        };
        parked(&l, "k", 1).await;
        a.record();
        b.record();
        match waiter.await.unwrap() {
            Err(RateLimited { retry_after }) => assert!(retry_after > 1, "{retry_after}"),
            Ok(()) => panic!("two recorded failures fill a cap of two"),
        }
        assert_eq!(l.waiting_on("k"), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn reserve_times_out_with_the_in_flight_retry_after() {
        let l = capped_limiter(1, 10);
        let _held = l.try_reserve("k").expect("held");
        let started = tokio::time::Instant::now();
        assert_eq!(
            l.reserve("k", RESERVATION_WAIT_MAX).await.unwrap_err(),
            RateLimited::IN_FLIGHT
        );
        assert_eq!(started.elapsed(), RESERVATION_WAIT_MAX);
        assert_eq!(l.waiting_on("k"), 0, "a timed-out waiter leaves");
        assert_eq!(
            l.waiter_keys(),
            0,
            "and takes the key's waiter slot with it"
        );
    }

    #[tokio::test]
    async fn at_most_max_attempts_reservations_wait_on_a_key() {
        let l = Arc::new(capped_limiter(2, 10));
        let _a = l.try_reserve("k").expect("a");
        let _b = l.try_reserve("k").expect("b");
        let waiters: Vec<_> = (0..2)
            .map(|_| {
                let l = Arc::clone(&l);
                tokio::spawn(async move {
                    l.reserve("k", Duration::from_secs(30))
                        .await
                        .map(RateLimitReservation::release)
                })
            })
            .collect();
        parked(&l, "k", 2).await;
        // The cap is full of waiters: one more is refused without waiting.
        let refused = tokio::time::timeout(
            Duration::from_secs(1),
            l.reserve("k", Duration::from_secs(30)),
        )
        .await
        .expect("refused at once, not parked");
        assert_eq!(refused.unwrap_err(), RateLimited::IN_FLIGHT);
        assert_eq!(l.waiting_on("k"), 2);
        for waiter in waiters {
            waiter.abort();
        }
    }

    #[tokio::test]
    async fn a_cancelled_waiter_leaves_no_residue() {
        let l = Arc::new(capped_limiter(1, 10));
        let held = l.try_reserve("k").expect("held");
        let waiter = {
            let l = Arc::clone(&l);
            tokio::spawn(async move {
                l.reserve("k", Duration::from_secs(30))
                    .await
                    .map(RateLimitReservation::release)
            })
        };
        parked(&l, "k", 1).await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert_eq!(l.waiting_on("k"), 0, "the dropped waiter left the count");
        assert_eq!(l.waiter_keys(), 0, "and took the key's waiter slot with it");
        held.release();
        assert_eq!(l.tracked_keys(), 0, "nothing is left on the key");
    }

    #[tokio::test]
    async fn a_reset_wakes_a_waiter_its_forgiven_attempts_held_out() {
        let l = Arc::new(capped_limiter(3, 10));
        l.record("k");
        let _a = l.try_reserve("k").expect("a");
        let _b = l.try_reserve("k").expect("b");
        let waiter = {
            let l = Arc::clone(&l);
            tokio::spawn(async move {
                l.reserve("k", Duration::from_secs(30))
                    .await
                    .map(RateLimitReservation::release)
            })
        };
        parked(&l, "k", 1).await;
        l.reset("k");
        let admitted = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("the reset wakes the waiter")
            .unwrap();
        assert_eq!(
            admitted,
            Ok(()),
            "the forgiven attempt's slot goes to the waiter"
        );
    }

    #[tokio::test]
    async fn a_plain_record_refuses_a_waiter_at_once() {
        let l = Arc::new(capped_limiter(2, 10));
        let _a = l.try_reserve("k").expect("a");
        let _b = l.try_reserve("k").expect("b");
        let waiter = {
            let l = Arc::clone(&l);
            tokio::spawn(async move {
                l.reserve("k", Duration::from_secs(30))
                    .await
                    .map(RateLimitReservation::release)
            })
        };
        parked(&l, "k", 1).await;
        l.record("k");
        l.record("k");
        let refused = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("the record wakes the waiter")
            .unwrap();
        assert!(
            matches!(refused, Err(RateLimited { retry_after }) if retry_after > 1),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn a_settle_wakes_only_its_own_keys_waiters() {
        // A waiter parked on one key is not woken by settles, records, or
        // resets on another: a wake costs only the waiters it concerns.
        let l = Arc::new(capped_limiter(1, 10));
        let held_b = l.try_reserve("b").expect("b");
        let waiter = {
            let l = Arc::clone(&l);
            tokio::spawn(async move {
                l.reserve("b", Duration::from_secs(30))
                    .await
                    .map(RateLimitReservation::release)
            })
        };
        parked(&l, "b", 1).await;
        for _ in 0..20 {
            l.try_reserve("a").expect("a").release();
            l.try_reserve("a").expect("a").record();
            l.reset("a");
            l.record("a");
            l.reset("a");
            // Give a wrongly woken waiter the chance to run.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            l.wakes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "settles on another key woke the waiter"
        );
        held_b.release();
        assert_eq!(waiter.await.unwrap(), Ok(()));
        assert_eq!(l.wakes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn an_absent_limiter_reserves_an_inert_slot() {
        let reservation = try_reserve_optional(None, "k").expect("no limiter admits");
        reservation.record();
    }
}
