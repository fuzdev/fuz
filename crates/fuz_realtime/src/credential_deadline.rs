//! Waiting out a connection's credential deadline in bounded sleeps.
//!
//! A WebSocket or an SSE stream ends when the credential it was opened with
//! expires ([`fuz_auth::ResolvedAuth::credential_deadline`]). That deadline
//! can sit far out: a session lives 30 days and an API token up to 36,500. A
//! single tokio sleep holds about 2.2 years at most, so the wait is a loop of
//! sleeps of at most [`CREDENTIAL_DEADLINE_SLEEP_CAP`], each re-reading the
//! clock against the absolute deadline — the same shape as the TS twin's
//! timer, whose `setTimeout` fires at once past about 24.8 days.
//!
//! ## Suspend
//!
//! The deadline is a monotonic [`std::time::Instant`], and the monotonic clock
//! stops while the host is suspended — so a host asleep for a week would hold
//! a connection a week past its credential. The wait therefore also carries
//! the same deadline on the wall clock, which keeps running through a
//! suspend, and ends at whichever is reached first: after a resume it ends
//! within one sleep step, an hour at most. The wall deadline is taken when the
//! wait starts, from the time left on the monotonic one, so a skew between the
//! database's clock and the server's still moves nothing. A wall clock
//! stepped forward can end the wait early; the client reconnects through the
//! gates, which is the fail-closed side of the trade.

use std::time::{Duration, SystemTime};

use tokio::time::Instant;

/// The longest single sleep the deadline wait takes — one hour.
///
/// Far inside both tokio's sleep ceiling and the TS twin's `setTimeout`
/// ceiling, and short enough that a resume from suspend is noticed within it.
/// A longer deadline is reached through several.
pub const CREDENTIAL_DEADLINE_SLEEP_CAP: Duration = Duration::from_hours(1);

/// The next sleep toward `deadline` from `now`: what remains, capped at
/// [`CREDENTIAL_DEADLINE_SLEEP_CAP`], or `None` once the deadline is reached.
pub(crate) fn next_deadline_sleep(now: Instant, deadline: Instant) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(now)?;
    if remaining.is_zero() {
        return None;
    }
    Some(remaining.min(CREDENTIAL_DEADLINE_SLEEP_CAP))
}

/// Resolve when `deadline` has passed; never, for `None` (a credential with no
/// expiry). Cancel-safe: dropping it drops a sleep and nothing else.
pub(crate) async fn credential_deadline_reached(deadline: Option<std::time::Instant>) {
    credential_deadline_reached_on(deadline, SystemTime::now).await;
}

/// [`credential_deadline_reached`] against the wall clock `wall_now` reads —
/// the seam the suspend tests drive, since tokio's paused clock moves only
/// the monotonic one.
async fn credential_deadline_reached_on(
    deadline: Option<std::time::Instant>,
    wall_now: impl Fn() -> SystemTime,
) {
    let Some(deadline) = deadline else {
        return std::future::pending().await;
    };
    let deadline = Instant::from_std(deadline);
    // the same deadline on the wall clock, which a suspend does not stop;
    // `None` only past what a `SystemTime` holds, which no wake-up reaches
    let wall_deadline = wall_now().checked_add(deadline.saturating_duration_since(Instant::now()));
    while let Some(step) = next_deadline_sleep(Instant::now(), deadline) {
        if wall_deadline.is_some_and(|wall_deadline| wall_now() >= wall_deadline) {
            return;
        }
        tokio::time::sleep(step).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CREDENTIAL_DEADLINE_SLEEP_CAP, credential_deadline_reached, credential_deadline_reached_on,
        next_deadline_sleep,
    };
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};
    use tokio::time::Instant;

    const HOUR: Duration = Duration::from_hours(1);
    const DAY: Duration = Duration::from_hours(24);

    /// Every sleep is bounded, however far out the deadline: a session's
    /// 30 days and an API token's 36,500 are each reached through capped
    /// steps, never one sleep past tokio's ceiling.
    #[test]
    fn a_far_deadline_is_slept_toward_in_capped_steps() {
        assert_eq!(CREDENTIAL_DEADLINE_SLEEP_CAP, HOUR);
        let now = Instant::now();
        for lifetime in [30 * DAY, 36_500 * DAY] {
            assert_eq!(
                next_deadline_sleep(now, now + lifetime),
                Some(CREDENTIAL_DEADLINE_SLEEP_CAP),
                "a {lifetime:?} deadline sleeps one capped step at a time"
            );
        }
        assert_eq!(
            next_deadline_sleep(now, now + Duration::from_secs(2)),
            Some(Duration::from_secs(2))
        );
        assert_eq!(next_deadline_sleep(now, now), None);
        assert_eq!(next_deadline_sleep(now + DAY, now), None);
    }

    /// Spawn the wait on `deadline`, then step the paused clock a day at a
    /// time for `days`, yielding after each step so a due sleep runs: `true`
    /// once the wait has resolved.
    async fn reached_after_days(deadline: Option<std::time::Instant>, days: u32) -> bool {
        let wait = tokio::spawn(credential_deadline_reached(deadline));
        for _ in 0..days {
            tokio::time::advance(DAY).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            if wait.is_finished() {
                return true;
            }
        }
        false
    }

    /// A 30-day deadline is not met a day in, nor at day 29, and is met once
    /// it passes.
    #[tokio::test(start_paused = true)]
    async fn a_30_day_deadline_fires_at_the_deadline_not_before() {
        let deadline = std::time::Instant::now() + 30 * DAY;
        let wait = tokio::spawn(credential_deadline_reached(Some(deadline)));
        tokio::time::advance(29 * DAY).await;
        tokio::task::yield_now().await;
        assert!(!wait.is_finished(), "fired before its deadline");
        tokio::time::advance(DAY + Duration::from_secs(1)).await;
        tokio::time::timeout(Duration::from_secs(1), wait)
            .await
            .expect("fired once the deadline passed")
            .expect("the wait does not panic");
    }

    /// An API token's longest lifetime is past what one tokio sleep holds —
    /// tokio clamps a longer sleep to about 2.2 years, so a single sleep with
    /// no re-check would fire then. Three years in, nothing has fired. (A loop
    /// of uncapped sleeps re-reads the clock and does not fire early either;
    /// `a_far_deadline_is_slept_toward_in_capped_steps` pins the step size.)
    #[tokio::test(start_paused = true)]
    async fn a_36_500_day_deadline_does_not_fire_early() {
        let deadline = std::time::Instant::now() + 36_500 * DAY;
        assert!(!reached_after_days(Some(deadline), 3 * 366).await);
    }

    /// No deadline never resolves.
    #[tokio::test(start_paused = true)]
    async fn no_deadline_never_fires() {
        assert!(!reached_after_days(None, 40).await);
    }

    /// A wall clock the test moves by hand, for the wait's `wall_now`.
    #[derive(Clone)]
    struct WallClock(Arc<Mutex<SystemTime>>);

    impl WallClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(
                SystemTime::UNIX_EPOCH + 1_000_000 * DAY,
            )))
        }
        fn now(&self) -> SystemTime {
            *self.0.lock().expect("the test clock is not poisoned")
        }
        fn advance(&self, by: Duration) {
            *self.0.lock().expect("the test clock is not poisoned") += by;
        }
    }

    /// Step both clocks by `by`, as a host awake for that long sees them.
    async fn awake(wall: &WallClock, by: Duration) {
        wall.advance(by);
        tokio::time::advance(by).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    /// A suspend stops the monotonic clock and not the wall clock. A 30-day
    /// deadline with a suspend of most of 10 days in it is met on the wall
    /// clock — at the first wake-up after the resume, an hour at most, the
    /// moment the wall clock reaches it — not 10 days late on the monotonic
    /// one.
    #[tokio::test(start_paused = true)]
    async fn a_suspend_does_not_extend_the_deadline() {
        let wall = WallClock::new();
        // anchored on the paused clock, so the boundaries below are exact
        let deadline = Instant::now().into_std() + 30 * DAY;
        let wait = tokio::spawn({
            let wall = wall.clone();
            async move { credential_deadline_reached_on(Some(deadline), move || wall.now()).await }
        });
        tokio::task::yield_now().await;
        awake(&wall, 20 * DAY).await;
        assert!(!wait.is_finished(), "fired before either deadline");
        // the host sleeps an hour short of 10 days: only the wall clock moves,
        // so the next wake-up lands on the wall deadline exactly
        wall.advance(239 * HOUR);
        tokio::task::yield_now().await;
        assert!(!wait.is_finished(), "the wait wakes only on its own sleep");
        // a minute short of a step after the resume, then the step
        awake(&wall, Duration::from_mins(59)).await;
        assert!(!wait.is_finished(), "fired before its next wake-up");
        awake(&wall, Duration::from_secs(60)).await;
        assert!(
            wait.is_finished(),
            "the first wake-up after the resume meets the wall deadline"
        );
    }

    /// The wall clock stepped back — by NTP, by hand — moves nothing: the
    /// monotonic deadline still ends the wait on time.
    #[tokio::test(start_paused = true)]
    async fn a_wall_clock_stepped_back_does_not_extend_the_deadline() {
        let wall = WallClock::new();
        let deadline = Instant::now().into_std() + 2 * DAY;
        let wait = tokio::spawn({
            let wall = wall.clone();
            async move { credential_deadline_reached_on(Some(deadline), move || wall.now()).await }
        });
        tokio::task::yield_now().await;
        *wall.0.lock().expect("the test clock is not poisoned") -= 30 * DAY;
        awake(&wall, Duration::from_secs(2 * 24 * 60 * 60 - 1)).await;
        assert!(!wait.is_finished(), "fired before its deadline");
        awake(&wall, Duration::from_secs(1)).await;
        assert!(wait.is_finished(), "the monotonic deadline ends the wait");
    }
}
