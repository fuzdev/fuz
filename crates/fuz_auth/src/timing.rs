//! Constant-time floor primitives for auth-denial responses.
//!
//! Without a wall-clock floor on denial paths, an attacker can
//! distinguish cheap rejections (e.g. signup's `no_matching_invite` —
//! bails before Argon2 + tx) from expensive ones (`signup_conflict` —
//! Argon2 + tx + rollback) by response-time and use the gap as a
//! username-enumeration oracle. The shape here lets each handler pick
//! its own floor and jitter constants while sharing the
//! eager-evaluation property that keeps the budget running concurrently
//! with the work.
//!
//! ## Eager-evaluation invariant
//!
//! [`compute_fail_deadline`] captures `Instant::now()` at call time and
//! returns an absolute deadline. The handler then runs its work, and
//! on a denial path calls [`wait_for_deadline`], which delegates to
//! [`tokio::time::sleep_until`] — resolving immediately when the work
//! already exceeded the target, and otherwise padding up to it. Net
//! observed response time is therefore `max(work, deadline)`, not
//! `work + delay`.
//!
//! **Do not** restructure to construct the sleep future eagerly and
//! await later (`let f = sleep(d); … ; f.await`). That degrades to
//! `work + delay` and re-opens the enumeration oracle, because the
//! timer in `Sleep` starts at poll time. The `Instant`-and-defer split
//! used here is what preserves the property; the `start_paused` unit
//! tests pin it.
//!
//! ## Rate-limit posture
//!
//! 429 responses do **not** apply the floor — they short-circuit before
//! any work and the timing isn't an enumeration signal. Each handler
//! checks rate limits, computes the deadline, then proceeds; only the
//! classified-failure paths (403 / 409) wait on the deadline.

use std::sync::Once;

/// Which denial-timing floor a disabled-floor banner names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailFloor {
    Login,
    Signup,
}

/// Announce, once per process per floor, that a denial-timing floor is off.
///
/// Called by the router builders ([`crate::account_router::account_router`],
/// [`crate::signup_routes::signup_router`]) at assembly, when the configured
/// floor is `0`. A zero floor turns off the username-enumeration defense
/// described above, so — like the rate limiters'
/// [`crate::RateLimiterMode::DisabledForTesting`] banner — it is loud and on
/// stderr as well as the log: a deployment that copied a test binary's `0`
/// must show it in its first lines of output rather than leave it to be
/// inferred from an absence. A non-zero floor prints nothing.
pub(crate) fn warn_if_fail_floor_disabled(floor: FailFloor, floor_ms: u64) {
    static LOGIN_WARNED: Once = Once::new();
    static SIGNUP_WARNED: Once = Once::new();
    if floor_ms != 0 {
        return;
    }
    let (warned, label) = match floor {
        FailFloor::Login => (&LOGIN_WARNED, "LOGIN"),
        FailFloor::Signup => (&SIGNUP_WARNED, "SIGNUP"),
    };
    warned.call_once(|| {
        eprintln!(
            "!!! {label} FAILURE TIMING FLOOR DISABLED — test-only mode. A production server must never print this."
        );
        tracing::warn!(floor = ?floor, "failure timing floor disabled — test-only mode");
    });
}

/// Compute an absolute deadline `floor_ms` ± `jitter_ms` from now.
///
/// Returns `None` when `floor_ms == 0` — denial-time floor disabled,
/// used by integration tests where padding every failure path is
/// pointless. Uniform jitter prevents a stable clamp point from leaking
/// whenever a path occasionally exceeds the floor; OS RNG (via
/// `getrandom`) is overkill for unpredictability of the exact delay,
/// but it's the randomness primitive already on the spine.
#[must_use]
pub fn compute_fail_deadline(floor_ms: u64, jitter_ms: u64) -> Option<tokio::time::Instant> {
    if floor_ms == 0 {
        return None;
    }
    let total = if jitter_ms == 0 {
        floor_ms
    } else {
        let span = jitter_ms * 2 + 1;
        let mut bytes = [0u8; 8];
        // Failure here means the OS RNG is unavailable — unreachable
        // on supported platforms; fall back to the bare floor.
        let jitter = getrandom::fill(&mut bytes).map_or(0u64, |()| {
            (u64::from_le_bytes(bytes) % span).saturating_sub(jitter_ms)
        });
        floor_ms.saturating_add(jitter)
    };
    Some(tokio::time::Instant::now() + std::time::Duration::from_millis(total))
}

/// Pad until `deadline` if set; no-op when work already exceeded it
/// (`sleep_until` resolves immediately past its target).
pub async fn wait_for_deadline(deadline: Option<tokio::time::Instant>) {
    if let Some(d) = deadline {
        tokio::time::sleep_until(d).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_fail_deadline_returns_none_when_disabled() {
        assert!(compute_fail_deadline(0, 25).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn compute_fail_deadline_is_eager_and_lands_in_window() {
        // The deadline must be computed from `Instant::now()` at call
        // time, not at first poll — that's what makes the floor run
        // concurrently with the handler work below it. Verify by
        // capturing the deadline before advancing the clock past the
        // jitter ceiling and confirming `wait_for_deadline` resolves.
        let deadline = compute_fail_deadline(250, 25).expect("deadline");
        // Jitter window is [floor - jitter, floor + jitter] →
        // [225 ms, 275 ms] from now.
        let now = tokio::time::Instant::now();
        let elapsed = deadline.saturating_duration_since(now);
        assert!(
            elapsed >= std::time::Duration::from_millis(225)
                && elapsed <= std::time::Duration::from_millis(275),
            "deadline {elapsed:?} outside [225ms, 275ms]"
        );
        let fut = tokio::spawn(async move { wait_for_deadline(Some(deadline)).await });
        tokio::time::advance(std::time::Duration::from_millis(280)).await;
        fut.await.expect("task panic");
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_deadline_none_is_immediate() {
        wait_for_deadline(None).await;
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_deadline_past_target_is_immediate() {
        // Pretend work overshot the deadline: target is in the past
        // already. `sleep_until` resolves immediately.
        let past = tokio::time::Instant::now() - std::time::Duration::from_millis(500);
        wait_for_deadline(Some(past)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn jitter_distribution_stays_within_window() {
        // Sanity-check the saturating arithmetic — every call must land
        // inside [floor - jitter, floor + jitter]. Catches off-by-one,
        // underflow on `saturating_sub`, and any future regression that
        // widens or shifts the window.
        let floor = 100u64;
        let jitter = 25u64;
        let lo = std::time::Duration::from_millis(floor - jitter);
        let hi = std::time::Duration::from_millis(floor + jitter);
        for _ in 0..1000 {
            let deadline = compute_fail_deadline(floor, jitter).expect("deadline");
            let elapsed = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                elapsed >= lo && elapsed <= hi,
                "deadline {elapsed:?} outside [{lo:?}, {hi:?}]"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn zero_jitter_lands_exactly_on_floor() {
        // `jitter_ms == 0` skips the RNG path entirely. Result must
        // land precisely at `now + floor_ms`.
        let deadline = compute_fail_deadline(100, 0).expect("deadline");
        let elapsed = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert_eq!(elapsed, std::time::Duration::from_millis(100));
    }
}
