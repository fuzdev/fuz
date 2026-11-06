//! The credential deadline — the moment a resolved credential stops
//! authenticating, which a long-lived connection opened on it must not
//! outlive.
//!
//! A WebSocket or an SSE stream is authorized once, at open, and closed on
//! revocation by identity. Expiry has no revocation event: nothing is written
//! when a session or token passes its `expires_at`. So the resolve walk
//! computes the deadline once ([`ResolvedAuth::credential_deadline`]) and the
//! transport closes the connection when it arrives.
//!
//! The deadline is the earliest of what the credential carries:
//!
//! - **Session** — the signed cookie's embedded expiry and the
//!   `auth_session` row's `expires_at`.
//! - **API token** — the `api_token` row's `expires_at`; an eternal token
//!   (`expires_at IS NULL`) has none.
//! - **Daemon token** — none: it has no row and no expiry, and a rotation
//!   closes no connection.
//!
//! A row's expiry is read as **remaining time measured on the database
//! clock** ([`EXPIRES_IN_MS_SQL`], `expires_at - NOW()` in the same statement
//! that checks `expires_at > NOW()`), then anchored to this process's
//! monotonic clock — so a skew between the database's clock and the server's
//! moves no deadline. The cookie's expiry is a wall-clock second this server
//! signed, read against the same wall clock the cookie check reads.
//!
//! [`ResolvedAuth::credential_deadline`]: crate::ResolvedAuth::credential_deadline

use std::time::{Duration, Instant};

/// SQL expression for a row's remaining lifetime in milliseconds, measured on
/// the database clock — `NULL` when `expires_at` is `NULL` (an eternal API
/// token). `float8`, so the driver decodes it as `f64` on every engine.
pub const EXPIRES_IN_MS_SQL: &str = "(EXTRACT(EPOCH FROM (expires_at - NOW())) * 1000)::float8";

/// A row's remaining lifetime from [`EXPIRES_IN_MS_SQL`]'s value.
///
/// A negative or `NaN` value — a row the statement's own `expires_at > NOW()`
/// already refuses, read at the boundary — is zero; a value past what a
/// [`Duration`] holds saturates.
pub fn remaining_from_db_ms(ms: f64) -> Duration {
    // `f64::max` answers the non-NaN operand, so NaN reads as zero
    Duration::try_from_secs_f64(ms.max(0.0) / 1000.0).unwrap_or(Duration::MAX)
}

/// The deadline `now` plus the shortest of `remaining`, or `None` when no
/// entry carries one.
///
/// `None` is also the answer when the sum does not fit an [`Instant`] — a
/// lifetime that far out is no deadline a connection can meet.
pub fn credential_deadline_after(
    now: Instant,
    remaining: impl IntoIterator<Item = Option<Duration>>,
) -> Option<Instant> {
    let shortest = remaining.into_iter().flatten().min()?;
    now.checked_add(shortest)
}

#[cfg(test)]
mod tests {
    use super::{credential_deadline_after, remaining_from_db_ms};
    use std::time::{Duration, Instant};

    const DAY: Duration = Duration::from_hours(24);

    #[test]
    fn the_deadline_is_the_shortest_remaining_lifetime() {
        let now = Instant::now();
        assert_eq!(
            credential_deadline_after(now, [Some(30 * DAY), Some(Duration::from_secs(2))]),
            Some(now + Duration::from_secs(2)),
        );
        assert_eq!(
            credential_deadline_after(now, [Some(Duration::from_secs(2)), Some(30 * DAY)]),
            Some(now + Duration::from_secs(2)),
        );
        // an absent entry (an eternal token's row) never wins
        assert_eq!(
            credential_deadline_after(now, [None, Some(DAY)]),
            Some(now + DAY)
        );
    }

    #[test]
    fn no_lifetime_is_no_deadline() {
        assert_eq!(credential_deadline_after(Instant::now(), []), None);
        assert_eq!(
            credential_deadline_after(Instant::now(), [None, None]),
            None
        );
        // a lifetime past what an `Instant` holds is none a connection meets
        assert_eq!(
            credential_deadline_after(Instant::now(), [Some(Duration::MAX)]),
            None
        );
    }

    #[test]
    fn a_db_lifetime_reads_as_a_duration() {
        assert_eq!(remaining_from_db_ms(1500.0), Duration::from_millis(1500));
        // a token's longest lifetime is far past a tokio sleep's cap, and is
        // still read exactly
        assert_eq!(remaining_from_db_ms(36_500.0 * 86_400_000.0), 36_500 * DAY);
        assert_eq!(remaining_from_db_ms(-5.0), Duration::ZERO);
        assert_eq!(remaining_from_db_ms(f64::NAN), Duration::ZERO);
        assert_eq!(remaining_from_db_ms(f64::INFINITY), Duration::MAX);
    }
}
