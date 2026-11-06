//! Per-action rate-limit gate, and the limiter pair it charges
//! ([`ActionRateLimits`]).
//!
//! Consults the IP and account limiters per the [`RateLimitClass`] a spec
//! declares on [`crate::ActionSpec::rate_limit`], surfacing `rate_limited`
//! on rejection. Mirrors the rate-limit step of TS `perform_action.ts` with
//! the same atomic-per-request semantics: a request rejected on one
//! axis doesn't burn budget on the other.
//!
//! [`fn@crate::perform_action`] is the one caller on the dispatch path — every
//! spec, the auth-family specs [`crate::auth_adapter`] builds included, is
//! gated there, after authorization and ahead of params validation. One
//! shared limiter pair per deployment caps the whole action surface
//! (matches TS `default_action_account_rate_limit`).

use std::sync::Arc;

use fuz_auth::{
    RateLimitClass, RateLimiter, RateLimiterMode, RateLimiterOptions, try_reserve_optional,
};
use fuz_http::{JsonrpcError, rate_limited};
use serde_json::json;

/// The per-account and per-IP action limiters, built once.
///
/// A server shares them across the dispatcher on both transports
/// ([`crate::ActionDispatch`]), which charges every
/// spec declaring `ActionSpec::rate_limit` through [`check_action_rate_limit`]
/// — consumer specs and the spine's auth spec set alike. One budget per caller
/// across all of them — the twin of `fuz_app`'s `create_app_server` threading
/// one `action_account_rate_limiter` / `action_ip_rate_limiter` pair into
/// every transport.
///
/// Built only through a [`RateLimiterMode`], so both axes are present or both
/// are absent: a registered spec's rate class can never name an axis left
/// `None` while the rest of the process enforces, and a disabled pair
/// announces itself through the mode's banner.
#[derive(Clone, Debug)]
pub struct ActionRateLimits {
    account: Option<Arc<RateLimiter>>,
    ip: Option<Arc<RateLimiter>>,
}

impl ActionRateLimits {
    /// Both limiters at the spine defaults
    /// ([`fuz_auth::DEFAULT_ACTION_ACCOUNT_RATE_LIMIT`],
    /// [`fuz_auth::DEFAULT_ACTION_IP_RATE_LIMIT`]), the bounds `fuz_app`'s
    /// defaults carry.
    #[must_use]
    pub fn defaults(mode: RateLimiterMode) -> Self {
        Self::new(
            mode,
            fuz_auth::DEFAULT_ACTION_ACCOUNT_RATE_LIMIT,
            fuz_auth::DEFAULT_ACTION_IP_RATE_LIMIT,
        )
    }

    /// Both limiters at the given bounds — for a server that tunes them, or a
    /// test binary that caps them so a suite reaches the throttle quickly.
    #[must_use]
    pub fn new(mode: RateLimiterMode, account: RateLimiterOptions, ip: RateLimiterOptions) -> Self {
        Self {
            account: mode.limiter(account),
            ip: mode.limiter(ip),
        }
    }

    /// The per-account limiter, `None` when disabled for testing.
    #[must_use]
    pub fn account(&self) -> Option<Arc<RateLimiter>> {
        self.account.clone()
    }

    /// The per-IP limiter, `None` when disabled for testing.
    #[must_use]
    pub fn ip(&self) -> Option<Arc<RateLimiter>> {
        self.ip.clone()
    }
}

/// Per-action rate-limit gate.
///
/// Consults the IP / account limiters per
/// the declared [`RateLimitClass`] and surfaces [`rate_limited`] on
/// rejection. Throttle-requests semantics (record on every successful
/// pass) — mirrors the rate-limit step of TS `perform_action.ts`.
///
/// Returns `Ok(())` when:
/// - `class` is `None` (no gate),
/// - the relevant limiter arg is `None` (consumer chose to skip).
///
/// The IP axis keys [`fuz_http::rate_limit_ip_key`] of `ip_key` — an IPv6
/// client buckets with its whole `/64` — while the caller keeps the full
/// address for everything else.
///
/// An unresolved `ip_key` does **not** skip the IP axis — it buckets under
/// [`fuz_http::UNRESOLVED_CLIENT_IP`], the same literal the twin's
/// `get_client_ip` substitutes, so a caller whose address the middleware could
/// not produce is throttled rather than exempt.
///
/// A missing `account_id` does not skip the account axis either — it buckets
/// under the empty key, one bucket shared by every accountless caller. No
/// compiled spec gets here that way: [`crate::ActionRegistry::compile`]
/// refuses an account-keyed class on an account axis that is not `Required`,
/// and the dispatcher's 401 answers an accountless caller of a
/// required-account spec before this gate. The shared bucket is what a direct
/// caller that passes `None` anyway gets — throttled together, never exempt.
/// The twin's `perform_action.ts` skips the account axis there instead, behind
/// the same registration check.
///
/// Returns `Err(rate_limited(...))` when any consulted limiter rejects.
///
/// # Errors
///
/// Returns the `rate_limited` JSON-RPC error with a `retry_after`
/// `data` payload when any consulted limiter rejects.
pub fn check_action_rate_limit(
    class: Option<RateLimitClass>,
    account_id: Option<&uuid::Uuid>,
    ip_key: Option<&str>,
    account_limiter: Option<&RateLimiter>,
    ip_limiter: Option<&RateLimiter>,
) -> Result<(), JsonrpcError> {
    let Some(class) = class else { return Ok(()) };

    // The account key is the id's canonical rendering, formatted zero-alloc
    // into a stack buffer and only once a class is declared — the dispatchers
    // call this gate on every message, and most specs carry no class at all.
    // A missing account keys the empty string: the shared bucket the doc
    // describes, unreachable through a compiled spec.
    let mut account_key_buf = uuid::Uuid::encode_buffer();
    let account_key: &str =
        account_id.map_or("", |id| id.hyphenated().encode_lower(&mut account_key_buf));

    // Materialize the active (limiter, key) pairs per axis. `None`
    // means "this axis isn't checked" — either the class skips it or the
    // limiter wasn't configured.
    // The IP key is built only once an IP-keyed class meets a limiter.
    let ip_axis: Option<(&RateLimiter, String)> = match class {
        RateLimitClass::Ip | RateLimitClass::Both => ip_limiter.map(|l| {
            (
                l,
                fuz_http::rate_limit_ip_key(ip_key.unwrap_or(fuz_http::UNRESOLVED_CLIENT_IP)),
            )
        }),
        RateLimitClass::Account => None,
    };
    let account_axis: Option<(&RateLimiter, &str)> = match class {
        RateLimitClass::Account | RateLimitClass::Both => account_limiter.map(|l| (l, account_key)),
        RateLimitClass::Ip => None,
    };

    // Phase 1: reserve both axes, surface the first rejection. Matches
    // the TS rate-limit step — IP then account, no record on rejection.
    // Reserving rather than checking admits and counts the request in one
    // locked step per axis, so concurrent dispatches on other threads can't
    // all pass a check before any records (the TS step runs synchronously, so
    // it has no such gap). A rejection on the account axis drops — releases —
    // the IP reservation.
    // Never waits (`try_reserve`): the gate settles in the same step, so a
    // refusal is only ever a real one.
    let (ip_axis_limiter, ip_axis_key) = ip_axis.unzip();
    let ip_reservation =
        try_reserve_optional(ip_axis_limiter, ip_axis_key.as_deref().unwrap_or_default())
            .map_err(|limited| rate_limited_err(limited.retry_after))?;
    let (account_axis_limiter, account_axis_key) = account_axis.unzip();
    let account_reservation =
        try_reserve_optional(account_axis_limiter, account_axis_key.unwrap_or_default())
            .map_err(|limited| rate_limited_err(limited.retry_after))?;

    // Phase 2: both axes admitted — record on each. Atomic-per-request
    // semantics: a request rejected on one axis doesn't burn budget on
    // the other (matches the TS rate-limit step's record phase).
    ip_reservation.record();
    account_reservation.record();
    Ok(())
}

fn rate_limited_err(retry_after: u64) -> JsonrpcError {
    rate_limited("rate limited", Some(json!({"retry_after": retry_after})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_http::JsonrpcErrorCode;

    // Distinct account-id fixtures (the gate takes the account id and
    // formats the key itself).
    fn alice() -> uuid::Uuid {
        uuid::Uuid::from_u128(0xA)
    }
    fn bob() -> uuid::Uuid {
        uuid::Uuid::from_u128(0xB)
    }

    fn limiter(max: u32) -> RateLimiter {
        RateLimiter::new(RateLimiterOptions {
            max_attempts: max,
            window_ms: 60_000,
            max_keys: None,
        })
    }

    #[test]
    fn no_class_is_noop() {
        let acct = limiter(3);
        let ip = limiter(3);
        // Even with limiters present, None class bypasses entirely.
        assert!(
            check_action_rate_limit(
                None,
                Some(&alice()),
                Some("1.1.1.1"),
                Some(&acct),
                Some(&ip)
            )
            .is_ok()
        );
    }

    #[test]
    fn account_class_blocks_after_max() {
        let acct = limiter(3);
        for _ in 0..3 {
            check_action_rate_limit(
                Some(RateLimitClass::Account),
                Some(&alice()),
                None,
                Some(&acct),
                None,
            )
            .expect("first 3 calls allowed");
        }
        let err = check_action_rate_limit(
            Some(RateLimitClass::Account),
            Some(&alice()),
            None,
            Some(&acct),
            None,
        )
        .expect_err("4th call rejected");
        assert_eq!(err.code, JsonrpcErrorCode::RateLimited);
        assert_eq!(err.message, "rate limited");
        let data = err.data.expect("data carries retry_after");
        let retry_after = data["retry_after"].as_u64().expect("retry_after is u64");
        assert!(retry_after > 0, "retry_after must be positive");
    }

    #[test]
    fn account_class_isolates_keys() {
        let acct = limiter(2);
        for _ in 0..2 {
            check_action_rate_limit(
                Some(RateLimitClass::Account),
                Some(&alice()),
                None,
                Some(&acct),
                None,
            )
            .expect("alice allowed");
        }
        check_action_rate_limit(
            Some(RateLimitClass::Account),
            Some(&alice()),
            None,
            Some(&acct),
            None,
        )
        .expect_err("alice now blocked");
        check_action_rate_limit(
            Some(RateLimitClass::Account),
            Some(&bob()),
            None,
            Some(&acct),
            None,
        )
        .expect("bob still allowed (independent key)");
    }

    /// A missing account is a shared bucket, not an exemption: the registry
    /// keeps a compiled spec from getting here, and a direct caller that does
    /// is throttled with every other accountless one.
    #[test]
    fn account_class_buckets_a_missing_account_together() {
        let acct = limiter(2);
        for _ in 0..2 {
            check_action_rate_limit(Some(RateLimitClass::Account), None, None, Some(&acct), None)
                .expect("first 2 calls allowed");
        }
        let err =
            check_action_rate_limit(Some(RateLimitClass::Both), None, None, Some(&acct), None)
                .expect_err("a third accountless call shares the exhausted bucket");
        assert_eq!(err.code, JsonrpcErrorCode::RateLimited);
        check_action_rate_limit(
            Some(RateLimitClass::Account),
            Some(&alice()),
            None,
            Some(&acct),
            None,
        )
        .expect("an account keeps its own bucket");
    }

    #[test]
    fn ip_class_blocks_after_max() {
        let ip = limiter(2);
        for _ in 0..2 {
            check_action_rate_limit(
                Some(RateLimitClass::Ip),
                Some(&alice()),
                Some("1.1.1.1"),
                None,
                Some(&ip),
            )
            .expect("first 2 calls allowed");
        }
        let err = check_action_rate_limit(
            Some(RateLimitClass::Ip),
            Some(&alice()),
            Some("1.1.1.1"),
            None,
            Some(&ip),
        )
        .expect_err("3rd call rejected on IP axis");
        assert_eq!(err.code, JsonrpcErrorCode::RateLimited);
    }

    /// IPv6 clients bucket by their `/64`: another address in the same `/64`
    /// shares the budget, one in the next `/64` has its own.
    #[test]
    fn ip_class_buckets_ipv6_by_64() {
        let ip = limiter(1);
        let gate = |addr: &str| {
            check_action_rate_limit(
                Some(RateLimitClass::Ip),
                Some(&alice()),
                Some(addr),
                None,
                Some(&ip),
            )
        };
        gate("2001:db8:1:2::1").expect("first call allowed");
        let err = gate("2001:db8:1:2:8000::5").expect_err("same /64, same bucket");
        assert_eq!(err.code, JsonrpcErrorCode::RateLimited);
        gate("2001:db8:1:3::1").expect("the next /64 has its own bucket");
        assert!(!ip.check("2001:db8:1:2::/64").is_allowed());
    }

    /// An unresolved IP is a bucket, not an exemption. The twin's
    /// `get_client_ip` substitutes `'unknown'` and throttles under it, so a
    /// caller whose address the middleware could not produce is held to the
    /// same budget rather than passing the gate unbounded.
    #[test]
    fn ip_class_buckets_an_unresolved_key_under_the_sentinel() {
        let ip = limiter(2);
        for _ in 0..2 {
            check_action_rate_limit(
                Some(RateLimitClass::Ip),
                Some(&alice()),
                None, // no client_ip resolved
                None,
                Some(&ip),
            )
            .expect("first 2 calls allowed");
        }
        let err = check_action_rate_limit(
            Some(RateLimitClass::Ip),
            Some(&alice()),
            None,
            None,
            Some(&ip),
        )
        .expect_err("3rd call rejected on the IP axis");
        assert_eq!(err.code, JsonrpcErrorCode::RateLimited);
    }

    /// The sentinel is one shared bucket, so an unresolved caller and an
    /// explicit `"unknown"` land together — which is what the twin does too,
    /// its `client_ip` being an ordinary string.
    #[test]
    fn the_unresolved_sentinel_is_the_same_bucket_as_its_literal() {
        let ip = limiter(1);
        check_action_rate_limit(
            Some(RateLimitClass::Ip),
            Some(&alice()),
            Some(fuz_http::UNRESOLVED_CLIENT_IP),
            None,
            Some(&ip),
        )
        .expect("first call allowed");
        let err = check_action_rate_limit(
            Some(RateLimitClass::Ip),
            Some(&alice()),
            None,
            None,
            Some(&ip),
        )
        .expect_err("the unresolved caller shares the sentinel's budget");
        assert_eq!(err.code, JsonrpcErrorCode::RateLimited);
    }

    /// An unset limiter is still the consumer's opt-out — the sentinel closes
    /// the missing-key hole, not the missing-limiter one.
    #[test]
    fn ip_class_skips_when_no_ip_limiter() {
        for _ in 0..5 {
            check_action_rate_limit(Some(RateLimitClass::Ip), Some(&alice()), None, None, None)
                .expect("no limiter wired — no gate");
        }
    }

    #[test]
    fn both_class_either_axis_can_reject() {
        let acct = limiter(10);
        let ip = limiter(2);
        for _ in 0..2 {
            check_action_rate_limit(
                Some(RateLimitClass::Both),
                Some(&alice()),
                Some("1.1.1.1"),
                Some(&acct),
                Some(&ip),
            )
            .expect("first 2 allowed (under both caps)");
        }
        // IP cap hits first (2 < 10).
        let err = check_action_rate_limit(
            Some(RateLimitClass::Both),
            Some(&alice()),
            Some("1.1.1.1"),
            Some(&acct),
            Some(&ip),
        )
        .expect_err("3rd call rejected by IP axis");
        assert_eq!(err.code, JsonrpcErrorCode::RateLimited);
    }

    #[test]
    fn missing_limiter_arg_skips_axis() {
        // class = Account but no account limiter → no gating happens.
        for _ in 0..10 {
            check_action_rate_limit(
                Some(RateLimitClass::Account),
                Some(&alice()),
                None,
                None,
                None,
            )
            .expect("no limiter → no gate");
        }
    }

    #[test]
    fn both_axes_follow_the_mode() {
        let enforced = ActionRateLimits::defaults(RateLimiterMode::Enforced);
        assert!(enforced.account().is_some() && enforced.ip().is_some());
        let disabled = ActionRateLimits::defaults(RateLimiterMode::DisabledForTesting);
        assert!(disabled.account().is_none() && disabled.ip().is_none());
    }

    #[test]
    fn clones_share_one_budget() {
        let limits = ActionRateLimits::defaults(RateLimiterMode::Enforced);
        let copy = limits.clone();
        assert!(Arc::ptr_eq(
            &limits.account().expect("enforced"),
            &copy.account().expect("enforced"),
        ));
    }
}
