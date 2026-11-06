//! Per-method rate-limit class declared on an action spec entry.
//!
//! Surfaces declare a `rate_limit: Option<RateLimitClass>` field on
//! every entry; the dispatcher consults it before the handler runs,
//! gating per-method scraping pressure. Borne by the crate's one
//! canonical entry type, [`crate::auth_action_entry::AuthActionEntry`],
//! which every action-spec surface here declares its rows with.
//! Most entries are `None` (no gate); TS posture is selective — only
//! the handful of methods that represent an enumeration / scraping /
//! offer-spam surface carry `Some(Account)` (e.g.
//! `account_token_create`, `role_grant_offer_create`, every admin
//! method).
//!
//! The `fuz_actions` auth adapter copies an entry's class onto the
//! `ActionSpec::rate_limit` it builds, and `fuz_actions::perform_action`
//! gates it there (through `check_action_rate_limit`) with the deployment's
//! one limiter pair — a single per-account cap across the whole action
//! surface (matching TS `default_action_account_rate_limit`).
//!
//! Mirrors TS `RateLimitKey = z.enum(['ip', 'account', 'both'])` in
//! `fuz_app/src/lib/http/error_schemas.ts`. `None` on an entry skips
//! the gate entirely (no limiter consulted).

/// Per-method rate-limit class. See module docs.
///
/// - [`Self::Ip`]: check the IP limiter only.
/// - [`Self::Account`]: check the account limiter only.
/// - [`Self::Both`]: check both; either rejection blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitClass {
    Ip,
    Account,
    Both,
}

impl RateLimitClass {
    /// Wire-format name matching `fuz_app`'s `RateLimitKey` enum
    /// (`'ip' | 'account' | 'both'`).
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Account => "account",
            Self::Both => "both",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimitClass;

    #[test]
    fn names_match_the_twin_wire_strings() {
        assert_eq!(RateLimitClass::Ip.name(), "ip");
        assert_eq!(RateLimitClass::Account.name(), "account");
        assert_eq!(RateLimitClass::Both.name(), "both");
    }
}
