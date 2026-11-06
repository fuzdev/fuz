//! `CredentialType` — how the request was authenticated — and
//! [`CredentialGate`], the per-action allowlist over it.
//!
//! Mirrors `fuz_app`'s `credential_type` context key:
//! - `Session` — cookie-based session (`fuz_session`)
//! - `ApiToken` — `Authorization: Bearer <token>` looked up in
//!   `api_token` table
//! - `DaemonToken` — `X-Daemon-Token` header with timing-safe validation

/// How the request was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialType {
    Session,
    ApiToken,
    DaemonToken,
}

impl CredentialType {
    /// Wire-format name matching `fuz_app`'s `CREDENTIAL_TYPE_*` literals.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::ApiToken => "api_token",
            Self::DaemonToken => "daemon_token",
        }
    }

    /// Every credential type, for exhaustive iteration.
    ///
    /// **Adding a variant widens [`CredentialGate::Any`] — and therefore every
    /// spec that declares it — with no code change at those specs.** Rust
    /// doesn't exhaustiveness-check slices, so this const plus
    /// `credential_types_are_exhaustively_reviewed` below is what forces the
    /// re-decision: the new channel silently reaching ~100 endpoints is the
    /// same "nobody chose permissive, they chose the short thing" defect the
    /// mandatory-gate change was made to close, one level up.
    pub const ALL: &'static [Self] = &[Self::Session, Self::ApiToken, Self::DaemonToken];
}

/// Which credential channels admit a request — the credential axis of
/// [`AuthSpec`](crate::AuthSpec).
///
/// Deliberately **not** an `Option<&[CredentialType]>`. Under the optional
/// shape, `None` meant "any credential admits" and was what every ergonomic
/// constructor supplied, so the path of least resistance was maximum
/// credential reach and a spec's silence was indistinguishable from a
/// decision. Here the permissive case is [`Any`](Self::Any) — a value that has
/// to be typed — which makes each spec's declaration the review artifact for
/// the channels it accepts.
///
/// One representation per meaning: the session-only shape is the
/// [`SESSION_ONLY`](Self::SESSION_ONLY) constant rather than a variant, so it
/// can't compare unequal to the `Only` form of itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialGate {
    /// Every credential type admits. Spell this when an action is reachable
    /// by an API token as well as a browser session.
    Any,
    /// Only the listed credential types admit. Never empty — an empty
    /// allowlist admits nothing and is rejected by
    /// [`AuthSpec::validate`](crate::AuthSpec::validate).
    Only(&'static [CredentialType]),
}

impl CredentialGate {
    /// Session-cookie only — rejects the bearer and daemon-token channels.
    ///
    /// The anti-pivot shape for credential-lifecycle mutations: a leaked API
    /// token can read which sessions and tokens exist, but cannot mint another
    /// token, revoke one, or kill a session.
    pub const SESSION_ONLY: Self = Self::Only(&[CredentialType::Session]);

    /// The allowlist as a slice — empty for [`Any`](Self::Any), which is the
    /// shape both the action manifest and the 403 payload want.
    #[inline]
    #[must_use]
    pub const fn allowed(self) -> &'static [CredentialType] {
        match self {
            Self::Any => &[],
            Self::Only(types) => types,
        }
    }

    /// True iff `credential_type` admits under this gate.
    ///
    /// `None` — no credential resolved — admits only under [`Any`](Self::Any),
    /// which is what lets public and `optional_identity` specs run
    /// unauthenticated while a gated spec rejects the anonymous caller.
    #[inline]
    #[must_use]
    pub fn admits(self, credential_type: Option<CredentialType>) -> bool {
        match self {
            Self::Any => true,
            Self::Only(types) => credential_type.is_some_and(|ct| types.contains(&ct)),
        }
    }

    /// True iff the gate constrains nothing.
    #[inline]
    #[must_use]
    pub const fn is_any(self) -> bool {
        matches!(self, Self::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialGate, CredentialType};

    /// Adding a `CredentialType` variant fails to compile here, on purpose.
    ///
    /// The wildcard-free `match` is the only exhaustiveness check available —
    /// `CredentialGate::Only`'s slice isn't one, and neither is
    /// [`CredentialType::ALL`]. So this is the single site that forces the
    /// question a new channel raises: **every `CredentialGate::Any` spec now
    /// admits it.** Before adding a variant, walk the `Any` census
    /// (`any_credential_surface` in `action_auth`) and decide per spec; then
    /// extend `ALL` and this match together.
    #[test]
    fn credential_types_are_exhaustively_reviewed() {
        for credential_type in CredentialType::ALL {
            match credential_type {
                CredentialType::Session
                | CredentialType::ApiToken
                | CredentialType::DaemonToken => {}
            }
        }
        assert_eq!(
            CredentialType::ALL.len(),
            3,
            "a new credential type widens every CredentialGate::Any spec — see this test's docs",
        );
    }

    /// `Any` admits whatever `ALL` holds — the property that makes adding a
    /// variant a silent widening rather than a compile error at the spec sites.
    #[test]
    fn any_admits_every_declared_credential_type() {
        for credential_type in CredentialType::ALL {
            assert!(
                CredentialGate::Any.admits(Some(*credential_type)),
                "{} must be admitted by Any",
                credential_type.name(),
            );
        }
    }
}
