//! Per-connection auth context.
//!
//! Populated at accept time from `SO_PEERCRED`. fuzd is single-user:
//! a uid-mismatched peer — or one whose credential can't be read — is
//! rejected fail-closed at accept (see [`crate::conn::accept_uds`] and its
//! `should_accept_peer` gate). Once past the accept gate, every
//! authenticated connection sits at [`AuthLevel::Keeper`].

use fuz_wire::AuthLevel;

/// Auth context attached to each connection.
#[derive(Debug, Clone, Copy)]
pub struct AuthContext {
    /// Auth tier: always [`AuthLevel::Keeper`] for accepted connections
    /// today (cross-uid peers are dropped at accept).
    pub level: AuthLevel,
}

/// Returns `true` if `ctx.level` is at least as high as `required`.
///
/// Strict hierarchy: `Keeper > Public`. Pre-1.1 fuzd has no
/// `Authenticated` tier (no account model).
#[must_use]
pub const fn check_auth(required: AuthLevel, ctx: AuthContext) -> bool {
    match required {
        AuthLevel::Public => true,
        AuthLevel::Keeper => matches!(ctx.level, AuthLevel::Keeper),
    }
}
