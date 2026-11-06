//! Shared registry-row shape for authenticated action families.
//!
//! `(method, auth, input, side_effects, rate_limit)` — the five fields that
//! every authenticated action surface (account / admin /
//! `role_grant_offer`) needs at compile time. Each surface declares a
//! `&'static [AuthActionEntry]` registry and `dispatch(method, ...)`
//! routes by name.
//!
//! Add new authenticated surfaces by declaring a new registry of
//! `AuthActionEntry` plus a new variant on
//! `fuz_actions::auth_adapter::AuthActionFamily`.

use fuz_http::InputShape;

use crate::action_auth::AuthSpec;
use crate::action_rate_limit::RateLimitClass;

/// One row in an authenticated action registry.
///
/// Fields mirror TS `RequestResponseActionSpec`'s required attributes
/// (the wire-shape input/output Zod schemas live alongside in the TS
/// spec; in Rust they're erased post-codegen, so the entry carries
/// only the dispatch-time metadata).
#[derive(Debug, Clone, Copy)]
pub struct AuthActionEntry {
    /// Wire method name (`"admin_account_list"`, `"account_token_create"`,
    /// etc.). Used as the dispatcher's lookup key.
    pub method: &'static str,
    /// Auth axis required to reach this method's handler.
    pub auth: AuthSpec,
    /// Whether the method takes params — [`InputShape::Void`] for a twin
    /// whose input is `z.void()`. The `fuz_actions` adapter copies it onto the
    /// `ActionSpec` it builds, where the dispatcher enforces it.
    pub input: InputShape,
    /// `true` → dispatcher wraps the handler in a DB transaction;
    /// `false` → pool-routed read.
    pub side_effects: bool,
    /// Per-method rate-limit class. `None` skips the gate. See
    /// [`crate::action_rate_limit`].
    pub rate_limit: Option<RateLimitClass>,
}

/// Every authenticated action registry this crate owns.
///
/// Each entry's rate-limit class is declared here; the `fuz_actions`
/// adapter copies it onto the `ActionSpec::rate_limit` it builds, where the
/// dispatcher gates it and introspection reads it, rather than looking the
/// name up here.
///
/// The registries are the whole authenticated surface, which is what the
/// `CredentialGate::Any` census in [`crate::action_auth`] enumerates and
/// what [`auth_action_entry`] resolves a single method against.
pub const AUTH_ACTION_ENTRY_REGISTRIES: [&[AuthActionEntry]; 6] = [
    crate::account_action_specs::ACCOUNT_ACTION_ENTRIES,
    crate::admin_action_specs::ADMIN_ACTION_ENTRIES,
    crate::role_grant_offer_action_specs::ROLE_GRANT_OFFER_ACTION_ENTRIES,
    crate::actor_lookup_action_specs::ACTOR_LOOKUP_ACTION_ENTRIES,
    crate::actor_search_action_specs::ACTOR_SEARCH_ACTION_ENTRIES,
    crate::self_service_role_action_specs::SELF_SERVICE_ROLE_ACTION_ENTRIES,
];

/// Look up the registry row declaring `method`.
///
/// Searches every registry in [`AUTH_ACTION_ENTRY_REGISTRIES`], returning
/// `None` for a method this crate doesn't own (a cell-bundle spec, a
/// consumer spec, a testing seam).
///
/// Method names are unique across the registries — the dispatchers route
/// by name — so the first match is the only match.
#[must_use]
pub fn auth_action_entry(method: &str) -> Option<&'static AuthActionEntry> {
    AUTH_ACTION_ENTRY_REGISTRIES
        .into_iter()
        .flatten()
        .find(|entry| entry.method == method)
}

#[cfg(test)]
mod tests {
    use super::{AUTH_ACTION_ENTRY_REGISTRIES, auth_action_entry};
    use crate::action_rate_limit::RateLimitClass;

    #[test]
    fn method_names_are_unique_across_registries() {
        let mut methods: Vec<&str> = AUTH_ACTION_ENTRY_REGISTRIES
            .into_iter()
            .flatten()
            .map(|entry| entry.method)
            .collect();
        let total = methods.len();
        methods.sort_unstable();
        methods.dedup();
        assert_eq!(methods.len(), total, "registry method names must be unique");
    }

    #[test]
    fn lookup_resolves_a_declared_class_and_a_bare_entry() {
        let create = auth_action_entry("role_grant_offer_create").expect("entry present");
        assert_eq!(create.rate_limit, Some(RateLimitClass::Account));
        let accept = auth_action_entry("role_grant_offer_accept").expect("entry present");
        assert_eq!(accept.rate_limit, Some(RateLimitClass::Account));
        let decline = auth_action_entry("role_grant_offer_decline").expect("entry present");
        assert_eq!(decline.rate_limit, None);
    }

    #[test]
    fn lookup_misses_a_method_this_crate_does_not_own() {
        assert!(auth_action_entry("cell_get").is_none());
    }
}
