//! `self_service_role_set` action spec — toggle a self-service-eligible
//! GLOBAL `role_grant` on the calling actor.
//!
//! Rust twin of `fuz_app`'s `auth/self_service_role_actions.ts` +
//! `auth/self_service_role_action_specs.ts`. One static `request_response`
//! verb that takes `{role, enabled}` and toggles a global (`scope_id` = NULL)
//! `role_grant` on the caller for an allowlisted role. Idempotent in both
//! directions: re-enabling a held role returns `changed: false`; disabling a
//! role the caller doesn't hold returns `changed: false`.
//!
//! Opt-in surface (not in the standard auth spec set) — mounted via
//! `fuz_actions::auth_adapter::build_self_service_role_specs`, which threads
//! the per-deployment eligible-role allowlist into the handler. Mirrors how TS
//! keeps `create_self_service_role_actions` out of `create_standard_rpc_actions`.
//! Eligibility is a deployment policy (the consumer's allowlist), not a role
//! gate — so the [`AuthSpec`] is the plain `authenticated()` shape and the
//! ineligible-role rejection happens in the handler.
//!
//! Audit metadata carries `self_service: true` on the `role_grant_create` /
//! `role_grant_revoke` rows so reviewers can distinguish self-toggled grants
//! from admin grants/offers. The shape boundary mirrors
//! `actor_lookup_action_specs.rs`: the entry row and
//! [`SelfServiceRoleActionSpecs`] carry the auth axis + method + handler,
//! lifted into a canonical `fuz_actions::ActionSpec` by the adapter.

use std::collections::HashSet;

use serde_json::Value;

use crate::action_auth::AuthSpec;
use crate::action_rate_limit::RateLimitClass;
use crate::actor_queries::query_create_role_grant;
use crate::audit_emitter::AuditLogInput;
use crate::audit_event_type::AuditEventType;
use crate::auth_action_context::AuthenticatedActionContext;
use crate::auth_action_entry::AuthActionEntry;
use crate::credential_type::CredentialGate;
use crate::name_schema::is_valid_name;
use crate::params_helpers::parse_role_param;
use crate::role::{RoleRegistryError, is_builtin_role};
use crate::role_grant_offer_action_specs::emit_supersede_audits;
use crate::role_grant_offer_queries::query_revoke_role_grant;
use fuz_http::{
    InputShape, JsonrpcError, forbidden, internal_error_with_source, invalid_input_params,
    method_not_found, reject_unknown_keys,
};

/// `data.reason` (403) when the caller asks to self-toggle a role outside the
/// configured allowlist. Mirrors TS `ERROR_ROLE_NOT_SELF_SERVICE_ELIGIBLE`.
pub const ERROR_ROLE_NOT_SELF_SERVICE_ELIGIBLE: &str = "role_not_self_service_eligible";

/// Validate a deployment's self-service eligible-role allowlist at
/// construction.
///
/// Refuses a builtin role (`admin` / `keeper`) — self-toggling one would hand
/// any account instance-wide authority, so no allowlist may name it — and a
/// name outside the role grammar. The same fail-loud-at-boot shape as
/// [`RoleRegistry::new`](crate::RoleRegistry::new), reusing its error, since
/// both refuse a builtin name where only app roles belong.
///
/// # Errors
///
/// [`RoleRegistryError::BuiltinCollision`] for a builtin role,
/// [`RoleRegistryError::InvalidName`] for a name outside the grammar.
pub fn validate_self_service_eligible_roles(roles: &[String]) -> Result<(), RoleRegistryError> {
    for role in roles {
        if is_builtin_role(role) {
            return Err(RoleRegistryError::BuiltinCollision(role.clone()));
        }
        if !is_valid_name(role) {
            return Err(RoleRegistryError::InvalidName(role.clone()));
        }
    }
    Ok(())
}

/// Auth + dispatch entry for `self_service_role_set`.
///
/// Actor-bound, side-effecting; per-account rate-limited like the TS spec
/// (`rate_limit: 'account'`) to bound audit-row churn from role flapping —
/// every call writes a `role_grant_create`/`role_grant_revoke` row even when
/// idempotent (`changed: false`).
/// `CredentialGate::SESSION_ONLY` — self-toggling a role moves the caller's own
/// authority, the same privilege-pivot shape as `role_grant_offer_accept`. The
/// verb exists to serve a UI affordance, so the
/// bearer channel buys nothing and a leaked account-wide token self-granting an
/// eligible role is exactly what the gate refuses.
pub static SELF_SERVICE_ROLE_ACTION_ENTRIES: &[AuthActionEntry] = &[AuthActionEntry {
    method: "self_service_role_set",
    auth: AuthSpec::authenticated(CredentialGate::SESSION_ONLY),
    input: InputShape::Object,
    side_effects: true,
    rate_limit: Some(RateLimitClass::Account),
}];

/// Dispatcher for the `self_service_role_set` family; its entry rows are
/// [`SELF_SERVICE_ROLE_ACTION_ENTRIES`] (see `account_action_specs.rs` for the
/// boundary rationale).
#[derive(Debug)]
pub struct SelfServiceRoleActionSpecs;

impl SelfServiceRoleActionSpecs {
    /// Dispatch a self-service-role action by method name.
    ///
    /// `eligible` is the per-deployment allowlist of self-service-eligible
    /// role names, threaded in by `build_self_service_role_specs`.
    ///
    /// # Errors
    ///
    /// Returns a [`JsonrpcError`] on validation failure, an ineligible role
    /// (403), a DB error, or serialization failure.
    pub async fn dispatch(
        method: &str,
        params: &Value,
        ctx: &AuthenticatedActionContext<'_>,
        db: &(impl deadpool_postgres::GenericClient + ?Sized),
        eligible: &HashSet<String>,
    ) -> Result<Value, JsonrpcError> {
        match method {
            "self_service_role_set" => {
                handle_self_service_role_set(params, ctx, db, eligible).await
            }
            _ => Err(method_not_found(method)),
        }
    }
}

/// Declared input keys — the exact key set of the TS twin's
/// `SelfServiceRoleSetInput`. `acting` is declared because the spec carries an
/// actor axis, even though the authorization phase, not this parser, reads it.
const SELF_SERVICE_ROLE_SET_KEYS: &[&str] = &["role", "enabled", "acting"];

/// Parse + validate `{role, enabled}`. (`acting` is consumed upstream by the
/// authorization phase, not here.)
fn parse_input(params: &Value) -> Result<(String, bool), JsonrpcError> {
    reject_unknown_keys(params, SELF_SERVICE_ROLE_SET_KEYS)?;
    let role = parse_role_param(params, "role")?;
    let enabled = params
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid_input_params("missing or invalid 'enabled' parameter", None))?;
    Ok((role.to_owned(), enabled))
}

async fn handle_self_service_role_set(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    eligible: &HashSet<String>,
) -> Result<Value, JsonrpcError> {
    let (role, enabled) = parse_input(params)?;

    if !eligible.contains(&role) {
        return Err(forbidden(
            "role not eligible for self-service",
            Some(ERROR_ROLE_NOT_SELF_SERVICE_ELIGIBLE),
        ));
    }

    let actor_id = ctx.auth.actor.id;
    let account_id = ctx.auth.account.id;

    // Global (scope_id = NULL) grant lookup against the in-memory snapshot —
    // no DB roundtrip. Mirrors TS `has_scoped_role(auth, role, null)`. The
    // snapshot is active-only (`query_role_grant_find_active_for_actor` filters revoked +
    // expired), so presence here means "currently held".
    let held = ctx
        .auth
        .role_grants
        .iter()
        .find(|g| g.role == role && g.scope_id.is_none());

    if enabled {
        // Idempotent re-grant. The TOCTOU window (snapshot vs insert) is
        // benign: `query_create_role_grant` collapses concurrent grants via
        // `ON CONFLICT DO NOTHING`, so the DB ends with exactly one grant.
        if held.is_some() {
            return Ok(serde_json::json!({"ok": true, "enabled": true, "changed": false}));
        }

        // Self-service grants are global (scope `None`); `granted_by` is the
        // caller granting to themselves.
        let role_grant =
            query_create_role_grant(db, &actor_id, &role, None, None, Some(&actor_id), None)
                .await
                .map_err(|e| internal_error_with_source("create role_grant query failed", &e))?;

        // `role_grant_create` is the canonical actor-bound-subject event —
        // populate both target columns even on self-service (grantor and
        // grantee are the same identity) so the "always populated for
        // role_grant_create" rule holds uniformly.
        ctx.audit_emit(
            db,
            AuditLogInput::for_event(AuditEventType::RoleGrantCreate)
                .actor(actor_id)
                .account(account_id)
                .target_account(account_id)
                .target_actor(Some(actor_id))
                .ip(ctx.client_ip.clone())
                .metadata(serde_json::json!({
                    "role": role_grant.role,
                    "role_grant_id": role_grant.id.to_string(),
                    "scope_id": role_grant.scope_id.map(|u| u.to_string()),
                    "self_service": true,
                })),
        )
        .await?;

        return Ok(serde_json::json!({"ok": true, "enabled": true, "changed": true}));
    }

    // Disable: revoke the held global grant, if any.
    let Some(target) = held else {
        return Ok(serde_json::json!({"ok": true, "enabled": false, "changed": false}));
    };

    // `revoked_by = self`, no `reason` (mirrors the TS twin) — the
    // `self_service: true` metadata is the distinguishing marker.
    let result = query_revoke_role_grant(db, target.id, actor_id, Some(actor_id), None)
        .await
        .map_err(|e| internal_error_with_source("revoke role_grant query failed", &e))?;
    let Some(result) = result else {
        // Raced with another closer — treat as already revoked.
        return Ok(serde_json::json!({"ok": true, "enabled": false, "changed": false}));
    };

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantRevoke)
            .actor(actor_id)
            .account(account_id)
            .target_account(account_id)
            .target_actor(Some(actor_id))
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "role": result.role,
                "role_grant_id": result.id.to_string(),
                "scope_id": result.scope_id.map(|u| u.to_string()),
                "self_service": true,
            })),
    )
    .await?;

    // Supersede cascade — `query_revoke_role_grant` marks any pending offers
    // for the same `(account, role, scope)` superseded as a side effect.
    // A self-service-only role can't be offered (offer creation gates on the
    // role's `grant_paths`), so this is empty in practice; emit the forensic
    // audit per sibling for completeness when an admin-grantable role is also
    // self-service-eligible.
    //
    // TODO: the WS supersede notification (grantor inbox push) is omitted —
    // a self-service global role realistically has no pending offers, and
    // superseded siblings surface on the grantor's next refresh.
    // `queue_supersede_notifications` is `pub(crate)` if that changes.
    emit_supersede_audits(
        ctx,
        db,
        &result.superseded_offers,
        "role_grant_revoked",
        result.id,
    )
    .await?;

    Ok(serde_json::json!({"ok": true, "enabled": false, "changed": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec carries an actor axis, so the twin declares `acting` and the
    /// key list admits it — while any other key is `-32602`, the strict-object
    /// half a `params.get` chain cannot see.
    #[test]
    fn parse_input_refuses_an_unknown_key_and_admits_the_selector() {
        const ACTOR: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";
        assert_eq!(
            SELF_SERVICE_ROLE_SET_KEYS,
            ["role", "enabled", "acting"],
            "the twin's `SelfServiceRoleSetInput` key set"
        );
        assert!(
            parse_input(&serde_json::json!({"role": "educator", "enabled": true, "acting": ACTOR}))
                .is_ok(),
            "the declared shape must parse"
        );
        let error =
            parse_input(&serde_json::json!({"role": "educator", "enabled": true, "nope": 1}))
                .expect_err("an undeclared key must be refused");
        assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);
    }

    #[test]
    fn parse_input_requires_role_and_enabled() {
        assert!(parse_input(&serde_json::json!({"enabled": true})).is_err());
        assert!(parse_input(&serde_json::json!({"role": "educator"})).is_err());
        // The twin's `RoleName`: a string outside the role grammar is a
        // malformed input, not a role that is merely ineligible.
        let over_length = "a".repeat(crate::name_schema::NAME_LENGTH_MAX + 1);
        for role in [
            "",
            "Educator",
            "not a role",
            "educator_",
            "edu__cator",
            "educator\n",
            over_length.as_str(),
        ] {
            let err = parse_input(&serde_json::json!({"role": role, "enabled": true}))
                .expect_err("an off-grammar role is refused");
            assert_eq!(
                err.code,
                fuz_http::JsonrpcErrorCode::InvalidParams,
                "{role:?}"
            );
            assert!(err.data.is_none(), "{role:?}");
        }
        let parsed = parse_input(&serde_json::json!({"role": "educator", "enabled": true}));
        assert!(matches!(parsed, Ok((role, true)) if role == "educator"));
    }

    #[test]
    fn eligible_roles_refuse_builtins_and_bad_names() {
        let roles = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert!(validate_self_service_eligible_roles(&roles(&["educator"])).is_ok());
        assert!(validate_self_service_eligible_roles(&[]).is_ok());
        for builtin in ["admin", "keeper"] {
            assert_eq!(
                validate_self_service_eligible_roles(&roles(&["educator", builtin])),
                Err(RoleRegistryError::BuiltinCollision(builtin.to_owned()))
            );
        }
        for bad in ["Educator", "edu__cator"] {
            assert_eq!(
                validate_self_service_eligible_roles(&roles(&[bad])),
                Err(RoleRegistryError::InvalidName(bad.to_owned()))
            );
        }
    }

    #[test]
    fn entries_expose_single_side_effecting_account_limited_verb() {
        let entries = SELF_SERVICE_ROLE_ACTION_ENTRIES;
        assert!(matches!(entries, [e] if e.method == "self_service_role_set" && e.side_effects));
    }
}
