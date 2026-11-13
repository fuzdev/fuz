//! Adapters that lift `fuz_auth`'s action-entry rows into the canonical
//! [`crate::ActionSpec`] registry shape.
//!
//! The rows are the `*_ACTION_ENTRIES` tables `fuz_auth` ships beside each
//! family's dispatcher — for example
//! [`fuz_auth::account_action_specs::ACCOUNT_ACTION_ENTRIES`],
//! [`fuz_auth::admin_action_specs::ADMIN_ACTION_ENTRIES`], and
//! [`fuz_auth::role_grant_offer_action_specs::ROLE_GRANT_OFFER_ACTION_ENTRIES`]
//! — each carrying a method's name, auth axes, side-effect flag, and rate
//! class.
//!
//! ## Lift, not unify
//!
//! `fuz_auth` can't depend on `fuz_actions` (the reverse edge would be a
//! cycle), so `fuz_auth` keeps its own entry rows and dispatchers, and this
//! module reads the rows and wraps each dispatcher in an [`ActionSpec`]
//! handler. That split is the permanent shape, not a step toward merging
//! the two: consumers building a registry call [`build_auth_spec_set`] (or
//! the per-family builders here).
//!
//! ## Bridging the context shape
//!
//! `fuz_auth::AuthenticatedActionContext` and [`crate::ActionContext`]
//! are similar but not identical:
//!
//! - `fuz_auth`'s context takes its db as a generic client and lacks
//!   `notify`, `signal`, `connection_id`, `log`.
//! - `fuz_actions`' context exposes all of those.
//!
//! The adapter handlers **build the `fuz_auth` context from the
//! `fuz_actions` context** at dispatch time:
//!
//! ```text
//!   fuz_actions::ActionContext  →  AuthenticatedActionContext
//!     ctx.db           (ActionDb::Tx | ::Pool)   → &impl GenericClient
//!     ctx.auth         (required for these)      → &RequestActorContext
//!     ctx.credential_type                        → Option<CredentialType>
//!     ctx.post_commit_effects                    → post_commit
//!     options.audit    (shared Arc<AuditEmitter>) → &Arc<AuditEmitter>
//!     options.connection_closer                      → &Arc<dyn ConnectionCloser>
//!     ctx.client_ip                              → Option<String>
//! ```
//!
//! The actor-bound families share one `AuthenticatedActionContext`; the
//! account-grain families share `AccountActionContext`. The handlers emit
//! audit rows through the context's `audit_emit`, which routes each event
//! per `fuz_auth::AUDIT_EVENT_SPECS` (in the request transaction, with its
//! fan-out after the commit, or on the pool).

use std::collections::HashSet;
use std::sync::Arc;

use fuz_auth::{
    AccountActionContext, AccountActionSpecs, ActorLookupActionSpecs, ActorSearchActionSpecs,
    AdminActionSpecs, AuditEmitter, AuthActionEntry, AuthenticatedActionContext, ConnectionCloser,
    OfferCreateAuthorize, RoleGrantOfferActionSpecs, RoleRegistry, SelfServiceRoleActionSpecs,
    account_action_specs::ACCOUNT_ACTION_ENTRIES,
    actor_lookup_action_specs::ACTOR_LOOKUP_ACTION_ENTRIES,
    actor_search_action_specs::ACTOR_SEARCH_ACTION_ENTRIES,
    admin_action_specs::ADMIN_ACTION_ENTRIES,
    role_grant_offer_action_specs::ROLE_GRANT_OFFER_ACTION_ENTRIES,
    self_service_role_action_specs::SELF_SERVICE_ROLE_ACTION_ENTRIES,
};
use fuz_http::JsonrpcError;
use serde_json::Value;

use crate::action_context::ActionContext;
use crate::action_registry::ActionHandler;
use crate::action_spec::ActionSpec;
use fuz_db::ActionDb;

/// Build the canonical [`ActionSpec`] set for `fuz_auth`'s account
/// self-service methods.
///
/// Each entry's rate-limit class lands on [`ActionSpec::rate_limit`], which
/// `perform_action` gates ahead of params validation.
#[must_use]
pub fn build_account_specs(
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
) -> Vec<ActionSpec> {
    build_family_specs(
        AuthActionFamily::Account,
        ACCOUNT_ACTION_ENTRIES,
        audit,
        connection_closer,
    )
}

/// Build the canonical [`ActionSpec`] set for `fuz_auth`'s admin methods.
///
/// `roles` is the app's [`RoleRegistry`], captured by each handler closure so
/// `admin_account_list` can surface `roles.list_admin_grantable()` as its
/// `grantable_roles`. Like [`build_role_grant_offer_specs`] this builds its
/// specs directly rather than routing through [`AuthActionFamily`] — the `Copy`
/// enum can't carry the `Arc` — while reusing the same context bridge.
#[must_use]
#[expect(
    clippy::needless_pass_by_value,
    reason = "takes its `Arc`s by value like its sibling builders; this one only clones them per spec"
)]
pub fn build_admin_specs(
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
    roles: Arc<RoleRegistry>,
) -> Vec<ActionSpec> {
    ADMIN_ACTION_ENTRIES
        .iter()
        .map(|entry| {
            let method = entry.method;
            let audit = Arc::clone(&audit);
            let connection_closer = Arc::clone(&connection_closer);
            let roles = Arc::clone(&roles);
            let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
                let audit = Arc::clone(&audit);
                let connection_closer = Arc::clone(&connection_closer);
                let roles = Arc::clone(&roles);
                Box::pin(async move {
                    let (inner_ctx, db) =
                        bridge_authenticated_context(ctx, &audit, &connection_closer)?;
                    match db {
                        ActionDb::Pool(c) => {
                            AdminActionSpecs::dispatch(method, &params, &inner_ctx, c, &roles).await
                        }
                        ActionDb::Tx(t) => {
                            AdminActionSpecs::dispatch(method, &params, &inner_ctx, t, &roles).await
                        }
                    }
                })
            });
            auth_family_spec(entry, handler)
        })
        .collect()
}

/// Build the canonical [`ActionSpec`] set for `fuz_auth`'s
/// role-grant-offer methods (consentful-role-grants surface).
///
/// Sibling to [`build_admin_specs`] but separate because the offer
/// surface is **not** admin-only — `role_grant_offer_accept` is
/// per-actor self-service, and `role_grant_offer_create` is gated by
/// the offered role's `grant_paths` + the injected `authorize`
/// predicate, not by the caller holding `admin`.
///
/// `authorize` is the consumer-supplied offer-create authorization
/// predicate (TS `RoleGrantOfferCreateAuthorize`). Pass
/// `Arc::new(fuz_auth::AdminOfferAuthorize)` for the default admin-only
/// check, or a custom impl for scope-aware authorization (e.g. a classroom
/// teacher offering scoped roles). It is consulted by
/// `role_grant_offer_create` and `role_grant_assign`, after their
/// admin-grantability and builtin-role gates.
///
/// `roles` is the app's [`RoleRegistry`], consulted by the offer-create and
/// revoke gates via `roles.is_admin_grantable`.
///
/// Unlike the admin / account families this builds its specs directly
/// rather than routing through [`AuthActionFamily`] — the `Copy` enum
/// can't carry the `authorize` `Arc` — while reusing the same context
/// bridge.
///
/// Matching TS, `role_grant_offer_create` (offer-spam +
/// account-existence-oracle surface), `role_grant_offer_accept` (replay
/// churn), `role_grant_revoke` and `role_grant_assign` carry
/// `rate_limit: Account`; the others carry none.
#[must_use]
#[expect(
    clippy::needless_pass_by_value,
    reason = "takes its `Arc`s by value like its sibling builders; this one only clones them per spec"
)]
pub fn build_role_grant_offer_specs(
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
    authorize: Arc<dyn OfferCreateAuthorize>,
    roles: Arc<RoleRegistry>,
) -> Vec<ActionSpec> {
    ROLE_GRANT_OFFER_ACTION_ENTRIES
        .iter()
        .map(|entry| {
            let method = entry.method;
            let audit = Arc::clone(&audit);
            let connection_closer = Arc::clone(&connection_closer);
            let authorize = Arc::clone(&authorize);
            let roles = Arc::clone(&roles);
            let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
                let audit = Arc::clone(&audit);
                let connection_closer = Arc::clone(&connection_closer);
                let authorize = Arc::clone(&authorize);
                let roles = Arc::clone(&roles);
                Box::pin(async move {
                    let (inner_ctx, db) =
                        bridge_authenticated_context(ctx, &audit, &connection_closer)?;
                    RoleGrantOfferActionSpecs::dispatch(
                        method,
                        &params,
                        &inner_ctx,
                        &db,
                        authorize.as_ref(),
                        &roles,
                    )
                    .await
                })
            });
            auth_family_spec(entry, handler)
        })
        .collect()
}

/// Build the canonical [`ActionSpec`] set for `fuz_auth`'s `actor_lookup`
/// method (batched id → label resolver).
///
/// **Opt-in** — deliberately NOT part of [`build_auth_spec_set`], mirroring
/// TS where `create_actor_lookup_actions` is excluded from
/// `create_standard_rpc_actions` (consumers without a byline / owner-column
/// surface skip it). Mount it separately alongside the standard set.
///
/// `actor_lookup` carries `rate_limit: Account` (the batched
/// username-enumeration surface).
#[must_use]
pub fn build_actor_lookup_specs(
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
) -> Vec<ActionSpec> {
    build_family_specs(
        AuthActionFamily::ActorLookup,
        ACTOR_LOOKUP_ACTION_ENTRIES,
        audit,
        connection_closer,
    )
}

/// Build the canonical [`ActionSpec`] set for `fuz_auth`'s `actor_search`
/// method (prefix search over `actor.name`, scope-gated for non-admins).
///
/// **Opt-in** — like [`build_actor_lookup_specs`], deliberately NOT part of
/// [`build_auth_spec_set`] (mirrors TS keeping `create_actor_search_actions`
/// out of `create_standard_rpc_actions`). `actor_search` carries
/// `rate_limit: Account` (the prefix-enumeration surface).
#[must_use]
pub fn build_actor_search_specs(
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
) -> Vec<ActionSpec> {
    build_family_specs(
        AuthActionFamily::ActorSearch,
        ACTOR_SEARCH_ACTION_ENTRIES,
        audit,
        connection_closer,
    )
}

/// Build the canonical [`ActionSpec`] set for `fuz_auth`'s
/// `self_service_role_set` method (allowlist-gated self role toggle).
///
/// **Opt-in** — like [`build_actor_lookup_specs`] / [`build_actor_search_specs`],
/// deliberately NOT part of [`build_auth_spec_set`] (mirrors TS keeping
/// `create_self_service_role_actions` out of `create_standard_rpc_actions`).
///
/// `eligible_roles` is the per-deployment allowlist of self-service-eligible
/// role names (e.g. `["educator"]`) — captured into the handler and
/// consulted before any mutation; a role outside it is rejected with
/// `forbidden` (reason `role_not_self_service_eligible`). Unlike the family
/// builders this can't route through [`AuthActionFamily`] (the enum is `Copy`
/// and can't carry the allowlist), so it builds its spec directly while reusing
/// the same context bridge.
///
/// `self_service_role_set` carries `rate_limit: Account` (bounds audit-row
/// churn from role flapping).
///
/// # Panics
///
/// Panics if `eligible_roles` names a builtin role (`admin` / `keeper`) or a
/// name outside the role grammar
/// ([`fuz_auth::validate_self_service_eligible_roles`]) — a boot-time
/// misconfiguration, refused loudly like the TS twin's factory-time throw.
#[must_use]
#[expect(
    clippy::needless_pass_by_value,
    reason = "takes its `Arc`s by value like its sibling builders; this one only clones them per spec"
)]
#[expect(
    clippy::panic,
    reason = "boot-time config guard: a builtin self-service role is a misconfig, fail loud"
)]
pub fn build_self_service_role_specs(
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
    eligible_roles: Vec<String>,
) -> Vec<ActionSpec> {
    if let Err(error) = fuz_auth::validate_self_service_eligible_roles(&eligible_roles) {
        panic!("build_self_service_role_specs: invalid eligible_roles: {error}");
    }
    let eligible: Arc<HashSet<String>> = Arc::new(eligible_roles.into_iter().collect());
    SELF_SERVICE_ROLE_ACTION_ENTRIES
        .iter()
        .map(|entry| {
            let method = entry.method;
            let audit = Arc::clone(&audit);
            let connection_closer = Arc::clone(&connection_closer);
            let eligible = Arc::clone(&eligible);
            let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
                let audit = Arc::clone(&audit);
                let connection_closer = Arc::clone(&connection_closer);
                let eligible = Arc::clone(&eligible);
                Box::pin(async move {
                    let (inner_ctx, db) =
                        bridge_authenticated_context(ctx, &audit, &connection_closer)?;
                    match db {
                        ActionDb::Pool(c) => {
                            SelfServiceRoleActionSpecs::dispatch(
                                method, &params, &inner_ctx, c, &eligible,
                            )
                            .await
                        }
                        ActionDb::Tx(t) => {
                            SelfServiceRoleActionSpecs::dispatch(
                                method, &params, &inner_ctx, t, &eligible,
                            )
                            .await
                        }
                    }
                })
            });
            auth_family_spec(entry, handler)
        })
        .collect()
}

/// Build every fuz_auth-owned action spec in one call.
///
/// Convenience aggregate over [`build_account_specs`] +
/// [`build_admin_specs`] + [`build_role_grant_offer_specs`]. Returns
/// the concatenated `Vec<ActionSpec>` ready to merge into the
/// consumer's action registry.
///
/// The specs carry their entries' classes on [`ActionSpec::rate_limit`], so
/// the dispatcher's limiters ([`crate::ActionDispatch::rate_limits`]) charge them
/// alongside every other spec in the registry — one budget per axis, as the
/// TS twin threads one `action_account_rate_limiter` into both transports.
///
/// `authorize` is the offer-create authorization predicate forwarded to
/// [`build_role_grant_offer_specs`]; pass
/// `Arc::new(fuz_auth::AdminOfferAuthorize)` for the default admin-only
/// check, or a custom impl for scope-aware authorization.
///
/// `roles` is the app's [`RoleRegistry`] (the role vocabulary + grantability),
/// forwarded to the admin + role-grant-offer surfaces so grantability reads the
/// registry rather than a hardcode. Pass `Arc::new(RoleRegistry::default())`
/// for the builtins-only registry (byte-identical to the prior `["admin"]`
/// behaviour), or a consumer registry that declares app roles.
#[must_use]
pub fn build_auth_spec_set(
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
    authorize: Arc<dyn OfferCreateAuthorize>,
    roles: Arc<RoleRegistry>,
) -> Vec<ActionSpec> {
    let mut specs = build_account_specs(Arc::clone(&audit), Arc::clone(&connection_closer));
    specs.extend(build_admin_specs(
        Arc::clone(&audit),
        Arc::clone(&connection_closer),
        Arc::clone(&roles),
    ));
    specs.extend(build_role_grant_offer_specs(
        audit,
        connection_closer,
        authorize,
        roles,
    ));
    specs
}

/// Closed set of **account-grain** (`actor: 'none'`) authenticated action
/// families the adapter dispatches through the generic builder.
///
/// Each variant pairs with a `*ActionSpecs::dispatch` static method in
/// `fuz_auth`.
///
/// Stored by-value (one byte) in each handler closure so the dispatch
/// match is a jump-table at runtime — no trait objects, no
/// `Pin<Box<dyn Future>>` indirection inside the dispatch. The outer
/// `ActionHandler` Box is the only allocation per request.
///
/// Actor-bound surfaces (`admin`, `role_grant_offer`) are **not** here — they
/// build their specs directly ([`build_admin_specs`] /
/// [`build_role_grant_offer_specs`]) so the closure can capture an `Arc` (the
/// registry / the authorize predicate) that this `Copy` enum can't carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthActionFamily {
    Account,
    ActorLookup,
    ActorSearch,
}

impl AuthActionFamily {
    /// Dispatch an account-grain family to its `*ActionSpecs::dispatch`,
    /// handling the `ActionDb::Pool` vs `ActionDb::Tx` variant. Every variant
    /// is account-grain (`actor: 'none'`, taking an [`AccountActionContext`])
    /// and operates on the caller's own account without resolving a persona.
    async fn dispatch_account_grain(
        self,
        method: &str,
        params: &Value,
        ctx: &AccountActionContext<'_>,
        db: &ActionDb<'_>,
    ) -> Result<Value, JsonrpcError> {
        match (self, db) {
            (Self::Account, ActionDb::Pool(c)) => {
                AccountActionSpecs::dispatch(method, params, ctx, *c).await
            }
            (Self::Account, ActionDb::Tx(t)) => {
                AccountActionSpecs::dispatch(method, params, ctx, *t).await
            }
            (Self::ActorLookup, ActionDb::Pool(c)) => {
                ActorLookupActionSpecs::dispatch(method, params, ctx, *c).await
            }
            (Self::ActorLookup, ActionDb::Tx(t)) => {
                ActorLookupActionSpecs::dispatch(method, params, ctx, *t).await
            }
            (Self::ActorSearch, ActionDb::Pool(c)) => {
                ActorSearchActionSpecs::dispatch(method, params, ctx, *c).await
            }
            (Self::ActorSearch, ActionDb::Tx(t)) => {
                ActorSearchActionSpecs::dispatch(method, params, ctx, *t).await
            }
        }
    }
}

/// Build the `Vec<ActionSpec>` for one account-grain family — internal shape
/// shared by [`build_account_specs`] / [`build_actor_lookup_specs`] /
/// [`build_actor_search_specs`]. Each iterates its static registry of
/// [`AuthActionEntry`] rows, building per-entry handler closures that share the
/// same account-grain bridge + dispatch shape. (The
/// actor-bound surfaces — `admin`, `role_grant_offer` — build directly.)
#[expect(
    clippy::needless_pass_by_value,
    reason = "takes its `Arc`s by value like the builders that call it; it only clones them per spec"
)]
fn build_family_specs(
    family: AuthActionFamily,
    entries: &'static [AuthActionEntry],
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
) -> Vec<ActionSpec> {
    entries
        .iter()
        .map(|entry| {
            build_authenticated_action_spec(
                family,
                entry,
                Arc::clone(&audit),
                Arc::clone(&connection_closer),
            )
        })
        .collect()
}

/// Build one [`ActionSpec`] for a single entry in an account-grain action
/// family ([`AuthActionFamily`]). The closure captures the family enum (one
/// byte) and matches at dispatch time — much simpler than the prior trait +
/// `Pin<Box<dyn Future>>` shape, with one fewer allocation per request.
fn build_authenticated_action_spec(
    family: AuthActionFamily,
    entry: &'static AuthActionEntry,
    audit: Arc<AuditEmitter>,
    connection_closer: Arc<dyn ConnectionCloser>,
) -> ActionSpec {
    let method = entry.method;
    let handler: ActionHandler = Arc::new(move |params: Value, ctx: ActionContext<'_>| {
        let audit = Arc::clone(&audit);
        let connection_closer = Arc::clone(&connection_closer);
        Box::pin(async move {
            let (inner_ctx, db) = bridge_account_grain_context(ctx, &audit, &connection_closer)?;
            family
                .dispatch_account_grain(method, &params, &inner_ctx, &db)
                .await
        })
    });
    auth_family_spec(entry, handler)
}

/// Build the [`ActionSpec`] for one [`AuthActionEntry`], the shape every
/// auth-family builder here ends with.
///
/// The entry's rate-limit class lands on [`ActionSpec::rate_limit`], so
/// `perform_action` gates it like any other spec's — after authorization,
/// ahead of params validation and the handler's transaction.
fn auth_family_spec(entry: &AuthActionEntry, handler: ActionHandler) -> ActionSpec {
    let mut spec = ActionSpec::new(
        entry.method,
        entry.auth,
        entry.input,
        entry.side_effects,
        handler,
    );
    spec.rate_limit = entry.rate_limit;
    spec
}

/// Bridge `fuz_actions::ActionContext` into a paired
/// `(AuthenticatedActionContext, ActionDb)`. Consumes `ctx` since
/// `client_ip: Option<String>` is moved into the inner context.
///
/// Returns the JSON-RPC `unauthenticated` error when `ctx.auth` is
/// `None` — every consumer of this bridge requires an authenticated
/// caller.
fn bridge_authenticated_context<'a>(
    ctx: ActionContext<'a>,
    audit: &'a Arc<AuditEmitter>,
    connection_closer: &'a Arc<dyn ConnectionCloser>,
) -> Result<(AuthenticatedActionContext<'a>, ActionDb<'a>), JsonrpcError> {
    // The actor-bound families (`Admin` / `RoleGrantOffer`) are `actor:
    // Required`, so the authorization phase always resolves the `Actor` variant
    // before the handler runs. The `unauthenticated()` fallback is defensive.
    let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
    Ok((
        AuthenticatedActionContext {
            auth,
            credential_type: ctx.credential_type,
            audit,
            post_commit: ctx.post_commit_effects,
            connection_closer,
            notification_sender: ctx.notification_sender,
            client_ip: ctx.client_ip,
        },
        ctx.db,
    ))
}

/// Bridge `fuz_actions::ActionContext` into a paired
/// `(AccountActionContext, ActionDb)` for an account-grain family. Consumes
/// `ctx` since `client_ip: Option<String>` is moved into the inner context.
///
/// The account-grain families are declared `actor: None`, so the authorization
/// phase produces the `Account` variant (account resolved, no actor) before the
/// handler runs. Returns the JSON-RPC `unauthenticated` error for any other
/// variant — defensive, since `account: Required` already 401s the anonymous
/// case and `actor: None` never yields the `Actor` variant.
fn bridge_account_grain_context<'a>(
    ctx: ActionContext<'a>,
    audit: &'a Arc<AuditEmitter>,
    connection_closer: &'a Arc<dyn ConnectionCloser>,
) -> Result<(AccountActionContext<'a>, ActionDb<'a>), JsonrpcError> {
    let auth = ctx
        .auth
        .account_grain()
        .ok_or_else(fuz_http::unauthenticated)?;
    Ok((
        AccountActionContext {
            auth,
            credential_type: ctx.credential_type,
            session_hash: ctx.session_hash,
            audit,
            post_commit: ctx.post_commit_effects,
            connection_closer,
            notification_sender: ctx.notification_sender,
            client_ip: ctx.client_ip,
        },
        ctx.db,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fuz_auth::{
        AdminOfferAuthorize, AuditEmitter, ConnectionCloser, NoopConnectionCloser, RoleRegistry,
        auth_action_entry,
    };

    use super::{
        build_account_specs, build_actor_lookup_specs, build_actor_search_specs, build_admin_specs,
        build_role_grant_offer_specs, build_self_service_role_specs,
    };
    use crate::action_spec::ActionSpec;

    /// A pool that is never connected — the builders only capture it inside
    /// the `AuditEmitter` these tests never dispatch through.
    fn audit() -> Arc<AuditEmitter> {
        let pool = fuz_db::create_pool(
            "postgres://nobody@127.0.0.1:1/nothing",
            &fuz_db::PoolOptions::default(),
        )
        .expect("pool");
        Arc::new(AuditEmitter::new(pool))
    }

    fn closer() -> Arc<dyn ConnectionCloser> {
        Arc::new(NoopConnectionCloser)
    }

    /// Every spec the auth-family builders produce, across all six
    /// registries — the account-grain families, the two actor surfaces, the
    /// self-service role toggle, and the two actor-bound families that build
    /// their specs directly.
    fn every_built_spec() -> Vec<ActionSpec> {
        let mut specs = build_account_specs(audit(), closer());
        specs.extend(build_admin_specs(
            audit(),
            closer(),
            Arc::new(RoleRegistry::default()),
        ));
        specs.extend(build_role_grant_offer_specs(
            audit(),
            closer(),
            Arc::new(AdminOfferAuthorize),
            Arc::new(RoleRegistry::default()),
        ));
        specs.extend(build_actor_lookup_specs(audit(), closer()));
        specs.extend(build_actor_search_specs(audit(), closer()));
        specs.extend(build_self_service_role_specs(audit(), closer(), Vec::new()));
        specs
    }

    /// The registry↔spec enforcement gate, in both directions that matter.
    ///
    /// Every built spec must resolve a row in
    /// `fuz_auth::AUTH_ACTION_ENTRY_REGISTRIES`, which is what makes the
    /// registry list *complete* for every family `every_built_spec` builds:
    /// a new family whose entries were added but whose registry was never
    /// listed there fails here once its builder joins `every_built_spec`
    /// (that builder list is the maintenance obligation) — and the
    /// `CredentialGate::Any` census in `fuz_auth`'s `action_auth` reads the
    /// same list, so an unlisted registry would otherwise be a whole
    /// authenticated surface silently missing from that review.
    ///
    /// And each spec's `rate_limit` must equal its entry's class — the class
    /// the dispatcher gates and introspection (`_testing_action_manifest`)
    /// reports.
    #[test]
    fn every_built_spec_matches_its_registry_entry() {
        let specs = every_built_spec();
        assert!(!specs.is_empty(), "the builders produce specs");
        for spec in &specs {
            let entry = auth_action_entry(spec.method).unwrap_or_else(|| {
                panic!(
                    "{} must be declared in an auth action registry",
                    spec.method
                )
            });
            assert_eq!(
                spec.rate_limit, entry.rate_limit,
                "{} must carry its entry's rate-limit class",
                spec.method,
            );
            assert_eq!(spec.auth, entry.auth, "{} auth shape", spec.method);
            assert_eq!(spec.input, entry.input, "{} input shape", spec.method);
            assert_eq!(
                spec.side_effects, entry.side_effects,
                "{} side effects",
                spec.method,
            );
        }
    }

    /// Every built spec passes the registry-time invariants together — unique
    /// methods across the families, and each entry's account-keyed class
    /// (carried as `rate_limit`) on a required account axis.
    #[test]
    fn every_built_spec_compiles_into_a_registry() {
        let specs = every_built_spec();
        let count = specs.len();
        let registry = crate::ActionRegistry::compile(specs)
            .unwrap_or_else(|e| panic!("the auth-family specs must compile: {e}"));
        assert_eq!(registry.len(), count);
    }
}
