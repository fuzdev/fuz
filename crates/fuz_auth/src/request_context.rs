//! Request contexts and the dispatcher's authorization phase.
//!
//! **Two structs, three resolved states.** Account-grain operations (logout,
//! password change) carry a [`RequestContext`] (account only); actions that
//! resolve an actor carry a [`RequestActorContext`] (account + actor +
//! `role_grants`). The dispatcher's authorization phase ([`apply_authorization_phase`])
//! produces one of three [`ResolvedAuthOwned`] states — anonymous, account-grain,
//! or actor-bound — reusing the two structs as payloads so the type-level actor
//! guarantee survives (make-impossible-states).
//!
//! The actor binds **here, at the authorization phase**, not at credential
//! resolution: the transport resolves account-grain identity and the dispatcher
//! resolves the acting actor from the request's `acting` input. This mirrors
//! `fuz_app`'s `auth/request_context.ts` (`resolve_acting_actor` +
//! `apply_authorization_phase`).

use deadpool_postgres::GenericClient;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::account_schema::AccountRow;
use crate::action_auth::{AuthAxis, AuthSpec};
use crate::actor_queries::{
    ResolveActingActorResult, query_role_grant_find_active_for_actor, resolve_acting_actor,
};
use crate::actor_schema::ActorRow;
use crate::role_grant_schema::RoleGrantRow;
use fuz_http::{JsonrpcError, JsonrpcErrorCode, internal_error_with_source};

/// Account-only context (`actor: None`).
///
/// Built by the authorization phase for account-grain actions — operations on
/// the caller's own account (logout, password change, account self-service)
/// that don't need a persona.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub account: AccountRow,
}

/// Actor-bound context. Built by the authorization phase when the action
/// resolves an actor (`actor: Optional` / `Required`) — most RPC handlers,
/// where the actor is the bridge to role grants.
#[derive(Debug, Clone)]
pub struct RequestActorContext {
    pub account: AccountRow,
    pub actor: ActorRow,
    pub role_grants: Vec<RoleGrantRow>,
}

impl RequestActorContext {
    /// Check if this context has an active role grant for `role` at exactly
    /// `scope` — `None` matches a **global** (unscoped) grant only.
    ///
    /// Mirrors TS `has_scoped_role`. `has_scoped_role(ROLE_ADMIN, None)` is
    /// the admin check everywhere admin confers authority: a scoped `admin`
    /// row (which no grant path mints — builtin roles are global-only)
    /// confers nothing.
    #[must_use]
    pub fn has_scoped_role(&self, role: &str, scope: Option<Uuid>) -> bool {
        self.role_grants
            .iter()
            .any(|g| g.role == role && g.scope_id == scope)
    }

    /// Check if this context has an active role grant for any of `roles` at
    /// exactly `scope` (`None` = global). Empty `roles` admits no-one.
    ///
    /// Mirrors TS `has_any_scoped_role`. The dispatcher's role gate calls it
    /// with `None`: a spec's `roles` names no scope, so only a global grant
    /// satisfies it.
    #[must_use]
    pub fn has_any_scoped_role(&self, roles: &[&str], scope: Option<Uuid>) -> bool {
        self.role_grants
            .iter()
            .any(|g| g.scope_id == scope && roles.contains(&g.role.as_str()))
    }
}

/// Owned resolved-auth state, living on the dispatcher's frame for the
/// duration of a request. Handlers borrow a [`ResolvedAuthContext`] view of it.
///
/// Three states — exactly the cases the authorization phase produces:
///
/// - [`Anonymous`](Self::Anonymous) — public actions, or an unauthenticated
///   caller on an `Optional` axis.
/// - [`Account`](Self::Account) — account-grain (`actor: None`): the resolved
///   account with no persona.
/// - [`Actor`](Self::Actor) — an acting actor resolved from `acting` (or the
///   single-actor account), with `role_grants` loaded.
#[derive(Debug)]
pub enum ResolvedAuthOwned {
    /// No identity surfaced.
    Anonymous,
    /// Account-grain (no actor).
    Account(RequestContext),
    /// Actor-bound.
    Actor(RequestActorContext),
}

impl ResolvedAuthOwned {
    /// Borrow this owned state as the handler-facing [`ResolvedAuthContext`].
    #[must_use]
    pub const fn as_context(&self) -> ResolvedAuthContext<'_> {
        match self {
            Self::Anonymous => ResolvedAuthContext::Anonymous,
            Self::Account(c) => ResolvedAuthContext::Account(c),
            Self::Actor(c) => ResolvedAuthContext::Actor(c),
        }
    }
}

/// Handler-facing borrowed view of the resolved auth state.
///
/// A discriminated enum reusing the existing two structs as payloads (the
/// idiomatic Rust analog of TS's nullable-actor struct + narrowing). `actor:
/// Required` handlers match [`Actor`](Self::Actor) and get the guaranteed actor
/// with no `Option` unwrap; identity-aware reads call [`Self::actor`] for the
/// `Option<&RequestActorContext>` shape.
#[derive(Debug, Clone, Copy)]
pub enum ResolvedAuthContext<'a> {
    /// No identity (public / unauthenticated optional axis).
    Anonymous,
    /// Account-grain (`actor: None`) — account self-service.
    Account(&'a RequestContext),
    /// Actor resolved — actor guaranteed at the type level.
    Actor(&'a RequestActorContext),
}

impl<'a> ResolvedAuthContext<'a> {
    /// The resolved actor context, or `None` for the anonymous / account-grain
    /// states. Identity-aware reads (`cell_get` / `cell_list`) call this to get
    /// the `Option<&RequestActorContext>` their authz predicates take.
    #[must_use]
    pub const fn actor(self) -> Option<&'a RequestActorContext> {
        match self {
            Self::Actor(c) => Some(c),
            Self::Anonymous | Self::Account(_) => None,
        }
    }

    /// The resolved account, or `None` for the anonymous state.
    #[must_use]
    pub const fn account(self) -> Option<&'a AccountRow> {
        match self {
            Self::Anonymous => None,
            Self::Account(c) => Some(&c.account),
            Self::Actor(c) => Some(&c.account),
        }
    }

    /// The account-grain context, or `None` unless this is the `Account` state.
    ///
    /// The account-grain dispatch bridge (`fuz_actions::auth_adapter`) calls
    /// this for `actor: None` specs — the authorization phase produces the
    /// `Account` variant for them (no actor resolved), and the handler needs the
    /// whole `&RequestContext`. Unlike [`Self::account`], this is `None` for the
    /// `Actor` variant: the account-grain families are declared `actor: None`,
    /// so they never resolve an actor, and a defensive `None` here surfaces a
    /// wiring mistake rather than silently account-grain-ing an actor context.
    #[must_use]
    pub const fn account_grain(self) -> Option<&'a RequestContext> {
        match self {
            Self::Account(c) => Some(c),
            Self::Anonymous | Self::Actor(_) => None,
        }
    }
}

/// The dispatcher's authorization phase — resolve the acting actor and build
/// the [`ResolvedAuthOwned`] context.
///
/// Ports `fuz_app`'s `apply_authorization_phase`. Branching by
/// `auth.account` × `auth.actor`:
///
/// - public (`account: None, actor: None`) → [`ResolvedAuthOwned::Anonymous`].
/// - `account == None` (optional axis, no credential) → `Anonymous`. `Required`
///   callers were already rejected by the pre-authorization 401.
/// - `actor == None` (account-grain) → [`ResolvedAuthOwned::Account`].
/// - `actor == Required | Optional` → resolve via [`resolve_acting_actor`]:
///   - resolved → [`ResolvedAuthOwned::Actor`] with `role_grants` loaded.
///   - multi-actor + no `acting` → `actor_required` 400 (`Required`) or
///     account-grain fallback (`Optional`).
///   - `acting` names a foreign actor → `actor_not_on_account` 400.
///   - zero actors → `no_actors_on_account` 500 (signup invariant violation).
///
/// The credential-resolved `account` is reused for the built context — no torn
/// read window, so `fuz_app`'s `account_vanished` 500 branch can't fire here.
///
/// # Errors
///
/// Returns a [`JsonrpcError`] folding the resolution failure into the wire
/// shape (`actor_required` / `actor_not_on_account` 400, `no_actors_on_account`
/// 500), or an internal error on a DB failure.
pub async fn apply_authorization_phase<C: GenericClient + ?Sized>(
    client: &C,
    account: Option<&AccountRow>,
    auth: &AuthSpec,
    acting: Option<Uuid>,
) -> Result<ResolvedAuthOwned, JsonrpcError> {
    if auth.is_public() {
        return Ok(ResolvedAuthOwned::Anonymous);
    }

    let Some(account) = account else {
        // Optional axis hit without a credential. `Required` callers were
        // already rejected at the pre-authorization 401 gate.
        return Ok(ResolvedAuthOwned::Anonymous);
    };

    if !auth.needs_actor() {
        // Account-grain (`actor: None`) — no persona resolution.
        return Ok(ResolvedAuthOwned::Account(RequestContext {
            account: account.clone(),
        }));
    }

    // `actor: Required` or `actor: Optional` — resolve the acting actor.
    let resolved = resolve_acting_actor(client, &account.id, acting)
        .await
        .map_err(|e| {
            internal_error_with_source("authorization phase: actor resolution failed", &e)
        })?;

    match resolved {
        ResolveActingActorResult::Resolved(actor) => {
            let role_grants = query_role_grant_find_active_for_actor(client, &actor.id)
                .await
                .map_err(|e| {
                    internal_error_with_source("authorization phase: role grants query failed", &e)
                })?;
            Ok(ResolvedAuthOwned::Actor(RequestActorContext {
                account: account.clone(),
                actor,
                role_grants,
            }))
        }
        ResolveActingActorResult::ActorRequired { available } => {
            if matches!(auth.actor, AuthAxis::Optional) {
                // Multi-actor account, no pick — fall back to account-grain.
                Ok(ResolvedAuthOwned::Account(RequestContext {
                    account: account.clone(),
                }))
            } else {
                Err(actor_required_error(&available))
            }
        }
        ResolveActingActorResult::ActorNotOnAccount => Err(actor_not_on_account_error()),
        ResolveActingActorResult::NoActors => Err(no_actors_error()),
    }
}

/// `actor_required` 400 — multi-actor account, no `acting` pick. Carries the
/// available actor list so the client can prompt; never a silent pick.
fn actor_required_error(available: &[ActorRow]) -> JsonrpcError {
    let available_json: Vec<Value> = available
        .iter()
        .map(|a| json!({"id": a.id, "name": a.name}))
        .collect();
    JsonrpcError {
        code: JsonrpcErrorCode::InvalidParams,
        message: "actor_required".to_owned(),
        data: Some(json!({"reason": "actor_required", "available": available_json})),
    }
}

/// `actor_not_on_account` 400 — `acting` named an actor not on the account.
/// Opaque (no available list echoed).
fn actor_not_on_account_error() -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::InvalidParams,
        message: "actor_not_on_account".to_owned(),
        data: Some(json!({"reason": "actor_not_on_account"})),
    }
}

/// `no_actors_on_account` 500 — the account enumerated zero actors. A
/// server-invariant violation: signup / bootstrap always mint an actor in-tx.
fn no_actors_error() -> JsonrpcError {
    JsonrpcError {
        code: JsonrpcErrorCode::InternalError,
        message: "no_actors_on_account".to_owned(),
        data: Some(json!({"reason": "no_actors_on_account"})),
    }
}
