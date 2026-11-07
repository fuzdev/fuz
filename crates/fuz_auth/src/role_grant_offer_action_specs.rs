//! Role-grant-offer action specs — consentful grant flow on the Rust
//! spine.
//!
//! Mirrors `fuz_app`'s `auth/role_grant_offer_actions.ts`. Ships the
//! full offer lifecycle (`_create` / `_accept` / `_decline` /
//! `_retract` / `_list` / `_history`) plus `role_grant_revoke` and
//! `role_grant_assign` (admin-only). Handlers emit audit events through
//! `ctx.audit_emit`
//! and fan out WS notifications to the affected counterparty through
//! the `ctx.notification_sender` capability, queued on the post-commit
//! drain (`queue_offer_notification`) so a rolled-back tx never leaks
//! a notification. `Noop` when the consumer wires no WS surface.
//!
//! Handler shape parallels `admin_action_specs.rs`:
//! `ROLE_GRANT_OFFER_ACTION_ENTRIES` static + `RoleGrantOfferActionSpecs`
//! dispatch + the shared
//! [`crate::auth_action_context::AuthenticatedActionContext`]. The
//! `fuz_actions` adapter (`build_role_grant_offer_specs`) reads the
//! entries and surfaces them on the unified registry, same as
//! `build_admin_specs`.

use serde::Serialize;
use serde_json::Value;

use crate::action_auth::AuthSpec;
use crate::action_rate_limit::RateLimitClass;
use crate::actor_queries::{
    query_account_has_active_global_role, query_account_has_global_role,
    query_active_actors_by_account, query_count_active_accounts_with_global_role_for_update,
    query_create_role_grant,
};
use crate::audit_emitter::AuditLogInput;
use crate::audit_event_type::AuditEventType;
use crate::auth_action_context::AuthenticatedActionContext;
use crate::auth_action_entry::AuthActionEntry;
use crate::credential_type::CredentialGate;
use crate::name_schema::is_valid_name;
use crate::params_helpers::{parse_pagination_params, parse_role_param, require_text_len};
use crate::request_context::RequestActorContext;
use crate::role::{ROLE_ADMIN, ROLE_KEEPER, RoleRegistry, is_builtin_role};
use crate::role_grant_offer_queries::{
    AcceptOfferInput, AcceptOfferResult, BuiltinOfferRefusal, CreateRoleGrantOfferInput,
    RevokeRoleGrantResult, RoleGrantOffer, RoleGrantOfferError, SupersededOffer,
    default_expiry_from_now, query_accept_offer, query_revoke_role_grant,
    query_role_grant_find_active_role_for_actor, query_role_grant_offer_create,
    query_role_grant_offer_decline, query_role_grant_offer_history_for_account,
    query_role_grant_offer_list, query_role_grant_offer_retract,
    query_role_grant_offer_supersede_outgoing,
};
use futures::future::BoxFuture;
use fuz_db::{ActionDb, action_db_dispatch};
use fuz_http::{
    InputShape, JsonrpcError, forbidden, internal_error_with_source, invalid_input_params,
    invalid_params, invalid_request, method_not_found, not_found, parse_optional_str_param,
    parse_optional_uuid_param, parse_uuid_param, reject_unknown_keys, serialize_result,
};

/// WS-notification methods for the consentful-grant lifecycle.
///
/// Each is pushed to the affected counterparty and mirrors a TS
/// notification method in
/// `fuz_app/src/lib/auth/role_grant_offer_notifications.ts`; the wire
/// params are `{ offer: RoleGrantOffer }` for the offer-lifecycle events
/// (received / retracted / accepted / declined), `{ offer, reason,
/// cause_id }` for supersede, and a flat `{ role_grant_id, role,
/// scope_kind, scope_id, reason }` for revoked.
///
/// `received` → recipient on create; `retracted` → recipient; `accepted`
/// / `declined` → grantor; `supersede` (one per superseded sibling) →
/// each sibling's grantor; `revoked` → revokee, sent by the admin
/// `role_grant_revoke` action, whose method it doesn't share.
pub const ROLE_GRANT_OFFER_RECEIVED_METHOD: &str = "role_grant_offer_received";
pub const ROLE_GRANT_OFFER_RETRACTED_METHOD: &str = "role_grant_offer_retracted";
pub const ROLE_GRANT_OFFER_ACCEPTED_METHOD: &str = "role_grant_offer_accepted";
pub const ROLE_GRANT_OFFER_DECLINED_METHOD: &str = "role_grant_offer_declined";
pub const ROLE_GRANT_OFFER_SUPERSEDE_METHOD: &str = "role_grant_offer_supersede";
pub const ROLE_GRANT_REVOKED_METHOD: &str = "role_grant_revoked";

/// Max length of the free-text `message` on `role_grant_offer_create` and of
/// the `reason` on `role_grant_offer_decline`. Mirrors the TS
/// `ROLE_GRANT_OFFER_MESSAGE_LENGTH_MAX`.
pub const ROLE_GRANT_OFFER_MESSAGE_LENGTH_MAX: usize = 500;

/// Max length of the free-text `reason` on `role_grant_revoke`, stamped on
/// `role_grant.revoked_reason`.
///
/// Mirrors the TS `ROLE_GRANT_REVOKED_REASON_LENGTH_MAX`. Same value as
/// [`ROLE_GRANT_OFFER_MESSAGE_LENGTH_MAX`] today, kept a separate constant
/// because the two are separate columns on separate tables — the twin names
/// them separately for the same reason.
pub const ROLE_GRANT_REVOKED_REASON_LENGTH_MAX: usize = 500;

/// `data.reason` on the offer-create role-not-grantable denial.
/// Mirrors `ERROR_ROLE_GRANT_OFFER_ROLE_NOT_GRANTABLE` in
/// `fuz_app/src/lib/http/error_schemas.ts`.
pub const ERROR_ROLE_GRANT_OFFER_ROLE_NOT_GRANTABLE: &str = "role_grant_offer_role_not_grantable";

/// `data.reason` on the offer-create authorize-callback denial. Mirrors
/// `ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED`.
pub const ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED: &str = "role_grant_offer_not_authorized";

/// `data.reason` on `query_role_grant_offer_create`'s self-target reject.
pub const ERROR_ROLE_GRANT_OFFER_SELF_TARGET: &str = "role_grant_offer_self_target";

/// `data.reason` when `to_actor_id` is supplied but doesn't belong to
/// `to_account_id`.
pub const ERROR_ROLE_GRANT_OFFER_ACTOR_ACCOUNT_MISMATCH: &str =
    "role_grant_offer_actor_account_mismatch";

/// `data.reason` when the offer id is missing or belongs to a
/// different recipient (IDOR mask).
pub const ERROR_ROLE_GRANT_OFFER_NOT_FOUND: &str = "role_grant_offer_not_found";

/// `data.reason` when the offer is in a terminal state on accept.
pub const ERROR_ROLE_GRANT_OFFER_TERMINAL: &str = "role_grant_offer_terminal";

/// `data.reason` when the offer is pending but past `expires_at`.
pub const ERROR_ROLE_GRANT_OFFER_EXPIRED: &str = "role_grant_offer_expired";

/// `data.reason` when an actor-targeted offer is being accepted by a
/// different actor on the same account.
pub const ERROR_ROLE_GRANT_OFFER_ACTOR_MISMATCH: &str = "role_grant_offer_actor_mismatch";

/// `data.reason` when a `role_grant_revoke` target id is missing,
/// already revoked, or belongs to a different actor (IDOR mask).
/// Mirrors `ERROR_ROLE_GRANT_NOT_FOUND`.
pub const ERROR_ROLE_GRANT_NOT_FOUND: &str = "role_grant_not_found";

/// `data.reason` when `role_grant_revoke` rejects a role whose
/// `grant_paths` doesn't include `'admin'` (keeper / daemon-scoped
/// roles stay CLI-only). Mirrors `ERROR_ROLE_NOT_WEB_GRANTABLE`.
pub const ERROR_ROLE_NOT_WEB_GRANTABLE: &str = "role_not_web_grantable";

/// `data.reason` when a grant path is asked to bind a builtin role to a scope.
///
/// Builtin roles (`admin` / `keeper`) are global-only: every builtin gate
/// reads the global grant, so a scoped one would confer nothing but a
/// misleading row — refused at `role_grant_assign`, `role_grant_offer_create`,
/// and `role_grant_offer_accept`.
pub const ERROR_ROLE_GRANT_BUILTIN_SCOPED: &str = "role_grant_builtin_scoped";

/// `data.reason` when `role_grant_revoke` targets the **keeper** account's
/// global `admin` grant.
///
/// A **403**. No web path grants `admin` to the keeper again (bootstrap is
/// one-shot and keeper is not web-grantable), so revoking it would lock the
/// keeper out of the admin surface for good. Mirrors TS
/// `ERROR_CANNOT_REVOKE_KEEPER_ADMIN`.
pub const ERROR_CANNOT_REVOKE_KEEPER_ADMIN: &str = "cannot_revoke_keeper_admin";

/// `data.reason` when `role_grant_revoke` targets a global `admin` grant whose
/// revoke would leave no active admin account.
///
/// A **403**, counted as `account_delete`'s last-admin guard counts (active
/// accounts, active actors), less the grant being revoked, under the same row
/// locks. Mirrors TS
/// `ERROR_CANNOT_REVOKE_LAST_ADMIN`.
pub const ERROR_CANNOT_REVOKE_LAST_ADMIN: &str = "cannot_revoke_last_admin";

/// Admin role allowlist for the dispatcher-gated `role_grant_revoke` /
/// `role_grant_assign` methods.
const ADMIN_GATE_ROLES: &[&str] = &[ROLE_ADMIN];

/// Parsed `role_grant_offer_create` params an [`OfferCreateAuthorize`] gates on.
///
/// Mirrors the `input` arg of TS `RoleGrantOfferCreateAuthorize` (`role`,
/// `scope_id`, `to_account_id`), plus `scope_kind` for scope-typed offers.
#[derive(Debug, Clone)]
pub struct OfferCreateAuthorizeInput {
    pub role: String,
    pub scope_kind: Option<String>,
    pub scope_id: Option<uuid::Uuid>,
    pub to_account_id: uuid::Uuid,
}

/// Consumer-injectable authorization predicate for
/// `role_grant_offer_create` and `role_grant_assign` — the Rust twin of TS
/// `RoleGrantOfferCreateAuthorize`.
///
/// Assign — the global-admin path that confers a grant with no offer — runs
/// it too, so a policy over which grants may exist (a role that must be
/// scoped, a scope that must be real) holds on both paths.
///
/// **Object-safe** — dispatched as `Arc<dyn OfferCreateAuthorize>` on the
/// cold offer-create path (one DB-write request, vtable cost negligible).
/// Async via [`BoxFuture`] per the spine's dyn-trait carve-out.
///
/// Invoked AFTER the admin-grantability gate (`roles.is_admin_grantable`), so
/// the predicate only ever sees admin-grantable roles — matching the TS
/// ordering where the callback runs after the grant-path filter. A builtin
/// role never reaches it unless the caller holds a **global** `admin`: the
/// spine decides builtin-role offers itself, so a predicate needs no builtin
/// handling of its own. Returns
/// `Ok(true)` to admit, `Ok(false)` to deny (→ `forbidden` /
/// `role_grant_offer_not_authorized`), or `Err` for a hard error (e.g. a
/// DB failure inside a scoped-existence guard).
///
/// `db` is the request's own handle — both verbs have side effects, so it is
/// the request transaction — and an impl that needs the database (a
/// scoped-existence check on a consumer-owned table, say) reads through it
/// with [`fuz_db::action_db_dispatch!`]: no second pool checkout, and the read
/// sees the request's snapshot. **Read-only**: the predicate decides, it never
/// writes — a write would commit or roll back with the request, and nothing
/// enforces this but the impl.
pub trait OfferCreateAuthorize: Send + Sync {
    fn authorize<'a>(
        &'a self,
        auth: &'a RequestActorContext,
        input: &'a OfferCreateAuthorizeInput,
        db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>>;
}

/// Default offer-create authorization — the v1 **admin-only** check.
///
/// The caller must hold a **global** `admin` grant; holding the offered role
/// itself confers no power to offer it (no holder-propagation). The global
/// check keys on
/// `has_scoped_role(ADMIN, None)` so a *scoped* `admin` can't escalate into
/// global authority over the offer surface. Mirrors TS `default_authorize`.
/// The behaviour `build_auth_spec_set` wires when a consumer supplies no custom
/// predicate; a consumer wanting scoped delegation supplies its own
/// `OfferCreateAuthorize` (e.g. one that lets the holder of a scoped grant
/// offer roles within that scope).
#[derive(Debug, Clone, Copy, Default)]
pub struct AdminOfferAuthorize;

impl AdminOfferAuthorize {
    /// The decision itself: whether `auth` holds a **global** `admin` grant.
    /// Reads the request's role-grant snapshot alone — no database.
    #[must_use]
    pub fn admits(auth: &RequestActorContext) -> bool {
        auth.has_scoped_role(ROLE_ADMIN, None)
    }
}

impl OfferCreateAuthorize for AdminOfferAuthorize {
    fn authorize<'a>(
        &'a self,
        auth: &'a RequestActorContext,
        _input: &'a OfferCreateAuthorizeInput,
        _db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>> {
        let allowed = Self::admits(auth);
        Box::pin(async move { Ok(allowed) })
    }
}

/// Role-grant-offer action registry — every method, in registration
/// order: `_create` / `_accept` / `_decline` / `_retract` / `_list` /
/// `_history` + `role_grant_revoke` + `role_grant_assign`.
///
/// Auth: every method is `Authenticated` (no role gate at the
/// dispatcher) except `role_grant_revoke` and `role_grant_assign`, which
/// add `roles: ['admin']`. `_create` and `_accept` are session-only
/// ([`CredentialGate::SESSION_ONLY`]) — the two verbs that confer a role.
/// Handler-level checks enforce the admin-grant-path-only
/// constraint (create / revoke) and IDOR guards (accept / decline /
/// retract).
///
/// TS posture: `role_grant_offer_create`, `role_grant_offer_accept`,
/// `role_grant_revoke`, and `role_grant_assign` carry `rate_limit: 'account'`
/// — offer-spam plus the account-existence-oracle surface on create, replay
/// churn on accept (each call locks the offer row and reads the grant), and
/// admin-side burn on the two grant mutations. The rest are ungated:
/// `_decline` / `_retract` / `_list` / `_history` confer nothing.
pub static ROLE_GRANT_OFFER_ACTION_ENTRIES: &[AuthActionEntry] = &[
    // `CredentialGate::SESSION_ONLY` — offering spends the caller's authority
    // to confer a role. Over a leaked API token that is a privilege pivot onto
    // another account: the leak offers a role to an account its holder
    // controls, that account accepts over its own session, and the resulting
    // role_grant outlives revoking the token. Under a consumer authorizer that
    // delegates offering (a scoped holder offering roles in its scope), every
    // such holder's token would be a role-minting credential. An offer is a
    // grantor's consent act, like accepting is the recipient's; scripted
    // conferral is `role_grant_assign`'s, admin-gated and narrowable by a
    // token scope.
    AuthActionEntry {
        method: "role_grant_offer_create",
        auth: AuthSpec::authenticated(CredentialGate::SESSION_ONLY),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    // `CredentialGate::SESSION_ONLY` — the offer verb that moves the
    // *caller's own* authority. Accepting a pending admin offer over a leaked
    // API token is a privilege pivot in the same family as the credential-
    // lifecycle mutations `account_grain(SESSION_ONLY)` closes: the token is
    // account-wide and non-expiring, and the resulting role_grant outlives
    // revoking it. Consent inherently belongs to a human at a browser, and no
    // automation accepts an offer on its own behalf. `_decline` / `_retract`
    // stay `Any` deliberately — they destroy a pending offer and confer
    // nothing.
    AuthActionEntry {
        method: "role_grant_offer_accept",
        auth: AuthSpec::authenticated(CredentialGate::SESSION_ONLY),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "role_grant_offer_decline",
        auth: AuthSpec::authenticated(CredentialGate::Any),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "role_grant_offer_retract",
        auth: AuthSpec::authenticated(CredentialGate::Any),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "role_grant_offer_list",
        auth: AuthSpec::authenticated(CredentialGate::Any),
        input: InputShape::Object,
        side_effects: false,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "role_grant_offer_history",
        auth: AuthSpec::authenticated(CredentialGate::Any),
        input: InputShape::Object,
        side_effects: false,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "role_grant_revoke",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_GATE_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "role_grant_assign",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_GATE_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
];

/// Top-level dispatcher type — matches the `AdminActionSpecs` /
/// `AccountActionSpecs` shape.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoleGrantOfferActionSpecs;

impl RoleGrantOfferActionSpecs {
    /// Dispatch a role-grant-offer action over the request's `db`.
    ///
    /// # Errors
    ///
    /// Returns a [`JsonrpcError`] on validation failure, denial,
    /// driver error, or serialization failure.
    pub async fn dispatch(
        method: &str,
        params: &Value,
        ctx: &AuthenticatedActionContext<'_>,
        db: &ActionDb<'_>,
        authorize: &dyn OfferCreateAuthorize,
        roles: &RoleRegistry,
    ) -> Result<Value, JsonrpcError> {
        action_db_dispatch!(db, client => {
            dispatch_method(method, params, ctx, client, db, authorize, roles).await
        })
    }
}

/// [`RoleGrantOfferActionSpecs::dispatch`] over the concrete client: `db` is
/// `action_db`'s client, and `action_db` itself goes only to the verbs that ask
/// the [`OfferCreateAuthorize`].
async fn dispatch_method(
    method: &str,
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    action_db: &ActionDb<'_>,
    authorize: &dyn OfferCreateAuthorize,
    roles: &RoleRegistry,
) -> Result<Value, JsonrpcError> {
    match method {
        "role_grant_offer_create" => {
            handle_role_grant_offer_create(params, ctx, db, action_db, authorize, roles).await
        }
        "role_grant_offer_accept" => handle_role_grant_offer_accept(params, ctx, db).await,
        "role_grant_offer_decline" => handle_role_grant_offer_decline(params, ctx, db).await,
        "role_grant_offer_retract" => handle_role_grant_offer_retract(params, ctx, db).await,
        "role_grant_offer_list" => handle_role_grant_offer_list(params, ctx, db).await,
        "role_grant_offer_history" => handle_role_grant_offer_history(params, ctx, db).await,
        "role_grant_revoke" => handle_role_grant_revoke(params, ctx, db, roles).await,
        "role_grant_assign" => {
            handle_role_grant_assign(params, ctx, db, action_db, authorize, roles).await
        }
        _ => Err(method_not_found(method)),
    }
}

/// Queue a JSON-RPC notification to every socket bound to `recipient`,
/// on the post-commit drain (same seam as the audit fan-out) so a
/// rolled-back tx never leaks a notification. The send itself is a
/// non-blocking channel push; `Noop` when the consumer has no WS
/// surface. Mirrors the TS `notification_sender.send_to_account` calls
/// queued via `emit_after_commit` in `role_grant_offer_actions.ts`.
fn queue_offer_notification(
    ctx: &AuthenticatedActionContext<'_>,
    recipient: uuid::Uuid,
    method: &'static str,
    params: &Value,
) {
    let message = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
    .to_string();
    let sender = std::sync::Arc::clone(ctx.notification_sender);
    ctx.post_commit.queue_notify(Box::new(move || {
        Box::pin(async move {
            sender.send_to_account(recipient, &message);
        })
    }));
}

/// Fan out a `role_grant_offer_supersede` notification to each superseded
/// sibling's *grantor* (`sibling.from_account_id` off the query
/// RETURNING — never the audit `target_account`). `reason` is
/// `"sibling_accepted"` (accept path) or `"role_grant_revoked"` (revoke
/// path); `cause_id` is the accepted offer id or the revoked `role_grant`
/// id respectively.
///
/// `pub(crate)` as the notification half of the supersede fan-out pair —
/// [`emit_supersede_audits`] is the audit half. Wiring it into
/// `self_service_role_action_specs`'s revoke cascade is a deliberate
/// open decision, not a reachability problem (see the TODO there).
pub(crate) fn queue_supersede_notifications(
    ctx: &AuthenticatedActionContext<'_>,
    siblings: &[SupersededOffer],
    reason: &'static str,
    cause_id: uuid::Uuid,
) {
    for sibling in siblings {
        queue_offer_notification(
            ctx,
            sibling.from_account_id,
            ROLE_GRANT_OFFER_SUPERSEDE_METHOD,
            &serde_json::json!({
                "offer": &sibling.offer,
                "reason": reason,
                "cause_id": cause_id,
            }),
        );
    }
}

/// Emit one `role_grant_offer_supersede` audit row per pending sibling offer
/// a cascade invalidated — the accept path (`reason: "sibling_accepted"`),
/// the admin `role_grant_revoke` path (the revokee's incoming siblings and its
/// own outgoing offers) and the self-service revoke path (all
/// `"role_grant_revoked"`), and account removal (`"account_deleted"`).
/// `cause_id` is the accepted offer id, the revoked `role_grant` id, or the
/// removed account id respectively.
///
/// The acting pair is read off `ctx`, not passed in: every call site is the
/// caller's own `ctx.auth.actor.id` / `ctx.auth.account.id`, so two adjacent
/// bare `Uuid` params bought nothing but a silently-compiling swap.
///
/// The target pair is the *sibling's*: `to_account_id` (the recipient inbox
/// the offer was pending in) and the actor-grain `to_actor_id`, null on
/// account-grain offers. On the accept path that target account happens to
/// equal the acting account — the handler passes `ctx.auth.account.id` as
/// `AcceptOfferInput.to_account_id`, and the supersede UPDATE matches
/// siblings on exactly that column — but on the admin revoke path it is the
/// revokee's inbox instead (self-service revokes its caller's own, where the
/// two coincide), which is why the two pairs are sourced separately.
pub(crate) async fn emit_supersede_audits(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    siblings: &[SupersededOffer],
    reason: &'static str,
    cause_id: uuid::Uuid,
) -> Result<(), JsonrpcError> {
    for sibling in siblings {
        ctx.audit_emit(
            db,
            AuditLogInput::for_event(AuditEventType::RoleGrantOfferSupersede)
                .actor(ctx.auth.actor.id)
                .account(ctx.auth.account.id)
                .target_account(sibling.offer.to_account_id)
                .target_actor(sibling.offer.to_actor_id)
                .ip(ctx.client_ip.clone())
                .metadata(serde_json::json!({
                    "offer_id": sibling.offer.id.to_string(),
                    "role": sibling.offer.role,
                    "scope_id": sibling.offer.scope_id.map(|u| u.to_string()),
                    "reason": reason,
                    "cause_id": cause_id.to_string(),
                })),
        )
        .await?;
    }
    Ok(())
}

/// Declared input keys per method, each the exact key set of the TS twin's
/// `object` in `auth/role_grant_offer_action_specs.ts`.
///
/// [`reject_unknown_keys`] runs each list at the top of its handler. Every
/// spec in this family carries an actor axis, so every list declares `acting`
/// — the twin's biconditional.
mod keys {
    /// `role_grant_offer_create`.
    pub const OFFER_CREATE: &[&str] = &[
        "to_account_id",
        "to_actor_id",
        "role",
        "scope_kind",
        "scope_id",
        "message",
        "acting",
    ];
    /// `role_grant_offer_accept`.
    pub const OFFER_ACCEPT: &[&str] = &["offer_id", "acting"];
    /// `role_grant_offer_decline`.
    pub const OFFER_DECLINE: &[&str] = &["offer_id", "reason", "acting"];
    /// `role_grant_offer_retract`.
    pub const OFFER_RETRACT: &[&str] = &["offer_id", "acting"];
    /// `role_grant_offer_list`.
    pub const OFFER_LIST: &[&str] = &["account_id", "acting"];
    /// `role_grant_offer_history`.
    pub const OFFER_HISTORY: &[&str] = &["account_id", "limit", "offset", "acting"];
    /// `role_grant_revoke`.
    pub const ROLE_GRANT_REVOKE: &[&str] = &["actor_id", "role_grant_id", "reason", "acting"];
    /// `role_grant_assign`.
    pub const ROLE_GRANT_ASSIGN: &[&str] = &[
        "to_account_id",
        "to_actor_id",
        "role",
        "scope_kind",
        "scope_id",
        "acting",
    ];
}

// --- create -----------------------------------------------------------

#[derive(Debug)]
struct CreateParams {
    to_account_id: uuid::Uuid,
    role: String,
    scope_kind: Option<String>,
    scope_id: Option<uuid::Uuid>,
    message: Option<String>,
    to_actor_id: Option<uuid::Uuid>,
}

/// Refuse a half-scoped grant input: `scope_kind` and `scope_id` are paired —
/// both absent for a global grant, both present for a scoped one — the
/// `role_grant_scope_kind_paired` / `role_grant_offer_scope_kind_paired`
/// CHECKs, surfaced as `-32602` here rather than a constraint-violation 500.
fn require_scope_paired(
    scope_kind: Option<&str>,
    scope_id: Option<uuid::Uuid>,
) -> Result<(), JsonrpcError> {
    if scope_kind.is_some() != scope_id.is_some() {
        return Err(invalid_input_params(
            "'scope_kind' and 'scope_id' must be given together (both for a scoped grant, \
             neither for a global one)",
            None,
        ));
    }
    Ok(())
}

/// Whether a grant input binds a builtin role to a scope — refused on every
/// grant path (see [`ERROR_ROLE_GRANT_BUILTIN_SCOPED`]).
fn is_scoped_builtin(role: &str, scope_id: Option<uuid::Uuid>) -> bool {
    scope_id.is_some() && is_builtin_role(role)
}

/// The `-32602` a scoped builtin-role grant input answers.
fn builtin_scoped_error() -> JsonrpcError {
    invalid_params(
        "builtin roles are global-only and cannot be scoped",
        Some(ERROR_ROLE_GRANT_BUILTIN_SCOPED),
    )
}

/// Parse the optional `scope_kind` both grant inputs carry: a scope-kind name
/// ([`is_valid_name`], the shared name grammar and its length cap), twin of the
/// shared `optional(nullable(ScopeKindName))`. Off the grammar is `-32602` with no
/// reason, as an off-grammar `role` is — the index-side `'GLOBAL'` token
/// among it, which with the all-zeros `scope_id` would otherwise equal a
/// global grant's key in the partial unique indexes.
fn parse_scope_kind_param(params: &Value) -> Result<Option<String>, JsonrpcError> {
    let Some(scope_kind) = parse_optional_str_param(params, "scope_kind")? else {
        return Ok(None);
    };
    if !is_valid_name(scope_kind) {
        return Err(invalid_input_params(
            "'scope_kind' is not a valid scope-kind name",
            None,
        ));
    }
    Ok(Some(scope_kind.to_owned()))
}

fn parse_create_params(params: &Value) -> Result<CreateParams, JsonrpcError> {
    reject_unknown_keys(params, keys::OFFER_CREATE)?;
    let to_account_id = parse_uuid_param(params, "to_account_id")?;
    let role = parse_role_param(params, "role")?.to_owned();
    let scope_kind = parse_scope_kind_param(params)?;
    let scope_id = parse_optional_uuid_param(params, "scope_id")?;
    require_scope_paired(scope_kind.as_deref(), scope_id)?;
    let message = parse_optional_str_param(params, "message")?.map(str::to_owned);
    if let Some(message) = message.as_deref() {
        require_text_len(message, ROLE_GRANT_OFFER_MESSAGE_LENGTH_MAX, "message")?;
    }
    let to_actor_id = parse_optional_uuid_param(params, "to_actor_id")?;
    Ok(CreateParams {
        to_account_id,
        role,
        scope_kind,
        scope_id,
        message,
        to_actor_id,
    })
}

#[derive(Debug, Serialize)]
struct CreateResult<'a> {
    offer: &'a RoleGrantOffer,
}

async fn handle_role_grant_offer_create(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    action_db: &ActionDb<'_>,
    authorize: &dyn OfferCreateAuthorize,
    roles: &RoleRegistry,
) -> Result<Value, JsonrpcError> {
    let parsed = parse_create_params(params)?;
    let caller_actor_id = ctx.auth.actor.id;
    let caller_account_id = ctx.auth.account.id;

    // Admin-grantability gate — registry-driven (`grant_paths` includes
    // `Admin`). The default registry admits only `admin`; a consumer registry
    // admits its app roles. Mirrors TS `role_has_grant_path(role_specs,
    // input.role, GRANT_PATH_ADMIN)`. Runs BEFORE the injected authorize
    // predicate so the predicate only sees admin-grantable roles (matches TS
    // ordering).
    if !roles.is_admin_grantable(&parsed.role) {
        emit_create_failure_audit(ctx, db, &parsed, caller_account_id, caller_actor_id).await?;
        return Err(forbidden(
            "role not grantable",
            Some(ERROR_ROLE_GRANT_OFFER_ROLE_NOT_GRANTABLE),
        ));
    }

    // Builtin roles are global-only — refused before the injected predicate,
    // so no consumer authorizer can admit a scoped `admin` / `keeper` offer.
    if is_scoped_builtin(&parsed.role, parsed.scope_id) {
        emit_create_failure_audit(ctx, db, &parsed, caller_account_id, caller_actor_id).await?;
        return Err(builtin_scoped_error());
    }

    // Offering a builtin role is global-admin authority, decided here rather
    // than by the injected predicate: a consumer predicate answering by holding
    // the role (a scope-blind check) would otherwise let a scoped `admin`
    // row offer a global `admin` to a second account it controls. Same denial
    // the default predicate gives.
    if is_builtin_role(&parsed.role) && !ctx.auth.has_scoped_role(ROLE_ADMIN, None) {
        emit_create_failure_audit(ctx, db, &parsed, caller_account_id, caller_actor_id).await?;
        return Err(forbidden(
            "not authorized to offer this role",
            Some(ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED),
        ));
    }

    // Injected authorize predicate (TS `RoleGrantOfferCreateAuthorize`).
    // `AdminOfferAuthorize` = the default admin-only check (caller holds
    // `admin`); a consumer can supply a scope-aware predicate (e.g. a
    // classroom teacher offering scoped roles). `Err` surfaces a hard
    // failure; `Ok(false)` is a forensic-audited denial.
    let authz_input = OfferCreateAuthorizeInput {
        role: parsed.role.clone(),
        scope_kind: parsed.scope_kind.clone(),
        scope_id: parsed.scope_id,
        to_account_id: parsed.to_account_id,
    };
    if !authorize
        .authorize(ctx.auth, &authz_input, action_db)
        .await?
    {
        emit_create_failure_audit(ctx, db, &parsed, caller_account_id, caller_actor_id).await?;
        return Err(forbidden(
            "not authorized to offer this role",
            Some(ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED),
        ));
    }

    let offer = match query_role_grant_offer_create(
        db,
        CreateRoleGrantOfferInput {
            from_actor_id: caller_actor_id,
            to_account_id: parsed.to_account_id,
            to_actor_id: parsed.to_actor_id,
            role: parsed.role.clone(),
            scope_kind: parsed.scope_kind.clone(),
            scope_id: parsed.scope_id,
            message: parsed.message.clone(),
            expires_at: default_expiry_from_now(),
        },
    )
    .await
    {
        Ok(offer) => offer,
        Err(RoleGrantOfferError::SelfTarget) => {
            emit_create_failure_audit(ctx, db, &parsed, caller_account_id, caller_actor_id).await?;
            return Err(invalid_params(
                "cannot offer to self",
                Some(ERROR_ROLE_GRANT_OFFER_SELF_TARGET),
            ));
        }
        Err(RoleGrantOfferError::ActorAccountMismatch) => {
            emit_create_failure_audit(ctx, db, &parsed, caller_account_id, caller_actor_id).await?;
            return Err(invalid_params(
                "to_actor_id does not belong to to_account_id",
                Some(ERROR_ROLE_GRANT_OFFER_ACTOR_ACCOUNT_MISMATCH),
            ));
        }
        Err(err) => return Err(map_offer_error(err, "role_grant_offer_create")),
    };

    // Success audit — actor-grain `target_actor_id` populated when the
    // offer is actor-targeted; account-grain (null) otherwise.
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantOfferCreate)
            .actor(caller_actor_id)
            .account(caller_account_id)
            .target_account(parsed.to_account_id)
            .target_actor(offer.to_actor_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "offer_id": offer.id.to_string(),
                "role": offer.role,
                "scope_id": offer.scope_id.map(|u| u.to_string()),
                "to_account_id": offer.to_account_id.to_string(),
            })),
    )
    .await?;

    // WS notification — the recipient's inbox push. The recipient is
    // `offer.to_account_id`, already in scope — no re-query, unlike an
    // audit-chain-derived design (the flat audit metadata can't
    // reconstruct the 16-field offer payload).
    queue_offer_notification(
        ctx,
        offer.to_account_id,
        ROLE_GRANT_OFFER_RECEIVED_METHOD,
        &serde_json::json!({ "offer": &offer }),
    );

    serialize_result(CreateResult { offer: &offer })
}

async fn emit_create_failure_audit(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    parsed: &CreateParams,
    caller_account_id: uuid::Uuid,
    caller_actor_id: uuid::Uuid,
) -> Result<(), JsonrpcError> {
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantOfferCreate)
            .failure()
            .actor(caller_actor_id)
            .account(caller_account_id)
            .target_account(parsed.to_account_id)
            .target_actor(parsed.to_actor_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "role": parsed.role,
                "scope_id": parsed.scope_id.map(|u| u.to_string()),
                "to_account_id": parsed.to_account_id.to_string(),
            })),
    )
    .await
}

// --- accept -----------------------------------------------------------

#[derive(Debug, Serialize)]
struct AcceptResult<'a> {
    role_grant_id: uuid::Uuid,
    offer: &'a RoleGrantOffer,
    superseded_offer_ids: Vec<uuid::Uuid>,
}

async fn handle_role_grant_offer_accept(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::OFFER_ACCEPT)?;
    let offer_id = parse_uuid_param(params, "offer_id")?;
    let caller_actor_id = ctx.auth.actor.id;
    let caller_account_id = ctx.auth.account.id;

    let result = match query_accept_offer(
        db,
        AcceptOfferInput {
            offer_id,
            to_account_id: caller_account_id,
            actor_id: caller_actor_id,
        },
    )
    .await
    {
        Ok(result) => result,
        Err(RoleGrantOfferError::BuiltinRefused { offer, refusal }) => {
            return Err(refuse_builtin_accept(ctx, db, &offer, refusal).await?);
        }
        Err(err) => return Err(map_offer_transition_error(err, "role_grant_offer_accept")),
    };

    // A replay (or a race loser) wrote nothing — the accept that minted the
    // grant already audited it and notified the grantor — so it audits and
    // notifies nothing; repeating them would let any replay write rows and
    // send notifications without bound.
    if result.created {
        emit_accept_audits(ctx, db, &result, caller_account_id, caller_actor_id).await?;
    }

    let superseded_offer_ids: Vec<uuid::Uuid> = result
        .superseded_offers
        .iter()
        .map(|s| s.offer.id)
        .collect();
    serialize_result(AcceptResult {
        role_grant_id: result.role_grant_id,
        offer: &result.offer,
        superseded_offer_ids,
    })
}

/// Answer (and audit) an accept the query refused as a builtin-role offer that
/// must not mint.
///
/// The refusal is a forensic event — someone holds an offer of a builtin role
/// the spine won't confer — so it is audited as a `role_grant_offer_accept`
/// **failure**, the way offer-create refusals are. Failure outcomes route
/// through the pool, so the row survives the request's rollback. Metadata is
/// the success row's shape minus `role_grant_id` (no grant was minted), plus
/// the wire `reason`.
///
/// Returns the error the verb answers; `Err` only on an audit-emit failure.
async fn refuse_builtin_accept(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    offer: &RoleGrantOffer,
    refusal: BuiltinOfferRefusal,
) -> Result<JsonrpcError, JsonrpcError> {
    let error = match refusal {
        // `keeper`'s grant path is bootstrap-only — the offer-create answer for
        // a role no offer may confer.
        BuiltinOfferRefusal::BootstrapOnly => forbidden(
            "role not grantable",
            Some(ERROR_ROLE_GRANT_OFFER_ROLE_NOT_GRANTABLE),
        ),
        BuiltinOfferRefusal::Scoped => invalid_request(Some(ERROR_ROLE_GRANT_BUILTIN_SCOPED)),
        BuiltinOfferRefusal::GrantorNotAuthorized => forbidden(
            "the offer's grantor can no longer confer this role",
            Some(ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED),
        ),
    };
    let reason = error
        .data
        .as_ref()
        .and_then(|d| d.get("reason"))
        .cloned()
        .unwrap_or(Value::Null);
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantOfferAccept)
            .failure()
            .actor(ctx.auth.actor.id)
            .account(ctx.auth.account.id)
            .target_account(ctx.auth.account.id)
            .target_actor(Some(ctx.auth.actor.id))
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "offer_id": offer.id.to_string(),
                "role": offer.role,
                "scope_id": offer.scope_id.map(|u| u.to_string()),
                "reason": reason,
            })),
    )
    .await?;
    Ok(error)
}

async fn emit_accept_audits(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    result: &AcceptOfferResult,
    caller_account_id: uuid::Uuid,
    caller_actor_id: uuid::Uuid,
) -> Result<(), JsonrpcError> {
    // `role_grant_offer_accept` — actor-bound subject; populate both
    // target columns since the actor↔account binding is known.
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantOfferAccept)
            .actor(caller_actor_id)
            .account(caller_account_id)
            .target_account(caller_account_id)
            .target_actor(Some(caller_actor_id))
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "offer_id": result.offer.id.to_string(),
                "role_grant_id": result.role_grant_id.to_string(),
                "role": result.offer.role,
                "scope_id": result.offer.scope_id.map(|u| u.to_string()),
            })),
    )
    .await?;

    // `role_grant_create` — chained on the role_grant just bound to
    // this actor. On self-accept the actor and the target are the
    // same identity.
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantCreate)
            .actor(caller_actor_id)
            .account(caller_account_id)
            .target_account(caller_account_id)
            .target_actor(Some(caller_actor_id))
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "role": result.offer.role,
                "role_grant_id": result.role_grant_id.to_string(),
                "scope_id": result.offer.scope_id.map(|u| u.to_string()),
                "source_offer_id": result.offer.id.to_string(),
            })),
    )
    .await?;

    // One supersede event per sibling — actor-grain inherits the
    // sibling's `to_actor_id` (actor-grain when actor-targeted,
    // account-grain (null) when not).
    emit_supersede_audits(
        ctx,
        db,
        &result.superseded_offers,
        "sibling_accepted",
        result.offer.id,
    )
    .await?;

    // WS notifications. The grantor of the accepted offer learns it was
    // taken; each superseded sibling's *grantor* learns their pending
    // offer was obsoleted (`reason: 'sibling_accepted'`, `cause_id` =
    // the accepted offer). Recipient ids ride on the query RETURNING —
    // `result.from_account_id` (lead grantor) and each
    // `sibling.from_account_id` (sibling grantor) — never the audit
    // `target_account` (which is the accepting account).
    queue_offer_notification(
        ctx,
        result.from_account_id,
        ROLE_GRANT_OFFER_ACCEPTED_METHOD,
        &serde_json::json!({ "offer": &result.offer }),
    );
    queue_supersede_notifications(
        ctx,
        &result.superseded_offers,
        "sibling_accepted",
        result.offer.id,
    );
    Ok(())
}

// --- decline ---------------------------------------------------------

/// Add `reason` to an audit metadata object only when the caller gave one.
///
/// The decline and revoke reasons are optional free text, and their audit
/// schemas (`audit_metadata_schemas` on the TS spine) declare `reason` an
/// optional string: absent when none was given, never `null`. The TS spine
/// omits the key the same way.
fn with_optional_reason(mut metadata: Value, reason: Option<&str>) -> Value {
    if let (Some(reason), Value::Object(map)) = (reason, &mut metadata) {
        map.insert("reason".to_owned(), Value::String(reason.to_owned()));
    }
    metadata
}

async fn handle_role_grant_offer_decline(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::OFFER_DECLINE)?;
    let offer_id = parse_uuid_param(params, "offer_id")?;
    let reason: Option<String> = parse_optional_str_param(params, "reason")?.map(str::to_owned);
    if let Some(reason) = reason.as_deref() {
        require_text_len(reason, ROLE_GRANT_OFFER_MESSAGE_LENGTH_MAX, "reason")?;
    }
    let caller_actor_id = ctx.auth.actor.id;
    let caller_account_id = ctx.auth.account.id;

    let declined =
        match query_role_grant_offer_decline(db, offer_id, caller_account_id, reason.as_deref())
            .await
        {
            Ok(declined) => declined,
            Err(err) => return Err(map_offer_transition_error(err, "role_grant_offer_decline")),
        };

    // `role_grant_offer_decline` is *to* the offering actor — populate
    // both `target_account_id` (the grantor account, joined in via CTE)
    // and `target_actor_id` (the grantor actor).
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantOfferDecline)
            .actor(caller_actor_id)
            .account(caller_account_id)
            .target_account(declined.from_account_id)
            .target_actor(Some(declined.offer.from_actor_id))
            .ip(ctx.client_ip.clone())
            .metadata(with_optional_reason(
                serde_json::json!({
                    "offer_id": declined.offer.id.to_string(),
                    "role": declined.offer.role,
                    "scope_id": declined.offer.scope_id.map(|u| u.to_string()),
                }),
                reason.as_deref(),
            )),
    )
    .await?;

    // WS notification — the grantor learns their offer was declined. The
    // decline reason rides inside `offer.decline_reason` (stamped on the
    // row), so no sibling field. Grantor account joined in via the CTE.
    queue_offer_notification(
        ctx,
        declined.from_account_id,
        ROLE_GRANT_OFFER_DECLINED_METHOD,
        &serde_json::json!({ "offer": &declined.offer }),
    );

    // the terminal offer, as accept answers its own
    Ok(serde_json::json!({ "offer": &declined.offer }))
}

// --- retract ---------------------------------------------------------

async fn handle_role_grant_offer_retract(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::OFFER_RETRACT)?;
    let offer_id = parse_uuid_param(params, "offer_id")?;
    let caller_actor_id = ctx.auth.actor.id;
    let caller_account_id = ctx.auth.account.id;

    let retracted = match query_role_grant_offer_retract(db, offer_id, caller_actor_id).await {
        Ok(retracted) => retracted,
        Err(err) => return Err(map_offer_transition_error(err, "role_grant_offer_retract")),
    };

    // `role_grant_offer_retract` is *from* the recipient inbox —
    // `target_account_id` is the recipient account; `target_actor_id`
    // inherits the offer's `to_actor_id` (set on actor-targeted offers,
    // null on account-grain offers).
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantOfferRetract)
            .actor(caller_actor_id)
            .account(caller_account_id)
            .target_account(retracted.to_account_id)
            .target_actor(retracted.to_actor_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "offer_id": retracted.id.to_string(),
                "role": retracted.role,
                "scope_id": retracted.scope_id.map(|u| u.to_string()),
            })),
    )
    .await?;

    // WS notification — the recipient learns their pending offer was
    // pulled. Recipient is `retracted.to_account_id`, on the row.
    queue_offer_notification(
        ctx,
        retracted.to_account_id,
        ROLE_GRANT_OFFER_RETRACTED_METHOD,
        &serde_json::json!({ "offer": &retracted }),
    );

    // the terminal offer, as accept answers its own
    Ok(serde_json::json!({ "offer": &retracted }))
}

// --- list ------------------------------------------------------------

async fn handle_role_grant_offer_list(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::OFFER_LIST)?;
    let requested_account_id = parse_optional_uuid_param(params, "account_id")?;
    let caller_account_id = ctx.auth.account.id;
    let target = requested_account_id.unwrap_or(caller_account_id);

    // Cross-account inspection requires a **global** admin grant — a
    // scoped admin must not be able to read another account's inbox.
    if target != caller_account_id && !ctx.auth.has_scoped_role(ROLE_ADMIN, None) {
        return Err(forbidden("admin required to inspect another account", None));
    }

    let offers = query_role_grant_offer_list(db, target)
        .await
        .map_err(|e| internal_error_with_source("role_grant_offer_list query failed", &e))?;
    Ok(serde_json::json!({ "offers": offers }))
}

// --- history ---------------------------------------------------------

/// Default page size for `role_grant_offer_history`. Mirrors the TS
/// schema's default.
const ROLE_GRANT_OFFER_HISTORY_DEFAULT_LIMIT: i64 = 100;
/// Hard cap on `limit` for `role_grant_offer_history`. Mirrors the TS
/// schema's max.
const ROLE_GRANT_OFFER_HISTORY_LIMIT_MAX: i64 = 500;

async fn handle_role_grant_offer_history(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::OFFER_HISTORY)?;
    let requested_account_id = parse_optional_uuid_param(params, "account_id")?;
    let caller_account_id = ctx.auth.account.id;
    let target = requested_account_id.unwrap_or(caller_account_id);

    if target != caller_account_id && !ctx.auth.has_scoped_role(ROLE_ADMIN, None) {
        return Err(forbidden("admin required to inspect another account", None));
    }

    // The twin declares `limit` as `.min(1).max(500)` and `offset` as
    // `.min(0)`, so an out-of-range page is `-32602` there — clamping it here
    // would silently answer a page for a request the twin refuses.
    let page = parse_pagination_params(
        params,
        ROLE_GRANT_OFFER_HISTORY_DEFAULT_LIMIT,
        ROLE_GRANT_OFFER_HISTORY_LIMIT_MAX,
    )?;

    let offers = query_role_grant_offer_history_for_account(db, target, page.limit, page.offset)
        .await
        .map_err(|e| internal_error_with_source("role_grant_offer_history query failed", &e))?;
    Ok(serde_json::json!({ "offers": offers }))
}

// --- role_grant_revoke (admin-only) ----------------------------------

async fn handle_role_grant_revoke(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    roles: &RoleRegistry,
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::ROLE_GRANT_REVOKE)?;
    let actor_id = parse_uuid_param(params, "actor_id")?;
    let role_grant_id = parse_uuid_param(params, "role_grant_id")?;
    let reason: Option<String> = parse_optional_str_param(params, "reason")?.map(str::to_owned);
    if let Some(reason) = reason.as_deref() {
        require_text_len(reason, ROLE_GRANT_REVOKED_REASON_LENGTH_MAX, "reason")?;
    }
    let admin_actor_id = ctx.auth.actor.id;
    let admin_account_id = ctx.auth.account.id;

    // IDOR guard + role lookup + actor → account JOIN. Single SELECT
    // resolves the role-grant's account_id for the audit envelope's
    // `target_account_id` and the post-tx socket-close fan-out target.
    let active = query_role_grant_find_active_role_for_actor(db, role_grant_id, actor_id)
        .await
        .map_err(|e| {
            internal_error_with_source("role_grant_find_active_role_for_actor failed", &e)
        })?;
    let Some(active) = active else {
        return Err(not_found("role_grant", Some(ERROR_ROLE_GRANT_NOT_FOUND)));
    };
    let target_account_id = active.account_id;
    let target_actor_id = actor_id;

    // Admin-grantability gate — keeper/daemon-scoped roles stay CLI-only
    // (their `grant_paths` does not include `Admin`). Registry-driven: the
    // default registry admits only `admin`, a consumer registry admits its
    // app roles.
    let emit_revoke_failure = || {
        ctx.audit_emit(
            db,
            AuditLogInput::for_event(AuditEventType::RoleGrantRevoke)
                .failure()
                .actor(admin_actor_id)
                .account(admin_account_id)
                .target_account(target_account_id)
                .target_actor(Some(target_actor_id))
                .ip(ctx.client_ip.clone())
                .metadata(serde_json::json!({
                    "role": active.role,
                    "role_grant_id": role_grant_id.to_string(),
                })),
        )
    };
    if !roles.is_admin_grantable(&active.role) {
        emit_revoke_failure().await?;
        return Err(forbidden(
            "role not web-grantable",
            Some(ERROR_ROLE_NOT_WEB_GRANTABLE),
        ));
    }

    // The global `admin` grant is guarded like the account that holds it:
    // the keeper account's is never revoked (no web path re-grants it, so the
    // keeper would be locked out of the admin surface for good), and the
    // grant goes only when an active admin account remains without it — the
    // count leaves this grant out, so a second admin actor on the same
    // account still counts. The count locks what it counted, so a concurrent
    // revoke or account removal can't pass the same guard.
    if active.role == ROLE_ADMIN && active.scope_id.is_none() {
        if query_account_has_global_role(db, &target_account_id, ROLE_KEEPER)
            .await
            .map_err(|e| internal_error_with_source("keeper role check failed", &e))?
        {
            emit_revoke_failure().await?;
            return Err(forbidden(
                "cannot revoke the keeper account's admin grant",
                Some(ERROR_CANNOT_REVOKE_KEEPER_ADMIN),
            ));
        }
        if query_account_has_active_global_role(db, &target_account_id, ROLE_ADMIN)
            .await
            .map_err(|e| internal_error_with_source("admin role check failed", &e))?
            && query_count_active_accounts_with_global_role_for_update(
                db,
                ROLE_ADMIN,
                Some(&role_grant_id),
            )
            .await
            .map_err(|e| internal_error_with_source("admin count failed", &e))?
                == 0
        {
            emit_revoke_failure().await?;
            return Err(forbidden(
                "cannot revoke the last admin's admin grant",
                Some(ERROR_CANNOT_REVOKE_LAST_ADMIN),
            ));
        }
    }

    let result = query_revoke_role_grant(
        db,
        role_grant_id,
        actor_id,
        Some(admin_actor_id),
        reason.as_deref(),
    )
    .await
    .map_err(|e| internal_error_with_source("revoke_role_grant query failed", &e))?;
    let Some(mut result) = result else {
        // Raced with another closer or the grant was revoked between
        // the IDOR check and the UPDATE.
        return Err(not_found("role_grant", Some(ERROR_ROLE_GRANT_NOT_FOUND)));
    };
    // The revokee's own pending offers end with the grant: an offer records
    // no authority, so one made under this grant would still confer on
    // accept. Every outgoing offer of the actor goes, superseded like the
    // revokee's incoming siblings (same reason, same cause, same fan-out).
    let outgoing = query_role_grant_offer_supersede_outgoing(db, &[actor_id])
        .await
        .map_err(|e| internal_error_with_source("outgoing offer supersede failed", &e))?;
    result.superseded_offers.extend(outgoing);

    emit_revoke_audits(
        ctx,
        db,
        &result,
        admin_actor_id,
        admin_account_id,
        target_account_id,
        target_actor_id,
        reason.as_deref(),
    )
    .await?;

    Ok(serde_json::json!({ "ok": true, "revoked": true }))
}

#[allow(clippy::too_many_arguments)]
async fn emit_revoke_audits(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    result: &RevokeRoleGrantResult,
    admin_actor_id: uuid::Uuid,
    admin_account_id: uuid::Uuid,
    target_account_id: uuid::Uuid,
    target_actor_id: uuid::Uuid,
    reason: Option<&str>,
) -> Result<(), JsonrpcError> {
    // `role_grant_revoke` — actor-bound subject. `target_actor_id` is
    // the role-grant's grantee; `target_account_id` is its hosting
    // account.
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantRevoke)
            .actor(admin_actor_id)
            .account(admin_account_id)
            .target_account(target_account_id)
            .target_actor(Some(target_actor_id))
            .ip(ctx.client_ip.clone())
            .metadata(with_optional_reason(
                serde_json::json!({
                    "role": result.role,
                    "role_grant_id": result.id.to_string(),
                    "scope_id": result.scope_id.map(|u| u.to_string()),
                }),
                reason,
            )),
    )
    .await?;

    // Supersede cascade — one event per pending sibling offer
    // invalidated by the revoke. Recipient is known
    // (`offer.to_account_id`); `target_actor_id` inherits the offer's
    // `to_actor_id`.
    emit_supersede_audits(
        ctx,
        db,
        &result.superseded_offers,
        "role_grant_revoked",
        result.id,
    )
    .await?;

    // WS notifications. The revokee learns their active grant was pulled
    // — FLAT params (`{role_grant_id, role, scope_kind, scope_id,
    // reason}`, the grant's `scope_kind` and `scope_id` both null for a
    // global grant, every key present), and the
    // closer (`revoked_by`) is deliberately omitted (the revokee
    // doesn't need the admin's identity; the account is implicit in the
    // send target). Each superseded sibling's *grantor* learns their
    // pending offer was obsoleted (`reason: 'role_grant_revoked'`,
    // `cause_id` = the revoked role_grant).
    queue_offer_notification(
        ctx,
        target_account_id,
        ROLE_GRANT_REVOKED_METHOD,
        &serde_json::json!({
            "role_grant_id": result.id,
            "role": result.role,
            "scope_kind": result.scope_kind,
            "scope_id": result.scope_id,
            "reason": reason,
        }),
    );
    queue_supersede_notifications(
        ctx,
        &result.superseded_offers,
        "role_grant_revoked",
        result.id,
    );
    Ok(())
}

// --- helpers ---------------------------------------------------------

/// Map a [`RoleGrantOfferError`] from an offer transition (accept, decline,
/// retract) to its JSON-RPC error: a missing offer is the 404 mask, a
/// terminal or expired one an invalid request, an actor-targeted offer
/// reached by another actor a 403. Anything else goes through
/// [`map_offer_error`]; accept's builtin refusal is audited, so its caller
/// handles that variant first.
fn map_offer_transition_error(err: RoleGrantOfferError, ctx_label: &'static str) -> JsonrpcError {
    match err {
        RoleGrantOfferError::NotFound(_) => {
            not_found("offer", Some(ERROR_ROLE_GRANT_OFFER_NOT_FOUND))
        }
        RoleGrantOfferError::AlreadyTerminal(_) => {
            invalid_request(Some(ERROR_ROLE_GRANT_OFFER_TERMINAL))
        }
        RoleGrantOfferError::Expired(_) => invalid_request(Some(ERROR_ROLE_GRANT_OFFER_EXPIRED)),
        RoleGrantOfferError::ActorMismatch(_) => forbidden(
            "offer is targeted to a different actor",
            Some(ERROR_ROLE_GRANT_OFFER_ACTOR_MISMATCH),
        ),
        err => map_offer_error(err, ctx_label),
    }
}

/// Map an unclassified [`RoleGrantOfferError`] to a JSON-RPC 500.
/// Classified variants are handled inline at each callsite — they
/// must never reach this mapper.
fn map_offer_error(err: RoleGrantOfferError, ctx_label: &'static str) -> JsonrpcError {
    match err {
        RoleGrantOfferError::Query(e) => internal_error_with_source(ctx_label, &e),
        // Classified variants reach this point only on a convergence
        // regression (a new caller forgot to handle one inline).
        // Surface as a compile-time exhaustive-match check that fails
        // loudly at runtime, rather than silently mapping to a
        // generic 500.
        e @ (RoleGrantOfferError::SelfTarget
        | RoleGrantOfferError::ActorAccountMismatch
        | RoleGrantOfferError::NotFound(_)
        | RoleGrantOfferError::AlreadyTerminal(_)
        | RoleGrantOfferError::Expired(_)
        | RoleGrantOfferError::ActorMismatch(_)
        | RoleGrantOfferError::BuiltinRefused { .. }) => {
            unreachable!("{ctx_label}: variant {e:?} must be handled inline at the callsite")
        }
    }
}

// --- role_grant_assign (admin-only, immediate conferral) --------------

/// Parsed `role_grant_assign` params: `{to_account_id, to_actor_id?, role,
/// scope_kind?, scope_id?}`. No `message` (no offer for a grantee to read it
/// on). `scope_kind` pairs with `scope_id` exactly as on
/// `role_grant_offer_create` — both or neither — so a scoped grant row
/// satisfies the `role_grant_scope_kind_paired` CHECK.
#[derive(Debug)]
struct AssignParams {
    to_account_id: uuid::Uuid,
    to_actor_id: Option<uuid::Uuid>,
    role: String,
    scope_kind: Option<String>,
    scope_id: Option<uuid::Uuid>,
}

fn parse_assign_params(params: &Value) -> Result<AssignParams, JsonrpcError> {
    reject_unknown_keys(params, keys::ROLE_GRANT_ASSIGN)?;
    let to_account_id = parse_uuid_param(params, "to_account_id")?;
    let to_actor_id = parse_optional_uuid_param(params, "to_actor_id")?;
    let role = parse_role_param(params, "role")?.to_owned();
    let scope_kind = parse_scope_kind_param(params)?;
    let scope_id = parse_optional_uuid_param(params, "scope_id")?;
    require_scope_paired(scope_kind.as_deref(), scope_id)?;
    Ok(AssignParams {
        to_account_id,
        to_actor_id,
        role,
        scope_kind,
        scope_id,
    })
}

/// Resolve the grant's target actor. A supplied `to_actor_id` must be an active
/// actor of `to_account_id`; otherwise the account's sole active actor is used
/// (a multi-actor account must name one). A missing / actorless account
/// 404-masks.
async fn resolve_assign_target_actor(
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    to_account_id: uuid::Uuid,
    to_actor_id: Option<uuid::Uuid>,
) -> Result<uuid::Uuid, JsonrpcError> {
    let actors = query_active_actors_by_account(db, &to_account_id)
        .await
        .map_err(|e| internal_error_with_source("active_actors_for_account failed", &e))?;
    // A named actor must be an active actor of the account.
    if let Some(actor_id) = to_actor_id {
        return if actors.iter().any(|a| a.id == actor_id) {
            Ok(actor_id)
        } else {
            Err(invalid_params(
                "to_actor_id does not belong to to_account_id",
                Some(ERROR_ROLE_GRANT_OFFER_ACTOR_ACCOUNT_MISMATCH),
            ))
        };
    }
    // Otherwise resolve the account's sole active actor.
    match actors.as_slice() {
        [single] => Ok(single.id),
        [] => Err(not_found("account", None)),
        _ => Err(invalid_params(
            "to_actor_id is required for a multi-actor account",
            None,
        )),
    }
}

/// The forensic `role_grant_create` failure row of a refused assign — no
/// grant was created, so `role_grant_id` is omitted.
async fn emit_assign_failure_audit(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    parsed: &AssignParams,
) -> Result<(), JsonrpcError> {
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantCreate)
            .failure()
            .actor(ctx.auth.actor.id)
            .account(ctx.auth.account.id)
            .target_account(parsed.to_account_id)
            .target_actor(parsed.to_actor_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "role": parsed.role,
                "scope_kind": parsed.scope_kind,
                "scope_id": parsed.scope_id.map(|u| u.to_string()),
            })),
    )
    .await
}

/// Handle `role_grant_assign` — the immediate admin-only conferral path, the
/// consent-free sibling of `role_grant_offer_create` (gated at the dispatcher
/// on a **global** `admin`, and re-checked here). Re-checks admin-grantability
/// so keeper / CLI-only roles can't be web-assigned, refuses a scoped builtin
/// role, runs the consumer's [`OfferCreateAuthorize`] (refusal →
/// `role_grant_offer_not_authorized`), resolves the target actor, writes the
/// (idempotent) grant, and emits a
/// `role_grant_create` audit row — the same event the offer-accept and
/// self-service paths emit.
///
/// No WS notification in v1 (the grantee picks the capability up on its next
/// authenticated request); a "role granted" notification is a later nicety.
async fn handle_role_grant_assign(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    action_db: &ActionDb<'_>,
    authorize: &dyn OfferCreateAuthorize,
    roles: &RoleRegistry,
) -> Result<Value, JsonrpcError> {
    let parsed = parse_assign_params(params)?;
    let admin_actor_id = ctx.auth.actor.id;
    let admin_account_id = ctx.auth.account.id;

    // Defense in depth behind the dispatcher's role gate: conferring roles is
    // global-admin authority. A scoped `admin` must never reach the write, or
    // it could assign itself a global `admin`.
    if !ctx.auth.has_scoped_role(ROLE_ADMIN, None) {
        return Err(forbidden(
            "forbidden",
            Some(fuz_http::INSUFFICIENT_PERMISSIONS_REASON),
        ));
    }

    // Admin-grantability gate — the same registry check the offer/revoke gates
    // use; keeper / daemon-scoped roles stay CLI-only. Denial is forensic-audited.
    // A builtin role asked for with a scope is refused the same way (audited),
    // with its own reason: builtin roles are global-only.
    let builtin_scoped = is_scoped_builtin(&parsed.role, parsed.scope_id);
    if builtin_scoped || !roles.is_admin_grantable(&parsed.role) {
        emit_assign_failure_audit(ctx, db, &parsed).await?;
        if builtin_scoped && roles.is_admin_grantable(&parsed.role) {
            return Err(builtin_scoped_error());
        }
        return Err(forbidden(
            "role not web-grantable",
            Some(ERROR_ROLE_NOT_WEB_GRANTABLE),
        ));
    }

    // The consumer's offer policy binds the immediate path too: assign is an
    // offer the grantee doesn't get to decline, so a grant the predicate would
    // refuse as an offer (a scope that doesn't exist, a role that must be
    // scoped) is refused here, with the offer path's reason. Twin of the TS
    // assign handler's `authorize` call.
    let authz_input = OfferCreateAuthorizeInput {
        role: parsed.role.clone(),
        scope_kind: parsed.scope_kind.clone(),
        scope_id: parsed.scope_id,
        to_account_id: parsed.to_account_id,
    };
    if !authorize
        .authorize(ctx.auth, &authz_input, action_db)
        .await?
    {
        emit_assign_failure_audit(ctx, db, &parsed).await?;
        return Err(forbidden(
            "not authorized to grant this role",
            Some(ERROR_ROLE_GRANT_OFFER_NOT_AUTHORIZED),
        ));
    }

    let target_actor_id =
        resolve_assign_target_actor(db, parsed.to_account_id, parsed.to_actor_id).await?;

    // Idempotent write — re-assigning an already-held grant returns the existing
    // row. `scope_kind` + `scope_id` land as the pair the input carried.
    let grant = query_create_role_grant(
        db,
        &target_actor_id,
        &parsed.role,
        parsed.scope_kind.as_deref(),
        parsed.scope_id.as_ref(),
        Some(&admin_actor_id),
        None,
    )
    .await
    .map_err(|e| internal_error_with_source("create_role_grant failed", &e))?;

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::RoleGrantCreate)
            .actor(admin_actor_id)
            .account(admin_account_id)
            .target_account(parsed.to_account_id)
            .target_actor(Some(target_actor_id))
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "role": grant.role,
                "role_grant_id": grant.id.to_string(),
                "scope_kind": parsed.scope_kind,
                "scope_id": grant.scope_id.map(|u| u.to_string()),
            })),
    )
    .await?;

    Ok(serde_json::json!({ "ok": true, "role_grant_id": grant.id }))
}

#[cfg(test)]
mod tests {
    use super::{
        AdminOfferAuthorize, ROLE_GRANT_OFFER_ACTION_ENTRIES, ROLE_GRANT_OFFER_MESSAGE_LENGTH_MAX,
        ROLE_GRANT_REVOKED_REASON_LENGTH_MAX, is_scoped_builtin, keys, parse_assign_params,
        parse_create_params, reject_unknown_keys, require_text_len,
    };
    use crate::name_schema::NAME_LENGTH_MAX;
    use crate::request_context::RequestActorContext;
    use crate::role_grant_schema::RoleGrantRow;
    use crate::{AccountRow, ActorRow};
    use fuz_http::JsonrpcErrorCode;
    use serde_json::{Value, json};
    use uuid::Uuid;

    /// Every method's declared key list, paired with the dispatch name whose
    /// handler runs it.
    const KEY_TABLE: &[(&str, &[&str])] = &[
        ("role_grant_offer_create", keys::OFFER_CREATE),
        ("role_grant_offer_accept", keys::OFFER_ACCEPT),
        ("role_grant_offer_decline", keys::OFFER_DECLINE),
        ("role_grant_offer_retract", keys::OFFER_RETRACT),
        ("role_grant_offer_list", keys::OFFER_LIST),
        ("role_grant_offer_history", keys::OFFER_HISTORY),
        ("role_grant_revoke", keys::ROLE_GRANT_REVOKE),
        ("role_grant_assign", keys::ROLE_GRANT_ASSIGN),
    ];

    const TO_ACCOUNT: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";

    #[test]
    fn every_offer_key_list_belongs_to_a_registered_method_and_declares_acting() {
        assert_eq!(
            KEY_TABLE.len(),
            ROLE_GRANT_OFFER_ACTION_ENTRIES.len(),
            "one key list per registered method"
        );
        for (method, allowed) in KEY_TABLE {
            let entry = ROLE_GRANT_OFFER_ACTION_ENTRIES
                .iter()
                .find(|e| e.method == *method)
                .unwrap_or_else(|| panic!("{method} is not a registered method"));
            assert!(
                entry.auth.needs_actor() && allowed.contains(&"acting"),
                "{method}: the actor axis and the declared selector go together"
            );
            let error = reject_unknown_keys(&json!({"nope": 1}), allowed)
                .expect_err(&format!("{method} must refuse an undeclared key"));
            assert_eq!(error.code, JsonrpcErrorCode::InvalidParams, "{method}");
        }
    }

    /// `scope_kind` and `message` are `optional(nullable(...))` strings on the twin, so a
    /// present wrong type is `-32602` there rather than a dropped field.
    #[test]
    fn offer_create_refuses_wrong_typed_optionals_and_unknown_keys() {
        for params in [
            json!({"to_account_id": TO_ACCOUNT, "role": "admin", "scope_kind": 42}),
            json!({"to_account_id": TO_ACCOUNT, "role": "admin", "message": true}),
            json!({"to_account_id": TO_ACCOUNT, "role": "admin", "nope": 1}),
        ] {
            let error =
                parse_create_params(&params).expect_err(&format!("{params} must be refused"));
            assert_eq!(
                error.code,
                JsonrpcErrorCode::InvalidParams,
                "params: {params}"
            );
        }

        let parsed = parse_create_params(&json!({
            "to_account_id": TO_ACCOUNT,
            "role": "admin",
            "scope_kind": Value::Null,
            "message": Value::Null,
        }))
        .expect("a nullish optional reads as absent");
        assert!(parsed.scope_kind.is_none() && parsed.message.is_none());
    }

    /// `scope_kind` pairs with `scope_id` on both grant inputs — both or
    /// neither. A half-scoped input is `-32602`, never the paired-CHECK 500.
    #[test]
    fn grant_inputs_refuse_an_unpaired_scope() {
        const SCOPE: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
        for params in [
            json!({"to_account_id": TO_ACCOUNT, "role": "teacher", "scope_id": SCOPE}),
            json!({"to_account_id": TO_ACCOUNT, "role": "teacher", "scope_kind": "classroom"}),
        ] {
            let assign = parse_assign_params(&params).expect_err("assign: unpaired scope");
            assert_eq!(assign.code, JsonrpcErrorCode::InvalidParams, "{params}");
            let create = parse_create_params(&params).expect_err("create: unpaired scope");
            assert_eq!(create.code, JsonrpcErrorCode::InvalidParams, "{params}");
        }

        let parsed = parse_assign_params(&json!({
            "to_account_id": TO_ACCOUNT,
            "role": "teacher",
            "scope_kind": "classroom",
            "scope_id": SCOPE,
        }))
        .expect("a paired scope parses");
        assert_eq!(parsed.scope_kind.as_deref(), Some("classroom"));
        assert_eq!(parsed.scope_id, Some(Uuid::parse_str(SCOPE).unwrap()));

        let global = parse_assign_params(&json!({
            "to_account_id": TO_ACCOUNT,
            "role": "teacher",
            "scope_kind": Value::Null,
            "scope_id": Value::Null,
        }))
        .expect("a null pair reads as global");
        assert!(global.scope_kind.is_none() && global.scope_id.is_none());
    }

    /// `scope_kind` is a scope-kind name on both grant inputs — the
    /// grammar and length cap of the twin's shared `ScopeKindName` — and off
    /// it is `-32602` with no reason, as an off-grammar `role` is.
    #[test]
    fn grant_inputs_hold_scope_kind_to_the_scope_kind_grammar() {
        const SCOPE: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
        const NIL: &str = "00000000-0000-0000-0000-000000000000";
        assert_eq!(NAME_LENGTH_MAX, 64);
        let params = |scope_kind: &str, scope_id: &str| {
            json!({
                "to_account_id": TO_ACCOUNT,
                "role": "teacher",
                "scope_kind": scope_kind,
                "scope_id": scope_id,
            })
        };
        let at_max = "a".repeat(NAME_LENGTH_MAX);
        for admitted in ["classroom", "a", "a_b_c", at_max.as_str()] {
            let assign =
                parse_assign_params(&params(admitted, SCOPE)).expect("assign: on the grammar");
            assert_eq!(assign.scope_kind.as_deref(), Some(admitted));
            let create =
                parse_create_params(&params(admitted, SCOPE)).expect("create: on the grammar");
            assert_eq!(create.scope_kind.as_deref(), Some(admitted));
        }
        // An astral-plane character is two UTF-16 units, as `String.length`
        // counts, and off the alphabet whatever the count.
        let astral_at_max = "\u{1F600}".repeat(NAME_LENGTH_MAX / 2);
        assert_eq!(astral_at_max.encode_utf16().count(), NAME_LENGTH_MAX);
        let refused = [
            "GLOBAL".to_owned(),
            "Classroom".to_owned(),
            "class-room".to_owned(),
            "room1".to_owned(),
            "_room".to_owned(),
            "room_".to_owned(),
            "a__b".to_owned(),
            "class room".to_owned(),
            String::new(),
            astral_at_max,
            format!("{at_max}a"),
        ];
        for refused in &refused {
            for scope_id in [SCOPE, NIL] {
                let assign = parse_assign_params(&params(refused, scope_id))
                    .expect_err("assign: off the grammar");
                assert_eq!(assign.code, JsonrpcErrorCode::InvalidParams, "{refused:?}");
                assert_eq!(assign.message, fuz_http::INVALID_PARAMS_MESSAGE);
                assert!(assign.data.is_none(), "the refusal carries no reason");
                let create = parse_create_params(&params(refused, scope_id))
                    .expect_err("create: off the grammar");
                assert_eq!(create.code, JsonrpcErrorCode::InvalidParams, "{refused:?}");
                assert_eq!(create.message, fuz_http::INVALID_PARAMS_MESSAGE);
                assert!(create.data.is_none(), "the refusal carries no reason");
            }
        }
    }

    #[test]
    fn only_builtin_roles_bound_to_a_scope_are_scoped_builtins() {
        let scope = Some(Uuid::from_u128(1));
        assert!(is_scoped_builtin("admin", scope));
        assert!(is_scoped_builtin("keeper", scope));
        assert!(!is_scoped_builtin("admin", None));
        assert!(!is_scoped_builtin("teacher", scope));
    }

    /// The default offer authorizer reads the **global** admin grant: a
    /// scoped `admin` row authorizes no offer.
    #[test]
    fn admin_offer_authorize_ignores_a_scoped_admin() {
        let mut scoped = actor_ctx(&[]);
        scoped.role_grants.push(RoleGrantRow {
            id: Uuid::nil(),
            actor_id: Uuid::nil(),
            role: "admin".to_owned(),
            scope_id: Some(Uuid::from_u128(1)),
        });
        assert!(!AdminOfferAuthorize::admits(&scoped));
    }

    #[test]
    fn role_grant_assign_refuses_an_unknown_key() {
        let error = parse_assign_params(&json!({
            "to_account_id": TO_ACCOUNT,
            "role": "admin",
            "message": "no such field on this verb",
        }))
        .expect_err("assign declares no `message`");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
    }

    /// The free-text bound is the twin's `bounded_string({max: n})`: inclusive at
    /// the bound, refused one past it, and counted in **characters** — a
    /// 500-character multibyte note is under the cap even though its byte
    /// length is far over.
    #[test]
    fn free_text_bound_matches_the_ts_max() {
        assert_eq!(ROLE_GRANT_OFFER_MESSAGE_LENGTH_MAX, 500);
        assert_eq!(ROLE_GRANT_REVOKED_REASON_LENGTH_MAX, 500);
        let max = ROLE_GRANT_OFFER_MESSAGE_LENGTH_MAX;
        assert!(require_text_len("", max, "message").is_ok());
        assert!(require_text_len(&"a".repeat(max), max, "message").is_ok());
        assert!(require_text_len(&"a".repeat(max + 1), max, "message").is_err());
        let multibyte = "\u{00FC}".repeat(max);
        assert!(multibyte.len() > max, "the byte length is over the bound");
        assert!(require_text_len(&multibyte, max, "message").is_ok());
        assert!(require_text_len(&"\u{00FC}".repeat(max + 1), max, "message").is_err());
        // Astral plane: U+1F600 is one `char` but two UTF-16 code units, so
        // the twin's `String.length` counts it twice. Half the bound in
        // emoji is exactly the bound; one more is over.
        let astral_at_max = "\u{1F600}".repeat(max / 2);
        assert_eq!(astral_at_max.encode_utf16().count(), max);
        assert!(require_text_len(&astral_at_max, max, "message").is_ok());
        let astral_over = "\u{1F600}".repeat(max / 2 + 1);
        assert_eq!(astral_over.encode_utf16().count(), max + 2);
        assert!(require_text_len(&astral_over, max, "message").is_err());
    }

    fn actor_ctx(roles: &[&str]) -> RequestActorContext {
        RequestActorContext {
            account: AccountRow {
                id: Uuid::nil(),
                username: "u".to_owned(),
            },
            actor: ActorRow {
                id: Uuid::nil(),
                account_id: Uuid::nil(),
                name: "a".to_owned(),
            },
            role_grants: roles
                .iter()
                .map(|r| RoleGrantRow {
                    id: Uuid::nil(),
                    actor_id: Uuid::nil(),
                    role: (*r).to_owned(),
                    scope_id: None,
                })
                .collect(),
        }
    }

    /// `AdminOfferAuthorize` admits iff the caller holds `admin` — holding the
    /// offered role itself confers nothing (no holder-propagation).
    #[test]
    fn admin_offer_authorize_requires_admin() {
        // An admin may offer a role it doesn't personally hold.
        let admin = actor_ctx(&["admin"]);
        assert!(AdminOfferAuthorize::admits(&admin), "admin → admit");
        // A non-admin holder of the offered role is denied (no propagation).
        let holder = actor_ctx(&["post"]);
        assert!(
            !AdminOfferAuthorize::admits(&holder),
            "non-admin holder → deny"
        );
    }
}
