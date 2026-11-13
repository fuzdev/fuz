//! Cell-grant ACL RPC handlers + [`build_cell_grant_spec_set`].
//!
//! Three verbs (`cell_grant_create` / `cell_grant_revoke` /
//! `cell_grant_list`) bound to canonical [`ActionSpec`]s, concatenated
//! into the cell spec set by `build_cell_spec_set`.
//!
//! Grant management is **manage-tier only** (`can_manage_cell` = admin /
//! owner). Editor-grant holders may edit a cell's content but cannot
//! manage its grants. Two revoke paths reach past the manager: self-revoke
//! of an actor-shaped grant ("leave shared cell"), and — when the consumer
//! mounts a [`CellGrantRevokeAuthorize`] — the steward of a scoped
//! role-shaped grant's scope. All three 404-mask
//! (`cell_not_found` / `cell_grant_not_found`) so probing via the share
//! endpoints is no easier than via `cell_get`. Mirrors the TS
//! `cell_grant_actions.ts`.
//!
//! Create / revoke emit `cell_grant_create` / `cell_grant_revoke` audit
//! events in-tx with the mutation.
//!
//! Role-shaped grants validate the role against the closed role registry
//! threaded into `build_cell_spec_set` — an unregistered role is rejected
//! at create (fail loud) rather than producing an inert grant row.
//!
//! A cell whose `moderation` doesn't admit an audience (pending, rejected, or
//! an unknown marker) refuses every grant — `403`
//! [`ERROR_CELL_GRANT_UNAPPROVED`], right after the manage gate, no admin
//! exemption — since the read predicate wouldn't honor it until approval.
//!
//! A consumer may narrow who a manager grants to with a
//! [`CellGrantCreateAuthorize`], asked after the spine's own gates and before
//! the write; a denial is `403` [`ERROR_CELL_GRANT_NOT_AUTHORIZED`].
//!
//! A consumer may widen who revokes with a [`CellGrantRevokeAuthorize`],
//! fenced to the steward of a scoped role-shaped grant: asked only when the
//! caller neither manages the cell nor holds the grant, for a grant naming a
//! role and a scope; a denial keeps the 404 mask, and an allowed revoke's
//! audit row stamps `steward: true`.

use std::sync::Arc;

use deadpool_postgres::GenericClient;
use futures::future::BoxFuture;
use fuz_actions::action_context::ActionContext;
use fuz_actions::action_registry::ActionHandler;
use fuz_actions::action_spec::ActionSpec;
use fuz_auth::{AuditEventType, AuthSpec, CredentialGate, RequestActorContext, RoleRegistry};
use fuz_db::ActionDb;
use fuz_http::{InputShape, JsonrpcError, parse_strict_params};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::cell_action_specs::{
    dispatch_db, emit_cell_audit, map_cell_error, require_manageable_cell,
};
use fuz_cell::cell_authz::{can_manage_cell, can_view_cell};
use fuz_cell::cell_grant_queries::{
    query_cell_grant_create, query_cell_grant_delete, query_cell_grant_get,
    query_cell_grant_list_for_cell,
};
use fuz_cell::cell_grant_schema::{
    CellGrantCreateInput, CellGrantLevel, CellGrantListInput, CellGrantPrincipalInput,
    CellGrantRevokeInput, CellGrantRow,
};
use fuz_cell::cell_moderation::cell_moderation_admits_audience;
use fuz_cell::cell_queries::query_cell_get;

// -- Error reasons (mirror TS `cell_grant_action_specs.ts`) -----------------

/// Grant id did not resolve, or caller may not see it (IDOR mask).
pub const ERROR_CELL_GRANT_NOT_FOUND: &str = "cell_grant_not_found";
/// `cell_grant_create` principal resolves to the cell's owner (implicit
/// access; a self-grant row would shadow it).
pub const ERROR_CELL_GRANT_PRINCIPAL_IS_OWNER: &str = "cell_grant_principal_is_owner";
/// `cell_grant_create` role-shaped principal names a role that isn't in the
/// closed role registry. Fail loud rather than create an inert grant.
pub const ERROR_CELL_GRANT_UNKNOWN_ROLE: &str = "cell_grant_unknown_role";
/// `cell_grant_create` on a cell whose `moderation` doesn't admit an audience
/// (pending, rejected, or an unknown marker) — a grant would extend an
/// audience the cell doesn't have yet.
pub const ERROR_CELL_GRANT_UNAPPROVED: &str = "cell_grant_unapproved";
/// The mounted [`CellGrantCreateAuthorize`] refused a manager's
/// `cell_grant_create`. A **403** `forbidden`, answered only to a caller who
/// manages the cell (everyone else gets the 404 mask before the hook runs).
pub const ERROR_CELL_GRANT_NOT_AUTHORIZED: &str = "cell_grant_not_authorized";

// -- Authorize seam ---------------------------------------------------------

/// What a [`CellGrantCreateAuthorize`] decides on — the twin of the TS
/// `CellGrantCreateAuthorizeInput`.
#[derive(Debug, Clone)]
pub struct CellGrantCreateAuthorizeInput {
    /// The cell the grant names.
    pub cell_id: Uuid,
    /// The cell's owner (`None` = a system cell).
    pub cell_created_by: Option<Uuid>,
    /// The level the grant confers — on an upsert, the new level.
    pub level: CellGrantLevel,
    /// Who the grant admits: an actor, or a role at an optional scope.
    pub principal: CellGrantPrincipalInput,
}

/// Consumer-injectable gate on `cell_grant_create` — the Rust twin of TS
/// `CellGrantCreateAuthorize`.
///
/// Asked after the spine's own gates — the manage tier (a non-manager gets the
/// 404 mask and never reaches it), the moderation admission, and the role
/// registry — and before the owner check and the write, for a new grant and a
/// level change alike. `Ok(false)` refuses with **403**
/// [`ERROR_CELL_GRANT_NOT_AUTHORIZED`] and writes neither the grant nor an
/// audit row; `Err` is a hard error. A consumer narrows sharing with it (say,
/// role-shaped grants only to roles of the cell's own space); it can't widen
/// it, as every caller it sees already manages the cell.
///
/// **Object-safe** — dispatched as `Arc<dyn CellGrantCreateAuthorize>` on the
/// cold grant path; async via [`BoxFuture`] per the spine's dyn-trait
/// carve-out. `db` is the request transaction (`cell_grant_create` has side
/// effects): an impl that needs the database (a scope-existence check, say)
/// reads through it with [`fuz_db::action_db_dispatch!`]. **Read-only**: the
/// hook decides, it never writes — a write would commit or roll back with the
/// grant, and nothing enforces this but the impl.
pub trait CellGrantCreateAuthorize: Send + Sync {
    fn authorize<'a>(
        &'a self,
        auth: &'a RequestActorContext,
        input: &'a CellGrantCreateAuthorizeInput,
        db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>>;
}

/// What a [`CellGrantRevokeAuthorize`] decides on — the twin of the TS
/// `CellGrantRevokeAuthorizeInput`.
///
/// Only a role-shaped grant with a scope reaches the hook, so `role` and
/// `scope_id` are always present.
#[derive(Debug, Clone)]
pub struct CellGrantRevokeAuthorizeInput {
    /// The grant being revoked.
    pub grant_id: Uuid,
    /// The cell the grant names.
    pub cell_id: Uuid,
    /// The cell's owner (`None` = a system cell).
    pub cell_created_by: Option<Uuid>,
    /// The role the grant admits.
    pub role: String,
    /// The scope the grant is bound to — the scope whose steward the hook
    /// decides on.
    pub scope_id: Uuid,
    /// The level the grant confers.
    pub level: CellGrantLevel,
}

/// Consumer-injectable widening of `cell_grant_revoke` to a scope's steward —
/// the Rust twin of TS `CellGrantRevokeAuthorize`.
///
/// The role-shaped twin of self-revoke: an actor-shaped grant's grantee may
/// leave a cell, and for a role-shaped grant the grantee is the scope, so the
/// scope's steward speaks for it (say, a teacher removing a cell shared into
/// their classroom). The consumer decides what stewards a scope. The input
/// carries the grant's role so a consumer whose scopes are stewarded only for
/// certain roles can refuse the rest.
///
/// The hook sees no scope kind and no scope liveness, so the consumer owns
/// both. A cell grant carries no `scope_kind`, and
/// [`RequestActorContext::has_scoped_role`] matches on role and `scope_id`
/// alone, so a consumer with two scope kinds whose ids can coincide must tell
/// them apart itself; and a scope that is gone keeps its stewards until the
/// consumer revokes their scoped role grants with it. Narrow on `role`: admit
/// only the roles whose scopes have stewards, rather than any scoped grant.
///
/// Deliberately fenced. The spine asks it only when the caller neither
/// manages the cell nor holds the grant (self-revoke), and only for a
/// role-shaped grant with a non-null `scope_id` — an actor-shaped grant or a
/// scopeless role grant never reaches it, and a soft-deleted cell 404s first.
/// `Ok(true)` revokes as a manager would — same delete, `still_admitted`, and
/// `cell_grant_revoke` audit row, its metadata stamped `steward: true`;
/// `Ok(false)` answers the same 404 [`ERROR_CELL_GRANT_NOT_FOUND`] mask as
/// every other non-qualifying caller (not a 403 — the caller mustn't learn the
/// grant exists); `Err` is a hard error — it is not masked, so refuse with
/// `Ok(false)`, never an error. Unmounted, revoke is the manager's and the
/// self-closer's alone.
///
/// The grant it decides on is the grant revoked: the delete matches the
/// grant's `level` as the hook saw it, so a level change landing between the
/// read and the delete answers the 404 mask rather than revoking a grant the
/// hook never judged.
///
/// **Object-safe** — dispatched as `Arc<dyn CellGrantRevokeAuthorize>` on the
/// cold revoke path; async via [`BoxFuture`] per the spine's dyn-trait
/// carve-out. `db` is the request transaction (`cell_grant_revoke` has side
/// effects), read through with [`fuz_db::action_db_dispatch!`] like
/// [`CellGrantCreateAuthorize`]'s, and read-only like it.
pub trait CellGrantRevokeAuthorize: Send + Sync {
    fn authorize<'a>(
        &'a self,
        auth: &'a RequestActorContext,
        input: &'a CellGrantRevokeAuthorizeInput,
        db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<bool, JsonrpcError>>;
}

// -- Helpers ----------------------------------------------------------------

/// The grant-specific 404 (IDOR mask — grant-miss and unauthorized share
/// one shape).
fn grant_not_found() -> JsonrpcError {
    fuz_http::not_found("cell grant", Some(ERROR_CELL_GRANT_NOT_FOUND))
}

/// Serialize a grant row to its `GrantJson` wire value.
pub(crate) fn grant_to_value(row: &CellGrantRow) -> Result<Value, JsonrpcError> {
    serde_json::to_value(row)
        .map_err(|e| fuz_http::internal_error_with_source("cell grant serialize failed", &e))
}

/// Audit-metadata principal envelope from a grant row: `{actor_id}` for an
/// actor-shaped grant, `{role, scope_id}` for a role-shaped one (mirrors the
/// TS `CellGrantPrincipalAuditMetadata`).
fn grant_principal_metadata(row: &CellGrantRow) -> Value {
    row.actor_id.map_or_else(
        || json!({ "role": row.role, "scope_id": row.scope_id }),
        |actor_id| json!({ "actor_id": actor_id }),
    )
}

/// The `{cell_id, grant_id, level, principal}` audit envelope shared by
/// `cell_grant_create` / `cell_grant_revoke` (IDs only).
fn grant_audit_metadata(row: &CellGrantRow) -> Value {
    json!({
        "cell_id": row.cell_id,
        "grant_id": row.id,
        "level": row.level,
        "principal": grant_principal_metadata(row),
    })
}

// -- Handlers ---------------------------------------------------------------

async fn handle_grant_create<C: GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellGrantCreateInput,
    roles: &RoleRegistry,
    authorizer: Option<&Arc<dyn CellGrantCreateAuthorize>>,
) -> Result<Value, JsonrpcError> {
    // Manage-tier only (admin / owner). Non-managers get the IDOR-mask 404,
    // same as a non-viewer on the read path.
    let cell = require_manageable_cell(client, auth, input.cell_id).await?;
    // A grant extends a cell's audience, and a contribution whose moderation
    // doesn't admit one (pending, rejected, or an unknown marker) has none
    // past its author and admins — `can_view_cell`'s grant arm wouldn't admit
    // on it — so refuse the grant rather than mint a row that would wake up on
    // approval. After the manage gate, so a non-manager keeps the 404 mask;
    // no admin exemption.
    if !cell_moderation_admits_audience(cell.moderation.as_deref()) {
        return Err(fuz_http::forbidden(
            "cell_grant_create requires an unmoderated or approved cell",
            Some(ERROR_CELL_GRANT_UNAPPROVED),
        ));
    }
    // Fail loud on a role-shaped principal naming an unregistered role — a
    // grant for a role no one can hold would be silently inert. Checked after
    // the manage-tier 404 (a non-manager gets the mask, not a role-registry
    // probe) and before insert. Mirrors the TS role-validity gate.
    if let CellGrantPrincipalInput::Role { role, .. } = &input.principal
        && !roles.contains(role)
    {
        // the TS twin's text, `unknown role "<role>"`
        return Err(fuz_http::invalid_params(
            &format!("unknown role \"{role}\""),
            Some(ERROR_CELL_GRANT_UNKNOWN_ROLE),
        ));
    }
    // The consumer's gate, asked only of a manager past the spine's gates;
    // a refusal writes nothing.
    if let Some(authorize) = authorizer {
        let authz_input = CellGrantCreateAuthorizeInput {
            cell_id: cell.id,
            cell_created_by: cell.created_by,
            level: input.level,
            principal: input.principal.clone(),
        };
        if !authorize.authorize(auth, &authz_input, &ctx.db).await? {
            return Err(fuz_http::forbidden(
                "cell grant is not permitted here",
                Some(ERROR_CELL_GRANT_NOT_AUTHORIZED),
            ));
        }
    }
    // Reject owner-as-principal: owner access is implicit on `created_by`,
    // so a self-grant row would shadow it without changing access. Only
    // actor-shaped principals can name an owner; system cells
    // (`created_by IS NULL`) have no owner to collide with.
    if let CellGrantPrincipalInput::Actor { actor_id } = &input.principal
        && cell.created_by == Some(*actor_id)
    {
        return Err(fuz_http::invalid_params(
            "grant principal is the cell owner",
            Some(ERROR_CELL_GRANT_PRINCIPAL_IS_OWNER),
        ));
    }
    let row = query_cell_grant_create(
        client,
        cell.id,
        input.level,
        &input.principal,
        Some(auth.actor.id),
    )
    .await
    .map_err(|e| map_cell_error(e, false))?;
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellGrantCreate,
        grant_audit_metadata(&row),
    )
    .await?;
    Ok(json!({ "grant": grant_to_value(&row)? }))
}

/// Whether the mounted [`CellGrantRevokeAuthorize`] admits `auth` as the
/// steward of `grant`'s scope — `false` with no hook, for an actor-shaped
/// grant, and for a scopeless role grant, none of which reach it.
async fn steward_admits_revoke(
    auth: &RequestActorContext,
    grant: &CellGrantRow,
    cell_created_by: Option<Uuid>,
    authorizer: Option<&Arc<dyn CellGrantRevokeAuthorize>>,
    db: &ActionDb<'_>,
) -> Result<bool, JsonrpcError> {
    let Some(authorize) = authorizer else {
        return Ok(false);
    };
    let (None, Some(role), Some(scope_id)) = (grant.actor_id, &grant.role, grant.scope_id) else {
        return Ok(false);
    };
    let input = CellGrantRevokeAuthorizeInput {
        grant_id: grant.id,
        cell_id: grant.cell_id,
        cell_created_by,
        role: role.clone(),
        scope_id,
        level: grant.level,
    };
    authorize.authorize(auth, &input, db).await
}

async fn handle_grant_revoke<C: GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellGrantRevokeInput,
    authorizer: Option<&Arc<dyn CellGrantRevokeAuthorize>>,
) -> Result<Value, JsonrpcError> {
    let grant = query_cell_grant_get(client, input.grant_id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let Some(grant) = grant else {
        return Err(grant_not_found());
    };
    let cell = query_cell_get(client, grant.cell_id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let Some(cell) = cell else {
        // Grant exists but its cell is gone (soft-deleted). Treat as a
        // grant miss for the IDOR mask.
        return Err(grant_not_found());
    };
    let is_manager = can_manage_cell(Some(auth), &cell);
    // Self-revoke (leave shared cell) is open regardless of authority path,
    // but only for the caller's own actor-shaped grant. Owner-with-self-
    // grant can't happen (rejected at create time).
    let is_self_actor_grant = grant.actor_id == Some(auth.actor.id);
    // The steward of a scoped role grant's scope, asked only of a caller with
    // neither of the above — so a manager or self-closer never consults it.
    let is_steward = !is_manager
        && !is_self_actor_grant
        && steward_admits_revoke(auth, &grant, cell.created_by, authorizer, &ctx.db).await?;
    if !is_manager && !is_self_actor_grant && !is_steward {
        return Err(grant_not_found());
    }
    // A steward's admission was decided on the grant's level, so its delete
    // matches that level: a level change landing in between deletes nothing.
    let expected_level = is_steward.then_some(grant.level);
    let deleted = query_cell_grant_delete(client, grant.id, expected_level)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let Some(deleted) = deleted else {
        // Raced with another closer, or (a steward's) with a level change.
        // 404 covers the gap.
        return Err(grant_not_found());
    };
    // Recompute admit state against the remaining grants. Always true for a
    // manager's revoke; a self-closer or a steward may have admitted through
    // nothing else, so let `can_view_cell` decide — uniform shape.
    let remaining = query_cell_grant_list_for_cell(client, cell.id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let still_admitted = can_view_cell(Some(auth), &cell, Some(&remaining));
    // Stamp `self: true` on a self-revoke (leave-shared-cell) and
    // `steward: true` on a scope steward's, so the audit trail distinguishes
    // both from a manager revoking someone else's grant.
    let mut metadata = grant_audit_metadata(&deleted);
    if let Value::Object(map) = &mut metadata {
        if is_self_actor_grant {
            map.insert("self".to_owned(), json!(true));
        }
        if is_steward {
            map.insert("steward".to_owned(), json!(true));
        }
    }
    emit_cell_audit(ctx, client, auth, AuditEventType::CellGrantRevoke, metadata).await?;
    Ok(json!({ "ok": true, "still_admitted": still_admitted }))
}

async fn handle_grant_list<C: GenericClient + ?Sized>(
    client: &C,
    auth: &RequestActorContext,
    input: CellGrantListInput,
) -> Result<Value, JsonrpcError> {
    // Same gate as create — the share list is the manager's to curate;
    // viewers and editors alike fall through to the IDOR-mask 404.
    let cell = require_manageable_cell(client, auth, input.cell_id).await?;
    let grants = query_cell_grant_list_for_cell(client, cell.id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let grants = grants
        .iter()
        .map(grant_to_value)
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(json!({ "grants": grants }))
}

// -- Spec construction ------------------------------------------------------

/// Build the three `cell_grant_*` [`ActionSpec`]s.
///
/// Concatenated into the cell spec set by `build_cell_spec_set`. `create`
/// / `revoke` carry side effects (DB writes); `list` is read-only. All
/// require an authenticated actor (manage-tier authz runs per-cell in the
/// handler). `roles` is the role registry the `cell_grant_create` handler
/// validates role-shaped principals against; `authorizer` is the
/// consumer's optional [`CellGrantCreateAuthorize`] on it, and
/// `revoke_authorizer` the optional [`CellGrantRevokeAuthorize`] on
/// `cell_grant_revoke`.
#[must_use]
pub fn build_cell_grant_spec_set(
    roles: Arc<RoleRegistry>,
    authorizer: Option<Arc<dyn CellGrantCreateAuthorize>>,
    revoke_authorizer: Option<Arc<dyn CellGrantRevokeAuthorize>>,
) -> Vec<ActionSpec> {
    vec![
        ActionSpec::with_side_effects(
            "cell_grant_create",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(move |params, ctx| {
                    let roles = Arc::clone(&roles);
                    let authorizer = authorizer.clone();
                    Box::pin(async move {
                        let input: CellGrantCreateInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(
                            ctx,
                            handle_grant_create(&ctx, auth, input, &roles, authorizer.as_ref())
                        )
                    })
                });
                handler
            },
        ),
        ActionSpec::with_side_effects(
            "cell_grant_revoke",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(move |params, ctx| {
                    let revoke_authorizer = revoke_authorizer.clone();
                    Box::pin(async move {
                        let input: CellGrantRevokeInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(
                            ctx,
                            handle_grant_revoke(&ctx, auth, input, revoke_authorizer.as_ref())
                        )
                    })
                });
                handler
            },
        ),
        ActionSpec::read_only(
            "cell_grant_list",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellGrantListInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_grant_list(auth, input))
                    })
                });
                handler
            },
        ),
    ]
}
