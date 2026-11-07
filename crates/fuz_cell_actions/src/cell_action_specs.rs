//! Cell RPC handlers + the self-contained [`build_cell_spec_set`].
//!
//! The generic verbs (`cell_create` / `cell_get` / `cell_update` /
//! `cell_delete` / `cell_list` / `cell_clone` / `cell_moderate` /
//! `cell_policy_set`) bound to canonical [`ActionSpec`]s. Consumers
//! concatenate [`build_cell_spec_set`] into their
//! [`fuz_actions::ActionRegistry`] exactly as they do
//! [`fuz_actions::auth_adapter::build_auth_spec_set`].
//!
//! Unlike the auth families (which live below `fuz_actions` and need the
//! `auth_adapter` lift), `fuz_cell` depends on `fuz_actions` directly and
//! builds its own specs — no adapter indirection.
//!
//! [`build_cell_spec_set`] also concatenates the `cell_grant_*`,
//! `cell_field_*`, and `cell_item_*` spec sets, and `cell_get` bundles the
//! forward fields + items (visibility-filtered, truncation-flagged).
//!
//! Cell write handlers emit their audit events in-tx (routing via
//! [`fuz_auth::AUDIT_EVENT_SPECS`]) atomically with the mutation. The wire
//! contract is the TS `cell_action_specs.ts` schemas.

use std::sync::Arc;

use futures::future::BoxFuture;
use fuz_actions::action_context::ActionContext;
use fuz_actions::action_registry::ActionHandler;
use fuz_actions::action_spec::ActionSpec;
use fuz_auth::{
    AuditEventType, AuditLogInput, AuthSpec, CredentialGate, ROLE_ADMIN, RateLimitClass,
    RequestActorContext, RoleRegistry, is_valid_fact_hash,
};
use fuz_db::ActionDb;
use fuz_db::is_pg_unique_violation;
use fuz_http::{
    InputShape, JsonrpcError, SAFE_INTEGER_MAX, parse_strict_params,
    parse_strict_params_allowing_null,
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::cell_grant_action_specs::{
    CellGrantCreateAuthorize, CellGrantRevokeAuthorize, grant_to_value,
};
use crate::cell_ref_admission::require_new_refs_held;
use fuz_cell::cell_authz::{can_edit_cell, can_manage_cell, can_view_cell};
use fuz_cell::cell_field_queries::{query_cell_field_list_for_source, query_cell_field_set};
use fuz_cell::cell_grant_queries::{
    query_cell_grant_list_for_cell, query_cell_grants_for_caller_in_cells,
};
use fuz_cell::cell_grant_schema::CellGrantRow;
use fuz_cell::cell_item_queries::{query_cell_item_insert, query_cell_item_list_for_parent};
use fuz_cell::cell_queries::{
    CELL_LIST_LIMIT_DEFAULT, CELL_LIST_LIMIT_MAX, CellListParams, CellSetPolicyResult,
    query_cell_create, query_cell_delete, query_cell_get, query_cell_get_by_path, query_cell_list,
    query_cell_load_many, query_cell_set_moderation, query_cell_set_policy, query_cell_update,
};
use fuz_cell::cell_relation_visibility::filter_visible_targets;
use fuz_cell::cell_schema::{
    CellCloneInput, CellCreateInput, CellData, CellDeleteInput, CellGetInput, CellListInput,
    CellListOrderBy, CellListOrderDir, CellModerateInput, CellModeration, CellPolicy,
    CellPolicySetInput, CellRow, CellUpdateInput, CellVisibility,
};
use fuz_cell::cell_steward::cell_steward_admits;
use fuz_cell::cell_view_sql::CellViewer;
use fuz_cell::error::CellError;

/// Consumer-injectable per-kind validator for cell `data` payloads.
///
/// The Rust twin of TS `CellActionDeps.validate_data`. Threaded into
/// [`build_cell_spec_set`] and called as `(kind, data)` — `kind` is the cell's
/// top-level `kind` column, so the validator dispatches on it:
///
/// - `cell_create`: the input's `kind` and `data`;
/// - `cell_update` (only when a `data` payload is present): the existing
///   cell's `kind` (write-once, so the update can't change it) and the new
///   `data`;
/// - `cell_clone`: the source's `kind` (a clone inherits it) and the
///   **post-merge** data, for the root and every cloned child.
///
/// It answers yes or no, never rewrites: the handler stores the caller's data
/// as sent. A shape failure maps to a `JsonrpcError` (the consumer returns
/// `fuz_http::invalid_params`). `None` = pass-through (no per-kind
/// validation). The check is pure (no DB / auth context), so it's a plain
/// `Arc<dyn Fn>`.
pub type CellDataValidator =
    Arc<dyn Fn(Option<&str>, &Value) -> Result<(), JsonrpcError> + Send + Sync>;

/// Parsed `cell_create` params a [`CellCreateAuthorize`] gates on.
///
/// Mirrors the input arg of TS `CellCreateAuthorize.authorize` (`kind`,
/// `data`, `parent_id`, `parent_kind`, `root_id`, `root_policy`). Modeled on
/// [`fuz_auth::role_grant_offer_action_specs::OfferCreateAuthorizeInput`].
#[derive(Debug, Clone)]
pub struct CellCreateAuthorizeInput {
    /// The cell's capability tag (the top-level `cell.kind` value, `Option`).
    pub kind: Option<String>,
    /// The raw wire `data` payload.
    pub data: Value,
    /// The immediate container the create targets. `None` = a root creation
    /// (parentless); `Some` = a contribution under that parent.
    pub parent_id: Option<Uuid>,
    /// The immediate container's `kind` column, read by the handler with the
    /// parent — so an authorizer checks the parent → child edge (which kinds
    /// may sit under which) without a read of its own. `None` for a root
    /// creation, and for a parent that is typeless.
    pub parent_kind: Option<String>,
    /// The governing root of the directory subtree, resolved by the handler
    /// from the parent (`parent.root_id ?? parent.id`). `None` for a root
    /// creation.
    pub root_id: Option<Uuid>,
    /// The governing root's contribution `policy` column — the handler reads
    /// the root in-tx and hands its policy over, so a directory-aware
    /// authorizer resolves `root_policy[kind]` **without a DB read of its
    /// own**. `None` for a root creation, and for a root that carries no
    /// policy (the authorizer's floor governs). A missing or soft-deleted root
    /// answers `cell_not_found` before the authorizer runs.
    ///
    /// The policy is a manage-tier column, never the root's `data`: an editor
    /// grant can rewrite `data`, so a policy read from it would be the
    /// editor's to loosen.
    pub root_policy: Option<Value>,
}

/// An authorizer's decision for a `cell_create`.
///
/// Folds the moderation outcome into the authority decision — one policy
/// resolution, not two. The Rust twin of the TS `CellCreateVerdict` union.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Reject the create. The handler surfaces a **403** `forbidden` (the
    /// parent was viewable, or it is a root creation — an unviewable parent is
    /// already 404-masked upstream, before the authorizer runs).
    Deny,
    /// Admit the create. `moderation_required` decides the born lifecycle:
    /// `true` → `moderation = pending` + visibility forced private (awaits a
    /// `cell_moderate` approval); `false` → `moderation = approved` + the
    /// author's chosen visibility (live immediately, e.g. reactions).
    Allow {
        /// Whether the contribution is born `pending` (awaiting approval).
        moderation_required: bool,
    },
}

/// Consumer-injectable authorization predicate for `cell_create` — the Rust
/// twin of TS `CellCreateAuthorize`.
///
/// **Parent-aware**: it gates both roots (`parent_id = None`) and contributions
/// (`parent_id = Some`), returning a [`Verdict`] that also carries the
/// moderation outcome. `cell_clone` consults it too: every cell a clone writes
/// is a parentless creation of the source's kind, asked as a root.
///
/// **Object-safe** — dispatched as `Arc<dyn CellCreateAuthorize>` on the cold
/// cell-create path (one DB-write request, vtable cost negligible). Async via
/// [`BoxFuture`] per the spine's dyn-trait carve-out.
///
/// Runs AFTER the per-kind [`CellDataValidator`] (the validator answers "is
/// `data` well-formed?"; the authorizer answers "may *this actor* create *this
/// kind* here?") and AFTER the handler has resolved `root_id` + `root_policy`
/// from the parent (a `None` authorizer still resolves `root_id` + 404-masks an
/// unviewable parent or a missing or soft-deleted root). Returns
/// `Verdict::Allow{..}` / `Verdict::Deny`, or `Err` for a hard error.
///
/// **The common path reads no database** — the governing root's policy arrives
/// in the input (`root_policy`), read in-tx by the handler. A policy needing
/// more (a content pre-screen, say) reads through `db`, the request's own
/// handle: `cell_create` and `cell_clone` have side effects, so it is the
/// request transaction, and the read sees the request's snapshot with no
/// second pool checkout. Run generic query functions over it with
/// [`fuz_db::action_db_dispatch!`]. **Read-only**: the authorizer decides, it
/// never writes — a write would commit or roll back with the create, and
/// nothing enforces this but the impl.
///
/// **The policy is opaque to the spine.** The authorizer that interprets a
/// root's `policy` is also what accepts one: [`Self::validate_policy`] runs on
/// every non-null policy write (a root's `cell_create`, `cell_policy_set`).
pub trait CellCreateAuthorize: Send + Sync {
    fn authorize<'a>(
        &'a self,
        auth: &'a RequestActorContext,
        input: &'a CellCreateAuthorizeInput,
        db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<Verdict, JsonrpcError>>;

    /// Accept or refuse a root `policy` before it is written — the shape this
    /// authorizer's [`Self::authorize`] reads. Runs after the manage and
    /// root-only gates, so it decides validity alone, never authority; return
    /// `fuz_http::invalid_params` with [`ERROR_CELL_POLICY_INVALID`] (or a
    /// reason of the consumer's) for a policy it can't interpret.
    ///
    /// The default refuses every policy (`cell_policy_unsupported`, the answer
    /// given when no authorizer is mounted): an authorizer that reads no policy
    /// stores none, so a root never carries a policy nothing enforces.
    ///
    /// # Errors
    ///
    /// The refusal, as the `JsonrpcError` the write answers with.
    fn validate_policy(&self, policy: &Value) -> Result<(), JsonrpcError> {
        let _ = policy;
        Err(cell_policy_unsupported())
    }
}

// -- Error reasons (mirror TS `cell_action_specs.ts`) -----------------------

/// Cell id/path did not resolve, or the caller can't view it (IDOR mask).
pub const ERROR_CELL_NOT_FOUND: &str = "cell_not_found";
/// Non-admin caller supplied a `path` write.
pub const ERROR_CELL_PATH_ADMIN_ONLY: &str = "cell_path_admin_only";
/// A `path` write collided with an existing active cell's path.
pub const ERROR_CELL_PATH_TAKEN: &str = "cell_path_taken";
/// Non-manage-tier caller tried to change `cell.visibility`.
pub const ERROR_CELL_VISIBILITY_MANAGE_ONLY: &str = "cell_visibility_manage_only";
/// `cell_get` input lacked both `id` and `path`.
pub const ERROR_CELL_GET_REQUIRES_ID_OR_PATH: &str = "cell_get_requires_id_or_path";
/// Null-auth `cell_list` caller passed a `created_by` filter.
pub const ERROR_CELL_LIST_CREATED_BY_REQUIRES_AUTH: &str = "cell_list_created_by_requires_auth";
/// Null-auth `cell_list` caller passed `shared_with: 'me'`.
pub const ERROR_CELL_LIST_SHARED_WITH_REQUIRES_AUTH: &str = "cell_list_shared_with_requires_auth";
/// Wire-supplied `data` carried a `"kind"` key.
///
/// `kind` is the top-level `cell.kind` column (single source of truth), so a
/// `kind` inside `data` is rejected fail-loud on `cell_create` /
/// `cell_update` / `cell_clone`.
pub const ERROR_CELL_KIND_IN_DATA: &str = "cell_kind_in_data";

/// `cell_create` was given an empty-string `kind`.
///
/// `kind` is a non-empty capability tag or absent — `None` is the typeless
/// state, so `""` (a tag that tags nothing) is rejected fail-loud, keeping
/// `kind` a clean `null | non-empty-string` on both spines.
pub const ERROR_CELL_KIND_EMPTY: &str = "cell_kind_empty";

/// The parent-aware [`CellCreateAuthorize`] returned [`Verdict::Deny`] for a
/// **viewable** parent (or a root creation).
///
/// "You see it, you can't contribute here." A **403** `forbidden`, distinct
/// from the create-path **404** mask used when the parent itself isn't viewable.
pub const ERROR_CELL_CREATE_FORBIDDEN: &str = "cell_create_forbidden";

/// `cell_moderate` caller can view the contribution but lacks moderation
/// authority over its governing root (not admin / not the root's manager).
///
/// A **403** `forbidden`. The author can view their own pending contribution,
/// so they reach this gate — and are denied here, which is the anti-self-
/// approval guard (`moderation` is not author-writable).
pub const ERROR_CELL_MODERATE_FORBIDDEN: &str = "cell_moderate_forbidden";

/// A non-admin write's `data` introduces a fact ref the acting actor does not
/// hold.
///
/// A **403** `forbidden`. A ref is new when the write's derived refs carry a
/// hash its base doesn't — nothing on `cell_create`, the cell's current refs
/// on `cell_update`, the source row's refs on `cell_clone` — and held when the
/// acting actor has put the fact's bytes (a `fact_holder` row). The answer
/// reads holder rows only, so it is the same for a fact that is stored and one
/// that isn't. The gate is the `cell_ref_admission` module.
pub const ERROR_CELL_REF_NOT_HELD: &str = "cell_ref_not_held";

/// `cell_moderate` target has no governing root (`root_id` is null) — it is a
/// root or an unparented cell, not a gated contribution, so there is nothing to
/// moderate. A **400** `invalid_params`.
pub const ERROR_CELL_NOT_A_CONTRIBUTION: &str = "cell_not_a_contribution";

/// `cell_moderate` names a transition the target's `moderation` doesn't allow.
///
/// An approval of a contribution that is not `pending` (approved or rejected
/// already, or never moderated), or a rejection of one that is neither
/// `pending` nor `approved` (rejected already, or never moderated).
///
/// A **400** `invalid_params`, answered to a caller holding moderation
/// authority over the governing root (the 404 mask and the 403 come first).
/// Without it an approval would force any reachable contribution public.
pub const ERROR_CELL_NOT_PENDING: &str = "cell_not_pending";

/// A policy write (a root `cell_create` carrying one, or `cell_policy_set`)
/// targeted a cell with a parent. Only a root carries a contribution policy.
/// A **400** `invalid_params`.
pub const ERROR_CELL_POLICY_ROOT_ONLY: &str = "cell_policy_root_only";

/// A non-null policy write found nothing to interpret it.
///
/// No create authorizer is mounted, or the mounted one's
/// [`CellCreateAuthorize::validate_policy`] keeps the default. The policy is
/// opaque to the spine, so with nothing to interpret it the write is refused
/// rather than stored inert. A **400** `invalid_params`.
pub const ERROR_CELL_POLICY_UNSUPPORTED: &str = "cell_policy_unsupported";

/// `cell_policy_set` caller can view the root but can't manage it.
///
/// Not admin and not the owner — an editor grant included. A **403**
/// `forbidden`; a caller who can't view the root gets the 404 mask first.
pub const ERROR_CELL_POLICY_MANAGE_ONLY: &str = "cell_policy_manage_only";

/// The conventional reason a [`CellCreateAuthorize::validate_policy`] refuses a
/// policy it can't interpret with. The spine never answers it itself.
pub const ERROR_CELL_POLICY_INVALID: &str = "cell_policy_invalid";

/// `cell_create` keys whose TS twin is `optional(nullable(…))`, so an
/// explicit `null` is a spelling of "absent" rather than a refusal.
///
/// Every other key on the input — `visibility` and `acting` included — is
/// `optional` alone, and `fuz_http::parse_strict_params_allowing_null` holds
/// those to the same `-32602` the twin gives.
const CELL_CREATE_NULLABLE: &[&str] = &["kind", "path", "parent_id", "policy"];

/// `cell_policy_set` keys whose TS twin is `nullable(...)` — `policy: null`
/// clears the root's policy.
const CELL_POLICY_SET_NULLABLE: &[&str] = &["policy"];

/// `cell_update` keys whose TS twin admits `null`. `path` is the tri-state
/// write (absent keeps, `null` clears, a string sets), so `null` is the
/// clearing spelling and not an absent value.
const CELL_UPDATE_NULLABLE: &[&str] = &["path"];

/// Upper bound on `cell.path` length (mirrors the TS `CellPath` brand:
/// `.min(1).max(256)`). The cell layer imposes no path *grammar* — only
/// non-empty + a sane ceiling.
pub const CELL_PATH_LENGTH_MAX: usize = 256;

/// Upper bound on a wire `kind`, in UTF-16 code units.
///
/// Applies on `cell_create` and to the `cell_list` filter (mirrors the TS
/// `CELL_KIND_LENGTH_MAX`). The cell layer imposes no `kind` *grammar*; the
/// tag is copied into every audit row the cell's mutations write, so it is
/// bounded where it enters. The same value as `fuz_cell`'s
/// `CELL_FIELD_NAME_LENGTH_MAX`.
pub const CELL_KIND_LENGTH_MAX: usize = 64;

/// Cap on the forward fields / items bundled into a `cell_get` response
/// (mirrors the TS `CELL_RELATIONS_BUNDLE_LIMIT`).
///
/// Beyond it the relation is `*_truncated: true` and the client paginates
/// via the explicit `cell_field_list` / `cell_item_list` verbs.
pub const CELL_RELATIONS_BUNDLE_LIMIT: i64 = 500;

/// Cap on a `cell_field_list` / `cell_item_list` page, forward and reverse
/// alike (mirrors the TS `CELL_RELATION_LIST_LIMIT_MAX`).
pub const CELL_RELATION_LIST_LIMIT_MAX: i64 = 500;

/// The page size a `cell_field_list` / `cell_item_list` call omitting `limit` gets.
///
/// Forward and reverse alike (mirrors the TS
/// `CELL_RELATION_LIST_LIMIT_DEFAULT`). Both lists are public reads, so an
/// omitted limit never means unbounded.
pub const CELL_RELATION_LIST_LIMIT_DEFAULT: i64 = 50;

// -- Small shared helpers ---------------------------------------------------

/// The shared `cell_not_found` 404 (IDOR mask — miss and unauthorized
/// share one shape).
pub(crate) fn cell_not_found() -> JsonrpcError {
    fuz_http::not_found("cell", Some(ERROR_CELL_NOT_FOUND))
}

/// The `cell_moderate` refusal of a transition the contribution's state
/// doesn't allow.
fn cell_not_pending() -> JsonrpcError {
    fuz_http::invalid_params(
        "cell is not pending moderation",
        Some(ERROR_CELL_NOT_PENDING),
    )
}

/// The refusal of a policy write nothing can interpret.
fn cell_policy_unsupported() -> JsonrpcError {
    fuz_http::invalid_params(
        "cell.policy needs a create authorizer that accepts it",
        Some(ERROR_CELL_POLICY_UNSUPPORTED),
    )
}

/// The refusal of a policy write on a cell with a parent.
fn cell_policy_root_only() -> JsonrpcError {
    fuz_http::invalid_params(
        "cell.policy is set only on a root (a cell without a parent)",
        Some(ERROR_CELL_POLICY_ROOT_ONLY),
    )
}

/// Validate a non-null policy write through the mounted authorizer:
/// `cell_policy_unsupported` with none mounted, else its `validate_policy`.
fn validate_policy_write(
    authorizer: Option<&Arc<dyn CellCreateAuthorize>>,
    policy: &CellPolicy,
) -> Result<(), JsonrpcError> {
    let Some(authorize) = authorizer else {
        return Err(cell_policy_unsupported());
    };
    authorize.validate_policy(policy.as_value())
}

/// Validate an optional list `limit` (`1..=max` when present) for the list
/// verb `method` — the relation lists and `cell_list` — the twin of its
/// `pipe(number, integer, min_value(1), max_value(max))`.
pub(crate) fn validate_list_limit(
    limit: Option<i64>,
    max: i64,
    method: &str,
) -> Result<(), JsonrpcError> {
    if let Some(n) = limit
        && !(1..=max).contains(&n)
    {
        return Err(fuz_http::invalid_input_params(
            &format!("{method} limit must be 1-{max}"),
            None,
        ));
    }
    Ok(())
}

/// Validate an optional list `offset` (`0..=SAFE_INTEGER_MAX` when present)
/// for the list verb `method`, the twin of its
/// `pipe(number, safe_integer, min_value(0))` — `safe_integer` refuses past
/// `Number.MAX_SAFE_INTEGER`.
pub(crate) fn validate_list_offset(offset: Option<i64>, method: &str) -> Result<(), JsonrpcError> {
    if offset.is_some_and(|n| !(0..=SAFE_INTEGER_MAX).contains(&n)) {
        return Err(fuz_http::invalid_input_params(
            &format!("{method} offset must be 0-{SAFE_INTEGER_MAX}"),
            None,
        ));
    }
    Ok(())
}

/// Load a cell's grants only when the caller is authenticated — `None` auth
/// admits solely via the public branch of `can_view_cell`, so the grant
/// load is wasted work. Mirrors the per-call skip in the TS handlers. Its
/// sole caller is `require_admitted_cell`, and that is what keeps the skip
/// earning its place: the four optional-auth call sites reach it only
/// through the core.
async fn load_grants_if_authed<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    auth: Option<&RequestActorContext>,
    cell_id: Uuid,
) -> Result<Option<Vec<CellGrantRow>>, JsonrpcError> {
    if auth.is_none() {
        return Ok(None);
    }
    let grants = query_cell_grant_list_for_cell(client, cell_id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    Ok(Some(grants))
}

/// The `load → 404 → grants → predicate → 404` sequence the three
/// grant-consulting tiers below share.
///
/// `admits` is what names the tier — [`can_edit_cell`] for the write tier,
/// [`can_view_cell`] for the two read tiers. Grants load through
/// `load_grants_if_authed` (so an unauthenticated caller runs no grant
/// query) and are read from the **loaded row's** id, not the caller's input.
/// Both refusals — the row absent, and the predicate denying — answer with the
/// same [`cell_not_found`]; the tier wrappers say why that mask is the point.
async fn require_admitted_cell<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    auth: Option<&RequestActorContext>,
    cell_id: Uuid,
    admits: fn(Option<&RequestActorContext>, &CellRow, Option<&[CellGrantRow]>) -> bool,
) -> Result<CellRow, JsonrpcError> {
    let row = query_cell_get(client, cell_id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let Some(row) = row else {
        return Err(cell_not_found());
    };
    let grants = load_grants_if_authed(client, auth, row.id).await?;
    if !admits(auth, &row, grants.as_deref()) {
        return Err(cell_not_found());
    }
    Ok(row)
}

/// Load the cell at `cell_id` and gate the caller on [`can_edit_cell`],
/// 404-masking a miss and a denial alike. Returns the loaded row.
///
/// The write tier: `cell_update` / `cell_delete`, the `source` a
/// `cell_field_set` / `cell_field_delete` writes, and the `parent` every
/// `cell_item_*` mutation writes. Denial is [`cell_not_found`] rather than a
/// 403 because a 403 confirms the row exists — a caller with no authority
/// could otherwise walk ids and read a private cell's existence off the
/// difference between the two answers, so miss and deny carry one wire shape
/// (the IDOR mask), as on the TS twin.
///
/// The row comes back so a caller that needs it — `cell_delete`'s audit
/// metadata, `cell_update`'s visibility comparison — doesn't re-read it; a
/// caller that wants only the gate drops it.
pub(crate) async fn require_editable_cell<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    auth: &RequestActorContext,
    cell_id: Uuid,
) -> Result<CellRow, JsonrpcError> {
    require_admitted_cell(client, Some(auth), cell_id, can_edit_cell).await
}

/// Load the cell at `cell_id` and gate an authenticated caller on
/// [`can_view_cell`], 404-masking a miss and a denial alike. Returns the
/// loaded row.
///
/// The read tier of the paths that already hold an actor: `cell_create`'s
/// parent, `cell_clone`'s source, and the far endpoint a write links to (`cell_field_set`'s `target`,
/// `cell_item_insert`'s `child`). That endpoint check is what keeps a link
/// from being an existence oracle — without it a caller could point a field at
/// any id and read the answer off whether the write succeeded. The denial
/// carries the same mask, for the reason [`require_editable_cell`] gives.
/// `cell_moderate`'s target goes through
/// [`require_viewable_or_stewarded_cell`] instead.
///
/// [`require_viewable_cell_optional_auth`] is this gate for the public reads,
/// which admit an unauthenticated caller.
pub(crate) async fn require_viewable_cell<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    auth: &RequestActorContext,
    cell_id: Uuid,
) -> Result<CellRow, JsonrpcError> {
    require_admitted_cell(client, Some(auth), cell_id, can_view_cell).await
}

/// Load the cell at `cell_id` and gate a possibly-unauthenticated caller on
/// [`can_view_cell`], 404-masking a miss and a denial alike. Returns the
/// loaded row.
///
/// The public-read call sites of this tier — the four bidirectional
/// endpoints of `cell_field_list` / `cell_item_list`, whose specs are
/// `optional_identity`. Not every `optional_identity` read routes here:
/// `cell_get` keeps its own inline gate because it loads by id-or-path and
/// then reads the grants back for the `can_edit` flag it returns, and
/// `cell_list` has no per-id gate at all (its visibility predicate lives in
/// the query).
///
/// An unauthenticated caller performs **zero** grant queries: the load runs
/// through `load_grants_if_authed`, and only the `public` branch of
/// [`can_view_cell`] can admit a `None` caller, so a grant read would be pure
/// waste. The mask is [`require_editable_cell`]'s, and it carries the most
/// weight here — these are the reads an anonymous prober can reach.
pub(crate) async fn require_viewable_cell_optional_auth<
    C: deadpool_postgres::GenericClient + ?Sized,
>(
    client: &C,
    auth: Option<&RequestActorContext>,
    cell_id: Uuid,
) -> Result<CellRow, JsonrpcError> {
    require_admitted_cell(client, auth, cell_id, can_view_cell).await
}

/// Gate a loaded cell on [`can_view_cell`] or, when that denies, the steward
/// arm ([`cell_steward_admits`] — the governing root's manager reading a
/// pending or rejected contribution), 404-masking a denial.
///
/// The read gate of the surfaces a moderator works from: `cell_get` and
/// `cell_moderate`'s view step. It is **not** for `cell_clone`'s source, a
/// contribution's parent, the relation endpoint gates, or the grant paths —
/// those keep [`can_view_cell`] alone (`fuz_cell::cell_steward` says why), so
/// a later sweep must not route them here. The steward check runs only after
/// the view check denies, so an admitted read costs no root load.
pub(crate) async fn admit_viewable_or_stewarded_cell<
    C: deadpool_postgres::GenericClient + ?Sized,
>(
    client: &C,
    auth: Option<&RequestActorContext>,
    row: &CellRow,
    grants: Option<&[CellGrantRow]>,
) -> Result<(), JsonrpcError> {
    if can_view_cell(auth, row, grants) {
        return Ok(());
    }
    if cell_steward_admits(client, auth, row)
        .await
        .map_err(|e| map_cell_error(e, false))?
    {
        return Ok(());
    }
    Err(cell_not_found())
}

/// Load the cell at `cell_id` and gate the caller through
/// [`admit_viewable_or_stewarded_cell`], 404-masking a miss and a denial
/// alike. Returns the loaded row. `cell_moderate`'s view step — it lets a
/// non-admin root owner reach the root-authority check.
pub(crate) async fn require_viewable_or_stewarded_cell<
    C: deadpool_postgres::GenericClient + ?Sized,
>(
    client: &C,
    auth: &RequestActorContext,
    cell_id: Uuid,
) -> Result<CellRow, JsonrpcError> {
    let row = query_cell_get(client, cell_id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let Some(row) = row else {
        return Err(cell_not_found());
    };
    let grants = load_grants_if_authed(client, Some(auth), row.id).await?;
    admit_viewable_or_stewarded_cell(client, Some(auth), &row, grants.as_deref()).await?;
    Ok(row)
}

/// Load the cell at `cell_id` and gate the caller on [`can_manage_cell`],
/// 404-masking a miss and a denial alike. Returns the loaded row.
///
/// The manage tier — `cell_audit_list` plus the `cell_grant_create` /
/// `cell_grant_list` ACL surfaces. [`can_manage_cell`] is admin-or-owner and
/// consults no grants (manage is not a grant level), so this tier issues **no**
/// grant query at all; that is its one structural difference from the three
/// siblings, and why it doesn't route through `require_admitted_cell`.
///
/// The tier sits above [`can_view_cell`] deliberately: an audit timeline and a
/// share list both say who touched the cell, which is more sensitive than the
/// content, so a viewer or an editor gets the same [`cell_not_found`] mask a
/// stranger does.
pub(crate) async fn require_manageable_cell<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    auth: &RequestActorContext,
    cell_id: Uuid,
) -> Result<CellRow, JsonrpcError> {
    let row = query_cell_get(client, cell_id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let Some(row) = row else {
        return Err(cell_not_found());
    };
    if !can_manage_cell(Some(auth), &row) {
        return Err(cell_not_found());
    }
    Ok(row)
}

/// Serialize a row to its `CellJson` wire value.
fn cell_to_value(row: &CellRow) -> Result<Value, JsonrpcError> {
    serde_json::to_value(row)
        .map_err(|e| fuz_http::internal_error_with_source("cell serialize failed", &e))
}

/// Emit a cell-domain audit event for the caller, routing per
/// [`fuz_auth::AUDIT_EVENT_SPECS`] (in-tx on success — atomic with the
/// mutation). Shared by the grant / field / item handlers too; `metadata`
/// is the per-event envelope (IDs, plus the policies `cell_policy_set`
/// records). `db` must be the handler's tx client so the audit row commits
/// with the state row.
pub(crate) async fn emit_cell_audit<C: deadpool_postgres::GenericClient + ?Sized>(
    ctx: &ActionContext<'_>,
    db: &C,
    auth: &RequestActorContext,
    event_type: AuditEventType,
    metadata: Value,
) -> Result<(), JsonrpcError> {
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(event_type)
            .actor(auth.actor.id)
            .account(auth.account.id)
            .ip(ctx.client_ip.clone())
            .metadata(metadata),
    )
    .await
}

/// Build the `{cell_id, kind?, path?}` envelope shared by `cell_create` /
/// `cell_update` / `cell_delete` audit rows (mirrors the TS
/// `CellAuditMetadata`). `kind` / `path` are omitted when absent.
fn cell_mutation_metadata(row: &CellRow) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("cell_id".to_owned(), json!(row.id));
    if let Some(kind) = &row.kind {
        map.insert("kind".to_owned(), json!(kind));
    }
    if let Some(path) = &row.path {
        map.insert("path".to_owned(), json!(path));
    }
    Value::Object(map)
}

/// Map a [`CellError`] to a JSON-RPC error. On a path-bearing write, a
/// unique violation is the `idx_cell_path_unique` collision → `conflict`
/// (409); everything else is an opaque internal error.
pub(crate) fn map_cell_error(err: CellError, path_write: bool) -> JsonrpcError {
    match err {
        CellError::Db(e) if path_write && is_pg_unique_violation(&e) => {
            fuz_http::conflict("cell.path is already taken", Some(ERROR_CELL_PATH_TAKEN))
        }
        CellError::Db(e) => fuz_http::internal_error_with_source("cell query failed", &e),
        decode @ CellError::Decode(_) => {
            fuz_http::internal_error_with_source("cell row decode failed", &decode)
        }
    }
}

/// Reject a `path` write outside `[1, CELL_PATH_LENGTH_MAX]` characters
/// (mirrors the TS `CellPath` brand). The wire structs are duck-typed
/// (no schema layer on the Rust spine), so length is
/// enforced here in the handler. The count is UTF-16 code units, which is
/// what `String.length` — and so the brand's `bounded_string` — measures, so
/// an astral-plane character costs two on both spines.
fn validate_cell_path(path: &str) -> Result<(), JsonrpcError> {
    let len = path.encode_utf16().count();
    if len == 0 || len > CELL_PATH_LENGTH_MAX {
        return Err(fuz_http::invalid_input_params(
            "cell.path must be 1-256 characters",
            None,
        ));
    }
    Ok(())
}

/// Reject a wire `kind` longer than [`CELL_KIND_LENGTH_MAX`].
///
/// Mirrors the TS `bounded_string({max: CELL_KIND_LENGTH_MAX})` on `cell_create` and
/// the `cell_list` filter. Like [`validate_cell_path`], the count is UTF-16
/// code units, and the refusal is a schema-shaped `invalid_params` with no
/// reason. An empty `kind` passes here: `cell_create` refuses it separately
/// (`cell_kind_empty`), and as a `cell_list` filter it matches nothing.
fn validate_cell_kind_length(kind: &str) -> Result<(), JsonrpcError> {
    if kind.encode_utf16().count() > CELL_KIND_LENGTH_MAX {
        return Err(fuz_http::invalid_input_params(
            "cell.kind must be at most 64 characters",
            None,
        ));
    }
    Ok(())
}

/// Reject a `cell_list` `ref` filter that isn't a wire fact hash (mirrors the
/// TS `FactHashSchema`). The wire key is `ref` — `ref_hash` is the Rust field
/// name behind serde's rename — so the message names `ref`. Refusing here
/// rather than running the filter keeps an off-grammar address from reading
/// as an honest empty page on one spine and `invalid_params` on the other.
fn validate_cell_list_ref(ref_hash: &str) -> Result<(), JsonrpcError> {
    if !is_valid_fact_hash(ref_hash) {
        return Err(fuz_http::invalid_input_params(
            "cell_list ref must be a blake3 fact hash",
            None,
        ));
    }
    Ok(())
}

/// Reject a `"kind"` key inside a wire-supplied `data` object (single source
/// of truth — `kind` is the top-level `cell.kind` column). Fail-loud, applied
/// to `cell_create` / `cell_update` / `cell_clone` data inputs. A non-object
/// `data` (or one without the key) passes.
fn reject_kind_in_data(data: &Value) -> Result<(), JsonrpcError> {
    if data.get("kind").is_some() {
        return Err(fuz_http::invalid_params(
            "cell.data must not contain `kind` (it is a top-level field)",
            Some(ERROR_CELL_KIND_IN_DATA),
        ));
    }
    Ok(())
}

// -- Handlers (generic over the resolved client) ----------------------------

async fn handle_create<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellCreateInput,
    validator: Option<&CellDataValidator>,
    authorizer: Option<&Arc<dyn CellCreateAuthorize>>,
) -> Result<Value, JsonrpcError> {
    // Schema-level on the twin, so it answers ahead of every handler check.
    if let Some(kind) = &input.kind {
        validate_cell_kind_length(kind)?;
    }
    // Admin gate before path-length validation (matches TS precedence): a
    // non-admin supplying any `path` gets `cell_path_admin_only`, not a
    // length error — so the length rule never leaks to unauthorized callers.
    let path_write = input.path.is_some();
    if path_write && !auth.has_scoped_role(ROLE_ADMIN, None) {
        return Err(fuz_http::forbidden(
            "cell.path is admin-only",
            Some(ERROR_CELL_PATH_ADMIN_ONLY),
        ));
    }
    if let Some(path) = &input.path {
        validate_cell_path(path)?;
    }
    // Input-shape checks run AFTER the authz gate (matching TS + the clone
    // path): `kind` is the top-level column, so a `kind` inside `data` is a
    // single-source-of-truth violation, and an empty `kind` is rejected (a tag
    // tags nothing — `None` is the typeless state, keeping `kind` a clean
    // `null | non-empty-string`).
    reject_kind_in_data(input.data.as_value())?;
    if input.kind.as_deref() == Some("") {
        return Err(fuz_http::invalid_params(
            "cell.kind must not be empty (use null for a typeless cell)",
            Some(ERROR_CELL_KIND_EMPTY),
        ));
    }
    // Per-kind data-shape validation (TS `validate_data_or_throw` at create).
    if let Some(validate) = validator {
        validate(input.kind.as_deref(), input.data.as_value())?;
    }
    // A contribution policy is a root's alone, and the mounted authorizer —
    // what interprets it — must accept it (none mounted refuses it). The
    // authorizer does not gate it: a root's creator manages the root anyway.
    if let Some(policy) = &input.policy {
        if input.parent_id.is_some() {
            return Err(cell_policy_root_only());
        }
        validate_policy_write(authorizer, policy)?;
    }
    // Directory tree: resolve the governing `root_id` from the parent (and the
    // root's `policy` for the authorizer). This runs whether or not
    // an authorizer is mounted — `root_id` is written regardless, and an
    // unviewable parent 404-masks the attempt (the same IDOR mask the read path
    // uses; never reveals a hidden container). A root creation (`parent_id =
    // None`) has `root_id = None`. The root is read **in-tx**, reusing the
    // parent row when the parent *is* the root, else one read by `root_id` — so
    // the common authorizer needs no read of its own. A missing or soft-deleted
    // root answers `cell_not_found` like a missing parent (soft delete doesn't
    // cascade, so a live parent can sit under a tombstoned root): nothing is
    // written pointing at the tombstone, and an authorizer never sees a root id
    // it can't read.
    let (root_id, root_policy, parent_kind) = if let Some(parent_id) = input.parent_id {
        let parent = require_viewable_cell(client, auth, parent_id).await?;
        let rid = parent.root_id.unwrap_or(parent.id);
        let root_policy = if rid == parent.id {
            parent.policy
        } else {
            query_cell_get(client, rid)
                .await
                .map_err(|e| map_cell_error(e, false))?
                .ok_or_else(cell_not_found)?
                .policy
        };
        (Some(rid), root_policy, parent.kind)
    } else {
        (None, None, None)
    };
    // Creation-capability gate — the opt-in parent-aware `CellCreateAuthorize`.
    // Runs after the validator (shape) and after the parent-resolve (so a
    // hidden parent already 404-masked). `Verdict::Deny` for a *viewable*
    // parent / a root creation is a 403 `forbidden` (not the 404 mask);
    // `Verdict::Allow` folds the moderation outcome.
    // The columns default to open-create (`moderation = None`, author's
    // visibility) when no authorizer is mounted.
    let mut moderation: Option<&str> = None;
    let mut visibility = input.visibility;
    if let Some(authorize) = authorizer {
        let authz_input = CellCreateAuthorizeInput {
            kind: input.kind.clone(),
            data: input.data.as_value().clone(),
            parent_id: input.parent_id,
            parent_kind,
            root_id,
            root_policy,
        };
        match authorize.authorize(auth, &authz_input, &ctx.db).await? {
            Verdict::Deny => {
                return Err(fuz_http::forbidden(
                    "cell creation is not permitted here",
                    Some(ERROR_CELL_CREATE_FORBIDDEN),
                ));
            }
            // Moderation is a *contribution* concept — only stamp it for a
            // create with a parent. A root / unparented create stays
            // `moderation = None` at the author's visibility even under a
            // mounted authorizer (there is no container to be moderated under).
            Verdict::Allow {
                moderation_required,
            } if input.parent_id.is_some() => {
                if moderation_required {
                    // Born pending: stays private until `cell_moderate` approves it.
                    moderation = Some("pending");
                    visibility = Some(CellVisibility::Private);
                } else {
                    // Born approved + live immediately at the author's visibility.
                    moderation = Some("approved");
                }
            }
            // Root / unparented allow: admitted, no moderation marker.
            Verdict::Allow { .. } => {}
        }
    }
    // Possession-gated ref admission — every ref is new on a create.
    require_new_refs_held(client, auth, None, input.data.as_value()).await?;
    let row = query_cell_create(
        client,
        input.data.as_value(),
        input.kind.as_deref(),
        visibility,
        input.path.as_deref(),
        input.parent_id,
        root_id,
        moderation,
        input.policy.as_ref().map(CellPolicy::as_value),
        Some(auth.actor.id),
    )
    .await
    .map_err(|e| map_cell_error(e, path_write))?;
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellCreate,
        cell_mutation_metadata(&row),
    )
    .await?;
    Ok(json!({ "cell": cell_to_value(&row)? }))
}

async fn handle_get<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    auth: Option<&RequestActorContext>,
    input: CellGetInput,
) -> Result<Value, JsonrpcError> {
    // The `path` lookup key takes the same `CellPath` grammar a `path` write
    // does — the twin declares one branded type for both, so an off-grammar
    // path must be `invalid_params` here rather than a guaranteed lookup miss.
    if let Some(path) = &input.path {
        validate_cell_path(path)?;
    }
    // `id` precedence; both absent ⇒ invalid_params, as the TS handler's
    // guard answers (its schema leaves both optional).
    let row = if let Some(id) = input.id {
        query_cell_get(client, id).await
    } else if let Some(path) = &input.path {
        query_cell_get_by_path(client, path).await
    } else {
        return Err(fuz_http::invalid_params(
            "cell_get requires id or path",
            Some(ERROR_CELL_GET_REQUIRES_ID_OR_PATH),
        ));
    }
    .map_err(|e| map_cell_error(e, false))?;

    let Some(row) = row else {
        return Err(cell_not_found());
    };
    // Grants feed the view / edit predicates (manage tier is grant-free).
    let grants = query_cell_grant_list_for_cell(client, row.id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    // 404 covers miss + unauthorized so private-cell existence doesn't leak.
    // The governing root's manager also reads a pending or rejected
    // contribution here (the steward arm); the `can_edit` / `can_grant` flags
    // stay on the base predicates, so a steward reads `false` / `false`.
    admit_viewable_or_stewarded_cell(client, auth, &row, Some(&grants)).await?;
    let can_edit = can_edit_cell(auth, &row, Some(&grants));
    let can_grant = can_manage_cell(auth, &row);
    // Bundle the forward fields + items, one over the cap so truncation is
    // detectable without a count query. `*_truncated` reflects the raw
    // relation size before the visibility filter.
    let raw_fields = query_cell_field_list_for_source(
        client,
        &CellViewer::unrestricted(),
        row.id,
        Some(CELL_RELATIONS_BUNDLE_LIMIT + 1),
        None,
    )
    .await
    .map_err(|e| map_cell_error(e, false))?;
    let raw_items = query_cell_item_list_for_parent(
        client,
        &CellViewer::unrestricted(),
        row.id,
        Some(CELL_RELATIONS_BUNDLE_LIMIT + 1),
        None,
    )
    .await
    .map_err(|e| map_cell_error(e, false))?;
    let cap = usize::try_from(CELL_RELATIONS_BUNDLE_LIMIT).unwrap_or(usize::MAX);
    let fields_truncated = raw_fields.len() > cap;
    let items_truncated = raw_items.len() > cap;
    let fields_bundled = &raw_fields[..raw_fields.len().min(cap)];
    let items_bundled = &raw_items[..raw_items.len().min(cap)];
    // Strict target-visibility: drop bundled relations whose target the
    // caller can't view, so a viewer of this cell can't enumerate private
    // linked cells by id. One batched filter over both relation id-sets.
    let mut relation_ids: Vec<Uuid> =
        Vec::with_capacity(fields_bundled.len() + items_bundled.len());
    relation_ids.extend(fields_bundled.iter().map(|f| f.target_id));
    relation_ids.extend(items_bundled.iter().map(|i| i.child_id));
    let visible = filter_visible_targets(client, auth, &relation_ids)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let fields: Vec<Value> = fields_bundled
        .iter()
        .filter(|f| visible.contains(&f.target_id))
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|e| fuz_http::internal_error_with_source("cell field serialize failed", &e))?;
    let items: Vec<Value> = items_bundled
        .iter()
        .filter(|i| visible.contains(&i.child_id))
        .map(serde_json::to_value)
        .collect::<Result<_, _>>()
        .map_err(|e| fuz_http::internal_error_with_source("cell item serialize failed", &e))?;
    Ok(json!({
        "cell": cell_to_value(&row)?,
        "fields": fields,
        "fields_truncated": fields_truncated,
        "items": items,
        "items_truncated": items_truncated,
        "can_edit": can_edit,
        "can_grant": can_grant,
    }))
}

async fn handle_update<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellUpdateInput,
    validator: Option<&CellDataValidator>,
) -> Result<Value, JsonrpcError> {
    // Validate a real path *value* write (not a clear-to-null).
    if let Some(Some(path)) = &input.path {
        validate_cell_path(path)?;
    }
    // Any present `path` (incl. explicit null) is admin-only. Check before
    // the fetch so non-admins can't probe existence by varying `path`.
    let path_provided = input.path.is_some();
    if path_provided && !auth.has_scoped_role(ROLE_ADMIN, None) {
        return Err(fuz_http::forbidden(
            "cell.path is admin-only",
            Some(ERROR_CELL_PATH_ADMIN_ONLY),
        ));
    }
    let existing = require_editable_cell(client, auth, input.cell_id).await?;
    // Visibility writes are manage-tier only — gated on an actual change so
    // a client round-tripping the unchanged value isn't rejected.
    if let Some(new_visibility) = input.visibility
        && new_visibility != existing.visibility
        && !can_manage_cell(Some(auth), &existing)
    {
        return Err(fuz_http::forbidden(
            "cell.visibility is manage-tier only",
            Some(ERROR_CELL_VISIBILITY_MANAGE_ONLY),
        ));
    }
    // Input-shape checks run AFTER the authz gates (the can_edit 404 IDOR mask
    // fires first, so an unauthorized caller can't tell a malformed update from
    // a missing cell): a `kind` inside `data` is rejected (kind is the immutable
    // top-level column), then the per-kind data validator.
    let data = input.data.as_ref().map(CellData::as_value);
    if let Some(data) = data {
        reject_kind_in_data(data)?;
    }
    if let (Some(validate), Some(data)) = (validator, data) {
        validate(existing.kind.as_deref(), data)?;
    }
    // Possession-gated ref admission against the cell's current refs: refs
    // the cell already carries stay, whoever introduced them.
    if let Some(data) = data {
        require_new_refs_held(client, auth, existing.refs.as_deref(), data).await?;
    }
    // A path *value* (not a clear-to-null) is the only thing that can hit
    // the unique index.
    let path_value_write = matches!(input.path, Some(Some(_)));
    let path_arg = input.path.as_ref().map(Option::as_deref);
    let updated = query_cell_update(
        client,
        input.cell_id,
        data,
        input.visibility,
        path_arg,
        Some(auth.actor.id),
    )
    .await
    .map_err(|e| map_cell_error(e, path_value_write))?;
    let Some(updated) = updated else {
        // Raced with a deleter between the authz check and the UPDATE.
        return Err(cell_not_found());
    };
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellUpdate,
        cell_mutation_metadata(&updated),
    )
    .await?;
    Ok(json!({ "cell": cell_to_value(&updated)? }))
}

async fn handle_delete<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellDeleteInput,
) -> Result<Value, JsonrpcError> {
    let existing = require_editable_cell(client, auth, input.cell_id).await?;
    let deleted = query_cell_delete(client, input.cell_id, Some(auth.actor.id))
        .await
        .map_err(|e| map_cell_error(e, false))?;
    if !deleted {
        return Err(cell_not_found());
    }
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellDelete,
        cell_mutation_metadata(&existing),
    )
    .await?;
    Ok(json!({ "ok": true, "deleted": true }))
}

async fn handle_list<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    auth: Option<&RequestActorContext>,
    input: CellListInput,
) -> Result<Value, JsonrpcError> {
    if let Some(ref_hash) = &input.ref_hash {
        validate_cell_list_ref(ref_hash)?;
    }
    if let Some(kind) = &input.kind {
        validate_cell_kind_length(kind)?;
    }
    // The prefix filter is a `CellPath` on the twin, so it carries the same
    // grammar as a path write or a path lookup — an empty or over-long prefix
    // is refused rather than run as a `LIKE` that can never match.
    if let Some(prefix) = &input.path_prefix {
        validate_cell_path(prefix)?;
    }
    // Bound the batch-read set so a caller can't widen `id = ANY(...)`
    // past the page cap (mirrors the TS `ids.max(CELL_LIST_LIMIT_MAX)`).
    if input
        .ids
        .as_ref()
        .is_some_and(|ids| i64::try_from(ids.len()).map_or(true, |n| n > CELL_LIST_LIMIT_MAX))
    {
        return Err(fuz_http::invalid_input_params(
            "cell_list ids exceeds the maximum page size",
            None,
        ));
    }
    // An out-of-range page is refused, not clamped — the bounds of the TS
    // twin's `limit` (an integer in `[1, CELL_LIST_LIMIT_MAX]`) and `offset`
    // (a safe integer, at least 0), which carry no reason. Every schema-twin check
    // sits above the auth-reason checks below: the twin's schema refuses
    // before its handler runs.
    validate_list_limit(input.limit, CELL_LIST_LIMIT_MAX, "cell_list")?;
    validate_list_offset(input.offset, "cell_list")?;
    // The remaining value grammar the twin's schema holds — `shared_with` is
    // `literal('me')`, `order_by` / `order_direction` are `one_of`s — refused
    // here too, still ahead of the auth-reason checks and with no reason.
    if let Some(sw) = input.shared_with.as_deref()
        && sw != "me"
    {
        return Err(fuz_http::invalid_input_params(
            "cell_list shared_with must be \"me\"",
            None,
        ));
    }
    if let Some(order_by) = input.order_by.as_deref()
        && !matches!(order_by, "created_at" | "updated_at")
    {
        return Err(fuz_http::invalid_input_params(
            "cell_list order_by must be created_at or updated_at",
            None,
        ));
    }
    if let Some(direction) = input.order_direction.as_deref()
        && !matches!(direction, "asc" | "desc")
    {
        return Err(fuz_http::invalid_input_params(
            "cell_list order_direction must be asc or desc",
            None,
        ));
    }
    // `created_by` is a soft account-id enumeration probe; require auth.
    if auth.is_none() && input.created_by.is_some() {
        return Err(fuz_http::invalid_params(
            "cell_list created_by requires authentication",
            Some(ERROR_CELL_LIST_CREATED_BY_REQUIRES_AUTH),
        ));
    }
    // `shared_with: 'me'` resolves to the caller's grants; no auth ⇒ no
    // caller.
    if auth.is_none() && input.shared_with.is_some() {
        return Err(fuz_http::invalid_params(
            "cell_list shared_with requires authentication",
            Some(ERROR_CELL_LIST_SHARED_WITH_REQUIRES_AUTH),
        ));
    }
    let shared_with_caller_only = input.shared_with.is_some();
    // The caller the visibility predicate binds — anonymous when there is
    // no auth, so the public arm alone admits.
    let viewer = CellViewer::new(auth);
    let limit = input.limit.unwrap_or(CELL_LIST_LIMIT_DEFAULT);
    let offset = input.offset.unwrap_or(0);
    let params = CellListParams {
        ids: input.ids.as_deref(),
        kind: input.kind.as_deref(),
        visibility: input.visibility,
        ref_hash: input.ref_hash.as_deref(),
        created_by: input.created_by,
        path_prefix: input.path_prefix.as_deref(),
        root_id: input.root_id,
        moderation: input.moderation.map(CellModeration::as_str),
        viewer,
        shared_with_caller_only,
        order_by: if input.order_by.as_deref() == Some("updated_at") {
            CellListOrderBy::UpdatedAt
        } else {
            CellListOrderBy::CreatedAt
        },
        order_dir: if input.order_direction.as_deref() == Some("asc") {
            CellListOrderDir::Asc
        } else {
            CellListOrderDir::Desc
        },
        limit,
        offset,
    };
    let rows = query_cell_list(client, &params)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let cells = rows
        .iter()
        .map(cell_to_value)
        .collect::<Result<Vec<Value>, _>>()?;
    let mut response = serde_json::Map::new();
    response.insert("cells".to_owned(), Value::Array(cells));
    // On the `shared_with: 'me'` path, enrich with the caller's own admit
    // grants per cell so the UI can label each shared row. Omitted on every
    // other path (matches the optional `cell_grants` key in the TS output).
    if shared_with_caller_only && !rows.is_empty() && auth.is_some() {
        let cell_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        let grant_rows = query_cell_grants_for_caller_in_cells(client, &cell_ids, &params.viewer)
            .await
            .map_err(|e| map_cell_error(e, false))?;
        let mut cell_grants = serde_json::Map::new();
        for g in &grant_rows {
            let entry = cell_grants
                .entry(g.cell_id.to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(arr) = entry {
                arr.push(grant_to_value(g)?);
            }
        }
        response.insert("cell_grants".to_owned(), Value::Object(cell_grants));
    }
    Ok(Value::Object(response))
}

/// Shallow-merge `patch` over `source_data` (patch-last). `kind` is not
/// in `data` — it is the top-level `cell.kind` column, copied verbatim from the
/// source by [`clone_one_cell_row`] (a clone can't re-kind) — so the only
/// `data` guard here is rejecting a stray `"kind"` key in the patch (handled by
/// the caller via [`reject_kind_in_data`] before the merge).
fn merge_clone_data(source_data: &Value, patch: Option<&Value>) -> Value {
    patch.map_or_else(
        || source_data.clone(),
        |patch| {
            let mut base = source_data.clone();
            if let (Value::Object(base_map), Value::Object(patch_map)) = (&mut base, patch) {
                for (k, v) in patch_map {
                    base_map.insert(k.clone(), v.clone());
                }
            }
            base
        },
    )
}

/// Clone one cell row: merged `data`, the source's `kind` (copied verbatim —
/// a clone can't re-kind) + `visibility`, `path` nulled (admin-only paths can't
/// auto-clone), `created_by` the caller, and zero grants. Only the root takes a
/// `patch`; children clone verbatim.
///
/// Each cloned row is a creation — a fresh, unparented cell of the source's
/// kind — so the mounted [`CellCreateAuthorize`] gates it exactly as it gates a
/// parentless `cell_create`: `Verdict::Deny` is the same 403
/// `cell_create_forbidden`, and an allow stamps no moderation (a root has no
/// container to be moderated under). So clone is no side door past the
/// creation policy: a caller denied a root `cell_create` of some kind can't
/// clone a viewable cell of that kind into one they own.
///
/// Each row then passes ref admission against **its own source row's** refs:
/// what the source already carries is cloned without holding it, and only a
/// ref the root's `patch` adds needs possession.
async fn clone_one_cell_row<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    db: &ActionDb<'_>,
    source: &CellRow,
    auth: &RequestActorContext,
    patch: Option<&Value>,
    validator: Option<&CellDataValidator>,
    authorizer: Option<&Arc<dyn CellCreateAuthorize>>,
) -> Result<CellRow, JsonrpcError> {
    let data = merge_clone_data(&source.data, patch);
    // Per-kind data-shape validation on the POST-merge data (matches TS,
    // which validates the merged clone payload). Covers the patched root and
    // verbatim-cloned children alike.
    if let Some(validate) = validator {
        validate(source.kind.as_deref(), &data)?;
    }
    // Creation-capability gate, after the shape check (the `cell_create`
    // order). The clone is parentless, so no `parent_kind` / `root_id` /
    // `root_policy`.
    if let Some(authorize) = authorizer {
        let authz_input = CellCreateAuthorizeInput {
            kind: source.kind.clone(),
            data: data.clone(),
            parent_id: None,
            parent_kind: None,
            root_id: None,
            root_policy: None,
        };
        if authorize.authorize(auth, &authz_input, db).await? == Verdict::Deny {
            return Err(fuz_http::forbidden(
                "cell creation is not permitted here",
                Some(ERROR_CELL_CREATE_FORBIDDEN),
            ));
        }
    }
    // Possession-gated ref admission against the source row's refs: a clone
    // carries what the source already serves to this viewer; a patch adding a
    // ref needs the caller to hold it.
    require_new_refs_held(client, auth, source.refs.as_deref(), &data).await?;
    // A clone is a fresh, unparented cell — the directory-tree and control
    // columns (`parent_id` / `root_id` / `moderation` / `policy`) are not
    // inherited from the source: a clone is born with no policy, so cloning a
    // root never copies its governance onto a cell the cloner owns.
    query_cell_create(
        client,
        &data,
        source.kind.as_deref(),
        Some(source.visibility),
        None,
        None,
        None,
        None,
        None,
        Some(auth.actor.id),
    )
    .await
    .map_err(|e| map_cell_error(e, false))
}

async fn handle_clone<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellCloneInput,
    validator: Option<&CellDataValidator>,
    authorizer: Option<&Arc<dyn CellCreateAuthorize>>,
) -> Result<Value, JsonrpcError> {
    // 404 covers miss + unviewable so clones can't probe private existence.
    let source = require_viewable_cell(client, auth, input.source_id).await?;
    // A `kind` inside the clone patch is rejected — kind is the immutable
    // top-level column (copied verbatim from the source), never in `data`.
    let patch = input.with_data_patch.as_ref().map(CellData::as_value);
    if let Some(patch) = patch {
        reject_kind_in_data(patch)?;
    }
    let deep = input.deep == Some(true);

    // Validate the patch and create the root before any relation copy — the
    // dispatcher wraps the whole handler in a transaction, so a later
    // failure rolls the root + its edges back together.
    let cloned_root =
        clone_one_cell_row(client, &ctx.db, &source, auth, patch, validator, authorizer).await?;

    // Outgoing fields copy shallowly — the clone points at the same targets
    // (fields are references, not contents). Strict target-visibility:
    // only copy edges whose target the caller may view, so clone isn't a
    // side door to owning edges into private cells.
    let source_fields = query_cell_field_list_for_source(
        client,
        &CellViewer::unrestricted(),
        source.id,
        None,
        None,
    )
    .await
    .map_err(|e| map_cell_error(e, false))?;
    let field_target_ids: Vec<Uuid> = source_fields.iter().map(|f| f.target_id).collect();
    let field_visible = filter_visible_targets(client, Some(auth), &field_target_ids)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    for f in &source_fields {
        if !field_visible.contains(&f.target_id) {
            continue;
        }
        query_cell_field_set(client, cloned_root.id, &f.name, f.target_id)
            .await
            .map_err(|e| map_cell_error(e, false))?;
    }

    // Items: deep clones each viewable direct child and re-attaches at the
    // source position (the clone's slot is fresh, no collision); shallow
    // copies the edge sharing both `child_id` and `position`. Either way,
    // non-viewable children are dropped silently.
    let source_items =
        query_cell_item_list_for_parent(client, &CellViewer::unrestricted(), source.id, None, None)
            .await
            .map_err(|e| map_cell_error(e, false))?;
    let child_ids: Vec<Uuid> = source_items.iter().map(|i| i.child_id).collect();
    let child_visible = filter_visible_targets(client, Some(auth), &child_ids)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    // Deep mode: bulk-load the viewable children once (not a per-child get in
    // the loop) so the walk is two reads + the irreducible per-child clone,
    // not an N+1. Shallow mode copies edges and needs no row loads.
    let viewable_children: std::collections::HashMap<Uuid, CellRow> = if deep {
        let ids: Vec<Uuid> = child_ids
            .iter()
            .copied()
            .filter(|id| child_visible.contains(id))
            .collect();
        query_cell_load_many(client, &ids)
            .await
            .map_err(|e| map_cell_error(e, false))?
            .into_iter()
            .map(|c| (c.id, c))
            .collect()
    } else {
        std::collections::HashMap::new()
    };
    // `item_count` mirrors the TS metadata: deep-cloned children (0 in shallow
    // mode, where edges are merely copied). No skipped-child count is tracked
    // — surfacing it would leak the source's hidden-child count to the cloner
    // — so non-viewable children are dropped silently.
    let mut cloned_child_count: i64 = 0;
    for item in &source_items {
        if !child_visible.contains(&item.child_id) {
            continue;
        }
        let child_id = if deep {
            // Absent => raced with a deleter between the filter and the bulk
            // load; drop silently.
            let Some(child) = viewable_children.get(&item.child_id) else {
                continue;
            };
            let cloned =
                clone_one_cell_row(client, &ctx.db, child, auth, None, validator, authorizer)
                    .await?;
            cloned_child_count += 1;
            cloned.id
        } else {
            item.child_id
        };
        query_cell_item_insert(client, cloned_root.id, &item.position, child_id)
            .await
            .map_err(|e| map_cell_error(e, false))?;
    }

    // Clone audit envelope (richer than the standard cell-mutation one):
    // `{source_id, new_id, deep, item_count, kind?}` — no skipped-child count
    // (it would leak the source's hidden-child count to the cloner).
    let mut meta = serde_json::Map::new();
    meta.insert("source_id".to_owned(), json!(source.id));
    meta.insert("new_id".to_owned(), json!(cloned_root.id));
    meta.insert("deep".to_owned(), json!(deep));
    meta.insert(
        "item_count".to_owned(),
        json!(if deep { cloned_child_count } else { 0 }),
    );
    if let Some(kind) = &source.kind {
        meta.insert("kind".to_owned(), json!(kind));
    }
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellClone,
        Value::Object(meta),
    )
    .await?;

    Ok(json!({ "cell": cell_to_value(&cloned_root)? }))
}

/// `cell_moderate` — the `pending → approved | rejected` decision and the
/// `approved → rejected` takedown, gated on moderation authority over the
/// **governing root** (not the contribution).
///
/// 404-masks a target the caller neither views nor stewards (a pending
/// contribution reaches no audience, so a stranger never learns it exists);
/// the steward arm lets a non-admin root owner through to the root check. A
/// viewable target whose caller lacks `can_manage` of the root → **403**
/// (this is where the author — who *can* view their own pending cell — is
/// denied, the anti-self-approval guard). An approved contribution its author
/// narrowed to private is not stewarded, so its root owner gets the 404 there.
/// Approval flips `moderation → approved` + `visibility → public`; rejection
/// sets `moderation → rejected` and leaves visibility alone. Any other
/// transition (approving a contribution that is not pending, rejecting one
/// already rejected or never moderated) → **400** `cell_not_pending`.
async fn handle_moderate<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellModerateInput,
) -> Result<Value, JsonrpcError> {
    // 404 covers miss + unviewable so a pending contribution doesn't leak
    // existence to a non-viewer; the governing root's manager stewards it.
    let existing = require_viewable_or_stewarded_cell(client, auth, input.cell_id).await?;
    // Only a contribution (with a governing root) is moderatable.
    let Some(root_id) = existing.root_id else {
        return Err(fuz_http::invalid_params(
            "cell is not a contribution (no governing root to moderate under)",
            Some(ERROR_CELL_NOT_A_CONTRIBUTION),
        ));
    };
    // Authority is over the governing ROOT (admin / root owner), not the
    // contribution — the author manages the contribution and could otherwise
    // self-approve. A viewable-but-unauthorized caller (incl. the author) → 403.
    let root = query_cell_get(client, root_id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let Some(root) = root else {
        return Err(cell_not_found());
    };
    if !can_manage_cell(Some(auth), &root) {
        return Err(fuz_http::forbidden(
            "cell_moderate requires moderation authority over the governing root",
            Some(ERROR_CELL_MODERATE_FORBIDDEN),
        ));
    }
    // The UPDATE carries the allowed from-states: an approval moves only a
    // pending contribution, a rejection a pending or approved one (the
    // takedown); a rejected or unmoderated one never moves.
    let updated = query_cell_set_moderation(
        client,
        input.cell_id,
        input.moderation.as_str(),
        input.moderation.approves(),
        Some(auth.actor.id),
    )
    .await
    .map_err(|e| map_cell_error(e, false))?;
    let Some(updated) = updated else {
        // No row in an allowed from-state: the transition is refused (or
        // another moderator moved it first) — or a deleter won the race (404).
        let raced = query_cell_get(client, input.cell_id)
            .await
            .map_err(|e| map_cell_error(e, false))?;
        return Err(if raced.is_some() {
            cell_not_pending()
        } else {
            cell_not_found()
        });
    };
    let mut meta = serde_json::Map::new();
    meta.insert("cell_id".to_owned(), json!(updated.id));
    meta.insert("root_id".to_owned(), json!(root_id));
    meta.insert("moderation".to_owned(), json!(input.moderation.as_str()));
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellModerate,
        Value::Object(meta),
    )
    .await?;
    Ok(json!({ "cell": cell_to_value(&updated)? }))
}

/// `cell_policy_set` — replace (or clear) a root's contribution policy,
/// manage-tier on the root.
///
/// Order: the 404 mask (a caller who can't view the cell), then the manage
/// check (**403** `cell_policy_manage_only` — an editor grant edits `data` but
/// never the policy that decides who may contribute), then root-only (**400**
/// `cell_policy_root_only`), then a non-null policy's validation through the
/// mounted authorizer (`cell_policy_unsupported` with none). Audited as
/// `cell_policy_set` with the policy written and the one it replaced.
async fn handle_policy_set<C: deadpool_postgres::GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellPolicySetInput,
    authorizer: Option<&Arc<dyn CellCreateAuthorize>>,
) -> Result<Value, JsonrpcError> {
    let existing = require_viewable_cell(client, auth, input.cell_id).await?;
    if !can_manage_cell(Some(auth), &existing) {
        return Err(fuz_http::forbidden(
            "cell.policy is manage-tier only",
            Some(ERROR_CELL_POLICY_MANAGE_ONLY),
        ));
    }
    if existing.parent_id.is_some() {
        return Err(cell_policy_root_only());
    }
    if let Some(policy) = &input.policy {
        validate_policy_write(authorizer, policy)?;
    }
    let result = query_cell_set_policy(
        client,
        input.cell_id,
        input.policy.as_ref().map(CellPolicy::as_value),
        Some(auth.actor.id),
    )
    .await
    .map_err(|e| map_cell_error(e, false))?;
    let Some(CellSetPolicyResult {
        cell: updated,
        previous_policy,
    }) = result
    else {
        // Raced with a deleter between the gates and the UPDATE.
        return Err(cell_not_found());
    };
    let mut meta = serde_json::Map::new();
    meta.insert("cell_id".to_owned(), json!(updated.id));
    meta.insert(
        "policy".to_owned(),
        updated.policy.clone().unwrap_or(Value::Null),
    );
    // read under the UPDATE's row lock, not from `existing`, which a set
    // racing past the gates may already have overwritten
    meta.insert(
        "previous_policy".to_owned(),
        previous_policy.unwrap_or(Value::Null),
    );
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellPolicySet,
        Value::Object(meta),
    )
    .await?;
    Ok(json!({ "cell": cell_to_value(&updated)? }))
}

/// Dispatch to a generic handler over whichever [`ActionDb`] variant the
/// dispatcher supplied: `handler(client, args…)`.
macro_rules! dispatch_db {
    ($ctx:expr, $handler:ident ( $($arg:expr),* $(,)? )) => {
        fuz_db::action_db_dispatch!($ctx.db, client => $handler(client, $($arg),*).await)
    };
}
pub(crate) use dispatch_db;

// -- Spec construction ------------------------------------------------------

/// The consumer's seams into [`build_cell_spec_set`].
///
/// `Default` is the open cell layer: the builtin roles only, no validator, no
/// authorizers (open create and open grant).
#[derive(Default)]
#[allow(
    missing_debug_implementations,
    reason = "Arc-of-dyn and closure fields carry no Debug"
)]
pub struct CellSpecSetOptions {
    /// The role registry `cell_grant_create` validates role-shaped principals
    /// against — the instance the auth surface is built over, so the two role
    /// vocabularies are one. Twin of the TS `roles` option.
    pub roles: Arc<RoleRegistry>,
    /// The per-kind `data` validator (`None` = pass-through).
    pub validator: Option<CellDataValidator>,
    /// The opt-in [`CellCreateAuthorize`] gating cell creation by the actor's
    /// capabilities (per cell-kind), and the validator of every root policy
    /// write; `None` = open create, and every policy write refused
    /// `cell_policy_unsupported`. Each cell a clone writes is a parentless
    /// creation it gates.
    pub create_authorizer: Option<Arc<dyn CellCreateAuthorize>>,
    /// The opt-in [`CellGrantCreateAuthorize`] the manager's
    /// `cell_grant_create` passes through; `None` = no gate past the spine's.
    pub grant_create_authorizer: Option<Arc<dyn CellGrantCreateAuthorize>>,
    /// The opt-in [`CellGrantRevokeAuthorize`] that admits a scope's steward
    /// to `cell_grant_revoke` a scoped role-shaped grant; `None` = revoke is
    /// the manager's and the self-closer's alone.
    pub grant_revoke_authorizer: Option<Arc<dyn CellGrantRevokeAuthorize>>,
}

/// Build the canonical [`ActionSpec`] set for the cell layer.
///
/// Returns the cell layer's spec set — the core verbs plus the ACL / field /
/// item / audit verbs — each with its pinned rate-limit class, ready to
/// concatenate into a consumer's [`fuz_actions::ActionRegistry`]. Reads
/// (`cell_get` / `cell_list`) are `Public` (optional auth — per-row
/// `can_view_cell` runs in the handler); writes are `Authenticated`. The
/// consumer's seams arrive on [`CellSpecSetOptions`].
#[must_use]
pub fn build_cell_spec_set(options: CellSpecSetOptions) -> Vec<ActionSpec> {
    let CellSpecSetOptions {
        roles,
        validator,
        create_authorizer: authorizer,
        grant_create_authorizer,
        grant_revoke_authorizer,
    } = options;
    let mut specs = vec![
        ActionSpec::with_side_effects(
            "cell_create",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let validator = validator.clone();
                let authorizer = authorizer.clone();
                let handler: ActionHandler = Arc::new(move |params, ctx| {
                    let validator = validator.clone();
                    let authorizer = authorizer.clone();
                    Box::pin(async move {
                        let input: CellCreateInput =
                            parse_strict_params_allowing_null(params, CELL_CREATE_NULLABLE)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(
                            ctx,
                            handle_create(
                                &ctx,
                                auth,
                                input,
                                validator.as_ref(),
                                authorizer.as_ref()
                            )
                        )
                    })
                });
                handler
            },
        )
        .with_rate_limit(RateLimitClass::Account),
        ActionSpec::read_only(
            "cell_get",
            AuthSpec::optional_identity(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellGetInput = parse_strict_params(params)?;
                        dispatch_db!(ctx, handle_get(ctx.auth.actor(), input))
                    })
                });
                handler
            },
        )
        .with_rate_limit(RateLimitClass::Ip),
        ActionSpec::with_side_effects(
            "cell_update",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let validator = validator.clone();
                let handler: ActionHandler = Arc::new(move |params, ctx| {
                    let validator = validator.clone();
                    Box::pin(async move {
                        let input: CellUpdateInput =
                            parse_strict_params_allowing_null(params, CELL_UPDATE_NULLABLE)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_update(&ctx, auth, input, validator.as_ref()))
                    })
                });
                handler
            },
        ),
        ActionSpec::with_side_effects(
            "cell_delete",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellDeleteInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_delete(&ctx, auth, input))
                    })
                });
                handler
            },
        ),
        ActionSpec::read_only(
            "cell_list",
            AuthSpec::optional_identity(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        // The wire schema is `with_default_fn(..., () => ({}))`, and
                        // `parse_strict_params` maps absent params (and a direct
                        // `Value::Null` caller) to `{}`, so this decodes to an
                        // empty filter.
                        let input: CellListInput = parse_strict_params(params)?;
                        dispatch_db!(ctx, handle_list(ctx.auth.actor(), input))
                    })
                });
                handler
            },
        )
        .with_rate_limit(RateLimitClass::Ip),
        ActionSpec::with_side_effects(
            "cell_clone",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let validator = validator.clone();
                let authorizer = authorizer.clone();
                let handler: ActionHandler = Arc::new(move |params, ctx| {
                    let validator = validator.clone();
                    let authorizer = authorizer.clone();
                    Box::pin(async move {
                        let input: CellCloneInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(
                            ctx,
                            handle_clone(
                                &ctx,
                                auth,
                                input,
                                validator.as_ref(),
                                authorizer.as_ref()
                            )
                        )
                    })
                });
                handler
            },
        )
        .with_rate_limit(RateLimitClass::Account),
        ActionSpec::with_side_effects(
            "cell_moderate",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellModerateInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_moderate(&ctx, auth, input))
                    })
                });
                handler
            },
        )
        .with_rate_limit(RateLimitClass::Account),
        ActionSpec::with_side_effects(
            "cell_policy_set",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let authorizer = authorizer.clone();
                let handler: ActionHandler = Arc::new(move |params, ctx| {
                    let authorizer = authorizer.clone();
                    Box::pin(async move {
                        let input: CellPolicySetInput =
                            parse_strict_params_allowing_null(params, CELL_POLICY_SET_NULLABLE)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(
                            ctx,
                            handle_policy_set(&ctx, auth, input, authorizer.as_ref())
                        )
                    })
                });
                handler
            },
        )
        .with_rate_limit(RateLimitClass::Account),
    ];
    // Grant / field / item / audit verbs concatenate their own spec sets.
    specs.extend(crate::cell_grant_action_specs::build_cell_grant_spec_set(
        roles,
        grant_create_authorizer,
        grant_revoke_authorizer,
    ));
    specs.extend(crate::cell_field_action_specs::build_cell_field_spec_set());
    specs.extend(crate::cell_item_action_specs::build_cell_item_spec_set());
    specs.extend(crate::cell_audit_action_specs::build_cell_audit_spec_set());
    specs
}

#[cfg(test)]
mod tests {
    use fuz_auth::RateLimitClass;

    use super::{
        CELL_KIND_LENGTH_MAX, CELL_PATH_LENGTH_MAX, CellSpecSetOptions, SAFE_INTEGER_MAX,
        build_cell_spec_set, validate_cell_kind_length, validate_cell_list_ref, validate_cell_path,
        validate_list_limit, validate_list_offset,
    };

    #[test]
    fn validate_list_limit_bounds() {
        for ok in [None, Some(1), Some(500)] {
            assert!(
                validate_list_limit(ok, 500, "cell_field_list").is_ok(),
                "{ok:?}"
            );
        }
        for (bad, method) in [
            (Some(0), "cell_field_list"),
            (Some(501), "cell_item_list"),
            (Some(-1), "cell_item_list"),
        ] {
            let error = validate_list_limit(bad, 500, method).unwrap_err();
            assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);
            // the bound and the verb go to the debug log, not the wire
            assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE, "{bad:?}");
            assert!(error.data.is_none(), "{error:?}");
        }
    }

    #[test]
    fn validate_list_offset_bounds() {
        for ok in [None, Some(0), Some(1), Some(SAFE_INTEGER_MAX)] {
            assert!(validate_list_offset(ok, "cell_list").is_ok(), "{ok:?}");
        }
        for bad in [
            Some(-1),
            Some(i64::MIN),
            Some(SAFE_INTEGER_MAX + 1),
            Some(i64::MAX),
        ] {
            let error = validate_list_offset(bad, "cell_list").unwrap_err();
            assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);
            // the bound and the verb go to the debug log, not the wire
            assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE, "{bad:?}");
            assert!(error.data.is_none(), "{error:?}");
        }
    }

    /// Every mounted cell method with the rate-limit class its TS twin
    /// declares, in registration order.
    ///
    /// The sources are `auth/cell_action_specs.ts` and its four siblings
    /// (`cell_grant_` / `cell_field_` / `cell_item_` / `cell_audit_`). A `None`
    /// row is a spec the twin declares no `rate_limit` on and is as
    /// load-bearing as a `Some` one — the dispatcher consults a bucket only
    /// when a class is declared, so an extra class throttles a method the twin
    /// does not.
    const EXPECTED_RATE_LIMITS: &[(&str, Option<RateLimitClass>)] = &[
        ("cell_create", Some(RateLimitClass::Account)),
        ("cell_get", Some(RateLimitClass::Ip)),
        ("cell_update", None),
        ("cell_delete", None),
        ("cell_list", Some(RateLimitClass::Ip)),
        ("cell_clone", Some(RateLimitClass::Account)),
        ("cell_moderate", Some(RateLimitClass::Account)),
        ("cell_policy_set", Some(RateLimitClass::Account)),
        ("cell_grant_create", None),
        ("cell_grant_revoke", None),
        ("cell_grant_list", None),
        ("cell_field_set", None),
        ("cell_field_delete", None),
        ("cell_field_list", Some(RateLimitClass::Ip)),
        ("cell_item_insert", None),
        ("cell_item_move", None),
        ("cell_item_delete", None),
        ("cell_item_list", Some(RateLimitClass::Ip)),
        ("cell_audit_list", None),
    ];

    fn spec_set() -> Vec<fuz_actions::ActionSpec> {
        build_cell_spec_set(CellSpecSetOptions::default())
    }

    #[test]
    fn rate_limit_classes_match_the_ts_twin() {
        let specs = spec_set();
        let actual: Vec<&str> = specs.iter().map(|s| s.method).collect();
        let expected: Vec<&str> = EXPECTED_RATE_LIMITS.iter().map(|(m, _)| *m).collect();
        assert_eq!(
            actual, expected,
            "EXPECTED_RATE_LIMITS must list every cell spec, in registration order"
        );
        for (method, class) in EXPECTED_RATE_LIMITS {
            let spec = specs
                .iter()
                .find(|s| s.method == *method)
                .unwrap_or_else(|| panic!("missing spec: {method}"));
            assert_eq!(spec.rate_limit, *class, "{method}: rate-limit class");
        }
    }

    /// The cell set passes every registry-time invariant, the rate-limit /
    /// account-axis one among them, without a database: a consumer that
    /// mounts it would otherwise learn of a violation only at boot.
    #[test]
    fn the_cell_spec_set_compiles_into_a_registry() {
        let registry = fuz_actions::ActionRegistry::compile(spec_set())
            .unwrap_or_else(|e| panic!("the cell spec set must compile: {e}"));
        assert_eq!(registry.len(), EXPECTED_RATE_LIMITS.len());
    }

    #[test]
    fn validate_cell_kind_length_bounds() {
        assert_eq!(CELL_KIND_LENGTH_MAX, 64);
        assert!(validate_cell_kind_length(&"a".repeat(CELL_KIND_LENGTH_MAX)).is_ok());
        let error = validate_cell_kind_length(&"a".repeat(CELL_KIND_LENGTH_MAX + 1))
            .expect_err("a kind one unit past the cap must be refused");
        assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);
        assert!(error.data.is_none(), "the refusal carries no reason");
        // empty is another check's: `cell_kind_empty` on create, no match on list
        assert!(validate_cell_kind_length("").is_ok());
        // UTF-16 code units, as `String.length` counts: an astral character costs two.
        let astral_at_max = "\u{1F600}".repeat(CELL_KIND_LENGTH_MAX / 2);
        assert_eq!(astral_at_max.encode_utf16().count(), CELL_KIND_LENGTH_MAX);
        assert!(validate_cell_kind_length(&astral_at_max).is_ok());
        assert!(validate_cell_kind_length(&format!("{astral_at_max}a")).is_err());
    }

    #[test]
    fn validate_cell_path_bounds() {
        assert!(validate_cell_path("/map/main").is_ok());
        assert!(validate_cell_path("x").is_ok());
        assert!(validate_cell_path(&"a".repeat(CELL_PATH_LENGTH_MAX)).is_ok());
        // Empty and over-cap are rejected.
        assert!(validate_cell_path("").is_err());
        assert!(validate_cell_path(&"a".repeat(CELL_PATH_LENGTH_MAX + 1)).is_err());
        // Multibyte-but-BMP: `\u{00FC}` is two UTF-8 bytes and one UTF-16
        // code unit, so a full-length run of it is at the bound, not over.
        assert!(validate_cell_path(&"\u{00FC}".repeat(CELL_PATH_LENGTH_MAX)).is_ok());
        // Astral plane: U+1F600 is one `char` but two UTF-16 code units, so
        // the twin's `String.length` counts it twice. Half the bound in emoji
        // is exactly the bound; one more is over.
        let astral_at_max = "\u{1F600}".repeat(CELL_PATH_LENGTH_MAX / 2);
        assert_eq!(astral_at_max.encode_utf16().count(), CELL_PATH_LENGTH_MAX);
        assert!(validate_cell_path(&astral_at_max).is_ok());
        let astral_over = "\u{1F600}".repeat(CELL_PATH_LENGTH_MAX / 2 + 1);
        assert_eq!(astral_over.encode_utf16().count(), CELL_PATH_LENGTH_MAX + 2);
        assert!(validate_cell_path(&astral_over).is_err());
    }

    /// The `ref` filter takes the `FactHashSchema` grammar the twin declares,
    /// so an off-grammar address is `-32602` rather than an equality test
    /// that can never match. The wire key is `ref`; `ref_hash` is the Rust
    /// field name behind serde's rename.
    #[test]
    fn cell_list_ref_takes_the_fact_hash_grammar() {
        let hex = "abcdef0123456789".repeat(4);
        assert!(validate_cell_list_ref(&format!("blake3:{hex}")).is_ok());
        for refused in [
            // Missing prefix, wrong case, wrong algorithm — the three the
            // permissive parser normalizes rather than refusing.
            String::new(),
            hex.clone(),
            format!("blake3:{}", hex.to_uppercase()),
            format!("sha256:{hex}"),
            // Digest length, either side of the bound.
            format!("blake3:{}", "a".repeat(63)),
            format!("blake3:{}", "a".repeat(65)),
            // The shapes a confused client sends: a cell id, and a probe.
            "3f8a1c2e-1234-4abc-9def-0123456789ab".to_owned(),
            "' OR 1=1--".to_owned(),
        ] {
            assert!(validate_cell_list_ref(&refused).is_err(), "{refused}");
        }
    }
}

/// The `CredentialGate` census over the cell verb surface — the `fuz_cell`
/// half of the readable-in-one-place permissive surface (`fuz_auth`'s half is
/// `action_auth::any_credential_surface`).
///
/// The whole set is `Any` today, deliberately: cells are the content primitive,
/// and a consumer's automation writing cells over an API token is the expected
/// shape, not an anomaly. This test exists so that stays a *statement* rather
/// than an omission — and so a narrowing here is visible as the twin-edit it
/// requires (every method below is in the cross-backend action manifest, so
/// changing one without the matching `fuz_app` change fails the parity gate).
#[cfg(test)]
mod any_credential_surface {
    #[test]
    fn every_cell_verb_admits_any_credential() {
        let specs = super::build_cell_spec_set(super::CellSpecSetOptions::default());
        let gated: Vec<&str> = specs
            .iter()
            .filter(|s| !s.auth.credentials.is_any())
            .map(|s| s.method)
            .collect();
        assert!(
            gated.is_empty(),
            "cell verbs are all Any by decision — narrowing {gated:?} needs a paired fuz_app edit \
             or the cross-backend action-manifest parity gate fails",
        );
    }
}
