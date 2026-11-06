//! Cell view / edit / manage authorization — pure predicates over
//! `(auth, cell, grants)`.
//!
//! Mirrors `fuz_app`'s `auth/cell_authorize.ts` three tiers. The caller
//! loads the cell's `cell_grant` rows out-of-band (via
//! [`crate::cell_grant_queries::query_cell_grant_list_for_cell`]) and
//! passes them to the view / edit predicates; `None` skips the grant
//! branch (unauthenticated callers, or callers that know no grant could
//! admit).
//!
//! - [`can_view_cell`] — admin / owner / public / any `viewer`+ grant, the
//!   public and grant arms only while the cell's `moderation` admits an
//!   audience ([`crate::cell_moderation`]: unmoderated or `approved`).
//! - [`can_edit_cell`] — admin / owner / `editor` grant, the grant arm only
//!   while the cell's `moderation` admits an audience. NULL `created_by`
//!   is admin-only (system-origin defense-in-depth) — grants do NOT bypass
//!   that guard.
//! - [`can_manage_cell`] — admin / owner only. Not delegable, not a grant
//!   level. Gates `visibility` writes + all grant management. Grants are
//!   not consulted.
//! - [`can_steward_cell`] — the governing root's manager reading a pending or
//!   rejected contribution under it. A separate read arm beside
//!   [`can_view_cell`], composed only at the surfaces a moderator works from
//!   ([`crate::cell_steward`] names them).
//!
//! The admin bypass on every tier is the **global** `admin` grant
//! (`has_scoped_role(ROLE_ADMIN, None)`): a scoped `admin` row — which no
//! grant path mints, builtin roles being global-only — confers nothing.
//!
//! Grant-admit: actor-shaped grants match `auth.actor.id`; role-shaped
//! grants match a held `role_grant` with the same role and either a matching
//! `scope_id` or `scope_id IS NULL` (any scope). `RequestActorContext`'s
//! `role_grants` are already active-filtered at load, so no expiry recheck
//! is needed here (the TS mirror rechecks belt-and-suspenders).
//!
//! Unauthenticated callers pass `None` for `auth`; only the `public`
//! branch admits them (view) — edit / manage are always denied.
//!
//! Moderation gates the audience: a cell's effective audience is its
//! visibility or grants **and** its admission, so a pending, rejected, or
//! unknown-marker contribution is readable through [`can_view_cell`] by its
//! owner and a global admin alone, whatever its `visibility` or grants say.
//! The `editor` grant arm of [`can_edit_cell`] follows the same admission;
//! the owner, admin, and manage arms don't consult it.

use fuz_auth::{ROLE_ADMIN, RequestActorContext};

use crate::cell_grant_schema::{CellGrantLevel, CellGrantRow};
use crate::cell_moderation::{cell_moderation_admits_audience, cell_moderation_is_stewardable};
use crate::cell_schema::{CellRow, CellViewFacts, CellVisibility};

/// Whether `auth` owns `cell` — the implicit manage tier below admin.
///
/// Owner is the `cell.created_by` actor. NULL `created_by` (system
/// origin) is never owned; the explicit guard keeps that a load-bearing
/// property rather than relying on equality against a missing value.
fn is_owner<T: CellViewFacts + ?Sized>(auth: &RequestActorContext, cell: &T) -> bool {
    cell.created_by() == Some(auth.actor.id)
}

/// Whether any grant in `grants` admits `auth` at `required_level`.
///
/// `None` short-circuits to false (caller skipped the load — no grant
/// could admit). Actor-shaped grants match the resolved actor; role-shaped
/// grants match a held `role_grant` with the same role and either a matching
/// `scope_id` or a NULL (any-scope) grant `scope_id`. `required_level ==
/// Editor` filters out viewer-level grants up front.
fn grant_admits(
    auth: &RequestActorContext,
    grants: Option<&[CellGrantRow]>,
    required_level: CellGrantLevel,
) -> bool {
    let Some(grants) = grants else { return false };
    for g in grants {
        if required_level == CellGrantLevel::Editor && g.level != CellGrantLevel::Editor {
            continue;
        }
        if let Some(actor_id) = g.actor_id {
            if actor_id == auth.actor.id {
                return true;
            }
            continue;
        }
        // Role-shaped: the table CHECK guarantees `role IS NOT NULL` here.
        if let Some(role) = &g.role
            && auth
                .role_grants
                .iter()
                .any(|p| &p.role == role && (g.scope_id.is_none() || p.scope_id == g.scope_id))
        {
            return true;
        }
    }
    false
}

/// View authorization: admin, the owner, a `public` cell (incl.
/// unauthenticated callers), or any `viewer`+ grant.
///
/// The public and grant arms also require the cell's `moderation` to admit
/// an audience ([`cell_moderation_admits_audience`]) — a pending or rejected
/// contribution stays with its owner and admins even when public or
/// granted. The admin and owner arms don't consult it.
///
/// Reads only the [`CellViewFacts`], so a full [`CellRow`] and the narrow
/// [`crate::cell_schema::CellViewRow`] both answer it.
#[must_use]
pub fn can_view_cell<T: CellViewFacts + ?Sized>(
    auth: Option<&RequestActorContext>,
    cell: &T,
    grants: Option<&[CellGrantRow]>,
) -> bool {
    if let Some(auth) = auth
        && auth.has_scoped_role(ROLE_ADMIN, None)
    {
        return true;
    }
    if auth.is_some_and(|auth| is_owner(auth, cell)) {
        return true;
    }
    if !cell_moderation_admits_audience(cell.moderation()) {
        return false;
    }
    if cell.visibility() == CellVisibility::Public {
        return true;
    }
    let Some(auth) = auth else { return false };
    grant_admits(auth, grants, CellGrantLevel::Viewer)
}

/// Edit authorization: admin, owner, or an `editor` grant. Unauthenticated
/// callers can never edit. NULL `created_by` is admin-only — `editor`
/// grants do NOT bypass that guard.
///
/// The grant arm requires the cell's `moderation` to admit an audience
/// ([`cell_moderation_admits_audience`]), as in [`can_view_cell`]: a grant
/// made while a contribution was approved stops admitting once it is
/// rejected, for writes as for reads (every write verb echoes or reveals the
/// row it touched).
#[must_use]
pub fn can_edit_cell(
    auth: Option<&RequestActorContext>,
    cell: &CellRow,
    grants: Option<&[CellGrantRow]>,
) -> bool {
    let Some(auth) = auth else { return false };
    if auth.has_scoped_role(ROLE_ADMIN, None) {
        return true;
    }
    // Explicit: NULL `created_by` (system origin) is admin-only — grants
    // never admit edit on a system cell.
    if cell.created_by.is_none() {
        return false;
    }
    is_owner(auth, cell)
        || (cell_moderation_admits_audience(cell.moderation.as_deref())
            && grant_admits(auth, grants, CellGrantLevel::Editor))
}

/// Steward authorization: whether `auth` manages `root` — the governing root
/// of `cell` — and `cell` is a pending or rejected contribution under it.
///
/// The moderator's read of a contribution its audience can't see: true when
/// `cell.root_id` is `root`, `cell.moderation` is exactly `pending` or
/// `rejected` ([`cell_moderation_is_stewardable`]), `root` is not soft-deleted,
/// and [`can_manage_cell`] admits `auth` on `root` (global admin or the
/// root's owner — no grant tier confers manage). Unauthenticated callers are
/// never stewards. An approved contribution later narrowed to private is not
/// stewarded — it reads like any cell its author narrowed.
///
/// Not part of [`can_view_cell`]: the steward arm admits only where a
/// moderator works ([`crate::cell_steward`] names the sites), so the relation
/// gates, clone, contribution parents, and the grant paths keep the narrower
/// predicate.
#[must_use]
pub fn can_steward_cell(
    auth: Option<&RequestActorContext>,
    cell: &CellRow,
    root: &CellRow,
) -> bool {
    auth.is_some()
        && cell.root_id == Some(root.id)
        && cell_moderation_is_stewardable(cell.moderation.as_deref())
        && root.deleted_at.is_none()
        && can_manage_cell(auth, root)
}

/// Manage authorization: admin or owner. Gates `visibility` writes, all
/// grant management, and the per-cell audit timeline. Not delegable, not a
/// grant level.
#[must_use]
pub fn can_manage_cell(auth: Option<&RequestActorContext>, cell: &CellRow) -> bool {
    let Some(auth) = auth else { return false };
    if auth.has_scoped_role(ROLE_ADMIN, None) {
        return true;
    }
    is_owner(auth, cell)
}

#[cfg(test)]
mod tests {
    use fuz_auth::{AccountRow, ActorRow, RequestActorContext};
    use serde_json::json;
    use uuid::Uuid;

    use super::{can_edit_cell, can_manage_cell, can_steward_cell, can_view_cell};
    use crate::cell_grant_schema::{CellGrantLevel, CellGrantRow};
    use crate::cell_schema::{CellRow, CellVisibility};

    /// Build a `RequestActorContext` with the given actor id and global
    /// (unscoped) role grants.
    fn actor_ctx(actor_id: Uuid, roles: &[&str]) -> RequestActorContext {
        let account_id = Uuid::new_v4();
        RequestActorContext {
            account: AccountRow {
                id: account_id,
                username: "u".to_owned(),
            },
            actor: ActorRow {
                id: actor_id,
                account_id,
                name: "a".to_owned(),
            },
            role_grants: roles
                .iter()
                .map(|r| fuz_auth::RoleGrantRow {
                    id: Uuid::new_v4(),
                    actor_id,
                    role: (*r).to_owned(),
                    scope_id: None,
                })
                .collect(),
        }
    }

    /// An actor-shaped grant row at `level` admitting `actor_id`.
    fn actor_grant(cell_id: Uuid, actor_id: Uuid, level: CellGrantLevel) -> CellGrantRow {
        CellGrantRow {
            id: Uuid::new_v4(),
            cell_id,
            level,
            actor_id: Some(actor_id),
            role: None,
            scope_id: None,
            granted_by: None,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    /// A role-shaped grant row at `level` for `(role, scope_id?)`.
    fn role_grant_row(
        cell_id: Uuid,
        role: &str,
        scope_id: Option<Uuid>,
        level: CellGrantLevel,
    ) -> CellGrantRow {
        CellGrantRow {
            id: Uuid::new_v4(),
            cell_id,
            level,
            actor_id: None,
            role: Some(role.to_owned()),
            scope_id,
            granted_by: None,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    fn cell(visibility: CellVisibility, created_by: Option<Uuid>) -> CellRow {
        CellRow {
            id: Uuid::new_v4(),
            data: json!({}),
            kind: Some("note".to_owned()),
            visibility,
            path: None,
            refs: None,
            parent_id: None,
            root_id: None,
            moderation: None,
            policy: None,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: None,
            deleted_at: None,
            created_by,
            updated_by: None,
            grant_count: 0,
        }
    }

    #[test]
    fn anonymous_views_only_public() {
        let owner = Uuid::new_v4();
        assert!(can_view_cell(
            None,
            &cell(CellVisibility::Public, Some(owner)),
            None
        ));
        assert!(!can_view_cell(
            None,
            &cell(CellVisibility::Private, Some(owner)),
            None
        ));
        // Anonymous never edits / manages.
        assert!(!can_edit_cell(
            None,
            &cell(CellVisibility::Public, Some(owner)),
            None
        ));
        assert!(!can_manage_cell(
            None,
            &cell(CellVisibility::Public, Some(owner))
        ));
    }

    #[test]
    fn owner_views_edits_manages_own_private_cell() {
        let owner = Uuid::new_v4();
        let ctx = actor_ctx(owner, &[]);
        let c = cell(CellVisibility::Private, Some(owner));
        assert!(can_view_cell(Some(&ctx), &c, None));
        assert!(can_edit_cell(Some(&ctx), &c, None));
        assert!(can_manage_cell(Some(&ctx), &c));
    }

    #[test]
    fn non_owner_authed_caller_cannot_edit_public_cell() {
        let owner = Uuid::new_v4();
        let stranger = actor_ctx(Uuid::new_v4(), &[]);
        let c = cell(CellVisibility::Public, Some(owner));
        // Can view (public) but not edit / manage (not owner, not admin).
        assert!(can_view_cell(Some(&stranger), &c, None));
        assert!(!can_edit_cell(Some(&stranger), &c, None));
        assert!(!can_manage_cell(Some(&stranger), &c));
    }

    #[test]
    fn admin_views_edits_manages_any_cell() {
        let admin = actor_ctx(Uuid::new_v4(), &[fuz_auth::ROLE_ADMIN]);
        let c = cell(CellVisibility::Private, Some(Uuid::new_v4()));
        assert!(can_view_cell(Some(&admin), &c, None));
        assert!(can_edit_cell(Some(&admin), &c, None));
        assert!(can_manage_cell(Some(&admin), &c));
    }

    /// The admin bypass is the **global** grant: a scoped `admin` row (legacy
    /// data — no grant path mints one) views, edits, and manages nothing it
    /// couldn't without it.
    #[test]
    fn scoped_admin_gets_no_admin_bypass() {
        let mut scoped_admin = actor_ctx(Uuid::new_v4(), &[]);
        let owner = Uuid::new_v4();
        let private = cell(CellVisibility::Private, Some(owner));
        scoped_admin.role_grants.push(fuz_auth::RoleGrantRow {
            id: Uuid::new_v4(),
            actor_id: scoped_admin.actor.id,
            role: fuz_auth::ROLE_ADMIN.to_owned(),
            scope_id: Some(private.id),
        });
        assert!(!can_view_cell(Some(&scoped_admin), &private, None));
        assert!(!can_edit_cell(Some(&scoped_admin), &private, None));
        assert!(!can_manage_cell(Some(&scoped_admin), &private));
        // The system-origin guard holds too: a NULL `created_by` cell stays
        // global-admin-only for edit.
        let system = cell(CellVisibility::Public, None);
        assert!(!can_edit_cell(Some(&scoped_admin), &system, None));
    }

    #[test]
    fn system_origin_null_created_by_is_admin_only_for_edit() {
        let someone = actor_ctx(Uuid::new_v4(), &[]);
        let admin = actor_ctx(Uuid::new_v4(), &[fuz_auth::ROLE_ADMIN]);
        let c = cell(CellVisibility::Public, None);
        // Public ⇒ anyone views; but NULL created_by edits are admin-only.
        assert!(can_view_cell(Some(&someone), &c, None));
        assert!(!can_edit_cell(Some(&someone), &c, None));
        assert!(!can_manage_cell(Some(&someone), &c));
        assert!(can_edit_cell(Some(&admin), &c, None));
    }

    #[test]
    fn actor_viewer_grant_admits_view_only() {
        let viewer = actor_ctx(Uuid::new_v4(), &[]);
        let c = cell(CellVisibility::Private, Some(Uuid::new_v4()));
        let grants = [actor_grant(c.id, viewer.actor.id, CellGrantLevel::Viewer)];
        // Viewer grant admits view but never edit; never manage (grant-free).
        assert!(can_view_cell(Some(&viewer), &c, Some(&grants)));
        assert!(!can_edit_cell(Some(&viewer), &c, Some(&grants)));
        assert!(!can_manage_cell(Some(&viewer), &c));
        // Without the grant list (None), the same caller is denied.
        assert!(!can_view_cell(Some(&viewer), &c, None));
    }

    #[test]
    fn actor_editor_grant_admits_view_and_edit_not_manage() {
        let editor = actor_ctx(Uuid::new_v4(), &[]);
        let c = cell(CellVisibility::Private, Some(Uuid::new_v4()));
        let grants = [actor_grant(c.id, editor.actor.id, CellGrantLevel::Editor)];
        assert!(can_view_cell(Some(&editor), &c, Some(&grants)));
        assert!(can_edit_cell(Some(&editor), &c, Some(&grants)));
        // Editor grant is NOT the manage tier — visibility / grant writes stay closed.
        assert!(!can_manage_cell(Some(&editor), &c));
    }

    #[test]
    fn editor_grant_does_not_bypass_system_origin_guard() {
        let editor = actor_ctx(Uuid::new_v4(), &[]);
        let c = cell(CellVisibility::Private, None); // system origin
        let grants = [actor_grant(c.id, editor.actor.id, CellGrantLevel::Editor)];
        // Edit is admin-only on NULL created_by — the editor grant can't admit it.
        assert!(!can_edit_cell(Some(&editor), &c, Some(&grants)));
        // It still admits view (the system guard is edit/manage-specific).
        assert!(can_view_cell(Some(&editor), &c, Some(&grants)));
    }

    #[test]
    fn role_grant_admits_by_role_and_scope() {
        let scope = Uuid::new_v4();
        let teacher = actor_ctx(Uuid::new_v4(), &[]);
        // Give the actor a scoped `teacher` role_grant matching the grant scope.
        let mut scoped = teacher;
        scoped.role_grants.push(fuz_auth::RoleGrantRow {
            id: Uuid::new_v4(),
            actor_id: scoped.actor.id,
            role: "teacher".to_owned(),
            scope_id: Some(scope),
        });
        let c = cell(CellVisibility::Private, Some(Uuid::new_v4()));

        // Exact-scope role grant admits.
        let scoped_grant = [role_grant_row(
            c.id,
            "teacher",
            Some(scope),
            CellGrantLevel::Viewer,
        )];
        assert!(can_view_cell(Some(&scoped), &c, Some(&scoped_grant)));

        // Any-scope (NULL) role grant admits any holder of the role.
        let any_scope = [role_grant_row(
            c.id,
            "teacher",
            None,
            CellGrantLevel::Viewer,
        )];
        assert!(can_view_cell(Some(&scoped), &c, Some(&any_scope)));

        // A different scope does NOT admit.
        let other = [role_grant_row(
            c.id,
            "teacher",
            Some(Uuid::new_v4()),
            CellGrantLevel::Viewer,
        )];
        assert!(!can_view_cell(Some(&scoped), &c, Some(&other)));

        // A role the actor doesn't hold does NOT admit.
        let unheld = [role_grant_row(
            c.id,
            "principal",
            None,
            CellGrantLevel::Viewer,
        )];
        assert!(!can_view_cell(Some(&scoped), &c, Some(&unheld)));
    }

    /// The moderation states the read arms are tabled over: `None`
    /// (unmoderated), the three literals, and a marker no rule names.
    const MODERATIONS: [Option<&str>; 5] = [
        None,
        Some("approved"),
        Some("pending"),
        Some("rejected"),
        Some("unknown"),
    ];

    fn admits_audience(moderation: Option<&str>) -> bool {
        matches!(moderation, None | Some("approved"))
    }

    /// The read invariant: a cell's effective audience is its visibility or
    /// grants **and** its moderation admission. Public and grant arms are
    /// gated on admission (an allowlist — an unknown marker admits nothing);
    /// the owner and global-admin arms are not.
    #[test]
    fn moderation_gates_the_public_and_grant_read_arms() {
        let owner = Uuid::new_v4();
        let owner_ctx = actor_ctx(owner, &[]);
        let admin = actor_ctx(Uuid::new_v4(), &[fuz_auth::ROLE_ADMIN]);
        let stranger = actor_ctx(Uuid::new_v4(), &[]);
        let holder = actor_ctx(Uuid::new_v4(), &[]);
        let mut role_holder = actor_ctx(Uuid::new_v4(), &[]);
        role_holder.role_grants.push(fuz_auth::RoleGrantRow {
            id: Uuid::new_v4(),
            actor_id: role_holder.actor.id,
            role: "member".to_owned(),
            scope_id: None,
        });
        for moderation in MODERATIONS {
            let admitted = admits_audience(moderation);
            for visibility in [CellVisibility::Public, CellVisibility::Private] {
                let mut c = cell(visibility, Some(owner));
                c.moderation = moderation.map(str::to_owned);
                let grants = [
                    actor_grant(c.id, holder.actor.id, CellGrantLevel::Viewer),
                    role_grant_row(c.id, "member", None, CellGrantLevel::Editor),
                ];
                let public = visibility == CellVisibility::Public;
                let label = format!("{moderation:?} {visibility:?}");
                assert_eq!(
                    can_view_cell(None, &c, None),
                    public && admitted,
                    "anon {label}"
                );
                assert_eq!(
                    can_view_cell(Some(&stranger), &c, Some(&grants)),
                    public && admitted,
                    "stranger {label}"
                );
                assert!(can_view_cell(Some(&owner_ctx), &c, None), "owner {label}");
                assert!(can_view_cell(Some(&admin), &c, None), "admin {label}");
                assert_eq!(
                    can_view_cell(Some(&holder), &c, Some(&grants)),
                    admitted,
                    "actor grant holder {label}"
                );
                assert_eq!(
                    can_view_cell(Some(&role_holder), &c, Some(&grants)),
                    admitted,
                    "role grant holder {label}"
                );
                assert_eq!(
                    can_edit_cell(Some(&role_holder), &c, Some(&grants)),
                    admitted,
                    "role editor grant holder edits {label}"
                );
                assert!(
                    can_edit_cell(Some(&owner_ctx), &c, None),
                    "owner edits {label}"
                );
            }
        }
    }

    /// The steward arm: the governing root's manager (global admin or the
    /// root's owner) reads a pending or rejected contribution under that root,
    /// and nobody else gains anything from it. Tabled beside `can_view_cell`
    /// over every moderation state and viewer.
    #[test]
    fn steward_arm_admits_the_root_manager_on_pending_and_rejected_only() {
        let author = Uuid::new_v4();
        let root_owner = Uuid::new_v4();
        let author_ctx = actor_ctx(author, &[]);
        let root_owner_ctx = actor_ctx(root_owner, &[]);
        let admin = actor_ctx(Uuid::new_v4(), &[fuz_auth::ROLE_ADMIN]);
        let stranger = actor_ctx(Uuid::new_v4(), &[]);
        let holder = actor_ctx(Uuid::new_v4(), &[]);
        let root = cell(CellVisibility::Public, Some(root_owner));
        for moderation in MODERATIONS {
            let stewardable = matches!(moderation, Some("pending" | "rejected"));
            let admitted = admits_audience(moderation);
            let mut c = cell(CellVisibility::Private, Some(author));
            c.root_id = Some(root.id);
            c.parent_id = Some(root.id);
            c.moderation = moderation.map(str::to_owned);
            let grants = [actor_grant(c.id, holder.actor.id, CellGrantLevel::Viewer)];
            let label = format!("{moderation:?}");

            assert!(!can_steward_cell(None, &c, &root), "anon {label}");
            assert!(!can_view_cell(None, &c, None), "anon view {label}");
            assert_eq!(
                can_steward_cell(Some(&root_owner_ctx), &c, &root),
                stewardable,
                "root owner {label}"
            );
            assert!(
                !can_view_cell(Some(&root_owner_ctx), &c, None),
                "the root owner gains no view arm {label}"
            );
            assert_eq!(
                can_steward_cell(Some(&admin), &c, &root),
                stewardable,
                "admin {label}"
            );
            assert!(can_view_cell(Some(&admin), &c, None), "admin views {label}");
            // The author owns the contribution, not the root: they read it
            // through the owner arm, never the steward arm.
            assert!(
                !can_steward_cell(Some(&author_ctx), &c, &root),
                "author {label}"
            );
            assert!(
                can_view_cell(Some(&author_ctx), &c, None),
                "author views {label}"
            );
            assert!(
                !can_steward_cell(Some(&stranger), &c, &root),
                "stranger {label}"
            );
            assert!(
                !can_view_cell(Some(&stranger), &c, None),
                "stranger view {label}"
            );
            assert!(
                !can_steward_cell(Some(&holder), &c, &root),
                "grant holder {label}"
            );
            assert_eq!(
                can_view_cell(Some(&holder), &c, Some(&grants)),
                admitted,
                "grant holder view {label}"
            );
        }
    }

    /// The steward arm needs the cell's own governing root, live.
    #[test]
    fn steward_arm_needs_the_live_governing_root() {
        let root_owner = actor_ctx(Uuid::new_v4(), &[]);
        let root = cell(CellVisibility::Public, Some(root_owner.actor.id));
        let mut c = cell(CellVisibility::Private, Some(Uuid::new_v4()));
        c.root_id = Some(root.id);
        c.moderation = Some("pending".to_owned());
        assert!(can_steward_cell(Some(&root_owner), &c, &root), "control");

        let mut deleted = root.clone();
        deleted.deleted_at = Some("2026-01-02T00:00:00Z".to_owned());
        assert!(
            !can_steward_cell(Some(&root_owner), &c, &deleted),
            "a tombstoned root"
        );

        let other_root = cell(CellVisibility::Public, Some(root_owner.actor.id));
        assert!(
            !can_steward_cell(Some(&root_owner), &c, &other_root),
            "a root the cell doesn't belong to"
        );

        let mut parentless = c;
        parentless.root_id = None;
        assert!(
            !can_steward_cell(Some(&root_owner), &parentless, &root),
            "a root itself"
        );
    }

    #[test]
    fn role_editor_grant_admits_edit_but_viewer_role_grant_does_not() {
        // The orthogonal axis the existing role test misses: a role-SHAPED grant
        // at the EDIT tier. Every other `can_edit_cell` test uses actor-shaped
        // grants. Role grants are broad-blast-radius — one row admits every
        // holder of the role — so an over-admit here (a viewer-level role grant
        // wrongly admitting edit, or a scope-mismatch admitting edit) is a
        // privilege-escalation bug.
        let scope = Uuid::new_v4();
        let mut teacher = actor_ctx(Uuid::new_v4(), &[]);
        teacher.role_grants.push(fuz_auth::RoleGrantRow {
            id: Uuid::new_v4(),
            actor_id: teacher.actor.id,
            role: "teacher".to_owned(),
            scope_id: Some(scope),
        });
        let c = cell(CellVisibility::Private, Some(Uuid::new_v4()));

        // A scope-matched EDITOR-level role grant admits edit.
        let editor_grant = [role_grant_row(
            c.id,
            "teacher",
            Some(scope),
            CellGrantLevel::Editor,
        )];
        assert!(can_edit_cell(Some(&teacher), &c, Some(&editor_grant)));

        // A VIEWER-level role grant must NOT admit edit (the editor-tier filter).
        let viewer_grant = [role_grant_row(
            c.id,
            "teacher",
            Some(scope),
            CellGrantLevel::Viewer,
        )];
        assert!(!can_edit_cell(Some(&teacher), &c, Some(&viewer_grant)));

        // A different scope must NOT admit edit even at the editor tier.
        let wrong_scope = [role_grant_row(
            c.id,
            "teacher",
            Some(Uuid::new_v4()),
            CellGrantLevel::Editor,
        )];
        assert!(!can_edit_cell(Some(&teacher), &c, Some(&wrong_scope)));
    }
}
