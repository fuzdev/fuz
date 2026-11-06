//! [`crate::cell_authz::can_view_cell`] in SQL — the view predicate a query
//! applies to a cell row before `LIMIT`, so a page holds only rows the
//! caller may view.
//!
//! [`can_view_cell_sql`] is the one SQL form of the predicate: `cell_list`
//! embeds it (adding the steward arm beside it), and the relation lists
//! apply it to the cell at the other end of each edge. It binds the caller
//! through a [`CellViewer`], and the role-shaped grant arm reads the
//! `caller_role_grants` CTE [`caller_role_grants_cte`] defines. Twin of
//! `fuz_app`'s `db/cell_view_sql.ts`.

use fuz_auth::{ROLE_ADMIN, RequestActorContext};
use tokio_postgres::types::ToSql;
use uuid::Uuid;

use crate::cell_moderation::cell_moderation_admits_audience_sql;

/// The caller a view predicate binds — what
/// [`crate::cell_authz::can_view_cell`] reads off the request context.
///
/// Built from the context ([`Self::new`]) or from an actor and its grants
/// ([`Self::for_actor`]), so the role-grant arrays stay parallel — `unnest`
/// pads the shorter with NULLs, and a NULL scope reads as a global grant.
#[derive(Debug, Clone, Default)]
pub struct CellViewer<'a> {
    /// The acting actor; `None` for an anonymous caller.
    actor_id: Option<Uuid>,
    /// Whether the caller holds the global admin role — the arm that admits
    /// every cell.
    is_admin: bool,
    /// The roles of the caller's role grants, parallel to
    /// `role_grant_scope_ids`.
    role_grant_roles: Vec<&'a str>,
    /// The scopes of the caller's role grants (`None` = a global grant),
    /// parallel to `role_grant_roles`.
    role_grant_scope_ids: Vec<Option<Uuid>>,
}

impl<'a> CellViewer<'a> {
    /// The caller `auth` names — `None` is anonymous, admitted by the public
    /// arm alone.
    #[must_use]
    pub fn new(auth: Option<&'a RequestActorContext>) -> Self {
        let Some(auth) = auth else {
            return Self::default();
        };
        Self::for_actor(
            auth.actor.id,
            auth.role_grants
                .iter()
                .map(|g| (g.role.as_str(), g.scope_id)),
        )
    }

    /// The actor `actor_id` holding `grants` — its active role grants as
    /// `(role, scope_id)` pairs, `None` a global grant — for a caller known
    /// by its actor and grants rather than a request context. Admin when a
    /// global [`ROLE_ADMIN`] grant is among them, as [`Self::new`] reads it.
    #[must_use]
    pub fn for_actor(
        actor_id: Uuid,
        grants: impl IntoIterator<Item = (&'a str, Option<Uuid>)>,
    ) -> Self {
        let (role_grant_roles, role_grant_scope_ids): (Vec<&'a str>, Vec<Option<Uuid>>) =
            grants.into_iter().unzip();
        let is_admin = role_grant_roles
            .iter()
            .zip(&role_grant_scope_ids)
            .any(|(role, scope_id)| *role == ROLE_ADMIN && scope_id.is_none());
        Self {
            actor_id: Some(actor_id),
            is_admin,
            role_grant_roles,
            role_grant_scope_ids,
        }
    }

    /// A server-side read that filters nothing — the admin arm admits every
    /// cell. For a caller that applies its own view check afterwards (the
    /// `cell_get` bundle) or acts for the server itself (a seed).
    #[must_use]
    pub fn unrestricted() -> Self {
        Self {
            is_admin: true,
            ..Self::default()
        }
    }

    /// The viewer's bind values in [`CellViewerSqlParams`] order, then the
    /// [`caller_role_grants_cte`] arrays: `[is_admin, actor_id, roles,
    /// scope_ids]`.
    #[must_use]
    pub fn sql_params(&self) -> [&(dyn ToSql + Sync); 4] {
        [
            &self.is_admin,
            &self.actor_id,
            &self.role_grant_roles,
            &self.role_grant_scope_ids,
        ]
    }
}

/// Where a query binds the [`CellViewer`] facts [`can_view_cell_sql`] reads —
/// each a `$N` placeholder.
#[derive(Debug, Clone, Copy)]
pub struct CellViewerSqlParams<'a> {
    /// The global-admin flag (`bool`).
    pub is_admin: &'a str,
    /// The acting actor (`uuid`, NULL when anonymous) — the owner arm, and
    /// the actor-shaped grant arm.
    pub actor_id: &'a str,
}

/// The `caller_role_grants` CTE body (no `WITH`): the caller's
/// `(role, scope_id)` pairs, unnested once per query from the parallel
/// arrays at placeholders `roles` and `scope_ids`.
#[must_use]
pub fn caller_role_grants_cte(roles: &str, scope_ids: &str) -> String {
    format!(
        "caller_role_grants AS (
                 SELECT role, scope_id FROM unnest({roles}::text[], {scope_ids}::uuid[]) AS p(role, scope_id)
               )"
    )
}

/// The `cell_grant` admits-caller predicate over grant alias `g`.
///
/// An actor-shaped grant matches the actor at placeholder `actor_id`; a
/// role-shaped grant matches a `(role, scope_id)` pair in the
/// `caller_role_grants` CTE (a NULL grant `scope_id` matches any scope).
/// Mirrors `grant_admits` in [`crate::cell_authz`].
#[must_use]
pub fn cell_grant_admits_caller_sql(g: &str, actor_id: &str) -> String {
    format!(
        "(({actor_id}::uuid IS NOT NULL AND {g}.actor_id = {actor_id})
              OR ({g}.role IS NOT NULL AND EXISTS (
                    SELECT 1 FROM caller_role_grants p
                    WHERE p.role = {g}.role
                      AND ({g}.scope_id IS NULL OR p.scope_id IS NOT DISTINCT FROM {g}.scope_id)
                  )))"
    )
}

/// [`crate::cell_authz::can_view_cell`] over the cell alias `c`: admin, the
/// owner, or — while the cell's `moderation` admits an audience — `public`
/// or a `cell_grant` admitting the caller.
///
/// Reads the caller at `params`; the grant arm needs the
/// [`caller_role_grants_cte`] in scope. Liveness (`deleted_at IS NULL`) is
/// the query's own clause, as `can_view_cell` reads a loaded live row.
#[must_use]
pub fn can_view_cell_sql(c: &str, params: CellViewerSqlParams<'_>) -> String {
    let CellViewerSqlParams { is_admin, actor_id } = params;
    let audience_admitted = cell_moderation_admits_audience_sql(c);
    let grant_admits = cell_grant_admits_caller_sql("g", actor_id);
    format!(
        "({is_admin}::bool
                 OR ({actor_id}::uuid IS NOT NULL AND {c}.created_by = {actor_id})
                 OR ({audience_admitted} AND (
                       {c}.visibility = 'public'
                       OR ({actor_id}::uuid IS NOT NULL AND EXISTS (
                             SELECT 1 FROM cell_grant g WHERE g.cell_id = {c}.id AND {grant_admits}
                           ))
                     )))"
    )
}

#[cfg(test)]
mod tests {
    use fuz_auth::ROLE_ADMIN;
    use uuid::Uuid;

    use super::CellViewer;

    #[test]
    fn for_actor_reads_admin_off_a_global_admin_grant_only() {
        let actor = Uuid::from_u128(1);
        let scope = Uuid::from_u128(2);
        assert!(CellViewer::for_actor(actor, [(ROLE_ADMIN, None)]).is_admin);
        assert!(!CellViewer::for_actor(actor, [(ROLE_ADMIN, Some(scope))]).is_admin);
        assert!(!CellViewer::for_actor(actor, [("member", None)]).is_admin);
        assert!(!CellViewer::for_actor(actor, []).is_admin);
    }

    #[test]
    fn for_actor_keeps_the_grant_pairs_parallel() {
        let actor = Uuid::from_u128(1);
        let scope = Uuid::from_u128(2);
        let viewer = CellViewer::for_actor(actor, [("member", Some(scope)), ("other", None)]);
        assert_eq!(viewer.actor_id, Some(actor));
        assert_eq!(viewer.role_grant_roles, ["member", "other"]);
        assert_eq!(viewer.role_grant_scope_ids, [Some(scope), None]);
    }
}
