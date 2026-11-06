//! The steward read arm, with the governing-root load it needs.
//!
//! [`crate::can_steward_cell`] is pure over `(auth, cell, root)`;
//! [`cell_steward_admits`] is the composition every steward site runs after
//! [`crate::can_view_cell`] denies: it loads the governing root (active rows
//! only, so a soft-deleted root stewards nothing) and applies the predicate.
//! It short-circuits with no query unless the caller is authenticated and the
//! cell is a pending or rejected contribution.
//!
//! **Where the steward arm applies** — the surfaces a moderator works from:
//! `cell_get`, `cell_moderate` (whose root-authority check it lets a non-admin
//! root owner reach), the cell-scoped fact route, and `cell_list`'s general
//! predicate (the SQL twin in [`crate::cell_queries::query_cell_list`]).
//!
//! **Where it must not** — every other read keeps [`crate::can_view_cell`]
//! alone: `cell_clone` (a steward copying a contribution out from under its
//! moderation), the parent check on `cell_create` (a steward contributing
//! under a pending post), the relation endpoint gates,
//! [`crate::filter_visible_targets`] (the `cell_get` bundle), the field / item
//! lists' SQL view filter ([`crate::cell_view_sql`]), `cell_list`'s
//! `shared_with` semi-join (a grant footprint, not a moderation queue), and
//! `cell_grant_revoke`'s `still_admitted` recompute. Widening one of these is
//! a decision, not a sweep. Twin of `fuz_app`'s `auth/cell_steward.ts`.

use deadpool_postgres::GenericClient;
use fuz_auth::RequestActorContext;

use crate::cell_authz::can_steward_cell;
use crate::cell_moderation::cell_moderation_is_stewardable;
use crate::cell_queries::query_cell_get;
use crate::cell_schema::CellRow;
use crate::error::CellError;

/// Whether `auth` stewards `cell` — loads the governing root and applies
/// [`can_steward_cell`].
///
/// Returns `false` without a query for an unauthenticated caller, a root, or
/// a cell whose moderation isn't `pending` / `rejected`; a missing or
/// soft-deleted root is `false` too.
///
/// # Errors
///
/// [`CellError`] on driver / decode failure of the root load.
pub async fn cell_steward_admits<C: GenericClient + ?Sized>(
    client: &C,
    auth: Option<&RequestActorContext>,
    cell: &CellRow,
) -> Result<bool, CellError> {
    let Some(root_id) = cell.root_id else {
        return Ok(false);
    };
    if auth.is_none() || !cell_moderation_is_stewardable(cell.moderation.as_deref()) {
        return Ok(false);
    }
    let Some(root) = query_cell_get(client, root_id).await? else {
        return Ok(false);
    };
    Ok(can_steward_cell(auth, cell, &root))
}
