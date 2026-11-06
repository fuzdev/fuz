//! Strict relation-read visibility filter.
//!
//! Forward relation reads must not surface edges whose target the caller
//! cannot view — otherwise an editor of a public parent could enumerate
//! private children by id, or a public cell could leak the existence of
//! private linked cells. The `cell_get` bundle and the clone walk filter the
//! edges they read through this helper; the `cell_field_list` /
//! `cell_item_list` pages apply the same predicate in SQL instead
//! ([`crate::cell_view_sql`]), before their limit.
//!
//! This helper bulk-loads the candidate cells' view facts
//! ([`crate::cell_queries::CELL_VIEW_COLUMNS`] — never the `data` payload)
//! and their grants, then runs [`crate::cell_authz::can_view_cell`] per cell
//! in memory, returning the set of viewable ids. Two queries for the whole
//! id-set (avoids the N+1 a per-row check would cause). Mirrors `fuz_app`'s
//! `auth/cell_relation_visibility.ts`.

use std::collections::{HashMap, HashSet};

use deadpool_postgres::GenericClient;
use fuz_auth::RequestActorContext;
use uuid::Uuid;

use crate::cell_authz::can_view_cell;
use crate::cell_grant_queries::query_cell_grant_list_for_cells;
use crate::cell_grant_schema::CellGrantRow;
use crate::cell_queries::query_cell_view_load_many;
use crate::error::CellError;

/// Return the subset of `ids` the caller may view.
///
/// Soft-deleted targets and ids with no matching cell are absent from the
/// result (treated as not-viewable). Grants are loaded only for
/// authenticated callers — `None` auth admits solely via the public branch
/// of `can_view_cell`, so the grant load is skipped entirely. Duplicate
/// ids are harmless (deduped before the load).
///
/// # Errors
///
/// [`CellError`] on driver / decode failure of the bulk loads.
pub async fn filter_visible_targets<C: GenericClient + ?Sized>(
    client: &C,
    auth: Option<&RequestActorContext>,
    ids: &[Uuid],
) -> Result<HashSet<Uuid>, CellError> {
    let mut visible = HashSet::new();
    if ids.is_empty() {
        return Ok(visible);
    }
    let unique: Vec<Uuid> = {
        let mut seen = HashSet::new();
        ids.iter().copied().filter(|id| seen.insert(*id)).collect()
    };
    let cells = query_cell_view_load_many(client, &unique).await?;
    // Grants only matter for authenticated callers — null auth admits via
    // the public branch alone, so skip the grant load entirely.
    let mut grants_by_cell: HashMap<Uuid, Vec<CellGrantRow>> = HashMap::new();
    if auth.is_some() {
        let grant_rows = query_cell_grant_list_for_cells(client, &unique).await?;
        for g in grant_rows {
            grants_by_cell.entry(g.cell_id).or_default().push(g);
        }
    }
    for cell in &cells {
        let grants = if auth.is_some() {
            Some(grants_by_cell.get(&cell.id).map_or(&[][..], Vec::as_slice))
        } else {
            None
        };
        if can_view_cell(auth, cell, grants) {
            visible.insert(cell.id);
        }
    }
    Ok(visible)
}
