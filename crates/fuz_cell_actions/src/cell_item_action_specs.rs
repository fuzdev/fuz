//! Cell-item RPC handlers + [`build_cell_item_spec_set`].
//!
//! Four verbs (`cell_item_insert` / `cell_item_move` / `cell_item_delete` /
//! `cell_item_list`) bound to canonical [`ActionSpec`]s, concatenated into
//! the cell spec set by `build_cell_spec_set`.
//!
//! - `insert` — admin / owner / editor-grant on `parent` may insert;
//!   `child` must be view-admitted. `cell_item_position_taken` on a
//!   `(parent_id, position)` unique violation.
//! - `move` — admin / owner / editor-grant on `parent`. Same collision
//!   shape; 404 when the source slot raced with a deleter.
//! - `delete` — admin / owner / editor-grant on `parent`. Idempotent.
//! - `list` — bidirectional, either direction a page of up to `limit`
//!   ([`CELL_RELATION_LIST_LIMIT_DEFAULT`] when omitted) items whose other
//!   end the caller may view — the view predicate runs in SQL, before the
//!   limit. Forward (`parent_id`) gates on `can_view_cell(parent)`, then pages
//!   the items whose child is viewable (strict target-visibility). Reverse
//!   (`child_id`) gates on `can_view_cell(child)`, then pages the items whose
//!   parent is viewable.
//!
//! All paths 404-mask on cell-miss / tier-denial — every cell gate here is
//! one of `cell_action_specs`' shared tier helpers
//! (`require_editable_cell` / `require_viewable_cell` /
//! `require_viewable_cell_optional_auth`), each masking a miss and its own
//! tier's denial alike. `insert` / `move` / `delete` emit
//! `cell_item_insert` / `cell_item_move` / `cell_item_delete` audit events
//! in-tx with the mutation. Mirrors the TS `cell_item_actions.ts`.

use std::sync::Arc;

use deadpool_postgres::GenericClient;
use fuz_actions::action_context::ActionContext;
use fuz_actions::action_registry::ActionHandler;
use fuz_actions::action_spec::ActionSpec;
use fuz_auth::{AuditEventType, AuthSpec, CredentialGate, RateLimitClass, RequestActorContext};
use fuz_db::is_pg_unique_violation;
use fuz_http::{InputShape, JsonrpcError, parse_strict_params};
use serde_json::{Value, json};

use crate::cell_action_specs::{
    CELL_RELATION_LIST_LIMIT_DEFAULT, CELL_RELATION_LIST_LIMIT_MAX, dispatch_db, emit_cell_audit,
    map_cell_error, require_editable_cell, require_viewable_cell,
    require_viewable_cell_optional_auth, validate_list_limit,
};
use fuz_cell::cell_item_queries::{
    query_cell_item_delete, query_cell_item_insert, query_cell_item_list_for_child,
    query_cell_item_list_for_parent, query_cell_item_move,
};
use fuz_cell::cell_item_schema::{
    CellItemDeleteInput, CellItemInsertInput, CellItemListInput, CellItemMoveInput, CellItemRow,
    is_valid_position,
};
use fuz_cell::cell_view_sql::CellViewer;
use fuz_cell::error::CellError;

// -- Error reasons (mirror TS `cell_item_action_specs.ts`) ------------------

/// `cell_item_list` got neither `parent_id` nor `child_id` (or both).
pub const ERROR_CELL_ITEM_LIST_REQUIRES_PARENT_OR_CHILD: &str =
    "cell_item_list_requires_parent_or_child";
/// `(parent_id, position)` collision on insert / move. The client refreshes
/// its fractional-index bracket and retries.
pub const ERROR_CELL_ITEM_POSITION_TAKEN: &str = "cell_item_position_taken";

// -- Helpers ----------------------------------------------------------------

/// Reject a position outside the base62 fractional-index grammar (mirrors
/// the TS `CellItemPosition` brand). Validated before any fetch.
fn validate_position(position: &str) -> Result<(), JsonrpcError> {
    if is_valid_position(position) {
        return Ok(());
    }
    Err(fuz_http::invalid_input_params(
        "cell item position must be a base62 fractional-index key (1-200 chars)",
        None,
    ))
}

/// The `cell_item_position_taken` invalid-params error.
fn position_taken() -> JsonrpcError {
    fuz_http::invalid_params(
        "cell_item position taken",
        Some(ERROR_CELL_ITEM_POSITION_TAKEN),
    )
}

/// Map a write error, translating a `(parent_id, position)` unique
/// violation to [`position_taken`].
fn map_item_write_error(err: CellError) -> JsonrpcError {
    if let CellError::Db(e) = &err
        && is_pg_unique_violation(e)
    {
        return position_taken();
    }
    map_cell_error(err, false)
}

/// Serialize an item row to its `ItemJson` wire value.
fn item_to_value(row: &CellItemRow) -> Result<Value, JsonrpcError> {
    serde_json::to_value(row)
        .map_err(|e| fuz_http::internal_error_with_source("cell item serialize failed", &e))
}

// -- Handlers ---------------------------------------------------------------

async fn handle_item_insert<C: GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellItemInsertInput,
) -> Result<Value, JsonrpcError> {
    validate_position(&input.position)?;
    require_editable_cell(client, auth, input.parent_id).await?;
    // Child must be view-admitted — otherwise insert leaks existence.
    require_viewable_cell(client, auth, input.child_id).await?;
    let row = query_cell_item_insert(client, input.parent_id, &input.position, input.child_id)
        .await
        .map_err(map_item_write_error)?;
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellItemInsert,
        json!({ "parent_id": row.parent_id, "position": row.position, "child_id": row.child_id }),
    )
    .await?;
    Ok(json!({ "item": item_to_value(&row)? }))
}

async fn handle_item_move<C: GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellItemMoveInput,
) -> Result<Value, JsonrpcError> {
    validate_position(&input.position)?;
    validate_position(&input.new_position)?;
    require_editable_cell(client, auth, input.parent_id).await?;
    let row = query_cell_item_move(
        client,
        input.parent_id,
        &input.position,
        &input.new_position,
    )
    .await
    .map_err(map_item_write_error)?;
    let Some(row) = row else {
        // Source slot missing — raced with a deleter.
        return Err(fuz_http::not_found(
            "cell_item",
            Some(crate::cell_action_specs::ERROR_CELL_NOT_FOUND),
        ));
    };
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellItemMove,
        json!({
            "parent_id": row.parent_id,
            "position_old": input.position,
            "position_new": row.position,
        }),
    )
    .await?;
    Ok(json!({ "item": item_to_value(&row)? }))
}

async fn handle_item_delete<C: GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellItemDeleteInput,
) -> Result<Value, JsonrpcError> {
    validate_position(&input.position)?;
    require_editable_cell(client, auth, input.parent_id).await?;
    let deleted = query_cell_item_delete(client, input.parent_id, &input.position)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    if let Some(row) = &deleted {
        emit_cell_audit(
            ctx,
            client,
            auth,
            AuditEventType::CellItemDelete,
            json!({ "parent_id": row.parent_id, "position": row.position, "child_id": row.child_id }),
        )
        .await?;
    }
    Ok(json!({ "ok": true, "deleted": deleted.is_some() }))
}

async fn handle_item_list<C: GenericClient + ?Sized>(
    client: &C,
    auth: Option<&RequestActorContext>,
    input: CellItemListInput,
) -> Result<Value, JsonrpcError> {
    validate_list_limit(input.limit, CELL_RELATION_LIST_LIMIT_MAX, "cell_item_list")?;
    let limit = input.limit.unwrap_or(CELL_RELATION_LIST_LIMIT_DEFAULT);
    // The forward cursor is a position key, so it takes the position grammar
    // — the twin declares `position_after` as `optional(CellItemPosition)`,
    // and a cursor the grammar refuses can only have been hand-built.
    if let Some(position_after) = &input.position_after {
        validate_position(position_after)?;
    }
    // Exactly one endpoint — after the checks the TS twin's schema makes
    // (`limit`, the cursor grammar), as its handler guard runs after them.
    if input.parent_id.is_some() == input.child_id.is_some() {
        return Err(fuz_http::invalid_input_params(
            "cell_item_list requires exactly one of parent_id or child_id",
            Some(ERROR_CELL_ITEM_LIST_REQUIRES_PARENT_OR_CHILD),
        ));
    }

    if let Some(parent_id) = input.parent_id {
        // Forward: gate on can_view_cell(parent), then page the viewable children.
        let parent = require_viewable_cell_optional_auth(client, auth, parent_id).await?;
        let rows = query_cell_item_list_for_parent(
            client,
            &CellViewer::new(auth),
            parent.id,
            Some(limit),
            input.position_after.as_deref(),
        )
        .await
        .map_err(|e| map_cell_error(e, false))?;
        let items = rows
            .iter()
            .map(item_to_value)
            .collect::<Result<Vec<Value>, _>>()?;
        return Ok(json!({ "items": items }));
    }

    // Reverse: 2-layer authz. Gate on can_view_cell(child), then page the
    // items whose parent is viewable. The XOR check above guarantees
    // `child_id` is set here; the let-else is a lint-safe fallback rather
    // than an unwrap.
    let Some(child_id) = input.child_id else {
        return Err(fuz_http::invalid_input_params(
            "cell_item_list requires exactly one of parent_id or child_id",
            Some(ERROR_CELL_ITEM_LIST_REQUIRES_PARENT_OR_CHILD),
        ));
    };
    let child = require_viewable_cell_optional_auth(client, auth, child_id).await?;
    let rows =
        query_cell_item_list_for_child(client, &CellViewer::new(auth), child.id, Some(limit))
            .await
            .map_err(|e| map_cell_error(e, false))?;
    let items = rows
        .iter()
        .map(item_to_value)
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(json!({ "items": items }))
}

// -- Spec construction ------------------------------------------------------

/// Build the four `cell_item_*` [`ActionSpec`]s.
///
/// Concatenated into the cell spec set by `build_cell_spec_set`. `insert` /
/// `move` / `delete` carry side effects and require an authenticated actor;
/// `list` is a public read (the view predicate filters each page in SQL).
#[must_use]
pub fn build_cell_item_spec_set() -> Vec<ActionSpec> {
    vec![
        ActionSpec::with_side_effects(
            "cell_item_insert",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellItemInsertInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_item_insert(&ctx, auth, input))
                    })
                });
                handler
            },
        ),
        ActionSpec::with_side_effects(
            "cell_item_move",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellItemMoveInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_item_move(&ctx, auth, input))
                    })
                });
                handler
            },
        ),
        ActionSpec::with_side_effects(
            "cell_item_delete",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellItemDeleteInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_item_delete(&ctx, auth, input))
                    })
                });
                handler
            },
        ),
        ActionSpec::read_only(
            "cell_item_list",
            AuthSpec::optional_identity(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellItemListInput = parse_strict_params(params)?;
                        dispatch_db!(ctx, handle_item_list(ctx.auth.actor(), input))
                    })
                });
                handler
            },
        )
        .with_rate_limit(RateLimitClass::Ip),
    ]
}
