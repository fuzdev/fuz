//! Cell-field RPC handlers + [`build_cell_field_spec_set`].
//!
//! Three verbs (`cell_field_set` / `cell_field_delete` / `cell_field_list`)
//! bound to canonical [`ActionSpec`]s, concatenated into the cell spec set
//! by `build_cell_spec_set`.
//!
//! - `set` — admin / owner / editor-grant on `source` may set; `target`
//!   must be view-admitted (so a caller can't link to a cell they couldn't
//!   otherwise see). Idempotent UPSERT on `(source_id, name)`.
//! - `delete` — admin / owner / editor-grant on `source`. Idempotent.
//! - `list` — bidirectional, either direction a page of up to `limit`
//!   ([`CELL_RELATION_LIST_LIMIT_DEFAULT`] when omitted) fields whose other
//!   end the caller may view — the view predicate runs in SQL, before the
//!   limit. Forward (`source_id`) gates on `can_view_cell(source)`, then pages
//!   the fields whose target is viewable (strict target-visibility). Reverse
//!   (`target_id`) gates on `can_view_cell(target)`, then pages the fields
//!   whose source is viewable.
//!
//! All paths 404-mask on cell-miss / tier-denial — every cell gate here is
//! one of `cell_action_specs`' shared tier helpers
//! (`require_editable_cell` / `require_viewable_cell` /
//! `require_viewable_cell_optional_auth`), each masking a miss and its own
//! tier's denial alike. `set` / `delete` emit `cell_field_set` /
//! `cell_field_delete` audit events in-tx with the mutation. Mirrors the TS
//! `cell_field_actions.ts`.

use std::sync::Arc;

use deadpool_postgres::GenericClient;
use fuz_actions::action_context::ActionContext;
use fuz_actions::action_registry::ActionHandler;
use fuz_actions::action_spec::ActionSpec;
use fuz_auth::{AuditEventType, AuthSpec, CredentialGate, RateLimitClass, RequestActorContext};
use fuz_http::{InputShape, JsonrpcError, parse_strict_params};
use serde_json::{Value, json};

use crate::cell_action_specs::{
    CELL_RELATION_LIST_LIMIT_DEFAULT, CELL_RELATION_LIST_LIMIT_MAX, dispatch_db, emit_cell_audit,
    map_cell_error, require_editable_cell, require_viewable_cell,
    require_viewable_cell_optional_auth, validate_list_limit,
};
use fuz_cell::cell_field_queries::{
    query_cell_field_delete, query_cell_field_list_for_source, query_cell_field_list_for_target,
    query_cell_field_set,
};
use fuz_cell::cell_field_schema::{
    CellFieldDeleteInput, CellFieldListInput, CellFieldRow, CellFieldSetInput, is_valid_field_name,
};
use fuz_cell::cell_view_sql::CellViewer;

// -- Error reasons (mirror TS `cell_field_action_specs.ts`) -----------------

/// `cell_field_list` got neither `source_id` nor `target_id` (or both).
pub const ERROR_CELL_FIELD_LIST_REQUIRES_SOURCE_OR_TARGET: &str =
    "cell_field_list_requires_source_or_target";

// -- Helpers ----------------------------------------------------------------

/// Reject a field name outside the `snake_case` grammar (mirrors the TS
/// `CellFieldName` brand). Validated before any fetch so a bad name can't
/// probe cell existence.
fn validate_field_name(name: &str) -> Result<(), JsonrpcError> {
    if is_valid_field_name(name) {
        return Ok(());
    }
    Err(fuz_http::invalid_input_params(
        "cell field name must match ^[a-z][a-z0-9_]{0,63}$",
        None,
    ))
}

/// Serialize a field row to its `FieldJson` wire value.
fn field_to_value(row: &CellFieldRow) -> Result<Value, JsonrpcError> {
    serde_json::to_value(row)
        .map_err(|e| fuz_http::internal_error_with_source("cell field serialize failed", &e))
}

// -- Handlers ---------------------------------------------------------------

async fn handle_field_set<C: GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellFieldSetInput,
) -> Result<Value, JsonrpcError> {
    validate_field_name(&input.name)?;
    // Source must be editable.
    require_editable_cell(client, auth, input.source_id).await?;
    // Target must be view-admitted — otherwise a caller could probe for the
    // existence of private cells by pointing a field at them.
    require_viewable_cell(client, auth, input.target_id).await?;
    let row = query_cell_field_set(client, input.source_id, &input.name, input.target_id)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    emit_cell_audit(
        ctx,
        client,
        auth,
        AuditEventType::CellFieldSet,
        json!({ "source_id": row.source_id, "name": row.name, "target_id": row.target_id }),
    )
    .await?;
    Ok(json!({ "field": field_to_value(&row)? }))
}

async fn handle_field_delete<C: GenericClient + ?Sized>(
    client: &C,
    ctx: &ActionContext<'_>,
    auth: &RequestActorContext,
    input: CellFieldDeleteInput,
) -> Result<Value, JsonrpcError> {
    validate_field_name(&input.name)?;
    require_editable_cell(client, auth, input.source_id).await?;
    let deleted = query_cell_field_delete(client, input.source_id, &input.name)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    if let Some(row) = &deleted {
        emit_cell_audit(
            ctx,
            client,
            auth,
            AuditEventType::CellFieldDelete,
            json!({ "source_id": row.source_id, "name": row.name, "target_id": row.target_id }),
        )
        .await?;
    }
    Ok(json!({ "ok": true, "deleted": deleted.is_some() }))
}

async fn handle_field_list<C: GenericClient + ?Sized>(
    client: &C,
    auth: Option<&RequestActorContext>,
    input: CellFieldListInput,
) -> Result<Value, JsonrpcError> {
    validate_list_limit(input.limit, CELL_RELATION_LIST_LIMIT_MAX, "cell_field_list")?;
    let limit = input.limit.unwrap_or(CELL_RELATION_LIST_LIMIT_DEFAULT);
    // The forward cursor is a field name, so it takes the field-name grammar
    // — the twin declares `name_after` as `optional(CellFieldName)`, and a
    // cursor the grammar refuses can only have been hand-built.
    if let Some(name_after) = &input.name_after {
        validate_field_name(name_after)?;
    }
    // Exactly one endpoint — after the checks the TS twin's schema makes
    // (`limit`, the cursor grammar), as its handler guard runs after them.
    if input.source_id.is_some() == input.target_id.is_some() {
        return Err(fuz_http::invalid_input_params(
            "cell_field_list requires exactly one of source_id or target_id",
            Some(ERROR_CELL_FIELD_LIST_REQUIRES_SOURCE_OR_TARGET),
        ));
    }

    if let Some(source_id) = input.source_id {
        // Forward: gate on can_view_cell(source), then page the viewable targets.
        let source = require_viewable_cell_optional_auth(client, auth, source_id).await?;
        let rows = query_cell_field_list_for_source(
            client,
            &CellViewer::new(auth),
            source.id,
            Some(limit),
            input.name_after.as_deref(),
        )
        .await
        .map_err(|e| map_cell_error(e, false))?;
        let fields = rows
            .iter()
            .map(field_to_value)
            .collect::<Result<Vec<Value>, _>>()?;
        return Ok(json!({ "fields": fields }));
    }

    // Reverse: 2-layer authz. Gate on can_view_cell(target), then page the
    // fields whose source is viewable. The XOR check above guarantees
    // `target_id` is set here; the let-else is a lint-safe fallback rather
    // than an unwrap.
    let Some(target_id) = input.target_id else {
        return Err(fuz_http::invalid_input_params(
            "cell_field_list requires exactly one of source_id or target_id",
            Some(ERROR_CELL_FIELD_LIST_REQUIRES_SOURCE_OR_TARGET),
        ));
    };
    let target = require_viewable_cell_optional_auth(client, auth, target_id).await?;
    let rows =
        query_cell_field_list_for_target(client, &CellViewer::new(auth), target.id, Some(limit))
            .await
            .map_err(|e| map_cell_error(e, false))?;
    let fields = rows
        .iter()
        .map(field_to_value)
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(json!({ "fields": fields }))
}

// -- Spec construction ------------------------------------------------------

/// Build the three `cell_field_*` [`ActionSpec`]s.
///
/// Concatenated into the cell spec set by `build_cell_spec_set`. `set` /
/// `delete` carry side effects and require an authenticated actor; `list`
/// is a public read (the view predicate filters each page in SQL).
#[must_use]
pub fn build_cell_field_spec_set() -> Vec<ActionSpec> {
    vec![
        ActionSpec::with_side_effects(
            "cell_field_set",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellFieldSetInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_field_set(&ctx, auth, input))
                    })
                });
                handler
            },
        ),
        ActionSpec::with_side_effects(
            "cell_field_delete",
            AuthSpec::authenticated(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellFieldDeleteInput = parse_strict_params(params)?;
                        let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                        dispatch_db!(ctx, handle_field_delete(&ctx, auth, input))
                    })
                });
                handler
            },
        ),
        ActionSpec::read_only(
            "cell_field_list",
            AuthSpec::optional_identity(CredentialGate::Any),
            InputShape::Object,
            {
                let handler: ActionHandler = Arc::new(|params, ctx| {
                    Box::pin(async move {
                        let input: CellFieldListInput = parse_strict_params(params)?;
                        dispatch_db!(ctx, handle_field_list(ctx.auth.actor(), input))
                    })
                });
                handler
            },
        )
        .with_rate_limit(RateLimitClass::Ip),
    ]
}
