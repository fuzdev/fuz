//! Cell-audit RPC handler + [`build_cell_audit_spec_set`].
//!
//! One verb (`cell_audit_list`) — the per-cell audit timeline. Returns the
//! most-recent audit rows referencing the cell on any cell-domain metadata
//! key, narrowed to the `CellAuditEventJson` wire shape (no `ip`, no
//! `metadata`, no account join). Mirrors the TS `cell_audit_actions.ts`.
//!
//! **Manage-tier only** (`can_manage_cell` = admin / owner). The timeline
//! reveals who-touched-the-cell, so it is gated above `can_view_cell` —
//! viewers and editors get the IDOR-mask 404, same shape as `cell_get`.

use std::sync::Arc;

use deadpool_postgres::GenericClient;
use fuz_actions::action_registry::ActionHandler;
use fuz_actions::action_spec::ActionSpec;
use fuz_auth::{AuthSpec, CredentialGate, RequestActorContext};
use fuz_http::{InputShape, JsonrpcError, parse_strict_params};
use serde_json::{Value, json};

use crate::cell_action_specs::{dispatch_db, map_cell_error, require_manageable_cell};
use fuz_cell::cell_audit_queries::query_audit_log_list_by_cell;
use fuz_cell::cell_audit_schema::{CELL_AUDIT_LIST_EVENTS_MAX, CellAuditListInput};

async fn handle_audit_list<C: GenericClient + ?Sized>(
    client: &C,
    auth: &RequestActorContext,
    input: CellAuditListInput,
) -> Result<Value, JsonrpcError> {
    // Manage-tier gate (admin / owner). Viewers + editors fall through to
    // the IDOR-mask 404 — the timeline is more sensitive than the content.
    let cell = require_manageable_cell(client, auth, input.cell_id).await?;
    let rows = query_audit_log_list_by_cell(client, cell.id, CELL_AUDIT_LIST_EVENTS_MAX)
        .await
        .map_err(|e| map_cell_error(e, false))?;
    let events = rows
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<Value>, _>>()
        .map_err(|e| fuz_http::internal_error_with_source("cell audit serialize failed", &e))?;
    Ok(json!({ "events": events }))
}

/// Build the one `cell_audit_list` [`ActionSpec`].
///
/// Concatenated into the cell spec set by `build_cell_spec_set`. Read-only;
/// requires an authenticated actor (manage-tier authz runs per-cell in the
/// handler).
#[must_use]
pub fn build_cell_audit_spec_set() -> Vec<ActionSpec> {
    vec![ActionSpec::read_only(
        "cell_audit_list",
        AuthSpec::authenticated(CredentialGate::Any),
        InputShape::Object,
        {
            let handler: ActionHandler = Arc::new(|params, ctx| {
                Box::pin(async move {
                    let input: CellAuditListInput = parse_strict_params(params)?;
                    let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
                    dispatch_db!(ctx, handle_audit_list(auth, input))
                })
            });
            handler
        },
    )]
}
