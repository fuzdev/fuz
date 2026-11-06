//! Cell-audit wire + row types for the per-cell timeline.
//!
//! Mirrors the TS `cell_audit_action_specs.ts`. The wire row is
//! **narrower** than the full `audit_log` event: `account_id` /
//! `target_account_id` / `target_actor_id` / `ip` / `metadata` are
//! deliberately dropped. The timeline reveals who-touched-the-cell at the
//! manage tier; it has no need for the actor↔account join or collaborator
//! IPs (admins reach the full surface via the admin audit verbs).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The most events `cell_audit_list` returns, the most recent first.
///
/// Fixed: the input takes no `limit` and the output no cursor, so this is the
/// whole timeline a caller sees (mirrors the TS `CELL_AUDIT_LIST_EVENTS_MAX`).
pub const CELL_AUDIT_LIST_EVENTS_MAX: i64 = 50;

/// `cell_audit_list` input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellAuditListInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub cell_id: Uuid,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// One narrowed cell-audit row. Serializes to the `CellAuditEventJson`
/// wire shape (6 keys). `created_at` projects SQL-side as a UTC ISO-8601
/// string.
#[derive(Debug, Clone, Serialize)]
pub struct CellAuditEventRow {
    pub id: Uuid,
    pub seq: i64,
    pub event_type: String,
    pub outcome: String,
    pub actor_id: Option<Uuid>,
    pub created_at: String,
}
