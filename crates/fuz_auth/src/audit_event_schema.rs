//! Audit log row shape.
//!
//! `event_type` and `outcome` ride as plain strings on the wire (open
//! registry — consumers extend by emitting new strings). The
//! [`AuditOutcome`](crate::audit_emitter::AuditOutcome) enum
//! covers the two builtins.

use serde::Serialize;
use serde_json::Value;

/// Audit log row as materialized by the INSERT … RETURNING * call.
///
/// Mirrors `fuz_app`'s `AuditLogEvent`. Field nullability matches the
/// table DDL. Listeners read this through the audit emitter chain.
///
/// `Serialize` makes the row wire-shape-equivalent to TS
/// `AuditLogEventJson` so [`crate::audit_log_queries::AuditLogEventWithUsernames`]
/// can `#[serde(flatten)]` it under the `audit_log_list` RPC response.
#[derive(Debug, Clone, Serialize)]
pub struct AuditLogEvent {
    pub id: uuid::Uuid,
    pub seq: i64,
    pub event_type: String,
    pub outcome: String,
    pub actor_id: Option<uuid::Uuid>,
    pub account_id: Option<uuid::Uuid>,
    pub target_account_id: Option<uuid::Uuid>,
    pub target_actor_id: Option<uuid::Uuid>,
    pub ip: Option<String>,
    /// ISO 8601 UTC string for wire parity with the TS reference backend.
    pub created_at: String,
    /// JSONB metadata decoded into `serde_json::Value`. Read via the
    /// `::text` cast on the SQL side to avoid pulling the
    /// `with-serde_json-1` feature on `tokio-postgres`.
    pub metadata: Option<Value>,
}
