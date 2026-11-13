//! Wire protocol types for sidecar communication
//!
//! All sidecars use the same JSON-lines protocol over stdio.
//!
//! Note: No version field - protocol is internal (daemon ↔ embedded script),
//! both sides compiled together. Add versioning if scripts become externally
//! loadable or protocol becomes a public specification.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request sent to a sidecar process (JSON-lines over stdin)
#[derive(Debug, Serialize)]
pub struct WireRequest {
    pub id: u64,
    pub tool: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Value>,
}

/// Response from a sidecar process (JSON-lines over stdout)
#[derive(Debug, Deserialize)]
pub struct WireResponse {
    pub id: u64,
    pub ok: bool,
    pub output: Option<Value>,
    pub error: Option<String>,
    /// Execution time in milliseconds (for metrics)
    pub duration_ms: u64,
}
