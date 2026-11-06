//! Sidecar and daemon status types
//!
//! Shared between daemon (`fuz_sidecar`, `fuzd_server`) and client (`fuz_client`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Tool information returned by `tool.list` RPC
///
/// Runtime representation of a tool. For static compile-time definitions,
/// see `fuz_sidecar::ToolDef`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub runtime: String,
}

/// Version information from a sidecar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Runtime version (e.g., "2.1.4" for Deno, "3.12.0" for Python)
    pub runtime: String,
    /// TypeScript version (Deno only)
    pub typescript: Option<String>,
    /// Tool dependency versions (e.g., {"prettier": "3.7.4", "svelte": "5.45.8"})
    pub dependencies: HashMap<String, String>,
}

/// Status of a sidecar for reporting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SidecarStatus {
    /// Not started, will spawn on first request
    Unloaded,
    /// Currently spawning
    Loading,
    /// Running and accepting requests
    Running,
    /// Shutting down due to idle timeout
    ShuttingDown,
    /// Failed after max restarts
    Failed,
}

/// Sidecar status info for RPC responses.
///
/// Postcard-friendly: no `#[serde(skip_serializing_if)]` attributes so
/// the wire codec round-trips `None` correctly. The JSON CLI surface
/// (`fuzd status --json`) therefore renders each entry's `None` fields as
/// `null` rather than omitting them — acceptable since `--json` consumers
/// parse the shape rather than pattern-matching keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarStatusInfo {
    pub id: String,
    pub runtime: String,
    pub status: SidecarStatus,
    pub last_active_ms: Option<u64>,
    pub uptime_ms: Option<u64>,
    pub restart_count: u32,
    pub error_message: Option<String>,
    pub tools: Vec<String>,
    pub description: Option<String>,
    /// Version information (cached from `__version_info` call)
    pub version_info: Option<VersionInfo>,
}

/// Result of a sidecar start operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartResult {
    pub started: Vec<String>,
    pub already_running: Vec<String>,
    pub failed: Vec<String>,
}

/// Result of a sidecar stop operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopResult {
    pub stopped: Vec<String>,
    pub already_stopped: Vec<String>,
}

/// Result of a sidecar restart operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartResult {
    pub restarted: Vec<String>,
    pub failed: Vec<String>,
}

/// Which sidecar(s) a control action (start / stop / restart / status) targets.
///
/// Replaces the prior magic-`"all"` `Option<String>` request field: `All` is
/// the single spelling of "every sidecar", and no id is reserved — a sidecar
/// literally named `"all"` is `One("all")`, distinct from `All`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SidecarTarget {
    /// Every registered sidecar.
    All,
    /// One sidecar by id.
    One(String),
}

impl SidecarTarget {
    /// The targeted id, or `None` for [`SidecarTarget::All`] — the filter shape
    /// the pool consumes (`None` ⇒ no filter ⇒ all sidecars).
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::All => None,
            Self::One(id) => Some(id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sidecar_status_serialization() {
        // Verify lowercase serialization
        let status = SidecarStatus::Running;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""running""#);

        let status = SidecarStatus::ShuttingDown;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""shuttingdown""#);
    }

    #[test]
    fn test_sidecar_status_deserialization() {
        let status: SidecarStatus = serde_json::from_str(r#""unloaded""#).unwrap();
        assert_eq!(status, SidecarStatus::Unloaded);

        let status: SidecarStatus = serde_json::from_str(r#""loading""#).unwrap();
        assert_eq!(status, SidecarStatus::Loading);
    }

    #[test]
    fn test_sidecar_status_info() {
        let info = SidecarStatusInfo {
            id: "deno".to_string(),
            runtime: "deno".to_string(),
            status: SidecarStatus::Running,
            last_active_ms: Some(100),
            uptime_ms: Some(5000),
            restart_count: 0,
            error_message: None,
            tools: vec!["prettier".to_string()],
            description: None,
            version_info: None,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains(r#""status":"running""#));

        // Post-postcard-port the Option fields render as null, not
        // omitted — see SidecarStatusInfo doc comment.
        assert!(json.contains(r#""error_message":null"#));
        assert!(json.contains(r#""description":null"#));
        assert!(json.contains(r#""version_info":null"#));
    }

    #[test]
    fn sidecar_target_id_folds_all_to_none() {
        assert_eq!(SidecarTarget::All.id(), None);
        assert_eq!(SidecarTarget::One("deno".to_string()).id(), Some("deno"));
        // A sidecar literally named "all" is unambiguous — `One`, not `All`.
        assert_eq!(SidecarTarget::One("all".to_string()).id(), Some("all"));
    }

    #[test]
    fn sidecar_target_postcard_round_trips() {
        for target in [SidecarTarget::All, SidecarTarget::One("deno".to_string())] {
            let bytes = postcard::to_allocvec(&target).unwrap();
            let decoded: SidecarTarget = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.id(), target.id());
        }
    }
}
