//! Sidecar error types
//!
//! This module provides typed errors for sidecar operations, enabling
//! consumers to handle specific failure cases programmatically.
//!
//! # Error Handling Strategy
//!
//! This crate uses `thiserror` for typed errors that cross crate boundaries.
//! Binary crates (CLI, daemon) wrap these in their own typed errors (`CliError`,
//! `StartupError`) for consistent handling and display.
//!
//! # Example
//!
//! ```text
//! use fuz_sidecar::{SidecarPool, SidecarError};
//!
//! match pool.call("prettier", content, None).await {
//!     Ok(result) => println!("{result}"),
//!     Err(SidecarError::UnknownTool { tool }) => {
//!         eprintln!("Tool '{tool}' not found");
//!     }
//!     Err(SidecarError::SidecarFailed { id, .. }) => {
//!         eprintln!("Sidecar '{id}' is in failed state, try restarting");
//!     }
//!     Err(e) => eprintln!("Error: {e}"),
//! }
//! ```

use thiserror::Error;

/// Errors that can occur during sidecar operations.
///
/// These errors cover the full lifecycle of sidecar processes:
/// - Spawning (process creation, stdio setup)
/// - Protocol (JSON-lines communication)
/// - Tool execution (unknown tools, tool-level errors)
/// - Pool management (unknown sidecars, lifecycle states)
#[derive(Debug, Error)]
pub enum SidecarError {
    //
    // Spawn errors - process creation failures
    //
    /// Failed to create temporary file for embedded script.
    ///
    /// Sidecars use embedded scripts written to tempfiles at spawn time.
    /// This error indicates a filesystem issue (permissions, disk full, etc.).
    #[error("failed to create script tempfile")]
    TempfileCreate(#[source] std::io::Error),

    /// Failed to write embedded script to temporary file.
    #[error("failed to write sidecar script")]
    ScriptWrite(#[source] std::io::Error),

    /// Failed to spawn the sidecar subprocess.
    ///
    /// Common causes: runtime not installed, PATH issues, permissions.
    #[error("failed to spawn {runtime} sidecar")]
    ProcessSpawn {
        runtime: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Failed to capture a stdio pipe from the spawned process.
    ///
    /// This is an internal error - stdio should always be available
    /// when requested via `Stdio::piped()`.
    #[error("failed to get {pipe} from sidecar process")]
    PipeMissing { pipe: &'static str },

    //
    // Protocol errors - JSON-lines communication failures
    //
    /// Failed to parse JSON response from sidecar.
    ///
    /// Indicates a protocol mismatch or sidecar bug. The sidecar should
    /// always return valid JSON-lines responses.
    #[error("failed to parse sidecar response")]
    ResponseParse(#[source] serde_json::Error),

    /// Sidecar returned an error response for a tool invocation.
    ///
    /// This is a tool-level error (e.g., prettier syntax error, parse failure),
    /// not a sidecar infrastructure error.
    #[error("tool error: {message}")]
    ToolError { message: String },

    /// Sidecar returned success but with no output value.
    ///
    /// Protocol violation - successful responses must include output.
    #[error("sidecar returned success with no output")]
    MissingOutput,

    //
    // Handle errors - actor communication failures
    //
    /// Requested tool is not provided by this sidecar.
    ///
    /// Check available tools via `Sidecar::tools()` or `tool.list` RPC.
    #[error("unknown tool: {tool}")]
    UnknownTool { tool: String },

    /// The sidecar controller task has terminated.
    ///
    /// The controller may have crashed or been shut down. The pool will
    /// attempt automatic recovery based on `RecoveryConfig`.
    #[error("sidecar controller has shut down")]
    ControllerShutdown,

    /// The controller dropped the response channel before responding.
    ///
    /// Similar to `ControllerShutdown` but specifically during a pending request.
    #[error("sidecar controller dropped response channel")]
    ResponseDropped,

    //
    // Pool errors - sidecar lifecycle management
    //
    /// Requested sidecar ID does not exist in the pool.
    ///
    /// Valid sidecar IDs are configured at pool creation time
    /// (e.g., "deno", "python").
    #[error("unknown sidecar: {id}")]
    UnknownSidecar { id: String },

    /// Sidecar is in failed state after exceeding max restart attempts.
    ///
    /// The sidecar crashed repeatedly within the recovery window.
    /// Depending on `FailurePolicy`, it may recover on the next request
    /// or stay failed until daemon restart.
    #[error("sidecar '{id}' failed: {message}")]
    SidecarFailed { id: String, message: String },

    /// Sidecar entry disappeared during an async operation.
    ///
    /// Internal error - should not occur in normal operation.
    #[error("sidecar '{id}' disappeared during {operation}")]
    SidecarDisappeared { id: String, operation: &'static str },

    /// Sidecar process exited unexpectedly.
    ///
    /// Used internally by the crash monitor. Consumers typically see
    /// `ControllerShutdown` or `SidecarFailed` instead.
    #[error("{runtime} sidecar crashed")]
    SidecarCrashed { runtime: &'static str },

    /// Error communicating with sidecar process.
    ///
    /// IO error on stdin/stdout pipes.
    #[error("sidecar communication error")]
    Communication(#[source] std::io::Error),
}

impl SidecarError {
    /// Returns `true` if this error indicates the sidecar should be restarted.
    ///
    /// Used by recovery logic to determine if automatic restart is appropriate.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::ControllerShutdown
                | Self::ResponseDropped
                | Self::SidecarCrashed { .. }
                | Self::Communication(_)
        )
    }

    /// Returns `true` if this is a tool-level error vs infrastructure error.
    ///
    /// Tool errors (like syntax errors in code being formatted) are expected
    /// and should be reported to the user. Infrastructure errors indicate
    /// something wrong with the sidecar system itself.
    #[must_use]
    pub const fn is_tool_error(&self) -> bool {
        matches!(self, Self::ToolError { .. })
    }
}
