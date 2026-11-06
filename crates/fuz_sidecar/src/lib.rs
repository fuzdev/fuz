//! Sidecar traits for Fuz
//!
//! Sidecars are long-running processes that provide tool execution for
//! different runtimes (Deno, Python, etc.). They communicate via JSON-lines
//! over stdio with multiplexed request/response matching.
//!
//! # Architecture
//!
//! - `SidecarController` + `SidecarControllerFactory`: Generic controller implementation for stdio-based sidecars
//! - `SpawnConfig`: Runtime-specific configuration (command, script, tools)
//! - `SidecarPool`: Routes requests to appropriate sidecar, manages lifecycle
//!
//! See `docs/sidecars.md` for full architecture documentation.

mod controller;
mod error;
mod pool;
mod protocol;
mod sidecar;

pub use controller::{SidecarController, SidecarControllerFactory, SpawnConfig};
pub use error::SidecarError;
pub use fuz_wire::{RestartResult, SidecarStatus, SidecarStatusInfo, StartResult, StopResult};
pub use pool::{FailurePolicy, SidecarConfig, SidecarFactoryDyn, SidecarPool};
pub use protocol::{WireRequest, WireResponse};
pub use sidecar::{
    ControllerCommand, RecoveryConfig, Sidecar, SidecarFactory, SidecarHandle, SidecarRequest,
};

use serde::{Deserialize, Serialize};
use tokio::process::Command;

/// Environment variables that must not be inherited by sidecar processes.
///
/// Sidecars run untrusted code and must not have access to auth credentials.
/// fuzd authenticates by UDS + `SO_PEERCRED` and holds no credential in its
/// environment, so the list is empty; the stripping stays in place so a future
/// credential is a one-line addition.
pub const SENSITIVE_ENV_VARS: &[&str] = &[];

/// Create a tokio Command with sensitive environment variables removed.
///
/// Use this instead of `Command::new()` when spawning sidecar processes
/// to ensure auth tokens and other sensitive data aren't leaked.
///
/// # Example
///
/// ```no_run
/// # use fuz_sidecar::secure_command;
/// # fn main() -> Result<(), std::io::Error> {
/// let mut child = secure_command("deno")
///     .args(["run", "script.ts"])
///     .spawn()?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub fn secure_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    for var in SENSITIVE_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd
}

/// Static tool definition provided by a sidecar
///
/// Compile-time metadata about tools. Use `fuz_wire::ToolInfo` for
/// runtime RPC responses that include the runtime field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
}
