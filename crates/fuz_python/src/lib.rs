//! Python sidecar for Fuz
//!
//! A placeholder Python sidecar with a test tool.
//!
//! Uses the generic controller from `fuz_sidecar`. See `docs/sidecars.md` for
//! architecture and security details.

use fuz_sidecar::{SidecarControllerFactory, SpawnConfig, ToolDef};
use std::path::Path;
use tokio::process::Command;

/// Embedded sidecar script (compiled into binary)
pub const SIDECAR_SCRIPT: &str = include_str!("../sidecar.py");

/// Tools available in the Python sidecar
pub const PYTHON_TOOLS: &[ToolDef] = &[ToolDef {
    name: "hello-python",
    description: "Hello world: computes 21 * 2",
}];

/// Build the Python command for the given script path.
fn build_command(script_path: &Path, _config_path: Option<&Path>) -> Command {
    let mut cmd = fuz_sidecar::secure_command("python3");
    cmd.arg("-u") // unbuffered output
        .arg(script_path);
    cmd
}

/// Configuration for the Python sidecar.
pub const SPAWN_CONFIG: SpawnConfig = SpawnConfig {
    runtime: "python",
    script: SIDECAR_SCRIPT,
    config: None,
    tools: PYTHON_TOOLS,
    build_command,
};

/// Default channel buffer size for the controller mailbox.
pub const DEFAULT_CHANNEL_BUFFER: usize = 256;

/// Create a Python sidecar factory with default channel buffer.
#[must_use]
pub const fn factory() -> SidecarControllerFactory {
    SidecarControllerFactory::new(SPAWN_CONFIG, DEFAULT_CHANNEL_BUFFER)
}

/// Create a Python sidecar factory with custom channel buffer size.
#[must_use]
pub const fn factory_with_buffer(channel_buffer: usize) -> SidecarControllerFactory {
    SidecarControllerFactory::new(SPAWN_CONFIG, channel_buffer)
}
