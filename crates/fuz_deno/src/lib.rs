//! Deno sidecar for Fuz
//!
//! Provides JS/TypeScript tooling via Deno runtime:
//! - prettier (code formatting)
//! - svelte-parse (Svelte AST)
//! - acorn-ts-parse (TypeScript AST)
//!
//! Uses the generic controller from `fuz_sidecar`. See `docs/sidecars.md` for
//! architecture and security details.

use fuz_sidecar::{SidecarControllerFactory, SpawnConfig, ToolDef};
use std::path::Path;
use tokio::process::Command;

/// Embedded sidecar script (compiled into binary)
pub const SIDECAR_SCRIPT: &str = include_str!("../sidecar.ts");

/// Deno config for import map (ensures acorn-typescript uses same acorn instance)
pub const DENO_CONFIG: &str = r#"{"imports":{"acorn":"npm:acorn@8.15.0"}}"#;

/// Tools available in the Deno sidecar
pub const DENO_TOOLS: &[ToolDef] = &[
    ToolDef {
        name: "prettier",
        description: "Format code with Prettier",
    },
    ToolDef {
        name: "svelte-parse",
        description: "Parse Svelte source to AST",
    },
    ToolDef {
        name: "acorn-ts-parse",
        description: "Parse TypeScript source to AST",
    },
];

/// Build the Deno command for the given script and config paths.
fn build_command(script_path: &Path, config_path: Option<&Path>) -> Command {
    let mut cmd = fuz_sidecar::secure_command("deno");
    cmd.args(["run", "--allow-read", "--allow-env", "--allow-sys=cpus"]);
    if let Some(config) = config_path {
        cmd.arg(format!("--config={}", config.display()));
    }
    cmd.arg(script_path);
    cmd
}

/// Configuration for the Deno sidecar.
pub const SPAWN_CONFIG: SpawnConfig = SpawnConfig {
    runtime: "deno",
    script: SIDECAR_SCRIPT,
    config: Some(DENO_CONFIG),
    tools: DENO_TOOLS,
    build_command,
};

/// Default channel buffer size for the controller mailbox.
pub const DEFAULT_CHANNEL_BUFFER: usize = 256;

/// Create a Deno sidecar factory with default channel buffer.
#[must_use]
pub const fn factory() -> SidecarControllerFactory {
    SidecarControllerFactory::new(SPAWN_CONFIG, DEFAULT_CHANNEL_BUFFER)
}

/// Create a Deno sidecar factory with custom channel buffer size.
#[must_use]
pub const fn factory_with_buffer(channel_buffer: usize) -> SidecarControllerFactory {
    SidecarControllerFactory::new(SPAWN_CONFIG, channel_buffer)
}
