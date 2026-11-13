//! Generic sidecar controller with multiplexing
//!
//! Provides a reusable controller implementation for sidecars that communicate
//! via JSON-lines over stdio. Runtime-specific configuration is provided
//! via `SpawnConfig`.
//!
//! # Embedded scripts
//!
//! Scripts are embedded at compile time via `include_str!` and written to
//! a tempfile at spawn time. See `docs/sidecars.md` for security details.

use crate::error::SidecarError;
use crate::protocol::{WireRequest, WireResponse};
use crate::{ControllerCommand, SidecarFactory, SidecarHandle, SidecarRequest, ToolDef};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Configuration for spawning a sidecar controller.
///
/// All fields use static references for zero-cost configuration.
///
/// # Design note
///
/// `build_command` is a function pointer rather than `Box<dyn Fn>` because:
/// - Sidecars have static configuration (embedded script, fixed tools)
/// - Zero allocation, const-constructible
/// - If runtime config is needed, implement `SidecarFactory` directly
#[derive(Clone)]
pub struct SpawnConfig {
    /// Runtime identifier (e.g., "deno", "python")
    pub runtime: &'static str,
    /// Embedded script content
    pub script: &'static str,
    /// Optional config file content (e.g., deno.json for import maps)
    pub config: Option<&'static str>,
    /// Available tools
    pub tools: &'static [ToolDef],
    /// Function to build the command given script path and optional config path
    pub build_command: fn(script: &Path, config: Option<&Path>) -> Command,
}

impl std::fmt::Debug for SpawnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnConfig")
            .field("runtime", &self.runtime)
            .field("tools", &self.tools)
            .finish_non_exhaustive()
    }
}

/// Generic sidecar controller state
#[derive(Debug)]
pub struct SidecarController {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    pending: HashMap<u64, oneshot::Sender<Result<Value, SidecarError>>>,
    runtime: &'static str,
    /// Drop guard: keeps the script tempfile alive for the lifetime of the
    /// controller.
    _script_file: NamedTempFile,
    /// Drop guard: keeps the config tempfile alive for the lifetime of the
    /// controller.
    _config_file: Option<NamedTempFile>,
}

impl SidecarController {
    /// Spawn a new sidecar process with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Failed to create tempfile for script
    /// - Failed to write script to tempfile
    /// - Failed to spawn the subprocess
    pub fn spawn(config: &SpawnConfig) -> Result<Self, SidecarError> {
        // Write embedded script to tempfile
        let mut script_file = NamedTempFile::new().map_err(SidecarError::TempfileCreate)?;
        script_file
            .write_all(config.script.as_bytes())
            .map_err(SidecarError::ScriptWrite)?;

        // Write optional config file (e.g., deno.json for import maps)
        let config_file = if let Some(config_content) = config.config {
            let mut file = NamedTempFile::new().map_err(SidecarError::TempfileCreate)?;
            file.write_all(config_content.as_bytes())
                .map_err(SidecarError::ScriptWrite)?;
            Some(file)
        } else {
            None
        };

        // Build and spawn command
        let mut child = (config.build_command)(
            script_file.path(),
            config_file.as_ref().map(NamedTempFile::path),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| SidecarError::ProcessSpawn {
            runtime: config.runtime,
            source: e,
        })?;

        let stdin = child
            .stdin
            .take()
            .ok_or(SidecarError::PipeMissing { pipe: "stdin" })?;
        let stdout = child
            .stdout
            .take()
            .ok_or(SidecarError::PipeMissing { pipe: "stdout" })?;
        let stderr = child
            .stderr
            .take()
            .ok_or(SidecarError::PipeMissing { pipe: "stderr" })?;

        // Spawn task to log stderr with prefix
        let runtime = config.runtime;
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                eprintln!("[sidecar:{runtime}] {line}");
            }
        });

        Ok(Self {
            child,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
            pending: HashMap::new(),
            runtime: config.runtime,
            _script_file: script_file,
            _config_file: config_file,
        })
    }

    /// Send a request to the sidecar
    async fn send_request(&mut self, req: SidecarRequest) -> Result<(), SidecarError> {
        let wire_req = WireRequest {
            id: req.id,
            tool: req.tool,
            content: req.content,
            options: req.options,
        };

        // Store the response channel
        self.pending.insert(req.id, req.response_tx);

        // Write request as JSON line
        // Note: serialization should never fail for WireRequest, but map to Communication for safety
        let json = serde_json::to_string(&wire_req).map_err(|e| {
            SidecarError::Communication(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        self.stdin
            .write_all(json.as_bytes())
            .await
            .map_err(SidecarError::Communication)?;
        self.stdin
            .write_all(b"\n")
            .await
            .map_err(SidecarError::Communication)?;
        self.stdin
            .flush()
            .await
            .map_err(SidecarError::Communication)?;

        Ok(())
    }

    /// Read and dispatch a response from the sidecar
    ///
    /// Note: Manual `read_line` loop instead of `LinesStream` for explicit EOF
    /// handling and clearer control flow.
    async fn read_response(&mut self) -> Result<bool, SidecarError> {
        let mut line = String::new();
        let bytes_read = self
            .stdout
            .read_line(&mut line)
            .await
            .map_err(SidecarError::Communication)?;

        if bytes_read == 0 {
            // EOF - sidecar crashed
            return Ok(false);
        }

        let response: WireResponse =
            serde_json::from_str(&line).map_err(SidecarError::ResponseParse)?;

        // Find and complete the pending request
        if let Some(tx) = self.pending.remove(&response.id) {
            let result = if response.ok {
                response.output.ok_or(SidecarError::MissingOutput)
            } else {
                Err(SidecarError::ToolError {
                    message: response
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string()),
                })
            };
            // Ignore send error - receiver may have dropped
            let _ = tx.send(result);
        }

        Ok(true)
    }

    /// Fail all pending requests (e.g., on crash)
    fn fail_all_pending(&mut self, error: &SidecarError) {
        for (_, tx) in self.pending.drain() {
            // Map the shutdown cause to an appropriate error for each pending request
            let err = match error {
                SidecarError::ControllerShutdown => SidecarError::ControllerShutdown,
                SidecarError::SidecarCrashed { runtime } => {
                    SidecarError::SidecarCrashed { runtime }
                }
                _ => SidecarError::ResponseDropped,
            };
            let _ = tx.send(Err(err));
        }
    }
}

impl Drop for SidecarController {
    fn drop(&mut self) {
        // Kill the child process
        #[expect(
            clippy::let_underscore_must_use,
            reason = "`Drop` has no caller to report a failed kill to"
        )]
        let _ = self.child.start_kill();
    }
}

/// Run the sidecar controller event loop
pub async fn run_sidecar_controller(
    mut controller: SidecarController,
    mut rx: mpsc::Receiver<ControllerCommand>,
) {
    let runtime = controller.runtime;
    loop {
        tokio::select! {
            biased;

            // Prioritize incoming commands
            cmd = rx.recv() => {
                match cmd {
                    Some(ControllerCommand::Request(req)) => {
                        if let Err(e) = controller.send_request(req).await {
                            eprintln!("Failed to send request to sidecar: {e}");
                            break;
                        }
                    }
                    Some(ControllerCommand::Shutdown) | None => {
                        controller.fail_all_pending(&SidecarError::ControllerShutdown);
                        break;
                    }
                }
            }

            // Read responses from sidecar
            result = controller.read_response() => {
                match result {
                    Ok(true) => {} // Response handled
                    Ok(false) => {
                        eprintln!("{runtime} sidecar process exited unexpectedly");
                        controller.fail_all_pending(&SidecarError::SidecarCrashed { runtime });
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error reading from sidecar: {e}");
                        controller.fail_all_pending(&SidecarError::ResponseDropped);
                        break;
                    }
                }
            }
        }
    }
}

/// Generic factory for spawning sidecar controllers.
///
/// Implements `SidecarFactory` using `SpawnConfig` for runtime-specific behavior.
#[derive(Debug, Clone)]
pub struct SidecarControllerFactory {
    config: SpawnConfig,
    channel_buffer: usize,
}

impl SidecarControllerFactory {
    /// Create a new factory with the given configuration.
    #[must_use]
    pub const fn new(config: SpawnConfig, channel_buffer: usize) -> Self {
        Self {
            config,
            channel_buffer,
        }
    }
}

impl SidecarFactory for SidecarControllerFactory {
    #[expect(
        clippy::unused_async_trait_impl,
        reason = "trait conformance: the `impl Future` rewrite would spawn the controller process and channel at call time, before the future is awaited"
    )]
    async fn spawn(&self) -> Result<(SidecarHandle, JoinHandle<()>), SidecarError> {
        let controller = SidecarController::spawn(&self.config)?;

        let (tx, rx) = mpsc::channel(self.channel_buffer);
        let handle = SidecarHandle::new(tx, self.config.tools, self.config.runtime);

        let join_handle = tokio::spawn(run_sidecar_controller(controller, rx));

        Ok((handle, join_handle))
    }

    fn runtime(&self) -> &'static str {
        self.config.runtime
    }

    fn tools(&self) -> &[ToolDef] {
        self.config.tools
    }
}
