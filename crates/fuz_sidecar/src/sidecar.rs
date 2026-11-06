//! Sidecar traits with multiplexing support
//!
//! Provides sidecar traits and a handle-based controller pattern
//! that enables concurrent request processing through a single sidecar process.

use super::{RestartResult, SidecarStatus, SidecarStatusInfo, StartResult, StopResult, ToolDef};
use crate::error::SidecarError;
use serde_json::Value;
use std::future::Future;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Sidecar trait for concurrent tool execution
///
/// Takes `&self` (not `&mut self`) because the actor pattern handles
/// internal synchronization via channels.
///
/// **Not object-safe** — methods return `impl Future` (RPITIT), so
/// `dyn` dispatch is unavailable on stable Rust. Consumed as
/// `<T: Sidecar>` bounds (or through the concrete [`SidecarHandle`]).
/// The factory-side dyn variant is [`crate::pool::SidecarFactoryDyn`].
pub trait Sidecar: Send + Sync {
    /// Call a tool asynchronously
    ///
    /// Multiple calls can be in flight concurrently - the implementation
    /// handles multiplexing and response matching.
    fn call(
        &self,
        tool: &str,
        content: &str,
        options: Option<Value>,
    ) -> impl Future<Output = Result<Value, SidecarError>> + Send;

    /// List of tools this sidecar supports
    fn tools(&self) -> &[ToolDef];

    /// Runtime name for logging
    fn runtime(&self) -> &'static str;

    /// Check if the sidecar is healthy
    fn is_alive(&self) -> bool;

    /// Shutdown the sidecar gracefully
    fn shutdown(&self) -> impl Future<Output = ()> + Send;

    /// Get per-sidecar status info (for pools with multiple sidecars)
    ///
    /// Returns empty vec for single sidecars, detailed status for pools.
    fn sidecar_status(&self) -> Vec<SidecarStatusInfo> {
        // Default: single sidecar, return basic status
        vec![SidecarStatusInfo {
            id: self.runtime().to_string(),
            runtime: self.runtime().to_string(),
            status: if self.is_alive() {
                SidecarStatus::Running
            } else {
                SidecarStatus::Unloaded
            },
            last_active_ms: None,
            uptime_ms: None,
            restart_count: 0,
            error_message: None,
            tools: self.tools().iter().map(|t| t.name.to_string()).collect(),
            version_info: None,
            description: None,
        }]
    }

    /// Start sidecars by id, or all when `None` (pool only)
    fn start_sidecars(&self, _id: Option<&str>) -> impl Future<Output = StartResult> + Send {
        async {
            StartResult {
                started: Vec::new(),
                already_running: Vec::new(),
                failed: vec!["not a pool".to_string()],
            }
        }
    }

    /// Stop sidecars by id, or all when `None` (pool only)
    fn stop_sidecars(&self, _id: Option<&str>) -> impl Future<Output = StopResult> + Send {
        async {
            StopResult {
                stopped: Vec::new(),
                already_stopped: Vec::new(),
            }
        }
    }

    /// Restart sidecars by id, or all when `None` (pool only)
    fn restart_sidecars(&self, _id: Option<&str>) -> impl Future<Output = RestartResult> + Send {
        async {
            RestartResult {
                restarted: Vec::new(),
                failed: vec!["not a pool".to_string()],
            }
        }
    }

    /// Get detailed status for sidecar(s) (pool only)
    ///
    /// # Errors
    /// Returns an error if the specified sidecar ID is unknown (pool implementation only).
    fn get_sidecar_status(
        &self,
        _id: Option<&str>,
    ) -> Result<Vec<SidecarStatusInfo>, SidecarError> {
        Ok(self.sidecar_status())
    }

    /// Get list of sidecar IDs (pool only)
    fn sidecar_ids(&self) -> Vec<&'static str> {
        vec![]
    }
}

/// Request sent from handle to actor
#[derive(Debug)]
pub struct SidecarRequest {
    pub id: u64,
    pub tool: String,
    pub content: String,
    pub options: Option<Value>,
    pub response_tx: oneshot::Sender<Result<Value, SidecarError>>,
}

/// Command sent to controller (request or control)
#[derive(Debug)]
pub enum ControllerCommand {
    Request(SidecarRequest),
    Shutdown,
}

/// Handle to communicate with a sidecar controller
///
/// Cloneable and cheaply shareable - all clones talk to the same controller.
/// Implements `Sidecar` by sending requests over a channel.
#[derive(Debug, Clone)]
pub struct SidecarHandle {
    tx: mpsc::Sender<ControllerCommand>,
    tools: &'static [ToolDef],
    runtime: &'static str,
}

impl SidecarHandle {
    /// Create a new handle with the given channel and metadata
    #[must_use]
    pub const fn new(
        tx: mpsc::Sender<ControllerCommand>,
        tools: &'static [ToolDef],
        runtime: &'static str,
    ) -> Self {
        Self { tx, tools, runtime }
    }

    /// Check if the actor channel is still open
    #[must_use]
    pub fn is_connected(&self) -> bool {
        !self.tx.is_closed()
    }
}

/// Global request ID counter for multiplexing
static NEXT_REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl Sidecar for SidecarHandle {
    async fn call(
        &self,
        tool: &str,
        content: &str,
        options: Option<Value>,
    ) -> Result<Value, SidecarError> {
        // Validate tool name before sending to sidecar
        // Internal tools (starting with __) bypass validation
        if !tool.starts_with("__") && !self.tools.iter().any(|t| t.name == tool) {
            return Err(SidecarError::UnknownTool {
                tool: tool.to_string(),
            });
        }

        let (response_tx, response_rx) = oneshot::channel();

        // Generate unique ID (monotonic across all handles)
        let id = NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let request = SidecarRequest {
            id,
            tool: tool.to_string(),
            content: content.to_string(),
            options,
            response_tx,
        };

        self.tx
            .send(ControllerCommand::Request(request))
            .await
            .map_err(|_| SidecarError::ControllerShutdown)?;

        response_rx
            .await
            .map_err(|_| SidecarError::ResponseDropped)?
    }

    fn tools(&self) -> &[ToolDef] {
        self.tools
    }

    fn runtime(&self) -> &'static str {
        self.runtime
    }

    fn is_alive(&self) -> bool {
        self.is_connected()
    }

    async fn shutdown(&self) {
        let _ = self.tx.send(ControllerCommand::Shutdown).await;
    }
}

/// Factory for spawning sidecar actors
///
/// Returns a handle and join handle for the spawned actor task.
///
/// **Not object-safe** — `spawn` returns `impl Future` (RPITIT).
/// Consumed as `<F: SidecarFactory>` bounds; see
/// [`crate::pool::SidecarFactoryDyn`] for the object-safe `Arc<dyn>`
/// variant the pool stores (blanket impl converts any `SidecarFactory`).
pub trait SidecarFactory: Send + Sync {
    /// Spawn a new sidecar actor and return handles to it
    ///
    /// Returns:
    /// - `SidecarHandle` for sending requests to the actor
    /// - `JoinHandle<()>` for monitoring actor task completion (crash detection)
    fn spawn(
        &self,
    ) -> impl Future<Output = Result<(SidecarHandle, JoinHandle<()>), SidecarError>> + Send;

    /// Runtime name
    fn runtime(&self) -> &'static str;

    /// Tools provided by this factory's sidecars
    fn tools(&self) -> &[ToolDef];
}

/// Configuration for crash recovery
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Maximum restart attempts before giving up
    pub max_restarts: u32,
    /// Time window for counting restarts
    pub window: Duration,
    /// Initial backoff duration
    pub backoff_initial: Duration,
    /// Maximum backoff duration
    pub backoff_max: Duration,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            window: Duration::from_secs(60),
            backoff_initial: Duration::from_millis(100),
            backoff_max: Duration::from_secs(5),
        }
    }
}
