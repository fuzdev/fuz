//! Multi-sidecar pool with lazy loading and idle shutdown
//!
//! Manages multiple sidecars (Deno, Python, etc.) with:
//! - Lazy loading: spawn on first tool request
//! - Idle shutdown: automatic shutdown after inactivity
//! - Unified tool routing: routes by tool name to correct sidecar
//!
//! TODO: If a second pooled resource type emerges, consider extracting common
//! helpers (state machine, idle monitoring, crash recovery) to a base module.

use crate::error::SidecarError;
use crate::{RecoveryConfig, Sidecar, SidecarFactory, SidecarHandle, ToolDef};
use futures::future::{BoxFuture, join_all};
use fuz_wire::{RestartResult, SidecarStatus, SidecarStatusInfo, StartResult, StopResult};
use parking_lot::RwLock;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

// Recovery configuration defaults
const DEFAULT_MAX_RESTARTS: u32 = 3;
const RECOVERY_WINDOW_SECS: u64 = 60;
const RECOVERY_BACKOFF_INITIAL_MS: u64 = 100;
const RECOVERY_BACKOFF_MAX_SECS: u64 = 5;

// Idle monitoring
const IDLE_CHECK_INTERVAL_SECS: u64 = 5;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

/// Configuration for a sidecar in the pool
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    /// Unique identifier (e.g., "deno", "python")
    pub id: &'static str,
    /// Idle timeout before auto-shutdown (default: 30s)
    pub idle_timeout: Duration,
    /// Crash recovery settings
    pub recovery: RecoveryConfig,
    /// What to do after max restarts exceeded
    pub on_failure: FailurePolicy,
}

impl SidecarConfig {
    /// Create config with default settings
    #[must_use]
    pub const fn new(id: &'static str) -> Self {
        Self {
            id,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            recovery: RecoveryConfig {
                max_restarts: DEFAULT_MAX_RESTARTS,
                window: Duration::from_secs(RECOVERY_WINDOW_SECS),
                backoff_initial: Duration::from_millis(RECOVERY_BACKOFF_INITIAL_MS),
                backoff_max: Duration::from_secs(RECOVERY_BACKOFF_MAX_SECS),
            },
            on_failure: FailurePolicy::RetryOnNextCall,
        }
    }

    /// Set idle timeout
    #[must_use]
    pub const fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set failure policy
    #[must_use]
    pub const fn with_failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.on_failure = policy;
        self
    }
}

/// What to do after max restarts exceeded
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FailurePolicy {
    /// Reset to Unloaded on next call, try again (resilient)
    #[default]
    RetryOnNextCall,
    /// Stay in Failed state until daemon restart (safe)
    StayFailed,
}

/// Object-safe factory trait for dynamic dispatch.
///
/// **Object-safe** — consumed as `Arc<dyn SidecarFactoryDyn>` by the
/// pool. Blanket impl is provided for every `SidecarFactory` so callers
/// don't author this directly. Async via `BoxFuture`, the
/// dyn-trait convention.
pub trait SidecarFactoryDyn: Send + Sync {
    /// Spawn a new sidecar (boxed future for object safety)
    fn spawn_dyn(&self) -> BoxFuture<'_, Result<(SidecarHandle, JoinHandle<()>), SidecarError>>;
    /// Runtime name
    fn runtime(&self) -> &'static str;
    /// Tools provided by this factory
    fn tools(&self) -> &[ToolDef];
}

/// Blanket implementation for all `SidecarFactory` types
impl<F: SidecarFactory + 'static> SidecarFactoryDyn for F {
    fn spawn_dyn(&self) -> BoxFuture<'_, Result<(SidecarHandle, JoinHandle<()>), SidecarError>> {
        Box::pin(self.spawn())
    }

    fn runtime(&self) -> &'static str {
        SidecarFactory::runtime(self)
    }

    fn tools(&self) -> &[ToolDef] {
        SidecarFactory::tools(self)
    }
}

/// Action to take after checking sidecar state
enum LoadAction {
    /// Already running, return handle
    Ready(SidecarHandle),
    /// Wait for an in-progress load to complete
    WaitForLoad(Arc<Notify>),
    /// Need to spawn the sidecar
    Spawn(Arc<Notify>),
    /// Sidecar is in failed state
    Failed(String),
    /// Unknown sidecar
    Unknown,
}

/// Internal state of a managed sidecar
enum SidecarState {
    /// Not started, will spawn on first request
    Unloaded,
    /// Currently spawning (another task is doing the spawn)
    Loading,
    /// Running and accepting requests
    Running {
        handle: SidecarHandle,
        started_at: Instant,
        last_activity: Instant,
        restart_count: u32,
    },
    /// Shutting down due to idle timeout
    ShuttingDown,
    /// Failed after max restarts
    Failed { message: String, restart_count: u32 },
}

impl SidecarState {
    /// Get status for reporting
    const fn status(&self) -> SidecarStatus {
        match self {
            Self::Unloaded => SidecarStatus::Unloaded,
            Self::Loading => SidecarStatus::Loading,
            Self::Running { .. } => SidecarStatus::Running,
            Self::ShuttingDown => SidecarStatus::ShuttingDown,
            Self::Failed { .. } => SidecarStatus::Failed,
        }
    }
}

/// Entry for a sidecar in the pool
struct PoolEntry {
    state: SidecarState,
    factory: Arc<dyn SidecarFactoryDyn>,
    config: SidecarConfig,
    /// Notifies waiters when spawn completes (success or failure)
    spawn_complete: Arc<Notify>,
    /// Cancellation token for the current monitor task (if running)
    /// Cancelled on intentional shutdown to distinguish from crash
    monitor_shutdown: CancellationToken,
    /// Cached version info from `__version_info` call
    version_info: Option<fuz_wire::VersionInfo>,
}

/// Build status info from a pool entry
#[expect(
    clippy::cast_possible_truncation,
    reason = "a running sidecar's elapsed milliseconds stay far below `u64::MAX`"
)]
fn build_status_info(id: &str, entry: &PoolEntry) -> SidecarStatusInfo {
    let (last_active_ms, uptime_ms, restart_count, error_message) = match &entry.state {
        SidecarState::Running {
            started_at,
            last_activity,
            restart_count,
            ..
        } => (
            Some(last_activity.elapsed().as_millis() as u64),
            Some(started_at.elapsed().as_millis() as u64),
            *restart_count,
            None,
        ),
        SidecarState::Failed {
            message,
            restart_count,
        } => (None, None, *restart_count, Some(message.clone())),
        _ => (None, None, 0, None),
    };

    SidecarStatusInfo {
        id: id.to_string(),
        runtime: entry.factory.runtime().to_string(),
        status: entry.state.status(),
        last_active_ms,
        uptime_ms,
        restart_count,
        error_message,
        tools: entry
            .factory
            .tools()
            .iter()
            .map(|t| t.name.to_string())
            .collect(),
        description: None,
        version_info: entry.version_info.clone(),
    }
}

/// Multi-sidecar pool with lazy loading and idle shutdown
pub struct SidecarPool {
    /// Map from sidecar ID to entry
    sidecars: RwLock<HashMap<&'static str, PoolEntry>>,
    /// Map from tool name to sidecar ID for routing
    tool_map: HashMap<&'static str, &'static str>,
    /// Combined tools from all sidecars
    all_tools: Vec<ToolDef>,
    /// Shutdown token for idle monitor
    shutdown: CancellationToken,
    /// Handle to idle monitor task
    _monitor_handle: JoinHandle<()>,
    /// Weak self-reference for spawning monitor tasks
    self_ref: std::sync::Weak<Self>,
}

impl std::fmt::Debug for SidecarPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SidecarPool")
            .field("tool_map", &self.tool_map)
            .field("all_tools", &self.all_tools)
            .finish_non_exhaustive()
    }
}

impl SidecarPool {
    /// Create a new sidecar pool
    ///
    /// # Arguments
    /// * `configs` - List of (factory, config) pairs for each sidecar
    pub fn new(configs: Vec<(Arc<dyn SidecarFactoryDyn>, SidecarConfig)>) -> Arc<Self> {
        let mut sidecars = HashMap::new();
        let mut tool_map = HashMap::new();
        let mut all_tools = Vec::new();

        for (factory, config) in configs {
            // Build tool map
            for tool in factory.tools() {
                tool_map.insert(tool.name, config.id);
                all_tools.push(tool.clone());
            }

            // Create pool entry
            sidecars.insert(
                config.id,
                PoolEntry {
                    state: SidecarState::Unloaded,
                    factory,
                    config,
                    spawn_complete: Arc::new(Notify::new()),
                    monitor_shutdown: CancellationToken::new(),
                    version_info: None,
                },
            );
        }

        let shutdown = CancellationToken::new();

        // Create pool with monitor
        Arc::new_cyclic(|weak| {
            let weak_pool = std::sync::Weak::clone(weak);
            let monitor_shutdown = shutdown.clone();
            let monitor_handle = tokio::spawn(async move {
                Self::idle_monitor_loop(weak_pool, monitor_shutdown).await;
            });

            Self {
                sidecars: RwLock::new(sidecars),
                tool_map,
                all_tools,
                shutdown,
                _monitor_handle: monitor_handle,
                self_ref: std::sync::Weak::clone(weak),
            }
        })
    }

    /// Background task that checks for idle sidecars
    async fn idle_monitor_loop(pool: std::sync::Weak<Self>, shutdown: CancellationToken) {
        let check_interval = Duration::from_secs(IDLE_CHECK_INTERVAL_SECS);

        loop {
            tokio::select! {
                () = tokio::time::sleep(check_interval) => {
                    if let Some(pool) = pool.upgrade() {
                        pool.check_idle_sidecars().await;
                    } else {
                        // Pool dropped, exit
                        return;
                    }
                }
                () = shutdown.cancelled() => {
                    return;
                }
            }
        }
    }

    /// Check for and shutdown idle sidecars
    async fn check_idle_sidecars(&self) {
        let now = Instant::now();
        let mut to_shutdown = Vec::new();

        // Identify idle sidecars (read lock)
        {
            let guard = self.sidecars.read();
            for (id, entry) in guard.iter() {
                if let SidecarState::Running { last_activity, .. } = &entry.state
                    && now.duration_since(*last_activity) > entry.config.idle_timeout
                {
                    to_shutdown.push(*id);
                }
            }
        }

        // Shutdown idle sidecars in parallel
        for id in &to_shutdown {
            eprintln!("Sidecar {id}: idle timeout, shutting down");
        }
        join_all(to_shutdown.iter().map(|id| self.shutdown_sidecar(id))).await;
    }

    /// Shutdown a specific sidecar
    async fn shutdown_sidecar(&self, id: &str) {
        // Get handle, cancel monitor, and mark as shutting down
        let handle = {
            let mut guard = self.sidecars.write();
            if let Some(entry) = guard.get_mut(id) {
                if let SidecarState::Running { handle, .. } = &entry.state {
                    let h = handle.clone();
                    // Cancel monitor BEFORE shutdown so it knows this is intentional
                    entry.monitor_shutdown.cancel();
                    entry.state = SidecarState::ShuttingDown;
                    Some(h)
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Shutdown outside lock
        if let Some(handle) = handle {
            handle.shutdown().await;
        }

        // Mark as unloaded
        {
            let mut guard = self.sidecars.write();
            if let Some(entry) = guard.get_mut(id)
                && matches!(entry.state, SidecarState::ShuttingDown)
            {
                entry.state = SidecarState::Unloaded;
            }
        }
    }

    /// Find sidecar ID for a tool name
    #[must_use]
    pub fn sidecar_for_tool(&self, tool_name: &str) -> Option<&'static str> {
        self.tool_map.get(tool_name).copied()
    }

    /// Get status info for all sidecars
    #[must_use]
    pub fn status(&self) -> Vec<SidecarStatusInfo> {
        let guard = self.sidecars.read();
        guard
            .iter()
            .map(|(id, entry)| build_status_info(id, entry))
            .collect()
    }

    /// Ensure a sidecar is loaded, spawning if necessary
    #[expect(clippy::option_if_let_else, reason = "more readable as if-let")]
    async fn ensure_loaded(&self, sidecar_id: &str) -> Result<SidecarHandle, SidecarError> {
        loop {
            // Check current state (read lock, released before any await)
            let action = {
                let guard = self.sidecars.read();
                if let Some(entry) = guard.get(sidecar_id) {
                    let notify = Arc::clone(&entry.spawn_complete);
                    match &entry.state {
                        SidecarState::Running { handle, .. } => LoadAction::Ready(handle.clone()),
                        SidecarState::Loading => {
                            // Another task is spawning, wait for notification
                            LoadAction::WaitForLoad(notify)
                        }
                        SidecarState::Failed { message, .. } => {
                            let policy = entry.config.on_failure;
                            if policy == FailurePolicy::StayFailed {
                                LoadAction::Failed(message.clone())
                            } else {
                                // RetryOnNextCall: spawn
                                LoadAction::Spawn(notify)
                            }
                        }
                        SidecarState::Unloaded | SidecarState::ShuttingDown => {
                            LoadAction::Spawn(notify)
                        }
                    }
                } else {
                    LoadAction::Unknown
                }
            };
            // Guard dropped here

            match action {
                LoadAction::Ready(handle) => return Ok(handle),
                LoadAction::WaitForLoad(notify) => {
                    // Wait for spawning task to complete
                    notify.notified().await;
                }
                LoadAction::Spawn(notify) => {
                    // Try to claim the spawn
                    if self.try_start_spawn(sidecar_id) {
                        return self.do_spawn(sidecar_id, notify).await;
                    }
                    // Another task claimed it, wait for notification
                    notify.notified().await;
                }
                LoadAction::Failed(message) => {
                    return Err(SidecarError::SidecarFailed {
                        id: sidecar_id.to_string(),
                        message,
                    });
                }
                LoadAction::Unknown => {
                    return Err(SidecarError::UnknownSidecar {
                        id: sidecar_id.to_string(),
                    });
                }
            }
        }
    }

    /// Try to claim the spawn for a sidecar (returns true if we should spawn)
    fn try_start_spawn(&self, sidecar_id: &str) -> bool {
        let mut guard = self.sidecars.write();
        if let Some(entry) = guard.get_mut(sidecar_id) {
            match &entry.state {
                SidecarState::Unloaded | SidecarState::ShuttingDown => {
                    entry.state = SidecarState::Loading;
                    true
                }
                SidecarState::Failed { .. }
                    if entry.config.on_failure == FailurePolicy::RetryOnNextCall =>
                {
                    entry.state = SidecarState::Loading;
                    true
                }
                _ => false,
            }
        } else {
            false
        }
    }

    /// Actually spawn a sidecar (called after claiming the spawn)
    async fn do_spawn(
        &self,
        sidecar_id: &str,
        notify: Arc<Notify>,
    ) -> Result<SidecarHandle, SidecarError> {
        // Get factory and create fresh monitor token (write lock, brief)
        let (factory, monitor_shutdown, recovery_config) = {
            let mut guard = self.sidecars.write();
            let entry = guard
                .get_mut(sidecar_id)
                .ok_or_else(|| SidecarError::UnknownSidecar {
                    id: sidecar_id.to_string(),
                })?;

            // Fresh token for this session
            entry.monitor_shutdown = CancellationToken::new();

            (
                Arc::clone(&entry.factory),
                entry.monitor_shutdown.clone(),
                entry.config.recovery.clone(),
            )
        };

        // Spawn outside lock
        let result = factory.spawn_dyn().await;

        // Update state based on result
        let mut guard = self.sidecars.write();
        let spawn_result = if let Some(entry) = guard.get_mut(sidecar_id) {
            match result {
                Ok((handle, join_handle)) => {
                    let now = Instant::now();
                    entry.state = SidecarState::Running {
                        handle: handle.clone(),
                        started_at: now,
                        last_activity: now,
                        restart_count: 0,
                    };

                    // Fetch version info in the background (non-blocking)
                    let handle_clone = handle.clone();
                    let sidecar_id_str = sidecar_id.to_string();
                    let weak_pool = std::sync::Weak::clone(&self.self_ref);
                    tokio::spawn(async move {
                        // Version info is non-critical; errors are silently ignored
                        let Ok(response) = handle_clone.call("__version_info", "", None).await
                        else {
                            return;
                        };
                        let Ok(version_info) =
                            serde_json::from_value::<fuz_wire::VersionInfo>(response)
                        else {
                            return;
                        };
                        // Cache the version info
                        if let Some(pool) = weak_pool.upgrade() {
                            let mut guard = pool.sidecars.write();
                            if let Some(entry) = guard.get_mut(sidecar_id_str.as_str()) {
                                entry.version_info = Some(version_info);
                            }
                        }
                    });

                    // Spawn monitor task to detect crashes
                    let weak_pool = std::sync::Weak::clone(&self.self_ref);
                    let sidecar_id = sidecar_id.to_string();
                    tokio::spawn(Self::run_crash_monitor(
                        weak_pool,
                        sidecar_id,
                        join_handle,
                        monitor_shutdown,
                        recovery_config,
                    ));

                    Ok(handle)
                }
                Err(e) => {
                    entry.state = SidecarState::Failed {
                        message: e.to_string(),
                        restart_count: 1,
                    };
                    Err(e)
                }
            }
        } else {
            Err(SidecarError::SidecarDisappeared {
                id: sidecar_id.to_string(),
                operation: "spawn",
            })
        };

        // Release lock before notifying to avoid holding it while waiters wake
        drop(guard);

        // Wake all tasks waiting for this spawn to complete
        notify.notify_waiters();

        spawn_result
    }

    /// Monitor task that detects sidecar crashes and triggers recovery
    async fn run_crash_monitor(
        pool: std::sync::Weak<Self>,
        sidecar_id: String,
        mut controller_task: JoinHandle<()>,
        shutdown: CancellationToken,
        config: RecoveryConfig,
    ) {
        let mut restart_times: Vec<Instant> = Vec::new();
        let mut backoff = config.backoff_initial;

        loop {
            tokio::select! {
                // Controller task completed = crash or normal exit
                _ = &mut controller_task => {
                    // Check if this was a requested shutdown
                    if shutdown.is_cancelled() {
                        return;
                    }

                    let Some(pool) = pool.upgrade() else {
                        // Pool dropped, nothing to do
                        return;
                    };

                    eprintln!("Sidecar {sidecar_id}: crashed, attempting recovery...");

                    // Check restart window
                    let now = Instant::now();
                    restart_times.retain(|t| now.duration_since(*t) < config.window);

                    if restart_times.len() >= config.max_restarts as usize {
                        eprintln!(
                            "Sidecar {sidecar_id}: max restarts ({}) exceeded in {:?} window, giving up",
                            config.max_restarts,
                            config.window
                        );
                        pool.mark_failed(&sidecar_id, "max restarts exceeded");
                        return;
                    }

                    restart_times.push(now);

                    // Backoff before respawn
                    eprintln!(
                        "Sidecar {sidecar_id}: waiting {backoff:?} before respawn (attempt {}/{})",
                        restart_times.len(),
                        config.max_restarts
                    );

                    tokio::select! {
                        () = tokio::time::sleep(backoff) => {}
                        () = shutdown.cancelled() => {
                            eprintln!("Sidecar {sidecar_id}: shutdown during recovery backoff");
                            return;
                        }
                    }

                    // Attempt respawn
                    match pool.respawn_crashed(&sidecar_id).await {
                        Ok(new_task) => {
                            eprintln!("Sidecar {sidecar_id}: respawn successful");
                            controller_task = new_task;
                            backoff = config.backoff_initial; // Reset on success
                        }
                        Err(e) => {
                            eprintln!("Sidecar {sidecar_id}: respawn failed: {e}");
                            backoff = (backoff * 2).min(config.backoff_max);
                            // Continue loop to retry after next backoff
                            // Create a dummy task that completes immediately to trigger retry
                            controller_task = tokio::spawn(async {});
                        }
                    }
                }

                // Shutdown signal
                () = shutdown.cancelled() => {
                    return;
                }
            }
        }
    }

    /// Mark a sidecar as failed (called by crash monitor)
    fn mark_failed(&self, sidecar_id: &str, message: &str) {
        let mut guard = self.sidecars.write();
        if let Some(entry) = guard.get_mut(sidecar_id) {
            let restart_count = match &entry.state {
                SidecarState::Running { restart_count, .. }
                | SidecarState::Failed { restart_count, .. } => *restart_count,
                _ => 0,
            };
            entry.state = SidecarState::Failed {
                message: message.to_string(),
                restart_count,
            };
            // Notify any waiters that spawn "completed" (with failure)
            entry.spawn_complete.notify_waiters();
        }
    }

    /// Respawn a crashed sidecar (called by crash monitor)
    ///
    /// Returns the new `JoinHandle` for the monitor to track.
    async fn respawn_crashed(&self, sidecar_id: &str) -> Result<JoinHandle<()>, SidecarError> {
        // Get factory and set state to Loading
        let factory = {
            let mut guard = self.sidecars.write();
            let entry = guard
                .get_mut(sidecar_id)
                .ok_or_else(|| SidecarError::UnknownSidecar {
                    id: sidecar_id.to_string(),
                })?;

            // Get current restart_count before changing state
            let restart_count = match &entry.state {
                SidecarState::Running { restart_count, .. } => *restart_count,
                _ => 0,
            };

            entry.state = SidecarState::Loading;
            (Arc::clone(&entry.factory), restart_count)
        };

        let (factory, restart_count) = factory;

        // Spawn outside lock
        let result = factory.spawn_dyn().await;

        // Update state
        let mut guard = self.sidecars.write();
        let entry = guard
            .get_mut(sidecar_id)
            .ok_or_else(|| SidecarError::SidecarDisappeared {
                id: sidecar_id.to_string(),
                operation: "respawn",
            })?;

        match result {
            Ok((handle, join_handle)) => {
                let now = Instant::now();
                entry.state = SidecarState::Running {
                    handle,
                    started_at: now,
                    last_activity: now,
                    restart_count: restart_count + 1,
                };
                entry.spawn_complete.notify_waiters();
                Ok(join_handle)
            }
            Err(e) => {
                // Stay in Loading state, let monitor retry
                Err(e)
            }
        }
    }

    /// Record activity for a sidecar (resets idle timer)
    pub fn record_activity(&self, sidecar_id: &str) {
        let mut guard = self.sidecars.write();
        if let Some(entry) = guard.get_mut(sidecar_id)
            && let SidecarState::Running { last_activity, .. } = &mut entry.state
        {
            *last_activity = Instant::now();
        }
    }

    /// Shutdown all sidecars
    pub async fn shutdown_all(&self) {
        // Signal idle monitor to stop
        self.shutdown.cancel();

        // Cancel all per-sidecar monitors and collect handles
        let handles: Vec<_> = {
            let guard = self.sidecars.read();
            guard
                .values()
                .filter_map(|entry| {
                    if let SidecarState::Running { handle, .. } = &entry.state {
                        // Cancel crash monitor so it knows this is intentional
                        entry.monitor_shutdown.cancel();
                        Some(handle.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        // Shutdown all in parallel
        join_all(handles.iter().map(SidecarHandle::shutdown)).await;
    }

    /// Get list of all sidecar IDs
    #[must_use]
    pub fn sidecar_ids(&self) -> Vec<&'static str> {
        self.sidecars.read().keys().copied().collect()
    }

    /// Start a sidecar (trigger lazy load)
    ///
    /// Returns true if started, false if already running.
    ///
    /// # Errors
    /// Returns an error if the sidecar ID is unknown or if loading fails.
    pub async fn start_sidecar(&self, id: &str) -> Result<bool, SidecarError> {
        // Check if already running
        {
            let guard = self.sidecars.read();
            if let Some(entry) = guard.get(id) {
                if matches!(entry.state, SidecarState::Running { .. }) {
                    return Ok(false); // Already running
                }
            } else {
                return Err(SidecarError::UnknownSidecar { id: id.to_string() });
            }
        }

        // Start it
        self.ensure_loaded(id).await?;
        Ok(true)
    }

    /// Stop a sidecar
    ///
    /// Returns true if stopped, false if already stopped.
    ///
    /// # Errors
    /// Returns an error if the sidecar ID is unknown.
    pub async fn stop_sidecar(&self, id: &str) -> Result<bool, SidecarError> {
        // Check if running
        {
            let guard = self.sidecars.read();
            if let Some(entry) = guard.get(id) {
                if !matches!(entry.state, SidecarState::Running { .. }) {
                    return Ok(false); // Already stopped
                }
            } else {
                return Err(SidecarError::UnknownSidecar { id: id.to_string() });
            }
        }

        // Stop it
        self.shutdown_sidecar(id).await;
        Ok(true)
    }

    /// Restart a sidecar
    ///
    /// # Errors
    /// Returns an error if the sidecar ID is unknown or if loading fails.
    pub async fn restart_sidecar(&self, id: &str) -> Result<(), SidecarError> {
        // Validate exists
        {
            let guard = self.sidecars.read();
            if !guard.contains_key(id) {
                return Err(SidecarError::UnknownSidecar { id: id.to_string() });
            }
        }

        // Stop if running
        self.shutdown_sidecar(id).await;
        // Start
        self.ensure_loaded(id).await?;
        Ok(())
    }

    /// Start sidecars by id, or all when `None`
    pub async fn start_sidecars(&self, id: Option<&str>) -> StartResult {
        let ids: Vec<&str> =
            id.map_or_else(|| self.sidecar_ids().into_iter().collect(), |one| vec![one]);

        let mut result = StartResult {
            started: Vec::new(),
            already_running: Vec::new(),
            failed: Vec::new(),
        };

        // Start all in parallel
        let results = join_all(
            ids.iter()
                .map(|id| async move { (*id, self.start_sidecar(id).await) }),
        )
        .await;

        for (sidecar_id, res) in results {
            match res {
                Ok(true) => result.started.push(sidecar_id.to_string()),
                Ok(false) => result.already_running.push(sidecar_id.to_string()),
                Err(_) => result.failed.push(sidecar_id.to_string()),
            }
        }

        result
    }

    /// Stop sidecars by id, or all when `None`
    pub async fn stop_sidecars(&self, id: Option<&str>) -> StopResult {
        let ids: Vec<&str> =
            id.map_or_else(|| self.sidecar_ids().into_iter().collect(), |one| vec![one]);

        let mut result = StopResult {
            stopped: Vec::new(),
            already_stopped: Vec::new(),
        };

        // Stop all in parallel
        let results = join_all(
            ids.iter()
                .map(|id| async move { (*id, self.stop_sidecar(id).await) }),
        )
        .await;

        for (sidecar_id, res) in results {
            match res {
                Ok(true) => result.stopped.push(sidecar_id.to_string()),
                Ok(false) | Err(_) => result.already_stopped.push(sidecar_id.to_string()),
            }
        }

        result
    }

    /// Restart sidecars by id, or all when `None`
    pub async fn restart_sidecars(&self, id: Option<&str>) -> RestartResult {
        let ids: Vec<&str> =
            id.map_or_else(|| self.sidecar_ids().into_iter().collect(), |one| vec![one]);

        let mut result = RestartResult {
            restarted: Vec::new(),
            failed: Vec::new(),
        };

        // Restart all in parallel
        let results = join_all(
            ids.iter()
                .map(|id| async move { (*id, self.restart_sidecar(id).await) }),
        )
        .await;

        for (sidecar_id, res) in results {
            match res {
                Ok(()) => result.restarted.push(sidecar_id.to_string()),
                Err(_) => result.failed.push(sidecar_id.to_string()),
            }
        }

        result
    }

    /// Get detailed status for a specific sidecar or all
    ///
    /// # Errors
    /// Returns an error if the specified sidecar ID is unknown.
    pub fn get_status(&self, id: Option<&str>) -> Result<Vec<SidecarStatusInfo>, SidecarError> {
        let guard = self.sidecars.read();

        let Some(id) = id else {
            return Ok(guard
                .iter()
                .map(|(id, entry)| build_status_info(id, entry))
                .collect());
        };

        guard
            .get(id)
            .map(|entry| vec![build_status_info(id, entry)])
            .ok_or_else(|| SidecarError::UnknownSidecar { id: id.to_string() })
    }
}

impl Sidecar for SidecarPool {
    async fn call(
        &self,
        tool: &str,
        content: &str,
        options: Option<Value>,
    ) -> Result<Value, SidecarError> {
        let sidecar_id = self
            .sidecar_for_tool(tool)
            .ok_or_else(|| SidecarError::UnknownTool {
                tool: tool.to_string(),
            })?;

        // Get or load the sidecar
        let handle = self.ensure_loaded(sidecar_id).await?;

        // Record activity for idle timer
        self.record_activity(sidecar_id);

        // Delegate to the sidecar
        handle.call(tool, content, options).await
    }

    fn tools(&self) -> &[ToolDef] {
        &self.all_tools
    }

    fn runtime(&self) -> &'static str {
        "pool"
    }

    fn is_alive(&self) -> bool {
        true // Pool is always "alive", individual sidecars may not be
    }

    async fn shutdown(&self) {
        self.shutdown_all().await;
    }

    fn sidecar_status(&self) -> Vec<SidecarStatusInfo> {
        self.status()
    }

    async fn start_sidecars(&self, id: Option<&str>) -> StartResult {
        Self::start_sidecars(self, id).await
    }

    async fn stop_sidecars(&self, id: Option<&str>) -> StopResult {
        Self::stop_sidecars(self, id).await
    }

    async fn restart_sidecars(&self, id: Option<&str>) -> RestartResult {
        Self::restart_sidecars(self, id).await
    }

    fn get_sidecar_status(&self, id: Option<&str>) -> Result<Vec<SidecarStatusInfo>, SidecarError> {
        Self::get_status(self, id)
    }

    fn sidecar_ids(&self) -> Vec<&'static str> {
        Self::sidecar_ids(self)
    }
}

impl Sidecar for Arc<SidecarPool> {
    async fn call(
        &self,
        tool: &str,
        content: &str,
        options: Option<Value>,
    ) -> Result<Value, SidecarError> {
        (**self).call(tool, content, options).await
    }

    fn tools(&self) -> &[ToolDef] {
        (**self).tools()
    }

    fn runtime(&self) -> &'static str {
        (**self).runtime()
    }

    fn is_alive(&self) -> bool {
        (**self).is_alive()
    }

    async fn shutdown(&self) {
        (**self).shutdown().await;
    }

    fn sidecar_status(&self) -> Vec<SidecarStatusInfo> {
        (**self).sidecar_status()
    }

    async fn start_sidecars(&self, id: Option<&str>) -> StartResult {
        (**self).start_sidecars(id).await
    }

    async fn stop_sidecars(&self, id: Option<&str>) -> StopResult {
        (**self).stop_sidecars(id).await
    }

    async fn restart_sidecars(&self, id: Option<&str>) -> RestartResult {
        (**self).restart_sidecars(id).await
    }

    fn get_sidecar_status(&self, id: Option<&str>) -> Result<Vec<SidecarStatusInfo>, SidecarError> {
        (**self).get_sidecar_status(id)
    }

    fn sidecar_ids(&self) -> Vec<&'static str> {
        (**self).sidecar_ids()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControllerCommand;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::{broadcast, mpsc};

    /// Test tool info
    static TEST_TOOLS: &[ToolDef] = &[ToolDef {
        name: "test-tool",
        description: "Test tool",
    }];

    /// Factory that spawns controllers which can be crashed via broadcast channel
    struct TestFactory {
        /// Send to crash the current controller (all subscribers receive)
        crash_tx: broadcast::Sender<()>,
        /// Count of spawns
        spawn_count: Arc<AtomicU32>,
    }

    impl TestFactory {
        fn new() -> (Self, broadcast::Sender<()>) {
            let (crash_tx, _) = broadcast::channel(16);
            let factory = Self {
                crash_tx: crash_tx.clone(),
                spawn_count: Arc::new(AtomicU32::new(0)),
            };
            (factory, crash_tx)
        }
    }

    impl SidecarFactory for TestFactory {
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "trait conformance: an `async fn` body runs when awaited; the `impl Future` rewrite would run it at call time"
        )]
        async fn spawn(&self) -> Result<(SidecarHandle, JoinHandle<()>), SidecarError> {
            self.spawn_count.fetch_add(1, Ordering::SeqCst);

            // Create a channel for the handle
            let (tx, mut rx) = mpsc::channel::<ControllerCommand>(16);

            // Each controller gets its own crash receiver by subscribing
            let mut crash_rx = self.crash_tx.subscribe();

            let join_handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        cmd = rx.recv() => {
                            match cmd {
                                Some(ControllerCommand::Shutdown) | None => return,
                                Some(ControllerCommand::Request(req)) => {
                                    // Echo back success
                                    let _ = req.response_tx.send(Ok(Value::String("ok".to_string())));
                                }
                            }
                        }
                        _ = crash_rx.recv() => {
                            // Simulate crash by just returning
                            return;
                        }
                    }
                }
            });

            let handle = SidecarHandle::new(tx, TEST_TOOLS, "test");
            Ok((handle, join_handle))
        }

        fn runtime(&self) -> &'static str {
            "test"
        }

        fn tools(&self) -> &[ToolDef] {
            TEST_TOOLS
        }
    }

    #[tokio::test]
    async fn test_crash_recovery() {
        // Create factory with crash signal
        let (factory, crash_signal) = TestFactory::new();
        let spawn_count = Arc::clone(&factory.spawn_count);

        // Create pool with short recovery backoff for fast tests
        let config = SidecarConfig::new("test").with_idle_timeout(Duration::from_secs(300)); // Long idle so it doesn't interfere

        let pool = SidecarPool::new(vec![(Arc::new(factory), config)]);

        // Start the sidecar
        let result = pool.start_sidecar("test").await;
        assert!(result.is_ok());
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);

        // Verify it's running
        let status = pool.get_status(Some("test")).unwrap();
        assert_eq!(status[0].status, SidecarStatus::Running);
        assert_eq!(status[0].restart_count, 0);

        // Signal crash (send to all current subscribers)
        let _ = crash_signal.send(());

        // Wait for recovery (backoff is 100ms by default)
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Verify respawn happened
        assert_eq!(spawn_count.load(Ordering::SeqCst), 2);

        // Verify status shows restart
        let status = pool.get_status(Some("test")).unwrap();
        assert_eq!(status[0].status, SidecarStatus::Running);
        assert_eq!(status[0].restart_count, 1);

        // Cleanup
        pool.shutdown_all().await;
    }

    #[tokio::test]
    async fn test_intentional_shutdown_no_recovery() {
        // Create factory with crash signal
        let (factory, _crash_signal) = TestFactory::new();
        let spawn_count = Arc::clone(&factory.spawn_count);

        let config = SidecarConfig::new("test").with_idle_timeout(Duration::from_secs(300));

        let pool = SidecarPool::new(vec![(Arc::new(factory), config)]);

        // Start the sidecar
        pool.start_sidecar("test").await.unwrap();
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);

        // Intentional shutdown (not crash)
        pool.stop_sidecar("test").await.unwrap();

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify NO respawn happened (intentional shutdown should not trigger recovery)
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);

        // Verify status is Unloaded
        let status = pool.get_status(Some("test")).unwrap();
        assert_eq!(status[0].status, SidecarStatus::Unloaded);

        pool.shutdown_all().await;
    }
}
