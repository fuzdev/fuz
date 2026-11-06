//! Batched request logging

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Debounce duration - wait for activity to settle
const LOG_DEBOUNCE: Duration = Duration::from_millis(150);

/// Throttle duration - max wait time before forced flush
const LOG_THROTTLE: Duration = Duration::from_secs(6);

/// Aggregated logging state (single lock for both fields)
#[derive(Default)]
struct LogState {
    counts: HashMap<String, usize>,
    total_duration: Duration,
}

/// Batched logger for tool.run requests
///
/// Aggregates successful tool.run calls and flushes them periodically using
/// debounce + throttle: waits for activity to settle (`LOG_DEBOUNCE=150ms`) but
/// forces flush after max wait time (`LOG_THROTTLE=6s`).
pub struct RequestLogger {
    state: Mutex<LogState>,
    notify: Notify,
}

impl RequestLogger {
    /// Create a new request logger
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LogState::default()),
            notify: Notify::new(),
        })
    }

    /// Record a successful tool.run call (batched)
    pub fn record_tool_success(&self, tool: &str, duration: Duration) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *state.counts.entry(tool.to_string()).or_default() += 1;
            state.total_duration += duration;
        }
        self.notify.notify_one();
    }

    /// Flush accumulated counts to stderr
    fn flush(&self) {
        let LogState {
            counts,
            total_duration,
        } = std::mem::take(
            &mut *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );

        if counts.is_empty() {
            return;
        }

        let total: usize = counts.values().sum();

        // Sort by tool name for consistent output
        let mut items: Vec<_> = counts.into_iter().collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));

        let summary: Vec<String> = items
            .into_iter()
            .map(|(tool, count)| format!("{tool}({count})"))
            .collect();

        tracing::info!(
            count = total,
            tools = %summary.join(" "),
            total_ms = total_duration.as_millis(),
            "tool.run batch"
        );
    }

    /// Spawn the background flush task
    pub fn spawn_flush_task(self: &Arc<Self>, shutdown: CancellationToken) -> JoinHandle<()> {
        let logger = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                // Wait for first request or shutdown
                tokio::select! {
                    () = logger.notify.notified() => {}
                    () = shutdown.cancelled() => {
                        logger.flush();
                        return;
                    }
                }

                // Batch until debounce or throttle expires
                let throttle_deadline = Instant::now() + LOG_THROTTLE;
                loop {
                    let remaining = throttle_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break; // throttle expired
                    }

                    tokio::select! {
                        result = tokio::time::timeout(LOG_DEBOUNCE, logger.notify.notified()) => {
                            if result.is_err() {
                                break; // debounce expired (no new requests)
                            }
                            // Got another request, continue batching
                        }
                        () = shutdown.cancelled() => {
                            logger.flush();
                            return;
                        }
                    }
                }

                logger.flush();
            }
        })
    }
}

impl std::fmt::Debug for RequestLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestLogger")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for LogState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogState")
            .field("counts", &self.counts)
            .field("total_duration", &self.total_duration)
            .finish()
    }
}
