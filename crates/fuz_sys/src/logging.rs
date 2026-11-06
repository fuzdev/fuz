//! Process-wide logging initialization for fuz binaries.
//!
//! Gated behind the `logging` feature so consumers that don't install a
//! tracing subscriber (e.g. the `fuz` CLI) don't link the fmt
//! subscriber. Server/daemon binaries opt in with
//! `fuz_sys = { workspace = true, features = ["logging"] }`.
//!
//! ## Why non-blocking
//!
//! The default `tracing_subscriber::fmt()` writer writes synchronously
//! under `std::io::Stdout`'s lock. When whatever consumes stdout backs up
//! — a test harness's piped, undrained socket; a stalled `journald` — a
//! full stdout buffer blocks the writing worker mid-lock, and every other
//! tokio worker that logs parks behind it. On an async server that starves
//! the whole runtime: even lock-free routes like `/health` (which
//! `fuz_http::request_tracing_layer` logs) hang. Routing events through
//! `tracing_appender::non_blocking` — a background writer thread draining a
//! bounded, lossy channel — means logging can never block the runtime; it
//! drops lines under sustained overload instead.

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Initialize a non-blocking stdout `tracing` subscriber.
///
/// Reads the filter from `RUST_LOG`, falling back to `default_filter`
/// (e.g. `"info,zzz_server=info"`). Formatted events go through a
/// background writer thread so logging never blocks the async runtime.
///
/// Idempotent-friendly: uses `try_init`, so a second call (e.g. across
/// repeated test-harness setups in one process) is a silent no-op rather
/// than a panic.
///
/// # Returns
///
/// The [`WorkerGuard`] for the background writer. **Hold it for the whole
/// process lifetime** — bind it in `main` (`let _log_guard = …;`) and let
/// it drop at exit. Dropping flushes buffered lines and stops the worker;
/// dropping it early silently discards logs.
//
// `WorkerGuard` is itself `#[must_use]`, so no attribute is needed here
// (a redundant one trips `clippy::double_must_use`).
pub fn init_non_blocking_stdout(default_filter: &str) -> WorkerGuard {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .try_init();
    guard
}
