//! Fuz Daemon (fuzd)
//!
//! UDS server hosting fuzd's **workloads** — long-running things tied to
//! client demand, held over a shared registry (refcount / idle-grace /
//! sharing) and answered with streaming responses. Two kinds are built: the
//! **observer** (poll-driven process / network / services sampler) and the
//! **watcher** (event-driven filesystem watch). The sidecar kind exists in
//! code but is feature-gated off the default build (see below). Authenticates
//! peers via filesystem permissions on the socket file (mode 0600) +
//! `SO_PEERCRED` UID match.
//!
//! # Signals
//!
//! - SIGINT (Ctrl+C): Graceful shutdown
//! - SIGTERM: Graceful shutdown
//!
//! # Design
//!
//! The daemon writes nothing to disk other than the socket file at
//! `~/.fuz/run/socket` and the lock beside it (`socket.lock`) that makes it the
//! socket's only owner. All other state files (daemon.json, logs) are
//! managed by the CLI.
//!
//! # Exit codes
//!
//! `0` after a clean shutdown; `75` (`fuz_daemon::EXIT_ALREADY_RUNNING`) when
//! another fuzd already owns the socket path, so nothing was started; `1` for
//! every other failure. Lifecycle subcommands carry their own codes. Across
//! every form, a command line that does not parse exits `2` with the message
//! on stderr (never `1`, which `fuzd status` gives "not running"), as does a
//! fuz home that cannot be used as configured (an unusable `HOME` with
//! `FUZ_HOME` unset, a relative `FUZ_HOME`, a `FUZ_HOME` too long for the
//! socket under it, and — where `start` writes under it — a world-writable
//! home); `--help` prints usage to stdout and exits `0`.
//!
//! # Exit timing
//!
//! The runtime is built by hand rather than by `#[tokio::main]`, whose runtime
//! drop waits without limit for blocking-pool tasks. An observer sample (`/proc`
//! reads, a `systemctl` subprocess) is abandoned, not cancelled, when its
//! collector stops, and keeps its blocking-pool thread until it returns; once
//! `run` has returned, the process waits at most [`RUNTIME_SHUTDOWN_TIMEOUT`] for
//! such a task before it exits anyway.
//!
//! # Sidecar scripts
//!
//! The sidecar workload kind (non-Rust runtime hosting) is **feature-gated,
//! off by default**: the shipped daemon links neither `fuz_deno` nor
//! `fuz_python`, so it embeds no `sidecar.ts` and never spawns a Deno process.
//! Building with `--features sidecar` wires the Deno + Python factories into
//! the pool; their scripts are then embedded at compile time via `include_str!`
//! and written to tempfiles at spawn time. The default daemon runs an empty
//! `SidecarPool` — the sidecar dispatch arms exist but resolve to empty /
//! not-found, since no @fuzdev tool consumes them.

mod cli;
mod error;

use error::StartupError;
use fuz_home::get_socket_path;
#[cfg(feature = "sidecar")]
use fuz_sidecar::SidecarConfig;
use fuz_sidecar::SidecarPool;
use fuz_sys::cli::{EXIT_USAGE, format_error_chain, parse_env_args};
use fuzd_server::{RequestLogger, SYSTEMCTL_SHOW_TIMEOUT, ServerConfig};
use std::process::ExitCode;
#[cfg(feature = "sidecar")]
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// How long the process waits, after `run` returns, for blocking-pool tasks
/// still running. By then the server has drained, so nothing left on the pool
/// has anyone to answer — only an abandoned observer sample. A healthy sample
/// returns in milliseconds, and the wait ends as soon as the pool is empty.
///
/// It outlasts [`SYSTEMCTL_SHOW_TIMEOUT`] by a margin, so a hung `systemctl`
/// spawned before the shutdown is always killed and reaped by its own deadline
/// rather than orphaned by the exit. What it cuts short is a sample that
/// never returns — a `/proc` read in uninterruptible sleep — which no longer
/// holds the process.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration =
    SYSTEMCTL_SHOW_TIMEOUT.saturating_add(Duration::from_millis(500));

fn main() -> ExitCode {
    // Parse before the runtime starts. A command line argh can't parse exits 2,
    // not argh's 1 — `status`'s "not running" — so a script can tell a typo from
    // an answer; `--help` prints to stdout and exits 0.
    let args = match parse_env_args::<cli::Fuzd>(EXIT_USAGE) {
        Ok(args) => args,
        Err(code) => return code,
    };
    let result = build_runtime()
        .and_then(|runtime| block_on_bounded(runtime, run(args), RUNTIME_SHUTDOWN_TIMEOUT));
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {}", format_error_chain(&e));
            if let Some(hint) = e.hint() {
                eprintln!("hint: {hint}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// Build the runtime every `fuzd` form runs on: multi-thread with every driver
/// enabled, as `#[tokio::main]` builds it.
fn build_runtime() -> Result<Runtime, StartupError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(StartupError::Runtime)
}

/// Drive `future` to completion on `runtime`, then shut the runtime down,
/// waiting at most `timeout` for tasks still on its blocking pool — they are
/// left running and die with the process.
///
/// Everything `future` owns has been dropped by the time it completes — the
/// daemon's log guard included, so buffered log lines are flushed before the
/// shutdown starts.
fn block_on_bounded<F: Future>(runtime: Runtime, future: F, timeout: Duration) -> F::Output {
    let output = runtime.block_on(future);
    runtime.shutdown_timeout(timeout);
    output
}

async fn run(args: cli::Fuzd) -> Result<ExitCode, StartupError> {
    match args.command {
        // Lifecycle subcommands manage a backgrounded daemon and carry their
        // own exit code (e.g. `status` is 0 = the daemon answers / 1 = not).
        Some(command) => Ok(cli::dispatch(command).await?),
        // No subcommand: run the daemon in the foreground.
        None => run_daemon().await.map(|()| ExitCode::SUCCESS),
    }
}

async fn run_daemon() -> Result<(), StartupError> {
    // Non-blocking stdout logging so a stalled log consumer can't starve
    // the async runtime. `_log_guard` must stay live for the whole
    // process — dropping it at end of `run` flushes buffered lines.
    // Without this, `fuzd_server`'s `tracing` events (incl. the cross-uid
    // peer-rejection warns) are emitted but discarded.
    let _log_guard = fuz_sys::logging::init_non_blocking_stdout("info");

    // Resolve the socket path from FUZ_HOME (defaults to ~/.fuz/run/socket).
    // `fuz_home` owns the filename and the join — this is the bind side of the
    // path `fuz_client` connects to, so both must read the same source.
    let socket_path = get_socket_path()?;

    // Create factories and pool. Under `--features sidecar` the Deno + Python
    // factories are wired in (sidecars start lazily on first tool call; both
    // scripts are embedded at compile time). The default build links no
    // non-Rust runtime host and runs an empty pool.
    #[cfg(feature = "sidecar")]
    let pool = SidecarPool::new(vec![
        (Arc::new(fuz_deno::factory()), SidecarConfig::new("deno")),
        (
            Arc::new(fuz_python::factory()),
            SidecarConfig::new("python"),
        ),
    ]);
    #[cfg(not(feature = "sidecar"))]
    let pool = SidecarPool::new(vec![]);

    // Graceful-shutdown token, cancelled on the first SIGINT/SIGTERM. The
    // signal select is single-sourced in `fuz_sys::signal` (shared with the
    // HTTP spine's `fuz_http::lifecycle`).
    let shutdown = fuz_sys::signal::shutdown_token();

    // Run the server (blocks until shutdown)
    let pkg_version = env!("CARGO_PKG_VERSION");
    let git_info = option_env!("FUZ_GIT_INFO").unwrap_or("unknown");
    let version = format!("{pkg_version} ({git_info})");
    let config = ServerConfig {
        socket_path: socket_path.clone(),
        version: version.clone(),
    };
    let logger = RequestLogger::new();

    #[cfg(feature = "sidecar")]
    let sidecars = "deno, python (lazy)";
    #[cfg(not(feature = "sidecar"))]
    let sidecars = "none";

    tracing::info!(
        %version,
        socket = %socket_path.display(),
        sidecars,
        "fuzd starting"
    );
    fuzd_server::run(pool, config, shutdown, logger).await?;
    tracing::info!("fuzd stopped");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blocking-pool task that never returns — an observer sample abandoned
    /// mid-`systemctl` — must not hold the process past the shutdown timeout,
    /// where a dropped runtime would wait for it without limit.
    #[test]
    fn a_hung_blocking_task_does_not_hold_the_exit() {
        let (tx, rx) = std::sync::mpsc::channel();
        // On its own thread so a regression fails the test at the bound
        // instead of hanging it for the task's whole sleep.
        std::thread::spawn(move || {
            let runtime = build_runtime().expect("runtime");
            let output = block_on_bounded(
                runtime,
                async {
                    // Spawned and never awaited, like a sample whose collector
                    // stopped.
                    drop(tokio::task::spawn_blocking(|| {
                        std::thread::sleep(Duration::from_secs(60));
                    }));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    7
                },
                Duration::from_millis(200),
            );
            let _ = tx.send(output);
        });
        let output = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("returned within the shutdown timeout, not after the blocking task");
        assert_eq!(output, 7, "the future's output is passed through");
    }
}
