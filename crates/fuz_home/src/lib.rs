//! The `~/.fuz` home layer.
//!
//! Everything tied to fuz's on-disk home conventions: the `FUZ_HOME`
//! directory layout (`paths`), the CLI-owned `daemon.json` (`daemon`),
//! log-file paths and rotation (`logs`), the `FuzHomeError` taxonomy
//! (`error`), and the daemon lifecycle timing constants. The generic,
//! home-agnostic primitives live in `fuz_sys`, which this crate depends on.

mod daemon;
mod error;
mod logs;
mod paths;
mod pid;

// Every module here is private, so this re-export list is what makes a *module*
// item public: a `pub` inside `daemon` / `error` / `logs` / `paths` / `pid` buys
// cross-module visibility only, and stays crate-internal until it is named
// below. It is most of the public API, not all of it — the crate root also
// declares the daemon lifecycle constants directly, further down this file
// (`fuz_daemon` consumes every one of them, `fuzd_server` one).
//
// The layout's path-segment constants stay behind the line: the `get_*_dir`
// helpers are what consumers compose, so a caller never needs to join a segment
// itself. `CURRENT_LINK` and `TOOLS_DIR` are the two exceptions — the
// symlink-walking callers in `fuz_artifact` / `fuz_release` do need them.
pub use daemon::{
    DaemonInfo, MaybeDaemonInfo, current_daemon_info, read_daemon_info, read_daemon_info_typed,
    remove_daemon_file, write_daemon_info,
};
pub use error::FuzHomeError;
pub use logs::{get_daemon_log_path, rotate_logs};
pub use paths::{
    CURRENT_LINK, TOOLS_DIR, check_fuz_home_not_world_writable, ensure_fuz_home, get_artifacts_dir,
    get_bin_dir, get_config_dir, get_current_link, get_fuz_home, get_npm_cache_dir, get_run_dir,
    get_socket_path, get_state_dir, get_tool_current_link, get_tool_dir, get_tools_dir,
    socket_lock_path,
};
pub use pid::verify_pid_is_fuzd;

// Test-only home override — present only under the `test_home_override` feature,
// which production builds never enable (see `paths.rs`).
#[cfg(feature = "test_home_override")]
pub use paths::{clear_fuz_home_override_for_testing, set_fuz_home_override_for_testing};

//
// Daemon lifecycle constants
//

/// Health poll during startup (ms)
pub const HEALTH_POLL_INTERVAL_MS: u64 = 100;

/// Health poll timeout during startup (seconds).
///
/// The poll returns as soon as the daemon answers, so this is only how long a
/// slow cold start (an exec stalled on disk IO) gets before `fuzd start` gives
/// up and kills it.
pub const HEALTH_POLL_TIMEOUT_SECS: u64 = 10;

/// Graceful shutdown drain timeout (seconds) - daemon side
pub const SHUTDOWN_TIMEOUT_SECS: u64 = 10;

/// CLI waits drain + buffer for system load variance (seconds)
pub const CLI_SHUTDOWN_BUFFER_SECS: u64 = 2;

/// Force kill SIGTERM → SIGKILL timeout (seconds)
pub const FORCE_KILL_TIMEOUT_SECS: u64 = 2;

/// Force kill poll interval (ms)
pub const FORCE_KILL_POLL_INTERVAL_MS: u64 = 100;

/// Max rotated log files to keep
pub const MAX_LOG_ROTATIONS: u32 = 3;
