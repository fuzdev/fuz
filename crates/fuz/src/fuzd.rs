//! Observe the external `fuzd` daemon — never drive it.
//!
//! Per fuz's no-proxying, no-delegating stance, `fuz` does not run
//! fuzd's lifecycle (`start` /
//! `stop` / `restart`) on the user's behalf and does not re-expose fuzd's CLI
//! under a `fuz` noun. fuzd is a separately-installed tool the user manages
//! directly through its own CLI (`fuzd start` / `restart` / `status` / `logs`).
//!
//! What `fuz` legitimately does is *observe* fuzd passively, read-only:
//!
//! * **installed?** — is there a `fuzd` binary on fuz's bin path.
//! * **running?** — does a plain blocking connect to the daemon's UDS succeed.
//!   fuzd spawns a task per connection and treats an immediate close as a clean
//!   peer-closed, so this liveness probe sends no frame and disturbs nothing.
//!
//! These feed `fuz self status` and an actionable hint (e.g. "run `fuzd
//! restart`"). fuz never starts, stops, or restarts the daemon — daemon
//! lifecycle lives on the fuzd binary, not behind a `fuz daemon` namespace.
//!
//! Both are looked for under the fuz home. When that cannot be resolved there
//! is nowhere to look: [`state`] returns the home layer's error, and `fuz self
//! status` reports the daemon as unknown.

use fuz_home::{FuzHomeError, get_bin_dir, get_socket_path};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// fuzd presence, derived from passive observation. `Running` implies the
/// binary is present, so the variants are ordered by how much they tell us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzdState {
    /// The daemon is listening on its UDS (connect probe succeeded).
    Running,
    /// A `fuzd` binary is installed but the daemon isn't listening.
    Stopped,
    /// No `fuzd` binary on fuz's bin path.
    NotInstalled,
}

/// Is something accepting connections on the socket at `socket`?
///
/// A blocking connect with no frame sent: `Ok` means something is accepting
/// connections; `NotFound` (no socket) / `ConnectionRefused` (stale socket
/// after a crash) mean it isn't. Liveness only — not an RPC, never proxying.
fn is_listening(socket: &Path) -> bool {
    UnixStream::connect(socket).is_ok()
}

/// Is the daemon currently listening on its UDS?
///
/// For a caller that has just worked under the fuz home, and so knows it
/// resolves: a home that cannot be resolved reads as not running here.
/// [`state`] is the form that reports it.
#[must_use]
pub fn is_running() -> bool {
    get_socket_path().is_ok_and(|path| is_listening(&path))
}

/// Combined presence state (a running daemon takes precedence over the
/// installed check).
///
/// # Errors
///
/// The home layer's error when the fuz home cannot be resolved: there is then
/// no socket or bin path to look at, and the state is unknown rather than
/// "not installed".
pub fn state() -> Result<FuzdState, FuzHomeError> {
    let socket = get_socket_path()?;
    let bin = get_bin_dir()?.join("fuzd");
    Ok(if is_listening(&socket) {
        FuzdState::Running
    } else if bin.exists() {
        FuzdState::Stopped
    } else {
        FuzdState::NotInstalled
    })
}
