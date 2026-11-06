//! PID utilities for daemon lifecycle management

use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;

/// The typed signal callers pass to [`send_signal`] (re-exported from `nix`
/// so consumers name `Signal::SIGTERM` without depending on `nix` directly).
pub use nix::sys::signal::Signal;

/// Check if a process with the given PID is alive
///
/// On Linux, uses `/proc/{pid}` existence check (fast).
/// On other Unix, falls back to a null-signal (`kill(pid, 0)`) probe.
#[cfg(target_os = "linux")]
#[must_use]
pub fn is_pid_alive(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(all(unix, not(target_os = "linux")))]
#[must_use]
pub fn is_pid_alive(pid: i32) -> bool {
    // `kill(pid, None)` sends the null signal — a pure existence/permission
    // probe. Only `ESRCH` means "no such process"; `EPERM` means it exists but
    // we may not signal it, so treat that (and any other errno) as alive,
    // matching the Linux `/proc` branch's existence semantics.
    !matches!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH))
}

/// Send a signal to a process via `kill(2)` directly (no `kill(1)` subprocess).
///
/// Returns `Ok(true)` if the signal was delivered, `Ok(false)` if the process
/// no longer exists (`ESRCH` — not an error, so callers stay idempotent), and
/// `Err` for any other failure (e.g. `EPERM`).
///
/// # Errors
///
/// Returns the underlying `nix::errno::Errno` for any failure other than
/// `ESRCH`.
pub fn send_signal(pid: i32, signal: Signal) -> nix::Result<bool> {
    match kill(Pid::from_raw(pid), signal) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    // The current PID fits i32 on every supported platform; the `as i32` cast
    // reads cleaner than `i32::try_from(...).unwrap()` in these assertions.
    #![allow(clippy::cast_possible_wrap)]
    use super::*;

    #[test]
    fn test_is_pid_alive_current_process() {
        // Current process is definitely alive
        let pid = std::process::id() as i32;
        assert!(is_pid_alive(pid));
    }

    #[test]
    fn test_is_pid_alive_nonexistent() {
        // PID 1 is init, but very high PIDs are unlikely to exist
        // Use a PID that's almost certainly not in use
        assert!(!is_pid_alive(i32::MAX));
    }

    #[test]
    fn test_send_signal_nonexistent() {
        // Signalling a nonexistent PID surfaces as `Ok(false)` (ESRCH mapped to
        // "process gone"), never `Err` — so callers stay idempotent.
        let result = send_signal(i32::MAX, Signal::SIGTERM);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "nonexistent pid → Ok(false)");
    }
}
