//! Fuz daemon lifecycle.
//!
//! Spawn / signal / health-poll / stale-pid / logs management for the `fuzd`
//! process, backing `fuzd`'s own lifecycle CLI (`fuzd start / stop / restart /
//! status / logs`), per the noun-first grammar. `fuz` does **not** drive
//! fuzd's lifecycle — it observes fuzd passively (see `fuz`'s `fuzd` probe
//! module) and the user manages the daemon via `fuzd` directly.
//!
//! `start` always spawns the bare `fuzd` daemon process as a detached child —
//! fuzd does not self-daemonize, so no fork/daemonize machinery is needed. It
//! resolves the fuzd binary next to the running executable (else PATH), so
//! `fuzd start` re-spawns itself.
//!
//! Lifecycle operations return an [`ExitCode`] rather than calling
//! `std::process::exit` — the `fuzd` binary owns the actual exit, keeping the
//! state machine unit-testable (the library never exits the process).

mod error;
mod log_tail;

pub use error::DaemonError;
pub use log_tail::logs;

use fuz_client::{DaemonStatusResponse, SidecarStatus, SidecarStatusInfo};
use fuz_home::{
    CLI_SHUTDOWN_BUFFER_SECS, DaemonInfo, FORCE_KILL_POLL_INTERVAL_MS, FORCE_KILL_TIMEOUT_SECS,
    FuzHomeError, HEALTH_POLL_INTERVAL_MS, HEALTH_POLL_TIMEOUT_SECS, MAX_LOG_ROTATIONS,
    MaybeDaemonInfo, SHUTDOWN_TIMEOUT_SECS, current_daemon_info, ensure_fuz_home,
    get_daemon_log_path, get_socket_path, read_daemon_info, read_daemon_info_typed,
    recorded_daemon_pid, remove_daemon_file, rotate_logs, socket_lock_path, verify_pid_is_fuzd,
    write_daemon_info,
};
use fuz_sys::cli::EXIT_USAGE;
use fuz_sys::file_lock::read_lock_holder;
use fuz_sys::secure_file::{SecureFileError, open_truncate_nofollow_regular};
use fuz_sys::{SECURE_FILE_MODE, Signal, is_pid_alive, send_signal};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

/// Exit code of the bare `fuzd` daemon when another fuzd already owns its
/// socket path (holds the lock beside the socket), so it started nothing.
///
/// `EX_TEMPFAIL` (75) — the code `fuz` gives a held lock — and set apart from
/// the generic `1` because [`start`] branches on it: a spawned child that exits
/// with it lost the socket path to another fuzd, which [`start`] reports as
/// already running (when that daemon answers) or as an error naming it (when
/// it does not), rather than as an unexplained crash.
pub const EXIT_ALREADY_RUNNING: u8 = 75;

//
// Lifecycle state
//

/// Daemon lifecycle state, derived from `daemon.json`, a health probe, and the
/// socket lock.
#[derive(Debug)]
pub enum DaemonState {
    /// The recorded daemon answers the health check.
    Running(DaemonInfo),
    /// The recorded daemon is a live fuzd still holding the socket lock, but it
    /// does not answer the health check — hung, stopped, or a daemon of another
    /// protocol version. `daemon.json` is kept: its pid is the only handle
    /// `fuzd stop --force` has on the daemon.
    Unresponsive(DaemonInfo),
    /// No `daemon.json`.
    Stopped,
    /// The recorded daemon is gone — it neither answers nor holds the socket
    /// lock — and callers clean its `daemon.json`.
    Stale(DaemonInfo),
}

/// Get daemon state from `daemon.json`, a health probe, and the socket lock.
///
/// No `daemon.json` is [`DaemonState::Stopped`]; a `daemon.json` whose daemon
/// answers the Hello probe is [`DaemonState::Running`]. One whose daemon does
/// *not* answer is told apart by the socket lock beside the recorded socket:
/// while the lock's body names the recorded pid and that pid is still a live
/// fuzd (not gone, nor reused by another process), the daemon still owns the
/// socket path and is [`DaemonState::Unresponsive`] — hung, or answering with
/// a mismatched `PROTOCOL_VERSION` (the probe cannot tell the two apart).
/// Otherwise it is
/// [`DaemonState::Stale`] — crashed, killed, or past the point in its shutdown
/// where it released the lock — and callers clean the file.
///
/// # Errors
/// Returns [`DaemonError::FuzHome`] if `daemon.json` cannot be read.
pub async fn get_daemon_state() -> Result<DaemonState, DaemonError> {
    match read_daemon_info()? {
        None => Ok(DaemonState::Stopped),
        Some(info) => {
            if fuz_client::check_health().await {
                Ok(DaemonState::Running(info))
            } else if holds_socket_lock(
                read_lock_holder(&socket_lock_path(&info.socket_path)),
                info.pid,
                verify_pid_is_fuzd,
            ) {
                Ok(DaemonState::Unresponsive(info))
            } else {
                Ok(DaemonState::Stale(info))
            }
        }
    }
}

//
// Helpers
//

/// Warn about and clean up a stale `daemon.json` — only while it still
/// names the stale pid, since a daemon started since owns its own file.
fn handle_stale_daemon(info: &DaemonInfo, quiet: bool) -> Result<(), DaemonError> {
    if !quiet {
        eprintln!(
            "warning: cleaned stale daemon.json (pid {} no longer owns the socket)",
            info.pid
        );
    }
    remove_daemon_file_if_names(info.pid)
}

/// Remove `daemon.json` only while it still names `pid` — a daemon started
/// since owns its own file.
fn remove_daemon_file_if_names(pid: i32) -> Result<(), DaemonError> {
    if let Ok(Some(current)) = read_daemon_info()
        && current.pid == pid
    {
        remove_daemon_file()?;
    }
    Ok(())
}

/// What may keep a recorded daemon that holds the socket lock from answering
/// the health check — the probe is one bit, so the error lines name both.
const NOT_ANSWERING_CAUSES: &str = "hung, or a daemon of another protocol version";

/// Print the error for a [`DaemonState::Unresponsive`] daemon, ending with
/// `hint`.
fn report_unresponsive(info: &DaemonInfo, hint: &str) {
    eprintln!(
        "error: fuzd (pid {}) holds {} but does not answer this fuzd's health check",
        info.pid,
        info.socket_path.display()
    );
    eprintln!("hint: it may be {NOT_ANSWERING_CAUSES}; {hint}");
}

/// Refuse a daemon log path that holds anything but a regular file (or
/// nothing), judged without following a link there.
fn refuse_irregular_log(log_path: &Path) -> Result<(), DaemonError> {
    let file_type = match std::fs::symlink_metadata(log_path) {
        Ok(meta) => meta.file_type(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(DaemonError::LogFile(SecureFileError::Io(
                log_path.to_path_buf(),
                e,
            )));
        }
    };
    if file_type.is_symlink() {
        Err(DaemonError::LogFile(SecureFileError::Symlink(
            log_path.to_path_buf(),
        )))
    } else if file_type.is_file() {
        Ok(())
    } else {
        Err(DaemonError::LogFile(SecureFileError::NotRegularFile(
            log_path.to_path_buf(),
        )))
    }
}

/// Find the fuzd binary: next to the running executable, else fall back to
/// PATH. The `fuzd` CLI finds itself this way to spawn the bare daemon.
fn find_fuzd_binary() -> Result<PathBuf, DaemonError> {
    let exe = std::env::current_exe().map_err(DaemonError::FindBinaryFailed)?;
    if let Some(fuzd_path) = exe.parent().map(|dir| dir.join("fuzd"))
        && fuzd_path.exists()
    {
        return Ok(fuzd_path);
    }
    // Fall back to PATH
    Ok(PathBuf::from("fuzd"))
}

/// Why a spawned daemon never became ready.
#[derive(Debug, PartialEq, Eq)]
enum NotReady {
    /// The child exited [`EXIT_ALREADY_RUNNING`]: another fuzd owns the socket
    /// path. `holder` is its pid from the socket lock's body; `answering` is
    /// whether the socket answered the health check once the child had exited.
    AlreadyRunning {
        holder: Option<u32>,
        answering: bool,
    },
    /// The child exited [`EXIT_USAGE`]: it refused what it was given to run
    /// with (the fuz home as configured), and re-running unchanged fails the
    /// same way.
    Refused,
    /// The child was still not ready at the deadline, and was killed and
    /// reaped.
    TimedOut,
    /// Any other failure — a crash, a failed wait — described for the `error:`
    /// line.
    Failed(String),
}

/// Whether a spawned daemon's exit code says it lost the socket path to
/// another fuzd (`None` = killed by a signal).
fn exited_already_running(code: Option<i32>) -> bool {
    code == Some(i32::from(EXIT_ALREADY_RUNNING))
}

/// Whether a health answer on the socket can be the spawned child's, given the
/// pid the socket lock's body names.
///
/// The lock is taken and its body written before the socket is bound, so a
/// socket that answers while the body names another pid belongs to another
/// daemon — one that won the path while the child was starting. No pid (no
/// lock file, or a body not yet written) gives the answer the benefit of the
/// doubt.
fn answer_is_childs(holder: Option<u32>, child_pid: u32) -> bool {
    holder.is_none_or(|pid| pid == child_pid)
}

/// Poll until the spawned daemon is ready: it answers the health check and
/// owns the socket lock (`lock_path`).
///
/// `health` is the probe ([`fuz_client::check_health`] in production) and
/// `timeout` the readiness deadline (`HEALTH_POLL_TIMEOUT_SECS` in
/// production), parameters so the ownership decision and the timeout path are
/// testable without a live socket or a multi-second wait.
///
/// No failure return leaves a child behind: one still running at the deadline
/// is killed and reaped ([`NotReady::TimedOut`]), and one whose status cannot
/// be read is already gone. A start that reports failure and leaves its child
/// running would orphan a daemon that binds late and is recorded nowhere — no
/// `daemon.json`, yet holding the socket lock, so `stop` finds nothing to stop
/// and `start` reports it running.
async fn poll_health_until_ready<H, F>(
    child: &mut Child,
    lock_path: &Path,
    timeout: Duration,
    mut health: H,
) -> Result<(), NotReady>
where
    H: FnMut() -> F,
    F: Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;

    loop {
        // Check child exit first (fast path for crash)
        let exited = match child.try_wait() {
            Ok(exited) => exited,
            Err(e) => {
                // `waitpid` fails only once the child is gone (ECHILD — reaped by
                // the kernel under an inherited `SIGCHLD` ignore): nothing to
                // kill, and its pid may already be reused.
                return Err(NotReady::Failed(e.to_string()));
            }
        };
        if let Some(status) = exited {
            if exited_already_running(status.code()) {
                // The owner may have bound its socket only after the child lost
                // the lock, so probe once more rather than trusting earlier
                // misses: an answering owner is a running daemon, not a failure.
                return Err(NotReady::AlreadyRunning {
                    holder: read_lock_holder(lock_path),
                    answering: health().await,
                });
            }
            if status.code() == Some(i32::from(EXIT_USAGE)) {
                return Err(NotReady::Refused);
            }
            return Err(NotReady::Failed(format!(
                "daemon exited with code {}",
                status.code().unwrap_or(-1)
            )));
        }

        // The Hello round-trip is the readiness signal — it succeeds only once
        // the daemon is bound and accepting — but only from the child itself.
        // Another fuzd that took the socket path first answers too; while the
        // lock names it, keep polling, and the child exits "already running".
        if health().await && answer_is_childs(read_lock_holder(lock_path), child.id()) {
            return Ok(());
        }

        if Instant::now() >= deadline {
            kill_child(child);
            return Err(NotReady::TimedOut);
        }

        tokio::time::sleep(Duration::from_millis(HEALTH_POLL_INTERVAL_MS)).await;
    }
}

/// Kill a spawned daemon `start` is giving up on, and reap it. Both steps are
/// best-effort and harmless on a child that has already exited.
fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Format the ` (pid N)` suffix of a lifecycle message, empty when the socket
/// lock names no holder.
fn pid_suffix(pid: Option<u32>) -> String {
    pid.map_or_else(String::new, |pid| format!(" (pid {pid})"))
}

/// Send shutdown RPC. Ignores all errors — the daemon may already be shutting
/// down or unreachable; the caller drives the timeout + `force` fallback.
async fn send_shutdown_rpc() {
    let _ = fuz_client::shutdown().await;
}

/// Whether the daemon is down once [`shutdown_and_await`] or [`force_stop`]
/// returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownOutcome {
    /// The daemon is gone and `daemon.json` is cleaned (when it still names
    /// the daemon) — it either answered the shutdown RPC within the deadline,
    /// or it was force-killed and let go of the socket lock.
    Stopped,
    /// The daemon still holds the socket path: the deadline passed with it
    /// still answering or still holding the socket lock and `force` unset, so
    /// nothing was killed; or it was force-killed and still held the lock
    /// `FORCE_KILL_TIMEOUT_SECS` after the kill. `daemon.json` is left in place
    /// and the refusal is already printed.
    Unresponsive,
}

/// Ask the running daemon to shut down and wait for it to go away.
///
/// The graceful dance shared by [`stop`] and [`restart`]: send the shutdown
/// RPC, then poll until the daemon has let go of the socket path (see
/// [`daemon_released`]), up to `SHUTDOWN_TIMEOUT_SECS +
/// CLI_SHUTDOWN_BUFFER_SECS`. On death `daemon.json`
/// is removed **only** when the file still names the pid that was shut down —
/// a daemon that came back under us owns its own file.
///
/// On timeout with `force`, `force_notice` is printed (for the caller whose UX
/// announces the kill) and the daemon goes through [`force_stop`]. Without
/// `force` the refusal is printed, its hint naming `fuzd <command> --force`,
/// and nothing is killed. Every other line of output belongs to the caller.
///
/// # Errors
/// Returns a [`DaemonError`] if removing `daemon.json` fails.
async fn shutdown_and_await(
    info: &DaemonInfo,
    command: &str,
    quiet: bool,
    force: bool,
    force_notice: Option<&str>,
) -> Result<ShutdownOutcome, DaemonError> {
    send_shutdown_rpc().await;

    // Poll until health fails
    let total_timeout = SHUTDOWN_TIMEOUT_SECS + CLI_SHUTDOWN_BUFFER_SECS;
    let deadline = Instant::now() + Duration::from_secs(total_timeout);

    let lock_path = socket_lock_path(&info.socket_path);
    while Instant::now() < deadline {
        let answering = fuz_client::check_health().await;
        if daemon_released(
            answering,
            read_lock_holder(&lock_path),
            info.pid,
            verify_pid_is_fuzd,
        ) {
            remove_daemon_file_if_names(info.pid)?;
            return Ok(ShutdownOutcome::Stopped);
        }
        tokio::time::sleep(Duration::from_millis(HEALTH_POLL_INTERVAL_MS)).await;
    }

    // Timeout
    if !force {
        if !quiet {
            eprintln!("error: daemon not responding");
            eprintln!("hint: re-run `fuzd {command} --force` to kill it");
        }
        return Ok(ShutdownOutcome::Unresponsive);
    }

    if let Some(notice) = force_notice
        && !quiet
    {
        eprintln!("{notice}");
    }
    force_stop(info, quiet).await
}

/// Force-kill the recorded daemon and wait for it to let go of the socket
/// path.
///
/// The `--force` path of [`stop`] and [`restart`], reached after a graceful
/// shutdown times out, or at once for a [`DaemonState::Unresponsive`] daemon,
/// which a shutdown RPC cannot reach. After [`force_kill`] the wait goes on — up
/// to `FORCE_KILL_TIMEOUT_SECS` — until the lock is released (see
/// [`daemon_released`]): a `SIGKILL` returns before the process is gone, and a
/// daemon started while the killed one still holds the lock would be refused.
/// Then `daemon.json` is dropped if it still names the killed pid.
///
/// # Errors
/// Returns a [`DaemonError`] if removing `daemon.json` fails.
async fn force_stop(info: &DaemonInfo, quiet: bool) -> Result<ShutdownOutcome, DaemonError> {
    let lock_path = socket_lock_path(&info.socket_path);
    force_kill(info.pid, quiet).await?;
    if !await_lock_release(
        &lock_path,
        info.pid,
        Duration::from_secs(FORCE_KILL_TIMEOUT_SECS),
    )
    .await
    {
        if !quiet {
            eprintln!(
                "error: fuzd (pid {}) still holds {} after SIGKILL",
                info.pid,
                lock_path.display()
            );
            eprintln!("hint: it is likely blocked in the kernel; re-run once it has exited");
        }
        return Ok(ShutdownOutcome::Unresponsive);
    }
    remove_daemon_file_if_names(info.pid)?;
    Ok(ShutdownOutcome::Stopped)
}

/// Whether the daemon `pid` has let go of its socket path, so a daemon started
/// next can take it.
///
/// A closed listener alone is not that: the daemon unlinks its socket and only
/// then releases the socket lock, so a daemon spawned the moment health first
/// fails could find the lock still held and exit "already running". The lock's
/// body settles it — the daemon truncates it while still holding the lock, so a
/// body that no longer names `pid` means released or about to be. A body still
/// naming a `pid` that is gone means it died holding the lock (killed outright,
/// nothing truncated), and the kernel has already dropped the `flock`.
///
/// `is_alive` is [`verify_pid_is_fuzd`] in production, a parameter so the decision is
/// testable without live processes.
fn daemon_released(
    answering: bool,
    holder: Option<u32>,
    pid: i32,
    is_alive: impl FnOnce(i32) -> bool,
) -> bool {
    !answering && !holds_socket_lock(holder, pid, is_alive)
}

/// Whether the daemon `pid` still holds the socket lock whose body names
/// `holder`: the body names it and it is still alive.
///
/// The lock half of [`daemon_released`], and what tells a recorded daemon that
/// does not answer apart from a gone one in [`get_daemon_state`]. `is_alive` is
/// [`verify_pid_is_fuzd`] in production.
fn holds_socket_lock(holder: Option<u32>, pid: i32, is_alive: impl FnOnce(i32) -> bool) -> bool {
    holder.is_some_and(|holder| i32::try_from(holder) == Ok(pid)) && is_alive(pid)
}

/// Poll until the daemon `pid` has let go of the socket lock at `lock_path`
/// (see [`daemon_released`]), up to `timeout`; whether it did.
///
/// The force-kill path's wait: the daemon no longer answers by then, so only
/// the lock is read.
async fn await_lock_release(lock_path: &Path, pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if daemon_released(false, read_lock_holder(lock_path), pid, verify_pid_is_fuzd) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(FORCE_KILL_POLL_INTERVAL_MS)).await;
    }
}

async fn force_kill(pid: i32, quiet: bool) -> Result<(), DaemonError> {
    if !verify_pid_is_fuzd(pid) {
        if !quiet {
            eprintln!("warning: PID {pid} is no longer fuzd, skipping kill");
        }
        return Ok(());
    }

    // Send SIGTERM
    let _ = send_signal(pid, Signal::SIGTERM);

    let deadline = Instant::now() + Duration::from_secs(FORCE_KILL_TIMEOUT_SECS);
    while Instant::now() < deadline {
        if !is_pid_alive(pid) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(FORCE_KILL_POLL_INTERVAL_MS)).await;
    }

    // Still alive after SIGTERM timeout - re-verify before SIGKILL.
    // This prevents killing a wrong process if PID was reused.
    if !verify_pid_is_fuzd(pid) {
        if !quiet {
            eprintln!("warning: PID {pid} is no longer fuzd after SIGTERM, skipping SIGKILL");
        }
        return Ok(());
    }

    if !quiet {
        eprintln!("SIGTERM timeout, sending SIGKILL");
    }
    let _ = send_signal(pid, Signal::SIGKILL);

    Ok(())
}

/// The daemon socket's path, or the home's refusal of it — with the pid
/// `daemon.json` records, when there is one, so a refusal of a home whose
/// socket path is too long can say a daemon may still be running there.
///
/// The pid is read for display only: nothing is verified, signalled, or
/// cleaned up.
fn socket_path_or_refusal() -> Result<PathBuf, DaemonError> {
    match get_socket_path() {
        Ok(path) => Ok(path),
        Err(refusal @ FuzHomeError::SocketPathTooLong { .. }) => Err(match recorded_daemon_pid() {
            Some(recorded_pid) => DaemonError::SocketUnreachable {
                refusal,
                recorded_pid,
            },
            None => DaemonError::FuzHome(refusal),
        }),
        Err(e) => Err(e.into()),
    }
}

//
// Lifecycle operations
//

/// The `fuzd start` refusal beside a live fuzd whose daemon.json declares
/// schema `version` and isn't readable as this fuzd's — the error line, then
/// the hint.
fn unrecognized_daemon_refusal(pid: i32, version: u32) -> [String; 2] {
    [
        format!(
            "error: daemon.json (schema version {version}) is not one this fuzd can read, \
             and the fuzd it names (pid {pid}) is still running"
        ),
        format!(
            "hint: it was likely started by another fuz version; stop it (`kill {pid}`), \
             then re-run `fuzd start`"
        ),
    ]
}

/// Start the daemon (spawn the bare fuzd process, poll health, write
/// `daemon.json`).
///
/// A child that is not ready within `HEALTH_POLL_TIMEOUT_SECS`, or that is
/// ready but cannot be recorded in `daemon.json`, is killed before the error
/// is reported, so a failed start leaves no daemon behind. A
/// [`DaemonState::Unresponsive`] daemon is refused (exit 1) without spawning:
/// it still owns the socket path, and a child would only lose it. A child that
/// exits [`EXIT_USAGE`] refused its configuration, and `start` exits with that
/// code too.
///
/// # Errors
/// Returns a [`DaemonError`] if the fuzd binary can't be located or spawned,
/// or if the log/run directories can't be prepared.
pub async fn start(quiet: bool) -> Result<ExitCode, DaemonError> {
    // A home no daemon could listen under is refused before anything is read
    // or spawned.
    socket_path_or_refusal()?;
    // The version-skew guard: refuse to spawn next to a live fuzd whose
    // daemon.json this fuzd can't read — almost always one started by another
    // fuz version. Its record (socket path, wire protocol) is not ours to
    // interpret, so there is no shutdown RPC to send it; auto-stopping would
    // mean SIGTERM-by-pid, force-killing in-flight work. The operator stops it.
    if let MaybeDaemonInfo::Unrecognized { pid, version } = read_daemon_info_typed()? {
        if !quiet {
            for line in unrecognized_daemon_refusal(pid, version) {
                eprintln!("{line}");
            }
        }
        return Ok(ExitCode::FAILURE);
    }

    match get_daemon_state().await? {
        DaemonState::Running(info) => {
            if !quiet {
                eprintln!(
                    "already running at {} (pid {})",
                    info.socket_path.display(),
                    info.pid
                );
            }
            return Ok(ExitCode::SUCCESS);
        }
        // The recorded daemon still owns the socket path, so a child spawned
        // now would only exit "already running"; and the desired state — a
        // daemon that answers — does not hold, so this is a refusal (exit 1),
        // like start's other refusals, not "already running".
        DaemonState::Unresponsive(info) => {
            if !quiet {
                report_unresponsive(
                    &info,
                    "`fuzd restart --force` kills it and starts a new one",
                );
            }
            return Ok(ExitCode::FAILURE);
        }
        DaemonState::Stale(info) => handle_stale_daemon(&info, quiet)?,
        // No `daemon.json` is not proof nothing is running: a foreground
        // `fuzd` writes none, and a racing `fuzd start` has not written its
        // own yet. One that answers is reported, not raced — a child spawned
        // beside it would only exit "already running". Its pid comes from the
        // socket lock it holds.
        DaemonState::Stopped => {
            if fuz_client::check_health().await {
                if !quiet {
                    let socket_path = get_socket_path()?;
                    let holder = read_lock_holder(&socket_lock_path(&socket_path));
                    eprintln!(
                        "already running at {}{}",
                        socket_path.display(),
                        pid_suffix(holder)
                    );
                }
                return Ok(ExitCode::SUCCESS);
            }
        }
    }

    let fuzd = find_fuzd_binary()?;

    // The home check comes before anything is created under the home: a
    // world-writable `~/.fuz` is refused here, not after a daemon is up. It
    // also creates `~/.fuz/state/logs/` (0700) when missing.
    ensure_fuz_home()?;

    let log_path = get_daemon_log_path()?;

    // A symlink or other non-regular file at the log path is refused as it
    // stands — neither rotated aside nor written through.
    refuse_irregular_log(&log_path)?;

    if let Err(e) = rotate_logs(&log_path, MAX_LOG_ROTATIONS)
        && !quiet
    {
        eprintln!("warning: failed to rotate logs: {e}");
    }

    // No-follow, so a link planted after the check above is refused too.
    let log_file = open_truncate_nofollow_regular(&log_path, SECURE_FILE_MODE)
        .map_err(DaemonError::LogFile)?;

    let log_file_clone =
        log_file
            .try_clone()
            .map_err(|source| DaemonError::CloneLogFileFailed {
                path: log_path.clone(),
                source,
            })?;

    // Spawn fuzd. It takes no configuration from the environment — the socket
    // path is canonical — so we only forward the host environment.
    let mut child = Command::new(&fuzd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file_clone))
        .stderr(Stdio::from(log_file))
        .spawn()
        .map_err(DaemonError::SpawnDaemonFailed)?;

    // Get PID as i32
    #[allow(clippy::cast_possible_wrap)]
    let pid = child.id() as i32;

    // Poll health
    let socket_path = get_socket_path()?;
    let lock_path = socket_lock_path(&socket_path);
    let ready = poll_health_until_ready(
        &mut child,
        &lock_path,
        Duration::from_secs(HEALTH_POLL_TIMEOUT_SECS),
        fuz_client::check_health,
    )
    .await;
    match ready {
        Ok(()) => {
            // Write daemon.json (v2 schema with socket_path). A daemon that
            // can't be recorded is killed, not left serving: the error below
            // reports the start failed, and nothing could stop it by pid.
            let recorded =
                current_daemon_info(pid).and_then(|info| write_daemon_info(&info).map(|_| info));
            let info = match recorded {
                Ok(info) => info,
                Err(e) => {
                    kill_child(&mut child);
                    return Err(e.into());
                }
            };

            if !quiet {
                println!("started at {} (pid {pid})", info.socket_path.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        // Another fuzd took the socket path between the state check above and
        // the child's lock — a racing `fuzd start`, most often — and answers:
        // the desired state holds, and the child recorded nothing.
        Err(NotReady::AlreadyRunning {
            holder,
            answering: true,
        }) => {
            if !quiet {
                eprintln!(
                    "already running at {}{}",
                    socket_path.display(),
                    pid_suffix(holder)
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        // The holder owns the socket path but does not answer this fuzd's
        // health check — a daemon of another protocol version, one still
        // starting or stopping, or one that accepts but does not answer in
        // time. `daemon.json` recorded no such daemon when start checked (a
        // recorded one holding the lock is `Unresponsive`, refused above), so
        // `fuzd stop` has no pid to reach it by.
        Err(NotReady::AlreadyRunning {
            holder,
            answering: false,
        }) => {
            if !quiet {
                eprintln!(
                    "error: another fuzd is already running on {}{}",
                    socket_path.display(),
                    pid_suffix(holder)
                );
                let pid = holder.map_or_else(|| "<pid>".to_string(), |pid| pid.to_string());
                eprintln!(
                    "hint: it does not answer this fuzd's health check (another protocol version, hung, or still starting or stopping); `fuzd stop` cannot reach it — wait and re-run, or stop it with `kill {pid}`"
                );
            }
            Ok(ExitCode::FAILURE)
        }
        // The poll has already killed and reaped the child.
        Err(NotReady::TimedOut) => {
            if !quiet {
                eprintln!(
                    "error: daemon (pid {pid}) not ready within {HEALTH_POLL_TIMEOUT_SECS}s; killed it"
                );
                eprintln!("hint: check the daemon log with `fuzd logs`");
            }
            Ok(ExitCode::FAILURE)
        }
        // The child refused its configuration. The lifecycle command exits with
        // the child's code, so a caller sees the same `2` bare `fuzd` gives.
        Err(NotReady::Refused) => {
            if !quiet {
                eprintln!(
                    "error: daemon exited with code {EXIT_USAGE}: it refused its configuration"
                );
                eprintln!("hint: the daemon log names what to change: `fuzd logs`");
            }
            Ok(ExitCode::from(EXIT_USAGE))
        }
        // The child is gone: it exited, or its status could not be read.
        Err(NotReady::Failed(e)) => {
            if !quiet {
                eprintln!("error: {e}");
                eprintln!("hint: check the daemon log with `fuzd logs`");
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Stop the daemon gracefully, force-killing on timeout when `force` is set.
///
/// A [`DaemonState::Unresponsive`] daemon cannot be asked to shut down: without
/// `force` that is a refusal (exit 1) whose hint names `fuzd stop --force`, and
/// with it the daemon is force-killed at once. A home whose socket path is too
/// long is refused (exit 2) with nothing read, signalled, or cleaned.
///
/// # Errors
/// Returns a [`DaemonError`] if the home is refused or cleaning up
/// `daemon.json` fails.
pub async fn stop(quiet: bool, force: bool) -> Result<ExitCode, DaemonError> {
    // A home no daemon could listen under is refused before anything is read
    // or cleaned.
    socket_path_or_refusal()?;
    let outcome = match get_daemon_state().await? {
        DaemonState::Stopped => {
            if !quiet {
                println!("not running");
            }
            return Ok(ExitCode::SUCCESS);
        }
        DaemonState::Stale(info) => {
            handle_stale_daemon(&info, quiet)?;
            if !quiet {
                println!("not running");
            }
            return Ok(ExitCode::SUCCESS);
        }
        DaemonState::Unresponsive(info) => {
            if !force {
                if !quiet {
                    report_unresponsive(&info, "re-run `fuzd stop --force` to kill it");
                }
                return Ok(ExitCode::FAILURE);
            }
            if !quiet {
                eprintln!("not answering, force killing...");
            }
            force_stop(&info, quiet).await?
        }
        DaemonState::Running(info) => {
            shutdown_and_await(
                &info,
                "stop",
                quiet,
                force,
                Some("timeout, force killing..."),
            )
            .await?
        }
    };

    match outcome {
        ShutdownOutcome::Stopped => {
            if !quiet {
                println!("stopped");
            }
            Ok(ExitCode::SUCCESS)
        }
        ShutdownOutcome::Unresponsive => Ok(ExitCode::FAILURE),
    }
}

/// Restart the daemon: stop (graceful, force on timeout) then start.
///
/// A [`DaemonState::Unresponsive`] daemon is refused (exit 1) without `force`,
/// its hint naming `fuzd restart --force`; with `force` it is killed at once,
/// and the start follows once it has let go of the socket path.
///
/// Refuses (exit 1) beside a daemon that answers but has no `daemon.json` — a
/// foreground `fuzd`, one whose `daemon.json` was deleted, or one a concurrent
/// `fuzd start` has not recorded yet. Restart stops only a daemon `fuzd start`
/// recorded, so it neither stops that one nor reports it restarted.
///
/// # Errors
/// Returns a [`DaemonError`] if stopping or starting the daemon fails.
pub async fn restart(quiet: bool, force: bool) -> Result<ExitCode, DaemonError> {
    // A home no daemon could listen under is refused before anything is read,
    // stopped, or cleaned.
    socket_path_or_refusal()?;
    match get_daemon_state().await? {
        DaemonState::Running(info) => {
            // Restart announces no kill of its own, so it passes no notice. An
            // unresponsive daemon is terminal here — restart refuses rather
            // than spawning a second daemon beside one that won't die.
            if shutdown_and_await(&info, "restart", quiet, force, None).await?
                == ShutdownOutcome::Unresponsive
            {
                return Ok(ExitCode::FAILURE);
            }
        }
        DaemonState::Unresponsive(info) => {
            if !force {
                if !quiet {
                    report_unresponsive(&info, "re-run `fuzd restart --force` to kill it");
                }
                return Ok(ExitCode::FAILURE);
            }
            if force_stop(&info, quiet).await? == ShutdownOutcome::Unresponsive {
                return Ok(ExitCode::FAILURE);
            }
        }
        DaemonState::Stale(info) => handle_stale_daemon(&info, quiet)?,
        // A daemon that answers with no `daemon.json` — a foreground `fuzd`,
        // an orphan whose `daemon.json` is gone, or a concurrent start's child
        // not yet recorded — is one restart cannot stop: it has no pid on
        // record to stop by, and shutting down over the socket a daemon its
        // owner runs in a terminal is not restart's call. Falling through to
        // `start` would report it "already running" and succeed, leaving the
        // old binary serving.
        DaemonState::Stopped => {
            if fuz_client::check_health().await {
                if !quiet {
                    let socket_path = get_socket_path()?;
                    let holder = read_lock_holder(&socket_lock_path(&socket_path));
                    eprintln!(
                        "error: a fuzd with no daemon.json is running at {}{}",
                        socket_path.display(),
                        pid_suffix(holder)
                    );
                    eprintln!(
                        "hint: restart stops only a daemon `fuzd start` recorded; stop this one (Ctrl-C in its terminal, or kill its pid), then re-run `fuzd restart`"
                    );
                }
                return Ok(ExitCode::FAILURE);
            }
        }
    }

    // Now start
    start(quiet).await
}

//
// Status
//

/// `fuzd status --json` output — the one shape all four status outcomes
/// render through (running with a live RPC answer, running but unreachable,
/// recorded but not answering, stopped).
///
/// `running` is the only unconditional key; every other field is
/// `skip_serializing_if`-omitted when absent, so each outcome emits exactly
/// the keys it can speak to rather than padding the others with `null`. Which
/// keys that is per outcome lives in one builder each —
/// [`running_status_json`], [`unreachable_status_json`],
/// [`not_answering_status_json`], [`stopped_status_json`] — shared by
/// [`status`] and the test that pins each outcome's keys and values.
#[derive(serde::Serialize)]
struct DaemonStatusJson {
    running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    socket_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sidecars: Option<Vec<SidecarStatusInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<String>>,
    /// Why the daemon's own status RPC could not be reached, on an otherwise
    /// running daemon.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Why no daemon answers: `stopped` (none is running) or `not_answering`
    /// (the recorded daemon holds the socket but does not answer).
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

impl DaemonStatusJson {
    /// The all-absent base every outcome fills in from.
    const fn empty(running: bool) -> Self {
        Self {
            running,
            version: None,
            socket_path: None,
            pid: None,
            sidecars: None,
            tools: None,
            error: None,
            reason: None,
        }
    }
}

/// The running-and-answering outcome: everything the daemon reported plus the
/// socket + PID the CLI already knew.
fn running_status_json(status: DaemonStatusResponse, info: &DaemonInfo) -> DaemonStatusJson {
    DaemonStatusJson {
        version: Some(status.version),
        socket_path: Some(info.socket_path.display().to_string()),
        pid: Some(info.pid),
        sidecars: Some(status.sidecars),
        tools: Some(status.tools),
        ..DaemonStatusJson::empty(true)
    }
}

/// The running-but-unreachable outcome: the process is up, so the local
/// `daemon.json` facts hold, but nothing the status RPC would have answered is
/// available — `error` says why instead.
fn unreachable_status_json(info: &DaemonInfo, error: String) -> DaemonStatusJson {
    DaemonStatusJson {
        socket_path: Some(info.socket_path.display().to_string()),
        pid: Some(info.pid),
        error: Some(error),
        ..DaemonStatusJson::empty(true)
    }
}

/// The not-answering outcome ([`DaemonState::Unresponsive`]): the recorded
/// daemon holds the socket lock but does not answer, so `running` is `false` —
/// it is the answering daemon `running` reports — with the recorded socket +
/// PID and `reason` saying why.
fn not_answering_status_json(info: &DaemonInfo) -> DaemonStatusJson {
    DaemonStatusJson {
        socket_path: Some(info.socket_path.display().to_string()),
        pid: Some(info.pid),
        reason: Some("not_answering"),
        ..DaemonStatusJson::empty(false)
    }
}

/// The not-running outcome: no daemon, so no socket / PID to report — only
/// `reason`.
fn stopped_status_json() -> DaemonStatusJson {
    DaemonStatusJson {
        reason: Some("stopped"),
        ..DaemonStatusJson::empty(false)
    }
}

/// Render one [`DaemonStatusJson`] to stdout — the single `--json` encoder
/// behind all four status outcomes.
fn print_status_json(status: &DaemonStatusJson) -> Result<(), DaemonError> {
    println!("{}", serde_json::to_string_pretty(status)?);
    Ok(())
}

/// Status indicator for display.
const fn status_indicator(status: &SidecarStatus) -> &'static str {
    match status {
        SidecarStatus::Running => "[*]",
        SidecarStatus::Unloaded => "[ ]",
        SidecarStatus::Loading | SidecarStatus::ShuttingDown => "[~]",
        SidecarStatus::Failed => "[!]",
    }
}

/// Format `SidecarStatus` for display.
const fn format_status(status: &SidecarStatus) -> &'static str {
    match status {
        SidecarStatus::Running => "running",
        SidecarStatus::Unloaded => "unloaded",
        SidecarStatus::Loading => "loading",
        SidecarStatus::ShuttingDown => "shutting_down",
        SidecarStatus::Failed => "failed",
    }
}

/// Show daemon status: version, pid, socket, sidecars, and tools.
///
/// Returns [`ExitCode::SUCCESS`] when the recorded daemon answers,
/// [`ExitCode::FAILURE`] otherwise — stopped, or recorded but not answering
/// ([`DaemonState::Unresponsive`]). The exit code is the scriptable contract
/// (`-q` suppresses output and yields the code only). A fuz home that cannot
/// be used as configured is an error, not "stopped": its caller exits `2`
/// ([`DaemonError::exit_code`]).
///
/// # Errors
/// Returns a [`DaemonError`] if daemon state can't be read or JSON output
/// can't be serialized.
pub async fn status(json: bool, quiet: bool, verbose: bool) -> Result<ExitCode, DaemonError> {
    // A home no daemon could listen under is an error, never "stopped".
    socket_path_or_refusal()?;
    let info = match get_daemon_state().await? {
        DaemonState::Running(info) => info,
        DaemonState::Unresponsive(info) => {
            if json {
                print_status_json(&not_answering_status_json(&info))?;
            } else if !quiet {
                println!("not answering (pid {})", info.pid);
                eprintln!(
                    "hint: it holds {} but does not answer this fuzd's health check — it may be {NOT_ANSWERING_CAUSES}; `fuzd stop --force` kills it",
                    info.socket_path.display()
                );
            }
            return Ok(ExitCode::FAILURE);
        }
        DaemonState::Stale(info) => {
            handle_stale_daemon(&info, quiet)?;
            print_stopped_status(json, quiet)?;
            return Ok(ExitCode::FAILURE);
        }
        DaemonState::Stopped => {
            print_stopped_status(json, quiet)?;
            return Ok(ExitCode::FAILURE);
        }
    };

    // Daemon is running — fetch the full status via RPC.
    match fuz_client::daemon_status().await {
        Ok(status) => {
            if json {
                print_status_json(&running_status_json(status, &info))?;
            } else if !quiet {
                render_running_human(&status, &info, verbose);
            }
        }
        Err(e) => {
            if json {
                print_status_json(&unreachable_status_json(&info, e.to_string()))?;
            } else if !quiet {
                println!(
                    "fuzd (running, PID {}, socket {})",
                    info.pid,
                    info.socket_path.display()
                );
                eprintln!("  warning: failed to get status: {e}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Render the running-daemon status to stdout in the human-readable
/// (non-`--json`, non-`--quiet`) format: the header line, then — only when the
/// sidecar pool has entries — the per-sidecar lines and the tool count (tools
/// come only from sidecars, so the shipped daemon's empty pool prints the
/// header alone). The pure presentation half of [`status`]'s running arm.
fn render_running_human(status: &DaemonStatusResponse, info: &DaemonInfo, verbose: bool) {
    println!(
        "fuzd {} (running, PID {}, socket {})",
        status.version,
        info.pid,
        info.socket_path.display()
    );
    if status.sidecars.is_empty() {
        return;
    }
    println!();
    for sc in &status.sidecars {
        let indicator = status_indicator(&sc.status);
        let tools_str = if sc.tools.is_empty() {
            "(no tools)".to_string()
        } else {
            sc.tools.join(", ")
        };

        let sidecar_id = sc
            .version_info
            .as_ref()
            .map_or_else(|| sc.id.clone(), |vi| format!("{}:{}", sc.id, vi.runtime));

        if verbose {
            println!(
                "{} {:16} {:9}",
                indicator,
                sidecar_id,
                format_status(&sc.status)
            );
            if let Some(ref version_info) = sc.version_info {
                if let Some(ref ts_version) = version_info.typescript {
                    println!("    TypeScript: {ts_version}");
                }
                if !version_info.dependencies.is_empty() {
                    println!("    Dependencies:");
                    let mut deps: Vec<_> = version_info.dependencies.iter().collect();
                    deps.sort_by_key(|(name, _)| *name);
                    for (name, version) in deps {
                        println!("      {name}@{version}");
                    }
                }
            }
            for tool in &sc.tools {
                println!("    └─ {tool}");
            }
        } else {
            println!(
                "{} {:16} {:9} {}",
                indicator,
                sidecar_id,
                format_status(&sc.status),
                tools_str
            );
        }
    }
    println!();
    println!("Tools: {} available", status.tools.len());
}

fn print_stopped_status(json: bool, quiet: bool) -> Result<(), DaemonError> {
    if json {
        print_status_json(&stopped_status_json())?;
    } else if !quiet {
        println!("stopped");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon log path may hold a regular file or nothing; a symlink
    /// (live or dangling) or a directory is refused without following it.
    #[test]
    fn refuse_irregular_log_accepts_only_a_regular_file_or_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fuzd.log");
        refuse_irregular_log(&path).unwrap();

        std::fs::write(&path, b"log").unwrap();
        refuse_irregular_log(&path).unwrap();

        let target = dir.path().join("target.log");
        std::fs::write(&target, b"other").unwrap();
        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            refuse_irregular_log(&link),
            Err(DaemonError::LogFile(SecureFileError::Symlink(_)))
        ));
        let dangling = dir.path().join("dangling.log");
        std::os::unix::fs::symlink(dir.path().join("absent"), &dangling).unwrap();
        assert!(matches!(
            refuse_irregular_log(&dangling),
            Err(DaemonError::LogFile(SecureFileError::Symlink(_)))
        ));

        let subdir = dir.path().join("dir.log");
        std::fs::create_dir(&subdir).unwrap();
        assert!(matches!(
            refuse_irregular_log(&subdir),
            Err(DaemonError::LogFile(SecureFileError::NotRegularFile(_)))
        ));
    }

    /// `start` tells a child that lost the socket path to another fuzd apart
    /// from one that crashed.
    #[test]
    fn exited_already_running_singles_out_the_lock_refusal() {
        assert!(exited_already_running(Some(i32::from(
            EXIT_ALREADY_RUNNING
        ))));
        assert!(!exited_already_running(Some(1)));
        assert!(!exited_already_running(Some(0)));
        assert!(!exited_already_running(None));
    }

    /// A stale record is cleaned only while `daemon.json` still names its pid:
    /// a daemon recorded since the state was read owns the file.
    #[test]
    fn handle_stale_daemon_keeps_a_record_naming_another_pid() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(
            home.path(),
            std::fs::Permissions::from_mode(fuz_sys::SECURE_DIR_MODE),
        )
        .expect("chmod home");
        fuz_home::set_fuz_home_override_for_testing(home.path());

        let stale = current_daemon_info(1_000_001).expect("stale info");
        let newer = current_daemon_info(1_000_002).expect("newer info");
        let path = write_daemon_info(&newer).expect("write daemon.json");

        handle_stale_daemon(&stale, true).expect("clean stale");
        let kept = read_daemon_info()
            .expect("read daemon.json")
            .map(|info| info.pid);
        assert_eq!(
            kept,
            Some(newer.pid),
            "a newer daemon's record must survive"
        );

        handle_stale_daemon(&newer, true).expect("clean newer");
        assert!(!path.exists(), "a record naming the stale pid is removed");

        fuz_home::clear_fuz_home_override_for_testing();
    }

    /// Write a socket lock body naming `pid`, as a holder would — the poll reads
    /// the body only, so no `flock` is needed to stand in for one.
    fn write_lock_body(path: &Path, pid: u32) {
        let info = fuz_sys::file_lock::LockInfo {
            pid,
            started_at: "2020-01-01T00:00:00Z".to_string(),
        };
        std::fs::write(path, serde_json::to_string(&info).expect("encode")).expect("write body");
    }

    /// A readiness deadline the poll tests below never reach: each ends on the
    /// child's exit or answer well before it.
    const POLL_TIMEOUT: Duration = Duration::from_secs(10);

    fn spawn_sh(script: &str) -> Child {
        Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sh")
    }

    /// The staggered-starts race: the socket answers, but the lock names another
    /// daemon, so the answer is not the child's. The poll waits for the child to
    /// lose the lock and reports the holder running, instead of a start of a
    /// child that is about to exit.
    #[tokio::test]
    async fn poll_does_not_take_another_daemons_answer_for_the_childs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("socket.lock");
        let other = std::process::id();
        write_lock_body(&lock, other);
        let mut child = spawn_sh("sleep 0.3; exit 75");
        let result =
            poll_health_until_ready(&mut child, &lock, POLL_TIMEOUT, || async { true }).await;
        assert_eq!(
            result,
            Err(NotReady::AlreadyRunning {
                holder: Some(other),
                answering: true,
            })
        );
    }

    /// An answer while the lock names the child itself is the child's: ready.
    #[tokio::test]
    async fn poll_takes_the_childs_own_answer_as_ready() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("socket.lock");
        let mut child = spawn_sh("sleep 10");
        write_lock_body(&lock, child.id());
        let result =
            poll_health_until_ready(&mut child, &lock, POLL_TIMEOUT, || async { true }).await;
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(result, Ok(()));
    }

    /// A child that loses the lock to a holder that never answers: the holder's
    /// pid is reported, and `answering` is false.
    #[tokio::test]
    async fn poll_reports_a_silent_holder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("socket.lock");
        write_lock_body(&lock, 4242);
        let mut child = spawn_sh("exit 75");
        let result =
            poll_health_until_ready(&mut child, &lock, POLL_TIMEOUT, || async { false }).await;
        assert_eq!(
            result,
            Err(NotReady::AlreadyRunning {
                holder: Some(4242),
                answering: false,
            })
        );
    }

    /// A child that exits with the usage code refused its configuration, which
    /// `start` passes through rather than flattening to a failure.
    #[tokio::test]
    async fn poll_reports_a_usage_exit_as_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("socket.lock");
        let mut child = spawn_sh("exit 2");
        let result =
            poll_health_until_ready(&mut child, &lock, POLL_TIMEOUT, || async { false }).await;
        assert_eq!(result, Err(NotReady::Refused));
    }

    /// Any other exit is a plain failure, whatever the socket answers.
    #[tokio::test]
    async fn poll_reports_any_other_exit_as_a_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("socket.lock");
        let mut child = spawn_sh("exit 1");
        let result =
            poll_health_until_ready(&mut child, &lock, POLL_TIMEOUT, || async { false }).await;
        assert_eq!(
            result,
            Err(NotReady::Failed("daemon exited with code 1".to_string()))
        );
    }

    /// A child still not ready at the deadline is killed and reaped, not left
    /// to bind late as an orphan nothing recorded.
    #[tokio::test]
    async fn poll_kills_a_child_not_ready_by_the_deadline() {
        use std::os::unix::process::ExitStatusExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = dir.path().join("socket.lock");
        let mut child = spawn_sh("exec sleep 30");
        let result =
            poll_health_until_ready(&mut child, &lock, Duration::from_millis(300), || async {
                false
            })
            .await;
        let reaped = child.try_wait().expect("try_wait");
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(result, Err(NotReady::TimedOut));
        let status = reaped.expect("the timed-out child was reaped");
        assert_eq!(status.signal(), Some(9), "killed, not exited: {status:?}");
    }

    #[test]
    fn answer_is_childs_trusts_only_a_matching_or_absent_holder() {
        assert!(answer_is_childs(Some(7), 7));
        assert!(answer_is_childs(None, 7), "no body: the pre-lock behavior");
        assert!(!answer_is_childs(Some(8), 7));
    }

    /// The restart race: a daemon that has stopped answering but whose lock
    /// still names it has not let go of the socket path yet, so a daemon spawned
    /// now would be refused. It has once the body is truncated or names
    /// another, or once the pid is gone (killed holding the lock).
    #[test]
    fn daemon_released_waits_for_the_lock_not_just_the_listener() {
        let alive = |_| true;
        let dead = |_| false;
        assert!(!daemon_released(true, None, 7, dead), "still answering");
        assert!(
            !daemon_released(false, Some(7), 7, alive),
            "listener closed, lock still held"
        );
        assert!(daemon_released(false, None, 7, alive), "lock released");
        assert!(daemon_released(false, Some(8), 7, alive), "another holder");
        assert!(
            daemon_released(false, Some(7), 7, dead),
            "died holding the lock: the kernel dropped it"
        );
    }

    /// The lock half of the state check: a recorded daemon that does not
    /// answer still owns the socket path only while the lock's body names it
    /// and it is alive — the `Unresponsive` case; any other body, or a gone
    /// pid, is a stale record.
    #[test]
    fn holds_socket_lock_needs_the_body_to_name_a_live_pid() {
        let alive = |_| true;
        let dead = |_| false;
        assert!(holds_socket_lock(Some(7), 7, alive));
        assert!(!holds_socket_lock(Some(7), 7, dead), "died holding it");
        assert!(!holds_socket_lock(Some(8), 7, alive), "another holder");
        assert!(!holds_socket_lock(None, 7, alive), "released");
    }

    /// The post-`SIGKILL` wait: a live fuzd named by the lock body holds it, so
    /// the wait times out; once that process is gone, the wait returns
    /// released. A symlink named `fuzd` gives a stand-in process fuzd's command
    /// name.
    #[tokio::test]
    async fn await_lock_release_waits_for_the_holder_to_exit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake_fuzd = dir.path().join("fuzd");
        std::os::unix::fs::symlink("/bin/sleep", &fake_fuzd).expect("symlink");
        let mut child = Command::new(&fake_fuzd)
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn fake fuzd");
        let pid = i32::try_from(child.id()).expect("pid fits i32");
        let lock = dir.path().join("socket.lock");
        write_lock_body(&lock, child.id());

        let held = await_lock_release(&lock, pid, Duration::from_millis(300)).await;

        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let _ = child.kill();
            let _ = child.wait();
        });
        let started = Instant::now();
        let released = await_lock_release(&lock, pid, POLL_TIMEOUT).await;
        let waited = started.elapsed();
        killer.join().expect("killer thread");

        assert!(!held, "a live fuzd naming the lock still holds it");
        assert!(released, "released once the holder is gone");
        assert!(
            waited >= Duration::from_millis(200),
            "waited for the exit rather than returning at once: {waited:?}"
        );
    }

    #[test]
    fn status_indicator_and_format_status_cover_all_states() {
        let cases = [
            (SidecarStatus::Running, "[*]", "running"),
            (SidecarStatus::Unloaded, "[ ]", "unloaded"),
            (SidecarStatus::Loading, "[~]", "loading"),
            (SidecarStatus::ShuttingDown, "[~]", "shutting_down"),
            (SidecarStatus::Failed, "[!]", "failed"),
        ];
        for (status, indicator, formatted) in cases {
            assert_eq!(
                status_indicator(&status),
                indicator,
                "indicator for {formatted}"
            );
            assert_eq!(format_status(&status), formatted, "format for {formatted}");
        }
    }

    /// The four `--json` outcomes share one struct and one encoder, so the
    /// per-outcome key set is a property of which fields each arm builder
    /// fills in. Pin those sets against the real builders: a new field that
    /// forgets its `skip_serializing_if` leaks a `null` into all four, and a
    /// field an arm stops filling in silently disappears from that arm.
    ///
    /// Pin the *values* too, because a key set cannot see them. `running` is
    /// the sharpest case — it is the one unconditional key, so it is present
    /// no matter what it says, and inverting it would leave every set below
    /// identical while telling a consumer the opposite of the truth. The
    /// payload fields need it for a different reason: a builder that
    /// fabricates a value rather than forwarding the daemon's answer emits the
    /// same key with the wrong contents, which is invisible to a set compare
    /// and is the failure this arm's whole payload is exposed to.
    #[test]
    fn status_json_outcomes_carry_the_keys_and_values_they_speak_to() {
        let keys = |status: &DaemonStatusJson| -> Vec<String> {
            let value = serde_json::to_value(status).expect("status serializes");
            let object = value.as_object().expect("status is a JSON object");
            let mut keys: Vec<String> = object.keys().cloned().collect();
            keys.sort();
            keys
        };

        // The builders read only `pid` + `socket_path` off this, and nothing
        // here validates the struct, so `version` is inert — the literal is not
        // standing in for `fuz_home`'s `DAEMON_INFO_VERSION`, which is
        // deliberately crate-internal. The one exported route to a real version
        // is `current_daemon_info`, and it resolves the live socket path off the
        // environment — the wrong shape for a pure unit test.
        let info = DaemonInfo {
            version: 2,
            pid: 1234,
            socket_path: PathBuf::from("/run/socket"),
        };

        // Every value here is chosen to be *unforgeable* — a builder that
        // fabricates a field instead of forwarding the daemon's answer has to
        // produce something a fixture value can't coincide with:
        //
        // - `version` is not the crate's own version, so stamping
        //   `env!("CARGO_PKG_VERSION")` — the live idiom in `fuzd`'s `main`,
        //   and the realistic confusion for a field named "version" — fails.
        // - the top-level `tools` shares no element with the sidecar's inner
        //   `tools`, so deriving the list from the sidecars instead of
        //   forwarding `status.tools` fails.
        // - two sidecars in differing states, so a forward that truncates or
        //   filters on `status` fails.
        //
        // Note what each mechanism is doing: the first two are caught by the
        // values being *disjoint* from everything a fabrication could reach,
        // not by the fixture's size — shrinking it back to one sidecar keeps
        // them. Only the third needs a second entry. Preserve both properties.
        let answered = DaemonStatusResponse {
            version: "9.9.9-fixture".to_string(),
            sidecars: vec![
                SidecarStatusInfo {
                    id: "deno".to_string(),
                    runtime: "deno".to_string(),
                    status: SidecarStatus::Running,
                    last_active_ms: None,
                    uptime_ms: None,
                    restart_count: 0,
                    error_message: None,
                    tools: vec!["sidecar_tool".to_string()],
                    description: None,
                    version_info: None,
                },
                SidecarStatusInfo {
                    id: "python".to_string(),
                    runtime: "python".to_string(),
                    status: SidecarStatus::Unloaded,
                    last_active_ms: None,
                    uptime_ms: None,
                    restart_count: 0,
                    error_message: None,
                    tools: Vec::new(),
                    description: None,
                    version_info: None,
                },
            ],
            tools: vec!["daemon_tool".to_string()],
        };
        let running = running_status_json(answered.clone(), &info);
        assert_eq!(
            keys(&running),
            [
                "pid",
                "running",
                "sidecars",
                "socket_path",
                "tools",
                "version"
            ]
        );
        assert!(running.running, "the answering outcome is a running daemon");
        // Values, not just keys: each field must carry what its source said,
        // so a builder that fabricates or cross-wires one is caught.
        assert_eq!(running.version.as_deref(), Some(answered.version.as_str()));
        assert_eq!(running.socket_path.as_deref(), Some("/run/socket"));
        assert_eq!(running.pid, Some(info.pid));
        assert_eq!(running.tools.as_deref(), Some(answered.tools.as_slice()));
        // `SidecarStatusInfo` has no `PartialEq`, and the serialized form is
        // the contract anyway — compare what the encoder will emit.
        assert_eq!(
            serde_json::to_value(&running.sidecars).expect("sidecars serialize"),
            serde_json::to_value(&answered.sidecars).expect("sidecars serialize")
        );

        let unreachable = unreachable_status_json(&info, "connection refused".to_string());
        assert_eq!(
            unreachable.error.as_deref(),
            Some("connection refused"),
            "the error passthrough is the whole point of this outcome"
        );
        assert_eq!(unreachable.socket_path.as_deref(), Some("/run/socket"));
        assert_eq!(unreachable.pid, Some(info.pid));
        assert_eq!(
            keys(&unreachable),
            ["error", "pid", "running", "socket_path"]
        );
        assert!(
            unreachable.running,
            "an unreachable daemon is still a running one"
        );

        let not_answering = not_answering_status_json(&info);
        assert_eq!(
            keys(&not_answering),
            ["pid", "reason", "running", "socket_path"]
        );
        assert!(
            !not_answering.running,
            "a daemon that does not answer is not reported running"
        );
        assert_eq!(not_answering.reason, Some("not_answering"));
        assert_eq!(not_answering.socket_path.as_deref(), Some("/run/socket"));
        assert_eq!(not_answering.pid, Some(info.pid));

        let stopped = stopped_status_json();
        assert_eq!(keys(&stopped), ["reason", "running"]);
        assert!(!stopped.running, "the stopped outcome is not running");
        assert_eq!(stopped.reason, Some("stopped"));
    }
}
