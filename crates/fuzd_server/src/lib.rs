//! Fuzd UDS server library.
//!
//! Binds a Unix domain socket at the configured path (`~/.fuz/run/socket`
//! by default) under an exclusive lock beside it, so one daemon owns a path at
//! a time; authenticates peers via `SO_PEERCRED` (same-uid only),
//! and dispatches postcard-framed actions: the daemon control plane, the
//! demand-driven workload registry (observer and watcher kinds), and the
//! dormant sidecar actions, answered by the configured [`Sidecar`] pool.

mod auth;
mod conn;
mod dispatch;
mod error;
mod logging;
mod out;
mod workload;

pub use error::ServerError;
pub use logging::RequestLogger;
pub use workload::services_source::SYSTEMCTL_SHOW_TIMEOUT;
pub use workload::source::{ObserverError, ObserverSource, UserScopedSource};
pub use workload::watch_source::{NotifyWatchSource, WatchError, WatchSession, WatchSource};
pub use workload::{RegistryConfig, WorkloadRegistry};

use fuz_home::{SHUTDOWN_TIMEOUT_SECS, SOCKET_PATH_MAX, socket_lock_path};
use fuz_sidecar::Sidecar;
use fuz_sys::file_lock::{FileLock, FileLockError, LockInfo};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

/// Server configuration.
#[derive(Debug)]
pub struct ServerConfig {
    /// Path to the UDS socket file. Created at startup with mode 0600.
    pub socket_path: PathBuf,
    /// Daemon version string, advertised back via `HelloResponse` and
    /// `DaemonStatusResponse`.
    pub version: String,
}

/// Connection drain timeout (matches `SHUTDOWN_TIMEOUT_SECS`).
const DRAIN_TIMEOUT: Duration = Duration::from_secs(SHUTDOWN_TIMEOUT_SECS);

/// Shared application state visible to every dispatcher invocation.
#[derive(Debug)]
pub struct AppState<S: Sidecar> {
    pub sidecar: Arc<S>,
    pub version: Arc<String>,
    pub shutdown: CancellationToken,
    pub logger: Arc<RequestLogger>,
    pub draining: Arc<AtomicBool>,
    /// Demand-driven workload registry (observer collectors, future
    /// watcher etc.). Cheap to clone — one `Arc` inside.
    pub workloads: WorkloadRegistry,
}

impl<S: Sidecar> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            sidecar: Arc::clone(&self.sidecar),
            version: Arc::clone(&self.version),
            shutdown: self.shutdown.clone(),
            logger: Arc::clone(&self.logger),
            draining: Arc::clone(&self.draining),
            workloads: self.workloads.clone(),
        }
    }
}

/// Run the UDS server with an async sidecar.
///
/// Takes the socket path's lock (`<socket_path>.lock`), binds the socket, sets
/// the run dir to 0700 and the socket to 0600, and spawns an accept loop. The
/// caller-supplied `shutdown` token cancels both the accept loop and
/// in-flight connection tasks; cleanup unlinks the socket file and releases
/// the lock before the connection drain.
///
/// The lock is what makes the bind exclusive: the bind itself unlinks a
/// leftover socket first, so without it a second daemon on the same path would
/// silently take over a live one's socket.
///
/// # Errors
///
/// Returns [`ServerError::SocketPathTooLong`] if `socket_path` exceeds
/// [`SOCKET_PATH_MAX`] (nothing is created, locked, or bound),
/// [`ServerError::AlreadyRunning`] if another fuzd holds the lock
/// (nothing is unlinked or bound), [`ServerError::Lock`] if the lock can't be
/// taken for another reason, [`ServerError::Bind`] if `socket_path` can't be
/// bound, [`ServerError::SocketPerms`] if chmod fails,
/// [`ServerError::RemoveStaleSocket`] if a leftover socket file can't
/// be removed, or [`ServerError::Uid`] if `/proc/self/status` can't be
/// read.
pub async fn run<S: Sidecar + 'static>(
    sidecar: S,
    config: ServerConfig,
    shutdown: CancellationToken,
    logger: Arc<RequestLogger>,
) -> Result<(), ServerError> {
    check_socket_path_len(&config.socket_path)?;
    let daemon_uid = current_uid()?;

    // Ensure the socket parent directory exists.
    if let Some(parent) = config.socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        // Moded, and recursive: on a `~/.fuz` that does not exist yet this call
        // mints the home *and* `run/`, and an unmoded create would leave the
        // ancestor at `0o777 & !umask` permanently — the `set_permissions`
        // below only reaches the leaf.
        tokio::fs::DirBuilder::new()
            .mode(fuz_sys::SECURE_DIR_MODE)
            .recursive(true)
            .create(parent)
            .await
            .map_err(|source| ServerError::Bind {
                path: config.socket_path.clone(),
                source,
            })?;
        // Tighten the run dir to owner-only; defense-in-depth behind the
        // 0600 socket and the SO_PEERCRED same-uid gate. Distinct from the
        // create above, which is a no-op on a directory that already exists:
        // this re-tightens a run dir a previous, laxer run left behind.
        // The socket is 0600 on its own, but an owner-only parent keeps other
        // users from traversing to it.
        let dir_perms = std::fs::Permissions::from_mode(fuz_sys::SECURE_DIR_MODE);
        std::fs::set_permissions(parent, dir_perms).map_err(|source| ServerError::SocketPerms {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    // Own the socket path before touching it. A live daemon holds this lock for
    // as long as it owns the path, so a second one stops here — before the
    // unlink below, which would otherwise take a running daemon's socket out
    // from under it. `flock` dies with its holder, so a crashed daemon leaves
    // nothing to recover.
    let socket_lock = acquire_socket_lock(&config.socket_path)?;

    // Remove any leftover socket file from a previous run.
    remove_socket_if_exists(&config.socket_path).await?;

    let listener = UnixListener::bind(&config.socket_path).map_err(|source| ServerError::Bind {
        path: config.socket_path.clone(),
        source,
    })?;
    let perms = std::fs::Permissions::from_mode(fuz_sys::SECURE_FILE_MODE);
    std::fs::set_permissions(&config.socket_path, perms).map_err(|source| {
        ServerError::SocketPerms {
            path: config.socket_path.clone(),
            source,
        }
    })?;

    let draining = Arc::new(AtomicBool::new(false));
    // Observer collectors read user-scoped `/proc` + `systemctl --user`; watcher
    // collectors run `notify` filesystem watches. The registry's root token is
    // the daemon shutdown token, so shutdown stops every collector.
    let workloads = WorkloadRegistry::new(
        Arc::new(UserScopedSource::new()),
        Arc::new(NotifyWatchSource::new()),
        shutdown.clone(),
    );
    let state = Arc::new(AppState {
        sidecar: Arc::new(sidecar),
        version: Arc::new(config.version),
        shutdown: shutdown.clone(),
        logger: Arc::clone(&logger),
        draining: Arc::clone(&draining),
        workloads,
    });

    // Spawn the logger flush task.
    let flush_handle = logger.spawn_flush_task(shutdown.clone());

    info!(socket = %config.socket_path.display(), uid = daemon_uid, "fuzd listening");

    let connections = TaskTracker::new();
    let accept_task = {
        let state = Arc::clone(&state);
        let shutdown = shutdown.clone();
        tokio::spawn(conn::accept_uds(
            listener,
            state,
            daemon_uid,
            shutdown,
            connections.clone(),
        ))
    };

    // Wait for the shutdown signal, then drain with a bounded budget.
    shutdown.cancelled().await;
    info!("shutdown signal received, draining connections");
    draining.store(true, std::sync::atomic::Ordering::Relaxed);

    // Stop accepting, unlink the socket, and release the socket lock at once.
    // A restarting CLI counts this daemon stopped once it no longer answers
    // and the lock's body no longer names it, so a new daemon may take the
    // path while this one drains; unlinking any later would delete the new
    // daemon's socket.
    accept_task.abort();
    let _ = accept_task.await;
    if let Err(err) = remove_socket_if_exists(&config.socket_path).await {
        warn!(
            error = %fuz_sys::cli::format_error_chain(&err),
            "failed to remove socket on shutdown"
        );
    }
    // Release the path with the socket, not at exit: the lock guards the window
    // in which this daemon owns the path, and that window just closed. Held
    // through the drain, it would refuse the daemon a restarting CLI starts
    // next as "already running" for up to the drain timeout. The lock file
    // itself stays — see `acquire_socket_lock`.
    drop(socket_lock);

    // Then wait for the connection tasks: each one finishes the dispatch it is
    // in and flushes its writer — the `DAEMON_SHUTDOWN` response included —
    // before the process is allowed to exit. A connection that can't within its
    // flush budget (see `conn::run_conn`) tears itself down, so this timeout is
    // a backstop, not the bound a client that stops reading meets.
    connections.close();
    if tokio::time::timeout(DRAIN_TIMEOUT, connections.wait())
        .await
        .is_err()
    {
        warn!(
            remaining = connections.len(),
            "connections still open after the drain timeout"
        );
    }

    // Wait for the logger to finish flushing.
    flush_handle.await.ok();

    info!("server shutdown complete");

    Ok(())
}

/// Refuse a socket path longer than [`SOCKET_PATH_MAX`].
///
/// `bind` would refuse it too, but only as an `InvalidInput` under the generic
/// [`ServerError::Bind`] — and only after the run dir and the lock were made —
/// so the length is checked up front, where the error can name the cause.
fn check_socket_path_len(socket_path: &Path) -> Result<(), ServerError> {
    let len = socket_path.as_os_str().len();
    if len > SOCKET_PATH_MAX {
        return Err(ServerError::SocketPathTooLong {
            path: socket_path.to_path_buf(),
            len,
            max: SOCKET_PATH_MAX,
        });
    }
    Ok(())
}

/// Take the exclusive lock that says this daemon owns `socket_path`.
///
/// The lock file sits beside the socket (`<socket_path>.lock`), so a daemon on
/// an isolated socket — a test's tempdir — has a lock of its own. It is opened
/// `SECURE_FILE_MODE` in the run dir `run` has already created and tightened,
/// and its body names the holder's pid — for the refusal message, for whoever
/// `cat`s it, and for `fuzd start` / `stop`, which read it to tell this daemon
/// from another. Taking it is `run`'s first act on the path, so the pid is in
/// the body before the socket is bound.
///
/// Nothing removes the lock file, on release or shutdown: `flock` locks the
/// inode, so unlinking the path while another daemon is about to lock it would
/// let two daemons each hold a lock on a different inode.
fn acquire_socket_lock(socket_path: &Path) -> Result<FileLock, ServerError> {
    let lock_path = socket_lock_path(socket_path);
    FileLock::acquire(&lock_path, &LockInfo::current()).map_err(|source| match source {
        FileLockError::Held { pid } => ServerError::AlreadyRunning {
            socket_path: socket_path.to_path_buf(),
            pid,
        },
        source => ServerError::Lock {
            path: lock_path,
            source,
        },
    })
}

async fn remove_socket_if_exists(path: &Path) -> Result<(), ServerError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ServerError::RemoveStaleSocket {
            path: path.to_path_buf(),
            source: err,
        }),
    }
}

/// Read the real UID from `/proc/self/status`. Linux-only, no extra deps.
///
/// macOS gap: `/proc` doesn't exist there, so this fails and `fuzd` won't start.
/// The peer-side credential read already uses tokio's portable `UCred`; only
/// this self-uid lookup is Linux-bound. Port to a portable `geteuid()` (nix
/// `user` feature) to run on macOS — see `docs/platform_support.md` § macOS.
fn current_uid() -> Result<u32, ServerError> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(ServerError::Uid)?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let real = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| ServerError::Uid(std::io::Error::other("missing real UID")))?;
            return real
                .parse::<u32>()
                .map_err(|err| ServerError::Uid(std::io::Error::other(err.to_string())));
        }
    }
    Err(ServerError::Uid(std::io::Error::other(
        "no Uid: line in /proc/self/status",
    )))
}
