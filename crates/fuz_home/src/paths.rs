//! Path and environment utilities
//!
//! Directory structure:
//! ```text
//! ~/.fuz/
//! ├── artifacts/        # Content-addressed self-artifact store (fuz-only)
//! │   └── v1-<hash>/    # Individual artifact
//! │       ├── fuz       # Binary
//! │       └── meta.json # Inputs, outputs, status
//! ├── current -> artifacts/v1-<hash>  # Active artifact symlink
//! ├── tools/            # Per-tool installs (fuzd, zap, …)
//! │   └── <name>/v1-<hash>/  # Tool binaries + meta.json; `current` symlink beside
//! ├── bin/              # Stable PATH entries
//! │   ├── fuz -> ../current/fuz
//! │   └── fuzd -> ../tools/fuzd/current/fuzd
//! ├── config/           # Configuration
//! │   └── signing.key   # Publisher signing key (mode 0600)
//! ├── run/              # Runtime (ephemeral, per-session)
//! │   ├── daemon.json   # PID, socket_path, schema version (mode 0600)
//! │   ├── socket        # UDS socket file (mode 0600)
//! │   ├── socket.lock   # fuzd's socket ownership lock (flock)
//! │   └── artifact.lock # Artifact lock: builds and `current` changes (flock)
//! ├── cache/            # Regenerable caches
//! │   └── npm/          # fuzi's npm tarball CAS
//! └── state/            # Persistent state
//!     ├── history.json  # Artifact switch history
//!     ├── release_log/  # head.json — the last accepted release log head
//!     └── logs/         # daemon_output.log (+ rotations)
//! ```
//!
//! An install directory's name is its content hash, `v1-` and 64 lowercase
//! hex (the BLAKE3 aggregate over its binaries; `fuz_artifact::is_content_hash`
//! is the one check of the form). This crate builds the paths around it and
//! leaves the name to the artifact layer.

use crate::error::FuzHomeError;
use fuz_sys::{HomeDirError, SECURE_DIR_MODE};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

//
// Directory names
//
// The layout's path segments. Building blocks for the `get_*_dir` helpers
// below, not API: this module is private and the crate root re-exports only
// `TOOLS_DIR` + `CURRENT_LINK`, the two a consumer walking the tool symlinks
// genuinely needs. They are still spelled `pub` because inside a private
// module that *is* the crate-visible spelling — `pub(crate)` says the same
// thing and trips `clippy::redundant_pub_crate` (nursery, and CI runs
// `-D warnings`). So the crate root's re-export list, not these declarations,
// is what draws the API line. The `~/.fuz` layout they spell out is a
// published contract (see `docs/fuz_home.md`) — changing a value moves every
// install's tree.
//

/// Config directory name
pub const CONFIG_DIR: &str = "config";

/// Run directory name (ephemeral runtime state)
pub const RUN_DIR: &str = "run";

/// State directory name (persistent state like logs)
pub const STATE_DIR: &str = "state";

/// Bin directory name
pub const BIN_DIR: &str = "bin";

/// Logs subdirectory name (under state)
pub const LOGS_DIR: &str = "logs";

/// Artifacts directory name
pub const ARTIFACTS_DIR: &str = "artifacts";

/// Tools directory name (per-tool install roots live under this)
pub const TOOLS_DIR: &str = "tools";

/// Current artifact symlink name (also the per-tool `current` symlink name)
pub const CURRENT_LINK: &str = "current";

/// Cache directory name (`~/.fuz/cache/`) — content-addressed download caches.
pub const CACHE_DIR: &str = "cache";

/// npm subdirectory under the cache (`~/.fuz/cache/npm/`).
///
/// fuzi's CAS of npm tarballs, keyed by their lockfile `integrity` (sha512).
/// Held *unsealed*: trust-anchored by npm's own integrity metadata, not an
/// @fuzdev signature.
pub const NPM_CACHE_DIR: &str = "npm";

//
// File names
//
// Same story as the directory names above — `pub` inside a private module,
// none of them re-exported. A consumer wants the composed path
// (`get_socket_path`, `get_daemon_log_path`) or the file's contents
// (`read_daemon_info` / `write_daemon_info`), never the segment.
//

/// Daemon info file name
pub const DAEMON_FILE: &str = "daemon.json";

/// Daemon UDS socket filename (under `~/.fuz/run/`).
pub const SOCKET_FILE: &str = "socket";

/// Daemon log file name
pub const DAEMON_LOG_FILE: &str = "daemon_output.log";

/// Get `FUZ_HOME` directory (default: ~/.fuz)
///
/// Resolution order: the test-only in-process override (under the
/// `test_home_override` feature) → the `FUZ_HOME` env var → `~/.fuz`, under
/// [`fuz_sys::home_dir`].
///
/// The result is always absolute. An empty `FUZ_HOME` reads as unset (the
/// workspace's "unset or empty" rule for env vars); a relative one is refused
/// rather than resolved against the process cwd, which would give every
/// command run from a different directory a different home. The `~/.fuz`
/// fallback holds the home directory to the same rule — see
/// [`fuz_sys::home_dir`]. `FUZ_HOME` is read as OS bytes, so a non-UTF-8
/// value is a path like any other, not a silent fallback to `~/.fuz`.
///
/// # Errors
/// [`FuzHomeError::RelativeFuzHome`] for a relative `FUZ_HOME`, or
/// [`FuzHomeError::HomeDir`] when `FUZ_HOME` is unset or empty and the home
/// directory is unusable.
pub fn get_fuz_home() -> Result<PathBuf, FuzHomeError> {
    #[cfg(feature = "test_home_override")]
    if let Some(path) = home_override::get() {
        return Ok(path);
    }
    resolve_fuz_home(std::env::var_os("FUZ_HOME"), fuz_sys::home_dir)
}

/// The pure core of [`get_fuz_home`], with `FUZ_HOME` and the home-directory
/// lookup injected.
fn resolve_fuz_home(
    fuz_home: Option<OsString>,
    home_dir: impl FnOnce() -> Result<PathBuf, HomeDirError>,
) -> Result<PathBuf, FuzHomeError> {
    let fuz_home = fuz_home.filter(|value| !value.is_empty());
    match fuz_home.map(PathBuf::from) {
        Some(path) if path.is_absolute() => Ok(path),
        Some(path) => Err(FuzHomeError::RelativeFuzHome { path }),
        None => Ok(home_dir().map_err(FuzHomeError::HomeDir)?.join(".fuz")),
    }
}

// --- Test-only home override (feature `test_home_override`) ------------------
//
// Redirects `get_fuz_home` in-process so the fetch/install flows (which resolve
// every `~/.fuz` path through this one funnel) can run against a temp dir. It
// exists because edition 2024 + the workspace's `unsafe_code = "forbid"` make
// `std::env::set_var("FUZ_HOME", …)` unavailable even in tests.
//
// Production-safety is the same discipline as `fuz_crypto`'s `test_trust_anchor`
// sibling (see that crate for the full rationale + verification): every item
// below is `#[cfg(feature = "test_home_override")]`, so feature-off the override
// code does not exist and `get_fuz_home` keeps its env-var/`~/.fuz` resolution —
// an accidental production reference to `set_fuz_home_override_for_testing` is a
// compile error. The feature is enabled only via `[dev-dependencies]` (the
// `fuz_sign` / `fuz_artifact` / `fuz_release` suites and this crate's own
// tests); `resolver = "2"` keeps it off every normal build (verified via
// `cargo tree -e features` + `nm` symbol-absence on the `fuz`/`fuzd` binaries).
//
// Lower-severity than the trust anchor: redirecting the home is no more
// privileged than the supported `FUZ_HOME` env var. The gate is still here so
// the symbol stays out of shipping binaries and so this can't be mistaken for a
// production reconfiguration hook.
//
// MAINTAINER: enable only from a `[dev-dependencies]` entry — never
// `[dependencies]`, `[build-dependencies]`, or a `default` feature set.

#[cfg(feature = "test_home_override")]
mod home_override {
    use std::path::PathBuf;
    use std::sync::RwLock;

    static OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

    pub(super) fn set(path: PathBuf) {
        *OVERRIDE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(path);
    }

    pub(super) fn clear() {
        *OVERRIDE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub(super) fn get() -> Option<PathBuf> {
        OVERRIDE
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Redirect [`get_fuz_home`] (and thus every `~/.fuz` path) to `path` for the
/// remainder of the process.
///
/// **Test-only** — behind the `test_home_override` feature, which no production
/// build enables. Lets a test drive the fetch/install flows against a temp home
/// without the `unsafe` env mutation that edition 2024 forbids.
#[cfg(feature = "test_home_override")]
pub fn set_fuz_home_override_for_testing(path: impl Into<PathBuf>) {
    home_override::set(path.into());
}

/// Clear the override set by [`set_fuz_home_override_for_testing`], restoring
/// the env-var/`~/.fuz` resolution.
///
/// **Test-only** (see [`set_fuz_home_override_for_testing`]).
#[cfg(feature = "test_home_override")]
pub fn clear_fuz_home_override_for_testing() {
    home_override::clear();
}

/// Get config directory (`~/.fuz/config/`)
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_config_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_fuz_home()?.join(CONFIG_DIR))
}

/// Get run directory (`~/.fuz/run/`) - ephemeral runtime state
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_run_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_fuz_home()?.join(RUN_DIR))
}

/// Get daemon socket path (`~/.fuz/run/socket`).
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_socket_path() -> Result<PathBuf, FuzHomeError> {
    Ok(get_run_dir()?.join(SOCKET_FILE))
}

/// The lock file beside a daemon socket (`<socket_path>.lock`) — the one
/// derivation shared by the daemon that holds it and the CLI that reads its
/// holder's pid.
///
/// Derived from the socket path rather than from `FUZ_HOME`, so a daemon on an
/// isolated socket (a test's tempdir) has a lock of its own.
#[must_use]
pub fn socket_lock_path(socket_path: &Path) -> PathBuf {
    let mut lock_path = socket_path.as_os_str().to_owned();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

/// Get state directory (`~/.fuz/state/`) - persistent state like logs
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_state_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_fuz_home()?.join(STATE_DIR))
}

/// Get bin directory (`~/.fuz/bin/`)
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_bin_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_fuz_home()?.join(BIN_DIR))
}

/// Get logs directory (`~/.fuz/state/logs/`)
///
/// Crate-internal — not re-exported. Consumers want the log file itself
/// (`get_daemon_log_path`), and [`ensure_fuz_home`] creates the directory.
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_logs_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_state_dir()?.join(LOGS_DIR))
}

/// Get artifacts directory (`~/.fuz/artifacts/`)
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_artifacts_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_fuz_home()?.join(ARTIFACTS_DIR))
}

/// Get current artifact symlink path (`~/.fuz/current`)
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_current_link() -> Result<PathBuf, FuzHomeError> {
    Ok(get_fuz_home()?.join(CURRENT_LINK))
}

/// Get the tools directory (`~/.fuz/tools/`) — per-tool install roots.
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_tools_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_fuz_home()?.join(TOOLS_DIR))
}

/// Get a single tool's directory (`~/.fuz/tools/<name>/`).
///
/// Holds content-addressed install dirs (`v1-<hash>/`) plus the `current`
/// symlink. Created on demand by the install flow.
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]),
/// or [`FuzHomeError::InvalidToolName`] when `name` is not a single plain path
/// component (empty, `.`, `..`, or containing `/`).
pub fn get_tool_dir(name: &str) -> Result<PathBuf, FuzHomeError> {
    // The name becomes one path component under `tools/`: a `..`, a `/`, or an
    // empty name would put every path built from it — the install dirs,
    // `current` — somewhere else.
    if !fuz_sys::fs::is_plain_file_name(name.as_ref()) {
        return Err(FuzHomeError::InvalidToolName {
            name: name.to_string(),
        });
    }
    Ok(get_tools_dir()?.join(name))
}

/// Get a tool's `current` symlink path (`~/.fuz/tools/<name>/current`).
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`])
/// or `name` is not a plain tool name (see [`get_tool_dir`]).
pub fn get_tool_current_link(name: &str) -> Result<PathBuf, FuzHomeError> {
    Ok(get_tool_dir(name)?.join(CURRENT_LINK))
}

/// Get the cache directory (`~/.fuz/cache/`).
///
/// Not created by [`ensure_fuz_home`] — caches are created on demand by the
/// tool that owns them (e.g. fuzi), at `fuz_sys::SECURE_DIR_MODE`.
///
/// Crate-internal — not re-exported. The only cache with an owner today is
/// fuzi's npm CAS, which consumers reach through [`get_npm_cache_dir`]; a
/// second cache adds its own accessor beside that one.
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_cache_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_fuz_home()?.join(CACHE_DIR))
}

/// Get the npm tarball cache directory (`~/.fuz/cache/npm/`) — fuzi's CAS.
///
/// # Errors
/// Returns an error if the fuz home cannot be resolved (see [`get_fuz_home`]).
pub fn get_npm_cache_dir() -> Result<PathBuf, FuzHomeError> {
    Ok(get_cache_dir()?.join(NPM_CACHE_DIR))
}

/// Ensure `FUZ_HOME` directory structure exists with secure permissions (mode 0700).
///
/// Creates with `DirBuilder::mode(0o700)` so newly-created directories
/// land at the secure mode atomically — no chmod-after-create window
/// where another user could see permissive umask perms (typically 0755)
/// on the freshly-created `~/.fuz/`.
///
/// Pre-existing directories (e.g. `~/.fuz/` from a prior install) keep
/// whatever mode they had — we don't tighten them on every run, because
/// that would silently override a user who deliberately loosened them.
///
/// Creates:
/// - `~/.fuz/` (mode 0700, if new)
/// - `~/.fuz/artifacts/` (mode 0700, if new)
/// - `~/.fuz/bin/` (mode 0700, if new)
/// - `~/.fuz/config/` (mode 0700, if new)
/// - `~/.fuz/run/` (mode 0700, if new)
/// - `~/.fuz/state/logs/` (mode 0700, if new)
///
/// # Errors
/// Returns an error if any directory cannot be created.
#[cfg(unix)]
pub fn ensure_fuz_home() -> Result<PathBuf, FuzHomeError> {
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;

    let fuz_home = get_fuz_home()?;

    // A pre-existing ~/.fuz must not be writable by other local users: with
    // write access they could swap out bin/fuz or an artifact and get code
    // execution the next time fuz runs. Refuse fail-closed rather than trust it.
    // (A fresh install has nothing to check — the dirs below land at 0700.)
    check_home_not_world_writable(&fuz_home)?;

    let artifacts_dir = get_artifacts_dir()?;
    let bin_dir = get_bin_dir()?;
    let config_dir = get_config_dir()?;
    let run_dir = get_run_dir()?;
    let logs_dir = get_logs_dir()?;

    // recursive(true) means each intermediate dir we create also lands at
    // mode 0o700 — covers `~/.fuz/state/` when we create `~/.fuz/state/logs/`.
    let mut builder = fs::DirBuilder::new();
    builder.mode(SECURE_DIR_MODE).recursive(true);

    for dir in [&artifacts_dir, &bin_dir, &config_dir, &run_dir, &logs_dir] {
        builder
            .create(dir)
            .map_err(|source| FuzHomeError::CreateDirFailed {
                path: dir.clone(),
                source,
            })?;
    }

    Ok(fuz_home)
}

/// Refuse to write under a `~/.fuz` that is world-writable.
///
/// [`ensure_fuz_home`] applies the same guard at creation time. This is the
/// standalone form, for the **repeat** write paths that land a fresh binary in
/// an already-existing home: `fuz self upgrade`, `fuz tool install` /
/// `upgrade`, and the no-forge local tool install behind `cargo xtask install`
/// resolve their target dirs (`get_artifacts_dir` / [`get_tool_dir`]) and
/// create them directly, never calling [`ensure_fuz_home`] (the
/// xtask flow does call it, but the install function it reaches is public API
/// that must hold the floor for any caller). Without this call they would
/// install into a home that turned world-writable *after* bootstrap — the
/// exact tree an attacker swaps `bin/fuz` in.
///
/// Call it once at the top of any flow that installs a binary under `~/.fuz`,
/// before the first filesystem write (and before any network work, so the
/// refusal is immediate). Read-only flows must **not** call it — `fuz self upgrade
/// --check` / `fuz tool upgrade --check` write nothing, and refusing there
/// would change their exit-code contract.
///
/// See [`FuzHomeError::InsecureHome`] for what counts (only the other-write
/// bit) and why.
///
/// # Errors
/// [`FuzHomeError::InsecureHome`] if the home exists and is world-writable,
/// [`FuzHomeError::ReadFailed`] if its mode can't be read, or
/// [`FuzHomeError::HomeDir`] or [`FuzHomeError::RelativeFuzHome`] if the home
/// can't be resolved. A missing home is fine — nothing is installed there yet.
#[cfg(unix)]
pub fn check_fuz_home_not_world_writable() -> Result<(), FuzHomeError> {
    check_home_not_world_writable(&get_fuz_home()?)
}

/// Reject a pre-existing `~/.fuz` that is world-writable (writable by *any*
/// local user), which would let someone else swap out `bin/fuz` or an artifact
/// and get code execution the next time fuz runs. Refuse fail-closed rather than
/// trust it — the spirit of SSH's `StrictModes`.
///
/// The path-taking core behind [`ensure_fuz_home`] (which already holds the
/// resolved home) and [`check_fuz_home_not_world_writable`] (which resolves it
/// for external callers).
///
/// Only the other-write bit (`0o002`) is checked, not group-write: under the
/// common private-group scheme (each user in their own group) plus `umask 002`,
/// a `0775` directory is routine and benign, so flagging group-write would be a
/// pervasive false positive. A missing dir is fine — the caller creates it at
/// `0700`. Follows symlinks: the real directory's mode is what matters. A dir
/// owned by a *different* user isn't singled out — the caller's `create_dir`
/// fails with `EACCES` on it anyway.
#[cfg(unix)]
fn check_home_not_world_writable(path: &Path) -> Result<(), FuzHomeError> {
    use std::os::unix::fs::PermissionsExt;

    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(FuzHomeError::ReadFailed {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o002 != 0 {
        return Err(FuzHomeError::InsecureHome {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A tool name that is not one plain component is refused before any path
    /// is built from it (and before the home is even resolved), so nothing
    /// derived from it — install dirs, `current` — can leave `tools/`.
    #[test]
    fn get_tool_dir_refuses_a_name_that_is_not_one_component() {
        for name in ["", ".", "..", "../x", "a/b", "fuzd/", "../../current"] {
            for result in [get_tool_dir(name), get_tool_current_link(name)] {
                assert!(
                    matches!(&result, Err(FuzHomeError::InvalidToolName { name: n }) if n == name),
                    "{name:?}: got {result:?}"
                );
            }
        }
    }

    /// The lock sits beside the socket it guards, whatever directory that is.
    #[test]
    fn socket_lock_path_appends_lock_to_the_socket_path() {
        assert_eq!(
            socket_lock_path(Path::new("/home/u/.fuz/run/socket")),
            PathBuf::from("/home/u/.fuz/run/socket.lock")
        );
        assert_eq!(
            socket_lock_path(Path::new("/tmp/x/s")),
            PathBuf::from("/tmp/x/s.lock")
        );
    }

    #[test]
    fn world_writable_check_allows_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        check_home_not_world_writable(&dir.path().join("does-not-exist"))
            .expect("a missing ~/.fuz is fine — it gets created at 0700");
    }

    #[test]
    fn world_writable_check_allows_owner_and_group_writable() {
        // 0700 (owner-only) and 0775 (group-writable — routine under umask 002 /
        // private groups) are both fine: only *other*-write is a real hole.
        for mode in [0o700, 0o750, 0o770, 0o775] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                check_home_not_world_writable(dir.path()).is_ok(),
                "mode {mode:o} should be allowed (only other-write is a hole)"
            );
        }
    }

    #[test]
    fn world_writable_check_rejects_other_writable() {
        for mode in [0o777, 0o707, 0o703, 0o702] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let err = check_home_not_world_writable(dir.path()).unwrap_err();
            assert!(
                matches!(err, FuzHomeError::InsecureHome { .. }),
                "mode {mode:o} must be rejected, got {err:?}"
            );
        }
    }

    /// `FUZ_HOME`'s rule: absolute is used as given (the home directory never
    /// consulted), empty is unset, relative is refused.
    #[test]
    fn resolve_fuz_home_takes_an_absolute_fuz_home_and_reads_empty_as_unset() {
        let unreachable = || -> Result<PathBuf, HomeDirError> {
            panic!("home directory consulted with FUZ_HOME set")
        };
        assert_eq!(
            resolve_fuz_home(Some("/srv/fuz".into()), unreachable).unwrap(),
            PathBuf::from("/srv/fuz")
        );
        let fallback = || Ok(PathBuf::from("/home/u"));
        for unset in [None, Some(OsString::new())] {
            assert_eq!(
                resolve_fuz_home(unset.clone(), fallback).unwrap(),
                PathBuf::from("/home/u/.fuz"),
                "FUZ_HOME={unset:?}"
            );
        }
        for relative in ["relhome", "./fuz", "~/.fuz"] {
            let error = resolve_fuz_home(Some(relative.into()), unreachable).unwrap_err();
            assert!(
                matches!(&error, FuzHomeError::RelativeFuzHome { path } if path == Path::new(relative)),
                "FUZ_HOME={relative}: {error}"
            );
        }
    }

    /// With `FUZ_HOME` unset or empty, an unusable home directory is an error
    /// carrying the reason — never a `.fuz` joined onto an empty or relative
    /// home, which would land under the process cwd.
    #[test]
    fn resolve_fuz_home_refuses_an_unusable_home_directory() {
        for reason in [
            HomeDirError::NotFound,
            HomeDirError::Empty,
            HomeDirError::Relative {
                path: PathBuf::from("h"),
            },
        ] {
            for unset in [None, Some(OsString::new())] {
                let error = resolve_fuz_home(unset, || Err(reason.clone())).unwrap_err();
                assert!(
                    matches!(&error, FuzHomeError::HomeDir(found) if *found == reason),
                    "{reason}: {error}"
                );
            }
        }
    }
}
