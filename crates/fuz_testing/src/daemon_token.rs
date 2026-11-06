//! Daemon-token **producer** — generate and persist the `X-Daemon-Token`
//! credential.
//!
//! **Test-only by dep graph.** This half lives here rather than in
//! `fuz_auth` because no @fuzdev consumer authenticates with
//! `X-Daemon-Token` in production: the credential exists to let the
//! cross-backend harness drive the `_testing_*` backdoor specs, which are
//! already confined to this crate. Keeping the producer alongside them means
//! a production binary cannot mint a keeper-grade credential or write it to
//! disk — the symbols aren't in its dependency graph, and `cargo xtask
//! check-release` fails the build if `fuz_testing` ever enters one.
//!
//! The consuming half — [`fuz_auth::DaemonTokenState`],
//! [`fuz_auth::validate_daemon_token`], and the keeper-account adapters —
//! stays in `fuz_auth`, where the credential walk needs it. On a
//! production assembly that state is `None` and the leg is unreachable.
//!
//! ## Secret-file discipline
//!
//! `write_token_file` goes through [`fuz_sys::secure_file::write_secure_file`],
//! which creates its temp with the mode applied **at creation** (`O_EXCL` +
//! `.mode(0o600)`), fsyncs, renames, then fsyncs the parent dir. A
//! hand-rolled path that writes the temp at the ambient umask and chmods
//! *after* the rename with the error discarded would publish the credential
//! world-readable for the length of that window, permanently if the chmod
//! failed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use fuz_auth::{DaemonTokenState, SharedDaemonTokenState};
use fuz_sys::SECURE_FILE_MODE;
use fuz_sys::secure_file::write_secure_file;
use parking_lot::RwLock;

/// Write the daemon token to disk atomically, owner-only from the first inode.
///
/// On-disk format is JSON `{"token": "..."}` — the wrapper leaves room
/// for future fields (`rotated_at`, version) without changing every
/// reader. Matches `fuz_app`'s TS `write_daemon_token` and the
/// cross-backend harness's TS reader (`spawn_backend.read_daemon_token`).
///
/// Delegates to [`write_secure_file`], so the credential is never observable
/// at the ambient umask: the temp file is created `O_EXCL` with mode `0600`
/// already applied, and the rename publishes that inode. There is no
/// post-rename `chmod` to fail silently.
///
/// The blocking write runs on [`tokio::task::spawn_blocking`] — a 60-byte
/// `write` plus two `fsync`s is short, but it is still filesystem I/O.
///
/// # Errors
///
/// Returns an `io::Error` when the parent directory cannot be created, the
/// secure write fails, or the blocking task panics.
async fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "token path has no parent dir",
            )
        })?
        .to_path_buf();

    tokio::fs::create_dir_all(&parent).await?;

    // Serializing `{token: <string>}` is infallible in practice; map the
    // theoretical error into an `io::Error` rather than panicking (this
    // crate forbids unjustified panic points and the daemon aborts on panic).
    let payload = serde_json::to_string(&serde_json::json!({"token": token}))
        .map_err(std::io::Error::other)?;
    let contents = format!("{payload}\n");
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        write_secure_file(&path, contents.as_bytes(), SECURE_FILE_MODE)
            .map_err(std::io::Error::other)
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Initialize daemon token state: generate a token, write it to
/// `<base_dir>/run/daemon_token`, return the shared handle.
///
/// The sole constructor of a populated [`DaemonTokenState`]. A test binary
/// calls this and injects the handle into the production assembly it wraps;
/// production assemblies leave the slot `None`.
///
/// # Errors
///
/// Returns an `io::Error` when the token file cannot be written.
pub async fn init_daemon_token(base_dir: &Path) -> std::io::Result<SharedDaemonTokenState> {
    let token_path: PathBuf = base_dir.join("run").join("daemon_token");
    // 32 random bytes → base64url (43 chars), the session token's format —
    // the twin of `fuz_app`'s `generate_daemon_token`
    let token = fuz_auth::generate_session_token();

    write_token_file(&token_path, &token).await?;
    tracing::info!(path = %token_path.display(), "daemon token initialized");

    let state = DaemonTokenState {
        current_token: token,
        previous_token: None,
        keeper_account_id: None,
        token_path,
    };

    Ok(Arc::new(RwLock::new(state)))
}

/// [`init_daemon_token`] driven by an env var naming the base dir, or
/// `Ok(None)` when that var is unset or empty.
///
/// The shape every `testing_*` binary needs: read the consumer's
/// `*_DAEMON_TOKEN_DIR`, expand a leading `~`, mint the credential, and hand
/// the handle to the production assembly's `run_app` / `build_router`. Unset
/// means "no daemon-token auth" — the same state a production binary is in,
/// so a test binary run without the var behaves like production rather than
/// half-configured.
///
/// The base dir does not need to exist: the token write `create_dir_all`s
/// the token's parent, which creates `<base_dir>` on the way.
///
/// # Errors
///
/// Returns the [`init_daemon_token`] I/O error when the var is set but the
/// credential can't be written, or an `InvalidInput` error when the value
/// starts with `~` and the home directory is unusable.
pub async fn init_daemon_token_from_env(
    var: &str,
) -> std::io::Result<Option<SharedDaemonTokenState>> {
    init_daemon_token_from_value(var, std::env::var(var).ok(), fuz_sys::home_dir).await
}

/// The core of [`init_daemon_token_from_env`], with the variable's value and
/// the home-directory lookup injected.
async fn init_daemon_token_from_value(
    var: &str,
    value: Option<String>,
    home_dir: impl FnOnce() -> Result<PathBuf, fuz_sys::HomeDirError>,
) -> std::io::Result<Option<SharedDaemonTokenState>> {
    let Some(dir) = value.filter(|dir| !dir.is_empty()) else {
        return Ok(None);
    };
    let dir = fuz_sys::expand_tilde_checked(&dir, home_dir).map_err(|reason| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{var}: {reason}"))
    })?;
    init_daemon_token(&dir).await.map(Some)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A `~` directory with an unusable home is refused before anything is
    /// written, never a credential under a literal `~` in the cwd. The value
    /// climbs into `/proc`, so a regression that expands against the real home
    /// fails to write (a different error kind) rather than planting a
    /// credential there.
    #[tokio::test]
    async fn from_value_refuses_a_tilde_dir_without_a_usable_home() {
        let value = "~/../../../../../../proc/fuz_testing_unwritable".to_owned();
        let error = init_daemon_token_from_value("X_DIR", Some(value), || {
            Err(fuz_sys::HomeDirError::Empty)
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().starts_with("X_DIR: "), "{error}");
    }

    #[tokio::test]
    async fn from_value_reads_an_empty_value_as_unset() {
        let state = init_daemon_token_from_value("X_DIR", Some(String::new()), || {
            unreachable!("an empty value never consults the home")
        })
        .await
        .expect("empty is unset");
        assert!(state.is_none());
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path)
            .expect("token file exists")
            .permissions()
            .mode()
            & 0o777
    }

    #[tokio::test]
    async fn init_publishes_the_token_owner_only() {
        // The regression pin: the credential must never be observable at the
        // ambient umask. A writer that creates the temp with `tokio::fs::write`
        // (0666 & ~umask → 0644 under the default) and chmods only *after* the
        // rename, discarding the error, publishes a world-readable inode for
        // that window — permanently so if the chmod fails. `write_secure_file`
        // applies the mode at creation instead, so there is no window and no
        // failure path that leaves it permissive.
        let dir = tempfile::tempdir().unwrap();
        let state = init_daemon_token(dir.path()).await.unwrap();

        let path = state.read().token_path.clone();
        assert_eq!(mode_of(&path), 0o600, "token file is owner-only");
        assert_eq!(
            state.read().current_token.len(),
            43,
            "the session token's format"
        );

        // No temp file survives the write.
        let strays: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "daemon_token")
            .collect();
        assert!(strays.is_empty(), "no temp files left behind: {strays:?}");
    }

    #[tokio::test]
    async fn from_env_is_none_when_the_var_is_unset_or_empty() {
        // Unset means "no daemon-token auth" — the same state production is
        // in — rather than a half-configured test binary. Empty counts as
        // unset so a blank value in a harness env map doesn't try to write a
        // credential into the process CWD.
        assert!(
            init_daemon_token_from_env("FUZ_TESTING_DAEMON_TOKEN_DIR_DEFINITELY_UNSET")
                .await
                .unwrap()
                .is_none()
        );
    }
}
