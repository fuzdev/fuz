//! Narrow filesystem seam for bootstrap token I/O.
//!
//! Bootstrap reads a one-shot token file on each request and burns it inside
//! the transaction the token authorized, just before the commit. The trait
//! scopes to exactly those two operations so unit tests can swap in an
//! in-memory implementation without reaching for a general filesystem
//! abstraction.
//!
//! The token this file holds is the highest-value credential in the system —
//! presenting it mints the keeper account — so [`FileBootstrapTokenStore`]
//! reads it through [`fuz_sys::secure_file::load_secure_file`] rather than a
//! bare read: `O_NOFOLLOW` (symlink rejection with no TOCTOU window), a
//! regular-file check and permission check on the *descriptor* (a FIFO or
//! device node is refused without waiting on it; any group/other access is
//! refused), and a size cap. The deploy recipe already publishes it `0600`
//! owned by the service user, so the check ratifies the shape zap produces; a
//! hand-placed `0644` file fails loud at boot instead of being read. It burns
//! it through [`fuz_sys::secure_file::burn_secure_file`]: unlink the entry,
//! then fsync the directory, so a crash after the commit can't bring it back.

use std::path::PathBuf;

use futures::future::BoxFuture;
use fuz_sys::secure_file::BurnOutcome;

/// Two-operation seam for the one-shot bootstrap token file.
///
/// Implementations must not trim or normalize the bytes returned by
/// [`Self::read_token`] — the caller does length-independent trimming
/// and a constant-time compare. Variable-time work in this trait would
/// re-open the timing oracle the bootstrap handler closes.
///
/// **Object-safe** — consumed as `Arc<dyn BootstrapTokenStore>` so
/// [`crate::BootstrapOptions`] stays non-generic. Async via
/// [`BoxFuture`], the dyn-trait convention — RPITIT
/// doesn't yet support `dyn`.
///
/// Twin of `fuz_app`'s `BootstrapTokenStore`, which also carries the token's
/// `path` for its log lines: the TS boot check reads through the store, while
/// [`crate::is_bootstrap_available`] takes the path itself.
pub trait BootstrapTokenStore: Send + Sync {
    /// Read the raw token bytes.
    fn read_token(&self) -> BoxFuture<'_, std::io::Result<Vec<u8>>>;

    /// Burn the token so it can never be presented again. Required, not
    /// best-effort: [`crate::bootstrap_handler`] calls it last inside the
    /// bootstrap transaction, and an `Err` rolls the bootstrap back
    /// (`token_file_undeletable`). [`BurnOutcome::AlreadyGone`] — nothing was
    /// there — is a burn: the token can't be presented either way.
    fn burn_token(&self) -> BoxFuture<'_, std::io::Result<BurnOutcome>>;
}

/// Read a bootstrap token file with the secure-file checks applied.
///
/// Shared by [`FileBootstrapTokenStore::read_token`] and
/// [`crate::is_bootstrap_available`] so "bootstrap is available" and "the
/// token file can actually be read" can't drift apart — an availability
/// check laxer than the read it gates is the misconfiguration that reports
/// green at boot and fails at request time.
///
/// Runs the blocking read on [`tokio::task::spawn_blocking`]; the secure-file
/// helpers are sync (`std::fs`) because they need descriptor-level `fstat` and
/// `O_NOFOLLOW`, which `tokio::fs` doesn't expose.
///
/// Logs nothing: whether a refusal is worth a warning depends on the caller
/// (a bootstrapped server with no token file is the steady state), so each
/// caller logs at its own level.
///
/// # Errors
///
/// Returns an `io::Error` carrying the underlying
/// [`fuz_sys::secure_file::SecureFileError`]'s message — not found, symlink,
/// not a regular file, group/other-accessible mode, or over the size cap.
pub(crate) async fn read_bootstrap_token_file(path: PathBuf) -> std::io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        fuz_sys::secure_file::load_secure_file(&path).map_err(std::io::Error::other)
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Production [`BootstrapTokenStore`] backed by `read_bootstrap_token_file`.
///
/// The configured path is logged once at construction by the wiring
/// site, so error paths don't need to thread the path through the
/// trait surface.
pub struct FileBootstrapTokenStore {
    path: PathBuf,
}

impl FileBootstrapTokenStore {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    #[must_use]
    pub const fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl std::fmt::Debug for FileBootstrapTokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBootstrapTokenStore")
            .field("path", &self.path)
            .finish()
    }
}

impl BootstrapTokenStore for FileBootstrapTokenStore {
    fn read_token(&self) -> BoxFuture<'_, std::io::Result<Vec<u8>>> {
        Box::pin(read_bootstrap_token_file(self.path.clone()))
    }

    fn burn_token(&self) -> BoxFuture<'_, std::io::Result<BurnOutcome>> {
        let path = self.path.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                fuz_sys::secure_file::burn_secure_file(&path).map_err(std::io::Error::other)
            })
            .await
            .map_err(std::io::Error::other)?
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn write_token(dir: &std::path::Path, contents: &[u8], mode: u32) -> PathBuf {
        let path = dir.join("secret_bootstrap_token");
        std::fs::write(&path, contents).expect("write token");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("set token mode");
        path
    }

    #[tokio::test]
    async fn reads_an_owner_only_token_verbatim() {
        // Bytes come back untouched — the handler owns trailing-newline
        // handling and the constant-time compare, so any normalization here
        // would reopen the timing oracle the trait doc warns about.
        let dir = tempfile::tempdir().unwrap();
        let path = write_token(dir.path(), b"secret-token-value\n", 0o600);
        let store = FileBootstrapTokenStore::new(path);

        let bytes = store.read_token().await.expect("owner-only token reads");

        assert_eq!(bytes, b"secret-token-value\n");
    }

    #[tokio::test]
    async fn rejects_a_group_or_world_readable_token() {
        // The regression pin: a plain `tokio::fs::read` accepts any readable
        // file, so a bootstrap token left at 0644 — the mode a hand-rolled
        // `echo … > file` produces under the default umask — would be read and
        // honored, handing keeper-account creation to every local user. Both
        // permissive modes must fail loud.
        for mode in [0o644, 0o640] {
            let dir = tempfile::tempdir().unwrap();
            let path = write_token(dir.path(), b"secret-token-value\n", mode);
            let store = FileBootstrapTokenStore::new(path);

            let result = store.read_token().await;

            assert!(
                result.is_err(),
                "mode {mode:o} must be refused, not read as a valid token"
            );
        }
    }

    #[tokio::test]
    async fn rejects_a_symlinked_token() {
        // `O_NOFOLLOW` rejects the link atomically, so a writable directory
        // can't be used to redirect the read at a file the operator never
        // placed (and whose mode the check would then be asserting about the
        // wrong inode).
        let dir = tempfile::tempdir().unwrap();
        let target = write_token(dir.path(), b"secret-token-value\n", 0o600);
        let link = dir.path().join("linked_token");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        let store = FileBootstrapTokenStore::new(link);

        assert!(store.read_token().await.is_err(), "symlink must be refused");
    }

    #[tokio::test]
    async fn missing_token_is_an_error_not_an_empty_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileBootstrapTokenStore::new(dir.path().join("absent"));

        assert!(store.read_token().await.is_err());
    }

    #[tokio::test]
    async fn burn_removes_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_token(dir.path(), b"secret-token-value\n", 0o600);
        let store = FileBootstrapTokenStore::new(path.clone());

        let outcome = store.burn_token().await.expect("burn succeeds");

        assert_eq!(outcome, BurnOutcome::Burned);
        assert!(!path.exists(), "one-shot token is gone after bootstrap");
    }

    #[tokio::test]
    async fn burn_of_a_missing_token_is_already_gone() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileBootstrapTokenStore::new(dir.path().join("absent"));

        let outcome = store.burn_token().await.expect("a missing token is burned");

        assert_eq!(outcome, BurnOutcome::AlreadyGone);
    }

    /// A directory the server can't write refuses the burn and keeps the
    /// token — what rolls a bootstrap back. As root the unlink succeeds and
    /// this fails: run the suite as an unprivileged user.
    #[tokio::test]
    async fn burn_fails_in_a_directory_the_server_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("bootstrap");
        std::fs::create_dir(&sub).unwrap();
        let path = write_token(&sub, b"secret-token-value\n", 0o600);
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();
        let store = FileBootstrapTokenStore::new(path.clone());

        let result = store.burn_token().await;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "the burn is refused (as root it would succeed)"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"secret-token-value\n");
    }
}
