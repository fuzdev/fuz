//! Narrow filesystem seam for bootstrap token I/O.
//!
//! Bootstrap reads a one-shot token file on each request and deletes
//! it post-commit. The trait scopes to exactly those two operations so
//! unit tests can swap in an in-memory implementation without reaching
//! for a general filesystem abstraction.
//!
//! The token this file holds is the highest-value credential in the system —
//! presenting it mints the keeper account — so [`FileBootstrapTokenStore`]
//! reads it through [`fuz_sys::secure_file::load_secure_file`] rather than a
//! bare read: `O_NOFOLLOW` (symlink rejection with no TOCTOU window), a
//! regular-file check and permission check on the *descriptor* (a FIFO or
//! device node is refused without waiting on it; any group/other access is
//! refused), and a size cap. The deploy recipe already publishes it `0600`
//! owned by the service user, so the check ratifies the shape zap produces; a
//! hand-placed `0644` file fails loud at boot instead of being read.

use std::path::PathBuf;

use futures::future::BoxFuture;

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
pub trait BootstrapTokenStore: Send + Sync {
    /// Read the raw token bytes.
    fn read_token(&self) -> BoxFuture<'_, std::io::Result<Vec<u8>>>;

    /// Best-effort delete after successful bootstrap. The handler logs
    /// (but does not fail) if delete returns an error.
    fn delete_token(&self) -> BoxFuture<'_, std::io::Result<()>>;
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
/// # Errors
///
/// Returns an `io::Error` carrying the underlying
/// [`fuz_sys::secure_file::SecureFileError`]'s message — not found, symlink,
/// not a regular file, group/other-accessible mode, or over the size cap.
pub(crate) async fn read_bootstrap_token_file(path: PathBuf) -> std::io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        fuz_sys::secure_file::load_secure_file(&path).map_err(|e| {
            tracing::warn!(error = %e, "bootstrap token file rejected");
            std::io::Error::other(e)
        })
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

    fn delete_token(&self) -> BoxFuture<'_, std::io::Result<()>> {
        Box::pin(async move { tokio::fs::remove_file(&self.path).await })
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
    async fn delete_removes_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_token(dir.path(), b"secret-token-value\n", 0o600);
        let store = FileBootstrapTokenStore::new(path.clone());

        store.delete_token().await.expect("delete succeeds");

        assert!(!path.exists(), "one-shot token is gone after bootstrap");
    }
}
