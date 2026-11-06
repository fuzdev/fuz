//! Storage backends for Fuz
//!
//! This crate provides the `Storage` trait and implementations for different backends:
//! - `FileStorage` - Local filesystem (no credentials needed)
//! - `ForgeStorage` - a running `fuz_forge` over HTTP (`/api/fuz_forge/files`)
//! - `SshStorage` - a remote host over SSH (`scp`/`ssh`)
//! - `HttpsStorage` - a public static host over anonymous HTTPS (read-only)
//!
//! Every backend is a **dumb byte store** — it never signs or verifies. `fuz`
//! verifies the ed25519 signature + blake3 pins against its embedded key after
//! fetching, regardless of transport, so the byte source and the trust anchor
//! are orthogonal (see `docs/storage_backends.md`). Auth is per-backend and
//! ambient: `forge://` uses a bearer token (`FUZ_FORGE_TOKEN`, else
//! `<fuz_forge_home>/api_token`, resolved by [`forge_home`]), `ssh://`
//! uses the caller's ssh agent / key, and local paths and `https://` need
//! nothing — there is no shared `credentials.json`.
//!
//! Naming a store never creates it: constructing a backend, or parsing a
//! location into one, changes nothing on disk or on a host. A local store's
//! directory comes into being with the first upload, so only a publish makes
//! one; [`parse_existing_storage`] is the parse for every caller that works
//! on a store already there, and refuses a local directory that is not.
//!
//! A key is held to one contract by every backend ([`validate_forge_key`]),
//! so no key names a path outside the storage root. That is a rule about
//! keys, not about the tree under the root. On the filesystem backends a
//! symlinked root or directory is followed by whatever goes through it, and a
//! symlink to a file is read through by `download`, `download_to_file`, and
//! `exists` (an upload replaces the link, a delete removes it) — so a store
//! reads from wherever its links point. No [`Storage`] method creates a link;
//! planting one takes write access to the store by other means. `list`
//! returns regular files only there: a symlink to a file is not listed.
//!
//! All backends share one on-store layout, owned by
//! `fuz_release::ReleaseLayout` — flat at the
//! root for the fuz self artifact, one `tools/<name>/` prefix per tool. The
//! version lives in the filename, never as a directory level, so a tool's
//! whole stream is one list-prefix:
//! ```text
//! releases/
//! ├── latest-x86_64-unknown-linux-gnu.json
//! ├── fuz-0.3.0-x86_64-unknown-linux-gnu.tar.gz
//! ├── fuz-0.3.0-x86_64-unknown-linux-gnu.manifest.json
//! └── tools/
//!     └── fuzd/
//!         ├── latest-x86_64-unknown-linux-gnu.json
//!         ├── fuzd-0.3.0-x86_64-unknown-linux-gnu.tar.gz
//!         └── fuzd-0.3.0-x86_64-unknown-linux-gnu.manifest.json
//! ```
//! Keys therefore contain `/`, which is why every backend validates them
//! traversal-safe rather than assuming a single flat segment.

// Allow missing errors docs for obvious Result functions
#![allow(clippy::missing_errors_doc)]

pub mod base_url;
pub mod error;
mod file;
mod forge;
pub mod forge_home;
pub(crate) mod http_client;
pub(crate) mod http_status;
pub(crate) mod http_transfer;
mod https;
mod key;
mod ssh;

use std::future::Future;
use std::path::Path;

pub use error::{StorageBackendKind, StorageError};
pub use file::FileStorage;
pub use forge::{
    ForgeStorage, MAX_FORGE_LIST_SIZE, forge_base_url_refusal_message, forge_client_builder,
};
pub use http_client::Redirects;
pub use http_transfer::{MAX_ERROR_BODY_LEN, read_error_text};
pub use https::HttpsStorage;
pub use key::{validate_forge_key, validate_list_prefix};
pub use ssh::SshStorage;

/// Storage backend trait for release distribution.
///
/// All paths are relative to the storage root (bucket, directory, etc.), and
/// are keys held to one contract ([`validate_forge_key`]): every backend
/// refuses, with [`StorageError::InvalidKey`], a key that is absolute, has a
/// `.` or `..` segment, or steps outside `[A-Za-z0-9._/-]` — before it becomes
/// a filesystem path, a URL, or a remote command. No key names a path outside
/// the root; a symlink under the root is followed (see the crate docs).
/// Implementations must be async-safe and handle their own connection pooling.
///
/// **Not object-safe** — methods return `impl Future` (RPITIT), so
/// `dyn` dispatch is unavailable on stable Rust. Consumed via the
/// [`StorageBackend`] enum wrapper (or `<T: Storage>` bounds), never as
/// `Arc<dyn Storage>`.
pub trait Storage: Send + Sync {
    /// Which backend this is — the typed identity used in error messages.
    fn backend_kind(&self) -> StorageBackendKind;

    /// Human-readable name for error messages (e.g. "`FileStorage`", "SSH").
    fn name(&self) -> &'static str {
        self.backend_kind().label()
    }

    /// Refuse a read-only backend, with the [`StorageError::Unsupported`] its
    /// own `operation` (`upload`, `list`, `delete`) would return.
    ///
    /// For a caller whose work ends in such an operation — a publish packs
    /// and signs before its first upload — to learn it up front, from the
    /// backend rather than from which backend it happens to be.
    fn require_writable(&self, operation: &'static str) -> Result<(), StorageError> {
        let backend = self.backend_kind();
        if backend.is_read_only() {
            return Err(StorageError::Unsupported { backend, operation });
        }
        Ok(())
    }

    /// Upload data to the given path.
    ///
    /// Creates parent directories as needed (for filesystem backends).
    /// Overwrites existing files.
    fn upload(
        &self,
        path: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Download data from the given path.
    ///
    /// Returns `StorageError::NotFound` if the path doesn't exist.
    fn download(&self, path: &str) -> impl Future<Output = Result<Vec<u8>, StorageError>> + Send;

    /// Download a small document, refusing one longer than `max` bytes with
    /// [`StorageError::TooLarge`].
    ///
    /// For the documents a caller parses — a pointer, a manifest, a signed
    /// head — where `max` is far below the ceiling [`Storage::download`]
    /// buffers up to. An implementation holds at most `max` bytes and one
    /// chunk more, whatever the store sends: the bound is enforced before and
    /// while reading, never by measuring a finished download.
    ///
    /// **Required, with no default over [`Storage::download`]** — one would
    /// refuse the same documents while buffering each to the backend's own
    /// ceiling first, so a new backend has to write the bounded read.
    /// `FileStorage` refuses on the file's size and reads one byte past `max`,
    /// `ForgeStorage` and `HttpsStorage` refuse on a declared length and count
    /// the body as it arrives, and `SshStorage` stops reading the remote
    /// `cat` at `max` and kills it. The `size` a refusal reports is what the
    /// backend had seen when it stopped, which is the document's length only
    /// where the store declares one.
    fn download_capped(
        &self,
        path: &str,
        max: u64,
    ) -> impl Future<Output = Result<Vec<u8>, StorageError>> + Send;

    /// Download to a file on disk, **streaming** the body so peak memory is
    /// bounded by a chunk rather than the whole artifact. Returns the number of
    /// bytes written.
    ///
    /// **Required, with no buffered default** — a fallback through
    /// [`Storage::download`] would be correct but hold the whole artifact in
    /// RAM, silently defeating the one property this method exists for, so a
    /// new backend has to make the streaming choice deliberately.
    /// `FileStorage` copies, `ForgeStorage` and `HttpsStorage` read
    /// `Response::chunk()`, and `SshStorage` runs `scp`. Callers that verify content (the `fuz_release`
    /// consumer) hash the written file afterward — keeping the content hash in
    /// the consumer, not this byte-transport layer.
    fn download_to_file(
        &self,
        path: &str,
        dest: &Path,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;

    /// Upload from a file on disk, **streaming** the body so peak memory is
    /// bounded by a chunk rather than the whole artifact.
    ///
    /// **Required, with no buffered default**, for the reason spelled out on
    /// [`Storage::download_to_file`]. `FileStorage` copies, `ForgeStorage`
    /// sends a streaming request body, and `SshStorage` runs `scp`. Used by the
    /// `fuz_sign` producer (`pack_tarball_to_file` → `upload_file`).
    fn upload_file(
        &self,
        path: &str,
        src: &Path,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Check if a path exists.
    fn exists(&self, path: &str) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// List files matching a prefix.
    ///
    /// Returns paths relative to storage root. The prefix is the empty string
    /// (the whole store), a directory (`tools/fuzd/`), or the start of a key
    /// (`tools/fuzd/fuzd-`), and is held to the key contract
    /// ([`validate_list_prefix`]): one that could leave the root is
    /// [`StorageError::InvalidKey`].
    /// `FileStorage` lists one directory: the prefix's own — a prefix ending
    /// in `/` names a directory whether or not it exists, and one that does
    /// not lists as empty — or the one holding the file-name prefix.
    /// `ForgeStorage` and `SshStorage` match every key by string prefix.
    ///
    /// The filesystem backends return regular files only. A symlink to a file
    /// is not listed, though [`Storage::download`] and [`Storage::exists`]
    /// follow it. A symlinked root lists like a real one on both; a symlinked
    /// directory inside the root is listed by `FileStorage` when the prefix
    /// names it, and is not descended by `SshStorage`.
    fn list(&self, prefix: &str) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;

    /// Delete a file.
    ///
    /// No error if file doesn't exist.
    fn delete(&self, path: &str) -> impl Future<Output = Result<(), StorageError>> + Send;
}

//
// StorageBackend enum
//

/// Enum wrapper for storage backends.
///
/// This avoids `Box<dyn Storage>` allocations and allows pattern matching.
/// Used by `parse_storage()` to return different backend types.
#[derive(Debug)]
pub enum StorageBackend {
    /// Local filesystem storage
    File(FileStorage),
    /// A running `fuz_forge` over HTTP
    Forge(ForgeStorage),
    /// A remote host over SSH (`scp`/`ssh`)
    Ssh(SshStorage),
    /// A public static host over anonymous HTTPS (read-only)
    Https(HttpsStorage),
}

impl Storage for StorageBackend {
    fn backend_kind(&self) -> StorageBackendKind {
        match self {
            Self::File(s) => s.backend_kind(),
            Self::Forge(s) => s.backend_kind(),
            Self::Ssh(s) => s.backend_kind(),
            Self::Https(s) => s.backend_kind(),
        }
    }

    async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::File(s) => s.upload(path, data).await,
            Self::Forge(s) => s.upload(path, data).await,
            Self::Ssh(s) => s.upload(path, data).await,
            Self::Https(s) => s.upload(path, data).await,
        }
    }

    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        match self {
            Self::File(s) => s.download(path).await,
            Self::Forge(s) => s.download(path).await,
            Self::Ssh(s) => s.download(path).await,
            Self::Https(s) => s.download(path).await,
        }
    }

    async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        // Forward to the inner backend's bounded read.
        match self {
            Self::File(s) => s.download_capped(path, max).await,
            Self::Forge(s) => s.download_capped(path, max).await,
            Self::Ssh(s) => s.download_capped(path, max).await,
            Self::Https(s) => s.download_capped(path, max).await,
        }
    }

    async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
        // Forward to the inner backend's streaming impl (the trait has no
        // default body, so a new backend is forced to provide its own).
        match self {
            Self::File(s) => s.download_to_file(path, dest).await,
            Self::Forge(s) => s.download_to_file(path, dest).await,
            Self::Ssh(s) => s.download_to_file(path, dest).await,
            Self::Https(s) => s.download_to_file(path, dest).await,
        }
    }

    async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
        // Forward to the inner backend's streaming impl.
        match self {
            Self::File(s) => s.upload_file(path, src).await,
            Self::Forge(s) => s.upload_file(path, src).await,
            Self::Ssh(s) => s.upload_file(path, src).await,
            Self::Https(s) => s.upload_file(path, src).await,
        }
    }

    async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        match self {
            Self::File(s) => s.exists(path).await,
            Self::Forge(s) => s.exists(path).await,
            Self::Ssh(s) => s.exists(path).await,
            Self::Https(s) => s.exists(path).await,
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        match self {
            Self::File(s) => s.list(prefix).await,
            Self::Forge(s) => s.list(prefix).await,
            Self::Ssh(s) => s.list(prefix).await,
            Self::Https(s) => s.list(prefix).await,
        }
    }

    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        match self {
            Self::File(s) => s.delete(path).await,
            Self::Forge(s) => s.delete(path).await,
            Self::Ssh(s) => s.delete(path).await,
            Self::Https(s) => s.delete(path).await,
        }
    }
}

/// Parse a storage location string into a storage backend.
///
/// Supported URI forms:
/// - Local paths: `~/releases`, `./releases`, `/var/releases`, `file:///path`
/// - Forge: `forge://<host>` (bearer token from `FUZ_FORGE_TOKEN` /
///   `<fuz_forge_home>/api_token`, see [`forge_home`]; empty host falls back
///   to `FUZ_FORGE_BASE_URL`)
/// - SSH: `ssh://user@host[:port]/path` (auth via the caller's `ssh` agent /
///   key file — no `credentials.json`)
/// - HTTPS: `https://host[:port][/base/path]` (anonymous and read-only;
///   `http://` only for a loopback host — any other `http://` URI is refused)
///
/// Every backend authenticates ambiently (bearer token / ssh agent / nothing),
/// so no credentials argument is threaded through.
///
/// Parsing changes nothing, on disk or on a host: a local directory that does
/// not exist is accepted as it is ([`FileStorage::new`]) and comes into being
/// with the first upload. So this is the parse for a publish, which may
/// target a store that is not there yet; every other caller uses
/// [`parse_existing_storage`], which refuses a missing directory.
///
/// # Errors
///
/// Returns [`StorageError::InvalidConfig`] for malformed URIs,
/// [`StorageError::LocalRootNotDir`] for a local path that something other
/// than a directory holds (a store could never be created there), and any
/// error from constructing the underlying backend.
pub fn parse_storage(location: &str) -> Result<StorageBackend, StorageError> {
    parse_location(location, LocalPath::MayBeMissing)
}

/// [`parse_storage`] for a caller that works on a store already there.
///
/// That is every caller but a publish: a reader (`fuz`, a release log
/// origin), and a producer command that sweeps or deletes what was published
/// (`cargo xtask prune`, `release-log backfill`). The backend it returns is
/// the same one, writes included.
///
/// Differs for a local path alone: the directory must already exist
/// ([`FileStorage::open_existing`]), where [`parse_storage`] accepts one that
/// is not there yet. So a mistyped path is an error here, naming the cause,
/// rather than a store that reads as empty. Neither parse creates anything,
/// and every other scheme — `forge://`, `ssh://`, `https://` — parses exactly
/// as it does for [`parse_storage`].
///
/// # Errors
///
/// As [`parse_storage`], plus [`StorageError::LocalRootNotDir`] for a local
/// path that is not an existing directory.
pub fn parse_existing_storage(location: &str) -> Result<StorageBackend, StorageError> {
    parse_location(location, LocalPath::MustExist)
}

/// What a local-path location does when its directory is missing. Neither
/// creates it.
#[derive(Debug, Clone, Copy)]
enum LocalPath {
    /// Accept it: the first upload creates the directory.
    MayBeMissing,
    /// Refuse it.
    MustExist,
}

fn parse_location(location: &str, local: LocalPath) -> Result<StorageBackend, StorageError> {
    // Forge storage: forge://<host> (or forge:// + FUZ_FORGE_BASE_URL).
    // The credential is the forge bearer token, resolved from the environment /
    // `<fuz_forge_home>/api_token` (`forge_home`).
    if let Some(host) = location.strip_prefix("forge://") {
        let base = forge::resolve_forge_base(host)?;
        let token = forge_home::resolve_forge_token()?;
        let storage = ForgeStorage::new(&base, token)?;
        return Ok(StorageBackend::Forge(storage));
    }

    // SSH storage: ssh://user@host[:port]/path (auth via the caller's ssh
    // agent / key file — no credentials.json).
    if location.starts_with("ssh://") {
        let storage = SshStorage::new(location)?;
        return Ok(StorageBackend::Ssh(storage));
    }

    // HTTPS storage: https://host/base/path, anonymous and read-only. `http://`
    // routes here too so the backend's own rule decides it — accepted for a
    // loopback host, refused by name for any other — rather than the URI
    // reading as an unknown scheme.
    if location.starts_with("https://") || location.starts_with("http://") {
        let storage = HttpsStorage::new(location)?;
        return Ok(StorageBackend::Https(storage));
    }

    // Unknown URI scheme
    if location.contains("://") && !location.starts_with("file://") {
        return Err(StorageError::InvalidConfig {
            message: format!("unknown storage scheme: {location}"),
        });
    }

    // File storage: paths or file:// URIs
    let path = location.strip_prefix("file://").unwrap_or(location);
    let storage = match local {
        LocalPath::MayBeMissing => FileStorage::new(path)?,
        LocalPath::MustExist => FileStorage::open_existing(path)?,
    };
    Ok(StorageBackend::File(storage))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    /// What [`spawn_server`] does with one request.
    pub enum Reply {
        /// Write these raw bytes (status line, headers, body) and close.
        Raw(Vec<u8>),
        /// Write this head, then [`FLOOD_BYTES`] of body with no end in sight
        /// (no terminating chunk, no declared length), then close.
        Flood { head: &'static str, chunked: bool },
        /// Write this head, then one body byte every [`DRIP_INTERVAL`].
        Drip { head: &'static str },
        /// Never answer; hold the connection open.
        Stall,
    }

    /// Body bytes a flooding [`Reply`] writes before it gives up — far past
    /// any cap a test downloads under, and bounded so a client that fails to
    /// abort ends the test instead of filling memory or disk.
    const FLOOD_BYTES: usize = 64 * 64 * 1024;

    /// Gap between a dripping server's bytes, and how many it sends.
    const DRIP_INTERVAL: Duration = Duration::from_millis(50);
    const DRIP_BYTES: usize = 400;

    pub fn ok(body: &[u8]) -> Reply {
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(body);
        Reply::Raw(raw)
    }

    pub fn status(status_line: &str) -> Reply {
        Reply::Raw(
            format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes(),
        )
    }

    pub fn redirect(location: &str) -> Reply {
        Reply::Raw(
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n"
            )
            .into_bytes(),
        )
    }

    /// Request heads the server has received, in order.
    pub type Requests = Arc<Mutex<Vec<String>>>;

    /// Bind a loopback listener and answer every connection's request with
    /// `respond(method, path)`. Returns the base URL and the captured heads.
    pub async fn spawn_server<F>(respond: F) -> (String, Requests)
    where
        F: Fn(&str, &str) -> Reply + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("local_addr"));
        let requests: Requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let respond = Arc::new(respond);

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let captured = Arc::clone(&captured);
                let respond = Arc::clone(&respond);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
                    let method = parts.next().unwrap_or_default().to_string();
                    let path = parts.next().unwrap_or_default().to_string();
                    captured.lock().await.push(head);

                    // Write errors are the client hanging up, which is what
                    // the abort tests expect.
                    match respond(&method, &path) {
                        Reply::Raw(raw) => {
                            let _ = sock.write_all(&raw).await;
                            let _ = sock.flush().await;
                        }
                        Reply::Drip { head } => {
                            if sock.write_all(head.as_bytes()).await.is_err() {
                                return;
                            }
                            for _ in 0..DRIP_BYTES {
                                tokio::time::sleep(DRIP_INTERVAL).await;
                                if sock.write_all(b"x").await.is_err() {
                                    return;
                                }
                            }
                        }
                        Reply::Flood { head, chunked } => {
                            if sock.write_all(head.as_bytes()).await.is_err() {
                                return;
                            }
                            let block = [b'x'; 1024];
                            for _ in 0..FLOOD_BYTES / block.len() {
                                let written = if chunked {
                                    let mut frame = b"400\r\n".to_vec();
                                    frame.extend_from_slice(&block);
                                    frame.extend_from_slice(b"\r\n");
                                    sock.write_all(&frame).await
                                } else {
                                    sock.write_all(&block).await
                                };
                                if written.is_err() {
                                    return;
                                }
                            }
                        }
                        Reply::Stall => std::future::pending::<()>().await,
                    }
                });
            }
        });

        (base, requests)
    }

    /// A loopback HTTP server that answers any request with `total` body
    /// bytes and no declared length, stopping when the client hangs up.
    /// Returns the base URL and the count of body bytes it managed to write.
    pub async fn spawn_flood(total: usize) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let written = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&written);
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            if socket
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let block = [b'x'; 16 * 1024];
            while counter.load(Ordering::SeqCst) < total {
                if socket.write_all(&block).await.is_err() {
                    return;
                }
                counter.fetch_add(block.len(), Ordering::SeqCst);
            }
        });
        (base, written)
    }

    /// Body size the flood tests serve: far more than loopback socket buffers
    /// hold, so a server that wrote all of it had a client reading all of it.
    pub const FLOOD_TOTAL: usize = 64 * 1024 * 1024;

    /// Assert `download_capped(.., 1024)` against a flood is refused **while
    /// reading**: the error reports a size just past the limit, and the server
    /// was cut off long before it had sent the body.
    pub async fn assert_capped_while_reading(storage: &impl Storage, written: &AtomicUsize) {
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            storage.download_capped("head.json", 1024),
        )
        .await
        .expect("a bounded read returns at the first overrun");
        match result {
            Err(StorageError::TooLarge { size, max, .. }) => {
                assert_eq!(max, 1024);
                assert!(size > max, "refused past the limit: {size}");
                assert!(
                    size < 1024 * 1024,
                    "refused at the first overrun, not after the body: {size}"
                );
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
        // The client is gone; give the server a moment to notice.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let sent = written.load(Ordering::SeqCst);
        assert!(
            sent < FLOOD_TOTAL,
            "the client hung up before the body was sent: {sent}"
        );
    }

    /// The enum forwards `download_capped` to the backend's bounded read.
    #[tokio::test]
    async fn backend_enum_bounds_download_capped_while_reading() {
        let (base, written) = spawn_flood(FLOOD_TOTAL).await;
        let backend = parse_storage(&base).unwrap();
        assert!(matches!(backend, StorageBackend::Https(_)));
        assert_capped_while_reading(&backend, &written).await;
    }

    /// Naming a local store creates nothing under either parse: the
    /// existing-store one refuses a directory that is not there, the other
    /// accepts it and leaves it to the first upload.
    #[tokio::test]
    async fn neither_parse_creates_a_local_directory() {
        let dir = tempfile::tempdir().unwrap();
        let absolute = dir.path().join("missing");
        // Absolute, `file://`, and `~`-relative: none exists, none is created.
        let home_relative = format!("~/.fuz-storage-test-{}", fuz_sys::rand::random_hex_suffix());
        let expanded = fuz_sys::expand_tilde(&home_relative);
        assert!(!expanded.exists());
        // A relative path resolves against the working directory, which is
        // this crate's source directory under `cargo test`.
        let relative = format!("missing-origin-{}", fuz_sys::rand::random_hex_suffix());
        for location in [
            absolute.to_str().unwrap().to_string(),
            format!("file://{}", absolute.display()),
            home_relative,
            relative.clone(),
        ] {
            let err = parse_existing_storage(&location).unwrap_err();
            assert!(
                matches!(err, StorageError::LocalRootNotDir),
                "{location}: {err:?}"
            );
        }
        // `parse_storage` accepts the missing directory and leaves it missing.
        // (Under the tempdir only: were it to create, it must not be in the
        // home or the source directory.)
        for location in [
            absolute.to_str().unwrap().to_string(),
            format!("file://{}", absolute.display()),
        ] {
            assert!(
                matches!(parse_storage(&location), Ok(StorageBackend::File(_))),
                "{location}"
            );
        }
        assert!(!absolute.exists());
        assert!(!expanded.exists());
        assert!(!Path::new(&relative).exists());

        // An existing directory opens; every other scheme parses as it does
        // for `parse_storage`.
        assert!(matches!(
            parse_existing_storage(dir.path().to_str().unwrap()),
            Ok(StorageBackend::File(_))
        ));
        assert!(matches!(
            parse_existing_storage("https://releases.example.com"),
            Ok(StorageBackend::Https(_))
        ));
        assert!(matches!(
            parse_existing_storage("ssh://deploy@vps.example.com/var/www/releases"),
            Ok(StorageBackend::Ssh(_))
        ));
        assert!(parse_existing_storage("nope://x").is_err());

        // The first upload through `parse_storage` is what creates the store.
        let backend = parse_storage(absolute.to_str().unwrap()).unwrap();
        backend.upload("latest.json", b"{}").await.unwrap();
        assert!(absolute.join("latest.json").is_file());
        assert!(matches!(
            parse_existing_storage(absolute.to_str().unwrap()),
            Ok(StorageBackend::File(_))
        ));
    }

    /// `require_writable` and the operations agree on which backend only
    /// reads: where it refuses, each of them returns the same error it does,
    /// and where it passes, none of them is `Unsupported`.
    #[tokio::test]
    async fn require_writable_refuses_what_the_operations_would() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        std::fs::write(&src, b"payload").unwrap();

        let read_only = parse_existing_storage("https://releases.example.com/fuz").unwrap();
        assert!(read_only.backend_kind().is_read_only());
        // No request is made: an unsupported operation fails before one.
        let operations = [
            ("upload", read_only.upload("k", b"x").await),
            ("upload", read_only.upload_file("k", &src).await),
            ("list", read_only.list("").await.map(drop)),
            ("delete", read_only.delete("k").await),
        ];
        for (operation, result) in operations {
            let refused = read_only.require_writable(operation).unwrap_err();
            assert!(
                matches!(
                    refused,
                    StorageError::Unsupported {
                        backend: StorageBackendKind::Https,
                        operation: op,
                    } if op == operation
                ),
                "{refused:?}"
            );
            assert_eq!(result.unwrap_err().to_string(), refused.to_string());
        }

        let writable = [
            parse_storage(dir.path().join("store").to_str().unwrap()).unwrap(),
            parse_storage("ssh://deploy@vps.example.com/var/www/releases").unwrap(),
            StorageBackend::Forge(
                ForgeStorage::new("https://forge.example.com", "tok".to_string()).unwrap(),
            ),
        ];
        for backend in &writable {
            assert!(!backend.backend_kind().is_read_only(), "{backend:?}");
            for operation in ["upload", "list", "delete"] {
                backend.require_writable(operation).unwrap();
            }
        }
        // The local one, the only one here with no host behind it: none of its
        // operations is unsupported.
        let local = &writable[0];
        local.upload("k", b"x").await.unwrap();
        local.upload_file("k2", &src).await.unwrap();
        assert_eq!(local.list("").await.unwrap(), ["k", "k2"]);
        local.delete("k").await.unwrap();
    }

    #[tokio::test]
    async fn backend_enum_forwards_download_capped() {
        let dir = tempfile::tempdir().unwrap();
        let backend = parse_storage(dir.path().to_str().unwrap()).unwrap();
        backend.upload("head.json", b"0123456789").await.unwrap();
        assert!(matches!(
            backend.download_capped("head.json", 9).await,
            Err(StorageError::TooLarge { size: 10, .. })
        ));
    }
}
