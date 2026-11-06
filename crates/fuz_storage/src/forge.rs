//! Forge HTTP storage backend
//!
//! Reads and writes release artifacts through a running `fuz_forge`'s file-store
//! API (`/api/fuz_forge/files/*`), authenticated with a bearer token. The forge
//! is a dumb byte store — it never signs or verifies; `fuz` verifies signatures
//! against its embedded key after fetching, regardless of where the bytes came
//! from. The same backend serves both the consumer (`fuz tool install` /
//! `fuz self upgrade`) and the Rust publisher (`fuzf tool publish`).
//!
//! Keys may contain `/` (the rustup-style release layout — `tools/<name>/`,
//! with the version in the *filename*, not a directory level) and are passed
//! through to the forge unchanged —
//! the file store accepts path-structured keys natively (a catch-all route plus
//! traversal-safe validation), so all backends (`FileStorage`, `ForgeStorage`,
//! `SshStorage`, `HttpsStorage`) share one on-store layout. Keys are validated traversal-safe
//! ([`validate_forge_key`]) before every request.
//!
//! Every request goes through the `reqwest` client policy shared with
//! `HttpsStorage` (the crate's `http_client` module): a loopback `http` base
//! bypasses the environment's proxies, and an `https` base cannot issue a
//! plaintext request. Reads follow redirects, each hop vetted; writes (`upload`,
//! `upload_file`, `delete`) follow none (see [`ForgeStorage::new`]).
//!
//! The forge's own CLI (`fuzf`) talks to the same server with the same
//! bearer token, so it takes its policy from here rather than restating it:
//! [`crate::base_url::validate_base_url`] for the server URL,
//! [`forge_client_builder`] for its client, [`forge_base_url_refusal_message`]
//! for a refused URL's wording, [`MAX_FORGE_LIST_SIZE`] for a file listing, and
//! [`crate::forge_home`] for the home, the token, and `FUZ_FORGE_BASE_URL`.
//!
//! # Cohesion: a storage backend, not a stray
//!
//! `ForgeStorage` is the distribution-domain backend — a peer of `FileStorage`,
//! `SshStorage`, and `HttpsStorage` under the unified `StorageBackend` enum,
//! reached through the `forge://` scheme dispatch `parse_storage` and
//! `parse_existing_storage` share. It lives in `fuz_storage` (rather than
//! beside `fuz_release`'s distribution types) by construction, not by
//! accident: it is one of the enum's variants and the crate's `Storage`-trait
//! dispatch covers it, so relocating the type would make `fuz_storage` depend
//! on `fuz_release` — a cycle. Independently, [`validate_forge_key`] (the
//! crate's `key` module, shared by every backend) is the single-source-of-truth
//! key contract the forge server consumes (`fuz_forge_server` deps
//! `fuz_storage`, not `fuz_release`), so it stays in this crate regardless. The
//! would-be "clean relocation" of `ForgeStorage` is therefore a non-move; treat
//! it as a settled backend.

use std::path::Path;
use std::time::Duration;

use crate::Storage;
use crate::base_url::{self, BaseUrl, BaseUrlRefusal};
use crate::error::{StorageBackendKind, StorageError};
use crate::forge_home::{FORGE_BASE_URL_ENV, forge_base_url_env};
use crate::http_client::{Redirects, client_builder};
use crate::http_status::is_auth_status;
use crate::http_transfer::{
    BodyLimit, REQUEST_TIMEOUT, check_content_length, download_body_to_file, error_chain,
    read_body_capped, read_error_text,
};
use crate::key::{validate_forge_key, validate_list_prefix};

/// Backend identity for error messages.
const BACKEND: StorageBackendKind = StorageBackendKind::Forge;

/// API path prefix for the forge file store (mounted under the server root).
const FILES_API_PREFIX: &str = "/api/fuz_forge/files";

// Maximum transfer size (10 GiB). Since `upload_file` / `download_to_file`
// stream through disk (bounded memory), this is a policy / sanity ceiling
// rather than a memory guard — single-sourced in `fuz_sys::limits` with
// `fuz_release`'s extraction ceilings so legitimate GB-scale artifacts (e.g. OS
// images) aren't rejected client-side, and matching the forge's
// `FUZ_FORGE_FILE_STORE_MAX_BYTES`. The buffered `upload` / `download`
// apply it as their in-memory bound.
use fuz_sys::limits::MAX_TRANSFER_SIZE;

/// Most bytes of a file listing [`Storage::list`] buffers (16 MiB).
///
/// The forge answers a listing with one JSON document naming every file in its
/// store, unpaged, and the whole of it is buffered to be parsed. An entry is a
/// few hundred bytes — its key, two hex digests, a size, a content type, a
/// timestamp — so this holds the listing of a store of tens of thousands of
/// files, and a response past it is refused rather than buffered.
pub const MAX_FORGE_LIST_SIZE: u64 = 16 * 1024 * 1024;

/// HTTP storage backend backed by a running `fuz_forge` file store.
///
/// Construct directly with [`ForgeStorage::new`], or via
/// [`crate::parse_storage`] from a `forge://<host>` URI (which resolves the base
/// URL and bearer token from the environment / `<fuz_forge_home>/api_token`).
pub struct ForgeStorage {
    /// Client for reads: follows redirects under the shared policy.
    read_client: reqwest::Client,
    /// Client for writes: follows no redirect (see [`Redirects::Refuse`]).
    write_client: reqwest::Client,
    /// Normalized base URL (scheme + `host[:port]` + any base path, no
    /// trailing slash). A key resolves to `<base_url>/api/fuz_forge/files/<key>`.
    base_url: String,
    /// Bearer token sent on every request. Never logged (see `Debug` impl).
    token: String,
}

// Redact the token so it can't leak into logs / panic output.
impl std::fmt::Debug for ForgeStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForgeStorage")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ForgeStorage {
    /// Create a forge backend from a base URL and bearer token.
    ///
    /// `base_url` must be `https://host[:port][/base/path]`, or `http://...`
    /// only for a loopback host — `localhost`, `127.0.0.1`, or `[::1]` — so a
    /// bearer token is never sent over plaintext to a remote host. A URL
    /// carrying userinfo (`user:pass@`), a query, or a fragment is refused
    /// (the shared rules in the crate's `base_url` module).
    ///
    /// Reads follow redirects under the policy shared with
    /// [`crate::HttpsStorage`] (the crate's `http_client` module): at most
    /// `MAX_REDIRECTS` hops, no loops, no target carrying userinfo, never from
    /// `https` onto `http`, and plaintext only from loopback to loopback. The
    /// bearer token itself is dropped by `reqwest` on any hop that changes
    /// scheme, host, or port. Writes do not follow redirects: a `3xx` answer
    /// fails them, since following one can turn the write into a `GET` that
    /// succeeds without anything written. Every request gets an `https_only`
    /// client for an `https` base, and no `Referer` is sent.
    pub fn new(base_url: &str, token: String) -> Result<Self, StorageError> {
        let base = validate_base_url(base_url)?;
        if token.trim().is_empty() {
            return Err(StorageError::InvalidConfig {
                message: "forge token cannot be empty".to_string(),
            });
        }
        let build = |redirects| {
            forge_client_builder(&base, redirects).build().map_err(|e| {
                StorageError::InvalidConfig {
                    message: format!("failed to create HTTP client: {e}"),
                }
            })
        };
        Ok(Self {
            read_client: build(Redirects::Follow)?,
            write_client: build(Redirects::Refuse)?,
            base_url: base.url,
            token,
        })
    }
}

/// Connect deadline for a forge client (30 s).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A client builder for a forge rooted at `base`.
///
/// The shared policy (`client_builder`) plus the forge's timeouts: a 30 s
/// connect deadline and `REQUEST_TIMEOUT` (5 min) for the whole request,
/// sized for a large artifact.
///
/// `ForgeStorage` builds both its clients from this, and `fuzf` its one. The
/// loopback proxy bypass in the shared policy is what keeps the bearer token
/// from reaching an environment proxy in the clear.
pub fn forge_client_builder(base: &BaseUrl, redirects: Redirects) -> reqwest::ClientBuilder {
    client_builder(base, redirects)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
}

impl ForgeStorage {
    /// The buffered download behind [`Storage::download`] and
    /// [`Storage::download_capped`], with the size ceiling as a parameter.
    ///
    /// A `Content-Length` over `max` is refused before any body is read, and
    /// the body is counted while it streams, so an oversized one is never
    /// buffered whole however it is framed.
    async fn download_bounded(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        validate_forge_key(path)?;

        let url = build_files_url(&self.base_url, path);
        let mut response = self
            .read_client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| StorageError::DownloadFailed {
                backend: BACKEND,
                message: error_chain(&e),
            })?;

        let status = response.status();
        if status.is_success() {
            let limit = BodyLimit {
                backend: BACKEND,
                path,
                max,
            };
            check_content_length(&response, &limit)?;
            read_body_capped(&mut response, &limit).await
        } else if status == reqwest::StatusCode::NOT_FOUND {
            Err(StorageError::NotFound {
                backend: BACKEND,
                path: path.to_string(),
            })
        } else if is_auth_status(status) {
            Err(StorageError::PermissionDenied {
                backend: BACKEND,
                path: path.to_string(),
            })
        } else {
            let body = read_error_text(&mut response).await;
            Err(StorageError::DownloadFailed {
                backend: BACKEND,
                message: format!("HTTP {status}: {body}"),
            })
        }
    }
}

impl ForgeStorage {
    /// [`Storage::download_to_file`] with the size ceiling as a parameter.
    ///
    /// A refusal before the transfer starts (the status, a declared length
    /// over `max`) leaves a file already at `dest` as it was; on any failure
    /// after that the path `dest` is unlinked (`download_body_to_file`, the
    /// tail shared with `HttpsStorage`). The byte counter is the bound that
    /// holds: `Content-Length` may be absent or wrong.
    async fn download_to_file_capped(
        &self,
        path: &str,
        dest: &Path,
        max: u64,
    ) -> Result<u64, StorageError> {
        validate_forge_key(path)?;

        let url = build_files_url(&self.base_url, path);
        let mut response = self
            .read_client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| StorageError::DownloadFailed {
                backend: BACKEND,
                message: error_chain(&e),
            })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(StorageError::NotFound {
                backend: BACKEND,
                path: path.to_string(),
            });
        }
        if is_auth_status(status) {
            return Err(StorageError::PermissionDenied {
                backend: BACKEND,
                path: path.to_string(),
            });
        }
        if !status.is_success() {
            let body = read_error_text(&mut response).await;
            return Err(StorageError::DownloadFailed {
                backend: BACKEND,
                message: format!("HTTP {status}: {body}"),
            });
        }

        // Streamed to disk one chunk at a time (bounded memory).
        let limit = BodyLimit {
            backend: BACKEND,
            path,
            max,
        };
        download_body_to_file(&mut response, dest, &limit).await
    }

    /// [`Storage::list`] with the listing's size ceiling as a parameter.
    ///
    /// The listing is refused past `max` bytes — from a declared
    /// `Content-Length`, or while the body streams — and never buffered whole.
    async fn list_capped(&self, prefix: &str, max: u64) -> Result<Vec<String>, StorageError> {
        validate_list_prefix(prefix)?;
        // The file store lists every file; filter by prefix client-side.
        let url = format!("{}{}", self.base_url, FILES_API_PREFIX);
        let mut response = self
            .read_client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| StorageError::DownloadFailed {
                backend: BACKEND,
                message: error_chain(&e),
            })?;

        let status = response.status();
        if !status.is_success() {
            if is_auth_status(status) {
                return Err(StorageError::PermissionDenied {
                    backend: BACKEND,
                    path: prefix.to_string(),
                });
            }
            let body = read_error_text(&mut response).await;
            return Err(StorageError::DownloadFailed {
                backend: BACKEND,
                message: format!("list failed: HTTP {status}: {body}"),
            });
        }

        // Bounded before and while it is read. The limit's `path` is the
        // prefix, which is all a listing has to name.
        let limit = BodyLimit {
            backend: BACKEND,
            path: prefix,
            max,
        };
        let too_large = |error| match error {
            StorageError::TooLarge { max, .. } => StorageError::DownloadFailed {
                backend: BACKEND,
                message: format!("file listing exceeded the size cap ({max} bytes)"),
            },
            other => other,
        };
        check_content_length(&response, &limit).map_err(too_large)?;
        let bytes = read_body_capped(&mut response, &limit)
            .await
            .map_err(too_large)?;
        let parsed: FileListResponse =
            serde_json::from_slice(&bytes).map_err(|e| StorageError::DownloadFailed {
                backend: BACKEND,
                message: format!("failed to parse file list: {e}"),
            })?;

        Ok(parsed
            .files
            .into_iter()
            .map(|f| f.filename)
            .filter(|name| name.starts_with(prefix))
            .collect())
    }
}

impl Storage for ForgeStorage {
    fn backend_kind(&self) -> StorageBackendKind {
        BACKEND
    }

    async fn upload(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        validate_forge_key(path)?;

        let size = data.len() as u64;
        if size > MAX_TRANSFER_SIZE {
            return Err(StorageError::TooLarge {
                backend: BACKEND,
                path: path.to_string(),
                size,
                max: MAX_TRANSFER_SIZE,
            });
        }

        let url = build_files_url(&self.base_url, path);
        let mut response = self
            .write_client
            .post(&url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: BACKEND,
                message: error_chain(&e),
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else if is_auth_status(status) {
            Err(StorageError::PermissionDenied {
                backend: BACKEND,
                path: path.to_string(),
            })
        } else if status.is_redirection() {
            Err(write_redirected(status))
        } else {
            let body = read_error_text(&mut response).await;
            Err(StorageError::UploadFailed {
                backend: BACKEND,
                message: format!("HTTP {status}: {body}"),
            })
        }
    }

    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        self.download_bounded(path, MAX_TRANSFER_SIZE).await
    }

    async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        // Counted while the body streams; never above the transfer ceiling
        // whatever the caller asks for.
        self.download_bounded(path, max.min(MAX_TRANSFER_SIZE))
            .await
    }

    async fn upload_file(&self, path: &str, src: &Path) -> Result<(), StorageError> {
        validate_forge_key(path)?;

        let file = tokio::fs::File::open(src)
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: BACKEND,
                message: format!("open {} failed: {e}", src.display()),
            })?;
        let size = file
            .metadata()
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: BACKEND,
                message: format!("stat {} failed: {e}", src.display()),
            })?
            .len();
        if size > MAX_TRANSFER_SIZE {
            return Err(StorageError::TooLarge {
                backend: BACKEND,
                path: path.to_string(),
                size,
                max: MAX_TRANSFER_SIZE,
            });
        }

        // Stream the file as the request body (no whole-file buffer). The
        // explicit Content-Length keeps the request non-chunked so the forge's
        // Content-Length pre-check can reject over-cap uploads before reading.
        let url = build_files_url(&self.base_url, path);
        let mut response = self
            .write_client
            .post(&url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CONTENT_LENGTH, size)
            .body(reqwest::Body::from(file))
            .send()
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: BACKEND,
                message: error_chain(&e),
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else if is_auth_status(status) {
            Err(StorageError::PermissionDenied {
                backend: BACKEND,
                path: path.to_string(),
            })
        } else if status.is_redirection() {
            Err(write_redirected(status))
        } else {
            let body = read_error_text(&mut response).await;
            Err(StorageError::UploadFailed {
                backend: BACKEND,
                message: format!("HTTP {status}: {body}"),
            })
        }
    }

    async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
        self.download_to_file_capped(path, dest, MAX_TRANSFER_SIZE)
            .await
    }

    async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        validate_forge_key(path)?;

        // Metadata-only probe: `?meta` on the catch-all download route returns the
        // file's JSON metadata (200) or 404, without streaming the body. The forge
        // can't carry a `/{*key}/meta` suffix (axum 0.8 catch-alls are terminal),
        // so the metadata selector rides as a query param. `exists` only needs the
        // status, not the body.
        let url = format!("{}?meta", build_files_url(&self.base_url, path));
        let response = self
            .read_client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| StorageError::DownloadFailed {
                backend: BACKEND,
                message: error_chain(&e),
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(true)
        } else if status == reqwest::StatusCode::NOT_FOUND {
            Ok(false)
        } else if is_auth_status(status) {
            Err(StorageError::PermissionDenied {
                backend: BACKEND,
                path: path.to_string(),
            })
        } else {
            Err(StorageError::DownloadFailed {
                backend: BACKEND,
                message: format!("meta failed: HTTP {status}"),
            })
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        self.list_capped(prefix, MAX_FORGE_LIST_SIZE).await
    }

    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        validate_forge_key(path)?;

        let url = build_files_url(&self.base_url, path);
        let mut response = self
            .write_client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| StorageError::UploadFailed {
                backend: BACKEND,
                message: error_chain(&e),
            })?;

        // Treat 404 as success — delete is idempotent.
        let status = response.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else if is_auth_status(status) {
            Err(StorageError::PermissionDenied {
                backend: BACKEND,
                path: path.to_string(),
            })
        } else if status.is_redirection() {
            Err(write_redirected(status))
        } else {
            let body = read_error_text(&mut response).await;
            Err(StorageError::UploadFailed {
                backend: BACKEND,
                message: format!("delete failed: HTTP {status}: {body}"),
            })
        }
    }
}

/// The error for a write the forge answered with a `3xx`.
///
/// The write client follows no redirect, so the answer arrives as the
/// response. Its body — a login page, say — is not the forge's and is not
/// echoed; the status alone says what happened.
fn write_redirected(status: reqwest::StatusCode) -> StorageError {
    StorageError::UploadFailed {
        backend: BACKEND,
        message: format!(
            "the forge answered a write with a redirect (HTTP {status}); \
             writes do not follow redirects"
        ),
    }
}

/// Subset of the file-store list response (`GET /api/fuz_forge/files`).
#[derive(Debug, serde::Deserialize)]
struct FileListResponse {
    files: Vec<FileEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct FileEntry {
    filename: String,
}

/// Build the file-store URL for a validated key.
///
/// The key is passed through verbatim — the forge accepts path-structured keys
/// natively, and [`validate_forge_key`] has already constrained the charset to
/// `[A-Za-z0-9._/-]` (all URL-path-safe), so no percent-encoding is needed.
fn build_files_url(base: &str, key: &str) -> String {
    format!("{base}{FILES_API_PREFIX}/{key}")
}

/// A refused forge base URL in the forge's words — the one wording
/// `ForgeStorage` and `fuzf` both print.
///
/// Plaintext to a non-loopback host names the bearer token, since that is
/// what it would expose; every other refusal is the shared clause after
/// `invalid forge base URL: `. Like the refusal, it never echoes the URL.
pub fn forge_base_url_refusal_message(refusal: &BaseUrlRefusal) -> String {
    match refusal {
        BaseUrlRefusal::PlaintextHost(host) => format!(
            "refusing to send a bearer token over plaintext http to non-loopback host '{host}'; use https"
        ),
        other => format!("invalid forge base URL: {other}"),
    }
}

/// Validate and normalize a forge base URL through the shared
/// [`crate::base_url`] rules, refusing in the forge's words.
fn validate_base_url(base: &str) -> Result<BaseUrl, StorageError> {
    base_url::validate_base_url(base).map_err(|refusal| StorageError::InvalidConfig {
        message: forge_base_url_refusal_message(&refusal),
    })
}

/// Resolve the forge base URL from a `forge://` host component.
///
/// An empty host falls back to `FUZ_FORGE_BASE_URL` ([`forge_base_url_env`];
/// a full URL, which may be `http://localhost...` for dev); a non-empty host
/// becomes `https://<host>`.
pub fn resolve_forge_base(host: &str) -> Result<String, StorageError> {
    if !host.is_empty() {
        return Ok(format!("https://{host}"));
    }
    forge_base_url_env()?.ok_or_else(|| StorageError::InvalidConfig {
        message: format!(
            "forge:// requires a host (forge://<host>) or the {FORGE_BASE_URL_ENV} env var"
        ),
    })
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::{MAX_REDIRECTS, RedirectRefusal};
    use crate::tests::{Reply, ok, redirect, spawn_server, status};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    //
    // Pure-logic tests
    //

    #[test]
    fn base_url_requires_secure_scheme() {
        let url = |base: &str| validate_base_url(base).unwrap().url;
        assert_eq!(
            url("https://forge.example.com/"),
            "https://forge.example.com"
        );
        assert_eq!(url("http://localhost:4041"), "http://localhost:4041");
        assert_eq!(url("http://127.0.0.1:4041"), "http://127.0.0.1:4041");
        assert_eq!(url("http://[::1]:4041"), "http://[::1]:4041");
        // a base path is kept, trailing slashes are not
        assert_eq!(url("https://h/forge//"), "https://h/forge");
        // plaintext to a remote host is refused, naming the token at stake
        let err = validate_base_url("http://forge.example.com").unwrap_err();
        assert!(err.to_string().contains("bearer token"), "{err}");
        // unknown scheme
        assert!(validate_base_url("ftp://forge.example.com").is_err());
    }

    #[test]
    fn only_an_https_base_keeps_environment_proxies() {
        let is_https = |base: &str| validate_base_url(base).unwrap().is_https;
        assert!(is_https("https://forge.example.com"));
        assert!(is_https("HTTPS://forge.example.com"));
        // An uppercase plaintext scheme validates as loopback and must still
        // bypass the proxies.
        assert!(!is_https("HTTP://localhost:4041"));
        assert!(!is_https("http://127.0.0.1:4041"));
        assert!(!is_https("http://[::1]:4041"));
    }

    /// The forge sends a bearer token, so its base is held to the same rules
    /// as the anonymous https backend's: no userinfo (which the client would
    /// send beside the token), no query or fragment (which would land in the
    /// middle of every file-store URL). Driven through the public constructor.
    #[test]
    fn new_refuses_userinfo_query_and_fragment() {
        let mut failures = Vec::new();
        for (base, expected) in [
            (
                "https://user:hunter2@forge.example.com",
                "must not carry credentials",
            ),
            (
                "https://user@forge.example.com",
                "must not carry credentials",
            ),
            (
                "http://user:hunter2@localhost:4041",
                "must not carry credentials",
            ),
            ("https://forge.example.com/?q", "query or fragment"),
            ("https://forge.example.com/?", "query or fragment"),
            ("https://forge.example.com/#f", "query or fragment"),
            ("http://127.0.0.1:4041/base#f", "query or fragment"),
        ] {
            match ForgeStorage::new(base, "tok".to_string()) {
                Err(StorageError::InvalidConfig { message })
                    if message.contains(expected) && !message.contains("hunter2") => {}
                other => failures.push(format!("{base}: {other:?}")),
            }
        }
        assert!(
            failures.is_empty(),
            "not refused as expected:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn files_url_passes_path_keys_through() {
        // Native `/`: the key is not mangled into a single segment.
        assert_eq!(
            build_files_url("https://h", "tools/zap/latest.json"),
            "https://h/api/fuz_forge/files/tools/zap/latest.json"
        );
        assert_eq!(
            build_files_url("https://h", "latest.json"),
            "https://h/api/fuz_forge/files/latest.json"
        );
    }

    //
    // Round-trip tests against a one-shot in-process HTTP server (no deps)
    //

    #[derive(Default, Clone, Debug)]
    struct Captured {
        method: String,
        path: String,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Bind a localhost listener and answer exactly one request with
    /// `status_line` (e.g. `"HTTP/1.1 200 OK"`) + `resp_body`. Returns the base
    /// URL and a slot that receives the captured request.
    async fn spawn_once(
        status_line: &'static str,
        resp_body: &'static [u8],
    ) -> (String, Arc<Mutex<Option<Captured>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let base = format!("http://{addr}");
        let slot: Arc<Mutex<Option<Captured>>> = Arc::new(Mutex::new(None));
        let slot_for_task = Arc::clone(&slot);

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = sock.read(&mut tmp).await.expect("read");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                let Some(end) = find_subslice(&buf, b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let content_length = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                let mut body = buf[end + 4..].to_vec();
                while body.len() < content_length {
                    let n = sock.read(&mut tmp).await.expect("read body");
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&tmp[..n]);
                }
                let mut lines = head.lines();
                let request_line = lines.next().unwrap_or_default();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                let authorization = head.lines().find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_string())
                });
                *slot_for_task.lock().await = Some(Captured {
                    method,
                    path,
                    authorization,
                    body,
                });
                break;
            }
            let resp = format!(
                "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                resp_body.len()
            );
            sock.write_all(resp.as_bytes()).await.expect("write head");
            sock.write_all(resp_body).await.expect("write body");
            sock.flush().await.expect("flush");
        });

        (base, slot)
    }

    //
    // Proxy bypass, tested in a child process: the proxy variables are read
    // from the process environment, which a test cannot set for itself.
    //

    /// Names the loopback base the child half downloads from.
    const PROXY_CHILD_BASE_ENV: &str = "FUZ_STORAGE_TEST_FORGE_PROXY_CHILD_BASE";

    /// Helper for `loopback_http_token_bypasses_environment_proxy`, run in a
    /// subprocess that inherits proxy variables: downloads one key from the
    /// base named in [`PROXY_CHILD_BASE_ENV`].
    #[tokio::test]
    #[ignore = "subprocess helper for loopback_http_token_bypasses_environment_proxy"]
    async fn forge_proxy_bypass_child() {
        let Ok(base) = std::env::var(PROXY_CHILD_BASE_ENV) else {
            return;
        };
        let storage = ForgeStorage::new(&base, "secret-token".to_string()).expect("new");
        let got = tokio::time::timeout(Duration::from_secs(30), storage.download("latest.json"))
            .await
            .expect("deadline")
            .expect("download");
        assert_eq!(got, b"direct");
    }

    /// With the proxy variables set, a loopback `http` forge base still
    /// connects straight to its host, so the bearer token never reaches the
    /// proxy in plaintext.
    #[tokio::test]
    async fn loopback_http_token_bypasses_environment_proxy() {
        let (base, direct) = spawn_once("HTTP/1.1 200 OK", b"direct").await;
        let (proxy, proxied) = spawn_once("HTTP/1.1 200 OK", b"proxied").await;

        let exe = std::env::current_exe().expect("test executable");
        let mut child = tokio::process::Command::new(exe);
        child
            .args([
                "--ignored",
                "--exact",
                "forge::tests::forge_proxy_bypass_child",
            ])
            .env(PROXY_CHILD_BASE_ENV, &base)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy");
        for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
            child.env(name, &proxy);
        }
        let output = tokio::time::timeout(Duration::from_secs(60), child.output())
            .await
            .expect("deadline")
            .expect("run child");

        assert!(
            proxied.lock().await.is_none(),
            "the request (and its bearer token) went to the proxy"
        );
        assert!(
            output.status.success(),
            "child download failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let direct = direct.lock().await;
        let captured = direct.as_ref().expect("one direct request");
        assert_eq!(
            captured.authorization.as_deref(),
            Some("Bearer secret-token")
        );
    }

    #[tokio::test]
    async fn download_returns_body_and_sends_bearer() {
        let (base, slot) = spawn_once("HTTP/1.1 200 OK", b"artifact-bytes").await;
        let storage = ForgeStorage::new(&base, "tok-123".to_string()).expect("new");

        let got = storage
            .download("tools/zap/latest.json")
            .await
            .expect("download");
        assert_eq!(got, b"artifact-bytes");

        let captured = slot.lock().await.clone().expect("captured");
        assert_eq!(captured.method, "GET");
        // Native `/`: the path-structured key reaches the forge verbatim.
        assert_eq!(captured.path, "/api/fuz_forge/files/tools/zap/latest.json");
        assert_eq!(captured.authorization.as_deref(), Some("Bearer tok-123"));
    }

    /// The limit is enforced while the body is read, not after it is buffered.
    #[tokio::test]
    async fn forge_download_capped_bounds_the_body_while_reading() {
        let (base, written) = crate::tests::spawn_flood(crate::tests::FLOOD_TOTAL).await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        crate::tests::assert_capped_while_reading(&storage, &written).await;
    }

    #[tokio::test]
    async fn download_capped_refuses_a_body_over_the_callers_limit() {
        let (base, _slot) = spawn_once("HTTP/1.1 200 OK", b"0123456789").await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let err = storage
            .download_capped("head.json", 9)
            .await
            .expect_err("over the limit");
        assert!(
            matches!(
                err,
                StorageError::TooLarge {
                    backend: StorageBackendKind::Forge,
                    size: 10,
                    max: 9,
                    ..
                }
            ),
            "got {err:?}"
        );

        let (base, _slot) = spawn_once("HTTP/1.1 200 OK", b"0123456789").await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        assert_eq!(
            storage
                .download_capped("head.json", 10)
                .await
                .expect("at the limit"),
            b"0123456789"
        );
    }

    #[tokio::test]
    async fn exists_probes_meta_query_and_sends_bearer() {
        let (base, slot) = spawn_once("HTTP/1.1 200 OK", b"{}").await;
        let storage = ForgeStorage::new(&base, "tok-meta".to_string()).expect("new");

        assert!(
            storage
                .exists("tools/zap/latest.json")
                .await
                .expect("exists")
        );

        let captured = slot.lock().await.clone().expect("captured");
        assert_eq!(captured.method, "GET");
        // `?meta` rides on the native catch-all path (no `/meta` suffix).
        assert_eq!(
            captured.path,
            "/api/fuz_forge/files/tools/zap/latest.json?meta"
        );
        assert_eq!(captured.authorization.as_deref(), Some("Bearer tok-meta"));
    }

    #[tokio::test]
    async fn exists_404_is_false() {
        let (base, _slot) = spawn_once("HTTP/1.1 404 Not Found", b"nope").await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        assert!(!storage.exists("missing.json").await.expect("exists"));
    }

    #[tokio::test]
    async fn delete_404_is_ok() {
        let (base, _slot) = spawn_once("HTTP/1.1 404 Not Found", b"gone").await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        storage
            .delete("missing.json")
            .await
            .expect("delete is idempotent");
    }

    #[tokio::test]
    async fn download_404_maps_to_not_found() {
        let (base, _slot) = spawn_once("HTTP/1.1 404 Not Found", b"missing").await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");

        let err = storage.download("nope.json").await.expect_err("should 404");
        assert!(matches!(err, StorageError::NotFound { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn download_401_maps_to_permission_denied() {
        let (base, _slot) = spawn_once("HTTP/1.1 401 Unauthorized", b"nope").await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");

        let err = storage.download("x.json").await.expect_err("should 401");
        assert!(
            matches!(err, StorageError::PermissionDenied { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn upload_posts_body_with_bearer() {
        let (base, slot) = spawn_once("HTTP/1.1 200 OK", b"{\"status\":\"created\"}").await;
        let storage = ForgeStorage::new(&base, "tok-xyz".to_string()).expect("new");

        storage
            .upload("tools/zap/0.1.0/zap.tar.gz", b"payload")
            .await
            .expect("upload");

        let captured = slot.lock().await.clone().expect("captured");
        assert_eq!(captured.method, "POST");
        assert_eq!(
            captured.path,
            "/api/fuz_forge/files/tools/zap/0.1.0/zap.tar.gz"
        );
        assert_eq!(captured.authorization.as_deref(), Some("Bearer tok-xyz"));
        assert_eq!(captured.body, b"payload");
    }

    #[tokio::test]
    async fn download_to_file_streams_body_to_disk() {
        let (base, slot) = spawn_once("HTTP/1.1 200 OK", b"streamed-artifact-bytes").await;
        let storage = ForgeStorage::new(&base, "tok-stream".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let n = storage
            .download_to_file("tools/zap/0.1.0/zap.tar.gz", &dest)
            .await
            .expect("download_to_file");

        assert_eq!(n, b"streamed-artifact-bytes".len() as u64);
        assert_eq!(
            std::fs::read(&dest).expect("read dest"),
            b"streamed-artifact-bytes"
        );

        let captured = slot.lock().await.clone().expect("captured");
        assert_eq!(captured.method, "GET");
        assert_eq!(
            captured.path,
            "/api/fuz_forge/files/tools/zap/0.1.0/zap.tar.gz"
        );
        assert_eq!(captured.authorization.as_deref(), Some("Bearer tok-stream"));
    }

    #[tokio::test]
    async fn upload_file_streams_body_with_bearer() {
        let (base, slot) = spawn_once("HTTP/1.1 200 OK", b"{\"status\":\"created\"}").await;
        let storage = ForgeStorage::new(&base, "tok-up".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("art.tar.gz");
        std::fs::write(&src, b"streamed upload payload").expect("write src");

        storage
            .upload_file("tools/zap/0.1.0/zap.tar.gz", &src)
            .await
            .expect("upload_file");

        let captured = slot.lock().await.clone().expect("captured");
        assert_eq!(captured.method, "POST");
        assert_eq!(
            captured.path,
            "/api/fuz_forge/files/tools/zap/0.1.0/zap.tar.gz"
        );
        assert_eq!(captured.authorization.as_deref(), Some("Bearer tok-up"));
        // The streamed file body arrives byte-identical.
        assert_eq!(captured.body, b"streamed upload payload");
    }

    #[tokio::test]
    async fn download_to_file_404_maps_to_not_found() {
        let (base, _slot) = spawn_once("HTTP/1.1 404 Not Found", b"missing").await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let err = storage
            .download_to_file("nope.tar.gz", &dir.path().join("out.bin"))
            .await
            .expect_err("should 404");
        assert!(matches!(err, StorageError::NotFound { .. }), "got {err:?}");
    }

    //
    // Bounds: what a failed streaming download leaves, and how much of a
    // response is read
    //

    /// Size ceiling the bounded-download tests run under.
    const TEST_CAP: u64 = 64 * 1024;

    /// A `200` that declares `declared` body bytes and sends `sent`.
    fn declared(declared: u64, sent: &[u8]) -> Reply {
        let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\r\n").into_bytes();
        raw.extend_from_slice(sent);
        Reply::Raw(raw)
    }

    /// A `200` whose body has no declared length and no end in sight.
    fn flood(chunked: bool) -> Reply {
        let head = if chunked {
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        } else {
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
        };
        Reply::Flood { head, chunked }
    }

    /// A `500` whose body is the same flood, ended by the connection closing —
    /// a body a client that reads to the end receives whole.
    fn flood_500() -> Reply {
        Reply::Flood {
            head: "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n",
            chunked: false,
        }
    }

    /// A body that ends short of its declared length is a failed transfer,
    /// and the bytes that did arrive are not left on disk.
    #[tokio::test]
    async fn truncated_body_leaves_no_partial_file() {
        let (base, _) = spawn_server(|_, _| declared(100, b"partial")).await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let err = storage
            .download_to_file("cut.bin", &dest)
            .await
            .expect_err("truncated");
        assert!(
            matches!(err, StorageError::DownloadFailed { .. }),
            "got {err:?}"
        );
        assert!(!dest.exists(), "partial download left behind");
    }

    /// A body that runs past the cap with no declared length is cut off by
    /// the byte counter, however it is framed, and nothing is left at `dest`.
    #[tokio::test]
    async fn flooding_body_is_refused_and_leaves_no_file() {
        for chunked in [true, false] {
            let (base, _) = spawn_server(move |_, _| flood(chunked)).await;
            let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
            let dir = tempfile::tempdir().expect("tempdir");
            let dest = dir.path().join("out.bin");

            let err = tokio::time::timeout(
                Duration::from_secs(30),
                storage.download_to_file_capped("big.bin", &dest, TEST_CAP),
            )
            .await
            .expect("refused at the first overrun")
            .expect_err("too large");
            match err {
                StorageError::TooLarge { size, max, .. } => {
                    assert_eq!(max, TEST_CAP);
                    assert!(size > max && size < 2 * TEST_CAP, "{size}");
                }
                other => panic!("chunked={chunked}: expected TooLarge, got {other:?}"),
            }
            assert!(!dest.exists(), "chunked={chunked}: partial download left");
        }
    }

    /// A declared length one byte over the cap is refused from the headers:
    /// the body is never asked for, and `dest` is never created — a file
    /// already there is as it was. One byte under it downloads.
    #[tokio::test]
    async fn oversized_content_length_is_refused_before_dest_is_created() {
        let (base, _) = spawn_server(|_, path| {
            if path.ends_with("over.bin") {
                declared(17, b"")
            } else {
                ok(b"0123456789abcdef")
            }
        })
        .await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let refused = |err: StorageError| {
            assert!(
                matches!(
                    err,
                    StorageError::TooLarge {
                        backend: StorageBackendKind::Forge,
                        size: 17,
                        max: 16,
                        ..
                    }
                ),
                "got {err:?}"
            );
        };
        refused(
            storage
                .download_to_file_capped("over.bin", &dest, 16)
                .await
                .expect_err("too large"),
        );
        assert!(!dest.exists(), "refused before dest is created");

        std::fs::write(&dest, b"already here").expect("write dest");
        refused(
            storage
                .download_to_file_capped("over.bin", &dest, 16)
                .await
                .expect_err("too large"),
        );
        assert_eq!(std::fs::read(&dest).expect("read dest"), b"already here");

        assert_eq!(
            storage
                .download_to_file_capped("at.bin", &dest, 16)
                .await
                .expect("at the cap"),
            16
        );
        assert_eq!(
            std::fs::read(&dest).expect("read dest"),
            b"0123456789abcdef"
        );
    }

    /// `download_to_file` applies the transfer ceiling, and `list` the
    /// listing's: a declared length one byte over each is refused from the
    /// headers, naming the ceiling that refused it.
    #[tokio::test]
    async fn public_methods_apply_their_own_ceilings() {
        let (base, _) = spawn_server(|_, path| {
            let len = if path == FILES_API_PREFIX {
                MAX_FORGE_LIST_SIZE + 1
            } else {
                MAX_TRANSFER_SIZE + 1
            };
            declared(len, b"")
        })
        .await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let err = storage
            .download_to_file("streamed.bin", &dest)
            .await
            .expect_err("too large");
        assert!(
            matches!(err, StorageError::TooLarge { max, .. } if max == MAX_TRANSFER_SIZE),
            "got {err:?}"
        );
        assert!(!dest.exists(), "refused before dest is created");

        let err = storage.list("").await.expect_err("too large");
        assert_eq!(
            err.to_string(),
            format!(
                "Forge: download failed: file listing exceeded the size cap ({MAX_FORGE_LIST_SIZE} bytes)"
            )
        );
    }

    /// What a failed `download_to_file` leaves of a file already at `dest`.
    /// Refused before the transfer starts — by the status, by a declared
    /// length — it is as it was. Failed once the transfer has started, it is
    /// gone: the download truncated it, and the partial result is unlinked.
    #[tokio::test]
    async fn a_failed_download_leaves_an_existing_dest_only_when_it_never_started() {
        let (base, _) = spawn_server(|_, path| match path.rsplit('/').next() {
            Some("missing") => status("HTTP/1.1 404 Not Found"),
            Some("denied") => status("HTTP/1.1 403 Forbidden"),
            Some("broken") => status("HTTP/1.1 500 Internal Server Error"),
            Some("declared-over") => declared(TEST_CAP + 1, b""),
            Some("truncated") => declared(100, b"partial"),
            _ => flood(true),
        })
        .await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let mut failures = Vec::new();
        for (key, kept) in [
            ("missing", true),
            ("denied", true),
            ("broken", true),
            ("declared-over", true),
            ("truncated", false),
            ("overrun", false),
        ] {
            std::fs::write(&dest, b"already here").expect("write dest");
            let result = storage.download_to_file_capped(key, &dest, TEST_CAP).await;
            let found = std::fs::read(&dest).ok();
            let expected = kept.then(|| b"already here".to_vec());
            if result.is_ok() || found != expected {
                failures.push(format!("{key}: {result:?}, dest {found:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // A symlink at `dest` is followed by the create, and it is the link
        // that is unlinked: its target stays, holding what arrived.
        let target = dir.path().join("target.bin");
        std::fs::write(&target, b"already here").expect("write target");
        std::fs::remove_file(&dest).ok();
        std::os::unix::fs::symlink(&target, &dest).expect("symlink");
        storage
            .download_to_file_capped("truncated", &dest, TEST_CAP)
            .await
            .expect_err("truncated");
        assert!(dest.symlink_metadata().is_err(), "the link is removed");
        assert_eq!(std::fs::read(&target).expect("read target"), b"partial");
    }

    /// A `dest` that cannot be created fails the download and creates nothing.
    #[tokio::test]
    async fn a_dest_that_cannot_be_created_fails_the_download() {
        let (base, _) = spawn_server(|_, _| ok(b"bytes")).await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("no-such-dir").join("out.bin");

        let err = storage
            .download_to_file("k.bin", &dest)
            .await
            .expect_err("no parent");
        assert!(
            matches!(&err, StorageError::DownloadFailed { message, .. } if message.starts_with("create ")),
            "got {err:?}"
        );
        assert!(!dir.path().join("no-such-dir").exists());
    }

    /// An error response's body is read only as far as a message could use
    /// it: a body of any length costs `MAX_ERROR_BODY_LEN` bytes, the error
    /// still names the status and shows the body's start, and a short body is
    /// carried whole. Every method that reports a body is held to it.
    #[tokio::test]
    async fn an_error_body_is_read_to_a_bound_whatever_its_length() {
        use crate::http_transfer::MAX_ERROR_BODY_LEN;
        const STATUS: &str = "HTTP 500 Internal Server Error: ";

        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        std::fs::write(&src, b"payload").expect("write src");
        let dest = dir.path().join("out.bin");

        let mut failures = Vec::new();
        for long in [true, false] {
            for method in [
                "download",
                "download_capped",
                "download_to_file",
                "list",
                "upload",
                "upload_file",
                "delete",
            ] {
                let (base, _) = spawn_server(move |_, _| {
                    if long {
                        flood_500()
                    } else {
                        Reply::Raw(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 9\r\n\
                              Connection: close\r\n\r\ndisk full"
                                .to_vec(),
                        )
                    }
                })
                .await;
                let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
                let request = async {
                    match method {
                        "download" => storage.download("k").await.map(drop),
                        "download_capped" => storage.download_capped("k", 64).await.map(drop),
                        "download_to_file" => storage.download_to_file("k", &dest).await.map(drop),
                        "list" => storage.list("").await.map(drop),
                        "upload" => storage.upload("k", b"payload").await,
                        "upload_file" => storage.upload_file("k", &src).await,
                        _ => storage.delete("k").await,
                    }
                };
                let result = tokio::time::timeout(Duration::from_secs(30), request)
                    .await
                    .expect("an error response is not read to its end");
                let prefix = match method {
                    "list" => "list failed: ",
                    "delete" => "delete failed: ",
                    _ => "",
                };
                let body = if long {
                    "x".repeat(MAX_ERROR_BODY_LEN)
                } else {
                    "disk full".to_string()
                };
                let expected = format!("{prefix}{STATUS}{body}");
                let carried = match &result {
                    Err(
                        StorageError::DownloadFailed { message, .. }
                        | StorageError::UploadFailed { message, .. },
                    ) => message.as_str(),
                    _ => "",
                };
                if carried != expected {
                    failures.push(format!(
                        "{method} (long={long}): carried {} bytes: {:?}",
                        carried.len(),
                        result.map_err(|e| e.to_string())
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        assert!(!dest.exists(), "an error response created dest");
    }

    /// A listing parses to the keys under the prefix, and one past the cap
    /// is refused — from its declared length, or while its body streams —
    /// rather than buffered.
    #[tokio::test]
    async fn a_listing_is_read_to_a_bound() {
        const LISTING: &[u8] = br#"{"files":[{"filename":"tools/zap/a","size_bytes":1},{"filename":"tools/zapper/b"},{"filename":"latest.json"}]}"#;
        let (base, requests) = spawn_server(|_, _| ok(LISTING)).await;
        let storage = ForgeStorage::new(&base, "tok-list".to_string()).expect("new");
        assert_eq!(
            storage.list("tools/zap/").await.expect("list"),
            ["tools/zap/a"]
        );
        assert_eq!(
            storage.list("").await.expect("list"),
            ["tools/zap/a", "tools/zapper/b", "latest.json"]
        );
        let requests = requests.lock().await;
        assert!(
            requests[0].starts_with("GET /api/fuz_forge/files HTTP/1.1\r\n")
                && requests[0].contains("Bearer tok-list"),
            "{}",
            requests[0]
        );
        drop(requests);

        // At the cap it reads; one byte under the listing's length it does not.
        let len = LISTING.len() as u64;
        assert!(storage.list_capped("", len).await.is_ok());
        let over = format!(
            "Forge: download failed: file listing exceeded the size cap ({} bytes)",
            len - 1
        );
        assert_eq!(
            storage
                .list_capped("", len - 1)
                .await
                .expect_err("over the cap")
                .to_string(),
            over
        );

        // No declared length, no end: cut off by the counter.
        let (base, _) = spawn_server(|_, _| flood(false)).await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let err = tokio::time::timeout(Duration::from_secs(30), storage.list_capped("", TEST_CAP))
            .await
            .expect("refused at the first overrun")
            .expect_err("over the cap");
        assert_eq!(
            err.to_string(),
            format!(
                "Forge: download failed: file listing exceeded the size cap ({TEST_CAP} bytes)"
            )
        );
    }

    /// An error response's body is best-effort text. One that ends short of
    /// its declared length is shown as far as it arrived, and bytes that are
    /// not UTF-8 are replaced, not dropped with the rest of the body — a body
    /// cut at the read bound mid-character included.
    #[tokio::test]
    async fn an_error_body_that_is_cut_short_or_not_utf8_is_still_shown() {
        use crate::http_transfer::MAX_ERROR_BODY_LEN;
        const HEAD: &str = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n";

        // Declares 100 bytes, sends 9, and closes.
        let (base, _) = spawn_server(|_, _| {
            Reply::Raw(format!("{HEAD}Content-Length: 100\r\n\r\ndisk full").into_bytes())
        })
        .await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let err = storage.download("k").await.expect_err("500");
        assert_eq!(
            err.to_string(),
            "Forge: download failed: HTTP 500 Internal Server Error: disk full"
        );
        let err = storage.upload("k", b"payload").await.expect_err("500");
        assert_eq!(
            err.to_string(),
            "Forge: upload failed: HTTP 500 Internal Server Error: disk full"
        );

        // Bytes that are not UTF-8, between text that is.
        let (base, _) = spawn_server(|_, _| {
            let mut raw = format!("{HEAD}Content-Length: 11\r\n\r\n").into_bytes();
            raw.extend_from_slice(b"disk\xff\xfe full");
            Reply::Raw(raw)
        })
        .await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let err = storage.download("k").await.expect_err("500");
        assert_eq!(
            err.to_string(),
            "Forge: download failed: HTTP 500 Internal Server Error: disk\u{fffd}\u{fffd} full"
        );

        // A two-byte character straddling the read bound: the text before it
        // is kept.
        let (base, _) = spawn_server(|_, _| {
            let body = format!("{}\u{e9}tail", "x".repeat(MAX_ERROR_BODY_LEN - 1));
            let mut raw = format!("{HEAD}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
            raw.extend_from_slice(body.as_bytes());
            Reply::Raw(raw)
        })
        .await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        match storage.download("k").await.expect_err("500") {
            StorageError::DownloadFailed { message, .. } => {
                let body = message
                    .strip_prefix("HTTP 500 Internal Server Error: ")
                    .expect("names the status");
                assert!(
                    body.starts_with(&"x".repeat(MAX_ERROR_BODY_LEN - 1)) && !body.contains("tail"),
                    "{} bytes",
                    body.len()
                );
            }
            other => panic!("expected DownloadFailed, got {other:?}"),
        }
    }

    /// A file already at `dest` that the download cannot open for writing is
    /// not one the download created or truncated, so the failure leaves it as
    /// it was: only a `dest` the call opened is unlinked.
    #[tokio::test]
    async fn a_dest_that_cannot_be_opened_is_left_as_it_was() {
        use std::os::unix::fs::PermissionsExt;
        let (base, _) = spawn_server(|_, _| ok(b"bytes")).await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");
        std::fs::write(&dest, b"already here").expect("write dest");
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o444)).expect("chmod");
        if std::fs::OpenOptions::new().write(true).open(&dest).is_ok() {
            // Running with CAP_DAC_OVERRIDE: the mode refuses nothing.
            return;
        }

        let err = storage
            .download_to_file("k.bin", &dest)
            .await
            .expect_err("read-only dest");
        assert!(
            matches!(&err, StorageError::DownloadFailed { message, .. } if message.starts_with("create ")),
            "got {err:?}"
        );
        assert_eq!(std::fs::read(&dest).expect("read dest"), b"already here");

        // A directory at `dest` is refused the same way, and stays.
        let dir_dest = dir.path().join("a-directory");
        std::fs::create_dir(&dir_dest).expect("mkdir");
        storage
            .download_to_file("k.bin", &dir_dest)
            .await
            .expect_err("dest is a directory");
        assert!(dir_dest.is_dir());
    }

    //
    // Redirects: the client policy shared with `HttpsStorage`
    //

    /// Assert a request failed on the redirect policy for `reason`.
    fn assert_redirect_refused(err: StorageError, reason: &RedirectRefusal) {
        match err {
            StorageError::DownloadFailed { message, .. }
            | StorageError::UploadFailed { message, .. } => {
                assert!(message.contains(&reason.to_string()), "{message}");
            }
            other => panic!("expected a refused redirect, got {other:?}"),
        }
    }

    /// The message a write fails with when the forge answers it with a `3xx`.
    const WRITE_NOT_FOLLOWED: &str = "writes do not follow redirects";

    /// Assert a write failed on a `3xx` answer it did not follow.
    fn assert_write_not_followed(err: StorageError) {
        match err {
            StorageError::UploadFailed { message, .. } => {
                assert!(message.contains(WRITE_NOT_FOLLOWED), "{message}");
            }
            other => panic!("expected an unfollowed write redirect, got {other:?}"),
        }
    }

    /// A listener on `127.0.0.2` that records whether anything connected.
    ///
    /// `127.0.0.2` stands in for a remote plaintext host: outside the loopback
    /// carve-out's exact addresses, so the redirect policy treats it as
    /// remote, yet routed to `lo` on Linux, so a client that followed a
    /// redirect there is caught connecting rather than reaching the network.
    /// Returns a forge base that redirects every request to it, the forge's
    /// captured requests, and the flag.
    #[cfg(target_os = "linux")]
    async fn spawn_redirect_to_remote_plaintext() -> (
        String,
        crate::tests::Requests,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::sync::atomic::{AtomicBool, Ordering};

        let remote = TcpListener::bind("127.0.0.2:0")
            .await
            .expect("bind 127.0.0.2");
        let remote_addr = remote.local_addr().expect("local_addr");
        let reached = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&reached);
        tokio::spawn(async move {
            while let Ok((sock, _)) = remote.accept().await {
                flag.store(true, Ordering::SeqCst);
                drop(sock);
            }
        });
        let location = format!("http://{remote_addr}/api/fuz_forge/files/latest.json");
        let (base, requests) = spawn_server(move |_, _| redirect(&location)).await;
        (base, requests, reached)
    }

    /// A loopback `http` forge that redirects a read to a remote plaintext
    /// host is refused by the policy on every read method, before any
    /// connection to that host.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn read_redirect_from_loopback_to_remote_http_is_refused() {
        let (base, requests, reached) = spawn_redirect_to_remote_plaintext().await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let results = [
            ("download", storage.download("latest.json").await.map(drop)),
            (
                "download_to_file",
                storage
                    .download_to_file("latest.json", &dir.path().join("out.bin"))
                    .await
                    .map(drop),
            ),
            ("exists", storage.exists("latest.json").await.map(drop)),
            ("list", storage.list("").await.map(drop)),
        ];

        assert!(
            !reached.load(std::sync::atomic::Ordering::SeqCst),
            "a read followed the redirect to the remote plaintext host"
        );
        assert_eq!(
            requests.lock().await.len(),
            results.len(),
            "one request per method"
        );
        for (method, result) in results {
            let err = result.expect_err(method);
            assert_redirect_refused(err, &RedirectRefusal::InsecureScheme);
        }
    }

    /// The same redirect on a write is not followed at all: the write fails
    /// on the `3xx` itself.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn write_redirect_to_remote_http_is_not_followed() {
        let (base, requests, reached) = spawn_redirect_to_remote_plaintext().await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        std::fs::write(&src, b"payload").expect("write src");
        let results = [
            ("upload", storage.upload("latest.json", b"payload").await),
            (
                "upload_file",
                storage.upload_file("latest.json", &src).await,
            ),
            ("delete", storage.delete("latest.json").await),
        ];

        assert!(
            !reached.load(std::sync::atomic::Ordering::SeqCst),
            "a write followed the redirect to the remote plaintext host"
        );
        assert_eq!(
            requests.lock().await.len(),
            results.len(),
            "one request per method"
        );
        for (method, result) in results {
            assert_write_not_followed(result.expect_err(method));
        }
    }

    /// A raw `3xx` answer with this status line, carrying a body a write's
    /// error must not echo.
    fn redirect_with(status_line: &str, location: &str) -> Reply {
        let body = "<html>sign in</html>";
        Reply::Raw(
            format!(
                "{status_line}\r\nLocation: {location}\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        )
    }

    /// Writes never follow a redirect, whatever its status: `301`/`302` would
    /// turn the `POST` into a `GET`, `303` turns anything into one, and
    /// `307`/`308` replay the body (a buffered one — a streamed one cannot
    /// be). Here the redirect target is a same-origin page answering `200`, as
    /// an auth proxy's `/login` would, so a followed write would "succeed".
    #[tokio::test]
    async fn writes_never_follow_redirects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        std::fs::write(&src, b"payload").expect("write src");

        let mut failures = Vec::new();
        for status_line in [
            "HTTP/1.1 301 Moved Permanently",
            "HTTP/1.1 302 Found",
            "HTTP/1.1 303 See Other",
            "HTTP/1.1 307 Temporary Redirect",
            "HTTP/1.1 308 Permanent Redirect",
        ] {
            for method in ["upload", "upload_file", "delete"] {
                let (base, requests) = spawn_server(move |_, path| {
                    if path == "/login" {
                        ok(b"<html>login page</html>")
                    } else {
                        redirect_with(status_line, "/login")
                    }
                })
                .await;
                let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");
                let result = match method {
                    "upload" => storage.upload("latest.json", b"payload").await,
                    "upload_file" => storage.upload_file("latest.json", &src).await,
                    _ => storage.delete("latest.json").await,
                };
                let seen = requests.lock().await.len();
                let refused = matches!(
                    &result,
                    Err(StorageError::UploadFailed { message, .. })
                        if message.contains(WRITE_NOT_FOLLOWED) && !message.contains("sign in")
                );
                if !refused || seen != 1 {
                    failures.push(format!(
                        "{method} on {status_line}: {result:?}, {seen} request(s)"
                    ));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "writes that followed a redirect or failed otherwise:\n{}",
            failures.join("\n")
        );
    }

    /// An endless redirect chain stops at the shared hop cap, not
    /// `reqwest`'s default.
    #[tokio::test]
    async fn redirect_chain_over_the_limit_is_refused() {
        // `.../hop/<n>` redirects to `.../hop/<n+1>`, an endless fresh chain.
        let (base, requests) = spawn_server(|_, path| {
            let n = path
                .rsplit('/')
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or_default();
            redirect(&format!("/api/fuz_forge/files/hop/{}", n + 1))
        })
        .await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");

        let err = storage
            .download("hop/0")
            .await
            .expect_err("refused redirect");
        assert_redirect_refused(err, &RedirectRefusal::TooMany);
        // the original request plus one per hop followed
        assert_eq!(requests.lock().await.len(), MAX_REDIRECTS + 1);
    }

    /// A redirect within loopback is followed, and the next hop carries no
    /// `Referer` naming the forge URL it came from.
    #[tokio::test]
    async fn redirect_within_loopback_is_followed_without_referer() {
        let (base, requests) = spawn_server(|_, path| {
            if path == "/api/fuz_forge/files/latest.json" {
                redirect("/moved/latest.json")
            } else {
                ok(b"moved-bytes")
            }
        })
        .await;
        let storage = ForgeStorage::new(&base, "tok".to_string()).expect("new");

        assert_eq!(
            storage.download("latest.json").await.expect("download"),
            b"moved-bytes"
        );
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(requests[1].starts_with("GET /moved/latest.json "));
        assert!(
            !requests[1].to_ascii_lowercase().contains("referer:"),
            "Referer sent: {}",
            requests[1]
        );
    }

    /// A redirect to another origin — here another loopback port, which the
    /// policy allows — is fetched without the bearer token. `reqwest` drops
    /// it on any hop that changes scheme, host, or port; pinned here because
    /// the forge's docs promise it.
    #[tokio::test]
    async fn redirect_to_another_origin_drops_the_bearer_token() {
        let (other, other_requests) = spawn_server(|_, _| ok(b"other-bytes")).await;
        let location = format!("{other}/latest.json");
        let (base, requests) = spawn_server(move |_, _| redirect(&location)).await;
        let storage = ForgeStorage::new(&base, "secret-token".to_string()).expect("new");

        assert_eq!(
            storage.download("latest.json").await.expect("download"),
            b"other-bytes"
        );
        let first = requests.lock().await;
        assert_eq!(first.len(), 1, "{first:?}");
        assert!(first[0].contains("Bearer secret-token"), "{}", first[0]);
        let second = other_requests.lock().await;
        assert_eq!(second.len(), 1, "{second:?}");
        assert!(
            !second[0].contains("secret-token"),
            "token forwarded across origins: {}",
            second[0]
        );
    }

    #[tokio::test]
    async fn debug_redacts_token() {
        let storage = ForgeStorage::new("https://h", "super-secret".to_string()).expect("new");
        let rendered = format!("{storage:?}");
        assert!(
            !rendered.contains("super-secret"),
            "token leaked: {rendered}"
        );
        assert!(rendered.contains("redacted"));
    }
}
