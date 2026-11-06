//! Anonymous read-only HTTPS storage backend
//!
//! Reads keys from a public static host — a CDN, a release host, a raw file
//! host — with plain `GET` and `HEAD` requests under one base URL. It is the
//! generic transport for bytes anyone may fetch: it sends no credentials of any
//! kind, keeps no cookies, and knows nothing about what the keys mean.
//!
//! The host is untrusted, like every backend's byte source — callers that need
//! integrity verify the bytes after the fetch. What this module owns is the
//! transport's own exposure to a hostile or broken host:
//!
//! - **Scheme.** Every request is `https`. Plain `http` is accepted only for a
//!   loopback base (see [`HttpsStorage::new`]), so a local server needs no
//!   certificate.
//! - **Redirects.** Followed up to
//!   [`MAX_REDIRECTS`](crate::http_client::MAX_REDIRECTS) hops, each vetted by
//!   [`check_redirect`](crate::http_client::check_redirect): an `https` base
//!   can never be redirected onto `http`, and its client is `https_only`, so
//!   it cannot issue a plaintext request at all.
//! - **Size.** Bodies are counted while they stream and aborted at the ceiling
//!   — `MAX_BUFFERED_SIZE` for the buffered `download`, `MAX_TRANSFER_SIZE` for
//!   `download_to_file`; `Content-Length` is only a fast-path refusal.
//! - **Time.** A connect timeout plus an idle timeout between reads on every
//!   request, so a stalled host fails the transfer instead of hanging it. The
//!   buffered `download` and `exists` also carry a total deadline, so a host
//!   trickling bytes cannot hold them open.
//! - **Proxies.** A loopback `http` base bypasses the environment's proxies,
//!   so its plaintext request never leaves the machine.
//! - **Referer.** Never sent, so a redirect target does not learn the URL it
//!   was redirected from.
//! - **Keys.** Validated by [`validate_forge_key`] before they are joined onto
//!   the base, so a key can neither leave the base path nor name another host.
//!
//! The redirect, `https_only`, proxy, and `Referer` rules are the client policy
//! `ForgeStorage` shares — one implementation, in the crate's `http_client`
//! module; the forge follows redirects on its reads only.
//!
//! Writing, listing, and deleting have no anonymous HTTP form; those methods
//! return [`StorageError::Unsupported`].

use std::path::Path;
use std::time::Duration;

use fuz_sys::limits::{MAX_BUFFERED_SIZE, MAX_TRANSFER_SIZE};

use crate::Storage;
use crate::base_url::{self, BaseUrl};
use crate::error::{StorageBackendKind, StorageError};
use crate::http_client::{Redirects, client_builder};
use crate::http_status::is_auth_status;
use crate::http_transfer::{
    BodyLimit, REQUEST_TIMEOUT, check_content_length, download_body_to_file, error_chain,
    read_body_capped,
};
use crate::key::validate_forge_key;

/// Backend identity for error messages.
const BACKEND: StorageBackendKind = StorageBackendKind::Https;

/// Time allowed to establish a connection (TCP + TLS).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle time allowed between reads. The wait for response headers is one such
/// gap, spanning connect and every redirect hop.
///
/// The only time bound on `download_to_file`: a large artifact on a slow link
/// is a legitimately long transfer, while a host that stops sending is not,
/// and only the gap between reads tells the two apart. The small-payload
/// requests add a total deadline on top (see [`Timeouts::request`]).
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The time bounds a backend is built with.
#[derive(Debug, Clone, Copy)]
struct Timeouts {
    /// Idle time allowed between reads, on every request.
    read: Duration,
    /// Total deadline — connect through the end of the body — on the buffered
    /// `download` and on `exists`. An idle timeout alone leaves those open to
    /// a host that trickles a byte at a time; `download_to_file` carries no
    /// total deadline, since no fixed one fits every artifact and link.
    request: Duration,
}

impl Timeouts {
    const DEFAULT: Self = Self {
        read: READ_TIMEOUT,
        request: REQUEST_TIMEOUT,
    };
}

/// Anonymous read-only storage backend over HTTPS.
///
/// Construct directly with [`HttpsStorage::new`], or via
/// [`crate::parse_storage`] from an `https://host/base/path` URI. Supports
/// `download`, `download_to_file`, and `exists`; every other [`Storage`] method
/// returns [`StorageError::Unsupported`].
#[derive(Debug)]
pub struct HttpsStorage {
    client: reqwest::Client,
    /// Normalized base URL (scheme + `host[:port]` + base path, no trailing
    /// slash). A key resolves to `<base_url>/<key>`.
    base_url: String,
    /// Total deadline for the buffered `download` and `exists`.
    request_timeout: Duration,
}

impl HttpsStorage {
    /// Create a backend rooted at `base_url`.
    ///
    /// `base_url` must be `https://host[:port][/base/path]`. Plain `http://`
    /// is accepted only when the host is `localhost`, `127.0.0.1`, or `[::1]`;
    /// any other `http://` host is refused. A URL carrying userinfo
    /// (`user:pass@`), a query, or a fragment is refused — the backend is
    /// unauthenticated and the base names a directory, not a request (the
    /// shared rules in the crate's `base_url` module).
    pub fn new(base_url: &str) -> Result<Self, StorageError> {
        Self::with_timeouts(base_url, Timeouts::DEFAULT)
    }

    /// [`HttpsStorage::new`] with the time bounds as a parameter.
    fn with_timeouts(base_url: &str, timeouts: Timeouts) -> Result<Self, StorageError> {
        let base = validate_base_url(base_url)?;
        let client = client_builder(&base, Redirects::Follow)
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(timeouts.read)
            .build()
            .map_err(|e| StorageError::InvalidConfig {
                message: format!("failed to create HTTP client: {e}"),
            })?;
        Ok(Self {
            client,
            base_url: base.url,
            request_timeout: timeouts.request,
        })
    }

    /// Resolve a key to its URL, refusing any key that is not traversal-safe.
    ///
    /// The validated charset (`[A-Za-z0-9._/-]`, no `.`/`..` or empty
    /// segments, relative) is URL-path-safe and carries no `?`, `#`, `\`,
    /// `:`, or control character, so the join needs no percent-encoding and
    /// the result always sits under the base path on the base host.
    fn key_url(&self, key: &str) -> Result<String, StorageError> {
        validate_forge_key(key)?;
        Ok(format!("{}/{key}", self.base_url))
    }

    /// Send one request and map a non-success status to its error.
    ///
    /// `deadline` is the total time allowed from connect through the end of
    /// the response body; `None` leaves the request on the idle timeout alone.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        deadline: Option<Duration>,
    ) -> Result<reqwest::Response, StorageError> {
        let url = self.key_url(path)?;
        let mut request = self.client.request(method, &url);
        if let Some(deadline) = deadline {
            request = request.timeout(deadline);
        }
        let response = request
            .send()
            .await
            .map_err(|e| StorageError::DownloadFailed {
                backend: BACKEND,
                message: error_chain(&e),
            })?;
        check_status(response.status(), path)?;
        Ok(response)
    }

    /// The buffered download behind [`Storage::download`] and
    /// [`Storage::download_capped`], with the size ceiling as a parameter.
    async fn download_bounded(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        let mut response = self
            .send(reqwest::Method::GET, path, Some(self.request_timeout))
            .await?;
        let limit = BodyLimit {
            backend: BACKEND,
            path,
            max,
        };
        check_content_length(&response, &limit)?;
        read_body_capped(&mut response, &limit).await
    }

    /// [`Storage::download_to_file`] with the size ceiling as a parameter.
    ///
    /// A refusal before the transfer starts (the status, a declared length
    /// over `max`) leaves a file already at `dest` as it was; on any failure
    /// after that the path `dest` is unlinked (`download_body_to_file`, the
    /// tail shared with `ForgeStorage`).
    async fn download_to_file_capped(
        &self,
        path: &str,
        dest: &Path,
        max: u64,
    ) -> Result<u64, StorageError> {
        let mut response = self.send(reqwest::Method::GET, path, None).await?;
        let limit = BodyLimit {
            backend: BACKEND,
            path,
            max,
        };
        download_body_to_file(&mut response, dest, &limit).await
    }
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "trait conformance: the read-only backend's refusals stay `async fn` like every `Storage` impl; the `impl Future` rewrite would run them at call time"
)]
impl Storage for HttpsStorage {
    fn backend_kind(&self) -> StorageBackendKind {
        BACKEND
    }

    async fn upload(&self, _path: &str, _data: &[u8]) -> Result<(), StorageError> {
        Err(unsupported("upload"))
    }

    async fn download(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        // Buffered, so bounded by the in-memory ceiling; `download_to_file`
        // is the path for anything larger.
        self.download_bounded(path, MAX_BUFFERED_SIZE).await
    }

    async fn download_capped(&self, path: &str, max: u64) -> Result<Vec<u8>, StorageError> {
        // Counted while the body streams, like every read here; never above
        // the buffered ceiling whatever the caller asks for.
        self.download_bounded(path, max.min(MAX_BUFFERED_SIZE))
            .await
    }

    async fn download_to_file(&self, path: &str, dest: &Path) -> Result<u64, StorageError> {
        self.download_to_file_capped(path, dest, MAX_TRANSFER_SIZE)
            .await
    }

    async fn upload_file(&self, _path: &str, _src: &Path) -> Result<(), StorageError> {
        Err(unsupported("upload"))
    }

    async fn exists(&self, path: &str) -> Result<bool, StorageError> {
        // `HEAD` answers with the status alone — no body to bound.
        match self
            .send(reqwest::Method::HEAD, path, Some(self.request_timeout))
            .await
        {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn list(&self, _prefix: &str) -> Result<Vec<String>, StorageError> {
        Err(unsupported("list"))
    }

    async fn delete(&self, _path: &str) -> Result<(), StorageError> {
        Err(unsupported("delete"))
    }
}

const fn unsupported(operation: &'static str) -> StorageError {
    StorageError::Unsupported {
        backend: BACKEND,
        operation,
    }
}

/// Map a response status to the shared storage-error shapes: 404 is
/// `NotFound`, 401/403 `PermissionDenied`, any other non-success
/// `DownloadFailed`.
///
/// The error carries the status only. The body of an error response is
/// untrusted, unbounded text from the host, so it is never read.
fn check_status(status: reqwest::StatusCode, path: &str) -> Result<(), StorageError> {
    if status.is_success() {
        Ok(())
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
        Err(StorageError::DownloadFailed {
            backend: BACKEND,
            message: format!("HTTP {status}"),
        })
    }
}

/// Validate and normalize a base URL through the shared [`crate::base_url`]
/// rules (see [`HttpsStorage::new`]).
fn validate_base_url(base: &str) -> Result<BaseUrl, StorageError> {
    base_url::validate_base_url(base).map_err(|refusal| StorageError::InvalidConfig {
        message: format!("invalid https storage URL: {refusal}"),
    })
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::RedirectRefusal;
    use crate::tests::{Reply, Requests, ok, redirect, spawn_server, status};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    //
    // Pure-logic tests
    //

    #[test]
    fn base_url_accepts_https_and_normalizes() {
        assert_eq!(
            validate_base_url("https://releases.example.com").unwrap(),
            BaseUrl {
                url: "https://releases.example.com".to_string(),
                is_https: true,
            }
        );
        // A trailing slash is trimmed; a base path and port are kept.
        assert_eq!(
            validate_base_url("https://example.com:8443/base/path/")
                .unwrap()
                .url,
            "https://example.com:8443/base/path"
        );
    }

    #[test]
    fn base_url_allows_plaintext_only_for_loopback() {
        for base in [
            "http://localhost:4041",
            "http://127.0.0.1:4041/releases",
            "http://[::1]:4041",
            // an alternate spelling of 127.0.0.1 parses to the same address
            "http://127.1:4041",
        ] {
            let got = validate_base_url(base).expect(base);
            assert!(!got.is_https, "{base}");
        }
        // plaintext to any other host is refused, loopback look-alikes included
        for base in [
            "http://example.com/releases",
            "http://127.0.0.2/releases",
            "http://localhost.example.com/",
            "http://[::2]/releases",
            "http://0.0.0.0/releases",
        ] {
            let err = validate_base_url(base).expect_err(base);
            assert!(
                err.to_string().contains("refusing plaintext http"),
                "{base}: {err}"
            );
        }
    }

    #[test]
    fn base_url_rejects_other_schemes_and_malformed_urls() {
        assert!(validate_base_url("ftp://example.com/releases").is_err());
        assert!(validate_base_url("https://").is_err());
        assert!(validate_base_url("not a url").is_err());
    }

    #[test]
    fn base_url_rejects_userinfo_without_echoing_it() {
        for base in [
            "https://user:hunter2@example.com/releases",
            "https://user@example.com/releases",
            "https://:hunter2@example.com/releases",
        ] {
            let err = validate_base_url(base).expect_err(base);
            let message = err.to_string();
            assert!(message.contains("must not carry credentials"), "{message}");
            assert!(!message.contains("hunter2"), "secret leaked: {message}");
        }
    }

    #[test]
    fn base_url_rejects_query_and_fragment() {
        for base in [
            "https://example.com/releases?token=abc",
            "https://example.com/releases?",
            "https://example.com/releases#frag",
        ] {
            let err = validate_base_url(base).expect_err(base);
            assert!(
                err.to_string().contains("query or fragment"),
                "{base}: {err}"
            );
        }
    }

    #[test]
    fn key_url_joins_under_the_base() {
        let storage = HttpsStorage::new("https://example.com/base/").unwrap();
        assert_eq!(
            storage.key_url("tools/zap/latest.json").unwrap(),
            "https://example.com/base/tools/zap/latest.json"
        );
        let rootless = HttpsStorage::new("https://example.com").unwrap();
        assert_eq!(
            rootless.key_url("latest.json").unwrap(),
            "https://example.com/latest.json"
        );
    }

    #[test]
    fn key_url_rejects_every_escape_form() {
        let storage = HttpsStorage::new("https://example.com/base").unwrap();
        for key in [
            "",
            "../secret",
            "tools/../../secret",
            "tools/./x",
            "/etc/passwd",
            "//evil.example.com/x",
            "https://evil.example.com/x",
            "evil.example.com:443/x",
            "latest.json?x=1",
            "latest.json#frag",
            "tools\\..\\secret",
            "tools/%2e%2e/secret",
            "tools/a b",
            "tools/a\nb",
            "tools/a\0b",
            "tools/a\tb",
            "@evil.example.com/x",
        ] {
            let err = storage.key_url(key).expect_err(key);
            assert!(
                matches!(err, StorageError::InvalidKey { .. }),
                "{key:?}: {err:?}"
            );
        }
    }

    #[test]
    fn status_mapping_reuses_the_shared_error_shapes() {
        use reqwest::StatusCode;
        assert!(check_status(StatusCode::OK, "k").is_ok());
        assert!(matches!(
            check_status(StatusCode::NOT_FOUND, "k"),
            Err(StorageError::NotFound { .. })
        ));
        for status in [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN] {
            assert!(matches!(
                check_status(status, "k"),
                Err(StorageError::PermissionDenied { .. })
            ));
        }
        // an unfollowed redirect status is a failure, not a success
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::FOUND,
        ] {
            assert!(matches!(
                check_status(status, "k"),
                Err(StorageError::DownloadFailed { .. })
            ));
        }
    }

    //
    // Round-trip tests against an in-process HTTP server (no deps)
    //

    /// Size ceiling the flood tests download under.
    const FLOOD_CAP: u64 = 64 * 1024;

    /// Upper bound on any single hostile-server test: a client that loses its
    /// own bound fails here instead of hanging the suite.
    const TEST_DEADLINE: Duration = Duration::from_secs(30);

    async fn bounded<T>(test: impl Future<Output = T>) -> T {
        tokio::time::timeout(TEST_DEADLINE, test)
            .await
            .expect("the client's own bound should end this well inside the test deadline")
    }

    /// The single captured request line (`METHOD /path HTTP/1.1`).
    async fn only_request(requests: &Requests) -> String {
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 1, "expected one request: {requests:?}");
        requests[0].clone()
    }

    #[tokio::test]
    async fn download_returns_body_and_sends_no_credentials() {
        let (base, requests) = spawn_server(|_, _| ok(b"artifact-bytes")).await;
        let storage = HttpsStorage::new(&format!("{base}/releases")).expect("new");

        let got = storage
            .download("tools/zap/latest.json")
            .await
            .expect("download");
        assert_eq!(got, b"artifact-bytes");

        let head = only_request(&requests).await;
        assert!(
            head.starts_with("GET /releases/tools/zap/latest.json HTTP/1.1\r\n"),
            "{head}"
        );
        let lower = head.to_ascii_lowercase();
        for header in ["authorization:", "cookie:", "referer:"] {
            assert!(!lower.contains(header), "{header} sent: {head}");
        }
    }

    #[tokio::test]
    async fn download_to_file_streams_body_to_disk() {
        // Larger than one read, so the body arrives as several chunks.
        let body: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
        let served = body.clone();
        let (base, requests) = spawn_server(move |_, _| ok(&served)).await;
        let storage = HttpsStorage::new(&base).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let n = storage
            .download_to_file("tools/zap/zap.tar.gz", &dest)
            .await
            .expect("download_to_file");

        assert_eq!(n, body.len() as u64);
        assert_eq!(std::fs::read(&dest).expect("read dest"), body);
        let head = only_request(&requests).await;
        assert!(head.starts_with("GET /tools/zap/zap.tar.gz "), "{head}");
    }

    #[tokio::test]
    async fn exists_probes_with_head() {
        let (base, requests) = spawn_server(|_, _| status("HTTP/1.1 200 OK")).await;
        let storage = HttpsStorage::new(&base).expect("new");

        assert!(storage.exists("latest.json").await.expect("exists"));
        let head = only_request(&requests).await;
        assert!(head.starts_with("HEAD /latest.json "), "{head}");
    }

    #[tokio::test]
    async fn exists_404_is_false() {
        let (base, _) = spawn_server(|_, _| status("HTTP/1.1 404 Not Found")).await;
        let storage = HttpsStorage::new(&base).expect("new");
        assert!(!storage.exists("missing.json").await.expect("exists"));
    }

    #[tokio::test]
    async fn exists_500_is_an_error_not_false() {
        let (base, _) = spawn_server(|_, _| status("HTTP/1.1 500 Internal Server Error")).await;
        let storage = HttpsStorage::new(&base).expect("new");
        let err = storage.exists("latest.json").await.expect_err("should 500");
        assert!(
            matches!(err, StorageError::DownloadFailed { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn download_404_maps_to_not_found() {
        let (base, _) = spawn_server(|_, _| status("HTTP/1.1 404 Not Found")).await;
        let storage = HttpsStorage::new(&base).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let err = storage.download("nope.json").await.expect_err("should 404");
        assert!(matches!(err, StorageError::NotFound { .. }), "got {err:?}");
        let err = storage
            .download_to_file("nope.json", &dest)
            .await
            .expect_err("should 404");
        assert!(matches!(err, StorageError::NotFound { .. }), "got {err:?}");
        assert!(!dest.exists(), "a refused download must not create dest");
    }

    #[tokio::test]
    async fn download_500_maps_to_download_failed_without_the_body() {
        let (base, _) = spawn_server(|_, _| {
            Reply::Raw(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 11\r\n\
                  Connection: close\r\n\r\nhostile-msg"
                    .to_vec(),
            )
        })
        .await;
        let storage = HttpsStorage::new(&base).expect("new");

        let err = storage.download("x.json").await.expect_err("should 500");
        match err {
            StorageError::DownloadFailed { message, .. } => {
                assert!(message.contains("500"), "{message}");
                assert!(!message.contains("hostile-msg"), "{message}");
            }
            other => panic!("expected DownloadFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_403_maps_to_permission_denied() {
        let (base, _) = spawn_server(|_, _| status("HTTP/1.1 403 Forbidden")).await;
        let storage = HttpsStorage::new(&base).expect("new");
        let err = storage.download("x.json").await.expect_err("should 403");
        assert!(
            matches!(err, StorageError::PermissionDenied { .. }),
            "got {err:?}"
        );
    }

    /// A declared length over the cap is refused from the headers alone: the
    /// server never sends the body it promised, so a client that tried to read
    /// it would hit the idle timeout instead of returning `TooLarge`.
    #[tokio::test]
    async fn oversized_content_length_is_refused_before_reading() {
        let (base, _) = spawn_server(|_, _| {
            Reply::Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n".to_vec())
        })
        .await;
        let storage = HttpsStorage::new(&base).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let err = storage
            .download_capped("big.bin", 16)
            .await
            .expect_err("too large");
        assert!(
            matches!(
                err,
                StorageError::TooLarge {
                    size: 1000,
                    max: 16,
                    ..
                }
            ),
            "got {err:?}"
        );
        let err = storage
            .download_to_file_capped("big.bin", &dest, 16)
            .await
            .expect_err("too large");
        assert!(matches!(err, StorageError::TooLarge { .. }), "got {err:?}");
        assert!(!dest.exists(), "refused before dest is created");
    }

    /// `Storage::download_capped` — the trait method, not the backend's own
    /// bounded read called directly — stops reading at the caller's limit.
    #[tokio::test]
    async fn download_capped_bounds_the_body_while_reading() {
        let (base, written) = crate::tests::spawn_flood(crate::tests::FLOOD_TOTAL).await;
        let storage = HttpsStorage::new(&base).expect("new");
        crate::tests::assert_capped_while_reading(&storage, &written).await;
    }

    /// A body with no declared length that runs far past the cap: only a
    /// mid-stream counter stops it. Without one the client reads the whole
    /// flood and reports something other than an overrun at the cap.
    async fn assert_flood_is_aborted(head: &'static str, chunked: bool) {
        let (base, _) = spawn_server(move |_, _| Reply::Flood { head, chunked }).await;
        let storage = HttpsStorage::new(&base).expect("new");

        let err = bounded(storage.download_capped("big.bin", FLOOD_CAP))
            .await
            .expect_err("too large");
        match err {
            StorageError::TooLarge { size, max, .. } => {
                assert_eq!(max, FLOOD_CAP);
                assert!(size > max, "aborted past the cap: {size}");
                assert!(
                    size < 2 * FLOOD_CAP,
                    "aborted at the first overrun, not after the flood: {size}"
                );
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");
        let err = bounded(storage.download_to_file_capped("big.bin", &dest, FLOOD_CAP))
            .await
            .expect_err("too large");
        assert!(matches!(err, StorageError::TooLarge { .. }), "got {err:?}");
        assert!(!dest.exists(), "partial download left behind");
    }

    #[tokio::test]
    async fn lying_chunked_body_is_aborted_mid_stream() {
        assert_flood_is_aborted(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn lying_unframed_body_is_aborted_mid_stream() {
        assert_flood_is_aborted("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", false).await;
    }

    /// The public methods pass the ceilings they document: the buffered
    /// `download` the in-memory one, `download_to_file` the transfer one. A
    /// declared length one byte over each is refused from the headers, and the
    /// error names the ceiling that refused it.
    #[tokio::test]
    async fn public_methods_apply_their_own_ceilings() {
        let (base, _) = spawn_server(|_, path| {
            let len = if path == "/buffered.bin" {
                MAX_BUFFERED_SIZE + 1
            } else {
                MAX_TRANSFER_SIZE + 1
            };
            Reply::Raw(format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n").into_bytes())
        })
        .await;
        let storage = HttpsStorage::new(&base).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let err = bounded(storage.download("buffered.bin"))
            .await
            .expect_err("too large");
        assert!(
            matches!(err, StorageError::TooLarge { max, .. } if max == MAX_BUFFERED_SIZE),
            "got {err:?}"
        );
        let err = bounded(storage.download_to_file("streamed.bin", &dest))
            .await
            .expect_err("too large");
        assert!(
            matches!(err, StorageError::TooLarge { max, .. } if max == MAX_TRANSFER_SIZE),
            "got {err:?}"
        );
        assert!(!dest.exists(), "refused before dest is created");
    }

    /// A body that ends short of its declared length is a failed transfer, and
    /// the bytes that did arrive are not left on disk.
    #[tokio::test]
    async fn truncated_body_leaves_no_partial_file() {
        let (base, _) = spawn_server(|_, _| {
            Reply::Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial".to_vec())
        })
        .await;
        let storage = HttpsStorage::new(&base).expect("new");
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

    /// Short idle timeout, with the total deadline out of the way.
    const IDLE_ONLY: Timeouts = Timeouts {
        read: Duration::from_millis(200),
        request: Duration::from_secs(60),
    };

    #[tokio::test]
    async fn stalled_server_times_out() {
        let (base, _) = spawn_server(|_, _| Reply::Stall).await;
        let storage = HttpsStorage::with_timeouts(&base, IDLE_ONLY).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let err = bounded(storage.download("latest.json"))
            .await
            .expect_err("stalled");
        match err {
            StorageError::DownloadFailed { message, .. } => {
                assert!(message.contains("timed out"), "{message}");
            }
            other => panic!("expected DownloadFailed, got {other:?}"),
        }
        assert!(bounded(storage.exists("latest.json")).await.is_err());
        assert!(
            bounded(storage.download_to_file("latest.json", &dest))
                .await
                .is_err()
        );
        assert!(!dest.exists(), "a stalled request must not create dest");
    }

    /// A host that sends headers and part of the body, then goes quiet.
    #[tokio::test]
    async fn stalled_body_times_out_and_leaves_no_partial_file() {
        // The shared server closes after a `Reply::Raw`; a stall needs the
        // socket held open with the body unfinished.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("local_addr"));
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut tmp = [0u8; 1024];
            let _ = sock.read(&mut tmp).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
                .await;
            std::future::pending::<()>().await;
        });
        let storage = HttpsStorage::with_timeouts(&base, IDLE_ONLY).expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");

        let err = bounded(storage.download_to_file("slow.bin", &dest))
            .await
            .expect_err("stalled");
        assert!(
            matches!(&err, StorageError::DownloadFailed { message, .. } if message.contains("timed out")),
            "got {err:?}"
        );
        assert!(!dest.exists(), "partial download left behind");
    }

    /// A host trickling bytes never trips the idle timeout. The total deadline
    /// cuts the buffered `download`; `download_to_file` has none and keeps
    /// reading for as long as bytes arrive.
    #[tokio::test]
    async fn slow_drip_is_cut_by_the_total_deadline_on_download_only() {
        let (base, _) = spawn_server(|_, _| Reply::Drip {
            head: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1000\r\n",
        })
        .await;
        let deadline = Duration::from_millis(400);
        let storage = HttpsStorage::with_timeouts(
            &base,
            Timeouts {
                read: Duration::from_secs(10),
                request: deadline,
            },
        )
        .expect("new");

        let started = std::time::Instant::now();
        let err = bounded(storage.download("drip.json"))
            .await
            .expect_err("deadline");
        assert!(
            matches!(&err, StorageError::DownloadFailed { message, .. } if message.contains("timed out")),
            "got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "cut by the total deadline, not the idle timeout: {:?}",
            started.elapsed()
        );

        // Three deadlines in, the streaming download is still receiving.
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out.bin");
        let streaming = storage.download_to_file("drip.bin", &dest);
        assert!(
            tokio::time::timeout(deadline * 3, streaming).await.is_err(),
            "download_to_file must not carry the total deadline"
        );
    }

    /// `exists` carries the total deadline too: with the idle timeout out of
    /// reach, a host that never answers is still cut.
    #[tokio::test]
    async fn exists_is_cut_by_the_total_deadline() {
        let (base, _) = spawn_server(|_, _| Reply::Stall).await;
        let storage = HttpsStorage::with_timeouts(
            &base,
            Timeouts {
                read: TEST_DEADLINE * 2,
                request: Duration::from_millis(300),
            },
        )
        .expect("new");

        let err = bounded(storage.exists("latest.json"))
            .await
            .expect_err("deadline");
        assert!(
            matches!(err, StorageError::DownloadFailed { .. }),
            "got {err:?}"
        );
    }

    //
    // Proxy bypass, tested in a child process: the proxy variables are read
    // from the process environment, which a test cannot set for itself.
    //

    /// Names the loopback base the child half downloads from.
    const PROXY_CHILD_BASE_ENV: &str = "FUZ_STORAGE_TEST_PROXY_CHILD_BASE";

    /// Helper for `loopback_http_bypasses_environment_proxy`, run in a
    /// subprocess that inherits proxy variables: downloads one key from the
    /// base named in [`PROXY_CHILD_BASE_ENV`].
    #[tokio::test]
    #[ignore = "subprocess helper for loopback_http_bypasses_environment_proxy"]
    async fn proxy_bypass_child() {
        let Ok(base) = std::env::var(PROXY_CHILD_BASE_ENV) else {
            return;
        };
        let storage = HttpsStorage::new(&base).expect("new");
        let got = bounded(storage.download("latest.json"))
            .await
            .expect("download");
        assert_eq!(got, b"direct");
    }

    /// With the proxy variables naming a credentialed proxy, a loopback `http`
    /// base still connects straight to its host: the proxy sees no connection,
    /// so neither the request nor the proxy credentials go anywhere but the
    /// loopback target.
    #[tokio::test]
    async fn loopback_http_bypasses_environment_proxy() {
        let (base, direct) = spawn_server(|_, _| ok(b"direct")).await;
        let (proxy, proxied) = spawn_server(|_, _| ok(b"proxied")).await;
        let proxy = proxy.replace("http://", "http://user:hunter2@");

        let exe = std::env::current_exe().expect("test executable");
        let mut child = tokio::process::Command::new(exe);
        child
            .args(["--ignored", "--exact", "https::tests::proxy_bypass_child"])
            .env(PROXY_CHILD_BASE_ENV, &base)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy");
        for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
            child.env(name, &proxy);
        }
        let output = bounded(child.output()).await.expect("run child");

        let proxied = proxied.lock().await;
        assert!(proxied.is_empty(), "request went to the proxy: {proxied:?}");
        assert!(
            output.status.success(),
            "child download failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(direct.lock().await.len(), 1, "one direct request");
    }

    #[tokio::test]
    async fn redirect_within_loopback_is_followed() {
        let (base, requests) = spawn_server(|_, path| {
            if path == "/latest.json" {
                redirect("/moved/latest.json")
            } else {
                ok(b"moved-bytes")
            }
        })
        .await;
        let storage = HttpsStorage::new(&base).expect("new");

        assert_eq!(
            storage.download("latest.json").await.expect("download"),
            b"moved-bytes"
        );
        let requests = requests.lock().await;
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(requests[1].starts_with("GET /moved/latest.json "));
        // A redirected request is the one a `Referer` would be added to.
        assert!(
            !requests[1].to_ascii_lowercase().contains("referer:"),
            "Referer sent: {}",
            requests[1]
        );
    }

    async fn assert_redirect_refused(location: &'static str, reason: RedirectRefusal) {
        let (base, _) = spawn_server(move |_, path| {
            // `/hop/<n>` redirects to `/hop/<n+1>`, an endless fresh chain.
            path.strip_prefix("/hop/")
                .and_then(|n| n.parse::<u32>().ok())
                .map_or_else(
                    || redirect(location),
                    |n| redirect(&format!("/hop/{}", n + 1)),
                )
        })
        .await;
        let storage = HttpsStorage::new(&base).expect("new");
        let key = if location.is_empty() {
            "hop/0"
        } else {
            "latest.json"
        };

        let err = storage.download(key).await.expect_err("refused redirect");
        match err {
            StorageError::DownloadFailed { message, .. } => {
                assert!(message.contains(&reason.to_string()), "{message}");
            }
            other => panic!("expected DownloadFailed, got {other:?}"),
        }
        assert!(storage.exists(key).await.is_err());
    }

    #[tokio::test]
    async fn redirect_from_loopback_to_remote_http_is_refused() {
        assert_redirect_refused(
            "http://example.com/latest.json",
            RedirectRefusal::InsecureScheme,
        )
        .await;
    }

    #[tokio::test]
    async fn redirect_loop_is_refused() {
        assert_redirect_refused("/latest.json", RedirectRefusal::Loop).await;
    }

    #[tokio::test]
    async fn redirect_chain_over_the_limit_is_refused() {
        assert_redirect_refused("", RedirectRefusal::TooMany).await;
    }

    #[tokio::test]
    async fn mutating_and_listing_methods_are_unsupported() {
        // No server: an unsupported method fails before any request.
        let storage = HttpsStorage::new("https://example.com/releases").expect("new");
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        std::fs::write(&src, b"payload").expect("write src");

        let is_unsupported = |err: StorageError, operation: &str| {
            assert!(
                matches!(
                    err,
                    StorageError::Unsupported {
                        backend: StorageBackendKind::Https,
                        operation: op,
                    } if op == operation
                ),
                "{operation}: got {err:?}"
            );
        };
        is_unsupported(storage.upload("k", b"x").await.unwrap_err(), "upload");
        is_unsupported(storage.upload_file("k", &src).await.unwrap_err(), "upload");
        is_unsupported(storage.list("").await.unwrap_err(), "list");
        is_unsupported(storage.delete("k").await.unwrap_err(), "delete");
    }

    #[test]
    fn backend_kind_is_https() {
        let storage = HttpsStorage::new("https://example.com").expect("new");
        assert_eq!(storage.backend_kind(), StorageBackendKind::Https);
        assert_eq!(storage.name(), "HTTPS");
    }
}
