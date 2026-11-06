//! The production [`TarballSource`]: stream an npm tarball over HTTPS with
//! `reqwest`.
//!
//! Mirrors `fuz_storage::ForgeStorage::download_to_file`'s `Response::chunk()`
//! streaming (bounded memory, no whole-tarball buffering), minus the bearer auth
//! and with fuzi's tighter per-tarball cap. **Transport-only**: it never hashes
//! or verifies — that is [`crate::cache::NpmCache::commit`]'s job. The
//! `https`-only trust gate lives in `classify` (the SSRF / plaintext-exfil
//! floor); this layer keeps that gate intact at the transport edge by **refusing
//! redirects** — fuzi contacts exactly the lockfile's `resolved` URL. Following a
//! redirect could escape classify's check (downgrade `https`→`http`, or reach an
//! internal/metadata host), and the fuz projects' own lockfiles resolve only to
//! direct `registry.npmjs.org` tarball URLs (no redirects), so v0 refuses and a
//! 3xx surfaces as a teaching error.
//
// TODO (future, gated on a real use case): some private registries / mirrors
// (Artifactory, Nexus, Verdaccio, S3-backed) 302 a tarball to a CDN/object-store
// URL. The preferred opt-in is NOT a blanket "follow all https redirects" flag but
// a **least-privilege allowlist**: the user supplies one or more redirect-target
// matchers (host + path-prefix or glob, e.g. `https://cdn.example.com/tarballs/*`),
// and a redirect is followed only if its target is https AND matches an entry — so
// even a compromised registry can redirect only to the allowlisted CDN, never to an
// arbitrary internal/metadata host (which the blanket flag would permit). Build it
// against a real mirror, with that mirror's pattern as the test — not speculatively.
// Until then this is YAGNI / model-and-refuse: the loud 3xx error below is the
// actionable signpost.

use std::path::Path;
use std::time::Duration;

use reqwest::redirect;
use tokio::io::AsyncWriteExt as _;

use super::{FetchError, TarballSource, removing_dest_on_error};
use crate::cache::MAX_NPM_TARBALL_SIZE;

/// Connection-establishment timeout — a registry that won't connect promptly is
/// down/unreachable; fail fast rather than hang.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle (between-chunk) read timeout — kills a slow-loris / stalled stream
/// without penalizing a large-but-steady download (so there is *no* overall cap).
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The HTTPS client fetching tarballs could not be built — a deterministic
/// failure of this machine's TLS setup (its certificate trust store, say).
///
/// Its own type rather than a [`FetchError`] arm: it happens once, before any
/// tarball is contacted, so it never reaches the per-tarball classification —
/// the caller maps it to [`FuziError::HttpClient`](crate::FuziError::HttpClient).
#[derive(Debug, thiserror::Error)]
#[error("{reason}")]
pub struct ClientInitError {
    /// The client builder's failure detail.
    pub reason: String,
}

/// A `reqwest`-backed tarball downloader.
#[derive(Debug, Clone)]
pub struct NpmTarballSource {
    client: reqwest::Client,
    /// Per-tarball byte cap (the impl's tighter layer over `fuz_sys::limits`).
    max_bytes: u64,
}

impl NpmTarballSource {
    /// Build a source with a fresh HTTP client and the default per-tarball cap.
    ///
    /// The client **refuses redirects** ([`redirect::Policy::none`]) — fuzi
    /// contacts exactly the lockfile's `resolved` URL, so the `https`-only gate
    /// can't be sidestepped via a 3xx (which instead surfaces as a teaching
    /// transport error). Connect + idle-read timeouts bound a stalled registry.
    ///
    /// # Errors
    ///
    /// Returns [`ClientInitError`] if the TLS-backed client cannot be
    /// constructed — deterministic, so the caller keeps it out of the "re-run
    /// to retry" fetch class.
    pub fn new() -> Result<Self, ClientInitError> {
        // IMPORTANT — do NOT enable reqwest's transfer-decompression (`gzip` /
        // `brotli` / `deflate` features), for *both* correctness and performance:
        //   - Correctness: fuzi hashes the **raw transferred bytes** against the
        //     lockfile sha512, which is computed over the *gzipped* `.tar.gz`. If
        //     reqwest auto-decompressed a `Content-Encoding`-marked body, every
        //     integrity check would mismatch.
        //   - Performance: there is nothing to gain — the payload is *already* gzip,
        //     and HTTP-recompressing high-entropy data saves ~0 bytes while costing
        //     CPU on both ends. npm registries serve `.tgz` as identity-encoded
        //     `application/octet-stream`, and without the feature reqwest advertises
        //     no `Accept-Encoding`, so we receive exactly the raw bytes we hash.
        // The workspace `reqwest` features are `["json", "rustls-no-provider",
        // "stream"]` (no decompression) by design — this comment guards that
        // against a future feature bump. TLS verification is on (rustls + the
        // `ring` provider that `fuz_sys::tls` installs as the process default).
        fuz_sys::tls::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .user_agent(concat!("fuzi/", env!("CARGO_PKG_VERSION")))
            .redirect(redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .map_err(|e| ClientInitError {
                reason: e.to_string(),
            })?;
        Ok(Self {
            client,
            max_bytes: MAX_NPM_TARBALL_SIZE,
        })
    }

    /// Construct with an explicit client + cap (tests inject a tiny cap).
    #[cfg(test)]
    const fn with_cap(client: reqwest::Client, max_bytes: u64) -> Self {
        Self { client, max_bytes }
    }
}

impl TarballSource for NpmTarballSource {
    async fn fetch_to_file(&self, url: &str, dest: &Path) -> Result<u64, FetchError> {
        removing_dest_on_error(dest, self.stream_to_file(url, dest)).await
    }
}

impl NpmTarballSource {
    /// The download itself; [`TarballSource::fetch_to_file`] wraps it so every
    /// error arm — a stream read, a write, the cap — leaves no partial `dest`.
    async fn stream_to_file(&self, url: &str, dest: &Path) -> Result<u64, FetchError> {
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| classify_send_error(url, &e))?;

        let status = response.status();
        if status.is_redirection() {
            // `Policy::none` does not chase the redirect (it could escape the
            // https-only gate); teach what happened rather than failing opaquely.
            // Permanent: the same request gets the same 3xx forever.
            return Err(FetchError::Permanent(format!(
                "{url}: registry redirected (HTTP {status}); fuzi fetches the resolved URL directly — regenerate the lockfile against a direct registry, or file an issue and we can add support"
            )));
        }
        if is_transient_client_status(status) {
            // The 4xx codes that mean "not now", not "never" — a rate limit or
            // a request timeout. Re-running is the retry.
            return Err(FetchError::Transport(format!(
                "{url}: HTTP {status} — the registry asked fuzi to back off; re-run later"
            )));
        }
        if status.is_client_error() {
            // Every other 4xx is the registry's definitive answer — a
            // yanked/renamed tarball (404), or auth fuzi does not implement
            // (401/403). Classing it transient would exit EX_TEMPFAIL "re-run to
            // retry" and send an agent obeying the taxonomy into an endless retry
            // loop.
            return Err(FetchError::Permanent(format!(
                "{url}: HTTP {status} — the registry will not serve this tarball; re-running will not help (regenerate the lockfile, or check registry credentials)"
            )));
        }
        if !status.is_success() {
            // 5xx and anything else non-2xx: the registry may recover.
            return Err(FetchError::Transport(format!("{url}: HTTP {status}")));
        }

        // Content-Length is a hint — reject an oversized body up front, but the
        // streaming counter below is the hard cap (the header may lie or be absent).
        if let Some(len) = response.content_length()
            && len > self.max_bytes
        {
            return Err(FetchError::TooLarge {
                got: len,
                max: self.max_bytes,
            });
        }

        let mut file = tokio::fs::File::create(dest)
            .await
            .map_err(|source| FetchError::Io {
                what: "create download temp",
                source,
            })?;
        let mut total: u64 = 0;
        loop {
            let chunk = response.chunk().await.map_err(|e| {
                FetchError::Transport(format!("stream read from {url} failed: {e}"))
            })?;
            let Some(chunk) = chunk else { break };
            total = total.saturating_add(chunk.len() as u64);
            if total > self.max_bytes {
                return Err(FetchError::TooLarge {
                    got: total,
                    max: self.max_bytes,
                });
            }
            file.write_all(&chunk)
                .await
                .map_err(|source| FetchError::Io {
                    what: "write download temp",
                    source,
                })?;
        }
        file.flush().await.map_err(|source| FetchError::Io {
            what: "flush download temp",
            source,
        })?;

        Ok(total)
    }
}

/// Sort a failed `send()` — no response arrived — into the TLS-certificate
/// class or the transient one.
///
/// A rejected server certificate is deterministic: the same chain checked
/// against the same trust fails the same way on every run, so exiting 75
/// "re-run to retry" would loop an agent. It is the machine's (or its proxy's)
/// trust that must change, so it becomes [`FetchError::TlsCertificate`] and
/// exits `EX_CONFIG` (78). Everything else here — refused connection, timeout,
/// reset, DNS — stays transient.
///
/// The residual: a DNS `NXDOMAIN` also stays transient. Through reqwest it is
/// indistinguishable from an offline resolver (both arrive as a connect error
/// with the resolver's message), and misreading "offline" as permanent would be
/// the worse error.
fn classify_send_error(url: &str, error: &reqwest::Error) -> FetchError {
    tls_certificate_rejection(error).map_or_else(
        || FetchError::Transport(format!("request to {url} failed: {error}")),
        |rejection| FetchError::TlsCertificate {
            host: url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
                .unwrap_or_else(|| url.to_owned()),
            reason: rejection.to_string(),
        },
    )
}

/// The rustls certificate verdict anywhere in `error`'s source chain.
///
/// Matched: [`rustls::Error::InvalidCertificate`] (expired, unknown issuer,
/// wrong name, revoked, bad signature …), [`rustls::Error::NoCertificatesPresented`],
/// and [`rustls::Error::InvalidCertRevocationList`] — each is fuzi's own
/// verdict on what the server presented, measured against local trust, and so
/// repeats on a re-run. Not matched: an alert the *peer* sent
/// (`AlertReceived`, possibly about its own state) and the negotiation
/// failures (`PeerIncompatible` / `PeerMisbehaved`), which are not a question
/// of trust and can be a middlebox's transient fault.
/// (`InvalidCertRevocationList` is unreachable today — fuzi configures no CRLs —
/// and is listed so a future CRL setup stays in the class.)
///
/// An [`std::io::Error`] link is followed through `get_ref()`, not
/// `source()`: `source()` skips the error it wraps (returning *that* error's
/// source), and the handshake failure reaches hyper as rustls's verdict inside
/// an `io::Error` inside another `io::Error` — a `source()` walk never sees it.
fn tls_certificate_rejection<'e>(
    error: &'e (dyn std::error::Error + 'static),
) -> Option<&'e rustls::Error> {
    let is_certificate = |e: &rustls::Error| {
        matches!(
            e,
            rustls::Error::InvalidCertificate(_)
                | rustls::Error::NoCertificatesPresented
                | rustls::Error::InvalidCertRevocationList(_)
        )
    };
    let mut link = Some(error);
    while let Some(e) = link {
        if let Some(tls) = e.downcast_ref::<rustls::Error>() {
            return is_certificate(tls).then_some(tls);
        }
        link = e.downcast_ref::<std::io::Error>().map_or_else(
            || e.source(),
            |io| {
                io.get_ref()
                    .map(|inner| -> &(dyn std::error::Error + 'static) { inner })
            },
        );
    }
    None
}

/// The 4xx statuses that are a registry's "not now" rather than its "never":
/// `408 Request Timeout` and `429 Too Many Requests` (a rate limit — the common
/// one on a cold install's burst of tarball fetches).
///
/// They take the transient class so the exit-code taxonomy's "re-run to retry"
/// stays true in both directions: a yanked tarball never loops an agent, and a
/// rate-limited one is not reported as a lockfile the user must change.
///
/// `425 Too Early` is deliberately **not** here. It refuses a request sent as
/// TLS 1.3 early data (0-RTT), and fuzi never sends any — reqwest leaves
/// `tls_early_data` off and this client does not turn it on — so a 425 is not
/// the replay refusal a re-run would clear: it is a registry or intermediary
/// answering a request it should not, and it takes the permanent class with
/// every other 4xx.
fn is_transient_client_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::TOO_MANY_REQUESTS
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpListener;

    /// Bind a loopback listener and answer exactly one HTTP request with
    /// `status_line` + `body`. Returns the base URL. No deps — same one-shot
    /// in-process server technique as `fuz_storage::forge` tests.
    async fn serve_once(status_line: &'static str, body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain the request head (we don't assert on it here).
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = format!(
                "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
            sock.flush().await.unwrap();
        });
        format!("http://{addr}")
    }

    /// Answer one request with a `301` redirect to `location` (no body).
    async fn serve_redirect_once(location: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut tmp = [0u8; 1024];
            let mut buf = Vec::new();
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = format!(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
        });
        format!("http://{addr}")
    }

    fn temp_dest() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("download.tgz");
        (dir, dest)
    }

    #[test]
    fn new_builds_a_client() {
        assert!(NpmTarballSource::new().is_ok());
    }

    #[tokio::test]
    async fn sends_a_fuzi_user_agent() {
        use std::sync::{Arc, Mutex};
        // Capture the request head so we can assert the UA fuzi sends.
        let captured = Arc::new(Mutex::new(String::new()));
        let cap = Arc::clone(&captured);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            *cap.lock().unwrap() = String::from_utf8_lossy(&buf).into_owned();
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx")
                .await
                .unwrap();
            sock.flush().await.unwrap();
        });
        let (_d, dest) = temp_dest();
        NpmTarballSource::new()
            .unwrap()
            .fetch_to_file(&format!("http://{addr}/foo.tgz"), &dest)
            .await
            .unwrap();
        let head = captured.lock().unwrap().to_lowercase();
        assert!(
            head.contains("user-agent: fuzi/"),
            "missing fuzi UA in: {head}"
        );
    }

    #[tokio::test]
    async fn redirect_is_refused() {
        // A registry that 302s the tarball: with `Policy::none` the redirect is
        // not chased (it could escape the https-only gate) — a teaching transport
        // error, not a silent follow.
        let base = serve_redirect_once("https://cdn.example.com/foo.tgz").await;
        let (_d, dest) = temp_dest();
        let source = NpmTarballSource::new().unwrap();

        let err = source
            .fetch_to_file(&format!("{base}/foo.tgz"), &dest)
            .await
            .unwrap_err();
        match err {
            FetchError::Permanent(msg) => assert!(msg.contains("redirected"), "{msg}"),
            other => panic!("expected Permanent, got {other:?}"),
        }
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn streams_body_to_file() {
        let body = b"the tarball bytes, streamed to disk";
        let base = serve_once("HTTP/1.1 200 OK", body).await;
        let (_d, dest) = temp_dest();
        let source = NpmTarballSource::new().unwrap();

        let n = source
            .fetch_to_file(&format!("{base}/foo.tgz"), &dest)
            .await
            .unwrap();
        assert_eq!(n, body.len() as u64);
        assert_eq!(std::fs::read(&dest).unwrap(), body);
    }

    #[tokio::test]
    async fn client_error_status_is_permanent() {
        // A 404 (yanked/renamed tarball) is the registry's definitive answer.
        // Classing it transient would exit EX_TEMPFAIL "re-run to retry" and
        // send an agent obeying the taxonomy into an endless retry loop.
        let base = serve_once("HTTP/1.1 404 Not Found", b"nope").await;
        let (_d, dest) = temp_dest();
        let source = NpmTarballSource::new().unwrap();

        let err = source
            .fetch_to_file(&format!("{base}/missing.tgz"), &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Permanent(_)), "{err:?}");
        assert!(err.is_permanent());
        // No temp file was created for a pre-stream failure.
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn server_error_status_stays_transient() {
        // 5xx is the arm that keeps its "re-run to retry" promise.
        let base = serve_once("HTTP/1.1 503 Service Unavailable", b"later").await;
        let (_d, dest) = temp_dest();
        let source = NpmTarballSource::new().unwrap();

        let err = source
            .fetch_to_file(&format!("{base}/flaky.tgz"), &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Transport(_)), "{err:?}");
        assert!(!err.is_permanent());
    }

    #[tokio::test]
    async fn rate_limit_and_retry_later_statuses_are_transient() {
        // A 429 on a cold install's burst of fetches is "not now", not a yanked
        // tarball: it must keep exit 75's "re-run to retry", not exit 65's
        // "change the lockfile". Same for 408.
        for status_line in [
            "HTTP/1.1 429 Too Many Requests",
            "HTTP/1.1 408 Request Timeout",
        ] {
            let base = serve_once(status_line, b"slow down").await;
            let (_d, dest) = temp_dest();
            let err = NpmTarballSource::new()
                .unwrap()
                .fetch_to_file(&format!("{base}/busy.tgz"), &dest)
                .await
                .unwrap_err();
            assert!(
                matches!(err, FetchError::Transport(_)),
                "{status_line}: {err:?}"
            );
            assert!(!err.is_permanent(), "{status_line}");
            assert!(err.to_string().contains("re-run later"), "{err}");
        }
    }

    #[tokio::test]
    async fn too_early_is_permanent() {
        // fuzi never sends 0-RTT early data, so a 425 is not a replay refusal a
        // re-run clears — it must not exit 75 "re-run to retry".
        let base = serve_once("HTTP/1.1 425 Too Early", b"too early").await;
        let (_d, dest) = temp_dest();
        let err = NpmTarballSource::new()
            .unwrap()
            .fetch_to_file(&format!("{base}/early.tgz"), &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Permanent(_)), "{err:?}");
        assert!(err.is_permanent());
    }

    #[tokio::test]
    async fn refused_redirect_is_permanent() {
        // The same request gets the same 3xx forever — retrying is pointless.
        let base = serve_redirect_once("https://cdn.example.com/foo.tgz").await;
        let (_d, dest) = temp_dest();
        let err = NpmTarballSource::new()
            .unwrap()
            .fetch_to_file(&format!("{base}/foo.tgz"), &dest)
            .await
            .unwrap_err();
        assert!(err.is_permanent(), "{err:?}");
    }

    /// Bind a loopback listener and answer exactly one request with `response`
    /// written verbatim — status line, headers, and body — then close. For the
    /// framings `serve_once` cannot express: chunked, close-delimited, a
    /// Content-Length the body does not honor, a `Content-Encoding`.
    async fn serve_raw_once(response: Vec<u8>) -> String {
        serve_raw_once_capturing(response).await.0
    }

    /// [`serve_raw_once`], also handing back the request head fuzi sent.
    async fn serve_raw_once_capturing(
        response: Vec<u8>,
    ) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (head_tx, head_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = head_tx.send(String::from_utf8_lossy(&buf).into_owned());
            // The client may hang up mid-body (the cap tripping): not an error.
            let _ = sock.write_all(&response).await;
            let _ = sock.flush().await;
            // Dropping the socket closes it: the end of a close-delimited body.
        });
        (format!("http://{addr}"), head_rx)
    }

    #[tokio::test]
    async fn body_shorter_than_content_length_is_transient_and_leaves_no_dest() {
        // The connection drops after 4 of the 100 announced bytes: a mid-stream
        // transport failure (re-run retries), and the partial temp is removed by
        // the source itself.
        let base = serve_raw_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec(),
        )
        .await;
        let (_d, dest) = temp_dest();
        let err = NpmTarballSource::new()
            .unwrap()
            .fetch_to_file(&format!("{base}/cut.tgz"), &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Transport(_)), "{err:?}");
        assert!(!err.is_permanent());
        assert!(!dest.exists(), "the partial download must be removed");
    }

    /// A source with a tiny cap (no TLS involved: the tests serve plain http).
    fn capped_source(max_bytes: u64) -> NpmTarballSource {
        fuz_sys::tls::ensure_crypto_provider();
        NpmTarballSource::with_cap(
            reqwest::Client::builder()
                .redirect(redirect::Policy::none())
                .build()
                .unwrap(),
            max_bytes,
        )
    }

    #[tokio::test]
    async fn chunked_body_over_the_cap_trips_the_streaming_counter() {
        // No Content-Length to pre-reject on: only the streaming counter stands
        // between an endless body and the disk. Two 6-byte chunks against an
        // 8-byte cap.
        let base = serve_raw_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n6\r\nghijkl\r\n0\r\n\r\n"
                .to_vec(),
        )
        .await;
        let (_d, dest) = temp_dest();
        let err = capped_source(8)
            .fetch_to_file(&format!("{base}/big.tgz"), &dest)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::TooLarge { max: 8, .. }),
            "{err:?}"
        );
        assert!(err.is_permanent());
        assert!(!dest.exists(), "the partial download must be removed");
    }

    #[tokio::test]
    async fn close_delimited_body_over_the_cap_trips_the_streaming_counter() {
        // HTTP/1.0-style framing: no length, no chunking, the body ends when
        // the server closes. The counter is the only bound.
        let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(&[b'x'; 64]);
        let base = serve_raw_once(response).await;
        let (_d, dest) = temp_dest();
        let err = capped_source(16)
            .fetch_to_file(&format!("{base}/big.tgz"), &dest)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::TooLarge { max: 16, .. }),
            "{err:?}"
        );
        assert!(!dest.exists(), "the partial download must be removed");
    }

    #[tokio::test]
    async fn content_encoded_body_is_kept_raw() {
        // The lockfile's sha512 is over the bytes as served. A body marked
        // `Content-Encoding: gzip` must land byte-for-byte — never decoded —
        // and fuzi must not ask for an encoding in the first place.
        let raw = {
            use std::io::Write as _;
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(b"a tarball that is already gzip").unwrap();
            gz.finish().unwrap()
        };
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            raw.len()
        )
        .into_bytes();
        response.extend_from_slice(&raw);
        let (base, head) = serve_raw_once_capturing(response).await;
        let (_d, dest) = temp_dest();
        let n = NpmTarballSource::new()
            .unwrap()
            .fetch_to_file(&format!("{base}/foo.tgz"), &dest)
            .await
            .unwrap();
        assert_eq!(n, raw.len() as u64);
        let landed = std::fs::read(&dest).unwrap();
        assert_eq!(landed, raw, "the transferred bytes, not their decoding");
        // So the lockfile hash, taken over the served bytes, still matches.
        assert_eq!(
            crate::test_support::sha512_sri(&landed),
            crate::test_support::sha512_sri(&raw)
        );
        let head = head.await.unwrap().to_lowercase();
        assert!(!head.contains("accept-encoding"), "{head}");
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let body = b"0123456789"; // 10 bytes
        let base = serve_once("HTTP/1.1 200 OK", body).await;
        let (_d, dest) = temp_dest();
        // Cap of 2 bytes — the Content-Length hint trips it.
        fuz_sys::tls::ensure_crypto_provider();
        let source = NpmTarballSource::with_cap(reqwest::Client::new(), 2);

        let err = source
            .fetch_to_file(&format!("{base}/big.tgz"), &dest)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::TooLarge { max: 2, .. }));
    }

    /// A throwaway self-signed `localhost` certificate (P-256, valid until
    /// 2126) and its PKCS#8 key, DER as hex — test-only, trusted by nothing.
    ///
    /// Regenerate: `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256
    /// -nodes -days 36500 -subj /CN=localhost -addext subjectAltName=DNS:localhost
    /// -keyout k.pem -out c.pem`, then `openssl x509 -in c.pem -outform der | xxd
    /// -p` and `openssl pkcs8 -topk8 -nocrypt -in k.pem -outform der | xxd -p`.
    const SELF_SIGNED_CERT_HEX: &str = concat!(
        "308201963082013ba00302010202143c8da2bc739d233fa19b8f95bfef10d2d38cfbda300a06082a",
        "8648ce3d04030230143112301006035504030c096c6f63616c686f73743020170d32363130323832",
        "33323533355a180f32313236313030343233323533355a30143112301006035504030c096c6f6361",
        "6c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200045d7dc4c3e6efc4d9",
        "cc17d06ba38eaf3e3dfa07b49770636824874eda2781319047feb7c0c9ae615fbbd52b27ce4217f2",
        "c8b54ef04f08352db05ab831689e3796a3693067301d0603551d0e04160414a487706b627be45120",
        "90c7ac387c2d806b0e7079301f0603551d23041830168014a487706b627be4512090c7ac387c2d80",
        "6b0e7079300f0603551d130101ff040530030101ff30140603551d11040d300b82096c6f63616c68",
        "6f7374300a06082a8648ce3d0403020349003046022100cda0ac13abdbfd8e145147236f95a7e108",
        "6878bffae3c2386f6536da06e6daf6022100e51bd656c490e114536b60ccb24f72fbb0102c6faba2",
        "df5e4d56aa8b9a077789",
    );
    const SELF_SIGNED_KEY_HEX: &str = concat!(
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420c3a8c3d6",
        "4e85219f8f0ef898b65202bd5d395e21419a6f58c6b06259ecd51277a144034200045d7dc4c3e6ef",
        "c4d9cc17d06ba38eaf3e3dfa07b49770636824874eda2781319047feb7c0c9ae615fbbd52b27ce42",
        "17f2c8b54ef04f08352db05ab831689e3796",
    );

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Serve one TLS handshake on loopback with the self-signed certificate —
    /// a registry whose chain this machine does not trust. Returns the port.
    fn serve_untrusted_tls_once() -> u16 {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        fuz_sys::tls::ensure_crypto_provider();
        let config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(from_hex(SELF_SIGNED_CERT_HEX))],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(from_hex(SELF_SIGNED_KEY_HEX))),
                )
                .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(config).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            // Drives the handshake until the client aborts on the certificate.
            let _ = std::io::Read::read(&mut tls, &mut [0u8; 64]);
        });
        port
    }

    #[tokio::test]
    async fn untrusted_certificate_is_a_tls_certificate_error_not_transient() {
        // The same chain fails the same trust on every run: exiting 75 "re-run
        // to retry" would loop an agent, so the verdict is lifted out of the
        // transport class with the host it names.
        let port = serve_untrusted_tls_once();
        let (_d, dest) = temp_dest();
        let err = NpmTarballSource::new()
            .unwrap()
            .fetch_to_file(&format!("https://localhost:{port}/foo.tgz"), &dest)
            .await
            .unwrap_err();
        match &err {
            FetchError::TlsCertificate { host, reason } => {
                assert_eq!(host, "localhost");
                assert!(reason.contains("certificate"), "{reason}");
            }
            other => panic!("expected TlsCertificate, got {other:?}"),
        }
        assert!(!dest.exists());
    }

    #[test]
    fn certificate_verdicts_are_found_through_a_wrapping_io_error() {
        // `io::Error::source` skips the error it wraps, which is how rustls's
        // verdict travels — the walk must open each `io::Error` itself.
        // The shape reqwest produces: rustls inside `io::Error` inside `io::Error`.
        let wrapped = std::io::Error::other(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
        ));
        let outer = Outer(wrapped);
        assert!(matches!(
            tls_certificate_rejection(&outer),
            Some(rustls::Error::InvalidCertificate(_))
        ));
        // A non-certificate TLS failure stays out of the class (transient).
        let other = Outer(std::io::Error::other(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        )));
        assert!(tls_certificate_rejection(&other).is_none());
        let plain = Outer(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert!(tls_certificate_rejection(&plain).is_none());
    }

    /// One link of wrapping above an `io::Error`, as hyper's connect error is.
    #[derive(Debug)]
    struct Outer(std::io::Error);

    impl std::fmt::Display for Outer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("connect error")
        }
    }

    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }
}
