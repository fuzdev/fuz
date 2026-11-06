//! The `reqwest` client policy shared by the HTTP backends (`ForgeStorage`,
//! `HttpsStorage`) and the forge's CLI (`fuzf`).
//!
//! Each starts its client from [`client_builder`] — the three forge clients
//! (`ForgeStorage`'s read and write clients and `fuzf`'s) through
//! [`crate::forge_client_builder`] — so a hostile or misconfigured host meets
//! one policy whichever client talks to it. The module is crate-private;
//! outside the crate the policy is reached through `forge_client_builder`,
//! with [`Redirects`] re-exported at the crate root. The policy reads the base's [`BaseUrl::is_https`] — the loopback decision
//! `base_url` makes once — and covers:
//!
//! - **Proxies.** A loopback `http` base bypasses the environment's proxies,
//!   so its plaintext request — and the forge's bearer token — never leaves
//!   the machine. An `https` base keeps them; they tunnel the TLS stream
//!   without seeing inside it.
//! - **Scheme.** An `https` base gets an `https_only` client, which cannot
//!   issue a plaintext request at all — the belt to the redirect rule's braces.
//! - **Redirects.** Chosen per client ([`Redirects`]). A following client
//!   takes up to [`MAX_REDIRECTS`] hops, each vetted by [`check_redirect`]: an
//!   `https` URL is never redirected onto `http`, and a loopback `http` URL
//!   never leaves loopback in plaintext. A refusing client — the forge's
//!   writes — takes none.
//! - **Referer.** Never sent, so a redirect target does not learn the URL it
//!   was redirected from.
//!
//! Timeouts are each backend's own; they differ by what the backend serves.

use crate::base_url::{BaseUrl, has_userinfo, is_loopback_host};

/// Redirect hops followed per request before the request fails.
pub const MAX_REDIRECTS: usize = 5;

/// Why a redirect hop is refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RedirectRefusal {
    #[error("too many redirects (limit {MAX_REDIRECTS})")]
    TooMany,
    #[error("redirect loop")]
    Loop,
    #[error("redirect to a non-https URL refused")]
    InsecureScheme,
    #[error("redirect to a URL carrying credentials refused")]
    Credentials,
}

/// Whether a client follows redirects at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redirects {
    /// Follow each hop `check_redirect` allows — for reads.
    Follow,
    /// Follow none: a `3xx` answer is returned as the response. For writes,
    /// where following can turn the request into a `GET` (`301`/`302` on a
    /// `POST`, `303` on anything) that succeeds without anything written, or
    /// replay the body to another origin (`307`/`308`).
    Refuse,
}

/// A client builder carrying the shared policy (see the module doc) for a
/// backend rooted at `base`. The caller adds its timeouts and builds.
pub fn client_builder(base: &BaseUrl, redirects: Redirects) -> reqwest::ClientBuilder {
    fuz_sys::tls::ensure_crypto_provider();
    let mut builder = reqwest::Client::builder();
    if !base.is_https {
        builder = builder.no_proxy();
    }
    let policy = match redirects {
        Redirects::Follow => reqwest::redirect::Policy::custom(|attempt| {
            match check_redirect(attempt.previous(), attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(refusal) => attempt.error(refusal),
            }
        }),
        Redirects::Refuse => reqwest::redirect::Policy::none(),
    };
    builder
        .https_only(base.is_https)
        .referer(false)
        .redirect(policy)
}

/// Decide whether a redirect to `next` may be followed.
///
/// `previous` is the chain so far, the original request URL first. The rules:
///
/// - at most [`MAX_REDIRECTS`] hops, and never back to a URL already visited;
/// - an `https` target is always acceptable — a host commonly redirects to a
///   different `https` origin (a CDN, an object store);
/// - an `http` target is followed only when the URL being redirected *from*
///   is itself `http` and the target host is loopback. A plaintext request
///   exists only as the loopback carve-out, so this lets a local server
///   redirect within loopback and nothing else: an `https` URL never
///   redirects to `http` (not even to loopback), and a loopback `http` URL
///   never redirects to a remote `http` host;
/// - a target carrying userinfo is refused, since following it would send
///   credentials the host chose.
pub fn check_redirect(previous: &[url::Url], next: &url::Url) -> Result<(), RedirectRefusal> {
    if previous.len() > MAX_REDIRECTS {
        return Err(RedirectRefusal::TooMany);
    }
    if previous.contains(next) {
        return Err(RedirectRefusal::Loop);
    }
    let from_plaintext = previous.last().is_some_and(|url| url.scheme() == "http");
    match next.scheme() {
        "https" => {}
        "http" if from_plaintext && is_loopback_host(next) => {}
        _ => return Err(RedirectRefusal::InsecureScheme),
    }
    if has_userinfo(next) {
        return Err(RedirectRefusal::Credentials);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        s.parse().expect("test url")
    }

    #[test]
    fn redirect_follows_https_targets() {
        let from = [url("https://example.com/latest.json")];
        assert_eq!(
            check_redirect(&from, &url("https://cdn.example.net/x/latest.json")),
            Ok(())
        );
        // the loopback carve-out may be redirected up to https
        let local = [url("http://127.0.0.1:4041/latest.json")];
        assert_eq!(
            check_redirect(&local, &url("https://example.com/latest.json")),
            Ok(())
        );
    }

    #[test]
    fn redirect_never_downgrades_https_to_http() {
        let from = [url("https://example.com/latest.json")];
        for next in [
            "http://example.com/latest.json",
            // not even to loopback: an https base has no plaintext carve-out
            "http://127.0.0.1/latest.json",
            "http://localhost/latest.json",
            "ftp://example.com/latest.json",
        ] {
            assert_eq!(
                check_redirect(&from, &url(next)),
                Err(RedirectRefusal::InsecureScheme),
                "{next}"
            );
        }
        // a chain that reached https stays there, even one that began on
        // loopback http
        let chain = [
            url("http://127.0.0.1:4041/latest.json"),
            url("https://example.com/latest.json"),
        ];
        assert_eq!(
            check_redirect(&chain, &url("http://127.0.0.1:4041/other.json")),
            Err(RedirectRefusal::InsecureScheme)
        );
    }

    #[test]
    fn redirect_keeps_loopback_http_on_loopback() {
        let from = [url("http://127.0.0.1:4041/latest.json")];
        assert_eq!(
            check_redirect(&from, &url("http://localhost:4042/moved.json")),
            Ok(())
        );
        for next in [
            "http://example.com/latest.json",
            // in 127.0.0.0/8 but not the loopback carve-out's exact address
            "http://127.0.0.2/latest.json",
        ] {
            assert_eq!(
                check_redirect(&from, &url(next)),
                Err(RedirectRefusal::InsecureScheme),
                "{next}"
            );
        }
    }

    #[test]
    fn redirect_refuses_loops_overruns_and_credentials() {
        let from = [url("https://example.com/a"), url("https://example.com/b")];
        assert_eq!(
            check_redirect(&from, &url("https://example.com/a")),
            Err(RedirectRefusal::Loop)
        );
        assert_eq!(
            check_redirect(&from, &url("https://user:pw@example.com/c")),
            Err(RedirectRefusal::Credentials)
        );

        // `previous` holds the original URL plus one entry per hop followed.
        let chain = |hops: usize| -> Vec<url::Url> {
            (0..=hops)
                .map(|n| url(&format!("https://example.com/{n}")))
                .collect()
        };
        let next = url("https://example.com/next");
        assert_eq!(check_redirect(&chain(MAX_REDIRECTS - 1), &next), Ok(()));
        assert_eq!(
            check_redirect(&chain(MAX_REDIRECTS), &next),
            Err(RedirectRefusal::TooMany)
        );
    }
}
