//! Host verification — refusing requests addressed to a name the server
//! doesn't answer to, which is how DNS rebinding reaches a loopback server.
//!
//! In a rebinding attack, a page on an attacker's domain re-resolves that
//! domain to `127.0.0.1` and talks to the local server **same-origin**: its
//! GETs carry no `Origin` header, so the [`crate::origin_layer`] allowlist
//! doesn't apply. The `Host` header gives it away — the browser sets it from
//! the URL, so it names the attacker's domain, never `localhost`.
//!
//! A host is allowed when its name is loopback (`localhost`, `127.0.0.0/8`,
//! `[::1]`), at any port — a rebinding page can't put one of those in `Host`
//! — or when an allowed origin names it (the allowlist is where the
//! server's UI is served from, so its hosts are the server's own names).
//! Matching reuses the origin pattern syntax, so `http://localhost:*` or
//! `https://*.fuz.dev` admit the hosts they'd admit as origins.
//!
//! A request without a `Host` header passes: browsers always send one, so
//! its absence means a non-browser client, which the auth stack governs. An
//! h2c prior-knowledge request carries no `Host` (only `:authority`), so it
//! passes too — no browser speaks h2c. A request with more than one `Host`
//! is refused (RFC 9112 §3.2).

use std::net::IpAddr;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::origin::AllowedOrigins;

/// Canonical error reason for a host rejection.
pub const FORBIDDEN_HOST_REASON: &str = "forbidden_host";

/// Build the canonical host-rejection response: `403` + the flat
/// `{"error": "forbidden_host"}` REST body.
#[must_use]
pub fn forbidden_host_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": FORBIDDEN_HOST_REASON })),
    )
        .into_response()
}

/// True when `host` (a `Host` header value, `name[:port]`) names a loopback
/// address: `localhost`, an IPv4 address in `127.0.0.0/8`, or `[::1]`.
///
/// Anything after the name but a `:` and a port (decimal digits, at most
/// 65535) makes it not loopback: `[::1]junk`, `localhost:abc`, and
/// `localhost: 1` are refused.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    let (name, rest) = if host.starts_with('[') {
        match host.find(']') {
            Some(end) => host.split_at(end + 1),
            None => return false,
        }
    } else {
        host.rfind(':')
            .map_or((host, ""), |colon| host.split_at(colon))
    };
    let port_is_valid = rest.is_empty()
        || rest.strip_prefix(':').is_some_and(|port| {
            !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && port.parse::<u16>().is_ok()
        });
    if !port_is_valid {
        return false;
    }
    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let ip = name
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(name);
    ip.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl AllowedOrigins {
    /// Check a literal `Host` header value: loopback, or named by an allowed
    /// origin pattern on either scheme.
    #[must_use]
    pub fn allows_host(&self, host: &str) -> bool {
        if is_loopback_host(host) {
            return true;
        }
        // a `Host` can't hold these, and they'd change how the origin parses
        if host.is_empty() || host.contains(['/', '?', '#', '@']) {
            return false;
        }
        ["http://", "https://"]
            .iter()
            .any(|scheme| self.allows(&format!("{scheme}{host}")))
    }

    /// Host check for a request — true when there's no `Host` header or one
    /// that passes [`allows_host`](Self::allows_host). A `Host` that isn't
    /// visible ASCII is refused, and so is more than one `Host` (RFC 9112
    /// §3.2).
    #[must_use]
    pub fn allows_request_host(&self, headers: &HeaderMap) -> bool {
        let mut hosts = headers.get_all(header::HOST).iter();
        match (hosts.next(), hosts.next()) {
            (None, _) => true,
            (Some(value), None) => value.to_str().is_ok_and(|host| self.allows_host(host)),
            (Some(_), Some(_)) => false,
        }
    }
}

/// axum middleware enforcing [`AllowedOrigins::allows_request_host`],
/// refusing with `403`.
///
/// Off by default: [`crate::compose_stack`] mounts it in every route group,
/// over [`StackOptions::allowed_origins`](crate::StackOptions::allowed_origins)
/// (the allowlist the origin check reads), when
/// [`StackOptions::host_gate`](crate::StackOptions::host_gate) is set — which
/// a server answering on loopback should do.
pub async fn host_layer(
    State(allowed): State<AllowedOrigins>,
    req: Request,
    next: Next,
) -> Response {
    if !allowed.allows_request_host(req.headers()) {
        return forbidden_host_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(values: &[&str]) -> AllowedOrigins {
        AllowedOrigins::parse(&values.join(",")).expect("valid allowlist")
    }

    #[test]
    fn loopback_hosts_pass_at_any_port() {
        for host in [
            "localhost",
            "localhost:4460",
            "LOCALHOST:5173",
            "127.0.0.1",
            "127.0.0.1:4460",
            "127.1.2.3:80",
            "[::1]",
            "[::1]:4460",
        ] {
            assert!(
                patterns(&["https://app.example.com"]).allows_host(host),
                "{host}"
            );
        }
    }

    #[test]
    fn loopback_hosts_with_trailing_junk_are_not_loopback() {
        for host in [
            "[::1]junk",
            "[::1]:",
            "[::1]:abc",
            "[::1",
            "localhost:abc",
            "localhost: 1",
            "localhost:",
            "localhost:+1",
            "localhost:65536",
            "127.0.0.1:4460x",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
        // a valid optional port still counts
        for host in ["localhost", "localhost:65535", "[::1]:1", "127.0.0.1:80"] {
            assert!(is_loopback_host(host), "{host}");
        }
    }

    #[test]
    fn other_hosts_fail_without_a_matching_origin() {
        let allowed = patterns(&["http://localhost:4460"]);
        for host in [
            "evil.example.com",
            "evil.example.com:4460",
            "localhost.evil.example.com:4460",
            "127.0.0.1.nip.io:4460",
            "0.0.0.0:4460",
            "[::ffff:127.0.0.1]:4460",
            "10.0.0.1:4460",
            "",
        ] {
            assert!(!allowed.allows_host(host), "{host}");
        }
    }

    #[test]
    fn hosts_named_by_allowed_origins_pass() {
        let allowed = patterns(&["https://zzz.example.com", "http://*.fuz.dev:*"]);
        assert!(allowed.allows_host("zzz.example.com"));
        assert!(allowed.allows_host("ZZZ.example.com"));
        assert!(allowed.allows_host("api.fuz.dev:8080"));
        assert!(!allowed.allows_host("zzz.example.com:8443"));
        assert!(!allowed.allows_host("fuz.dev"));
    }

    #[test]
    fn hosts_that_would_reshape_the_origin_fail() {
        let allowed = patterns(&["http://localhost:*", "https://zzz.example.com"]);
        assert!(!allowed.allows_host("evil.example.com@zzz.example.com"));
        assert!(!allowed.allows_host("zzz.example.com/x"));
    }

    #[test]
    fn request_without_host_passes() {
        assert!(patterns(&["https://app.example.com"]).allows_request_host(&HeaderMap::new()));
    }

    #[test]
    fn request_with_foreign_host_fails() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "rebind.example.com:4460".parse().unwrap());
        assert!(!patterns(&["http://localhost:4460"]).allows_request_host(&headers));
        headers.insert(header::HOST, "localhost:4460".parse().unwrap());
        assert!(patterns(&["http://localhost:4460"]).allows_request_host(&headers));
    }

    #[test]
    fn request_with_two_hosts_fails() {
        let allowed = patterns(&["http://localhost:4460"]);
        let mut headers = HeaderMap::new();
        headers.append(header::HOST, "localhost:4460".parse().unwrap());
        headers.append(header::HOST, "localhost:4460".parse().unwrap());
        assert!(!allowed.allows_request_host(&headers));
        let mut headers = HeaderMap::new();
        headers.append(header::HOST, "localhost:4460".parse().unwrap());
        headers.append(header::HOST, "rebind.example.com".parse().unwrap());
        assert!(!allowed.allows_request_host(&headers));
    }
}
