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
//!
//! The gate is on by default ([`crate::StackOptions::new`]). A refusal is
//! said in the log as well as answered: the first in each
//! [`HOST_REFUSAL_WARN_INTERVAL`] is a warning naming the refused `Host`
//! (quoted ASCII-only and truncated, since the client wrote it) and the env
//! var that lists the server's names, with a count of the refusals the
//! interval held back. The response says neither, so a client learns nothing
//! about the allowlist.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use fuz_sys::text::{quoted, truncate};

use crate::origin::AllowedOrigins;

/// The shortest gap between two refusal warnings; the refusals between are
/// counted and reported with the next one.
pub const HOST_REFUSAL_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// The longest excerpt of a refused `Host` a warning quotes.
const HOST_EXCERPT_MAX: usize = 200;

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

    /// Host check for a request's `Host` header values — true when there are
    /// none or one that passes [`allows_host`](Self::allows_host). A value
    /// that isn't visible ASCII (a tab and the space allowed, as in a header
    /// value) is refused, and so is more than one `Host` (RFC 9112 §3.2).
    /// Twin of the TS `allows_request_hosts`.
    #[must_use]
    pub fn allows_request_hosts(&self, hosts: &[&str]) -> bool {
        match hosts {
            [] => true,
            [host] => is_header_text(host) && self.allows_host(host),
            _ => false,
        }
    }

    /// [`allows_request_hosts`](Self::allows_request_hosts) over a request's
    /// headers; a `Host` value that isn't text is refused.
    #[must_use]
    pub fn allows_request_host(&self, headers: &HeaderMap) -> bool {
        let mut hosts = headers.get_all(header::HOST).iter();
        match (hosts.next(), hosts.next()) {
            (None, _) => true,
            (Some(value), None) => value
                .to_str()
                .is_ok_and(|host| self.allows_request_hosts(&[host])),
            (Some(_), Some(_)) => false,
        }
    }
}

/// True when every char is visible ASCII, the space, or a tab — what
/// `HeaderValue::to_str` admits.
fn is_header_text(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
}

/// Counts refusals between warnings, so a flood of foreign `Host`s writes one
/// line per [`HOST_REFUSAL_WARN_INTERVAL`] and holds no per-host state.
#[derive(Debug, Default)]
struct RefusalWarnings {
    state: Mutex<RefusalWarningState>,
}

#[derive(Debug, Default)]
struct RefusalWarningState {
    last_warned: Option<Instant>,
    held_back: u64,
}

impl RefusalWarnings {
    /// Record a refusal at `now`: `Some(held_back)` when it is warned (the
    /// refusals held back since the last warning), `None` when it is held
    /// back itself.
    fn note(&self, now: Instant) -> Option<u64> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let due = state
            .last_warned
            .is_none_or(|last| now.saturating_duration_since(last) >= HOST_REFUSAL_WARN_INTERVAL);
        if due {
            state.last_warned = Some(now);
            Some(std::mem::take(&mut state.held_back))
        } else {
            state.held_back = state.held_back.saturating_add(1);
            None
        }
    }
}

/// The host gate's state: the allowlist it reads, the env var that carries
/// it (named in the refusal warning), and the warning's rate limit.
#[derive(Debug, Clone)]
pub struct HostGate {
    allowed: AllowedOrigins,
    allowed_origins_var: &'static str,
    warnings: Arc<RefusalWarnings>,
}

impl HostGate {
    /// A gate over `allowed`, its refusal warning naming `allowed_origins_var`.
    #[must_use]
    pub fn new(allowed: AllowedOrigins, allowed_origins_var: &'static str) -> Self {
        Self {
            allowed,
            allowed_origins_var,
            warnings: Arc::default(),
        }
    }
}

/// The refusal warning's text. Twin of the TS `format_host_refusal_warning`.
///
/// `host` is the refused `Host` as the request carried it — several values
/// joined with `, `, the way a fetch `Headers` joins them.
#[must_use]
pub fn format_host_refusal_warning(
    host: &str,
    allowed_origins_var: &str,
    held_back: u64,
) -> String {
    let held_back = if held_back == 0 {
        String::new()
    } else {
        format!(" ({held_back} more refused since the last warning)")
    };
    format!(
        "host gate refused a request for Host {}{held_back}: the server answers only to \
         loopback names and the hosts {allowed_origins_var} names. If it should answer to \
         this name, add the origin it is served from to {allowed_origins_var}",
        quoted(&truncate(host, HOST_EXCERPT_MAX))
    )
}

/// axum middleware enforcing [`AllowedOrigins::allows_request_host`],
/// refusing with `403` and warning (rate-limited, module doc).
///
/// On by default: [`crate::compose_stack`] mounts it in every route group,
/// over [`StackOptions::allowed_origins`](crate::StackOptions::allowed_origins)
/// (the allowlist the origin check reads), unless
/// [`StackOptions::host_gate`](crate::StackOptions::host_gate) is cleared.
pub async fn host_layer(State(gate): State<HostGate>, req: Request, next: Next) -> Response {
    if !gate.allowed.allows_request_host(req.headers()) {
        if let Some(held_back) = gate.warnings.note(Instant::now()) {
            let host = req
                .headers()
                .get_all(header::HOST)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join(", ");
            tracing::warn!(
                "{}",
                format_host_refusal_warning(&host, gate.allowed_origins_var, held_back)
            );
        }
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
    fn host_values_outside_header_text_fail() {
        let allowed = patterns(&["http://localhost:*"]);
        assert!(allowed.allows_request_hosts(&[]));
        assert!(allowed.allows_request_hosts(&["localhost:4460"]));
        assert!(!allowed.allows_request_hosts(&["localhost\u{0}"]));
        assert!(!allowed.allows_request_hosts(&["localhost\u{7f}"]));
        assert!(!allowed.allows_request_hosts(&["localhost", "localhost"]));
    }

    #[test]
    fn refusal_warnings_are_rate_limited() {
        let warnings = RefusalWarnings::default();
        let start = Instant::now();
        assert_eq!(warnings.note(start), Some(0));
        assert_eq!(warnings.note(start + Duration::from_secs(1)), None);
        assert_eq!(warnings.note(start + Duration::from_secs(2)), None);
        assert_eq!(warnings.note(start + HOST_REFUSAL_WARN_INTERVAL), Some(2));
        assert_eq!(
            warnings.note(start + HOST_REFUSAL_WARN_INTERVAL + Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn refusal_warning_quotes_the_host() {
        let text = format_host_refusal_warning("evil\u{1b}.example", "FUZ_ALLOWED_ORIGINS", 0);
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(text.contains("FUZ_ALLOWED_ORIGINS"), "{text}");
        assert!(!text.contains("more refused"), "{text}");
        let text = format_host_refusal_warning(&"a".repeat(500), "X", 3);
        assert!(text.len() < 500, "{text}");
        assert!(
            text.contains("(3 more refused since the last warning)"),
            "{text}"
        );
    }

    #[test]
    fn refusal_warning_whole_text_matches_the_ts_twin() {
        assert_eq!(
            format_host_refusal_warning("rebind.example", "FUZ_ALLOWED_ORIGINS", 0),
            "host gate refused a request for Host \"rebind.example\": the server answers only to \
             loopback names and the hosts FUZ_ALLOWED_ORIGINS names. If it should answer to this \
             name, add the origin it is served from to FUZ_ALLOWED_ORIGINS"
        );
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
