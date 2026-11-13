//! `X-Forwarded-For` resolution + `ClientIp` extension + axum middleware.
//!
//! Split from the monolithic proxy lift so the resolution algorithm
//! (pure, easy to fuzz) is testable without booting axum, while the
//! middleware shape (axum-aware) lives in one focused file.
//!
//! ## Discrete state
//!
//! Middleware takes `State<Arc<Vec<ParsedProxy>>>` directly. **No `App`
//! coupling** — the proxy set is
//! [`StackOptions::trusted_proxies`](crate::StackOptions::trusted_proxies),
//! independent of the consumer's app struct.
//!
//! ## Mount ordering
//!
//! [`crate::compose_stack`] mounts this middleware innermost in every route
//! group, the fallback included, so every handler sees `ClientIp`. The
//! middleware always populates it — even when `trusted_proxies` is empty,
//! every connection's TCP peer IP fails `is_trusted_ip` so the XFF header is
//! ignored and `ClientIp` carries the normalized connection IP (preserving
//! direct-bind deployment behavior). A router driven outside the stack (a
//! test exercising a handler alone) has no `ClientIp` extension; readers
//! that tolerate that fall back to [`UNRESOLVED_CLIENT_IP`].

use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;

use crate::ip_canonical::{normalize_ip, validate_ip_strict};
use crate::parsed_proxy::ParsedProxy;
use crate::proxy::is_trusted_ip;

/// Resolved client IP, stored in `request.extensions()` by
/// [`client_ip_middleware`].
///
/// Handlers read it via the `Extension` extractor — as
/// `Option<Extension<ClientIp>>` where the router may run without the
/// middleware, read through [`ClientIp::from_extension`] or
/// [`ClientIp::as_str_or_unresolved`]. Always populated when the middleware
/// runs.
#[derive(Debug, Clone)]
pub struct ClientIp(pub String);

impl ClientIp {
    /// Borrow the resolved address out of an optional `Extension` extractor —
    /// `None` when the extension is absent (the middleware isn't mounted).
    #[must_use]
    pub fn from_extension(ext: Option<&Extension<Self>>) -> Option<&str> {
        ext.map(|Extension(Self(ip))| ip.as_str())
    }

    /// Borrow the resolved address out of an optional `Extension` extractor,
    /// substituting [`UNRESOLVED_CLIENT_IP`] when it is absent — the twin's
    /// `get_client_ip` value when nothing resolved, so an unresolved caller
    /// shares one rate-limit bucket and one audit rendering rather than an
    /// empty string.
    #[must_use]
    pub fn as_str_or_unresolved(ext: Option<&Extension<Self>>) -> &str {
        Self::from_extension(ext).unwrap_or(UNRESOLVED_CLIENT_IP)
    }
}

/// Bucket key standing in for a client IP that did not resolve.
///
/// [`client_ip_middleware`] always produces an address, so this is reached
/// only where the middleware is not mounted — a bare router, an in-process
/// test harness, a transport that carries no peer. The twin has the same hole
/// and fills it the same way: `fuz_app`'s `get_client_ip` reads
/// `c.get('client_ip') || 'unknown'`, so its rate limiters bucket an
/// unresolved caller under this literal rather than skipping the gate.
/// Sharing one bucket is the fail-closed answer — the alternative is an
/// unthrottled path.
pub const UNRESOLVED_CLIENT_IP: &str = "unknown";

/// Resolve the real client IP from an `X-Forwarded-For` header value.
///
/// Walks right-to-left, skipping trusted-proxy entries. The first untrusted
/// entry is the client IP. The walk **stops** at the first entry that fails
/// strict IP validation and returns `None`, so the middleware falls back to
/// the connection IP: an entry is only as trustworthy as the hop that wrote
/// it, and everything left of a malformed one was written before any trusted
/// hop vouched for it. If every entry is trusted, returns the leftmost one
/// (the middleware warns: likely misconfiguration). Empty entries (`a,,b`, a
/// blank header) are dropped before the walk; each entry is trimmed of JS
/// whitespace ([`crate::trim_js_whitespace`]), as the twin's `trim` does.
///
/// Stopping, not skipping, is the rate-limit-key rule. Returning a malformed
/// entry would let an attacker rotate arbitrary strings into fresh per-IP
/// buckets; skipping it and walking on would hand the key to the entry the
/// client wrote whenever a trusted hop appends a non-bare-IP token (`ip:port`,
/// `[v6]:port`, `unknown`, `unix:`). Tradeoff: behind such a proxy every
/// client collapses to the proxy's connection IP in rate limiting. Standard
/// proxies (nginx's `$remote_addr`, cloud LBs) append bare IPs.
#[must_use]
pub fn resolve_client_ip(forwarded_for: &str, proxies: &[ParsedProxy]) -> Option<String> {
    let entries: Vec<String> = forwarded_for
        .split(',')
        .filter_map(|raw| {
            let trimmed = crate::trim_js_whitespace(raw);
            if trimmed.is_empty() {
                None
            } else {
                Some(normalize_ip(trimmed))
            }
        })
        .collect();
    if entries.is_empty() {
        return None;
    }

    for entry in entries.iter().rev() {
        // a malformed entry stops the walk: `None`, the connection IP
        validate_ip_strict(entry)?;
        if !is_trusted_ip(entry, proxies) {
            return Some(entry.clone());
        }
    }

    // Every entry was valid and trusted — fall back to the leftmost. The
    // middleware logs a misconfiguration warn when it sees this shape
    // (resolved IP is itself trusted).
    entries.first().cloned()
}

/// The request's `X-Forwarded-For` value, every line of it.
///
/// Each header line is read as Latin-1, in order, and the lines are joined with
/// `", "` — what Node hands the twin (its HTTP parser decodes header bytes as
/// Latin-1 and joins a repeated `X-Forwarded-For` with `", "`). `None` when no
/// line is present.
///
/// Every line, not the first: a proxy that appends its own line after the
/// client's puts the address it saw last, and reading only the first line
/// would key the request on whatever the client wrote. Latin-1, not UTF-8 or
/// visible ASCII: a header with any other byte would otherwise read as absent.
/// A byte outside ASCII can only make an entry fail strict IP validation,
/// which stops the walk there.
#[must_use]
pub fn forwarded_for_value(headers: &HeaderMap) -> Option<String> {
    let mut lines = headers.get_all("x-forwarded-for").iter().peekable();
    lines.peek()?;
    let lines: Vec<String> = lines
        .map(|line| line.as_bytes().iter().map(|&b| char::from(b)).collect())
        .collect();
    Some(lines.join(", "))
}

/// axum middleware that resolves the client IP and stores it on the
/// request via `request.extensions_mut().insert(ClientIp(...))`.
///
/// Three branches mirror `fuz_app`'s `create_proxy_middleware`:
///
/// 1. No `X-Forwarded-For` header → use the normalized connection IP.
/// 2. XFF present but connection from an untrusted IP → ignore the
///    header (spoof-proof) and use the connection IP. Log at `debug`.
/// 3. XFF present and connection from a trusted proxy → walk the
///    header right-to-left. If the resolved entry is itself in the
///    trusted set, log at `warn` (likely misconfiguration).
///
/// Always populates `ClientIp` — when `trusted_proxies` is empty
/// every connection looks untrusted, so the value is the normalized
/// TCP peer IP (matching the direct-bind posture).
pub async fn client_ip_middleware(
    State(proxies): State<Arc<Vec<ParsedProxy>>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let connection_ip = addr.ip().to_string();
    let forwarded_for = forwarded_for_value(req.headers());

    let proxies_slice = proxies.as_slice();

    let client_ip = match forwarded_for {
        None => normalize_ip(&connection_ip),
        // Empty XFF header — treat as absent. Matches TS
        // `if (!forwarded_for)` falsy semantics; otherwise the
        // trusted-XFF arm would substitute the connection IP via
        // the `None` fall-back inside `resolve_client_ip` and then
        // spuriously fire the "all XFF entries trusted" warn because
        // the substituted connection IP is itself in the trusted set.
        Some(ref ff) if ff.is_empty() => normalize_ip(&connection_ip),
        Some(ref ff) if is_trusted_ip(&connection_ip, proxies_slice) => {
            // Trusted connection — walk the header for the
            // originator. `resolve_client_ip` returns `None` when the
            // walk met a malformed entry; fall back to the connection
            // IP silently in that case (TS skips the misconfig warn
            // here too, emitting it only when the resolver actually
            // returned a value that turned out to be trusted itself).
            #[expect(
                clippy::option_if_let_else,
                reason = "explicit None/Some arms read clearer than map_or_else"
            )]
            match resolve_client_ip(ff, proxies_slice) {
                None => normalize_ip(&connection_ip),
                Some(resolved) => {
                    if is_trusted_ip(&resolved, proxies_slice) {
                        tracing::warn!(
                            forwarded_for = ff.as_str(),
                            "all XFF entries are trusted — possible proxy misconfiguration"
                        );
                    }
                    resolved
                }
            }
        }
        Some(_) => {
            // XFF present but connection from an untrusted IP —
            // ignore the spoofable header and key on the TCP peer.
            tracing::debug!(connection_ip, "XFF ignored — connection from untrusted IP");
            normalize_ip(&connection_ip)
        }
    };

    req.extensions_mut().insert(ClientIp(client_ip));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::parse_proxy_entry;

    #[test]
    fn an_extension_lends_its_address_and_an_absent_one_reads_unresolved() {
        let ext = Extension(ClientIp("203.0.113.7".to_owned()));
        assert_eq!(ClientIp::from_extension(Some(&ext)), Some("203.0.113.7"));
        assert_eq!(ClientIp::as_str_or_unresolved(Some(&ext)), "203.0.113.7");
        assert_eq!(ClientIp::from_extension(None), None);
        assert_eq!(ClientIp::as_str_or_unresolved(None), UNRESOLVED_CLIENT_IP);
    }

    fn proxies(entries: &[&str]) -> Vec<ParsedProxy> {
        entries
            .iter()
            .map(|e| parse_proxy_entry(e).unwrap())
            .collect()
    }

    #[test]
    fn an_unparseable_mapped_form_is_no_client_ip() {
        // Stripping `::ffff:` before the parse once accepted both, the second
        // as the non-canonical `::ffff:1.2.3.4`.
        assert_eq!(resolve_client_ip("::ffff:::1.2.3.4", &[]), None);
        assert_eq!(resolve_client_ip("::ffff:::ffff:1.2.3.4", &[]), None);
    }

    fn headers_with(lines: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(
                "x-forwarded-for",
                axum::http::HeaderValue::from_bytes(line).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn forwarded_for_absent_is_none() {
        assert_eq!(forwarded_for_value(&HeaderMap::new()), None);
    }

    #[test]
    fn forwarded_for_empty_line_is_empty_not_absent() {
        // The middleware's empty arm treats this as absent, as the twin does.
        assert_eq!(
            forwarded_for_value(&headers_with(&[b""])).as_deref(),
            Some("")
        );
    }

    #[test]
    fn forwarded_for_joins_every_line_in_order() {
        let headers = headers_with(&[b"198.51.100.7", b"203.0.113.6, 10.0.0.1"]);
        assert_eq!(
            forwarded_for_value(&headers).as_deref(),
            Some("198.51.100.7, 203.0.113.6, 10.0.0.1")
        );
    }

    #[test]
    fn a_spoofed_first_line_does_not_pick_the_client_ip() {
        // The client writes the first line; the trusted proxy appends the
        // address it saw as a second. The walk must see both.
        let headers = headers_with(&[b"198.51.100.7", b"203.0.113.6"]);
        let value = forwarded_for_value(&headers).unwrap();
        assert_eq!(
            resolve_client_ip(&value, &proxies(&["127.0.0.1"])).as_deref(),
            Some("203.0.113.6")
        );
    }

    #[test]
    fn forwarded_for_reads_bytes_as_latin1() {
        // A non-ASCII byte no longer drops the header: it lands in its own
        // entry, which fails strict validation — left of the untrusted entry
        // the walk returns, so it is never reached.
        let headers = headers_with(&[b"\xe9vil, 203.0.113.6"]);
        let value = forwarded_for_value(&headers).unwrap();
        assert_eq!(value, "\u{e9}vil, 203.0.113.6");
        assert_eq!(
            resolve_client_ip(&value, &proxies(&["127.0.0.1"])).as_deref(),
            Some("203.0.113.6")
        );
    }

    #[test]
    fn a_latin1_nel_byte_is_not_trimmed() {
        // Byte 0x85 reads as U+0085, which JS `trim` keeps: the entry is
        // malformed on both spines, so the walk stops at it.
        let headers = headers_with(&[b"198.51.100.7, 203.0.113.6\x85"]);
        let value = forwarded_for_value(&headers).unwrap();
        assert_eq!(resolve_client_ip(&value, &proxies(&["127.0.0.1"])), None);
        // U+00A0 (byte 0xA0) is JS whitespace, so it is trimmed
        let headers = headers_with(&[b"198.51.100.7, \xa0203.0.113.6\xa0"]);
        let value = forwarded_for_value(&headers).unwrap();
        assert_eq!(
            resolve_client_ip(&value, &proxies(&["127.0.0.1"])).as_deref(),
            Some("203.0.113.6")
        );
    }

    #[test]
    fn resolve_single_untrusted_entry_returns_it() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("203.0.113.1", &p).as_deref(),
            Some("203.0.113.1")
        );
    }

    #[test]
    fn resolve_single_trusted_entry_returns_it() {
        // All-trusted edge: leftmost-strictly-valid fallback path.
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("127.0.0.1", &p).as_deref(),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn resolve_rightmost_first_strips_trusted_tail() {
        let p = proxies(&["127.0.0.1", "10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip("203.0.113.1, 10.1.2.3, 127.0.0.1", &p).as_deref(),
            Some("203.0.113.1")
        );
    }

    #[test]
    fn resolve_stops_at_first_untrusted_from_right() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("spoofed, 198.51.100.1, 127.0.0.1", &p).as_deref(),
            Some("198.51.100.1")
        );
    }

    #[test]
    fn resolve_empty_header_returns_none() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(resolve_client_ip("", &p), None);
    }

    #[test]
    fn resolve_whitespace_only_returns_none() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(resolve_client_ip(" , , ", &p), None);
    }

    #[test]
    fn resolve_trims_whitespace_around_entries() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("  203.0.113.1  , 127.0.0.1 ", &p).as_deref(),
            Some("203.0.113.1")
        );
    }

    #[test]
    fn resolve_normalizes_ipv4_mapped_entry() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("::ffff:203.0.113.1, 127.0.0.1", &p).as_deref(),
            Some("203.0.113.1")
        );
    }

    #[test]
    fn resolve_normalizes_uppercase_ipv6_entry() {
        let p = proxies(&["::1"]);
        assert_eq!(
            resolve_client_ip("FE80::ABCD, ::1", &p).as_deref(),
            Some("fe80::abcd")
        );
    }

    #[test]
    fn resolve_stops_at_a_malformed_entry_during_walk() {
        // Never the client-written entry left of the malformed one.
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("198.51.100.7, attacker-controlled, 127.0.0.1", &p),
            None
        );
    }

    #[test]
    fn resolve_stops_at_a_malformed_rightmost_entry() {
        // A trusted hop that appends a non-bare-IP token (`ip:port`,
        // `unknown`, `unix:`): the entry left of it is the client's own.
        let p = proxies(&["127.0.0.1"]);
        for appended in ["203.0.113.1:8080", "[2001:db8::1]:8080", "unknown", "unix:"] {
            let header = format!("198.51.100.7, {appended}");
            assert_eq!(resolve_client_ip(&header, &p), None, "{header}");
        }
    }

    #[test]
    fn resolve_stops_at_port_suffixed_entry() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("198.51.100.7, 203.0.113.1:8080, 127.0.0.1", &p),
            None
        );
    }

    #[test]
    fn resolve_stops_at_colon_injection() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("attacker:controlled, 127.0.0.1", &p),
            None
        );
    }

    #[test]
    fn resolve_stops_at_bracketed_host_port() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(resolve_client_ip("[::1]:8080, 127.0.0.1", &p), None);
    }

    #[test]
    fn resolve_returns_an_untrusted_entry_right_of_a_malformed_one() {
        // The walk returns before it meets the malformed entry.
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("garbage, 198.51.100.7, 127.0.0.1", &p).as_deref(),
            Some("198.51.100.7")
        );
    }

    #[test]
    fn resolve_all_malformed_returns_none() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(resolve_client_ip("garbage, also-bad", &p), None);
    }

    #[test]
    fn resolve_all_trusted_returns_leftmost() {
        let p = proxies(&["127.0.0.1", "10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip("10.1.1.1, 10.2.2.2", &p).as_deref(),
            Some("10.1.1.1")
        );
    }

    #[test]
    fn resolve_consecutive_commas_skipped() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("203.0.113.1,,127.0.0.1", &p).as_deref(),
            Some("203.0.113.1")
        );
    }

    #[test]
    fn resolve_handles_ipv6_originator() {
        let p = proxies(&["127.0.0.1"]);
        assert_eq!(
            resolve_client_ip("2001:db8::1, 127.0.0.1", &p).as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn resolve_handles_v4_mapped_v6_against_v4_cidr_trust() {
        let p = proxies(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip("1.2.3.4, ::ffff:10.0.0.1", &p).as_deref(),
            Some("1.2.3.4")
        );
    }
}
