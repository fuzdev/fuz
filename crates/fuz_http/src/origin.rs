//! Origin verification — a validated allowlist ([`AllowedOrigins`]) and the
//! middleware that enforces it.
//!
//! ## Origin-only
//!
//! The check reads `Origin` and nothing else; there is no `Referer` fallback,
//! as on the TS spine. Per the Fetch spec, browsers send `Origin` on every
//! unsafe method (POST/PUT/DELETE/PATCH) whatever the `Referrer-Policy`, so a
//! `Referer` arm would never fire from a real browser on a state-changing
//! route.
//!
//! ## Pattern grammar
//!
//! An allowlist is a comma-separated list of entries (conventionally the
//! `FUZ_ALLOWED_ORIGINS` env var, which the caller reads). Each entry is
//! written the way a browser writes an `Origin` — `scheme://host[:port]` —
//! where a whole host label or the port may be `*`. The grammar and the
//! matching are the same on both spines, and the TS twin's
//! `parse_allowed_origins` refuses the same entries with the same
//! [`OriginPatternError::kind`] strings.
//!
//! - **Exact**: `https://app.example.com`, `http://localhost:5173`.
//! - **Port wildcard**: `http://localhost:*` — any port, or none. A present
//!   port must be digits.
//! - **Label wildcard**: `https://*.fuz.dev` — each `*` is exactly **one**
//!   non-empty label: `api.fuz.dev` matches, `a.b.fuz.dev` and the bare
//!   parent `fuz.dev` don't. Several may appear (`https://*.*.corp.fuz.dev`),
//!   in any position, on either scheme.
//! - **IPv6**: `http://[::1]:3000` — bracketed, exact, no wildcard inside.
//!
//! Refused at parse, each with its [`OriginPatternError`]: an empty entry
//! (a stray comma); anything but printable ASCII (an international hostname is
//! written in its punycode form); no `scheme://`; a scheme other than http or
//! https (`null`, `file://…`, `chrome-extension://…`); a path, query,
//! fragment, or trailing slash; userinfo; an empty host; a character no
//! hostname holds (`%`, `\`, `^`, `|`, `<`, `>`, `[`, `]`); an unbracketed
//! IPv6 address; a `*` that isn't a whole label; an IPv4 address not written
//! as four canonical decimal numbers (`127.1`, `0x7f.0.0.1`, `127.0.0.01`, a
//! trailing dot); an IPv6 address not in the form a browser sends (leading
//! zeros, an uncompressed zero run, a dotted-quad tail, a zone); a port that
//! isn't `1..=65535` without leading zeros; the scheme's default port (`:80`
//! on http, `:443` on https), which a browser leaves out of `Origin`.
//!
//! An entry that passes is one a browser can send, so every accepted exact
//! entry matches itself — the matcher needs no identical-string shortcut, and
//! has none. Matching is ASCII case-insensitive. The single-label wildcard is
//! load-bearing: a suffix match (`host.ends_with(".fuz.dev")`) would admit
//! attacker-controlled deeper subdomains (`evil.user-content.fuz.dev`).
//!
//! ## Requests
//!
//! [`AllowedOrigins::allows_request`] passes a request with no `Origin` —
//! non-browser clients (curl, server-to-server) don't auto-attach cookies, so
//! CSRF doesn't apply, and auth is the control. An `Origin` that isn't visible
//! ASCII, or more than one `Origin` header, is refused: neither is something a
//! browser sends, and reading either as absent would fail open.

use std::fmt;
use std::net::Ipv6Addr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use fuz_sys::text::{quoted, truncate};

/// Canonical error reason for an origin rejection. Mirrors `fuz_app`'s
/// `ERROR_FORBIDDEN_ORIGIN` (`http/error_schemas.ts`) so the wire body
/// matches across both spines.
pub const FORBIDDEN_ORIGIN_REASON: &str = "forbidden_origin";

/// Separator between entries in an allowlist value.
pub const ALLOWED_ORIGINS_SEPARATOR: char = ',';

/// The longest excerpt of a refused entry an error message quotes.
const ENTRY_EXCERPT_MAX: usize = 200;

/// Build the canonical origin-rejection response.
///
/// `403` + the flat `{"error": "forbidden_origin"}` REST body matching
/// `fuz_app`'s `REST_FORBIDDEN_ORIGIN`. The single source of the rejection across
/// every origin-checking site: the [`origin_layer`] middleware plus the
/// per-handler checks every spine entry point makes through `fuz_auth`'s gate.
#[must_use]
pub fn forbidden_origin_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": FORBIDDEN_ORIGIN_REASON })),
    )
        .into_response()
}

/// Why one allowlist entry was refused (module doc § Pattern grammar).
///
/// [`kind`](Self::kind) is the wire name both spines emit; the TS twin's
/// `OriginPatternErrorKind` lists the same strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OriginPatternError {
    /// The entry is empty — a stray comma.
    #[error("it is empty (a stray comma?)")]
    EmptyEntry,
    /// The entry holds a character outside printable ASCII, or a space.
    #[error(
        "an origin is printable ASCII with no spaces (an international hostname is written in \
         its punycode form)"
    )]
    NotPrintableAscii,
    /// No `scheme://`.
    #[error("it has no `scheme://`")]
    MissingScheme,
    /// A scheme other than http or https.
    #[error("the scheme is neither http nor https")]
    UnsupportedScheme,
    /// A path, query, fragment, or trailing slash.
    #[error(
        "an origin ends at the host or port — no path, query, or fragment, and no trailing slash"
    )]
    HasPath,
    /// Userinfo (`user@`).
    #[error("an origin carries no userinfo")]
    HasUserinfo,
    /// An empty host.
    #[error("it has no host")]
    MissingHost,
    /// A character no hostname holds.
    #[error(
        "a hostname holds none of `%`, `\\`, `^`, `|`, `<`, `>`, `[`, `]` (a browser sends it \
         decoded, with no percent-encoding)"
    )]
    InvalidHostChar,
    /// An IPv6 address without brackets.
    #[error("an IPv6 address is written in brackets, `[::1]`")]
    UnbracketedIpv6,
    /// A `*` that isn't a whole host label.
    #[error("a `*` stands for one whole host label, as in `https://*.example.com`")]
    PartialWildcard,
    /// A host a browser reads as an IPv4 address and writes differently.
    #[error(
        "a host ending in a number is an IPv4 address, which a browser sends as four decimal \
         numbers 0-255 with no leading zeros and no trailing dot"
    )]
    NonCanonicalIpv4,
    /// A `[` with no closing `]`.
    #[error("the IPv6 address has no closing `]`")]
    UnclosedIpv6,
    /// A bracketed host that isn't an IPv6 address in the form a browser
    /// sends.
    #[error(
        "the bracketed host is not an IPv6 address written the way a browser sends it: hex \
         groups without leading zeros, the longest run of zero groups as `::`, no dotted-quad \
         tail, no zone"
    )]
    InvalidIpv6,
    /// Something other than `:port` after the IPv6 address.
    #[error("only `:port` may follow the IPv6 address")]
    InvalidAfterIpv6,
    /// A port that is neither `1..=65535` without leading zeros nor `*`.
    #[error("the port is neither a number in 1-65535 (no leading zeros) nor `*`")]
    InvalidPort,
    /// The scheme's default port, which a browser leaves out of `Origin`.
    #[error(
        "it names the scheme's default port, which a browser leaves out of `Origin` and `Host` — \
         write it without the port"
    )]
    DefaultPort,
}

impl OriginPatternError {
    /// The wire name of this refusal, shared with the TS twin.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::EmptyEntry => "empty_entry",
            Self::NotPrintableAscii => "not_printable_ascii",
            Self::MissingScheme => "missing_scheme",
            Self::UnsupportedScheme => "unsupported_scheme",
            Self::HasPath => "has_path",
            Self::HasUserinfo => "has_userinfo",
            Self::MissingHost => "missing_host",
            Self::InvalidHostChar => "invalid_host_char",
            Self::UnbracketedIpv6 => "unbracketed_ipv6",
            Self::PartialWildcard => "partial_wildcard",
            Self::NonCanonicalIpv4 => "non_canonical_ipv4",
            Self::UnclosedIpv6 => "unclosed_ipv6",
            Self::InvalidIpv6 => "invalid_ipv6",
            Self::InvalidAfterIpv6 => "invalid_after_ipv6",
            Self::InvalidPort => "invalid_port",
            Self::DefaultPort => "default_port",
        }
    }
}

/// One reason an allowlist value was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AllowedOriginsError {
    /// The value is blank: an empty allowlist would refuse every browser
    /// request, so it is a configuration error rather than a posture.
    #[error("no origins supplied — list at least one")]
    NoOrigins,
    /// An entry is refused. `position` is 1-based; `entry` is the entry as
    /// given, trimmed.
    #[error("entry {position} {} is refused: {error}", quoted(&truncate(.entry, ENTRY_EXCERPT_MAX)))]
    Entry {
        position: usize,
        entry: String,
        error: OriginPatternError,
    },
}

impl AllowedOriginsError {
    /// The wire name of this refusal, shared with the TS twin: `no_origins`,
    /// or the entry's [`OriginPatternError::kind`].
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NoOrigins => "no_origins",
            Self::Entry { error, .. } => error.kind(),
        }
    }

    /// The refused entry's 1-based position, or `None` for a list-level
    /// refusal.
    #[must_use]
    pub const fn position(&self) -> Option<usize> {
        match self {
            Self::NoOrigins => None,
            Self::Entry { position, .. } => Some(*position),
        }
    }
}

/// Every reason [`AllowedOrigins::parse`] refused a value — never empty.
///
/// `Display` joins the reasons with `"; "` and ends with the expected shape,
/// so a boot error can carry them on one line behind the name of the variable
/// the value came from.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "{} (expected comma-separated `scheme://host[:port]` entries with an http or https scheme, \
     where a whole host label or the port may be `*`, e.g. `http://localhost:5173`)",
    join_errors(.0)
)]
pub struct AllowedOriginsErrors(Vec<AllowedOriginsError>);

impl AllowedOriginsErrors {
    /// The individual reasons, in entry order.
    #[must_use]
    pub fn errors(&self) -> &[AllowedOriginsError] {
        &self.0
    }
}

fn join_errors(errors: &[AllowedOriginsError]) -> String {
    errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The wildcards an [`OriginPattern`] holds — [`OriginPattern::wildcard_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginWildcard {
    /// `:*` alone — the host at any port, or none.
    Port,
    /// `*` host labels, the port exact or absent.
    Host(HostWildcard),
    /// `*` host labels and `:*`.
    HostAndPort(HostWildcard),
}

/// How much of a pattern's host its `*` labels leave open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostWildcard {
    /// Some labels are fixed (`*.example.com`, `example.*`): any host matching
    /// the fixed ones, each `*` any one label.
    Partial,
    /// No label is fixed (`*`, `*.*`): every host of `labels` labels — four of
    /// them cover every IPv4 address.
    Whole {
        /// The host's label count.
        labels: usize,
    },
}

/// A pattern's host.
#[derive(Clone, PartialEq, Eq)]
enum PatternHost {
    /// A bracketed IPv6 literal, brackets included, as written.
    Ipv6(Box<str>),
    /// A name or IPv4 address, label by label.
    Labels(Box<[Label]>),
}

/// One host label of a pattern.
#[derive(Clone, PartialEq, Eq)]
enum Label {
    /// `*` — any one non-empty label.
    Any,
    /// A literal label, compared ASCII case-insensitively.
    Exact(Box<str>),
}

/// A pattern's port.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PatternPort {
    /// No port — the origin must carry none.
    Absent,
    /// `:*` — any port, or none.
    Any,
    /// One port.
    Exact(u16),
}

/// One validated allowlist entry.
///
/// `Debug` and [`as_str`](Self::as_str) show the entry as written.
#[derive(Clone, PartialEq, Eq)]
pub struct OriginPattern {
    raw: Box<str>,
    https: bool,
    host: PatternHost,
    port: PatternPort,
}

impl fmt::Debug for OriginPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OriginPattern").field(&self.raw).finish()
    }
}

impl OriginPattern {
    /// The entry as written (trimmed).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// True when the entry holds a wildcard — a `*` host label or the `:*`
    /// port — and so admits origins beyond the one it names.
    #[must_use]
    pub fn has_wildcard(&self) -> bool {
        self.wildcard_kind().is_some()
    }

    /// Which wildcards the entry holds, `None` for an exact entry — the shape
    /// the boot warning ([`crate::origin_wildcard_warning`]) describes.
    ///
    /// A bracketed IPv6 host is exact, so it takes only the port form.
    #[must_use]
    pub fn wildcard_kind(&self) -> Option<OriginWildcard> {
        let host = match &self.host {
            PatternHost::Ipv6(_) => None,
            PatternHost::Labels(labels) => {
                let any = labels.iter().filter(|label| **label == Label::Any).count();
                if any == 0 {
                    None
                } else if any < labels.len() {
                    Some(HostWildcard::Partial)
                } else {
                    Some(HostWildcard::Whole {
                        labels: labels.len(),
                    })
                }
            }
        };
        match (host, self.port == PatternPort::Any) {
            (None, false) => None,
            (None, true) => Some(OriginWildcard::Port),
            (Some(host), false) => Some(OriginWildcard::Host(host)),
            (Some(host), true) => Some(OriginWildcard::HostAndPort(host)),
        }
    }

    /// The host as parsed: labels `.`-joined and lowercased (a `*` label as
    /// `*`), an IPv6 literal bracketed.
    pub(crate) fn host_text(&self) -> String {
        match &self.host {
            PatternHost::Ipv6(host) => host.to_string(),
            PatternHost::Labels(labels) => labels
                .iter()
                .map(|label| match label {
                    Label::Any => "*",
                    Label::Exact(exact) => exact,
                })
                .collect::<Vec<_>>()
                .join("."),
        }
    }

    /// True when the entry names a port — one exact port, not `:*`.
    pub(crate) const fn has_exact_port(&self) -> bool {
        matches!(self.port, PatternPort::Exact(_))
    }

    /// Validate one trimmed entry against the grammar (module doc). The checks
    /// run in a fixed order, and the first that fails names the refusal — the
    /// TS twin runs the same order, so both spines name the same kind.
    fn parse(entry: &str) -> Result<Self, OriginPatternError> {
        if entry.is_empty() {
            return Err(OriginPatternError::EmptyEntry);
        }
        if !entry.bytes().all(is_visible_ascii) {
            return Err(OriginPatternError::NotPrintableAscii);
        }
        let Some((scheme, authority)) = entry.split_once("://") else {
            return Err(OriginPatternError::MissingScheme);
        };
        let https = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return Err(OriginPatternError::UnsupportedScheme);
        };
        if authority.contains(['/', '?', '#']) {
            return Err(OriginPatternError::HasPath);
        }
        if authority.contains('@') {
            return Err(OriginPatternError::HasUserinfo);
        }

        let (host, port) = if authority.starts_with('[') {
            let Some(end) = authority.find(']') else {
                return Err(OriginPatternError::UnclosedIpv6);
            };
            let (bracketed, rest) = authority.split_at(end + 1);
            let inner = &bracketed[1..end];
            let canonical = inner
                .parse::<Ipv6Addr>()
                .ok()
                .map(ipv6_origin_form)
                .filter(|form| form.eq_ignore_ascii_case(inner));
            if canonical.is_none() {
                return Err(OriginPatternError::InvalidIpv6);
            }
            let port = match rest.strip_prefix(':') {
                Some(port) => Some(port),
                None if rest.is_empty() => None,
                None => return Err(OriginPatternError::InvalidAfterIpv6),
            };
            (
                PatternHost::Ipv6(bracketed.to_ascii_lowercase().into()),
                port,
            )
        } else {
            let (host, port) = authority
                .rsplit_once(':')
                .map_or((authority, None), |(host, port)| (host, Some(port)));
            if host.is_empty() {
                return Err(OriginPatternError::MissingHost);
            }
            if host.contains(':') {
                return Err(OriginPatternError::UnbracketedIpv6);
            }
            if host.contains(['%', '\\', '^', '|', '<', '>', '[', ']']) {
                return Err(OriginPatternError::InvalidHostChar);
            }
            if host
                .split('.')
                .any(|label| label.contains('*') && label != "*")
            {
                return Err(OriginPatternError::PartialWildcard);
            }
            if !is_canonical_ipv4_or_name(host) {
                return Err(OriginPatternError::NonCanonicalIpv4);
            }
            let labels = host
                .split('.')
                .map(|label| {
                    if label == "*" {
                        Label::Any
                    } else {
                        Label::Exact(label.to_ascii_lowercase().into())
                    }
                })
                .collect();
            (PatternHost::Labels(labels), port)
        };

        let port = match port {
            None => PatternPort::Absent,
            Some("*") => PatternPort::Any,
            Some(port) => {
                let number = port
                    .parse::<u16>()
                    .ok()
                    .filter(|n| *n != 0 && n.to_string() == port)
                    .ok_or(OriginPatternError::InvalidPort)?;
                if number == if https { 443 } else { 80 } {
                    return Err(OriginPatternError::DefaultPort);
                }
                PatternPort::Exact(number)
            }
        };

        Ok(Self {
            raw: entry.into(),
            https,
            host,
            port,
        })
    }

    /// Match a visible-ASCII `Origin` value against this pattern.
    fn matches(&self, origin: &str) -> bool {
        let prefix = if self.https { "https://" } else { "http://" };
        let Some(rest) = strip_prefix_ignore_ascii_case(origin, prefix) else {
            return false;
        };
        let port_part = match &self.host {
            PatternHost::Ipv6(host) => match strip_prefix_ignore_ascii_case(rest, host) {
                Some(port_part) => port_part,
                None => return false,
            },
            PatternHost::Labels(labels) => {
                // no label holds a `:`, so the host ends at the first one
                let (host, port_part) = rest.find(':').map_or((rest, ""), |i| rest.split_at(i));
                if host.split('.').count() != labels.len() {
                    return false;
                }
                let labels_match =
                    labels
                        .iter()
                        .zip(host.split('.'))
                        .all(|(label, given)| match label {
                            Label::Any => !given.is_empty() && !given.contains('/'),
                            Label::Exact(exact) => given.eq_ignore_ascii_case(exact),
                        });
                if !labels_match {
                    return false;
                }
                port_part
            }
        };
        match self.port {
            PatternPort::Absent => port_part.is_empty(),
            PatternPort::Any => {
                port_part.is_empty()
                    || port_part.strip_prefix(':').is_some_and(|digits| {
                        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
                    })
            }
            PatternPort::Exact(port) => port_part
                .strip_prefix(':')
                .is_some_and(|digits| digits == port.to_string()),
        }
    }
}

/// A validated, non-empty origin allowlist.
///
/// Built only by [`parse`](Self::parse), so it is never empty and holds no
/// entry a browser can't send. Cheap to clone (the patterns are shared), so
/// it serves as `axum` state directly.
#[derive(Clone, PartialEq, Eq)]
pub struct AllowedOrigins {
    patterns: Arc<[OriginPattern]>,
}

impl fmt::Debug for AllowedOrigins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.patterns.iter()).finish()
    }
}

impl AllowedOrigins {
    /// Parse a comma-separated allowlist value (conventionally the
    /// `FUZ_ALLOWED_ORIGINS` env var, which the caller reads and names in its
    /// own boot error).
    ///
    /// Entries are split on [`ALLOWED_ORIGINS_SEPARATOR`] and trimmed of ASCII
    /// whitespace; every entry is validated (module doc § Pattern grammar).
    /// Twin of the TS `parse_allowed_origins`.
    ///
    /// # Errors
    ///
    /// Returns [`AllowedOriginsErrors`] holding [`AllowedOriginsError::NoOrigins`]
    /// when the value is blank, or one [`AllowedOriginsError::Entry`] per
    /// refused entry — every one, not just the first.
    pub fn parse(raw: &str) -> Result<Self, AllowedOriginsErrors> {
        if trim_ascii_whitespace(raw).is_empty() {
            return Err(AllowedOriginsErrors(vec![AllowedOriginsError::NoOrigins]));
        }
        let mut patterns = Vec::new();
        let mut errors = Vec::new();
        for (index, entry) in raw.split(ALLOWED_ORIGINS_SEPARATOR).enumerate() {
            let entry = trim_ascii_whitespace(entry);
            match OriginPattern::parse(entry) {
                Ok(pattern) => patterns.push(pattern),
                Err(error) => errors.push(AllowedOriginsError::Entry {
                    position: index + 1,
                    entry: entry.to_owned(),
                    error,
                }),
            }
        }
        if !errors.is_empty() {
            return Err(AllowedOriginsErrors(errors));
        }
        Ok(Self {
            patterns: patterns.into(),
        })
    }

    /// The entries, in the order given.
    #[must_use]
    pub fn patterns(&self) -> &[OriginPattern] {
        &self.patterns
    }

    /// The entries that hold a wildcard ([`OriginPattern::has_wildcard`]) —
    /// the ones [`crate::admit_origin_wildcards`] refuses or warns about at
    /// boot.
    pub fn wildcards(&self) -> impl Iterator<Item = &OriginPattern> {
        self.patterns.iter().filter(|p| p.has_wildcard())
    }

    /// True when `origin` (an `Origin` value) matches an entry. A value that
    /// isn't visible ASCII matches nothing.
    #[must_use]
    pub fn allows(&self, origin: &str) -> bool {
        origin.bytes().all(is_visible_ascii) && self.patterns.iter().any(|p| p.matches(origin))
    }

    /// The request-level check: true when the request carries no `Origin`,
    /// or exactly one that [`allows`](Self::allows) admits. An `Origin` that
    /// isn't visible ASCII, or a second `Origin` header, is refused (module
    /// doc § Requests).
    #[must_use]
    pub fn allows_request(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(header::ORIGIN).iter();
        match (values.next(), values.next()) {
            (None, _) => true,
            (Some(_), Some(_)) => false,
            (Some(value), None) => {
                std::str::from_utf8(value.as_bytes()).is_ok_and(|origin| self.allows(origin))
            }
        }
    }
}

/// axum middleware enforcing [`AllowedOrigins::allows_request`], refusing
/// with [`forbidden_origin_response`].
///
/// [`crate::compose_stack`] mounts it in every route group, the fallback
/// included, over
/// [`StackOptions::allowed_origins`](crate::StackOptions::allowed_origins); a
/// group leaves it only through
/// [`RouteGroup::origin_carve_out`](crate::RouteGroup::origin_carve_out).
pub async fn origin_layer(
    State(allowed): State<AllowedOrigins>,
    req: Request,
    next: Next,
) -> Response {
    if !allowed.allows_request(req.headers()) {
        return forbidden_origin_response();
    }
    next.run(req).await
}

/// `0x21..=0x7E` — printable ASCII without the space.
const fn is_visible_ascii(b: u8) -> bool {
    matches!(b, 0x21..=0x7e)
}

/// `value` without leading and trailing ASCII whitespace (space, tab, LF, FF,
/// CR) — the set the TS twin trims, so a Unicode space stays in the entry and
/// refuses it on both spines.
fn trim_ascii_whitespace(value: &str) -> &str {
    value.trim_matches(|c: char| c.is_ascii_whitespace())
}

/// `value` after `prefix`, compared ASCII case-insensitively.
fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

/// An IPv6 address as a browser serializes it in an origin: lowercase hex
/// groups without leading zeros, the first longest run of two or more zero
/// groups as `::`, and never a dotted-quad tail.
fn ipv6_origin_form(address: Ipv6Addr) -> String {
    use std::fmt::Write as _;

    let groups = address.segments();
    // the first longest run of zero groups, when it is two or more long
    let mut compress: Option<(usize, usize)> = None;
    let mut index = 0;
    while index < groups.len() {
        if groups[index] != 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index < groups.len() && groups[index] == 0 {
            index += 1;
        }
        let len = index - start;
        if len >= 2 && compress.is_none_or(|(_, longest)| len > longest) {
            compress = Some((start, len));
        }
    }

    let mut out = String::new();
    let mut index = 0;
    while index < groups.len() {
        if let Some((start, len)) = compress
            && index == start
        {
            out.push_str(if start == 0 { "::" } else { ":" });
            index += len;
            continue;
        }
        let _ = write!(out, "{:x}", groups[index]);
        index += 1;
        if index < groups.len() {
            out.push(':');
        }
    }
    out
}

/// False when `host` (no brackets, wildcard labels allowed) is one a browser
/// reads as an IPv4 address and then writes differently. A browser takes any
/// host whose last label is a number — decimal or `0x` hex, one trailing dot
/// aside — for an IPv4 address and sends it as four decimal numbers.
fn is_canonical_ipv4_or_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    let last = name.rsplit('.').next().unwrap_or(name);
    let hex = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()));
    let is_number = hex || (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()));
    if !is_number {
        return true;
    }
    // a trailing dot makes a fifth, empty label
    host.split('.').count() == 4
        && host.split('.').all(|label| {
            label == "*"
                || label
                    .parse::<u8>()
                    .is_ok_and(|octet| octet.to_string() == label)
        })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn origins(raw: &str) -> AllowedOrigins {
        AllowedOrigins::parse(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"))
    }

    fn kinds(raw: &str) -> Vec<(Option<usize>, &'static str)> {
        AllowedOrigins::parse(raw)
            .expect_err(raw)
            .errors()
            .iter()
            .map(|e| (e.position(), e.kind()))
            .collect()
    }

    fn headers(values: &[&[u8]]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for value in values {
            h.append(
                header::ORIGIN,
                HeaderValue::from_bytes(value).expect("header value"),
            );
        }
        h
    }

    #[test]
    fn valid_entries_pass() {
        for entry in [
            "http://localhost:5460",
            "HTTP://LocalHost:5460",
            "https://zzz.example.com",
            "https://zzz.example.com:8443",
            // the other scheme's default port is a port like any other
            "http://localhost:443",
            "https://zzz.example.com:80",
            "http://192.168.1.10:5460",
            "http://127.0.0.1:4460",
            "http://[::1]:5460",
            "http://[::1]",
            "http://[2001:db8::1]:5460",
            "http://[2001:DB8::1]:5460",
            "http://[fe80::1:0:0:1]",
            "http://[::ffff:102:304]",
            "http://[1:2:3:4:5:6:7:8]",
            "http://[::]",
            "http://localhost",
            "http://localhost.",
            "https://xn--bcher-kva.example",
            "https://my_host.example",
            "https://1.2.3.4a",
            "https://0xg.example",
            "http://localhost:*",
            "http://[::1]:*",
            "https://*.example.com",
            "https://*.*.corp.example.com",
            "https://*.example.com:*",
            "https://example.*",
            "http://192.168.1.*",
            "http://*.168.1.10:5460",
            "http://*",
            "http://*:*",
            "https://*.*",
            "http://*.*.*.*",
        ] {
            assert_eq!(OriginPattern::parse(entry).map(|_| ()), Ok(()), "{entry}");
        }
    }

    #[test]
    fn malformed_entries_are_refused_with_their_kind() {
        use OriginPatternError as E;
        for (entry, expected) in [
            ("", E::EmptyEntry),
            ("http://localhost:5460/", E::HasPath),
            ("http://localhost:5460/chats", E::HasPath),
            ("https://zzz.example.com?x=1", E::HasPath),
            ("https://zzz.example.com#top", E::HasPath),
            ("localhost:5460", E::MissingScheme),
            ("*", E::MissingScheme),
            ("null", E::MissingScheme),
            ("//localhost:5460", E::MissingScheme),
            ("ws://localhost:5460", E::UnsupportedScheme),
            ("file://localhost", E::UnsupportedScheme),
            ("chrome-extension://abcdefghijklmnop", E::UnsupportedScheme),
            ("http://", E::MissingHost),
            ("http://:5460", E::MissingHost),
            ("http://user@localhost:5460", E::HasUserinfo),
            ("http://local host:5460", E::NotPrintableAscii),
            ("http://local\u{7f}host:5460", E::NotPrintableAscii),
            ("https://b\u{fc}cher.example", E::NotPrintableAscii),
            ("http://localhost:", E::InvalidPort),
            ("http://localhost:abc", E::InvalidPort),
            ("http://localhost:0", E::InvalidPort),
            ("http://localhost:65536", E::InvalidPort),
            ("http://localhost:05460", E::InvalidPort),
            ("http://localhost:+80", E::InvalidPort),
            ("http://localhost:80", E::DefaultPort),
            ("https://zzz.example.com:443", E::DefaultPort),
            ("https://*foo.example.com", E::PartialWildcard),
            ("http://::1:5460", E::UnbracketedIpv6),
            ("https://zzz%2eexample.com", E::InvalidHostChar),
            ("http://local\\host:5460", E::InvalidHostChar),
            ("http://a|b", E::InvalidHostChar),
            ("http://a]:5460", E::InvalidHostChar),
            ("http://127.1:5460", E::NonCanonicalIpv4),
            ("http://127.0.0.01:5460", E::NonCanonicalIpv4),
            ("http://0x7f.0.0.1:5460", E::NonCanonicalIpv4),
            ("http://127.0.0.0X1", E::NonCanonicalIpv4),
            ("http://0x", E::NonCanonicalIpv4),
            ("http://2130706433", E::NonCanonicalIpv4),
            ("http://127.0.0.1.:5460", E::NonCanonicalIpv4),
            ("http://256.0.0.1", E::NonCanonicalIpv4),
            ("http://1.2.3.4.5", E::NonCanonicalIpv4),
            ("http://*.1:5460", E::NonCanonicalIpv4),
            ("http://[0:0:0:0:0:0:0:1]:5460", E::InvalidIpv6),
            ("http://[::0001]:5460", E::InvalidIpv6),
            ("http://[::ffff:1.2.3.4]", E::InvalidIpv6),
            ("http://[1:0:0:2:0:0:0:3]", E::InvalidIpv6),
            ("http://[localhost]:5460", E::InvalidIpv6),
            ("http://[::*]:5460", E::InvalidIpv6),
            ("http://[fe80::1%eth0]", E::InvalidIpv6),
            ("http://[::1", E::UnclosedIpv6),
            ("http://[::1]5460", E::InvalidAfterIpv6),
        ] {
            assert_eq!(
                OriginPattern::parse(entry).map(|_| ()),
                Err(expected),
                "{entry:?}"
            );
        }
    }

    #[test]
    fn a_blank_value_has_no_origins() {
        for raw in ["", "   ", "\t\n"] {
            assert_eq!(kinds(raw), [(None, "no_origins")], "{raw:?}");
        }
    }

    #[test]
    fn every_refused_entry_is_reported_with_its_position() {
        assert_eq!(
            kinds("http://localhost:5173, null,https://a.example/ ,"),
            [
                (Some(2), "missing_scheme"),
                (Some(3), "has_path"),
                (Some(4), "empty_entry"),
            ]
        );
        assert_eq!(
            kinds(","),
            [(Some(1), "empty_entry"), (Some(2), "empty_entry")]
        );
    }

    #[test]
    fn only_ascii_whitespace_is_trimmed() {
        assert_eq!(
            origins(" \thttp://localhost:5173\r\n").patterns()[0].as_str(),
            "http://localhost:5173"
        );
        assert_eq!(
            kinds("\u{a0}http://localhost:5173"),
            [(Some(1), "not_printable_ascii")]
        );
    }

    #[test]
    fn the_error_message_names_each_entry_and_the_shape() {
        let message = AllowedOrigins::parse("http://ok.example,http://a/,null")
            .expect_err("refused")
            .to_string();
        assert!(message.contains("entry 2 \"http://a/\""), "{message}");
        assert!(message.contains("entry 3 \"null\""), "{message}");
        assert!(message.contains("scheme://host[:port]"), "{message}");
        // a control character in an entry is escaped, not printed
        let message = AllowedOrigins::parse("http://a\u{1b}b")
            .expect_err("refused")
            .to_string();
        assert!(!message.contains('\u{1b}'), "{message:?}");
    }

    #[test]
    fn exact_entries_match_themselves_with_no_shortcut() {
        for entry in [
            "http://localhost:5460",
            "https://zzz.example.com",
            "http://[::1]:5460",
            "http://[2001:db8::1]",
            "http://127.0.0.1:4460",
        ] {
            assert!(origins(entry).allows(entry), "{entry}");
        }
    }

    #[test]
    fn matching() {
        for (patterns, origin, allowed) in [
            ("https://app.example.com", "https://app.example.com", true),
            ("https://app.example.com", "https://App.Example.COM", true),
            ("https://app.example.com", "https://evil.example.com", false),
            ("https://app.example.com", "http://app.example.com", false),
            (
                "https://app.example.com",
                "https://app.example.com.evil.com",
                false,
            ),
            (
                "https://app.example.com",
                "https://app.example.com:443",
                false,
            ),
            ("http://localhost:*", "http://localhost:5173", true),
            ("http://localhost:*", "http://localhost", true),
            ("http://localhost:*", "http://localhost:", false),
            ("http://localhost:*", "http://localhost:abc", false),
            ("http://localhost:5173", "http://localhost:5174", false),
            ("http://localhost", "http://localhost:5173", false),
            ("https://*.fuz.dev", "https://staging.fuz.dev", true),
            ("https://*.fuz.dev", "https://evilfuz.dev", false),
            ("https://*.fuz.dev", "https://fuz.dev", false),
            (
                "https://*.fuz.dev",
                "https://evil.user-content.fuz.dev",
                false,
            ),
            ("https://*.fuz.dev", "https://a/b.fuz.dev", false),
            ("http://*.localhost", "http://api.localhost", true),
            ("https://*.*.corp.fuz.dev", "https://a.b.corp.fuz.dev", true),
            ("https://*.*.corp.fuz.dev", "https://b.corp.fuz.dev", false),
            ("https://*.fuz.dev:*", "https://api.fuz.dev:8443", true),
            ("https://*.fuz.dev:*", "https://a.b.fuz.dev:8443", false),
            ("http://*:*", "http://a:b:80", false),
            ("http://[::1]:3000", "http://[::1]:3000", true),
            ("http://[::1]:3000", "http://[::1]:3001", false),
            ("http://[::1]:*", "http://[::1]", true),
            // no identical-string shortcut: an entry with a wildcard is no origin
            ("http://localhost:*", "http://localhost:*", false),
            ("https://*.fuz.dev:*", "https://*.fuz.dev:*", false),
            ("http://localhost:*", "null", false),
            ("http://localhost:*", "", false),
            (
                "http://localhost:*",
                "http://localhost:5173, http://localhost:5173",
                false,
            ),
            ("http://*", "http://caf\u{e9}", false),
        ] {
            assert_eq!(
                origins(patterns).allows(origin),
                allowed,
                "{patterns} vs {origin:?}"
            );
        }
    }

    #[test]
    fn request_without_origin_passes() {
        assert!(origins("https://app.example.com").allows_request(&HeaderMap::new()));
    }

    #[test]
    fn request_with_one_origin_is_matched() {
        let allowed = origins("https://app.example.com");
        assert!(allowed.allows_request(&headers(&[b"https://app.example.com"])));
        assert!(!allowed.allows_request(&headers(&[b"https://evil.example.com"])));
        assert!(!allowed.allows_request(&headers(&[b""])));
    }

    #[test]
    fn request_with_an_unreadable_origin_is_refused() {
        let allowed = origins("http://*:*");
        for value in [&b"http://caf\xe9"[..], b"http://a\tb", b"http://\xff"] {
            assert!(!allowed.allows_request(&headers(&[value])), "{value:?}");
        }
    }

    #[test]
    fn request_with_a_duplicated_origin_is_refused() {
        let allowed = origins("https://app.example.com");
        let same = b"https://app.example.com";
        assert!(!allowed.allows_request(&headers(&[same, same])));
        assert!(!allowed.allows_request(&headers(&[same, b"https://evil.example.com"])));
    }

    #[test]
    fn wildcard_kind_reads_the_parsed_shape() {
        use HostWildcard::{Partial, Whole};
        for (entry, kind) in [
            ("http://localhost:5173", None),
            ("https://app.example.com", None),
            ("http://[::1]:3000", None),
            ("http://[2001:db8::1]", None),
            ("http://localhost:*", Some(OriginWildcard::Port)),
            ("http://192.168.1.10:*", Some(OriginWildcard::Port)),
            ("http://[::1]:*", Some(OriginWildcard::Port)),
            ("https://*.example.com", Some(OriginWildcard::Host(Partial))),
            ("https://example.*", Some(OriginWildcard::Host(Partial))),
            (
                "http://app.*.test:5460",
                Some(OriginWildcard::Host(Partial)),
            ),
            ("http://192.168.1.*", Some(OriginWildcard::Host(Partial))),
            ("http://*", Some(OriginWildcard::Host(Whole { labels: 1 }))),
            (
                "https://*.*",
                Some(OriginWildcard::Host(Whole { labels: 2 })),
            ),
            (
                "http://*.*.*.*",
                Some(OriginWildcard::Host(Whole { labels: 4 })),
            ),
            (
                "https://*.example.com:*",
                Some(OriginWildcard::HostAndPort(Partial)),
            ),
            (
                "http://*:*",
                Some(OriginWildcard::HostAndPort(Whole { labels: 1 })),
            ),
        ] {
            let pattern = OriginPattern::parse(entry).unwrap();
            assert_eq!(pattern.wildcard_kind(), kind, "{entry}");
            assert_eq!(pattern.has_wildcard(), kind.is_some(), "{entry}");
        }
    }

    #[test]
    fn host_text_is_the_parsed_host() {
        for (entry, host) in [
            ("https://*.Example.COM:*", "*.example.com"),
            ("http://localhost:5173", "localhost"),
            ("http://[::1]:*", "[::1]"),
            ("http://*", "*"),
        ] {
            assert_eq!(OriginPattern::parse(entry).unwrap().host_text(), host);
        }
    }

    #[test]
    fn wildcards_lists_only_wildcard_entries() {
        let allowed =
            origins("http://localhost:5173,http://localhost:*,https://*.fuz.dev,http://[::1]");
        let listed: Vec<&str> = allowed.wildcards().map(OriginPattern::as_str).collect();
        assert_eq!(listed, ["http://localhost:*", "https://*.fuz.dev"]);
    }

    #[test]
    fn ipv6_origin_form_is_the_browser_serialization() {
        for (written, sent) in [
            ("::1", "::1"),
            ("::", "::"),
            ("0:0:0:0:0:0:0:1", "::1"),
            ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
            ("1::", "1::"),
            ("1:0:0:0:0:0:0:0", "1::"),
            ("1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7"),
            ("1:0:0:2:0:0:0:3", "1:0:0:2::3"),
            ("1:0:0:2:3:0:0:4", "1::2:3:0:0:4"),
            ("::ffff:1.2.3.4", "::ffff:102:304"),
            ("fe80::1:0:0:1", "fe80::1:0:0:1"),
        ] {
            let address: Ipv6Addr = written.parse().unwrap();
            assert_eq!(ipv6_origin_form(address), sent, "{written}");
        }
    }
}
