//! Wildcard allowlist entries — refused at boot unless the operator opts in
//! with [`ALLOW_ORIGIN_WILDCARDS_VAR`], and said aloud on every boot that
//! admits them.
//!
//! Wildcards are origin syntax an operator may want, but each one admits pages
//! the server does not serve, and the server trusts them all — so a list that
//! holds one boots only with `FUZ_ALLOW_ORIGIN_WILDCARDS=true`
//! ([`admit_origin_wildcards`]). Refused, the error names each entry and what
//! it admits; admitted, each entry logs the same text at `warn`. The forms, as
//! [`crate::AllowedOrigins`] matches them ([`OriginWildcard`]):
//!
//! - **port** (`:*`) — the host at any port, or none;
//! - **host** — each `*` label is any one label, in any position
//!   (`https://*.example.com`, `https://example.*`), and a host that is all
//!   `*` labels (`http://*`, `https://*.*`) is every host with that many
//!   labels — four of them cover every IPv4 address;
//! - **both** (`http://*:*`, `https://*.example.com:*`).
//!
//! A bracketed IPv6 host is exact, so it takes only the port form. When the
//! server mounts the host gate ([`OriginWildcardOptions::host_gate`]), the
//! text adds that the `Host` check answers to the same hosts.

use fuz_sys::text::{quoted, truncate};

use crate::origin::{AllowedOrigins, HostWildcard, OriginPattern, OriginWildcard};
use crate::server_env::ServerEnvError;

/// The env var that admits wildcard allowlist entries: exactly `true` admits
/// them, exactly `false` (or unset) refuses them, anything else is a
/// configuration error ([`parse_allow_origin_wildcards`]).
pub const ALLOW_ORIGIN_WILDCARDS_VAR: &str = "FUZ_ALLOW_ORIGIN_WILDCARDS";

/// The longest excerpt of a malformed [`ALLOW_ORIGIN_WILDCARDS_VAR`] value an
/// error quotes.
const FLAG_EXCERPT_MAX: usize = 40;

/// What the server adds to the text for a wildcard entry: the gates it mounts
/// and what a trusted page reaches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginWildcardOptions {
    /// The server mounts the `Host` check ([`crate::StackOptions::host_gate`]),
    /// which the same entries widen.
    pub host_gate: bool,
    /// The server's own sentence on what a page the allowlist trusts reaches
    /// there, placed after the spine's, on every wildcard entry.
    pub note: Option<&'static str>,
    /// The server's sentence for an entry with a port wildcard (`:*`) only,
    /// after [`Self::note`] — what a port wildcard opens there that a host
    /// wildcard doesn't.
    pub port_wildcard_note: Option<&'static str>,
}

impl OriginWildcardOptions {
    /// The host gate on (as [`crate::StackOptions::new`] mounts it), no notes.
    pub const DEFAULT: Self = Self {
        host_gate: true,
        note: None,
        port_wildcard_note: None,
    };
}

impl Default for OriginWildcardOptions {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Read [`ALLOW_ORIGIN_WILDCARDS_VAR`]'s value: `None` (unset) and `false` are
/// `false`, `true` is `true`.
///
/// # Errors
///
/// [`ServerEnvError`] naming the var for any other value — blank, padded, or
/// another spelling of a boolean included, so a typo never reads as either.
pub fn parse_allow_origin_wildcards(value: Option<&str>) -> Result<bool, ServerEnvError> {
    match value {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(other) => Err(ServerEnvError(format!(
            "{ALLOW_ORIGIN_WILDCARDS_VAR}: expected `true` or `false`, got {}",
            quoted(&truncate(other, FLAG_EXCERPT_MAX))
        ))),
    }
}

/// Admit `origins`' wildcard entries when `allowed` ([`ALLOW_ORIGIN_WILDCARDS_VAR`]
/// is `true`), logging each one's [`origin_wildcard_warning`] at `warn`; an
/// exact list passes either way, silently.
///
/// `origins_var` names the env var the list was read from, in the log line
/// and the error.
///
/// # Errors
///
/// [`ServerEnvError`] when the list holds a wildcard and `allowed` is false —
/// naming each wildcard entry, what it admits, and the flag.
pub fn admit_origin_wildcards(
    origins: &AllowedOrigins,
    allowed: bool,
    origins_var: &str,
    options: &OriginWildcardOptions,
) -> Result<(), ServerEnvError> {
    let wildcards: Vec<(&OriginPattern, String)> = origins
        .wildcards()
        .filter_map(|pattern| Some((pattern, origin_wildcard_warning(pattern, options)?)))
        .collect();
    if wildcards.is_empty() {
        return Ok(());
    }
    if allowed {
        for (pattern, warning) in &wildcards {
            tracing::warn!(origin = %pattern.as_str(), "{origins_var}: {warning}");
        }
        return Ok(());
    }
    let entries = wildcards
        .iter()
        .map(|(pattern, warning)| format!("`{}`: {warning}.", pattern.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    Err(ServerEnvError(format!(
        "{origins_var} holds a wildcard entry, refused unless \
         {ALLOW_ORIGIN_WILDCARDS_VAR}=true. {entries}"
    )))
}

/// What a wildcard in `pattern` admits — the text [`admit_origin_wildcards`]
/// logs or refuses with; `None` for an exact entry.
#[must_use]
pub fn origin_wildcard_warning(
    pattern: &OriginPattern,
    options: &OriginWildcardOptions,
) -> Option<String> {
    let wildcard = pattern.wildcard_kind()?;
    let host = pattern.host_text();
    let (kind, host_wildcard, any_port) = match wildcard {
        OriginWildcard::Port => ("port wildcard", None, true),
        OriginWildcard::Host(h) => ("host wildcard", Some(h), false),
        OriginWildcard::HostAndPort(h) => ("host and port wildcard", Some(h), true),
    };

    let hosts = match host_wildcard {
        None => format!("`{host}`"),
        Some(HostWildcard::Partial) => {
            format!("ANY host matching `{host}` (each `*` is any one label)")
        }
        Some(HostWildcard::Whole { labels }) => {
            let every = match labels {
                1 => "every single-label name, `localhost` included".to_owned(),
                4 => "every IPv4 address and every four-label hostname".to_owned(),
                n => format!("every hostname of {n} labels"),
            };
            format!("ANY host of that shape (no label of `{host}` is fixed: {every})")
        }
    };
    let ports = if any_port {
        "ANY port on "
    } else if pattern.has_exact_port() {
        "that port on "
    } else {
        ""
    };

    let mut sentences = vec![format!(
        "{kind}: a page served from {ports}{hosts} is an allowed origin. The server trusts \
         every such page: one that is same-site with the host you log in at carries the \
         session cookie, and with it can call the API and open the WebSocket."
    )];
    if let Some(note) = options.note {
        sentences.push(note.to_owned());
    }
    if any_port && let Some(note) = options.port_wildcard_note {
        sentences.push(note.to_owned());
    }
    if options.host_gate {
        sentences.push(if host_wildcard.is_none() {
            format!("The `Host` check answers to {host} at any port too.")
        } else {
            "The `Host` check answers to the same hosts, on either scheme, so a page that \
             re-points a matching domain at this machine (DNS rebinding) passes it."
                .to_owned()
        });
    }
    sentences.push("Name exact origins unless every such page is trusted".to_owned());
    Some(sentences.join(" "))
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
    use crate::AllowedOrigins;

    fn patterns(value: &str) -> AllowedOrigins {
        AllowedOrigins::parse(value).unwrap_or_else(|e| panic!("{value}: {e}"))
    }

    const fn with(host_gate: bool, note: Option<&'static str>) -> OriginWildcardOptions {
        OriginWildcardOptions {
            host_gate,
            note,
            port_wildcard_note: None,
        }
    }

    fn pattern(origin: &str) -> OriginPattern {
        patterns(origin).patterns()[0].clone()
    }

    /// The warning for a wildcard entry with the host gate on, as a server
    /// that sets a host gate mounts it.
    fn warning(origin: &str) -> String {
        origin_wildcard_warning(&pattern(origin), &with(true, None))
            .unwrap_or_else(|| panic!("{origin} warns"))
    }

    #[test]
    fn exact_origins_carry_no_warning() {
        for origin in [
            "http://localhost:5460",
            "http://127.0.0.1:4460",
            "https://zzz.example.com",
            "http://[::1]:5460",
            "http://[2001:db8::1]",
        ] {
            assert_eq!(
                origin_wildcard_warning(&pattern(origin), &with(true, Some("note"))),
                None,
                "{origin}"
            );
        }
    }

    #[test]
    fn the_whole_text_of_one_warning() {
        assert_eq!(
            origin_wildcard_warning(&pattern("http://localhost:*"), &with(true, Some("A note.")))
                .unwrap(),
            "port wildcard: a page served from ANY port on `localhost` is an allowed origin. \
             The server trusts every such page: one that is same-site with the host you log in \
             at carries the session cookie, and with it can call the API and open the \
             WebSocket. A note. The `Host` check answers to localhost at any port too. Name \
             exact origins unless every such page is trusted"
        );
        // the port note rides only on an entry with a port wildcard, after the
        // general one
        let notes = OriginWildcardOptions {
            host_gate: false,
            note: Some("A note."),
            port_wildcard_note: Some("A port note."),
        };
        for (origin, carries) in [
            ("http://localhost:*", true),
            ("https://*.example.com:*", true),
            ("https://*.example.com", false),
            ("http://*", false),
        ] {
            let text = origin_wildcard_warning(&pattern(origin), &notes).unwrap();
            let expected = if carries {
                "WebSocket. A note. A port note. Name"
            } else {
                "WebSocket. A note. Name"
            };
            assert!(text.contains(expected), "{origin}: {text}");
        }
        // no host gate, no note: neither sentence
        assert_eq!(
            origin_wildcard_warning(&pattern("https://*.example.com"), &with(false, None)).unwrap(),
            "host wildcard: a page served from ANY host matching `*.example.com` (each `*` is \
             any one label) is an allowed origin. The server trusts every such page: one that \
             is same-site with the host you log in at carries the session cookie, and with it \
             can call the API and open the WebSocket. Name exact origins unless every such page \
             is trusted"
        );
    }

    #[test]
    fn a_port_wildcard_warning_names_the_host_at_any_port() {
        for (origin, host) in [
            ("http://localhost:*", "localhost"),
            ("http://192.168.1.10:*", "192.168.1.10"),
            ("http://[::1]:*", "[::1]"),
        ] {
            let text = warning(origin);
            assert!(text.starts_with("port wildcard: "), "{origin}: {text}");
            assert!(
                text.contains(&format!("ANY port on `{host}` is an allowed origin")),
                "{origin}: {text}"
            );
            assert!(
                text.contains(&format!(
                    "The `Host` check answers to {host} at any port too"
                )),
                "{origin}: {text}"
            );
            assert!(text.contains("session cookie"), "{origin}: {text}");
            assert!(!text.contains("ANY host"), "{origin}: {text}");
            // and the matcher does what the text says
            let list = patterns(origin);
            for port in ["", ":1", ":5173", ":65535"] {
                let scheme_host = origin.trim_end_matches(":*");
                assert!(list.allows(&format!("{scheme_host}{port}")));
            }
        }
    }

    #[test]
    fn a_host_wildcard_warning_names_every_matching_host() {
        for (origin, pattern_host, admitted, ports) in [
            (
                "https://*.example.com",
                "*.example.com",
                "https://evil.example.com",
                "from ANY host",
            ),
            // not only a leading label
            (
                "https://example.*",
                "example.*",
                "https://example.evil",
                "from ANY host",
            ),
            (
                "http://app.*.test:5460",
                "app.*.test",
                "http://app.evil.test:5460",
                "from that port on ANY host",
            ),
            (
                "http://192.168.1.*",
                "192.168.1.*",
                "http://192.168.1.77",
                "from ANY host",
            ),
        ] {
            let text = warning(origin);
            assert!(text.starts_with("host wildcard: "), "{origin}: {text}");
            assert!(
                text.contains(&format!(
                    "{ports} matching `{pattern_host}` (each `*` is any one label)"
                )),
                "{origin}: {text}"
            );
            assert!(text.contains("DNS rebinding"), "{origin}: {text}");
            assert!(text.contains("session cookie"), "{origin}: {text}");
            assert!(!text.contains("ANY port"), "{origin}: {text}");
            let list = patterns(origin);
            assert!(list.allows(admitted), "{origin}");
            // the `Host` check opens for the same host
            let host = admitted.split_once("://").unwrap().1;
            assert!(list.allows_host(host), "{origin}");
        }
    }

    #[test]
    fn a_whole_host_wildcard_warning_says_no_label_is_fixed() {
        for (origin, shape, admitted) in [
            (
                "http://*",
                "every single-label name, `localhost` included",
                vec!["http://localhost", "http://intranet"],
            ),
            (
                "https://*.*",
                "every hostname of 2 labels",
                vec!["https://evil.example", "https://example.com"],
            ),
            (
                "https://*.*.*",
                "every hostname of 3 labels",
                vec!["https://www.evil.example"],
            ),
            (
                "http://*.*.*.*",
                "every IPv4 address and every four-label hostname",
                vec!["http://10.0.0.7", "http://203.0.113.9", "http://a.b.c.d"],
            ),
        ] {
            let text = warning(origin);
            assert!(text.starts_with("host wildcard: "), "{origin}: {text}");
            assert!(text.contains("ANY host of that shape"), "{origin}: {text}");
            assert!(text.contains("is fixed"), "{origin}: {text}");
            assert!(text.contains(shape), "{origin}: {text}");
            assert!(text.contains("DNS rebinding"), "{origin}: {text}");
            assert!(!text.contains("ANY port"), "{origin}: {text}");
            let list = patterns(origin);
            for origin in admitted {
                assert!(list.allows(origin), "{origin}");
                let host = origin.split_once("://").unwrap().1;
                assert!(list.allows_host(host), "{origin}");
            }
        }
    }

    #[test]
    fn a_host_and_port_wildcard_warning_says_both() {
        for (origin, hosts, admitted) in [
            (
                "https://*.example.com:*",
                "ANY port on ANY host matching `*.example.com`",
                "https://evil.example.com:8443",
            ),
            (
                "http://*:*",
                "ANY port on ANY host of that shape (no label of `*` is fixed: every \
                 single-label name, `localhost` included) is an allowed origin",
                "http://localhost:5173",
            ),
            (
                "http://*.*.*.*:*",
                "ANY port on ANY host of that shape (no label of `*.*.*.*` is fixed: every \
                 IPv4 address",
                "http://192.168.1.10:9000",
            ),
        ] {
            let text = warning(origin);
            assert!(
                text.starts_with("host and port wildcard: "),
                "{origin}: {text}"
            );
            assert!(text.contains(hosts), "{origin}: {text}");
            assert!(text.contains("DNS rebinding"), "{origin}: {text}");
            let list = patterns(origin);
            assert!(list.allows(admitted), "{origin}");
            let host = admitted.split_once("://").unwrap().1;
            assert!(list.allows_host(host), "{origin}");
        }
    }

    #[test]
    fn without_the_host_gate_no_host_sentence() {
        for origin in ["http://localhost:*", "https://*.example.com", "http://*:*"] {
            let text = origin_wildcard_warning(&pattern(origin), &with(false, None)).unwrap();
            assert!(!text.contains("`Host` check"), "{origin}: {text}");
            assert!(!text.contains("DNS rebinding"), "{origin}: {text}");
        }
    }

    /// The `warn` lines `run` logs, captured.
    fn captured_warnings(run: impl FnOnce()) -> Vec<String> {
        #[derive(Clone, Default)]
        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .filter(|line| line.contains("WARN"))
            .map(str::to_owned)
            .collect()
    }

    const MIXED: &str = "https://app.example, http://localhost:*, https://*.example.com";

    #[test]
    fn a_wildcard_is_refused_without_the_flag() {
        let mut result = Ok(());
        let warnings = captured_warnings(|| {
            result = admit_origin_wildcards(
                &patterns(MIXED),
                false,
                "FUZ_ALLOWED_ORIGINS",
                &OriginWildcardOptions::DEFAULT,
            );
        });
        let message = result.expect_err("refused").0;
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(
            message.starts_with(
                "FUZ_ALLOWED_ORIGINS holds a wildcard entry, refused unless \
                 FUZ_ALLOW_ORIGIN_WILDCARDS=true. "
            ),
            "{message}"
        );
        // each entry, with what it admits; the exact one not at all
        assert!(
            message.contains(
                "`http://localhost:*`: port wildcard: a page served from ANY port on `localhost`"
            ),
            "{message}"
        );
        assert!(
            message.contains("`https://*.example.com`: host wildcard: a page served from ANY host"),
            "{message}"
        );
        assert!(!message.contains("`https://app.example`"), "{message}");
    }

    #[test]
    fn a_wildcard_is_admitted_and_warned_with_the_flag() {
        let options = with(true, Some("The app note."));
        let mut result = Err(ServerEnvError(String::new()));
        let warnings = captured_warnings(|| {
            result =
                admit_origin_wildcards(&patterns(MIXED), true, "APP_ALLOWED_ORIGINS", &options);
        });
        result.expect("admitted");
        assert_eq!(warnings.len(), 2, "one per wildcard entry: {warnings:?}");
        let expected = |origin: &str| {
            format!(
                "APP_ALLOWED_ORIGINS: {}",
                origin_wildcard_warning(&pattern(origin), &options).unwrap()
            )
        };
        assert!(
            warnings[0].contains(&expected("http://localhost:*"))
                && warnings[0].contains("origin=http://localhost:*"),
            "{warnings:?}"
        );
        assert!(
            warnings[1].contains(&expected("https://*.example.com"))
                && warnings[1].contains("origin=https://*.example.com"),
            "{warnings:?}"
        );
    }

    #[test]
    fn an_exact_list_passes_silently_either_way() {
        for allowed in [false, true] {
            let mut result = Err(ServerEnvError(String::new()));
            let warnings = captured_warnings(|| {
                result = admit_origin_wildcards(
                    &patterns("https://app.example, http://[::1]:3000"),
                    allowed,
                    "FUZ_ALLOWED_ORIGINS",
                    &OriginWildcardOptions::DEFAULT,
                );
            });
            result.expect("an exact list passes");
            assert!(warnings.is_empty(), "{warnings:?}");
        }
    }

    #[test]
    fn the_flag_is_exactly_true_or_false() {
        assert_eq!(parse_allow_origin_wildcards(None), Ok(false));
        assert_eq!(parse_allow_origin_wildcards(Some("false")), Ok(false));
        assert_eq!(parse_allow_origin_wildcards(Some("true")), Ok(true));
        for value in [
            "", " ", "TRUE", "True", "1", "yes", "on", " true", "true ", "0",
        ] {
            let message = parse_allow_origin_wildcards(Some(value))
                .expect_err(value)
                .0;
            assert!(
                message.starts_with("FUZ_ALLOW_ORIGIN_WILDCARDS: expected `true` or `false`, got "),
                "{value:?}: {message}"
            );
        }
    }
}
