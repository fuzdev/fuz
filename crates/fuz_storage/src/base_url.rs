//! Base-URL validation shared by the HTTP backends (`ForgeStorage`,
//! `HttpsStorage`), and public so the forge's CLI (`fuzf`) validates its
//! server URL by the same rules rather than a copy of them.
//!
//! Both backends root every request at one configured base URL, and both admit
//! plaintext only for a loopback host. The loopback decision also picks the
//! client's proxy policy — a loopback `http` base bypasses the environment's
//! proxies, so its plaintext request (and the forge's bearer token) never
//! leaves the machine — so it is made here, once, and each backend reads
//! [`BaseUrl::is_https`] instead of re-deriving it from the string.
//!
//! The rules, in the order they are checked:
//!
//! - the base parses as a URL;
//! - the scheme is `https`, or `http` with a loopback host
//!   (`is_loopback_host`); any other scheme is refused;
//! - it names a host;
//! - it carries no userinfo (`user:pass@`) — neither backend authenticates
//!   through the URL, and the forge would send it beside its bearer token;
//! - it carries no query or fragment — the base names a directory that keys
//!   are joined under, not a request.
//!
//! A refusal never echoes the URL, since its userinfo may be a secret.

/// A validated, normalized base URL.
///
/// Readable outside the crate but not constructible there — only
/// [`validate_base_url`] makes one, so holding a `BaseUrl` means the rules
/// passed.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BaseUrl {
    /// The parsed URL re-serialized (scheme and host lowercased) with every
    /// trailing slash removed: scheme + `host[:port]` + any base path. A key
    /// or API path is appended after a `/`.
    pub url: String,
    /// `false` only for the loopback `http` carve-out. The single source of
    /// the backends' proxy decision.
    pub is_https: bool,
}

/// Why a base URL is refused.
///
/// Each message is a clause the backend prefixes with what the URL is for
/// (`invalid forge base URL: …`, the forge's wording being
/// [`crate::forge_base_url_refusal_message`]). No variant carries the URL
/// itself.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BaseUrlRefusal {
    #[error("not a valid URL: {0}")]
    Malformed(url::ParseError),
    #[error("unsupported scheme '{0}' (expected https, or http for a loopback host)")]
    Scheme(String),
    /// An `http` base whose host is not loopback. Carries the host, which
    /// holds no userinfo.
    #[error("refusing plaintext http to non-loopback host '{0}'; use https")]
    PlaintextHost(String),
    #[error("no host")]
    NoHost,
    #[error("must not carry credentials (user:pass@)")]
    Userinfo,
    #[error("must not carry a query or fragment")]
    QueryOrFragment,
}

/// Validate and normalize a base URL (rules in the module doc).
pub fn validate_base_url(base: &str) -> Result<BaseUrl, BaseUrlRefusal> {
    let url = base
        .parse::<url::Url>()
        .map_err(BaseUrlRefusal::Malformed)?;
    let is_https = match url.scheme() {
        "https" => true,
        "http" if is_loopback_host(&url) => false,
        "http" => {
            return Err(BaseUrlRefusal::PlaintextHost(
                url.host_str().unwrap_or_default().to_string(),
            ));
        }
        other => return Err(BaseUrlRefusal::Scheme(other.to_string())),
    };
    if url.host_str().is_none_or(str::is_empty) {
        return Err(BaseUrlRefusal::NoHost);
    }
    if has_userinfo(&url) {
        return Err(BaseUrlRefusal::Userinfo);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(BaseUrlRefusal::QueryOrFragment);
    }
    Ok(BaseUrl {
        url: url.as_str().trim_end_matches('/').to_string(),
        is_https,
    })
}

/// `true` when the URL's host is one a plaintext `http` URL may name: the
/// name `localhost`, or the loopback address `127.0.0.1` or `::1` exactly.
///
/// Matched on the parsed host, so an alternate spelling of the same address
/// (`127.1`, `0x7f.0.0.1`, `[0:0:0:0:0:0:0:1]`) or of the name (`LOCALHOST` —
/// the parser lowercases a special scheme's domain) is recognized. Refused, as
/// deliberately narrow rather than as unsafe: a look-alike name
/// (`localhost.example.com`), the fully-qualified `localhost.`, another
/// address in `127.0.0.0/8`, and the IPv4-mapped `::ffff:127.0.0.1`.
pub(crate) fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(addr)) => addr == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(addr)) => addr == std::net::Ipv6Addr::LOCALHOST,
        None => false,
    }
}

/// `true` when the URL carries a username or password.
pub(crate) fn has_userinfo(url: &url::Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_loopback_http() {
        // (input, normalized url, is_https)
        let cases = [
            (
                "https://forge.example.com",
                "https://forge.example.com",
                true,
            ),
            (
                "https://example.com:8443/base/path//",
                "https://example.com:8443/base/path",
                true,
            ),
            ("HTTPS://Example.COM/", "https://example.com", true),
            ("http://localhost:4041", "http://localhost:4041", false),
            ("http://LOCALHOST", "http://localhost", false),
            ("HTTP://localhost:4041/", "http://localhost:4041", false),
            (
                "http://127.0.0.1:4041/releases",
                "http://127.0.0.1:4041/releases",
                false,
            ),
            ("http://127.1:4041", "http://127.0.0.1:4041", false),
            ("http://[::1]:8080", "http://[::1]:8080", false),
            ("http://[0:0:0:0:0:0:0:1]", "http://[::1]", false),
            (" https://h/base/ \n", "https://h/base", true),
        ];
        for (input, url, is_https) in cases {
            assert_eq!(
                validate_base_url(input),
                Ok(BaseUrl {
                    url: url.to_string(),
                    is_https,
                }),
                "{input}"
            );
        }
    }

    #[test]
    fn refuses_each_rule() {
        let plaintext = |host: &str| BaseUrlRefusal::PlaintextHost(host.to_string());
        let cases = [
            ("http://example.com", plaintext("example.com")),
            ("http://127.0.0.2", plaintext("127.0.0.2")),
            ("http://0.0.0.0", plaintext("0.0.0.0")),
            ("http://[::2]", plaintext("[::2]")),
            ("http://[::ffff:127.0.0.1]", plaintext("[::ffff:7f00:1]")),
            ("http://localhost.", plaintext("localhost.")),
            (
                "http://localhost.example.com",
                plaintext("localhost.example.com"),
            ),
            ("ftp://h", BaseUrlRefusal::Scheme("ftp".to_string())),
            ("file:///srv", BaseUrlRefusal::Scheme("file".to_string())),
            ("http://user:pw@localhost", BaseUrlRefusal::Userinfo),
            ("https://user@h", BaseUrlRefusal::Userinfo),
            ("https://:pw@h", BaseUrlRefusal::Userinfo),
            ("https://h/?q", BaseUrlRefusal::QueryOrFragment),
            ("https://h/?", BaseUrlRefusal::QueryOrFragment),
            ("https://h/#f", BaseUrlRefusal::QueryOrFragment),
            ("http://localhost/#", BaseUrlRefusal::QueryOrFragment),
        ];
        for (input, expected) in cases {
            assert_eq!(validate_base_url(input), Err(expected), "{input}");
        }
        for input in ["https://", "not a url", "", "http://[::1%25lo]"] {
            assert!(
                matches!(validate_base_url(input), Err(BaseUrlRefusal::Malformed(_))),
                "{input}"
            );
        }
    }

    #[test]
    fn refusals_never_echo_userinfo() {
        for input in [
            "https://user:hunter2@example.com",
            "http://user:hunter2@localhost",
            "https://:hunter2@example.com/base",
        ] {
            let message = validate_base_url(input).expect_err(input).to_string();
            assert!(!message.contains("hunter2"), "secret leaked: {message}");
        }
    }
}
