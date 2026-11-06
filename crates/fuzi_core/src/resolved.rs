//! Classify a `resolved` URL by fetch scheme and host — the SSRF/metadata floor
//! that gates which tarball URLs `classify` will hand to the fetch phase.
//!
//! SECURITY — SSRF floor, not a full guard. The `https`-only rule blocks plaintext
//! exfil and the integrity gate makes a tampered `resolved`'s *response* useless
//! (wrong bytes fail the sha512). The host block adds defense-in-depth so a
//! tampered lock cannot make fuzi fire a GET at an internal endpoint before
//! the integrity check runs — covering both **literal internal IPs** and
//! **internal hosts reached by name** (`localhost`, any single-label host with
//! no dot, and the internal-use suffixes `.localhost` / `.local` / `.internal`
//! — the last covering `metadata.google.internal` and
//! `instance-data.ec2.internal`).
//!
//! The literal layer judges what the WHATWG host parser folds a host to
//! (decimal / hex / octal / shortened IPv4 forms become `Ipv4`, bracketed
//! literals `Ipv6`): IPv4 loopback, link-local, private, shared (CGNAT
//! `100.64.0.0/10`, which also holds Alibaba Cloud's `100.100.100.200`
//! metadata endpoint), this-network (`0.0.0.0/8`), IETF protocol assignments
//! (`192.0.0.0/24`), benchmarking (`198.18.0.0/15`), broadcast, multicast, and
//! reserved (`240.0.0.0/4`); IPv6 loopback, unspecified, unique-local,
//! link-local, site-local, multicast, Teredo (`2001::/32`), and the local-use
//! NAT64 prefix (`64:ff9b:1::/48`, whose IPv4 embedding is operator-chosen);
//! and every IPv6 form that carries an IPv4 address a translator or tunnel
//! would deliver to —
//! IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`), SIIT
//! IPv4-translated (`::ffff:0:a.b.c.d`), well-known NAT64 (`64:ff9b::/96`), and
//! 6to4 (`2002::/16`) — judged by that embedded IPv4.
//!
//! What it still does NOT catch — a *public, dotted, public-TLD hostname that
//! resolves to an internal IP at connect time* (DNS rebinding, including to a
//! CGNAT address — only the literal is caught). Closing that
//! means checking the resolved addresses, which reqwest's
//! `ClientBuilder::dns_resolver` hook makes possible (a resolver that filters
//! what it returns); v0 does not install one, and npm has the same gap.
//! Teredo is blocked whole rather than unwrapped: a crafted literal can carry
//! any IPv4 in its obfuscated client field, and no registry is served from a
//! Teredo address. Every `resolved` URL in the fuz
//! projects' own lockfiles is `registry.npmjs.org`, so the block never fires on
//! a legitimate lock.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The fetch-scheme + host classification of a `resolved` value.
pub enum ResolvedKind {
    /// An `https` URL aimed at a public host — accepted (integrity is the trust gate).
    Https,
    /// A `git+…` dependency — refused (not a fetchable tarball).
    Git,
    /// A `file:` URL or bare relative path — refused (not a fetchable tarball).
    File,
    /// A parseable URL with a non-`https` scheme (`http`, `ftp`, …) — refused.
    NonHttps,
    /// An `https` URL whose host is blocked as an SSRF/metadata risk; carries a
    /// short reason naming the class: a localhost, single-label, or
    /// internal-use-domain name, or a loopback, link-local, private, shared
    /// (CGNAT), this-network, IETF protocol-assignment, benchmarking, reserved,
    /// unique-local, site-local, unspecified, broadcast, multicast, Teredo, or
    /// local-use NAT64 address (an embedded IPv4 is judged and named as itself).
    Blocked(&'static str),
}

/// Classify a `resolved` URL by scheme and host. Any `https://` tarball aimed at
/// a public host is accepted (the integrity is the trust gate);
/// `git+…`/`file:`/relative/non-https are refused, and an `https` URL pointing at
/// a loopback / link-local / private / metadata host (or `localhost`) is blocked.
pub fn classify_resolved(resolved: &str) -> ResolvedKind {
    if resolved.starts_with("git+") {
        return ResolvedKind::Git;
    }
    if resolved.starts_with("file:") {
        return ResolvedKind::File;
    }
    match url::Url::parse(resolved) {
        Ok(u) if u.scheme() == "https" => {
            blocked_host_reason(&u).map_or(ResolvedKind::Https, ResolvedKind::Blocked)
        }
        // A parseable URL with a non-https scheme (http, ftp, …).
        Ok(_) => ResolvedKind::NonHttps,
        // Not a URL at all — a bare relative path (`../x`, `vendor/x`).
        Err(_) => ResolvedKind::File,
    }
}

/// Internal-use domain suffixes (leading dot) a tarball URL must never target:
/// `.localhost` (RFC 6761 loopback), `.local` (RFC 6762 mDNS / local network), and
/// `.internal` (ICANN-reserved private use — also the home of
/// `metadata.google.internal` and `instance-data.ec2.internal`). A public registry
/// is always a multi-label FQDN under a public TLD, so these never match a
/// legitimate lock.
const INTERNAL_DOMAIN_SUFFIXES: &[&str] = &[".localhost", ".local", ".internal"];

/// The reason an `https` URL's host is an SSRF/internal-target risk, or `None` for
/// a fine public host. Catches literal internal IPs and internal hosts named
/// directly (`localhost`, any single-label/dotless host, and the
/// [`INTERNAL_DOMAIN_SUFFIXES`]). The residual it deliberately does *not* cover is
/// a public dotted hostname that *resolves* to an internal IP at connect time (DNS
/// rebinding — see the module-level SECURITY note).
fn blocked_host_reason(url: &url::Url) -> Option<&'static str> {
    match url.host()? {
        url::Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name == "localhost" || name.ends_with(".localhost") {
                Some("localhost")
            } else if !name.contains('.') {
                // A dotless host resolves only via local search domains
                // (`metadata`, `intranet`, a short internal name) — never a public
                // registry, which is always a dotted FQDN.
                Some("single-label (internal) host")
            } else if INTERNAL_DOMAIN_SUFFIXES.iter().any(|s| name.ends_with(s)) {
                Some("internal-use domain")
            } else {
                None
            }
        }
        url::Host::Ipv4(ip) => ipv4_block_reason(ip),
        url::Host::Ipv6(ip) => ipv6_block_reason(ip),
    }
}

/// Block-reason for an IPv4 literal host (loopback / link-local / private / …).
///
/// The shared, IETF protocol-assignment, benchmarking, this-network, and
/// reserved ranges are matched by bits (`Ipv4Addr::is_shared`,
/// `is_benchmarking`, and `is_reserved` are still unstable). Order
/// matters where ranges nest: `0.0.0.0` keeps its own reason inside
/// `0.0.0.0/8`, and `255.255.255.255` inside `240.0.0.0/4`.
const fn ipv4_block_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let [a, b, c, _] = ip.octets();
    if ip.is_loopback() {
        Some("loopback address")
    } else if ip.is_link_local() {
        Some("link-local address (cloud-metadata range)")
    } else if ip.is_private() {
        Some("private address")
    } else if a == 100 && (b & 0xc0) == 0x40 {
        // 100.64.0.0/10, RFC 6598
        Some("shared address (CGNAT range)")
    } else if a == 192 && b == 0 && c == 0 {
        // 192.0.0.0/24, RFC 6890 IETF protocol assignments
        Some("IETF protocol-assignment address")
    } else if a == 198 && (b & 0xfe) == 18 {
        // 198.18.0.0/15, RFC 2544 benchmarking
        Some("benchmarking address")
    } else if ip.is_unspecified() {
        Some("unspecified address")
    } else if a == 0 {
        // 0.0.0.0/8, RFC 791 "this network"; Linux routes it to the local host
        Some("this-network address")
    } else if ip.is_broadcast() {
        Some("broadcast address")
    } else if ip.is_multicast() {
        Some("multicast address")
    } else if (a & 0xf0) == 0xf0 {
        // 240.0.0.0/4, RFC 1112 reserved
        Some("reserved address")
    } else {
        None
    }
}

/// Block-reason for an IPv6 literal host.
///
/// An address carrying an IPv4 one a translator or tunnel would deliver to is
/// judged by that IPv4 ([`embedded_ipv4`]); the IPv6-native internal ranges
/// are matched by prefix (the `std` predicates for most are still unstable).
const fn ipv6_block_reason(ip: Ipv6Addr) -> Option<&'static str> {
    // Before the embedded-IPv4 check: `::1` and `::` sit inside the
    // IPv4-compatible `::/96` and would otherwise read as `0.0.0.1` / `0.0.0.0`.
    if ip.is_loopback() {
        return Some("loopback address");
    }
    if ip.is_unspecified() {
        return Some("unspecified address");
    }
    if let Some(v4) = embedded_ipv4(ip) {
        return ipv4_block_reason(v4);
    }
    let segments = ip.segments();
    let first = segments[0];
    if (first & 0xfe00) == 0xfc00 {
        return Some("unique-local address");
    }
    if (first & 0xffc0) == 0xfe80 {
        return Some("link-local address");
    }
    if (first & 0xffc0) == 0xfec0 {
        return Some("site-local address");
    }
    if ip.is_multicast() {
        return Some("multicast address");
    }
    // RFC 4380 Teredo, `2001::/32`: blocked whole, since a crafted literal can
    // carry any IPv4 in its client field and no registry lives on Teredo.
    if first == 0x2001 && segments[1] == 0 {
        return Some("Teredo address");
    }
    // RFC 8215 local-use NAT64: the operator picks the IPv4 embedding, so the
    // address can't be unwrapped — and it never names a public host.
    if first == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001 {
        return Some("local-use NAT64 address");
    }
    None
}

/// The IPv4 address an IPv6 literal delivers to, for the forms that carry one
/// at a fixed position: IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96`
/// (deprecated, still routed by some stacks), SIIT IPv4-translated
/// `::ffff:0:0:0/96`, well-known NAT64 `64:ff9b::/96`, and 6to4 `2002::/16`
/// (the IPv4 in segments 1–2).
const fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = ip.octets();
    match ip.segments() {
        // IPv4-mapped, IPv4-compatible, SIIT IPv4-translated, well-known
        // NAT64: the IPv4 is the low 32 bits.
        [0, 0, 0, 0, 0, 0xffff | 0, _, _]
        | [0, 0, 0, 0, 0xffff, 0, _, _]
        | [0x0064, 0xff9b, 0, 0, 0, 0, _, _] => Some(Ipv4Addr::new(o[12], o[13], o[14], o[15])),
        // 6to4: the IPv4 follows the 16-bit prefix.
        [0x2002, ..] => Some(Ipv4Addr::new(o[2], o[3], o[4], o[5])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_https_is_accepted() {
        assert!(matches!(
            classify_resolved("https://registry.npmjs.org/x/-/x-1.0.0.tgz"),
            ResolvedKind::Https
        ));
        assert!(matches!(
            classify_resolved("https://npm.example.com/x/-/x-1.0.0.tgz"),
            ResolvedKind::Https
        ));
    }

    #[test]
    fn git_and_file_schemes_classified() {
        assert!(matches!(
            classify_resolved("git+https://github.com/x/y.git#abc"),
            ResolvedKind::Git
        ));
        assert!(matches!(classify_resolved("file:../x"), ResolvedKind::File));
        // A bare relative path is not a URL — treated as a file dep.
        assert!(matches!(classify_resolved("../x"), ResolvedKind::File));
    }

    #[test]
    fn non_https_scheme_classified() {
        assert!(matches!(
            classify_resolved("http://registry.npmjs.org/x.tgz"),
            ResolvedKind::NonHttps
        ));
        // `git://` (no `git+` prefix) is a non-https scheme, not a git dep.
        assert!(matches!(
            classify_resolved("git://github.com/x/y.git"),
            ResolvedKind::NonHttps
        ));
    }

    #[test]
    fn internal_and_metadata_hosts_blocked() {
        for url in [
            "https://localhost:4873/x/-/x-1.0.0.tgz",   // localhost
            "https://169.254.169.254/latest/meta-data", // ipv4 link-local (cloud metadata)
            "https://127.0.0.1/x/-/x-1.0.0.tgz",        // ipv4 loopback
            "https://10.0.0.5/x/-/x-1.0.0.tgz",         // ipv4 private
            "https://192.168.1.1/x/-/x-1.0.0.tgz",      // ipv4 private
            "https://[::1]/x/-/x-1.0.0.tgz",            // ipv6 loopback
            "https://[fd00::1]/x/-/x-1.0.0.tgz",        // ipv6 unique-local
        ] {
            assert!(
                matches!(classify_resolved(url), ResolvedKind::Blocked(_)),
                "{url} should be a blocked host"
            );
        }
    }

    #[test]
    fn internal_hosts_named_directly_blocked() {
        // The cloud-metadata endpoint and internal services reached by NAME rather
        // than literal IP — the by-name SSRF path the literal-IP block alone misses.
        for url in [
            "https://metadata.google.internal/computeMetadata/v1/x/-/x-1.0.0.tgz", // GCP metadata FQDN
            "https://instance-data.ec2.internal/x/-/x-1.0.0.tgz", // AWS metadata FQDN
            "https://registry.internal/x/-/x-1.0.0.tgz",          // .internal suffix
            "https://npm.local/x/-/x-1.0.0.tgz",                  // mDNS .local
            "https://foo.localhost/x/-/x-1.0.0.tgz",              // .localhost
            "https://metadata/x/-/x-1.0.0.tgz",                   // single-label (dotless)
            "https://intranet/x/-/x-1.0.0.tgz",                   // single-label (dotless)
        ] {
            assert!(
                matches!(classify_resolved(url), ResolvedKind::Blocked(_)),
                "{url} should be a blocked host"
            );
        }
    }

    #[test]
    fn public_registry_hosts_still_accepted() {
        // Multi-label FQDNs under public TLDs must NOT be blocked (no regression).
        for url in [
            "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
            "https://npm.example.com/x/-/x-1.0.0.tgz",
            "https://cdn.jsdelivr.net/x/-/x-1.0.0.tgz",
            "https://my-registry.internal.example.com/x/-/x-1.0.0.tgz", // ".internal." in the middle, public TLD
        ] {
            assert!(
                matches!(classify_resolved(url), ResolvedKind::Https),
                "{url} should be accepted"
            );
        }
    }

    /// The host parser's folds, pinned: every spelling of an internal address
    /// the WHATWG parser normalizes reaches the literal layer as the address
    /// itself.
    #[test]
    fn folded_spellings_of_internal_hosts_are_blocked() {
        for url in [
            "https://2130706433/x.tgz",          // decimal 127.0.0.1
            "https://0x7f000001/x.tgz",          // hex
            "https://0x7f.0.0.1/x.tgz",          // hex octet
            "https://0177.0.0.1/x.tgz",          // octal octet
            "https://127.1/x.tgz",               // shortened
            "https://0xa9.0xfe.0xa9.0xfe/x.tgz", // 169.254.169.254, hex
            "https://[::ffff:127.0.0.1]/x.tgz",  // IPv4-mapped
            "https://[::ffff:7f00:1]/x.tgz",     // IPv4-mapped, hex
            "https://localhost./x.tgz",          // trailing dot
            "https://LOCALHOST/x.tgz",           // case
            "https://Metadata.Google.Internal./x.tgz",
            "https://%6c%6f%63%61%6c%68%6f%73%74/x.tgz", // percent-encoded localhost
            "https://127.0.0.1./x.tgz",                  // trailing dot on a literal
        ] {
            assert!(
                matches!(classify_resolved(url), ResolvedKind::Blocked(_)),
                "{url} should be a blocked host"
            );
        }
    }

    #[test]
    fn ipv6_forms_embedding_an_internal_ipv4_are_blocked() {
        for (url, reason) in [
            ("https://[::127.0.0.1]/x.tgz", "loopback address"), // IPv4-compatible
            (
                "https://[::ffff:0:a9fe:a9fe]/x.tgz",
                "link-local address (cloud-metadata range)",
            ), // SIIT
            ("https://[64:ff9b::10.0.0.1]/x.tgz", "private address"), // NAT64
            (
                "https://[64:ff9b::a9fe:a9fe]/x.tgz",
                "link-local address (cloud-metadata range)",
            ),
            ("https://[2002:7f00:1::]/x.tgz", "loopback address"), // 6to4
            ("https://[2002:c0a8:101::1]/x.tgz", "private address"), // 6to4 192.168.1.1
            ("https://[64:ff9b:1::1]/x.tgz", "local-use NAT64 address"),
            ("https://[fec0::1]/x.tgz", "site-local address"),
            ("https://[ff02::1]/x.tgz", "multicast address"),
            ("https://224.0.0.1/x.tgz", "multicast address"),
            ("https://239.255.255.250/x.tgz", "multicast address"),
            ("https://[::ffff:224.0.0.1]/x.tgz", "multicast address"),
            ("https://[::]/x.tgz", "unspecified address"),
            ("https://[fe80::1]/x.tgz", "link-local address"),
        ] {
            match classify_resolved(url) {
                ResolvedKind::Blocked(got) => assert_eq!(got, reason, "{url}"),
                _ => panic!("{url} should be a blocked host"),
            }
        }
    }

    /// The ranges `std` has no stable predicate for, matched by bits — direct,
    /// and through the IPv6 embedding forms.
    #[test]
    fn special_purpose_ranges_are_blocked() {
        const CGNAT: &str = "shared address (CGNAT range)";
        const THIS: &str = "this-network address";
        const RESERVED: &str = "reserved address";
        for (url, reason) in [
            ("https://100.64.0.1/x.tgz", CGNAT),
            ("https://100.100.100.200/x.tgz", CGNAT), // Alibaba Cloud metadata
            ("https://100.127.255.255/x.tgz", CGNAT),
            ("https://[::ffff:100.100.100.200]/x.tgz", CGNAT),
            ("https://[64:ff9b::6464:64c8]/x.tgz", CGNAT),
            ("https://[2002:6440:1::]/x.tgz", CGNAT),
            ("https://0.0.0.0/x.tgz", "unspecified address"),
            ("https://0.1.2.3/x.tgz", THIS),
            ("https://0.255.255.255/x.tgz", THIS),
            ("https://[::ffff:0.1.2.3]/x.tgz", THIS),
            ("https://[::0.1.2.3]/x.tgz", THIS), // IPv4-compatible
            ("https://240.0.0.1/x.tgz", RESERVED),
            ("https://254.255.255.255/x.tgz", RESERVED),
            ("https://255.255.255.254/x.tgz", RESERVED),
            ("https://255.255.255.255/x.tgz", "broadcast address"),
            ("https://[::ffff:240.0.0.1]/x.tgz", RESERVED),
            ("https://[2002:f000:1::]/x.tgz", RESERVED),
            (
                "https://192.0.0.192/x.tgz",
                "IETF protocol-assignment address",
            ),
            (
                "https://192.0.0.0/x.tgz",
                "IETF protocol-assignment address",
            ),
            (
                "https://192.0.0.255/x.tgz",
                "IETF protocol-assignment address",
            ),
            ("https://198.18.0.1/x.tgz", "benchmarking address"),
            ("https://198.19.255.255/x.tgz", "benchmarking address"),
            ("https://[::ffff:198.18.0.1]/x.tgz", "benchmarking address"),
            (
                "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/x.tgz",
                "Teredo address",
            ),
            ("https://[2001::1]/x.tgz", "Teredo address"),
        ] {
            match classify_resolved(url) {
                ResolvedKind::Blocked(got) => assert_eq!(got, reason, "{url}"),
                _ => panic!("{url} should be a blocked host"),
            }
        }
    }

    #[test]
    fn public_and_just_outside_blocked_ranges_are_accepted() {
        // Unwrapping judges the embedded address; a public one is not blocked.
        for url in [
            "https://[::ffff:104.16.0.35]/x.tgz",
            "https://[64:ff9b::104.16.0.35]/x.tgz",
            "https://[2002:6810:23::1]/x.tgz",
            "https://[2606:4700::6810:23]/x.tgz", // plain global IPv6
            "https://104.16.0.35/x.tgz",
            // just outside the CGNAT /10, past 0/8, and below multicast + reserved
            "https://100.63.255.255/x.tgz",
            // just outside 192.0.0.0/24, 198.18.0.0/15, and Teredo's 2001::/32
            "https://192.0.1.0/x.tgz",
            "https://198.17.255.255/x.tgz",
            "https://198.20.0.0/x.tgz",
            "https://[2001:1::1]/x.tgz",
            "https://[2001:4860:4860::8888]/x.tgz",
            "https://100.128.0.0/x.tgz",
            "https://223.255.255.255/x.tgz",
            "https://1.0.0.1/x.tgz",
        ] {
            assert!(
                matches!(classify_resolved(url), ResolvedKind::Https),
                "{url} should be accepted"
            );
        }
    }
}
