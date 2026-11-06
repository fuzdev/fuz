//! IP literal canonicalization + strict validation.
//!
//! Split out of the monolithic `proxy.rs` lift so the canonicalization
//! contract (RFC 5952 IPv6 + IPv4-mapped collapse) can be tested in
//! isolation from the trusted-proxy matcher.
//!
//! ## RFC 5952 IPv6 canonicalization (deliberate parity inversion)
//!
//! Rust's `Ipv6Addr` Display emits RFC 5952 canonical form (lowercase
//! hex, longest-zero-run compressed, IPv4-mapped dotted notation). The
//! port routes every input through `IpAddr::from_str` then re-emits via
//! `to_string()` so `::1`, `::01`, `::0001`, and
//! `0:0:0:0:0:0:0:1` collapse to one bucket key.
//!
//! `fuz_app`'s `http/ip_canonical.ts` mirrors this. `fuz_app`'s
//! `http/proxy.ts::normalize_ip` delegates to that `canonicalize_ip`
//! helper, so the equivalent-forms-collapse contract holds on both
//! surfaces.
//!
//! ## Rate-limit keys
//!
//! [`rate_limit_ip_key`] is the bucket key an IP-keyed rate limiter uses: an
//! IPv6 address collapses to its `/64`, the smallest block a host is
//! commonly assigned, so rotating through one's own subnet buys no fresh
//! budget. Only the limiter call sites apply it — the client IP the
//! middleware resolves stays the full address everywhere else (audit rows,
//! token `last_used_ip`, `REMOTE_ADDR`).

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

/// IP address family. Used by [`crate::proxy::is_trusted_ip`] to keep
/// CIDR matches from crossing families (`0.0.0.0/0` must not match
/// IPv6, and vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

/// Lowercase + canonicalize the IP literal, then strip `::ffff:` prefix
/// on IPv4-mapped IPv6.
///
/// Three-step pipeline:
///
/// 1. ASCII-lowercase. Necessary for both the `::ffff:` strip and the
///    parser round-trip below (consistent input).
/// 2. If the result parses as a real IP, re-emit via `to_string()` —
///    RFC 5952 canonical form. Closes the rate-limit-key poisoning
///    surface where `::1`, `::01`, and `0:0:0:0:0:0:0:1` would
///    otherwise produce three different bucket keys for the same
///    address.
/// 3. On a successful parse only, strip `::ffff:` when the suffix
///    contains `.` — IPv4-mapped IPv6 collapses to plain IPv4 so it
///    matches v4-trusted-proxy entries and rate-limit keys consistently.
///    The strip moves AFTER canonicalization because Rust's `Ipv6Addr`
///    Display emits the dotted IPv4-mapped form; without the reordering,
///    `::ffff:0:0` (no dot) and `::ffff:0.0.0.0` (dotted) would diverge.
///
/// Idempotent. Safe on non-IP strings — `normalize_ip("unknown")`
/// returns `"unknown"` (the canonicalize step is conditional on a
/// successful parse).
#[must_use]
pub fn normalize_ip(ip: &str) -> String {
    let lowered = ip.to_ascii_lowercase();
    let Ok(addr) = IpAddr::from_str(&lowered) else {
        // strip nothing off an unparseable string — `::ffff:1.2.3.4%` stays
        // whole, as `fuz_app`'s `canonicalize_ip` leaves it
        return lowered;
    };
    let canonical = addr.to_string();
    if let Some(rest) = canonical.strip_prefix("::ffff:")
        && rest.contains('.')
    {
        return rest.to_owned();
    }
    canonical
}

/// Strict IP validity check. Returns the address family on success,
/// `None` on any malformed input.
///
/// Two-layer guard:
///
/// 1. Character-set pre-filter (`0-9a-fA-F.:` only). Rejects port
///    suffixes, bracketed forms, embedded whitespace, control bytes —
///    cheap rejection on the hot path before allocator-touching parse.
/// 2. Round-trip through `IpAddr::from_str`.
///
/// On Rust, layer 2 alone catches every shape `fuz_app`'s TS port adds
/// layer 1 to handle (Rust's parser is stricter than JS's). The
/// char-set filter is kept anyway as defense-in-depth + documented
/// intent.
#[must_use]
pub fn validate_ip_strict(ip: &str) -> Option<IpFamily> {
    if ip.is_empty() {
        return None;
    }
    if !ip.chars().all(is_ip_literal_char) {
        return None;
    }
    match IpAddr::from_str(ip) {
        Ok(IpAddr::V4(_)) => Some(IpFamily::V4),
        Ok(IpAddr::V6(_)) => Some(IpFamily::V6),
        Err(_) => None,
    }
}

/// The bucket key an IP-keyed rate limiter uses for client IP `ip`.
///
/// An IPv6 address keys its `/64`: the low 64 bits masked off, rendered in
/// RFC 5952 canonical form with a `/64` suffix (`2001:db8:1:2::/64`; the
/// all-zero prefix is `::/64`). A zone suffix (`%eth0`) is dropped first. An
/// IPv4 address — an IPv4-mapped IPv6 one included — keys its canonical
/// form, with no suffix. Anything that doesn't parse
/// ([`crate::UNRESOLVED_CLIENT_IP`] among them) is returned unchanged. Twin of
/// `fuz_app`'s `rate_limit_ip_key`.
///
/// For limiter keys only: audit rows and every other record of the client
/// keep the full address.
#[must_use]
pub fn rate_limit_ip_key(ip: &str) -> String {
    let bare = ip.split_once('%').map_or(ip, |(address, _zone)| address);
    match IpAddr::from_str(&normalize_ip(bare)) {
        Ok(IpAddr::V6(v6)) => {
            let prefix = Ipv6Addr::from_bits(v6.to_bits() & IPV6_PREFIX_64_MASK);
            format!("{prefix}/64")
        }
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Err(_) => ip.to_owned(),
    }
}

/// The high 64 bits of an IPv6 address — its `/64` network prefix.
const IPV6_PREFIX_64_MASK: u128 = !(u128::MAX >> 64);

const fn is_ip_literal_char(c: char) -> bool {
    matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F' | '.' | ':')
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- normalize_ip ---------------------------------------------------------

    #[test]
    fn normalize_strips_ipv4_mapped_v6_prefix() {
        assert_eq!(normalize_ip("::ffff:127.0.0.1"), "127.0.0.1");
        assert_eq!(normalize_ip("::ffff:10.1.2.3"), "10.1.2.3");
    }

    #[test]
    fn normalize_strips_uppercase_ipv4_mapped_prefix() {
        assert_eq!(normalize_ip("::FFFF:192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn normalize_preserves_ffff_one_no_dot() {
        // `::ffff:1` is a real IPv6 address (g5 = 0, g6 = 0xffff,
        // g7 = 1), NOT an IPv4-mapped form (which requires g5 =
        // 0xffff). The `.` requirement on strip keeps the two cases
        // distinct.
        assert_eq!(normalize_ip("::ffff:1"), "::ffff:1");
    }

    #[test]
    fn normalize_canonicalizes_ipv6_zero_padding() {
        assert_eq!(normalize_ip("::1"), "::1");
        assert_eq!(normalize_ip("::01"), "::1");
        assert_eq!(normalize_ip("::0001"), "::1");
    }

    #[test]
    fn normalize_canonicalizes_ipv6_full_to_compressed() {
        assert_eq!(normalize_ip("0:0:0:0:0:0:0:1"), "::1");
        assert_eq!(
            normalize_ip("0000:0000:0000:0000:0000:0000:0000:0001"),
            "::1"
        );
    }

    #[test]
    fn normalize_canonicalizes_ipv6_explicit_double_colon_run() {
        let a = normalize_ip("2001:0:0:0:1:0:0:1");
        let b = normalize_ip("2001::1:0:0:1");
        assert_eq!(a, b);
        assert_eq!(a, "2001::1:0:0:1");
    }

    #[test]
    fn normalize_ipv4_mapped_collapse_is_order_safe() {
        // The dot-bearing input strips early; the no-dot variant has
        // to canonicalize to the dotted form (Rust's `Ipv6Addr`
        // Display emits IPv4-mapped notation) before stripping. Both
        // must produce the same plain-v4 string.
        assert_eq!(normalize_ip("::ffff:0:0"), "0.0.0.0");
        assert_eq!(normalize_ip("::ffff:0.0.0.0"), "0.0.0.0");
        assert_eq!(normalize_ip("::ffff:7f00:1"), "127.0.0.1");
        assert_eq!(normalize_ip("::ffff:127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn normalize_collapses_equivalent_ipv6_to_same_key() {
        let forms = [
            "::1",
            "::01",
            "::0001",
            "0:0:0:0:0:0:0:1",
            "0000:0000:0000:0000:0000:0000:0000:0001",
        ];
        let canonical = normalize_ip(forms[0]);
        for form in &forms[1..] {
            assert_eq!(normalize_ip(form), canonical, "drift on {form:?}");
        }
    }

    #[test]
    fn normalize_preserves_strictly_invalid_input_unchanged() {
        assert_eq!(normalize_ip("::1\n"), "::1\n");
        assert_eq!(normalize_ip("[::1]:8080"), "[::1]:8080");
        assert_eq!(normalize_ip("203.0.113.1:8080"), "203.0.113.1:8080");
        assert_eq!(normalize_ip("attacker:controlled"), "attacker:controlled");
    }

    #[test]
    fn normalize_strips_nothing_off_unparseable_mapped_forms() {
        // the strip applies only to a parsed address, as in `fuz_app`'s
        // `canonicalize_ip`; each of these would strip to a different string
        assert_eq!(normalize_ip("::ffff:1.2.3.4%"), "::ffff:1.2.3.4%");
        assert_eq!(normalize_ip("::ffff:1.2.3.4%eth0"), "::ffff:1.2.3.4%eth0");
        assert_eq!(normalize_ip("::ffff:999.1.1.1"), "::ffff:999.1.1.1");
        assert_eq!(normalize_ip("::FFFF:1.2.3.4:80"), "::ffff:1.2.3.4:80");
        assert_eq!(normalize_ip("::ffff:::1.2.3.4"), "::ffff:::1.2.3.4");
    }

    #[test]
    fn normalize_lowercases_ipv6() {
        assert_eq!(normalize_ip("FE80::1"), "fe80::1");
        assert_eq!(normalize_ip("2001:DB8::ABCD"), "2001:db8::abcd");
    }

    #[test]
    fn normalize_passes_plain_ipv4_through() {
        assert_eq!(normalize_ip("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn normalize_is_idempotent() {
        for input in [
            "::ffff:127.0.0.1",
            "FE80::1",
            "127.0.0.1",
            "::1",
            "unknown",
            "",
        ] {
            let once = normalize_ip(input);
            let twice = normalize_ip(&once);
            assert_eq!(once, twice, "not idempotent for {input:?}");
        }
    }

    #[test]
    fn normalize_safe_on_non_ip_strings() {
        assert_eq!(normalize_ip("unknown"), "unknown");
        assert_eq!(normalize_ip(""), "");
    }

    // -- rate_limit_ip_key -----------------------------------------------------

    /// The key table, kept identical with `fuz_app`'s
    /// `src/test/http/ip_canonical.test.ts` — the twins must bucket alike.
    const RATE_LIMIT_IP_KEY_CASES: &[(&str, &str)] = &[
        // IPv6 keys its /64
        ("2001:db8:1:2::1", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
        // the /65 bit is still inside the /64
        ("2001:db8:1:2:8000::", "2001:db8:1:2::/64"),
        // the /64 bit is not
        ("2001:db8:1:3::", "2001:db8:1:3::/64"),
        ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
        // so is the /63 bit
        ("2001:db8:1:1::", "2001:db8:1:1::/64"),
        // equivalent forms, uppercase, full width
        (
            "2001:0DB8:0001:0002:0000:0000:0000:0001",
            "2001:db8:1:2::/64",
        ),
        ("2001:db8:0:0:1::", "2001:db8::/64"),
        // the all-zero prefix
        ("::1", "::/64"),
        ("::", "::/64"),
        // canonical compression of the prefix: longest zero run, first on a tie
        ("2001:0:0:1:abcd::", "2001:0:0:1::/64"),
        ("1:0:0:0::5", "1::/64"),
        ("fe80::1", "fe80::/64"),
        // a zone is dropped
        ("fe80::1%eth0", "fe80::/64"),
        ("FE80::ABCD%25", "fe80::/64"),
        // IPv4 unchanged, no /32
        ("203.0.113.7", "203.0.113.7"),
        ("127.0.0.1", "127.0.0.1"),
        // IPv4-mapped IPv6 keys the IPv4 address
        ("::ffff:203.0.113.7", "203.0.113.7"),
        ("::ffff:cb00:7107", "203.0.113.7"),
        // not an address: unchanged — not lowercased, the zone kept
        ("unknown", "unknown"),
        ("UNKNOWN", "UNKNOWN"),
        ("unknown%eth0", "unknown%eth0"),
        ("", ""),
        ("attacker:controlled", "attacker:controlled"),
        ("[::1]:8080", "[::1]:8080"),
        // an unparseable mapped form keeps its `::ffff:` — stripped, `::1.2.3.4` would parse
        ("::ffff:::1.2.3.4", "::ffff:::1.2.3.4"),
    ];

    #[test]
    fn rate_limit_ip_key_table() {
        for (ip, key) in RATE_LIMIT_IP_KEY_CASES {
            assert_eq!(rate_limit_ip_key(ip), *key, "{ip:?}");
        }
    }

    #[test]
    fn rate_limit_ip_key_leaves_an_unparseable_mapped_form_unchanged() {
        // stripping `::ffff:` off this unparseable string left `::1.2.3.4`,
        // which parses, so it keyed `::/64`; `fuz_app` returns it unchanged
        assert_eq!(rate_limit_ip_key("::ffff:::1.2.3.4"), "::ffff:::1.2.3.4");
    }

    #[test]
    fn rate_limit_ip_key_shares_a_bucket_within_a_64_only() {
        let a = rate_limit_ip_key("2001:db8:1:2::1");
        assert_eq!(a, rate_limit_ip_key("2001:db8:1:2:8000::"));
        assert_eq!(a, rate_limit_ip_key("2001:db8:1:2:dead:beef:0:1"));
        assert_ne!(a, rate_limit_ip_key("2001:db8:1:3::"));
        assert_ne!(a, rate_limit_ip_key("2001:db8:1:1:ffff:ffff:ffff:ffff"));
    }

    #[test]
    fn rate_limit_ip_key_is_idempotent() {
        for (ip, _) in RATE_LIMIT_IP_KEY_CASES {
            let once = rate_limit_ip_key(ip);
            assert_eq!(rate_limit_ip_key(&once), once, "{ip:?}");
        }
    }

    // -- validate_ip_strict ---------------------------------------------------

    #[test]
    fn validate_accepts_well_formed_ipv4() {
        assert_eq!(validate_ip_strict("127.0.0.1"), Some(IpFamily::V4));
        assert_eq!(validate_ip_strict("0.0.0.0"), Some(IpFamily::V4));
        assert_eq!(validate_ip_strict("255.255.255.255"), Some(IpFamily::V4));
    }

    #[test]
    fn validate_accepts_well_formed_ipv6() {
        assert_eq!(validate_ip_strict("::1"), Some(IpFamily::V6));
        assert_eq!(validate_ip_strict("::"), Some(IpFamily::V6));
        assert_eq!(validate_ip_strict("2001:db8::1"), Some(IpFamily::V6));
        assert_eq!(validate_ip_strict("fe80::1"), Some(IpFamily::V6));
        assert_eq!(validate_ip_strict("FE80::1"), Some(IpFamily::V6));
    }

    #[test]
    fn validate_accepts_ipv4_mapped_v6() {
        assert_eq!(validate_ip_strict("::ffff:127.0.0.1"), Some(IpFamily::V6));
    }

    #[test]
    fn validate_rejects_empty() {
        assert_eq!(validate_ip_strict(""), None);
    }

    #[test]
    fn validate_rejects_garbage() {
        assert_eq!(validate_ip_strict("not-an-ip"), None);
        assert_eq!(validate_ip_strict("garbage"), None);
    }

    #[test]
    fn validate_rejects_colon_injection() {
        assert_eq!(validate_ip_strict("attacker:controlled"), None);
        assert_eq!(validate_ip_strict("host:port"), None);
        assert_eq!(validate_ip_strict("a:b:c"), None);
    }

    #[test]
    fn validate_rejects_ipv4_with_port() {
        assert_eq!(validate_ip_strict("203.0.113.1:8080"), None);
    }

    #[test]
    fn validate_rejects_bracketed_host_port() {
        assert_eq!(validate_ip_strict("[::1]:8080"), None);
        assert_eq!(validate_ip_strict("[2001:db8::1]:8080"), None);
    }

    #[test]
    fn validate_rejects_embedded_whitespace_or_control() {
        assert_eq!(validate_ip_strict("::1\n"), None);
        assert_eq!(validate_ip_strict("::1 "), None);
        assert_eq!(validate_ip_strict(" ::1"), None);
        assert_eq!(validate_ip_strict("127.0.0.1\t"), None);
    }
}
