//! Trusted-proxy parsing + matching.
//!
//! The matcher and parser split across four modules:
//!
//! - [`crate::ip_canonical`] — `normalize_ip` + `validate_ip_strict`
//! - [`crate::parsed_proxy`] — `ParsedProxy` type + `ProxyParseError`
//! - this file — `parse_proxy_entry`, `parse_proxy_list`, `is_trusted_ip`
//! - [`crate::ip_resolve`] — `resolve_client_ip` + middleware + `ClientIp`
//!
//! ## Divergences from `fuz_app`'s `http/proxy.ts`
//!
//! Two deliberate parity inversions, both tightening the Rust side
//! relative to the TS source.
//!
//! 1. **`normalize_ip` canonicalizes IPv6** (in [`crate::ip_canonical`]).
//!    Equivalent forms collapse to one bucket key.
//! 2. **No Referer fallback in origin check** (in [`crate::origin`]).
//!
//! ## Strict-IP validation
//!
//! Rust's `std::net::IpAddr::from_str` is materially stricter than the
//! JS helpers `fuz_app`'s TS port defends against — it already rejects
//! bracketed forms (`[::1]:8080`), embedded whitespace (`::1\n`,
//! `::1 `), colon-injection (`attacker:controlled`), and IPv4-with-port
//! (`203.0.113.1:8080`). The two-layer guard inside
//! [`crate::ip_canonical::validate_ip_strict`] is therefore mostly
//! redundant on Rust, but kept verbatim with the TS port so the
//! rate-limit-key poisoning hole stays closed even if a future
//! refactor swaps the parser.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::ip_canonical::{IpFamily, normalize_ip, validate_ip_strict};
use crate::parsed_proxy::{ParsedProxy, ProxyParseError};

// -- Parsing ------------------------------------------------------------------

/// Parse a trusted-proxy entry string into a [`ParsedProxy`].
///
/// Accepts plain IPs (`127.0.0.1`, `::1`) and CIDR notation
/// (`10.0.0.0/8`, `fe80::/10`). Plain IPs are normalized (lowercase,
/// `::ffff:` stripped on IPv4-mapped IPv6) and validated. CIDR prefixes
/// are validated against family bounds and the network address must be
/// network-aligned (host bits zero) — a non-aligned entry like
/// `10.0.0.5/8` is almost certainly a config mistake and refusing it
/// surfaces the error at startup instead of producing surprising match
/// results at runtime. A `/0` prefix is refused for either family
/// ([`ProxyParseError::PrefixZero`]): it trusts every client as a proxy, so
/// the client's own `X-Forwarded-For` would choose the IP every per-IP limiter
/// keys on.
///
/// # Errors
///
/// Returns [`ProxyParseError`] on malformed input. See variants for the
/// specific failure modes.
pub fn parse_proxy_entry(entry: &str) -> Result<ParsedProxy, ProxyParseError> {
    let Some(slash_index) = entry.find('/') else {
        let normalized = normalize_ip(entry);
        if validate_ip_strict(&normalized).is_none() {
            return Err(ProxyParseError::InvalidIp(entry.to_owned()));
        }
        let addr = IpAddr::from_str(&normalized)
            .map_err(|_| ProxyParseError::InvalidIp(entry.to_owned()))?;
        return Ok(ParsedProxy::Ip(addr));
    };

    let network_str = &entry[..slash_index];
    let prefix_str = &entry[slash_index + 1..];

    // Match fuz_app's exact prefix-parsing diagnostics: NaN before
    // negative before not-an-integer. The `.parse::<i32>()` already
    // rejects `8.5`, but reparsing the canonical form back to the
    // original input catches inputs like `08` whose canonical form
    // differs from the source — same posture as the TS port. The
    // `i32` intermediate is so negative inputs surface as
    // `PrefixNegative` rather than `PrefixNaN` (a `u8` parse would
    // collapse both into a single "not a number" diagnostic).
    let prefix: i32 = prefix_str
        .parse()
        .map_err(|_| ProxyParseError::PrefixNaN(entry.to_owned()))?;
    if prefix < 0 {
        return Err(ProxyParseError::PrefixNegative(entry.to_owned()));
    }
    if prefix.to_string() != prefix_str {
        return Err(ProxyParseError::PrefixNotInteger(entry.to_owned()));
    }

    let normalized_network = normalize_ip(network_str);
    let Some(family) = validate_ip_strict(&normalized_network) else {
        return Err(ProxyParseError::InvalidCidr(entry.to_owned()));
    };
    if prefix == 0 {
        return Err(ProxyParseError::PrefixZero(entry.to_owned()));
    }

    match family {
        IpFamily::V4 => {
            if prefix > 32 {
                return Err(ProxyParseError::PrefixV4OutOfRange(entry.to_owned()));
            }
            // Safe: prefix ∈ [1, 32] after the checks above.
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "prefix bounded to 1..=32"
            )]
            let prefix_u8 = prefix as u8;
            let v4: Ipv4Addr = normalized_network
                .parse()
                .map_err(|_| ProxyParseError::InvalidCidr(entry.to_owned()))?;
            let network = u128::from(u32::from(v4));
            let host_mask: u128 = if prefix_u8 == 32 {
                0
            } else {
                (1u128 << (32 - prefix_u8)) - 1
            };
            if network & host_mask != 0 {
                return Err(ProxyParseError::HostBitsSet(entry.to_owned()));
            }
            Ok(ParsedProxy::Cidr {
                network,
                prefix: prefix_u8,
                family: IpFamily::V4,
            })
        }
        IpFamily::V6 => {
            if prefix > 128 {
                return Err(ProxyParseError::PrefixV6OutOfRange(entry.to_owned()));
            }
            // Safe: prefix ∈ [1, 128] after the checks above.
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "prefix bounded to 1..=128"
            )]
            let prefix_u8 = prefix as u8;
            let v6: Ipv6Addr = normalized_network
                .parse()
                .map_err(|_| ProxyParseError::InvalidCidr(entry.to_owned()))?;
            let network = u128::from(v6);
            // `/0` is refused above, so the shift width stays in [0, 127]
            // (`1u128 << 128` would overflow).
            let host_mask: u128 = match prefix_u8 {
                128 => 0,
                n => (1u128 << (128 - n)) - 1,
            };
            if network & host_mask != 0 {
                return Err(ProxyParseError::HostBitsSet(entry.to_owned()));
            }
            Ok(ParsedProxy::Cidr {
                network,
                prefix: prefix_u8,
                family: IpFamily::V6,
            })
        }
    }
}

/// Parse a comma-separated string of trusted-proxy entries.
///
/// Empty or whitespace-only entries are skipped silently — operators
/// can leave trailing commas or use empty strings to opt out without
/// startup errors. Any non-empty entry that fails to parse fails the
/// whole call so the misconfiguration surfaces at startup rather than
/// silently leaving a hole in the trust set.
///
/// # Errors
///
/// Returns the first [`ProxyParseError`] encountered.
pub fn parse_proxy_list(value: &str) -> Result<Vec<ParsedProxy>, ProxyParseError> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_proxy_entry)
        .collect()
}

// -- Matching -----------------------------------------------------------------

fn ip_to_bits(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

const fn cidr_contains(ip_bits: u128, network: u128, prefix: u8, total_bits: u8) -> bool {
    // Exact-match prefix (`prefix == total_bits`) yields `shift = 0` —
    // the shift is a no-op and the comparison is over the full value.
    //
    // `parse_proxy_entry` never yields a /0, but `ParsedProxy` is
    // constructible directly: an IPv6 /0 would produce `shift = 128`, and a
    // u128 shift by 128 overflows, so the `shift >= 128` branch below keeps
    // that a match rather than a panic.
    let shift = total_bits - prefix;
    if shift >= 128 {
        return true;
    }
    (ip_bits >> shift) == (network >> shift)
}

/// Check whether `ip` matches any entry in the trusted-proxy list.
///
/// `ip` is normalized and validated before matching — malformed input
/// returns `false` without panicking.
#[must_use]
pub fn is_trusted_ip(ip: &str, proxies: &[ParsedProxy]) -> bool {
    let normalized = normalize_ip(ip);
    let Some(family) = validate_ip_strict(&normalized) else {
        return false;
    };
    let Ok(addr) = IpAddr::from_str(&normalized) else {
        return false;
    };
    let ip_bits = ip_to_bits(addr);

    for proxy in proxies {
        match proxy {
            ParsedProxy::Ip(proxy_ip) => {
                if *proxy_ip == addr {
                    return true;
                }
            }
            ParsedProxy::Cidr {
                network,
                prefix,
                family: cidr_family,
            } => {
                if *cidr_family != family {
                    // Cross-family CIDR matches are always false — `::/0`
                    // is "all IPv6", not "all addresses".
                    continue;
                }
                let total_bits = match family {
                    IpFamily::V4 => 32u8,
                    IpFamily::V6 => 128u8,
                };
                if cidr_contains(ip_bits, *network, *prefix, total_bits) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies(entries: &[&str]) -> Vec<ParsedProxy> {
        entries
            .iter()
            .map(|e| parse_proxy_entry(e).unwrap())
            .collect()
    }

    // -- parse_proxy_entry ----------------------------------------------------

    #[test]
    fn an_unparseable_mapped_form_is_not_a_proxy_entry() {
        // Stripping `::ffff:` before the parse once read this as `::1.2.3.4`.
        assert!(parse_proxy_entry("::ffff:::1.2.3.4").is_err());
    }

    #[test]
    fn parse_plain_ipv4() {
        let p = parse_proxy_entry("127.0.0.1").unwrap();
        assert!(matches!(p, ParsedProxy::Ip(IpAddr::V4(_))));
    }

    #[test]
    fn parse_plain_ipv6() {
        let p = parse_proxy_entry("::1").unwrap();
        assert!(matches!(p, ParsedProxy::Ip(IpAddr::V6(_))));
    }

    #[test]
    fn parse_normalizes_ipv4_mapped_to_plain_v4() {
        let p = parse_proxy_entry("::ffff:127.0.0.1").unwrap();
        assert!(matches!(p, ParsedProxy::Ip(IpAddr::V4(_))));
    }

    #[test]
    fn parse_lowercases_ipv6() {
        let p = parse_proxy_entry("FE80::1").unwrap();
        if let ParsedProxy::Ip(addr) = p {
            assert_eq!(addr.to_string(), "fe80::1");
        } else {
            panic!("expected ParsedProxy::Ip");
        }
    }

    #[test]
    fn parse_ipv4_cidr() {
        let p = parse_proxy_entry("10.0.0.0/8").unwrap();
        assert!(matches!(
            p,
            ParsedProxy::Cidr {
                prefix: 8,
                family: IpFamily::V4,
                ..
            }
        ));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let p = parse_proxy_entry("fe80::/10").unwrap();
        assert!(matches!(
            p,
            ParsedProxy::Cidr {
                prefix: 10,
                family: IpFamily::V6,
                ..
            }
        ));
    }

    #[test]
    fn parse_refuses_slash_zero_naming_the_entry() {
        // A /0 trusts every client as a proxy — the client's own XFF would
        // pick every per-IP bucket — so it fails at parse time, for either
        // family and aligned or not, and the error names the entry.
        for entry in [
            "0.0.0.0/0",
            "::/0",
            "10.0.0.0/0",
            "fe80::/0",
            "::ffff:0.0.0.0/0",
        ] {
            let err = parse_proxy_entry(entry).unwrap_err();
            assert!(
                matches!(&err, ProxyParseError::PrefixZero(e) if e == entry),
                "{entry}: {err:?}"
            );
            assert!(err.to_string().contains(entry), "{entry}: {err}");
        }
        // the narrowest real ranges still parse
        assert!(matches!(
            parse_proxy_entry("0.0.0.0/1"),
            Ok(ParsedProxy::Cidr { prefix: 1, .. })
        ));
        assert!(matches!(
            parse_proxy_entry("::/1"),
            Ok(ParsedProxy::Cidr { prefix: 1, .. })
        ));
        // shape errors still come first
        assert!(matches!(
            parse_proxy_entry("hello/0"),
            Err(ProxyParseError::InvalidCidr(_))
        ));
    }

    #[test]
    fn parse_ipv4_slash_thirty_two_as_cidr() {
        let p = parse_proxy_entry("192.168.1.1/32").unwrap();
        assert!(matches!(p, ParsedProxy::Cidr { prefix: 32, .. }));
    }

    #[test]
    fn parse_rejects_invalid_ip() {
        assert!(matches!(
            parse_proxy_entry("hello"),
            Err(ProxyParseError::InvalidIp(_))
        ));
        assert!(matches!(
            parse_proxy_entry(""),
            Err(ProxyParseError::InvalidIp(_))
        ));
    }

    #[test]
    fn parse_rejects_non_aligned_v4_cidr() {
        assert!(matches!(
            parse_proxy_entry("10.0.0.5/8"),
            Err(ProxyParseError::HostBitsSet(_))
        ));
    }

    #[test]
    fn parse_rejects_non_aligned_v6_cidr() {
        assert!(matches!(
            parse_proxy_entry("fe80::1/10"),
            Err(ProxyParseError::HostBitsSet(_))
        ));
    }

    #[test]
    fn parse_rejects_v4_prefix_over_range() {
        assert!(matches!(
            parse_proxy_entry("10.0.0.0/33"),
            Err(ProxyParseError::PrefixV4OutOfRange(_))
        ));
    }

    #[test]
    fn parse_rejects_v6_prefix_over_range() {
        assert!(matches!(
            parse_proxy_entry("::1/129"),
            Err(ProxyParseError::PrefixV6OutOfRange(_))
        ));
    }

    #[test]
    fn parse_rejects_nan_prefix() {
        assert!(matches!(
            parse_proxy_entry("10.0.0.0/abc"),
            Err(ProxyParseError::PrefixNaN(_))
        ));
    }

    #[test]
    fn parse_rejects_negative_prefix() {
        assert!(matches!(
            parse_proxy_entry("10.0.0.0/-1"),
            Err(ProxyParseError::PrefixNegative(_))
        ));
    }

    #[test]
    fn parse_rejects_empty_prefix() {
        assert!(matches!(
            parse_proxy_entry("10.0.0.0/"),
            Err(ProxyParseError::PrefixNaN(_))
        ));
    }

    #[test]
    fn parse_rejects_invalid_cidr_network() {
        assert!(matches!(
            parse_proxy_entry("not-an-ip/8"),
            Err(ProxyParseError::InvalidCidr(_))
        ));
    }

    // -- parse_proxy_list -----------------------------------------------------

    #[test]
    fn parse_list_empty_string() {
        assert!(parse_proxy_list("").unwrap().is_empty());
    }

    #[test]
    fn parse_list_whitespace_only() {
        assert!(parse_proxy_list("   ").unwrap().is_empty());
    }

    #[test]
    fn parse_list_two_entries() {
        let v = parse_proxy_list("127.0.0.1, 10.0.0.0/8").unwrap();
        assert_eq!(v.len(), 2);
        assert!(matches!(v[0], ParsedProxy::Ip(_)));
        assert!(matches!(v[1], ParsedProxy::Cidr { .. }));
    }

    #[test]
    fn parse_list_tolerates_trailing_comma() {
        let v = parse_proxy_list("127.0.0.1,").unwrap();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn parse_list_tolerates_leading_whitespace() {
        let v = parse_proxy_list("  127.0.0.1").unwrap();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn parse_list_tolerates_internal_empty_segments() {
        let v = parse_proxy_list("127.0.0.1,,10.0.0.0/8").unwrap();
        assert_eq!(v.len(), 2);
        let v = parse_proxy_list("127.0.0.1, , 10.0.0.0/8").unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn parse_list_fails_fast_on_any_bad_entry() {
        assert!(parse_proxy_list("127.0.0.1, garbage").is_err());
    }

    // -- is_trusted_ip --------------------------------------------------------

    #[test]
    fn trusted_exact_ipv4_match() {
        let p = proxies(&["127.0.0.1"]);
        assert!(is_trusted_ip("127.0.0.1", &p));
        assert!(!is_trusted_ip("127.0.0.2", &p));
    }

    #[test]
    fn trusted_exact_ipv6_match_case_insensitive() {
        let p = proxies(&["FE80::1"]);
        assert!(is_trusted_ip("fe80::1", &p));
        assert!(is_trusted_ip("FE80::1", &p));
        assert!(is_trusted_ip("Fe80::1", &p));
    }

    #[test]
    fn trusted_v4_cidr_slash_eight() {
        let p = proxies(&["10.0.0.0/8"]);
        assert!(is_trusted_ip("10.0.0.1", &p));
        assert!(is_trusted_ip("10.255.255.255", &p));
        assert!(!is_trusted_ip("11.0.0.1", &p));
        assert!(!is_trusted_ip("9.255.255.255", &p));
    }

    #[test]
    fn trusted_v4_cidr_slash_thirty_two_exact() {
        let p = proxies(&["10.0.0.1/32"]);
        assert!(is_trusted_ip("10.0.0.1", &p));
        assert!(!is_trusted_ip("10.0.0.2", &p));
    }

    #[test]
    fn trusted_v6_cidr_slash_ten() {
        let p = proxies(&["fe80::/10"]);
        assert!(is_trusted_ip("fe80::1", &p));
        assert!(is_trusted_ip("febf::1", &p));
        assert!(!is_trusted_ip("fec0::1", &p));
    }

    /// A directly constructed `/0` — the parser refuses one, so these pin the
    /// matcher alone: the family guard and the `shift >= 128` branch.
    fn slash_zero(family: IpFamily) -> Vec<ParsedProxy> {
        vec![ParsedProxy::Cidr {
            network: 0,
            prefix: 0,
            family,
        }]
    }

    #[test]
    fn trusted_cross_family_guard_v4_zero_does_not_match_v6() {
        let p = slash_zero(IpFamily::V4);
        assert!(!is_trusted_ip("::1", &p));
        assert!(!is_trusted_ip("fe80::1", &p));
        assert!(!is_trusted_ip("2001:db8::1", &p));
    }

    #[test]
    fn trusted_cross_family_guard_v6_zero_does_not_match_v4() {
        let p = slash_zero(IpFamily::V6);
        assert!(!is_trusted_ip("127.0.0.1", &p));
        assert!(!is_trusted_ip("10.0.0.1", &p));
    }

    #[test]
    fn trusted_v4_zero_matches_all_v4() {
        let p = slash_zero(IpFamily::V4);
        assert!(is_trusted_ip("0.0.0.0", &p));
        assert!(is_trusted_ip("1.2.3.4", &p));
        assert!(is_trusted_ip("255.255.255.255", &p));
    }

    #[test]
    fn trusted_v6_zero_matches_all_v6() {
        // Exercises the cidr_contains shift>=128 branch.
        let p = slash_zero(IpFamily::V6);
        assert!(is_trusted_ip("::", &p));
        assert!(is_trusted_ip("::1", &p));
        assert!(is_trusted_ip("fe80::1", &p));
        assert!(is_trusted_ip("2001:db8::1", &p));
    }

    #[test]
    fn trusted_v4_mapped_v6_matches_plain_v4_proxy() {
        let p = proxies(&["127.0.0.1"]);
        assert!(is_trusted_ip("::ffff:127.0.0.1", &p));
    }

    #[test]
    fn trusted_v4_mapped_v6_matches_v4_cidr() {
        let p = proxies(&["10.0.0.0/8"]);
        assert!(is_trusted_ip("::ffff:10.1.2.3", &p));
        assert!(!is_trusted_ip("::ffff:11.0.0.1", &p));
    }

    #[test]
    fn trusted_v4_mapped_in_config_matches_plain_v4_input() {
        let p = proxies(&["::ffff:127.0.0.1"]);
        assert!(is_trusted_ip("127.0.0.1", &p));
    }

    #[test]
    fn trusted_malformed_input_returns_false_does_not_panic() {
        let p = proxies(&["2001:db8::/32"]);
        assert!(!is_trusted_ip("attacker:controlled", &p));
        assert!(!is_trusted_ip("203.0.113.1:8080", &p));
        assert!(!is_trusted_ip("[::1]:8080", &p));
        assert!(!is_trusted_ip("", &p));
        assert!(!is_trusted_ip("not-an-ip", &p));
    }

    #[test]
    fn trusted_empty_proxy_list_returns_false() {
        assert!(!is_trusted_ip("127.0.0.1", &[]));
        assert!(!is_trusted_ip("::1", &[]));
    }

    #[test]
    fn trusted_v4_cidr_slash_sixteen_in_range() {
        let p = proxies(&["10.1.0.0/16"]);
        assert!(is_trusted_ip("10.1.0.1", &p));
        assert!(is_trusted_ip("10.1.255.255", &p));
        assert!(!is_trusted_ip("10.2.0.1", &p));
    }

    // -- cidr_contains --------------------------------------------------------

    // These exercise the private helper directly — the public matchers
    // are also tested above but `cidr_contains` has UB-adjacent corners
    // that deserve isolated coverage.

    #[test]
    fn cidr_contains_v4_slash_zero_matches_all() {
        assert!(cidr_contains(0, 0, 0, 32));
        assert!(cidr_contains(0xFFFF_FFFF, 0, 0, 32));
        assert!(cidr_contains(0x0A00_0001, 0, 0, 32));
    }

    #[test]
    fn cidr_contains_v6_slash_zero_matches_all() {
        // Shift = 128 path — must not UB on u128 right-shift.
        assert!(cidr_contains(0, 0, 0, 128));
        assert!(cidr_contains(u128::MAX, 0, 0, 128));
        assert!(cidr_contains(
            0xfe80_0000_0000_0000_0000_0000_0000_0001,
            0,
            0,
            128
        ));
    }

    #[test]
    fn cidr_contains_exact_match_prefix() {
        // shift = 0 path.
        assert!(cidr_contains(42, 42, 32, 32));
        assert!(!cidr_contains(42, 43, 32, 32));
        assert!(cidr_contains(u128::MAX, u128::MAX, 128, 128));
    }

    #[test]
    fn cidr_contains_v4_slash_twenty_four() {
        let net = 0x0A00_0000u128;
        assert!(cidr_contains(0x0A00_0000, net, 24, 32));
        assert!(cidr_contains(0x0A00_00FF, net, 24, 32));
        assert!(!cidr_contains(0x0A00_0100, net, 24, 32));
        assert!(!cidr_contains(0x0AFF_FFFF, net, 24, 32));
    }
}
