//! Trusted-proxy entry types — split out of `proxy.rs` so the data
//! shape and its parse errors stay distinct from the matcher logic.
//!
//! A CIDR entry's family is [`crate::ip_canonical::IpFamily`] — the validator
//! and the matcher share one vocabulary.

use std::net::IpAddr;

use crate::ip_canonical::IpFamily;

/// A parsed trusted-proxy entry — either an exact IP or a CIDR range.
///
/// `Cidr.network` carries the address bits widened to `u128` so IPv4
/// and IPv6 share one match path. For IPv4 entries the low 32 bits hold
/// the network address; the upper 96 are zero by construction in
/// [`crate::proxy::parse_proxy_entry`].
#[derive(Debug, Clone)]
pub enum ParsedProxy {
    Ip(IpAddr),
    Cidr {
        network: u128,
        prefix: u8,
        family: IpFamily,
    },
}

/// Errors surfaced by [`crate::proxy::parse_proxy_entry`] at server
/// startup.
///
/// Variants mirror the diagnostics in `fuz_app`'s `parse_proxy_entry`
/// (`Invalid proxy IP`, `Invalid CIDR prefix (not a number)`, etc.) so
/// operators porting from the TS deployment see the same messages.
///
/// Validate trusted-proxies config **eagerly at boot** — `fuz_http` carries
/// the behavior to every consumer.
#[derive(Debug, thiserror::Error)]
pub enum ProxyParseError {
    #[error("invalid proxy IP: {0}")]
    InvalidIp(String),
    #[error("invalid CIDR prefix (not a number): {0}")]
    PrefixNaN(String),
    #[error("invalid CIDR prefix (negative): {0}")]
    PrefixNegative(String),
    #[error("invalid CIDR prefix (not an integer): {0}")]
    PrefixNotInteger(String),
    /// A `/0` entry (`0.0.0.0/0`, `::/0`) trusts every address of its family
    /// as a proxy, so any client's `X-Forwarded-For` picks the IP every per-IP
    /// limiter keys on. Refused rather than honored.
    #[error("CIDR prefix 0 trusts every address as a proxy: {0}")]
    PrefixZero(String),
    #[error("invalid CIDR prefix for IPv4 (max 32): {0}")]
    PrefixV4OutOfRange(String),
    #[error("invalid CIDR prefix for IPv6 (max 128): {0}")]
    PrefixV6OutOfRange(String),
    #[error("non-network-aligned CIDR (host bits set): {0}")]
    HostBitsSet(String),
    #[error("invalid proxy CIDR: {0}")]
    InvalidCidr(String),
}
