//! The untrusted-content hardening headers every served fact carries.
//!
//! Fact bytes are served with a producer-supplied `content_type` emitted
//! verbatim, inline. To stop a fact stored as (or sniffable to) `text/html`
//! from executing as stored XSS for any reader of a referencing cell, every
//! fact response carries [`FACT_SECURITY_HEADERS`]: `X-Content-Type-Options:
//! nosniff` + `Content-Security-Policy: default-src 'none'; sandbox`.
//!
//! The embedded and disk-stream branches set them on the response directly.
//! On the `X-Accel-Redirect` branch nginx serves the bytes from its internal
//! facts location, and a location with its own `add_header` stops the
//! server-level headers from applying — so that location must carry the set
//! itself, as the lines [`fact_security_header_directives`] renders. The
//! X-Accel validator (`crate::nginx`) refuses a facts location without them.
//!
//! The TS twin is `fuz_app`'s `server/fact_security_headers.ts`; both pin the
//! same literals.

/// `X-Content-Type-Options` for fact responses — block MIME sniffing so an
/// `application/octet-stream` fact can't be sniffed into executable HTML.
pub const FACT_X_CONTENT_TYPE_OPTIONS: &str = "nosniff";

/// `Content-Security-Policy` for fact responses.
///
/// A fact stored as (or sniffable to) `text/html` would otherwise execute as
/// stored XSS for any reader of a referencing cell. `default-src 'none';
/// sandbox` neutralizes script execution and sub-resource loads even when a
/// fact is rendered inline; harmless for directly-served images (they load no
/// sub-resources).
pub const FACT_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; sandbox";

/// The fact hardening headers as `(name, value)` pairs, in render order.
///
/// `Content-Disposition: attachment` is deliberately absent — it would
/// force-download and break legitimate inline image rendering.
pub const FACT_SECURITY_HEADERS: [(&str, &str); 2] = [
    ("X-Content-Type-Options", FACT_X_CONTENT_TYPE_OPTIONS),
    ("Content-Security-Policy", FACT_CONTENT_SECURITY_POLICY),
];

/// The exact nginx `add_header … always;` lines the internal facts location
/// must carry, rendered from [`FACT_SECURITY_HEADERS`].
///
/// `always` makes nginx add the header on every status, not just 2xx/3xx.
/// Paste these into the facts `location` block (the X-Accel validator refuses
/// a facts location missing any of them).
#[must_use]
pub fn fact_security_header_directives() -> Vec<String> {
    FACT_SECURITY_HEADERS
        .iter()
        .map(|(name, value)| format!("add_header {name} \"{value}\" always;"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_ts_twin() {
        // Pinned to the same literals as `fuz_app`'s
        // `server/fact_security_headers.ts` — change both together.
        assert_eq!(FACT_X_CONTENT_TYPE_OPTIONS, "nosniff");
        assert_eq!(FACT_CONTENT_SECURITY_POLICY, "default-src 'none'; sandbox");
        assert_eq!(
            fact_security_header_directives(),
            [
                "add_header X-Content-Type-Options \"nosniff\" always;",
                "add_header Content-Security-Policy \"default-src 'none'; sandbox\" always;",
            ]
        );
    }
}
