//! Timestamp utilities
//!
//! RFC 3339 timestamp functions for signatures and metadata.

/// Returns current UTC time as RFC 3339 string (truncated to seconds).
///
/// Used for `signed_at` in signatures and `created_at` in meta.json.
///
/// Format: `2025-01-15T10:30:00Z` (UTC, no subseconds)
///
/// # Panics
///
/// Never panics - RFC 3339 formatting of `OffsetDateTime` is infallible.
#[expect(
    clippy::expect_used,
    reason = "RFC 3339 formatting of `OffsetDateTime` cannot fail"
)]
pub fn rfc3339_now() -> String {
    let full = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting cannot fail");
    // Truncate to seconds: take YYYY-MM-DDTHH:MM:SS (19 chars) and append Z
    // This removes subseconds and timezone offset (+00:00 -> Z)
    if full.len() >= 19 {
        format!("{}Z", &full[..19])
    } else {
        full
    }
}

/// Whether `s` is an RFC 3339 timestamp in the one shape [`rfc3339_now`]
/// emits: `YYYY-MM-DDTHH:MM:SSZ` (UTC `Z` suffix, second precision).
///
/// Structure only, not calendar validity — `9999-99-99T99:99:99Z` passes. The
/// timestamps this gates (a key file's creation date, a release record's
/// times) are publisher-asserted; the one comparison made
/// against a clock (a release log backfill refusing a manifest dated after its
/// own run) is a string comparison this fixed shape makes valid. The fixed
/// shape is also what keeps them ASCII and unambiguous to every reader.
#[must_use]
pub fn is_rfc3339_utc_seconds(s: &str) -> bool {
    // Format: 2025-01-15T10:30:00Z (20 chars)
    let bytes = s.as_bytes();
    bytes.len() == 20
        && bytes[19] == b'Z'
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_now_format() {
        let ts = rfc3339_now();
        // Exact format: 2025-01-15T10:30:00Z (20 chars, no subseconds)
        assert_eq!(ts.len(), 20, "should be exactly 20 chars: {ts}");
        assert!(ts.ends_with('Z'), "should end with Z: {ts}");
        assert!(ts.contains('T'), "should have T separator: {ts}");
        assert_eq!(ts.matches('-').count(), 2, "should have 2 dashes: {ts}");
        assert_eq!(ts.matches(':').count(), 2, "should have 2 colons: {ts}");
    }

    #[test]
    fn is_rfc3339_utc_seconds_accepts_valid() {
        assert!(is_rfc3339_utc_seconds("2025-01-15T10:30:00Z"));
        assert!(is_rfc3339_utc_seconds("2024-12-31T23:59:59Z"));
        assert!(is_rfc3339_utc_seconds("2000-01-01T00:00:00Z"));
    }

    #[test]
    fn is_rfc3339_utc_seconds_rejects_invalid() {
        // Wrong length
        assert!(!is_rfc3339_utc_seconds(""));
        assert!(!is_rfc3339_utc_seconds("2025-01-15T10:30:00"));
        assert!(!is_rfc3339_utc_seconds("2025-01-15T10:30:00Z extra"));
        // Wrong suffix
        assert!(!is_rfc3339_utc_seconds("2025-01-15T10:30:00+00:00"));
        assert!(!is_rfc3339_utc_seconds("2025-01-15T10:30:00z"));
        assert!(!is_rfc3339_utc_seconds("2025-01-15T10:30:00.5Z"));
        // Wrong separators
        assert!(!is_rfc3339_utc_seconds("2025/01/15T10:30:00Z"));
        assert!(!is_rfc3339_utc_seconds("2025-01-15 10:30:00Z"));
        assert!(!is_rfc3339_utc_seconds("2025-01-15T10-30:00Z"));
        assert!(!is_rfc3339_utc_seconds("2025-01/15T10:30:00Z"));
        // Non-digits
        assert!(!is_rfc3339_utc_seconds("XXXX-01-15T10:30:00Z"));
        assert!(!is_rfc3339_utc_seconds("2025-0a-15T10:30:00Z"));
        // Multi-byte input of the right byte length is not a timestamp (and
        // must not panic on a char boundary).
        assert!(!is_rfc3339_utc_seconds("2025-01-15T10:30:\u{e9}Z"));
    }

    #[test]
    fn rfc3339_now_is_rfc3339_utc_seconds() {
        assert!(is_rfc3339_utc_seconds(&rfc3339_now()));
    }
}
