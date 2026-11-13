//! Small random helpers shared across the workspace.

use std::fmt::Write as _;

/// Generate a cryptographically random lowercase-hex string of `2 * num_bytes`
/// chars (`num_bytes` random bytes, hex-encoded).
///
/// # Panics
///
/// Panics if the OS RNG fails (should never happen on a healthy system).
#[expect(
    clippy::expect_used,
    reason = "getrandom only fails if the OS RNG is broken"
)]
#[must_use]
pub fn random_hex(num_bytes: usize) -> String {
    let mut bytes = vec![0u8; num_bytes];
    getrandom::fill(&mut bytes).expect("getrandom failed");
    let mut s = String::with_capacity(num_bytes * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Generate a cryptographically random hex suffix (16 hex chars / 64 bits).
///
/// Used for temp directory and file names — the entropy keeps two concurrent
/// writers of the same target from sharing (and clobbering) a temp path.
#[must_use]
pub fn random_hex_suffix() -> String {
    random_hex(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_suffix_is_16_chars() {
        let suffix = random_hex_suffix();
        assert_eq!(suffix.len(), 16);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_hex_suffix_varies() {
        assert_ne!(random_hex_suffix(), random_hex_suffix());
    }
}
