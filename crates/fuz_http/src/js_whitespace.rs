//! JS whitespace: the set `String.prototype.trim` strips, for inputs the TS
//! twin trims.
//!
//! Rust's `str::trim` strips Unicode `White_Space`; JS's `trim` strips the
//! ECMAScript `WhiteSpace` and `LineTerminator` code points. The two sets
//! differ by two characters: U+0085 (NEL) is `White_Space` but not JS
//! whitespace, and U+FEFF (ZWNBSP / BOM) is JS whitespace but not
//! `White_Space`. Every other member is shared — the ASCII controls TAB, LF,
//! VT, FF, CR, plus every `Zs` space separator, LS (U+2028) and PS (U+2029).
//!
//! A trimmed value that reaches the wire — a login identifier, an
//! `X-Forwarded-For` entry — trims through [`trim_js_whitespace`] so a padded
//! input answers the same on both spines.

/// True iff `c` is whitespace to JS `String.prototype.trim`.
#[must_use]
const fn is_js_whitespace(c: char) -> bool {
    (c.is_whitespace() && c != '\u{85}') || c == '\u{FEFF}'
}

/// Trim leading and trailing JS whitespace, as `String.prototype.trim` does.
#[must_use]
pub fn trim_js_whitespace(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_what_js_trims() {
        // U+FEFF is JS whitespace though not Unicode `White_Space`
        assert_eq!(trim_js_whitespace("\u{FEFF}alice\u{FEFF}"), "alice");
        for c in [
            '\t', '\n', '\u{B}', '\u{C}', '\r', ' ', '\u{A0}', '\u{1680}', '\u{2000}', '\u{200A}',
            '\u{2028}', '\u{2029}', '\u{202F}', '\u{205F}', '\u{3000}',
        ] {
            let padded = format!("{c}alice{c}");
            assert_eq!(
                trim_js_whitespace(&padded),
                "alice",
                "U+{:04X}",
                u32::from(c)
            );
        }
    }

    #[test]
    fn keeps_what_js_keeps() {
        // U+0085 is Unicode `White_Space` but not JS whitespace
        assert_eq!(trim_js_whitespace("\u{85}alice\u{85}"), "\u{85}alice\u{85}");
        // zero-width space is neither
        assert_eq!(trim_js_whitespace("\u{200B}alice"), "\u{200B}alice");
        assert_eq!(trim_js_whitespace(" a b "), "a b");
    }
}
