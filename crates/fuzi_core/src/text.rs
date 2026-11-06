//! Untrusted text: the characters fuzi refuses in a name it creates, and
//! where it escapes strings it did not write.
//!
//! Lockfile keys, a link's `resolved`, bin names, a sibling `package.json`'s
//! `name` and `version`, a symlink's text, a tarball's entry names — all of it
//! is data someone else chose, and all of it ends up either on disk (as a
//! directory or symlink name) or in a message. Two rules follow:
//!
//! - **On disk.** A placed `node_modules` key is held to npm's own package-name
//!   characters ([`is_package_name_char`], an allowlist): no key npm writes for
//!   a real package is affected, and a lookalike letter or an odd space cannot
//!   pass for another package. A link's sibling segment and a bin's command
//!   and target are names npm does not constrain — a sibling directory may be
//!   legitimately Unicode — so those refuse the
//!   [unprintable](fuz_sys::text::is_unprintable) characters only (a
//!   denylist): a name built to read as another one in a listing (a bidi
//!   override, a zero-width or blank character) or to drive the terminal that
//!   prints it.
//! - **In a message.** Every structured payload (a refusal's key, a problem's
//!   detail, a warning) carries its strings raw, and every *human* rendering —
//!   the [`FuziError`](crate::FuziError) `Display` bodies and the `fuzi`
//!   binary's own lines — passes each one through
//!   [`escape_untrusted`](fuz_sys::text::escape_untrusted). A field can then
//!   neither emit a control sequence nor add a line to the message it is
//!   printed in. The escaping is wider than the denylist: a non-ASCII space is
//!   a legitimate character in a directory name and is spelled out in a
//!   message all the same.
//!
//! The denylist and the escaping are `fuz_sys::text`'s, shared with the
//! release crates' messages; the allowlist is fuzi's own.

/// True iff `c` may appear in an npm package name: an ASCII letter or digit,
/// or one of `-._~!'()*` — the characters `encodeURIComponent` leaves alone,
/// which is npm's own rule for a name (`@` and `/` are the scope's structure,
/// not name characters).
pub const fn is_package_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '!' | '\'' | '(' | ')' | '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_name_chars_are_exactly_what_encode_uri_component_keeps() {
        let kept: String = (0..=0x0010_ffff_u32)
            .filter_map(char::from_u32)
            .filter(|c| is_package_name_char(*c))
            .collect();
        assert_eq!(
            kept,
            "!'()*-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
        );
    }
}
