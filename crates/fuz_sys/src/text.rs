//! Untrusted text: which characters do not print, and an escaping form for a
//! string someone else chose.
//!
//! A lockfile key, a storage key, a field of a signed document, a parser's
//! message repeating a token, a symlink's text — data the program did not
//! write ends up in a message, and a message ends up on a terminal or in a
//! log. A string passed through [`escape_untrusted`] on its way there can
//! neither emit a control sequence, add a line to the message it sits in, nor
//! read as something else in a listing. [`quoted`] is the same text in double
//! quotes it cannot close, and [`truncate`] the bound for a value of any
//! length.
//!
//! A value is escaped where it is rendered: a type's `Display`
//! escapes the strings it holds and embeds another error's `Display` as it
//! is. [`escape_message`] is for a whole message on its way into one line —
//! it spells out what is still unprintable and leaves the escapes already
//! there alone.
//!
//! The set is named here rather than left to the standard library's `Debug`
//! tables, which differ between toolchains and leave some blank fillers
//! alone: [`is_unprintable`] is escaped whatever the toolchain, and what
//! `Debug`'s tables escape beyond it is escaped too.

/// True iff `c` is a control character or a character that shows nothing.
///
/// The controls are `char::is_control` — C0, DEL, and C1 (U+009B is a
/// one-character CSI). The rest are the characters that change how the
/// surrounding text *reads* without showing anything themselves — Unicode's
/// default-ignorable code points plus the separators and annotation marks:
/// the bidi marks, embeddings, overrides, and isolates; the zero-width
/// characters and joiners; the soft hyphen and the combining grapheme joiner;
/// the Hangul fillers and the braille blank, which render as empty space; the
/// variation selectors; the line and paragraph separators; the BOM; the
/// interlinear-annotation, shorthand-format, musical-format, and tag
/// characters.
///
/// Spaces are deliberately not here: a no-break or ideographic space is an
/// ordinary character in a directory name. [`escape_untrusted`] spells them
/// out in a message regardless.
pub const fn is_unprintable(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{34f}'
                | '\u{61c}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fffb}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'
        )
}

/// True iff `text` carries any [unprintable](is_unprintable) character.
pub fn has_unprintable(text: &str) -> bool {
    text.chars().any(is_unprintable)
}

/// True iff [`escape_untrusted`] spells `c` as an escape because `c` does not
/// print.
///
/// That is the [`is_unprintable`] set, plus whatever else the standard
/// library's `Debug` tables escape (other format characters, combining marks,
/// unassigned and private-use code points).
///
/// For a caller that escapes into another syntax — JSON's `\uXXXX`, say —
/// and wants the same set.
#[must_use]
pub fn needs_escape(c: char) -> bool {
    is_unprintable(c) || (!matches!(c, '"' | '\'' | '\\') && c.escape_debug().len() > 1)
}

/// `text` with every control, invisible, or otherwise non-printing character
/// escaped (`\n`, `\u{1b}`, `\u{202e}`) and every `\` doubled.
///
/// Text the program did not write can then neither drive the terminal it is
/// printed to, add a line to the message it sits in, nor forge an escape.
/// Quotes are left as they are; the text is not being re-quoted. Printable
/// non-ASCII text passes through.
///
/// The shared escaping form for human output. It does not bound the text: a
/// caller that prints a value of any length cuts it first.
#[must_use]
pub fn escape_untrusted(text: &str) -> String {
    escape(text, Backslash::Double)
}

/// `message` with every character that does not print escaped as
/// [`escape_untrusted`] escapes it, and each `\` left as it is.
///
/// For a message, not a value: text the program composed — an error's
/// `Display`, say — whose untrusted parts were escaped where they were
/// rendered. On its way into one line of a report such a message is passed
/// through this, so anything unprintable still in it (a part some rendering
/// left raw, a newline between its own lines) is spelled out, while the
/// escapes it already holds are not escaped a second time: the result of
/// [`escape_untrusted`] or [`quoted`] passes through unchanged.
///
/// A value goes through [`escape_untrusted`] instead. Here a value's own
/// backslash is not doubled, so its literal `\n` would read as an escaped
/// newline.
#[must_use]
pub fn escape_message(message: &str) -> String {
    escape(message, Backslash::Keep)
}

/// What `escape` does with a `\`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Backslash {
    /// Escape it, so the text's own backslashes cannot pass for escapes.
    Double,
    /// Leave it: the text's backslashes are escapes already.
    Keep,
}

fn escape(text: &str, backslash: Backslash) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '"' | '\'') || (c == '\\' && backslash == Backslash::Keep) {
            out.push(c);
        } else if is_unprintable(c) {
            // Named explicitly rather than left to `escape_debug`'s own tables,
            // so the set is escaped by construction, whatever the toolchain.
            out.extend(c.escape_default());
        } else {
            out.extend(c.escape_debug());
        }
    }
    out
}

/// `value` in double quotes for a message: escaped by [`escape_untrusted`],
/// and each `"` inside it escaped too, so the quoted text ends where the value
/// does.
///
/// Ordinary text reads as its `Debug` form does. Like [`escape_untrusted`] it
/// does not bound the value.
#[must_use]
pub fn quoted(value: &str) -> String {
    format!("\"{}\"", escape_untrusted(value).replace('"', "\\\""))
}

/// `text` whole when it is at most `max` bytes, otherwise its longest prefix
/// that is (cut on a character boundary) with `...` appended.
///
/// The bound for a value of any length on its way into a message. It is taken
/// on the text as it is, before [`escape_untrusted`] or [`quoted`]: the cut
/// text is then escaped whole, so no escape is cut in half.
#[must_use]
pub fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of each class [`is_unprintable`] names.
    const UNPRINTABLE: &[char] = &[
        '\0',
        '\u{7}',
        '\t',
        '\n',
        '\r',
        '\u{1b}',
        '\u{7f}',    // DEL
        '\u{85}',    // C1 NEL
        '\u{9b}',    // C1 CSI
        '\u{ad}',    // soft hyphen
        '\u{34f}',   // combining grapheme joiner
        '\u{61c}',   // Arabic letter mark
        '\u{115f}',  // Hangul choseong filler
        '\u{1160}',  // Hangul jungseong filler
        '\u{17b4}',  // Khmer inherent vowel
        '\u{180b}',  // Mongolian free variation selector
        '\u{180e}',  // Mongolian vowel separator
        '\u{200b}',  // zero-width space
        '\u{200c}',  // zero-width non-joiner
        '\u{200d}',  // zero-width joiner
        '\u{200e}',  // LRM
        '\u{200f}',  // RLM
        '\u{2028}',  // line separator
        '\u{2029}',  // paragraph separator
        '\u{202a}',  // LRE
        '\u{202e}',  // RLO
        '\u{2060}',  // word joiner
        '\u{2066}',  // LRI
        '\u{2069}',  // PDI
        '\u{2800}',  // braille pattern blank
        '\u{3164}',  // Hangul filler
        '\u{fe00}',  // variation selector-1
        '\u{fe0f}',  // variation selector-16
        '\u{feff}',  // BOM
        '\u{ffa0}',  // halfwidth Hangul filler
        '\u{fff0}',  // specials (unassigned, default-ignorable)
        '\u{fff9}',  // interlinear annotation anchor
        '\u{1bca0}', // shorthand format letter overlap
        '\u{1d173}', // musical symbol begin beam
        '\u{e0001}', // language tag
        '\u{e007f}', // cancel tag
        '\u{e0100}', // variation selector-17
        '\u{e0fff}', // end of the default-ignorable tag block
    ];

    /// The spaces besides U+0020: printable enough for a directory name, and
    /// still not something a message should show as a gap.
    const SPACES: &[char] = &[
        '\u{a0}',   // no-break space
        '\u{1680}', // Ogham space mark
        '\u{2000}', // en quad
        '\u{2003}', // em space
        '\u{200a}', // hair space
        '\u{202f}', // narrow no-break space
        '\u{205f}', // medium mathematical space
        '\u{3000}', // ideographic space
    ];

    #[test]
    fn unprintable_covers_controls_and_invisible_characters() {
        for &c in UNPRINTABLE {
            assert!(is_unprintable(c), "{c:?} must be unprintable");
        }
    }

    #[test]
    fn unprintable_leaves_spaces_and_visible_text() {
        for &c in SPACES {
            assert!(!is_unprintable(c), "{c:?}");
        }
        for c in ('a'..='z')
            .chain('A'..='Z')
            .chain('0'..='9')
            .chain("-._~@/ !'()*+".chars())
        {
            assert!(!is_unprintable(c), "{c:?}");
        }
        for c in ['é', 'ß', '日', '\u{301}', '．', '‥', '🙂', '\u{2801}', 'ㄱ'] {
            assert!(!is_unprintable(c), "{c:?}");
        }
    }

    /// The exact spelling of each class, on any toolchain: the blank fillers
    /// are characters `char::escape_debug` leaves alone on some toolchains;
    /// NUL it spells `\0`.
    #[test]
    fn escape_untrusted_spells_each_class_one_way() {
        let cases = [
            // The blank fillers.
            ("a\u{115f}b", "a\\u{115f}b"),
            ("a\u{1160}b", "a\\u{1160}b"),
            ("a\u{3164}b", "a\\u{3164}b"),
            ("a\u{ffa0}b", "a\\u{ffa0}b"),
            ("a\u{2800}b", "a\\u{2800}b"),
            // NUL is spelled like every other control without a short form.
            ("a\0b", "a\\u{0}b"),
            ("a\u{1b}[31mb", "a\\u{1b}[31mb"),
            ("a\u{9b}b", "a\\u{9b}b"),
            // The controls with a short form keep it.
            ("a\tb\rc\nd", "a\\tb\\rc\\nd"),
            // A bidi override, a zero-width space, a variation selector, the
            // line separator.
            ("a\u{202e}b", "a\\u{202e}b"),
            ("a\u{200b}b", "a\\u{200b}b"),
            ("a\u{fe0f}b", "a\\u{fe0f}b"),
            ("a\u{2028}b", "a\\u{2028}b"),
            // Quotes pass; a backslash is doubled, so a literal backslash-n
            // cannot pass for an escaped newline.
            ("it's a \"name\"", "it's a \"name\""),
            ("a\\nb", "a\\\\nb"),
            // Printable non-ASCII passes.
            ("café 日本語 — ok", "café 日本語 — ok"),
            ("", ""),
        ];
        for (text, expected) in cases {
            assert_eq!(escape_untrusted(text), expected, "{text:?}");
        }
    }

    #[test]
    fn escape_untrusted_spells_out_spaces_that_are_not_the_ascii_one() {
        for &c in SPACES {
            let escaped = escape_untrusted(&format!("a{c}b"));
            assert!(needs_escape(c), "{c:?}");
            assert_eq!(escaped, format!("a\\u{{{:x}}}b", u32::from(c)));
        }
        assert_eq!(escape_untrusted("a b"), "a b");
    }

    #[test]
    fn escape_untrusted_leaves_no_unprintable_character() {
        // Every unprintable character is escaped — one at a time, and over the
        // whole Unicode range for the set as a whole.
        for &c in UNPRINTABLE {
            let escaped = escape_untrusted(&format!("a{c}b"));
            assert!(!has_unprintable(&escaped), "{c:?} -> {escaped:?}");
            assert!(escaped.starts_with("a\\") && escaped.ends_with('b'));
        }
        let all: String = (0..=0x0010_ffff_u32).filter_map(char::from_u32).collect();
        assert!(!has_unprintable(&escape_untrusted(&all)));
    }

    #[test]
    fn needs_escape_is_exactly_what_escape_untrusted_escapes_for_not_printing() {
        for c in (0..=0x0010_ffff_u32).filter_map(char::from_u32) {
            let escaped = escape_untrusted(c.encode_utf8(&mut [0; 4]));
            let spelled_out = escaped.chars().count() > 1 && c != '\\';
            assert_eq!(needs_escape(c), spelled_out, "{c:?} -> {escaped}");
        }
        for c in ['a', ' ', '"', '\'', '\\', 'é', '—', '·'] {
            assert!(!needs_escape(c), "{c:?}");
        }
    }

    #[test]
    fn escape_untrusted_spells_escapes_and_doubles_backslashes() {
        assert_eq!(
            escape_untrusted("x\u{1b}[31m\ny\u{202e}z\u{9b}"),
            "x\\u{1b}[31m\\ny\\u{202e}z\\u{9b}"
        );
        // A literal backslash-n in the input cannot pass for an escaped newline.
        assert_eq!(escape_untrusted("a\\nb"), "a\\\\nb");
    }

    #[test]
    fn escape_message_escapes_what_does_not_print_and_keeps_backslashes() {
        // What a rendering left raw is spelled out, as `escape_untrusted`
        // spells it.
        assert_eq!(
            escape_message("a\u{1b}[2K\nb\u{202e}c\u{2800}d\u{a0}e\0"),
            "a\\u{1b}[2K\\nb\\u{202e}c\\u{2800}d\\u{a0}e\\u{0}"
        );
        // A backslash is the message's own: not doubled.
        assert_eq!(
            escape_message("a\\nb \\u{1b} \\\\ c"),
            "a\\nb \\u{1b} \\\\ c"
        );
        assert_eq!(
            escape_message("it's a \"name\" caf\u{e9}"),
            "it's a \"name\" caf\u{e9}"
        );
    }

    /// An escaped value inside a message is not escaped again, whatever the
    /// value: `escape_message` is the identity on what `escape_untrusted` and
    /// `quoted` produce, and on its own output.
    #[test]
    fn escape_message_leaves_escaped_text_as_it_is() {
        let all: String = (0..=0x0010_ffff_u32).filter_map(char::from_u32).collect();
        for escaped in [escape_untrusted(&all), quoted(&all), escape_message(&all)] {
            assert_eq!(escape_message(&escaped), escaped);
            assert!(!has_unprintable(&escape_message(&escaped)));
        }
        let hostile = "x\u{1b}[2K\r\u{202e}\u{2800}\"\\";
        let message = format!(
            "download failed: {} ({})",
            quoted(hostile),
            escape_untrusted(hostile)
        );
        assert_eq!(escape_message(&message), message);
    }

    #[test]
    fn quoted_is_the_value_in_quotes_with_nothing_non_printing() {
        // Ordinary text reads as its `Debug` form does.
        for value in ["", "0.0.1+b1", "../x", "it's", "a\\b", "a\"b", "caf\u{e9}"] {
            assert_eq!(quoted(value), format!("{value:?}"), "{value:?}");
        }
        assert_eq!(quoted("a\"b"), "\"a\\\"b\"");
        // A value cannot close the quotes it is shown in.
        assert_eq!(quoted("x\" (ok) \"y"), "\"x\\\" (ok) \\\"y\"");
        assert_eq!(
            quoted("a\u{1b}[31m\n\u{202e}\u{200b}b"),
            "\"a\\u{1b}[31m\\n\\u{202e}\\u{200b}b\""
        );
        assert_eq!(
            quoted("a\u{115f}\u{1160}\u{3164}\u{ffa0}\u{2800}\0b"),
            "\"a\\u{115f}\\u{1160}\\u{3164}\\u{ffa0}\\u{2800}\\u{0}b\""
        );
    }

    #[test]
    fn truncate_keeps_what_fits_and_cuts_on_a_character_boundary() {
        assert_eq!(truncate("", 0), "");
        assert_eq!(truncate("", 4), "");
        assert_eq!(truncate("abcd", 4), "abcd");
        assert_eq!(truncate("abcde", 4), "abcd...");
        assert_eq!(truncate("abc", 0), "...");
        // `é` is two bytes: a bound inside it cuts before it.
        assert_eq!(truncate("aé", 3), "aé");
        assert_eq!(truncate("aéb", 3), "aé...");
        assert_eq!(truncate("aéb", 2), "a...");
        // Nothing is escaped or replaced: that is the caller's next step.
        assert_eq!(truncate("a\u{1b}\nb\u{202e}c", 4), "a\u{1b}\nb...");
    }

    #[test]
    fn escape_untrusted_passes_ordinary_text_through() {
        for text in [
            "node_modules/@fuzdev/zap",
            "../zap",
            "it's a \"name\"",
            "café 日本語 — ok",
        ] {
            assert_eq!(escape_untrusted(text), text);
        }
    }
}
