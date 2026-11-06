//! Reading a release stream's published manifests from storage.
//!
//! A stream — the fuz self artifact, or one tool — keeps a signed manifest per
//! `(version, target)` under its `ReleaseLayout` prefix. The producer flows that
//! take stock of what is published (`prune`, `backfill`, and a publish about to
//! write a release log's first head) find those manifests the same way: list
//! the prefix, keep the manifest keys, read each one under the manifest size
//! cap. That walk lives here so they cannot disagree about what a stream holds,
//! or about which streams there are.

use std::cmp::Ordering;

use fuz_artifact::tools::FIRST_PARTY_TOOLS;
use fuz_release::{Manifest, ReleaseError, ReleaseLayout, SELF_NAME, download_manifest};
use fuz_storage::{Storage, StorageError};
use fuz_sys::text::{escape_message, escape_untrusted, quoted, truncate};

/// One release stream: the fuz self artifact, or one first-party tool.
#[derive(Debug)]
pub struct StreamRef {
    /// `fuz` for the self artifact, else the tool name.
    pub name: &'static str,
    /// Where the stream's keys live in storage.
    pub layout: ReleaseLayout,
    /// Whether this is the self artifact's stream.
    pub is_self: bool,
}

/// Every release stream: the self artifact, then each first-party tool.
pub fn streams() -> impl Iterator<Item = StreamRef> {
    std::iter::once(StreamRef {
        name: SELF_NAME,
        layout: ReleaseLayout::self_artifact(),
        is_self: true,
    })
    .chain(FIRST_PARTY_TOOLS.iter().map(|tool| StreamRef {
        name: tool,
        layout: ReleaseLayout::tool(tool),
        is_self: false,
    }))
}

/// The layout of the stream a release named `name` is published in.
pub fn layout_of(name: &str) -> ReleaseLayout {
    if name == SELF_NAME {
        ReleaseLayout::self_artifact()
    } else {
        ReleaseLayout::tool(name)
    }
}

/// The manifest keys every stream holds, sorted, leaving out `own_key`.
///
/// Keys only: nothing is downloaded, parsed, or verified, so a manifest that
/// is malformed still counts as something storage holds.
///
/// # Errors
///
/// The first stream that cannot be listed.
pub async fn manifest_keys_except(
    storage: &impl Storage,
    own_key: &str,
) -> Result<Vec<String>, StorageError> {
    let mut keys = Vec::new();
    for stream in streams() {
        keys.extend(
            storage
                .list(stream.layout.prefix())
                .await?
                .into_iter()
                .filter(|key| is_stream_manifest_key(key, &stream.layout, stream.name))
                .filter(|key| key != own_key),
        );
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

/// The suffix of a manifest's storage key.
const MANIFEST_SUFFIX: &str = ".manifest.json";

/// The prefix every key of `stream_name`'s own releases starts with:
/// `<layout prefix><name>-`.
///
/// The `<name>-` part keeps a sweep of the self stream (layout prefix `""`)
/// from matching tool keys under `tools/…`, and never confuses `fuz-` with
/// `fuzd-`.
pub fn stream_key_prefix(layout: &ReleaseLayout, stream_name: &str) -> String {
    format!("{}{stream_name}-", layout.prefix())
}

/// Whether `key`, from a listing of `layout`'s prefix, is a manifest of the
/// stream `stream_name`: `<layout prefix><name>-….manifest.json`.
pub fn is_stream_manifest_key(key: &str, layout: &ReleaseLayout, stream_name: &str) -> bool {
    key.ends_with(MANIFEST_SUFFIX) && key.starts_with(&stream_key_prefix(layout, stream_name))
}

/// Download the manifest at `key` and parse it, refusing one past
/// `MAX_MANIFEST_SIZE`.
///
/// Parsed and structurally validated only: the signature is the caller's to
/// verify, where it matters.
pub async fn read_manifest(storage: &impl Storage, key: &str) -> Result<Manifest, ReleaseError> {
    let bytes = download_manifest(storage, key).await?;
    Ok(Manifest::from_json(&bytes)?)
}

/// Most bytes of one untrusted value [`printable`] keeps.
const MAX_PRINTED_LEN: usize = 256;

/// `text` as one bounded, printable line.
///
/// Cut to a bounded length on a character boundary (`...` appended when cut),
/// then escaped by [`escape_untrusted`]: every control,
/// invisible, or otherwise non-printing character — a newline, an escape
/// sequence, a direction override, a blank filler — and `\` doubled so an
/// escape cannot be forged.
///
/// Storage keys and the fields of what storage holds are whatever storage
/// holds. They pass through this — or through `printable_quoted`, where one
/// is shown in quotes — on their way to an error message or a report, so
/// nothing read from storage can add a line to that output or drive the
/// terminal it is printed to.
#[must_use]
pub fn printable(text: &str) -> String {
    escape_untrusted(&truncate(text, MAX_PRINTED_LEN))
}

/// An error's own message as one bounded, printable line.
///
/// The message is the program's: its error types escape the strings they
/// carry where they render them. So it is cut as [`printable`] cuts a value
/// (on the message as rendered) and passed through [`escape_message`], which
/// spells out whatever in it is still unprintable — a newline between its own
/// lines, a string some error shows raw — and leaves the escapes already
/// there alone. A value goes through [`printable`], which escapes `\` too.
#[must_use]
pub fn printable_message(message: &str) -> String {
    escape_message(&truncate(message, MAX_PRINTED_LEN))
}

/// `text` in double quotes, as one bounded, printable line: cut as
/// [`printable`] cuts it, then quoted by [`fuz_sys::text::quoted`], so a `"`
/// in the value cannot close the quotes it is shown in.
#[must_use]
pub fn printable_quoted(text: &str) -> String {
    quoted(&truncate(text, MAX_PRINTED_LEN))
}

/// Order two versions: by semver when both parse, a semver version before one
/// that is not, and by string otherwise — a total order over any two strings.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    match (semver::Version::parse(a), semver::Version::parse(b)) {
        (Ok(x), Ok(y)) => x.cmp(&y).then_with(|| a.cmp(b)),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_by_semver_then_by_string() {
        let cases = [
            ("0.9.0", "0.10.0", Ordering::Less),
            ("1.0.0-rc.1", "1.0.0", Ordering::Less),
            ("1.0.0", "1.0.0", Ordering::Equal),
            // A semver version sorts before one that is not.
            ("9.9.9", "2", Ordering::Less),
            ("nightly", "0.1.0", Ordering::Greater),
            // Neither parses: string order.
            ("3", "nightly", Ordering::Less),
        ];
        for (a, b, expected) in cases {
            assert_eq!(compare_versions(a, b), expected, "{a} vs {b}");
            assert_eq!(compare_versions(b, a), expected.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn printable_is_one_bounded_line_with_nothing_non_printing() {
        assert_eq!(printable("fuz-0.1.0-x86_64"), "fuz-0.1.0-x86_64");
        assert_eq!(printable("it's \"quoted\""), "it's \"quoted\"");
        assert_eq!(printable("a\nb\rc\td"), "a\\nb\\rc\\td");
        assert_eq!(printable("a\x1b[31mb"), "a\\u{1b}[31mb");
        // A direction override, and a backslash that would forge an escape.
        assert_eq!(printable("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(printable("a\\nb"), "a\\\\nb");
        // The blank fillers and NUL, which show nothing and which the standard
        // library's own escaping does not spell one way.
        assert_eq!(
            printable("a\u{115f}\u{1160}\u{3164}\u{ffa0}\u{2800}\0b"),
            "a\\u{115f}\\u{1160}\\u{3164}\\u{ffa0}\\u{2800}\\u{0}b"
        );
        // Printable non-ASCII is left as it is.
        assert_eq!(printable("é"), "é");
        // Cut on a character boundary, never inside one.
        let long = format!("{}é", "k".repeat(MAX_PRINTED_LEN - 1));
        assert_eq!(
            printable(&long),
            format!("{}...", "k".repeat(MAX_PRINTED_LEN - 1))
        );
    }

    /// A message is bounded and made one line, with the escapes it holds left
    /// as they are.
    #[test]
    fn printable_message_keeps_the_escapes_a_message_already_holds() {
        let escaped = "storage error: invalid storage key \"a\\u{1b}\\\\b\\\"\": key too long";
        assert_eq!(printable_message(escaped), escaped);
        // What a message still holds raw is spelled out.
        assert_eq!(
            printable_message("git said:\nfatal\u{1b}[2K\u{202e}"),
            "git said:\\nfatal\\u{1b}[2K\\u{202e}"
        );
        assert_eq!(
            printable_message(&"m".repeat(MAX_PRINTED_LEN + 1)),
            format!("{}...", "m".repeat(MAX_PRINTED_LEN))
        );
    }

    /// The quoted form is the same bounded text in quotes it cannot close.
    #[test]
    fn printable_quoted_bounds_escapes_and_keeps_its_quotes() {
        assert_eq!(printable_quoted("0.1.0"), "\"0.1.0\"");
        assert_eq!(
            printable_quoted("a\" b\u{2800}\u{1b}[2K\\"),
            "\"a\\\" b\\u{2800}\\u{1b}[2K\\\\\""
        );
        assert_eq!(
            printable_quoted(&"\"".repeat(MAX_PRINTED_LEN + 1)),
            format!("\"{}...\"", "\\\"".repeat(MAX_PRINTED_LEN))
        );
    }

    /// The bound is on the text, taken before it is escaped: the cut text is
    /// escaped whole, so an escape is never cut in half.
    #[test]
    fn printable_cuts_the_text_before_it_escapes_it() {
        let long = "\u{1b}".repeat(MAX_PRINTED_LEN + 1);
        assert_eq!(
            printable(&long),
            format!("{}...", "\\u{1b}".repeat(MAX_PRINTED_LEN))
        );
    }
}
