//! The readers of the request headers the gates decide on.
//!
//! `Origin` feeds the origin check, `Origin` and `Referer` browser context,
//! `Host` the host gate and `Content-Type` the CORS simple-request refusal;
//! the line primitives the credential readers share live here too.
//!
//! One rule per reader, `fuz_app`'s `http/request_headers.ts` reading the same
//! one, and the shared table `request_header_conformance.json` (owned by
//! `fuz_app`, with a byte-identical copy beside this module) holding both
//! spines to the same rows. Each reader takes the whole [`HeaderMap`] and reads
//! **every** line of its header ([`HeaderMap::get_all`]), so a header sent
//! twice is something it can see.
//!
//! A malformed `Origin`, `Host` or `Content-Type` — an empty line, more than
//! one line, a byte the grammar doesn't hold — reads [`HeaderRead::Refused`],
//! never [`HeaderRead::Absent`]: reading a malformed browser signal as no
//! signal at all would fail open past the gate it feeds.
//!
//! **Join-invariance.** The TS twin on a runtime without a per-line view reads
//! one line holding the repeated lines joined with `, `. No origin, host or
//! media type holds a comma, so each reader refuses one anywhere in its value:
//! the join of a repeat is then refused as the repeat itself is, and one
//! expected answer holds on every runtime.

use axum::http::header::{AsHeaderName, CONTENT_TYPE, HOST, ORIGIN, REFERER};
use axum::http::{HeaderMap, HeaderValue};

/// One header's reading: none sent, exactly one well-formed line, or refused.
/// Twin of the TS `HeaderRead`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderRead<T> {
    /// No line of the header.
    Absent,
    /// Exactly one line, well-formed.
    One(T),
    /// An empty line, more than one line, or a value off the grammar.
    Refused,
}

/// Strip HTTP optional whitespace — SP and HTAB, nothing else — from both ends
/// of a field value or a part of one.
///
/// Not `<[u8]>::trim_ascii`, which also strips LF, FF, and CR, and not
/// `str::trim`, which strips every Unicode whitespace character — `0xA0` and
/// `0x85` among them once a header's bytes are read as text. Twin of
/// `fuz_app`'s `trim_optional_whitespace`.
#[must_use]
pub const fn trim_optional_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

/// The one line of a header, by count alone: absent, the single line, or
/// refused for more than one.
fn read_one_line(headers: &HeaderMap, name: impl AsHeaderName) -> HeaderRead<&HeaderValue> {
    let mut lines = headers.get_all(name).iter();
    match (lines.next(), lines.next()) {
        (None, _) => HeaderRead::Absent,
        (Some(line), None) => HeaderRead::One(line),
        (Some(_), Some(_)) => HeaderRead::Refused,
    }
}

/// The one value of a header sent exactly once, as text.
///
/// `None` when the header is absent, sent as more than one line, or holds a
/// byte outside visible ASCII, SP, and HTAB — what the credential readers
/// discard on.
#[must_use]
pub fn single_line(headers: &HeaderMap, name: impl AsHeaderName) -> Option<&str> {
    match read_one_line(headers, name) {
        HeaderRead::One(line) => line.to_str().ok(),
        HeaderRead::Absent | HeaderRead::Refused => None,
    }
}

/// `0x21..=0x7E` without the comma — every byte of an origin or a host.
const fn is_origin_or_host_byte(b: u8) -> bool {
    matches!(b, 0x21..=0x2b | 0x2d..=0x7e)
}

/// [`read_origin`]'s and [`read_host`]'s rule over one header's lines —
/// [`crate::AllowedOrigins::allows_request_hosts`] reads `Host` values given
/// as text through it.
pub(crate) fn read_origin_or_host_lines<'a>(
    lines: impl IntoIterator<Item = &'a [u8]>,
) -> HeaderRead<&'a str> {
    let mut lines = lines.into_iter();
    match (lines.next(), lines.next()) {
        (None, _) => HeaderRead::Absent,
        (Some(_), Some(_)) => HeaderRead::Refused,
        (Some(line), None) => {
            if line.is_empty() || !line.iter().copied().all(is_origin_or_host_byte) {
                return HeaderRead::Refused;
            }
            // every byte is ASCII, so the line is UTF-8
            std::str::from_utf8(line).map_or(HeaderRead::Refused, HeaderRead::One)
        }
    }
}

/// Read the `Origin` lines.
///
/// [`HeaderRead::Absent`] when there are none, [`HeaderRead::One`] for exactly
/// one line of printable ASCII with no space
/// or comma, [`HeaderRead::Refused`] otherwise — an empty line, a second line,
/// a byte outside that set.
///
/// The opaque origin `null` reads `One`: it is a value a browser sends, and
/// the allowlist refuses it.
#[must_use]
pub fn read_origin(headers: &HeaderMap) -> HeaderRead<&str> {
    read_origin_or_host_lines(headers.get_all(ORIGIN).iter().map(HeaderValue::as_bytes))
}

/// Read the `Host` lines, by [`read_origin`]'s rule: an empty `Host` names
/// nothing, and more than one is refused (RFC 9112 §3.2).
#[must_use]
pub fn read_host(headers: &HeaderMap) -> HeaderRead<&str> {
    read_origin_or_host_lines(headers.get_all(HOST).iter().map(HeaderValue::as_bytes))
}

/// A `token` byte (RFC 9110 §5.6.2).
const fn is_token_byte(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`'
        | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

/// True when `essence` is `token "/" token`.
fn is_media_type_essence(essence: &[u8]) -> bool {
    let Some(slash) = essence.iter().position(|&b| b == b'/') else {
        return false;
    };
    let (kind, subtype) = (&essence[..slash], &essence[slash + 1..]);
    !kind.is_empty()
        && !subtype.is_empty()
        && kind.iter().copied().all(is_token_byte)
        && subtype.iter().copied().all(is_token_byte)
}

/// Read the `Content-Type` lines to the MIME essence.
///
/// [`HeaderRead::Absent`] when there are none, [`HeaderRead::One`] with the essence (the part before
/// any `;`, stripped of SP and HTAB, lowercased) when there is exactly one line
/// of header text with no comma whose essence is `token "/" token`,
/// [`HeaderRead::Refused`] otherwise.
///
/// A comma is refused anywhere in the value, a quoted parameter's included: a
/// joined repeat whose first line carries a parameter
/// (`application/json; charset=utf-8, text/plain`) has a well-formed essence,
/// and only refusing the comma reads it as the repeat it is.
#[must_use]
pub fn read_content_type(headers: &HeaderMap) -> HeaderRead<String> {
    let line = match read_one_line(headers, CONTENT_TYPE) {
        HeaderRead::One(line) => line,
        HeaderRead::Absent => return HeaderRead::Absent,
        HeaderRead::Refused => return HeaderRead::Refused,
    };
    let Ok(value) = line.to_str() else {
        return HeaderRead::Refused;
    };
    if value.contains(',') {
        return HeaderRead::Refused;
    }
    let essence = trim_optional_whitespace(value.split(';').next().unwrap_or_default().as_bytes());
    if !is_media_type_essence(essence) {
        return HeaderRead::Refused;
    }
    // a media type essence is ASCII
    std::str::from_utf8(essence).map_or(HeaderRead::Refused, |essence| {
        HeaderRead::One(essence.to_ascii_lowercase())
    })
}

/// True when the request carries a browser-context header.
///
/// Any `Origin` or `Referer` line counts, an empty or repeated one included —
/// a presence test: a malformed browser signal is still a browser signal.
/// Twin of `fuz_app`'s `is_browser_context`.
///
/// The bearer and daemon-token legs discard their credential when this is
/// true, and the request continues without it. A defense against a token
/// replayed from a cross-origin page, which sends `Origin`, not a proof that
/// the caller is not a browser: a same-origin `GET` sends no `Origin`, and
/// with `referrerPolicy: 'no-referrer'` no `Referer` either, so page script on
/// the origin keeps a token it attaches. Nothing checks the peer address.
#[must_use]
pub fn is_browser_context(headers: &HeaderMap) -> bool {
    headers.contains_key(ORIGIN) || headers.contains_key(REFERER)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    /// The shared table, byte-identical to `fuz_app`'s
    /// `testing/cross_backend/request_header_conformance.json`.
    const TABLE: &str = include_str!("request_header_conformance.json");

    /// A table line's bytes: one byte per character (U+0000–U+00FF).
    fn line_bytes(line: &str) -> Vec<u8> {
        line.chars()
            .map(|c| u8::try_from(u32::from(c)).expect("a table line is one byte per character"))
            .collect()
    }

    /// Fill a line's `{placeholders}` from the table's unit values.
    fn fill(text: &str, placeholders: &serde_json::Map<String, Value>) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let close = rest[open..].find('}').expect("a closed placeholder") + open;
            let name = &rest[open + 1..close];
            let value = placeholders
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("unknown placeholder {{{name}}}"));
            out.push_str(value);
            rest = &rest[close + 1..];
        }
        out.push_str(rest);
        out
    }

    /// Parse `Name: value` lines into a map the way a request-head parser
    /// would: every line appended, the value stripped of SP and HTAB.
    fn header_map(lines: &[Vec<u8>]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            let colon = line.iter().position(|&b| b == b':').expect("a header line");
            let name = axum::http::HeaderName::from_bytes(&line[..colon]).expect("a header name");
            let value = HeaderValue::from_bytes(trim_optional_whitespace(&line[colon + 1..]))
                .expect("a header value");
            headers.append(name, value);
        }
        headers
    }

    /// Fold lines to one line per name, joined with `, ` (`; ` for `Cookie`)
    /// in first-occurrence order and stripped of SP and HTAB — the view a
    /// runtime without a per-line view gives the TS twin.
    fn fold(lines: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut names: Vec<(String, Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
        for line in lines {
            let colon = line.iter().position(|&b| b == b':').expect("a header line");
            let name = &line[..colon];
            let key = String::from_utf8_lossy(name).to_ascii_lowercase();
            let value = trim_optional_whitespace(&line[colon + 1..]).to_vec();
            match names.iter_mut().find(|(k, _, _)| *k == key) {
                Some((_, _, values)) => values.push(value),
                None => names.push((key, name.to_vec(), vec![value])),
            }
        }
        names
            .into_iter()
            .map(|(key, name, values)| {
                let separator: &[u8] = if key == "cookie" { b"; " } else { b", " };
                let joined = values.join(separator);
                let mut line = name;
                line.extend_from_slice(b": ");
                line.extend_from_slice(trim_optional_whitespace(&joined));
                line
            })
            .collect()
    }

    /// A reading in the table's spelling.
    fn spell<T: AsRef<str>>(read: &HeaderRead<T>) -> Value {
        match read {
            HeaderRead::Absent => Value::from("absent"),
            HeaderRead::Refused => Value::from("refused"),
            HeaderRead::One(value) => serde_json::json!({ "one": value.as_ref() }),
        }
    }

    /// Every reader's reading of `headers`, in the table's spelling.
    fn read_all(headers: &HeaderMap) -> Value {
        serde_json::json!({
            "origin": spell(&read_origin(headers)),
            "browser_context": is_browser_context(headers),
            "host": spell(&read_host(headers)),
            "content_type": spell(&read_content_type(headers)),
        })
    }

    /// An expected reading with its `one` value filled.
    fn fill_read(read: &Value, placeholders: &serde_json::Map<String, Value>) -> Value {
        match read {
            Value::Object(map) => {
                let mut map = map.clone();
                for value in map.values_mut() {
                    match value {
                        Value::String(text) => *text = fill(text, placeholders),
                        Value::Object(one) => {
                            for inner in one.values_mut() {
                                if let Value::String(text) = inner {
                                    *text = fill(text, placeholders);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Value::Object(map)
            }
            other => other.clone(),
        }
    }

    fn table() -> (serde_json::Map<String, Value>, Vec<Value>) {
        let table: Value = serde_json::from_str(TABLE).expect("the table is JSON");
        let placeholders = table["unit_placeholders"]
            .as_object()
            .expect("unit_placeholders")
            .clone();
        let rows = table["rows"].as_array().expect("rows").clone();
        assert!(!rows.is_empty());
        (placeholders, rows)
    }

    fn row_lines(row: &Value, placeholders: &serde_json::Map<String, Value>) -> Vec<Vec<u8>> {
        row["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .map(|line| line_bytes(&fill(line.as_str().expect("a line"), placeholders)))
            .collect()
    }

    #[test]
    fn every_conformance_row_reads_as_the_table_says() {
        let (placeholders, rows) = table();
        let mut failures = Vec::new();
        for row in &rows {
            let got = read_all(&header_map(&row_lines(row, &placeholders)));
            let expected = fill_read(&row["read"], &placeholders);
            if got != expected {
                failures.push(format!("{}: expected {expected}, got {got}", row["name"]));
            }
        }
        assert!(
            failures.is_empty(),
            "rows disagree:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn every_conformance_row_reads_the_same_folded() {
        let (placeholders, rows) = table();
        let mut failures = Vec::new();
        let mut folded_rows = 0;
        for row in &rows {
            let lines = row_lines(row, &placeholders);
            let folded = fold(&lines);
            if folded.len() != lines.len() {
                folded_rows += 1;
            }
            let by_line = read_all(&header_map(&lines));
            let by_fold = read_all(&header_map(&folded));
            if by_line != by_fold {
                failures.push(format!(
                    "{}: {by_line} over the lines, {by_fold} folded",
                    row["name"]
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "rows not join-invariant:\n{}",
            failures.join("\n")
        );
        // a fold that changes no row would hold every row equal to itself
        assert!(
            folded_rows > 0,
            "no row repeats a header, so the fold changed nothing"
        );
    }

    #[test]
    fn trim_optional_whitespace_strips_sp_and_htab_only() {
        assert_eq!(trim_optional_whitespace(b" \t a b \t "), b"a b");
        assert_eq!(trim_optional_whitespace(b" \t "), b"");
        assert_eq!(trim_optional_whitespace(b""), b"");
        for kept in [
            &b"\xa0a\xa0"[..],
            b"\x85a\x85",
            b"\x0ba",
            b"\x0ca",
            b"\na\r",
        ] {
            assert_eq!(trim_optional_whitespace(kept), kept);
        }
    }

    #[test]
    fn either_browser_header_is_browser_context() {
        let mut headers = HeaderMap::new();
        assert!(!is_browser_context(&headers));
        headers.insert(
            REFERER,
            HeaderValue::from_static("https://app.example/page"),
        );
        assert!(is_browser_context(&headers));
        headers.insert(ORIGIN, HeaderValue::from_static("https://app.example"));
        assert!(is_browser_context(&headers));
        headers.remove(REFERER);
        assert!(is_browser_context(&headers));
    }

    #[test]
    fn single_line_reads_one_text_line_only() {
        let mut headers = HeaderMap::new();
        assert_eq!(single_line(&headers, ORIGIN), None);
        headers.append(ORIGIN, HeaderValue::from_static("a"));
        assert_eq!(single_line(&headers, ORIGIN), Some("a"));
        headers.append(ORIGIN, HeaderValue::from_static("a"));
        assert_eq!(single_line(&headers, ORIGIN), None);
        let mut headers = HeaderMap::new();
        headers.append(ORIGIN, HeaderValue::from_bytes(b"\xe9").expect("obs-text"));
        assert_eq!(single_line(&headers, ORIGIN), None);
    }
}
