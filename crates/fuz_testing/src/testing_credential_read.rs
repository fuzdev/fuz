//! `_testing_credential_read` action spec.
//!
//! Reads the three credentials — the session cookie, the bearer token, the
//! daemon token — out of a list of header lines with the readers the
//! credential walk calls ([`fuz_auth::parse_session_from_cookies`],
//! [`fuz_auth::read_bearer_token`], [`fuz_auth::read_daemon_token`]), so the
//! shared credential conformance table checks this spine's header grammar row
//! by row, over the wire and in this crate's own unit test. Pure: no database
//! read, no state beyond the server's keyring and cookie name.
//!
//! Reads `{lines: string[]}`: the request's header lines, each `Name: value`,
//! in the order sent — a name may repeat. Every character is one byte, as the
//! TS twin's runtime hands it a header's bytes: U+00E9 is the byte `0xE9`.
//! Answers `{session_cookie: "absent" | "invalid" | "valid", bearer_token:
//! string | null, daemon_token: string | null}` — each leg's reading before
//! any database work. Mirrors `fuz_app`'s TS `_testing_credential_read`.
//!
//! Every refusal of `lines` is `invalid_params` with the reason
//! [`ERROR_TESTING_CREDENTIAL_READ_LINE`]: a value that is no list of
//! strings, a list over [`TESTING_CREDENTIAL_READ_LINES_MAX`] lines or a line
//! over [`TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX`] characters (the TS twin's
//! input schema states the same caps — without them this side would refuse a
//! name `HeaderName` cannot hold, and the twin would read it), and a line
//! that is no header line — no `:`, a name that is no HTTP token, or a
//! character no field value holds (above U+00FF, or a control character other
//! than HTAB).
//!
//! Gated on the daemon-token credential, matching `_testing_reset`.

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_auth::{Keyring, SessionCookieRead};
use fuz_http::{InputShape, JsonrpcError, invalid_input_params, invalid_params};
use serde_json::{Value, json};

/// The `data.reason` of every refusal of `lines`: no list of strings, over a
/// cap, or holding a line that is no header line.
pub const ERROR_TESTING_CREDENTIAL_READ_LINE: &str = "invalid_header_line";

/// The longest header line the action reads, in UTF-16 code units — what the
/// TS twin's `TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX` bounds, one a byte for
/// every character a line may hold.
pub const TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX: usize = 1024;

/// The most header lines the action reads — the TS twin's
/// `TESTING_CREDENTIAL_READ_LINES_MAX`.
pub const TESTING_CREDENTIAL_READ_LINES_MAX: usize = 32;

/// The refusal's message — the TS twin's.
const INVALID_HEADER_LINE_MESSAGE: &str = "a header line must be `Name: value` in bytes";

/// Declared input keys — the exact key set of the TS twin's
/// `testing_credential_read_action_spec.input` strict object.
const TESTING_CREDENTIAL_READ_KEYS: &[&str] = &["lines"];

/// Build the request headers a list of `Name: value` lines stands for — what
/// an HTTP parser does to a request head: the name ends at the first `:` and
/// is an HTTP token, the value loses its outer SP and HTAB, each character is
/// one byte, and lines of one name keep their order.
///
/// `None` for a line with no `:`, a name that is no token, a character no
/// field value holds, or more lines than a `HeaderMap` holds — never a panic,
/// whoever calls and however many lines they pass.
fn parse_testing_header_lines<'l>(lines: impl IntoIterator<Item = &'l str>) -> Option<HeaderMap> {
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        // `HeaderName` also takes an uppercase name and lowercases it, as the
        // twin does; the token check first keeps the two grammars one
        if !fuz_auth::is_cookie_name(name) {
            return None;
        }
        let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
        // one byte per character; a character above U+00FF is no byte
        let bytes: Vec<u8> = value
            .chars()
            .map(u8::try_from)
            .collect::<Result<_, _>>()
            .ok()?;
        // `HeaderValue` refuses the bytes a parser refuses: a control
        // character other than HTAB, and DEL
        let value = HeaderValue::from_bytes(fuz_auth::trim_optional_whitespace(&bytes)).ok()?;
        // `append` panics once the map is full; a list past the map's size is
        // no request head either
        headers.try_append(name, value).ok()?;
    }
    Some(headers)
}

/// Answer one `_testing_credential_read` input.
///
/// Reads each credential out of `lines` with the readers the credential walk
/// calls. The action handler and this crate's conformance test both call
/// this, so the table checks the same functions the wire serves.
///
/// # Errors
///
/// `invalid_params` with reason [`ERROR_TESTING_CREDENTIAL_READ_LINE`] for a
/// line that is no header line, and for more lines than a `HeaderMap` holds
/// — this function applies no cap of its own (the action's input parse does).
pub fn run_testing_credential_read<'l>(
    lines: impl IntoIterator<Item = &'l str>,
    keyring: &Keyring,
    cookie_name: &str,
) -> Result<Value, JsonrpcError> {
    let headers = parse_testing_header_lines(lines).ok_or_else(|| {
        invalid_params(
            INVALID_HEADER_LINE_MESSAGE,
            Some(ERROR_TESTING_CREDENTIAL_READ_LINE),
        )
    })?;
    let session_cookie = match fuz_auth::parse_session_from_cookies(&headers, keyring, cookie_name)
    {
        SessionCookieRead::Absent => "absent",
        SessionCookieRead::Invalid => "invalid",
        SessionCookieRead::Valid(_) => "valid",
    };
    Ok(json!({
        "session_cookie": session_cookie,
        "bearer_token": fuz_auth::read_bearer_token(&headers),
        "daemon_token": fuz_auth::read_daemon_token(&headers),
    }))
}

/// Read the `lines` of a `_testing_credential_read` input — what the TS twin's
/// input schema admits: an object whose only key is `lines`, a list of at
/// most [`TESTING_CREDENTIAL_READ_LINES_MAX`] strings of at most
/// [`TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX`] UTF-16 code units each.
///
/// # Errors
///
/// `invalid_params` with the twin's schema-refusal message: with no reason
/// for an unknown key, with [`ERROR_TESTING_CREDENTIAL_READ_LINE`] for
/// anything wrong with `lines`.
fn parse_testing_credential_read_input(params: &Value) -> Result<Vec<&str>, JsonrpcError> {
    fuz_http::reject_unknown_keys(params, TESTING_CREDENTIAL_READ_KEYS)?;
    let refuse =
        |detail: &str| invalid_input_params(detail, Some(ERROR_TESTING_CREDENTIAL_READ_LINE));
    let lines: Vec<&str> = params
        .get("lines")
        .and_then(Value::as_array)
        .and_then(|lines| lines.iter().map(Value::as_str).collect())
        .ok_or_else(|| refuse("lines (array of strings) is required"))?;
    if lines.len() > TESTING_CREDENTIAL_READ_LINES_MAX {
        return Err(refuse("lines holds more lines than the cap"));
    }
    if lines
        .iter()
        .any(|line| line.encode_utf16().count() > TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX)
    {
        return Err(refuse("a line is longer than the cap"));
    }
    Ok(lines)
}

/// Build the `_testing_credential_read` action spec over the server's cookie
/// keyring and session cookie name.
#[must_use]
pub fn create_testing_credential_read_action_spec(
    keyring: Arc<Keyring>,
    cookie_name: &'static str,
) -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |params: Value, _ctx: ActionContext<'_>| {
        let keyring = Arc::clone(&keyring);
        Box::pin(async move {
            let lines = parse_testing_credential_read_input(&params)?;
            run_testing_credential_read(lines, &keyring, cookie_name)
        })
    });

    ActionSpec::read_only(
        "_testing_credential_read",
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}

#[cfg(test)]
mod tests {
    //! The credential conformance table, run against this spine's readers:
    //! every row of `credential_conformance.json` — a byte-identical copy of
    //! `fuz_app`'s `testing/cross_backend/credential_conformance.json`, which
    //! `fuz_app`'s cross-backend parity project holds equal to this one —
    //! through the action's input parse and [`run_testing_credential_read`],
    //! as its handler runs them. The TS twin's unit test reads
    //! the same rows through its own readers; live values are per leg, so the
    //! rows name them with `{placeholders}` this test fills from its own
    //! keyring.

    use fuz_auth::keyring::MIN_KEY_LENGTH;
    use fuz_auth::{create_session_cookie_value, generate_api_token, generate_session_token};

    use super::*;

    /// The table, embedded at compile time.
    const TABLE: &str = include_str!("credential_conformance.json");

    const COOKIE_NAME: &str = "fuz_session";

    /// The placeholder names the TS twin's
    /// `CREDENTIAL_CONFORMANCE_PLACEHOLDERS` lists, in its order.
    const PLACEHOLDERS: [&str; 10] = [
        "cookie_name",
        "cookie_name_upper",
        "session_cookie",
        "session_cookie_percent_encoded",
        "session_cookie_bad_mac",
        "session_cookie_expired",
        "session_cookie_empty_identity",
        "session_cookie_rowless",
        "api_token",
        "daemon_token",
    ];

    fn keyring() -> Keyring {
        Keyring::new(&"k".repeat(MIN_KEY_LENGTH)).expect("a keyring")
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs()
    }

    /// `encodeURIComponent`, for the cookie values this test signs (ASCII).
    fn percent_encode(value: &str) -> String {
        value
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    /// This leg's placeholder values: credentials of its own, signed with its
    /// own keyring — the twin of `build_credential_conformance_placeholders`.
    fn placeholders(keyring: &Keyring) -> Vec<(&'static str, String)> {
        let session_cookie = create_session_cookie_value(keyring, &generate_session_token());
        let (payload, signature) = session_cookie.rsplit_once('.').expect("value.signature");
        let swapped = if signature.starts_with('A') { 'B' } else { 'A' };
        let bad_mac = format!("{payload}.{swapped}{}", &signature[1..]);
        let now = now_secs();
        let values = [
            COOKIE_NAME.to_owned(),
            COOKIE_NAME.to_uppercase(),
            session_cookie.clone(),
            percent_encode(&session_cookie),
            bad_mac,
            keyring.sign(&format!("credential-conformance-expired:{}", now - 3600)),
            keyring.sign(&format!(":{}", now + 3600)),
            keyring.sign(&format!("credential-conformance-rowless:{}", now + 3600)),
            generate_api_token().token,
            generate_session_token(),
        ];
        assert_ne!(
            values[3], session_cookie,
            "the percent-encoded row is not vacuous"
        );
        PLACEHOLDERS.into_iter().zip(values).collect()
    }

    fn fill(text: &str, placeholders: &[(&'static str, String)]) -> String {
        let filled = placeholders
            .iter()
            .fold(text.to_owned(), |text, (name, value)| {
                text.replace(&format!("{{{name}}}"), value)
            });
        assert!(!filled.contains('{'), "an unknown placeholder in {text:?}");
        filled
    }

    fn table() -> Value {
        serde_json::from_str(TABLE).expect("the table is JSON")
    }

    fn rows<'t>(table: &'t Value, key: &str) -> &'t Vec<Value> {
        let rows = table[key].as_array().expect("a table of rows");
        assert!(!rows.is_empty(), "{key} has rows");
        rows
    }

    fn lines(row: &Value, placeholders: &[(&'static str, String)]) -> Vec<String> {
        row["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .map(|line| fill(line.as_str().expect("a line"), placeholders))
            .collect()
    }

    /// Read `lines` as the action's handler does: the input parse, then the
    /// read.
    fn read_lines(lines: &[String], keyring: &Keyring) -> Result<Value, JsonrpcError> {
        let params = json!({ "lines": lines });
        let lines = parse_testing_credential_read_input(&params)?;
        run_testing_credential_read(lines, keyring, COOKIE_NAME)
    }

    #[test]
    fn every_row_gets_the_reading_it_names() {
        let keyring = keyring();
        let placeholders = placeholders(&keyring);
        let table = table();
        let mut failures = Vec::new();
        for row in rows(&table, "rows") {
            let name = row["name"].as_str().expect("a name");
            let lines = lines(row, &placeholders);
            let token = |key: &str| match &row["read"][key] {
                Value::Null => Value::Null,
                Value::String(token) => Value::String(fill(token, &placeholders)),
                other => panic!("{name}: read.{key} is {other}"),
            };
            let expected = json!({
                "session_cookie": row["read"]["session_cookie"],
                "bearer_token": token("bearer_token"),
                "daemon_token": token("daemon_token"),
            });
            match read_lines(&lines, &keyring) {
                Ok(got) if got == expected => {}
                // the tokens are this run's own, minted above and never live
                Ok(got) => failures.push(format!("{name}: expected {}, got {got}", row["read"])),
                Err(error) => failures.push(format!("{name}: refused: {}", error.message)),
            }
        }
        assert!(
            failures.is_empty(),
            "{} credential conformance rows disagree:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn every_refused_row_is_refused_with_its_reason() {
        let keyring = keyring();
        let placeholders = placeholders(&keyring);
        let table = table();
        for row in rows(&table, "refused") {
            let name = row["name"].as_str().expect("a name");
            let lines = lines(row, &placeholders);
            let error = read_lines(&lines, &keyring).expect_err(name);
            assert_eq!(
                error.code,
                fuz_http::JsonrpcErrorCode::InvalidParams,
                "{name}"
            );
            assert_eq!(
                error.data,
                Some(json!({ "reason": row["reason"] })),
                "{name}"
            );
            assert_eq!(row["reason"], ERROR_TESTING_CREDENTIAL_READ_LINE, "{name}");
        }
    }

    /// The table's cap rows sit at this spine's caps, so a cap changed on one
    /// spine alone fails its own unit leg.
    #[test]
    fn the_cap_rows_sit_at_the_caps() {
        let keyring = keyring();
        let placeholders = placeholders(&keyring);
        let table = table();
        let filled = |name: &str| -> Vec<String> {
            let row = rows(&table, "rows")
                .iter()
                .chain(rows(&table, "refused"))
                .find(|row| row["name"] == name)
                .unwrap_or_else(|| panic!("no row named {name:?}"));
            lines(row, &placeholders)
        };
        let longest = |lines: &[String]| {
            lines
                .iter()
                .map(|line| line.encode_utf16().count())
                .max()
                .unwrap_or(0)
        };
        assert_eq!(
            longest(&filled("a line of exactly the length cap")),
            TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX
        );
        let over_length = filled("a line one character over the length cap");
        assert_eq!(
            longest(&over_length),
            TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX + 1
        );
        assert!(over_length.len() <= TESTING_CREDENTIAL_READ_LINES_MAX);
        assert_eq!(
            filled("exactly the cap of lines").len(),
            TESTING_CREDENTIAL_READ_LINES_MAX
        );
        let over_count = filled("one line over the cap of lines");
        assert_eq!(over_count.len(), TESTING_CREDENTIAL_READ_LINES_MAX + 1);
        assert!(longest(&over_count) <= TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX);
    }

    /// The input parse refuses what the twin's schema refuses, with its
    /// reasons: the field's for anything wrong with `lines`, none for an
    /// unknown key.
    #[test]
    fn every_refusal_of_the_lines_carries_the_one_reason() {
        let reason_of = |params: Value| {
            let error = parse_testing_credential_read_input(&params).expect_err("a refusal");
            assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);
            assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE);
            error.data
        };
        let reason = Some(json!({ "reason": ERROR_TESTING_CREDENTIAL_READ_LINE }));
        for params in [
            json!({}),
            json!({ "lines": "Cookie: a=1" }),
            json!({ "lines": [1] }),
            json!({ "lines": [null] }),
            // two UTF-16 code units a character, as the twin counts
            json!({ "lines": ["\u{1F600}".repeat(TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX / 2 + 1)] }),
        ] {
            assert_eq!(reason_of(params.clone()), reason, "{params}");
        }
        assert_eq!(reason_of(json!({ "lines": [], "other": 1 })), None);
        // an astral line within the cap passes the parse (the grammar refuses it)
        let within =
            json!({ "lines": ["\u{1F600}".repeat(TESTING_CREDENTIAL_READ_LINE_LENGTH_MAX / 2)] });
        assert!(parse_testing_credential_read_input(&within).is_ok());
    }

    /// Every placeholder the table uses is one this leg fills, and every one
    /// this leg fills is used — so a placeholder added to the table on the TS
    /// side fails here until it has a value.
    #[test]
    fn the_table_uses_exactly_the_placeholders_this_leg_fills() {
        let mut used: Vec<&str> = Vec::new();
        let mut rest = TABLE;
        while let Some(start) = rest.find('{') {
            let after = &rest[start + 1..];
            let end = after
                .find(|c: char| !(c.is_ascii_lowercase() || c == '_'))
                .unwrap_or(after.len());
            if end > 0 && after[end..].starts_with('}') && !used.contains(&&after[..end]) {
                used.push(&after[..end]);
            }
            rest = after;
        }
        used.sort_unstable();
        let mut known = PLACEHOLDERS.to_vec();
        known.sort_unstable();
        assert_eq!(used, known);
    }

    #[test]
    fn header_lines_parse_as_a_request_head_does() {
        let headers = parse_testing_header_lines(["A: 1", "a:\t2 ", "B:"]).expect("header lines");
        let values = |name: &str| -> Vec<&[u8]> {
            headers
                .get_all(name)
                .iter()
                .map(HeaderValue::as_bytes)
                .collect()
        };
        assert_eq!(values("a"), [b"1", b"2"]);
        assert_eq!(values("b"), [b""]);
        // one byte per character
        let headers = parse_testing_header_lines(["A: caf\u{e9}"]).expect("a latin1 line");
        assert_eq!(values_of(&headers, "a"), [b"caf\xe9".to_vec()]);
        for refused in ["A", ": 1", "A B: 1", "A: \u{100}", "A: \u{b}", "A: \u{7f}"] {
            assert!(
                parse_testing_header_lines([refused]).is_none(),
                "{refused:?}"
            );
        }
    }

    /// The action's handler caps the list; a direct caller of the `pub` read
    /// is not capped, and gets the refusal rather than `HeaderMap`'s panic.
    #[test]
    fn more_lines_than_a_header_map_holds_are_refused_not_a_panic() {
        // distinct names: the map's limit counts entries by name
        let lines: Vec<String> = (0..40_000).map(|i| format!("x{i}: 1")).collect();
        assert!(parse_testing_header_lines(lines.iter().map(String::as_str)).is_none());
        let error =
            run_testing_credential_read(lines.iter().map(String::as_str), &keyring(), COOKIE_NAME)
                .expect_err("a refusal");
        assert_eq!(error.code, fuz_http::JsonrpcErrorCode::InvalidParams);
        assert_eq!(
            error.data,
            Some(json!({ "reason": ERROR_TESTING_CREDENTIAL_READ_LINE }))
        );
    }

    fn values_of(headers: &HeaderMap, name: &str) -> Vec<Vec<u8>> {
        headers
            .get_all(name)
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect()
    }
}
