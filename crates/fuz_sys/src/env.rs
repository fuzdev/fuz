//! Environment-value parsing helpers.
//!
//! Pure parsers for env-driven config, shared across spine consumers and the
//! test fixtures (`fuz_testing`'s startup DB reset). The helpers take a `&str`
//! rather than reading `std::env` themselves so callers keep their own
//! var-lookup seam — production reads `std::env::var`, tests inject a map
//! (matching the `from_vars` testability pattern) — and so the parsers stay
//! race-free and unit-testable without mutating global process env.

use thiserror::Error;

/// A string value that isn't a recognized `stringbool` token.
///
/// Carries the offending value so the caller can surface it (typically
/// prefixed with the env var name). See [`parse_stringbool`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("expected a boolean (true/1/yes/on/y/enabled or false/0/no/off/n/disabled), got {value:?}")]
pub struct StringboolParseError {
    /// The unrecognized value, verbatim.
    pub value: String,
}

/// Parse a stringbool value: case-insensitive truthy
/// (`true`/`1`/`yes`/`on`/`y`/`enabled`) / falsy
/// (`false`/`0`/`no`/`off`/`n`/`disabled`).
///
/// Unknown values error rather than defaulting, so a typo doesn't
/// silently flip an env-driven feature. The error carries the offending
/// value; callers prepend the env var name when surfacing it.
///
/// Mirrors the TS spine's `EnvStringbool` — the env contract
/// shared with `fuz_app`'s `BaseServerEnv`.
///
/// # Errors
///
/// [`StringboolParseError`] when `value` is outside the recognized set.
pub fn parse_stringbool(value: &str) -> Result<bool, StringboolParseError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" | "y" | "enabled" => Ok(true),
        "false" | "0" | "no" | "off" | "n" | "disabled" => Ok(false),
        _ => Err(StringboolParseError {
            value: value.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_truthy_values() {
        for raw in ["true", "TRUE", "1", "yes", "on", "y", "enabled", "Enabled"] {
            assert_eq!(parse_stringbool(raw), Ok(true), "{raw:?} should be truthy");
        }
    }

    #[test]
    fn parses_falsy_values() {
        for raw in [
            "false", "FALSE", "0", "no", "off", "n", "disabled", "Disabled",
        ] {
            assert_eq!(parse_stringbool(raw), Ok(false), "{raw:?} should be falsy");
        }
    }

    #[test]
    fn rejects_unknown_value() {
        let err = parse_stringbool("maybe").unwrap_err();
        // Offending value is carried verbatim and appears in the message.
        assert_eq!(err.value, "maybe");
        assert!(err.to_string().contains("maybe"));
    }
}
