//! SQL identifier validation for dynamic DDL queries.
//!
//! `PostgreSQL` DDL operations (`DROP TABLE`, `TRUNCATE`, `ALTER`) do not
//! support parameterized table/column names — only values can be
//! parameterized. This validator gates table/column names before they
//! are string-interpolated into DDL queries.
//!
//! Ported from `fuz_app/src/lib/db/sql_identifier.ts`. No regex crate
//! dependency — the rule (`[a-zA-Z_][a-zA-Z0-9_]*`) is cheap to check
//! by hand.

use crate::error::DbError;

/// Test whether `name` matches the valid-identifier rule
/// (`[a-zA-Z_][a-zA-Z0-9_]*`, the JS `/^[a-zA-Z_][a-zA-Z0-9_]*$/`).
///
/// The rule is spelled by this function and nowhere else. The TS twin
/// exports its regex as `VALID_SQL_IDENTIFIER` and tests against it; the
/// Rust port checked by hand and exported the pattern *as an inert string*
/// beside it, so the shared name promised an enforcement it never carried —
/// editing it changed nothing. Dropped rather than kept in sync with a
/// validator that doesn't read it.
#[must_use]
pub fn is_valid_sql_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        None => false,
        Some(c) if !c.is_ascii_alphabetic() && c != '_' => false,
        _ => chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
    }
}

/// Assert that a string is a valid SQL identifier.
///
/// # Errors
///
/// Returns [`DbError::InvalidIdentifier`] when the input contains
/// characters outside `[a-zA-Z0-9_]` or starts with a digit.
pub fn assert_valid_sql_identifier(name: &str) -> Result<&str, DbError> {
    if is_valid_sql_identifier(name) {
        Ok(name)
    } else {
        Err(DbError::InvalidIdentifier(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_typical_table_names() {
        for name in &[
            "account",
            "actor",
            "_private",
            "schema_version",
            "Camel_Case",
            "x1",
        ] {
            assert!(is_valid_sql_identifier(name), "expected {name} to be valid");
            assert!(assert_valid_sql_identifier(name).is_ok());
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_valid_sql_identifier(""));
        assert!(assert_valid_sql_identifier("").is_err());
    }

    #[test]
    fn rejects_leading_digit() {
        assert!(!is_valid_sql_identifier("1table"));
        match assert_valid_sql_identifier("1table") {
            Err(DbError::InvalidIdentifier(s)) => assert_eq!(s, "1table"),
            other => panic!("expected InvalidIdentifier, got {other:?}"),
        }
    }

    #[test]
    fn rejects_injection_attempts() {
        for evil in &[
            "users; DROP TABLE accounts",
            "users--",
            "users'",
            "users\";",
            "users users",
            "users\nDROP",
            "users(1)",
            "user-table",
            "users.column",
            "",
            " users",
            "users ",
        ] {
            assert!(
                !is_valid_sql_identifier(evil),
                "expected {evil:?} to be rejected"
            );
            assert!(assert_valid_sql_identifier(evil).is_err());
        }
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(!is_valid_sql_identifier("naïve"));
        assert!(!is_valid_sql_identifier("café"));
    }
}
