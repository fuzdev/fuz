//! Query-string shape helpers converging axum handlers with the TS twin's
//! query semantics.
//!
//! `fuz_app`'s route pipeline reads queries through Hono's `c.req.query()` —
//! a duplicated key resolves to its **first** occurrence, and routes that
//! declare a `z.strictObject` query schema 400 unknown keys in the
//! params → query → 401 → authz → 403 phase order. axum's derived-serde
//! `Query<T>` extractor diverges on every axis: it answers a duplicated
//! known key with a plain-text "duplicate field" 400 **before the handler
//! runs** (a backend fingerprint observable anonymously), silently ignores
//! unknown keys, and rejects ahead of any params/auth work the TS order
//! runs first.
//!
//! Handlers that must match the TS twin therefore take
//! `Query<Vec<(String, String)>>` (never rejects) and go through
//! [`query_first`] — plus [`assert_known_query_keys`] when (and only when)
//! the TS route declares a strict query schema. A TS route with **no**
//! query schema (e.g. `GET /api/account/status`) ignores unknown keys, so
//! its twin uses [`query_first`] alone.
//!
//! A pair with an empty name (`?=x`) is not a key on the TS side: Hono builds
//! the `c.req.query()` record by skipping a pair whose decoded name is empty,
//! so a strict schema is never shown one. axum's extractor keeps it, as
//! `("", "x")`, and [`assert_known_query_keys`] passes over it.

use axum::response::Response;

use crate::rest_error::invalid_query_params_response;

/// Refuse unknown query keys — the twin of a TS route's `z.strictObject`
/// query schema, where an undeclared key is a 400 `invalid_query_params`.
///
/// Call before any auth resolution so the phase order matches the TS
/// pipeline (params → query → 401/403). Only for routes whose TS twin
/// declares a strict query schema; a schema-less TS route ignores unknown
/// keys and its twin must too.
///
/// A pair with an empty name (`?=x`, `?=`, `=x` beside a declared key) is
/// ignored rather than refused: Hono leaves it out of the record the schema
/// parses, so the TS route has no key to object to. The name is the decoded
/// one on both sides — `?+=x` and `?%20=x` name a key that is one space, and
/// are refused like any other undeclared key.
///
/// One spelling still differs: a key named for an `Object.prototype` member
/// (`constructor`, `toString`, `__proto__`, …) is dropped by Hono's record
/// builder, so the TS route accepts it; here it is an undeclared key.
///
/// # Errors
///
/// Returns the flat 400 `invalid_query_params` denial `Response` (`Err`)
/// when a non-empty key falls outside `allowed`.
#[allow(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine REST handler idiom"
)]
pub fn assert_known_query_keys(
    pairs: &[(String, String)],
    allowed: &[&str],
) -> Result<(), Response> {
    if pairs
        .iter()
        .any(|(k, _)| !k.is_empty() && !allowed.contains(&k.as_str()))
    {
        return Err(invalid_query_params_response());
    }
    Ok(())
}

/// First occurrence of `key` in the raw query pairs.
///
/// The TS twin's duplicate-key semantics: Hono's `c.req.query()` keeps the
/// first value, and later occurrences are invisible to validation, so
/// `?limit=5&limit=1001` reads as `limit=5`.
#[must_use]
pub fn query_first<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(k, val)| ((*k).to_owned(), (*val).to_owned()))
            .collect()
    }

    #[test]
    fn unknown_query_key_is_refused() {
        let p = pairs(&[("acting", "x"), ("foo", "1")]);
        let resp = assert_known_query_keys(&p, &["acting"]).expect_err("foo refused");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn empty_query_passes_any_allowlist() {
        assert_known_query_keys(&[], &[]).expect("empty query passes");
        assert_known_query_keys(&[], &["acting"]).expect("empty query passes");
    }

    /// A nameless pair is not a key: it passes any allowlist — alone,
    /// repeated, or on either side of a declared key — and hides nothing, so
    /// an undeclared key beside it is still refused.
    #[test]
    fn nameless_pair_is_ignored_and_hides_no_unknown_key() {
        for p in [
            pairs(&[("", "x")]),
            pairs(&[("", "")]),
            pairs(&[("", "x"), ("", "y")]),
            pairs(&[("", "x"), ("acting", "a")]),
            pairs(&[("acting", "a"), ("", "x")]),
        ] {
            assert_known_query_keys(&p, &["acting"])
                .unwrap_or_else(|_| panic!("a nameless pair is not a key: {p:?}"));
        }
        assert_known_query_keys(&pairs(&[("", "x")]), &[]).expect("no allowlist entry needed");

        for p in [
            pairs(&[("", "x"), ("foo", "1")]),
            pairs(&[("foo", "1"), ("", "x")]),
            // a one-space name is a name
            pairs(&[(" ", "x")]),
        ] {
            let resp = assert_known_query_keys(&p, &["acting"])
                .expect_err("an undeclared key is refused beside a nameless pair");
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{p:?}");
        }

        let p = pairs(&[("", "x"), ("acting", "a")]);
        assert_eq!(query_first(&p, "acting"), Some("a"));
    }

    /// The same rule from the raw query string, through the extractor the
    /// handlers take — pinning which spellings reach the helper with an empty
    /// name. Each verdict is the one the TS twin's strict `{acting}` schema
    /// gives the record Hono's `c.req.query()` builds from that string.
    #[test]
    fn raw_query_spellings_get_the_twin_verdict() {
        use axum::extract::Query;
        use axum::http::Uri;

        let cases = [
            // no pair at all
            ("", true),
            ("&", true),
            ("&&", true),
            // an empty name: skipped
            ("=x", true),
            ("=", true),
            ("=x=y", true),
            ("&=", true),
            ("=x&=y", true),
            ("=x&acting=3f8a1c2e-1234-4abc-9def-0123456789ab", true),
            ("acting=3f8a1c2e-1234-4abc-9def-0123456789ab&=x", true),
            // an undeclared name, with or without a nameless pair beside it
            ("foo", false),
            ("foo=", false),
            ("=x&foo=1", false),
            ("a&=x", false),
            // a name that only looks empty: one space, one `%`, one NUL
            ("+=x", false),
            ("%20=x", false),
            ("%=x", false),
            ("%00=x", false),
        ];
        for (raw, accepted) in cases {
            let uri: Uri = format!("/r?{raw}").parse().expect("uri parses");
            let Query(p) = Query::<Vec<(String, String)>>::try_from_uri(&uri)
                .expect("the raw-pairs extractor never rejects");
            assert_eq!(
                assert_known_query_keys(&p, &["acting"]).is_ok(),
                accepted,
                "?{raw} → {p:?}"
            );
        }
    }

    #[test]
    fn known_keys_pass_and_duplicates_take_the_first() {
        let p = pairs(&[("limit", "5"), ("limit", "1001"), ("offset", "0")]);
        assert_known_query_keys(&p, &["offset", "limit"]).expect("known keys pass");
        assert_eq!(query_first(&p, "limit"), Some("5"), "first occurrence wins");
        assert_eq!(query_first(&p, "offset"), Some("0"));
        assert_eq!(query_first(&p, "acting"), None);
    }
}
