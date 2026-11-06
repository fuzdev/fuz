//! Parsing the `?acting=` selector shared by the REST/serving routes.
//!
//! The `acting` actor selector arrives as a query-string value on the
//! hand-mounted routes that resolve the acting actor themselves rather than
//! through the RPC dispatcher ([`crate::actor_queries`]'s resolver consumes
//! the parsed `Uuid`): the role-gated REST surfaces — `fuz_fact_serving`'s
//! bare-hash read, `fuz_db_admin`'s router, `fuz_realtime`'s audit stream —
//! `GET /api/account/status`, and routes a consumer mounts itself.
//! `fuz_fact_serving`'s cell-scoped public route is not among them: it
//! declares no `acting` slot, reads no query, and treats a multi-actor caller
//! as anonymous. The TS `ActingActor` is a bare optional `Uuid`
//! (`http/auth_shape.ts`), so the only accepted spelling is a bare uuid under
//! the strict wire grammar of the `fuz_schema` `Uuid` twin, which takes the
//! max UUID in any case — [`fuz_http::is_valid_uuid`] is that grammar's Rust
//! twin and gates this parser. The TS status route and WS upgrade read the
//! raw query through `parse_acting`, by the same grammar; the TS REST query
//! routes validate `acting` with a Zod query schema, which refuses the
//! uppercase max (see [`parse_acting_selector`]). This module is the single
//! parser for that shape;
//! each route maps a malformed value to its own transport error (400) or
//! treats it as absent, per its posture.
//!
//! The JSON `?params=` decoding on the RPC GET path is a different concept and
//! is not this parser's business: that one decodes a whole JSON-RPC params
//! object, not a selector value.
//!
//! [`parse_acting_query`] bundles the parse with the flat 400
//! `invalid_query_params` for the routes that answer a malformed selector
//! that way — in this workspace, the role-gated surfaces above.
//! [`parse_acting_selector`] is the parse alone, for a route that disposes of
//! a malformed value itself: the `/status` persona picker treats it as
//! absent, and a route with its own error envelope answers its own 400.

use axum::response::Response;
use fuz_http::invalid_query_params_response;
use uuid::Uuid;

/// The `?acting=` value was present but not a valid uuid.
///
/// Callers map this to a 400 (the routes that go on to require an acting
/// actor) or treat it as absent (the `/status` persona picker, where no
/// persona is an answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActingSelectorParseError;

/// Parse an optional `?acting=` selector value.
///
/// - absent (`None`) → `Ok(None)` (the single-actor / default case).
/// - a bare uuid → `Ok(Some(uuid))`.
/// - present but unparseable → `Err(ActingSelectorParseError)` — the caller
///   decides whether that is a 400 or a treated-as-absent missing persona.
///
/// "Bare uuid" is the [`fuz_http::is_valid_uuid`] grammar — the twin of the TS
/// `parse_acting`'s, the `fuz_schema` `Uuid` — not Rust's permissive
/// `Uuid::parse_str`. So a JSON-quoted spelling (`"<uuid>"`), a hyphenless,
/// braced, or URN form, and an id whose version/variant nibbles are out of
/// range are all refused, and the max UUID is a selector in any case, as the
/// twin takes it.
///
/// # Errors
///
/// Returns [`ActingSelectorParseError`] when `raw` is present but is not a bare
/// uuid.
// TODO: the gap closes when the TS query schemas declare the `fuz_schema`
// `ActingActor` twin
pub fn parse_acting_selector(raw: Option<&str>) -> Result<Option<Uuid>, ActingSelectorParseError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if !fuz_http::is_valid_uuid(raw) {
        return Err(ActingSelectorParseError);
    }
    Uuid::parse_str(raw)
        .map(Some)
        .map_err(|_| ActingSelectorParseError)
}

/// Parse an optional `?acting=` selector value, mapping a malformed value to
/// the canonical 400 `{error: "invalid_query_params"}` denial `Response`.
///
/// The bundled form of [`parse_acting_selector`] for the routes whose posture
/// is "present-but-malformed is a client error" in the flat REST envelope. In
/// this workspace those are `fuz_fact_serving`'s admin-only bare-hash read
/// (not its cell-scoped public route, which takes no selector), the
/// `fuz_db_admin` router, and `fuz_realtime`'s audit stream. Absent ⇒
/// `Ok(None)` (the single-actor / default case).
///
/// # Errors
///
/// Returns the ready-to-return 400 denial `Response` (`Err`) when `raw` is
/// present but is not a bare uuid.
#[allow(
    clippy::result_large_err,
    reason = "Err is the ready-to-return axum Response — the spine's REST handler idiom"
)]
pub fn parse_acting_query(raw: Option<&str>) -> Result<Option<Uuid>, Response> {
    parse_acting_selector(raw).map_err(|_| invalid_query_params_response())
}

#[cfg(test)]
mod tests {
    use super::{ActingSelectorParseError, parse_acting_query, parse_acting_selector};
    use axum::http::StatusCode;

    #[test]
    fn absent_is_none() {
        assert_eq!(parse_acting_selector(None), Ok(None));
    }

    #[test]
    fn bare_uuid() {
        let id = "3f8a1c2e-1234-4abc-9def-0123456789ab";
        assert_eq!(
            parse_acting_selector(Some(id)),
            Ok(Some(id.parse().unwrap()))
        );
    }

    /// Either case is a selector, the max UUID too, and names the id its
    /// lowercase spelling does — the value TS `parse_acting` returns.
    #[test]
    fn either_case_names_the_lowercase_id() {
        for (raw, canonical) in [
            (
                "3F8A1C2E-1234-4ABC-9DEF-0123456789AB",
                "3f8a1c2e-1234-4abc-9def-0123456789ab",
            ),
            (
                "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
            (
                "ffffffff-FFFF-ffff-FFFF-ffffffffffff",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
        ] {
            let Ok(Some(parsed)) = parse_acting_selector(Some(raw)) else {
                panic!("{raw} must be a selector");
            };
            assert_eq!(parsed.to_string(), canonical, "{raw}");
        }
    }

    /// Every spelling the twin grammar refuses (the TS Zod `Uuid` too). The JSON-quoted
    /// form is the load-bearing row: `?acting=%22<uuid>%22` must be a 400 on
    /// both spines across every REST family that resolves the selector.
    #[test]
    fn malformed_is_err() {
        let id = "3f8a1c2e-1234-4abc-9def-0123456789ab";
        for raw in [
            "not-a-uuid",
            "",
            &format!("\"{id}\""),
            &format!("'{id}'"),
            &format!(" {id} "),
            // The wire grammar rows a bare `Uuid::parse_str` would admit:
            // hyphenless, braced, URN, and a bad variant nibble.
            "3f8a1c2e12344abc9def0123456789ab",
            &format!("{{{id}}}"),
            &format!("urn:uuid:{id}"),
            "11111111-1111-1111-1111-111111111111",
        ] {
            assert_eq!(
                parse_acting_selector(Some(raw)),
                Err(ActingSelectorParseError),
                "raw: {raw}"
            );
        }
    }

    #[test]
    fn query_absent_is_none() {
        assert!(matches!(parse_acting_query(None), Ok(None)));
    }

    #[test]
    fn query_bare_uuid() {
        let id = "3f8a1c2e-1234-4abc-9def-0123456789ab";
        let Ok(Some(parsed)) = parse_acting_query(Some(id)) else {
            panic!("a bare uuid must parse");
        };
        assert_eq!(parsed, id.parse::<uuid::Uuid>().unwrap());
    }

    #[test]
    fn query_malformed_is_400() {
        let id = "3f8a1c2e-1234-4abc-9def-0123456789ab";
        for raw in [
            "not-a-uuid",
            &format!("\"{id}\""),
            "3f8a1c2e12344abc9def0123456789ab",
        ] {
            let Err(response) = parse_acting_query(Some(raw)) else {
                panic!("expected a 400 denial for {raw}");
            };
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
