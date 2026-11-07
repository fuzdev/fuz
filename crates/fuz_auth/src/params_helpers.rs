//! Auth-owned JSON-RPC params rules: role names, text bounds, and the paged
//! reads' `limit` / `offset` / `since_seq` with their declared reasons.
//!
//! The generic hand-decode helpers these build on — field parsers, the
//! wire-UUID grammar, the unknown-key / null-key / void refusals — live in
//! `fuz_http::params`; this module keeps only the rules that name fields the
//! auth surface owns.
//!
//! Every check here is one the TS twin makes in an action's input schema, so
//! every refusal is [`invalid_input_params`]: the generic `invalid params`
//! message the twin answers, the per-field detail logged at debug, and a
//! `data.reason` only where the field declares one.

use serde_json::Value;

use fuz_http::{
    JsonrpcError, SAFE_INTEGER_MAX, invalid_input_params, parse_optional_i64_param, parse_str_param,
};

/// `data.reason` on every refusal of a paged read's `limit`: outside
/// `[1, max_limit]`, or not an integer.
///
/// A declared reason: the TS twin's `limit` field carries it as its
/// `invalid_reason` (`ERROR_LIMIT_INVALID` in `fuz_app`'s
/// `http/error_schemas.ts`), and both spines answer it on **every** refusal of
/// the field, whatever the fault — so a non-integer `limit` carries it too.
pub const ERROR_LIMIT_INVALID: &str = "limit_invalid";

/// `data.reason` on every refusal of a paged read's `offset`: negative, past
/// `Number.MAX_SAFE_INTEGER`, or not an integer. A declared reason, like
/// [`ERROR_LIMIT_INVALID`].
pub const ERROR_OFFSET_INVALID: &str = "offset_invalid";

/// `data.reason` on every refusal of `audit_log_list`'s `since_seq` cursor:
/// negative, past `Number.MAX_SAFE_INTEGER`, or not an integer. A declared
/// reason, like [`ERROR_LIMIT_INVALID`].
///
/// A sibling of [`ERROR_OFFSET_INVALID`] rather than a reuse of it: the two
/// name different fields, and a client discriminating on the reason must be
/// able to tell which one it got wrong.
pub const ERROR_SINCE_SEQ_INVALID: &str = "since_seq_invalid";

/// `data.reason` on every refusal of `audit_log_list`'s `outcome` filter: a
/// string outside the closed enum (`'success' | 'failure'`), or not a string.
/// A declared reason, like [`ERROR_LIMIT_INVALID`].
pub const ERROR_OUTCOME_INVALID: &str = "outcome_invalid";

/// Parse a required role-name field — the twin of a TS input field declared
/// as `RoleName`.
///
/// A role string is caller-chosen until it passes this: the grant verbs
/// write the role they refuse into a failure audit row, so the grammar has to
/// hold before any gate that audits. [`crate::name_schema::is_valid_name`],
/// the shared name grammar, is the grammar: it fixes the alphabet — lowercase
/// ASCII letters and underscores, the letters in runs joined by single
/// underscores — and the length, at most
/// [`crate::name_schema::NAME_LENGTH_MAX`], so a failure row never carries
/// more than that of the caller's text.
///
/// # Errors
///
/// [`invalid_input_params`] (no `reason`) on missing / non-string /
/// off-grammar: the generic `invalid params` on the wire, the field named in
/// the debug log.
pub(crate) fn parse_role_param<'a>(
    params: &'a Value,
    name: &'static str,
) -> Result<&'a str, JsonrpcError> {
    let role = parse_str_param(params, name)?;
    if !crate::name_schema::is_valid_name(role) {
        return Err(invalid_input_params(
            &format!("'{name}' is not a valid role name"),
            None,
        ));
    }
    Ok(role)
}

/// Refuse a text field longer than `max` — the twin of a TS
/// `bounded_string({max})`.
///
/// The count is UTF-16 code units, which is what `String.length` — and so
/// the twin's `bounded_string`, a `fuz_schema` `max_length` — measures: a value of exactly `max` units passes, and an astral-plane
/// character costs two on both spines. The hand-decoded specs
/// carry no schema to enforce the bound, so each one calls this on the field
/// it bounds.
///
/// # Errors
///
/// `invalid_params` when the value is over the bound (the generic message on the
/// wire; the debug log names the field and the bound).
pub(crate) fn require_text_len(
    value: &str,
    max: usize,
    field: &'static str,
) -> Result<(), JsonrpcError> {
    if value.encode_utf16().count() > max {
        return Err(invalid_input_params(
            &format!("'{field}' must be at most {max} characters"),
            None,
        ));
    }
    Ok(())
}

/// [`parse_optional_i64_param`] for a field that declares a reason: a present
/// non-integer carries `reason` too, since the twin answers a field's declared
/// reason on every refusal of it.
fn parse_optional_reasoned_i64_param(
    params: &Value,
    name: &'static str,
    reason: &'static str,
) -> Result<Option<i64>, JsonrpcError> {
    parse_optional_i64_param(params, name).map_err(|e| JsonrpcError {
        data: Some(serde_json::json!({"reason": reason})),
        ..e
    })
}

/// Validated pagination shape returned by [`parse_pagination_params`].
#[derive(Debug, Clone, Copy)]
pub struct PaginationParams {
    /// `1..=max_limit` enforced by the parser.
    pub limit: i64,
    /// `0..=SAFE_INTEGER_MAX` enforced by the parser.
    pub offset: i64,
}

/// Parse `{limit?, offset?}` from JSON-RPC params with bounded validation.
///
/// Defaults: `limit = default_limit` (when omitted/null); `offset = 0`.
/// Validates `limit ∈ [1, max_limit]` and `offset ∈ [0, SAFE_INTEGER_MAX]`.
/// Every refusal of a field carries that field's declared reason —
/// [`ERROR_LIMIT_INVALID`] for `limit`, [`ERROR_OFFSET_INVALID`] for
/// `offset` — whatever the fault: out of range, past [`SAFE_INTEGER_MAX`], or
/// not an integer. The twin declares the same reasons on the
/// `AdminAccountListInput` / `AuditLogListInput` /
/// `AuditLogRoleGrantHistoryInput` / `RoleGrantOfferHistoryInput` fields, and
/// its dispatcher answers them on every refusal of the field.
///
/// # Errors
///
/// `invalid_params` with the field's reason on a non-integer limit/offset, an
/// out-of-range limit, or a negative or unsafe offset.
pub fn parse_pagination_params(
    params: &Value,
    default_limit: i64,
    max_limit: i64,
) -> Result<PaginationParams, JsonrpcError> {
    let limit = parse_optional_reasoned_i64_param(params, "limit", ERROR_LIMIT_INVALID)?
        .unwrap_or(default_limit);
    if limit < 1 || limit > max_limit {
        return Err(invalid_input_params(
            &format!("'limit' must be between 1 and {max_limit}"),
            Some(ERROR_LIMIT_INVALID),
        ));
    }
    let offset =
        parse_optional_reasoned_i64_param(params, "offset", ERROR_OFFSET_INVALID)?.unwrap_or(0);
    if offset < 0 {
        return Err(invalid_input_params(
            "'offset' must be >= 0",
            Some(ERROR_OFFSET_INVALID),
        ));
    }
    if offset > SAFE_INTEGER_MAX {
        return Err(invalid_input_params(
            "'offset' must be a safe integer",
            Some(ERROR_OFFSET_INVALID),
        ));
    }
    Ok(PaginationParams { limit, offset })
}

/// Parse the optional `since_seq` gap-fill cursor, bounded at zero.
///
/// The twin declares it `optional(nullable(pipe(number, integer, min_value(0), ...)))`, so a negative
/// cursor is `invalid_params` there rather than a query predicate that admits
/// every row. Every refusal — negative, past [`SAFE_INTEGER_MAX`], or not an
/// integer — carries [`ERROR_SINCE_SEQ_INVALID`], the field's declared
/// reason on the twin.
///
/// # Errors
///
/// `invalid_params` with [`ERROR_SINCE_SEQ_INVALID`] on a non-integer,
/// negative, or unsafe `since_seq`.
pub fn parse_optional_since_seq_param(params: &Value) -> Result<Option<i64>, JsonrpcError> {
    let since_seq =
        parse_optional_reasoned_i64_param(params, "since_seq", ERROR_SINCE_SEQ_INVALID)?;
    if since_seq.is_some_and(|s| s < 0) {
        return Err(invalid_input_params(
            "'since_seq' must be >= 0",
            Some(ERROR_SINCE_SEQ_INVALID),
        ));
    }
    // the twin's `int()` refuses past `Number.MAX_SAFE_INTEGER`, under the
    // field's declared reason like every other refusal of it
    if since_seq.is_some_and(|s| s > SAFE_INTEGER_MAX) {
        return Err(invalid_input_params(
            "'since_seq' must be a safe integer",
            Some(ERROR_SINCE_SEQ_INVALID),
        ));
    }
    Ok(since_seq)
}
#[cfg(test)]
mod tests {
    use super::{
        ERROR_LIMIT_INVALID, ERROR_OFFSET_INVALID, ERROR_SINCE_SEQ_INVALID, SAFE_INTEGER_MAX,
        parse_optional_since_seq_param, parse_pagination_params, parse_role_param,
        require_text_len,
    };
    use fuz_http::{JsonrpcError, JsonrpcErrorCode};
    use serde_json::{Value, json};

    /// A role field is a string in the role-name grammar; anything else —
    /// absent, another type, or a string outside the grammar, its length cap
    /// included — is `invalid_params` with no `reason`.
    #[test]
    fn parse_role_param_holds_the_role_name_grammar() {
        let at_max = "a".repeat(crate::name_schema::NAME_LENGTH_MAX);
        for role in ["admin", "a", "space_member", "a_b_c", at_max.as_str()] {
            assert_eq!(
                parse_role_param(&json!({ "role": role }), "role").ok(),
                Some(role)
            );
        }
        for params in [
            // on the alphabet, one past the length cap
            json!({"role": format!("{at_max}a")}),
            json!({}),
            json!({"role": null}),
            json!({"role": 7}),
            json!({"role": ""}),
            json!({"role": "Admin"}),
            json!({"role": "two words"}),
            json!({"role": "_admin"}),
            json!({"role": "admin_"}),
            json!({"role": "ad__min"}),
            json!({"role": "ad___min"}),
            json!({"role": "admin\n"}),
            json!({"role": "r\u{f4}le"}),
        ] {
            let err = parse_role_param(&params, "role").expect_err("refused");
            assert_eq!(err.code, JsonrpcErrorCode::InvalidParams, "{params}");
            assert!(err.data.is_none(), "{params}");
        }
    }

    /// The bound is inclusive, counted in UTF-16 code units, and its refusal
    /// names the field and the bound.
    #[test]
    fn a_text_bound_is_inclusive_and_counts_utf16_units() {
        const MAX: usize = 7;
        assert!(require_text_len("", MAX, "note").is_ok());
        assert!(require_text_len(&"a".repeat(MAX), MAX, "note").is_ok());
        let error = require_text_len(&"a".repeat(MAX + 1), MAX, "note")
            .expect_err("one past the bound is refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE);
        assert_eq!(error.data, None);

        // U+00FC is two bytes and one unit: bytes are not the measure.
        assert!(require_text_len(&"\u{00FC}".repeat(MAX), MAX, "note").is_ok());
        // U+1F600 is one `char` and two units: `char`s are not the measure.
        let astral_at_max = format!("a{}", "\u{1F600}".repeat(3));
        assert_eq!(astral_at_max.encode_utf16().count(), MAX);
        assert!(require_text_len(&astral_at_max, MAX, "note").is_ok());
        let astral_over = "\u{1F600}".repeat(4);
        assert_eq!(astral_over.chars().count(), 4, "under the bound in chars");
        assert_eq!(astral_over.encode_utf16().count(), MAX + 1);
        assert!(require_text_len(&astral_over, MAX, "note").is_err());
    }

    #[test]
    fn integers_past_the_safe_range_carry_the_field_reason() {
        let page = parse_pagination_params(&json!({"offset": SAFE_INTEGER_MAX}), 10, 100)
            .expect("the safe max is admitted");
        assert_eq!(page.offset, SAFE_INTEGER_MAX);
        for params in [
            json!({"offset": SAFE_INTEGER_MAX + 1}),
            json!({"offset": i64::MAX}),
        ] {
            let e = parse_pagination_params(&params, 10, 100).expect_err("past the safe range");
            assert_eq!(e.code, JsonrpcErrorCode::InvalidParams, "{params}");
            assert_eq!(reason_of(&e), Some(ERROR_OFFSET_INVALID), "{params}");
        }
        assert_eq!(
            parse_optional_since_seq_param(&json!({"since_seq": SAFE_INTEGER_MAX}))
                .expect("the safe max is admitted"),
            Some(SAFE_INTEGER_MAX)
        );
        let e = parse_optional_since_seq_param(&json!({"since_seq": SAFE_INTEGER_MAX + 1}))
            .expect_err("past the safe range");
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(reason_of(&e), Some(ERROR_SINCE_SEQ_INVALID));
    }

    fn reason_of(e: &JsonrpcError) -> Option<&str> {
        e.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str)
    }

    /// The twin's dispatcher answers a declared field's reason on every
    /// refusal of the field, so each case kind the adversarial suites generate
    /// — a wrong type, a fraction, an out-of-range or unsafe integer — carries
    /// it here too.
    #[test]
    fn every_refusal_of_a_paging_field_carries_its_reason() {
        for (params, reason) in [
            (json!({"limit": "not_a_number"}), ERROR_LIMIT_INVALID),
            (json!({"limit": 1.5}), ERROR_LIMIT_INVALID),
            (json!({"limit": true}), ERROR_LIMIT_INVALID),
            (json!({"limit": 0}), ERROR_LIMIT_INVALID),
            (json!({"limit": 101}), ERROR_LIMIT_INVALID),
            (json!({"limit": 1e16}), ERROR_LIMIT_INVALID),
            (json!({"offset": "not_a_number"}), ERROR_OFFSET_INVALID),
            (json!({"offset": 0.5}), ERROR_OFFSET_INVALID),
            (json!({"offset": [1]}), ERROR_OFFSET_INVALID),
            (json!({"offset": -1}), ERROR_OFFSET_INVALID),
            (json!({"offset": 1e16}), ERROR_OFFSET_INVALID),
        ] {
            let e = parse_pagination_params(&params, 10, 100).expect_err("refused");
            assert_eq!(e.code, JsonrpcErrorCode::InvalidParams, "{params}");
            assert_eq!(reason_of(&e), Some(reason), "{params}");
        }
        for params in [
            json!({"since_seq": "1"}),
            json!({"since_seq": 1.5}),
            json!({"since_seq": -1}),
            json!({"since_seq": 1e16}),
        ] {
            let e = parse_optional_since_seq_param(&params).expect_err("refused");
            assert_eq!(reason_of(&e), Some(ERROR_SINCE_SEQ_INVALID), "{params}");
        }
    }

    /// Parse wire text, so `-0` and `5.0` reach the helpers as serde decodes
    /// them off a request rather than as `json!` builds them.
    fn wire(text: &str) -> Value {
        serde_json::from_str(text).expect("valid JSON")
    }

    #[test]
    fn paging_fields_admit_integral_floats() {
        let page = parse_pagination_params(&wire(r#"{"limit": 5.0, "offset": -0}"#), 10, 100)
            .expect("integral floats are integers");
        assert_eq!((page.limit, page.offset), (5, 0));
        let page = parse_pagination_params(&wire(r#"{"limit": 1e1, "offset": 2e0}"#), 10, 100)
            .expect("exponents are integers");
        assert_eq!((page.limit, page.offset), (10, 2));
        assert_eq!(
            parse_optional_since_seq_param(&wire(r#"{"since_seq": 3.0}"#)).expect("admitted"),
            Some(3)
        );
        assert_eq!(
            parse_optional_since_seq_param(&wire(r#"{"since_seq": -0}"#)).expect("admitted"),
            Some(0)
        );
        // an integral float past the bound is still refused with the reason
        let e = parse_pagination_params(&wire(r#"{"limit": 101.0}"#), 10, 100)
            .expect_err("out of range");
        assert_eq!(reason_of(&e), Some(ERROR_LIMIT_INVALID));
    }

    /// A reasoned refusal keeps the generic message: the reason rides in
    /// `data`, never the detail.
    #[test]
    fn a_reasoned_type_refusal_keeps_the_generic_message() {
        let e = parse_pagination_params(&json!({"limit": "x"}), 10, 100).expect_err("refused");
        assert_eq!(e.message, fuz_http::INVALID_PARAMS_MESSAGE);
        assert_eq!(e.data, Some(json!({"reason": ERROR_LIMIT_INVALID})));
    }

    #[test]
    fn a_negative_since_seq_is_refused_and_zero_is_not() {
        // The twin bounds the cursor `pipe(number, integer, min_value(0), ...)`, so `-1` is
        // `invalid_params` there rather than a predicate matching every row.
        let e = parse_optional_since_seq_param(&json!({"since_seq": -1}))
            .expect_err("-1 must be refused");
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(
            e.data.as_ref().and_then(|d| d.get("reason")),
            Some(&json!(ERROR_SINCE_SEQ_INVALID)),
            "the reason names the field, not the pagination offset"
        );

        // Zero is the floor, and omitted / null both read as absent.
        assert_eq!(
            parse_optional_since_seq_param(&json!({"since_seq": 0})).expect("0 is admitted"),
            Some(0)
        );
        assert_eq!(
            parse_optional_since_seq_param(&json!({})).expect("absent is admitted"),
            None
        );
        assert_eq!(
            parse_optional_since_seq_param(&json!({"since_seq": Value::Null}))
                .expect("null is nullish-absent"),
            None
        );

        // A present wrong-typed cursor stays `-32602`, not silently absent.
        assert_eq!(
            parse_optional_since_seq_param(&json!({"since_seq": "1"}))
                .expect_err("a string must be refused")
                .code,
            JsonrpcErrorCode::InvalidParams
        );
    }
}
