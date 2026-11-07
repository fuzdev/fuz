//! Strict typed-params decoding — [`parse_strict_params`].
//!
//! The spine's typed inputs decode through `#[derive(Deserialize)]`, which
//! covers most of what the TS twin's strict object schema declares:
//! required-vs-optional, types, and (with `#[serde(deny_unknown_fields)]`)
//! unknown keys. It is *more permissive* than the twin in exactly one place —
//! serde maps a JSON `null` onto `Option::None`, where the twin's `optional`
//! admits an absent key and nothing else. So `{"ids": null}` reads as "no
//! filter" and answers `200` on the bare decode it wraps (the crate-private
//! `parse_params`), and `-32602` on the TS twin.
//!
//! [`parse_strict_params`] closes that: the same decode with a `null` walk in
//! front of it, and is the typed-params decode this crate exports for every
//! action input. An input whose twin declares a nullable field spells that out
//! through [`parse_strict_params_allowing_null`], which exempts the named
//! keys and holds the rest to the same walk.
//!
//! The hand-decoded half (field parsers, `reject_unknown_keys`) and the
//! wire-UUID adapters are the sibling [`crate::params`] module.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::jsonrpc_error::{JsonrpcError, invalid_input_params, parse_params};

/// Parse JSON-RPC `params` into a typed input, refusing an explicit `null` on
/// any key first.
///
/// The strict-object twin of `parse_params`, which it delegates the
/// decode to — see that function for the `params` object-or-null contract and
/// the positional-array guard. The extra half here is the `null` walk, run
/// **before** the decode so a `null` is refused rather than coerced into
/// `None`.
///
/// # Errors
///
/// [`invalid_input_params`] (-32602) for a key whose value is `null`, or
/// whatever `parse_params` refuses.
pub fn parse_strict_params<T: DeserializeOwned>(params: Value) -> Result<T, JsonrpcError> {
    parse_strict_params_allowing_null(params, &[])
}

/// Parse JSON-RPC `params` into a typed input, refusing an explicit `null` on
/// any key the twin does **not** declare `optional(nullable(...))` / `nullable(...)`.
///
/// The escape hatch [`parse_strict_params`] delegates to. Passing the
/// nullable keys explicitly — rather than opting the whole input out of the
/// walk — keeps the exemption as narrow as the schema is: `cell_create`
/// admits `null` on its nullish keys and still refuses it on `visibility` and
/// `acting`, exactly like the twin.
///
/// The named keys are only exempted from the walk; whether `null` then
/// decodes depends on the field, so pair a nullable UUID with
/// [`crate::deserialize_nullish_wire_uuid`] rather than the `optional`
/// deserializer.
///
/// # Errors
///
/// [`invalid_input_params`] (-32602) for a key outside `nullable` whose value is
/// `null`, or whatever `parse_params` refuses.
pub fn parse_strict_params_allowing_null<T: DeserializeOwned>(
    params: Value,
    nullable: &[&str],
) -> Result<T, JsonrpcError> {
    reject_null_fields(&params, nullable)?;
    parse_params(params)
}

/// Reject a JSON `null` on any top-level `params` key outside `nullable`.
///
/// The TS twin's `optional` admits an absent key and nothing else, so `{"ids":
/// null}` is `-32602` on the TS backend; serde's `Option<T>` instead maps
/// `null` to `None`, so the same request would read as "no filter" on Rust and
/// silently answer 200. This walk is what closes that.
///
/// The rule the `nullable` list encodes: a method may admit `null` on exactly
/// the keys its TS twin declares nullable (`nullable`, or `optional` of one)
/// (`cell_create.{kind,path,parent_id,policy}`, `cell_update.path`,
/// `cell_policy_set.policy`, the grant principal's `scope_id`), and nowhere
/// else. Name them as a const beside the
/// handler that passes them to [`parse_strict_params_allowing_null`], so the
/// exemption reads next to the schema it mirrors rather than being inferred
/// from a field's type.
///
/// **Top-level only — and what covers the nested fields is not this walk.**
/// The spine's nested inputs are discriminated unions of strict objects, and
/// they are *not* all-required: `CellGrantPrincipalInput::Role.scope_id` is
/// optional, and it is one of the three `optional(nullable(...))` keys named above. What
/// makes a nested optional safe is that every one of them carries an explicit
/// serde adapter that decides `null` itself — `deserialize_optional_wire_uuid`
/// refuses a present `null` ("expected a string", the `optional(...)` answer),
/// `deserialize_nullish_wire_uuid` maps it to `None` on purpose. A **bare**
/// `Option<T>` is the lenient shape, and there are none nested.
///
/// So the rule for a new nested optional field is "pick the adapter your twin's
/// modifier names", not "this walk has you covered" — it does not reach there.
/// A non-object `params` is a no-op here, and needs no caller-side
/// branch: an **absent** `params` reaches a handler as [`Value::Null`] on the
/// classified transports ([`crate::classify`] refuses every other non-object
/// at the envelope with `-32600`) and `parse_params` maps it to
/// `{}`, while on the unclassified GET query-string path
/// `parse_params`'s own object guard is what refuses the rest.
///
/// # Errors
///
/// [`invalid_input_params`] (-32602) for a key whose value is `null` (map order,
/// not wire order).
fn reject_null_fields(params: &Value, nullable: &[&str]) -> Result<(), JsonrpcError> {
    let Some(object) = params.as_object() else {
        return Ok(());
    };
    for (key, value) in object {
        if value.is_null() && !nullable.contains(&key.as_str()) {
            return Err(invalid_input_params(
                &format!("{key} must not be null"),
                None,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use super::*;
    use crate::JsonrpcErrorCode;

    /// The shape the walk exists for: optional scalars beside a loose nested
    /// object that models nothing (the `CellData` case).
    #[derive(Debug, Default, serde::Deserialize)]
    #[serde(default, deny_unknown_fields)]
    struct StrictInput {
        limit: Option<i64>,
        ids: Option<Vec<String>>,
        data: Option<Value>,
    }

    #[test]
    fn a_top_level_null_is_invalid_params() {
        for params in [
            serde_json::json!({"limit": null}),
            serde_json::json!({"ids": null}),
            serde_json::json!({"limit": 5, "ids": null}),
        ] {
            let e = parse_strict_params::<StrictInput>(params.clone()).unwrap_err();
            assert_eq!(e.code, JsonrpcErrorCode::InvalidParams, "params: {params}");
            assert_eq!(e.message, crate::INVALID_PARAMS_MESSAGE, "params: {params}");
        }
    }

    #[test]
    fn a_nested_null_inside_a_loose_value_is_accepted() {
        // The walk is top-level only — `data` is an untyped JSON blob on the
        // wire, and a `null` inside it is content, not an absent field.
        let input: StrictInput =
            parse_strict_params(serde_json::json!({"data": {"x": null}})).expect("nested null ok");
        assert_eq!(input.data, Some(serde_json::json!({"x": null})));
    }

    #[test]
    fn an_absent_key_still_defaults() {
        let input: StrictInput = parse_strict_params(serde_json::json!({})).expect("empty ok");
        assert!(input.limit.is_none() && input.ids.is_none() && input.data.is_none());

        // An absent `params` arrives as `Value::Null` and is a no-op walk.
        let input: StrictInput = parse_strict_params(Value::Null).expect("null params ok");
        assert!(input.limit.is_none());
    }

    #[test]
    fn a_declared_nullable_key_is_exempt_and_its_neighbours_are_not() {
        let input: StrictInput =
            parse_strict_params_allowing_null(serde_json::json!({"ids": null}), &["ids"])
                .expect("a declared-nullable key admits null");
        assert!(input.ids.is_none());

        let e = parse_strict_params_allowing_null::<StrictInput>(
            serde_json::json!({"ids": null, "limit": null}),
            &["ids"],
        )
        .unwrap_err();
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.message, crate::INVALID_PARAMS_MESSAGE);
    }

    #[test]
    fn the_underlying_parse_params_contract_still_applies() {
        // The positional-array guard and `deny_unknown_fields` are inherited.
        let e = parse_strict_params::<StrictInput>(serde_json::json!([1])).unwrap_err();
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        let e = parse_strict_params::<StrictInput>(serde_json::json!({"nope": 1})).unwrap_err();
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
    }
}
