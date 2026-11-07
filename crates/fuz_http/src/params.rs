//! Hand-decoded JSON-RPC params: the field helpers, the wire-UUID grammar, and
//! the input shape with its void rule.
//!
//! Action handlers that read `params: &serde_json::Value` field by field share
//! these helpers: pull a string field, parse it as a UUID, refuse an
//! undeclared key, refuse a present `null` the twin's `optional` refuses.
//! Every check here is one the TS twin makes in an action's input schema, so
//! every refusal is [`invalid_input_params`]: the generic `invalid params`
//! message the twin answers, the per-field detail logged at debug, and a
//! `data.reason` only where a field declares one.
//!
//! [`InputShape`] is the per-action descriptor the dispatcher enforces the
//! void rule ([`require_void_params`]) from.
//!
//! [`is_valid_uuid`] is the wire grammar every UUID the spine decodes from a
//! request passes; the `deserialize_*wire_uuid*` adapters put it in front of
//! serde's permissive `Uuid` parser for typed inputs.
//!
//! [`deserialize_wire_int`], [`deserialize_optional_wire_int`] and
//! [`deserialize_nullish_wire_int`] read a typed
//! integer field as the twin's `pipe(number, integer)` does — any integral
//! spelling (`5.0`, `1e1`, `-0`) within the safe-integer range — where
//! serde's own integer impls refuse every float token.
//! Floats parse correctly rounded (the workspace enables `serde_json`'s
//! `float_roundtrip`), so a fraction `JSON.parse` keeps is never rounded onto
//! an integer here.
//!
//! The typed-input half of the same contract — `#[derive(Deserialize)]`
//! inputs decoded with a `null` walk in front — is the sibling
//! [`crate::strict_params`] module. The two split by decode style, not by
//! rule: a hand-decoded handler reaches for this module, a serde-typed one
//! for that one plus the wire-UUID adapters here.
//!
//! Domain-specific field rules (role names, text bounds, paging) stay with
//! the crates that own those fields.

use serde::Deserialize;
use serde_json::Value;

use crate::jsonrpc_error::{JsonrpcError, internal_error_with_source, invalid_input_params};

/// Serialize an action-spec result into a JSON-RPC `Value`, mapping a
/// serialization failure to `internal_error` with the source attached.
///
/// Every action-spec handler ends by encoding its typed result struct
/// the same way; this collapses that tail (`serde_json::to_value(..)
/// .map_err(..)`) so the error message + source wrapping stay identical
/// across handlers.
///
/// # Errors
///
/// `internal_error` (with the `serde_json::Error` as source) when the
/// value can't be serialized.
pub fn serialize_result<T: serde::Serialize>(value: T) -> Result<Value, JsonrpcError> {
    serde_json::to_value(value).map_err(|e| internal_error_with_source("serialization failed", &e))
}

/// Refuse any `params` key the method's TS twin does not declare.
///
/// The hand-decoded action specs read their fields with `params.get(..)`
/// chains, which ignore a key nothing looks for — where the twin's
/// `object` answers `-32602 Unrecognized key`. Calling this at the top
/// of a handler, against a `const` listing exactly the twin's input keys, is
/// what closes that without giving up the per-field `data.reason` codes a
/// serde struct could not carry.
///
/// `acting` belongs in `allowed` **iff** the twin's input declares
/// `acting: ActingActor` — the biconditional `fuz_app`'s registry enforces
/// (declare it iff the spec carries an actor axis). A spec without the axis
/// must refuse a well-formed selector as an unrecognized key, which is what
/// leaving it out of the list does.
///
/// A non-object `params` is a no-op here: an absent `params` reaches a handler
/// as [`Value::Null`], and every other non-object shape is refused before any
/// handler runs — at the envelope on POST and WS ([`crate::classify`]), and
/// by `fuz_actions::perform_action`'s params-shape check on `GET /rpc`, whose
/// query string carries any JSON value. A caller outside the dispatcher passes
/// an object or `null`.
///
/// # Errors
///
/// [`invalid_input_params`] (-32602) on the first unrecognized key (map order,
/// not wire order): the wire carries the generic `invalid params`, and the
/// debug log names the key.
pub fn reject_unknown_keys(params: &Value, allowed: &[&str]) -> Result<(), JsonrpcError> {
    let Some(object) = params.as_object() else {
        return Ok(());
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid_input_params(
                &format!("unrecognized key: \"{key}\""),
                None,
            ));
        }
    }
    Ok(())
}

/// Refuse an explicit JSON `null` on any of the named keys.
///
/// A TS `optional` field admits an absent key and nothing else, while a
/// nullable optional one reads `null` as absent. The hand-decoders collapse
/// both onto `None`, so a `null` on an `optional` field answers 200 on this
/// spine and `-32602` on the twin. Name those keys here — the nullable ones
/// are the majority and stay off the list.
///
/// The polarity is the inverse of [`crate::parse_strict_params`]'s walk,
/// and deliberately so: that one guards serde-typed inputs, where every
/// optional field is null-coercible and the exemptions are few, so it denies
/// by default. Here the twin's modifier is `optional(nullable(...))` on nearly every
/// hand-decoded field, so naming the few `optional`-only ones keeps each call
/// site as short as the divergence is.
///
/// `acting` never needs listing: the dispatcher's own selector gate refuses a
/// non-string `acting` on every spec, ahead of any handler.
///
/// # Errors
///
/// [`invalid_input_params`] (-32602) on the first listed key whose value is
/// `null`: the wire carries the generic `invalid params`, and the debug log
/// names the key.
pub fn reject_null_keys(params: &Value, non_nullable: &[&str]) -> Result<(), JsonrpcError> {
    for key in non_nullable {
        if params.get(*key).is_some_and(Value::is_null) {
            return Err(invalid_input_params(
                &format!("{key} must not be null"),
                None,
            ));
        }
    }
    Ok(())
}

/// Parse an optional string field. [`Value::Null`] and a missing key both
/// decode to `None`; a present non-string surfaces `invalid_params`.
///
/// The string sibling of [`parse_optional_i64_param`], for the `optional(nullable(...))`
/// free-text and filter fields. Reading these with
/// `params.get(name).and_then(Value::as_str)` instead would read a
/// present-but-wrong-typed value as absent, so `{"message": 42}` would be
/// stored as "no message" here and `-32602` on the twin.
///
/// Returns a borrowed `&str` tied to `params`'s lifetime — callers that need
/// an owned value `.map(str::to_owned)`.
///
/// # Errors
///
/// `invalid_params` on a present non-null non-string.
pub fn parse_optional_str_param<'a>(
    params: &'a Value,
    name: &'static str,
) -> Result<Option<&'a str>, JsonrpcError> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_str().map(Some).ok_or_else(|| {
            invalid_input_params(&format!("'{name}' must be a string or null"), None)
        }),
    }
}

/// Parse an optional boolean field. [`Value::Null`] and a missing key both
/// decode to `None`; a present non-boolean surfaces `invalid_params`.
///
/// The boolean sibling of [`parse_optional_str_param`], with the same reason
/// for existing: `and_then(Value::as_bool)` reads `{"include_deleted": "yes"}`
/// as absent where the twin's `boolean` refuses it.
///
/// # Errors
///
/// `invalid_params` on a present non-null non-boolean.
pub fn parse_optional_bool_param(
    params: &Value,
    name: &'static str,
) -> Result<Option<bool>, JsonrpcError> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_bool().map(Some).ok_or_else(|| {
            invalid_input_params(&format!("'{name}' must be a boolean or null"), None)
        }),
    }
}

/// Parse a required string field from JSON-RPC params.
///
/// Only presence and type are checked — emptiness, length, and grammar are
/// the caller's, since each field's twin schema spells its own.
///
/// # Errors
///
/// [`invalid_input_params`] on missing / non-string: the generic
/// `invalid params` on the wire, the field named in the debug log.
pub fn parse_str_param<'a>(params: &'a Value, name: &'static str) -> Result<&'a str, JsonrpcError> {
    params.get(name).and_then(Value::as_str).ok_or_else(|| {
        invalid_input_params(&format!("missing or invalid '{name}' parameter"), None)
    })
}

/// Whether `s` is a valid wire UUID — the canonical grammar for every UUID
/// the spine decodes from a request (query values, JSON-RPC params).
///
/// Twin of the TS `Uuid` schema in `fuz_app` — the `@fuzdev/fuz_schema`
/// `Uuid` in `primitive_schemas.ts` (`pipe(string, uuid, to_lower_case)`):
/// hyphenated 8-4-4-4-12 hex (case-insensitive) with the
/// RFC 9562 version nibble in `1..=8` and the variant nibble in `[89abAB]`,
/// plus the two special values — nil (all zeros) and max (all `f`s, in any
/// case, as RFC 9562 §4 reads a UUID case-insensitively).
/// Non-hyphenated, braced, and URN forms are rejected — Postgres and Rust's
/// `Uuid::parse_str` accept all three, the TS spine never did.
///
/// What a caller keeps is the parsed `uuid::Uuid`, never the string, so an id
/// sent in either case compares and renders as its lowercase form, the TS
/// twin's output.
///
/// Every id the spine mints is a Postgres `gen_random_uuid()` v4, so the
/// strictness rejects nothing a legitimate flow produces; it exists so both
/// spines refuse the same synthetic input with the same error.
///
/// `Uuid::parse_str` is **not** a substitute — it is the permissive parser
/// this guards. Call this first at every ingress, then parse.
///
/// A consumer outside this workspace carries the same grammar in a spine-free
/// crate that cannot depend on this one. The two are **behaviorally**
/// identical, not textually, and their test tables carry the same grammar
/// rows plus each side's own domain negatives. Change the grammar in one,
/// change it in both.
///
/// Hand-rolled instead of regex: `regex` isn't a workspace dependency, and a
/// byte scan is faster than a DFA compile.
#[must_use]
pub fn is_valid_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    if !bytes.iter().enumerate().all(|(i, &c)| match i {
        8 | 13 | 18 | 23 => c == b'-',
        _ => c.is_ascii_hexdigit(),
    }) {
        return false;
    }
    if matches!(bytes[14], b'1'..=b'8')
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
    {
        return true;
    }
    // Shape is already pinned (36 chars, dashes at 8/13/18/23, hex
    // elsewhere), so "every byte is `0` or `-`" is exactly the nil UUID and
    // "every byte is `f`, `F` or `-`" exactly the max UUID, in any case.
    bytes.iter().all(|&b| b == b'0' || b == b'-')
        || bytes.iter().all(|&b| matches!(b, b'f' | b'F' | b'-'))
}

/// Parse a required UUID field from JSON-RPC params.
///
/// Refuses a field that is missing, non-string, or not a UUID. Used by every
/// action-spec handler decoding a UUID parameter.
///
/// "UUID" is the [`is_valid_uuid`] grammar — the twin of the TS
/// `Uuid` these params are declared as — not Rust's permissive
/// `Uuid::parse_str`, which also admits hyphenless, braced and URN forms and
/// any version/variant nibbles.
///
/// # Errors
///
/// [`invalid_input_params`] on missing / non-string / non-UUID: the generic
/// `invalid params` on the wire, the field and its fault in the debug log.
pub fn parse_uuid_param(params: &Value, name: &'static str) -> Result<uuid::Uuid, JsonrpcError> {
    let raw = parse_str_param(params, name)?;
    parse_wire_uuid(raw)
        .ok_or_else(|| invalid_input_params(&format!("'{name}' is not a valid uuid"), None))
}

/// Parse one wire UUID string under the strict [`is_valid_uuid`]
/// grammar. `None` when the grammar refuses it.
///
/// The single choke point the param helpers share, so no decoder can run the
/// permissive parser without the grammar in front of it.
fn parse_wire_uuid(raw: &str) -> Option<uuid::Uuid> {
    if !is_valid_uuid(raw) {
        return None;
    }
    uuid::Uuid::parse_str(raw).ok()
}

/// Parse an optional UUID field. `serde_json::Value::Null` and a
/// missing key both decode to `None`; a non-string non-null surfaces
/// `invalid_params`.
///
/// Same [`is_valid_uuid`] grammar as [`parse_uuid_param`].
///
/// # Errors
///
/// `invalid_params` on non-null + non-string, or on a string that
/// doesn't parse as a UUID.
pub fn parse_optional_uuid_param(
    params: &Value,
    name: &'static str,
) -> Result<Option<uuid::Uuid>, JsonrpcError> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .ok_or_else(|| {
                invalid_input_params(&format!("'{name}' must be a uuid string or null"), None)
            })
            .and_then(|s| {
                parse_wire_uuid(s).ok_or_else(|| {
                    invalid_input_params(&format!("'{name}' is not a valid uuid"), None)
                })
            })
            .map(Some),
    }
}

/// Deserialize a **required** wire UUID field under the strict
/// [`is_valid_uuid`] grammar.
///
/// Wire inputs that decode through `#[derive(Deserialize)]` reach
/// `uuid::Uuid`'s own `Deserialize`, which runs the permissive
/// `Uuid::parse_str` — it admits the hyphenless, braced and `urn:uuid:`
/// spellings and any version/variant nibbles, all of which the TS twin's
/// `Uuid` refuses. Annotating the field
/// `#[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]` puts the
/// grammar in front of the parser, so an off-grammar id is `invalid_params`
/// (-32602) on both spines instead of reaching a lookup on one of them.
///
/// # Errors
///
/// The deserializer's error when the value is not a string, or a custom
/// error naming the value when it is a string outside the grammar.
pub fn deserialize_wire_uuid<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<uuid::Uuid, D::Error> {
    let raw = String::deserialize(deserializer)?;
    parse_wire_uuid(&raw).ok_or_else(|| serde::de::Error::custom(wire_uuid_message(&raw)))
}

/// Deserialize an **optional** wire UUID field under the strict
/// [`is_valid_uuid`] grammar, refusing an explicit `null`.
///
/// Pair it with `#[serde(default)]` — `#[serde(default, deserialize_with =
/// "fuz_http::deserialize_optional_wire_uuid")]` — so an **absent** key is
/// `None` without calling this function, while a **present** key always does.
/// A **container-level** `#[serde(default)]` on a struct deriving `Default`
/// satisfies the same requirement and is the right spelling when every field
/// is optional (the `acting`-only admin inputs are the case). A present `null`
/// therefore fails as "expected a string", which is what the TS twin's
/// `optional(...)` answers: it admits an absent key and nothing else, where
/// serde's bare `Option<Uuid>` would quietly read `null` as "no value".
///
/// # Errors
///
/// The deserializer's error when the value is `null` or a non-string, or a
/// custom error naming the value when it is a string outside the grammar.
pub fn deserialize_optional_wire_uuid<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<uuid::Uuid>, D::Error> {
    deserialize_wire_uuid(deserializer).map(Some)
}

/// Deserialize a **nullish** wire UUID field under the strict
/// [`is_valid_uuid`] grammar, mapping an explicit `null` to `None`.
///
/// The twin of the TS `optional(nullable(Uuid))` — the handful of input fields whose
/// schema admits `null` as a spelling of "absent" (`cell_create.parent_id`,
/// the grant principal's `scope_id`). Pair it with `#[serde(default)]` the
/// same way [`deserialize_optional_wire_uuid`] is paired; the difference is
/// only which of the two TS modifiers the field carries, so read the schema
/// before choosing. Prefer the `optional` form — a field that admits
/// `null` has two spellings for one meaning.
///
/// # Errors
///
/// The deserializer's error when the value is neither `null` nor a string,
/// or a custom error naming the value when it is a string outside the
/// grammar.
pub fn deserialize_nullish_wire_uuid<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<uuid::Uuid>, D::Error> {
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    parse_wire_uuid(&raw)
        .ok_or_else(|| serde::de::Error::custom(wire_uuid_message(&raw)))
        .map(Some)
}

/// Deserialize a **required list** of wire UUIDs under the strict
/// [`is_valid_uuid`] grammar, refusing any non-string element.
///
/// The list twin of [`deserialize_wire_uuid`], for the id lists the TS twin
/// declares as `array(Uuid)`. A bare `Vec<Uuid>` field decodes each element
/// through `uuid::Uuid`'s permissive `Deserialize`; annotating it
/// `#[serde(deserialize_with = "fuz_http::deserialize_wire_uuid_vec")]` puts
/// the grammar in front of every element. Without `#[serde(default)]` an
/// absent key stays serde's missing-field error, and an empty list is a list.
///
/// # Errors
///
/// The deserializer's error when the value is `null`, a non-sequence, or
/// carries a non-string element, or a custom error naming the first element
/// outside the grammar.
pub fn deserialize_wire_uuid_vec<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<uuid::Uuid>, D::Error> {
    let raws = Vec::<String>::deserialize(deserializer)?;
    raws.into_iter()
        .map(|raw| {
            parse_wire_uuid(&raw).ok_or_else(|| serde::de::Error::custom(wire_uuid_message(&raw)))
        })
        .collect()
}

/// Deserialize an **optional list** of wire UUIDs under the strict
/// [`is_valid_uuid`] grammar, refusing an explicit `null` and any
/// non-string element.
///
/// The list twin of [`deserialize_optional_wire_uuid`], for the
/// id-list filters (`cell_list.ids`) the TS twin declares as
/// `optional(array(Uuid))`. Same pairing with `#[serde(default)]`, and the
/// same `null` refusal — here reported as "expected a sequence".
///
/// # Errors
///
/// The deserializer's error when the value is `null`, a non-sequence, or
/// carries a non-string element, or a custom error naming the first element
/// outside the grammar.
pub fn deserialize_optional_wire_uuid_vec<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<uuid::Uuid>>, D::Error> {
    deserialize_wire_uuid_vec(deserializer).map(Some)
}

/// Deserialize a **required** wire integer field the way the TS twin's
/// `pipe(number, integer)` reads it.
///
/// The twin admits any finite JSON number with no fractional part whose
/// magnitude is at most `Number.MAX_SAFE_INTEGER` ([`crate::SAFE_INTEGER_MAX`]),
/// whatever its spelling: `5`, `5.0`, `1e1` and `-0` are all integers there.
/// serde's own integer impls refuse every float token — `-0` included, which
/// `serde_json` parses as a float — and admit integer literals past 2^53, so a
/// bare `i64` / `u64` / `u32` field is stricter than the twin on one side and
/// looser on the other. Annotating the field
/// `#[serde(deserialize_with = "fuz_http::deserialize_wire_int")]` reads it as
/// the twin does, then converts into the field's type; `-0` reads as `0`.
///
/// A refusal is a serde error, so a typed input decoded through
/// [`crate::parse_strict_params`] answers the generic `invalid params`, as the
/// twin's schema does for a field declaring no `invalid_reason`. Range rules
/// past the type's own (a `limit`'s `1..=max`) stay with the field's owner.
///
/// # Errors
///
/// The deserializer's error when the value is not a number (a string, a
/// boolean, `null`), and an invalid-value error when it has a fractional part,
/// is not finite, exceeds the safe-integer range, or does not fit the field's
/// type (a negative into `u64`, a value past `u32::MAX`).
pub fn deserialize_wire_int<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: TryFrom<i64>,
{
    let n = deserializer.deserialize_any(WireIntVisitor)?;
    T::try_from(n).map_err(|_| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Signed(n),
            &"an integer in the field's range",
        )
    })
}

/// Deserialize an **optional** wire integer field the way the TS twin's
/// `optional(pipe(number, integer))` reads it, refusing an explicit `null`.
///
/// Pair it with `#[serde(default)]` (on the field, or on a container deriving
/// `Default`) so an absent key is `None` without calling this function, the
/// same contract as [`deserialize_optional_wire_uuid`]: a present `null` then
/// fails as "expected an integer", which is what `optional(...)` answers.
///
/// # Errors
///
/// [`deserialize_wire_int`]'s, `null` included.
pub fn deserialize_optional_wire_int<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: TryFrom<i64>,
{
    deserialize_wire_int(deserializer).map(Some)
}

/// Deserialize a **nullish** wire integer field the way the TS twin's
/// `nullable(pipe(number, integer))` reads it, mapping an explicit `null` to
/// `None`.
///
/// Without `#[serde(default)]` the key stays required — `null` or an integer
/// — which is `nullable(...)`; with it an absent key reads as `None` too, which
/// is `optional(nullable(...))`. Read the schema before choosing, as for
/// [`deserialize_nullish_wire_uuid`].
///
/// # Errors
///
/// [`deserialize_wire_int`]'s for any value but `null`.
pub fn deserialize_nullish_wire_int<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: TryFrom<i64>,
{
    let Some(n) = deserializer.deserialize_option(NullishWireIntVisitor)? else {
        return Ok(None);
    };
    T::try_from(n).map(Some).map_err(|_| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Signed(n),
            &"an integer in the field's range",
        )
    })
}

/// The `null`-admitting wrapper of [`WireIntVisitor`].
struct NullishWireIntVisitor;

impl<'de> serde::de::Visitor<'de> for NullishWireIntVisitor {
    type Value = Option<i64>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an integer or null")
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Option<i64>, E> {
        Ok(None)
    }

    fn visit_some<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Option<i64>, D::Error> {
        deserializer.deserialize_any(WireIntVisitor).map(Some)
    }
}

/// The visitor behind [`deserialize_wire_int`]: a JSON number with an
/// integral value in the safe-integer range, as an `i64`.
struct WireIntVisitor;

/// The bound every wire integer holds, `Number.MAX_SAFE_INTEGER`, unsigned.
#[allow(clippy::cast_sign_loss)]
const SAFE_INTEGER_MAX_U64: u64 = crate::SAFE_INTEGER_MAX as u64;

impl serde::de::Visitor<'_> for WireIntVisitor {
    type Value = i64;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an integer")
    }

    fn visit_i64<E: serde::de::Error>(self, n: i64) -> Result<i64, E> {
        if n.unsigned_abs() <= SAFE_INTEGER_MAX_U64 {
            Ok(n)
        } else {
            Err(E::invalid_value(
                serde::de::Unexpected::Signed(n),
                &"a safe integer",
            ))
        }
    }

    fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<i64, E> {
        if n <= SAFE_INTEGER_MAX_U64 {
            // in range by the check above
            #[allow(clippy::cast_possible_wrap)]
            Ok(n as i64)
        } else {
            Err(E::invalid_value(
                serde::de::Unexpected::Unsigned(n),
                &"a safe integer",
            ))
        }
    }

    fn visit_f64<E: serde::de::Error>(self, f: f64) -> Result<i64, E> {
        // `SAFE_INTEGER_MAX` is exactly representable, so the bound is exact
        #[allow(clippy::cast_precision_loss)]
        let max = crate::SAFE_INTEGER_MAX as f64;
        if f.is_finite() && f.fract() == 0.0 && f.abs() <= max {
            // integral and within the safe range, so the cast is exact
            #[allow(clippy::cast_possible_truncation)]
            Ok(f as i64)
        } else {
            Err(E::invalid_value(
                serde::de::Unexpected::Float(f),
                &"a safe integer",
            ))
        }
    }
}

/// Message body the wire-UUID deserializers report for a string the grammar
/// refuses. Serde renders it under the offending field's name, so the text
/// carries only the value.
fn wire_uuid_message(raw: &str) -> String {
    format!("`{raw}` is not a valid uuid")
}

/// The shape an action's input takes, as the dispatcher enforces it — the
/// Rust spine's twin of whether a TS action spec's `input` is `void`.
///
/// Every `ActionSpec` declares one (there is no default: a parameterless
/// method that forgot to say so would answer any params at all), and
/// `_testing_action_manifest` reports it as `"input": "void" | "object"`, the
/// field the cross-backend manifest parity gate diffs against the TS spine's
/// `is_void_schema(spec.input)`.
///
/// The descriptor is deliberately coarse — it says *whether* a method takes
/// params, not *which*. An [`InputShape::Object`] handler still validates its
/// own fields (`crate::parse_strict_params` for a typed input,
/// [`reject_unknown_keys`] and the field helpers for a hand-decoded one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputShape {
    /// A parameterless method — the twin of a TS `void` input. The
    /// dispatcher refuses every params shape but the no-arg call
    /// ([`require_void_params`]) before the handler runs.
    Void,
    /// A by-name object input — any other TS input schema. The dispatcher
    /// holds `params` to absent-or-object; the fields are the handler's.
    ///
    /// An `object({})` input is `Object` too, though it admits the same
    /// calls a `void` one does: the descriptor mirrors the twin's schema,
    /// not the set it accepts. Its handler refuses keys with
    /// `reject_unknown_keys(&params, &[])`.
    Object,
}

impl InputShape {
    /// The manifest's wire spelling: `"void"` or `"object"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Object => "object",
        }
    }

    /// Hold `params` to this shape. A no-op for [`InputShape::Object`], whose
    /// absent-or-object rule the dispatcher checks on its own, ahead of this.
    ///
    /// # Errors
    ///
    /// [`require_void_params`]'s refusal for an [`InputShape::Void`] method
    /// handed anything but the no-arg call.
    pub fn check(self, params: &Value) -> Result<(), JsonrpcError> {
        match self {
            Self::Void => require_void_params(params),
            Self::Object => Ok(()),
        }
    }
}

/// Refuse any declared parameter on a method that takes none — the void rule
/// [`InputShape::Void`] holds a method to, and the twin of a TS `void`
/// input.
///
/// Two shapes are the no-arg call:
///
/// - `Value::Null` — how an absent `params` arrives on the classified
///   transports (see [`crate::parse_strict_params`]), and how the GET path hands
///   an absent `?params=`;
/// - `{}` — JSON-RPC 2.0 lets `params` be omitted, and an empty by-name
///   structure carries no parameters. Published `fuz_app` WebSocket clients
///   send `{}` for a parameterless call, so refusing it breaks every void
///   method over WS; the TS dispatcher reads it as absent for a `void`
///   input too.
///
/// Everything else is `invalid_params`: a non-empty object (a declared key the
/// method does not take), a scalar, and any array — `[]` included. The spine is
/// by-name only (`parse_params` refuses positional params outright), so an
/// empty positional list is a malformed call rather than a spelling of "none".
///
/// The dispatcher calls this through [`InputShape::check`] for every void
/// spec, so a handler never needs to.
///
/// # Errors
///
/// [`invalid_input_params`] (-32602) when `params` is anything but `null` or `{}`.
pub fn require_void_params(params: &Value) -> Result<(), JsonrpcError> {
    match params {
        Value::Null => Ok(()),
        Value::Object(map) if map.is_empty() => Ok(()),
        _ => Err(invalid_input_params("this method takes no params", None)),
    }
}

/// The `data.reason` the dispatcher's [`json_has_own_proto_key`] refusal
/// carries — `ERROR_PARAMS_PROTO_KEY` in `fuz_app`'s `http/error_schemas.ts`.
pub const ERROR_PARAMS_PROTO_KEY: &str = "params_proto_key";

/// Whether any object in `value` has an own `__proto__` key, at any depth —
/// what the dispatcher refuses in a request's `params`
/// ([`ERROR_PARAMS_PROTO_KEY`]).
///
/// The key is harmless to serde, but a JS client that copies the stored JSON
/// back with plain assignment (`target[key] = value`, any shallow copy or
/// merge loop) hits the prototype setter, so stored JSON carrying one is a
/// prototype-pollution sink for whoever reads it. `constructor` and
/// `prototype` keys are inert on a plain object and are not checked.
///
/// Walks with an explicit stack, as the TS twin (`json_has_own_proto_key` in
/// `http/schema_helpers.ts`) must: `JSON.parse` nests deeper than its call
/// stack. `serde_json` caps nesting on parse, so the stack here stays shallow;
/// the walk is linear in the value's nodes either way.
#[must_use]
pub fn json_has_own_proto_key(value: &Value) -> bool {
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            Value::Object(map) => {
                if map.contains_key("__proto__") {
                    return true;
                }
                stack.extend(map.values());
            }
            Value::Array(items) => stack.extend(items),
            _ => {}
        }
    }
    false
}

/// Read a JSON number with an integral value as an `i64`, as the TS twin's
/// `pipe(number, integer)` does.
///
/// `5`, `5.0`, `1e1` and `-0` are all integers there, so `Value::as_i64`
/// alone (integer literals only) would be stricter than the twin.
///
/// Returns `None` for a non-number, a fraction, a non-finite value, or a float
/// of magnitude `9.2e18` or more (a margin under `i64::MAX`, past which the
/// cast would saturate). It does not cap at `Number.MAX_SAFE_INTEGER` — the
/// twin's `int()` refuses past it, so a caller holding that line checks
/// against [`crate::SAFE_INTEGER_MAX`] after.
#[must_use]
pub fn as_integral_i64(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        value.as_f64().and_then(|f| {
            #[allow(clippy::cast_possible_truncation)]
            if f.is_finite() && f.fract() == 0.0 && f.abs() < 9.2e18 {
                Some(f as i64)
            } else {
                None
            }
        })
    })
}

/// Parse an optional integer field. `serde_json::Value::Null` and a
/// missing key both decode to `None`; any number with an integral value is
/// admitted ([`as_integral_i64`]); anything else surfaces `invalid_params`.
///
/// The TS nullable optional fields (`limit` / `offset` / `since_seq`)
/// collapse `undefined | null` to absent on the wire, matching this
/// shape.
///
/// # Errors
///
/// `invalid_params` on non-null + non-integer.
pub fn parse_optional_i64_param(
    params: &Value,
    name: &'static str,
) -> Result<Option<i64>, JsonrpcError> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => as_integral_i64(v).map(Some).ok_or_else(|| {
            invalid_input_params(&format!("'{name}' must be an integer or null"), None)
        }),
    }
}

/// Parse an optional closed-enum string field.
///
/// `serde_json::Value::Null` and a missing key both decode to `None`. Every
/// other refusal — a non-string, or a string not in `allowed` — surfaces
/// `invalid_params` with `data.reason = reason`: the reason is the field's
/// declared one (its twin's `invalid_reason`), owed on every refusal of the
/// field.
///
/// Returns a borrowed `&str` tied to `params`'s lifetime — callers that
/// need an owned value `.map(str::to_owned)`.
///
/// # Errors
///
/// `invalid_params` with `reason` on non-null + non-string, or on a string
/// not in `allowed`.
pub fn parse_optional_enum_param<'a>(
    params: &'a Value,
    name: &'static str,
    allowed: &[&str],
    reason: &'static str,
) -> Result<Option<&'a str>, JsonrpcError> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .ok_or_else(|| {
                invalid_input_params(&format!("'{name}' must be a string or null"), Some(reason))
            })
            .and_then(|s| {
                if allowed.contains(&s) {
                    Ok(Some(s))
                } else {
                    let allowed_list = allowed.join("/");
                    Err(invalid_input_params(
                        &format!("'{name}' must be one of: {allowed_list}"),
                        Some(reason),
                    ))
                }
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InputShape, as_integral_i64, deserialize_nullish_wire_uuid, deserialize_optional_wire_uuid,
        deserialize_optional_wire_uuid_vec, deserialize_wire_uuid, deserialize_wire_uuid_vec,
        is_valid_uuid, json_has_own_proto_key, parse_optional_bool_param,
        parse_optional_enum_param, parse_optional_i64_param, parse_optional_str_param,
        parse_optional_uuid_param, parse_uuid_param, reject_null_keys, reject_unknown_keys,
        require_void_params,
    };
    use crate::{JsonrpcError, JsonrpcErrorCode};
    use serde_json::{Value, json};

    /// One field per integer type the adapters serve.
    #[derive(Debug, PartialEq, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireInts {
        #[serde(default, deserialize_with = "super::deserialize_optional_wire_int")]
        a: Option<i64>,
        #[serde(default, deserialize_with = "super::deserialize_optional_wire_int")]
        b: Option<u32>,
        #[serde(default, deserialize_with = "super::deserialize_optional_wire_int")]
        c: Option<u64>,
    }

    #[derive(Debug, serde::Deserialize)]
    struct RequiredWireInt {
        #[serde(deserialize_with = "super::deserialize_wire_int")]
        n: i64,
    }

    /// Decode `{"<field>": <literal>}` from text (not `json!`, which would
    /// build an integer for `5.0`) and through a `Value`, which must agree.
    fn decode_ints(field: &str, literal: &str) -> Result<WireInts, String> {
        let text = format!(r#"{{"{field}":{literal}}}"#);
        let from_str = serde_json::from_str::<WireInts>(&text).map_err(|e| e.to_string());
        let value: Value = serde_json::from_str(&text).expect("valid json");
        let from_value = serde_json::from_value::<WireInts>(value).map_err(|e| e.to_string());
        assert_eq!(from_str.is_ok(), from_value.is_ok(), "{text}");
        from_str
    }

    #[test]
    fn deserialize_wire_int_admits_every_integral_spelling() {
        for (literal, expected) in [
            ("5", 5),
            ("5.0", 5),
            ("1e1", 10),
            ("-0", 0),
            ("-0.0", 0),
            ("4.9999999999999999", 5),
            ("-1", -1),
            ("9007199254740991", 9_007_199_254_740_991),
            ("-9007199254740991", -9_007_199_254_740_991),
            // correctly rounded, as `JSON.parse` is (`float_roundtrip`)
            ("9007199254740991.0", 9_007_199_254_740_991),
            ("-9007199254740991.0", -9_007_199_254_740_991),
        ] {
            let decoded = decode_ints("a", literal).unwrap_or_else(|e| panic!("{literal}: {e}"));
            assert_eq!(decoded.a, Some(expected), "{literal}");
        }
        assert_eq!(decode_ints("b", "7.0").unwrap().b, Some(7));
        assert_eq!(decode_ints("c", "-0").unwrap().c, Some(0));
        assert_eq!(decode_ints("b", "4294967295").unwrap().b, Some(u32::MAX));
    }

    #[test]
    fn deserialize_wire_int_refuses_what_the_twin_refuses() {
        for literal in [
            "5.5",
            "1.0000000000000002",
            "-0.5",
            r#""5""#,
            "true",
            "null",
            "[]",
            "{}",
            "9007199254740992",
            "-9007199254740992",
            "9007199254740992.0",
            // JS-canonical fractions the default float parse rounds onto an
            // integer; `float_roundtrip` keeps them fractions
            "0.9999999999999999",
            "99.99999999999999",
            "4503599627370495.5",
            "1e20",
            "-1e20",
        ] {
            assert!(decode_ints("a", literal).is_err(), "{literal}");
        }
        // the field's own range
        for (field, literal) in [("b", "-1"), ("b", "-1.0"), ("b", "4294967296"), ("c", "-1")] {
            assert!(decode_ints(field, literal).is_err(), "{field}: {literal}");
        }
    }

    #[test]
    fn deserialize_wire_int_absent_and_required() {
        assert_eq!(
            serde_json::from_str::<WireInts>("{}").unwrap(),
            WireInts {
                a: None,
                b: None,
                c: None
            }
        );
        assert_eq!(
            serde_json::from_str::<RequiredWireInt>(r#"{"n":1e1}"#)
                .unwrap()
                .n,
            10
        );
        assert!(serde_json::from_str::<RequiredWireInt>("{}").is_err());
        assert!(serde_json::from_str::<RequiredWireInt>(r#"{"n":null}"#).is_err());
        assert!(serde_json::from_str::<RequiredWireInt>(r#"{"n":2.5}"#).is_err());
    }

    #[test]
    fn deserialize_nullish_wire_int_reads_null_as_none() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Nullable {
            #[serde(deserialize_with = "super::deserialize_nullish_wire_int")]
            n: Option<i32>,
        }
        let read = |text: &str| serde_json::from_str::<Nullable>(text).map(|v| v.n);
        assert_eq!(read(r#"{"n":null}"#).unwrap(), None);
        assert_eq!(read(r#"{"n":12.0}"#).unwrap(), Some(12));
        assert_eq!(read(r#"{"n":-0}"#).unwrap(), Some(0));
        // `nullable(...)` without a default: the key is required
        assert!(read("{}").is_err());
        for text in [r#"{"n":1.5}"#, r#"{"n":"1"}"#, r#"{"n":2147483648}"#] {
            assert!(read(text).is_err(), "{text}");
        }
        let value: Value = serde_json::from_str(r#"{"n":12.0}"#).unwrap();
        assert_eq!(
            serde_json::from_value::<Nullable>(value).unwrap().n,
            Some(12)
        );
        let value: Value = serde_json::from_str(r#"{"n":null}"#).unwrap();
        assert_eq!(serde_json::from_value::<Nullable>(value).unwrap().n, None);
    }

    fn has_proto(text: &str) -> bool {
        json_has_own_proto_key(&serde_json::from_str::<Value>(text).expect("valid json"))
    }

    #[test]
    fn json_has_own_proto_key_finds_the_key_at_any_depth() {
        for text in [
            r#"{"__proto__":{"x":1}}"#,
            r#"{"__proto__":null}"#,
            r#"{"a":1,"b":{"c":{"__proto__":{}}}}"#,
            r#"{"a":{"b":[1,{"__proto__":{}}]}}"#,
            r#"[{"__proto__":1}]"#,
            // the escaped spelling decodes to the key
            r#"{"\u005f_proto__":1}"#,
        ] {
            assert!(has_proto(text), "{text}");
        }
    }

    #[test]
    fn json_has_own_proto_key_admits_constructor_values_and_near_misses() {
        for text in [
            r#"{"constructor":{"prototype":{"x":1}}}"#,
            r#"{"prototype":{}}"#,
            r#"{"a":"__proto__","b":["__proto__"]}"#,
            r#"{"__proto":1,"_proto__":1,"__PROTO__":1}"#,
            "{}",
            "[]",
            "null",
            "1",
            r#""__proto__""#,
        ] {
            assert!(!has_proto(text), "{text}");
        }
    }

    #[test]
    fn json_has_own_proto_key_walks_deep_values_without_recursing() {
        // past serde_json's parse-time depth cap, built by hand
        let mut deep = json!({"__proto__": 1});
        for _ in 0..100_000 {
            deep = Value::Array(vec![deep]);
        }
        // `Value`'s own drop recurses, so the tower is never dropped — not
        // even when the assertion below fails and the test unwinds
        let deep = std::mem::ManuallyDrop::new(deep);
        assert!(json_has_own_proto_key(&deep));
    }

    /// One field per deserializer, so a decode failure names which shape
    /// refused the input.
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireUuids {
        #[serde(deserialize_with = "deserialize_wire_uuid")]
        required: uuid::Uuid,
        #[serde(default, deserialize_with = "deserialize_optional_wire_uuid")]
        optional: Option<uuid::Uuid>,
        #[serde(default, deserialize_with = "deserialize_nullish_wire_uuid")]
        nullish: Option<uuid::Uuid>,
        #[serde(default, deserialize_with = "deserialize_optional_wire_uuid_vec")]
        list: Option<Vec<uuid::Uuid>>,
    }

    const VALID: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";

    fn parse(value: Value) -> Result<WireUuids, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn unknown_keys_are_refused_and_declared_ones_pass() {
        const ALLOWED: &[&str] = &["limit", "acting"];
        assert!(reject_unknown_keys(&json!({}), ALLOWED).is_ok());
        assert!(reject_unknown_keys(&json!({"limit": 1, "acting": "x"}), ALLOWED).is_ok());
        // A non-object `params` — the shape an absent `params` arrives as — is
        // a no-op, since there is no key to judge.
        assert!(reject_unknown_keys(&Value::Null, ALLOWED).is_ok());

        let e = reject_unknown_keys(&json!({"nope": 1}), ALLOWED)
            .expect_err("an undeclared key must be refused");
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.message, crate::INVALID_PARAMS_MESSAGE);
    }

    #[test]
    fn an_undeclared_acting_key_is_unknown_like_any_other() {
        // The biconditional: a spec with no actor axis declares no `acting`,
        // so a well-formed selector is refused as an unrecognized key.
        const NO_ACTOR_AXIS: &[&str] = &["ids"];
        const WITH_ACTOR_AXIS: &[&str] = &["ids", "acting"];
        assert!(
            reject_unknown_keys(&json!({"ids": [], "acting": VALID}), NO_ACTOR_AXIS).is_err(),
            "a spec without the axis must refuse the selector"
        );
        assert!(
            reject_unknown_keys(&json!({"ids": [], "acting": VALID}), WITH_ACTOR_AXIS).is_ok(),
            "a spec with the axis must admit it"
        );
    }

    #[test]
    fn a_null_on_a_named_key_is_refused_and_its_neighbours_are_not() {
        const NON_NULLABLE: &[&str] = &["confirm"];
        assert!(reject_null_keys(&json!({"confirm": true}), NON_NULLABLE).is_ok());
        assert!(reject_null_keys(&json!({}), NON_NULLABLE).is_ok());
        // An unnamed key is `optional(nullable(...))` on the twin, so its `null` stands.
        assert!(reject_null_keys(&json!({"reason": Value::Null}), NON_NULLABLE).is_ok());

        let e = reject_null_keys(&json!({"confirm": Value::Null}), NON_NULLABLE)
            .expect_err("a null on a named key must be refused");
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.message, crate::INVALID_PARAMS_MESSAGE);
    }

    #[test]
    fn an_optional_string_refuses_a_present_wrong_type() {
        assert_eq!(
            parse_optional_str_param(&json!({"reason": "why"}), "reason")
                .ok()
                .flatten(),
            Some("why")
        );
        // `optional(nullable(...))` semantics: absent and `null` are both "no value".
        assert_eq!(
            parse_optional_str_param(&json!({}), "reason")
                .ok()
                .flatten(),
            None
        );
        assert_eq!(
            parse_optional_str_param(&json!({"reason": Value::Null}), "reason")
                .ok()
                .flatten(),
            None
        );
        for wrong in [json!(42), json!(true), json!([]), json!({})] {
            let params = json!({"reason": wrong});
            let e = parse_optional_str_param(&params, "reason")
                .expect_err(&format!("{params} must be refused"));
            assert_eq!(e.code, JsonrpcErrorCode::InvalidParams, "params: {params}");
        }
    }

    #[test]
    fn an_optional_bool_refuses_a_present_wrong_type() {
        assert_eq!(
            parse_optional_bool_param(&json!({"include_deleted": true}), "include_deleted").ok(),
            Some(Some(true))
        );
        assert_eq!(
            parse_optional_bool_param(&json!({}), "include_deleted").ok(),
            Some(None)
        );
        assert_eq!(
            parse_optional_bool_param(&json!({"include_deleted": Value::Null}), "include_deleted")
                .ok(),
            Some(None)
        );
        for wrong in [json!("yes"), json!(1), json!([])] {
            let params = json!({"include_deleted": wrong});
            let e = parse_optional_bool_param(&params, "include_deleted")
                .expect_err(&format!("{params} must be refused"));
            assert_eq!(e.code, JsonrpcErrorCode::InvalidParams, "params: {params}");
        }
    }

    #[test]
    fn every_shape_takes_the_valid_grammar() {
        let parsed = parse(json!({
            "required": VALID,
            "optional": VALID,
            "nullish": VALID,
            "list": [VALID],
        }))
        .unwrap_or_else(|e| panic!("valid uuids must parse: {e}"));
        assert!(parsed.optional.is_some() && parsed.nullish.is_some());
        assert_eq!(parsed.list.as_ref().map(Vec::len), Some(1));
        assert_eq!(parsed.required.to_string(), VALID);
    }

    /// The spellings `Uuid::parse_str` admits and [`crate::is_valid_uuid`]
    /// refuses — the whole point of putting the grammar in front of the
    /// parser.
    #[test]
    fn every_shape_refuses_the_permissive_spellings() {
        for raw in [
            "3f8a1c2e12344abc9def0123456789ab",
            "{3f8a1c2e-1234-4abc-9def-0123456789ab}",
            "urn:uuid:3f8a1c2e-1234-4abc-9def-0123456789ab",
            "3f8a1c2e-1234-9abc-9def-0123456789ab",
        ] {
            assert!(parse(json!({"required": raw})).is_err(), "required {raw}");
            assert!(
                parse(json!({"required": VALID, "optional": raw})).is_err(),
                "optional {raw}"
            );
            assert!(
                parse(json!({"required": VALID, "nullish": raw})).is_err(),
                "nullish {raw}"
            );
            assert!(
                parse(json!({"required": VALID, "list": [raw]})).is_err(),
                "list {raw}"
            );
        }
    }

    /// The required list on its own struct, so its key can be left out.
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RequiredList {
        #[serde(deserialize_with = "deserialize_wire_uuid_vec")]
        ids: Vec<uuid::Uuid>,
    }

    fn parse_list(value: Value) -> Result<RequiredList, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn a_required_list_decodes_its_elements_in_order() {
        const OTHER: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
        // A repeat is kept, and the order is the wire's — not sorted, not
        // reversed.
        let parsed = parse_list(json!({"ids": [OTHER, VALID, VALID]}))
            .unwrap_or_else(|e| panic!("valid uuids must parse: {e}"));
        let ids: Vec<String> = parsed.ids.iter().map(ToString::to_string).collect();
        assert_eq!(ids, [OTHER, VALID, VALID]);
        let empty = parse_list(json!({"ids": []}))
            .unwrap_or_else(|e| panic!("an empty list is a list: {e}"));
        assert!(empty.ids.is_empty());
    }

    /// One bad element refuses the whole list, wherever it sits, and a
    /// string the grammar refuses is reported in the spine's words.
    #[test]
    fn a_required_list_refuses_an_off_grammar_element() {
        for element in [
            json!("3f8a1c2e12344abc9def0123456789ab"),
            json!("{3f8a1c2e-1234-4abc-9def-0123456789ab}"),
            json!("urn:uuid:3f8a1c2e-1234-4abc-9def-0123456789ab"),
            json!("3f8a1c2e-1234-9abc-9def-0123456789ab"),
            json!("not-a-uuid"),
            json!(42),
            Value::Null,
        ] {
            for ids in [
                json!([element.clone(), VALID]),
                json!([VALID, element.clone()]),
            ] {
                assert!(parse_list(json!({"ids": ids.clone()})).is_err(), "{ids}");
            }
        }
        let error = parse_list(json!({"ids": [VALID, "not-a-uuid"]}))
            .expect_err("an off-grammar element is refused");
        assert_eq!(error.to_string(), "`not-a-uuid` is not a valid uuid");
        let error = parse(json!({"required": VALID, "list": ["not-a-uuid"]}))
            .expect_err("the optional list refuses it the same way");
        assert_eq!(error.to_string(), "`not-a-uuid` is not a valid uuid");
    }

    /// Required means present and a list: an absent key is serde's
    /// missing-field error — not an empty list — and `null` or a lone string
    /// is no list.
    #[test]
    fn a_required_list_must_be_present_and_a_list() {
        let error = parse_list(json!({})).expect_err("an absent key is refused");
        assert_eq!(error.to_string(), "missing field `ids`");
        for ids in [Value::Null, json!(VALID), json!({"0": VALID})] {
            assert!(parse_list(json!({"ids": ids.clone()})).is_err(), "{ids}");
        }
    }

    #[test]
    fn only_the_nullish_shape_admits_an_explicit_null() {
        assert!(parse(json!({"required": Value::Null})).is_err());
        assert!(parse(json!({"required": VALID, "optional": Value::Null})).is_err());
        assert!(parse(json!({"required": VALID, "list": Value::Null})).is_err());
        let parsed = parse(json!({"required": VALID, "nullish": Value::Null}))
            .unwrap_or_else(|e| panic!("a nullish field reads null as absent: {e}"));
        assert!(parsed.nullish.is_none());
    }

    /// The manifest spelling is the TS `is_void_schema` split, and only the
    /// void shape refuses anything: an object input's fields are its
    /// handler's.
    #[test]
    fn an_input_shape_names_itself_and_only_void_refuses() {
        assert_eq!(InputShape::Void.name(), "void");
        assert_eq!(InputShape::Object.name(), "object");
        for params in [Value::Null, json!({})] {
            assert!(InputShape::Void.check(&params).is_ok(), "{params}");
        }
        for params in [Value::Null, json!({}), json!({"x": 1})] {
            assert!(InputShape::Object.check(&params).is_ok(), "{params}");
        }
        let e = InputShape::Void
            .check(&json!({"x": 1}))
            .expect_err("a declared key is refused");
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(e.message, crate::INVALID_PARAMS_MESSAGE);
        assert!(e.data.is_none());
    }

    #[test]
    fn a_void_input_takes_absent_or_empty_params_and_nothing_else() {
        assert!(require_void_params(&Value::Null).is_ok());
        assert!(require_void_params(&json!({})).is_ok());
        for present in [
            json!({"nope": 1}),
            json!({"nope": Value::Null}),
            json!([]),
            json!([1]),
            json!(1),
            json!("x"),
            json!(false),
        ] {
            let e = require_void_params(&present)
                .expect_err(&format!("{present} must be refused"))
                .code;
            assert_eq!(e, JsonrpcErrorCode::InvalidParams, "params: {present}");
        }
    }

    fn reason_of(e: &JsonrpcError) -> Option<&str> {
        e.data
            .as_ref()
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str)
    }

    /// Parse wire text, so `-0` and `5.0` reach the helpers as serde decodes
    /// them off a request rather than as `json!` builds them.
    fn wire(text: &str) -> Value {
        serde_json::from_str(text).expect("valid JSON")
    }

    /// The twin's `pipe(number, integer)` reads every integral number as an
    /// integer — a float spelling, an exponent, a negative zero.
    #[test]
    fn integral_numbers_read_as_integers() {
        for (text, expected) in [
            ("5", Some(5)),
            ("5.0", Some(5)),
            ("1e1", Some(10)),
            ("-0", Some(0)),
            ("-0.0", Some(0)),
            ("-3.0", Some(-3)),
            ("9007199254740993", Some(9_007_199_254_740_993)),
            ("1.5", None),
            ("1e-1", None),
            ("1e19", None),
            ("9.25e18", None),
            ("18446744073709551615", None),
            ("\"5\"", None),
            ("true", None),
            ("null", None),
        ] {
            assert_eq!(as_integral_i64(&wire(text)), expected, "{text}");
        }
    }

    #[test]
    fn optional_integer_params_admit_integral_floats() {
        for (text, expected) in [
            (r#"{"n": 5.0}"#, Some(5)),
            (r#"{"n": 1e1}"#, Some(10)),
            (r#"{"n": -0}"#, Some(0)),
            (r#"{"n": null}"#, None),
            ("{}", None),
        ] {
            assert_eq!(
                parse_optional_i64_param(&wire(text), "n").expect("admitted"),
                expected,
                "{text}"
            );
        }
        let e = parse_optional_i64_param(&wire(r#"{"n": 1.5}"#), "n").expect_err("a fraction");
        assert_eq!(e.code, JsonrpcErrorCode::InvalidParams);
        assert!(e.data.is_none(), "an undeclared field carries no reason");
    }

    #[test]
    fn every_refusal_of_an_enum_field_carries_its_reason() {
        const OUTCOME_INVALID: &str = "outcome_invalid";
        const ALLOWED: &[&str] = &["success", "failure"];
        for params in [
            json!({"outcome": 42}),
            json!({"outcome": true}),
            json!({"outcome": {}}),
            json!({"outcome": "maybe"}),
        ] {
            let e = parse_optional_enum_param(&params, "outcome", ALLOWED, OUTCOME_INVALID)
                .expect_err("refused");
            assert_eq!(e.code, JsonrpcErrorCode::InvalidParams, "{params}");
            assert_eq!(reason_of(&e), Some(OUTCOME_INVALID), "{params}");
        }
        assert_eq!(
            parse_optional_enum_param(
                &json!({"outcome": Value::Null}),
                "outcome",
                ALLOWED,
                OUTCOME_INVALID
            )
            .expect("null is nullish-absent"),
            None
        );
    }

    /// Twin of a consumer's repo-id test table outside this workspace, which
    /// is in turn the twin of the TS `Uuid` schema's vectors. The grammar rows
    /// must stay identical across the three, but for the max UUID in upper or
    /// mixed case, which this grammar and the `fuz_schema` `Uuid` take and that
    /// table refuses (declared in each); each side keeps its
    /// own domain negatives besides (a repo slug there, none here).
    #[test]
    fn uuid_accepts_rfc_uuids() {
        // Postgres gen_random_uuid() v4 — the only shape real ids take.
        assert!(is_valid_uuid("3f8a1c2e-1234-4abc-9def-0123456789ab"));
        // Hex is case-insensitive in the versioned grammar.
        assert!(is_valid_uuid("3F8A1C2E-1234-4ABC-9DEF-0123456789AB"));
        // Every RFC 9562 version nibble 1..=8 is admitted, not just v4.
        assert!(is_valid_uuid("3f8a1c2e-1234-1abc-9def-0123456789ab"));
        assert!(is_valid_uuid("3f8a1c2e-1234-8abc-9def-0123456789ab"));
        // All four variant nibbles, either case.
        assert!(is_valid_uuid("3f8a1c2e-1234-4abc-8def-0123456789ab"));
        assert!(is_valid_uuid("3f8a1c2e-1234-4abc-Bdef-0123456789ab"));
    }

    #[test]
    fn uuid_accepts_nil_and_max_in_any_case() {
        assert!(is_valid_uuid("00000000-0000-0000-0000-000000000000"));
        assert!(is_valid_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        // RFC 9562 §4 reads a UUID case-insensitively, the max too, as the
        // fuz_schema `Uuid` does.
        assert!(is_valid_uuid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"));
        assert!(is_valid_uuid("ffffffff-FFFF-ffff-FFFF-ffffffffffff"));
        // A near-max still needs a valid version or variant nibble.
        assert!(!is_valid_uuid("ffffffff-ffff-ffff-ffff-fffffffffffe"));
        assert!(!is_valid_uuid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFE"));
    }

    /// An accepted id parses to the value its lowercase spelling names, and
    /// renders lowercase: the TS twin lowercases its output, so both spines
    /// hold the same value, not only the same verdict.
    #[test]
    fn uuid_params_parse_to_the_lowercase_value() {
        for (raw, canonical) in [
            (
                "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
            (
                "ffffffff-FFFF-ffff-FFFF-ffffffffffff",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ),
            (
                "3F8A1C2E-1234-4ABC-9DEF-0123456789AB",
                "3f8a1c2e-1234-4abc-9def-0123456789ab",
            ),
        ] {
            let parsed = parse_uuid_param(&json!({ "id": raw }), "id")
                .unwrap_or_else(|e| panic!("{raw} must parse: {e:?}"));
            assert_eq!(parsed.to_string(), canonical, "{raw}");
            let optional = parse_optional_uuid_param(&json!({ "id": raw }), "id")
                .unwrap_or_else(|e| panic!("{raw} must parse: {e:?}"));
            assert_eq!(optional.map(|u| u.to_string()).as_deref(), Some(canonical));
            let typed: uuid::Uuid = deserialize_wire_uuid(&mut serde_json::Deserializer::from_str(
                &format!("\"{raw}\""),
            ))
            .unwrap_or_else(|e| panic!("{raw} must deserialize: {e}"));
            assert_eq!(typed.to_string(), canonical, "{raw}");
        }
        assert_eq!(
            parse_uuid_param(
                &json!({ "id": "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" }),
                "id"
            )
            .expect("the uppercase max parses"),
            uuid::Uuid::max()
        );
    }

    #[test]
    fn uuid_rejects_bad_nibbles() {
        // Version nibble 0 — the synthetic near-nil id that exposed the
        // grammar split (`Uuid::parse_str` accepted it, the wire grammar does not).
        assert!(!is_valid_uuid("00000000-0000-0000-0000-000000000001"));
        // The all-ones id every hand-written fixture reaches for is itself
        // rejected: version nibble `1` is fine, variant nibble `1` is not.
        assert!(!is_valid_uuid("11111111-1111-1111-1111-111111111111"));
        // Version nibble 9 and hex-but-not-version nibbles.
        assert!(!is_valid_uuid("3f8a1c2e-1234-9abc-9def-0123456789ab"));
        assert!(!is_valid_uuid("3f8a1c2e-1234-fabc-9def-0123456789ab"));
        // Variant nibble outside [89abAB].
        assert!(!is_valid_uuid("3f8a1c2e-1234-4abc-1def-0123456789ab"));
        assert!(!is_valid_uuid("3f8a1c2e-1234-4abc-cdef-0123456789ab"));
    }

    #[test]
    fn uuid_rejects_non_hyphenated_forms() {
        // `Uuid::parse_str` (and Postgres) accept all of these; the wire
        // grammar does not — the TS spine never did.
        assert!(!is_valid_uuid("3f8a1c2e12344abc9def0123456789ab"));
        assert!(!is_valid_uuid("{3f8a1c2e-1234-4abc-9def-0123456789ab}"));
        assert!(!is_valid_uuid(
            "urn:uuid:3f8a1c2e-1234-4abc-9def-0123456789ab"
        ));
        assert!(!is_valid_uuid("not-a-uuid"));
        assert!(!is_valid_uuid(""));
    }
}
