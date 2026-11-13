//! Canonical JSON serialization
//!
//! Deterministic JSON output for the signed documents (release manifests and
//! release log heads). The signed bytes are a domain tag followed by this
//! output — see `crate::signing::SignedMessage`.
//!
//! Properties:
//! - Sorted object keys (lexicographic by UTF-8 bytes)
//! - No whitespace (compact format)
//! - ASCII-only strings
//! - Integer-only numbers (no floats)

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write;

use crate::error::CanonicalError;

/// Serialize a value to canonical JSON.
///
/// # Errors
///
/// Returns error if:
/// - Any string contains non-ASCII characters
/// - Any number is not representable as an integer (floats, overflow)
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let json_value = serde_json::to_value(value)?;
    let mut out = String::new();
    write_canonical(&json_value, &mut out)?;
    Ok(out)
}

/// Write canonical JSON directly to string, guaranteeing key ordering.
///
/// Avoids round-tripping through `serde_json::Map` which has unclear ordering guarantees.
#[expect(
    clippy::expect_used,
    reason = "infallible: `write!` to a `String` has no I/O, and serializing a valid `&str` cannot fail"
)]
fn write_canonical(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // Only integers allowed - reject floats and overflow
            if !n.is_i64() && !n.is_u64() {
                return Err(CanonicalError::NumberNotInteger(n.to_string()));
            }
            write!(out, "{n}").expect("infallible: write to String");
        }
        Value::String(s) => {
            if !s.is_ascii() {
                return Err(CanonicalError::NonAsciiString(s.clone()));
            }
            // Use serde_json for proper escaping
            out.push_str(&serde_json::to_string(s).expect("infallible: &str serialization"));
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Collect into BTreeMap which maintains lexicographic order by key.
            // BTreeMap::iter() is guaranteed to yield entries in sorted order.
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if !k.is_ascii() {
                    return Err(CanonicalError::NonAsciiString((*k).clone()));
                }
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(*k).expect("infallible: &str serialization"));
                out.push(':');
                write_canonical(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_is_stable() {
        // This test MUST NOT be updated casually.
        // Changing expected output breaks all existing signatures.
        let data = json!({
            "z": "last",
            "a": "first",
            "nested": {"b": 2, "a": 1},
            "number": 42
        });
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(
            canonical,
            r#"{"a":"first","nested":{"a":1,"b":2},"number":42,"z":"last"}"#
        );
    }

    #[test]
    fn canonical_json_sorted_keys() {
        let data = json!({"z": 1, "a": 2, "m": 3});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn canonical_json_no_whitespace() {
        let data = json!({"key": [1, 2, 3], "nested": {"a": "b"}});
        let canonical = canonical_json(&data).expect("should succeed");
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
        assert!(!canonical.contains('\t'));
    }

    #[test]
    fn canonical_json_rejects_non_ascii() {
        let data = json!({"name": "café"});
        let result = canonical_json(&data);
        assert!(matches!(result, Err(CanonicalError::NonAsciiString(_))));
    }

    #[test]
    fn canonical_json_rejects_non_integers() {
        // Floats are rejected
        let data = json!({"value": 1.5});
        assert!(matches!(
            canonical_json(&data),
            Err(CanonicalError::NumberNotInteger(_))
        ));
    }

    #[test]
    fn canonical_json_escapes_control_chars() {
        let data = json!({"text": "line1\nline2\ttab"});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"text":"line1\nline2\ttab"}"#);
    }

    #[test]
    fn canonical_json_escapes_quotes_and_backslash() {
        let data = json!({"text": "say \"hello\" \\ world"});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"text":"say \"hello\" \\ world"}"#);
    }

    #[test]
    fn canonical_json_does_not_escape_forward_slash() {
        // Forward slash escaping varies by implementation.
        // We use serde_json's default (no escape).
        // This test documents the behavior - if serde_json changes, we'll know.
        let data = json!({"url": "https://fuz.dev/path"});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"url":"https://fuz.dev/path"}"#);
    }

    #[test]
    fn canonical_json_escapes_null_byte() {
        let data = json!({"text": "before\x00after"});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"text":"before\u0000after"}"#);
    }

    #[test]
    fn canonical_json_empty_object() {
        let data = json!({});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, "{}");
    }

    #[test]
    fn canonical_json_empty_array() {
        let data = json!([]);
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, "[]");
    }

    #[test]
    fn canonical_json_nested_empty() {
        let data = json!({"empty_obj": {}, "empty_arr": [], "items": [{}]});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"empty_arr":[],"empty_obj":{},"items":[{}]}"#);
    }

    // Verify serde_json escaping behavior hasn't changed.
    // We depend on exact byte output for signature stability.
    // If these fail after a serde_json update, signatures will break.
    #[test]
    fn serde_json_escaping_is_stable() {
        // Control characters use \uXXXX
        assert_eq!(
            serde_json::to_string("\x00").expect("serialize"),
            r#""\u0000""#
        );
        assert_eq!(
            serde_json::to_string("\x1f").expect("serialize"),
            r#""\u001f""#
        );
        // Standard escapes
        assert_eq!(serde_json::to_string("\n").expect("serialize"), r#""\n""#);
        assert_eq!(serde_json::to_string("\t").expect("serialize"), r#""\t""#);
        assert_eq!(serde_json::to_string("\r").expect("serialize"), r#""\r""#);
        assert_eq!(serde_json::to_string("\\").expect("serialize"), r#""\\""#);
        assert_eq!(serde_json::to_string("\"").expect("serialize"), r#""\"""#);
        // Forward slash is NOT escaped (some JSON libs do escape it)
        assert_eq!(serde_json::to_string("/").expect("serialize"), r#""/""#);
    }

    #[test]
    fn canonical_json_boolean_values() {
        let data = json!({"flag": true, "other": false});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"flag":true,"other":false}"#);
    }

    #[test]
    fn canonical_json_null_value() {
        let data = json!({"empty": null});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"empty":null}"#);
    }

    #[test]
    fn canonical_json_negative_integer() {
        let data = json!({"value": -42});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"value":-42}"#);
    }

    #[test]
    fn canonical_json_large_integer() {
        let data = json!({"big": 9_007_199_254_740_992_i64});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"big":9007199254740992}"#);
    }

    #[test]
    fn canonical_json_array_ordering_preserved() {
        let data = json!([3, 1, 2]);
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, "[3,1,2]");
    }

    #[test]
    fn canonical_json_rejects_non_ascii_in_keys() {
        // Object keys must also be ASCII-only
        let mut map = serde_json::Map::new();
        map.insert("café".to_string(), json!("value"));
        let data = Value::Object(map);
        let result = canonical_json(&data);
        assert!(matches!(result, Err(CanonicalError::NonAsciiString(_))));
    }

    #[test]
    fn canonical_json_deeply_nested() {
        // Verify deeply nested structures work without stack overflow
        // 100 levels should be fine for any reasonable manifest
        let mut data = json!("leaf");
        for i in 0..100 {
            data = json!({ format!("level{i}"): data });
        }
        let result = canonical_json(&data);
        assert!(result.is_ok());
        let canonical = result.expect("should succeed");
        assert!(canonical.starts_with('{'));
        assert!(canonical.ends_with('}'));
    }

    #[test]
    fn canonical_json_empty_string() {
        let data = json!({"empty": ""});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, r#"{"empty":""}"#);
    }

    #[test]
    fn canonical_json_max_i64() {
        let data = json!({"max": i64::MAX});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, format!(r#"{{"max":{}}}"#, i64::MAX));
    }

    #[test]
    fn canonical_json_min_i64() {
        let data = json!({"min": i64::MIN});
        let canonical = canonical_json(&data).expect("should succeed");
        assert_eq!(canonical, format!(r#"{{"min":{}}}"#, i64::MIN));
    }

    /// Above `i64::MAX` only the `is_u64` arm admits a value; pin that it
    /// serializes exactly rather than being refused or rounded.
    #[test]
    fn canonical_json_above_i64_max_uses_the_u64_arm() {
        let above = u64::try_from(i64::MAX).expect("positive") + 1;
        for n in [above, u64::MAX] {
            let canonical = canonical_json(&json!({"n": n})).expect("should succeed");
            assert_eq!(canonical, format!(r#"{{"n":{n}}}"#));
        }
        assert_eq!(
            canonical_json(&json!({"n": u64::MAX})).expect("should succeed"),
            r#"{"n":18446744073709551615}"#
        );
    }
}
