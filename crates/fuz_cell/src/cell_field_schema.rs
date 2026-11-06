//! Cell-field wire + row types.
//!
//! A `cell_field` row is a named relation `(source_id, name) → target_id`
//! — a JSON-object-shaped edge from one cell to another. `(source_id,
//! name)` is unique: re-setting a name overwrites its target. Mirrors the
//! TS `cell_field_action_specs.ts` wire shapes.
//!
//! Wire inputs are duck-typed (`serde_json::Value` → local `Deserialize`),
//! matching the rest of the crate. `CellFieldRow` serializes directly to
//! the `FieldJson` wire shape (same 4 keys as the TS reference).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Field-name length cap (mirrors the TS `CELL_FIELD_NAME_REGEX` brand
/// `^[a-z][a-z0-9_]{0,63}$`).
///
/// The wire is duck-typed (no schema layer on the spine), so the handler
/// enforces the grammar via [`is_valid_field_name`].
pub const CELL_FIELD_NAME_LENGTH_MAX: usize = 64;

/// Whether `name` matches the fuz `snake_case` field-name grammar: a
/// leading lowercase letter, then lowercase alphanumerics / underscores,
/// 1-64 chars total.
#[must_use]
pub fn is_valid_field_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    name.len() <= CELL_FIELD_NAME_LENGTH_MAX
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Decoded `cell_field` row. Serializes to the `FieldJson` wire shape.
///
/// `created_at` projects SQL-side as a UTC ISO-8601 string (the workspace
/// `tokio-postgres` has no time-type feature).
#[derive(Debug, Clone, Serialize)]
pub struct CellFieldRow {
    pub source_id: Uuid,
    pub name: String,
    pub target_id: Uuid,
    pub created_at: String,
}

/// `cell_field_set` input. UPSERT on `(source_id, name)` — re-issuing the
/// same input updates `target_id` and bumps `created_at`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellFieldSetInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub source_id: Uuid,
    pub name: String,
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub target_id: Uuid,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_field_delete` input. Idempotent: success even when no row matched.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellFieldDeleteInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub source_id: Uuid,
    pub name: String,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_field_list` input. Exactly one of `source_id` (forward fields) or
/// `target_id` (reverse upfields). `limit` caps either direction (the verb
/// defaults it); `name_after` is the forward cursor.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CellFieldListInput {
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub source_id: Option<Uuid>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub target_id: Option<Uuid>,
    pub name_after: Option<String>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_int")]
    pub limit: Option<i64>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::{CELL_FIELD_NAME_LENGTH_MAX, is_valid_field_name};

    #[test]
    fn field_name_grammar() {
        assert!(is_valid_field_name("tags"));
        assert!(is_valid_field_name("a"));
        assert!(is_valid_field_name("cover_image_2"));
        assert!(is_valid_field_name(&"a".repeat(CELL_FIELD_NAME_LENGTH_MAX)));
        // Empty, leading digit / underscore, uppercase, over-cap, bad chars.
        assert!(!is_valid_field_name(""));
        assert!(!is_valid_field_name("2tags"));
        assert!(!is_valid_field_name("_tags"));
        assert!(!is_valid_field_name("Tags"));
        assert!(!is_valid_field_name("a-b"));
        assert!(!is_valid_field_name(
            &"a".repeat(CELL_FIELD_NAME_LENGTH_MAX + 1)
        ));
    }
}
