//! Cell-item wire + row types.
//!
//! A `cell_item` row is ordered-child membership `(parent_id, position) →
//! child_id`. `position` is opaque text (a fractional-indexing key); lex
//! ordering is the contract. The `(parent_id, position)` PK enforces one
//! cell per slot but allows the same `child_id` at multiple positions
//! (JSON-array-shaped — ordered multiset). Mirrors the TS
//! `cell_item_action_specs.ts` wire shapes.
//!
//! Wire inputs are duck-typed (`serde_json::Value` → local `Deserialize`),
//! matching the rest of the crate. `CellItemRow` serializes directly to the
//! `ItemJson` wire shape (same 4 keys as the TS reference).

use fuz_sys::fractional_index::FRACTIONAL_INDEX_LENGTH_MAX;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Whether `position` matches the base62 fractional-index grammar
/// (`^[0-9A-Za-z]+$`, 1-`FRACTIONAL_INDEX_LENGTH_MAX` chars).
///
/// The cap comes from `fuz_sys::fractional_index`, so this wire check and the
/// generator that produces positions can't drift apart. The wire is duck-typed
/// (no Zod layer on the spine), so the handler enforces the grammar here. The
/// no-trailing-`'0'` invariant lives client-side, not on the wire.
#[must_use]
pub fn is_valid_position(position: &str) -> bool {
    !position.is_empty()
        && position.len() <= FRACTIONAL_INDEX_LENGTH_MAX
        && position.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Decoded `cell_item` row. Serializes to the `ItemJson` wire shape.
///
/// `created_at` projects SQL-side as a UTC ISO-8601 string (the workspace
/// `tokio-postgres` has no time-type feature).
#[derive(Debug, Clone, Serialize)]
pub struct CellItemRow {
    pub parent_id: Uuid,
    pub position: String,
    pub child_id: Uuid,
    pub created_at: String,
}

/// `cell_item_insert` input. Client computes `position` via
/// `fractional_index_between` before calling. A `(parent_id, position)`
/// collision surfaces as `cell_item_position_taken`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellItemInsertInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub parent_id: Uuid,
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub child_id: Uuid,
    pub position: String,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_item_move` input. Move within the same parent (cross-parent moves
/// are a future extension).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellItemMoveInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub parent_id: Uuid,
    pub position: String,
    pub new_position: String,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_item_delete` input. Idempotent on the slot key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellItemDeleteInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub parent_id: Uuid,
    pub position: String,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_item_list` input. Exactly one of `parent_id` (forward items) or
/// `child_id` (reverse parents). `limit` caps either direction (the verb
/// defaults it); `position_after` is the forward cursor.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CellItemListInput {
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub parent_id: Option<Uuid>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub child_id: Option<Uuid>,
    pub position_after: Option<String>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_int")]
    pub limit: Option<i64>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::{FRACTIONAL_INDEX_LENGTH_MAX, is_valid_position};

    #[test]
    fn position_grammar() {
        assert!(is_valid_position("a0"));
        assert!(is_valid_position("Zz09"));
        assert!(is_valid_position("V"));
        assert!(is_valid_position(&"a".repeat(FRACTIONAL_INDEX_LENGTH_MAX)));
        // Empty, non-base62 chars, over-cap.
        assert!(!is_valid_position(""));
        assert!(!is_valid_position("a-b"));
        assert!(!is_valid_position("a_b"));
        assert!(!is_valid_position("a b"));
        assert!(!is_valid_position(
            &"a".repeat(FRACTIONAL_INDEX_LENGTH_MAX + 1)
        ));
    }
}
