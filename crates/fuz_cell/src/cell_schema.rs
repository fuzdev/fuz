//! Cell wire + row types.
//!
//! `CellVisibility` is the coarse access-control axis (peer to
//! `cell_grant`, stored as a top-level PG enum column — never inside
//! `data`); `kind` is the capability tag, likewise a top-level column
//! (never inside `data`). `CellRow` is the decoded DB row; it serializes
//! directly to the `CellJson` wire shape (the same keys as the TS reference
//! backend's `CellJson`), so handlers return `serde_json::to_value(row)`
//! without a separate wire struct.
//!
//! Wire inputs are duck-typed: a local `Deserialize` struct per verb
//! parsed from `serde_json::Value`. Typed codegen lands later; the wire
//! contract is the TS `cell_action_specs.ts` schemas. The content a write
//! carries decodes as [`CellData`], the twin of the TS `CellData` schema, and
//! a root's contribution policy as [`CellPolicy`], the twin of `CellPolicy`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Coarse access-control axis. Serializes to the lowercase wire tokens
/// (`"private"` / `"public"`) the TS `CellVisibility` enum uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CellVisibility {
    Private,
    Public,
}

impl CellVisibility {
    /// PG enum literal for this variant — bound as a `text` param then
    /// cast `::cell_visibility` in SQL.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Public => "public",
        }
    }

    /// Decode the `visibility::text` projection back into the enum.
    /// `None` on an unrecognized literal (a schema/enum drift signal).
    #[must_use]
    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "private" => Some(Self::Private),
            "public" => Some(Self::Public),
            _ => None,
        }
    }
}

/// Column a `cell_list` query orders by.
///
/// The wire carries `order_by` as a string; the `cell_list` handler refuses
/// any value but `created_at` / `updated_at` (the TS schema's `one_of`) and
/// maps an absent one to [`Self::CreatedAt`], as the TS backend does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CellListOrderBy {
    #[default]
    CreatedAt,
    UpdatedAt,
}

impl CellListOrderBy {
    /// Column name interpolated into the `ORDER BY` clause.
    #[must_use]
    pub const fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
        }
    }
}

/// Sort direction for a `cell_list` query. The handler refuses a wire value
/// other than `asc` / `desc` (the TS schema's `one_of`) and maps an absent one
/// to [`Self::Desc`], as the TS backend does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CellListOrderDir {
    Asc,
    #[default]
    Desc,
}

impl CellListOrderDir {
    /// SQL keyword interpolated into the `ORDER BY` clause.
    #[must_use]
    pub const fn sql(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

/// Decoded `cell` row. Serializes to the `CellJson` wire shape.
///
/// Timestamps are ISO-8601 strings produced SQL-side (`to_char(... AT
/// TIME ZONE 'UTC')`) so the wire matches the TS backend without a Rust
/// time-type dependency. `data` round-trips through `data::text` (the
/// workspace `tokio-postgres` has no `with-serde_json` feature).
/// `grant_count` is a correlated-subquery projection, not a column.
#[derive(Debug, Clone, Serialize)]
pub struct CellRow {
    pub id: Uuid,
    pub data: Value,
    /// Capability tag, hoisted out of `data` to a nullable top-level column
    /// (peer to `visibility` / `path`). Fixed at birth — written at INSERT,
    /// carried on no update input. Serialized even when null so the wire row
    /// always carries the key. `None` = a typeless cell (pure structural
    /// content, no capability tag).
    pub kind: Option<String>,
    pub visibility: CellVisibility,
    pub path: Option<String>,
    pub refs: Option<Vec<String>>,
    /// Immediate container in the directory tree — nullable FK to `cell.id`.
    /// `None` = a root (parentless; e.g. a top-level space). Set once at
    /// create, immutable in v1 (carried on no update input). Serialized even
    /// when null.
    pub parent_id: Option<Uuid>,
    /// Governing root of the directory subtree, denormalized for flat-subtree
    /// queries — `root_id = parent.root_id ?? parent.id`, so a root has
    /// `None`. Set once at create, immutable in v1. Serialized even when null.
    pub root_id: Option<Uuid>,
    /// Approval-lifecycle marker for a gated contribution (`pending` /
    /// `approved` / `rejected`); `None` = unmoderated. A control field with a
    /// non-author writer (set by the server from the create authorizer's
    /// verdict, transitioned only by `cell_moderate`) — peer to `visibility`,
    /// never inside `data` (an author can edit their own `data` and would
    /// self-approve). Serialized even when null.
    pub moderation: Option<String>,
    /// A root's contribution policy — an opaque JSON object the consumer's
    /// create authorizer interprets (`None` = the authorizer's floor governs).
    /// Roots only (the table CHECK). A control field with a manage-tier writer
    /// (set at a root's `cell_create`, changed only by `cell_policy_set`),
    /// never inside `data` — an editor grant can write `data`, and the policy
    /// decides who may contribute. Serialized even when null.
    pub policy: Option<Value>,
    pub created_at: String,
    pub updated_at: Option<String>,
    pub deleted_at: Option<String>,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub grant_count: i32,
}

/// The facts [`crate::cell_authz::can_view_cell`] reads off a cell — what a
/// full [`CellRow`] and the narrow [`CellViewRow`] both carry, so a bulk
/// visibility check need not load `data` / `refs`.
///
/// **Object-safe.**
pub trait CellViewFacts {
    /// The cell's `visibility`.
    fn visibility(&self) -> CellVisibility;
    /// The cell's `moderation` marker (`None` = unmoderated).
    fn moderation(&self) -> Option<&str>;
    /// The owning actor (`None` = system origin, owned by no one).
    fn created_by(&self) -> Option<Uuid>;
}

impl CellViewFacts for CellRow {
    fn visibility(&self) -> CellVisibility {
        self.visibility
    }
    fn moderation(&self) -> Option<&str> {
        self.moderation.as_deref()
    }
    fn created_by(&self) -> Option<Uuid> {
        self.created_by
    }
}

/// A cell read for its view check alone — the
/// [`crate::cell_queries::CELL_VIEW_COLUMNS`] projection. Twin of
/// `fuz_app`'s `CellViewRow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellViewRow {
    pub id: Uuid,
    pub visibility: CellVisibility,
    pub moderation: Option<String>,
    pub created_by: Option<Uuid>,
}

impl CellViewFacts for CellViewRow {
    fn visibility(&self) -> CellVisibility {
        self.visibility
    }
    fn moderation(&self) -> Option<&str> {
        self.moderation.as_deref()
    }
    fn created_by(&self) -> Option<Uuid> {
        self.created_by
    }
}

// -- Cell data --------------------------------------------------------------

/// The fields [`CellData`] types: each optional, a string when present.
const CELL_DATA_STRING_FIELDS: [&str; 2] = ["label", "summary"];

/// Why a JSON value is not [`CellData`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CellDataError {
    /// The value is not a JSON object.
    #[error("cell data must be an object")]
    NotObject,
    /// A typed base field is present with a non-string value.
    #[error("cell data `{field}` must be a string")]
    FieldNotString {
        /// The typed field (`label` / `summary`).
        field: &'static str,
    },
}

/// The cell content a write carries — the twin of `fuz_app`'s `CellData`,
/// `loose_object({label: optional(string), summary: optional(string)})`.
///
/// A JSON object whose `label` and `summary`, when present, are strings; every
/// other key passes through unchecked, as the loose schema admits it. The
/// write inputs (`cell_create.data`, `cell_update.data`,
/// `cell_clone.with_data_patch`) decode through it, so a non-object or a
/// mistyped base field fails the param decode — the generic `invalid params`
/// the twin's schema step answers, ahead of every handler check. A `kind` key is
/// not refused here: the handler refuses it with its own reason
/// (`cell_kind_in_data`), after the auth gates, as the twin does. An own
/// `__proto__` key never reaches it: the dispatcher refuses params holding
/// one at any depth (`fuz_http::ERROR_PARAMS_PROTO_KEY`).
///
/// The read row ([`CellRow::data`]) stays a bare [`Value`]: it decodes what
/// the database holds, and only writes are validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CellData(Value);

impl CellData {
    /// The data as a JSON value — always a [`Value::Object`].
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.0
    }

    /// The data as an owned JSON value — always a [`Value::Object`].
    #[must_use]
    pub fn into_value(self) -> Value {
        self.0
    }
}

impl TryFrom<Value> for CellData {
    type Error = CellDataError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let Value::Object(map) = &value else {
            return Err(CellDataError::NotObject);
        };
        for field in CELL_DATA_STRING_FIELDS {
            if map.get(field).is_some_and(|v| !v.is_string()) {
                return Err(CellDataError::FieldNotString { field });
            }
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for CellData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

// -- Cell policy ------------------------------------------------------------

/// Why a JSON value is not a [`CellPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CellPolicyError {
    /// The value is not a JSON object.
    #[error("cell policy must be an object")]
    NotObject,
}

/// A root's contribution policy as a write carries it — the twin of
/// `fuz_app`'s `CellPolicy`, `loose_object({})`.
///
/// Any JSON object: the spine stores it without reading it, and the mounted
/// create authorizer both validates
/// (`CellCreateAuthorize::validate_policy`) and interprets it. A non-object
/// fails the param decode — the generic `invalid params` the twin's schema
/// step answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CellPolicy(Value);

impl CellPolicy {
    /// The policy as a JSON value — always a [`Value::Object`].
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.0
    }
}

impl TryFrom<Value> for CellPolicy {
    type Error = CellPolicyError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if value.is_object() {
            Ok(Self(value))
        } else {
            Err(CellPolicyError::NotObject)
        }
    }
}

impl<'de> Deserialize<'de> for CellPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Decode a required key whose value may be `null` — the twin of a TS
/// `nullable` (absent is refused, `null` is `None`). A bare `Option` field
/// would read an absent key as `None` too.
fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// -- Wire inputs ------------------------------------------------------------

/// `cell_create` input. `created_by` is NOT on the wire — stamped from
/// `auth.actor.id`. `path` is admin-only (a present non-null value is
/// gated); `null` / absent collapse to "no path".
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellCreateInput {
    pub data: CellData,
    /// Capability tag, written once into the top-level `cell.kind` column.
    /// Immutable — there is no `kind` on [`CellUpdateInput`]. Non-empty when
    /// present (an empty string is rejected `cell_kind_empty`); `None` / absent
    /// = a typeless cell.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub visibility: Option<CellVisibility>,
    #[serde(default)]
    pub path: Option<String>,
    /// Immediate container — the directory the new cell is created in. `None` /
    /// absent = a root (parentless). The handler resolves `root_id` from it and
    /// gates the create through the parent-aware authorizer; `root_id` /
    /// `moderation` are handler-derived, never caller input.
    #[serde(default, deserialize_with = "fuz_http::deserialize_nullish_wire_uuid")]
    pub parent_id: Option<Uuid>,
    /// The new root's contribution policy. Only a root takes one (a `Some`
    /// with a `parent_id` is refused `cell_policy_root_only`), and a mounted
    /// create authorizer must accept it (`validate_policy`); with none mounted
    /// a policy is refused `cell_policy_unsupported`. `None` / absent / `null`
    /// = no policy.
    #[serde(default)]
    pub policy: Option<CellPolicy>,
    /// Acting-actor selector. Read by the dispatcher's authorization phase
    /// (`perform_action`) to resolve the acting actor on multi-actor accounts;
    /// the handler reads `auth.actor.id` off the resolved context and ignores
    /// this field.
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_get` input. `id` OR `path` (id precedence); both absent is an
/// `invalid_params` error.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellGetInput {
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_update` input.
///
/// Tri-state `path`: absent (`None`) keeps the value, `null`
/// (`Some(None)`) clears it, a string (`Some(Some)`) sets it. Any
/// present `path` is admin-only. A present `data` / `visibility`
/// overwrites; absent keeps.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellUpdateInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub cell_id: Uuid,
    #[serde(default)]
    pub data: Option<CellData>,
    #[serde(default)]
    pub visibility: Option<CellVisibility>,
    #[serde(default)]
    pub path: Option<Option<String>>,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_delete` input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellDeleteInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub cell_id: Uuid,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// A `cell.moderation` marker on the wire — the twin of the TS
/// `CellModeration` (`'pending' | 'approved' | 'rejected'`), the markers the
/// create authorizer's verdict and `cell_moderate` write.
///
/// `cell_list`'s `moderation` filter decodes as one, so another value is
/// `invalid_params` with no reason at decode rather than a filter matching
/// nothing, as on the twin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CellModeration {
    /// [`crate::cell_moderation::CELL_MODERATION_PENDING`].
    Pending,
    /// [`crate::cell_moderation::CELL_MODERATION_APPROVED`].
    Approved,
    /// [`crate::cell_moderation::CELL_MODERATION_REJECTED`].
    Rejected,
}

impl CellModeration {
    /// The `cell.moderation` literal this marker names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => crate::cell_moderation::CELL_MODERATION_PENDING,
            Self::Approved => crate::cell_moderation::CELL_MODERATION_APPROVED,
            Self::Rejected => crate::cell_moderation::CELL_MODERATION_REJECTED,
        }
    }
}

/// The terminal transition a `cell_moderate` call applies to a gated
/// contribution's `moderation` lifecycle.
///
/// The born state (`pending`) is set by the create authorizer, never on the
/// wire; the verb only moves it to a terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CellModerationDecision {
    /// Publish the contribution: `moderation → approved`, `visibility → public`.
    Approved,
    /// Reject the contribution: `moderation → rejected` (stays private).
    Rejected,
}

impl CellModerationDecision {
    /// The `cell.moderation` literal this decision writes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    /// Whether the decision publishes the contribution (flips visibility public).
    #[must_use]
    pub const fn approves(self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// `cell_moderate` input — the `pending → approved | rejected` decision, or
/// the `approved → rejected` takedown.
///
/// Gated on moderation authority over the governing root (not the contribution,
/// which the author manages).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellModerateInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub cell_id: Uuid,
    pub moderation: CellModerationDecision,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_policy_set` input — replace a root's contribution policy (`None`
/// clears it).
///
/// Manage-tier on the root: a viewer without manage authority (an editor
/// grant included) is refused `cell_policy_manage_only`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellPolicySetInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub cell_id: Uuid,
    /// The new policy — required on the wire, `null` to clear.
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub policy: Option<CellPolicy>,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_clone` input — source must be view-admitted (404 mask otherwise).
///
/// The clone is owned by the caller; `path` is always nulled (admin-only
/// paths can't auto-clone). `with_data_patch` shallow-merges over the
/// source `data` (patch-last); a patch object carrying a `"kind"` key is
/// rejected (kind is the top-level `cell.kind` column, copied verbatim from
/// the source — never `data`). `deep` recurses into `items[]` at depth 1
/// (direct children).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellCloneInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub source_id: Uuid,
    #[serde(default)]
    pub deep: Option<bool>,
    #[serde(default)]
    pub with_data_patch: Option<CellData>,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_list` input. Every dimension optional and AND-combined.
///
/// The whole input defaults to empty (the TS schema is `with_default_fn(..., () => ({}))`), so
/// an **absent** params decodes to `CellListInput::default()`. A wire
/// `null` is refused at the envelope on the classified transports; the
/// unclassified GET query-string path decodes it as `{}` via
/// `fuz_http::parse_strict_params`, the same as absent.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CellListInput {
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid_vec")]
    pub ids: Option<Vec<Uuid>>,
    pub kind: Option<String>,
    pub visibility: Option<CellVisibility>,
    #[serde(rename = "ref")]
    pub ref_hash: Option<String>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub created_by: Option<Uuid>,
    pub path_prefix: Option<String>,
    /// Scope to a directory subtree by governing root (the feed + mod-queue
    /// key — `idx_cell_root`).
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub root_id: Option<Uuid>,
    /// Filter by moderation lifecycle marker (`pending` drives the mod-queue
    /// via `idx_cell_moderation_pending`). A [`CellModeration`], so another
    /// value is refused at decode rather than matching nothing.
    pub moderation: Option<CellModeration>,
    /// Only `"me"` is valid at the wire (the handler rejects anything else as
    /// `invalid_params`, and an unauthenticated caller outright). It narrows to
    /// cells admitting the caller via a `cell_grant` row, excluding the cells
    /// the caller created.
    pub shared_with: Option<String>,
    pub order_by: Option<String>,
    pub order_direction: Option<String>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_int")]
    pub limit: Option<i64>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_int")]
    pub offset: Option<i64>,
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::{
        CellCloneInput, CellCreateInput, CellData, CellDataError, CellGetInput, CellListInput,
        CellUpdateInput,
    };
    use serde_json::{Value, json};

    /// Deserialize through the production path — the RPC layer hands the verb
    /// a `serde_json::Value` (`fuz_http::parse_strict_params`), not a string.
    fn parse<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// A grammar-valid v4 — the only id shape Postgres ever mints.
    const CELL_ID: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";

    /// The list pages read an integer as the twin does — every integral
    /// spelling, nothing fractional, nothing past the safe range — and the
    /// relation lists' `limit` too. Decoded from text, since `json!` would
    /// build an integer for `5.0`.
    #[test]
    fn list_pages_read_integral_floats() {
        use crate::cell_field_schema::CellFieldListInput;
        use crate::cell_item_schema::CellItemListInput;
        fn list(text: &str) -> Result<CellListInput, serde_json::Error> {
            serde_json::from_str(text)
        }
        let input = list(r#"{"limit":5.0,"offset":-0}"#).unwrap();
        assert_eq!((input.limit, input.offset), (Some(5), Some(0)));
        assert_eq!(list(r#"{"limit":1e1}"#).unwrap().limit, Some(10));
        for text in [
            r#"{"limit":5.5}"#,
            r#"{"offset":0.5}"#,
            r#"{"offset":9007199254740992}"#,
            r#"{"limit":"5"}"#,
            r#"{"limit":null}"#,
        ] {
            assert!(list(text).is_err(), "{text}");
        }
        let field: CellFieldListInput = serde_json::from_str(r#"{"limit":5.0}"#).unwrap();
        assert_eq!(field.limit, Some(5));
        let item: CellItemListInput = serde_json::from_str(r#"{"limit":5.0}"#).unwrap();
        assert_eq!(item.limit, Some(5));
        assert!(serde_json::from_str::<CellFieldListInput>(r#"{"limit":5.5}"#).is_err());
        assert!(serde_json::from_str::<CellItemListInput>(r#"{"limit":5.5}"#).is_err());
    }

    /// `cell_list`'s `moderation` filter is the twin's `CellModeration`: the
    /// three markers decode, and any other value is refused at decode rather
    /// than filtering to nothing.
    #[test]
    fn list_moderation_filter_takes_only_the_markers() {
        use super::CellModeration;
        for (raw, marker) in [
            ("pending", CellModeration::Pending),
            ("approved", CellModeration::Approved),
            ("rejected", CellModeration::Rejected),
        ] {
            let input: CellListInput = parse(json!({"moderation": raw})).unwrap();
            assert_eq!(input.moderation, Some(marker));
            assert_eq!(marker.as_str(), raw);
        }
        for bad in [json!(""), json!("bogus"), json!("Pending"), json!(1)] {
            assert!(
                parse::<CellListInput>(json!({"moderation": bad})).is_err(),
                "{bad}"
            );
        }
    }

    /// The spellings `Uuid::parse_str` accepts and the TS `Uuid` refuses.
    /// Mirrors the `is_valid_uuid` table in `fuz_http::params` — the grammar
    /// these fields decode through — so a widening there fails here too.
    const OFF_GRAMMAR_UUIDS: [&str; 6] = [
        // Hyphenless, braced, and URN spellings of `CELL_ID`.
        "3f8a1c2e12344abc9def0123456789ab",
        "{3f8a1c2e-1234-4abc-9def-0123456789ab}",
        "urn:uuid:3f8a1c2e-1234-4abc-9def-0123456789ab",
        // Version nibble outside `1..=8`, and variant nibble outside `[89ab]`.
        "3f8a1c2e-1234-9abc-9def-0123456789ab",
        "3f8a1c2e-1234-4abc-1def-0123456789ab",
        "not-a-uuid",
    ];

    /// Spellings the grammar takes besides `CELL_ID`, each with the id it
    /// names: an uppercase id, and the max UUID in upper and mixed case
    /// (RFC 9562 §4, as both TS `Uuid`s). Each decodes to the lowercase id,
    /// the TS twins' output.
    const ON_GRAMMAR_UUIDS: [(&str, &str); 3] = [
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
    ];

    #[test]
    fn a_uuid_field_takes_either_case_and_holds_the_lowercase_id() {
        for (raw, canonical) in ON_GRAMMAR_UUIDS {
            let update: CellUpdateInput = parse(json!({"cell_id": raw}))
                .unwrap_or_else(|e| panic!("cell_id {raw} must parse: {e}"));
            assert_eq!(update.cell_id.to_string(), canonical, "cell_id {raw}");
            let get: CellGetInput =
                parse(json!({"id": raw})).unwrap_or_else(|e| panic!("id {raw} must parse: {e}"));
            assert_eq!(
                get.id.map(|id| id.to_string()).as_deref(),
                Some(canonical),
                "id {raw}"
            );
            let list: CellListInput = parse(json!({"ids": [raw]}))
                .unwrap_or_else(|e| panic!("ids [{raw}] must parse: {e}"));
            assert_eq!(
                list.ids
                    .map(|ids| ids.iter().map(ToString::to_string).collect::<Vec<_>>()),
                Some(vec![canonical.to_owned()]),
                "ids [{raw}]"
            );
        }
    }

    #[test]
    fn a_required_uuid_field_takes_only_the_wire_grammar() {
        assert!(parse::<CellUpdateInput>(json!({"cell_id": CELL_ID})).is_ok());
        for raw in OFF_GRAMMAR_UUIDS {
            assert!(
                parse::<CellUpdateInput>(json!({"cell_id": raw})).is_err(),
                "cell_id {raw} must be refused"
            );
        }
    }

    #[test]
    fn an_optional_uuid_field_takes_only_the_wire_grammar() {
        assert!(parse::<CellGetInput>(json!({"id": CELL_ID})).is_ok());
        assert!(parse::<CellGetInput>(json!({})).is_ok());
        for raw in OFF_GRAMMAR_UUIDS {
            assert!(
                parse::<CellGetInput>(json!({"id": raw})).is_err(),
                "id {raw} must be refused"
            );
        }
    }

    /// The twin's `optional` admits an absent key and nothing else, so an
    /// explicit `null` is refused at the field, not read as "no value" —
    /// independently of `fuz_http`'s pre-decode walk.
    #[test]
    fn an_optional_uuid_field_refuses_an_explicit_null() {
        assert!(parse::<CellGetInput>(json!({"id": Value::Null})).is_err());
        assert!(parse::<CellGetInput>(json!({"acting": Value::Null})).is_err());
        assert!(parse::<CellListInput>(json!({"ids": Value::Null})).is_err());
    }

    /// `cell_create.parent_id` is `optional(nullable(Uuid))` on the twin — `null` is a
    /// spelling of "a root", not a refusal. The grammar still applies to a
    /// string.
    #[test]
    fn a_nullish_uuid_field_reads_null_as_absent() {
        let input: CellCreateInput = parse(json!({"data": {}, "parent_id": Value::Null}))
            .unwrap_or_else(|e| panic!("nullish parent_id must parse: {e}"));
        assert!(input.parent_id.is_none());
        assert!(parse::<CellCreateInput>(json!({"data": {}, "parent_id": CELL_ID})).is_ok());
        assert!(
            parse::<CellCreateInput>(json!({"data": {}, "parent_id": OFF_GRAMMAR_UUIDS[0]}))
                .is_err()
        );
    }

    #[test]
    fn a_uuid_list_field_holds_every_element_to_the_grammar() {
        assert!(parse::<CellListInput>(json!({"ids": [CELL_ID, CELL_ID]})).is_ok());
        assert!(parse::<CellListInput>(json!({"ids": []})).is_ok());
        for raw in OFF_GRAMMAR_UUIDS {
            assert!(
                parse::<CellListInput>(json!({"ids": [CELL_ID, raw]})).is_err(),
                "ids element {raw} must be refused"
            );
        }
        // A non-string element is refused by the element type, not coerced.
        assert!(parse::<CellListInput>(json!({"ids": [1]})).is_err());
        assert!(parse::<CellListInput>(json!({"ids": [Value::Null]})).is_err());
    }

    /// `CellData` is the twin's `loose_object({label: optional(string),
    /// summary: optional(string)})`: an object, its two typed fields strings when present, every
    /// other key passed through.
    #[test]
    fn cell_data_takes_an_object_with_string_base_fields() {
        for ok in [
            json!({}),
            json!({"label": "l", "summary": "s"}),
            json!({"extra": [1, Value::Null], "nested": {"label": 1}}),
        ] {
            let data = CellData::try_from(ok.clone())
                .unwrap_or_else(|e| panic!("{ok} must be cell data: {e}"));
            assert_eq!(data.as_value(), &ok);
            assert_eq!(data.into_value(), ok);
        }
        for not_object in [
            json!("not_an_object"),
            json!(42),
            json!(true),
            json!([]),
            Value::Null,
        ] {
            assert_eq!(
                CellData::try_from(not_object),
                Err(CellDataError::NotObject)
            );
        }
        for (bad, field) in [
            (json!({"label": 123}), "label"),
            (json!({"label": Value::Null}), "label"),
            (json!({"summary": []}), "summary"),
            (json!({"label": "l", "summary": false}), "summary"),
        ] {
            assert_eq!(
                CellData::try_from(bad),
                Err(CellDataError::FieldNotString { field })
            );
        }
    }

    /// Every write input decodes its content through `CellData`, so a
    /// mistyped `data` / `with_data_patch` fails the param decode itself.
    #[test]
    fn the_write_inputs_refuse_data_that_is_not_cell_data() {
        for bad in [json!("not_an_object"), json!([1]), json!({"label": 1})] {
            assert!(
                parse::<CellCreateInput>(json!({"data": bad})).is_err(),
                "{bad}"
            );
            assert!(
                parse::<CellUpdateInput>(json!({"cell_id": CELL_ID, "data": bad})).is_err(),
                "{bad}"
            );
            assert!(
                parse::<CellCloneInput>(json!({"source_id": CELL_ID, "with_data_patch": bad}))
                    .is_err(),
                "{bad}"
            );
        }
        let input: CellCreateInput = parse(json!({"data": {"label": "l", "x": 1}}))
            .unwrap_or_else(|e| panic!("cell data must parse: {e}"));
        assert_eq!(input.data.as_value(), &json!({"label": "l", "x": 1}));
        // the optional ones stay optional
        assert!(
            parse::<CellUpdateInput>(json!({"cell_id": CELL_ID}))
                .is_ok_and(|input| input.data.is_none())
        );
        assert!(
            parse::<CellCloneInput>(json!({"source_id": CELL_ID}))
                .is_ok_and(|input| input.with_data_patch.is_none())
        );
    }
}
