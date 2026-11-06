//! Cell-grant ACL wire + row types.
//!
//! A `cell_grant` row admits a principal — an actor (`actor_id`) xor a
//! role+scope (`role`, `scope_id?`) — at a `level` (`viewer` / `editor`)
//! on one cell. Owner is implicit on `cell.created_by` and never appears
//! as a grant. Mirrors the TS `cell_grant_action_specs.ts` wire shapes.
//!
//! Wire inputs are duck-typed (`serde_json::Value` → local `Deserialize`),
//! matching the rest of the crate. `CellGrantRow` serializes directly to
//! the `GrantJson` wire shape (same 8 keys as the TS reference).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Grant level — view-only or view-plus-edit. Stored as a `TEXT` column
/// with a `CHECK` (not a PG enum), so it binds / reads as a plain string
/// (no `::text` cast on the wire side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CellGrantLevel {
    Viewer,
    Editor,
}

impl CellGrantLevel {
    /// Column literal for this variant (bound directly as a `text` param).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
        }
    }

    /// Decode the `level` column back into the enum. `None` on an
    /// unrecognized literal (a schema/CHECK drift signal).
    #[must_use]
    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "viewer" => Some(Self::Viewer),
            "editor" => Some(Self::Editor),
            _ => None,
        }
    }
}

/// Decoded `cell_grant` row. Serializes to the `GrantJson` wire shape.
///
/// Same 8 keys the TS reference surfaces. `created_at` projects SQL-side
/// as an ISO-8601 string (the workspace `tokio-postgres` has no time-type
/// feature).
#[derive(Debug, Clone, Serialize)]
pub struct CellGrantRow {
    pub id: Uuid,
    pub cell_id: Uuid,
    pub level: CellGrantLevel,
    pub actor_id: Option<Uuid>,
    pub role: Option<String>,
    pub scope_id: Option<Uuid>,
    pub granted_by: Option<Uuid>,
    pub created_at: String,
}

/// Wire-input principal, discriminated by `kind`.
///
/// Actor-shaped principals carry a pre-resolved `actor_id` — the picker UI
/// runs `actor_search` to convert a typed name to an id before this verb
/// is called (no name resolver here). Role-shaped principals carry
/// `(role, scope_id?)`; `scope_id` null / absent = any-scope grant.
///
/// `deny_unknown_fields` applies per arm — the tag is consumed before the
/// variant reads its fields, so `kind` is never itself an unknown field, and
/// the other arm's fields are rejected rather than silently dropped. Twin of
/// the TS `z.discriminatedUnion('kind', [strictObject, strictObject])`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum CellGrantPrincipalInput {
    Actor {
        #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
        actor_id: Uuid,
    },
    Role {
        /// The role the grant admits, on the shared name grammar
        /// ([`fuz_auth::is_valid_name`]) — the twin's `RoleName`. Off it is
        /// `invalid_params` with no reason at decode, ahead of the role
        /// registry check.
        #[serde(deserialize_with = "deserialize_role_name")]
        role: String,
        #[serde(default, deserialize_with = "fuz_http::deserialize_nullish_wire_uuid")]
        scope_id: Option<Uuid>,
    },
}

/// Decode a role name, refusing a string off [`fuz_auth::is_valid_name`] —
/// the twin of a TS field declared as `RoleName`.
///
/// A refusal is a serde error, so `fuz_http::parse_strict_params` answers it
/// as the generic `invalid params` (-32602) with no `data.reason`, as the twin's
/// schema step does.
fn deserialize_role_name<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let role = String::deserialize(deserializer)?;
    if !fuz_auth::is_valid_name(&role) {
        return Err(serde::de::Error::custom("not a valid role name"));
    }
    Ok(role)
}

/// `cell_grant_create` input. Idempotent on the principal's unique index —
/// re-granting the same `(cell_id, principal)` updates `level` +
/// `granted_by` rather than producing a duplicate row.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellGrantCreateInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub cell_id: Uuid,
    pub level: CellGrantLevel,
    pub principal: CellGrantPrincipalInput,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_grant_revoke` input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellGrantRevokeInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub grant_id: Uuid,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

/// `cell_grant_list` input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellGrantListInput {
    #[serde(deserialize_with = "fuz_http::deserialize_wire_uuid")]
    pub cell_id: Uuid,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    pub acting: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::CellGrantPrincipalInput;
    use serde_json::{Value, json};

    /// Deserialize through the production path — the RPC layer hands the
    /// verb a `serde_json::Value` (`fuz_http::parse_strict_params`), not a string.
    fn parse(value: Value) -> Result<CellGrantPrincipalInput, serde_json::Error> {
        serde_json::from_value(value)
    }

    const ACTOR_ID: &str = "11111111-1111-4111-8111-111111111111";
    const SCOPE_ID: &str = "22222222-2222-4222-9222-222222222222";

    /// Every shape the TS `discriminatedUnion` accepts still parses, tag in
    /// any position.
    #[test]
    fn principal_accepts_the_canonical_arms() {
        assert!(matches!(
            parse(json!({"kind": "actor", "actor_id": ACTOR_ID})),
            Ok(CellGrantPrincipalInput::Actor { .. })
        ));
        // Tag order is irrelevant — JSON objects are unordered.
        assert!(matches!(
            parse(json!({"actor_id": ACTOR_ID, "kind": "actor"})),
            Ok(CellGrantPrincipalInput::Actor { .. })
        ));
        // `scope_id` absent / null / present — all any-scope-or-scoped forms.
        assert!(matches!(
            parse(json!({"kind": "role", "role": "admin"})),
            Ok(CellGrantPrincipalInput::Role { scope_id: None, .. })
        ));
        assert!(matches!(
            parse(json!({"kind": "role", "role": "admin", "scope_id": Value::Null})),
            Ok(CellGrantPrincipalInput::Role { scope_id: None, .. })
        ));
        assert!(matches!(
            parse(json!({"kind": "role", "role": "admin", "scope_id": SCOPE_ID})),
            Ok(CellGrantPrincipalInput::Role {
                scope_id: Some(_),
                ..
            })
        ));
    }

    /// The principal's ids decode through the strict wire grammar, so a
    /// spelling `Uuid::parse_str` takes and `z.uuid()` refuses is
    /// `invalid_params` here rather than a live lookup. `scope_id` is
    /// `Uuid.nullish()` on the twin, so `null` stays a spelling of
    /// "any scope" while an off-grammar string does not.
    #[test]
    fn principal_ids_take_only_the_wire_uuid_grammar() {
        for raw in [
            "11111111111141118111111111111111",       // hyphenless
            "{11111111-1111-4111-8111-111111111111}", // braced
            "urn:uuid:11111111-1111-4111-8111-111111111111",
            "11111111-1111-9111-8111-111111111111", // version nibble outside 1..=8
            "11111111-1111-4111-1111-111111111111", // variant nibble outside [89ab]
            "not-a-uuid",
        ] {
            assert!(
                parse(json!({"kind": "actor", "actor_id": raw})).is_err(),
                "actor_id {raw} must be refused"
            );
            assert!(
                parse(json!({"kind": "role", "role": "admin", "scope_id": raw})).is_err(),
                "scope_id {raw} must be refused"
            );
        }
        // An explicit `null` on the actor arm's required id is still a refusal.
        assert!(parse(json!({"kind": "actor", "actor_id": Value::Null})).is_err());
    }

    /// Both arms are strict: an unmodeled key — including the *other* arm's
    /// field — is a hard reject, never a silent drop.
    #[test]
    fn principal_rejects_unknown_fields_per_arm() {
        assert!(parse(json!({"kind": "actor", "actor_id": ACTOR_ID, "extra": 1})).is_err());
        assert!(parse(json!({"kind": "role", "role": "admin", "extra": 1})).is_err());
        // Cross-arm leakage: a role-shaped key on the actor arm and vice versa.
        assert!(parse(json!({"kind": "actor", "actor_id": ACTOR_ID, "role": "admin"})).is_err());
        assert!(parse(json!({"kind": "role", "role": "admin", "actor_id": ACTOR_ID})).is_err());
        // An explicit `null` is still the key being present — the shape a
        // reader most expects leniency on, and the one a client most easily
        // sends by serializing an absent optional. `scope_id` is modeled on
        // the role arm and nullable *there*; on the actor arm it is unknown,
        // and unknown-with-a-null-value rejects exactly like a valued one.
        assert!(
            parse(json!({"kind": "actor", "actor_id": ACTOR_ID, "scope_id": Value::Null})).is_err()
        );
        assert!(parse(json!({"kind": "role", "role": "admin", "extra": Value::Null})).is_err());
        // The discriminant itself stays closed.
        assert!(parse(json!({"kind": "nobody", "actor_id": ACTOR_ID})).is_err());
        assert!(parse(json!({"actor_id": ACTOR_ID})).is_err());
    }

    /// The role arm's `role` is a role name, as the twin's `RoleName` is: a
    /// string off the shared name grammar, or past `NAME_LENGTH_MAX`, is
    /// refused at decode; a name on it decodes whether or not it is
    /// registered, which the handler checks.
    #[test]
    fn principal_role_takes_only_the_name_grammar() {
        let too_long = "a".repeat(fuz_auth::NAME_LENGTH_MAX + 1);
        for bad in [
            "",
            "Admin",
            "a_",
            "_a",
            "a__b",
            "a1",
            "GLOBAL",
            "a b",
            too_long.as_str(),
        ] {
            assert!(
                parse(json!({"kind": "role", "role": bad})).is_err(),
                "role {bad:?} must be refused"
            );
        }
        assert!(parse(json!({"kind": "role", "role": 1})).is_err());
        let at_max = "a".repeat(fuz_auth::NAME_LENGTH_MAX);
        for good in ["nobody", "teaching_assistant", at_max.as_str()] {
            assert!(
                matches!(
                    parse(json!({"kind": "role", "role": good})),
                    Ok(CellGrantPrincipalInput::Role { .. })
                ),
                "role {good:?} must decode"
            );
        }
    }

    /// An off-grammar role reaches the wire as the twin's schema refusal
    /// does: `invalid_params` (-32602), the generic message, no `data`.
    #[test]
    fn an_off_grammar_role_is_invalid_params_with_no_reason() {
        let err = fuz_http::parse_strict_params::<super::CellGrantCreateInput>(json!({
            "cell_id": ACTOR_ID,
            "level": "viewer",
            "principal": {"kind": "role", "role": "Not_A_Role"},
        }))
        .unwrap_err();
        assert_eq!(err.code, fuz_http::JsonrpcErrorCode::InvalidParams);
        assert_eq!(err.message, fuz_http::INVALID_PARAMS_MESSAGE);
        assert!(err.data.is_none());
    }
}
