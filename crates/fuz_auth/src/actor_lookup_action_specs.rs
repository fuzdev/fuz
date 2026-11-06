//! `actor_lookup` action spec — authenticated batched id → (username,
//! `display_name`) resolver, keyed by actor id.
//!
//! Mirrors `fuz_app`'s
//! `auth/actor_lookup_action_specs.ts` + `auth/actor_lookup_actions.ts`.
//!
//! Opt-in surface (not in the standard auth spec set) — the `spine_stub`
//! mounts it via `fuz_actions::auth_adapter::build_actor_lookup_specs`,
//! mirroring how TS keeps `create_actor_lookup_actions` out of
//! `create_standard_rpc_actions`. Account-grain (TS `actor: 'none'`): only
//! that the caller is authenticated matters, so dispatch needs no actor.
//!
//! Wire shape `{actors: [{id, username, display_name?}]}` deliberately omits
//! `account_id` / `email` / timestamps / role state — see the TS module's
//! info-leak audit. `display_name` is omitted (not `null`) when `actor.name`
//! is blank, matching the TS wire shape so clients see `undefined` rather
//! than a sentinel string. Unknown ids are silently absent (no tombstone
//! oracle), bounded by the per-account rate limit + [`ACTOR_LOOKUP_IDS_MAX`].
//!
//! The shape boundary mirrors `account_action_specs.rs`: the entry row and
//! [`ActorLookupActionSpecs`] carry the auth axis + method + handler, lifted
//! into a canonical `fuz_actions::ActionSpec` by the adapter.

use serde_json::Value;

use crate::action_auth::AuthSpec;
use crate::action_rate_limit::RateLimitClass;
use crate::actor_queries::{actor_summary_to_value, query_actors_by_ids};
use crate::auth_action_context::AccountActionContext;
use crate::auth_action_entry::AuthActionEntry;
use crate::credential_type::CredentialGate;
use fuz_http::{
    InputShape, JsonrpcError, internal_error_with_source, invalid_input_params, method_not_found,
    reject_unknown_keys,
};

/// Hard cap on ids resolvable in one call. Bounds the batched
/// username-enumeration surface. Matches TS `ACTOR_LOOKUP_IDS_MAX`.
pub const ACTOR_LOOKUP_IDS_MAX: usize = 50;

/// Auth + dispatch entry for `actor_lookup`. Account-grain authenticated
/// read; per-account rate-limited like the TS spec (`rate_limit: 'account'`).
pub static ACTOR_LOOKUP_ACTION_ENTRIES: &[AuthActionEntry] = &[AuthActionEntry {
    method: "actor_lookup",
    auth: AuthSpec::account_grain(CredentialGate::Any),
    input: InputShape::Object,
    side_effects: false,
    rate_limit: Some(RateLimitClass::Account),
}];

/// Dispatcher for the `actor_lookup` family; its entry rows are
/// [`ACTOR_LOOKUP_ACTION_ENTRIES`] (see `account_action_specs.rs` for the
/// boundary rationale).
#[derive(Debug)]
pub struct ActorLookupActionSpecs;

impl ActorLookupActionSpecs {
    /// Dispatch an actor-lookup action by method name.
    ///
    /// # Errors
    ///
    /// Returns a [`JsonrpcError`] on validation failure, DB error, or
    /// serialization failure.
    pub async fn dispatch(
        method: &str,
        params: &Value,
        _ctx: &AccountActionContext<'_>,
        db: &(impl deadpool_postgres::GenericClient + ?Sized),
    ) -> Result<Value, JsonrpcError> {
        match method {
            "actor_lookup" => handle_actor_lookup(params, db).await,
            _ => Err(method_not_found(method)),
        }
    }
}

async fn handle_actor_lookup(
    params: &Value,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let ids = parse_ids(params)?;
    let rows = query_actors_by_ids(db, &ids)
        .await
        .map_err(|e| internal_error_with_source("actor lookup query failed", &e))?;
    let actors: Vec<Value> = rows
        .into_iter()
        .map(|r| actor_summary_to_value(r.id, &r.username, &r.display_name))
        .collect();
    Ok(serde_json::json!({ "actors": actors }))
}

/// Declared input keys — the exact key set of the TS twin's
/// `ActorLookupInput`. No `acting`: the spec's actor axis is `none`.
const ACTOR_LOOKUP_KEYS: &[&str] = &["ids"];

/// Parse + validate the `{ids}` input. Mirrors the TS Zod bound
/// `array(Uuid).min(1).max(ACTOR_LOOKUP_IDS_MAX)`.
fn parse_ids(params: &Value) -> Result<Vec<uuid::Uuid>, JsonrpcError> {
    reject_unknown_keys(params, ACTOR_LOOKUP_KEYS)?;
    let arr = params
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_input_params("missing or invalid 'ids' parameter", None))?;
    if arr.is_empty() {
        return Err(invalid_input_params(
            "'ids' must contain at least one id",
            None,
        ));
    }
    if arr.len() > ACTOR_LOOKUP_IDS_MAX {
        return Err(invalid_input_params("'ids' exceeds the per-call cap", None));
    }
    arr.iter()
        .map(|v| {
            v.as_str()
                .filter(|s| fuz_http::is_valid_uuid(s))
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or_else(|| invalid_input_params("'ids' contains an invalid uuid", None))
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use fuz_http::JsonrpcErrorCode;
    use serde_json::json;

    use super::{ACTOR_LOOKUP_ACTION_ENTRIES, parse_ids};

    const ACTOR: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";

    /// The spec's actor axis is `none`, so the twin's `ActorLookupInput`
    /// declares only `ids` — a well-formed selector is an unrecognized key.
    #[test]
    fn actor_lookup_refuses_an_undeclared_acting_key() {
        assert!(
            !ACTOR_LOOKUP_ACTION_ENTRIES[0].auth.needs_actor(),
            "the axis the absent key mirrors"
        );
        let error = parse_ids(&json!({"ids": [ACTOR], "acting": ACTOR}))
            .expect_err("actor_lookup declares no `acting`");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
    }

    #[test]
    fn actor_lookup_refuses_an_unknown_key_and_takes_the_declared_shape() {
        let error = parse_ids(&json!({"ids": [ACTOR], "nope": 1}))
            .expect_err("an undeclared key must be refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);

        let ids = parse_ids(&json!({"ids": [ACTOR]})).expect("the declared shape must parse");
        assert_eq!(ids.len(), 1);
    }
}
