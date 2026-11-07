//! `actor_search` action spec — authenticated prefix search over `actor.name`.
//! Mirrors `fuz_app`'s `auth/actor_search_action_specs.ts` +
//! `auth/actor_search_actions.ts`.
//!
//! Opt-in surface (not in `build_auth_spec_set`) — the `spine_stub` mounts it
//! via `fuz_actions::auth_adapter::build_actor_search_specs`, mirroring TS
//! keeping `create_actor_search_actions` out of `create_standard_rpc_actions`.
//! Account-grain (TS `actor: 'none'`).
//!
//! ## Admin gate (empty `scope_ids`)
//!
//! Unbounded global search is admin-only. Non-admin callers must pass at least
//! one `scope_id` (results are then filtered to actors holding an active
//! `role_grant` on those scopes); omitting it is rejected with `invalid_params`
//! carrying [`ERROR_ACTOR_SEARCH_SCOPE_REQUIRED`]. The admin check is
//! account-grain — any **active** actor on the caller's account holding a
//! global `admin` `role_grant` — since the account-grain posture doesn't load
//! the caller's `role_grants` for an in-memory check. See §Authorization in
//! `fuz_app`'s `docs/security.md`.
//!
//! The shape boundary mirrors `account_action_specs.rs`.

use serde_json::Value;

use crate::action_auth::AuthSpec;
use crate::action_rate_limit::RateLimitClass;
use crate::actor_queries::{actor_summary_to_value, query_account_has_active_global_role};
use crate::actor_search_queries::query_actor_search;
use crate::auth_action_context::AccountActionContext;
use crate::auth_action_entry::AuthActionEntry;
use crate::credential_type::CredentialGate;
use crate::params_helpers::require_text_len;
use crate::role::ROLE_ADMIN;
use fuz_http::{
    InputShape, JsonrpcError, internal_error_with_source, invalid_input_params, invalid_params,
    method_not_found, parse_str_param, reject_null_keys, reject_unknown_keys,
};

/// Hard cap on rows returned per call. Matches TS `ACTOR_SEARCH_LIMIT_MAX`.
pub const ACTOR_SEARCH_LIMIT_MAX: i64 = 50;
/// Default row count when `limit` is omitted. Matches TS `ACTOR_SEARCH_LIMIT_DEFAULT`.
pub const ACTOR_SEARCH_LIMIT_DEFAULT: i64 = 20;
/// Max query length. Matches TS `ACTOR_SEARCH_QUERY_LENGTH_MAX`.
pub const ACTOR_SEARCH_QUERY_LENGTH_MAX: usize = 50;
/// Reason emitted when a non-admin caller omits `scope_ids`. Matches TS
/// `ERROR_ACTOR_SEARCH_SCOPE_REQUIRED`.
pub const ERROR_ACTOR_SEARCH_SCOPE_REQUIRED: &str = "actor_search_scope_required";

/// Auth + dispatch entry for `actor_search`. Account-grain authenticated read;
/// per-account rate-limited like the TS spec (`rate_limit: 'account'`).
pub static ACTOR_SEARCH_ACTION_ENTRIES: &[AuthActionEntry] = &[AuthActionEntry {
    method: "actor_search",
    auth: AuthSpec::account_grain(CredentialGate::Any),
    input: InputShape::Object,
    side_effects: false,
    rate_limit: Some(RateLimitClass::Account),
}];

/// Dispatcher for the `actor_search` family; its entry rows are
/// [`ACTOR_SEARCH_ACTION_ENTRIES`] (see `account_action_specs.rs` for the
/// boundary rationale).
#[derive(Debug)]
pub struct ActorSearchActionSpecs;

impl ActorSearchActionSpecs {
    /// Dispatch an actor-search action by method name.
    ///
    /// # Errors
    ///
    /// Returns a [`JsonrpcError`] on validation failure, the admin-gate
    /// rejection, DB error, or serialization failure.
    pub async fn dispatch(
        method: &str,
        params: &Value,
        ctx: &AccountActionContext<'_>,
        db: &(impl deadpool_postgres::GenericClient + ?Sized),
    ) -> Result<Value, JsonrpcError> {
        match method {
            "actor_search" => handle_actor_search(params, ctx, db).await,
            _ => Err(method_not_found(method)),
        }
    }
}

async fn handle_actor_search(
    params: &Value,
    ctx: &AccountActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let input = parse_search_input(params)?;

    if input.scope_ids.is_empty() {
        // Unbounded global search is admin-only. Account-grain admin check —
        // any *active* actor on the caller's account holds the global `admin`
        // grant. The tombstone-aware query is what every admission gate reads:
        // soft-delete leaves `role_grant` rows intact (undelete restores them),
        // so the blind sibling would admit an account whose only admin grant
        // hangs off a tombstoned actor.
        let is_admin = query_account_has_active_global_role(db, &ctx.auth.account.id, ROLE_ADMIN)
            .await
            .map_err(|e| internal_error_with_source("admin role check failed", &e))?;
        if !is_admin {
            return Err(invalid_params(
                "scope_ids required for non-admin callers",
                Some(ERROR_ACTOR_SEARCH_SCOPE_REQUIRED),
            ));
        }
    }

    let rows = query_actor_search(db, &input.query, &input.scope_ids, input.limit)
        .await
        .map_err(|e| internal_error_with_source("actor search query failed", &e))?;
    let actors: Vec<Value> = rows
        .into_iter()
        .map(|r| actor_summary_to_value(r.id, &r.username, &r.display_name))
        .collect();
    Ok(serde_json::json!({ "actors": actors }))
}

/// Parsed + validated `actor_search` input. Mirrors the TS schema's bounds
/// (`query` 1..=50, `scope_ids` optional uuid array, `limit` 1..=50).
#[derive(Debug)]
struct SearchInput {
    query: String,
    scope_ids: Vec<uuid::Uuid>,
    limit: i64,
}

/// Declared input keys — the exact key set of the TS twin's
/// `ActorSearchInput`. No `acting`: the spec's actor axis is `none`, so the
/// twin declares no selector and a well-formed one is an unrecognized key.
const ACTOR_SEARCH_KEYS: &[&str] = &["query", "scope_ids", "limit"];

/// `scope_ids` and `limit` are `optional(...)` on the twin — not
/// `optional(nullable(...))` — so an explicit `null` is refused rather than read as absent.
const ACTOR_SEARCH_NON_NULLABLE: &[&str] = &["scope_ids", "limit"];

fn parse_search_input(params: &Value) -> Result<SearchInput, JsonrpcError> {
    reject_unknown_keys(params, ACTOR_SEARCH_KEYS)?;
    reject_null_keys(params, ACTOR_SEARCH_NON_NULLABLE)?;
    let query = parse_str_param(params, "query")?;
    if query.is_empty() {
        return Err(invalid_input_params("'query' must be non-empty", None));
    }
    require_text_len(query, ACTOR_SEARCH_QUERY_LENGTH_MAX, "query")?;

    let scope_ids = match params.get("scope_ids") {
        None => Vec::new(),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_str()
                    .filter(|s| fuz_http::is_valid_uuid(s))
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    .ok_or_else(|| {
                        invalid_input_params("'scope_ids' contains an invalid uuid", None)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(invalid_input_params("'scope_ids' must be an array", None)),
    };

    let limit = match params.get("limit") {
        None => ACTOR_SEARCH_LIMIT_DEFAULT,
        Some(v) => {
            // any integral spelling (`5.0`, `1e1`), as the twin's `int()`;
            // the `1..=50` bound below is inside the safe range
            let n = fuz_http::as_integral_i64(v)
                .ok_or_else(|| invalid_input_params("'limit' must be an integer", None))?;
            if !(1..=ACTOR_SEARCH_LIMIT_MAX).contains(&n) {
                return Err(invalid_input_params("'limit' out of range", None));
            }
            n
        }
    };

    Ok(SearchInput {
        query: query.to_owned(),
        scope_ids,
        limit,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use fuz_http::JsonrpcErrorCode;
    use serde_json::{Value, json};

    use super::{
        ACTOR_SEARCH_ACTION_ENTRIES, ACTOR_SEARCH_LIMIT_DEFAULT, ACTOR_SEARCH_QUERY_LENGTH_MAX,
        parse_search_input,
    };

    const SCOPE: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";

    /// The spec's actor axis is `none`, so the twin's `ActorSearchInput`
    /// declares no `acting` — a well-formed selector is an unrecognized key.
    #[test]
    fn actor_search_refuses_an_undeclared_acting_key() {
        assert!(
            !ACTOR_SEARCH_ACTION_ENTRIES[0].auth.needs_actor(),
            "the axis the absent key mirrors"
        );
        let error = parse_search_input(&json!({"query": "ab", "acting": SCOPE}))
            .expect_err("actor_search declares no `acting`");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
    }

    /// `query` is the twin's `bounded_string({min: 1, max: 50})`: exactly the bound
    /// passes, one unit past it is refused in the spine's shared words, and
    /// the units are UTF-16 — an astral-plane character costs two.
    #[test]
    fn actor_search_bounds_the_query_in_utf16_units() {
        let max = ACTOR_SEARCH_QUERY_LENGTH_MAX;
        let at_max = parse_search_input(&json!({"query": "a".repeat(max), "scope_ids": [SCOPE]}))
            .expect("a query of exactly the bound is taken");
        assert_eq!(at_max.query.len(), max);

        let error = parse_search_input(&json!({"query": "a".repeat(max + 1)}))
            .expect_err("one past the bound is refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE);
        assert_eq!(error.data, None);

        // U+1F600 is one `char` and two UTF-16 units.
        let astral_at_max = "\u{1F600}".repeat(max / 2);
        assert!(parse_search_input(&json!({"query": astral_at_max})).is_ok());
        let astral_over = "\u{1F600}".repeat(max / 2 + 1);
        assert!(
            astral_over.chars().count() < max,
            "under the bound in chars"
        );
        let error = parse_search_input(&json!({"query": astral_over}))
            .expect_err("over the bound in UTF-16 units");
        assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE);

        let error = parse_search_input(&json!({"query": ""})).expect_err("an empty query");
        assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE);
    }

    #[test]
    fn actor_search_refuses_an_unknown_key() {
        let error = parse_search_input(&json!({"query": "ab", "nope": 1}))
            .expect_err("an undeclared key must be refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
    }

    /// `scope_ids` and `limit` are `optional(...)` on the twin — not
    /// `optional(nullable(...))` — so an explicit `null` is refused rather than read as
    /// "no filter" / "the default".
    #[test]
    fn actor_search_refuses_a_null_on_an_optional_key() {
        for params in [
            json!({"query": "ab", "scope_ids": Value::Null}),
            json!({"query": "ab", "limit": Value::Null}),
        ] {
            let error =
                parse_search_input(&params).expect_err(&format!("{params} must be refused"));
            assert_eq!(
                error.code,
                JsonrpcErrorCode::InvalidParams,
                "params: {params}"
            );
        }
    }

    #[test]
    fn actor_search_takes_the_declared_shape() {
        let input = parse_search_input(&json!({"query": "ab", "scope_ids": [SCOPE], "limit": 5}))
            .expect("the declared shape must parse");
        assert_eq!(input.query, "ab");
        assert_eq!(input.scope_ids.len(), 1);
        assert_eq!(input.limit, 5);

        let defaults = parse_search_input(&json!({"query": "ab"})).expect("absent optionals");
        assert!(defaults.scope_ids.is_empty());
        assert_eq!(defaults.limit, ACTOR_SEARCH_LIMIT_DEFAULT);
    }

    /// `limit` is `pipe(number, integer, ...)` on the twin: any integral spelling.
    #[test]
    fn actor_search_reads_an_integral_float_limit() {
        for (text, expected) in [("5.0", 5), ("1e1", 10)] {
            let params: Value =
                serde_json::from_str(&format!(r#"{{"query":"ab","limit":{text}}}"#)).unwrap();
            let input = parse_search_input(&params).expect("an integral limit");
            assert_eq!(input.limit, expected, "{text}");
        }
        for text in ["5.5", "-0", "51.0"] {
            let params: Value =
                serde_json::from_str(&format!(r#"{{"query":"ab","limit":{text}}}"#)).unwrap();
            assert!(parse_search_input(&params).is_err(), "{text}");
        }
    }
}
