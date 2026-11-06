//! Account self-service action specs.
//!
//! Specs covering session management + API token CRUD, scoped to the
//! authenticated account. Mirrors `fuz_app`'s `auth/account_action_specs.ts`.
//!
//! ## Shape boundary
//!
//! The canonical `ActionSpec` shape lives in **`fuz_actions`**, which this
//! crate can't depend on. This module ships the entry rows (auth axes,
//! method names, rate classes) and the dispatcher ([`AccountActionSpecs`]);
//! `fuz_actions::auth_adapter` lifts them into `ActionSpec`s under the same
//! method names. The split is permanent.

use serde::Deserialize;

use serde_json::Value;

use crate::action_auth::AuthSpec;
use crate::action_rate_limit::RateLimitClass;
use crate::api_token::generate_api_token;
use crate::api_token_queries::{
    query_api_token_enforce_limit, query_api_token_list_for_account, query_create_api_token,
    query_revoke_api_token_for_account,
};
use crate::audit_emitter::{AuditLogInput, AuditOutcome, credential_type_value};
use crate::audit_event_type::AuditEventType;
use crate::auth_action_context::AccountActionContext;
use crate::auth_action_entry::AuthActionEntry;
use crate::connection_closer::ConnectionCloseTarget;
use crate::credential_type::CredentialGate;
use crate::params_helpers::require_text_len;
use crate::session_queries::{
    query_session_list_for_account, query_session_revoke_all_for_account,
    query_session_revoke_for_account,
};
use crate::token_scope::{RawTokenScopeInput, TokenScopeDocument};
use fuz_http::{
    InputShape, JsonrpcError, as_integral_i64, internal_error, internal_error_with_source,
    invalid_input_params, invalid_params, method_not_found, parse_optional_str_param,
    parse_str_param, reject_null_keys, reject_unknown_keys, serialize_result,
};

/// Max API tokens per account before the oldest are evicted on create.
/// Matches `fuz_app`'s `DEFAULT_MAX_TOKENS`.
pub const DEFAULT_MAX_TOKENS: i64 = 10;

/// `data.reason` on every `account_token_create` scope-param rejection —
/// one discriminator so a client can branch on "the scope you sent is
/// unusable" without string-matching the detail message.
pub const ERROR_TOKEN_SCOPE_INVALID: &str = "token_scope_invalid";

/// `data.reason` on every `account_token_create` lifetime-param rejection —
/// the temporal sibling of [`ERROR_TOKEN_SCOPE_INVALID`].
pub const ERROR_TOKEN_LIFETIME_INVALID: &str = "token_lifetime_invalid";

/// Upper bound on `lifetime.days` — a sanity cap (100 years), not a policy
/// ceiling. Matches `fuz_app`'s `TOKEN_TTL_DAYS_MAX` so out-of-range
/// requests 400 identically on both spines.
pub const TOKEN_TTL_DAYS_MAX: i64 = 36_500;

/// Dispatcher for the account self-service specs.
///
/// The entry rows are [`ACCOUNT_ACTION_ENTRIES`] — each an
/// [`crate::AuthActionEntry`] (`{method, auth, side_effects, rate_limit}`) —
/// and the dispatch arm is [`AccountActionSpecs::dispatch`];
/// `fuz_actions::auth_adapter` lifts both into `ActionSpec`s (see the module
/// doc for why the split is permanent).
#[derive(Debug, Clone, Copy, Default)]
pub struct AccountActionSpecs;

/// Account action registry — every self-service method, in registration
/// order. Static so callers can compare entries by reference if needed.
pub static ACCOUNT_ACTION_ENTRIES: &[AuthActionEntry] = &[
    AuthActionEntry {
        method: "account_verify",
        auth: AuthSpec::account_grain(CredentialGate::Any),
        input: InputShape::Void,
        side_effects: false,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "account_session_list",
        auth: AuthSpec::account_grain(CredentialGate::Any),
        input: InputShape::Void,
        side_effects: false,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "account_token_list",
        auth: AuthSpec::account_grain(CredentialGate::Any),
        input: InputShape::Void,
        side_effects: false,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "account_session_revoke",
        auth: AuthSpec::account_grain(CredentialGate::SESSION_ONLY),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "account_session_revoke_all",
        auth: AuthSpec::account_grain(CredentialGate::SESSION_ONLY),
        input: InputShape::Void,
        side_effects: true,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "account_token_create",
        auth: AuthSpec::account_grain(CredentialGate::SESSION_ONLY),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "account_token_revoke",
        auth: AuthSpec::account_grain(CredentialGate::SESSION_ONLY),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: None,
    },
];

impl AccountActionSpecs {
    /// Dispatch an account action by method name.
    ///
    /// The dispatcher routes here after auth + transaction
    /// wrap. Returns the result `Value` (JSON-RPC `result` field) or a
    /// typed error.
    ///
    /// The four parameterless methods — `account_verify`,
    /// `account_session_list`, `account_session_revoke_all`,
    /// `account_token_list` — never read `params`: their TS twins declare
    /// `fuz_schema`'s `void`, so their entries declare [`fuz_http::InputShape::Void`] and
    /// the dispatcher refuses every shape but the no-arg call before routing
    /// here.
    ///
    /// # Errors
    ///
    /// Returns a [`JsonrpcError`] on validation failure, DB error, or
    /// serialization failure.
    pub async fn dispatch(
        method: &str,
        params: &Value,
        ctx: &AccountActionContext<'_>,
        db: &(impl deadpool_postgres::GenericClient + ?Sized),
    ) -> Result<Value, JsonrpcError> {
        match method {
            "account_verify" => handle_account_verify(ctx, db).await,
            "account_session_list" => handle_account_session_list(ctx, db).await,
            "account_session_revoke" => handle_account_session_revoke(params, ctx, db).await,
            "account_session_revoke_all" => handle_account_session_revoke_all(ctx, db).await,
            "account_token_create" => handle_account_token_create(params, ctx, db).await,
            "account_token_list" => handle_account_token_list(ctx, db).await,
            "account_token_revoke" => handle_account_token_revoke(params, ctx, db).await,
            _ => Err(method_not_found(method)),
        }
    }
}

// -- Handlers --------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
struct AccountVerifyResult {
    id: String,
    username: String,
    email: Option<String>,
    email_verified: bool,
    created_at: String,
}

#[derive(Debug, serde::Serialize)]
struct AccountSessionInfo {
    id: String,
    account_id: String,
    created_at: String,
    expires_at: String,
    /// Whether this is the session the request authenticated with — no column
    /// holds it, so it is computed per request.
    is_current: bool,
}

#[derive(Debug, serde::Serialize)]
struct AccountSessionListResult {
    sessions: Vec<AccountSessionInfo>,
}

#[derive(Debug, serde::Serialize)]
struct AccountRevokeResult {
    ok: bool,
    revoked: bool,
}

#[derive(Debug, serde::Serialize)]
struct AccountSessionRevokeAllResult {
    ok: bool,
    count: u64,
}

#[derive(serde::Serialize)]
struct AccountTokenCreateResult {
    ok: bool,
    token: String,
    id: String,
    name: String,
    /// ISO 8601 expiry, or `null` for an eternal token. Mirrors the TS
    /// `TokenCreateOutput.expires_at` (strict output — the field must be
    /// present-as-null, never omitted).
    expires_at: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct ApiTokenInfo {
    id: String,
    account_id: String,
    name: String,
    expires_at: Option<String>,
    last_used_at: Option<String>,
    last_used_ip: Option<String>,
    created_at: String,
    /// Human-readable scope label (`full` / `full (grandfathered)` /
    /// `N methods`), matching the TS `ClientApiTokenJson.scope`. A label
    /// rather than the document: nothing authorizes off this list, and the
    /// operator reading it needs to tell a grandfathered token from a
    /// deliberately-full one at a glance.
    scope: String,
}

#[derive(Debug, serde::Serialize)]
struct AccountTokenListResult {
    tokens: Vec<ApiTokenInfo>,
}

async fn handle_account_verify(
    ctx: &AccountActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let account_id = ctx.auth.account.id;

    let summary = crate::account_queries::query_account_summary(db, &account_id)
        .await
        .map_err(|e| internal_error_with_source("verify query failed", &e))?
        .ok_or_else(|| internal_error("account not found"))?;

    let result = AccountVerifyResult {
        id: summary.id.to_string(),
        username: summary.username,
        email: summary.email,
        email_verified: summary.email_verified,
        created_at: summary.created_at,
    };
    serialize_result(result)
}

async fn handle_account_session_list(
    ctx: &AccountActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let account_id = ctx.auth.account.id;

    let rows = query_session_list_for_account(db, &account_id)
        .await
        .map_err(|e| internal_error_with_source("session list query failed", &e))?;

    let account_id_str = account_id.to_string();
    let sessions: Vec<AccountSessionInfo> = rows
        .into_iter()
        .map(|r| AccountSessionInfo {
            is_current: ctx.session_hash == Some(r.id.as_str()),
            id: r.id,
            account_id: account_id_str.clone(),
            created_at: r.created_at,
            expires_at: r.expires_at,
        })
        .collect();

    serialize_result(AccountSessionListResult { sessions })
}

/// Declared input keys per method, each the exact key set of the TS twin's
/// strict `fuz_schema` `object` in `auth/account_action_specs.ts`.
///
/// None of them declares `acting`: every spec in this family is `actor:
/// 'none'`, so under the twin's biconditional a well-formed selector is an
/// unrecognized key here. The four `void` methods carry no list at all —
/// their entries declare [`fuz_http::InputShape::Void`], so the dispatcher
/// refuses any declared key outright.
mod keys {
    /// `account_session_revoke`.
    pub const SESSION_REVOKE: &[&str] = &["session_id"];
    /// `account_token_create`.
    pub const TOKEN_CREATE: &[&str] = &["name", "scope", "lifetime"];
    /// `account_token_revoke`.
    pub const TOKEN_REVOKE: &[&str] = &["token_id"];

    /// `account_token_create.name` is `with_default(bounded_string(..), 'CLI
    /// token')` — a default fills an **absent** key only, so an explicit `null`
    /// is refused rather than defaulted.
    pub const TOKEN_CREATE_NON_NULLABLE: &[&str] = &["name"];
}

async fn handle_account_session_revoke(
    params: &Value,
    ctx: &AccountActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::SESSION_REVOKE)?;
    let account_id = ctx.auth.account.id;
    let session_id = parse_str_param(params, "session_id")?;
    // The `SessionId` grammar, ahead of the lookup — same rule as
    // `account_token_revoke`'s `token_id` below: the twin declares the field
    // as a branded blake3 digest, so an off-grammar id is `invalid_params`
    // there and must not be a success envelope here.
    if !crate::is_valid_session_id(session_id) {
        return Err(invalid_input_params(
            "'session_id' is not a valid session id",
            None,
        ));
    }

    let deleted = query_session_revoke_for_account(db, session_id, &account_id)
        .await
        .map_err(|e| internal_error_with_source("session revoke query failed", &e))?;

    if deleted {
        ctx.close_connections_after_commit(ConnectionCloseTarget::Session(session_id.to_owned()));
    }

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::SessionRevoke)
            .outcome(if deleted {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            })
            .account(account_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "session_id": session_id,
                "credential_type": credential_type_value(ctx.credential_type),
            })),
    )
    .await?;

    serialize_result(AccountRevokeResult {
        ok: true,
        revoked: deleted,
    })
}

async fn handle_account_session_revoke_all(
    ctx: &AccountActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let account_id = ctx.auth.account.id;

    let deleted_count = query_session_revoke_all_for_account(db, &account_id)
        .await
        .map_err(|e| internal_error_with_source("session revoke_all query failed", &e))?;

    ctx.close_connections_after_commit(ConnectionCloseTarget::Account(account_id));

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::SessionRevokeAll)
            .account(account_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "count": deleted_count,
                "credential_type": credential_type_value(ctx.credential_type),
            })),
    )
    .await?;

    serialize_result(AccountSessionRevokeAllResult {
        ok: true,
        count: deleted_count,
    })
}

/// Parse the required `scope` param of `account_token_create`.
///
/// Wire shape mirrors the stored document minus its row-owned fields —
/// `{"kind":"full"}` or `{"kind":"methods","methods":[…]}` — decoded strictly
/// through [`RawTokenScopeInput`]: an unknown key is refused, `version` and
/// `grandfathered` included (the constructors stamp the first; the second is
/// the migration's mark for tokens that predate scoping, and letting a caller
/// forge it would turn a tracked debt into a laundered one), as are a
/// `methods` on `kind: "full"` and a `null` `methods`. Twin of the TS
/// `TokenScopeInput`; duplicate method names collapse into one on both.
///
/// Method names are **not** validated against the live registry — `fuz_auth`
/// sits below `fuz_actions` in the crate graph and cannot see the
/// `ActionRegistry`. A typo mints a token that silently calls nothing; accepted
/// rather than papered over with a dependency inversion.
fn parse_token_scope_param(params: &Value) -> Result<TokenScopeDocument, JsonrpcError> {
    let invalid = |message: &str| invalid_input_params(message, Some(ERROR_TOKEN_SCOPE_INVALID));
    let scope = params
        .get("scope")
        .ok_or_else(|| invalid("scope is required"))?;
    let input = RawTokenScopeInput::deserialize(scope)
        .map_err(|e| invalid(&format!("invalid scope: {e}")))?;
    input
        .into_document()
        .map_err(|e| invalid(&format!("invalid scope: {e}")))
}

/// Parse the **required** `lifetime` param of `account_token_create`:
/// `{kind: "eternal"}` → `None`, `{kind: "ttl", days: N}` → `Some(days)`
/// with `1 ≤ days ≤ TOKEN_TTL_DAYS_MAX`.
///
/// There is deliberately no default — an omitted lifetime is a 400, never an
/// eternal token, so `expires_at IS NULL` always records a deliberate choice.
/// Unknown keys on the lifetime object are rejected, twinning the TS
/// `TokenLifetimeInput`, a `variant` of strict `object` arms, exactly (the
/// manifest parity gate is blind to param schemas, so this parser is the only
/// thing holding the two spines to the same input shape). `pub` so
/// `fuz_forge_server`'s inlined mint parses the identical shape instead of
/// growing a drifting copy.
///
/// # Errors
///
/// Returns `invalid_params` with reason [`ERROR_TOKEN_LIFETIME_INVALID`] on a
/// missing/malformed `lifetime`, an unknown `kind`, an unknown key, or
/// out-of-range `days`.
pub fn parse_token_lifetime_param(params: &Value) -> Result<Option<u32>, JsonrpcError> {
    let invalid = |message: &str| invalid_input_params(message, Some(ERROR_TOKEN_LIFETIME_INVALID));
    let lifetime = params
        .get("lifetime")
        .ok_or_else(|| invalid("lifetime is required"))?;
    let obj = lifetime
        .as_object()
        .ok_or_else(|| invalid("lifetime must be an object"))?;
    let kind = obj
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("lifetime.kind is required"))?;
    match kind {
        "eternal" => {
            if obj.keys().any(|k| k != "kind") {
                return Err(invalid("unknown key on lifetime"));
            }
            Ok(None)
        }
        "ttl" => {
            if obj.keys().any(|k| k != "kind" && k != "days") {
                return Err(invalid("unknown key on lifetime"));
            }
            let days_value = obj
                .get("days")
                .ok_or_else(|| invalid("lifetime.days is required for kind \"ttl\""))?;
            // any JSON number with an integral value — `5.0` and `1e2` pass
            // TS's `integer`
            let Some(days) = as_integral_i64(days_value) else {
                return Err(invalid("lifetime.days must be an integer"));
            };
            if !(1..=TOKEN_TTL_DAYS_MAX).contains(&days) {
                return Err(invalid(&format!(
                    "lifetime.days must be between 1 and {TOKEN_TTL_DAYS_MAX}"
                )));
            }
            // Cast is safe: bounded by TOKEN_TTL_DAYS_MAX above.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Ok(Some(days as u32))
        }
        other => Err(invalid(&format!("unknown lifetime.kind {other:?}"))),
    }
}

/// Max length of `account_token_create`'s `name`, in UTF-16 code units.
///
/// The name is copied into the `token_create` audit row, so it is bounded
/// where it enters. Mirrors the TS `API_TOKEN_NAME_LENGTH_MAX`.
pub const API_TOKEN_NAME_LENGTH_MAX: usize = 255;

/// Parse `account_token_create`'s `name`: the default when the key is absent,
/// else a string of at most [`API_TOKEN_NAME_LENGTH_MAX`] UTF-16 code units
/// (twin of `with_default(bounded_string({max}), 'CLI token')`).
fn parse_token_name_param(params: &Value) -> Result<String, JsonrpcError> {
    let Some(name) = parse_optional_str_param(params, "name")? else {
        return Ok("CLI token".to_owned());
    };
    require_text_len(name, API_TOKEN_NAME_LENGTH_MAX, "name")?;
    Ok(name.to_owned())
}

async fn handle_account_token_create(
    params: &Value,
    ctx: &AccountActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::TOKEN_CREATE)?;
    reject_null_keys(params, keys::TOKEN_CREATE_NON_NULLABLE)?;
    let account_id = ctx.auth.account.id;

    let name = parse_token_name_param(params)?;

    // `scope` is **required** — default-deny at mint. There is deliberately no
    // permissive fallback: an omitted scope is a 400, not a full-authority
    // token: a scope field nothing depends on is a false promise. A caller who
    // wants full authority says so, and the resulting document records that
    // they did.
    let scope_doc = parse_token_scope_param(params)?;
    let scope_json = scope_doc.to_json().map_err(|e| {
        invalid_params(
            &format!("invalid scope: {e}"),
            Some(ERROR_TOKEN_SCOPE_INVALID),
        )
    })?;

    // `lifetime` is required for the same reason `scope` is — an omitted
    // lifetime is a 400, never an eternal token.
    let ttl_days = parse_token_lifetime_param(params)?;
    let expires_at = ttl_days.map(|days| {
        std::time::SystemTime::now() + std::time::Duration::from_secs(u64::from(days) * 86_400)
    });

    let generated = generate_api_token();

    let minted = query_create_api_token(
        db,
        &generated.id,
        &account_id,
        &name,
        &generated.token_hash,
        &scope_json,
        expires_at,
    )
    .await
    .map_err(|e| internal_error_with_source("token create query failed", &e))?;

    let evicted = query_api_token_enforce_limit(db, &account_id, DEFAULT_MAX_TOKENS)
        .await
        .map_err(|e| internal_error_with_source("token enforce_limit query failed", &e))?;
    // The cap deleted the evicted rows; their connections end only when closed,
    // and only after the commit — the same post-commit close the revocations use.
    // No audit row: fuz_app's event registry has no eviction event, and `token_create`
    // records the mint that caused it.
    for token_id in evicted {
        ctx.close_connections_after_commit(ConnectionCloseTarget::Token(token_id));
    }

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::TokenCreate)
            .account(account_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "token_id": generated.id,
                "name": name,
                "credential_type": credential_type_value(ctx.credential_type),
            })),
    )
    .await?;

    serialize_result(AccountTokenCreateResult {
        ok: true,
        token: generated.token,
        id: generated.id,
        name,
        expires_at: minted.expires_at,
    })
}

async fn handle_account_token_list(
    ctx: &AccountActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let account_id = ctx.auth.account.id;

    let rows = query_api_token_list_for_account(db, &account_id)
        .await
        .map_err(|e| internal_error_with_source("token list query failed", &e))?;

    let tokens: Vec<ApiTokenInfo> = rows
        .into_iter()
        .map(|r| ApiTokenInfo {
            id: r.id,
            account_id: r.account_id.to_string(),
            name: r.name,
            expires_at: r.expires_at,
            last_used_at: r.last_used_at,
            last_used_ip: r.last_used_ip,
            created_at: r.created_at,
            scope: r.scope,
        })
        .collect();

    serialize_result(AccountTokenListResult { tokens })
}

async fn handle_account_token_revoke(
    params: &Value,
    ctx: &AccountActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::TOKEN_REVOKE)?;
    let account_id = ctx.auth.account.id;
    let token_id = parse_str_param(params, "token_id")?;
    // The `ApiTokenId` grammar, ahead of the lookup — the twin declares
    // `token_id` with the `ApiTokenId` grammar, so an off-grammar id is
    // `invalid_params` there and must not be a `{ok: true, revoked: false}`
    // success envelope here.
    if !crate::is_valid_token_id(token_id) {
        return Err(invalid_input_params(
            "'token_id' is not a valid api token id",
            None,
        ));
    }

    let deleted = query_revoke_api_token_for_account(db, token_id, &account_id)
        .await
        .map_err(|e| internal_error_with_source("token revoke query failed", &e))?;

    if deleted {
        ctx.close_connections_after_commit(ConnectionCloseTarget::Token(token_id.to_owned()));
    }

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::TokenRevoke)
            .outcome(if deleted {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            })
            .account(account_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "token_id": token_id,
                "credential_type": credential_type_value(ctx.credential_type),
            })),
    )
    .await?;

    serialize_result(AccountRevokeResult {
        ok: true,
        revoked: deleted,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ACCOUNT_ACTION_ENTRIES, API_TOKEN_NAME_LENGTH_MAX, CredentialGate,
        ERROR_TOKEN_SCOPE_INVALID, keys, parse_token_lifetime_param, parse_token_name_param,
        parse_token_scope_param, reject_null_keys, reject_unknown_keys,
    };
    use crate::token_scope::TokenScope;
    use fuz_http::JsonrpcErrorCode;
    use serde_json::{Value, json};

    const ACTOR: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";

    /// Every method that declares a shape, with its key list. The four
    /// `void` methods are absent — the dispatcher's void rule refuses any
    /// declared key before a key list could apply.
    const KEY_TABLE: &[(&str, &[&str])] = &[
        ("account_session_revoke", keys::SESSION_REVOKE),
        ("account_token_create", keys::TOKEN_CREATE),
        ("account_token_revoke", keys::TOKEN_REVOKE),
    ];

    /// Every account spec is `actor: 'none'`, so no twin input declares
    /// `acting` and a well-formed selector is an unrecognized key.
    #[test]
    fn no_account_key_list_declares_acting() {
        for (method, allowed) in KEY_TABLE {
            let entry = ACCOUNT_ACTION_ENTRIES
                .iter()
                .find(|e| e.method == *method)
                .unwrap_or_else(|| panic!("{method} is not a registered method"));
            assert!(
                !entry.auth.needs_actor(),
                "{method}: the axis the absent key mirrors"
            );
            assert!(
                !allowed.contains(&"acting"),
                "{method}: no actor axis, so the twin declares no selector"
            );
            let error = reject_unknown_keys(&json!({"acting": ACTOR}), allowed)
                .expect_err(&format!("{method} must refuse the selector"));
            assert_eq!(error.code, JsonrpcErrorCode::InvalidParams, "{method}");
        }
    }

    #[test]
    fn every_account_key_list_refuses_a_stray_key() {
        for (method, allowed) in KEY_TABLE {
            let error = reject_unknown_keys(&json!({"nope": 1}), allowed)
                .expect_err(&format!("{method} must refuse an undeclared key"));
            assert_eq!(error.code, JsonrpcErrorCode::InvalidParams, "{method}");
        }
    }

    /// `account_token_create.name` is `with_default(bounded_string(..), ..)`,
    /// and a default fills an absent key only — so an explicit `null` is
    /// `-32602` on the twin rather than the default.
    #[test]
    fn the_token_name_default_does_not_swallow_a_null() {
        let error = reject_null_keys(
            &json!({"name": Value::Null}),
            keys::TOKEN_CREATE_NON_NULLABLE,
        )
        .expect_err("a null name must be refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
        assert!(reject_null_keys(&json!({}), keys::TOKEN_CREATE_NON_NULLABLE).is_ok());
    }

    /// `name` is capped at `API_TOKEN_NAME_LENGTH_MAX` UTF-16 code units — the
    /// twin's `bounded_string({max})` — and defaults only when absent.
    #[test]
    fn token_name_is_capped_in_utf16_units() {
        assert_eq!(API_TOKEN_NAME_LENGTH_MAX, 255);
        assert_eq!(parse_token_name_param(&json!({})).unwrap(), "CLI token");

        let at_max = "a".repeat(API_TOKEN_NAME_LENGTH_MAX);
        assert_eq!(
            parse_token_name_param(&json!({"name": at_max})).unwrap(),
            at_max
        );
        let error = parse_token_name_param(&json!({"name": format!("{at_max}a")}))
            .expect_err("a name one unit past the cap must be refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
        assert_eq!(error.message, fuz_http::INVALID_PARAMS_MESSAGE);
        assert!(error.data.is_none(), "the refusal carries no reason");

        // An astral-plane character costs two units, as `String.length` counts.
        let astral_at_max = format!(
            "{}a",
            "\u{1F600}".repeat((API_TOKEN_NAME_LENGTH_MAX - 1) / 2)
        );
        assert_eq!(
            astral_at_max.encode_utf16().count(),
            API_TOKEN_NAME_LENGTH_MAX
        );
        assert!(parse_token_name_param(&json!({"name": astral_at_max})).is_ok());
        let astral_over = "\u{1F600}".repeat(API_TOKEN_NAME_LENGTH_MAX.div_ceil(2));
        assert_eq!(
            astral_over.encode_utf16().count(),
            API_TOKEN_NAME_LENGTH_MAX + 1
        );
        assert!(parse_token_name_param(&json!({"name": astral_over})).is_err());
    }

    /// The lifetime parser twins the TS `TokenLifetimeInput` strict union —
    /// pinned shape by shape so the two spines can't drift on what a valid
    /// `lifetime` is (the manifest parity gate is blind to param schemas).
    #[test]
    fn token_lifetime_parses_the_strict_union() {
        // eternal → None
        assert_eq!(
            parse_token_lifetime_param(&json!({"lifetime": {"kind": "eternal"}})).unwrap(),
            None
        );
        // ttl → Some(days)
        assert_eq!(
            parse_token_lifetime_param(&json!({"lifetime": {"kind": "ttl", "days": 30}})).unwrap(),
            Some(30)
        );
        // TS `integer` accepts integral floats — so does this parser
        assert_eq!(
            parse_token_lifetime_param(&json!({"lifetime": {"kind": "ttl", "days": 30.0}}))
                .unwrap(),
            Some(30)
        );
    }

    #[test]
    fn token_lifetime_rejections_match_the_ts_strict_object() {
        let rejected = [
            json!({}),                                                 // missing
            json!({"lifetime": null}),                                 // wrong type
            json!({"lifetime": "eternal"}),                            // not an object
            json!({"lifetime": {}}),                                   // no kind
            json!({"lifetime": {"kind": "forever"}}),                  // unknown kind
            json!({"lifetime": {"kind": "eternal", "days": 5}}),       // strict: unknown key
            json!({"lifetime": {"kind": "ttl"}}),                      // no days
            json!({"lifetime": {"kind": "ttl", "days": 0}}),           // below min
            json!({"lifetime": {"kind": "ttl", "days": 36_501}}),      // above max
            json!({"lifetime": {"kind": "ttl", "days": 5.5}}),         // non-integer
            json!({"lifetime": {"kind": "ttl", "days": "30"}}),        // string
            json!({"lifetime": {"kind": "ttl", "days": 1, "and": 2}}), // strict: unknown key
        ];
        for params in rejected {
            assert!(
                parse_token_lifetime_param(&params).is_err(),
                "must reject {params}"
            );
        }
    }

    /// The anti-pivot boundary: a leaked API token can *enumerate* an
    /// account's sessions and tokens but cannot mint another token, revoke
    /// one, or kill a session.
    ///
    /// Pinned as an exact partition rather than a spot-check, so widening a
    /// mutation to the bearer channel — or adding a mutation that forgets the
    /// gate — fails here instead of shipping silently. Twinned with
    /// `fuz_app`'s `account_action_specs.ts`, whose four
    /// `credential_types: ['session']` declarations carry the same property.
    #[test]
    fn credential_lifecycle_mutations_are_session_only() {
        let session_only: Vec<&str> = ACCOUNT_ACTION_ENTRIES
            .iter()
            .filter(|e| e.auth.credentials == CredentialGate::SESSION_ONLY)
            .map(|e| e.method)
            .collect();
        assert_eq!(
            session_only,
            [
                "account_session_revoke",
                "account_session_revoke_all",
                "account_token_create",
                "account_token_revoke",
            ],
        );
    }

    /// The complement: the three reads are deliberately reachable by any
    /// credential, and no account spec sits in some third state.
    #[test]
    fn account_reads_are_any_credential() {
        let any: Vec<&str> = ACCOUNT_ACTION_ENTRIES
            .iter()
            .filter(|e| e.auth.credentials.is_any())
            .map(|e| e.method)
            .collect();
        assert_eq!(
            any,
            [
                "account_verify",
                "account_session_list",
                "account_token_list"
            ],
        );
    }

    /// The mint decodes `scope` strictly, as the twin's `TokenScopeInput`
    /// does: each of these used to mint a token (a `full` one, for every
    /// `full`-kinded case), and each is now refused.
    #[test]
    fn token_scope_param_refuses_what_the_twin_refuses() {
        let refused = [
            json!({"kind": "full", "junk": 1}),
            json!({"kind": "full", "version": 1}),
            json!({"kind": "full", "version": 99}),
            json!({"kind": "full", "grandfathered": true}),
            json!({"kind": "full", "methods": ["cell_get"]}),
            json!({"kind": "full", "methods": null}),
            json!({"kind": "methods", "methods": null}),
            json!({"kind": "methods"}),
            json!({"kind": "methods", "methods": ["cell_get"], "version": 1}),
            json!({"kind": "methods", "methods": [1]}),
            json!({"kind": "methods", "methods": "cell_get"}),
            json!({"kind": "everything"}),
            json!({"kind": 1}),
            json!({}),
            json!(null),
            json!("full"),
        ];
        for scope in refused {
            let error = parse_token_scope_param(&json!({ "scope": scope }))
                .expect_err(&format!("{scope} must be refused"));
            assert_eq!(error.code, JsonrpcErrorCode::InvalidParams, "{scope}");
            assert_eq!(
                error.data,
                Some(json!({"reason": ERROR_TOKEN_SCOPE_INVALID})),
                "{scope}"
            );
        }
    }

    #[test]
    fn token_scope_param_accepts_the_two_arms_and_dedups_methods() {
        let full = parse_token_scope_param(&json!({"scope": {"kind": "full"}})).expect("full");
        assert_eq!(full.scope, TokenScope::Full);
        assert!(!full.grandfathered);
        let narrow = parse_token_scope_param(
            &json!({"scope": {"kind": "methods", "methods": ["cell_get", "cell_get", "cell_list"]}}),
        )
        .expect("methods");
        assert_eq!(narrow.label(), "2 methods");
        let none = parse_token_scope_param(&json!({"scope": {"kind": "methods", "methods": []}}))
            .expect("an empty set is legal");
        assert_eq!(none.label(), "0 methods");
    }
}
