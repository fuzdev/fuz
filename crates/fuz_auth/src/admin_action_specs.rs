//! Admin action specs — cross-account session/token revocation.
//!
//! Mirrors `fuz_app`'s `auth/admin_action_specs.ts`. Admin handlers operate on a *target* account
//! (`input.account_id`); audit rows carry `target_account_id` so the
//! listener chain routes account-wide revocation to the target's
//! sockets rather than the admin's own.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::account_queries::{
    AccountIdentitySnapshot, AdminAccountEntry, query_account_by_email, query_account_by_id,
    query_account_by_username, query_account_soft_delete, query_account_undelete,
    query_admin_account_list, query_purge_account,
};
use crate::action_auth::{AuthSpec, credential_type_required};
use crate::action_rate_limit::RateLimitClass;
use crate::actor_queries::{
    query_account_has_active_global_role, query_account_has_global_role, query_actor_soft_delete,
    query_actor_undelete, query_actors_by_account,
    query_count_active_accounts_with_global_role_for_update,
};
use crate::actor_schema::ActorRow;
use crate::api_token_queries::query_revoke_all_api_tokens_for_account;
use crate::app_settings_queries::{
    AppSettingsWithUsername, query_app_settings_load, query_app_settings_load_with_username,
    query_app_settings_update,
};
use crate::app_settings_schema::AppSettings;
use crate::audit_emitter::AuditLogInput;
use crate::audit_event_type::{AuditEventType, is_valid_audit_event_type_name};
use crate::audit_log_queries::{
    AUDIT_LOG_DEFAULT_LIMIT, AUDIT_LOG_LIST_LIMIT_MAX, AuditLogEventWithUsernames,
    AuditLogListFilters, query_audit_log_list_role_grant_history,
    query_audit_log_list_with_usernames,
};
use crate::auth_action_context::AuthenticatedActionContext;
use crate::auth_action_entry::AuthActionEntry;
use crate::credential_type::CredentialGate;
use crate::credential_type::CredentialType;
use crate::invite_queries::{
    Invite, InviteWithUsernames, query_create_invite, query_invite_delete_unclaimed,
    query_invite_list_all_with_usernames,
};
use crate::name_schema::NAME_LENGTH_MAX;
use crate::params_helpers::{
    ERROR_OUTCOME_INVALID, parse_optional_since_seq_param, parse_pagination_params,
    require_text_len,
};
use crate::role::{ROLE_ADMIN, ROLE_KEEPER, RoleRegistry};
use crate::role_grant_offer_action_specs::emit_supersede_audits;
use crate::role_grant_offer_queries::query_role_grant_offer_supersede_outgoing;
use fuz_http::{
    InputShape, JsonrpcError, conflict, forbidden, internal_error_with_source,
    invalid_input_params, invalid_params, method_not_found, not_found, parse_optional_bool_param,
    parse_optional_enum_param, parse_optional_str_param, parse_optional_uuid_param,
    parse_strict_params, parse_uuid_param, reject_null_keys, reject_unknown_keys, serialize_result,
};

/// `data.reason` when a non-admin targets an account other than their own
/// on `account_delete`. Mirrors the inline reason in `action_auth.rs` and
/// TS `ERROR_INSUFFICIENT_PERMISSIONS`.
const ERROR_INSUFFICIENT_PERMISSIONS: &str = "insufficient_permissions";
use crate::connection_closer::ConnectionCloseTarget;
use crate::session_queries::{
    AdminSession, query_session_list_all_active, query_session_revoke_all_for_account,
};
use fuz_db::is_pg_unique_violation;

/// Default page size for `admin_account_list`. Mirrors TS
/// `ADMIN_ACCOUNT_LIST_DEFAULT_LIMIT`.
pub const ADMIN_ACCOUNT_LIST_DEFAULT_LIMIT: i64 = 50;
/// Hard cap on `limit` for `admin_account_list`. Mirrors TS
/// `ADMIN_ACCOUNT_LIST_LIMIT_MAX`.
pub const ADMIN_ACCOUNT_LIST_LIMIT_MAX: i64 = 200;

/// `data.reason` value on the "account not found" failure. Mirrors
/// `ERROR_ACCOUNT_NOT_FOUND` in `fuz_app/src/lib/http/error_schemas.ts`.
pub const ERROR_ACCOUNT_NOT_FOUND: &str = "account_not_found";

/// `data.reason` value on `invite_delete` when the invite is missing
/// or already claimed. Mirrors `ERROR_INVITE_NOT_FOUND` in
/// `fuz_app/src/lib/http/error_schemas.ts`.
pub const ERROR_INVITE_NOT_FOUND: &str = "invite_not_found";

/// `data.reason` value on `invite_create` when an unclaimed invite with
/// matching email or username already exists (PG unique violation
/// on `idx_invite_email_unclaimed` / `idx_invite_username_unclaimed`).
///
/// Mirrors `ERROR_INVITE_DUPLICATE`.
pub const ERROR_INVITE_DUPLICATE: &str = "invite_duplicate";

/// `data.reason` value on `invite_create` when an account already
/// exists with the requested username. Mirrors
/// `ERROR_INVITE_ACCOUNT_EXISTS_USERNAME`.
pub const ERROR_INVITE_ACCOUNT_EXISTS_USERNAME: &str = "invite_account_exists_username";

/// `data.reason` value on `invite_create` when an account already
/// exists with the requested email. Mirrors
/// `ERROR_INVITE_ACCOUNT_EXISTS_EMAIL`.
pub const ERROR_INVITE_ACCOUNT_EXISTS_EMAIL: &str = "invite_account_exists_email";

/// Admin role allowlist — used by every admin spec.
pub const ADMIN_ROLES: &[&str] = &[ROLE_ADMIN];

/// Keeper role allowlist — gates the hard-purge action.
pub const KEEPER_ROLES: &[&str] = &[ROLE_KEEPER];

/// Daemon-token credential gate.
///
/// Paired with [`KEEPER_ROLES`] so `account_purge` is keeper-CLI-only
/// (matching the keeper auth shape `credential_types: ['daemon_token']` +
/// `roles: ['keeper']`).
///
/// **No production assembly mounts the daemon token** — every consumer passes
/// `daemon_token_state: None`, and the producing half lives in `fuz_testing`,
/// so nothing outside a `testing_*` binary can mint the credential. That makes
/// `account_purge` unreachable in production *by design*: the irreversible
/// hard-purge is an out-of-band (DB / bootstrap) operation, alongside
/// keeper-account removal. The gate stays declared so the spec's intent — and
/// the testing surface that still exercises it — remains legible.
pub const DAEMON_TOKEN_ONLY: CredentialGate = CredentialGate::Only(&[CredentialType::DaemonToken]);

/// `data.reason` on `account_purge` when `confirm: true` is absent.
/// Fail-loud: the irreversible purge refuses to run without explicit
/// confirmation.
pub const ERROR_PURGE_NOT_CONFIRMED: &str = "purge_not_confirmed";

/// `data.reason` (403) on `account_delete` / `account_purge` for a keeper target.
///
/// The keeper account is never API-removable: auth resolution and
/// daemon-token resolution both pivot on it, so tombstoning or cascading it
/// away would brick keeper/daemon auth with no recovery (the keeper role is
/// not web-revocable, and `account_purge` itself requires keeper auth).
/// Keeper-account removal stays out-of-band (bootstrap / DB). Mirrors
/// `fuz_app`'s `ERROR_CANNOT_DELETE_KEEPER`.
pub const ERROR_CANNOT_DELETE_KEEPER: &str = "cannot_delete_keeper";

/// `data.reason` (403) on `account_delete` / `account_purge` for the last admin.
///
/// Refused when the target is the **sole remaining active admin** — removing
/// it would leave no account able to authenticate into the admin surface
/// (`account_undelete` is itself admin-gated), and no web path re-grants
/// admin. Soft-deleted admins don't count (they can't log in), and the count
/// locks its rows, so concurrent removals can't both pass. Mirrors
/// `fuz_app`'s `ERROR_CANNOT_DELETE_LAST_ADMIN`.
pub const ERROR_CANNOT_DELETE_LAST_ADMIN: &str = "cannot_delete_last_admin";

/// Dispatch entry point for the admin family. The registry itself is
/// [`ADMIN_ACTION_ENTRIES`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AdminActionSpecs;

/// Admin action registry — every admin method, in registration order.
///
/// Rows are [`crate::AuthActionEntry`] — `{method, auth, side_effects,
/// rate_limit}`.
///
/// TS posture: the admin mutations and listings carry
/// `rate_limit: 'account'`, bounding admin-side scraping pressure. It is not
/// universal — `app_settings_get` declares none on either spine, and says so
/// at its own entry below.
pub static ADMIN_ACTION_ENTRIES: &[AuthActionEntry] = &[
    AuthActionEntry {
        method: "admin_account_list",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: false,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "admin_session_list",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: false,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "admin_session_revoke_all",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "admin_token_revoke_all",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "audit_log_list",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: false,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "audit_log_role_grant_history",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: false,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "invite_create",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "invite_list",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: false,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "invite_delete",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    // Account soft-delete (self-or-admin) + hard-purge (keeper). delete =
    // soft, purge = hard. No `admin_` prefix: privilege lives in the auth
    // check, not the name, so self-service deletion stays open.
    //
    // `account_delete` is `Authenticated` with no role gate — the handler
    // elevates to admin only when the target isn't the caller's own
    // account (input-dependent elevation, like `role_grant_offer_list`).
    // The gate is `Any` for the admin path; the handler holds the self path
    // to a session (input-dependent credential gating, same 403 body).
    AuthActionEntry {
        method: "account_delete",
        auth: AuthSpec::authenticated(CredentialGate::Any),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    AuthActionEntry {
        method: "account_purge",
        auth: AuthSpec::authenticated_gated(DAEMON_TOKEN_ONLY, KEEPER_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    // Reactivation (inverse of soft-delete) is admin-only — no self path
    // because a tombstoned account can't authenticate.
    AuthActionEntry {
        method: "account_undelete",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
    // App settings: read (no rate_limit, matches TS `app_settings_get_action_spec`)
    // + update (account-rate-limited mutation). Both are always in the registry;
    // dispatch returns `method_not_found` only if a consumer omits the handler
    // wiring — the Rust admin surface always wires both.
    AuthActionEntry {
        method: "app_settings_get",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: false,
        rate_limit: None,
    },
    AuthActionEntry {
        method: "app_settings_update",
        auth: AuthSpec::authenticated_gated(CredentialGate::Any, ADMIN_ROLES),
        input: InputShape::Object,
        side_effects: true,
        rate_limit: Some(RateLimitClass::Account),
    },
];

impl AdminActionSpecs {
    /// Dispatch an admin action.
    ///
    /// # Errors
    ///
    /// Returns a [`JsonrpcError`] on validation failure, DB error, or
    /// serialization failure.
    pub async fn dispatch(
        method: &str,
        params: &Value,
        ctx: &AuthenticatedActionContext<'_>,
        db: &(impl deadpool_postgres::GenericClient + ?Sized),
        roles: &RoleRegistry,
    ) -> Result<Value, JsonrpcError> {
        match method {
            "admin_account_list" => handle_admin_account_list(params, db, roles).await,
            "admin_session_list" => handle_admin_session_list(params, db).await,
            "admin_session_revoke_all" => {
                handle_admin_revoke_all(
                    AuditEventType::SessionRevokeAll,
                    "session revoke_all query failed",
                    params,
                    ctx,
                    db,
                    RevokeKind::Sessions,
                )
                .await
            }
            "admin_token_revoke_all" => {
                handle_admin_revoke_all(
                    AuditEventType::TokenRevokeAll,
                    "token revoke_all query failed",
                    params,
                    ctx,
                    db,
                    RevokeKind::Tokens,
                )
                .await
            }
            "audit_log_list" => handle_audit_log_list(params, db).await,
            "audit_log_role_grant_history" => handle_audit_log_role_grant_history(params, db).await,
            "invite_create" => handle_invite_create(params, ctx, db).await,
            "invite_list" => handle_invite_list(params, ctx, db).await,
            "invite_delete" => handle_invite_delete(params, ctx, db).await,
            "account_delete" => handle_account_delete(params, ctx, db).await,
            "account_purge" => handle_account_purge(params, ctx, db).await,
            "account_undelete" => handle_account_undelete(params, ctx, db).await,
            "app_settings_get" => handle_app_settings_get(params, db).await,
            "app_settings_update" => handle_app_settings_update(params, ctx, db).await,
            _ => Err(method_not_found(method)),
        }
    }
}

/// Declared input keys per method, each the exact key set of the TS twin's
/// `object` in `auth/admin_action_specs.ts`.
///
/// [`reject_unknown_keys`] runs each list at the top of its handler, so a key
/// the twin refuses is `-32602` here too rather than a field nothing reads.
/// `acting` appears on all of them because every admin spec carries an actor
/// axis and so declares `acting: ActingActor` on TS — the biconditional the
/// twin's registry enforces.
mod keys {
    /// `admin_session_revoke_all` and `admin_token_revoke_all` — one shared
    /// handler, one shared shape.
    pub const ADMIN_REVOKE_ALL: &[&str] = &["account_id", "acting"];
    /// `admin_account_list`.
    pub const ADMIN_ACCOUNT_LIST: &[&str] = &["acting", "limit", "offset", "include_deleted"];
    /// `audit_log_list`.
    pub const AUDIT_LOG_LIST: &[&str] = &[
        "event_type",
        "outcome",
        "account_id",
        "limit",
        "offset",
        "since_seq",
        "acting",
    ];
    /// `audit_log_role_grant_history`.
    pub const AUDIT_LOG_ROLE_GRANT_HISTORY: &[&str] = &["limit", "offset", "acting"];
    /// `invite_create`.
    pub const INVITE_CREATE: &[&str] = &["email", "username", "acting"];
    /// `invite_delete`.
    pub const INVITE_DELETE: &[&str] = &["invite_id", "acting"];
    /// `account_delete`.
    pub const ACCOUNT_DELETE: &[&str] = &["account_id", "acting"];
    /// `account_purge`.
    pub const ACCOUNT_PURGE: &[&str] = &["account_id", "confirm", "acting"];
    /// `account_undelete`.
    pub const ACCOUNT_UNDELETE: &[&str] = &["account_id", "acting"];
    /// `app_settings_update`.
    pub const APP_SETTINGS_UPDATE: &[&str] = &["open_signup", "acting"];

    /// `account_purge.confirm` is `optional(boolean)` on the twin — the
    /// one admin key wrapped in `optional` alone rather than
    /// `optional(nullable(...))`,
    /// so an explicit `null` is refused rather than read as absent.
    pub const ACCOUNT_PURGE_NON_NULLABLE: &[&str] = &["confirm"];
}

/// Wire input for the three admin reads whose only declared key is the
/// dispatcher-owned actor selector — `admin_session_list`, `invite_list` and
/// `app_settings_get`, each `with_default_fn(object({acting: ActingActor}), () => ({}))`
/// on the TS twin.
///
/// It carries no field a handler reads; it exists so an unknown key and an
/// explicit `null` on `acting` are the same `-32602` the strict object
/// produces, instead of params the handler never looks at. The container-level
/// `#[serde(default)]` is what makes an absent `acting` `None` without running
/// the deserializer, so a present `null` still reaches it and is refused.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ActingOnlyInput {
    #[serde(deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    acting: Option<uuid::Uuid>,
}

#[derive(Debug, Clone, Copy)]
enum RevokeKind {
    Sessions,
    Tokens,
}

#[derive(Debug, serde::Serialize)]
struct AdminRevokeAllResult {
    ok: bool,
    count: u64,
}

async fn handle_admin_revoke_all(
    event_type: AuditEventType,
    delete_err_msg: &'static str,
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    kind: RevokeKind,
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::ADMIN_REVOKE_ALL)?;
    let admin_account_id = ctx.auth.account.id;
    let target_account_id = parse_uuid_param(params, "account_id")?;

    let target = query_account_by_id(db, &target_account_id)
        .await
        .map_err(|e| internal_error_with_source("account lookup failed", &e))?;

    if target.is_none() {
        // Account-grain (no `.actor()`), matching this verb's success row.
        return Err(deny_account_not_found(ctx, db, &target_account_id, event_type, None).await);
    }

    let count = match kind {
        RevokeKind::Sessions => query_session_revoke_all_for_account(db, &target_account_id)
            .await
            .map_err(|e| internal_error_with_source(delete_err_msg, &e))?,
        RevokeKind::Tokens => query_revoke_all_api_tokens_for_account(db, &target_account_id)
            .await
            .map_err(|e| internal_error_with_source(delete_err_msg, &e))?,
    };

    ctx.close_connections_after_commit(ConnectionCloseTarget::Account(target_account_id));

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(event_type)
            .account(admin_account_id)
            .target_account(target_account_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({"count": count})),
    )
    .await?;

    serialize_result(AdminRevokeAllResult { ok: true, count })
}

#[derive(Debug)]
struct InviteCreateParams {
    email: Option<String>,
    username: Option<String>,
}

fn parse_invite_create_params(params: &Value) -> Result<InviteCreateParams, JsonrpcError> {
    reject_unknown_keys(params, keys::INVITE_CREATE)?;
    // Both fields are `optional(nullable(...))` on the twin, so `null` reads as absent — but
    // a present value of any other type is `-32602` there and must be here.
    let email = parse_optional_str_param(params, "email")?.map(str::to_owned);
    let username = parse_optional_str_param(params, "username")?.map(str::to_owned);
    if email.is_none() && username.is_none() {
        return Err(invalid_input_params(
            "at least one of 'email' or 'username' is required",
            None,
        ));
    }
    // The twin declares these as `Email` / `Username`, the same creation-site
    // primitives the signup pipeline validates against — an invite mints the
    // identity a later signup claims, so it is a creation site too and must
    // not admit an address or a name signup would refuse.
    if let Some(email) = email.as_deref()
        && !crate::is_valid_email(email)
    {
        return Err(invalid_input_params(
            "'email' is not a valid email address",
            None,
        ));
    }
    // `Username` validates the raw value and *then* lowercases, so storage is
    // canonical across every creation site on both spines and the invite
    // reads back the same way a signup-created account does.
    let username = match username {
        Some(u) => match crate::canonical_username_for_creation(&u) {
            Some(canonical) => Some(canonical),
            None => {
                return Err(invalid_input_params(
                    "'username' is not a valid username",
                    None,
                ));
            }
        },
        None => None,
    };
    Ok(InviteCreateParams { email, username })
}

#[derive(Debug, Serialize)]
struct InviteCreateResult {
    ok: bool,
    invite: Invite,
}

#[derive(Debug, Serialize)]
struct InviteListResult {
    invites: Vec<InviteWithUsernames>,
}

#[derive(Debug, Serialize)]
struct InviteDeleteResult {
    ok: bool,
}

async fn handle_invite_create(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let InviteCreateParams { email, username } = parse_invite_create_params(params)?;

    // No failure-audit emits on the four classified denial paths
    // (`invalid_params`, `ACCOUNT_EXISTS_USERNAME/EMAIL`, `DUPLICATE`):
    // the probe key on each is the email or username itself, and a
    // `Failure`-outcome row would turn the append-only audit log into
    // a PII sink for enumeration attempts. Account-enumeration pressure
    // is mitigated upstream by admin mutation rate-limiting. Mirrors TS.
    //
    // `handle_invite_delete`'s `invite_not_found` path *does* emit a
    // failure audit — different shape (UUID probe key, no PII concern).

    if let Some(u) = username.as_deref() {
        let existing = query_account_by_username(db, u)
            .await
            .map_err(|e| internal_error_with_source("account lookup by username failed", &e))?;
        if existing.is_some() {
            return Err(conflict(
                "an account already exists with that username",
                Some(ERROR_INVITE_ACCOUNT_EXISTS_USERNAME),
            ));
        }
    }
    if let Some(e) = email.as_deref() {
        let existing = query_account_by_email(db, e)
            .await
            .map_err(|e| internal_error_with_source("account lookup by email failed", &e))?;
        if existing.is_some() {
            return Err(conflict(
                "an account already exists with that email",
                Some(ERROR_INVITE_ACCOUNT_EXISTS_EMAIL),
            ));
        }
    }

    let invite = match query_create_invite(
        db,
        email.as_deref(),
        username.as_deref(),
        Some(&ctx.auth.actor.id),
    )
    .await
    {
        Ok(invite) => invite,
        Err(err) if is_pg_unique_violation(&err) => {
            return Err(conflict(
                "an unclaimed invite already exists",
                Some(ERROR_INVITE_DUPLICATE),
            ));
        }
        Err(err) => {
            return Err(internal_error_with_source(
                "invite_create query failed",
                &err,
            ));
        }
    };

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::InviteCreate)
            .actor(ctx.auth.actor.id)
            .account(ctx.auth.account.id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "invite_id": invite.id,
                "email": email,
                "username": username,
            })),
    )
    .await?;

    serialize_result(InviteCreateResult { ok: true, invite })
}

async fn handle_invite_list(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let _input: ActingOnlyInput = parse_strict_params(params.clone())?;
    // No audit emit: read-only `side_effects: false` (matches TS).
    let _ = ctx;
    let invites = query_invite_list_all_with_usernames(db)
        .await
        .map_err(|e| internal_error_with_source("invite_list query failed", &e))?;
    serialize_result(InviteListResult { invites })
}

async fn handle_invite_delete(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::INVITE_DELETE)?;
    let invite_id = parse_uuid_param(params, "invite_id")?;

    let deleted = query_invite_delete_unclaimed(db, &invite_id)
        .await
        .map_err(|e| internal_error_with_source("invite_delete query failed", &e))?;

    if !deleted {
        // Deliberate divergence from TS: emit a failure audit on
        // `invite_not_found`. The probe key is a UUID (no PII concern,
        // unlike the `invite_create` denial paths whose probe keys are
        // email/username), so the PII-sink reasoning that suppresses
        // failure audits on those paths doesn't apply here. Operationally
        // this parallels the `admin_session_revoke_all` 404 pattern — a
        // real admin attempt against a missing resource is forensic
        // signal worth keeping. TS uniformly grouped this with the
        // email/username cases; the convergence direction is TS adopts
        // the emit.
        ctx.audit_emit(
            db,
            AuditLogInput::for_event(AuditEventType::InviteDelete)
                .failure()
                .actor(ctx.auth.actor.id)
                .account(ctx.auth.account.id)
                .ip(ctx.client_ip.clone())
                .metadata(serde_json::json!({
                    "reason": ERROR_INVITE_NOT_FOUND,
                    "attempted_invite_id": invite_id.to_string(),
                })),
        )
        .await?;
        return Err(not_found("invite", Some(ERROR_INVITE_NOT_FOUND)));
    }

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::InviteDelete)
            .actor(ctx.auth.actor.id)
            .account(ctx.auth.account.id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "invite_id": invite_id.to_string(),
            })),
    )
    .await?;

    serialize_result(InviteDeleteResult { ok: true })
}

#[derive(Debug, Serialize)]
struct AdminAccountDeleteResult {
    ok: bool,
    deleted: bool,
}

#[derive(Debug, Serialize)]
struct AdminAccountPurgeResult {
    ok: bool,
    purged: bool,
}

#[derive(Debug, Serialize)]
struct AdminAccountUndeleteResult {
    ok: bool,
    undeleted: bool,
}

/// Shared removability guard for `account_delete` / `account_purge`.
///
/// Checked after auth + (for purge) confirm, before any mutation. Two
/// protections, each emitting a forensic `outcome: 'failure'` audit row
/// (fail-loud) before returning 403:
///
/// - **Keeper** — the keeper account is never API-removable (auth +
///   daemon-token resolution both pivot on it; keeper role is
///   non-web-revocable and purge needs keeper auth). Out-of-band only.
/// - **Last admin** — the sole remaining *active* admin is protected
///   (soft-deleted admins can't log in, so they don't count). The count locks
///   the rows it counted, so two removals racing for the last two admins
///   serialize and the second is refused — no web path re-grants a lost
///   admin, so the invariant has to hold rather than be recoverable.
///   `role_grant_revoke` guards the admin grant itself the same way.
///
/// A missing account holds neither role here and falls through to the
/// handler's own not-found path. `event_type` selects the audit event.
async fn guard_account_removable(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    target_account_id: &uuid::Uuid,
    event_type: AuditEventType,
) -> Result<(), JsonrpcError> {
    let admin_actor_id = ctx.auth.actor.id;
    let admin_account_id = ctx.auth.account.id;
    let verb = if matches!(event_type, AuditEventType::AccountPurge) {
        "purge"
    } else {
        "delete"
    };
    // The fail-loud failure-audit rows below route `Pool` (per
    // `AUDIT_EVENT_SPECS`), so `ctx.audit_emit` spawns the write fire-and-forget
    // and returns immediately — the row lands eventually but is NOT observable
    // synchronously after dispatch. Integration tests therefore assert the
    // denial *result*, not the audit row, on the Rust side; the TS twin asserts
    // the row deterministically via `await_pending_effects`.

    if query_account_has_global_role(db, target_account_id, ROLE_KEEPER)
        .await
        .map_err(|e| internal_error_with_source("keeper role check failed", &e))?
    {
        ctx.audit_emit(
            db,
            AuditLogInput::for_event(event_type)
                .failure()
                .actor(admin_actor_id)
                .account(admin_account_id)
                .target_account(*target_account_id)
                .ip(ctx.client_ip.clone())
                .metadata(serde_json::json!({ "reason": ERROR_CANNOT_DELETE_KEEPER })),
        )
        .await?;
        return Err(forbidden(
            &format!("cannot {verb} the keeper account"),
            Some(ERROR_CANNOT_DELETE_KEEPER),
        ));
    }

    // `_active_` variant: a tombstoned admin is already excluded from the
    // active count, so removing it can't drop the tally — guarding it would
    // falsely block (cannot_delete_last_admin) the removal of a soft-deleted
    // admin while another active admin exists. The keeper branch above stays
    // unconditional; the last-admin branch fires only for an *active* target.
    if query_account_has_active_global_role(db, target_account_id, ROLE_ADMIN)
        .await
        .map_err(|e| internal_error_with_source("admin role check failed", &e))?
        && query_count_active_accounts_with_global_role_for_update(db, ROLE_ADMIN, None)
            .await
            .map_err(|e| internal_error_with_source("admin count failed", &e))?
            <= 1
    {
        ctx.audit_emit(
            db,
            AuditLogInput::for_event(event_type)
                .failure()
                .actor(admin_actor_id)
                .account(admin_account_id)
                .target_account(*target_account_id)
                .ip(ctx.client_ip.clone())
                .metadata(serde_json::json!({ "reason": ERROR_CANNOT_DELETE_LAST_ADMIN })),
        )
        .await?;
        return Err(forbidden(
            &format!("cannot {verb} the last admin account"),
            Some(ERROR_CANNOT_DELETE_LAST_ADMIN),
        ));
    }

    Ok(())
}

/// Emit the fail-loud not-found failure audit for an admin action whose
/// target account doesn't exist (or is already in the state the verb would
/// produce), then
/// build the masked 404.
///
/// Shared by `admin_session_revoke_all` / `admin_token_revoke_all` /
/// `account_delete` / `account_purge` / `account_undelete` — every admin verb
/// keyed by a caller-supplied account uuid. The probe key is a uuid, so the
/// failure row leaks nothing (no PII sink) while keeping the forensic trail.
///
/// `actor_id` is `Option` because the revoke-all verbs are **account-grain**
/// throughout (their success rows carry no `actor` either); the
/// delete / purge / undelete verbs are actor-attributed. Returns the
/// [`JsonrpcError`] to return — the emit's own failure when the audit write
/// rejects, else the masked `not_found`.
async fn deny_account_not_found(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    target_account_id: &uuid::Uuid,
    event_type: AuditEventType,
    actor_id: Option<uuid::Uuid>,
) -> JsonrpcError {
    let mut input = AuditLogInput::for_event(event_type)
        .failure()
        .account(ctx.auth.account.id)
        .ip(ctx.client_ip.clone())
        .metadata(serde_json::json!({
            "reason": ERROR_ACCOUNT_NOT_FOUND,
            "attempted_account_id": target_account_id.to_string(),
        }));
    if let Some(actor_id) = actor_id {
        input = input.actor(actor_id);
    }
    if let Err(e) = ctx.audit_emit(db, input).await {
        return e;
    }
    not_found("account", Some(ERROR_ACCOUNT_NOT_FOUND))
}

/// Emit the account-grain identity-snapshot audit row for an account
/// lifecycle transition (`account_delete` / `account_purge` /
/// `account_undelete`).
///
/// The snapshot is what makes the row self-describing after the fact: the
/// `audit_log` identity columns carry no FK, so a purged account's id
/// survives on historical rows with nothing to join against — the
/// `username` / `email` metadata names it.
///
/// # Errors
///
/// Returns the [`JsonrpcError`] from the audit write.
async fn emit_account_lifecycle_audit(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    event_type: AuditEventType,
    target_account_id: uuid::Uuid,
    snapshot: &AccountIdentitySnapshot,
) -> Result<(), JsonrpcError> {
    ctx.audit_emit(
        db,
        AuditLogInput::for_event(event_type)
            .actor(ctx.auth.actor.id)
            .account(ctx.auth.account.id)
            .target_account(target_account_id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "username": snapshot.username,
                "email": snapshot.email,
            })),
    )
    .await
}

/// Emit one actor-grain name-snapshot audit row per actor for an account
/// lifecycle transition (`actor_delete` / `actor_purge` / `actor_undelete`).
///
/// The caller picks which actors the transition actually touched — the ones
/// whose tombstone flipped for delete/undelete, all of them for the purge
/// cascade — so the emitted rows match the rows that moved.
///
/// # Errors
///
/// Returns the [`JsonrpcError`] from the first failing audit write.
async fn emit_actor_lifecycle_audits<'a>(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    event_type: AuditEventType,
    target_account_id: uuid::Uuid,
    actors: impl IntoIterator<Item = &'a ActorRow>,
) -> Result<(), JsonrpcError> {
    for actor in actors {
        ctx.audit_emit(
            db,
            AuditLogInput::for_event(event_type)
                .actor(ctx.auth.actor.id)
                .account(ctx.auth.account.id)
                .target_account(target_account_id)
                .target_actor(Some(actor.id))
                .ip(ctx.client_ip.clone())
                .metadata(serde_json::json!({ "name": actor.name })),
        )
        .await?;
    }
    Ok(())
}

/// The `role_grant_offer_supersede` reason when an account's removal ends
/// the pending offers its actors made; `cause_id` is the removed account.
const SUPERSEDE_REASON_ACCOUNT_DELETED: &str = "account_deleted";

/// Supersede every pending offer the removed account's actors made, with its
/// audit rows — the cascade a revoke runs on the revokee's offers. An offer
/// records no authority, so one outliving its grantor's account would still
/// confer on accept. No supersede notification: a cascade notifies the
/// grantor, and the grantor's connections close with its account.
async fn cancel_outgoing_offers(
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    target_account_id: uuid::Uuid,
    actors: &[ActorRow],
) -> Result<(), JsonrpcError> {
    let actor_ids: Vec<uuid::Uuid> = actors.iter().map(|a| a.id).collect();
    let superseded = query_role_grant_offer_supersede_outgoing(db, &actor_ids)
        .await
        .map_err(|e| internal_error_with_source("outgoing offer supersede failed", &e))?;
    emit_supersede_audits(
        ctx,
        db,
        &superseded,
        SUPERSEDE_REASON_ACCOUNT_DELETED,
        target_account_id,
    )
    .await
}

/// Soft-delete an account (self-or-admin, reversible tombstone).
///
/// `account_id` is optional — omitted (or equal to the caller's own
/// account) is a self-delete; a different account requires the admin role
/// (input-dependent elevation, like `role_grant_offer_list`). A self-delete
/// is **session-only**, enforced here rather than on the spec (whose gate
/// stays `Any` so an admin deleting another account keeps any credential): an
/// API or daemon token is refused with the dispatcher's own
/// `credential_type_required` 403, ahead of the keeper / last-admin guards, so
/// a leaked token can't end the account it belongs to. Tombstones
/// the account + its actor(s), supersedes the pending offers its actors made,
/// revokes all sessions/tokens, closes live
/// sockets, and emits `account_delete` plus one `actor_delete` per
/// soft-deleted actor — each carrying its identity snapshot. Auth
/// resolution already rejects soft-deleted accounts, so the revoke +
/// socket close are belt-and-suspenders against live access.
async fn handle_account_delete(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::ACCOUNT_DELETE)?;
    let admin_account_id = ctx.auth.account.id;
    let admin_actor_id = ctx.auth.actor.id;
    // Default to the caller's own account (self-delete); deleting another
    // account requires admin.
    let target_account_id =
        parse_optional_uuid_param(params, "account_id")?.unwrap_or(admin_account_id);
    // Self path: a session only, before the guards below say anything about
    // the account.
    if target_account_id == admin_account_id
        && !CredentialGate::SESSION_ONLY.admits(ctx.credential_type)
    {
        return Err(credential_type_required(CredentialGate::SESSION_ONLY));
    }
    if target_account_id != admin_account_id && !ctx.auth.has_scoped_role(ROLE_ADMIN, None) {
        return Err(forbidden(
            "cannot delete another account",
            Some(ERROR_INSUFFICIENT_PERMISSIONS),
        ));
    }

    // Keeper + last-admin guards (fail-loud, before the tombstone).
    guard_account_removable(ctx, db, &target_account_id, AuditEventType::AccountDelete).await?;

    // Read actor names before the tombstone so they snapshot into the
    // per-actor events.
    let actors = query_actors_by_account(db, &target_account_id)
        .await
        .map_err(|e| internal_error_with_source("actor list failed", &e))?;

    let Some(snapshot) = query_account_soft_delete(db, &target_account_id, Some(&admin_actor_id))
        .await
        .map_err(|e| internal_error_with_source("account soft-delete failed", &e))?
    else {
        // Missing or already soft-deleted.
        return Err(deny_account_not_found(
            ctx,
            db,
            &target_account_id,
            AuditEventType::AccountDelete,
            Some(admin_actor_id),
        )
        .await);
    };

    cancel_outgoing_offers(ctx, db, target_account_id, &actors).await?;

    let mut soft_deleted_actors = Vec::new();
    for actor in &actors {
        let flipped = query_actor_soft_delete(db, &actor.id, Some(&admin_actor_id))
            .await
            .map_err(|e| internal_error_with_source("actor soft-delete failed", &e))?;
        if flipped {
            soft_deleted_actors.push(actor);
        }
    }

    let _ = query_session_revoke_all_for_account(db, &target_account_id)
        .await
        .map_err(|e| internal_error_with_source("session revoke failed", &e))?;
    let _ = query_revoke_all_api_tokens_for_account(db, &target_account_id)
        .await
        .map_err(|e| internal_error_with_source("token revoke failed", &e))?;
    ctx.close_connections_after_commit(ConnectionCloseTarget::Account(target_account_id));

    emit_account_lifecycle_audit(
        ctx,
        db,
        AuditEventType::AccountDelete,
        target_account_id,
        &snapshot,
    )
    .await?;
    emit_actor_lifecycle_audits(
        ctx,
        db,
        AuditEventType::ActorDelete,
        target_account_id,
        soft_deleted_actors,
    )
    .await?;

    serialize_result(AdminAccountDeleteResult {
        ok: true,
        deleted: true,
    })
}

/// Hard-purge an account (keeper-gated, irreversible). Fail-loud:
/// requires `confirm: true` and emits a WARN. Supersedes the pending offers
/// its actors made, audited, before the cascade deletes them. Snapshots identity into
/// `account_purge` + per-actor `actor_purge` before the cascading delete
/// removes the rows — the `audit_log` identity columns carry no FK, so
/// the purged ids survive on historical rows and the snapshots name them.
async fn handle_account_purge(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::ACCOUNT_PURGE)?;
    reject_null_keys(params, keys::ACCOUNT_PURGE_NON_NULLABLE)?;
    let admin_actor_id = ctx.auth.actor.id;
    let target_account_id = parse_uuid_param(params, "account_id")?;

    // Fail-loud: refuse the irreversible purge without explicit confirm. A
    // non-boolean `confirm` is a shape failure ahead of the guard, so the
    // fail-loud reason names the missing confirmation and never a wrong type.
    if parse_optional_bool_param(params, "confirm")? != Some(true) {
        return Err(invalid_params(
            "purge requires confirm: true",
            Some(ERROR_PURGE_NOT_CONFIRMED),
        ));
    }

    // Keeper + last-admin guards (fail-loud, before the cascade).
    guard_account_removable(ctx, db, &target_account_id, AuditEventType::AccountPurge).await?;

    // Snapshot actors before the cascade removes them.
    let actors = query_actors_by_account(db, &target_account_id)
        .await
        .map_err(|e| internal_error_with_source("actor list failed", &e))?;

    // Before the cascade, whose `ON DELETE CASCADE` would take the offers
    // with no audit row.
    cancel_outgoing_offers(ctx, db, target_account_id, &actors).await?;

    let Some(snapshot) = query_purge_account(db, &target_account_id)
        .await
        .map_err(|e| internal_error_with_source("account purge failed", &e))?
    else {
        return Err(deny_account_not_found(
            ctx,
            db,
            &target_account_id,
            AuditEventType::AccountPurge,
            Some(admin_actor_id),
        )
        .await);
    };

    ctx.close_connections_after_commit(ConnectionCloseTarget::Account(target_account_id));

    tracing::warn!(
        target_account_id = %target_account_id,
        by_actor_id = %admin_actor_id,
        "account hard-purged (irreversible cascading delete)",
    );

    emit_account_lifecycle_audit(
        ctx,
        db,
        AuditEventType::AccountPurge,
        target_account_id,
        &snapshot,
    )
    .await?;
    emit_actor_lifecycle_audits(
        ctx,
        db,
        AuditEventType::ActorPurge,
        target_account_id,
        &actors,
    )
    .await?;

    serialize_result(AdminAccountPurgeResult {
        ok: true,
        purged: true,
    })
}

/// Reactivate a soft-deleted account (admin-only, inverse of soft-delete).
/// Clears the `deleted_at` tombstone on the account + its soft-deleted
/// actor(s), emitting `account_undelete` + one `actor_undelete` per
/// reactivated actor. There is no self path (a tombstoned account can't
/// authenticate); does not restore revoked sessions/tokens.
async fn handle_account_undelete(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::ACCOUNT_UNDELETE)?;
    let admin_actor_id = ctx.auth.actor.id;
    let target_account_id = parse_uuid_param(params, "account_id")?;

    // Snapshot actors (the listing includes soft-deleted rows) before
    // clearing the tombstones so names land in the per-actor events.
    let actors = query_actors_by_account(db, &target_account_id)
        .await
        .map_err(|e| internal_error_with_source("actor list failed", &e))?;

    let Some(snapshot) = query_account_undelete(db, &target_account_id)
        .await
        .map_err(|e| internal_error_with_source("account undelete failed", &e))?
    else {
        // Missing or not soft-deleted.
        return Err(deny_account_not_found(
            ctx,
            db,
            &target_account_id,
            AuditEventType::AccountUndelete,
            Some(admin_actor_id),
        )
        .await);
    };

    let mut undeleted_actors = Vec::new();
    for actor in &actors {
        let flipped = query_actor_undelete(db, &actor.id)
            .await
            .map_err(|e| internal_error_with_source("actor undelete failed", &e))?;
        if flipped {
            undeleted_actors.push(actor);
        }
    }

    emit_account_lifecycle_audit(
        ctx,
        db,
        AuditEventType::AccountUndelete,
        target_account_id,
        &snapshot,
    )
    .await?;
    emit_actor_lifecycle_audits(
        ctx,
        db,
        AuditEventType::ActorUndelete,
        target_account_id,
        undeleted_actors,
    )
    .await?;

    serialize_result(AdminAccountUndeleteResult {
        ok: true,
        undeleted: true,
    })
}

#[derive(Debug, Serialize)]
struct AdminAccountListResult {
    accounts: Vec<AdminAccountEntry>,
    /// Sorted admin-grantable role names from the [`RoleRegistry`] —
    /// wire-equivalent to TS `Array<RoleName>`.
    grantable_roles: Vec<String>,
}

async fn handle_admin_account_list(
    params: &Value,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
    roles: &RoleRegistry,
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::ADMIN_ACCOUNT_LIST)?;
    let page = parse_pagination_params(
        params,
        ADMIN_ACCOUNT_LIST_DEFAULT_LIMIT,
        ADMIN_ACCOUNT_LIST_LIMIT_MAX,
    )?;
    // Active-only unless the caller opts into tombstoned rows (admin UI
    // "show deleted" view). Absent / `null` → false; any other non-boolean is
    // the `-32602` the twin's `optional(nullable(boolean))` answers.
    let include_deleted = parse_optional_bool_param(params, "include_deleted")?.unwrap_or(false);
    let accounts = query_admin_account_list(db, page.limit, page.offset, include_deleted)
        .await
        .map_err(|e| internal_error_with_source("admin_account_list query failed", &e))?;
    let grantable_roles = roles.list_admin_grantable();
    serialize_result(AdminAccountListResult {
        accounts,
        grantable_roles,
    })
}

#[derive(Debug, Serialize)]
struct AdminSessionListResult {
    sessions: Vec<AdminSession>,
}

async fn handle_admin_session_list(
    params: &Value,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let _input: ActingOnlyInput = parse_strict_params(params.clone())?;
    let sessions = query_session_list_all_active(db)
        .await
        .map_err(|e| internal_error_with_source("admin_session_list query failed", &e))?;
    serialize_result(AdminSessionListResult { sessions })
}

#[derive(Debug, Serialize)]
struct AuditLogListResult {
    events: Vec<AuditLogEventWithUsernames>,
}

async fn handle_audit_log_list(
    params: &Value,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::AUDIT_LOG_LIST)?;
    let page = parse_pagination_params(params, AUDIT_LOG_DEFAULT_LIMIT, AUDIT_LOG_LIST_LIMIT_MAX)?;
    let filters = AuditLogListFilters {
        event_type: parse_event_type_filter(params)?,
        outcome: parse_optional_enum_param(
            params,
            "outcome",
            &["success", "failure"],
            ERROR_OUTCOME_INVALID,
        )?
        .map(str::to_owned),
        account_id: parse_optional_uuid_param(params, "account_id")?,
        since_seq: parse_optional_since_seq_param(params)?,
    };
    let events = query_audit_log_list_with_usernames(db, &filters, page.limit, page.offset)
        .await
        .map_err(|e| internal_error_with_source("audit_log_list query failed", &e))?;
    serialize_result(AuditLogListResult { events })
}

/// Parse `audit_log_list`'s optional `event_type` filter, held to the twin's
/// `AuditEventTypeName` grammar and its length cap: a name off either is
/// `invalid_params` with no reason, as the twin's schema answers, rather than
/// a filter matching nothing.
fn parse_event_type_filter(params: &Value) -> Result<Option<String>, JsonrpcError> {
    let Some(event_type) = parse_optional_str_param(params, "event_type")? else {
        return Ok(None);
    };
    require_text_len(event_type, NAME_LENGTH_MAX, "event_type")?;
    if !is_valid_audit_event_type_name(event_type) {
        return Err(invalid_input_params(
            "'event_type' must start with a letter; only letters, digits, _ . / - allowed",
            None,
        ));
    }
    Ok(Some(event_type.to_owned()))
}

async fn handle_audit_log_role_grant_history(
    params: &Value,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::AUDIT_LOG_ROLE_GRANT_HISTORY)?;
    let page = parse_pagination_params(params, AUDIT_LOG_DEFAULT_LIMIT, AUDIT_LOG_LIST_LIMIT_MAX)?;
    let events = query_audit_log_list_role_grant_history(db, page.limit, page.offset)
        .await
        .map_err(|e| internal_error_with_source("audit_log_role_grant_history query failed", &e))?;
    // Same wire shape as `audit_log_list` — TS treats them as separate
    // `RoleGrantHistoryEventJson` vs `AuditLogEventWithUsernamesJson`
    // types with identical fields. The Rust port unifies on
    // `AuditLogEventWithUsernames`.
    serialize_result(AuditLogListResult { events })
}

#[derive(Debug, Serialize)]
struct AppSettingsGetResult {
    settings: AppSettingsWithUsername,
}

#[derive(Debug, Serialize)]
struct AppSettingsUpdateResult {
    ok: bool,
    settings: AppSettingsWithUsername,
}

/// Read-only load of global app settings with the updater's username.
/// No audit — `side_effects: false` read, mirrors TS `app_settings_get_handler`.
async fn handle_app_settings_get(
    params: &Value,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    let _input: ActingOnlyInput = parse_strict_params(params.clone())?;
    let settings = query_app_settings_load_with_username(db)
        .await
        .map_err(|e| internal_error_with_source("app_settings_get query failed", &e))?;
    serialize_result(AppSettingsGetResult { settings })
}

/// Update global app settings and return the new row.
///
/// Loads the old `open_signup` before mutating so the audit metadata
/// carries `{setting, old_value, new_value}`. Emits `app_settings_update`
/// in-tx (atomic with the `UPDATE`), then re-loads the joined row to
/// return to the caller. Account-shape audit: `account_id` of the acting
/// admin; no `target_account_id` (the event is not targeted at another
/// account). Mirrors `app_settings_update_handler` in `fuz_app`.
async fn handle_app_settings_update(
    params: &Value,
    ctx: &AuthenticatedActionContext<'_>,
    db: &(impl deadpool_postgres::GenericClient + ?Sized),
) -> Result<Value, JsonrpcError> {
    reject_unknown_keys(params, keys::APP_SETTINGS_UPDATE)?;
    let open_signup = match params.get("open_signup") {
        Some(v) => match v.as_bool() {
            Some(b) => b,
            None => {
                return Err(invalid_input_params(
                    "'open_signup' must be a boolean",
                    None,
                ));
            }
        },
        None => {
            return Err(invalid_input_params("'open_signup' is required", None));
        }
    };

    // Load old value for the audit metadata before applying the update.
    let old = query_app_settings_load(db)
        .await
        .map_err(|e| internal_error_with_source("app_settings load (pre-update) failed", &e))?;

    query_app_settings_update(db, AppSettings { open_signup }, &ctx.auth.actor.id)
        .await
        .map_err(|e| internal_error_with_source("app_settings_update query failed", &e))?;

    ctx.audit_emit(
        db,
        AuditLogInput::for_event(AuditEventType::AppSettingsUpdate)
            .account(ctx.auth.account.id)
            .ip(ctx.client_ip.clone())
            .metadata(serde_json::json!({
                "setting": "open_signup",
                "old_value": old.open_signup,
                "new_value": open_signup,
            })),
    )
    .await?;

    let settings = query_app_settings_load_with_username(db)
        .await
        .map_err(|e| internal_error_with_source("app_settings re-load failed", &e))?;

    serialize_result(AppSettingsUpdateResult { ok: true, settings })
}

#[cfg(test)]
mod tests {
    use fuz_http::{JsonrpcErrorCode, parse_strict_params};
    use serde_json::{Value, json};

    use super::{
        ADMIN_ACTION_ENTRIES, ActingOnlyInput, keys, parse_event_type_filter,
        parse_invite_create_params, reject_null_keys, reject_unknown_keys,
    };

    const ACTOR: &str = "3f8a1c2e-1234-4abc-9def-0123456789ab";

    /// `audit_log_list`'s `event_type` filter holds the twin's
    /// `AuditEventTypeName` grammar and its length cap: absent and `null` are
    /// no filter, an on-grammar name filters, and an off-grammar one, or one
    /// past the cap, is `invalid_params` with no reason rather than a filter
    /// matching nothing.
    #[test]
    fn event_type_filter_holds_the_audit_event_type_name_grammar() {
        assert_eq!(parse_event_type_filter(&json!({})).unwrap(), None);
        assert_eq!(
            parse_event_type_filter(&json!({"event_type": null})).unwrap(),
            None
        );
        assert_eq!(
            parse_event_type_filter(&json!({"event_type": "ns/custom.event-1"})).unwrap(),
            Some("ns/custom.event-1".to_owned())
        );
        let at_max = "a".repeat(crate::NAME_LENGTH_MAX);
        assert_eq!(
            parse_event_type_filter(&json!({"event_type": at_max})).unwrap(),
            Some(at_max.clone())
        );
        for bad in [
            json!(""),
            json!("'; DROP TABLE --"),
            json!("_login"),
            json!(42),
            json!(format!("{at_max}a")),
        ] {
            let error = parse_event_type_filter(&json!({"event_type": bad})).unwrap_err();
            assert_eq!(error.code, JsonrpcErrorCode::InvalidParams, "{bad}");
            assert!(error.data.is_none(), "{bad}: no reason");
        }
    }

    /// Every method's declared key list, paired with the dispatch name whose
    /// handler runs it. The three `acting`-only reads are absent: their shape
    /// is `ActingOnlyInput`, covered by the three tests above.
    const KEY_TABLE: &[(&str, &[&str])] = &[
        ("admin_session_revoke_all", keys::ADMIN_REVOKE_ALL),
        ("admin_token_revoke_all", keys::ADMIN_REVOKE_ALL),
        ("admin_account_list", keys::ADMIN_ACCOUNT_LIST),
        ("audit_log_list", keys::AUDIT_LOG_LIST),
        (
            "audit_log_role_grant_history",
            keys::AUDIT_LOG_ROLE_GRANT_HISTORY,
        ),
        ("invite_create", keys::INVITE_CREATE),
        ("invite_delete", keys::INVITE_DELETE),
        ("account_delete", keys::ACCOUNT_DELETE),
        ("account_purge", keys::ACCOUNT_PURGE),
        ("account_undelete", keys::ACCOUNT_UNDELETE),
        ("app_settings_update", keys::APP_SETTINGS_UPDATE),
    ];

    /// Each list names a real method, and each method's list refuses a key the
    /// twin's `object` does not declare.
    #[test]
    fn every_admin_key_list_belongs_to_a_registered_method_and_refuses_a_stray_key() {
        for (method, allowed) in KEY_TABLE {
            assert!(
                ADMIN_ACTION_ENTRIES.iter().any(|e| e.method == *method),
                "{method} is not a registered admin method"
            );
            let error = reject_unknown_keys(&json!({"nope": 1}), allowed)
                .expect_err(&format!("{method} must refuse an undeclared key"));
            assert_eq!(error.code, JsonrpcErrorCode::InvalidParams, "{method}");
        }
    }

    /// Every admin spec carries an actor axis, so under the twin's
    /// biconditional every admin input declares `acting`.
    #[test]
    fn every_admin_key_list_declares_the_acting_selector() {
        for (method, allowed) in KEY_TABLE {
            assert!(
                allowed.contains(&"acting"),
                "{method}: every admin spec has an actor axis, so it declares `acting`"
            );
            let entry = ADMIN_ACTION_ENTRIES
                .iter()
                .find(|e| e.method == *method)
                .unwrap();
            assert!(
                entry.auth.needs_actor(),
                "{method}: the axis the declared key mirrors"
            );
        }
    }

    /// `account_purge.confirm` is the family's one `optional`-only key, so an
    /// explicit `null` is refused where the `optional(nullable(...))` filters
    /// read it as absent.
    #[test]
    fn account_purge_refuses_a_null_confirm() {
        let params = json!({"account_id": ACTOR, "confirm": Value::Null});
        let error = reject_null_keys(&params, keys::ACCOUNT_PURGE_NON_NULLABLE)
            .expect_err("a null confirm must be refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);
        // The walk visits only the keys it is given. A null `account_id` is
        // not its business — the key is a required `Uuid` on the twin, and
        // `parse_uuid_param` downstream is what refuses it.
        assert!(
            reject_null_keys(
                &json!({"account_id": Value::Null}),
                keys::ACCOUNT_PURGE_NON_NULLABLE
            )
            .is_ok()
        );
    }

    /// `invite_create` reads two `optional(nullable(...))` strings; a present wrong type is
    /// `-32602` on the twin rather than a silently dropped field.
    #[test]
    fn invite_create_refuses_a_wrong_typed_address() {
        for params in [
            json!({"email": 42, "username": "bob"}),
            json!({"username": true}),
            json!({"email": ["a@b.co"]}),
        ] {
            let error = parse_invite_create_params(&params)
                .expect_err(&format!("{params} must be refused"));
            assert_eq!(
                error.code,
                JsonrpcErrorCode::InvalidParams,
                "params: {params}"
            );
        }
    }

    /// The same handler's unknown-key half, and its `optional(nullable(...))` half — a
    /// `null` address is the absent one, which then trips the at-least-one
    /// refinement rather than a type error.
    #[test]
    fn invite_create_refuses_an_unknown_key_and_reads_null_as_absent() {
        let error = parse_invite_create_params(&json!({"username": "bob", "nope": 1}))
            .expect_err("an undeclared key must be refused");
        assert_eq!(error.code, JsonrpcErrorCode::InvalidParams);

        let parsed = parse_invite_create_params(&json!({"username": "bob", "email": Value::Null}))
            .expect("a nullish address reads as absent");
        assert_eq!(parsed.username.as_deref(), Some("bob"));
        assert!(parsed.email.is_none());
    }

    /// The three `acting`-only admin reads take an absent `params` (the
    /// `with_default_fn` half) and a well-formed selector, and nothing else.
    #[test]
    fn the_acting_only_input_takes_the_default_and_the_selector() {
        for params in [Value::Null, json!({}), json!({"acting": ACTOR})] {
            assert!(
                parse_strict_params::<ActingOnlyInput>(params.clone()).is_ok(),
                "params: {params}"
            );
        }
    }

    /// An unknown key is the strict-object half — `-32602` on the twin, where
    /// a handler ignoring `params` outright answers 200.
    #[test]
    fn the_acting_only_input_refuses_an_unknown_key() {
        for params in [json!({"nope": 1}), json!({"acting": ACTOR, "nope": 1})] {
            let error = parse_strict_params::<ActingOnlyInput>(params.clone())
                .expect_err(&format!("{params} must be refused"));
            assert_eq!(
                error.code,
                JsonrpcErrorCode::InvalidParams,
                "params: {params}"
            );
        }
    }

    /// `acting` is `optional(Uuid)`, which admits an absent key and nothing
    /// else, and holds a present value to the wire UUID grammar rather than
    /// `Uuid::parse_str`'s permissive spellings.
    #[test]
    fn the_acting_only_input_holds_the_selector_to_the_wire_grammar() {
        for params in [
            json!({"acting": Value::Null}),
            json!({"acting": "3f8a1c2e12344abc9def0123456789ab"}),
            json!({"acting": format!("urn:uuid:{ACTOR}")}),
            json!({"acting": 1}),
        ] {
            let error = parse_strict_params::<ActingOnlyInput>(params.clone())
                .expect_err(&format!("{params} must be refused"));
            assert_eq!(
                error.code,
                JsonrpcErrorCode::InvalidParams,
                "params: {params}"
            );
        }
    }

    /// `account_purge` is the workspace's only daemon-token-gated spec, and
    /// the daemon token is mounted by no production assembly — so the
    /// irreversible hard-purge is deliberately out-of-band (DB / bootstrap),
    /// alongside keeper-account removal.
    ///
    /// Pinned because the gate reads as dead weight from the call site:
    /// anyone widening it to restore web reachability should have to change
    /// this assertion and re-decide, not discover the consequence later.
    #[test]
    fn account_purge_is_the_only_daemon_token_gated_spec() {
        let gated: Vec<&str> = ADMIN_ACTION_ENTRIES
            .iter()
            .filter(|e| !e.auth.credentials.is_any())
            .map(|e| e.method)
            .collect();
        assert_eq!(gated, ["account_purge"]);
        assert_eq!(
            ADMIN_ACTION_ENTRIES
                .iter()
                .find(|e| e.method == "account_purge")
                .map(|e| e.auth.credentials),
            Some(super::DAEMON_TOKEN_ONLY),
        );
        assert_eq!(super::DAEMON_TOKEN_ONLY.allowed().len(), 1);
        assert!(!super::DAEMON_TOKEN_ONLY.admits(Some(crate::CredentialType::Session)));
    }
}
