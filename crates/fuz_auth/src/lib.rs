//! `fuz_auth` — auth surface for the fuz spine.
//!
//! Twin of `fuz_app`'s TypeScript `auth/` subsystem (keyring, sessions,
//! password hashing, API + daemon tokens, rate limiter, audit emitter,
//! bootstrap, account REST routes); the twins converge on the better shape
//! and match observably.
//!
//! ## Consumer pattern
//!
//! Consumers compose the auth subsystem from concrete and `dyn`-trait
//! capabilities — assembled into per-call [`SignupOptions`] /
//! [`BootstrapOptions`] structs at the wiring site. Hot-path seams
//! (keyring, rate limiter, daemon token) stay concrete; cold-path
//! seams (password hasher, audit listeners, connection closer) take
//! `Arc<dyn Trait>`.
//!
//! ## Migration namespace
//!
//! Auth ships its DDL in the reserved `"fuz_auth"` namespace
//! ([`AUTH_MIGRATIONS_NAMESPACE`]). Consumers splice their own namespaces
//! after — `fuz_db`'s runner rejects the reserved name when a consumer
//! supplies it accidentally.
//!
//! ## Named projections
//!
//! Every auth table has a `pub const *_COLUMNS: [&str; N]` in its query
//! module — [`ACCOUNT_COLUMNS`](account_queries::ACCOUNT_COLUMNS),
//! [`ACTOR_COLUMNS`](actor_queries::ACTOR_COLUMNS),
//! [`ROLE_GRANT_COLUMNS`](actor_queries::ROLE_GRANT_COLUMNS),
//! [`ROLE_GRANT_OFFER_COLUMNS`](role_grant_offer_queries::ROLE_GRANT_OFFER_COLUMNS),
//! [`AUTH_SESSION_COLUMNS`](session_queries::AUTH_SESSION_COLUMNS),
//! [`INVITE_COLUMNS`](invite_queries::INVITE_COLUMNS),
//! [`API_TOKEN_COLUMNS`](api_token_queries::API_TOKEN_COLUMNS),
//! [`AUDIT_LOG_COLUMNS`](audit_log_queries::AUDIT_LOG_COLUMNS),
//! [`APP_SETTINGS_COLUMNS`](app_settings_queries::APP_SETTINGS_COLUMNS) —
//! the twins of `fuz_app`'s consts, same names and order. A read that
//! hydrates the table's wire row projects the const through
//! `fuz_db::qualify_columns` (or an `omit_columns` narrowing of it, like the
//! `token_hash`-less token listing) and decodes positionally through one
//! decoder per shape; CTE / JOIN reads append their extra expressions
//! after the const's columns and index them from `*_COLUMNS.len()`. The narrower purpose rows this crate deliberately
//! reads (`AccountRow`'s identity pair, `RoleGrantRow` for ACL checks, the
//! delete snapshots) have their own private per-shape column list and
//! decoder, unit-checked as a subset of the table const. No read spells a
//! column list of its own, so a column is added in one place and a
//! reordered projection can't silently transpose two same-typed columns
//! at a single site. Decoders resolve their indices **by column name at
//! compile time** (`fuz_db::col!` over the const), so a const can be
//! extended or reordered freely — every decode index follows, a name the
//! const doesn't carry is a compile error, and the appended CTE / JOIN
//! expressions keep indexing from `*_COLUMNS.len()`. A projection that
//! narrows a table const (the `token_hash`-less listing, the admin
//! summaries) is a *literal* const the decoder indexes into, pinned to its
//! `omit_columns` derivation by a unit test. A newly added column is simply
//! unread until its struct field lands; the registry guard compares column
//! sets, not order.
//!
//! The PG-gated `tests/columns.rs` is the registry guard: every live
//! table in the auth chain is either a const (which must name exactly the
//! live columns — a column added to the DDL but not the const fails there
//! instead of silently vanishing from every read) or a reasoned exemption
//! (`schema_version`, `bootstrap_lock`). `fuz_cell`'s twin test extends the
//! same registry over the cell chain.

// === crypto + low-level primitives ===
pub mod hash;
pub mod keyring;
pub mod session_cookie;

// === password ===
pub mod password;
pub mod password_argon2;
pub mod password_hasher;

// === identity primitives (username, email, and uuid shape and bounds) ===
pub mod primitive_schemas;

// === schemas (data types) ===
pub mod account_schema;
pub mod actor_schema;
pub mod api_token_schema;
pub mod app_settings_schema;
pub mod audit_event_schema;
pub mod role_grant_schema;
pub mod session_schema;

// === open-registry types ===
pub mod credential_type;
pub mod name_schema;
pub mod role;
pub mod token_scope;

// === DB queries ===
pub mod account_queries;
pub mod actor_queries;
pub mod actor_search_queries;
pub mod api_token_queries;
pub mod app_settings_queries;
pub mod audit_log_queries;
pub mod invite_queries;
pub mod role_grant_offer_queries;
pub mod session_queries;

// === auth resolution + middleware ===
pub mod acting;
pub mod auth_gate;
pub mod bearer_auth;
mod credential_deadline;
pub mod request_context;
pub mod resolve;

// === audit ===
pub mod audit_emitter;
pub mod audit_event_type;
pub mod audit_listener;
pub mod connection_closer;
pub mod notification_sender;
pub mod revocation_guard;

// === tokens ===
pub mod api_token;
pub mod daemon_token;

// === bootstrap + lifecycle ===
pub mod bootstrap;
pub mod bootstrap_keeper_resolved;
pub mod bootstrap_token_store;

// === signup ===
pub mod signup;

// === rate limiting ===
pub mod rate_limiter;

// === timing primitives (constant-time floor for auth-denial paths) ===
pub mod timing;

// === REST routes ===
pub mod account_login;
pub mod account_logout;
pub mod account_password;
pub mod account_route_state;
pub mod account_router;
pub mod account_status;
pub mod bootstrap_routes;
pub mod route_helpers;
pub mod route_response;
pub mod signup_routes;

// === action specs ===
pub mod account_action_specs;
pub mod action_auth;
pub mod action_rate_limit;
pub mod actor_lookup_action_specs;
pub mod actor_search_action_specs;
pub mod admin_action_specs;
pub mod auth_action_context;
pub mod auth_action_entry;
pub mod params_helpers;
pub mod role_grant_offer_action_specs;
pub mod self_service_role_action_specs;

// === maintenance ===
pub mod auth_cleanup;

// === migrations ===
pub mod migrations;

// === errors ===
pub mod error;

// -- Public API re-exports ---------------------------------------------------

pub use account_action_specs::AccountActionSpecs;
pub use account_login::{
    DEFAULT_LOGIN_FAIL_FLOOR_MS, DEFAULT_LOGIN_FAIL_JITTER_MS, LoginInput, login_handler,
};
pub use account_logout::logout_handler;
pub use account_password::{PasswordInput, password_handler};
pub use account_queries::{
    ActorSummary, AdminAccount, AdminAccountEntry, PendingOfferSummary, RoleGrantSummary,
    query_admin_account_list,
};
pub use account_route_state::AccountRouteState;
pub use account_router::account_router;
pub use account_schema::{AccountRow, AccountSummaryRow, AccountWithPasswordHash};
pub use account_status::status_handler;
pub use acting::{ActingSelectorParseError, parse_acting_query, parse_acting_selector};
pub use action_auth::{
    AuthAxis, AuthSpec, check_action_auth_post_authorization, check_action_auth_pre_authorization,
    credential_type_required, token_scope_denied,
};
pub use action_rate_limit::RateLimitClass;
pub use actor_lookup_action_specs::{ACTOR_LOOKUP_IDS_MAX, ActorLookupActionSpecs};
pub use actor_queries::{ResolveActingActorResult, query_create_role_grant, resolve_acting_actor};
pub use actor_schema::ActorRow;
pub use actor_search_action_specs::{ActorSearchActionSpecs, ERROR_ACTOR_SEARCH_SCOPE_REQUIRED};
pub use admin_action_specs::AdminActionSpecs;
pub use api_token::{
    API_TOKEN_ID_PREFIX, API_TOKEN_LEN, API_TOKEN_PREFIX, GeneratedApiToken, generate_api_token,
    hash_api_token, is_api_token_shaped,
};
pub use api_token_schema::{ApiTokenListRow, ApiTokenRow};
pub use app_settings_schema::AppSettings;
pub use audit_emitter::{
    AuditEmitter, AuditLogInput, AuditNotifyFn, AuditOutcome, AuditPostCommit,
    CollectingAuditPostCommit, NoopAuditPostCommit, credential_type_value, dropped_row_json,
    route_audit_emit,
};
pub use audit_event_schema::AuditLogEvent;
pub use audit_event_type::{
    AUDIT_EVENT_SPECS, AuditEventKind, AuditEventSpec, AuditEventType, AuditRouting,
    RevocationScope, audit_event_spec, is_valid_audit_event_type_name, revocation_scope_for_wire,
};
pub use audit_listener::{AuditListenerFn, AuditListenerId};
pub use audit_log_queries::{
    AUDIT_LOG_DEFAULT_LIMIT, AUDIT_LOG_LIST_LIMIT_MAX, AuditLogEventWithUsernames,
    AuditLogListFilters, query_audit_log_list_role_grant_history,
    query_audit_log_list_with_usernames,
};
pub use auth_action_context::{AccountActionContext, AuthenticatedActionContext};
pub use auth_action_entry::{AUTH_ACTION_ENTRY_REGISTRIES, AuthActionEntry, auth_action_entry};
pub use auth_cleanup::{
    AuthCleanupOptions, AuthCleanupResult, DEFAULT_AUTH_CLEANUP_INTERVAL,
    cleanup_expired_role_grant_offers, cleanup_expired_sessions, run_auth_cleanup,
    spawn_auth_cleanup,
};
pub use auth_gate::{AuthGate, OriginChecked};
pub use bearer_auth::is_browser_context;
pub use bootstrap::{
    BOOTSTRAP_TOKEN_LENGTH_MAX, BOOTSTRAP_TOKEN_MIN_BYTES, BootstrapInput, BootstrapOptions,
    bootstrap_handler, is_bootstrap_available,
};
pub use bootstrap_keeper_resolved::BootstrapKeeperResolved;
pub use bootstrap_routes::BootstrapRouteState;
pub use bootstrap_token_store::{BootstrapTokenStore, FileBootstrapTokenStore};
pub use connection_closer::{
    ConnectionCloseTarget, ConnectionCloser, NoopConnectionCloser, queue_connection_close,
};
pub use credential_type::{CredentialGate, CredentialType};
pub use daemon_token::{
    DAEMON_TOKEN_HEADER, DaemonTokenKeeperResolved, DaemonTokenState, SharedDaemonTokenState,
    resolve_keeper_into, validate_daemon_token,
};
pub use error::{BootstrapError, BootstrapErrorKind, SignupError, SignupErrorKind};
pub use hash::{SESSION_ID_LENGTH, SessionHash, hash_session_token, is_valid_session_id};
pub use invite_queries::{
    Invite, InviteWithUsernames, LockedInvite, query_create_invite, query_invite_claim_unscoped,
    query_invite_delete_unclaimed, query_invite_find_unclaimed_match_for_update,
    query_invite_list_all_with_usernames,
};
pub use keyring::{Keyring, KeyringError, KeyringErrors};
pub use migrations::{
    AUTH_COLUMN_PROJECTIONS, AUTH_INTEGRATION_TRUNCATE_TABLES, AUTH_MIGRATIONS,
    AUTH_MIGRATIONS_NAMESPACE,
};
pub use name_schema::{NAME_LENGTH_MAX, is_valid_name};
pub use notification_sender::{NoopNotificationSender, NotificationSender};
pub use params_helpers::{
    ERROR_LIMIT_INVALID, ERROR_OFFSET_INVALID, ERROR_SINCE_SEQ_INVALID, PaginationParams,
    parse_optional_since_seq_param, parse_pagination_params,
};
pub use password::{
    PASSWORD_LENGTH_MAX, PASSWORD_LENGTH_MIN, PASSWORD_PROVIDED_LENGTH_MIN, Password,
    PasswordLengthError, PasswordProvided, password_length,
};
pub use password_argon2::Argon2idHasher;
pub use password_hasher::{HashedPassword, PasswordHashError, PasswordHasher};
pub use primitive_schemas::{
    EMAIL_LENGTH_MAX, FACT_HASH_HEX_LENGTH, FACT_HASH_PREFIX, TOKEN_ID_PREFIX,
    TOKEN_ID_SUFFIX_LENGTH, USERNAME_LENGTH_MAX, USERNAME_LENGTH_MIN, USERNAME_PROVIDED_LENGTH_MAX,
    canonical_username_for_creation, is_valid_email, is_valid_fact_hash, is_valid_token_id,
    is_valid_username_for_creation,
};
pub use rate_limiter::{
    DEFAULT_ACTION_ACCOUNT_RATE_LIMIT, DEFAULT_ACTION_IP_RATE_LIMIT,
    DEFAULT_LOGIN_ACCOUNT_RATE_LIMIT, DEFAULT_LOGIN_IP_RATE_LIMIT, DEFAULT_RATE_LIMITER_MAX_KEYS,
    IN_FLIGHT_RETRY_AFTER_SECONDS, RESERVATION_WAIT_MAX, RateLimitReservation, RateLimitResult,
    RateLimited, RateLimiter, RateLimiterMode, RateLimiterOptions, reserve_optional,
    try_reserve_optional,
};
pub use request_context::{
    RequestActorContext, RequestContext, ResolvedAuthContext, ResolvedAuthOwned,
    apply_authorization_phase,
};
pub use resolve::{
    AdmissionRecheck, CREDENTIAL_READ_FAULT_BODY, CredentialFaultKind, CredentialReadFault,
    PublicContextFault, ResolvedAuth, ResolvedCredential, recheck_admission,
    revalidate_resolved_auth,
};
pub use revocation_guard::register_revocation_guard;
pub use role::{
    GrantPath, ROLE_ADMIN, ROLE_KEEPER, RoleRegistry, RoleRegistryError, RoleSpec, is_builtin_role,
};
pub use role_grant_offer_action_specs::{
    AdminOfferAuthorize, OfferCreateAuthorize, OfferCreateAuthorizeInput, RoleGrantOfferActionSpecs,
};
pub use role_grant_offer_queries::{
    AcceptOfferInput, AcceptOfferResult, BuiltinOfferRefusal, CreateRoleGrantOfferInput,
    ROLE_GRANT_OFFER_DEFAULT_TTL_MS, ROLE_GRANT_OFFER_SCOPE_KIND_GLOBAL_TOKEN,
    ROLE_GRANT_OFFER_SCOPE_SENTINEL_UUID, RevokeForScopeResult, RevokedGrantAtScope,
    RoleGrantOffer, RoleGrantOfferError, SupersededOffer, default_expiry_from_now,
    query_accept_offer, query_role_grant_offer_create, query_role_grant_offer_supersede_outgoing,
    query_role_grant_revoke_for_scope,
};
pub use role_grant_schema::{RoleGrantRow, role_grant_active_sql};
pub use route_response::{credential_type_required_response, token_scope_surface_denied_response};
pub use self_service_role_action_specs::{
    ERROR_ROLE_NOT_SELF_SERVICE_ELIGIBLE, SelfServiceRoleActionSpecs,
    validate_self_service_eligible_roles,
};
pub use session_cookie::{
    SESSION_AGE_MAX, SESSION_COOKIE_NAME, SessionCookie, clear_session_cookie,
    generate_session_token, parse_session_from_cookies, sign_session_cookie,
};
pub use session_queries::{
    ADMIN_SESSION_LIST_LIMIT, AdminSession, CappedSession, DEFAULT_MAX_SESSIONS,
    create_capped_session, query_session_cleanup_expired, query_session_enforce_limit,
    query_session_list_all_active,
};
pub use session_schema::{AuthSessionRow, SessionListRow};
pub use signup::{
    DEFAULT_SIGNUP_FAIL_FLOOR_MS, DEFAULT_SIGNUP_FAIL_JITTER_MS, SignupInput, SignupOptions,
    SignupSuccess, signup_handler,
};
pub use signup_routes::SignupRouteState;
pub use timing::{compute_fail_deadline, wait_for_deadline};
pub use token_scope::{
    MAX_TOKEN_SCOPE_BYTES, SurfaceCapability, TOKEN_SCOPE_VERSION, TokenScope, TokenScopeDocument,
    TokenScopeError, TokenSurface,
};
