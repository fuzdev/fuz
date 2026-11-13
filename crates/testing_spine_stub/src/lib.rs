//! `testing_spine_stub` — test-only spine consumer.
//!
//! Mounts the spine's **standard surface** — account REST
//! (`/api/account/{status,login,logout,password,bootstrap,signup}`),
//! the unified RPC dispatcher (`/api/rpc`) and WS endpoint (`/api/ws`)
//! carrying the protocol (`heartbeat` WS-only, `peer/ping` on both) +
//! account + admin + role-grant-offer action families plus the opt-in
//! `actor_lookup` + `actor_search` specs, audit emission with
//! the revocation guard, and every `fuz_testing` `_testing_*` spec — plus
//! `fuz_cell`'s full surface (CRUD + clone + grant ACL + field / item
//! relations + per-cell audit timeline; the cross-backend domain primitive
//! under test). It also mounts
//! the cell-gated fact-serving routes and the public `/ready` deploy gate
//! (column-presence schema-drift probe, off the declared surface — fed the
//! committed `expected_schema.json` the TS spine shares, via an env path).
//!
//! Unlike the spine's other cross-backend consumers it has no production
//! sibling, so this single crate both assembles the spine ([`run_app`]) and
//! wires the test fixtures (`src/main.rs`) — the "consumer library + test
//! binary" split those consumers keep collapses to one crate.
//!
//! **NEVER ship this in a release.** `fuz_release`'s manifest filter refuses
//! any `testing_`-prefixed binary, and `cargo xtask check-release` refuses a
//! production binary that reaches `fuz_testing`, which this crate links. The
//! whole crate is `publish = false`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::{Json, Router};
use fuz_actions::ActionRateLimits;
use fuz_actions::server::{
    AppBackendSpec, BootedAppBackend, ServeOptions, SpineBackendOptions, StartupError,
    compile_action_registry, create_app_backend, serve_until_shutdown,
};
use fuz_http::{BaseServerEnv, ServerEnvOptions};

/// Default loopback bind address (port 1177, slots beside zzz's test
/// binaries on 1175/1176). `HOST` overrides the host; `--port`, then
/// `FUZ_RUST_SPINE_STUB_PORT`, then `PORT` the port.
pub const DEFAULT_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1177);

/// The name the stub's sentinels carry.
pub const SERVER_NAME: &str = "testing_spine_stub";

/// The env the stub reads: the spine's base vars, its trusted proxies under
/// `FUZ_TRUSTED_PROXIES` — loopback when unset, as the TS spine test server
/// wires them unconditionally.
pub const ENV_OPTIONS: ServerEnvOptions = ServerEnvOptions {
    trusted_proxies_var: "FUZ_TRUSTED_PROXIES",
};

/// The migration chain, in order: `fuz_cell` and `fuz_fact` (`fact_holder`)
/// FK into `actor`, so both follow `fuz_auth` — the TS spine binary's
/// namespace set and order, so both record identical `schema_version` rows.
const MIGRATION_NAMESPACES: &[fuz_db::MigrationNamespace] = &[
    fuz_auth::AUTH_MIGRATIONS,
    fuz_cell::CELL_MIGRATIONS,
    fuz_fact::FACT_MIGRATIONS,
];

/// Test [`fuz_cell_actions::CellCreateAuthorize`] policy the role-gated-participation
/// cross case drives — the **directory model**.
///
/// Admin bypasses everything (`Allow{ moderation_required: false }`). For a
/// non-admin:
/// - **Root creation** (`parent_id`/`root_id` = `None`): `kind = "space"` is
///   admin-only → `Verdict::Deny`; every *other* parentless kind stays open, so
///   the plain-create `cell_crud` / `cell_relations` cross cases are unaffected.
/// - **Contribution** (`root_id = Some`): the governing root's
///   `policy[kind] = { min_role?, moderation_required? }` decides — a missing
///   entry (or no policy) denies; a present `min_role` the actor lacks denies;
///   otherwise it admits with the entry's `moderation_required` folded into the
///   verdict (so the suite can assert `pending` vs `approved`). The root's
///   policy arrives in the input (the handler read it in-tx) — the predicate is
///   **pure**, no DB handle.
///
/// It accepts a root policy whose every entry is an object with an optional
/// string `min_role` and an optional boolean `moderation_required`, and
/// refuses any other with `cell_policy_invalid`.
///
/// Byte-equivalent with the TS `test_cell_gated_create_authorize`; the cross
/// case mounts both. A cross-language test contract.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestCellGatedCreateAuthorize;

impl fuz_cell_actions::CellCreateAuthorize for TestCellGatedCreateAuthorize {
    fn authorize<'a>(
        &'a self,
        auth: &'a fuz_auth::RequestActorContext,
        input: &'a fuz_cell_actions::CellCreateAuthorizeInput,
        _db: &'a fuz_db::ActionDb<'a>,
    ) -> futures::future::BoxFuture<'a, Result<fuz_cell_actions::Verdict, fuz_http::JsonrpcError>>
    {
        use fuz_cell_actions::Verdict;
        // Admin bypass — admins create roots + any kind, live immediately.
        if auth.has_scoped_role(fuz_auth::ROLE_ADMIN, None) {
            return Box::pin(async {
                Ok(Verdict::Allow {
                    moderation_required: false,
                })
            });
        }
        // Root creation (no governing root): `space` is admin-only; other
        // parentless kinds stay open (the plain-create cross cases).
        if input.root_id.is_none() {
            let verdict = if input.kind.as_deref() == Some("space") {
                Verdict::Deny
            } else {
                Verdict::Allow {
                    moderation_required: false,
                }
            };
            return Box::pin(async move { Ok(verdict) });
        }
        // Contribution: resolve the governing root's per-kind policy from the
        // handler-supplied `root_policy` (no DB read of our own).
        let kind = input.kind.as_deref().unwrap_or_default();
        // No rule for this kind under the governed root → denied.
        let verdict =
            input
                .root_policy
                .as_ref()
                .and_then(|p| p.get(kind))
                .map_or(Verdict::Deny, |rule| {
                    let min_role = rule.get("min_role").and_then(serde_json::Value::as_str);
                    let moderation_required = rule
                        .get("moderation_required")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    if min_role.is_none_or(|role| auth.has_scoped_role(role, None)) {
                        Verdict::Allow {
                            moderation_required,
                        }
                    } else {
                        Verdict::Deny
                    }
                });
        Box::pin(async move { Ok(verdict) })
    }

    fn validate_policy(&self, policy: &serde_json::Value) -> Result<(), fuz_http::JsonrpcError> {
        let rule_is_valid = |rule: &serde_json::Value| {
            rule.as_object().is_some_and(|rule| {
                rule.iter().all(|(key, value)| match key.as_str() {
                    "min_role" => value.is_string(),
                    "moderation_required" => value.is_boolean(),
                    _ => false,
                })
            })
        };
        let valid = policy
            .as_object()
            .is_some_and(|rules| rules.values().all(rule_is_valid));
        if valid {
            Ok(())
        } else {
            Err(fuz_http::invalid_params(
                "invalid space policy",
                Some(fuz_cell_actions::ERROR_CELL_POLICY_INVALID),
            ))
        }
    }
}

/// Test [`fuz_cell_actions::CellGrantRevokeAuthorize`] policy the steward-revoke
/// cross case drives: the caller stewards a scope when it holds an active
/// `participant` grant bound to that scope.
///
/// The spine asks it only for a non-manager, non-grantee caller revoking a
/// role-shaped grant with a scope, so it only reads the scope. A test policy,
/// not a model: it ignores `role` and scope liveness, which a consumer's hook
/// owns ([`fuz_cell_actions::CellGrantRevokeAuthorize`]). Byte-equivalent
/// with the TS `test_cell_grant_steward_revoke_authorize`; the cross case
/// mounts both. A cross-language test contract.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestCellGrantStewardRevokeAuthorize;

impl fuz_cell_actions::CellGrantRevokeAuthorize for TestCellGrantStewardRevokeAuthorize {
    fn authorize<'a>(
        &'a self,
        auth: &'a fuz_auth::RequestActorContext,
        input: &'a fuz_cell_actions::CellGrantRevokeAuthorizeInput,
        _db: &'a fuz_db::ActionDb<'a>,
    ) -> futures::future::BoxFuture<'a, Result<bool, fuz_http::JsonrpcError>> {
        let stewards = auth.has_scoped_role("participant", Some(input.scope_id));
        Box::pin(async move { Ok(stewards) })
    }
}

/// Options for [`run_app`].
#[derive(Debug, Clone, Copy)]
pub struct RunAppOptions {
    /// The bind when `HOST` and every port input are unset, and the half a
    /// set one leaves out.
    pub default_addr: SocketAddr,
    /// `--port`, the command line's port, ahead of every env input.
    pub port: Option<u16>,
    /// Bounds the graceful-shutdown connection drain.
    pub drain_timeout: Duration,
}

/// What one stub invocation asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubInvocation {
    /// Serve, on the `--port` given if any.
    Serve { port: Option<u16> },
    /// Print [`USAGE`] to stdout and exit `0`.
    Help,
}

/// The stub's usage text.
pub const USAGE: &str = "Usage: testing_spine_stub [--port <port>]\n\
\n\
Serves the spine's standard surface for the cross-backend suites, configured\n\
by the process environment.\n\
\n\
Options:\n\
\x20 --port <port>  the port to bind (else FUZ_RUST_SPINE_STUB_PORT, then PORT, then 1177)\n\
\x20 -h, --help     print this help\n";

/// Parse the arguments after the program name.
///
/// Strict: the cross-backend harness passes `--port <port>`, and anything else
/// — an unknown flag, a malformed port, an extra argument — is refused before
/// the env is read, so a typo never boots a stub on the wrong port.
///
/// # Errors
///
/// The line to print above [`USAGE`]; the caller exits `2`.
pub fn parse_stub_args(args: &[String]) -> Result<StubInvocation, String> {
    match args {
        [] => Ok(StubInvocation::Serve { port: None }),
        [flag] if flag == "--help" || flag == "-h" => Ok(StubInvocation::Help),
        [flag] if flag == "--port" => Err("`--port` needs a value".to_owned()),
        [flag, value] if flag == "--port" => value
            .parse::<u16>()
            .map(|port| StubInvocation::Serve { port: Some(port) })
            .map_err(|e| format!("`--port {value}`: {e}")),
        [other, ..] => Err(format!("unexpected argument `{other}`")),
    }
}

/// The stub's own env, read beside [`BaseServerEnv`].
#[derive(Debug)]
struct StubConfig {
    /// `FUZ_RUST_SPINE_STUB_PORT`, below `--port` and above `PORT`.
    port: Option<u16>,
    /// `FUZ_LOGIN_RATE_LIMIT_ENABLED` — the login limiters' mode.
    enable_login_rate_limit: bool,
    /// `FUZ_ACTION_RATE_LIMIT_ENABLED` — see [`build_action_rate_limits`].
    enable_action_rate_limit: bool,
    /// `FUZ_ACTION_RATE_LIMIT_MAX_ATTEMPTS` — replaces both action limiters'
    /// caps. Refused unless `enable_action_rate_limit` is set.
    action_rate_limit_max_attempts: Option<u32>,
    /// `FUZ_AUDIT_SSE_KEEP_ALIVE_MS` — replaces the audit stream's keep-alive
    /// interval ([`fuz_actions::server::AuditSseSpec::keep_alive`]); unset
    /// keeps the spine default.
    audit_sse_keep_alive: Option<Duration>,
    /// `FUZ_WS_RECEIVE_TIMEOUT_MS` — replaces both WS endpoints' receive
    /// timeout ([`fuz_actions::ActionWsOptions::receive_timeout`]); unset
    /// keeps [`fuz_actions::DEFAULT_WS_RECEIVE_TIMEOUT`].
    ws_receive_timeout: Option<Duration>,
    /// `FUZ_RUST_SPINE_STUB_DIR`, the base dir for the daemon-token file
    /// (`{dir}/run/daemon_token`) and the facts root (`{dir}/facts`).
    spine_stub_dir: PathBuf,
    /// `FUZ_RUST_SPINE_STUB_EXPECTED_SCHEMA_PATH`, the committed
    /// `expected_schema.json` the `/ready` gate introspects against — the SAME
    /// fixture the TS spine reads. Unset leaves `/ready` unmounted; the
    /// cross-backend harness always sets it.
    expected_schema_path: Option<String>,
}

impl StubConfig {
    fn from_vars(get: &impl Fn(&str) -> Option<String>) -> Result<Self, StartupError> {
        let port = get("FUZ_RUST_SPINE_STUB_PORT")
            .map(|value| {
                value
                    .trim()
                    .parse::<u16>()
                    .map_err(|e| StartupError::Config(format!("FUZ_RUST_SPINE_STUB_PORT: {e}")))
            })
            .transpose()?;
        let enable_action_rate_limit = parse_stringbool(get, "FUZ_ACTION_RATE_LIMIT_ENABLED")?;
        Ok(Self {
            port,
            enable_login_rate_limit: parse_stringbool(get, "FUZ_LOGIN_RATE_LIMIT_ENABLED")?,
            action_rate_limit_max_attempts: parse_action_rate_limit_max_attempts(
                get("FUZ_ACTION_RATE_LIMIT_MAX_ATTEMPTS").as_deref(),
                enable_action_rate_limit,
            )?,
            enable_action_rate_limit,
            audit_sse_keep_alive: parse_timing_ms(
                "FUZ_AUDIT_SSE_KEEP_ALIVE_MS",
                get("FUZ_AUDIT_SSE_KEEP_ALIVE_MS").as_deref(),
            )?,
            ws_receive_timeout: parse_timing_ms(
                "FUZ_WS_RECEIVE_TIMEOUT_MS",
                get("FUZ_WS_RECEIVE_TIMEOUT_MS").as_deref(),
            )?,
            spine_stub_dir: get("FUZ_RUST_SPINE_STUB_DIR").map_or_else(
                || std::env::temp_dir().join("fuz_spine_stub"),
                PathBuf::from,
            ),
            expected_schema_path: get("FUZ_RUST_SPINE_STUB_EXPECTED_SCHEMA_PATH"),
        })
    }
}

/// Read a stringbool var through the spine parser
/// ([`fuz_sys::env::parse_stringbool`]). Unset → `false`; an unknown value is
/// refused so a typo doesn't silently flip behavior.
fn parse_stringbool(
    get: &impl Fn(&str) -> Option<String>,
    name: &str,
) -> Result<bool, StartupError> {
    get(name).map_or(Ok(false), |value| {
        fuz_sys::env::parse_stringbool(&value)
            .map_err(|e| StartupError::Config(format!("{name}: {e}")))
    })
}

/// Parse the optional `FUZ_ACTION_RATE_LIMIT_MAX_ATTEMPTS` against the
/// enable flag. A cap is a positive integer, and setting one without
/// `FUZ_ACTION_RATE_LIMIT_ENABLED` is refused — a cap that silently does
/// nothing would leave a suite asserting a throttle the stub never built.
fn parse_action_rate_limit_max_attempts(
    raw: Option<&str>,
    enabled: bool,
) -> Result<Option<u32>, StartupError> {
    let Some(raw) = raw else { return Ok(None) };
    let max_attempts = raw
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            StartupError::Config(format!(
                "FUZ_ACTION_RATE_LIMIT_MAX_ATTEMPTS: expected a positive integer, got {raw:?}"
            ))
        })?;
    if !enabled {
        return Err(StartupError::Config(
            "FUZ_ACTION_RATE_LIMIT_MAX_ATTEMPTS is set but FUZ_ACTION_RATE_LIMIT_ENABLED is not"
                .to_owned(),
        ));
    }
    Ok(Some(max_attempts))
}

/// Parse an optional timing var (`FUZ_AUDIT_SSE_KEEP_ALIVE_MS`,
/// `FUZ_WS_RECEIVE_TIMEOUT_MS`) — a positive integer of ms up to
/// [`fuz_realtime::SSE_KEEP_ALIVE_INTERVAL_MAX`] (2³¹ − 1 ms), read by the
/// timing cross project. The one cap serves both: the WS endpoint has none of
/// its own, and the TS binary caps its receive timeout at the equal
/// `WS_RECEIVE_TIMEOUT_MAX`. Only ASCII whitespace is trimmed (`trim_ascii`,
/// not `trim`, whose Unicode set JS's `trim` doesn't share), so the TS spine
/// binary's `parse_timing_ms_env` accepts the same set.
fn parse_timing_ms(name: &str, raw: Option<&str>) -> Result<Option<Duration>, StartupError> {
    let Some(raw) = raw else { return Ok(None) };
    let max = fuz_realtime::SSE_KEEP_ALIVE_INTERVAL_MAX;
    let interval = raw
        .trim_ascii()
        .parse::<u32>()
        .ok()
        .map(|ms| Duration::from_millis(u64::from(ms)))
        .filter(|interval| !interval.is_zero() && *interval <= max)
        .ok_or_else(|| {
            StartupError::Config(format!(
                "{name}: expected a positive integer of ms up to {}, got {raw:?}",
                max.as_millis()
            ))
        })?;
    Ok(Some(interval))
}

/// The mode a stub `*_ENABLED` flag selects: off by default, so the standard
/// cross suites never meet a throttle, and the security suites opt in.
const fn limiter_mode(enabled: bool) -> fuz_auth::RateLimiterMode {
    if enabled {
        fuz_auth::RateLimiterMode::Enforced
    } else {
        fuz_auth::RateLimiterMode::DisabledForTesting
    }
}

/// The stub's action rate limiters, built through `mode`, the posture
/// `FUZ_ACTION_RATE_LIMIT_ENABLED` selects.
///
/// One per-IP and one per-account limiter at the spine's action windows, with
/// `max_attempts` replacing both caps when given — one pair, handed to both
/// dispatcher states, which charge every classed spec (the auth families,
/// `peer/ping`, the cell verbs), so one budget spans both transports.
///
/// - **Off** ([`fuz_auth::RateLimiterMode::DisabledForTesting`], the default,
///   which the standard cross suites depend on): no action class is throttled
///   on either transport — matching the TS spine test server, which builds
///   no action limiters under `rate_limiters: 'disabled_for_testing'`.
/// - **On** ([`fuz_auth::RateLimiterMode::Enforced`]): the action rate-limit
///   cross suite drives this over a real socket with a small cap.
fn build_action_rate_limits(
    mode: fuz_auth::RateLimiterMode,
    max_attempts: Option<u32>,
) -> ActionRateLimits {
    let with_cap = |defaults: fuz_auth::RateLimiterOptions| fuz_auth::RateLimiterOptions {
        max_attempts: max_attempts.unwrap_or(defaults.max_attempts),
        ..defaults
    };
    ActionRateLimits::new(
        mode,
        with_cap(fuz_auth::DEFAULT_ACTION_ACCOUNT_RATE_LIMIT),
        with_cap(fuz_auth::DEFAULT_ACTION_IP_RATE_LIMIT),
    )
}

/// Read and check the `/ready` fixture at `path`, keeping it for the process.
///
/// The path is configuration, so an unreadable or malformed fixture is a
/// config error (exit `2`) rather than a build defect.
fn load_expected_schema(path: &str) -> Result<&'static str, StartupError> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        StartupError::Config(format!(
            "failed to read expected schema fixture {path}: {e}"
        ))
    })?;
    serde_json::from_str::<fuz_db::ExpectedSchema>(&raw).map_err(|e| {
        StartupError::Config(format!(
            "failed to parse expected schema fixture {path}: {e}"
        ))
    })?;
    Ok(raw.leak())
}

/// Run the `testing_spine_stub` lifecycle to completion.
///
/// Reads the env, boots the spine core through the toolkit's
/// `create_app_backend` (with `fuz_testing`'s env-gated startup reset as the
/// pre-migration hook), mounts the standard surface plus the `fuz_testing`
/// seams, and serves until SIGINT/SIGTERM.
///
/// No upkeep runs beside it, unlike the production spine servers: the stub
/// is compared against the TS spine test server, which schedules no cleanup.
/// The sweeps are covered directly by `fuz_auth`'s `tests/auth_cleanup.rs`.
///
/// # Errors
///
/// [`StartupError`] for env or config failures, database connectivity or
/// migration failures, a database not at READ COMMITTED, and bind or serve
/// failures.
pub async fn run_app(options: RunAppOptions) -> Result<(), StartupError> {
    let RunAppOptions {
        default_addr,
        port,
        drain_timeout,
    } = options;

    let var = |key: &str| std::env::var(key).ok();
    let mut env = BaseServerEnv::from_vars(&var, ENV_OPTIONS)?;
    let config = StubConfig::from_vars(&var)?;
    if let Some(port) = port.or(config.port) {
        env.port = Some(port);
    }
    let addr = env.bind_addr(default_addr)?;
    let shutdown = fuz_http::shutdown_token();

    // The daemon-token credential `_testing_reset` authenticates as keeper
    // with — the stub can't reset between tests without it. Its producer lives
    // in `fuz_testing`; the harness reads the token once at spawn.
    let daemon_token_state = fuz_testing::init_daemon_token(&config.spine_stub_dir)
        .await
        .map_err(|e| {
            StartupError::Config(format!(
                "daemon token init under {} failed: {e}",
                config.spine_stub_dir.display()
            ))
        })?;

    let spec = AppBackendSpec {
        session_cookie_name: fuz_auth::SESSION_COOKIE_NAME,
        migration_namespaces: MIGRATION_NAMESPACES,
        // unset (a bare manual run), the boot builds no `/ready`
        expected_schema_json: match config.expected_schema_path.as_deref() {
            Some(path) => Some(load_expected_schema(path)?),
            None => None,
        },
        // the timing cross project shortens the keep-alive interval
        audit_sse: Some(fuz_actions::server::AuditSseSpec {
            keep_alive: config
                .audit_sse_keep_alive
                .or(fuz_actions::server::AuditSseSpec::DEFAULT.keep_alive),
        }),
        browser_gates: fuz_actions::server::BrowserGateSpec::DEFAULT,
    };
    let BootedAppBackend { backend, ready } = create_app_backend(
        &env,
        &spec,
        SpineBackendOptions {
            // The login limiters, opt-in via `FUZ_LOGIN_RATE_LIMIT_ENABLED` so
            // the login-security suite drives the 429 wire shape over a real
            // socket while the rest never meet it.
            rate_limiters: limiter_mode(config.enable_login_rate_limit),
            ..fuz_testing::testing_backend_options(daemon_token_state)
        },
    )
    .await?;

    let limits = build_action_rate_limits(
        limiter_mode(config.enable_action_rate_limit),
        config.action_rate_limit_max_attempts,
    );

    // -- The front door and the route states ------------------------------
    let gate = backend.auth_gate();
    let mut auth_rest_routes = backend.auth_rest_routes(gate.clone());
    // No denial floor, so the cross suites' failed logins (auth,
    // login-security) don't each pay it — the TS spine test binary's
    // `login_fail_floor_ms: 0`. The floor is a production timing-oracle
    // defense no cross test asserts (`fuz_auth`'s `tests/login.rs` pins it
    // in-process); `account_router` announces the zero floor.
    auth_rest_routes.account.login_fail_floor_ms = 0;
    auth_rest_routes.account.login_fail_jitter_ms = 0;
    auth_rest_routes.signup = Some(fuz_auth::SignupRouteState {
        options: Arc::new(fuz_auth::SignupOptions {
            pool: backend.pool.clone(),
            password_hasher: Arc::clone(&backend.password_hasher),
            audit: Arc::clone(&backend.audit_emitter),
            // Always off, under either flag — the TS spine test server never
            // passes a signup limiter. Built through the mode rather than a
            // literal `None` so the stub announces disabled limiters in every
            // flag combination, as the TS spine does.
            signup_ip_rate_limiter: fuz_auth::RateLimiterMode::DisabledForTesting
                .limiter(fuz_auth::DEFAULT_LOGIN_IP_RATE_LIMIT),
            signup_account_rate_limiter: fuz_auth::RateLimiterMode::DisabledForTesting
                .limiter(fuz_auth::DEFAULT_LOGIN_ACCOUNT_RATE_LIMIT),
            // No denial floor, so the identity-parity suite's denied signups
            // (no invite → 403) don't each pay it — the TS spine test binary's
            // `signup_fail_floor_ms: 0`.
            signup_fail_floor_ms: 0,
            signup_fail_jitter_ms: 0,
        }),
        gate: gate.clone(),
    });

    // -- Action registry: protocol + auth families + cell + the seams ------
    // Role registry mirrors the TS spine's `spine_roles`: the builtins, the
    // `cell_editor` role (no grant path — role-shaped cell grants name it),
    // and the admin-grantable `participant` the role-gated-participation cross
    // suite exercises (offer / `role_grant_assign` grantability + admin-only
    // conferral). The auth surface and the cell grants read this one registry.
    // A cross-language test contract — must match the TS `create_role_registry`.
    let role_registry = Arc::new(
        fuz_auth::RoleRegistry::new(vec![
            fuz_auth::RoleSpec::new("cell_editor", vec![]),
            fuz_auth::RoleSpec::new("participant", vec![fuz_auth::GrantPath::Admin]),
        ])
        .map_err(|e| StartupError::Config(format!("role registry: {e}")))?,
    );
    let mut specs: Vec<fuz_actions::ActionSpec> = fuz_actions::PROTOCOL_ACTION_SPECS();
    specs.extend(backend.auth_spec_set(
        Arc::new(fuz_auth::AdminOfferAuthorize),
        Arc::clone(&role_registry),
    ));
    // `actor_lookup` — opt-in batched id → label resolver. Mounted
    // separately from the auth spec set (mirrors TS keeping it out of
    // `create_standard_rpc_actions`); off the declared surface, exercised by
    // the dedicated actor-lookup cross suite.
    specs.extend(fuz_actions::auth_adapter::build_actor_lookup_specs(
        Arc::clone(&backend.audit_emitter),
        backend.connection_closer(),
    ));
    // `actor_search` — opt-in prefix search, scope-gated for non-admins.
    // Mounted separately like `actor_lookup`; off the declared surface,
    // exercised by the dedicated actor-search cross suite.
    specs.extend(fuz_actions::auth_adapter::build_actor_search_specs(
        Arc::clone(&backend.audit_emitter),
        backend.connection_closer(),
    ));
    // Cell CRUD — the domain layer under cross-backend test. Role-shaped
    // `cell_grant`s validate against the role registry above, as the TS side's
    // `create_all_cell_actions({roles: spine_roles})` does.
    // The directory-model creation-capability policy: roots of `kind:
    // "space"` are admin-only; a contribution is gated by its governing root's
    // `policy[kind]` (the ladder + `moderation_required`); plain parentless
    // creates stay open. The role-gated-participation cross case (authored
    // upstream in fuz_app) drives this against the byte-equivalent TS policy.
    let cell_create_authorizer: Arc<dyn fuz_cell_actions::CellCreateAuthorize> =
        Arc::new(TestCellGatedCreateAuthorize);
    // And the steward-revoke policy: a scoped `participant` grant stewards its
    // scope, so its holder may revoke a role-shaped cell grant bound there. The
    // steward-revoke cross case drives it against the byte-equivalent TS policy.
    let cell_grant_revoke_authorizer: Arc<dyn fuz_cell_actions::CellGrantRevokeAuthorize> =
        Arc::new(TestCellGrantStewardRevokeAuthorize);
    specs.extend(fuz_cell_actions::build_cell_spec_set(
        fuz_cell_actions::CellSpecSetOptions {
            roles: Arc::clone(&role_registry),
            create_authorizer: Some(cell_create_authorizer),
            grant_revoke_authorizer: Some(cell_grant_revoke_authorizer),
            ..Default::default()
        },
    ));
    // `_testing_reset`, its domain-state callback emptying every cell and
    // fact table on the reset's own transaction (before the auth-table wipe +
    // fresh-keeper re-seed), so a test never sees another test's cells or
    // facts — the set the TS spine binary empties; and `_testing_drain_effects`.
    specs.extend(fuz_testing::testing_reset_specs(
        &backend.extra_action_specs_runtime(),
        Some(fuz_testing::truncate_reset_state(
            &[fuz_cell::CELL_DROP_TABLES, fuz_fact::FACT_DROP_TABLES].concat(),
        )),
    )?);
    // `_testing_flood_notifications` — queue a burst of notifications onto the
    // caller's own WebSocket connection inside one handler poll, so the
    // cross-process outbound-overflow suite can push a connection's queue past
    // its byte budget deterministically (over HTTP it refuses: there is no
    // connection to queue onto).
    specs.push(fuz_testing::create_testing_flood_notifications_action_spec());
    // `_testing_mint_session` — forge an expired-by-construction server-side
    // session (backdated `auth_session` row behind a still-valid cookie) so the
    // expiry conformance cases exercise the DB-row expiry gate over real
    // resolution.
    specs.push(fuz_testing::create_testing_mint_session_action_spec(
        Arc::clone(&backend.keyring),
        fuz_auth::SESSION_COOKIE_NAME,
    ));
    // `_testing_put_fact` — seed an embedded fact so the cross-process
    // fact-serving suite can store bytes without a DB handle (it drives over
    // real HTTP; the referencing cell is seeded via the `cell_create` RPC).
    specs.push(fuz_testing::create_testing_put_fact_action_spec());
    // `_testing_schema_snapshot` — introspect the live schema so the
    // cross-backend schema-parity gate can diff the stub's DDL (auth + cell +
    // fact, incl. the `cell_visibility` enum) against the TS spine's.
    specs.push(fuz_testing::create_testing_schema_snapshot_action_spec());
    // `_testing_migration_tracker` — dump the `schema_version` rows so the
    // cross-backend tracker-identity gate can assert byte-identical migration
    // identity (namespace + name + sequence) against the TS spine. Catches the
    // name/partitioning drift the schema-snapshot gate excludes by design.
    specs.push(fuz_testing::create_testing_migration_tracker_action_spec());
    // `_testing_origin_check` — answer the origin allowlist's parse and match
    // for one `{patterns, origin}` pair, so the TS twin's conformance table runs
    // row by row against this spine's grammar and matcher.
    specs.push(fuz_testing::create_testing_origin_check_action_spec());
    // `_testing_shorten_credential_expiry` — pull an account's session and
    // token expiries in to seconds from now, so the cross-backend
    // credential-deadline cases watch a WebSocket or audit stream end at its
    // credential's expiry.
    specs.push(fuz_testing::create_testing_shorten_credential_expiry_action_spec());
    // `_testing_action_manifest` — dump the live RPC method set + per-method
    // auth shape for the cross-impl action-manifest parity gate (the
    // action-surface twin of `_testing_schema_snapshot`). Appended LAST so it
    // enumerates every method above it plus its own descriptor; the builder
    // filters the protocol actions to match the TS mount scope.
    let action_manifest_spec = fuz_testing::create_testing_action_manifest_action_spec(&specs);
    specs.push(action_manifest_spec);
    let registry = compile_action_registry(specs)?;

    let dispatch = backend.action_dispatch(gate.clone(), registry, &limits);
    // No role gate — matches this stub's TS twin, the `testing_spine_server`
    // module in the `fuz_app` package's own cross-backend test harness
    // (another repo, not a file here), whose `ws_endpoints` spec declares no
    // `required_roles`. The domain-free stub carries no privileged broadcast,
    // so any authenticated account may hold a socket; the cross-backend
    // conformance suites depend on that parity.
    let ws_state = backend.ws_route_state(dispatch.clone(), Vec::new());
    // A second endpoint serving the same registry behind a role gate, on the
    // same connection registry — the twin of the TS spine binary's role-gated
    // `ws_endpoints` entry, which shares its transport. One account can then
    // hold a gated and an ungated socket side by side, so a revoked role must
    // close the gated registrations of one registry and leave the ungated ones
    // open (the `describe_ws_role_gated_cross_tests` suite in `fuz_app`). Its
    // path and roles are that suite's `SPINE_ROLE_GATED_WS_PATH` and
    // `SPINE_ROLE_GATED_WS_ROLES`: `admin`, and the scopable `participant`.
    let gated_ws_state = fuz_actions::WsRouteState {
        required_roles: vec![fuz_auth::ROLE_ADMIN, "participant"],
        ..ws_state.clone()
    };

    // -- Router ---------------------------------------------------------
    // Account REST + bootstrap + signup nest under `/api/account`; RPC +
    // WS nest under `/api`. The gates (body cap, origin allowlist, client-IP
    // resolution, request tracing) come from `fuz_http::compose_stack` below.
    let api_account = auth_rest_routes.into_router();
    // Both endpoints at the spine's limits, the receive timeout replaced when
    // the timing cross project sets one — as the TS binary passes its
    // `receive_timeout` to both `ws_endpoints` entries.
    let ws_defaults = fuz_actions::ActionWsOptions::default();
    let ws_options = fuz_actions::ActionWsOptions {
        receive_timeout: config.ws_receive_timeout.or(ws_defaults.receive_timeout),
        ..ws_defaults
    };
    let api = Router::new()
        .merge(fuz_actions::create_rpc_router(dispatch))
        .merge(fuz_actions::register_action_ws_with_options(
            ws_state, ws_options,
        ))
        .nest(
            "/gated",
            fuz_actions::register_action_ws_with_options(gated_ws_state, ws_options),
        );

    // Admin-gated audit-log SSE stream (`GET /api/admin/audit/stream`) — the
    // shared spine router at the spine defaults.
    let audit_route = backend.audit_stream_router(gate.clone())?;

    // Cell-gated fact serving (`fuz_fact_serving`) — the cell-scoped
    // per-reference read + the admin-only bare-hash read, twinning fuz_app's
    // `serve_fact_route.ts`. The cross suite seeds embedded facts via
    // `_testing_put_fact`, plus external rows whose URL names another fact's
    // file (refused before any disk read), so the disk-stream / X-Accel paths
    // aren't exercised here (their parity is covered by a consumer's own gate,
    // outside this workspace).
    let fact_routes = fuz_fact_serving::fact_routers(fuz_fact_serving::FactServingRouteState {
        gate,
        facts_dir: config.spine_stub_dir.join("facts"),
        x_accel: None,
    });

    // `/ready` — the column-presence schema-drift probe over the SAME
    // committed `expected_schema.json` the TS spine reads (column-presence is
    // engine-portable, so one fixture is the cross-impl contract), off the
    // declared surface like `fact_routes`. Absent without the fixture path.
    if ready.is_none() {
        tracing::info!("FUZ_RUST_SPINE_STUB_EXPECTED_SCHEMA_PATH unset — /ready not mounted");
    }
    let app_routes = Router::new()
        .route("/health", get(health))
        .nest("/api/account", api_account)
        .nest("/api", api)
        .merge(audit_route)
        .merge(fact_routes)
        .merge(ready.unwrap_or_default());

    // One group, the whole surface under the 1 MiB default cap and the origin
    // check — `/health` and `/ready` included, as on the TS spine, which checks
    // origin on every path: a probe sends no `Origin`, so the check costs it
    // nothing, and a foreign page gets the same 403 everywhere. axum's empty
    // 404 is the fallback, behind the same gates. No carve-outs: nothing here
    // refuses browser callers on its own.
    let router = fuz_http::compose_stack(
        [fuz_http::RouteGroup::new(
            "spine",
            app_routes,
            fuz_http::BodyCap::Bytes(fuz_http::DEFAULT_BODY_LIMIT_BYTES),
        )],
        fuz_http::RouteGroup::new(
            "fallback",
            Router::new(),
            fuz_http::BodyCap::Bytes(fuz_http::DEFAULT_BODY_LIMIT_BYTES),
        ),
        &backend.stack_options(),
    );

    serve_until_shutdown(
        router,
        ServeOptions {
            server_name: SERVER_NAME,
            addr,
            drain_timeout,
            shutdown,
            connection_closer: Some(backend.connection_closer()),
            upkeep: None,
        },
    )
    .await
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn the_harness_port_flag_and_help_parse() {
        assert_eq!(
            parse_stub_args(&[]),
            Ok(StubInvocation::Serve { port: None })
        );
        assert_eq!(
            parse_stub_args(&args(&["--port", "1177"])),
            Ok(StubInvocation::Serve { port: Some(1177) })
        );
        assert_eq!(parse_stub_args(&args(&["-h"])), Ok(StubInvocation::Help));
        assert_eq!(
            parse_stub_args(&args(&["--help"])),
            Ok(StubInvocation::Help)
        );
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in [
            &["--port"][..],
            &["--port", "nope"],
            &["--port", "70000"],
            &["--port", "1", "extra"],
            &["start"],
            &["--prot", "1"],
        ] {
            assert!(parse_stub_args(&args(bad)).is_err(), "{bad:?}");
        }
    }

    fn config(pairs: &[(&str, &str)]) -> Result<StubConfig, StartupError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        StubConfig::from_vars(&|k| map.get(k).cloned())
    }

    #[test]
    fn a_malformed_stub_port_is_a_config_error() {
        assert_eq!(
            config(&[("FUZ_RUST_SPINE_STUB_PORT", "1178")])
                .expect("reads")
                .port,
            Some(1178)
        );
        let error = config(&[("FUZ_RUST_SPINE_STUB_PORT", "nope")]).expect_err("refused");
        assert_eq!(error.exit_code(), 2);
        assert!(
            error.to_string().contains("FUZ_RUST_SPINE_STUB_PORT"),
            "{error}"
        );
    }

    #[test]
    fn trusted_proxies_default_to_loopback_like_the_ts_spine() {
        let read = |pairs: &[(&str, &str)]| {
            let map: HashMap<&str, &str> = pairs.iter().copied().collect();
            BaseServerEnv::from_vars(
                &|k| {
                    map.get(k)
                        .map(|v| (*v).to_owned())
                        .or_else(|| (k == "FUZ_ALLOWED_ORIGINS").then(|| "http://localhost".into()))
                },
                ENV_OPTIONS,
            )
            .expect("reads")
        };
        assert_eq!(read(&[]).trusted_proxies.len(), 2, "127.0.0.1 and ::1");
        assert!(
            read(&[("FUZ_TRUSTED_PROXIES", ",")])
                .trusted_proxies
                .is_empty()
        );
    }

    #[test]
    fn a_misconfigured_fixture_path_is_a_config_error() {
        let error = load_expected_schema("/nonexistent/expected_schema.json").expect_err("absent");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn action_rate_limits_off_build_none() {
        let limits = build_action_rate_limits(fuz_auth::RateLimiterMode::DisabledForTesting, None);
        assert!(limits.account().is_none());
        assert!(limits.ip().is_none());
    }

    #[test]
    fn action_rate_limits_on_build_both_with_the_cap() {
        let limits = build_action_rate_limits(fuz_auth::RateLimiterMode::Enforced, Some(2));
        let account = limits.account().expect("account limiter built");
        let ip = limits.ip().expect("ip limiter built");
        assert!(!Arc::ptr_eq(&account, &ip));
        // The cap replaces both limiters' `max_attempts`.
        for limiter in [&account, &ip] {
            limiter.record("k");
            limiter.record("k");
            assert!(!limiter.check("k").is_allowed());
        }
    }

    #[test]
    fn timing_ms_parse() {
        const NAME: &str = "FUZ_TEST_TIMING_MS";
        assert!(matches!(parse_timing_ms(NAME, None), Ok(None)));
        for (raw, ms) in [
            ("200", 200),
            (" 200 ", 200),
            ("\t\n\x0C\r200\r\n", 200),
            ("+200", 200),
            ("0200", 200),
            ("1", 1),
            ("2147483647", 2_147_483_647),
        ] {
            assert_eq!(
                parse_timing_ms(NAME, Some(raw)).expect("accepted"),
                Some(Duration::from_millis(ms)),
                "{raw:?}"
            );
        }
        for bad in [
            "0",
            "-1",
            "",
            "+",
            "fast",
            "1.5",
            "1e3",
            "0x10",
            "2147483648",
            // whitespace one language's `trim` strips and the other's keeps
            "\u{FEFF}200",
            "200\u{85}",
            "\u{A0}200",
            "\x0B200",
        ] {
            let error = parse_timing_ms(NAME, Some(bad)).expect_err("refused");
            assert!(
                matches!(&error, StartupError::Config(message) if message.starts_with(NAME)),
                "{bad:?}: {error}"
            );
        }
    }

    #[test]
    fn timing_vars_reach_the_config() {
        let set = config(&[
            ("FUZ_AUDIT_SSE_KEEP_ALIVE_MS", "200"),
            ("FUZ_WS_RECEIVE_TIMEOUT_MS", "1000"),
        ])
        .expect("reads");
        assert_eq!(set.audit_sse_keep_alive, Some(Duration::from_millis(200)));
        assert_eq!(set.ws_receive_timeout, Some(Duration::from_millis(1000)));
        let unset = config(&[]).expect("reads");
        assert_eq!(unset.audit_sse_keep_alive, None);
        assert_eq!(unset.ws_receive_timeout, None);
        let error = config(&[("FUZ_WS_RECEIVE_TIMEOUT_MS", "0")]).expect_err("refused");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn action_rate_limit_max_attempts_parse() {
        assert!(matches!(
            parse_action_rate_limit_max_attempts(None, false),
            Ok(None)
        ));
        assert!(matches!(
            parse_action_rate_limit_max_attempts(Some("3"), true),
            Ok(Some(3))
        ));
        for bad in ["0", "-1", "", "three"] {
            assert!(
                matches!(
                    parse_action_rate_limit_max_attempts(Some(bad), true),
                    Err(StartupError::Config(_))
                ),
                "{bad:?} should be refused"
            );
        }
        // A cap without the enable flag would do nothing — refused.
        assert!(matches!(
            parse_action_rate_limit_max_attempts(Some("3"), false),
            Err(StartupError::Config(_))
        ));
    }
}
