//! [`AppBackend`] and [`create_app_backend`] — the composition core every
//! spine server holds, and the boot sequence that builds it.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use fuz_auth::{
    AuditEmitter, AuthGate, ConnectionCloser, Keyring, PasswordHasher, RateLimiter,
    RateLimiterMode, RateLimiterOptions, SharedDaemonTokenState,
};
use fuz_db::{MigrationNamespace, Pool};
use fuz_http::{BaseServerEnv, ParsedProxy, StackOptions};
use fuz_realtime::{ConnectionRegistry, RealtimeCloser, SseRegistry};

use crate::PreMigrationHook;

use super::startup_error::{StartupError, check_transaction_isolation};

/// What a consumer's server is, fixed at compile time — one `const` per
/// consumer, beside the swap points in [`SpineBackendOptions`].
#[derive(Debug, Clone, Copy)]
pub struct AppBackendSpec {
    /// The session cookie the server signs and reads (a per-app override of
    /// [`fuz_auth::SESSION_COOKIE_NAME`]).
    pub session_cookie_name: &'static str,
    /// The migration chain, in order (auth first: the other substrates FK
    /// into `actor`). The same chain the consumer's `db-status` reports.
    /// [`create_app_backend`] refuses a chain that doesn't start with
    /// [`fuz_auth::AUTH_MIGRATIONS`] or that carries a consumer namespace
    /// under a reserved spine name ([`fuz_db::assert_migration_namespaces`]).
    pub migration_namespaces: &'static [MigrationNamespace],
    /// The committed `expected_schema.json` `/ready` checks the live database
    /// against, embedded with `include_str!` so the binary is self-contained.
    /// `None` for a server with no deploy gate (a local daemon): the boot
    /// builds no `/ready`.
    pub expected_schema_json: Option<&'static str>,
    /// The admin audit-log SSE stream, when the server mounts it: builds
    /// [`AppBackend::audit_sse`], fans audit rows to it, and closes its
    /// streams with the `WebSocket`s. `None` mounts no stream. Twin of the TS
    /// `create_app_server`'s `audit_log_sse`.
    pub audit_sse: Option<AuditSseSpec>,
    /// How the server's browser gates read: the allowlist's var, whether it
    /// mounts the `Host` check, and its note on the wildcard origin text.
    /// [`BrowserGateSpec::DEFAULT`] for a server on the spine's own env.
    pub browser_gates: BrowserGateSpec,
}

/// The server's browser gates — [`AppBackendSpec::browser_gates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserGateSpec {
    /// The env var the allowlist was read from, named by the wildcard origin
    /// refusal and warning ([`fuz_http::admit_origin_wildcards`]).
    /// [`fuz_http::ALLOWED_ORIGINS_VAR`] unless the server reads its own.
    pub allowed_origins_var: &'static str,
    /// Mount the `Host` check, the DNS-rebinding gate
    /// ([`fuz_http::StackOptions::host_gate`]) — on in [`Self::DEFAULT`].
    /// [`AppBackend::stack_options`] carries it, and the wildcard origin text
    /// says what the same entries open there.
    pub host_gate: bool,
    /// The server's sentence on what a page the allowlist trusts reaches
    /// there, added to every wildcard entry's text
    /// ([`fuz_http::OriginWildcardOptions::note`]).
    pub origin_wildcard_note: Option<&'static str>,
    /// The server's sentence for a port wildcard entry only
    /// ([`fuz_http::OriginWildcardOptions::port_wildcard_note`]).
    pub port_wildcard_note: Option<&'static str>,
}

impl BrowserGateSpec {
    /// The spine's own allowlist var, the host gate on, no notes.
    pub const DEFAULT: Self = Self {
        allowed_origins_var: fuz_http::ALLOWED_ORIGINS_VAR,
        host_gate: true,
        origin_wildcard_note: None,
        port_wildcard_note: None,
    };

    /// What these gates add to the wildcard origin text
    /// ([`fuz_http::origin_wildcard_warning`]).
    #[must_use]
    pub const fn origin_wildcard_options(&self) -> fuz_http::OriginWildcardOptions {
        fuz_http::OriginWildcardOptions {
            host_gate: self.host_gate,
            note: self.origin_wildcard_note,
            port_wildcard_note: self.port_wildcard_note,
        }
    }

    /// Refuse a wildcard in `env`'s allowlist unless
    /// `FUZ_ALLOW_ORIGIN_WILDCARDS=true`, and say what each admits when it is
    /// ([`fuz_http::admit_origin_wildcards`], with these gates' var and text).
    ///
    /// [`create_app_backend`] runs it first thing, and [`super::boot_only`]
    /// (the branch with no `DATABASE_URL`) too, so a misconfigured list is
    /// loud before the database exists.
    ///
    /// # Errors
    ///
    /// [`StartupError::Config`] (exit `2`) naming each wildcard entry, what
    /// it admits, and the flag, when the list holds one and the flag is off.
    pub fn admit_origin_wildcards(&self, env: &BaseServerEnv) -> Result<(), StartupError> {
        fuz_http::admit_origin_wildcards(
            &env.allowed_origins,
            env.allow_origin_wildcards,
            self.allowed_origins_var,
            &self.origin_wildcard_options(),
        )?;
        Ok(())
    }
}

/// How a server's audit-log SSE stream behaves — [`AppBackendSpec::audit_sse`].
///
/// Twin of the object form of the TS `create_app_server`'s `audit_log_sse`,
/// less its `role`: the role the stream requires lives on
/// [`fuz_realtime::AuditStreamRouteState::required_role`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditSseSpec {
    /// Each stream's keep-alive interval ([`SseRegistry::with_keep_alive`]);
    /// `None` writes no keep-alives. [`Self::DEFAULT`] takes
    /// [`fuz_realtime::SSE_KEEP_ALIVE_INTERVAL`]; a server behind a proxy
    /// with a shorter idle timeout lowers it, and a test server shortens it.
    /// The boot refuses an interval [`fuz_realtime::sse_keep_alive_is_valid`]
    /// refuses — zero, or past [`fuz_realtime::SSE_KEEP_ALIVE_INTERVAL_MAX`] —
    /// with [`StartupError::Config`], as the twin throws on one. The TS
    /// `keep_alive_ms`, `null` for off.
    pub keep_alive: Option<Duration>,
}

impl AuditSseSpec {
    /// The stream at the spine defaults: keep-alives every
    /// [`fuz_realtime::SSE_KEEP_ALIVE_INTERVAL`].
    pub const DEFAULT: Self = Self {
        keep_alive: Some(fuz_realtime::SSE_KEEP_ALIVE_INTERVAL),
    };
}

impl Default for AuditSseSpec {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The swap points [`create_app_backend`] takes: the `testing_*` seams the
/// production binary and its test sibling differ on, and the per-IP login
/// bound.
#[allow(missing_debug_implementations)] // Arc-of-dyn + boxed-closure fields
pub struct SpineBackendOptions {
    /// Production wires [`fuz_auth::Argon2idHasher`]; a test binary
    /// `fuz_testing::TestingArgon2idHasher`.
    pub password_hasher: Arc<dyn PasswordHasher>,
    /// The mode every spine limiter is built through. Production:
    /// [`RateLimiterMode::Enforced`].
    pub rate_limiters: RateLimiterMode,
    /// The per-IP login bound (`/login`, `/password`), built through
    /// [`Self::rate_limiters`]. Production: [`fuz_auth::DEFAULT_LOGIN_IP_RATE_LIMIT`];
    /// a server whose callers share an address (a classroom behind one NAT)
    /// raises it.
    pub login_ip_rate_limit: RateLimiterOptions,
    /// The daemon-token credential state. Production: `None` — the producer
    /// lives in `fuz_testing`, which a production binary cannot link.
    pub daemon_token_state: Option<SharedDaemonTokenState>,
    /// Fired after the pool exists and before migrations. Production: `None`;
    /// a test binary's env-gated schema reset.
    pub pre_migration_hook: Option<PreMigrationHook<StartupError>>,
    /// Whether the audit emitter tracks its in-flight writes, the substrate of
    /// `_testing_drain_effects`. Production: `false`.
    pub audit_inflight_tracking: bool,
}

impl SpineBackendOptions {
    /// The production options: `password_hasher`, every limiter enforced at
    /// the spine defaults, no daemon token, no hook, no in-flight tracking.
    #[must_use]
    pub fn production(password_hasher: Arc<dyn PasswordHasher>) -> Self {
        Self {
            password_hasher,
            rate_limiters: RateLimiterMode::Enforced,
            login_ip_rate_limit: fuz_auth::DEFAULT_LOGIN_IP_RATE_LIMIT,
            daemon_token_state: None,
            pre_migration_hook: None,
            audit_inflight_tracking: false,
        }
    }
}

/// The long-lived spine state a server is composed from — the twin of
/// `fuz_app`'s `AppBackend` deps.
///
/// A consumer holds one beside its own fields and builds its route states
/// from it ([`Self::account_route_state`] and the rest). Every field is an
/// `Arc` or an `Arc`-backed handle, so `Clone` is cheap.
#[derive(Clone)]
pub struct AppBackend {
    pub pool: Pool,
    pub keyring: Arc<Keyring>,
    pub password_hasher: Arc<dyn PasswordHasher>,
    pub audit_emitter: Arc<AuditEmitter>,
    /// Whether `/api/account/bootstrap` is open, set at boot and cleared by
    /// the bootstrap that consumes the token.
    pub bootstrap_available: Arc<AtomicBool>,
    pub login_ip_rate_limiter: Option<Arc<RateLimiter>>,
    pub login_account_rate_limiter: Option<Arc<RateLimiter>>,
    /// The mode the limiters above were built through; the signup limiters
    /// are built through it too.
    pub rate_limiters: RateLimiterMode,
    /// Always `None` in production (see [`SpineBackendOptions`]).
    pub daemon_token_state: Option<SharedDaemonTokenState>,
    /// The WebSocket connection registry.
    pub realtime: Arc<ConnectionRegistry>,
    /// The admin audit-log SSE registry, when [`AppBackendSpec::audit_sse`]
    /// mounts the stream.
    pub audit_sse: Option<Arc<SseRegistry>>,
    pub allowed_origins: fuz_http::AllowedOrigins,
    /// Whether the server mounts the `Host` check
    /// ([`BrowserGateSpec::host_gate`]), for [`Self::stack_options`].
    pub host_gate: bool,
    /// The env var the allowlist was read from
    /// ([`BrowserGateSpec::allowed_origins_var`]), which the host gate's
    /// refusal warning names.
    pub allowed_origins_var: &'static str,
    pub trusted_proxies: Arc<Vec<ParsedProxy>>,
    pub bootstrap_token_path: Option<PathBuf>,
    pub session_cookie_name: &'static str,
}

impl std::fmt::Debug for AppBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppBackend")
            .field("session_cookie_name", &self.session_cookie_name)
            .field(
                "allowed_origins_count",
                &self.allowed_origins.patterns().len(),
            )
            .field("has_daemon_token", &self.daemon_token_state.is_some())
            .field("has_audit_sse", &self.audit_sse.is_some())
            .field(
                "has_bootstrap_token_path",
                &self.bootstrap_token_path.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl AppBackend {
    /// The front door every credentialed route checks a request at — the
    /// origin allowlist beside the credential walk (daemon token → cookie →
    /// bearer) over the server's session cookie. Build it once and clone it
    /// into every route state, and read the stack's options from the same
    /// backend ([`Self::stack_options`]), so the stack's origin check and the
    /// in-handler one read one allowlist.
    #[must_use]
    pub fn auth_gate(&self) -> AuthGate {
        AuthGate {
            pool: self.pool.clone(),
            keyring: Arc::clone(&self.keyring),
            daemon_token_state: self.daemon_token_state.clone(),
            session_cookie_name: self.session_cookie_name,
            allowed_origins: self.allowed_origins.clone(),
        }
    }

    /// The `compose_stack` options: the allowlist and the var it was read
    /// from, the trusted proxies, and the host gate unless the server clears
    /// it ([`BrowserGateSpec::host_gate`]).
    #[must_use]
    pub fn stack_options(&self) -> StackOptions {
        StackOptions {
            host_gate: self.host_gate,
            allowed_origins_var: self.allowed_origins_var,
            ..StackOptions::new(
                self.allowed_origins.clone(),
                Arc::clone(&self.trusted_proxies),
            )
        }
    }

    /// The closer over every live transport: the WebSocket registry, and the
    /// audit SSE registry when mounted. The auth listener chain, the RPC and
    /// WS handlers, the auth cleanup, and shutdown all close through it.
    #[must_use]
    pub fn connection_closer(&self) -> Arc<dyn ConnectionCloser> {
        self.audit_sse.as_ref().map_or_else(
            || {
                let registry: Arc<ConnectionRegistry> = Arc::clone(&self.realtime);
                let closer: Arc<dyn ConnectionCloser> = registry;
                closer
            },
            |sse| RealtimeCloser::connection_closer(&self.realtime, sse),
        )
    }

    /// The WebSocket registry as a `NotificationSender`, for the
    /// role-grant-offer inbox fan-out — the instance the WS endpoint
    /// populates, so an HTTP-created offer reaches the recipient's sockets.
    #[must_use]
    pub fn notification_sender(&self) -> Arc<dyn fuz_auth::NotificationSender> {
        let registry: Arc<ConnectionRegistry> = Arc::clone(&self.realtime);
        registry
    }

    /// What an [`crate::ExtraActionSpecsFactory`] receives.
    #[must_use]
    pub fn extra_action_specs_runtime(&self) -> crate::ExtraActionSpecsRuntime {
        crate::ExtraActionSpecsRuntime {
            password_hasher: Arc::clone(&self.password_hasher),
            keyring: Arc::clone(&self.keyring),
            daemon_token_state: self.daemon_token_state.clone(),
            session_cookie_name: self.session_cookie_name,
            audit_emitter: Arc::clone(&self.audit_emitter),
        }
    }

    /// The auth cleanup's options over this backend — its pool, its emitter
    /// (so expiry audits reach the emitter's listeners), and
    /// [`Self::connection_closer`] (so a swept session's connections close).
    #[must_use]
    pub fn auth_cleanup_options(&self) -> fuz_auth::AuthCleanupOptions {
        fuz_auth::AuthCleanupOptions {
            pool: self.pool.clone(),
            audit: Arc::clone(&self.audit_emitter),
            connection_closer: self.connection_closer(),
        }
    }
}

/// A booted [`AppBackend`] and the `/ready` router over it.
#[derive(Debug)]
pub struct BootedAppBackend {
    pub backend: AppBackend,
    /// `GET /ready`: the column-presence schema-drift probe over
    /// [`AppBackendSpec::expected_schema_json`]; `None` when the spec has no
    /// fixture, so the server mounts no `/ready`.
    pub ready: Option<Router>,
}

/// Refuse a migration chain before any connection opens: it must start with
/// the auth namespace (the cell and fact chains reference `actor`), and no
/// consumer namespace may bear a reserved spine name.
///
/// # Errors
///
/// [`StartupError::Config`] naming the offending namespace.
fn check_migration_chain(namespaces: &[MigrationNamespace]) -> Result<(), StartupError> {
    if namespaces.first().map(|ns| ns.name) != Some(fuz_auth::AUTH_MIGRATIONS_NAMESPACE) {
        let names: Vec<&str> = namespaces.iter().map(|ns| ns.name).collect();
        return Err(StartupError::Config(format!(
            "the migration chain must start with fuz_auth::AUTH_MIGRATIONS (the other chains reference `actor`); got {names:?}"
        )));
    }
    fuz_db::assert_migration_namespaces(namespaces)
        .map_err(|error| StartupError::Config(error.to_string()))
}

/// Build the spine core and boot it against the database — the twin of
/// `fuz_app`'s `create_app_backend` plus the boot half of `create_app_server`.
///
/// In order:
///
/// 1. the origin allowlist's wildcards — refused unless
///    `FUZ_ALLOW_ORIGIN_WILDCARDS=true`, each warned of when admitted
///    ([`BrowserGateSpec::admit_origin_wildcards`]); the migration chain's
///    shape (auth first, spine names reserved), before any connection opens;
///    the pool from `DATABASE_URL`, the keyring from
///    `SECRET_FUZ_COOKIE_KEYS` (refused when absent or weak — never an
///    ephemeral key that resets every session on restart), the audit emitter,
///    the login limiters, and the realtime registries;
/// 2. the READ COMMITTED guard ([`ensure_read_committed`]), before anything
///    writes;
/// 3. the pre-migration hook;
/// 4. the migration chain;
/// 5. the keeper resolved into the daemon-token state, when there is one;
/// 6. bootstrap availability, against the migrated schema;
/// 7. the audit listeners: the audit stream's fan-out when mounted, then the
///    revocation guard, so a revocation's row reaches the streams before the
///    close ends them;
/// 8. the `/ready` router over the embedded expected schema, when the spec
///    has one.
///
/// # Errors
///
/// [`StartupError::Config`] for a wildcard allowlist entry without the opt-in,
/// an absent `DATABASE_URL`, bad cookie keys, or a migration chain that
/// doesn't start with auth or that gives a consumer namespace a reserved spine
/// name;
/// [`StartupError::Database`] for the pool, a boot query, or a migration;
/// [`StartupError::TransactionIsolation`]; whatever the hook returns; and
/// [`StartupError::ExpectedSchema`] for a malformed fixture.
#[allow(
    clippy::unused_async_trait_impl,
    reason = "an `async fn` body runs when awaited; the `impl Future` rewrite would build the pool and keyring at call time"
)]
pub async fn create_app_backend(
    env: &BaseServerEnv,
    spec: &AppBackendSpec,
    options: SpineBackendOptions,
) -> Result<BootedAppBackend, StartupError> {
    // first, so the refusal (exit `2`) comes before any database work and a
    // warning before anything is served
    spec.browser_gates.admit_origin_wildcards(env)?;
    check_migration_chain(spec.migration_namespaces)?;
    let backend = build_app_backend(env, spec, &options)?;

    ensure_read_committed(&backend.pool).await?;

    if let Some(hook) = options.pre_migration_hook {
        hook(&backend.pool).await?;
    }

    fuz_db::run_migrations(&backend.pool, spec.migration_namespaces).await?;

    // The token is static for the process; bootstrap's `on_keeper_resolved`
    // sets the keeper on a fresh database, and this covers one already
    // bootstrapped.
    if let Some(state) = &backend.daemon_token_state {
        fuz_auth::resolve_keeper_into(state, &backend.pool).await;
    }

    let bootstrap_available = fuz_auth::is_bootstrap_available(
        &backend.pool,
        backend
            .bootstrap_token_path
            .as_deref()
            .and_then(|p| p.to_str()),
    )
    .await;
    backend
        .bootstrap_available
        .store(bootstrap_available, Ordering::SeqCst);

    register_audit_listeners(&backend);

    let ready = match spec.expected_schema_json {
        Some(json) => Some(fuz_http::ready_router(fuz_http::ReadyRouteState {
            pool: backend.pool.clone(),
            expected: Arc::new(parse_expected_schema(json)?),
        })),
        None => None,
    };
    Ok(BootedAppBackend { backend, ready })
}

/// Register the backend's audit listeners: the audit stream's fan-out when it
/// is mounted, then the one revocation listener over every live transport
/// ([`AppBackend::connection_closer`]).
///
/// In that order: the emitter runs its listeners in registration order, so a
/// revocation's row reaches the streams before the listener's close ends them
/// — the order the TS twin's `create_app_server` registers them in.
fn register_audit_listeners(backend: &AppBackend) {
    if let Some(sse) = &backend.audit_sse {
        fuz_realtime::register_audit_sse_listener(&backend.audit_emitter, sse);
    }
    fuz_auth::register_revocation_guard(&backend.audit_emitter, &backend.connection_closer());
}

/// Build the spine core without touching the database — step 1 of
/// [`create_app_backend`], which every server goes through.
///
/// The pool from `DATABASE_URL` (lazy: it connects on first checkout), the
/// keyring from `SECRET_FUZ_COOKIE_KEYS`, the audit emitter, the login
/// limiters through `options.rate_limiters`, and the realtime registries. A
/// test that composes a server's routers without a database builds its core
/// here (`fuz_testing::inert_app_backend`). `options.pre_migration_hook` is
/// [`create_app_backend`]'s and unused here.
///
/// # Errors
///
/// [`StartupError::Config`] for an absent `DATABASE_URL`, bad cookie keys, or
/// an out-of-range [`AuditSseSpec::keep_alive`];
/// [`StartupError::Database`] for an unparseable URL.
pub fn build_app_backend(
    env: &BaseServerEnv,
    spec: &AppBackendSpec,
    options: &SpineBackendOptions,
) -> Result<AppBackend, StartupError> {
    let SpineBackendOptions {
        password_hasher,
        rate_limiters,
        login_ip_rate_limit,
        daemon_token_state,
        pre_migration_hook: _,
        audit_inflight_tracking,
    } = options;
    let rate_limiters = *rate_limiters;
    let audit_sse = spec.audit_sse.map(build_audit_sse).transpose()?;
    let database_url = env
        .database_url
        .as_deref()
        .ok_or_else(|| StartupError::Config("DATABASE_URL required for full app".into()))?;
    let pool = fuz_db::create_pool(
        database_url,
        &fuz_db::PoolOptions {
            checkout_timeout: env.db_checkout_timeout,
        },
    )?;
    let keyring = Arc::new(build_keyring(env.cookie_keys.as_deref())?);
    let audit_emitter = Arc::new(
        if *audit_inflight_tracking {
            AuditEmitter::new_with_inflight_tracking(pool.clone())
        } else {
            AuditEmitter::new(pool.clone())
        }
        .with_checkout_timeout(env.db_audit_checkout_timeout),
    );
    Ok(AppBackend {
        login_ip_rate_limiter: rate_limiters.limiter(*login_ip_rate_limit),
        login_account_rate_limiter: rate_limiters
            .limiter(fuz_auth::DEFAULT_LOGIN_ACCOUNT_RATE_LIMIT),
        rate_limiters,
        keyring,
        password_hasher: Arc::clone(password_hasher),
        audit_emitter,
        bootstrap_available: Arc::new(AtomicBool::new(false)),
        daemon_token_state: daemon_token_state.clone(),
        realtime: Arc::new(ConnectionRegistry::new()),
        audit_sse,
        allowed_origins: env.allowed_origins.clone(),
        host_gate: spec.browser_gates.host_gate,
        allowed_origins_var: spec.browser_gates.allowed_origins_var,
        trusted_proxies: Arc::new(env.trusted_proxies.clone()),
        bootstrap_token_path: env.bootstrap_token_path.clone(),
        session_cookie_name: spec.session_cookie_name,
        pool,
    })
}

/// Build the audit stream's registry from its spec.
///
/// # Errors
///
/// [`StartupError::Config`] for a keep-alive interval
/// [`fuz_realtime::sse_keep_alive_is_valid`] refuses, which
/// [`SseRegistry::with_keep_alive`] would panic on.
fn build_audit_sse(spec: AuditSseSpec) -> Result<Arc<SseRegistry>, StartupError> {
    let AuditSseSpec { keep_alive } = spec;
    if !fuz_realtime::sse_keep_alive_is_valid(keep_alive) {
        return Err(StartupError::Config(format!(
            "the audit stream's keep-alive interval must be positive and at most {:?}, or None \
             to turn keep-alives off; got {keep_alive:?}",
            fuz_realtime::SSE_KEEP_ALIVE_INTERVAL_MAX
        )));
    }
    Ok(Arc::new(SseRegistry::new().with_keep_alive(keep_alive)))
}

/// Build the keyring from the `SECRET_FUZ_COOKIE_KEYS` value. [`Keyring::new`]
/// validates, so the per-key length policy stays in `fuz_auth`.
///
/// # Errors
///
/// [`StartupError::Config`] when the value is absent, empty, or any key is
/// shorter than the spine minimum.
fn build_keyring(cookie_keys: Option<&str>) -> Result<Keyring, StartupError> {
    let value = cookie_keys.ok_or_else(|| {
        StartupError::Config(
            "SECRET_FUZ_COOKIE_KEYS is required (`__`-separated cookie-signing keys)".into(),
        )
    })?;
    Keyring::new(value)
        .map_err(|e| StartupError::Config(format!("SECRET_FUZ_COOKIE_KEYS invalid: {e}")))
}

/// Parse an `expected_schema.json` column map.
///
/// # Errors
///
/// [`StartupError::ExpectedSchema`] when it is not one.
pub fn parse_expected_schema(json: &str) -> Result<fuz_db::ExpectedSchema, StartupError> {
    serde_json::from_str(json).map_err(StartupError::ExpectedSchema)
}

/// Refuse a database whose `default_transaction_isolation` is anything but
/// `read committed` ([`super::startup_error::REQUIRED_TRANSACTION_ISOLATION`]).
///
/// One pooled connection answers for all: the setting comes from the server,
/// database, and role, the same for every connection, since
/// `fuz_db::create_pool` forwards no per-connection options. It is read once,
/// at boot; a setting changed while the server runs reaches new connections
/// unchecked until the next restart.
///
/// # Errors
///
/// [`StartupError::Database`] when the connection or query fails;
/// [`StartupError::TransactionIsolation`] for any other setting.
pub async fn ensure_read_committed(pool: &Pool) -> Result<(), StartupError> {
    let client = pool.get().await.map_err(fuz_db::DbError::PoolGet)?;
    let row = client
        .query_one(
            "SELECT current_setting('default_transaction_isolation')",
            &[],
        )
        .await
        .map_err(fuz_db::DbError::from)?;
    check_transaction_isolation(row.get(0))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use super::*;

    #[test]
    fn the_keyring_refuses_absent_or_weak_keys() {
        for keys in [None, Some(""), Some("short")] {
            let error = build_keyring(keys).expect_err("refused");
            assert_eq!(error.exit_code(), 2, "{error}");
            assert!(
                error.to_string().contains("SECRET_FUZ_COOKIE_KEYS"),
                "{error}"
            );
        }
        build_keyring(Some("0123456789abcdef0123456789abcdef")).expect("a long key builds");
    }

    /// The env for a boot over `origins`, with the wildcard flag as given, and
    /// a database URL nothing answers at (port 1): a boot that gets past the
    /// allowlist fails reaching the database.
    fn wildcard_env(origins: &str, flag: Option<&str>) -> BaseServerEnv {
        BaseServerEnv::from_vars(
            &|k| match k {
                "DATABASE_URL" => Some("postgres://spine:spine@127.0.0.1:1/unused".to_owned()),
                "SECRET_FUZ_COOKIE_KEYS" => Some("0123456789abcdef0123456789abcdef".to_owned()),
                "FUZ_ALLOWED_ORIGINS" => Some(origins.to_owned()),
                "FUZ_ALLOW_ORIGIN_WILDCARDS" => flag.map(str::to_owned),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads")
    }

    async fn boot(env: &BaseServerEnv, gates: BrowserGateSpec) -> StartupError {
        let spec = AppBackendSpec {
            session_cookie_name: "spine_test_session",
            migration_namespaces: &[fuz_auth::AUTH_MIGRATIONS],
            expected_schema_json: None,
            audit_sse: None,
            browser_gates: gates,
        };
        match create_app_backend(
            env,
            &spec,
            SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new())),
        )
        .await
        {
            Ok(_) => panic!("nothing answers at the database URL"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    async fn the_boot_refuses_a_wildcard_origin_without_the_opt_in() {
        let gates = BrowserGateSpec {
            allowed_origins_var: "APP_ALLOWED_ORIGINS",
            host_gate: true,
            origin_wildcard_note: Some("The app note."),
            port_wildcard_note: Some("The port note."),
        };
        for flag in [None, Some("false")] {
            let error = boot(
                &wildcard_env("http://localhost, http://localhost:*", flag),
                gates,
            )
            .await;
            let StartupError::Config(message) = &error else {
                panic!("{flag:?}: expected a config error, got {error:?}");
            };
            assert_eq!(error.exit_code(), 2);
            assert!(
                message.starts_with(
                    "APP_ALLOWED_ORIGINS holds a wildcard entry, refused unless \
                     FUZ_ALLOW_ORIGIN_WILDCARDS=true. `http://localhost:*`: port wildcard: "
                ),
                "{message}"
            );
            // the text the server's gates shape
            assert!(
                message
                    .contains("The app note. The port note. The `Host` check answers to localhost"),
                "{message}"
            );
        }
    }

    #[tokio::test]
    async fn the_boot_admits_a_wildcard_origin_with_the_opt_in() {
        // past the allowlist, the boot reaches for the database
        let error = boot(
            &wildcard_env("http://localhost:*", Some("true")),
            BrowserGateSpec::DEFAULT,
        )
        .await;
        assert!(matches!(error, StartupError::Database(_)), "{error:?}");
        // and an exact list needs no opt-in
        let error = boot(
            &wildcard_env("http://localhost", None),
            BrowserGateSpec::DEFAULT,
        )
        .await;
        assert!(matches!(error, StartupError::Database(_)), "{error:?}");
    }

    #[test]
    fn the_backend_stack_options_carry_the_host_gate() {
        let env = wildcard_env("http://localhost", None);
        for host_gate in [false, true] {
            let spec = AppBackendSpec {
                session_cookie_name: "spine_test_session",
                migration_namespaces: &[],
                expected_schema_json: None,
                audit_sse: None,
                browser_gates: BrowserGateSpec {
                    host_gate,
                    ..BrowserGateSpec::DEFAULT
                },
            };
            let backend = build_app_backend(
                &env,
                &spec,
                &SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new())),
            )
            .expect("the core builds without the database");
            assert_eq!(backend.stack_options().host_gate, host_gate);
        }
    }

    /// The two checkout vars reach what they bound: the request var every step
    /// of the pool's own checkout (the wait, a new connection's connect, a
    /// reused one's recycle), the audit var the emitter's — and neither the
    /// other's.
    #[tokio::test]
    async fn the_checkout_vars_bound_the_pool_and_the_audit_emitter() {
        let env = BaseServerEnv::from_vars(
            &|k| match k {
                "DATABASE_URL" => Some("postgres://spine:spine@127.0.0.1:1/unused".to_owned()),
                "SECRET_FUZ_COOKIE_KEYS" => Some("0123456789abcdef0123456789abcdef".to_owned()),
                "FUZ_ALLOWED_ORIGINS" => Some("http://localhost".to_owned()),
                "FUZ_DB_CHECKOUT_TIMEOUT_MS" => Some("250".to_owned()),
                "FUZ_DB_AUDIT_CHECKOUT_TIMEOUT_MS" => Some("700".to_owned()),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads");
        let spec = AppBackendSpec {
            session_cookie_name: "spine_test_session",
            migration_namespaces: &[],
            expected_schema_json: None,
            audit_sse: None,
            browser_gates: BrowserGateSpec::DEFAULT,
        };
        let backend = build_app_backend(
            &env,
            &spec,
            &SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new())),
        )
        .expect("the core builds without the database");
        let request = Some(Duration::from_millis(250));
        let timeouts = backend.pool.timeouts();
        assert_eq!(
            (timeouts.wait, timeouts.create, timeouts.recycle),
            (request, request, request)
        );
        assert_eq!(
            backend.audit_emitter.checkout_timeout(),
            Duration::from_millis(700)
        );
    }

    /// `_testing_drain_effects` is a barrier only over the tracked emitter: a
    /// fire-and-forget write still in flight (here, stuck dialing a server
    /// that accepts the connection and never answers) holds the drain, and
    /// the untracked production emitter's drain returns at once.
    #[tokio::test]
    async fn audit_inflight_tracking_makes_the_drain_wait_for_a_write() {
        use fuz_auth::{AuditEventType, AuditLogInput};

        let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let url = format!(
            "postgres://spine:spine@{}/spine_unused",
            silent.local_addr().expect("has an address")
        );
        let env = BaseServerEnv::from_vars(
            &|k| match k {
                "DATABASE_URL" => Some(url.clone()),
                "SECRET_FUZ_COOKIE_KEYS" => Some("0123456789abcdef0123456789abcdef".to_owned()),
                "FUZ_ALLOWED_ORIGINS" => Some("http://localhost".to_owned()),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads");
        let spec = AppBackendSpec {
            session_cookie_name: "spine_test_session",
            migration_namespaces: &[],
            expected_schema_json: None,
            audit_sse: None,
            browser_gates: BrowserGateSpec::DEFAULT,
        };
        let build = |audit_inflight_tracking| {
            build_app_backend(
                &env,
                &spec,
                &SpineBackendOptions {
                    audit_inflight_tracking,
                    ..SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new()))
                },
            )
            .expect("the core builds without the database")
        };
        let emit = |backend: &AppBackend| {
            backend
                .audit_emitter
                .emit(AuditLogInput::for_event(AuditEventType::Logout))
        };

        let tracked = build(true);
        let write = emit(&tracked);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                tracked.audit_emitter.drain_inflight()
            )
            .await
            .is_err(),
            "the drain waits while the write is in flight"
        );
        write.abort();
        tokio::time::timeout(
            Duration::from_secs(5),
            tracked.audit_emitter.drain_inflight(),
        )
        .await
        .expect("the drain resolves once the write ends");

        let untracked = build(false);
        let write = emit(&untracked);
        tokio::time::timeout(
            Duration::from_millis(200),
            untracked.audit_emitter.drain_inflight(),
        )
        .await
        .expect("untracked, the drain returns at once");
        write.abort();
    }

    /// A revocation's row reaches the audit stream it revokes before the
    /// revocation listener ends that stream: the stream reads the row's frame,
    /// then ends.
    #[tokio::test]
    async fn a_revoked_stream_receives_its_revocation_row_then_ends() {
        use futures::StreamExt;

        let env = BaseServerEnv::from_vars(
            &|k| match k {
                "DATABASE_URL" => Some("postgres://unused@127.0.0.1:1/unused".to_owned()),
                "SECRET_FUZ_COOKIE_KEYS" => Some("0123456789abcdef0123456789abcdef".to_owned()),
                "FUZ_ALLOWED_ORIGINS" => Some("http://localhost".to_owned()),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads");
        let spec = AppBackendSpec {
            session_cookie_name: "spine_test_session",
            migration_namespaces: &[],
            expected_schema_json: None,
            audit_sse: Some(AuditSseSpec::DEFAULT),
            browser_gates: BrowserGateSpec::DEFAULT,
        };
        let backend = build_app_backend(
            &env,
            &spec,
            &SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new())),
        )
        .expect("the core builds without the database");
        register_audit_listeners(&backend);

        let sse = backend.audit_sse.as_ref().expect("the stream is mounted");
        let account_id = uuid::Uuid::new_v4();
        let mut stream = Box::pin(
            sse.admit(sse.subscribe_pending(fuz_realtime::SseSubscription {
                identity: fuz_realtime::ConnectionIdentity {
                    account_id: Some(account_id),
                    ..fuz_realtime::ConnectionIdentity::default()
                },
                credential_deadline: None,
            }))
            .expect("admitted"),
        );
        assert_eq!(
            stream.next().await.expect("open").expect("infallible"),
            fuz_realtime::SSE_CONNECTED_COMMENT
        );

        backend
            .audit_emitter
            .notify(Arc::new(fuz_auth::AuditLogEvent {
                id: uuid::Uuid::new_v4(),
                seq: 1,
                event_type: "logout".to_owned(),
                outcome: "success".to_owned(),
                actor_id: None,
                account_id: Some(account_id),
                target_account_id: None,
                target_actor_id: None,
                ip: None,
                created_at: "2026-01-01T00:00:00Z".to_owned(),
                metadata: None,
            }))
            .await;

        let frame = stream
            .next()
            .await
            .expect("the row's frame")
            .expect("infallible");
        assert!(
            frame.starts_with(r#"data: {"method":"logout","#),
            "the revocation row reached the stream first: {frame}"
        );
        assert!(stream.next().await.is_none(), "and then the stream ended");
    }

    /// The audit stream's keep-alive interval is the spec's: an admitted stream
    /// on a backend built with a short interval writes the keep-alive comment
    /// at it, one built with `None` writes none, and an interval the registry
    /// would refuse is a configuration error at boot, not a panic.
    #[tokio::test(start_paused = true)]
    async fn the_audit_stream_keep_alive_is_the_specs() {
        use std::convert::Infallible;
        use std::pin::Pin;

        use futures::{Stream, StreamExt};

        fn open(backend: &AppBackend) -> Pin<Box<impl Stream<Item = Result<String, Infallible>>>> {
            let sse = backend.audit_sse.as_ref().expect("the stream is mounted");
            Box::pin(
                sse.admit(sse.subscribe_pending(fuz_realtime::SseSubscription {
                    identity: fuz_realtime::ConnectionIdentity::default(),
                    credential_deadline: None,
                }))
                .expect("admitted"),
            )
        }

        let env = BaseServerEnv::from_vars(
            &|k| match k {
                "DATABASE_URL" => Some("postgres://unused@127.0.0.1:1/unused".to_owned()),
                "SECRET_FUZ_COOKIE_KEYS" => Some("0123456789abcdef0123456789abcdef".to_owned()),
                "FUZ_ALLOWED_ORIGINS" => Some("http://localhost".to_owned()),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads");
        let build = |keep_alive| {
            build_app_backend(
                &env,
                &AppBackendSpec {
                    session_cookie_name: "spine_test_session",
                    migration_namespaces: &[],
                    expected_schema_json: None,
                    audit_sse: Some(AuditSseSpec { keep_alive }),
                    browser_gates: BrowserGateSpec::DEFAULT,
                },
                &SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new())),
            )
        };

        assert_eq!(
            AuditSseSpec::default().keep_alive,
            Some(fuz_realtime::SSE_KEEP_ALIVE_INTERVAL)
        );

        let short = build(Some(Duration::from_secs(1))).expect("a valid interval");
        let mut stream = open(&short);
        assert_eq!(
            stream.next().await.expect("open").expect("infallible"),
            fuz_realtime::SSE_CONNECTED_COMMENT
        );
        let keep_alive = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("a keep-alive within the short interval")
            .expect("open")
            .expect("infallible");
        assert_eq!(keep_alive, fuz_realtime::SSE_KEEP_ALIVE_COMMENT);

        let off = build(None).expect("off is valid");
        let mut stream = open(&off);
        assert_eq!(
            stream.next().await.expect("open").expect("infallible"),
            fuz_realtime::SSE_CONNECTED_COMMENT
        );
        assert!(
            tokio::time::timeout(10 * fuz_realtime::SSE_KEEP_ALIVE_INTERVAL, stream.next())
                .await
                .is_err(),
            "keep-alives off: an idle stream writes nothing"
        );

        for refused in [
            Duration::ZERO,
            fuz_realtime::SSE_KEEP_ALIVE_INTERVAL_MAX + Duration::from_millis(1),
        ] {
            let error = build(Some(refused)).expect_err("refused at boot");
            assert!(matches!(error, StartupError::Config(_)), "{error}");
            assert_eq!(error.exit_code(), 2, "{error}");
        }
    }

    /// The login IP bound is the option's, built through the mode: a server
    /// that raises it gets its bound, and the testing mode builds none.
    #[test]
    fn the_login_ip_limiter_takes_its_bound_from_the_options() {
        let env = BaseServerEnv::from_vars(
            &|k| match k {
                "DATABASE_URL" => Some("postgres://localhost:1/spine_unused".to_owned()),
                "SECRET_FUZ_COOKIE_KEYS" => Some("0123456789abcdef0123456789abcdef".to_owned()),
                "FUZ_ALLOWED_ORIGINS" => Some("http://localhost".to_owned()),
                _ => None,
            },
            fuz_http::ServerEnvOptions {
                trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
            },
        )
        .expect("the env reads");
        let spec = AppBackendSpec {
            session_cookie_name: "spine_test_session",
            migration_namespaces: &[],
            expected_schema_json: None,
            audit_sse: None,
            browser_gates: BrowserGateSpec::DEFAULT,
        };
        let build = |rate_limiters, max_attempts| {
            build_app_backend(
                &env,
                &spec,
                &SpineBackendOptions {
                    rate_limiters,
                    login_ip_rate_limit: RateLimiterOptions {
                        max_attempts,
                        ..fuz_auth::DEFAULT_LOGIN_IP_RATE_LIMIT
                    },
                    ..SpineBackendOptions::production(Arc::new(fuz_auth::Argon2idHasher::new()))
                },
            )
            .expect("the core builds without the database")
        };
        let limiter = build(RateLimiterMode::Enforced, 2)
            .login_ip_rate_limiter
            .expect("enforced");
        limiter.record("k");
        assert!(limiter.check("k").is_allowed());
        limiter.record("k");
        assert!(!limiter.check("k").is_allowed(), "the option's bound of 2");
        assert!(
            build(RateLimiterMode::DisabledForTesting, 2)
                .login_ip_rate_limiter
                .is_none()
        );
    }

    #[test]
    fn a_malformed_expected_schema_is_a_build_defect() {
        let error = parse_expected_schema("{not json").expect_err("malformed");
        assert!(matches!(error, StartupError::ExpectedSchema(_)), "{error}");
        assert_eq!(error.exit_code(), 1);
        let schema = parse_expected_schema(r#"{"account":["id"]}"#).expect("a column map");
        assert_eq!(schema.len(), 1);
    }

    /// The boot refuses a chain that doesn't start with auth, or that gives a
    /// consumer namespace a reserved spine name, with a config error naming it.
    #[test]
    fn the_migration_chain_starts_with_auth_and_reserves_spine_names() {
        const APP: MigrationNamespace = MigrationNamespace::new("my_app", &[]);
        check_migration_chain(&[fuz_auth::AUTH_MIGRATIONS, APP]).expect("auth, then the app");
        for chain in [&[][..], &[APP, fuz_auth::AUTH_MIGRATIONS][..]] {
            let error = check_migration_chain(chain).expect_err("auth must come first");
            assert_eq!(error.exit_code(), 2, "{error}");
            assert!(error.to_string().contains("AUTH_MIGRATIONS"), "{error}");
        }
        for name in fuz_db::RESERVED_NAMESPACES {
            let error = check_migration_chain(&[
                fuz_auth::AUTH_MIGRATIONS,
                MigrationNamespace::new(name, &[]),
            ])
            .expect_err("a consumer namespace under a spine name");
            assert_eq!(error.exit_code(), 2, "{error}");
            assert!(
                error.to_string().contains(&format!("\"{name}\"")),
                "{error}"
            );
        }
    }
}
