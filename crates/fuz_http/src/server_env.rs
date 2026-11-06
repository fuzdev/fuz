//! [`BaseServerEnv`] — the env vars every spine server reads the same way.
//!
//! The Rust twin of `fuz_app`'s `BaseServerEnv` (`server/env.ts`): the bind
//! pair (`HOST` / `PORT`), `DATABASE_URL`, `SECRET_FUZ_COOKIE_KEYS`,
//! `FUZ_ALLOWED_ORIGINS`, `FUZ_ALLOW_ORIGIN_WILDCARDS`,
//! `FUZ_BOOTSTRAP_TOKEN_PATH`, and the consumer's trusted-proxy list, whose
//! var name is the one per-consumer part
//! ([`ServerEnvOptions::trusted_proxies_var`]). A consumer with vars of its own
//! reads them beside this through the same lookup and keeps them in its own
//! struct.
//!
//! Read through [`BaseServerEnv::from_vars`], which takes the var lookup, so a
//! test injects a map instead of mutating process env.
//!
//! The rules, each fail-loud where a wrong value is security-consequential:
//!
//! - `FUZ_ALLOWED_ORIGINS` is required: absent, blank, or with any malformed
//!   entry, the read fails naming the var ([`crate::AllowedOrigins::parse`]).
//! - `FUZ_ALLOW_ORIGIN_WILDCARDS` is exactly `true` or `false` when set — any
//!   other value fails the read ([`crate::parse_allow_origin_wildcards`]). Only
//!   `true` lets a wildcard allowlist entry boot; the boot
//!   (`fuz_actions::server::create_app_backend`) refuses one otherwise.
//! - The trusted-proxy list defaults to loopback (`127.0.0.1`, `::1`) when
//!   unset or empty — the shape of a server behind its own nginx — and a
//!   malformed entry fails the read. A value that parses to no entries (`,`)
//!   is the explicit opt-out: no `X-Forwarded-For` trust.
//! - `HOST` blank is unset. `PORT` must parse as a port when set; a blank
//!   `PORT` is refused like any other malformed value, since a deploy template
//!   that rendered it empty is a bug the server should not paper over with
//!   its default port.
//! - `~` in `FUZ_BOOTSTRAP_TOKEN_PATH` expands through
//!   [`fuz_sys::expand_tilde`], the one home lookup.
//! - `FUZ_DB_CHECKOUT_TIMEOUT_MS` (default 5000) bounds the pool checkouts a
//!   request makes, and `FUZ_DB_AUDIT_CHECKOUT_TIMEOUT_MS` (default 30000)
//!   the checkout behind each of the audit emitter's pool writes — the
//!   failed-login row a request waits on included, so that request can wait up
//!   to the audit bound. Each is a whole number of milliseconds in
//!   `1..=600000` when set; anything else, blank included, fails the read
//!   naming the var — there is no "0 = off" (the TS twin's `z.coerce` reads
//!   `5e3` as 5000; this reader refuses it, as it does for `PORT`).
//!
//! The cookie keys and database URL are carried as read; the keyring and the
//! pool are built from them by the server, which knows whether it needs them.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use crate::{AllowedOrigins, ParsedProxy};

/// The env var holding the origin allowlist ([`BaseServerEnv::allowed_origins`]).
pub const ALLOWED_ORIGINS_VAR: &str = "FUZ_ALLOWED_ORIGINS";

/// The trusted-proxy list when its var is unset or empty: the loopback nginx
/// hop, in both families.
pub const DEFAULT_TRUSTED_PROXIES: &str = "127.0.0.1,::1";

/// The env var bounding every request's pool checkout
/// ([`BaseServerEnv::db_checkout_timeout`]).
pub const DB_CHECKOUT_TIMEOUT_VAR: &str = "FUZ_DB_CHECKOUT_TIMEOUT_MS";

/// The env var bounding the checkout behind each audit pool write
/// ([`BaseServerEnv::db_audit_checkout_timeout`]).
pub const DB_AUDIT_CHECKOUT_TIMEOUT_VAR: &str = "FUZ_DB_AUDIT_CHECKOUT_TIMEOUT_MS";

/// The largest checkout timeout either var admits, in milliseconds (10 minutes).
pub const DB_CHECKOUT_TIMEOUT_MAX_MS: u64 = 600_000;

/// A var that failed to read: the message names the var and the reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ServerEnvError(pub String);

/// The per-consumer part of [`BaseServerEnv::from_vars`].
#[derive(Debug, Clone, Copy)]
pub struct ServerEnvOptions {
    /// The trusted-proxy var, prefixed per consumer
    /// (`FUZ_FORGE_TRUSTED_PROXIES`, or an app's own `FUZ_<APP>_TRUSTED_PROXIES`).
    pub trusted_proxies_var: &'static str,
}

/// The env every spine server reads, validated.
///
/// `Debug` shows only whether `database_url` and `cookie_keys` are set — the
/// URL can carry the database password.
#[derive(Clone)]
pub struct BaseServerEnv {
    /// `DATABASE_URL`. Absent → the server runs boot-only (no database).
    pub database_url: Option<String>,
    /// `SECRET_FUZ_COOKIE_KEYS`, as read: `__`-separated cookie-signing keys.
    pub cookie_keys: Option<String>,
    /// `HOST`, `None` when unset or blank.
    pub host: Option<String>,
    /// `PORT`, `None` when unset.
    pub port: Option<u16>,
    /// `FUZ_ALLOWED_ORIGINS` — required, never empty.
    pub allowed_origins: AllowedOrigins,
    /// `FUZ_ALLOW_ORIGIN_WILDCARDS` — whether a wildcard entry in
    /// `allowed_origins` may boot ([`crate::admit_origin_wildcards`]); `false`
    /// when unset.
    pub allow_origin_wildcards: bool,
    /// The consumer's trusted-proxy list, loopback when unset.
    pub trusted_proxies: Vec<ParsedProxy>,
    /// `FUZ_BOOTSTRAP_TOKEN_PATH`, `~` expanded.
    pub bootstrap_token_path: Option<PathBuf>,
    /// `FUZ_DB_CHECKOUT_TIMEOUT_MS` — the bound on the pool checkouts a
    /// request makes; [`fuz_db::DEFAULT_CHECKOUT_TIMEOUT`] when unset. Audit
    /// writes use [`Self::db_audit_checkout_timeout`] instead, the
    /// failed-login row a request waits on included.
    pub db_checkout_timeout: Duration,
    /// `FUZ_DB_AUDIT_CHECKOUT_TIMEOUT_MS` — the bound on the checkout behind
    /// each audit pool write; [`fuz_db::DEFAULT_AUDIT_CHECKOUT_TIMEOUT`] when
    /// unset. A failed login awaits its row, so it can wait up to this bound.
    pub db_audit_checkout_timeout: Duration,
}

impl std::fmt::Debug for BaseServerEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaseServerEnv")
            .field("database_url_set", &self.database_url.is_some())
            .field("cookie_keys_set", &self.cookie_keys.is_some())
            .field("host", &self.host)
            .field("port", &self.port)
            .field("allowed_origins", &self.allowed_origins)
            .field("allow_origin_wildcards", &self.allow_origin_wildcards)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("bootstrap_token_path", &self.bootstrap_token_path)
            .field("db_checkout_timeout", &self.db_checkout_timeout)
            .field("db_audit_checkout_timeout", &self.db_audit_checkout_timeout)
            .finish()
    }
}

impl BaseServerEnv {
    /// Read and validate from `get`, a var lookup (`|k| std::env::var(k).ok()`
    /// in production, a map in tests).
    ///
    /// # Errors
    ///
    /// [`ServerEnvError`] naming the var, for an absent or malformed
    /// `FUZ_ALLOWED_ORIGINS`, a `FUZ_ALLOW_ORIGIN_WILDCARDS` other than `true`
    /// or `false`, a malformed trusted-proxy list, a `PORT` that is not a
    /// port, or a checkout timeout that is not a whole number of milliseconds
    /// in `1..=600000`.
    pub fn from_vars(
        get: &impl Fn(&str) -> Option<String>,
        options: ServerEnvOptions,
    ) -> Result<Self, ServerEnvError> {
        let port = match get("PORT") {
            None => None,
            Some(s) => Some(
                s.trim()
                    .parse::<u16>()
                    .map_err(|e| ServerEnvError(format!("PORT: {e}")))?,
            ),
        };
        let allowed_origins = AllowedOrigins::parse(&get(ALLOWED_ORIGINS_VAR).unwrap_or_default())
            .map_err(|e| ServerEnvError(format!("{ALLOWED_ORIGINS_VAR}: {e}")))?;
        let allow_origin_wildcards =
            crate::parse_allow_origin_wildcards(get(crate::ALLOW_ORIGIN_WILDCARDS_VAR).as_deref())?;
        let var = options.trusted_proxies_var;
        let trusted_proxies = crate::parse_proxy_list(
            &get(var)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_TRUSTED_PROXIES.to_owned()),
        )
        .map_err(|e| ServerEnvError(format!("{var}: {e}")))?;
        Ok(Self {
            database_url: get("DATABASE_URL"),
            cookie_keys: get("SECRET_FUZ_COOKIE_KEYS"),
            host: get("HOST").filter(|s| !s.trim().is_empty()),
            port,
            allowed_origins,
            allow_origin_wildcards,
            trusted_proxies,
            bootstrap_token_path: get("FUZ_BOOTSTRAP_TOKEN_PATH")
                .map(|s| fuz_sys::expand_tilde(&s)),
            db_checkout_timeout: parse_checkout_timeout(
                get,
                DB_CHECKOUT_TIMEOUT_VAR,
                fuz_db::DEFAULT_CHECKOUT_TIMEOUT,
            )?,
            db_audit_checkout_timeout: parse_checkout_timeout(
                get,
                DB_AUDIT_CHECKOUT_TIMEOUT_VAR,
                fuz_db::DEFAULT_AUDIT_CHECKOUT_TIMEOUT,
            )?,
        })
    }

    /// Read and validate from the process env.
    ///
    /// # Errors
    ///
    /// As [`Self::from_vars`].
    pub fn from_process(options: ServerEnvOptions) -> Result<Self, ServerEnvError> {
        Self::from_vars(&|key| std::env::var(key).ok(), options)
    }

    /// The address to bind: `default_addr` when neither `HOST` nor `PORT` is
    /// set, else the pair with the missing half taken from `default_addr`. A
    /// set `HOST` resolves through `ToSocketAddrs` (`localhost`,
    /// `127.0.0.1`, ...), first address wins.
    ///
    /// # Errors
    ///
    /// [`ServerEnvError`] when `HOST` resolves to no address.
    pub fn bind_addr(&self, default_addr: SocketAddr) -> Result<SocketAddr, ServerEnvError> {
        let port = self.port.unwrap_or_else(|| default_addr.port());
        let Some(host) = &self.host else {
            return Ok(SocketAddr::new(default_addr.ip(), port));
        };
        (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| ServerEnvError(format!("HOST/PORT '{host}:{port}': {e}")))?
            .next()
            .ok_or_else(|| ServerEnvError(format!("HOST '{host}' resolved to no addresses")))
    }
}

/// Read a checkout-timeout var.
///
/// [`DB_CHECKOUT_TIMEOUT_VAR`] or [`DB_AUDIT_CHECKOUT_TIMEOUT_VAR`]: `default`
/// when unset, else a whole number of milliseconds from 1 to
/// [`DB_CHECKOUT_TIMEOUT_MAX_MS`], read the way `PORT` is (trimmed, then
/// parsed — a blank value is refused). Public for a server that reads its own
/// env and builds [`BaseServerEnv`] by hand (zzz).
///
/// # Errors
///
/// [`ServerEnvError`] naming `var` when the value is malformed or out of range.
pub fn parse_checkout_timeout(
    get: &impl Fn(&str) -> Option<String>,
    var: &str,
    default: Duration,
) -> Result<Duration, ServerEnvError> {
    let Some(value) = get(var) else {
        return Ok(default);
    };
    let ms = value
        .trim()
        .parse::<u64>()
        .map_err(|e| ServerEnvError(format!("{var}: {e}")))?;
    if !(1..=DB_CHECKOUT_TIMEOUT_MAX_MS).contains(&ms) {
        return Err(ServerEnvError(format!(
            "{var}: must be between 1 and {DB_CHECKOUT_TIMEOUT_MAX_MS} milliseconds, got {ms}"
        )));
    }
    Ok(Duration::from_millis(ms))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on assertion failure by design"
)]
mod tests {
    use std::collections::HashMap;

    use std::net::IpAddr;

    use super::*;

    const OPTIONS: ServerEnvOptions = ServerEnvOptions {
        trusted_proxies_var: "FUZ_TEST_TRUSTED_PROXIES",
    };

    fn read(pairs: &[(&str, &str)]) -> Result<BaseServerEnv, ServerEnvError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        BaseServerEnv::from_vars(&|k| map.get(k).cloned(), OPTIONS)
    }

    /// `read` with a valid allowlist added unless the pairs carry one.
    fn env(pairs: &[(&str, &str)]) -> BaseServerEnv {
        let mut pairs = pairs.to_vec();
        if !pairs.iter().any(|(k, _)| *k == "FUZ_ALLOWED_ORIGINS") {
            pairs.push(("FUZ_ALLOWED_ORIGINS", "http://localhost"));
        }
        read(&pairs).expect("the env reads")
    }

    const DEFAULT_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 4041);

    #[test]
    fn reads_the_canonical_var_names() {
        let env = env(&[
            ("DATABASE_URL", "postgres://localhost/x"),
            ("SECRET_FUZ_COOKIE_KEYS", "k"),
            ("HOST", "127.0.0.1"),
            ("PORT", "14041"),
            ("FUZ_ALLOWED_ORIGINS", "http://a.example, http://b.example"),
            ("FUZ_BOOTSTRAP_TOKEN_PATH", "/tmp/bt"),
        ]);
        assert_eq!(env.database_url.as_deref(), Some("postgres://localhost/x"));
        assert_eq!(env.cookie_keys.as_deref(), Some("k"));
        assert_eq!(
            env.bind_addr(DEFAULT_ADDR).unwrap(),
            "127.0.0.1:14041".parse::<SocketAddr>().unwrap()
        );
        let origins: Vec<&str> = env
            .allowed_origins
            .patterns()
            .iter()
            .map(crate::OriginPattern::as_str)
            .collect();
        assert_eq!(origins, ["http://a.example", "http://b.example"]);
        assert_eq!(env.bootstrap_token_path, Some(PathBuf::from("/tmp/bt")));
    }

    #[test]
    fn the_wildcard_flag_reads_strictly() {
        assert!(!env(&[]).allow_origin_wildcards);
        assert!(!env(&[("FUZ_ALLOW_ORIGIN_WILDCARDS", "false")]).allow_origin_wildcards);
        assert!(env(&[("FUZ_ALLOW_ORIGIN_WILDCARDS", "true")]).allow_origin_wildcards);
        for value in ["", "1", "TRUE", "yes"] {
            let error = read(&[
                ("FUZ_ALLOWED_ORIGINS", "http://localhost"),
                ("FUZ_ALLOW_ORIGIN_WILDCARDS", value),
            ])
            .expect_err(value);
            assert!(
                error.0.starts_with("FUZ_ALLOW_ORIGIN_WILDCARDS: "),
                "{value:?}: {error}"
            );
        }
        // reading the env refuses no wildcard: the boot does, flag in hand
        assert!(!env(&[("FUZ_ALLOWED_ORIGINS", "http://localhost:*")]).allow_origin_wildcards);
    }

    #[test]
    fn the_checkout_timeouts_default_and_read_like_port() {
        let defaults = env(&[]);
        assert_eq!(defaults.db_checkout_timeout, Duration::from_secs(5));
        assert_eq!(defaults.db_audit_checkout_timeout, Duration::from_secs(30));
        let set = env(&[
            ("FUZ_DB_CHECKOUT_TIMEOUT_MS", " 250 "),
            ("FUZ_DB_AUDIT_CHECKOUT_TIMEOUT_MS", "600000"),
        ]);
        assert_eq!(set.db_checkout_timeout, Duration::from_millis(250));
        assert_eq!(set.db_audit_checkout_timeout, Duration::from_secs(600));
        assert_eq!(
            env(&[("FUZ_DB_CHECKOUT_TIMEOUT_MS", "1")]).db_checkout_timeout,
            Duration::from_millis(1)
        );
        for var in [
            "FUZ_DB_CHECKOUT_TIMEOUT_MS",
            "FUZ_DB_AUDIT_CHECKOUT_TIMEOUT_MS",
        ] {
            for value in ["0", "-1", "abc", "600001", "", "  ", "5e3", "1.5"] {
                let error = read(&[("FUZ_ALLOWED_ORIGINS", "http://localhost"), (var, value)])
                    .expect_err(value);
                assert!(
                    error.0.starts_with(&format!("{var}: ")),
                    "{value:?}: {error}"
                );
            }
        }
    }

    #[test]
    fn debug_redacts_the_database_url_and_cookie_keys() {
        let env = env(&[
            ("DATABASE_URL", "postgres://u:db-password-Xc7@db.internal/x"),
            ("SECRET_FUZ_COOKIE_KEYS", "cookie-secret-Qz9"),
        ]);
        let rendered = format!("{env:?}");
        for secret in ["db-password-Xc7", "db.internal", "cookie-secret-Qz9"] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(rendered.contains("database_url_set: true"), "{rendered}");
        assert!(rendered.contains("cookie_keys_set: true"), "{rendered}");
    }

    #[test]
    fn the_bind_falls_back_to_the_default_by_halves() {
        assert_eq!(env(&[]).bind_addr(DEFAULT_ADDR).unwrap(), DEFAULT_ADDR);
        assert_eq!(
            env(&[("HOST", "  ")]).bind_addr(DEFAULT_ADDR).unwrap(),
            DEFAULT_ADDR,
            "a blank HOST is unset"
        );
        assert_eq!(
            env(&[("PORT", "12345")]).bind_addr(DEFAULT_ADDR).unwrap(),
            SocketAddr::new(DEFAULT_ADDR.ip(), 12345)
        );
        assert_eq!(
            env(&[("HOST", "0.0.0.0")]).bind_addr(DEFAULT_ADDR).unwrap(),
            "0.0.0.0:4041".parse::<SocketAddr>().unwrap(),
            "the port half comes from the caller's default"
        );
        let other_default: SocketAddr = "127.0.0.1:4141".parse().unwrap();
        assert_eq!(
            env(&[("HOST", "127.0.0.1")])
                .bind_addr(other_default)
                .unwrap(),
            other_default
        );
    }

    #[test]
    fn a_malformed_or_blank_port_is_refused() {
        for port in ["not-a-port", "", "  ", "70000"] {
            let err =
                read(&[("FUZ_ALLOWED_ORIGINS", "http://localhost"), ("PORT", port)]).unwrap_err();
            assert!(err.0.starts_with("PORT: "), "{port:?}: {err}");
        }
    }

    #[test]
    fn a_missing_or_malformed_allowlist_is_refused() {
        for value in [None, Some("  , "), Some("https://ok.example,null")] {
            let pairs: Vec<(&str, &str)> = value
                .map(|v| vec![("FUZ_ALLOWED_ORIGINS", v)])
                .unwrap_or_default();
            let err = read(&pairs).unwrap_err();
            assert!(
                err.0.starts_with("FUZ_ALLOWED_ORIGINS: "),
                "{value:?}: {err}"
            );
        }
    }

    #[test]
    fn trusted_proxies_default_to_loopback() {
        assert_eq!(env(&[]).trusted_proxies.len(), 2, "127.0.0.1 and ::1");
        assert_eq!(
            env(&[("FUZ_TEST_TRUSTED_PROXIES", "")])
                .trusted_proxies
                .len(),
            2,
            "empty is unset"
        );
        assert_eq!(
            env(&[("FUZ_TEST_TRUSTED_PROXIES", "10.0.0.0/8")])
                .trusted_proxies
                .len(),
            1
        );
        assert!(
            env(&[("FUZ_TEST_TRUSTED_PROXIES", ",")])
                .trusted_proxies
                .is_empty(),
            "`,` is the explicit opt-out"
        );
    }

    #[test]
    fn a_malformed_proxy_list_is_refused_naming_the_consumer_var() {
        let err = read(&[
            ("FUZ_ALLOWED_ORIGINS", "http://localhost"),
            ("FUZ_TEST_TRUSTED_PROXIES", "not-an-ip"),
        ])
        .unwrap_err();
        assert!(err.0.starts_with("FUZ_TEST_TRUSTED_PROXIES: "), "{err}");
    }

    #[test]
    fn the_bootstrap_token_path_expands_a_leading_tilde() {
        let Ok(home) = fuz_sys::home_dir() else {
            return; // no usable home: the path stays verbatim
        };
        assert_eq!(
            env(&[("FUZ_BOOTSTRAP_TOKEN_PATH", "~/bt")]).bootstrap_token_path,
            Some(home.join("bt"))
        );
        assert_eq!(
            env(&[("FUZ_BOOTSTRAP_TOKEN_PATH", "~other/bt")]).bootstrap_token_path,
            Some(PathBuf::from("~other/bt")),
            "`~user` does not expand"
        );
    }
}
