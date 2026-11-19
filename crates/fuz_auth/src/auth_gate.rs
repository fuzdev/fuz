//! [`AuthGate`] — the one front door every spine entry point checks a request
//! at: the origin allowlist, then the credential walk.
//!
//! Every surface that reads request headers into an identity goes through a
//! gate's methods — the RPC transports, the WS upgrade, the account REST
//! routes, the audit SSE stream, the db-admin browser, both fact reads, and a
//! consumer's own hand-written routes. The credential walk
//! (daemon-token → cookie → bearer) is reachable no other way outside this
//! crate, so a new surface cannot resolve a credential without holding a gate,
//! and the gate it holds carries the origin allowlist beside the walk.
//!
//! ## Why the steps stay separate
//!
//! [`AuthGate::preflight`] fuses the two checks for a surface that does
//! nothing between them. The steps are also callable alone, because some
//! surfaces have work that must sit between them:
//!
//! - `/password` charges its per-IP limiter after the origin check and before
//!   the credential walk touches the database.
//! - The RPC transports parse and route the envelope (a WS-only method, a
//!   side-effecting method over `GET`) before resolving.
//! - The REST surfaces that mirror the TS pipeline validate route params and
//!   the query shape between the two.
//!
//! The origin check comes first on every surface: a page from a foreign
//! origin is refused before any query is parsed or any credential read. It is
//! the in-handler half of a belt the stack's `origin_layer` also wears
//! (`fuz_http::compose_stack`), so a router mounted outside that stack — or
//! under a carve-out — still refuses a foreign page on a credentialed surface.
//!
//! ## The order is a type rule
//!
//! [`AuthGate::check_origin`] answers with an [`OriginChecked`] witness that
//! nothing else can construct and that holds the very headers it admitted.
//! Both credential reads ([`AuthGate::resolve_credential`],
//! [`AuthGate::public_request_context`]) take the witness in place of the
//! headers, so a credential is read only from a request the origin check
//! admitted, and only after it ran; what the type cannot see — that a
//! surface calls the gate at all — the `token_scope_surface_census` test
//! guards.

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use deadpool_postgres::Pool;
use fuz_http::{AllowedOrigins, CookieClearHook};

use crate::daemon_token::SharedDaemonTokenState;
use crate::keyring::Keyring;
use crate::request_context::RequestActorContext;
use crate::resolve::{
    CredentialReadFault, PublicContextFault, ResolvedAuth, build_public_request_context,
    resolve_auth_from_headers,
};
use crate::session_cookie::{
    SessionCookieRead, format_session_clear_cookie, parse_session_from_cookies,
};

/// The auth scope: the paths under which the spine reads and mints
/// credentials.
///
/// `fuz_app`'s `AUTH_MIDDLEWARE_PATH`, where its session, bearer, and
/// daemon-token middleware mount. Every spine route that reads a credential is
/// written under it (the account routes, the RPC and WebSocket endpoints, the
/// audit stream, the fact reads), and it is where an invalid session cookie is
/// cleared ([`AuthGate::cookie_clear_hook`]).
///
/// The pattern is the TS twin's: a path prefix and `/*`.
/// [`auth_middleware_applies`] reads it.
pub const AUTH_MIDDLEWARE_PATH: &str = "/api/*";

/// Whether `path` is under the auth scope ([`AUTH_MIDDLEWARE_PATH`]).
///
/// Under it: the bare prefix (`/api`) or anything below it (`/api/`,
/// `/api/x`). A path that only starts with the prefix's letters (`/apix`) is
/// outside, and the match is case-sensitive — what the TS twin's router
/// matches `/api/*` against.
///
/// `path` is a request's `Uri::path`, as the router reads it: raw — not
/// percent-decoded, dot segments kept. The TS twin's clear follows its own
/// router's reading instead (percent-decoded, dot segments resolved), so the
/// two differ on spellings a browser never sends: `/%61pi/x` and `/./api/x`
/// are cleared there and not here, `/api/../health` here and not there. Left
/// unconverged on purpose — each spine clears exactly where its own router
/// puts the auth scope.
#[must_use]
pub fn auth_middleware_applies(path: &str) -> bool {
    let prefix = AUTH_MIDDLEWARE_PATH
        .strip_suffix("/*")
        .unwrap_or(AUTH_MIDDLEWARE_PATH);
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Proof that [`AuthGate::check_origin`] admitted a request's headers — what
/// every credential read takes in place of the headers.
///
/// A borrow of the admitted `HeaderMap` behind a private field, so only
/// `check_origin` makes one, and a credential read sees exactly the headers
/// that were checked. Not `Clone`: one check admits one credential read.
///
/// Its `Debug` prints how many headers it holds, never the headers — they
/// carry the request's `Cookie` and `Authorization`.
#[must_use = "an origin check's witness is what a credential read takes"]
pub struct OriginChecked<'h> {
    headers: &'h HeaderMap,
}

impl std::fmt::Debug for OriginChecked<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginChecked")
            .field("header_count", &self.headers.len())
            .finish_non_exhaustive()
    }
}

impl<'h> OriginChecked<'h> {
    /// The headers the origin check admitted.
    #[must_use]
    pub const fn headers(&self) -> &'h HeaderMap {
        self.headers
    }
}

/// The origin allowlist and the credential walk, held together.
///
/// Built once at startup and cloned into every route state that reads a
/// request's identity — every field is an `Arc`, an `Arc`-backed pool, or
/// `Copy`, so a clone is cheap. The route states read the pool, keyring, and
/// cookie name through it too, so one value configures a server's whole
/// front door.
#[derive(Clone)]
pub struct AuthGate {
    /// The pool the credential walk reads, and the route states' pool.
    pub pool: Pool,
    /// The cookie-signing keyring the cookie leg verifies with.
    pub keyring: Arc<Keyring>,
    /// The daemon-token state the walk tries first; `None` in every
    /// production assembly (only `fuz_testing` mints the credential).
    pub daemon_token_state: Option<SharedDaemonTokenState>,
    /// The per-app session cookie name (default [`crate::SESSION_COOKIE_NAME`]).
    pub session_cookie_name: &'static str,
    /// The validated origin allowlist [`check_origin`](Self::check_origin)
    /// reads.
    pub allowed_origins: AllowedOrigins,
}

impl std::fmt::Debug for AuthGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthGate")
            .field("session_cookie_name", &self.session_cookie_name)
            .field("has_daemon_token", &self.daemon_token_state.is_some())
            .field("allowed_origins", &self.allowed_origins)
            .finish_non_exhaustive()
    }
}

impl AuthGate {
    /// The [`fuz_http::StackOptions`] for this gate's server, reading the
    /// gate's own allowlist — so the stack's `origin_layer` and the gate's
    /// in-handler check cannot drift apart — and carrying the gate's
    /// [`cookie_clear_hook`](Self::cookie_clear_hook). Request tracing and the
    /// host gate on ([`fuz_http::StackOptions::new`]); set the flags on the
    /// result.
    #[must_use]
    pub fn stack_options(
        &self,
        trusted_proxies: Arc<Vec<fuz_http::ParsedProxy>>,
    ) -> fuz_http::StackOptions {
        fuz_http::StackOptions {
            cookie_clear: Some(self.cookie_clear_hook()),
            ..fuz_http::StackOptions::new(self.allowed_origins.clone(), trusted_proxies)
        }
    }

    /// The stack's cookie-clear hook for this gate's session cookie
    /// ([`fuz_http::StackOptions::cookie_clear`]): a request under the auth
    /// scope ([`auth_middleware_applies`]) whose session cookie is present
    /// and invalid ([`SessionCookieRead::Invalid`]) gets the clearing
    /// `Set-Cookie` ([`format_session_clear_cookie`]) on its response.
    ///
    /// "Invalid" is what the cookie alone shows — unreadable, a bad MAC, a
    /// signed expiry that has passed, an empty identity, an empty value. A
    /// request with no session cookie clears nothing, and neither does a
    /// validly signed one whose `auth_session` row is gone. The clear does not
    /// depend on which credential authenticates the request: an invalid
    /// cookie beside a winning daemon token or bearer is still cleared, as on
    /// the TS twin.
    ///
    /// The stack mounts the hook inside the origin check and writes its
    /// answer on every response but an accepted upgrade, ahead of the
    /// handler's own `Set-Cookie` ([`fuz_http::cookie_clear`]).
    ///
    /// A cookie name that is not an RFC 6265 `cookie-name` has no clearing
    /// string; the hook then clears nothing and says so at `error`. The
    /// server toolkit refuses such a name at boot.
    #[must_use]
    pub fn cookie_clear_hook(&self) -> CookieClearHook {
        let keyring = Arc::clone(&self.keyring);
        let cookie_name = self.session_cookie_name;
        let clear = format_session_clear_cookie(cookie_name)
            .ok()
            .and_then(|clear| HeaderValue::try_from(clear).ok());
        if clear.is_none() {
            tracing::error!(
                cookie_name,
                "the session cookie name is not an RFC 6265 cookie-name; an invalid session \
                 cookie will not be cleared"
            );
        }
        CookieClearHook::new(move |path, headers| {
            let clear = clear.as_ref()?;
            if !auth_middleware_applies(path) {
                return None;
            }
            matches!(
                parse_session_from_cookies(headers, &keyring, cookie_name),
                SessionCookieRead::Invalid
            )
            .then(|| clear.clone())
        })
    }

    /// Refuse a request from a foreign origin: `Ok` when it carries no
    /// `Origin`, or exactly one the allowlist admits
    /// ([`AllowedOrigins::allows_request`]), with the [`OriginChecked`]
    /// witness the credential reads take.
    ///
    /// # Errors
    ///
    /// Returns the canonical `403 forbidden_origin` response
    /// ([`fuz_http::forbidden_origin_response`]) to answer with.
    #[expect(
        clippy::result_large_err,
        reason = "Err is the ready-to-return axum Response — the spine REST handler idiom"
    )]
    pub fn check_origin<'h>(&self, headers: &'h HeaderMap) -> Result<OriginChecked<'h>, Response> {
        if self.allowed_origins.allows_request(headers) {
            Ok(OriginChecked { headers })
        } else {
            Err(fuz_http::forbidden_origin_response())
        }
    }

    /// Walk the daemon-token → cookie → bearer pipeline: the account-grain
    /// identity the request carries, or `None`.
    ///
    /// A leg whose read fails ends the walk: the next leg is not tried, so a
    /// database fault never resolves a lower-priority credential or an
    /// anonymous caller in place of the one the read failed on.
    ///
    /// `client_ip` is the resolved client IP the bearer leg records as
    /// `api_token.last_used_ip`; a handler with no `ClientIp` extension passes
    /// [`fuz_http::ClientIp::as_str_or_unresolved`]'s sentinel.
    /// The headers are `origin`'s — [`check_origin`](Self::check_origin)'s
    /// witness; [`preflight`](Self::preflight) runs both.
    ///
    /// # Errors
    ///
    /// [`CredentialReadFault`] when a leg's pool checkout or query fails; the
    /// surface answers with its response.
    pub async fn resolve_credential(
        &self,
        origin: OriginChecked<'_>,
        client_ip: &str,
    ) -> Result<Option<ResolvedAuth>, CredentialReadFault> {
        resolve_auth_from_headers(
            origin.headers,
            &self.keyring,
            &self.pool,
            self.daemon_token_state.as_ref(),
            self.session_cookie_name,
            client_ip,
        )
        .await
    }

    /// [`check_origin`](Self::check_origin), then
    /// [`resolve_credential`](Self::resolve_credential) — for a surface with
    /// nothing to do between the two.
    ///
    /// # Errors
    ///
    /// Returns the `403 forbidden_origin` response when the origin check
    /// refuses, and the credential walk is not run; or the
    /// [`CredentialReadFault`] response when the walk's read fails.
    #[expect(
        clippy::result_large_err,
        reason = "Err is the ready-to-return axum Response — the spine REST handler idiom"
    )]
    pub async fn preflight(
        &self,
        headers: &HeaderMap,
        client_ip: &str,
    ) -> Result<Option<ResolvedAuth>, Response> {
        let origin = self.check_origin(headers)?;
        self.resolve_credential(origin, client_ip)
            .await
            .map_err(axum::response::IntoResponse::into_response)
    }

    /// The caller's actor context on a **pure-public** route — the credential
    /// walk plus the public-route rules (a narrowed token, or an account
    /// without exactly one active actor, reads as anonymous). The headers are
    /// `origin`'s — [`check_origin`](Self::check_origin)'s witness.
    ///
    /// The rules are on `build_public_request_context` in [`crate::resolve`].
    ///
    /// # Errors
    ///
    /// [`PublicContextFault::Credential`] when the credential walk's read
    /// fails, and [`PublicContextFault::CallerRead`] when the pool checkout,
    /// actor read, or role-grant read after it fails — never an anonymous
    /// caller. The route answers with the fault's response.
    pub async fn public_request_context(
        &self,
        origin: OriginChecked<'_>,
        client_ip: &str,
    ) -> Result<Option<RequestActorContext>, PublicContextFault> {
        build_public_request_context(
            origin.headers,
            &self.keyring,
            &self.pool,
            self.daemon_token_state.as_ref(),
            self.session_cookie_name,
            client_ip,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use axum::http::header;

    use super::*;

    /// The boundary of the auth scope, as the TS twin's router matches
    /// `/api/*` — and the raw path's own reading where the twin's differs:
    /// dot segments are kept and nothing is percent-decoded.
    #[test]
    fn the_auth_scope_is_the_prefix_and_everything_below_it() {
        for inside in [
            "/api",
            "/api/",
            "/api/x",
            "/api/account/login",
            "/api//x",
            "/api/../health",
        ] {
            assert!(auth_middleware_applies(inside), "{inside}");
        }
        for outside in [
            "/", "", "/apix", "/api-x", "/API/x", "/Api", "//api/x", "/x/api/x", "/health",
            "/%61pi/x", "/./api/x", "/api%2Fx", "api/x",
        ] {
            assert!(!auth_middleware_applies(outside), "{outside}");
        }
    }

    /// A gate over a pool that connects to nothing: the hook reads headers
    /// only.
    fn hook_gate() -> AuthGate {
        let mut config = deadpool_postgres::Config::new();
        config.url = Some("postgres://localhost:1/unreachable".to_owned());
        AuthGate {
            pool: config
                .create_pool(
                    Some(deadpool_postgres::Runtime::Tokio1),
                    tokio_postgres::NoTls,
                )
                .expect("a lazy pool"),
            keyring: Arc::new(
                Keyring::new(&"k".repeat(crate::keyring::MIN_KEY_LENGTH)).expect("a keyring"),
            ),
            daemon_token_state: None,
            session_cookie_name: "fuz_session",
            allowed_origins: AllowedOrigins::parse("https://app.example").expect("an allowlist"),
        }
    }

    fn cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, value.parse().expect("a header value"));
        headers
    }

    #[test]
    fn the_hook_clears_an_invalid_session_cookie_under_the_auth_scope() {
        let gate = hook_gate();
        let hook = gate.cookie_clear_hook();
        let clear = HeaderValue::from_static(
            "fuz_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
        );
        let signed =
            crate::sign_session_cookie(&gate.keyring, "token", "fuz_session").expect("a cookie");
        let valid = signed.split(';').next().expect("name=value").to_owned();

        // present and invalid: cleared, on every path under the scope
        for invalid in ["fuz_session=bogus", "fuz_session=", "a=1; fuz_session=x.y"] {
            for path in ["/api", "/api/", "/api/rpc", "/api/unrouted"] {
                assert_eq!(hook.clear_for(path, &cookie(invalid)), Some(clear.clone()));
            }
            // and nowhere else
            for path in ["/", "/health", "/apix", "/API/rpc"] {
                assert_eq!(hook.clear_for(path, &cookie(invalid)), None, "{path}");
            }
        }
        // absent, and valid (whatever its session row): nothing
        assert_eq!(hook.clear_for("/api/rpc", &HeaderMap::new()), None);
        assert_eq!(hook.clear_for("/api/rpc", &cookie("other=1")), None);
        assert_eq!(hook.clear_for("/api/rpc", &cookie(&valid)), None);
        // the same hook rides the gate's stack options
        assert!(
            gate.stack_options(Arc::new(Vec::new()))
                .cookie_clear
                .is_some()
        );
    }

    /// A name with no clearing string clears nothing rather than writing a
    /// header that reads back differently.
    #[test]
    fn a_cookie_name_the_grammar_cannot_carry_clears_nothing() {
        let gate = AuthGate {
            session_cookie_name: "bad name",
            ..hook_gate()
        };
        let hook = gate.cookie_clear_hook();
        assert_eq!(hook.clear_for("/api/rpc", &cookie("bad name=bogus")), None);
    }

    #[test]
    fn the_witness_debug_masks_the_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("fuz_session=secret-cookie-value"),
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token-value"),
        );
        let witness = OriginChecked { headers: &headers };
        let printed = format!("{witness:?}");
        assert_eq!(printed, "OriginChecked { header_count: 2, .. }");
        for secret in ["secret", "cookie", "authorization", "Bearer"] {
            assert!(
                !printed.to_lowercase().contains(&secret.to_lowercase()),
                "{printed}"
            );
        }
    }
}
