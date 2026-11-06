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

use axum::http::HeaderMap;
use axum::response::Response;
use deadpool_postgres::Pool;
use fuz_http::AllowedOrigins;

use crate::daemon_token::SharedDaemonTokenState;
use crate::keyring::Keyring;
use crate::request_context::RequestActorContext;
use crate::resolve::{
    CredentialReadFault, PublicContextFault, ResolvedAuth, build_public_request_context,
    resolve_auth_from_headers,
};

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
    /// in-handler check cannot drift apart. Request tracing on, the host gate
    /// off ([`fuz_http::StackOptions::new`]); set the flags on the result.
    #[must_use]
    pub fn stack_options(
        &self,
        trusted_proxies: Arc<Vec<fuz_http::ParsedProxy>>,
    ) -> fuz_http::StackOptions {
        fuz_http::StackOptions::new(self.allowed_origins.clone(), trusted_proxies)
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
    #[allow(
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
    #[allow(
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
    use axum::http::{HeaderValue, header};

    use super::*;

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
