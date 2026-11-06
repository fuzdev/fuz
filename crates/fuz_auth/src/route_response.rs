//! Shared error / rate-limit response builders for the auth REST routes.
//!
//! The `/signup`, `/login`, `/logout`, `/password`, and `/bootstrap`
//! handlers all surface the same JSON error envelope
//! (`{ "error": <reason> }`, [`fuz_http::rest_error_response`]) and the same
//! 429 + `Retry-After` shape.
//! Centralized here per the "extract early when reuse is known" policy;
//! the wire shape mirrors `fuz_app`.
//!
//! The internal-failure 500 is not built here: those handlers and `/status`
//! answer [`fuz_http::internal_error_response`] — the flat
//! `{"error":"internal_error"}` body — from each of their own failure arms.

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::credential_type::CredentialGate;

#[derive(Debug, Serialize)]
struct RateLimitErrorBody {
    error: String,
    retry_after: u64,
}

/// `429` with a `Retry-After` header and
/// `{ "error": "rate_limit_exceeded", "retry_after": N }`.
pub(crate) fn rate_limit_exceeded(retry_after: u64) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(val) = retry_after.to_string().parse() {
        headers.insert(axum::http::header::RETRY_AFTER, val);
    }
    (
        StatusCode::TOO_MANY_REQUESTS,
        headers,
        Json(RateLimitErrorBody {
            error: "rate_limit_exceeded".to_owned(),
            retry_after,
        }),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
struct CredentialTypeRequiredBody {
    error: &'static str,
    required_credential_types: Vec<&'static str>,
}

/// `403` with
/// `{ "error": "credential_type_required", "required_credential_types": [...] }`.
///
/// The canonical credential-channel-gating denial for the REST routes whose
/// action-spec twins carry a [`CredentialGate`]: session-bound account
/// operations (`/password`, `/logout`) that must be driven by a browser-context
/// session cookie, not a bearer / daemon token. Mirrors `fuz_app`'s dispatcher
/// `require_credential_types([...])` 403.
///
/// Takes the gate it denies on rather than hardcoding the names, so the body
/// can't drift from the gate the caller actually checked — the REST half of
/// the same single-source-of-truth the dispatcher's 403 gets from
/// [`crate::AuthSpec`].
pub fn credential_type_required_response(gate: CredentialGate) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(CredentialTypeRequiredBody {
            error: "credential_type_required",
            required_credential_types: gate.allowed().iter().map(|c| c.name()).collect(),
        }),
    )
        .into_response()
}

#[derive(Debug, Serialize)]
struct TokenScopeRequiredBody {
    error: &'static str,
    required_scope: &'static str,
}

/// `403` with
/// `{ "error": "token_scope_required", "required_scope": "surface:<name>" }`
/// — the canonical denial when a narrowed token reaches a **non-RPC surface**
/// (rule 3: a scoped token is RPC-only).
///
/// One shape for all four surfaces. They are REST-ish routes whose sibling
/// denials are already flat (`credential_type_required` above,
/// `insufficient_permissions`, the fact route's bare statuses), so emitting the
/// JSON-RPC envelope from them would put two shapes on one denial depending on
/// which route you hit. The envelope belongs to the dispatcher's per-method
/// gate ([`crate::token_scope_denied`]) and stops there.
///
/// Takes a [`SurfaceCapability`](crate::SurfaceCapability) rather than the
/// [`TokenSurface`](crate::TokenSurface) enum, so a **consumer** crate mounting
/// its own non-RPC surface can emit this exact body for its own name. The
/// spine's four call sites still pass `TokenSurface::X.capability()`, so nothing
/// here drifts from the enum the census enumerates — only the set of nameable
/// surfaces widens.
///
/// That widening is the point. The enum is closed to *this workspace's*
/// surfaces, and a consumer cannot add a variant; without a string it would
/// have to reach for [`crate::token_scope_denied`] and emit the JSON-RPC
/// envelope from a REST route — reintroducing the two-shapes-for-one-denial
/// split this function exists to have removed. A surface name decides nothing
/// (rule 3 is all-or-nothing), so there was never anything for the closed
/// parameter to protect.
///
/// The newtype is what keeps the widening from costing anything: a surface
/// name is a *declared* `&'static str` constant
/// ([`TokenSurface::capability`](crate::TokenSurface::capability), `fuz_forge`'s
/// `SURFACE_*`), never a value assembled from the request, so a route cannot
/// reflect a caller-supplied string back out in `required_scope`; and it is
/// always a `surface:<name>`, never an `rpc:<method>` capability, which names a
/// method gate a route does not have.
#[must_use]
pub fn token_scope_surface_denied_response(capability: crate::SurfaceCapability) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(TokenScopeRequiredBody {
            error: "token_scope_required",
            required_scope: capability.as_str(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialGate, StatusCode, credential_type_required_response,
        token_scope_surface_denied_response,
    };
    use crate::token_scope::TokenSurface;

    /// Every non-RPC surface denies with **one** body shape.
    ///
    /// The four surfaces live in four crates, so nothing but this assertion
    /// stops them drifting into per-route shapes — which is what they were
    /// doing before: three emitted the JSON-RPC envelope while their own
    /// sibling denials on the same routes were flat. A client should read one
    /// vocabulary regardless of which surface refused it.
    #[tokio::test]
    async fn every_surface_denial_shares_one_flat_body() {
        use axum::body::to_bytes;

        for surface in TokenSurface::ALL {
            let response = token_scope_surface_denied_response(surface.capability());
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("read denial body");
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).expect("denial body is JSON");
            assert_eq!(
                body,
                serde_json::json!({
                    "error": "token_scope_required",
                    "required_scope": surface.capability().as_str(),
                }),
                "{} must use the shared flat shape",
                surface.capability(),
            );
        }
    }

    /// The REST 403's `required_credential_types` is derived from the gate the
    /// caller checked, so `/password` and `/logout` cannot advertise a channel
    /// set different from the one they enforce — the failure mode the old
    /// hardcoded `&["session"]` literal made possible.
    #[tokio::test]
    async fn body_names_the_gate_it_denies_on() {
        let response = credential_type_required_response(CredentialGate::SESSION_ONLY);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("body is json"),
            serde_json::json!({
                "error": "credential_type_required",
                "required_credential_types": ["session"],
            }),
        );
    }
}
