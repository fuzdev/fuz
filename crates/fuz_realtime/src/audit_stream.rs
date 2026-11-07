//! Admin-gated audit-log SSE stream router (`GET /api/admin/audit/stream`).
//!
//! The shared route every spine consumer mounts to expose the audit-log SSE
//! feed — the HTTP half of [`crate::sse`]. The handler runs the spine's
//! non-RPC gate pipeline — origin ([`fuz_auth::AuthGate::check_origin`]) →
//! query shape → credential ([`fuz_auth::AuthGate::resolve_credential`]) →
//! credential channel → token scope → acting actor → role — and opens the
//! stream on the consumer's [`SseRegistry`] in two phases, so a revocation
//! racing the request can't leave a stream open (below), returning a
//! `text/event-stream` response immediately. The consumer wires
//! [`register_audit_sse_listener`] onto its [`AuditEmitter`] so every audit
//! row fans to the open streams; revocations close them through the consumer's
//! [`RealtimeCloser`](crate::RealtimeCloser), not through this listener.
//!
//! That pipeline is the one `fuz_db_admin` and `fuz_fact_serving`'s bare route
//! already ran, down to the shared pieces:
//! [`assert_known_query_keys`] + [`parse_acting_query`] for the `?acting=`
//! query the twin declares (`object({acting})`), and
//! [`require_acting_actor`] for the authorization phase. A multi-actor admin
//! therefore **picks a persona** here rather than being refused, and the role
//! check reads that persona's grants.
//!
//! Wire shapes match the TS reference (`fuz_app`'s
//! `create_audit_log_route_specs({stream})`): the connect comment + `data:`
//! frame come from the spine primitive, and denials return the canonical
//! flat-REST error bodies ([`fuz_http::authentication_required_response`] /
//! [`fuz_http::insufficient_permissions_response`]) so the cross-backend SSE
//! suite (`describe_cross_process_sse_tests`) sees one contract on every
//! backend.
//!
//! ## Admission
//!
//! A stream is authorized once, so the handler must not open one on a
//! credential, an actor, or a role revoked while the request was in flight.
//! Its gates run first, in the twin's pipeline order, before any stream is
//! registered — a revocation landing after them would close nothing. So the
//! handler then registers the stream **pending**
//! ([`SseRegistry::subscribe_pending`]), re-reads the credential, the acting
//! actor, and its role grants ([`fuz_auth::recheck_admission`], which the
//! WebSocket upgrade shares), and only then admits ([`SseRegistry::admit`]).
//! Every revocation closes streams after its write commits, so its close
//! either ran before the registration — and the re-reads see the committed
//! revocation: `401 authentication_required` for a dead credential or an
//! acting actor deleted since the gates ran, `403 insufficient_permissions`
//! for a lost role — or after, and found the pending entry: admission then
//! fails, and the response is a `200` whose body is the connect comment and
//! nothing else — to an `EventSource`, a stream closed an instant after it
//! opened (the client's reconnect is answered by the gates, with the precise
//! status). A pending registration receives no audit row, counts toward no
//! cap, and is removed when a re-read refuses the request. [`crate::sse`]'s
//! "Two-phase registration" has the registry half.
//!
//! The server's shutdown closes pending registrations too, and every
//! registration after it is born closed. The gates answer as they always do
//! — a refused caller hears its 400 / 401 / 403 during a shutdown too — and a
//! registration the shutdown closed or that was born closed
//! ([`PendingSseStream::closed`]) skips the re-reads and is answered with the
//! connect comment, as is one whose re-read fails once the shutdown closed it
//! — the shutdown tearing the pool down beside it — not 500: the failure is
//! the shutdown's doing. A re-read that fails on a registration the shutdown
//! has not closed — live, or closed by a revocation — is still a 500, and
//! nothing is admitted unchecked either way.
//!
//! `zzz_server`, `testing_spine_stub`, and other spine servers mount this
//! router; the per-consumer variance is
//! the session cookie name, the gated role, and the admitted credential
//! channels — all fields on [`AuditStreamRouteState`], the last defaulting to
//! session-only.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use fuz_auth::actor_queries::query_active_actor_holds_any_global_role;
use fuz_auth::route_helpers::require_acting_actor;
use fuz_auth::{
    AdmissionRecheck, AuditEmitter, AuditLogEvent, AuthGate, CredentialGate, ROLE_ADMIN,
    credential_type_required_response, parse_acting_query, recheck_admission,
};
use fuz_http::{ClientIp, assert_known_query_keys, query_first};
use serde::Serialize;

use uuid::Uuid;

use crate::connection::{ConnectionIdentity, NotAdmitted};
use crate::sse::{PendingSseStream, SSE_CONNECTED_COMMENT, SseRegistry, SseSubscription};

/// Default per-session cap on open audit-log streams, applied by
/// [`SseRegistry::new`] — the twin of the TS `AUDIT_LOG_SSE_MAX_PER_SCOPE`,
/// whose `scope` is the session hash here too.
///
/// Ten tabs on one session is a comfortable ceiling for normal use; only an
/// abusive or leaking client meets it. Times the session cap
/// (`fuz_auth::DEFAULT_MAX_SESSIONS`) it bounds an account's streams — the
/// figure the WS half's
/// [`DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT`](crate::DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT)
/// matches. Override or disable via [`SseRegistry::with_max_per_scope`].
pub const AUDIT_LOG_SSE_MAX_PER_SCOPE: usize = 10;

/// `{method, params}` wrapper matching the TS JSON-RPC-shaped SSE
/// notification (`SseNotification`); `params` is the full audit row.
#[derive(Serialize)]
struct SseNotification<'a> {
    method: &'a str,
    params: &'a AuditLogEvent,
}

/// Register the audit-log → SSE fan-out listener on `emitter`: every audit
/// row is broadcast to every open stream on `registry` as one
/// `data: {"method":<event_type>,"params":<row>}\n\n` frame.
///
/// It closes nothing. A revocation reaches the streams through the
/// registry's [`fuz_auth::ConnectionCloser`] impl — bound with the WS registry
/// in a [`RealtimeCloser`](crate::RealtimeCloser), which the handlers and
/// the one revocation listener (`fuz_auth::register_revocation_guard`)
/// close through ([`crate::sse`]'s "Close-on-revoke"). Twin of the TS
/// `create_audit_log_sse`'s `on_audit_event`.
pub fn register_audit_sse_listener(emitter: &AuditEmitter, registry: &Arc<SseRegistry>) {
    let registry = Arc::clone(registry);
    emitter.add_listener(Arc::new(move |event: Arc<AuditLogEvent>| {
        let registry = Arc::clone(&registry);
        Box::pin(async move {
            match serde_json::to_string(&SseNotification {
                method: &event.event_type,
                params: event.as_ref(),
            }) {
                Ok(json) => {
                    registry.broadcast(&format!("data: {json}\n\n"));
                }
                Err(e) => {
                    tracing::error!(error = %e, event_type = %event.event_type, "audit SSE: serialize failed");
                }
            }
        })
    }));
}

/// State for [`audit_stream_router`].
///
/// Carries the auth primitives the role gate needs plus the shared
/// [`SseRegistry`] the open stream registers with. Cloned per request by
/// axum's `State` extractor — every field is `Arc` / `Copy`.
#[derive(Clone)]
pub struct AuditStreamRouteState {
    /// The front door the stream checks a request at — the origin check, then
    /// the credential walk (daemon-token first, to match the rest of the
    /// spine) — and the pool the role read and the admission re-read run on.
    /// The session cookie read is the gate's.
    pub gate: AuthGate,
    /// The SSE registry the open stream registers with — the same instance
    /// the consumer passed to [`register_audit_sse_listener`].
    pub audit_sse: Arc<SseRegistry>,
    /// Role the caller must hold (default [`ROLE_ADMIN`]).
    pub required_role: &'static str,
    /// Credential channels admitted (default
    /// [`CredentialGate::SESSION_ONLY`]). The same axis every `AuthSpec`
    /// declares and the sibling non-RPC surface
    /// `fuz_db_admin`'s `DbAdminRouteState`
    /// carries, checked ahead of the scope and role gates.
    ///
    /// The default is session-only on both spines: the stream is a
    /// long-lived, instance-wide admin feed, and a bearer on an admin account
    /// is not a channel a deployment chose for it. Widen it only with a
    /// consumer that has a real bearer-driven stream client; the
    /// token-scoped close (`fuz_auth::ConnectionCloseTarget::Token`) is wired for
    /// exactly that case, as the twin's `token` revocation scope is.
    pub credential_gate: CredentialGate,
}

impl AuditStreamRouteState {
    /// Construct route state with the spine defaults: [`ROLE_ADMIN`] for the
    /// role gate and [`CredentialGate::SESSION_ONLY`] for the credential gate.
    /// Set `required_role` / `credential_gate` directly afterward for a
    /// consumer with a custom role or admitted channel set; the session cookie
    /// name is the gate's.
    #[must_use]
    pub const fn new(gate: AuthGate, audit_sse: Arc<SseRegistry>) -> Self {
        Self {
            gate,
            audit_sse,
            required_role: ROLE_ADMIN,
            credential_gate: CredentialGate::SESSION_ONLY,
        }
    }
}

impl std::fmt::Debug for AuditStreamRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditStreamRouteState")
            .field("gate", &self.gate)
            .field("required_role", &self.required_role)
            .field("credential_gate", &self.credential_gate)
            .finish_non_exhaustive()
    }
}

/// Router exposing `GET /api/admin/audit/stream` at its absolute path.
///
/// Merge (not nest) into the consumer's app router — the route carries its
/// full `/api/admin/...` path so it lands correctly under a root `merge`.
pub fn audit_stream_router(state: AuditStreamRouteState) -> Router {
    Router::new()
        .route("/api/admin/audit/stream", get(audit_stream))
        .with_state(state)
}

/// `GET /api/admin/audit/stream` — role-gated audit-log SSE subscription.
///
/// On a resolved caller holding `state.required_role`, opens a
/// `text/event-stream` keyed to the caller's account (+ session hash + gating
/// role) so a later access-invalidation row for that subscriber drops the
/// stream — see [`crate::sse`]'s "Close-on-revoke" for the event set. Denials
/// return the canonical flat-REST error body before any stream opens, in the
/// spine's phase order: 400 `invalid_query_params`, 401
/// `authentication_required`, 403 `credential_type_required`, 403
/// `token_scope_required`, 400 `actor_required` / `actor_not_on_account`,
/// 403 `insufficient_permissions` — then, at the re-read once the stream is
/// registered, 401 again for a credential revoked or an acting actor deleted
/// while the request ran, and 403 for a role lost (module doc, "Admission").
/// A registration closed before it is admitted — by a revocation or the
/// server's shutdown, including one born closed — gets a `200` whose body is
/// the connect comment alone, also when the re-read failed after the shutdown
/// closed it; any other read failure is a 500.
async fn audit_stream(
    State(state): State<AuditStreamRouteState>,
    Query(query_pairs): Query<Vec<(String, String)>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
) -> Response {
    // The gate's origin check first — a foreign page is refused before its
    // query is read, as the TS twin's origin middleware refuses it ahead of
    // the route.
    let origin = match state.gate.check_origin(&headers) {
        Ok(origin) => origin,
        Err(refused) => return refused,
    };

    // Query shape before auth — the TS pipeline's phase order, so the two
    // backends answer a malformed query identically whatever the caller's
    // credentials. `?acting=` is the only key the twin's
    // `AuditStreamQuery` (`object({acting})`) declares; first
    // occurrence wins on a duplicate, as it does on every other spine surface.
    if let Err(response) = assert_known_query_keys(&query_pairs, &["acting"]) {
        return response;
    }
    let acting = match parse_acting_query(query_first(&query_pairs, "acting")) {
        Ok(acting) => acting,
        Err(response) => return response,
    };

    // The touch the bearer leg fires happens *inside* this call, ahead of the
    // scope gate below — so a narrowed token the route goes on to 403 still
    // records its use, by design.
    let client_ip = ClientIp::as_str_or_unresolved(client_ip.as_ref());
    let auth = match state.gate.resolve_credential(origin, client_ip).await {
        Ok(Some(auth)) => auth,
        Ok(None) => return fuz_http::authentication_required_response(),
        Err(fault) => return fault.into_response(),
    };

    // Credential-channel gate — the coarsest authority axis, checked first so
    // a refused channel learns nothing about the deployment's token scoping or
    // role structure. Same phase order as `fuz_db_admin`'s `require_role` and
    // the TS dispatcher's pipeline (401 → channel → scope → role).
    //
    // On the default session-only mount this is what actually keeps a bearer
    // off the stream: the scope gate below refuses a *narrowed* token, but a
    // full-scope one satisfies it, and the role gate reads only the resolved
    // actor's grants — so an admin account's api token would otherwise pass
    // every gate below.
    if !state.credential_gate.admits(Some(auth.credential_type())) {
        return credential_type_required_response(state.credential_gate);
    }

    // Token-scope surface gate (rule 3) — a narrowed token holds no SSE stream.
    //
    // Same reasoning as the WS upgrade: this is a long-lived server→client feed
    // whose contents are decided by the account's role, not by any per-message
    // scope check, so there is no point at which a narrowing could be applied
    // once the stream is open.
    //
    // Unreachable under the default session-only `credential_gate` (a session
    // is `TokenScope::Full` by construction), and load-bearing for a consumer
    // that widens the gate — the same shape `fuz_db_admin` carries.
    if !auth.scope().admits_non_rpc_surface() {
        return fuz_auth::token_scope_surface_denied_response(
            fuz_auth::TokenSurface::AuditStream.capability(),
        );
    }

    // Authorization phase — resolve the acting actor, then read *its* grants.
    // The twin declares `actor: 'required'` and a `?acting=` query, so a
    // multi-actor admin picks a persona here rather than being refused: the
    // shared helper answers 400 `actor_required` / `actor_not_on_account`
    // exactly as `fuz_db_admin` and the TS dispatcher do.
    //
    // The role read hangs off the **resolved** actor, never the account —
    // the spine's rule that a role 403 is decided by the persona actually
    // acting. (`fuz_db_admin` gates account-grain instead; that is its
    // documented deviation, not the pattern.)
    let account_id = auth.account.id;
    let Ok(client) = state.gate.pool.get().await.inspect_err(|e| {
        tracing::error!(error = ?e, "audit_stream: db pool error");
    }) else {
        return fuz_http::db_unavailable_response();
    };
    let actor = match require_acting_actor(&client, &account_id, acting, "audit_stream").await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    // Global grants only, of an active actor on an active account — a scoped
    // grant of the role (for `admin`, one no grant path mints) must not open
    // the instance-wide audit stream. Mirrors the TS `require_role` gate's
    // `has_any_scoped_role(_, _, null)`.
    match query_active_actor_holds_any_global_role(&client, &actor.id, &[state.required_role]).await
    {
        Ok(true) => {}
        Ok(false) => return fuz_http::insufficient_permissions_response(&[state.required_role]),
        Err(e) => {
            tracing::error!(error = ?e, "audit_stream: role grants query failed");
            return fuz_http::internal_error_response();
        }
    }

    // Register the stream pending — after every gate, so from here on every
    // revocation finds it (module doc, "Admission"). Every identity key the
    // resolution produced goes in, so each close the revocation listener can
    // reach for has something to match: `session_hash` keys `session_revoke`,
    // `api_token_id` keys `token_revoke`, `required_roles` keys
    // `role_grant_revoke`. A given credential fills in only its own (a
    // session has no token id and vice versa); a daemon token fills in
    // neither and is reachable by account-wide close alone. Dropped — and so
    // removed — by every refusal below.
    let pending = state.audit_sse.subscribe_pending(SseSubscription {
        identity: ConnectionIdentity {
            session_hash: auth.session_hash().map(str::to_owned),
            account_id: Some(account_id),
            api_token_id: auth.api_token_id().map(str::to_owned),
            required_roles: vec![state.required_role],
        },
        // the stream ends when the credential it opens on expires
        credential_deadline: auth.credential_deadline,
    });
    // Born closed (the shutdown began first) or already closed by the
    // shutdown: skip the re-reads, which admission refuses whatever they
    // answer — so a shutdown's answer never depends on the pool. A
    // revocation's close is left to the re-reads, which see it committed and
    // answer precisely.
    if closed_by_shutdown(&pending) {
        tracing::info!(%account_id, "audit_stream: shutting down before the re-read");
        return closed_stream_response();
    }

    // Re-read what the gates read, now that the stream is registered: a
    // revocation that closed before the registration is committed, so these
    // see it. The answer is the one the gates would have given a moment later.
    match recheck_admission(&client, &auth, &actor.id, &[state.required_role]).await {
        Ok(recheck) => {
            if let Some(refusal) = recheck_refusal(recheck, state.required_role) {
                tracing::info!(%account_id, ?recheck, "audit_stream: refused at the re-read");
                return refusal;
            }
        }
        Err(e) => {
            return read_failure_response(&pending, account_id, "admission re-check failed", &e);
        }
    }
    drop(client);

    // Admit — the cap's eviction happens here, after every gate. A
    // registration a revocation closed while it was pending — or the server's
    // shutdown, which also refuses every registration after it — is not
    // admitted: the body is the connect comment and nothing else — to an
    // `EventSource`, a stream closed an instant after it opened — so the
    // client reconnects into the gates.
    match state.audit_sse.admit(pending) {
        Ok(stream) => event_stream_response(Body::from_stream(stream)),
        Err(not_admitted) => {
            tracing::info!(%account_id, %not_admitted, "audit_stream: closed before admission");
            closed_stream_response()
        }
    }
}

/// The response for a re-read that refused, `None` for an admitted one — the
/// twin's: `401 authentication_required` for a revoked credential or an
/// acting actor deleted since the gates ran, `403 insufficient_permissions`
/// naming `required_role` for a lost role.
fn recheck_refusal(recheck: AdmissionRecheck, required_role: &'static str) -> Option<Response> {
    match recheck {
        AdmissionRecheck::Admitted => None,
        AdmissionRecheck::CredentialRevoked | AdmissionRecheck::ActorInactive => {
            Some(fuz_http::authentication_required_response())
        }
        AdmissionRecheck::RoleRevoked => Some(fuz_http::insufficient_permissions_response(&[
            required_role,
        ])),
    }
}

/// The answer to a database failure between registration and admission: the
/// connect comment alone when the shutdown closed the registration meanwhile
/// — the failure is the shutdown's doing, tearing the pool down beside the
/// reads, and the client's reconnect meets the gates — otherwise a 500, a
/// revocation's close included. Fail closed either way: nothing is admitted
/// unchecked.
fn read_failure_response(
    pending: &PendingSseStream,
    account_id: Uuid,
    what: &'static str,
    error: &(dyn std::error::Error + 'static),
) -> Response {
    // the chain, not `Display`: a `tokio_postgres::Error` prints only its kind
    let error = fuz_sys::cli::format_error_chain(error);
    if closed_by_shutdown(pending) {
        tracing::info!(
            %account_id,
            error = %error,
            what,
            "audit_stream: the re-read was ended by the shutdown"
        );
        closed_stream_response()
    } else {
        tracing::error!(error = %error, "audit_stream: {what}");
        fuz_http::internal_error_response()
    }
}

fn closed_by_shutdown(pending: &PendingSseStream) -> bool {
    pending.closed() == Some(NotAdmitted::ShuttingDown)
}

/// A `200` whose body is the connect comment and nothing else — to an
/// `EventSource`, a stream closed an instant after it opened.
fn closed_stream_response() -> Response {
    event_stream_response(Body::from(SSE_CONNECTED_COMMENT))
}

fn event_stream_response(body: Body) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(body)
        // builder only errors on invalid header values, all static here.
        .unwrap_or_else(|_| fuz_http::internal_error_response())
}

#[cfg(test)]
mod tests {
    use super::{
        AdmissionRecheck, AuditStreamRouteState, CredentialGate, audit_stream_router,
        recheck_refusal,
    };
    use crate::sse::SseRegistry;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use fuz_auth::ROLE_ADMIN;
    use std::sync::Arc;
    use tower::ServiceExt as _;

    /// GET the stream with `origin` and `query` over a pool that cannot
    /// connect: `(status, body)`.
    async fn get_stream(origin: Option<&str>, query: &str) -> (StatusCode, String) {
        let pool = fuz_db::create_pool(
            "postgres://nobody@127.0.0.1:1/nothing",
            &fuz_db::PoolOptions::default(),
        )
        .expect("a lazily-built pool needs no server");
        let router = audit_stream_router(AuditStreamRouteState::new(
            fuz_testing::testing_auth_gate(pool),
            Arc::new(SseRegistry::new()),
        ));
        let mut request = Request::get(format!("/api/admin/audit/stream{query}"));
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        let response = router
            .oneshot(request.body(Body::empty()).expect("request builds"))
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body collects");
        (status, String::from_utf8(bytes.to_vec()).expect("utf-8"))
    }

    /// The stream refuses a foreign `Origin` with the flat `forbidden_origin`
    /// 403 before its query is read (an unknown key beside it) and before the
    /// credential walk; an allowed origin reaches the query gate, and with a
    /// clean query the 401.
    #[tokio::test]
    async fn the_stream_refuses_a_foreign_origin_first() {
        assert_eq!(
            get_stream(Some("https://evil.example"), "?nope=1").await,
            (
                StatusCode::FORBIDDEN,
                r#"{"error":"forbidden_origin"}"#.to_owned()
            )
        );
        let allowed = Some(fuz_testing::TESTING_ALLOWED_ORIGIN);
        assert_eq!(
            get_stream(allowed, "?nope=1").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(get_stream(allowed, "").await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(get_stream(None, "").await.0, StatusCode::UNAUTHORIZED);
    }

    /// The re-read's refusals answer as the twin's do: 401 for a revoked
    /// credential and for an acting actor deleted since the gates ran, 403
    /// naming the role for a lost one.
    #[tokio::test]
    async fn a_refused_re_read_answers_the_twins_status() {
        assert!(recheck_refusal(AdmissionRecheck::Admitted, ROLE_ADMIN).is_none());
        for (recheck, status, body) in [
            (
                AdmissionRecheck::CredentialRevoked,
                StatusCode::UNAUTHORIZED,
                r#"{"error":"authentication_required"}"#,
            ),
            (
                AdmissionRecheck::ActorInactive,
                StatusCode::UNAUTHORIZED,
                r#"{"error":"authentication_required"}"#,
            ),
            (
                AdmissionRecheck::RoleRevoked,
                StatusCode::FORBIDDEN,
                r#"{"error":"insufficient_permissions","required_roles":["admin"]}"#,
            ),
        ] {
            let response = recheck_refusal(recheck, ROLE_ADMIN).expect("refused");
            assert_eq!(response.status(), status, "{recheck:?}");
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body collects");
            assert_eq!(
                std::str::from_utf8(&bytes).expect("utf-8"),
                body,
                "{recheck:?}"
            );
        }
    }

    /// A stock mount admits the session channel only.
    ///
    /// Both spines wire the token-scoped close — `api_token_id` on every
    /// stream's identity and
    /// [`RevocationScope::Token`](fuz_auth::RevocationScope::Token) closing
    /// `fuz_auth::ConnectionCloseTarget::Token` here, the `token` arm of
    /// `create_revocation_guard` there — so widening the gate loses no close.
    /// What it hands over is a long-lived instance-wide admin feed to a
    /// credential channel the deployment never chose, which is why the default
    /// is the narrow one and widening it is a consumer's explicit act.
    ///
    /// The route-level proof — a full-scope bearer refused ahead of the scope
    /// and role gates — lives in `tests/audit_stream.rs`, where every case is
    /// `#[ignore = "requires PostgreSQL"]`. That leaves a bare `cargo test`
    /// with no signal at all on a default flipped to [`CredentialGate::Any`],
    /// the one edit that reopens the channel silently. The pool builds lazily
    /// from a URL, so this half needs no database and runs in the default gate.
    #[test]
    fn the_stock_route_state_admits_the_session_channel_only() {
        let pool = fuz_db::create_pool(
            "postgres://u:p@localhost:5432/unused",
            &fuz_db::PoolOptions::default(),
        )
        .expect("a lazily-built pool needs no server");
        let state = AuditStreamRouteState::new(
            fuz_testing::testing_auth_gate(pool),
            Arc::new(SseRegistry::new()),
        );
        assert_eq!(
            state.credential_gate,
            CredentialGate::SESSION_ONLY,
            "a stock audit stream must admit the session channel and nothing else",
        );
        assert_eq!(state.required_role, ROLE_ADMIN);
    }
}
