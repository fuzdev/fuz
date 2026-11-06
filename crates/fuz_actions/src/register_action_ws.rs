//! WS upgrade handler factory.
//!
//! Mirrors `fuz_app`'s `actions/register_action_ws.ts` shape.
//!
//! ## What this owns
//!
//! - The axum upgrade handler (cookie/bearer/daemon-token resolution,
//!   origin check, 401 on auth failure, the token-scope surface gate, the
//!   acting-actor phase, the optional [`WsRouteState::required_roles`] gate,
//!   and upgrade-time spec lookup for actions that need it), and the socket's
//!   limits
//!   ([`ActionWsOptions`], the defaults through [`register_action_ws`], the
//!   consumer's through [`register_action_ws_with_options`]): the inbound
//!   message cap ([`DEFAULT_WS_MAX_MESSAGE_BYTES`]) and, independent of it,
//!   the byte budget of each connection's outbound queue
//!   ([`DEFAULT_WS_OUTBOUND_QUEUE_BYTES`]), past which the socket is closed
//!   with [`fuz_realtime::WS_CLOSE_OUTBOUND_OVERFLOW`] (4005), and the receive
//!   timeout ([`DEFAULT_WS_RECEIVE_TIMEOUT`], 60 s), past which a silent socket
//!   is closed with [`fuz_realtime::WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`] (4003).
//!   Gate order — origin 403 → unauthenticated 401 → scope 403 → acting
//!   actor → role 403, then the upgrade itself (404 for a request that asks
//!   for no upgrade, axum's own refusal for a malformed one) — matches the
//!   TS twin's middleware chain ahead of its upgrade helper. Any method but
//!   `GET` (and the `HEAD` axum serves through it) is a 404. The acting-actor phase runs on every
//!   endpoint, gated or not: the `?acting=` query selector (first
//!   occurrence; a malformed value reads as omitted, as the twin's
//!   `parse_acting` reads it) goes through
//!   [`fuz_auth::route_helpers::require_acting_actor`], which answers 400
//!   `actor_required` (a multi-actor account omitting `acting`, with the
//!   `available` actors), 400 `actor_not_on_account` (a selector naming no
//!   active actor of the account), or 500 `no_actors_on_account` (the
//!   account has no active actor). The twin's fourth outcome, the 500
//!   `account_vanished` of a torn read, has no counterpart: the actor read
//!   here is one statement.
//! - **Admission**, in `on_upgrade` — [`admit_upgrade`]: the connection is
//!   registered pending, its credential re-read, and only then admitted, so
//!   a revocation racing the upgrade cannot leave a socket on a dead
//!   credential (see below). A refused upgrade is closed with
//!   [`fuz_realtime::WS_CLOSE_SESSION_REVOKED`] (4001),
//!   [`fuz_realtime::WS_CLOSE_PERMISSION_REVOKED`] (4006) when a role
//!   [`WsRouteState::required_roles`] lists was revoked meanwhile,
//!   [`fuz_realtime::WS_CLOSE_INTERNAL_ERROR`] (1011) when the re-read itself
//!   failed, or [`fuz_realtime::WS_CLOSE_GOING_AWAY`] (1001) when the server
//!   began shutting down first, before any loop runs. The handler takes a
//!   [`ConnectionRegistry::hold_upgrade`] before the handshake and keeps it
//!   through the upgraded future, so the server's shutdown waits for the
//!   refusal frame as it does for a loop's close.
//! - The per-account connection cap
//!   ([`fuz_realtime::DEFAULT_MAX_CONNECTIONS_PER_ACCOUNT`], evict-oldest,
//!   the superseded socket closed with
//!   [`fuz_realtime::WS_CLOSE_CONNECTION_LIMIT`]) runs inside
//!   [`ConnectionRegistry::admit`], the last step of that admission — after
//!   every gate and the re-read — keyed on the authenticated account for
//!   every credential type.
//! - The credential deadline: the socket is closed with
//!   [`fuz_realtime::WS_CLOSE_SESSION_REVOKED`] (4001) and
//!   [`fuz_realtime::WS_CLOSE_CREDENTIAL_EXPIRED_REASON`] when the credential
//!   it upgraded on expires ([`fuz_auth::ResolvedAuth::credential_deadline`],
//!   handed to the loop as [`fuz_realtime::WsLoopOptions`]).
//! - Building the per-socket [`WsConnectionState`] +
//!   `ws_dispatch_fn`.
//! - Plumbing through [`fuz_realtime::run_ws_connection`].
//!
//! ## Admission: the revocation race
//!
//! The credential is resolved before the handshake, and the socket is
//! registered only inside `on_upgrade` — after the `101`, hyper's upgrade,
//! and a task spawn. Every revocation (session revoke, logout, password
//! change, token revoke, account delete) closes the sockets *registered*
//! under what it revoked, so one landing in that gap would close nothing,
//! and the socket would then be admitted on the dead credential and keep it:
//! per-message dispatch re-authorizes the *actor*, never the session or
//! token, so the socket would go on dispatching — `account_token_create`
//! included, minting a fresh credential after a password change — and its
//! admission could evict a live socket of the same account past the cap.
//!
//! [`admit_upgrade`] closes the gap in three steps: register the connection
//! **pending** ([`ConnectionRegistry::register_pending`] — closeable by every
//! revocation, inert otherwise), re-read the credential
//! ([`fuz_auth::recheck_admission`]), then
//! [`ConnectionRegistry::admit`]. Every close fires after its revocation
//! committed, and the re-read's statements start after the registration and
//! see whatever committed before them (`READ COMMITTED`). So a revocation's
//! close either **preceded** the registration — its commit then precedes the
//! re-read, which refuses — or **followed** it and found the pending entry,
//! so `admit` refuses. No interleaving admits a revoked credential. The cap
//! is enforced only by `admit`, so a refused upgrade evicts nothing, and
//! pending registrations never count toward it.
//!
//! The upgrade's role gate is re-read the same way, beside the credential:
//! a role revocation closes the registered sockets gated on the role
//! (a `ConnectionCloseTarget::Role` close, which the pending entry is
//! registered under through its [`fuz_realtime::ConnectionIdentity`]), so one
//! landing between the gate and the registration would close nothing and
//! the socket would be admitted without the role for its lifetime. The
//! re-read reads the same grants the gate read — the resolved acting
//! actor's active global grants, counted only while that actor and its
//! account are active.
//!
//! The acting actor itself is re-read beside the credential on every
//! endpoint, gated or not: an actor soft-deleted under its live account keeps
//! the account's sessions and tokens and its own grant rows, so neither the
//! credential nor the role re-read alone would refuse it on an ungated
//! endpoint. A tombstoned acting actor is refused like a dead credential
//! (4001).
//!
//! ## What this delegates
//!
//! - The origin check and the credential walk → [`fuz_auth::AuthGate::preflight`]; the re-read
//!   → [`fuz_auth::recheck_admission`].
//! - Connection registry → [`fuz_realtime::ConnectionRegistry`].
//! - Message loop → [`fuz_realtime::run_ws_connection`].
//! - Per-frame dispatch → `ws_dispatch_fn`.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use deadpool_postgres::Pool;
use fuz_auth::actor_queries::query_active_actor_holds_any_global_role;
use fuz_auth::{AdmissionRecheck, ResolvedAuth, recheck_admission};
use fuz_http::{ClientIp, query_first};
use fuz_realtime::{
    ActionPeer, Connection, ConnectionGuard, ConnectionIdentity, ConnectionPeer,
    ConnectionRegistry, ConnectionSender, DEFAULT_MAX_IN_FLIGHT_PEER_REQUESTS_PER_CONNECTION,
    PendingConnection, PendingPeerRequests, SignalToken, UpgradeRefusal, WsLoopOptions,
    connection_channel, refuse_upgrade, run_ws_connection,
};
use uuid::Uuid;

use crate::perform_action::ActionDispatch;
use crate::ws_dispatch::{WsConnectionState, ws_dispatch_fn};

/// Default cap on an inbound WebSocket message (and frame), in bytes.
///
/// Equal to [`fuz_http::DEFAULT_BODY_LIMIT_BYTES`], the default HTTP body cap,
/// so one JSON-RPC request is bounded the same on both transports.
/// [`register_action_ws`] applies it; a consumer that raises its RPC body
/// cap passes the same value as [`ActionWsOptions::max_message_bytes`] to
/// [`register_action_ws_with_options`].
/// tungstenite's own defaults would be 64 MiB per message and 16 MiB per
/// frame.
///
/// An oversized message fails the socket read, and the connection closes
/// with [`fuz_realtime::WS_CLOSE_MESSAGE_TOO_BIG`] (1009, see
/// [`fuz_realtime::run_ws_connection`]) — there is no per-message error
/// reply, so a client should refuse to send one. Twin of `fuz_app`'s
/// `DEFAULT_WS_MAX_MESSAGE_BYTES`, whose server closes with the same code.
///
/// It bounds what the server *reads*. What the server queues *for* a
/// connection has its own budget, [`DEFAULT_WS_OUTBOUND_QUEUE_BYTES`], which
/// a different message cap does not move.
pub const DEFAULT_WS_MAX_MESSAGE_BYTES: usize = fuz_http::DEFAULT_BODY_LIMIT_BYTES;

/// Default byte budget of one connection's outbound queue — the frames the
/// server has queued for a socket and its loop has not yet taken to write.
///
/// 4 MiB — four messages at [`DEFAULT_WS_MAX_MESSAGE_BYTES`] as it stands, and a
/// value of its own: it does not move with that constant. Each waiting
/// frame is charged the UTF-8 length of its text plus
/// [`fuz_realtime::OUTBOUND_FRAME_OVERHEAD_BYTES`]; a frame that does not fit
/// closes the socket with [`fuz_realtime::WS_CLOSE_OUTBOUND_OVERFLOW`]
/// (4005), and a frame is always queued into an empty queue, so one message
/// larger than the whole budget is still deliverable
/// ([`fuz_realtime::connection_channel`]).
///
/// [`register_action_ws`] applies it, and so does
/// [`ActionWsOptions::default`]; the value does not follow the message cap,
/// so a consumer that raises only its inbound cap keeps this budget. A
/// consumer whose server pushes more than this at a client between two
/// writes — large frames, or long bursts — sets its own
/// [`ActionWsOptions::outbound_queue_bytes`] with
/// [`register_action_ws_with_options`].
pub const DEFAULT_WS_OUTBOUND_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// Default receive silence past which a socket is closed with
/// [`fuz_realtime::WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`] (4003) — 60 s, the twin
/// of `fuz_app`'s `DEFAULT_WS_RECEIVE_TIMEOUT`.
///
/// A live `FrontendWebsocketClient` sends a heartbeat whenever either
/// direction has been idle for its interval (30 s by default), so it stays
/// well inside this. A consumer whose clients may stay silent longer — one
/// that lets a user raise the client's heartbeat interval — sets a larger
/// timeout with [`register_action_ws_with_options`], at least twice its
/// longest client interval.
pub const DEFAULT_WS_RECEIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// The limits of the sockets one [`register_action_ws_with_options`] router
/// serves — two sizes and a receive timeout. [`Default`] is what
/// [`register_action_ws`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionWsOptions {
    /// Cap on an inbound message (and frame), in bytes
    /// ([`DEFAULT_WS_MAX_MESSAGE_BYTES`]).
    pub max_message_bytes: usize,
    /// Byte budget of each connection's outbound queue
    /// ([`DEFAULT_WS_OUTBOUND_QUEUE_BYTES`]). Not derived from
    /// `max_message_bytes`. Zero is refused when the router is built.
    pub outbound_queue_bytes: usize,
    /// Receive silence past which a socket is closed with
    /// [`fuz_realtime::WS_CLOSE_SERVER_HEARTBEAT_TIMEOUT`]
    /// ([`DEFAULT_WS_RECEIVE_TIMEOUT`]); `None` keeps silent sockets open, the
    /// twin's `receive_timeout: null`. Counted from admission and from every text
    /// or binary frame read ([`fuz_realtime::WsLoopOptions::receive_timeout`]).
    /// Zero is refused when the router is built.
    pub receive_timeout: Option<Duration>,
}

impl Default for ActionWsOptions {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_WS_MAX_MESSAGE_BYTES,
            outbound_queue_bytes: DEFAULT_WS_OUTBOUND_QUEUE_BYTES,
            receive_timeout: Some(DEFAULT_WS_RECEIVE_TIMEOUT),
        }
    }
}

/// Shared state for the WS upgrade handler.
///
/// Built once at boot (`AppBackend::ws_route_state`), handed to
/// [`register_action_ws`].
#[derive(Clone)]
pub struct WsRouteState {
    /// The dispatcher every frame runs through — the same
    /// [`ActionDispatch`] the server's RPC router takes — whose gate is the
    /// front door the upgrade checks a request at (the origin check, then the
    /// credential walk, [`fuz_auth::AuthGate::preflight`]) and whose pool the admission
    /// re-read runs on.
    pub dispatch: ActionDispatch,
    pub connection_registry: Arc<ConnectionRegistry>,
    /// Roles permitted to hold a socket — **any-of** disjunction, empty =
    /// no role gate (any authenticated, unscoped credential may upgrade).
    ///
    /// The coarse upgrade-time authority gate, twin of `fuz_app`'s
    /// `register_action_ws({required_roles})` → `require_role(roles)`.
    /// Per-action `auth` still applies to every message; this exists because a
    /// connected socket receives **every** broadcast with no per-recipient ACL,
    /// so "who may hold a socket" is a separate question from "who may call
    /// this method" — a consumer whose broadcasts are privileged (`fuz_forge`'s
    /// `fuz_forge_repo_updated`) must refuse the socket itself, not just the
    /// verbs.
    ///
    /// **Grain: the resolved acting actor, global scope.** Admits when the
    /// actor the upgrade resolved (module doc, the acting-actor phase) holds
    /// an active global (`scope_id IS NULL`) grant for one of these roles —
    /// the twin's `require_role`, which reads the same actor's grants
    /// (`has_any_scoped_role(ctx, roles, null)` — a scoped grant never
    /// admits). A role held only by a sibling actor of the account does not
    /// admit, and a soft-deleted actor is never resolved, so its grants never
    /// reach the gate.
    ///
    /// **Held for the socket's life.** The roles are recorded on every
    /// registration ([`fuz_realtime::ConnectionIdentity::required_roles`]) and
    /// re-read at admission ([`admit_upgrade`]); a revoked global grant of a
    /// listed role closes the account's sockets on this endpoint with
    /// [`fuz_realtime::WS_CLOSE_PERMISSION_REVOKED`] (4006), through the audit
    /// listener (`fuz_auth::register_revocation_guard`). An any-of
    /// gate over-closes: the loss of any listed role closes the socket,
    /// whether or not the account still holds another.
    pub required_roles: Vec<&'static str>,
}

impl std::fmt::Debug for WsRouteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsRouteState")
            .field("dispatch", &self.dispatch)
            .field("required_roles", &self.required_roles)
            .finish_non_exhaustive()
    }
}

/// Internal axum state for the WS upgrade handler.
///
/// Wraps the consumer-facing [`WsRouteState`] with the two
/// server-initiated-request primitives built **inside**
/// [`register_action_ws`] — the process-shared [`PendingPeerRequests`]
/// the read loop demuxes inbound responses into, and the registry-backed
/// [`ActionPeer`] handlers reach via `ctx.request_client` — per router, so
/// they stay out of the consumer-built state.
#[derive(Clone)]
struct WsHandlerState {
    route: WsRouteState,
    pending: Arc<PendingPeerRequests>,
    peer: Arc<dyn ActionPeer>,
    /// Inbound message + frame cap, outbound queue budget, receive timeout.
    options: ActionWsOptions,
}

/// Build an `axum::Router` exposing `GET /ws` (consumer remounts).
///
/// Only `GET` is routed (axum serves `HEAD` through it); any other method on
/// the path is a 404, as on the twin, whose guards ride its `GET` route.
///
/// Mount path is the consumer's choice — typically `/api/ws` to match
/// `fuz_app`'s convention. The body cap, origin check, client-IP resolution,
/// and tracing come from the consumer's `fuz_http::compose_stack`; the
/// handler checks the origin again through the state's gate.
///
/// The pending-peer-request registry + the registry-backed [`ActionPeer`]
/// are constructed here, once per router, over the state's
/// `connection_registry` — both shared across every connection this router
/// serves (per-connection isolation lives in the `(ConnectionId, id)`
/// key, not in separate registries).
pub fn register_action_ws(state: WsRouteState) -> Router {
    register_action_ws_with_options(state, ActionWsOptions::default())
}

/// [`register_action_ws`] with the consumer's limits ([`ActionWsOptions`]).
///
/// The options set the inbound message cap, the outbound queue budget, and
/// the receive timeout. A consumer bounds both transports with one value by
/// passing its RPC group's `fuz_http::BodyCap::Bytes` size as
/// `max_message_bytes`.
///
/// # Panics
///
/// Panics if `options.outbound_queue_bytes` is zero — a queue with no budget
/// holds one frame at a time, so a connection would be closed with 4005 the
/// first time a second frame is queued behind one still waiting — or if
/// `options.receive_timeout` is `Some` zero, which would close every socket
/// at its first check (`None` is how a consumer turns the timeout off). These
/// are boot-time wiring invariants, caught at assembly; neither is reachable
/// from a request path.
pub fn register_action_ws_with_options(state: WsRouteState, options: ActionWsOptions) -> Router {
    // Fail loud at assembly, not at a connection's first send.
    assert!(
        options.outbound_queue_bytes > 0,
        "register_action_ws_with_options: outbound_queue_bytes is zero — a connection would be \
         closed for an outbound overflow by the first frame queued behind one still waiting; \
         pass a byte budget (DEFAULT_WS_OUTBOUND_QUEUE_BYTES is the default)"
    );
    assert!(
        options.receive_timeout != Some(Duration::ZERO),
        "register_action_ws_with_options: receive_timeout is zero — every socket would be closed \
         at its first check; pass a timeout (DEFAULT_WS_RECEIVE_TIMEOUT is the default), or None \
         to keep silent sockets open"
    );
    let pending = Arc::new(PendingPeerRequests::new(
        DEFAULT_MAX_IN_FLIGHT_PEER_REQUESTS_PER_CONNECTION,
    ));
    let peer: Arc<dyn ActionPeer> = Arc::new(ConnectionPeer::new(
        Arc::clone(&state.connection_registry),
        Arc::clone(&pending),
    ));
    Router::new()
        .route(
            "/ws",
            get(ws_handler).fallback(|| async { crate::server::not_found_response() }),
        )
        .with_state(WsHandlerState {
            route: state,
            pending,
            peer,
            options,
        })
}

/// Admit an upgraded connection: register, re-check, admit.
///
/// Registers it pending, re-checks its credential, the acting actor, and the
/// endpoint's `required_roles`, then admits it — the socket-free half of `on_upgrade`
/// (module doc, "Admission: the revocation race").
///
/// `required_roles` is the endpoint's gate ([`WsRouteState::required_roles`]):
/// recorded on the registration, so a role close reaches it, and re-read
/// after the credential, so a revocation that landed before the registration
/// refuses. The re-read reads the grants of `acting_actor_id`, the actor the
/// upgrade resolved and its role gate read. Empty reads no role.
///
/// `sender` is the sender half of the connection's outbound channel
/// ([`fuz_realtime::connection_channel`], built with the router's outbound
/// queue budget); nothing is queued on it until admission. On success the caller gets the [`Connection`] the WS loop
/// takes and the [`ConnectionGuard`] it holds for the socket's lifetime. On a
/// refusal the pending registration is already removed, nothing was evicted,
/// and the caller closes the socket with [`fuz_realtime::refuse_upgrade`].
///
/// The per-account connection cap is enforced here, by the final
/// [`ConnectionRegistry::admit`] — so this runs only after every upgrade gate
/// (origin → 401 → scope → acting actor → role), and an unauthenticated,
/// forbidden, or revoked request can never close someone else's socket. Every credential
/// type is keyed on its account; a daemon token is not exempt.
///
/// The re-check is [`recheck_admission`], which the audit stream's admission
/// shares. `pool` must hand out autocommit clients (a plain pool does): its
/// statements have to see every revocation committed before they start.
///
/// # Errors
///
/// - [`UpgradeRefusal::Revoked`] — the credential no longer authenticates
///   (its session or token is gone or expired, or the account deleted), the
///   acting actor is no longer an active actor of the account (soft-deleted),
///   or a revocation closed the pending registration before it could be
///   admitted.
/// - [`UpgradeRefusal::PermissionRevoked`] — the acting actor no longer
///   holds any of `required_roles` globally, or a role close closed the
///   pending registration.
/// - [`UpgradeRefusal::Unavailable`] — the re-check could not run (pool
///   checkout, credential query, actor query, or role query failure). Fail closed: never admitted unchecked. A
///   failure after the registration was closed refuses for that close
///   instead.
/// - [`UpgradeRefusal::ShuttingDown`] — the server's shutdown closed the
///   pending registration, or began before it registered (the registration
///   was then born closed, and is refused before any database work).
pub async fn admit_upgrade(
    connection_registry: &Arc<ConnectionRegistry>,
    pool: &Pool,
    resolved: &ResolvedAuth,
    acting_actor_id: &Uuid,
    required_roles: &[&'static str],
    sender: ConnectionSender,
) -> Result<(Connection, ConnectionGuard), UpgradeRefusal> {
    let account_id = resolved.account.id;
    // Owns its entry: every refusal below drops it, which removes the entry.
    let pending = connection_registry.register_pending(
        sender,
        ConnectionIdentity {
            session_hash: resolved.session_hash().map(str::to_owned),
            account_id: Some(account_id),
            api_token_id: resolved.api_token_id().map(str::to_owned),
            required_roles: required_roles.to_vec(),
        },
        SignalToken::new(),
    );
    // Born closed (the shutdown began first) or already closed: refuse before
    // any database work, so a shutdown's refusal never depends on the pool.
    if let Some(not_admitted) = pending.closed() {
        tracing::info!(
            %account_id,
            %not_admitted,
            "ws upgrade admission: closed before the re-check"
        );
        return Err(UpgradeRefusal::from(not_admitted));
    }

    // A re-check that fails because the registration was closed meanwhile —
    // a shutdown tearing the pool down beside it — refuses for the close,
    // not as unavailable.
    let unavailable = |pending: &PendingConnection| {
        pending
            .closed()
            .map_or(UpgradeRefusal::Unavailable, UpgradeRefusal::from)
    };
    let client = pool.get().await.map_err(|e| {
        tracing::error!(error = ?e, "ws upgrade admission: pool checkout failed");
        unavailable(&pending)
    })?;
    // The credential, then the acting actor on every endpoint (one
    // soft-deleted under its live account keeps the account's credential and
    // its own grant rows), then the endpoint's roles, global grants only —
    // like the gates in front.
    let recheck = recheck_admission(&client, resolved, acting_actor_id, required_roles)
        .await
        .map_err(|e| {
            tracing::error!(error = ?e, "ws upgrade admission: re-check failed");
            unavailable(&pending)
        })?;
    drop(client);
    match recheck {
        AdmissionRecheck::Admitted => {}
        AdmissionRecheck::CredentialRevoked => {
            tracing::info!(%account_id, "ws upgrade admission: credential revoked during the upgrade");
            return Err(UpgradeRefusal::Revoked);
        }
        AdmissionRecheck::ActorInactive => {
            tracing::info!(%account_id, "ws upgrade admission: acting actor deleted during the upgrade");
            return Err(UpgradeRefusal::Revoked);
        }
        AdmissionRecheck::RoleRevoked => {
            tracing::info!(%account_id, "ws upgrade admission: role revoked during the upgrade");
            return Err(UpgradeRefusal::PermissionRevoked);
        }
    }

    connection_registry.admit(pending).map_err(|not_admitted| {
        tracing::info!(%account_id, %not_admitted, "ws upgrade admission: closed while pending");
        UpgradeRefusal::from(not_admitted)
    })
}

/// Whether the request asks for a WebSocket — an `Upgrade` header naming
/// `websocket`, case-insensitively, the one check the twin's upgrade helper
/// makes before it upgrades.
fn asks_for_websocket(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

/// Axum handler for `GET /ws` (and `HEAD`, which axum serves through it) —
/// upgrades to WebSocket with auth.
///
/// The gates run before the upgrade is looked at, as the twin's middleware
/// runs ahead of its upgrade helper: a refused caller hears its 403 / 401 /
/// 400 whether or not it asked to upgrade, and one the gates admit that did
/// not ask is a 404. Any other method on the path is a 404 too.
async fn ws_handler(
    State(state): State<WsHandlerState>,
    Query(query_pairs): Query<Vec<(String, String)>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let WsHandlerState {
        route,
        pending,
        peer,
        options:
            ActionWsOptions {
                max_message_bytes,
                outbound_queue_bytes,
                receive_timeout,
            },
    } = state;

    // The gate's origin check, then the credential walk — the in-handler half
    // of the belt the stack's `origin_layer` also wears
    // (`fuz_http::compose_stack`).
    let resolved = route
        .dispatch
        .gate
        .preflight(
            &headers,
            // The bearer leg's `api_token` touch has no skip-the-column form, so an
            // absent `ClientIp` extension records the sentinel rather than erasing.
            ClientIp::as_str_or_unresolved(client_ip.as_ref()),
        )
        .await;

    let resolved = match resolved {
        Ok(Some(resolved)) => resolved,
        Ok(None) => return fuz_http::authentication_required_response(),
        Err(refused) => return refused,
    };

    // Token-scope surface gate — a narrowed token cannot hold a socket.
    //
    // Rule 3 (`TokenScope::admits_non_rpc_surface`), and here it is doing real
    // work rather than being conservative for its own sake: server-initiated
    // pushes (broadcasts, role-grant-offer notifications, `ActionPeer`
    // requests) reach whatever the account's connection reaches, and there is
    // no per-recipient filter to narrow them by. So a scoped token that could
    // upgrade would observe far more than it was granted.
    if !resolved.scope().admits_non_rpc_surface() {
        return fuz_auth::token_scope_surface_denied_response(
            fuz_auth::TokenSurface::WsUpgrade.capability(),
        );
    }

    // Acting-actor phase — every endpoint, gated or not, as the twin's
    // `run_authorization_phase` on the upgrade route. The selector is read the way the
    // twin's `parse_acting` reads it: first occurrence, a malformed value as
    // omitted, unknown keys ignored. The helper answers the twin's 400s and
    // its `no_actors_on_account` 500.
    let acting = fuz_auth::parse_acting_selector(query_first(&query_pairs, "acting"))
        .ok()
        .flatten();
    let Ok(client) = route.dispatch.gate.pool.get().await.inspect_err(|e| {
        tracing::error!(error = ?e, "ws upgrade actor phase: pool checkout failed");
    }) else {
        return fuz_http::db_unavailable_response();
    };
    let actor = match fuz_auth::route_helpers::require_acting_actor(
        &client,
        &resolved.account.id,
        acting,
        "ws_upgrade",
    )
    .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };

    // Role gate — the coarse upgrade-time authority check over the resolved
    // actor's grants, run after the scope gate so a narrowed token is told
    // about its scope rather than about a role it also lacks (the TS twin
    // mounts the same gates in the same order). Empty `required_roles` skips
    // the read.
    //
    // Grain + denial body are documented on `WsRouteState::required_roles`.
    if !route.required_roles.is_empty() {
        match query_active_actor_holds_any_global_role(&client, &actor.id, &route.required_roles)
            .await
        {
            Ok(true) => {}
            Ok(false) => return fuz_http::insufficient_permissions_response(&route.required_roles),
            Err(e) => {
                tracing::error!(error = ?e, "ws upgrade role gate: role query failed");
                return fuz_http::internal_error_response();
            }
        }
    }
    drop(client);
    let acting_actor_id = actor.id;

    let client_ip_value = ClientIp::from_extension(client_ip.as_ref()).map(str::to_owned);

    // Only now the upgrade itself, past every gate: a request that is no
    // WebSocket upgrade at all (no `Upgrade: websocket`) is the path's 404 —
    // what the twin's upgrade helper answers by passing on to the not-found
    // handler — and one that asks to upgrade but is malformed (a missing key,
    // a wrong version) is axum's own refusal.
    let ws = match ws {
        Ok(ws) => ws,
        Err(_) if !asks_for_websocket(&headers) => return crate::server::not_found_response(),
        Err(rejection) => return rejection.into_response(),
    };
    // Held from before the handshake answers until the upgraded future ends,
    // so a server shutting down waits for this socket's close — a refusal
    // frame included — and not only for a registered loop's.
    let shutdown_hold = route.connection_registry.hold_upgrade();
    let ws = ws
        .max_message_size(max_message_bytes)
        .max_frame_size(max_message_bytes);
    ws.on_upgrade(move |socket| async move {
        let _shutdown_hold = shutdown_hold;
        // Build the outbound channel with the router's queue budget, then
        // admit: register pending → re-check the credential → admit (module
        // doc, "Admission: the revocation race").
        // The handshake has already answered 101, so a refusal is a close
        // frame — 4001 for a credential revoked mid-upgrade, 4006 for a gating
        // role revoked mid-upgrade, 1011 when the re-check itself failed, 1001
        // once the server is shutting down — and the loop never starts.
        let (notify_tx, notify_rx) = connection_channel(outbound_queue_bytes);
        let (conn, _guard) = match admit_upgrade(
            &route.connection_registry,
            &route.dispatch.gate.pool,
            &resolved,
            &acting_actor_id,
            &route.required_roles,
            notify_tx,
        )
        .await
        {
            Ok(admitted) => admitted,
            Err(refusal) => {
                refuse_upgrade(socket, refusal).await;
                return;
            }
        };

        // The socket closes when its credential expires (4001, "Credential
        // expired"): expiry writes nothing a revocation listener hears.
        let loop_options = WsLoopOptions {
            credential_deadline: resolved.credential_deadline,
            receive_timeout,
        };

        // Build the per-socket dispatch closure.
        let conn_state = Arc::new(WsConnectionState {
            auth: resolved,
            client_ip: client_ip_value,
            connection_id: conn.id,
        });
        let dispatch = ws_dispatch_fn(
            route.dispatch.perform_action_options(Arc::clone(&peer)),
            conn_state,
        );

        run_ws_connection(
            socket,
            Arc::clone(&route.connection_registry),
            conn,
            notify_rx,
            pending,
            dispatch,
            loop_options,
        )
        .await;
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ActionWsOptions, DEFAULT_WS_MAX_MESSAGE_BYTES, DEFAULT_WS_OUTBOUND_QUEUE_BYTES,
        DEFAULT_WS_RECEIVE_TIMEOUT,
    };
    use std::time::Duration;

    /// The default receive timeout is 60 s, the twin's server heartbeat.
    #[test]
    fn the_default_receive_timeout_is_the_twins_60_seconds() {
        assert_eq!(DEFAULT_WS_RECEIVE_TIMEOUT, Duration::from_secs(60));
        assert_eq!(
            ActionWsOptions::default().receive_timeout,
            Some(DEFAULT_WS_RECEIVE_TIMEOUT)
        );
    }

    /// The default outbound budget is 4 MiB — four default-size messages —
    /// and a different message cap leaves it where it is.
    #[test]
    fn the_default_outbound_budget_is_its_own_constant() {
        assert_eq!(DEFAULT_WS_MAX_MESSAGE_BYTES, 1024 * 1024);
        assert_eq!(DEFAULT_WS_OUTBOUND_QUEUE_BYTES, 4 * 1024 * 1024);
        assert_eq!(
            ActionWsOptions::default(),
            ActionWsOptions {
                max_message_bytes: DEFAULT_WS_MAX_MESSAGE_BYTES,
                outbound_queue_bytes: DEFAULT_WS_OUTBOUND_QUEUE_BYTES,
                receive_timeout: Some(DEFAULT_WS_RECEIVE_TIMEOUT),
            }
        );
        let raised = ActionWsOptions {
            max_message_bytes: 16 * DEFAULT_WS_MAX_MESSAGE_BYTES,
            ..ActionWsOptions::default()
        };
        assert_eq!(raised.outbound_queue_bytes, DEFAULT_WS_OUTBOUND_QUEUE_BYTES);
    }
}
