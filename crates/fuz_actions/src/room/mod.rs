//! The room verbs over `fuz_realtime`'s [`RoomRegistry`]: join, leave, send,
//! state, watch, and unwatch, as a spec set a consumer mounts.
//!
//! [`build_room_spec_set`] returns the specs, each [`ActionSpec::ws_only`]
//! (a room belongs to a socket; over HTTP they answer `method_not_found`),
//! actor-required (`account: required, actor: required`), and without side
//! effects — the registry is memory, not the database, so no transaction
//! opens for a relayed message. The registry does the work and the fan-out;
//! this module parses, bounds, authorizes, and limits.
//!
//! Seats are keyed by connection and actor: under the dispatcher's `acting`
//! selector, a leave, send, or state set acts on the acting actor's own
//! seat, never another actor's on the same socket.
//!
//! ## The consumer's seams ([`RoomSpecSetOptions`])
//!
//! - **[`RoomAuthorize`]** decides each join and watch: [`RoomVerdict::Deny`]
//!   answers `room_not_found`, the same as a room that doesn't exist, so a
//!   caller learns nothing of rooms it can't enter; [`RoomVerdict::Allow`]
//!   carries the [`RoomScope`] the seat or watch is admitted under, for
//!   eviction, and an optional member cap below the registry's. It gets the
//!   caller's ids and the database, not the request's role grants: authority
//!   is read through the database inside the reserve window (the trait doc).
//! - **Eviction** is the consumer calling [`RoomRegistry::evict`] after its
//!   own authority change commits — from the handler's `post_commit_effects`
//!   — never before.
//! - **Rate limits.** `room_join` and `room_watch` carry the spine's
//!   per-account class ([`RateLimitClass::Account`]): each runs the
//!   consumer's database authorizer, and one account may hold many sockets.
//!   **[`RoomRateLimiter`]** is per connection, outside the account budget:
//!   it bounds the count of joins, sends, and state sets, and the bytes of
//!   payloads and states as each frame carries them (JSON-escaped,
//!   [`json_escaped_len`]), because every room-wide byte lands in each
//!   member's outbound queue (`fuz_actions::DEFAULT_WS_OUTBOUND_QUEUE_BYTES`)
//!   and a member reading slower than its room sends is closed for the
//!   overflow. A join stays on it too, since its state and the seats it
//!   moves fan out to every member; a watch fans out nothing, so it costs
//!   only its account charge.
//! - **`join_extra`**, a hook whose value the join answers as `extra`
//!   (`null` without one) — for what a consumer mints per seat.
//!
//! ## A join, step by step
//!
//! The dispatcher's account charge; parse; refuse a state over the
//! registry's bound; charge the connection's limiter;
//! [`RoomRegistry::reserve_seat`] (the join is now reachable by evictions);
//! the authorizer; then the request's own signal — a client `cancel` of the
//! join drops it here, answering `request_cancelled` — and
//! [`RoomRegistry::admit_seat`]. A socket closing mid-authorizer drops the
//! request future, and with it the join in flight. A watch runs the same
//! steps through the watch halves, without the connection's limiter.
//!
//! ## Wire
//!
//! `payload` and `state` are strings the client encodes, so both twins
//! measure their bounds alike, in UTF-8 bytes; the limiter charges their
//! escaped length. A send addressed to the sender's own member id is refused
//! as `room_member_not_found`. Refusals carry `data.reason`: the
//! `ERROR_ROOM_*` constants, plus `rate_limited` with `data.retry_after`.
//! The notifications are the `ROOM_*_METHOD` constants `fuz_realtime` fans
//! out, each with the room's `seq` (`fuz_realtime`'s `room_registry` module
//! doc says what it promises).

mod rate_limit;

use std::sync::Arc;

use futures::future::BoxFuture;
use fuz_auth::{AuthSpec, CredentialGate, RateLimitClass, RequestActorContext};
use fuz_db::ActionDb;
use fuz_http::{InputShape, JsonrpcError};
use fuz_realtime::{
    ConnectionId, MemberId, RoomError, RoomId, RoomJoined, RoomRegistry, RoomRegistryOptions,
    RoomScope, RoomSeatAdmit, RoomSeatRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::action_context::ActionContext;
use crate::action_registry::ActionHandler;
use crate::action_spec::ActionSpec;

pub use rate_limit::{
    DEFAULT_ROOM_RATE_LIMIT, JSON_ESCAPE_MAX_EXPANSION, RoomRateLimitOptions, RoomRateLimited,
    RoomRateLimiter, json_escaped_len,
};

/// Seat the caller in a room: `{room_id, state?, rejoin_of?}` →
/// `{room_id, member_id, seq, members, topology, extra}`.
pub const ROOM_JOIN_METHOD: &str = "room_join";
/// End the caller's seat in a room: `{room_id}` → `{left}`.
pub const ROOM_LEAVE_METHOD: &str = "room_leave";
/// Relay a payload: `{room_id, to, payload}` → `null`, `to` a member id or
/// `null` for the whole room.
pub const ROOM_SEND_METHOD: &str = "room_send";
/// Set the caller's member state: `{room_id, state}` → `{seq}`.
pub const ROOM_STATE_SET_METHOD: &str = "room_state_set";
/// Watch a room's members without joining: `{room_id}` →
/// `{room_id, seq, members}`.
pub const ROOM_WATCH_METHOD: &str = "room_watch";
/// Stop watching: `{room_id}` → `{unwatched}`.
pub const ROOM_UNWATCH_METHOD: &str = "room_unwatch";

/// No such room, or one the caller may not join or watch (the IDOR mask),
/// or one an eviction closed to the request while it was in flight.
pub const ERROR_ROOM_NOT_FOUND: &str = "room_not_found";
/// The room seats its maximum.
pub const ERROR_ROOM_FULL: &str = "room_full";
/// The caller's own leave of the room overtook the join.
pub const ERROR_ROOM_JOIN_SUPERSEDED: &str = "room_join_superseded";
/// A rejoin names a seat that has moved since — its actor sits elsewhere now
/// (exclusive registries).
pub const ERROR_ROOM_SEAT_MOVED: &str = "room_seat_moved";
/// The caller's connection holds no seat in the room.
pub const ERROR_ROOM_NOT_JOINED: &str = "room_not_joined";
/// The addressee is not a member of the room, or is the sender's own seat.
pub const ERROR_ROOM_MEMBER_NOT_FOUND: &str = "room_member_not_found";
/// The payload is over the registry's bound.
pub const ERROR_ROOM_PAYLOAD_TOO_LARGE: &str = "room_payload_too_large";
/// The state is over the registry's bound.
pub const ERROR_ROOM_STATE_TOO_LARGE: &str = "room_state_too_large";
/// The connection watches its maximum of rooms.
pub const ERROR_ROOM_WATCH_LIMIT: &str = "room_watch_limit";

/// Which access an authorizer decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomAccess {
    /// A seat: the caller hears and sends messages, and is seen.
    Join,
    /// A watch: the caller sees who is seated, nothing more.
    Watch,
}

/// What [`RoomAuthorize`] decides on: who asks, for which room and access.
///
/// It carries the caller's identity, never its authority. Each field is
/// fixed for the request's life, so none can go stale between the
/// dispatcher's resolve and the authorizer's read:
///
/// - `actor_id` — the acting actor (after the `acting` selector), the key a
///   policy reads its grants and memberships by;
/// - `account_id` — the actor's account, which an actor never changes, for
///   a policy keyed by account;
/// - `room_id`, `access` — the request itself.
///
/// Whether the actor or account is still live (not soft-deleted since the
/// dispatcher resolved it) is the authorizer's to read with its grants, as
/// any live-grant read does.
#[derive(Debug, Clone, Copy)]
pub struct RoomAuthorizeInput<'a> {
    pub actor_id: Uuid,
    pub account_id: Uuid,
    pub room_id: &'a RoomId,
    pub access: RoomAccess,
}

/// An authorizer's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomVerdict {
    /// Answered `room_not_found`, as a missing room is.
    Deny,
    /// Admitted under `scope` (eviction's handle on it); `max_members`
    /// lowers the registry's cap for this join, and a watch ignores it.
    Allow {
        scope: Option<RoomScope>,
        max_members: Option<usize>,
    },
}

/// The consumer's decision on each join and watch.
///
/// Runs between the registry's reserve and admit, so an eviction landing
/// while it reads still reaches the request ([`RoomRegistry`]'s two-phase
/// join). It reads through `db`, the request's pooled client (the specs
/// have no side effects, so there is no transaction), under READ COMMITTED,
/// and must only read. A room it doesn't know is a [`RoomVerdict::Deny`].
///
/// **Authority is read through `db`, inside the reserve window, never from
/// the request.** The dispatcher loads the actor's role grants before the
/// handler runs, so before the reserve: a consumer's eviction (its write
/// committed, then [`RoomRegistry::evict`]) landing between that load and
/// the reserve finds no join in flight to reach, and a verdict on those
/// grants would seat the evicted actor. A read after the reserve sees the
/// committed write, or the eviction reaches the join — the race closes
/// either way. So the input carries the caller's ids
/// ([`RoomAuthorizeInput`]), not its grants.
///
/// **Object-safe** — dispatched as `Arc<dyn RoomAuthorize>`, async through a
/// [`BoxFuture`] per the spine's dyn-trait carve-out.
pub trait RoomAuthorize: Send + Sync {
    /// Decide `input` for the caller.
    ///
    /// # Errors
    ///
    /// A hard failure (a query that failed), answered as it is.
    fn authorize<'a>(
        &'a self,
        input: &'a RoomAuthorizeInput<'a>,
        db: &'a ActionDb<'a>,
    ) -> BoxFuture<'a, Result<RoomVerdict, JsonrpcError>>;
}

/// What [`RoomJoinExtra`] gets for an admitted seat.
#[derive(Debug, Clone, Copy)]
pub struct RoomJoinExtraInput<'a> {
    /// The request's context as the dispatcher resolved it, before the
    /// reserve: its `role_grants` may predate an eviction, so derive nothing
    /// from them that needs current authority (the seat itself was admitted
    /// on the authorizer's live read).
    pub auth: &'a RequestActorContext,
    pub room_id: &'a RoomId,
    pub member_id: MemberId,
}

/// A consumer's addition to every admitted join's answer, as `extra`.
pub type RoomJoinExtra = Arc<dyn Fn(&RoomJoinExtraInput<'_>) -> Value + Send + Sync>;

/// The consumer's seams into [`build_room_spec_set`].
pub struct RoomSpecSetOptions {
    /// The registry, over the connection registry of the WebSocket endpoint
    /// the specs are mounted on.
    pub registry: Arc<RoomRegistry>,
    pub authorizer: Arc<dyn RoomAuthorize>,
    /// `None` leaves the verbs unlimited — a test server's choice, not a
    /// deployment's.
    pub limiter: Option<Arc<RoomRateLimiter>>,
    /// `None` answers `extra: null`.
    pub join_extra: Option<RoomJoinExtra>,
}

impl std::fmt::Debug for RoomSpecSetOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomSpecSetOptions")
            .field("registry", &self.registry.options())
            .field("limiter", &self.limiter)
            .field("join_extra", &self.join_extra.is_some())
            .finish_non_exhaustive()
    }
}

/// Why [`build_room_spec_set`] refused its options: a limiter that would
/// refuse a request the registry's bounds admit, forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoomSpecSetError {
    /// The limiter's `max_requests` is zero.
    #[error("the room limiter's max_requests is 0, so it refuses every join, send, and state set")]
    NoRequestBudget,
    /// The limiter's `max_bytes` is below what one max-size payload or state
    /// can charge (its UTF-8 bound times [`JSON_ESCAPE_MAX_EXPANSION`]).
    #[error(
        "the room limiter's max_bytes ({max_bytes}) is below the worst-case charge of a max-size {bound} ({charge} bytes), which it would refuse forever"
    )]
    ByteBudgetBelowBound {
        /// `"payload"` or `"state"`.
        bound: &'static str,
        charge: u64,
        max_bytes: u64,
    },
}

/// Refuse a limiter that can never cover a request the registry admits.
fn check_limits(
    registry: &RoomRegistryOptions,
    limiter: &RoomRateLimitOptions,
) -> Result<(), RoomSpecSetError> {
    if limiter.max_requests == 0 {
        return Err(RoomSpecSetError::NoRequestBudget);
    }
    for (bound, bytes) in [
        ("payload", registry.max_payload_bytes),
        ("state", registry.max_state_bytes),
    ] {
        let charge = u64::try_from(bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(JSON_ESCAPE_MAX_EXPANSION);
        if charge > limiter.max_bytes {
            return Err(RoomSpecSetError::ByteBudgetBelowBound {
                bound,
                charge,
                max_bytes: limiter.max_bytes,
            });
        }
    }
    Ok(())
}

/// Build the room verbs (module doc), ready to extend a consumer's registry.
///
/// # Errors
///
/// [`RoomSpecSetError`] when the limiter can never cover a request the
/// registry's bounds admit: no request budget, or a byte budget below a
/// max-size payload's or state's worst-case escaped charge.
pub fn build_room_spec_set(
    options: RoomSpecSetOptions,
) -> Result<Vec<ActionSpec>, RoomSpecSetError> {
    let RoomSpecSetOptions {
        registry,
        authorizer,
        limiter,
        join_extra,
    } = options;
    if let Some(limiter) = &limiter {
        check_limits(registry.options(), limiter.options())?;
    }
    let rooms = Arc::new(Rooms {
        registry,
        authorizer,
        limiter,
        join_extra,
    });
    // join and watch run the consumer's database authorizer: the account
    // budget bounds them across every socket the account holds
    let account = Some(RateLimitClass::Account);
    Ok(vec![
        room_spec(ROOM_JOIN_METHOD, account, &rooms, |rooms, params, ctx| {
            Box::pin(async move { rooms.join(params, &ctx).await })
        }),
        room_spec(ROOM_LEAVE_METHOD, None, &rooms, |rooms, params, ctx| {
            Box::pin(async move { rooms.leave(params, &ctx) })
        }),
        room_spec(ROOM_SEND_METHOD, None, &rooms, |rooms, params, ctx| {
            Box::pin(async move { rooms.send(params, &ctx) })
        }),
        room_spec(ROOM_STATE_SET_METHOD, None, &rooms, |rooms, params, ctx| {
            Box::pin(async move { rooms.set_state(params, &ctx) })
        }),
        room_spec(ROOM_WATCH_METHOD, account, &rooms, |rooms, params, ctx| {
            Box::pin(async move { rooms.watch(params, &ctx).await })
        }),
        room_spec(ROOM_UNWATCH_METHOD, None, &rooms, |rooms, params, ctx| {
            Box::pin(async move { rooms.unwatch(params, &ctx) })
        }),
    ])
}

/// A room verb's body, given the shared state.
type RoomHandleFn =
    for<'a> fn(Arc<Rooms>, Value, ActionContext<'a>) -> BoxFuture<'a, Result<Value, JsonrpcError>>;

/// One room verb: WS-only, actor-required, no side effects, object input,
/// under `rate_limit`.
fn room_spec(
    method: &'static str,
    rate_limit: Option<RateLimitClass>,
    rooms: &Arc<Rooms>,
    handle: RoomHandleFn,
) -> ActionSpec {
    let rooms = Arc::clone(rooms);
    let handler: ActionHandler =
        Arc::new(move |params, ctx| handle(Arc::clone(&rooms), params, ctx));
    let spec = ActionSpec::read_only(
        method,
        AuthSpec::authenticated(CredentialGate::Any),
        InputShape::Object,
        handler,
    )
    .with_ws_only();
    match rate_limit {
        Some(class) => spec.with_rate_limit(class),
        None => spec,
    }
}

/// The specs' shared state.
struct Rooms {
    registry: Arc<RoomRegistry>,
    authorizer: Arc<dyn RoomAuthorize>,
    limiter: Option<Arc<RoomRateLimiter>>,
    join_extra: Option<RoomJoinExtra>,
}

// -- inputs (mirror the TS twin's schemas) ---------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoomJoinInput {
    room_id: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default, deserialize_with = "fuz_http::deserialize_optional_wire_uuid")]
    rejoin_of: Option<Uuid>,
    /// Read by the dispatcher's authorization phase.
    #[serde(
        default,
        rename = "acting",
        deserialize_with = "fuz_http::deserialize_optional_wire_uuid"
    )]
    _acting: Option<Uuid>,
}

/// `room_leave`, `room_watch`, and `room_unwatch`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoomIdInput {
    room_id: String,
    #[serde(
        default,
        rename = "acting",
        deserialize_with = "fuz_http::deserialize_optional_wire_uuid"
    )]
    _acting: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoomSendInput {
    room_id: String,
    /// Required, `null` for the whole room.
    #[serde(deserialize_with = "fuz_http::deserialize_nullish_wire_uuid")]
    to: Option<Uuid>,
    payload: String,
    #[serde(
        default,
        rename = "acting",
        deserialize_with = "fuz_http::deserialize_optional_wire_uuid"
    )]
    _acting: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoomStateSetInput {
    room_id: String,
    state: String,
    #[serde(
        default,
        rename = "acting",
        deserialize_with = "fuz_http::deserialize_optional_wire_uuid"
    )]
    _acting: Option<Uuid>,
}

#[derive(Serialize)]
struct RoomJoinOutput {
    #[serde(flatten)]
    joined: RoomJoined,
    extra: Value,
}

// -- handlers -------------------------------------------------------------------

impl Rooms {
    async fn join(&self, params: Value, ctx: &ActionContext<'_>) -> Result<Value, JsonrpcError> {
        let input: RoomJoinInput = fuz_http::parse_strict_params(params)?;
        let room_id = parse_room_id(&input.room_id)?;
        let (auth, connection_id) = caller(ctx, ROOM_JOIN_METHOD)?;
        if input
            .state
            .as_ref()
            .is_some_and(|state| state.len() > self.registry.options().max_state_bytes)
        {
            return Err(room_error(RoomError::StateTooLarge));
        }
        self.charge(
            connection_id,
            input.state.as_deref().map_or(0, json_escaped_len),
        )?;
        let pending = self
            .registry
            .reserve_seat(RoomSeatRequest {
                connection_id,
                actor_id: auth.actor.id,
                room_id: room_id.clone(),
                rejoin_of: input.rejoin_of.map(MemberId::from_uuid),
            })
            .map_err(room_error)?;
        let authorize_input = RoomAuthorizeInput {
            actor_id: auth.actor.id,
            account_id: auth.account.id,
            room_id: &room_id,
            access: RoomAccess::Join,
        };
        let RoomVerdict::Allow { scope, max_members } =
            self.authorizer.authorize(&authorize_input, &ctx.db).await?
        else {
            return Err(room_not_found());
        };
        if ctx.signal.is_cancelled() {
            return Err(cancelled());
        }
        let joined = self
            .registry
            .admit_seat(
                pending,
                RoomSeatAdmit {
                    scope,
                    max_members,
                    state: input.state,
                },
            )
            .map_err(room_error)?;
        let extra = self.join_extra.as_ref().map_or(Value::Null, |extra| {
            extra(&RoomJoinExtraInput {
                auth,
                room_id: &room_id,
                member_id: joined.member_id,
            })
        });
        to_output(&RoomJoinOutput { joined, extra })
    }

    fn leave(&self, params: Value, ctx: &ActionContext<'_>) -> Result<Value, JsonrpcError> {
        let input: RoomIdInput = fuz_http::parse_strict_params(params)?;
        let room_id = parse_room_id(&input.room_id)?;
        let (auth, connection_id) = caller(ctx, ROOM_LEAVE_METHOD)?;
        let left = self.registry.leave(connection_id, auth.actor.id, &room_id);
        Ok(json!({ "left": left }))
    }

    fn send(&self, params: Value, ctx: &ActionContext<'_>) -> Result<Value, JsonrpcError> {
        let input: RoomSendInput = fuz_http::parse_strict_params_allowing_null(params, &["to"])?;
        let room_id = parse_room_id(&input.room_id)?;
        let (auth, connection_id) = caller(ctx, ROOM_SEND_METHOD)?;
        if input.payload.len() > self.registry.options().max_payload_bytes {
            return Err(room_error(RoomError::PayloadTooLarge));
        }
        self.charge(connection_id, json_escaped_len(&input.payload))?;
        self.registry
            .send(
                connection_id,
                auth.actor.id,
                &room_id,
                input.to.map(MemberId::from_uuid),
                &input.payload,
            )
            .map_err(room_error)?;
        Ok(Value::Null)
    }

    fn set_state(&self, params: Value, ctx: &ActionContext<'_>) -> Result<Value, JsonrpcError> {
        let input: RoomStateSetInput = fuz_http::parse_strict_params(params)?;
        let room_id = parse_room_id(&input.room_id)?;
        let (auth, connection_id) = caller(ctx, ROOM_STATE_SET_METHOD)?;
        if input.state.len() > self.registry.options().max_state_bytes {
            return Err(room_error(RoomError::StateTooLarge));
        }
        self.charge(connection_id, json_escaped_len(&input.state))?;
        let seq = self
            .registry
            .set_state(connection_id, auth.actor.id, &room_id, input.state)
            .map_err(room_error)?;
        Ok(json!({ "seq": seq }))
    }

    async fn watch(&self, params: Value, ctx: &ActionContext<'_>) -> Result<Value, JsonrpcError> {
        let input: RoomIdInput = fuz_http::parse_strict_params(params)?;
        let room_id = parse_room_id(&input.room_id)?;
        let (auth, connection_id) = caller(ctx, ROOM_WATCH_METHOD)?;
        let pending = self
            .registry
            .reserve_watch(connection_id, auth.actor.id, room_id.clone())
            .map_err(room_error)?;
        let authorize_input = RoomAuthorizeInput {
            actor_id: auth.actor.id,
            account_id: auth.account.id,
            room_id: &room_id,
            access: RoomAccess::Watch,
        };
        let RoomVerdict::Allow { scope, .. } =
            self.authorizer.authorize(&authorize_input, &ctx.db).await?
        else {
            return Err(room_not_found());
        };
        if ctx.signal.is_cancelled() {
            return Err(cancelled());
        }
        let occupancy = self
            .registry
            .admit_watch(pending, scope)
            .map_err(room_error)?;
        to_output(&occupancy)
    }

    fn unwatch(&self, params: Value, ctx: &ActionContext<'_>) -> Result<Value, JsonrpcError> {
        let input: RoomIdInput = fuz_http::parse_strict_params(params)?;
        let room_id = parse_room_id(&input.room_id)?;
        let (_, connection_id) = caller(ctx, ROOM_UNWATCH_METHOD)?;
        let unwatched = self.registry.unwatch(connection_id, &room_id);
        Ok(json!({ "unwatched": unwatched }))
    }

    /// Charge the connection's limiter one request and `bytes`, as escaped.
    fn charge(&self, connection_id: ConnectionId, bytes: usize) -> Result<(), JsonrpcError> {
        let Some(limiter) = &self.limiter else {
            return Ok(());
        };
        limiter.charge(connection_id, bytes).map_err(|limited| {
            fuz_http::rate_limited(
                "rate limited",
                Some(json!({ "retry_after": limited.retry_after })),
            )
        })
    }
}

/// The caller's actor and socket. The dispatcher resolved the actor (the
/// specs require one) and refuses the specs over HTTP, so both are there;
/// the refusals are defense.
fn caller<'c>(
    ctx: &'c ActionContext<'_>,
    method: &str,
) -> Result<(&'c RequestActorContext, ConnectionId), JsonrpcError> {
    let auth = ctx.auth.actor().ok_or_else(fuz_http::unauthenticated)?;
    let connection_id = ctx
        .connection_id
        .ok_or_else(|| fuz_http::method_not_found(method))?;
    Ok((auth, connection_id))
}

/// Read a wire room id, refused as the twin's input schema refuses it.
fn parse_room_id(raw: &str) -> Result<RoomId, JsonrpcError> {
    RoomId::parse(raw).map_err(|e| fuz_http::invalid_input_params(&format!("room_id: {e}"), None))
}

fn to_output<T: Serialize>(output: &T) -> Result<Value, JsonrpcError> {
    serde_json::to_value(output)
        .map_err(|e| fuz_http::internal_error_with_source("room output serialization failed", &e))
}

fn room_not_found() -> JsonrpcError {
    fuz_http::not_found("room", Some(ERROR_ROOM_NOT_FOUND))
}

fn cancelled() -> JsonrpcError {
    fuz_http::request_cancelled("request cancelled")
}

/// The answer for a registry refusal.
fn room_error(error: RoomError) -> JsonrpcError {
    match error {
        RoomError::Evicted => room_not_found(),
        // the socket is closing; nothing will read this
        RoomError::ConnectionClosed => cancelled(),
        RoomError::JoinSuperseded => fuz_http::conflict(
            "the join was superseded by a leave",
            Some(ERROR_ROOM_JOIN_SUPERSEDED),
        ),
        RoomError::SeatMoved => {
            fuz_http::conflict("the seat has moved", Some(ERROR_ROOM_SEAT_MOVED))
        }
        RoomError::Full => fuz_http::conflict("room is full", Some(ERROR_ROOM_FULL)),
        RoomError::NotJoined => {
            fuz_http::conflict("not joined to the room", Some(ERROR_ROOM_NOT_JOINED))
        }
        RoomError::MemberNotFound => {
            fuz_http::not_found("room member", Some(ERROR_ROOM_MEMBER_NOT_FOUND))
        }
        RoomError::PayloadTooLarge => {
            fuz_http::invalid_params("payload is too large", Some(ERROR_ROOM_PAYLOAD_TOO_LARGE))
        }
        RoomError::StateTooLarge => {
            fuz_http::invalid_params("state is too large", Some(ERROR_ROOM_STATE_TOO_LARGE))
        }
        RoomError::WatchLimit => {
            fuz_http::conflict("too many watches", Some(ERROR_ROOM_WATCH_LIMIT))
        }
    }
}

#[cfg(test)]
mod tests;
