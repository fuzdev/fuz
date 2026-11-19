//! The room registry's vocabulary: ids, options, the shapes it answers and
//! fans out, and its refusals.

use std::fmt;
use std::num::NonZeroUsize;

use serde::Serialize;

/// The notification a room's members and watchers get when a member is
/// seated: `{room_id, seq, member}`.
pub const ROOM_MEMBER_JOINED_METHOD: &str = "room_member_joined";
/// The notification a room's members and watchers get when a member's seat
/// ends: `{room_id, seq, member_id, reason}` ([`RoomLeftReason`]).
pub const ROOM_MEMBER_LEFT_METHOD: &str = "room_member_left";
/// The notification a room's members and watchers get when a member sets its
/// state: `{room_id, seq, member_id, state}`.
pub const ROOM_MEMBER_STATE_METHOD: &str = "room_member_state";
/// A member's payload, to its addressee or to the room minus its sender:
/// `{room_id, seq, from, to, payload}`, `to` null for a room-wide send.
pub const ROOM_MESSAGE_METHOD: &str = "room_message";
/// The notification a seat's own connection gets when the server ends the
/// seat: `{room_id, member_id, reason, moved_to}` ([`RoomSeatLostReason`]).
pub const ROOM_SEAT_LOST_METHOD: &str = "room_seat_lost";
/// The notification a watcher gets when the server ends its watch:
/// `{room_id, reason}` ([`RoomEvictReason`]).
pub const ROOM_WATCH_ENDED_METHOD: &str = "room_watch_ended";

/// The longest [`RoomId`], in bytes (and characters: the id is ASCII).
pub const ROOM_ID_MAX_LENGTH: usize = 128;

/// Default [`RoomRegistryOptions::max_members_per_room`]: generous for a
/// full-mesh call, where every member holds a peer connection to every other.
pub const DEFAULT_ROOM_MAX_MEMBERS: usize = 32;
/// Default [`RoomRegistryOptions::max_payload_bytes`]: room for a session
/// description with many candidates, small beside the outbound budget.
pub const DEFAULT_ROOM_MAX_PAYLOAD_BYTES: usize = 64 * 1024;
/// Default [`RoomRegistryOptions::max_state_bytes`]: a few flags, encoded.
pub const DEFAULT_ROOM_MAX_STATE_BYTES: usize = 1024;
/// Default [`RoomRegistryOptions::max_watches_per_connection`].
pub const DEFAULT_ROOM_MAX_WATCHES_PER_CONNECTION: usize = 256;

/// A room's key — an opaque string the consumer chooses and parses (e.g. a
/// voice room keyed by a space id).
///
/// Bounded: 1 to [`ROOM_ID_MAX_LENGTH`] printable ASCII characters (`!`
/// through `~`, so no whitespace or control characters). ASCII keeps the
/// bound one number on both twins, where a UTF-16 length and a UTF-8 one
/// would differ.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RoomId(String);

impl RoomId {
    /// Parse a wire room id.
    ///
    /// # Errors
    ///
    /// [`RoomIdError`] when `raw` is empty, longer than
    /// [`ROOM_ID_MAX_LENGTH`], or holds a character outside `!`..=`~`.
    pub fn parse(raw: &str) -> Result<Self, RoomIdError> {
        if raw.is_empty() || raw.len() > ROOM_ID_MAX_LENGTH {
            return Err(RoomIdError::Length);
        }
        if !raw.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(RoomIdError::Character);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a string is not a [`RoomId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoomIdError {
    #[error("a room id is 1 to {ROOM_ID_MAX_LENGTH} characters")]
    Length,
    #[error("a room id is printable ASCII with no spaces")]
    Character,
}

/// One seat's id — random per join, so a client addresses members without
/// ever seeing a connection id, and a rejoin gets a new one.
///
/// A UUID on the wire (lowercase, hyphenated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct MemberId(uuid::Uuid);

impl MemberId {
    /// A fresh random id.
    #[must_use]
    pub fn random() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// The id a client named (a `to` or a `rejoin_of`).
    #[must_use]
    pub const fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id)
    }

    /// The id as a UUID.
    #[must_use]
    pub const fn as_uuid(self) -> uuid::Uuid {
        self.0
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A consumer's tag for the authority a seat or watch was admitted under.
///
/// Set from the authorizer's verdict — e.g. the group whose membership let
/// the actor in. Eviction targets it: when that authority changes, the
/// consumer evicts the scope, or an actor within it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoomScope(String);

impl RoomScope {
    /// Tag a scope.
    #[must_use]
    pub fn new(scope: impl Into<String>) -> Self {
        Self(scope.into())
    }

    /// The tag as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How a room's members reach each other's media — what the join answers,
/// so a client knows whom to connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomTopology {
    /// Every member connects to every other; the server relays only the
    /// members' messages.
    #[default]
    Mesh,
}

/// A [`crate::RoomRegistry`]'s bounds and rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomRegistryOptions {
    /// One seat per actor across the whole registry: an admitted join moves
    /// the actor's other seat, wherever it is, and the newest admitted seat
    /// wins (`room_seat_lost` with reason `moved` to the seat it displaced).
    pub exclusive: bool,
    /// The most members a room seats; an authorizer's verdict may lower it
    /// for one join, never raise it.
    pub max_members_per_room: NonZeroUsize,
    /// The longest message payload, in UTF-8 bytes.
    pub max_payload_bytes: usize,
    /// The longest member state, in UTF-8 bytes.
    pub max_state_bytes: usize,
    /// The most rooms one connection watches at once.
    pub max_watches_per_connection: usize,
    /// What the join answers as the room's topology.
    pub topology: RoomTopology,
}

impl Default for RoomRegistryOptions {
    fn default() -> Self {
        Self {
            exclusive: false,
            max_members_per_room: NonZeroUsize::new(DEFAULT_ROOM_MAX_MEMBERS)
                .unwrap_or(NonZeroUsize::MIN),
            max_payload_bytes: DEFAULT_ROOM_MAX_PAYLOAD_BYTES,
            max_state_bytes: DEFAULT_ROOM_MAX_STATE_BYTES,
            max_watches_per_connection: DEFAULT_ROOM_MAX_WATCHES_PER_CONNECTION,
            topology: RoomTopology::Mesh,
        }
    }
}

/// One seated member, as members and watchers see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoomMember {
    pub member_id: MemberId,
    pub actor_id: uuid::Uuid,
    /// The member's client-encoded state, `null` until it sets one.
    pub state: Option<String>,
}

/// What an admitted join answers: the seat, and the room as of `seq` — the
/// seq of the joiner's own `room_member_joined`, so a client drops every
/// buffered event at or below it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoomJoined {
    pub room_id: RoomId,
    pub member_id: MemberId,
    pub seq: u64,
    /// Every member, the joiner included, in seating order.
    pub members: Vec<RoomMember>,
    pub topology: RoomTopology,
}

/// What an admitted watch answers, and what [`crate::RoomRegistry::occupancy`]
/// reads: the room's members as of `seq`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoomOccupancy {
    pub room_id: RoomId,
    pub seq: u64,
    pub members: Vec<RoomMember>,
}

/// Why a member left, as `room_member_left` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomLeftReason {
    /// The member left.
    Left,
    /// The member's socket closed.
    Disconnected,
    /// The member's actor was seated elsewhere (exclusive registries), or its
    /// connection rejoined the room.
    Moved,
    /// The consumer evicted the member.
    Evicted,
    /// The consumer closed the room.
    RoomClosed,
}

/// Why the server ended a seat, as `room_seat_lost` tells the seat's own
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomSeatLostReason {
    /// A newer seat took over; `moved_to` names its room.
    Moved,
    Evicted,
    RoomClosed,
}

/// Why the consumer evicts — the reason members, seats, and watches are told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomEvictReason {
    /// The actor lost its access (removed from the group, say).
    Evicted,
    /// The room itself is gone (its space deleted, say).
    RoomClosed,
}

impl From<RoomEvictReason> for RoomLeftReason {
    fn from(reason: RoomEvictReason) -> Self {
        match reason {
            RoomEvictReason::Evicted => Self::Evicted,
            RoomEvictReason::RoomClosed => Self::RoomClosed,
        }
    }
}

impl From<RoomEvictReason> for RoomSeatLostReason {
    fn from(reason: RoomEvictReason) -> Self {
        match reason {
            RoomEvictReason::Evicted => Self::Evicted,
            RoomEvictReason::RoomClosed => Self::RoomClosed,
        }
    }
}

/// What [`crate::RoomRegistry::evict`] removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomEvictTarget {
    /// Every seat and watch of an actor.
    Actor(uuid::Uuid),
    /// An actor's seats and watches admitted under one scope.
    ActorInScope {
        actor_id: uuid::Uuid,
        scope: RoomScope,
    },
    /// Every seat and watch of a room.
    Room(RoomId),
    /// Every seat and watch admitted under a scope.
    Scope(RoomScope),
}

/// What one [`crate::RoomRegistry::evict`] removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoomEvicted {
    /// Seated members removed.
    pub seats: usize,
    /// Watches removed.
    pub watches: usize,
    /// Joins and watches in flight it reached: refused outright by an actor
    /// or room target, marked by a scope target (refused at admission only
    /// if their verdict names the scope).
    pub pending: usize,
}

/// A room operation's refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoomError {
    /// The connection is gone or closing, so nothing is seated on it.
    #[error("the connection is closed")]
    ConnectionClosed,
    /// An eviction reached the join or watch while it was in flight.
    #[error("the room was closed to this join while it was in flight")]
    Evicted,
    /// The connection left the room while its join was in flight.
    #[error("the join was superseded by a leave")]
    JoinSuperseded,
    /// The seat a rejoin names moved elsewhere since — its actor was seated
    /// again after it — so the rejoin would take that newer seat back.
    #[error("the seat named by the rejoin has moved")]
    SeatMoved,
    /// The room seats its maximum already.
    #[error("the room is full")]
    Full,
    /// The connection holds no seat in the room.
    #[error("not joined to the room")]
    NotJoined,
    /// The addressee is not a member of the room.
    #[error("no such member in the room")]
    MemberNotFound,
    /// The payload is over [`RoomRegistryOptions::max_payload_bytes`].
    #[error("the payload is too large")]
    PayloadTooLarge,
    /// The state is over [`RoomRegistryOptions::max_state_bytes`].
    #[error("the state is too large")]
    StateTooLarge,
    /// The connection watches [`RoomRegistryOptions::max_watches_per_connection`]
    /// rooms already.
    #[error("too many watches on this connection")]
    WatchLimit,
}
