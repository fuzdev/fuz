//! Rooms over the WebSocket registry: members seated in a room by key,
//! relayed messages, per-member state, and occupancy watches.
//!
//! A room is a key ([`RoomId`]) the consumer chooses — e.g. a voice room
//! keyed by a space id — holding **seats** and **watches**. A seat is one
//! actor's membership on one connection, with a random [`MemberId`] that
//! clients address each other by (a connection id never reaches the wire)
//! and a small client-encoded state string. Seats are keyed by connection
//! and actor: a connection whose requests act as different actors of one
//! account (the dispatcher's `acting` selector) holds a seat per actor, and
//! a leave, send, or state set touches only the acting actor's own seat; an
//! event skips the seat that caused it, not its connection. A watch sees the
//! members without joining; it is one per connection and room, whichever
//! actor last asked for it. The registry relays opaque payloads between
//! members and knows nothing of what they carry. Rooms live in memory and
//! die with the process: a restart drops every room and clients rejoin.
//!
//! The action specs over it — the verbs, the authorizer hook, the
//! per-connection limiter — are `fuz_actions`' `room` module; this crate
//! holds the state and the fan-out, and no `ActionSpec` knowledge.
//!
//! ## One lock, one order
//!
//! Rooms, seats, watches, joins in flight, and the per-connection and
//! per-actor indexes sit under one `parking_lot::Mutex`, since exclusivity
//! and eviction span rooms. Every notification is queued **under** it,
//! through [`ConnectionRegistry`]'s non-blocking sends, so each room's
//! events carry a `seq` that orders them: one counter per room, bumped by
//! every event in the room. The lock order is this registry, then the
//! connection registry, which never calls back. A room with no seats and no
//! watches is deleted; a new one starts its `seq` again at zero.
//!
//! `seq` orders a room's events, and lets a client drop the events at or
//! below the snapshot a join or watch answered; it is not contiguous per
//! client (an addressed message bumps it, and only the addressee sees that
//! one), and it restarts when a room is deleted and created again. Order
//! across rooms is unspecified: one eviction or disconnect spanning several
//! rooms tells them in no promised order; within a room, the events that
//! carry a `seq` follow it.
//!
//! Nothing here waits: a recipient that cannot take a frame is closed for
//! the overflow (4005) by the connection registry, and its seats are then
//! released like any other disconnect.
//!
//! ## Two-phase join
//!
//! A join is [`RoomRegistry::reserve_seat`], the consumer's authorizer, then
//! [`RoomRegistry::admit_seat`]. The reserve inserts the join **in flight**
//! before the authorizer reads anything, refused when the socket has already
//! closed, and returns a [`PendingSeat`] whose drop removes it — so a join
//! cut off mid-authorizer (its socket closed, its request future dropped)
//! leaves nothing behind. While in flight it is reachable: an eviction that
//! names its actor or room refuses it, one that names a scope marks it, so
//! the admit refuses when the verdict's scope is that one, and the
//! connection's own [`RoomRegistry::leave`] of the room refuses it as
//! superseded. That closes the race of an eviction against an authorizer:
//! a consumer evicts after its write commits, and its authorizer reads under
//! READ COMMITTED, so the eviction either precedes the reserve — then its
//! commit precedes the authorizer's read, which denies — or follows it and
//! reaches the join in flight.
//!
//! The argument holds only for authority the authorizer **reads inside that
//! window**, after the reserve, from the database. Anything loaded before
//! the reserve — the request's own role grants, which the dispatcher reads
//! before the handler runs — may predate an eviction that also precedes the
//! reserve and so found nothing in flight to reach: the stale read would
//! admit an evicted actor. `fuz_actions`' authorizer hook therefore gets the
//! caller's ids and the database, never the request's grants. Watches run
//! the same two phases ([`RoomRegistry::reserve_watch`],
//! [`RoomRegistry::admit_watch`]).
//!
//! The admit seats the member unless it was refused meanwhile, its socket
//! closed, or the room is full. A refused join displaces nothing.
//!
//! ## Exclusivity and the rejoin guard
//!
//! With [`RoomRegistryOptions::exclusive`] an actor holds one seat across
//! the registry: the newest **admitted** join wins (admits serialize under
//! the lock, so two sockets racing settle by which admits last, not which
//! sent first), and the seat it displaces hears `room_seat_lost` with reason
//! `moved` and `moved_to`, the new seat's room. Either way a connection
//! holds one seat per room for each actor; joining again as that actor moves
//! its old seat the same way.
//!
//! A seat whose socket died never hears that it moved. Its client, on
//! reconnecting, rejoins naming the seat it held (`rejoin_of`), and must not
//! take back the seat its actor holds now. So an exclusive registry keeps a
//! short per-actor **tombstone** of seats that ended without a leave: each
//! seat moved away, and each released by its disconnect, which counts as
//! moved once the actor is seated again by any other join. A rejoin naming
//! a moved seat is refused ([`RoomError::SeatMoved`]) instead of seated; one
//! naming a seat released by its disconnect and not moved since is seated,
//! as is any other. Tombstones last [`ROOM_REJOIN_TOMBSTONE_TTL`], at most
//! [`ROOM_REJOIN_TOMBSTONES_PER_ACTOR`] per actor; past either bound a
//! rejoin is seated like a fresh join.
//!
//! ## Disconnect
//!
//! The first seat or watch a connection reserves arms **one** waiter on the
//! connection's socket token — the token every close path cancels, read
//! crate-privately from [`ConnectionRegistry`] — and the connection keeps it
//! for its life, however many joins and leaves it makes. When the token
//! fires, the waiter releases every seat (`room_member_left` with reason
//! `disconnected`), watch, and join in flight the connection holds.
//!
//! ## Eviction
//!
//! [`RoomRegistry::evict`] is the consumer's call when its own authority
//! changes, made after the change commits: by actor, by actor within a
//! scope, by room, or by scope ([`RoomEvictTarget`]), covering seats, watches,
//! and joins in flight alike, so an evicted actor keeps neither a seat nor
//! a watch. Its socket still hears the room while another actor of the same
//! account is seated there or holds the watch, on that actor's own
//! authority.
//!
//! ## Bounds
//!
//! Seats are bounded by the rooms' cap (and by one per actor when exclusive),
//! watches per connection, joins in flight by the connection's in-flight
//! request cap, waiters at one per connection, and tombstones as above.

mod types;

#[cfg(test)]
mod tests;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::connection::ConnectionId;
use crate::connection_registry::ConnectionRegistry;

pub use types::{
    DEFAULT_ROOM_MAX_MEMBERS, DEFAULT_ROOM_MAX_PAYLOAD_BYTES, DEFAULT_ROOM_MAX_STATE_BYTES,
    DEFAULT_ROOM_MAX_WATCHES_PER_CONNECTION, MemberId, ROOM_ID_MAX_LENGTH,
    ROOM_MEMBER_JOINED_METHOD, ROOM_MEMBER_LEFT_METHOD, ROOM_MEMBER_STATE_METHOD,
    ROOM_MESSAGE_METHOD, ROOM_SEAT_LOST_METHOD, ROOM_WATCH_ENDED_METHOD, RoomError,
    RoomEvictReason, RoomEvictTarget, RoomEvicted, RoomId, RoomIdError, RoomJoined, RoomLeftReason,
    RoomMember, RoomOccupancy, RoomRegistryOptions, RoomScope, RoomSeatLostReason, RoomTopology,
};

/// How long an exclusive registry remembers a seat that ended without a
/// leave, for the rejoin guard (module doc).
pub const ROOM_REJOIN_TOMBSTONE_TTL: Duration = Duration::from_mins(15);

/// The most tombstones an exclusive registry keeps per actor; past it the
/// oldest goes.
pub const ROOM_REJOIN_TOMBSTONES_PER_ACTOR: usize = 8;

/// The most scope evictions one join or watch in flight records; past it
/// the join or watch is refused outright, whatever its verdict's scope.
///
/// A client sees what any eviction of its request in flight answers: the
/// join or watch is refused as if the room were missing (`room_not_found`
/// from the verbs). It trips only when more distinct scopes than this are
/// evicted during one authorizer read. Both twins hold the same bound.
pub const MAX_POISONED_SCOPES: usize = 16;

/// The fewest actors the tombstone map holds before it sweeps expired
/// entries; it sweeps again at twice what a sweep leaves.
const TOMBSTONE_SWEEP_FLOOR: usize = 64;

/// A join to seat: who, on which connection, into which room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSeatRequest {
    pub connection_id: ConnectionId,
    pub actor_id: Uuid,
    pub room_id: RoomId,
    /// The seat this join takes up again after a reconnect — refused as
    /// [`RoomError::SeatMoved`] on an exclusive registry when that seat has
    /// moved since (module doc); ignored otherwise.
    pub rejoin_of: Option<MemberId>,
}

/// What the authorizer's verdict and the request add at admission.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomSeatAdmit {
    /// The authority the seat is admitted under, for eviction.
    pub scope: Option<RoomScope>,
    /// This join's member cap, below the registry's; `None` keeps the
    /// registry's.
    pub max_members: Option<usize>,
    /// The member's initial state.
    pub state: Option<String>,
}

/// The room registry: see the module doc.
///
/// Build one over the connection registry its WebSocket endpoint uses
/// (`Arc::new(RoomRegistry::new(Arc::clone(&connections), options))`); a
/// connection id from any other registry names no socket here. Its reserves
/// spawn a task, so they run inside a tokio runtime.
#[derive(Debug)]
pub struct RoomRegistry {
    connections: Arc<ConnectionRegistry>,
    options: RoomRegistryOptions,
    state: Mutex<State>,
    /// Disconnect waiters alive — one per connection that ever reserved.
    live_waiters: Arc<AtomicUsize>,
}

impl RoomRegistry {
    /// An empty registry over `connections`.
    #[must_use]
    pub fn new(connections: Arc<ConnectionRegistry>, options: RoomRegistryOptions) -> Self {
        Self {
            connections,
            options,
            state: Mutex::new(State::default()),
            live_waiters: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The registry's options.
    #[must_use]
    pub const fn options(&self) -> &RoomRegistryOptions {
        &self.options
    }

    /// Phase one of a join: put it in flight before the authorizer runs
    /// (module doc, "Two-phase join").
    ///
    /// # Errors
    ///
    /// [`RoomError::ConnectionClosed`] when the connection is gone or closing;
    /// [`RoomError::SeatMoved`] when the request is a rejoin of a seat that
    /// has moved (exclusive registries).
    pub fn reserve_seat(
        self: &Arc<Self>,
        request: RoomSeatRequest,
    ) -> Result<PendingSeat, RoomError> {
        let RoomSeatRequest {
            connection_id,
            actor_id,
            room_id,
            rejoin_of,
        } = request;
        let member_id = MemberId::random();
        let ticket = {
            let mut guard = self.state.lock();
            let state = &mut *guard;
            if self.options.exclusive
                && let Some(rejoin_of) = rejoin_of
                && state
                    .tombstones
                    .rejoin_moved(actor_id, rejoin_of, Instant::now())
            {
                return Err(RoomError::SeatMoved);
            }
            let ticket = state.next_ticket();
            self.connection_entry(state, connection_id)?
                .pending
                .insert(ticket);
            state.pending.insert(
                ticket,
                Pending {
                    kind: PendingKind::Seat {
                        member_id,
                        rejoin_of,
                    },
                    connection_id,
                    actor_id,
                    room_id: room_id.clone(),
                    refused: None,
                    poisoned: Vec::new(),
                },
            );
            ticket
        };
        Ok(PendingSeat {
            ticket: PendingTicket::new(self, ticket),
            member_id,
            room_id,
        })
    }

    /// Phase two of a join: seat the member (module doc).
    ///
    /// Moves the actor's own seat in the room on this connection, and on an
    /// exclusive registry the actor's seat anywhere, to this one: each hears
    /// `room_seat_lost` with reason `moved`, its room `room_member_left` with
    /// reason `moved`. Then the room hears `room_member_joined`.
    ///
    /// # Errors
    ///
    /// [`RoomError::StateTooLarge`]; [`RoomError::Evicted`],
    /// [`RoomError::JoinSuperseded`], or [`RoomError::ConnectionClosed`] when
    /// the join was refused in flight or its socket closed;
    /// [`RoomError::SeatMoved`] for a rejoin of a moved seat;
    /// [`RoomError::Full`] when the room seats its cap (the lower of the
    /// registry's and `admit.max_members`) after the moves this join makes.
    pub fn admit_seat(
        &self,
        pending: PendingSeat,
        admit: RoomSeatAdmit,
    ) -> Result<RoomJoined, RoomError> {
        let ticket = pending.ticket.take(self).ok_or(RoomError::Evicted)?;
        let RoomSeatAdmit {
            scope,
            max_members,
            state: member_state,
        } = admit;
        let exclusive = self.options.exclusive;
        let out = Out(&self.connections);

        let mut guard = self.state.lock();
        let state = &mut *guard;
        // the join leaves flight whatever the answer
        let entry = state.take_pending(ticket);
        if member_state
            .as_ref()
            .is_some_and(|s| s.len() > self.options.max_state_bytes)
        {
            return Err(RoomError::StateTooLarge);
        }
        let entry = entry.ok_or(RoomError::Evicted)?;
        let PendingKind::Seat {
            member_id,
            rejoin_of,
        } = entry.kind
        else {
            return Err(RoomError::Evicted);
        };
        if let Some(refused) = entry.refused {
            return Err(refused);
        }
        let connection_id = entry.connection_id;
        let actor_id = entry.actor_id;
        let room_id = entry.room_id;
        let own_seat = match state.connections.get(&connection_id) {
            Some(conn) if !conn.signal.is_cancelled() => conn.seat(&room_id, actor_id),
            _ => return Err(RoomError::ConnectionClosed),
        };
        if scope.as_ref().is_some_and(|s| entry.poisoned.contains(s)) {
            return Err(RoomError::Evicted);
        }
        let now = Instant::now();
        if exclusive
            && let Some(rejoin_of) = rejoin_of
            && state.tombstones.rejoin_moved(actor_id, rejoin_of, now)
        {
            return Err(RoomError::SeatMoved);
        }

        // the seats this join moves: the actor's own on this connection in
        // the room, and on an exclusive registry the actor's, wherever it is
        let mut displaced: Vec<(RoomId, MemberId)> = Vec::new();
        if let Some(seat) = own_seat {
            displaced.push((room_id.clone(), seat));
        }
        if exclusive
            && let Some((room, seat)) = state.seat_of_actor.get(&actor_id)
            && !displaced.iter().any(|(_, m)| m == seat)
        {
            displaced.push((room.clone(), *seat));
        }

        let registry_cap = self.options.max_members_per_room.get();
        let cap = max_members.map_or(registry_cap, |max| max.min(registry_cap));
        let seated = state.rooms.get(&room_id).map_or(0, |room| room.seats.len());
        let freed = displaced
            .iter()
            .filter(|(room, _)| *room == room_id)
            .count();
        if seated.saturating_sub(freed) >= cap {
            return Err(RoomError::Full);
        }

        for (room, seat) in displaced {
            let removed = state.remove(out, &room, &[seat], &[], Departure::Moved { to: &room_id });
            if exclusive {
                for seat in removed {
                    state
                        .tombstones
                        .push(seat.actor_id, seat.member_id, now, TombstoneKind::Moved);
                }
            }
        }

        let room = state.rooms.entry(room_id.clone()).or_default();
        room.seats.push(Seat {
            member_id,
            connection_id,
            actor_id,
            scope,
            state: member_state.clone(),
        });
        let seq = room.next_seq();
        out.send(
            &room.recipients(Some(member_id)),
            ROOM_MEMBER_JOINED_METHOD,
            &MemberJoinedParams {
                room_id: &room_id,
                seq,
                member: RoomMember {
                    member_id,
                    actor_id,
                    state: member_state,
                },
            },
        );
        let members = room.members();
        if let Some(conn) = state.connections.get_mut(&connection_id) {
            conn.set_seat(room_id.clone(), actor_id, member_id);
        }
        if exclusive {
            state
                .seat_of_actor
                .insert(actor_id, (room_id.clone(), member_id));
            state.tombstones.settle(actor_id, rejoin_of, now);
        }
        Ok(RoomJoined {
            room_id,
            member_id,
            seq,
            members,
            topology: self.options.topology,
        })
    }

    /// End `actor_id`'s seat in the room on the connection (`room_member_left`
    /// with reason `left`), and refuse that actor's joins of the room still in
    /// flight on it ([`RoomError::JoinSuperseded`]). Another actor's seat on
    /// the same connection is untouched. Idempotent; `true` when it ended or
    /// refused anything.
    pub fn leave(&self, connection_id: ConnectionId, actor_id: Uuid, room_id: &RoomId) -> bool {
        let out = Out(&self.connections);
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let Some(conn) = state.connections.get(&connection_id) else {
            return false;
        };
        let seat = conn.seat(room_id, actor_id);
        let tickets: Vec<u64> = conn.pending.iter().copied().collect();
        let mut left = false;
        for ticket in tickets {
            if let Some(pending) = state.pending.get_mut(&ticket)
                && pending.room_id == *room_id
                && pending.actor_id == actor_id
                && matches!(pending.kind, PendingKind::Seat { .. })
                && pending.refused.is_none()
            {
                pending.refused = Some(RoomError::JoinSuperseded);
                left = true;
            }
        }
        if let Some(seat) = seat {
            state.remove(out, room_id, &[seat], &[], Departure::Left);
            left = true;
        }
        left
    }

    /// Relay `payload` from `actor_id`'s seat in the room on the connection to
    /// the member `to`, or with `None` to every other member
    /// (`room_message`). Watchers get no messages. Returns the message's
    /// `seq`.
    ///
    /// # Errors
    ///
    /// [`RoomError::PayloadTooLarge`], [`RoomError::NotJoined`], or
    /// [`RoomError::MemberNotFound`] when `to` names no member of the room —
    /// or names the sender's own seat: a seat never addresses itself.
    pub fn send(
        &self,
        connection_id: ConnectionId,
        actor_id: Uuid,
        room_id: &RoomId,
        to: Option<MemberId>,
        payload: &str,
    ) -> Result<u64, RoomError> {
        if payload.len() > self.options.max_payload_bytes {
            return Err(RoomError::PayloadTooLarge);
        }
        let out = Out(&self.connections);
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let from = state
            .connections
            .get(&connection_id)
            .and_then(|conn| conn.seat(room_id, actor_id))
            .ok_or(RoomError::NotJoined)?;
        let room = state.rooms.get_mut(room_id).ok_or(RoomError::NotJoined)?;
        let recipients = match to {
            Some(to) if to == from => return Err(RoomError::MemberNotFound),
            Some(to) => vec![
                room.seats
                    .iter()
                    .find(|seat| seat.member_id == to)
                    .ok_or(RoomError::MemberNotFound)?
                    .connection_id,
            ],
            None => room.member_connections(Some(from)),
        };
        let seq = room.next_seq();
        out.send(
            &recipients,
            ROOM_MESSAGE_METHOD,
            &MessageParams {
                room_id,
                seq,
                from,
                to,
                payload,
            },
        );
        Ok(seq)
    }

    /// Set `actor_id`'s member state in the room on the connection, telling
    /// the other members and the watchers (`room_member_state`). Returns its
    /// `seq`.
    ///
    /// # Errors
    ///
    /// [`RoomError::StateTooLarge`] or [`RoomError::NotJoined`].
    pub fn set_state(
        &self,
        connection_id: ConnectionId,
        actor_id: Uuid,
        room_id: &RoomId,
        member_state: String,
    ) -> Result<u64, RoomError> {
        if member_state.len() > self.options.max_state_bytes {
            return Err(RoomError::StateTooLarge);
        }
        let out = Out(&self.connections);
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let member_id = state
            .connections
            .get(&connection_id)
            .and_then(|conn| conn.seat(room_id, actor_id))
            .ok_or(RoomError::NotJoined)?;
        let room = state.rooms.get_mut(room_id).ok_or(RoomError::NotJoined)?;
        let index = room
            .seats
            .iter()
            .position(|seat| seat.member_id == member_id)
            .ok_or(RoomError::NotJoined)?;
        let recipients = room.recipients(Some(member_id));
        let seq = room.next_seq();
        let seat_state: &str = room.seats[index].state.insert(member_state);
        out.send(
            &recipients,
            ROOM_MEMBER_STATE_METHOD,
            &MemberStateParams {
                room_id,
                seq,
                member_id,
                state: seat_state,
            },
        );
        Ok(seq)
    }

    /// Phase one of a watch, as [`Self::reserve_seat`] is of a join.
    ///
    /// # Errors
    ///
    /// [`RoomError::ConnectionClosed`], or [`RoomError::WatchLimit`] when the
    /// connection watches its maximum of other rooms.
    pub fn reserve_watch(
        self: &Arc<Self>,
        connection_id: ConnectionId,
        actor_id: Uuid,
        room_id: RoomId,
    ) -> Result<PendingWatch, RoomError> {
        let ticket = {
            let mut guard = self.state.lock();
            let state = &mut *guard;
            let ticket = state.next_ticket();
            let max = self.options.max_watches_per_connection;
            let conn = self.connection_entry(state, connection_id)?;
            if !conn.watches.contains(&room_id) && conn.watches.len() >= max {
                return Err(RoomError::WatchLimit);
            }
            conn.pending.insert(ticket);
            state.pending.insert(
                ticket,
                Pending {
                    kind: PendingKind::Watch,
                    connection_id,
                    actor_id,
                    room_id: room_id.clone(),
                    refused: None,
                    poisoned: Vec::new(),
                },
            );
            ticket
        };
        Ok(PendingWatch {
            ticket: PendingTicket::new(self, ticket),
            room_id,
        })
    }

    /// Phase two of a watch: from now on the connection hears the room's
    /// member events. Watching a room already watched answers its occupancy
    /// again and takes the new scope.
    ///
    /// # Errors
    ///
    /// [`RoomError::Evicted`] or [`RoomError::ConnectionClosed`] when the
    /// watch was refused in flight or its socket closed;
    /// [`RoomError::WatchLimit`].
    pub fn admit_watch(
        &self,
        pending: PendingWatch,
        scope: Option<RoomScope>,
    ) -> Result<RoomOccupancy, RoomError> {
        let ticket = pending.ticket.take(self).ok_or(RoomError::Evicted)?;
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let entry = state.take_pending(ticket).ok_or(RoomError::Evicted)?;
        if !matches!(entry.kind, PendingKind::Watch) {
            return Err(RoomError::Evicted);
        }
        if let Some(refused) = entry.refused {
            return Err(refused);
        }
        if scope.as_ref().is_some_and(|s| entry.poisoned.contains(s)) {
            return Err(RoomError::Evicted);
        }
        let connection_id = entry.connection_id;
        let room_id = entry.room_id;
        let conn = match state.connections.get_mut(&connection_id) {
            Some(conn) if !conn.signal.is_cancelled() => conn,
            _ => return Err(RoomError::ConnectionClosed),
        };
        let watching = conn.watches.contains(&room_id);
        if !watching && conn.watches.len() >= self.options.max_watches_per_connection {
            return Err(RoomError::WatchLimit);
        }
        conn.watches.insert(room_id.clone());
        let room = state.rooms.entry(room_id.clone()).or_default();
        if let Some(watcher) = room
            .watchers
            .iter_mut()
            .find(|watcher| watcher.connection_id == connection_id)
        {
            watcher.actor_id = entry.actor_id;
            watcher.scope = scope;
        } else {
            room.watchers.push(Watcher {
                connection_id,
                actor_id: entry.actor_id,
                scope,
            });
        }
        Ok(RoomOccupancy {
            room_id,
            seq: room.seq,
            members: room.members(),
        })
    }

    /// Stop the connection's watch of the room. Idempotent; `true` when it
    /// was watching. A watch still in flight is untouched — a client stops
    /// one by cancelling its request.
    pub fn unwatch(&self, connection_id: ConnectionId, room_id: &RoomId) -> bool {
        let out = Out(&self.connections);
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let watching = state
            .connections
            .get(&connection_id)
            .is_some_and(|conn| conn.watches.contains(room_id));
        if watching {
            state.remove(out, room_id, &[], &[connection_id], Departure::Left);
        }
        watching
    }

    /// Remove the seats and watches `target` names, and refuse its joins and
    /// watches in flight (module doc, "Eviction"). Each removed seat hears
    /// `room_seat_lost`, its room `room_member_left`, each removed watch
    /// `room_watch_ended`, all with `reason`.
    ///
    /// A join in flight has no scope until its verdict, so a scope target
    /// marks it instead, and its admit refuses when its verdict's scope is
    /// that one; a join marked by more scopes than a small bound is refused
    /// outright.
    pub fn evict(&self, target: &RoomEvictTarget, reason: RoomEvictReason) -> RoomEvicted {
        let out = Out(&self.connections);
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let mut evicted = RoomEvicted::default();

        for pending in state.pending.values_mut() {
            if pending.refused.is_some() {
                continue;
            }
            match target {
                RoomEvictTarget::Actor(actor_id) if pending.actor_id == *actor_id => {
                    pending.refused = Some(RoomError::Evicted);
                }
                RoomEvictTarget::Room(room_id) if pending.room_id == *room_id => {
                    pending.refused = Some(RoomError::Evicted);
                }
                RoomEvictTarget::ActorInScope { actor_id, scope }
                    if pending.actor_id == *actor_id =>
                {
                    pending.poison(scope);
                }
                RoomEvictTarget::Scope(scope) => pending.poison(scope),
                _ => continue,
            }
            evicted.pending += 1;
        }

        let rooms: Vec<RoomId> = match target {
            RoomEvictTarget::Room(room_id) => vec![room_id.clone()],
            _ => state.rooms.keys().cloned().collect(),
        };
        for room_id in rooms {
            let Some(room) = state.rooms.get(&room_id) else {
                continue;
            };
            let seats: Vec<MemberId> = room
                .seats
                .iter()
                .filter(|seat| target_matches(target, seat.actor_id, seat.scope.as_ref(), &room_id))
                .map(|seat| seat.member_id)
                .collect();
            let watchers: Vec<ConnectionId> = room
                .watchers
                .iter()
                .filter(|watcher| {
                    target_matches(target, watcher.actor_id, watcher.scope.as_ref(), &room_id)
                })
                .map(|watcher| watcher.connection_id)
                .collect();
            if seats.is_empty() && watchers.is_empty() {
                continue;
            }
            evicted.seats += seats.len();
            evicted.watches += watchers.len();
            state.remove(out, &room_id, &seats, &watchers, Departure::Evicted(reason));
        }
        evicted
    }

    /// The room's members as of its current `seq`, or `None` when no room
    /// by that id exists (no seats and no watches).
    #[must_use]
    pub fn occupancy(&self, room_id: &RoomId) -> Option<RoomOccupancy> {
        let state = self.state.lock();
        state.rooms.get(room_id).map(|room| RoomOccupancy {
            room_id: room_id.clone(),
            seq: room.seq,
            members: room.members(),
        })
    }

    /// Drop every room, seat, watch, and tombstone, telling no one, and
    /// refuse every join and watch in flight ([`RoomError::Evicted`]). For a
    /// test server's reset between cases; the connections' disconnect
    /// waiters stay armed.
    pub fn clear(&self) {
        let mut guard = self.state.lock();
        let state = &mut *guard;
        state.rooms.clear();
        state.seat_of_actor.clear();
        state.tombstones.clear();
        for pending in state.pending.values_mut() {
            if pending.refused.is_none() {
                pending.refused = Some(RoomError::Evicted);
            }
        }
        for conn in state.connections.values_mut() {
            conn.seats.clear();
            conn.watches.clear();
        }
    }

    /// The connection's entry, created — with its disconnect waiter armed —
    /// on its first reserve.
    fn connection_entry<'s>(
        self: &Arc<Self>,
        state: &'s mut State,
        connection_id: ConnectionId,
    ) -> Result<&'s mut ConnectionRooms, RoomError> {
        match state.connections.entry(connection_id) {
            Entry::Occupied(entry) => {
                let conn = entry.into_mut();
                if conn.signal.is_cancelled() {
                    Err(RoomError::ConnectionClosed)
                } else {
                    Ok(conn)
                }
            }
            Entry::Vacant(entry) => {
                let signal = self
                    .connections
                    .socket_signal(connection_id)
                    .filter(|signal| !signal.is_cancelled())
                    .ok_or(RoomError::ConnectionClosed)?;
                self.arm_waiter(connection_id, signal.clone());
                Ok(entry.insert(ConnectionRooms {
                    signal,
                    seats: HashMap::new(),
                    watches: HashSet::new(),
                    pending: HashSet::new(),
                }))
            }
        }
    }

    /// Spawn the connection's one disconnect waiter (module doc,
    /// "Disconnect"). It holds the registry weakly, so it never keeps a
    /// dropped registry alive.
    fn arm_waiter(self: &Arc<Self>, connection_id: ConnectionId, signal: CancellationToken) {
        let registry: Weak<Self> = Arc::downgrade(self);
        let live = LiveWaiter::new(&self.live_waiters);
        tokio::spawn(async move {
            let _live = live;
            signal.cancelled().await;
            if let Some(registry) = registry.upgrade() {
                registry.release_connection(connection_id);
            }
        });
    }

    /// Release everything a closed connection holds: its seats
    /// (`room_member_left` with reason `disconnected`), watches, and joins
    /// and watches in flight.
    fn release_connection(&self, connection_id: ConnectionId) {
        let out = Out(&self.connections);
        let mut guard = self.state.lock();
        let state = &mut *guard;
        let Some(conn) = state.connections.remove(&connection_id) else {
            return;
        };
        for ticket in &conn.pending {
            if let Some(pending) = state.pending.get_mut(ticket)
                && pending.refused.is_none()
            {
                pending.refused = Some(RoomError::ConnectionClosed);
            }
        }
        for room_id in &conn.watches {
            state.remove(out, room_id, &[], &[connection_id], Departure::Disconnected);
        }
        let now = Instant::now();
        for (room_id, seat) in conn.all_seats() {
            let removed = state.remove(out, room_id, &[seat], &[], Departure::Disconnected);
            if self.options.exclusive {
                for seat in removed {
                    state.tombstones.push(
                        seat.actor_id,
                        seat.member_id,
                        now,
                        TombstoneKind::Disconnected,
                    );
                }
            }
        }
    }

    /// Remove a join or watch in flight that its owner let go of.
    fn forget_pending(&self, ticket: u64) {
        self.state.lock().take_pending(ticket);
    }

    /// Disconnect waiters alive.
    #[cfg(test)]
    fn live_waiters(&self) -> usize {
        self.live_waiters.load(Ordering::SeqCst)
    }
}

/// A join in flight, between [`RoomRegistry::reserve_seat`] and
/// [`RoomRegistry::admit_seat`]. Dropping it — any refusal, a cancelled
/// request, a socket closed mid-authorizer — removes it.
#[must_use = "admit it with `RoomRegistry::admit_seat`; dropping it withdraws the join"]
pub struct PendingSeat {
    ticket: PendingTicket,
    member_id: MemberId,
    room_id: RoomId,
}

impl PendingSeat {
    /// The member id the seat will have once admitted.
    #[must_use]
    pub const fn member_id(&self) -> MemberId {
        self.member_id
    }

    /// The room the join is for.
    #[must_use]
    pub const fn room_id(&self) -> &RoomId {
        &self.room_id
    }
}

impl std::fmt::Debug for PendingSeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingSeat")
            .field("member_id", &self.member_id)
            .field("room_id", &self.room_id)
            .finish_non_exhaustive()
    }
}

/// A watch in flight, between [`RoomRegistry::reserve_watch`] and
/// [`RoomRegistry::admit_watch`]. Dropping it removes it.
#[must_use = "admit it with `RoomRegistry::admit_watch`; dropping it withdraws the watch"]
pub struct PendingWatch {
    ticket: PendingTicket,
    room_id: RoomId,
}

impl PendingWatch {
    /// The room the watch is for.
    #[must_use]
    pub const fn room_id(&self) -> &RoomId {
        &self.room_id
    }
}

impl std::fmt::Debug for PendingWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingWatch")
            .field("room_id", &self.room_id)
            .finish_non_exhaustive()
    }
}

/// The ticket of a join or watch in flight, held for its admit: dropped
/// unadmitted, it removes its entry from the registry that issued it.
struct PendingTicket {
    registry: Arc<RoomRegistry>,
    ticket: u64,
    armed: bool,
}

impl PendingTicket {
    fn new(registry: &Arc<RoomRegistry>, ticket: u64) -> Self {
        Self {
            registry: Arc::clone(registry),
            ticket,
            armed: true,
        }
    }

    /// Hand the ticket to `registry`'s admit, which removes the entry
    /// itself — or `None` when another registry issued it, which then
    /// removes its own entry on the drop.
    fn take(mut self, registry: &RoomRegistry) -> Option<u64> {
        if !std::ptr::eq(Arc::as_ptr(&self.registry), registry) {
            return None;
        }
        self.armed = false;
        Some(self.ticket)
    }
}

impl Drop for PendingTicket {
    fn drop(&mut self) {
        if self.armed {
            self.registry.forget_pending(self.ticket);
        }
    }
}

/// Whether an eviction `target` names a seat or watch of `actor_id`, admitted
/// under `scope`, in `room_id`.
fn target_matches(
    target: &RoomEvictTarget,
    actor_id: Uuid,
    scope: Option<&RoomScope>,
    room_id: &RoomId,
) -> bool {
    match target {
        RoomEvictTarget::Actor(target_actor) => actor_id == *target_actor,
        RoomEvictTarget::ActorInScope {
            actor_id: target_actor,
            scope: target_scope,
        } => actor_id == *target_actor && scope == Some(target_scope),
        RoomEvictTarget::Room(target_room) => room_id == target_room,
        RoomEvictTarget::Scope(target_scope) => scope == Some(target_scope),
    }
}

/// Counts one disconnect waiter while it lives.
struct LiveWaiter(Arc<AtomicUsize>);

impl LiveWaiter {
    fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(count))
    }
}

impl Drop for LiveWaiter {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The fan-out: queue one notification for each connection, never waiting.
#[derive(Clone, Copy)]
struct Out<'a>(&'a ConnectionRegistry);

impl Out<'_> {
    fn send<T: Serialize>(self, ids: &[ConnectionId], method: &str, params: &T) {
        if ids.is_empty() {
            return;
        }
        let frame = fuz_http::notification(method, params);
        if !frame.is_empty() {
            self.0.send_to_each(ids, frame);
        }
    }
}

// -- notification params ------------------------------------------------------

#[derive(Serialize)]
struct MemberJoinedParams<'a> {
    room_id: &'a RoomId,
    seq: u64,
    member: RoomMember,
}

#[derive(Serialize)]
struct MemberLeftParams<'a> {
    room_id: &'a RoomId,
    seq: u64,
    member_id: MemberId,
    reason: RoomLeftReason,
}

#[derive(Serialize)]
struct MemberStateParams<'a> {
    room_id: &'a RoomId,
    seq: u64,
    member_id: MemberId,
    state: &'a str,
}

#[derive(Serialize)]
struct MessageParams<'a> {
    room_id: &'a RoomId,
    seq: u64,
    from: MemberId,
    to: Option<MemberId>,
    payload: &'a str,
}

#[derive(Serialize)]
struct SeatLostParams<'a> {
    room_id: &'a RoomId,
    member_id: MemberId,
    reason: RoomSeatLostReason,
    moved_to: Option<&'a RoomId>,
}

#[derive(Serialize)]
struct WatchEndedParams<'a> {
    room_id: &'a RoomId,
    reason: RoomEvictReason,
}

// -- state --------------------------------------------------------------------

#[derive(Debug, Default)]
struct State {
    rooms: HashMap<RoomId, Room>,
    connections: HashMap<ConnectionId, ConnectionRooms>,
    /// Joins and watches in flight, by ticket.
    pending: HashMap<u64, Pending>,
    last_ticket: u64,
    /// Each actor's one seat, on an exclusive registry.
    seat_of_actor: HashMap<Uuid, (RoomId, MemberId)>,
    /// Seats ended without a leave, on an exclusive registry.
    tombstones: Tombstones,
}

#[derive(Debug, Default)]
struct Room {
    seq: u64,
    /// In seating order.
    seats: Vec<Seat>,
    /// One per connection.
    watchers: Vec<Watcher>,
}

#[derive(Debug)]
struct Seat {
    member_id: MemberId,
    connection_id: ConnectionId,
    actor_id: Uuid,
    scope: Option<RoomScope>,
    state: Option<String>,
}

#[derive(Debug)]
struct Watcher {
    connection_id: ConnectionId,
    actor_id: Uuid,
    scope: Option<RoomScope>,
}

/// What one connection holds.
#[derive(Debug)]
struct ConnectionRooms {
    /// The socket token its waiter waits on.
    signal: CancellationToken,
    /// Each room's seats on this connection, by actor — one unless requests
    /// act as several actors of the account.
    seats: HashMap<RoomId, HashMap<Uuid, MemberId>>,
    watches: HashSet<RoomId>,
    pending: HashSet<u64>,
}

impl ConnectionRooms {
    /// `actor_id`'s seat in the room on this connection.
    fn seat(&self, room_id: &RoomId, actor_id: Uuid) -> Option<MemberId> {
        self.seats.get(room_id)?.get(&actor_id).copied()
    }

    fn set_seat(&mut self, room_id: RoomId, actor_id: Uuid, member_id: MemberId) {
        self.seats
            .entry(room_id)
            .or_default()
            .insert(actor_id, member_id);
    }

    /// Forget `actor_id`'s seat in the room, if it is still `member_id`.
    fn clear_seat(&mut self, room_id: &RoomId, actor_id: Uuid, member_id: MemberId) {
        let Some(by_actor) = self.seats.get_mut(room_id) else {
            return;
        };
        if by_actor.get(&actor_id) == Some(&member_id) {
            by_actor.remove(&actor_id);
        }
        if by_actor.is_empty() {
            self.seats.remove(room_id);
        }
    }

    /// Every seat on this connection, with its room.
    fn all_seats(&self) -> impl Iterator<Item = (&RoomId, MemberId)> {
        self.seats
            .iter()
            .flat_map(|(room_id, by_actor)| by_actor.values().map(move |seat| (room_id, *seat)))
    }
}

#[derive(Debug)]
struct Pending {
    kind: PendingKind,
    connection_id: ConnectionId,
    actor_id: Uuid,
    room_id: RoomId,
    /// Why it will be refused at admission, once something refused it.
    refused: Option<RoomError>,
    /// Scopes evicted while it was in flight.
    poisoned: Vec<RoomScope>,
}

impl Pending {
    fn poison(&mut self, scope: &RoomScope) {
        if self.poisoned.contains(scope) {
            return;
        }
        if self.poisoned.len() >= MAX_POISONED_SCOPES {
            self.refused = Some(RoomError::Evicted);
        } else {
            self.poisoned.push(scope.clone());
        }
    }
}

#[derive(Debug)]
enum PendingKind {
    Seat {
        member_id: MemberId,
        rejoin_of: Option<MemberId>,
    },
    Watch,
}

/// Why seats and watches leave a room: what [`State::remove`] tells the
/// room, each removed seat, and each removed watcher. The room hears each
/// removed seat as `room_member_left`; a removed watch is told only on an
/// eviction.
#[derive(Debug, Clone, Copy)]
enum Departure<'a> {
    /// The member left, or the connection stopped watching: only the room
    /// hears, of a seat.
    Left,
    /// The socket closed: only the room hears, of a seat.
    Disconnected,
    /// A newer seat took over, in room `to`: the moved seat hears where.
    Moved { to: &'a RoomId },
    /// The consumer evicted: seats and watchers hear why.
    Evicted(RoomEvictReason),
}

impl<'a> Departure<'a> {
    /// The reason `room_member_left` gives the room.
    fn left(self) -> RoomLeftReason {
        match self {
            Self::Left => RoomLeftReason::Left,
            Self::Disconnected => RoomLeftReason::Disconnected,
            Self::Moved { .. } => RoomLeftReason::Moved,
            Self::Evicted(reason) => reason.into(),
        }
    }

    /// What `room_seat_lost` tells a removed seat's connection, if it hears.
    fn seat_lost(self) -> Option<(RoomSeatLostReason, Option<&'a RoomId>)> {
        match self {
            Self::Left | Self::Disconnected => None,
            Self::Moved { to } => Some((RoomSeatLostReason::Moved, Some(to))),
            Self::Evicted(reason) => Some((reason.into(), None)),
        }
    }

    /// What `room_watch_ended` tells a removed watcher, if it hears.
    const fn watch_ended(self) -> Option<RoomEvictReason> {
        match self {
            Self::Evicted(reason) => Some(reason),
            Self::Left | Self::Disconnected | Self::Moved { .. } => None,
        }
    }
}

impl Room {
    const fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    const fn is_empty(&self) -> bool {
        self.seats.is_empty() && self.watchers.is_empty()
    }

    fn members(&self) -> Vec<RoomMember> {
        self.seats
            .iter()
            .map(|seat| RoomMember {
                member_id: seat.member_id,
                actor_id: seat.actor_id,
                state: seat.state.clone(),
            })
            .collect()
    }

    /// The connections a member event goes to: every member's but the seat
    /// `except`'s, and every watcher's.
    fn recipients(&self, except: Option<MemberId>) -> Vec<ConnectionId> {
        let mut ids = self.member_connections(except);
        ids.extend(self.watchers.iter().map(|watcher| watcher.connection_id));
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// The connection of every seat but `except`. A connection holding
    /// another seat beside `except`'s (another actor of the account) is
    /// included.
    fn member_connections(&self, except: Option<MemberId>) -> Vec<ConnectionId> {
        let mut ids: Vec<ConnectionId> = self
            .seats
            .iter()
            .filter(|seat| Some(seat.member_id) != except)
            .map(|seat| seat.connection_id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

impl State {
    const fn next_ticket(&mut self) -> u64 {
        self.last_ticket += 1;
        self.last_ticket
    }

    fn take_pending(&mut self, ticket: u64) -> Option<Pending> {
        let pending = self.pending.remove(&ticket)?;
        if let Some(conn) = self.connections.get_mut(&pending.connection_id) {
            conn.pending.remove(&ticket);
        }
        Some(pending)
    }

    /// Remove `seats` and `watchers` from one room, then tell everyone what
    /// `why` says (see [`Departure`]); delete the room if it is left empty.
    /// Returns the removed seats.
    fn remove(
        &mut self,
        out: Out<'_>,
        room_id: &RoomId,
        seats: &[MemberId],
        watchers: &[ConnectionId],
        why: Departure<'_>,
    ) -> Vec<Seat> {
        let left = why.left();
        let seat_lost = why.seat_lost();
        let watch_ended = why.watch_ended();
        let Some(room) = self.rooms.get_mut(room_id) else {
            return Vec::new();
        };
        let (removed_seats, kept): (Vec<Seat>, Vec<Seat>) = std::mem::take(&mut room.seats)
            .into_iter()
            .partition(|seat| seats.contains(&seat.member_id));
        room.seats = kept;
        let (removed_watchers, kept): (Vec<Watcher>, Vec<Watcher>) =
            std::mem::take(&mut room.watchers)
                .into_iter()
                .partition(|watcher| watchers.contains(&watcher.connection_id));
        room.watchers = kept;

        // the room's remaining members and watchers hear each departure
        let recipients = room.recipients(None);
        for seat in &removed_seats {
            let seq = room.next_seq();
            out.send(
                &recipients,
                ROOM_MEMBER_LEFT_METHOD,
                &MemberLeftParams {
                    room_id,
                    seq,
                    member_id: seat.member_id,
                    reason: left,
                },
            );
            if let Some((reason, moved_to)) = seat_lost {
                out.send(
                    &[seat.connection_id],
                    ROOM_SEAT_LOST_METHOD,
                    &SeatLostParams {
                        room_id,
                        member_id: seat.member_id,
                        reason,
                        moved_to,
                    },
                );
            }
        }
        if let Some(reason) = watch_ended {
            for watcher in &removed_watchers {
                out.send(
                    &[watcher.connection_id],
                    ROOM_WATCH_ENDED_METHOD,
                    &WatchEndedParams { room_id, reason },
                );
            }
        }
        if room.is_empty() {
            self.rooms.remove(room_id);
        }

        for seat in &removed_seats {
            if let Some(conn) = self.connections.get_mut(&seat.connection_id) {
                conn.clear_seat(room_id, seat.actor_id, seat.member_id);
            }
            if self
                .seat_of_actor
                .get(&seat.actor_id)
                .is_some_and(|(room, member)| room == room_id && *member == seat.member_id)
            {
                self.seat_of_actor.remove(&seat.actor_id);
            }
        }
        for watcher in &removed_watchers {
            if let Some(conn) = self.connections.get_mut(&watcher.connection_id) {
                conn.watches.remove(room_id);
            }
        }
        removed_seats
    }
}

// -- tombstones ---------------------------------------------------------------

/// Seats that ended without a leave, per actor, for the rejoin guard
/// (module doc, "Exclusivity and the rejoin guard").
#[derive(Debug, Default)]
struct Tombstones {
    by_actor: HashMap<Uuid, VecDeque<Tombstone>>,
    /// The actor count past which the map sweeps.
    sweep_at: usize,
}

#[derive(Debug)]
struct Tombstone {
    member_id: MemberId,
    at: Instant,
    kind: TombstoneKind,
}

/// How a remembered seat ended, as the rejoin guard reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TombstoneKind {
    /// Moved away, or released by a disconnect and the actor seated since:
    /// a rejoin of it is refused.
    Moved,
    /// Released by its disconnect, the actor not seated since: a rejoin of
    /// it is seated.
    Disconnected,
}

impl Tombstones {
    /// Whether `actor_id`'s seat `member_id` has moved since it ended.
    fn rejoin_moved(&mut self, actor_id: Uuid, member_id: MemberId, now: Instant) -> bool {
        self.live(actor_id, now).is_some_and(|tombstones| {
            tombstones.iter().any(|tombstone| {
                tombstone.member_id == member_id && tombstone.kind == TombstoneKind::Moved
            })
        })
    }

    /// Remember a seat of `actor_id` that ended without a leave.
    fn push(&mut self, actor_id: Uuid, member_id: MemberId, now: Instant, kind: TombstoneKind) {
        let tombstones = self.by_actor.entry(actor_id).or_default();
        tombstones.retain(|tombstone| !tombstone.expired(now));
        tombstones.push_back(Tombstone {
            member_id,
            at: now,
            kind,
        });
        while tombstones.len() > ROOM_REJOIN_TOMBSTONES_PER_ACTOR {
            tombstones.pop_front();
        }
        if self.by_actor.len() > self.sweep_at.max(TOMBSTONE_SWEEP_FLOOR) {
            self.by_actor.retain(|_, tombstones| {
                tombstones.retain(|tombstone| !tombstone.expired(now));
                !tombstones.is_empty()
            });
            self.sweep_at = self.by_actor.len() * 2;
        }
    }

    /// `actor_id` was just seated (by a rejoin of `rejoin_of`, or fresh):
    /// the rejoined seat's tombstone is spent, and every other seat it lost
    /// to a disconnect now counts as moved.
    fn settle(&mut self, actor_id: Uuid, rejoin_of: Option<MemberId>, now: Instant) {
        let Some(tombstones) = self.live(actor_id, now) else {
            return;
        };
        tombstones.retain(|tombstone| Some(tombstone.member_id) != rejoin_of);
        for tombstone in tombstones.iter_mut() {
            tombstone.kind = TombstoneKind::Moved;
        }
        if tombstones.is_empty() {
            self.by_actor.remove(&actor_id);
        }
    }

    /// Forget every tombstone.
    fn clear(&mut self) {
        self.by_actor.clear();
    }

    /// `actor_id`'s unexpired tombstones, pruning the expired ones.
    fn live(&mut self, actor_id: Uuid, now: Instant) -> Option<&mut VecDeque<Tombstone>> {
        let tombstones = self.by_actor.get_mut(&actor_id)?;
        tombstones.retain(|tombstone| !tombstone.expired(now));
        Some(tombstones)
    }
}

impl Tombstone {
    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.at) >= ROOM_REJOIN_TOMBSTONE_TTL
    }
}
