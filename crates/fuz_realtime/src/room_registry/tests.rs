//! Unit tests of the room registry, over a real connection registry with
//! in-memory connections.

use std::num::NonZeroUsize;
use std::sync::Arc;

use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    MemberId, ROOM_REJOIN_TOMBSTONE_TTL, ROOM_REJOIN_TOMBSTONES_PER_ACTOR, RoomError,
    RoomEvictReason, RoomEvictTarget, RoomEvicted, RoomId, RoomIdError, RoomJoined, RoomRegistry,
    RoomRegistryOptions, RoomScope, RoomSeatAdmit, RoomSeatRequest,
};
use crate::{
    ConnectionId, ConnectionIdentity, ConnectionReceiver, ConnectionRegistry, connection_channel,
};

const BUDGET: usize = 1 << 20;

struct Harness {
    connections: Arc<ConnectionRegistry>,
    rooms: Arc<RoomRegistry>,
}

struct Client {
    id: ConnectionId,
    actor: Uuid,
    rx: ConnectionReceiver,
    signal: CancellationToken,
}

impl Harness {
    fn new(options: RoomRegistryOptions) -> Self {
        let connections = Arc::new(ConnectionRegistry::new());
        let rooms = Arc::new(RoomRegistry::new(Arc::clone(&connections), options));
        Self { connections, rooms }
    }

    fn exclusive() -> Self {
        Self::new(RoomRegistryOptions {
            exclusive: true,
            ..RoomRegistryOptions::default()
        })
    }

    /// A connection for a new actor.
    fn connect(&self) -> Client {
        self.connect_as(Uuid::new_v4())
    }

    /// A connection for `actor`.
    fn connect_as(&self, actor: Uuid) -> Client {
        self.connect_with_budget(actor, BUDGET)
    }

    fn connect_with_budget(&self, actor: Uuid, budget: usize) -> Client {
        let (sender, rx) = connection_channel(budget);
        let signal = CancellationToken::new();
        let conn =
            self.connections
                .add_connection(sender, ConnectionIdentity::default(), signal.clone());
        Client {
            id: conn.id,
            actor,
            rx,
            signal,
        }
    }

    fn reserve(&self, client: &Client, room: &RoomId) -> Result<super::PendingSeat, RoomError> {
        self.reserve_rejoin(client, room, None)
    }

    fn reserve_rejoin(
        &self,
        client: &Client,
        room: &RoomId,
        rejoin_of: Option<MemberId>,
    ) -> Result<super::PendingSeat, RoomError> {
        self.rooms.reserve_seat(RoomSeatRequest {
            connection_id: client.id,
            actor_id: client.actor,
            room_id: room.clone(),
            rejoin_of,
        })
    }

    fn join(&self, client: &Client, room: &RoomId) -> Result<RoomJoined, RoomError> {
        self.join_with(client, room, None, RoomSeatAdmit::default())
    }

    fn join_with(
        &self,
        client: &Client,
        room: &RoomId,
        rejoin_of: Option<MemberId>,
        admit: RoomSeatAdmit,
    ) -> Result<RoomJoined, RoomError> {
        let pending = self.reserve_rejoin(client, room, rejoin_of)?;
        self.rooms.admit_seat(pending, admit)
    }

    fn watch(&self, client: &Client, room: &RoomId) -> Result<super::RoomOccupancy, RoomError> {
        let pending = self
            .rooms
            .reserve_watch(client.id, client.actor, room.clone())?;
        self.rooms.admit_watch(pending, None)
    }

    /// Close `client`'s socket the way its loop does, and wait for its
    /// disconnect waiter to release it.
    async fn disconnect(&self, client: &Client) {
        client.signal.cancel();
        self.connections.remove_connection(client.id);
        let rooms = Arc::clone(&self.rooms);
        let id = client.id;
        until(move || !rooms.state.lock().connections.contains_key(&id)).await;
    }

    fn room_exists(&self, room: &RoomId) -> bool {
        self.rooms.state.lock().rooms.contains_key(room)
    }
}

/// Yield until `done` holds — the spawned waiters run on the test runtime.
async fn until(mut done: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if done() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the condition never held");
}

fn room(id: &str) -> RoomId {
    RoomId::parse(id).unwrap()
}

/// Every frame queued for `client`, parsed.
fn frames(client: &mut Client) -> Vec<Value> {
    let mut out = Vec::new();
    while let Ok(frame) = client.rx.try_recv() {
        out.push(serde_json::from_str(frame.as_str()).unwrap());
    }
    out
}

/// The methods of every frame queued for `client`.
fn methods(client: &mut Client) -> Vec<String> {
    frames(client)
        .iter()
        .map(|f| f["method"].as_str().unwrap().to_owned())
        .collect()
}

fn member_ids(joined: &RoomJoined) -> Vec<MemberId> {
    joined.members.iter().map(|m| m.member_id).collect()
}

#[test]
fn room_ids_are_bounded_printable_ascii() {
    assert_eq!(RoomId::parse("space:1").unwrap().as_str(), "space:1");
    assert_eq!(RoomId::parse(&"x".repeat(128)).unwrap().as_str().len(), 128);
    assert_eq!(RoomId::parse(""), Err(RoomIdError::Length));
    assert_eq!(RoomId::parse(&"x".repeat(129)), Err(RoomIdError::Length));
    for bad in ["a b", "a\tb", "caf\u{e9}", "a\u{0}b", "\u{7f}"] {
        assert_eq!(RoomId::parse(bad), Err(RoomIdError::Character), "{bad:?}");
    }
}

#[tokio::test]
async fn a_join_answers_the_room_and_tells_the_others() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let mut a = h.connect();
    let mut b = h.connect();

    let joined_a = h
        .join_with(
            &a,
            &line,
            None,
            RoomSeatAdmit {
                state: Some("{\"mic\":false}".to_owned()),
                ..RoomSeatAdmit::default()
            },
        )
        .unwrap();
    assert_eq!(joined_a.seq, 1);
    assert_eq!(member_ids(&joined_a), [joined_a.member_id]);
    assert_eq!(joined_a.members[0].actor_id, a.actor);
    assert_eq!(
        joined_a.members[0].state.as_deref(),
        Some("{\"mic\":false}")
    );
    assert!(
        frames(&mut a).is_empty(),
        "the joiner hears only its answer"
    );

    let joined_b = h.join(&b, &line).unwrap();
    assert_eq!(joined_b.seq, 2);
    assert_eq!(
        member_ids(&joined_b),
        [joined_a.member_id, joined_b.member_id]
    );
    assert!(frames(&mut b).is_empty());
    let heard = frames(&mut a);
    assert_eq!(heard.len(), 1);
    assert_eq!(
        heard[0],
        json!({
            "jsonrpc": "2.0",
            "method": "room_member_joined",
            "params": {
                "room_id": "line",
                "seq": 2,
                "member": {"member_id": joined_b.member_id, "actor_id": b.actor, "state": null},
            },
        })
    );
    // the snapshot serializes as the wire answer
    assert_eq!(
        serde_json::to_value(&joined_b).unwrap()["topology"],
        json!("mesh")
    );
}

#[tokio::test]
async fn a_leave_tells_the_others_and_an_empty_room_is_deleted() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let mut a = h.connect();
    let b = h.connect();
    h.join(&a, &line).unwrap();
    let joined_b = h.join(&b, &line).unwrap();
    frames(&mut a);

    assert!(h.rooms.leave(b.id, b.actor, &line));
    assert!(!h.rooms.leave(b.id, b.actor, &line), "idempotent");
    let heard = frames(&mut a);
    assert_eq!(
        heard[0]["params"],
        json!({"room_id": "line", "seq": 3, "member_id": joined_b.member_id, "reason": "left"})
    );

    assert!(h.rooms.leave(a.id, a.actor, &line));
    assert!(!h.room_exists(&line), "the empty room is deleted");
    assert!(h.rooms.occupancy(&line).is_none());
    // a new room by the same id starts again
    assert_eq!(h.join(&a, &line).unwrap().seq, 1);
}

#[tokio::test]
async fn a_send_reaches_its_addressee_or_the_room_minus_the_sender() {
    let h = Harness::new(RoomRegistryOptions {
        max_payload_bytes: 8,
        ..RoomRegistryOptions::default()
    });
    let line = room("line");
    let mut a = h.connect();
    let mut b = h.connect();
    let mut c = h.connect();
    let mut watcher = h.connect();
    let joined_a = h.join(&a, &line).unwrap();
    let joined_b = h.join(&b, &line).unwrap();
    h.join(&c, &line).unwrap();
    h.watch(&watcher, &line).unwrap();
    for client in [&mut a, &mut b, &mut c, &mut watcher] {
        frames(client);
    }

    let seq = h
        .rooms
        .send(a.id, a.actor, &line, Some(joined_b.member_id), "offer")
        .unwrap();
    let heard = frames(&mut b);
    assert_eq!(
        heard[0]["params"],
        json!({"room_id": "line", "seq": seq, "from": joined_a.member_id, "to": joined_b.member_id, "payload": "offer"})
    );
    assert!(frames(&mut a).is_empty());
    assert!(frames(&mut c).is_empty());

    h.rooms.send(a.id, a.actor, &line, None, "hi").unwrap();
    assert_eq!(methods(&mut b), ["room_message"]);
    assert_eq!(methods(&mut c), ["room_message"]);
    assert!(frames(&mut a).is_empty(), "not to the sender");
    assert!(frames(&mut watcher).is_empty(), "watchers get no messages");

    assert_eq!(
        h.rooms.send(watcher.id, watcher.actor, &line, None, "x"),
        Err(RoomError::NotJoined)
    );
    assert_eq!(
        h.rooms
            .send(a.id, a.actor, &line, Some(MemberId::random()), "x"),
        Err(RoomError::MemberNotFound)
    );
    // a seat never addresses itself
    assert_eq!(
        h.rooms
            .send(a.id, a.actor, &line, Some(joined_a.member_id), "x"),
        Err(RoomError::MemberNotFound)
    );
    assert!(frames(&mut a).is_empty());
    // the cap is UTF-8 bytes: four two-byte characters fit, five don't
    h.rooms
        .send(a.id, a.actor, &line, None, "\u{e9}\u{e9}\u{e9}\u{e9}")
        .unwrap();
    assert_eq!(
        h.rooms
            .send(a.id, a.actor, &line, None, "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}"),
        Err(RoomError::PayloadTooLarge)
    );
}

#[tokio::test]
async fn state_reaches_the_others_and_the_watchers_and_is_bounded() {
    let h = Harness::new(RoomRegistryOptions {
        max_state_bytes: 4,
        ..RoomRegistryOptions::default()
    });
    let line = room("line");
    let mut a = h.connect();
    let mut b = h.connect();
    let mut watcher = h.connect();
    let joined_a = h.join(&a, &line).unwrap();
    h.join(&b, &line).unwrap();
    h.watch(&watcher, &line).unwrap();
    frames(&mut a);
    frames(&mut watcher);

    let seq = h
        .rooms
        .set_state(a.id, a.actor, &line, "on".to_owned())
        .unwrap();
    assert_eq!(seq, 3);
    assert!(frames(&mut a).is_empty(), "the setter has its answer");
    for client in [&mut b, &mut watcher] {
        let heard = frames(client);
        assert_eq!(
            heard[0]["params"],
            json!({"room_id": "line", "seq": 3, "member_id": joined_a.member_id, "state": "on"})
        );
    }
    assert_eq!(
        h.rooms.occupancy(&line).unwrap().members[0]
            .state
            .as_deref(),
        Some("on")
    );
    assert_eq!(
        h.rooms.set_state(a.id, a.actor, &line, "12345".to_owned()),
        Err(RoomError::StateTooLarge)
    );
    assert_eq!(
        h.rooms
            .set_state(watcher.id, watcher.actor, &line, "x".to_owned()),
        Err(RoomError::NotJoined)
    );
    let pending = h.reserve(&watcher, &line).unwrap();
    assert_eq!(
        h.rooms.admit_seat(
            pending,
            RoomSeatAdmit {
                state: Some("12345".to_owned()),
                ..RoomSeatAdmit::default()
            }
        ),
        Err(RoomError::StateTooLarge)
    );
}

/// Every event in a room takes the next `seq`, whatever its kind, so a
/// watcher sees one strictly increasing sequence.
#[tokio::test]
async fn every_event_in_a_room_takes_the_next_seq() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let mut watcher = h.connect();
    assert_eq!(h.watch(&watcher, &line).unwrap().seq, 0);
    let a = h.connect();
    let b = h.connect();
    h.join(&a, &line).unwrap();
    h.join(&b, &line).unwrap();
    let send_seq = h.rooms.send(a.id, a.actor, &line, None, "x").unwrap();
    h.rooms
        .set_state(b.id, b.actor, &line, "s".to_owned())
        .unwrap();
    h.rooms.leave(a.id, a.actor, &line);

    let seqs: Vec<u64> = frames(&mut watcher)
        .iter()
        .map(|f| f["params"]["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(
        send_seq, 3,
        "a message takes a seq though watchers never see it"
    );
    assert_eq!(seqs, [1, 2, 4, 5]);
    assert_eq!(h.rooms.occupancy(&line).unwrap().seq, 5);
}

#[tokio::test]
async fn a_watch_sees_the_members_without_joining_and_is_bounded() {
    let h = Harness::new(RoomRegistryOptions {
        max_watches_per_connection: 2,
        ..RoomRegistryOptions::default()
    });
    let line = room("line");
    let a = h.connect();
    let joined_a = h.join(&a, &line).unwrap();
    let mut watcher = h.connect();

    let occupancy = h.watch(&watcher, &line).unwrap();
    assert_eq!(occupancy.seq, 1);
    assert_eq!(occupancy.members.len(), 1);
    assert_eq!(occupancy.members[0].member_id, joined_a.member_id);
    // watching again answers again and counts once
    assert_eq!(h.watch(&watcher, &line).unwrap().seq, 1);
    h.watch(&watcher, &room("two")).unwrap();
    assert_eq!(
        h.watch(&watcher, &room("three")).unwrap_err(),
        RoomError::WatchLimit
    );

    h.rooms.leave(a.id, a.actor, &line);
    assert_eq!(methods(&mut watcher), ["room_member_left"]);
    assert!(h.room_exists(&line), "a watched room outlives its members");
    assert!(h.rooms.unwatch(watcher.id, &line));
    assert!(!h.rooms.unwatch(watcher.id, &line));
    assert!(!h.room_exists(&line), "and is deleted with its last watch");
    // a freed slot admits another watch
    h.watch(&watcher, &room("three")).unwrap();
}

#[tokio::test]
async fn a_full_room_refuses_and_a_verdict_lowers_the_cap() {
    let h = Harness::new(RoomRegistryOptions {
        max_members_per_room: NonZeroUsize::new(2).unwrap(),
        ..RoomRegistryOptions::default()
    });
    let line = room("line");
    let a = h.connect();
    let b = h.connect();
    let c = h.connect();
    let below = RoomSeatAdmit {
        max_members: Some(1),
        ..RoomSeatAdmit::default()
    };
    h.join(&a, &line).unwrap();
    assert_eq!(
        h.join_with(&b, &line, None, below).unwrap_err(),
        RoomError::Full
    );
    let above = RoomSeatAdmit {
        max_members: Some(10),
        ..RoomSeatAdmit::default()
    };
    h.join_with(&b, &line, None, above).unwrap();
    assert_eq!(h.join(&c, &line).unwrap_err(), RoomError::Full);
    assert!(
        h.rooms.state.lock().pending.is_empty(),
        "a refused join leaves nothing"
    );
}

/// An actor at its seat elsewhere, refused by a full room, keeps its seat.
#[tokio::test]
async fn a_refused_join_displaces_nothing() {
    let h = Harness::new(RoomRegistryOptions {
        exclusive: true,
        max_members_per_room: NonZeroUsize::new(1).unwrap(),
        ..RoomRegistryOptions::default()
    });
    let (here, full) = (room("here"), room("full"));
    let mut a = h.connect();
    let b = h.connect();
    let joined = h.join(&a, &here).unwrap();
    h.join(&b, &full).unwrap();
    assert_eq!(h.join(&a, &full).unwrap_err(), RoomError::Full);
    assert!(frames(&mut a).is_empty());
    assert_eq!(
        h.rooms.occupancy(&here).unwrap().members[0].member_id,
        joined.member_id
    );
}

/// A full room still seats an actor whose move frees a seat in it.
#[tokio::test]
async fn a_move_within_a_full_room_frees_its_own_seat() {
    let h = Harness::new(RoomRegistryOptions {
        exclusive: true,
        max_members_per_room: NonZeroUsize::new(1).unwrap(),
        ..RoomRegistryOptions::default()
    });
    let line = room("line");
    let actor = Uuid::new_v4();
    let old = h.connect_as(actor);
    let new = h.connect_as(actor);
    h.join(&old, &line).unwrap();
    let joined = h.join(&new, &line).unwrap();
    assert_eq!(member_ids(&joined), [joined.member_id]);
}

#[tokio::test]
async fn an_exclusive_join_moves_the_actors_seat() {
    let h = Harness::exclusive();
    let (first, second) = (room("first"), room("second"));
    let actor = Uuid::new_v4();
    let mut tab = h.connect_as(actor);
    let mut other = h.connect();
    let old = h.join(&tab, &first).unwrap();
    h.join(&other, &first).unwrap();
    frames(&mut tab);

    let new = h.join(&tab, &second).unwrap();
    assert_eq!(
        frames(&mut tab)[0]["params"],
        json!({"room_id": "first", "member_id": old.member_id, "reason": "moved", "moved_to": "second"})
    );
    assert_eq!(
        frames(&mut other)[0]["params"],
        json!({"room_id": "first", "seq": 3, "member_id": old.member_id, "reason": "moved"})
    );
    assert_eq!(h.rooms.occupancy(&first).unwrap().members.len(), 1);
    assert_eq!(member_ids(&new), [new.member_id]);
    // the moved seat can't be taken back
    assert_eq!(
        h.join_with(&tab, &first, Some(old.member_id), RoomSeatAdmit::default())
            .unwrap_err(),
        RoomError::SeatMoved
    );
}

/// Two sockets of one actor reserve, then admit in the reverse order: the
/// last admitted wins, whichever reserved first.
#[tokio::test]
async fn the_last_admitted_of_two_sockets_wins() {
    let h = Harness::exclusive();
    let line = room("line");
    let actor = Uuid::new_v4();
    let mut tab_1 = h.connect_as(actor);
    let mut tab_2 = h.connect_as(actor);
    let pending_1 = h.reserve(&tab_1, &line).unwrap();
    let pending_2 = h.reserve(&tab_2, &line).unwrap();

    let joined_2 = h
        .rooms
        .admit_seat(pending_2, RoomSeatAdmit::default())
        .unwrap();
    let joined_1 = h
        .rooms
        .admit_seat(pending_1, RoomSeatAdmit::default())
        .unwrap();
    assert_eq!(member_ids(&joined_1), [joined_1.member_id]);
    assert_eq!(
        frames(&mut tab_2)[0]["params"],
        json!({"room_id": "line", "member_id": joined_2.member_id, "reason": "moved", "moved_to": "line"})
    );
    assert!(frames(&mut tab_1).is_empty());
}

/// A connection joining a room it sits in again moves its own seat, on any
/// registry.
#[tokio::test]
async fn joining_again_moves_the_connections_own_seat() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let mut a = h.connect();
    let first = h.join(&a, &line).unwrap();
    let second = h.join(&a, &line).unwrap();
    assert_ne!(first.member_id, second.member_id);
    assert_eq!(member_ids(&second), [second.member_id]);
    assert_eq!(methods(&mut a), ["room_seat_lost"]);
}

/// A connection whose requests act as two actors of one account holds a seat
/// for each, and every seat operation touches only the acting actor's own.
#[tokio::test]
async fn seats_are_per_actor_on_one_connection() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let mut tab = h.connect();
    let other_actor = Uuid::new_v4();
    let mut other = h.connect();
    let first = h.join(&tab, &line).unwrap();
    let pending = h
        .rooms
        .reserve_seat(RoomSeatRequest {
            connection_id: tab.id,
            actor_id: other_actor,
            room_id: line.clone(),
            rejoin_of: None,
        })
        .unwrap();
    let second = h
        .rooms
        .admit_seat(pending, RoomSeatAdmit::default())
        .unwrap();
    assert_eq!(
        member_ids(&second),
        [first.member_id, second.member_id],
        "the second actor's join moved nothing"
    );
    h.join(&other, &line).unwrap();
    frames(&mut tab);
    frames(&mut other);

    // a state set and a send act from the acting actor's seat
    h.rooms
        .set_state(tab.id, other_actor, &line, "s".to_owned())
        .unwrap();
    assert_eq!(
        frames(&mut other)[0]["params"]["member_id"],
        json!(second.member_id)
    );
    // events skip the seat that caused them, not its connection: the first
    // seat on the same socket hears the second's state
    assert_eq!(
        frames(&mut tab)[0]["params"]["member_id"],
        json!(second.member_id)
    );
    h.rooms
        .send(tab.id, other_actor, &line, Some(first.member_id), "p")
        .unwrap();
    let heard = frames(&mut tab);
    assert_eq!(heard[0]["params"]["from"], json!(second.member_id));
    assert_eq!(heard[0]["params"]["to"], json!(first.member_id));
    // an actor with no seat on the connection has nothing to act on
    let stranger = Uuid::new_v4();
    assert_eq!(
        h.rooms.send(tab.id, stranger, &line, None, "p"),
        Err(RoomError::NotJoined)
    );
    assert!(!h.rooms.leave(tab.id, stranger, &line));

    // a leave ends only the acting actor's seat
    assert!(h.rooms.leave(tab.id, other_actor, &line));
    let members = h.rooms.occupancy(&line).unwrap().members;
    assert_eq!(members.len(), 2);
    assert!(members.iter().any(|m| m.member_id == first.member_id));
    h.rooms
        .send(tab.id, tab.actor, &line, None, "still here")
        .unwrap();
}

#[tokio::test]
async fn a_shared_registry_seats_an_actor_on_each_socket() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let actor = Uuid::new_v4();
    let tab_1 = h.connect_as(actor);
    let tab_2 = h.connect_as(actor);
    let first = h.join(&tab_1, &line).unwrap();
    // `rejoin_of` means nothing without exclusivity
    let second = h
        .join_with(
            &tab_2,
            &line,
            Some(first.member_id),
            RoomSeatAdmit::default(),
        )
        .unwrap();
    assert_eq!(member_ids(&second), [first.member_id, second.member_id]);
}

#[tokio::test]
async fn a_seat_lost_to_a_disconnect_is_rejoined() {
    let h = Harness::exclusive();
    let line = room("line");
    let actor = Uuid::new_v4();
    let mut other = h.connect();
    h.join(&other, &line).unwrap();
    let old_tab = h.connect_as(actor);
    let old = h.join(&old_tab, &line).unwrap();
    frames(&mut other);

    h.disconnect(&old_tab).await;
    assert_eq!(
        frames(&mut other)[0]["params"],
        json!({"room_id": "line", "seq": 3, "member_id": old.member_id, "reason": "disconnected"})
    );
    let new_tab = h.connect_as(actor);
    h.join_with(
        &new_tab,
        &line,
        Some(old.member_id),
        RoomSeatAdmit::default(),
    )
    .unwrap();
    assert!(
        !h.rooms.state.lock().tombstones.contains_key(&actor),
        "the rejoin spends the tombstone"
    );
}

/// The steal-back: a seat released by its disconnect, then the actor seated
/// elsewhere — the dead seat's rejoin must not take the new seat back.
#[tokio::test]
async fn a_rejoin_after_the_actor_moved_on_is_refused() {
    let h = Harness::exclusive();
    let (first, second) = (room("first"), room("second"));
    let actor = Uuid::new_v4();
    let dead_tab = h.connect_as(actor);
    let old = h.join(&dead_tab, &first).unwrap();
    h.disconnect(&dead_tab).await;

    let live_tab = h.connect_as(actor);
    let live = h.join(&live_tab, &second).unwrap();

    let reconnected = h.connect_as(actor);
    assert_eq!(
        h.reserve_rejoin(&reconnected, &first, Some(old.member_id))
            .unwrap_err(),
        RoomError::SeatMoved,
        "refused at the reserve, before the authorizer"
    );
    assert_eq!(
        h.rooms.occupancy(&second).unwrap().members[0].member_id,
        live.member_id
    );
}

/// The guard is decided at the admit too: a rejoin reserved before the
/// actor's other join admitted is refused after it.
#[tokio::test]
async fn a_rejoin_in_flight_when_the_actor_moved_on_is_refused() {
    let h = Harness::exclusive();
    let (first, second) = (room("first"), room("second"));
    let actor = Uuid::new_v4();
    let dead_tab = h.connect_as(actor);
    let old = h.join(&dead_tab, &first).unwrap();
    h.disconnect(&dead_tab).await;

    let reconnected = h.connect_as(actor);
    let rejoin = h
        .reserve_rejoin(&reconnected, &first, Some(old.member_id))
        .unwrap();
    let live_tab = h.connect_as(actor);
    h.join(&live_tab, &second).unwrap();
    assert_eq!(
        h.rooms
            .admit_seat(rejoin, RoomSeatAdmit::default())
            .unwrap_err(),
        RoomError::SeatMoved
    );
}

#[tokio::test(start_paused = true)]
async fn tombstones_are_short_and_few() {
    let h = Harness::exclusive();
    let (first, second) = (room("first"), room("second"));
    let actor = Uuid::new_v4();
    let tab = h.connect_as(actor);
    let old = h.join(&tab, &first).unwrap();
    h.join(&tab, &second).unwrap();
    tokio::time::advance(ROOM_REJOIN_TOMBSTONE_TTL).await;
    let late = h.connect_as(actor);
    h.join_with(&late, &first, Some(old.member_id), RoomSeatAdmit::default())
        .expect("past its time a tombstone guards nothing");

    // moves past the per-actor bound forget the oldest: each join moves the
    // seat the one before it took
    let mut seats = Vec::new();
    for _ in 0..ROOM_REJOIN_TOMBSTONES_PER_ACTOR + 2 {
        seats.push(h.join(&tab, &first).unwrap().member_id);
    }
    let tombstones = h.rooms.state.lock().tombstones[&actor].len();
    assert_eq!(tombstones, ROOM_REJOIN_TOMBSTONES_PER_ACTOR);
    let fresh = h.connect_as(actor);
    drop(h.reserve_rejoin(&fresh, &first, Some(seats[0])).unwrap());
    assert_eq!(
        h.reserve_rejoin(&fresh, &first, Some(seats[1]))
            .unwrap_err(),
        RoomError::SeatMoved
    );
}

/// An eviction reaches a join between its reserve and its admit: by actor
/// and by room outright, by scope only when the verdict names that scope.
#[tokio::test]
async fn an_eviction_reaches_a_join_in_flight() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let a = h.connect();
    let scope = RoomScope::new("group-1");
    let in_scope = || RoomSeatAdmit {
        scope: Some(scope.clone()),
        ..RoomSeatAdmit::default()
    };

    for target in [
        RoomEvictTarget::Actor(a.actor),
        RoomEvictTarget::Room(line.clone()),
        RoomEvictTarget::Scope(scope.clone()),
        RoomEvictTarget::ActorInScope {
            actor_id: a.actor,
            scope: scope.clone(),
        },
    ] {
        let pending = h.reserve(&a, &line).unwrap();
        let evicted = h.rooms.evict(&target, RoomEvictReason::Evicted);
        assert_eq!(
            evicted,
            RoomEvicted {
                pending: 1,
                ..RoomEvicted::default()
            },
            "{target:?}"
        );
        assert_eq!(
            h.rooms.admit_seat(pending, in_scope()).unwrap_err(),
            RoomError::Evicted,
            "{target:?}"
        );
        assert!(!h.room_exists(&line));
    }

    // a scope eviction leaves a join admitted under another scope alone
    let pending = h.reserve(&a, &line).unwrap();
    h.rooms.evict(
        &RoomEvictTarget::Scope(RoomScope::new("group-2")),
        RoomEvictReason::Evicted,
    );
    h.rooms.admit_seat(pending, in_scope()).unwrap();
    // and an eviction of another actor leaves it alone outright
    let b = h.connect();
    let pending = h.reserve(&b, &line).unwrap();
    h.rooms
        .evict(&RoomEvictTarget::Actor(a.actor), RoomEvictReason::Evicted);
    h.rooms.admit_seat(pending, in_scope()).unwrap();
}

#[tokio::test]
async fn an_eviction_covers_seats_and_watches() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let scope = RoomScope::new("group");
    let actor = Uuid::new_v4();
    // the evicted actor sits in the room on one socket and watches it on another
    let mut seated = h.connect_as(actor);
    let mut watching = h.connect_as(actor);
    let mut stays = h.connect();
    let pending = h.reserve(&seated, &line).unwrap();
    let joined = h
        .rooms
        .admit_seat(
            pending,
            RoomSeatAdmit {
                scope: Some(scope.clone()),
                ..RoomSeatAdmit::default()
            },
        )
        .unwrap();
    h.join(&stays, &line).unwrap();
    let pending = h
        .rooms
        .reserve_watch(watching.id, actor, line.clone())
        .unwrap();
    h.rooms.admit_watch(pending, Some(scope.clone())).unwrap();
    for client in [&mut seated, &mut watching, &mut stays] {
        frames(client);
    }

    let evicted = h.rooms.evict(
        &RoomEvictTarget::ActorInScope {
            actor_id: actor,
            scope,
        },
        RoomEvictReason::Evicted,
    );
    assert_eq!(
        evicted,
        RoomEvicted {
            seats: 1,
            watches: 1,
            pending: 0
        }
    );
    assert_eq!(
        frames(&mut seated)[0]["params"],
        json!({"room_id": "line", "member_id": joined.member_id, "reason": "evicted", "moved_to": null})
    );
    assert_eq!(
        frames(&mut watching)[0],
        json!({"jsonrpc": "2.0", "method": "room_watch_ended", "params": {"room_id": "line", "reason": "evicted"}})
    );
    assert_eq!(
        frames(&mut stays)[0]["params"],
        json!({"room_id": "line", "seq": 3, "member_id": joined.member_id, "reason": "evicted"})
    );
    assert_eq!(h.rooms.occupancy(&line).unwrap().members.len(), 1);
}

/// Closing a room tells each member its seat is lost and each watcher its
/// watch ended, and no one about the others leaving.
#[tokio::test]
async fn closing_a_room_ends_every_seat_and_watch() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let mut a = h.connect();
    let mut b = h.connect();
    let mut watcher = h.connect();
    h.join(&a, &line).unwrap();
    h.join(&b, &line).unwrap();
    h.watch(&watcher, &line).unwrap();
    for client in [&mut a, &mut b, &mut watcher] {
        frames(client);
    }

    let evicted = h.rooms.evict(
        &RoomEvictTarget::Room(line.clone()),
        RoomEvictReason::RoomClosed,
    );
    assert_eq!((evicted.seats, evicted.watches), (2, 1));
    for client in [&mut a, &mut b] {
        let heard = frames(client);
        assert_eq!(heard.len(), 1);
        assert_eq!(heard[0]["method"], "room_seat_lost");
        assert_eq!(heard[0]["params"]["reason"], "room_closed");
    }
    assert_eq!(methods(&mut watcher), ["room_watch_ended"]);
    assert!(!h.room_exists(&line));
}

#[tokio::test]
async fn a_leave_supersedes_the_connections_join_in_flight() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let a = h.connect();
    let pending = h.reserve(&a, &line).unwrap();
    // another actor's leave on the connection leaves the join alone
    assert!(!h.rooms.leave(a.id, Uuid::new_v4(), &line));
    assert!(h.rooms.leave(a.id, a.actor, &line));
    assert_eq!(
        h.rooms
            .admit_seat(pending, RoomSeatAdmit::default())
            .unwrap_err(),
        RoomError::JoinSuperseded
    );
}

#[tokio::test]
async fn a_dropped_join_in_flight_leaves_nothing() {
    let h = Harness::new(RoomRegistryOptions::default());
    let a = h.connect();
    let pending = h.reserve(&a, &room("line")).unwrap();
    assert_eq!(h.rooms.state.lock().pending.len(), 1);
    drop(pending);
    let state = h.rooms.state.lock();
    assert!(state.pending.is_empty());
    assert!(state.connections[&a.id].pending.is_empty());
}

#[tokio::test]
async fn a_closed_socket_is_refused_at_either_phase() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");

    // cancelled while still registered — the window between a close path
    // firing the token and the socket's loop removing the connection: no
    // entry, no waiter
    let closing = h.connect();
    closing.signal.cancel();
    assert!(h.connections.is_registered(closing.id));
    assert_eq!(
        h.reserve(&closing, &line).unwrap_err(),
        RoomError::ConnectionClosed
    );
    assert_eq!(
        h.rooms
            .reserve_watch(closing.id, closing.actor, line.clone())
            .unwrap_err(),
        RoomError::ConnectionClosed
    );
    assert_eq!(h.rooms.live_waiters(), 0);
    assert!(h.rooms.state.lock().connections.is_empty());

    // closed before the reserve: no entry, no waiter
    let gone = h.connect();
    gone.signal.cancel();
    h.connections.remove_connection(gone.id);
    assert_eq!(
        h.reserve(&gone, &line).unwrap_err(),
        RoomError::ConnectionClosed
    );
    assert_eq!(
        h.rooms
            .reserve_watch(gone.id, gone.actor, line.clone())
            .unwrap_err(),
        RoomError::ConnectionClosed
    );
    assert_eq!(h.rooms.live_waiters(), 0);

    // closed between the two: refused at once, before its waiter runs
    let a = h.connect();
    let pending = h.reserve(&a, &line).unwrap();
    a.signal.cancel();
    assert_eq!(
        h.rooms
            .admit_seat(pending, RoomSeatAdmit::default())
            .unwrap_err(),
        RoomError::ConnectionClosed
    );
    assert!(!h.room_exists(&line));
}

#[tokio::test]
async fn a_disconnect_releases_every_seat_and_watch() {
    let h = Harness::new(RoomRegistryOptions::default());
    let (first, second, watched) = (room("first"), room("second"), room("watched"));
    let mut other = h.connect();
    h.join(&other, &first).unwrap();
    h.join(&other, &second).unwrap();
    let leaving = h.connect();
    let in_first = h.join(&leaving, &first).unwrap();
    let in_second = h.join(&leaving, &second).unwrap();
    h.watch(&leaving, &watched).unwrap();
    let in_flight = h.reserve(&leaving, &room("third")).unwrap();
    frames(&mut other);

    h.disconnect(&leaving).await;
    let mut left: Vec<Value> = frames(&mut other)
        .into_iter()
        .map(|f| f["params"].clone())
        .collect();
    left.sort_by_key(|p| p["room_id"].as_str().unwrap().to_owned());
    assert_eq!(
        left,
        [
            json!({"room_id": "first", "seq": 3, "member_id": in_first.member_id, "reason": "disconnected"}),
            json!({"room_id": "second", "seq": 3, "member_id": in_second.member_id, "reason": "disconnected"}),
        ]
    );
    assert!(!h.room_exists(&watched));
    assert_eq!(
        h.rooms
            .admit_seat(in_flight, RoomSeatAdmit::default())
            .unwrap_err(),
        RoomError::ConnectionClosed
    );
    assert_eq!(h.rooms.live_waiters(), 1, "only the other connection's");
}

/// A disconnect releases the seat of every actor that joined on the
/// connection, not one per room.
#[tokio::test]
async fn a_disconnect_releases_every_actors_seat() {
    let h = Harness::exclusive();
    let line = room("line");
    let tab = h.connect();
    let second_actor = Uuid::new_v4();
    let mut other = h.connect();
    h.join(&tab, &line).unwrap();
    let pending = h
        .rooms
        .reserve_seat(RoomSeatRequest {
            connection_id: tab.id,
            actor_id: second_actor,
            room_id: line.clone(),
            rejoin_of: None,
        })
        .unwrap();
    h.rooms
        .admit_seat(pending, RoomSeatAdmit::default())
        .unwrap();
    h.join(&other, &line).unwrap();
    frames(&mut other);

    h.disconnect(&tab).await;
    let reasons: Vec<Value> = frames(&mut other)
        .into_iter()
        .map(|f| f["params"]["reason"].clone())
        .collect();
    assert_eq!(reasons, [json!("disconnected"), json!("disconnected")]);
    assert_eq!(h.rooms.occupancy(&line).unwrap().members.len(), 1);
    assert!(
        !h.rooms
            .state
            .lock()
            .seat_of_actor
            .contains_key(&second_actor)
    );
}

/// A watch is one per connection and room, held for whichever actor last
/// asked: evicting that actor ends it, evicting an earlier asker doesn't.
#[tokio::test]
async fn a_watch_is_held_for_the_actor_that_last_asked() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let mut tab = h.connect();
    let second_actor = Uuid::new_v4();
    h.watch(&tab, &line).unwrap();
    let pending = h
        .rooms
        .reserve_watch(tab.id, second_actor, line.clone())
        .unwrap();
    h.rooms.admit_watch(pending, None).unwrap();

    let first = h
        .rooms
        .evict(&RoomEvictTarget::Actor(tab.actor), RoomEvictReason::Evicted);
    assert_eq!(first.watches, 0, "the earlier asker no longer holds it");
    assert!(frames(&mut tab).is_empty());
    let second = h.rooms.evict(
        &RoomEvictTarget::Actor(second_actor),
        RoomEvictReason::Evicted,
    );
    assert_eq!(second.watches, 1);
    assert_eq!(frames(&mut tab)[0]["method"], "room_watch_ended");
    assert!(!h.room_exists(&line));
}

/// One waiter per connection, however many seats and watches it takes and
/// gives back; none once the socket closes.
#[tokio::test]
async fn one_waiter_per_connection_across_many_joins() {
    let h = Harness::exclusive();
    let a = h.connect();
    let b = h.connect();
    for i in 0..200 {
        let line = room(&format!("line-{}", i % 3));
        h.join(&a, &line).unwrap();
        h.watch(&a, &line).unwrap();
        h.join(&b, &line).unwrap();
        drop(h.reserve(&a, &line).unwrap());
        assert!(h.rooms.leave(a.id, a.actor, &line));
        assert!(h.rooms.unwatch(a.id, &line));
        h.rooms.leave(b.id, b.actor, &line);
    }
    // let any stray waiter run before counting
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(h.rooms.live_waiters(), 2);
    {
        let state = h.rooms.state.lock();
        assert!(state.rooms.is_empty());
        assert!(state.pending.is_empty());
    }

    h.disconnect(&a).await;
    h.disconnect(&b).await;
    until(|| h.rooms.live_waiters() == 0).await;
    assert!(h.rooms.state.lock().connections.is_empty());
}

/// A member that stops reading overflows its outbound budget on the room's
/// fan-out: the connection registry closes it, and its seat is released as
/// a disconnect.
#[tokio::test]
async fn a_slow_member_is_closed_and_released() {
    let h = Harness::new(RoomRegistryOptions::default());
    let line = room("line");
    let mut sender = h.connect();
    let slow = h.connect_with_budget(Uuid::new_v4(), 256);
    h.join(&sender, &line).unwrap();
    let slow_seat = h.join(&slow, &line).unwrap();
    frames(&mut sender);

    let payload = "x".repeat(100);
    let mut sent = 0;
    while !slow.signal.is_cancelled() {
        h.rooms
            .send(sender.id, sender.actor, &line, None, &payload)
            .unwrap();
        sent += 1;
        assert!(sent < 100, "the budget overflows");
    }
    assert!(!h.connections.is_registered(slow.id));
    let rooms = Arc::clone(&h.rooms);
    until(move || rooms.occupancy(&room("line")).unwrap().members.len() == 1).await;
    assert_eq!(
        frames(&mut sender)[0]["params"]["member_id"],
        json!(slow_seat.member_id)
    );
}

#[tokio::test]
async fn clear_drops_everything_and_refuses_what_is_in_flight() {
    let h = Harness::exclusive();
    let line = room("line");
    let mut a = h.connect();
    h.join(&a, &line).unwrap();
    h.join(&a, &room("other")).unwrap();
    h.watch(&a, &line).unwrap();
    let pending = h.reserve(&a, &line).unwrap();
    frames(&mut a);

    h.rooms.clear();
    assert!(frames(&mut a).is_empty(), "silent");
    assert!(h.rooms.occupancy(&line).is_none());
    assert_eq!(
        h.rooms
            .admit_seat(pending, RoomSeatAdmit::default())
            .unwrap_err(),
        RoomError::Evicted
    );
    let state = h.rooms.state.lock();
    assert!(state.tombstones.is_empty());
    assert!(state.seat_of_actor.is_empty());
    assert_eq!(state.connections.len(), 1, "the waiter's entry stays");
    drop(state);
    // and the connection joins afresh, on the same waiter
    h.join(&a, &line).unwrap();
    assert_eq!(h.rooms.live_waiters(), 1);
}
