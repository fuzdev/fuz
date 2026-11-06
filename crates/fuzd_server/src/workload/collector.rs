//! Shared collector plumbing: the subscriber-management command + the fan-out
//! subscriber record, common to every streaming workload kind.
//!
//! Lifecycle (refcount, idle-grace, the revive race) lives in the registry
//! ([`super`]); a collector task is a dumb executor that maintains its fan-out
//! subscriber list and obeys these commands. The observer and watcher kinds
//! share the *subscriber model* (identical add / remove / drop semantics and
//! the resync-on-full-channel flag) but each owns its frame encoding +
//! acquisition, so the per-kind collector loops stay separate.
//!
//! **A collector never awaits a subscriber.** Every frame it emits — the first
//! snapshot ([`add_subscriber`]) as much as the fan-out — goes out by
//! `try_send`; a full channel is a dropped frame plus a resync, never a wait. One
//! client that stops reading costs only its own frames: the collector keeps
//! serving everyone else, keeps draining its command channel, and keeps
//! answering its stop token.

use fuz_wire::{ActionId, FrameFlags};
use tokio::sync::mpsc::error::TrySendError;

use crate::out::{OutFrame, OutTx};

/// Depth of a collector's command channel.
pub const COLLECTOR_CMD_CAP: usize = 64;

/// Commands the registry sends to a collector task — kind-agnostic subscriber
/// management. The registry holds `mpsc::Sender<CollectorCommand>` per workload
/// regardless of kind, so a connection drop / unsubscribe reaches any collector
/// uniformly.
#[derive(Debug)]
pub enum CollectorCommand {
    /// Add a subscriber and immediately send it a snapshot frame.
    AddSubscriber {
        conn_id: u64,
        request_id: u32,
        out_tx: OutTx,
    },
    /// Remove one subscription (explicit unsubscribe).
    RemoveSubscriber { conn_id: u64, request_id: u32 },
    /// Remove every subscription for a closed connection.
    DropConnection { conn_id: u64 },
}

/// One fan-out target.
pub struct Subscriber {
    pub conn_id: u64,
    pub request_id: u32,
    pub out_tx: OutTx,
    /// Set when a `try_send` hit a full channel — or the subscriber joined while
    /// its channel was full: the next frame this subscriber gets is a fresh
    /// snapshot (resync), not an incremental or coverage frame.
    pub needs_resync: bool,
}

/// Build a stream frame (never `FINAL`) from a pre-encoded body. Every kind's
/// fan-out emits its frames through this — the flags are always
/// [`FrameFlags::EMPTY`] (a subscription stream has no `FINAL` frame; it ends on
/// connection close).
pub const fn out_frame(request_id: u32, action: ActionId, body: Vec<u8>) -> OutFrame {
    OutFrame {
        request_id,
        action,
        flags: FrameFlags::EMPTY,
        body,
    }
}

/// What a fan-out loop must do with the subscriber [`send_resync_snapshot`]
/// just looked at.
pub enum ResyncOutcome {
    /// Not flagged — the caller sends its incremental frame as usual.
    NotFlagged,
    /// Flagged and dealt with: the snapshot went out and the flag is cleared,
    /// or the channel was full, or there was no snapshot body to send. The
    /// latter two leave the subscriber flagged for the next pass; either way
    /// the caller skips it and sends nothing incremental this pass.
    Handled,
    /// The subscriber's channel is closed — the caller records it for removal.
    Closed,
}

/// One pre-encoded frame body and its action, not yet addressed to a
/// subscriber. A snapshot is a sequence of these: one snapshot frame, and — for
/// an observer snapshot too large for one frame — the `added` deltas that carry
/// the rest of it ([`super::frame_split`]).
pub type EncodedFrame = (ActionId, Vec<u8>);

/// Queue `frames` for one subscriber, in order, never awaiting room. Stops at
/// the first frame that does not go out; the frames before it stay queued.
///
/// # Errors
///
/// Returns the [`TrySendError`] of the frame that did not go out.
pub fn try_send_frames(
    out_tx: &OutTx,
    request_id: u32,
    frames: &[EncodedFrame],
) -> Result<(), TrySendError<()>> {
    for (action, body) in frames {
        out_tx
            .try_send(out_frame(request_id, *action, body.clone()))
            .map_err(|err| match err {
                TrySendError::Full(_) => TrySendError::Full(()),
                TrySendError::Closed(_) => TrySendError::Closed(()),
            })?;
    }
    Ok(())
}

/// Serve one subscriber its resync snapshot, if it is flagged for one.
///
/// The shared resync arm at the top of each kind's `fanout` loop: a subscriber
/// whose channel filled gets a fresh snapshot instead of the incremental frame
/// it missed, so a consumer never applies a delta / event batch across a gap.
/// The watcher's separate `fanout_coverage` loop does not serve a resync — a
/// full channel there only raises the flag this helper later acts on.
/// The kind supplies `snapshot`, its snapshot frames (encoded once per pass,
/// lazily — `None` when no subscriber needed one, or when the encode failed).
///
/// Both no-progress cases leave `needs_resync` set so the next pass retries;
/// only a delivered snapshot clears it. A snapshot of several frames that a
/// full channel cut short does no harm: the subscriber stays flagged, and the
/// next snapshot resets whatever part of this one it read. Subscriber removal
/// stays with the caller, which owns the loop's index bookkeeping.
pub fn send_resync_snapshot(
    sub: &mut Subscriber,
    snapshot: Option<&[EncodedFrame]>,
) -> ResyncOutcome {
    if !sub.needs_resync {
        return ResyncOutcome::NotFlagged;
    }
    let Some(frames) = snapshot else {
        return ResyncOutcome::Handled; // encode failed; stay flagged, retry next pass
    };
    match try_send_frames(&sub.out_tx, sub.request_id, frames) {
        Ok(()) => {
            sub.needs_resync = false;
            ResyncOutcome::Handled
        }
        Err(TrySendError::Full(())) => ResyncOutcome::Handled,
        Err(TrySendError::Closed(())) => ResyncOutcome::Closed,
    }
}

/// Handle [`CollectorCommand::AddSubscriber`]: register the subscriber and
/// offer it `snapshot`, its first frames, **without awaiting room**.
///
/// A collector serves every subscriber of its workload from one task, so an
/// awaited send into one connection's channel would stall the fan-out to all
/// the others (and, held in a `select!` arm body, keep the collector from
/// seeing its stop token). Instead a full channel registers the subscriber
/// already flagged `needs_resync`: the kind's next fan-out pass serves it a
/// fresh snapshot ([`send_resync_snapshot`]) before anything incremental, so
/// its first frame is still a snapshot — just a later one. A snapshot that
/// could not be encoded (`None`) registers it flagged the same way. A closed
/// channel (the connection is already gone) registers nothing.
pub fn add_subscriber(
    subs: &mut Vec<Subscriber>,
    conn_id: u64,
    request_id: u32,
    out_tx: OutTx,
    snapshot: Option<&[EncodedFrame]>,
) {
    let sent = snapshot.map(|frames| try_send_frames(&out_tx, request_id, frames));
    let needs_resync = match sent {
        Some(Ok(())) => false,
        None | Some(Err(TrySendError::Full(()))) => true,
        Some(Err(TrySendError::Closed(()))) => return,
    };
    subs.push(Subscriber {
        conn_id,
        request_id,
        out_tx,
        needs_resync,
    });
}

/// Handle [`CollectorCommand::RemoveSubscriber`]: drop the one subscription
/// matching `(conn_id, request_id)`.
pub fn remove_subscriber(subs: &mut Vec<Subscriber>, conn_id: u64, request_id: u32) {
    subs.retain(|s| !(s.conn_id == conn_id && s.request_id == request_id));
}

/// Handle [`CollectorCommand::DropConnection`]: drop every subscription for a
/// closed connection.
pub fn drop_connection(subs: &mut Vec<Subscriber>, conn_id: u64) {
    subs.retain(|s| s.conn_id != conn_id);
}

/// Drop the subscribers whose channel closed during a fan-out — back-to-front so
/// the gathered `swap_remove` indices stay valid as earlier ones are removed.
pub fn drop_closed(subs: &mut Vec<Subscriber>, closed: Vec<usize>) {
    for idx in closed.into_iter().rev() {
        subs.swap_remove(idx);
    }
}

/// A channel whose one slot is already taken — a subscriber that has stopped
/// reading, as the collector sees it. The receiver must be kept alive (dropping
/// it would read as a closed connection, not a stuck one).
#[cfg(test)]
pub fn full_out_channel() -> (OutTx, crate::out::OutRx) {
    let (out_tx, out_rx) = tokio::sync::mpsc::channel(1);
    let filler = out_frame(0, fuz_wire::ids::PONG, Vec::new());
    assert!(out_tx.try_send(filler).is_ok(), "prefill the one slot");
    (out_tx, out_rx)
}

/// Send a collector a [`CollectorCommand::AddSubscriber`] for `conn_id` (at a
/// fixed request id) over `out_tx`.
#[cfg(test)]
pub async fn send_add_subscriber(
    cmd_tx: &tokio::sync::mpsc::Sender<CollectorCommand>,
    conn_id: u64,
    out_tx: OutTx,
) {
    cmd_tx
        .send(CollectorCommand::AddSubscriber {
            conn_id,
            request_id: 99,
            out_tx,
        })
        .await
        .expect("send add");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_frames() -> Vec<EncodedFrame> {
        vec![(fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME, vec![1])]
    }

    #[test]
    fn add_subscriber_sends_the_snapshot_when_there_is_room() {
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(4);
        let mut subs = Vec::new();
        add_subscriber(&mut subs, 1, 9, out_tx, Some(&snapshot_frames()));
        assert_eq!(subs.len(), 1);
        assert!(
            !subs[0].needs_resync,
            "a delivered snapshot leaves no resync owed"
        );
        let frame = out_rx.try_recv().expect("the snapshot went out");
        assert_eq!(frame.request_id, 9);
        assert_eq!(frame.action, fuz_wire::ids::OBSERVER_SNAPSHOT_FRAME);
    }

    #[test]
    fn add_subscriber_on_a_full_channel_registers_it_flagged_without_waiting() {
        // The collector must not wait for room: the subscriber is registered at
        // once, flagged so the next fan-out pass serves its snapshot.
        let (out_tx, mut out_rx) = full_out_channel();
        let mut subs = Vec::new();
        add_subscriber(&mut subs, 1, 9, out_tx, Some(&snapshot_frames()));
        assert_eq!(subs.len(), 1, "registered despite the full channel");
        assert!(subs[0].needs_resync, "owes a snapshot as its first frame");
        let filler = out_rx.try_recv().expect("the prefill");
        assert_eq!(filler.action, fuz_wire::ids::PONG);
        assert!(out_rx.try_recv().is_err(), "no snapshot was queued");
    }

    #[test]
    fn add_subscriber_on_a_closed_channel_registers_nothing() {
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(4);
        drop(out_rx);
        let mut subs = Vec::new();
        add_subscriber(&mut subs, 1, 9, out_tx, Some(&snapshot_frames()));
        assert!(subs.is_empty(), "a gone connection is not subscribed");
    }

    fn sub(conn_id: u64) -> Subscriber {
        // A sender to a dropped receiver is fine — these subscribers are never
        // sent to; the test only exercises the index bookkeeping.
        let (out_tx, _rx) = tokio::sync::mpsc::channel(1);
        Subscriber {
            conn_id,
            request_id: 1,
            out_tx,
            needs_resync: false,
        }
    }

    #[test]
    fn drop_closed_removes_by_descending_index_without_invalidation() {
        // Drop the subscribers at indices 1 and 3 of four. Front-to-back
        // `swap_remove` would, after removing index 1, shift index 3 past the
        // shrunken len (panic) — the descending order keeps the gathered
        // indices valid. Survivors must be exactly the un-closed conn_ids.
        let mut subs = vec![sub(0), sub(1), sub(2), sub(3)];
        drop_closed(&mut subs, vec![1, 3]);
        let mut survivors: Vec<u64> = subs.iter().map(|s| s.conn_id).collect();
        survivors.sort_unstable();
        assert_eq!(survivors, vec![0, 2]);
    }

    #[test]
    fn add_subscriber_without_a_snapshot_registers_it_owed_one() {
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(4);
        let mut subs = Vec::new();
        add_subscriber(&mut subs, 1, 9, out_tx, None);
        assert_eq!(subs.len(), 1);
        assert!(subs[0].needs_resync, "the next pass serves its snapshot");
        assert!(out_rx.try_recv().is_err(), "nothing was sent");
    }
}
