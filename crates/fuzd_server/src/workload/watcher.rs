//! The watcher collector task.
//!
//! One task per registered watcher workload. It holds a [`WatchSession`] while
//! it has subscribers (push-driven — no interval sampling), coalesces the event
//! stream over a short flush window, and fans event frames out to every
//! subscriber. Demand-driven: it drops the OS watch when it has no subscribers
//! and exits when its [`CancellationToken`] fires (idle-grace retire or daemon
//! shutdown).
//!
//! Unlike the [observer](super::observer) the watcher has **no delta** — a
//! filesystem watch is an append-only event stream, not a diffable entity set.
//! A subscription opens with one [`WatcherSnapshotFrame`] (the watched roots +
//! their [`WatchCoverage`]), then event frames; on overflow / full-channel it
//! re-sends the snapshot to signal a gap (the consumer resets its fs region),
//! mirroring the observer's resync-over-drop. Coverage *changes* (a watch coming
//! up partial, degrading after establishment, or recovering) ride a separate
//! [`WatcherCoverageFrame`] — a label update with no event gap — so the consumer
//! learns its fs region is incomplete without a disruptive re-baseline.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fuz_wire::{
    WatchCoverage, WatchEvent, WatchSnapshot, WatcherCoverageFrame, WatcherEventFrame,
    WatcherSnapshotFrame, WorkloadId, encode_payload, ids,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::collector::{
    CollectorCommand, EncodedFrame, ResyncOutcome, Subscriber, add_subscriber, drop_closed,
    drop_connection, out_frame, remove_subscriber, send_resync_snapshot, try_send_frames,
};
use super::frame_split::{FRAME_BODY_BUDGET, split_encode, split_vec};
use super::watch_source::{WatchSession, WatchSource};

/// How often buffered fs events are coalesced into one frame and fanned out.
/// Short enough to feel live, long enough to batch a build's burst.
pub const WATCH_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Max events buffered between flushes. Past this the batch is dropped and
/// subscribers resync with a snapshot (a partial fs batch would mislead — the
/// resync signals the gap), mirroring the observer's resync-over-drop.
const WATCH_BUFFER_CAP: usize = 4096;

/// Minimum spacing between watch-establishment retries when `start` fails (a
/// missing root, or an exhausted inotify budget). Without it the active loop
/// re-attempts + warns on every flush tick (~4×/s) while a subscriber waits;
/// this bounds a persistently-stuck watch to one attempt + one warning per
/// interval. A dropped *established* watch still reconnects immediately (the
/// gate resets on success).
const WATCH_START_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// One message from the live session, folding its two channels (the event stream
/// and the watch thread's coverage-degradation reports) so the collector borrows
/// `session` once per loop turn.
enum SessionMsg {
    /// A cleaned filesystem event (`None` = the backend thread ended → re-establish).
    Event(Option<WatchEvent>),
    /// A live re-watch degradation: the count of additional blind-spot subtrees
    /// (`None` = the channel closed alongside the thread).
    Degradation(Option<u32>),
}

/// The blind-spot subtree count a coverage carries (0 unless [`Partial`]).
///
/// [`Partial`]: WatchCoverage::Partial
const fn unwatched_count(coverage: WatchCoverage) -> u32 {
    match coverage {
        WatchCoverage::Partial { unwatched } => unwatched,
        _ => 0,
    }
}

/// Coverage derived from a running blind-spot total on a *live* watch: zero is
/// [`Complete`], otherwise [`Partial`]. Used only while a session is live (the
/// dark/`Unavailable` and pre-establishment/`Unknown` states are set elsewhere).
///
/// [`Complete`]: WatchCoverage::Complete
/// [`Partial`]: WatchCoverage::Partial
const fn coverage_from_unwatched(unwatched: u32) -> WatchCoverage {
    if unwatched == 0 {
        WatchCoverage::Complete
    } else {
        WatchCoverage::Partial { unwatched }
    }
}

/// Run a watcher collector until its `stop` token fires.
///
/// The stop token is raced against the whole loop, not only polled between
/// arms, so nothing the loop is in the middle of can hold the collector — and
/// with it every subscriber's channel sender — past a stop. Dropping the loop
/// drops the live [`WatchSession`], which releases the OS watch.
pub async fn run_watch_collector(
    roots: Vec<PathBuf>,
    recursive: bool,
    workload_id: WorkloadId,
    source: Arc<dyn WatchSource>,
    cmd_rx: mpsc::Receiver<CollectorCommand>,
    stop: CancellationToken,
) {
    debug!(workload_id, recursive, "watch collector started");
    tokio::select! {
        biased;
        () = stop.cancelled() => {}
        () = collect(roots, recursive, workload_id, source, cmd_rx) => {}
    }
    debug!(workload_id, "watch collector stopped");
}

/// The collector loop proper; returns when the command channel closes.
async fn collect(
    roots: Vec<PathBuf>,
    recursive: bool,
    workload_id: WorkloadId,
    source: Arc<dyn WatchSource>,
    mut cmd_rx: mpsc::Receiver<CollectorCommand>,
) {
    let mut snapshot = WatchSnapshot {
        roots: roots
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        recursive,
        // Coverage is unknown until the first establishment; it's stamped (and
        // resynced to subscribers) once `source.start()` reports it.
        coverage: WatchCoverage::Unknown,
    };
    let mut subs: Vec<Subscriber> = Vec::new();
    // The active OS watch, `Some` only while there are subscribers.
    let mut session: Option<WatchSession> = None;
    // When the last `source.start()` was attempted, to rate-limit retries on a
    // persistently unwatchable path (`None` once a watch is live — so a dropped
    // watch reconnects immediately, only repeated failures back off).
    let mut last_start_attempt: Option<tokio::time::Instant> = None;
    // Running blind-spot total on the live watch: the establishment baseline plus
    // any live re-watch degradations. Reset on idle and on each re-establishment;
    // folded into `coverage` monotonically (a live re-watch only adds blind spots,
    // so recovery to Complete waits for a fresh establishment).
    let mut current_unwatched: u32 = 0;
    let mut buf: Vec<WatchEvent> = Vec::new();
    let mut flush = tokio::time::interval(WATCH_FLUSH_INTERVAL);
    flush.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        if subs.is_empty() {
            // Idle: drop the OS watch (releases descriptors) and wait. Coverage
            // is no longer known — the next subscriber re-establishes it.
            if session.is_some() {
                session = None;
                buf.clear();
                snapshot.coverage = WatchCoverage::Unknown;
                current_unwatched = 0;
            }
            match cmd_rx.recv().await {
                Some(c) => handle_cmd(c, &mut subs, &snapshot, workload_id),
                None => break,
            }
        } else {
            // Ensure the watch is live; on failure log loudly and retry, but
            // rate-limited (see WATCH_START_RETRY_INTERVAL) so a persistently
            // unwatchable path doesn't re-attempt + warn on every flush tick.
            if session.is_none()
                && last_start_attempt.is_none_or(|t| t.elapsed() >= WATCH_START_RETRY_INTERVAL)
            {
                last_start_attempt = Some(tokio::time::Instant::now());
                match source.start(&roots, recursive) {
                    Ok(s) => {
                        // Stamp the established coverage; if it changed, push a
                        // coverage frame so subscribers learn it (no event gap).
                        // Seed the running blind-spot total from this baseline —
                        // live degradations add to it until the next establishment.
                        set_coverage(&mut snapshot, &mut subs, s.coverage, workload_id);
                        current_unwatched = unwatched_count(s.coverage);
                        session = Some(s);
                        last_start_attempt = None; // live again — reconnect promptly if it drops
                    }
                    Err(err) => {
                        // The watch is dark; tell subscribers (not just the log).
                        set_coverage(
                            &mut snapshot,
                            &mut subs,
                            WatchCoverage::Unavailable,
                            workload_id,
                        );
                        warn!(
                            workload_id,
                            error = %fuz_sys::cli::format_error_chain(&err),
                            hint = err.hint().unwrap_or("paths missing — nothing to watch"),
                            "watch source failed to start; retrying"
                        );
                    }
                }
            }
            // Select over the (possibly absent) session — its event stream and its
            // coverage-degradation channel — in one borrow, so the other select
            // arms don't conflict on `session`. The two are disjoint fields of the
            // same session, so the inner select borrows them independently.
            let recv_session = async {
                match session.as_mut() {
                    Some(s) => {
                        tokio::select! {
                            ev = s.events.recv() => SessionMsg::Event(ev),
                            deg = s.coverage_degradations.recv() => SessionMsg::Degradation(deg),
                        }
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                msg = recv_session => match msg {
                    SessionMsg::Event(Some(ev)) => {
                        buf.push(ev);
                        if buf.len() >= WATCH_BUFFER_CAP {
                            // Overflow: drop the batch + resync everyone.
                            buf.clear();
                            flag_all_for_resync(&mut subs);
                            fanout(&mut subs, &[], &snapshot, workload_id, FRAME_BODY_BUDGET);
                        }
                    }
                    // Backend thread ended (e.g. start failed earlier) — retry.
                    SessionMsg::Event(None) => session = None,
                    // A live re-watch left new blind spots: fold the count into the
                    // running total and push the degraded coverage (no event gap).
                    SessionMsg::Degradation(Some(extra)) => {
                        current_unwatched = current_unwatched.saturating_add(extra);
                        set_coverage(
                            &mut snapshot,
                            &mut subs,
                            coverage_from_unwatched(current_unwatched),
                            workload_id,
                        );
                    }
                    // Degradation channel closed (watch thread gone); the event
                    // arm's `None` drives the session reset.
                    SessionMsg::Degradation(None) => {}
                },
                _ = flush.tick() => {
                    if !buf.is_empty() || subs.iter().any(|s| s.needs_resync) {
                        fanout(&mut subs, &buf, &snapshot, workload_id, FRAME_BODY_BUDGET);
                        buf.clear();
                    }
                },
                cmd = cmd_rx.recv() => match cmd {
                    Some(c) => handle_cmd(c, &mut subs, &snapshot, workload_id),
                    None => break,
                },
            }
        }
    }
}

fn handle_cmd(
    cmd: CollectorCommand,
    subs: &mut Vec<Subscriber>,
    snapshot: &WatchSnapshot,
    workload_id: WorkloadId,
) {
    match cmd {
        CollectorCommand::AddSubscriber {
            conn_id,
            request_id,
            out_tx,
        } => {
            // A new subscriber is whole immediately: send the watch snapshot
            // (the roots — its fs region) before any events flow.
            let frames = snapshot_frames(snapshot, workload_id, FRAME_BODY_BUDGET);
            // Never await room: a backed-up connection joins flagged for resync
            // and gets its snapshot on the next flush instead.
            add_subscriber(subs, conn_id, request_id, out_tx, frames.as_deref());
        }
        CollectorCommand::RemoveSubscriber {
            conn_id,
            request_id,
        } => remove_subscriber(subs, conn_id, request_id),
        CollectorCommand::DropConnection { conn_id } => drop_connection(subs, conn_id),
    }
}

/// Fan one coalesced event batch out to every subscriber. A subscriber flagged
/// `needs_resync` gets a fresh snapshot instead; on a full channel we drop the
/// frame and flag resync (never a silent gap the consumer can't detect).
///
/// The batch goes out in as many event frames as `budget` needs (a flush holds
/// up to [`WATCH_BUFFER_CAP`] paths, none of them bounded). An event whose path
/// is too long for a frame on its own cannot reach the consumer, so it is
/// logged and every subscriber resyncs — the gap signal — instead of reading a
/// batch that lacks it.
fn fanout(
    subs: &mut Vec<Subscriber>,
    events: &[WatchEvent],
    snapshot: &WatchSnapshot,
    workload_id: WorkloadId,
    budget: usize,
) {
    let mut event_frames: Vec<EncodedFrame> = Vec::new();
    if !events.is_empty() {
        match split_encode(
            WatcherEventFrame {
                events: events.to_vec(),
            },
            budget,
            split_event_frame,
        ) {
            Ok(split) => {
                if split.dropped > 0 {
                    warn!(
                        workload_id,
                        dropped = split.dropped,
                        "watch events too large for a frame were left out; resyncing subscribers"
                    );
                    flag_all_for_resync(subs);
                }
                event_frames.extend(
                    split
                        .bodies
                        .into_iter()
                        .map(|body| (ids::WATCHER_EVENT_FRAME, body)),
                );
            }
            Err(err) => {
                warn!(
                    error = %fuz_sys::cli::format_error_chain(&err),
                    "encode watch event frame failed; resyncing subscribers"
                );
                flag_all_for_resync(subs);
            }
        }
    }
    let snapshot_frames = if subs.iter().any(|s| s.needs_resync) {
        snapshot_frames(snapshot, workload_id, budget)
    } else {
        None
    };

    let mut closed: Vec<usize> = Vec::new();
    for (idx, sub) in subs.iter_mut().enumerate() {
        match send_resync_snapshot(sub, snapshot_frames.as_deref()) {
            ResyncOutcome::NotFlagged => {}
            ResyncOutcome::Handled => continue,
            ResyncOutcome::Closed => {
                closed.push(idx);
                continue;
            }
        }
        match try_send_frames(&sub.out_tx, sub.request_id, &event_frames) {
            Ok(()) => {}
            Err(TrySendError::Full(())) => sub.needs_resync = true,
            Err(TrySendError::Closed(())) => closed.push(idx),
        }
    }
    drop_closed(subs, closed);
}

/// Encode the watch snapshot as its one frame, or `None` (logged) when it
/// cannot be encoded or does not fit `budget`. The roots it echoes are the
/// subscriber's own, and a subscribe whose roots could not fit is refused
/// before it reaches a collector, so the second case is a backstop. The caller
/// leaves its subscribers flagged for the next pass.
///
/// A watch snapshot is never split: it is one frame or refused, so unlike the
/// observer's it needs no continuation count.
fn snapshot_frames(
    snapshot: &WatchSnapshot,
    workload_id: WorkloadId,
    budget: usize,
) -> Option<Vec<EncodedFrame>> {
    let body = encode_payload(&WatcherSnapshotFrame {
        workload_id,
        snapshot: snapshot.clone(),
    })
    .map_err(|err| {
        warn!(
            error = %fuz_sys::cli::format_error_chain(&err),
            "encode watch snapshot frame failed"
        );
    })
    .ok()?;
    if body.len() > budget {
        warn!(
            workload_id,
            len = body.len(),
            "watch snapshot does not fit a frame; its roots are too long"
        );
        return None;
    }
    Some(vec![(ids::WATCHER_SNAPSHOT_FRAME, body)])
}

/// Halve an event frame, keeping the events' order. The split for
/// [`split_encode`].
fn split_event_frame(
    frame: WatcherEventFrame,
) -> Result<(WatcherEventFrame, WatcherEventFrame), WatcherEventFrame> {
    split_vec(frame.events)
        .map(|(first, second)| {
            (
                WatcherEventFrame { events: first },
                WatcherEventFrame { events: second },
            )
        })
        .map_err(|events| WatcherEventFrame { events })
}

/// Flag every subscriber for resync — its next frame becomes a fresh snapshot
/// (the gap signal) instead of an incremental event batch.
fn flag_all_for_resync(subs: &mut [Subscriber]) {
    for sub in subs {
        sub.needs_resync = true;
    }
}

/// Update the snapshot's coverage and, on a change, push a [`WatcherCoverageFrame`]
/// to every subscriber — a label update with **no event gap**, decoupled from the
/// snapshot/resync frame.
///
/// The new value is always stored (so late joiners get it in their first
/// snapshot) and every transition is pushed: a clean establishment's
/// `Unknown → Complete`, a partial establishment, a post-establishment
/// degradation, and a recovery. Because the coverage frame carries no gap, the
/// consumer applies it in place without re-baselining its fs region (no dropped
/// first event batch, which is what riding a snapshot resync would cost).
/// Unchanged coverage is a no-op, so a stable watch never churns.
fn set_coverage(
    snapshot: &mut WatchSnapshot,
    subs: &mut Vec<Subscriber>,
    coverage: WatchCoverage,
    workload_id: WorkloadId,
) {
    if snapshot.coverage == coverage {
        return;
    }
    snapshot.coverage = coverage;
    fanout_coverage(subs, coverage, workload_id);
}

/// Push a coverage-only frame to every subscriber (no event gap). On a full
/// per-connection channel we fall back to flagging resync — the resync snapshot
/// carries the current coverage anyway, so the update still lands — and a closed
/// channel drops the subscriber. A subscriber already flagged is skipped for the
/// same reason: its next frame must be that snapshot (for one that joined while
/// its channel was full, its *first* frame), never a coverage label ahead of it.
fn fanout_coverage(subs: &mut Vec<Subscriber>, coverage: WatchCoverage, workload_id: WorkloadId) {
    let body = match encode_payload(&WatcherCoverageFrame {
        workload_id,
        coverage,
    }) {
        Ok(body) => body,
        Err(err) => {
            // Unreachable for this tiny POD; flag resync so the coverage still
            // reaches subscribers via the next snapshot frame.
            warn!(
                error = %fuz_sys::cli::format_error_chain(&err),
                "encode watch coverage frame failed"
            );
            flag_all_for_resync(subs);
            return;
        }
    };
    let mut closed: Vec<usize> = Vec::new();
    for (idx, sub) in subs.iter_mut().enumerate() {
        if sub.needs_resync {
            continue;
        }
        match sub.out_tx.try_send(out_frame(
            sub.request_id,
            ids::WATCHER_COVERAGE_FRAME,
            body.clone(),
        )) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => sub.needs_resync = true,
            Err(TrySendError::Closed(_)) => closed.push(idx),
        }
    }
    drop_closed(subs, closed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::out::OutFrame;
    use crate::workload::collector::{COLLECTOR_CMD_CAP, full_out_channel, send_add_subscriber};
    use crate::workload::watch_source::{WatchError, WatchGuard};
    use fuz_wire::FrameFlags;
    use fuz_wire::{WatchEventKind, WatcherCoverageFrame, WatcherEventFrame};
    use std::sync::Mutex;

    fn event(path: &str, kind: WatchEventKind) -> WatchEvent {
        WatchEvent {
            path: path.to_owned(),
            kind,
        }
    }

    /// A test double whose `start` returns a session pre-loaded with `seed`
    /// events and reporting `coverage`; it keeps each sender alive (in `senders`)
    /// so the channel stays open for the collector's whole run, and exposes each
    /// session's degradation sender (in `degradations`) so a test can simulate a
    /// live-re-watch blind spot.
    #[derive(Debug)]
    struct MockWatchSource {
        seed: Vec<WatchEvent>,
        coverage: WatchCoverage,
        senders: Mutex<Vec<mpsc::UnboundedSender<WatchEvent>>>,
        degradations: Mutex<Vec<mpsc::UnboundedSender<u32>>>,
    }

    impl MockWatchSource {
        fn new(seed: Vec<WatchEvent>) -> Self {
            Self {
                seed,
                coverage: WatchCoverage::Complete,
                senders: Mutex::new(Vec::new()),
                degradations: Mutex::new(Vec::new()),
            }
        }

        /// Emit one filesystem event on the most-recent session.
        fn emit(&self, ev: WatchEvent) {
            if let Some(tx) = self.senders.lock().unwrap().last() {
                let _ = tx.send(ev);
            }
        }

        /// Report a live-re-watch degradation of `unwatched` blind-spot subtrees
        /// on the most-recent session — the collector folds it into coverage.
        fn degrade(&self, unwatched: u32) {
            if let Some(tx) = self.degradations.lock().unwrap().last() {
                let _ = tx.send(unwatched);
            }
        }
    }

    impl WatchSource for MockWatchSource {
        fn start(&self, _roots: &[PathBuf], _recursive: bool) -> Result<WatchSession, WatchError> {
            let (tx, rx) = mpsc::unbounded_channel();
            for ev in &self.seed {
                let _ = tx.send(ev.clone());
            }
            self.senders.lock().unwrap().push(tx);
            let (deg_tx, deg_rx) = mpsc::unbounded_channel();
            self.degradations.lock().unwrap().push(deg_tx);
            Ok(WatchSession {
                events: rx,
                guard: WatchGuard::detached(),
                coverage: self.coverage,
                coverage_degradations: deg_rx,
            })
        }
    }

    #[test]
    fn full_channel_flags_resync_then_sends_snapshot() {
        // Resync-over-drop for events: a full subscriber channel drops the event
        // frame and resyncs with a snapshot, never a silent gap.
        let snapshot = WatchSnapshot {
            roots: vec!["/w".to_owned()],
            recursive: true,
            coverage: WatchCoverage::Complete,
        };
        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(1);
        out_tx
            .try_send(OutFrame {
                request_id: 1,
                action: ids::WATCHER_EVENT_FRAME,
                flags: FrameFlags::EMPTY,
                body: vec![],
            })
            .expect("prefill the channel");
        let mut subs = vec![Subscriber {
            conn_id: 1,
            request_id: 1,
            out_tx,
            needs_resync: false,
        }];

        // Event batch can't be sent (full) → dropped + flagged for resync.
        fanout(
            &mut subs,
            &[event("/w/a", WatchEventKind::Created)],
            &snapshot,
            7,
            FRAME_BODY_BUDGET,
        );
        assert!(
            subs[0].needs_resync,
            "full channel flags resync, drops the batch"
        );

        // Make room, fan out again: the subscriber resyncs with a snapshot.
        out_rx.try_recv().expect("drain the prefill");
        fanout(
            &mut subs,
            &[event("/w/b", WatchEventKind::Modified)],
            &snapshot,
            7,
            FRAME_BODY_BUDGET,
        );
        assert!(
            !subs[0].needs_resync,
            "resync clears once the snapshot is sent"
        );
        let frame = out_rx.try_recv().expect("a frame was sent");
        assert_eq!(
            frame.action,
            ids::WATCHER_SNAPSHOT_FRAME,
            "resync sends a snapshot, not events"
        );
    }

    #[test]
    fn buffer_overflow_resync_supersedes_pending_events() {
        // The buffer-cap overflow branch (`buf.len() >= WATCH_BUFFER_CAP`) drops
        // the whole batch and `flag_all_for_resync`s *every* subscriber, so each
        // next frame is a fresh snapshot (the gap signal) rather than a
        // misleading partial batch. Flooding 4096 events through the live
        // collector to trip the literal cap is racy (a flush tick drains the
        // buffer first), so this pins the branch's *effect* as a unit:
        // flag-all-then-fanout sends a SNAPSHOT to every subscriber — even with a
        // non-empty event batch pending — and clears the flag. (The sibling
        // `full_channel_flags_resync_then_sends_snapshot` covers the per-sub
        // full-channel path; this covers the all-subscribers overflow flagging.)
        let snapshot = WatchSnapshot {
            roots: vec!["/w".to_owned()],
            recursive: true,
            coverage: WatchCoverage::Complete,
        };
        let (tx_a, mut rx_a) = mpsc::channel::<OutFrame>(4);
        let (tx_b, mut rx_b) = mpsc::channel::<OutFrame>(4);
        let mut subs = vec![
            Subscriber {
                conn_id: 1,
                request_id: 1,
                out_tx: tx_a,
                needs_resync: false,
            },
            Subscriber {
                conn_id: 2,
                request_id: 2,
                out_tx: tx_b,
                needs_resync: false,
            },
        ];

        flag_all_for_resync(&mut subs);
        assert!(
            subs.iter().all(|s| s.needs_resync),
            "every subscriber is flagged on overflow"
        );

        // A non-empty batch is pending, but the resync flag supersedes it.
        fanout(
            &mut subs,
            &[event("/w/a", WatchEventKind::Created)],
            &snapshot,
            9,
            FRAME_BODY_BUDGET,
        );

        assert!(
            subs.iter().all(|s| !s.needs_resync),
            "resync clears once the snapshots are sent"
        );
        for rx in [&mut rx_a, &mut rx_b] {
            let frame = rx.try_recv().expect("a frame was sent to each subscriber");
            assert_eq!(
                frame.action,
                ids::WATCHER_SNAPSHOT_FRAME,
                "overflow resync sends a snapshot, not the dropped batch"
            );
            assert!(
                rx.try_recv().is_err(),
                "exactly one (snapshot) frame per subscriber — the batch is dropped"
            );
        }
    }

    #[tokio::test]
    async fn collector_streams_snapshot_then_events() {
        let source: Arc<dyn WatchSource> = Arc::new(MockWatchSource::new(vec![
            event("/w/src/main.rs", WatchEventKind::Modified),
            event("/w/src/new.rs", WatchEventKind::Created),
        ]));
        let (cmd_tx, cmd_rx) = mpsc::channel(COLLECTOR_CMD_CAP);
        let stop = CancellationToken::new();
        let handle = tokio::spawn(run_watch_collector(
            vec![PathBuf::from("/w")],
            true,
            7,
            source,
            cmd_rx,
            stop.clone(),
        ));

        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(16);
        cmd_tx
            .send(CollectorCommand::AddSubscriber {
                conn_id: 1,
                request_id: 99,
                out_tx,
            })
            .await
            .expect("send add");

        // First frame: the watch snapshot on the subscribe request_id, not FINAL.
        let frame = out_rx.recv().await.expect("snapshot frame");
        assert_eq!(frame.request_id, 99);
        assert_eq!(frame.action, ids::WATCHER_SNAPSHOT_FRAME);
        assert!(!frame.flags.is_final(), "stream frames are not FINAL");
        let snap: WatcherSnapshotFrame = fuz_wire::decode_payload(&frame.body).expect("decode");
        assert_eq!(snap.workload_id, 7);
        assert_eq!(snap.snapshot.roots, vec!["/w".to_owned()]);

        // Then the establishment coverage frame: a clean watch confirms
        // `Unknown → Complete` (pushed, not suppressed — it rides a coverage frame,
        // not a disruptive snapshot resync, so it costs no event drop).
        let frame = out_rx.recv().await.expect("coverage frame");
        assert_eq!(
            frame.action,
            ids::WATCHER_COVERAGE_FRAME,
            "establishment confirms Complete"
        );
        let cov: WatcherCoverageFrame = fuz_wire::decode_payload(&frame.body).expect("decode");
        assert_eq!(cov.coverage, WatchCoverage::Complete);

        // Then a coalesced event frame (the two seeded events, after one flush).
        let frame = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("event frame in time")
            .expect("event frame");
        assert_eq!(frame.action, ids::WATCHER_EVENT_FRAME);
        let events: WatcherEventFrame = fuz_wire::decode_payload(&frame.body).expect("decode");
        assert_eq!(
            events.events.len(),
            2,
            "both seeded events coalesced into one frame"
        );

        stop.cancel();
        handle.await.expect("collector joins");
    }

    #[tokio::test]
    async fn collector_pushes_coverage_frame_when_establishment_is_partial() {
        // A partial establishment (blind spots) is surfaced to the subscriber as a
        // dedicated coverage frame carrying Partial — a label update with no event
        // gap (not a snapshot resync), and not just a daemon-log warn.
        let source: Arc<dyn WatchSource> = Arc::new(MockWatchSource {
            seed: Vec::new(),
            coverage: WatchCoverage::Partial { unwatched: 3 },
            senders: Mutex::new(Vec::new()),
            degradations: Mutex::new(Vec::new()),
        });
        let (cmd_tx, cmd_rx) = mpsc::channel(COLLECTOR_CMD_CAP);
        let stop = CancellationToken::new();
        let handle = tokio::spawn(run_watch_collector(
            vec![PathBuf::from("/w")],
            true,
            7,
            source,
            cmd_rx,
            stop.clone(),
        ));

        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(16);
        cmd_tx
            .send(CollectorCommand::AddSubscriber {
                conn_id: 1,
                request_id: 99,
                out_tx,
            })
            .await
            .expect("send add");

        // First frame: the snapshot, coverage not yet known (establishment hasn't run).
        let frame = out_rx.recv().await.expect("first snapshot");
        assert_eq!(frame.action, ids::WATCHER_SNAPSHOT_FRAME);
        let snap: WatcherSnapshotFrame = fuz_wire::decode_payload(&frame.body).expect("decode");
        assert_eq!(
            snap.snapshot.coverage,
            WatchCoverage::Unknown,
            "coverage unknown pre-establish"
        );

        // Then a dedicated coverage frame (not a snapshot resync): now Partial.
        let frame = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("coverage frame in time")
            .expect("coverage frame");
        assert_eq!(
            frame.action,
            ids::WATCHER_COVERAGE_FRAME,
            "a coverage change rides a coverage frame, not a snapshot resync"
        );
        let cov: WatcherCoverageFrame = fuz_wire::decode_payload(&frame.body).expect("decode");
        assert_eq!(
            cov.coverage,
            WatchCoverage::Partial { unwatched: 3 },
            "the partial coverage is surfaced to the subscriber"
        );

        stop.cancel();
        handle.await.expect("collector joins");
    }

    #[tokio::test]
    async fn collector_folds_live_rewatch_degradation_into_coverage() {
        // A live re-watch that drops dirs (a *post-establishment* blind spot)
        // reaches the collector via the degradation channel and degrades
        // `coverage` — not just the daemon log. The mock establishes Complete,
        // then reports a degradation of 2 blind-spot subtrees.
        let source = Arc::new(MockWatchSource::new(Vec::new()));
        // A concrete clone for the collector; the function-argument coercion site
        // unsizes it to `Arc<dyn WatchSource>` (no cast). `source` stays for `degrade`.
        let collector_source: Arc<MockWatchSource> = Arc::clone(&source);
        let (cmd_tx, cmd_rx) = mpsc::channel(COLLECTOR_CMD_CAP);
        let stop = CancellationToken::new();
        let handle = tokio::spawn(run_watch_collector(
            vec![PathBuf::from("/w")],
            true,
            7,
            collector_source,
            cmd_rx,
            stop.clone(),
        ));

        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(16);
        cmd_tx
            .send(CollectorCommand::AddSubscriber {
                conn_id: 1,
                request_id: 99,
                out_tx,
            })
            .await
            .expect("send add");

        // Snapshot first, then the establishment coverage frame (clean → Complete).
        let frame = out_rx.recv().await.expect("snapshot");
        assert_eq!(frame.action, ids::WATCHER_SNAPSHOT_FRAME);
        let frame = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("establishment coverage in time")
            .expect("establishment coverage frame");
        assert_eq!(frame.action, ids::WATCHER_COVERAGE_FRAME);
        let cov: WatcherCoverageFrame = fuz_wire::decode_payload(&frame.body).expect("decode");
        assert_eq!(
            cov.coverage,
            WatchCoverage::Complete,
            "clean establishment confirms Complete"
        );

        // A live re-watch drops 2 subtrees → coverage degrades to Partial { 2 }.
        source.degrade(2);
        let frame = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("degraded coverage in time")
            .expect("degraded coverage frame");
        assert_eq!(
            frame.action,
            ids::WATCHER_COVERAGE_FRAME,
            "degradation rides a coverage frame"
        );
        let cov: WatcherCoverageFrame = fuz_wire::decode_payload(&frame.body).expect("decode");
        assert_eq!(
            cov.coverage,
            WatchCoverage::Partial { unwatched: 2 },
            "the live-re-watch degradation folded into coverage"
        );

        stop.cancel();
        handle.await.expect("collector joins");
    }

    #[test]
    fn coverage_change_skips_a_subscriber_owed_a_snapshot() {
        // A flagged subscriber's next frame is its resync snapshot — which
        // carries the current coverage — so a coverage frame must not jump the
        // queue. For one that joined backed up, that snapshot is its first frame.
        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(4);
        let mut subs = vec![Subscriber {
            conn_id: 1,
            request_id: 1,
            out_tx,
            needs_resync: true,
        }];
        fanout_coverage(&mut subs, WatchCoverage::Complete, 7);
        assert!(
            out_rx.try_recv().is_err(),
            "no coverage frame ahead of the snapshot"
        );
        assert!(subs[0].needs_resync, "still owed its snapshot");

        let snapshot = WatchSnapshot {
            roots: vec!["/w".to_owned()],
            recursive: true,
            coverage: WatchCoverage::Complete,
        };
        fanout(&mut subs, &[], &snapshot, 7, FRAME_BODY_BUDGET);
        let frame = out_rx.try_recv().expect("the resync snapshot");
        assert_eq!(frame.action, ids::WATCHER_SNAPSHOT_FRAME);
    }

    /// Spawn a collector over `source` watching `/w`; returns the command
    /// sender, the stop token, and the join handle.
    fn spawn_watch_collector(
        source: Arc<dyn WatchSource>,
    ) -> (
        mpsc::Sender<CollectorCommand>,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel(COLLECTOR_CMD_CAP);
        let stop = CancellationToken::new();
        let handle = tokio::spawn(run_watch_collector(
            vec![PathBuf::from("/w")],
            true,
            7,
            source,
            cmd_rx,
            stop.clone(),
        ));
        (cmd_tx, stop, handle)
    }

    #[tokio::test]
    async fn a_stuck_subscriber_does_not_hold_up_another_subscribers_frames() {
        // One collector serves every subscriber, so it must never wait on one:
        // a subscriber joining with a full channel (a client that stopped
        // reading) leaves the next flush's events reaching the healthy one.
        let source = Arc::new(MockWatchSource::new(Vec::new()));
        let collector_source: Arc<MockWatchSource> = Arc::clone(&source);
        let (cmd_tx, stop, handle) = spawn_watch_collector(collector_source);
        let (healthy_tx, mut healthy_rx) = mpsc::channel::<OutFrame>(16);
        send_add_subscriber(&cmd_tx, 1, healthy_tx).await;
        let frame = healthy_rx.recv().await.expect("healthy snapshot");
        assert_eq!(frame.action, ids::WATCHER_SNAPSHOT_FRAME);
        let frame = healthy_rx.recv().await.expect("establishment coverage");
        assert_eq!(frame.action, ids::WATCHER_COVERAGE_FRAME);

        let (stuck_tx, mut stuck_rx) = full_out_channel();
        send_add_subscriber(&cmd_tx, 2, stuck_tx).await;
        source.emit(event("/w/a", WatchEventKind::Created));

        let frame = tokio::time::timeout(WATCH_FLUSH_INTERVAL * 4, healthy_rx.recv())
            .await
            .expect("the healthy subscriber's events arrived despite the stuck one")
            .expect("event frame");
        assert_eq!(frame.action, ids::WATCHER_EVENT_FRAME);

        // Once the stuck client reads again, its first frame is a snapshot.
        stuck_rx.recv().await.expect("the prefill");
        let frame = tokio::time::timeout(WATCH_FLUSH_INTERVAL * 4, stuck_rx.recv())
            .await
            .expect("the late snapshot in time")
            .expect("snapshot frame");
        assert_eq!(
            frame.action,
            ids::WATCHER_SNAPSHOT_FRAME,
            "a subscriber that joined backed up still starts on a snapshot"
        );
        assert_eq!(frame.request_id, 99);

        stop.cancel();
        handle.await.expect("collector joins");
    }

    #[tokio::test]
    async fn stop_ends_the_collector_promptly_with_a_stuck_subscriber() {
        let (cmd_tx, stop, handle) =
            spawn_watch_collector(Arc::new(MockWatchSource::new(Vec::new())));
        let (stuck_tx, _stuck_rx) = full_out_channel();
        send_add_subscriber(&cmd_tx, 1, stuck_tx).await;
        // Let the collector take the command before stopping it.
        tokio::time::sleep(Duration::from_millis(50)).await;

        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("the collector exits on stop despite a stuck subscriber")
            .expect("collector joins");
    }

    fn subscriber(out_tx: crate::out::OutTx) -> Subscriber {
        Subscriber {
            conn_id: 1,
            request_id: 1,
            out_tx,
            needs_resync: false,
        }
    }

    fn watch_snapshot() -> WatchSnapshot {
        WatchSnapshot {
            roots: vec!["/w".to_owned()],
            recursive: true,
            coverage: WatchCoverage::Complete,
        }
    }

    #[test]
    fn a_full_flush_of_long_paths_goes_out_in_frames_within_the_limit() {
        // A full buffer of 4 KiB paths is more than one frame holds: it goes out
        // as several event frames, each within the limit, every event once and
        // in order.
        let events: Vec<WatchEvent> = (0..WATCH_BUFFER_CAP)
            .map(|i| {
                event(
                    &format!("/w/{i:05}/{}", "p".repeat(4096)),
                    WatchEventKind::Modified,
                )
            })
            .collect();
        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(64);
        let mut subs = vec![subscriber(out_tx)];
        fanout(&mut subs, &events, &watch_snapshot(), 7, FRAME_BODY_BUDGET);
        assert!(!subs[0].needs_resync, "nothing was dropped");
        let mut seen = Vec::new();
        let mut frames = 0;
        while let Ok(frame) = out_rx.try_recv() {
            assert_eq!(frame.action, ids::WATCHER_EVENT_FRAME);
            assert!(
                frame.body.len() <= FRAME_BODY_BUDGET,
                "{}",
                frame.body.len()
            );
            let batch: WatcherEventFrame = fuz_wire::decode_payload(&frame.body).unwrap();
            seen.extend(batch.events.into_iter().map(|e| e.path));
            frames += 1;
        }
        assert!(frames > 1, "{frames} frames");
        let expected: Vec<String> = events.into_iter().map(|e| e.path).collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn an_event_too_large_for_a_frame_resyncs_instead_of_leaving_a_silent_gap() {
        let budget = 512;
        let events = [
            event("/w/a", WatchEventKind::Created),
            event(
                &format!("/w/{}", "q".repeat(budget)),
                WatchEventKind::Created,
            ),
        ];
        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(8);
        let mut subs = vec![subscriber(out_tx)];
        fanout(&mut subs, &events, &watch_snapshot(), 7, budget);
        let frame = out_rx.try_recv().expect("a frame");
        assert_eq!(
            frame.action,
            ids::WATCHER_SNAPSHOT_FRAME,
            "the gap signal, not a batch missing an event"
        );
        assert!(out_rx.try_recv().is_err(), "no partial batch after it");
        assert!(!subs[0].needs_resync, "the resync went out");
    }
}
