//! Fuz daemon client library.
//!
//! Async client for communicating with the Fuz daemon over its Unix
//! domain socket. Every public function opens a fresh `UnixStream` and
//! begins with the Hello handshake; from there the surface splits in two.
//!
//! **One-shot calls** — `check_health`, `daemon_status`, `shutdown` — do a
//! single action round-trip and close.
//!
//! **Subscriptions** — `observe_subscribe` / `watch_subscribe` and their
//! `_at` forms — write one subscribe request and then hold the connection
//! open, delivering frames on that request id to the caller's callback.
//! With `follow == false` they return after the first snapshot; with
//! `follow == true` they stream until the daemon closes the connection.
//! Subscription frames carry no `FINAL` flag, so the stream is unbounded and
//! ends only with the connection. A stream that ends before its first
//! snapshot is an error ([`ClientError::StreamEndedBeforeSnapshot`]), never an
//! empty success.

mod error;

pub use error::ClientError;

pub use fuz_home::DaemonInfo;
use fuz_home::get_socket_path;
use fuz_wire::{
    Action, ActionId, DaemonShutdownRequest, DaemonShutdownResponse, DaemonStatusRequest,
    HelloOutcome, HelloRequest, HelloResponse, MAX_FRAME, ObserverDeltaFrame, ObserverDomain,
    ObserverEventFrame, ObserverSnapshotFrame, ObserverSubscribeRequest, PROTOCOL_VERSION,
    ProtoError, WatcherCoverageFrame, WatcherEventFrame, WatcherSnapshotFrame,
    WatcherSubscribeRefused, WatcherSubscribeRequest, ids, read_frame, write_frame,
};
pub use fuz_wire::{
    DaemonStatusResponse, ObserverDelta, ObserverEvent, ObserverSnapshot, SidecarStatus,
    SidecarStatusInfo, WatchCoverage, WatchEvent, WatchSnapshot, WorkloadId,
};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::time::timeout;

/// Per-call round-trip timeout. UDS is local, so this is "abandon the
/// daemon and fail fast" rather than the network-friendly multi-second
/// budgets HTTP needed.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Health-check round-trip is much shorter — a hung daemon should not
/// block CLI start probes.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_millis(500);

//
// Connection plumbing
//

fn socket_path() -> Result<PathBuf, ClientError> {
    Ok(get_socket_path()?)
}

async fn dial(path: &Path) -> Result<UnixStream, ClientError> {
    match UnixStream::connect(path).await {
        Ok(s) => Ok(s),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(ClientError::DaemonNotRunning {
            path: path.display().to_string(),
        }),
        Err(err) => Err(ClientError::Connect {
            path: path.display().to_string(),
            source: err,
        }),
    }
}

/// Generic request/response over a UDS stream. One write, one read,
/// `action_id` checked against the expected response variant.
async fn request_response<Req, Resp>(
    stream: &mut UnixStream,
    request_id: u32,
    req: &Req,
    expected_id: ActionId,
) -> Result<Resp, ClientError>
where
    Req: Action + Sync,
    Resp: Action,
{
    write_frame(stream, request_id, req, MAX_FRAME).await?;
    let (header, body) = match timeout(REQUEST_TIMEOUT, read_frame(stream, MAX_FRAME)).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(ClientError::Connect {
                path: "uds".to_string(),
                source: io::Error::new(io::ErrorKind::TimedOut, "request timeout"),
            });
        }
    };
    if header.action != expected_id {
        return Err(ClientError::UnexpectedAction {
            expected: expected_id,
            got: header.action,
        });
    }
    let resp: Resp = fuz_wire::decode_payload(&body)?;
    Ok(resp)
}

/// Run the `PROTOCOL_VERSION` handshake. Every connection starts with
/// one of these — mismatched versions surface as a clear error rather
/// than a silent later decode failure.
async fn hello(stream: &mut UnixStream) -> Result<(), ClientError> {
    let req = HelloRequest {
        protocol_version: PROTOCOL_VERSION,
    };
    let resp: HelloResponse = request_response(stream, 1, &req, ids::HELLO_RESPONSE).await?;
    match resp.outcome {
        HelloOutcome::Ok => Ok(()),
        // The frame's `ours` is the *server's* version (`theirs` echoes this
        // client's own back) — report that as the daemon's, not our echo.
        HelloOutcome::VersionMismatch { ours, theirs: _ } => Err(ClientError::ProtocolMismatch {
            ours: PROTOCOL_VERSION,
            theirs: ours,
        }),
    }
}

/// Open a fresh connection and complete the Hello handshake.
async fn dial_and_hello() -> Result<UnixStream, ClientError> {
    let path = socket_path()?;
    dial_and_hello_at(&path).await
}

/// Open a fresh connection to `path` and complete the Hello handshake.
///
/// The path-explicit form behind [`dial_and_hello`]; callers that need to
/// reach a non-canonical socket (a long-lived consumer pointed at an
/// isolated daemon, e.g. tests) use this directly.
async fn dial_and_hello_at(path: &Path) -> Result<UnixStream, ClientError> {
    let mut stream = dial(path).await?;
    hello(&mut stream).await?;
    Ok(stream)
}

//
// Health check
//

/// Decide health from one Hello response frame: the action must be
/// `HELLO_RESPONSE`, the payload must decode, and the outcome must be
/// [`HelloOutcome::Ok`] — a version-mismatched daemon is alive but unusable,
/// so it does not count as healthy.
///
/// Lifted out of [`check_health`] so the decision is unit-testable without a
/// live daemon, the same shape as the `dispatch_*_frame` helpers below.
fn hello_frame_is_healthy(action: ActionId, body: &[u8]) -> bool {
    if action != ids::HELLO_RESPONSE {
        return false;
    }
    let Ok(resp): Result<HelloResponse, _> = fuz_wire::decode_payload(body) else {
        return false;
    };
    matches!(resp.outcome, HelloOutcome::Ok)
}

/// Is the daemon alive and protocol-compatible? Performs a Hello round-trip
/// on the canonical socket ([`get_socket_path`]).
///
/// `true` means the daemon answered within `HEALTH_CHECK_TIMEOUT` with a
/// matching `PROTOCOL_VERSION`. Everything else — no socket, no answer, a
/// version mismatch, a malformed frame — is `false`. The daemon's version
/// string rides the same response but no caller wants it here; [`daemon_status`]
/// is the surface that reports it.
///
/// [`get_socket_path`]: fuz_home::get_socket_path
pub async fn check_health() -> bool {
    let Ok(path) = socket_path() else {
        return false;
    };
    let Ok(Ok(mut stream)) = timeout(HEALTH_CHECK_TIMEOUT, UnixStream::connect(&path)).await else {
        return false;
    };
    let req = HelloRequest {
        protocol_version: PROTOCOL_VERSION,
    };
    let Ok(Ok(())) = timeout(
        HEALTH_CHECK_TIMEOUT,
        write_frame(&mut stream, 1, &req, MAX_FRAME),
    )
    .await
    else {
        return false;
    };
    let Ok(Ok((header, body))) =
        timeout(HEALTH_CHECK_TIMEOUT, read_frame(&mut stream, MAX_FRAME)).await
    else {
        return false;
    };
    hello_frame_is_healthy(header.action, &body)
}

//
// Daemon RPCs
//

/// Get comprehensive daemon status.
///
/// # Errors
/// Returns an error if the daemon is not running or not responding.
pub async fn daemon_status() -> Result<DaemonStatusResponse, ClientError> {
    let mut stream = dial_and_hello().await?;
    request_response(
        &mut stream,
        2,
        &DaemonStatusRequest,
        ids::DAEMON_STATUS_RESPONSE,
    )
    .await
}

/// Request graceful daemon shutdown.
///
/// # Errors
/// Returns an error if the daemon is not running or not responding.
pub async fn shutdown() -> Result<(), ClientError> {
    let mut stream = dial_and_hello().await?;
    let _: DaemonShutdownResponse = request_response(
        &mut stream,
        2,
        &DaemonShutdownRequest,
        ids::DAEMON_SHUTDOWN_RESPONSE,
    )
    .await?;
    Ok(())
}

//
// Generic subscription driver (streaming)
//

/// What a per-frame handler tells the [`run_subscription`] driver to do next.
#[derive(Debug)]
enum FrameControl {
    /// Keep reading frames (the steady-state for a `follow` subscription).
    Continue,
    /// A snapshot was delivered; keep reading (the `follow` snapshot arm).
    SnapshotThenContinue,
    /// Stop cleanly after this frame — the non-`follow` short-circuit, returned
    /// from the snapshot arm once the one-shot snapshot has been delivered.
    StopAfterSnapshot,
}

/// Drive one streaming subscription: dial + hello, write the subscribe request
/// on `SUB_REQUEST_ID`, then read frames on that id until the daemon closes the
/// connection, handing each `(action, body)` to `handle_frame`.
///
/// This owns the parts every workload subscription shares — the request id, the
/// dial/hello, the subscribe write, the read loop, the end-of-stream mapping,
/// the `request_id` filter, and the per-frame `FINAL` check — so each public
/// `*_subscribe_at` supplies only its request payload and a small per-action
/// decode/dispatch closure.
///
/// The stream ending (`UnexpectedEof` / `ConnectionReset`, or a `FINAL` frame)
/// is a clean end once a snapshot has been delivered, and
/// [`ClientError::StreamEndedBeforeSnapshot`] before one: the caller asked for
/// the daemon's view and got none, which must not read as an empty success.
/// `handle_frame` owns the per-kind decode, the caller callback, the
/// unexpected-action error, and the non-`follow` short-circuit (via
/// [`FrameControl::StopAfterSnapshot`]).
async fn run_subscription<Req, F>(
    socket_path: &Path,
    sub_req: Req,
    mut handle_frame: F,
) -> Result<(), ClientError>
where
    Req: Action + Sync,
    F: FnMut(ActionId, &[u8]) -> Result<FrameControl, ClientError>,
{
    // request_id 1 was the Hello; the subscription rides request_id 2 and
    // every stream frame echoes it.
    const SUB_REQUEST_ID: u32 = 2;
    let mut stream = dial_and_hello_at(socket_path).await?;
    write_frame(&mut stream, SUB_REQUEST_ID, &sub_req, MAX_FRAME).await?;

    let mut saw_snapshot = false;
    let ended = |saw_snapshot: bool| {
        if saw_snapshot {
            Ok(())
        } else {
            Err(ClientError::StreamEndedBeforeSnapshot)
        }
    };
    loop {
        let (header, body) = match read_frame(&mut stream, MAX_FRAME).await {
            Ok(framed) => framed,
            // The daemon closing the stream (shutdown, workload stopped) is
            // a clean end once there was a snapshot to show.
            Err(ProtoError::Io(err))
                if matches!(
                    err.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                return ended(saw_snapshot);
            }
            Err(err) => return Err(err.into()),
        };
        if header.request_id != SUB_REQUEST_ID {
            continue; // not our stream (shouldn't happen on a dedicated conn)
        }
        match handle_frame(header.action, &body)? {
            FrameControl::Continue => {}
            FrameControl::SnapshotThenContinue => saw_snapshot = true,
            FrameControl::StopAfterSnapshot => return Ok(()),
        }
        if header.flags.is_final() {
            return ended(saw_snapshot);
        }
    }
}

//
// Observer workload subscription (streaming)
//

/// One frame from an observer subscription, handed to the caller's
/// callback as it arrives.
#[derive(Debug)]
pub enum ObserverFrame {
    /// Full snapshot (the first frame, and every resync). Resets consumer
    /// state.
    Snapshot {
        workload_id: WorkloadId,
        snapshot: ObserverSnapshot,
    },
    /// Entity-level delta (added / changed / removed + fresh system stats).
    Delta(ObserverDelta),
    /// Discrete spawn / exit timeline events.
    Events(Vec<ObserverEvent>),
}

/// A snapshot that arrived across frames, waiting for its last continuation.
#[derive(Debug)]
struct PendingSnapshot {
    workload_id: WorkloadId,
    snapshot: ObserverSnapshot,
    /// Continuation deltas still to come.
    remaining: u32,
}

/// Fold one continuation delta's `added` entities into `pending`'s snapshot.
///
/// A continuation adds and nothing else, in the snapshot's own domain.
fn absorb_continuation(
    pending: &mut PendingSnapshot,
    delta: ObserverDelta,
) -> Result<(), ClientError> {
    let malformed = |reason| Err(ClientError::MalformedSnapshot { reason });
    match (&mut pending.snapshot, delta) {
        (ObserverSnapshot::Process(s), ObserverDelta::Process(d))
            if d.changed.is_empty() && d.removed.is_empty() =>
        {
            s.processes.extend(d.added);
        }
        (ObserverSnapshot::Network(s), ObserverDelta::Network(d))
            if d.changed.is_empty() && d.removed.is_empty() =>
        {
            s.connections.extend(d.added);
        }
        (ObserverSnapshot::Services(s), ObserverDelta::Services(d))
            if d.changed.is_empty() && d.removed.is_empty() =>
        {
            s.units.extend(d.added);
        }
        (ObserverSnapshot::Process(_), ObserverDelta::Process(_))
        | (ObserverSnapshot::Network(_), ObserverDelta::Network(_))
        | (ObserverSnapshot::Services(_), ObserverDelta::Services(_)) => {
            return malformed("a continuation changed or removed entities");
        }
        _ => return malformed("a continuation is for another domain"),
    }
    pending.remaining -= 1;
    Ok(())
}

/// Decode + dispatch one observer stream frame: map the `(action, body)` to an
/// [`ObserverFrame`], hand it to `on_frame`, and decide whether the driver
/// continues. The snapshot arm short-circuits to
/// [`FrameControl::StopAfterSnapshot`] when `!follow` (the one-shot path); an
/// action outside the observer frame set is a protocol error. Lifted out of the
/// `observe_subscribe_at` closure so the decode-arm wiring + follow logic are
/// unit-testable without a live daemon.
///
/// A snapshot frame with `continues > 0` is held in `pending` until that many
/// continuation deltas have added the rest of its entities, then handed over
/// whole — `on_frame` only ever sees whole snapshots. A new snapshot frame
/// while one is pending restarts the assembly (the daemon resynced); any other
/// frame then is [`ClientError::MalformedSnapshot`].
fn dispatch_observer_frame(
    action: ActionId,
    body: &[u8],
    follow: bool,
    pending: &mut Option<PendingSnapshot>,
    on_frame: &mut impl FnMut(ObserverFrame),
) -> Result<FrameControl, ClientError> {
    let whole = match action {
        ids::OBSERVER_SNAPSHOT_FRAME => {
            let frame: ObserverSnapshotFrame = fuz_wire::decode_payload(body)?;
            let assembly = PendingSnapshot {
                workload_id: frame.workload_id,
                snapshot: frame.snapshot,
                remaining: frame.continues,
            };
            if assembly.remaining > 0 {
                *pending = Some(assembly);
                return Ok(FrameControl::Continue);
            }
            *pending = None;
            assembly
        }
        ids::OBSERVER_DELTA_FRAME => {
            let frame: ObserverDeltaFrame = fuz_wire::decode_payload(body)?;
            let Some(mut assembly) = pending.take() else {
                on_frame(ObserverFrame::Delta(frame.delta));
                return Ok(FrameControl::Continue);
            };
            absorb_continuation(&mut assembly, frame.delta)?;
            if assembly.remaining > 0 {
                *pending = Some(assembly);
                return Ok(FrameControl::Continue);
            }
            assembly
        }
        ids::OBSERVER_EVENT_FRAME => {
            if pending.is_some() {
                return Err(ClientError::MalformedSnapshot {
                    reason: "an event frame arrived before the snapshot was complete",
                });
            }
            let frame: ObserverEventFrame = fuz_wire::decode_payload(body)?;
            on_frame(ObserverFrame::Events(frame.events));
            return Ok(FrameControl::Continue);
        }
        got => {
            return Err(ClientError::UnexpectedAction {
                expected: ids::OBSERVER_SNAPSHOT_FRAME,
                got,
            });
        }
    };
    on_frame(ObserverFrame::Snapshot {
        workload_id: whole.workload_id,
        snapshot: whole.snapshot,
    });
    Ok(if follow {
        FrameControl::SnapshotThenContinue
    } else {
        FrameControl::StopAfterSnapshot
    })
}

/// Subscribe to an observer domain and stream frames to `on_frame`.
///
/// Opens a dedicated connection to the canonical socket (`~/.fuz/run/socket`,
/// `FUZ_HOME`-aware), registers the subscription (sharing one daemon-side
/// collector with any other subscriber of the same domain), and delivers the
/// initial snapshot then live deltas/events. With `follow == false` this
/// returns after the first snapshot; with `follow == true` it streams until
/// the daemon closes the connection (e.g. shutdown) or the process is
/// interrupted.
///
/// [`observe_subscribe_at`] is the path-explicit form for long-lived
/// consumers pointed at a non-canonical socket (an isolated daemon, tests).
///
/// # Errors
///
/// Returns [`ClientError::DaemonNotRunning`] when fuzd isn't listening
/// (callers degrade with an actionable hint), or a wire error on a
/// malformed frame.
pub async fn observe_subscribe(
    domain: ObserverDomain,
    follow: bool,
    on_frame: impl FnMut(ObserverFrame),
) -> Result<(), ClientError> {
    let path = socket_path()?;
    observe_subscribe_at(&path, domain, follow, on_frame).await
}

/// Subscribe to an observer domain over the socket at `socket_path`.
///
/// The path-explicit form behind [`observe_subscribe`]. A long-lived consumer
/// (a daemon holding the subscription across many browser viewers) uses this
/// when it must reach a non-canonical socket — an isolated daemon under a
/// test-owned directory, say — without mutating `FUZ_HOME` (`set_var` is
/// `unsafe` under edition 2024, which the spine workspaces forbid).
///
/// # Errors
///
/// Returns [`ClientError::DaemonNotRunning`] when no daemon is listening at
/// `socket_path` (callers degrade with an actionable hint), or a wire error
/// on a malformed frame.
pub async fn observe_subscribe_at(
    socket_path: &Path,
    domain: ObserverDomain,
    follow: bool,
    mut on_frame: impl FnMut(ObserverFrame),
) -> Result<(), ClientError> {
    let mut pending = None;
    run_subscription(
        socket_path,
        ObserverSubscribeRequest { domain },
        |action, body| dispatch_observer_frame(action, body, follow, &mut pending, &mut on_frame),
    )
    .await
}

//
// Watcher workload subscription (streaming)
//

/// One frame from a watcher subscription, handed to the caller's callback as
/// it arrives.
#[derive(Debug)]
pub enum WatchFrame {
    /// The watch configuration (the first frame, and every resync). Tells the
    /// consumer to reset its fs-event region.
    Snapshot {
        workload_id: WorkloadId,
        snapshot: WatchSnapshot,
    },
    /// A coalesced batch of filesystem change events.
    Events(Vec<WatchEvent>),
    /// A coverage-only change (no event gap) — the consumer updates the watch's
    /// coverage label in place without resetting its fs region.
    Coverage(WatchCoverage),
}

/// Decode + dispatch one watcher stream frame — the [`WatchFrame`] twin of
/// [`dispatch_observer_frame`]. Snapshot short-circuits on `!follow`; coverage
/// frames keep streaming (no event gap); an off-set action is a protocol error.
fn dispatch_watch_frame(
    action: ActionId,
    body: &[u8],
    follow: bool,
    on_frame: &mut impl FnMut(WatchFrame),
) -> Result<FrameControl, ClientError> {
    match action {
        ids::WATCHER_SNAPSHOT_FRAME => {
            let frame: WatcherSnapshotFrame = fuz_wire::decode_payload(body)?;
            on_frame(WatchFrame::Snapshot {
                workload_id: frame.workload_id,
                snapshot: frame.snapshot,
            });
            Ok(if follow {
                FrameControl::SnapshotThenContinue
            } else {
                FrameControl::StopAfterSnapshot
            })
        }
        ids::WATCHER_EVENT_FRAME => {
            let frame: WatcherEventFrame = fuz_wire::decode_payload(body)?;
            on_frame(WatchFrame::Events(frame.events));
            Ok(FrameControl::Continue)
        }
        ids::WATCHER_COVERAGE_FRAME => {
            let frame: WatcherCoverageFrame = fuz_wire::decode_payload(body)?;
            on_frame(WatchFrame::Coverage(frame.coverage));
            Ok(FrameControl::Continue)
        }
        ids::WATCHER_SUBSCRIBE_REFUSED => {
            let frame: WatcherSubscribeRefused = fuz_wire::decode_payload(body)?;
            Err(ClientError::WatchRefused {
                reason: frame.reason,
            })
        }
        got => Err(ClientError::UnexpectedAction {
            expected: ids::WATCHER_SNAPSHOT_FRAME,
            got,
        }),
    }
}

/// Subscribe to a filesystem watch over `roots` and stream frames to
/// `on_frame`.
///
/// Opens a dedicated connection to the canonical socket, registers the watch
/// (sharing one daemon-side watcher with any subscriber of the same normalized
/// `(roots, recursive)`), and delivers the initial snapshot then live event
/// batches. With `follow == false` this returns after the first snapshot; with
/// `follow == true` it streams until the daemon closes the connection or the
/// process is interrupted.
///
/// [`watch_subscribe_at`] is the path-explicit form for long-lived consumers
/// pointed at a non-canonical socket (an isolated daemon, tests).
///
/// # Errors
///
/// Returns [`ClientError::DaemonNotRunning`] when fuzd isn't listening
/// (callers degrade with an actionable hint), or a wire error on a malformed
/// frame.
pub async fn watch_subscribe(
    roots: Vec<String>,
    recursive: bool,
    follow: bool,
    on_frame: impl FnMut(WatchFrame),
) -> Result<(), ClientError> {
    let path = socket_path()?;
    watch_subscribe_at(&path, roots, recursive, follow, on_frame).await
}

/// Subscribe to a filesystem watch over the socket at `socket_path`.
///
/// The path-explicit form behind [`watch_subscribe`]. A long-lived consumer
/// (a daemon holding the subscription across many browser viewers) uses this
/// when it must reach a non-canonical socket — an isolated daemon under a
/// test-owned directory — without mutating `FUZ_HOME`.
///
/// # Errors
///
/// Returns [`ClientError::DaemonNotRunning`] when no daemon is listening at
/// `socket_path`, or a wire error on a malformed frame.
pub async fn watch_subscribe_at(
    socket_path: &Path,
    roots: Vec<String>,
    recursive: bool,
    follow: bool,
    mut on_frame: impl FnMut(WatchFrame),
) -> Result<(), ClientError> {
    run_subscription(
        socket_path,
        WatcherSubscribeRequest { roots, recursive },
        |action, body| dispatch_watch_frame(action, body, follow, &mut on_frame),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuz_wire::{
        ObserverEventFrame, ObserverSnapshot, ObserverSnapshotFrame, ProcessSnapshot,
        SystemResources, WatchCoverage, WatchSnapshot, WatcherCoverageFrame, WatcherEventFrame,
        WatcherSnapshotFrame, encode_payload,
    };

    /// A minimal but valid encoded observer snapshot frame (empty process list).
    fn observer_snapshot_body() -> Vec<u8> {
        let frame = ObserverSnapshotFrame {
            workload_id: 42,
            continues: 0,
            snapshot: ObserverSnapshot::Process(ProcessSnapshot {
                system: SystemResources {
                    cpu_pct: 0.0,
                    ncpu: 1,
                    mem_total_bytes: 0,
                    mem_available_bytes: 0,
                    load_1: 0.0,
                    load_5: 0.0,
                    load_15: 0.0,
                    uptime_secs: 0,
                },
                processes: Vec::new(),
            }),
        };
        encode_payload(&frame).expect("encode observer snapshot")
    }

    #[test]
    fn observer_dispatch_decodes_known_frames_and_rejects_unknown() {
        let mut frames = Vec::new();
        let body = observer_snapshot_body();
        let ctl = dispatch_observer_frame(
            ids::OBSERVER_SNAPSHOT_FRAME,
            &body,
            true,
            &mut None,
            &mut |f| {
                frames.push(f);
            },
        )
        .expect("snapshot must decode");
        assert!(
            matches!(ctl, FrameControl::SnapshotThenContinue),
            "follow keeps streaming past the snapshot"
        );
        assert!(matches!(
            frames.as_slice(),
            [ObserverFrame::Snapshot {
                workload_id: 42,
                ..
            }]
        ));

        // An empty event frame decodes and continues.
        frames.clear();
        let events = encode_payload(&ObserverEventFrame { events: Vec::new() }).unwrap();
        dispatch_observer_frame(
            ids::OBSERVER_EVENT_FRAME,
            &events,
            true,
            &mut None,
            &mut |f| {
                frames.push(f);
            },
        )
        .unwrap();
        assert!(matches!(frames.as_slice(), [ObserverFrame::Events(v)] if v.is_empty()));

        // An action outside the observer frame set is a protocol error, naming
        // the expected snapshot id — guards against a mis-wired decode arm.
        let err = dispatch_observer_frame(
            ids::WATCHER_SNAPSHOT_FRAME,
            &[],
            true,
            &mut None,
            &mut |_| {},
        )
        .expect_err("an off-set action must error");
        assert!(matches!(
            err,
            ClientError::UnexpectedAction { expected, got }
                if expected == ids::OBSERVER_SNAPSHOT_FRAME && got == ids::WATCHER_SNAPSHOT_FRAME
        ));
    }

    #[test]
    fn observer_snapshot_stops_after_snapshot_when_not_following() {
        let body = observer_snapshot_body();
        let ctl = dispatch_observer_frame(
            ids::OBSERVER_SNAPSHOT_FRAME,
            &body,
            false,
            &mut None,
            &mut |_| {},
        )
        .expect("snapshot must decode");
        assert!(
            matches!(ctl, FrameControl::StopAfterSnapshot),
            "non-follow must stop after the one-shot snapshot"
        );
    }

    #[test]
    fn watch_dispatch_decodes_known_frames_and_rejects_unknown() {
        let snap = WatcherSnapshotFrame {
            workload_id: 7,
            snapshot: WatchSnapshot {
                roots: Vec::new(),
                recursive: false,
                coverage: WatchCoverage::Unknown,
            },
        };
        let body = encode_payload(&snap).unwrap();
        let mut frames = Vec::new();
        let ctl = dispatch_watch_frame(ids::WATCHER_SNAPSHOT_FRAME, &body, false, &mut |f| {
            frames.push(f);
        })
        .unwrap();
        assert!(
            matches!(ctl, FrameControl::StopAfterSnapshot),
            "non-follow stops"
        );
        assert!(matches!(
            frames.as_slice(),
            [WatchFrame::Snapshot { workload_id: 7, .. }]
        ));

        // An event frame keeps streaming.
        let ev = encode_payload(&WatcherEventFrame { events: Vec::new() }).unwrap();
        let ctl = dispatch_watch_frame(ids::WATCHER_EVENT_FRAME, &ev, true, &mut |_| {}).unwrap();
        assert!(matches!(ctl, FrameControl::Continue));

        // The observer snapshot id is off the watcher set → protocol error.
        let err = dispatch_watch_frame(ids::OBSERVER_SNAPSHOT_FRAME, &[], true, &mut |_| {})
            .expect_err("an off-set action must error");
        assert!(matches!(
            err,
            ClientError::UnexpectedAction { expected, got }
                if expected == ids::WATCHER_SNAPSHOT_FRAME && got == ids::OBSERVER_SNAPSHOT_FRAME
        ));
    }

    /// The `WATCHER_COVERAGE_FRAME` arm (decoupled coverage update, no event gap)
    /// — decodes to `WatchFrame::Coverage` and keeps streaming.
    #[test]
    fn watch_dispatch_decodes_the_coverage_frame() {
        let body = encode_payload(&WatcherCoverageFrame {
            workload_id: 9,
            coverage: WatchCoverage::Partial { unwatched: 3 },
        })
        .unwrap();
        let mut frames = Vec::new();
        let ctl = dispatch_watch_frame(ids::WATCHER_COVERAGE_FRAME, &body, true, &mut |f| {
            frames.push(f);
        })
        .expect("coverage frame must decode");
        assert!(
            matches!(ctl, FrameControl::Continue),
            "a coverage update never ends the subscription"
        );
        assert!(matches!(
            frames.as_slice(),
            [WatchFrame::Coverage(WatchCoverage::Partial {
                unwatched: 3
            })]
        ));
    }

    /// The health decision is exactly "a decodable `HELLO_RESPONSE` whose
    /// outcome is `Ok`" — health carries no other axis (there is no
    /// wire-level draining signal to read).
    #[test]
    fn hello_frame_is_healthy_only_on_an_ok_outcome() {
        let ok = encode_payload(&HelloResponse {
            server_protocol_version: PROTOCOL_VERSION,
            server_version: "0.1.0".to_string(),
            outcome: HelloOutcome::Ok,
        })
        .unwrap();
        assert!(hello_frame_is_healthy(ids::HELLO_RESPONSE, &ok));

        // A version-mismatched daemon answers, but it is unusable.
        let mismatch = encode_payload(&HelloResponse {
            server_protocol_version: PROTOCOL_VERSION,
            server_version: "0.1.0".to_string(),
            outcome: HelloOutcome::VersionMismatch {
                // Server perspective: `ours` is the daemon's (newer) version,
                // `theirs` echoes this client's.
                ours: PROTOCOL_VERSION + 1,
                theirs: PROTOCOL_VERSION,
            },
        })
        .unwrap();
        assert!(!hello_frame_is_healthy(ids::HELLO_RESPONSE, &mismatch));

        // Right payload, wrong action, and an undecodable body.
        assert!(!hello_frame_is_healthy(ids::PONG, &ok));
        assert!(!hello_frame_is_healthy(ids::HELLO_RESPONSE, &[0xff; 4]));
    }

    /// A one-connection fake daemon at a fresh socket path (call it inside a
    /// runtime): it answers the
    /// Hello, reads the subscribe request, sends `frames` on its request id,
    /// then closes. Returns the socket path (under a directory the caller
    /// removes) and the server task.
    fn fake_daemon(
        name: &str,
        frames: Vec<(ActionId, Vec<u8>)>,
    ) -> (PathBuf, tokio::task::JoinHandle<()>) {
        let dir = std::env::temp_dir().join(format!("fuzc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (hello, _) = read_frame(&mut stream, MAX_FRAME).await.unwrap();
            let resp = HelloResponse {
                server_protocol_version: PROTOCOL_VERSION,
                server_version: "test".to_string(),
                outcome: HelloOutcome::Ok,
            };
            write_frame(&mut stream, hello.request_id, &resp, MAX_FRAME)
                .await
                .unwrap();
            let (sub, _) = read_frame(&mut stream, MAX_FRAME).await.unwrap();
            for (action, body) in frames {
                fuz_wire::write_raw_frame(
                    &mut stream,
                    sub.request_id,
                    action,
                    fuz_wire::FrameFlags::EMPTY,
                    &body,
                    MAX_FRAME,
                )
                .await
                .unwrap();
            }
        });
        (path, server)
    }

    fn remove_socket_dir(path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[tokio::test]
    async fn an_observe_stream_that_ends_before_a_snapshot_is_an_error() {
        for follow in [false, true] {
            let (path, server) = fake_daemon(&format!("obs-{follow}"), Vec::new());
            let mut frames = 0;
            let result =
                observe_subscribe_at(&path, ObserverDomain::Process, follow, |_| frames += 1).await;
            server.await.unwrap();
            remove_socket_dir(&path);
            assert!(
                matches!(result, Err(ClientError::StreamEndedBeforeSnapshot)),
                "follow={follow}: {result:?}"
            );
            assert_eq!(frames, 0);
        }
    }

    #[tokio::test]
    async fn a_watch_stream_that_ends_before_a_snapshot_is_an_error() {
        // Event and coverage frames are not a snapshot: the stream still ended
        // before one.
        let events = encode_payload(&WatcherEventFrame { events: Vec::new() }).unwrap();
        let (path, server) = fake_daemon("watch", vec![(ids::WATCHER_EVENT_FRAME, events)]);
        let result = watch_subscribe_at(&path, vec!["/w".to_string()], true, true, |_| {}).await;
        server.await.unwrap();
        remove_socket_dir(&path);
        assert!(
            matches!(result, Err(ClientError::StreamEndedBeforeSnapshot)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_followed_stream_that_ends_after_its_snapshot_is_a_clean_end() {
        let (path, server) = fake_daemon(
            "after",
            vec![(ids::OBSERVER_SNAPSHOT_FRAME, observer_snapshot_body())],
        );
        let mut snapshots = 0;
        let result = observe_subscribe_at(&path, ObserverDomain::Process, true, |frame| {
            if matches!(frame, ObserverFrame::Snapshot { .. }) {
                snapshots += 1;
            }
        })
        .await;
        server.await.unwrap();
        remove_socket_dir(&path);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(snapshots, 1);
    }

    fn process(pid: i32) -> fuz_wire::ProcessInfo {
        fuz_wire::ProcessInfo {
            key: fuz_wire::ProcessKey { pid, start_time: 1 },
            ppid: 1,
            name: format!("p{pid}"),
            state: 'S',
            cpu_pct: 0.0,
            mem_bytes: 0,
            cmdline: None,
        }
    }

    fn system() -> SystemResources {
        SystemResources {
            cpu_pct: 0.0,
            ncpu: 1,
            mem_total_bytes: 0,
            mem_available_bytes: 0,
            load_1: 0.0,
            load_5: 0.0,
            load_15: 0.0,
            uptime_secs: 0,
        }
    }

    /// A process snapshot frame holding `pids`, completed by `continues` deltas.
    fn split_snapshot(pids: &[i32], continues: u32) -> (ActionId, Vec<u8>) {
        let frame = ObserverSnapshotFrame {
            workload_id: 5,
            continues,
            snapshot: ObserverSnapshot::Process(ProcessSnapshot {
                system: system(),
                processes: pids.iter().copied().map(process).collect(),
            }),
        };
        (
            ids::OBSERVER_SNAPSHOT_FRAME,
            encode_payload(&frame).unwrap(),
        )
    }

    /// A continuation delta adding `pids`.
    fn continuation(pids: &[i32]) -> (ActionId, Vec<u8>) {
        let frame = ObserverDeltaFrame {
            delta: ObserverDelta::Process(fuz_wire::ProcessDelta {
                system: system(),
                added: pids.iter().copied().map(process).collect(),
                changed: Vec::new(),
                removed: Vec::new(),
            }),
        };
        (ids::OBSERVER_DELTA_FRAME, encode_payload(&frame).unwrap())
    }

    fn snapshot_pids(frame: &ObserverFrame) -> Vec<i32> {
        let ObserverFrame::Snapshot {
            snapshot: ObserverSnapshot::Process(s),
            ..
        } = frame
        else {
            panic!("expected a process snapshot, got {frame:?}");
        };
        let mut pids: Vec<i32> = s.processes.iter().map(|p| p.key.pid).collect();
        pids.sort_unstable();
        pids
    }

    #[tokio::test]
    async fn a_one_shot_observe_gets_a_split_snapshot_whole() {
        let (path, server) = fake_daemon(
            "split",
            vec![split_snapshot(&[1, 2], 1), continuation(&[3, 4])],
        );
        let mut frames = Vec::new();
        let result =
            observe_subscribe_at(&path, ObserverDomain::Process, false, |f| frames.push(f)).await;
        server.await.unwrap();
        remove_socket_dir(&path);
        result.unwrap();
        assert_eq!(frames.len(), 1, "one snapshot, nothing partial: {frames:?}");
        assert_eq!(snapshot_pids(&frames[0]), vec![1, 2, 3, 4]);
    }

    #[test]
    fn a_new_snapshot_mid_assembly_restarts_it() {
        let mut pending = None;
        let mut frames = Vec::new();
        let mut feed = |(action, body): (ActionId, Vec<u8>), frames: &mut Vec<ObserverFrame>| {
            dispatch_observer_frame(action, &body, true, &mut pending, &mut |f| frames.push(f))
        };
        feed(split_snapshot(&[1], 2), &mut frames).unwrap();
        feed(continuation(&[2]), &mut frames).unwrap();
        assert!(frames.is_empty(), "nothing until the snapshot is whole");
        // The daemon resynced: the old assembly is dropped, the new one counts.
        feed(split_snapshot(&[7], 1), &mut frames).unwrap();
        let ctl = feed(continuation(&[8]), &mut frames).unwrap();
        assert!(matches!(ctl, FrameControl::SnapshotThenContinue));
        assert_eq!(frames.len(), 1);
        assert_eq!(snapshot_pids(&frames[0]), vec![7, 8]);
        // Assembled: a delta now is an ordinary delta.
        feed(continuation(&[9]), &mut frames).unwrap();
        assert!(matches!(frames[1], ObserverFrame::Delta(_)));
    }

    #[test]
    fn another_frame_mid_assembly_is_a_protocol_error() {
        let events = encode_payload(&ObserverEventFrame { events: Vec::new() }).unwrap();
        let changing = encode_payload(&ObserverDeltaFrame {
            delta: ObserverDelta::Process(fuz_wire::ProcessDelta {
                system: system(),
                added: Vec::new(),
                changed: vec![process(3)],
                removed: Vec::new(),
            }),
        })
        .unwrap();
        for (action, body) in [
            (ids::OBSERVER_EVENT_FRAME, events),
            (ids::OBSERVER_DELTA_FRAME, changing),
        ] {
            let mut pending = None;
            let (snap_action, snap) = split_snapshot(&[1], 1);
            dispatch_observer_frame(snap_action, &snap, true, &mut pending, &mut |_| {}).unwrap();
            let err = dispatch_observer_frame(action, &body, true, &mut pending, &mut |_| {})
                .expect_err("not a continuation");
            assert!(
                matches!(err, ClientError::MalformedSnapshot { .. }),
                "{action}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_refused_watch_is_an_error_naming_the_cause() {
        let refused = encode_payload(&WatcherSubscribeRefused {
            reason: fuz_wire::WatchRefusal::RootsTooLarge {
                encoded: 11,
                limit: 10,
            },
        })
        .unwrap();
        let (path, server) =
            fake_daemon("refused", vec![(ids::WATCHER_SUBSCRIBE_REFUSED, refused)]);
        let result = watch_subscribe_at(&path, vec!["/w".to_string()], true, true, |_| {}).await;
        server.await.unwrap();
        remove_socket_dir(&path);
        let err = result.expect_err("refused");
        assert!(matches!(err, ClientError::WatchRefused { .. }), "{err:?}");
        assert!(err.to_string().contains("roots"), "{err}");
        assert!(err.hint().is_some());
    }

    #[tokio::test]
    async fn a_split_snapshot_cut_short_by_the_daemon_is_an_error_not_a_partial_success() {
        for follow in [false, true] {
            let (path, server) = fake_daemon(
                &format!("short-{follow}"),
                vec![split_snapshot(&[1, 2], 2), continuation(&[3])],
            );
            let mut frames = Vec::new();
            let result =
                observe_subscribe_at(&path, ObserverDomain::Process, follow, |f| frames.push(f))
                    .await;
            server.await.unwrap();
            remove_socket_dir(&path);
            assert!(
                matches!(result, Err(ClientError::StreamEndedBeforeSnapshot)),
                "follow={follow}: {result:?}"
            );
            assert!(frames.is_empty(), "no partial snapshot reached the caller");
        }
    }
}
