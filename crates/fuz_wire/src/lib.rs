//! fuzd UDS wire protocol and the daemon/sidecar RPC payload types.
//!
//! The postcard-framed two-stage envelope (frame layout
//! `total_len (u32) | request_id (u32) | action_id (u16) | flags (u8) | payload`,
//! big-endian; see [`Header`] and [`FrameFlags`]) plus the
//! daemon/sidecar status DTOs (`DaemonStatusResponse`, `SidecarStatusInfo`,
//! `ToolInfo`, …) that ride it. Shared by the daemon (`fuzd_server`,
//! `fuz_sidecar`) and the client (`fuz_client`); kept separate from `fuz_sys` so
//! the rest of the workspace doesn't transitively compile postcard + tokio.

mod actions;
mod codec;
mod error;
mod messages;
mod observer;
mod sidecar;
mod watcher;
mod workload;

pub use actions::{Action, ActionId, AuthLevel, ids};
pub use codec::{
    FrameFlags, HEADER_BYTES, Header, decode_payload, encode_payload, read_frame, write_frame,
    write_raw_frame,
};
pub use error::ProtoError;
pub use messages::{
    DaemonShutdownRequest, DaemonShutdownResponse, DaemonStatusRequest, DaemonStatusResponse,
    Goodbye, HelloOutcome, HelloRequest, HelloResponse, Ping, Pong, ShutdownStatus,
    SidecarCallListRequest, SidecarCallListResponse, SidecarCallOutcome, SidecarCallRunRequest,
    SidecarCallRunResponse, SidecarRestartRequest, SidecarRestartResponse, SidecarStartRequest,
    SidecarStartResponse, SidecarStatusRequest, SidecarStatusResponse, SidecarStopRequest,
    SidecarStopResponse,
};
pub use observer::{
    ConnectionEvent, ConnectionInfo, ConnectionKey, InterfaceInfo, NetworkDelta, NetworkSnapshot,
    ObserverDelta, ObserverDeltaFrame, ObserverDomain, ObserverEvent, ObserverEventFrame,
    ObserverSnapshot, ObserverSnapshotFrame, ObserverSubscribeRequest, ObserverUnsubscribeRequest,
    ObserverUnsubscribeResponse, ProcessDelta, ProcessEvent, ProcessInfo, ProcessKey,
    ProcessSnapshot, ServiceEvent, ServiceUnit, ServicesDelta, ServicesSnapshot, SocketProtocol,
    SocketState, SystemResources, UnitActiveState,
};
pub use sidecar::{
    RestartResult, SidecarStatus, SidecarStatusInfo, SidecarTarget, StartResult, StopResult,
    ToolInfo, VersionInfo,
};
pub use watcher::{
    WatchCoverage, WatchEvent, WatchEventKind, WatchRefusal, WatchSnapshot, WatcherCoverageFrame,
    WatcherEventFrame, WatcherSnapshotFrame, WatcherSubscribeRefused, WatcherSubscribeRequest,
    WatcherUnsubscribeRequest, WatcherUnsubscribeResponse,
};
pub use workload::{
    UnsubscribeOutcome, WorkloadId, WorkloadInfo, WorkloadKind, WorkloadListRequest,
    WorkloadListResponse, WorkloadStatusRequest, WorkloadStatusResponse, WorkloadStopOutcome,
    WorkloadStopRequest, WorkloadStopResponse,
};

/// Current wire protocol version, bumped on every wire-shape change pre-1.0.
///
/// The Hello handshake exchanges versions, and a mismatch fails it. The health
/// probe is one bit, so `fuzd status` reports such a daemon as "not answering"
/// (naming a protocol mismatch as one possible cause), not the two versions.
///
/// History:
/// * `1` — initial UDS + postcard two-stage envelope.
/// * `2` — streaming responses: a `flags` byte ([`FrameFlags`]) added to
///   the frame header after `action_id` (`HEADER_BYTES` 6 → 7), enabling
///   multiple response frames per `request_id` terminated by a `FINAL`
///   frame. Adds the generic workload-control surface
///   ([`WorkloadListRequest`]) and the `observer` workload kind
///   ([`ObserverSubscribeRequest`]).
/// * `3` — the `watcher` workload kind ([`WatcherSubscribeRequest`] +
///   snapshot/event frames, `0x0110 – 0x012F`): an event-driven filesystem
///   watch streaming change events. Additive action ids, no framing change.
/// * `4` — [`WatchSnapshot`] gains a [`WatchCoverage`] field (the watch's actual
///   coverage, so a partial/dark watch is visible to the consumer, not just the
///   daemon log). A payload-shape break (postcard is not self-describing), no
///   new action ids or framing change.
/// * `5` — the `watcher` kind's [`WatcherCoverageFrame`] (`0x0115`): a
///   coverage-only update decoupled from the snapshot/gap frame, so a coverage
///   change (partial establishment, post-establishment degradation, recovery)
///   reaches the consumer without the disruptive resync that drops events.
///   Additive action id, no framing change.
/// * `6` — [`ObserverSnapshotFrame`] gains `continues`, the count of the delta
///   frames that complete a snapshot too large for one frame (a payload-shape
///   break); and the watcher's [`WatcherSubscribeRefused`] (`0x0116`), a
///   `FINAL` refusal of a subscribe whose roots cannot fit the snapshot frame.
pub const PROTOCOL_VERSION: u32 = 6;

/// Symmetric frame-size limit — the single load-bearing guard, enforced at
/// `read_frame`. `fuzd_server`'s sidecar-call content check reuses it directly.
///
/// One cap covers both directions: fuzd's hot path carries large tool inputs
/// and sometimes large outputs, so a single symmetric limit fits better than
/// asymmetric client→server / server→client bounds.
pub const MAX_FRAME: u32 = 10 * 1024 * 1024;
