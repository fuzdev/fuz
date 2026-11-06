//! Per-action request / response structs.
//!
//! Every type that flows over the wire impls [`Action`] so the codec
//! reads its [`ActionId`] off the trait. New message types are
//! append-only — see [`ids`].
//!
//! Payload types use postcard, so they derive `Serialize, Deserialize,
//! Debug, Clone` and avoid `serde_json::Value` / dynamic shapes.

use serde::{Deserialize, Serialize};

use super::actions::{Action, ActionId, AuthLevel, ids};
use crate::sidecar::{
    RestartResult, SidecarStatusInfo, SidecarTarget, StartResult, StopResult, ToolInfo,
};

//
// Control plane (0x0001 – 0x000F)
//

/// Initial handshake: client advertises its `PROTOCOL_VERSION` and the
/// daemon replies with its own. Mismatch is a user-visible error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloRequest {
    pub protocol_version: u32,
}

impl Action for HelloRequest {
    const ID: ActionId = ids::HELLO_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Public;
}

/// Daemon's `HelloResponse`.
///
/// `outcome` distinguishes successful version
/// match from a protocol mismatch — the daemon still answers a mismatch
/// (rather than closing silently) so the client can surface a clear
/// error from `fuzd status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponse {
    pub server_protocol_version: u32,
    pub server_version: String,
    pub outcome: HelloOutcome,
}

impl Action for HelloResponse {
    const ID: ActionId = ids::HELLO_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Public;
}

/// Outcome variant for [`HelloResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelloOutcome {
    /// Versions match; proceed.
    Ok,
    /// Versions diverge; the client should refuse the connection.
    VersionMismatch { ours: u32, theirs: u32 },
}

/// No-payload keepalive. Optional; not used by today's CLI but reserved
/// for future idle-check use cases.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Ping;

impl Action for Ping {
    const ID: ActionId = ids::PING;
    const AUTH: AuthLevel = AuthLevel::Public;
}

/// Reply to a [`Ping`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Pong;

impl Action for Pong {
    const ID: ActionId = ids::PONG;
    const AUTH: AuthLevel = AuthLevel::Public;
}

/// Explicit peer-initiated goodbye. The read loop also handles EOF on
/// connection close — this exists for the well-behaved case.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Goodbye;

impl Action for Goodbye {
    const ID: ActionId = ids::GOODBYE;
    const AUTH: AuthLevel = AuthLevel::Public;
}

//
// Daemon lifecycle (0x0010 – 0x001F)
//

/// Request comprehensive daemon status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DaemonStatusRequest;

impl Action for DaemonStatusRequest {
    const ID: ActionId = ids::DAEMON_STATUS_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Daemon status payload — version + every sidecar + every tool name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatusResponse {
    pub version: String,
    pub sidecars: Vec<SidecarStatusInfo>,
    pub tools: Vec<String>,
}

impl Action for DaemonStatusResponse {
    const ID: ActionId = ids::DAEMON_STATUS_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Request graceful shutdown of the daemon.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DaemonShutdownRequest;

impl Action for DaemonShutdownRequest {
    const ID: ActionId = ids::DAEMON_SHUTDOWN_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Shutdown acknowledgement. The daemon flips `draining` and replies
/// with [`ShutdownStatus::ShuttingDown`]; subsequent calls land on the
/// `Draining` outcome of whichever action they tried.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonShutdownResponse {
    pub status: ShutdownStatus,
}

impl Action for DaemonShutdownResponse {
    const ID: ActionId = ids::DAEMON_SHUTDOWN_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Outcome variant for [`DaemonShutdownResponse`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ShutdownStatus {
    ShuttingDown,
}

//
// Sidecar control (0x0020 – 0x003F)
//

/// Start one sidecar ([`SidecarTarget::One`]) or every sidecar ([`SidecarTarget::All`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarStartRequest {
    pub target: SidecarTarget,
}

impl Action for SidecarStartRequest {
    const ID: ActionId = ids::SIDECAR_START_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarStartResponse {
    pub result: StartResult,
}

impl Action for SidecarStartResponse {
    const ID: ActionId = ids::SIDECAR_START_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarStopRequest {
    pub target: SidecarTarget,
}

impl Action for SidecarStopRequest {
    const ID: ActionId = ids::SIDECAR_STOP_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarStopResponse {
    pub result: StopResult,
}

impl Action for SidecarStopResponse {
    const ID: ActionId = ids::SIDECAR_STOP_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarRestartRequest {
    pub target: SidecarTarget,
}

impl Action for SidecarRestartRequest {
    const ID: ActionId = ids::SIDECAR_RESTART_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarRestartResponse {
    pub result: RestartResult,
}

impl Action for SidecarRestartResponse {
    const ID: ActionId = ids::SIDECAR_RESTART_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarStatusRequest {
    pub target: SidecarTarget,
}

impl Action for SidecarStatusRequest {
    const ID: ActionId = ids::SIDECAR_STATUS_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarStatusResponse {
    pub sidecars: Vec<SidecarStatusInfo>,
}

impl Action for SidecarStatusResponse {
    const ID: ActionId = ids::SIDECAR_STATUS_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

//
// Sidecar call dispatch (0x0040 – 0x005F) — the hot path
//
// Invoke a sidecar-hosted operation by name. Distinct from the `tool` noun
// (first-party @fuzdev binaries fuz installs); this is the dormant
// sidecar-call surface, kept on the wire for any future sidecar consumer.

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SidecarCallListRequest;

impl Action for SidecarCallListRequest {
    const ID: ActionId = ids::SIDECAR_CALL_LIST_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarCallListResponse {
    pub tools: Vec<ToolInfo>,
}

impl Action for SidecarCallListResponse {
    const ID: ActionId = ids::SIDECAR_CALL_LIST_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Run one sidecar-hosted operation.
///
/// `content` is the source bytes (already
/// a `String` today; the sidecar parses it). `options` is an opaque JSON
/// string the sidecar parses itself — keeps `fuz_wire` operation-agnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarCallRunRequest {
    pub tool: String,
    pub content: String,
    pub options: Option<String>,
}

impl Action for SidecarCallRunRequest {
    const ID: ActionId = ids::SIDECAR_CALL_RUN_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Outer response always succeeds at the wire level (frame written,
/// decoded); the application result is the `outcome` variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarCallRunResponse {
    pub outcome: SidecarCallOutcome,
}

impl Action for SidecarCallRunResponse {
    const ID: ActionId = ids::SIDECAR_CALL_RUN_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Per-action outcome enum for [`SidecarCallRunResponse`].
///
/// Today's sidecars
/// produce JSON output which the client parses — `result` carries the
/// raw bytes of that JSON value so transport stays operation-agnostic
/// while preserving postcard wire shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SidecarCallOutcome {
    /// Tool ran successfully. `result` is the postcard-friendly JSON
    /// rendering produced by the sidecar (most tools return a `String`;
    /// pass-through `tool.run` calls may return any JSON value).
    Ok { result: String },
    /// Request body exceeded [`crate::MAX_FRAME`].
    ContentTooLarge { len: u64, max: u64 },
    /// No sidecar exposes this tool name.
    ToolNotFound { tool: String },
    /// Sidecar reported a typed error; the message is suitable for
    /// surfacing to the user.
    SidecarError { message: String },
    /// Daemon is shutting down; the request was rejected without
    /// invoking the sidecar.
    Draining,
}
