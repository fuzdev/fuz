//! Generic workload-control payloads (0x0100 – 0x010F).
//!
//! Kind-agnostic discovery and teardown over fuzd's demand-driven
//! workload registry. Per-kind surfaces (subscribe, stream frames) live in
//! each kind's own module — [`observer`](crate::observer), which polls an OS
//! domain and streams snapshot → deltas → events, and
//! [`watcher`](crate::watcher), which watches a filesystem path-set and
//! streams snapshot → events (plus coverage). A normal caller goes
//! straight to the kind-specific surface; `workload list` / `status` /
//! `stop` are the debugging + manual-teardown surface.

use serde::{Deserialize, Serialize};

use super::actions::{Action, ActionId, AuthLevel, ids};

/// Stable per-daemon id for a registered workload. Monotonic for the life
/// of the daemon process; not persisted across restarts.
pub type WorkloadId = u64;

/// Which kind of workload a registration is. memo / fact / lsp / sidecar
/// append as they ship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadKind {
    /// Poll-driven sampler — see [`ObserverSubscribeRequest`](crate::ObserverSubscribeRequest)
    /// and [`ObserverDomain`](crate::ObserverDomain).
    Observer,
    /// Event-driven filesystem watcher — see
    /// [`WatcherSubscribeRequest`](crate::WatcherSubscribeRequest).
    Watcher,
}

/// Outcome of unsubscribing one connection from a workload.
///
/// Generic across kinds — the `outcome` of both
/// [`ObserverUnsubscribeResponse`](crate::ObserverUnsubscribeResponse) and
/// [`WatcherUnsubscribeResponse`](crate::WatcherUnsubscribeResponse), since a
/// subscription drops the same way in either kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsubscribeOutcome {
    /// This connection's subscription to the workload was dropped.
    Unsubscribed,
    /// This connection had no subscription to that workload id.
    NotSubscribed,
}

/// Public summary of one registered workload (for `workload list` /
/// `status`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadInfo {
    pub id: WorkloadId,
    pub kind: WorkloadKind,
    /// Human-readable scope, e.g. `"observer:process"`. Derived from the
    /// registration params — fuzd models no `project`/`repo` underneath.
    pub description: String,
    /// Active registration (refcount) — how many clients share this
    /// workload right now.
    pub subscribers: u32,
}

/// List every workload currently registered on fuzd.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WorkloadListRequest;

impl Action for WorkloadListRequest {
    const ID: ActionId = ids::WORKLOAD_LIST_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadListResponse {
    pub workloads: Vec<WorkloadInfo>,
}

impl Action for WorkloadListResponse {
    const ID: ActionId = ids::WORKLOAD_LIST_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Status of one workload by id.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WorkloadStatusRequest {
    pub id: WorkloadId,
}

impl Action for WorkloadStatusRequest {
    const ID: ActionId = ids::WORKLOAD_STATUS_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// `workload` is `None` when no workload with that id is registered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadStatusResponse {
    pub workload: Option<WorkloadInfo>,
}

impl Action for WorkloadStatusResponse {
    const ID: ActionId = ids::WORKLOAD_STATUS_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Manually stop a workload by id, regardless of refcount. A debugging /
/// admin escape hatch; normal teardown is unsubscribe + idle-grace.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WorkloadStopRequest {
    pub id: WorkloadId,
}

impl Action for WorkloadStopRequest {
    const ID: ActionId = ids::WORKLOAD_STOP_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadStopResponse {
    pub outcome: WorkloadStopOutcome,
}

impl Action for WorkloadStopResponse {
    const ID: ActionId = ids::WORKLOAD_STOP_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Outcome of a [`WorkloadStopRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadStopOutcome {
    /// The workload was found and stopped (its collector cancelled,
    /// subscribers' streams ended).
    Stopped,
    /// No workload with that id is registered.
    NotFound,
}
