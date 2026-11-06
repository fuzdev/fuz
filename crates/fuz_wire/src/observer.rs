//! Observer workload kind payloads (0x0190 – 0x01AF).
//!
//! The observer kind samples an OS domain on an interval and streams the
//! result to subscribers: one full **snapshot** frame, then entity-level
//! **delta** frames (`{ added, changed, removed }`), plus discrete
//! **event** frames (the durable spawn/exit timeline). One kind,
//! domain-parameterized ([`ObserverDomain`]); the process domain is the
//! only v1 domain.
//!
//! Subscribe and register are one step — the observer has no
//! registration-without-subscription use. The subscribe response stream
//! reuses the request's `request_id`; the first frame is a snapshot
//! (which also carries the [`WorkloadId`] so the subscriber can
//! `Unsubscribe` or `workload status` it later), then deltas. On overflow
//! or reconnect the collector re-sends a snapshot frame to resync.

use serde::{Deserialize, Serialize};

use super::actions::{Action, ActionId, AuthLevel, ids};
use super::workload::{UnsubscribeOutcome, WorkloadId};

/// Which OS domain an observer samples.
///
/// Each domain shares identical streaming semantics (snapshot → deltas →
/// events) — they differ only in payload shape, so they append here (and as
/// [`ObserverSnapshot`] / [`ObserverDelta`] / [`ObserverEvent`] variants)
/// without a new wire range or new action ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObserverDomain {
    /// Process tree + per-process and system CPU/mem/load.
    Process,
    /// Active network connections (by owning pid) + interface throughput.
    Network,
    /// systemd unit states (user scope).
    Services,
}

impl ObserverDomain {
    /// Short label used in `workload list` descriptions and CLI output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Network => "network",
            Self::Services => "services",
        }
    }
}

/// Subscribe to an observer domain.
///
/// Find-or-create the shared collector, refcount++, then stream a snapshot
/// then deltas against this `request_id`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ObserverSubscribeRequest {
    pub domain: ObserverDomain,
}

impl Action for ObserverSubscribeRequest {
    const ID: ActionId = ids::OBSERVER_SUBSCRIBE_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// First stream frame and every resync frame: the full current state.
///
/// Receiving it **resets** consumer state. Carries the [`WorkloadId`] so
/// a long-lived consumer can `Unsubscribe` / `workload status` it.
///
/// A snapshot too large for one frame arrives as this frame carrying a prefix
/// of the entities, followed by `continues` [`ObserverDeltaFrame`]s whose
/// `added` carry the rest (and nothing else); the snapshot is whole once they
/// are in. `fuz_client` assembles them and hands its caller only whole
/// snapshots. A delta or an event batch too large for one frame arrives as
/// several, each applying in turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverSnapshotFrame {
    pub workload_id: WorkloadId,
    /// How many delta frames, right after this one, complete the snapshot;
    /// `0` when it fits one frame.
    pub continues: u32,
    pub snapshot: ObserverSnapshot,
}

impl Action for ObserverSnapshotFrame {
    const ID: ActionId = ids::OBSERVER_SNAPSHOT_FRAME;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Per-domain full snapshot payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObserverSnapshot {
    Process(ProcessSnapshot),
    Network(NetworkSnapshot),
    Services(ServicesSnapshot),
}

/// Entity-level delta frame. `added` / `changed` carry full records; the
/// unit of change is the entity (no field-level diffing). `removed`
/// carries keys only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverDeltaFrame {
    pub delta: ObserverDelta,
}

impl Action for ObserverDeltaFrame {
    const ID: ActionId = ids::OBSERVER_DELTA_FRAME;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Per-domain delta payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObserverDelta {
    Process(ProcessDelta),
    Network(NetworkDelta),
    Services(ServicesDelta),
}

/// Discrete-event frame — the durable timeline (spawn / exit + cmdline),
/// distinct from the live snapshot/delta tree. A consumer may persist these
/// (to an events table, say); fuzd only emits them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverEventFrame {
    pub events: Vec<ObserverEvent>,
}

impl Action for ObserverEventFrame {
    const ID: ActionId = ids::OBSERVER_EVENT_FRAME;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Per-domain discrete event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObserverEvent {
    Process(ProcessEvent),
    Network(ConnectionEvent),
    Services(ServiceEvent),
}

/// Drop one subscription on this connection (refcount--; idle-grace stop
/// at zero).
///
/// The CLI follower tears down by closing the connection instead;
/// `Unsubscribe` is for long-lived consumers that hold one connection
/// across many subscriptions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ObserverUnsubscribeRequest {
    pub workload_id: WorkloadId,
}

impl Action for ObserverUnsubscribeRequest {
    const ID: ActionId = ids::OBSERVER_UNSUBSCRIBE_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverUnsubscribeResponse {
    pub outcome: UnsubscribeOutcome,
}

impl Action for ObserverUnsubscribeResponse {
    const ID: ActionId = ids::OBSERVER_UNSUBSCRIBE_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

//
// Process domain
//

/// Stable per-process identity: pid plus `/proc/<pid>/stat` field 22
/// (`start_time`, in clock ticks since boot).
///
/// pid alone is unstable (reuse); the pair is the PID-reuse defense and
/// the hierarchy join key (connections → owning pid, units → their pids
/// all key off this).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: i32,
    pub start_time: u64,
}

/// One process's sampled state.
///
/// `PartialEq` drives the collector's delta diff — a process is `changed`
/// only when its full record differs from what subscribers last saw
/// (idle processes with steady `cpu_pct == 0.0` and stable memory are
/// excluded, so deltas stay small).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub key: ProcessKey,
    /// Parent pid (`/proc/<pid>/stat` field 4).
    pub ppid: i32,
    /// `comm` — the executable name, truncated to 15 chars by the kernel.
    pub name: String,
    /// Process state code (`R`, `S`, `D`, `Z`, `T`, `I`, …).
    pub state: char,
    /// CPU usage as a percentage of one core since the previous sample
    /// (can exceed 100 for multi-threaded processes). `0.0` on the sample
    /// where the process first appears.
    pub cpu_pct: f32,
    /// Resident set size in bytes (`VmRSS` from `/proc/<pid>/status`).
    pub mem_bytes: u64,
    /// Full command line (NUL-joined argv, rendered space-separated), or
    /// `None` when unreadable or empty (kernel threads have no cmdline). Cut
    /// to at most 4 KiB, ending in `...` when cut. Like every string here it is
    /// another process's text, raw: escape it before display.
    pub cmdline: Option<String>,
}

/// Machine-wide CPU / memory / load (what the daemon's uid can see —
/// system-wide CPU and load are world-readable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResources {
    /// Aggregate CPU busy fraction since the previous sample, `0.0..=100.0`
    /// (normalized across all cores). `0.0` on the first sample.
    pub cpu_pct: f32,
    /// Online CPU count.
    pub ncpu: u32,
    /// Total physical memory in bytes (`MemTotal`).
    pub mem_total_bytes: u64,
    /// Available memory in bytes (`MemAvailable`).
    pub mem_available_bytes: u64,
    /// 1 / 5 / 15-minute load averages.
    pub load_1: f32,
    pub load_5: f32,
    pub load_15: f32,
    /// System uptime in seconds.
    pub uptime_secs: u64,
}

/// Full process-domain snapshot: machine-wide resources + every visible
/// process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub system: SystemResources,
    pub processes: Vec<ProcessInfo>,
}

/// Entity-level process delta. `system` is the refreshed machine-wide
/// resources each tick; `added` / `changed` carry full [`ProcessInfo`]
/// records; `removed` carries [`ProcessKey`]s only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDelta {
    pub system: SystemResources,
    pub added: Vec<ProcessInfo>,
    pub changed: Vec<ProcessInfo>,
    pub removed: Vec<ProcessKey>,
}

/// Discrete process-timeline event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessEvent {
    /// A process appeared since the previous sample.
    Spawn {
        key: ProcessKey,
        ppid: i32,
        name: String,
        cmdline: Option<String>,
    },
    /// A process disappeared since the previous sample.
    Exit { key: ProcessKey, name: String },
}

//
// Network domain
//

/// Stable per-connection identity: the socket inode, unique for the
/// socket's lifetime (the PID-reuse analogue — a 4-tuple alone recycles).
///
/// The 4-tuple (`local_addr` / `peer_addr`) rides [`ConnectionInfo`] for
/// display; the inode is the delta key and the join anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionKey {
    /// Socket inode (`/proc/net/{tcp,udp}` field 10; `socket:[inode]` in
    /// `/proc/<pid>/fd`).
    pub inode: u64,
}

/// Socket transport + address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketProtocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl SocketProtocol {
    /// Lowercase wire label (`tcp` / `tcp6` / `udp` / `udp6`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tcp6 => "tcp6",
            Self::Udp => "udp",
            Self::Udp6 => "udp6",
        }
    }
}

/// Kernel socket state — the `st` field of `/proc/net/{tcp,udp}` (the TCP
/// state machine, which UDP rows reuse: an unconnected UDP socket reads
/// `Close`, a `connect(2)`-ed one `Established`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    /// A state code outside the documented 0x01–0x0B range.
    Unknown,
}

impl SocketState {
    /// Map a `/proc/net/*` hex state code (`0x01`–`0x0B`) to a state.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::Established,
            0x02 => Self::SynSent,
            0x03 => Self::SynRecv,
            0x04 => Self::FinWait1,
            0x05 => Self::FinWait2,
            0x06 => Self::TimeWait,
            0x07 => Self::Close,
            0x08 => Self::CloseWait,
            0x09 => Self::LastAck,
            0x0A => Self::Listen,
            0x0B => Self::Closing,
            _ => Self::Unknown,
        }
    }
}

/// One active socket.
///
/// `PartialEq` drives the collector's delta diff — a connection is `changed`
/// only when its full record differs (e.g. a TCP socket walking the state
/// machine, or its owning pid resolving on a later sample).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub key: ConnectionKey,
    pub protocol: SocketProtocol,
    /// Local `ip:port` (display).
    pub local_addr: String,
    /// Peer `ip:port` (display; `0.0.0.0:0` / `[::]:0` for listeners).
    pub peer_addr: String,
    pub state: SocketState,
    /// Owning pid — the **process-domain cross-link** (the join key the
    /// host tree hangs off). `None` when no process this uid can see owns
    /// the socket (user scope: only our own `/proc/<pid>/fd` inodes resolve).
    pub pid: Option<i32>,
}

/// Per-interface throughput.
///
/// `rx_bytes` / `tx_bytes` are the cumulative kernel counters; `rx_bps` /
/// `tx_bps` are the bytes-per-second rates the collector derives between
/// successive samples (`0.0` on the first sample).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bps: f32,
    pub tx_bps: f32,
}

/// Full network snapshot: interface throughput + every visible connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub interfaces: Vec<InterfaceInfo>,
    pub connections: Vec<ConnectionInfo>,
}

/// Entity-level network delta.
///
/// `interfaces` is the refreshed throughput each tick (like `system` in the
/// process domain); `added` / `changed` carry full [`ConnectionInfo`] records;
/// `removed` carries [`ConnectionKey`]s only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDelta {
    pub interfaces: Vec<InterfaceInfo>,
    pub added: Vec<ConnectionInfo>,
    pub changed: Vec<ConnectionInfo>,
    pub removed: Vec<ConnectionKey>,
}

/// Discrete connection-timeline event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionEvent {
    /// A socket appeared since the previous sample.
    Open {
        key: ConnectionKey,
        protocol: SocketProtocol,
        local_addr: String,
        peer_addr: String,
        pid: Option<i32>,
    },
    /// A socket disappeared since the previous sample.
    Close {
        key: ConnectionKey,
        peer_addr: String,
    },
}

//
// Services domain
//

/// systemd unit activation state (the closed `ActiveState` set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnitActiveState {
    Active,
    Reloading,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Maintenance,
    /// An `ActiveState` outside the documented set.
    Unknown,
}

impl UnitActiveState {
    /// Parse systemd's `ActiveState` string.
    #[must_use]
    pub fn from_systemd(raw: &str) -> Self {
        match raw {
            "active" => Self::Active,
            "reloading" => Self::Reloading,
            "inactive" => Self::Inactive,
            "failed" => Self::Failed,
            "activating" => Self::Activating,
            "deactivating" => Self::Deactivating,
            "maintenance" => Self::Maintenance,
            _ => Self::Unknown,
        }
    }
}

/// One systemd unit's sampled state. Keyed by `name` (the unit name) for
/// deltas and the timeline.
///
/// `PartialEq` drives the delta diff; a transition event is emitted only
/// when `active_state` changes (sub-state/description churn alone is `changed`
/// but not a timeline transition).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceUnit {
    /// Unit name, e.g. `nginx.service` — the stable delta + timeline key.
    pub name: String,
    /// Unit-file load state (`loaded` / `not-found` / `masked` / …).
    pub load_state: String,
    pub active_state: UnitActiveState,
    /// Fine-grained sub-state (`running` / `dead` / `exited` / `failed` / …).
    pub sub_state: String,
    /// Human description.
    pub description: String,
    /// Main pid — the **process-domain cross-link**. `None` when the unit
    /// has no live main process (inactive, a oneshot that exited, or one
    /// this uid can't see).
    pub main_pid: Option<i32>,
}

/// Full services snapshot: every visible systemd unit (user scope v1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesSnapshot {
    pub units: Vec<ServiceUnit>,
}

/// Entity-level services delta — units diff by `name`. `added` / `changed`
/// carry full [`ServiceUnit`] records; `removed` carries unit names only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesDelta {
    pub added: Vec<ServiceUnit>,
    pub changed: Vec<ServiceUnit>,
    pub removed: Vec<String>,
}

/// Discrete unit-transition event (the durable services timeline).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceEvent {
    /// A unit's `active_state` changed (or it newly appeared) — the new
    /// state is recorded.
    Transition {
        name: String,
        active_state: UnitActiveState,
        sub_state: String,
        main_pid: Option<i32>,
    },
    /// A unit disappeared from the visible set.
    Removed { name: String },
}
