//! `Action` trait + stable `ActionId` constants + `AuthLevel`.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Stable `u16` identifier for one wire message type.
///
/// IDs are assigned explicitly in [`ids`]. The codec writes the explicit
/// `u16`, so reordering source declarations never affects the wire.
///
/// Range groupings:
/// * `0x0000` — reserved sentinel
/// * `0x0001 – 0x000F` — control plane (Hello / Ping / Pong / Goodbye)
/// * `0x0010 – 0x001F` — daemon lifecycle (Status / Shutdown)
/// * `0x0020 – 0x003F` — sidecar control (Start / Stop / Restart / Status)
/// * `0x0040 – 0x005F` — sidecar call dispatch (List / Run) — the hot path
/// * `0x0060 – 0x007F` — artifact ops (reserved)
/// * `0x0080 – 0x00FF` — key ops (reserved)
/// * `0x0100 – 0x010F` — generic workload control (List / Status / Stop)
/// * `0x0110 – 0x012F` — watcher workload kind (Subscribe / frames / Unsubscribe)
/// * `0x0190 – 0x01AF` — observer workload kind (Subscribe / frames / Unsubscribe)
/// * `0x0200+` — reserved
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(pub u16);

impl std::fmt::Display for ActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

/// Required auth posture for *receiving* an action.
///
/// A deliberately minimal two-level hierarchy (`Public` / `Keeper`).
/// Outgoing messages don't carry auth — the gate applies on receive, not
/// on send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthLevel {
    /// No credentials needed. Reserved for future expansion (no fuzd
    /// action actually sits here today; even Hello is admin-only since
    /// the only callers are same-uid local CLI / webui binaries).
    Public,
    /// Trusted same-uid local peer via `SO_PEERCRED`. All fuzd RPC
    /// methods sit here today.
    Keeper,
}

/// Pairs a Rust struct with its wire ID and the auth level required to
/// receive it.
///
/// The codec reads `A::ID` off the trait when writing — the writer cannot
/// pick the wrong `action_id` for a given struct.
///
/// **Not object-safe** — consumed only as a generic bound (`A: Action`) by
/// the codec (`write_frame` / `decode_payload`) and the dispatch gate; the
/// `Sized` supertrait + associated `const`s preclude `dyn` use anyway.
//
// TODO: every wire type carries a 4-line `impl Action for X { const ID;
// const AUTH; }`. A declarative `action!(Type, ID, AuthLevel)` macro could
// collapse them into one line apiece; kept explicit for now since the spelled-out
// impls read plainly next to each type and are trivial to scan/grep. Deferred,
// not rejected.
pub trait Action: Serialize + DeserializeOwned + Sized {
    const ID: ActionId;
    const AUTH: AuthLevel;
}

/// Concrete action IDs.
///
/// `0x0000` is reserved as a sentinel ("no action") and is never assigned.
/// New IDs are append-only inside each grouping: removing or reassigning
/// is a wire break (bump [`crate::PROTOCOL_VERSION`]).
pub mod ids {
    use super::ActionId;

    // Control plane (0x0001 – 0x000F).
    pub const HELLO_REQUEST: ActionId = ActionId(0x0001);
    pub const HELLO_RESPONSE: ActionId = ActionId(0x0002);
    pub const PING: ActionId = ActionId(0x0003);
    pub const PONG: ActionId = ActionId(0x0004);
    pub const GOODBYE: ActionId = ActionId(0x0005);

    // Daemon lifecycle (0x0010 – 0x001F).
    pub const DAEMON_STATUS_REQUEST: ActionId = ActionId(0x0010);
    pub const DAEMON_STATUS_RESPONSE: ActionId = ActionId(0x0011);
    pub const DAEMON_SHUTDOWN_REQUEST: ActionId = ActionId(0x0012);
    pub const DAEMON_SHUTDOWN_RESPONSE: ActionId = ActionId(0x0013);

    // Sidecar control (0x0020 – 0x003F).
    pub const SIDECAR_START_REQUEST: ActionId = ActionId(0x0020);
    pub const SIDECAR_START_RESPONSE: ActionId = ActionId(0x0021);
    pub const SIDECAR_STOP_REQUEST: ActionId = ActionId(0x0022);
    pub const SIDECAR_STOP_RESPONSE: ActionId = ActionId(0x0023);
    pub const SIDECAR_RESTART_REQUEST: ActionId = ActionId(0x0024);
    pub const SIDECAR_RESTART_RESPONSE: ActionId = ActionId(0x0025);
    pub const SIDECAR_STATUS_REQUEST: ActionId = ActionId(0x0026);
    pub const SIDECAR_STATUS_RESPONSE: ActionId = ActionId(0x0027);

    // Sidecar call dispatch (0x0040 – 0x005F) — the hot path. Invoke a
    // sidecar-hosted operation by name; distinct from the `tool` noun, which
    // names first-party @fuzdev binaries fuz installs.
    pub const SIDECAR_CALL_LIST_REQUEST: ActionId = ActionId(0x0040);
    pub const SIDECAR_CALL_LIST_RESPONSE: ActionId = ActionId(0x0041);
    pub const SIDECAR_CALL_RUN_REQUEST: ActionId = ActionId(0x0042);
    pub const SIDECAR_CALL_RUN_RESPONSE: ActionId = ActionId(0x0043);

    // Generic workload control (0x0100 – 0x010F). Kind-agnostic discovery
    // and teardown over the demand-driven workload registry. Per-kind
    // surfaces (subscribe, frames) live in each kind's own range.
    pub const WORKLOAD_LIST_REQUEST: ActionId = ActionId(0x0100);
    pub const WORKLOAD_LIST_RESPONSE: ActionId = ActionId(0x0101);
    pub const WORKLOAD_STATUS_REQUEST: ActionId = ActionId(0x0102);
    pub const WORKLOAD_STATUS_RESPONSE: ActionId = ActionId(0x0103);
    pub const WORKLOAD_STOP_REQUEST: ActionId = ActionId(0x0104);
    pub const WORKLOAD_STOP_RESPONSE: ActionId = ActionId(0x0105);

    // Watcher workload kind (0x0110 – 0x012F) — event-driven filesystem
    // watcher, path-set-parameterized. Subscribe streams a snapshot frame
    // (the watched roots) then event frames against one request_id; resync
    // re-sends the snapshot to signal a possible gap. A coverage frame carries
    // a coverage-only change (no gap, no event drop) decoupled from the
    // snapshot. A subscribe the daemon cannot serve gets one `FINAL` refused
    // frame instead of a stream. Distinct from the observer (push acquisition via inotify, no
    // delta diffing).
    pub const WATCHER_SUBSCRIBE_REQUEST: ActionId = ActionId(0x0110);
    pub const WATCHER_SNAPSHOT_FRAME: ActionId = ActionId(0x0111);
    pub const WATCHER_EVENT_FRAME: ActionId = ActionId(0x0112);
    pub const WATCHER_UNSUBSCRIBE_REQUEST: ActionId = ActionId(0x0113);
    pub const WATCHER_UNSUBSCRIBE_RESPONSE: ActionId = ActionId(0x0114);
    pub const WATCHER_COVERAGE_FRAME: ActionId = ActionId(0x0115);
    pub const WATCHER_SUBSCRIBE_REFUSED: ActionId = ActionId(0x0116);

    // Observer workload kind (0x0190 – 0x01AF) — poll-driven snapshot +
    // delta collectors (process / network / services), domain-parameterized.
    // Subscribe streams a snapshot frame then delta frames against one
    // request_id; resync re-sends a snapshot frame.
    pub const OBSERVER_SUBSCRIBE_REQUEST: ActionId = ActionId(0x0190);
    pub const OBSERVER_SNAPSHOT_FRAME: ActionId = ActionId(0x0191);
    pub const OBSERVER_DELTA_FRAME: ActionId = ActionId(0x0192);
    pub const OBSERVER_UNSUBSCRIBE_REQUEST: ActionId = ActionId(0x0193);
    pub const OBSERVER_UNSUBSCRIBE_RESPONSE: ActionId = ActionId(0x0194);
    pub const OBSERVER_EVENT_FRAME: ActionId = ActionId(0x0195);
}
