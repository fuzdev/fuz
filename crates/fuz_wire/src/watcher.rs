//! Watcher workload kind payloads (0x0110 – 0x012F).
//!
//! The watcher kind watches a filesystem path-set and streams change events to
//! subscribers. It is the **event-driven** (push, inotify-backed) sibling of
//! the [`observer`](crate::observer) kind: same stream *delivery* (frames on
//! one `request_id`), different *acquisition* (push vs. poll) — so it earns a
//! distinct kind.
//!
//! Unlike the observer it has **no delta frame**: a filesystem watch is a pure
//! append-only event stream, not a diffable entity set. A subscription opens
//! with one [`WatcherSnapshotFrame`] (the watched roots — the "what am I
//! watching" config, *not* a directory listing), then [`WatcherEventFrame`]s as
//! files change. On overflow / resync the collector re-sends the snapshot frame
//! to signal a possible gap (the consumer treats it as "reset your fs region").
//!
//! Coverage changes ride a separate [`WatcherCoverageFrame`], **not** the
//! snapshot: a watch coming up partial, degrading after establishment, or
//! recovering is a label change with no event gap, so re-sending the snapshot
//! (which means "reset your fs region", dropping the first event batch) would be
//! wrong. The dedicated frame keeps the snapshot's single "gap / fresh
//! subscription" meaning while still pushing every coverage transition.
//!
//! Subscribe and register are one step (like the observer): there's no
//! register-without-subscription use. The snapshot frame carries the
//! [`WorkloadId`] so a long-lived consumer can `Unsubscribe` / `workload
//! status` it.

use serde::{Deserialize, Serialize};

use super::actions::{Action, ActionId, AuthLevel, ids};
use super::workload::{UnsubscribeOutcome, WorkloadId};

/// Subscribe to a filesystem watch over `roots`.
///
/// Find-or-create the shared watcher (clients passing the same normalized
/// `(roots, recursive)` share one inotify watch — the kind's whole point),
/// refcount++, then stream a snapshot then events against this `request_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherSubscribeRequest {
    /// Filesystem paths to watch (absolute, as the daemon's uid sees them).
    pub roots: Vec<String>,
    /// Watch subdirectories too (the daemon applies a built-in ignore set for
    /// heavy dirs like `node_modules` / `.git` / `target` so a real workspace
    /// stays under the inotify watch budget).
    pub recursive: bool,
}

impl Action for WatcherSubscribeRequest {
    const ID: ActionId = ids::WATCHER_SUBSCRIBE_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// First stream frame and every resync frame: the watch configuration.
///
/// Receiving it tells the consumer to **reset** its fs-event region (a fresh
/// subscription, or a resync after a dropped event batch). Carries the
/// [`WorkloadId`] so a long-lived consumer can `Unsubscribe` / `workload
/// status` it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherSnapshotFrame {
    pub workload_id: WorkloadId,
    pub snapshot: WatchSnapshot,
}

impl Action for WatcherSnapshotFrame {
    const ID: ActionId = ids::WATCHER_SNAPSHOT_FRAME;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// The watch configuration — what the watcher is watching. There is no
/// filesystem *listing* here; a watcher streams change events, it does not
/// enumerate the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchSnapshot {
    /// The watched roots (echoed back so the consumer knows the watched-dirs
    /// region).
    pub roots: Vec<String>,
    pub recursive: bool,
    /// How faithfully the watch covers `roots`. A selective-recursive watch can
    /// come up with blind spots, so `roots` alone overstates coverage — this is
    /// the honest signal a consumer needs to know whether its fs region is a
    /// faithful view or a silent partial one. The snapshot carries the *current*
    /// coverage (so a fresh subscriber and a post-gap resync are correct), but
    /// coverage *changes* during a stable subscription arrive on a dedicated
    /// [`WatcherCoverageFrame`], not by re-sending this snapshot.
    pub coverage: WatchCoverage,
}

/// How much of a requested watch is actually under a live filesystem watch.
///
/// A [`WatchSnapshot`]'s `roots` say what was *asked* for; this says what was
/// *achieved*. The watcher walks the tree adding a non-recursive watch per
/// directory, so it can run out of inotify budget mid-walk or hit an unreadable
/// directory — leaving blind spots the bare root list hides. [`Complete`] is the
/// only state where "what am I watching" equals "what I asked to watch".
///
/// [`Complete`]: WatchCoverage::Complete
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchCoverage {
    /// Not yet established — the watch is being brought up, or is between
    /// establishment attempts. Coverage isn't known yet (assume nothing). A
    /// cleanly-established watch transitions out of `Unknown` to `Complete` via a
    /// [`WatcherCoverageFrame`] (no event gap), so a healthy watch reports
    /// `Complete`, not a lingering `Unknown`.
    Unknown,
    /// Every attempted watch established. The region is fully covered.
    Complete,
    /// Some directories went unwatched. `unwatched` counts the dropped blind-spot
    /// **subtrees** (a failed watch drops a whole subtree, counted once), not
    /// individual directories — so it's a floor on the real blind-spot size.
    Partial { unwatched: u32 },
    /// No root could be watched — the region is dark, no events will arrive. The
    /// daemon log names the cause (inotify budget vs permissions vs gone).
    Unavailable,
}

/// The daemon's answer to a [`WatcherSubscribeRequest`] it will not serve: one
/// `FINAL` frame on the request id, in place of the stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherSubscribeRefused {
    pub reason: WatchRefusal,
}

impl Action for WatcherSubscribeRefused {
    const ID: ActionId = ids::WATCHER_SUBSCRIBE_REFUSED;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// Why a watch subscription was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchRefusal {
    /// The roots are too long for the watch's snapshot frame, which echoes
    /// them, to fit one frame: `encoded` bytes against a `limit`.
    RootsTooLarge { encoded: u64, limit: u64 },
}

/// A coverage-only update — the watch's coverage changed without an event gap.
///
/// Decoupled from [`WatcherSnapshotFrame`] (which means "reset your fs region"):
/// a coverage change (coming up [`Partial`], degrading after establishment, or
/// recovering) is a label update the consumer applies *in place*, keeping its
/// event region. This lets the daemon push **every** coverage transition —
/// including a clean establishment's `Unknown` → [`Complete`] — without the
/// disruptive resync that would drop the first event batch.
///
/// [`Complete`]: WatchCoverage::Complete
/// [`Partial`]: WatchCoverage::Partial
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WatcherCoverageFrame {
    pub workload_id: WorkloadId,
    pub coverage: WatchCoverage,
}

impl Action for WatcherCoverageFrame {
    const ID: ActionId = ids::WATCHER_COVERAGE_FRAME;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// A coalesced batch of filesystem change events. A flush too large for one
/// frame arrives as several of these, in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherEventFrame {
    pub events: Vec<WatchEvent>,
}

impl Action for WatcherEventFrame {
    const ID: ActionId = ids::WATCHER_EVENT_FRAME;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

/// One filesystem change.
///
/// User-scoped v1 carries no owning pid — inotify does not report the touching
/// process (that needs `fanotify` + `CAP_SYS_ADMIN`), so the consumer attaches
/// fs events to the watched-dirs region rather than a pid. The privileged
/// collector seam can fill a pid later without changing this shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchEvent {
    /// Absolute path that changed.
    pub path: String,
    pub kind: WatchEventKind,
}

/// The kind of filesystem change. Coalesced from the OS backend's finer-grained
/// event taxonomy (inotify / `FSEvents`) to the three the consumers care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchEventKind {
    /// A path appeared.
    Created,
    /// An existing path's contents or metadata changed.
    Modified,
    /// A path disappeared.
    Removed,
}

/// Drop one subscription on this connection (refcount--; idle-grace stop at
/// zero).
///
/// The CLI follower tears down by closing the connection instead; `Unsubscribe`
/// is for long-lived consumers holding one connection across many
/// subscriptions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WatcherUnsubscribeRequest {
    pub workload_id: WorkloadId,
}

impl Action for WatcherUnsubscribeRequest {
    const ID: ActionId = ids::WATCHER_UNSUBSCRIBE_REQUEST;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WatcherUnsubscribeResponse {
    pub outcome: UnsubscribeOutcome,
}

impl Action for WatcherUnsubscribeResponse {
    const ID: ActionId = ids::WATCHER_UNSUBSCRIBE_RESPONSE;
    const AUTH: AuthLevel = AuthLevel::Keeper;
}
