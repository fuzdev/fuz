//! Demand-driven workload registry.
//!
//! A workload is a registration that has clients. The registry maps a
//! shareable key (an observer domain, or a watcher's roots + recursion) to a
//! running collector task, tracks the refcount (active subscriptions), and
//! stops a collector after an idle grace once its refcount hits zero.
//! **Sharing is the point**: two clients subscribing the same key share one
//! collector.
//!
//! Lifecycle (refcount + idle-grace + the revive race) lives here under
//! one lock; the collector task is a dumb executor that obeys subscribe /
//! remove / drop commands and exits when its (child) stop token fires.
//!
//! The registry's command sends await room in a collector's bounded command
//! channel. That wait is bounded by one in-flight sample, because a collector
//! never awaits a subscriber (see [`collector`]) — it handles every command
//! without waiting — and it ends at once when the collector exits, which drops
//! the receiver.

pub mod bounds;
pub mod collector;
pub mod frame_split;
pub mod net_source;
pub mod observer;
pub mod proc_source;
pub mod services_source;
pub mod source;
pub mod watch_source;
pub mod watcher;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fuz_wire::{
    ObserverDomain, UnsubscribeOutcome, WorkloadId, WorkloadInfo, WorkloadKind, WorkloadStopOutcome,
};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::out::OutTx;
use collector::{COLLECTOR_CMD_CAP, CollectorCommand};
use observer::run_collector;
use source::ObserverSource;
use watch_source::WatchSource;
use watcher::run_watch_collector;

/// Default idle grace for cheap-to-rebuild workloads — the observer re-polls
/// instantly, so a brief re-subscribe (a tab flip, a tool re-invocation) costs
/// nothing to resume. The per-kind default lives in [`RegistryConfig`].
const OBSERVER_IDLE_GRACE: Duration = Duration::from_secs(5);

/// Idle grace for the watcher kind. Long, because re-establishing a watch does a
/// selective-recursive tree walk adding one inotify descriptor per directory —
/// so a brief consumer reconnect (a client daemon's restart) or a watch-set
/// change within the window resumes the *same* watcher instead of forcing a
/// full teardown + re-walk. The per-kind default lives in [`RegistryConfig`].
const WATCHER_IDLE_GRACE: Duration = Duration::from_secs(120);

/// Per-kind idle-grace policy: how long a zero-refcount workload of each kind
/// lingers before it's retired.
///
/// Fuzd-internal tuning — **not** a wire or user-facing config knob.
/// [`RegistryConfig::default`] holds the canonical values;
/// [`WorkloadRegistry::with_config`] injects an override (tuning, tests).
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Grace for observer workloads (cheap to re-establish — a re-poll).
    pub observer_grace: Duration,
    /// Grace for watcher workloads (expensive to re-establish — a re-walk).
    pub watcher_grace: Duration,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            observer_grace: OBSERVER_IDLE_GRACE,
            watcher_grace: WATCHER_IDLE_GRACE,
        }
    }
}

impl RegistryConfig {
    /// The idle grace for a workload of this key's kind.
    const fn idle_grace(&self, key: &WorkloadKey) -> Duration {
        match key {
            WorkloadKey::Observer(_) => self.observer_grace,
            WorkloadKey::Watcher(_) => self.watcher_grace,
        }
    }
}

/// Normalized identity of a watcher registration — the watched path-set + the
/// recursion flag. Clients passing the same set (in any order) share one watch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WatchKey {
    /// Sorted + deduped watch roots.
    pub roots: Vec<PathBuf>,
    pub recursive: bool,
}

/// Shareable identity of a workload — clients with the same key share one
/// collector.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum WorkloadKey {
    Observer(ObserverDomain),
    Watcher(WatchKey),
}

/// `(connection id, request id)` — identifies one subscription.
type SubId = (u64, u32);

/// A registered workload: its collector handle + lifecycle bookkeeping.
#[derive(Debug)]
struct Workload {
    id: WorkloadId,
    kind: WorkloadKind,
    description: String,
    /// Active subscriptions; `len()` is the refcount.
    subs: HashSet<SubId>,
    cmd_tx: mpsc::Sender<CollectorCommand>,
    /// Child of the registry root token: cancelled on idle-grace retire,
    /// manual stop, or daemon shutdown.
    stop: CancellationToken,
    /// Bumped on every event that should invalidate a pending retire (a
    /// retire arming, or a revive). A retire fires only if the gen it
    /// captured still matches — the revive-race guard.
    retire_gen: u64,
}

impl Workload {
    fn info(&self) -> WorkloadInfo {
        WorkloadInfo {
            id: self.id,
            kind: self.kind,
            description: self.description.clone(),
            subscribers: u32::try_from(self.subs.len()).unwrap_or(u32::MAX),
        }
    }
}

/// Registry internals, held behind one `Arc` so retire timers can capture
/// it without an `Arc<Self>`-typed receiver (not stable).
#[derive(Debug)]
struct Shared {
    workloads: Mutex<HashMap<WorkloadKey, Workload>>,
    /// Acquisition seam for the observer kind (poll-driven `/proc` etc.).
    source: Arc<dyn ObserverSource>,
    /// Acquisition seam for the watcher kind (event-driven filesystem).
    watch_source: Arc<dyn WatchSource>,
    /// Parent of every collector's stop token — cancel to stop all on
    /// daemon shutdown.
    root: CancellationToken,
    /// Per-kind idle-grace policy (how long a zero-refcount workload lingers).
    config: RegistryConfig,
    next_id: AtomicU64,
    next_conn: AtomicU64,
}

/// The daemon's workload registry. Lives in `AppState`; cheap to clone
/// (one `Arc`).
#[derive(Debug, Clone)]
pub struct WorkloadRegistry {
    shared: Arc<Shared>,
}

impl WorkloadRegistry {
    /// Create a registry over the given acquisition sources (observer +
    /// watcher) with the default [`RegistryConfig`]. `root` is the daemon
    /// shutdown token — collectors are children of it, so a single cancel stops
    /// them all.
    #[must_use]
    pub fn new(
        source: Arc<dyn ObserverSource>,
        watch_source: Arc<dyn WatchSource>,
        root: CancellationToken,
    ) -> Self {
        Self::with_config(source, watch_source, root, RegistryConfig::default())
    }

    /// Like [`WorkloadRegistry::new`] but with an explicit [`RegistryConfig`]
    /// (per-kind idle-grace overrides). The default suits production; this seam
    /// exists for tuning and tests.
    #[must_use]
    pub fn with_config(
        source: Arc<dyn ObserverSource>,
        watch_source: Arc<dyn WatchSource>,
        root: CancellationToken,
        config: RegistryConfig,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                workloads: Mutex::new(HashMap::new()),
                source,
                watch_source,
                root,
                config,
                next_id: AtomicU64::new(1),
                next_conn: AtomicU64::new(1),
            }),
        }
    }

    /// Allocate a fresh per-connection id (for subscription bookkeeping).
    #[must_use]
    pub fn next_conn_id(&self) -> u64 {
        self.shared.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// Find-or-create the workload for `key`, refcount++ this subscription, and
    /// stream the collector's snapshot + frames to `out_tx` against
    /// `request_id`. Returns the (possibly shared) workload id.
    ///
    /// `start` spawns the kind's collector — given the fresh id, the collector's
    /// command receiver, and a stop token — and returns its `(kind,
    /// description)`; it runs only when the workload is first created (a shared
    /// key reuses the running collector). The find-or-create + revive-race +
    /// refcount-insert is single-sourced here so both kinds share one correct
    /// copy; `observer_subscribe` / `watch_subscribe` supply only the per-kind
    /// key and `start`.
    async fn subscribe(
        &self,
        key: WorkloadKey,
        conn_id: u64,
        request_id: u32,
        out_tx: OutTx,
        start: impl FnOnce(
            WorkloadId,
            mpsc::Receiver<CollectorCommand>,
            CancellationToken,
        ) -> (WorkloadKind, String),
    ) -> WorkloadId {
        let (id, cmd_tx) = {
            let mut map = self.shared.workloads.lock();
            let shared = &self.shared;
            let entry = map.entry(key).or_insert_with(|| {
                let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
                let (cmd_tx, cmd_rx) = mpsc::channel(COLLECTOR_CMD_CAP);
                let stop = shared.root.child_token();
                let (kind, description) = start(id, cmd_rx, stop.clone());
                Workload {
                    id,
                    kind,
                    description,
                    subs: HashSet::new(),
                    cmd_tx,
                    stop,
                    retire_gen: 0,
                }
            });
            if entry.subs.is_empty() {
                // Reviving from idle: invalidate any pending retire timer.
                entry.retire_gen += 1;
            }
            entry.subs.insert((conn_id, request_id));
            (entry.id, entry.cmd_tx.clone())
        };
        if cmd_tx
            .send(CollectorCommand::AddSubscriber {
                conn_id,
                request_id,
                out_tx,
            })
            .await
            .is_err()
        {
            warn!(workload_id = id, "collector gone before AddSubscriber");
        }
        id
    }

    /// Subscribe a connection to an observer domain.
    ///
    /// Find-or-create the shared collector, refcount++, and tell the
    /// collector to stream a snapshot then deltas to `out_tx` against
    /// `request_id`. Returns the (possibly shared) workload id.
    pub async fn observer_subscribe(
        &self,
        domain: ObserverDomain,
        conn_id: u64,
        request_id: u32,
        out_tx: OutTx,
    ) -> WorkloadId {
        self.subscribe(
            WorkloadKey::Observer(domain),
            conn_id,
            request_id,
            out_tx,
            |id, cmd_rx, stop| {
                let source = Arc::clone(&self.shared.source);
                tokio::spawn(run_collector(domain, id, source, cmd_rx, stop));
                (
                    WorkloadKind::Observer,
                    format!("observer:{}", domain.label()),
                )
            },
        )
        .await
    }

    /// Subscribe a connection to a filesystem watch over `roots`.
    ///
    /// Find-or-create the shared watcher (the normalized `(roots, recursive)`
    /// key is the share point), refcount++, and tell the collector to stream a
    /// snapshot then event frames to `out_tx` against `request_id`. Returns the
    /// (possibly shared) workload id.
    pub async fn watch_subscribe(
        &self,
        roots: Vec<PathBuf>,
        recursive: bool,
        conn_id: u64,
        request_id: u32,
        out_tx: OutTx,
    ) -> WorkloadId {
        // Normalize so ["/a","/b"] and ["/b","/a"] share one watcher.
        let mut norm = roots;
        norm.sort();
        norm.dedup();
        let key = WorkloadKey::Watcher(WatchKey {
            roots: norm.clone(),
            recursive,
        });
        self.subscribe(key, conn_id, request_id, out_tx, move |id, cmd_rx, stop| {
            let watch_source = Arc::clone(&self.shared.watch_source);
            let description = format!(
                "watcher:{}",
                norm.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            tokio::spawn(run_watch_collector(
                norm,
                recursive,
                id,
                watch_source,
                cmd_rx,
                stop,
            ));
            (WorkloadKind::Watcher, description)
        })
        .await
    }

    /// Drop a connection's subscription(s) to one workload by id.
    ///
    /// Kind-agnostic — finds the workload by id and removes every subscription
    /// this connection holds on it (the unsubscribe frame carries its own
    /// `request_id`, distinct from the subscribe frame's, so we match on the
    /// connection, not the frame). Serves both observer and watcher kinds.
    pub async fn unsubscribe(&self, workload_id: WorkloadId, conn_id: u64) -> UnsubscribeOutcome {
        let (removed, cmd_tx, key, idle_gen) = {
            let mut map = self.shared.workloads.lock();
            let Some(key) = map
                .iter()
                .find(|(_, w)| w.id == workload_id)
                .map(|(k, _)| k.clone())
            else {
                return UnsubscribeOutcome::NotSubscribed;
            };
            let Some(w) = map.get_mut(&key) else {
                return UnsubscribeOutcome::NotSubscribed;
            };
            let removed: Vec<SubId> = w
                .subs
                .iter()
                .filter(|(c, _)| *c == conn_id)
                .copied()
                .collect();
            if removed.is_empty() {
                return UnsubscribeOutcome::NotSubscribed;
            }
            for sub in &removed {
                w.subs.remove(sub);
            }
            let idle_gen = if w.subs.is_empty() {
                w.retire_gen += 1;
                Some(w.retire_gen)
            } else {
                None
            };
            (removed, w.cmd_tx.clone(), key, idle_gen)
        };
        for (conn_id, request_id) in removed {
            let _ = cmd_tx
                .send(CollectorCommand::RemoveSubscriber {
                    conn_id,
                    request_id,
                })
                .await;
        }
        if let Some(generation) = idle_gen {
            arm_retire(&self.shared, key, generation);
        }
        UnsubscribeOutcome::Unsubscribed
    }

    /// Drop every subscription belonging to a closed connection.
    pub async fn drop_connection(&self, conn_id: u64) {
        let mut to_retire: Vec<(WorkloadKey, u64)> = Vec::new();
        let notifies: Vec<mpsc::Sender<CollectorCommand>> = {
            let mut map = self.shared.workloads.lock();
            let mut notifies = Vec::new();
            for (key, w) in map.iter_mut() {
                let before = w.subs.len();
                w.subs.retain(|(c, _)| *c != conn_id);
                if w.subs.len() != before {
                    notifies.push(w.cmd_tx.clone());
                    if w.subs.is_empty() {
                        w.retire_gen += 1;
                        to_retire.push((key.clone(), w.retire_gen));
                    }
                }
            }
            notifies
        };
        for cmd_tx in notifies {
            let _ = cmd_tx
                .send(CollectorCommand::DropConnection { conn_id })
                .await;
        }
        for (key, generation) in to_retire {
            arm_retire(&self.shared, key, generation);
        }
    }

    /// Every registered workload (the `workload list` surface).
    #[must_use]
    pub fn list(&self) -> Vec<WorkloadInfo> {
        self.shared
            .workloads
            .lock()
            .values()
            .map(Workload::info)
            .collect()
    }

    /// Status of one workload by id (`None` if not registered).
    #[must_use]
    pub fn status(&self, id: WorkloadId) -> Option<WorkloadInfo> {
        self.shared
            .workloads
            .lock()
            .values()
            .find(|w| w.id == id)
            .map(Workload::info)
    }

    /// Manually stop a workload by id, regardless of refcount.
    pub fn stop(&self, id: WorkloadId) -> WorkloadStopOutcome {
        let mut map = self.shared.workloads.lock();
        let Some(key) = map.iter().find(|(_, w)| w.id == id).map(|(k, _)| k.clone()) else {
            return WorkloadStopOutcome::NotFound;
        };
        if let Some(w) = map.remove(&key) {
            w.stop.cancel();
            debug!(workload_id = id, "workload stopped");
        }
        WorkloadStopOutcome::Stopped
    }
}

/// Arm a retire timer for an idle workload. After the kind's idle grace it
/// retires the workload iff it's still idle with the same generation.
fn arm_retire(shared: &Arc<Shared>, key: WorkloadKey, generation: u64) {
    let shared = Arc::clone(shared);
    let grace = shared.config.idle_grace(&key);
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        try_retire(&shared, &key, generation);
    });
}

/// Retire a workload iff it's still idle and no revive bumped its
/// generation since the retire was armed.
fn try_retire(shared: &Arc<Shared>, key: &WorkloadKey, generation: u64) {
    let mut map = shared.workloads.lock();
    let still_idle = map
        .get(key)
        .is_some_and(|w| w.retire_gen == generation && w.subs.is_empty());
    if still_idle && let Some(w) = map.remove(key) {
        w.stop.cancel();
        debug!(workload_id = w.id, "retired idle workload");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::out::OutFrame;
    use net_source::RawNetworkSample;
    use proc_source::{RawProcessSample, RawSystem};
    use services_source::RawServicesSample;
    use source::ObserverError;
    use watch_source::{WatchError, WatchGuard, WatchSession};

    #[derive(Debug)]
    struct NoopSource;
    impl ObserverSource for NoopSource {
        fn sample_process(&self) -> Result<RawProcessSample, ObserverError> {
            Ok(RawProcessSample {
                system: RawSystem {
                    ncpu: 1,
                    total_cpu_ticks: 0,
                    idle_cpu_ticks: 0,
                    mem_total_bytes: 0,
                    mem_available_bytes: 0,
                    load_1: 0.0,
                    load_5: 0.0,
                    load_15: 0.0,
                    uptime_secs: 0,
                },
                procs: vec![],
            })
        }

        fn sample_network(&self) -> Result<RawNetworkSample, ObserverError> {
            Ok(RawNetworkSample {
                interfaces: vec![],
                connections: vec![],
            })
        }

        fn sample_services(&self) -> Result<RawServicesSample, ObserverError> {
            Ok(RawServicesSample { units: vec![] })
        }
    }

    /// A watch source for registry-level tests: every `start` yields a session
    /// that emits no events and stops nothing on drop. The registry's grace /
    /// retire logic is independent of collector activity, so this keeps the
    /// timing tests hermetic — no real inotify thread, no filesystem.
    #[derive(Debug)]
    struct NoopWatchSource;
    impl WatchSource for NoopWatchSource {
        fn start(&self, _roots: &[PathBuf], _recursive: bool) -> Result<WatchSession, WatchError> {
            // The senders drop here: the collector sees closed channels and parks
            // (see `run_watch_collector`), which is all this double needs.
            let (_tx, events) = mpsc::unbounded_channel();
            let (_deg_tx, coverage_degradations) = mpsc::unbounded_channel();
            Ok(WatchSession {
                events,
                guard: WatchGuard::detached(),
                coverage: fuz_wire::WatchCoverage::Complete,
                coverage_degradations,
            })
        }
    }

    fn registry_with(watch_source: Arc<dyn WatchSource>) -> WorkloadRegistry {
        WorkloadRegistry::new(Arc::new(NoopSource), watch_source, CancellationToken::new())
    }

    fn registry() -> WorkloadRegistry {
        registry_with(Arc::new(watch_source::NotifyWatchSource::new()))
    }

    #[tokio::test]
    async fn subscribing_same_domain_shares_one_workload() {
        let reg = registry();
        let (tx1, _rx1) = mpsc::channel::<OutFrame>(16);
        let (tx2, _rx2) = mpsc::channel::<OutFrame>(16);
        let id1 = reg
            .observer_subscribe(ObserverDomain::Process, 1, 10, tx1)
            .await;
        let id2 = reg
            .observer_subscribe(ObserverDomain::Process, 2, 20, tx2)
            .await;
        assert_eq!(id1, id2, "same domain shares one collector");
        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].subscribers, 2);
        assert_eq!(list[0].kind, WorkloadKind::Observer);
        assert_eq!(list[0].description, "observer:process");
    }

    #[tokio::test]
    async fn unsubscribe_decrements_refcount() {
        let reg = registry();
        let (tx1, _rx1) = mpsc::channel::<OutFrame>(16);
        let (tx2, _rx2) = mpsc::channel::<OutFrame>(16);
        let id = reg
            .observer_subscribe(ObserverDomain::Process, 1, 10, tx1)
            .await;
        reg.observer_subscribe(ObserverDomain::Process, 2, 20, tx2)
            .await;
        let outcome = reg.unsubscribe(id, 1).await;
        assert_eq!(outcome, UnsubscribeOutcome::Unsubscribed);
        assert_eq!(reg.status(id).map(|w| w.subscribers), Some(1));
        // Unsubscribing from a connection that never subscribed.
        assert_eq!(
            reg.unsubscribe(id, 99).await,
            UnsubscribeOutcome::NotSubscribed
        );
    }

    #[tokio::test]
    async fn stop_removes_workload() {
        let reg = registry();
        let (tx, _rx) = mpsc::channel::<OutFrame>(16);
        let id = reg
            .observer_subscribe(ObserverDomain::Process, 1, 10, tx)
            .await;
        assert_eq!(reg.stop(id), WorkloadStopOutcome::Stopped);
        assert!(reg.list().is_empty());
        assert_eq!(reg.stop(id), WorkloadStopOutcome::NotFound);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_workload_retires_after_grace() {
        let reg = registry();
        let (tx, _rx) = mpsc::channel::<OutFrame>(16);
        let id = reg
            .observer_subscribe(ObserverDomain::Process, 1, 10, tx)
            .await;
        // Connection drops → refcount 0 → retire armed.
        reg.drop_connection(1).await;
        // Still present within the grace window.
        assert!(reg.status(id).is_some());
        // Let the spawned retire task poll once so its sleep timer is
        // registered against the (paused) clock before we advance it.
        tokio::task::yield_now().await;
        // Advance past the grace period; the retire timer fires.
        tokio::time::advance(OBSERVER_IDLE_GRACE + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(reg.list().is_empty(), "idle workload retired after grace");
    }

    #[tokio::test(start_paused = true)]
    async fn resubscribe_within_grace_cancels_retire() {
        let reg = registry();
        let (tx, _rx) = mpsc::channel::<OutFrame>(16);
        let id = reg
            .observer_subscribe(ObserverDomain::Process, 1, 10, tx)
            .await;
        reg.drop_connection(1).await;
        // A new subscriber arrives before grace expires → revive.
        let (tx2, _rx2) = mpsc::channel::<OutFrame>(16);
        let id2 = reg
            .observer_subscribe(ObserverDomain::Process, 2, 20, tx2)
            .await;
        assert_eq!(id, id2, "revived the same workload");
        // The stale retire must not kill the revived workload.
        tokio::time::advance(OBSERVER_IDLE_GRACE + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            reg.status(id).is_some(),
            "revived workload survives stale retire"
        );
    }

    /// Per-kind idle-grace: a watcher outlives the short observer grace, and a
    /// resubscribe within its grace reattaches to the *same* watcher (no
    /// teardown, no selective-recursive re-walk); the observer still retires at
    /// the short grace.
    #[tokio::test(start_paused = true)]
    async fn watcher_grace_outlives_observer_grace() {
        let reg = registry_with(Arc::new(NoopWatchSource));
        let roots = vec![PathBuf::from("/test/watch/root")];

        // One observer + one watcher on the same connection.
        let (otx, _orx) = mpsc::channel::<OutFrame>(16);
        let observer_id = reg
            .observer_subscribe(ObserverDomain::Process, 1, 10, otx)
            .await;
        let (wtx, _wrx) = mpsc::channel::<OutFrame>(16);
        let watcher_id = reg.watch_subscribe(roots.clone(), true, 1, 11, wtx).await;

        // The connection drops → both go to refcount 0 → both arm a retire.
        reg.drop_connection(1).await;
        tokio::task::yield_now().await;

        // Past the short observer grace, before the long watcher grace: the
        // observer has retired, the watcher is still alive.
        tokio::time::advance(OBSERVER_IDLE_GRACE + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            reg.status(observer_id).is_none(),
            "observer retired at the short grace"
        );
        assert!(
            reg.status(watcher_id).is_some(),
            "watcher survives past the short observer grace"
        );

        // A resubscribe within the watcher grace reattaches to the same watcher.
        let (wtx2, _wrx2) = mpsc::channel::<OutFrame>(16);
        let watcher_id2 = reg.watch_subscribe(roots, true, 2, 20, wtx2).await;
        assert_eq!(
            watcher_id, watcher_id2,
            "within-grace resubscribe reattaches to the same watcher (no re-walk)"
        );

        // Drop again; once the full watcher grace elapses it finally retires.
        reg.drop_connection(2).await;
        tokio::task::yield_now().await;
        tokio::time::advance(WATCHER_IDLE_GRACE + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            reg.list().is_empty(),
            "watcher retires after its full grace"
        );
    }
}
