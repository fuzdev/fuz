//! `WatchSource` — the acquisition seam for watcher collectors.
//!
//! v1 ships one impl, [`NotifyWatchSource`], backed by the `notify` crate
//! (inotify on Linux, `FSEvents` on macOS). Like [`super::source::ObserverSource`]
//! the seam is object-safe (`Arc<dyn WatchSource>`) so the mechanism — a test
//! double, or a future privileged `fanotify` helper that could attribute the
//! touching pid — swaps without touching the collector or the wire.
//!
//! ## Selective recursion
//!
//! A naive recursive watch over a dev workspace establishes one inotify
//! descriptor per directory, and `node_modules` / `target` trees blow the
//! `fs.inotify.max_user_watches` budget instantly. So [`NotifyWatchSource`]
//! walks the tree itself, adding a **non-recursive** watch per directory while
//! skipping the [`IGNORED_DIR_NAMES`] heavy trees, and re-watches new
//! directories as they're created. The watched count stays proportional to the
//! source tree, not the build artifacts.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fuz_wire::{WatchCoverage, WatchEvent, WatchEventKind};
use notify::{EventKind, RecursiveMode, Watcher};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Directory names never watched or reported — heavy or noisy trees that would
/// exhaust the inotify watch budget and flood the event stream. Skipped at
/// watch establishment (no descriptor) and filtered out of events.
pub const IGNORED_DIR_NAMES: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    ".svelte-kit",
    "build",
];

/// How long the processing thread blocks on a backend event before
/// re-checking the stop flag (also bounds watch-teardown latency).
const RAW_RECV_POLL: Duration = Duration::from_millis(250);

/// The one actionable knob for an exhausted inotify budget — single-sourced so
/// every budget-related warning agrees: the total-failure path (via
/// [`WatchError::hint`]) and the partial-walk path (via [`warn_incomplete_walk`])
/// both point here when watches are dropped for lack of budget.
pub const INOTIFY_BUDGET_HINT: &str = "raise fs.inotify.max_user_watches or narrow the watch path";

/// The actionable knob for a directory whose children can't be enumerated —
/// single-sourced (like [`INOTIFY_BUDGET_HINT`]) so the partial-walk warning
/// (via [`warn_incomplete_walk`]) words the permissions remedy consistently. An
/// unreadable dir is a *partial*-walk cause only: it requires its own watch to
/// have succeeded first, so it can't arise on the total-failure path.
pub const PERMISSIONS_HINT: &str = "check directory permissions";

/// The actionable knob for a requested **root** that doesn't exist — single-sourced
/// so the partial-walk warning ([`warn_incomplete_walk`]) and the total-failure
/// hint ([`WatchError::hint`]) word it identically. Distinct from a vanished
/// *child* (a benign mid-walk race): a missing root is a persistent blind spot —
/// nothing watches its parent, so there's no dynamic re-watch recovery.
pub const MISSING_ROOT_HINT: &str = "a requested watch path does not exist";

/// Minimum spacing between "live re-watch is incomplete" warnings on the watch
/// thread. A burst of directory creations (a checkout, an archive extract) can
/// each re-walk and fail; without this every one would warn. Bounds a
/// persistently over-budget watch to one warning per interval.
const PARTIAL_REWATCH_WARN_INTERVAL: Duration = Duration::from_secs(5);

/// Failure to establish a filesystem watch.
#[derive(Debug, Error)]
pub enum WatchError {
    /// The OS backend refused (commonly the inotify watch limit is exhausted).
    #[error("filesystem watch backend error: {0}")]
    Backend(String),
    /// No roots were requested (an empty path-set).
    #[error("no watchable directory under the requested root(s)")]
    NoWatchableRoots,
    /// Every requested root was dropped — the watch is dark. Carries the
    /// breakdown so the cause is named (budget vs other vs missing) instead of
    /// guessing; `vanished_roots` are requested roots that don't exist. There's no
    /// `unreadable` term: an unreadable dir is one whose *children* can't be
    /// enumerated, which requires its own watch to have succeeded — impossible when
    /// every root's watch failed. (Likewise no benign child-`vanished` term — a
    /// child vanish requires its root to have watched, so `watched >= 1`.)
    #[error(
        "no root could be watched ({budget} over inotify budget, {other} other error(s), \
         {vanished_roots} missing)"
    )]
    AllRootsFailed {
        budget: usize,
        other: usize,
        vanished_roots: usize,
    },
}

impl WatchError {
    /// The actionable remediation for this failure's dominant cause, if any —
    /// so the caller logs the right knob instead of always blaming the budget.
    #[must_use]
    pub const fn hint(&self) -> Option<&'static str> {
        match self {
            Self::Backend(_) => Some(INOTIFY_BUDGET_HINT),
            Self::AllRootsFailed { budget, .. } if *budget > 0 => Some(INOTIFY_BUDGET_HINT),
            Self::AllRootsFailed { vanished_roots, .. } if *vanished_roots > 0 => {
                Some(MISSING_ROOT_HINT)
            }
            // NoWatchableRoots (empty input) and an all-`other` failure have no
            // single knob to turn — the error is unexpected (logged verbatim).
            Self::NoWatchableRoots | Self::AllRootsFailed { .. } => None,
        }
    }
}

/// Acquisition seam for watcher collectors.
///
/// **Object-safe** — held as `Arc<dyn WatchSource>` so the watch mechanism can
/// be swapped (test double, privileged helper) without touching the collector
/// or the wire.
pub trait WatchSource: Send + Sync + std::fmt::Debug + 'static {
    /// Begin watching `roots`. Returns a live [`WatchSession`]: a receiver of
    /// cleaned [`WatchEvent`]s plus a guard whose drop stops the watch
    /// (releasing every descriptor).
    ///
    /// # Errors
    ///
    /// Returns [`WatchError`] when the backend can't establish the watch (e.g.
    /// the inotify limit is exhausted, or every root is missing) — the caller
    /// surfaces an actionable hint rather than failing silently.
    fn start(&self, roots: &[PathBuf], recursive: bool) -> Result<WatchSession, WatchError>;
}

/// A live watch: cleaned events out + a guard that stops the watch on drop.
pub struct WatchSession {
    /// Cleaned filesystem events (ignored paths already filtered).
    pub events: mpsc::UnboundedReceiver<WatchEvent>,
    /// Dropping this stops the backend watch. The collector holds it for the
    /// life of the subscription.
    pub guard: WatchGuard,
    /// How faithfully this watch covers the requested roots — [`Complete`] or
    /// [`Partial`] (a live session always watched ≥1 dir; total failure is the
    /// `Err` path). The collector forwards it to subscribers on the snapshot.
    ///
    /// [`Complete`]: WatchCoverage::Complete
    /// [`Partial`]: WatchCoverage::Partial
    pub coverage: WatchCoverage,
    /// Post-establishment coverage degradations from the watch thread: each item
    /// is the count of additional blind-spot subtrees a live re-watch left dark (a
    /// newly-created dir whose subtree couldn't be fully watched — an inotify
    /// budget exhaustion mid-run). The collector folds these into `coverage`
    /// **monotonically** — a live re-watch can't cheaply learn a blind spot
    /// cleared, so recovery to [`Complete`](WatchCoverage::Complete) waits for a
    /// full re-establishment. A source with no live-rewatch path (a test double)
    /// leaves this channel idle.
    pub coverage_degradations: mpsc::UnboundedReceiver<u32>,
}

impl std::fmt::Debug for WatchSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchSession").finish_non_exhaustive()
    }
}

/// Stops a [`WatchSession`] on drop: sets the processing thread's stop flag, so
/// the thread drops the backend watcher and releases its descriptors.
#[derive(Debug)]
pub struct WatchGuard {
    stop: Arc<AtomicBool>,
}

impl WatchGuard {
    /// A guard that stops nothing on drop — for test doubles (and any
    /// [`WatchSource`] whose backend lifetime is managed elsewhere).
    #[must_use]
    pub fn detached() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Real OS filesystem watcher (the v1 [`WatchSource`]): `notify`-backed.
#[derive(Debug, Default)]
pub struct NotifyWatchSource;

impl NotifyWatchSource {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl WatchSource for NotifyWatchSource {
    fn start(&self, roots: &[PathBuf], recursive: bool) -> Result<WatchSession, WatchError> {
        if roots.is_empty() {
            return Err(WatchError::NoWatchableRoots);
        }
        // notify delivers events to its own thread via the closure; forward
        // them on a std channel to a processing thread that *owns* the watcher,
        // so it can add watches for newly-created directories (the watcher
        // itself owns the closure, so it can't re-watch from inside it).
        let (raw_tx, raw_rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = raw_tx.send(res);
        })
        .map_err(|e| WatchError::Backend(e.to_string()))?;

        let mut walk = WalkOutcome::default();
        for root in roots {
            walk += watch_tree(&mut watcher, root, recursive);
        }
        if walk.watched == 0 {
            // Nothing came up. Hand back the breakdown so the collector logs the
            // real cause; an all-`vanished` walk just means the roots are gone.
            return Err(WatchError::AllRootsFailed {
                budget: walk.budget_failures,
                other: walk.other_failures,
                vanished_roots: walk.vanished_roots,
            });
        }
        if walk.is_complete() {
            debug!(
                roots = roots.len(),
                watched = walk.watched,
                recursive,
                "watch established"
            );
        } else {
            // Some directories watched, some dropped — the watch came up with
            // blind spots (a mid-walk inotify-budget exhaustion or an unreadable
            // dir). Fail loud rather than serve a silently-partial watch. A
            // benign removal race (a `vanished` dir) is *not* a blind spot, so it
            // doesn't reach here.
            warn_incomplete_walk(&walk, "watch establishment");
        }

        let (clean_tx, clean_rx) = mpsc::unbounded_channel::<WatchEvent>();
        // The watch thread's return path to the collector: live re-watch
        // degradations (a newly-created dir whose subtree couldn't be fully
        // watched), so post-establishment blind spots reach `coverage`, not just
        // the throttled log.
        let (coverage_tx, coverage_rx) = mpsc::unbounded_channel::<u32>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("fuzd-watch".to_owned())
            .spawn(move || {
                process_events(
                    &raw_rx,
                    &mut watcher,
                    recursive,
                    &clean_tx,
                    &coverage_tx,
                    &stop_thread,
                );
                // Dropping the watcher releases every descriptor.
                drop(watcher);
            })
            .map_err(|e| WatchError::Backend(e.to_string()))?;

        Ok(WatchSession {
            events: clean_rx,
            guard: WatchGuard { stop },
            coverage: walk.coverage(),
            coverage_degradations: coverage_rx,
        })
    }
}

/// The tally of a selective-recursive watch walk: how many directories went
/// under a live watch, and how the rest were dropped — split by cause so a
/// partial establishment is surfaced with the *accurate* hint (the inotify
/// budget and a permissions problem want different knobs), and so a benign
/// removal race isn't mistaken for a blind spot.
///
/// `watched + (the failure buckets)` don't sum to a directory count: a
/// `watch()` failure drops a whole *subtree* (counted once, never descended),
/// and an unreadable dir is itself watched (it's its *children* that are dark).
/// So the failure buckets count blind-spot **subtrees**, a floor on real size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WalkOutcome {
    /// Directories now under a live (non-recursive) watch.
    watched: usize,
    /// `watch()` calls that failed with the inotify watch budget exhausted
    /// (`notify` `MaxFilesWatch`, i.e. `ENOSPC`) — the subtree is dark and the
    /// knob is [`INOTIFY_BUDGET_HINT`]. The expected partial-watch cause.
    budget_failures: usize,
    /// `read_dir()` calls that failed for a non-transient reason (permissions) —
    /// the directory is watched but its children can't be enumerated, so an
    /// unknown-size subtree is dark. Points at permissions, *not* the budget.
    unreadable_dirs: usize,
    /// `watch()` calls that failed for some *other* reason (an I/O error that
    /// isn't budget-or-gone) — dark subtree, but neither standard knob applies.
    other_failures: usize,
    /// **Child** `watch()`/`read_dir()` calls that failed because the path was
    /// gone (`PathNotFound` / `NotFound`) — a benign removal race mid-walk. The
    /// directory no longer exists *and its parent is watched*, so a reappearance
    /// self-heals via the dynamic re-watch: **not** a blind spot, excluded from
    /// [`unwatched`](Self::unwatched) and never warned about.
    vanished: usize,
    /// **Root** `watch()` calls that failed because the requested root doesn't
    /// exist (`PathNotFound` / `NotFound`). Unlike a vanished child this **is** a
    /// blind spot: nothing watches a root's parent, so there's no dynamic re-watch
    /// recovery — the requested path is simply dark. Counted in
    /// [`unwatched`](Self::unwatched); the knob is [`MISSING_ROOT_HINT`].
    vanished_roots: usize,
}

impl WalkOutcome {
    /// Blind-spot subtrees left dark — the real failure modes, *excluding* benign
    /// child-`vanished` races (a removed child whose parent is watched isn't an
    /// unwatched dir). A vanished *root* **is** counted: it has no recovery path.
    const fn unwatched(self) -> usize {
        self.budget_failures + self.unreadable_dirs + self.other_failures + self.vanished_roots
    }

    /// True when the walk left no blind spots (a `vanished`-only walk is still
    /// complete — the missing dirs are gone, not unwatched).
    const fn is_complete(self) -> bool {
        self.unwatched() == 0
    }

    /// The coverage of a *live* walk (`watched >= 1`; `watched == 0` is the
    /// `Err` path, not coverage). Drives [`WatchSession::coverage`].
    fn coverage(self) -> WatchCoverage {
        if self.is_complete() {
            WatchCoverage::Complete
        } else {
            WatchCoverage::Partial {
                unwatched: u32::try_from(self.unwatched()).unwrap_or(u32::MAX),
            }
        }
    }

    /// Record one failed **child** `watch()` call. A child vanish is benign — its
    /// parent is watched, so a reappearance self-heals via the dynamic re-watch.
    fn record_watch_failure(&mut self, err: &notify::Error) {
        match classify_watch_failure(err) {
            WatchFailure::Budget => self.budget_failures += 1,
            WatchFailure::Gone => self.vanished += 1,
            WatchFailure::Other => self.other_failures += 1,
        }
    }

    /// Record the failed **root** `watch()` call. Same classification, but a
    /// *missing* root is a **blind spot**, not a benign race: nothing watches a
    /// root's parent, so there's no dynamic re-watch recovery — so a `Gone` root
    /// lands in [`vanished_roots`](Self::vanished_roots) (counted in
    /// [`unwatched`](Self::unwatched)), not the benign `vanished`.
    fn record_root_watch_failure(&mut self, err: &notify::Error) {
        match classify_watch_failure(err) {
            WatchFailure::Budget => self.budget_failures += 1,
            WatchFailure::Gone => self.vanished_roots += 1,
            WatchFailure::Other => self.other_failures += 1,
        }
    }
}

/// How a failed `watch()` call is bucketed — the classification shared by the root
/// and child recorders, which differ only in where a [`Gone`](WatchFailure::Gone)
/// path lands (benign for a child, a blind spot for a root).
enum WatchFailure {
    /// The inotify watch budget is exhausted (`MaxFilesWatch` / `ENOSPC`).
    Budget,
    /// The path is gone (`PathNotFound`, or an `Io` `NotFound`) — a missing path.
    Gone,
    /// Anything else — an unexpected backend error.
    Other,
}

/// Classify a `notify` watch failure. Single-sources the subtle "gone" detection
/// (both `PathNotFound` *and* an `Io` `NotFound`), so the root and child recorders
/// can't drift on what counts as a missing path.
fn classify_watch_failure(err: &notify::Error) -> WatchFailure {
    match &err.kind {
        notify::ErrorKind::MaxFilesWatch => WatchFailure::Budget,
        notify::ErrorKind::PathNotFound => WatchFailure::Gone,
        notify::ErrorKind::Io(e) if e.kind() == std::io::ErrorKind::NotFound => WatchFailure::Gone,
        _ => WatchFailure::Other,
    }
}

impl std::ops::AddAssign for WalkOutcome {
    fn add_assign(&mut self, rhs: Self) {
        self.watched += rhs.watched;
        self.budget_failures += rhs.budget_failures;
        self.unreadable_dirs += rhs.unreadable_dirs;
        self.other_failures += rhs.other_failures;
        self.vanished += rhs.vanished;
        self.vanished_roots += rhs.vanished_roots;
    }
}

/// Loudly report a selective-recursive walk that left blind spots — the watch is
/// live but partial, so a consumer's "what am I watching" overstates coverage.
/// The remediation names only the failure modes that actually occurred, so a
/// pure-permissions partial doesn't get told to raise the inotify budget.
fn warn_incomplete_walk(walk: &WalkOutcome, context: &str) {
    let mut remedies: Vec<&str> = Vec::new();
    if walk.budget_failures > 0 {
        remedies.push(INOTIFY_BUDGET_HINT);
    }
    if walk.unreadable_dirs > 0 {
        remedies.push(PERMISSIONS_HINT);
    }
    if walk.other_failures > 0 {
        remedies.push("see the backend error above");
    }
    if walk.vanished_roots > 0 {
        remedies.push(MISSING_ROOT_HINT);
    }
    warn!(
        context,
        watched = walk.watched,
        budget_failures = walk.budget_failures,
        unreadable_dirs = walk.unreadable_dirs,
        other_failures = walk.other_failures,
        vanished = walk.vanished,
        vanished_roots = walk.vanished_roots,
        unwatched = walk.unwatched(),
        "filesystem watch incomplete — {} blind-spot subtree(s) unwatched; {}",
        walk.unwatched(),
        remedies.join("; "),
    );
}

/// Watch `root` (and, when `recursive`, every non-ignored descendant directory)
/// non-recursively. Returns a [`WalkOutcome`] tallying the watches established
/// and the directories dropped, so a partial walk can be surfaced.
fn watch_tree<W: Watcher>(watcher: &mut W, root: &Path, recursive: bool) -> WalkOutcome {
    let mut walk = WalkOutcome::default();
    if let Err(err) = watcher.watch(root, RecursiveMode::NonRecursive) {
        // The *root* watch — a missing root is a blind spot (no recovery path),
        // unlike a vanished child (benign). See `record_root_watch_failure`.
        walk.record_root_watch_failure(&err);
        return walk;
    }
    walk.watched = 1;
    if !recursive {
        return walk;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // Gone between watch and enumeration — a benign removal race, not a
            // blind spot (the subtree no longer exists).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                walk.vanished += 1;
                continue;
            }
            // Watched, but its children can't be enumerated (permissions) — an
            // unknown-size subtree goes dark. Count it (don't silently skip).
            Err(_) => {
                walk.unreadable_dirs += 1;
                continue;
            }
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if is_ignored_name(&entry.file_name()) {
                continue;
            }
            let child = entry.path();
            match watcher.watch(&child, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    walk.watched += 1;
                    stack.push(child);
                }
                // No watch on this dir → it (and its subtree, never descended) is
                // a blind spot — bucketed by cause (budget / gone / other).
                Err(err) => walk.record_watch_failure(&err),
            }
        }
    }
    walk
}

/// Drain the backend's raw events: filter ignored paths, map to the coarse
/// [`WatchEventKind`], re-watch newly-created directories, and forward cleaned
/// events. Runs on a dedicated OS thread that owns `watcher`; exits when the
/// guard sets `stop` or the collector drops the receiver.
fn process_events<W: Watcher>(
    raw_rx: &std::sync::mpsc::Receiver<notify::Result<notify::Event>>,
    watcher: &mut W,
    recursive: bool,
    clean_tx: &mpsc::UnboundedSender<WatchEvent>,
    coverage_tx: &mpsc::UnboundedSender<u32>,
    stop: &AtomicBool,
) {
    // Rate-limits the live-blind-spot warning below so a creation burst doesn't
    // warn per event.
    let mut last_partial_warn: Option<Instant> = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match raw_rx.recv_timeout(RAW_RECV_POLL) {
            Ok(Ok(event)) => {
                let Some(kind) = map_event_kind(event.kind) else {
                    continue;
                };
                for path in &event.paths {
                    // Filter on the event's own leaf name only. The walk skips
                    // ignored dirs at establishment, so the only ignored events
                    // that arrive are direct-child entries naming one (e.g. a
                    // `node_modules` created under a watched parent). Checking
                    // *every* component would also match an ignored segment in a
                    // watch root's own ancestor path (a root under `.../build/…`),
                    // silently dropping every event under it.
                    if path.file_name().is_some_and(is_ignored_name) {
                        continue;
                    }
                    // Selective recursion: a new *real* directory (no symlink
                    // follow — matching the establishment walk's `file_type`, so a
                    // symlinked dir can't graft a watch onto its target tree) under
                    // a watched tree gets its own watch (+ non-ignored descendants).
                    if recursive
                        && kind == WatchEventKind::Created
                        && fuz_sys::fs::is_real_dir(path)
                    {
                        let walk = watch_tree(watcher, path, true);
                        if !walk.is_complete() {
                            // A live blind spot — the re-watch of a new subtree
                            // dropped dirs. Report the degradation count to the
                            // collector so `coverage` reflects it (not just the
                            // log), then warn loudly but throttled. (The send is
                            // unthrottled — coverage should track reality; budget
                            // exhaustion mid-run is rare, so the per-re-watch frame
                            // it drives is acceptable.)
                            let _ = coverage_tx
                                .send(u32::try_from(walk.unwatched()).unwrap_or(u32::MAX));
                            let now = Instant::now();
                            if last_partial_warn.is_none_or(|t| {
                                now.duration_since(t) >= PARTIAL_REWATCH_WARN_INTERVAL
                            }) {
                                last_partial_warn = Some(now);
                                warn_incomplete_walk(&walk, "live re-watch");
                            }
                        }
                    }
                    if clean_tx
                        .send(WatchEvent {
                            path: path.to_string_lossy().into_owned(),
                            kind,
                        })
                        .is_err()
                    {
                        return; // collector gone
                    }
                }
            }
            Ok(Err(err)) => debug!(%err, "watch backend reported an error"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Map the backend's fine-grained event taxonomy to the three kinds consumers
/// track. Access events and the catch-all variants are dropped.
const fn map_event_kind(kind: EventKind) -> Option<WatchEventKind> {
    match kind {
        EventKind::Create(_) => Some(WatchEventKind::Created),
        EventKind::Modify(_) => Some(WatchEventKind::Modified),
        EventKind::Remove(_) => Some(WatchEventKind::Removed),
        EventKind::Access(_) | EventKind::Any | EventKind::Other => None,
    }
}

/// True if `name` is an ignored directory name.
fn is_ignored_name(name: &OsStr) -> bool {
    IGNORED_DIR_NAMES.iter().any(|ig| name == OsStr::new(ig))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests panic on setup/assertion failure by design"
)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind, RemoveKind};

    #[test]
    fn ignored_name_matches_heavy_dirs_only() {
        assert!(is_ignored_name(OsStr::new("node_modules")));
        assert!(is_ignored_name(OsStr::new(".git")));
        assert!(is_ignored_name(OsStr::new("target")));
        assert!(!is_ignored_name(OsStr::new("src")));
        assert!(!is_ignored_name(OsStr::new("lib")));
    }

    #[test]
    fn ignored_filter_matches_the_leaf_name_not_an_ancestor_segment() {
        // The event's leaf name is what's filtered: a `node_modules` / `.git`
        // entry a watched parent reports is dropped.
        let leaf = |p: &str| Path::new(p).file_name().is_some_and(is_ignored_name);
        assert!(leaf("/home/u/dev/app/node_modules"));
        assert!(leaf("/home/u/dev/app/.git"));
        // But an event *under* a watch root whose own ancestor path contains an
        // ignored segment (a root at `.../build/…`) must NOT be filtered —
        // checking every component would silently drop every event under it.
        assert!(!leaf("/home/u/build/app/src/main.rs"));
        assert!(!leaf("/home/u/dev/app/src/main.rs"));
    }

    #[test]
    fn event_kind_maps_create_modify_remove_and_drops_access() {
        assert_eq!(
            map_event_kind(EventKind::Create(CreateKind::File)),
            Some(WatchEventKind::Created)
        );
        assert_eq!(
            map_event_kind(EventKind::Modify(ModifyKind::Any)),
            Some(WatchEventKind::Modified)
        );
        assert_eq!(
            map_event_kind(EventKind::Remove(RemoveKind::File)),
            Some(WatchEventKind::Removed)
        );
        assert_eq!(
            map_event_kind(EventKind::Access(notify::event::AccessKind::Any)),
            None
        );
        assert_eq!(map_event_kind(EventKind::Any), None);
    }

    #[test]
    fn watch_tree_skips_ignored_subtrees() {
        // dir/{src/, node_modules/, .git/} — only dir + dir/src get watched.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::create_dir(root.join("src").join("nested")).unwrap();
        std::fs::create_dir(root.join("node_modules")).unwrap();
        std::fs::create_dir(root.join("node_modules").join("pkg")).unwrap();
        std::fs::create_dir(root.join(".git")).unwrap();

        let (raw_tx, _raw_rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = raw_tx.send(res);
        })
        .expect("watcher");
        // root + src + src/nested = 3 (node_modules + .git pruned).
        let walk = watch_tree(&mut watcher, root, true);
        assert_eq!(
            walk.watched, 3,
            "watches root + src + src/nested, skips node_modules + .git"
        );
        assert!(walk.is_complete(), "a clean tempdir walk drops nothing");
    }

    #[test]
    fn watch_tree_non_recursive_watches_only_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("src")).unwrap();
        let (raw_tx, _raw_rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = raw_tx.send(res);
        })
        .expect("watcher");
        assert_eq!(
            watch_tree(&mut watcher, dir.path(), false).watched,
            1,
            "non-recursive = root only"
        );
    }

    /// What error a [`FailingWatcher`] raises for a failed path — one per
    /// `notify::ErrorKind` branch of [`WalkOutcome::record_watch_failure`].
    #[derive(Default, Clone, Copy)]
    enum FailKind {
        /// inotify budget exhausted (`MaxFilesWatch`) — the expected blind spot.
        #[default]
        Budget,
        /// The path vanished mid-walk (`PathNotFound`) — a benign removal race.
        Vanished,
        /// Some other I/O error — a blind spot with no standard remediation.
        Other,
    }

    /// A test-double `Watcher` whose `watch()` fails (with `fail_kind`) for any
    /// path at or under one of `fail_under`, and records the rest. Drives every
    /// failure-classification branch deterministically — no real inotify
    /// exhaustion, no real missing path.
    #[derive(Default)]
    struct FailingWatcher {
        fail_under: Vec<PathBuf>,
        fail_kind: FailKind,
        watched: Vec<PathBuf>,
    }

    impl Watcher for FailingWatcher {
        fn new<F: notify::EventHandler>(
            _handler: F,
            _config: notify::Config,
        ) -> notify::Result<Self> {
            // The walk constructs the double directly; `new` exists only to
            // satisfy the trait and is never called.
            Ok(Self::default())
        }
        fn watch(&mut self, path: &Path, _mode: RecursiveMode) -> notify::Result<()> {
            if self.fail_under.iter().any(|p| path.starts_with(p)) {
                return Err(match self.fail_kind {
                    FailKind::Budget => notify::Error::new(notify::ErrorKind::MaxFilesWatch),
                    FailKind::Vanished => notify::Error::new(notify::ErrorKind::PathNotFound),
                    FailKind::Other => notify::Error::generic("test: other watch failure"),
                });
            }
            self.watched.push(path.to_path_buf());
            Ok(())
        }
        fn unwatch(&mut self, _path: &Path) -> notify::Result<()> {
            Ok(())
        }
        fn kind() -> notify::WatcherKind {
            notify::WatcherKind::NullWatcher
        }
    }

    #[test]
    fn watch_tree_counts_budget_failures_as_blind_spots() {
        // root/{src/nested/, lib/}; fail every watch at/under `src` with the
        // inotify-budget error, so the walk watches root + lib and counts src as
        // one dropped budget subtree (its `nested` child is never reached — the
        // failed dir isn't descended).
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::create_dir(root.join("src").join("nested")).unwrap();
        std::fs::create_dir(root.join("lib")).unwrap();

        let mut watcher = FailingWatcher {
            fail_under: vec![root.join("src")],
            fail_kind: FailKind::Budget,
            ..FailingWatcher::default()
        };
        let walk = watch_tree(&mut watcher, root, true);
        assert_eq!(walk.watched, 2, "root + lib watched");
        assert_eq!(walk.budget_failures, 1, "src is one dropped budget subtree");
        assert_eq!(walk.unreadable_dirs, 0);
        assert_eq!(walk.other_failures, 0);
        assert_eq!(walk.vanished, 0);
        assert_eq!(walk.unwatched(), 1);
        assert!(
            !walk.is_complete(),
            "a dropped watch makes the walk incomplete"
        );
        assert_eq!(walk.coverage(), WatchCoverage::Partial { unwatched: 1 });
    }

    #[test]
    fn watch_tree_vanished_dir_is_not_a_blind_spot() {
        // A dir removed between enumeration and watch (`PathNotFound`) is a benign
        // race, *not* a blind spot: counted as `vanished`, excluded from
        // `unwatched()`, so the walk stays complete and quiet, which
        // keeps a checkout/extract churn from warning about the inotify budget.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::create_dir(root.join("lib")).unwrap();

        let mut watcher = FailingWatcher {
            fail_under: vec![root.join("src")],
            fail_kind: FailKind::Vanished,
            ..FailingWatcher::default()
        };
        let walk = watch_tree(&mut watcher, root, true);
        assert_eq!(walk.watched, 2, "root + lib watched");
        assert_eq!(walk.vanished, 1, "src vanished mid-walk");
        assert_eq!(
            walk.budget_failures, 0,
            "a removal race isn't a budget failure"
        );
        assert_eq!(
            walk.unwatched(),
            0,
            "a vanished dir is not an unwatched blind spot"
        );
        assert!(walk.is_complete(), "a vanished-only walk is still complete");
        assert_eq!(walk.coverage(), WatchCoverage::Complete);
    }

    #[test]
    fn watch_tree_vanished_root_is_a_blind_spot() {
        // A *root* that doesn't exist (its own watch fails NotFound) is a blind
        // spot, not a benign race: nothing watches its parent, so a reappearance
        // can't self-heal (no dynamic re-watch) — the vanished-root edge. Contrast
        // `watch_tree_vanished_dir_is_not_a_blind_spot` (a *child*, which is benign).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut watcher = FailingWatcher {
            fail_under: vec![dir.path().to_path_buf()],
            fail_kind: FailKind::Vanished,
            ..FailingWatcher::default()
        };
        let walk = watch_tree(&mut watcher, dir.path(), true);
        assert_eq!(walk.watched, 0, "the root itself couldn't be watched");
        assert_eq!(walk.vanished_roots, 1, "a missing root is a blind spot");
        assert_eq!(walk.vanished, 0, "not bucketed as a benign child vanish");
        assert!(
            !walk.is_complete(),
            "a vanished root leaves the region incomplete"
        );
        assert_eq!(walk.unwatched(), 1);
    }

    #[test]
    fn vanished_root_alongside_a_survivor_degrades_to_partial() {
        // The edge `start` sums per-root: a surviving root (a clean subtree) plus a
        // vanished root must report Partial, not Complete. Were the vanished root
        // counted in the benign bucket, the sum would hide the dark root as Complete.
        let mut combined = WalkOutcome {
            watched: 3,
            ..WalkOutcome::default()
        };
        combined += WalkOutcome {
            watched: 0,
            vanished_roots: 1,
            ..WalkOutcome::default()
        };
        assert!(
            !combined.is_complete(),
            "a dark root degrades the summed coverage"
        );
        assert_eq!(combined.coverage(), WatchCoverage::Partial { unwatched: 1 });
    }

    #[test]
    fn watch_tree_other_failure_is_a_blind_spot_without_the_budget_hint() {
        // A non-budget, non-vanish watch error is still a blind spot, but in its
        // own bucket so the warn doesn't misattribute it to the inotify budget.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir(root.join("src")).unwrap();

        let mut watcher = FailingWatcher {
            fail_under: vec![root.join("src")],
            fail_kind: FailKind::Other,
            ..FailingWatcher::default()
        };
        let walk = watch_tree(&mut watcher, root, true);
        assert_eq!(walk.watched, 1, "root watched, src dropped");
        assert_eq!(walk.other_failures, 1);
        assert_eq!(
            walk.budget_failures, 0,
            "an unexpected error isn't a budget failure"
        );
        assert!(
            !walk.is_complete(),
            "an other-error subtree is a blind spot"
        );
    }

    #[test]
    fn watch_tree_stays_complete_when_every_watch_succeeds() {
        // The quiet path: a double that fails nothing → no blind spots, no warn.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("src")).unwrap();
        let mut watcher = FailingWatcher::default();
        let walk = watch_tree(&mut watcher, dir.path(), true);
        assert_eq!(walk.watched, 2, "root + src");
        assert_eq!(walk.unwatched(), 0);
        assert!(
            walk.is_complete(),
            "a fully-successful walk is complete (and stays quiet)"
        );
        assert_eq!(walk.coverage(), WatchCoverage::Complete);
    }

    #[test]
    fn watch_tree_root_failure_yields_zero_watched() {
        // The total-failure feeder: a root whose watch fails → watched 0, which
        // `start` turns into `AllRootsFailed` carrying the breakdown (not a
        // partial-failure warn).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut watcher = FailingWatcher {
            fail_under: vec![dir.path().to_path_buf()],
            fail_kind: FailKind::Budget,
            ..FailingWatcher::default()
        };
        let walk = watch_tree(&mut watcher, dir.path(), true);
        assert_eq!(walk.watched, 0);
        assert_eq!(walk.budget_failures, 1);
        assert!(!walk.is_complete());
    }

    #[test]
    fn watch_tree_counts_unreadable_dirs() {
        // A dir that watches fine but can't be enumerated (mode 000) → its
        // unknown-size subtree is a blind spot, counted as one unreadable dir.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::create_dir(locked.join("child")).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Probe: running as root can still read a 000 dir, which would make the
        // assertion vacuous — skip in that case.
        let still_readable = std::fs::read_dir(&locked).is_ok();

        let mut watcher = FailingWatcher::default();
        let walk = watch_tree(&mut watcher, dir.path(), true);

        // Restore before asserting so tempdir cleanup can remove `locked`.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        if still_readable {
            return;
        }
        assert_eq!(walk.watched, 2, "root + locked watched");
        assert_eq!(walk.unreadable_dirs, 1, "locked can't be enumerated");
        assert_eq!(
            walk.budget_failures, 0,
            "an unreadable dir isn't a watch failure"
        );
        assert!(!walk.is_complete());
    }

    #[test]
    fn watch_error_hint_names_the_dominant_cause() {
        // The enriched total-failure error points at the right knob per cause —
        // budget wins when present, else a missing root points at the path, else
        // there's nothing to turn (an unreadable dir can't fail a root, so
        // permissions never reach the total-failure path).
        let budget = WatchError::AllRootsFailed {
            budget: 2,
            other: 0,
            vanished_roots: 0,
        };
        assert_eq!(budget.hint(), Some(INOTIFY_BUDGET_HINT));

        let gone = WatchError::AllRootsFailed {
            budget: 0,
            other: 0,
            vanished_roots: 4,
        };
        assert_eq!(
            gone.hint(),
            Some(MISSING_ROOT_HINT),
            "every root is a missing path"
        );

        let other = WatchError::AllRootsFailed {
            budget: 0,
            other: 2,
            vanished_roots: 0,
        };
        assert_eq!(other.hint(), None, "an unexpected error has no single knob");

        assert_eq!(WatchError::NoWatchableRoots.hint(), None);
    }
}
