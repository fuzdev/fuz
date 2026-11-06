//! Interrupt honesty — the process-global registry of live staging roots, and
//! the best-effort drain a signal task runs before the process exits.
//!
//! `Drop` cleans up an interrupted install only when the stack unwinds, and a
//! signal does not unwind: with no handler installed, SIGINT (Ctrl-C),
//! SIGTERM, and SIGHUP end the process with the `.fuzi-installing-<rand>` tree still on
//! disk. This module is the half of the cleanup that lives in the library — every
//! [`StagingTree`](crate::staging::StagingTree) registers its root here for
//! exactly as long as it owns it, and [`drain_staging_roots`] removes whatever
//! is still registered when the signal arrives.
//!
//! **The signal handling itself is deliberately not here.** `fuzi_core` stays
//! runtime-agnostic; the `fuzi` binary owns the tokio signal task that calls
//! [`drain_staging_roots`] and then exits `128 + signum`. That split is also
//! what makes the drain legal: `remove_dir_all` is not async-signal-safe, so it
//! must run on an ordinary thread woken by tokio's self-pipe rather than inside
//! a raw handler (which `unsafe_code = "forbid"` rules out anyway).
//!
//! # The swap race
//!
//! A drain that fired *between* `rename(staging → node_modules)` and the
//! deregistration would delete **through** a directory that has just become the
//! live `node_modules`: `remove_dir_all` opens the root and then unlinks
//! relative to that descriptor, so the rename does not save the tree an already
//! open drain is walking. Deleting a user's live `node_modules` is the one
//! outcome worse than leaking a staging dir, so the registry mutex doubles as
//! the swap's mutual exclusion — [`StagingRegistration::publish`] deregisters
//! *and* performs the rename while holding it, and the drain holds it across
//! its own removals.
//!
//! Mutual exclusion alone only orders the two, though; it does not stop a swap
//! that lost the race from running *afterwards*, and by then the tree it would
//! publish is gone (or half-removed). That swap's **first** act is to rename the
//! live `node_modules` aside to `.fuzi-old-<rand>` — so a process that exits a
//! moment later leaves the user's tree parked under a name [`clean`](crate::clean())
//! deletes. The claim is therefore recorded *in the locked state*: the drain
//! moves the roots it takes into [`Registry::drained`], and a `publish` whose
//! root is drained **refuses** — before the closure runs, so no rename ever
//! starts.
//!
//! A drain and a swap therefore never interleave, and the "drain first" order
//! is not merely ordered but **terminal**: the swap does not happen at all, and
//! `node_modules` is left exactly as it was. The price is a mutual wait — a
//! drain waits out an in-flight swap (two renames, three on the
//! restore-on-failure path), and a swap that arrives during a drain waits out
//! the removals and then refuses.
//!
//! # The creation race
//!
//! The same lock closes the other end of a staging tree's life. A signal during
//! the fetch phase fires a drain with nothing registered, and the install
//! thread can still reach [`StagingTree::create`](crate::staging::StagingTree::create)
//! in the moment before the signal task exits the process. A `mkdir` there,
//! registered or not, would be a tree no drain will ever look at again.
//!
//! So creation is one critical section too: [`StagingRegistration::register`]
//! takes the lock, **refuses** if a drain has fired ([`Registry::fired`]), and
//! otherwise runs the `mkdir` and records the root before releasing it. Every
//! ordering is then accounted for:
//!
//! - a drain that fired first is seen under the lock, and no directory is made;
//! - a drain that fires while the `mkdir` runs waits on the lock, and finds the
//!   root already registered when it gets it;
//! - a drain that fires later finds the root like any other live tree.
//!
//! Registering first and creating after (or the other way round) in two
//! critical sections would leave a window either way: a drain between them
//! removes a path that does not exist yet, or finds no path at all, and the
//! `mkdir` then leaks. The price is that a drain waits out one `mkdir`, as it
//! waits out a swap's renames.
//!
//! # Scope
//!
//! This closes the *signal* leak only. A release-build panic still aborts
//! (`panic = "abort"` runs no destructors), and SIGKILL / power loss run
//! nothing at all — [`clean`](crate::clean()) stays the backstop for those.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// The registry's locked state: which staging roots are live, and which a drain
/// has already claimed.
///
/// One struct behind one mutex rather than two statics, because the two facts
/// are only meaningful together — a `publish` decides whether to swap by reading
/// both in the same critical section the drain writes them in.
///
/// `pub` only because [`STAGING_ROOTS`] and [`StagingRegistration::register`]
/// name it across the crate and the test-only helpers hand it back out; this
/// module is private, so the type never leaves the crate, and its fields stay
/// private to this module.
#[derive(Debug)]
pub struct Registry {
    /// Staging roots currently owned by a live
    /// [`StagingTree`](crate::staging::StagingTree).
    ///
    /// In practice at most one entry (v0 supports one install per process), but
    /// nothing depends on that.
    roots: Vec<PathBuf>,
    /// Roots a drain has taken out of `roots` and (best effort) removed.
    ///
    /// A claim, not a log: [`StagingRegistration::publish`] refuses for a root
    /// listed here, because the tree it would rename into place is gone or
    /// half-gone. Recorded per root rather than as one process-wide flag so the
    /// refusal names exactly the trees a drain took — and so a test can stage
    /// the condition on its own (random) root without steering every other
    /// test's publish in this process.
    ///
    /// Never cleared, and safe not to be: a staging root's name ends in a
    /// 64-bit random suffix, so no later tree is ever handed a drained root's
    /// path — a stale claim has nothing to refuse but the tree it was made for.
    /// (In practice the question does not arise, since a drain is the last
    /// thing that happens before the process exits; that is the expected usage,
    /// not the reason this is sound.)
    drained: Vec<PathBuf>,
    /// Whether a drain has started — set first thing, roots or none.
    ///
    /// What [`drain_fired`] reads: once a drain fires, the signal task owns the
    /// process's output and its exit status, and the install thread must not
    /// render an outcome (its error is the drain's doing, and its exit would
    /// race the drain's `128 + signum`). Process-wide on purpose, unlike
    /// `drained`: the question is about the process, not one tree.
    ///
    /// Also what [`StagingRegistration::register`] refuses on: no staging tree
    /// is created once a drain has fired, because no drain would remove it
    /// (see the module docs' creation race).
    fired: bool,
}

impl Registry {
    /// The empty registry — `const` so the static needs no lazy-init dance.
    const fn new() -> Self {
        Self {
            roots: Vec::new(),
            drained: Vec::new(),
            fired: false,
        }
    }

    /// Start a drain on the locked state: record that one fired, and claim
    /// every live root — taken out of `roots` and listed in `drained`, so from
    /// here on a `publish` for one of them refuses instead of renaming the live
    /// `node_modules` aside for a tree the drain is deleting. Returns the
    /// claimed roots, for the caller to remove under the same lock.
    fn begin_drain(&mut self) -> Vec<PathBuf> {
        self.fired = true;
        let roots = std::mem::take(&mut self.roots);
        self.drained.extend(roots.iter().cloned());
        roots
    }

    /// Whether a drain has claimed `root`.
    fn is_drained(&self, root: &Path) -> bool {
        self.drained.iter().any(|claimed| claimed == root)
    }
}

/// The process-global staging registry.
///
/// Process-global because the drain runs on a thread that has no access to the
/// install's call stack.
///
/// Crate-visible only so [`StagingTree::create`](crate::staging::StagingTree::create)
/// can name the registry it registers into (a test hands it a private one
/// instead). Holding it grants nothing else: [`Registry`]'s fields are private
/// to this module, so a lock taken elsewhere can only block.
pub static STAGING_ROOTS: Mutex<Registry> = Mutex::new(Registry::new());

/// Lock `registry`, ignoring poisoning.
///
/// A poisoned registry means some thread panicked while holding it; the
/// contained [`Registry`] has no invariant a panic could have broken, and
/// refusing to clean up because of an unrelated panic would be strictly worse
/// than proceeding.
fn lock(registry: &Mutex<Registry>) -> MutexGuard<'_, Registry> {
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A staging root's membership in a [`Registry`] (in production,
/// [`STAGING_ROOTS`]), held for as long as its
/// [`StagingTree`](crate::staging::StagingTree) owns the directory.
///
/// Registered on construction — in the same critical section that creates the
/// directory — and deregistered on drop (the ordinary unwound return) or by
/// [`publish`](Self::publish) (the atomic swap). The drop half is why an `Err`
/// anywhere in materialization needs no explicit bookkeeping.
#[derive(Debug)]
pub struct StagingRegistration {
    /// The registry the root is listed in, so `publish` and `Drop` take back
    /// out exactly what `register` put in.
    registry: &'static Mutex<Registry>,
    /// The registered root, or `None` once [`publish`](Self::publish) has
    /// already deregistered it (which disarms the `Drop`).
    root: Option<PathBuf>,
}

/// [`StagingRegistration::register`] declined to create the staging root: a
/// drain has already fired in this process.
///
/// Like [`PublishRefused`], a distinct type the one caller
/// ([`StagingTree::create`](crate::staging::StagingTree::create)) translates
/// into its own vocabulary, so the interrupt path stays an ordinary error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterRefused;

/// [`StagingRegistration::publish`] declined to run the swap: a drain had
/// already claimed this staging root.
///
/// A distinct type rather than an `Option`, so the one caller
/// ([`StagingTree::commit`](crate::staging::StagingTree::commit)) has to say
/// what an interrupted publish means in *its* vocabulary — this module knows
/// nothing about `FuziError`, and the library must never exit or panic on the
/// interrupt path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishRefused;

impl StagingRegistration {
    /// Create `root` with `create` and register it as a live staging tree in
    /// `registry`, **both while holding the registry lock** — unless a drain has
    /// already fired, in which case `create` never runs.
    ///
    /// The creation seam, the mirror of [`publish`](Self::publish): holding the
    /// lock across the `mkdir` is what leaves no instant in which the tree
    /// exists but a drain could miss it (see the module docs' creation race). A
    /// drain that fires while `create` runs waits on the lock, then finds the
    /// root registered and removes it.
    ///
    /// Returns what `create` returned: `Ok(Ok(registration))` once the root
    /// exists and is registered, `Ok(Err(e))` if `create` failed — nothing is
    /// registered then, since `create` made nothing to clean up.
    ///
    /// # Errors
    ///
    /// [`RegisterRefused`] if a drain has fired in this process (with or
    /// without roots to remove — a fetch-phase interrupt has none). The signal
    /// task is about to exit; a tree made now would be removed by no one and
    /// leak to `fuzi clean`.
    ///
    /// `create` runs **with the registry lock held**, so it must not touch the
    /// registry itself (the lock is not reentrant), and it should stay one
    /// `mkdir`: a drain waits it out before its deadline starts.
    pub fn register<E>(
        registry: &'static Mutex<Registry>,
        root: PathBuf,
        create: impl FnOnce(&Path) -> Result<(), E>,
    ) -> Result<Result<Self, E>, RegisterRefused> {
        let mut locked = lock(registry);
        if locked.fired {
            return Err(RegisterRefused);
        }
        if let Err(source) = create(&root) {
            return Ok(Err(source));
        }
        locked.roots.push(root.clone());
        Ok(Ok(Self {
            registry,
            root: Some(root),
        }))
    }

    /// Deregister the root and run `publish` **while still holding the registry
    /// lock**, returning what it returns — unless a drain has already claimed
    /// the root, in which case the closure never runs.
    ///
    /// The swap seam: `publish` is the `rename` that turns the staging root
    /// into the live `node_modules`, and running it under the lock is what
    /// makes a concurrent [`drain_staging_roots`] impossible to interleave with
    /// (see the module docs). Deregistering first — rather than after — also
    /// means a drain that wins the lock race afterwards finds nothing to
    /// remove, instead of a path that now names the published tree.
    ///
    /// # Errors
    ///
    /// [`PublishRefused`] if a drain claimed this root: the tree the swap would
    /// publish has been removed (or partly removed), and its first act would be
    /// to rename the live `node_modules` aside — so it must not start at all.
    /// The refusal costs nothing to honor: the root is deregistered either way,
    /// the caller's cleanup guard removes whatever the drain left, and a
    /// re-removal of an already-removed tree is a harmless `ENOENT`.
    ///
    /// If `publish` itself fails, the root likewise stays deregistered: the
    /// caller's cleanup guard removes the tree on the unwound return, and a
    /// signal landing in that window leaks the staging dir rather than risking
    /// the live tree — `fuzi clean` is the backstop, as it is for every
    /// non-unwinding exit.
    ///
    /// `publish` runs **with the registry lock held**, so it must not touch the
    /// registry itself: [`STAGING_ROOTS`] is a plain, non-reentrant `Mutex` and
    /// a re-entering closure self-deadlocks. Keep the closure to the swap.
    pub fn publish<T>(mut self, publish: impl FnOnce() -> T) -> Result<T, PublishRefused> {
        let mut registry = lock(self.registry);
        // Deregister first, then decide — pure bookkeeping, and correct either
        // way: the root is still listed (an ordinary publish) or was taken by a
        // drain, in which case removing one *equal* entry finds nothing and can
        // never take another registration's. Taking the root also disarms this
        // value's `Drop`, so nothing re-enters the non-reentrant registry lock
        // on the way out of either branch.
        let claimed = self.root.take().is_some_and(|root| {
            deregister(&mut registry.roots, &root);
            registry.is_drained(&root)
        });
        if claimed {
            return Err(PublishRefused);
        }
        Ok(publish())
    }

    /// Whether a drain has claimed this registration's root — the question
    /// behind an error the install hit because its tree vanished: the drain's
    /// own removal is an interrupt, anyone else's is not. Takes the registry
    /// lock (so not from inside a [`publish`](Self::publish) closure). `false`
    /// once the root is deregistered by a publish.
    #[must_use]
    pub fn is_claimed(&self) -> bool {
        self.root
            .as_ref()
            .is_some_and(|root| lock(self.registry).is_drained(root))
    }
}

impl Drop for StagingRegistration {
    fn drop(&mut self) {
        if let Some(root) = self.root.take() {
            deregister(&mut lock(self.registry).roots, &root);
        }
    }
}

/// Remove **one** occurrence of `root` from the locked registry.
///
/// One, not all: two live trees can legitimately share a path only in exotic
/// cases, but a registration must never deregister an entry it does not own —
/// that would hand a still-live staging root to no one and leak it past the
/// drain.
fn deregister(roots: &mut Vec<PathBuf>, root: &Path) {
    if let Some(index) = roots.iter().position(|registered| registered == root) {
        roots.remove(index);
    }
}

/// How long [`drain_staging_roots`] keeps retrying one root.
///
/// A single `remove_dir_all` **loses** against a live install: the extraction
/// threads are still creating files in the tree it is walking, so it returns
/// `ENOTEMPTY` having deleted most of it — measured, not theorized (a warm
/// 229-package install interrupted at six different points left a partial tree
/// on four of them). Retrying converges because the drain holds the registry
/// lock: the swap cannot publish, and no writer can put a removed staging root
/// back — every staging mkdir is floored below the root (`crate::staging`'s
/// `make_dir_below`), and extraction below its package directory, so an
/// extraction worker whose package directory a pass removed fails with
/// `NotFound` and the extraction pool stops picking up jobs. The install
/// thread's own mkdirs (package directories, `.bin`) can re-create a directory
/// below a surviving root, but they run one at a time and fail once the root is
/// gone. The deadline bounds how long a Ctrl-C can appear to hang — a whole
/// materialization is well under it, and blowing through it degrades to
/// leaving a partial tree (which `fuzi clean` reaps), never to a wrong
/// deletion.
///
/// It bounds **one root**, not the whole drain: draining N roots can take N ×
/// this. The registry holds one root per live install, and v0 supports one
/// install per process, so N is 1 in practice.
// TODO: a cooperative abort flag the extraction workers poll would let them
// stop before the drain's first pass rather than at their next `mkdir` or file
// create under a removed directory. A convergence speedup only — the floor
// already keeps a removed root removed — so not worth the coupling into the hot
// loop unless the drain's time is measured to matter.
const DRAIN_DEADLINE: Duration = Duration::from_secs(3);

/// Pause between removal attempts — long enough that a retry is not a spin,
/// short enough to be invisible next to the extraction it is waiting out.
const DRAIN_RETRY_PAUSE: Duration = Duration::from_millis(20);

/// What one root's removal came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Removal {
    /// The drain removed the tree, and it was still gone when the drain
    /// stopped looking.
    Removed,
    /// Nothing to remove — another remover got there first (an ordinary
    /// unwound cleanup, a concurrent `fuzi clean`, or the user).
    Absent,
    /// Still on disk when the deadline expired: writers kept filling it faster
    /// than the passes emptied it, or the removal failed outright. Read off the
    /// **filesystem** at expiry, not inferred from the passes — a pass that
    /// succeeded says only that the tree was gone at that instant.
    Remaining,
}

/// What a [`drain_staging_roots`] call did, for the caller's one-line report.
///
/// Two lists rather than a count, because they call for different words: a
/// removed tree needs no follow-up, while a remaining one is exactly what
/// `fuzi clean` exists to reap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Staging roots this drain removed.
    pub removed: Vec<PathBuf>,
    /// Staging roots still (at least partly) on disk.
    pub remaining: Vec<PathBuf>,
}

/// Remove every registered staging root, best effort.
///
/// The `fuzi` binary's signal task calls this and then exits `128 + signum`;
/// nothing else should. Neither list overstates: a root that was already gone
/// is in neither, and a root whose deadline expired is sorted by what is
/// actually on disk at that moment (see `Removal`), so "removed N" is never a
/// tree the user is still left holding.
///
/// The registry lock is held across the removals on purpose: it is the mutual
/// exclusion that keeps this from racing a concurrent swap (see the module
/// docs), not merely a guard on the `Vec`. Holding it is also what makes the
/// retry converge — the install cannot publish out from under the drain.
///
/// The deadline bounds the **removals**, not the call. Taking the lock comes
/// first, and an in-flight [`commit`](crate::staging::StagingTree::commit)
/// holds it across its renames (an in-flight
/// [`create`](crate::staging::StagingTree::create) across its `mkdir`), so a
/// drain waits that syscall out before its own clock starts — nothing bounds
/// that wait but the syscall itself, which on a slow filesystem (NFS, fuse) is
/// as long as it is. Once the removals begin
/// the deadline is **per root**, bounding them at N × `DRAIN_DEADLINE`; in
/// practice the registry holds one.
#[must_use]
pub fn drain_staging_roots() -> DrainReport {
    drain_registry(&STAGING_ROOTS, DRAIN_DEADLINE)
}

/// [`drain_staging_roots`] over any registry and deadline — the seam that lets
/// a test fire a drain without firing the process-global one, which would
/// make every other test's staging tree refuse to be created.
fn drain_registry(registry: &Mutex<Registry>, deadline: Duration) -> DrainReport {
    let mut locked = lock(registry);
    // Claim them before removing anything, in the same critical section (see
    // `Registry::begin_drain`), and mark the drain fired even with nothing to
    // remove — `drain_fired` answers for the process, not for a tree, and
    // `register` refuses from here on.
    let roots = locked.begin_drain();
    remove_staging_roots(roots, deadline)
}

/// Whether a [`drain_staging_roots`] has started in this process.
///
/// The install thread's question before it renders anything: once a drain
/// fired, the signal task owns stdout, stderr, and the exit status — its
/// `128 + signum` is the run's status, and an error the install thread is
/// holding (a refused publish, a tree removed under the extractor) is the
/// drain's doing, not a result to report. Reads under the registry lock, so a
/// call that lands during a drain waits it out and answers `true`.
///
/// A signal that arrives *after* this answered `false` still wins the exit:
/// the install thread may be mid-render when the drain exits. That residual is
/// the contract — an interrupted run's status is `128 + signum`; its stdout is
/// not a document.
#[must_use]
pub fn drain_fired() -> bool {
    lock(&STAGING_ROOTS).fired
}

/// Remove each root within `deadline` apiece, sorting them into the report.
///
/// Split from [`drain_staging_roots`] (with the deadline as a parameter) so the
/// removal semantics are testable without touching the process-global registry
/// — which the rest of the suite is concurrently registering into — and without
/// a test having to wait out the production deadline.
fn remove_staging_roots(roots: Vec<PathBuf>, deadline: Duration) -> DrainReport {
    let mut report = DrainReport::default();
    for root in roots {
        match remove_staging_root(&root, deadline) {
            Removal::Removed => report.removed.push(root),
            Removal::Remaining => report.remaining.push(root),
            Removal::Absent => {}
        }
    }
    report
}

/// Remove one root, retrying until it is gone or `deadline` expires.
///
/// The retry is the whole point: see [`DRAIN_DEADLINE`] for why one pass is not
/// enough against a live install. Each attempt makes progress (the tree only
/// shrinks apart from what writers add back), so the loop converges as soon as
/// the last extraction finishes.
///
/// Gone is final. The drain fired before its first pass, so
/// [`StagingRegistration::register`] refuses any new root, and no other mkdir
/// can create one: staging floors every directory it creates below the root,
/// and extraction below its package directory. A writer racing the removal
/// fails with `NotFound` instead of putting the root back. That invariant, not
/// the timing of the passes, is what makes a removal stick — a pass that finds
/// the root gone proves nothing about whether writers have stopped, only that
/// none of them can bring it back. The loop still ends on a `NotFound` pass
/// rather than on `Ok` (one retry pause of confirmation, cheap), and the
/// expiry arm still asks the filesystem outright.
fn remove_staging_root(root: &Path, deadline: Duration) -> Removal {
    let started = Instant::now();
    let mut removed_any = false;
    loop {
        match fs::remove_dir_all(root) {
            // Gone, and it stays gone: nothing re-creates a staging root once
            // a drain has fired (see above). Ending here rather than on `Ok`
            // costs one retry pause and confirms that on the filesystem.
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return if removed_any {
                    Removal::Removed
                } else {
                    Removal::Absent
                };
            }
            Ok(()) => removed_any = true,
            Err(_) => {}
        }
        if started.elapsed() >= deadline {
            // The one exit that cannot be read off the passes. Calling a tree
            // still on disk `Removed` is the report's one load-bearing lie: the
            // user is told "removed 1 staging tree(s)" and *not* sent to `fuzi
            // clean`, for a tree still sitting in their project. So the verdict
            // is the tree's state at expiry — read off the filesystem rather
            // than trusting the floor, which only fuzi's own writers honor —
            // with `removed_any` only deciding who to credit for a root that is
            // gone.
            return match (is_gone(root), removed_any) {
                (false, _) => Removal::Remaining,
                (true, true) => Removal::Removed,
                (true, false) => Removal::Absent,
            };
        }
        std::thread::sleep(DRAIN_RETRY_PAUSE);
    }
}

/// Whether nothing is at `root` right now.
///
/// `symlink_metadata` (lstat — does not follow) rather than `Path::exists`: a
/// dangling symlink where the staging root was is still something the removal
/// did not take, and `exists` would call it gone. Any other error reads as "not
/// gone" for the same reason — the drain claims a removal only on evidence.
fn is_gone(root: &Path) -> bool {
    matches!(root.symlink_metadata(), Err(source) if source.kind() == io::ErrorKind::NotFound)
}

/// Whether `root` is currently registered.
///
/// Test-only: the registry has no consumer-facing read surface — production
/// code registers, deregisters, and drains, never inspects. Takes the registry
/// lock, so (like every helper here) it must not be called from inside a
/// [`StagingRegistration::publish`] closure.
///
/// Registry-touching tests should assert *containment of their own* (random)
/// root rather than draining: the registry is process-global and the rest of
/// the suite registers into it in parallel.
#[cfg(test)]
pub fn is_staging_root_registered(root: &Path) -> bool {
    lock(&STAGING_ROOTS)
        .roots
        .iter()
        .any(|registered| registered == root)
}

/// Hold the registry the way a drain does, so a test can pin what the swap is
/// mutually exclusive with. Blocks every registration for as long as the guard
/// lives — hold it briefly.
#[cfg(test)]
pub fn lock_roots_for_tests() -> MutexGuard<'static, Registry> {
    lock(&STAGING_ROOTS)
}

/// Claim `root` the way [`drain_staging_roots`] does, without draining.
///
/// Test-only, and the reason the claim is per root rather than a process-wide
/// flag: a test can stage "a drain took my tree" on its own (random) path and
/// leave every other test's publish in this process alone. Removing the tree
/// from disk is the caller's job — a drain does both, and a test that wants the
/// full shape should too.
#[cfg(test)]
pub fn mark_drained_for_tests(root: PathBuf) {
    lock(&STAGING_ROOTS).drained.push(root);
}

/// A private registry a drain has already fired on — what the process-global
/// one looks like after a fetch-phase interrupt, without firing that one
/// (which would make every other test's staging tree refuse to be created).
///
/// Leaked, because a registration holds its registry for `'static`; a test
/// leaks one empty `Mutex<Registry>`.
#[cfg(test)]
pub fn fired_registry_for_tests() -> &'static Mutex<Registry> {
    let registry = Box::leak(Box::new(Mutex::new(Registry::new())));
    let _ = drain_registry(registry, Duration::ZERO);
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Register `root` in the process-global registry without creating
    /// anything — the bookkeeping half alone, for the tests that pin it.
    fn register_for_test(root: PathBuf) -> StagingRegistration {
        StagingRegistration::register(&STAGING_ROOTS, root, |_| Ok::<(), ()>(()))
            .expect("the process-global registry is never drained in tests")
            .expect("a no-op create cannot fail")
    }

    /// A private, never-drained registry, leaked for the `'static` a
    /// registration holds.
    fn fresh_registry() -> &'static Mutex<Registry> {
        Box::leak(Box::new(Mutex::new(Registry::new())))
    }

    /// The `mkdir` a staging tree's creation runs, for the creation-race tests.
    fn mkdir(root: &Path) -> io::Result<()> {
        fs::create_dir(root)
    }

    /// Once a drain has fired — even one with nothing to remove, as a
    /// fetch-phase interrupt is — registration **refuses**, and the `create`
    /// step never runs, so no directory is left for nobody to remove.
    ///
    /// The leak this closes: the signal task exits a moment after its drain,
    /// and an install thread reaching `StagingTree::create` in that moment
    /// used to make (and register, too late) a `.fuzi-installing-*` tree only
    /// `fuzi clean` would ever reap.
    #[test]
    fn register_refuses_after_a_drain_fired_and_creates_nothing() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join(".fuzi-installing-after-drain");
        let registry = fired_registry_for_tests();

        let mut created = false;
        let registered = StagingRegistration::register(registry, root.clone(), |root| {
            created = true;
            mkdir(root)
        });

        assert!(matches!(registered, Err(RegisterRefused)), "{registered:?}");
        assert!(!created, "create must not run once a drain has fired");
        assert!(!root.exists(), "no staging tree may be left on disk");
        assert!(lock(registry).roots.is_empty());
    }

    /// A failed `create` registers nothing — there is no tree for a drain to
    /// remove — and hands its error back unchanged.
    #[test]
    fn register_lists_nothing_when_create_fails() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("missing-parent/.fuzi-installing-x");
        let registry = fresh_registry();

        let registered = StagingRegistration::register(registry, root, mkdir)
            .expect("nothing has drained this registry");

        let err = registered.expect_err("the parent does not exist");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(lock(registry).roots.is_empty());
    }

    /// A drain that fires **while** the root is being created waits for the
    /// `mkdir` and then removes the root — the tree is never on disk without
    /// being registered.
    ///
    /// Staged rather than raced: the drainer is started from inside `create`,
    /// where the registry lock is held, and `create` lingers *before* its
    /// `mkdir` so the drainer has every chance to reach the lock first. With
    /// the `mkdir` and the registration in one critical section the drain
    /// cannot run until both are done, so the verdict is the same under any
    /// schedule. Split them — release the lock between the two in either order
    /// — and the drainer runs during the linger: it finds no root (registration
    /// after the `mkdir`) or a root not yet on disk (registration before it),
    /// and the `mkdir` then leaves a tree nothing will remove. A scheduling
    /// fluke can only let a split implementation pass, never fail this one.
    #[test]
    fn a_drain_that_fires_during_create_still_removes_the_root() {
        use std::sync::mpsc;

        let dir = TempDir::new().unwrap();
        let root = dir.path().join(".fuzi-installing-mid-create");
        let registry = fresh_registry();

        let mut drainer = None;
        let registration = StagingRegistration::register(registry, root.clone(), |root| {
            let (started, ready) = mpsc::channel();
            drainer = Some(std::thread::spawn(move || {
                let _ = started.send(());
                drain_registry(registry, Duration::from_secs(10))
            }));
            ready.recv().unwrap();
            // Long enough for the drainer to reach the lock — the instant the
            // fix makes it wait at, and a split implementation would let past
            // *before* the `mkdir` below, where either split order leaks.
            std::thread::sleep(Duration::from_millis(50));
            mkdir(root)
        })
        .expect("no drain had fired when registration started")
        .expect("the mkdir succeeds");
        let report = drainer.unwrap().join().unwrap();

        assert_eq!(report.removed, vec![root.clone()]);
        assert!(report.remaining.is_empty());
        assert!(!root.exists(), "the drain must have removed the new tree");
        // The drain claimed the root, so the swap would refuse it.
        assert_eq!(registration.publish(|| ()), Err(PublishRefused));
        // And the registry now refuses new trees.
        assert!(matches!(
            StagingRegistration::register(registry, dir.path().join("later"), mkdir),
            Err(RegisterRefused)
        ));
    }

    /// Registration is visible to the registry, and drop takes it back out —
    /// the whole contract the drain depends on. Asserted by containment of a
    /// unique path rather than by draining, so the process-global registry
    /// stays safe to share with the rest of the suite running in parallel.
    #[test]
    fn register_then_drop_deregisters() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join(".fuzi-installing-register-drop");
        {
            let _registration = register_for_test(root.clone());
            assert!(is_staging_root_registered(&root));
        }
        assert!(!is_staging_root_registered(&root));
    }

    /// A drain marks itself fired before anything else — with no root
    /// registered too (an interrupt during planning or fetching), because the
    /// install thread's "may I render?" is about the process, not a tree — and
    /// claims every live root. On a local `Registry`: draining the
    /// process-global one would take the rest of the suite's roots.
    #[test]
    fn begin_drain_fires_even_with_nothing_registered() {
        let mut empty = Registry::new();
        assert!(!empty.fired);
        assert!(empty.begin_drain().is_empty());
        assert!(empty.fired);

        let root = PathBuf::from("/nowhere/.fuzi-installing-begin-drain");
        let mut live = Registry::new();
        live.roots.push(root.clone());
        assert_eq!(live.begin_drain(), vec![root.clone()]);
        assert!(live.fired);
        assert!(live.roots.is_empty());
        assert!(live.is_drained(&root));
    }

    /// `publish` deregisters the root and hands back whatever the swap returned.
    ///
    /// (The *ordering* — deregistered before the swap runs, both under one lock
    /// — is not observable from another thread by construction, which is the
    /// point; it is pinned from the outside by `staging`'s
    /// `commit_swaps_under_the_interrupt_registry_lock`.)
    #[test]
    fn publish_deregisters_and_returns_the_swaps_value() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join(".fuzi-installing-publish-order");
        let registration = register_for_test(root.clone());
        assert!(is_staging_root_registered(&root));

        let published = registration.publish(|| "swapped");

        assert_eq!(published, Ok("swapped"));
        assert!(!is_staging_root_registered(&root));
    }

    /// The refusal: once a drain has claimed the root, `publish` returns
    /// [`PublishRefused`] **without running the swap**.
    ///
    /// This is the whole point of recording the claim in the locked state. Mere
    /// mutual exclusion would let a swap that lost the lock race run afterwards
    /// — and its first act is to rename the live `node_modules` aside, which on
    /// a process that is about to exit parks the user's tree under a
    /// `.fuzi-old-*` name `fuzi clean` deletes. `staging`'s
    /// `commit_refuses_to_publish_after_a_drain_claimed_the_root` pins the same
    /// contract end to end, on a real tree.
    #[test]
    fn publish_refuses_after_a_drain_claimed_the_root() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join(".fuzi-installing-drained");
        let registration = register_for_test(root.clone());
        mark_drained_for_tests(root.clone());

        let mut swapped = false;
        let published = registration.publish(|| swapped = true);

        assert_eq!(published, Err(PublishRefused));
        assert!(
            !swapped,
            "the swap must not run after a drain took the tree"
        );
        // Refused or not, the root leaves the live set — the drain owns it now.
        assert!(!is_staging_root_registered(&root));
    }

    /// The claim is per root, not per process: a drain that took *another*
    /// tree's root leaves this one publishable. What makes the refusal safe to
    /// test in a parallel suite, and the honest reading of the claim — a drain
    /// only endangers the trees it actually took.
    #[test]
    fn publish_ignores_a_claim_on_a_different_root() {
        let dir = TempDir::new().unwrap();
        let mine = dir.path().join(".fuzi-installing-mine");
        let theirs = dir.path().join(".fuzi-installing-theirs");
        let registration = register_for_test(mine);
        mark_drained_for_tests(theirs);

        assert_eq!(registration.publish(|| "swapped"), Ok("swapped"));
    }

    /// A failed swap leaves the root deregistered — the documented trade: the
    /// caller's cleanup guard removes the tree on the unwound return, and a
    /// signal in that window leaks a staging dir rather than risking a live one.
    #[test]
    fn publish_leaves_the_root_deregistered_when_the_swap_fails() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join(".fuzi-installing-publish-failure");
        let registration = register_for_test(root.clone());

        let swapped = registration
            .publish(|| Err::<(), &str>("rename failed"))
            .expect("the swap ran — nothing claimed this root");

        assert!(swapped.is_err());
        assert!(!is_staging_root_registered(&root));
    }

    /// `publish` deregisters exactly one entry and disarms its own `Drop`, so a
    /// second live registration of the same path survives it. Both halves are
    /// load-bearing: a `retain`-style removal would take the other tree's entry
    /// out too, and an un-disarmed `Drop` would take it out a moment later —
    /// either way the surviving staging root would be invisible to the drain.
    #[test]
    fn publish_deregisters_one_entry_and_disarms_its_drop() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join(".fuzi-installing-double-registered");
        let first = register_for_test(root.clone());
        let _second = register_for_test(root.clone());

        assert_eq!(first.publish(|| ()), Ok(()));

        assert!(
            is_staging_root_registered(&root),
            "the second registration must still be registered"
        );
    }

    /// The removal pass drops each tree recursively, does not trip over a root
    /// that is already gone, and reports only what it actually removed — in the
    /// order given.
    #[test]
    fn remove_staging_roots_removes_trees_and_skips_the_absent() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("first");
        let missing = dir.path().join("missing");
        let second = dir.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir_all(second.join("nested/deep")).unwrap();
        fs::write(second.join("nested/deep/file.txt"), b"x").unwrap();

        let report =
            remove_staging_roots(vec![first.clone(), missing, second.clone()], Duration::ZERO);

        // The already-gone entry is neither fatal nor claimed as removed.
        assert_eq!(report.removed, vec![first.clone(), second.clone()]);
        assert!(report.remaining.is_empty());
        assert!(!first.exists());
        assert!(!second.exists(), "removal is recursive");
    }

    /// Pin: draining a staging tree that holds a sibling link unlinks the link
    /// and leaves the link's target — outside the project — untouched.
    #[test]
    fn remove_staging_roots_does_not_follow_a_link_into_its_target() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("lib");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("sentinel"), b"keep").unwrap();
        let root = dir.path().join("app/.fuzi-installing-x");
        fs::create_dir_all(root.join("@s")).unwrap();
        std::os::unix::fs::symlink("../../../lib", root.join("@s/lib")).unwrap();
        assert!(
            root.join("@s/lib/sentinel").is_file(),
            "sanity: the link resolves"
        );

        let report = remove_staging_roots(vec![root.clone()], Duration::ZERO);

        assert_eq!(report.removed, vec![root.clone()]);
        assert!(!root.exists());
        assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"keep");
    }

    /// A root that cannot be removed at all is reported as remaining rather
    /// than silently dropped — that list is what sends the user to `fuzi clean`.
    #[test]
    fn remove_staging_roots_reports_an_unremovable_root_as_remaining() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        // A write-denied parent makes the unlink of `root` fail with EACCES,
        // which is the one removal failure a test can conjure deterministically.
        let parent = dir.path().join("locked");
        let root = parent.join("staging");
        fs::create_dir_all(root.join("child")).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
        // Probe: running as root, `DAC_OVERRIDE` beats the missing write bit and
        // the removal succeeds, which would make the assertion vacuous — skip in
        // that case rather than assert something the kernel isn't enforcing.
        let write_denied = fs::write(parent.join("probe"), b"x").is_err();

        let report = remove_staging_roots(vec![root.clone()], Duration::ZERO);

        // Restore write permission so the TempDir can clean itself up.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        if !write_denied {
            return;
        }
        assert!(report.removed.is_empty());
        assert_eq!(report.remaining, vec![root.clone()]);
        assert!(root.exists());
    }

    /// The drain outlasts writers that are still filling the tree.
    ///
    /// This is the case a single `remove_dir_all` loses, and it is not
    /// hypothetical: interrupting a real 229-package install mid-materialize
    /// left a partial staging tree on most attempts, because the extraction
    /// threads keep creating files in the tree the removal is walking. Here a
    /// pre-populated tree plus a live writer reproduce that shape — a harsher
    /// writer than fuzi's own, which are floored below the root, since this one
    /// re-creates the root itself, as a writer outside fuzi could. A single
    /// pass has 300 directories to walk while the writer keeps adding, so it is
    /// highly likely — not guaranteed — to come back `ENOTEMPTY`, while the
    /// retry keeps going until the writer stops. The asymmetry is deliberate: a
    /// scheduling fluke can only make this test pass a single-pass
    /// implementation (a false green), never fail the retrying one.
    #[test]
    fn remove_staging_roots_outlasts_a_concurrent_writer() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = TempDir::new().unwrap();
        let root = dir.path().join("staging");
        // Big enough that the first pass has real work to lose the race over.
        for i in 0..300 {
            fs::create_dir_all(root.join(format!("pkg{i}"))).unwrap();
            fs::write(root.join(format!("pkg{i}/index.js")), b"export {}").unwrap();
        }

        // A writer shaped like an extraction worker: keeps re-creating package
        // directories (root included) until told to stop.
        let stop = Arc::new(AtomicBool::new(false));
        let writer = {
            let root = root.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut i = 0;
                while !stop.load(Ordering::Relaxed) {
                    let package = root.join(format!("pkg{i}"));
                    let _ = fs::create_dir_all(&package);
                    let _ = fs::write(package.join("index.js"), b"export {}");
                    i += 1;
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };
        let drainer = {
            let root = root.clone();
            std::thread::spawn(move || remove_staging_roots(vec![root], Duration::from_secs(10)))
        };

        // Let the two race for a while, then stop the writer and join it, so
        // nothing can re-create the tree after the drain finishes.
        std::thread::sleep(Duration::from_millis(150));
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        let report = drainer.join().unwrap();

        assert_eq!(report.removed, vec![root.clone()]);
        assert!(report.remaining.is_empty());
        assert!(!root.exists());
    }

    /// A pass that succeeded is **not** the verdict: when a writer puts the
    /// root back and the deadline then expires, the drain reports the tree as
    /// remaining — the case that sends the user to `fuzi clean`. fuzi's own
    /// writers cannot put a root back (they are floored below it); the expiry
    /// verdict reads the filesystem so a writer outside fuzi is reported too.
    ///
    /// This is the honesty half of the retry. An implementation that latches
    /// "removed" on the first successful pass and never re-falsifies it prints
    /// "removed 1 staging tree(s)" *and* omits the `fuzi clean` line, for a tree
    /// still sitting in the user's project — the exact case `fuzi clean`'s own
    /// help says it exists to cover.
    ///
    /// Staged rather than raced, unlike
    /// `remove_staging_roots_outlasts_a_concurrent_writer`: the root starts
    /// empty so the first pass certainly succeeds, and the restorer takes the
    /// parent's write bit off as soon as it has put the root back, so every
    /// later pass fails `EACCES` and the tree is certainly still there at
    /// expiry. The one unsynchronized instant is between the restorer's
    /// `create_dir` and its `chmod` — a single syscall, while the drain is
    /// committed to a whole [`DRAIN_RETRY_PAUSE`] of sleep — and losing it only
    /// costs the restorer another round.
    #[test]
    fn remove_staging_roots_reports_a_re_created_tree_as_remaining() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("project");
        let root = parent.join("staging");
        fs::create_dir_all(&root).unwrap();

        // The extraction worker's move, minus the racing: re-create the root
        // the instant the drain's first pass removes it — a `create_dir` that
        // returns `Ok` *is* that instant, with no poll-then-act gap — and then
        // make it unremovable, so no later pass can turn the answer back into
        // `NotFound`.
        let settled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let restorer = {
            let parent = parent.clone();
            let root = root.clone();
            let settled = std::sync::Arc::clone(&settled);
            std::thread::spawn(move || {
                let give_up = Instant::now() + Duration::from_secs(10);
                while Instant::now() < give_up {
                    if fs::create_dir(&root).is_ok() {
                        let _ = fs::set_permissions(&parent, fs::Permissions::from_mode(0o500));
                        let _ = fs::create_dir(root.join("pkg"));
                        if root.symlink_metadata().is_ok() {
                            settled.store(true, std::sync::atomic::Ordering::SeqCst);
                            return true;
                        }
                        // Lost the sub-syscall window: the root is only settled
                        // once it is both back *and* unremovable, so restore
                        // write access and wait for the next removal.
                        let _ = fs::set_permissions(&parent, fs::Permissions::from_mode(0o700));
                    }
                    std::thread::yield_now();
                }
                false
            })
        };

        // Comfortably longer than a first pass on an empty directory, so the
        // deadline cannot expire before the root is back (which would probe an
        // honestly-removed tree), and short enough to stay a unit test.
        let report = remove_staging_roots(vec![root.clone()], Duration::from_millis(250));
        // Snapshot immediately: a restorer that settles only *after* the drain
        // returned produced a report its setup was never in force for — skip,
        // don't assert against it.
        let settled_during_drain = settled.load(std::sync::atomic::Ordering::SeqCst);
        let restored = restorer.join().unwrap();

        // Probe and restore before asserting, so the TempDir can always clean
        // up. Running as root, `DAC_OVERRIDE` beats the missing write bit and
        // the drain removes the tree anyway — the setup the assertion needs is
        // not in force, so skip rather than assert what the kernel isn't
        // enforcing.
        let write_denied = fs::write(parent.join("probe"), b"x").is_err();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        if !restored || !write_denied || !settled_during_drain {
            return;
        }

        assert!(
            report.removed.is_empty(),
            "a tree that is still on disk was not removed"
        );
        assert_eq!(report.remaining, vec![root.clone()]);
        assert!(
            root.exists(),
            "sanity: the restored tree outlived the drain"
        );
    }

    /// An empty registry drains to nothing (the common case: a signal during
    /// planning, verify, or clean, none of which stage anything).
    #[test]
    fn remove_staging_roots_on_empty_is_empty() {
        assert_eq!(
            remove_staging_roots(Vec::new(), Duration::ZERO),
            DrainReport::default()
        );
    }
}
