//! [`BackgroundWrites`] — the spine's tracker of detached background writes.
//!
//! A write the request path never waits on — an audit failure row
//! (`fuz_auth::AuditEmitter::emit`), a bearer token's use
//! (`fuz_auth::api_token_queries::spawn_api_token_touch`) — runs on a detached
//! tokio task, and so does work a request awaits but must not cancel by
//! being dropped (the bootstrap's burn-and-commit, `bootstrap_handler`; an
//! action's post-commit effects, `fuz_actions::PostCommitEffects::drain_all`,
//! whose dispatch a socket closed at shutdown drops; a whole request dropped
//! once its commit has started, [`BackgroundWrites::finish_past_commit`]).
//! Dropping the task's handle doesn't cancel it, but the runtime shutting
//! down does, mid-checkout or mid-write, with nothing logged. So every such
//! write is spawned through the one tracker, which counts it in flight until
//! its task ends, and the two barriers that must see the writes land await it: a server's
//! graceful shutdown ([`crate::serve_with_shutdown`], through the router's
//! [`crate::ShutdownDuties`]) and the `_testing_drain_effects` test action.
//!
//! A server's backend owns its one tracker (`fuz_actions::server::AppBackend`'s
//! `background_writes`); its `fuz_auth::AuditEmitter` is built over it and its
//! `fuz_auth::AuthGate` holds it beside the credential walk, so one drain
//! covers every write. The TS twin splits the one tracker in two, both
//! awaited by `AppServer.close` in `fuz_app`: a `RequestFlushTracker`
//! (`http/pending_effects.ts`) holds each request's effect flush — an HTTP
//! request's eager writes (its token touch) and post-commit thunks, and a
//! WS message's after its reply — and the audit emitter's own in-flight set
//! (`AuditEmitter.drain_inflight`) holds its failure rows.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use fuz_db::CommitWatch;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Counts the detached writes in flight so [`Self::drain`] can await them.
///
/// Always on: an atomic increment and decrement per write. Shared by `Arc`
/// between the backend that owns it, the `fuz_auth::AuditEmitter` built over
/// it, every `fuz_auth::AuthGate` the backend builds, and every
/// `fuz_actions::PostCommitEffects` a dispatch builds over that emitter.
/// `Default` makes a fresh one — what a test builds a gate or an emitter
/// over; a tracker nothing drains loses its writes at shutdown.
#[derive(Debug, Default)]
pub struct BackgroundWrites {
    pending: AtomicUsize,
    drain_notify: Notify,
}

tokio::task_local! {
    /// The tracker the running task was spawned through, by address — set
    /// for each task [`BackgroundWrites::spawn`] starts, so a drain called
    /// from inside one knows it is one of the writes it would wait for.
    static TRACKED_BY: usize;
}

/// One tracked write: counted in flight from [`Self::acquire`] until the
/// guard drops.
///
/// Settling in `Drop` rather than at the end of the spawned task's body is
/// what lets a drain finish when that body never reaches its end — a listener
/// that panics under unwinding, a task aborted or dropped with its runtime
/// before it ran. Otherwise the count would stay up and
/// [`BackgroundWrites::drain`] would wait forever.
struct InflightWriteGuard {
    writes: Arc<BackgroundWrites>,
}

impl InflightWriteGuard {
    /// Count one write in flight.
    fn acquire(writes: &Arc<BackgroundWrites>) -> Self {
        writes.pending.fetch_add(1, Ordering::SeqCst);
        Self {
            writes: Arc::clone(writes),
        }
    }
}

impl Drop for InflightWriteGuard {
    fn drop(&mut self) {
        if self.writes.pending.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.writes.drain_notify.notify_waiters();
        }
    }
}

impl BackgroundWrites {
    /// Spawn `write` on a detached tokio task, counted in flight until the
    /// task ends however it ends — done, panicked, or aborted before it ran.
    ///
    /// The count is taken before the spawn, so a concurrent [`Self::drain`]
    /// can never observe a count that omits it. Dropping the returned handle
    /// doesn't cancel the task; awaiting it yields the write's output.
    pub fn spawn<F>(self: &Arc<Self>, write: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let inflight = InflightWriteGuard::acquire(self);
        let tracker = self.address();
        tokio::spawn(TRACKED_BY.scope(tracker, async move {
            // held for the task's life: the count settles when the task ends
            let _inflight = inflight;
            write.await
        }))
    }

    /// How many writes are in flight — spawned and not yet ended. What a
    /// shutdown whose drain bound ran out reports as given up.
    #[must_use]
    pub fn inflight_count(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }

    /// Await every write in flight.
    ///
    /// Waits until no write is outstanding, so a write that starts while the
    /// drain is waiting (an emit from a post-commit effect) is awaited too;
    /// one that starts after the drain resolves is not.
    ///
    /// Called from inside one of this tracker's own writes, it returns at
    /// once: the caller is one of the writes it would wait for, so it can never
    /// usefully wait, and inside the tracker's own work there is no barrier.
    /// The check is made on every pass, so a drain that started outside and
    /// was then moved into a tracked write — a request handed off past its
    /// commit ([`Self::finish_past_commit`]), which wakes it — returns too.
    /// That is what `testing_spine_stub`'s layer that drains after each
    /// request relies on for a handed-off request, whose client is gone.
    pub async fn drain(&self) {
        loop {
            // Arm the waiter before re-checking the count so a `notify_waiters`
            // between the load and the await can't be missed.
            let notified = self.drain_notify.notified();
            let tracked_here = TRACKED_BY
                .try_with(|tracker| *tracker == self.address())
                .unwrap_or(false);
            if tracked_here || self.pending.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// This tracker's address — its identity for [`TRACKED_BY`].
    fn address(&self) -> usize {
        std::ptr::from_ref(self).addr()
    }
}

impl BackgroundWrites {
    /// Wrap a request's future so that dropping it once its commit has
    /// started hands it to this tracker to finish, rather than cancelling it.
    ///
    /// The future runs under a fresh [`CommitWatch`], which
    /// [`fuz_db::commit_checked`] marks as its first commit starts. Dropped
    /// before that, the future is dropped with the wrapper and its transaction
    /// rolls back. Dropped after, its rest — the commit's round trip, the
    /// post-commit effects, a revocation's connection closes — runs on a task
    /// spawned through this tracker, counted in flight like any write, so the
    /// committed change is never left unannounced and the shutdown drain waits
    /// for it. Its output, then, is discarded: the caller that would have
    /// read it is gone.
    ///
    /// The owners of a request's drop wrap with it: the serve loop wraps each
    /// HTTP request (`crate::serve_with_shutdown`), and a WebSocket loop each
    /// dispatch (`fuz_realtime`).
    ///
    /// "Started" is the request's first commit: whatever the request does
    /// after it — more transactions included — runs to completion on the
    /// tracker once it is dropped. So code running after a commit within a
    /// request is tracked work: a [`Self::drain`] it awaits returns at once
    /// ([`Self::drain`]'s doc), and nothing it awaits may wait for the
    /// tracker to be empty by other means. The mark is seen only by
    /// `fuz_db::commit_checked` on the request's own task — a commit in a
    /// task the request spawns is not marked, and neither are the
    /// autocommit writes of a pooled client.
    pub fn finish_past_commit<F>(self: &Arc<Self>, future: F) -> FinishPastCommit<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let watch = Arc::new(CommitWatch::default());
        FinishPastCommit {
            future: Some(Box::pin(CommitWatch::scope(Arc::clone(&watch), future))),
            watch,
            writes: Arc::clone(self),
        }
    }
}

/// A request's future that finishes on its tracker, rather than being
/// cancelled, when dropped once its commit has started
/// ([`BackgroundWrites::finish_past_commit`]).
#[must_use = "a future does nothing unless polled"]
pub struct FinishPastCommit<T: Send + 'static> {
    /// `None` once it has completed, or once handed off.
    future: Option<Pin<Box<dyn Future<Output = T> + Send>>>,
    watch: Arc<CommitWatch>,
    writes: Arc<BackgroundWrites>,
}

impl<T: Send + 'static> std::fmt::Debug for FinishPastCommit<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinishPastCommit")
            .field("pending", &self.future.is_some())
            .field("commit_started", &self.watch.is_started())
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static> Future for FinishPastCommit<T> {
    type Output = T;

    /// # Panics
    ///
    /// When polled again after it completed, as a future may.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        #[expect(
            clippy::expect_used,
            reason = "polling a completed future is a caller bug, as for any future"
        )]
        let future = self.future.as_mut().expect("polled after completion");
        let polled = future.as_mut().poll(cx);
        if polled.is_ready() {
            self.future = None;
        }
        polled
    }
}

impl<T: Send + 'static> Drop for FinishPastCommit<T> {
    fn drop(&mut self) {
        let Some(future) = self.future.take() else {
            return;
        };
        // dropped while unwinding: the future's state is suspect, and
        // spawning from a panic is no place to continue it
        if std::thread::panicking() {
            if self.watch.is_started() {
                tracing::warn!(
                    "a request dropped past its commit while unwinding: its post-commit work \
                     is lost"
                );
            }
            return;
        }
        if !self.watch.is_started() {
            return;
        }
        // Outside any runtime there is nowhere to spawn, and the future goes
        // with the wrapper, its committed work unfinished. Inside a runtime
        // that is itself tearing down, the spawn is taken and the task
        // dropped with the rest — the process is ending under it.
        if tokio::runtime::Handle::try_current().is_err() {
            tracing::warn!(
                "a request dropped past its commit outside a runtime: its post-commit work \
                 is lost"
            );
            return;
        }
        self.writes.spawn(async move {
            drop(future.await);
        });
        // a drain the future was already waiting in now runs inside a tracked
        // write: wake it to see that and return
        self.writes.drain_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::BackgroundWrites;

    #[tokio::test]
    async fn the_drain_waits_for_a_write_in_flight() {
        let writes = Arc::new(BackgroundWrites::default());
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        writes.spawn(async move {
            released.await.ok();
        });
        assert_eq!(writes.inflight_count(), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), writes.drain())
                .await
                .is_err(),
            "the drain holds while the write is in flight"
        );
        release.send(()).expect("the write is waiting");
        tokio::time::timeout(Duration::from_secs(5), writes.drain())
            .await
            .expect("the drain resolves once the write ends");
        assert_eq!(writes.inflight_count(), 0);
    }

    #[tokio::test]
    async fn an_aborted_write_still_settles_the_drain() {
        let writes = Arc::new(BackgroundWrites::default());
        // the current-thread test runtime doesn't run the task until this
        // test yields, so the abort lands before its first poll
        let handle = writes.spawn(async {});
        handle.abort();
        assert!(
            handle.await.is_err_and(|e| e.is_cancelled()),
            "the write was cancelled before it ran"
        );
        tokio::time::timeout(Duration::from_secs(5), writes.drain())
            .await
            .expect("the drain resolves once the aborted write's task is gone");
    }

    /// Unmarked — no commit started — the wrapped future answers like the
    /// bare one, and dropped it is gone: nothing is handed to the tracker.
    /// (The hand-off past a commit needs a real one: `fuz_actions`'
    /// `dispatch_past_commit` suite.)
    #[tokio::test]
    async fn a_request_with_no_commit_answers_and_drops_as_it_is() {
        let writes = Arc::new(BackgroundWrites::default());
        assert_eq!(writes.finish_past_commit(async { 7 }).await, 7);

        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held = writes.finish_past_commit({
            let reached = Arc::clone(&reached);
            async move {
                tokio::task::yield_now().await;
                reached.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        drop(held);
        tokio::task::yield_now().await;
        assert_eq!(writes.inflight_count(), 0, "nothing handed off");
        assert!(
            !reached.load(std::sync::atomic::Ordering::SeqCst),
            "the dropped future never ran"
        );
    }

    /// A drain first polled outside the tracker, then moved into one of its
    /// writes — what a request handed off past its commit does to a drain it
    /// was waiting in — wakes on the hand-off and returns at once.
    #[tokio::test]
    async fn a_drain_moved_into_a_tracked_write_returns() {
        let writes = Arc::new(BackgroundWrites::default());
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let blocker = writes.spawn(async move {
            released.await.ok();
        });
        let mut drain = {
            let writes = Arc::clone(&writes);
            Box::pin(async move { writes.drain().await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut drain)
                .await
                .is_err(),
            "outside, the drain waits for the blocker"
        );
        let moved = writes.spawn(drain);
        // the wake `FinishPastCommit`'s hand-off sends after its spawn
        writes.drain_notify.notify_waiters();
        tokio::time::timeout(Duration::from_secs(5), moved)
            .await
            .expect("inside, the drain returns without the blocker")
            .expect("the task ran");
        release.send(()).expect("the blocker is waiting");
        blocker.await.expect("the blocker ran");
    }

    /// Two drains joined on one tracked write both return at once, while a
    /// drain outside still waits for the other write in flight.
    #[tokio::test]
    async fn drains_inside_a_tracked_write_return_while_one_outside_waits() {
        let writes = Arc::new(BackgroundWrites::default());
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        writes.spawn(async move {
            released.await.ok();
        });
        let inner = Arc::clone(&writes);
        let joined = writes.spawn(async move {
            futures::future::join(inner.drain(), inner.drain()).await;
        });
        tokio::time::timeout(Duration::from_secs(5), joined)
            .await
            .expect("both inner drains return at once")
            .expect("the task ran");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), writes.drain())
                .await
                .is_err(),
            "the outside drain waits for the write in flight"
        );
        release.send(()).expect("the write is waiting");
        tokio::time::timeout(Duration::from_secs(5), writes.drain())
            .await
            .expect("the outside drain ends once the tracker empties");
    }
}
