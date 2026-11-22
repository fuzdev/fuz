//! [`BackgroundWrites`] — the spine's tracker of detached background writes.
//!
//! A write the request path never waits on — an audit failure row
//! ([`crate::AuditEmitter::emit`]), a bearer token's use
//! ([`crate::api_token_queries::spawn_api_token_touch`]) — runs on a detached
//! tokio task, and so does work a request awaits but must not cancel by
//! being dropped (the bootstrap's burn-and-commit, `bootstrap_handler`; an
//! action's post-commit effects, `fuz_actions::PostCommitEffects::drain_all`,
//! whose dispatch a socket closed at shutdown drops). Dropping the task's
//! handle doesn't cancel it, but the runtime shutting down does, mid-checkout
//! or mid-write, with nothing logged. So every such write is spawned
//! through the one tracker, which counts it in flight until its task ends,
//! and the two barriers that must see the writes land await it: a server's graceful shutdown
//! (`fuz_actions::server::serve_until_shutdown`) and the
//! `_testing_drain_effects` test action.
//!
//! A server's backend owns its one tracker (`fuz_actions::server::AppBackend`'s
//! `background_writes`); its [`crate::AuditEmitter`] is built over it and its
//! [`crate::AuthGate`] holds it beside the credential walk, so one drain
//! covers every write. The TS twin splits the one tracker in two, both
//! awaited by `AppServer.close` in `fuz_app`: a `RequestFlushTracker`
//! (`http/pending_effects.ts`) holds each request's effect flush — an HTTP
//! request's eager writes (its token touch) and post-commit thunks, and a
//! WS message's after its reply — and the audit emitter's own in-flight set
//! (`AuditEmitter.drain_inflight`) holds its failure rows.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Counts the detached writes in flight so [`Self::drain`] can await them.
///
/// Always on: an atomic increment and decrement per write. Shared by `Arc`
/// between the backend that owns it, the [`crate::AuditEmitter`] built over
/// it, every [`crate::AuthGate`] the backend builds, and every
/// `fuz_actions::PostCommitEffects` a dispatch builds over that emitter. `Default` makes a
/// fresh one — what a test builds a gate or an emitter over; a tracker
/// nothing drains loses its writes at shutdown.
#[derive(Debug, Default)]
pub struct BackgroundWrites {
    pending: AtomicUsize,
    drain_notify: Notify,
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
        tokio::spawn(async move {
            // held for the task's life: the count settles when the task ends
            let _inflight = inflight;
            write.await
        })
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
    pub async fn drain(&self) {
        loop {
            // Arm the waiter before re-checking the count so a `notify_waiters`
            // between the load and the await can't be missed.
            let notified = self.drain_notify.notified();
            if self.pending.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
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
}
