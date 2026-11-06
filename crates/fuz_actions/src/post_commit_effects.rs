//! Post-commit effects queue.
//!
//! Handlers queue **non-DB side-channels** here — audit listener fan-out,
//! WS broadcasts, log lines, anything that should fire after the request
//! transaction commits but should NOT fire if it rolls back.
//!
//! ## Design choice: `Box<dyn FnOnce() -> BoxFuture>` queue
//!
//! Considered three shapes:
//!
//! 1. **Typed enum (`PostCommitEffect::AuditFanOut { event: Arc<...> }`,
//!    `PostCommitEffect::Broadcast { msg: String }`, ...)** — type-safe but
//!    rigid; every new effect kind requires a registry-side enum arm
//!    edit, which couples handlers to the framework crate.
//! 2. **`Box<dyn FnOnce() -> BoxFuture>`** — flexible, handlers
//!    construct the effect closure inline, registry-agnostic. Pays one
//!    Box per queued effect (cold path — credential mutations, not
//!    every request).
//! 3. **`Vec<JoinHandle<()>>`** — assumes every
//!    effect is already spawned. Defeats the "fire only if tx commits"
//!    contract because `tokio::spawn` is independent of the awaiting
//!    future.
//!
//! Choose **option 2** for the framework default. Consumers wanting
//! type-safe effects build domain-specific enums on top (e.g. a
//! consumer-side effect enum that closes over its audit listener
//! registry). The framework stays flexible without
//! prescribing a taxonomy.
//!
//! ## Drain shape: concurrent fan-out, on its own task
//!
//! [`PostCommitEffects::drain_all`] runs the queued futures **concurrently**
//! via [`futures::future::join_all`]. Effects that need ordering must be
//! combined into one queued future internally.
//!
//! The fan-out runs on a spawned task that the drain awaits, so dropping the
//! dispatching future — an HTTP client that disconnects, a socket whose
//! in-flight dispatches are torn down — can't cancel effects whose
//! transaction already committed (a lost socket close would leave a revoked
//! session's socket open). The remaining window is the `COMMIT` round trip
//! itself: a future dropped there loses its effects whether or not the commit
//! landed.

use std::future::Future;
use std::sync::Mutex;

use futures::future::BoxFuture;
use fuz_auth::{AuditNotifyFn, AuditPostCommit};

/// A single deferred side-effect.
///
/// `FnOnce` because each effect runs exactly once; `Send` so the queue
/// is movable across `await` points; `'static` because the effect must
/// outlive the request frame (consumers move owned data into the
/// closure).
pub type PostCommitEffect = Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send>;

/// FIFO queue of [`PostCommitEffect`]s drained after the request tx commits.
///
/// `std::sync::Mutex` (not `tokio::sync::Mutex`) — the queue is mutated
/// from sync code (push) and drained from async code (`drain_all`);
/// critical sections are O(1) Vec push/swap with no `.await` inside.
///
/// Stored on [`super::ActionContext`] so handlers see the queue through
/// `&ctx.post_commit_effects` without `&mut ctx` propagating through every
/// handler signature.
#[derive(Default)]
pub struct PostCommitEffects {
    queue: Mutex<Vec<PostCommitEffect>>,
}

impl std::fmt::Debug for PostCommitEffects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.queue.lock().map_or(0, |q| q.len());
        f.debug_struct("PostCommitEffects")
            .field("queued", &count)
            .finish()
    }
}

impl PostCommitEffects {
    /// Build an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a deferred effect onto the queue.
    ///
    /// The effect runs **only if** the request transaction commits. On
    /// rollback the queue is dropped without running.
    pub fn push(&self, effect: PostCommitEffect) {
        if let Ok(mut q) = self.queue.lock() {
            q.push(effect);
        }
    }

    /// Push a deferred effect built from a `FnOnce() -> Future` shape.
    ///
    /// Convenience for callers that don't want to spell the `Box` +
    /// `BoxFuture` ceremony.
    pub fn push_fn<F, Fut>(&self, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.push(Box::new(move || {
            let fut = f();
            Box::pin(fut)
        }));
    }

    /// Number of queued effects.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.lock().map_or(0, |q| q.len())
    }

    /// `true` if no effects are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drain every queued effect and run them concurrently, on a spawned
    /// task this awaits.
    ///
    /// Awaits all futures with [`futures::future::join_all`] — one slow
    /// effect doesn't block the others. Individual effects that need
    /// ordering must be composed into one queued future before
    /// pushing. Dropping the returned future doesn't cancel the effects
    /// (see the module doc); a panicking effect is logged, not propagated.
    pub async fn drain_all(&self) {
        let drained = {
            let Ok(mut q) = self.queue.lock() else {
                return;
            };
            std::mem::take(&mut *q)
        };
        if drained.is_empty() {
            return;
        }
        let task = tokio::spawn(async move {
            let futures: Vec<_> = drained.into_iter().map(|effect| effect()).collect();
            futures::future::join_all(futures).await;
        });
        if let Err(e) = task.await {
            tracing::error!(error = %e, "post-commit effect task failed");
        }
    }

    /// Clear the queue without running anything (called on rollback).
    pub fn clear(&self) {
        if let Ok(mut q) = self.queue.lock() {
            q.clear();
        }
    }
}

/// Bridge into [`fuz_auth::AuditEmitter::emit_in_tx`]: queue the
/// post-commit listener fan-out closure on this dispatcher's effect
/// queue.
///
/// When the request transaction commits, the dispatcher drains
/// `post_commit_effects` and the queued notify fires; on rollback the
/// queue is cleared and the notify never runs (matching the in-tx
/// audit row's fate).
impl AuditPostCommit for PostCommitEffects {
    fn queue_notify(&self, notify: AuditNotifyFn) {
        self.push(Box::new(move || notify()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn empty_queue_drains_cleanly() {
        let q = PostCommitEffects::new();
        assert!(q.is_empty());
        q.drain_all().await;
        assert!(q.is_empty());
    }

    #[tokio::test]
    async fn drain_runs_each_effect_once() {
        let q = PostCommitEffects::new();
        let counter = Arc::new(AtomicU32::new(0));
        for _ in 0..5 {
            let c = Arc::clone(&counter);
            q.push_fn(move || async move {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(q.len(), 5);
        q.drain_all().await;
        assert_eq!(counter.load(Ordering::SeqCst), 5);
        assert!(q.is_empty());
    }

    #[tokio::test]
    async fn a_dropped_drain_still_runs_its_effects() {
        // a client that disconnects mid-drain drops the dispatching future;
        // the committed transaction's effects must run anyway
        let q = PostCommitEffects::new();
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let counter = Arc::new(AtomicU32::new(0));
        {
            let (started, release, counter) = (
                Arc::clone(&started),
                Arc::clone(&release),
                Arc::clone(&counter),
            );
            q.push_fn(move || async move {
                started.notify_one();
                release.notified().await;
                counter.fetch_add(1, Ordering::SeqCst);
            });
        }
        let drain = tokio::spawn(async move { q.drain_all().await });
        started.notified().await;
        drain.abort();
        assert!(drain.await.unwrap_err().is_cancelled());
        release.notify_one();
        for _ in 0..100 {
            if counter.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "the effect ran to completion"
        );
    }

    #[tokio::test]
    async fn clear_drops_effects_without_running() {
        let q = PostCommitEffects::new();
        let counter = Arc::new(AtomicU32::new(0));
        for _ in 0..3 {
            let c = Arc::clone(&counter);
            q.push_fn(move || async move {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
        q.clear();
        q.drain_all().await;
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}
