//! Whether the work running on a task has started a commit.
//!
//! A request — an HTTP route, an action dispatch over HTTP or a WebSocket —
//! can be dropped at any await: its client goes away, its socket's loop ends.
//! Dropped before its commit, its transaction rolls back, which is sound.
//! Dropped while its commit is in flight, the `COMMIT` has already gone to
//! the server and lands, but whatever the request runs after it — the
//! post-commit effects, a revocation's connection closes — never runs, so a
//! committed change goes unannounced.
//!
//! So the place that owns the drop scopes the request in a [`CommitWatch`]
//! ([`CommitWatch::scope`]), [`crate::commit_checked`] marks the watch in
//! scope the moment a commit starts, and the owner, dropping the request,
//! reads [`CommitWatch::is_started`] to decide: not started, let it drop; started,
//! hand it somewhere to finish (`fuz_http::BackgroundWrites::finish_past_commit`
//! does both halves). The mark rides a task-local, so every commit through
//! [`crate::commit_checked`] under a scoped request is seen with no plumbing
//! through the code between them; a commit outside any scope (an upkeep
//! sweep, a migration) marks nothing.
//!
//! What the mark does not see:
//!
//! - **A commit on another task.** The task-local belongs to the request's
//!   own task, so a commit in a task the request spawns marks nothing, and
//!   dropping the request then cancels whatever follows that commit on the
//!   request's task. Keep a commit's tail — its effects, its closes — on the
//!   task that commits, as the bootstrap does (its burn, commit and tail run
//!   together on one tracked task).
//! - **Autocommit writes.** A statement on a pooled client commits on its
//!   own, through no [`crate::commit_checked`], so it marks nothing: a
//!   request dropped after one is cancelled like any other.
//! - **Anything past the first commit.** The mark is one-way: once a request
//!   has started a commit, everything it does after — a second transaction
//!   included — runs to completion when it is dropped.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

tokio::task_local! {
    static COMMIT_WATCH: Arc<CommitWatch>;
}

/// Set once a commit has started in the scope it watches.
#[derive(Debug, Default)]
pub struct CommitWatch(AtomicBool);

impl CommitWatch {
    /// Run `future` with `watch` in scope, so a commit it starts through
    /// [`crate::commit_checked`] marks it. The scope travels with the
    /// future, so it still holds if the future is moved to another task.
    pub fn scope<F: Future>(watch: Arc<Self>, future: F) -> impl Future<Output = F::Output> {
        COMMIT_WATCH.scope(watch, future)
    }

    /// Whether a commit has started in the watched scope.
    #[must_use]
    pub fn is_started(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Mark the watch in scope, if any — called by [`crate::commit_checked`] as
/// its commit starts.
pub(crate) fn mark_commit_started() {
    let _ = COMMIT_WATCH.try_with(|watch| watch.0.store(true, Ordering::Release));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_mark_in_scope_sets_the_watch_and_one_outside_sets_nothing() {
        let watch = Arc::new(CommitWatch::default());
        mark_commit_started();
        assert!(!watch.is_started(), "no scope, no mark");
        CommitWatch::scope(Arc::clone(&watch), async { mark_commit_started() }).await;
        assert!(watch.is_started());
    }

    #[tokio::test]
    async fn the_scope_travels_with_a_future_moved_to_another_task() {
        let watch = Arc::new(CommitWatch::default());
        let scoped = CommitWatch::scope(Arc::clone(&watch), async {
            tokio::task::yield_now().await;
            mark_commit_started();
        });
        tokio::spawn(scoped).await.expect("the task runs");
        assert!(watch.is_started());
    }
}
