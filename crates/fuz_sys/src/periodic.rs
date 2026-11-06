//! Periodic background task primitive (transport-free).
//!
//! The loop every long-running fuz process reaches for when it owns upkeep —
//! an expiry sweep, a cleanup pass: one pass at startup, then one per
//! interval, until shutdown. [`spawn_periodic`] is that loop in one place, so
//! a sweep is its pass plus one call, and every sweep in a process stops on
//! the same [`CancellationToken`] the server drains on (`signal`'s
//! `shutdown_token`, behind its own feature).
//!
//! ```ignore
//! let shutdown = fuz_sys::signal::shutdown_token();
//! let sweep = fuz_sys::periodic::spawn_periodic(
//!     "temp sweep",
//!     Duration::from_secs(60 * 60),
//!     shutdown.clone(),
//!     move || {
//!         let root = root.clone();
//!         async move { sweep_temps(&root).await }
//!     },
//! );
//! // … serve until `shutdown` is cancelled …
//! shutdown.cancel();
//! let _ = sweep.await;
//! ```

use std::error::Error;
use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

/// Spawn a task that runs `pass` now, then once per `interval`, until
/// `shutdown` is cancelled.
///
/// - **Startup pass.** The first pass starts as soon as the task is polled;
///   later passes follow one `interval` apart.
/// - **A slow pass delays the schedule.** Passes never overlap, and a pass
///   that overruns its interval pushes the next one back
///   ([`MissedTickBehavior::Delay`]): the next pass starts when the slow one
///   ends, the one after a full `interval` later — no burst of catch-up
///   passes.
/// - **A failed pass is logged, never fatal.** An `Err` is logged at `warn`
///   with `name` and its full source chain — recorded as an error value, since
///   an error's `Display` commonly leaves its cause to `source()` — and the
///   loop goes on to the next interval, so an outage is retried rather than
///   ending the upkeep for the life of the process.
/// - **Shutdown drops the pass in progress.** Cancelling `shutdown` ends the
///   task at its next await point, whether it is waiting out the interval or
///   inside a pass, so awaiting the returned handle after a cancel is prompt
///   and never waits on a pass. A pass must therefore be safe to drop
///   mid-flight — transactional work rolls back and the next start's startup
///   pass picks it up. A token cancelled before the task first runs means no
///   pass runs at all.
///
/// `pass` is called once per pass and returns that pass's future, so state a
/// pass needs is cloned into each future (`Arc`s, a pool handle). `name`
/// labels the task in the failure log.
///
/// The handle resolves once the loop has stopped; awaiting it after
/// cancelling `shutdown` is how a caller joins the task before exiting.
///
/// # Panics
///
/// If `interval` is zero, or when called outside a tokio runtime — both at
/// the call site, before anything is spawned.
pub fn spawn_periodic<F, Fut, E>(
    name: &'static str,
    interval: Duration,
    shutdown: CancellationToken,
    mut pass: F,
) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send,
    E: Error + 'static,
{
    // built here, not in the task, so a zero interval panics in the caller;
    // its first tick completes at once: the startup pass
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tokio::spawn(async move {
        let passes = async {
            loop {
                ticker.tick().await;
                if let Err(e) = pass().await {
                    // as an error value, not `%e`: the subscriber walks
                    // `source()`, where the cause usually is
                    let error: &(dyn Error + 'static) = &e;
                    tracing::warn!(task = name, error, "periodic pass failed");
                }
            }
        };
        tokio::select! {
            // shutdown first: a cancelled token wins over a due pass
            biased;
            () = shutdown.cancelled() => {}
            () = passes => {}
        }
    })
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::mpsc;
    use tokio::time::Instant;

    use super::*;

    const INTERVAL: Duration = Duration::from_secs(10);

    /// Join a task whose token was cancelled. Bounded on the paused clock, so
    /// a loop that ignores its token fails the test instead of hanging it.
    async fn join_cancelled(task: JoinHandle<()>) {
        tokio::time::timeout(INTERVAL * 1000, task)
            .await
            .expect("the task ends once its token is cancelled")
            .expect("the task ends cleanly");
    }

    /// A pass that reports the paused-clock offset it started at.
    fn recording_pass(
        started: Instant,
        tx: mpsc::UnboundedSender<Duration>,
    ) -> impl FnMut() -> std::future::Ready<Result<(), Infallible>> + Send + 'static {
        move || {
            tx.send(started.elapsed())
                .expect("the test holds the receiver");
            std::future::ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_startup_pass_runs_at_once_then_one_per_interval() {
        let started = Instant::now();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let task = spawn_periodic(
            "test",
            INTERVAL,
            shutdown.clone(),
            recording_pass(started, tx),
        );

        assert_eq!(rx.recv().await, Some(Duration::ZERO), "the startup pass");
        assert_eq!(rx.recv().await, Some(INTERVAL));
        assert_eq!(rx.recv().await, Some(INTERVAL * 2));

        shutdown.cancel();
        join_cancelled(task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_pass_does_not_end_the_loop() {
        let started = Instant::now();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let task = spawn_periodic("test", INTERVAL, shutdown.clone(), move || {
            tx.send(started.elapsed())
                .expect("the test holds the receiver");
            std::future::ready(Err::<(), _>(std::io::Error::other(
                "the database is unreachable",
            )))
        });

        // every pass fails, and each next one still runs on schedule
        assert_eq!(rx.recv().await, Some(Duration::ZERO));
        assert_eq!(rx.recv().await, Some(INTERVAL));
        assert_eq!(rx.recv().await, Some(INTERVAL * 2));
        assert!(!task.is_finished());

        shutdown.cancel();
        join_cancelled(task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_ends_the_loop_between_passes() {
        let started = Instant::now();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let task = spawn_periodic(
            "test",
            INTERVAL,
            shutdown.clone(),
            recording_pass(started, tx),
        );
        assert_eq!(rx.recv().await, Some(Duration::ZERO));

        shutdown.cancel();
        join_cancelled(task).await;

        // the task ended without waiting out the interval, and dropped the
        // pass closure with it: the channel closes with no further pass
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(rx.recv().await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_drops_a_pass_in_progress() {
        let started = Instant::now();
        let entered = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let task = spawn_periodic("test", INTERVAL, shutdown.clone(), {
            let entered = Arc::clone(&entered);
            let finished = Arc::clone(&finished);
            move || {
                let entered = Arc::clone(&entered);
                let finished = Arc::clone(&finished);
                let tx = tx.clone();
                async move {
                    entered.fetch_add(1, Ordering::SeqCst);
                    tx.send(()).expect("the test holds the receiver");
                    // a pass far longer than the test waits
                    tokio::time::sleep(INTERVAL * 100).await;
                    finished.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), Infallible>(())
                }
            }
        });
        rx.recv().await.expect("the startup pass began");

        shutdown.cancel();
        join_cancelled(task).await;

        assert_eq!(started.elapsed(), Duration::ZERO, "the join is prompt");
        assert_eq!(entered.load(Ordering::SeqCst), 1);
        assert_eq!(finished.load(Ordering::SeqCst), 0, "the pass was dropped");
    }

    #[tokio::test(start_paused = true)]
    async fn an_already_cancelled_token_runs_no_pass() {
        let passes = Arc::new(AtomicUsize::new(0));
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let task = spawn_periodic("test", INTERVAL, shutdown, {
            let passes = Arc::clone(&passes);
            move || {
                passes.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok::<(), Infallible>(()))
            }
        });
        join_cancelled(task).await;
        assert_eq!(passes.load(Ordering::SeqCst), 0);
    }

    /// `Delay`, not tokio's default `Burst` (which would start passes at
    /// 25s, 25s, 30s) or `Skip` (25s, 30s).
    #[tokio::test(start_paused = true)]
    async fn a_slow_pass_delays_the_schedule_instead_of_bursting() {
        let started = Instant::now();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let shutdown = CancellationToken::new();
        let mut first = true;
        let task = spawn_periodic("test", INTERVAL, shutdown.clone(), move || {
            tx.send(started.elapsed())
                .expect("the test holds the receiver");
            // only the startup pass overruns: two and a half intervals
            let overrun = std::mem::take(&mut first).then_some(INTERVAL * 5 / 2);
            async move {
                if let Some(overrun) = overrun {
                    tokio::time::sleep(overrun).await;
                }
                Ok::<(), Infallible>(())
            }
        });

        assert_eq!(rx.recv().await, Some(Duration::ZERO));
        // the overdue pass starts when the slow one ends …
        assert_eq!(rx.recv().await, Some(Duration::from_secs(25)));
        // … and the schedule restarts from there, a full interval apart
        assert_eq!(rx.recv().await, Some(Duration::from_secs(35)));
        assert_eq!(rx.recv().await, Some(Duration::from_secs(45)));

        shutdown.cancel();
        join_cancelled(task).await;
    }

    #[tokio::test]
    #[should_panic(expected = "`period` must be non-zero")]
    async fn a_zero_interval_panics_at_the_call_site() {
        let _task = spawn_periodic("test", Duration::ZERO, CancellationToken::new(), || {
            std::future::ready(Ok::<(), Infallible>(()))
        });
    }
}
