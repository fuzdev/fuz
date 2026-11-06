//! Argon2id implementation of [`PasswordHasher`].
//!
//! OWASP defaults via `argon2::Argon2::default()`. Hashing runs on
//! `tokio::task::spawn_blocking` to avoid blocking the async runtime
//! (CPU-bound, ~50 ms / call).
//!
//! Every hash and verify first takes a permit from one process-wide
//! semaphore sized to the machine's parallelism (`ARGON2_PERMITS`). Each
//! call allocates its Argon2 memory (~19 MiB at the defaults) on a blocking
//! thread, and tokio's blocking pool grows to 512 threads, so without the
//! bound a burst of concurrent signups or logins costs a burst of memory no
//! rate limiter caps (a limiter counts attempts, not concurrent ones). The
//! semaphore is a static rather than a hasher field because every consumer
//! builds its own [`Argon2idHasher`]; one process, one bound.

use std::num::NonZeroUsize;
use std::sync::LazyLock;

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher as ArgonHasher, PasswordVerifier, SaltString,
};
use futures::future::{BoxFuture, FutureExt};
use tokio::sync::Semaphore;

use crate::password_hasher::{HashedPassword, PasswordHasher};

/// Process-wide bound on concurrent Argon2 work: one permit per available
/// core (`std::thread::available_parallelism`, 1 when unknown).
///
/// More in flight than cores buys no throughput — each call is CPU-bound on
/// its own thread — and costs one Argon2 memory block per extra call. A
/// caller past the bound waits for a permit; it holds no database client
/// while it waits (login and the password change release theirs before the
/// verify, signup hashes before it opens its transaction).
static ARGON2_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| {
    Semaphore::new(std::thread::available_parallelism().map_or(1, NonZeroUsize::get))
});

/// Run `work` on the blocking pool once `permits` grants a permit.
///
/// The permit moves into the blocking closure and drops when `work` returns,
/// so the bound counts the CPU work itself: a caller whose future is dropped
/// mid-hash (a cancelled request) leaves the closure running and the permit
/// held until it finishes, rather than freeing a slot for another hash while
/// this one still runs.
///
/// # Errors
///
/// A message when `permits` is closed (never, for [`ARGON2_PERMITS`]) or when
/// `work` panicked, carrying the panic's payload.
async fn run_bounded<T, F>(permits: &'static Semaphore, work: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = permits
        .acquire()
        .await
        .map_err(|e| format!("argon2 permits unavailable: {e}"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|e| format!("argon2 task failed: {e}"))
}

/// Dummy Argon2 hash for enumeration prevention — run argon2 verify
/// against a known hash when the account doesn't exist so login timing
/// is consistent.
pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Argon2id hasher using OWASP-default parameters.
///
/// Cheap to clone (no
/// owned state beyond `Argon2::default()`'s internal pointer-to-static
/// params); typically held as `Arc<Argon2idHasher>` on the consumer's
/// auth state, then cast to `Arc<dyn PasswordHasher>`.
#[derive(Debug, Clone, Default)]
pub struct Argon2idHasher;

impl Argon2idHasher {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl PasswordHasher for Argon2idHasher {
    fn hash(&self, password: String) -> BoxFuture<'static, Result<HashedPassword, String>> {
        async move {
            run_bounded(&ARGON2_PERMITS, move || {
                let mut salt_bytes = [0u8; 16];
                getrandom::fill(&mut salt_bytes)
                    .map_err(|e| format!("salt generation failed: {e}"))?;
                let salt = SaltString::encode_b64(&salt_bytes)
                    .map_err(|e| format!("salt encoding failed: {e}"))?;
                let argon2 = Argon2::default();
                let hash = argon2
                    .hash_password(password.as_bytes(), &salt)
                    .map_err(|e| format!("hash failed: {e}"))?;
                Ok(HashedPassword::new(hash.to_string()))
            })
            .await?
        }
        .boxed()
    }

    fn verify(&self, password: String, hash: String) -> BoxFuture<'static, bool> {
        async move {
            run_bounded(&ARGON2_PERMITS, move || {
                let Ok(parsed) = PasswordHash::new(&hash) else {
                    return false;
                };
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            })
            .await
            .unwrap_or_else(|e| {
                // Refused, as a wrong password is — and logged, since only a
                // fault gets here.
                tracing::error!(error = %e, "password verify did not complete");
                false
            })
        }
        .boxed()
    }

    fn dummy_hash(&self) -> &'static str {
        DUMMY_HASH
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_flight_work_never_exceeds_the_permits() {
        static PERMITS: Semaphore = Semaphore::const_new(2);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        // Every call is spawned before any is awaited, so all twelve contend.
        let mut calls = Vec::new();
        for _ in 0..12 {
            let in_flight = Arc::clone(&in_flight);
            let peak = Arc::clone(&peak);
            calls.push(tokio::spawn(run_bounded(&PERMITS, move || {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                in_flight.fetch_sub(1, Ordering::SeqCst);
            })));
        }
        for call in calls {
            assert_eq!(call.await.unwrap(), Ok(()));
        }
        // At the bound, not under it: twelve 20 ms calls on a pool of 512
        // blocking threads overlap, so a peak of 1 would mean the bound
        // serialized the work rather than capping it.
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_caller_holds_its_permit_until_the_work_ends() {
        static PERMITS: Semaphore = Semaphore::const_new(1);
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel::<()>();
        let caller = tokio::spawn(run_bounded(&PERMITS, move || {
            started_tx.send(()).unwrap();
            finish_rx.recv().unwrap();
        }));
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();
        // The request is cancelled mid-hash; the blocking work keeps running.
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(
            PERMITS.try_acquire().is_err(),
            "the permit must stay with the running work, not the dropped caller"
        );
        finish_tx.send(()).unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(5), PERMITS.acquire())
            .await
            .expect("the permit frees once the work ends")
            .unwrap();
        drop(permit);
    }

    #[tokio::test]
    async fn a_closed_semaphore_runs_nothing() {
        static PERMITS: Semaphore = Semaphore::const_new(1);
        PERMITS.close();
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_work = Arc::clone(&ran);
        let result = run_bounded(&PERMITS, move || {
            ran_in_work.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert!(result.is_err());
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn hash_then_verify_round_trips_through_the_bound() {
        let hasher = Argon2idHasher::new();
        let hashed = hasher
            .hash("bounded-password-Qm4".to_owned())
            .await
            .unwrap();
        assert!(
            hasher
                .verify(
                    "bounded-password-Qm4".to_owned(),
                    hashed.as_str().to_owned()
                )
                .await
        );
        assert!(
            !hasher
                .verify(
                    "another-password-Qm4".to_owned(),
                    hashed.as_str().to_owned()
                )
                .await
        );
    }

    #[tokio::test]
    async fn a_panicking_task_carries_its_payload() {
        static PERMITS: Semaphore = Semaphore::const_new(1);
        #[allow(clippy::panic)] // the panic is the input under test
        let result = run_bounded(&PERMITS, || -> () { panic!("argon2 exploded") }).await;
        let error = result.expect_err("a panic is an error");
        assert!(error.contains("argon2 exploded"), "{error}");
        assert!(
            PERMITS.try_acquire().is_ok(),
            "the permit frees with the task"
        );
    }
}
