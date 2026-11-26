//! Observe a lock wait a test arranged, exactly: a session waiting on a lock
//! is read off `pg_stat_activity`, never inferred from a sleep.
//!
//! The overview is the crate doc § Lock waits.

#![expect(
    clippy::expect_used,
    reason = "a test harness: a setup fault panics loudly naming the step, and the in-tests carve-out doesn't reach a library module"
)]

use std::time::Duration;

use fuz_db::Pool;
use tokio::time::Instant;

/// How long a lock wait a test arranged may take to show: a bound on a hang
/// only, set far past any scheduling delay, never a timing assertion.
pub const LOCK_WAIT_DEADLINE: Duration = Duration::from_secs(20);

/// How often a wait reads the server's view of the sessions.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Sessions of `pool`'s database waiting on a lock.
///
/// # Panics
///
/// When the pool is unreachable or the read fails (on pglet, always — see the
/// crate doc § Lock waits).
pub async fn lock_waiters(pool: &Pool) -> i64 {
    pool.get()
        .await
        .expect("lock_waiters: pool.get")
        .query_one(
            "SELECT COUNT(*) FROM pg_stat_activity
             WHERE wait_event_type = 'Lock' AND datname = current_database()",
            &[],
        )
        .await
        .expect("lock_waiters: read pg_stat_activity")
        .get(0)
}

/// Sessions waiting on a lock the backend `holder_pid` holds.
///
/// # Panics
///
/// As [`lock_waiters`].
pub async fn blocked_by(pool: &Pool, holder_pid: i32) -> i64 {
    pool.get()
        .await
        .expect("blocked_by: pool.get")
        .query_one(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
            &[&holder_pid],
        )
        .await
        .expect("blocked_by: read pg_stat_activity")
        .get(0)
}

/// The backend pid of the session `client` runs on — the holder a
/// [`blocked_by`] wait is scoped to.
///
/// # Panics
///
/// When the read fails.
pub async fn backend_pid(client: &impl deadpool_postgres::GenericClient) -> i32 {
    client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("backend_pid: read pg_backend_pid()")
        .get(0)
}

/// Wait until `n` sessions of `pool`'s database wait on a lock.
///
/// # Panics
///
/// Naming `what` when none comes within [`LOCK_WAIT_DEADLINE`], and as
/// [`lock_waiters`].
pub async fn until_lock_waiters(pool: &Pool, n: i64, what: &str) {
    until_lock_waiters_or(pool, n, || false, what).await;
}

/// Wait until `n` sessions of `pool`'s database wait on a lock, or `finished`
/// returns `true`. Returns whether the waiters came — `false` when `finished`
/// ended the wait first.
///
/// # Panics
///
/// Naming `what` when neither comes within [`LOCK_WAIT_DEADLINE`], and as
/// [`lock_waiters`].
pub async fn until_lock_waiters_or(
    pool: &Pool,
    n: i64,
    finished: impl Fn() -> bool,
    what: &str,
) -> bool {
    let deadline = Instant::now() + LOCK_WAIT_DEADLINE;
    loop {
        if finished() {
            return false;
        }
        if lock_waiters(pool).await >= n {
            return true;
        }
        assert!(
            Instant::now() < deadline,
            "no lock wait within {LOCK_WAIT_DEADLINE:?}: {what} \
             (awaited {n} waiting session(s) in the test database)"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Wait until a session waits on a lock the backend `holder_pid` holds.
///
/// # Panics
///
/// Naming `what` when none comes within [`LOCK_WAIT_DEADLINE`], and as
/// [`blocked_by`].
pub async fn until_blocked_by(pool: &Pool, holder_pid: i32, what: &str) {
    until_blocked_by_or(pool, holder_pid, || false, what).await;
}

/// Wait until a session waits on a lock the backend `holder_pid` holds, or
/// `finished` returns `true`. Returns whether a session waited — `false` when
/// `finished` ended the wait first.
///
/// # Panics
///
/// Naming `what` when neither comes within [`LOCK_WAIT_DEADLINE`], and as
/// [`blocked_by`].
pub async fn until_blocked_by_or(
    pool: &Pool,
    holder_pid: i32,
    finished: impl Fn() -> bool,
    what: &str,
) -> bool {
    let deadline = Instant::now() + LOCK_WAIT_DEADLINE;
    loop {
        if finished() {
            return false;
        }
        if blocked_by(pool, holder_pid).await >= 1 {
            return true;
        }
        assert!(
            Instant::now() < deadline,
            "no lock wait within {LOCK_WAIT_DEADLINE:?}: {what} \
             (awaited a session blocked by backend {holder_pid})"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Run `call` in a transaction of its own, committed when it returns `Ok`, as
/// the dispatcher does; an `Err` rolls the transaction back as it drops.
///
/// `in_tx!(pool, |tx| call(&tx))` — `pool` a [`fuz_db::Pool`] (or a
/// [`crate::TestDb`]), `call` a future over the `deadpool_postgres`
/// transaction bound to `tx`, evaluating to a `Result`. A macro, not a
/// function, so `call` borrows the transaction without a boxed closure.
///
/// # Panics
///
/// When a connection can't be checked out, or the transaction can't begin or
/// commit.
#[macro_export]
macro_rules! in_tx {
    ($pool:expr, |$tx:ident| $call:expr) => {{
        let mut client = $pool.get().await.expect("in_tx: pool.get");
        let $tx = client.transaction().await.expect("in_tx: begin");
        let result = $call.await;
        if result.is_ok() {
            $tx.commit().await.expect("in_tx: commit");
        }
        result
    }};
}

/// Race two calls over a lock.
///
/// Run `first` on a transaction left open, then `second` (a future, usually
/// an [`in_tx!`](crate::in_tx)); once `second` waits on a lock the first
/// holds — or, failing the case, has finished without waiting — commit the
/// first (roll it back when it failed). Evaluates to `(first, second,
/// waited)`, `waited` whether `second` waited on the first.
///
/// `race!(pool, first: |tx| call(&tx), second: in_tx!(pool, |tx| other(&tx)))`.
/// The wait is scoped to the first's backend ([`until_blocked_by_or`]), so no
/// other session's wait passes for the second's.
///
/// # Panics
///
/// When neither comes within [`LOCK_WAIT_DEADLINE`], and on a database fault
/// holding, committing, or rolling back the first.
#[macro_export]
macro_rules! race {
    ($pool:expr, first: |$ftx:ident| $first:expr, second: $second:expr) => {{
        let pool = $pool;
        let mut holder_client = pool.get().await.expect("race: pool.get");
        let $ftx = holder_client.transaction().await.expect("race: begin");
        let holder_pid = $crate::backend_pid(&$ftx).await;
        let first = $first.await;
        let first_ok = first.is_ok();
        let done = ::std::sync::atomic::AtomicBool::new(false);
        let run = async {
            let result = $second;
            done.store(true, ::std::sync::atomic::Ordering::SeqCst);
            result
        };
        let finish = async {
            let waited = $crate::until_blocked_by_or(
                pool,
                holder_pid,
                || done.load(::std::sync::atomic::Ordering::SeqCst),
                "the second neither waits on the first nor finishes",
            )
            .await;
            if first_ok {
                $ftx.commit().await.expect("race: commit the first");
            } else {
                $ftx.rollback().await.expect("race: roll the first back");
            }
            waited
        };
        let (second, waited) = ::tokio::join!(run, finish);
        (first, second, waited)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TestEngine, TestingDbOptions};

    const DB: TestingDbOptions<'static> = TestingDbOptions {
        suite: "fuz_testing_lock_wait",
        migrations: &[],
        setup_sql: Some("CREATE TABLE probe (id int PRIMARY KEY); INSERT INTO probe VALUES (1)"),
        engine: TestEngine::Postgres,
    };

    /// Each observer sees the wait a held row lock makes, scoped both ways.
    #[tokio::test]
    #[ignore = "postgres-only: observes a lock wait"]
    async fn a_held_row_lock_is_observed() {
        let pool = DB.open().await;
        let mut holder_client = pool.get().await.expect("pool.get");
        let holder = holder_client.transaction().await.expect("begin");
        holder
            .execute("SELECT id FROM probe WHERE id = 1 FOR UPDATE", &[])
            .await
            .expect("hold the row");
        let holder_pid = backend_pid(&holder).await;
        let waiter = tokio::spawn({
            let pool = pool.pool().clone();
            async move {
                let client = pool.get().await.expect("pool.get");
                client
                    .execute("UPDATE probe SET id = 1 WHERE id = 1", &[])
                    .await
                    .expect("the update")
            }
        });
        until_lock_waiters(&pool, 1, "the update waits on the held row").await;
        until_blocked_by(&pool, holder_pid, "the update waits on the holder").await;
        assert_eq!(lock_waiters(&pool).await, 1);
        assert_eq!(blocked_by(&pool, holder_pid).await, 1);
        assert!(!waiter.is_finished(), "the update still waits");
        holder.commit().await.expect("release");
        assert_eq!(waiter.await.expect("the update's task"), 1);
        assert_eq!(lock_waiters(&pool).await, 0);
    }

    /// A finished call ends the `_or` waits without a lock wait.
    #[tokio::test]
    #[ignore = "postgres-only: observes a lock wait"]
    async fn a_finished_call_ends_the_wait_without_waiting() {
        let pool = DB.open().await;
        assert!(!until_lock_waiters_or(&pool, 1, || true, "finished").await);
        assert!(!until_blocked_by_or(&pool, 0, || true, "finished").await);
    }

    /// `race!` reports a second call that waits on the first, and one that
    /// doesn't.
    #[tokio::test]
    #[ignore = "postgres-only: observes a lock wait"]
    async fn race_reports_whether_the_second_waited() {
        let pool = DB.open().await;
        let update = "UPDATE probe SET id = 1 WHERE id = 1";
        let (first, second, waited) = crate::race!(
            &pool,
            first: |tx| tx.execute(update, &[]),
            second: crate::in_tx!(pool, |tx| tx.execute(update, &[]))
        );
        assert_eq!((first.expect("first"), second.expect("second")), (1, 1));
        assert!(waited, "the second update waits on the first's row");
        let read = "SELECT id FROM probe";
        let (first, second, waited) = crate::race!(
            &pool,
            first: |tx| tx.execute(update, &[]),
            second: crate::in_tx!(pool, |tx| tx.query(read, &[]))
        );
        assert!(first.is_ok() && second.is_ok());
        assert!(!waited, "a plain read never waits on a row lock");
    }
}
