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

/// Commit `tx` as the dispatcher commits an action's transaction, with
/// [`fuz_db::commit_checked`] — the commit of [`in_tx!`](crate::in_tx) and of
/// [`race!`](crate::race)'s first.
///
/// # Panics
///
/// When the transaction was aborted: the call returned `Ok` after swallowing
/// a failed statement, which the dispatcher answers with an error rather
/// than the call's `Ok` (the transaction is rolled back first). And when the
/// commit fails for another reason, as on any database fault.
#[expect(
    clippy::panic,
    reason = "a test harness: a call the dispatcher would refuse fails its test loudly"
)]
pub async fn commit_as_dispatcher(tx: deadpool_postgres::Transaction<'_>) {
    match fuz_db::commit_checked(tx).await {
        Ok(()) => {}
        Err(fuz_db::DbError::TransactionAborted(source)) => panic!(
            "commit as the dispatcher: the call returned Ok over an aborted transaction — it swallowed a failed \
             statement, which the dispatcher answers with an error; rolled back: {source}"
        ),
        Err(e) => panic!("commit as the dispatcher: {e}"),
    }
}

/// Run `call` in a transaction of its own, committed when it returns `Ok` as
/// the dispatcher commits ([`commit_as_dispatcher`]), and rolled back when it
/// returns `Err`.
///
/// `in_tx!(pool, |tx| call(&tx))` — `pool` a [`fuz_db::Pool`] (or a
/// [`crate::TestDb`]), `call` a future over the `deadpool_postgres`
/// transaction bound to `tx`, evaluating to a `Result`. A macro, not a
/// function, so `call` borrows the transaction without a boxed closure.
///
/// The rollback is awaited, not left to the transaction's drop: a dropped
/// transaction only queues its `ROLLBACK`, so a refused call's locks could
/// still be held when the next statement on another session — or a
/// [`race!`](crate::race) observer — runs.
///
/// # Panics
///
/// When a connection can't be checked out, or the transaction can't begin,
/// commit, or roll back — and when `call` returns `Ok` after swallowing a
/// statement error that aborted the transaction: the dispatcher would answer
/// an error, so a test passing on that `Ok` would vouch for a call the server
/// refuses.
#[macro_export]
macro_rules! in_tx {
    ($pool:expr, |$tx:ident| $call:expr) => {{
        let mut client = $pool.get().await.expect("in_tx: pool.get");
        let $tx = client.transaction().await.expect("in_tx: begin");
        let result = $call.await;
        if result.is_ok() {
            $crate::commit_as_dispatcher($tx).await;
        } else {
            $tx.rollback().await.expect("in_tx: rollback");
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
/// When neither comes within [`LOCK_WAIT_DEADLINE`], on a database fault
/// holding, committing, or rolling back the first, and when the first returned
/// `Ok` over an aborted transaction ([`commit_as_dispatcher`]).
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
                $crate::commit_as_dispatcher($ftx).await;
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

    /// A refused call's locks are released before `in_tx!` answers.
    ///
    /// The call locks row 1, then leaves a statement waiting on row 2 (held
    /// by a gate session) and returns `Err`. Its `ROLLBACK` queues behind that
    /// statement, so a macro that left the rollback to the transaction's drop
    /// answers while row 1 is still locked, and the probe after it — the next
    /// statement, on another session — is refused. The gate opens once the
    /// statement waits, except when the macro has already answered: then only
    /// after the probe, so the old answer shows every run, not by timing.
    #[tokio::test]
    #[ignore = "postgres-only: observes a lock wait"]
    async fn a_refused_call_releases_its_locks_before_in_tx_answers() {
        use futures::FutureExt as _;
        use std::sync::atomic::{AtomicBool, Ordering};

        let pool = DB.open().await;
        pool.get()
            .await
            .expect("pool.get")
            .execute("INSERT INTO probe VALUES (2)", &[])
            .await
            .expect("seed row 2");
        let mut gate_client = pool.get().await.expect("pool.get");
        let gate = gate_client.transaction().await.expect("begin");
        gate.execute("SELECT id FROM probe WHERE id = 2 FOR UPDATE", &[])
            .await
            .expect("hold row 2");
        let gate_pid = backend_pid(&gate).await;
        // Checked out now, so the probe never gets the call's client back
        // from the pool and queues behind its waiting statement.
        let prober = pool.get().await.expect("pool.get");
        let answered = AtomicBool::new(false);
        let probed = tokio::sync::Notify::new();

        let caller = async {
            let refused = crate::in_tx!(pool, |tx| async {
                tx.execute("SELECT id FROM probe WHERE id = 1 FOR UPDATE", &[])
                    .await
                    .map_err(|e| e.to_string())?;
                // Sent, never awaited: one poll queues the statement.
                let _ = tx
                    .batch_execute("SELECT id FROM probe WHERE id = 2 FOR UPDATE")
                    .now_or_never();
                Err::<(), String>("refused".to_owned())
            });
            answered.store(true, Ordering::SeqCst);
            assert!(refused.is_err(), "the call is refused");
            let probe = prober
                .execute("SELECT id FROM probe WHERE id = 1 FOR UPDATE NOWAIT", &[])
                .await;
            probed.notify_one();
            probe
        };
        let release = async {
            // An answer ends the wait too: the call's client is back in the
            // pool then, and an observer checking it out would queue behind
            // the waiting statement.
            let waited = until_blocked_by_or(
                &pool,
                gate_pid,
                || answered.load(Ordering::SeqCst),
                "the call's statement waits on row 2",
            )
            .await;
            if !waited {
                probed.notified().await;
            }
            gate.commit().await.expect("release row 2");
        };
        let (probe, ()) = tokio::join!(caller, release);
        assert_eq!(
            probe.expect("row 1 is free once in_tx! answers the refused call"),
            1
        );
    }

    /// A call that swallows a failed statement and returns `Ok` is refused
    /// as the dispatcher refuses it — `in_tx!` panics rather than answer the
    /// call's `Ok` — and nothing it wrote persists. On a plain `COMMIT` the
    /// server silently rolls the aborted transaction back and the `Ok` stands.
    #[tokio::test]
    async fn an_ok_over_an_aborted_transaction_is_refused() {
        use futures::FutureExt as _;
        use std::panic::AssertUnwindSafe;

        let db = TestingDbOptions {
            suite: "fuz_testing_in_tx",
            migrations: &[],
            setup_sql: Some("CREATE TABLE probe (id int PRIMARY KEY)"),
            engine: TestEngine::Any,
        };
        let pool = db.open().await;
        let swallowing = AssertUnwindSafe(async {
            crate::in_tx!(pool, |tx| async {
                tx.execute("INSERT INTO probe VALUES (1)", &[]).await?;
                // the duplicate fails and aborts the transaction; its error
                // is dropped
                let _ = tx.execute("INSERT INTO probe VALUES (1)", &[]).await;
                Ok::<(), tokio_postgres::Error>(())
            })
        })
        .catch_unwind()
        .await;
        let Err(panic) = swallowing else {
            panic!("in_tx! answered the call's Ok over an aborted transaction");
        };
        let message = panic.downcast_ref::<String>().map_or("", String::as_str);
        assert!(
            message.contains(
                "commit as the dispatcher: the call returned Ok over an aborted transaction"
            ),
            "panics naming the swallowed statement, not another fault: {message}"
        );
        let count: i64 = pool
            .get()
            .await
            .expect("pool.get")
            .query_one("SELECT COUNT(*) FROM probe", &[])
            .await
            .expect("count the rows")
            .get(0);
        assert_eq!(count, 0, "the aborted transaction left nothing behind");
    }

    /// A first call that swallows a failed statement and returns `Ok` is
    /// refused as `in_tx!` refuses one: `race!` panics committing it, and
    /// nothing it wrote persists.
    #[tokio::test]
    #[ignore = "postgres-only: race! scopes its wait to a backend"]
    async fn race_refuses_a_first_ok_over_an_aborted_transaction() {
        use futures::FutureExt as _;
        use std::panic::AssertUnwindSafe;

        let pool = DB.open().await;
        let raced = AssertUnwindSafe(async {
            crate::race!(
                &pool,
                first: |tx| async {
                    tx.execute("INSERT INTO probe VALUES (2)", &[]).await?;
                    // the duplicate fails and aborts the transaction; its
                    // error is dropped
                    let _ = tx.execute("INSERT INTO probe VALUES (2)", &[]).await;
                    Ok::<(), tokio_postgres::Error>(())
                },
                second: Ok::<(), tokio_postgres::Error>(())
            )
        })
        .catch_unwind()
        .await;
        let Err(panic) = raced else {
            panic!("race! committed a first Ok over an aborted transaction");
        };
        let message = panic.downcast_ref::<String>().map_or("", String::as_str);
        assert!(
            message.contains(
                "commit as the dispatcher: the call returned Ok over an aborted transaction"
            ),
            "panics naming the swallowed statement, not another fault: {message}"
        );
        let count: i64 = pool
            .get()
            .await
            .expect("pool.get")
            .query_one("SELECT COUNT(*) FROM probe WHERE id = 2", &[])
            .await
            .expect("count the rows")
            .get(0);
        assert_eq!(count, 0, "the aborted transaction left nothing behind");
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
