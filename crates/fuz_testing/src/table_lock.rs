//! Stall a handler at one of its database reads — the fixture for a race
//! between two reads of the same request.
//!
//! Some handlers read state, do something else, then act on what they read:
//! a WebSocket upgrade resolves its credential, runs its role gate, and only
//! then registers the socket. Whether a change landing in between is handled
//! is invisible to a test that can only run the handler start to finish.
//! [`TestingTableLock`] makes the gap addressable: take an `ACCESS EXCLUSIVE`
//! lock on a table the handler reads *in between* (and reads nowhere earlier),
//! start the request, wait until it is queued behind the lock
//! ([`TestingTableLock::wait_for_waiter`]), make the change, and release. The
//! handler then resumes from a known point with the change already committed.
//!
//! Sibling of [`crate::seed`] and [`crate::credentials`]: shared by the
//! `fuz_actions` and `fuz_realtime` suites that pin the connection-admission
//! re-check.

#![expect(
    clippy::expect_used,
    reason = "a test harness: a setup fault panics loudly naming the step, and the in-tests carve-out doesn't reach a library module"
)]

use std::time::Duration;

use fuz_db::Pool;

/// How long [`TestingTableLock::wait_for_waiter`] waits for a query to queue
/// behind the lock before calling the test broken.
const WAITER_TIMEOUT: Duration = Duration::from_secs(10);

/// An `ACCESS EXCLUSIVE` lock on one table, held in an open transaction on a
/// pooled client until [`Self::release`]. See the module doc.
///
/// Dropped without `release` — a test that panicked while holding it — the
/// client is taken out of the pool and its connection closed, which ends the
/// transaction and frees the lock; an open transaction is never handed back
/// to the pool.
pub struct TestingTableLock {
    /// `Some` until [`Self::release`] or drop takes it.
    client: Option<deadpool_postgres::Object>,
    table: String,
}

impl Drop for TestingTableLock {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            // detach from the pool; dropping the bare client closes the
            // connection, and the server rolls the transaction back
            drop(deadpool_postgres::Object::take(client));
        }
    }
}

impl std::fmt::Debug for TestingTableLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestingTableLock")
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}

impl TestingTableLock {
    /// Lock `table` against every read and write from other connections.
    ///
    /// `table` is spliced into the statement as an identifier, so pass only
    /// fixed test constants.
    ///
    /// # Panics
    ///
    /// Panics if the pool is unreachable or the lock statement fails.
    pub async fn acquire(pool: &Pool, table: &str) -> Self {
        let client = pool.get().await.expect("pool.get");
        client
            .batch_execute(&format!(
                "BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"
            ))
            .await
            .expect("lock the table");
        Self {
            client: Some(client),
            table: table.to_owned(),
        }
    }

    /// Wait until another connection's query is queued behind this lock —
    /// the handler under test has reached its read of the table.
    ///
    /// # Panics
    ///
    /// Panics if nothing queues within the timeout: the handler never reached
    /// the read, or it does not read this table.
    pub async fn wait_for_waiter(&self) {
        let deadline = tokio::time::Instant::now() + WAITER_TIMEOUT;
        loop {
            let waiting: i64 = self
                .client()
                .query_one(
                    "SELECT count(*) FROM pg_locks
                     WHERE NOT granted AND relation = to_regclass($1)",
                    &[&self.table],
                )
                .await
                .expect("read pg_locks")
                .get(0);
            if waiting > 0 {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no query queued behind the lock on `{}`",
                self.table
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Commit, releasing the lock: the queued query proceeds. The client
    /// goes back to the pool with no transaction open.
    ///
    /// # Panics
    ///
    /// Panics if the commit fails.
    pub async fn release(mut self) {
        self.client()
            .batch_execute("COMMIT")
            .await
            .expect("release the table lock");
        // committed — return the client to the pool rather than closing it
        drop(self.client.take());
    }

    /// The locking client — present until `release` or drop.
    const fn client(&self) -> &deadpool_postgres::Object {
        self.client
            .as_ref()
            .expect("the lock holds its client until released")
    }
}
