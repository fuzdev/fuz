//! In-process test doubles for the spine's capabilities: a pool that never
//! connects ([`unreachable_pool`]) and a connection closer that records what
//! it is asked to close ([`RecordingConnectionCloser`]).

#![expect(
    clippy::expect_used,
    reason = "a test harness: a setup fault panics loudly naming the step, and the in-tests carve-out doesn't reach a library module"
)]

use fuz_auth::{ConnectionCloseTarget, ConnectionCloser};
use fuz_db::Pool;
use fuz_http::{ShutdownCloser, ShutdownFuture};
use parking_lot::Mutex;

/// A database URL nothing answers: port `1` on loopback refuses a connection
/// at once, with no DNS lookup and no wait on a timeout.
///
/// For a pool or a `DATABASE_URL` that must parse but is never meant to be
/// reached. The in-source unit tests of the crates `fuz_testing` depends on
/// can't name it (a dev-dependency there is another instance of their crate)
/// and spell the same shape.
pub const UNREACHABLE_DATABASE_URL: &str = "postgres://unreachable@127.0.0.1:1/unreachable";

/// A pool over [`UNREACHABLE_DATABASE_URL`]: building it connects to nothing
/// (`deadpool` connects on the first checkout), and every checkout fails.
///
/// For a test whose code under test refuses before the database, or one that
/// pins what a handler answers when its checkout fails.
///
/// # Panics
///
/// Never reached — the URL parses.
#[must_use]
pub fn unreachable_pool() -> Pool {
    fuz_db::create_pool(UNREACHABLE_DATABASE_URL, &fuz_db::PoolOptions::default())
        .expect("an unreachable pool builds without connecting")
}

/// A [`ConnectionCloser`] that closes nothing and records every target it is
/// asked to close, in order.
///
/// A test asserts *that* a handler or listener asked for the right close,
/// apart from whether a registry held a matching connection.
///
/// It reports [`Self::with_closes`]'s count as closed for each target (`0` by
/// default, a server with no live connection), and closes nothing on
/// shutdown.
///
/// `fuz_auth`'s own unit tests keep a copy of their own: there a
/// dev-dependency on this crate is another instance of `fuz_auth`, whose
/// trait the copy couldn't implement.
#[derive(Debug, Default)]
pub struct RecordingConnectionCloser {
    closed: Mutex<Vec<ConnectionCloseTarget>>,
    closes: usize,
}

impl RecordingConnectionCloser {
    /// A closer that reports `closes` connections closed for each target —
    /// for code that acts on the count.
    #[must_use]
    pub fn with_closes(closes: usize) -> Self {
        Self {
            closed: Mutex::default(),
            closes,
        }
    }

    /// Every target asked for so far, in order.
    #[must_use]
    pub fn closed(&self) -> Vec<ConnectionCloseTarget> {
        self.closed.lock().clone()
    }
}

impl ShutdownCloser for RecordingConnectionCloser {
    fn close_all_connections(&self) -> usize {
        0
    }

    fn wait_closed(&self) -> ShutdownFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for RecordingConnectionCloser {
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
        self.closed.lock().push(target.clone());
        self.closes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_each_target_in_order_and_reports_its_count() {
        let closer = RecordingConnectionCloser::with_closes(2);
        let session = ConnectionCloseTarget::Session("hash".to_owned());
        let token = ConnectionCloseTarget::Token("tok_x".to_owned());
        assert_eq!(closer.close_connections(&session), 2);
        assert_eq!(closer.close_connections(&token), 2);
        assert_eq!(closer.closed(), [session, token]);
        assert_eq!(closer.close_all_connections(), 0);
        let default = RecordingConnectionCloser::default();
        assert_eq!(
            default.close_connections(&ConnectionCloseTarget::Token("t".to_owned())),
            0
        );
    }

    #[tokio::test]
    async fn an_unreachable_pool_builds_and_refuses_a_checkout() {
        assert!(unreachable_pool().get().await.is_err());
    }
}
