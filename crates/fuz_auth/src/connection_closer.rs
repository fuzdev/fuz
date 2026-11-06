//! `ConnectionCloser` capability — close live connections (WebSocket and SSE)
//! on revocation (session revoke, password change, logout, …).
//!
//! Decouples the revocation handlers and the audit listener chain from a
//! concrete connection registry. `fuz_realtime` implements it on each of its
//! registries — `ConnectionRegistry` (WS) and `SseRegistry` (SSE) — and
//! `RealtimeCloser` fans one call out to both, which is the impl a consumer
//! with both transports binds; consumers without a live-connection surface
//! bind [`NoopConnectionCloser`].
//!
//! It extends [`fuz_http::ShutdownCloser`], so the closer a server already
//! holds is also what `fuz_http::serve_with_shutdown` closes every live
//! connection through when the server shuts down: one capability reaches
//! every transport for revocation and shutdown alike.
//!
//! ## Why the handlers close directly
//!
//! The one revocation no handler closes for is a role's
//! ([`ConnectionCloseTarget::Role`]): the audit listener is its only closer.
//! That is enough for a role because both role-revoke handlers write their
//! audit row inside the request transaction: a revoke that commits has its
//! row, so the listener's close cannot be lost to a failed audit write.
//!
//! The audit listener closes connections too, but only once the audit row
//! is written, and a pool-routed audit write (the REST `/logout` and
//! `/password` handlers) can fail after the revocation has already
//! committed. The handler's own close is what guarantees the revoked
//! credential's connections end whatever happens to the audit write — so the
//! closer it holds must reach **every** transport whose connections outlive
//! their credential, SSE included: a stream is authorized once at open and
//! never rechecks.
//!
//! Cold path — `Arc<dyn ConnectionCloser>` is correct.
//!
//! ## Closing after commit
//!
//! A revocation that runs inside a request transaction (the RPC
//! `*_revoke*` / `account_delete` / `account_purge` handlers, and
//! `account_token_create` for the tokens its cap evicts) must not close
//! connections until that transaction commits: a client told "revoked" rechecks
//! its session straight away, and before the commit the row it probes is
//! still there, so the probe reads "valid" and the client is left holding a
//! dead socket. [`queue_connection_close`] defers the close onto the request's
//! post-commit queue — run after the commit, dropped on rollback, so a
//! rolled-back revocation also leaves the connections alone. REST handlers close
//! inline once their own write has committed — `/logout`'s on an autocommit
//! pool client, `/login`'s session-cap eviction and `/password`'s change
//! after the transaction each opens, so a `/password` whose transaction rolls
//! back closes nothing.
//! The scheduled session sweep ([`crate::auth_cleanup`]) is the one close
//! with no request behind it: it closes each expired session it deletes, after
//! the commit of the transaction that deletes them.
//!
//! Connection admission leans on the same rule. A connection that is still
//! opening registers first and then re-reads its credential, acting actor,
//! and roles ([`crate::recheck_admission`], shared by the WS upgrade and the
//! SSE stream): a close that missed the registration must belong to a
//! revocation that re-read can see, which holds only if the close came after
//! the commit. A close fired before its commit
//! could miss the registration *and* be invisible to the re-read, and the
//! connection would open on the revoked credential.

use std::sync::Arc;

use fuz_http::{ShutdownCloser, WaitClosedFuture};

use crate::audit_emitter::AuditPostCommit;

/// Close live connections (WebSocket and SSE) by identity.
///
/// One method, [`Self::close_connections`], taking the [`ConnectionCloseTarget`] a
/// revocation names — a handler's direct close, [`queue_connection_close`]'s
/// deferred one, and the audit listener's
/// ([`ConnectionCloseTarget::from_audit_event`]) all reach an impl through it.
/// It returns how many connections it closed. Closing is idempotent: a
/// connection already gone simply isn't counted, so the handler's direct
/// close and the audit listener's close on the same revocation compose.
///
/// Sync — implementations must not `.await` inside (audit listener tasks run
/// it synchronously on the emit fan-out; an internal `.await` could deadlock
/// the runtime).
///
/// The [`ShutdownCloser`] supertrait is the shutdown half: every impl also
/// closes all of its connections, and waits for them to finish closing, when
/// the server stops — so an `Arc<dyn ConnectionCloser>` is passed to
/// `fuz_http::serve_with_shutdown` as it is (`closer.as_ref()` upcasts to
/// `&dyn ShutdownCloser`). Its `wait_closed` is the one async method, and
/// only shutdown calls it.
///
/// **Object-safe** — consumed as `Arc<dyn ConnectionCloser>`.
pub trait ConnectionCloser: ShutdownCloser {
    /// Close every connection `target` names — pending admission or admitted
    /// — returning how many closed.
    fn close_connections(&self, target: &ConnectionCloseTarget) -> usize;
}

/// No-op implementation. Useful for consumers without a live-connection
/// surface (headless CLIs, smoke-test binaries): it closes nothing, on
/// revocation or on shutdown.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopConnectionCloser;

impl ShutdownCloser for NoopConnectionCloser {
    fn close_all_connections(&self) -> usize {
        0
    }
    fn wait_closed(&self) -> WaitClosedFuture<'_> {
        Box::pin(std::future::ready(()))
    }
}

impl ConnectionCloser for NoopConnectionCloser {
    fn close_connections(&self, _: &ConnectionCloseTarget) -> usize {
        0
    }
}

/// Which connections a revocation closes — the argument of
/// [`ConnectionCloser::close_connections`] and [`queue_connection_close`].
///
/// Twin of `fuz_app`'s `ConnectionCloseTarget`, one variant per revocation
/// close (shutdown's close-all is [`ShutdownCloser`], never a revocation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionCloseTarget {
    /// Connections authenticated by this session-token hash.
    Session(String),
    /// Connections authenticated by this API token id.
    Token(String),
    /// Every connection of this account.
    Account(uuid::Uuid),
    /// This account's connections whose endpoint gated them on this role —
    /// the close for a revoked **global** grant of it (a role gate admits on
    /// global grants only, so revoking a scoped one closes nothing;
    /// [`Self::from_audit_event`] filters). A WebSocket closes with
    /// `WS_CLOSE_PERMISSION_REVOKED`, not a revocation's code: the credential
    /// is still good.
    ///
    /// **Over-closes an any-of gate**: a connection whose endpoint listed
    /// several roles closes on the loss of any of them, whether or not the
    /// account still holds another; its client reconnects into the gate when
    /// it still qualifies. No handler queues it: the audit listener is a
    /// role's only closer, which the in-transaction audit row makes enough
    /// (module doc).
    Role {
        /// The account that lost the role.
        account_id: uuid::Uuid,
        /// The role it lost.
        role: String,
    },
}

/// Queue a connection close on `post_commit`, so it runs only after the request
/// transaction commits (and never on rollback). See the module doc for why
/// an in-transaction revocation must not close inline.
pub fn queue_connection_close(
    post_commit: &dyn AuditPostCommit,
    closer: &Arc<dyn ConnectionCloser>,
    target: ConnectionCloseTarget,
) {
    let closer = Arc::clone(closer);
    post_commit.queue_notify(Box::new(move || {
        Box::pin(async move {
            closer.close_connections(&target);
        })
    }));
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;
    use crate::audit_emitter::CollectingAuditPostCommit;

    /// Records each close instead of closing anything.
    #[derive(Default)]
    struct RecordingCloser {
        closed: Mutex<Vec<ConnectionCloseTarget>>,
    }

    impl ShutdownCloser for RecordingCloser {
        fn close_all_connections(&self) -> usize {
            0
        }
        fn wait_closed(&self) -> WaitClosedFuture<'_> {
            Box::pin(std::future::ready(()))
        }
    }

    impl ConnectionCloser for RecordingCloser {
        fn close_connections(&self, target: &ConnectionCloseTarget) -> usize {
            self.closed.lock().push(target.clone());
            1
        }
    }

    impl RecordingCloser {
        fn closed(&self) -> Vec<ConnectionCloseTarget> {
            self.closed.lock().clone()
        }
    }

    #[tokio::test]
    async fn queued_closes_wait_for_the_commit() {
        let recording = Arc::new(RecordingCloser::default());
        let closer: Arc<dyn ConnectionCloser> = Arc::<RecordingCloser>::clone(&recording);
        let post_commit = CollectingAuditPostCommit::default();
        let account = uuid::Uuid::new_v4();
        let targets = vec![
            ConnectionCloseTarget::Session("hash".to_owned()),
            ConnectionCloseTarget::Token("tok_1".to_owned()),
            ConnectionCloseTarget::Account(account),
            ConnectionCloseTarget::Role {
                account_id: account,
                role: "admin".to_owned(),
            },
        ];
        for target in &targets {
            queue_connection_close(&post_commit, &closer, target.clone());
        }
        assert!(
            recording.closed().is_empty(),
            "nothing closes before the commit"
        );
        post_commit.drain().await;
        assert_eq!(
            recording.closed(),
            targets,
            "each target closes once, after the commit"
        );
    }

    #[tokio::test]
    async fn a_dropped_queue_closes_nothing() {
        // a rollback drops the queue unrun — the revocation never happened
        let recording = Arc::new(RecordingCloser::default());
        let closer: Arc<dyn ConnectionCloser> = Arc::<RecordingCloser>::clone(&recording);
        let post_commit = CollectingAuditPostCommit::default();
        queue_connection_close(
            &post_commit,
            &closer,
            ConnectionCloseTarget::Account(uuid::Uuid::new_v4()),
        );
        drop(post_commit);
        assert!(recording.closed().is_empty());
    }
}
