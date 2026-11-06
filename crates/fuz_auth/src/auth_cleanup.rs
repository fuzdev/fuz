//! Periodic auth cleanup — sweeps expired sessions and `role_grant` offers.
//!
//! Twin of `fuz_app`'s `auth/cleanup.ts`. [`run_auth_cleanup`] is one pass: it
//! deletes expired sessions and closes the connections they opened
//! ([`cleanup_expired_sessions`]), then audits newly expired offers
//! ([`cleanup_expired_role_grant_offers`]), returning both counts.
//! [`spawn_auth_cleanup`] schedules it — the one call a server makes. The
//! per-pass pieces stay public for a consumer that wants its own cadence or
//! error isolation per sweep.
//!
//! ## Expired sessions: the sweep closes what it sweeps
//!
//! A session past `expires_at` fails every validity check, but the
//! connections it opened do not read it again: a WebSocket re-authorizes the
//! actor per message, never the session, and an SSE stream is authorized once
//! at open. While the expired row lingers, `account_session_revoke` is the
//! per-session handle on those connections — it closes for the row it
//! deletes. The sweep deletes that row, so it takes over the close: every
//! session it deletes has its connections closed through
//! [`AuthCleanupOptions::connection_closer`], the same close a revocation makes
//! (4001 on a WebSocket; an SSE stream ends). Otherwise a swept session's
//! connections would be reachable only by an account-wide revocation.
//!
//! The sweep's close is the second on expiry, not the first: every WebSocket
//! and SSE stream already closes at its credential's deadline
//! ([`crate::ResolvedAuth::credential_deadline`]) in the process holding it,
//! whether or not a sweep runs. The sweep is for sessions only: an expired API
//! token's row is not swept — its connections close at their deadline, and
//! `account_token_revoke` still finds the row to close for.
//!
//! The closes run after the delete's commit, which is the rule every
//! revocation close keeps (see [`crate::connection_closer`]). An expired
//! session is refused with or without its row, so the order is not what
//! protects a client rechecking on 4001 or a connection still opening; it
//! keeps the sweep inside the one invariant admission leans on — a close
//! that missed a registration belongs to a write the re-read can see —
//! rather than on the re-read's clock. A commit whose outcome is unknown
//! still closes: the sessions are expired either way.
//!
//! That is why the delete runs in its own transaction rather than as one
//! autocommit statement. The ids are in hand before the commit is sent, so a
//! connection lost on the delete's response rolls the delete back for the
//! next pass, and one lost on the commit's still closes — no failure leaves
//! rows deleted with their ids unread. A commit that fails outright has
//! closed too; the rows it left are deleted by the next pass, whose closes
//! then find nothing.
//!
//! One pass closes for every session it swept; a session with no live
//! connection costs a lookup and closes nothing. The pass logs one count, not
//! a line per session.
//!
//! No audit row is written for a swept session, matching the twin: expiry is
//! not an event anyone performed, and the session was already refused
//! everywhere. So the audit listeners never see it, and the direct close is
//! the only one.
//!
//! One limit: the closes reach this process's registries, as every
//! revocation close does — a second instance on the same database keeps the
//! connections it holds on a session this instance swept.
//!
//! The TS twin sweeps the same way: its `cleanup_expired_sessions` deletes
//! in a transaction and closes each swept session's connections after the
//! commit, whatever the commit's outcome, and `start_auth_cleanup` schedules
//! the pass on this loop's rules (over `start_periodic`, the twin of
//! `spawn_periodic`). It differs in two places. Its `stop` waits for a pass in
//! progress where cancelling here drops it — a promise cannot be dropped. And
//! a closer that throws for one session is logged there and the rest still
//! close; a closer here cannot fail.
//!
//! ## Offer idempotency
//!
//! An expired pending offer has no terminal state — expiry is computed from
//! `expires_at`, never written — so the offer sweep claims rows instead:
//! [`query_role_grant_offer_sweep_expired`] stamps
//! `role_grant_offer.expire_audited_at` on the expired, not-yet-audited
//! pending offers, and each claimed row's `role_grant_offer_expire` audit row
//! is inserted in the **same transaction**. Every expiry is therefore audited
//! exactly once: a second pass finds nothing, and concurrent passes (two
//! instances on one database) claim disjoint rows — a row another pass holds
//! blocks on its row lock, then fails the re-checked stamp. A failed audit
//! insert rolls the stamps back with it and the next pass retries. A re-offer
//! clears the stamp (the create upsert), so a refreshed offer's own expiry is
//! audited too.
//!
//! Listener fan-out (SSE, WS broadcasters) runs after the commit through a
//! [`CollectingAuditPostCommit`], so no listener sees an event that rolled
//! back. The audit rows carry no `ip` — no request is behind a sweep.
//!
//! ## Scheduling
//!
//! [`spawn_auth_cleanup`] runs the pass beside the server, on
//! [`fuz_sys::periodic::spawn_periodic`]: a pass at once, then one per
//! interval ([`DEFAULT_AUTH_CLEANUP_INTERVAL`] unless the consumer has a
//! reason to differ), until the shutdown token is cancelled. A failed pass —
//! the database out of reach — is logged and retried on the next interval.
//!
//! Spawn it once migrations have run (the startup pass reads the auth
//! tables), with the app's bound [`AuditEmitter`] so the expiry audits reach
//! its listeners and the [`ConnectionCloser`] its revocation handlers close
//! through — the one over the registries its connections live in, both
//! transports where it has both — and join it after the server drains:
//!
//! ```ignore
//! let shutdown = fuz_http::shutdown_token();
//! // … build the app, run migrations, bind …
//! let auth_cleanup = fuz_auth::spawn_auth_cleanup(
//!     fuz_auth::AuthCleanupOptions {
//!         pool: pool.clone(),
//!         audit: Arc::clone(&audit),
//!         connection_closer: Arc::clone(&connection_closer),
//!     },
//!     fuz_auth::DEFAULT_AUTH_CLEANUP_INTERVAL,
//!     shutdown.clone(),
//! );
//! let served = fuz_http::serve_with_shutdown(
//!     listener,
//!     router,
//!     shutdown.clone(),
//!     connection_closer.as_ref(),
//!     drain,
//! )
//! .await;
//! // the token is cancelled by now, so the task stops
//! let _ = auth_cleanup.await;
//! ```
//!
//! Shutdown drops a pass in progress. Both sweeps are safe to drop. A session
//! sweep dropped before its commit rolls the delete back for the next start's
//! pass; its closes follow the commit with no await between, so one dropped
//! inside the commit leaves at most rows deleted with their connections open
//! — connections that are closing with the process. An offer sweep dropped
//! before its commit rolls its stamps back for the next start's pass. One
//! dropped between its commit and its listener fan-out leaves the audit rows
//! written and unannounced — the listeners are closing with the process.
//!
//! `testing_spine_stub` leaves it unscheduled, matching the TS spine test
//! server it is compared against, which schedules none. A consumer's
//! `testing_*` binary runs it through the shared `run_app`: no cross-process
//! suite can make an offer that is already expired, and a backdated session
//! is refused the same whether or not its row has been swept — a connection
//! left open on one is closed by the next pass.

use std::sync::Arc;
use std::time::Duration;

use fuz_db::{DbError, Pool, commit_checked};
use fuz_sys::periodic::spawn_periodic;
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::audit_emitter::{AuditEmitter, AuditLogInput, CollectingAuditPostCommit};
use crate::audit_event_type::AuditEventType;
use crate::connection_closer::ConnectionCloseTarget;
use crate::connection_closer::ConnectionCloser;
use crate::role_grant_offer_queries::query_role_grant_offer_sweep_expired;
use crate::session_queries::query_session_cleanup_expired;

/// How often [`spawn_auth_cleanup`] runs a pass after its startup pass
/// (10 minutes), unless the consumer passes its own.
///
/// An expired session or offer is already refused by every check that reads
/// it, and a connection closes at its credential's deadline on its own, so
/// the interval bounds two things: how late an offer expiry's audit row
/// lands, and how long dead rows linger.
pub const DEFAULT_AUTH_CLEANUP_INTERVAL: Duration = Duration::from_mins(10);

/// What the cleanup sweeps need: the pool they run on, the bound audit
/// emitter whose listeners the offer sweep fans out to, and the closer the
/// session sweep closes through.
#[derive(Clone)]
pub struct AuthCleanupOptions {
    pub pool: Pool,
    pub audit: Arc<AuditEmitter>,
    /// Closes the connections of each session the sweep deletes. Bind the
    /// closer the app's revocation handlers hold — over the registries its
    /// connections live in, and reaching every transport it serves
    /// (`fuz_realtime::RealtimeCloser` where it mounts an SSE stream beside
    /// its WebSocket). Required: a sweep with nothing to close through would
    /// strand the swept sessions' connections.
    pub connection_closer: Arc<dyn ConnectionCloser>,
}

impl std::fmt::Debug for AuthCleanupOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCleanupOptions")
            .field("pool", &self.pool)
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

/// Counts from one [`run_auth_cleanup`] pass. Mirrors TS `AuthCleanupResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthCleanupResult {
    /// Expired session rows deleted — each one's connections closed.
    pub expired_sessions: u64,
    /// Expired offers audited (and stamped) by this pass.
    pub expired_offers: u64,
}

/// Delete every expired session and close the connections each one opened,
/// returning the count of sessions deleted.
///
/// The delete runs in its own transaction and the closes follow its commit,
/// so on a successful pass every close is for a row already gone (see the
/// module doc's § Expired sessions). Each swept session is closed by its id —
/// the session-token hash the registries key on — so another session of the
/// same account keeps its connections. A pass that closed something logs the
/// count at `info`. No audit row is written.
///
/// # Errors
///
/// A [`DbError`] from pool checkout, opening the transaction, the delete, or
/// the commit. The first three close nothing and delete nothing. A failed
/// commit is returned **after** the closes: the sessions the delete returned
/// are expired whether or not the commit landed, so their connections are
/// closed either way, and the next pass deletes any row the commit left.
pub async fn cleanup_expired_sessions(options: &AuthCleanupOptions) -> Result<u64, DbError> {
    let (swept, committed) = {
        let mut client = options.pool.get().await?;
        let tx = client.transaction().await?;
        // the ids are in hand before the commit is sent: a connection lost on
        // the delete's response rolls the delete back for the next pass, and
        // one lost on the commit's still closes below
        let swept = query_session_cleanup_expired(&tx).await?;
        (swept, commit_checked(tx).await)
    };
    // the commit has been answered and its connection is back in the pool.
    // No await from here on, so a dropped pass can't close for some of the
    // swept sessions and not others
    let closed_connections: usize = swept
        .iter()
        .map(|session_id| {
            options
                .connection_closer
                .close_connections(&ConnectionCloseTarget::Session(session_id.clone()))
        })
        .sum();
    if closed_connections > 0 {
        tracing::info!(
            expired_sessions = swept.len(),
            closed_connections,
            "auth cleanup closed the connections of expired sessions"
        );
    }
    committed?;
    Ok(swept.len() as u64)
}

/// Audit each newly expired offer once, returning the count audited.
///
/// Claims the expired, not-yet-audited pending offers and writes one
/// `role_grant_offer_expire` audit row per offer, in one transaction, then
/// fans the events out to the audit listeners after the commit. Mirrors TS
/// `cleanup_expired_role_grant_offers`.
///
/// Each event's actor is the grantor, its target account the recipient, and
/// its target actor the offer's `to_actor_id` (`NULL` for an account-grain
/// offer); metadata carries `offer_id`, `role`, and `scope_id`. The offer rows
/// are kept — they carry history value past expiry.
///
/// # Errors
///
/// A [`DbError`] from pool checkout, the claim, an audit insert, or the
/// commit. The transaction rolls back, so no offer is stamped and the next
/// pass retries them all.
pub async fn cleanup_expired_role_grant_offers(
    options: &AuthCleanupOptions,
) -> Result<u64, DbError> {
    let mut client = options.pool.get().await?;
    let tx = client.transaction().await?;
    let post_commit = CollectingAuditPostCommit::default();
    match claim_and_audit_expired_offers(&tx, &options.audit, &post_commit).await {
        Ok(audited) => {
            commit_checked(tx).await?;
            // release the pool slot before fan-out, so a listener that takes
            // its own connection never waits on the sweep's
            drop(client);
            post_commit.drain().await;
            Ok(audited)
        }
        Err(e) => {
            // dropping `post_commit` undrained: nothing fans out for rows
            // that never landed
            if let Err(rollback_err) = tx.rollback().await {
                tracing::warn!(error = ?rollback_err, "auth cleanup rollback failed");
            }
            Err(e.into())
        }
    }
}

/// The in-transaction body of [`cleanup_expired_role_grant_offers`]: claim,
/// then one audit insert per claimed offer, its fan-out queued on
/// `post_commit`.
async fn claim_and_audit_expired_offers(
    tx: &deadpool_postgres::Transaction<'_>,
    audit: &Arc<AuditEmitter>,
    post_commit: &CollectingAuditPostCommit,
) -> Result<u64, tokio_postgres::Error> {
    let expired = query_role_grant_offer_sweep_expired(tx).await?;
    for offer in &expired {
        // no `.ip(..)`: no request is behind a sweep, so the column stays NULL
        // like the twin's `ip: null`
        let input = AuditLogInput::for_event(AuditEventType::RoleGrantOfferExpire)
            .actor(offer.from_actor_id)
            .target_account(offer.to_account_id)
            .target_actor(offer.to_actor_id)
            .metadata(json!({
                "offer_id": offer.id,
                "role": offer.role,
                "scope_id": offer.scope_id,
            }));
        audit.emit_in_tx(tx, input, post_commit).await?;
    }
    Ok(expired.len() as u64)
}

/// Run every auth cleanup sweep — expired sessions, then expired offers — and
/// return both counts. Mirrors TS `run_auth_cleanup`.
///
/// The session sweep ([`cleanup_expired_sessions`]) commits its delete and
/// closes the swept sessions' connections before the offer sweep starts, so
/// a failed offer sweep takes neither back; a session sweep whose commit
/// failed has closed too, and the offer sweep does not run.
///
/// # Errors
///
/// The first sweep's [`DbError`], unwrapped — there is no per-sweep
/// isolation here; call the sweeps directly for that.
pub async fn run_auth_cleanup(options: &AuthCleanupOptions) -> Result<AuthCleanupResult, DbError> {
    let expired_sessions = cleanup_expired_sessions(options).await?;
    let expired_offers = cleanup_expired_role_grant_offers(options).await?;
    Ok(AuthCleanupResult {
        expired_sessions,
        expired_offers,
    })
}

/// Run [`run_auth_cleanup`] beside the server: a pass now, then one every
/// `interval`, until `shutdown` is cancelled.
///
/// The auth surface's upkeep in one call — spawn it once migrations have run
/// and join the handle after the server drains (see the module doc's
/// § Scheduling). A failed pass is logged at `warn` and the next interval
/// retries; a pass that swept something logs its counts at `info`, and one
/// that closed a swept session's connections logs that count too. Shutdown
/// drops a pass in progress, which is safe for both sweeps.
///
/// Built on [`spawn_periodic`], which fixes the loop's semantics (startup
/// pass, delayed-not-burst schedule, prompt join).
///
/// # Panics
///
/// If `interval` is zero, or when called outside a tokio runtime.
pub fn spawn_auth_cleanup(
    options: AuthCleanupOptions,
    interval: Duration,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_periodic("auth cleanup", interval, shutdown, move || {
        let options = options.clone();
        async move {
            let swept = run_auth_cleanup(&options).await?;
            if swept != AuthCleanupResult::default() {
                tracing::info!(
                    expired_sessions = swept.expired_sessions,
                    expired_offers = swept.expired_offers,
                    "auth cleanup swept expired rows"
                );
            }
            Ok::<(), DbError>(())
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::audit_emitter::AuditOutcome;
    use crate::audit_event_type::{AuditEventType, AuditRouting, audit_event_spec};

    /// The sweep writes its expiry audits in its own transaction, so the
    /// routing table declares the event in-tx on success.
    #[test]
    fn role_grant_offer_expire_routes_in_tx_on_success() {
        let spec = audit_event_spec(AuditEventType::RoleGrantOfferExpire);
        assert_eq!(spec.routing_for(AuditOutcome::Success), AuditRouting::InTx);
    }
}
