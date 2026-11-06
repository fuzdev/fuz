//! Audit log emitter — write rows to `audit_log` + fan out to listeners.
//!
//! Mirrors `fuz_app`'s `audit_emitter.ts`. The bound emitter closes over a [`Pool`] plus a
//! listener chain; every `audit.emit(input)` site:
//!
//! 1. Spawns a `tokio::task` that INSERTs the row via the captured pool
//!    (rollback-resilient — audit rows persist even if the request
//!    transaction rolls back).
//! 2. On successful insert, fans the materialized
//!    [`Arc<AuditLogEvent>`](AuditLogEvent) out to every listener.
//!
//! ## Failure mode
//!
//! A pool write is fail-open: a failed checkout or INSERT drops the row and
//! the request goes on — auth flows must not break because the audit table is
//! unreachable. The drop is logged at `error` as one structured line carrying
//! the whole row ([`dropped_row_json`]), so the record survives in the log
//! when it cannot reach the table. Same posture as `fuz_app`.
//!
//! The checkout behind a pool write waits up to the emitter's own bound
//! ([`AuditEmitter::with_checkout_timeout`], default
//! [`fuz_db::DEFAULT_AUDIT_CHECKOUT_TIMEOUT`], 30 s) — longer than a request's
//! (`FUZ_DB_CHECKOUT_TIMEOUT_MS`, 5 s), so a pool saturated enough to shed
//! requests with a 503 does not also drop the failure rows recording them.
//! A failed login awaits its row, so it can wait up to this bound.
//! An in-transaction write ([`AuditEmitter::emit_in_tx`]) checks nothing out.

use std::sync::Arc;
use std::time::Duration;

use std::sync::atomic::{AtomicUsize, Ordering};

use deadpool_postgres::{GenericClient, Pool};
use futures::future::BoxFuture;
use parking_lot::{Mutex, RwLock};
use serde_json::Value;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::audit_event_schema::AuditLogEvent;
use crate::audit_event_type::{
    AuditEventKind, AuditEventType, AuditRouting, is_spine_audit_event_type_name,
    is_valid_audit_event_type_name,
};
use crate::audit_listener::{AuditListenerFn, AuditListenerId};
use crate::audit_log_queries::{audit_log_columns, decode_audit_log_row};
use crate::credential_type::CredentialType;
use fuz_http::{JsonrpcError, internal_error_with_source};

/// Outcome of an audit event. Wire-format string matches `fuz_app`
/// (`'success' | 'failure'`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Failure,
}

impl AuditOutcome {
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Input for [`AuditEmitter::emit`]. Mirrors `fuz_app`'s
/// `AuditLogInput`. `outcome` defaults to [`AuditOutcome::Success`] at
/// the SQL layer when omitted.
///
/// `event_type` is the closed [`AuditEventType`] enum — the
/// `audit_log.event_type` TEXT column stores the wire-format string
/// via [`AuditEventType::as_str`], matching TS `fuz_app`'s string
/// literals. The Rust-side type-safe carrier prevents typos at every
/// emit site and pairs with [`crate::AUDIT_EVENT_SPECS`] for routing
/// lookup.
///
/// Build via the chainable setters rather than struct literals — most
/// emit sites only set a subset of fields and the literal form's run of
/// `None` rows is visual noise:
///
/// ```ignore
/// AuditLogInput::for_event(AuditEventType::TokenCreate)
///     .account(account_id)
///     .ip(client_ip)
///     .metadata(json!({ "token_id": ... }))
/// ```
#[derive(Debug, Clone)]
pub struct AuditLogInput {
    pub event_type: AuditEventKind,
    pub outcome: Option<AuditOutcome>,
    pub actor_id: Option<uuid::Uuid>,
    pub account_id: Option<uuid::Uuid>,
    pub target_account_id: Option<uuid::Uuid>,
    pub target_actor_id: Option<uuid::Uuid>,
    pub ip: Option<String>,
    pub metadata: Option<Value>,
}

impl AuditLogInput {
    /// Start a builder for `event_type`. Defaults outcome to
    /// [`AuditOutcome::Success`] — flip with [`Self::failure`] on
    /// denial paths.
    #[must_use]
    pub const fn for_event(event_type: AuditEventType) -> Self {
        Self {
            event_type: AuditEventKind::Spine(event_type),
            outcome: Some(AuditOutcome::Success),
            actor_id: None,
            account_id: None,
            target_account_id: None,
            target_actor_id: None,
            ip: None,
            metadata: None,
        }
    }

    /// Start a builder for a consumer-defined custom audit event.
    ///
    /// Custom events have no [`AUDIT_EVENT_SPECS`](crate::AUDIT_EVENT_SPECS)
    /// row, so the caller supplies per-outcome routing: typically
    /// `success_routing = InTx` (atomic with the mutating handler tx) and
    /// `failure_routing = Pool` (a failure audit emitted on an Err path must
    /// survive the rollback). Defaults outcome to [`AuditOutcome::Success`].
    ///
    /// # Panics
    ///
    /// When `name` is off the audit event-type grammar
    /// ([`is_valid_audit_event_type_name`]) —
    /// the name the `audit_log_list` filter accepts, so an off-grammar event
    /// could be written but never selected. Evaluated in `const` context the
    /// panic is a compile error. Twin of the TS startup refusal of an
    /// off-grammar `extra_events` key.
    ///
    /// Also when `name` is a spine [`AuditEventType`]'s wire string — the
    /// revocation guard and the `audit_log_list` filter would read the
    /// custom event as the spine's own (a custom `session_revoke_all` would
    /// fan out a revocation). Twin of the TS startup refusal of an
    /// `extra_events` key that shadows a built-in event type.
    #[must_use]
    pub const fn for_custom_event(
        name: &'static str,
        success_routing: AuditRouting,
        failure_routing: AuditRouting,
    ) -> Self {
        assert!(
            is_valid_audit_event_type_name(name),
            "custom audit event name is off the audit event-type grammar (a letter, then letters, digits, `_`, `.`, `/` and `-`, at most 64 characters)"
        );
        assert!(
            !is_spine_audit_event_type_name(name),
            "custom audit event name collides with a spine audit event type"
        );
        Self {
            event_type: AuditEventKind::Custom {
                name,
                success_routing,
                failure_routing,
            },
            outcome: Some(AuditOutcome::Success),
            actor_id: None,
            account_id: None,
            target_account_id: None,
            target_actor_id: None,
            ip: None,
            metadata: None,
        }
    }

    /// Override the outcome.
    #[must_use]
    pub const fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Set outcome to [`AuditOutcome::Failure`].
    #[must_use]
    pub const fn failure(self) -> Self {
        self.outcome(AuditOutcome::Failure)
    }

    /// Set the acting actor — the actor whose authority drove the event.
    #[must_use]
    pub const fn actor(mut self, actor_id: uuid::Uuid) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    /// Set the acting account.
    #[must_use]
    pub const fn account(mut self, account_id: uuid::Uuid) -> Self {
        self.account_id = Some(account_id);
        self
    }

    /// Set the target account — the account the event is about (admin
    /// revoke target, offer recipient, etc.).
    #[must_use]
    pub const fn target_account(mut self, target_account_id: uuid::Uuid) -> Self {
        self.target_account_id = Some(target_account_id);
        self
    }

    /// Set the target actor. Accepts `Option<Uuid>` because the typical
    /// shape is "actor-grain when targeted, account-grain (`None`)
    /// otherwise" — callers can thread `offer.to_actor_id` directly
    /// without a `match`.
    #[must_use]
    pub const fn target_actor(mut self, target_actor_id: Option<uuid::Uuid>) -> Self {
        self.target_actor_id = target_actor_id;
        self
    }

    /// Set the request's client IP — **for request-bound events only**.
    ///
    /// Takes `Option<String>` so a handler can pass `ctx.client_ip.clone()`
    /// directly. The `None` here means "this request has no resolved
    /// address", which records [`fuz_http::UNRESOLVED_CLIENT_IP`] rather than
    /// a `NULL` column: that literal is what the twin's `get_client_ip` yields
    /// when the trusted-proxy middleware resolves nothing, so the two spines
    /// write the same row — reachable only where the middleware isn't mounted
    /// (a bare router, an in-process harness), never in production.
    ///
    /// An event with **no request behind it** — a background sweep, a
    /// scheduled expiry — must not call this at all. The column then stays
    /// `NULL`, matching the twin's `ip: null` on the same events; calling it
    /// with `None` would instead claim a request whose address couldn't be
    /// resolved.
    #[must_use]
    pub fn ip(mut self, ip: Option<String>) -> Self {
        self.ip = Some(ip.unwrap_or_else(|| fuz_http::UNRESOLVED_CLIENT_IP.to_owned()));
        self
    }

    /// Set the JSON metadata payload.
    #[must_use]
    pub fn metadata(mut self, metadata: Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Test-only in-flight tracker for fire-and-forget `emit` writes.
///
/// Counts outstanding pool-routed audit tasks so [`AuditEmitter::drain_inflight`]
/// can await them — the deterministic barrier behind the
/// `_testing_drain_effects` test action, replacing poll/sleep before a
/// post-mutation `audit_log_list` read. `None` on the emitter in production.
#[derive(Debug, Default)]
struct InflightAuditWrites {
    pending: AtomicUsize,
    drain_notify: Notify,
}

/// One tracked [`AuditEmitter::emit`] write: counted in flight from
/// [`Self::acquire`] until the guard drops.
///
/// Settling in `Drop` rather than at the end of the spawned task's body is
/// what lets a drain finish when that body never reaches its end — a
/// listener that panics under unwinding, a task aborted or dropped with its
/// runtime before it ran. Otherwise the count would stay up and
/// [`AuditEmitter::drain_inflight`] would wait forever.
struct InflightWriteGuard {
    emitter: Arc<AuditEmitter>,
}

impl InflightWriteGuard {
    /// Count one write in flight; `None` when `emitter` doesn't track them.
    fn acquire(emitter: &Arc<AuditEmitter>) -> Option<Self> {
        let inflight = emitter.inflight.as_ref()?;
        inflight.pending.fetch_add(1, Ordering::SeqCst);
        Some(Self {
            emitter: Arc::clone(emitter),
        })
    }
}

impl Drop for InflightWriteGuard {
    fn drop(&mut self) {
        if let Some(inflight) = &self.emitter.inflight
            && inflight.pending.fetch_sub(1, Ordering::SeqCst) == 1
        {
            inflight.drain_notify.notify_waiters();
        }
    }
}

/// Bound audit-emit capability.
///
/// Constructed once at startup with the consumer's [`Pool`], wrapped in
/// `Arc<AuditEmitter>`, then shared via composition into every handler
/// that emits audit rows. Listeners are registered after the rest of the
/// auth state is built (e.g. the revocation guard, which captures
/// the consumer's `Arc<ConnectionCloser>`), and a registration can be undone
/// through the [`AuditListenerId`] [`Self::add_listener`] returns.
pub struct AuditEmitter {
    pool: Pool,
    /// The bound on the checkout behind each pool write
    /// ([`Self::with_checkout_timeout`]).
    checkout_timeout: Duration,
    /// One entry per registration, in registration order — the id is what
    /// lets [`Self::remove_listener`] take out one registration of a
    /// listener registered twice.
    listeners: RwLock<Vec<(AuditListenerId, AuditListenerFn)>>,
    /// `Some` only on test binaries built via
    /// [`Self::new_with_inflight_tracking`]; `None` in production. Stored
    /// by value — each tracked write's [`InflightWriteGuard`] reaches it
    /// through an `Arc<Self>`, cloned only when tracking is on.
    inflight: Option<InflightAuditWrites>,
}

impl std::fmt::Debug for AuditEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditEmitter")
            .field("listener_count", &self.listeners.read().len())
            .field("checkout_timeout", &self.checkout_timeout)
            .finish_non_exhaustive()
    }
}

impl AuditEmitter {
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            checkout_timeout: fuz_db::DEFAULT_AUDIT_CHECKOUT_TIMEOUT,
            listeners: RwLock::new(Vec::new()),
            inflight: None,
        }
    }

    /// Bound the checkout behind each pool write by `timeout` instead of
    /// [`fuz_db::DEFAULT_AUDIT_CHECKOUT_TIMEOUT`] — the server passes
    /// `FUZ_DB_AUDIT_CHECKOUT_TIMEOUT_MS` (`fuz_http::BaseServerEnv::db_audit_checkout_timeout`).
    /// Twin of the TS `create_app_backend` option `db_audit_checkout_timeout_ms`.
    #[must_use]
    pub const fn with_checkout_timeout(mut self, timeout: Duration) -> Self {
        self.checkout_timeout = timeout;
        self
    }

    /// The bound on the checkout behind each pool write — the default, or the
    /// one [`Self::with_checkout_timeout`] set.
    #[must_use]
    pub const fn checkout_timeout(&self) -> Duration {
        self.checkout_timeout
    }

    /// Like [`Self::new`] but tracks in-flight fire-and-forget `emit`
    /// writes so [`Self::drain_inflight`] can await them.
    ///
    /// **Test binaries only.** The counter is pure overhead in production,
    /// and production never calls the `_testing_drain_effects` action that
    /// drains it. The cross-backend conformance suite uses the drain as the
    /// deterministic barrier before reading `audit_log_list` (no poll/sleep).
    #[must_use]
    pub fn new_with_inflight_tracking(pool: Pool) -> Self {
        Self {
            pool,
            checkout_timeout: fuz_db::DEFAULT_AUDIT_CHECKOUT_TIMEOUT,
            listeners: RwLock::new(Vec::new()),
            inflight: Some(InflightAuditWrites::default()),
        }
    }

    /// Whether this emitter tracks its in-flight [`Self::emit`] writes —
    /// `true` only when built via [`Self::new_with_inflight_tracking`]. When
    /// `false`, [`Self::drain_inflight`] returns at once and waits on nothing.
    ///
    /// The `_testing_drain_effects` action reports it as `tracked`, and the
    /// `list_audit_events` reads refuse `false`: a test binary built over
    /// [`Self::new`] would answer the drain at once and its audit reads would
    /// race the writes. Twin of the TS `AuditEmitter.is_tracking_inflight` in
    /// `fuz_app`.
    #[must_use]
    pub const fn is_tracking_inflight(&self) -> bool {
        self.inflight.is_some()
    }

    /// Await every fire-and-forget [`Self::emit`] write in flight.
    ///
    /// Waits until no tracked write is outstanding, so a write that starts
    /// while the drain is waiting (an emit from a post-commit effect) is
    /// awaited too; one that starts after the drain resolves is not. Once it
    /// resolves, a following `audit_log_list` observes every row whose `emit`
    /// ran before the drain was called. A tracked write is the whole spawned
    /// task — the INSERT and the listener fan-out of the row it wrote — and
    /// it stops counting when that task ends however it ends: finished,
    /// unwound by a panicking listener, or aborted.
    /// [`Self::emit_in_tx`] is not tracked: its row commits with the
    /// caller's transaction, and its fan-out runs from the post-commit drain.
    ///
    /// No-op unless the emitter was built via
    /// [`Self::new_with_inflight_tracking`]. Twin of the TS
    /// `AuditEmitter.drain_inflight` in `fuz_app`, which also waits for zero
    /// rather than for a snapshot.
    pub async fn drain_inflight(&self) {
        let Some(inflight) = &self.inflight else {
            return;
        };
        loop {
            // Arm the waiter before re-checking the count so a `notify_waiters`
            // between the load and the await can't be missed.
            let notified = inflight.drain_notify.notified();
            if inflight.pending.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Register an audit-event listener at the end of the chain.
    ///
    /// Listeners are invoked in registration order for every row an emit
    /// wrote and on every [`Self::notify`]. Returns the id of this
    /// registration, which [`Self::remove_listener`] takes to undo it. Each
    /// call is its own registration: the same listener registered twice
    /// fires twice, and each id removes only its own entry. A listener
    /// meant to live as long as the emitter can ignore the id.
    ///
    /// Twin of the TS `AuditEmitter.add_listener` in `fuz_app`, which
    /// returns a remover closure in place of the id.
    pub fn add_listener(&self, listener: AuditListenerFn) -> AuditListenerId {
        let id = AuditListenerId::next();
        self.listeners.write().push((id, listener));
        id
    }

    /// Unregister the listener registration `id` names.
    ///
    /// Returns whether a registration was removed: `false` when `id` was
    /// already removed or came from another emitter, so a second call is a
    /// no-op. The remaining listeners keep their order. A [`Self::notify`]
    /// already in progress still runs a listener removed during its fan-out
    /// — it runs a snapshot of the chain taken when it started — and the
    /// next one does not.
    ///
    /// Twin of calling the remover the TS `AuditEmitter.add_listener`
    /// returns.
    pub fn remove_listener(&self, id: AuditListenerId) -> bool {
        let mut listeners = self.listeners.write();
        let Some(index) = listeners.iter().position(|(entry_id, _)| *entry_id == id) else {
            return false;
        };
        listeners.remove(index);
        true
    }

    /// Count of registered listeners — introspection for tests and
    /// diagnostics. Twin of the TS `AuditEmitter.listener_count`.
    pub fn listener_count(&self) -> usize {
        self.listeners.read().len()
    }

    /// Spawn a fire-and-forget audit write via the captured pool.
    ///
    /// Pool-routed: the INSERT runs on a separate connection from the
    /// request transaction. The audit row lands even when the request
    /// rolls back — the right shape for attempt/failure audits whose
    /// forensic record should outlive a denied operation. For success
    /// audits that should be atomic with a state mutation, use
    /// [`Self::emit_in_tx`] instead. See [`crate::AUDIT_EVENT_SPECS`]
    /// for the per-event routing policy.
    ///
    /// Returns a `JoinHandle<()>` the caller can await to keep the row
    /// observable by response time (integration tests rely on this for
    /// post-response DB queries). The write runs on a detached tokio
    /// task — a dropped awaiting future doesn't cancel the spawned
    /// task, so the audit row still lands.
    pub fn emit(self: &Arc<Self>, input: AuditLogInput) -> JoinHandle<()> {
        let emitter = Arc::clone(self);
        // Register the in-flight write BEFORE spawning so a concurrent
        // `drain_inflight` can never observe a count that omits it. `None`
        // in production — zero overhead on the hot path.
        let inflight = InflightWriteGuard::acquire(self);
        tokio::spawn(async move {
            // held for the task's life: the count settles when the task ends
            // however it ends — done, panicked, or aborted before it ran
            let _inflight = inflight;
            emitter.write_and_notify(input).await;
        })
    }

    /// In-tx audit write — INSERT against the supplied `db` client.
    ///
    /// Atomic with the caller's transaction: when the request tx
    /// commits, the audit row commits with it; when it rolls back, the
    /// audit row rolls back too. Right shape for SUCCESS audits paired
    /// with a state mutation. Listener fan-out is queued via
    /// `post_commit` and runs **after** the request tx commits.
    ///
    /// For attempt/failure audits that should survive rollback, use
    /// [`Self::emit`] (pool-routed). See [`crate::AUDIT_EVENT_SPECS`]
    /// for the per-event routing policy.
    ///
    /// # Errors
    ///
    /// Returns the underlying `tokio_postgres` error on INSERT failure.
    /// Callers decide whether to propagate (fails the handler, rolls
    /// the audit row back with the state) or log-and-swallow.
    pub async fn emit_in_tx<C>(
        self: &Arc<Self>,
        db: &C,
        input: AuditLogInput,
        post_commit: &dyn AuditPostCommit,
    ) -> Result<(), tokio_postgres::Error>
    where
        C: GenericClient + ?Sized,
    {
        let event_type_str = input.event_type.as_str();
        let row = insert_audit_row(db, &input).await?;
        let Some(event) = row else {
            tracing::warn!(
                event_type = event_type_str,
                "audit log insert returned no row"
            );
            return Ok(());
        };
        let emitter = Arc::clone(self);
        let event = Arc::new(event);
        post_commit.queue_notify(Box::new(move || {
            Box::pin(async move { emitter.notify(event).await })
        }));
        Ok(())
    }

    async fn write_and_notify(&self, input: AuditLogInput) {
        let event_type_str = input.event_type.as_str();
        let client = match self
            .pool
            .timeout_get(&fuz_db::checkout_timeouts(self.checkout_timeout))
            .await
        {
            Ok(c) => c,
            Err(e) => {
                log_dropped_row(&input, &e);
                return;
            }
        };

        match insert_audit_row(&client, &input).await {
            Ok(Some(event)) => self.notify(Arc::new(event)).await,
            Ok(None) => tracing::warn!(
                event_type = event_type_str,
                "audit log insert returned no row"
            ),
            Err(e) => log_dropped_row(&input, &e),
        }
    }

    /// Fan out an audit row to every listener on the chain concurrently.
    ///
    /// Runs a snapshot of the chain taken on entry: a listener registered
    /// during the fan-out first hears the next event, and one removed during
    /// it still hears this one. Each listener is called in registration
    /// order, and the futures they return run concurrently via
    /// `futures::future::join_all`, so a slow listener (stalled SSE client,
    /// network-bound webhook) doesn't block the others for the same event.
    /// The boxed-future signature exists precisely so listeners CAN run
    /// concurrently; this implementation honors that.
    ///
    /// # Panics
    ///
    /// Nothing here catches or logs a listener's panic; it propagates out of
    /// this call. Every listener is called before any future is polled, so a
    /// panic in a call leaves the later listeners uncalled, and a panic while
    /// polling drops the futures still pending — either way the rest of the
    /// chain misses the event. Where it lands next depends on the caller: on
    /// [`Self::emit`]'s spawned task, tokio stops the unwind at the task
    /// boundary — the panic hook's message on stderr is the only trace, the
    /// returned `JoinHandle` yields the panic as its `JoinError`, and the
    /// in-flight count still settles. Under `panic = "abort"` the process
    /// aborts instead (spine servers build with `panic = "unwind"`). From the
    /// post-commit drain (an `emit_in_tx` row's fan-out), the panic is logged
    /// there and takes down the sibling effects still pending in the same
    /// drain. A listener
    /// that must not take the others down with it keeps its own body
    /// panic-free, or under unwinding moves the work onto its own
    /// `tokio::spawn` and returns at once. The TS twin differs here: it calls
    /// each listener in its own `try`, logs a throw, and goes on to the next.
    pub async fn notify(&self, event: Arc<AuditLogEvent>) {
        // clone the chain and release the lock before calling out, so a
        // listener can add or remove listeners without deadlocking
        let listeners = self.listeners.read().clone();
        let futures = listeners
            .into_iter()
            .map(|(_, listener)| listener(Arc::clone(&event)));
        futures::future::join_all(futures).await;
    }
}

/// Routing-aware audit emit shared by every action-context type.
///
/// Looks up `input.event_type` in
/// [`AUDIT_EVENT_SPECS`](crate::AUDIT_EVENT_SPECS) and dispatches per the spec's
/// `routing_for(outcome)`: [`AuditRouting::Pool`] spawns a fire-and-forget pool
/// write (survives rollback); [`AuditRouting::InTx`] INSERTs against `db` in the
/// request transaction and queues listener fan-out on `post_commit` for the
/// post-commit drain. The single routing table is the source of truth for every
/// emit site, auth or domain.
///
/// `fuz_actions::ActionContext` (passing its `PostCommitEffects`) and
/// [`AuthenticatedActionContext`](crate::AuthenticatedActionContext) (passing its
/// `&dyn AuditPostCommit`) both delegate here, so the security-consequential
/// which-rows-survive-rollback decision lives in exactly one place.
///
/// # Errors
///
/// Pool routing always returns `Ok(())`. In-tx routing surfaces a
/// [`JsonrpcError`] on INSERT failure — propagate via `?` so the handler rolls
/// the audit row back together with the state.
pub async fn route_audit_emit<C>(
    audit: &Arc<AuditEmitter>,
    post_commit: &dyn AuditPostCommit,
    db: &C,
    input: AuditLogInput,
) -> Result<(), JsonrpcError>
where
    C: GenericClient + ?Sized,
{
    let outcome = input.outcome.unwrap_or(AuditOutcome::Success);
    let routing = input.event_type.routing_for(outcome);
    match routing {
        AuditRouting::Pool => {
            audit.emit(input);
            Ok(())
        }
        AuditRouting::InTx => audit
            .emit_in_tx(db, input, post_commit)
            .await
            .map_err(|e| internal_error_with_source("audit emit failed", &e)),
    }
}

/// Build a `metadata.credential_type` JSON value for credential-gated
/// audit events. Returns `Value::Null` when no credential was resolved.
#[must_use]
pub fn credential_type_value(credential_type: Option<CredentialType>) -> Value {
    credential_type
        .map(CredentialType::name)
        .map_or(Value::Null, |s| Value::String(s.to_owned()))
}

// -- In-tx routing primitives -----------------------------------------------

/// Boxed post-commit notify closure: `FnOnce() -> BoxFuture<()>`.
///
/// The shape (a `FnOnce` returning a future) lets the closure own the
/// `Arc<AuditEmitter>` + `Arc<AuditLogEvent>` clones inline — no
/// borrowing the dispatcher frame, no extra allocation past the box
/// itself.
pub type AuditNotifyFn = Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send + 'static>;

/// Post-commit hook for [`AuditEmitter::emit_in_tx`].
///
/// The in-tx INSERT lands in the request transaction. Listener fan-out
/// must happen **after** the request tx commits, or listeners (SSE
/// pushers, WS broadcasters) would surface events that may yet be
/// rolled back. This trait is the bridge between the audit emitter
/// (in `fuz_auth`) and the post-commit drain queue (in `fuz_actions`'s
/// `PostCommitEffects`).
///
/// `fuz_actions::PostCommitEffects` implements this trait so the action
/// dispatcher's drain owns the timing. Code that owns its own transaction
/// (a background sweep) passes [`CollectingAuditPostCommit`] and drains it
/// after commit; [`NoopAuditPostCommit`] is for callers that want no fan-out
/// at all (CLI tooling, REPL probes) — the audit row still lands, but no
/// listener fires.
///
/// **Object-safe** — consumed as `&dyn AuditPostCommit` by
/// [`AuditEmitter::emit_in_tx`] and
/// [`crate::AuthenticatedActionContext`]. Sync method (no async on
/// this trait).
pub trait AuditPostCommit: Send + Sync {
    /// Queue a notify closure to run after the request tx commits.
    fn queue_notify(&self, notify: AuditNotifyFn);
}

/// No-op post-commit hook — drops every queued closure unrun.
///
/// Use only when there's genuinely no post-commit drain available
/// (CLI tooling, REPL probes — a sweep that owns its transaction uses
/// [`CollectingAuditPostCommit`]). The in-tx INSERT still lands; what's
/// skipped is everything queued for after the commit — the audit listener
/// fan-out **and** the handlers' own socket closes
/// ([`crate::queue_connection_close`]), so a revocation run with this hook
/// leaves live sockets open. For action-dispatcher contexts,
/// `fuz_actions::PostCommitEffects` is the right implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAuditPostCommit;

impl AuditPostCommit for NoopAuditPostCommit {
    fn queue_notify(&self, _notify: AuditNotifyFn) {}
}

/// Post-commit hook that collects queued closures until the caller drains
/// them after its own commit.
///
/// For code that owns its transaction outside the action dispatcher — a
/// background sweep ([`crate::auth_cleanup::cleanup_expired_role_grant_offers`])
/// or a maintenance job — and still wants the listener fan-out
/// [`NoopAuditPostCommit`] drops: pass it to [`AuditEmitter::emit_in_tx`],
/// commit, then [`Self::drain`]. On a rollback, drop it undrained — nothing
/// fans out for rows that never landed. `fuz_actions::PostCommitEffects` is
/// the dispatcher's equivalent; `fuz_auth` sits below `fuz_actions`, so this
/// is the one an auth-layer caller can name.
#[derive(Default)]
pub struct CollectingAuditPostCommit {
    queued: Mutex<Vec<AuditNotifyFn>>,
}

impl std::fmt::Debug for CollectingAuditPostCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectingAuditPostCommit")
            .field("queued", &self.queued.lock().len())
            .finish()
    }
}

impl CollectingAuditPostCommit {
    /// Run every queued closure, in queue order, and empty the queue. Call
    /// only after the transaction the closures were queued against commits.
    pub async fn drain(&self) {
        let queued = std::mem::take(&mut *self.queued.lock());
        for notify in queued {
            notify().await;
        }
    }
}

impl AuditPostCommit for CollectingAuditPostCommit {
    fn queue_notify(&self, notify: AuditNotifyFn) {
        self.queued.lock().push(notify);
    }
}

/// The whole row a dropped pool write would have inserted, as one JSON
/// object: `event_type`, `outcome`, the four id columns, `ip`, `metadata`.
///
/// Nothing is masked. No spine event's metadata carries a secret — it records
/// ids, names, and reasons, never a credential. A consumer's custom event
/// ([`AuditLogInput::for_custom_event`]) is logged whole, so keep secrets out
/// of audit metadata (they would land in `audit_log` too). The TS twin masks a
/// metadata field its event schema marks `sensitivity: 'secret'`; no builtin
/// event declares one, so both twins log the same builtin row.
#[must_use]
pub fn dropped_row_json(input: &AuditLogInput) -> Value {
    serde_json::json!({
        "event_type": input.event_type.as_str(),
        "outcome": input.outcome.unwrap_or(AuditOutcome::Success).as_str(),
        "actor_id": input.actor_id,
        "account_id": input.account_id,
        "target_account_id": input.target_account_id,
        "target_actor_id": input.target_actor_id,
        "ip": input.ip,
        "metadata": input.metadata,
    })
}

/// Log a dropped pool write: one `error` line carrying the whole row
/// ([`dropped_row_json`]) and the cause. Twin of the TS emitter's
/// `audit row dropped` line.
fn log_dropped_row(input: &AuditLogInput, error: &dyn std::fmt::Debug) {
    tracing::error!(
        row = %dropped_row_json(input),
        error = ?error,
        "audit row dropped",
    );
}

/// Shared INSERT path used by both pool-routed and in-tx audit emits.
///
/// Generic over `GenericClient` so the same SQL/row-extraction body
/// services both `&Object` (pool) and `&Transaction` (in-tx). Keeping
/// one helper means schema changes (column additions, JSONB encoding
/// flips) edit one site, not two.
///
/// Returns `Ok(None)` only when the INSERT-RETURNING produces zero
/// rows — a server-side anomaly, never expected. Callers translate to
/// a `warn` log.
async fn insert_audit_row<C>(
    client: &C,
    input: &AuditLogInput,
) -> Result<Option<AuditLogEvent>, tokio_postgres::Error>
where
    C: GenericClient + ?Sized,
{
    let outcome = input.outcome.unwrap_or(AuditOutcome::Success).as_str();
    let event_type_str = input.event_type.as_str();
    let metadata_json = input.metadata.as_ref().map(Value::to_string);

    // `metadata::text::jsonb` round-trips through SQL as TEXT, so we
    // don't need `tokio-postgres`'s `with-serde_json-1` feature.
    // `audit_log_columns` plays the same trick on the `RETURNING
    // metadata::text` read.
    let sql = format!(
        "INSERT INTO audit_log
           (event_type, outcome, actor_id, account_id,
            target_account_id, target_actor_id, ip, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::jsonb)
         RETURNING {columns}",
        columns = audit_log_columns("audit_log"),
    );
    let row = client
        .query_opt(
            &sql,
            &[
                &event_type_str,
                &outcome,
                &input.actor_id,
                &input.account_id,
                &input.target_account_id,
                &input.target_actor_id,
                &input.ip,
                &metadata_json,
            ],
        )
        .await?;

    Ok(row.as_ref().map(decode_audit_log_row))
}

#[cfg(test)]
mod tests {
    use super::{AuditLogInput, AuditOutcome};
    use crate::audit_event_type::{AuditEventType, AuditRouting};

    #[test]
    fn an_unset_ip_leaves_the_column_null() {
        let input = AuditLogInput::for_event(AuditEventType::Login);
        assert_eq!(input.ip, None);
    }

    #[test]
    fn for_event_defaults_to_a_success_outcome() {
        let input = AuditLogInput::for_event(AuditEventType::Login);
        assert_eq!(input.outcome, Some(AuditOutcome::Success));
    }

    #[test]
    fn a_resolved_ip_is_recorded_verbatim() {
        let input =
            AuditLogInput::for_event(AuditEventType::Login).ip(Some("198.51.100.9".to_owned()));
        assert_eq!(input.ip.as_deref(), Some("198.51.100.9"));
    }

    #[test]
    fn an_unresolved_ip_records_the_sentinel() {
        let input = AuditLogInput::for_event(AuditEventType::Login).ip(None);
        assert_eq!(input.ip.as_deref(), Some(fuz_http::UNRESOLVED_CLIENT_IP));
    }

    #[test]
    fn for_custom_event_accepts_an_on_grammar_name() {
        const INPUT: AuditLogInput = AuditLogInput::for_custom_event(
            "app.classroom_create",
            AuditRouting::InTx,
            AuditRouting::Pool,
        );
        assert_eq!(INPUT.event_type.as_str(), "app.classroom_create");
        assert_eq!(INPUT.outcome, Some(AuditOutcome::Success));
    }

    /// An off-grammar name is refused at construction: the `audit_log_list`
    /// filter could never select the event it would write.
    #[test]
    #[should_panic(expected = "off the audit event-type grammar")]
    fn for_custom_event_panics_on_an_off_grammar_name() {
        let _ = AuditLogInput::for_custom_event(
            std::hint::black_box("classroom create"),
            AuditRouting::InTx,
            AuditRouting::Pool,
        );
    }

    /// A name past the shared cap is refused at construction, as the
    /// `audit_log_list` filter refuses it.
    #[test]
    #[should_panic(expected = "at most 64 characters")]
    fn for_custom_event_panics_on_a_name_past_the_cap() {
        let _ = AuditLogInput::for_custom_event(
            std::hint::black_box(
                "a_name_of_sixty_five_characters_which_is_one_past_the_cap_xxxxxxx",
            ),
            AuditRouting::InTx,
            AuditRouting::Pool,
        );
    }

    /// A spine event type's wire string is refused at construction: the
    /// revocation guard and the `audit_log_list` filter would read the
    /// custom event as the spine's own.
    #[test]
    #[should_panic(expected = "collides with a spine audit event type")]
    fn for_custom_event_panics_on_a_spine_event_name() {
        let _ = AuditLogInput::for_custom_event(
            std::hint::black_box("session_revoke_all"),
            AuditRouting::InTx,
            AuditRouting::Pool,
        );
    }
}

/// The listener chain: registration, removal, and the snapshot `notify` runs.
/// No database — the pool builds lazily and `notify` never touches it.
#[cfg(test)]
mod listener_tests {
    use std::sync::{Arc, OnceLock, Weak};

    use parking_lot::Mutex;

    use super::AuditEmitter;
    use crate::audit_event_schema::AuditLogEvent;
    use crate::audit_listener::{AuditListenerFn, AuditListenerId};

    type Calls = Arc<Mutex<Vec<&'static str>>>;

    fn emitter() -> Arc<AuditEmitter> {
        let pool = fuz_db::create_pool(
            "postgres://u:p@localhost:5432/unused",
            &fuz_db::PoolOptions::default(),
        )
        .expect("a lazily-built pool needs no server");
        Arc::new(AuditEmitter::new(pool))
    }

    fn event() -> Arc<AuditLogEvent> {
        Arc::new(AuditLogEvent {
            id: uuid::Uuid::nil(),
            seq: 1,
            event_type: "login".to_owned(),
            outcome: "success".to_owned(),
            actor_id: None,
            account_id: None,
            target_account_id: None,
            target_actor_id: None,
            ip: None,
            created_at: "2026-01-01T00:00:00.000Z".to_owned(),
            metadata: None,
        })
    }

    /// A listener that records `label` when called.
    fn recording(calls: &Calls, label: &'static str) -> AuditListenerFn {
        let calls = Arc::clone(calls);
        Arc::new(move |_event| {
            calls.lock().push(label);
            Box::pin(async {})
        })
    }

    async fn notify_and_take(emitter: &AuditEmitter, calls: &Calls) -> Vec<&'static str> {
        emitter.notify(event()).await;
        std::mem::take(&mut *calls.lock())
    }

    #[tokio::test]
    async fn listeners_are_called_in_registration_order() {
        let emitter = emitter();
        let calls = Calls::default();
        emitter.add_listener(recording(&calls, "a"));
        emitter.add_listener(recording(&calls, "b"));
        emitter.add_listener(recording(&calls, "c"));
        assert_eq!(notify_and_take(&emitter, &calls).await, ["a", "b", "c"]);
    }

    #[tokio::test]
    async fn a_removed_listener_stops_hearing_and_the_rest_keep_their_order() {
        let emitter = emitter();
        let calls = Calls::default();
        emitter.add_listener(recording(&calls, "a"));
        let b = emitter.add_listener(recording(&calls, "b"));
        emitter.add_listener(recording(&calls, "c"));
        assert!(emitter.remove_listener(b));
        assert_eq!(emitter.listener_count(), 2);
        assert_eq!(notify_and_take(&emitter, &calls).await, ["a", "c"]);
    }

    #[tokio::test]
    async fn removing_twice_is_a_no_op() {
        let emitter = emitter();
        let calls = Calls::default();
        let a = emitter.add_listener(recording(&calls, "a"));
        emitter.add_listener(recording(&calls, "b"));
        assert!(emitter.remove_listener(a));
        assert!(
            !emitter.remove_listener(a),
            "a second removal removes nothing"
        );
        assert_eq!(emitter.listener_count(), 1);
        assert_eq!(notify_and_take(&emitter, &calls).await, ["b"]);
    }

    #[tokio::test]
    async fn each_registration_of_one_listener_is_its_own() {
        let emitter = emitter();
        let calls = Calls::default();
        let listener = recording(&calls, "dup");
        let first = emitter.add_listener(Arc::clone(&listener));
        emitter.add_listener(recording(&calls, "between"));
        let second = emitter.add_listener(listener);
        assert_ne!(first, second);
        assert_eq!(
            notify_and_take(&emitter, &calls).await,
            ["dup", "between", "dup"],
            "a listener registered twice fires twice",
        );
        assert!(emitter.remove_listener(first));
        assert_eq!(
            notify_and_take(&emitter, &calls).await,
            ["between", "dup"],
            "removing one registration leaves the other in place",
        );
    }

    #[tokio::test]
    async fn an_id_from_another_emitter_removes_nothing() {
        let issuer = emitter();
        let other = emitter();
        let calls = Calls::default();
        let foreign = issuer.add_listener(recording(&calls, "issuer"));
        other.add_listener(recording(&calls, "other"));
        assert!(!other.remove_listener(foreign));
        assert_eq!(notify_and_take(&other, &calls).await, ["other"]);
    }

    #[tokio::test]
    async fn a_notify_in_progress_runs_the_chain_it_started_with() {
        let emitter = emitter();
        let calls = Calls::default();
        let doomed_id: Arc<OnceLock<AuditListenerId>> = Arc::default();
        // `a` removes `doomed` and registers `late` mid-fan-out; weak, so the
        // emitter isn't kept alive by its own listener
        let weak: Weak<AuditEmitter> = Arc::downgrade(&emitter);
        let late = recording(&calls, "late");
        let a: AuditListenerFn = {
            let calls = Arc::clone(&calls);
            let doomed_id = Arc::clone(&doomed_id);
            Arc::new(move |_event| {
                calls.lock().push("a");
                if let (Some(emitter), Some(id)) = (weak.upgrade(), doomed_id.get())
                    && emitter.remove_listener(*id)
                {
                    emitter.add_listener(Arc::clone(&late));
                }
                Box::pin(async {})
            })
        };
        emitter.add_listener(a);
        let doomed = emitter.add_listener(recording(&calls, "doomed"));
        doomed_id.set(doomed).expect("set once");
        assert_eq!(
            notify_and_take(&emitter, &calls).await,
            ["a", "doomed"],
            "the in-progress event reaches the removed listener, not the new one",
        );
        assert_eq!(
            notify_and_take(&emitter, &calls).await,
            ["a", "late"],
            "the next event follows the changed chain",
        );
    }
}

/// The in-flight count behind [`AuditEmitter::drain_inflight`] settles when a
/// tracked write's task never reaches the end of its body. No database: the
/// task is aborted before it first runs, so the lazily built pool is never
/// used. The listener-panic case needs a written row, so it lives in the
/// Postgres suite `tests/audit_drain.rs`.
#[cfg(test)]
mod drain_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{AuditEmitter, AuditLogInput};
    use crate::audit_event_type::AuditEventType;

    #[test]
    fn is_tracking_inflight_reports_the_construction() {
        let pool = || {
            fuz_db::create_pool(
                "postgres://u:p@localhost:5432/unused",
                &fuz_db::PoolOptions::default(),
            )
            .expect("a lazily-built pool needs no server")
        };
        assert!(AuditEmitter::new_with_inflight_tracking(pool()).is_tracking_inflight());
        assert!(!AuditEmitter::new(pool()).is_tracking_inflight());
    }

    #[tokio::test]
    async fn an_aborted_write_still_settles_the_drain() {
        let pool = fuz_db::create_pool(
            "postgres://u:p@localhost:5432/unused",
            &fuz_db::PoolOptions::default(),
        )
        .expect("a lazily-built pool needs no server");
        let emitter = Arc::new(AuditEmitter::new_with_inflight_tracking(pool));
        // the current-thread test runtime doesn't run the task until this
        // test yields, so the abort lands before its first poll
        let handle = emitter.emit(AuditLogInput::for_event(AuditEventType::Login));
        handle.abort();
        assert!(
            handle.await.is_err_and(|e| e.is_cancelled()),
            "the write was cancelled before it ran"
        );
        tokio::time::timeout(Duration::from_secs(5), emitter.drain_inflight())
            .await
            .expect("drain_inflight resolves once the aborted write's task is gone");
    }
}
