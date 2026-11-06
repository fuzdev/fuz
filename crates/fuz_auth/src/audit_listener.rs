//! Audit-event listener shape and registration handle.
//!
//! ## Listener signature
//!
//! A listener takes `Arc<AuditLogEvent>` and returns a boxed future: the
//! chain shares one event without a per-listener clone, and a listener can
//! do async work (an SSE push over the network) inside its future, which
//! [`AuditEmitter::notify`](crate::AuditEmitter::notify) runs concurrently
//! with the others. The cost is an `Arc` per event and a boxed future per
//! listener call, which a synchronous `Fn(&AuditLogEvent)` would avoid.
//!
//! The TS twin in `fuz_app`'s `audit_emitter.ts` takes synchronous
//! listeners — `(event) => void`, called in turn — so one with async work
//! starts it and returns.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::future::BoxFuture;

use crate::audit_event_schema::AuditLogEvent;

/// Listener callback shape.
///
/// Type alias for the boxed-`Fn` form so listener factories can be
/// written without spelling the full type at every call site.
pub type AuditListenerFn = Arc<dyn Fn(Arc<AuditLogEvent>) -> BoxFuture<'static, ()> + Send + Sync>;

/// Handle for one listener registration on an
/// [`AuditEmitter`](crate::AuditEmitter).
///
/// Returned by [`AuditEmitter::add_listener`](crate::AuditEmitter::add_listener)
/// and passed to
/// [`AuditEmitter::remove_listener`](crate::AuditEmitter::remove_listener).
///
/// Identifies the registration, not the listener: the same
/// [`AuditListenerFn`] registered twice gets two ids, and each removes only
/// its own entry. Ids are unique across the process, so one presented to an
/// emitter that didn't issue it removes nothing. Plain data, not a guard —
/// dropping it leaves the listener registered, which is what a listener
/// meant to live as long as the emitter wants.
///
/// The TS twin hands back a remover closure instead (`add_listener` returns
/// `() => void` in `fuz_app`'s `audit_emitter.ts`); the id is the same
/// handle in a shape that needs no captured reference to the emitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditListenerId(u64);

impl AuditListenerId {
    /// Mint the next process-unique id.
    pub(crate) fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}
