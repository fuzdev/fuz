//! `_testing_drain_effects` action spec.
//!
//! Test binaries register this on their `ActionRegistry` alongside
//! `_testing_reset`. It awaits every in-flight fire-and-forget audit
//! `emit` (via [`fuz_auth::AuditEmitter::drain_inflight`]) so a following
//! `audit_log_list` read is authoritative — the deterministic barrier the
//! cross-backend conformance suite uses in place of a poll/sleep before
//! asserting on audit rows.
//!
//! The emitter must have been built via
//! [`fuz_auth::AuditEmitter::new_with_inflight_tracking`]; otherwise the
//! drain is a no-op (nothing is tracked). The action answers
//! `{"ok": true, "tracked": <bool>}`, `tracked` read from
//! [`fuz_auth::AuditEmitter::is_tracking_inflight`], and `fuz_app`'s
//! `list_audit_events` reads refuse `tracked: false` — so a test binary built
//! over an untracked emitter fails its first audit read instead of racing it.
//!
//! Gated on the daemon-token credential — effectively keeper-only without
//! forcing the `actor: 'required'` biconditional, matching `_testing_reset`.
//! Mirrors `fuz_app`'s TS `_testing_drain_effects`, which does the same
//! await — `AuditEmitter.drain_inflight` over an emitter built with
//! `track_inflight: true`, the twin of `new_with_inflight_tracking` here.

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_auth::AuditEmitter;
use fuz_http::InputShape;
use serde_json::{Value, json};

/// Build the `_testing_drain_effects` action spec bound to `emitter`.
///
/// The handler runs `drain_effects`. The TS twin's input is `z.void()`, so
/// the spec declares [`InputShape::Void`]: the dispatcher refuses any declared
/// parameter before the drain runs, and an absent `params` and a `{}` both
/// call it.
#[must_use]
pub fn create_testing_drain_effects_action_spec(emitter: Arc<AuditEmitter>) -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |_params: Value, _ctx: ActionContext<'_>| {
        let emitter = Arc::clone(&emitter);
        Box::pin(async move { Ok(drain_effects(&emitter).await) })
    });

    ActionSpec::read_only(
        "_testing_drain_effects",
        crate::TESTING_ACTION_AUTH,
        InputShape::Void,
        handler,
    )
}

/// The action's body: await `emitter.drain_inflight()`, then answer
/// `{"ok": true, "tracked": <emitter.is_tracking_inflight()>}`.
async fn drain_effects(emitter: &AuditEmitter) -> Value {
    emitter.drain_inflight().await;
    json!({ "ok": true, "tracked": emitter.is_tracking_inflight() })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use fuz_auth::{AuditEmitter, AuditEventType, AuditLogInput};
    use serde_json::json;

    use super::drain_effects;

    /// A never-connected lazy pool — nothing is emitted, so the drain never
    /// touches it.
    fn unused_pool() -> deadpool_postgres::Pool {
        fuz_db::create_pool(
            "postgresql://test@localhost/test",
            &fuz_db::PoolOptions::default(),
        )
        .expect("lazy pool builds")
    }

    #[tokio::test]
    async fn a_tracking_emitter_answers_tracked_true() {
        let emitter = AuditEmitter::new_with_inflight_tracking(unused_pool());
        assert_eq!(
            drain_effects(&emitter).await,
            json!({ "ok": true, "tracked": true }),
        );
    }

    #[tokio::test]
    async fn an_untracked_emitter_answers_tracked_false() {
        let emitter = AuditEmitter::new(unused_pool());
        assert_eq!(
            drain_effects(&emitter).await,
            json!({ "ok": true, "tracked": false }),
        );
    }

    /// The handler's body awaits the drain: on the current-thread test
    /// runtime the write's task hasn't run when `drain_effects` is called, so
    /// only a drain that yields until the write settles sees it finished.
    #[tokio::test]
    async fn the_drain_waits_for_a_tracked_write() {
        // refused at once, so the write settles fast without a server
        let pool = fuz_db::create_pool(
            "postgres://nobody@127.0.0.1:1/nothing",
            &fuz_db::PoolOptions::default(),
        )
        .expect("lazy pool builds");
        let emitter = Arc::new(AuditEmitter::new_with_inflight_tracking(pool));
        let write = emitter.emit(AuditLogInput::for_event(AuditEventType::Login));
        assert!(
            !write.is_finished(),
            "the write ran before the drain was called"
        );
        let answer = tokio::time::timeout(Duration::from_secs(10), drain_effects(&emitter))
            .await
            .expect("the drain settles once the refused write does");
        assert!(
            write.is_finished(),
            "the drain answered before the write settled"
        );
        assert_eq!(answer, json!({ "ok": true, "tracked": true }));
    }
}
