//! `_testing_drain_effects` action spec.
//!
//! The overview is on [`create_testing_drain_effects_action_spec`].

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_http::BackgroundWrites;
use fuz_http::InputShape;
use serde_json::{Value, json};

/// Build the `_testing_drain_effects` action spec over `background_writes`,
/// the server's tracker.
///
/// The handler runs `drain_effects`. The TS twin's input is `s.void`, so
/// the spec declares [`InputShape::Void`]: the dispatcher refuses any declared
/// parameter before the drain runs, and an absent `params` and a `{}` both
/// call it.
///
/// Test binaries register this on their `ActionRegistry` alongside
/// `_testing_reset`. It awaits every detached write in flight on the server's
/// tracker (`fuz_actions::server::AppBackend::background_writes`) — each
/// fire-and-forget audit `emit`, each bearer token touch, the bootstrap
/// write, each action's post-commit effects — so a following
/// `audit_log_list` or database read is authoritative: the deterministic
/// barrier the cross-backend conformance
/// suite uses in place of a poll/sleep before asserting on audit rows or
/// `api_token.last_used_at`.
///
/// The action answers `{"ok": true}`, as the TS twin does.
///
/// Gated on the daemon-token credential — effectively keeper-only without
/// forcing the `actor: 'required'` biconditional, matching `_testing_reset`.
/// Mirrors `fuz_app`'s TS `_testing_drain_effects`, with one divergence: the
/// TS action awaits `AuditEmitter.drain_inflight` only, while this one also
/// waits on post-commit effects in flight (the TS token touch and post-commit
/// thunks ride the request's effect flush instead).
#[must_use]
pub fn create_testing_drain_effects_action_spec(
    background_writes: Arc<BackgroundWrites>,
) -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |_params: Value, _ctx: ActionContext<'_>| {
        let background_writes = Arc::clone(&background_writes);
        Box::pin(async move { Ok(drain_effects(&background_writes).await) })
    });

    ActionSpec::read_only(
        "_testing_drain_effects",
        crate::TESTING_ACTION_AUTH,
        InputShape::Void,
        handler,
    )
}

/// The action's body: await `background_writes.drain()`, then answer
/// `{"ok": true}`.
async fn drain_effects(background_writes: &BackgroundWrites) -> Value {
    background_writes.drain().await;
    json!({ "ok": true })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use fuz_auth::{AuditEmitter, AuditEventType, AuditLogInput};
    use fuz_http::BackgroundWrites;
    use serde_json::json;

    use super::drain_effects;

    /// A pool refused at once, so a write over it settles fast without a
    /// server.
    fn refused_pool() -> deadpool_postgres::Pool {
        crate::unreachable_pool()
    }

    #[tokio::test]
    async fn the_drain_answers_ok() {
        assert_eq!(
            drain_effects(&BackgroundWrites::default()).await,
            json!({ "ok": true }),
        );
    }

    /// The handler's body awaits the drain: on the current-thread test
    /// runtime the write's task hasn't run when `drain_effects` is called, so
    /// only a drain that yields until the write settles sees it finished.
    #[tokio::test]
    async fn the_drain_waits_for_a_write() {
        let writes = Arc::new(BackgroundWrites::default());
        let emitter = Arc::new(AuditEmitter::new(refused_pool(), Arc::clone(&writes)));
        let write = emitter.emit(AuditLogInput::for_event(AuditEventType::Login));
        assert!(
            !write.is_finished(),
            "the write ran before the drain was called"
        );
        let answer = tokio::time::timeout(Duration::from_secs(10), drain_effects(&writes))
            .await
            .expect("the drain settles once the refused write does");
        assert!(
            write.is_finished(),
            "the drain answered before the write settled"
        );
        assert_eq!(answer, json!({ "ok": true }));
    }

    /// A token touch in flight on the tracker holds the drain the same way:
    /// the touch has settled by the time the action answers.
    #[tokio::test]
    async fn the_drain_waits_for_a_token_touch() {
        let writes = Arc::new(BackgroundWrites::default());
        let touch = fuz_auth::api_token_queries::spawn_api_token_touch(
            &writes,
            &refused_pool(),
            "tok_unused",
            "127.0.0.1",
        );
        assert!(
            !touch.is_finished(),
            "the touch ran before the drain was called"
        );
        let answer = tokio::time::timeout(Duration::from_secs(10), drain_effects(&writes))
            .await
            .expect("the drain settles once the refused touch does");
        assert!(
            touch.is_finished(),
            "the drain answered before the touch settled"
        );
        assert_eq!(answer, json!({ "ok": true }));
    }
}
