//! `_testing_room_evict` action spec.
//!
//! The overview is on [`create_testing_room_evict_action_spec`].

use std::sync::Arc;

use fuz_actions::{ActionContext, ActionHandler, ActionSpec};
use fuz_http::{InputShape, JsonrpcError, invalid_input_params};
use fuz_realtime::{RoomEvictReason, RoomEvictTarget, RoomId, RoomRegistry, RoomScope};
use serde_json::{Value, json};

/// The spec's wire method.
const TESTING_ROOM_EVICT_METHOD: &str = "_testing_room_evict";

/// Declared input keys — a strict object.
const TESTING_ROOM_EVICT_KEYS: &[&str] = &["target", "reason"];

/// Read `params` as the twin's input schema reads it (module doc, "Wire").
fn parse_input(params: &Value) -> Result<(RoomEvictTarget, RoomEvictReason), JsonrpcError> {
    if !params.is_object() {
        return Err(invalid_input_params("params must be an object", None));
    }
    fuz_http::reject_unknown_keys(params, TESTING_ROOM_EVICT_KEYS)?;
    let target = params
        .get("target")
        .filter(|target| target.is_object())
        .ok_or_else(|| invalid_input_params("target (object) is required", None))?;
    let kind = fuz_http::parse_str_param(target, "kind")?;
    let scope = |target: &Value| -> Result<RoomScope, JsonrpcError> {
        fuz_http::parse_str_param(target, "scope").map(RoomScope::new)
    };
    let target = match kind {
        "actor" => {
            fuz_http::reject_unknown_keys(target, &["kind", "actor_id"])?;
            RoomEvictTarget::Actor(fuz_http::parse_uuid_param(target, "actor_id")?)
        }
        "actor_in_scope" => {
            fuz_http::reject_unknown_keys(target, &["kind", "actor_id", "scope"])?;
            RoomEvictTarget::ActorInScope {
                actor_id: fuz_http::parse_uuid_param(target, "actor_id")?,
                scope: scope(target)?,
            }
        }
        "room" => {
            fuz_http::reject_unknown_keys(target, &["kind", "room_id"])?;
            let raw = fuz_http::parse_str_param(target, "room_id")?;
            RoomEvictTarget::Room(
                RoomId::parse(raw)
                    .map_err(|e| invalid_input_params(&format!("room_id: {e}"), None))?,
            )
        }
        "scope" => {
            fuz_http::reject_unknown_keys(target, &["kind", "scope"])?;
            RoomEvictTarget::Scope(scope(target)?)
        }
        _ => return Err(invalid_input_params("target.kind is unknown", None)),
    };
    let reason = match params.get("reason").and_then(Value::as_str) {
        Some("evicted") => RoomEvictReason::Evicted,
        Some("room_closed") => RoomEvictReason::RoomClosed,
        _ => {
            return Err(invalid_input_params(
                "reason must be \"evicted\" or \"room_closed\"",
                None,
            ));
        }
    };
    Ok((target, reason))
}

/// Build the `_testing_room_evict` action spec over `registry`, the one the
/// binary's room verbs run on.
///
/// Calls a backend's room registry's [`RoomRegistry::evict`], as a consumer
/// does after its own authority change commits, so the cross suites pin
/// eviction on both spines without a consumer's domain to drive it. A test
/// binary mounting the room verbs (`fuz_actions::room`) mounts this beside
/// them, over the same registry.
///
/// ## Wire
///
/// Params, a strict object `{target, reason}`:
///
/// - `target` — what to evict, a strict object on `kind`:
///   `{kind: "actor", actor_id}`, `{kind: "actor_in_scope", actor_id, scope}`,
///   `{kind: "room", room_id}`, or `{kind: "scope", scope}` — the
///   [`RoomEvictTarget`] arms. `actor_id` is a wire UUID, `room_id` a
///   [`RoomId`], `scope` any string.
/// - `reason` — `"evicted"` or `"room_closed"` ([`RoomEvictReason`]).
///
/// Anything else is `invalid_params` with no reason, as the TS twin's input
/// schema refuses it. The result is the registry's count,
/// `{seats, watches, pending}` ([`fuz_realtime::RoomEvicted`]).
///
/// Without side effects, like the room verbs: the registry is memory, so no
/// transaction opens. Gated on the daemon-token credential, matching
/// `_testing_reset`. Mirrors `fuz_app`'s TS `_testing_room_evict`.
#[must_use]
pub fn create_testing_room_evict_action_spec(registry: Arc<RoomRegistry>) -> ActionSpec {
    let handler: ActionHandler = Arc::new(move |params: Value, _ctx: ActionContext<'_>| {
        let registry = Arc::clone(&registry);
        Box::pin(async move {
            let (target, reason) = parse_input(&params)?;
            let evicted = registry.evict(&target, reason);
            Ok(json!({
                "seats": evicted.seats,
                "watches": evicted.watches,
                "pending": evicted.pending,
            }))
        })
    });

    ActionSpec::read_only(
        TESTING_ROOM_EVICT_METHOD,
        crate::TESTING_ACTION_AUTH,
        InputShape::Object,
        handler,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_input_reads_each_target_and_reason() {
        let actor = "0b4f5b0e-1c8a-4d63-9a51-1f0c2a3b4c5d";
        let parsed = |params: Value| parse_input(&params).map(|(target, _)| target);
        assert_eq!(
            parsed(json!({"target": {"kind": "actor", "actor_id": actor}, "reason": "evicted"}))
                .unwrap(),
            RoomEvictTarget::Actor(actor.parse().unwrap())
        );
        assert_eq!(
            parsed(json!({
                "target": {"kind": "actor_in_scope", "actor_id": actor, "scope": "g1"},
                "reason": "evicted"
            }))
            .unwrap(),
            RoomEvictTarget::ActorInScope {
                actor_id: actor.parse().unwrap(),
                scope: RoomScope::new("g1"),
            }
        );
        assert_eq!(
            parsed(
                json!({"target": {"kind": "room", "room_id": "open:a"}, "reason": "room_closed"})
            )
            .unwrap(),
            RoomEvictTarget::Room(RoomId::parse("open:a").unwrap())
        );
        assert_eq!(
            parse_input(
                &json!({"target": {"kind": "scope", "scope": "g1"}, "reason": "room_closed"})
            )
            .unwrap(),
            (
                RoomEvictTarget::Scope(RoomScope::new("g1")),
                RoomEvictReason::RoomClosed
            )
        );
    }

    #[test]
    fn the_input_is_strict() {
        let actor = "0b4f5b0e-1c8a-4d63-9a51-1f0c2a3b4c5d";
        for params in [
            json!(null),
            json!([]),
            json!({"reason": "evicted"}),
            json!({"target": {"kind": "scope", "scope": "g1"}}),
            json!({"target": {"kind": "scope", "scope": "g1"}, "reason": "moved"}),
            json!({"target": {"kind": "scope", "scope": "g1"}, "reason": "evicted", "x": 1}),
            json!({"target": {"kind": "scope", "scope": "g1", "x": 1}, "reason": "evicted"}),
            json!({"target": {"kind": "scope", "actor_id": actor}, "reason": "evicted"}),
            json!({"target": {"kind": "actor", "actor_id": "nope"}, "reason": "evicted"}),
            json!({"target": {"kind": "room", "room_id": "has space"}, "reason": "evicted"}),
            json!({"target": {"kind": "everyone"}, "reason": "evicted"}),
            json!({"target": "scope", "reason": "evicted"}),
        ] {
            assert!(parse_input(&params).is_err(), "{params}");
        }
    }
}
