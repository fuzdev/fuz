//! `heartbeat` protocol action.
//!
//! Mirrors `fuz_app/src/lib/actions/heartbeat.ts`. Always registered;
//! protocol-level rather than application-level.
//!
//! ## Behavior
//!
//! `side_effects: false`, and [`ActionSpec::ws_only`] — the socket's liveness
//! probe is served over WebSocket only, so an HTTP call answers
//! `method_not_found` exactly as an unregistered method does. The TS twin
//! reaches the same contract by mounting: `protocol_actions` is spread into a
//! consumer's WS endpoint and never into its HTTP-RPC mount.
//!
//! Auth is `account: required, actor: none`, matching the TS spec. Over the
//! socket that is a no-op — the upgrade already authenticated the connection —
//! but declaring it keeps the two spines' auth shapes identical rather than
//! resting the gate on the transport.
//!
//! Nullary input and output — the input is `void` on the TS side, so the
//! spec declares [`fuz_http::InputShape::Void`]: an absent, `null`, or `{}`
//! params is the call and the dispatcher refuses any other shape with
//! `-32602` before the handler runs. The output is an empty object. Liveness is
//! proven by a successful round-trip, not by payload content;
//! `{client_ts, server_ts}` fields can be added later if a real consumer needs
//! them, in lockstep across both impls.

use std::sync::Arc;

use fuz_auth::{AuthSpec, CredentialGate};
use fuz_http::InputShape;
use serde_json::{Map, Value};

use crate::action_spec::ActionSpec;

/// The wire method name.
pub const HEARTBEAT_METHOD: &str = "heartbeat";

/// Build the heartbeat spec.
#[must_use]
pub fn heartbeat_action_spec() -> ActionSpec {
    ActionSpec::read_only(
        HEARTBEAT_METHOD,
        AuthSpec::account_grain(CredentialGate::Any),
        InputShape::Void,
        Arc::new(|_params, _ctx| Box::pin(async move { Ok(heartbeat()) })),
    )
    .with_ws_only()
}

/// The heartbeat body: echo `{}`. A declared param never reaches here — the
/// spec's [`InputShape::Void`] has the dispatcher refuse it first.
fn heartbeat() -> Value {
    Value::Object(Map::new())
}

#[cfg(test)]
mod tests {
    use super::{HEARTBEAT_METHOD, heartbeat, heartbeat_action_spec};
    use fuz_auth::{AuthAxis, CredentialGate};
    use fuz_http::InputShape;
    use serde_json::json;

    /// The auth shape is the TS spec's, field for field
    /// (`{account: 'required', actor: 'none'}` with no role or credential
    /// gate) — the socket is already authenticated, so this is a declaration
    /// of intent rather than a live gate over WS.
    #[test]
    fn heartbeat_is_account_grain_and_ws_only() {
        let spec = heartbeat_action_spec();
        assert_eq!(spec.method, HEARTBEAT_METHOD);
        assert!(!spec.side_effects);
        assert!(spec.ws_only);
        assert_eq!(spec.auth.account, AuthAxis::Required);
        assert_eq!(spec.auth.actor, AuthAxis::None);
        assert_eq!(spec.auth.roles, None);
        assert_eq!(spec.auth.credentials, CredentialGate::Any);
    }

    /// The twin's `void` input: the spec declares the void shape, so the
    /// dispatcher (not the handler) refuses a declared param, and the body
    /// answers `{}`.
    #[test]
    fn heartbeat_is_void_and_echoes_an_empty_object() {
        assert_eq!(heartbeat_action_spec().input, InputShape::Void);
        assert_eq!(heartbeat(), json!({}));
    }
}
