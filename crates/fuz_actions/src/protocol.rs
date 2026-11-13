//! Aggregator for built-in **dispatchable** protocol actions.
//!
//! Mirrors the dispatch-map half of `fuz_app/src/lib/actions/protocol.ts`.
//! The TS bundle also carries `cancel`, but as a `remote_notification` spec
//! that `compile_action_registry` keeps out of `action_map`; this crate's
//! registry *is* the dispatch map, so `cancel` is simply absent (see
//! [`fuz_realtime::CANCEL_METHOD`]). Consumers merge
//! [`PROTOCOL_ACTION_SPECS`] alongside their own specs when building
//! their [`crate::ActionRegistry`]:
//!
//! ```ignore
//! let mut specs: Vec<ActionSpec> = Vec::new();
//! specs.extend(fuz_actions::PROTOCOL_ACTION_SPECS());
//! specs.extend(my_app_specs());
//! let registry = ActionRegistry::compile(specs)?;
//! ```
//!
//! Built as a function rather than a static slice because each
//! [`ActionSpec`] holds an `Arc<dyn ...>` handler — `Arc::new` isn't
//! `const` so we can't build the slice at compile time.

use crate::action_spec::ActionSpec;
use crate::heartbeat::heartbeat_action_spec;
use crate::peer_ping::peer_ping_action_spec;

/// The full set of built-in protocol action specs.
///
/// `peer/ping` is the server→client complement to the client→server
/// `heartbeat` (see `peer_ping`). Like `heartbeat` it is protocol-level
/// (every consumer registers it; `heartbeat` is `ws_only`, `peer/ping` is
/// reachable on both transports) and so is **excluded
/// from the cross-impl action-manifest** by the
/// `PROTOCOL_ACTION_SPECS`-method filter — its parity is the behavioral
/// `describe_peer_ping_ws_tests` suite, not the manifest gate.
///
/// `cancel` is not here: it is a notification the WS read loop owns, never
/// a dispatched method (see [`fuz_realtime::CANCEL_METHOD`]).
#[must_use]
#[expect(
    non_snake_case,
    reason = "named like the constant spec set it stands for; its specs own `Arc`'d handler closures, so it can't be a `const`"
)]
pub fn PROTOCOL_ACTION_SPECS() -> Vec<ActionSpec> {
    vec![heartbeat_action_spec(), peer_ping_action_spec()]
}
